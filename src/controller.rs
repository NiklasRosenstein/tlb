use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::{
    apps::v1::{Deployment, StatefulSet},
    core::v1::{ConfigMap, PersistentVolumeClaim, Pod, Secret, Service},
};
use kube::{
    Api, ResourceExt,
    api::ListParams,
    runtime::{
        Controller,
        controller::{Action, Config},
        reflector::{ObjectRef, Store},
        watcher,
    },
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tlb::{
    Error, ReconcileContext, Result, TunnelProvider,
    crds::{ClusterTunnelClass, TunnelClass},
    managed,
    simpleevent::SimpleEventRecorder,
    state::{
        Binding, BindingData, CLASS_UID_LABEL, ClassSnapshot, JOURNAL_FINALIZER, JOURNAL_LABEL, SERVICE_UID_LABEL,
        required_uid,
    },
};
use tokio::sync::Mutex;

const SERVICE_FINALIZER: &str = "tlb.io/tunnel-cleanup";
const CLASS_FINALIZER: &str = "tlb.io/finalizer";
const RESYNC: Duration = Duration::from_secs(30);

struct Data {
    client: kube::Client,
    namespace: String,
    events: SimpleEventRecorder,
    locks: Mutex<BTreeMap<String, Weak<Mutex<()>>>>,
    bindings: RwLock<BTreeMap<String, BindingData>>,
    failures: RwLock<BTreeMap<String, (std::time::Instant, u32)>>,
}

impl Data {
    async fn lock(&self, uid: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let mutex = {
            let mut locks = self.locks.lock().await;
            locks.retain(|_, lock| lock.strong_count() > 0);
            match locks.get(uid).and_then(Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(Mutex::new(()));
                    locks.insert(uid.into(), Arc::downgrade(&lock));
                    lock
                }
            }
        };
        mutex.lock_owned().await
    }
    fn journals(&self) -> Api<Secret> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }
    fn context(&self, binding: Binding) -> ReconcileContext {
        ReconcileContext {
            client: self.client.clone(),
            events: self.events.clone(),
            metadata: binding.data.class.metadata.clone(),
            namespaced: binding.data.class.namespaced,
            binding,
        }
    }
}

fn class_name(service: &Service) -> Option<&str> {
    service
        .spec
        .as_ref()?
        .load_balancer_class
        .as_deref()?
        .strip_prefix("tlb.io/")
        .filter(|name| !name.is_empty())
}

async fn resolve(service: &Service, data: &Data) -> Result<Option<ClassSnapshot>> {
    let Some(name) = class_name(service) else {
        return Ok(None);
    };
    let namespace = service
        .namespace()
        .ok_or_else(|| Error::ConfigError("Service namespace missing".into()))?;
    if let Some(class) = Api::<TunnelClass>::namespaced(data.client.clone(), &namespace)
        .get_opt(name)
        .await?
    {
        return Ok(Some(ClassSnapshot {
            metadata: class.metadata,
            spec: class.spec.inner,
            namespaced: true,
        }));
    }
    Ok(Api::<ClusterTunnelClass>::all(data.client.clone())
        .get_opt(name)
        .await?
        .map(|class| ClassSnapshot {
            metadata: class.metadata,
            spec: class.spec.inner,
            namespaced: false,
        }))
}

async fn ensure_class_finalizer(class: &mut ClassSnapshot, data: &Data) -> Result<()> {
    if class.namespaced {
        let namespace = class
            .metadata
            .namespace
            .as_deref()
            .ok_or_else(|| Error::ConfigError("class namespace missing".into()))?;
        let api: Api<TunnelClass> = Api::namespaced(data.client.clone(), namespace);
        let current = api
            .get(
                class
                    .metadata
                    .name
                    .as_deref()
                    .ok_or_else(|| Error::ConfigError("class name missing".into()))?,
            )
            .await?;
        if current.uid().as_deref() != Some(required_uid(&class.metadata)?) {
            return Err(Error::CleanupPending);
        }
        class.metadata = managed::set_finalizer(&api, &current, CLASS_FINALIZER, true)
            .await?
            .metadata;
    } else {
        let api: Api<ClusterTunnelClass> = Api::all(data.client.clone());
        let current = api
            .get(
                class
                    .metadata
                    .name
                    .as_deref()
                    .ok_or_else(|| Error::ConfigError("class name missing".into()))?,
            )
            .await?;
        if current.uid().as_deref() != Some(required_uid(&class.metadata)?) {
            return Err(Error::CleanupPending);
        }
        class.metadata = managed::set_finalizer(&api, &current, CLASS_FINALIZER, true)
            .await?
            .metadata;
    }
    Ok(())
}

fn same_configuration(a: &ClassSnapshot, b: &ClassSnapshot) -> Result<bool> {
    Ok(a.metadata.uid == b.metadata.uid
        && a.namespaced == b.namespaced
        && serde_json::to_value(&a.spec)? == serde_json::to_value(&b.spec)?)
}

fn requires_rebinding(a: &ClassSnapshot, b: &ClassSnapshot) -> bool {
    a.metadata.uid != b.metadata.uid
        || a.namespaced != b.namespaced
        || a.spec.netbird.is_some() != b.spec.netbird.is_some()
        || a.spec.cloudflare.as_ref().map(|c| &c.account_id) != b.spec.cloudflare.as_ref().map(|c| &c.account_id)
        || a.spec.netbird.as_ref().map(|c| &c.management_url) != b.spec.netbird.as_ref().map(|c| &c.management_url)
}

fn validate_mutable_configuration(a: &ClassSnapshot, b: &ClassSnapshot) -> Result<()> {
    if a.spec.netbird.as_ref().map(|c| &c.resource_prefix) != b.spec.netbird.as_ref().map(|c| &c.resource_prefix)
        || a.spec.cloudflare.as_ref().map(|c| &c.resource_prefix)
            != b.spec.cloudflare.as_ref().map(|c| &c.resource_prefix)
    {
        return Err(Error::ConfigError(
            "resourcePrefix is immutable while a Service is bound".into(),
        ));
    }
    Ok(())
}

async fn credentials(service: &Service, class: &ClassSnapshot, data: &Data) -> Result<BTreeMap<String, String>> {
    tlb::config::validate_class(class)?;
    let reference = if let Some(netbird) = &class.spec.netbird {
        Some(("setup-key", &netbird.setup_key_ref))
    } else {
        class
            .spec
            .cloudflare
            .as_ref()
            .and_then(|c| c.api_token_ref.as_ref())
            .map(|r| ("api-token", r))
    };
    let mut values = BTreeMap::new();
    if let Some((key, reference)) = reference {
        let value = tlb::get_secret_value(
            &data.client,
            reference,
            &service
                .namespace()
                .ok_or_else(|| Error::ConfigError("Service namespace missing".into()))?,
        )
        .await
        .map_err(|_| Error::ConfigError(format!("cannot read credential Secret {}", reference.name)))?;
        if value.is_empty() {
            return Err(Error::ConfigError("credential value cannot be empty".into()));
        }
        if key == "api-token" && reqwest::header::HeaderValue::from_str(&format!("Bearer {value}")).is_err() {
            return Err(Error::ConfigError("invalid Cloudflare API token header".into()));
        }
        values.insert(key.into(), value);
    }
    Ok(values)
}

async fn validate_workload_inputs(service: &Service, class: &ClassSnapshot, data: &Data) -> Result<()> {
    let options = tlb::config::validate_service(service, class)?;
    if class.spec.netbird.is_some()
        && let Some(mappings) = options.map_ports.as_deref()
        && tlb::PortMapping::parse_multiple(mappings)
            .map_err(Error::ConfigError)?
            .iter()
            .any(|m| m.listen_tls)
    {
        let namespace = service
            .namespace()
            .ok_or_else(|| Error::ConfigError("Service namespace missing".into()))?;
        let name = options
            .tls_secret_name
            .ok_or_else(|| Error::ConfigError("TLS Secret is required".into()))?;
        let secret = Api::<Secret>::namespaced(data.client.clone(), &namespace)
            .get(&name)
            .await?;
        tlb::config::validate_tls_secret(&secret)?;
    }
    Ok(())
}

fn provider(class: &ClassSnapshot) -> Result<Box<dyn TunnelProvider + Send + Sync>> {
    match (&class.spec.netbird, &class.spec.cloudflare) {
        (Some(config), None) => Ok(Box::new(config.clone())),
        (None, Some(config)) => Ok(Box::new(config.clone())),
        _ => Err(Error::ConfigError("binding must contain exactly one provider".into())),
    }
}

async fn cleanup(mut binding: Binding, data: &Data) -> Result<Action> {
    if !binding.data.cleaning {
        binding.data.cleaning = true;
        binding.save(data.client.clone()).await?;
    }
    let uid = required_uid(&binding.data.service.metadata)?.to_string();
    let ctx = data.context(binding.clone());
    if let Err(error) = provider(&binding.data.class)?
        .cleanup_service(&ctx, &binding.data.service)
        .await
    {
        if !matches!(error, Error::CleanupPending)
            && let Ok(values) = credentials(&binding.data.service, &binding.data.class, data).await
            && values != binding.data.credentials
        {
            let mut fresh = Binding::from_secret(data.journals().get(&binding.secret.name_any()).await?)?;
            fresh.data.credentials = values;
            fresh.save(data.client.clone()).await?;
        }
        return Err(error);
    }
    managed::patch_ingress(&ctx, &binding.data.service, Vec::new()).await?;
    data.bindings.write().unwrap().remove(&uid);
    // Provider progress can update the journal's resource version during cleanup.
    let fresh = data.journals().get(&binding.secret.name_any()).await?;
    let fresh = managed::set_finalizer(&data.journals(), &fresh, JOURNAL_FINALIZER, false).await?;
    managed::delete(&data.journals(), &fresh).await?;
    if data.journals().get_opt(&fresh.name_any()).await?.is_some() {
        return Err(Error::CleanupPending);
    }
    let namespace = binding
        .data
        .service
        .namespace()
        .ok_or_else(|| Error::ConfigError("journal Service namespace missing".into()))?;
    let api: Api<Service> = Api::namespaced(data.client.clone(), &namespace);
    if let Some(service) = api.get_opt(&binding.data.service.name_any()).await?
        && service.uid().as_deref() == Some(&uid)
    {
        managed::set_finalizer(&api, &service, SERVICE_FINALIZER, false).await?;
    }
    Ok(Action::requeue(Duration::from_secs(1)))
}

async fn service_reconcile(service: Arc<Service>, data: Arc<Data>) -> Result<Action> {
    if class_name(&service).is_none() && !service.finalizers().iter().any(|f| f == SERVICE_FINALIZER) {
        return Ok(Action::await_change());
    }
    let uid = required_uid(&service.metadata)?.to_string();
    let _guard = data.lock(&uid).await;
    tokio::time::timeout(Duration::from_secs(120), reconcile_service(&service, &data))
        .await
        .map_err(|_| Error::UnexpectedError("Service reconciliation exceeded 120 seconds".into()))?
}

async fn reconcile_service(service: &Service, data: &Data) -> Result<Action> {
    let namespace = service
        .namespace()
        .ok_or_else(|| Error::ConfigError("Service namespace missing".into()))?;
    let api: Api<Service> = Api::namespaced(data.client.clone(), &namespace);
    let Some(current) = api.get_opt(&service.name_any()).await? else {
        return Ok(Action::await_change());
    };
    if current.uid() != service.uid() {
        return Ok(Action::await_change());
    }
    let service = current;
    let journal = data.journals().get_opt(&Binding::name(&service)?).await?;
    let desired = resolve(&service, data).await?;
    let mut binding = match journal {
        Some(secret) => {
            let mut binding = Binding::from_secret(secret)?;
            if binding.data.cleaning
                || binding.secret.metadata.deletion_timestamp.is_some()
                || service.metadata.deletion_timestamp.is_some()
                || service.spec.as_ref().and_then(|s| s.type_.as_deref()) != Some("LoadBalancer")
                || desired.as_ref().is_none_or(|c| c.metadata.deletion_timestamp.is_some())
            {
                return cleanup(binding, data).await;
            }
            let class = desired.as_ref().expect("live desired class checked above");
            validate_workload_inputs(&service, class, data).await?;
            let values = credentials(&service, class, data).await?;
            if requires_rebinding(&binding.data.class, class) {
                return cleanup(binding, data).await;
            }
            validate_mutable_configuration(&binding.data.class, class)?;
            if !same_configuration(&binding.data.class, class)?
                || binding.data.credentials != values
                || binding.data.service.spec != service.spec
                || binding.data.service.metadata.annotations != service.metadata.annotations
            {
                binding.data.class = class.clone();
                binding.data.credentials = values;
                binding.data.service = service.clone();
                binding.save(data.client.clone()).await?;
            }
            binding
        }
        None => {
            if service.metadata.deletion_timestamp.is_some() {
                ensure_no_legacy(&service, data).await?;
                managed::set_finalizer(&api, &service, SERVICE_FINALIZER, false).await?;
                return Ok(Action::await_change());
            }
            let Some(mut class) = desired else {
                if service.finalizers().iter().any(|f| f == SERVICE_FINALIZER) {
                    ensure_no_legacy(&service, data).await?;
                    managed::set_finalizer(&api, &service, SERVICE_FINALIZER, false).await?;
                }
                return Ok(Action::requeue(RESYNC));
            };
            if class.metadata.deletion_timestamp.is_some() {
                return Ok(Action::requeue(RESYNC));
            }
            validate_workload_inputs(&service, &class, data).await?;
            ensure_no_legacy(&service, data).await?;
            ensure_class_finalizer(&mut class, data).await?;
            let service = managed::set_finalizer(&api, &service, SERVICE_FINALIZER, true).await?;
            let credentials = credentials(&service, &class, data).await?;
            Binding::create(
                data.client.clone(),
                &data.namespace,
                BindingData {
                    service,
                    class,
                    credentials,
                    cleaning: false,
                    cloudflare: Default::default(),
                },
            )
            .await?
        }
    };
    // A class deletion that races journal creation must see the journal or prevent provisioning.
    let current_class = resolve(&service, data).await?;
    if current_class
        .as_ref()
        .is_none_or(|c| c.metadata.deletion_timestamp.is_some() || c.metadata.uid != binding.data.class.metadata.uid)
    {
        return cleanup(binding, data).await;
    }
    if !same_configuration(
        &binding.data.class,
        current_class.as_ref().expect("live class checked above"),
    )? {
        return Ok(Action::requeue(Duration::from_secs(1)));
    }
    let fresh = Binding::from_secret(data.journals().get(&binding.secret.name_any()).await?)?;
    if fresh.data.cleaning || fresh.secret.metadata.deletion_timestamp.is_some() {
        return cleanup(fresh, data).await;
    }
    binding = fresh;
    data.bindings
        .write()
        .unwrap()
        .insert(required_uid(&service.metadata)?.into(), binding.data.clone());
    let ctx = data.context(binding);
    provider(&ctx.binding.data.class)?
        .reconcile_service(&ctx, &service)
        .await?;
    data.failures.write().unwrap().remove(required_uid(&service.metadata)?);
    Ok(Action::requeue(RESYNC))
}

async fn ensure_no_legacy(service: &Service, data: &Data) -> Result<()> {
    let selector = ListParams::default().labels(&format!("{}={}", tlb::FOR_SERVICE_LABEL, service.name_any()));
    let mut metadata = Vec::new();
    metadata.extend(
        Api::<Deployment>::all(data.client.clone())
            .list(&selector)
            .await?
            .items
            .into_iter()
            .map(|r| r.metadata),
    );
    metadata.extend(
        Api::<StatefulSet>::all(data.client.clone())
            .list(&selector)
            .await?
            .items
            .into_iter()
            .map(|r| r.metadata),
    );
    metadata.extend(
        Api::<Secret>::all(data.client.clone())
            .list(&selector)
            .await?
            .items
            .into_iter()
            .map(|r| r.metadata),
    );
    for object in metadata {
        if object
            .labels
            .as_ref()
            .is_some_and(|l| l.contains_key(tlb::state::BINDING_LABEL))
        {
            continue;
        }
        let owned = object.owner_references.as_ref().is_some_and(|rs| {
            rs.iter()
                .any(|r| Some(&r.uid) == service.metadata.uid.as_ref() && r.kind == "Service")
        });
        let class_matches = object
            .labels
            .as_ref()
            .and_then(|l| l.get(tlb::FOR_TUNNEL_CLASS_LABEL))
            .map(String::as_str)
            == class_name(service);
        if owned || class_matches {
            return Err(Error::ConfigError(format!(
                "resource {}/{} has no private binding journal; recover its ownership and external state before provisioning or deleting this Service",
                object.namespace.as_deref().unwrap_or_default(),
                object.name.as_deref().unwrap_or_default()
            )));
        }
    }
    Ok(())
}

async fn journal_reconcile(secret: Arc<Secret>, data: Arc<Data>) -> Result<Action> {
    let binding = Binding::from_secret((*secret).clone())?;
    let uid = required_uid(&binding.data.service.metadata)?.to_string();
    let _guard = data.lock(&uid).await;
    let Some(secret) = data.journals().get_opt(&secret.name_any()).await? else {
        return Ok(Action::await_change());
    };
    let binding = Binding::from_secret(secret)?;
    let namespace = binding
        .data
        .service
        .namespace()
        .ok_or_else(|| Error::ConfigError("journal Service namespace missing".into()))?;
    let service = Api::<Service>::namespaced(data.client.clone(), &namespace)
        .get_opt(&binding.data.service.name_any())
        .await?;
    if service.as_ref().is_some_and(|s| s.uid().as_deref() == Some(&uid)) {
        return Ok(Action::requeue(RESYNC));
    }
    tokio::time::timeout(Duration::from_secs(120), cleanup(binding, &data))
        .await
        .map_err(|_| Error::UnexpectedError("orphan cleanup exceeded 120 seconds".into()))?
}

async fn class_cleanup(class: &ClassSnapshot, data: &Data) -> Result<bool> {
    let selector = ListParams::default().labels(&format!("{CLASS_UID_LABEL}={}", required_uid(&class.metadata)?));
    let journals = data.journals().list(&selector).await?;
    let pending = !journals.items.is_empty();
    for secret in journals {
        let mut binding = Binding::from_secret(secret)?;
        if !binding.data.cleaning {
            binding.data.cleaning = true;
            binding.save(data.client.clone()).await?;
        }
    }
    // Name labels cannot prove ownership; do not delete ambiguous resources during class finalization.
    let selector = ListParams::default().labels(&format!(
        "{}={}",
        tlb::FOR_TUNNEL_CLASS_LABEL,
        class.metadata.name.as_deref().unwrap_or_default()
    ));
    let deployments = Api::<Deployment>::all(data.client.clone()).list(&selector).await?;
    let statefulsets = Api::<StatefulSet>::all(data.client.clone()).list(&selector).await?;
    let secrets = Api::<Secret>::all(data.client.clone()).list(&selector).await?;
    if deployments
        .items
        .into_iter()
        .map(|r| r.metadata)
        .chain(statefulsets.items.into_iter().map(|r| r.metadata))
        .chain(secrets.items.into_iter().map(|r| r.metadata))
        .any(|m| {
            !m.labels
                .as_ref()
                .is_some_and(|l| l.contains_key(tlb::state::BINDING_LABEL))
        })
    {
        return Err(Error::ConfigError(
            "class has resources without verifiable UID ownership; explicit recovery is required".into(),
        ));
    }
    Ok(!pending)
}

async fn namespaced_class(class: Arc<TunnelClass>, data: Arc<Data>) -> Result<Action> {
    let api = Api::namespaced(
        data.client.clone(),
        &class
            .namespace()
            .ok_or_else(|| Error::ConfigError("class namespace missing".into()))?,
    );
    if class.metadata.deletion_timestamp.is_some() {
        if class_cleanup(
            &ClassSnapshot {
                metadata: class.metadata.clone(),
                spec: class.spec.inner.clone(),
                namespaced: true,
            },
            &data,
        )
        .await?
        {
            managed::set_finalizer(&api, &*class, CLASS_FINALIZER, false).await?;
            return Ok(Action::await_change());
        }
    } else {
        managed::set_finalizer(&api, &*class, CLASS_FINALIZER, true).await?;
    }
    Ok(Action::requeue(RESYNC))
}
async fn cluster_class(class: Arc<ClusterTunnelClass>, data: Arc<Data>) -> Result<Action> {
    let api = Api::all(data.client.clone());
    if class.metadata.deletion_timestamp.is_some() {
        if class_cleanup(
            &ClassSnapshot {
                metadata: class.metadata.clone(),
                spec: class.spec.inner.clone(),
                namespaced: false,
            },
            &data,
        )
        .await?
        {
            managed::set_finalizer(&api, &*class, CLASS_FINALIZER, false).await?;
            return Ok(Action::await_change());
        }
    } else {
        managed::set_finalizer(&api, &*class, CLASS_FINALIZER, true).await?;
    }
    Ok(Action::requeue(RESYNC))
}

fn retry<K: kube::Resource<DynamicType = ()>>(object: Arc<K>, error: &Error, data: Arc<Data>) -> Action {
    if matches!(error, Error::CleanupPending) {
        return Action::requeue(Duration::from_secs(2));
    }
    log::warn!(
        "reconciliation failed for {}/{} uid={}: {error}",
        object.namespace().unwrap_or_default(),
        object.name_any(),
        object.uid().unwrap_or_default()
    );
    let key = object
        .uid()
        .unwrap_or_else(|| format!("{}/{}", object.namespace().unwrap_or_default(), object.name_any()));
    let mut failures = data.failures.write().unwrap();
    failures.retain(|_, (last, _)| last.elapsed() < Duration::from_secs(600));
    let (last, attempt) = failures.entry(key).or_insert((std::time::Instant::now(), 0));
    *last = std::time::Instant::now();
    *attempt = attempt.saturating_add(1).min(6);
    Action::requeue(
        Duration::from_secs((1u64 << *attempt).min(60)) + Duration::from_millis(rand::random::<u64>() % 1000),
    )
}
fn affected_class(store: &Store<Service>, name: &str, namespace: Option<&str>) -> Vec<ObjectRef<Service>> {
    store
        .state()
        .into_iter()
        .filter(|s| class_name(s) == Some(name) && namespace.is_none_or(|ns| s.namespace().as_deref() == Some(ns)))
        .map(|s| ObjectRef::from_obj(&*s))
        .collect()
}
fn affected_secret(store: &Store<Service>, secret: &Secret, data: &Data) -> Vec<ObjectRef<Service>> {
    if secret.namespace().as_deref() == Some(&data.namespace)
        && secret.labels().get(JOURNAL_LABEL).map(String::as_str) == Some("true")
    {
        return Binding::from_secret(secret.clone())
            .map(|b| vec![ObjectRef::from_obj(&b.data.service)])
            .unwrap_or_default();
    }
    let bindings = data.bindings.read().unwrap();
    store
        .state()
        .into_iter()
        .filter(|service| {
            let tls = service.namespace() == secret.namespace()
                && service.annotations().get("tlb.io/tls-secret-name") == Some(&secret.name_any());
            let credentials = service.uid().and_then(|uid| bindings.get(&uid)).is_some_and(|b| {
                let reference = b
                    .class
                    .spec
                    .netbird
                    .as_ref()
                    .map(|c| &c.setup_key_ref)
                    .or_else(|| b.class.spec.cloudflare.as_ref().and_then(|c| c.api_token_ref.as_ref()));
                reference.is_some_and(|r| {
                    r.name == secret.name_any()
                        && r.namespace.as_ref().or(b.service.metadata.namespace.as_ref())
                            == secret.metadata.namespace.as_ref()
                })
            });
            tls || credentials
        })
        .map(|s| ObjectRef::from_obj(&*s))
        .collect()
}

fn controller_result<T, E: std::fmt::Display>(
    result: std::result::Result<T, kube::runtime::controller::Error<Error, E>>,
) -> std::result::Result<(), ()> {
    match result {
        Ok(_) => Ok(()),
        Err(error) => {
            log::warn!("controller stream: {error}");
            match error {
                kube::runtime::controller::Error::ReconcilerFailed(..)
                | kube::runtime::controller::Error::ObjectNotFound(..) => Ok(()),
                _ => Err(()),
            }
        }
    }
}

async fn controllers(data: Arc<Data>, ready: Arc<AtomicBool>) {
    let controller = Controller::new(Api::<Service>::all(data.client.clone()), watcher::Config::default())
        .with_config(Config::default().concurrency(16));
    let store = controller.store();
    let class_store = store.clone();
    let cluster_store = store.clone();
    let pod_store = store.clone();
    let secret_store = store.clone();
    let secret_data = data.clone();
    let controller = controller
        .owns(Api::<Deployment>::all(data.client.clone()), watcher::Config::default())
        .owns(Api::<StatefulSet>::all(data.client.clone()), watcher::Config::default())
        .owns(Api::<ConfigMap>::all(data.client.clone()), watcher::Config::default())
        .owns(
            Api::<PersistentVolumeClaim>::all(data.client.clone()),
            watcher::Config::default(),
        )
        .watches(
            Api::<TunnelClass>::all(data.client.clone()),
            watcher::Config::default(),
            move |c| affected_class(&class_store, &c.name_any(), c.namespace().as_deref()),
        )
        .watches(
            Api::<ClusterTunnelClass>::all(data.client.clone()),
            watcher::Config::default(),
            move |c| affected_class(&cluster_store, &c.name_any(), None),
        )
        .watches(
            Api::<Secret>::all(data.client.clone()),
            watcher::Config::default(),
            move |s| affected_secret(&secret_store, &s, &secret_data),
        )
        .watches(
            Api::<Pod>::all(data.client.clone()),
            watcher::Config::default().labels(tlb::state::BINDING_LABEL),
            move |pod| {
                pod_store
                    .state()
                    .into_iter()
                    .filter(|s| s.metadata.uid.as_ref() == pod.labels().get(SERVICE_UID_LABEL))
                    .map(|s| ObjectRef::from_obj(&*s))
                    .collect::<Vec<_>>()
            },
        );
    let services = controller
        .run(service_reconcile, retry, data.clone())
        .map(controller_result)
        .try_for_each(|_| async { Ok(()) });
    let journal_controller = Controller::new(
        data.journals(),
        watcher::Config::default().labels(&format!("{JOURNAL_LABEL}=true")),
    )
    .with_config(Config::default().concurrency(16));
    let journal_cache = journal_controller.store();
    let journals = journal_controller
        .run(journal_reconcile, retry, data.clone())
        .map(controller_result)
        .try_for_each(|_| async { Ok(()) });
    let class_controller = Controller::new(Api::<TunnelClass>::all(data.client.clone()), watcher::Config::default())
        .with_config(Config::default().concurrency(4));
    let class_cache = class_controller.store();
    let classes = class_controller
        .run(namespaced_class, retry, data.clone())
        .map(controller_result)
        .try_for_each(|_| async { Ok(()) });
    let cluster_controller = Controller::new(
        Api::<ClusterTunnelClass>::all(data.client.clone()),
        watcher::Config::default(),
    )
    .with_config(Config::default().concurrency(4));
    let cluster_cache = cluster_controller.store();
    let clusters = cluster_controller
        .run(cluster_class, retry, data)
        .map(controller_result)
        .try_for_each(|_| async { Ok(()) });
    let readiness = async {
        if tokio::try_join!(
            store.wait_until_ready(),
            journal_cache.wait_until_ready(),
            class_cache.wait_until_ready(),
            cluster_cache.wait_until_ready()
        )
        .is_ok()
        {
            ready.store(true, Ordering::Release);
        }
        std::future::pending::<()>().await;
    };
    tokio::select! { _ = services => {}, _ = journals => {}, _ = classes => {}, _ = clusters => {}, _ = readiness => {} }
}

pub async fn run(_reconcile_interval: Duration) -> Result<()> {
    let namespace = std::env::var("POD_NAMESPACE").unwrap_or_else(|_| "tlb-system".into());
    let client = kube::Client::try_default().await?;
    let data = Arc::new(Data {
        events: SimpleEventRecorder::from_client(client.clone(), "tlb-controller"),
        client: client.clone(),
        namespace: namespace.clone(),
        locks: Mutex::new(BTreeMap::new()),
        bindings: RwLock::new(BTreeMap::new()),
        failures: RwLock::new(BTreeMap::new()),
    });
    let ready = Arc::new(AtomicBool::new(false));
    let mut leader = tlb::leadership::Leadership::new(client, &namespace);
    let health = health_server(ready.clone());
    let work = async {
        loop {
            match leader.acquire_or_renew().await {
                Ok(true) => {
                    ready.store(false, Ordering::Release);
                    log::info!("acquired controller leadership in namespace {namespace}");
                    let work = controllers(data.clone(), ready.clone());
                    tokio::pin!(work);
                    let mut interval = tokio::time::interval(Duration::from_secs(5));
                    interval.tick().await;
                    loop {
                        tokio::select! {
                            _ = &mut work => break,
                            _ = interval.tick() => {
                                if !matches!(leader.acquire_or_renew().await, Ok(true)) { break; }
                            }
                        }
                    }
                    ready.store(false, Ordering::Release);
                    log::warn!("controller work cancelled; leadership must be reacquired");
                }
                Ok(false) => {
                    ready.store(true, Ordering::Release);
                }
                Err(error) => {
                    ready.store(false, Ordering::Release);
                    log::warn!("cannot acquire controller Lease: {error}");
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    };
    tokio::select! { _ = work => {}, result = health => { result?; }, _ = shutdown() => { ready.store(false, Ordering::Release); } }
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            tokio::select! { _ = terminate.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

async fn health_server(ready: Arc<AtomicBool>) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut buffer = [0u8; 1024];
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer)).await;
        let Ok(Ok(n)) = read else {
            continue;
        };
        let request = std::str::from_utf8(&buffer[..n]).unwrap_or_default();
        let healthy = request.starts_with("GET /healthz ")
            || (request.starts_with("GET /readyz ") && ready.load(Ordering::Acquire));
        let status = if healthy { "200 OK" } else { "503 Service Unavailable" };
        let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = tokio::time::timeout(Duration::from_secs(1), stream.write_all(response.as_bytes())).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn class() -> ClassSnapshot {
        serde_json::from_value(
            json!({"metadata":{"name":"public", "namespace":"apps", "uid":"class-uid"},
            "namespaced":true,"spec":{"netbird":{"managementUrl":"https://netbird.example.com",
            "setupKeyRef":{"name":"key","key":"token"}}}}),
        )
        .unwrap()
    }

    #[test]
    fn mutable_class_updates_preserve_the_binding() {
        let current = class();
        let mut desired = current.clone();
        desired.spec.netbird.as_mut().unwrap().image = Some("netbird:new".into());
        assert!(!same_configuration(&current, &desired).unwrap());
        assert!(!requires_rebinding(&current, &desired));
        assert!(validate_mutable_configuration(&current, &desired).is_ok());
        desired.spec.netbird.as_mut().unwrap().resource_prefix = Some("new-".into());
        assert!(validate_mutable_configuration(&current, &desired).is_err());
    }

    #[test]
    fn recreated_class_and_provider_account_require_new_bindings() {
        let current = class();
        let mut desired = current.clone();
        desired.metadata.uid = Some("new-uid".into());
        assert!(requires_rebinding(&current, &desired));
        desired = current.clone();
        desired.spec.netbird.as_mut().unwrap().management_url = "https://other.example.com".into();
        assert!(requires_rebinding(&current, &desired));
    }
}
