use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::{
    apps::v1::{Deployment, StatefulSet},
    core::v1::{ConfigMap, Namespace, PersistentVolumeClaim, Pod, Secret, Service},
    networking::v1::Ingress,
};
use kube::{
    Api, Resource, ResourceExt,
    api::ListParams,
    runtime::{
        Controller,
        controller::{Action, Config},
        events::EventType,
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
fn external_refresh(value: Option<&str>) -> Result<Duration> {
    let seconds = value
        .unwrap_or("300")
        .parse::<u64>()
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| Error::ConfigError("TLB_EXTERNAL_REFRESH_INTERVAL_SECONDS must be a positive integer".into()))?;
    let duration = Duration::from_secs(seconds);
    if std::time::Instant::now().checked_add(duration).is_none() {
        return Err(Error::ConfigError("external refresh interval is too large".into()));
    }
    Ok(duration)
}

struct Data {
    dns_lock: Arc<Mutex<()>>,
    external_refresh: Duration,
    client: kube::Client,
    namespace: String,
    workload_policy: tlb::config::WorkloadPolicy,
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
            dns_lock: self.dns_lock.clone(),
            external_refresh: self.external_refresh,
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
    managed::cleanup_owner(&ctx).await?;
    managed::patch_ingress(&ctx, &binding.data.service, Vec::new()).await?;
    data.bindings.write().unwrap().remove(&uid);
    let namespace = binding
        .data
        .service
        .namespace()
        .ok_or_else(|| Error::ConfigError("journal Service namespace missing".into()))?;
    let api: Api<Service> = Api::namespaced(data.client.clone(), &namespace);
    // Remove the Service finalizer before its journal so interrupted cleanup remains recoverable.
    if let Some(service) = api.get_opt(&binding.data.service.name_any()).await?
        && service.uid().as_deref() == Some(&uid)
    {
        managed::set_finalizer(&api, &service, SERVICE_FINALIZER, false).await?;
    }
    // Provider progress can update the journal's resource version during cleanup.
    let fresh = data.journals().get(&binding.secret.name_any()).await?;
    let fresh = managed::set_finalizer(&data.journals(), &fresh, JOURNAL_FINALIZER, false).await?;
    managed::delete(&data.journals(), &fresh).await?;
    if data.journals().get_opt(&fresh.name_any()).await?.is_some() {
        return Err(Error::CleanupPending);
    }
    Ok(Action::requeue(Duration::from_secs(1)))
}

async fn service_reconcile(service: Arc<Service>, data: Arc<Data>) -> Result<Action> {
    if class_name(&service).is_none() && !service.finalizers().iter().any(|f| f == SERVICE_FINALIZER) {
        return Ok(Action::await_change());
    }
    let uid = required_uid(&service.metadata)?.to_string();
    let _guard = data.lock(&uid).await;
    let result = tokio::time::timeout(Duration::from_secs(120), reconcile_service(&service, &data))
        .await
        .unwrap_or_else(|_| {
            Err(Error::UnexpectedError(
                "Service reconciliation exceeded 120 seconds".into(),
            ))
        });
    if let Err(error) = &result
        && !matches!(error, Error::CleanupPending)
    {
        data.events
            .publish(
                &service.object_ref(&()),
                EventType::Warning,
                "ReconcileFailed".into(),
                Some(error.to_string()),
                "Reconcile".into(),
            )
            .await;
    }
    result
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
            if data.workload_policy.validate(&binding.data.class).is_err()
                || data.workload_policy.validate(class).is_err()
            {
                let ctx = data.context(binding.clone());
                managed::patch_ingress(&ctx, &service, Vec::new()).await?;
                managed::cleanup_workloads(&ctx).await?;
                data.workload_policy.validate(class)?;
            }

            if binding.data.workload_namespace != data.workload_policy.namespace {
                return Err(Error::ConfigError(
                    "drain existing bindings before changing TLB_WORKLOAD_NAMESPACE".into(),
                ));
            }

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
                return Ok(Action::await_change());
            };
            if class.metadata.deletion_timestamp.is_some() {
                return Ok(Action::await_change());
            }
            data.workload_policy.validate(&class)?;
            validate_workload_inputs(&service, &class, data).await?;
            ensure_no_legacy(&service, data).await?;
            ensure_class_finalizer(&mut class, data).await?;
            let credentials = credentials(&service, &class, data).await?;
            Binding::create(
                data.client.clone(),
                &data.namespace,
                BindingData {
                    workload_namespace: data.workload_policy.namespace.clone(),
                    workload_owner: None,
                    service: service.clone(),
                    class,
                    credentials,
                    cleaning: false,
                    cloudflare: Default::default(),
                    netbird_dns: Default::default(),
                },
            )
            .await?
        }
    };
    // Persist the binding before adding the Service finalizer so missing journals identify legacy state.
    managed::set_finalizer(&api, &service, SERVICE_FINALIZER, true).await?;
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
    if !managed::ensure_owner(&mut binding, data.client.clone()).await? {
        return cleanup(binding, data).await;
    }
    data.bindings
        .write()
        .unwrap()
        .insert(required_uid(&service.metadata)?.into(), binding.data.clone());
    let ctx = data.context(binding);
    let outcome = provider(&ctx.binding.data.class)?
        .reconcile_service(&ctx, &service)
        .await?;
    data.failures.write().unwrap().remove(required_uid(&service.metadata)?);
    Ok(outcome
        .requeue_after(data.external_refresh)
        .map(Action::requeue)
        .unwrap_or_else(Action::await_change))
}

async fn ensure_no_legacy(service: &Service, data: &Data) -> Result<()> {
    if service.finalizers().iter().any(|f| f == SERVICE_FINALIZER) {
        return Err(Error::ConfigError(
            "Service has a tunnel finalizer but no private binding journal; recover its external state before proceeding".into(),
        ));
    }
    let namespace = service
        .namespace()
        .ok_or_else(|| Error::ConfigError("Service namespace missing".into()))?;
    let selector = ListParams::default();
    let deployments = Api::<Deployment>::namespaced(data.client.clone(), &namespace)
        .list(&selector)
        .await?;
    let statefulsets = Api::<StatefulSet>::namespaced(data.client.clone(), &namespace)
        .list(&selector)
        .await?;
    let secrets = Api::<Secret>::namespaced(data.client.clone(), &namespace)
        .list(&selector)
        .await?;
    for object in deployments
        .items
        .into_iter()
        .map(|r| r.metadata)
        .chain(statefulsets.items.into_iter().map(|r| r.metadata))
        .chain(secrets.items.into_iter().map(|r| r.metadata))
    {
        if object.owner_references.as_ref().is_some_and(|refs| {
            refs.iter().any(|owner| {
                owner.api_version == "v1"
                    && owner.kind == "Service"
                    && Some(&owner.uid) == service.metadata.uid.as_ref()
            })
        }) && object
            .labels
            .as_ref()
            .is_some_and(|labels| labels.get(tlb::FOR_TUNNEL_CLASS_LABEL).map(String::as_str) == class_name(service))
        {
            return Err(Error::ConfigError(
                "Service owns tunnel resources without a private binding journal; explicit recovery is required".into(),
            ));
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
        return Ok(Action::await_change());
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
    // Only Services actually selecting this class can require legacy recovery.
    let services = if class.namespaced {
        Api::<Service>::namespaced(
            data.client.clone(),
            class
                .metadata
                .namespace
                .as_deref()
                .ok_or_else(|| Error::ConfigError("class namespace missing".into()))?,
        )
    } else {
        Api::<Service>::all(data.client.clone())
    };
    for service in services.list(&ListParams::default()).await? {
        if class_name(&service) == class.metadata.name.as_deref()
            && service.finalizers().iter().any(|f| f == SERVICE_FINALIZER)
            && resolve(&service, data)
                .await?
                .is_some_and(|selected| selected.metadata.uid == class.metadata.uid)
            && data.journals().get_opt(&Binding::name(&service)?).await?.is_none()
        {
            return Err(Error::ConfigError("class has a Service with a tunnel finalizer but no private binding journal; explicit recovery is required".into()));
        }
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
    Ok(Action::await_change())
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
    Ok(Action::await_change())
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
fn affected_workload(store: &Store<Service>, metadata: &kube::api::ObjectMeta) -> Vec<ObjectRef<Service>> {
    store
        .state()
        .into_iter()
        .filter(|s| s.metadata.uid.as_ref() == metadata.labels.as_ref().and_then(|l| l.get(SERVICE_UID_LABEL)))
        .map(|s| ObjectRef::from_obj(&*s))
        .collect()
}
fn affected_secret(
    store: &Store<Service>,
    secret: &Secret,
    data: &Data,
    classes: &Store<TunnelClass>,
    clusters: &Store<ClusterTunnelClass>,
) -> Vec<ObjectRef<Service>> {
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
            let owned = service.namespace() == secret.namespace()
                && secret
                    .owner_references()
                    .iter()
                    .any(|r| r.kind == "Service" && Some(&r.uid) == service.metadata.uid.as_ref());
            let tls = service.namespace() == secret.namespace()
                && service.annotations().get("tlb.io/tls-secret-name") == Some(&secret.name_any());
            let class = class_name(service).and_then(|name| {
                classes
                    .get(&ObjectRef::new(name).within(service.namespace().as_deref().unwrap_or_default()))
                    .map(|c| c.spec.inner.clone())
                    .or_else(|| clusters.get(&ObjectRef::new(name)).map(|c| c.spec.inner.clone()))
            });
            let matches = |spec: &tlb::crds::TunnelClassInnerSpec| {
                let references: Vec<_> = if let Some(nb) = &spec.netbird {
                    std::iter::once(&nb.setup_key_ref)
                        .chain(nb.custom_dns.iter().map(|d| &d.api_token_ref))
                        .collect()
                } else {
                    spec.cloudflare
                        .as_ref()
                        .and_then(|c| c.api_token_ref.as_ref())
                        .into_iter()
                        .collect()
                };
                references.iter().any(|r| {
                    r.name == secret.name_any()
                        && r.namespace.as_ref().or(service.metadata.namespace.as_ref())
                            == secret.metadata.namespace.as_ref()
                })
            };
            owned
                || secret.labels().get(SERVICE_UID_LABEL) == service.metadata.uid.as_ref()
                || tls
                || class.as_ref().is_some_and(matches)
                || service.uid().and_then(|uid| bindings.get(&uid)).is_some_and(|b| {
                    matches(&b.class.spec)
                        || b.netbird_dns.targets.iter().any(|t| {
                            t.token_ref.name == secret.name_any()
                                && t.token_ref.namespace.as_ref().or(b.service.metadata.namespace.as_ref())
                                    == secret.metadata.namespace.as_ref()
                        })
                })
        })
        .map(|s| ObjectRef::from_obj(&*s))
        .collect()
}

fn affected_journals(store: &Store<Secret>, service: &Service) -> Vec<ObjectRef<Secret>> {
    let mut refs = vec![];
    if let Ok(name) = Binding::name(service) {
        // The journal namespace is supplied by the caller.
        refs.push(ObjectRef::new(&name));
    }
    refs.extend(
        store
            .state()
            .iter()
            .filter_map(|s| Binding::from_secret((**s).clone()).ok())
            .filter(|b| {
                b.data.service.namespace() == service.namespace() && b.data.service.name_any() == service.name_any()
            })
            .map(|b| ObjectRef::from_obj(&b.secret)),
    );
    refs
}

fn journal_class<K: kube::Resource<DynamicType = ()>>(secret: &Secret, namespaced: bool) -> Vec<ObjectRef<K>> {
    Binding::from_secret(secret.clone())
        .ok()
        .filter(|b| b.data.class.namespaced == namespaced)
        .map(|b| {
            let reference = ObjectRef::new(b.data.class.metadata.name.as_deref().unwrap_or_default());
            vec![if namespaced {
                reference.within(b.data.class.metadata.namespace.as_deref().unwrap_or_default())
            } else {
                reference
            }]
        })
        .unwrap_or_default()
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
    let class_controller = Controller::new(Api::<TunnelClass>::all(data.client.clone()), watcher::Config::default())
        .with_config(Config::default().concurrency(4));
    let class_cache = class_controller.store();
    let cluster_controller = Controller::new(
        Api::<ClusterTunnelClass>::all(data.client.clone()),
        watcher::Config::default(),
    )
    .with_config(Config::default().concurrency(4));
    let cluster_cache = cluster_controller.store();
    let secret_classes = class_cache.clone();
    let secret_clusters = cluster_cache.clone();
    let controller = Controller::new(Api::<Service>::all(data.client.clone()), watcher::Config::default())
        .with_config(Config::default().concurrency(16));
    let store = controller.store();
    let class_store = store.clone();
    let cluster_store = store.clone();
    let pod_store = store.clone();
    let ingress_store = store.clone();
    let secret_store = store.clone();
    let secret_data = data.clone();
    let controller = controller
        .watches(
            Api::<Ingress>::all(data.client.clone()),
            watcher::Config::default(),
            move |ingress| {
                ingress_store
                    .state()
                    .into_iter()
                    .filter(|service| tlb::netbird_ingress::affected(service, &ingress))
                    .map(|service| ObjectRef::from_obj(&*service))
                    .collect::<Vec<_>>()
            },
        )
        .watches(
            Api::<Deployment>::all(data.client.clone()),
            watcher::Config::default(),
            {
                let store = store.clone();
                move |o| affected_workload(&store, &o.metadata)
            },
        )
        .watches(
            Api::<StatefulSet>::all(data.client.clone()),
            watcher::Config::default(),
            {
                let store = store.clone();
                move |o| affected_workload(&store, &o.metadata)
            },
        )
        .watches(
            Api::<ConfigMap>::all(data.client.clone()),
            watcher::Config::default(),
            {
                let store = store.clone();
                move |o| affected_workload(&store, &o.metadata)
            },
        )
        .watches(
            Api::<PersistentVolumeClaim>::all(data.client.clone()),
            watcher::Config::default(),
            {
                let store = store.clone();
                move |o| affected_workload(&store, &o.metadata)
            },
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
            move |s| affected_secret(&secret_store, &s, &secret_data, &secret_classes, &secret_clusters),
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
    let journal_store = journal_cache.clone();
    let journal_namespace = data.namespace.clone();
    let journals = journal_controller
        .watches(
            Api::<Service>::all(data.client.clone()),
            watcher::Config::default(),
            move |service| {
                affected_journals(&journal_store, &service)
                    .into_iter()
                    .map(|r| r.within(&journal_namespace))
                    .collect::<Vec<_>>()
            },
        )
        .run(journal_reconcile, retry, data.clone())
        .map(controller_result)
        .try_for_each(|_| async { Ok(()) });
    let classes = class_controller
        .watches(
            data.journals(),
            watcher::Config::default().labels(&format!("{JOURNAL_LABEL}=true")),
            |s| journal_class::<TunnelClass>(&s, true),
        )
        .watches(
            Api::<Service>::all(data.client.clone()),
            watcher::Config::default(),
            |s| {
                class_name(&s)
                    .map(|name| {
                        ObjectRef::<TunnelClass>::new(name).within(s.namespace().as_deref().unwrap_or_default())
                    })
                    .into_iter()
                    .collect::<Vec<_>>()
            },
        )
        .run(namespaced_class, retry, data.clone())
        .map(controller_result)
        .try_for_each(|_| async { Ok(()) });
    let clusters = cluster_controller
        .watches(
            data.journals(),
            watcher::Config::default().labels(&format!("{JOURNAL_LABEL}=true")),
            |s| journal_class::<ClusterTunnelClass>(&s, false),
        )
        .watches(
            Api::<Service>::all(data.client.clone()),
            watcher::Config::default(),
            |s| {
                class_name(&s)
                    .map(ObjectRef::<ClusterTunnelClass>::new)
                    .into_iter()
                    .collect::<Vec<_>>()
            },
        )
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

pub async fn run() -> Result<()> {
    let namespace = std::env::var("POD_NAMESPACE").unwrap_or_else(|_| "kube-system".into());
    let allow_unsafe = std::env::var("TLB_ALLOW_UNSAFE_WORKLOAD_OVERRIDES")
        .unwrap_or_else(|_| "false".into())
        .parse::<bool>()
        .map_err(|_| Error::ConfigError("TLB_ALLOW_UNSAFE_WORKLOAD_OVERRIDES must be true or false".into()))?;
    let workload_policy =
        tlb::config::WorkloadPolicy::new(&namespace, std::env::var("TLB_WORKLOAD_NAMESPACE").ok(), allow_unsafe)?;
    let client = kube::Client::try_default().await?;
    let workload_namespace = Api::<Namespace>::all(client.clone())
        .get(&workload_policy.namespace)
        .await?;
    if workload_namespace.metadata.deletion_timestamp.is_some() {
        return Err(Error::ConfigError("workload namespace is terminating".into()));
    }
    let data = Arc::new(Data {
        dns_lock: Default::default(),
        external_refresh: external_refresh(std::env::var("TLB_EXTERNAL_REFRESH_INTERVAL_SECONDS").ok().as_deref())?,
        workload_policy,
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

    #[tokio::test]
    async fn service_validation_errors_publish_events_and_survive_event_api_failure() {
        use kube::client::Body;
        for event_status in [201, 403] {
            let service: Service = serde_json::from_value(json!({
                "metadata":{"name":"api","namespace":"apps","uid":"service-uid",
                    "annotations":{"tlb.io/map-ports":"https:80,ssh:22"}},
                "spec":{"type":"LoadBalancer","loadBalancerClass":"tlb.io/public",
                    "clusterIP":"10.0.0.1","ports":[{"port":80}]}
            }))
            .unwrap();
            let snapshot = service.clone();
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            let requests = calls.clone();
            let client = kube::Client::new(
                tower::service_fn(move |request: http::Request<Body>| {
                    let service = snapshot.clone();
                    let calls = calls.clone();
                    async move {
                        let path = request.uri().path().to_string();
                        calls.lock().unwrap().push(path.clone());
                        let (status, response) = match path.as_str() {
                            "/api/v1/namespaces/apps/services/api" => (200, serde_json::to_value(service).unwrap()),
                            "/api/v1/namespaces/tlb-system/secrets/tlb-service-uid" => (
                                404,
                                json!({"kind":"Status","status":"Failure","reason":"NotFound","code":404}),
                            ),
                            "/apis/tlb.io/v1alpha1/namespaces/apps/tunnelclasses/public" => (
                                200,
                                json!({
                                    "metadata":{"name":"public","namespace":"apps","uid":"class-uid"},"spec":{"cloudflare":{}}
                                }),
                            ),
                            "/apis/events.k8s.io/v1/namespaces/apps/events" => {
                                assert_eq!(request.method(), "POST");
                                let bytes = request.into_body().collect_bytes().await.unwrap();
                                let event: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                                assert_eq!(event["type"], "Warning");
                                assert_eq!(event["reason"], "ReconcileFailed");
                                assert_eq!(event["action"], "Reconcile");
                                assert_eq!(event["regarding"]["kind"], "Service");
                                assert_eq!(event["regarding"]["name"], "api");
                                assert_eq!(event["regarding"]["namespace"], "apps");
                                assert_eq!(event["regarding"]["uid"], "service-uid");
                                assert!(
                                    event["note"]
                                        .as_str()
                                        .unwrap()
                                        .contains("Cloudflare accepts one port mapping")
                                );
                                (
                                    event_status,
                                    if event_status == 201 {
                                        event
                                    } else {
                                        json!({"kind":"Status","status":"Failure","reason":"Forbidden","code":403})
                                    },
                                )
                            }
                            _ => panic!("unexpected API request: {path}"),
                        };
                        Ok::<_, std::io::Error>(
                            http::Response::builder()
                                .status(status)
                                .body(Body::from(serde_json::to_vec(&response).unwrap()))
                                .unwrap(),
                        )
                    }
                }),
                "default",
            );
            let data = Arc::new(Data {
                dns_lock: Default::default(),
                external_refresh: Duration::from_secs(300),
                events: SimpleEventRecorder::from_client(client.clone(), "test"),
                client,
                namespace: "tlb-system".into(),
                workload_policy: tlb::config::WorkloadPolicy::new("tlb-system", None, false).unwrap(),
                locks: Default::default(),
                bindings: Default::default(),
                failures: Default::default(),
            });
            let error = service_reconcile(Arc::new(service), data).await.unwrap_err();
            assert!(matches!(error, Error::ConfigError(_)));
            assert!(error.to_string().contains("Cloudflare accepts one port mapping"));
            assert_eq!(requests.lock().unwrap().len(), 4);
        }
    }

    #[test]
    fn scheduling_has_no_blanket_resync() {
        use tlb::ReconcileOutcome::*;
        let refresh = external_refresh(None).unwrap();
        assert_eq!(refresh, Duration::from_secs(300));
        assert_eq!(Settled.requeue_after(refresh), None);
        assert_eq!(DiscoveryPending.requeue_after(refresh), Some(Duration::from_secs(5)));
        assert_eq!(ExternalRefresh.requeue_after(refresh), Some(refresh));
        assert_eq!(external_refresh(Some("60")).unwrap(), Duration::from_secs(60));
        for invalid in ["0", "-1", "", "abc", "18446744073709551615"] {
            assert!(external_refresh(Some(invalid)).is_err());
        }
    }

    #[test]
    fn service_recreation_wakes_both_journals_and_journal_deletion_wakes_class() {
        use kube::runtime::reflector::store::Writer;
        let mut binding = Binding {
            secret: serde_json::from_value(json!({"metadata":{"name":"tlb-service-uid","namespace":"tlb-system","uid":"binding-uid"}})).unwrap(),
            data: serde_json::from_value(json!({
                "service":{"metadata":{"name":"api","namespace":"apps","uid":"service-uid"}},
                "class":{"metadata":{"name":"public","namespace":"apps","uid":"class-uid"},"namespaced":true,"spec":{"netbird":{"managementUrl":"https://example.com","setupKeyRef":{"name":"key","key":"key"}}}},
                "credentials":{}, "workload_namespace":"kube-system"
            })).unwrap(),
        };
        binding.secret.metadata.labels = Some(BTreeMap::from([
            (JOURNAL_LABEL.into(), "true".into()),
            (SERVICE_UID_LABEL.into(), "service-uid".into()),
            (CLASS_UID_LABEL.into(), "class-uid".into()),
        ]));
        binding.secret.data = Some(BTreeMap::from([(
            "binding.json".into(),
            k8s_openapi::ByteString(serde_json::to_vec(&binding.data).unwrap()),
        )]));
        let mut writer = Writer::<Secret>::default();
        writer.apply_watcher_event(&watcher::Event::Apply(binding.secret.clone()));
        let mut recreated = binding.data.service.clone();
        recreated.metadata.uid = Some("new-uid".into());
        let refs = affected_journals(&writer.as_reader(), &recreated);
        assert!(refs.iter().any(|r| r.name == "tlb-service-uid"));
        assert!(refs.iter().any(|r| r.name == "tlb-new-uid"));
        assert_eq!(
            journal_class::<TunnelClass>(&binding.secret, true),
            vec![ObjectRef::new("public").within("apps")]
        );
        assert!(journal_class::<ClusterTunnelClass>(&binding.secret, false).is_empty());
    }

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
