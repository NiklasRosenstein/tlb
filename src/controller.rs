use k8s_openapi::{
    api::core::v1::{Namespace, Service},
    apimachinery::pkg::apis::meta::v1::OwnerReference,
};
use kube::{
    Api, Resource,
    api::ListParams,
    runtime::{controller::Action, events::EventType},
};
use log::info;
use tlb::{Error, Reconcile, simpleevent::SimpleEventRecorder};

use tlb::Result;
use tlb::crds::TunnelClassInnerSpec;

///
/// Context for the controller, containing the Kubernetes client and event recorder.
///
#[derive(Clone)]
struct Context {
    pub client: kube::Client,
    pub events: SimpleEventRecorder,
}

///
/// Context for reconciling that includes the resource metadata. If reconciling a [`TunnelClass`],
/// the `namespaced` field is `true`. It is set to `false` when reconciling a [`ClusterTunnelClass`].
///
#[derive(Clone)]
struct ReconcileContext {
    pub context: Context,
    pub metadata: kube::api::ObjectMeta,
    pub namespaced: bool,
}

///
/// Reconciler implementation for cluster- and namespace-scoped tunnel classes. The resource scope
/// semantic is carried over via the [`ReconcileContext`].
///
#[async_trait::async_trait]
impl Reconcile<ReconcileContext> for TunnelClassInnerSpec {
    async fn reconcile(&self, ctx: &ReconcileContext) -> Result<Action> {
        // Validate the name and namespace fields in the metadata.
        if ctx.metadata.name.is_none() {
            return Err(Error::UnexpectedError(".metadata.name is not set".to_string()));
        }
        if ctx.namespaced && ctx.metadata.namespace.is_none() {
            return Err(Error::UnexpectedError(
                ".metadata.naamespace is not set for namespaced TunnelClass".to_string(),
            ));
        }

        let tunnel_class_name = ctx.metadata.name.as_ref().unwrap();
        let namespace = ctx.metadata.namespace.as_ref();

        // If this is a cluster-scoped tunnel class, and there is another namespaced tunnel class
        // with the same name, we should not reconcile it.
        if !ctx.namespaced {
            // TODO: We need to search for a same-named tunnel class in _all_ namespaces.
            //       We might want to get that information from the [`run`] function, as it
            //       already fetches all tunnel classes.
            // if Api::<tlb::crds::TunnelClass>::namespaced(
            //     ctx.context.client.clone(),
            //     &namespace.unwrap(),
            // )
            // .get_opt(&tunnel_class_name)
            // .await
            // .is_ok()
            // {
            //     // A namespaced tunnel class with the same name exists.
            //     return Ok(Action::await_change());
            // }
        }

        // Get all the namespaces that we are interested in.
        let namespaces: Vec<Namespace> = if ctx.namespaced {
            assert!(namespace.is_some());
            vec![
                Api::<Namespace>::all(ctx.context.client.clone())
                    .get(namespace.as_ref().unwrap())
                    .await?,
            ]
        } else {
            Api::<Namespace>::all(ctx.context.client.clone())
                .list(&ListParams::default())
                .await?
                .into_iter()
                .collect()
        };

        let load_balancer_class = format!("tlb.io/{tunnel_class_name}");
        info!(
            "Reconciling tunnel class `{}` in namespaces: {}",
            tunnel_class_name,
            namespaces
                .iter()
                .map(|ns| ns.metadata.name.clone().unwrap())
                .collect::<Vec<_>>()
                .join(", ")
        );

        // Collect all services across the namespaces that match the load balancer class.
        let mut services: Vec<Service> = Vec::new();
        for ns in &namespaces {
            let ns_name = ns.metadata.name.as_ref().unwrap();
            let svc_list = Api::<Service>::namespaced(ctx.context.client.clone(), ns_name)
                .list(&ListParams::default())
                .await?
                .into_iter()
                .filter(|svc| {
                    svc.spec.as_ref().and_then(|spec| spec.load_balancer_class.as_ref()) == Some(&load_balancer_class)
                });
            services.extend(svc_list);
        }
        info!(
            "Found {} matching service(s) with load balancer class `{}` in namespaces: {}",
            services.len(),
            load_balancer_class,
            namespaces
                .iter()
                .map(|ns| ns.metadata.name.clone().unwrap())
                .collect::<Vec<_>>()
                .join(", ")
        );

        // Process each individual service.
        for service in services {
            let svc_name = service.metadata.name.as_ref().unwrap();
            let svc_namespace = service.metadata.namespace.as_ref().unwrap();
            info!("Processing service `{svc_name}` in namespace `{svc_namespace}`");

            // Publish an event for the service reconciliation.
            ctx.context
                .events
                .publish(
                    &service.object_ref(&()),
                    EventType::Normal,
                    "Processing".into(),
                    Some(format!(
                        "Reconciling service `{svc_name}` in namespace `{svc_namespace}` with tunnel class `{tunnel_class_name}`"
                    )),
                    "Reconcile".into(),
                )
                .await?;

            let options = tlb::ServiceAnnotations::from(service.metadata.annotations.clone().unwrap_or_default());

            let owner_references = vec![
                OwnerReference {
                    api_version: "v1".into(),
                    kind: "Service".into(),
                    name: svc_name.clone(),
                    uid: service.metadata.uid.clone().unwrap_or_default(),
                    controller: Some(false),
                    block_owner_deletion: Some(true),
                },
                OwnerReference {
                    api_version: "tlb.io/v1alpha1".into(),
                    kind: if ctx.namespaced {
                        "TunnelClass".into()
                    } else {
                        "ClusterTunnelClass".into()
                    },
                    name: tunnel_class_name.to_string(),
                    uid: ctx.metadata.uid.clone().unwrap_or_default(),
                    controller: Some(true),
                    block_owner_deletion: Some(true),
                },
            ];

            if let Some(netbird) = self.netbird.clone() {
                tlb::netbird::reconcile_netbird_service(
                    &ctx.context.client,
                    &ctx.context.events,
                    owner_references,
                    service,
                    options,
                    netbird,
                )
                .await?;
            }
        }

        Ok(Action::await_change())
    }
}

pub async fn run(reconcile_interval: std::time::Duration) {
    let client = kube::Client::try_default()
        .await
        .expect("failed to create kube::Client");
    let context = Context {
        client: client.clone(),
        events: SimpleEventRecorder::from_client(client, "tlb-controller"),
    };

    // Periodically reconcile all tunnel classes.
    // TODO: Instead, watch services and trigger a reconciliation when a service is created or updated?
    let mut interval = tokio::time::interval(reconcile_interval);
    loop {
        info!("Starting reconciliation cycle");

        let mut tunnel_classes = Vec::new();

        // Fetch all namespace-scoped tunnel classes.
        match Api::<tlb::crds::TunnelClass>::all(context.client.clone())
            .list(&ListParams::default())
            .await
        {
            Ok(resources) => tunnel_classes.extend(resources.into_iter().map(|t| (t.spec.inner, t.metadata, true))),
            Err(e) => {
                info!("Failed to list TunnelClasses: {e}");
            }
        };

        // Fetch all cluster-scoped tunnel classes.
        match Api::<tlb::crds::ClusterTunnelClass>::all(context.client.clone())
            .list(&ListParams::default())
            .await
        {
            Ok(resources) => tunnel_classes.extend(resources.into_iter().map(|t| (t.spec.inner, t.metadata, false))),
            Err(e) => {
                info!("Failed to list ClusterTunnelClasses: {e}");
            }
        };

        for tunnel_class in tunnel_classes {
            let ctx = ReconcileContext {
                context: context.clone(),
                metadata: tunnel_class.1.clone(),
                namespaced: tunnel_class.2,
            };
            tunnel_class.0.reconcile(&ctx).await.unwrap_or_else(|e| {
                info!(
                    "Failed to reconcile TunnelClass {}: {}",
                    tunnel_class.1.name.unwrap(),
                    e
                );
                Action::requeue(reconcile_interval)
            });
        }

        interval.tick().await;
    }
}
