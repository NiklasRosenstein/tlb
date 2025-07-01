use std::sync::Arc;

use k8s_openapi::api::core::v1::Namespace;
use kube::{
    Resource,
    runtime::{
        controller::Action,
        events::{Event, EventType},
    },
};
use log::info;
use tlb::{Error, Reconcile};

use tlb::Result;
use tlb::crds::TunnelClassInnerSpec;

///
/// Context for the controller, containing the Kubernetes client and event recorder.
///
#[derive(Clone)]
struct Context {
    pub client: kube::Client,
    pub events: Arc<kube::runtime::events::Recorder>,
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
            return Err(Error::UnexpectedError(
                ".metadata.name is not set".to_string(),
            ));
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
            // if kube::api::Api::<tlb::crds::TunnelClass>::namespaced(
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
                kube::api::Api::<Namespace>::all(ctx.context.client.clone())
                    .get(namespace.as_ref().unwrap())
                    .await?,
            ]
        } else {
            kube::api::Api::<Namespace>::all(ctx.context.client.clone())
                .list(&kube::api::ListParams::default())
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
        let mut services: Vec<k8s_openapi::api::core::v1::Service> = Vec::new();
        for ns in &namespaces {
            let ns_name = ns.metadata.name.as_ref().unwrap();
            let svc_list = kube::api::Api::<k8s_openapi::api::core::v1::Service>::namespaced(
                ctx.context.client.clone(),
                ns_name,
            )
            .list(&kube::api::ListParams::default())
            .await?
            .into_iter()
            .filter(|svc| {
                svc.spec
                    .as_ref()
                    .and_then(|spec| spec.load_balancer_class.as_ref())
                    == Some(&load_balancer_class)
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
            info!(
                "Processing service `{}` in namespace `{}`",
                svc_name, svc_namespace
            );

            // Publish an event for the service reconciliation.
            ctx.context
                .events
                .publish(
                    &Event {
                        type_: EventType::Normal,
                        reason: "Processing".into(),
                        note: Some(format!(
                            "Reconciling service `{}` in namespace `{}` with tunnel class `{}`",
                            svc_name, svc_namespace, tunnel_class_name
                        )),
                        action: "Reconcile".into(),
                        secondary: None,
                    },
                    &service.object_ref(&()),
                )
                .await?

            // TODO
            // Here you would implement the logic to reconcile the service with the tunnel class.
            // This could involve updating annotations, labels, or other properties based on the
            // tunnel class specifications.
        }

        Ok(Action::await_change())
    }
}

pub async fn run() {
    let client = kube::Client::try_default()
        .await
        .expect("failed to create kube::Client");
    let context = Context {
        client: client.clone(),
        events: Arc::new(kube::runtime::events::Recorder::new(
            client,
            "tlb-controller".into(),
        )),
    };

    // Periodically reconcile all tunnel classes.
    // TODO: Instead, watch services and trigger a reconciliation when a service is created or updated?
    let reconcile_interval = std::time::Duration::from_secs(10);
    let mut interval = tokio::time::interval(reconcile_interval);
    loop {
        info!("Starting reconciliation cycle");

        let mut tunnel_classes = Vec::new();

        // Fetch all namespace-scoped tunnel classes.
        match kube::Api::<tlb::crds::TunnelClass>::all(context.client.clone())
            .list(&kube::api::ListParams::default())
            .await
        {
            Ok(resources) => tunnel_classes.extend(
                resources
                    .into_iter()
                    .map(|t| (t.spec.inner, t.metadata, true)),
            ),
            Err(e) => {
                info!("Failed to list TunnelClasses: {}", e);
            }
        };

        // Fetch all cluster-scoped tunnel classes.
        match kube::Api::<tlb::crds::ClusterTunnelClass>::all(context.client.clone())
            .list(&kube::api::ListParams::default())
            .await
        {
            Ok(resources) => tunnel_classes.extend(
                resources
                    .into_iter()
                    .map(|t| (t.spec.inner, t.metadata, false)),
            ),
            Err(e) => {
                info!("Failed to list ClusterTunnelClasses: {}", e);
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
