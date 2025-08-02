use std::collections::HashSet;

use k8s_openapi::{
    api::{
        apps::v1::Deployment,
        core::v1::{Namespace, Service},
    },
    apimachinery::pkg::apis::meta::v1::OwnerReference,
};
use kube::{
    api::{Api, ApiResource, DynamicObject, GroupVersionKind, ListParams, Patch, PatchParams, Resource},
    runtime::{controller::Action, events::EventType},
};
use log::info;
use serde_json::json;
use tlb::{
    crds::{ClusterTunnelClass, TunnelClass, TunnelClassInnerSpec},
    simpleevent::SimpleEventRecorder,
    Error, Result,
};

const FINALIZER_NAME: &str = "tlb.io/finalizer";

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

/// Returns all deployments that were created by this tunnel class.
async fn get_deployments(ctx: &ReconcileContext) -> Result<Vec<Deployment>> {
    let tunnel_class_name = ctx.metadata.name.as_ref().unwrap();
    let deployment_api = Api::<Deployment>::all(ctx.context.client.clone());
    let deployments = deployment_api
        .list(&ListParams::default().labels(&format!("tlb.io/tunnel-class={}", tunnel_class_name)))
        .await?;
    Ok(deployments.items)
}

async fn reconcile(
    tunnel_class: &TunnelClassInnerSpec,
    ctx: &ReconcileContext,
) -> Result<Action> {
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

    let api_resource = if ctx.namespaced {
        ApiResource::from_gvk(&GroupVersionKind::gvk("tlb.io", "v1alpha1", "TunnelClass"))
    } else {
        ApiResource::from_gvk(&GroupVersionKind::gvk(
            "tlb.io",
            "v1alpha1",
            "ClusterTunnelClass",
        ))
    };

    let tunnel_class_api: Api<DynamicObject> = if ctx.namespaced {
        Api::namespaced_with(
            ctx.context.client.clone(),
            ctx.metadata.namespace.as_ref().unwrap(),
            &api_resource,
        )
    } else {
        Api::all_with(ctx.context.client.clone(), &api_resource)
    };

    if ctx.metadata.deletion_timestamp.is_some() {
        info!("Deleting tunnel class `{}`", tunnel_class_name);

        // Clean up all deployments that were created by this tunnel class.
        let deployments = get_deployments(ctx).await?;
        for deployment in deployments {
            let deployment_name = deployment.metadata.name.as_ref().unwrap();
            let deployment_namespace = deployment.metadata.namespace.as_ref().unwrap();
            info!(
                "Deleting deployment `{}` in namespace `{}`",
                deployment_name, deployment_namespace
            );
            Api::<Deployment>::namespaced(ctx.context.client.clone(), deployment_namespace)
                .delete(deployment_name, &Default::default())
                .await?;
        }

        // Remove the finalizer.
        tunnel_class_api
            .patch(
                tunnel_class_name,
                &PatchParams::default(),
                &Patch::Merge(json!({
                    "metadata": {
                        "finalizers": null
                    }
                })),
            )
            .await?;

        return Ok(Action::await_change());
    }

    // Add the finalizer if it's not present.
    if !ctx
        .metadata
        .finalizers
        .as_ref()
        .map_or(false, |f| f.contains(&FINALIZER_NAME.to_string()))
    {
        tunnel_class_api
            .patch(
                tunnel_class_name,
                &PatchParams::default(),
                &Patch::Merge(json!({
                    "metadata": {
                        "finalizers": [FINALIZER_NAME]
                    }
                })),
            )
            .await?;
    }

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

    // Clean up orphaned deployments.
    let services_with_lb_class: HashSet<String> =
        services.iter().map(|s| s.metadata.name.clone().unwrap()).collect();

    for ns in &namespaces {
        let deployment_api =
            Api::<Deployment>::namespaced(ctx.context.client.clone(), ns.metadata.name.as_ref().unwrap());
        let deployments = deployment_api
            .list(&ListParams::default().labels(&format!("tlb.io/tunnel-class={}", tunnel_class_name)))
            .await?;

        for deployment in deployments {
            let deployment_name = deployment.metadata.name.as_ref().unwrap();
            let service_name_label = deployment
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get("controller.tlb.io/for-service"));

            if let Some(service_name) = service_name_label {
                if !services_with_lb_class.contains(service_name) {
                    info!(
                        "Deleting orphaned deployment `{}` for service `{}`",
                        deployment_name, service_name
                    );
                    deployment_api.delete(deployment_name, &Default::default()).await?;
                }
            }
        }
    }

    // Process each individual service.
    for service in services {
        let svc_name = service.metadata.name.as_ref().unwrap();
        let svc_namespace = service.metadata.namespace.as_ref().unwrap();
        info!("Processing service `{}` in namespace `{}`", svc_name, svc_namespace);

        // Publish an event for the service reconciliation.
        ctx.context
            .events
            .publish(
                &service.object_ref(&()),
                EventType::Normal,
                "Processing".into(),
                Some(format!(
                    "Reconciling service `{}` in namespace `{}` with tunnel class `{}`",
                    svc_name, svc_namespace, tunnel_class_name
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

        if let Some(netbird) = tunnel_class.netbird.clone() {
            tlb::netbird::reconcile_netbird_service(
                &ctx.context.client,
                &ctx.context.events,
                owner_references,
                service,
                options,
                netbird,
                tunnel_class_name,
            )
            .await?;
        }
    }

    Ok(Action::await_change())
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
        match Api::<TunnelClass>::all(context.client.clone())
            .list(&ListParams::default())
            .await
        {
            Ok(resources) => {
                tunnel_classes.extend(resources.into_iter().map(|t| (t.spec.inner, t.metadata, true)))
            }
            Err(e) => {
                info!("Failed to list TunnelClasses: {}", e);
            }
        };

        // Fetch all cluster-scoped tunnel classes.
        match Api::<ClusterTunnelClass>::all(context.client.clone())
            .list(&ListParams::default())
            .await
        {
            Ok(resources) => tunnel_classes
                .extend(resources.into_iter().map(|t| (t.spec.inner, t.metadata, false))),
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
            reconcile(&tunnel_class.0, &ctx)
                .await
                .unwrap_or_else(|e| {
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
