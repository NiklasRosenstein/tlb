use std::collections::HashSet;

use k8s_openapi::api::{
    apps::v1::{Deployment, StatefulSet},
    core::v1::{Namespace, Secret, Service},
};
use kube::{
    api::{Api, ApiResource, DynamicObject, GroupVersionKind, ListParams, Patch, PatchParams},
    runtime::controller::Action,
};
use log::info;
use serde_json::json;
use tlb::{
    Error, Result, TunnelProvider,
    crds::{ClusterTunnelClass, TunnelClass, TunnelClassInnerSpec},
    simpleevent::SimpleEventRecorder,
};

use tlb::ReconcileContext;

const FINALIZER_NAME: &str = "tlb.io/finalizer";

/// Returns all deployments that were created by this tunnel class.
async fn get_deployments(ctx: &ReconcileContext) -> Result<Vec<Deployment>> {
    let tunnel_class_name = ctx.metadata.name.as_ref().unwrap();
    let deployment_api = Api::<Deployment>::all(ctx.client.clone());
    let deployments = deployment_api
        .list(&ListParams::default().labels(&format!("tlb.io/tunnel-class={tunnel_class_name}")))
        .await?;
    Ok(deployments.items)
}

async fn get_secrets(ctx: &ReconcileContext) -> Result<Vec<Secret>> {
    let tunnel_class_name = ctx.metadata.name.as_ref().unwrap();
    let secret_api = Api::<Secret>::all(ctx.client.clone());
    let secrets = secret_api
        .list(&ListParams::default().labels(&format!("tlb.io/tunnel-class={tunnel_class_name}")))
        .await?;
    Ok(secrets.items)
}

async fn get_statefulsets(ctx: &ReconcileContext) -> Result<Vec<StatefulSet>> {
    let tunnel_class_name = ctx.metadata.name.as_ref().unwrap();
    let statefulset_api = Api::<StatefulSet>::all(ctx.client.clone());
    let statefulsets = statefulset_api
        .list(&ListParams::default().labels(&format!("tlb.io/tunnel-class={tunnel_class_name}")))
        .await?;
    Ok(statefulsets.items)
}

async fn reconcile(tunnel_class: &TunnelClassInnerSpec, ctx: &ReconcileContext) -> Result<Action> {
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
        ApiResource::from_gvk(&GroupVersionKind::gvk("tlb.io", "v1alpha1", "ClusterTunnelClass"))
    };

    let tunnel_class_api: Api<DynamicObject> = if ctx.namespaced {
        Api::namespaced_with(
            ctx.client.clone(),
            ctx.metadata.namespace.as_ref().unwrap(),
            &api_resource,
        )
    } else {
        Api::all_with(ctx.client.clone(), &api_resource)
    };

    if ctx.metadata.deletion_timestamp.is_some() {
        info!("Deleting tunnel class `{tunnel_class_name}`");

        // Clean up all deployments that were created by this tunnel class.
        let deployments = get_deployments(ctx).await?;
        for deployment in deployments {
            let deployment_name = deployment.metadata.name.as_ref().unwrap();
            let deployment_namespace = deployment.metadata.namespace.as_ref().unwrap();
            info!("Deleting deployment `{deployment_name}` in namespace `{deployment_namespace}`");
            Api::<Deployment>::namespaced(ctx.client.clone(), deployment_namespace)
                .delete(deployment_name, &Default::default())
                .await?;
        }

        // Clean up all statefulsets that were created by this tunnel class.
        let statefulsets = get_statefulsets(ctx).await?;
        for statefulset in statefulsets {
            let statefulset_name = statefulset.metadata.name.as_ref().unwrap();
            let statefulset_namespace = statefulset.metadata.namespace.as_ref().unwrap();
            info!("Deleting statefulset `{statefulset_name}` in namespace `{statefulset_namespace}`");
            Api::<StatefulSet>::namespaced(ctx.client.clone(), statefulset_namespace)
                .delete(statefulset_name, &Default::default())
                .await?;
        }

        // Clean up all secrets that were created by this tunnel class.
        let secrets = get_secrets(ctx).await?;
        for secret in secrets {
            let secret_name = secret.metadata.name.as_ref().unwrap();
            let secret_namespace = secret.metadata.namespace.as_ref().unwrap();
            info!("Deleting secret `{secret_name}` in namespace `{secret_namespace}`");
            Api::<Secret>::namespaced(ctx.client.clone(), secret_namespace)
                .delete(secret_name, &Default::default())
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
        .is_some_and(|f| f.contains(&FINALIZER_NAME.to_string()))
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
            Api::<Namespace>::all(ctx.client.clone())
                .get(namespace.as_ref().unwrap())
                .await?,
        ]
    } else {
        Api::<Namespace>::all(ctx.client.clone())
            .list(&ListParams::default())
            .await?
            .into_iter()
            .collect()
    };

    let load_balancer_class = format!("tlb.io/{tunnel_class_name}");
    info!(
        "Reconciling tunnel class `{tunnel_class_name}` in namespaces: {}",
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
        let svc_list = Api::<Service>::namespaced(ctx.client.clone(), ns_name)
            .list(&ListParams::default())
            .await?
            .into_iter()
            .filter(|svc| {
                svc.spec.as_ref().and_then(|spec| spec.load_balancer_class.as_ref()) == Some(&load_balancer_class)
            });
        services.extend(svc_list);
    }
    info!(
        "Found {} matching service(s) with load balancer class `{load_balancer_class}` in namespaces: {}",
        services.len(),
        namespaces
            .iter()
            .map(|ns| ns.metadata.name.clone().unwrap())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Clean up orphaned deployments.
    let services_with_lb_class: HashSet<String> = services.iter().map(|s| s.metadata.name.clone().unwrap()).collect();

    for ns in &namespaces {
        let deployment_api = Api::<Deployment>::namespaced(ctx.client.clone(), ns.metadata.name.as_ref().unwrap());
        let deployments = deployment_api
            .list(&ListParams::default().labels(&format!("tlb.io/tunnel-class={tunnel_class_name}")))
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
                    info!("Deleting orphaned deployment `{deployment_name}` for service `{service_name}`");
                    deployment_api.delete(deployment_name, &Default::default()).await?;
                }
            }
        }
    }

    // Clean up orphaned secrets.
    for ns in &namespaces {
        let secret_api = Api::<Secret>::namespaced(ctx.client.clone(), ns.metadata.name.as_ref().unwrap());
        let secrets = secret_api
            .list(&ListParams::default().labels(&format!("tlb.io/tunnel-class={tunnel_class_name}")))
            .await?;

        for secret in secrets {
            let secret_name = secret.metadata.name.as_ref().unwrap();
            let service_name_label = secret
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get("tlb.io/for-service"));

            if let Some(service_name) = service_name_label {
                if !services_with_lb_class.contains(service_name) {
                    info!("Deleting orphaned secret `{secret_name}` for service `{service_name}`");
                    secret_api.delete(secret_name, &Default::default()).await?;
                }
            }
        }
    }

    let all_providers: Vec<Box<dyn TunnelProvider>> = vec![
        Box::new(tlb::crds::NetbirdConfig::default()),
        Box::new(tlb::crds::CloudflareConfig::default()),
    ];

    let active_providers: Vec<Box<dyn TunnelProvider>> = vec![
        tunnel_class
            .netbird
            .as_ref()
            .map(|c| Box::new(c.clone()) as Box<dyn TunnelProvider>),
        tunnel_class
            .cloudflare
            .as_ref()
            .map(|c| Box::new(c.clone()) as Box<dyn TunnelProvider>),
    ]
    .into_iter()
    .flatten()
    .collect();

    // Process each individual service.
    for service in services {
        // Cleanup resources from providers that are no longer configured.
        for provider_to_cleanup in all_providers.iter() {
            if !active_providers.iter().any(|p| p.name() == provider_to_cleanup.name()) {
                provider_to_cleanup.cleanup_service(ctx, &service).await?;
            }
        }

        // Reconcile for the current providers.
        for provider in active_providers.iter() {
            provider.reconcile_service(ctx, &service).await?;
        }
    }

    Ok(Action::await_change())
}

pub async fn run(reconcile_interval: std::time::Duration) {
    let client = kube::Client::try_default()
        .await
        .expect("failed to create kube::Client");
    let events = SimpleEventRecorder::from_client(client.clone(), "tlb-controller");

    // Periodically reconcile all tunnel classes.
    // TODO: Instead, watch services and trigger a reconciliation when a service is created or updated?
    let mut interval = tokio::time::interval(reconcile_interval);
    loop {
        info!("Starting reconciliation cycle");

        let mut tunnel_classes = Vec::new();

        // Fetch all namespace-scoped tunnel classes.
        match Api::<TunnelClass>::all(client.clone())
            .list(&ListParams::default())
            .await
        {
            Ok(resources) => tunnel_classes.extend(resources.into_iter().map(|t| (t.spec.inner, t.metadata, true))),
            Err(e) => {
                info!("Failed to list TunnelClasses: {e}");
            }
        };

        // Fetch all cluster-scoped tunnel classes.
        match Api::<ClusterTunnelClass>::all(client.clone())
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
                client: client.clone(),
                events: events.clone(),
                metadata: tunnel_class.1.clone(),
                namespaced: tunnel_class.2,
            };
            reconcile(&tunnel_class.0, &ctx).await.unwrap_or_else(|e| {
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
