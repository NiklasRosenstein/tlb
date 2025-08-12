use k8s_openapi::api::{
    apps::v1::{Deployment, StatefulSet},
    core::v1::{Namespace, Secret, Service},
};
use kube::{
    Resource,
    api::{Api, ApiResource, DynamicObject, GroupVersionKind, ListParams, Patch, PatchParams},
    runtime::controller::Action,
};
use log::{error, info};
use serde_json::json;
use tlb::{
    Error, FOR_TUNNEL_CLASS_LABEL, PROVIDER_LABEL, Result, TunnelProvider,
    crds::{ClusterTunnelClass, TunnelClass, TunnelClassInnerSpec},
    simpleevent::SimpleEventRecorder,
};

use tlb::ReconcileContext;

const TUNNELCLASS_FINALIZER_NAME: &str = "tlb.io/finalizer";
const SERVICE_FINALIZER_NAME: &str = "tlb.io/tunnel-cleanup";
const LAST_OBSERVED_STATE_ANNOTATION: &str = "controller.tlb.io/last-observed-state";

/// Returns all deployments that were created by this tunnel class.
async fn get_deployments(ctx: &ReconcileContext) -> Result<Vec<Deployment>> {
    let tunnel_class_name = ctx.metadata.name.as_ref().unwrap();
    let deployment_api = Api::<Deployment>::all(ctx.client.clone());
    let deployments = deployment_api
        .list(&ListParams::default().labels(&format!("{FOR_TUNNEL_CLASS_LABEL}={tunnel_class_name}")))
        .await?;
    Ok(deployments.items)
}

async fn get_secrets(ctx: &ReconcileContext) -> Result<Vec<Secret>> {
    let tunnel_class_name = ctx.metadata.name.as_ref().unwrap();
    let secret_api = Api::<Secret>::all(ctx.client.clone());
    let secrets = secret_api
        .list(&ListParams::default().labels(&format!("{FOR_TUNNEL_CLASS_LABEL}={tunnel_class_name}")))
        .await?;
    Ok(secrets.items)
}

async fn get_statefulsets(ctx: &ReconcileContext) -> Result<Vec<StatefulSet>> {
    let tunnel_class_name = ctx.metadata.name.as_ref().unwrap();
    let statefulset_api = Api::<StatefulSet>::all(ctx.client.clone());
    let statefulsets = statefulset_api
        .list(&ListParams::default().labels(&format!("{FOR_TUNNEL_CLASS_LABEL}={tunnel_class_name}")))
        .await?;
    Ok(statefulsets.items)
}

/// Gets the current load balancer class for a service (if it's a tunnel provider)
fn get_current_tunnel_state(service: &Service) -> Option<String> {
    service
        .spec
        .as_ref()
        .and_then(|spec| spec.load_balancer_class.as_ref())
        .filter(|lbc| lbc.starts_with("tlb.io/"))
        .cloned()
}

/// Gets the last observed state from the service annotation
fn get_last_observed_state(service: &Service) -> Option<String> {
    service
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(LAST_OBSERVED_STATE_ANNOTATION))
        .cloned()
}

/// Updates the last observed state annotation on a service
async fn update_service_state_annotation(
    ctx: &ReconcileContext,
    service: &Service,
    new_state: Option<&str>,
) -> Result<()> {
    let service_name = service.metadata.name.as_ref().unwrap();
    let service_namespace = service.metadata.namespace.as_ref().unwrap();
    let service_api = Api::<Service>::namespaced(ctx.client.clone(), service_namespace);

    let patch = if let Some(state) = new_state {
        json!({
            "metadata": {
                "annotations": {
                    LAST_OBSERVED_STATE_ANNOTATION: state
                }
            }
        })
    } else {
        // Remove the annotation by setting it to null
        json!({
            "metadata": {
                "annotations": {
                    LAST_OBSERVED_STATE_ANNOTATION: null
                }
            }
        })
    };

    service_api
        .patch(service_name, &PatchParams::default(), &Patch::Merge(patch))
        .await?;

    if let Some(state) = new_state {
        info!("Updated last observed state for service `{service_name}` to `{state}`");
    } else {
        info!("Removed last observed state annotation from service `{service_name}`");
    }

    Ok(())
}

/// Gets the provider type for a given tunnel class spec
fn get_provider_type(tunnel_class_spec: &TunnelClassInnerSpec) -> Option<tlb::ProviderType> {
    // Determine which provider is configured for this tunnel class
    if tunnel_class_spec.cloudflare.is_some() {
        Some(tlb::ProviderType::Cloudflare)
    } else if tunnel_class_spec.netbird.is_some() {
        Some(tlb::ProviderType::Netbird)
    } else {
        None
    }
}

/// Converts a TunnelClassInnerSpec to a TunnelProvider instance with validation
fn get_provider_from_spec(spec: &TunnelClassInnerSpec) -> Result<Box<dyn TunnelProvider>> {
    match (&spec.netbird, &spec.cloudflare) {
        (Some(netbird), None) => Ok(Box::new(netbird.clone()) as Box<dyn TunnelProvider>),
        (None, Some(cloudflare)) => Ok(Box::new(cloudflare.clone()) as Box<dyn TunnelProvider>),
        (None, None) => Err(Error::UnexpectedError(
            "Tunnel class must have exactly one provider configured (netbird or cloudflare)".to_string(),
        )),
        (Some(_), Some(_)) => Err(Error::UnexpectedError(
            "Tunnel class must have exactly one provider configured, found multiple providers".to_string(),
        )),
    }
}

/// Looks up a tunnel class by name and returns its provider instance
async fn lookup_tunnel_class_provider(
    ctx: &ReconcileContext,
    tunnel_class_name: &str,
    service_namespace: &str,
) -> Result<Option<Box<dyn TunnelProvider>>> {
    // First try to find a namespaced tunnel class in the service's namespace
    let tunnel_class_api = Api::<TunnelClass>::namespaced(ctx.client.clone(), service_namespace);
    if let Ok(tunnel_class) = tunnel_class_api.get(tunnel_class_name).await {
        return Ok(Some(get_provider_from_spec(&tunnel_class.spec.inner)?));
    }

    // If not found, try cluster-scoped tunnel class
    let cluster_tunnel_class_api = Api::<ClusterTunnelClass>::all(ctx.client.clone());
    if let Ok(cluster_tunnel_class) = cluster_tunnel_class_api.get(tunnel_class_name).await {
        return Ok(Some(get_provider_from_spec(&cluster_tunnel_class.spec.inner)?));
    }

    Ok(None)
}

/// Handles Service finalizer logic and cleanup when a Service is being deleted
async fn handle_service_finalizer(ctx: &ReconcileContext, service: &Service) -> Result<bool> {
    let service_name = service.metadata.name.as_ref().unwrap();
    let service_namespace = service.metadata.namespace.as_ref().unwrap();
    let service_api = Api::<Service>::namespaced(ctx.client.clone(), service_namespace);

    // Check if the service is being deleted
    if service.metadata.deletion_timestamp.is_some() {
        info!("Service `{service_name}` in namespace `{service_namespace}` is being deleted, performing cleanup");

        // Get the tunnel class that was used for this service
        let current_state = get_current_tunnel_state(service);
        let last_observed_state = get_last_observed_state(service);

        // Use current state if available, otherwise fall back to last observed state
        let tunnel_class_state = current_state.or(last_observed_state);

        let mut cleanup_errors = Vec::new();

        if let Some(state) = tunnel_class_state {
            if let Some(tunnel_class_name) = state.strip_prefix("tlb.io/") {
                // Look up the tunnel class to get its provider configuration
                if let Some(provider) = lookup_tunnel_class_provider(ctx, tunnel_class_name, service_namespace).await? {
                    info!(
                        "Cleaning up service `{service_name}` with provider: {}",
                        provider.provider_type()
                    );
                    if let Err(e) = provider.cleanup_service(ctx, service).await {
                        error!(
                            "Provider '{}' cleanup failed for service '{}': {}",
                            provider.name(),
                            service_name,
                            e
                        );
                        cleanup_errors.push(format!("provider '{}': {}", provider.name(), e));
                    }
                } else {
                    error!(
                        "Could not find tunnel class '{tunnel_class_name}' for service '{service_name}' during cleanup"
                    );
                    cleanup_errors.push(format!("tunnel class '{tunnel_class_name}' not found"));
                }
            } else {
                error!("Invalid tunnel class state '{state}' for service '{service_name}' during cleanup");
                cleanup_errors.push(format!("invalid tunnel class state '{state}'"));
            }
        } else {
            // No tunnel class information available - this shouldn't happen if our finalizer logic is correct
            // but we'll handle it gracefully by trying to remove the finalizer anyway
            error!(
                "No tunnel class state found for service '{service_name}' during cleanup - removing finalizer anyway"
            );
        }

        // Only remove finalizer if ALL cleanup operations succeeded
        if cleanup_errors.is_empty() {
            // Remove our finalizer
            let current_finalizers = service.metadata.finalizers.as_ref().cloned().unwrap_or_default();
            let updated_finalizers: Vec<String> = current_finalizers
                .into_iter()
                .filter(|f| f != SERVICE_FINALIZER_NAME)
                .collect();

            service_api
                .patch(
                    service_name,
                    &PatchParams::default(),
                    &Patch::Merge(json!({
                        "metadata": {
                            "finalizers": updated_finalizers
                        }
                    })),
                )
                .await?;

            info!(
                "Removed finalizer from service `{service_name}` in namespace `{service_namespace}` - cleanup operations succeeded"
            );
        } else {
            // Create an event about the cleanup failures
            let event_msg = format!(
                "Cannot remove finalizer from service `{service_name}`: cleanup failed ({})",
                cleanup_errors.join(", ")
            );
            ctx.events
                .publish(
                    &service.object_ref(&()),
                    kube::runtime::events::EventType::Warning,
                    "CleanupFailed".into(),
                    Some(event_msg.clone()),
                    "Cleanup".into(),
                )
                .await?;

            error!(
                "Cleanup failed for service `{service_name}`, keeping finalizer in place: {}",
                cleanup_errors.join(", ")
            );
            // Don't return an error here - we want the controller to retry later
        }

        return Ok(true); // Service is being deleted, skip further processing
    }

    // Add finalizer if it's not present
    let has_finalizer = service
        .metadata
        .finalizers
        .as_ref()
        .map(|f| f.contains(&SERVICE_FINALIZER_NAME.to_string()))
        .unwrap_or(false);

    if !has_finalizer {
        let mut current_finalizers = service.metadata.finalizers.as_ref().cloned().unwrap_or_default();
        current_finalizers.push(SERVICE_FINALIZER_NAME.to_string());

        service_api
            .patch(
                service_name,
                &PatchParams::default(),
                &Patch::Merge(json!({
                    "metadata": {
                        "finalizers": current_finalizers
                    }
                })),
            )
            .await?;

        info!("Added finalizer to service `{service_name}` in namespace `{service_namespace}`");
    }

    Ok(false) // Service is not being deleted, continue processing
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
        .is_some_and(|f| f.contains(&TUNNELCLASS_FINALIZER_NAME.to_string()))
    {
        tunnel_class_api
            .patch(
                tunnel_class_name,
                &PatchParams::default(),
                &Patch::Merge(json!({
                    "metadata": {
                        "finalizers": [TUNNELCLASS_FINALIZER_NAME]
                    }
                })),
            )
            .await?;
    }

    // Check for provider transitions and emit warning events
    let current_provider_type = get_provider_type(tunnel_class);
    let last_observed_provider = ctx
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(PROVIDER_LABEL))
        .and_then(|s| match s.as_str() {
            "cloudflare" => Some(tlb::ProviderType::Cloudflare),
            "netbird" => Some(tlb::ProviderType::Netbird),
            _ => None,
        });

    if let (Some(current), Some(last)) = (current_provider_type, last_observed_provider) {
        if current != last {
            // Provider transition detected - emit warning event
            // Create a dummy object to get the object reference
            let dummy_object = if ctx.namespaced {
                DynamicObject::new(tunnel_class_name, &api_resource).within(ctx.metadata.namespace.as_ref().unwrap())
            } else {
                DynamicObject::new(tunnel_class_name, &api_resource)
            };

            ctx.events
                .publish(
                    &dummy_object.object_ref(&api_resource),
                    kube::runtime::events::EventType::Warning,
                    "ProviderTransitionNotSupported".into(),
                    Some(format!(
                        "Provider transition from {last} to {current} is not supported. Resources from the previous provider may not be cleaned up automatically. Consider deleting and recreating the tunnel class instead."
                    )),
                    "Reconcile".into(),
                )
                .await?;
        }
    }

    // Update the last observed provider annotation
    if let Some(current_provider) = current_provider_type {
        let provider_str = match current_provider {
            tlb::ProviderType::Cloudflare => "cloudflare",
            tlb::ProviderType::Netbird => "netbird",
        };

        tunnel_class_api
            .patch(
                tunnel_class_name,
                &PatchParams::default(),
                &Patch::Merge(json!({
                    "metadata": {
                        "annotations": {
                            PROVIDER_LABEL: provider_str
                        }
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

    // Collect all services across the namespaces that either:
    // 1. Currently match the load balancer class, or
    // 2. Have the last-observed-state annotation pointing to this tunnel class (for cleanup)
    let mut services: Vec<Service> = Vec::new();
    for ns in &namespaces {
        let ns_name = ns.metadata.name.as_ref().unwrap();
        let svc_list = Api::<Service>::namespaced(ctx.client.clone(), ns_name)
            .list(&ListParams::default())
            .await?
            .into_iter()
            .filter(|svc| {
                // Include services with current matching loadBalancerClass
                let has_current_class =
                    svc.spec.as_ref().and_then(|spec| spec.load_balancer_class.as_ref()) == Some(&load_balancer_class);

                // Include services with last-observed-state pointing to this tunnel class
                let has_last_observed = svc
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|annotations| annotations.get(LAST_OBSERVED_STATE_ANNOTATION))
                    .map(|state| state == &load_balancer_class)
                    .unwrap_or(false);

                has_current_class || has_last_observed
            });
        services.extend(svc_list);
    }
    info!(
        "Found {} service(s) with load balancer class `{load_balancer_class}` or last-observed-state in namespaces: {}",
        services.len(),
        namespaces
            .iter()
            .map(|ns| ns.metadata.name.clone().unwrap())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Validate that exactly one provider is configured and get the active provider
    let active_provider = get_provider_from_spec(tunnel_class)?;

    for service in services {
        // Handle Service finalizer logic and check if service is being deleted
        let service_being_deleted = handle_service_finalizer(ctx, &service).await?;

        // Skip further processing if service is being deleted
        if service_being_deleted {
            continue;
        }

        // Get current and last observed states
        let current_state = get_current_tunnel_state(&service);
        let last_observed_state = get_last_observed_state(&service);

        // If last observed state != current state, cleanup with previous provider
        if let Some(old_state) = &last_observed_state {
            if last_observed_state != current_state {
                if let Some(old_tunnel_class_name) = old_state.strip_prefix("tlb.io/") {
                    let service_namespace = service.metadata.namespace.as_ref().unwrap();
                    if let Some(old_provider) =
                        lookup_tunnel_class_provider(ctx, old_tunnel_class_name, service_namespace).await?
                    {
                        info!(
                            "Cleaning up service `{}` with old provider: {}",
                            service.metadata.name.as_ref().unwrap(),
                            old_provider.provider_type()
                        );
                        old_provider.cleanup_service(ctx, &service).await?;
                    }
                }
                // Update state annotation after successful cleanup
                update_service_state_annotation(ctx, &service, current_state.as_deref()).await?;
            }
        }

        // If load balancer class == current tunnel class, reconcile with current provider
        if current_state.as_ref() == Some(&load_balancer_class) {
            // Add Service finalizer if we're managing this service
            let has_finalizer = service
                .metadata
                .finalizers
                .as_ref()
                .map(|f| f.contains(&SERVICE_FINALIZER_NAME.to_string()))
                .unwrap_or(false);

            if !has_finalizer {
                let service_name = service.metadata.name.as_ref().unwrap();
                let service_namespace = service.metadata.namespace.as_ref().unwrap();
                let service_api = Api::<Service>::namespaced(ctx.client.clone(), service_namespace);

                let mut current_finalizers = service.metadata.finalizers.as_ref().cloned().unwrap_or_default();
                current_finalizers.push(SERVICE_FINALIZER_NAME.to_string());

                service_api
                    .patch(
                        service_name,
                        &PatchParams::default(),
                        &Patch::Merge(json!({
                            "metadata": {
                                "finalizers": current_finalizers
                            }
                        })),
                    )
                    .await?;

                info!("Added finalizer to service `{service_name}` in namespace `{service_namespace}`");
            }

            active_provider.reconcile_service(ctx, &service).await?;
        } else {
            // Service doesn't have matching loadBalancerClass - remove finalizer if present
            let has_finalizer = service
                .metadata
                .finalizers
                .as_ref()
                .map(|f| f.contains(&SERVICE_FINALIZER_NAME.to_string()))
                .unwrap_or(false);

            if has_finalizer {
                let service_name = service.metadata.name.as_ref().unwrap();
                let service_namespace = service.metadata.namespace.as_ref().unwrap();
                let service_api = Api::<Service>::namespaced(ctx.client.clone(), service_namespace);

                let current_finalizers = service.metadata.finalizers.as_ref().cloned().unwrap_or_default();
                let updated_finalizers: Vec<String> = current_finalizers
                    .into_iter()
                    .filter(|f| f != SERVICE_FINALIZER_NAME)
                    .collect();

                service_api
                    .patch(
                        service_name,
                        &PatchParams::default(),
                        &Patch::Merge(json!({
                            "metadata": {
                                "finalizers": updated_finalizers
                            }
                        })),
                    )
                    .await?;

                info!(
                    "Removed finalizer from service `{service_name}` in namespace `{service_namespace}` (no longer using tunnel class)"
                );
            }
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
                let tunnel_class_name = tunnel_class.1.name.as_deref().unwrap_or("<unknown>");
                let namespace = if tunnel_class.2 {
                    tunnel_class
                        .1
                        .namespace
                        .as_ref()
                        .map(|ns| format!(" in namespace '{ns}'"))
                        .unwrap_or_default()
                } else {
                    " (cluster-scoped)".to_string()
                };
                log::error!(
                    "Failed to reconcile TunnelClass '{}'{}: {} (in controller::reconcile at {}:{})",
                    tunnel_class_name,
                    namespace,
                    e,
                    file!(),
                    line!()
                );
                Action::requeue(reconcile_interval)
            });
        }

        interval.tick().await;
    }
}
