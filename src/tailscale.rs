use std::collections::BTreeMap;

use k8s_openapi::{
    api::{
        apps::v1::{Deployment, DeploymentSpec},
        core::v1::{
            Capabilities, Container, EnvVar, EnvVarSource, LoadBalancerIngress, PodSpec,
            PodTemplateSpec, SecretKeySelector, SecurityContext, Service, ServiceStatus,
        },
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference},
};
use kube::{
    api::{ObjectMeta, Patch, PatchParams},
    Api, Client,
};
use log::info;
use serde_json::json;

use crate::{
    crds::TailscaleConfig, simpleevent::SimpleEventRecorder, Error, Result, ServiceAnnotations,
};

const DEFAULT_TAILSCALE_IMAGE: &str = "ghcr.io/tailscale/tailscale:latest";

#[allow(clippy::too_many_arguments)]
pub async fn reconcile_tailscale_service(
    client: &Client,
    _events: &SimpleEventRecorder,
    owner_references: Vec<OwnerReference>,
    service: Service,
    options: ServiceAnnotations,
    tailscale: TailscaleConfig,
) -> Result<()> {
    let svc_name = service
        .metadata
        .name
        .as_ref()
        .ok_or(Error::UnexpectedError(format!("Service does not have a name: {:?}", service)))?;
    let svc_namespace = service
        .metadata
        .namespace
        .as_ref()
        .ok_or(Error::UnexpectedError(format!(
            "Service `{}` does not have a namespace",
            svc_name
        )))?;
    let cluster_ip = match service.spec.as_ref().and_then(|s| s.cluster_ip.clone()) {
        Some(ip) => ip,
        None => {
            return Err(Error::UnexpectedError("Service does not have a cluster IP".to_string()));
        }
    };

    let deployment_namespace =
        tailscale.auth_key_secret_ref.namespace.unwrap_or(svc_namespace.clone());

    let _deployment_api = Api::<Deployment>::namespaced(client.clone(), &deployment_namespace);
    let svc_api = Api::<Service>::namespaced(client.clone(), svc_namespace);

    let match_labels = BTreeMap::from([
        ("app.kubernetes.io/name".to_string(), "tailscale".to_string()),
        ("app.kubernetes.io/instance".to_string(), svc_name.to_string()),
        ("controller.tlb.io/for-service".to_string(), svc_name.clone()),
    ]);

    let deployment_prefix = tailscale.deployment_prefix.unwrap_or_else(|| "tunnel-".to_string());
    let deployment_name = format!("{deployment_prefix}{svc_name}");

    let env = vec![
        EnvVar {
            name: "TS_KUBE_SECRET".into(),
            value: Some(tailscale.auth_key_secret_ref.name.clone()),
            ..Default::default()
        },
        EnvVar {
            name: "TS_AUTHKEY".into(),
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    name: tailscale.auth_key_secret_ref.name,
                    key: tailscale.auth_key_secret_ref.key,
                    optional: Some(false),
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
        EnvVar {
            name: "TS_USERSPACE".into(),
            value: Some("false".into()),
            ..Default::default()
        },
        EnvVar {
            name: "TS_DEST_IP".into(),
            value: Some(cluster_ip),
            ..Default::default()
        },
    ];

    // Construct the node selector from the service annotations.
    let node_selector = crate::deployment::get_node_selector(&options);
    let affinity = crate::deployment::get_affinity(&options, match_labels.clone());
    let deployment_strategy = crate::deployment::get_deployment_strategy(&options);

    let deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(deployment_name.clone()),
            namespace: Some(deployment_namespace.clone()),
            owner_references: Some(owner_references),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(options.replicas),
            selector: LabelSelector {
                match_labels: Some(match_labels.clone()),
                ..Default::default()
            },
            strategy: Some(deployment_strategy),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(match_labels.clone()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    node_selector: Some(node_selector),
                    affinity: Some(affinity),
                    init_containers: Some(vec![Container {
                        name: "sysctler".into(),
                        image: Some("busybox:latest".into()),
                        security_context: Some(SecurityContext {
                            privileged: Some(true),
                            ..Default::default()
                        }),
                        command: Some(vec!["/bin/sh".into()]),
                        args: Some(vec![
                            "-c".into(),
                            "sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1".into(),
                        ]),
                        ..Default::default()
                    }]),
                    containers: vec![Container {
                        name: "tailscale".into(),
                        image: Some(tailscale.image.unwrap_or(DEFAULT_TAILSCALE_IMAGE.into())),
                        env: Some(env),
                        security_context: Some(SecurityContext {
                            capabilities: Some(Capabilities {
                                add: Some(vec!["NET_ADMIN".into()]),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    crate::deployment::create_or_patch_deployment(client, &deployment_namespace, &deployment).await?;

    let lb_ingress = vec![LoadBalancerIngress {
        hostname: Some(deployment_name.clone()),
        ..Default::default()
    }];

    let status = ServiceStatus {
        load_balancer: Some(k8s_openapi::api::core::v1::LoadBalancerStatus {
            ingress: Some(lb_ingress),
        }),
        ..Default::default()
    };

    let new_status = Patch::Apply(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "status": status
    }));

    let ps = PatchParams::apply("tlb-controller").force();
    svc_api.patch_status(svc_name, &ps, &new_status).await?;

    info!("Patched status for service `{}`", svc_name);

    Ok(())
}
