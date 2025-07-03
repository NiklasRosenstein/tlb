use std::collections::BTreeMap;

use k8s_openapi::{
    api::{
        apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy},
        core::v1::{
            Affinity, Capabilities, Container, EnvVar, EnvVarSource, PodSpec, PodTemplateSpec, SecretKeySelector,
            SecurityContext, Service, ServicePort, ServiceStatus,
        },
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference},
};
use kube::{
    Api, Client, Resource,
    api::{ObjectMeta, Patch, PatchParams},
    runtime::events::EventType,
};
use log::info;
use serde_json::json;

use crate::{Error, Result, ServiceAnnotations, crds::NetbirdConfig, simpleevent::SimpleEventRecorder};

const DEFAULT_CLUSTER_INTERFACE: &str = "eth0";
const DEFAULT_NETBIRD_INTERFACE: &str = "wt0";
const DEFAULT_NETBIRD_IMAGE: &str = "netbirdio/netbird:latest";
const DEFAULT_NETBIRD_ENTRYPOINT: &str = "/usr/local/bin/netbird up";

///
/// Generates a shell script that sets up iptables rules for forwarding traffic coming in to the Netbird interface
/// and launches the Netbird service.
///
fn get_netbird_launch_script(service_ip: &String, ports: &[ServicePort]) -> String {
    let cluster_iface = DEFAULT_CLUSTER_INTERFACE;
    let netbird_iface = DEFAULT_NETBIRD_INTERFACE;
    let mut launch_script = vec!["#!/bin/sh".to_string(), "set -e".to_string()];

    ports.iter().for_each(|port| {
        let protocol = port.protocol.as_ref().unwrap_or(&"TCP".to_string()).to_lowercase();
        let port = port.port;

        // Accept new connections to the cluster IP and port.
        launch_script.push(format!(
            "iptables -A FORWARD -i {netbird_iface} -o {cluster_iface} -p {protocol} -d {service_ip} --dport {port} -m conntrack --ctstate NEW -j ACCEPT"
        ));

        // Accept established connections to the cluster IP and port.
        launch_script.push(format!(
            "iptables -A FORWARD -i {netbird_iface} -o {cluster_iface} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        ));
        launch_script.push(format!(
            "iptables -A FORWARD -i {cluster_iface} -o {netbird_iface} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        ));

        // NAT packets destined for the cluster IP and port.
        launch_script.push(format!(
            "iptables -t nat -I PREROUTING 1 -i {netbird_iface} -p {protocol} --dport {port} -j DNAT --to-destination {service_ip}:{port}"
        ));

        launch_script.push(format!(
            "iptables -t nat -A POSTROUTING -o {cluster_iface} -j MASQUERADE"
        ));
    });

    launch_script.push(DEFAULT_NETBIRD_ENTRYPOINT.to_string());
    launch_script.join("\n")
}

///
/// Given a Kubernetes `Service` object, that, assuming it does point or used to point to one of our tunnel
/// load balancer classes, reconcile the Netbird service by creating or updating a Deployment that runs the Netbird
/// service with NAT-ed forwarding rules for the service's cluster IP and ports.
///
pub async fn reconcile_netbird_service(
    client: &Client,
    events: &SimpleEventRecorder,
    owner_references: Vec<OwnerReference>,
    service: Service,
    options: ServiceAnnotations,
    netbird: NetbirdConfig,
) -> Result<()> {
    let svc_name = service.metadata.name.as_ref().ok_or(Error::UnexpectedError(format!(
        "Service does not have a name: {:?}",
        service
    )))?;
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
    let ports = match service.spec.as_ref().and_then(|s| s.ports.clone()) {
        Some(ports) => ports,
        None => {
            events
                .publish(
                    &service.object_ref(&()),
                    EventType::Warning,
                    "MissingPorts".into(),
                    Some("No ports defined.".to_string()),
                    "Reconcile".into(),
                )
                .await?;
            Vec::new()
        }
    };

    // We need to run in the same namespace that has the secret. If the namespace of the secret is
    // not specified, we assume we're in a namespaced tunnel, so the secret and the service will
    // be in the same namespace.
    let deployment_namespace = netbird.setup_key_ref.namespace.unwrap_or(svc_namespace.clone());

    let deployment_api = Api::<Deployment>::namespaced(client.clone(), &deployment_namespace);
    let svc_api = Api::<Service>::namespaced(client.clone(), svc_namespace);

    // Labels to match on for the Deployment.
    let match_labels = BTreeMap::from([
        ("app.kubernetes.io/name".to_string(), "netbird".to_string()),
        ("app.kubernetes.io/instance".to_string(), svc_name.to_string()),
        ("controller.tlb.io/for-service".to_string(), svc_name.clone()),
    ]);

    // Construct commands for setting up iptables in the Netbird pod.
    let launch_script = get_netbird_launch_script(&cluster_ip, &ports);

    let mut env = vec![
        EnvVar {
            name: "NB_MANAGEMENT_URL".into(),
            value: Some(netbird.management_url),
            ..Default::default()
        },
        EnvVar {
            name: "NB_SETUP_KEY".into(),
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    name: netbird.setup_key_ref.name,
                    key: netbird.setup_key_ref.key,
                    optional: Some(false),
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
    ];

    let mut lb_ingress_host: Option<String> = None;
    if let Some(dns) = &options.dns {
        // Split the netbird DNS name.
        let netbird_dns_domain = netbird
            .netbird_dns_domain
            .clone()
            .unwrap_or_else(|| "netbird.selfhosted".to_string());
        let dns_names = dns
            .split(',')
            .map(|s| s.trim())
            .map(|s| s.strip_suffix(&format!(".{netbird_dns_domain}")).unwrap_or(s))
            .collect::<Vec<_>>();

        // We use the first DNS name as the load balancer ingress host.
        if let Some(first_dns) = dns_names.first() {
            lb_ingress_host = Some(format!("{}.{netbird_dns_domain}", first_dns));
        }

        // Add the DNS names as environment variables.
        env.push(EnvVar {
            name: "NB_EXTRA_DNS_LABELS".into(),
            value: Some(dns_names.join(",")),
            ..Default::default()
        });
    } else {
        events
            .publish(
                &service.object_ref(&()),
                EventType::Warning,
                "MissingDNSAnnotation".into(),
                Some(format!(
                    "Service `{}` in namespace `{}` does not have the `tlb.io/dns` annotation set. \
                                The controller cannot determine the IP addresses assigned to the tunnel peers,
                                hence the LoadBalancer status will stay `Pending`.",
                    svc_name, svc_namespace
                )),
                "Reconcile".into(),
            )
            .await?;
    }

    // Construct the node selector from the service annotations.
    let node_selector: BTreeMap<String, String> = if let Some(node_selector_str) = &options.node_selector {
        node_selector_str
            .split(',')
            .map(|s| s.trim())
            .filter_map(|s| {
                let mut parts = s.splitn(2, '=');
                if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                    Some((key.to_string(), value.to_string()))
                } else {
                    None
                }
            })
            .collect()
    } else {
        BTreeMap::new()
    };

    // Construct anti-affinity rules based on topology key.
    let affinity = Affinity {
        pod_anti_affinity: Some(k8s_openapi::api::core::v1::PodAntiAffinity {
            required_during_scheduling_ignored_during_execution: Some(vec![
                k8s_openapi::api::core::v1::PodAffinityTerm {
                    label_selector: Some(LabelSelector {
                        match_labels: Some(match_labels.clone()),
                        ..Default::default()
                    }),
                    topology_key: options
                        .topology_key
                        .clone()
                        .unwrap_or_else(|| "kubernetes.io/hostname".to_string()),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        ..Default::default()
    };

    // If there's only one replica, we need a different deployment strategy.
    let deployment_strategy = if options.replicas == 1 {
        DeploymentStrategy {
            type_: Some("Recreate".into()),
            rolling_update: None,
        }
    } else {
        DeploymentStrategy {
            type_: Some("RollingUpdate".into()),
            rolling_update: None,
        }
    };

    let deployment_name = format!("tunnel-{}", svc_name);
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
                    containers: vec![Container {
                        name: "netbird".into(),
                        image: Some(DEFAULT_NETBIRD_IMAGE.into()),
                        command: Some(vec!["/bin/sh".into(), "-c".into(), launch_script]),
                        env: Some(env),
                        security_context: Some(SecurityContext {
                            capabilities: Some(Capabilities {
                                add: Some(vec!["NET_ADMIN".into()]),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        readiness_probe: Some(k8s_openapi::api::core::v1::Probe {
                            exec: Some(k8s_openapi::api::core::v1::ExecAction {
                                command: Some(
                                    vec!["ip", "addr", "show", DEFAULT_NETBIRD_INTERFACE]
                                        .into_iter()
                                        .map(|s| s.into())
                                        .collect(),
                                ),
                            }),
                            initial_delay_seconds: Some(5),
                            period_seconds: Some(30),
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

    // Try to fetch the existing deployment
    match deployment_api.get_opt(&deployment_name).await? {
        Some(_existing) => {
            // Patch the deployment if it exists (server-side apply)
            use kube::api::{Patch, PatchParams};
            deployment_api
                .patch(
                    &deployment_name,
                    &PatchParams::apply("tlb-controller").force(),
                    &Patch::Apply(&deployment),
                )
                .await?;
            info!("Patched deployment for service `{}`", svc_name);
        }
        None => {
            // Create the deployment if it does not exist
            use kube::api::PostParams;
            deployment_api.create(&PostParams::default(), &deployment).await?;
            info!("Created deployment for service `{}`", svc_name);
        }
    }

    let status = ServiceStatus {
        load_balancer: Some(k8s_openapi::api::core::v1::LoadBalancerStatus {
            ingress: Some(
                lb_ingress_host
                    .as_ref()
                    .map(|host| {
                        vec![k8s_openapi::api::core::v1::LoadBalancerIngress {
                            hostname: Some(host.clone()),
                            ..Default::default()
                        }]
                    })
                    .unwrap_or_default(),
            ),
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
