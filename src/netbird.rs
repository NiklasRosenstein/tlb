use std::{collections::BTreeMap, time::Duration};

use k8s_openapi::{
    api::{
        apps::v1::{Deployment, DeploymentSpec},
        core::v1::{
            Capabilities, Container, ContainerPort, EnvVar, EnvVarSource, LoadBalancerIngress, Pod, PodSpec,
            PodTemplateSpec, SecretKeySelector, SecurityContext, Service, ServicePort, ServiceStatus,
        },
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference},
};
use kube::{
    Api, Client, Resource,
    api::{ObjectMeta, Patch, PatchParams},
    core::Selector,
    runtime::events::EventType,
};
use log::info;
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpStream,
};

use crate::{
    Error, Result, ServiceAnnotations,
    crds::{NetbirdAnnounceType, NetbirdConfig, NetbirdForwardingMode},
    simpleevent::SimpleEventRecorder,
};

const DEFAULT_CLUSTER_INTERFACE: &str = "eth0";
const DEFAULT_NETBIRD_INTERFACE: &str = "wt0";
const DEFAULT_NETBIRD_IMAGE: &str = "netbirdio/netbird:latest";
pub const DEFAULT_NETBIRD_UP_COMMAND: &str = "/usr/local/bin/netbird up -F -l=warn";

/// We prefer to expose the Netbird tunnel using the IP address of the Netbird peer, as this will work in most cases.
/// Using the DNS name instead will require that the DNS server can resolve the Netbird domain, which is not always
/// the case, especially when registering a CNAME entry for the Netbird tunnel in a public DNS server.
const DEFAULT_ANNOUNCE_TYPE: NetbirdAnnounceType = NetbirdAnnounceType::IP;

/// We launch a small TCP server on port `15411` in the tunnel Pod to expose the Netbird peer IP.
pub const NETBIRD_PEER_IP_PORT: u16 = 15411;

///
/// Generates a shell script that sets up iptables rules for forwarding traffic coming in to the Netbird interface
/// and launches the Netbird service.
///
#[allow(clippy::too_many_arguments)]
fn get_netbird_launch_script(
    forwarding_mode: NetbirdForwardingMode,
    service_ip: String,
    service_name: String,
    service_namespace: String,
    cluster_iface: String,
    netbird_iface: String,
    up_command: String,
    ports: &[ServicePort],
) -> String {
    let mut launch_script = vec!["#!/bin/sh".to_string(), "set -e".to_string()];

    match forwarding_mode {
        NetbirdForwardingMode::Iptables => {
            // Install iptables if it's not already installed.
            launch_script.push("if ! command iptables >/dev/null; then apk add --no-cache iptables; fi".to_owned());
        }
        NetbirdForwardingMode::Socat | NetbirdForwardingMode::SocatWithDns => {
            // Install socat if it's not already installed.
            launch_script.push("if ! command socat >/dev/null; then apk add --no-cache socat; fi".to_owned());
        }
    }

    ports.iter().for_each(|port| {
        let protocol = port.protocol.as_ref().unwrap_or(&"TCP".to_string()).to_lowercase();
        let protocol_upper = protocol.to_uppercase();
        let port = port.port;

        match forwarding_mode {
            NetbirdForwardingMode::Iptables => {
                // Accept new connections to the cluster IP and port.
                launch_script.push(format!(
                    "iptables -A FORWARD -i {netbird_iface} -o {cluster_iface} \
                        -p {protocol} -d {service_ip} --dport {port} -m conntrack \
                        --ctstate NEW -j ACCEPT"
                ));

                // Accept established connections to the cluster IP and port.
                launch_script.push(format!(
                    "iptables -A FORWARD -i {netbird_iface} -o {cluster_iface} \
                    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
                ));
                launch_script.push(format!(
                    "iptables -A FORWARD -i {cluster_iface} -o {netbird_iface} \
                        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
                ));

                // NAT packets destined for the cluster IP and port.
                launch_script.push(format!(
                    "iptables -t nat -I PREROUTING 1 -i {netbird_iface} \
                        -p {protocol} --dport {port} -j DNAT \
                        --to-destination {service_ip}:{port}"
                ));

                launch_script.push(format!(
                    "iptables -t nat -A POSTROUTING -o {cluster_iface} -j MASQUERADE"
                ));
            }
            NetbirdForwardingMode::Socat => launch_script.push(format!(
                "socat {protocol_upper}-LISTEN:{port},fork,reuseaddr \
                    {protocol_upper}:{service_ip}:{port} &"
            )),
            NetbirdForwardingMode::SocatWithDns => launch_script.push(format!(
                "socat {protocol_upper}-LISTEN:{port},fork,reuseaddr \
                    {protocol_upper}:{service_name}.{service_namespace}:{port} &"
            )),
        }

        launch_script.push("apk add socat".to_owned());
    });

    // Launch a process in the background that waits for the Netbird interface to come up and expose it via a TCP server.
    launch_script.push(format!(
        "( \
            while ! ip addr show {netbird_iface} &>/dev/null; do \
                echo \"[peer-ip-server] Waiting for {netbird_iface} to come up...\"; \
                sleep 1; \
            done; \
            peer_ip=$(ip addr show {netbird_iface} | grep 'inet ' | awk '{{print $2}}' | cut -d'/' -f1); \
            echo \"[peer-ip-server] {netbird_iface} is up with ip $peer_ip, serving on port {NETBIRD_PEER_IP_PORT}...\"; \
            while true; do \
                echo \"$peer_ip\" | nc -l -p {NETBIRD_PEER_IP_PORT}; \
            done \
        ) &"
    ));

    launch_script.push(up_command);
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

    let _deployment_api = Api::<Deployment>::namespaced(client.clone(), &deployment_namespace);
    let pod_api = Api::<Pod>::namespaced(client.clone(), &deployment_namespace);
    let svc_api = Api::<Service>::namespaced(client.clone(), svc_namespace);

    // Labels to match on for the Deployment.
    let match_labels = BTreeMap::from([
        ("app.kubernetes.io/name".to_string(), "netbird".to_string()),
        ("app.kubernetes.io/instance".to_string(), svc_name.to_string()),
        ("controller.tlb.io/for-service".to_string(), svc_name.clone()),
    ]);

    // Construct commands for setting up iptables in the Netbird pod.
    let launch_script = get_netbird_launch_script(
        netbird.forwarding_mode.unwrap_or(NetbirdForwardingMode::Socat),
        cluster_ip,
        svc_name.clone(),
        svc_namespace.clone(),
        netbird
            .cluster_interface
            .unwrap_or(DEFAULT_CLUSTER_INTERFACE.to_string()),
        netbird
            .netbird_interface
            .unwrap_or(DEFAULT_NETBIRD_INTERFACE.to_string()),
        netbird.up_command.unwrap_or(DEFAULT_NETBIRD_UP_COMMAND.to_string()),
        &ports,
    );

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

    let mut announce_type = netbird.announce_type.unwrap_or(DEFAULT_ANNOUNCE_TYPE);
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
    } else if announce_type == NetbirdAnnounceType::DNS {
        events
            .publish(
                &service.object_ref(&()),
                EventType::Warning,
                "MissingDNSAnnotation".into(),
                Some(
                    "Missing `tlb.io/dns` annotation for `announceType: DNS`. Falling back to IP announcement."
                        .to_string(),
                ),
                "Reconcile".into(),
            )
            .await?;
        announce_type = NetbirdAnnounceType::IP;
    }

    // Construct the node selector from the service annotations.
    let node_selector = crate::deployment::get_node_selector(&options);
    let affinity = crate::deployment::get_affinity(&options, match_labels.clone());
    let deployment_strategy = crate::deployment::get_deployment_strategy(&options);

    let deployment_prefix = netbird.deployment_prefix.unwrap_or_else(|| "tunnel-".to_string());
    let deployment_name = format!("{deployment_prefix}{svc_name}");
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
                        image: Some(netbird.image.unwrap_or(DEFAULT_NETBIRD_IMAGE.into())),
                        command: Some(vec!["/bin/sh".into(), "-c".into(), launch_script]),
                        env: Some(env),
                        security_context: Some(SecurityContext {
                            capabilities: Some(Capabilities {
                                add: Some(vec!["NET_ADMIN".into()]),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ports: Some(vec![ContainerPort {
                            name: Some("peer-ip".into()),
                            protocol: Some("TCP".into()),
                            container_port: NETBIRD_PEER_IP_PORT.into(),
                            ..Default::default()
                        }]),
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

    crate::deployment::create_or_patch_deployment(client, &deployment_namespace, &deployment).await?;

    // Find all pods that match the deployment's selector.
    let pods = pod_api
        .list(&kube::api::ListParams::default().labels_from(&Selector::from_iter(match_labels.into_iter())))
        .await?;
    let pod_netbird_ips = get_pod_netbird_peer_ips(pods.items, events).await?;
    let lb_ingress: Vec<LoadBalancerIngress> = match announce_type {
        NetbirdAnnounceType::IP => pod_netbird_ips
            .into_iter()
            .map(|ip| LoadBalancerIngress {
                ip: Some(ip),
                ..Default::default()
            })
            .collect(),
        NetbirdAnnounceType::DNS => lb_ingress_host
            .as_ref()
            .map(|host| {
                vec![k8s_openapi::api::core::v1::LoadBalancerIngress {
                    hostname: Some(host.clone()),
                    ..Default::default()
                }]
            })
            .unwrap_or_default(),
    };

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

/// Executes `ip addr show <netbird_interface>` on the pod's Netbird interface to get the Netbird peer IPs.
async fn get_pod_netbird_peer_ips(pods: Vec<Pod>, events: &SimpleEventRecorder) -> Result<Vec<String>> {
    let mut peer_ips = Vec::new();

    for pod in pods {
        let pod_name = pod
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| Error::UnexpectedError("Pod does not have a name".to_string()))?;

        let pod_ready = pod
            .status
            .as_ref()
            .map(|s| {
                s.conditions
                    .as_ref()
                    .unwrap_or(&Vec::new())
                    .iter()
                    .any(|c| c.type_ == "Ready" && c.status == "True")
            })
            .unwrap_or(false);
        if !pod_ready {
            events
                .publish(
                    &pod.object_ref(&()),
                    EventType::Warning,
                    "PodNotReady".into(),
                    Some(format!("Pod `{}` is not ready", pod_name)),
                    "Reconcile".into(),
                )
                .await?;
            continue;
        };

        let pod_ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.clone())
            .ok_or_else(|| Error::UnexpectedError(format!("Pod `{}` does not have an IP", pod_name)))?;

        // Attempt to connect to the Netbird peer IP server on the pod's IP and port.
        info!(
            "[peer-ip-server] Attempting to connect to Netbird peer IP server on pod `{}` at {}:{}",
            pod_name, pod_ip, NETBIRD_PEER_IP_PORT
        );
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(format!("{pod_ip}:{NETBIRD_PEER_IP_PORT}",)),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            e => {
                events
                    .publish(
                        &pod.object_ref(&()),
                        EventType::Warning,
                        "PeerIPServerConnectionFailed".into(),
                        Some(format!(
                            "Failed to connect to Netbird peer IP server on pod `{}`: {:?}",
                            pod_name, e
                        )),
                        "Reconcile".into(),
                    )
                    .await?;
                continue;
            }
        };

        info!(
            "[peer-ip-server] Connected to Netbird peer IP server on pod `{}` at {}:{}",
            pod_name, pod_ip, NETBIRD_PEER_IP_PORT
        );
        // Read a single line from the stream to get the Netbird peer IP.
        let mut reader = BufReader::new(&mut stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).await?;

        // Trim the response line and check if it's empty.
        let response_line = response_line.trim().to_string();
        if response_line.is_empty() {
            events
                .publish(
                    &pod.object_ref(&()),
                    EventType::Warning,
                    "PeerIPServerEmptyResponse".into(),
                    Some(format!(
                        "Received empty response from Netbird peer IP server on pod `{}`",
                        pod_name
                    )),
                    "Reconcile".into(),
                )
                .await?;
            continue;
        }

        eprintln!("[peer-ip-server] peer IP server on pod `{pod_name}` is `{response_line}`");

        peer_ips.push(response_line);
    }

    eprintln!("[peer-ip-server] Found {} Netbird peer IPs", peer_ips.len());
    Ok(peer_ips)
}
