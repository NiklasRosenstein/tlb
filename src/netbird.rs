use std::{collections::BTreeMap, time::Duration};

use async_trait::async_trait;
use k8s_openapi::{
    api::{
        apps::v1::{StatefulSet, StatefulSetSpec},
        core::v1::{
            Affinity, Capabilities, Container, ContainerPort, EmptyDirVolumeSource, EnvVar, EnvVarSource,
            LoadBalancerIngress, PersistentVolumeClaim, PersistentVolumeClaimSpec, Pod, PodSpec, PodTemplateSpec,
            Secret, SecretKeySelector, SecurityContext, Service, ServicePort, ServiceStatus, Volume, VolumeMount,
            VolumeResourceRequirements,
        },
    },
    apimachinery::pkg::{
        api::resource::Quantity,
        apis::meta::v1::{LabelSelector, OwnerReference},
    },
};
use kube::{
    Api, Resource, ResourceExt,
    api::{ObjectMeta, Patch, PatchParams, PostParams},
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
    Error, ReconcileContext, Result, ServiceAnnotations, TunnelProvider,
    crds::{NetbirdAnnounceType, NetbirdConfig},
    simpleevent::SimpleEventRecorder,
};

const DEFAULT_CLUSTER_INTERFACE: &str = "eth0";
const DEFAULT_NETBIRD_INTERFACE: &str = "wt0";
const DEFAULT_NETBIRD_IMAGE: &str = "netbirdio/netbird:latest";
pub const DEFAULT_NETBIRD_UP_COMMAND: &str = "/usr/local/bin/netbird up -F -l=warn";

/// Resolves a port mapping to actual port number and protocol
fn resolve_port_mapping(mapping: &crate::PortMapping, ports: &[ServicePort]) -> Result<(i32, String)> {
    if let Ok(port_num) = mapping.service_port.parse::<i32>() {
        // Port specified by number - find matching port for protocol
        let service_port = ports.iter().find(|p| p.port == port_num);
        let protocol = service_port
            .and_then(|p| p.protocol.as_ref())
            .unwrap_or(&"TCP".to_string())
            .to_lowercase();
        Ok((port_num, protocol))
    } else {
        // Look up port by name
        if let Some(service_port) = ports.iter().find(|p| p.name.as_ref() == Some(&mapping.service_port)) {
            let protocol = service_port
                .protocol
                .as_ref()
                .unwrap_or(&"TCP".to_string())
                .to_lowercase();
            Ok((service_port.port, protocol))
        } else {
            Err(Error::ConfigError(format!(
                "Port mapping references unknown service port '{}'",
                mapping.service_port
            )))
        }
    }
}

/// We prefer to expose the Netbird tunnel using the IP address of the Netbird peer, as this will work in most cases.
/// Using the DNS name instead will require that the DNS server can resolve the Netbird domain, which is not always
/// the case, especially when registering a CNAME entry for the Netbird tunnel in a public DNS server.
const DEFAULT_ANNOUNCE_TYPE: NetbirdAnnounceType = NetbirdAnnounceType::IP;

/// We launch a small TCP server on port `15411` in the tunnel Pod to expose the Netbird peer IP.
pub const NETBIRD_PEER_IP_PORT: u16 = 15411;

///
/// Generates a shell script that sets up port forwarding using socat for traffic coming in to the Netbird interface
/// and launches the Netbird service.
///
#[allow(clippy::too_many_arguments)]
fn get_netbird_launch_script(
    service_ip: String,
    _service_name: String,
    _service_namespace: String,
    _cluster_iface: String,
    netbird_iface: String,
    up_command: String,
    ports: &[ServicePort],
    port_mappings: Option<Vec<crate::PortMapping>>,
) -> Result<String> {
    let mut launch_script = vec!["#!/bin/sh".to_string(), "set -e".to_string()];

    // Install socat if it's not already installed.
    launch_script.push("if ! command socat 2>&1 >/dev/null; then apk add --no-cache socat; fi".to_owned());

    if let Some(mappings) = port_mappings {
        // Use custom port mappings
        for mapping in mappings {
            // Resolve service port to actual port number and protocol
            let (target_port, protocol) = resolve_port_mapping(&mapping, ports)?;

            let listen_spec = if mapping.listen_tls {
                format!(
                    "openssl-listen:{},fork,reuseaddr,cert=/tls/tls.crt,key=/tls/tls.key,verify=0",
                    mapping.listen_port
                )
            } else {
                format!("{protocol}-listen:{},fork,reuseaddr", mapping.listen_port)
            };

            let target_spec = if mapping.service_tls {
                let verify = if mapping.service_tls_verify {
                    "verify=1"
                } else {
                    "verify=0"
                };
                format!("openssl:{service_ip}:{target_port},{verify}")
            } else {
                format!("{protocol}:{service_ip}:{target_port}")
            };

            launch_script.push(format!("socat {listen_spec} {target_spec} &"));
        }
    } else {
        // Default behavior: direct 1:1 port mapping without TLS
        ports.iter().for_each(|port| {
            let protocol = port.protocol.as_ref().unwrap_or(&"TCP".to_string()).to_lowercase();
            let port_num = port.port;

            // Regular socat forwarding without TLS
            launch_script.push(format!(
                "socat {protocol}-listen:{port_num},fork,reuseaddr \
                    {protocol}:{service_ip}:{port_num} &"
            ));
        });
    }

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
    Ok(launch_script.join("\n"))
}

#[async_trait]
impl TunnelProvider for NetbirdConfig {
    fn provider_type(&self) -> crate::ProviderType {
        crate::ProviderType::Netbird
    }

    async fn reconcile_service(&self, ctx: &ReconcileContext, service: &Service) -> Result<()> {
        let options = ServiceAnnotations::from(service.metadata.annotations.clone().unwrap_or_default());
        let tunnel_class_name = ctx.metadata.name.as_ref().unwrap();

        let svc_name = service.metadata.name.as_ref().ok_or(Error::UnexpectedError(format!(
            "Service does not have a name: {service:?} (in netbird::reconcile_service at {}:{})",
            file!(),
            line!()
        )))?;
        let svc_namespace = service
            .metadata
            .namespace
            .as_ref()
            .ok_or(Error::UnexpectedError(format!(
                "Service `{svc_name}` does not have a namespace (in netbird::reconcile_service at {}:{})",
                file!(),
                line!()
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
                ctx.events
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
        let resource_namespace = self.setup_key_ref.namespace.clone().unwrap_or(svc_namespace.clone());

        // Only set owner references when the StatefulSet and Service are in the same namespace.
        // This avoids OwnerRefInvalidNamespace errors when they're in different namespaces.
        // Cleanup will still work through labels.
        let owner_references = if resource_namespace == *svc_namespace {
            vec![OwnerReference {
                api_version: "v1".into(),
                kind: "Service".into(),
                name: service.name_any(),
                uid: service.metadata.uid.clone().unwrap_or_default(),
                controller: Some(false),
                block_owner_deletion: Some(true),
            }]
        } else {
            Vec::new()
        };

        let pod_api = Api::<Pod>::namespaced(ctx.client.clone(), &resource_namespace);
        let svc_api = Api::<Service>::namespaced(ctx.client.clone(), svc_namespace);

        // Labels to match on for the Deployment.
        let match_labels = BTreeMap::from([
            ("app.kubernetes.io/name".to_string(), "netbird".to_string()),
            ("app.kubernetes.io/instance".to_string(), svc_name.to_string()),
            (crate::FOR_SERVICE_LABEL.to_string(), svc_name.clone()),
            (crate::FOR_TUNNEL_CLASS_LABEL.to_string(), tunnel_class_name.to_string()),
            (crate::PROVIDER_LABEL.to_string(), "netbird".to_string()),
        ]);

        let netbird_interface = self
            .netbird_interface
            .clone()
            .unwrap_or(DEFAULT_NETBIRD_INTERFACE.to_string());

        // Parse and validate port mappings
        let port_mappings = if let Some(map_ports_str) = &options.map_ports {
            match crate::PortMapping::parse_multiple(map_ports_str) {
                Ok(mappings) => Some(mappings),
                Err(err) => {
                    ctx.events
                        .publish(
                            &service.object_ref(&()),
                            EventType::Warning,
                            "InvalidPortMapping".into(),
                            Some(format!("Invalid port mapping configuration: {err}")),
                            "Reconcile".into(),
                        )
                        .await?;
                    return Ok(());
                }
            }
        } else {
            None
        };

        // Construct commands for setting up port forwarding in the Netbird pod.
        let launch_script = match get_netbird_launch_script(
            cluster_ip,
            svc_name.clone(),
            svc_namespace.clone(),
            self.cluster_interface
                .clone()
                .unwrap_or(DEFAULT_CLUSTER_INTERFACE.to_string()),
            netbird_interface.clone(),
            self.up_command
                .clone()
                .unwrap_or(DEFAULT_NETBIRD_UP_COMMAND.to_string()),
            &ports,
            port_mappings.clone(),
        ) {
            Ok(script) => script,
            Err(err) => {
                ctx.events
                    .publish(
                        &service.object_ref(&()),
                        EventType::Warning,
                        "LaunchScriptError".into(),
                        Some(err.to_string()),
                        "Reconcile".into(),
                    )
                    .await?;
                return Ok(());
            }
        };

        let mut env = vec![
            EnvVar {
                name: "NB_MANAGEMENT_URL".into(),
                value: Some(self.management_url.clone()),
                ..Default::default()
            },
            EnvVar {
                name: "NB_SETUP_KEY".into(),
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        name: self.setup_key_ref.name.clone(),
                        key: self.setup_key_ref.key.clone(),
                        optional: Some(false),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            EnvVar {
                name: "NB_CONFIG".into(),
                value: Some("/var/lib/netbird/config.json".into()),
                ..Default::default()
            },
        ];

        let mut announce_type = self.announce_type.clone().unwrap_or(DEFAULT_ANNOUNCE_TYPE);
        let mut lb_ingress_host: Option<String> = None;
        if let Some(dns) = &options.dns {
            // Split the netbird DNS name.
            let netbird_dns_domain = self
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
                lb_ingress_host = Some(format!("{first_dns}.{netbird_dns_domain}"));
            }

            // Add the DNS names as environment variables.
            env.push(EnvVar {
                name: "NB_EXTRA_DNS_LABELS".into(),
                value: Some(dns_names.join(",")),
                ..Default::default()
            });
        } else if announce_type == NetbirdAnnounceType::DNS {
            ctx.events
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

        // Construct affinity rules: both anti-affinity for spreading replicas and affinity for target service locality
        let pod_affinity = crate::build_pod_affinity_for_service(service);
        let affinity = Affinity {
            pod_affinity,
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

        // Prepare capabilities list - always include NET_ADMIN
        let mut capabilities = vec!["NET_ADMIN".into()];

        // Add eBPF capabilities if enabled (defaults to true)
        if self.enable_ebpf_capabilities.unwrap_or(true) {
            capabilities.push("SYS_ADMIN".into());
            capabilities.push("SYS_RESOURCE".into());
        }

        let pod_spec = PodSpec {
            node_selector: Some(node_selector),
            affinity: Some(affinity),
            containers: vec![Container {
                name: "netbird".into(),
                image: Some(self.image.clone().unwrap_or(DEFAULT_NETBIRD_IMAGE.into())),
                command: Some(vec!["/bin/sh".into(), "-c".into(), launch_script]),
                env: Some(env),
                security_context: Some(SecurityContext {
                    capabilities: Some(Capabilities {
                        add: Some(capabilities),
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
                            vec!["ip", "addr", "show", &netbird_interface]
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
        };

        let mut pod_template = PodTemplateSpec {
            metadata: Some(ObjectMeta {
                labels: Some(match_labels.clone()),
                ..Default::default()
            }),
            spec: Some(pod_spec),
        };

        let resource_name = format!(
            "{}{}",
            self.resource_prefix.clone().unwrap_or_else(|| "tunnel-".to_string()),
            svc_name
        );

        let mut statefulset_spec = StatefulSetSpec {
            replicas: Some(options.replicas),
            selector: LabelSelector {
                match_labels: Some(match_labels.clone()),
                ..Default::default()
            },
            service_name: Some(svc_name.clone()),
            ..Default::default()
        };

        if let Some(storage_class) = &self.storage_class {
            // persistent storage
            let pvc = PersistentVolumeClaim {
                metadata: ObjectMeta {
                    name: Some("netbird-data".into()),
                    ..Default::default()
                },
                spec: Some(PersistentVolumeClaimSpec {
                    access_modes: Some(vec!["ReadWriteOnce".into()]),
                    storage_class_name: Some(storage_class.clone()),
                    resources: Some(VolumeResourceRequirements {
                        requests: Some(BTreeMap::from([(
                            "storage".to_string(),
                            Quantity(self.size.clone().unwrap_or_else(|| "32Mi".to_string())),
                        )])),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            statefulset_spec.volume_claim_templates = Some(vec![pvc]);
        } else {
            // emptyDir
            pod_template.spec.as_mut().unwrap().volumes = Some(vec![Volume {
                name: "netbird-data".into(),
                empty_dir: Some(EmptyDirVolumeSource::default()),
                ..Default::default()
            }]);
        }
        // Setup volumes and volume mounts
        let mut volume_mounts = vec![VolumeMount {
            name: "netbird-data".into(),
            mount_path: "/var/lib/netbird".into(),
            ..Default::default()
        }];

        // Check if TLS is used in any port mappings to determine if TLS secret should be mounted
        let needs_tls_secret = port_mappings
            .as_ref()
            .map(|mappings| mappings.iter().any(|m| m.listen_tls || m.service_tls))
            .unwrap_or(false);

        // Add TLS secret volume and mount if TLS is used in port mappings
        let mut secret_resource_version: Option<String> = None;
        if needs_tls_secret {
            if let Some(tls_secret_name) = &options.tls_secret_name {
                // Get the TLS secret to track its resourceVersion for pod rotation
                let secret_api = Api::<Secret>::namespaced(ctx.client.clone(), svc_namespace);
                match secret_api.get_opt(tls_secret_name).await? {
                    Some(secret) => {
                        secret_resource_version = secret.metadata.resource_version.clone();
                    }
                    None => {
                        ctx.events
                            .publish(
                                &service.object_ref(&()),
                                EventType::Warning,
                                "TLSSecretNotFound".into(),
                                Some(format!(
                                    "TLS secret '{tls_secret_name}' not found in namespace '{svc_namespace}'"
                                )),
                                "Reconcile".into(),
                            )
                            .await?;
                        return Ok(());
                    }
                }

                // Add TLS secret volume to the pod
                let mut volumes = pod_template.spec.as_mut().unwrap().volumes.take().unwrap_or_default();
                volumes.push(Volume {
                    name: "tls-secret".into(),
                    secret: Some(k8s_openapi::api::core::v1::SecretVolumeSource {
                        secret_name: Some(tls_secret_name.clone()),
                        ..Default::default()
                    }),
                    ..Default::default()
                });
                pod_template.spec.as_mut().unwrap().volumes = Some(volumes);

                // Add TLS secret volume mount
                volume_mounts.push(VolumeMount {
                    name: "tls-secret".into(),
                    mount_path: "/tls".into(),
                    read_only: Some(true),
                    ..Default::default()
                });
            } else {
                ctx.events
                    .publish(
                        &service.object_ref(&()),
                        EventType::Warning,
                        "TLSConfigurationError".into(),
                        Some(
                            "Port mapping configuration uses TLS but no 'tlb.io/tls-secret-name' annotation is set. \
                            TLS termination requires a secret containing the TLS certificate and key."
                                .to_string(),
                        ),
                        "Reconcile".into(),
                    )
                    .await?;
                return Ok(());
            }
        }

        // Apply volume mounts to the container
        let container = pod_template.spec.as_mut().unwrap().containers.get_mut(0).unwrap();
        container.volume_mounts = Some(volume_mounts);

        // Add secret resource version to pod template annotations to trigger pod rotation when secret changes
        if let Some(resource_version) = secret_resource_version {
            let mut annotations = pod_template
                .metadata
                .as_ref()
                .and_then(|m| m.annotations.clone())
                .unwrap_or_default();
            annotations.insert("controller.tlb.io/tls-secret-version".to_string(), resource_version);
            pod_template.metadata.as_mut().unwrap().annotations = Some(annotations);
        }

        statefulset_spec.template = pod_template;

        let statefulset = StatefulSet {
            metadata: ObjectMeta {
                name: Some(resource_name.clone()),
                namespace: Some(resource_namespace.clone()),
                owner_references: if owner_references.is_empty() {
                    None
                } else {
                    Some(owner_references)
                },
                labels: Some(match_labels.clone()),
                ..Default::default()
            },
            spec: Some(statefulset_spec),
            ..Default::default()
        };

        let statefulset_api = Api::<StatefulSet>::namespaced(ctx.client.clone(), &resource_namespace);
        // Patch or create the statefulset.
        match statefulset_api.get_opt(&resource_name).await? {
            Some(_) => {
                // It exists, so let's patch it.
                match statefulset_api
                    .patch(
                        &resource_name,
                        &PatchParams::apply("tlb-controller").force(),
                        &Patch::Apply(&statefulset),
                    )
                    .await
                {
                    Ok(_) => {
                        info!("Patched statefulset for service `{svc_name}`");
                    }
                    Err(kube::Error::Api(e)) if e.code == 422 => {
                        info!(
                            "Patching StatefulSet '{resource_name}' failed, likely due to immutable field change. Deleting and recreating."
                        );
                        ctx.events
                            .publish(
                                &service.object_ref(&()),
                                EventType::Warning,
                                "StatefulSetRecreation".into(),
                                Some(format!(
                                    "Patch for StatefulSet '{resource_name}' failed. Deleting and recreating."
                                )),
                                "Reconcile".into(),
                            )
                            .await?;
                        statefulset_api.delete(&resource_name, &Default::default()).await?;

                        // Recreate the statefulset immediately.
                        info!("Re-creating statefulset for service `{svc_name}` after deletion.");
                        statefulset_api.create(&PostParams::default(), &statefulset).await?;
                        info!("Re-created statefulset for service `{svc_name}`");
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
            None => {
                // It does not exist, so create it.
                statefulset_api.create(&PostParams::default(), &statefulset).await?;
                info!("Created statefulset for service `{svc_name}`");
            }
        }

        // Also need to delete the deployment if it exists from a previous version
        use k8s_openapi::api::apps::v1::Deployment;
        let deployment_api = Api::<Deployment>::namespaced(ctx.client.clone(), &resource_namespace);
        if deployment_api.get_opt(&resource_name).await?.is_some() {
            info!("Deleting deployment `{resource_name}` for service `{svc_name}` as it is now a statefulset");
            deployment_api.delete(&resource_name, &Default::default()).await?;
        }

        // Find all pods that match the resource's selector.
        let pods = pod_api
            .list(&kube::api::ListParams::default().labels_from(&Selector::from_iter(match_labels.into_iter())))
            .await?;
        let pod_netbird_ips = get_pod_netbird_peer_ips(pods.items, &ctx.events).await?;
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

        info!("Patched status for service `{svc_name}`");

        Ok(())
    }

    async fn cleanup_service(&self, ctx: &ReconcileContext, service: &Service) -> Result<()> {
        let svc_name = service.name_any();
        let svc_namespace = service.namespace().unwrap();
        let tunnel_class_name = ctx.metadata.name.as_ref().unwrap();

        // Use label selectors to find resources instead of hardcoded names
        // This ensures cleanup works even if resource_prefix changes
        let label_selector = format!(
            "{}={},{}={},{}={}",
            crate::FOR_SERVICE_LABEL,
            svc_name,
            crate::FOR_TUNNEL_CLASS_LABEL,
            tunnel_class_name,
            crate::PROVIDER_LABEL,
            "netbird"
        );

        // Clean up StatefulSets
        let statefulset_api = Api::<StatefulSet>::namespaced(ctx.client.clone(), &svc_namespace);
        let statefulsets = statefulset_api
            .list(&kube::api::ListParams::default().labels(&label_selector))
            .await
            .map_err(|e| {
                Error::UnexpectedError(format!(
                    "Failed to list StatefulSets for service '{svc_name}' in namespace '{svc_namespace}': {e}"
                ))
            })?;

        for statefulset in statefulsets {
            let statefulset_name = statefulset.metadata.name.as_ref().unwrap();
            info!("Deleting netbird statefulset `{statefulset_name}` for service `{svc_name}` using label selector");
            statefulset_api
                .delete(statefulset_name, &Default::default())
                .await
                .map_err(|e| {
                    Error::UnexpectedError(format!(
                        "Failed to delete StatefulSet '{statefulset_name}' for service '{svc_name}': {e}"
                    ))
                })?;
        }

        // Clean up PVCs created by the StatefulSets
        // PVCs created by StatefulSets inherit the StatefulSet's selector labels
        let pvc_api = Api::<PersistentVolumeClaim>::namespaced(ctx.client.clone(), &svc_namespace);
        let pvcs = pvc_api
            .list(&kube::api::ListParams::default().labels(&label_selector))
            .await
            .map_err(|e| {
                Error::UnexpectedError(format!(
                    "Failed to list PVCs for service '{svc_name}' in namespace '{svc_namespace}': {e}"
                ))
            })?;

        for pvc in pvcs {
            let pvc_name = pvc.metadata.name.as_ref().unwrap();
            info!("Deleting PVC `{pvc_name}` for service `{svc_name}`");
            pvc_api.delete(pvc_name, &Default::default()).await.map_err(|e| {
                Error::UnexpectedError(format!(
                    "Failed to delete PVC '{pvc_name}' for service '{svc_name}': {e}"
                ))
            })?;
        }

        Ok(())
    }
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
                    Some(format!("Pod `{pod_name}` is not ready")),
                    "Reconcile".into(),
                )
                .await?;
            continue;
        };

        let pod_ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.clone())
            .ok_or_else(|| Error::UnexpectedError(format!("Pod `{pod_name}` does not have an IP")))?;

        // Attempt to connect to the Netbird peer IP server on the pod's IP and port.
        info!(
            "[peer-ip-server] Attempting to connect to Netbird peer IP server on pod `{pod_name}` at {pod_ip}:{NETBIRD_PEER_IP_PORT}"
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
                            "Failed to connect to Netbird peer IP server on pod `{pod_name}`: {e:?}"
                        )),
                        "Reconcile".into(),
                    )
                    .await?;
                continue;
            }
        };

        info!(
            "[peer-ip-server] Connected to Netbird peer IP server on pod `{pod_name}` at {pod_ip}:{NETBIRD_PEER_IP_PORT}"
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
                        "Received empty response from Netbird peer IP server on pod `{pod_name}`"
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

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ServicePort;

    #[test]
    fn test_port_mapping_parsing() {
        // Test valid mappings
        let mapping = crate::PortMapping::parse("443/tls:8080").unwrap();
        assert_eq!(mapping.listen_port, 443);
        assert!(mapping.listen_tls);
        assert_eq!(mapping.service_port, "8080");
        assert!(!mapping.service_tls);
        assert!(mapping.service_tls_verify);

        let mapping = crate::PortMapping::parse("80:http").unwrap();
        assert_eq!(mapping.listen_port, 80);
        assert!(!mapping.listen_tls);
        assert_eq!(mapping.service_port, "http");
        assert!(!mapping.service_tls);
        assert!(mapping.service_tls_verify);

        let mapping = crate::PortMapping::parse("443/tls:5001/tls-no-verify").unwrap();
        assert_eq!(mapping.listen_port, 443);
        assert!(mapping.listen_tls);
        assert_eq!(mapping.service_port, "5001");
        assert!(mapping.service_tls);
        assert!(!mapping.service_tls_verify);

        // Test multiple mappings
        let mappings = crate::PortMapping::parse_multiple("80:http, 443/tls:https").unwrap();
        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].listen_port, 80);
        assert_eq!(mappings[1].listen_port, 443);
        assert!(mappings[1].listen_tls);
    }

    #[test]
    fn test_tls_socat_command_generation_with_port_mapping() {
        let ports = vec![ServicePort {
            name: Some("https".to_string()),
            port: 443,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        }];

        let port_mappings = Some(vec![crate::PortMapping {
            listen_port: 443,
            listen_tls: true,
            service_port: "443".to_string(),
            service_tls: false,
            service_tls_verify: true,
        }]);

        let script = get_netbird_launch_script(
            "10.0.0.1".to_string(),
            "test-service".to_string(),
            "default".to_string(),
            "eth0".to_string(),
            "wt0".to_string(),
            "netbird up".to_string(),
            &ports,
            port_mappings,
        )
        .unwrap();

        assert!(script.contains("openssl-listen:443"));
        assert!(script.contains("cert=/tls/tls.crt"));
        assert!(script.contains("key=/tls/tls.key"));
        assert!(script.contains("verify=0"));
        assert!(script.contains("tcp:10.0.0.1:443"));
    }

    #[test]
    fn test_tls_443_to_80_forwarding_with_port_mapping() {
        let ports = vec![ServicePort {
            name: Some("http".to_string()),
            port: 80,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        }];

        let port_mappings = Some(vec![crate::PortMapping {
            listen_port: 443,
            listen_tls: true,
            service_port: "http".to_string(),
            service_tls: false,
            service_tls_verify: true,
        }]);

        let script = get_netbird_launch_script(
            "10.0.0.1".to_string(),
            "test-service".to_string(),
            "default".to_string(),
            "eth0".to_string(),
            "wt0".to_string(),
            "netbird up".to_string(),
            &ports,
            port_mappings,
        )
        .unwrap();

        // Should create TLS termination on 443 forwarding to port 80 (resolved from "http" port name)
        assert!(script.contains("openssl-listen:443"));
        assert!(script.contains("tcp:10.0.0.1:80"));
    }

    #[test]
    fn test_service_to_service_tls() {
        let ports = vec![ServicePort {
            name: Some("https".to_string()),
            port: 5001,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        }];

        let port_mappings = Some(vec![crate::PortMapping {
            listen_port: 443,
            listen_tls: true,
            service_port: "5001".to_string(),
            service_tls: true,
            service_tls_verify: false,
        }]);

        let script = get_netbird_launch_script(
            "10.0.0.1".to_string(),
            "test-service".to_string(),
            "default".to_string(),
            "eth0".to_string(),
            "wt0".to_string(),
            "netbird up".to_string(),
            &ports,
            port_mappings,
        )
        .unwrap();

        // Should create TLS termination on 443 connecting to TLS service on 5001 without verification
        assert!(script.contains("openssl-listen:443"));
        assert!(script.contains("openssl:10.0.0.1:5001,verify=0"));
    }

    #[test]
    fn test_regular_socat_without_port_mappings() {
        let ports = vec![ServicePort {
            name: Some("http".to_string()),
            port: 80,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        }];

        let script = get_netbird_launch_script(
            "10.0.0.1".to_string(),
            "test-service".to_string(),
            "default".to_string(),
            "eth0".to_string(),
            "wt0".to_string(),
            "netbird up".to_string(),
            &ports,
            None, // No port mappings - should use default 1:1 mapping
        )
        .unwrap();

        // Should use regular TCP socat, not openssl-listen
        assert!(script.contains("tcp-listen:80"));
        assert!(!script.contains("openssl-listen"));
        assert!(!script.contains("cert="));
    }

    #[test]
    fn test_invalid_port_mapping_returns_error() {
        let ports = vec![ServicePort {
            name: Some("http".to_string()),
            port: 80,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        }];

        let port_mappings = Some(vec![crate::PortMapping {
            listen_port: 443,
            listen_tls: true,
            service_port: "invalid-port".to_string(), // This port doesn't exist
            service_tls: false,
            service_tls_verify: true,
        }]);

        let result = get_netbird_launch_script(
            "10.0.0.1".to_string(),
            "test-service".to_string(),
            "default".to_string(),
            "eth0".to_string(),
            "wt0".to_string(),
            "netbird up".to_string(),
            &ports,
            port_mappings,
        );

        // Should return an error for invalid port mapping
        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Port mapping references unknown service port 'invalid-port'"));
    }
}
