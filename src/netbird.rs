use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use async_trait::async_trait;
use k8s_openapi::{
    api::{
        apps::v1::{StatefulSet, StatefulSetSpec},
        core::v1::{
            Affinity, Capabilities, Container, ContainerPort, EmptyDirVolumeSource, EnvVar, EnvVarSource,
            LoadBalancerIngress, PersistentVolumeClaim, PersistentVolumeClaimSpec, Pod, PodSpec, PodTemplateSpec,
            Secret, SecretKeySelector, SecurityContext, Service, ServicePort, Volume, VolumeMount,
            VolumeResourceRequirements,
        },
    },
    apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::LabelSelector},
};
use kube::{Api, Resource, ResourceExt, api::ObjectMeta, core::Selector, runtime::events::EventType};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader},
    net::TcpStream,
};

use crate::{
    Error, ReconcileContext, Result, TunnelProvider,
    crds::{NetbirdAnnounceType, NetbirdConfig},
    simpleevent::SimpleEventRecorder,
};

const DEFAULT_CLUSTER_INTERFACE: &str = "eth0";
const DEFAULT_NETBIRD_INTERFACE: &str = "wt0";
const DEFAULT_NETBIRD_IMAGE: &str = "netbirdio/netbird:latest";
pub const DEFAULT_NETBIRD_UP_COMMAND: &str = "/usr/local/bin/netbird up -F -l=warn --disable-dns";

/// Resolves a port mapping to actual port number and protocol
fn resolve_port_mapping(mapping: &crate::PortMapping, ports: &[ServicePort]) -> Result<(i32, String)> {
    if let Ok(port_num) = mapping.service_port.parse::<i32>() {
        // Port specified by number - find matching port for protocol
        let service_port = ports
            .iter()
            .find(|p| p.port == port_num)
            .ok_or_else(|| Error::ConfigError(format!("Port mapping references unknown service port '{port_num}'")))?;
        let protocol = service_port
            .protocol
            .as_ref()
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
    let service_ip = match service_ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) => format!("[{ip}]"),
        Ok(IpAddr::V4(ip)) => ip.to_string(),
        Err(_) => return Err(Error::ConfigError("invalid Service ClusterIP".into())),
    };
    let mut launch_script = vec![
        "#!/bin/sh".to_string(),
        "set -e".to_string(),
        "children=''".into(),
        "trap 'trap - EXIT TERM INT; kill $children 2>/dev/null || true; sleep 1; kill -KILL $children 2>/dev/null || true; wait 2>/dev/null || true' EXIT".into(),
        "trap 'exit 1' TERM INT".into(),
    ];

    // Install socat if it's not already installed.
    launch_script.push("if ! command -v socat >/dev/null 2>&1; then apk add --no-cache socat; fi".to_owned());

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

            launch_script.push(format!(
                "socat {listen_spec} {target_spec} &\nchildren=\"$children $!\""
            ));
        }
    } else {
        // Default behavior: direct 1:1 port mapping without TLS
        ports.iter().for_each(|port| {
            let protocol = port.protocol.as_ref().unwrap_or(&"TCP".to_string()).to_lowercase();
            let port_num = port.port;

            // Regular socat forwarding without TLS
            launch_script.push(format!(
                "socat {protocol}-listen:{port_num},fork,reuseaddr \
                    {protocol}:{service_ip}:{port_num} &\nchildren=\"$children $!\""
            ));
        });
    }

    // Wait for an IPv4 address before exposing it; interface creation precedes address assignment.
    launch_script.push(format!(
        "( \
            while peer_ip=$(ip -4 addr show {netbird_iface} 2>/dev/null | grep 'inet ' | awk '{{print $2}}' | cut -d'/' -f1 | head -n1); [ -z \"$peer_ip\" ]; do \
                echo \"[peer-ip-server] Waiting for {netbird_iface} to come up...\"; \
                sleep 1; \
            done; \
            echo \"[peer-ip-server] {netbird_iface} is up with ip $peer_ip, serving on port {NETBIRD_PEER_IP_PORT}...\"; \
            while true; do \
                echo \"$peer_ip\" | nc -l -p {NETBIRD_PEER_IP_PORT}; \
            done \
        ) &"
    ));

    launch_script.push("children=\"$children $!\"".into());
    launch_script.push(format!("( {up_command} ) &\nchildren=\"$children $!\""));
    launch_script.push(
        "while true; do for child in $children; do kill -0 \"$child\" 2>/dev/null || exit 1; done; sleep 1; done"
            .into(),
    );
    Ok(launch_script.join("\n"))
}

/// Creation and apply have separate field ownership; TLS removal must delete the reserved fields explicitly.
async fn remove_tls_template(ctx: &ReconcileContext, api: &Api<StatefulSet>, statefulset: &StatefulSet) -> Result<()> {
    ctx.check_owned(&statefulset.metadata)?;
    let template = &statefulset
        .spec
        .as_ref()
        .ok_or_else(|| Error::ConfigError("StatefulSet spec missing".into()))?
        .template;
    let has_tls = template.spec.as_ref().is_some_and(|spec| {
        spec.volumes
            .as_ref()
            .is_some_and(|volumes| volumes.iter().any(|v| v.name == "tls-secret"))
            || spec.containers.iter().any(|c| {
                c.name == "netbird"
                    && c.volume_mounts
                        .as_ref()
                        .is_some_and(|mounts| mounts.iter().any(|m| m.mount_path == "/tls"))
            })
    }) || template
        .metadata
        .as_ref()
        .and_then(|m| m.annotations.as_ref())
        .is_some_and(|annotations| annotations.contains_key("controller.tlb.io/tls-secret-version"));
    if has_tls {
        api.patch(&statefulset.name_any(), &kube::api::PatchParams::default(), &kube::api::Patch::<serde_json::Value>::Strategic(serde_json::json!({
            "metadata": {"uid": crate::state::required_uid(&statefulset.metadata)?, "resourceVersion": statefulset.resource_version().ok_or_else(|| Error::ConfigError("StatefulSet resource version missing".into()))?},
            "spec": {"template": {
                "metadata": {"annotations": {"controller.tlb.io/tls-secret-version": null}},
                "spec": {"volumes": [{"name": "tls-secret", "$patch": "delete"}],
                    "containers": [{"name": "netbird", "volumeMounts": [{"mountPath": "/tls", "$patch": "delete"}]}]}
            }}
        }))).await?;
    }
    Ok(())
}

#[async_trait]
impl TunnelProvider for NetbirdConfig {
    async fn reconcile_service(&self, ctx: &ReconcileContext, service: &Service) -> Result<crate::ReconcileOutcome> {
        let options = crate::config::validate_service(service, &ctx.binding.data.class)?;

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
                    .await;
                Vec::new()
            }
        };

        let resource_namespace = ctx.binding.data.workload_namespace.clone();
        let owner_references = ctx.owner_references()?;
        let pod_api = Api::<Pod>::namespaced(ctx.client.clone(), &resource_namespace);
        let match_labels = ctx.labels()?;
        let credential_name = ctx.resource_name("nb-", "-key")?;
        let credential = ctx
            .binding
            .data
            .credentials
            .get("setup-key")
            .ok_or_else(|| Error::ConfigError("binding is missing its setup key".into()))?;
        let credential_secret = Secret {
            metadata: ctx.metadata(&credential_name)?,
            data: Some(BTreeMap::from([(
                "setup-key".into(),
                k8s_openapi::ByteString(credential.as_bytes().to_vec()),
            )])),
            ..Default::default()
        };

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
                        .await;
                    return Err(Error::ConfigError("invalid NetBird workload configuration".into()));
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
                    .await;
                return Err(Error::ConfigError("invalid NetBird workload configuration".into()));
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
                        name: credential_name.clone(),
                        key: "setup-key".into(),
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

        env.push(EnvVar {
            name: "NB_DISABLE_EBPF_WG_PROXY".into(),
            value: Some((!self.enable_ebpf_capabilities.unwrap_or(false)).to_string()),
            ..Default::default()
        });
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
                .await;
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

        // eBPF capability grants require operator opt-in.
        if self.enable_ebpf_capabilities.unwrap_or(false) {
            capabilities.push("SYS_ADMIN".into());
            capabilities.push("SYS_RESOURCE".into());
        }

        let pod_spec = PodSpec {
            automount_service_account_token: Some(false),
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

        let resource_name =
            ctx.resource_name_with_limit(self.resource_prefix.as_deref().unwrap_or("tunnel-"), "", 52)?;

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
                    labels: Some(match_labels.clone()),
                    owner_references: Some(owner_references.clone()),
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
            .map(|mappings| mappings.iter().any(|m| m.listen_tls))
            .unwrap_or(false);

        // Add TLS secret volume and mount if TLS is used in port mappings
        let mut secret_resource_version: Option<String> = None;
        let runtime_tls_name = ctx.resource_name("nb-", "-tls")?;
        if needs_tls_secret {
            if let Some(tls_secret_name) = &options.tls_secret_name {
                // Get the TLS secret to track its resourceVersion for pod rotation
                let secret_api = Api::<Secret>::namespaced(ctx.client.clone(), svc_namespace);
                match secret_api.get_opt(tls_secret_name).await? {
                    Some(secret) => {
                        crate::config::validate_tls_secret(&secret)?;
                        let runtime = Secret {
                            metadata: ctx.metadata(&runtime_tls_name)?,
                            type_: Some("kubernetes.io/tls".into()),
                            data: Some(
                                secret
                                    .data
                                    .unwrap_or_default()
                                    .into_iter()
                                    .filter(|(key, _)| key == "tls.crt" || key == "tls.key")
                                    .collect(),
                            ),
                            ..Default::default()
                        };
                        secret_resource_version = crate::managed::apply_secret(ctx, &runtime).await?.resource_version();
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
                            .await;
                        return Err(Error::ConfigError(format!(
                            "TLS Secret {svc_namespace}/{tls_secret_name} is missing"
                        )));
                    }
                }

                // Add TLS secret volume to the pod
                let mut volumes = pod_template.spec.as_mut().unwrap().volumes.take().unwrap_or_default();
                volumes.push(Volume {
                    name: "tls-secret".into(),
                    secret: Some(k8s_openapi::api::core::v1::SecretVolumeSource {
                        secret_name: Some(runtime_tls_name.clone()),
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
                    .await;
                return Err(Error::ConfigError("invalid NetBird workload configuration".into()));
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

        let credential_secret = crate::managed::apply(
            ctx,
            &Api::<Secret>::namespaced(ctx.client.clone(), &resource_namespace),
            &credential_secret,
        )
        .await?;
        let mut statefulset = statefulset;
        statefulset
            .spec
            .as_mut()
            .unwrap()
            .template
            .metadata
            .as_mut()
            .unwrap()
            .annotations
            .get_or_insert_default()
            .insert(
                "controller.tlb.io/secret-version".into(),
                credential_secret.resource_version().unwrap_or_default(),
            );
        let statefulset_api = Api::<StatefulSet>::namespaced(ctx.client.clone(), &resource_namespace);
        // Invalid or immutable desired fields leave the running workload intact.
        let statefulset = crate::managed::apply(ctx, &statefulset_api, &statefulset).await?;

        if !needs_tls_secret {
            remove_tls_template(ctx, &statefulset_api, &statefulset).await?;
            crate::managed::prune_secret(ctx, &runtime_tls_name).await?;
        }
        // Find all pods that match the resource's selector.
        let pods = pod_api
            .list(&kube::api::ListParams::default().labels_from(&Selector::from_iter(match_labels)))
            .await?;
        let observations = get_pod_netbird_peer_ips(pods.items, &ctx.events).await?;
        let pod_netbird_ips = observations.addresses();
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

        crate::managed::patch_ingress(ctx, service, lb_ingress).await?;

        crate::netbird_dns::reconcile(ctx, self, service, &observations).await?;
        if observations.incomplete() {
            return Err(Error::UnexpectedError(
                "NetBird peer address discovery incomplete".into(),
            ));
        }
        Ok(crate::ReconcileOutcome::ExternalRefresh)
    }

    async fn cleanup_service(&self, ctx: &ReconcileContext, _service: &Service) -> Result<()> {
        crate::netbird_dns::cleanup(ctx).await?;
        crate::managed::cleanup_workloads(ctx).await?;
        crate::managed::cleanup_storage(ctx).await
    }
}

/// Reads one bounded, newline-terminated IP address before the exchange deadline.
async fn read_peer_ip<R: AsyncRead + Unpin>(stream: R, deadline: tokio::time::Instant) -> std::io::Result<IpAddr> {
    tokio::time::timeout_at(deadline, async {
        let mut reader = BufReader::new(stream.take(64));
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line).await?;
        if line.last() != Some(&b'\n') || line.len() >= 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer IP response must be a short complete line",
            ));
        }
        std::str::from_utf8(&line)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "peer response is not an IP address"))
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "peer IP exchange timed out"))?
}

async fn query_peer_ip(pod_ip: IpAddr) -> std::io::Result<IpAddr> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let stream = tokio::time::timeout_at(
        deadline,
        TcpStream::connect(SocketAddr::new(pod_ip, NETBIRD_PEER_IP_PORT)),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "peer IP connection timed out"))??;
    read_peer_ip(stream, deadline).await
}

#[derive(Default, Debug)]
pub(crate) struct PeerObservations {
    /// Eligible Pod UIDs map to their observed IPv4 address, or None when discovery failed.
    pub eligible: BTreeMap<String, Option<String>>,
}

impl PeerObservations {
    pub fn incomplete(&self) -> bool {
        self.eligible.values().any(Option::is_none)
    }

    pub fn addresses(&self) -> Vec<String> {
        let mut addresses: Vec<_> = self.eligible.values().flatten().cloned().collect();
        addresses.sort();
        addresses.dedup();
        addresses
    }
}

async fn get_pod_netbird_peer_ips(pods: Vec<Pod>, events: &SimpleEventRecorder) -> Result<PeerObservations> {
    let mut observations = PeerObservations::default();
    for pod in pods {
        if pod.metadata.deletion_timestamp.is_some()
            || !pod.status.as_ref().is_some_and(|s| {
                s.conditions
                    .as_ref()
                    .is_some_and(|cs| cs.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
            })
        {
            continue;
        }
        let uid = crate::state::required_uid(&pod.metadata)?.to_string();
        observations.eligible.insert(uid.clone(), None);
        let Some(pod_ip) = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.as_ref())
            .and_then(|s| s.parse::<IpAddr>().ok())
        else {
            continue;
        };
        match query_peer_ip(pod_ip).await {
            Ok(IpAddr::V4(ip)) => {
                observations.eligible.insert(uid, Some(ip.to_string()));
            }
            Ok(IpAddr::V6(_)) => {}
            Err(err) => {
                log::warn!(
                    "peer IP discovery failed for {}/{}: {err}",
                    pod.namespace().unwrap_or_default(),
                    pod.name_any()
                );
                let _ = events
                    .publish(
                        &pod.object_ref(&()),
                        EventType::Warning,
                        "PeerIPDiscoveryFailed".into(),
                        Some(err.to_string()),
                        "Reconcile".into(),
                    )
                    .await;
            }
        }
    }
    Ok(observations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ServicePort;

    #[test]
    fn failed_forwarder_terminates_the_supervisor() {
        use std::process::{Command, Stdio};
        let script = get_netbird_launch_script(
            "10.0.0.1".into(),
            "api".into(),
            "apps".into(),
            "eth0".into(),
            "wt0".into(),
            "exec sleep 30".into(),
            &[ServicePort {
                port: 80,
                ..Default::default()
            }],
            None,
        )
        .unwrap();
        let script = format!("socat() {{ return 1; }}\nip() {{ return 1; }}\n{script}");
        let mut child = Command::new("sh")
            .args(["-c", &script])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(!status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("failed forwarder left supervisor alive: {script}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[tokio::test]
    async fn peer_ip_frames_are_bounded_and_validated() {
        for (input, expected) in [
            ("100.64.1.2\n", Some("100.64.1.2")),
            ("2001:db8::1\n", Some("2001:db8::1")),
            ("\n", None),
            ("not-an-ip\n", None),
            ("100.64.1.2", None),
        ] {
            let result = read_peer_ip(input.as_bytes(), tokio::time::Instant::now() + Duration::from_secs(1)).await;
            assert_eq!(result.ok().map(|ip| ip.to_string()).as_deref(), expected);
        }
        let oversized = vec![b'1'; 1024];
        assert!(
            read_peer_ip(
                oversized.as_slice(),
                tokio::time::Instant::now() + Duration::from_secs(1)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn stalled_peer_cannot_exceed_deadline() {
        let (_writer, reader) = tokio::io::duplex(128);
        let error = read_peer_ip(reader, tokio::time::Instant::now() + Duration::from_millis(10))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

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
