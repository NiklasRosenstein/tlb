use std::{collections::BTreeMap, sync::Arc};

use k8s_openapi::{
    api::{
        apps::v1::{Deployment, DeploymentSpec},
        core::v1::{
            Affinity, Capabilities, Container, EnvVar, EnvVarSource, Namespace, PodSpec, PodTemplateSpec,
            SecretKeySelector, SecurityContext, Service, ServiceStatus,
        },
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference},
};
use kube::{
    Api, Resource,
    api::{ListParams, ObjectMeta, Patch, PatchParams},
    runtime::{
        controller::Action,
        events::{Event, EventType},
    },
};
use log::info;
use serde_json::json;
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
/// Configuration that can be specified as annotations on the Service object.
///
#[derive(Default, Clone, Debug)]
struct ServiceAnnotations {
    /// A comma-separated list of DNS names that should be assigned to the tunnel. The behaviour
    /// of this annotation may vary slightly based on the implementation of the tunnel class.
    pub dns: Option<String>,

    /// The number of tunnel replicas to deploy. Defaults to 1.
    pub replicas: Option<i32>,

    /// A topology key that can be used to spread the tunnel replicas across different nodes.
    /// Defaults to `kubernetes.io/hostname`.
    pub topology_key: Option<String>,

    /// A comma-separated list of node labels to use as node selectors for the tunnel pods.
    pub node_selector: Option<String>,
}

impl From<BTreeMap<String, String>> for ServiceAnnotations {
    fn from(annotations: BTreeMap<String, String>) -> Self {
        // TODO: Can we use serde?
        let dns = annotations.get("tlb.io/dns").cloned();
        let replicas = annotations.get("tlb.io/replicas").and_then(|s| s.parse().ok());
        let topology_key = annotations.get("tlb.io/topology-key").cloned();
        let node_selector = annotations.get("tlb.io/node-selector").cloned();

        ServiceAnnotations {
            dns,
            replicas,
            topology_key,
            node_selector,
        }
    }
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
            info!("Processing service `{}` in namespace `{}`", svc_name, svc_namespace);

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
                .await?;

            let options = ServiceAnnotations::from(service.metadata.annotations.clone().unwrap_or_default());

            if let Some(netbird) = self.netbird.clone() {
                // If the tunnel class is cluster-scoped, we must schedule the tunnel pods into the
                // namespace that contains the secret, otherwise can't easily mount it.
                let deployment_namespace = if ctx.namespaced {
                    svc_namespace.to_string()
                } else {
                    // For cluster-scoped tunnel classes, we use the namespace of the tunnel class.
                    // TODO: Validate elsewhere that the secret namespace is set in a cluster-scoped tunnel class?
                    netbird
                        .setup_key_ref
                        .namespace
                        .clone()
                        .unwrap_or_else(|| ctx.metadata.namespace.clone().unwrap_or_else(|| "default".to_string()))
                };

                // Define the Netbird deployment.
                let match_labels = BTreeMap::from([
                    ("app.kubernetes.io/name".to_string(), "netbird".to_string()),
                    ("app.kubernetes.io/instance".to_string(), svc_name.to_string()),
                    ("controller.tlb.io/for-service".to_string(), svc_name.clone()),
                ]);

                // Construct commands for setting up iptables in the Netbird pod.
                let cluster_iface = "eth0".to_string();
                let mut launch_script = vec!["#!/bin/sh".to_string(), "set -e".to_string()];
                if let Some(ports) = service.spec.as_ref().and_then(|spec| spec.ports.clone()) {
                    ports.iter().for_each(|port| {
                        if let Some(cluster_ip) = service.spec.as_ref().and_then(|spec| spec.cluster_ip.clone()) {
                            let protocol = port.protocol.as_ref().unwrap_or(&"TCP".to_string()).to_lowercase();
                            let port = port.port;

                            // Accept new connections to the cluster IP and port.
                            launch_script.push(format!(
                                "iptables -A FORWARD -i wt0 -o {cluster_iface} -p {protocol} -d {cluster_ip} --dport {port} -m conntrack --ctstate NEW -j ACCEPT"
                            ));

                            // Accept established connections to the cluster IP and port.
                            launch_script.push(format!(
                                "iptables -A FORWARD -i wt0 -o {cluster_iface} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
                            ));
                            launch_script.push(format!(
                                "iptables -A FORWARD -i {cluster_iface} -o wt0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
                            ));

                            // NAT packets destined for the cluster IP and port.
                            launch_script.push(format!(
                                "iptables -t nat -I PREROUTING 1 -i wt0 -p {protocol} --dport {port} -j DNAT --to-destination {cluster_ip}:{port}"
                            ));

                            launch_script.push(format!(
                                "iptables -t nat -A POSTROUTING -o {cluster_iface} -j MASQUERADE"
                            ));
                        }
                    });
                }
                launch_script.push("/usr/local/bin/netbird up".to_string());

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
                    ctx.context
                        .events
                        .publish(
                            &Event {
                                type_: EventType::Warning,
                                reason: "MissingDNSAnnotation".into(),
                                note: Some(format!(
                                    "Service `{}` in namespace `{}` does not have the `tlb.io/dns` annotation set. \
                                The controller cannot determine the IP addresses assigned to the tunnel peers,
                                hence the LoadBalancer status will stay `Pending`.",
                                    svc_name, svc_namespace
                                )),
                                action: "Reconcile".into(),
                                secondary: None,
                            },
                            &service.object_ref(&()),
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

                let deployment = Deployment {
                    metadata: ObjectMeta {
                        name: Some(format!("{}-netbird", svc_name)),
                        namespace: Some(deployment_namespace.clone()),
                        owner_references: Some(vec![
                            OwnerReference {
                                api_version: "v1".into(),
                                kind: "Service".into(),
                                name: format!("{svc_name}-netbird-tunnel"),
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
                        ]),
                        ..Default::default()
                    },
                    spec: Some(DeploymentSpec {
                        replicas: options.replicas,
                        selector: LabelSelector {
                            match_labels: Some(match_labels.clone()),
                            ..Default::default()
                        },
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
                                    image: Some("netbirdio/netbird:latest".into()),
                                    command: Some(vec!["/bin/sh".into(), "-c".into(), launch_script.join("\n")]),
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

                let api = Api::<Deployment>::namespaced(ctx.context.client.clone(), &deployment_namespace);

                // Try to fetch the existing deployment
                match api.get_opt(&format!("{}-netbird", svc_name)).await? {
                    Some(_existing) => {
                        // Patch the deployment if it exists (server-side apply)
                        use kube::api::{Patch, PatchParams};
                        api.patch(
                            &format!("{}-netbird", svc_name),
                            &PatchParams::apply("tlb-controller").force(),
                            &Patch::Apply(&deployment),
                        )
                        .await?;
                        info!("Patched deployment for service `{}`", svc_name);
                    }
                    None => {
                        // Create the deployment if it does not exist
                        use kube::api::PostParams;
                        api.create(&PostParams::default(), &deployment).await?;
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

                let api = Api::<Service>::namespaced(ctx.context.client.clone(), svc_namespace);
                let ps = PatchParams::apply("tlb-controller").force();
                api.patch_status(svc_name, &ps, &new_status).await?;

                info!("Patched status for service `{}`", svc_name);
            }

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
        events: Arc::new(kube::runtime::events::Recorder::new(client, "tlb-controller".into())),
    };

    // Periodically reconcile all tunnel classes.
    // TODO: Instead, watch services and trigger a reconciliation when a service is created or updated?
    let reconcile_interval = std::time::Duration::from_secs(10);
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
                info!("Failed to list TunnelClasses: {}", e);
            }
        };

        // Fetch all cluster-scoped tunnel classes.
        match Api::<tlb::crds::ClusterTunnelClass>::all(context.client.clone())
            .list(&ListParams::default())
            .await
        {
            Ok(resources) => tunnel_classes.extend(resources.into_iter().map(|t| (t.spec.inner, t.metadata, false))),
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
