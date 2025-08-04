use std::collections::BTreeMap;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use k8s_openapi::{
    ByteString,
    api::{
        apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy, RollingUpdateDeployment},
        core::v1::{
            ConfigMap, Container, LoadBalancerIngress, PodSpec, PodTemplateSpec, Secret, Service, ServicePort,
            ServiceStatus, Volume, VolumeMount,
        },
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference},
};
use kube::{
    Resource,
    api::{Api, Patch, PatchParams, PostParams, ResourceExt},
};
use log::{error, info};
use rand::RngCore;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    Error, ReconcileContext, Result, ServiceAnnotations, TunnelProvider,
    crds::{PangolinAnnounceType, PangolinConfig},
};

use crate::{FOR_SERVICE_LABEL, FOR_TUNNEL_CLASS_LABEL, PROVIDER_LABEL};

const FINALIZER_NAME: &str = "tlb.io/pangolin-tunnel";
const DEFAULT_PANGOLIN_IMAGE: &str = "pangolin/pangolind:latest";
const PANGOLIN_API_URL: &str = "https://api.pangolin.com/v1";
const DEFAULT_RESOURCE_PREFIX: &str = "pg-";
const DEFAULT_TUNNEL_PREFIX: &str = "kube-";

#[derive(Deserialize, Debug)]
struct PangolinApiMsg {
    #[allow(dead_code)]
    code: u16,
    #[allow(dead_code)]
    message: String,
    #[allow(dead_code)]
    documentation_url: Option<String>,
}

#[derive(Deserialize, Debug)]
struct PangolinApiResponse<T> {
    #[allow(dead_code)]
    errors: Vec<PangolinApiMsg>,
    #[allow(dead_code)]
    messages: Vec<PangolinApiMsg>,
    result: Option<T>,
    success: bool,
}

#[derive(Deserialize, Debug)]
struct Tunnel {
    id: String,
}

#[derive(Deserialize, Debug)]
struct Zone {
    id: String,
    name: String,
}

#[derive(Deserialize, Debug)]
struct DnsRecord {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    name: String,
    content: String,
    #[serde(rename = "type")]
    record_type: String,
}

#[derive(Serialize)]
struct CreateDnsRecordPayload<'a> {
    #[serde(rename = "type")]
    record_type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
    proxied: bool,
}

struct PangolinApi {
    client: reqwest::Client,
    account_id: String,
}

#[derive(Serialize)]
struct CreateTunnelPayload<'a> {
    name: &'a str,
    tunnel_secret: &'a str,
}

impl PangolinApi {
    fn new(auth_token: &str, account_id: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {auth_token}")).unwrap(),
        );
        let client = reqwest::Client::builder().default_headers(headers).build().unwrap();
        Self {
            client,
            account_id: account_id.to_string(),
        }
    }

    // TODO: This is a placeholder implementation. The actual API call may be different.
    async fn create_tunnel(&self, name: &str, tunnel_secret: &str) -> anyhow::Result<Tunnel> {
        let payload = CreateTunnelPayload {
            name,
            tunnel_secret,
        };
        let res = self
            .client
            .post(format!(
                "{}/accounts/{}/tunnels",
                PANGOLIN_API_URL, self.account_id
            ))
            .json(&payload)
            .send()
            .await?
            .text()
            .await?;

        let res: PangolinApiResponse<Tunnel> = serde_json::from_str(&res)?;

        if !res.success || res.result.is_none() {
            anyhow::bail!(res.errors.first().map_or_else(
                || "Unknown error".to_string(),
                |e| format!("Pangolin API error: {} - {}", e.code, e.message)
            ));
        }
        Ok(res.result.unwrap())
    }

    // TODO: This is a placeholder implementation. The actual API call may be different.
    async fn delete_tunnel(&self, tunnel_id: &str) -> anyhow::Result<()> {
        let res = self
            .client
            .delete(format!(
                "{}/accounts/{}/tunnels/{}",
                PANGOLIN_API_URL, self.account_id, tunnel_id
            ))
            .send()
            .await?;

        if !res.status().is_success() && res.status() != 404 {
            let status = res.status();
            let body = res
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read response body>".to_string());
            anyhow::bail!("Pangolin API error: {} - {}", status, body);
        }
        Ok(())
    }

    // TODO: This is a placeholder implementation. The actual API call may be different.
    async fn list_zones(&self) -> anyhow::Result<Vec<Zone>> {
        let res = self
            .client
            .get(format!("{}/zones", PANGOLIN_API_URL))
            .send()
            .await?
            .text()
            .await?;

        let res: PangolinApiResponse<Vec<Zone>> = serde_json::from_str(&res)?;

        if !res.success || res.result.is_none() {
            anyhow::bail!(res.errors.first().map_or_else(
                || "Unknown error".to_string(),
                |e| format!("Pangolin API error: {} - {}", e.code, e.message)
            ));
        }
        Ok(res.result.unwrap())
    }

    async fn find_zone_for_hostname(&self, hostname: &str) -> anyhow::Result<Option<Zone>> {
        let zones = self.list_zones().await?;

        let mut best_match: Option<Zone> = None;
        let mut best_match_len = 0;

        for zone in zones {
            if hostname.ends_with(&zone.name) && zone.name.len() > best_match_len {
                best_match_len = zone.name.len();
                best_match = Some(zone);
            }
        }

        Ok(best_match)
    }

    // TODO: This is a placeholder implementation. The actual API call may be different.
    async fn create_dns_record(
        &self,
        zone_id: &str,
        record_type: &str,
        name: &str,
        content: &str,
    ) -> anyhow::Result<DnsRecord> {
        let payload = CreateDnsRecordPayload {
            record_type,
            name,
            content,
            ttl: 300,
            proxied: true,
        };

        let res = self
            .client
            .post(format!("{}/zones/{}/dns_records", PANGOLIN_API_URL, zone_id))
            .json(&payload)
            .send()
            .await?
            .text()
            .await?;

        let res: PangolinApiResponse<DnsRecord> = serde_json::from_str(&res)?;

        if !res.success || res.result.is_none() {
            anyhow::bail!(res.errors.first().map_or_else(
                || "Unknown error".to_string(),
                |e| format!("Pangolin API error: {} - {}", e.code, e.message)
            ));
        }
        Ok(res.result.unwrap())
    }

    // TODO: This is a placeholder implementation. The actual API call may be different.
    async fn list_dns_records(&self, zone_id: &str, name: &str) -> anyhow::Result<Vec<DnsRecord>> {
        let res = self
            .client
            .get(format!(
                "{}/zones/{}/dns_records?name={}",
                PANGOLIN_API_URL, zone_id, name
            ))
            .send()
            .await?
            .text()
            .await?;

        let res: PangolinApiResponse<Vec<DnsRecord>> = serde_json::from_str(&res)?;

        if !res.success || res.result.is_none() {
            anyhow::bail!(res.errors.first().map_or_else(
                || "Unknown error".to_string(),
                |e| format!("Pangolin API error: {} - {}", e.code, e.message)
            ));
        }
        Ok(res.result.unwrap())
    }

    // TODO: This is a placeholder implementation. The actual API call may be different.
    async fn delete_dns_record(&self, zone_id: &str, record_id: &str) -> anyhow::Result<()> {
        let res = self
            .client
            .delete(format!(
                "{}/zones/{}/dns_records/{}",
                PANGOLIN_API_URL, zone_id, record_id
            ))
            .send()
            .await?;

        if !res.status().is_success() && res.status() != 404 {
            let status = res.status();
            let body = res
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read response body>".to_string());
            anyhow::bail!("Pangolin API error: {} - {}", status, body);
        }
        Ok(())
    }
}

const WELL_KNOWN_PORTS: &[(u16, &str)] = &[
    (80, "http"),
    (443, "https"),
    (22, "ssh"),
    (3389, "rdp"),
    (5432, "tcp"),
    (3306, "tcp"),
    (6379, "tcp"),
    (1433, "tcp"),
    (5984, "http"),
    (8080, "http"),
    (8443, "https"),
];

fn determine_port_protocol(port: &ServicePort, protocol_annotation: Option<&str>) -> String {
    if let Some(annotation) = protocol_annotation {
        for mapping in annotation.split(',') {
            let mapping = mapping.trim();
            if let Some((port_spec, protocol)) = mapping.split_once(':') {
                let port_spec = port_spec.trim();
                let protocol = protocol.trim();

                if port_spec.parse::<u16>().map(|p| p == port.port as u16).unwrap_or(false) {
                    return protocol.to_string();
                }

                if let Some(port_name) = &port.name {
                    if port_spec == port_name {
                        return protocol.to_string();
                    }
                }
            }
        }

        if !annotation.contains(':') {
            return annotation.to_string();
        }
    }

    if let Some(port_name) = &port.name {
        let name_lower = port_name.to_lowercase();
        if name_lower.contains("http") && !name_lower.contains("https") {
            return "http".to_string();
        }
        if name_lower.contains("https") {
            return "https".to_string();
        }
        if name_lower.contains("ssh") {
            return "ssh".to_string();
        }
        if name_lower.contains("rdp") {
            return "rdp".to_string();
        }
    }

    for &(well_known_port, protocol) in WELL_KNOWN_PORTS {
        if port.port as u16 == well_known_port {
            return protocol.to_string();
        }
    }

    match port.protocol.as_deref().unwrap_or("TCP").to_uppercase().as_str() {
        "UDP" => "udp".to_string(),
        _ => "tcp".to_string(),
    }
}

fn generate_pangolind_config(
    tunnel_id: &str,
    service_name: &str,
    namespace: &str,
    ports: &[ServicePort],
    protocol_annotation: Option<&str>,
) -> String {
    let mut config = format!(
        "tunnel: {}\ncredentials-file: /etc/pangolind/creds/credentials.json\ningress:\n",
        tunnel_id
    );

    for port in ports {
        let protocol = determine_port_protocol(port, protocol_annotation);
        let service_url = format!("{}://{}.{}:{}", protocol, service_name, namespace, port.port);

        config.push_str(&format!("  - service: {}\n", service_url));
    }

    config
}

async fn manage_dns_records(
    pg_client: &PangolinApi,
    dns_annotation: &str,
    tunnel_hostname: &str,
    operation: DnsOperation,
) -> DnsManagementResult {
    info!("manage_dns_records called with operation: {:?}", operation);
    let mut result = DnsManagementResult::new();
    let hostnames: Vec<&str> = dns_annotation.split(',').map(|s| s.trim()).collect();

    for hostname in hostnames {
        if hostname.is_empty() {
            continue;
        }

        match pg_client.find_zone_for_hostname(hostname).await {
            Ok(Some(zone)) => {
                info!("Found zone '{}' for hostname '{}'", zone.name, hostname);

                match operation {
                    DnsOperation::Create => {
                        match pg_client.list_dns_records(&zone.id, hostname).await {
                            Ok(existing_records) => {
                                let cname_exists = existing_records
                                    .iter()
                                    .any(|record| record.record_type == "CNAME" && record.content == tunnel_hostname);

                                if !cname_exists {
                                    match pg_client
                                        .create_dns_record(&zone.id, "CNAME", hostname, tunnel_hostname)
                                        .await
                                    {
                                        Ok(_) => {
                                            info!(
                                                "Created CNAME record for '{}' pointing to '{}'",
                                                hostname, tunnel_hostname
                                            );
                                            result.successful_hostnames.push(hostname.to_string());
                                        }
                                        Err(e) => {
                                            error!("Failed to create DNS record for '{}': {}", hostname, e);
                                            result
                                                .failed_hostnames
                                                .push((hostname.to_string(), format!("create DNS record: {}", e)));
                                        }
                                    }
                                } else {
                                    info!("CNAME record for '{}' already exists", hostname);
                                    result.successful_hostnames.push(hostname.to_string());
                                }
                            }
                            Err(e) => {
                                error!("Failed to list DNS records for '{}': {}", hostname, e);
                                result
                                    .failed_hostnames
                                    .push((hostname.to_string(), format!("list DNS records for creation: {}", e)));
                            }
                        }
                    }
                    DnsOperation::Delete => {
                        match pg_client.list_dns_records(&zone.id, hostname).await {
                            Ok(records) => {
                                for record in records {
                                    if record.record_type == "CNAME" && record.content == tunnel_hostname {
                                        match pg_client.delete_dns_record(&zone.id, &record.id).await {
                                            Ok(_) => {
                                                info!(
                                                    "Deleted DNS record for '{}' pointing to tunnel '{}'",
                                                    hostname, tunnel_hostname
                                                );
                                                result.successful_hostnames.push(hostname.to_string());
                                            }
                                            Err(e) => {
                                                error!("Failed to delete DNS record for '{}': {}", hostname, e);
                                                result
                                                    .failed_hostnames
                                                    .push((hostname.to_string(), format!("delete DNS record: {}", e)));
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to list DNS records for '{}': {}", hostname, e);
                                result
                                    .failed_hostnames
                                    .push((hostname.to_string(), format!("list DNS records for deletion: {}", e)));
                            }
                        }
                    }
                }
            }
            Ok(None) => {
                let action = match operation {
                    DnsOperation::Create => "creation",
                    DnsOperation::Delete => "cleanup",
                };
                error!("No Pangolin zone found for hostname '{}' during {}", hostname, action);
                result
                    .failed_hostnames
                    .push((hostname.to_string(), format!("no zone found during {}", action)));
            }
            Err(e) => {
                let action = match operation {
                    DnsOperation::Create => "creation",
                    DnsOperation::Delete => "cleanup",
                };
                error!(
                    "Failed to find zone for hostname '{}' during {}: {}",
                    hostname, action, e
                );
                result
                    .failed_hostnames
                    .push((hostname.to_string(), format!("find zone during {}: {}", action, e)));
            }
        }
    }

    result
}

#[derive(Clone, Copy, Debug)]
enum DnsOperation {
    Create,
    Delete,
}

#[derive(Debug)]
struct DnsManagementResult {
    successful_hostnames: Vec<String>,
    failed_hostnames: Vec<(String, String)>,
}

impl DnsManagementResult {
    fn new() -> Self {
        Self {
            successful_hostnames: Vec::new(),
            failed_hostnames: Vec::new(),
        }
    }

    fn has_successes(&self) -> bool {
        !self.successful_hostnames.is_empty()
    }

    fn has_failures(&self) -> bool {
        !self.failed_hostnames.is_empty()
    }
}

#[async_trait]
impl TunnelProvider for PangolinConfig {
    fn provider_type(&self) -> crate::ProviderType {
        crate::ProviderType::Pangolin
    }

    async fn reconcile_service(&self, ctx: &ReconcileContext, service: &Service) -> Result<()> {
        let owner_references = vec![OwnerReference {
            api_version: "v1".into(),
            kind: "Service".into(),
            name: service.name_any(),
            uid: service.metadata.uid.clone().unwrap_or_default(),
            controller: Some(false),
            block_owner_deletion: Some(true),
        }];

        let svc_name = service.name_any();
        let svc_namespace = service.namespace().unwrap_or_else(|| "default".to_string());

        let service_annotations =
            ServiceAnnotations::from(service.metadata.annotations.as_ref().cloned().unwrap_or_default());

        let ports = service
            .spec
            .as_ref()
            .and_then(|s| s.ports.as_ref())
            .cloned()
            .unwrap_or_default();
        let protocol_annotation = service
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get("tlb.io/protocol"))
            .map(|s| s.as_str());

        if self.api_token_ref.name.is_empty() || self.api_token_ref.key.is_empty() {
            return Err(Error::ConfigError(format!(
                "Invalid Pangolin configuration for service '{}': api_token_ref name='{}' key='{}' cannot be empty",
                svc_name, self.api_token_ref.name, self.api_token_ref.key
            )));
        }

        let api_token = crate::get_secret_value(
            &ctx.client,
            &self.api_token_ref,
            &svc_namespace,
        )
        .await
        .map_err(|e| Error::ConfigError(format!(
            "Failed to get API token secret for service '{}' in namespace '{}': {}",
            svc_name, svc_namespace, e
        )))?;

        let pg_client = PangolinApi::new(&api_token, &self.account_id);

        let resource_prefix = self
            .resource_prefix
            .clone()
            .unwrap_or(DEFAULT_RESOURCE_PREFIX.to_string());
        let secret_name = format!("{resource_prefix}{svc_name}");
        let secret_api: Api<Secret> = Api::namespaced(ctx.client.clone(), &svc_namespace);

        let existing_secret = secret_api.get_opt(&secret_name).await?;

        if let Some(secret) = existing_secret {
            if secret.metadata.deletion_timestamp.is_some() {
                info!("Secret {secret_name} for service {svc_name} is being deleted, cleaning up Pangolin tunnel");

                if let Some(data) = secret.data {
                    if let Some(tunnel_id_bytes) = data.get("tunnel-id") {
                        let tunnel_id = String::from_utf8(tunnel_id_bytes.0.clone()).unwrap();

                        if let Err(e) = pg_client.delete_tunnel(&tunnel_id).await {
                            error!("Failed to delete Pangolin tunnel {tunnel_id}: {e}");
                            return Err(Error::UnexpectedError(e.to_string()));
                        }
                        info!("Successfully deleted Pangolin tunnel {tunnel_id}");
                    }
                }

                let mut finalizers = secret.metadata.finalizers.unwrap_or_default();
                finalizers.retain(|f| f != FINALIZER_NAME);
                secret_api
                    .patch(
                        &secret_name,
                        &PatchParams::default(),
                        &Patch::Merge(json!({
                            "metadata": {
                                "finalizers": finalizers
                            }
                        })),
                    )
                    .await?;

                return Ok(());
            }
        }

        let tunnel_id = if let Some(secret) = secret_api.get_opt(&secret_name).await? {
            let data = secret.data.unwrap();
            String::from_utf8(data.get("tunnel-id").unwrap().0.clone()).unwrap()
        } else {
            info!("No secret found for service {svc_name}, creating new Pangolin tunnel");
            let tunnel_prefix = self.tunnel_prefix.clone().unwrap_or(DEFAULT_TUNNEL_PREFIX.to_string());
            let tunnel_name = format!("{tunnel_prefix}{svc_namespace}-{svc_name}");

            let mut tunnel_secret_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut tunnel_secret_bytes);
            let tunnel_secret = general_purpose::STANDARD.encode(tunnel_secret_bytes);

            let tunnel = pg_client
            .create_tunnel(&tunnel_name, &tunnel_secret)
            .await
            .map_err(|e| Error::UnexpectedError(format!(
                "Failed to create Pangolin tunnel '{}' for service '{}' in namespace '{}': {}",
                tunnel_name, svc_name, svc_namespace, e
            )))?;

            let credentials_json = json!({
                "AccountTag": self.account_id,
                "TunnelSecret": tunnel_secret,
                "TunnelID": tunnel.id
            });

            let secret_data = BTreeMap::from([
                ("tunnel-id".to_string(), ByteString(tunnel.id.clone().into_bytes())),
                (
                    "tunnel-secret".to_string(),
                    ByteString(tunnel_secret.clone().into_bytes()),
                ),
                (
                    "credentials.json".to_string(),
                    ByteString(credentials_json.to_string().into_bytes()),
                ),
            ]);

            let secret = Secret {
                metadata: ObjectMeta {
                    name: Some(secret_name.clone()),
                    namespace: Some(svc_namespace.clone()),
                    finalizers: Some(vec![FINALIZER_NAME.to_string()]),
                    owner_references: Some(owner_references.clone()),
                    labels: Some(BTreeMap::from([
                        (
                            FOR_TUNNEL_CLASS_LABEL.to_string(),
                            ctx.metadata.name.as_ref().unwrap().to_string(),
                        ),
                        (FOR_SERVICE_LABEL.to_string(), svc_name.clone()),
                        (PROVIDER_LABEL.to_string(), "pangolin".to_string()),
                    ])),
                    ..Default::default()
                },
                data: Some(secret_data),
                ..Default::default()
            };

            secret_api.create(&PostParams::default(), &secret).await?;
            info!("Created secret {secret_name} for service {svc_name}");

            tunnel.id
        };

        let config_content =
            generate_pangolind_config(&tunnel_id, &svc_name, &svc_namespace, &ports, protocol_annotation);

        let config_name = format!("{resource_prefix}{svc_name}-config");
        let configmap_api: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), &svc_namespace);

        let configmap = ConfigMap {
            metadata: ObjectMeta {
                name: Some(config_name.clone()),
                namespace: Some(svc_namespace.clone()),
                owner_references: Some(owner_references.clone()),
                labels: Some(BTreeMap::from([
                    (
                        FOR_TUNNEL_CLASS_LABEL.to_string(),
                        ctx.metadata.name.as_ref().unwrap().to_string(),
                    ),
                    (FOR_SERVICE_LABEL.to_string(), svc_name.clone()),
                    (PROVIDER_LABEL.to_string(), "pangolin".to_string()),
                ])),
                ..Default::default()
            },
            data: Some(BTreeMap::from([("config.yaml".to_string(), config_content)])),
            ..Default::default()
        };

        configmap_api
            .patch(
                &config_name,
                &PatchParams::apply("tlb-controller"),
                &Patch::Apply(&configmap),
            )
            .await?;

        info!("Created/updated pangolind config {config_name} for service {svc_name}");

        let configmap = configmap_api.get(&config_name).await.map_err(|e| {
            Error::UnexpectedError(format!(
                "Failed to get ConfigMap '{}' for service '{}': {}",
                config_name, svc_name, e
            ))
        })?;
        let config_version = configmap
            .metadata
            .resource_version
            .unwrap_or_else(|| "unknown".to_string());

        let secret = secret_api.get(&secret_name).await?;
        let secret_version = secret
            .metadata
            .resource_version
            .unwrap_or_else(|| "unknown".to_string());

        let deployment_name = format!("{resource_prefix}{svc_name}");
        let deployment_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), &svc_namespace);

        let deployment = Deployment {
            metadata: ObjectMeta {
                name: Some(deployment_name.clone()),
                namespace: Some(svc_namespace.clone()),
                owner_references: Some(owner_references),
                labels: Some(BTreeMap::from([
                    (
                        FOR_TUNNEL_CLASS_LABEL.to_string(),
                        ctx.metadata.name.as_ref().unwrap().to_string(),
                    ),
                    (FOR_SERVICE_LABEL.to_string(), svc_name.clone()),
                    (PROVIDER_LABEL.to_string(), "pangolin".to_string()),
                ])),
                ..Default::default()
            },
            spec: Some(DeploymentSpec {
                replicas: Some(1),
                strategy: Some(DeploymentStrategy {
                    type_: Some("RollingUpdate".to_string()),
                    rolling_update: Some(RollingUpdateDeployment {
                        max_surge: Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(1)),
                        max_unavailable: Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(0)),
                    }),
                }),
                selector: LabelSelector {
                    match_labels: Some(BTreeMap::from([("app".to_string(), deployment_name.clone())])),
                    match_expressions: None,
                },
                template: PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        labels: Some(BTreeMap::from([
                            ("app".to_string(), deployment_name.clone()),
                            (
                                "controller.tlb.io/config-version".to_string(),
                                format!("{}-{}", secret_version, config_version),
                            ),
                        ])),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        containers: vec![Container {
                            name: "pangolind".to_string(),
                            image: Some(self.image.clone().unwrap_or(DEFAULT_PANGOLIN_IMAGE.to_string())),
                            args: Some(vec![
                                "tunnel".to_string(),
                                "--no-autoupdate".to_string(),
                                "--config".to_string(),
                                "/etc/pangolind/config/config.yaml".to_string(),
                                "run".to_string(),
                            ]),
                            volume_mounts: Some(vec![
                                VolumeMount {
                                    name: "tunnel-credentials".to_string(),
                                    mount_path: "/etc/pangolind/creds".to_string(),
                                    read_only: Some(true),
                                    ..Default::default()
                                },
                                VolumeMount {
                                    name: "tunnel-config".to_string(),
                                    mount_path: "/etc/pangolind/config".to_string(),
                                    read_only: Some(true),
                                    ..Default::default()
                                },
                            ]),
                            ..Default::default()
                        }],
                        volumes: Some(vec![
                            Volume {
                                name: "tunnel-credentials".to_string(),
                                secret: Some(k8s_openapi::api::core::v1::SecretVolumeSource {
                                    secret_name: Some(secret_name.clone()),
                                    items: Some(vec![k8s_openapi::api::core::v1::KeyToPath {
                                        key: "credentials.json".to_string(),
                                        path: "credentials.json".to_string(),
                                        ..Default::default()
                                    }]),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                            Volume {
                                name: "tunnel-config".to_string(),
                                config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                                    name: config_name.clone(),
                                    items: Some(vec![k8s_openapi::api::core::v1::KeyToPath {
                                        key: "config.yaml".to_string(),
                                        path: "config.yaml".to_string(),
                                        ..Default::default()
                                    }]),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        ]),
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        };

        deployment_api
            .patch(
                &deployment_name,
                &PatchParams::apply("tlb-controller"),
                &Patch::Apply(&deployment),
            )
            .await?;

        info!("Reconciled pangolind deployment {deployment_name} for service {svc_name}");

        let tunnel_hostname = format!("{tunnel_id}.pangolintunnel.com");
        let mut ingress_hostnames = vec![];

        let announce_type = self.announce_type.as_ref().unwrap_or(&PangolinAnnounceType::External);

        match announce_type {
            PangolinAnnounceType::Internal => {
                info!(
                    "Using Internal announce mode for service '{}' - only tunnel hostname will be announced",
                    svc_name
                );
                ingress_hostnames.push(tunnel_hostname.clone());
            }
            PangolinAnnounceType::External => {
                if let Some(dns_annotation) = &service_annotations.dns {
                    let dns_result =
                        manage_dns_records(&pg_client, dns_annotation, &tunnel_hostname, DnsOperation::Create).await;

                    if dns_result.has_successes() {
                        info!(
                            "Successfully created DNS records for service '{}': {}",
                            svc_name,
                            dns_result.successful_hostnames.join(", ")
                        );

                        if dns_result.has_failures() {
                            for (hostname, error) in &dns_result.failed_hostnames {
                                ctx.events
                                    .publish(
                                        &service.object_ref(&()),
                                        kube::runtime::events::EventType::Warning,
                                        "DNSRecordFailed".into(),
                                        Some(format!("Failed to create DNS record for '{}': {}", hostname, error)),
                                        "DNSManagement".into(),
                                    )
                                    .await?;
                            }
                        }

                        ingress_hostnames = dns_result.successful_hostnames;
                    } else {
                        error!(
                            "Failed to create any DNS records for service '{}' - falling back to internal tunnel hostname",
                            svc_name
                        );
                        ingress_hostnames.push(tunnel_hostname.clone());

                        for (hostname, error) in &dns_result.failed_hostnames {
                            ctx.events
                                .publish(
                                    &service.object_ref(&()),
                                    kube::runtime::events::EventType::Warning,
                                    "DNSRecordFailed".into(),
                                    Some(format!("Failed to create DNS record for '{}': {}", hostname, error)),
                                    "DNSManagement".into(),
                                )
                                .await?;
                        }
                    }
                } else {
                    info!(
                        "No DNS annotation found for service '{}' in External mode - using tunnel hostname",
                        svc_name
                    );
                    ingress_hostnames.push(tunnel_hostname.clone());
                }
            }
        }

        let ingress: Vec<LoadBalancerIngress> = ingress_hostnames
            .into_iter()
            .map(|hostname| LoadBalancerIngress {
                hostname: Some(hostname),
                ..Default::default()
            })
            .collect();

        let status = ServiceStatus {
            load_balancer: Some(k8s_openapi::api::core::v1::LoadBalancerStatus { ingress: Some(ingress) }),
            ..Default::default()
        };

        let new_status = Patch::Apply(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "status": status
        }));

        let svc_api: Api<Service> = Api::namespaced(ctx.client.clone(), &svc_namespace);
        let ps = PatchParams::apply("tlb-controller").force();
        svc_api.patch_status(&svc_name, &ps, &new_status).await?;

        info!("Patched status for service `{svc_name}`");

        Ok(())
    }

    async fn cleanup_service(&self, ctx: &ReconcileContext, service: &Service) -> Result<()> {
        let svc_name = service.name_any();
        let svc_namespace = service.namespace().unwrap_or_else(|| "default".to_string());
        let tunnel_class_name = ctx.metadata.name.as_ref().unwrap();

        if self.api_token_ref.name.is_empty() || self.api_token_ref.key.is_empty() {
            error!(
                "Invalid Pangolin configuration for service '{}': api_token_ref name='{}' key='{}' cannot be empty",
                svc_name, self.api_token_ref.name, self.api_token_ref.key
            );
            return Err(Error::ConfigError(
                "Invalid Pangolin configuration: api_token_ref name and key cannot be empty".to_string(),
            ));
        }

        let api_token = match crate::get_secret_value(&ctx.client, &self.api_token_ref, &svc_namespace).await {
            Ok(token) => Some(token),
            Err(e) => {
                error!("Failed to get API token secret '{:?}': {}", self.api_token_ref, e);
                None
            }
        };

        let pg_client_opt = api_token
            .as_ref()
            .map(|token| PangolinApi::new(token, &self.account_id));

        let service_annotations =
            ServiceAnnotations::from(service.metadata.annotations.as_ref().cloned().unwrap_or_default());

        let label_selector = format!(
            "{}={},{}={},{}={}",
            crate::FOR_SERVICE_LABEL,
            svc_name,
            crate::FOR_TUNNEL_CLASS_LABEL,
            tunnel_class_name,
            crate::PROVIDER_LABEL,
            "pangolin"
        );

        let secret_api: Api<Secret> = Api::namespaced(ctx.client.clone(), &svc_namespace);
        let secrets = secret_api
            .list(&kube::api::ListParams::default().labels(&label_selector))
            .await
            .map_err(|e| {
                Error::UnexpectedError(format!(
                    "Failed to list Secrets for service '{}' in namespace '{}': {}",
                    svc_name, svc_namespace, e
                ))
            })?;

        let mut critical_cleanup_errors: Vec<String> = Vec::new();

        for secret in secrets {
            let secret_name = secret.metadata.name.as_ref().unwrap();

            if secret
                .metadata
                .finalizers
                .as_ref()
                .map(|f| f.contains(&FINALIZER_NAME.to_string()))
                .unwrap_or(false)
            {
                let mut cleanup_successful = true;
                let mut cleanup_errors = Vec::new();

                if let Some(pg_client) = &pg_client_opt {
                    info!("Cleaning up Pangolin tunnel for secret `{secret_name}` before deletion");

                    if let Some(tunnel_data) = &secret.data {
                        if let Some(tunnel_id_bytes) = tunnel_data.get("tunnel-id") {
                            if let Ok(tunnel_id) = String::from_utf8(tunnel_id_bytes.0.clone()) {
                                let tunnel_hostname = format!("{tunnel_id}.pangolintunnel.com");

                                let announce_type =
                                    self.announce_type.as_ref().unwrap_or(&PangolinAnnounceType::External);

                                match announce_type {
                                    PangolinAnnounceType::Internal => {
                                        info!(
                                            "Internal announce mode for tunnel {tunnel_id} - no DNS records to clean up"
                                        );
                                    }
                                    PangolinAnnounceType::External => {
                                        if let Some(dns_annotation) = &service_annotations.dns {
                                            let dns_result = manage_dns_records(
                                                pg_client,
                                                dns_annotation,
                                                &tunnel_hostname,
                                                DnsOperation::Delete,
                                            )
                                            .await;

                                            if dns_result.has_failures() {
                                                let failed_hostnames: Vec<String> = dns_result
                                                    .failed_hostnames
                                                    .iter()
                                                    .map(|(hostname, error)| format!("{}: {}", hostname, error))
                                                    .collect();
                                                let error_msg = format!(
                                                    "DNS record deletion failed: {}",
                                                    failed_hostnames.join(", ")
                                                );
                                                error!(
                                                    "Failed to delete some DNS records for tunnel {tunnel_id}: {}",
                                                    error_msg
                                                );
                                                cleanup_errors.push(format!("DNS record deletion: {}", error_msg));
                                                cleanup_successful = false;

                                                for (hostname, error) in &dns_result.failed_hostnames {
                                                    if let Err(e) = ctx
                                                        .events
                                                        .publish(
                                                            &service.object_ref(&()),
                                                            kube::runtime::events::EventType::Warning,
                                                            "DNSRecordDeletionFailed".into(),
                                                            Some(format!(
                                                                "Failed to delete DNS record for '{}': {}",
                                                                hostname, error
                                                            )),
                                                            "DNSCleanup".into(),
                                                        )
                                                        .await
                                                    {
                                                        log::warn!(
                                                            "Failed to publish DNS deletion failure event: {}",
                                                            e
                                                        );
                                                    }
                                                }
                                            } else {
                                                info!("Successfully deleted DNS records for tunnel {tunnel_id}");
                                            }
                                        } else {
                                            info!(
                                                "No DNS annotation found for tunnel {tunnel_id} - no DNS records to clean up"
                                            );
                                        }
                                    }
                                }

                                if let Err(e) = pg_client.delete_tunnel(&tunnel_id).await {
                                    error!("Failed to delete Pangolin tunnel {tunnel_id}: {e}");
                                    cleanup_errors.push(format!("tunnel deletion: {e}"));
                                    cleanup_successful = false;
                                } else {
                                    info!("Successfully deleted Pangolin tunnel {tunnel_id}");
                                }
                            }
                        }
                    }
                } else {
                    cleanup_errors.push("no API access available for tunnel cleanup".to_string());
                    cleanup_successful = false;
                }

                if cleanup_successful {
                    let mut finalizers = secret.metadata.finalizers.clone().unwrap_or_default();
                    finalizers.retain(|f| f != FINALIZER_NAME);
                    secret_api
                        .patch(
                            secret_name,
                            &PatchParams::default(),
                            &Patch::Merge(json!({
                                "metadata": {
                                    "finalizers": finalizers
                                }
                            })),
                        )
                        .await
                        .map_err(|e| {
                            Error::UnexpectedError(format!(
                                "Failed to remove finalizer from Secret '{}' for service '{}': {}",
                                secret_name, svc_name, e
                            ))
                        })?;

                    info!("Removed finalizer from pangolin secret `{secret_name}` for service `{svc_name}`");
                } else {
                    ctx.events
                        .publish(
                            &secret.object_ref(&()),
                            kube::runtime::events::EventType::Warning,
                            "CleanupFailed".into(),
                            Some(format!(
                                "Cannot remove finalizer from secret `{secret_name}`: cleanup failed ({})",
                                cleanup_errors.join(", ")
                            )),
                            "Cleanup".into(),
                        )
                        .await?;

                    error!(
                        "Cleanup failed for secret `{secret_name}`, keeping finalizer in place: {}",
                        cleanup_errors.join(", ")
                    );
                    critical_cleanup_errors.extend(
                        cleanup_errors
                            .iter()
                            .map(|e| format!("secret '{}': {}", secret_name, e)),
                    );
                    continue;
                }
            }

            info!("Deleting pangolin secret `{secret_name}` for service `{svc_name}` using label selector");
            secret_api.delete(secret_name, &Default::default()).await.map_err(|e| {
                Error::UnexpectedError(format!(
                    "Failed to delete Secret '{}' for service '{}': {}",
                    secret_name, svc_name, e
                ))
            })?;
        }

        let configmap_api: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), &svc_namespace);
        let configmaps = configmap_api
            .list(&kube::api::ListParams::default().labels(&label_selector))
            .await
            .map_err(|e| {
                Error::UnexpectedError(format!(
                    "Failed to list ConfigMaps for service '{}' in namespace '{}': {}",
                    svc_name, svc_namespace, e
                ))
            })?;

        for configmap in configmaps {
            let configmap_name = configmap.metadata.name.as_ref().unwrap();
            info!("Deleting pangolin configmap `{configmap_name}` for service `{svc_name}` using label selector");
            configmap_api
                .delete(configmap_name, &Default::default())
                .await
                .map_err(|e| {
                    Error::UnexpectedError(format!(
                        "Failed to delete ConfigMap '{}' for service '{}': {}",
                        configmap_name, svc_name, e
                    ))
                })?;
        }

        let deployment_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), &svc_namespace);
        let deployments = deployment_api
            .list(&kube::api::ListParams::default().labels(&label_selector))
            .await
            .map_err(|e| {
                Error::UnexpectedError(format!(
                    "Failed to list Deployments for service '{}' in namespace '{}': {}",
                    svc_name, svc_namespace, e
                ))
            })?;

        for deployment in deployments {
            let deployment_name = deployment.metadata.name.as_ref().unwrap();
            info!("Deleting pangolin deployment `{deployment_name}` for service `{svc_name}` using label selector");
            deployment_api
                .delete(deployment_name, &Default::default())
                .await
                .map_err(|e| {
                    Error::UnexpectedError(format!(
                        "Failed to delete Deployment '{}' for service '{}': {}",
                        deployment_name, svc_name, e
                    ))
                })?;
        }

        if !critical_cleanup_errors.is_empty() {
            return Err(Error::UnexpectedError(format!(
                "Critical cleanup operations failed for service '{}': {}",
                svc_name,
                critical_cleanup_errors.join(", ")
            )));
        }

        Ok(())
    }
}
