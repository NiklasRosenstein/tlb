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
    crds::{CloudflareAnnounceType, CloudflareConfig},
};

use crate::{FOR_SERVICE_LABEL, FOR_TUNNEL_CLASS_LABEL, PROVIDER_LABEL};

const FINALIZER_NAME: &str = "tlb.io/cloudflare-tunnel";
const DEFAULT_CLOUDFLARED_IMAGE: &str = "cloudflare/cloudflared:latest";
const CLOUDFLARE_API_URL: &str = "https://api.cloudflare.com/client/v4";
const DEFAULT_RESOURCE_PREFIX: &str = "cf-";
const DEFAULT_TUNNEL_PREFIX: &str = "kube-";

#[derive(Deserialize, Debug)]
struct CloudflareApiMsg {
    #[allow(dead_code)]
    code: u16,
    #[allow(dead_code)]
    message: String,
    #[allow(dead_code)]
    documentation_url: Option<String>,
    // source
}

#[derive(Deserialize, Debug)]
struct CloudflareApiResponse<T> {
    #[allow(dead_code)]
    errors: Vec<CloudflareApiMsg>,
    #[allow(dead_code)]
    messages: Vec<CloudflareApiMsg>,
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

struct CloudflareApi {
    client: reqwest::Client,
    account_id: String,
}

#[derive(Serialize)]
struct CreateTunnelPayload<'a> {
    name: &'a str,
    config_src: &'a str,
    tunnel_secret: &'a str,
}

impl CloudflareApi {
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

    async fn create_tunnel(&self, name: &str, tunnel_secret: &str) -> anyhow::Result<Tunnel> {
        let payload = CreateTunnelPayload {
            name,
            config_src: "cloudflare",
            tunnel_secret,
        };
        let res = self
            .client
            .post(format!(
                "{}/accounts/{}/cfd_tunnel",
                CLOUDFLARE_API_URL, self.account_id
            ))
            .json(&payload)
            .send()
            .await?
            .text()
            .await?;

        let res: CloudflareApiResponse<Tunnel> = serde_json::from_str(&res)?;

        if !res.success || res.result.is_none() {
            anyhow::bail!(res.errors.first().map_or_else(
                || "Unknown error".to_string(),
                |e| format!("Cloudflare API error: {} - {}", e.code, e.message)
            ));
        }
        Ok(res.result.unwrap())
    }

    async fn delete_tunnel(&self, tunnel_id: &str) -> anyhow::Result<()> {
        let res = self
            .client
            .delete(format!(
                "{}/accounts/{}/cfd_tunnel/{}",
                CLOUDFLARE_API_URL, self.account_id, tunnel_id
            ))
            .send()
            .await?;

        if !res.status().is_success() && res.status() != 404 {
            let status = res.status();
            let body = res
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read response body>".to_string());
            anyhow::bail!("Cloudflare API error: {} - {}", status, body);
        }
        Ok(())
    }

    async fn list_zones(&self) -> anyhow::Result<Vec<Zone>> {
        let res = self
            .client
            .get(format!("{CLOUDFLARE_API_URL}/zones"))
            .send()
            .await?
            .text()
            .await?;

        let res: CloudflareApiResponse<Vec<Zone>> = serde_json::from_str(&res)?;

        if !res.success || res.result.is_none() {
            anyhow::bail!(res.errors.first().map_or_else(
                || "Unknown error".to_string(),
                |e| format!("Cloudflare API error: {} - {}", e.code, e.message)
            ));
        }
        Ok(res.result.unwrap())
    }

    async fn find_zone_for_hostname(&self, hostname: &str) -> anyhow::Result<Option<Zone>> {
        let zones = self.list_zones().await?;

        // Find the most specific zone that matches the hostname
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
            ttl: 300,      // 5 minutes TTL
            proxied: true, // Enable proxying for Cloudflare tunnels
        };

        let res = self
            .client
            .post(format!("{CLOUDFLARE_API_URL}/zones/{zone_id}/dns_records"))
            .json(&payload)
            .send()
            .await?
            .text()
            .await?;

        let res: CloudflareApiResponse<DnsRecord> = serde_json::from_str(&res)?;

        if !res.success || res.result.is_none() {
            anyhow::bail!(res.errors.first().map_or_else(
                || "Unknown error".to_string(),
                |e| format!("Cloudflare API error: {} - {}", e.code, e.message)
            ));
        }
        Ok(res.result.unwrap())
    }

    async fn list_dns_records(&self, zone_id: &str, name: &str) -> anyhow::Result<Vec<DnsRecord>> {
        let res = self
            .client
            .get(format!("{CLOUDFLARE_API_URL}/zones/{zone_id}/dns_records?name={name}"))
            .send()
            .await?
            .text()
            .await?;

        let res: CloudflareApiResponse<Vec<DnsRecord>> = serde_json::from_str(&res)?;

        if !res.success || res.result.is_none() {
            anyhow::bail!(res.errors.first().map_or_else(
                || "Unknown error".to_string(),
                |e| format!("Cloudflare API error: {} - {}", e.code, e.message)
            ));
        }
        Ok(res.result.unwrap())
    }

    async fn delete_dns_record(&self, zone_id: &str, record_id: &str) -> anyhow::Result<()> {
        let res = self
            .client
            .delete(format!("{CLOUDFLARE_API_URL}/zones/{zone_id}/dns_records/{record_id}"))
            .send()
            .await?;

        if !res.status().is_success() && res.status() != 404 {
            let status = res.status();
            let body = res
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read response body>".to_string());
            anyhow::bail!("Cloudflare API error: {} - {}", status, body);
        }
        Ok(())
    }
}

/// Well-known port to protocol mappings
const WELL_KNOWN_PORTS: &[(u16, &str)] = &[
    (80, "http"),
    (443, "https"),
    (22, "ssh"),
    (3389, "rdp"),
    (5432, "tcp"),   // PostgreSQL
    (3306, "tcp"),   // MySQL
    (6379, "tcp"),   // Redis
    (1433, "tcp"),   // SQL Server
    (5984, "http"),  // CouchDB
    (8080, "http"),  // Common HTTP alternate
    (8443, "https"), // Common HTTPS alternate
];

/// Determines the protocol for a given service port based on map-ports annotation, port name, and well-known ports
fn determine_port_protocol(port: &ServicePort, map_ports_annotation: Option<&str>) -> String {
    // 1. Check explicit map-ports annotation first
    if let Some(annotation) = map_ports_annotation {
        // Handle port mappings in NetBird format:
        // - NetBird format: "443/tls:8080" (listen_port[/tls]:service_port)
        for mapping in annotation.split(',') {
            let mapping = mapping.trim();
            if let Some((left_spec, right_spec)) = mapping.split_once(':') {
                let left_spec = left_spec.trim();
                let right_spec = right_spec.trim();

                // Check if this mapping applies to our port (by number or name)
                let port_matches = right_spec
                    .parse::<u16>()
                    .map(|p| p == port.port as u16)
                    .unwrap_or(false)
                    || port.name.as_ref().map(|name| name == right_spec).unwrap_or(false);

                if port_matches {
                    // Parse NetBird format - left_spec should be a port number, optionally with /tls
                    if let Ok(_listen_port) = left_spec.strip_suffix("/tls").unwrap_or(left_spec).parse::<u16>() {
                        // This is NetBird format - for Cloudflare, we need to determine protocol from service port
                        // Use well-known port mappings or port name hints
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

                        // Check well-known ports for the service port
                        for &(well_known_port, protocol) in WELL_KNOWN_PORTS {
                            if port.port as u16 == well_known_port {
                                return protocol.to_string();
                            }
                        }
                        return "tcp".to_string();
                    }
                }
            }
        }
    }

    // 2. Check port name for protocol hints
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

    // 3. Check well-known ports
    for &(well_known_port, protocol) in WELL_KNOWN_PORTS {
        if port.port as u16 == well_known_port {
            return protocol.to_string();
        }
    }

    // 4. Fallback to TCP/UDP based on port protocol
    match port.protocol.as_deref().unwrap_or("TCP").to_uppercase().as_str() {
        "UDP" => "udp".to_string(),
        _ => "tcp".to_string(),
    }
}

/// Finds the service port that matches a port mapping
fn find_service_port<'a>(mapping: &crate::PortMapping, ports: &'a [ServicePort]) -> Option<&'a ServicePort> {
    // Try to match by port number first
    if let Ok(port_number) = mapping.service_port.parse::<u16>() {
        for port in ports {
            if port.port as u16 == port_number {
                return Some(port);
            }
        }
    }

    // Try to match by port name
    for port in ports {
        if let Some(port_name) = &port.name {
            if *port_name == mapping.service_port {
                return Some(port);
            }
        }
    }

    None
}

/// Determines the protocol for Cloudflare from a PortMapping and ServicePort
fn determine_protocol_from_mapping(mapping: &crate::PortMapping, service_port: &ServicePort) -> String {
    // For Cloudflare, we can use the listen port information to determine protocol

    // First, check if listen port is a named port that indicates protocol
    let listen_port_lower = mapping.listen_port.to_lowercase();
    if listen_port_lower == "http" {
        return "http".to_string();
    }
    if listen_port_lower == "https" {
        return "https".to_string();
    }
    if listen_port_lower == "ssh" {
        return "ssh".to_string();
    }
    if listen_port_lower == "rdp" {
        return "rdp".to_string();
    }

    // If listen port is numeric, check for well-known port numbers
    if let Ok(port_num) = mapping.listen_port.parse::<u16>() {
        for &(well_known_port, protocol) in WELL_KNOWN_PORTS {
            if port_num == well_known_port {
                return protocol.to_string();
            }
        }
    }

    // Fall back to checking service port name for protocol hints
    if let Some(port_name) = &service_port.name {
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

    // Check well-known ports for the service port
    for &(well_known_port, protocol) in WELL_KNOWN_PORTS {
        if service_port.port as u16 == well_known_port {
            return protocol.to_string();
        }
    }

    // Default to tcp
    "tcp".to_string()
}

/// Generates cloudflared configuration YAML content
fn generate_cloudflared_config(
    tunnel_id: &str,
    service_name: &str,
    namespace: &str,
    ports: &[ServicePort],
    map_ports_annotation: Option<&str>,
) -> String {
    let mut config =
        format!("tunnel: {tunnel_id}\ncredentials-file: /etc/cloudflared/creds/credentials.json\ningress:\n");

    // Parse port mappings if annotation exists
    if let Some(annotation) = map_ports_annotation {
        // Use PortMapping struct to parse the annotation
        match crate::PortMapping::parse_multiple(annotation) {
            Ok(port_mappings) => {
                // Generate service entries based on port mappings
                for mapping in port_mappings {
                    // Find the corresponding service port
                    if let Some(service_port) = find_service_port(&mapping, ports) {
                        let protocol = determine_protocol_from_mapping(&mapping, service_port);
                        let service_url =
                            format!("{}://{}.{}:{}", protocol, service_name, namespace, service_port.port);
                        config.push_str(&format!("  - service: {service_url}\n"));
                    }
                }
            }
            Err(_) => {
                // Fall back to generating entries for each service port if parsing fails
                for port in ports {
                    let protocol = determine_port_protocol(port, map_ports_annotation);
                    let service_url = format!("{}://{}.{}:{}", protocol, service_name, namespace, port.port);
                    config.push_str(&format!("  - service: {service_url}\n"));
                }
            }
        }
    } else {
        // No annotation - generate entries for each service port
        for port in ports {
            let protocol = determine_port_protocol(port, None);
            let service_url = format!("{}://{}.{}:{}", protocol, service_name, namespace, port.port);
            config.push_str(&format!("  - service: {service_url}\n"));
        }
    }

    config
}

/// Manages DNS records for a service - either creates or deletes them based on the operation
/// Returns DnsManagementResult with both successful and failed hostnames
async fn manage_dns_records(
    cf_client: &CloudflareApi,
    dns_annotation: &str,
    tunnel_hostname: &str,
    operation: DnsOperation,
) -> DnsManagementResult {
    info!("manage_dns_records called with operation: {operation:?}");
    let mut result = DnsManagementResult::new();
    let hostnames: Vec<&str> = dns_annotation.split(',').map(|s| s.trim()).collect();

    for hostname in hostnames {
        if hostname.is_empty() {
            continue;
        }

        // Find the appropriate zone for this hostname
        match cf_client.find_zone_for_hostname(hostname).await {
            Ok(Some(zone)) => {
                info!("Found zone '{}' for hostname '{}'", zone.name, hostname);

                match operation {
                    DnsOperation::Create => {
                        // Check if DNS record already exists
                        match cf_client.list_dns_records(&zone.id, hostname).await {
                            Ok(existing_records) => {
                                let cname_exists = existing_records
                                    .iter()
                                    .any(|record| record.record_type == "CNAME" && record.content == tunnel_hostname);

                                if !cname_exists {
                                    // Create CNAME record pointing to the tunnel
                                    match cf_client
                                        .create_dns_record(&zone.id, "CNAME", hostname, tunnel_hostname)
                                        .await
                                    {
                                        Ok(_) => {
                                            info!(
                                                "Created CNAME record for '{hostname}' pointing to '{tunnel_hostname}'"
                                            );
                                            result.successful_hostnames.push(hostname.to_string());
                                        }
                                        Err(e) => {
                                            error!("Failed to create DNS record for '{hostname}': {e}");
                                            result
                                                .failed_hostnames
                                                .push((hostname.to_string(), format!("create DNS record: {e}")));
                                        }
                                    }
                                } else {
                                    info!("CNAME record for '{hostname}' already exists");
                                    result.successful_hostnames.push(hostname.to_string());
                                }
                            }
                            Err(e) => {
                                error!("Failed to list DNS records for '{hostname}': {e}");
                                result
                                    .failed_hostnames
                                    .push((hostname.to_string(), format!("list DNS records for creation: {e}")));
                            }
                        }
                    }
                    DnsOperation::Delete => {
                        // List DNS records for this hostname and delete matching ones
                        match cf_client.list_dns_records(&zone.id, hostname).await {
                            Ok(records) => {
                                // Find CNAME records pointing to our tunnel
                                for record in records {
                                    if record.record_type == "CNAME" && record.content == tunnel_hostname {
                                        match cf_client.delete_dns_record(&zone.id, &record.id).await {
                                            Ok(_) => {
                                                info!(
                                                    "Deleted DNS record for '{hostname}' pointing to tunnel '{tunnel_hostname}'"
                                                );
                                                result.successful_hostnames.push(hostname.to_string());
                                            }
                                            Err(e) => {
                                                error!("Failed to delete DNS record for '{hostname}': {e}");
                                                result
                                                    .failed_hostnames
                                                    .push((hostname.to_string(), format!("delete DNS record: {e}")));
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to list DNS records for '{hostname}': {e}");
                                result
                                    .failed_hostnames
                                    .push((hostname.to_string(), format!("list DNS records for deletion: {e}")));
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
                error!("No Cloudflare zone found for hostname '{hostname}' during {action}");
                result
                    .failed_hostnames
                    .push((hostname.to_string(), format!("no zone found during {action}")));
            }
            Err(e) => {
                let action = match operation {
                    DnsOperation::Create => "creation",
                    DnsOperation::Delete => "cleanup",
                };
                error!("Failed to find zone for hostname '{hostname}' during {action}: {e}");
                result
                    .failed_hostnames
                    .push((hostname.to_string(), format!("find zone during {action}: {e}")));
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

/// Result of DNS record management operations
#[derive(Debug)]
struct DnsManagementResult {
    /// Hostnames that were successfully processed
    successful_hostnames: Vec<String>,
    /// Errors for hostnames that failed to be processed
    failed_hostnames: Vec<(String, String)>, // (hostname, error)
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
impl TunnelProvider for CloudflareConfig {
    fn provider_type(&self) -> crate::ProviderType {
        crate::ProviderType::Cloudflare
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

        // Parse service annotations using the existing ServiceAnnotations struct
        let service_annotations =
            ServiceAnnotations::from(service.metadata.annotations.as_ref().cloned().unwrap_or_default());

        // Get service ports and use map_ports annotation
        let ports = service
            .spec
            .as_ref()
            .and_then(|s| s.ports.as_ref())
            .cloned()
            .unwrap_or_default();
        let map_ports_annotation = service_annotations.map_ports.as_deref();

        // Validate api_token_ref configuration first
        if self.api_token_ref.name.is_empty() || self.api_token_ref.key.is_empty() {
            return Err(Error::ConfigError(format!(
                "Invalid Cloudflare configuration for service '{}': api_token_ref name='{}' key='{}' cannot be empty",
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
            "Failed to get API token secret for service '{}' in namespace '{}': {} (in cloudflare::reconcile_service at {}:{})",
            svc_name, svc_namespace, e, file!(), line!()
        )))?;

        let cf_client = CloudflareApi::new(&api_token, &self.account_id);

        let resource_prefix = self
            .resource_prefix
            .clone()
            .unwrap_or(DEFAULT_RESOURCE_PREFIX.to_string());
        let secret_name = format!("{resource_prefix}{svc_name}");
        let secret_api: Api<Secret> = Api::namespaced(ctx.client.clone(), &svc_namespace);

        let existing_secret = secret_api.get_opt(&secret_name).await?;

        // TODO(@niklas): Handle the case where the Tunnel no longer exists in Cloudflare.

        if let Some(secret) = existing_secret {
            if secret.metadata.deletion_timestamp.is_some() {
                info!("Secret {secret_name} for service {svc_name} is being deleted, cleaning up Cloudflare tunnel");

                if let Some(data) = secret.data {
                    if let Some(tunnel_id_bytes) = data.get("tunnel-id") {
                        let tunnel_id = String::from_utf8(tunnel_id_bytes.0.clone()).unwrap();

                        // TODO(@niklas): Handle the tunnel cleanup in cleanup_service(), such that it is also called
                        //                when the tunnel class is deleted.
                        if let Err(e) = cf_client.delete_tunnel(&tunnel_id).await {
                            error!("Failed to delete Cloudflare tunnel {tunnel_id}: {e}");
                            return Err(Error::CloudflareError(e.to_string()));
                        }
                        info!("Successfully deleted Cloudflare tunnel {tunnel_id}");
                    }
                }

                // Remove finalizer
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
            info!("No secret found for service {svc_name}, creating new Cloudflare tunnel");
            let tunnel_prefix = self.tunnel_prefix.clone().unwrap_or(DEFAULT_TUNNEL_PREFIX.to_string());
            let tunnel_name = format!("{tunnel_prefix}{svc_namespace}-{svc_name}");

            // Generate a random 32-byte tunnel secret and encode it as base64
            let mut tunnel_secret_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut tunnel_secret_bytes);
            let tunnel_secret = general_purpose::STANDARD.encode(tunnel_secret_bytes);

            let tunnel = cf_client
            .create_tunnel(&tunnel_name, &tunnel_secret)
            .await
            .map_err(|e| Error::CloudflareError(format!(
                "Failed to create Cloudflare tunnel '{}' for service '{}' in namespace '{}': {} (in cloudflare::reconcile_service at {}:{})",
                tunnel_name, svc_name, svc_namespace, e, file!(), line!()
            )))?;

            // Create the credentials.json file for cloudflared
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
                        (PROVIDER_LABEL.to_string(), "cloudflare".to_string()),
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

        // Generate cloudflared configuration
        let config_content =
            generate_cloudflared_config(&tunnel_id, &svc_name, &svc_namespace, &ports, map_ports_annotation);

        // Create ConfigMap with cloudflared configuration
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
                    (PROVIDER_LABEL.to_string(), "cloudflare".to_string()),
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

        info!("Created/updated cloudflared config {config_name} for service {svc_name}");

        // Fetch current configmap to get its resource version.
        let configmap = configmap_api.get(&config_name).await.map_err(|e| {
            Error::CloudflareError(format!(
                "Failed to get ConfigMap '{config_name}' for service '{svc_name}': {e}"
            ))
        })?;
        let config_version = configmap
            .metadata
            .resource_version
            .unwrap_or_else(|| "unknown".to_string());

        // Get the secret to include its resource version in pod labels for automatic rotation
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
                    (PROVIDER_LABEL.to_string(), "cloudflare".to_string()),
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
                                format!("{secret_version}-{config_version}"),
                            ),
                        ])),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        affinity: crate::build_pod_affinity_for_service(service).map(|pod_affinity| {
                            k8s_openapi::api::core::v1::Affinity {
                                pod_affinity: Some(pod_affinity),
                                ..Default::default()
                            }
                        }),
                        containers: vec![Container {
                            name: "cloudflared".to_string(),
                            image: Some(self.image.clone().unwrap_or(DEFAULT_CLOUDFLARED_IMAGE.to_string())),
                            args: Some(vec![
                                "tunnel".to_string(),
                                "--no-autoupdate".to_string(),
                                "--config".to_string(),
                                "/etc/cloudflared/config/config.yaml".to_string(),
                                "run".to_string(),
                            ]),
                            volume_mounts: Some(vec![
                                VolumeMount {
                                    name: "tunnel-credentials".to_string(),
                                    mount_path: "/etc/cloudflared/creds".to_string(),
                                    read_only: Some(true),
                                    ..Default::default()
                                },
                                VolumeMount {
                                    name: "tunnel-config".to_string(),
                                    mount_path: "/etc/cloudflared/config".to_string(),
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

        info!("Reconciled cloudflared deployment {deployment_name} for service {svc_name}");

        // Handle DNS configuration based on announce_type
        let tunnel_hostname = format!("{tunnel_id}.cfargotunnel.com");
        let mut ingress_hostnames = vec![];

        // Get the announce type, defaulting to External
        let announce_type = self.announce_type.as_ref().unwrap_or(&CloudflareAnnounceType::External);

        match announce_type {
            CloudflareAnnounceType::Internal => {
                // Internal mode: only use the tunnel hostname, no DNS record management
                info!("Using Internal announce mode for service '{svc_name}' - only tunnel hostname will be announced");
                ingress_hostnames.push(tunnel_hostname.clone());
            }
            CloudflareAnnounceType::External => {
                // External mode: try to create DNS records, fall back to internal if that fails
                if let Some(dns_annotation) = &service_annotations.dns {
                    let dns_result =
                        manage_dns_records(&cf_client, dns_annotation, &tunnel_hostname, DnsOperation::Create).await;

                    if dns_result.has_successes() {
                        // At least some DNS records were created successfully
                        info!(
                            "Successfully created DNS records for service '{}': {}",
                            svc_name,
                            dns_result.successful_hostnames.join(", ")
                        );

                        // Post events for any failed DNS records
                        if dns_result.has_failures() {
                            for (hostname, error) in &dns_result.failed_hostnames {
                                ctx.events
                                    .publish(
                                        &service.object_ref(&()),
                                        kube::runtime::events::EventType::Warning,
                                        "DNSRecordFailed".into(),
                                        Some(format!("Failed to create DNS record for '{hostname}': {error}")),
                                        "DNSManagement".into(),
                                    )
                                    .await?;
                            }
                        }

                        ingress_hostnames = dns_result.successful_hostnames;
                    } else {
                        // All DNS records failed - fall back to tunnel hostname
                        error!(
                            "Failed to create any DNS records for service '{svc_name}' - falling back to internal tunnel hostname"
                        );
                        ingress_hostnames.push(tunnel_hostname.clone());

                        // Post events for all failed DNS records
                        for (hostname, error) in &dns_result.failed_hostnames {
                            ctx.events
                                .publish(
                                    &service.object_ref(&()),
                                    kube::runtime::events::EventType::Warning,
                                    "DNSRecordFailed".into(),
                                    Some(format!("Failed to create DNS record for '{hostname}': {error}")),
                                    "DNSManagement".into(),
                                )
                                .await?;
                        }
                    }
                } else {
                    info!("No DNS annotation found for service '{svc_name}' in External mode - using tunnel hostname");
                    // No DNS annotation in external mode - use tunnel hostname
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

        // Validate api_token_ref configuration first
        if self.api_token_ref.name.is_empty() || self.api_token_ref.key.is_empty() {
            error!(
                "Invalid Cloudflare configuration for service '{}': api_token_ref name='{}' key='{}' cannot be empty",
                svc_name, self.api_token_ref.name, self.api_token_ref.key
            );
            return Err(Error::ConfigError(
                "Invalid Cloudflare configuration: api_token_ref name and key cannot be empty".to_string(),
            ));
        }

        // Get API token for cleanup operations
        let api_token = match crate::get_secret_value(&ctx.client, &self.api_token_ref, &svc_namespace).await {
            Ok(token) => Some(token),
            Err(e) => {
                error!("Failed to get API token secret '{:?}': {}", self.api_token_ref, e);
                // Continue with Kubernetes resource cleanup even if API access fails
                None
            }
        };

        let cf_client_opt = api_token
            .as_ref()
            .map(|token| CloudflareApi::new(token, &self.account_id));

        // Parse service annotations to potentially use in secret cleanup
        let service_annotations =
            ServiceAnnotations::from(service.metadata.annotations.as_ref().cloned().unwrap_or_default());

        // Use label selectors to find resources instead of hardcoded names
        // This ensures cleanup works even if resource_prefix changes
        let label_selector = format!(
            "{}={},{}={},{}={}",
            crate::FOR_SERVICE_LABEL,
            svc_name,
            crate::FOR_TUNNEL_CLASS_LABEL,
            tunnel_class_name,
            crate::PROVIDER_LABEL,
            "cloudflare"
        );

        // Clean up Secrets - need to handle finalizers properly
        let secret_api: Api<Secret> = Api::namespaced(ctx.client.clone(), &svc_namespace);
        let secrets = secret_api
            .list(&kube::api::ListParams::default().labels(&label_selector))
            .await
            .map_err(|e| {
                Error::CloudflareError(format!(
                    "Failed to list Secrets for service '{svc_name}' in namespace '{svc_namespace}': {e}"
                ))
            })?;

        // Track if any critical cleanup operations failed (like tunnel deletion)
        let mut critical_cleanup_errors: Vec<String> = Vec::new();

        for secret in secrets {
            let secret_name = secret.metadata.name.as_ref().unwrap();

            // Check if this secret has tunnel credentials and clean up the tunnel first
            if secret
                .metadata
                .finalizers
                .as_ref()
                .map(|f| f.contains(&FINALIZER_NAME.to_string()))
                .unwrap_or(false)
            {
                let mut cleanup_successful = true;
                let mut cleanup_errors = Vec::new();

                // Only attempt cleanup if we have API access
                if let Some(cf_client) = &cf_client_opt {
                    info!("Cleaning up Cloudflare tunnel for secret `{secret_name}` before deletion");

                    if let Some(tunnel_data) = &secret.data {
                        if let Some(tunnel_id_bytes) = tunnel_data.get("tunnel-id") {
                            if let Ok(tunnel_id) = String::from_utf8(tunnel_id_bytes.0.clone()) {
                                let tunnel_hostname = format!("{tunnel_id}.cfargotunnel.com");

                                // Clean up DNS records based on announce_type
                                let announce_type =
                                    self.announce_type.as_ref().unwrap_or(&CloudflareAnnounceType::External);

                                match announce_type {
                                    CloudflareAnnounceType::Internal => {
                                        // Internal mode: no DNS records to clean up
                                        info!(
                                            "Internal announce mode for tunnel {tunnel_id} - no DNS records to clean up"
                                        );
                                    }
                                    CloudflareAnnounceType::External => {
                                        // External mode: clean up DNS records if service had DNS annotation
                                        if let Some(dns_annotation) = &service_annotations.dns {
                                            let dns_result = manage_dns_records(
                                                cf_client,
                                                dns_annotation,
                                                &tunnel_hostname,
                                                DnsOperation::Delete,
                                            )
                                            .await;

                                            if dns_result.has_failures() {
                                                let failed_hostnames: Vec<String> = dns_result
                                                    .failed_hostnames
                                                    .iter()
                                                    .map(|(hostname, error)| format!("{hostname}: {error}"))
                                                    .collect();
                                                let error_msg = format!(
                                                    "DNS record deletion failed: {}",
                                                    failed_hostnames.join(", ")
                                                );
                                                error!(
                                                    "Failed to delete some DNS records for tunnel {tunnel_id}: {error_msg}"
                                                );
                                                cleanup_errors.push(format!("DNS record deletion: {error_msg}"));
                                                cleanup_successful = false;

                                                // Post events for individual DNS deletion failures
                                                for (hostname, error) in &dns_result.failed_hostnames {
                                                    if let Err(e) = ctx
                                                        .events
                                                        .publish(
                                                            &service.object_ref(&()),
                                                            kube::runtime::events::EventType::Warning,
                                                            "DNSRecordDeletionFailed".into(),
                                                            Some(format!(
                                                                "Failed to delete DNS record for '{hostname}': {error}"
                                                            )),
                                                            "DNSCleanup".into(),
                                                        )
                                                        .await
                                                    {
                                                        log::warn!("Failed to publish DNS deletion failure event: {e}");
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

                                // Delete the tunnel itself
                                if let Err(e) = cf_client.delete_tunnel(&tunnel_id).await {
                                    error!("Failed to delete Cloudflare tunnel {tunnel_id}: {e}");
                                    cleanup_errors.push(format!("tunnel deletion: {e}"));
                                    cleanup_successful = false;
                                } else {
                                    info!("Successfully deleted Cloudflare tunnel {tunnel_id}");
                                }
                            }
                        }
                    }
                } else {
                    // No API access - can't clean up tunnel, this should prevent finalizer removal
                    cleanup_errors.push("no API access available for tunnel cleanup".to_string());
                    cleanup_successful = false;
                }

                // Only remove finalizer if cleanup was completely successful
                if cleanup_successful {
                    // Remove the finalizer to allow secret deletion
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
                            Error::CloudflareError(format!(
                                "Failed to remove finalizer from Secret '{secret_name}' for service '{svc_name}': {e}"
                            ))
                        })?;

                    info!("Removed finalizer from cloudflare secret `{secret_name}` for service `{svc_name}`");
                } else {
                    // Create an event about the failure to clean up
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
                    // Track critical cleanup failure for service-level error handling
                    critical_cleanup_errors
                        .extend(cleanup_errors.iter().map(|e| format!("secret '{secret_name}': {e}")));
                    continue; // Skip deletion attempt, secret will remain
                }
            }

            info!("Deleting cloudflare secret `{secret_name}` for service `{svc_name}` using label selector");
            secret_api.delete(secret_name, &Default::default()).await.map_err(|e| {
                Error::CloudflareError(format!(
                    "Failed to delete Secret '{secret_name}' for service '{svc_name}': {e}"
                ))
            })?;
        }

        // Clean up ConfigMaps
        let configmap_api: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), &svc_namespace);
        let configmaps = configmap_api
            .list(&kube::api::ListParams::default().labels(&label_selector))
            .await
            .map_err(|e| {
                Error::CloudflareError(format!(
                    "Failed to list ConfigMaps for service '{svc_name}' in namespace '{svc_namespace}': {e}"
                ))
            })?;

        for configmap in configmaps {
            let configmap_name = configmap.metadata.name.as_ref().unwrap();
            info!("Deleting cloudflare configmap `{configmap_name}` for service `{svc_name}` using label selector");
            configmap_api
                .delete(configmap_name, &Default::default())
                .await
                .map_err(|e| {
                    Error::CloudflareError(format!(
                        "Failed to delete ConfigMap '{configmap_name}' for service '{svc_name}': {e}"
                    ))
                })?;
        }

        // Clean up Deployments
        let deployment_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), &svc_namespace);
        let deployments = deployment_api
            .list(&kube::api::ListParams::default().labels(&label_selector))
            .await
            .map_err(|e| {
                Error::CloudflareError(format!(
                    "Failed to list Deployments for service '{svc_name}' in namespace '{svc_namespace}': {e}"
                ))
            })?;

        for deployment in deployments {
            let deployment_name = deployment.metadata.name.as_ref().unwrap();
            info!("Deleting cloudflare deployment `{deployment_name}` for service `{svc_name}` using label selector");
            deployment_api
                .delete(deployment_name, &Default::default())
                .await
                .map_err(|e| {
                    Error::CloudflareError(format!(
                        "Failed to delete Deployment '{deployment_name}' for service '{svc_name}': {e}"
                    ))
                })?;
        }

        // Return error if any critical cleanup operations failed
        if !critical_cleanup_errors.is_empty() {
            return Err(Error::CloudflareError(format!(
                "Critical cleanup operations failed for service '{}': {}",
                svc_name,
                critical_cleanup_errors.join(", ")
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod cloudflare_tests {
    use super::*;
    use k8s_openapi::api::core::v1::ServicePort;

    #[test]
    fn test_determine_port_protocol_with_netbird_format() {
        let port = ServicePort {
            name: Some("http".to_string()),
            port: 8080,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        };

        // Test NetBird format: "443/tls:8080" (should determine protocol based on service port characteristics)
        let result = determine_port_protocol(&port, Some("443/tls:8080"));
        assert_eq!(result, "http"); // Port name is "http"

        // Test NetBird format: "443/tls:http" (matching by port name)
        let result = determine_port_protocol(&port, Some("443/tls:http"));
        assert_eq!(result, "http"); // Port name is "http"

        // Test NetBird format without TLS: "80:8080"
        let result = determine_port_protocol(&port, Some("80:8080"));
        assert_eq!(result, "http"); // Port name is "http"

        // Test with well-known service port
        let https_port = ServicePort {
            name: Some("web".to_string()),
            port: 443,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        };
        let result = determine_port_protocol(&https_port, Some("8443/tls:443"));
        assert_eq!(result, "https"); // Service port 443 is well-known HTTPS
    }

    #[test]
    fn test_determine_port_protocol_well_known_ports() {
        // Test HTTPS port
        let https_port = ServicePort {
            port: 443,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        };
        let result = determine_port_protocol(&https_port, None);
        assert_eq!(result, "https");

        // Test SSH port
        let ssh_port = ServicePort {
            port: 22,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        };
        let result = determine_port_protocol(&ssh_port, None);
        assert_eq!(result, "ssh");

        // Test unknown port
        let unknown_port = ServicePort {
            port: 9999,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        };
        let result = determine_port_protocol(&unknown_port, None);
        assert_eq!(result, "tcp");
    }

    #[test]
    fn test_generate_cloudflared_config_with_map_ports() {
        let ports = vec![
            ServicePort {
                name: Some("web".to_string()),
                port: 8080,
                protocol: Some("TCP".to_string()),
                ..Default::default()
            },
            ServicePort {
                name: Some("admin".to_string()),
                port: 2222,
                protocol: Some("TCP".to_string()),
                ..Default::default()
            },
        ];

        let config = generate_cloudflared_config(
            "test-tunnel-id",
            "test-service",
            "default",
            &ports,
            Some("443/tls:8080, 22:2222"),
        );

        assert!(config.contains("tunnel: test-tunnel-id"));
        // With listen port support, protocols are determined from listen ports first
        // 443/tls:8080 -> 443 is well-known HTTPS port, so https protocol
        // 22:2222 -> 22 is well-known SSH port, so ssh protocol
        assert!(config.contains("service: https://test-service.default:8080"));
        assert!(config.contains("service: ssh://test-service.default:2222"));
    }

    #[test]
    fn test_generate_cloudflared_config_with_named_listen_ports() {
        let ports = vec![
            ServicePort {
                name: Some("web".to_string()),
                port: 8080,
                protocol: Some("TCP".to_string()),
                ..Default::default()
            },
            ServicePort {
                name: Some("api".to_string()),
                port: 3000,
                protocol: Some("TCP".to_string()),
                ..Default::default()
            },
        ];

        // Test that Cloudflare can handle named listen ports
        let config = generate_cloudflared_config(
            "test-tunnel-id",
            "test-service",
            "default",
            &ports,
            Some("https/tls:web, http:api"),
        );

        assert!(config.contains("tunnel: test-tunnel-id"));
        // Should generate service entries for both mappings based on named listen ports
        assert!(config.contains("service: https://test-service.default:8080")); // https/tls:web -> https protocol
        assert!(config.contains("service: http://test-service.default:3000")); // http:api -> http protocol
    }
}
