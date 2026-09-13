use crate::{
    Error, ReconcileContext, Result, TunnelProvider,
    crds::{CloudflareAnnounceType, CloudflareConfig},
    state::{Binding, DnsIntent},
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use k8s_openapi::{
    ByteString,
    api::{
        apps::v1::{Deployment, DeploymentSpec},
        core::v1::{
            Affinity, ConfigMap, Container, HTTPGetAction, LoadBalancerIngress, Pod, PodSpec, PodTemplateSpec, Probe,
            Secret, Service, ServicePort, Volume, VolumeMount,
        },
    },
    apimachinery::pkg::{
        apis::meta::v1::{LabelSelector, ObjectMeta},
        util::intstr::IntOrString,
    },
};
use kube::{
    Api, ResourceExt,
    api::{ListParams, LogParams},
};
use rand::Rng;
use reqwest::{
    Method,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

const CLOUDFLARE_API_URL: &str = "https://api.cloudflare.com/client/v4";
const DEFAULT_IMAGE: &str = "cloudflare/cloudflared:latest";

#[derive(Deserialize)]
struct ApiResponse<T> {
    success: bool,
    result: Option<T>,
    #[serde(default)]
    errors: Vec<ApiError>,
    result_info: Option<PageInfo>,
}
#[derive(Deserialize)]
struct ApiError {
    code: u32,
    message: String,
}
#[derive(Deserialize)]
struct PageInfo {
    total_pages: Option<u32>,
}
#[derive(Deserialize)]
struct Tunnel {
    id: String,
    name: String,
    config_src: Option<String>,
    deleted_at: Option<String>,
}
#[derive(Deserialize)]
struct Zone {
    id: String,
    name: String,
}
#[derive(Deserialize)]
struct DnsRecord {
    id: String,
    name: String,
    content: String,
    #[serde(rename = "type")]
    kind: String,
    comment: Option<String>,
    proxied: bool,
    ttl: u32,
}

struct CloudflareApi {
    client: reqwest::Client,
    base: String,
    account: String,
}

impl CloudflareApi {
    fn new(token: &str, account: &str) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut headers = HeaderMap::new();
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| Error::ConfigError("invalid Cloudflare API token header".into()))?;
        authorization.set_sensitive(true);
        headers.insert(AUTHORIZATION, authorization);
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(cf_error)?;
        Ok(Self {
            client,
            base: CLOUDFLARE_API_URL.into(),
            account: account.into(),
        })
    }

    fn from_binding(binding: &Binding) -> Result<Self> {
        let token = binding
            .data
            .credentials
            .get("api-token")
            .ok_or_else(|| Error::ConfigError("binding has no Cloudflare API token".into()))?;
        let account = binding
            .data
            .class
            .spec
            .cloudflare
            .as_ref()
            .and_then(|c| c.account_id.as_deref())
            .ok_or_else(|| Error::ConfigError("binding has no Cloudflare account".into()))?;
        Self::new(token, account)
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<Value>,
    ) -> Result<Option<ApiResponse<T>>> {
        let mut url = reqwest::Url::parse(&format!("{}{path}", self.base)).map_err(cf_error)?;
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(key, value)| (key, value)));
        }
        let mut request = self.client.request(method.clone(), url);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request.send().await.map_err(cf_error)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND && matches!(method, Method::GET | Method::DELETE) {
            return Ok(None);
        }
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(cf_error)? {
            if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err(Error::CloudflareError("API response exceeded 2 MiB".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        let envelope: ApiResponse<T> = serde_json::from_slice(&bytes)
            .map_err(|_| Error::CloudflareError(format!("invalid API response (HTTP {status})")))?;
        if !status.is_success() || !envelope.success {
            let message = envelope
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(Error::CloudflareError(format!("HTTP {status}: {message}")));
        }
        Ok(Some(envelope))
    }

    async fn list<T: DeserializeOwned>(&self, path: &str, query: &[(String, String)]) -> Result<Vec<T>> {
        let mut items = Vec::new();
        for page in 1..=1000 {
            let mut query = query.to_vec();
            query.extend([("page".into(), page.to_string()), ("per_page".into(), "50".into())]);
            let response = self
                .request::<Vec<T>>(Method::GET, path, &query, None)
                .await?
                .ok_or_else(|| Error::CloudflareError("list endpoint returned 404".into()))?;
            let result = response
                .result
                .ok_or_else(|| Error::CloudflareError("list response has no result".into()))?;
            let done = response
                .result_info
                .and_then(|r| r.total_pages)
                .map(|pages| page >= pages)
                .unwrap_or(result.len() < 50);
            items.extend(result);
            if done {
                return Ok(items);
            }
        }
        Err(Error::CloudflareError("API pagination exceeded its bound".into()))
    }

    async fn tunnels(&self, name: &str) -> Result<Vec<Tunnel>> {
        let tunnels: Vec<Tunnel> = self
            .list(
                &format!("/accounts/{}/cfd_tunnel", self.account),
                &[("name".into(), name.into()), ("is_deleted".into(), "false".into())],
            )
            .await?;
        Ok(tunnels.into_iter().filter(|t| t.name == name).collect())
    }

    async fn tunnel(&self, id: &str) -> Result<Option<Tunnel>> {
        Ok(self
            .request::<Tunnel>(
                Method::GET,
                &format!("/accounts/{}/cfd_tunnel/{id}", self.account),
                &[],
                None,
            )
            .await?
            .and_then(|r| r.result)
            .filter(|t| t.deleted_at.is_none()))
    }

    async fn records(&self, intent: &DnsIntent) -> Result<Vec<DnsRecord>> {
        let records: Vec<DnsRecord> = self
            .list(
                &format!("/zones/{}/dns_records", intent.zone_id),
                &[("name".into(), intent.hostname.clone())],
            )
            .await?;
        let mut records: Vec<_> = records
            .into_iter()
            .filter(|r| r.name.eq_ignore_ascii_case(&intent.hostname))
            .collect();
        if let Some(id) = &intent.record_id
            && !records.iter().any(|r| &r.id == id)
            && let Some(record) = self
                .request::<DnsRecord>(
                    Method::GET,
                    &format!("/zones/{}/dns_records/{id}", intent.zone_id),
                    &[],
                    None,
                )
                .await?
                .and_then(|r| r.result)
        {
            records.push(record);
        }
        Ok(records)
    }

    async fn delete_record(&self, zone: &str, id: &str) -> Result<()> {
        self.request::<Value>(Method::DELETE, &format!("/zones/{zone}/dns_records/{id}"), &[], None)
            .await?;
        Ok(())
    }
}

fn cf_error(error: impl std::fmt::Display) -> Error {
    Error::CloudflareError(error.to_string())
}

async fn ensure_tunnel(api: &CloudflareApi, ctx: &ReconcileContext, binding: &mut Binding) -> Result<String> {
    if binding.data.cloudflare.tunnel_name.is_none() {
        let prefix = binding
            .data
            .class
            .spec
            .cloudflare
            .as_ref()
            .and_then(|c| c.tunnel_prefix.as_deref())
            .unwrap_or("kube-");
        let name = format!("{prefix}{}", binding.uid()?);
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        binding.data.cloudflare.tunnel_name = Some(name);
        binding.data.cloudflare.tunnel_secret = Some(general_purpose::STANDARD.encode(bytes));
        binding.save(ctx.client.clone()).await?;
    }
    let name = binding
        .data
        .cloudflare
        .tunnel_name
        .as_deref()
        .ok_or_else(|| Error::ConfigError("tunnel intent has no name".into()))?;
    let secret = binding
        .data
        .cloudflare
        .tunnel_secret
        .as_deref()
        .ok_or_else(|| Error::ConfigError("tunnel intent has no credential".into()))?;
    if let Some(id) = &binding.data.cloudflare.tunnel_id {
        if let Some(tunnel) = api.tunnel(id).await? {
            if tunnel.config_src.as_deref() != Some("local") {
                return Err(cf_error("persisted tunnel requires local configuration"));
            }
            return Ok(tunnel.id);
        }
        binding.data.cloudflare.tunnel_id = None;
        binding.save(ctx.client.clone()).await?;
        return Box::pin(ensure_tunnel(api, ctx, binding)).await;
    }
    let mut matches = api.tunnels(name).await?;
    let tunnel = match matches.len() {
        0 => api
            .request::<Tunnel>(
                Method::POST,
                &format!("/accounts/{}/cfd_tunnel", api.account),
                &[],
                Some(json!({"name": name, "config_src": "local", "tunnel_secret": secret})),
            )
            .await?
            .and_then(|r| r.result)
            .ok_or_else(|| Error::CloudflareError("tunnel creation returned no identity".into()))?,
        1 => {
            let tunnel = matches.remove(0);
            if tunnel.config_src.as_deref() != Some("local")
                || binding
                    .data
                    .cloudflare
                    .tunnel_id
                    .as_ref()
                    .is_some_and(|id| id != &tunnel.id)
            {
                return Err(Error::CloudflareError(
                    "external tunnel identity conflicts with persisted intent".into(),
                ));
            }
            tunnel
        }
        _ => {
            return Err(Error::CloudflareError(
                "multiple tunnels match the persisted intent".into(),
            ));
        }
    };
    if binding.data.cloudflare.tunnel_id.as_ref() != Some(&tunnel.id) {
        binding.data.cloudflare.tunnel_id = Some(tunnel.id.clone());
        binding.save(ctx.client.clone()).await?;
    }
    Ok(tunnel.id)
}

fn owner_marker(binding: &Binding) -> Result<String> {
    Ok(format!("tlb binding {}", binding.uid()?))
}

async fn remove_dns(api: &CloudflareApi, intent: &DnsIntent, marker: &str) -> Result<()> {
    for record in api.records(intent).await? {
        if record.comment.as_deref() == Some(marker) {
            api.delete_record(&intent.zone_id, &record.id).await?;
        } else if intent.record_id.as_ref() == Some(&record.id) {
            return Err(Error::CloudflareError(format!(
                "DNS record {} no longer carries its ownership marker",
                record.id
            )));
        }
    }
    Ok(())
}

async fn reconcile_dns(
    api: &CloudflareApi,
    ctx: &ReconcileContext,
    binding: &mut Binding,
    desired: &BTreeSet<String>,
    target: &str,
) -> Result<()> {
    let marker = owner_marker(binding)?;
    for index in (0..binding.data.cloudflare.dns.len()).rev() {
        if !desired.contains(&binding.data.cloudflare.dns[index].hostname) {
            remove_dns(api, &binding.data.cloudflare.dns[index], &marker).await?;
            binding.data.cloudflare.dns.remove(index);
            binding.save(ctx.client.clone()).await?;
        }
    }
    let zones: Vec<Zone> = if desired
        .iter()
        .any(|name| !binding.data.cloudflare.dns.iter().any(|d| &d.hostname == name))
    {
        api.list("/zones", &[("account.id".into(), api.account.clone())])
            .await?
    } else {
        Vec::new()
    };
    for hostname in desired {
        let index = if let Some(index) = binding.data.cloudflare.dns.iter().position(|d| &d.hostname == hostname) {
            index
        } else {
            let zone = zones
                .iter()
                .filter(|zone| hostname == &zone.name || hostname.ends_with(&format!(".{}", zone.name)))
                .max_by_key(|zone| zone.name.len())
                .ok_or_else(|| Error::CloudflareError(format!("no accessible DNS zone for {hostname}")))?;
            binding.data.cloudflare.dns.push(DnsIntent {
                zone_id: zone.id.clone(),
                hostname: hostname.clone(),
                record_id: None,
            });
            binding.save(ctx.client.clone()).await?;
            binding.data.cloudflare.dns.len() - 1
        };
        let intent = &binding.data.cloudflare.dns[index];
        let records = api.records(intent).await?;
        if records.iter().any(|r| r.comment.as_deref() != Some(&marker)) {
            return Err(Error::CloudflareError(format!(
                "refusing to adopt existing DNS records for {hostname}"
            )));
        }
        if records.len() > 1 {
            return Err(Error::CloudflareError(format!(
                "multiple owned DNS records for {hostname}"
            )));
        }
        let payload =
            json!({"type": "CNAME", "name": hostname, "content": target, "ttl": 1, "proxied": true, "comment": marker});
        let record = match records.into_iter().next() {
            Some(record)
                if record.kind == "CNAME"
                    && record.content == target
                    && record.name.eq_ignore_ascii_case(hostname)
                    && record.proxied
                    && record.ttl == 1 =>
            {
                record
            }
            Some(record) => api
                .request::<DnsRecord>(
                    Method::PUT,
                    &format!("/zones/{}/dns_records/{}", intent.zone_id, record.id),
                    &[],
                    Some(payload),
                )
                .await?
                .and_then(|r| r.result)
                .ok_or_else(|| cf_error("DNS update returned no record"))?,
            None => api
                .request::<DnsRecord>(
                    Method::POST,
                    &format!("/zones/{}/dns_records", intent.zone_id),
                    &[],
                    Some(payload),
                )
                .await?
                .and_then(|r| r.result)
                .ok_or_else(|| cf_error("DNS creation returned no record"))?,
        };
        if binding.data.cloudflare.dns[index].record_id.as_ref() != Some(&record.id) {
            binding.data.cloudflare.dns[index].record_id = Some(record.id);
            binding.save(ctx.client.clone()).await?;
        }
    }
    Ok(())
}

fn quick_identity(pod: &Pod) -> Option<String> {
    if !pod
        .status
        .as_ref()?
        .conditions
        .as_ref()?
        .iter()
        .any(|c| c.type_ == "Ready" && c.status == "True")
    {
        return None;
    }
    quick_container_identity(pod)
}

fn quick_container_identity(pod: &Pod) -> Option<String> {
    if pod.metadata.deletion_timestamp.is_some() {
        return None;
    }
    let status = pod.status.as_ref()?;
    let container = status
        .container_statuses
        .as_ref()?
        .iter()
        .find(|c| c.name == "cloudflared")?;
    container.state.as_ref()?.running.as_ref()?;
    Some(format!(
        "{}:{}:{}",
        pod.uid()?,
        container.restart_count,
        container.container_id.as_deref()?
    ))
}

fn extract_url_from_log_line(line: &str) -> Option<String> {
    line.split_whitespace().find_map(|word| {
        let url = reqwest::Url::parse(word.trim_matches('|')).ok()?;
        let host = url.host_str()?;
        (url.scheme() == "https"
            && host.ends_with(".trycloudflare.com")
            && url.port().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none())
        .then(|| host.to_string())
    })
}

async fn quick_hostnames(ctx: &ReconcileContext, binding: &mut Binding) -> Result<Vec<String>> {
    let namespace = binding
        .data
        .service
        .namespace()
        .ok_or_else(|| Error::ConfigError("Service namespace missing".into()))?;
    let api: Api<Pod> = Api::namespaced(ctx.client.clone(), &namespace);
    let pods = api.list(&ListParams::default().labels(&ctx.selector()?)).await?;
    let mut current = BTreeMap::new();
    let mut announced = Vec::new();
    for pod in pods {
        let Some(identity) = quick_container_identity(&pod) else {
            continue;
        };
        let ready = quick_identity(&pod).is_some();
        if let Some(hostname) = binding.data.cloudflare.quick_urls.get(&identity) {
            current.insert(identity, hostname.clone());
            if ready {
                announced.push(hostname.clone());
            }
            continue;
        }
        let logs = api
            .logs(
                &pod.name_any(),
                &LogParams {
                    container: Some("cloudflared".into()),
                    tail_lines: Some(1000),
                    limit_bytes: Some(262144),
                    ..Default::default()
                },
            )
            .await;
        match logs {
            Ok(logs) => {
                if let Some(hostname) = logs.lines().find_map(extract_url_from_log_line) {
                    current.insert(identity, hostname.clone());
                    if ready {
                        announced.push(hostname);
                    }
                }
            }
            Err(err) => log::warn!("cannot discover quick tunnel for {namespace}/{}: {err}", pod.name_any()),
        }
    }
    if current != binding.data.cloudflare.quick_urls {
        binding.data.cloudflare.quick_urls = current;
        binding.save(ctx.client.clone()).await?;
    }
    Ok(announced)
}

#[async_trait]
impl TunnelProvider for CloudflareConfig {
    async fn reconcile_service(&self, ctx: &ReconcileContext, service: &Service) -> Result<()> {
        let options = crate::config::validate_service(service, &ctx.binding.data.class)?;
        let namespace = service
            .namespace()
            .ok_or_else(|| Error::ConfigError("Service namespace missing".into()))?;
        let origin = service_origin(service)?;
        let mut binding = ctx.binding.clone();
        let resource_name = ctx.resource_name(self.resource_prefix.as_deref().unwrap_or("cf-"), "")?;
        let mut volumes = Vec::new();
        let mut mounts = Vec::new();
        let mut rotation = BTreeMap::new();
        let mut hostnames = Vec::new();
        let mut dns_error = None;
        let mut args = vec![
            "tunnel".into(),
            "--no-autoupdate".into(),
            "--protocol".into(),
            self.transport_protocol.as_ref().into(),
            "--metrics".into(),
            "0.0.0.0:2000".into(),
        ];
        if self.api_token_ref.is_some() {
            let api = CloudflareApi::from_binding(&binding)?;
            let id = ensure_tunnel(&api, ctx, &mut binding).await?;
            let secret_name = ctx.resource_name("cf-", "-creds")?;
            let config_name = ctx.resource_name("cf-", "-config")?;
            let secret = Secret {
                metadata: ctx.metadata(&secret_name)?,
                data: Some(BTreeMap::from([(
                    "credentials.json".into(),
                    ByteString(serde_json::to_vec(&json!({
                        "AccountTag": self.account_id, "TunnelID": id, "TunnelSecret": binding.data.cloudflare.tunnel_secret
                    }))?),
                )])),
                ..Default::default()
            };
            let config = ConfigMap { metadata: ctx.metadata(&config_name)?, data: Some(BTreeMap::from([("config.yaml".into(), serde_yaml::to_string(&json!({
                "tunnel": id, "credentials-file": "/etc/cloudflared/creds/credentials.json", "ingress": [{ "service": origin }]
            })).map_err(cf_error)?)])), ..Default::default() };
            let secret =
                crate::managed::apply(ctx, &Api::<Secret>::namespaced(ctx.client.clone(), &namespace), &secret).await?;
            let config = crate::managed::apply(
                ctx,
                &Api::<ConfigMap>::namespaced(ctx.client.clone(), &namespace),
                &config,
            )
            .await?;
            rotation.insert(
                "controller.tlb.io/secret-version".into(),
                secret.resource_version().unwrap_or_default(),
            );
            rotation.insert(
                "controller.tlb.io/config-version".into(),
                config.resource_version().unwrap_or_default(),
            );
            volumes.push(Volume {
                name: "credentials".into(),
                secret: Some(k8s_openapi::api::core::v1::SecretVolumeSource {
                    secret_name: Some(secret_name),
                    ..Default::default()
                }),
                ..Default::default()
            });
            volumes.push(Volume {
                name: "config".into(),
                config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                    name: config_name,
                    ..Default::default()
                }),
                ..Default::default()
            });
            mounts.push(VolumeMount {
                name: "credentials".into(),
                mount_path: "/etc/cloudflared/creds".into(),
                read_only: Some(true),
                ..Default::default()
            });
            mounts.push(VolumeMount {
                name: "config".into(),
                mount_path: "/etc/cloudflared/config".into(),
                read_only: Some(true),
                ..Default::default()
            });
            args.extend([
                "--config".into(),
                "/etc/cloudflared/config/config.yaml".into(),
                "run".into(),
            ]);
            let target = format!("{id}.cfargotunnel.com");
            let desired: BTreeSet<String> = if matches!(self.announce_type, Some(CloudflareAnnounceType::Internal)) {
                BTreeSet::new()
            } else {
                options
                    .dns
                    .as_deref()
                    .unwrap_or_default()
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            };
            if let Err(error) = reconcile_dns(&api, ctx, &mut binding, &desired, &target).await {
                dns_error = Some(error);
            }
            hostnames = if desired.is_empty() || dns_error.is_some() {
                vec![target]
            } else {
                desired.into_iter().collect()
            };
        } else {
            args.extend(["--url".into(), origin]);
        }
        let labels = ctx.labels()?;
        let deployment = Deployment {
            metadata: ctx.metadata(&resource_name)?,
            spec: Some(DeploymentSpec {
                replicas: Some(options.replicas),
                selector: LabelSelector {
                    match_labels: Some(labels.clone()),
                    ..Default::default()
                },
                template: PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        labels: Some(labels),
                        annotations: Some(rotation),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        automount_service_account_token: Some(false),
                        affinity: crate::build_pod_affinity_for_service(service).map(|pod_affinity| Affinity {
                            pod_affinity: Some(pod_affinity),
                            ..Default::default()
                        }),
                        node_selector: options.node_selector.map(|s| {
                            s.split(',')
                                .filter_map(|s| s.trim().split_once('=').map(|(k, v)| (k.into(), v.into())))
                                .collect()
                        }),
                        containers: vec![Container {
                            name: "cloudflared".into(),
                            image: Some(self.image.clone().unwrap_or(DEFAULT_IMAGE.into())),
                            args: Some(args),
                            volume_mounts: Some(mounts),
                            readiness_probe: Some(Probe {
                                http_get: Some(HTTPGetAction {
                                    path: Some("/ready".into()),
                                    port: IntOrString::Int(2000),
                                    ..Default::default()
                                }),
                                period_seconds: Some(5),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }],
                        volumes: Some(volumes),
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        crate::managed::apply(
            ctx,
            &Api::<Deployment>::namespaced(ctx.client.clone(), &namespace),
            &deployment,
        )
        .await?;
        if self.api_token_ref.is_none() {
            hostnames = quick_hostnames(ctx, &mut binding).await?;
        }
        crate::managed::patch_ingress(
            ctx,
            service,
            hostnames
                .into_iter()
                .map(|hostname| LoadBalancerIngress {
                    hostname: Some(hostname),
                    ..Default::default()
                })
                .collect(),
        )
        .await?;
        if let Some(error) = dns_error {
            return Err(error);
        }
        Ok(())
    }

    async fn cleanup_service(&self, ctx: &ReconcileContext, _service: &Service) -> Result<()> {
        crate::managed::cleanup_workloads(ctx).await?;
        let mut binding = ctx.binding.clone();
        if self.api_token_ref.is_some() {
            let api = CloudflareApi::from_binding(&binding)?;
            let marker = owner_marker(&binding)?;
            while let Some(intent) = binding.data.cloudflare.dns.last() {
                remove_dns(&api, intent, &marker).await?;
                binding.data.cloudflare.dns.pop();
                binding.save(ctx.client.clone()).await?;
            }
            if let Some(name) = &binding.data.cloudflare.tunnel_name {
                let tunnels = if let Some(id) = &binding.data.cloudflare.tunnel_id {
                    api.tunnel(id).await?.into_iter().collect()
                } else {
                    api.tunnels(name).await?
                };
                if tunnels.len() > 1 {
                    return Err(cf_error("multiple tunnels match cleanup identity"));
                }
                for tunnel in tunnels {
                    if binding
                        .data
                        .cloudflare
                        .tunnel_id
                        .as_ref()
                        .is_some_and(|id| id != &tunnel.id)
                        || tunnel.config_src.as_deref() != Some("local")
                    {
                        return Err(cf_error("tunnel cleanup identity conflict"));
                    }
                    api.request::<Value>(
                        Method::DELETE,
                        &format!("/accounts/{}/cfd_tunnel/{}", api.account, tunnel.id),
                        &[],
                        None,
                    )
                    .await?;
                }
            }
        }
        crate::managed::cleanup_storage(ctx).await
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

/// Resolves the single origin shared by all hostnames on this tunnel.
pub(crate) fn service_origin(service: &Service) -> Result<String> {
    if service.annotations().contains_key("tlb.io/protocol") {
        return Err(Error::ConfigError(
            "use tlb.io/map-ports with protocol:service-port instead of tlb.io/protocol".into(),
        ));
    }
    let ports = service
        .spec
        .as_ref()
        .and_then(|s| s.ports.as_ref())
        .ok_or_else(|| Error::ConfigError("Service has no ports".into()))?;
    let (protocol, port) = if let Some(mapping) = service.annotations().get("tlb.io/map-ports") {
        if mapping.contains(',') {
            return Err(Error::ConfigError(
                "Cloudflare accepts one port mapping: multiple origins require hostname or path routing selectors"
                    .into(),
            ));
        }
        let (protocol, target) = mapping
            .trim()
            .split_once(':')
            .ok_or_else(|| Error::ConfigError("Cloudflare port mapping must be protocol:service-port".into()))?;
        let protocol = protocol.trim();
        let target = target.trim();
        let port = ports
            .iter()
            .find(|p| p.port.to_string() == target || p.name.as_deref() == Some(target))
            .ok_or_else(|| Error::ConfigError("port mapping must reference a Service port".into()))?;
        (protocol.to_string(), port)
    } else {
        if ports.len() != 1 {
            return Err(Error::ConfigError(
                "Cloudflare requires tlb.io/map-ports to select one origin from a multiport Service".into(),
            ));
        }
        (determine_port_protocol(&ports[0]), &ports[0])
    };
    if !matches!(protocol.as_str(), "http" | "https" | "tcp" | "ssh" | "rdp" | "smb") {
        return Err(Error::ConfigError("Cloudflare mapping protocol must be http, https, tcp, ssh, rdp, or smb; numeric listeners and TLS suffixes are not supported".into()));
    }
    if port.protocol.as_deref().unwrap_or("TCP") != "TCP" {
        return Err(Error::ConfigError(
            "Cloudflare origin must use a TCP Service port".into(),
        ));
    }
    let namespace = service
        .namespace()
        .ok_or_else(|| Error::ConfigError("Service namespace missing".into()))?;
    Ok(format!(
        "{protocol}://{}.{}.svc:{}",
        service.name_any(),
        namespace,
        port.port
    ))
}

/// Infers the origin protocol from the Service port name or number.
fn determine_port_protocol(port: &ServicePort) -> String {
    // Check port name for protocol hints
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

    // Check well-known ports
    for &(well_known_port, protocol) in WELL_KNOWN_PORTS {
        if port.port as u16 == well_known_port {
            return protocol.to_string();
        }
    }

    // Fallback to the transport protocol
    match port.protocol.as_deref().unwrap_or("TCP").to_uppercase().as_str() {
        "UDP" => "udp".to_string(),
        _ => "tcp".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{context, mock};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn server(responses: Vec<(&'static str, Value)>) -> (CloudflareApi, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut api = CloudflareApi::new("test-token", "account").unwrap();
        api.base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            for (expected, result) in responses {
                let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
                let mut bytes = Vec::new();
                loop {
                    let byte = tokio::time::timeout(Duration::from_secs(2), stream.read_u8())
                        .await
                        .unwrap()
                        .unwrap();
                    bytes.push(byte);
                    if bytes.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    assert!(bytes.len() < 16384);
                }
                let request = String::from_utf8(bytes).unwrap();
                assert!(request.lines().next().unwrap().starts_with(expected), "{request}");
                let body = json!({"success":true,"result":result,"result_info":{"total_pages":1}}).to_string();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        (api, task)
    }

    #[test]
    fn invalid_api_token_is_an_error_not_a_panic() {
        assert!(CloudflareApi::new("token\nInjected: bad", "account").is_err());
    }

    #[tokio::test]
    async fn renamed_tunnel_uses_the_persisted_id() {
        let (api, task) = server(vec![(
            "GET /accounts/account/cfd_tunnel/saved-id ",
            json!({"id":"saved-id", "name":"renamed", "config_src":"local"}),
        )])
        .await;
        let (client, _) = mock(vec![]);
        let ctx = context(client);
        let mut binding = ctx.binding.clone();
        binding.data.cloudflare.tunnel_name = Some("initial-name".into());
        binding.data.cloudflare.tunnel_secret = Some("secret".into());
        binding.data.cloudflare.tunnel_id = Some("saved-id".into());
        assert_eq!(ensure_tunnel(&api, &ctx, &mut binding).await.unwrap(), "saved-id");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn renamed_dns_record_is_deleted_by_id() {
        let (api, task) = server(vec![
            ("GET /zones/zone/dns_records?", json!([])),
            (
                "GET /zones/zone/dns_records/saved-id ",
                json!({"id":"saved-id", "name":"renamed.example.com",
                "content":"target", "type":"CNAME", "comment":"owner", "proxied":true, "ttl":1}),
            ),
            ("DELETE /zones/zone/dns_records/saved-id ", json!({"id":"saved-id"})),
        ])
        .await;
        remove_dns(
            &api,
            &DnsIntent {
                zone_id: "zone".into(),
                hostname: "original.example.com".into(),
                record_id: Some("saved-id".into()),
            },
            "owner",
        )
        .await
        .unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn zones_respect_the_api_page_limit() {
        let (api, task) = server(vec![("GET /zones?page=1&per_page=50 ", json!([]))]).await;
        assert!(api.list::<Zone>("/zones", &[]).await.unwrap().is_empty());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn failed_journal_save_recovers_created_tunnel_without_duplicate_creation() {
        use crate::test_support::Exchange;
        let response = json!([{ "id":"recovered", "name":"pending", "config_src":"local" }]);
        let (api, task) = server(vec![
            ("GET /accounts/account/cfd_tunnel?", response.clone()),
            ("GET /accounts/account/cfd_tunnel?", response),
        ])
        .await;
        let (client, requests) = mock(vec![
            Exchange {
                method: "PUT",
                path: "/api/v1/namespaces/tlb-system/secrets/tlb-service-uid",
                status: 500,
                response: json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"InternalError","message":"injected failure","code":500}),
                check: |_| {},
            },
            Exchange {
                method: "PUT",
                path: "/api/v1/namespaces/tlb-system/secrets/tlb-service-uid",
                status: 200,
                response: json!({"metadata":{"name":"tlb-service-uid","namespace":"tlb-system","uid":"binding-uid","resourceVersion":"2"}}),
                check: |body| {
                    assert!(body["data"]["binding.json"].is_string());
                },
            },
        ]);
        let ctx = context(client);
        let mut persisted = ctx.binding.clone();
        persisted.data.cloudflare.tunnel_name = Some("pending".into());
        persisted.data.cloudflare.tunnel_secret = Some("persisted-secret".into());
        let mut first_attempt = persisted.clone();
        assert!(ensure_tunnel(&api, &ctx, &mut first_attempt).await.is_err());
        assert_eq!(ensure_tunnel(&api, &ctx, &mut persisted).await.unwrap(), "recovered");
        assert!(requests.lock().unwrap().is_empty());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn dns_proxy_drift_is_repaired_by_record_id() {
        let (client, _) = mock(vec![]);
        let ctx = context(client);
        let mut binding = ctx.binding.clone();
        binding.data.cloudflare.dns.push(DnsIntent {
            zone_id: "zone".into(),
            hostname: "app.example.com".into(),
            record_id: Some("saved".into()),
        });
        let record = json!({"id":"saved","name":"app.example.com","content":"target","type":"CNAME", "comment":owner_marker(&binding).unwrap(),"proxied":false,"ttl":300});
        let (api, task) = server(vec![
            ("GET /zones/zone/dns_records?", json!([record.clone()])),
            ("PUT /zones/zone/dns_records/saved ", record),
        ])
        .await;
        reconcile_dns(&api, &ctx, &mut binding, &["app.example.com".into()].into(), "target")
            .await
            .unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn readiness_flap_retains_the_current_container_url_without_announcing_it() {
        use crate::test_support::Exchange;
        let pod = json!({"metadata":{"uid":"pod-uid","name":"pod"},"status":{
            "conditions":[{"type":"Ready","status":"False"}],
            "containerStatuses":[{"name":"cloudflared","image":"image","imageID":"id","ready":false,
                "restartCount":0,"containerID":"container-1","state":{"running":{}}}]
        }});
        let (client, requests) = mock(vec![Exchange {
            method: "GET",
            path: "/api/v1/namespaces/apps/pods",
            status: 200,
            response: json!({"items":[pod]}),
            check: |_| {},
        }]);
        let ctx = context(client);
        let mut binding = ctx.binding.clone();
        binding
            .data
            .cloudflare
            .quick_urls
            .insert("pod-uid:0:container-1".into(), "known.trycloudflare.com".into());
        assert!(quick_hostnames(&ctx, &mut binding).await.unwrap().is_empty());
        assert_eq!(binding.data.cloudflare.quick_urls.len(), 1);
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unready_connector_persists_hostname_before_logs_rotate() {
        use crate::test_support::Exchange;
        let mut pod = json!({"metadata":{"uid":"pod-uid","name":"pod"},"status":{
            "conditions":[{"type":"Ready","status":"False"}],
            "containerStatuses":[{"name":"cloudflared","image":"image","imageID":"id","ready":false,
                "restartCount":0,"containerID":"container-1","state":{"running":{}}}]
        }});
        let initial = json!({"items":[pod.clone()]});
        pod["status"]["conditions"][0]["status"] = json!("True");
        let (client, requests) = mock(vec![
            Exchange {
                method: "GET",
                path: "/api/v1/namespaces/apps/pods",
                status: 200,
                response: initial,
                check: |_| {},
            },
            Exchange {
                method: "GET",
                path: "/api/v1/namespaces/apps/pods/pod/log",
                status: 200,
                response: json!("INF | https://early.trycloudflare.com |"),
                check: |_| {},
            },
            Exchange {
                method: "PUT",
                path: "/api/v1/namespaces/tlb-system/secrets/tlb-service-uid",
                status: 200,
                response: json!({"metadata":{"name":"tlb-service-uid","namespace":"tlb-system","uid":"12345678-1234-1234-1234-123456789012","resourceVersion":"2"}}),
                check: |body| {
                    let bytes: ByteString = serde_json::from_value(body["data"]["binding.json"].clone()).unwrap();
                    let data: crate::state::BindingData = serde_json::from_slice(&bytes.0).unwrap();
                    assert_eq!(
                        data.cloudflare.quick_urls["pod-uid:0:container-1"],
                        "early.trycloudflare.com"
                    );
                },
            },
            // No log request is allowed after readiness: the original line is no longer available.
            Exchange {
                method: "GET",
                path: "/api/v1/namespaces/apps/pods",
                status: 200,
                response: json!({"items":[pod]}),
                check: |_| {},
            },
        ]);
        let ctx = context(client);
        let mut binding = ctx.binding.clone();
        assert!(quick_hostnames(&ctx, &mut binding).await.unwrap().is_empty());
        binding.data = serde_json::from_slice(&serde_json::to_vec(&binding.data).unwrap()).unwrap();
        assert_eq!(
            quick_hostnames(&ctx, &mut binding).await.unwrap(),
            vec!["early.trycloudflare.com"]
        );
        assert!(requests.lock().unwrap().is_empty());
    }

    #[test]
    fn quick_tunnel_identity_changes_on_container_restart_and_excludes_terminating_pods() {
        let mut pod: Pod = serde_json::from_value(json!({"metadata":{"uid":"pod-uid"}, "status":{
            "conditions":[{"type":"Ready", "status":"True"}],
            "containerStatuses":[{"name":"cloudflared", "image":"image", "imageID":"image-id", "ready":true,
                "restartCount":0,"containerID":"container-1","state":{"running":{}}}]
        }}))
        .unwrap();
        let first = quick_identity(&pod).unwrap();
        pod.status.as_mut().unwrap().container_statuses.as_mut().unwrap()[0].restart_count = 1;
        assert_ne!(quick_identity(&pod).unwrap(), first);
        pod.metadata.deletion_timestamp = Some(serde_json::from_value(json!("2026-09-13T00:00:00Z")).unwrap());
        assert!(quick_identity(&pod).is_none());
    }
}
