//! Custom-zone A records are reserved by Service UID in private binding journals.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use k8s_openapi::api::core::v1::{Secret, Service};
use kube::{
    Api, ResourceExt,
    api::{ListParams, Patch, PatchParams},
};
use reqwest::{
    Method, StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    Error, ReconcileContext, Result,
    crds::{NetbirdConfig, SeretKeyRef},
    netbird::PeerObservations,
    state::{Binding, JOURNAL_LABEL},
};

pub const HOSTNAMES: &str = "tlb.io/netbird-custom-dns-hostnames";
const CONDITION: &str = "tlb.io/CustomDNSReady";

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DnsState {
    #[serde(default)]
    pub targets: Vec<DnsTarget>,
    #[serde(default)]
    pub peers: BTreeMap<String, String>,
}

/// A target retains credentials until every reserved name has been cleaned up.
#[derive(Clone, Serialize, Deserialize)]
pub struct DnsTarget {
    pub api_url: String,
    pub zone_id: String,
    pub token_ref: SeretKeyRef,
    pub token: String,
    /// Map keys are durable reservations; IDs record the last observed A records.
    pub names: BTreeMap<String, Vec<String>>,
}

fn failure(reason: &'static str, message: impl Into<String>) -> Error {
    Error::NetbirdDnsError {
        reason,
        message: message.into(),
    }
}

pub fn api_root(management: &str, explicit: Option<&str>) -> Result<String> {
    let derived = format!("{}/api", management.trim_end_matches('/'));
    let mut url = reqwest::Url::parse(explicit.unwrap_or(&derived))
        .map_err(|_| failure("InvalidConfiguration", "invalid DNS API URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(failure(
            "InvalidConfiguration",
            "DNS API URL must be HTTP(S) without credentials, query, or fragment",
        ));
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn hostnames(service: &Service) -> Result<BTreeSet<String>> {
    let value = service.annotations().get(HOSTNAMES).map(String::as_str).unwrap_or("");
    if value.trim().is_empty() {
        return Ok(BTreeSet::new());
    }
    value
        .split(',')
        .map(|name| {
            let name = name
                .trim()
                .strip_suffix('.')
                .unwrap_or(name.trim())
                .to_ascii_lowercase();
            if !name.contains('.') || !crate::config::hostname(&name) {
                return Err(failure(
                    "InvalidConfiguration",
                    "custom DNS names must be explicit DNS hostnames without wildcards",
                ));
            }
            Ok(name)
        })
        .collect()
}

#[derive(Clone, Deserialize, Debug, PartialEq, Eq)]
struct Record {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    content: String,
    ttl: u32,
}
#[derive(Deserialize)]
struct Zone {
    domain: String,
    enabled: bool,
}

struct DnsApi {
    client: reqwest::Client,
    root: reqwest::Url,
    zone: String,
}
impl DnsApi {
    fn new(target: &DnsTarget) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut headers = HeaderMap::new();
        let mut token = HeaderValue::from_str(&format!("Token {}", target.token))
            .map_err(|_| failure("InvalidConfiguration", "invalid DNS API token"))?;
        token.set_sensitive(true);
        headers.insert(AUTHORIZATION, token);
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| failure("APIError", "cannot construct DNS API client"))?;
        Ok(Self {
            client,
            root: reqwest::Url::parse(&target.api_url)
                .map_err(|_| failure("InvalidConfiguration", "invalid persisted DNS API URL"))?,
            zone: target.zone_id.clone(),
        })
    }

    async fn request(&self, method: Method, record: Option<&str>, body: Option<Value>) -> Result<Option<Value>> {
        let mut url = self.root.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| failure("InvalidConfiguration", "invalid DNS API root"))?;
            path.pop_if_empty().push("dns").push("zones").push(&self.zone);
            if let Some(id) = record {
                path.push("records");
                if !id.is_empty() {
                    path.push(id);
                }
            }
        }
        let mut request = self.client.request(method.clone(), url);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| failure("APIError", "DNS API request failed or timed out"))?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND && matches!(method, Method::GET | Method::DELETE) {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(failure("APIError", format!("DNS API returned HTTP {status}")));
        }
        if method == Method::DELETE {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| failure("APIError", "DNS API response interrupted"))?
        {
            if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err(failure("APIError", "DNS API response exceeds 2 MiB"));
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| failure("APIError", "invalid DNS API response"))
    }

    async fn zone(&self) -> Result<Option<Zone>> {
        self.request(Method::GET, None, None)
            .await?
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| failure("APIError", "invalid DNS zone response"))
    }
    async fn records(&self) -> Result<Vec<Record>> {
        let value = self
            .request(Method::GET, Some(""), None)
            .await?
            .ok_or_else(|| failure("APIError", "DNS record list is unavailable"))?;
        serde_json::from_value(value).map_err(|_| failure("APIError", "invalid DNS record list"))
    }
    async fn delete(&self, id: &str) -> Result<()> {
        self.request(Method::DELETE, Some(id), None).await?;
        Ok(())
    }
    async fn put(&self, id: Option<&str>, name: &str, address: &str, ttl: u32) -> Result<Record> {
        let value = self
            .request(
                if id.is_some() { Method::PUT } else { Method::POST },
                Some(id.unwrap_or("")),
                Some(json!({"name": name, "type":"A", "content":address, "ttl":ttl})),
            )
            .await?
            .ok_or_else(|| failure("APIError", "DNS write returned no record"))?;
        let record: Record =
            serde_json::from_value(value).map_err(|_| failure("APIError", "invalid DNS record response"))?;
        if record.id.is_empty()
            || normalize(&record.name) != name
            || record.kind != "A"
            || record.content != address
            || record.ttl != ttl
        {
            return Err(failure("APIError", "DNS write returned an unexpected record"));
        }
        Ok(record)
    }
}

fn same_target(a: &DnsTarget, b: &DnsTarget) -> bool {
    a.api_url == b.api_url && a.zone_id == b.zone_id
}

fn check_reservations(
    binding: &Binding,
    target: &DnsTarget,
    names: &BTreeSet<String>,
    others: &[Binding],
) -> Result<()> {
    for other in others {
        if other.secret.uid() == binding.secret.uid() {
            continue;
        }
        for claimed in &other.data.netbird_dns.targets {
            if same_target(target, claimed) && names.iter().any(|name| claimed.names.contains_key(name)) {
                return Err(failure(
                    "Conflict",
                    format!(
                        "DNS hostname reserved by Service {}/{}",
                        other.data.service.namespace().unwrap_or_default(),
                        other.data.service.name_any()
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn update_peers(state: &mut DnsState, observations: &PeerObservations) -> BTreeSet<String> {
    state.peers.retain(|uid, _| observations.eligible.contains_key(uid));
    for (uid, address) in &observations.eligible {
        if let Some(address) = address {
            state.peers.insert(uid.clone(), address.clone());
        }
    }
    state.peers.values().cloned().collect()
}

async fn refresh_credentials(ctx: &ReconcileContext, binding: &mut Binding) -> Result<()> {
    for target in &mut binding.data.netbird_dns.targets {
        if let Ok(token) = crate::get_secret_value(
            &ctx.client,
            &target.token_ref,
            binding.data.service.namespace().as_deref().unwrap_or_default(),
        )
        .await
            && !token.is_empty()
            && HeaderValue::from_str(&format!("Token {token}")).is_ok()
        {
            target.token = token;
        }
    }
    binding.save(ctx.client.clone()).await
}

async fn reconcile_name(
    api: &DnsApi,
    records: &[Record],
    name: &str,
    addresses: &BTreeSet<String>,
    ttl: u32,
) -> Result<Vec<String>> {
    let existing: Vec<_> = records.iter().filter(|r| normalize(&r.name) == name).collect();
    if existing.iter().any(|r| r.kind != "A") {
        return Err(failure("Conflict", format!("non-A records exist at {name}")));
    }
    let mut retained = BTreeSet::new();
    for address in addresses {
        if let Some(record) = existing.iter().find(|r| &r.content == address) {
            if record.ttl != ttl {
                api.put(Some(&record.id), name, address, ttl).await?;
            }
            retained.insert(record.id.clone());
        } else {
            retained.insert(api.put(None, name, address, ttl).await?.id);
        }
    }
    for record in existing {
        if !retained.contains(&record.id) {
            api.delete(&record.id).await?;
        }
    }
    Ok(retained.into_iter().collect())
}

async fn cleanup_names(api: &DnsApi, names: &BTreeSet<String>) -> Result<()> {
    if names.is_empty() || api.zone().await?.is_none() {
        return Ok(());
    }
    for record in api.records().await? {
        if record.kind == "A" && names.contains(&normalize(&record.name)) {
            api.delete(&record.id).await?;
        }
    }
    if api.zone().await?.is_none() {
        return Ok(());
    }
    if api
        .records()
        .await?
        .iter()
        .any(|r| r.kind == "A" && names.contains(&normalize(&r.name)))
    {
        return Err(failure("CleanupPending", "reserved DNS records remain"));
    }
    Ok(())
}

async fn cleanup_targets(
    ctx: &ReconcileContext,
    binding: &mut Binding,
    desired: Option<(&DnsTarget, &BTreeSet<String>)>,
) -> Result<()> {
    for index in (0..binding.data.netbird_dns.targets.len()).rev() {
        let target = &binding.data.netbird_dns.targets[index];
        let stale: BTreeSet<_> = target
            .names
            .keys()
            .filter(|name| {
                !desired.is_some_and(|(current, names)| same_target(target, current) && names.contains(*name))
            })
            .cloned()
            .collect();
        if !stale.is_empty() {
            cleanup_names(&DnsApi::new(target)?, &stale).await?;
        }
        let target = &mut binding.data.netbird_dns.targets[index];
        target.names.retain(|name, _| !stale.contains(name));
        if target.names.is_empty() {
            binding.data.netbird_dns.targets.remove(index);
        }
        binding.save(ctx.client.clone()).await?;
    }
    Ok(())
}

async fn reconcile_inner(
    ctx: &ReconcileContext,
    config: &NetbirdConfig,
    service: &Service,
    observations: &PeerObservations,
) -> Result<Option<bool>> {
    let _guard = ctx.dns_lock.lock().await;
    let mut binding = ctx.binding.clone();
    let names = hostnames(service);
    let discovery = crate::netbird_ingress::IngressDiscovery::from_service(service);
    // Disabling DNS must finish historical cleanup even when declarations remain.
    if config.custom_dns.is_none()
        || (names.as_ref().is_ok_and(BTreeSet::is_empty) && discovery.as_ref().is_ok_and(Option::is_none))
    {
        if !binding.data.netbird_dns.targets.is_empty() {
            refresh_credentials(ctx, &mut binding).await?;
            cleanup_targets(ctx, &mut binding, None).await?;
            binding.data.netbird_dns.peers.clear();
            binding.save(ctx.client.clone()).await?;
        }
        if config.custom_dns.is_none() && (!names?.is_empty() || crate::netbird_ingress::configured(service)) {
            return Err(failure(
                "InvalidConfiguration",
                "custom DNS declarations require customDns on the NetBird class",
            ));
        }
        return Ok(None);
    }
    let mut names = names?;
    let discovery = discovery?;
    let dns = config.custom_dns.as_ref().expect("enabled DNS checked above");
    let token = crate::get_secret_value(
        &ctx.client,
        &dns.api_token_ref,
        service.namespace().as_deref().unwrap_or_default(),
    )
    .await
    .map_err(|_| failure("InvalidConfiguration", "cannot read DNS API credential Secret"))?;
    if token.is_empty() {
        return Err(failure("InvalidConfiguration", "DNS API token is empty"));
    }
    let target = DnsTarget {
        api_url: api_root(&config.management_url, dns.api_url.as_deref())?,
        zone_id: dns.zone_id.clone(),
        token_ref: dns.api_token_ref.clone(),
        token,
        names: BTreeMap::new(),
    };
    let api = DnsApi::new(&target)?;
    let zone = api
        .zone()
        .await?
        .ok_or_else(|| failure("InvalidConfiguration", "configured DNS zone does not exist"))?;
    let domain = normalize(&zone.domain);
    if !zone.enabled || !crate::config::hostname(&domain) {
        return Err(failure(
            "InvalidConfiguration",
            "DNS zone must be enabled with a valid domain",
        ));
    }
    if names
        .iter()
        .any(|n| n != &domain && !n.ends_with(&format!(".{domain}")))
    {
        return Err(failure(
            "InvalidConfiguration",
            "DNS hostname is outside the configured zone",
        ));
    }
    if let Some(discovery) = discovery {
        names.extend(discovery.hostnames(ctx.client.clone(), &domain).await?);
    }
    if names.is_empty() {
        refresh_credentials(ctx, &mut binding).await?;
        cleanup_targets(ctx, &mut binding, None).await?;
        binding.data.netbird_dns.peers.clear();
        binding.save(ctx.client.clone()).await?;
        return Ok(None);
    }
    let namespace = binding
        .secret
        .namespace()
        .ok_or_else(|| failure("InvalidConfiguration", "journal namespace missing"))?;
    let journals = Api::<Secret>::namespaced(ctx.client.clone(), &namespace)
        .list(&ListParams::default().labels(&format!("{JOURNAL_LABEL}=true")))
        .await?;
    let others = journals
        .into_iter()
        .map(Binding::from_secret)
        .collect::<Result<Vec<_>>>()?;
    check_reservations(&binding, &target, &names, &others)?;
    let index = match binding
        .data
        .netbird_dns
        .targets
        .iter()
        .position(|t| same_target(t, &target))
    {
        Some(index) => index,
        None => {
            binding.data.netbird_dns.targets.push(target.clone());
            binding.data.netbird_dns.targets.len() - 1
        }
    };
    let saved = &mut binding.data.netbird_dns.targets[index];
    saved.token_ref = target.token_ref.clone();
    saved.token = target.token.clone();
    for name in &names {
        saved.names.entry(name.clone()).or_default();
    }
    let addresses = update_peers(&mut binding.data.netbird_dns, observations);
    binding.save(ctx.client.clone()).await?;
    let records = api.records().await?;
    for name in &names {
        let ids = reconcile_name(&api, &records, name, &addresses, dns.ttl).await?;
        binding.data.netbird_dns.targets[index].names.insert(name.clone(), ids);
        binding.save(ctx.client.clone()).await?;
    }
    if observations.incomplete() {
        return Err(failure(
            "PeerDiscoveryFailed",
            "retaining last-known addresses for peers whose discovery failed",
        ));
    }
    refresh_credentials(ctx, &mut binding).await?;
    cleanup_targets(ctx, &mut binding, Some((&target, &names))).await?;
    Ok(Some(!addresses.is_empty()))
}

pub(crate) async fn reconcile(
    ctx: &ReconcileContext,
    config: &NetbirdConfig,
    service: &Service,
    observations: &PeerObservations,
) -> Result<()> {
    // Services without DNS need no extra API or status reads.
    if config.custom_dns.is_none()
        && !service.annotations().contains_key(HOSTNAMES)
        && !crate::netbird_ingress::configured(service)
        && ctx.binding.data.netbird_dns.targets.is_empty()
        && !service
            .status
            .as_ref()
            .and_then(|s| s.conditions.as_ref())
            .is_some_and(|cs| cs.iter().any(|c| c.type_ == CONDITION))
    {
        return Ok(());
    }
    let result = reconcile_inner(ctx, config, service, observations).await;
    let condition = match &result {
        Ok(None) => None,
        Ok(Some(true)) => Some((true, "Reconciled", "Custom DNS records are reconciled".to_string())),
        Ok(Some(false)) => Some((false, "NoReadyPeers", "No ready tunnel peer addresses".to_string())),
        Err(Error::NetbirdDnsError { reason, message }) => Some((false, *reason, message.clone())),
        Err(_) => Some((false, "APIError", "DNS reconciliation could not complete".to_string())),
    };
    set_condition(ctx, service, condition).await?;
    result.map(|_| ())
}

pub(crate) async fn cleanup(ctx: &ReconcileContext) -> Result<()> {
    if ctx.binding.data.netbird_dns.targets.is_empty() {
        if ctx
            .binding
            .data
            .class
            .spec
            .netbird
            .as_ref()
            .is_some_and(|c| c.custom_dns.is_some())
            || ctx.binding.data.service.annotations().contains_key(HOSTNAMES)
            || crate::netbird_ingress::configured(&ctx.binding.data.service)
        {
            set_condition(ctx, &ctx.binding.data.service, None).await?;
        }
        return Ok(());
    }
    let _guard = ctx.dns_lock.lock().await;
    let mut binding = ctx.binding.clone();
    refresh_credentials(ctx, &mut binding).await?;
    cleanup_targets(ctx, &mut binding, None).await?;
    set_condition(ctx, &binding.data.service, None).await
}

async fn set_condition(ctx: &ReconcileContext, service: &Service, state: Option<(bool, &str, String)>) -> Result<()> {
    let api = Api::<Service>::namespaced(ctx.client.clone(), service.namespace().as_deref().unwrap_or_default());
    let Some(current) = api.get_opt(&service.name_any()).await? else {
        return Ok(());
    };
    if current.uid() != service.uid() {
        return Ok(());
    }
    let existing =
        serde_json::to_value(current.status.as_ref().and_then(|s| s.conditions.as_ref())).unwrap_or(Value::Null);
    let mut conditions = existing.as_array().cloned().unwrap_or_default();
    let previous = conditions.iter().find(|c| c["type"] == CONDITION).cloned();
    conditions.retain(|c| c["type"] != CONDITION);
    if let Some((ready, reason, message)) = state {
        let status = if ready { "True" } else { "False" };
        let transition = previous
            .as_ref()
            .filter(|c| c["status"] == status)
            .map(|c| c["lastTransitionTime"].clone())
            .unwrap_or_else(|| json!(k8s_openapi::jiff::Timestamp::now().to_string()));
        conditions.push(
            json!({"type":CONDITION, "status":status, "reason":reason, "message":message,
            "observedGeneration":current.metadata.generation.unwrap_or(0), "lastTransitionTime":transition}),
        );
    }
    if existing.as_array().is_some_and(|old| old == &conditions) || (conditions.is_empty() && existing.is_null()) {
        return Ok(());
    }
    api.patch_status(
        &current.name_any(),
        &PatchParams::default(),
        &Patch::Merge(json!({
            "metadata":{"uid":current.uid(), "resourceVersion":current.resource_version()},
            "status":{"conditions":conditions}
        })),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
