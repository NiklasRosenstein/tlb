//! Validation before credentials are read or provider resources are created.
use crate::{Error, PortMapping, Result, ServiceAnnotations, state::ClassSnapshot};
use k8s_openapi::api::core::v1::Service;
use kube::ResourceExt;
use std::{collections::BTreeSet, net::IpAddr};

fn invalid(message: impl Into<String>) -> Error {
    Error::ConfigError(message.into())
}

pub fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
}

pub fn hostname(value: &str) -> bool {
    value.len() <= 253 && value.split('.').all(dns_label)
}

pub fn validate_class(class: &ClassSnapshot) -> Result<()> {
    let references = match (&class.spec.netbird, &class.spec.cloudflare) {
        (Some(netbird), None) => {
            let url = reqwest::Url::parse(&netbird.management_url)
                .map_err(|_| invalid("managementUrl must be an HTTP(S) URL"))?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(invalid("managementUrl must be an HTTP(S) URL"));
            }
            for iface in [&netbird.netbird_interface, &netbird.cluster_interface]
                .into_iter()
                .flatten()
            {
                if iface.is_empty()
                    || iface.len() > 15
                    || !iface.bytes().all(|c| c.is_ascii_alphanumeric() || b"_-.:".contains(&c))
                {
                    return Err(invalid("invalid network interface name"));
                }
            }
            if let Some(prefix) = &netbird.resource_prefix {
                validate_prefix(prefix)?;
            }
            let mut references = vec![&netbird.setup_key_ref];
            if let Some(dns) = &netbird.custom_dns {
                crate::netbird_dns::api_root(&netbird.management_url, dns.api_url.as_deref())?;
                if dns.zone_id.trim().is_empty() || !(1..=i32::MAX as u32).contains(&dns.ttl) {
                    return Err(invalid("customDns requires zoneId and TTL between 1 and 2147483647"));
                }
                references.push(&dns.api_token_ref);
            }
            references
        }
        (None, Some(cloudflare)) => {
            if cloudflare.account_id.is_some() != cloudflare.api_token_ref.is_some() {
                return Err(invalid("Cloudflare accountId and apiTokenRef must be set together"));
            }
            if let Some(account) = &cloudflare.account_id
                && (account.len() != 32 || !account.bytes().all(|c| c.is_ascii_hexdigit()))
            {
                return Err(invalid("Cloudflare accountId must be 32 hexadecimal characters"));
            }
            if let Some(prefix) = &cloudflare.resource_prefix {
                validate_prefix(prefix)?;
            }
            if let Some(prefix) = &cloudflare.tunnel_prefix {
                validate_prefix(prefix)?;
            }
            cloudflare.api_token_ref.iter().collect()
        }
        _ => return Err(invalid("exactly one provider must be configured")),
    };
    for reference in references {
        if !hostname(&reference.name) || reference.key.is_empty() {
            return Err(invalid("Secret reference requires a valid name and nonempty key"));
        }
        if let Some(namespace) = &reference.namespace {
            if !dns_label(namespace) {
                return Err(invalid("invalid Secret namespace"));
            }
            if class.namespaced && Some(namespace) != class.metadata.namespace.as_ref() {
                return Err(invalid(
                    "namespaced TunnelClass cannot reference a Secret in another namespace",
                ));
            }
        }
    }
    if class.namespaced && class.metadata.namespace.is_none() {
        return Err(invalid("namespaced class requires a namespace"));
    }
    Ok(())
}

fn validate_prefix(prefix: &str) -> Result<()> {
    if prefix.len() > 40
        || !prefix
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        || prefix.starts_with('-')
    {
        return Err(invalid(
            "resource prefix must contain lowercase letters, digits and hyphens, with no leading hyphen",
        ));
    }
    Ok(())
}

pub fn validate_service(service: &Service, class: &ClassSnapshot) -> Result<ServiceAnnotations> {
    validate_class(class)?;
    if class.namespaced && service.namespace() != class.metadata.namespace {
        return Err(invalid("Service and TunnelClass namespaces must match"));
    }
    let spec = service
        .spec
        .as_ref()
        .ok_or_else(|| invalid("Service spec is required"))?;
    if spec.type_.as_deref() != Some("LoadBalancer") {
        return Err(invalid("Service must have type LoadBalancer"));
    }
    spec.cluster_ip
        .as_deref()
        .and_then(|ip| ip.parse::<IpAddr>().ok())
        .ok_or_else(|| invalid("Service requires an allocated ClusterIP"))?;
    let ports = spec.ports.as_deref().unwrap_or_default();
    if ports.is_empty() {
        return Err(invalid("Service requires at least one port"));
    }
    let annotations = service.annotations();
    let options = ServiceAnnotations::from(annotations.clone());
    if let Some(replicas) = annotations.get("tlb.io/replicas")
        && replicas.parse::<i32>().ok().filter(|n| *n >= 0).is_none()
    {
        return Err(invalid("tlb.io/replicas must be a nonnegative integer"));
    }
    if let Some(dns) = &options.dns
        && dns.split(',').map(str::trim).any(|name| !hostname(name))
    {
        return Err(invalid("tlb.io/dns must contain DNS hostnames"));
    }
    if let Some(selector) = &options.node_selector {
        for entry in selector.split(',') {
            let (key, value) = entry
                .trim()
                .split_once('=')
                .ok_or_else(|| invalid("node selector must contain key=value entries"))?;
            if !label_key(key) || !label_value(value) {
                return Err(invalid("invalid node selector label"));
            }
        }
    }
    if let Some(key) = &options.topology_key
        && !label_key(key)
    {
        return Err(invalid("invalid topology key"));
    }
    if class.spec.cloudflare.is_some() {
        if annotations.contains_key(crate::netbird_dns::HOSTNAMES) || crate::netbird_ingress::configured(service) {
            return Err(invalid("custom DNS hostname declarations require a NetBird class"));
        }
        crate::cloudflare::service_origin(service)?;
    } else {
        if ports
            .iter()
            .any(|p| !matches!(p.protocol.as_deref().unwrap_or("TCP"), "TCP" | "UDP"))
        {
            return Err(invalid("NetBird supports TCP and UDP ports"));
        }
        let mappings = options
            .map_ports
            .as_deref()
            .map(PortMapping::parse_multiple)
            .transpose()
            .map_err(invalid)?;
        if let Some(mappings) = mappings {
            if mappings.is_empty() {
                return Err(invalid("port mappings cannot be empty"));
            }
            let mut listeners = BTreeSet::new();
            for mapping in mappings {
                let port = ports
                    .iter()
                    .find(|p| {
                        p.port.to_string() == mapping.service_port || p.name.as_ref() == Some(&mapping.service_port)
                    })
                    .ok_or_else(|| invalid("port mapping must reference a Service port"))?;
                if mapping.listen_port == 0
                    || mapping.listen_port == crate::netbird::NETBIRD_PEER_IP_PORT
                    || !listeners.insert(mapping.listen_port)
                {
                    return Err(invalid(
                        "listen ports must be unique, nonzero, and must not use the peer-IP port",
                    ));
                }
                if (mapping.listen_tls || mapping.service_tls) && port.protocol.as_deref().unwrap_or("TCP") != "TCP" {
                    return Err(invalid("TLS requires a TCP port"));
                }
                if mapping.listen_tls && options.tls_secret_name.is_none() {
                    return Err(invalid("TLS termination requires tlb.io/tls-secret-name"));
                }
            }
        } else if ports
            .iter()
            .any(|p| p.port == i32::from(crate::netbird::NETBIRD_PEER_IP_PORT))
        {
            return Err(invalid("Service port conflicts with the peer-IP port"));
        }
    }
    Ok(options)
}

fn label_key(value: &str) -> bool {
    match value.split_once('/') {
        Some((prefix, name)) => hostname(prefix) && !name.is_empty() && label_value(name),
        None => !value.is_empty() && label_value(value),
    }
}
fn label_value(value: &str) -> bool {
    value.len() <= 63
        && (value.is_empty()
            || (value.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
                && value.as_bytes()[0].is_ascii_alphanumeric()
                && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()))
}

/// TLS termination requires both mounted PEM files; forwarder supervision handles invalid PEM contents.
pub fn validate_tls_secret(secret: &k8s_openapi::api::core::v1::Secret) -> Result<()> {
    if ["tls.crt", "tls.key"].iter().any(|key| {
        secret
            .data
            .as_ref()
            .and_then(|d| d.get(*key))
            .is_none_or(|v| v.0.is_empty())
    }) {
        return Err(invalid("TLS Secret requires nonempty tls.crt and tls.key"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{context, mock};
    use serde_json::json;

    #[test]
    fn malformed_tls_secret_is_rejected() {
        let mut secret = k8s_openapi::api::core::v1::Secret::default();
        assert!(validate_tls_secret(&secret).is_err());
        secret.data = Some([("tls.crt".into(), k8s_openapi::ByteString(vec![1]))].into());
        assert!(validate_tls_secret(&secret).is_err());
        secret
            .data
            .as_mut()
            .unwrap()
            .insert("tls.key".into(), k8s_openapi::ByteString(vec![]));
        assert!(validate_tls_secret(&secret).is_err());
    }

    #[tokio::test]
    async fn class_reference_namespace_is_a_trust_boundary() {
        let (client, _) = mock(vec![]);
        let mut ctx = context(client);
        ctx.binding.data.class.spec = serde_json::from_value(json!({"netbird":{
            "managementUrl":"https://netbird.example.com", "setupKeyRef":{"name":"key", "key":"token", "namespace":"foreign"}
        }})).unwrap();
        assert!(validate_class(&ctx.binding.data.class).is_err());
        ctx.binding.data.class.namespaced = false;
        assert!(validate_class(&ctx.binding.data.class).is_ok());
        ctx.binding.data.class.namespaced = true;
        ctx.binding
            .data
            .class
            .spec
            .netbird
            .as_mut()
            .unwrap()
            .setup_key_ref
            .namespace = Some("apps".into());
        assert!(validate_service(&ctx.binding.data.service, &ctx.binding.data.class).is_ok());
        ctx.binding.data.service.metadata.namespace = Some("foreign".into());
        assert!(validate_service(&ctx.binding.data.service, &ctx.binding.data.class).is_err());
    }

    #[tokio::test]
    async fn cloudflare_mappings_select_protocol_and_service_port() {
        let (client, _) = mock(vec![]);
        let ctx = context(client);
        let mut service = ctx.binding.data.service.clone();
        service.spec.as_mut().unwrap().ports = Some(
            serde_json::from_value(json!([
                {"name":"web", "port":8080, "targetPort":3000},
                {"name":"admin", "port":2222},
                {"name":"dns", "port":53, "protocol":"UDP"}
            ]))
            .unwrap(),
        );
        for protocol in ["http", "https", "tcp", "ssh", "rdp", "smb"] {
            for target in ["web", "8080"] {
                service.metadata.annotations =
                    Some([("tlb.io/map-ports".into(), format!(" {protocol} : {target} "))].into());
                assert!(validate_service(&service, &ctx.binding.data.class).is_ok());
                assert_eq!(
                    crate::cloudflare::service_origin(&service).unwrap(),
                    format!("{protocol}://api.apps.svc:8080")
                );
            }
        }
        service.metadata.annotations = Some([("tlb.io/map-ports".into(), "ssh:admin".into())].into());
        assert_eq!(
            crate::cloudflare::service_origin(&service).unwrap(),
            "ssh://api.apps.svc:2222"
        );
        for mapping in [
            "",
            "https",
            "443:8080",
            "invalid:8080",
            "https:missing",
            "https:3000",
            "https:8080,ssh:2222",
            "https:8080,",
            "https/tls:8080",
            "https:8080/tls",
            "tcp:dns",
            "https::8080",
        ] {
            service.metadata.annotations = Some([("tlb.io/map-ports".into(), mapping.into())].into());
            assert!(
                validate_service(&service, &ctx.binding.data.class).is_err(),
                "{mapping}"
            );
        }
        service.metadata.annotations = None;
        assert!(validate_service(&service, &ctx.binding.data.class).is_err());
        service.spec.as_mut().unwrap().ports.as_mut().unwrap().truncate(1);
        assert_eq!(
            crate::cloudflare::service_origin(&service).unwrap(),
            "http://api.apps.svc:8080"
        );
        service.metadata.annotations = Some(
            [
                ("tlb.io/protocol".into(), "https".into()),
                ("tlb.io/map-ports".into(), "http:web".into()),
            ]
            .into(),
        );
        assert!(validate_service(&service, &ctx.binding.data.class).is_err());
    }

    #[tokio::test]
    async fn netbird_mappings_require_numeric_listeners_and_keep_tls_validation() {
        let (client, _) = mock(vec![]);
        let mut ctx = context(client);
        ctx.binding.data.class.spec = serde_json::from_value(json!({"netbird":{
            "managementUrl":"https://netbird.example.com", "setupKeyRef":{"name":"key", "key":"token"}
        }}))
        .unwrap();
        let mut service = ctx.binding.data.service.clone();
        for mapping in ["8080:80", "443/tls:80/tls", "8080:80,8443/tls:80/tls-no-verify"] {
            service.metadata.annotations = Some(
                [
                    ("tlb.io/map-ports".into(), mapping.into()),
                    ("tlb.io/tls-secret-name".into(), "tls".into()),
                ]
                .into(),
            );
            assert!(validate_service(&service, &ctx.binding.data.class).is_ok(), "{mapping}");
        }
        for mapping in ["http:80", "https:80", "0:80", "15411:80", "80:80,80:80", "443/tls:80"] {
            service.metadata.annotations = Some([("tlb.io/map-ports".into(), mapping.into())].into());
            assert!(
                validate_service(&service, &ctx.binding.data.class).is_err(),
                "{mapping}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_service_options_fail_before_api_access() {
        let (client, _) = mock(vec![]);
        let ctx = context(client);
        for (key, value) in [
            ("tlb.io/replicas", "-1"),
            ("tlb.io/replicas", "invalid"),
            ("tlb.io/dns", "bad/name"),
            ("tlb.io/node-selector", "broken"),
            ("tlb.io/protocol", "invalid"),
        ] {
            let mut service = ctx.binding.data.service.clone();
            service.metadata.annotations = Some([(key.into(), value.into())].into());
            assert!(validate_service(&service, &ctx.binding.data.class).is_err(), "{key}");
        }
        let mut service = ctx.binding.data.service.clone();
        service
            .spec
            .as_mut()
            .unwrap()
            .ports
            .as_mut()
            .unwrap()
            .push(Default::default());
        assert!(validate_service(&service, &ctx.binding.data.class).is_err());
    }
}

/// Operator policy for all class-selected workloads.
#[derive(Clone, Debug)]
pub struct WorkloadPolicy {
    pub namespace: String,
    pub allow_unsafe_overrides: bool,
}

impl WorkloadPolicy {
    pub fn new(controller_namespace: &str, namespace: Option<String>, allow_unsafe_overrides: bool) -> Result<Self> {
        if !dns_label(controller_namespace) {
            return Err(invalid("invalid controller namespace"));
        }
        if allow_unsafe_overrides
            && namespace
                .as_deref()
                .is_none_or(|ns| ns == controller_namespace || ns == "kube-system")
        {
            return Err(invalid(
                "unsafe workload overrides require an explicit workload namespace different from the controller namespace and kube-system",
            ));
        }
        let namespace = namespace.unwrap_or_else(|| controller_namespace.into());
        if !dns_label(&namespace) {
            return Err(invalid("invalid workload namespace"));
        }
        Ok(Self {
            namespace,
            allow_unsafe_overrides,
        })
    }

    pub fn validate(&self, class: &ClassSnapshot) -> Result<()> {
        let unsafe_override = class.spec.cloudflare.as_ref().is_some_and(|c| c.image.is_some())
            || class.spec.netbird.as_ref().is_some_and(|c| {
                c.image.is_some() || c.up_command.is_some() || c.enable_ebpf_capabilities == Some(true)
            });
        if unsafe_override && !self.allow_unsafe_overrides {
            return Err(invalid(
                "custom images, commands and eBPF capabilities require TLB_ALLOW_UNSAFE_WORKLOAD_OVERRIDES=true and a dedicated workload namespace",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unsafe_policy_requires_explicit_separate_namespace() {
        assert_eq!(
            WorkloadPolicy::new("kube-system", None, false).unwrap().namespace,
            "kube-system"
        );
        for namespace in [None, Some("kube-system".into()), Some("controller".into())] {
            assert!(WorkloadPolicy::new("controller", namespace, true).is_err());
        }
        assert!(WorkloadPolicy::new("kube-system", Some("tunnels".into()), true).is_ok());
        assert!(WorkloadPolicy::new("kube-system", Some("".into()), false).is_err());
    }

    #[test]
    fn both_class_kinds_require_opt_in_for_each_unsafe_field() {
        let restricted = WorkloadPolicy::new("kube-system", None, false).unwrap();
        let permitted = WorkloadPolicy::new("kube-system", Some("tunnels".into()), true).unwrap();
        for namespaced in [true, false] {
            for spec in [
                json!({"cloudflare":{"image":"cloudflare/cloudflared:latest"}}),
                json!({"netbird":{"managementUrl":"https://netbird.example.com","setupKeyRef":{"name":"key","key":"key"},"image":"netbirdio/netbird:latest"}}),
                json!({"netbird":{"managementUrl":"https://netbird.example.com","setupKeyRef":{"name":"key","key":"key"},"upCommand":"netbird up"}}),
                json!({"netbird":{"managementUrl":"https://netbird.example.com","setupKeyRef":{"name":"key","key":"key"},"enableEbpfCapabilities":true}}),
            ] {
                let class: ClassSnapshot = serde_json::from_value(json!({"metadata":{"name":"test","namespace":"apps","uid":"class"},"namespaced":namespaced,"spec":spec})).unwrap();
                assert!(restricted.validate(&class).is_err());
                assert!(permitted.validate(&class).is_ok());
            }
        }
    }
}
