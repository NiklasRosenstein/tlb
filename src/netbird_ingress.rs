//! Explicit IngressClass associations contribute hostnames to a tunnel Service's DNS set.
use std::collections::BTreeSet;

use k8s_openapi::api::{core::v1::Service, networking::v1::Ingress};
use kube::{Api, ResourceExt, api::ListParams};

use crate::{Error, Result};

pub const CLASS: &str = "tlb.io/netbird-custom-dns-ingress-class";
pub const NAMESPACES: &str = "tlb.io/netbird-custom-dns-ingress-namespaces";

pub fn configured(service: &Service) -> bool {
    service.annotations().contains_key(CLASS) || service.annotations().contains_key(NAMESPACES)
}

fn invalid(message: &str) -> Error {
    Error::NetbirdDnsError {
        reason: "InvalidConfiguration",
        message: message.into(),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct IngressDiscovery {
    class: String,
    /// None selects all namespaces; Some contains the explicit namespace allowlist.
    namespaces: Option<BTreeSet<String>>,
}

impl IngressDiscovery {
    pub fn from_service(service: &Service) -> Result<Option<Self>> {
        let Some(class) = service.annotations().get(CLASS) else {
            if service.annotations().contains_key(NAMESPACES) {
                return Err(invalid(
                    "Ingress namespace selection requires an IngressClass association",
                ));
            }
            return Ok(None);
        };
        let class = class.trim();
        if !crate::config::hostname(class) {
            return Err(invalid("custom DNS IngressClass must be a valid resource name"));
        }
        let namespaces = match service.annotations().get(NAMESPACES).map(|s| s.trim()) {
            Some("*") => None,
            Some(value) => {
                let names: BTreeSet<_> = value.split(',').map(|s| s.trim().to_owned()).collect();
                if names.iter().any(|s| !crate::config::dns_label(s)) {
                    return Err(invalid(
                        "Ingress namespaces must be a nonempty comma-separated list or '*'",
                    ));
                }
                Some(names)
            }
            None => Some(BTreeSet::from([service
                .namespace()
                .ok_or_else(|| invalid("Service namespace missing"))?])),
        };
        Ok(Some(Self {
            class: class.into(),
            namespaces,
        }))
    }

    pub fn includes_namespace(&self, namespace: &str) -> bool {
        self.namespaces.as_ref().is_none_or(|names| names.contains(namespace))
    }

    fn collect(&self, ingresses: &[Ingress], domain: &str) -> Result<BTreeSet<String>> {
        let mut names = BTreeSet::new();
        for ingress in ingresses {
            if ingress.metadata.deletion_timestamp.is_some()
                || !ingress.namespace().is_some_and(|ns| self.includes_namespace(&ns))
            {
                continue;
            }
            let Some(spec) = &ingress.spec else {
                continue;
            };
            // ingressClassName is an explicit reference; legacy controller-name annotations are not equivalent.
            if spec.ingress_class_name.as_deref() != Some(&self.class) {
                continue;
            }
            for host in spec.rules.iter().flatten().filter_map(|rule| rule.host.as_deref()) {
                if host.starts_with("*.") {
                    continue;
                }
                let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
                if !crate::config::hostname(&host) {
                    return Err(invalid("selected Ingress contains an invalid DNS rule hostname"));
                }
                if host == domain || host.ends_with(&format!(".{domain}")) {
                    names.insert(host);
                }
            }
        }
        Ok(names)
    }

    pub async fn hostnames(&self, client: kube::Client, domain: &str) -> Result<BTreeSet<String>> {
        let mut ingresses = Vec::new();
        match &self.namespaces {
            None => ingresses.extend(
                Api::<Ingress>::all(client)
                    .list(&ListParams::default())
                    .await
                    .map_err(|_| Error::NetbirdDnsError {
                        reason: "IngressDiscoveryFailed",
                        message: "Cannot list Ingresses; retaining DNS records".into(),
                    })?
                    .items,
            ),
            Some(namespaces) => {
                for namespace in namespaces {
                    ingresses.extend(
                        Api::<Ingress>::namespaced(client.clone(), namespace)
                            .list(&ListParams::default())
                            .await
                            .map_err(|_| Error::NetbirdDnsError {
                                reason: "IngressDiscoveryFailed",
                                message: format!("Cannot list Ingresses in {namespace}; retaining DNS records"),
                            })?
                            .items,
                    );
                }
            }
        }
        self.collect(&ingresses, domain)
    }
}

/// Class edits must also wake Services that selected the Ingress's previous class.
pub fn affected(service: &Service, ingress: &Ingress) -> bool {
    IngressDiscovery::from_service(service)
        .ok()
        .flatten()
        .is_some_and(|discovery| ingress.namespace().is_some_and(|ns| discovery.includes_namespace(&ns)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn service(scope: Option<&str>) -> Service {
        let mut service: Service = serde_json::from_value(json!({"metadata":{"namespace":"apps","annotations":{
            "tlb.io/netbird-custom-dns-ingress-class":"private"
        }}}))
        .unwrap();
        if let Some(scope) = scope {
            service
                .metadata
                .annotations
                .as_mut()
                .unwrap()
                .insert(NAMESPACES.into(), scope.into());
        }
        service
    }
    fn ingress(namespace: &str, class: Option<&str>, host: Option<&str>) -> Ingress {
        serde_json::from_value(json!({"metadata":{"namespace":namespace,"name":"route"},"spec":{
            "ingressClassName":class,"rules":[{"host":host}]
        }}))
        .unwrap()
    }

    #[test]
    fn namespace_selection_is_explicit_and_validated() {
        let discovery = IngressDiscovery::from_service(&service(None)).unwrap().unwrap();
        assert!(discovery.includes_namespace("apps"));
        assert!(!discovery.includes_namespace("other"));
        let discovery = IngressDiscovery::from_service(&service(Some(" apps,other,apps ")))
            .unwrap()
            .unwrap();
        assert!(discovery.includes_namespace("other"));
        assert!(!discovery.includes_namespace("third"));
        assert!(
            IngressDiscovery::from_service(&service(Some("*")))
                .unwrap()
                .unwrap()
                .includes_namespace("third")
        );
        for scope in ["", "apps,", "apps,*", "bad_namespace"] {
            assert!(IngressDiscovery::from_service(&service(Some(scope))).is_err());
        }
        let mut service = service(Some("*"));
        service.metadata.annotations.as_mut().unwrap().remove(CLASS);
        assert!(IngressDiscovery::from_service(&service).is_err());
        service
            .metadata
            .annotations
            .as_mut()
            .unwrap()
            .insert(CLASS.into(), "".into());
        assert!(IngressDiscovery::from_service(&service).is_err());
    }

    #[test]
    fn collects_only_concrete_rule_hosts_for_the_selected_class_namespace_and_zone() {
        let discovery = IngressDiscovery::from_service(&service(None)).unwrap().unwrap();
        let mut deleting = ingress("apps", Some("private"), Some("deleted.private.example.com"));
        deleting.metadata.deletion_timestamp = Some(serde_json::from_value(json!("2026-01-01T00:00:00Z")).unwrap());
        let mut tls_only = ingress("apps", Some("private"), None);
        tls_only.spec.as_mut().unwrap().tls =
            Some(serde_json::from_value(json!([{"hosts":["tls.private.example.com"]}])).unwrap());
        let mut legacy = ingress("apps", None, Some("legacy.private.example.com"));
        legacy.metadata.annotations = Some(Default::default());
        legacy
            .metadata
            .annotations
            .as_mut()
            .unwrap()
            .insert("kubernetes.io/ingress.class".into(), "private".into());
        let names = discovery
            .collect(
                &[
                    ingress("apps", Some("private"), Some("app.private.example.com")),
                    ingress("apps", Some("private"), Some("APP.PRIVATE.EXAMPLE.COM.")),
                    ingress("apps", Some("private"), Some("private.example.com")),
                    ingress("apps", Some("public"), Some("public.private.example.com")),
                    ingress("other", Some("private"), Some("other.private.example.com")),
                    ingress("apps", Some("private"), Some("outside.example.com")),
                    ingress("apps", Some("private"), Some("*.private.example.com")),
                    ingress("apps", None, Some("classless.private.example.com")),
                    deleting,
                    tls_only,
                    legacy,
                ],
                "private.example.com",
            )
            .unwrap();
        assert_eq!(
            names,
            BTreeSet::from(["app.private.example.com".into(), "private.example.com".into()])
        );
    }

    #[test]
    fn class_changes_and_deletions_wake_previous_subscribers() {
        let service = service(None);
        assert!(affected(&service, &ingress("apps", Some("public"), None)));
        assert!(affected(&service, &ingress("apps", None, None)));
        assert!(!affected(&service, &ingress("other", Some("private"), None)));
        assert!(!affected(&Service::default(), &ingress("apps", Some("private"), None)));
    }
}
