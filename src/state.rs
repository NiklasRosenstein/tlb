//! Private durable bindings between Services, classes, and provider resources.
use std::collections::BTreeMap;

use k8s_openapi::{
    ByteString,
    api::core::v1::{Secret, Service},
};
use kube::{
    Api, Client, ResourceExt,
    api::{ObjectMeta, PostParams},
};
use serde::{Deserialize, Serialize};

use crate::{Error, Result, crds::TunnelClassInnerSpec};

pub const BINDING_LABEL: &str = "controller.tlb.io/binding-uid";
pub const SERVICE_UID_LABEL: &str = "controller.tlb.io/service-uid";
pub const CLASS_UID_LABEL: &str = "controller.tlb.io/class-uid";
pub const JOURNAL_LABEL: &str = "controller.tlb.io/journal";
pub const JOURNAL_FINALIZER: &str = "tlb.io/binding-cleanup";

#[derive(Clone, Serialize, Deserialize)]
pub struct ClassSnapshot {
    pub metadata: ObjectMeta,
    pub namespaced: bool,
    pub spec: TunnelClassInnerSpec,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DnsIntent {
    pub zone_id: String,
    pub hostname: String,
    pub record_id: Option<String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CloudflareState {
    pub tunnel_name: Option<String>,
    pub tunnel_secret: Option<String>,
    pub tunnel_id: Option<String>,
    #[serde(default)]
    pub dns: Vec<DnsIntent>,
    #[serde(default)]
    pub quick_urls: BTreeMap<String, String>,
}

/// Credential values are private to the controller namespace and must never be logged.
#[derive(Clone, Serialize, Deserialize)]
pub struct BindingData {
    pub workload_namespace: String,
    pub workload_owner: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference>,
    pub service: Service,
    pub class: ClassSnapshot,
    pub credentials: BTreeMap<String, String>,
    #[serde(default)]
    pub cleaning: bool,
    #[serde(default)]
    pub cloudflare: CloudflareState,
    #[serde(default)]
    pub netbird_dns: crate::netbird_dns::DnsState,
}

#[derive(Clone)]
pub struct Binding {
    pub secret: Secret,
    pub data: BindingData,
}

impl Binding {
    pub fn name(service: &Service) -> Result<String> {
        Ok(format!("tlb-{}", required_uid(&service.metadata)?))
    }

    pub fn from_secret(secret: Secret) -> Result<Self> {
        if secret.labels().get(JOURNAL_LABEL).map(String::as_str) != Some("true") {
            return Err(Error::ConfigError(
                "journal name is occupied by an unrelated Secret".into(),
            ));
        }
        let bytes = secret
            .data
            .as_ref()
            .and_then(|data| data.get("binding.json"))
            .ok_or_else(|| Error::ConfigError("journal Secret is missing binding.json".into()))?;
        let data: BindingData = serde_json::from_slice(&bytes.0)?;
        if secret.name_any() != Self::name(&data.service)?
            || secret.labels().get(SERVICE_UID_LABEL) != data.service.metadata.uid.as_ref()
            || secret.labels().get(CLASS_UID_LABEL) != data.class.metadata.uid.as_ref()
        {
            return Err(Error::ConfigError(
                "journal identity does not match its persisted binding".into(),
            ));
        }
        Ok(Self { secret, data })
    }

    pub async fn create(client: Client, namespace: &str, data: BindingData) -> Result<Self> {
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(Self::name(&data.service)?),
                namespace: Some(namespace.into()),
                labels: Some(BTreeMap::from([
                    (JOURNAL_LABEL.into(), "true".into()),
                    (SERVICE_UID_LABEL.into(), required_uid(&data.service.metadata)?.into()),
                    (CLASS_UID_LABEL.into(), required_uid(&data.class.metadata)?.into()),
                ])),
                finalizers: Some(vec![JOURNAL_FINALIZER.into()]),
                ..Default::default()
            },
            data: Some(BTreeMap::from([(
                "binding.json".into(),
                ByteString(serde_json::to_vec(&data)?),
            )])),
            ..Default::default()
        };
        Self::from_secret(
            Api::<Secret>::namespaced(client, namespace)
                .create(&PostParams::default(), &secret)
                .await?,
        )
    }

    pub async fn save(&mut self, client: Client) -> Result<()> {
        let bytes = serde_json::to_vec(&self.data)?;
        if self
            .secret
            .data
            .as_ref()
            .and_then(|d| d.get("binding.json"))
            .is_some_and(|v| v.0 == bytes)
        {
            return Ok(());
        }
        let mut desired = self.secret.clone();
        desired.data = Some(BTreeMap::from([("binding.json".into(), ByteString(bytes))]));
        let api: Api<Secret> = Api::namespaced(
            client,
            self.secret
                .namespace()
                .as_deref()
                .ok_or_else(|| Error::ConfigError("journal namespace missing".into()))?,
        );
        self.secret = api
            .replace(&desired.name_any(), &PostParams::default(), &desired)
            .await?;
        Ok(())
    }

    pub fn uid(&self) -> Result<&str> {
        required_uid(&self.secret.metadata)
    }
}

pub fn required_uid(metadata: &ObjectMeta) -> Result<&str> {
    metadata
        .uid
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::ConfigError("Kubernetes object UID is required".into()))
}
