//! Optimistic Lease leadership with cancellation before another holder may take over.
use crate::{Error, Result};
use k8s_openapi::{api::coordination::v1::Lease, apimachinery::pkg::apis::meta::v1::MicroTime};
use kube::{
    Api, ResourceExt,
    api::{ObjectMeta, PostParams},
};
use std::time::{Duration, Instant};

pub struct Leadership {
    api: Api<Lease>,
    identity: String,
    observed: Option<(String, Instant)>,
}

impl Leadership {
    pub fn new(client: kube::Client, namespace: &str) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
            identity: format!("tlb-{:032x}", rand::random::<u128>()),
            observed: None,
        }
    }

    pub async fn acquire_or_renew(&mut self) -> Result<bool> {
        tokio::time::timeout(Duration::from_secs(3), self.update())
            .await
            .map_err(|_| Error::UnexpectedError("Lease request timed out".into()))?
    }

    async fn update(&mut self) -> Result<bool> {
        let existing = self.api.get_opt("tlb-controller").await?;
        let mut lease = existing.clone().unwrap_or_else(|| Lease {
            metadata: ObjectMeta {
                name: Some("tlb-controller".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let spec = lease.spec.get_or_insert_default();
        if spec
            .holder_identity
            .as_deref()
            .is_some_and(|holder| holder != self.identity && !holder.is_empty())
        {
            let version = lease.metadata.resource_version.clone().unwrap_or_default();
            let observed = self.observed.get_or_insert_with(|| (version.clone(), Instant::now()));
            if observed.0 != version {
                *observed = (version, Instant::now());
            }
            // Observe a full unchanged lease interval locally; wall-clock skew cannot shorten it.
            let duration = spec
                .lease_duration_seconds
                .filter(|duration| *duration > 0)
                .ok_or_else(|| Error::ConfigError("existing Lease has no positive duration".into()))?;
            if observed.1.elapsed() < Duration::from_secs(duration as u64) {
                return Ok(false);
            }
        }
        let now = MicroTime(k8s_openapi::jiff::Timestamp::now());
        if spec.holder_identity.as_deref() != Some(&self.identity) {
            spec.acquire_time = Some(now.clone());
            spec.lease_transitions = Some(spec.lease_transitions.unwrap_or(0).saturating_add(1));
        }
        spec.holder_identity = Some(self.identity.clone());
        spec.lease_duration_seconds = Some(30);
        spec.renew_time = Some(now);
        let result = if existing.is_some() {
            self.api.replace("tlb-controller", &PostParams::default(), &lease).await
        } else {
            self.api.create(&PostParams::default(), &lease).await
        };
        match result {
            Ok(lease) => {
                self.observed = Some((lease.resource_version().unwrap_or_default(), Instant::now()));
                Ok(true)
            }
            Err(kube::Error::Api(error)) if error.code == 409 => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}
