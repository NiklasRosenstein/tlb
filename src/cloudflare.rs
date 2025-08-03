use std::collections::BTreeMap;

use anyhow::Context;
use async_trait::async_trait;
use k8s_openapi::{
    ByteString,
    api::{
        apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy, RollingUpdateDeployment},
        core::v1::{Container, LoadBalancerIngress, PodSpec, PodTemplateSpec, Secret, Service, ServiceStatus},
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference},
};
use kube::{
    Client,
    api::{Api, Patch, PatchParams, PostParams, ResourceExt},
};
use log::{error, info};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    Error, ReconcileContext, Result, TunnelProvider,
    crds::{CloudflareConfig, SeretKeyRef},
};

use crate::{FOR_SERVICE_LABEL, MANAGED_BY_LABEL, PROVIDER_LABEL, TUNNEL_CLASS_LABEL};

const FINALIZER_NAME: &str = "tlb.io/cloudflare-tunnel";
const DEFAULT_CLOUDFLARED_IMAGE: &str = "cloudflare/cloudflared:latest";
const CLOUDFLARE_API_URL: &str = "https://api.cloudflare.com/client/v4";

#[derive(Deserialize, Debug)]
struct CloudflareApiResponse<T> {
    result: T,
    success: bool,
}

#[derive(Deserialize, Debug)]
struct Tunnel {
    id: String,
    #[serde(rename = "secret")]
    token: String,
}

struct CloudflareApi {
    client: reqwest::Client,
    account_id: String,
}

#[derive(Serialize)]
struct CreateTunnelPayload<'a> {
    name: &'a str,
    // The API expects a base64 encoded secret. The UI generates one, but if we provide an empty
    // one, the API will generate one for us.
    config: String,
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

    async fn create_tunnel(&self, name: &str) -> anyhow::Result<Tunnel> {
        let payload = CreateTunnelPayload {
            name,
            config: "{}".to_string(),
        };
        let res = self
            .client
            .post(format!("{}/accounts/{}/tunnels", CLOUDFLARE_API_URL, self.account_id))
            .json(&payload)
            .send()
            .await?
            .json::<CloudflareApiResponse<Tunnel>>()
            .await?;

        if !res.success {
            anyhow::bail!("Cloudflare API error");
        }
        Ok(res.result)
    }

    async fn delete_tunnel(&self, tunnel_id: &str) -> anyhow::Result<()> {
        let res = self
            .client
            .delete(format!(
                "{}/accounts/{}/tunnels/{}",
                CLOUDFLARE_API_URL, self.account_id, tunnel_id
            ))
            .send()
            .await?;

        if !res.status().is_success() && res.status() != 404 {
            anyhow::bail!("Cloudflare API error: {}", res.status());
        }
        Ok(())
    }
}

/// Fetches a secret from the Kubernetes API.
async fn get_secret(client: &Client, ns: &str, secret_ref: &SeretKeyRef) -> anyhow::Result<Secret> {
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), ns);
    secret_api
        .get(&secret_ref.name)
        .await
        .context(format!("Failed to get secret {} in namespace {}", secret_ref.name, ns))
}

#[async_trait]
impl TunnelProvider for CloudflareConfig {
    fn name(&self) -> &'static str {
        "cloudflare"
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
        let svc_namespace = service.namespace().unwrap();

        let api_token_secret = get_secret(
            &ctx.client,
            self.api_token_ref.namespace.as_ref().unwrap_or(&svc_namespace),
            &self.api_token_ref,
        )
        .await
        .map_err(|e| Error::ConfigError(e.to_string()))?;

        let api_token = String::from_utf8(
            api_token_secret
                .data
                .unwrap()
                .remove(&self.api_token_ref.key)
                .unwrap()
                .0,
        )
        .unwrap();

        let cf_client = CloudflareApi::new(&api_token, &self.account_id);

        let resource_prefix = self.resource_prefix.clone().unwrap_or("tunnel-".to_string());
    let secret_name = format!("{resource_prefix}{svc_name}");
        let secret_api: Api<Secret> = Api::namespaced(ctx.client.clone(), &svc_namespace);

        let existing_secret = secret_api.get_opt(&secret_name).await?;

        if let Some(secret) = existing_secret {
            if secret.metadata.deletion_timestamp.is_some() {
                info!(
                "Secret {secret_name} for service {svc_name} is being deleted, cleaning up Cloudflare tunnel"
                );

                if let Some(data) = secret.data {
                    if let Some(tunnel_id_bytes) = data.get("tunnel-id") {
                        let tunnel_id = String::from_utf8(tunnel_id_bytes.0.clone()).unwrap();

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

        let (tunnel_id, tunnel_token) = if let Some(secret) = secret_api.get_opt(&secret_name).await? {
            let data = secret.data.unwrap();
            let tunnel_id = String::from_utf8(data.get("tunnel-id").unwrap().0.clone()).unwrap();
            let tunnel_token = String::from_utf8(data.get("token").unwrap().0.clone()).unwrap();
            (tunnel_id, tunnel_token)
        } else {
            info!("No secret found for service {svc_name}, creating new Cloudflare tunnel");
            let tunnel_name = format!("kube-{svc_namespace}-{svc_name}");

            let tunnel = cf_client
                .create_tunnel(&tunnel_name)
                .await
                .map_err(|e| Error::CloudflareError(e.to_string()))?;

            let secret_data = BTreeMap::from([
                ("tunnel-id".to_string(), ByteString(tunnel.id.clone().into_bytes())),
                ("token".to_string(), ByteString(tunnel.token.clone().into_bytes())),
            ]);

            let secret = Secret {
                metadata: ObjectMeta {
                    name: Some(secret_name.clone()),
                    namespace: Some(svc_namespace.clone()),
                    finalizers: Some(vec![FINALIZER_NAME.to_string()]),
                    owner_references: Some(owner_references.clone()),
                    labels: Some(BTreeMap::from([
                        (MANAGED_BY_LABEL.to_string(), "tlb".to_string()),
                        (
                            TUNNEL_CLASS_LABEL.to_string(),
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

            (tunnel.id, tunnel.token)
        };

        let deployment_name = format!("{resource_prefix}{svc_name}");
        let deployment_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), &svc_namespace);

        let deployment = Deployment {
            metadata: ObjectMeta {
                name: Some(deployment_name.clone()),
                namespace: Some(svc_namespace.clone()),
                owner_references: Some(owner_references),
                labels: Some(BTreeMap::from([
                    (MANAGED_BY_LABEL.to_string(), "tlb".to_string()),
                    (
                        TUNNEL_CLASS_LABEL.to_string(),
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
                        labels: Some(BTreeMap::from([("app".to_string(), deployment_name.clone())])),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        containers: vec![Container {
                            name: "cloudflared".to_string(),
                            image: Some(self.image.clone().unwrap_or(DEFAULT_CLOUDFLARED_IMAGE.to_string())),
                            args: Some(vec![
                                "tunnel".to_string(),
                                "--no-autoupdate".to_string(),
                                "run".to_string(),
                                "--token".to_string(),
                                tunnel_token,
                            ]),
                            ..Default::default()
                        }],
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

        let hostname = format!("{tunnel_id}.cfargotunnel.com");
        let ingress = vec![LoadBalancerIngress {
            hostname: Some(hostname),
            ..Default::default()
        }];

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
        let svc_namespace = service.namespace().unwrap();

        let resource_prefix = self.resource_prefix.clone().unwrap_or("tunnel-".to_string());
        let secret_name = format!("{resource_prefix}{svc_name}");
        let deployment_name = format!("{resource_prefix}{svc_name}");

        let secret_api: Api<Secret> = Api::namespaced(ctx.client.clone(), &svc_namespace);
        if secret_api.get_opt(&secret_name).await?.is_some() {
            info!("Deleting cloudflare secret `{secret_name}` for service `{svc_name}`");
            secret_api.delete(&secret_name, &Default::default()).await?;
        }

        let deployment_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), &svc_namespace);
        if deployment_api.get_opt(&deployment_name).await?.is_some() {
            info!("Deleting cloudflare deployment `{deployment_name}` for service `{svc_name}`");
            deployment_api.delete(&deployment_name, &Default::default()).await?;
        }

        Ok(())
    }
}
