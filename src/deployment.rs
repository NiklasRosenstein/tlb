use std::collections::BTreeMap;

use k8s_openapi::api::{
    apps::v1::{Deployment, DeploymentStrategy},
    core::v1::Affinity,
};
use kube::{
    api::{Api, Patch, PatchParams},
    Client,
};
use log::info;

use crate::{Result, ServiceAnnotations};

pub fn get_node_selector(options: &ServiceAnnotations) -> BTreeMap<String, String> {
    if let Some(node_selector_str) = &options.node_selector {
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
    }
}

pub fn get_affinity(
    options: &ServiceAnnotations,
    match_labels: BTreeMap<String, String>,
) -> Affinity {
    Affinity {
        pod_anti_affinity: Some(k8s_openapi::api::core::v1::PodAntiAffinity {
            required_during_scheduling_ignored_during_execution: Some(vec![
                k8s_openapi::api::core::v1::PodAffinityTerm {
                    label_selector: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
                        match_labels: Some(match_labels),
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
    }
}

pub fn get_deployment_strategy(options: &ServiceAnnotations) -> DeploymentStrategy {
    if options.replicas == 1 {
        DeploymentStrategy {
            type_: Some("Recreate".into()),
            rolling_update: None,
        }
    } else {
        DeploymentStrategy {
            type_: Some("RollingUpdate".into()),
            rolling_update: None,
        }
    }
}

pub async fn create_or_patch_deployment(
    client: &Client,
    namespace: &str,
    deployment: &Deployment,
) -> Result<()> {
    let deployment_api = Api::<Deployment>::namespaced(client.clone(), namespace);
    let deployment_name = deployment.metadata.name.as_ref().unwrap();

    match deployment_api.get_opt(deployment_name).await? {
        Some(_existing) => {
            deployment_api
                .patch(
                    deployment_name,
                    &PatchParams::apply("tlb-controller").force(),
                    &Patch::Apply(deployment),
                )
                .await?;
            info!("Patched deployment `{}`", deployment_name);
        }
        None => {
            use kube::api::PostParams;
            deployment_api.create(&PostParams::default(), deployment).await?;
            info!("Created deployment `{}`", deployment_name);
        }
    }

    Ok(())
}
