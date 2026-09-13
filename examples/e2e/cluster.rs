use crate::{
    command,
    kubernetes::{Kubernetes, SYSTEM, entries, name},
};
use anyhow::{Context, Result, ensure};
use base64::Engine;
use kube::{
    Client, Config,
    config::{KubeConfigOptions, Kubeconfig},
};
use serde::Deserialize;
use serde_json::Value;
use std::{path::PathBuf, sync::Mutex, time::Duration};

pub struct Cluster {
    pub name: String,
    pub directory: PathBuf,
    kubeconfig: PathBuf,
    create_attempted: bool,
    pub kube: Option<Kubernetes>,
    sensitive: Mutex<Vec<String>>,
}
impl Cluster {
    pub fn new(scenario: &str) -> Result<Self> {
        let name = format!("tlb-e2e-{scenario}-{:08x}", rand::random::<u32>());
        let directory = std::env::temp_dir().join(&name);
        std::fs::create_dir(&directory)?;
        Ok(Self {
            kubeconfig: directory.join("kubeconfig"),
            name,
            directory,
            create_attempted: false,
            kube: None,
            sensitive: Mutex::new(Vec::new()),
        })
    }
    pub fn client(&self) -> Result<&Kubernetes> {
        self.kube.as_ref().context("cluster is not connected")
    }
    pub fn redact(&self, text: &str) -> String {
        let mut result = text.to_owned();
        for secret in self.sensitive.lock().unwrap().iter() {
            result = result.replace(secret, "[redacted]");
        }
        result
    }
    pub fn secret(&self, value: &str) {
        if !value.is_empty() {
            let mut secrets = self.sensitive.lock().unwrap();
            secrets.push(value.into());
            secrets.push(base64::prelude::BASE64_STANDARD.encode(value));
        }
    }
    pub async fn create(&mut self, node_image: &str, two_nodes: bool) -> Result<()> {
        let existing = command::capture("kind", &["get", "clusters"]).await?;
        ensure!(!existing.lines().any(|s| s == self.name), "cluster name collision");
        let config = self.directory.join("kind.yaml");
        std::fs::write(
            &config,
            if two_nodes {
                include_str!("../../tests/kind.yaml")
            } else {
                "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n- role: control-plane\n"
            },
        )?;
        self.create_attempted = true;
        command::run(
            "kind",
            &[
                "create",
                "cluster",
                "--name",
                &self.name,
                "--image",
                node_image,
                "--config",
                config.to_str().unwrap(),
                "--kubeconfig",
                self.kubeconfig.to_str().unwrap(),
                "--wait",
                "120s",
            ],
            240,
        )
        .await?;
        let mut config =
            Config::from_custom_kubeconfig(Kubeconfig::read_from(&self.kubeconfig)?, &KubeConfigOptions::default())
                .await?;
        config.connect_timeout = Some(Duration::from_secs(10));
        config.read_timeout = Some(Duration::from_secs(15));
        self.kube = Some(Kubernetes(Client::try_from(config)?));
        Ok(())
    }
    pub async fn load(&self, image: &str) -> Result<()> {
        command::run("kind", &["load", "docker-image", image, "--name", &self.name], 120).await
    }
    pub async fn install(&self, image: &str, replicas: u32) -> Result<()> {
        self.load(image).await?;
        let k = self.client()?;
        for value in installation(&std::fs::read_to_string("deploy/tlb.yaml")?, image, replicas)? {
            k.apply(value).await?;
        }
        k.rollout().await
    }
    /// Exec is a bounded, explicitly scoped subprocess. Arguments may contain test credentials and are never logged.
    pub async fn exec(&self, ns: &str, pod: &str, container: &str, args: &[&str]) -> Result<String> {
        let mut argv = vec![
            "--kubeconfig",
            self.kubeconfig.to_str().unwrap(),
            "--request-timeout=20s",
            "exec",
            "-n",
            ns,
            pod,
            "-c",
            container,
            "--",
        ];
        argv.extend_from_slice(args);
        command::capture("kubectl", &argv)
            .await
            .map_err(|e| anyhow::anyhow!("{}", self.redact(&format!("{e:#}"))))
    }
    pub async fn diagnostics(&self) {
        let directory = self.directory.join("logs");
        if std::fs::create_dir_all(&directory).is_err() {
            return;
        }
        let Some(k) = &self.kube else {
            // Before client creation there are no provisioned test credentials to redact.
            if self.create_attempted
                && let Err(error) = command::run(
                    "kind",
                    &["export", "logs", directory.to_str().unwrap(), "--name", &self.name],
                    60,
                )
                .await
            {
                eprintln!("Startup diagnostics failed: {error:#}");
            }
            return;
        };
        if let Ok(pods) = k.list("Pod", "", "").await {
            for pod in pods {
                let ns = pod["metadata"]["namespace"].as_str().unwrap_or_default();
                if ns == SYSTEM
                    && !name(&pod).starts_with("tlb-")
                    && !name(&pod).starts_with("tunnel-")
                    && !name(&pod).starts_with("cf-")
                {
                    continue;
                }
                let status = serde_json::json!({"metadata":pod["metadata"],"status":pod["status"]});
                let _ = std::fs::write(
                    directory.join(format!("{ns}-{}.json", name(&pod))),
                    self.redact(&status.to_string()),
                );
                for container in entries(&pod["spec"]["containers"]) {
                    let c = container["name"].as_str().unwrap_or_default();
                    if let Ok(log) = k.logs(ns, name(&pod), c).await {
                        let _ = std::fs::write(
                            directory.join(format!("{ns}-{}-{c}.log", name(&pod))),
                            self.redact(&log),
                        );
                    }
                }
            }
        }
        if let Ok(events) = k.list("Event", "", "").await {
            let _ = std::fs::write(
                directory.join("events.json"),
                self.redact(&serde_json::to_string_pretty(&events).unwrap_or_default()),
            );
        }
        eprintln!("Diagnostics: {}", directory.display());
    }
    pub async fn cleanup(&self, failed: bool) -> Result<()> {
        if self.create_attempted {
            command::run("kind", &["delete", "cluster", "--name", &self.name], 120)
                .await
                .with_context(|| format!("cluster cleanup failed; kubeconfig: {}", self.kubeconfig.display()))?;
        }
        if failed {
            for file in ["kubeconfig", "key.pem", "cert.pem"] {
                let path = self.directory.join(file);
                if path.exists() {
                    std::fs::remove_file(path)?;
                }
            }
        } else {
            std::fs::remove_dir_all(&self.directory)?;
        }
        Ok(())
    }
}
pub fn installation(manifest: &str, image: &str, replicas: u32) -> Result<Vec<Value>> {
    let mut objects = Vec::new();
    let mut controllers = 0;
    for document in serde_yaml::Deserializer::from_str(manifest) {
        let mut value = Value::deserialize(document)?;
        if value.is_null() {
            continue;
        }
        if value["kind"] == "Deployment" && value["metadata"]["name"] == "tlb-controller" {
            controllers += 1;
            value["spec"]["replicas"] = replicas.into();
            let containers = value["spec"]["template"]["spec"]["containers"]
                .as_array_mut()
                .context("controller containers")?;
            let container = containers
                .iter_mut()
                .find(|c| c["name"] == "tlb-controller")
                .context("controller container")?;
            container["image"] = image.into();
            container["imagePullPolicy"] = "Never".into();
            container["env"]
                .as_array_mut()
                .context("controller env")?
                .push(serde_json::json!({"name":"TLB_EXTERNAL_REFRESH_INTERVAL_SECONDS","value":"7200"}));
        }
        objects.push(value);
    }
    ensure!(
        controllers == 1,
        "expected one controller Deployment, got {controllers}"
    );
    Ok(objects)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn install_requires_a_controller_and_changes_only_its_image() {
        assert!(installation("kind: ConfigMap\nmetadata:\n  name: unrelated\n", "test:1", 2).is_err());
        let objects = installation(include_str!("../../deploy/tlb.yaml"), "test:1", 2).unwrap();
        let controller = objects.iter().find(|v| v["kind"] == "Deployment").unwrap();
        assert_eq!(controller["spec"]["replicas"], 2);
        assert_eq!(
            controller["spec"]["template"]["spec"]["containers"][0]["image"],
            "test:1"
        );
        assert!(objects.iter().any(|v| v["kind"] == "CustomResourceDefinition"));
    }
    #[test]
    fn diagnostic_redaction_covers_raw_and_base64_credentials() {
        let cluster = Cluster::new("redaction-test").unwrap();
        cluster.secret("private-token");
        assert_eq!(
            cluster.redact("private-token cHJpdmF0ZS10b2tlbg=="),
            "[redacted] [redacted]"
        );
        std::fs::remove_dir_all(&cluster.directory).unwrap();
    }
}
