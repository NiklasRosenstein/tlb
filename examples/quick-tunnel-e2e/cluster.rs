use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use kube::{
    Client, Config,
    config::{KubeConfigOptions, Kubeconfig},
};

use crate::command;

pub struct Cluster {
    pub name: String,
    directory: PathBuf,
    kubeconfig: PathBuf,
    create_attempted: bool,
}

impl Cluster {
    pub fn new() -> Result<Self> {
        let name = format!("tlb-e2e-{:016x}", rand::random::<u64>());
        let directory = std::env::temp_dir().join(&name);
        std::fs::create_dir(&directory)?;
        Ok(Self {
            kubeconfig: directory.join("kubeconfig"),
            directory,
            name,
            create_attempted: false,
        })
    }

    pub async fn create(&mut self, node_image: &str) -> Result<()> {
        let existing = command::capture("kind", &["get", "clusters"]).await?;
        ensure!(
            !existing.lines().any(|name| name == self.name),
            "cluster name collision"
        );
        // Partial creation also needs cleanup; no existing cluster is adopted.
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
                "--kubeconfig",
                self.kubeconfig.to_str().context("kubeconfig path")?,
                "--wait",
                "120s",
            ],
            240,
        )
        .await
    }

    pub async fn install(&self) -> Result<()> {
        let image = format!("tlb:{}", self.name);
        command::run("kind", &["load", "docker-image", &image, "--name", &self.name], 120).await?;
        command::run(
            "helm",
            &[
                "upgrade",
                "--install",
                "tlb-e2e",
                "helm/tlb-controller",
                "--kubeconfig",
                self.kubeconfig.to_str().context("kubeconfig path")?,
                "--namespace",
                "tlb-system",
                "--create-namespace",
                "--set",
                "image.repository=tlb",
                "--set",
                &format!("image.tag={}", self.name),
                "--set",
                "image.pullPolicy=Never",
                "--wait",
                "--timeout",
                "120s",
            ],
            150,
        )
        .await
    }

    pub async fn client(&self) -> Result<Client> {
        let mut config =
            Config::from_custom_kubeconfig(Kubeconfig::read_from(&self.kubeconfig)?, &KubeConfigOptions::default())
                .await?;
        config.connect_timeout = Some(std::time::Duration::from_secs(10));
        config.read_timeout = Some(std::time::Duration::from_secs(15));
        Ok(Client::try_from(config)?)
    }

    pub async fn diagnostics(&self) {
        if self.create_attempted {
            let logs = self.directory.join("logs");
            eprintln!("Saving kind diagnostics to {}", logs.display());
            if let Err(error) = command::run(
                "kind",
                &["export", "logs", logs.to_str().unwrap(), "--name", &self.name],
                60,
            )
            .await
            {
                eprintln!("Diagnostics failed: {error:#}");
            }
        }
    }

    pub async fn cleanup(&self, preserve_diagnostics: bool) -> Result<()> {
        if self.create_attempted {
            command::run("kind", &["delete", "cluster", "--name", &self.name], 120)
                .await
                .with_context(|| format!("cleanup failed; kubeconfig: {}", self.kubeconfig.display()))?;
        }
        if preserve_diagnostics {
            eprintln!("Diagnostics directory: {}", self.directory.display());
            // The deleted cluster's kubeconfig is not a diagnostic artifact.
            if self.kubeconfig.exists() {
                std::fs::remove_file(&self.kubeconfig)?;
            }
        } else {
            std::fs::remove_dir_all(&self.directory)?;
        }
        Ok(())
    }
}
