//! Credential-free public HTTP E2E using the built controller image and Helm chart.
mod cluster;
mod command;
mod workload;

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use cluster::Cluster;

#[derive(Parser)]
#[command(about = "Build TLB, install its chart in an isolated kind cluster, and verify a public Quick Tunnel")]
struct Options {
    #[arg(long, default_value = "kindest/node:v1.37.0")]
    node_image: String,
    #[arg(long, default_value = "nginx:stable-alpine")]
    origin_image: String,
    /// Deadline for Service discovery, DNS propagation, and public HTTP retries.
    #[arg(long, default_value_t = 240, value_parser = clap::value_parser!(u64).range(1..=600))]
    tunnel_timeout: u64,
}

async fn scenario(cluster: &mut Cluster, options: &Options) -> Result<()> {
    let image = format!("tlb:{}", cluster.name);
    command::run("docker", &["build", "--tag", &image, "."], 600).await?;
    cluster.create(&options.node_image).await?;
    cluster.install().await?;
    let client = cluster.client().await?;
    workload::create(client.clone(), &cluster.name, &options.origin_image).await?;
    let url = workload::verify(client, &cluster.name, Duration::from_secs(options.tunnel_timeout)).await?;
    eprintln!("PASS: {url} returned the exact marker {}", cluster.name);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::parse();
    rustls::crypto::ring::default_provider().install_default().ok();
    std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"))?;
    let mut cluster = Cluster::new()?;
    eprintln!("E2E cluster: {}", cluster.name);
    let result = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(1500), scenario(&mut cluster, &options)) => {
            result.context("E2E exceeded 25 minutes").and_then(|result| result)
        }
        signal = shutdown() => {
            signal.and_then(|()| Err(anyhow::anyhow!("E2E interrupted")))
        }
    };
    if result.is_err() {
        cluster.diagnostics().await;
    }
    let cleanup = cluster.cleanup(result.is_err()).await;
    // Tags are unique to this run; do not accumulate controller images across runs.
    if let Err(error) = command::run("docker", &["image", "rm", &format!("tlb:{}", cluster.name)], 30).await {
        eprintln!("Image cleanup: {error:#}");
    }
    if let Err(error) = cleanup {
        if let Err(original) = &result {
            eprintln!("E2E failure: {original:#}");
        }
        return Err(error);
    }
    result
}

async fn shutdown() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("receive Ctrl-C")?,
            _ = terminate.recv() => {},
        }
        Ok(())
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await.context("receive Ctrl-C")
}
