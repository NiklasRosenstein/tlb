//! Isolated Kubernetes and real-provider scenarios sharing build, diagnostics, and cleanup.
mod cluster;
mod command;
mod kubernetes;
mod scenarios;
use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use cluster::Cluster;
use futures::FutureExt;
use std::{
    panic::AssertUnwindSafe,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Scenario {
    Kubernetes,
    Lifecycle,
    Classes,
    Dns,
    Deployment,
    Runtime,
    Netbird,
    QuickTunnel,
    All,
}
impl Scenario {
    fn name(self) -> &'static str {
        match self {
            Self::Kubernetes => "kubernetes",
            Self::Lifecycle => "lifecycle",
            Self::Classes => "classes",
            Self::Dns => "dns",
            Self::Deployment => "deployment",
            Self::Runtime => "runtime",
            Self::Netbird => "netbird",
            Self::QuickTunnel => "quick-tunnel",
            Self::All => "all",
        }
    }
    fn expand(self) -> Vec<Self> {
        match self {
            Self::Kubernetes => vec![
                Self::Lifecycle,
                Self::Classes,
                Self::Dns,
                Self::Deployment,
                Self::Runtime,
            ],
            Self::All => vec![
                Self::Lifecycle,
                Self::Classes,
                Self::Dns,
                Self::Deployment,
                Self::Runtime,
                Self::Netbird,
                Self::QuickTunnel,
            ],
            s => vec![s],
        }
    }
}
#[derive(Parser)]
#[command(about = "Build TLB once and run selected scenarios in disposable kind clusters")]
struct Options {
    #[arg(value_enum, default_value = "kubernetes")]
    scenario: Scenario,
    #[arg(long, default_value = "kindest/node:v1.37.0")]
    node_image: String,
    #[arg(long, default_value = "nginx:stable-alpine")]
    origin_image: String,
    #[arg(long,default_value_t=240,value_parser=clap::value_parser!(u64).range(1..=600))]
    tunnel_timeout: u64,
}
async fn run(cluster: &mut Cluster, scenario: Scenario, options: &Options, image: &str, fixture: &str) -> Result<()> {
    cluster
        .create(&options.node_image, matches!(scenario, Scenario::Dns))
        .await?;
    if matches!(scenario, Scenario::Dns) {
        cluster.load(fixture).await?;
    }
    cluster
        .install(
            image,
            if matches!(scenario, Scenario::Dns | Scenario::Deployment) {
                2
            } else {
                1
            },
        )
        .await?;
    match scenario {
        Scenario::Lifecycle => scenarios::lifecycle::run(cluster.client()?).await,
        Scenario::Classes => scenarios::classes::run(cluster.client()?).await,
        Scenario::Dns => scenarios::dns::run(cluster, fixture).await,
        Scenario::Deployment => scenarios::deployment::run(cluster.client()?).await,
        Scenario::Runtime => scenarios::runtime::run(cluster.client()?).await,
        Scenario::Netbird => scenarios::netbird::run(cluster).await,
        Scenario::QuickTunnel => {
            let client = cluster.client()?.0.clone();
            scenarios::quick_tunnel::create(client.clone(), &cluster.name, &options.origin_image).await?;
            let url =
                scenarios::quick_tunnel::verify(client, &cluster.name, Duration::from_secs(options.tunnel_timeout))
                    .await?;
            eprintln!("PASS {url} returns the exact marker {}", cluster.name);
            Ok(())
        }
        _ => unreachable!("scenario group must be expanded"),
    }
}
async fn shutdown() -> Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {r=tokio::signal::ctrl_c()=>r.context("Ctrl-C")?,_=term.recv()=>{}};
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("Ctrl-C")
    }
}
async fn execute(options: &Options, image: &str, fixture: &str) -> Result<()> {
    let scenarios = options.scenario.expand();
    let build = async {
        command::run("docker", &["build", "--tag", image, "."], 600).await?;
        if scenarios.iter().any(|s| matches!(s, Scenario::Dns)) {
            command::run("docker", &["build", "--tag", fixture, "tests/netbird"], 120).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {
        result = build => result?,
        signal = shutdown() => { signal?; anyhow::bail!("build interrupted"); }
    }
    let mut failures = Vec::new();
    for scenario in scenarios {
        let mut cluster = Cluster::new(scenario.name())?;
        let start = Instant::now();
        eprintln!("RUN {}: {}", scenario.name(), cluster.name);
        let mut interrupted = false;
        let result = tokio::select! {
            result=tokio::time::timeout(Duration::from_secs(1500),AssertUnwindSafe(run(&mut cluster,scenario,options,image,fixture)).catch_unwind())=>
                result.context("scenario exceeded 25 minutes").and_then(|r|r.map_err(|_|anyhow::anyhow!("scenario panicked"))).and_then(|r|r),
            signal=shutdown()=>{interrupted=true;signal.and_then(|()|Err(anyhow::anyhow!("interrupted")))}
        };
        if result.is_err() {
            let _ = tokio::time::timeout(Duration::from_secs(90), cluster.diagnostics()).await;
        }
        let cleanup = cluster.cleanup(result.is_err()).await;
        if let Err(error) = result {
            let error = cluster.redact(&format!("{error:#}"));
            eprintln!(
                "FAIL {} ({:.1}s): {error}",
                scenario.name(),
                start.elapsed().as_secs_f64()
            );
            failures.push(format!("{}: {error}", scenario.name()));
        } else {
            eprintln!("PASS {} ({:.1}s)", scenario.name(), start.elapsed().as_secs_f64());
        }
        cleanup?;
        if interrupted {
            break;
        }
    }
    anyhow::ensure!(
        failures.is_empty(),
        "{} scenario(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::parse();
    rustls::crypto::ring::default_provider().install_default().ok();
    std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"))?;
    let tag = format!("e2e-{:016x}", rand::random::<u64>());
    let image = format!("tlb:{tag}");
    let fixture = format!("tlb-netbird-test:{tag}");
    let result = execute(&options, &image, &fixture).await;
    let mut cleanup_errors = Vec::new();
    for image in [&image, &fixture] {
        let filter = format!("reference={image}");
        match command::capture("docker", &["image", "ls", "--quiet", "--filter", &filter]).await {
            Ok(ids) if ids.trim().is_empty() => {}
            Ok(_) => {
                if let Err(e) = command::run("docker", &["image", "rm", image], 30).await {
                    cleanup_errors.push(format!("{image}: {e:#}"));
                }
            }
            Err(e) => cleanup_errors.push(format!("inspect {image}: {e:#}")),
        }
    }
    if !cleanup_errors.is_empty() {
        eprintln!("Image cleanup failed: {}", cleanup_errors.join("; "));
        if result.is_ok() {
            anyhow::bail!("image cleanup failed");
        }
    }
    result
}
