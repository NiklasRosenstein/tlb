//! The `internal netbird` subcommand.
use std::{process::Command, time::Duration};

use crate::{netbird::NETBIRD_PEER_IP_PORT, Result};
use tokio::io::AsyncWriteExt;

const DEFAULT_NETBIRD_INTERFACE: &str = "wt0";
const UP_COMMAND: &str = "/usr/local/bin/netbird up -F -l=warn";

pub async fn run(service_name: String, tcp_ports: &[u16], udp_ports: &[u16]) -> Result<()> {
    log::info!(
        "running internal netbird command for service {}, tcp ports {:?}, udp ports {:?}",
        service_name,
        tcp_ports,
        udp_ports
    );

    // Get the namespace from the service account.
    let namespace =
        std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/namespace")?;

    // Install socat if it's not already installed.
    if !Command::new("socat").output().is_ok() {
        log::info!("socat not found, installing...");
        let output = Command::new("apk").args(["add", "--no-cache", "socat"]).output()?;
        if !output.status.success() {
            log::error!(
                "failed to install socat: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Err("failed to install socat".into());
        }
        log::info!("socat installed successfully");
    }

    // Launch socat for each port.
    for port in tcp_ports {
        let _ = Command::new("socat")
            .args([
                format!("TCP-LISTEN:{},fork,reuseaddr", port),
                format!("TCP:{}.{}:{}", service_name, namespace, port),
            ])
            .spawn()?;
        log::info!("launched socat for tcp port {}", port);
    }
    for port in udp_ports {
        let _ = Command::new("socat")
            .args([
                format!("UDP-LISTEN:{},fork,reuseaddr", port),
                format!("UDP:{}.{}:{}", service_name, namespace, port),
            ])
            .spawn()?;
        log::info!("launched socat for udp port {}", port);
    }

    // Launch the Netbird up command.
    let _ = Command::new("/bin/sh")
        .args(["-c", UP_COMMAND])
        .spawn()?;
    log::info!("launched netbird up command");

    // Wait for the Netbird interface to come up.
    let peer_ip = loop {
        log::info!("waiting for netbird interface to come up...");
        if let Ok(output) = Command::new("ip").args(["addr", "show", DEFAULT_NETBIRD_INTERFACE]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(ip) = stdout
                    .lines()
                    .find(|line| line.contains("inet "))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|ip| ip.split('/').next())
                {
                    log::info!("netbird interface is up with ip {}", ip);
                    break ip.to_string();
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    };

    // Launch a process in the background that waits for the Netbird interface to come up and expose it via a TCP server.
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", NETBIRD_PEER_IP_PORT)).await?;
    log::info!("serving peer ip on port {}", NETBIRD_PEER_IP_PORT);

    loop {
        let (mut stream, _) = listener.accept().await?;
        let _ = stream.write_all(peer_ip.as_bytes()).await;
    }
}
