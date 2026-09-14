use std::{collections::BTreeMap, time::Duration};

use anyhow::{Result, ensure};
use k8s_openapi::{
    api::core::v1::{
        ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, HTTPGetAction, Namespace, Pod, PodSpec, Probe,
        Service, ServicePort, ServiceSpec, Volume, VolumeMount,
    },
    apimachinery::pkg::util::intstr::IntOrString,
};
use kube::{
    Api, Client,
    api::{ObjectMeta, PostParams},
};
use tlb::crds::{
    CloudflareAnnounceType, CloudflareConfig, CloudflareTransportProtocol, TunnelClass, TunnelClassInnerSpec,
    TunnelClassSpec,
};
use tokio::time::{Instant, sleep};

const NAMESPACE: &str = "quick-tunnel-e2e";
const NAME: &str = "http-probe";

/// The unique response proves the public request reached this run's Pod.
pub async fn create(client: Client, marker: &str, origin_image: &str) -> Result<()> {
    let params = PostParams::default();
    Api::<Namespace>::all(client.clone())
        .create(
            &params,
            &Namespace {
                metadata: metadata(NAMESPACE),
                ..Default::default()
            },
        )
        .await?;
    Api::<ConfigMap>::namespaced(client.clone(), NAMESPACE)
        .create(
            &params,
            &ConfigMap {
                metadata: metadata(NAME),
                data: Some(BTreeMap::from([("index.html".into(), marker.into())])),
                ..Default::default()
            },
        )
        .await?;
    Api::<Pod>::namespaced(client.clone(), NAMESPACE)
        .create(
            &params,
            &Pod {
                metadata: ObjectMeta {
                    labels: Some(BTreeMap::from([("app".into(), NAME.into())])),
                    ..metadata(NAME)
                },
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "http".into(),
                        image: Some(origin_image.into()),
                        ports: Some(vec![ContainerPort {
                            container_port: 80,
                            ..Default::default()
                        }]),
                        readiness_probe: Some(Probe {
                            http_get: Some(HTTPGetAction {
                                path: Some("/".into()),
                                port: IntOrString::Int(80),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        volume_mounts: Some(vec![VolumeMount {
                            name: "content".into(),
                            mount_path: "/usr/share/nginx/html".into(),
                            read_only: Some(true),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }],
                    volumes: Some(vec![Volume {
                        name: "content".into(),
                        config_map: Some(ConfigMapVolumeSource {
                            name: NAME.into(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await?;
    Api::<TunnelClass>::namespaced(client.clone(), NAMESPACE)
        .create(
            &params,
            &TunnelClass::new(
                "quick",
                TunnelClassSpec {
                    inner: TunnelClassInnerSpec {
                        cloudflare: Some(CloudflareConfig {
                            transport_protocol: CloudflareTransportProtocol::Http2,
                            api_token_ref: None,
                            account_id: None,
                            image: None,
                            resource_prefix: None,
                            tunnel_prefix: None,
                            announce_type: Some(CloudflareAnnounceType::External),
                        }),
                        ..Default::default()
                    },
                },
            ),
        )
        .await?;
    Api::<Service>::namespaced(client, NAMESPACE)
        .create(
            &params,
            &Service {
                metadata: ObjectMeta {
                    annotations: Some(BTreeMap::from([("tlb.io/map-ports".into(), "http:origin".into())])),
                    ..metadata(NAME)
                },
                spec: Some(ServiceSpec {
                    type_: Some("LoadBalancer".into()),
                    load_balancer_class: Some("tlb.io/quick".into()),
                    selector: Some(BTreeMap::from([("app".into(), NAME.into())])),
                    // Only the explicitly mapped second port reaches the HTTP origin.
                    ports: Some(vec![
                        ServicePort {
                            name: Some("unused".into()),
                            port: 8080,
                            target_port: Some(IntOrString::Int(9)),
                            ..Default::default()
                        },
                        ServicePort {
                            name: Some("origin".into()),
                            port: 18080,
                            target_port: Some(IntOrString::Int(80)),
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await?;
    Ok(())
}

fn metadata(name: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.into()),
        ..Default::default()
    }
}

pub async fn verify(client: Client, marker: &str, budget: Duration) -> Result<String> {
    let services = Api::<Service>::namespaced(client, NAMESPACE);
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let deadline = Instant::now() + budget;
    let mut last_error = "waiting for Service loadBalancer hostname".to_owned();
    loop {
        ensure!(
            Instant::now() < deadline,
            "public HTTP verification timed out: {last_error}"
        );
        // Re-read status on every attempt: a connector restart can change the hostname.
        let attempt = async {
            let service = services.get(NAME).await?;
            let hostname = service
                .status
                .and_then(|status| status.load_balancer)
                .and_then(|lb| lb.ingress)
                .unwrap_or_default()
                .into_iter()
                .find_map(|ingress| ingress.hostname);
            let Some(hostname) = hostname else {
                anyhow::bail!("waiting for Service loadBalancer hostname");
            };
            ensure!(
                quick_hostname(&hostname),
                "unexpected Quick Tunnel hostname: {hostname}"
            );
            let url = format!("https://{hostname}/?run={marker}");
            check_response(&http, &url, marker).await?;
            Ok::<_, anyhow::Error>(url)
        };
        match tokio::time::timeout_at(deadline, attempt).await {
            Ok(Ok(url)) => return Ok(url),
            Ok(Err(error)) => {
                last_error = format!("{error:#}");
                eprintln!("Waiting: {last_error}");
            }
            Err(_) => anyhow::bail!("public HTTP verification timed out: {last_error}"),
        }
        sleep(Duration::from_secs(5).min(deadline.saturating_duration_since(Instant::now()))).await;
    }
}

fn quick_hostname(hostname: &str) -> bool {
    hostname.strip_suffix(".trycloudflare.com").is_some_and(|label| {
        !label.is_empty() && label.len() <= 63 && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

async fn check_response(http: &reqwest::Client, url: &str, marker: &str) -> Result<()> {
    let mut response = http.get(url).send().await?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "{url} returned {}",
        response.status()
    );
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            body.len() + chunk.len() <= marker.len(),
            "{url} returned an unexpected response body"
        );
        body.extend_from_slice(&chunk);
    }
    ensure!(body == marker.as_bytes(), "{url} did not return this run's marker");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn only_accepts_quick_tunnel_hosts() {
        assert!(quick_hostname("some-generated-name.trycloudflare.com"));
        for invalid in [
            "trycloudflare.com",
            ".trycloudflare.com",
            "evil.com/path.trycloudflare.com",
            "a.b.trycloudflare.com",
        ] {
            assert!(!quick_hostname(invalid));
        }
    }

    #[tokio::test]
    async fn public_probe_requires_success_and_exact_marker() {
        rustls::crypto::ring::default_provider().install_default().ok();
        for (status, body, success) in [
            (200, "expected", true),
            (200, "wrong", false),
            (200, "expected extra", false),
            (502, "expected", false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                assert!(stream.read(&mut request).await.unwrap() > 0);
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            });
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap();
            assert_eq!(check_response(&client, &url, "expected").await.is_ok(), success);
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();
        }
    }
}
