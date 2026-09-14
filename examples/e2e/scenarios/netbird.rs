//! Disposable real NetBird server, connector, and client peers with TCP/UDP/TLS probes.
use crate::{cluster::Cluster, command, kubernetes::*};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::sync::Mutex;
const NS: &str = "netbird-test";
const URL: &str = "http://server.netbird-test.svc.cluster.local:80";
const PEER_IMAGE: &str = "netbirdio/netbird:0.76.3";
const PYTHON: &str = "python:3.13.7-alpine3.22";
async fn api(c: &Cluster, path: &str, body: Value, token: Option<&str>) -> Result<Value> {
    let mut headers = json!({"Content-Type":"application/json"});
    if let Some(token) = token {
        headers["Authorization"] = format!("Token {token}").into();
    }
    let code = format!(
        "import json,urllib.request\nbody={:?}.encode()\nheaders=json.loads({:?})\nrequest=urllib.request.Request({:?},data=body,headers=headers)\nprint(urllib.request.urlopen(request,timeout=10).read().decode())",
        body.to_string(),
        headers.to_string(),
        format!("{URL}{path}")
    );
    Ok(serde_json::from_str(
        &c.exec(NS, "tools", "tools", &["python3", "-c", &code]).await?,
    )?)
}
async fn pod_ready(k: &Kubernetes, pod: &str) -> Result<()> {
    wait(&format!("{pod} ready"), 120, async || {
        Ok(ready(&k.get("Pod", NS, pod).await?))
    })
    .await
}
fn random_secret() -> String {
    format!("{:032x}{:032x}", rand::random::<u128>(), rand::random::<u128>())
}
async fn probe(c: &Cluster, pod: &str, address: &str) -> Result<bool> {
    let script = format!(
        r#"import socket,ssl,json
address={address:?}
marker=b'tlb-netbird-forwarding'
responses=[]
for port in (18080,18443):
    connection=socket.create_connection((address,port),timeout=5)
    if port==18443:
        connection=ssl._create_unverified_context().wrap_socket(connection,server_hostname='localhost')
    connection.sendall(marker)
    response=b''
    while len(response)<len(marker):
        chunk=connection.recv(len(marker)-len(response))
        if not chunk: break
        response+=chunk
    responses.append(response.decode('ascii'))
    connection.close()
connection=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
connection.settimeout(5)
connection.sendto(marker,(address,19000))
responses.append(connection.recv(1024).decode('ascii'))
print(json.dumps(responses))
"#
    );
    Ok(c.exec(NS, pod, "probe", &["python3", "-c", &script])
        .await
        .is_ok_and(|s| valid_responses(&s)))
}
fn valid_responses(output: &str) -> bool {
    serde_json::from_str::<Vec<String>>(output)
        .is_ok_and(|responses| responses.len() == 3 && responses.iter().all(|s| s == "tlb-netbird-forwarding"))
}

pub async fn run(c: &Cluster) -> Result<()> {
    let k = c.client()?;
    k.namespace(NS).await?;
    let auth = random_secret();
    c.secret(&auth);
    let config = json!({"server":{"listenAddress":":80","exposedAddress":URL,"authSecret":auth,"dataDir":"/var/lib/netbird","logLevel":"info","logFile":"console","disableAnonymousMetrics":true,"disableGeoliteUpdate":true,"auth":{"issuer":format!("{URL}/oauth2"),"localAuthDisabled":false},"store":{"engine":"sqlite"}}});
    c.secret(&config.to_string());
    k.apply(object(
        "Secret",
        NS,
        "server-config",
        json!({"stringData":{"config.yaml":config.to_string()}}),
    ))
    .await?;
    k.apply(object("Service",NS,"server",json!({"spec":{"selector":{"app":"netbird-server"},"ports":[{"name":"http","port":80},{"name":"stun","port":3478,"protocol":"UDP"}]}}))).await?;
    // Geolocation is unused by this fixture and requires an external database download.
    k.apply(object("Pod",NS,"server",json!({"metadata":{"labels":{"app":"netbird-server"}},"spec":{"automountServiceAccountToken":false,"containers":[{"name":"server","image":"netbirdio/netbird-server:0.76.3","args":["--config","/etc/netbird/config.yaml"],"env":[{"name":"NB_SETUP_PAT_ENABLED","value":"true"},{"name":"NB_DISABLE_GEOLOCATION","value":"true"}],"volumeMounts":[{"name":"config","mountPath":"/etc/netbird","readOnly":true},{"name":"data","mountPath":"/var/lib/netbird"}]}],"volumes":[{"name":"config","secret":{"secretName":"server-config"}},{"name":"data","emptyDir":{}}]}}))).await?;
    k.apply(object("Pod",NS,"tools",json!({"spec":{"automountServiceAccountToken":false,"containers":[{"name":"tools","image":PYTHON,"command":["sleep","1800"]}]}}))).await?;
    pod_ready(k, "tools").await?;
    pod_ready(k, "server").await?;
    let password = random_secret();
    c.secret(&password);
    let bootstrap = Mutex::new(None);
    wait("NetBird account bootstrap", 120, async || {
        match api(
            c,
            "/api/setup",
            json!({"email":"admin@example.test","name":"Test","password":password,"create_pat":true,"pat_expire_in":1}),
            None,
        )
        .await
        {
            Ok(v) => {
                *bootstrap.lock().unwrap() = Some(v);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    })
    .await?;
    ensure!(
        k.logs(NS, "server", "server")
            .await?
            .contains("geolocation service is disabled"),
        "fixture must disable geolocation database downloads"
    );
    let bootstrap = bootstrap.into_inner().unwrap().context("bootstrap response")?;
    let token = bootstrap["personal_access_token"].as_str().context("bootstrap PAT")?;
    c.secret(token);
    let setup=api(c,"/api/setup-keys",json!({"name":"tlb-test","type":"reusable","expires_in":3600,"auto_groups":[],"usage_limit":10,"ephemeral":true}),Some(token)).await?;
    let setup_key = setup["key"].as_str().context("setup key")?;
    c.secret(setup_key);
    k.apply(object("Secret", NS, "setup", json!({"stringData":{"key":setup_key}})))
        .await?;
    let key = c.directory.join("key.pem");
    let cert = c.directory.join("cert.pem");
    command::run(
        "openssl",
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
        ],
        20,
    )
    .await?;
    let key_value = std::fs::read_to_string(&key)?;
    c.secret(&key_value);
    k.apply(object("Secret",NS,"tls",json!({"type":"kubernetes.io/tls","stringData":{"tls.key":key_value,"tls.crt":std::fs::read_to_string(&cert)?}}))).await?;
    std::fs::remove_file(key)?;
    std::fs::remove_file(cert)?;
    let origin = r#"import socketserver,threading
class TCP(socketserver.BaseRequestHandler):
    def handle(self): self.request.sendall(self.request.recv(1024))
class UDP(socketserver.BaseRequestHandler):
    def handle(self): self.request[1].sendto(self.request[0],self.client_address)
server=socketserver.ThreadingTCPServer(('0.0.0.0',8080),TCP)
threading.Thread(target=server.serve_forever,daemon=True).start()
socketserver.ThreadingUDPServer(('0.0.0.0',9000),UDP).serve_forever()
"#;
    k.apply(object("Pod",NS,"origin",json!({"metadata":{"labels":{"app":"origin"}},"spec":{"automountServiceAccountToken":false,"containers":[{"name":"origin","image":PYTHON,"command":["python3","-u","-c",origin]}]}}))).await?;
    pod_ready(k, "origin").await?;
    k.apply(object(
        "TunnelClass",
        NS,
        "netbird",
        json!({"spec":{"netbird":{"managementUrl":URL,"setupKeyRef":{"name":"setup","key":"key"}}}}),
    ))
    .await?;
    let service=k.apply(object("Service",NS,"origin",json!({"metadata":{"annotations":{"tlb.io/map-ports":"18080:tcp,18443/tls:tcp,19000:udp","tlb.io/tls-secret-name":"tls"}},"spec":{"type":"LoadBalancer","loadBalancerClass":"tlb.io/netbird","selector":{"app":"origin"},"ports":[{"name":"tcp","port":8080},{"name":"udp","port":9000,"protocol":"UDP"}]}}))).await?;
    wait("TLB announces real NetBird peer IP", 240, async || {
        Ok(k.get("Service", NS, "origin").await?["status"]["loadBalancer"]["ingress"][0]["ip"].is_string())
    })
    .await?;
    let announced = k.get("Service", NS, "origin").await?;
    let address = announced["status"]["loadBalancer"]["ingress"][0]["ip"]
        .as_str()
        .context("peer IP")?;
    for relay in [false, true] {
        let peer = if relay { "relayed-peer" } else { "direct-peer" };
        k.apply(object("Pod",NS,peer,json!({"spec":{"automountServiceAccountToken":false,"containers":[{"name":"netbird","image":PEER_IMAGE,"command":["/usr/local/bin/netbird","up","-F","-l","info","--disable-dns"],"env":[{"name":"NB_MANAGEMENT_URL","value":URL},{"name":"NB_SETUP_KEY","valueFrom":{"secretKeyRef":{"name":"setup","key":"key"}}},{"name":"NB_DISABLE_EBPF_WG_PROXY","value":"true"},{"name":"NB_FORCE_RELAY","value":relay.to_string()}],"securityContext":{"capabilities":{"add":["NET_ADMIN"]}}},{"name":"probe","image":PYTHON,"command":["sleep","1800"]}]}}))).await?;
        pod_ready(k, peer).await?;
        wait(
            &format!("{peer} TCP, UDP and TLS forwarding without eBPF"),
            180,
            async || probe(c, peer, address).await,
        )
        .await?;
        let logs = k.logs(NS, peer, "netbird").await?;
        ensure!(
            logs.contains("eBPF WireGuard proxy is disabled") || logs.contains("produce UDP proxy"),
            "userspace proxy not selected"
        );
    }
    k.delete("Service", NS, "origin").await?;
    wait(
        "real tunnel cleanup removes runtime Secrets and journal",
        120,
        async || k.clean(SYSTEM, &selector(&service)).await,
    )
    .await?;
    ensure!(
        k.list("Secret", NS, "").await?.len() == 3,
        "cleanup deleted source Secrets"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_three_protocols_must_return_the_exact_payload() {
        let good = "tlb-netbird-forwarding";
        assert!(valid_responses(&serde_json::to_string(&[good, good, good]).unwrap()));
        assert!(!valid_responses(&serde_json::to_string(&[good, good]).unwrap()));
        assert!(!valid_responses(
            &serde_json::to_string(&[good, "wrong TLS payload", good]).unwrap()
        ));
        assert!(!valid_responses("verified"));
    }
}
