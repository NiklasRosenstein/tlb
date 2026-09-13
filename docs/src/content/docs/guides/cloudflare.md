---
title: Cloudflare Tunnel
description: Publish a Service on a Cloudflare-managed domain with an API tunnel.
---

Use Cloudflare API mode when you want a stable hostname under your domain. TLB creates a locally configured tunnel, runs
`cloudflared`, and manages the DNS records declared on your Service.

For an account-free HTTP demo, use the [Quick Tunnel guide](../../start/quickstart/).

## Prepare credentials

You need your Cloudflare account ID and an API token that can manage tunnels in that account. For TLB-managed DNS, the
token also needs DNS edit access and zone read access for the domain's zone. Scope the token to the account and zones
you intend to use; see Cloudflare's
[token documentation](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) and
[tunnel setup permissions](https://developers.cloudflare.com/tunnel/setup/).

Create an `apps` namespace and a Secret through your normal secret-management process. The following class expects a
Secret named `cloudflare-token` with a key named `token` in that namespace. Do not commit the token to your manifests.

## Define the class

```yaml title="cloudflare-class.yaml"
apiVersion: tlb.io/v1alpha1
kind: TunnelClass
metadata:
  name: public
  namespace: apps
spec:
  cloudflare:
    accountId: "0123456789abcdef0123456789abcdef"
    apiTokenRef:
      name: cloudflare-token
      key: token
    announceType: External
```

Replace `accountId` with your 32-character account ID, then apply the class. `accountId` and `apiTokenRef` must be
provided together. Omitting both selects Quick mode.

A namespaced class can only reference credentials in its own namespace. For shared configuration, use a
`ClusterTunnelClass` and set `apiTokenRef.namespace` explicitly.

## Expose your application

This Service selects application Pods labelled `app: website` in `apps`:

```yaml title="website-service.yaml"
apiVersion: v1
kind: Service
metadata:
  name: website
  namespace: apps
  annotations:
    tlb.io/dns: website.example.com
    tlb.io/map-ports: "http:80"
    tlb.io/replicas: "2"
spec:
  type: LoadBalancer
  loadBalancerClass: tlb.io/public
  selector:
    app: website
  ports:
    - name: http
      port: 80
      targetPort: 8080
      protocol: TCP
```

Use a hostname in a zone owned by the configured Cloudflare account. TLB creates a proxied CNAME to the tunnel and
publishes the hostname in Service status.

```bash
kubectl -n apps get service website --watch
```

Multiple comma-separated DNS names can point to the same Service. Every hostname on one tunnel reaches the **same single
Service port**.

## Protocols and origin routing

TLB accepts `http`, `https`, `tcp`, `ssh`, `rdp`, and `smb` as origin protocols. Use `tlb.io/map-ports`
to select one TCP Service port by name or number, for example `"https:8080"` or `"ssh:admin"`. Without a mapping, the
Service must have exactly one TCP port and TLB infers its origin protocol.

Set `tlb.io/map-ports` explicitly when possible. `https` describes TLS between the connector and your application; it is
separate from the public HTTPS URL. For non-HTTP applications, follow Cloudflare's
[supported-protocol guidance](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/protocols/)
for the required client-side connection method. A DNS name alone does not create a generic public TCP listener.

TLB accepts one Cloudflare mapping per Service. All hostnames reach that origin. Multiple origins require hostname or
path routing selectors, which `map-ports` does not supply; use separate LoadBalancer Services to expose them. Numeric
listeners and NetBird TLS suffixes are not accepted for Cloudflare.

## DNS ownership and announcement

- `announceType: External` publishes the managed DNS names. It is the default.
- `announceType: Internal` publishes `<tunnel-id>.cfargotunnel.com` and leaves DNS management to another system. That
  identifier still needs an appropriate proxied DNS record for users to reach the tunnel.
- If DNS provisioning fails, TLB can publish the internal identifier while reporting the error and retrying DNS
  reconciliation. This is not proof that the public hostname works.

TLB marks records with its binding identity. It does not adopt an unrelated existing record at the same hostname.
Removing a name from `tlb.io/dns` removes the corresponding managed record; deleting the Service cleans the tunnel and
its managed DNS records.

The [class reference](../../reference/classes/#cloudflare-fields) lists images, naming, and announcement settings.

## Tunnel transport

`transportProtocol` selects the connection from cloudflared to Cloudflare: `auto` (default), `quic`, or `http2`. Set
`spec.cloudflare.transportProtocol: http2` when outbound UDP is blocked or automatic fallback does not establish a
connection. The tunnel needs outbound connectivity to Cloudflare on port 7844. This setting is independent of the origin
protocol selected by `tlb.io/map-ports`.
