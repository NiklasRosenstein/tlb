# tlb

TLB is a Kubernetes operator for exposing Kubernetes services and pods using various supported tunneling services,
allowing you to effectively expose your applications without needing to manage traditional LoadBalancers or manual
routing configurations.

## Usage

After installing TLB, you define your own `TunnelClass` or `ClusterTunnelClass` resources that can be referenced in a
`Service`'s `loadBalancerClass`.

```yaml
apiVersion: tlb.io/v1alpha1
kind: ClusterTunnelClass
metadata:
  name: netbird
spec:
  type: netbird
  netbird:
    managementURL: https://netbird.example.com
    setupKeyRef:
      name: netbird-setup-key
      namespace: tlb-system
      key: SETUP_KEY
```

In your Service, you can then reference this `ClusterTunnelClass`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
  namespace: default
  annotations:
    tlb.io/dns: "my-service.netbird.selfhosted"
    tlb.io/replicas: "1"
spec:
  type: LoadBalancer
  loadBalancerClass: tlb.io/netbird
  ports:
    - port: 80
      targetPort: 8080
  selector:
    app: my-app
```

> If a `TunnelClass` and `ClusterTunnelClass` with the same name exist, the `TunnelClass` will be used.

## Supported tunneling services

- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/) (WIP)
- [NetBird](https://netbird.io/) (WIP)
- [Tailscale](https://tailscale.com/) (planned)

## Examples

### Cloudflare Tunnel with Multiple Protocols

```yaml
apiVersion: v1
kind: Service
metadata:
  name: multi-protocol-app
  annotations:
    tlb.io/protocol: "80:http,22:ssh,3389:rdp"
spec:
  type: LoadBalancer
  loadBalancerClass: tlb.io/cloudflare
  ports:
    - name: web
      port: 80
      targetPort: 8080
      protocol: TCP
    - name: ssh
      port: 22
      targetPort: 22
      protocol: TCP
    - name: rdp
      port: 3389
      targetPort: 3389
      protocol: TCP
  selector:
    app: my-app
```

### Single Protocol Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: web-app
  annotations:
    tlb.io/protocol: "http"
spec:
  type: LoadBalancer
  loadBalancerClass: tlb.io/cloudflare
  ports:
    - port: 80
      targetPort: 8080
  selector:
    app: web-app
```

### Cloudflare Tunnel with Custom DNS

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-app
  annotations:
    tlb.io/dns: "app.example.com,api.example.com"
    tlb.io/protocol: "https"
spec:
  type: LoadBalancer
  loadBalancerClass: tlb.io/cloudflare
  ports:
    - port: 443
      targetPort: 8443
  selector:
    app: my-app
```

This example will:

1. Create a Cloudflare tunnel for the service
2. Automatically create CNAME records for `app.example.com` and `api.example.com` pointing to the tunnel hostname
3. Configure the tunnel to forward HTTPS traffic to the service on port 8443
4. Update the Service's load balancer status with both custom hostnames

## Limitations

- **Tunnel class provider transitions are not supported**: Switching a tunnel class from one provider to another (e.g.,
  from Cloudflare to Netbird) is not supported. This is because the controller loses access to the credentials needed to
  clean up resources from the previous provider. If you need to change providers, delete the tunnel class and recreate
  it with the new provider configuration.
- DNS management is only available for Cloudflare provider

## Service annotations

- `tlb.io/dns`: A comma-separated list of DNS names to assign to the tunnel. The semantics of this may vary slightly by
  the tunneling provider.
  - **Cloudflare**: If set, and the Cloudflare API token can edit the corresponding DNS Zone, corresponding CNAME
    records are created. However, the `loadBalancer` status in the service will continue to use the Cloudflare Tunnel
    name (e.g. `<uuid>.cfargotunnel.com`) unless the `loadBalancer` status will use the specified DNS names. For
    Cloudflare tunnels, the controller will automatically create CNAME records pointing to the tunnel hostname if the
    zones are managed by the same Cloudflare account.
- `tlb.io/protocol`: Specifies the protocol for traffic forwarding. Supports port-specific mapping (e.g.,
  `"80:http,22:ssh,3389:rdp"`) or a single protocol for all ports (e.g., `"http"`). Supported protocols include `http`,
  `https`, `tcp`, `udp`, `ssh`, and `rdp`. If not specified, the protocol is automatically detected based on port names,
  well-known ports, or defaults to `tcp`/`udp`. Only used by the Cloudflare provider.
- `tlb.io/replicas`: The number of replicas to create for the tunnel. This is useful for services that require high
  availability or load balancing. The operator will create the specified number of tunnels.
- `tlb.io/topology-key`: A topology key that is used for spreading multiple tunnels across nodes. Defaults to
  `kubernetes.io/hostname`.
- `tlb.io/node-selector`: A comma-separated list of node labels to select nodes for the tunnel. This is useful for
  targeting specific nodes in your cluster.

## Controller labels

The following labels are used by the controller on resources it creates:

- `controller.tlb.io/for-service`: Added to resources to remember what `Service` they were created for.
- `controller.tlb.io/for-tunnel-class`: Added to resources to remember what `(Cluster)TunnelClass` they were created
  for.
- `controller.tlb.io/provider`: The name of the tunnel provider that the resource was created for.
- `controller.tlb.io/secret-version`: Added to Pod templates to include the resource version of the tunnel credentials
  secret. This ensures that when the secret is updated, the deployment will automatically rotate the pods to pick up the
  new credentials.

## Controller finalizers

The controller uses finalizers to ensure proper cleanup of resources:

- `tlb.io/finalizer`: Added to `TunnelClass` and `ClusterTunnelClass` resources to ensure proper cleanup of all
  associated tunnel resources (Deployments, StatefulSets, Secrets, etc.) when the tunnel class is deleted.
- `tlb.io/tunnel-cleanup`: Added to Services with matching `loadBalancerClass` to ensure proper cleanup of tunnel
  resources (both Kubernetes resources and external resources like Cloudflare tunnels) when the Service is deleted. This
  prevents race conditions and ensures that external resources are properly cleaned up even if the controller is
  temporarily unavailable during Service deletion.
- `tlb.io/cloudflare-tunnel`: Added to Cloudflare tunnel credential secrets to ensure proper cleanup of Cloudflare
  tunnels via the Cloudflare API when the secret is deleted. This ensures that external Cloudflare tunnel resources are
  properly removed and prevents orphaned tunnels in the Cloudflare dashboard.

## Cloudflare configuration

- To make use of the `tlb.io/dns` annotation, your Cloudflare API key must have edit permissions for the DNS zone you
  want to manage. Note that the Service's load balancer status will still only contain the Cloudflare tunnel hostname
  (e.g. `<uuid>.cfargotunnel.com`), even when this annotation is used.

## Development

- Always run `mise run ci` to test if CI will pass (formatting, compiling, linting, tests)
- Run `mise run fmt` to format code

## Work in progress

- [x] Basic controller loop
- [ ] Use Kubernetes Watch API to watch for changes
- [ ] Skip reconciling cluster-scoped tunnel class if same-named namespaced tunnel class exists
- [ ] Netbird support
  - [x] Creation of `StatefulSet` resources for matching `Service` resources
  - [x] Population of `Service.spec.loadBalancerStatus` with the first DNS name specified in the `tlb.io/dns` annotation
  - [x] Support for `tlb.io/dns`
  - [x] Support for `tlb.io/replicas`
  - [x] Support for `tlb.io/topology-key`
  - [x] Support for `tlb.io/node-selector`
  - [x] Cleanup on `Service` change or deletion
  - [x] Cleanup on `TunnelClass` deletion
  - [x] Persistent Netbird peer identity over Pod restarts (when `storageClass` is set)
  - [ ] Update `StatefulSet` on `Service` only when they actually changed
- [ ] Cloudflare support
  - [x] Creation of `Deployment` resources for matching `Service` resources
  - [x] Traffic forwarding to target services with protocol detection
  - [x] Support for `tlb.io/protocol` annotation with automatic protocol detection
  - [x] Support for multiple ports with different protocols via cloudflared ingress configuration
  - [x] Cleanup on `Service` change or deletion
  - [x] Cleanup on `TunnelClass` deletion
  - [x] DNS record management with automatic CNAME creation for `tlb.io/dns` hostnames
- [ ] Tailscale support
