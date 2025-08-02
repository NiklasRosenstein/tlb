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

- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/) (planned)
- [NetBird](https://netbird.io/) (WIP)
- [Tailscale](https://tailscale.com/) (planned)

## Service annotations

- `tlb.io/dns`: A comma-separated list of DNS names to assign to the tunnel. The semantics of this may vary slightly by
  the tunneling service that is used and may be required by some (e.g. Cloudflare). If this is set, the Service's
  `loadBalancer` status will use the first name specified here. Defaults to `1`.
- `tlb.io/replicas`: The number of replicas to create for the tunnel. This is useful for services that require high
  availability or load balancing. The operator will create the specified number of tunnels.
- `tlb.io/topology-key`: A topology key that is used for spreading multiple tunnels across nodes. Defaults to
  `kubernetes.io/hostname`.
- `tlb.io/node-selector`: A comma-separated list of node labels to select nodes for the tunnel. This is useful for
  targeting specific nodes in your cluster.

## Known issues

### NetBird

- Pods created by the controller do not retain their identity. When they are re-scheduled, they will connect as new
  peers to the cluster and be assigned fresh IPs. It takes a while for the new IPs to propagate from the Pod, to the
  Service, to Ingresses and eventually, if you are using it, to be updated by external-dns and eventually make it
  through your computer's DNS cache.

## Work in progress

- [x] Basic controller loop
- [ ] Use Kubernetes Watch API to watch for changes
- [ ] Skip reconciling cluster-scoped tunnel class if same-named namespaced tunnel class exists
- [ ] Netbird support
  - [x] Creation of `Deployment` resources for matching `Service` resources
  - [x] Population of `Service.spec.loadBalancerStatus` with the first DNS name specified in the `tlb.io/dns` annotation
  - [x] Support for `tlb.io/dns`
  - [x] Support for `tlb.io/replicas`
  - [x] Support for `tlb.io/topology-key`
  - [x] Support for `tlb.io/node-selector`
  - [ ] Cleanup on `Service` change or deletion
  - [ ] Update `Deployment` on `Service` only when they actually changed
- [ ] Cloudflare support
- [ ] Tailscale support
