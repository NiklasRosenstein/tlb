# TLB - Tunnel LoadBalancer

TLB is a Kubernetes operator that simplifies exposing Kubernetes services through various tunneling providers,
eliminating the need for traditional LoadBalancers or complex routing configurations.

## 🚀 Quick Start

### 1. Define a TunnelClass

Create a `TunnelClass` or `ClusterTunnelClass` resource for your chosen provider:

```yaml
apiVersion: tlb.io/v1alpha1
kind: ClusterTunnelClass
metadata:
  name: netbird
spec:
  netbird:
    managementURL: https://netbird.example.com
    setupKeyRef:
      name: netbird-setup-key
      namespace: tlb-system
      key: SETUP_KEY
```

### 2. Configure Your Service

Reference the tunnel class in your Service and configure it with annotations:

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

> **Note:** If both `TunnelClass` and `ClusterTunnelClass` exist with the same name, the `TunnelClass` takes precedence.

## 🌐 Supported Providers

| Provider                                                                                        | Status     | DNS Management     | Protocols                  | High Availability    |
| ----------------------------------------------------------------------------------------------- | ---------- | ------------------ | -------------------------- | -------------------- |
| [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/) | ✅ Working | ✅ Automatic CNAME | HTTP/HTTPS/TCP/UDP/SSH/RDP | ✅ Multiple replicas |
| [NetBird](https://netbird.io/)                                                                  | ✅ Working | ❌ Not supported   | TCP/UDP                    | ✅ Multiple replicas |
| [Tailscale](https://tailscale.com/)                                                             | 🔄 Planned | ❌ Not supported   | TCP/UDP                    | 🔄 Planned           |

## 📝 Service Annotations

Configure your tunnels using these Service annotations:

| Annotation             | Description                              | Cloudflare             | NetBird                      | Example                                  |
| ---------------------- | ---------------------------------------- | ---------------------- | ---------------------------- | ---------------------------------------- |
| `tlb.io/dns`           | Comma-separated DNS names for the tunnel | ✅ Auto CNAME creation | ✅ Sets load balancer status | `"app.example.com,api.example.com"`      |
| `tlb.io/protocol`      | Protocol mapping for traffic forwarding  | ✅ Per-port or global  | ❌ Not used                  | `"80:http,22:ssh,3389:rdp"` or `"https"` |
| `tlb.io/replicas`      | Number of tunnel replicas for HA         | ✅ Supported           | ✅ Supported                 | `"3"`                                    |
| `tlb.io/topology-key`  | Topology key for spreading replicas      | ✅ Supported           | ✅ Supported                 | `"topology.kubernetes.io/zone"`          |
| `tlb.io/node-selector` | Node labels for tunnel placement         | ✅ Supported           | ✅ Supported                 | `"zone=us-west,type=worker"`             |

### Annotation Details

#### `tlb.io/dns`

- **Cloudflare**: Creates CNAME records automatically if API token has DNS permissions
- **NetBird**: Sets Netbird extra DNS labels for the peer(s). The Service's load balancer status is set to the IP
  addresses of all replica peers, unless the `announceType` is set to `DNS`. This is because public DNS servers will not
  be able to resolve the Netbird peer extra DNS labels.
- **Format**: Comma-separated list of hostnames

#### `tlb.io/protocol`

- **Cloudflare only**: Configures traffic forwarding protocols
- **Supported protocols**: `http`, `https`, `tcp`, `udp`, `ssh`, `rdp`
- **Format**:
  - Port-specific: `"80:http,22:ssh,3389:rdp"`
  - Global: `"https"` (applies to all ports)
- **Auto-detection**: Based on port names, well-known ports, or defaults to `tcp`/`udp`

#### `tlb.io/replicas`

- **Default**: `"1"`
- **Purpose**: Creates multiple tunnel instances for high availability

#### `tlb.io/topology-key`

- **Default**: `"kubernetes.io/hostname"`
- **Purpose**: Controls how replicas are distributed across nodes
- **Common values**: `"kubernetes.io/hostname"`, `"topology.kubernetes.io/zone"`

#### `tlb.io/node-selector`

- **Purpose**: Restricts tunnel pods to specific nodes
- **Format**: Comma-separated key=value pairs
- **Example**: `"disktype=ssd,zone=us-west-1"`

## 💡 Examples

### Cloudflare Tunnel Examples

#### Multi-Protocol Service

Perfect for applications that need multiple protocol support:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: multi-protocol-app
  annotations:
    tlb.io/protocol: "80:http,22:ssh,3389:rdp"
    tlb.io/dns: "myapp.example.com"
    tlb.io/replicas: "2"
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

#### Simple Web Application

Basic HTTP service with custom DNS:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: web-app
  annotations:
    tlb.io/protocol: "http"
    tlb.io/dns: "webapp.example.com"
spec:
  type: LoadBalancer
  loadBalancerClass: tlb.io/cloudflare
  ports:
    - port: 80
      targetPort: 8080
  selector:
    app: web-app
```

#### High-Availability HTTPS Service

Production-ready setup with multiple replicas and DNS:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: api-service
  annotations:
    tlb.io/dns: "api.example.com,api-backup.example.com"
    tlb.io/protocol: "https"
    tlb.io/replicas: "3"
    tlb.io/topology-key: "topology.kubernetes.io/zone"
spec:
  type: LoadBalancer
  loadBalancerClass: tlb.io/cloudflare
  ports:
    - port: 443
      targetPort: 8443
  selector:
    app: api-app
```

### NetBird Examples

#### Basic Service Exposure

Simple service exposure through NetBird:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: internal-app
  annotations:
    tlb.io/dns: "internal.netbird.local"
    tlb.io/replicas: "1"
spec:
  type: LoadBalancer
  loadBalancerClass: tlb.io/netbird
  ports:
    - port: 80
      targetPort: 8080
  selector:
    app: internal-app
```

## ⚠️ Important Limitations

| Limitation             | Description                                                                 | Workaround                                      |
| ---------------------- | --------------------------------------------------------------------------- | ----------------------------------------------- |
| **Provider Switching** | Cannot switch tunnel classes between providers (e.g., Cloudflare → NetBird) | Delete and recreate tunnel class                |
| **DNS Management**     | Only available for Cloudflare provider                                      | Use external DNS management for other providers |

## ⚙️ Provider-Specific Configuration

### Cloudflare Setup

For Tunnel management:

1. **API Token Requirements**: Your Cloudflare API token must have:
   - `Account:Cloudflare Tunnel:Edit` permissions

For DNS record management with the `tlb.io/dns` annotation:

1. **API Token Requirements**: Your Cloudflare API token must have:
   - `Zone:Zone:Read` permissions
   - `Zone:DNS:Edit` permissions for target zones

2. **DNS Behavior**:
   - CNAME records are automatically created pointing to the tunnel hostname
   - Service load balancer status shows the tunnel hostname (`<uuid>.cfargotunnel.com`), unless `tlb.io/dns` is set, at
     least one DNS CNAME record could be successfully created and the Cloudflare TunnelClass spec does not override the
     `announceType` to `Internal`.

### NetBird Setup

1. **Management URL**: Point to your NetBird management server
2. **Setup Key**: Generate a reusable setup key in NetBird dashboard

## 🏷️ Controller Labels & Finalizers

### Labels & Annotations Applied by Controller

The controller adds these labels to resources it manages:

| Label / Annotation                      | Purpose                                                       | Applied To           |
| --------------------------------------- | ------------------------------------------------------------- | -------------------- |
| `controller.tlb.io/for-service`         | Links resources to originating Service                        | All tunnel resources |
| `controller.tlb.io/for-tunnel-class`    | Links resources to TunnelClass                                | All tunnel resources |
| `controller.tlb.io/provider`            | Identifies the tunnel provider                                | All tunnel resources |
| `controller.tlb.io/secret-version`      | Triggers pod rotation on credential updates                   | Pod templates        |
| `controller.tlb.io/last-observed-state` | Stores last observed state about a resource to detect changes | `Service`            |

### Finalizers for Safe Cleanup

| Finalizer                  | Applied To                     | Purpose                                          |
| -------------------------- | ------------------------------ | ------------------------------------------------ |
| `tlb.io/finalizer`         | TunnelClass/ClusterTunnelClass | Ensures cleanup of all tunnel resources          |
| `tlb.io/tunnel-cleanup`    | Services                       | Prevents race conditions during service deletion |
| `tlb.io/cloudflare-tunnel` | Cloudflare credential secrets  | Ensures Cloudflare API cleanup                   |

## 🛠️ Development

### Quick Commands

```bash
# Run full CI suite (format, compile, lint, test)
mise run ci

# Format code
mise run fmt
```

### Development Workflow

1. Make your changes
2. Run `mise run fmt` to format code
3. Run `mise run ci` to ensure CI will pass
4. Submit your pull request

## 🗺️ Roadmap

### Core Features

- [x] **Basic controller loop**
- [ ] **Kubernetes Watch API** - Real-time change detection
- [ ] **Namespace precedence** - Skip cluster-scoped classes when namespaced exists

### Cloudflare Tunnel Support

- [x] ✅ **Deployment creation** for matching services
- [x] ✅ **Traffic forwarding** with protocol detection
- [x] ✅ **Multi-protocol support** via `tlb.io/protocol` annotation
- [x] ✅ **DNS management** with automatic CNAME creation
- [x] ✅ **Resource cleanup** on service/tunnel class changes
- [x] ✅ **High availability** support

### NetBird Support

- [x] ✅ **StatefulSet creation** for matching services
- [x] ✅ **Load balancer status** population
- [x] ✅ **DNS annotation** support
- [x] ✅ **Replica management** for high availability
- [x] ✅ **Topology and node selection** support
- [x] ✅ **Resource cleanup** on changes
- [x] ✅ **Persistent peer identity** with storage classes
- [ ] 🔄 **Selective updates** - Only update when services actually change

### Tailscale Support

- [ ] 🔄 **Basic integration** - Initial Tailscale support
- [ ] 🔄 **High availability** - Multiple replica support
- [ ] 🔄 **Node selection** - Topology-aware deployment

### Legend

- ✅ **Completed**
- 🔄 **In Progress**
- ❌ **Not Planned**
