# TLB — Tunnel LoadBalancer

TLB exposes Kubernetes Services through **Cloudflare Tunnel** and **NetBird**. Select a tunnel class on a `LoadBalancer`
Service; the controller runs the tunnel workloads and publishes their addresses in Service status.

**[Documentation](https://niklasrosenstein.github.io/tlb/)** ·
[Quickstart](https://niklasrosenstein.github.io/tlb/start/quickstart/) ·
[Configuration reference](https://niklasrosenstein.github.io/tlb/reference/classes/)

## Providers

| Provider                | Use case                                                                        |
| ----------------------- | ------------------------------------------------------------------------------- |
| Cloudflare Quick Tunnel | Try an HTTP application with a generated public hostname and no API credentials |
| Cloudflare API tunnel   | Publish an application on a domain in your Cloudflare account                   |
| NetBird                 | Reach TCP and UDP Services through your private peer network                    |

## Install

The Helm chart lives in this repository:

```bash
git clone https://github.com/NiklasRosenstein/tlb.git
cd tlb
helm upgrade --install tlb-controller ./helm/tlb-controller \
  --namespace tlb-system --create-namespace \
  --wait --timeout 120s
```

Use a matching chart and controller image. See the
[installation guide](https://niklasrosenstein.github.io/tlb/start/installation/) for image overrides, controller
settings, and cleanup order. The published docs describe the development version; release-specific source and examples
are available in the repository's release tags.

## Configure a tunnel

A class defines a provider; a Service selects it with `loadBalancerClass: tlb.io/<class-name>`. For example, this class
selects account-free Cloudflare Quick mode:

```yaml
apiVersion: tlb.io/v1alpha1
kind: TunnelClass
metadata:
  name: quick
  namespace: default
spec:
  cloudflare: {}
```

The [first-tunnel walkthrough](https://niklasrosenstein.github.io/tlb/start/quickstart/) includes a complete
application, Service, connection check, and cleanup. Use the
[Cloudflare](https://niklasrosenstein.github.io/tlb/guides/cloudflare/) or
[NetBird](https://niklasrosenstein.github.io/tlb/guides/netbird/) guide for provider credentials and configuration.

## Development

Rust and Deno versions are pinned through mise and `rust-toolchain.toml`:

```bash
mise install
mise run fmt
mise run ci
```

The Astro Starlight documentation lives in `docs/`. Use the Node version in `docs/.node-version`:

```bash
npm --prefix docs ci
npm --prefix docs run dev
npm --prefix docs run check
npm --prefix docs run build
```

See [docs/README.md](docs/README.md) for authoring and publishing, and
[development documentation](https://niklasrosenstein.github.io/tlb/operations/development/) for controller and
Kubernetes tests.
