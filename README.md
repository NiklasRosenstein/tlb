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

The installation manifest runs the controller and tunnel workloads in `kube-system`:

```bash
git clone https://github.com/NiklasRosenstein/tlb.git
cd tlb
kubectl apply --server-side -f deploy/tlb.yaml
kubectl -n kube-system rollout status deployment/tlb-controller --timeout=120s
```

Use the manifest from the release tag you want to run. See the
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

## Releases

Run `deno run -A scripts/release.ts 0.8.0` from the repository root with a clean working tree. The script requires
authenticated `gh` and `codex` CLIs, generates release notes from commits and source changes since the preceding version
tag, checks Cargo, commits the version files, atomically pushes the branch and tag to `origin`, and creates a GitHub
release. Use `--agent=claude` to generate notes with an authenticated Claude CLI instead. Notes generation must succeed
before any version files change.

To publish a GitHub release for an existing local and remote tag, including retrying failed GitHub release creation, run
`deno run -A scripts/release.ts 0.7.0 --github-only`. This mode summarizes the tagged code and creates the GitHub
release; it does not commit or push. GitHub release creation is separate from the atomic Git push.
