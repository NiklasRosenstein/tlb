# TLB development

TLB is a Rust Kubernetes controller for Cloudflare and NetBird tunnels.

## Toolchain and checks

Use the versions in `rust-toolchain.toml` and `mise.toml`. Run `mise install` to install the development tools. Run
`mise run ci` for formatting, linting, tests, builds, and generated CRD verification. Builds and tests need bounded
timeouts: allow up to ten minutes for a cold build.

Direct Cargo checks:

```bash
cargo fmt --all --check
cargo check --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo build --locked --all-features
./target/debug/controller --help
```

Run `deno check scripts`, `deno lint scripts`, and `mise run check-manifests` for auxiliary changes.

## Generated resources

`src/crds.rs` defines the custom resources. Generate the CRDs and installation bundle with `mise run update-crds` and
verify them with `mise run check-crds-uptodate`. Keep the Cargo version and deployment image tag consistent.

Controller behavior lives in `src/controller.rs`; provider implementations live in `src/cloudflare.rs` and
`src/netbird.rs`. Shared configuration and helpers live in `src/lib.rs`.

## Validation boundaries

Unit tests and compilation do not establish Kubernetes reconciliation correctness. Lifecycle changes need coverage for
creation, repeated reconciliation, partial failures, deletion, and namespace isolation. End-to-end checks require a
dedicated Kubernetes cluster and provider credentials. Use the installation manifest’s ServiceAccount to exercise RBAC.

Do not run `scripts/release.ts` for validation: it commits, tags, and pushes a release.
