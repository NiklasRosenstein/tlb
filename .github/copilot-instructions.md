# TLB - Tunnel LoadBalancer

TLB is a Kubernetes operator written in Rust that simplifies exposing Kubernetes services through various tunneling
providers (Cloudflare Tunnel, NetBird, planned Tailscale), eliminating the need for traditional LoadBalancers or complex
routing configurations.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected
information that does not match the info here.

## Working Effectively

### Prerequisites and Setup

- Ensure Rust 1.87+ is installed with rustfmt and clippy components:
  - `rustup component add rustfmt clippy` if needed
- Docker is available for containerization (note: limited by network access in some environments)
- Install mise task runner if available: `curl https://mise.run | sh` (may fail due to network restrictions)

### Core Development Commands

- **NEVER CANCEL**: All build and test commands should run to completion. Set timeouts appropriately.

#### Building the Project

- `cargo check` -- validates compilation without building binaries (~3 minutes first time, ~10 seconds incremental).
  NEVER CANCEL - Set timeout to 5+ minutes.
- `cargo build` -- builds debug binary (~41 seconds incremental). NEVER CANCEL - Set timeout to 3+ minutes.
- `cargo build --release` -- builds optimized binary (~2 minutes). NEVER CANCEL - Set timeout to 5+ minutes.

#### Testing

- `cargo test` -- runs all tests (~4 seconds, very limited test suite). NEVER CANCEL - Set timeout to 2+ minutes.
- Note: Project currently has minimal unit tests (only doc tests), focus on manual validation.

#### Code Quality

- `cargo fmt` -- formats code (~1 second)
- `cargo fmt --check` -- verifies formatting without changes
- `cargo clippy -- -D warnings` -- lints code with warnings as errors (~1-3 seconds)
  - Use `cargo clippy --fix --allow-dirty --allow-staged` to auto-fix all formatting issues (~7 seconds)
  - Do commit auto-fixes.
  - After auto-fix, `cargo clippy -- -D warnings` should pass with 0 warnings

#### CRD Management

- `cargo run crds` -- generates Kubernetes Custom Resource Definitions
- `cargo run crds > /tmp/crds.yaml` -- save generated CRDs to file
- `diff -u helm/tlb-controller/templates/crds/crds.yaml <(cargo run crds)` -- verify CRDs are up-to-date

#### Application Execution

- `cargo run` or `./target/debug/controller` -- runs the controller (requires Kubernetes cluster)
- `cargo run crds` -- generates and prints CRDs to stdout
- `cargo run -- --help` -- shows command help

### Alternative Build System (mise)

If mise is available, use these commands (may not work due to network restrictions):

- `mise run ci` -- full CI suite (format check, lint, test, build, CRD validation). NEVER CANCEL - Set timeout to 10+
  minutes.
- `mise run fmt` -- format all code (Rust + auxiliary files with deno)
- `mise run lint` -- lint all code
- `mise run build` -- build project
- `mise run test` -- run tests

### Docker Build

- `docker build -t tlb-test .` -- builds container (~2+ minutes). NEVER CANCEL - Set timeout to 10+ minutes.
- **NOTE**: May fail due to network access restrictions to cgr.dev registry.

## Validation

### Manual Validation Requirements

Since TLB is a Kubernetes controller, comprehensive end-to-end testing requires a Kubernetes cluster. However, you can
validate core functionality:

#### Controller Validation

- **ALWAYS** verify the controller binary runs and displays help correctly:
  - `./target/debug/controller --help`
  - Should show available commands: run, crds, help
- **ALWAYS** verify CRD generation works:
  - `./target/debug/controller crds | head -20`
  - Should output valid Kubernetes CRD YAML

#### Expected Failure Scenarios (Normal Behavior)

- Running `./target/debug/controller run` without Kubernetes should fail with:
  ```
  failed to create kube::Client: InferConfig(InferConfigError...
  ```
  - This is expected and indicates the controller is correctly trying to connect to Kubernetes

#### Compilation Validation

- **ALWAYS** run `cargo check` after making changes to verify no compilation errors
- **ALWAYS** run `cargo clippy --fix --allow-dirty --allow-staged` then check the diff to understand linting issues
- **ALWAYS** run `cargo test` even though test coverage is minimal

### End-to-End Scenarios (Requires Kubernetes)

If you have access to a Kubernetes cluster, validate these scenarios:

1. **TunnelClass Creation**: Apply examples from `examples/cloudflare.yaml` or `examples/netbird.yaml`
2. **Service Exposure**: Create a Service with `loadBalancerClass: tlb.io/cloudflare` or `tlb.io/netbird`
3. **Controller Operation**: Verify the controller creates tunnel Deployments/StatefulSets
4. **Cleanup**: Verify resources are properly cleaned up when Services are deleted

## Common Tasks

### Repository Structure Overview

```
/home/runner/work/tlb/tlb/
├── Cargo.toml              # Rust project configuration
├── mise.toml               # Task runner configuration
├── src/                    # Rust source code
│   ├── main.rs            # Controller entry point
│   ├── lib.rs             # Library code
│   ├── controller.rs      # Main controller logic
│   ├── cloudflare.rs      # Cloudflare provider
│   ├── netbird.rs         # NetBird provider
│   └── crds.rs            # Custom Resource Definitions
├── examples/              # Example configurations
│   ├── cloudflare.yaml    # Cloudflare tunnel example
│   └── netbird.yaml       # NetBird tunnel example
├── helm/                  # Kubernetes deployment charts
│   └── tlb-controller/    # Helm chart for controller
├── scripts/               # Utility scripts (TypeScript/Deno)
├── .github/workflows/     # CI/CD pipelines
└── Dockerfile            # Container build configuration
```

### Key Files to Monitor

- When modifying CRD structs in `src/crds.rs`, always run `cargo run crds` and verify output
- When changing controller logic in `src/controller.rs`, test compilation with `cargo check`
- When modifying provider logic in `src/cloudflare.rs` or `src/netbird.rs`, check for lint issues
- Helm chart versions in `helm/tlb-controller/Chart.yaml` should match `Cargo.toml` version

### Code Quality Checklist

Before committing changes:

1. `cargo fmt` -- format code
2. `cargo clippy --fix --allow-dirty --allow-staged` -- fix auto-correctable linting issues
3. `cargo check` -- verify compilation
4. `cargo test` -- run tests (minimal but ensures doc tests pass)
5. `cargo run crds > /tmp/crds.yaml && diff -u helm/tlb-controller/templates/crds/crds.yaml /tmp/crds.yaml` -- verify
   CRDs are up-to-date

### Known Issues and Workarounds

- **Linting**: Project currently has exactly 46 clippy warnings about string formatting in `src/cloudflare.rs` (42
  issues) and `src/netbird.rs` (4 issues)
  - Auto-fixable with `cargo clippy --fix --allow-dirty --allow-staged`
  - DO NOT commit auto-fixes during exploration - use `git checkout .` to revert
- **Network Restrictions**: mise installation and Docker registry access may fail in restricted environments
  - Use direct cargo commands as fallback when mise is unavailable
- **Test Coverage**: Limited unit test coverage (only 1 doc test passes); rely on compilation checks and manual
  validation
- **Kubernetes Dependency**: Controller requires valid kubeconfig or in-cluster configuration to run
  - Expect startup failures without Kubernetes - this is normal behavior
- **Docker Build**: May fail due to `cgr.dev/chainguard/static` registry access restrictions

## Important Notes

### Timing Expectations

- **First build**: `cargo check` ~3 minutes, `cargo build` ~41 seconds, `cargo build --release` ~2 minutes
- **Incremental builds**: Much faster, typically under 10 seconds for minor changes
- **CI Pipeline**: Runs in ~10 minutes according to GitHub workflow timeout

### Development Workflow

1. Make code changes
2. Run `cargo check` to verify compilation (~10 seconds incremental)
3. Run `cargo fmt` to format code (~1 second)
4. Run `cargo clippy --fix --allow-dirty --allow-staged` for linting (~7 seconds)
5. Run `cargo test` to verify tests still pass (~4 seconds)
6. If CRDs changed, verify with `cargo run crds` and diff check
7. Test manually with `./target/debug/controller --help` and `./target/debug/controller crds`

Do make sure to format files before committing, and always run `cargo check` to ensure no compilation errors.

### Quick Validation Checklist

Use this checklist to verify the instructions work correctly:

```bash
# 1. Components check
rustup component list --installed | grep -E "(rustfmt|clippy)"

# 2. Build verification
cargo check && cargo build

# 3. Test execution
cargo test

# 4. Format verification
cargo fmt --check

# 5. Linting state verification (should fail with 46 errors)
cargo clippy -- -D warnings 2>&1 | grep "46 previous errors"

# 6. Controller functionality
./target/debug/controller --help
./target/debug/controller crds | head -10

# 7. Expected failure test (should fail with kube client error)
timeout 5 ./target/debug/controller run 2>&1 | grep "failed to create kube::Client"

# 8. CRD verification
cargo run crds > /tmp/crds.yaml && diff -u helm/tlb-controller/templates/crds/crds.yaml /tmp/crds.yaml

# 9. Auto-fix test (then revert)
cargo clippy --fix --allow-dirty --allow-staged && cargo clippy -- -D warnings && git checkout .
```

### CI Compatibility

The project uses GitHub Actions with specific requirements:

- Rust 1.87 with rustfmt and clippy components
- Timeout set to 10 minutes for CI
- mise for task orchestration in CI environment
- Docker builds with multi-stage builds using Alpine/musl

## File Version

This file was last updated on 2025-08-09 and contains comprehensive instructions for working with the TLB repository.
