#!/usr/bin/env bash
set -euo pipefail
if kind get clusters | grep -qx tlb-netbird-e2e; then
  echo 'The dedicated tlb-netbird-e2e cluster already exists.' >&2
  exit 1
fi
work=$(mktemp -d /tmp/tlb-netbird-e2e-XXXXXX)
cleanup() {
  timeout 120 kind delete cluster --name tlb-netbird-e2e || true
  rm -f "$work/kubeconfig" "$work/install.yaml"
}
trap cleanup EXIT
timeout 600 docker build -t tlb:netbird-e2e .
timeout 240 kind create cluster --name tlb-netbird-e2e --image kindest/node:v1.37.0 --kubeconfig "$work/kubeconfig" --wait 120s
timeout 120 kind load docker-image tlb:netbird-e2e --name tlb-netbird-e2e
python3 tests/render_install.py tlb:netbird-e2e 1 > "$work/install.yaml"
timeout 60 kubectl --kubeconfig "$work/kubeconfig" apply --server-side -f "$work/install.yaml"
timeout 150 kubectl --kubeconfig "$work/kubeconfig" -n kube-system rollout status deployment/tlb-controller --timeout=120s
timeout 900 python3 tests/netbird.py --kubeconfig "$work/kubeconfig" --diagnostics "$work/logs"
