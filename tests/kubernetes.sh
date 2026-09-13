#!/usr/bin/env bash
set -euo pipefail

if kind get clusters | grep -qx tlb-audit; then
  echo 'The dedicated tlb-audit cluster already exists; use tests/kubernetes.py with its kubeconfig.' >&2
  exit 1
fi
kubeconfig=$(mktemp)
cleanup() {
  if [[ ${1:-0} != 0 ]]; then
    kubectl --kubeconfig "$kubeconfig" --request-timeout=10s -n kube-system logs \
      -l app.kubernetes.io/instance=tlb-controller --all-containers --tail=100 || true
    kubectl --kubeconfig "$kubeconfig" --request-timeout=10s -n dns-audit get pods,services,ingresses || true
    kubectl --kubeconfig "$kubeconfig" --request-timeout=10s -n dns-audit logs dns-api --tail=50 || true
  fi
  timeout 120 kind delete cluster --name tlb-audit || true
  rm -f "$kubeconfig"
}
trap 'cleanup $?' EXIT

timeout 600 docker build -t tlb:audit .
timeout 120 docker build -t tlb-netbird-test:audit tests/netbird
timeout 240 kind create cluster --name tlb-audit --config tests/kind.yaml --image kindest/node:v1.37.0 --kubeconfig "$kubeconfig" --wait 120s
timeout 120 kind load docker-image tlb:audit tlb-netbird-test:audit --name tlb-audit
install_manifest=$(mktemp)
python3 tests/render_install.py tlb:audit 2 > "$install_manifest"
timeout 60 kubectl --kubeconfig "$kubeconfig" apply --server-side -f "$install_manifest"
rm -f "$install_manifest"
timeout 30 kubectl --kubeconfig "$kubeconfig" -n kube-system set env deployment/tlb-controller TLB_EXTERNAL_REFRESH_INTERVAL_SECONDS=7200
timeout 120 kubectl --kubeconfig "$kubeconfig" -n kube-system rollout status deployment/tlb-controller --timeout=90s
timeout 360 python3 tests/kubernetes.py --kubeconfig "$kubeconfig"
timeout 600 python3 tests/kubernetes_netbird.py --kubeconfig "$kubeconfig"
timeout 180 python3 tests/kubernetes_deployment.py --kubeconfig "$kubeconfig"

timeout 600 python3 tests/kubernetes_runtime.py --kubeconfig "$kubeconfig"
