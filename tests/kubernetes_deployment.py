#!/usr/bin/env python3
"""Deployment and API guard checks for the dedicated kind-tlb-audit cluster."""
import argparse
import json
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--kubeconfig', required=True)
args = parser.parse_args()
base = ['kubectl', '--kubeconfig', args.kubeconfig, '--request-timeout=10s']


def run(*argv, obj=None, success=True):
    result = subprocess.run(base + list(argv), input=json.dumps(obj) if obj else None,
                            text=True, capture_output=True, timeout=30)
    assert (result.returncode == 0) == success, result.stderr
    return result.stdout if success else result.stderr


assert run('config', 'current-context').strip() == 'kind-tlb-audit'
ns = 'kube-system'
obj = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'guard-test', 'namespace': ns},
       'data': {'owned': 'initial'}}
run('create', '-f', '-', obj=obj)
original = json.loads(run('get', 'configmap', 'guard-test', '-n', ns, '-o', 'json'))
run('patch', 'configmap', 'guard-test', '-n', ns, '--type=merge', '-p', '{"data":{"foreign":"preserve"}}')
obj['metadata'].update({key: original['metadata'][key] for key in ('uid', 'resourceVersion')})
obj['data']['owned'] = 'updated'
error = run('apply', '--server-side', '--force-conflicts', '--field-manager=tlb-guard-test', '-f', '-', obj=obj, success=False)
assert 'Conflict' in error or 'modified' in error
current = json.loads(run('get', 'configmap', 'guard-test', '-n', ns, '-o', 'json'))
obj['metadata']['resourceVersion'] = current['metadata']['resourceVersion']
obj['metadata']['uid'] = '00000000-0000-0000-0000-000000000001'
error = run('apply', '--server-side', '--force-conflicts', '--field-manager=tlb-guard-test', '-f', '-', obj=obj, success=False)
assert 'uid' in error.lower()
obj['metadata']['uid'] = current['metadata']['uid']
run('apply', '--server-side', '--force-conflicts', '--field-manager=tlb-guard-test', '-f', '-', obj=obj)
current = json.loads(run('get', 'configmap', 'guard-test', '-n', ns, '-o', 'json'))
assert current['data'] == {'owned': 'updated', 'foreign': 'preserve'}
run('delete', 'configmap', 'guard-test', '-n', ns)
print('PASS forced apply preserves UID/RV guards and foreign fields', flush=True)


def lease():
    return json.loads(run('get', 'lease', 'tlb-controller', '-n', ns, '-o', 'json'))


def pods():
    return json.loads(run('get', 'pods', '-n', ns, '-l', 'app.kubernetes.io/instance=tlb-controller', '-o', 'json'))['items']


def ready_count():
    return sum(any(c['type'] == 'Ready' and c['status'] == 'True'
                   for c in p.get('status', {}).get('conditions', [])) for p in pods())


run('delete', 'crd', 'tunnelclasses.tlb.io', '--wait=true', '--timeout=30s')
try:
    deadline = time.monotonic() + 60
    while ready_count() == 2 and time.monotonic() < deadline:
        time.sleep(1)
    assert ready_count() < 2, 'leader stayed ready without a required CRD'
finally:
    run('apply', '-f', 'deploy/crds.yaml')
deadline = time.monotonic() + 60
while ready_count() != 2 and time.monotonic() < deadline:
    time.sleep(1)
assert ready_count() == 2, 'readiness did not recover after CRD restoration'
print('PASS missing primary watch resource clears readiness and restoration recovers it', flush=True)

initial = lease()['spec']['holderIdentity']
active = []
for pod in pods():
    logs = run('logs', pod['metadata']['name'], '-n', ns)
    if 'acquired controller leadership' in logs:
        active.append(pod['metadata']['name'])
assert len(active) == 1, 'exactly one replica must have started the controller loops'
run('delete', 'pod', active[0], '-n', ns, '--wait=false')
deadline = time.monotonic() + 75
while time.monotonic() < deadline:
    if lease()['spec']['holderIdentity'] != initial:
        break
    time.sleep(1)
else:
    raise AssertionError('standby did not take over the expired Lease')
print('PASS standby takes over after leader termination', flush=True)
run('rollout', 'status', 'deployment', '-n', ns, '--timeout=60s')
print('PASS two-replica deployment returns to readiness after failover', flush=True)
