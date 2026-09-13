#!/usr/bin/env python3
"""Lifecycle regression tests for the dedicated kind-tlb-audit cluster."""
import argparse
import json
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--kubeconfig', required=True)
args = parser.parse_args()
base = ['kubectl', '--kubeconfig', args.kubeconfig, '--request-timeout=10s']


def kubectl(*argv, obj=None):
    result = subprocess.run(base + list(argv), input=json.dumps(obj) if obj else None,
                            text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout


assert kubectl('config', 'current-context').strip() == 'kind-tlb-audit', 'dedicated test cluster required'


def apply(kind, name, spec=None, namespace=None, **extra):
    obj = dict(apiVersion='v1' if kind in ('Namespace', 'Secret', 'Service', 'PersistentVolumeClaim') else 'tlb.io/v1alpha1',
               kind=kind, metadata=dict(name=name), **extra)
    if namespace:
        obj['metadata']['namespace'] = namespace
    if spec is not None:
        obj['spec'] = spec
    kubectl('apply', '-f', '-', obj=obj)


def get(kind, namespace=None, selector=None):
    argv = ['get', kind, '-o', 'json']
    argv += ['-n', namespace] if namespace else ['-A']
    if selector:
        argv += ['-l', selector]
    return json.loads(kubectl(*argv))['items']


def wait(check, description, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            print('PASS', description, flush=True)
            return result
        time.sleep(1)
    raise AssertionError(description)


def patch(kind, name, namespace, body):
    kubectl('patch', kind, name, '-n', namespace, '--type=merge', '-p', json.dumps(body))


def service(namespace, name='api', finalizers=None, annotations=None, class_name='audit-public'):
    obj = dict(apiVersion='v1', kind='Service', metadata=dict(name=name, namespace=namespace,
               annotations={'tlb.io/replicas': '0', **(annotations or {})}, finalizers=finalizers or []),
               spec=dict(type='LoadBalancer', loadBalancerClass='tlb.io/' + class_name, ports=[dict(port=80)]))
    kubectl('apply', '-f', '-', obj=obj)


a, b = 'audit-a', 'audit-b'
for ns in (a, b):
    apply('Namespace', ns)
apply('Secret', 'audit-key', namespace='tlb-system', stringData={'key': 'test-only-not-a-provider-key'})
netbird = dict(netbird=dict(managementUrl='https://netbird.example.com',
               setupKeyRef=dict(name='audit-key', key='key', namespace='tlb-system'), storageClass='standard'))
apply('ClusterTunnelClass', 'audit-public', netbird)
apply('TunnelClass', 'audit-public', dict(cloudflare={}), a)
# Unrelated name labels in another namespace cannot veto lifecycle operations.
spoof = dict(apiVersion='v1', kind='Secret', metadata=dict(name='unrelated-labels', namespace=b,
    labels={'controller.tlb.io/for-tunnel-class': 'audit-public', 'controller.tlb.io/for-service': 'api'}))
kubectl('apply', '-f', '-', obj=spoof)
service(a, finalizers=['other.example/keep'])
service(b)
label = 'controller.tlb.io/binding-uid'
a_deploy = wait(lambda: get('deployments', a, label), 'namespaced class wins over cluster class')[0]
b_sts = wait(lambda: get('statefulsets', b, label), 'cluster class provisions in Service namespace')[0]
assert not get('statefulsets', a, label)

# A journal written before the Service finalizer must allow reconciliation to resume.
patch('services', 'api', a, {'metadata': {'finalizers': ['other.example/keep']}})
wait(lambda: 'tlb.io/tunnel-cleanup' in get('services', a)[0]['metadata'].get('finalizers', []),
     'persisted journal restores a missing Service finalizer')

# A legacy finalizer without a journal requires explicit recovery, even without visible workloads.
apply('TunnelClass', 'legacy', dict(cloudflare={}), b)
wait(lambda: any(c['metadata']['name'] == 'legacy' and 'tlb.io/finalizer' in c['metadata'].get('finalizers', [])
     for c in get('tunnelclasses', b)), 'legacy test class is finalized')
service(b, 'legacy', finalizers=['tlb.io/tunnel-cleanup'], class_name='legacy')
legacy_service = next(s for s in get('services', b) if s['metadata']['name'] == 'legacy')
time.sleep(3)
assert not get('secrets', 'tlb-system', 'controller.tlb.io/service-uid=' + legacy_service['metadata']['uid'])
kubectl('delete', 'tunnelclass', 'legacy', '-n', b, '--wait=false')
time.sleep(3)
assert any(c['metadata']['name'] == 'legacy' for c in get('tunnelclasses', b))
patch('services', 'legacy', b, {'metadata': {'finalizers': []}})
kubectl('delete', 'service', 'legacy', '-n', b, '--wait=false')
wait(lambda: not any(c['metadata']['name'] == 'legacy' for c in get('tunnelclasses', b)),
     'explicit legacy recovery releases class finalization')
assert not get('deployments', b, label)
assert a_deploy['metadata']['labels'][label] != b_sts['metadata']['labels'][label]
assert not get('statefulsets', 'tlb-system', label)
assert get('secrets', b, label)[0]['data']['setup-key'] == 'dGVzdC1vbmx5LW5vdC1hLXByb3ZpZGVyLWtleQ=='
print('PASS namespace isolation and central credential copy', flush=True)

service(a, 'invalid-mapping', annotations={'tlb.io/map-ports': 'https:80,ssh:22'})
invalid_service = next(s for s in get('services', a) if s['metadata']['name'] == 'invalid-mapping')
wait(lambda: any(e.get('regarding', {}).get('uid') == invalid_service['metadata']['uid']
     and e.get('type') == 'Warning' and e.get('reason') == 'ReconcileFailed'
     and 'Cloudflare accepts one port mapping' in e.get('note', '')
     for e in get('events.events.k8s.io', a)), 'invalid mapping produces a Warning Event on the Service')
assert not get('secrets', 'tlb-system', 'controller.tlb.io/service-uid=' + invalid_service['metadata']['uid'])
kubectl('delete', 'service', 'invalid-mapping', '-n', a, '--wait=false')

apply('Secret', 'invalid-tls', namespace=b, stringData={'tls.crt': 'incomplete'})
service(b, 'invalid-tls', annotations={'tlb.io/map-ports': '443/tls:80', 'tlb.io/tls-secret-name': 'invalid-tls'})
time.sleep(3)
tls_service = next(s for s in get('services', b) if s['metadata']['name'] == 'invalid-tls')
assert not get('secrets', 'tlb-system', 'controller.tlb.io/service-uid=' + tls_service['metadata']['uid'])
kubectl('delete', 'service', 'invalid-tls', '-n', b, '--wait=false')
kubectl('delete', 'secret', 'invalid-tls', '-n', b)
print('PASS malformed TLS Secret fails before binding creation', flush=True)

long_name = 'a' * 63
service(b, long_name, annotations={'tlb.io/replicas': '1', 'tlb.io/node-selector': 'audit.example/unschedulable=true'})
long_uid = next(s for s in get('services', b) if s['metadata']['name'] == long_name)['metadata']['uid']
long_selector = 'controller.tlb.io/service-uid=' + long_uid
long_pod = wait(lambda: get('pods', b, long_selector), 'long Service name produces a valid StatefulSet Pod')[0]
assert len(long_pod['metadata']['name']) <= 63
kubectl('delete', 'service', long_name, '-n', b, '--wait=false')
wait(lambda: not get('pods', b, long_selector) and not get('pvc', b, long_selector), 'long-name workload cleanup completes')

# Persist a labelled claim without starting a provider process.
claim = b_sts['spec']['volumeClaimTemplates'][0]
claim['metadata']['name'] = 'audit-retained'
claim['metadata']['namespace'] = b
claim['apiVersion'], claim['kind'] = 'v1', 'PersistentVolumeClaim'
kubectl('apply', '-f', '-', obj=claim)
claim_uid = get('pvc', b)[0]['metadata']['uid']
uid = b_sts['metadata']['uid']
patch('clustertunnelclass', 'audit-public', b, {'spec': {'netbird': {'image': 'netbirdio/netbird:test-update'}}})
wait(lambda: get('statefulsets', b, label)[0]['spec']['template']['spec']['containers'][0]['image'] == 'netbirdio/netbird:test-update',
     'mutable class image update reaches the existing StatefulSet')
assert get('statefulsets', b, label)[0]['metadata']['uid'] == uid
assert get('pvc', b)[0]['metadata']['uid'] == claim_uid
print('PASS mutable class updates preserve StatefulSet and PVC identities', flush=True)

patch('clustertunnelclass', 'audit-public', b, {'spec': {'netbird': {'managementUrl': 'invalid'}}})
time.sleep(3)
assert get('statefulsets', b, label)[0]['metadata']['uid'] == uid
assert get('pvc', b)[0]['metadata']['uid'] == claim_uid
patch('clustertunnelclass', 'audit-public', b, {'spec': {'netbird': {'managementUrl': 'https://netbird.example.com', 'size':'64Mi'}}})
time.sleep(3)
assert get('statefulsets', b, label)[0]['metadata']['uid'] == uid
assert get('pvc', b)[0]['metadata']['uid'] == claim_uid
print('PASS invalid configuration and immutable StatefulSet update preserve storage', flush=True)
patch('clustertunnelclass', 'audit-public', b, {'spec': {'netbird': {'size': None}}})

kubectl('delete', 'tunnelclass', 'audit-public', '-n', a, '--wait=false')
wait(lambda: not get('deployments', a, label), 'class deletion cleans only its own workloads')
wait(lambda: not get('tunnelclasses', a), 'foreign labels do not block class finalization')
assert any(secret['metadata']['name'] == 'unrelated-labels' for secret in get('secrets', b))
assert get('statefulsets', b, label)[0]['metadata']['uid'] == uid
# Removing a local class intentionally exposes the cluster class for this Service.
wait(lambda: get('statefulsets', a, label), 'Service rebinds to remaining cluster class')
assert 'other.example/keep' in get('services', a)[0]['metadata']['finalizers']

kubectl('delete', 'service', 'api', '-n', b, '--wait=false')
wait(lambda: not get('services', b), 'Service finalization completes')
wait(lambda: not get('statefulsets', b, label) and not get('pvc', b) and not get('secrets', b, label),
     'Service deletion cleans workloads, copied credentials and retained PVCs')
service(b)
new_sts = wait(lambda: get('statefulsets', b, label), 'same-name Service recreation provisions')[0]
assert new_sts['metadata']['uid'] != uid
assert new_sts['metadata']['name'] != b_sts['metadata']['name']
print('PASS recreated Service has independent UID identity', flush=True)

# Reject cross-namespace Secret access before a private journal is created.
apply('TunnelClass', 'audit-public', netbird, b)
foreign = 'blocked'
service(b, foreign)
time.sleep(3)
foreign_service = next(s for s in get('services', b) if s['metadata']['name'] == foreign)
assert not get('secrets', 'tlb-system', 'controller.tlb.io/service-uid=' + foreign_service['metadata']['uid'])
print('PASS namespaced Secret escape fails before journal or provider creation', flush=True)

# Remove test resources; preserve other finalizers until their owner explicitly removes them.
patch('services', 'api', a, {'metadata': {'finalizers': ['tlb.io/tunnel-cleanup']}})
for ns in (a, b):
    kubectl('delete', 'namespace', ns, '--wait=false')
wait(lambda: not get('secrets', 'tlb-system', 'controller.tlb.io/journal=true'), 'namespace deletion leaves no private journals', 90)
kubectl('delete', 'clustertunnelclass', 'audit-public', '--wait=false')
wait(lambda: not get('clustertunnelclasses'), 'cluster class finalizes after namespace cleanup')
kubectl('delete', 'secret', 'audit-key', '-n', 'tlb-system')
print('All Kubernetes lifecycle checks passed', flush=True)
