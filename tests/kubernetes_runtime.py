#!/usr/bin/env python3
"""Runtime Secret and policy checks in the dedicated kind-tlb-audit cluster."""
import argparse
import base64
import json
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--kubeconfig', required=True)
args = parser.parse_args()
base = ['kubectl', '--kubeconfig', args.kubeconfig, '--request-timeout=10s']


def run(*argv, obj=None):
    result = subprocess.run(base + list(argv), input=json.dumps(obj) if obj is not None else None,
                            capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, result.stderr
    return result.stdout


def apply(kind, name, namespace=None, **fields):
    obj = dict(apiVersion='tlb.io/v1alpha1' if kind.endswith('TunnelClass') else 'v1', kind=kind,
               metadata=dict(name=name), **fields)
    if namespace:
        obj['metadata']['namespace'] = namespace
    run('apply', '-f', '-', obj=obj)


def get(kind, namespace, selector=None):
    argv = ['get', kind, '-n', namespace, '-o', 'json']
    if selector:
        argv += ['-l', selector]
    return json.loads(run(*argv))['items']


def wait(check, message, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            print('PASS', message, flush=True)
            return value
        time.sleep(1)
    raise AssertionError(message)


def patch(kind, name, namespace, body):
    run('patch', kind, name, '-n', namespace, '--type=merge', '-p', json.dumps(body))


def configure(namespace, unsafe):
    run('-n', 'kube-system', 'set', 'env', 'deployment/tlb-controller',
        'TLB_WORKLOAD_NAMESPACE=' + namespace, 'TLB_ALLOW_UNSAFE_WORKLOAD_OVERRIDES=' + str(unsafe).lower())
    run('-n', 'kube-system', 'rollout', 'status', 'deployment/tlb-controller', '--timeout=30s')
    # Wait for the Lease to settle after replacing the elected controller.
    time.sleep(17)


def encoded(value):
    return base64.b64encode(value.encode()).decode()


def assert_clean(namespace, selector):
    return not any(get(kind, namespace, selector) for kind in ('pods', 'statefulsets', 'deployments', 'secrets', 'pvc'))


assert run('config', 'current-context').strip() == 'kind-tlb-audit'
for workload_ns in ('kube-system', 'tlb-tunnels'):
    if workload_ns != 'kube-system':
        apply('Namespace', workload_ns)
    configure(workload_ns, False)
    app = 'runtime-app'
    apply('Namespace', app)
    apply('Secret', 'source-key', app, stringData={'key': 'first', 'unneeded': 'never-copy'})
    apply('Secret', 'source-tls', app, stringData={'tls.crt': 'cert-one', 'tls.key': 'private-one', 'unneeded': 'never-copy'})
    spec = {'netbird': {'managementUrl': 'https://netbird.example.com', 'setupKeyRef': {'name': 'source-key', 'key': 'key'},
                        'storageClass': 'standard'}}
    apply('TunnelClass', 'runtime', app, spec=spec)
    apply('Service', 'runtime', app, spec={'type': 'LoadBalancer', 'loadBalancerClass': 'tlb.io/runtime', 'ports': [{'port': 80}]})
    patch('service', 'runtime', app, {'metadata': {'annotations': {'tlb.io/replicas': '0', 'tlb.io/map-ports': '443/tls:80',
                                                               'tlb.io/tls-secret-name': 'source-tls'}}})
    uid = get('services', app)[0]['metadata']['uid']
    selector = 'controller.tlb.io/service-uid=' + uid
    sts = wait(lambda: get('statefulsets', workload_ns, selector), 'runtime workload placement')[0]
    secrets = wait(lambda: len(get('secrets', workload_ns, selector)) == (3 if workload_ns == 'kube-system' else 2),
                   'journal and runtime copies are present')
    copies = [s for s in get('secrets', workload_ns, selector) if s['metadata']['labels'].get('controller.tlb.io/journal') != 'true']
    assert len(copies) == 2
    tls = next(s for s in copies if s.get('type') == 'kubernetes.io/tls')
    key = next(s for s in copies if 'setup-key' in s.get('data', {}))
    assert set(tls['data']) == {'tls.crt', 'tls.key'}
    assert key['data'] == {'setup-key': encoded('first')}
    owner = sts['metadata']['ownerReferences'][0]
    assert owner['kind'] == ('Secret' if workload_ns == 'kube-system' else 'ConfigMap')
    assert all(s['metadata']['ownerReferences'] == [owner] for s in copies)
    pod_spec = sts['spec']['template']['spec']
    assert not pod_spec['automountServiceAccountToken']
    assert pod_spec['containers'][0]['securityContext']['capabilities']['add'] == ['NET_ADMIN']
    assert any(e['name'] == 'NB_DISABLE_EBPF_WG_PROXY' and e['value'] == 'true' for e in pod_spec['containers'][0]['env'])
    assert not get('secrets', app, 'controller.tlb.io/binding-uid')

    apply('Secret', 'source-tls', app, stringData={'tls.crt': 'cert-two', 'tls.key': 'private-two'})
    apply('Secret', 'source-key', app, stringData={'key': 'second'})
    wait(lambda: any(s.get('data', {}).get('tls.crt') == encoded('cert-two') for s in get('secrets', workload_ns, selector)),
         'TLS source updates reach the runtime copy')
    wait(lambda: any(s.get('data', {}).get('setup-key') == encoded('second') for s in get('secrets', workload_ns, selector)),
         'credential rotation reaches the runtime copy')
    wait(lambda: get('statefulsets', workload_ns, selector)[0]['spec']['template']['metadata']['annotations'].get(
        'controller.tlb.io/tls-secret-version') != sts['spec']['template']['metadata']['annotations'].get('controller.tlb.io/tls-secret-version'),
        'TLS rotation changes the Pod template')

    # A Pod referencing TLS protects the copy during a TLS-to-plaintext rollout.
    reader = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'tls-reader', 'namespace': workload_ns,
        'labels': sts['metadata']['labels'], 'ownerReferences': [owner]},
        'spec': {'nodeSelector': {'test.tlb.io/unschedulable': 'true'},
                 'containers': [{'name': 'reader', 'image': 'busybox:1.37'}],
                 'volumes': [{'name': 'tls', 'secret': {'secretName': tls['metadata']['name']}}]}}
    run('create', '-f', '-', obj=reader)
    patch('service', 'runtime', app, {'metadata': {'annotations': {'tlb.io/map-ports': '18080:80'}}})
    wait(lambda: not any(v.get('secret', {}).get('secretName') == tls['metadata']['name']
        for v in get('statefulsets', workload_ns, selector)[0]['spec']['template']['spec'].get('volumes', [])),
        'plaintext configuration no longer references TLS')
    assert any(s['metadata']['name'] == tls['metadata']['name'] for s in get('secrets', workload_ns, selector))
    run('delete', 'pod', 'tls-reader', '-n', workload_ns, '--wait=true', '--timeout=30s')
    wait(lambda: not any(s['metadata']['name'] == tls['metadata']['name'] for s in get('secrets', workload_ns, selector)),
         'unused TLS copy is pruned after its last consumer disappears')
    patch('service', 'runtime', app, {'metadata': {'annotations': {'tlb.io/map-ports': '443/tls:80'}}})
    wait(lambda: any(s['metadata']['name'] == tls['metadata']['name'] for s in get('secrets', workload_ns, selector)),
         'TLS reactivation restores the runtime copy')

    # A valid source-reference change reuses the runtime name.
    apply('Secret', 'other-tls', app, stringData={'tls.crt': 'cert-three', 'tls.key': 'private-three'})
    patch('service', 'runtime', app, {'metadata': {'annotations': {'tlb.io/tls-secret-name': 'other-tls'}}})
    wait(lambda: any(s['metadata']['name'] == tls['metadata']['name'] and s.get('data', {}).get('tls.crt') == encoded('cert-three')
                     for s in get('secrets', workload_ns, selector)), 'source-reference change reuses the runtime Secret')
    run('delete', 'secret', 'source-key', 'other-tls', '-n', app)
    wait(lambda: any(('cannot read credential' in e.get('note', '') or ('other-tls' in e.get('note', '') and 'not found' in e.get('note', ''))) for e in get('events.events.k8s.io', app)),
         'source loss is reported')
    assert get('statefulsets', workload_ns, selector)[0]['metadata']['uid'] == sts['metadata']['uid']
    assert any(s.get('data', {}).get('setup-key') == encoded('second') for s in get('secrets', workload_ns, selector))

    # Hold one dependent Pod in termination to prove Secrets outlive their consumers.
    blocker = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'cleanup-blocker', 'namespace': workload_ns,
        'labels': sts['metadata']['labels'], 'finalizers': ['test.tlb.io/hold'], 'ownerReferences': [
            {'apiVersion': 'apps/v1', 'kind': 'StatefulSet', 'name': sts['metadata']['name'], 'uid': sts['metadata']['uid']}]},
        'spec': {'nodeSelector': {'test.tlb.io/unschedulable': 'true'}, 'containers': [{'name': 'test', 'image': 'busybox:1.37'}]}}
    run('create', '-f', '-', obj=blocker)
    run('delete', 'service', 'runtime', '-n', app, '--wait=false')
    wait(lambda: any(p['metadata'].get('deletionTimestamp') for p in get('pods', workload_ns, selector)), 'cleanup waits for terminating Pods')
    run('-n', 'kube-system', 'rollout', 'restart', 'deployment/tlb-controller')
    run('-n', 'kube-system', 'rollout', 'status', 'deployment/tlb-controller', '--timeout=30s')
    assert any(s['metadata']['name'] == tls['metadata']['name'] for s in get('secrets', workload_ns, selector))
    patch('pod', 'cleanup-blocker', workload_ns, {'metadata': {'finalizers': []}})
    wait(lambda: assert_clean(workload_ns, selector), 'restart and missing sources do not prevent complete cleanup')
    wait(lambda: not get('secrets', 'kube-system', selector), 'journal cleanup completes')
    if workload_ns != 'kube-system':
        assert not get('configmaps', workload_ns, 'controller.tlb.io/workload-owner')
    assert any(s['metadata']['name'] == 'source-tls' for s in get('secrets', app))
    run('delete', 'namespace', app, '--wait=true', '--timeout=30s')

# Exercise opt-in and revocation with a deliberately unschedulable workload.
configure('tlb-tunnels', True)
apply('Namespace', 'runtime-policy')
apply('Secret', 'key', 'runtime-policy', stringData={'key': 'test'})
apply('TunnelClass', 'policy', 'runtime-policy', spec={'netbird': {'managementUrl': 'https://netbird.example.com',
    'setupKeyRef': {'name': 'key', 'key': 'key'}, 'image': 'netbirdio/netbird:latest', 'enableEbpfCapabilities': False}})
apply('Service', 'policy', 'runtime-policy', spec={'type': 'LoadBalancer', 'loadBalancerClass': 'tlb.io/policy', 'ports': [{'port': 80}]})
patch('service', 'policy', 'runtime-policy', {'metadata': {'annotations': {'tlb.io/replicas': '0'}}})
selector = 'controller.tlb.io/service-uid=' + get('services', 'runtime-policy')[0]['metadata']['uid']
sts = wait(lambda: get('statefulsets', 'tlb-tunnels', selector), 'explicit opt-in permits unsafe class fields')[0]
patch('tunnelclass', 'policy', 'runtime-policy', {'spec': {'netbird': {'enableEbpfCapabilities': True}}})
wait(lambda: any(e['name'] == 'NB_DISABLE_EBPF_WG_PROXY' and e['value'] == 'false'
    for e in get('statefulsets', 'tlb-tunnels', selector)[0]['spec']['template']['spec']['containers'][0]['env']),
    'enabling eBPF updates the proxy setting on an existing workload')
assert set(get('statefulsets', 'tlb-tunnels', selector)[0]['spec']['template']['spec']['containers'][0][
    'securityContext']['capabilities']['add']) == {'NET_ADMIN', 'SYS_ADMIN', 'SYS_RESOURCE'}
configure('kube-system', False)
wait(lambda: not get('statefulsets', 'tlb-tunnels', selector), 'revoking opt-in stops affected workloads')
assert get('secrets', 'tlb-tunnels', selector) and get('secrets', 'kube-system', selector)
run('delete', 'namespace', 'runtime-policy', '--wait=false')
wait(lambda: assert_clean('tlb-tunnels', selector) and not get('secrets', 'kube-system', selector), 'revoked policy does not block cleanup')
assert not get('configmaps', 'tlb-tunnels', 'controller.tlb.io/workload-owner')
configure('kube-system', False)
run('delete', 'namespace', 'tlb-tunnels', '--wait=true', '--timeout=30s')
