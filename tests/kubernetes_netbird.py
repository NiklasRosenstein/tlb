#!/usr/bin/env python3
"""Real Kubernetes watches and lifecycle, with a controlled NetBird DNS API and peers."""
import argparse
import json
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--kubeconfig', required=True)
args = parser.parse_args()
base = ['kubectl', '--kubeconfig', args.kubeconfig, '--request-timeout=10s']
ns, other = 'dns-audit', 'dns-other'
workload_ns = 'dns-tunnels'
class_key = 'tlb.io/netbird-custom-dns-ingress-class'
scope_key = 'tlb.io/netbird-custom-dns-ingress-namespaces'
hosts_key = 'tlb.io/netbird-custom-dns-hostnames'
zone = 'private.example.com'


def run(*argv, obj=None):
    result = subprocess.run(base + list(argv), input=json.dumps(obj) if obj is not None else None,
                            text=True, capture_output=True, timeout=35)
    assert result.returncode == 0, result.stderr
    return result.stdout


def get(kind, name=None, namespace=ns, selector=None):
    argv = ['get', kind] + ([name] if name else []) + ['-n', namespace, '-o', 'json']
    if selector:
        argv += ['-l', selector]
    result = json.loads(run(*argv))
    return result if name else result['items']


def apply(kind, name, spec=None, namespace=ns, api='v1', **extra):
    obj = dict(apiVersion=api, kind=kind, metadata=dict(name=name, namespace=namespace), **extra)
    if spec is not None:
        obj['spec'] = spec
    run('apply', '-f', '-', obj=obj)


def patch(kind, name, body, namespace=ns):
    run('patch', kind, name, '-n', namespace, '--type=merge', '-p', json.dumps(body))


def wait(check, description, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            print('PASS', description, flush=True)
            return
        time.sleep(1)
    raise AssertionError(description)


def api(path='/__state', data=None):
    # Exec avoids a host port-forward process and exercises the in-cluster fixture.
    payload = json.dumps(data).encode() if data is not None else None
    code = ('import urllib.request; '
            f'r=urllib.request.Request("http://127.0.0.1:8080{path}", data={payload!r}); '
            'print(urllib.request.urlopen(r,timeout=5).read().decode())')
    return json.loads(run('exec', 'pod/dns-api', '-n', ns, '--', 'python3', '-c', code))


def records():
    return sorted((r['name'], r['content']) for r in api()['records'])


def expected(names, addresses=('100.64.0.10', '100.64.0.11')):
    return sorted([(f'{name}.{zone}', ip) for name in names for ip in addresses]
                  + [(f'untouched.{zone}', '100.64.0.99')])


def dns(names, description, addresses=('100.64.0.10', '100.64.0.11'), seconds=45):
    wanted, observed = expected(names, addresses), None

    def matches():
        nonlocal observed
        observed = records()
        return observed == wanted

    try:
        wait(matches, description, seconds)
    except AssertionError as error:
        raise AssertionError(f'{description}: expected {wanted}, observed {observed}') from error


def condition(reason, service='ingress'):
    return any(c['type'] == 'tlb.io/CustomDNSReady' and c['reason'] == reason
               for c in get('service', service).get('status', {}).get('conditions', []))


def ingress(name, host, cls='private', namespace=ns):
    backend = dict(service=dict(name='unused', port=dict(number=80)))
    rule = dict(host=host, http=dict(paths=[dict(path='/', pathType='Prefix', backend=backend)]))
    spec = dict(rules=[rule])
    if cls:
        spec['ingressClassName'] = cls
    apply('Ingress', name, spec, namespace, 'networking.k8s.io/v1')


def annotations(values):
    patch('service', 'ingress', dict(metadata=dict(annotations=values)))


def settled():
    # Require an idle API before a watch-only mutation so startup work cannot mask a missing watch.
    last, since = None, time.monotonic()
    deadline = since + 45
    while time.monotonic() < deadline:
        count = len(api()['calls'])
        if count != last:
            last, since = count, time.monotonic()
        elif time.monotonic() - since >= 5:
            return
        time.sleep(1)
    raise AssertionError('DNS reconciliation did not settle')


assert run('config', 'current-context').strip() == 'kind-tlb-audit', 'dedicated test cluster required'
deployment = get('deployment', namespace='kube-system', selector='app.kubernetes.io/instance=tlb-controller')
assert len(deployment) == 1
controller_env = deployment[0]['spec']['template']['spec']['containers'][0]['env']
assert any(e['name'] == 'TLB_EXTERNAL_REFRESH_INTERVAL_SECONDS' and e.get('value') == '7200'
           for e in controller_env), 'watch tests require the two-hour external refresh interval'
for namespace in (ns, other, workload_ns):
    run('apply', '-f', '-', obj=dict(apiVersion='v1', kind='Namespace', metadata=dict(name=namespace)))
run('-n', 'kube-system', 'set', 'env', 'deployment/tlb-controller',
    'TLB_WORKLOAD_NAMESPACE=' + workload_ns, 'TLB_ALLOW_UNSAFE_WORKLOAD_OVERRIDES=true')
run('-n', 'kube-system', 'rollout', 'status', 'deployment/tlb-controller', '--timeout=60s')
time.sleep(17)
apply('Pod', 'dns-api', dict(containers=[dict(name='api', image='tlb-netbird-test:audit', imagePullPolicy='Never',
      readinessProbe=dict(httpGet=dict(path='/__state', port=8080), periodSeconds=1))]))
apply('Service', 'dns-api', dict(selector={'app': 'dns-api'}, ports=[dict(port=8080)]))
patch('pod', 'dns-api', dict(metadata=dict(labels={'app': 'dns-api'})))
run('wait', 'pod/dns-api', '-n', ns, '--for=condition=Ready', '--timeout=60s')
apply('Secret', 'credentials', stringData=dict(key='test-setup-key', token='test-api-token'))
# The generated launch script and readiness probe observe a real dummy interface in each peer Pod.
up = ('peer_name=$(hostname); ip link add wt0 type dummy; '
      'ip addr add "100.64.0.$(( ${peer_name##*-} + 10 ))/32" dev wt0; '
      'ip link set wt0 up; exec sleep infinity')
apply('TunnelClass', 'dns-audit', dict(netbird=dict(
    managementUrl=f'http://dns-api.{ns}.svc:8080',
    setupKeyRef=dict(name='credentials', key='key'),
    image='tlb-netbird-test:audit', enableEbpfCapabilities=False, storageClass='standard', upCommand=up,
    customDns=dict(zoneId='zone', apiTokenRef=dict(name='credentials', key='token'), ttl=60))),
    api='tlb.io/v1alpha1')
# apiUrl is deliberately omitted: the production managementUrl derivation is exercised.
run('apply', '-f', '-', obj=dict(apiVersion='v1', kind='Service',
    metadata=dict(name='ingress', namespace=ns, annotations={class_key: 'private', 'tlb.io/replicas': '2'}),
    spec=dict(type='LoadBalancer', loadBalancerClass='tlb.io/dns-audit', ports=[dict(port=80)])))
ingress('first', f'first.{zone}')
dns(['first'], 'Ingress creation publishes both real ready-Pod addresses', seconds=120)
wait(lambda: condition('Reconciled'), 'custom DNS condition becomes ready')
assert hosts_key not in get('service', 'ingress')['metadata']['annotations']

settled()
ingress('new', f'new.{zone}')
dns(['first', 'new'], 'Ingress creation alone adds a hostname on a settled Service')
settled()
run('delete', 'ingress', 'new', '-n', ns, '--wait=false')
dns(['first'], 'deleting the last Ingress source alone removes its hostname')
settled()
ingress('first', f'edited.{zone}')
dns(['edited'], 'Ingress rule edit alone replaces records before the external refresh')
settled()
ingress('duplicate', f'edited.{zone}')
# Confirm the duplicate has been processed before deleting the first source.
settled()
run('delete', 'ingress', 'first', '-n', ns, '--wait=false')
settled()
assert records() == expected(['edited']), 'shared hostname must survive deletion of one source'
settled()
ingress('duplicate', f'edited.{zone}', 'public')
dns([], 'class change alone removes the previous class contribution')

for name, host, cls, namespace in [
    ('public', f'public.{zone}', 'public', ns),
    ('classless', f'classless.{zone}', None, ns),
    ('wildcard', f'*.{zone}', 'private', ns),
    ('outside', 'outside.example.org', 'private', ns),
    ('other', f'other.{zone}', 'private', other),
]:
    ingress(name, host, cls, namespace)
apply('Ingress', 'tls-only', dict(ingressClassName='private', tls=[dict(hosts=[f'tls.{zone}'])],
      defaultBackend=dict(service=dict(name='unused', port=dict(number=80)))), api='networking.k8s.io/v1')
ingress('included', f'included.{zone}')
dns(['included'], 'class, zone, wildcard, TLS-only and default namespace filters apply')
annotations({scope_key: f'{ns},{other}'})
dns(['included', 'other'], 'explicit namespace allowlist includes cross-namespace Ingresses')
annotations({scope_key: '*'})
settled()
ingress('other', f'changed.{zone}', namespace=other)
dns(['included', 'changed'], 'all-namespace discovery watches cross-namespace edits')
annotations({scope_key: None, hosts_key: f'included.{zone},explicit.{zone}'})
dns(['included', 'explicit'], 'explicit hostnames combine with discovered names and scope removal cleans up')
run('delete', 'ingress', 'included', '-n', ns, '--wait=false')
settled()
assert records() == expected(['included', 'explicit']), 'explicit source must preserve shared hostname'
annotations({hosts_key: f'explicit.{zone}'})
dns(['explicit'], 'removing last hostname source removes its records')

# Drop readiness without deleting the peer, then restore it through the same generated probe.
peer = sorted(get('pods', namespace=workload_ns, selector='controller.tlb.io/binding-uid'), key=lambda p: p['metadata']['name'])[1]
peer_name = peer['metadata']['name']
run('exec', peer_name, '-n', workload_ns, '--', 'ip', 'link', 'delete', 'wt0')
dns(['explicit'], 'unready peer is withdrawn by the Pod watch', ('100.64.0.10',), seconds=120)
run('exec', peer_name, '-n', workload_ns, '--', 'sh', '-c',
    'ip link add wt0 type dummy; ip addr add 100.64.0.11/32 dev wt0; ip link set wt0 up')
dns(['explicit'], 'recovered peer readiness restores its address')
annotations({'tlb.io/replicas': '1'})
dns(['explicit'], 'scale down removes retired peer address', ('100.64.0.10',))
annotations({'tlb.io/replicas': '0'})
dns([], 'scale to zero empties managed A records', ())
annotations({'tlb.io/replicas': '2'})
dns(['explicit'], 'scale up restores ready peer addresses', seconds=120)

# A second Service must not claim an existing owner's hostname, even with no ready peers.
run('apply', '-f', '-', obj=dict(apiVersion='v1', kind='Service',
    metadata=dict(name='conflicting', namespace=ns,
                  annotations={hosts_key: f'explicit.{zone}', 'tlb.io/replicas': '0'}),
    spec=dict(type='LoadBalancer', loadBalancerClass='tlb.io/dns-audit', ports=[dict(port=80)])))
wait(lambda: condition('Conflict', 'conflicting'), 'second Service cannot reserve the same hostname')
assert records() == expected(['explicit'])
run('delete', 'service', 'conflicting', '-n', ns, '--wait=false')
wait(lambda: all(s['metadata']['name'] != 'conflicting' for s in get('service')),
     'conflicting Service finalizes without deleting the owner records')
assert records() == expected(['explicit'])

# API errors preserve provider state and recover through the controller's normal retry policy.
api('/__control', dict(failure=503))
ingress('recover', f'recover.{zone}')
wait(lambda: condition('APIError'), 'provider failure is visible in Service status')
assert records() == expected(['explicit'])
api('/__control', dict(failure=0))
dns(['explicit', 'recover'], 'provider recovery reconciles pending Ingress changes')

# A genuine Kubernetes authorization failure must not be mistaken for an empty discovery result.
roles = get('clusterrole', namespace='kube-system', selector='app.kubernetes.io/instance=tlb-controller')
role = next(r for r in roles if any('ingresses' in rule.get('resources', []) for rule in r['rules']))
original_rules = role['rules']
rules = json.loads(json.dumps(original_rules))
for rule in rules:
    if 'ingresses' in rule.get('resources', []):
        rule['verbs'].remove('list')
try:
    patch('clusterrole', role['metadata']['name'], dict(rules=rules))
    ingress('recover', f'renamed.{zone}')
    wait(lambda: condition('IngressDiscoveryFailed'), 'Ingress list authorization failure is reported')
    assert records() == expected(['explicit', 'recover'])
finally:
    patch('clusterrole', role['metadata']['name'], dict(rules=original_rules))
dns(['explicit', 'renamed'], 'restored list permission safely reconciles the complete hostname set')

# Terminate the active controller while DNS ownership is live.
lease = get('lease', 'tlb-controller', 'kube-system')['spec']['holderIdentity']
controllers = get('pods', namespace='kube-system', selector='app.kubernetes.io/instance=tlb-controller')
leaders = [p for p in controllers if 'acquired controller leadership' in
           run('logs', p['metadata']['name'], '-n', 'kube-system')]
assert len(leaders) == 1, 'exactly one controller must have acquired leadership'
leader = leaders[0]
run('delete', 'pod', leader['metadata']['name'], '-n', 'kube-system', '--wait=false')
wait(lambda: get('lease', 'tlb-controller', 'kube-system')['spec']['holderIdentity'] != lease,
     'standby controller takes over live DNS ownership', 90)
settled()
ingress('recover', f'after-restart.{zone}')
dns(['explicit', 'after-restart'], 'new leader watches Ingresses and reconciles persisted ownership')
annotations({class_key: None})
dns(['explicit'], 'disabling discovery retains explicit names only')
api('/__control', dict(failure=503))
calls_before = len(api()['calls'])
run('delete', 'service', 'ingress', '-n', ns, '--wait=false')
wait(lambda: len(api()['calls']) > calls_before, 'Service cleanup attempts the unavailable provider')
remaining = get('service', 'ingress')['metadata']
assert remaining.get('deletionTimestamp') and 'tlb.io/tunnel-cleanup' in remaining.get('finalizers', [])
assert records() == expected(['explicit']), 'failed cleanup must retain owned records and finalizer'
api('/__control', dict(failure=0))
dns([], 'Service deletion cleans owned records and preserves unrelated record')
wait(lambda: all(s['metadata']['name'] != 'ingress' for s in get('service')),
     'Service finalizer completes')
wait(lambda: not get('secrets', namespace='kube-system', selector='controller.tlb.io/journal=true'),
     'DNS binding journal finalizes')
for namespace in (ns, other):
    run('delete', 'namespace', namespace, '--wait=false')
print('PASS NetBird DNS Kubernetes E2E suite', flush=True)

run('-n', 'kube-system', 'set', 'env', 'deployment/tlb-controller',
    'TLB_WORKLOAD_NAMESPACE=kube-system', 'TLB_ALLOW_UNSAFE_WORKLOAD_OVERRIDES=false')
run('-n', 'kube-system', 'rollout', 'status', 'deployment/tlb-controller', '--timeout=60s')
time.sleep(17)
run('delete', 'namespace', workload_ns, '--wait=true', '--timeout=30s')
