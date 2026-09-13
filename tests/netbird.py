#!/usr/bin/env python3
"""Real NetBird TCP, UDP and TLS forwarding against an isolated combined server."""
import argparse
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--kubeconfig', required=True)
parser.add_argument('--diagnostics', required=True)
args = parser.parse_args()
base = ['kubectl', '--kubeconfig', args.kubeconfig, '--request-timeout=10s']
ns = 'netbird-test'
server_url = 'http://server.netbird-test.svc.cluster.local:80'
netbird_image = 'netbirdio/netbird:0.76.3'
python_image = 'python:3.13.7-alpine3.22'
sensitive = []


def run(*argv, obj=None, script=None, timeout=40):
    result = subprocess.run(base + list(argv), input=json.dumps(obj) if obj is not None else script,
                            text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result.stdout


def apply(kind, name, **fields):
    api_version = 'tlb.io/v1alpha1' if kind.endswith('TunnelClass') else 'v1'
    metadata = fields.pop('metadata', {})
    metadata.update(name=name)
    if kind != 'Namespace':
        metadata['namespace'] = ns
    run('apply', '-f', '-', obj=dict(apiVersion=api_version, kind=kind, metadata=metadata, **fields))


def get(kind, namespace=ns, selector=None):
    argv = ['get', kind, '-n', namespace, '-o', 'json']
    if selector:
        argv += ['-l', selector]
    return json.loads(run(*argv))['items']


def wait(check, message, seconds=120):
    deadline = time.monotonic() + seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                print('PASS', message, flush=True)
                return value
        except (RuntimeError, ValueError, KeyError, IndexError) as error:
            last_error = str(error)
        time.sleep(2)
    raise RuntimeError(message + (': ' + last_error if last_error else ''))


def api(path, body=None, token=None):
    # The Python sidecar sends requests entirely within the disposable cluster.
    script = 'import json,urllib.request\n'
    script += 'body=' + repr(json.dumps(body).encode() if body is not None else None) + '\n'
    script += 'headers=' + repr({'Content-Type': 'application/json', **({'Authorization': 'Token ' + token} if token else {})}) + '\n'
    script += f'request=urllib.request.Request({server_url + path!r},data=body,headers=headers)\n'
    script += 'print(urllib.request.urlopen(request,timeout=10).read().decode())\n'
    return json.loads(run('exec', '-i', '-n', ns, 'tools', '--', 'python3', '-', script=script))


def ready(name):
    return run('wait', '-n', ns, '--for=condition=Ready', 'pod/' + name, '--timeout=120s', timeout=135)


def probe(name, address):
    script = f'''import socket,ssl
address={address!r}
marker=b'tlb-netbird-forwarding'
for port in (18080,18443):
    connection=socket.create_connection((address,port),timeout=10)
    if port==18443:
        context=ssl._create_unverified_context()
        connection=context.wrap_socket(connection,server_hostname='localhost')
    connection.sendall(marker)
    assert connection.recv(1024)==marker
    connection.close()
connection=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
connection.settimeout(10)
connection.sendto(marker,(address,19000))
assert connection.recv(1024)==marker
print('verified')
'''
    return 'verified' in run('exec', '-i', '-n', ns, name, '-c', 'probe', '--', 'python3', '-', script=script)


def main():
    assert run('config', 'current-context').strip() == 'kind-tlb-netbird-e2e'
    apply('Namespace', ns)
    config = {'server': {'listenAddress': ':80', 'exposedAddress': server_url, 'authSecret': secrets.token_hex(32),
                        'dataDir': '/var/lib/netbird', 'logLevel': 'info', 'logFile': 'console',
                        'disableAnonymousMetrics': True, 'disableGeoliteUpdate': True,
                        'auth': {'issuer': server_url + '/oauth2', 'localAuthDisabled': False},
                        'store': {'engine': 'sqlite'}}}
    sensitive.append(config['server']['authSecret'])
    apply('Secret', 'server-config', stringData={'config.yaml': json.dumps(config)})
    apply('Service', 'server', spec={'selector': {'app': 'netbird-server'}, 'ports': [
        {'name': 'http', 'port': 80}, {'name': 'stun', 'port': 3478, 'protocol': 'UDP'}]})
    apply('Pod', 'server', metadata={'labels': {'app': 'netbird-server'}}, spec={
        'automountServiceAccountToken': False,
        'containers': [{'name': 'server', 'image': 'netbirdio/netbird-server:0.76.3',
                        'args': ['--config', '/etc/netbird/config.yaml'],
                        'env': [{'name': 'NB_SETUP_PAT_ENABLED', 'value': 'true'}],
                        'volumeMounts': [{'name': 'config', 'mountPath': '/etc/netbird', 'readOnly': True},
                                         {'name': 'data', 'mountPath': '/var/lib/netbird'}]}],
        'volumes': [{'name': 'config', 'secret': {'secretName': 'server-config'}}, {'name': 'data', 'emptyDir': {}}]})
    apply('Pod', 'tools', spec={'automountServiceAccountToken': False,
        'containers': [{'name': 'tools', 'image': python_image, 'command': ['sleep', '1800']}]})
    ready('tools')
    ready('server')
    password = secrets.token_urlsafe(32)
    sensitive.append(password)
    bootstrap = wait(lambda: api('/api/setup', {'email': 'admin@example.test', 'name': 'Test', 'password': password,
                                               'create_pat': True, 'pat_expire_in': 1}), 'NetBird account bootstrap')
    token = bootstrap['personal_access_token']
    sensitive.append(token)
    setup = api('/api/setup-keys', {'name': 'tlb-test', 'type': 'reusable', 'expires_in': 3600, 'auto_groups': [],
                                  'usage_limit': 10, 'ephemeral': True}, token)
    setup_key = setup['key']
    sensitive.append(setup_key)
    apply('Secret', 'setup', stringData={'key': setup_key})
    with tempfile.TemporaryDirectory() as directory:
        key = Path(directory) / 'key.pem'
        cert = Path(directory) / 'cert.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-keyout', str(key), '-out', str(cert)],
                       capture_output=True, timeout=20, check=True)
        sensitive.append(key.read_text())
        apply('Secret', 'tls', type='kubernetes.io/tls', stringData={'tls.key': key.read_text(), 'tls.crt': cert.read_text()})
    origin = '''import socketserver,threading
class TCP(socketserver.BaseRequestHandler):
    def handle(self): self.request.sendall(self.request.recv(1024))
class UDP(socketserver.BaseRequestHandler):
    def handle(self): self.request[1].sendto(self.request[0],self.client_address)
server=socketserver.ThreadingTCPServer(('0.0.0.0',8080),TCP)
threading.Thread(target=server.serve_forever,daemon=True).start()
socketserver.ThreadingUDPServer(('0.0.0.0',9000),UDP).serve_forever()
'''
    apply('Pod', 'origin', metadata={'labels': {'app': 'origin'}}, spec={'automountServiceAccountToken': False,
        'containers': [{'name': 'origin', 'image': python_image, 'command': ['python3', '-u', '-c', origin]}]})
    ready('origin')
    apply('TunnelClass', 'netbird', spec={'netbird': {'managementUrl': server_url, 'setupKeyRef': {'name': 'setup', 'key': 'key'}}})
    apply('Service', 'origin', metadata={'annotations': {'tlb.io/map-ports': '18080:tcp,18443/tls:tcp,19000:udp',
                                                       'tlb.io/tls-secret-name': 'tls'}}, spec={
        'type': 'LoadBalancer', 'loadBalancerClass': 'tlb.io/netbird', 'selector': {'app': 'origin'},
        'ports': [{'name': 'tcp', 'port': 8080}, {'name': 'udp', 'port': 9000, 'protocol': 'UDP'}]})
    address = wait(lambda: next(s for s in get('services') if s['metadata']['name'] == 'origin').get('status', {}).get(
        'loadBalancer', {}).get('ingress', [{}])[0].get('ip'), 'TLB announces a real NetBird peer IP', 240)
    for relayed in (False, True):
        name = 'relayed-peer' if relayed else 'direct-peer'
        apply('Pod', name, spec={'automountServiceAccountToken': False, 'containers': [
            {'name': 'netbird', 'image': netbird_image, 'command': ['/usr/local/bin/netbird', 'up', '-F', '-l', 'info', '--disable-dns'],
             'env': [{'name': 'NB_MANAGEMENT_URL', 'value': server_url},
                     {'name': 'NB_SETUP_KEY', 'valueFrom': {'secretKeyRef': {'name': 'setup', 'key': 'key'}}},
                     {'name': 'NB_DISABLE_EBPF_WG_PROXY', 'value': 'true'},
                     {'name': 'NB_FORCE_RELAY', 'value': str(relayed).lower()}],
             'securityContext': {'capabilities': {'add': ['NET_ADMIN']}}},
            {'name': 'probe', 'image': python_image, 'command': ['sleep', '1800']}]})
        ready(name)
        wait(lambda: probe(name, address), name + ' TCP, UDP and TLS forwarding without eBPF', 180)
        logs = run('logs', '-n', ns, name, '-c', 'netbird')
        assert 'eBPF WireGuard proxy is disabled' in logs or 'produce UDP proxy' in logs, 'userspace proxy was not selected'
    uid = next(s for s in get('services') if s['metadata']['name'] == 'origin')['metadata']['uid']
    selector = 'controller.tlb.io/service-uid=' + uid
    run('delete', 'service', 'origin', '-n', ns, '--wait=false')
    wait(lambda: not any(get(kind, 'kube-system', selector) for kind in ('pods', 'statefulsets', 'secrets', 'pvc')),
         'real tunnel cleanup removes runtime Secrets and journal')
    assert len(get('secrets', ns)) == 3


try:
    main()
except BaseException:
    directory = Path(args.diagnostics)
    directory.mkdir(parents=True, exist_ok=True)
    for namespace in (ns, 'kube-system'):
        for pod in get('pods', namespace):
            name = pod['metadata']['name']
            if namespace == 'kube-system' and not ('tlb' in name or 'tunnel' in name):
                continue
            for container in pod['spec']['containers']:
                try:
                    logs = run('logs', '-n', namespace, name, '-c', container['name'], '--tail=200')
                    for value in sensitive:
                        logs = logs.replace(value, '[redacted]')
                    (directory / (name + '-' + container['name'] + '.log')).write_text(logs)
                except RuntimeError:
                    pass
    print('Diagnostics:', directory, flush=True)
    raise
