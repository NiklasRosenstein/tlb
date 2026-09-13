"""Stateful NetBird DNS API double; control endpoints are test-only."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

records = {'unrelated': dict(id='unrelated', name='untouched.private.example.com',
                             type='A', content='100.64.0.99', ttl=60)}
calls = []
failure = 0
sequence = 0


class Handler(BaseHTTPRequestHandler):
    def handle_request(self):
        global failure, sequence
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or 'null')
        status, response = 200, {}
        if self.path == '/__state' and self.command == 'GET':
            response = dict(records=list(records.values()), calls=calls, failure=failure)
        elif self.path == '/__control' and self.command == 'POST':
            failure = body['failure']
        elif self.headers.get('Authorization') != 'Token test-api-token':
            status = 401
        else:
            calls.append([self.command, self.path])
            parts = self.path.strip('/').split('/')
            if failure:
                status = failure
            elif parts == ['api', 'dns', 'zones', 'zone'] and self.command == 'GET':
                response = dict(domain='private.example.com', enabled=True)
            elif parts == ['api', 'dns', 'zones', 'zone', 'records']:
                if self.command == 'GET':
                    response = list(records.values())
                elif self.command == 'POST':
                    sequence += 1
                    record_id = f'record-{sequence}'
                    response = {**body, 'id': record_id}
                    records[record_id] = response
                else:
                    status = 405
            elif len(parts) == 6 and parts[:5] == ['api', 'dns', 'zones', 'zone', 'records']:
                record_id = parts[5]
                if record_id not in records:
                    status = 404
                elif self.command == 'DELETE':
                    del records[record_id]
                elif self.command == 'PUT':
                    response = {**body, 'id': record_id}
                    records[record_id] = response
                else:
                    status = 405
            else:
                status = 404
        data = json.dumps(response).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = handle_request


if __name__ == '__main__':
    HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
