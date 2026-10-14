"""TLS-only, authenticated API imported by Shuffle through OpenAPI."""
import hmac
import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .policy import respond


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Never log alert bodies or authentication.

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def do_POST(self):
        if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + self.server.token):
            self.send_error(401); return
        if self.path != '/respond':
            self.send_error(404); return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 65536:
                raise ValueError('invalid body length')
            result = respond(json.loads(self.rfile.read(size)), self.server.database)
            body = json.dumps(result).encode()
        except (ValueError, KeyError, TypeError, AttributeError):
            self.send_error(400, 'Invalid synthetic alert'); return
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)


def main():
    token = Path(os.environ['RESPONSE_TOKEN_FILE']).read_text().strip()
    if len(token) < 32:
        raise ValueError('strong token required')
    server = ThreadingHTTPServer((os.environ.get('RESPONSE_BIND', '127.0.0.1'), 8443), Handler)
    server.token = token; server.database = os.environ['RESPONSE_DATABASE']
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(os.environ['RESPONSE_CERT'], os.environ['RESPONSE_KEY'])
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
