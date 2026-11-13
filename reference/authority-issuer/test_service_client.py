"""Only disposable local HTTP/TLS endpoints are contacted."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from service_client import JsonService, MAX_BODY, s


class ServiceClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.temp.cleanup)
        cls.cert, cls.key = [Path(cls.temp.name) / name for name in ("cert.pem", "key.pem")]
        openssl = os.environ.get("VATE_TRIAL_OPENSSL") or shutil.which("openssl")
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-keyout", str(cls.key), "-out", str(cls.cert)], capture_output=True, timeout=20, check=True)

    def setUp(self):
        self.hits = []
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                size = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(size)
                owner.hits.append((self.path, raw, self.headers.get("Authorization")))
                self.respond()
            def do_GET(self):
                owner.hits.append((self.path, None, self.headers.get("Authorization")))
                self.respond()
            def respond(self):
                try:
                    if self.path == "/redirect":
                        self.send_response(307); self.send_header("Location", "/ok"); self.end_headers(); return
                    if self.path == "/unavailable":
                        self.send_response(503); self.end_headers(); return
                    raw = {"/duplicate": b'{"active":true,"active":false}', "/array": b'[]',
                           "/oversized": b'x' * (MAX_BODY + 1), "/bad": b'NaN'}.get(self.path, b'{"active":true}')
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain" if self.path == "/wrongtype" else "application/json")
                    if self.path == "/compressed": self.send_header("Content-Encoding", "gzip")
                    self.send_header("Content-Length", str(len(raw))); self.end_headers()
                    if self.path == "/slow":
                        self.wfile.write(raw[:1]); self.wfile.flush(); time.sleep(0.3); self.wfile.write(raw[1:])
                    else: self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError): pass
        self.servers = []
        for tls in (False, True):
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            if tls:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(self.cert, self.key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            self.servers.append((server, thread))
        self.addCleanup(self.close)
        self.plain = f"http://127.0.0.1:{self.servers[0][0].server_port}"
        self.tls = f"https://localhost:{self.servers[1][0].server_port}"

    def close(self):
        for server, thread in self.servers:
            server.shutdown(); server.server_close(); thread.join(3)
            self.assertFalse(thread.is_alive())

    def service(self, **options):
        return JsonService(self.tls, ca_file=self.cert, **options)

    def test_https_hostname_ca_and_form_roundtrip(self):
        result = self.service(authorization="Bearer fixture-credential").request("/introspect",
            form={"token": "local-token+value"})
        self.assertEqual(result, {"active": True})
        self.assertEqual(self.hits, [("/introspect", b'token=local-token%2Bvalue', "Bearer fixture-credential")])

    def test_untrusted_ca_and_wrong_hostname_do_not_reach_service(self):
        for service in (JsonService(self.tls), JsonService(self.tls.replace("localhost", "127.0.0.1"), ca_file=self.cert)):
            with self.assertRaisesRegex(s.AuthorityError, "ISSUER_SERVICE_UNAVAILABLE"): service.request("/ok")
        self.assertEqual(self.hits, [])

    def test_plaintext_requires_explicit_literal_loopback_mode(self):
        self.assertEqual(JsonService(self.plain, development_loopback=True).request("/ok"), {"active": True})
        for url, local in ((self.plain, False), ("http://localhost", True), ("http://example.com", True),
                           ("http://127.0.0.2", True), ("http://[::1]", True)):
            with self.assertRaises(s.AuthorityError): JsonService(url, development_loopback=local)

    def test_redirects_do_not_forward_credentials(self):
        with self.assertRaises(s.AuthorityError): self.service(authorization="Bearer fixture").request("/redirect")
        self.assertEqual([hit[0] for hit in self.hits], ["/redirect"])

    def test_response_shape_size_encoding_and_json_fail_closed(self):
        for path in ("/duplicate", "/array", "/oversized", "/bad", "/compressed", "/wrongtype", "/unavailable"):
            with self.subTest(path=path), self.assertRaises(s.AuthorityError): self.service().request(path)

    def test_timeout_never_returns_partial_decision(self):
        with self.assertRaises(s.AuthorityError): self.service(timeout_seconds=0.1).request("/slow")

    def test_endpoint_path_and_tls_changes_fail(self):
        for url in ("https://user:pass@localhost", "https://localhost?target=remote", "https://localhost/#x",
                    "https://localhost:0", "https://localhost/\n"):
            with self.assertRaises(s.AuthorityError): JsonService(url)
        for path in ("//other.example", "/../secret", "/ok?url=other", "/ok\n"):
            with self.assertRaises(s.AuthorityError): self.service().request(path)
        service = self.service(); service.context.check_hostname = False
        with self.assertRaises(s.AuthorityError): service.request("/ok")


if __name__ == "__main__":
    unittest.main()
