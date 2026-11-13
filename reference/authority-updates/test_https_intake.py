"""HTTPS is tested only against a disposable loopback server and test certificate."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from https_source import HttpsSnapshotSource
import snapshot as s


class HttpsIntakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name)
        cls.cert, cls.key = root / "cert.pem", root / "key.pem"
        openssl = os.environ.get("VATE_TRIAL_OPENSSL") or shutil.which("openssl")
        if openssl is None:
            raise RuntimeError("Existing openssl is required to generate the disposable TLS fixture")
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-keyout", str(cls.key), "-out", str(cls.cert)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20, check=True)

    def setUp(self):
        self.body, self.hits = b"local.fixture.bytes", []
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                owner.hits.append(self.path)
                try:
                    if self.path == "/redirect":
                        self.send_response(302); self.send_header("Location", "/ok"); self.end_headers(); return
                    if self.path == "/error":
                        self.send_response(503); self.end_headers(); return
                    body = b"x" * 65537 if self.path == "/oversized" else owner.body
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json" if self.path == "/wrong-type" else "application/jwt")
                    if self.path == "/encoded": self.send_header("Content-Encoding", "gzip")
                    self.send_header("Content-Length", str(len(body))); self.end_headers()
                    if self.path == "/slow":
                        self.wfile.write(body[:1]); self.wfile.flush(); time.sleep(0.3); self.wfile.write(body[1:])
                    else:
                        self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(self.cert, self.key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.close_server)
        self.base = f"https://localhost:{self.server.server_port}"

    def close_server(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(3)
        self.assertFalse(self.thread.is_alive())

    def source(self, path="/ok", **options):
        return HttpsSnapshotSource(self.base + path, ca_file=self.cert, **options)

    def test_selected_ca_and_hostname(self):
        self.assertEqual(self.source()(), self.body)

    def test_wrong_ca_and_wrong_hostname_fail(self):
        for source in (HttpsSnapshotSource(self.base + "/ok"),
                HttpsSnapshotSource(self.base.replace("localhost", "127.0.0.1") + "/ok", ca_file=self.cert)):
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_HTTP_UNAVAILABLE"):
                source()
        self.assertEqual(self.hits, [])

    def test_redirect_is_not_followed(self):
        with self.assertRaises(s.AuthorityError): self.source("/redirect")()
        self.assertEqual(self.hits, ["/redirect"])

    def test_size_type_encoding_and_server_error_fail(self):
        for path in ("/oversized", "/wrong-type", "/encoded", "/error"):
            with self.subTest(path=path), self.assertRaises(s.AuthorityError):
                self.source(path)()

    def test_timeout_does_not_return_partial_snapshot(self):
        with self.assertRaises(s.AuthorityError):
            self.source("/slow", timeout_seconds=0.1)()

    def test_url_restrictions_and_tls_mutation(self):
        for url in ("http://localhost/", "https://@localhost/", "https://user:password@localhost/",
                    "https://localhost/#fragment", "https://localhost:0/", "https://localhost/\n"):
            with self.assertRaises(s.AuthorityError): HttpsSnapshotSource(url)
        selected = self.source(); selected.context.check_hostname = False
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_TLS_CONFIGURATION_CHANGED"):
            selected()

    def test_https_refresh_reaches_managed_admission_and_dispatch(self):
        import test_authority_updates as fixtures
        fixtures.AuthorityUpdateTests.setUpClass()
        fixture = fixtures.AuthorityUpdateTests(); fixture.setUp()
        try:
            self.body, = fixture.setup_source()
            fixture.source.refresh(self.source())
            bound = fixture.admit()
            fixture.managed.dispatch(bound, caller_proof=fixture.f.proof)
            self.assertEqual(len(fixture.calls), 1)
        finally:
            fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
