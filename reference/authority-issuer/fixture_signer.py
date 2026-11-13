"""Disposable fixture key; not a persistent signing-key service."""
import base64
import os
from pathlib import Path
import select
import subprocess
import threading
import time

from service_client import s


class FixtureSigner:
    def __init__(self, node, node_sha256):
        s.need(s.jwt.file_sha(Path(node)) == node_sha256, "FIXTURE_NODE_CHANGED")
        self.process = subprocess.Popen([str(node), str(Path(__file__).with_suffix(".mjs"))],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": os.devnull})
        self.lock = threading.Lock()
        try:
            self.public_key = s.public_key(self.line(128).decode("ascii"))
        except BaseException:
            self.close()
            raise

    def line(self, limit):
        result = bytearray()
        deadline = time.monotonic() + 10
        while len(result) <= limit:
            remaining = deadline - time.monotonic()
            s.need(remaining > 0 and select.select([self.process.stdout], [], [], remaining)[0],
                   "FIXTURE_SIGNER_TIMEOUT")
            item = os.read(self.process.stdout.fileno(), 1)
            if item == b"\n":
                return bytes(result)
            s.need(bool(item), "FIXTURE_SIGNER_CLOSED")
            result.extend(item)
        raise s.AuthorityError("FIXTURE_SIGNER_RESPONSE_INVALID")

    def __call__(self, header, claims):
        def segment(value):
            return base64.urlsafe_b64encode(s.b.encode(value)).rstrip(b"=")
        raw = segment(header) + b"." + segment(claims)
        s.need(len(raw) < 130000, "FIXTURE_SIGNER_INPUT_INVALID")
        with self.lock:
            self.process.stdin.write(raw + b"\n")
            self.process.stdin.flush()
            signature = self.line(128)
        return raw + b"." + signature

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.process.stdin.close()
        self.process.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
