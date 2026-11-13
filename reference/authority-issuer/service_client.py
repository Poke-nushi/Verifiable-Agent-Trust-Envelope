"""Bounded JSON requests to application-selected authority endpoints."""
import math
from pathlib import Path
import ssl
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "authority-updates"))
import snapshot as s

MAX_BODY = 131072


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class JsonService:
    """Credentials/endpoints are selected by the host, never by incoming tokens."""

    def __init__(self, base_url, *, authorization=None, ca_file=None,
                 timeout_seconds=5.0, development_loopback=False):
        s.need(type(base_url) is str and 0 < len(base_url) <= 2048
               and all(32 < ord(ch) < 127 for ch in base_url), "ISSUER_ENDPOINT_INVALID")
        try:
            parsed = urlsplit(base_url)
            valid = (parsed.hostname and "@" not in parsed.netloc and not parsed.query
                     and not parsed.fragment and parsed.port != 0
                     and (parsed.scheme == "https" or development_loopback is True
                          and parsed.scheme == "http" and parsed.hostname == "127.0.0.1"))
        except ValueError:
            valid = False
        s.need(valid and type(development_loopback) is bool, "ISSUER_ENDPOINT_INVALID")
        s.need(type(timeout_seconds) in (int, float) and math.isfinite(timeout_seconds)
               and 0 < timeout_seconds <= 30, "ISSUER_TIMEOUT_INVALID")
        s.need(authorization is None or type(authorization) is str and 0 < len(authorization) <= 8192
               and all(32 <= ord(ch) < 127 for ch in authorization), "ISSUER_CREDENTIAL_INVALID")
        self.base_url = base_url.rstrip("/")
        self.authorization, self.timeout = authorization, timeout_seconds
        self.development_loopback = development_loopback
        self.context = ssl.create_default_context(cafile=str(ca_file) if ca_file is not None else None)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def descriptor(self):
        # Credentials may rotate without changing the selected source identity.
        return {"base_url": self.base_url, "development_loopback": self.development_loopback}

    def request(self, path, *, body=None, form=None):
        s.need(type(path) is str and path.startswith("/") and "//" not in path
               and all(ch.isascii() and (ch.isalnum() or ch in "/-_") for ch in path),
               "ISSUER_PATH_INVALID")
        s.need(self.context.verify_mode == ssl.CERT_REQUIRED and self.context.check_hostname
               and self.context.minimum_version >= ssl.TLSVersion.TLSv1_2, "ISSUER_TLS_CHANGED")
        s.need(body is None or form is None, "ISSUER_REQUEST_INVALID")
        headers = {"Accept": "application/json", "Accept-Encoding": "identity", "Cache-Control": "no-cache"}
        data = None
        if body is not None:
            data = s.b.encode(body)
            headers["Content-Type"] = "application/json"
        if form is not None:
            data = urlencode(form).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        s.need(data is None or len(data) <= MAX_BODY, "ISSUER_REQUEST_INVALID")
        if self.authorization is not None:
            headers["Authorization"] = self.authorization
        request = Request(self.base_url + path, data=data, headers=headers,
                          method="GET" if data is None else "POST")
        client = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=self.context))
        deadline = time.monotonic() + self.timeout
        try:
            with client.open(request, timeout=self.timeout) as response:
                s.need(response.status == 200 and response.headers.get_content_type() == "application/json"
                       and response.headers.get("Content-Encoding", "identity").lower() == "identity",
                       "ISSUER_RESPONSE_INVALID")
                length = response.headers.get("Content-Length")
                s.need(length is None or length.isdigit() and 0 < int(length) <= MAX_BODY,
                       "ISSUER_RESPONSE_INVALID")
                raw = bytearray()
                while True:
                    s.need(time.monotonic() <= deadline, "ISSUER_DEADLINE")
                    chunk = response.read1(min(8192, MAX_BODY + 1 - len(raw)))
                    s.need(time.monotonic() <= deadline, "ISSUER_DEADLINE")
                    if not chunk:
                        break
                    raw.extend(chunk)
                    s.need(len(raw) <= MAX_BODY, "ISSUER_RESPONSE_INVALID")
                s.need(bool(raw) and (length is None or len(raw) == int(length)), "ISSUER_RESPONSE_INVALID")
                result = s.b.decode(bytes(raw))
                s.need(type(result) is dict, "ISSUER_RESPONSE_INVALID")
                return result
        except s.AuthorityError:
            raise
        except HTTPError as exc:
            exc.close()
            raise s.AuthorityError("ISSUER_SERVICE_UNAVAILABLE") from None
        except Exception:
            # Do not include a token, credential, response body or URL in diagnostics.
            raise s.AuthorityError("ISSUER_SERVICE_UNAVAILABLE") from None
