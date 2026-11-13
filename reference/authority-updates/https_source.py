"""Operator-selected HTTPS delivery; snapshot signatures remain mandatory."""
import hashlib
import math
from pathlib import Path
import ssl
import sys
import time
from urllib.parse import urlsplit
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler

from snapshot import AuthorityError, need, jwt

_source = None
try:
    _source = Path(__file__).read_bytes()
    LOADED_SOURCE_SHA256 = (hashlib.sha256(_source).hexdigest() if hasattr(sys, "_getframe")
        and sys._getframe().f_code == compile(_source, sys._getframe().f_code.co_filename,
            "exec", dont_inherit=True, optimize=sys.flags.optimize) else None)
except (OSError, SyntaxError, ValueError):
    LOADED_SOURCE_SHA256 = None
del _source


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def validate_source_options(url, timeout_seconds):
    """Validate request configuration without consulting TLS or environment state."""
    need(type(url) is str and 0 < len(url) <= 4096 and all(ord(ch) > 32 and ord(ch) < 127 for ch in url),
         "AUTHORITY_URL_INVALID")
    try:
        parsed = urlsplit(url)
        valid = (parsed.scheme == "https" and parsed.hostname and "@" not in parsed.netloc
                 and not parsed.fragment and parsed.port != 0)
    except ValueError:
        valid = False
    need(valid, "AUTHORITY_URL_INVALID")
    need(type(timeout_seconds) in (int, float) and math.isfinite(timeout_seconds)
         and 0 < timeout_seconds <= 30, "AUTHORITY_TIMEOUT_INVALID")


class HttpsSnapshotSource:
    def __init__(self, url: str, *, ca_file: str | Path | None = None,
                 ca_data: str | bytes | None = None, timeout_seconds: float = 5.0):
        validate_source_options(url, timeout_seconds)
        need(ca_data is None or type(ca_data) in (str, bytes) and bool(ca_data) and ca_file is None,
             "AUTHORITY_CA_CONFIGURATION_INVALID")
        self.url, self.timeout = url, timeout_seconds
        self.context = ssl.create_default_context(
            cafile=str(ca_file) if ca_file is not None else None, cadata=ca_data)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def __call__(self) -> bytes:
        need(self.context.verify_mode == ssl.CERT_REQUIRED and self.context.check_hostname
             and self.context.minimum_version >= ssl.TLSVersion.TLSv1_2,
             "AUTHORITY_TLS_CONFIGURATION_CHANGED")
        opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=self.context))
        request = Request(self.url, headers={"Accept": "application/jwt", "Cache-Control": "no-cache",
                                             "Accept-Encoding": "identity"}, method="GET")
        deadline = time.monotonic() + self.timeout
        try:
            with opener.open(request, timeout=self.timeout) as response:
                need(response.status == 200 and response.headers.get_content_type() == "application/jwt"
                     and response.headers.get("Content-Encoding", "identity").lower() == "identity",
                     "AUTHORITY_HTTP_RESPONSE_INVALID")
                length = response.headers.get("Content-Length")
                need(length is None or length.isdigit() and 0 < int(length) <= jwt.MAX_TOKEN_BYTES,
                     "AUTHORITY_HTTP_RESPONSE_INVALID")
                raw = bytearray()
                while True:
                    need(time.monotonic() <= deadline, "AUTHORITY_HTTP_DEADLINE")
                    chunk = response.read1(min(8192, jwt.MAX_TOKEN_BYTES + 1 - len(raw)))
                    need(time.monotonic() <= deadline, "AUTHORITY_HTTP_DEADLINE")
                    if not chunk:
                        break
                    raw.extend(chunk)
                    need(len(raw) <= jwt.MAX_TOKEN_BYTES, "AUTHORITY_HTTP_RESPONSE_INVALID")
                need(bool(raw) and (length is None or len(raw) == int(length)), "AUTHORITY_HTTP_RESPONSE_INVALID")
                return bytes(raw)
        except AuthorityError:
            raise
        except HTTPError as exc:
            exc.close()
            raise AuthorityError("AUTHORITY_HTTP_UNAVAILABLE") from None
        except Exception:
            raise AuthorityError("AUTHORITY_HTTP_UNAVAILABLE") from None
