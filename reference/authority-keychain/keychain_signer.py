"""Optional macOS Keychain signer for the existing authority-issuer callback."""
from dataclasses import dataclass
import base64
import hashlib
import math
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference/authority-updates"))
import snapshot as s

b, jwt = s.b, s.jwt
PROFILE = "vate-macos-keychain-authority-signer-v1"
BRIDGE = "vate-keychain-es256-v1"
MAX_RESPONSE_BYTES = 2048
MAX_REQUEST_BYTES = 128 * 1024


@dataclass(frozen=True)
class _Configuration:
    helper: Path
    helper_sha256: str
    keychain: Path
    application_tag: str
    selection: s.AuthoritySelection
    timeout_seconds: float


def _regular_owned_file(path, *, executable=False):
    info = path.lstat()
    s.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
           and not info.st_mode & 0o022
           and (not executable or os.access(path, os.X_OK)), "KEYCHAIN_SIGNER_UNAVAILABLE")


class KeychainSigner:
    """Use an explicitly selected, already provisioned key; never unlock or create it."""

    def __init__(self, *, expected_profile, helper, helper_sha256, keychain,
                 application_tag, selection, timeout_seconds=10.0):
        s.need(expected_profile == PROFILE and sys.platform == "darwin"
               and type(selection) is s.AuthoritySelection
               and type(helper_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", helper_sha256)
               and type(application_tag) is str
               and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", application_tag)
               and type(timeout_seconds) in (int, float) and math.isfinite(timeout_seconds)
               and 0 < timeout_seconds <= 10, "KEYCHAIN_SIGNER_CONFIGURATION_INVALID")
        selection.descriptor()
        try:
            selected_helper, selected_keychain = Path(helper), Path(keychain)
            s.need(selected_helper.is_absolute() and selected_keychain.is_absolute(),
                   "KEYCHAIN_SIGNER_CONFIGURATION_INVALID")
            self._config = _Configuration(selected_helper.resolve(strict=True), helper_sha256,
                selected_keychain.resolve(strict=True), application_tag, selection, timeout_seconds)
            self._check_files()
        except (OSError, TypeError, ValueError, RuntimeError) as error:
            if isinstance(error, s.AuthorityError):
                raise
            raise s.AuthorityError("KEYCHAIN_SIGNER_UNAVAILABLE") from None

    def _check_files(self):
        cfg = self._config
        try:
            _regular_owned_file(cfg.helper, executable=True)
            _regular_owned_file(cfg.keychain)
            s.need(not cfg.keychain.stat().st_mode & 0o077, "KEYCHAIN_SIGNER_UNAVAILABLE")
            s.need(jwt.file_sha(cfg.helper) == cfg.helper_sha256, "KEYCHAIN_SIGNER_HELPER_CHANGED")
        except OSError:
            raise s.AuthorityError("KEYCHAIN_SIGNER_UNAVAILABLE") from None

    def _process(self, request):
        """Bound both pipe output and elapsed time; never inherit loader/preload settings."""
        process = None
        try:
            process = subprocess.Popen([str(self._config.helper), "sign"], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
            deadline = time.monotonic() + self._config.timeout_seconds
            position, output = 0, bytearray()
            with selectors.DefaultSelector() as selector:
                os.set_blocking(process.stdin.fileno(), False)
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE)
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    s.need(remaining > 0, "KEYCHAIN_SIGNER_TIMEOUT")
                    for key, _ in selector.select(remaining):
                        if key.fileobj is process.stdin:
                            count = os.write(key.fd, request[position:position + 4096])
                            position += count
                            if position == len(request):
                                selector.unregister(process.stdin)
                                process.stdin.close()
                        else:
                            chunk = os.read(key.fd, MAX_RESPONSE_BYTES + 1 - len(output))
                            output.extend(chunk)
                            s.need(len(output) <= MAX_RESPONSE_BYTES, "KEYCHAIN_SIGNER_FAILED")
                            if not chunk:
                                selector.unregister(process.stdout)
            remaining = deadline - time.monotonic()
            s.need(remaining > 0, "KEYCHAIN_SIGNER_TIMEOUT")
            s.need(process.wait(timeout=remaining) == 0, "KEYCHAIN_SIGNER_FAILED")
            return bytes(output)
        except subprocess.TimeoutExpired:
            raise s.AuthorityError("KEYCHAIN_SIGNER_TIMEOUT") from None
        except (OSError, ValueError) as error:
            # Preserve stable causes, never expose subprocess output or input.
            if isinstance(error, s.AuthorityError):
                raise
            raise s.AuthorityError("KEYCHAIN_SIGNER_FAILED") from None
        finally:
            if process is not None:
                try:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    raise s.AuthorityError("KEYCHAIN_SIGNER_CLEANUP_FAILED") from None
                finally:
                    process.stdin.close()
                    process.stdout.close()

    def __call__(self, header, claims):
        cfg = self._config
        selected = cfg.selection
        s.need(type(header) is dict and header == {"alg": "ES256", "typ": s.TOKEN_TYPE, "kid": selected.kid}
               and type(claims) is dict and set(claims) == s.CLAIMS
               and tuple(claims[key] for key in ("iss", "aud", "scope", "epoch")) ==
                   (selected.issuer, selected.audience, selected.scope, selected.epoch),
               "KEYCHAIN_SIGNER_CONTEXT_MISMATCH")
        try:
            signing_input = b".".join(base64.urlsafe_b64encode(b.encode(value)).rstrip(b"=")
                                      for value in (header, claims))
        except (TypeError, ValueError, OverflowError):
            raise s.AuthorityError("KEYCHAIN_SIGNER_INPUT_INVALID") from None
        s.need(len(signing_input) + 87 <= jwt.MAX_TOKEN_BYTES, "KEYCHAIN_SIGNER_INPUT_INVALID")
        request = b.encode({"contract": BRIDGE, "keychain_path": str(cfg.keychain),
            "application_tag": cfg.application_tag,
            "expected_public_key_spki_base64": base64.b64encode(selected.public_key_spki).decode("ascii"),
            "signing_input_base64": base64.b64encode(signing_input).decode("ascii")})
        s.need(len(request) <= MAX_REQUEST_BYTES, "KEYCHAIN_SIGNER_INPUT_INVALID")
        self._check_files()
        raw = self._process(request)
        self._check_files()
        try:
            result = b.decode(raw)
            s.need(type(result) is dict and set(result) == {"contract", "request_sha256", "signature_base64"}
                   and result["contract"] == BRIDGE
                   and result["request_sha256"] == hashlib.sha256(request).hexdigest()
                   and type(result["signature_base64"]) is str, "KEYCHAIN_SIGNER_FAILED")
            signature = base64.b64decode(result["signature_base64"], validate=True)
            s.need(len(signature) == 64 and base64.b64encode(signature).decode("ascii") == result["signature_base64"],
                   "KEYCHAIN_SIGNER_FAILED")
        except (TypeError, ValueError):
            raise s.AuthorityError("KEYCHAIN_SIGNER_FAILED") from None
        return signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")
