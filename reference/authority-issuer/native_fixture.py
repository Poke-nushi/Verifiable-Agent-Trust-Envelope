"""Owned loopback Hydra/OpenFGA fixture, with real OAuth code/PKCE.

Synthetic login/consent; fixed policy writers and one purchase registration.
No external resource action. Native credentials and databases are temporary.
"""
import base64
import hashlib
import hmac
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, HTTPCookieProcessor, ProxyHandler

from authority_issuer import MODEL

AUDIENCE = "urn:vate:authority-issuer:purchase"
PDP_OBJECT = "purchase:alice_purchase_agent_checkout"
BINARY_PINS = {
    "hydra": "50f7f8beadfe0209a0e44797f41e69d87e4a3226faa21a20a2a25cf8cfe94a4b",
    "openfga": "891dee8221d6a535e456c48ef1e59a25e80f26e7e60e2a06af86a4ff05f04178",
}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else encoded(value)).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def opener():
    return build_opener(ProxyHandler({}), NoRedirect(), HTTPCookieProcessor(CookieJar()))


def http(url, *, method="GET", body=None, form=None, bearer=None, client=None):
    parsed = urlsplit(url)
    require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1", "Non-loopback URL refused")
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = encoded(body)
        headers["Content-Type"] = "application/json"
    if form is not None:
        data = urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    try:
        response = (client or opener()).open(Request(url, data=data, method=method, headers=headers), timeout=10)
    except HTTPError as exc:
        response = exc
    with response:
        raw = response.read(2_000_001)
        require(len(raw) <= 2_000_000, "Oversized HTTP response")
        try:
            result = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            result = {"non_json_response_bytes": len(raw)}
        return response.code, dict(response.headers), result


def free_ports(count):
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


class NativeFixture:
    def __init__(self, output, runtime, native_root):
        self.native_root = native_root
        self.output, self.runtime = output, runtime
        hp, ha, fh, fg, bridge = free_ports(5)
        self.hydra = f"http://127.0.0.1:{hp}"
        self.admin = f"http://127.0.0.1:{ha}"
        self.fga = f"http://127.0.0.1:{fh}"
        self.bridge = f"http://127.0.0.1:{bridge}"
        self.ports = {"hydra_public": hp, "hydra_admin": ha, "fga_http": fh, "fga_grpc": fg, "bridge": bridge}
        self.backend_key, self.as_key, self.owner_key = [secrets.token_urlsafe(32) for _ in range(3)]
        self.sensitive = [self.backend_key, self.as_key, self.owner_key]
        self.events, self.cases, self.processes, self.log_handles = [], [], [], []
        self.phase, self.operations = "setup", 0
        self.lock = threading.RLock()
        self.server = None
        self.thread = None
        self.store_id = self.model_id = None


    def event(self, kind, **fields):
        with self.lock:
            record = {"seq": len(self.events) + 1, "phase": self.phase, "kind": kind, **fields}
            self.events.append(record)


    def backend(self, suffix, body=None, *, method="POST", credential=None):
        status, _, result = http(self.fga + suffix, method=method, body=body,
                                 bearer=credential or self.backend_key)
        self.event("openfga_http", path=suffix, method=method, request=body, status=status, response=result)
        return status, result


    def tuple(self, namespace):
        return {"user": "user:alice", "relation": namespace, "object": PDP_OBJECT}


    def manage(self, credential, body):
        status, _, result = http(self.bridge + "/manage", method="POST", body=body, bearer=credential)
        return status, result


    def update_body(self, namespace, operation="add"):
        return {"namespace": namespace, "operation": operation, "tenant": "demo", "user": "alice",
                "client": "purchase_agent" if namespace == "delegation" else None,
                "action": "commerce.purchase", "resource": PDP_OBJECT}


    def introspect(self, token):
        status, _, data = http(self.admin + "/admin/oauth2/introspect", method="POST", form={"token": token})
        require(status == 200, "Hydra introspection failed")
        keep = {k: data[k] for k in ("active", "client_id", "sub", "scope", "exp", "iat", "aud", "iss", "token_use") if k in data}
        self.event("hydra_introspection", token_sha256=sha(token.encode()), claims=keep)
        return keep


    def start_process(self, name, args, env):
        log = (self.runtime / (name + ".log")).open("wb")
        self.log_handles.append((name, log))
        proc = subprocess.Popen(args, cwd=self.runtime, env=env, stdout=log, stderr=subprocess.STDOUT)
        self.processes.append((name, proc))
        self.event("process_started", name=name, pid=proc.pid)


    def wait_ready(self, url):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            require(all(p.poll() is None for _, p in self.processes), "Component exited during startup")
            try:
                if http(url)[0] == 200:
                    return
            except (URLError, TimeoutError, ConnectionError):
                pass
            time.sleep(0.1)
        raise RuntimeError("Component readiness timed out")


    def setup(self):
        for name, expected in BINARY_PINS.items():
            require(sha((self.native_root / "bin" / name).read_bytes()) == expected, "Native binary hash changed")
        system_secret = secrets.token_urlsafe(32)
        self.sensitive.append(system_secret)
        config = {"dsn": "sqlite://" + str(self.runtime / "hydra.sqlite") + "?_fk=true",
                  "serve": {"public": {"host": "127.0.0.1", "port": self.ports["hydra_public"]},
                            "admin": {"host": "127.0.0.1", "port": self.ports["hydra_admin"]}},
                  "urls": {"self": {"issuer": self.hydra + "/"}, "login": self.bridge + "/login",
                           "consent": self.bridge + "/consent"},
                  "secrets": {"system": [system_secret]}, "log": {"level": "error", "format": "json"},
                  "sqa": {"opt_out": True}, "ttl": {"access_token": "10m"}}
        config_path = self.runtime / "hydra.json"
        save(config_path, config)
        config_path.chmod(0o600)
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": str(self.runtime)}
        command = [str(self.native_root / "bin/hydra"), "migrate", "sql", "up", "-e", "--yes", "--config", str(config_path)]
        migration = subprocess.run(command, cwd=self.runtime, env=env, capture_output=True, timeout=30)
        require(migration.returncode == 0, "Hydra SQLite migration failed")
        self.start_process("hydra", [str(self.native_root / "bin/hydra"), "serve", "all", "--dev", "--sqa-opt-out", "--config", str(config_path)], env)
        fga_env = {**env, "OPENFGA_AUTHN_PRESHARED_KEYS": self.backend_key}
        self.start_process("openfga", [str(self.native_root / "bin/openfga"), "run", "--http-addr", f"127.0.0.1:{self.ports['fga_http']}",
             "--grpc-addr", f"127.0.0.1:{self.ports['fga_grpc']}", "--authn-method", "preshared",
             "--datastore-engine", "memory", "--playground-enabled=false", "--metrics-enabled=false",
             "--profiler-enabled=false", "--trace-enabled=false", "--log-level", "error"], fga_env)
        self.wait_ready(self.admin + "/health/ready")
        self.wait_ready(self.fga + "/healthz")
        status, result = self.backend("/stores", {"name": "vate-authority-issuer-fixture"})
        require(status in (200, 201), "OpenFGA store creation failed")
        self.store_id = result["id"]
        status, result = self.backend(f"/stores/{self.store_id}/authorization-models", MODEL)
        require(status in (200, 201), "OpenFGA model creation failed")
        self.model_id = result["authorization_model_id"]
        self.server = ThreadingHTTPServer(("127.0.0.1", self.ports["bridge"]), self.handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        status, _, client = http(self.admin + "/admin/clients", method="POST", body={
            "client_id": "purchase_agent", "grant_types": ["authorization_code"], "response_types": ["code"],
            "redirect_uris": [self.bridge + "/callback"], "token_endpoint_auth_method": "none", "scope": "purchase.execute",
            "audience": [AUDIENCE]})
        require(status == 201 and client["client_id"] == "purchase_agent", "OAuth client creation failed")
        save(self.output / "CONFIGURATION.json", {"components": self.ports, "openfga_store": self.store_id,
             "openfga_model_id": self.model_id, "openfga_model": MODEL,
             "grant_mode": "explicit persisted-grant mode; introspection scope is recorded but not converted to permission",
             "required_token_audience": AUDIENCE,
             "login_and_consent": "synthetic fixture for alice/purchase_agent, using real Hydra challenges",
             "management_auth": "three distinct random keys: AS->PAP, owner->PAP, PAP->OpenFGA",
             "storage": "Hydra temporary SQLite, OpenFGA in memory", "tls": "HTTP loopback only; Hydra development mode",
             "concurrency": "sequential experiment; one intersection Check; no cross-service atomicity"})


    def handler(self):
        trial = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, value, location=None):
                data = encoded(value)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                if location:
                    self.send_header("Location", location)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path, query = urlsplit(self.path).path, parse_qs(urlsplit(self.path).query)
                try:
                    if path not in ("/login", "/consent"):
                        return self.reply(404, {"error": "unknown_path"})
                    kind = path[1:]
                    challenge = query[kind + "_challenge"][0]
                    trial.sensitive.append(challenge)
                    endpoint = trial.admin + "/admin/oauth2/auth/requests/" + kind + "?" + urlencode({kind + "_challenge": challenge})
                    status, _, request = http(endpoint)
                    require(status == 200 and request["client"]["client_id"] == "purchase_agent", "Unexpected OAuth challenge")
                    if kind == "login":
                        accepted = {"subject": "alice", "remember": False}
                        trial.event("synthetic_login", subject="alice", client="purchase_agent")
                    else:
                        require(request["subject"] == "alice" and request.get("requested_scope") == ["purchase.execute"], "Unexpected consent scope")
                        status, _ = trial.manage(trial.as_key, trial.update_body("delegation"))
                        require(status == 200, "Consent grant policy write failed")
                        accepted = {"grant_scope": ["purchase.execute"], "grant_access_token_audience": request.get("requested_access_token_audience", []), "remember": False}
                        trial.event("synthetic_consent", subject="alice", client="purchase_agent", scope=["purchase.execute"])
                    status, _, result = http(trial.admin + "/admin/oauth2/auth/requests/" + kind + "/accept?" + urlencode({kind + "_challenge": challenge}), method="PUT", body=accepted)
                    require(status == 200, "OAuth challenge acceptance failed")
                    self.reply(302, {}, result["redirect_to"])
                except Exception as exc:
                    trial.event("handler_error", path=path, error_type=type(exc).__name__)
                    self.reply(500, {"error": "fixture_login_consent_failed"})

            def do_POST(self):
                path = urlsplit(self.path).path
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 8192:
                        return self.reply(400, {"error": "invalid_body_size"})
                    body = json.loads(self.rfile.read(size))
                    auth = self.headers.get("Authorization", "")
                    token = auth[7:] if auth.startswith("Bearer ") else ""
                    if path == "/manage":
                        writer = next((name for name, key in (("as", trial.as_key), ("owner", trial.owner_key)) if hmac.compare_digest(token, key)), None)
                        if writer is None:
                            return self.reply(401, {"error": "unknown_writer"})
                        valid = any(body == trial.update_body(ns, op) for ns in ("delegation", "user_permission") for op in ("add", "remove"))
                        if not valid:
                            return self.reply(400, {"error": "unsupported_update"})
                        allowed = "delegation" if writer == "as" else "user_permission"
                        if body["namespace"] != allowed:
                            trial.event("pap_rejection", writer=writer, body=body, reason="writer_namespace_mismatch")
                            return self.reply(403, {"error": "writer_namespace_mismatch"})
                        native = {"authorization_model_id": trial.model_id,
                                  "writes" if body["operation"] == "add" else "deletes": {"tuple_keys": [trial.tuple(body["namespace"])]}}
                        status, data = trial.backend(f"/stores/{trial.store_id}/write", native)
                        require(status == 200, "Native policy update failed")
                        trial.event("pap_applied", writer=writer, body=body)
                        return self.reply(200, {"status": "applied", "writer": writer})
                    self.reply(404, {"error": "unknown_path"})
                except Exception as exc:
                    trial.event("handler_error", path=path, error_type=type(exc).__name__)
                    self.reply(503, {"decision": "deny", "reason": "dependency_or_handler_error", "operations": trial.operations})

        return Handler


    def issue_token(self):
        browser_client = opener()
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        state = secrets.token_urlsafe(24)
        self.sensitive.extend([verifier, state])
        url = self.hydra + "/oauth2/auth?" + urlencode({"response_type": "code", "client_id": "purchase_agent", "redirect_uri": self.bridge + "/callback",
             "scope": "purchase.execute", "audience": AUDIENCE, "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})
        code = None
        for _ in range(12):
            status, headers, _ = http(url, client=browser_client)
            self.event("oauth_redirect_http", request_path=urlsplit(url).path, status=status,
                       redirect_path=urlsplit(headers.get("Location", headers.get("location", ""))).path)
            require(status in (302, 303), "OAuth redirect flow failed")
            url = headers.get("Location", headers.get("location"))
            require(url is not None, "Missing OAuth redirect")
            parsed = urlsplit(url)
            require(parsed.hostname == "127.0.0.1" and parsed.port in self.ports.values(), "Unexpected redirect target")
            if url.startswith(self.bridge + "/callback?"):
                values = parse_qs(parsed.query)
                require(values.get("state") == [state] and "code" in values, "OAuth state/code mismatch")
                code = values["code"][0]
                self.sensitive.append(code)
                break
        require(code is not None, "OAuth redirect limit")
        status, _, result = http(self.hydra + "/oauth2/token", method="POST", form={"grant_type": "authorization_code", "client_id": "purchase_agent",
             "code": code, "redirect_uri": self.bridge + "/callback", "code_verifier": verifier})
        require(status == 200 and "access_token" in result, "OAuth token exchange failed")
        self.event("oauth_token_http", status=status, grant_type="authorization_code", pkce_method="S256", state_matched=True)
        token = result["access_token"]
        self.sensitive.append(token)
        self.event("oauth_code_pkce_complete", token_sha256=sha(token.encode()), token_type=result.get("token_type"), expires_in=result.get("expires_in"), scope=result.get("scope"))
        return token


    def cleanup(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
        for name, proc in reversed(self.processes):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
            self.event("process_stopped", name=name, pid=proc.pid, returncode=proc.returncode)
        for name, log in self.log_handles:
            log.close()
            content = (self.runtime / (name + ".log")).read_text(errors="replace")
            for secret in sorted(self.sensitive, key=len, reverse=True):
                content = content.replace(secret, "[REDACTED_EPHEMERAL_CREDENTIAL]")
            (self.output / (name + ".log")).write_text(content)
        save(self.output / "EVENTS.json", self.events)

