"""Owned local processes for the native lifecycle example; not a deployment service.

The spawn pipes carry trusted fixture configuration (including temporary service
credentials). They are not a network API and must never accept untrusted pickle.
"""
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
import multiprocessing
import os
from pathlib import Path
import ssl
import sys
import threading
import time

from authority_issuer import AuthorityIssuer, Registration, s, b, c, jwt
from authority_store import AuthorityStore
from service_client import JsonService
from managed_verifier import ManagedAuthorityVerifier
from refresh_lifecycle import RefreshingAuthorityVerifier
from supervised_https import SupervisedHttpsSnapshotSource

sys.path.insert(0, str(s.ROOT / "reference/authority-keychain"))
from keychain_signer import KeychainSigner, PROFILE as KEYCHAIN_PROFILE

CRASH_EXIT = 73


def role_configuration(role, config):
    """Do not send publisher credentials, key configuration or ledger to the recipient."""
    fields = ("selection", "node", "node_sha256", "cert") + {
        "publisher": ("publisher_directory", "publisher_anchor", "registration", "output", "oauth", "pdp",
                      "pdp_credential", "token", "helper", "helper_sha256", "keychain", "port", "tls_key"),
        "recipient": ("recipient_directory", "recipient_anchor", "dispatch_directory", "dispatch_anchor",
                      "policy", "effects", "url"),
    }[role]
    return {name: config[name] for name in fields}


def append_record(path, value):
    """Persist only explicitly selected, non-secret fixture observations."""
    raw = b.encode(value) + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        with os.fdopen(fd, "ab", buffering=0, closefd=False) as stream:
            stream.write(raw)
            os.fsync(fd)
    finally:
        os.close(fd)


def verifier(config):
    return s.SnapshotVerifier(expected_profile=s.PROFILE,
        selection=s.AuthoritySelection(**config["selection"]),
        node=config["node"], node_sha256=config["node_sha256"])


def open_authority(config, name):
    # Creation belongs to the controller's explicit initial setup, never reopen.
    return AuthorityStore(config[name + "_directory"], verifier=verifier(config),
                          expected_anchor=config[name + "_anchor"])


class ObservedService(JsonService):
    def __init__(self, kind, log, *args, **kwargs):
        self.kind, self.log = kind, log
        super().__init__(*args, **kwargs)

    def request(self, path, **options):
        entry = {"kind": self.kind, "path": path, "pid": os.getpid()}
        try:
            result = super().request(path, **options)
        except Exception:
            append_record(self.log, {**entry, "returned": False})
            raise
        # Never log forms, headers, credentials or arbitrary source response text.
        append_record(self.log, {**entry, "returned": True,
            **{key: result[key] for key in ("active", "allowed") if type(result.get(key)) is bool}})
        return result


def publisher(config, channel):
    state = open_authority(config, "publisher")
    registration = dict(config["registration"])
    registration["runtime_grant"] = jwt.RuntimeIssuerGrant(**registration["runtime_grant"])
    registration["delegation_grant"] = c.DelegationGrant(**registration["delegation_grant"])
    registration = Registration(**registration)
    log = Path(config["output"]) / "publisher-events.jsonl"
    oauth = ObservedService("introspection", log, config["oauth"], development_loopback=True)
    pdp = ObservedService("permission", log, config["pdp"], development_loopback=True,
                          authorization=config["pdp_credential"])
    signer = KeychainSigner(expected_profile=KEYCHAIN_PROFILE,
        helper=config["helper"], helper_sha256=config["helper_sha256"],
        keychain=config["keychain"], application_tag="lifecycle-key",
        selection=state.verifier.selection)
    issuer = AuthorityIssuer(registration=registration, oauth=oauth, pdp=pdp, state=state,
        token_provider=lambda: config["token"], signer=signer, ttl_seconds=120)
    gate = threading.Lock()
    delivery = {"unavailable": False}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            with gate:
                try:
                    s.need(self.path == "/authority" and not delivery["unavailable"], "FIXTURE_FEED_UNAVAILABLE")
                    raw = issuer.publish()
                    revision = state.status()["revision"]
                    target = Path(config["output"]) / f"snapshot-{revision:04d}.jwt"
                    with target.open("xb") as stream:
                        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                    append_record(log, {"kind": "published", "pid": os.getpid(),
                        "revision": revision, "snapshot_sha256": b.digest(raw)["value"]})
                except Exception as error:
                    append_record(log, {"kind": "delivery_failed", "pid": os.getpid(),
                        "cause": getattr(error, "cause", type(error).__name__)})
                    self.send_response(503); self.end_headers(); return
                self.send_response(200)
                self.send_header("Content-Type", "application/jwt")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except (OSError, ssl.SSLError):
                    # Issuance has committed; a disconnected receiver has not installed it.
                    append_record(log, {"kind": "delivery_disconnected", "pid": os.getpid(), "revision": revision})

    server = HTTPServer(("127.0.0.1", config["port"]), Handler)
    thread = None
    try:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(config["cert"], config["tls_key"])
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        channel.send({"ok": True, "pid": os.getpid(), "authority": state.status(),
                      "public_key_sha256": b.digest(state.verifier.selection.public_key_spki)["value"]})
        while True:
            command = channel.recv()
            if command["action"] == "stop":
                channel.send({"ok": True}); break
            with gate:
                if command["action"] == "delivery":
                    delivery["unavailable"] = command["unavailable"]
                elif command["action"] != "status":
                    raise ValueError("Unknown fixture action")
                channel.send({"ok": True, "authority": state.status()})
    finally:
        if thread is not None:
            server.shutdown(); thread.join(3)
        server.server_close()


def recipient(config, channel):
    source = open_authority(config, "recipient")
    state = b.durable_state_module().DurableStateStore(config["dispatch_directory"],
        expected_anchor=config["dispatch_anchor"])
    operation = {"request_id": None, "crash": False}

    def execute(effective, checkpoint):
        append_record(config["effects"], {"pid": os.getpid(), "request_id": operation["request_id"],
            "effective_sha256": b.digest(effective)["value"], "checkpoint_sha256": b.digest(checkpoint)["value"]})
        if operation["crash"]:
            # Only this fixture process exits, after its disposable recording effect.
            os._exit(CRASH_EXIT)

    managed = ManagedAuthorityVerifier(source=source, verifier_id=source.verifier.selection.audience,
        policy=config["policy"], state_store=state, execute=execute,
        max_runtime_token_age_seconds=180, max_caller_token_age_seconds=180)
    fetch = SupervisedHttpsSnapshotSource(config["url"], ca_file=config["cert"], timeout_seconds=5)
    session = RefreshingAuthorityVerifier(verifier=managed, fetch=fetch,
        refresh_interval_seconds=0.1, retry_interval_seconds=0.1)
    pending = {}

    def status(request_id=None):
        result = {"authority": source.status(), "refresh": asdict(session.status())}
        if request_id:
            retained = session.dispatch_status(request_id)
            result.update(history=retained.state, record=retained.record, checkpoint=retained.checkpoint)
        return result

    try:
        channel.send({"ok": True, "pid": os.getpid(), **status()})
        while True:
            command = channel.recv()
            action, request_id = command["action"], command.get("request_id")
            try:
                if action == "stop":
                    session.close(); channel.send({"ok": True}); break
                result = {}
                if action == "poll":
                    delay = session.status().next_attempt_in_seconds
                    if delay:
                        time.sleep(delay)
                    result["installed"] = session.poll()
                elif action == "admit":
                    original, request, _policy, evidence, proof = command["inputs"]
                    bound = session.admit(request, original=original,
                        evidence_artifacts={"urn:example:runtime-jwt": evidence}, caller_proof=proof)
                    pending[request_id] = bound
                    result["receipt"] = bound.receipt
                    result["effective"] = bound.effective
                elif action in ("restore", "dispatch"):
                    if request_id not in pending:
                        pending[request_id] = session.restore_admission(request_id)
                    bound = pending[request_id]
                    result["receipt"] = bound.receipt
                    if action == "dispatch":
                        operation.update(request_id=request_id, crash=command.get("crash", False))
                        dispatched = session.dispatch(bound, caller_proof=command["proof"])
                        result["checkpoint"] = dispatched.checkpoint
                elif action != "status":
                    raise ValueError("Unknown fixture action")
                channel.send({"ok": True, **result, **status(request_id)})
            except Exception as error:
                channel.send({"ok": False, "cause": getattr(error, "cause", type(error).__name__),
                              **status(request_id)})
    finally:
        session.close()


def fixture_process(role, config, channel):
    try:
        {"publisher": publisher, "recipient": recipient}[role](config, channel)
    except EOFError:
        pass
    except Exception as error:
        channel.send({"ok": False, "cause": getattr(error, "cause", type(error).__name__)})
    finally:
        channel.close()


class OwnedProcess:
    """Spawn/reap only this fixture's child; no shell or persistent daemon."""

    def __init__(self, role, config, *, target=fixture_process, timeout=20):
        context = multiprocessing.get_context("spawn")
        self.channel, child = context.Pipe()
        self.process = context.Process(target=target, args=(role, config, child))
        self.timeout, self.role = timeout, role
        try:
            self.process.start()
            child.close()
            self.initial = self.receive()
            if self.initial.get("ok") is not True:
                raise RuntimeError("Fixture startup failed: " + self.initial.get("cause", "invalid response"))
        except BaseException:
            if self.process.pid is not None:
                self.kill()
            else:
                self.channel.close()
            raise
        finally:
            child.close()

    def receive(self):
        if not self.channel.poll(self.timeout):
            self.kill()
            raise RuntimeError("Fixture response timed out")
        try:
            response = self.channel.recv()
        except EOFError:
            self.process.join(5)
            raise RuntimeError("Fixture exited without a response") from None
        if type(response) is not dict or type(response.get("ok")) is not bool:
            raise RuntimeError("Invalid fixture response")
        return response

    def ask(self, action, **values):
        self.channel.send({"action": action, **values})
        return self.receive()

    def crash_during_dispatch(self, request_id, proof):
        self.channel.send({"action": "dispatch", "request_id": request_id, "proof": proof, "crash": True})
        self.process.join(self.timeout)
        if self.process.is_alive():
            self.kill(); raise RuntimeError("Fixture callback did not exit")
        if self.process.exitcode != CRASH_EXIT:
            raise RuntimeError("Fixture did not reach its recording callback")
        self.channel.close()

    def kill(self):
        if self.process.is_alive():
            self.process.kill()
        self.process.join(5)
        self.channel.close()
        if self.process.is_alive():
            raise RuntimeError("Fixture process cleanup failed")

    def close(self):
        try:
            if self.process.is_alive():
                response = self.ask("stop")
                if response.get("ok") is not True:
                    raise RuntimeError("Fixture stop failed")
                self.process.join(5)
                if self.process.is_alive():
                    raise RuntimeError("Fixture did not stop")
        finally:
            self.kill()
