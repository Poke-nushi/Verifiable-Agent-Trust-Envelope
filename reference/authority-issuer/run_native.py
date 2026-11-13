#!/usr/bin/env python3
"""Real local Hydra/OpenFGA -> signed HTTPS update -> VATE recording callback."""
import argparse
from contextlib import ExitStack
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading

from authority_issuer import AuthorityIssuer, Registration, selected_scope, s, b, c, jwt
from service_client import JsonService
from fixture_signer import FixtureSigner
from native_fixture import NativeFixture, AUDIENCE, PDP_OBJECT, BINARY_PINS, http, require, save
from authority_store import AuthorityStore
from https_source import HttpsSnapshotSource
from managed_verifier import ManagedAuthorityVerifier
import example as purchase


class RecordingService(JsonService):
    def __init__(self, fixture, kind, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fixture, self.kind = fixture, kind

    def request(self, path, **options):
        result = super().request(path, **options)
        # Never record the form carrying the access token or the HTTP headers.
        self.fixture.event(self.kind, path=path, response=result)
        return result


class Feed:
    """Fixture TLS delivery. Every successful GET polls the selected sources anew."""
    def __init__(self, issuer, runtime, openssl, openssl_sha256):
        require(jwt.file_sha(Path(openssl)) == openssl_sha256, "Selected OpenSSL hash changed")
        self.issuer, self.unavailable, self.tokens = issuer, False, []
        cert, key = runtime / "feed-cert.pem", runtime / "feed-key.pem"
        subprocess.run([str(openssl), "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-keyout", str(key), "-out", str(cert)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20, check=True)
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                try:
                    if self.path != "/authority" or owner.unavailable:
                        raise s.AuthorityError("FIXTURE_FEED_UNAVAILABLE")
                    raw = owner.issuer.publish()
                    owner.tokens.append(raw)
                except Exception:
                    self.send_response(503); self.end_headers(); return
                self.send_response(200)
                self.send_header("Content-Type", "application/jwt")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(raw))); self.end_headers()
                self.wfile.write(raw)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
            self.source = HttpsSnapshotSource(f"https://localhost:{self.server.server_port}/authority", ca_file=cert)
        except BaseException:
            self.server.server_close()
            raise

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(3)
        require(not self.thread.is_alive(), "TLS fixture did not stop")


def fresh_purchase(runtime_signer, actor_signer, now, suffix):
    original, request, policy = purchase.inputs()
    original["operation_id"] += suffix
    original["payload"]["order_id"] += suffix
    request.update(request_id=request["request_id"] + suffix, transaction_id=original["operation_id"],
        input_hash=b.object_hash(original), issued_at=b.core.iso(now - timedelta(seconds=1)),
        expires_at=b.core.iso(now + timedelta(seconds=180)))
    second = int((now - jwt.EPOCH).total_seconds())
    runtime_claims = {"iss": "urn:example:runtime-issuer", "sub": request["runtime"], "aud": request["audience"],
        "iat": second, "nbf": second, "exp": second + 180,
        "vate_context_hash": b.runtime_context_hash(b.encode(request), b.encode(original))}
    runtime_token = runtime_signer({"alg": "ES256", "kid": "runtime-key", "typ": jwt.TOKEN_TYPE}, runtime_claims)
    request["evidence_refs"].append({"type": "runtime_attestation", "uri": "urn:example:runtime-jwt",
        "media_type": jwt.MEDIA_TYPE, "digest": b.digest(runtime_token)})
    request_raw, original_raw = b.encode(request), b.encode(original)
    proof = actor_signer({"alg": "ES256", "kid": "actor-key", "typ": c.TOKEN_TYPE}, {
        "iss": request["actor"], "sub": request["actor"], "aud": request["audience"],
        "iat": second, "nbf": second, "exp": second + 180, "grant_id": "purchase-grant",
        "request_sha256": b.digest(request_raw)["value"], "original_sha256": b.digest(original_raw)["value"]})
    return original_raw, request_raw, policy, runtime_token, proof


def run(args):
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    observations = []
    def check(name, observed, expected):
        matched = b.encode(observed) == b.encode(expected)
        observations.append({"case": name, "observed": observed, "expected": expected, "matched": matched})
        save(args.output / "OBSERVATIONS.json", observations)
        require(matched, "Observation mismatch: " + name)
    with tempfile.TemporaryDirectory(prefix="vate-authority-issuer-") as directory, ExitStack() as stack:
        runtime = Path(directory)
        fixture = NativeFixture(args.output, runtime, args.native_root)
        stack.callback(fixture.cleanup)
        fixture.setup()
        status, _ = fixture.manage(fixture.owner_key, fixture.update_body("user_permission"))
        require(status == 200, "Owner permission setup failed")
        token = fixture.issue_token()
        signers = [stack.enter_context(FixtureSigner(args.node, args.node_sha256)) for _ in range(3)]
        root_signer, runtime_signer, actor_signer = signers
        now = b.core.utc_now()
        second = int((now - jwt.EPOCH).total_seconds())
        first = fresh_purchase(runtime_signer, actor_signer, now, "-A")
        second_request = fresh_purchase(runtime_signer, actor_signer, now, "-B")
        request = b.decode(first[1])
        runtime_grant = jwt.RuntimeIssuerGrant("urn:example:runtime-issuer", "runtime-key", runtime_signer.public_key,
            request["runtime"], request["audience"], second - 5, second + 240)
        grant = c.DelegationGrant("purchase-grant", request["principal"], request["actor"], "actor-key",
            actor_signer.public_key, request["runtime"], request["audience"], request["target"]["resource"],
            request["action"], "USD", "120.00", ("merchant.checkout.confirm",), second - 5, second + 240)
        registration = Registration(fixture.hydra + "/", AUDIENCE, "alice", "purchase_agent", fixture.store_id,
            fixture.model_id, "user:alice", PDP_OBJECT, runtime_grant, grant)
        oauth = RecordingService(fixture, "issuer_introspection", fixture.admin, development_loopback=True)
        pdp = RecordingService(fixture, "issuer_pdp", fixture.fga,
            authorization="Bearer " + fixture.backend_key, development_loopback=True)
        selection = s.AuthoritySelection("urn:example:merchant-authority", "urn:example:verifier",
            selected_scope(registration, oauth, pdp, 120), "epoch-1", "authority-key", root_signer.public_key, 1, 120)
        verifier = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=selection,
            node=args.node, node_sha256=args.node_sha256)
        publisher_state = AuthorityStore.create(runtime / "publisher", verifier=verifier)
        recipient = AuthorityStore.create(runtime / "recipient", verifier=verifier)
        def publisher(state):
            return AuthorityIssuer(registration=registration, oauth=oauth, pdp=pdp, state=state,
                token_provider=lambda: token, signer=root_signer, ttl_seconds=120)
        feed = Feed(publisher(publisher_state), runtime, args.openssl, args.openssl_sha256)
        stack.callback(feed.close)
        state_type = b.durable_state_module().DurableStateStore
        dispatch_state = state_type.create(runtime / "dispatch", scope="native-authority-issuer", verifier_id=selection.audience)
        calls = []
        def managed():
            return ManagedAuthorityVerifier(source=recipient, verifier_id=selection.audience, policy=first[2],
                state_store=dispatch_state, execute=lambda *values: calls.append(values),
                max_runtime_token_age_seconds=180, max_caller_token_age_seconds=180)
        current = managed()
        def intake(): return recipient.refresh(feed.source)
        def admit(values):
            original, admission, _, evidence, proof = values
            return current.admit(admission, original=original,
                evidence_artifacts={"urn:example:runtime-jwt": evidence}, caller_proof=proof)
        def denied(name, pending, proof):
            count = len(calls)
            try:
                current.dispatch(pending, caller_proof=proof)
            except (b.Invalid, s.AuthorityError) as exc:
                check(name, {"cause": exc.cause, "new_callback_calls": len(calls) - count},
                      {"cause": "CALLER_AUTHORIZATION_FAILED", "new_callback_calls": 0})
            else:
                raise RuntimeError("Dispatch unexpectedly allowed: " + name)
        def unavailable_dispatch(name, pending, proof):
            count = len(calls)
            try:
                current.dispatch(pending, caller_proof=proof)
            except (b.Invalid, s.AuthorityError) as exc:
                check(name, {"cause": exc.cause, "unavailable": recipient.status()["unavailable"],
                             "new_callback_calls": len(calls) - count},
                      {"cause": "AUTHORITY_NOT_AVAILABLE", "unavailable": True, "new_callback_calls": 0})
            else:
                raise RuntimeError("Unavailable source dispatched: " + name)
        def refresh_fails(name):
            previous = recipient.status()["revision"]
            try:
                intake()
            except s.AuthorityError:
                check(name, [recipient.status()["unavailable"], recipient.status()["revision"]], [True, previous])
            else:
                raise RuntimeError("Refresh unexpectedly succeeded: " + name)

        intake()
        pending, pending_b = admit(first), admit(second_request)
        admitted_receipt = pending.receipt
        check("native-permit-admits-without-dispatch", [b.decode(pending.receipt)["decision"]["outcome"], len(calls)],
              ["attenuate", 0])
        old = feed.tokens[0]
        # A separate client's logical policy object cannot supply this
        # registration's permission/delegation through a shared resource edge.
        other_object = "purchase:alice_other_agent_checkout"
        status, _ = fixture.backend(f"/stores/{fixture.store_id}/write", {
            "authorization_model_id": fixture.model_id, "writes": {"tuple_keys": [
                {"user": "user:alice", "relation": relation, "object": other_object}
                for relation in ("user_permission", "delegation")]}})
        require(status == 200, "Other fixture registration setup failed")
        other = pdp.request(f"/stores/{fixture.store_id}/check", body={"authorization_model_id": fixture.model_id,
            "consistency": "HIGHER_CONSISTENCY", "tuple_key": {"user": "user:alice", "relation": "can_execute",
            "object": other_object}})
        check("other-registration-is-independently-permitted", other.get("allowed"), True)
        fixture.phase = "owner-revocation"
        require(fixture.manage(fixture.owner_key, fixture.update_body("user_permission", "remove"))[0] == 200,
                "Owner revocation failed")
        intake(); denied("owner-revocation-stops-dispatch", pending, first[4])
        # Reopen all durable stores with their retained anchors, not fresh directories.
        publisher_state = AuthorityStore(publisher_state.directory, verifier=verifier, expected_anchor=publisher_state.anchor)
        feed.issuer = publisher(publisher_state)
        recipient = AuthorityStore(recipient.directory, verifier=verifier, expected_anchor=recipient.anchor)
        dispatch_state = state_type(dispatch_state.directory, expected_anchor=dispatch_state.anchor)
        current = managed(); pending = current.restore_admission(request["request_id"])
        pending_b = current.restore_admission(b.decode(second_request[1])["request_id"])
        for name, selected in (("publisher", publisher_state), ("recipient", recipient)):
            try: selected.accept(old)
            except s.AuthorityError as exc: check(name + "-restart-rejects-old-revision", exc.cause, "AUTHORITY_ROLLBACK")
            else: raise RuntimeError("Old revision accepted")
        denied("restart-retains-revocation", pending, first[4])
        require(fixture.manage(fixture.owner_key, fixture.update_body("user_permission"))[0] == 200,
                "Owner restore failed")
        intake()
        fixture.phase = "delegation-revocation"
        require(fixture.manage(fixture.as_key, fixture.update_body("delegation", "remove"))[0] == 200,
                "Delegation revocation failed")
        intake(); denied("delegation-revocation-stops-dispatch", pending, first[4])
        check("other-registration-cannot-supply-selected-delegation",
            b.decode(jwt.decode_segment(feed.tokens[-1].split(b".")[1], jwt.MAX_TOKEN_BYTES))["delegation_grants"], [])
        require(fixture.manage(fixture.as_key, fixture.update_body("delegation"))[0] == 200, "Delegation restore failed")
        intake()
        fixture.phase = "delivery-failure-recovery"
        feed.unavailable = True
        refresh_fails("delivery-failure-marks-recipient-unavailable")
        recipient = AuthorityStore(recipient.directory, verifier=verifier, expected_anchor=recipient.anchor)
        current = managed()
        try: current.restore_admission(request["request_id"])
        except s.AuthorityError as exc: check("restart-cannot-restore-while-unavailable", exc.cause, "AUTHORITY_NOT_AVAILABLE")
        else: raise RuntimeError("Restore ignored unavailable source")
        unavailable_dispatch("restart-cannot-clear-delivery-failure", pending, first[4])
        feed.unavailable = False
        intake()
        pending = current.restore_admission(request["request_id"])
        pending_b = current.restore_admission(b.decode(second_request[1])["request_id"])
        result = current.dispatch(pending, caller_proof=first[4])
        check("fresh-recovery-executes-original-receipt-once", [len(calls), calls[0][0] == pending.effective,
            pending.receipt == admitted_receipt], [1, True, True])
        # Lose and restore the fixture's service credential; never touch a live account.
        fixture.phase = "source-failure-recovery"
        pdp.authorization = "Bearer invalid-fixture-credential"
        refresh_fails("pdp-credential-failure-blocks-publication")
        check("publisher-persists-unavailability", publisher_state.status()["unavailable"], True)
        unavailable_dispatch("pdp-failure-stops-pending-dispatch", pending_b, second_request[4])
        pdp.authorization = "Bearer " + fixture.backend_key
        intake()
        check("fresh-source-recovery-clears-unavailability",
              [publisher_state.status()["unavailable"], recipient.status()["unavailable"]], [False, False])
        fixture.phase = "native-pdp-stop"
        pdp_process = next(proc for name, proc in fixture.processes if name == "openfga")
        pdp_process.terminate(); pdp_process.wait(timeout=10)
        refresh_fails("native-pdp-unavailable-blocks-publication")
        unavailable_dispatch("native-pdp-unavailable-stops-dispatch", pending_b, second_request[4])
        fixture.phase = "oauth-revocation"
        status, _, _ = http(fixture.hydra + "/oauth2/revoke", method="POST", form={
            "token": token, "client_id": "purchase_agent", "token_type_hint": "access_token"})
        require(status == 200, "Native OAuth revocation failed")
        offset = len(fixture.events)
        intake()
        check("inactive-oauth-skips-pdp", [any(event["kind"] == "issuer_introspection"
            and event["response"].get("active") is False for event in fixture.events[offset:]),
            any(event["kind"] == "issuer_pdp" for event in fixture.events[offset:])], [True, False])
        denied("oauth-revocation-stops-dispatch", pending_b, second_request[4])
        exported = {"original.json": pending.original, "admission-request.json": pending.request,
            "admission-receipt.json": pending.receipt, "effective.json": pending.effective,
            "pre-dispatch.json": result.checkpoint, "registration.json": b.encode(registration.descriptor()),
            "selection.json": b.encode(selection.descriptor()), "recipient-status.json": b.encode(recipient.status()),
            "publisher-status.json": b.encode(publisher_state.status())}
        for index, raw in enumerate(feed.tokens, 1):
            exported[f"snapshot-{index:02d}.jwt"] = raw
        forbidden = [item.encode() for item in fixture.sensitive] + [first[4], second_request[4]]
        require(not any(secret in raw for raw in exported.values() for secret in forbidden), "Credential export detected")
        for name, raw in exported.items(): (args.output / name).write_bytes(raw)
    # Cleanup has now saved redacted fixture events/logs and stopped owned processes.
    require(not any(secret in path.read_bytes() for path in args.output.iterdir() if path.is_file()
                    for secret in forbidden), "Credential found in saved fixture output")
    sources = {str(path.relative_to(s.ROOT)): b.digest(path.read_bytes()) for family in
        ("authority-issuer", "authority-updates", "caller-authority", "runtime-jwt", "request-binding", "vate-verifier-core")
        for path in (s.ROOT / "reference" / family).rglob("*")
        if path.suffix in (".py", ".mjs") and "__pycache__" not in path.parts}
    report = {"profile": "vate-hydra-openfga-authority-issuer-v1", "all_matched": True,
        "evidence_kind": "native-loopback-services-recording-callback", "observations": observations,
        "native_binary_sha256": BINARY_PINS, "node_sha256": args.node_sha256,
        "openssl_sha256": args.openssl_sha256, "sources": sources,
        "artifacts": {path.name: b.digest(path.read_bytes()) for path in sorted(args.output.iterdir()) if path.is_file()},
        "owned_processes_stopped": all(proc.poll() is not None for _, proc in fixture.processes),
        "raw_credentials_exported": False, "callback_calls": len(calls)}
    save(args.output / "RUN.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-root", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--node-sha256", required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--openssl-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args)
    print(json.dumps({"all_matched": report["all_matched"], "cases": len(report["observations"]),
                      "callback_calls": report["callback_calls"]}))


if __name__ == "__main__":
    main()
