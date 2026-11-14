#!/usr/bin/env python3
"""Native IAM, persistent fixture key, supervised intake and process recovery."""
import argparse
import base64
from contextlib import ExitStack
from dataclasses import asdict
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

from authority_issuer import Registration, selected_scope, s, b, c, jwt
from authority_store import AuthorityStore
from fixture_signer import FixtureSigner
from service_client import JsonService
from native_fixture import NativeFixture, AUDIENCE, PDP_OBJECT, BINARY_PINS, http, require, save
from run_native import fresh_purchase
from lifecycle_fixture import OwnedProcess, append_record, role_configuration


class DisposableKeychain:
    """Explicit administration of one temporary test Keychain, never the default."""

    def __init__(self, build):
        self.directory = tempfile.TemporaryDirectory(prefix="vate-keychain-test-")
        self.path = Path(self.directory.name).resolve() / "fixture.keychain-db"
        self.password = secrets.token_hex(32).encode("ascii")
        self.helper, self.admin = build / "keychain-bridge", build / "keychain-admin"
        try:
            for name, target in (("keychain_bridge.swift", self.helper), ("fixture_keychain_admin.swift", self.admin)):
                result = subprocess.run(["/usr/bin/swiftc", str(s.ROOT / "reference/authority-keychain" / name),
                    "-o", str(target)], capture_output=True, timeout=60)
                require(result.returncode == 0, "Keychain fixture build failed")
            self.manage("create", password=self.password)
            self.public = self.inspect("provision")
        except BaseException:
            self.close(); raise

    def manage(self, action, *, password=None):
        result = subprocess.run([str(self.admin), action, str(self.path)], input=password,
            capture_output=True, timeout=10)
        require(result.returncode == 0 and not result.stdout and not result.stderr,
                "Disposable Keychain administration failed: " + action)

    def inspect(self, action="public-key"):
        result = subprocess.run([str(self.helper), action, str(self.path), "lifecycle-key"],
            capture_output=True, timeout=10)
        require(result.returncode == 0 and not result.stderr, "Fixture key selection failed")
        value = json.loads(result.stdout)
        require(value["private_key_extractable"] is False, "Fixture key is extractable")
        return base64.b64decode(value["public_key_spki_base64"], validate=True)

    def close(self):
        try:
            if self.path.exists():
                self.manage("delete")
        finally:
            self.directory.cleanup()


def keychain_settings():
    # Read configuration only, retain hashes rather than personal Keychain paths.
    return {name: b.digest(subprocess.check_output(["/usr/bin/security", name, "-d", "user"],
        stderr=subprocess.DEVNULL, timeout=10))["value"] for name in ("default-keychain", "list-keychains")}


def wait_service(url, process):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        require(process.poll() is None, "Restarted fixture service exited")
        try:
            if http(url)[0] == 200:
                return
        except (OSError, TimeoutError):
            pass
        time.sleep(0.1)
    raise RuntimeError("Restarted fixture service did not become ready")


def run(args):
    require(sys.platform == "darwin", "Native lifecycle fixture requires macOS")
    for path, expected in ((args.node, args.node_sha256), (args.openssl, args.openssl_sha256)):
        require(path.is_absolute() and jwt.file_sha(path) == expected, "Selected executable hash changed")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    settings_before = keychain_settings()
    observations, processes = [], []

    def check(name, observed, expected):
        matched = b.encode(observed) == b.encode(expected)
        observations.append({"case": name, "observed": observed, "expected": expected, "matched": matched})
        save(args.output / "OBSERVATIONS.json", observations)
        require(matched, "Observation mismatch: " + name)

    with tempfile.TemporaryDirectory(prefix="vate-authority-lifecycle-") as directory, ExitStack() as stack:
        runtime = Path(directory).resolve()
        fixture = NativeFixture(args.output, runtime, args.native_root.resolve())
        stack.callback(fixture.cleanup)
        fixture.setup()
        require(fixture.manage(fixture.owner_key, fixture.update_body("user_permission"))[0] == 200,
                "Owner permission setup failed")
        token = fixture.issue_token()
        keychain = DisposableKeychain(runtime)
        stack.callback(keychain.close)
        runtime_signer, actor_signer = [stack.enter_context(FixtureSigner(args.node, args.node_sha256)) for _ in range(2)]
        now = b.core.utc_now()
        second = int((now - jwt.EPOCH).total_seconds())
        purchases = [fresh_purchase(runtime_signer, actor_signer, now, "-lifecycle-" + name) for name in "ABC"]
        request = b.decode(purchases[0][1])
        runtime_grant = jwt.RuntimeIssuerGrant("urn:example:runtime-issuer", "runtime-key", runtime_signer.public_key,
            request["runtime"], request["audience"], second - 5, second + 240)
        grant = c.DelegationGrant("purchase-grant", request["principal"], request["actor"], "actor-key",
            actor_signer.public_key, request["runtime"], request["audience"], request["target"]["resource"],
            request["action"], "USD", "120.00", ("merchant.checkout.confirm",), second - 5, second + 240)
        registration = Registration(fixture.hydra + "/", AUDIENCE, "alice", "purchase_agent", fixture.store_id,
            fixture.model_id, "user:alice", PDP_OBJECT, runtime_grant, grant)
        oauth = JsonService(fixture.admin, development_loopback=True)
        pdp = JsonService(fixture.fga, development_loopback=True)
        selection = s.AuthoritySelection("urn:example:merchant-authority", "urn:example:verifier",
            selected_scope(registration, oauth, pdp, 120), "epoch-1", "authority-key", keychain.public, 1, 120)
        selected = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=selection,
            node=args.node, node_sha256=args.node_sha256)
        publisher_store = AuthorityStore.create(runtime / "publisher", verifier=selected)
        recipient_store = AuthorityStore.create(runtime / "recipient", verifier=selected)
        dispatch_store = b.durable_state_module().DurableStateStore.create(runtime / "dispatch",
            scope="native-authority-lifecycle", verifier_id=selection.audience)
        cert, tls_key = runtime / "feed-cert.pem", runtime / "feed-key.pem"
        result = subprocess.run([str(args.openssl), "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", str(tls_key),
            "-out", str(cert)], capture_output=True, timeout=20)
        require(result.returncode == 0, "Fixture TLS setup failed")
        from native_fixture import free_ports
        port = free_ports(1)[0]
        config = {"selection": asdict(selection), "registration": asdict(registration),
            "node": str(args.node), "node_sha256": args.node_sha256,
            "oauth": fixture.admin, "pdp": fixture.fga, "pdp_credential": "Bearer " + fixture.backend_key,
            "token": token, "helper": str(keychain.helper), "helper_sha256": jwt.file_sha(keychain.helper),
            "keychain": str(keychain.path), "output": str(args.output), "port": port,
            "url": f"https://localhost:{port}/authority", "cert": str(cert), "tls_key": str(tls_key),
            "publisher_directory": str(publisher_store.directory), "publisher_anchor": publisher_store.anchor,
            "recipient_directory": str(recipient_store.directory), "recipient_anchor": recipient_store.anchor,
            "dispatch_directory": str(dispatch_store.directory), "dispatch_anchor": dispatch_store.anchor,
            "policy": purchases[0][2], "effects": str(runtime / "effects.jsonl")}

        def start(role):
            child = OwnedProcess(role, role_configuration(role, config))
            processes.append(child)
            journal = args.output / "process-events.jsonl"
            def stop():
                try:
                    child.close()
                finally:
                    append_record(journal, {"role": role, "pid": child.process.pid, "event": "cleanup",
                        "alive": child.process.is_alive(), "exitcode": child.process.exitcode})
            stack.callback(stop)
            append_record(journal, {"role": role, "pid": child.process.pid, "event": "started"})
            return child

        def effects():
            path = Path(config["effects"])
            return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

        publisher, recipient = start("publisher"), start("recipient")
        ids = [b.decode(values[1])["request_id"] for values in purchases]
        receipts, effective_requests = [], []
        for request_id, values in zip(ids, purchases):
            admitted = recipient.ask("admit", request_id=request_id, inputs=values)
            check("permit-admits-" + request_id[-1], [admitted["ok"], admitted.get("history"), len(effects())], [True, "ready", 0])
            receipts.append(admitted["receipt"])
            effective_requests.append(admitted["effective"])

        def dispatch(index=0):
            return recipient.ask("dispatch", request_id=ids[index], proof=purchases[index][4])

        def denied(name, index=0):
            before = len(effects())
            result = dispatch(index)
            check(name, [result["ok"], result.get("cause"), len(effects()) - before],
                  [False, "CALLER_AUTHORIZATION_FAILED", 0])

        def refreshed(name):
            before = recipient.ask("status")["authority"]["revision"]
            result = recipient.ask("poll")
            check(name, [result["ok"], result["authority"]["unavailable"],
                result["authority"]["revision"] > before, result["installed"] is not None], [True, False, True, True])
            return result

        def unavailable(name):
            before = recipient.ask("status")["authority"]["revision"]
            result = recipient.ask("poll")
            check(name + "-refresh", [result["ok"], result.get("cause"),
                result["authority"]["unavailable"], result["authority"]["revision"]],
                [False, "AUTHORITY_REFRESH_FAILED", True, before])
            count = len(effects())
            blocked = dispatch()
            check(name + "-blocks-dispatch", [blocked["ok"], blocked.get("cause") in
                ("AUTHORITY_REFRESH_FAILED", "AUTHORITY_REFRESH_RETRY_WAIT"), len(effects()) - count], [False, True, 0])

        require(fixture.manage(fixture.owner_key, fixture.update_body("user_permission", "remove"))[0] == 200,
                "Owner permission withdrawal failed")
        refreshed("owner-withdrawal-delivered"); denied("owner-withdrawal-stops-dispatch")
        before_publisher = publisher.ask("status")["authority"]
        before_recipient = recipient.ask("status")["authority"]
        publisher.kill()
        unavailable("publisher-exit")
        recipient.kill(); recipient = start("recipient")
        check("fresh-recipient-retains-unavailability", [recipient.initial["refresh"]["phase"],
            recipient.initial["authority"]["unavailable"], recipient.initial["authority"]["revision"]],
            ["refresh_required", True, before_recipient["revision"]])
        check("recipient-clock-history-retained", b.core.parse_time(recipient.initial["authority"]["clock_high"]) >=
              b.core.parse_time(before_recipient["clock_high"]), True)
        unavailable("restart-with-publisher-still-down")
        publisher = start("publisher")
        check("fresh-publisher-keeps-key-and-ledger", [publisher.initial["public_key_sha256"],
            publisher.initial["authority"]], [b.digest(keychain.public)["value"], before_publisher])
        refreshed("fresh-revoked-snapshot-after-restart"); denied("restart-does-not-restore-permission")
        require(fixture.manage(fixture.owner_key, fixture.update_body("user_permission"))[0] == 200,
                "Owner permission restoration failed")
        refreshed("fresh-permission-restoration")
        restored = recipient.ask("restore", request_id=ids[0])
        check("unattempted-receipt-survives-restart", [restored["ok"], restored["receipt"] == receipts[0]], [True, True])

        keychain.manage("lock"); unavailable("locked-signing-key")
        check("signing-failure-persists-at-publisher", publisher.ask("status")["authority"]["unavailable"], True)
        keychain.manage("unlock", password=keychain.password)
        check("explicit-unlock-keeps-selected-key", keychain.inspect() == keychain.public, True)
        refreshed("fresh-source-read-after-unlock")
        publisher.ask("delivery", unavailable=True); unavailable("https-delivery-disabled")
        publisher.ask("delivery", unavailable=False); refreshed("https-delivery-restored")
        require(fixture.manage(fixture.as_key, fixture.update_body("delegation", "remove"))[0] == 200,
                "Delegation withdrawal failed")
        refreshed("delegation-withdrawal-delivered"); denied("delegation-withdrawal-stops-dispatch")
        require(fixture.manage(fixture.as_key, fixture.update_body("delegation"))[0] == 200,
                "Delegation restoration failed")
        refreshed("delegation-restored")

        hydra = next(proc for name, proc in fixture.processes if name == "hydra")
        hydra.terminate(); hydra.wait(timeout=10)
        unavailable("native-hydra-stopped")
        fixture.start_process("hydra-restarted", hydra.args,
            {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": str(runtime)})
        wait_service(fixture.admin + "/health/ready", fixture.processes[-1][1])
        refreshed("native-hydra-restored-with-original-database")
        result = dispatch()
        check("recovered-unattempted-operation-runs-once", [result["ok"], result["history"],
            result["receipt"] == receipts[0], len(effects())], [True, "callback_returned", True, 1])
        (args.output / "pre-dispatch-A.json").write_bytes(result["checkpoint"])
        recipient.close(); recipient = start("recipient")
        returned = recipient.ask("status", request_id=ids[0])
        duplicate = dispatch()
        check("returned-operation-not-repeated-after-restart", [returned["history"], duplicate["ok"],
            duplicate.get("cause"), len(effects())], ["callback_returned", False, "DURABLE_OPERATION_ALREADY_ATTEMPTED", 1])
        recipient.crash_during_dispatch(ids[1], purchases[1][4])
        recipient = start("recipient")
        uncertain = recipient.ask("status", request_id=ids[1])
        repeated = dispatch(1)
        check("uncertain-callback-not-repeated-after-restart", [uncertain["history"], repeated["ok"],
            repeated.get("cause"), len(effects())], ["attempt_consumed", False, "DURABLE_OPERATION_ALREADY_ATTEMPTED", 2])
        (args.output / "pre-dispatch-B.json").write_bytes(uncertain["checkpoint"])
        check("effects-belong-to-two-distinct-operations", [row["request_id"] for row in effects()], ids[:2])

        status, _, _ = http(fixture.hydra + "/oauth2/revoke", method="POST", form={
            "token": token, "client_id": "purchase_agent", "token_type_hint": "access_token"})
        require(status == 200, "Fixture OAuth revocation failed")
        refreshed("oauth-revocation-delivered"); denied("oauth-revocation-stops-pending-operation", 2)
        for index, request_id in enumerate(ids):
            final = recipient.ask("status", request_id=request_id)
            receipt = b.decode(receipts[index])
            original_hash = b.object_hash(b.decode(purchases[index][0]))
            check("retained-receipt-and-original-binding-" + request_id[-1], [
                b.decode(final["record"])["receipt_ref"]["digest"], receipt["request"]["input_hash"],
                receipt["attenuation"]["original_request_hash"]], [b.digest(receipts[index]), original_hash, original_hash])
            if index < 2:
                effect = effects()[index]
                check("callback-bound-to-effective-request-and-checkpoint-" + request_id[-1], [
                    effect["effective_sha256"], receipt["request_binding"]["effective_ref"]["digest"]["value"],
                    effect["checkpoint_sha256"]], [b.digest(effective_requests[index])["value"],
                    b.digest(effective_requests[index])["value"], b.digest(final["checkpoint"])["value"]])
            (args.output / f"dispatch-status-{index}.json").write_bytes(final["record"])
            (args.output / f"receipt-{index}.json").write_bytes(receipts[index])
            (args.output / f"effective-{index}.json").write_bytes(effective_requests[index])
            for name, raw in (("original", purchases[index][0]), ("request", purchases[index][1])):
                (args.output / f"{name}-{index}.json").write_bytes(raw)
        save(args.output / "effects.json", effects())
        save(args.output / "selection.json", selection.descriptor())
        save(args.output / "registration.json", registration.descriptor())
        save(args.output / "publisher-status.json", publisher.ask("status")["authority"])
        save(args.output / "recipient-status.json", recipient.ask("status")["authority"])
        save(args.output / "anchors.json", {name: b.digest(config[name + "_anchor"])
            for name in ("publisher", "recipient", "dispatch")})
        signer_sha = config["helper_sha256"]
        forbidden = [value.encode() for value in fixture.sensitive] + [keychain.password, tls_key.read_bytes()]
        forbidden += [value for purchase in purchases for value in purchase[3:]]
    check("personal-keychain-settings-unchanged", keychain_settings(), settings_before)
    check("owned-processes-stopped", all(not child.process.is_alive() for child in processes)
          and all(proc.poll() is not None for _, proc in fixture.processes), True)
    require(not any(secret in path.read_bytes() for path in args.output.iterdir() if path.is_file()
                    for secret in forbidden), "Credential found in saved fixture output")
    require(not any(b"PRIVATE KEY-----" in path.read_bytes() for path in args.output.iterdir() if path.is_file()),
            "Private key found in saved fixture output")
    sources = {str(path.relative_to(s.ROOT)): b.digest(path.read_bytes()) for family in
        ("authority-issuer", "authority-keychain", "authority-updates", "caller-authority", "runtime-jwt",
         "request-binding", "vate-verifier-core") for path in (s.ROOT / "reference" / family).rglob("*")
        if path.suffix in (".py", ".mjs", ".swift") and "__pycache__" not in path.parts}
    report = {"profile": "vate-hydra-openfga-authority-issuer-v1", "all_matched": True,
        "evidence_kind": "native-loopback-lifecycle-recording-callback", "observations": observations,
        "native_binary_sha256": BINARY_PINS, "node_sha256": args.node_sha256,
        "openssl_sha256": args.openssl_sha256, "keychain_helper_sha256": signer_sha,
        "sources": sources, "artifacts": {path.name: b.digest(path.read_bytes())
            for path in sorted(args.output.iterdir()) if path.is_file()},
        "processes": [{"role": child.role, "pid": child.process.pid, "exitcode": child.process.exitcode}
                      for child in processes], "owned_processes_stopped": True,
        "raw_credentials_exported": False, "callback_calls": 2,
        "scope": "same host, retained original stores and anchors, same authority key; process restarts only"}
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
    report = run(parser.parse_args())
    print(json.dumps({"all_matched": report["all_matched"], "cases": len(report["observations"]),
                      "callback_calls": report["callback_calls"]}))


if __name__ == "__main__":
    main()
