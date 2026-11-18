#!/usr/bin/env python3
"""Native Keychain key replacement and fresh local Hydra/OpenFGA authorization."""
import argparse
import base64
from contextlib import ExitStack
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from fixture_support import Fixture, ROOT, b, s, jwt
from migration import PlannedMigration, authority, selection, source_program

# The issuer has its own run_native.py. Load the named helpers under an explicit
# module name rather than importing this entry point again.
import importlib.util
example_spec = importlib.util.spec_from_file_location("migration_example", Path(__file__).with_name("run_example.py"))
example = importlib.util.module_from_spec(example_spec)
example_spec.loader.exec_module(example)
prepare, set_target, save = example.prepare, example.set_target, example.save
spec = importlib.util.spec_from_file_location("migration_issuer_lifecycle", ROOT / "reference/authority-issuer/run_lifecycle.py")
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)
from authority_issuer import AuthorityIssuer, Registration, selected_scope
from service_client import JsonService
from native_fixture import NativeFixture, AUDIENCE, PDP_OBJECT
from keychain_signer import KeychainSigner, PROFILE as KEYCHAIN_PROFILE


class RootSigner:
    def __init__(self, keychain, tag, selected):
        self.public_key = selected.public_key_spki
        self.signer = KeychainSigner(expected_profile=KEYCHAIN_PROFILE, helper=keychain.helper,
            helper_sha256=jwt.file_sha(keychain.helper), keychain=keychain.path,
            application_tag=tag, selection=selected)

    def __call__(self, header, claims):
        return self.signer(header, claims)


def run(args):
    if sys.platform != "darwin":
        raise RuntimeError("Native planned migration example requires macOS")
    source_program(args.source_root)
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    observations = []
    def check(name, observed, expected):
        matched = b.encode(observed) == b.encode(expected)
        observations.append({"case": name, "observed": observed, "expected": expected, "matched": matched})
        (output / "OBSERVATIONS.json").write_bytes(b.encode(observations))
        if not matched:
            raise RuntimeError("Native migration mismatch: " + name)
    settings_before = lifecycle.keychain_settings()
    with tempfile.TemporaryDirectory(prefix="vate-native-migration-") as directory, ExitStack() as stack:
        runtime = Path(directory).resolve()
        native = NativeFixture(output, runtime, args.native_root.resolve())
        stack.callback(native.cleanup)
        native.setup()
        check("initial-owner-grant", native.manage(native.owner_key, native.update_body("user_permission"))[0], 200)
        token = native.issue_token()
        keychain = lifecycle.DisposableKeychain(runtime)
        stack.callback(keychain.close)
        reply = subprocess.run([str(keychain.helper), "provision", str(keychain.path), "migration-new-key"],
            capture_output=True, timeout=10, check=True)
        key = json.loads(reply.stdout)
        check("new-key-non-extractable", key["private_key_extractable"], False)
        new_public = base64.b64decode(key["public_key_spki_base64"], validate=True)
        check("distinct-root-keys", keychain.public != new_public, True)
        old_signer = new_signer = None
        oauth = JsonService(native.admin, development_loopback=True)
        pdp = JsonService(native.fga, development_loopback=True, authorization="Bearer " + native.backend_key)
        registration = None
        def configure(f):
            nonlocal registration, old_signer, new_signer
            runtime_grant, delegation_grant = f.grants()
            registration = Registration(native.hydra + "/", AUDIENCE, "alice", "purchase_agent", native.store_id,
                native.model_id, "user:alice", PDP_OBJECT, runtime_grant, delegation_grant)
            scope = selected_scope(registration, oauth, pdp, 120)
            old_selected = s.AuthoritySelection("urn:example:merchant-authority", "urn:example:verifier",
                scope, "epoch-1", "old-key", keychain.public, 1, 120)
            new_selected = s.AuthoritySelection(old_selected.issuer, old_selected.audience,
                scope, old_selected.epoch, "new-key", new_public, 1, 120)
            old_signer = RootSigner(keychain, "lifecycle-key", old_selected)
            new_signer = RootSigner(keychain, "migration-new-key", new_selected)
            return scope, old_signer, new_signer
        with Fixture(output, source_root=args.source_root, now=b.core.utc_now(), configure_authority=configure) as f:
            # Make the pre-migration revocation a current native IAM observation.
            check("withdraw-owner-permission", native.manage(native.owner_key, native.update_body("user_permission", "remove"))[0], 200)
            verifier = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=f.selection, node=f.node, node_sha256=f.node_sha)
            old_state = authority.AuthorityStore(f.old / "publisher", verifier=verifier, expected_anchor=b.encode(f.anchors["publisher"]))
            old_issuer = AuthorityIssuer(registration=registration, oauth=oauth, pdp=pdp, state=old_state,
                token_provider=lambda: token, signer=old_signer, ttl_seconds=120)
            raw = old_issuer.publish()
            wrong_context = json.loads(jwt.decode_segment(raw.split(b".")[1], jwt.MAX_TOKEN_BYTES))
            wrong_context["aud"] = "urn:example:other-verifier"
            context_error = "accepted"
            try:
                old_signer({"alg": "ES256", "typ": s.TOKEN_TYPE, "kid": "old-key"}, wrong_context)
            except s.AuthorityError as error:
                context_error = error.cause
            check("signer-rejects-unselected-context", context_error, "KEYCHAIN_SIGNER_CONTEXT_MISMATCH")
            f.now = b.core.utc_now(); f.base["now"] = b.core.iso(f.now)
            f.install(raw)
            check("old-native-authority-denied", json.loads(jwt.decode_segment(raw.split(b".")[1], jwt.MAX_TOKEN_BYTES))["delegation_grants"], [])
            move = prepare(f, output / "moved")
            save(output / "JOURNAL-ANCHOR.json", json.loads(move.anchor))
            save(output / "OLD-ANCHORS.json", f.anchors)
            result = move.run(old_signer=old_signer, new_signer=new_signer)
            save(output / "MIGRATION.json", result)
            set_target(f, move, result)
            chosen = selection(result["selection"])
            new_verifier = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=chosen, node=f.node, node_sha256=f.node_sha)
            new_state = authority.AuthorityStore(move.directory / "publisher", verifier=new_verifier,
                expected_anchor=b.encode(result["anchors"]["publisher"]))
            new_issuer = AuthorityIssuer(registration=registration, oauth=oauth, pdp=pdp, state=new_state,
                token_provider=lambda: token, signer=new_signer, ttl_seconds=120)
            raw = new_issuer.publish()
            f.now = b.core.utc_now(); f.target_base["now"] = b.core.iso(f.now)
            f.install(raw, target=True)
            confirmation = base64.b64decode(result["key_confirmations"]["new"]["token_base64"], validate=True)
            check("key-confirmation-below-live-revision", f.install(confirmation, target=True, succeeds=False), "AUTHORITY_REVISION_INVALID")
            check("new-native-authority-still-denied", json.loads(jwt.decode_segment(raw.split(b".")[1], jwt.MAX_TOKEN_BYTES))["delegation_grants"], [])
            check("revoked-operation-refused", f.worker({**f.purchase("-revoked-native"), "action": "admit"}, target=True, succeeds=False), "CALLER_AUTHORIZATION_FAILED")
            check("restore-owner-permission", native.manage(native.owner_key, native.update_body("user_permission"))[0], 200)
            raw = new_issuer.publish()
            f.now = b.core.utc_now(); f.target_base["now"] = b.core.iso(f.now)
            f.install(raw, target=True)
            check("fresh-native-grant", len(json.loads(jwt.decode_segment(raw.split(b".")[1], jwt.MAX_TOKEN_BYTES))["delegation_grants"]), 1)
            check("old-program-refused", f.worker({"action": "status", "request_id": f.history["pending"]["request_id"]}, succeeds=False), "AUTHORITY_SCHEMA_CHANGED")
            check("old-permit-requires-new-admission", f.worker({"action": "restore", "request_id": f.history["pending"]["request_id"]}, target=True, succeeds=False), "STATE_CONFIGURATION_CHANGED")
            for name in ("returned", "unknown"):
                check("attempt-not-revived-" + name, f.worker({**f.purchase("-" + name, request_suffix="-new"), "action": "admit"},
                    target=True, succeeds=False), "DURABLE_OPERATION_ALREADY_ATTEMPTED")
            value = f.worker({**f.purchase("-pending", request_suffix="-new"), "action": "admit", "dispatch": True}, target=True)
            check("new-operation-returned", value["state"], "callback_returned")
            check("new-operation-count", len(value["calls"]), 1)
            check("committed-retry-no-reset", move.run(old_signer=None, new_signer=None, clock=None) == result, True)
            check("old-key-still-present", keychain.inspect() == keychain.public, True)
            check("old-authority-key-rejected", f.install(f.last_snapshot, target=True, succeeds=False), "AUTHORITY_HEADER_INVALID")
            for name, before in f.history.items():
                status = f.worker({"action": "status", "request_id": before["request_id"]}, target=True)["status"]
                check("original-receipt-" + name, status["receipt_ref"]["digest"]["value"], before["receipt_sha256"])
    check("personal-keychain-settings-unchanged", lifecycle.keychain_settings(), settings_before)
    save(output / "CLEANUP.json", {"keychain_settings_unchanged": True, "temporary_keychain_removed": not keychain.path.exists(),
                                  "temporary_runtime_removed": not runtime.exists()})
    save(output / "RUN.json", {"contract": "vate-native-planned-migration-example-v1",
        "evidence_kind": "native-local-iam-keychain-recording-callback", "observations": observations,
        "all_matched": all(item["matched"] for item in observations),
        "source_commit": result["source_commit"], "target_runtime": result["target_program"],
        "limits": ["same-host-local-filesystem", "synthetic-login-consent", "no-external-resource-effect",
                   "no-power-loss-test", "no-live-key-loss-recovery"]})
    return {"observations": len(observations), "all_matched": True, "output": str(output)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--native-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    print(json.dumps(run(parser.parse_args()), sort_keys=True))
