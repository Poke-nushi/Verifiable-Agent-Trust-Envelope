"""Fixture worker loading one explicitly selected installed source tree.

Input is a local trusted test controller's JSON, not a service API. Credentials
are synthetic. The worker never selects a real Keychain or an external effect.
"""
import base64
import json
from pathlib import Path
import sys


def run(source, job):
    sys.path.insert(0, str(source / "reference/authority-issuer"))
    from authority_issuer import s, b
    from authority_store import AuthorityStore
    from managed_verifier import ManagedAuthorityVerifier

    selection = dict(job["selection"])
    selection["public_key_spki"] = base64.b64decode(selection.pop("public_key_spki_base64"), validate=True)
    selected = s.AuthoritySelection(**selection)
    verifier = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=selected,
        node=job["node"], node_sha256=job["node_sha256"])
    now = b.core.parse_time(job["now"])
    directory = Path(job["directory"])
    state_type = b.durable_state_module().DurableStateStore
    if job["action"] == "create":
        stores = {name: AuthorityStore.create(directory / name, verifier=verifier, clock=lambda: now)
                  for name in ("publisher", "recipient")}
        state = state_type.create(directory / "dispatch", scope="planned-migration-fixture",
                                  verifier_id=selected.audience)
        return {"anchors": {**{name: json.loads(store.anchor) for name, store in stores.items()},
                            "dispatch": json.loads(state.anchor)}}
    stores = {name: AuthorityStore(directory / name, verifier=verifier,
        expected_anchor=b.encode(job["anchors"][name]), clock=lambda: now)
        for name in ("publisher", "recipient")}
    state = state_type(directory / "dispatch", expected_anchor=b.encode(job["anchors"]["dispatch"]))
    if job["action"] == "install":
        raw = base64.b64decode(job["snapshot"], validate=True)
        return {name: store.accept(raw) for name, store in stores.items()}
    calls = []
    def execute(effective, checkpoint):
        calls.append({"effective": b.digest(effective), "checkpoint": b.digest(checkpoint)})
        if job.get("callback") == "park":
            print(json.dumps({"fixture_ready": "callback"}), flush=True)
            if sys.stdin.readline().strip() != "continue":
                raise RuntimeError("Fixture callback was not released")
        if job.get("callback") == "unknown":
            raise RuntimeError("Disposable recording callback failed")
    managed = ManagedAuthorityVerifier(source=stores["recipient"], verifier_id=selected.audience,
        policy=job["policy"], state_store=state, execute=execute,
        max_runtime_token_age_seconds=180, max_caller_token_age_seconds=180)
    action = job["action"]
    if action == "park":
        print(json.dumps({"fixture_ready": "configured"}), flush=True)
        job.update(json.loads(sys.stdin.readline()))
        action = job["action"]
    if action == "status":
        status = managed.dispatch_status(job["request_id"])
        return {"status": json.loads(status.record), "checkpoint":
                base64.b64encode(status.checkpoint).decode() if status.checkpoint else None}
    if action == "restore":
        admitted = managed.restore_admission(job["request_id"])
    elif action == "admit":
        purchase = {name: base64.b64decode(job[name], validate=True)
                    for name in ("request", "original", "runtime_token", "proof")}
        admitted = managed.admit(purchase["request"], original=purchase["original"],
            evidence_artifacts={"urn:example:runtime-jwt": purchase["runtime_token"]},
            caller_proof=purchase["proof"], require_new_permit=job.get("require_new_permit", False))
    else:
        raise ValueError("Unknown fixture action")
    request_id = b.decode(admitted.request)["request_id"]
    error = None
    if job.get("dispatch"):
        try:
            managed.dispatch(admitted, caller_proof=base64.b64decode(job["proof"], validate=True))
        except b.DispatchAttemptError as exc:
            error = type(exc).__name__
    return {"request_id": request_id, "receipt_sha256": b.digest(admitted.receipt)["value"],
            "state": managed.dispatch_status(request_id).state, "calls": calls, "error": error}


if __name__ == "__main__":
    try:
        result = run(Path(sys.argv[1]).resolve(strict=True), json.loads(sys.stdin.readline()))
        print(json.dumps({"ok": True, "result": result}, sort_keys=True))
    except Exception as error:
        print(json.dumps({"ok": False, "cause": getattr(error, "cause", type(error).__name__)}, sort_keys=True))
        raise SystemExit(1)
