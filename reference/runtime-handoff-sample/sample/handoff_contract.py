"""Two-actor local file-set contract. New local proof types; unchanged VATE core."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import copy

from dependencies import demo, crypto, original_admission

encode, decode, need = demo.encode, demo.decode, demo.need
sha, b64, unb64 = crypto.sha, crypto.b64, crypto.unb64
exact, integer = crypto.exact, crypto.integer
PROFILE = "local-runtime-handoff-v1"
PROOF_TYP = "vate-local-handoff-attempt+jws"
STATUS_TYP = "vate-local-handoff-status+jws"
OBS_TYP = "vate-local-handoff-observation+jws"
MAX_COUNTER = 9007199254740991
MAX_EVENTS = 256
MAX_JOURNAL_BYTES = 1024 * 1024
MAX_EVENT_BYTES = 65536
RESERVED_EVENT_BYTES = 4096  # execution records and the store-wide terminal clock record
ZERO = "0" * 64


def reserved_event_count(state):
    # A live store always retains one terminal-clock slot, even with no accepted worker.
    return sum(op["reserved_events"] for op in state["operations"].values()) + int(not state["clock_bad"])


def validate_event_size(raw, kind):
    need(len(raw) <= MAX_EVENT_BYTES, "journal event capacity")
    if kind in ("clock", "execution_clock", "clock_fault", "native"):
        need(len(raw) <= RESERVED_EVENT_BYTES, "reserved event byte bound")


def iso(seconds):
    return datetime.fromtimestamp(integer(seconds), timezone.utc).isoformat().replace("+00:00", "Z")


def source_pins():
    from dependencies import ROOT
    names = ("reference/vate-verifier-core/vate_verifier_core.py",
             "reference/execution-evidence-demo/demo_contract.py",
             "reference/execution-evidence-demo/admission.py",
             "reference/post-admission-revocation-sample/sample/contract.py")
    return {name: sha((ROOT / name).read_bytes()) for name in names}


class Context:
    """Selected by the owner/reader, never taken from an evidence bundle."""
    def __init__(self, raw):
        self.raw, self.data = raw, decode(raw)
        c = self.data
        exact(c, {"profile", "provider", "store", "namespace", "receiver", "authority", "epoch",
                  "authority_public_pem", "authority_spki_sha256", "actors", "policy", "sources"})
        need(encode(c) == raw and c["profile"] == PROFILE, "context format/profile")
        for k in ("provider", "store", "namespace", "receiver", "authority", "epoch"):
            demo.identifier(c[k])
        need(isinstance(c["actors"], dict) and len(c["actors"]) == 2, "exactly two actors required")
        spkis = []
        for runtime, key in c["actors"].items():
            demo.identifier(runtime)
            exact(key, {"public_pem", "spki_sha256"})
            need(crypto.spki(unb64(key["public_pem"])) == key["spki_sha256"], "actor key mismatch")
            spkis.append(key["spki_sha256"])
        need(len(set(spkis)) == 2, "actors must use different keys")
        need(crypto.spki(unb64(c["authority_public_pem"])) == c["authority_spki_sha256"], "authority key mismatch")
        need(c["authority_spki_sha256"] not in spkis, "authority must be separate")
        need(c["sources"] == source_pins(), "selected source version mismatch")
        expected = original_admission.make_policy()
        expected["allowed_output_names"] = ["first.txt", "second.txt"]
        need(encode(c["policy"]) == encode(expected), "unsupported fixed policy")
        self.digest = sha(raw)
        self._verified = {}
        self._authorizations = {}

    def verify_actor(self, raw, runtime, typ):
        need(runtime in self.data["actors"] and typ in (PROOF_TYP, OBS_TYP), "actor proof role/type")
        return self._verify(raw, self.data["actors"][runtime]["public_pem"], typ)

    def verify_status(self, raw):
        return self._verify(raw, self.data["authority_public_pem"], STATUS_TYP)

    def _verify(self, raw, pem, typ):
        need(type(raw) is bytes and len(raw) <= 65536, "invalid signature input")
        cache_key = (raw, pem, typ)
        if cache_key not in self._verified:
            result = crypto.verify_jws(raw, unb64(pem), typ)
            if len(self._verified) >= MAX_EVENTS * 3:
                self._verified.clear()
            self._verified[cache_key] = result
        return self._verified[cache_key]

    def operation(self, operation):
        demo.validate_operation(operation, operation["target"]["resource"])
        prefix = "urn:vate:handoff:" + self.data["store"] + ":"
        need(operation["target"]["resource"].startswith(prefix), "resource outside selected provider")
        demo.identifier(operation["target"]["resource"][len(prefix):])
        need([f["name"] for f in operation["target"]["files"]] == self.data["policy"]["allowed_output_names"],
             "this sample uses its fixed two-file set")
        return operation

    def authorization(self, operation, bundle):
        raw = encode(bundle)
        key = (sha(encode(operation)), raw)
        if key not in self._authorizations:
            exact(bundle, {"runtime", "permit", "request", "core_result", "receipt", "record"})
            originals = {k: decode(unb64(bundle[k])) for k in bundle if k != "runtime"}
            regenerated = make_authorization(self, operation, bundle["runtime"],
                                            originals["permit"], originals["record"]["evaluated_at"])
            need(regenerated == bundle, "authorization originals/recomputation mismatch")
            self._authorizations[key] = originals
        return self._authorizations[key]

    def admission_current(self, operation, bundle, at):
        originals = self.authorization(operation, bundle)
        checked = integer(at) * 1_000_000
        windows = [originals[k] for k in ("permit", "receipt")]
        return (max(crypto.time_microseconds(x["issued_at"]) for x in windows) <= checked <
                min(crypto.time_microseconds(x["expires_at"]) for x in windows))

    def status(self, raw, at):
        verified = self.verify_status(raw)
        p, c = verified.payload, self.data
        exact(p, {"profile", "context_sha256", "runtime", "runtime_spki_sha256", "issuer", "epoch",
                  "sequence", "state", "generated_at", "last_changed_at", "next_update_at"})
        need(p["runtime"] in c["actors"], "unknown status subject")
        need(p["profile"] == PROFILE and p["context_sha256"] == self.digest and
             p["issuer"] == c["authority"] and p["epoch"] == c["epoch"] and
             p["runtime_spki_sha256"] == c["actors"][p["runtime"]]["spki_sha256"], "status subject/context")
        need(integer(p["sequence"]) >= 1, "status sequence")
        for k in ("generated_at", "last_changed_at", "next_update_at"):
            integer(p[k])
        need(p["last_changed_at"] <= p["generated_at"] <= at and
             p["generated_at"] < p["next_update_at"], "status times")
        need(p["state"] in ("active", "revoked", "suspended", "quarantined", "attenuated"), "status state")
        return verified

    def proof(self, ticket, raw, at):
        verified = self.verify_actor(raw, ticket["runtime"], PROOF_TYP)
        exact(verified.payload, ticket.keys())
        need(encode(verified.payload) == encode(ticket), "proof binding mismatch")
        need(ticket["issued_at"] <= at < ticket["expires_at"], "ticket/proof expired")
        return verified


def make_authorization(context, operation, runtime, permit, evaluated_at):
    """Explicit runtime composition; no mutation of the old demo's RUNTIME global."""
    context.operation(operation)
    need(runtime in context.data["actors"], "unknown authorization runtime")
    exact(permit, {"contract", "authorization_key", "operation_key", "input_hash", "issued_at", "expires_at", "status"})
    demo.identifier(permit["authorization_key"])
    need(permit["contract"] == demo.CONTRACT and permit["operation_key"] == operation["operation_key"] and
         permit["input_hash"] == demo.object_hash(operation) and permit["status"] == "active", "permit binding/status")
    need(timedelta(0) < demo.time_value(permit["expires_at"]) - demo.time_value(permit["issued_at"]) <=
         timedelta(minutes=10), "permit validity")
    request = {
        "version": demo.core.VERSION, "profile": demo.core.PROFILE,
        "request_id": "request-" + permit["authorization_key"], "transaction_id": operation["operation_key"],
        "issued_at": permit["issued_at"], "expires_at": permit["expires_at"], "action": operation["action"],
        "target": {"resource": operation["target"]["resource"], "audience": runtime},
        "actor": "urn:vate:demo:requester", "principal": "urn:vate:demo:local-owner",
        "runtime": runtime, "audience": runtime, "input_hash": demo.object_hash(operation),
        "constraints": {"tool_allowlist": [demo.ACTION], "target_resource": operation["target"]["resource"],
                        "demo_output_names": [x["name"] for x in operation["target"]["files"]],
                        "expected_runtime": runtime, "status": {"state": "active"}},
        "evidence_refs": [{"type": "mission_permit", "uri": "local:" + permit["authorization_key"],
                           "media_type": "application/json", "digest": demo.digest(encode(permit))}],
    }
    result = demo.core.VateVerifier(verifier_id="urn:vate:handoff:local-verifier", policy=context.data["policy"]).admit(
        request, now=demo.time_value(evaluated_at))
    need(result["decision"] == "allow", "only original allow supported")
    receipt = copy.deepcopy(result["admission_receipt"])
    receipt["proof"] = {"format": "none"}
    receipt["request"]["action_binding"] = demo.action_binding(operation)
    record = {"profile": PROFILE, "evaluated_at": evaluated_at, "operation_sha256": sha(encode(operation)),
              "context_sha256": context.digest, "runtime": runtime,
              "permit_sha256": sha(encode(permit)), "receipt_sha256": sha(encode(receipt)),
              "issuer_authenticity": "owner-selected-unsigned-local-record"}
    return {"runtime": runtime, **{k: b64(encode(v)) for k, v in
            {"permit": permit, "request": request, "core_result": result, "receipt": receipt, "record": record}.items()}}


def binding(context, op):
    c, operation = context.data, op["operation"]
    return {"profile": PROFILE, "context_sha256": context.digest, "provider": c["provider"], "store": c["store"],
            "namespace": c["namespace"], "operation_id": operation["operation_key"],
            "input_sha256": sha(encode(operation)), "runtime": op["runtime"],
            "runtime_spki_sha256": c["actors"][op["runtime"]]["spki_sha256"], "generation": op["generation"],
            "authorization_sha256": op["authorization_sha256"],
            "admission_sha256": sha(unb64(op["authorizations"][op["authorization_sha256"]]["receipt"]))}


def expected_inventory(operation):
    return {x["name"]: {"sha256": sha(x["text"].encode("utf-8")), "size": len(x["text"].encode("utf-8"))}
            for x in operation["target"]["files"]}


def effect_state(op, inventory, *, fenced=False):
    accepted, native = op["accepted"], op["native"]
    if accepted is not None:
        if native and native["outputs"] == inventory == expected_inventory(op["operation"]):
            return "completed"
        return "unresolved"
    if native is not None or inventory:
        return "unresolved"
    if fenced:
        return "confirmed_unexecuted"
    # A past generation's confirmation does not resolve the current actor's ticket.
    if any(t["generation"] == op["generation"] for t in op["tickets"].values()):
        return "unresolved"
    if op["generation"] > 1:
        return "confirmed_unexecuted"
    if not op["tickets"]:
        return "initial_ready"
    return "unresolved"


def post_receipt(op, issued_at=None):
    native = op["native"]
    if not native or native["started_at"] is None or native["finished_at"] is None:
        return None
    acceptance = op["accepted"]
    ticket = op["tickets"][acceptance["attempt_id"]]
    receipt = decode(unb64(op["authorizations"][ticket["authorization_sha256"]]["receipt"]))
    post = {
        "version": demo.core.VERSION, "profile": demo.core.PROFILE, "receipt_type": "post_execution",
        "receipt_id": "post-" + ticket["attempt_id"], "issued_at": issued_at or native["finished_at"],
        "issuer": {"id": "urn:vate:handoff:local-observer", "role": "broker"},
        "admission": {"receipt_id": receipt["receipt_id"], "digest": demo.digest(encode(receipt)),
                      "decision": receipt["decision"]["outcome"],
                      "uri": "local:authorization/" + ticket["authorization_sha256"] + "/receipt"},
        "execution": {"transaction_id": op["operation"]["operation_key"], "runtime": native["runtime"],
                      "started_at": native["started_at"], "finished_at": native["finished_at"],
                      "effective_request_hash": demo.object_hash(op["operation"]),
                      "action_binding": demo.action_binding(op["operation"])},
        "result": {"outcome": "success", "output_hash": demo.object_hash(native["outputs"]),
                   "side_effects": [{"tool": demo.ACTION, "resource": op["operation"]["target"]["resource"],
                                     "name": name, **item} for name, item in native["outputs"].items()],
                   "policy_violations": []}, "proof": {"format": "none"},
    }
    return post


def linkage(op):
    post = post_receipt(op)
    if post is None:
        return {"outcome": "unassessable", "reason_codes": ["ACTUAL_EXECUTION_TIMES_UNAVAILABLE"]}
    ticket = op["tickets"][op["accepted"]["attempt_id"]]
    receipt = decode(unb64(op["authorizations"][ticket["authorization_sha256"]]["receipt"]))
    return demo.core.VateVerifier(verifier_id="urn:vate:handoff:local-reader").validate_post_execution_linkage(receipt, post)
