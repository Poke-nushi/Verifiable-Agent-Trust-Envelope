"""Emit raw inputs and live Python assessments for the TypeScript parity test.

This is a test oracle, not a stored or self-attested SUT result. Mutations renew
raw references so semantic rejection cannot be explained by stale checksums.
"""
from __future__ import annotations

import base64
import copy
import json

import request_binding as b

FIXTURES = b.ROOT / "conformance/request-binding-v1/fixtures"


def raw(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def bundle(name="attenuate"):
    directory = FIXTURES / name
    return {key: json.loads((directory / filename).read_bytes()) for key, filename in (
        ("R", "admission-receipt.json"), ("A", "admission-request.json"), ("O", "original.json"),
        *(([("E", "effective.json")]) if (directory / "effective.json").exists() else []))}


def synchronize(value):
    """Renew canonical hashes and request context for a deliberate valid rebind."""
    a, o, r = value["A"], value["O"], value["R"]
    a.update(input_hash=b.object_hash(o), constraints=copy.deepcopy(o["constraints"]), target=copy.deepcopy(o["target"]),
             transaction_id=o["operation_id"], action=o["action"], audience=o["target"]["audience"])
    for key in ("input_hash", "constraints", "transaction_id", "action", "request_id"):
        r["request"][key] = copy.deepcopy(a[key])
    for key in ("actor", "principal", "runtime"):
        r["subject"][key] = a[key]
    if "E" in value:
        e = value["E"]
        r["request"]["action_binding"] = b.action_binding(e)
        if "attenuation" in r:
            r["attenuation"].update(original_request_hash=b.object_hash(o), effective_request_hash=b.object_hash(e),
                                     effective_constraints=copy.deepcopy(e["constraints"]))
            r["attenuation"]["changes"][0]["from"] = o["constraints"]["max_amount"]["value"]
            r["attenuation"]["changes"][0]["to"] = e["constraints"]["max_amount"]["value"]


def vectors():
    assessments = []
    def add(name, value=None, *, edit=None, cause=None, require_pass=False):
        v = copy.deepcopy(value if value is not None else bundle())
        r = v["R"]
        artifacts = {}
        for key, field in (("O", "original_ref"), ("A", "admission_request_ref"), ("E", "effective_ref")):
            if key in v:
                content = raw(v[key]); ref = b.reference(content)
                r["request_binding"][field] = ref
                artifacts[ref["uri"]] = content
        pin = b.reference(raw(v["A"]))
        entry = {"receipt": raw(r), "artifacts": artifacts, "pin": pin, "required": b.CONTRACT}
        if edit:
            edit(entry)
        expected = b.assess_request_binding(entry["receipt"], entry["artifacts"],
            required_contract=entry["required"], expected_admission_request_ref=entry["pin"])
        if cause is not None and cause not in [c.get("cause") for c in expected["checks"]]:
            raise AssertionError((name, cause, expected))
        if require_pass and expected["binding_requirement_met"] is not True:
            raise AssertionError((name, expected))
        assessments.append({"name": name, "receipt": base64.b64encode(entry["receipt"]).decode(),
            "artifacts": {uri: base64.b64encode(content).decode() for uri, content in entry["artifacts"].items()},
            "pin": entry["pin"], "required": entry["required"], "expected": expected})

    for name in ("allow", "attenuate", "new-permit", "deny-over-cap"):
        add(name, bundle(name), require_pass=True)
    add("missing pin", edit=lambda e: e.update(pin=None), cause="EXPECTED_ADMISSION_REQUEST_NOT_SUPPLIED")
    add("different pin", edit=lambda e: e.update(pin=b.reference(b"{}")), cause="ADMISSION_REFERENCE_MISMATCH")
    add("unknown requirement", edit=lambda e: e.update(required="future"), cause="UNSUPPORTED_BINDING_PROFILE")
    add("missing artifacts", edit=lambda e: e.update(artifacts={}), cause="ARTIFACT_NOT_SUPPLIED")
    add("bad artifact bytes", edit=lambda e: e["artifacts"].update({next(iter(e["artifacts"])): b"{}"}), cause="DIGEST_MISMATCH")
    def strip(e):
        r = b.decode(e["receipt"]); del r["request_binding"]; e["receipt"] = raw(r)
    add("stripped binding", edit=strip, cause="BINDING_NOT_DECLARED")

    for label, path, replacement, cause in (
        ("from mismatch", ("R", "attenuation", "changes", 0, "from"), "120", "ATTENUATION_FROM_MISMATCH"),
        ("expansion", ("R", "attenuation", "changes", 0, "to"), "121.00", "CONSTRAINT_NOT_NARROWED"),
        ("new permit flag", ("R", "attenuation", "require_new_permit"), 0, "SCHEMA_INVALID"),
        ("window microseconds", ("R", "expires_at"), "2026-11-12T00:05:00.000001Z", "RECEIPT_WINDOW_EXCEEDS_REQUEST"),
        ("calendar invalid", ("R", "expires_at"), "2026-02-30T00:00:00Z", "INVALID_RECEIPT_WINDOW"),
        ("time year zero", ("A", "issued_at"), "0000-01-01T00:00:00Z", "INVALID_REQUEST_WINDOW"),
        ("hash original", ("R", "attenuation", "original_request_hash"), "sha-256:" + "a"*64, "ORIGINAL_HASH_MISMATCH"),
        ("hash effective", ("R", "attenuation", "effective_request_hash"), "sha-256:" + "a"*64, "EFFECTIVE_HASH_MISMATCH"),
        ("hash input", ("A", "input_hash"), "sha-256:" + "a"*64, "INPUT_HASH_MISMATCH"),
        ("wrong runtime", ("R", "subject", "runtime"), "urn:other", "RECEIPT_SUBJECT_MISMATCH"),
        ("amount number", ("O", "payload", "amount", "value"), 25, "INVALID_DECIMAL_AMOUNT"),
        ("currency newline", ("O", "payload", "amount", "currency"), "USD\n", "SCHEMA_INVALID"),
        ("unknown constraint", ("O", "constraints", "unknown"), True, "SCHEMA_INVALID"),
        ("unknown transform", ("R", "attenuation", "mode"), "expand", "UNSUPPORTED_TRANSFORMATION"),
    ):
        value = bundle(); item = value
        for key in path[:-1]: item = item[key]
        item[path[-1]] = replacement
        add(label, value, cause=cause)

    for field in ("contract", "preimage_profile", "canonicalization", "transformation_profile"):
        value = bundle(); value["R"]["request_binding"][field] = "future"
        add("unknown " + field, value, cause="UNSUPPORTED_BINDING_PROFILE")

    # Type-confused objects at every meaningful receipt/context surface.
    for prefix in (("R",), ("R", "request"), ("R", "subject"), ("R", "decision"),
                   ("R", "attenuation"), ("R", "attenuation", "changes", 0),
                   ("A",), ("A", "evidence_refs", 0), ("O",), ("O", "payload"), ("E", "constraints")):
        original = bundle(); target = original
        for key in prefix: target = target[key]
        for key in list(target):
            if key == "request_binding": continue
            for bad in ([], {}, None, True):
                value = copy.deepcopy(original); cursor = value
                for part in prefix: cursor = cursor[part]
                cursor[key] = bad
                add("types " + repr((*prefix, key, bad)), value)

    for text in ("注文😀\ufffe", "\U00010000\ue000", "999999999999999999.12345678"):
        value = bundle()
        for key in ("O", "E"): value[key]["payload"]["order_id"] = text
        synchronize(value); add("unicode/hash " + repr(text), value)
    for purchase in ("25.00000000", "25.00000001"):
        value = bundle()
        for key in ("O", "E"): value[key]["payload"]["amount"]["value"] = purchase
        synchronize(value)
        add("precise purchase " + purchase, value, cause="PAYLOAD_EXCEEDS_CONSTRAINTS" if purchase.endswith("1") else None)
    for stamp in ("2026-11-12t09:05:00+09:00", "2026-11-11T23:05:00-01:00", "2026-11-12T00:04:59.999999z"):
        value = bundle(); value["R"]["expires_at"] = stamp; add("valid offset " + stamp, value)
    registry = json.loads((b.ROOT / "registries/evidence-vocabulary.v0.3.json").read_text())
    for entry in registry["evidence_types"]:
        for hint in ("<absent>", None, "invalid", *entry["allowed_protocol_hints"]):
            value = bundle(); ref = value["A"]["evidence_refs"][0]
            ref.update(type=entry["id"], protocol_hint=hint)
            if hint == "<absent>": ref.pop("protocol_hint")
            receipt_ref = value["R"]["evidence"][0]
            receipt_ref["type"] = ref["type"]
            if "protocol_hint" in ref: receipt_ref["protocol_hint"] = ref["protocol_hint"]
            valid_hint = hint == "<absent>" or hint in entry["allowed_protocol_hints"]
            add("evidence " + entry["id"] + " " + str(hint), value,
                cause=None if valid_hint else "SCHEMA_INVALID", require_pass=valid_hint)

    for field, changed in (("digest", {"alg": "sha-256", "value": "0"*64}),
                           ("uri", "urn:borrowed-evidence"), ("type", "runtime_attestation"),
                           ("protocol_hint", "spiffe"), ("media_type", "text/plain")):
        value = bundle(); value["R"]["evidence"][0][field] = changed
        add("receipt evidence mismatch " + field, value, cause="RECEIPT_EVIDENCE_MISMATCH")
    for bad in (None, [], {}, [None], ["unresolved"]):
        value = bundle(); value["R"]["evidence"] = bad
        add("receipt evidence shape " + repr(bad), value, cause="RECEIPT_EVIDENCE_MISMATCH")
    value = bundle(); value["R"]["evidence"].append(copy.deepcopy(value["R"]["evidence"][0]))
    add("receipt duplicate evidence", value, cause="RECEIPT_EVIDENCE_MISMATCH")
    value = bundle(); value["A"]["evidence_refs"].append(copy.deepcopy(value["A"]["evidence_refs"][0]))
    add("request duplicate evidence", value, cause="DUPLICATE_EVIDENCE_REFERENCE")
    value = bundle()
    second = {**value["A"]["evidence_refs"][0], "uri": "urn:second-policy"}
    value["A"]["evidence_refs"].append(second)
    value["R"]["evidence"].insert(0, {**value["R"]["evidence"][0], "uri": second["uri"], "annotation": True})
    add("matching reordered evidence with annotation", value, require_pass=True)

    parses = []
    inputs = [(repr(v), v) for v in (
        b"{}", b"-0", b"[0,-0,9007199254740991,-9007199254740991]", b"1.0", b"1e0", b"NaN", b"Infinity", b"-Infinity",
        b"9007199254740992", b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}', b'"\\ud800"', b'"\\udc00"',
        b'"\\ud83d\\ude00"', b'"\\ufffe"', b'"\\ufdd0"', b'{"__proto__":1,"2":2,"10":10}',
        b'"\xff"', b"\xef\xbb\xbf{}", b'{"a":}', b'"unterminated', b"01", b"[1,]", b'{"a":1}junk',
        b"[" * 64 + b"0" + b"]" * 64, b"[" * 65 + b"0" + b"]" * 65,
        b"[" * 64 + b"{}" + b"]" * 64, b"[" * 64 + b'{"a":0}' + b"]" * 64,
    )]
    inputs.extend([
        ("unsafe integer before duplicate", b'{"x":9007199254740992,"x":0}'),
        ("duplicate before trailing comma", b'{"x":1,"x":2,}'),
        ("5000-digit integer", b'9' * 5000),
        ("20000 nested arrays", b'[' * 20000 + b'0' + b']' * 20000),
        ("unicode before float / numeric keys", b'{"10":"\\ud800","2":1.0}'),
        ("float before unicode / numeric keys", b'{"10":1.0,"2":"\\ud800"}'),
        ("escaped string", b'{"quoted\\\"key":"backslash\\\\ / \\b\\f\\n\\r\\t \\ud83d\\ude00"}'),
    ])
    for name, content in inputs:
        try:
            value = b.decode(content)
            expected = {"value": value, "hash": b.object_hash(value)}
        except b.Invalid as exc:
            expected = {"cause": exc.cause}
        parses.append({"name": name, "bytes": base64.b64encode(content).decode(), "expected": expected})
    return {"assessments": assessments, "parses": parses}


if __name__ == "__main__":
    print(json.dumps(vectors(), ensure_ascii=True))
