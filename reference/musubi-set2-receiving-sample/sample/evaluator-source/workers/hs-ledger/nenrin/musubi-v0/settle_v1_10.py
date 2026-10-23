#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI settle v1.10: a conditional action can require a pinned approver with no stake in the contract (a2a-settlement-v1.10).

Why this file exists. Issue #29 (2026-10-05, babyblueviper1) read contract_v0.settle at ef54aa8: an approval there is
satisfied by an entry {"action": X} with no signature. That holds for contract_v0.settle and settle v1 to v1.3, which are
superseded and kept as published. From v1.4 an approval needs the principal's signature, and from v1.6 over
a2a-approval-v2 bytes naming the terms by contract_sha256; the current path (peer_kit.py settle) refuses an unsigned or
wrongly signed approval as forged_approval. What remained is the limit #29 points at: the only key that could approve
was the principal's, a party to the contract. The fields, signed bytes, reasons and the nine vectors this file is
built against are babyblueviper1's (fixtures/babyblueviper1_approver_v2, from preaction-governance-conformance@9860841).

What v1.10 changes, and nothing else:

  grant.approval_policy.approvers   [{"name", "public_key_ed25519_b64", "actions": [...]}], checked at contract_v0's door
                           like witnesses[] (canonical 32 byte key, non empty name) plus a non empty list of distinct
                           grant.conditional actions. Both parties sign it. A delegated child must keep the parent's
                           approvers exactly. An approver key equal to a party's key (approver_is_party) or a witness's
                           (approver_is_witness) is refused here: no verdict.
  the approval             an approvals[] entry {"action", "by": "approver", "approver": <name>, "valid_until_height",
                           "nonce", "single_use", "sig_b64"}, Ed25519 by the pinned key over
                           b"a2a-approval-v2\n" + canonical({contract_sha256, action, approver_key, valid_until_height,
                           nonce, single_use}). contract_sha256 is recomputed from the contract this settler holds, so
                           an approval for other terms, or one whose fields were edited, does not verify.
  gated actions            an action some approver lists counts as approved only with a verifying approver approval.
                           Anything else offered for it (the principal's signature, a bare {"action"}, a forged or
                           unpinned key) is not counted and is reported as approval_unverified with the reason:
                           not_an_approver_approval, malformed, approver_not_pinned, action_not_permitted_for_approver,
                           malformed_key_or_signature, bad_signature. Ordering, expiry and single use are v1.7's walk,
                           unchanged. Actions no approver lists keep v1.6's rule (the principal approves).
  no approvers pinned      v1.10 renders v1.9's settlement apart from schema, settled_under, establishes and
                           approval_gate, whose reading is approval_self_asserted: an approval, if any, comes from a party
                           to the contract (the principal's signature), not from a pinned approver.

How the walk is reused. v1.7's walk resolves classify_approval_v2 in its own module at call time; v1.10 points that
name at a classifier that applies the rule above for the length of one call and restores it in a finally block. No
earlier settle file is edited.

Stated limits: as v1.9. A settler older than v1.10 ignores the approvers and would count a principal's approval for a
gated action (contract_v0 before 2026-10-05 refuses the approvers key outright). A stolen approver key signs a valid
approval. The signature proves the approver signed, not that the approver judged well.
"""
import argparse, base64, contextlib, hashlib, json, os, random, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import settle_v1 as v1
import settle_v1_2 as v12
import settle_v1_5 as v15
import settle_v1_6 as v16
import settle_v1_7 as v17
import settle_v1_9 as v19
from contract_v0 import canonical, parse_strict, ed25519_verify, contract_sha256, b64_raw, EXEC_SCHEMA

SETTLE_SCHEMA = "a2a-settlement-v1.10"
SAME_EXCEPT = ("schema", "settled_under", "establishes", "approval_gate")
# 2026-10-10. The pinned approver rule (the clause evaluation this file introduced) lives in clause_eval_v0.py, so that
# admission (admit_v0.py) and settlement apply one copy of it. The names are imported back unchanged: this module's
# namespace, its outputs and its self test are what they were. run0002, the second contract and the first contract
# between two outside parties (contract_sha256 d7118f28...) settle to the same bytes before and after.
from clause_eval_v0 import (APPROVAL_V2_CONTEXT, HEX32, REASONS, approvers, policy_reading, approver_approval_bytes,
                            sign_approver_approval, verify_approver_approval, gated_actions)


def _reason_for(contract, gated, e, original):
    """None when the walk should treat e exactly as v1.9 does; otherwise ('approved' | reason)."""
    act = e.get("action") if isinstance(e, dict) else None
    if act in gated or (isinstance(e, dict) and e.get("by") == "approver"):
        res, why = verify_approver_approval(contract, e)
        if res == "approved" and act in gated:
            return "approved"
        return why or "action_not_permitted_for_approver"
    return None


def _approver_classifier(contract, gated, original):
    def classify(e, c):
        if c is not contract:
            return original(e, c)
        r = _reason_for(contract, gated, e, original)
        if r is None:
            return original(e, c)
        return "scoped_v2" if r == "approved" else None
    return classify


@contextlib.contextmanager
def _walk_classifier(fn):
    saved = v17.classify_approval_v2
    v17.classify_approval_v2 = fn
    try:
        yield
    finally:
        v17.classify_approval_v2 = saved


def _unverified_reasons(events, contract, gated):
    """(record_sha256, action) -> reasons, in record order, for each approval the walk will list as not counted."""
    out = {}
    for ev in events if isinstance(events, list) else []:
        if not (isinstance(ev, dict) and ev.get("schema") == EXEC_SCHEMA):
            continue
        s = v1.rec_sha(ev)
        for ap in ev.get("approvals") or []:
            r = _reason_for(contract, gated, ap, v16.classify_approval_v2)
            if r is not None and r != "approved":
                out.setdefault((s, ap.get("action") if isinstance(ap, dict) else None), []).append(r)
    return out


def _party_problems(contract):
    keys, wit = v12._keys(contract)
    pk, wk = set(v for v in keys.values() if v), set(v for v in wit.values() if v)
    p = []
    for i, a in enumerate(approvers(contract)):
        k = a.get("public_key_ed25519_b64")
        if k in pk:
            p.append({"reason": "approver_is_party", "detail": "approvers[%d] uses the key of a party to this contract" % i})
        if k in wk:
            p.append({"reason": "approver_is_witness", "detail": "approvers[%d] uses the key of a witness named in the grant" % i})
    return p


def settle_v1_10(contract, events, view, mode="strict", nenrin_records=None, spine=None, pool=None,
                 contract_anchor_height=None, history=None):
    kw = dict(mode=mode, nenrin_records=nenrin_records, spine=spine, pool=pool,
              contract_anchor_height=contract_anchor_height, history=history)
    gated = gated_actions(contract)
    if not gated:
        s = v19.settle_v1_9(contract, events, view, **kw)
        out = dict(s)
        out["schema"], out["settled_under"] = SETTLE_SCHEMA, v19.SETTLE_SCHEMA
        out["approval_gate"] = {"required": False, "reading": "approval_self_asserted"}
        out["establishes"] = list(s["establishes"]) + [
            "that the grant pins no approver, so a conditional action is approved by the principal's signature, a party to the contract (settle v1.6)"]
        return out
    probs = _party_problems(contract)
    if probs:
        s = v19.settle_v1_9(contract, events, view, **kw)
        out = dict(s)
        out["schema"], out["settled_under"] = SETTLE_SCHEMA, v19.SETTLE_SCHEMA
        out["underspecified"] = sorted(list(s.get("underspecified") or []) + probs, key=canonical)
        out["verdict"], out["status"], out["deviations"] = "underspecified", "undetermined", []
        out["bond_outcome"] = v15._bond_outcome(contract, "underspecified", "undetermined")
        out["approval_gate"] = {"required": True, "applied": False}
        out["establishes"] = list(s["establishes"])[:1] + [
            "that the pinned approver is not independent of the contract, so no verdict is rendered"]
        return out
    with _walk_classifier(_approver_classifier(contract, set(gated), v16.classify_approval_v2)):
        s = v19.settle_v1_9(contract, events, view, **kw)
    out = dict(s)
    out["schema"], out["settled_under"] = SETTLE_SCHEMA, v19.SETTLE_SCHEMA
    reasons = _unverified_reasons(events, contract, set(gated))
    devs, unverified = [], []
    for d in s.get("deviations") or []:
        k = (d.get("record_sha256"), d.get("observed"))
        if d.get("clause") == "forged_approval" and reasons.get(k):
            r = reasons[k].pop(0)
            d = {"clause": "approval_unverified", "reason": r, "observed": d.get("observed"), "record_sha256": d.get("record_sha256")}
            unverified.append({"action": d["observed"], "reason": r, "record_sha256": d["record_sha256"]})
        devs.append(d)
    out["deviations"] = devs
    out["approval_gate"] = {
        "required": True, "applied": True, "reading": "pinned",
        "approvers": sorted([{"name": a.get("name"), "key_sha256": hashlib.sha256(b64_raw(a["public_key_ed25519_b64"], 32)).hexdigest(),
                              "actions": sorted(a.get("actions") or [])} for a in approvers(contract)], key=canonical),
        "gated_actions": gated,
        "counted": [a for a in ((s.get("approvals") or {}).get("counted") or []) if a.get("action") in gated],
        "unverified": sorted(unverified, key=canonical)}
    out["establishes"] = list(s["establishes"]) + [
        "that every counted approval for %s was signed by an approver key both parties pinned in the grant, over a2a-approval-v2 bytes "
        "naming these terms by contract_sha256 and the approver's key" % ", ".join(gated)]
    out["does_not_establish"] = list(s.get("does_not_establish") or []) + [
        "that a settler older than v1.10 enforces the pinned approvers",
        "that the pinned approver judged well; only that its key signed"]
    return out


# --------------------------------------------------------------------------- self test
def _strip(s, names):
    return {k: v for k, v in s.items() if k not in names}


FIX = os.path.join(HERE, "fixtures", "babyblueviper1_approver_v2")


def _selftest():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import settle_v1_1 as v11
    import contract_v0 as v0

    n = 0
    # [1] babyblueviper1's nine vectors, through this file's verifier
    V = parse_strict(open(os.path.join(FIX, "vectors.json"), encoding="utf-8").read())
    for name, c in V["contracts"].items():
        assert contract_sha256(c) == V["contract_sha256"][name], name
    agree = 0
    for vec in V["vectors"]:
        c = V["contracts"][vec["contract"]]
        got = verify_approver_approval(c, vec["approval"]) if vec.get("approval") is not None else (policy_reading(c), None)
        assert list(got) == [vec["expect"]["result"], vec["expect"].get("reason")], (vec["id"], got)
        agree += 1
    ref = os.path.join(FIX, "verify_approval_v2.py")
    ref_note = ""
    if os.path.exists(ref) and os.path.exists(os.path.join(FIX, "_ed25519.py")):
        r = subprocess.run([sys.executable, ref], capture_output=True, text=True, cwd=FIX)
        assert r.returncode == 0 and "9/9 agree" in r.stdout, r.stdout[-300:]
        ref_note = "; their reference verifier also 9/9 here"
    n += 1; print("[1] babyblueviper1's vectors (preaction-governance-conformance@9860841): %d/%d agree, contract digests match%s" % (agree, len(V["vectors"]), ref_note))

    def newkey():
        k = Ed25519PrivateKey.generate()
        return k, base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    ka, pa = newkey(); kb, pb = newkey(); kw, pw = newkey(); kz, pz = newkey(); kf, pf = newkey()
    PDG = "a" * 64
    base = v11._Chain(60, "00" * 32, "common")
    for _ in range(38):
        base.block()
    lb = {"kind": "bitcoin_block", "height": 97, "hash": base.hashes[97]}
    DNE = ["that HS enforced any of this at runtime",
           "that the contractor obeyed the grant, only that its recorded acts match or deviate from it",
           "that HS judges liability or fault; the verdict is a function anyone recomputes",
           "that a prohibited action was impossible, only that performing one is a provable deviation",
           "that this is a legal contract or determines legal responsibility"]
    COND = [{"action": "emit_witness", "requires": "approver"}, {"action": "refund", "requires": "principal_approval"}]
    PIN = [{"name": "approver.example", "public_key_ed25519_b64": pz, "actions": ["emit_witness"]}]

    def grant(approvers_=None, **over):
        g = {"authorized_actions": ["read", "emit_witness", "refund"], "prohibited_actions": ["delete"], "conditional": COND,
             "delegation": {"allowed": []}, "revocation": {"effective_at": "anchor"},
             "finality": {"depth": 3, "max_target_bits": "207fffff"},
             "witnesses": [{"name": "nenrin-walker", "public_key_ed25519_b64": pw}]}
        if approvers_ is not None:
            g["approval_policy"] = {"allow_unscoped": False, "approvers": approvers_}
        g.update(over)
        return g

    def mk(approvers_=None, nonce="a" * 32):
        c = v0.build_contract(
            {"domain": "a.example", "key_url": "https://a.example/k.json", "public_key_ed25519_b64": pa},
            {"domain": "b.example", "key_url": "https://b.example/k.json", "public_key_ed25519_b64": pb},
            {"purpose": "endpoint_conduct_walk", "payload_digest": PDG, "a2a_task_id": "t1"}, grant(approvers_),
            ["that both parties signed these grant bytes at the stated time"], DNE,
            bond={"amount": 1000, "currency": "JPY"}, lower_bound=lb,
            contract_id="0123456789abcdef0123456789abcdef", nonce=nonce, agreed_at="2026-10-05T00:00:00Z")
        v0.sign_contract(c, ka, pa, "a.example"); v0.sign_contract(c, kb, pb, "b.example")
        return c

    def ex(c, actions, approvals=(), ref="1"):
        r = {"schema": EXEC_SCHEMA,
             "contract_ref": {"contract_id": c["contract_id"], "payload_digest": PDG, "contract_sha256": contract_sha256(c)},
             "performed_actions": list(actions), "approvals": list(approvals), "delegated_to": [], "nenrin_ref": (ref * 64)[:64]}
        return v12.sign_record(r, kb, "contractor")

    def run(blocks, tag):
        ch = base.fork(98, tag)
        recs = []
        for blk in blocks:
            recs += ch.block(blk) if blk else ch.block()
        for _ in range(5):
            ch.block()
        return recs, ch.view()

    def za(c, action="emit_witness", nonce="22" * 16, key=None, name="approver.example", pin_key=None, vu=500):
        return sign_approver_approval(key or kz, c, action, vu, nonce, name, pin_key or pz)

    # [2] the contract door and delegation
    C = mk(PIN)
    assert v0.verify_contract(C)["verdict"] == "accepted", v0.verify_contract(C)
    for bad, frag in (([{"name": "x", "public_key_ed25519_b64": pz, "actions": ["read"]}], "only grant.conditional"),
                      ([{"name": "x", "public_key_ed25519_b64": "AAAA", "actions": ["emit_witness"]}], "canonical 32 byte"),
                      ([{"name": "x", "public_key_ed25519_b64": pz, "actions": ["emit_witness"], "url": "y"}], "{name, public_key_ed25519_b64, actions}"),
                      ([PIN[0], dict(PIN[0])], "unique"),
                      ([], "1 to 16")):
        r = v0.verify_contract(mk(bad, nonce="e" * 32))
        assert r["verdict"] != "accepted" and any(frag in x.get("why", "") for x in r["refusals"]), (frag, r["refusals"])
    pg, cg = grant(PIN), grant([{"name": "approver.example", "public_key_ed25519_b64": pf, "actions": ["emit_witness"]}])
    assert any("pinned approvers" in x for x in v0.grant_subset(cg, pg)) and any("pinned approvers" in x for x in v0.grant_subset(grant(None), pg))
    assert not any("pinned approvers" in x for x in v0.grant_subset(grant(PIN), pg))
    n += 1; print("[2] contract door: approvers accepted; non-conditional action, bad key, unknown field, duplicate, empty list refused; a delegated child that swaps or drops the approvers is narrower-violating")

    # [3] no approvers: v1.10 renders v1.9 apart from the named fields
    C0 = mk(None, nonce="b" * 32)
    recs, view = run([[ex(C0, ["emit_witness"], [v16.sign_approval_v2(ka, C0, "emit_witness", 500, "11" * 16)])]], "t3")
    s9, s10 = v19.settle_v1_9(C0, recs, view), settle_v1_10(C0, recs, view)
    assert s10["verdict"] == "within_grant" and s10["approval_gate"] == {"required": False, "reading": "approval_self_asserted"}
    assert canonical(_strip(s10, SAME_EXCEPT)) == canonical(_strip(s9, SAME_EXCEPT))
    n += 1; print("[3] no approvers pinned: v1.10 == v1.9 on every field except the named ones; reading approval_self_asserted")

    # [4] the pinned approver signs: counted, within_grant, final
    recs, view = run([[ex(C, ["emit_witness"], [za(C)])]], "t4")
    s = settle_v1_10(C, recs, view)
    assert s["verdict"] == "within_grant" and s["status"] == "final" and s["bond_outcome"] == "held", s.get("deviations")
    assert [a["action"] for a in s["approval_gate"]["counted"]] == ["emit_witness"]
    n += 1; print("[4] approval by the pinned approver: counted, within_grant, final, bond held")

    # [5] what does not count for a gated action, each with its reason
    cases = (("principal signs it", [v16.sign_approval_v2(ka, C, "emit_witness", 500, "33" * 16)], "not_an_approver_approval"),
             ("bare {action}", [{"action": "emit_witness"}], "not_an_approver_approval"),
             ("unpinned key, pinned name", [za(C, key=kf)], "bad_signature"),
             ("contractor's key, pinned name", [za(C, key=kb)], "bad_signature"),
             ("signed for other terms", [za(mk(PIN, nonce="f" * 32))], "bad_signature"),
             ("single_use flipped after signing", [dict(za(C), single_use=False)], "bad_signature"),
             ("unpinned approver name", [za(C, name="someone-else")], "approver_not_pinned"),
             ("malformed nonce", [dict(za(C), nonce="xyz")], "malformed"))
    for i, (what, aps, reason) in enumerate(cases):
        recs, view = run([[ex(C, ["emit_witness"], aps)]], "t5%d" % i)
        s = settle_v1_10(C, recs, view)
        got = sorted((d["clause"], d.get("reason")) for d in s["deviations"])
        assert s["verdict"] == "deviation" and ("approval_unverified", reason) in got and ("conditional", None) in got, (what, got)
    n += 1; print("[5] for the gated action: principal's signature, bare {action}, unpinned key, contractor's key, other terms, edited field, unpinned name, malformed nonce: each approval_unverified with its reason, conditional deviation")

    # [6] v1.7's ordering and single use, unchanged
    recs, view = run([[ex(C, ["emit_witness"], ref="6")], [ex(C, ["read"], [za(C, nonce="66" * 16)], ref="7")]], "t6")
    assert [d["clause"] for d in settle_v1_10(C, recs, view)["deviations"]] == ["conditional"]
    once = za(C, nonce="67" * 16)
    recs, view = run([[ex(C, ["read"], [once], ref="8")], [ex(C, ["emit_witness"], ref="9")], [ex(C, ["emit_witness"], ref="a")]], "t6b")
    dv = settle_v1_10(C, recs, view)["deviations"]
    assert [d.get("why") for d in dv] == ["approval_reused"], dv
    n += 1; print("[6] approver's approval a block after the action: conditional; one single_use approval for two actions: approval_reused")

    # [6b] the rest of the approval lifecycle (Issue #29, pipavlo82): repeatable, other action, expiry
    rep = sign_approver_approval(kz, C, "emit_witness", 500, "68" * 16, "approver.example", pz, single_use=False)
    recs, view = run([[ex(C, ["read"], [rep], ref="b")], [ex(C, ["emit_witness"], ref="c")], [ex(C, ["emit_witness"], ref="d")]], "t6c")
    s = settle_v1_10(C, recs, view)
    assert s["verdict"] == "within_grant" and s["deviations"] == [], s["deviations"]
    recs, view = run([[ex(C, ["refund"], [za(C, nonce="69" * 16)], ref="e")]], "t6d")
    dv = settle_v1_10(C, recs, view)["deviations"]
    assert [(d["clause"], d["observed"]) for d in dv] == [("conditional", "refund")], dv
    recs, view = run([[ex(C, ["read"], [za(C, nonce="6a" * 16, vu=0)], ref="f")], [ex(C, ["emit_witness"], ref="0")]], "t6e")
    dv = settle_v1_10(C, recs, view)["deviations"]
    assert [(d["clause"], d.get("why")) for d in dv] == [("conditional", "approval_expired")], dv
    n += 1; print("[6b] single_use false covers two later executions: within_grant; an approval for emit_witness carried with refund: refund conditional; an approval past valid_until_height: approval_expired")

    # [7] an action no approver lists keeps v1.6's rule
    recs, view = run([[ex(C, ["emit_witness", "refund"], [za(C), v16.sign_approval_v2(ka, C, "refund", 500, "77" * 16)])]], "t7")
    s = settle_v1_10(C, recs, view)
    assert s["verdict"] == "within_grant", s["deviations"]
    recs, view = run([[ex(C, ["refund"], [sign_approver_approval(kz, C, "refund", 500, "78" * 16, "approver.example", pz)])]], "t7b")
    got = sorted((d["clause"], d.get("reason")) for d in settle_v1_10(C, recs, view)["deviations"])
    assert ("approval_unverified", "action_not_permitted_for_approver") in got, got
    n += 1; print("[7] refund (not gated) approved by the principal: within_grant; the approver approving refund: action_not_permitted_for_approver")

    # [8] the approver is a party or a witness
    for key, reason in ((pa, "approver_is_party"), (pw, "approver_is_witness")):
        Cx = mk([{"name": "x", "public_key_ed25519_b64": key, "actions": ["emit_witness"]}], nonce="c" * 32)
        recs, view = run([[ex(Cx, ["emit_witness"])]], "t8" + reason[-5:])
        s = settle_v1_10(Cx, recs, view)
        assert s["verdict"] == "underspecified" and reason in [u["reason"] for u in s["underspecified"]], (reason, s.get("underspecified"))
    n += 1; print("[8] approver key is a party's, or a witness's: underspecified, no verdict")

    # [9] the classifier is restored after a call, and after an exception inside the call
    assert v17.classify_approval_v2 is v16.classify_approval_v2
    real = v19.settle_v1_9
    def boom(*a, **k):
        raise RuntimeError("boom")
    v19.settle_v1_9 = boom
    try:
        settle_v1_10(C, [], view)
    except RuntimeError:
        pass
    finally:
        v19.settle_v1_9 = real
    assert v17.classify_approval_v2 is v16.classify_approval_v2
    n += 1; print("[9] v1.7's classifier name restored after a call and after an exception")

    # [10] determinism
    recs, view = run([[ex(C, ["emit_witness", "refund"], [za(C), v16.sign_approval_v2(ka, C, "refund", 500, "77" * 16), {"action": "emit_witness"}])],
                      [ex(C, ["read"], ref="9")]], "t10")
    ref_b = canonical(settle_v1_10(C, recs, view))
    rng = random.Random(10)
    for _ in range(20):
        rr = list(recs) + [recs[0]]; rng.shuffle(rr)
        assert canonical(settle_v1_10(C, rr, view)) == ref_b
    n += 1; print("[10] 20 shuffles with a duplicate: identical settlement bytes")

    # [11] mutants: each must change a verdict the tests above expect
    killed = 0
    g = globals()
    saved = {k: g[k] for k in ("_approver_classifier", "verify_approver_approval", "_party_problems")}
    try:
        g["_approver_classifier"] = lambda c, gt, o: o                                   # M1: ignore the gate
        recs, view = run([[ex(C, ["emit_witness"], [v16.sign_approval_v2(ka, C, "emit_witness", 500, "33" * 16)])]], "m1")
        killed += settle_v1_10(C, recs, view)["verdict"] != "deviation"
        g["_approver_classifier"] = saved["_approver_classifier"]
        g["verify_approver_approval"] = lambda c, e: ("approved", None) if isinstance(e, dict) and e.get("by") == "approver" else saved["verify_approver_approval"](c, e)   # M2: skip the signature
        recs, view = run([[ex(C, ["emit_witness"], [za(C, key=kf)])]], "m2")
        killed += settle_v1_10(C, recs, view)["verdict"] != "deviation"
        g["verify_approver_approval"] = saved["verify_approver_approval"]
        g["_party_problems"] = lambda c: []                                               # M3: a party may approve
        Cx = mk([{"name": "x", "public_key_ed25519_b64": pa, "actions": ["emit_witness"]}], nonce="d" * 32)
        recs, view = run([[ex(Cx, ["emit_witness"], [sign_approver_approval(ka, Cx, "emit_witness", 500, "99" * 16, "x", pa)])]], "m3")
        killed += settle_v1_10(Cx, recs, view)["verdict"] != "underspecified"
    finally:
        g.update(saved)
    assert killed == 3, killed
    n += 1; print("[11] 3 mutants (gate ignored, signature skipped, a party allowed as approver): all 3 caught")

    # [12] run0002 and the layers below
    rr = os.path.join(HERE, "run0002")
    if os.path.isdir(rr):
        rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
        C2 = rd(os.path.join(HERE, "second_contract_AB.json"))
        args = (C2, [rd(os.path.join(rr, "exec_19c44a79.anchored.json"))], rd(os.path.join(rr, "view.json")))
        nr = [rd(os.path.join(rr, "walk_8bf29f1a.json"))]
        s10, s9 = settle_v1_10(*args, nenrin_records=nr), v19.settle_v1_9(*args, nenrin_records=nr)
        assert s10["status"] == "final" and canonical(_strip(s10, SAME_EXCEPT)) == canonical(_strip(s9, SAME_EXCEPT))
        n += 1; print("[12] run0002: v1.10 == v1.9 apart from the named fields, final")
    r = subprocess.run([sys.executable, os.path.join(HERE, "settle_v1_9.py"), "--selftest"], capture_output=True, text=True)
    assert r.returncode == 0 and "SELF-TEST PASSED" in r.stdout, (r.stdout[-300:], r.stderr[-300:])
    n += 1; print("[13] settle_v1_9 self test (and every layer it runs, contract_v0 included) still passes")

    print("\nSELF-TEST PASSED: MUSUBI settle v1.10, %d checks (babyblueviper1's 9 vectors agree; contract door and delegation; no approvers: "
          "v1.9 unchanged; pinned approver counted; 8 kinds of approval refused with reasons; ordering and single use unchanged; repeatable, other action and expiry; ungated "
          "keeps the principal; party or witness as approver refused; classifier restored; determinism; 3 mutants caught; run0002 unchanged)" % n)


def main():
    ap = argparse.ArgumentParser(description="MUSUBI settle v1.10 (a conditional action can require a pinned approver with no stake)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--settle", metavar="CONTRACT.json")
    ap.add_argument("--event", action="append", default=[])
    ap.add_argument("--view", action="append", default=[])
    ap.add_argument("--nenrin", action="append", default=[])
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return 0
    if not a.settle or not a.view:
        ap.print_help(); return 1
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    contract = rd(a.settle)
    views = [rd(p) for p in a.view]
    cmp = v19.v18.v17.v14.compare_views_v1_4(views, contract)
    if cmp["chosen"] is None:
        print(json.dumps({"fork_choice": cmp}, indent=2)); return 2
    s = settle_v1_10(contract, [rd(p) for p in a.event], views[cmp["chosen"]], nenrin_records=[rd(p) for p in a.nenrin] or None)
    if a.out:
        open(a.out, "w", encoding="utf-8", newline="").write(canonical(s))
    print(json.dumps(s, ensure_ascii=False, indent=2))
    return 0 if s["status"] == "final" else 2


if __name__ == "__main__":
    sys.exit(main())
