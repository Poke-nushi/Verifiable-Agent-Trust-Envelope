#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI settle v1.11: when the contract requires admission before execution, an execution is read against the
relying party's signed admission (a2a-settlement-v1.11). One rule, and nothing else.

Why this file exists. A relying party can decide, at its own door and before the act, whether an action
is inside the signed grant. That decision is only worth something if settlement can check it afterwards: that an
admission existed, that it said admit, that what ran is what was admitted, that the admission was not written after
the fact, and that the relying party did not wave through something outside the grant.

When the rule applies. Only when contract.requirements.admission == "required_before_execution". For every other
contract this file returns settle v1.10's result unchanged, the same bytes, schema line included. run0002, the second
contract and the outside parties' contract d7118f28 carry no such requirement and settle exactly as before.

The rule, for each action in each execution record the lower layers accepted:

  unadmitted_execution           the record's admission_ref names no admission for the action, or names one that is
                                 not in hand, does not verify under the relying party's key, is for other terms, or
                                 was already used by an earlier action
  executed_after_refusal         the admission's decision was refuse, or escalate without a countable approval
                                 carried in the execution record
  executed_other_than_admitted   the digest of what the record says it executed is not the admission's
                                 action_binding_digest (an action changed between admission and execution)
  admission_after_execution      the admission's anchor is above the execution's anchor, or it has none
  admitted_out_of_grant          the admission said admit, and the shared clause evaluator, run here again, puts the
                                 action outside the grant. The relying party's signature is on that admission; this
                                 file states the fact and names the domain, it does not assign fault.

An execution record under such a contract carries
    "admission_ref": [{"action", "admission_sha256", "executed": {"action", "target", "amount", "nonce", "expiry_height"}}]
admission_sha256 is admission_verify_v0.admission_sha256 (the bytes the relying party signed). The lower layers refuse unknown
record fields, so for the length of one call this file adds admission_ref to settle v1.3's execution field list and
restores it in a finally block, the way v1.10 swaps v1.7's classifier. No earlier settle file is edited.

Inputs beyond v1.10: admissions (signed a2a-admission-v0 records, each with the anchor it was given), and relying_keys
({domain: public_key_ed25519_b64}, fetched by the caller from each record's key_url). A settler opens no socket.

Stated limits: as v1.10. The admission's anchor height is read as stated; verifying that anchor against headers is the
same step as for any anchored record and is the caller's when it collects the admissions. A relying party that never
publishes its admissions leaves executions unadmitted; that is the contract's requirement working, not a finding about
the contractor's conduct beyond that.
"""
import argparse, contextlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import settle_v1 as v1
import settle_v1_2 as v12
import settle_v1_3 as v13
import settle_v1_5 as v15
import settle_v1_10 as v110
import clause_eval_v0 as ce
import admission_verify_v0 as A
from contract_v0 import canonical, parse_strict, contract_sha256, EXEC_SCHEMA

SETTLE_SCHEMA = "a2a-settlement-v1.11"
REQUIRED = "required_before_execution"
CLAUSES = ("unadmitted_execution", "executed_after_refusal", "executed_other_than_admitted", "admission_after_execution", "admitted_out_of_grant")


def admission_required(contract):
    r = contract.get("requirements") if isinstance(contract, dict) else None
    return isinstance(r, dict) and r.get("admission") == REQUIRED


@contextlib.contextmanager
def _exec_field(name):
    fields = v13.FIELDS[EXEC_SCHEMA]
    had = name in fields
    fields.add(name)
    try:
        yield
    finally:
        if not had:
            fields.discard(name)


def _admission_index(contract, admissions, relying_keys):
    """admission_sha256 -> (record, anchor height or None), for the admissions that verify under a key the caller supplied."""
    out, unverified = {}, set()
    keys = relying_keys if isinstance(relying_keys, dict) else {}
    for rec in admissions if isinstance(admissions, list) else []:
        if not isinstance(rec, dict) or rec.get("schema") != A.SCHEMA:
            continue
        body = {k: v for k, v in rec.items() if k != "anchor"}
        sha = A.admission_sha256(body)
        dom = (rec.get("relying_party") or {}).get("domain") if isinstance(rec.get("relying_party"), dict) else None
        if A.verify_admission(body, keys.get(dom), contract)["verdict"] != "accepted":
            unverified.add(sha)
            continue
        anchor = rec.get("anchor") if isinstance(rec.get("anchor"), dict) else {}
        h = anchor.get("height") if isinstance(anchor.get("height"), int) and not isinstance(anchor.get("height"), bool) else None
        out[sha] = (body, h)
    return out, unverified


def admission_deviations(contract, events, admissions, relying_keys, skip=()):
    """The v1.11 rule over the execution records, in (anchor height, record sha256) order. Returns (deviations, read)."""
    csha = contract_sha256(contract)
    index, unverified = _admission_index(contract, admissions, relying_keys)
    recs, seen = [], set()
    for ev in events if isinstance(events, list) else []:
        if not (isinstance(ev, dict) and ev.get("schema") == EXEC_SCHEMA):
            continue
        if (ev.get("contract_ref") or {}).get("contract_sha256") != csha or v12.authenticate(ev, contract):
            continue
        s, h = v1.rec_sha(ev), v1.height_of(ev)
        if s in seen or s in skip or h is None:
            continue
        seen.add(s)
        recs.append((h, s, ev))
    recs.sort(key=lambda t: (t[0], t[1]))
    devs, used, read = [], set(), []
    for h, s, ev in recs:
        refs = [r for r in (ev.get("admission_ref") or []) if isinstance(r, dict)] if isinstance(ev.get("admission_ref"), list) else []
        taken = set()
        for a in [x for x in (ev.get("performed_actions") or []) if isinstance(x, str)]:
            d = lambda clause, why, sha=None: {"clause": clause, "observed": a, "height": h, "record_sha256": s, "admission_sha256": sha, "why": why}
            i = next((i for i, r in enumerate(refs) if i not in taken and r.get("action") == a), None)
            if i is None:
                devs.append(d("unadmitted_execution", "the execution record names no admission for this action")); continue
            taken.add(i)
            ref = refs[i]
            sha = ref.get("admission_sha256")
            if sha in unverified:
                devs.append(d("unadmitted_execution", "the admission named does not verify under the relying party's key in hand", sha)); continue
            if sha not in index:
                devs.append(d("unadmitted_execution", "the admission named was not presented to this settler", sha)); continue
            if sha in used:
                devs.append(d("unadmitted_execution", "the admission named was already used by an earlier action", sha)); continue
            used.add(sha)
            adm, ah = index[sha]
            dom = (adm.get("relying_party") or {}).get("domain")
            read.append({"action": a, "admission_sha256": sha, "decision": adm.get("decision"), "relying_party": dom, "record_sha256": s})
            ev_now = ce.evaluate_action(contract, a, approvals=ev.get("approvals") or [], height=(adm.get("chain_view") or {}).get("height"))
            if adm.get("decision") == "refuse":
                devs.append(d("executed_after_refusal", "the admission's decision was refuse (%s)" % ", ".join(adm.get("reasons") or []), sha))
            elif adm.get("decision") == "escalate" and "conditional" in ev_now["clauses"]:
                devs.append(d("executed_after_refusal", "the admission's decision was escalate and the execution carries no countable approval", sha))
            ex = ref.get("executed") if isinstance(ref.get("executed"), dict) else {}
            digest = A.action_digest(csha, {"action": {"action": ex.get("action"), "target": ex.get("target"), "amount": ex.get("amount")},
                                            "nonce": ex.get("nonce"), "expiry_height": ex.get("expiry_height")})
            if ex.get("action") != a or digest != (adm.get("action_ref") or {}).get("action_binding_digest"):
                devs.append(d("executed_other_than_admitted", "the digest of what was executed is not the admission's action_binding_digest", sha))
            if ah is None or ah > h:
                devs.append(d("admission_after_execution", "the admission has no anchor" if ah is None else "the admission is anchored at %d, the execution at %d" % (ah, h), sha))
            if adm.get("decision") == "admit" and [c for c in ev_now["clauses"] if c in ("prohibited", "unauthorized", "conditional")]:
                devs.append(d("admitted_out_of_grant", "relying party %s signed admit; the shared clause evaluator reads this action as %s under these terms"
                              % (dom, ", ".join(c for c in ev_now["clauses"] if c in ("prohibited", "unauthorized", "conditional"))), sha))
    return devs, read


def settle_v1_11(contract, events, view, admissions=None, relying_keys=None, mode="strict", nenrin_records=None, spine=None,
                 pool=None, contract_anchor_height=None, history=None):
    kw = dict(mode=mode, nenrin_records=nenrin_records, spine=spine, pool=pool,
              contract_anchor_height=contract_anchor_height, history=history)
    if not admission_required(contract):
        return v110.settle_v1_10(contract, events, view, **kw)
    with _exec_field("admission_ref"):
        s = v110.settle_v1_10(contract, events, view, **kw)
    out = dict(s)
    out["schema"], out["settled_under"] = SETTLE_SCHEMA, v110.SETTLE_SCHEMA
    skip = {x.get("sha256") for k in ("rejected", "orphaned", "predates_contract") for x in (s.get(k) or []) if isinstance(x, dict)}
    devs, read = ([], []) if s.get("verdict") == "underspecified" else admission_deviations(contract, events, admissions, relying_keys, skip=skip)
    out["deviations"] = list(s.get("deviations") or []) + devs
    if s.get("verdict") != "underspecified":
        out["verdict"] = "deviation" if out["deviations"] else "within_grant"
        out["bond_outcome"] = v15._bond_outcome(contract, out["verdict"], out.get("status"))
    out["admission_gate"] = {"required": True, "requirement": REQUIRED, "rule": SETTLE_SCHEMA, "evaluator_sha256": ce.evaluator_sha256(),
                             "admissions_read": sorted(read, key=canonical),
                             "counts": {c: sum(1 for d in devs if d["clause"] == c) for c in CLAUSES}}
    out["establishes"] = list(s.get("establishes") or []) + [
        "that every executed action was read against the relying party's signed admission named in the execution record, under the rule in a2a-settlement-v1.11",
        "that each admission's decision was recomputed here with the clause evaluator the admission names (admission_gate.evaluator_sha256)"]
    out["does_not_establish"] = list(s.get("does_not_establish") or []) + [
        "that a relying party which published no admission refused nothing; only that no admission was presented",
        "that HS allowed or blocked anything; the relying party ran admit() at its own door",
        "who is at fault when an admission and the grant disagree; the signatures show who signed what"]
    return out


# --------------------------------------------------------------------------- self test
FIXTURE = os.path.join(HERE, "fixtures", "settle_admission", "cases.json")


def load_fixture():
    """The scenarios the self tests read. They were made by a relying party's door that this repository does not carry
    (its implementation is not public); the records it signed are here, and anyone can settle them again.
    Returns (contracts, cases, relying_keys)."""
    f = parse_strict(open(FIXTURE, encoding="utf-8").read())
    return f["contracts"], f["cases"], f["relying_keys_pub_b64"]


def settle_fixture_case(settle, name, fixture=None, drop_admissions=False):
    contracts, cases, keys = fixture or load_fixture()
    c = cases[name]
    return settle(contracts[c["contract"]], c["events"], c["view"], admissions=[] if drop_admissions else c["admissions"], relying_keys=keys)


def _selftest():
    import hashlib, subprocess
    n = 0
    fx = load_fixture()
    contracts, cases, KEYS = fx
    P, AP, AN = contracts["plain"], contracts["admission_plain"], contracts["admission_pinned"]
    assert admission_required(AP) and admission_required(AN) and not admission_required(P)
    assert A.check_fixtures() == 0
    run = lambda name: settle_fixture_case(settle_v1_11, name, fx)
    clauses = lambda s: sorted(d["clause"] for d in s["deviations"])
    decided = lambda name: tuple(cases[name]["admission_decision"] or ())

    # [0] every v1.11 case in the fixture settles to the bytes recorded when it was made
    mine = sorted(k for k, c in cases.items() if c["expect"]["layer"] == "v1.11")
    for k in mine:
        s = run(k)
        assert hashlib.sha256(canonical(s).encode("utf-8")).hexdigest() == cases[k]["expect"]["settlement_sha256"], k
        assert (s["verdict"], s["status"], clauses(s)) == (cases[k]["expect"]["verdict"], cases[k]["expect"]["status"], cases[k]["expect"]["clauses"]), k
    n += 1; print("[0] %d fixture scenarios settle to the recorded bytes" % len(mine))

    # [1] no requirement: v1.11 returns v1.10's bytes
    corpus = sorted(k for k in cases if k.startswith("corpus/"))
    for k in corpus:
        c = cases[k]
        s10 = v110.settle_v1_10(contracts[c["contract"]], c["events"], c["view"])
        assert canonical(settle_v1_11(contracts[c["contract"]], c["events"], c["view"])) == canonical(s10), k
        assert hashlib.sha256(canonical(s10).encode("utf-8")).hexdigest() == c["expect"]["settlement_sha256"], k
    assert len(corpus) == 18
    rr = os.path.join(HERE, "run0002")
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    C2 = rd(os.path.join(HERE, "second_contract_AB.json"))
    args = (C2, [rd(os.path.join(rr, "exec_19c44a79.anchored.json"))], rd(os.path.join(rr, "view.json")))
    nr = [rd(os.path.join(rr, "walk_8bf29f1a.json"))]
    assert canonical(settle_v1_11(*args, nenrin_records=nr)) == canonical(v110.settle_v1_10(*args, nenrin_records=nr))
    assert contract_sha256(C2).startswith("14474983")
    n += 1; print("[1] contracts with no requirements.admission: v1.11 is v1.10 byte for byte (18 corpus scenarios, run0002 under the second contract 14474983)")

    # [2] admitted before, executed as admitted: within_grant
    s = run("v11/read")
    assert s["schema"] == SETTLE_SCHEMA and s["verdict"] == "within_grant" and s["status"] == "final" and s["deviations"] == [], s["deviations"]
    assert s["admission_gate"]["admissions_read"][0]["decision"] == "admit" and s["admission_gate"]["evaluator_sha256"] == ce.evaluator_sha256()
    assert run("v11/refund_principal_approved")["verdict"] == "within_grant" and run("v11/emit_approver_approved")["verdict"] == "within_grant"
    n += 1; print("[2] admit before, the same action executed after: within_grant, final (plain, conditional with the principal's approval, gated with the pinned approver's)")

    # [3] rule 1: unadmitted
    for k in ("v11/read_no_admission_ref", "v11/read_admission_not_presented", "v11/read_admission_signed_by_stranger", "v11/read_admission_signed_by_applicant"):
        assert clauses(run(k)) == ["unadmitted_execution"], (k, clauses(run(k)))
    n += 1; print("[3] no admission_ref, an admission not presented, one signed by a stranger, one signed by the applicant itself: unadmitted_execution")

    # [4] rule 2: executed after refusal, or after escalate with no approval
    s = run("v11/delete_refused")
    assert decided("v11/delete_refused")[0] == "refuse" and "executed_after_refusal" in clauses(s) and "prohibited" in clauses(s), clauses(s)
    s = run("v11/refund_escalated_no_approval")
    assert decided("v11/refund_escalated_no_approval")[0] == "escalate" and clauses(s) == ["conditional", "executed_after_refusal"], clauses(s)
    s = run("v11/refund_escalated_approval_carried")
    assert decided("v11/refund_escalated_approval_carried")[0] == "escalate" and s["verdict"] == "within_grant", clauses(s)
    n += 1; print("[4] executed after refuse: executed_after_refusal (and the grant's own clause); after escalate with no approval: the same; after escalate with the approval carried: within_grant")

    # [5] rule 3: something else was executed
    assert clauses(run("v11/read_executed_other_target")) == ["executed_other_than_admitted"]
    s = run("v11/read_admission_used_for_emit")
    assert "unadmitted_execution" in clauses(s) or "executed_other_than_admitted" in clauses(s), clauses(s)
    n += 1; print("[5] the executed target differs from the admitted one: executed_other_than_admitted; another action run on a read admission: not covered by it")

    # [6] rule 4: the admission came after
    assert clauses(run("v11/read_admission_anchored_above")) == ["admission_after_execution"]
    assert clauses(run("v11/read_admission_not_anchored")) == ["admission_after_execution"]
    assert run("v11/read_admission_same_block")["verdict"] == "within_grant"
    n += 1; print("[6] admission anchored above the execution, or not anchored: admission_after_execution; anchored in the same block or below: fine")

    # [7] rule 5: the relying party admitted something outside the grant
    s = run("v11/delete_admitted_by_mistake")
    assert "admitted_out_of_grant" in clauses(s) and "executed_after_refusal" not in clauses(s), clauses(s)
    why = next(d["why"] for d in s["deviations"] if d["clause"] == "admitted_out_of_grant")
    assert "shop.example" in why and "prohibited" in why
    s = run("v11/transfer_admitted_by_mistake")
    assert "admitted_out_of_grant" in clauses(s) and "unauthorized" in clauses(s)
    assert "admitted_out_of_grant" in clauses(run("v11/refund_admitted_by_mistake"))
    n += 1; print("[7] a relying party signs admit for a prohibited, an unauthorized or an unapproved conditional action: admitted_out_of_grant, naming the domain that signed")

    # [8] one admission, two executions
    s = run("v11/one_admission_two_executions")
    assert clauses(s) == ["unadmitted_execution"] and "already used" in s["deviations"][0]["why"], s["deviations"]
    n += 1; print("[8] the same admission named by two executions: the second is unadmitted_execution")

    # [9] the field list is restored, also after an exception
    assert "admission_ref" not in v13.FIELDS[EXEC_SCHEMA]
    real = v110.settle_v1_10
    def boom(*a, **k):
        raise RuntimeError("boom")
    v110.settle_v1_10 = boom
    try:
        run("v11/read")
    except RuntimeError:
        pass
    finally:
        v110.settle_v1_10 = real
    assert "admission_ref" not in v13.FIELDS[EXEC_SCHEMA]
    s = run("v11/no_requirement_refuses_admission_ref")
    assert any(d["clause"] == "nonconforming_record" for d in s["deviations"]), s["deviations"]
    n += 1; print("[9] settle v1.3's field list is restored after a call and after an exception; a contract without the requirement still refuses admission_ref as an unknown field")

    # [10] determinism
    assert canonical(run("v11/delete_admitted_by_mistake")) == canonical(run("v11/delete_admitted_by_mistake"))
    n += 1; print("[10] the same inputs give the same settlement bytes")

    # [11] mutants: each must change a verdict the tests above expect
    g, killed = globals(), 0
    saved = g["admission_deviations"]
    try:
        g["admission_deviations"] = lambda *a, **k: ([], [])                                  # M1: the rule is skipped
        killed += run("v11/read_no_admission_ref")["verdict"] == "within_grant"
    finally:
        g["admission_deviations"] = saved
    real_eval = ce.evaluate_action
    try:
        ce.evaluate_action = lambda *a, **k: {"class": "authorized", "clauses": [], "approval": None, "why": None}   # M2: the recompute always agrees
        killed += "admitted_out_of_grant" not in clauses(run("v11/delete_admitted_by_mistake"))
    finally:
        ce.evaluate_action = real_eval
    real_ver = A.verify_admission
    try:
        A.verify_admission = lambda *a, **k: {"verdict": "accepted", "refusals": []}          # M3: any signature is accepted
        killed += clauses(run("v11/read_admission_signed_by_stranger")) == []
    finally:
        A.verify_admission = real_ver
    assert killed == 3, killed
    n += 1; print("[11] 3 mutants (rule skipped, recompute always agrees, any admission signature accepted): all 3 change a verdict the checks above expect")

    r = subprocess.run([sys.executable, os.path.join(HERE, "settle_v1_10.py"), "--selftest"], capture_output=True, text=True)
    assert r.returncode == 0 and "SELF-TEST PASSED" in r.stdout, (r.stdout[-300:], r.stderr[-300:])
    n += 1; print("[12] settle_v1_10 self test (and every layer it runs) still passes")

    print("\nSELF-TEST PASSED: MUSUBI settle v1.11, %d checks (fixture bytes; no requirement: v1.10 byte for byte; admitted and executed: within_grant; "
          "unadmitted; after refusal; other than admitted; admission after execution; admitted out of grant; single use; field list restored; "
          "determinism; 3 mutants; v1.10 unchanged)" % n)


def main():
    ap = argparse.ArgumentParser(description="MUSUBI settle v1.11 (executions read against the relying party's admission when the contract requires one)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--settle", metavar="CONTRACT.json")
    ap.add_argument("--event", action="append", default=[])
    ap.add_argument("--view", action="append", default=[])
    ap.add_argument("--nenrin", action="append", default=[])
    ap.add_argument("--admission", action="append", default=[], help="a signed a2a-admission-v0 record with its anchor")
    ap.add_argument("--relying-key", action="append", default=[], metavar="DOMAIN=BASE64", help="the relying party's Ed25519 key, fetched from its key_url")
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return 0
    if not a.settle or not a.view:
        ap.print_help(); return 1
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    contract = rd(a.settle)
    views = [rd(p) for p in a.view]
    cmp = v110.v19.v18.v17.v14.compare_views_v1_4(views, contract)
    if cmp["chosen"] is None:
        print(json.dumps({"fork_choice": cmp}, indent=2)); return 2
    keys = dict(x.split("=", 1) for x in a.relying_key)
    s = settle_v1_11(contract, [rd(p) for p in a.event], views[cmp["chosen"]], admissions=[rd(p) for p in a.admission], relying_keys=keys,
                     nenrin_records=[rd(p) for p in a.nenrin] or None)
    if a.out:
        open(a.out, "w", encoding="utf-8", newline="").write(canonical(s))
    print(json.dumps(s, ensure_ascii=False, indent=2))
    return 0 if s["status"] == "final" else 2


if __name__ == "__main__":
    sys.exit(main())
