#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI settle v1.12: when the grant carries limits, the amount each execution states is read against them
(a2a-settlement-v1.12). One rule, and nothing else.

Why this file exists. Until now no settle layer saw an amount. A relying party that overlooked a limit and admitted
anyway left nothing for an audit to find, so "admission and settlement do not disagree" did not hold for amounts.
grant.limits (contract_v0, 2026-10-10) puts the limit into the bytes both parties signed; clause_eval_v0.over_limit is
the one reading of it, used by a relying party's door before the act and by this file after it.

When the rule applies. Only when contract.grant.limits is present. For every other contract this file returns settle
v1.11's result unchanged, the same bytes, schema line included: run0002, the second contract, the outside parties'
contract d7118f28 and the 18 scenario corpus carry no limits and settle exactly as before.

Where the amount comes from. An execution record under a contract that requires admission carries
    "admission_ref": [{"action", "admission_sha256", "executed": {"action", "target", "amount", "nonce", "expiry_height"}}]
and executed.amount is the amount. The contract door refuses limits without requirements.admission, so a contract
with limits always has this field to read. The amount is an integer in the unit grant.limits states for the action.

The rule, for each action in each execution record the lower layers accepted:

  amount_over_limit        grant.limits names the action and executed.amount is above max_amount, or the record states
                           no amount for it (no admission_ref entry, or amount null). A limit nobody can compare
                           against was not kept.
  admitted_out_of_grant    the same action was admitted: the relying party's signed admission, named by the record and
                           verified, says admit. v1.11 raises this clause for prohibited, unauthorized and unapproved
                           conditional actions; v1.12 raises it for an amount over the limit. The relying party's
                           signature is on that admission; this file states the fact and names the domain, it does
                           not assign fault.

What holds an amount to what was admitted is v1.11, unchanged: the digest of "executed" must be the admission's
action_binding_digest (executed_other_than_admitted), so an execution cannot state a smaller amount than the one the
relying party read without that being a deviation of its own.

Stated limits: as v1.11. The amount is the one the execution record states and the admission digest binds. Whether
that is the amount that moved in the world is outside these records. No approval lifts a limit: an approval does not
name an amount, so it cannot stand for one.
"""
import argparse, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import settle_v1 as v1
import settle_v1_2 as v12
import settle_v1_5 as v15
import settle_v1_10 as v110
import settle_v1_11 as v111
import clause_eval_v0 as ce
import admission_verify_v0 as A
from contract_v0 import canonical, parse_strict, contract_sha256, EXEC_SCHEMA

SETTLE_SCHEMA = "a2a-settlement-v1.12"
CLAUSES = ("amount_over_limit", "admitted_out_of_grant")


def has_limits(contract):
    g = contract.get("grant") if isinstance(contract, dict) else None
    return isinstance(g, dict) and g.get("limits") is not None


def limit_deviations(contract, events, admissions, relying_keys, skip=(), already=()):
    """The v1.12 rule over the execution records, in (anchor height, record sha256) order. Returns (deviations, read).

    already: (record_sha256, action, admission_sha256) triples for which v1.11 raised admitted_out_of_grant, so that one
    admission of one action is named once."""
    csha = contract_sha256(contract)
    index, _unverified = v111._admission_index(contract, admissions, relying_keys)
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
    devs, read, used, named = [], [], set(), set(already)
    for h, s, ev in recs:
        refs = [r for r in (ev.get("admission_ref") or []) if isinstance(r, dict)] if isinstance(ev.get("admission_ref"), list) else []
        taken = set()
        for a in [x for x in (ev.get("performed_actions") or []) if isinstance(x, str)]:
            i = next((i for i, r in enumerate(refs) if i not in taken and r.get("action") == a), None)
            ref = refs[i] if i is not None else {}
            if i is not None:
                taken.add(i)
            sha = ref.get("admission_sha256")
            first_use = sha in index and sha not in used          # v1.11 counts an admission once; so does this file
            if sha in index:
                used.add(sha)
            lim = ce.limit_for(contract, a)
            if lim is None:
                continue
            ex = ref.get("executed") if isinstance(ref.get("executed"), dict) else {}
            amount = ex.get("amount") if ex.get("action") == a else None
            over = ce.over_limit(contract, a, amount)
            read.append({"action": a, "amount": amount if (isinstance(amount, int) and not isinstance(amount, bool)) else None,
                         "max_amount": lim[0], "unit": lim[1], "over": over, "record_sha256": s})
            if not over:
                continue
            d = lambda clause, why: {"clause": clause, "observed": a, "height": h, "record_sha256": s, "admission_sha256": sha, "why": why}
            devs.append(d("amount_over_limit", "the execution states no amount for %s; grant.limits allows at most %s %s" % (a, lim[0], lim[1])
                          if read[-1]["amount"] is None else
                          "the execution states %d for %s; grant.limits allows at most %s %s" % (amount, a, lim[0], lim[1])))
            if first_use and (s, a, sha) not in named:
                adm, _ah = index[sha]
                if adm.get("decision") == "admit":
                    named.add((s, a, sha))
                    devs.append(d("admitted_out_of_grant", "relying party %s signed admit; the shared clause evaluator reads this amount as over_limit under these terms"
                                  % ((adm.get("relying_party") or {}).get("domain"),)))
    return devs, read


def settle_v1_12(contract, events, view, admissions=None, relying_keys=None, mode="strict", nenrin_records=None, spine=None,
                 pool=None, contract_anchor_height=None, history=None):
    s = v111.settle_v1_11(contract, events, view, admissions=admissions, relying_keys=relying_keys, mode=mode, nenrin_records=nenrin_records,
                          spine=spine, pool=pool, contract_anchor_height=contract_anchor_height, history=history)
    if not has_limits(contract):
        return s
    out = dict(s)
    out["schema"], out["settled_under"] = SETTLE_SCHEMA, s.get("schema")
    skip = {x.get("sha256") for k in ("rejected", "orphaned", "predates_contract") for x in (s.get(k) or []) if isinstance(x, dict)}
    already = {(d.get("record_sha256"), d.get("observed"), d.get("admission_sha256")) for d in (s.get("deviations") or [])
               if isinstance(d, dict) and d.get("clause") == "admitted_out_of_grant"}
    devs, read = ([], []) if s.get("verdict") == "underspecified" else limit_deviations(contract, events, admissions, relying_keys, skip=skip, already=already)
    out["deviations"] = list(s.get("deviations") or []) + devs
    if s.get("verdict") != "underspecified":
        out["verdict"] = "deviation" if out["deviations"] else "within_grant"
        out["bond_outcome"] = v15._bond_outcome(contract, out["verdict"], out.get("status"))
    out["limit_gate"] = {"rule": SETTLE_SCHEMA, "limits": contract["grant"]["limits"], "evaluator_sha256": ce.evaluator_sha256(),
                         "admission_required": v111.admission_required(contract),
                         "amounts_read": sorted(read, key=canonical),
                         "counts": {c: sum(1 for d in devs if d["clause"] == c) for c in CLAUSES}}
    out["establishes"] = list(s.get("establishes") or []) + [
        "that the amount each execution record states for a limited action was read against grant.limits, under the rule in a2a-settlement-v1.12"]
    out["does_not_establish"] = list(s.get("does_not_establish") or []) + [
        "that the amount an execution record states is the amount that moved; only that it is the amount the record states and the admission's digest binds",
        "that an approval lifted a limit; a limit is a cap no approval lifts"]
    return out


# --------------------------------------------------------------------------- self test
def _selftest():
    import hashlib, subprocess
    n = 0
    fx = v111.load_fixture()
    contracts, cases, KEYS = fx
    L, AP = contracts["limits"], contracts["admission_plain"]
    assert has_limits(L) and not has_limits(AP) and v111.admission_required(L)
    run = lambda name: v111.settle_fixture_case(settle_v1_12, name, fx)
    clauses = lambda s: sorted(d["clause"] for d in s["deviations"])
    decided = lambda name: (cases[name]["admission_decision"][0], cases[name]["admission_decision"][1])

    # [0] every case in the fixture settles under v1.12 to the bytes recorded when it was made
    count = 0
    for k, c in sorted(cases.items()):
        s = run(k)
        if c["expect"]["layer"] == "v1.12":
            assert hashlib.sha256(canonical(s).encode("utf-8")).hexdigest() == c["expect"]["settlement_sha256"], k
            assert (s["verdict"], s["status"], clauses(s)) == (c["expect"]["verdict"], c["expect"]["status"], c["expect"]["clauses"]), k
            count += 1
    n += 1; print("[0] %d fixture scenarios settle to the recorded bytes" % count)

    # [1] no limits: v1.12 is v1.11 byte for byte
    same = 0
    for k, c in sorted(cases.items()):
        if has_limits(contracts[c["contract"]]):
            continue
        assert canonical(run(k)) == canonical(v111.settle_fixture_case(v111.settle_v1_11, k, fx)), k
        same += 1
    corpus = sorted(k for k in cases if k.startswith("corpus/"))
    assert len(corpus) == 18 and all(hashlib.sha256(canonical(run(k)).encode("utf-8")).hexdigest() == cases[k]["expect"]["settlement_sha256"] for k in corpus)
    rr = os.path.join(HERE, "run0002")
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    C2 = rd(os.path.join(HERE, "second_contract_AB.json"))
    args = (C2, [rd(os.path.join(rr, "exec_19c44a79.anchored.json"))], rd(os.path.join(rr, "view.json")))
    nr = [rd(os.path.join(rr, "walk_8bf29f1a.json"))]
    assert canonical(settle_v1_12(*args, nenrin_records=nr)) == canonical(v110.settle_v1_10(*args, nenrin_records=nr))
    assert run("v12/no_limits_is_v1_11")["schema"] == v111.SETTLE_SCHEMA
    n += 1; print("[1] contracts with no grant.limits: v1.12 is v1.11 byte for byte (%d fixture scenarios, the 18 of the corpus among them, and run0002 under the second contract)" % same)

    # [2] within the limit, admitted and executed: within_grant
    s = run("v12/pay_80000")
    assert decided("v12/pay_80000")[0] == "admit" and s["schema"] == SETTLE_SCHEMA and s["settled_under"] == v111.SETTLE_SCHEMA and s["verdict"] == "within_grant" and s["status"] == "final", s["deviations"]
    assert s["limit_gate"]["amounts_read"] == [{"action": "pay", "amount": 80000, "max_amount": 100000, "unit": "JPY", "over": False, "record_sha256": s["limit_gate"]["amounts_read"][0]["record_sha256"]}]
    assert run("v12/pay_100000")["verdict"] == "within_grant"
    assert run("v12/read")["verdict"] == "within_grant" and run("v12/read")["limit_gate"]["amounts_read"] == []
    assert decided("v12/pay_large_150000_approved")[0] == "admit" and run("v12/pay_large_150000_approved")["verdict"] == "within_grant"
    assert decided("v12/pay_large_150000_no_approval")[0] == "escalate" and clauses(run("v12/pay_large_150000_no_approval")) == ["conditional", "executed_after_refusal"]
    n += 1; print("[2] pay 80,000 and 100,000 under a 100,000 limit, admitted and executed: within_grant, final; pay_large 150,000 with the approver's signature: within_grant; an action with no limit is not read")

    # [3] over the limit: refused, executed anyway
    s = run("v12/pay_150000_refused")
    assert decided("v12/pay_150000_refused") == ("refuse", ["amount_over_limit"]) and clauses(s) == ["amount_over_limit", "executed_after_refusal"], clauses(s)
    assert "150000" in next(d["why"] for d in s["deviations"] if d["clause"] == "amount_over_limit") and s["limit_gate"]["counts"] == {"amount_over_limit": 1, "admitted_out_of_grant": 0}
    n += 1; print("[3] pay 150,000: the relying party's door refused with amount_over_limit; executed anyway: executed_after_refusal and amount_over_limit")

    # [4] over the limit, and the relying party admitted it
    s = run("v12/pay_150000_admitted_by_mistake")
    assert clauses(s) == ["admitted_out_of_grant", "amount_over_limit"], clauses(s)
    why = next(d["why"] for d in s["deviations"] if d["clause"] == "admitted_out_of_grant")
    assert "shop.example" in why and "over_limit" in why and s["limit_gate"]["counts"] == {"amount_over_limit": 1, "admitted_out_of_grant": 1}
    assert clauses(run("v12/pay_large_2000000_approved_admitted_by_mistake")) == ["admitted_out_of_grant", "amount_over_limit"]
    s = run("v12/pay_large_2000000_no_approval_admitted_by_mistake")
    assert clauses(s).count("admitted_out_of_grant") == 1 and "amount_over_limit" in clauses(s) and "conditional" in clauses(s), clauses(s)
    n += 1; print("[4] the relying party signs admit for 150,000: admitted_out_of_grant, naming the domain that signed, and amount_over_limit; an approval does not lift the cap on pay_large; one admission is named once")

    # [5] the amount cannot be made smaller on the way to the record
    assert decided("v12/pay_admitted_80000_recorded_150000")[0] == "admit"
    assert clauses(run("v12/pay_admitted_80000_recorded_150000")) == ["admitted_out_of_grant", "amount_over_limit", "executed_other_than_admitted"]
    assert decided("v12/pay_refused_150000_recorded_80000")[0] == "refuse"
    assert clauses(run("v12/pay_refused_150000_recorded_80000")) == ["executed_after_refusal", "executed_other_than_admitted"]
    assert clauses(run("v12/pay_80000_recorded_without_amount")) == ["admitted_out_of_grant", "amount_over_limit", "executed_other_than_admitted"]
    assert clauses(run("v12/pay_80000_no_admission_ref")) == ["amount_over_limit", "unadmitted_execution"]
    n += 1; print("[5] admitted for 80,000 and recorded as 150,000, or refused for 150,000 and recorded as 80,000: executed_other_than_admitted; an execution that states no amount, or names no admission: amount_over_limit")

    # [6] determinism
    assert canonical(run("v12/pay_150000_refused")) == canonical(run("v12/pay_150000_refused"))
    n += 1; print("[6] the same inputs give the same settlement bytes")

    # [7] mutants: each must change a verdict the tests above expect
    g, killed = globals(), 0
    saved = g["limit_deviations"]
    try:
        g["limit_deviations"] = lambda *a, **k: ([], [])                                      # M1: the rule is skipped
        killed += clauses(run("v12/pay_150000_admitted_by_mistake")) == []
    finally:
        g["limit_deviations"] = saved
    real = ce.over_limit
    try:
        ce.over_limit = lambda *a, **k: False                                                 # M2: an evaluator that does not look at limits
        killed += "amount_over_limit" not in clauses(run("v12/pay_150000_refused"))
    finally:
        ce.over_limit = real
    real_lim = ce.limit_for
    try:
        ce.limit_for = lambda *a, **k: None                                                   # M3: limits are not found in the grant
        killed += clauses(run("v12/pay_150000_admitted_by_mistake")) == []
    finally:
        ce.limit_for = real_lim
    assert killed == 3, killed
    n += 1; print("[7] 3 mutants (rule skipped, an evaluator that ignores limits, limits not found): all 3 change a verdict the checks above expect")

    r = subprocess.run([sys.executable, os.path.join(HERE, "settle_v1_11.py"), "--selftest"], capture_output=True, text=True)
    assert r.returncode == 0 and "SELF-TEST PASSED" in r.stdout, (r.stdout[-300:], r.stderr[-300:])
    n += 1; print("[8] settle_v1_11 self test (and every layer it runs) still passes")

    print("\nSELF-TEST PASSED: MUSUBI settle v1.12, %d checks (fixture bytes; no limits: v1.11 byte for byte; within the limit: within_grant; over and refused; "
          "over and admitted: admitted_out_of_grant; the amount is bound by the admission digest; determinism; 3 mutants; v1.11 unchanged)" % n)


def main():
    ap = argparse.ArgumentParser(description="MUSUBI settle v1.12 (executed amounts read against grant.limits)")
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
    s = settle_v1_12(contract, [rd(p) for p in a.event], views[cmp["chosen"]], admissions=[rd(p) for p in a.admission], relying_keys=keys,
                     nenrin_records=[rd(p) for p in a.nenrin] or None)
    if a.out:
        open(a.out, "w", encoding="utf-8", newline="").write(canonical(s))
    print(json.dumps(s, ensure_ascii=False, indent=2))
    return 0 if s["status"] == "final" else 2


if __name__ == "__main__":
    sys.exit(main())
