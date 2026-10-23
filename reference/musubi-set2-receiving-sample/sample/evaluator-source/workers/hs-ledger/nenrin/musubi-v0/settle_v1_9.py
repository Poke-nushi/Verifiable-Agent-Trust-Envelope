#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI settle v1.9: a contract can also make "final" depend on measurers nobody chose (a2a-settlement-v1.9).

settle v1.8 refuses "final" until the spine is intact: terms verified, independent legal entities, the work
corroborated. corroboration counts entities, but the contractor can bring the entities. convergence v0 removes
that choice: the measurers are drawn from a pool both parties pinned, by a Bitcoin block that did not exist when
they signed, they measure after the draw, and the agreeing measurements must come from more than one method.

What v1.9 changes, and nothing else:

  requirements.convergence   when present, the contract must also carry the v1.8 spine gate, or v1.9 refuses to
                             settle it (underspecified, convergence_without_spine_gate): a contract that asks for
                             drawn measurers but not for the spine would let "final" rest on the grant check alone.
                             A malformed convergence block is underspecified (convergence_requirement_incomplete).
  the gate                   convergence_v0 runs on the spine's terms, vocabulary, declarations and measurements
                             plus the pinned pool. Unless its verdict is "converged", a settlement v1.8 would call
                             final is spine_unmet, the bond pending_spine, and spine_gate.failed gains
                             "not_converged:<verdict>". A contradicted verdict that names a party's claim is kept
                             in the gate report: the contractor said done, the drawn measurers said not.
  no convergence block       v1.9 renders v1.8's settlement apart from schema, settled_under, establishes and
                             convergence_gate (checked on synthetic runs and on run0002).

Stated limits: as v1.8 and convergence v0. A settler older than v1.9 ignores requirements.convergence. Drawn
measurers can still collude after the draw; the draw stops the parties choosing them, the method rule makes a lie
pass several directions, and the counts say how many independent entities would have to lie together.
"""
import argparse, hashlib, json, os, random, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import settle_v1_8 as v18
import convergence_v0 as cvg
import settle_v1_5 as v15
from contract_v0 import canonical, parse_strict, contract_sha256

SETTLE_SCHEMA = "a2a-settlement-v1.9"
SAME_EXCEPT = ("schema", "settled_under", "establishes", "convergence_gate")


def settle_v1_9(contract, events, view, mode="strict", nenrin_records=None, spine=None, pool=None, contract_anchor_height=None, history=None):
    s = v18.settle_v1_8(contract, events, view, mode=mode, nenrin_records=nenrin_records, spine=spine)
    out = dict(s)
    out["schema"], out["settled_under"] = SETTLE_SCHEMA, v18.SETTLE_SCHEMA
    req, probs = cvg.read_requirement(contract)
    reqs = contract.get("requirements") if isinstance(contract.get("requirements"), dict) else {}
    if req is None and not probs:
        out["convergence_gate"] = {"required": False}
        out["establishes"] = list(s["establishes"]) + ["that the contract states no requirements.convergence, so the measurers were not drawn (settle v1.8)"]
        return out
    under = []
    if probs:
        under += [{"reason": "convergence_requirement_incomplete", "detail": p} for p in probs]
    gate_req, _gp = v18.read_gate(contract)
    if not gate_req:
        under.append({"reason": "convergence_without_spine_gate", "detail": "requirements.convergence needs requirements.spine.gate, or final rests on the grant check alone"})
    if under:
        out["underspecified"] = sorted(list(s["underspecified"]) + under, key=canonical)
        out["verdict"], out["status"], out["deviations"] = "underspecified", "undetermined", []
        out["bond_outcome"] = v15._bond_outcome(contract, "underspecified", "undetermined")
        out["convergence_gate"] = {"required": True, "met": False, "verdict": None}
        out["establishes"] = list(s["establishes"])[:1] + ["that the contract asks for drawn measurers in a way this settler cannot apply, so no verdict is rendered"]
        return out
    sp = spine or {}
    co = cvg.verify_convergence(contract, sp.get("terms"), list(sp.get("measurements") or []), view, pool,
                                list(sp.get("declarations") or []), sp.get("vocabulary_bytes"), history=history, contract_anchor_height=contract_anchor_height)
    met = co["verdict"] == "converged"
    out["convergence_gate"] = {"required": True, "met": met, "verdict": co["verdict"], "draw": co["draw"],
                               "items": [{k: it[k] for k in ("item_id", "status", "drawn_agreeing_entities", "drawn_disagreeing_entities",
                                                             "agreeing_methods", "findings")} for it in co["items"]],
                               "refusals": co["refusals"], "findings": co["findings"],
                               "convergence_report_sha256": hashlib.sha256(canonical(co).encode("utf-8")).hexdigest()}
    est = list(s["establishes"])
    if not met:
        g = dict(out.get("spine_gate") or {})
        g["failed"] = list(g.get("failed") or []) + ["not_converged:%s" % co["verdict"]]
        g["met"] = False
        out["spine_gate"] = g
        if s["verdict"] != "underspecified":
            if s["status"] in ("final", "spine_unmet"):
                out["status"] = "spine_unmet"
            if v15._bond_outcome(contract, s["verdict"], "final") != "n/a":
                out["bond_outcome"] = "pending_spine"
        est.append("that the measurers drawn for this contract did not converge (%s), so this settlement is not final" % co["verdict"])
    else:
        est.append("that the measurers drawn by the pinned pool and beacon, measuring after the draw from at least the stated number of methods, converged within tolerance")
    out["establishes"] = est
    out["does_not_establish"] = list(s["does_not_establish"]) + [
        "that a settler older than v1.9 enforces requirements.convergence",
        "that the drawn measurers did not collude after being drawn"]
    return out


# --------------------------------------------------------------------------- self test
def _strip(s, names):
    return {k: v for k, v in s.items() if k not in names}


def _selftest():
    import contract_v0 as v0
    n = 0
    W = cvg.fixture()
    T, VB, P = W["terms"], W["vb"], W["pool"]
    honest = lambda dr, rest: [(dr[0][0], dr[0][1], 120, "on_site_tape_measure_v0", 99), (dr[1][0], dr[1][1], 118, "on_site_tape_measure_v0", 99),
                               (dr[2][0], dr[2][1], 121, "drawing_takeoff_v0", 99)]
    liar = lambda dr, rest: [(dr[0][0], dr[0][1], 80, "on_site_tape_measure_v0", 99), (dr[1][0], dr[1][1], 81, "on_site_tape_measure_v0", 99),
                             (dr[2][0], dr[2][1], 79, "drawing_takeoff_v0", 99)]
    friends = lambda dr, rest: [(k, p, 120, m, 99) for (k, p), m in zip(rest, ["on_site_tape_measure_v0", "drawing_takeoff_v0", "on_site_tape_measure_v0"])]
    c = cvg.make_contract(W)

    def run(plan, claim=None, cah=98, contract=c):
        view, d, exe, walk, ms = cvg.world(W, contract, plan, contractor_claim=claim)
        sp = {"terms": T, "vocabulary_bytes": VB, "declarations": W["decls"], "measurements": ms}
        return settle_v1_9(contract, [exe], view, nenrin_records=[walk], spine=sp, pool=P, contract_anchor_height=cah), view, exe, walk, sp

    # [1] drawn, after the draw, two directions, spine intact: final
    s, view, exe, walk, sp = run(honest)
    assert s["verdict"] == "within_grant" and s["status"] == "final" and s["bond_outcome"] == "held", (s["status"], s["spine_gate"], s["convergence_gate"])
    assert s["convergence_gate"]["met"] is True and s["spine_gate"]["met"] is True
    n += 1; print("[1] spine intact and three drawn measurers converge from two methods: within_grant / final / held")

    # [2] v1.8 alone is fooled by friends; v1.9 is not
    s, view, exe, walk, sp = run(friends, claim=120)
    s8 = v18.settle_v1_8(c, [exe], view, nenrin_records=[walk], spine=sp)
    assert s8["status"] == "final" and s8["spine_gate"]["met"] is True, (s8["status"], s8["spine_gate"])
    assert s["status"] == "spine_unmet" and s["bond_outcome"] == "pending_spine" and "not_converged:not_converged" in s["spine_gate"]["failed"]
    n += 1; print("[2] three friendly inspectors the parties brought, each its own company: v1.8 says final (corroborated), v1.9 says spine_unmet, not_converged")

    # [3] the lie: contractor claims 120, the drawn measurers find 80
    s, *_ = run(liar, claim=120)
    assert s["status"] == "spine_unmet" and s["convergence_gate"]["verdict"] == "contradicted"
    assert s["convergence_gate"]["items"][0]["findings"][0]["code"] == "party_claim_contradicted"
    n += 1; print("[3] contractor signs 120, drawn measurers find 80: spine_unmet, contradicted, the contractor's claim named")

    # [4] contract anchored at the beacon (parties could see the draw): not final
    s, *_ = run(honest, cah=99)
    assert s["status"] == "spine_unmet" and s["convergence_gate"]["verdict"] == "refused"
    n += 1; print("[4] contract anchored at the beacon block: convergence refused, spine_unmet")

    # [5] asking for drawn measurers without the spine gate, or with a malformed block: refused to settle
    cn = cvg.make_contract(W, spine=False, nonce="f")
    s5, *_ = run(honest, contract=cn)
    assert s5["verdict"] == "underspecified" and any(u["reason"] == "convergence_without_spine_gate" for u in s5["underspecified"])
    bad = dict(c["requirements"]["convergence"], draw_k=1)
    cb = cvg.make_contract(W, convergence=bad, nonce="e")
    s5, *_ = run(friends, contract=cb)
    assert s5["verdict"] == "underspecified" and any(u["reason"] == "convergence_requirement_incomplete" for u in s5["underspecified"])
    n += 1; print("[5] convergence without the spine gate, and draw_k 1: underspecified")

    # [6] no convergence block: v1.9 == v1.8 on every field but the named ones (synthetic and run0002)
    c0 = cvg.make_contract(W, convergence=False, nonce="d")
    view0, _, exe0, walk0, ms0 = cvg.world(W, c0, lambda dr, rest: [(k, p, 120, "on_site_tape_measure_v0", 99) for k, p in rest[:2]])
    sp0 = {"terms": T, "vocabulary_bytes": VB, "declarations": W["decls"], "measurements": ms0}
    a = settle_v1_9(c0, [exe0], view0, nenrin_records=[walk0], spine=sp0)
    b = v18.settle_v1_8(c0, [exe0], view0, nenrin_records=[walk0], spine=sp0)
    assert canonical(_strip(a, SAME_EXCEPT)) == canonical(_strip(b, SAME_EXCEPT)) and a["convergence_gate"] == {"required": False}
    rr = os.path.join(HERE, "run0002")
    if os.path.exists(os.path.join(rr, "settlement_walk2.json")):
        rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
        C2 = rd(os.path.join(HERE, "second_contract_AB.json"))
        s9 = settle_v1_9(C2, [rd(os.path.join(rr, "exec_19c44a79.anchored.json"))], rd(os.path.join(rr, "view.json")),
                         nenrin_records=[rd(os.path.join(rr, "walk_8bf29f1a.json"))])
        s6 = rd(os.path.join(rr, "settlement_walk2.json"))
        names = SAME_EXCEPT + v18.SAME_EXCEPT + v18.v17.SAME_EXCEPT
        assert s9["status"] == "final" and canonical(_strip(s9, names)) == canonical(_strip(s6, names))
        n += 1; print("[6] no convergence block: v1.9 == v1.8 on every field except the named ones; run0002 == the published settlement")
    else:
        n += 1; print("[6] no convergence block: v1.9 == v1.8 (run0002 not beside this file)")

    # [7] determinism
    s, view, exe, walk, sp = run(honest)
    ref = canonical(settle_v1_9(c, [exe], view, nenrin_records=[walk], spine=sp, pool=P, contract_anchor_height=98))
    rng = random.Random(9)
    for _ in range(5):
        mm = list(sp["measurements"]) + [sp["measurements"][0]]; rng.shuffle(mm)
        assert canonical(settle_v1_9(c, [exe], view, nenrin_records=[walk], spine=dict(sp, measurements=mm), pool=P, contract_anchor_height=98)) == ref
    n += 1; print("[7] 5 shuffles with a duplicate: identical settlement bytes")

    # [8] the layers below still pass
    for f in ("settle_v1_8.py", "convergence_v0.py"):
        r = subprocess.run([sys.executable, os.path.join(HERE, f), "--selftest"], capture_output=True, text=True)
        assert r.returncode == 0 and "SELF-TEST PASSED" in r.stdout, (f, r.stdout[-300:], r.stderr[-300:])
    n += 1; print("[8] settle_v1_8 and convergence_v0 self tests still pass")

    print("\nSELF-TEST PASSED: MUSUBI settle v1.9, %d checks (drawn measurers converge: final; friends fool v1.8 not v1.9; the lie contradicted; "
          "beacon seen at signing refused; convergence without the spine gate refused; no block: v1.8 unchanged; determinism)" % n)


def main():
    ap = argparse.ArgumentParser(description="MUSUBI settle v1.9 (final also needs measurers nobody chose)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--settle", metavar="CONTRACT.json")
    ap.add_argument("--event", action="append", default=[])
    ap.add_argument("--view", action="append", default=[])
    ap.add_argument("--nenrin", action="append", default=[])
    ap.add_argument("--terms"); ap.add_argument("--vocabulary")
    ap.add_argument("--declaration", action="append", default=[])
    ap.add_argument("--measurement", action="append", default=[])
    ap.add_argument("--pool", metavar="POOL.json")
    ap.add_argument("--contract-anchor-height", type=int)
    ap.add_argument("--history", action="append", default=None, metavar="PRIOR_RECORD.json")
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return 0
    if not a.settle or not a.view:
        ap.print_help(); return 1
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    contract = rd(a.settle)
    views = [rd(p) for p in a.view]
    cmp = v18.v17.v14.compare_views_v1_4(views, contract)
    if cmp["chosen"] is None:
        print(json.dumps({"fork_choice": cmp}, indent=2)); return 2
    spine = {"terms": rd(a.terms) if a.terms else None, "vocabulary_bytes": open(a.vocabulary, "rb").read() if a.vocabulary else None,
             "declarations": [rd(p) for p in a.declaration], "measurements": [rd(p) for p in a.measurement]}
    s = settle_v1_9(contract, [rd(p) for p in a.event], views[cmp["chosen"]], nenrin_records=[rd(p) for p in a.nenrin] or None,
                    spine=spine, pool=rd(a.pool) if a.pool else None, contract_anchor_height=a.contract_anchor_height,
                    history=[rd(p) for p in a.history] if a.history is not None else None)
    if a.out:
        open(a.out, "w", encoding="utf-8", newline="").write(canonical(s))
    print(json.dumps(s, ensure_ascii=False, indent=2))
    return 0 if s["status"] == "final" else 2


if __name__ == "__main__":
    sys.exit(main())
