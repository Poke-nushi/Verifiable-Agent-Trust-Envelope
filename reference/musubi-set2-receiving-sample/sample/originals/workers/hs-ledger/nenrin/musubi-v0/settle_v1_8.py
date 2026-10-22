#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI settle v1.8: a contract can make "final" depend on the whole spine (a2a-settlement-v1.8).

Why this file exists. settle v1.7 answers one question: do the contractor's anchored, signed records stay
inside the grant. It never looks at the three stages spine_verify added on 2026-09-26 (terms, independence,
corroboration). So a contract whose deliverable means nothing in particular, whose three actors are one owner
behind three keys, and whose work nobody measured, settles "within_grant / final" exactly like one where all
of that was checked. spine_verify reports those gaps (holes, unexercised), but a report nobody is bound by is
advice. An outside red team read the layers as decorative for that reason, and it was right about the effect.

What v1.8 changes, and nothing else:

  requirements.spine        a contract may carry {"gate": "final_requires_intact_spine"}. Without it, v1.8
                            renders v1.7's settlement, apart from the fields named in SAME_EXCEPT; the self
                            test checks that on synthetic runs and on run0002.
  the gate's terms          a contract that opts in must also make every spine stage mandatory, or v1.8
                            refuses to settle it (underspecified, spine_requirement_incomplete):
                              task.terms_sha256 pinned (terms v0),
                              requirements.independence with min_distinct_legal_entities >= 2,
                                witnesses_independent_of_parties true and declarations_required true,
                              requirements.corroboration with min_corroborating_entities >= 1 and
                                measurers_independent_of_parties true.
                            A gate that a contract can satisfy by stating a quorum of one is not a gate.
  the gate                  spine_verify runs on the same records plus the spine inputs (terms and their
                            vocabulary, actor declarations, measurements, tasks). The gate is met only if the
                            spine is intact (no holes), nothing is unexercised, terms are accepted, the
                            independence quorum is met and the work is corroborated. If it is not met, a
                            settlement that v1.7 would call final is status "spine_unmet" and the bond is
                            "pending_spine": the verdict and the deviations are still reported, because a
                            deviation is the contractor's own signed act and does not need anyone's
                            measurement to be a deviation. A provisional settlement stays provisional.

The verdict function is unchanged. v1.8 does not decide whether the work was good; it refuses to call a
settlement final when the contract itself said finality needs more than the grant check, and that "more"
is missing or broken. Every failure is named in spine_gate.failed and every input is recomputable.

Stated limits. A verifier older than v1.8 does not read requirements.spine, so a party that relies on the gate
must settle under v1.8 or later; the contract can say so in its task text, but no byte can stop someone running
an older settler and quoting it. The spine's own limits carry over: a declaration is the declarant's claim
about itself, checked against a public register only by the reader; a measurement is a signed claim by a
declared entity; independence counts distinct declared legal entities, not who really controls them.
"""
import argparse, base64, hashlib, json, os, random, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import contract_v0 as v0
import settle_v1 as v1
import settle_v1_1 as v11
import settle_v1_2 as v12
import settle_v1_5 as v15
import settle_v1_7 as v17
import spine_verify as sv
import terms_v0 as tv0
import independence_v0 as ind
import corroboration_v0 as cor
from contract_v0 import canonical, parse_strict, contract_sha256, EXEC_SCHEMA

SETTLE_SCHEMA = "a2a-settlement-v1.8"
GATE_VALUE = "final_requires_intact_spine"
GATE_KEYS = frozenset(("gate",))
GATE_RULE = ("when requirements.spine.gate is final_requires_intact_spine, a settlement is final only if spine_verify on the same "
             "records and the supplied terms, declarations and measurements reports spine intact, nothing unexercised, terms accepted, "
             "independence met and corroboration corroborated; otherwise a would-be final settlement is spine_unmet and the bond pending_spine")
SAME_EXCEPT = ("schema", "settled_under", "establishes", "spine_gate")


def _get(d, *path):
    cur = d
    for k in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _posint(x):
    return isinstance(x, int) and not isinstance(x, bool) and x >= 1


def read_gate(contract):
    """(required, problems). required is False when the contract carries no requirements.spine. problems lists
    why an opted-in contract cannot be settled under its own gate (underspecified entries)."""
    reqs = contract.get("requirements") if isinstance(contract.get("requirements"), dict) else {}
    if "spine" not in reqs:
        return False, []
    sp = reqs.get("spine")
    probs = []
    if not isinstance(sp, dict):
        return True, [{"reason": "spine_requirement_incomplete", "detail": "requirements.spine must be an object"}]
    extra = sorted(k for k in sp if k not in GATE_KEYS)
    if extra:
        probs.append({"reason": "spine_requirement_incomplete", "detail": "requirements.spine carries keys no verifier reads: %s" % ", ".join(extra)})
    if sp.get("gate") != GATE_VALUE:
        probs.append({"reason": "spine_requirement_incomplete", "detail": "requirements.spine.gate must be %s" % GATE_VALUE})
    pin = _get(contract, "task", "terms_sha256")
    if not (isinstance(pin, str) and v11.HEX64.match(pin)):
        probs.append({"reason": "spine_requirement_incomplete", "detail": "task.terms_sha256 is not pinned, so what the agreed bytes mean is not part of the terms"})
    ir = reqs.get("independence")
    if not isinstance(ir, dict):
        probs.append({"reason": "spine_requirement_incomplete", "detail": "requirements.independence is missing"})
    else:
        if not (_posint(ir.get("min_distinct_legal_entities")) and ir["min_distinct_legal_entities"] >= 2):
            probs.append({"reason": "spine_requirement_incomplete", "detail": "requirements.independence.min_distinct_legal_entities must be 2 or more"})
        for k in ("witnesses_independent_of_parties", "declarations_required"):
            if ir.get(k) is not True:
                probs.append({"reason": "spine_requirement_incomplete", "detail": "requirements.independence.%s must be true" % k})
    cr = reqs.get("corroboration")
    if not isinstance(cr, dict):
        probs.append({"reason": "spine_requirement_incomplete", "detail": "requirements.corroboration is missing"})
    else:
        if not _posint(cr.get("min_corroborating_entities")):
            probs.append({"reason": "spine_requirement_incomplete", "detail": "requirements.corroboration.min_corroborating_entities must be a positive integer"})
        if cr.get("measurers_independent_of_parties") is not True:
            probs.append({"reason": "spine_requirement_incomplete", "detail": "requirements.corroboration.measurers_independent_of_parties must be true"})
    return True, sorted(probs, key=canonical)


def gate_failures(sp):
    """The reasons a spine report does not meet the gate, in a fixed order."""
    f = []
    if sp["spine"] != "intact":
        f.append("spine_broken")
    for k in sp["unexercised"]:
        f.append("unexercised_" + k)
    if sp["terms_verdict"] != "accepted":
        f.append("terms_not_accepted")
    if sp["independence_verdict"] != "met":
        f.append("independence_not_met")
    if sp["corroboration_verdict"] != "corroborated":
        f.append("not_corroborated")
    return f


def settle_v1_8(contract, events, view, mode="strict", nenrin_records=None, spine=None):
    """spine: optional dict with tasks, terms, vocabulary_bytes, declarations, measurements (spine_verify's inputs)."""
    s = v17.settle_v1_7(contract, events, view, mode=mode, nenrin_records=nenrin_records)
    out = dict(s)
    out["schema"] = SETTLE_SCHEMA
    out["settled_under"] = v17.SETTLE_SCHEMA
    required, probs = read_gate(contract)
    est = list(s["establishes"])
    dne = list(s["does_not_establish"])
    if not required:
        out["spine_gate"] = {"required": False}
        out["establishes"] = est + ["that the contract carries no requirements.spine, so finality here is the grant check alone (settle v1.7)"]
        return out
    if probs:
        out["underspecified"] = sorted(list(s["underspecified"]) + probs, key=canonical)
        out["verdict"], out["status"], out["deviations"] = "underspecified", "undetermined", []
        out["bond_outcome"] = v15._bond_outcome(contract, "underspecified", "undetermined")
        out["spine_gate"] = {"required": True, "rule": GATE_RULE, "met": False, "failed": ["spine_requirement_incomplete"]}
        out["establishes"] = est[:1] + ["that the contract opts into the spine gate but does not make every spine stage mandatory, so no verdict is rendered under it"]
        return out
    sp_in = spine or {}
    sp = sv.spine_verify(contract, executions=list(events or []), view=view, nenrin_records=list(nenrin_records or []),
                         tasks=list(sp_in.get("tasks") or []), terms=sp_in.get("terms"),
                         vocabulary_bytes=sp_in.get("vocabulary_bytes"), declarations=list(sp_in.get("declarations") or []),
                         measurements=list(sp_in.get("measurements") or []), mode=mode)
    failed = gate_failures(sp)
    met = not failed
    gate = {"required": True, "rule": GATE_RULE, "met": met, "failed": failed,
            "spine": sp["spine"], "holes": sp["holes"], "unexercised": sp["unexercised"],
            "terms_verdict": sp["terms_verdict"], "independence_verdict": sp["independence_verdict"],
            "corroboration_verdict": sp["corroboration_verdict"],
            "spine_schema": sp["schema"], "spine_report_sha256": hashlib.sha256(canonical(sp).encode("utf-8")).hexdigest()}
    out["spine_gate"] = gate
    if not met and s["verdict"] != "underspecified":
        if s["status"] == "final":
            out["status"] = "spine_unmet"
        if v15._bond_outcome(contract, s["verdict"], s["status"]) != "n/a":
            out["bond_outcome"] = "pending_spine"
    if met:
        est.append("that the spine gate the contract states is met: the pinned terms verify, at least the stated number of distinct declared "
                   "legal entities stand behind the actors with witnesses outside the parties, and independent declared entities measured "
                   "the work within tolerance inside the block window")
    else:
        est.append("that the spine gate the contract states is not met (%s), so this settlement is not final whatever the grant check says" % ", ".join(failed))
    dne.append("that a verifier older than settle v1.8 enforces requirements.spine; v1.7 and below ignore it")
    dne.append("that a declared legal entity is who it says, or that two declared entities are not one owner; the reader checks the register")
    dne.append("that a corroborated item is true in the world; only that the counted entities signed measurements within tolerance in the window")
    out["establishes"] = est
    out["does_not_establish"] = dne
    return out


# --------------------------------------------------------------------------- self test
def _strip(s):
    return {k: v for k, v in s.items() if k not in SAME_EXCEPT}


def _selftest():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    def newkey():
        k = Ed25519PrivateKey.generate()
        return k, base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw,
                                                               serialization.PublicFormat.Raw)).decode()
    n = 0
    ka, pa = newkey(); kb, pb = newkey(); kw, pw = newkey(); k1, p1 = newkey(); k2, p2 = newkey()
    PDG = "a" * 64
    base = v11._Chain(60, "00" * 32, "v18-%d" % random.randint(0, 1 << 30))
    for _ in range(38):
        base.block()                                                       # 60..97
    lb = {"kind": "bitcoin_block", "height": 97, "hash": base.hashes[97]}
    DNE = ["that HS enforced any of this at runtime",
           "that the contractor obeyed the grant, only that its recorded acts match or deviate from it",
           "that HS judges liability or fault; the verdict is a function anyone recomputes",
           "that a prohibited action was impossible, only that performing one is a provable deviation",
           "that this is a legal contract or determines legal responsibility"]
    P = {"registry": "JP", "scheme": "houjin-bango", "id": "1111111111111", "name": "Principal K.K."}
    C_ = {"registry": "GLEIF", "scheme": "lei", "id": "5493001KJTIIGC8Y1R12", "name": "Contractor LLC"}
    W = {"registry": "JP", "scheme": "houjin-bango", "id": "5555555555555", "name": "Walker K.K."}
    I1 = {"registry": "JP", "scheme": "houjin-bango", "id": "1234567890123", "name": "Inspector One K.K."}
    I2 = {"registry": "JP", "scheme": "houjin-bango", "id": "9876543210987", "name": "Inspector Two K.K."}
    vocab = tv0.make_vocabulary("conduct-walk-glossary", "2026.10", {"endpoint_walked": {"unit": "endpoint", "methods": ["a2a_walk"]}})
    vb = tv0.vocabulary_bytes(vocab)
    vref = {"name": "conduct-walk-glossary", "version": "2026.10", "sha256": tv0.vocabulary_sha256(vb), "url": "https://example.test/g.json"}
    TERMS = tv0.build_terms(vref, [{"item_id": "endpoint_walked", "quantity": 1, "unit": "endpoint", "tolerance_bp": 0,
                                    "completion_test": {"method": "a2a_walk", "evidence_schema": "a2a-measurement-v0"}}])
    FULL = {"evidence": "nenrin_required", "recovery": "tsugi_required",
            "independence": {"min_distinct_legal_entities": 3, "witnesses_independent_of_parties": True, "declarations_required": True},
            "corroboration": {"min_corroborating_entities": 2, "measurers_independent_of_parties": True},
            "spine": {"gate": GATE_VALUE}}

    def mk(requirements=None, terms=TERMS, nonce="c"):
        g = {"authorized_actions": ["read", "write"], "prohibited_actions": ["delete"], "conditional": [],
             "delegation": {"allowed": []}, "revocation": {"effective_at": "anchor"},
             "finality": {"depth": 3, "max_target_bits": "207fffff"},
             "witnesses": [{"name": "nenrin-walker", "public_key_ed25519_b64": pw}]}
        task = {"purpose": "endpoint_conduct_walk", "payload_digest": PDG, "a2a_task_id": "t1"}
        if terms is not None:
            tv0.bind_terms(task, terms)
        c = v0.build_contract(
            {"domain": "principal.example", "key_url": "https://principal.example/keys/agreement.json", "public_key_ed25519_b64": pa},
            {"domain": "contractor.example", "key_url": "https://contractor.example/keys/agreement.json", "public_key_ed25519_b64": pb},
            task, g, ["that both parties signed these grant bytes at the stated time"], DNE,
            bond={"amount": 1000, "currency": "JPY", "holder": "principal"}, lower_bound=lb, requirements=requirements,
            contract_id="0123456789abcdef0123456789abcdef", nonce=nonce * 32, agreed_at="2026-10-02T00:00:00Z")
        v0.sign_contract(c, ka, pa, "principal.example")
        v0.sign_contract(c, kb, pb, "contractor.example")
        return c

    def decl(key, pub, domain, le):
        return ind.sign_declaration(ind.build_declaration(pub, domain, "https://%s/keys/agreement.json" % domain, le), key)
    DECLS = [decl(ka, pa, "principal.example", P), decl(kb, pb, "contractor.example", C_), decl(kw, pw, "walker.example", W),
             decl(k1, p1, "inspector-one.example", I1), decl(k2, p2, "inspector-two.example", I2)]

    def thread(contract, measurers, actions=("read",), measured=1):
        """Beacon at 98, the execution and the measurements at 99, five more blocks: depth 3 makes 99 final."""
        ch = base.fork(98, "m%d" % random.randint(0, 1 << 40))
        ch.block()
        b = {"kind": "bitcoin_block", "height": 98, "hash": ch.hashes[98]}
        cs = contract_sha256(contract)
        walk = {"schema": "jidec-path-v1", "context": {"contract_sha256": cs}, "subject": "contractor.example/a2a",
                "result": "pass", "nonce": "1234567890abcdef1234567890abcdef"}
        exe = v12.sign_record({"schema": EXEC_SCHEMA,
                               "contract_ref": {"contract_id": contract["contract_id"], "payload_digest": PDG, "contract_sha256": cs},
                               "performed_actions": list(actions), "approvals": [], "delegated_to": [],
                               "nenrin_ref": v1.rec_sha(walk)}, kb, "contractor")
        ms = [cor.sign_measurement(cor.build_measurement(contract, TERMS, "endpoint_walked", measured, "a2a_walk", pub, b), key)
              for key, pub in measurers]
        recs = ch.block([exe] + ms)
        for _ in range(5):
            ch.block()
        return ch.view(), walk, recs[0], recs[1:]

    INSPECTORS = [(k1, p1), (k2, p2)]

    # [1] no gate: v1.8 renders v1.7's settlement on every field but the named ones
    c0 = mk(requirements={"evidence": "nenrin_required", "recovery": "tsugi_required"}, terms=None, nonce="d")
    view0, walk0, exe0, _ = thread(c0, [])
    s7 = v17.settle_v1_7(c0, [exe0], view0, nenrin_records=[walk0])
    s8 = settle_v1_8(c0, [exe0], view0, nenrin_records=[walk0])
    assert s7["verdict"] == "within_grant" and s7["status"] == "final"
    assert canonical(_strip(s8)) == canonical(_strip(s7)) and s8["spine_gate"] == {"required": False}
    assert s8["schema"] == SETTLE_SCHEMA and s8["settled_under"] == v17.SETTLE_SCHEMA
    n += 1; print("[1] a contract without requirements.spine: v1.8 == v1.7 on every field except schema, settled_under, establishes, spine_gate")

    # [2] the gated contract with everything supplied and satisfied: final, bond held
    cG = mk(requirements=FULL)
    assert v0.verify_contract(cG)["verdict"] == "accepted", v0.verify_contract(cG)
    viewG, walkG, exeG, msG = thread(cG, INSPECTORS)
    SP = {"terms": TERMS, "vocabulary_bytes": vb, "declarations": DECLS, "measurements": msG}
    s8 = settle_v1_8(cG, [exeG], viewG, nenrin_records=[walkG], spine=SP)
    assert s8["verdict"] == "within_grant" and s8["status"] == "final" and s8["bond_outcome"] == "held", (s8["status"], s8["spine_gate"])
    g = s8["spine_gate"]
    assert g["met"] is True and g["failed"] == [] and g["spine"] == "intact" and g["unexercised"] == []
    assert (g["terms_verdict"], g["independence_verdict"], g["corroboration_verdict"]) == ("accepted", "met", "corroborated")
    n += 1; print("[2] gated contract, terms accepted, 5 declared entities (quorum 3), 2 independent inspectors corroborate: within_grant / final / held")

    # [3] v1.7 on the same gated contract with no spine inputs at all: final. That is what v1.8 exists to stop.
    s7 = v17.settle_v1_7(cG, [exeG], viewG, nenrin_records=[walkG])
    assert s7["verdict"] == "within_grant" and s7["status"] == "final" and s7["bond_outcome"] == "held"
    s8 = settle_v1_8(cG, [exeG], viewG, nenrin_records=[walkG])
    assert s8["verdict"] == "within_grant" and s8["status"] == "spine_unmet" and s8["bond_outcome"] == "pending_spine"
    assert s8["spine_gate"]["failed"] == ["unexercised_terms", "unexercised_corroboration", "terms_not_accepted", "independence_not_met", "not_corroborated"], s8["spine_gate"]["failed"]
    import bond_v0 as bv
    r = bv.build_bond_resolution(cG, s8, "released"); bv.sign_bond_resolution(r, ka, "principal")
    assert bv.verify_bond_resolution(r, cG, s8)["verdict"] == "premature"
    n += 1; print("[3] the same contract with no terms, declarations or measurements: v1.7 says final/held, v1.8 says spine_unmet/pending_spine "
                  "and names the five failures; a bond release signed now is premature under bond v0")

    # [4] each stage missing or broken on its own stops finality, with its own name
    cases = []
    sw = json.loads(json.dumps(TERMS)); sw["items"][0]["quantity"] = 2
    cases.append(("terms edited after pinning", dict(SP, terms=sw), {"spine_broken", "terms_not_accepted"}))
    one_owner = [decl(ka, pa, "principal.example", P), decl(kb, pb, "contractor.example", P), decl(kw, pw, "walker.example", P),
                 decl(k1, p1, "inspector-one.example", I1), decl(k2, p2, "inspector-two.example", I2)]
    cases.append(("one owner behind principal, contractor and witness", dict(SP, declarations=one_owner), {"spine_broken", "independence_not_met"}))
    cases.append(("no declarations", dict(SP, declarations=[]), {"independence_not_met"}))
    cases.append(("one inspector of the two required", dict(SP, measurements=msG[:1]), {"not_corroborated"}))
    cases.append(("no measurements", dict(SP, measurements=[]), {"unexercised_corroboration", "not_corroborated"}))
    for what, sp_in, want in cases:
        s8 = settle_v1_8(cG, [exeG], viewG, nenrin_records=[walkG], spine=sp_in)
        got = set(s8["spine_gate"]["failed"])
        assert s8["verdict"] == "within_grant" and s8["status"] == "spine_unmet" and s8["bond_outcome"] == "pending_spine", (what, s8["status"])
        assert want <= got, (what, got)
    n += 1; print("[4] %d single failures (edited terms, one owner, no declarations, one inspector short, no measurements): each is spine_unmet "
                  "with its own reason" % len(cases))

    # [5] a deviation stays a deviation: the gate never turns a proven prohibited act into anything else
    viewD, walkD, exeD, msD = thread(cG, INSPECTORS, actions=("read", "delete"))
    s8 = settle_v1_8(cG, [exeD], viewD, nenrin_records=[walkD], spine=dict(SP, measurements=msD))
    assert s8["verdict"] == "deviation" and s8["status"] == "final" and s8["bond_outcome"] == "forfeited", (s8["verdict"], s8["status"])
    assert [d["clause"] for d in s8["deviations"]] == ["prohibited"]
    s8 = settle_v1_8(cG, [exeD], viewD, nenrin_records=[walkD], spine=dict(SP, measurements=[]))
    assert s8["verdict"] == "deviation" and s8["status"] == "spine_unmet" and [d["clause"] for d in s8["deviations"]] == ["prohibited"]
    n += 1; print("[5] a recorded delete: deviation/final/forfeited with the spine met; with the spine unmet, still deviation, listed, status spine_unmet")

    # [6] a contract that opts in without making every stage mandatory is refused, not settled
    weak = [
        ("quorum of one entity", dict(FULL, independence=dict(FULL["independence"], min_distinct_legal_entities=1))),
        ("witnesses may belong to a party", dict(FULL, independence=dict(FULL["independence"], witnesses_independent_of_parties=False))),
        ("declarations optional", {k: v for k, v in FULL.items() if k != "independence"} | {"independence": {"min_distinct_legal_entities": 2, "witnesses_independent_of_parties": True}}),
        ("no corroboration block", {k: v for k, v in FULL.items() if k != "corroboration"}),
        ("measurers may be the parties", dict(FULL, corroboration={"min_corroborating_entities": 2, "measurers_independent_of_parties": False})),
        ("unknown gate key", dict(FULL, spine={"gate": GATE_VALUE, "soft": True})),
        ("other gate value", dict(FULL, spine={"gate": "advisory"})),
        ("gate not an object", dict(FULL, spine="intact")),
    ]
    for what, req in weak:
        cw = mk(requirements=req, nonce="f")
        s8 = settle_v1_8(cw, [], viewG, spine=SP)
        assert s8["verdict"] == "underspecified" and s8["status"] == "undetermined" and s8["bond_outcome"] == "undetermined", what
        assert any(u["reason"] == "spine_requirement_incomplete" for u in s8["underspecified"]), (what, s8["underspecified"])
    cw = mk(requirements=FULL, terms=None, nonce="f")
    s8 = settle_v1_8(cw, [], viewG, spine=SP)
    assert any("terms_sha256 is not pinned" in u.get("detail", "") for u in s8["underspecified"])
    n += 1; print("[6] %d weak opt-ins (quorum 1, witnesses inside, declarations optional, no corroboration, measurers inside, unknown key, "
                  "other value, not an object, no pinned terms): underspecified, spine_requirement_incomplete" % (len(weak) + 1))

    # [7] determinism: shuffled declarations and measurements, duplicates, give identical bytes
    ref = canonical(settle_v1_8(cG, [exeG], viewG, nenrin_records=[walkG], spine=SP))
    rng = random.Random(11)
    for _ in range(10):
        dd = list(DECLS) + [DECLS[0]]; rng.shuffle(dd)
        mm = list(msG) + [json.loads(json.dumps(msG[0]))]; rng.shuffle(mm)
        assert canonical(settle_v1_8(cG, [exeG], viewG, nenrin_records=[walkG], spine=dict(SP, declarations=dd, measurements=mm))) == ref
    n += 1; print("[7] 10 shuffles with duplicates: identical settlement bytes")

    # [8] run0002 (the second contract has no requirements.spine): v1.8 == the published settlement apart from the named fields
    here = os.path.dirname(os.path.abspath(__file__))
    rr = os.path.join(here, "run0002")
    if os.path.exists(os.path.join(rr, "settlement_walk2.json")):
        rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
        C2 = rd(os.path.join(here, "second_contract_AB.json"))
        ev2 = rd(os.path.join(rr, "exec_19c44a79.anchored.json"))
        s8 = settle_v1_8(C2, [ev2], rd(os.path.join(rr, "view.json")), nenrin_records=[rd(os.path.join(rr, "walk_8bf29f1a.json"))])
        s6 = rd(os.path.join(rr, "settlement_walk2.json"))
        strip_all = lambda s: {k: v for k, v in s.items() if k not in SAME_EXCEPT + v17.SAME_EXCEPT}
        assert s8["verdict"] == "within_grant" and s8["status"] == "final" and s8["spine_gate"] == {"required": False}
        assert canonical(strip_all(s8)) == canonical(strip_all(s6))
        n += 1; print("[8] run0002 (execution 19c44a79, block 969090): v1.8 == the published settlement on every field except the named ones")
    else:
        print("[8] skipped: run0002/ not beside this file")

    # [9] the layers below still pass
    for f, want in (("settle_v1_7.py", "SELF-TEST PASSED"), ("spine_verify.py", "SELF-TEST PASSED"), ("bond_v0.py", "SELF-TEST PASSED")):
        r = subprocess.run([sys.executable, os.path.join(here, f), "--selftest"], capture_output=True, text=True)
        assert r.returncode == 0 and want in r.stdout, (f, r.stdout[-300:], r.stderr[-300:])
    n += 1; print("[9] settle_v1_7, spine_verify and bond_v0 self tests still pass")

    print("\nSELF-TEST PASSED: MUSUBI settle v1.8, %d checks (no gate: v1.7 unchanged; gate met: final; each stage missing or broken: "
          "spine_unmet; deviations kept; weak opt-ins refused; determinism; run0002 unchanged)" % n)


def main():
    ap = argparse.ArgumentParser(description="MUSUBI settle v1.8 (a contract can make final depend on the whole spine)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--settle", metavar="CONTRACT.json")
    ap.add_argument("--event", action="append", default=[], metavar="RECORD.json")
    ap.add_argument("--view", action="append", default=[], metavar="HEADERS.json")
    ap.add_argument("--nenrin", action="append", default=[], metavar="WALK.json")
    ap.add_argument("--terms", metavar="TERMS.json")
    ap.add_argument("--vocabulary", metavar="VOCABULARY.json", help="the vocabulary file, read as bytes")
    ap.add_argument("--declaration", action="append", default=[], metavar="DECL.json")
    ap.add_argument("--measurement", action="append", default=[], metavar="MEASUREMENT.json")
    ap.add_argument("--task", action="append", default=[], metavar="TASK.json")
    ap.add_argument("--mode", choices=("strict", "legacy"), default="strict")
    ap.add_argument("--out", metavar="OUT.json")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return 0
    if not a.settle or not a.view:
        ap.print_help(); return 1
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    contract = rd(a.settle)
    views = [rd(p) for p in a.view]
    cmp = v17.v14.compare_views_v1_4(views, contract)
    print(json.dumps({"fork_choice": cmp}, indent=2))
    if cmp["chosen"] is None:
        return 2
    spine = {"terms": rd(a.terms) if a.terms else None,
             "vocabulary_bytes": open(a.vocabulary, "rb").read() if a.vocabulary else None,
             "declarations": [rd(p) for p in a.declaration], "measurements": [rd(p) for p in a.measurement],
             "tasks": [rd(p) for p in a.task]}
    s = settle_v1_8(contract, [rd(p) for p in a.event], views[cmp["chosen"]], mode=a.mode,
                    nenrin_records=[rd(p) for p in a.nenrin] if a.nenrin else None, spine=spine)
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="") as f:
            f.write(canonical(s))
        print("wrote", a.out)
    print(json.dumps(s, ensure_ascii=False, indent=2))
    return 0 if s["status"] == "final" else 2


if __name__ == "__main__":
    sys.exit(main())
