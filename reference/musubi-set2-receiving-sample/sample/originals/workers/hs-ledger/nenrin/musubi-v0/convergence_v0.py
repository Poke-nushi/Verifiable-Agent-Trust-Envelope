#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI convergence v0: gather measurers nobody chose at the transaction, from different directions (a2a-convergence-v0).

Why this file exists. corroboration v0 counts how many legal entities measured "done". It does not ask who chose
those entities. A contractor who brings two friendly inspectors gets two corroborating entities, each with its
own houjin bangou, each signing the same lie. Signatures cannot close that. What closes it, as far as anything
can, is the idea behind inverse scattering: you do not trust one sensor, you surround the object with sensors
placed where nobody arranged them, look at it from different directions, and accept a picture only when every
direction agrees. A fabricated object has to be consistent from every angle at once; a real one is.

So this layer requires three things the parties cannot arrange in advance:

  1. WHO measures is drawn, not chosen. The contract pins a pool of measurers (nenrin-witness-pool-v1, by
     pool_sha256) and a future Bitcoin height (beacon_height). Once that block exists, the draw is
     seed = sha256(beacon_hash | pool_sha256 | contract_sha256), a partial Fisher-Yates over the pool sorted by
     key: the same function as TSUGI's kuji (recovery-v0/witness_draw.mjs and recovery_verify.draw), so anyone,
     in JavaScript or Python, gets the same k measurers. Only drawn measurers count. A party, or anyone the
     parties brought who was not drawn, is reported and never counted.
  2. WHEN they measure is after the draw. A drawn measurer's record counts only if its beacon is at or after
     beacon_height: a measurement written before anyone knew who would be drawn was not made as a drawn one.
  4. WITH WHOM they have dealt before, when the contract sets history_independent: a drawn measurer that shares a
     signed earlier contract with a party, or signed a measurement under one, is not counted. Two companies with
     different registrations that keep turning up on each other's jobs are one interest; the interaction graph
     shows what the register does not. Only signed, verifying records make an edge; a history left out is
     "undetermined", never "independent".
  3. FROM WHERE they measure is more than one direction. The drawn measurements that agree must use at least
     min_distinct_methods of the methods the vocabulary lists for the item (tape on site, take-off from drawings,
     a non-destructive scan). A lie has to survive each method separately.

Per item the answer is: converged (enough drawn entities agree, from enough methods), diverged (drawn
measurers disagree with each other; the report names which projection), contradicted (the drawn measurers
agree with each other and not with the terms; if a party claimed the work was within terms, that claim is
named as contradicted), not_converged (too few drawn voices or directions), or undetermined (the beacon block
is not yet in the view, or drawn voices are still provisional).

What this does not establish: that the drawn measurers did not collude after being drawn (it only stops the
parties choosing them, and makes the lie pass several methods); that two declared entities are two owners; that
the pool itself was assembled fairly (the pool is pinned in both signatures, so both parties accepted it); that
the contract was signed before the beacon block existed, unless the caller supplies the height that anchors the
contract, in which case a contract anchored at or after the beacon is refused.
"""
import argparse, base64, json, os, random, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "recovery-v0"))
import contract_v0 as v0
import settle_v1_1 as v11
import terms_v0 as tv0
import independence_v0 as ind
import corroboration_v0 as cor
import recovery_verify as rv
from contract_v0 import canonical, parse_strict, contract_sha256, HEX64

OUT_SCHEMA = "a2a-convergence-v0"
REQ_KEYS = frozenset(("pool_sha256", "draw_k", "beacon_height", "min_distinct_methods", "min_drawn_agreeing", "history_independent"))
PARTIES = ("principal", "contractor")


def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def read_requirement(contract):
    """(req or None, problems). None when the contract states no requirements.convergence."""
    reqs = contract.get("requirements") if isinstance(contract.get("requirements"), dict) else {}
    if "convergence" not in reqs:
        return None, []
    c = reqs["convergence"]
    if not isinstance(c, dict):
        return None, ["requirements.convergence must be an object"]
    p = []
    extra = sorted(k for k in c if k not in REQ_KEYS)
    if extra:
        p.append("requirements.convergence carries keys no verifier reads: %s" % ", ".join(extra))
    if not (isinstance(c.get("pool_sha256"), str) and HEX64.match(c["pool_sha256"])):
        p.append("requirements.convergence.pool_sha256 must be 64 hex")
    k = c.get("draw_k")
    if not (_is_int(k) and k >= 2):
        p.append("requirements.convergence.draw_k must be 2 or more")
    lb = (contract.get("lower_bound") or {}).get("height") if isinstance(contract.get("lower_bound"), dict) else None
    bh = c.get("beacon_height")
    if not (_is_int(bh) and _is_int(lb) and bh > lb):
        p.append("requirements.convergence.beacon_height must be a block after the contract's lower_bound")
    md = c.get("min_distinct_methods")
    if not (_is_int(md) and md >= 2):
        p.append("requirements.convergence.min_distinct_methods must be 2 or more")
    ma = c.get("min_drawn_agreeing")
    if not (_is_int(ma) and ma >= 2 and _is_int(k) and ma <= k):
        p.append("requirements.convergence.min_drawn_agreeing must be 2 or more and at most draw_k")
    if "history_independent" in c and not isinstance(c["history_independent"], bool):
        p.append("requirements.convergence.history_independent must be true or false")
    return (None if p else dict(c)), p


def history_edges(history, csha):
    """Who has dealt with whom before, from signed records only. A prior contract that verifies links every pair of
    its actors (parties and witnesses); a prior measurement signed by its measurer links the measurer to the actors
    of the contract it names, when that contract is in the history. The contract being settled is skipped. Returns
    (adjacency {key: set(keys)}, counts). Unsigned or unverifiable records add nothing."""
    adj, used = {}, {"contracts": 0, "measurements": 0, "ignored": 0}
    actors_of = {}
    link = lambda a, b: (adj.setdefault(a, set()).add(b), adj.setdefault(b, set()).add(a)) if a and b and a != b else None
    for h in history or []:
        if isinstance(h, dict) and h.get("schema") == v0.SCHEMA:
            hs = contract_sha256(h)
            if hs == csha or v0.verify_contract(h)["verdict"] != "accepted":
                used["ignored"] += 1; continue
            ks = [a["key"] for a in ind.contract_actors(h) if a.get("key")]
            actors_of[hs] = ks
            for i in range(len(ks)):
                for j in range(i + 1, len(ks)):
                    link(ks[i], ks[j])
            used["contracts"] += 1
    for h in history or []:
        if isinstance(h, dict) and h.get("schema") == cor.MEAS_SCHEMA:
            pub = (h.get("measurer") or {}).get("public_key_ed25519_b64") if isinstance(h.get("measurer"), dict) else None
            msg = cor.measurement_signing_bytes(h)
            ok = pub and any(isinstance(x, dict) and cor.ed25519_verify(pub, x.get("sig_b64"), msg) is True for x in (h.get("signatures") or []))
            hs = h.get("contract_sha256")
            if not ok or hs == csha or hs not in actors_of:
                used["ignored"] += 1; continue
            for k in actors_of[hs]:
                link(pub, k)
            used["measurements"] += 1
    return adj, used


def _vocab_methods(terms, vocabulary_bytes):
    try:
        vocab = json.loads(vocabulary_bytes.decode("utf-8"))
        return {iid: set((it or {}).get("methods") or []) for iid, it in (vocab.get("items") or {}).items()}
    except (AttributeError, ValueError, UnicodeDecodeError):
        return None


def verify_convergence(contract, terms, measurements, view, pool, declarations=(), vocabulary_bytes=None, history=None,
                       contract_anchor_height=None):
    r = v0.R()
    csha = contract_sha256(contract) if isinstance(contract, dict) else None
    req, probs = read_requirement(contract) if isinstance(contract, dict) else (None, ["not a contract"])
    if probs:
        for x in probs:
            r.refuse("bad_requirements", x)
        return _out(r, csha, "refused", None, None, [])
    if req is None:
        return _out(r, csha, "none", None, None, [])
    tcheck = tv0.verify_terms(terms, vocabulary_bytes, contract=contract)
    if tcheck["verdict"] != "accepted":
        r.refuse("terms_not_accepted", "convergence needs the pinned terms and their vocabulary bytes (the methods live there): %s" % tcheck["verdict"])
        return _out(r, csha, "refused", req, None, [])
    tsha = tcheck["terms_sha256"]
    methods_of = _vocab_methods(terms, vocabulary_bytes) or {}
    cv, vproblem = v11.verify_view(view, contract)
    if cv is None:
        r.refuse("chain_view_rejected", vproblem)
        return _out(r, csha, "refused", req, None, [])
    try:
        psha = rv.pool_sha256(pool)
    except (ValueError, TypeError, AttributeError) as e:
        r.refuse("bad_pool", str(e)); return _out(r, csha, "refused", req, None, [])
    if psha != req["pool_sha256"]:
        r.refuse("pool_not_pinned", "the supplied pool hashes to %s, the contract pins %s" % (psha, req["pool_sha256"]))
        return _out(r, csha, "refused", req, None, [])
    bh = req["beacon_height"]
    if contract_anchor_height is not None:
        if not _is_int(contract_anchor_height) or contract_anchor_height >= bh:
            r.refuse("beacon_known_at_signing", "the contract is anchored at %s, not before the beacon block %d, so the parties could have seen the draw" % (contract_anchor_height, bh))
            return _out(r, csha, "refused", req, None, [])
    else:
        r.find("signing_time_unproven", "no contract anchor height was supplied, so nothing here shows the contract predates the beacon block")
    if bh not in cv["hashes"]:
        r.find("beacon_not_observed", "block %d is not in the view yet; nobody is drawn until it exists" % bh)
        return _out(r, csha, "undetermined", req, None, [])
    d = rv.draw(pool, cv["hashes"][bh], csha, req["draw_k"])
    drawn = {e["public_key_ed25519_b64"]: e["signed_domain"] for e in d["entries"]}
    draw_out = {"beacon": {"height": bh, "hash": cv["hashes"][bh]}, "pool_sha256": psha, "seed_sha256": d["seed_sha256"],
                "k": int(d["k"]), "drawn": sorted(d["drawn"])}

    entity_of = cor._entities(declarations, r)
    linked = set()
    if req.get("history_independent"):
        if history is None:
            r.find("history_not_supplied", "the contract asks for measurers with no prior dealings with a party, and no history was supplied")
            return _out(r, csha, "undetermined", req, draw_out, [])
        adj, hused = history_edges(history, csha)
        party_keys = {a["key"] for a in ind.contract_actors(contract) if a["role"] in PARTIES and a.get("key")}
        pent = {entity_of.get(k) for k in party_keys if entity_of.get(k)}
        for k in drawn:
            for nb in adj.get(k, ()):
                if nb in party_keys or (entity_of.get(nb) and entity_of.get(nb) in pent):
                    linked.add(k)
        draw_out = dict(draw_out, history={"records": hused, "drawn_linked_to_a_party": sorted(drawn[k] for k in linked)})
    if r.refusals:
        return _out(r, csha, "refused", req, draw_out, [])
    actors = ind.contract_actors(contract)
    party_key = {a["key"]: a["role"] for a in actors if a["role"] in PARTIES and a.get("key")}
    party_entities = {entity_of.get(k) for k in party_key if entity_of.get(k)}
    items = {it["item_id"]: it for it in terms["items"]}
    checkpoint = cv["checkpoint"]["height"]
    deadline = (terms.get("deadline") or {}).get("height") if isinstance(terms.get("deadline"), dict) else None

    uniq, seen = [], set()
    for m in measurements or []:
        key = canonical(m) if isinstance(m, (dict, list)) else repr(m)
        if key not in seen:
            seen.add(key); uniq.append(m)
    rows = []
    for i, m in enumerate(uniq):
        row = cor.examine_measurement(m, i, tsha, csha, items, cv, checkpoint, deadline)
        if row["use"] in ("ignored", "rejected"):
            rows.append(dict(row, role="n/a", counted=False)); continue
        k = row.get("measurer_key")
        item = items.get(row.get("item_id"))
        meth = m.get("method")
        row["method"] = meth
        if k in party_key:
            row["role"] = party_key[k]
        elif k in drawn:
            row["role"] = "drawn"
            row["domain"] = drawn[k]
        else:
            row["role"] = "not_drawn"
        row["entity"] = entity_of.get(k)
        if meth not in methods_of.get(row.get("item_id"), set()):
            row["agreement"] = "method_not_in_vocabulary"
        elif item is not None:
            ok, dev = tv0.within_tolerance(tv0._qty(item["quantity"]), tv0._qty(m.get("measured")), item.get("tolerance_bp", 0))
            row["agreement"], row["deviation_bp"] = ("within" if ok else "outside"), dev
        why = None
        if row["role"] != "drawn":
            why = "not drawn" if row["role"] == "not_drawn" else "a party measures its own work"
        elif not row.get("time_bound"):
            why = "provisional (not yet inside a block window)"
        elif row.get("beacon_height", -1) < bh:
            why = "measured before the draw (beacon %s < %d)" % (row.get("beacon_height"), bh)
        elif row["entity"] is None:
            why = "drawn measurer with no declared legal entity"
        elif k in linked:
            why = "drawn measurer has dealt with a party before (history graph)"
        elif row["entity"] in party_entities:
            why = "drawn measurer belongs to a party's legal entity"
        elif row.get("agreement") not in ("within", "outside"):
            why = row.get("agreement")
        row["counted"], row["not_counted_because"] = why is None, why
        rows.append(row)

    per_item = []
    for iid in sorted(items):
        mine = [x for x in rows if x.get("item_id") == iid]
        cnt = [x for x in mine if x["counted"]]
        within = {}
        outside = {}
        for x in cnt:
            (within if x["agreement"] == "within" else outside).setdefault(x["entity"], set()).add(x["method"])
        both = sorted(set(within) & set(outside))
        w_methods = sorted({mm for s in within.values() for mm in s})
        claims = [x for x in mine if x["role"] in PARTIES and x.get("agreement") in ("within", "outside")]
        pending = any(x["role"] == "drawn" and (x.get("not_counted_because") or "").startswith("provisional") for x in mine)
        if within and outside:
            status = "diverged"
        elif outside:
            status = "contradicted"
        elif len(within) >= req["min_drawn_agreeing"] and len(w_methods) >= req["min_distinct_methods"]:
            status = "converged"
        elif pending:
            status = "undetermined"
        else:
            status = "not_converged"
        finds = []
        if status == "contradicted":
            for x in claims:
                if x["agreement"] == "within":
                    finds.append({"code": "party_claim_contradicted", "party": x["role"], "measurement_sha256": x.get("sha256"),
                                  "why": "the %s measured the work within terms; every drawn measurer measured it outside" % x["role"]})
        if status == "diverged":
            finds.append({"code": "projections_disagree", "within": [{"entity": e, "methods": sorted(s)} for e, s in sorted(within.items())],
                          "outside": [{"entity": e, "methods": sorted(s)} for e, s in sorted(outside.items())]})
        per_item.append({
            "item_id": iid, "status": status,
            "drawn_agreeing_entities": len(within), "drawn_disagreeing_entities": len(outside),
            "agreeing_methods": w_methods, "self_inconsistent_entities": both,
            "required": {"min_drawn_agreeing": req["min_drawn_agreeing"], "min_distinct_methods": req["min_distinct_methods"]},
            "findings": finds,
            "measurements": sorted(({k: x.get(k) for k in ("sha256", "role", "domain", "entity", "method", "agreement", "deviation_bp",
                                                          "counted", "not_counted_because")} for x in mine), key=canonical)})
    sts = {x["status"] for x in per_item}
    order = ("diverged", "contradicted", "not_converged", "undetermined")
    verdict = next((s for s in order if s in sts), "converged" if per_item else "undetermined")
    return _out(r, csha, verdict, req, draw_out, per_item)


def _out(r, csha, verdict, req, draw, items):
    return {"schema": OUT_SCHEMA, "verdict": verdict, "contract_sha256": csha, "requirement": req, "draw": draw,
            "items": items, "refusals": sorted(r.refusals, key=canonical), "findings": sorted(r.findings, key=canonical),
            "establishes": [
                "that the counted measurers are exactly the ones the pinned pool, the beacon block and this contract draw, by a function anyone recomputes in Python or JavaScript",
                "that each counted measurement was signed by a drawn measurer after the beacon block, inside a block window, by a declared legal entity outside both parties",
                "that the agreeing measurements come from at least the stated number of entities and of the vocabulary's methods, or which projection disagreed",
            ],
            "does_not_establish": [
                "that the drawn measurers did not collude after being drawn; only that the parties did not choose them and that a lie had to pass several methods",
                "that two declared entities are two owners, or that the pool was assembled fairly (both parties signed its hash)",
                "that the contract predates the beacon block, unless the contract's anchor height was supplied",
                "that any measurement is true in the world",
            ]}


# --------------------------------------------------------------------------- fixture (shared with settle v1.9)
def fixture():
    """A complete synthetic world: keys, a chain, terms with two methods, a pool of six measurers, declarations."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    def newkey():
        k = Ed25519PrivateKey.generate()
        return k, base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    W = {}
    W["ka"], W["pa"] = newkey(); W["kb"], W["pb"] = newkey(); W["kw"], W["pw"] = newkey()
    W["meas"] = [newkey() for _ in range(6)]
    base = v11._Chain(60, "00" * 32, "conv-%d" % random.randint(0, 1 << 30))
    for _ in range(38):
        base.block()                                                       # 60..97
    W["base"] = base
    W["lb"] = {"kind": "bitcoin_block", "height": 97, "hash": base.hashes[97]}
    W["methods"] = ["drawing_takeoff_v0", "on_site_tape_measure_v0"]
    vocab = tv0.make_vocabulary("interior-glossary", "2026.10", {"wallcovering_m2": {"unit": "m2", "methods": W["methods"]}})
    W["vb"] = tv0.vocabulary_bytes(vocab)
    vref = {"name": "interior-glossary", "version": "2026.10", "sha256": tv0.vocabulary_sha256(W["vb"]), "url": "https://example.test/g.json"}
    W["terms"] = tv0.build_terms(vref, [{"item_id": "wallcovering_m2", "quantity": 120, "unit": "m2", "tolerance_bp": 300,
                                         "completion_test": {"method": "on_site_tape_measure_v0", "evidence_schema": "a2a-measurement-v0"}}])
    W["pool"] = {"entries": [{"signed_domain": "m%d.example" % i, "key_url": "https://m%d.example/keys/agreement.json" % i,
                              "public_key_ed25519_b64": p} for i, (_, p) in enumerate(W["meas"])]}
    LE = lambda n, i: {"registry": "JP", "scheme": "houjin-bango", "id": str(1000000000000 + i), "name": n}

    def decl(key, pub, domain, le):
        return ind.sign_declaration(ind.build_declaration(pub, domain, "https://%s/keys/agreement.json" % domain, le), key)
    W["decls"] = [decl(W["ka"], W["pa"], "principal.example", LE("Principal K.K.", 1)),
                  decl(W["kb"], W["pb"], "contractor.example", LE("Contractor K.K.", 2)),
                  decl(W["kw"], W["pw"], "walker.example", LE("Walker K.K.", 3))] + \
                 [decl(k, p, "m%d.example" % i, LE("Measurer %d K.K." % i, 10 + i)) for i, (k, p) in enumerate(W["meas"])]
    W["decl"] = decl
    W["LE"] = LE
    return W


def make_contract(W, convergence=None, spine=True, beacon_height=99, nonce="c"):
    g = {"authorized_actions": ["install_wallcovering", "measure"], "prohibited_actions": ["structural_change"], "conditional": [],
         "delegation": {"allowed": []}, "revocation": {"effective_at": "anchor"},
         "finality": {"depth": 3, "max_target_bits": "207fffff"},
         "witnesses": [{"name": "nenrin-walker", "public_key_ed25519_b64": W["pw"]}]}
    task = {"purpose": "interior_wallcovering_replacement", "payload_digest": "a" * 64}
    tv0.bind_terms(task, W["terms"])
    reqs = {"evidence": "nenrin_required", "recovery": "n/a",
            "independence": {"min_distinct_legal_entities": 3, "witnesses_independent_of_parties": True, "declarations_required": True},
            "corroboration": {"min_corroborating_entities": 1, "measurers_independent_of_parties": True}}
    if spine:
        reqs["spine"] = {"gate": "final_requires_intact_spine"}
    if convergence is not False:
        reqs["convergence"] = convergence or {"pool_sha256": rv.pool_sha256(W["pool"]), "draw_k": 3, "beacon_height": beacon_height,
                                              "min_distinct_methods": 2, "min_drawn_agreeing": 3}
    c = v0.build_contract(
        {"domain": "principal.example", "key_url": "https://principal.example/keys/agreement.json", "public_key_ed25519_b64": W["pa"]},
        {"domain": "contractor.example", "key_url": "https://contractor.example/keys/agreement.json", "public_key_ed25519_b64": W["pb"]},
        task, g, ["that both parties signed these grant bytes and these terms at the stated time"],
        ["that HS enforced any of this at runtime", "that the contractor obeyed the grant, only that its recorded acts match or deviate from it",
         "that HS judges liability or fault; the verdict is a function anyone recomputes",
         "that a prohibited action was impossible, only that performing one is a provable deviation",
         "that this is a legal contract or determines legal responsibility"],
        bond={"amount": 1000, "currency": "JPY", "holder": "principal"}, lower_bound=W["lb"], requirements=reqs,
        contract_id="0123456789abcdef0123456789abcdef", nonce=nonce * 32, agreed_at="2026-10-02T00:00:00Z")
    v0.sign_contract(c, W["ka"], W["pa"], "principal.example")
    v0.sign_contract(c, W["kb"], W["pb"], "contractor.example")
    return c


def world(W, contract, plan, contractor_claim=None, execute=True):
    """Build the chain 98, 99 (beacon), then put the execution and the measurements in block 100, five more blocks.
    plan(drawn_keys) -> list of (key, pub, measured, method, beacon_height). Returns (view, draw, exe, walk, measurements)."""
    import settle_v1 as v1
    import settle_v1_2 as v12
    ch = W["base"].fork(98, "w%d" % random.randint(0, 1 << 40))
    ch.block(); ch.block()                                                 # 98, 99
    csha = contract_sha256(contract)
    req = (contract.get("requirements") or {}).get("convergence") or {}
    bh = req.get("beacon_height", 99)
    d = rv.draw(W["pool"], ch.hashes[bh], csha, req.get("draw_k", 3)) if bh in ch.hashes else None
    keymap = {p: k for k, p in W["meas"]}
    drawn = [(keymap[e["public_key_ed25519_b64"]], e["public_key_ed25519_b64"]) for e in (d["entries"] if d else [])]
    beacon = lambda h: {"kind": "bitcoin_block", "height": h, "hash": ch.hashes[h]}
    ms = [cor.sign_measurement(cor.build_measurement(contract, W["terms"], "wallcovering_m2", q, meth, pub, beacon(bhh)), key)
          for key, pub, q, meth, bhh in plan(drawn, [(k, p) for k, p in W["meas"] if (k, p) not in drawn])]
    if contractor_claim is not None:
        ms.append(cor.sign_measurement(cor.build_measurement(contract, W["terms"], "wallcovering_m2", contractor_claim,
                                                             "on_site_tape_measure_v0", W["pb"], beacon(99)), W["kb"]))
    walk = {"schema": "jidec-path-v1", "context": {"contract_sha256": csha}, "subject": "contractor.example/a2a",
            "result": "pass", "nonce": "1234567890abcdef1234567890abcdef"}
    exe = v12.sign_record({"schema": v0.EXEC_SCHEMA,
                           "contract_ref": {"contract_id": contract["contract_id"], "payload_digest": "a" * 64, "contract_sha256": csha},
                           "performed_actions": ["install_wallcovering"], "approvals": [], "delegated_to": [],
                           "nenrin_ref": v1.rec_sha(walk)}, W["kb"], "contractor")
    recs = ch.block(([exe] if execute else []) + ms)                     # 100
    for _ in range(5):
        ch.block()
    exe_a = recs[0] if execute else None
    return ch.view(), d, exe_a, walk, recs[(1 if execute else 0):]


def _selftest():
    n = 0
    W = fixture()
    T, VB, P = W["terms"], W["vb"], W["pool"]
    c = make_contract(W)
    assert v0.verify_contract(c)["verdict"] == "accepted", v0.verify_contract(c)
    honest = lambda dr, rest: [(dr[0][0], dr[0][1], 120, "on_site_tape_measure_v0", 99), (dr[1][0], dr[1][1], 118, "on_site_tape_measure_v0", 99),
                               (dr[2][0], dr[2][1], 121, "drawing_takeoff_v0", 99)]

    # [1] three drawn entities, two methods, all within: converged; the draw is the TSUGI kuji function
    view, d, _, _, ms = world(W, c, honest)
    out = verify_convergence(c, T, ms, view, P, W["decls"], VB, contract_anchor_height=98)
    assert out["verdict"] == "converged", (out["verdict"], out["items"], out["refusals"])
    it = out["items"][0]
    assert it["drawn_agreeing_entities"] == 3 and it["agreeing_methods"] == W["methods"]
    assert out["draw"]["drawn"] == sorted(d["drawn"]) and out["draw"]["seed_sha256"] == d["seed_sha256"]
    n += 1; print("[1] 3 drawn entities by the kuji seed, 2 methods (tape, drawings), all within 3%: converged")

    # [2] the lie: the contractor claims 120, every drawn measurer finds 80: contradicted, the claim named
    liar = lambda dr, rest: [(dr[0][0], dr[0][1], 80, "on_site_tape_measure_v0", 99), (dr[1][0], dr[1][1], 81, "on_site_tape_measure_v0", 99),
                             (dr[2][0], dr[2][1], 79, "drawing_takeoff_v0", 99)]
    view, _, _, _, ms = world(W, c, liar, contractor_claim=120)
    out = verify_convergence(c, T, ms, view, P, W["decls"], VB, contract_anchor_height=98)
    assert out["verdict"] == "contradicted" and out["items"][0]["findings"][0]["code"] == "party_claim_contradicted", out["items"][0]["findings"]
    n += 1; print("[2] contractor signs 120 m2, three drawn measurers find about 80 from two directions: contradicted, party_claim_contradicted")

    # [3] one projection disagrees: diverged, and the report says which entity and method
    split = lambda dr, rest: [(dr[0][0], dr[0][1], 120, "on_site_tape_measure_v0", 99), (dr[1][0], dr[1][1], 119, "on_site_tape_measure_v0", 99),
                              (dr[2][0], dr[2][1], 90, "drawing_takeoff_v0", 99)]
    view, _, _, _, ms = world(W, c, split)
    out = verify_convergence(c, T, ms, view, P, W["decls"], VB, contract_anchor_height=98)
    f = out["items"][0]["findings"][0]
    assert out["verdict"] == "diverged" and f["code"] == "projections_disagree" and f["outside"][0]["methods"] == ["drawing_takeoff_v0"], f
    n += 1; print("[3] tape says 120, drawings say 90: diverged, the drawing projection named")

    # [4] friends the parties brought (measurers not drawn) agree: never counted
    friends = lambda dr, rest: [(k, p, 120, m, 99) for (k, p), m in zip(rest, ["on_site_tape_measure_v0", "drawing_takeoff_v0", "on_site_tape_measure_v0"])]
    view, _, _, _, ms = world(W, c, friends, contractor_claim=120)
    out = verify_convergence(c, T, ms, view, P, W["decls"], VB, contract_anchor_height=98)
    assert out["verdict"] == "not_converged" and out["items"][0]["drawn_agreeing_entities"] == 0
    assert {x["not_counted_because"] for x in out["items"][0]["measurements"]} == {"not drawn", "a party measures its own work"}
    n += 1; print("[4] three agreeing measurers who were not drawn plus the contractor's own: not_converged, none counted")

    # [5] one direction only: three drawn, all tape: not_converged (methods 1 < 2)
    mono = lambda dr, rest: [(k, p, 120, "on_site_tape_measure_v0", 99) for k, p in dr]
    view, _, _, _, ms = world(W, c, mono)
    out = verify_convergence(c, T, ms, view, P, W["decls"], VB, contract_anchor_height=98)
    assert out["verdict"] == "not_converged" and out["items"][0]["agreeing_methods"] == ["on_site_tape_measure_v0"]
    n += 1; print("[5] three drawn measurers, one method: not_converged")

    # [6] measured before the draw, a method the vocabulary does not list, a drawn measurer under a party's entity: not counted
    early = lambda dr, rest: [(dr[0][0], dr[0][1], 120, "on_site_tape_measure_v0", 98), (dr[1][0], dr[1][1], 120, "laser_guess_v0", 99),
                              (dr[2][0], dr[2][1], 120, "drawing_takeoff_v0", 99)]
    view, d6, _, _, ms = world(W, c, early)
    k2 = next(k for k, p in W["meas"] if p == d6["entries"][2]["public_key_ed25519_b64"])
    p2 = d6["entries"][2]["public_key_ed25519_b64"]
    i2 = [p for _, p in W["meas"]].index(p2)
    decls = [x for x in W["decls"] if x["public_key_ed25519_b64"] != p2] + [W["decl"](k2, p2, "m%d.example" % i2, W["LE"]("Contractor K.K.", 2))]
    out = verify_convergence(c, T, ms, view, P, decls, VB, contract_anchor_height=98)
    why = sorted(x["not_counted_because"] for x in out["items"][0]["measurements"])
    assert out["items"][0]["drawn_agreeing_entities"] == 0 and out["verdict"] == "not_converged", why
    assert any(w.startswith("measured before the draw") for w in why) and "method_not_in_vocabulary" in why and \
           "drawn measurer belongs to a party's legal entity" in why, why
    n += 1; print("[6] measured before the draw, a method outside the vocabulary, a drawn measurer that is the contractor's company: none counted")

    # [7] the pool swapped after signing, the contract anchored after the beacon, the beacon not yet mined
    view, _, _, _, ms = world(W, c, honest)
    P2 = {"entries": P["entries"][:5]}
    assert verify_convergence(c, T, ms, view, P2, W["decls"], VB)["refusals"][0]["code"] == "pool_not_pinned"
    assert verify_convergence(c, T, ms, view, P, W["decls"], VB, contract_anchor_height=99)["refusals"][0]["code"] == "beacon_known_at_signing"
    cfar = make_contract(W, beacon_height=200, nonce="d")
    o = verify_convergence(cfar, T, [], view, P, W["decls"], VB)
    assert o["verdict"] == "undetermined" and any(f["code"] == "beacon_not_observed" for f in o["findings"])
    o = verify_convergence(c, T, ms, view, P, W["decls"], VB)
    assert o["verdict"] == "converged" and any(f["code"] == "signing_time_unproven" for f in o["findings"])
    n += 1; print("[7] pool swapped: refused; contract anchored at the beacon: refused; beacon not mined: undetermined; no anchor height: converged with signing_time_unproven")

    # [8] weak requirements are refused
    for bad in ({"draw_k": 1}, {"min_distinct_methods": 1}, {"min_drawn_agreeing": 4}, {"beacon_height": 97}, {"pool_sha256": "x"}, {"extra": 1}):
        req = dict(c["requirements"]["convergence"]); req.update(bad)
        cb = make_contract(W, convergence=req, nonce="e")
        assert verify_convergence(cb, T, [], view, P, W["decls"], VB)["verdict"] == "refused", bad
    n += 1; print("[8] 6 weak or malformed requirements (k 1, one method, agreeing > k, beacon not after lower_bound, bad pool sha, unknown key): refused")

    # [8b] history graph: a drawn measurer that was a party to an earlier contract with the contractor is not counted
    ch_req = dict(c["requirements"]["convergence"], history_independent=True)
    ch = make_contract(W, convergence=ch_req, nonce="h")
    view, dh, _, _, ms = world(W, ch, honest)
    _t = make_contract(W, nonce="p")
    p0 = dh["entries"][0]["public_key_ed25519_b64"]; k0 = next(k for k, p in W["meas"] if p == p0)
    prior = v0.build_contract({"domain": "m.example", "key_url": "https://m.example/keys/agreement.json", "public_key_ed25519_b64": p0},
                              {"domain": "contractor.example", "key_url": "https://contractor.example/keys/agreement.json", "public_key_ed25519_b64": W["pb"]},
                              {"purpose": "earlier_job", "payload_digest": "b" * 64}, _t["grant"], _t["establishes"], _t["does_not_establish"],
                              lower_bound=W["lb"], contract_id="fedcba9876543210fedcba9876543210", nonce="9" * 32, agreed_at="2026-09-01T00:00:00Z")
    v0.sign_contract(prior, k0, p0, "m.example"); v0.sign_contract(prior, W["kb"], W["pb"], "contractor.example")
    assert v0.verify_contract(prior)["verdict"] == "accepted", v0.verify_contract(prior)
    o = verify_convergence(ch, T, ms, view, P, W["decls"], VB, history=[prior], contract_anchor_height=98)
    assert o["verdict"] == "not_converged" and o["draw"]["history"]["drawn_linked_to_a_party"] == [dh["entries"][0]["signed_domain"]], (o["verdict"], o["draw"])
    assert any(x["not_counted_because"] == "drawn measurer has dealt with a party before (history graph)" for x in o["items"][0]["measurements"])
    o = verify_convergence(ch, T, ms, view, P, W["decls"], VB, history=[], contract_anchor_height=98)
    assert o["verdict"] == "converged"
    o = verify_convergence(ch, T, ms, view, P, W["decls"], VB, contract_anchor_height=98)
    assert o["verdict"] == "undetermined" and any(f["code"] == "history_not_supplied" for f in o["findings"])
    forged = json.loads(json.dumps(prior)); forged["task"]["purpose"] = "edited"
    o = verify_convergence(ch, T, ms, view, P, W["decls"], VB, history=[forged], contract_anchor_height=98)
    assert o["verdict"] == "converged" and o["draw"]["history"]["records"]["ignored"] == 1
    n += 1; print("[8b] history graph: a drawn measurer who contracted with the contractor before is not counted; no history: undetermined; "
                  "an edited prior contract adds no edge")

    # [9] determinism, and the same draw from the JavaScript kuji
    view, d, _, _, ms = world(W, c, honest)
    ref = canonical(verify_convergence(c, T, ms, view, P, W["decls"], VB, contract_anchor_height=98))
    rng = random.Random(3)
    for _ in range(10):
        mm = list(ms) + [ms[0]]; rng.shuffle(mm)
        dd = list(W["decls"]); rng.shuffle(dd)
        assert canonical(verify_convergence(c, T, mm, view, P, dd, VB, contract_anchor_height=98)) == ref
    js = os.path.join(HERE, "..", "recovery-v0", "witness_draw.mjs")
    node = subprocess.run(["node", "--version"], capture_output=True, text=True) if os.path.exists(js) else None
    if node and node.returncode == 0:
        prog = ("import {draw} from %s; const a = JSON.parse(process.argv[1]);"
                "const d = await draw({pool: a.pool, beaconHash: a.b, subjectSha256: a.s, k: 3}); console.log(JSON.stringify(d.drawn));") % json.dumps("file://" + os.path.abspath(js))
        cv, _ = v11.verify_view(view, c)
        arg = json.dumps({"pool": P, "b": cv["hashes"][99], "s": contract_sha256(c)})
        r = subprocess.run(["node", "--input-type=module", "-e", prog, arg], capture_output=True, text=True)
        assert r.returncode == 0 and json.loads(r.stdout) == d["drawn"], (r.stdout, r.stderr[-300:], d["drawn"])
        n += 1; print("[9] 10 shuffles with duplicates: identical bytes; witness_draw.mjs (JavaScript) draws the same three measurers")
    else:
        n += 1; print("[9] 10 shuffles with duplicates: identical bytes (node not found, JavaScript draw not compared)")

    print("\nSELF-TEST PASSED: MUSUBI convergence v0, %d checks (drawn, after the draw, from several directions; the lie contradicted; "
          "friends, early records, party companies and measurers with a shared history not counted; pool and timing refusals; determinism; Python and JavaScript draw the same)" % n)


def main():
    ap = argparse.ArgumentParser(description="MUSUBI convergence v0 (measurers nobody chose, from different directions)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return 0
    ap.print_help(); return 1


if __name__ == "__main__":
    sys.exit(main())
