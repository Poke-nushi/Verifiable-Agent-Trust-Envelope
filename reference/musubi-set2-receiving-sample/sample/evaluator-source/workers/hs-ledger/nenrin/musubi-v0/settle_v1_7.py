#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI settle v1.7: an anchor through a batch must name the record as a listing (a2a-settlement-v1.7).

Why this file exists. settle v1.1 to v1.6 accept an anchor when its proof operations take
sha256(canonical(record without "anchor")) to the merkle root of the header at the claimed height.
Since 2026-09-29 those operations include hexlify, so a proof can pass from a record's digest through
the batch bytes the ledger stamps. horizon-shield#25 (babyblueviper1, 2026-09-30) showed what that
leaves open: the bytes path accepts the digest wherever its hex happens to sit in a stamped batch, under
a "rejected" list, a supersedes pointer, a log line, or a records[] entry of another kind. anchor_compose
was made structural in 05bca753 and gained batch_leg_check for verifiers; nothing in settle called it.
Two consequences, both reproduced in the self test against settle v1.6:

  G1  a record whose hex sits in a stamped batch that does not list it settles with that anchor.
  G2  collapse_anchorings keeps the earliest copy whose anchor verifies. A copy anchored through an
      earlier batch that only names the record wins over the honest copy, so the record's anchor
      height moves earlier than any batch that actually listed it.

What v1.7 changes, and nothing else:

  batch_leg_rule(record)   if the proof uses hexlify at all, hexlify must be the first operation, and
                           anchor_compose.batch_leg_check must accept the proof: the batch rebuilt from
                           the prepend and append operands up to the first sha256 parses as strict JSON
                           of a known batch schema, lists the digest as exactly one records[i].sha (same
                           kind and schema where the batch types its entries, count equal to
                           len(records)), and the splice sits at that member. A proof without hexlify is
                           a merkle path that commits the digest directly and is unchanged.
  settle walk              an anchor that passes run_proof and fails batch_leg_rule is underspecified
                           with reason anchor_batch_leg_refused and the refusal code as detail, placed
                           exactly where anchor_proof_invalid is. No verdict is rendered on it.
  collapse                 an anchor counts as verifying for collapse only if it also passes
                           batch_leg_rule, so the honest copy is the one kept.

Everything else is settle v1.6, reused verbatim: the walk below is v1.6's walk with the two lines above
changed, and approvals, terms, binding, ordering, revocation and the NENRIN cross check are v1.6's parts.
For every record whose anchor has no batch leg, or whose batch leg is a real listing, v1.7 renders the
same settlement as v1.6 apart from schema, settled_under, anchor_rule and one establishes line; the
self test checks that on synthetic runs and on run0002.

Stated limits: as v1.6. batch_leg_check reads the batch schemas anchor_compose.BATCH_RULES knows; a
batch of any other schema is refused, not guessed. It does not check that the batch was stamped by any
particular ledger; the header and the proof establish only that these bytes were committed by then.
"""
import argparse, base64, hashlib, json, os, random, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import contract_v0 as v0
import settle_v1 as v1
import settle_v1_1 as v11
import settle_v1_2 as v12
import settle_v1_3 as v13
import settle_v1_4 as v14
import settle_v1_5 as v15
import settle_v1_6 as v16
import anchor_compose as ac
from settle_v1_6 import classify_approval_v2, check_terms_v1_6
from contract_v0 import canonical, parse_strict, contract_sha256, EXEC_SCHEMA

SETTLE_SCHEMA = "a2a-settlement-v1.7"
ANCHOR_RULE = ("a proof that uses hexlify must start with it, and the batch rebuilt from its operands up to the first sha256 must list "
               "the record as exactly one records[i].sha of a known batch schema, with matching kind and schema (anchor_compose.batch_leg_check); "
               "a proof without hexlify is a merkle path and is unchanged")


def batch_leg_rule(ev):
    """(ok, code). ok is False only for a proof that goes through a batch without the batch listing this record."""
    a = ev.get("anchor") if isinstance(ev.get("anchor"), dict) else {}
    proof = a.get("proof")
    if not isinstance(proof, list):
        return True, "no_proof"
    at = [i for i, op in enumerate(proof) if isinstance(op, dict) and op.get("op") == "hexlify"]
    if not at:
        return True, "no_batch_leg"
    if at != [0]:
        return False, "hexlify_not_leading"
    try:
        return ac.batch_leg_check(ev, proof)
    except (ValueError, TypeError, AttributeError):
        return False, "batch_leg_malformed"


def anchor_valid_v1_7(ev, cv):
    return v13._anchor_valid(ev, cv) and batch_leg_rule(ev)[0]


def collapse_anchorings_v1_7(contract, events, view):
    """settle_v1_3.collapse_anchorings with the v1.7 anchor validity: keep the earliest copy whose anchor verifies
    and whose batch leg, if any, is a listing; if none does, keep them all and let the walk report why."""
    cv, _ = v11.verify_view(view, contract)
    groups = {}
    for ev in v1.bind(contract, events):
        groups.setdefault(v11.commitment_digest(ev).hex(), []).append(ev)
    out, collapsed = [], []
    for body, copies in sorted(groups.items()):
        uniq = {v1.rec_sha(e): e for e in copies}
        if len(uniq) == 1:
            out.append(next(iter(uniq.values())))
            continue
        valid = sorted(((v1.height_of(e), s, e) for s, e in uniq.items() if anchor_valid_v1_7(e, cv)),
                       key=lambda t: (t[0], t[1]))
        if valid:
            keep = valid[0]
            out.append(keep[2])
            collapsed.append({"body_sha256": body, "kept": keep[1], "height": keep[0],
                              "dropped": sorted(s for s in uniq if s != keep[1])})
        else:
            out.extend(uniq.values())
    return out, collapsed


def settle_v1_7(contract, events, view, mode="strict", nenrin_records=None):
    if mode not in ("strict", "legacy"):
        raise ValueError("mode must be 'strict' or 'legacy'")
    if not isinstance(events, list):
        events = []
    csha = contract_sha256(contract)
    g = contract.get("grant") or {}
    bound, foreign, unbound, inconsistent = v15.classify_binding(contract, events, csha)
    used = list(bound) + (list(unbound) if mode == "legacy" else [])

    under = check_terms_v1_6(contract)
    cv, vproblem = v11.verify_view(view, contract)
    if cv is None:
        under.append({"reason": "chain_view_rejected", "detail": vproblem})
    elif len(view["headers"]) > v14.MAX_HEADERS:
        under.append({"reason": "input_too_large", "detail": "headers"}); cv = None
    if len(used) > v14.MAX_RECORDS:
        under.append({"reason": "input_too_large", "detail": "records"}); used = []
    terms_ok = not under

    # v1.6's walk, verbatim except: collapse uses the v1.7 anchor validity, and a proof-valid anchor must also pass batch_leg_rule
    rejected, charges, orphaned, predates, ignored = [], [], [], [], []
    accepted, body_of = [], {}
    for ev in v1.bind(contract, used):
        body_of.setdefault(v11.commitment_digest(ev).hex(), set()).add(v1.rec_sha(ev))
    used, collapsed = collapse_anchorings_v1_7(contract, used, view) if terms_ok else (used, [])
    seen = set()
    for ev in (v1.bind(contract, used) if terms_ok else []):
        s = v1.rec_sha(ev)
        if s in seen:
            continue
        seen.add(s)
        why = v12.authenticate(ev, contract)
        if why:
            rejected.append({"sha256": s, "schema": ev.get("schema"), "why": why}); continue
        if ev.get("schema") == v1.REVOKE_SCHEMA and ev.get("revoked_by") != "principal":
            ignored.append({"sha256": s, "reason": "revocation_by_non_principal"}); continue
        probs = v13.conformance(ev)
        if ev.get("schema") == EXEC_SCHEMA:
            acts = ev.get("performed_actions") if isinstance(ev.get("performed_actions"), list) else []
            if len(acts) > v14.MAX_ACTIONS:
                probs.append("more than %d actions" % v14.MAX_ACTIONS)
            names = [a for a in acts] + [ap.get("action") for ap in (ev.get("approvals") or []) if isinstance(ap, dict)]
            badn = sorted({str(a) for a in names if not (isinstance(a, str) and v14.ACTION_RE.match(a))})
            if badn:
                probs.append("action names outside ^[a-z][a-z0-9_.:-]{0,63}$: %s" % badn)
        if probs:
            if ev.get("schema") == EXEC_SCHEMA and v13._signer(ev, contract) == "contractor":
                charges.append({"clause": "nonconforming_record", "record_sha256": s, "why": probs})
            else:
                rejected.append({"sha256": s, "schema": ev.get("schema"), "why": "nonconforming: %s" % "; ".join(probs)})
                continue
        a = ev.get("anchor") if isinstance(ev.get("anchor"), dict) else {}
        h = v1.height_of(ev)
        bh = a.get("block_hash")
        if h is None or not (isinstance(bh, str) and v11.HEX64.match(bh)):
            under.append({"reason": "anchor_incomplete", "sha256": s}); continue
        if h < cv["checkpoint"]["height"]:
            predates.append({"sha256": s, "height": h}); continue
        if h > cv["tip"] or h not in cv["hashes"]:
            under.append({"reason": "anchor_beyond_observed_chain", "sha256": s, "height": h}); continue
        if cv["hashes"][h] != bh:
            orphaned.append({"sha256": s, "height": h, "block_hash": bh}); continue
        if v11.run_proof(v11.commitment_digest(ev), a.get("proof")) != cv["merkle"][h]:
            under.append({"reason": "anchor_proof_invalid", "sha256": s, "height": h}); continue
        leg_ok, leg_code = batch_leg_rule(ev)
        if not leg_ok:
            under.append({"reason": "anchor_batch_leg_refused", "sha256": s, "height": h, "detail": leg_code}); continue
        accepted.append((h, s, ev))
    accepted.sort(key=lambda t: (t[0], t[1]))

    rev_cfg = g.get("revocation") if isinstance(g.get("revocation"), dict) else {}
    mode_r, window = rev_cfg.get("effective_at"), rev_cfg.get("ack_window")
    acks = [(h, s, e) for h, s, e in accepted if e["schema"] == v1.ACK_SCHEMA]
    revs_out, ends = [], []
    for h, s, e in accepted:
        if e["schema"] != v1.REVOKE_SCHEMA:
            continue
        names = body_of.get(v11.commitment_digest(e).hex(), set()) | {v11.commitment_digest(e).hex()}
        entry = {"sha256": s, "height": h, "basis": mode_r}
        if mode_r == "anchor":
            E = h
        else:
            mine = [ah for ah, _, ae in acks if ae.get("revocation_sha256") in names]
            E = min([h + window] + mine)
            entry["ack_height"] = min(mine) if mine else None
            entry["window_end"] = h + window
        entry["authority_ends_at"] = E
        revs_out.append(entry); ends.append((E, s))
    ends.sort()

    authorized = set(g.get("authorized_actions") or [])
    prohibited = set(g.get("prohibited_actions") or [])
    conditional = {c.get("action"): c for c in (g.get("conditional") or []) if isinstance(c, dict)}
    deleg = g.get("delegation")
    allowed_delegates = set((deleg.get("allowed") if isinstance(deleg, dict) else []) or [])
    exp = g.get("expiry_height")
    carriers, forged, label_bound, other_terms = [], [], [], []
    for h, s, e in accepted:
        if e["schema"] != EXEC_SCHEMA:
            continue
        for ap in e.get("approvals") or []:
            k = classify_approval_v2(ap, contract)
            act = ap.get("action") if isinstance(ap, dict) else None
            if k is None:
                forged.append({"clause": "forged_approval", "observed": act, "record_sha256": s})
            elif k == "label_bound":
                label_bound.append({"action": act, "record_sha256": s})
            elif k == "other_terms":
                other_terms.append({"action": act, "record_sha256": s, "contract_sha256": ap.get("contract_sha256")})
            else:
                carriers.append((h, s, ap))
    used_nonces = set()
    deviations = []
    for h, s, e in accepted:
        if e["schema"] != EXEC_SCHEMA:
            continue
        acts = [a for a in (e.get("performed_actions") or []) if isinstance(a, str)]
        ended = next((rs for E, rs in ends if E <= h), None)
        if ended:
            for a in acts:
                deviations.append({"clause": "revoked", "observed": a, "revocation_sha256": ended, "height": h, "record_sha256": s})
            continue
        for a in acts:
            if exp is not None and h > exp:
                deviations.append({"clause": "after_expiry", "observed": a, "height": h, "record_sha256": s})
            if a in prohibited:
                deviations.append({"clause": "prohibited", "observed": a, "height": h, "record_sha256": s}); continue
            if a in conditional:
                why, ok = None, False
                for ch, cs, ap in carriers:
                    if ap.get("action") != a:
                        continue
                    if not (cs == s or ch < h):
                        why = why or "approval not anchored before the action (same block, other record)"; continue
                    if h > ap["valid_until_height"]:
                        why = why or "approval_expired"; continue
                    if ap["single_use"] and ap["nonce"] in used_nonces:
                        why = why or "approval_reused"; continue
                    if ap["single_use"]:
                        used_nonces.add(ap["nonce"])
                    ok = True; break
                if not ok:
                    if why is None and any(x["action"] == a and x["record_sha256"] == s for x in label_bound):
                        why = "approval bound by contract_id, not these terms (replayable across renegotiation); not counted"
                    elif why is None and any(x["action"] == a and x["record_sha256"] == s for x in other_terms):
                        why = "approval bound to other terms (different contract_sha256); not counted"
                    deviations.append({"clause": "conditional", "observed": a, "height": h, "record_sha256": s,
                                       "why": why or "requires %s, no approval" % conditional[a].get("requires")})
                continue
            if a not in authorized:
                deviations.append({"clause": "unauthorized", "observed": a, "height": h, "record_sha256": s})
        for dg in e.get("delegated_to") or []:
            if dg not in allowed_delegates:
                deviations.append({"clause": "delegation", "observed": dg, "height": h, "record_sha256": s})
    deviations += forged + charges
    deviations += v15._nenrin_deviations(used, nenrin_records, csha)

    under = sorted(under, key=canonical)
    verdict = "underspecified" if under else ("deviation" if deviations else "within_grant")
    status, horizon, pinned, tip = "undetermined", None, [], None
    if cv is not None:
        usedh = sorted({h for h, _, _ in accepted})
        pinned = [{"height": h, "block_hash": cv["hashes"][h]} for h in usedh]
        tip = {"height": cv["tip"], "block_hash": cv["hashes"][cv["tip"]]}
        dp = (g.get("finality") or {}).get("depth") if isinstance(g.get("finality"), dict) else None
        if isinstance(dp, int) and not isinstance(dp, bool) and dp >= 1:
            f = cv["tip"] - dp + 1
            horizon = {"height": f, "block_hash": cv["hashes"].get(f)}
            if verdict != "underspecified":
                status = "final" if all(x <= f for x in usedh + [o["height"] for o in orphaned]) else "provisional"
    bond_outcome = v15._bond_outcome(contract, verdict, status)

    return {
        "schema": SETTLE_SCHEMA,
        "settled_under": v16.SETTLE_SCHEMA,
        "contract_id": contract.get("contract_id"),
        "contract_sha256": csha,
        "binding_mode": mode,
        "bound_by_label_only": (mode == "legacy" and bool(unbound)),
        "ordering_rule": v14.ORDERING_RULE,
        "approval_rule": "a2a-approval-v2: signed by the principal over contract_sha256, action, valid_until_height, nonce, single_use; "
                         "label_bound and other_terms approvals are listed and never counted; unscoped approvals are refused",
        "anchor_rule": ANCHOR_RULE,
        "view_rules": {"checkpoint": cv["checkpoint"], "max_target_bits": cv["max_target_bits"]} if cv else None,
        "chain_tip": tip, "finality_horizon": horizon, "pinned_blocks": pinned,
        "authoritative_event_set": [{"kind": v1._kind(e), "sha256": s, "height": h} for h, s, e in accepted],
        "revocations": revs_out,
        "verdict": verdict, "status": status, "bond_outcome": bond_outcome,
        "underspecified": under,
        "deviations": [] if verdict == "underspecified" else sorted(deviations, key=canonical),
        "approvals": {"counted": [{"action": ap.get("action"), "record_sha256": s, "nonce": ap.get("nonce")} for _, s, ap in carriers],
                      "label_bound": sorted(label_bound, key=canonical), "other_terms": sorted(other_terms, key=canonical)},
        "binding": {"bound": sorted(v1.rec_sha(e) for e in bound), "unbound": sorted(v1.rec_sha(e) for e in unbound),
                    "foreign": sorted(foreign, key=canonical), "inconsistent": sorted(inconsistent, key=canonical)},
        "orphaned": sorted(orphaned, key=canonical), "predates_contract": sorted(predates, key=canonical),
        "ignored": sorted(ignored, key=canonical), "rejected": sorted(rejected, key=canonical),
        "duplicate_anchorings": collapsed,
        "establishes": [
            "that every settled record and every counted approval names these terms by contract_sha256, recomputed here from the contract bytes",
            "that every accepted anchor whose proof passes through a batch listing names this record as exactly one records[i] of a batch schema this verifier reads, with matching kind and schema, and that hexlify appears only as the first operation",
            "that the contract terms are settleable (verified, no undeclared grant key, explicit authority, distinct keys, ungrindable ties, bounded revocation, no unscoped approvals)",
            "that on the verified header view pinned here, the authenticated, proof-checked records %s the grant" % (
                "stay within" if verdict == "within_grant" else "deviate from" if verdict == "deviation" else
                "cannot be settled without the listed terms, so no verdict is rendered on"),
            "that this settlement is %s under the grant's finality depth" % status,
        ],
        "does_not_establish": [
            "full Bitcoin consensus validity; only linkage, work above the checkpoint, the difficulty floor and the checkpoint",
            "that no key was stolen", "that acts nobody recorded did not happen",
            "that a label_bound or other_terms approval is false; only that it does not bind to these terms, so it is not counted",
            "that HS judged this; the verdict is recomputable by anyone from the same bytes and headers",
        ],
        "signatures": [],
    }


# --------------------------------------------------------------------------- self test
SAME_EXCEPT = ("schema", "settled_under", "anchor_rule", "establishes")


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
    ka, pa = newkey(); kb, pb = newkey(); _, pw = newkey()
    chain = v11._Chain(90, "00" * 32, "v17-%d" % random.randint(0, 1 << 30))
    for _ in range(8):
        chain.block()                                                   # 90..97
    lb = {"kind": "bitcoin_block", "height": 97, "hash": chain.hashes[97]}
    g = {"authorized_actions": ["read"], "prohibited_actions": ["delete"], "conditional": [],
         "delegation": {"allowed": []}, "revocation": {"effective_at": "anchor"},
         "finality": {"depth": 3, "max_target_bits": "207fffff"},
         "witnesses": [{"name": "nenrin-walker", "public_key_ed25519_b64": pw}]}
    C = v0.build_contract(
        {"domain": "gate.horizonshield.dev", "key_url": "https://gate.horizonshield.dev/keys/agreement.json", "public_key_ed25519_b64": pa},
        {"domain": "api.babyblueviper.com", "key_url": "https://api.babyblueviper.com/keys/agreement.json", "public_key_ed25519_b64": pb},
        {"purpose": "endpoint_conduct_walk", "payload_digest": "a" * 64, "a2a_task_id": "t1"}, g,
        ["that both parties signed these grant bytes at the stated time"],
        ["that HS enforced any of this at runtime",
         "that the contractor obeyed the grant, only that its recorded acts match or deviate from it",
         "that HS judges liability or fault; the verdict is a function anyone recomputes",
         "that a prohibited action was impossible, only that performing one is a provable deviation",
         "that this is a legal contract or determines legal responsibility"],
        bond={"amount": 1000, "currency": "JPY"}, lower_bound=lb,
        contract_id="0123456789abcdef0123456789abcdef", nonce="e" * 32, agreed_at="2026-09-30T00:00:00Z")
    v0.sign_contract(C, ka, pa, "gate.horizonshield.dev"); v0.sign_contract(C, kb, pb, "api.babyblueviper.com")
    ex = v12.sign_record({"schema": EXEC_SCHEMA,
                          "contract_ref": {"contract_id": C["contract_id"], "payload_digest": "a" * 64, "contract_sha256": contract_sha256(C)},
                          "performed_actions": ["read"], "approvals": [], "delegated_to": [], "nenrin_ref": "8" * 64}, kb, "contractor")
    d = v11.commitment_digest(ex)
    other = hashlib.sha256(b"another record").hexdigest()

    def stamp(batch):
        """Put sha256(sha256(batch)) in the next header, as a one step calendar path would. Returns (height, settle ops of the path)."""
        h = chain.h0 + len(chain.headers)
        tree = [(0x08, None, [("att", "bitcoin", h)])]
        claim = hashlib.sha256(batch).digest()
        raw = v11._mine(chain.prev, ac._run(tree, claim), salt=h)
        chain.headers.append({"height": h, "hex": raw.hex()}); chain.hashes[h] = v11.header_hash(raw); chain.prev = chain.hashes[h]
        fd, atts = ac.read_ots(ac.OTS_MAGIC + ac._vu(1) + b"\x08" + claim + ac._ser(tree))
        return h, ac.ots_ops([x for x in atts if x["kind"] == "bitcoin"][0]), claim

    def splice(batch, at):
        return [{"op": "hexlify"}, {"op": "prepend", "hex": batch[:at].hex()}, {"op": "append", "hex": batch[at + 64:].hex()}, {"op": "sha256"}]

    def with_anchor(h, proof):
        return ac.anchored_record(ex, {"height": h, "block_hash": chain.hashes[h], "proof": proof})

    # 98: a stamped batch that names the record only under "rejected"
    rej = canonical({"schema": "nenrin-agreement-batch-v1", "count": 1, "records": [{"sha": other, "kind": "agreement"}],
                     "rejected": [{"sha": d.hex()}]}).encode()
    h98, ots98, _ = stamp(rej)
    f_rej = with_anchor(h98, splice(rej, rej.index(d.hex().encode())) + ots98)
    # 99: listed, but as kind agreement
    kinded = canonical({"schema": "nenrin-agreement-batch-v1", "records": [{"sha": d.hex(), "kind": "agreement"}, {"sha": other, "kind": "agreement"}]}).encode()
    h99, ots99, _ = stamp(kinded)
    f_kind = with_anchor(h99, splice(kinded, kinded.index(d.hex().encode())) + ots99)   # the splice sits at records[0].sha
    # 100: a batch that lists sha256(digest), reached by sha256 then hexlify
    dd = hashlib.sha256(d).hexdigest()
    dbl = canonical({"schema": "nenrin-agreement-batch-v1", "records": [{"sha": dd, "kind": "execution"}]}).encode()
    h100, ots100, _ = stamp(dbl)
    f_dbl = with_anchor(h100, [{"op": "sha256"}] + splice(dbl, dbl.index(dd.encode())) + ots100)
    # 101: the honest batch
    hb = canonical({"schema": "nenrin-agreement-batch-v1", "records": [
        {"sha": d.hex(), "kind": "execution", "bytes_url": "https://agreement.example/execution/" + d.hex()},
        {"sha": other, "kind": "agreement"}]}).encode()
    h101, ots101, _ = stamp(hb)
    honest = with_anchor(h101, ac.batch_ops(d, hb, ex)[0] + ots101)
    # 102: the record directly in a block merkle tree (no batch leg)
    merkle = chain.block([ex])[0]
    for _ in range(3):
        chain.block()                                                   # 103..105; depth 3 puts 103 on the horizon
    view = chain.view()
    cv, _ = v11.verify_view(view, C)
    for r in (f_rej, f_kind, f_dbl, honest, merkle):
        assert v13._anchor_valid(r, cv), "every anchor passes the bytes path"

    # [1] G1: an anchor through a batch that does not list the record
    for rec, code in ((f_rej, "record_not_listed_in_batch"), (f_kind, "record_kind_mismatch"), (f_dbl, "hexlify_not_leading")):
        s6 = v16.settle_v1_6(C, [rec], view)
        s7 = settle_v1_7(C, [rec], view)
        assert s6["verdict"] == "within_grant" and s6["status"] == "final", (code, s6["verdict"], s6["underspecified"])
        assert s7["verdict"] == "underspecified" and s7["status"] == "undetermined" and s7["deviations"] == []
        assert [u for u in s7["underspecified"] if u["reason"] == "anchor_batch_leg_refused"] == \
               [{"reason": "anchor_batch_leg_refused", "sha256": v1.rec_sha(rec), "height": v1.height_of(rec), "detail": code}], s7["underspecified"]
    n += 1; print("[1] G1: anchors through a rejected list, a kind agreement listing, and a listing of sha256(digest): settle v1.6 says within_grant/final, "
                  "v1.7 says underspecified with anchor_batch_leg_refused (record_not_listed_in_batch, record_kind_mismatch, hexlify_not_leading)")

    # [2] G2: collapse keeps the earliest anchor that verifies; v1.6 is fooled into the rejected batch, v1.7 keeps the honest copy
    s6 = v16.settle_v1_6(C, [honest, f_rej, f_kind], view)
    s7 = settle_v1_7(C, [honest, f_rej, f_kind], view)
    assert s6["duplicate_anchorings"][0]["kept"] == v1.rec_sha(f_rej) and s6["authoritative_event_set"][0]["height"] == h98
    assert s7["duplicate_anchorings"][0]["kept"] == v1.rec_sha(honest) and s7["authoritative_event_set"] == [{"kind": "execution", "sha256": v1.rec_sha(honest), "height": h101}]
    assert s7["verdict"] == "within_grant" and s7["status"] == "final"
    n += 1; print("[2] G2: the same execution with three anchors: v1.6 keeps the rejected batch at %d (the anchor moves %d blocks earlier), "
                  "v1.7 keeps the listing at %d, within_grant/final" % (h98, h101 - h98, h101))

    # [3] honest anchors: v1.7 renders v1.6's settlement, field for field, apart from the four named fields
    for rec, what in ((honest, "batch leg that lists the record"), (merkle, "merkle path, no batch leg")):
        s6 = v16.settle_v1_6(C, [rec], view)
        s7 = settle_v1_7(C, [rec], view)
        assert s7["verdict"] == "within_grant" and s7["status"] == "final", (what, s7["underspecified"])
        assert canonical(_strip(s7)) == canonical(_strip(s6)), what
        assert s7["schema"] == SETTLE_SCHEMA and s7["settled_under"] == v16.SETTLE_SCHEMA and s7["anchor_rule"] == ANCHOR_RULE
    assert batch_leg_rule(honest) == (True, "listed_in_records") and batch_leg_rule(merkle) == (True, "no_batch_leg")
    n += 1; print("[3] a batch leg that lists the record, and a plain merkle path: v1.7 == v1.6 on every field except schema, settled_under, anchor_rule, establishes")

    # [4] malformed operands after hexlify never raise
    bad = [
        [{"op": "hexlify"}, {"op": "prepend", "hex": "zz"}, {"op": "sha256"}],
        [{"op": "hexlify"}, "prepend", {"op": "sha256"}],
        [{"op": "hexlify"}, {"op": "prepend", "hex": None}, {"op": "sha256"}],
        [{"op": "hexlify"}, {"op": "prepend", "hex": "00"}],
        [{"op": "hexlify"}, {"op": "reverse"}, {"op": "sha256"}],
    ]
    for p in bad:
        r = ac.anchored_record(ex, {"height": h101, "block_hash": chain.hashes[h101], "proof": p})
        ok, code = batch_leg_rule(r)
        assert ok is False and code in ("batch_leg_malformed", "batch_not_json"), (p, code)
        assert settle_v1_7(C, [r], view)["verdict"] == "underspecified"
    n += 1; print("[4] %d malformed batch legs (bad hex, a bare string, None, no sha256, an unknown op): refused, no exception" % len(bad))

    # [5] determinism: order and duplicates do not change the bytes
    rng = random.Random(7)
    base_set = [honest, f_rej, f_kind, f_dbl, merkle]
    ref = canonical(settle_v1_7(C, base_set, view))
    for _ in range(20):
        sh = base_set + [dict(rng.choice(base_set))]; rng.shuffle(sh)
        assert canonical(settle_v1_7(C, sh, view)) == ref
    got = json.loads(ref)
    assert got["verdict"] == "within_grant" and got["authoritative_event_set"][0]["height"] == h101
    n += 1; print("[5] five anchors of one execution, 20 shuffles with a duplicate: identical bytes, the honest listing kept")

    # [6] run0002: the real walk 2 settles the same under v1.7
    here = os.path.dirname(os.path.abspath(__file__))
    rr = os.path.join(here, "run0002")
    if os.path.exists(os.path.join(rr, "settlement_walk2.json")):
        rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
        C2 = rd(os.path.join(here, "second_contract_AB.json"))
        ev2 = rd(os.path.join(rr, "exec_19c44a79.anchored.json"))
        s7 = settle_v1_7(C2, [ev2], rd(os.path.join(rr, "view.json")), nenrin_records=[rd(os.path.join(rr, "walk_8bf29f1a.json"))])
        s6 = rd(os.path.join(rr, "settlement_walk2.json"))
        assert batch_leg_rule(ev2) == (True, "listed_in_records")
        assert s7["verdict"] == "within_grant" and s7["status"] == "final" and canonical(_strip(s7)) == canonical(_strip(s6))
        n += 1; print("[6] run0002 (execution 19c44a79, entry 63, block 969090): batch leg listed_in_records; v1.7 == the published v1.6 settlement "
                      "on every field except the four named")
    else:
        print("[6] skipped: run0002/ not beside this file")

    # [7] every layer below still passes
    for f, want in (("settle_v1_6.py", "SELF-TEST PASSED"), ("anchor_compose.py", "ALL PASS")):
        r = subprocess.run([sys.executable, os.path.join(here, f), "--selftest"], capture_output=True, text=True)
        assert r.returncode == 0 and want in r.stdout, (f, r.stdout[-300:], r.stderr[-300:])
    n += 1; print("[7] settle_v1_6 and anchor_compose self tests still pass")

    print("\nSELF-TEST PASSED: MUSUBI settle v1.7, %d checks (horizon-shield#25 leg 1: G1 an anchor through a batch that does not list the record, "
          "G2 collapse fooled into an earlier batch; honest anchors unchanged; run0002 unchanged)" % n)


def main():
    ap = argparse.ArgumentParser(description="MUSUBI settle v1.7 (an anchor through a batch must name the record as a listing)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--settle", metavar="CONTRACT.json")
    ap.add_argument("--event", action="append", default=[], metavar="RECORD.json")
    ap.add_argument("--view", action="append", default=[], metavar="HEADERS.json")
    ap.add_argument("--nenrin", action="append", default=[], metavar="WALK.json")
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
    cmp = v14.compare_views_v1_4(views, contract)
    print(json.dumps({"fork_choice": cmp}, indent=2))
    if cmp["chosen"] is None:
        return 2
    nenrin = [rd(p) for p in a.nenrin] if a.nenrin else None
    s = settle_v1_7(contract, [rd(p) for p in a.event], views[cmp["chosen"]], mode=a.mode, nenrin_records=nenrin)
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="") as f:
            f.write(canonical(s))
        print("wrote", a.out)
    print(json.dumps(s, ensure_ascii=False, indent=2))
    return 0 if s["status"] == "final" else 2


if __name__ == "__main__":
    sys.exit(main())
