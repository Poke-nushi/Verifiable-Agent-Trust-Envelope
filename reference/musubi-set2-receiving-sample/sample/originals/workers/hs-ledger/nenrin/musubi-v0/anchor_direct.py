#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI anchor_direct: anchor a record in Bitcoin yourself, without this project's ledger.

Why this file exists. Every settled MUSUBI execution so far reached Bitcoin through the NENRIN ledger: the ledger
lists the record in a batch, stamps the batch with OpenTimestamps, and anchor_compose joins record -> batch ->
.ots -> header. That works, and it makes this project a piece of infrastructure every contract passes through.
Two parties who want nothing from us should not need our ledger to get a settleable anchor. OpenTimestamps
needs no account and no server of ours, and settle has always accepted a proof that takes the record's digest
straight to a header merkle root. What was missing was the two lines that join them.

  1. stampable bytes   canonical(record without "anchor"), UTF-8. sha256 of these bytes is exactly the digest
                       settle starts from (settle_v1_1.commitment_digest). Write them to a file and run
                       `ots stamp` on it; the calendars are public and free.
  2. compose_direct    read the .ots (anchor_compose.read_ots, no library), require that it stamps those bytes,
                       follow its Bitcoin attestation (anchor_compose.ots_ops) and check the result against the
                       header at that height in a view settle accepts under the contract's rules. The anchor is
                       {height, block_hash, proof} with no hexlify, so settle v1.7's batch-leg rule does not apply
                       and settle runs the proof exactly as it runs every merkle path.

    python3 anchor_direct.py --stampable exec.json --out exec.stamp     then: ots stamp exec.stamp
    (wait for the stamp to confirm, then: ots upgrade exec.stamp.ots)
    python3 anchor_direct.py --record exec.json --ots exec.stamp.ots --contract c.json --view headers.json --out exec.anchored.json

What this does not do: it does not fetch anything, it does not stamp for you (`ots stamp` does), and it does not
check signatures (settle does). It establishes only that these record bytes were committed to Bitcoin by the
attested block, through a path anyone can rerun.
"""
import argparse, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import settle_v1_1 as v11
import anchor_compose as ac
from contract_v0 import canonical, parse_strict
from anchor_compose import Refused, read_ots, ots_ops, anchored_record


def stampable_bytes(record):
    """The bytes to give `ots stamp`. Their sha256 is settle's commitment digest of the record."""
    if not isinstance(record, dict):
        raise Refused("record_not_object")
    b = canonical({k: v for k, v in record.items() if k != "anchor"}).encode("utf-8")
    assert hashlib.sha256(b).digest() == v11.commitment_digest(record)
    return b


def compose_direct(record, ots, contract, view):
    """Returns {"status": "anchored", "anchor": {...}} or {"status": "pending", ...}. Raises Refused."""
    if not isinstance(record, dict):
        raise Refused("record_not_object")
    d = v11.commitment_digest(record)
    fdig, atts = read_ots(ots)
    if fdig != d:
        raise Refused("ots_for_other_bytes",
                      "the .ots stamps %s; the record's canonical bytes hash to %s (stamp the file --stampable writes)" % (fdig.hex(), d.hex()))
    btc = sorted([a for a in atts if a["kind"] == "bitcoin"], key=lambda a: a["height"])
    base = {"record_digest": d.hex(), "path": "direct"}
    if not btc:
        return dict(base, status="pending", waiting_on=sorted({a["uri"] for a in atts if a["kind"] == "pending"}),
                    detail="no Bitcoin attestation in this .ots yet; run ots upgrade once the calendars have committed it")
    cv, problem = v11.verify_view(view, contract)
    if cv is None:
        raise Refused("view_rejected", problem)
    tried = []
    for a in btc:
        h = a["height"]
        if h not in cv["hashes"]:
            tried.append({"height": h, "why": "not in the view"}); continue
        proof = ots_ops(a)
        if len(proof) > v11.MAX_PROOF_OPS:
            raise Refused("proof_too_long", "%d ops over %d" % (len(proof), v11.MAX_PROOF_OPS))
        if any(op.get("op") == "hexlify" for op in proof):
            raise Refused("unexpected_hexlify", "a direct stamp never hexlifies; this .ots was made for other bytes")
        if v11.run_proof(d, proof) != cv["merkle"][h]:
            tried.append({"height": h, "why": "the path does not reach the merkle root of the header at this height"}); continue
        return dict(base, status="anchored", anchor={"height": h, "block_hash": cv["hashes"][h], "proof": proof}, proof_ops=len(proof))
    raise Refused("no_attestation_verifies", json.dumps(tried))


# --------------------------------------------------------------------------- self test
def _selftest():
    import base64
    import contract_v0 as v0
    import settle_v1_2 as v12
    import settle_v1_7 as v17
    from contract_v0 import contract_sha256, EXEC_SCHEMA
    n = 0
    rec = {"schema": "a2a-execution-v0", "contract_id": "0123456789abcdef0123456789abcdef", "actions": ["read"], "note": "anchor_direct self test"}
    sb = stampable_bytes(rec)
    d = hashlib.sha256(sb).digest()
    assert d == v11.commitment_digest(rec)
    with_anchor = dict(rec, anchor={"height": 1, "block_hash": "0" * 64, "proof": []})
    assert stampable_bytes(with_anchor) == sb
    n += 1; print("[1] sha256 of the stampable bytes is settle's commitment digest, with or without an anchor field already present")

    tx_pre, tx_suf = bytes.fromhex("0100000001" + "11" * 36 + "ff") + b"\x6a\x20", bytes.fromhex("00000000")
    sib = hashlib.sha256(b"sib").digest()
    tree = [(0xf0, b"calendar-nonce", [(0x08, None, [("att", "pending", "https://a.example/cal"),
            (0xf1, tx_pre, [(0xf0, tx_suf, [(0x08, None, [(0x08, None, [(0xf0, sib, [(0x08, None, [(0x08, None, [("att", "bitcoin", 101)])])])])])])])])])]
    root = ac._run(tree, d)

    def view_with(m):
        headers, prev = [], "00" * 32
        for h, mm in ((99, hashlib.sha256(b"h99").digest()), (100, hashlib.sha256(b"h100").digest()), (101, m), (102, hashlib.sha256(b"h102").digest())):
            raw = v11._mine(prev, mm, salt=h)
            headers.append({"height": h, "hex": raw.hex()}); prev = v11.header_hash(raw)
        return {"headers": headers}
    view = view_with(root)
    ck = {"kind": "bitcoin_block", "height": 100, "hash": v11.header_hash(bytes.fromhex(view["headers"][1]["hex"]))}
    contract = {"lower_bound": ck, "grant": {"finality": {"depth": 1, "max_target_bits": "207fffff"}}}
    ots = ac.OTS_MAGIC + ac._vu(1) + b"\x08" + d + ac._ser(tree)
    res = compose_direct(rec, ots, contract, view)
    cv, _ = v11.verify_view(view, contract)
    assert res["status"] == "anchored" and res["anchor"]["height"] == 101
    assert v11.run_proof(v11.commitment_digest(anchored_record(rec, res["anchor"])), res["anchor"]["proof"]) == cv["merkle"][101]
    assert not any(op.get("op") == "hexlify" for op in res["anchor"]["proof"])
    n += 1; print("[2] record bytes -> .ots -> header 101 with no batch and no ledger: settle's own check passes (%d ops, no hexlify)" % res["proof_ops"])

    def refused(fn):
        try:
            fn(); return None
        except Refused as e:
            return e.code
    other = dict(rec, note="changed")
    assert refused(lambda: compose_direct(other, ots, contract, view)) == "ots_for_other_bytes"
    assert refused(lambda: compose_direct(rec, ots, contract, view_with(hashlib.sha256(b"x").digest()))) == "no_attestation_verifies"
    assert refused(lambda: compose_direct(rec, ots, contract, {"headers": view["headers"][2:]})) == "view_rejected"
    pend = [(0xf0, b"n", [(0x08, None, [("att", "pending", "https://a.example/cal")])])]
    pr = compose_direct(rec, ac.OTS_MAGIC + ac._vu(1) + b"\x08" + d + ac._ser(pend), contract, view)
    assert pr["status"] == "pending" and pr["waiting_on"] == ["https://a.example/cal"]
    n += 1; print("[3] another record's stamp, a header that does not match, a view the contract rejects: refused by name; an unconfirmed stamp: pending")

    # [4] settle v1.7 settles a signed execution anchored this way: within_grant, final; the batch-leg rule is not involved
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    def newkey():
        k = Ed25519PrivateKey.generate()
        return k, base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    ka, pa = newkey(); kb, pb = newkey(); _, pw = newkey()
    chain = v11._Chain(90, "00" * 32, "direct")
    for _ in range(8):
        chain.block()
    lb = {"kind": "bitcoin_block", "height": 97, "hash": chain.hashes[97]}
    g = {"authorized_actions": ["read"], "prohibited_actions": ["delete"], "conditional": [], "delegation": {"allowed": []},
         "revocation": {"effective_at": "anchor"}, "finality": {"depth": 3, "max_target_bits": "207fffff"},
         "witnesses": [{"name": "w", "public_key_ed25519_b64": pw}]}
    C = v0.build_contract({"domain": "a.example", "key_url": "https://a.example/k.json", "public_key_ed25519_b64": pa},
                          {"domain": "b.example", "key_url": "https://b.example/k.json", "public_key_ed25519_b64": pb},
                          {"purpose": "p", "payload_digest": "a" * 64, "a2a_task_id": "t"}, g,
                          ["that both parties signed these grant bytes at the stated time"],
                          ["that HS enforced any of this at runtime", "that the contractor obeyed the grant, only that its recorded acts match or deviate from it",
                           "that HS judges liability or fault; the verdict is a function anyone recomputes",
                           "that a prohibited action was impossible, only that performing one is a provable deviation",
                           "that this is a legal contract or determines legal responsibility"],
                          lower_bound=lb, contract_id="fedcba9876543210fedcba9876543210", nonce="1" * 32, agreed_at="2026-10-02T00:00:00Z")
    v0.sign_contract(C, ka, pa, "a.example"); v0.sign_contract(C, kb, pb, "b.example")
    ex = v12.sign_record({"schema": EXEC_SCHEMA, "contract_ref": {"contract_id": C["contract_id"], "payload_digest": "a" * 64, "contract_sha256": contract_sha256(C)},
                          "performed_actions": ["read"], "approvals": [], "delegated_to": [], "nenrin_ref": "8" * 64}, kb, "contractor")
    dx = hashlib.sha256(stampable_bytes(ex)).digest()
    t2 = [(0x08, None, [(0xf1, sib, [(0x08, None, [("att", "bitcoin", 98)])])])]
    h = 98
    raw = v11._mine(chain.prev, ac._run(t2, dx), salt=h)
    chain.headers.append({"height": h, "hex": raw.hex()}); chain.hashes[h] = v11.header_hash(raw); chain.prev = chain.hashes[h]
    for _ in range(4):
        chain.block()
    r2 = compose_direct(ex, ac.OTS_MAGIC + ac._vu(1) + b"\x08" + dx + ac._ser(t2), C, chain.view())
    s = v17.settle_v1_7(C, [anchored_record(ex, r2["anchor"])], chain.view())
    assert s["verdict"] == "within_grant" and s["status"] == "final", (s["verdict"], s["status"], s["underspecified"])
    assert v17.batch_leg_rule(anchored_record(ex, r2["anchor"])) == (True, "no_batch_leg")
    n += 1; print("[4] settle v1.7 on a signed execution the parties stamped themselves: within_grant, final; batch-leg rule: no_batch_leg")

    print("ALL PASS (anchor_direct: %d checks)" % n)


def main():
    ap = argparse.ArgumentParser(description="anchor a record in Bitcoin yourself (OpenTimestamps), without this project's ledger")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--stampable", metavar="RECORD.json", help="write the bytes to give `ots stamp` (needs --out)")
    ap.add_argument("--record"); ap.add_argument("--ots"); ap.add_argument("--contract"); ap.add_argument("--view"); ap.add_argument("--out")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return 0
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    if a.stampable:
        if not a.out:
            ap.print_help(); return 1
        b = stampable_bytes(rd(a.stampable))
        open(a.out, "wb").write(b)
        print(json.dumps({"wrote": a.out, "sha256": hashlib.sha256(b).hexdigest(), "next": "ots stamp " + a.out}, indent=2)); return 0
    if not all((a.record, a.ots, a.contract, a.view)):
        ap.print_help(); return 1
    record = rd(a.record)
    try:
        res = compose_direct(record, open(a.ots, "rb").read(), rd(a.contract), rd(a.view))
    except Refused as e:
        print(json.dumps({"status": "refused", "reason": e.code, "detail": e.detail}, indent=2)); return 2
    shown = {k: v for k, v in res.items() if k != "anchor"}
    if res["status"] == "anchored":
        shown["anchor"] = {"height": res["anchor"]["height"], "block_hash": res["anchor"]["block_hash"]}
        if a.out:
            open(a.out, "w", encoding="utf-8", newline="").write(canonical(anchored_record(record, res["anchor"])))
            shown["wrote"] = a.out
    print(json.dumps(shown, indent=2))
    return 0 if res["status"] == "anchored" else 3


if __name__ == "__main__":
    sys.exit(main())
