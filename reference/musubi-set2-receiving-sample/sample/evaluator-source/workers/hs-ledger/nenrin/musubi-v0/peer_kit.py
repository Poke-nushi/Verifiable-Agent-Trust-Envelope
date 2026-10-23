#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI peer_kit: two parties make, sign, anchor and settle a contract with nobody from this project involved.

Every MUSUBI contract so far has had this project as a party, and every execution reached Bitcoin through its
ledger. The adoption count says it plainly: contracts with an outside party 2, contracts with no party from this
project 0. The protocol is only a protocol if that second number can move without us. This file is the whole
path, for two parties A and B, using only these verification files, OpenTimestamps and public block headers:

    keygen          each party, on its own machine: an Ed25519 key (PEM) and its public key (base64)
    contract        either party: the unsigned contract from a small JSON of parameters. With contract_id, nonce and
                    agreed_at in the params (or --pins-from an earlier draft), both parties build the same bytes, so
                    neither has to publish a draft for the other: each builds, compares contract_sha256 (--expect), signs
    sign            each party: add its signature (contract_v0.sign_contract; refuses a key the contract does not pin)
    verify          anyone: contract_v0.verify_contract
    approve         an approver both parties pinned (optional): an a2a-approval-v2 approval for one conditional action
    exec            the contractor: a signed a2a-execution-v0 naming the contract by contract_sha256
    stampable       anyone: the bytes to give `ots stamp` (anchor_direct)
    anchor          anyone: the settle anchor from the confirmed .ots and a header view (anchor_direct)
    settle          anyone: settle v1.10 (v1.9, v1.8 and v1.7 underneath) on the anchored records
    request         the contractor (admission, optional): a signed action request, before acting

Admission (a2a-admission-v0). When params.json carries "requirements": {..., "admission": "required_before_execution"},
the contractor asks before it acts and the relying party (the principal, or whoever guards the resource) answers at
its own door with admit, escalate or refuse, signed with its own key. The contractor's execution record then names
that admission, and settle (v1.11, and v1.12 when the grant carries limits) reads the execution against it. This kit
makes the request, names the answer in the execution and settles. The door that writes the answer is the relying
party's own and is not part of this kit; its record is checked with admission_verify_v0.py, which is.

    python3 peer_kit.py request --contract c.AB.json --key b.pem --action read --valid-until <height> --out req.json
    python3 admission_verify_v0.py --verify adm.json --key <the relying party's key> --contract c.AB.json
    python3 peer_kit.py exec --contract c.AB.json --key b.pem --actions read --nenrin-ref <64 hex> --request req.json
        --admission adm.json --out e.json
    python3 peer_kit.py settle --contract c.AB.json --event e.anchored.json --view headers.json --admission adm.anchored.json
        --relying-key a.example=<base64 public key>

Block headers come from any explorer; header_view_fetch.py builds a view from two and checks they agree. Nothing
here sends anything anywhere, and no step needs an account, a key or a server of ours.

    python3 peer_kit.py keygen --out a.pem
    python3 peer_kit.py contract --params params.json --out c.unsigned.json
    (the other party, same bytes: python3 peer_kit.py contract --params params.json --pins-from c.unsigned.json
     --expect <contract_sha256> --out c.unsigned.json)
    python3 peer_kit.py sign --contract c.unsigned.json --key a.pem --domain a.example --out c.A.json
    python3 peer_kit.py sign --contract c.A.json --key b.pem --domain b.example --out c.AB.json
    python3 peer_kit.py exec --contract c.AB.json --key b.pem --actions read --nenrin-ref <64 hex> --out e.json
    (with a pinned approver: python3 peer_kit.py approve --contract c.AB.json --key z.pem --name z.example
     --action emit_witness --valid-until <height> --out ap.json, then exec ... --approval ap.json)
    python3 peer_kit.py stampable --record e.json --out e.stamp && ots stamp e.stamp     (later: ots upgrade e.stamp.ots)
    python3 peer_kit.py anchor --record e.json --ots e.stamp.ots --contract c.AB.json --view headers.json --out e.anchored.json
    python3 peer_kit.py settle --contract c.AB.json --event e.anchored.json --view headers.json

params.json: {"principal": {"domain", "key_url", "public_key_ed25519_b64"}, "contractor": {same}, "task": {"purpose",
"payload_digest"}, "authorized_actions": [...], "prohibited_actions": [...], "witnesses": [{"name",
"public_key_ed25519_b64"}], "lower_bound": {"kind": "bitcoin_block", "height", "hash"}, "finality_depth": 6,
"expiry_height": null, "requirements": {...} (optional: terms, independence, corroboration, spine, convergence),
"conditional": [{"action", "requires"}] (optional), "approvers": [{"name", "public_key_ed25519_b64", "actions"}]
(optional, settle v1.10: each listed action is approved only by that key; it must be a conditional action, and the key
may not be a party's or a witness's), "contract_id", "nonce" (32 lowercase hex each) and "agreed_at"
("YYYY-MM-DDTHH:MM:SSZ") (optional: pin them and every build of these params is byte-identical; left out, a build
draws fresh ones and prints them)}.

An approver is pinned in the grant, so it is part of contract_sha256: agree on it before either party signs. The
approval signs contract_sha256, which leaves out the signatures, so the approver can sign as soon as the terms are fixed.
"""
import argparse, base64, json, os, re, secrets, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import contract_v0 as v0
import settle_v1_2 as v12
import anchor_direct as ad
from contract_v0 import canonical, parse_strict, contract_sha256, EXEC_SCHEMA

DNE = ["that anyone enforced any of this at runtime; the grant is proved against the records afterwards",
       "that the contractor obeyed the grant, only that its recorded acts match or deviate from it",
       "that anyone judges liability or fault; the verdict is a function anyone recomputes from the contract, the records and the headers",
       "that a prohibited action was impossible, only that performing one is a provable deviation",
       "that this is a legal contract or determines legal responsibility",
       "when either signature was produced; agreed_at is the declared drafting time, not a proven signing time"]
EST = ["that both parties signed these grant bytes"]


def keygen(out):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


PINS = ("contract_id", "nonce", "agreed_at")
_HEX32 = re.compile(r"^[0-9a-f]{32}\Z")


def _check_pins(pins):
    for f in ("contract_id", "nonce"):
        if f in pins and not (isinstance(pins[f], str) and _HEX32.match(pins[f])):
            raise SystemExit("%s must be 32 lowercase hex" % f)
    if "agreed_at" in pins:
        a = pins["agreed_at"]
        try:
            ok = isinstance(a, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", a) and \
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.strptime(a, "%Y-%m-%dT%H:%M:%SZ")) == a
        except ValueError:
            ok = False
        if not ok:
            raise SystemExit("agreed_at must be a real UTC time written YYYY-MM-DDTHH:MM:SSZ")


def pins_from(contract):
    return {f: contract[f] for f in PINS if f in contract}


def build(params):
    pins = {f: params[f] for f in PINS if params.get(f) is not None}
    _check_pins(pins)
    g = {"authorized_actions": list(params["authorized_actions"]), "prohibited_actions": list(params.get("prohibited_actions") or []),
         "conditional": list(params.get("conditional") or []), "delegation": {"allowed": []}, "revocation": {"effective_at": "anchor"},
         "finality": {"depth": int(params.get("finality_depth", 6)), "max_target_bits": params.get("max_target_bits", "17080000")},
         "witnesses": list(params.get("witnesses") or [])}
    if params.get("expiry_height") is not None:
        g["expiry_height"] = params["expiry_height"]
    if params.get("approvers"):
        g["approval_policy"] = {"allow_unscoped": False, "approvers": [dict(a) for a in params["approvers"]]}
    task = dict(params["task"])
    return v0.build_contract(dict(params["principal"]), dict(params["contractor"]), task, g, EST, DNE,
                             requirements=params.get("requirements") or {"evidence": "nenrin_required", "recovery": "n/a"},
                             bond=params.get("bond"), lower_bound=params["lower_bound"],
                             contract_id=pins.get("contract_id") or secrets.token_hex(16),
                             nonce=pins.get("nonce") or secrets.token_hex(16), agreed_at=pins.get("agreed_at"))


def sign(contract, pem, domain):
    key, pub = v0._load_priv(pem)
    v0.sign_contract(contract, key, pub, domain)
    return contract


def approve(contract, pem, name, action, valid_until_height):
    import settle_v1_10 as v110
    key, pub = v0._load_priv(pem)
    pin = next((a for a in v110.approvers(contract) if a.get("name") == name), None)
    if pin is None or pin.get("public_key_ed25519_b64") != pub:
        raise SystemExit("this key is not the approver key the contract pins under that name")
    if action not in (pin.get("actions") or []):
        raise SystemExit("the contract does not let this approver approve %r" % action)
    return v110.sign_approver_approval(key, contract, action, int(valid_until_height), secrets.token_hex(16), name, pub)


def make_request(contract, pem, action, valid_until_height, target=None, amount=None, approvals=()):
    """The contractor's signed action request (admission_verify_v0.build_action_request), asked before acting."""
    import admission_verify_v0 as A
    key, pub = v0._load_priv(pem)
    me = next((p for p in contract["parties"] if p.get("role") == "contractor"), {})
    if me.get("public_key_ed25519_b64") != pub:
        raise SystemExit("this key is not the contractor key the contract pins")
    return A.build_action_request(contract, action, secrets.token_hex(16), int(valid_until_height), key, target=target, amount=amount, approvals=list(approvals))


def admission_ref(request, admission):
    import admission_verify_v0 as A
    a = request["action"]
    return {"action": a["action"], "admission_sha256": A.admission_sha256(admission),
            "executed": {"action": a["action"], "target": a.get("target"), "amount": a.get("amount"), "nonce": request["nonce"], "expiry_height": request["expiry_height"]}}


def make_exec(contract, pem, actions, nenrin_ref, approvals=(), admitted=()):
    key, pub = v0._load_priv(pem)
    me = next((p for p in contract["parties"] if p.get("role") == "contractor"), {})
    if me.get("public_key_ed25519_b64") != pub:
        raise SystemExit("this key is not the contractor key the contract pins")
    r = {"schema": EXEC_SCHEMA,
         "contract_ref": {"contract_id": contract["contract_id"], "payload_digest": (contract.get("task") or {}).get("payload_digest"),
                          "contract_sha256": contract_sha256(contract)},
         "performed_actions": list(actions), "approvals": list(approvals), "delegated_to": [], "nenrin_ref": nenrin_ref}
    if admitted:
        r["admission_ref"] = [admission_ref(req, adm) for req, adm in admitted]
    return v12.sign_record(r, key, "contractor")


def _selftest():
    n = 0
    t = tempfile.mkdtemp()
    pa = keygen(os.path.join(t, "a.pem")); pb = keygen(os.path.join(t, "b.pem")); pw = keygen(os.path.join(t, "w.pem"))
    try:
        keygen(os.path.join(t, "a.pem")); raise AssertionError("keygen overwrote a key")
    except FileExistsError:
        pass
    assert oct(os.stat(os.path.join(t, "a.pem")).st_mode & 0o777) == "0o600"
    n += 1; print("[1] keygen: three keys, file mode 600, an existing key file is never overwritten")
    params = {"principal": {"domain": "a.example", "key_url": "https://a.example/keys/agreement.json", "public_key_ed25519_b64": pa},
              "contractor": {"domain": "b.example", "key_url": "https://b.example/keys/agreement.json", "public_key_ed25519_b64": pb},
              "task": {"purpose": "endpoint_conduct_walk", "payload_digest": "a" * 64},
              "authorized_actions": ["read", "emit_witness"], "prohibited_actions": ["delete", "payment"],
              "witnesses": [{"name": "w", "public_key_ed25519_b64": pw}],
              "lower_bound": {"kind": "bitcoin_block", "height": 969500, "hash": "0" * 64}, "finality_depth": 6}
    c = build(params)
    assert v0.verify_contract(c)["verdict"] == "refused"
    sign(c, os.path.join(t, "a.pem"), "a.example")
    try:
        sign(c, os.path.join(t, "w.pem"), "b.example"); raise AssertionError("signed with a key the contract does not pin")
    except SystemExit:
        pass
    sign(c, os.path.join(t, "b.pem"), "b.example")
    vc = v0.verify_contract(c)
    assert vc["verdict"] == "accepted", vc
    assert not any(p.get("domain", "").endswith("horizonshield.dev") for p in c["parties"])
    n += 1; print("[2] contract built from params, signed by A then B (a third key refused), verify_contract accepted; no party is this project")
    e = make_exec(c, os.path.join(t, "b.pem"), ["read"], "8" * 64)
    assert v12.authenticate(e, c) is None and e["contract_ref"]["contract_sha256"] == contract_sha256(c)
    try:
        make_exec(c, os.path.join(t, "a.pem"), ["read"], "8" * 64); raise AssertionError("principal signed an execution")
    except SystemExit:
        pass
    n += 1; print("[3] execution signed by the contractor authenticates under the contract; the principal's key is refused")
    assert ad.stampable_bytes(e) == canonical({k: v for k, v in e.items() if k != "anchor"}).encode("utf-8")
    import subprocess
    r = subprocess.run([sys.executable, os.path.join(HERE, "anchor_direct.py"), "--selftest"], capture_output=True, text=True)
    assert r.returncode == 0 and "ALL PASS" in r.stdout, r.stdout[-300:]
    n += 1; print("[4] the stampable bytes for the execution, and anchor_direct (stamp, anchor, settle v1.7 final) pass")
    import settle_v1_10 as v110
    pz = keygen(os.path.join(t, "z.pem"))
    p2 = dict(params, conditional=[{"action": "emit_witness", "requires": "approver"}],
              approvers=[{"name": "z.example", "public_key_ed25519_b64": pz, "actions": ["emit_witness"]}])
    c2 = build(p2)
    ap1 = approve(c2, os.path.join(t, "z.pem"), "z.example", "emit_witness", 970000)
    sign(c2, os.path.join(t, "a.pem"), "a.example"); sign(c2, os.path.join(t, "b.pem"), "b.example")
    assert v0.verify_contract(c2)["verdict"] == "accepted"
    assert v110.verify_approver_approval(c2, ap1)[0] == "approved", v110.verify_approver_approval(c2, ap1)
    for bad in ((os.path.join(t, "a.pem"), "z.example", "emit_witness"), (os.path.join(t, "z.pem"), "z.example", "read")):
        try:
            approve(c2, bad[0], bad[1], bad[2], 970000); raise AssertionError("approve accepted %r" % (bad,))
        except SystemExit:
            pass
    e2 = make_exec(c2, os.path.join(t, "b.pem"), ["emit_witness"], "9" * 64, [ap1])
    assert v12.authenticate(e2, c2) is None and e2["approvals"] == [ap1]
    p3 = dict(p2, approvers=[{"name": "z.example", "public_key_ed25519_b64": pa, "actions": ["emit_witness"]}])
    c3 = build(p3); sign(c3, os.path.join(t, "a.pem"), "a.example"); sign(c3, os.path.join(t, "b.pem"), "b.example")
    assert {"reason": "approver_is_party", "detail": "approvers[0] uses the key of a party to this contract"} in v110._party_problems(c3)
    n += 1; print("[5] a pinned approver from params: signed before the parties (contract_sha256 leaves out signatures) and still approved after; a party key or an unlisted action is refused at approve; the approval rides in the execution; a party's key as approver is flagged approver_is_party")
    pinned = dict(params, contract_id="1" * 32, nonce="2" * 32, agreed_at="2026-10-08T00:00:00Z")
    b1 = build(pinned); b2 = build(json.loads(json.dumps(pinned)))
    assert canonical(b1) == canonical(b2) and contract_sha256(b1) == contract_sha256(b2)
    fresh = build(params)
    b3 = build(dict(params, **pins_from(fresh)))
    assert contract_sha256(b3) == contract_sha256(fresh) and canonical(b3) == canonical(fresh)
    old = dict(fresh, establishes=["that both parties signed these grant bytes at the stated time"])
    b4 = build(dict(params, **pins_from(old)))
    assert pins_from(b4) == pins_from(old) and b4["establishes"] == EST and contract_sha256(b4) != contract_sha256(old)
    for bad in ({"nonce": "XYZ"}, {"contract_id": "1" * 31}, {"agreed_at": "2026-02-30T00:00:00Z"}, {"agreed_at": "2026-10-08T24:00:00Z"},
                {"agreed_at": "2026-10-08T00:00:00Z\n"}):
        try:
            build(dict(params, **bad)); raise AssertionError("build accepted %r" % (bad,))
        except SystemExit:
            pass
    n += 1; print("[6] pinned contract_id, nonce and agreed_at: two builds of the same params are byte-identical; --pins-from an earlier draft keeps its three values and takes the current wording; malformed pins (not hex, Feb 30, hour 24, trailing newline) are refused")
    # [7] admission, the applicant's side: the contractor asks, and its execution names the relying party's answer
    import admission_verify_v0 as A
    import settle_v1_11 as v111
    p7 = dict(params, requirements={"evidence": "nenrin_required", "recovery": "n/a", "admission": "required_before_execution"},
              contract_id="7" * 32, nonce="8" * 32, agreed_at="2026-10-10T00:00:00Z")
    c7 = build(p7); sign(c7, os.path.join(t, "a.pem"), "a.example"); sign(c7, os.path.join(t, "b.pem"), "b.example")
    assert v0.verify_contract(c7)["verdict"] == "accepted" and v111.admission_required(c7) and not v111.admission_required(c)
    rq = make_request(c7, os.path.join(t, "b.pem"), "read", 970500, target="/invoices")
    assert A.request_shape_ok(rq) and A.request_signed(c7, rq) and rq["action_binding"]["digest"]["value"] == A.action_digest(contract_sha256(c7), rq)
    try:
        make_request(c7, os.path.join(t, "a.pem"), "read", 970500); raise AssertionError("accepted what it must refuse")
    except SystemExit:
        pass
    # an admission some relying party signed, taken from the fixture: it is for other terms, so it cannot stand for this contract
    contracts, cases, fkeys = v111.load_fixture()
    foreign = {k: v for k, v in cases["v11/read"]["admissions"][0].items() if k != "anchor"}
    assert A.verify_admission(foreign, fkeys["shop.example"], contracts["admission_plain"])["verdict"] == "accepted"
    assert A.verify_admission(foreign, fkeys["shop.example"], c7)["refusals"] == ["other_contract"]
    e7 = make_exec(c7, os.path.join(t, "b.pem"), ["read"], "7" * 64, admitted=[(rq, foreign)])
    assert e7["admission_ref"] == [{"action": "read", "admission_sha256": A.admission_sha256(foreign),
                                    "executed": {"action": "read", "target": "/invoices", "amount": None, "nonce": rq["nonce"], "expiry_height": 970500}}]
    with v111._exec_field("admission_ref"):
        assert v12.authenticate(e7, c7) is None
    anchored = lambda rec, h: dict(rec, anchor={"height": h})
    named = [d["clause"] for d in v111.admission_deviations(c7, [anchored(e7, 970010)], [anchored(foreign, 970005)], fkeys)[0]]
    bare = [d["clause"] for d in v111.admission_deviations(c7, [anchored(make_exec(c7, os.path.join(t, "b.pem"), ["read"], "5" * 64), 970010)], [], fkeys)[0]]
    assert (named, bare) == (["unadmitted_execution"], ["unadmitted_execution"]), (named, bare)
    n += 1; print("[7] admission, the applicant's side: the contractor's signed request and its action digest; a principal-signed request is refused; the execution names the admission "
                  "by admission_sha256; an admission for other terms, or none, leaves the execution unadmitted under settle v1.11 (the admitted paths are in settle_v1_11.py and settle_v1_12.py's self tests)")
    print("ALL PASS (peer_kit: %d checks)" % n)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["selftest", "keygen", "contract", "sign", "verify", "approve", "exec", "stampable", "anchor", "settle", "request"])
    ap.add_argument("--out"); ap.add_argument("--params"); ap.add_argument("--contract"); ap.add_argument("--key"); ap.add_argument("--domain")
    ap.add_argument("--actions"); ap.add_argument("--nenrin-ref"); ap.add_argument("--record"); ap.add_argument("--ots")
    ap.add_argument("--view", action="append", default=[]); ap.add_argument("--event", action="append", default=[])
    ap.add_argument("--name"); ap.add_argument("--action"); ap.add_argument("--valid-until", type=int)
    ap.add_argument("--approval", action="append", default=[])
    ap.add_argument("--pins-from"); ap.add_argument("--expect")
    ap.add_argument("--nenrin", action="append", default=[])   # settle: NENRIN records, passed through to settle_v1_10
    # admission (a2a-admission-v0): request, and the admission named by an execution and read by settle v1.11 and v1.12
    ap.add_argument("--request", action="append", default=[]); ap.add_argument("--admission", action="append", default=[])
    ap.add_argument("--target"); ap.add_argument("--amount", type=int); ap.add_argument("--relying-key", action="append", default=[])
    a = ap.parse_args()
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    wr = lambda obj: open(a.out, "w", encoding="utf-8", newline="").write(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
    if a.cmd == "selftest":
        _selftest(); return 0
    if a.cmd == "keygen":
        print(json.dumps({"private_key_file": a.out, "public_key_ed25519_b64": keygen(a.out),
                          "next": "publish the public key at your key_url; keep the PEM on this machine"}, indent=2)); return 0
    if a.cmd == "contract":
        params = rd(a.params)
        if a.pins_from:
            params = dict(params, **pins_from(rd(a.pins_from)))
        c = build(params); sha = contract_sha256(c)
        if a.expect and a.expect != sha:
            print(json.dumps({"contract_sha256": sha, "expected": a.expect, "match": False, "pins": pins_from(c)}))
            return 2
        wr(c); out = {"wrote": a.out, "contract_sha256": sha, "pins": pins_from(c)}
        if a.expect:
            out["match"] = True
        print(json.dumps(out))
        return 0
    if a.cmd == "sign":
        c = sign(rd(a.contract), a.key, a.domain); wr(c); print(json.dumps({"wrote": a.out, "signatures": len(c["signatures"])})); return 0
    if a.cmd == "verify":
        print(json.dumps(v0.verify_contract(rd(a.contract)), indent=2)); return 0
    if a.cmd == "approve":
        e = approve(rd(a.contract), a.key, a.name, a.action, a.valid_until); wr(e); print(json.dumps({"wrote": a.out})); return 0
    if a.cmd == "exec":
        if len(a.request) != len(a.admission):
            raise SystemExit("give one --request for each --admission, in the same order")
        e = make_exec(rd(a.contract), a.key, [x for x in a.actions.split(",") if x], a.nenrin_ref, [rd(x) for x in a.approval],
                      admitted=[(rd(q), rd(m)) for q, m in zip(a.request, a.admission)]); wr(e)
        print(json.dumps({"wrote": a.out})); return 0
    if a.cmd == "request":
        q = make_request(rd(a.contract), a.key, a.action, a.valid_until, target=a.target, amount=a.amount, approvals=[rd(x) for x in a.approval]); wr(q)
        print(json.dumps({"wrote": a.out, "action_binding_digest": q["action_binding"]["digest"]["value"], "nonce": q["nonce"]})); return 0
    if a.cmd == "stampable":
        sys.argv = ["anchor_direct.py", "--stampable", a.record, "--out", a.out]; return ad.main()
    if a.cmd == "anchor":
        sys.argv = ["anchor_direct.py", "--record", a.record, "--ots", a.ots, "--contract", a.contract, "--view", a.view[0], "--out", a.out]
        return ad.main()
    if a.cmd == "settle":
        import settle_v1_10 as v19
        # 2026-10-09 (kuangmi-bit, #31): --out and --nenrin were not passed through, so `settle ... --out f` printed the
        # settlement and wrote no file. Every option settle_v1_10 takes is now forwarded.
        common = (sum((["--event", x] for x in a.event), []) + sum((["--view", x] for x in a.view), [])
                  + sum((["--nenrin", x] for x in a.nenrin), []) + (["--out", a.out] if a.out else []))
        import settle_v1_11 as v111
        import settle_v1_12 as v112
        if a.admission or a.relying_key or v111.admission_required(rd(a.contract)) or v112.has_limits(rd(a.contract)):
            # a contract that requires admission settles under v1.11, and under v1.12 when its grant carries limits; for any
            # other contract v1.12 returns v1.11's bytes, and v1.11 returns v1.10's
            sys.argv = (["settle_v1_12.py", "--settle", a.contract] + common + sum((["--admission", x] for x in a.admission), [])
                        + sum((["--relying-key", x] for x in a.relying_key), []))
            return v112.main()
        sys.argv = ["settle_v1_10.py", "--settle", a.contract] + common
        return v19.main()
    return 1


if __name__ == "__main__":
    sys.exit(main())
