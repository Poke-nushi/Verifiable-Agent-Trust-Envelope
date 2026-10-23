#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI anchor_compose: build the settle anchor of a record that the ledger stamped inside a batch.

Why this file exists. settle v1.1 and up accept a record's anchor only as a proof: a list of append,
prepend, sha256 and hexlify operations that takes sha256(canonical(record without "anchor")) to the
merkle root serialized in the header at the claimed height. Real records never reach Bitcoin alone.
The NENRIN ledger lists each accepted record by its hex sha inside a batch, stamps the batch bytes with
OpenTimestamps, and the calendars aggregate that stamp into a Bitcoin transaction. So a real proof has
three legs, and until 2026-09-29 nothing joined them, which meant no real anchored record could be
settled (the synthetic self tests built their own merkle trees and never met this):

  1. record -> batch     hexlify the 32 byte digest, prepend the batch bytes before it, append the
                         bytes after it, sha256. The result is the batch sha (the ledger claim_sha256).
                         Acceptance is structural: the batch must parse as strict JSON with a known
                         schema, and the record must be exactly one records[i] (same kind and schema
                         where the batch types its entries, count equal to len(records)). A sha that
                         appears anywhere else is not a listing. batch_leg_check applies the same rule
                         to a proof a verifier is handed.
  2. batch -> Bitcoin    the operations of the .ots file the ledger serves for that entry, read here
                         without any library, from the file digest to a Bitcoin block header
                         attestation. Only the four operations settle runs are accepted; a path that
                         needs any other operation is refused by name, never approximated.
  3. Bitcoin -> header   the result must equal bytes 36..68 of the 80 byte header at the attested
                         height in a header view that settle_v1_1.verify_view accepts under the
                         contract's rules. The anchor carries that header's hash.

What this does not do: it does not fetch anything, does not verify record signatures (the settle
layers do), and does not upgrade a pending .ots (run `ots upgrade`, or wait for the ledger's stamping
job). A pending stamp is reported as pending with the calendars it waits on, never as an anchor.

Usage:
  anchor_compose.py --selftest
  anchor_compose.py --record REC.json --batch ENTRY.raw --ots ENTRY.ots --contract C.json --view V.json --out REC.anchored.json
"""
import argparse, hashlib, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import settle_v1_1 as v11
from contract_v0 import canonical, parse_strict

OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
UNARY = {0x08: "sha256", 0xf3: "hexlify", 0x02: "sha1", 0x03: "ripemd160", 0xf2: "reverse", 0x67: "keccak256"}
BINARY = {0xf0: "append", 0xf1: "prepend"}
SETTLE_OPS = {"sha256", "hexlify", "append", "prepend"}
MAX_DEPTH = 256
CHUNK = v11.MAX_OPERAND


class Refused(Exception):
    def __init__(self, code, detail=""):
        super().__init__("%s: %s" % (code, detail))
        self.code, self.detail = code, detail


# --------------------------------------------------------------------------- OpenTimestamps reader
class _R:
    def __init__(self, b):
        self.b, self.i = b, 0

    def byte(self):
        if self.i >= len(self.b):
            raise Refused("ots_truncated", "file ends inside the proof")
        self.i += 1
        return self.b[self.i - 1]

    def take(self, n):
        if self.i + n > len(self.b):
            raise Refused("ots_truncated", "file ends inside the proof")
        self.i += n
        return self.b[self.i - n:self.i]

    def varuint(self):
        v, shift = 0, 0
        while True:
            c = self.byte()
            v |= (c & 0x7f) << shift
            if not c & 0x80:
                return v
            shift += 7
            if shift > 63:
                raise Refused("ots_malformed", "varuint too long")

    def varbytes(self, maxlen):
        n = self.varuint()
        if n > maxlen:
            raise Refused("ots_malformed", "operand of %d bytes over the %d byte limit" % (n, maxlen))
        return self.take(n)


def _apply(name, arg, msg):
    if name == "sha256":
        return hashlib.sha256(msg).digest()
    if name == "hexlify":
        return msg.hex().encode("ascii")
    if name == "append":
        return msg + arg
    if name == "prepend":
        return arg + msg
    if name == "sha1":
        return hashlib.sha1(msg).digest()
    if name == "reverse":
        return msg[::-1]
    if name == "ripemd160":
        try:
            return hashlib.new("ripemd160", msg).digest()
        except ValueError:
            return None                              # followed only to keep reading; never part of an anchor
    return None                                      # keccak256: not in hashlib; the branch is unusable here


def _timestamp(r, msg, path, out, depth):
    """Read one timestamp node. out collects {"kind", "height"|"uri", "ops", "msg"} per attestation."""
    if depth > MAX_DEPTH:
        raise Refused("ots_malformed", "proof deeper than %d" % MAX_DEPTH)

    def one(tag):
        if tag == 0x00:
            atag = r.take(8)
            payload = r.varbytes(8192)
            item = {"ops": list(path), "msg": msg}
            if atag == TAG_BITCOIN:
                pr = _R(payload)
                item.update(kind="bitcoin", height=pr.varuint())
                if pr.i != len(payload):
                    raise Refused("ots_malformed", "bitcoin attestation payload has trailing bytes")
            elif atag == TAG_PENDING:
                pr = _R(payload)
                item.update(kind="pending", uri=pr.varbytes(1000).decode("ascii", "replace"))
            else:
                item.update(kind="other", tag=atag.hex())
            out.append(item)
            return
        if tag in UNARY:
            name, arg = UNARY[tag], None
        elif tag in BINARY:
            name, arg = BINARY[tag], r.varbytes(4096)
        else:
            raise Refused("ots_malformed", "unknown operation tag 0x%02x" % tag)
        nxt = _apply(name, arg, msg) if msg is not None else None
        if nxt is not None and len(nxt) > 4096:
            raise Refused("ots_malformed", "intermediate result over 4096 bytes")
        _timestamp(r, nxt, path + [(name, arg)], out, depth + 1)

    tag = r.byte()
    while tag == 0xff:
        one(r.byte())
        tag = r.byte()
    one(tag)


def read_ots(data):
    """Parse a detached .ots file. Returns (file_digest, attestations)."""
    r = _R(data)
    if r.take(len(OTS_MAGIC)) != OTS_MAGIC:
        raise Refused("ots_not_detached_timestamp", "missing the OpenTimestamps header magic")
    if r.varuint() != 1:
        raise Refused("ots_malformed", "unsupported major version")
    if r.byte() != 0x08:
        raise Refused("ots_file_hash_not_sha256", "only sha256 file digests are read")
    digest = r.take(32)
    out = []
    _timestamp(r, digest, [], out, 0)
    if r.i != len(data):
        raise Refused("ots_trailing_bytes", "%d bytes after the proof" % (len(data) - r.i))
    return digest, out


# --------------------------------------------------------------------------- the three legs
# Leg 1 acceptance lives in the parse, not in a byte search (2026-09-30, reported by babyblueviper1 in
# horizon-shield#25). A batch lists the records its intake ACCEPTED in records[]; a sha that appears anywhere else
# (a rejection list, a supersession pointer, a log line) is not a listing. So the batch is parsed as strict JSON,
# its schema must be one this file knows, the record must be exactly one records[i] with sha == hex(digest) and,
# where the batch types its entries, the same kind and schema as the record itself; count must equal
# len(records). Only then are the raw bytes of THAT member located to cut the prefix and suffix.
BATCH_RULES = {
    "nenrin-agreement-batch-v1": {"typed": True},
    "nenrin-witness-batch-v1": {"typed": False},
    "nenrin-trace-pin-batch-v0": {"typed": False},
}
RECORD_KIND = {"a2a-execution-v0": "execution", "a2a-contract-v0": "contract",
               "a2a-agreement-v1.1": "agreement", "a2a-agreement-v1": "agreement"}


def _json_positions(text, want):
    """Character span of the string value at path `want` (a tuple of keys and indexes) in valid JSON text."""
    ws = " \t\n\r"
    found = []

    def skip(i):
        while i < len(text) and text[i] in ws:
            i += 1
        return i

    def string_end(i):                      # i at the opening quote; returns index just past the closing quote
        i += 1
        while text[i] != '"':
            i += 2 if text[i] == "\\" else 1
        return i + 1

    def value(i, path):
        i = skip(i)
        c = text[i]
        if c == "{":
            i = skip(i + 1)
            if text[i] == "}":
                return i + 1
            while True:
                i = skip(i)
                k_end = string_end(i)
                key = json.loads(text[i:k_end])
                i = skip(k_end)
                i = value(i + 1, path + (key,))  # past ':'
                i = skip(i)
                if text[i] == ",":
                    i += 1
                    continue
                return i + 1                      # '}'
        if c == "[":
            i = skip(i + 1)
            if text[i] == "]":
                return i + 1
            n = 0
            while True:
                i = value(i, path + (n,))
                i = skip(i)
                n += 1
                if text[i] == ",":
                    i += 1
                    continue
                return i + 1                      # ']'
        if c == '"':
            e = string_end(i)
            if path == want:
                found.append((i + 1, e - 1))
            return e
        j = i
        while j < len(text) and text[j] not in ",]}" + ws:
            j += 1
        return j

    value(0, ())
    return found


def batch_ops(digest, batch, record=None):
    """Leg 1. Ops taking digest to sha256(batch), after the batch has been shown to list the record in records[]."""
    hx = digest.hex()
    try:
        text = batch.decode("utf-8")
        parsed = parse_strict(text)
    except Exception as e:                   # not UTF-8, not JSON, duplicate keys, too deep
        raise Refused("batch_not_json", "the batch bytes are not strict JSON (%s)" % type(e).__name__)
    if not isinstance(parsed, dict) or parsed.get("schema") not in BATCH_RULES:
        raise Refused("batch_schema_unknown", "batch schema %r is not one this composer reads" % (parsed.get("schema") if isinstance(parsed, dict) else None))
    rule = BATCH_RULES[parsed["schema"]]
    recs = parsed.get("records")
    if not isinstance(recs, list) or not all(isinstance(r, dict) for r in recs):
        raise Refused("batch_schema_unknown", "records must be a list of objects")
    if "count" in parsed and parsed["count"] != len(recs):
        raise Refused("batch_count_mismatch", "count %r but %d records" % (parsed["count"], len(recs)))
    hits = [i for i, r in enumerate(recs) if r.get("sha") == hx]
    if not hits:
        raise Refused("record_not_listed_in_batch",
                      "canonical digest %s is not the sha of any entry in records[] (a sha elsewhere in the batch is not a listing; "
                      "if the batch lists sha256 of the served bytes, those bytes are not canonical(record))" % hx)
    if len(hits) > 1:
        raise Refused("record_listed_twice", "records[] lists %s %d times" % (hx, len(hits)))
    idx = hits[0]
    entry = recs[idx]
    if rule["typed"]:
        rschema = record.get("schema") if isinstance(record, dict) else None
        kind = RECORD_KIND.get(rschema)
        if kind is None:
            raise Refused("record_kind_unknown", "record schema %r has no kind this batch type lists" % rschema)
        if entry.get("kind") != kind:
            raise Refused("record_kind_mismatch", "records[%d] is listed as kind %r, the record is %r" % (idx, entry.get("kind"), kind))
        if "schema" in entry and entry.get("schema") != rschema:
            raise Refused("record_schema_mismatch", "records[%d] is listed with schema %r, the record is %r" % (idx, entry.get("schema"), rschema))
    spans = _json_positions(text, ("records", idx, "sha"))
    if len(spans) != 1 or text[spans[0][0]:spans[0][1]] != hx:
        raise Refused("internal", "records[%d].sha could not be located in the raw bytes" % idx)
    a, b = spans[0]
    at = len(text[:a].encode("utf-8"))
    end = at + len(hx)
    prefix, suffix = batch[:at], batch[end:]
    ops = [{"op": "hexlify"}]
    chunks = [prefix[i:i + CHUNK] for i in range(0, len(prefix), CHUNK)]
    for c in reversed(chunks):
        ops.append({"op": "prepend", "hex": c.hex()})
    for i in range(0, len(suffix), CHUNK):
        ops.append({"op": "append", "hex": suffix[i:i + CHUNK].hex()})
    ops.append({"op": "sha256"})
    return ops, at


def batch_leg_check(record, proof):
    """For a verifier. If a proof starts with hexlify, it claims the record is listed inside a batch: rebuild the
    batch bytes from its prepend and append operands (up to the first sha256) and require that the digest sits
    exactly at records[i].sha of a batch this file reads, with the same checks as batch_ops. Returns (ok, reason).
    A proof that does not start with hexlify commits the digest directly (a merkle path) and is not a batch leg."""
    if not (isinstance(proof, list) and proof and isinstance(proof[0], dict) and proof[0].get("op") == "hexlify"):
        return True, "no_batch_leg"
    d = v11.commitment_digest(record)
    pre, suf = b"", b""
    for op in proof[1:]:
        k = op.get("op")
        if k == "sha256":
            break
        if k not in ("append", "prepend"):
            return False, "batch_leg_malformed"
        b = bytes.fromhex(op.get("hex", ""))
        if k == "prepend":
            pre = b + pre
        else:
            suf = suf + b
    else:
        return False, "batch_leg_malformed"
    batch = pre + d.hex().encode("ascii") + suf
    try:
        _, at = batch_ops(d, batch, record)
    except Refused as e:
        return False, e.code
    if at != len(pre):
        return False, "batch_leg_splice_not_at_listing"
    return True, "listed_in_records"


def ots_ops(att):
    """Leg 2. The attestation's path as settle ops, refusing anything settle does not run."""
    ops = []
    for name, arg in att["ops"]:
        if name not in SETTLE_OPS:
            raise Refused("ots_path_needs_unsupported_op",
                          "the path to block %s uses %s, which settle does not run" % (att.get("height"), name))
        ops.append({"op": name, "hex": arg.hex()} if arg is not None else {"op": name})
    return ops


def compose(record, batch, ots, contract, view):
    """Returns {"status": "anchored", "anchor": {...}, ...} or {"status": "pending", ...}. Raises Refused."""
    if not isinstance(record, dict):
        raise Refused("record_not_object")
    d = v11.commitment_digest(record)
    ops1, offset = batch_ops(d, batch, record)
    claim = hashlib.sha256(batch).digest()
    if v11.run_proof(d, ops1) != claim:
        raise Refused("internal", "leg 1 does not reproduce the batch sha")
    fdig, atts = read_ots(ots)
    if fdig != claim:
        raise Refused("ots_for_other_bytes", "the .ots stamps %s, the batch bytes hash to %s" % (fdig.hex(), claim.hex()))
    btc = sorted([a for a in atts if a["kind"] == "bitcoin"], key=lambda a: a["height"])
    base = {"record_digest": d.hex(), "batch_sha256": claim.hex(), "listed_at_offset": offset}
    if not btc:
        return dict(base, status="pending",
                    waiting_on=sorted({a["uri"] for a in atts if a["kind"] == "pending"}),
                    detail="no Bitcoin attestation in this .ots yet; upgrade it (ots upgrade, or the ledger's stamping job) and run again")
    cv, problem = v11.verify_view(view, contract)
    if cv is None:
        raise Refused("view_rejected", problem)
    tried = []
    for a in btc:
        h = a["height"]
        if h not in cv["hashes"]:
            tried.append({"height": h, "why": "not in the view (view covers %d..%d)" % (min(cv["hashes"]), cv["tip"])})
            continue
        proof = ops1 + ots_ops(a)
        if len(proof) > v11.MAX_PROOF_OPS:
            raise Refused("proof_too_long", "%d ops over %d" % (len(proof), v11.MAX_PROOF_OPS))
        if v11.run_proof(d, proof) != cv["merkle"][h]:
            tried.append({"height": h, "why": "the path does not reach the merkle root of the header at this height"})
            continue
        return dict(base, status="anchored", anchor={"height": h, "block_hash": cv["hashes"][h], "proof": proof},
                    proof_ops=len(proof), other_attestations=[x["height"] for x in btc if x is not a])
    raise Refused("no_attestation_verifies", json.dumps(tried))


def anchored_record(record, anchor):
    r = {k: v for k, v in record.items() if k != "anchor"}
    r["anchor"] = anchor
    return r


# --------------------------------------------------------------------------- self test
def _vu(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _vb(b):
    return _vu(len(b)) + b


def _ser(node):
    """Serialize a synthetic tree: node = [edge, ...]; edge = ("att", kind, value) | (tag, arg, child)."""
    def edge(e):
        if e[0] == "att":
            if e[1] == "bitcoin":
                return b"\x00" + TAG_BITCOIN + _vb(_vu(e[2]))
            return b"\x00" + TAG_PENDING + _vb(_vb(e[2].encode()))
        tag, arg, child = e
        return bytes([tag]) + (_vb(arg) if arg is not None else b"") + _ser(child)
    return b"".join(b"\xff" + edge(e) for e in node[:-1]) + edge(node[-1])


def _run(node, msg):
    """Follow the synthetic tree to its Bitcoin leaf and return the message there."""
    for e in node:
        if e[0] == "att":
            if e[1] == "bitcoin":
                return msg
            continue
        tag, arg, child = e
        name = UNARY.get(tag) or BINARY.get(tag)
        got = _run(child, _apply(name, arg, msg))
        if got is not None:
            return got
    return None


def _selftest():
    here = os.path.dirname(os.path.abspath(__file__))
    n = 0
    rec = {"schema": "a2a-execution-v0", "contract_id": "0123456789abcdef0123456789abcdef", "actions": ["read"],
           "note": "anchor_compose self test"}
    d = v11.commitment_digest(rec)
    other = hashlib.sha256(b"another record").hexdigest()

    def batch_for(listed, extra=""):
        return canonical({"schema": "nenrin-agreement-batch-v1", "records": [
            {"sha": other, "kind": "agreement"},
            {"sha": listed, "kind": "execution", "bytes_url": "https://example.test/execution/" + listed}],
            "note": "self test" + extra}).encode()

    batch = batch_for(d.hex())
    claim = hashlib.sha256(batch).digest()

    # a calendar-like path with a pending branch, then a transaction and a two level block merkle path
    tx_pre, tx_suf = bytes.fromhex("0100000001" + "11" * 36 + "ff") + b"\x6a\x20", bytes.fromhex("00000000")
    sib1, sib2 = hashlib.sha256(b"s1").digest(), hashlib.sha256(b"s2").digest()
    def tree_at(height):
        leg = [(0x08, None, [(0xf1, tx_pre, [(0xf0, tx_suf, [(0x08, None, [(0x08, None, [
            (0xf0, sib1, [(0x08, None, [(0x08, None, [(0xf1, sib2, [(0x08, None, [(0x08, None, [
                ("att", "bitcoin", height)])])])])])])])])])])])]
        return [(0xf0, b"calendar-nonce", [(0x08, None, [("att", "pending", "https://a.example/cal"),
                                                         (0xf1, b"agg", [(0x08, None, leg)])])])]
    tree = tree_at(101)
    root = _run(tree, claim)
    assert root is not None and len(root) == 32

    def view_with(merkle_root, bits=v11.REGTEST_BITS, at102=None):
        headers, prev = [], "00" * 32
        for h, m in ((99, hashlib.sha256(b"h99").digest()), (100, hashlib.sha256(b"h100").digest()), (101, merkle_root),
                     (102, at102 or hashlib.sha256(b"h102").digest())):
            raw = v11._mine(prev, m, bits=bits, salt=h)
            headers.append({"height": h, "hex": raw.hex()})
            prev = v11.header_hash(raw)
        return {"headers": headers}

    view = view_with(root)
    ck = {"kind": "bitcoin_block", "height": 100, "hash": v11.header_hash(bytes.fromhex(view["headers"][1]["hex"]))}
    contract = {"lower_bound": ck, "grant": {"finality": {"depth": 1, "max_target_bits": "207fffff"}}}
    ots = OTS_MAGIC + _vu(1) + b"\x08" + claim + _ser(tree)

    def refused(fn):
        try:
            fn(); return None
        except Refused as e:
            return e.code

    # [1] leg 1 alone reproduces the batch sha, and the chosen occurrence is the "sha" member, not the URL
    ops1, off = batch_ops(d, batch, rec)
    assert v11.run_proof(d, ops1) == claim and batch[off - 7:off] == b'"sha":"'
    assert batch.count(d.hex().encode()) == 2
    n += 1; print("[1] record -> batch: hexlify, prepend, append, sha256 gives the batch sha; the hex also sits in a URL, the proof uses the \"sha\" member")

    # [2] end to end: the composed anchor passes the exact check settle runs
    res = compose(rec, batch, ots, contract, view)
    a = res["anchor"]
    cv, _ = v11.verify_view(view, contract)
    ar = anchored_record(rec, a)
    assert res["status"] == "anchored" and a["height"] == 101 and a["block_hash"] == cv["hashes"][101]
    assert v11.run_proof(v11.commitment_digest(ar), a["proof"]) == cv["merkle"][101]
    n += 1; print("[2] record -> batch -> .ots -> header 101: settle's own check passes (%d ops)" % res["proof_ops"])

    # [3] a changed record no longer reaches the header with the same anchor
    bad = dict(ar); bad["actions"] = ["read", "write"]
    assert v11.run_proof(v11.commitment_digest(bad), a["proof"]) != cv["merkle"][101]
    n += 1; print("[3] one changed field in the record: the same anchor stops at a different root")

    # [4] refusals, each by name
    cases = {
        "record_not_listed_in_batch": lambda: compose(rec, batch_for(other), ots, contract, view),
        "record_listed_twice": lambda: compose(rec, canonical({"schema": "nenrin-agreement-batch-v1", "records": [{"sha": d.hex(), "kind": "execution"}, {"sha": d.hex(), "kind": "execution"}]}).encode(), ots, contract, view),
        "ots_for_other_bytes": lambda: compose(rec, batch_for(d.hex(), " changed"), ots, contract, view),
        "ots_trailing_bytes": lambda: compose(rec, batch, ots + b"\x00", contract, view),
        "ots_truncated": lambda: compose(rec, batch, ots[:-3], contract, view),
        "ots_not_detached_timestamp": lambda: compose(rec, batch, b"x" + ots[1:], contract, view),
        "view_rejected": lambda: compose(rec, batch, ots, contract, {"headers": view["headers"][2:]}),
        "no_attestation_verifies": lambda: compose(rec, batch, ots, contract, view_with(hashlib.sha256(b"x").digest())),
    }
    for code, fn in cases.items():
        got = refused(fn)
        assert got == code, (code, got)
    only_url = canonical({"schema": "nenrin-agreement-batch-v1", "records": [{"sha": other, "kind": "agreement", "url": "https://x.test/" + d.hex()}]}).encode()
    assert refused(lambda: batch_ops(d, only_url, rec)) == "record_not_listed_in_batch"
    n += 1; print("[4] refused by name: %s, and a hex that appears only in a URL" % ", ".join(sorted(cases)))

    # [5] a path that needs an operation settle does not run is refused, not approximated
    rev_tree = [(0xf2, None, [(0x08, None, [("att", "bitcoin", 101)])])]
    rev_ots = OTS_MAGIC + _vu(1) + b"\x08" + claim + _ser(rev_tree)
    rev_root = _run(rev_tree, claim)
    assert refused(lambda: compose(rec, batch, rev_ots, contract, view_with(rev_root))) == "ots_path_needs_unsupported_op"
    n += 1; print("[5] a Bitcoin path through reverse (an OpenTimestamps op settle does not run): ots_path_needs_unsupported_op")

    # [6] pending only: reported as pending with the calendar, no anchor
    pend = OTS_MAGIC + _vu(1) + b"\x08" + claim + _ser([(0xf0, b"n", [(0x08, None, [("att", "pending", "https://b.example")])])])
    p = compose(rec, batch, pend, contract, view)
    assert p["status"] == "pending" and p["waiting_on"] == ["https://b.example"] and "anchor" not in p
    n += 1; print("[6] a stamp still waiting on its calendar: status pending, waiting_on named, no anchor")

    # [7] a batch far over one operand: prefix and suffix are split into operands settle accepts
    big = canonical({"schema": "nenrin-witness-batch-v1", "records": [{"sha": other, "pad": "p" * 9000}, {"sha": d.hex()}], "tail": "t" * 5000}).encode()
    bops, _ = batch_ops(d, big)
    assert v11.run_proof(d, bops) == hashlib.sha256(big).digest()
    assert all(len(o.get("hex", "")) // 2 <= v11.MAX_OPERAND for o in bops) and sum(o["op"] == "prepend" for o in bops) >= 3
    n += 1; print("[7] a %d byte batch: %d operands, each at most %d bytes, still reaches the batch sha" % (len(big), len(bops) - 2, v11.MAX_OPERAND))

    # [7b] two calendars confirmed in different blocks: the lower height is used (the tighter upper bound)
    later = [(0xf0, b"late", [(0x08, None, [("att", "bitcoin", 102)])])]
    two = OTS_MAGIC + _vu(1) + b"\x08" + claim + _ser(later + tree)
    r2 = compose(rec, batch, two, contract, view_with(root, at102=_run(later, claim)))
    assert r2["anchor"]["height"] == 101 and r2["other_attestations"] == [102]
    n += 1; print("[7b] attestations at 102 and 101 both verify: the anchor uses 101 and lists 102")

    # [10] leg 1 acceptance is structural (horizon-shield#25, babyblueviper1): only records[] is a listing
    def vec(obj):
        return canonical(obj).encode()
    good = {"schema": "nenrin-agreement-batch-v1", "count": 2, "records": [{"sha": other, "kind": "agreement"}, {"sha": d.hex(), "kind": "execution", "schema": "a2a-execution-v0"}]}
    vectors = [
        ("under a rejected list, removed from records", {"schema": "nenrin-agreement-batch-v1", "count": 1, "records": [{"sha": other, "kind": "agreement"}], "rejected": [{"sha": d.hex()}]}, "record_not_listed_in_batch"),
        ("under a supersedes pointer", {"schema": "nenrin-agreement-batch-v1", "count": 1, "records": [{"sha": other, "kind": "agreement"}], "supersedes": {"sha": d.hex()}}, "record_not_listed_in_batch"),
        ("listed with kind agreement", {"schema": "nenrin-agreement-batch-v1", "count": 1, "records": [{"sha": d.hex(), "kind": "agreement"}]}, "record_kind_mismatch"),
        ("listed with another schema", {"schema": "nenrin-agreement-batch-v1", "count": 1, "records": [{"sha": d.hex(), "kind": "execution", "schema": "a2a-contract-v0"}]}, "record_schema_mismatch"),
        ("count disagrees with records", dict(good, count=3), "batch_count_mismatch"),
        ("unknown batch schema", dict(good, schema="nenrin-rejections-v1"), "batch_schema_unknown"),
    ]
    for name, obj, code in vectors:
        assert refused(lambda: batch_ops(d, vec(obj), rec)) == code, (name, refused(lambda: batch_ops(d, vec(obj), rec)))
    log = b'2026-09-30 intake note "sha":"' + d.hex().encode() + b'" rejected'
    assert refused(lambda: batch_ops(d, log, rec)) == "batch_not_json"
    dup = b'{"schema":"nenrin-agreement-batch-v1","records":[{"sha":"' + d.hex().encode() + b'","kind":"execution","kind":"execution"}]}'
    assert refused(lambda: batch_ops(d, dup, rec)) == "batch_not_json"
    both = vec(dict(good, rejected=[{"sha": d.hex()}]))            # listed AND rejected: the proof cuts at records[1].sha
    bops2, at2 = batch_ops(d, both, rec)
    assert both[at2 - 7:at2] == b'"sha":"' and both.index(b'"records"') < at2 < both.index(b'"rejected"') and v11.run_proof(d, bops2) == hashlib.sha256(both).digest()
    # a verifier-side check: a hand-built proof that splices the digest into the rejected entry is refused
    rej_at = both.index(d.hex().encode(), both.index(b'"rejected"'))
    forged = [{"op": "hexlify"}, {"op": "prepend", "hex": both[:rej_at].hex()}, {"op": "append", "hex": both[rej_at + 64:].hex()}, {"op": "sha256"}]
    assert v11.run_proof(d, forged) == hashlib.sha256(both).digest()                    # the bytes path alone accepts it
    assert batch_leg_check(rec, forged) == (False, "batch_leg_splice_not_at_listing")
    assert batch_leg_check(rec, bops2) == (True, "listed_in_records")
    n += 1; print("[10] leg 1 is structural: rejected list, supersedes, log line, kind, schema, count, unknown schema, duplicate keys refused by name; "
                  "listed and rejected at once cuts at records[]; a hand spliced proof into the rejected entry passes the bytes path but fails batch_leg_check")
    rr = os.path.join(here, "run0002")
    if os.path.exists(os.path.join(rr, "entry63.raw")):
        e63 = open(os.path.join(rr, "entry63.raw"), "rb").read()
        ex = parse_strict(open(os.path.join(rr, "exec_19c44a79.json"), encoding="utf-8").read())
        dx = v11.commitment_digest(ex)
        j = parse_strict(e63.decode())
        ops63, _ = batch_ops(dx, e63, ex)
        assert v11.run_proof(dx, ops63) == hashlib.sha256(e63).digest()
        moved = dict(j); moved["records"] = [r for r in j["records"] if r["sha"] != dx.hex()]; moved["count"] = len(moved["records"]); moved["rejected"] = [{"sha": dx.hex()}]
        sup = dict(moved); sup.pop("rejected"); sup["supersedes"] = {"sha": dx.hex()}
        kinded = dict(j); kinded["records"] = [dict(r, kind="agreement") if r["sha"] == dx.hex() else r for r in j["records"]]
        real = [(json.dumps(moved, separators=(",", ":")).encode(), "record_not_listed_in_batch"),
                (json.dumps(sup, separators=(",", ":")).encode(), "record_not_listed_in_batch"),
                (b'intake log: "sha":"' + dx.hex().encode() + b'"', "batch_not_json"),
                (json.dumps(kinded, separators=(",", ":")).encode(), "record_kind_mismatch")]
        for bb, code in real:
            assert refused(lambda: batch_ops(dx, bb, ex)) == code, code
        n += 1; print("[10b] the reporter's table on the real entry 63 and execution 19c44a79: the control passes, the four crafted batches are refused")
    else:
        print("[10b] skipped: run0002/ not beside this file")

    # [10c] babyblueviper1's CC0 leg 1 vectors (fixtures/babyblueviper1_leg1, vendored byte for byte, sha pinned)
    fxd = os.path.join(here, "fixtures", "babyblueviper1_leg1")
    rx = os.path.join(here, "run0002", "exec_19c44a79.json")
    if os.path.exists(os.path.join(fxd, "leg1_vectors.json")) and os.path.exists(rx):
        raw_v = open(os.path.join(fxd, "leg1_vectors.json"), "rb").read()
        assert hashlib.sha256(raw_v).hexdigest() == "3f9408a0a6292196adf13a217be937139260a309c055227369195203f18e243d", "vendored vectors changed"
        fv = json.loads(raw_v)
        exr = parse_strict(open(rx, encoding="utf-8").read())
        dxr = v11.commitment_digest(exr)
        assert dxr.hex() == fv["record_digest_hex"]
        for vv in fv["vectors"]:
            bb = bytes.fromhex(vv["batch_hex"])
            assert hashlib.sha256(bb).hexdigest() == vv["batch_sha256"], vv["id"]
            got = refused(lambda: batch_ops(dxr, bb, exr))
            want = None if vv["expect"] == "accepted" else vv["reason"]
            assert got == want, (vv["id"], got, want)
            at = bb.find(dxr.hex().encode())
            if want is None:
                assert batch_leg_check(exr, batch_ops(dxr, bb, exr)[0]) == (True, "listed_in_records"), vv["id"]
            elif at >= 0:
                spliced = [{"op": "hexlify"}, {"op": "prepend", "hex": bb[:at].hex()}, {"op": "append", "hex": bb[at + 64:].hex()}, {"op": "sha256"}]
                assert v11.run_proof(dxr, spliced) == hashlib.sha256(bb).digest(), vv["id"]
                assert batch_leg_check(exr, spliced) == (False, want), (vv["id"], batch_leg_check(exr, spliced))
        n += 1; print("[10c] babyblueviper1's CC0 vectors (sha 3f9408a0, %d vectors from the real entry 63): batch_ops and batch_leg_check give the expected code for each" % len(fv["vectors"]))
    else:
        print("[10c] skipped: fixtures/babyblueviper1_leg1 or run0002/ not beside this file")

    # [8] bytes written by the OpenTimestamps reference library (fixture), read by this parser
    fx_path = os.path.join(here, "anchor_compose_fixture.json")
    if os.path.exists(fx_path):
        fx = json.load(open(fx_path, encoding="utf-8"))
        fd, atts = read_ots(bytes.fromhex(fx["ots_hex"]))
        btc = [x for x in atts if x["kind"] == "bitcoin"]
        assert fd.hex() == fx["file_digest"] and len(btc) == 1 and btc[0]["height"] == fx["height"]
        assert btc[0]["msg"].hex() == fx["msg_at_attestation"]
        assert sorted(x["uri"] for x in atts if x["kind"] == "pending") == fx["pending_uris"]
        assert [o["op"] for o in ots_ops(btc[0])] == fx["op_names"]
        n += 1; print("[8] a .ots written by python-opentimestamps %s: same digest, height %d, same ops and result" % (fx["library"], fx["height"]))
    else:
        print("[8] skipped: anchor_compose_fixture.json not present")

    # [9] end to end through settle v1.6: a signed execution, listed in a batch, stamped, confirmed, settles final
    import importlib.util
    if importlib.util.find_spec("cryptography") is not None:
        import base64, random
        import contract_v0 as v0
        import settle_v1_2 as v12
        import settle_v1_6 as v16
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        def newkey():
            k = Ed25519PrivateKey.generate()
            return k, base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        ka, pa = newkey(); kb, pb = newkey(); _, pw = newkey()
        chain = v11._Chain(90, "00" * 32, "e2e-%d" % random.randint(0, 1 << 30))
        for _ in range(8):
            chain.block()                                           # 90..97
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
            contract_id="0123456789abcdef0123456789abcdef", nonce="e" * 32, agreed_at="2026-09-29T00:00:00Z")
        v0.sign_contract(C, ka, pa, "gate.horizonshield.dev"); v0.sign_contract(C, kb, pb, "api.babyblueviper.com")
        ex = v12.sign_record({"schema": v0.EXEC_SCHEMA,
                              "contract_ref": {"contract_id": C["contract_id"], "payload_digest": "a" * 64, "contract_sha256": v0.contract_sha256(C)},
                              "performed_actions": ["read"], "approvals": [], "delegated_to": [], "nenrin_ref": "8" * 64}, kb, "contractor")
        ed = v11.commitment_digest(ex)
        eb = canonical({"schema": "nenrin-agreement-batch-v1", "records": [
            {"sha": ed.hex(), "kind": "execution", "bytes_url": "https://agreement.example/execution/" + ed.hex()},
            {"sha": other, "kind": "agreement"}]}).encode()
        eclaim = hashlib.sha256(eb).digest()
        eots = OTS_MAGIC + _vu(1) + b"\x08" + eclaim + _ser(tree_at(98))
        raw = v11._mine(chain.prev, _run(tree_at(98), eclaim), salt=98)
        chain.headers.append({"height": 98, "hex": raw.hex()}); chain.hashes[98] = v11.header_hash(raw); chain.prev = chain.hashes[98]
        for _ in range(4):
            chain.block()                                           # 99..102; depth 3 puts 98 under the horizon
        ev = compose(ex, eb, eots, C, chain.view())
        assert ev["status"] == "anchored" and ev["anchor"]["height"] == 98
        s = v16.settle_v1_6(C, [anchored_record(ex, ev["anchor"])], chain.view())
        assert s["verdict"] == "within_grant" and s["status"] == "final", (s["verdict"], s["status"], s.get("underspecified"))
        ex2 = v12.sign_record(dict({k: v for k, v in ex.items() if k != "signatures"}, performed_actions=["read", "delete"]), kb, "contractor")
        s2 = v16.settle_v1_6(C, [anchored_record(ex2, ev["anchor"])], chain.view())
        assert s2["verdict"] == "underspecified" and any(u.get("reason") == "anchor_proof_invalid" for u in s2["underspecified"]), s2["underspecified"]
        n += 1; print("[9] settle v1.6 on a signed execution anchored through batch -> .ots -> header 98: within_grant, final; "
                      "the same anchor on a re-signed execution that adds delete: anchor_proof_invalid, no verdict")
    else:
        print("[9] skipped: the cryptography package is not installed (settle v1.6 verifies signatures)")

    print("ALL PASS (anchor_compose: %d checks)" % n)


def main():
    ap = argparse.ArgumentParser(description="compose a settle anchor for a record stamped inside a NENRIN batch")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--record"); ap.add_argument("--batch"); ap.add_argument("--ots")
    ap.add_argument("--contract"); ap.add_argument("--view"); ap.add_argument("--out")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return 0
    if not all((a.record, a.batch, a.ots, a.contract, a.view)):
        ap.print_help(); return 1
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    raw = lambda p: open(p, "rb").read()
    record = rd(a.record)
    try:
        res = compose(record, raw(a.batch), raw(a.ots), rd(a.contract), rd(a.view))
    except Refused as e:
        print(json.dumps({"status": "refused", "reason": e.code, "detail": e.detail}, indent=2)); return 2
    shown = {k: v for k, v in res.items() if k != "anchor"}
    if res["status"] == "anchored":
        shown["anchor"] = {"height": res["anchor"]["height"], "block_hash": res["anchor"]["block_hash"]}
        if a.out:
            with open(a.out, "w", encoding="utf-8", newline="") as f:
                f.write(canonical(anchored_record(record, res["anchor"])))
            shown["wrote"] = a.out
    print(json.dumps(shown, indent=2))
    return 0 if res["status"] == "anchored" else 3


if __name__ == "__main__":
    sys.exit(main())
