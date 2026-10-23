#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI header_view_fetch: build the header view settle takes, from two public block explorers.

settle v1.1 and up take the chain as raw 80 byte headers and verify them (linkage, proof of work, the
grant's difficulty floor, the contract checkpoint). This fetches that view from contract.lower_bound
to the tip, so a settlement can be run without a Bitcoin node:

  - Each header is rebuilt from the explorer's fields (version, previous hash, merkle root, time,
    bits, nonce) and must hash to the block id the explorer gave. An explorer cannot hand over a
    header that does not match its own id.
  - Two explorers (blockstream.info and mempool.space, both Esplora APIs) are fetched independently
    and every rebuilt header must be byte identical. One lying explorer yields no view.
  - The result is checked with settle_v1_1.verify_view under the contract's own rules before it is
    written. Two colluding explorers could still serve a heavier fake chain only by doing the work,
    which is what verify_view measures.

Network use is this file's whole job, so run it where the explorers are reachable. Nothing is sent
except block heights.

  header_view_fetch.py --selftest
  header_view_fetch.py --contract C.json --out view.json [--to HEIGHT]
"""
import argparse, json, os, struct, sys, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import settle_v1_1 as v11
from contract_v0 import parse_strict

SOURCES = {"blockstream": "https://blockstream.info/api", "mempool": "https://mempool.space/api"}
UA = "musubi-header-view-fetch/1 (+https://github.com/horizonshield/horizon-shield)"


def header_from_fields(b):
    """80 byte header from Esplora block fields. Raises ValueError on a missing or malformed field."""
    for k in ("version", "timestamp", "bits", "nonce"):
        if isinstance(b.get(k), bool) or not isinstance(b.get(k), int):
            raise ValueError("field %s missing or not an integer" % k)
    prev = b.get("previousblockhash") or "00" * 32
    for k, v in (("previousblockhash", prev), ("merkle_root", b.get("merkle_root")), ("id", b.get("id"))):
        if not (isinstance(v, str) and v11.HEX64.match(v)):
            raise ValueError("field %s missing or not 64 lowercase hex" % k)
    return (struct.pack("<i", b["version"]) + bytes.fromhex(prev)[::-1] + bytes.fromhex(b["merkle_root"])[::-1] +
            struct.pack("<III", b["timestamp"], b["bits"], b["nonce"]))


def _get(url, tries=3):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8")
        except Exception as e:                          # network errors are retried, then reported
            if i == tries - 1:
                raise RuntimeError("%s: %s" % (url, e))
            time.sleep(2 * (i + 1))


def fetch_source(base, lo, hi, get=_get):
    """{height: header bytes} for lo..hi from one Esplora API, each header checked against its id."""
    out, h = {}, hi
    while h >= lo:
        page = json.loads(get("%s/blocks/%d" % (base, h)))
        if not isinstance(page, list) or not page:
            raise RuntimeError("%s returned no blocks at %d" % (base, h))
        for b in page:
            bh = b.get("height")
            if not isinstance(bh, int) or bh < lo or bh > hi or bh in out:
                continue
            raw = header_from_fields(b)
            if v11.header_hash(raw) != b["id"]:
                raise RuntimeError("%s: rebuilt header at %d does not hash to the id it gave" % (base, bh))
            out[bh] = raw
        nxt = min(x.get("height", h) for x in page if isinstance(x.get("height"), int)) - 1
        if nxt >= h:
            raise RuntimeError("%s: pagination did not move below %d" % (base, h))
        h = nxt
    missing = [x for x in range(lo, hi + 1) if x not in out]
    if missing:
        raise RuntimeError("%s: missing heights %s" % (base, missing[:5]))
    return out


def build_view(contract, to=None, get=_get, sources=SOURCES):
    lb = contract.get("lower_bound") or {}
    lo = lb.get("height")
    if isinstance(lo, bool) or not isinstance(lo, int):
        raise RuntimeError("contract.lower_bound.height missing")
    tips = {}
    for name, base in sources.items():
        tips[name] = int(get(base + "/blocks/tip/height").strip())
    hi = min(tips.values()) if to is None else to
    if hi < lo:
        raise RuntimeError("tip %d is below the checkpoint %d" % (hi, lo))
    got = {name: fetch_source(base, lo, hi, get) for name, base in sources.items()}
    names = sorted(got)
    for h in range(lo, hi + 1):
        vals = {got[n][h] for n in names}
        if len(vals) != 1:
            raise RuntimeError("sources disagree at height %d: %s" % (h, {n: v11.header_hash(got[n][h]) for n in names}))
    view = {"headers": [{"height": h, "hex": got[names[0]][h].hex()} for h in range(lo, hi + 1)]}
    cv, problem = v11.verify_view(view, contract)
    if cv is None:
        raise RuntimeError("view rejected under the contract's rules: " + problem)
    return view, {"from": lo, "to": hi, "tips": tips, "sources": names, "tip_hash": cv["hashes"][hi], "work_hex": format(cv["work"], "x")}


# --------------------------------------------------------------------------- self test
GENESIS_FIELDS = {"id": v11.GENESIS_HASH, "height": 0, "version": 1, "timestamp": 1231006505, "bits": 486604799,
                  "nonce": 2083236893, "previousblockhash": None,
                  "merkle_root": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"}


def _selftest():
    n = 0
    raw = header_from_fields(GENESIS_FIELDS)
    assert raw.hex() == v11.GENESIS_HEX and v11.header_hash(raw) == v11.GENESIS_HASH
    n += 1; print("[1] mainnet genesis rebuilt from explorer fields is byte identical to the real header")

    # a regtest chain 200..231, served by two fake explorers
    chain, prev = {}, "00" * 32
    for h in range(200, 232):
        r = v11._mine(prev, bytes([h % 256]) * 32, salt=h)
        f = v11.header_fields(r)
        ver, t, bits, nonce = struct.unpack("<i", r[:4])[0], *struct.unpack("<III", r[68:80])
        chain[h] = {"id": v11.header_hash(r), "height": h, "version": ver, "timestamp": t, "bits": bits, "nonce": nonce,
                    "previousblockhash": f["prev"], "merkle_root": f["merkle"][::-1].hex()}
        prev = chain[h]["id"]
    contract = {"lower_bound": {"kind": "bitcoin_block", "height": 205, "hash": chain[205]["id"]},
                "grant": {"finality": {"depth": 6, "max_target_bits": "207fffff"}}}

    def explorer(tamper=None, tip=231, page=10):
        def get(url):
            if url.endswith("/blocks/tip/height"):
                return str(tip)
            h = int(url.rsplit("/", 1)[1])
            blocks = [dict(chain[x]) for x in range(h, max(199, h - page), -1) if x in chain]
            if tamper:
                tamper(blocks)
            return json.dumps(blocks)
        return get

    def run(a, b, to=None):
        srcs = {"a": "A", "b": "B"}
        return build_view(contract, to=to, get=lambda u: (a if u.startswith("A") else b)(u), sources=srcs)

    view, info = run(explorer(), explorer(tip=229, page=15))
    assert info["from"] == 205 and info["to"] == 229 and len(view["headers"]) == 25
    n += 1; print("[2] two explorers, different page sizes and tips: view 205..229 (the lower tip), verified under the contract")

    def fails(fn, needle):
        try:
            fn()
        except RuntimeError as e:
            return needle in str(e)
        return False

    def bump_nonce(blocks):
        for b in blocks:
            if b["height"] == 210:
                b["nonce"] += 1
    assert fails(lambda: run(explorer(), explorer(bump_nonce)), "does not hash to the id")
    n += 1; print("[3] an explorer whose fields do not rebuild its own id is refused")

    alt = dict(chain[210]); alt_raw = v11._mine(chain[209]["id"], b"\x77" * 32, salt=999)
    af = v11.header_fields(alt_raw)
    alt.update(id=v11.header_hash(alt_raw), timestamp=struct.unpack("<I", alt_raw[68:72])[0],
               nonce=struct.unpack("<I", alt_raw[76:80])[0], merkle_root=af["merkle"][::-1].hex())

    def swap(blocks):
        for i, b in enumerate(blocks):
            if b["height"] == 210:
                blocks[i] = dict(alt)
    assert fails(lambda: run(explorer(), explorer(swap)), "sources disagree at height 210")
    n += 1; print("[4] a second explorer serving a different but self consistent block 210: sources disagree, no view")

    def drop(blocks):
        blocks[:] = [b for b in blocks if b["height"] != 215]
    assert fails(lambda: run(explorer(), explorer(drop)), "missing heights")
    n += 1; print("[5] an explorer that skips a height is refused")

    easy = dict(contract); easy["grant"] = {"finality": {"depth": 6, "max_target_bits": "17080000"}}
    try:
        build_view(easy, get=explorer(), sources={"a": "A"}); ok = False
    except RuntimeError as e:
        ok = "easier than the grant's floor" in str(e)
    assert ok
    n += 1; print("[6] regtest headers under the real contract floor 17080000: rejected by verify_view before writing")
    print("ALL PASS (header_view_fetch: %d checks)" % n)


def main():
    ap = argparse.ArgumentParser(description="fetch and verify the header view settle takes")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--contract"); ap.add_argument("--out"); ap.add_argument("--to", type=int)
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return 0
    if not (a.contract and a.out):
        ap.print_help(); return 1
    contract = parse_strict(open(a.contract, encoding="utf-8").read())
    try:
        view, info = build_view(contract, to=a.to)
    except RuntimeError as e:
        print(json.dumps({"status": "failed", "detail": str(e)}, indent=2)); return 2
    with open(a.out, "w", encoding="utf-8", newline="") as f:
        json.dump(view, f, separators=(",", ":"))
    print(json.dumps(dict(info, status="ok", wrote=a.out), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
