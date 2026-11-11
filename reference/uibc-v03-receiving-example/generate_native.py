"""Create synthetic controls and capture pinned UIBC reports in a new directory."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "source"))
from uibc_core.signing import ed_public_key, ed_seal_sign, ed_key_id
from uibc_core.canonical import evidence_root
from uibc_core.verify import verify


def write(path, obj):
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def inventory(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def resign(pkg, seed):
    identity, manifest = read(pkg / "identity.json"), read(pkg / "manifest.json")
    sig, pub = ed_seal_sign(seed, identity, manifest)
    write(pkg / "signatures/seal.json", {
        "schema": manifest["schema"], "algorithm": "Ed25519",
        "signed": "identity+manifest", "key_id": ed_key_id(ed_public_key(seed)),
        "public_key": pub, "signature": sig,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="new directory; existing paths are never overwritten")
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    (args.output / "validation").mkdir()
    inputs = args.output / "inputs"
    inputs.mkdir(exist_ok=False)
    shutil.copytree(ROOT / "source/examples/sample-package", inputs / "published")
    shutil.copyfile(ROOT / "source/examples/sample-owner.pub", inputs / "published.pub")
    for name in ("tampered", "forged", "resealed", "identity-changed", "unsigned", "bad-signature", "schema-v03"):
        shutil.copytree(inputs / "published", inputs / name)
    first = read(inputs / "published/evidence/index.json")["entries"][0]["path"]
    (inputs / "tampered/evidence" / first).write_bytes(b"synthetic altered evidence\n")
    (inputs / "forged/evidence" / first).write_bytes(b"synthetic altered evidence\n")
    index = read(inputs / "forged/evidence/index.json")
    for entry in index["entries"]:
        entry["content_hash"] = hashlib.sha256((inputs / "forged/evidence" / entry["path"]).read_bytes()).hexdigest()
    write(inputs / "forged/evidence/index.json", index)
    manifest = read(inputs / "forged/manifest.json")
    manifest["evidence_root"] = evidence_root([e["content_hash"] for e in index["entries"]])
    write(inputs / "forged/manifest.json", manifest)
    for p in (inputs / "forged").rglob("*"):
        if p.is_file():
            shutil.copyfile(p, inputs / "resealed" / p.relative_to(inputs / "forged"))
    # Public, deterministic test material only. No operational key is used.
    attacker_seed = hashlib.sha256(b"UIBC v0.3 receiver disposable attacker test seed").digest()
    generated_seed = hashlib.sha256(b"UIBC v0.3 receiver disposable schema test seed").digest()
    resign(inputs / "resealed", attacker_seed)
    (inputs / "attacker.pub").write_text(ed_public_key(attacker_seed).hex() + "\n")
    changed = read(inputs / "identity-changed/identity.json")
    changed["owner"] = "synthetic-other-owner"
    write(inputs / "identity-changed/identity.json", changed)
    (inputs / "unsigned/signatures/seal.json").unlink()
    sig = read(inputs / "bad-signature/signatures/seal.json")
    raw = bytearray(base64.b64decode(sig["signature"]))
    raw[0] ^= 1
    sig["signature"] = base64.b64encode(raw).decode()
    write(inputs / "bad-signature/signatures/seal.json", sig)
    for filename in ("identity.json", "manifest.json"):
        obj = read(inputs / "schema-v03" / filename)
        obj["schema"] = "uibc-core/0.3.0-proposal"
        write(inputs / "schema-v03" / filename, obj)
    resign(inputs / "schema-v03", generated_seed)
    (inputs / "schema-v03.pub").write_text(ed_public_key(generated_seed).hex() + "\n")
    shutil.copytree(ROOT / "source/fixtures/clean.uibc", inputs / "hmac-published")
    shutil.copytree(ROOT / "reader/samples/regenerated/clean.uibc", inputs / "hmac-regenerated")
    shutil.copyfile(ROOT / "reader/samples/regenerated/DISPOSABLE-TEST-KEY.hex", inputs / "hmac.hex")
    (inputs / "wrong.hex").write_text((b"w" * 32).hex() + "\n")
    cases = [
        ("published-open", "published", None, None, "PASS", "not_assessed"),
        ("published-pinned", "published", None, "published.pub", "PASS", "matched"),
        ("published-wrong-pin", "published", None, "attacker.pub", "FAIL", "mismatched"),
        ("published-hmac-mode", "published", "hmac.hex", None, "FAIL", "mismatched"),
        ("tampered-open", "tampered", None, None, "FAIL", "mismatched"),
        ("tampered-pinned", "tampered", None, "published.pub", "FAIL", "mismatched"),
        ("forged-open", "forged", None, None, "FAIL", "mismatched"),
        ("forged-pinned", "forged", None, "published.pub", "FAIL", "mismatched"),
        ("resealed-open", "resealed", None, None, "PASS", "not_assessed"),
        ("resealed-owner-pin", "resealed", None, "published.pub", "FAIL", "mismatched"),
        ("resealed-attacker-pin", "resealed", None, "attacker.pub", "PASS", "matched"),
        ("identity-changed", "identity-changed", None, "published.pub", "FAIL", "mismatched"),
        ("unsigned-open", "unsigned", None, None, "INCONCLUSIVE", "not_assessed"),
        ("unsigned-pin", "unsigned", None, "published.pub", "INCONCLUSIVE", "not_assessed"),
        ("unsigned-hmac", "unsigned", "hmac.hex", None, "FAIL", "mismatched"),
        ("hmac-published-open", "hmac-published", None, None, "INCONCLUSIVE", "not_assessed"),
        ("hmac-open", "hmac-regenerated", None, None, "INCONCLUSIVE", "not_assessed"),
        ("hmac-strict", "hmac-regenerated", "hmac.hex", None, "PASS", "matched"),
        ("hmac-wrong-key", "hmac-regenerated", "wrong.hex", None, "FAIL", "mismatched"),
        ("hmac-public-pin", "hmac-regenerated", None, "published.pub", "INCONCLUSIVE", "not_assessed"),
        ("schema-v03", "schema-v03", None, "schema-v03.pub", "PASS", "matched"),
        ("bad-signature", "bad-signature", None, "published.pub", "FAIL", "mismatched"),
    ]
    rows = []
    for name, package, keyfile, pubfile, expected, expected_receiver in cases:
        key = bytes.fromhex((inputs / keyfile).read_text()) if keyfile else None
        pub = bytes.fromhex((inputs / pubfile).read_text()) if pubfile else None
        before = inventory(inputs / package)
        native = verify(str(inputs / package), key=key, pubkey=pub)
        if before != inventory(inputs / package):
            raise RuntimeError("native mutated inputs")
        if native["result"] != expected:
            raise RuntimeError(f"unexpected native result: {name}")
        rows.append({"case": name, "package": package, "hmac_key_file": keyfile,
                     "public_key_file": pubfile, "inputs": before, "native": native,
                     "expected_native_result": expected,
                     "expected_receiver_status": expected_receiver})
    write(args.output / "validation/native.json", {"python": sys.version, "cases": rows,
          "source_commit": "dc9eba3146e4e32bb1356f24ce8d72249a64702a",
          "inputs": inventory(inputs)})
    print(f"Captured {len(rows)} native conditions and bound input hashes.")


if __name__ == "__main__":
    main()
