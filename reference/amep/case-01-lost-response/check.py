"""Check the AMEP comparison for VATE case 1 (lost response, then recovery).

Default mode uses only the Python standard library. It checks:
  1. every file here matches SOURCE-PINS.json (the AMEP revision it was copied from);
  2. the VATE case 1 inputs in this checkout match the pinned VATE revision;
  3. the caller's signed unknown observation is in the recovered history, under the digest VATE records for it, and
     names the same operation and attempt as the pending phase;
  3a. the pending ticket and the signed observation refer to the same original attempt: the observation's attempt_id,
     runtime and operation_id are the ticket's, and the recovered history still carries that ticket record unchanged
     (the same record digest), so recovery added to the history rather than replacing the attempt;
  4. each AMEP verdict record names the SHA-256 of its packet, and states the expected outcome.

With --amep PATH (a checkout of github.com/stafordtituss/amep at the pinned commit, with its Python package's dependency
`cryptography` installed), it also:
  5. re-evaluates each packet with AMEP's Python verifier and compares the outcome with expected-results.json;
  6. verifies each verdict record's signature, and the caller's ES256 signature on the unknown observation.

Run from the repository root:
  python3 -B reference/amep/case-01-lost-response/check.py
  python3 -B reference/amep/case-01-lost-response/check.py --amep ../amep
"""
import argparse
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
CASE = "reference/authzen-receipt-vectors/cases/01-lost-response-recovery/with-unknown-observation"


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def unknown_observation():
    """The caller's signed unknown observation, as VATE's recovered history holds it."""
    history = load(os.path.join(ROOT, CASE, "recovered-history.json"))
    found = []
    for index, record in enumerate(history["records"]):
        raw = b64u(record["raw"])
        body = json.loads(raw)
        if body.get("kind") == "unknown":
            jws = b64u(body["body"]["raw"]).decode("ascii")
            header, payload, _ = jws.split(".")
            found.append({"index": index, "record_sha256": record["sha256"], "raw_sha256": hashlib.sha256(raw).hexdigest(),
                          "jws": jws, "jws_sha256": hashlib.sha256(jws.encode("ascii")).hexdigest(),
                          "header": json.loads(b64u(header)), "claims": json.loads(b64u(payload))})
    return found


def ticket(history_file):
    """The ticket record in one of the case's histories: (index, record sha256 as VATE records it, decoded body)."""
    history = load(os.path.join(ROOT, CASE, history_file))
    found = []
    for index, record in enumerate(history["records"]):
        raw = b64u(record["raw"])
        body = json.loads(raw)
        if body.get("kind") == "ticket":
            found.append((index, record["sha256"], hashlib.sha256(raw).hexdigest(), body["body"]))
    return found


def check(amep_path=None):
    problems, lines = [], []
    pins = load(os.path.join(HERE, "SOURCE-PINS.json"))
    expected = load(os.path.join(HERE, "expected-results.json"))

    # 1. the AMEP files here are the ones at the pinned AMEP commit
    for name, digest in pins["amep"]["files"].items():
        if sha256_file(os.path.join(HERE, name)) != digest:
            problems.append(f"{name} differs from AMEP {pins['amep']['commit'][:7]}")
    # 2. the VATE inputs are the ones at the pinned VATE commit
    for path, digest in pins["vate"]["files"].items():
        if sha256_file(os.path.join(ROOT, path)) != digest:
            problems.append(f"{path} differs from VATE {pins['vate']['commit'][:7]}")
    lines.append(f"pinned files: {len(pins['amep']['files'])} AMEP ({pins['amep']['commit'][:7]}), "
                 f"{len(pins['vate']['files'])} VATE ({pins['vate']['commit'][:7]})")

    # 3. the caller's signed unknown observation
    obs = unknown_observation()
    want = expected["unknown_observation"]
    if len(obs) != 1:
        problems.append(f"expected one unknown observation in the recovered history, found {len(obs)}")
    else:
        o = obs[0]
        if o["raw_sha256"] != o["record_sha256"]:
            problems.append("the unknown observation's record digest does not match its bytes")
        for key in ("record_sha256", "jws_sha256"):
            if o[key] != want[key]:
                problems.append(f"unknown observation {key} is {o[key]}, expected {want[key]}")
        pending = load(os.path.join(ROOT, CASE, "pending-history.json"))
        if (o["claims"].get("outcome"), o["claims"].get("operation_id"), o["claims"].get("runtime")) != ("unknown", pending["operation_id"], "runtime-a"):
            problems.append("the unknown observation does not state runtime-a's unknown outcome for the pending operation")
        if o["claims"].get("observed_at") != pending["observed_at"]:
            problems.append("the unknown observation's observed_at differs from the pending phase's")
        lines.append(f"caller's unknown observation: recovered-history.json records[{o['index']}], record sha256 {o['record_sha256'][:16]}…, "
                     f"JWS sha256 {o['jws_sha256'][:16]}…, outcome {o['claims'].get('outcome')} at {o['claims'].get('observed_at')}")

    # 3a. both records refer to the original attempt (requested in VATE PR #138 review)
    want_t = expected["original_attempt"]
    pend, rec = ticket("pending-history.json"), ticket("recovered-history.json")
    if len(pend) != 1 or len(rec) != 1:
        problems.append(f"expected one ticket in each history, found {len(pend)} pending and {len(rec)} recovered")
    else:
        (pi, psha, praw, pbody), (ri, rsha, rraw, _) = pend[0], rec[0]
        if praw != psha:
            problems.append("the pending ticket's record digest does not match its bytes")
        if psha != want_t["ticket_record_sha256"] or pbody.get("attempt_id") != want_t["attempt_id"]:
            problems.append("the pending ticket is not the pinned original attempt")
        if rsha != psha:
            problems.append("the recovered history does not carry the pending ticket unchanged")
        if rraw != psha:
            problems.append("the hash of the recovered ticket's bytes differs from the pending ticket's hash")
        if len(obs) == 1:
            c = obs[0]["claims"]
            for k in ("attempt_id", "runtime", "operation_id"):
                if c.get(k) != pbody.get(k):
                    problems.append(f"the signed observation's {k} ({c.get(k)}) differs from the pending ticket's ({pbody.get(k)})")
        lines.append(f"original attempt: pending-history.json records[{pi}] ticket {pbody.get('attempt_id')}, record sha256 {psha[:16]}…; "
                     f"the same record in recovered-history.json records[{ri}], whose bytes hash to the same value; "
                     f"the signed observation names the same attempt")

    # 4. each verdict record names its packet and states the expected outcome
    for phase, exp in expected["phases"].items():
        env = load(os.path.join(HERE, f"{phase}.verdict.dsse.json"))
        stmt = json.loads(base64.b64decode(env["payload"]))
        packet_sha = sha256_file(os.path.join(HERE, f"{phase}.packet.json"))
        if stmt["subject"][0]["digest"]["sha256"] != packet_sha or stmt["predicate"]["packet"]["sha256"] != packet_sha:
            problems.append(f"{phase}: the verdict record does not name the packet's digest")
        v = stmt["predicate"]["verdict"]
        if [v["outcome"], v["invariant"]] != [exp["outcome"], exp["invariant"]]:
            problems.append(f"{phase}: verdict record says {v['outcome']} {v['invariant']}, expected {exp['outcome']} {exp['invariant']}")
        lines.append(f"{phase:22} {v['outcome']:10} {v['invariant']:3} packet sha256 {packet_sha[:16]}…")

    # 5 and 6, with AMEP's verifier
    if amep_path:
        sys.path.insert(0, os.path.join(os.path.abspath(amep_path), "packages", "python", "src"))
        from amep_protocol import evaluate_text, verdict  # noqa: E402
        from amep_protocol.verdicts import verify_envelope  # noqa: E402
        from cryptography.hazmat.primitives import hashes  # noqa: E402
        from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402
        from cryptography.hazmat.primitives.serialization import load_pem_public_key  # noqa: E402
        keys = load(os.path.join(HERE, "keys.json"))
        verifier_key = load(os.path.join(HERE, "verifier-key.json"))
        for phase, exp in expected["phases"].items():
            with open(os.path.join(HERE, f"{phase}.packet.json"), encoding="utf-8") as fh:
                v = verdict(evaluate_text(fh.read(), keys))
            if (v.outcome, v.invariant) != (exp["outcome"], exp["invariant"]):
                problems.append(f"{phase}: AMEP evaluates {v.outcome} {v.invariant}, expected {exp['outcome']} {exp['invariant']}")
            try:
                verify_envelope(load(os.path.join(HERE, f"{phase}.verdict.dsse.json")), verifier_key)
            except Exception as exc:  # any failure to verify is a problem to report, not to hide
                problems.append(f"{phase}: verdict record signature does not verify ({exc})")
        if len(obs) == 1:
            ctx = load(os.path.join(ROOT, CASE, "context.json"))
            key = load_pem_public_key(base64.b64decode(ctx["actors"]["runtime-a"]["public_pem"]))
            header, payload, sig = obs[0]["jws"].split(".")
            raw = b64u(sig)
            try:
                key.verify(utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                           f"{header}.{payload}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
            except Exception:
                problems.append("the caller's ES256 signature on the unknown observation does not verify")
        lines.append("AMEP re-evaluation and signatures: " + ("checked" if not problems else "see problems"))
    return problems, lines


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--amep", help="path to a checkout of github.com/stafordtituss/amep at the pinned commit")
    args = parser.parse_args()
    problems, lines = check(args.amep)
    print("\n".join(lines))
    if problems:
        print("\nPROBLEMS:\n  " + "\n  ".join(problems))
        return 1
    print("\nall checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
