"""Check the AMEP comparison for VATE case 2 (accepted work interrupted).

Default mode uses only the Python standard library. It checks:
  1. every file here matches SOURCE-PINS.json (the AMEP revision it was copied from);
  2. the VATE case 2 inputs in this checkout match the pinned VATE revision;
  3. the AMEP packets describe this case's evidence:
     - each variant's interrupted history has one accepted record, for the pinned attempt of runtime-a;
     - after the handoff, VATE's provider-reported inventory is empty (zero-effects), or holds first.txt only
       (partial-effects), and the handoff retains runtime-a's attempt;
     - the files in AMEP's receipts and admission are the operation's files: each name, SHA-256 and size equals
       the operation's text, and the partial-effects receipts for runtime-a's call cover first.txt only, as VATE's
       inventory does;
  4. each AMEP verdict record names the SHA-256 of its packet, and states the expected packet verdict and every
     invocation's result (so z2-handoff-rerun records runtime-b's held_outcome).

With --amep PATH (a checkout of github.com/stafordtituss/amep at the pinned commit, with its Python package's dependency
`cryptography` installed), it also:
  5. re-evaluates each packet with AMEP's Python verifier and compares every result with expected-results.json;
  6. verifies each verdict record's signature.

Run from the repository root:
  python3 -B reference/amep/case-02-accepted-interrupted/check.py
  python3 -B reference/amep/case-02-accepted-interrupted/check.py --amep ../amep
"""
import argparse
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
CASE = "reference/authzen-receipt-vectors/cases/02-accepted-interrupted"


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def records(variant, history):
    """The decoded records of one of a variant's histories: (index, kind, body)."""
    out = []
    for index, record in enumerate(load(os.path.join(ROOT, CASE, variant, history))["records"]):
        doc = json.loads(b64u(record["raw"]))
        out.append((index, doc.get("kind"), doc.get("body")))
    return out


def results_of(statement):
    return {r["id"]: {k: r[k] for k in ("outcome", "invariant", "blame", "gaps")} for r in statement["predicate"]["results"]}


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

    # 3. the packets describe this case's evidence
    for variant, want in expected["variants"].items():
        accepted = [b for _, k, b in records(variant, "interrupted-history.json") if k == "accepted"]
        if len(accepted) != 1 or accepted[0].get("attempt_id") != want["attempt_id"]:
            problems.append(f"{variant}: expected one accepted record for {want['attempt_id']}")
        handoffs = [b for _, k, b in records(variant, "after-handoff-history.json") if k == "handoff"]
        if len(handoffs) != 1:
            problems.append(f"{variant}: expected one handoff record, found {len(handoffs)}")
            continue
        h = handoffs[0]
        if h.get("inventory") != want["inventory_after_handoff"]:
            problems.append(f"{variant}: the inventory after the handoff is {h.get('inventory')}, expected {want['inventory_after_handoff']}")
        if want["attempt_id"] not in h.get("retained_attempts", []):
            problems.append(f"{variant}: the handoff does not retain runtime-a's attempt")
        operation = load(os.path.join(ROOT, CASE, variant, "operation.json"))
        files = {f["name"]: {"sha256": hashlib.sha256(f["text"].encode("utf-8")).hexdigest(), "size": len(f["text"].encode("utf-8"))}
                 for f in operation["target"]["files"]}
        prefix = "z" if variant == "zero-effects" else "p"
        for phase in (p for p, e in expected["phases"].items() if e["variant"] == variant):
            packet = load(os.path.join(HERE, f"{phase}.packet.json"))
            for e in packet.get("effects", []):
                xf = e["executed"]["x-file"]
                if files.get(xf["name"]) != {"sha256": xf["sha256"], "size": xf["size"]}:
                    problems.append(f"{phase}: receipt {e['id']} names a file that is not the operation's")
            if not phase.startswith(prefix):
                problems.append(f"{phase}: listed under {variant}")
        observed = {e["executed"]["x-file"]["name"]: {"sha256": e["executed"]["x-file"]["sha256"], "size": e["executed"]["x-file"]["size"]}
                    for e in load(os.path.join(HERE, f"{prefix}1-interrupted.packet.json")).get("effects", [])}
        if observed != want["inventory_after_handoff"]:
            problems.append(f"{variant}: runtime-a's receipts cover {sorted(observed)}, but VATE's inventory is {sorted(want['inventory_after_handoff'])}")
        lines.append(f"{variant}: attempt {want['attempt_id'][:16]}…, inventory after handoff "
                     f"{sorted(want['inventory_after_handoff']) or 'empty'}, matching runtime-a's receipts")

    # 4. each verdict record names its packet and states the expected results
    for phase, exp in expected["phases"].items():
        env = load(os.path.join(HERE, f"{phase}.verdict.dsse.json"))
        stmt = json.loads(base64.b64decode(env["payload"]))
        packet_sha = sha256_file(os.path.join(HERE, f"{phase}.packet.json"))
        if stmt["subject"][0]["digest"]["sha256"] != packet_sha or stmt["predicate"]["packet"]["sha256"] != packet_sha:
            problems.append(f"{phase}: the verdict record does not name the packet's digest")
        v = stmt["predicate"]["verdict"]
        if [v["outcome"], v["invariant"]] != [exp["outcome"], exp["invariant"]]:
            problems.append(f"{phase}: verdict record says {v['outcome']} {v['invariant']}, expected {exp['outcome']} {exp['invariant']}")
        if results_of(stmt) != exp["results"]:
            problems.append(f"{phase}: verdict record's per-invocation results differ from expected-results.json")
        each = "; ".join(f"{i} {r['outcome']}" + "".join(f" {g['need']} {g['ref']}" for g in r["gaps"])
                         for i, r in exp["results"].items())
        lines.append(f"{phase:18} {v['outcome']:10} {v['invariant']:3} [{each}]")

    # 5 and 6, with AMEP's verifier
    if amep_path:
        sys.path.insert(0, os.path.join(os.path.abspath(amep_path), "packages", "python", "src"))
        from amep_protocol import evaluate_text, verdict  # noqa: E402
        from amep_protocol.verdicts import verify_envelope  # noqa: E402
        keys = load(os.path.join(HERE, "keys.json"))
        verifier_key = load(os.path.join(HERE, "verifier-key.json"))
        for phase, exp in expected["phases"].items():
            with open(os.path.join(HERE, f"{phase}.packet.json"), encoding="utf-8") as fh:
                res = evaluate_text(fh.read(), keys)
            v = verdict(res)
            if (v.outcome, v.invariant) != (exp["outcome"], exp["invariant"]):
                problems.append(f"{phase}: AMEP evaluates {v.outcome} {v.invariant}, expected {exp['outcome']} {exp['invariant']}")
            got = {r.invocation: {"outcome": r.outcome, "invariant": r.invariant, "blame": r.blame, "gaps": r.gaps} for r in res}
            if got != exp["results"]:
                problems.append(f"{phase}: AMEP's per-invocation results differ from expected-results.json")
            try:
                verify_envelope(load(os.path.join(HERE, f"{phase}.verdict.dsse.json")), verifier_key)
            except Exception as exc:  # any failure to verify is a problem to report, not to hide
                problems.append(f"{phase}: verdict record signature does not verify ({exc})")
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
