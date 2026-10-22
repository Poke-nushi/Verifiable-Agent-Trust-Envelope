#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression for settlement: nothing that settled before settles differently now.

Three real cases, one corpus and three published contracts, each compared with bytes recorded on 2026-10-10 from the
repository at 49c8b050, before the clause evaluator was moved out of settle_v1_10.py:

  run0002          walk 2 under the second contract (contract_sha256 14474983...): within_grant, final, no deviation
  the outside parties' contract (contract_sha256 d7118f28...), kept in their own repository; their published
                   settlement.json is the reference, and it is fetched from the URLs in tools/adoption/registry.json
  the corpus       18 deterministic scenarios (fixtures/settle_admission/cases.json, the cases named corpus/...)
  the contracts    the first and the second published contract and the outside parties' contract pass the contract
                   door exactly as before grant.limits became a grant key

For each: settle v1.10 gives the recorded bytes, and settle v1.11 and v1.12 give the same bytes (none of these
contracts requires admission or carries limits). Then every other scenario in the fixture, the ones with admissions
and with limits, settles under the layer it names to the sha256 recorded when it was made.

  python3 settle_regression.py            needs the network for the outside parties' files
  python3 settle_regression.py --offline  skips that case and says so
"""
import hashlib, json, os, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import contract_v0 as v0
import settle_v1_10 as v110
import settle_v1_11 as v111
import settle_v1_12 as v112
import admission_verify_v0 as A
from contract_v0 import canonical, parse_strict, contract_sha256

RUN0002_SHA256 = "d600a7c482323426d213f3899e94b77b1eb88928f9a3f259a9f4fc0b6bf96683"
PEER_SETTLEMENT_SHA256 = "a21190c7f30ed2436b96efe05d7434f9319b41d5cf42e50ed8c730d6b4067fe7"
CORPUS_SHA16 = "ccd9d4161e8e5980"
REGISTRY = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "tools", "adoption", "registry.json"))
ACCEPTED = lambda c: {"schema": "a2a-contract-verify-v0", "contract_sha256": contract_sha256(c), "verdict": "accepted", "refusals": [], "findings": []}
sha = lambda s: hashlib.sha256(s.encode("utf-8") if isinstance(s, str) else s).hexdigest()


def main():
    bad = 0
    def line(ok, text):
        nonlocal bad
        bad += not ok
        print(("ok   " if ok else "NG   ") + text)

    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    rr = os.path.join(HERE, "run0002")
    C2 = rd(os.path.join(HERE, "second_contract_AB.json"))
    args = (C2, [rd(os.path.join(rr, "exec_19c44a79.anchored.json"))], rd(os.path.join(rr, "view.json")))
    nr = [rd(os.path.join(rr, "walk_8bf29f1a.json"))]
    s10, s11 = v110.settle_v1_10(*args, nenrin_records=nr), v111.settle_v1_11(*args, nenrin_records=nr)
    line(contract_sha256(C2).startswith("14474983"), "second contract: contract_sha256 %s" % contract_sha256(C2))
    line((s10["verdict"], s10["status"], s10["deviations"]) == ("within_grant", "final", []), "run0002: within_grant, final, no deviation")
    line(sha(canonical(s10)) == RUN0002_SHA256, "run0002: settle v1.10 bytes are the bytes recorded before the change (%s)" % sha(canonical(s10))[:16])
    line(canonical(s11) == canonical(s10), "run0002: settle v1.11 gives the same bytes")
    line(canonical(v112.settle_v1_12(*args, nenrin_records=nr)) == canonical(s10), "run0002: settle v1.12 gives the same bytes")

    if "--offline" in sys.argv:
        print("skip the outside parties' contract d7118f28 (--offline): its files live in their repository and were not fetched")
    else:
        row = next(r for r in json.load(open(REGISTRY, encoding="utf-8"))["published_contracts"] if r.get("contract_sha256", "").startswith("d7118f28"))
        get = lambda u: urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "curl/8"}), timeout=30).read()
        cb, eb, vb, sb = get(row["contract_url"]), get(row["settle_inputs"]["event_url"]), get(row["settle_inputs"]["view_url"]), get(row["settlement_url"])
        c, e, v = (parse_strict(x.decode("utf-8")) for x in (cb, eb, vb))
        line(contract_sha256(c) == row["contract_sha256"], "outside parties' contract: contract_sha256 %s" % contract_sha256(c))
        line(sha(sb) == PEER_SETTLEMENT_SHA256, "their published settlement.json is the file recorded (%s)" % sha(sb)[:16])
        p10, p11 = v110.settle_v1_10(c, [e], v), v111.settle_v1_11(c, [e], v)
        line(canonical(p10).encode("utf-8") == sb, "settle v1.10 recomputes their settlement.json byte for byte")
        line(canonical(p11) == canonical(p10), "settle v1.11 gives the same bytes")
        line(canonical(v112.settle_v1_12(c, [e], v)) == canonical(p10), "settle v1.12 gives the same bytes")
        line(v0.verify_contract(c) == ACCEPTED(c) and "limits" not in c["grant"], "their contract passes the contract door as before (accepted, no refusal, no finding), and carries no limits")
        line((p10["verdict"], p10["status"], p10["deviations"]) == ("within_grant", "final", []), "within_grant, final, no deviation")

    line(A.check_fixtures() == 0, "the fixture files are the ones listed in fixtures/ADMISSION_FIXTURES.sha256")
    fx = v111.load_fixture()
    contracts, cases, _ = fx
    corpus = sorted(k for k in cases if k.startswith("corpus/"))
    outs = {}
    for layer, fn in (("v1.10", v110.settle_v1_10), ("v1.11", v111.settle_v1_11), ("v1.12", v112.settle_v1_12)):
        outs[layer] = {k: canonical(fn(contracts[cases[k]["contract"]], cases[k]["events"], cases[k]["view"])) for k in corpus}
    agg = sha("".join(outs["v1.10"][k] for k in corpus))[:16]
    line(len(corpus) == 18 and agg == CORPUS_SHA16, "corpus: 18 scenarios, settle v1.10 bytes are the bytes recorded before the change (%s)" % agg)
    line(outs["v1.11"] == outs["v1.10"], "corpus: settle v1.11 gives the same bytes for all 18")
    line(outs["v1.12"] == outs["v1.10"], "corpus: settle v1.12 gives the same bytes for all 18")

    for name in ("first_contract_AB.json", "second_contract_AB.json"):
        pub = rd(os.path.join(HERE, name))
        line(v0.verify_contract(pub) == ACCEPTED(pub), "%s: the contract door gives the same result as before limits were added (accepted, no refusal, no finding)" % name)

    rest = sorted(k for k in cases if not k.startswith("corpus/"))
    wrong = []
    for k in rest:
        fn = {"v1.11": v111.settle_v1_11, "v1.12": v112.settle_v1_12}[cases[k]["expect"]["layer"]]
        if sha(canonical(v111.settle_fixture_case(fn, k, fx))) != cases[k]["expect"]["settlement_sha256"]:
            wrong.append(k)
    line(not wrong, "admissions and limits: %d fixture scenarios settle to the sha256 recorded when they were made%s" % (len(rest), "" if not wrong else " EXCEPT " + ", ".join(wrong)))

    if bad:
        print("\nFAILED: %d" % bad); return 1
    print("\nALL PASS (settle_regression: run0002 under the second contract 14474983, %sthe 18 scenario corpus; settle v1.10 unchanged, settle v1.11 and v1.12 identical; "
          "the published contracts verify as before; %d scenarios with admissions and limits settle to the recorded bytes)"
          % ("" if "--offline" in sys.argv else "the outside parties' contract d7118f28, ", len(rest)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
