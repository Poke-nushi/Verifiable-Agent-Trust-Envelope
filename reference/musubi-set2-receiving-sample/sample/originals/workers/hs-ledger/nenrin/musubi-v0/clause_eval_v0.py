#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI clause evaluator v0: the one place that says how a single action reads against a signed grant.

Why this file exists. Settlement (settle v1.10, after the fact) and admission (a2a-admission-v0, before the act) must
give the same answer for the same action under the same contract. If each carried its own copy of the clauses, one
of them could drift and nobody would notice until a relying party admitted something a settler then called a
deviation. So the clauses live here, both import them, and every admission record names this file by sha256
(EVALUATOR_SHA256).

What moved here from settle_v1_10.py on 2026-10-10, unchanged: the pinned approver rule (approvers, gated_actions,
approver_approval_bytes, sign_approver_approval, verify_approver_approval, policy_reading and the reason list).
settle_v1_10 imports these names back, so its module namespace, its outputs and its self test are what they were.

What is stated here for the first time as a function: classify_action and evaluate_action. They restate, for one
action, the order the walk in settle v1.6 and v1.7 applies to every recorded action:

    authority ended by a revocation   -> revoked            (nothing else is looked at)
    past grant.expiry_height          -> after_expiry       (and the checks below still run)
    in grant.prohibited_actions       -> prohibited
    in grant.conditional              -> conditional unless a countable approval is carried
    not in grant.authorized_actions   -> unauthorized
    otherwise                         -> no deviation

Added on 2026-10-10 (admission v0.1), for grants that carry limits. The walks above never see an amount, so this clause
has no older statement to be held to; settle v1.12 and admit both read it from here:

    grant.limits names the action and the amount is above max_amount, or no amount is stated  -> over_limit

It is a hard cap. No approval lifts it, and it is read for every action the grant does not prohibit. The only source
of a limit is the signed grant. An action whose grant carries no limits is read exactly as before.

The walks in settle_v1_6.py and settle_v1_7.py are published and are not edited; they keep their own lines. What
holds this restatement to them is a test, not a promise: admit_consistency.py runs every scenario through both and
fails on the first disagreement, and settle v1.11 recomputes every admission with evaluate_action.

Nothing here renders a verdict about a party. It returns clause names; the callers decide what to do with them.
"""
import base64, hashlib, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from contract_v0 import canonical, ed25519_verify, contract_sha256, b64_raw

RULES = "musubi-clause-eval-v0"
APPROVAL_V2_CONTEXT = b"a2a-approval-v2\n"
HEX32 = re.compile(r"^[0-9a-f]{32}$")
REASONS = ("not_an_approver_approval", "malformed", "approver_not_pinned", "action_not_permitted_for_approver",
           "malformed_key_or_signature", "bad_signature")


def evaluator_sha256():
    """sha256 of this file's bytes. An admission record carries it, so a reader knows which clauses were applied."""
    with open(os.path.abspath(__file__), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# --------------------------------------------------------------------------- the pinned approver rule (from settle v1.10)
def approvers(contract):
    ap = (contract.get("grant") or {}).get("approval_policy")
    a = ap.get("approvers") if isinstance(ap, dict) else None
    return [x for x in a if isinstance(x, dict)] if isinstance(a, list) else []


def policy_reading(contract):
    return "pinned" if approvers(contract) else "approval_self_asserted"


def approver_approval_bytes(contract, e, approver_key_b64):
    return APPROVAL_V2_CONTEXT + canonical({
        "contract_sha256": contract_sha256(contract), "action": e.get("action"), "approver_key": approver_key_b64,
        "valid_until_height": e.get("valid_until_height"), "nonce": e.get("nonce"), "single_use": e.get("single_use")}).encode("utf-8")


def sign_approver_approval(key, contract, action, valid_until_height, nonce, approver_name, approver_key_b64, single_use=True):
    e = {"action": action, "by": "approver", "approver": approver_name, "valid_until_height": valid_until_height,
         "nonce": nonce, "single_use": single_use}
    e["sig_b64"] = base64.b64encode(key.sign(approver_approval_bytes(contract, e, approver_key_b64))).decode("ascii")
    return e


def verify_approver_approval(contract, e):
    """("approved", None) or ("approval_unverified", reason), in the order of babyblueviper1's reference verifier."""
    if not isinstance(e, dict) or e.get("by") != "approver":
        return "approval_unverified", "not_an_approver_approval"
    vu, nonce, su = e.get("valid_until_height"), e.get("nonce"), e.get("single_use")
    if not (isinstance(e.get("action"), str) and isinstance(vu, int) and not isinstance(vu, bool) and vu >= 0
            and isinstance(nonce, str) and HEX32.match(nonce) and isinstance(su, bool)):
        return "approval_unverified", "malformed"
    pin = next((a for a in approvers(contract) if a.get("name") == e.get("approver")), None)
    if pin is None:
        return "approval_unverified", "approver_not_pinned"
    if e["action"] not in (pin.get("actions") or []):
        return "approval_unverified", "action_not_permitted_for_approver"
    if b64_raw(pin.get("public_key_ed25519_b64"), 32) is None or b64_raw(e.get("sig_b64"), 64) is None:
        return "approval_unverified", "malformed_key_or_signature"
    if ed25519_verify(pin["public_key_ed25519_b64"], e["sig_b64"], approver_approval_bytes(contract, e, pin["public_key_ed25519_b64"])) is not True:
        return "approval_unverified", "bad_signature"
    return "approved", None


def gated_actions(contract):
    return sorted({x for a in approvers(contract) for x in (a.get("actions") or []) if isinstance(x, str)})


# --------------------------------------------------------------------------- one action against the grant
CLAUSES = ("revoked", "after_expiry", "prohibited", "conditional", "unauthorized", "over_limit")


def grant_sets(contract):
    g = contract.get("grant") if isinstance(contract.get("grant"), dict) else {}
    authorized = set(g.get("authorized_actions") or [])
    prohibited = set(g.get("prohibited_actions") or [])
    conditional = {c.get("action"): c for c in (g.get("conditional") or []) if isinstance(c, dict)}
    return authorized, prohibited, conditional, g.get("expiry_height")


def classify_action(contract, action):
    """Where the action sits in the grant, before approvals, expiry or revocation: prohibited, conditional, authorized or unauthorized."""
    authorized, prohibited, conditional, _ = grant_sets(contract)
    if action in prohibited:
        return "prohibited"
    if action in conditional:
        return "conditional"
    return "authorized" if action in authorized else "unauthorized"


def clause_path(contract, action):
    """The grant entry that decided classify_action, as a path a reader can open, or None when no entry names the action."""
    g = contract.get("grant") if isinstance(contract.get("grant"), dict) else {}
    kind = classify_action(contract, action)
    if kind == "prohibited":
        return "grant.prohibited_actions[%d]" % list(g.get("prohibited_actions") or []).index(action)
    if kind == "conditional":
        return "grant.conditional[%d]" % next(i for i, c in enumerate(g.get("conditional") or []) if isinstance(c, dict) and c.get("action") == action)
    if kind == "authorized":
        return "grant.authorized_actions[%d]" % list(g.get("authorized_actions") or []).index(action)
    return None


def limit_for(contract, action):
    """grant.limits[action] as (max_amount, unit), or None when the signed grant sets no limit on this action."""
    g = contract.get("grant") if isinstance(contract.get("grant"), dict) else {}
    lm = g.get("limits") if isinstance(g.get("limits"), dict) else {}
    x = lm.get(action)
    if not isinstance(x, dict):
        return None
    m = x.get("max_amount")
    return (m if (isinstance(m, int) and not isinstance(m, bool)) else None), x.get("unit")


def over_limit(contract, action, amount):
    """True when the grant limits this action and the amount is above the limit, is not stated, or the limit cannot be read.

    A limit nobody can compare against is not a limit that was kept: a missing amount and an unreadable max_amount both
    read as over the limit."""
    lim = limit_for(contract, action)
    if lim is None:
        return False
    if lim[0] is None or not (isinstance(amount, int) and not isinstance(amount, bool)) or amount < 0:
        return True
    return amount > lim[0]


def approval_counts(contract, action, approval):
    """Does this approvals[] entry count for this conditional action under these terms? (True, None) or (False, reason).

    An action a pinned approver lists counts only with that approver's signature (settle v1.10). Any other conditional
    action keeps settle v1.6's rule: the principal's a2a-approval-v2 signature over these terms.
    """
    if not isinstance(approval, dict) or approval.get("action") != action:
        return False, "approval_for_another_action"
    if action in gated_actions(contract):
        res, why = verify_approver_approval(contract, approval)
        return (True, None) if res == "approved" else (False, why)
    if approval.get("by") == "approver":
        res, why = verify_approver_approval(contract, approval)
        return False, (why or "action_not_permitted_for_approver")
    import settle_v1_6 as v16
    kind = v16.classify_approval_v2(approval, contract)
    if kind == "scoped_v2":
        return True, None
    return False, {None: "forged_approval", "label_bound": "approval_bound_by_label_only", "other_terms": "approval_for_other_terms"}.get(kind, str(kind))


def evaluate_action(contract, action, approvals=(), height=None, authority_ended=False, used_nonces=(), amount=None):
    """The clauses one action meets, in the walk's order. Returns {"clauses": [...], "approval": {...} or None, "class": ...}.

    approvals        approvals[] entries offered for this action (already carried or anchored before it).
    height           the height the action is, or would be, anchored at; None skips the two height rules.
    authority_ended  True when a principal's revocation took effect at or before that height.
    used_nonces      nonces of single_use approvals already spent by earlier actions.
    amount           the amount of this one action, in the unit grant.limits states for it. Read only when the grant
                     limits the action; then a missing amount reads as over the limit.
    An empty clauses list means the action is inside the grant.
    """
    authorized, prohibited, conditional, exp = grant_sets(contract)
    out = {"class": classify_action(contract, action), "clauses": [], "approval": None, "why": None}
    if authority_ended:
        out["clauses"].append("revoked")
        return out
    if exp is not None and height is not None and height > exp:
        out["clauses"].append("after_expiry")
    if action in prohibited:
        out["clauses"].append("prohibited")
        return out
    if action in conditional:
        why = None
        for ap in approvals or ():
            ok, reason = approval_counts(contract, action, ap)
            if not ok:
                why = why or reason
                continue
            if height is not None and height > ap["valid_until_height"]:
                why = why or "approval_expired"
                continue
            if ap["single_use"] and ap["nonce"] in used_nonces:
                why = why or "approval_reused"
                continue
            out["approval"] = {"by": ap.get("by") or "principal", "nonce": ap["nonce"], "single_use": ap["single_use"]}
            break
        else:
            out["clauses"].append("conditional")
            out["why"] = why or "requires %s, no approval" % conditional[action].get("requires")
    elif action not in authorized:
        out["clauses"].append("unauthorized")
    if over_limit(contract, action, amount):
        out["clauses"].append("over_limit")
    return out


# --------------------------------------------------------------------------- self test
def _selftest():
    from contract_v0 import parse_strict
    n = 0
    fix = os.path.join(HERE, "fixtures", "babyblueviper1_approver_v2", "vectors.json")
    V = parse_strict(open(fix, encoding="utf-8").read())
    agree = 0
    for vec in V["vectors"]:
        c = V["contracts"][vec["contract"]]
        got = verify_approver_approval(c, vec["approval"]) if vec.get("approval") is not None else (policy_reading(c), None)
        assert list(got) == [vec["expect"]["result"], vec["expect"].get("reason")], (vec["id"], got)
        agree += 1
    n += 1; print("[1] babyblueviper1's vectors through the shared approver rule: %d/%d agree" % (agree, len(V["vectors"])))

    C = {"grant": {"authorized_actions": ["read", "write", "pay"], "prohibited_actions": ["delete", "pay"],
                   "conditional": [{"action": "write", "requires": "principal_approval"}, {"action": "delete", "requires": "principal_approval"}],
                   "expiry_height": 100}}
    want = {"read": "authorized", "write": "conditional", "delete": "prohibited", "pay": "prohibited", "ship": "unauthorized"}
    assert {a: classify_action(C, a) for a in want} == want
    assert clause_path(C, "read") == "grant.authorized_actions[0]" and clause_path(C, "write") == "grant.conditional[0]"
    assert clause_path(C, "delete") == "grant.prohibited_actions[0]" and clause_path(C, "ship") is None
    n += 1; print("[2] one action against the grant: prohibited wins over conditional and authorized; an unnamed action is unauthorized")

    ev = lambda a, **k: evaluate_action(C, a, **k)["clauses"]
    assert ev("read") == [] and ev("ship") == ["unauthorized"] and ev("delete") == ["prohibited"] and ev("write") == ["conditional"]
    assert ev("read", height=101) == ["after_expiry"] and ev("delete", height=101) == ["after_expiry", "prohibited"]
    assert ev("ship", height=101) == ["after_expiry", "unauthorized"] and ev("read", height=100) == []
    assert ev("read", authority_ended=True) == ["revoked"] and ev("delete", height=101, authority_ended=True) == ["revoked"]
    assert evaluate_action({"grant": {"authorized_actions": []}}, "anything")["clauses"] == ["unauthorized"]
    assert evaluate_action({}, "anything")["clauses"] == ["unauthorized"]
    n += 1; print("[3] the walk's order for one action: revoked alone; after_expiry and then the grant clauses; an empty grant authorizes nothing")

    L = {"grant": {"authorized_actions": ["pay", "read"], "prohibited_actions": ["wire"], "conditional": [{"action": "pay_large", "requires": "approver"}],
                   "limits": {"pay": {"max_amount": 100000, "unit": "JPY"}, "pay_large": {"max_amount": 1000000, "unit": "JPY"}}}}
    lv = lambda a, **k: evaluate_action(L, a, **k)["clauses"]
    assert lv("pay", amount=100000) == [] and lv("pay", amount=0) == [] and lv("pay", amount=100001) == ["over_limit"]
    assert lv("pay") == ["over_limit"] and lv("pay", amount=True) == ["over_limit"] and lv("pay", amount=-1) == ["over_limit"]
    assert lv("read") == [] and lv("read", amount=10 ** 9) == [] and lv("wire", amount=1) == ["prohibited"]
    assert lv("pay_large", amount=5) == ["conditional"] and lv("pay_large", amount=2000000) == ["conditional", "over_limit"]
    assert lv("pay", amount=5, authority_ended=True) == ["revoked"] and limit_for(L, "pay") == (100000, "JPY") and limit_for(L, "read") is None
    assert evaluate_action({"grant": {"authorized_actions": ["pay"], "limits": {"pay": {"max_amount": "100000", "unit": "JPY"}}}}, "pay", amount=1)["clauses"] == ["over_limit"]
    assert ev("read", amount=10 ** 12) == [] and ev("write", amount=1) == ["conditional"]
    n += 1; print("[4] grant.limits: at the limit is inside, one above is over_limit, a missing or unreadable amount is over_limit; no approval is asked about it; a grant without limits reads as before")

    a, b = evaluator_sha256(), evaluator_sha256()
    assert a == b and len(a) == 64 and a == hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()
    n += 1; print("[5] evaluator_sha256 is the sha256 of this file: %s" % a)

    print("\nSELF-TEST PASSED: MUSUBI clause evaluator v0, %d checks (babyblueviper1's 9 vectors; grant membership; the walk's order; limits; the file names itself by sha256)" % n)


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        print(RULES, evaluator_sha256())
