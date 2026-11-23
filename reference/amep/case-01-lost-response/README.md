# Case 1 under AMEP: a lost response, then recovery

[VATE case 1](../../authzen-receipt-vectors/cases/01-lost-response-recovery/with-unknown-observation/) (variant
`with-unknown-observation`), evaluated by AMEP.
- **VATE:** commit [`c7533ad`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/c7533ad70c20e71b7912cdf708f33220e49c1f00/reference/authzen-receipt-vectors/cases/01-lost-response-recovery/with-unknown-observation). The case's files are unchanged at `093194d`.
- **AMEP:** commit [`765855d`](https://github.com/stafordtituss/amep/tree/765855de32d6649446d3d57ec2289b8a6e349095/interop/authzen-receipts/vate-01-lost-response). The packets, verdict records and keys here are copied unchanged from that folder.

`SOURCE-PINS.json` holds the SHA-256 of every pinned file on both sides.

## The case

runtime-a submits one operation that creates two files (`first.txt`, `second.txt`). The provider completes it, but the
response is lost, so the outcome is unknown to the caller. Later, the provider's record shows the original attempt
completed. The caller's unknown observation stays in the history.

## Side by side

| Phase | VATE | AMEP packet | AMEP verdict |
|---|---|---|---|
| Pending | `effect_state` `unresolved`; history bundle `51aded93…`. The PEP expectation is to hold the same logical effect | `1-pending`: only the caller's signed invocation, with the digest of the arguments it sent | `unresolved` I7, gap `receipt` for `i-1` |
| Recovered | `effect_state` `completed`, attempt `attempt-6919…` accepted; history bundle `b6d25add…` | `2-recovered`: the provider's signed call statement (`completed`, 2 effects) and two receipts, bound to the original invocation by its digest | `preserved` |
| Recovered, with the admission | as above | `4-approved-recovered`: as `2-recovered`, with the admission as an AMEP operation approval listing the digests of both file effects | `preserved` |
| A retry instead of holding | The provider refuses a new ticket for the operation (`repeat-ticket`, "no new ticket") | `3-retried`: a second invocation with the same arguments, which the provider also ran | `preserved` |
| A retry under the admission | as above | `5-approved-retried`: the retry spends the admission a second time | `violated` I8 |

Each AMEP verdict record is an in-toto statement in a DSSE envelope, signed by the caller's verifier key
(`verifier-key.json`). It names the SHA-256 of the packet it evaluated.

## The caller's signed observation

AMEP has no caller-signed "unknown" object. Its `unresolved` for the pending phase is derived from the evidence: the
caller's own signed invocation, with nothing from the provider bound to it. VATE's caller instead **signs** that the
outcome was unknown to it at `observed_at`. That's a statement AMEP doesn't make, so it is linked here by digest rather
than re-expressed.

| | |
|---|---|
| File | `with-unknown-observation/recovered-history.json` (VATE `c7533ad`) |
| Record | `records[7]`, kind `unknown`; record SHA-256 `fdf3e31cbb4ed8b2922a0e8080ff291570a5a153e73f908b3798dacc8ce1c84b`, as VATE records it (the SHA-256 of the decoded record) |
| Signed observation | Compact JWS, ES256, `typ` `vate-local-handoff-observation+jws`, signed by runtime-a's key in `context.json`; SHA-256 of the JWS `067fbc1edb27a7cc7bb07c73381b63e00ae3c023cdfb2735c464db2da5270c28` |
| It states | `outcome` `unknown`, `operation_id` `operation-one`, `attempt_id` `attempt-691929927987426a8b8359f6f3c572f1`, `runtime` `runtime-a`, `observed_at` `1792886400` |

A later verifier can check the caller's account and AMEP's verdict for the pending phase together:
- the observation says the outcome of this operation and attempt was unknown to runtime-a at `observed_at`;
- AMEP's `1-pending` record says the evidence the caller held then bound no provider statement to its invocation.

Neither establishes when the caller stopped waiting. That would take separate evidence.

## Where AMEP differs

- **Holding without an admission isn't an AMEP verdict.**
  - In `3-retried`, both executions are within the mandate, so the packet is `preserved`.
  - The evidence makes the double execution visible: two `completed` statements with the same `args_digest`.
  - Deciding the second run shouldn't have happened is the enforcement point's property. VATE's PEP comparison covers it; AMEP doesn't.
- **With an admission (`5-approved-retried`), AMEP decides it:** the retry spends the admission twice.
- **Recovery adds, never rewrites.** Every object of `1-pending` appears unchanged in `2-recovered`. The recovered receipts bind to the original invocation's digest, so they can't be attributed to a later attempt.

## Check it

With the Python standard library only, from the repository root:

```bash
python3 -B reference/amep/case-01-lost-response/check.py
python3 -B -m unittest reference/amep/case-01-lost-response/test_check.py
```

These check:
1. both sides' pinned digests;
2. that the caller's observation is present under the digests above, for the same operation, attempt and time as the pending phase;
3. that the ticket in `pending-history.json` (`records[1]`) and the signed observation refer to the same original attempt (`attempt-6919…`, runtime-a, `operation-one`), and that `recovered-history.json` still carries that ticket record unchanged: the same record digest, `ffa8ccc6…`, and its bytes hash to that same value. Recovery adds to the history; it doesn't replace the attempt;
4. that each AMEP verdict record names its packet's digest and states the expected outcome (`expected-results.json`).

To re-evaluate the packets with AMEP's Python verifier, and verify the signatures (the verdict records' Ed25519, and the caller's ES256 on the observation):

```bash
git clone https://github.com/stafordtituss/amep ../amep
git -C ../amep checkout 765855de32d6649446d3d57ec2289b8a6e349095
python3 -m venv .venv-amep && .venv-amep/bin/pip install cryptography
.venv-amep/bin/python -B reference/amep/case-01-lost-response/check.py --amep ../amep
```

Use the pinned commit, not the `amep-protocol` 0.3.0a1 release on PyPI. That release predates operation approvals, and
returns `unresolved` (never `preserved`) for phases 4 and 5.

To regenerate the AMEP files from scratch, run `python3 -I interop/authzen-receipts/vate-01-lost-response/generate.py` in the AMEP checkout. It asserts each verdict as it writes it.

## Licence

The AMEP files here are copied from AMEP under the Apache License 2.0; see `../NOTICE`. `check.py` and `test_check.py` are contributed under this repository's licence.
