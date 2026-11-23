# Case 2 under AMEP: accepted work, interrupted

Pinned sources:

- **VATE:** commit [`093194d`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/093194d5406a5b70358687aee6ba024bda825caa/reference/authzen-receipt-vectors/cases/02-accepted-interrupted), variants `zero-effects` and `partial-effects`.
- **AMEP:** commit [`160159d`](https://github.com/stafordtituss/amep/tree/160159d/interop/authzen-receipts/vate-02-accepted-interrupted). The packets, verdict records and keys here are copied unchanged from that folder.

## The case

- The owner admits one operation that writes two files.
- runtime-a's attempt is accepted, then interrupted.
- **`zero-effects`:** the provider's inventory is empty. **`partial-effects`:** it holds `first.txt` only.
- VATE keeps both `unresolved`. Its enforcement point should hold the same logical effect, including after the work is handed off to runtime-b.

**The question this answers:** after acceptance, what does the evidence establish when we see one of the two writes, or neither?

The admission is an AMEP operation approval over the digests of both file effects, as in case 1.

## Side by side

| AMEP packet | VATE | What the evidence holds | AMEP |
|---|---|---|---|
| `z1-interrupted` | zero-effects, interrupted | runtime-a's signed invocation; nothing from the provider | `unresolved` (I7), gap `receipt` |
| `z2-handoff-rerun` | zero-effects, after handoff¹ | runtime-b re-runs the operation under the same admission | runtime-a `unresolved` (`receipt`); runtime-b **`unresolved`, gap `held_outcome` naming runtime-a's call** |
| `z3-not-executed` | — | the provider signs `not_executed` for runtime-a's call | `preserved`, "nothing executed" |
| `z4-late-write` | — | as `z3`, then a receipt for that call appears | `violated` (I11), blame `server` |
| `p1-interrupted` | partial-effects, interrupted | one signed receipt, `first.txt`, matching VATE's inventory; no call statement | `preserved` |
| `p2-promised-two` | — | the provider's statement says `completed`, 2 effects; one receipt is present | `unresolved` (I7), gap `receipt` |
| `p3-handoff-rerun` | partial-effects, after handoff¹ | runtime-b re-runs both files under the same admission | runtime-a `preserved`; runtime-b `violated` (I8) |

**VATE marks some rows "—"**: these show what further evidence would establish, and VATE doesn't record them.

¹ **In VATE, this re-run doesn't happen.** The handoff retains runtime-a's original attempt, and runtime-b's request for a new ticket is refused (`repeat-ticket`: "no new ticket"). B's re-run under the same approval is the scenario AMEP adds: it asks what the evidence shows if an enforcement point lets the re-run through anyway.

## What the evidence establishes

- **Neither write seen.** The same answer as VATE: zero observed effects isn't nonexecution, so the call is `unresolved`, and the missing evidence is named.
- **One write seen.** AMEP's `preserved` answers a different question from VATE's `unresolved`: the write that happened was within authority. It doesn't say the operation finished. Only the provider's own statement makes the incompleteness visible (`p2`). So for "is this operation done?", VATE's `unresolved` is the right answer, and AMEP doesn't replace it.
- **A signed "not executed".** AMEP takes the provider's statement at its word (`z3`). VATE records no such statement in case 2, and with the evidence on record its accepted attempt stays `unresolved`. VATE reports `confirmed_unexecuted` in a different situation: in case 3's `fenced-handoff`, the old attempt has no recorded acceptance and the old worker can no longer write (its late submit is denied as `old_generation`). AMEP's answer to a late write is accountability, not prevention: the receipt contradicts the statement, and the provider is blamed (`z4`).
- **The handoff.** When runtime-b re-runs the work under the same admission:
  - if runtime-a's write is known, the admission is spent twice: `violated` (`p3`);
  - if runtime-a's outcome is unknown, runtime-b's call is `unresolved` until it's known (`z2`). That's AMEP's form of holding the same logical effect, when an admission exists.

## What this case changed in AMEP

`z2` exposed a gap. In AMEP 0.3.0a2, runtime-b's re-run came out `preserved` while runtime-a's outcome was unknown. Only later evidence would have revealed that the single-use admission was used twice. AMEP now **holds an approval** cited by a call with no receipts and no `not_executed` statement, within a packet and across packets (AMEP spec 5.10, held approvals; commit [`56759a2`](https://github.com/stafordtituss/amep/commit/56759a2), with five new conformance vectors). Case 1 led to operation approvals in the same way.

## Check it

With the Python standard library only, from the repository root:

```bash
python3 -B reference/amep/case-02-accepted-interrupted/check.py
python3 -B -m unittest reference/amep/case-02-accepted-interrupted/test_check.py
```

These check:
1. both sides' pinned digests;
2. that the packets describe this case:
   - each variant's accepted record is runtime-a's pinned attempt;
   - VATE's inventory after the handoff is empty, or `first.txt` only, and the handoff retains that attempt;
   - every file in AMEP's receipts is one of the operation's files, by name, SHA-256 and size;
   - runtime-a's receipts cover exactly the files in VATE's inventory;
3. that each verdict record names its packet's digest and states the expected packet verdict and every invocation's result (`expected-results.json`), including runtime-b's `held_outcome` in `z2`.

To re-evaluate the packets with AMEP's Python verifier, and verify the verdict records' Ed25519 signatures:

```bash
git clone https://github.com/stafordtituss/amep ../amep
git -C ../amep checkout 160159d
python3 -m venv .venv-amep && .venv-amep/bin/pip install cryptography
.venv-amep/bin/python -B reference/amep/case-02-accepted-interrupted/check.py --amep ../amep
```

Use the pinned commit, not the `amep-protocol` 0.3.0a2 release on PyPI. That release predates held approvals, and returns `preserved` for runtime-b's call in `z2`.

To regenerate the AMEP files from scratch, run `python3 -I interop/authzen-receipts/vate-02-accepted-interrupted/generate.py` in the AMEP checkout. It asserts the packet verdict and every invocation's result as it writes them.

## Licence

The AMEP files here are copied from AMEP under the Apache License 2.0; see `../NOTICE`. `check.py` and `test_check.py` are contributed under this repository's licence.
