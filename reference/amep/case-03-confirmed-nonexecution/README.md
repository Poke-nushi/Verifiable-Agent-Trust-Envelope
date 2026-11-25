# Case 3 under AMEP: confirmed nonexecution, and handoff

Pinned sources:

- **VATE:** commit [`3e9c262`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/3e9c262f1131f1b3fcb5907d8dc78c85a91ab9e5/reference/authzen-receipt-vectors/cases/03-confirmed-nonexecution-handoff), variants `fenced-handoff` and `live-worker`.
- **AMEP:** commit [`957be02`](https://github.com/stafordtituss/amep/tree/957be02/interop/authzen-receipts/vate-03-confirmed-nonexecution). The packets, verdict records and keys here are copied unchanged from that folder.

## The case

- The owner admits one operation that writes two files, and runtime-a gets the first ticket.
- **`fenced-handoff`:** the provider confirms runtime-a's attempt unexecuted and fences it (generation 2). runtime-a's late submit is denied (`old_generation`), and runtime-b completes the work.
- **`live-worker`:** runtime-a is still live, so the handoff is refused (`busy`), and runtime-a completes the work itself.

**The question this answers:** what must be established before a continuation is safe? VATE requires confirmed nonexecution *and* exclusion of the old worker.

The admission is an AMEP operation approval over the digests of both file effects, as in cases 1 and 2.

## Side by side

| AMEP packet | VATE phase | What the evidence holds | AMEP | VATE |
|---|---|---|---|---|
| `f1-pending` | fenced-handoff, pending | runtime-a's signed invocation; nothing from the provider | `unresolved` (I7), gap `receipt` | `unresolved`, hold |
| `f2-fenced` | fenced-handoff, fenced | the provider signs `not_executed` for runtime-a's call | `preserved`, "nothing executed"; the admission is released | `confirmed_unexecuted`, conditional continuation |
| `f3-completed` | fenced-handoff, completed | as `f2`; runtime-b runs under the same admission, both writes signed | both calls `preserved`; the admission is used once | `completed` |
| `f4-late-write` | — | as `f3`, and runtime-a's late write lands too | `violated` (I11), blame `server`; runtime-b stays `preserved` | prevented (`old_generation`) |
| `l1-pending` | live-worker, pending | as `f1` | `unresolved` (I7), gap `receipt` | `unresolved`, hold |
| `l2-busy-rerun` | — | runtime-b runs while runtime-a's outcome is unknown | runtime-b **`unresolved`, gap `held_outcome` naming runtime-a's call** | prevented (`busy`) |
| `l3-completed` | live-worker, completed | runtime-a's two writes, signed by the provider | `preserved` | `completed` |
| `l4-rerun-after` | — | as `l3`, then runtime-b re-runs | runtime-b `violated` (I8): the admission is spent twice | expected to hold a retry of the same operation (the VATE trace ends when runtime-a completes; runtime-b's retry is the scenario AMEP adds) |

**"—" rows** show evidence VATE never records, because its provider prevents it. They ask what the evidence would show if an enforcement point let it through anyway.

## What the evidence establishes

- **Before the provider speaks,** both hold (`f1`, `l1`).
- **A signed "not executed"** is enough for AMEP to release the admission (`f2`). VATE also requires that the old worker be *excluded*. AMEP has no counterpart to exclusion: it's prevention, and AMEP evaluates evidence after the fact.
- **If exclusion fails** (`f4`), the late write contradicts the provider's signed statement, and AMEP names the provider as accountable (I11). runtime-b isn't blamed: it continued on a signed statement. Prevention (VATE) and accountability (AMEP) cover the same failure from two sides.
- **A live worker** (`l2`): if the handoff were let through, runtime-b's call is held until runtime-a's outcome is known, which is AMEP's form of "hold the same logical effect". After runtime-a's write, a re-run is a double use (`l4`).

## Check it

With the Python standard library only, from the repository root:

```bash
python3 -B reference/amep/case-03-confirmed-nonexecution/check.py
python3 -B -m unittest reference/amep/case-03-confirmed-nonexecution/test_check.py
```

These check:
1. both sides' pinned digests;
2. that the packets describe this case:
   - runtime-a holds the pinned first ticket, with no acceptance, while pending;
   - in `fenced-handoff`, the handoff confirms that attempt unexecuted and retains it, and its late submit is denied as `old_generation`;
   - the completed history accepts runtime-b's attempt (`fenced-handoff`), or runtime-a's (`live-worker`);
   - every file in AMEP's receipts is one of the operation's files, by name, SHA-256 and size;
   - the pending and fenced packets carry no receipts;
   - the completing runtime's receipts cover exactly VATE's completed inventory;
   - the expected values match the recorded provider responses in the pinned `interactions.json` (the live-worker handoff status, the fenced handoff and runtime-a's denied late submit);
   - the expected phases are exactly the pinned packets and the signed verdict records, so an omitted phase is reported;
3. that each verdict record names its packet's digest and states the expected results (`expected-results.json`).

To re-evaluate the packets with AMEP's Python verifier and verify the verdict records' Ed25519 signatures:

```bash
git clone https://github.com/stafordtituss/amep ../amep
git -C ../amep checkout 957be02
python3 -m venv .venv-amep && .venv-amep/bin/pip install cryptography
.venv-amep/bin/python -B reference/amep/case-03-confirmed-nonexecution/check.py --amep ../amep
```

To regenerate the AMEP files from scratch, run `python3 -I interop/authzen-receipts/vate-03-confirmed-nonexecution/generate.py` in the AMEP checkout.

## Licence

The AMEP files here are copied from AMEP under the Apache License 2.0; see `../NOTICE`. `check.py` and `test_check.py` are contributed under this repository's licence.
