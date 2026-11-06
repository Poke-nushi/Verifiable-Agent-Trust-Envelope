# VATE recovery and retry vectors for AuthZEN #795

Compare how an implementation preserves an unknown result, recovers evidence,
and decides whether another attempt may proceed. These four cases contribute
VATE's local runtime-handoff histories to the shared test discussion in
[AuthZEN #795](https://github.com/openid/authzen/issues/795#issuecomment-6678840422).
Each case contains original input bytes, expected VATE receipts and assessments,
and separate expected PEP comparison conditions.

| Case | Variants | Expected distinction |
| --- | --- | --- |
| [1. Lost-response recovery](cases/01-lost-response-recovery/) | With and without a caller's unknown observation | Recover A's result against A's original admission and attempt; retain earlier records; do not repeat the effect. |
| [2. Accepted work interrupted](cases/02-accepted-interrupted/) | Zero effects; partial effects | Neither zero nor partial observed effects establishes nonexecution after acceptance. |
| [3. Nonexecution and handoff](cases/03-confirmed-nonexecution-handoff/) | Live worker; fenced old attempt | A live worker blocks handoff. Confirmed nonexecution and exclusion permit considering continuation under separate authorization conditions. |
| [4. A new permit](cases/04-new-permit-does-not-reopen/) | Unresolved; completed | A new local admission does not reopen the same unresolved or completed effect. |

The eight variants contain 17 saved snapshots from the existing
[runtime-handoff sample](../runtime-handoff-sample/README.md), fixed at
[`f128639`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/f1286390445bb55b92865dc21737e6e0696cee15/reference/runtime-handoff-sample).
They use two runtimes, a trusted local provider, disposable test keys, a fixed
fixture clock, and a two-file operation. No live AuthZEN PDP or PEP participates.

## Inspect a case

Each case has a `case.json` index and one directory per variant:

- `context.json` selects the synthetic provider, public test keys and policy.
- `operation.json` is the original intended operation.
- `input-history.json` orders the snapshots; each `*-history.json` is an
  unchanged provider export containing the original journal records and their
  signatures, hashes and observed inventory.
- `interactions.json` records the capture harness's local calls and responses,
  including rejected tickets, the live-worker response and the delayed attempt.
- `expected-assessments.json` contains the complete expected reader results.
- `expected-receipts.json` contains the derived VATE post-execution receipt at
  each snapshot, or `null` when none is available. `null` does not mean that the
  operation failed or did not execute.
- `expected-pep-decision.json` states the comparison conditions for dispatch.

The receipt objects have `proof.format: none`. Runtime/status signatures in the
input histories are separate proofs; they do not turn the derived receipt into
a signed AuthZEN receipt. The expected PEP conditions are test expectations,
not permissions returned by the reader. The fenced checkpoint in case 3 says
`conditional_continuation`: the integrating implementer must separately check
fresh PDP evaluation, PEP-side atomic reservation and signed receipt registration.
Those checks are not supplied by this package. The example
does not implement an AuthZEN receipt wire format or a prior-receipt-hash field.

In case 1, the pending snapshot was exported before the first submit. A fault
is injected after the provider commits its native result. The submit wrapper
reports `status: unknown` and includes a diagnostic `saved.effect_state: completed`;
both are preserved in `interactions.json`. This simulates a local interruption;
it does not exercise process termination or actual network response loss.
The later snapshot retains the earlier journal prefix and
recovers the original attempt. The first variant also retains a caller's signed
unknown observation; the second never creates one. A caller observation and an
AuthZEN receipt are different artifacts. A recovery format should include a
prior receipt hash only when an actual prior receipt exists.

To compare your implementation, map the recorded history to its own input format
and compare its receipt semantics and dispatch conditions with the expected files.
The replay command below validates the VATE fixtures; it does not accept your
PEP's output as an automated conformance test.

## Replay the fixed inputs

Use CPython 3.11–3.14 on macOS or Linux with `openssl` on `PATH`. Keep this folder
and the complete `runtime-handoff-sample/` folder as siblings. A repository
checkout or source archive already has that layout. The commands below run
from the repository root and do not install packages or contact a network service.

```sh
python3 -E -s -S -B reference/authzen-receipt-vectors/verify.py
```

Successful replay returns `status: matched`, four cases, eight variants and
17 snapshots. It checks the fixed source distribution, all input/expected-file
hashes, journal replay, original operation/admission/attempt bindings, derived
receipts and the case-specific expected states. `is_execution_ticket` stays
`false`. Exit 0 means this comparison matched; exit 2 reports an invalid or
mismatched input. Exit 3 with `status: unavailable` means that the signature
checking tool could not run; for example, `openssl` was missing from `PATH`.

`MANIFEST.json` uses raw-file SHA-256 and omits itself. Its hashes establish
fixture consistency, not publisher identity or external execution. The saved call
sequence, requests and responses are checked against the case and journal. They
remain harness observations; replay does not independently re-execute them.
To exercise the provider paths again, use the fresh-capture command below.

## Capture new local histories

This command performs synthetic local file operations in temporary stores,
creates temporary test keys, and saves only the exported inputs and expected
results. It removes the temporary stores and private keys when it finishes.
The output directory must not already exist.
If capture fails, any partial output remains for inspection; use a new output
directory for the next run. The fixed vectors are not overwritten.

```sh
python3 -E -s -S -B reference/authzen-receipt-vectors/capture.py --out /tmp/vate-authzen795-new
python3 -E -s -S -B reference/authzen-receipt-vectors/verify.py --vectors /tmp/vate-authzen795-new
```

New captures have new keys, signatures and identifiers, so their bytes differ.
The same expected states and binding checks apply.
The live-worker case uses a process rendezvous at the provider lock;
the interruption cases inject faults at named sample boundaries.

## Check changes

See [VALIDATION.md](VALIDATION.md) for the observed environments and results.

```sh
python3 -E -s -S -B -m unittest discover -s reference/authzen-receipt-vectors -p 'test_*.py' -v
```

The tests include fresh capture, fixed replay, relocated execution, original-file
preservation, and rejection of changed inputs, substituted context, modified
receipts, inconsistent calls, unexpected files, untrusted source caches and
permission relabelling. This package is a comparison aid; it is not an AuthZEN conformance suite, WG
adoption, production approval or a distributed exactly-once guarantee.
