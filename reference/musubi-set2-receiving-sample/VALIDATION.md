# Sample validation record

The results below belong to the published base sample. Validation of the
audit/dataset extension and subsequent native-output parser correction is
recorded separately in [AUDIT-VALIDATION.md](AUDIT-VALIDATION.md).

Local verification on 2026-10-23, macOS arm64. VATE source:
`f044b208bcb8046fd4aa262094b4b77271ba7b27`; Horizon Shield source:
`b85029de8d22c5246886f4f50ede03da0f54dfcf`.

Fresh wheel-only environments with 21 pinned distributions were prepared for
all three Python versions. These runs reused those environments after the
source, lock and runtime integrity checks passed.

| Check | Python 3.11.14 | Python 3.13.3 | Python 3.14.8 |
| --- | --- | --- | --- |
| Binding/negative unit checks, 26 tests | Pass | Pass | Pass |
| Real CLI and Inbox/SQLite checks, 18 cases | Pass | Pass | Pass |
| Saved-output failure and recovery, 35 cases | Pass | Pass | Pass |
| Fixed continuation guards, recovery and native replay, 11 cases | Pass | Pass | Pass |
| Environment preparation and pin checks, 11 tests | Pass | Pass | Pass |
| Actual sandboxed native integration, including output failure and recovery | Pass | Pass | Pass |
| Baseline then header-view reassessment via the example command | Pass | Pass | Pass |

All three native integrations reproduced stdout SHA-256
`18a19f8a1eb62593b857241f34c07b1d96550b93d5c9ea17184b2ac695818fbd`.
The changed-header assessment differed at `$.companion.log.anchor_depth` from
9 to 14. All 68 originals were restored from an Inbox export and replayed.
Previous assessments stayed unchanged. Two attempts to splice prior-run
references were rejected, a validly signed other-request record was marked
contradictory, and a normal upstream refusal was retained with its reason.

Synthetic successful evaluator outputs with a malformed pilot object, row arrays
or row identities are retained as evaluator errors. Record bindings remain intact,
the overall evidence state stays partial, and semantic assessments remain unassessed. Empty or duplicate row arrays keep their existing unassessed
outcome. The malformed-output probes use test doubles; these are defensive checks,
not observed failures of the pinned evaluator.

The recovery suite injects failures while writing the recovery receipt, export,
RESULT and error files, and checks a real SQLite write lock acquired just after
the assessment is committed. It verifies repeated recovery, historical-run recovery,
a recovered RESULT as the next evaluation's predecessor, rejection of mixed
run/selection/assessment/receiver/namespace references, object corruption,
incomplete runs and existing destinations. Database bytes, rows and history
heads remain unchanged during successful and rejected recovery attempts.
A copied database with substituted material-index references is rejected by
checking the pinned report's selection, review-set and snapshot identities.
Full extended RESULT files are also exercised as recovery receipt inputs.
Stored refusal, evaluator error and partial evidence retain their meanings.
An export readback mismatch is reported as a saved-output failure and can be
recovered into a new destination. A different export integrity error remains a
generic storage error, without a misleading output-recovery instruction.
Only the native evaluator is replaced by a test double in that failure suite;
the separate integration also recovers after an actual sandboxed evaluation
and confirms that recovery does not run it again.

Recovery failures after export are exercised at the recovery receipt, partial
material restoration, assessment and final RESULT writes. Each attempt leaves
the database and original receipt usable; retry into a new output restores the
same assessment and all 68 originals.

The continuation suite uses actual isolated replay for a baseline, recovers its
output without changing the database, and runs the fixed continuation command
against a source archive without Git metadata. Changed VATE source and evaluator
template metadata, a wrong interpreter and a missing database are rejected before
replay or Inbox access. These guard probes stub the downstream calls to detect
early access; the changed-descriptor case simulates the interpreter prefix while
checking a real altered descriptor. After restoring the fixed inputs, actual
continuation produces only the expected header delta and retains the prior
assessment. Both normal and recovered baseline results can be continued. An
already-extended result is rejected before replay, Inbox access or output creation.
A substituted baseline selection reference is rejected against the stored run;
that probe uses a native test double. Two output-failure probes also use a native
test double to check failures
before and after saving the new run, including a recoverable saved-output receipt.

Python 3.12 and Intel macOS were not exercised in this record. Linux and Windows
native execution are not implemented. These local runs do not establish
independent use on another person's machine or production compatibility.
Process termination, power loss and database repair are outside the tested
output-recovery contract.
