# Receiving contract: MUSUBI set2 sample

The opt-in local audit/dataset profile is specified in [AUDIT-CONTRACT.md](AUDIT-CONTRACT.md).
The contract below describes the unchanged base behavior when that profile is absent.

The adapter receives the fixed Horizon #51 set2 originals, binds them to explicit
receiver selections, runs a pinned upstream evaluator, and stores the inputs and
assessments in a VATE Inbox. It adds no normative VATE schema or semantic profile.

## Inputs and authority

`sample/manifest.json` records the repository, commit, relative paths, raw SHA-256
and lengths of 68 originals. Its acquisition timestamps are local retrieval
records, not independent arrival-time evidence.

`selection.json` selects the receiver, namespace, experiment/run labels,
assessment time, bundle and reference output digests, log ID and checkpoint,
request occurrences, criteria/checkers and required record candidates. Labels
are not signed identity attributes. Trust and an optional header view are
receiver-selected; the bundle cannot silently choose a new trust root.

`evaluator-template.json` fixes the upstream source files, entrypoint, packages
and dependency lock. Preparation verifies those inputs and creates a local
`evaluator.json` with runtime file, symlink, interpreter and launcher hashes.
Replay verifies that selected descriptor; it neither installs dependencies nor
silently refreshes pins. Original evidence never selects executable code.

The fixed-sample commands `run_example.py` and `continue_example.py` check the
prepared interpreter, evaluator template and `vate-source.json` file pins before
native replay or database access. Continuation requires an existing database and
the saved baseline's `RESULT.json`. Its selection reference must match the
fixed baseline serialized with the adapter's `encoded()` representation, and
must belong to the stored predecessor. An extended predecessor is rejected
before replay or storage. Continuation checks the extended result against the
sample's expected header delta. The lower-level `receiving.py` API accepts
explicit inputs and is not the fixed-sample continuation entry point.

## Binding and digests

A request is identified by its whole object, including type and occurrence ID.
Every entry of a candidate execution/payment/criteria file must match an entry
in the fixed bundle, bind to the selected request, and match the selected item
digest. Criteria also bind the criteria digest and checker. Filenames do not
establish A/B/C identity. A valid signature for another request is insufficient.

Raw-file SHA-256 and inner-object JCS SHA-256 are separate fields. Object
comparison uses a bounded JCS subset: ASCII strings, safe integers, booleans and
null. Floats, duplicate keys, unsafe integers and non-ASCII input are rejected
rather than approximated. This is not a general JCS implementation.

## States

Per-record binding is `bound`, `not_received`, `unsupported`, `ambiguous`,
`contradictory` or `not_selected`. Multiple candidates do not overwrite each
other. Unknown acceptance/audit/rail formats can be retained as originals while
their meaning remains unsupported. Unresolved selected requirements yield
`partial`; a fully bound selected set yields `selected_records_bound`.

Native evaluation is separate. A typed settlement and its exit code must agree.
Normal upstream rejection is `refused`, with the reason and full output retained.
Unexpected exits or malformed output are `evaluator_error`; record semantics
are `unassessed`. Input, manifest, configuration and storage failures stop as
`input_or_storage_error`. Execution errors are never missing evidence.
Successful native output must contain a pilot object and the three consumed row
arrays, with object rows carrying an integer sequence and request digest.

`within_delegation`, `budget_exceeded` and `accepted: null` retain their distinct
upstream meanings. Inbox core uses empty foreign requirements/native calls and
reports `selected_empty`; the adapter supplies the foreign binding assessment.

## Replay and history

The baseline compares exact stdout bytes with the reference settlement plus one
newline. Changed trust or header conditions produce another assessment with
explicit input/output differences; matching the old digest is not required.
`comparison.output_changes` and the continuation summary's `header_delta` are
relative to the fixed reference settlement. `changed_selection` compares the
actual stored predecessor's selection with the new selection.
The assessment time is receiver metadata, not an injected upstream clock.

Each reassessment must reference the current predecessor in the selected Inbox,
namespace and source identity. Its assessment, selection and original index must
belong to that saved run. Valid references from different runs cannot be spliced
together. Original inputs and previous assessments remain unchanged. Export can
restore exact originals for replay, with the selected runtime supplied separately.

## Saved output recovery

After a completed Inbox run, the adapter emits a recovery receipt before export
and final result output. `saved_output_error` distinguishes an output failure
from an unconfirmed database write. The receipt binds the run ID, receiver,
namespace, selection, assessment and core report. It is a local locator with
digest checks, not a signature or a new assessment.
An export write/read-back mismatch after completion also returns
`saved_output_error` with this receipt. Other export integrity failures retain
their storage-error classification.

`recover_output.py` accepts that receipt and an existing database. It follows the
stored run/job, selection and application index, checks the digest-addressed
objects and reconstructs output in a new directory. It does not register another
receipt, prepare another assessment or run the native evaluator. It changes no stored object or history
head; a historical run can be exported without becoming current. SQLite's
existing export transaction still requires access to the database and its
directory; this is not an OS-level read-only mount implementation.

Saved evaluation states and comparison data are retained, including refusal,
evaluator error and partial evidence. `output_recovered` reports output
reconstruction, not semantic success. A recovered evaluator error returns 64.
An inconsistent receipt, corrupt object, incomplete run or unavailable source
fails as `output_recovery_error`. The selected VATE reader source must match
`vate-source.json`; recovery does not require native replay or refresh its
runtime pins. It uses the saved evaluator descriptor as evidence.

The operation reconstructs one completed run, not the two-run wrapper's summary
or an interrupted evaluation. Filesystem causes must be fixed by the operator.
Missing recovery receipts after process termination, power loss and database
repair remain outside this sample's recovery contract.

## Execution boundary

Native replay requires macOS sandbox-exec. It denies networking, limits writes
to the run directory, and denies reading other home files and Keychain access.
The runtime and a working copy of pinned source remain readable. Permission
probes run before native evaluation; failure stops evaluation without an
unsandboxed fallback. Interpreter/launcher and installed-file pins do not cover
the entire host OS or standard library.

The wrapper is a fixed-source example, not a service or a live-source monitor.
New record formats require their own contract and tests before interpretation.
This sample does not establish production readiness or general compatibility.
