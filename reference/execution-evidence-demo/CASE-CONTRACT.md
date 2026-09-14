# Local File-Set Operation and Evidence Contract

Contract identifier: `vate-demo-file-set-v1`. This document defines the private
semantics of this reference demo. The public VATE core, schemas, and conformance
corpus keep their existing meanings.

## Operation and owners

`demo.create_file_set` creates a sorted, nonempty set of at most eight new text
files in a newly allocated sandbox. Each file has a simple lowercase `.txt`
leaf name and at most 4096 UTF-8 bytes. Contents are explicit strings; the
operation has no command, network, overwrite, directory-traversal, or arbitrary
file-read argument. A `urn:vate:demo:sandbox:...` resource names the specific
case's `sandbox/` directory; it is not a caller-supplied filesystem path.

The execution-input preimage has this shape:

```json
{
  "contract": "vate-demo-file-set-v1",
  "operation_key": "op-example",
  "action": "demo.create_file_set",
  "target": {
    "resource": "urn:vate:demo:sandbox:example",
    "files": [{"name": "summary.txt", "text": "Example text.\n"}]
  }
}
```

The controller allocates a fresh `operation_key` for explicit new intent. A
different `authorization_key` denotes a new unsigned permit instance for that
same operation. An `attempt_key` is allocated only when the execution gate
hands off. These identifiers are not inferred from matching text, filename,
or a short time window. `transaction_id` maps to `operation_key`; VATE
`request_id` maps to one authorization instance. This mapping is local to the
demo, not portable permit-successor semantics.

| Role | Responsibility and observation |
| --- | --- |
| Scenario controller | Allocates the case/sandbox, original input, local permit and policy; records the actual subprocess PID and response bytes. |
| Admission composition | Runs the existing core; applies the documented file subset rule; retains original/effective preimages and emits the final admission receipt. |
| Execution gate | Recomputes admission/preimage consistency, checks immediate eligibility and current time, compares exact candidate bytes, checks operation state and fresh provider state. |
| Separate local provider | Validates the bounded input, preserves exact stdin, creates files exclusively, rereads them, and writes its native result and invocation journal. |
| Observing adapter | Checks the returned native record, actual files and receipt linkage before generating a post-execution receipt. |
| Evidence reader | Recomputes the artifact inventory, admission, gate, input, native-record, output and state relationships from the capture. |

The provider CLI is an implementation component, not an authorization service.
Calling it directly bypasses VATE admission. Its path and no-overwrite bounds
still apply. The `provider/` and `sandbox/` namespaces contain only direct,
single regular files. Subdirectories, including empty ones, are rejected by
the gate, provider, snapshot builder and evidence reader. An invalid namespace
cannot be sealed into a manifest; a closed gate retains its candidate and
rejection record without allocating an attempt or calling the provider.
Manifest paths are relative and slash-separated. Retained provider diagnostic
names may contain spaces or Unicode. Absolute paths, drive prefixes,
backslashes, NUL, and empty, dot or double-dot path components are rejected.
This does not widen the operation's output-name restrictions.

Existing symlinks, hardlinks and non-regular evidence files are also rejected,
including the invocation journal before append. This bounds the
controlled local test; it does not defend against arbitrary concurrent changes
by an adversarial OS process.

Successful execute and query transports require a positive integer PID distinct
from the controller's PID; booleans and missing values are invalid. The native
result and both journal events must match the execute transport's PID. The query
records its own child PID, without requiring equality with the earlier execute
PID. These are local process observations, not authenticated identities. A
process-start failure can have no PID and leaves the attempt unknown.

## Admission and narrowing

The permit is a controller-owned record binding its authorization instance,
operation key, original input hash, status, and validity window. The window must
be positive and no longer than ten minutes; the demo issuer uses ten minutes by
default. Admission, the execution gate, and the evidence reader apply the same
local lifetime check. The core separately checks the stated validity times.
The permit is not a credential or a signature-verification fixture. Its bytes are retained
and hashed. `evidence_refs[].type = mission_permit` names its role; the demo
defines the local body. The final receipt records the content-binding and core
checks without asserting JOSE, PKI, or issuer authentication.

The unchanged core evaluates its request shape, hash grammar, evidence-reference
shape, time window, supplied status, runtime and action-policy conditions. Its
entire result is saved as `core-result.json`. Its evidence hooks and per-instance
replay set remain limited reference behavior. The demo does not interpret them
as proof of general evidence verification or durable replay prevention.

The file evaluator selects only candidate files whose names occur in the
verifier-owned `policy.allowed_output_names`. It preserves their order, names,
and contents. An empty permitted set yields `deny`. A proper subset yields
`attenuate`, with a single `/target/files` replacement, both preimage hashes,
effective constraints, and `require_new_permit`. An unchanged set yields
`allow`. If a policy requires a new permit but supplies no actual narrowing,
this limited evaluator denies rather than inventing an attenuation.

`attenuation.changes[].path` is relative to the execution-input preimage above,
not the complete VATE admission request. `demo_output_names` is a local
constraint evaluated by this demo; `demo_evidence` is a local post-receipt
extension. Existing schemas permit these shapes, but do not define their file
semantics. There is no new public schema field or general JSON Patch executor.

The gate checks a fixed list of obligations, records only checks actually
reached, and stops on the first failure. Missing, unknown, or malformed policy
fields are rejected. An empty check or violation list cannot establish that the
required checks ran. Current status is the supplied local permit status; there
is no live external revocation service.

Each gate record embeds the provider/sandbox `provider_snapshot` observed before
its checks, alongside its time, authorization, candidate digest and prior-attempt
binding. This observation is retained even when admission denial stops the checks
early. If reached, `fresh_local_provider_state` compares that snapshot with the
initialized empty state. A closed gate allocates no attempt and saves a separate
`after-dispatch-snapshot.json` before returning. The reader requires the gate,
after-refusal and currently inspected bytes to agree. A regular file present
before the gate can therefore be preserved and inspected without attributing it
to this operation. Changed, added or deleted files after refusal fail this check,
even if the artifact manifest is regenerated. An unsafe or missing namespace may
leave a rejection record with a null snapshot, but cannot establish a complete,
verified refusal.

Before classifying a closed gate as unused, the reader also examines the known
provider original paths. Recognizable demo received/native records, current
operation/admission references, or execution-journal events require their
companion originals. Missing received/native/journal files yield `incomplete`;
inconsistent present records yield `invalid`. A retained execution journal with
no operation-attribution originals cannot establish zero calls. The known event
names `execute_received` and `completed` trigger this check independently of
their attempt or digest fields; required-field validation follows recognition.
The recognition parser keeps duplicate object members and skips numeric
conversion. A known top-level event therefore cannot disappear because another
field is a float, an unsafe or very long integer, or a duplicate member. This
same parser preserves known-contract and current-operation reference cues in
received/native originals, including the received operation and target. Duplicate
references are all inspected. It establishes only an evidence cue; after
recognition, the original bytes undergo strict contract decoding and record
validation. An unreadable JSON object or a recognition
nesting-limit failure yields `invalid`, never a zero-call conclusion. Ordinary
opaque files and unrelated text or structured diagnostic logs remain preserved
as pre-existing bytes. Nested diagnostic fields and strings that mention an
event name are not top-level execution events.
Recognition uses the standard library's UTF-8, UTF-16 and UTF-32 encoding
detection and byte decoding, with or without BOMs. On Unicode decoding failure,
replacement-decoded text is only a cue that an object cannot be classified;
such an object yields `invalid`. Recovered text never becomes contract evidence.
Journal recognition locates CR/LF at the detected code-unit boundaries before
decoding each record. It does not split Unicode separator characters inside
JSON strings. Strict journal checks still use the original canonical bytes.

For a retained demo execution, the reader checks canonical received/native bytes,
operation/authorization/attempt and admission/input digest links, typed process
observations, and both journal projections and raw digests. A reference to the
current operation, resource, authorization, admission receipt or effective input
contradicts its `not_started` claim, including when an earlier authorization was
used for that same operation. The complete native output list must exactly match
the names, UTF-8 byte sizes and content digests derived from the retained received
operation's explicit text. The expected list is computed solely from that text.
Consistent records for a different operation can
remain pre-existing; their start, finish and completion order must place them
before the claimed gate snapshot. This attributes retained records and checks
their consistency. It does not authenticate the earlier execution, validate its
old authority, assert that this operation created its files, or require its old
output bytes to have remained unchanged before the current gate snapshot.

## Byte and hash table

Structured JSON files written by the demo use the VATE v0.3 fixture JSON byte basis: sorted keys,
compact separators, `ensure_ascii=True`, `allow_nan=False`, encoded as UTF-8,
with no trailing newline. The demo additionally rejects duplicate members,
floating-point tokens, and integers outside the safe-integer range. This is
not RFC 8785/JCS. File text is encoded directly as UTF-8, without newline or
Unicode normalization. See [digest-basis.md](../../docs/conformance/digest-basis.md).
JSON nesting limits depend on the Python runtime. Parsing or encoding recursion
failures become invalid-input errors without changing its recursion limit.
The reader still emits a JSON verification report; an unusable deep query
response preserves the recorded unknown attempt and retry prohibition.

| Field or edge | Exact selected preimage and basis |
| --- | --- |
| Admission request and receipt `request.input_hash` | Original execution-input object using the JSON basis above. It stays original when narrowed. |
| Decision record `admission_request_object_hash` | Entire VATE admission-request object, including evidence descriptors, identity, timestamps and the original `input_hash`. |
| `attenuation.original_request_hash` | Original execution-input object, not the entire admission request. |
| `attenuation.effective_request_hash` | Explicit retained effective execution-input object. No reconstruction from receipt text. |
| Receipt `request.action_binding` | `profile_defined_digest` with this contract identifier; the effective execution-input object, or original object for a deny. |
| Wire input | Entire canonical dispatch envelope. It adds authorization, attempt, runtime, receipt digest and effective-input hash to the explicit `operation` object. The gate's candidate bytes are serialized once into this envelope; exact sent bytes must equal exact provider-received bytes. |
| Native `input_hash` | The actual received envelope's `operation` object using the same JSON basis. |
| Post `execution.effective_request_hash` and `action_binding` | Same effective execution-input preimage as admission, checked against the native input and retained candidate. |
| Post `admission.digest` | Complete admission receipt using the JSON object basis. Its canonical file bytes have the same digest in this demo. |
| Output file `digest` | Each actual file's raw bytes, reread from the sandbox. |
| Post `result.output_hash` | JSON object `{"files": [...]}` with the sorted observed file manifest: name, raw byte size, and raw SHA-256 descriptor. |
| Manifest entries, provider input/native references | Exact raw file bytes. JSONL journal entries include their actual newline separators. |

The provider serializes its native result once and uses that same buffer for
the saved original, completion-journal digest and response. The adapter and
reader require those native bytes to use the JSON basis above. The post receipt
hashes the retained native bytes directly; reserializing an equivalent object
does not substitute for the original bytes.

The adapter and evidence reader check the real output set and file contents
against the effective input, then compare the native manifest and receipt
projection. A producer's `outcome: success` or `policy_violations: []` cannot
replace these observations. Tests include a false-success mutation that updates
the downstream hashes and receipt while leaving the admitted input unchanged.

The adapter's execute and reconciliation paths use the same native validation
as the reader: exact native fields and contract, original dispatch/attempt and
admission bindings, positive process IDs, the two journal event projections and
digests, execution/admission time ordering, and actual file contents. These
records are available before a post receipt is issued. The reader additionally
checks the later snapshots, retained controller states and post receipt.

Current and retained native records share structural validation before their
bindings are compared: the fixed contract and runtime, local identifiers, string
resource, positive integer PID, UTC timestamps, and `sha-256:` input-hash grammar
are required. `received_digest`, `admission_digest`, and every file digest have
exactly `alg` and `value`, with `sha-256` and 64 lowercase hexadecimal characters.
Native files contain 1..8 entries with safe, sorted, unique leaf names and bounded
integer sizes. The native format records only `outcome: success`; an unusable
or missing success record cannot establish a terminal receipt. Matching malformed
values in two records does not satisfy these structural checks.

Numeric fields require actual integers, not booleans. Byte sizes are nonnegative
and bounded by the artifact limit (2 MiB), or 4096 bytes for an output file.
This applies to the manifest, snapshots, native/query file inventories and post
side effects before comparing them with observations. Transport `returncode`
accepts safe signed JSON integers: `0` is a successful process exit; any other
integer is an unsuccessful exit. `null` means no exit code was obtained, such
as a start failure or timeout. A known exit code requires an observed child PID.
An unsuccessful or unavailable exit code does not establish non-execution.
A successful exit does not establish response acceptance either. Execute must
return the exact native original. Query must return the observed-response fields,
matching operation/attempt keys, exact original bytes carried in base64, and the
strictly typed current file inventory. The live adapter and reader use these same
response checks separately from validation of the native originals.

## Attempt state and reconciliation

The controller's operation slot lives in memory for one sequential run. The
files are an audit capture, not a restart-safe transaction store.

| Event | Controller observation | Immediate action |
| --- | --- | --- |
| Gate closes | `not_dispatched`; no attempt allocated | Preserve gate and leave the current provider/sandbox contents unchanged. |
| Gate opens | Attempt allocated; `indeterminate` recorded before subprocess dispatch | Send exactly the validated candidate. |
| Valid native response and actual output checks | `confirmed_success` / `created` | Emit a terminal post-execution receipt linked to that attempt. |
| No usable response, including controlled response loss | `indeterminate` / `unknown` | Preserve the attempt without fabricated finish time, result output or terminal receipt. |
| Same or fresh authorization after dispatch | Original attempt remains bound to the operation | Gate blocks another dispatch, including after confirmed success. |
| Read-only provider query returns matching original evidence and files | `confirmed_success` / `created` for the original attempt | Emit its terminal receipt and preserve the previous unknown observation. |
| Query lacks required provider evidence | Outcome remains unknown | Keep retry closed; no success or non-execution inference. |

The controlled loss occurs after the provider creates files, saves its native
result, and logs completion, but before it returns stdout. The controller
observes an empty response even though the test reader can see provider
originals. A truncated nonempty response or an unrelated JSON response also
leaves the attempt unknown. Offline verification reports the controller's retained unknown
state until a captured reconciliation establishes its terminal observation;
it separately lists the locally inspected files. The verifier does not itself
advance controller state or authorize retries.

The reader recalculates response rejection from the captured stdout, transport
and checked originals, then compares it with the saved unknown state and reason.
A valid response cannot be relabelled unknown by changing only controller claims.
A failed response cannot support a terminal receipt. Native originals, execution
bindings, process records, snapshots and actual files still undergo their required
checks: invalid originals yield `invalid`, and missing originals yield `incomplete`.
Preserving a faithfully recorded unusable response does not relax those checks.

The query returns the original received bytes, original native result bytes,
and a fresh read of current output files. It does not enter the execution path
or append provider records. Before/after snapshots cover provider and output
bytes; tests also check no additional invocation or file appears. The adapter
saves query evidence outside those trees. An unusable query response, including
empty, truncated or mismatching bytes, preserves the original unknown attempt
and emits no terminal receipt. One query is exercised per run.

Both `attempt-observation.observed_at` and `reconciliation.observed_at` mark the
start of processing a returned response, before native validation and post
receipt issuance. They are not timestamps of terminal receipt emission. The
reader requires the local sequence: execute return, original observation, then
query return, reconciliation observation, and post issuance. When a fresh
authorization/retry gate is captured in this flow, its evaluation and gate
check occur between the original observation and query return. A direct success
also requires post issuance at or after its response-processing observation.
These checks use the captured local UTC timestamps, not a distributed clock
or a cross-host ordering guarantee.

Raw transport captures retain the bytes actually received. The execute response
must equal the canonical native-result bytes, while the query response wrapper
is decoded and checked for its fields, original received/native bytes, and
current file observations. The wrapper's whitespace and UTF-8/16/32 encoding
are not required to match the demo's JSON serialization. This does not relax
the canonical-byte checks on the embedded originals or their digest bindings.

Creating multiple files is sequential, not transactional. Unexpected I/O errors
can leave partial effects or incomplete provider evidence; the controller then
keeps an unknown result. Concurrent writers, general process-crash recovery,
host restart, distributed state and exactly-once execution are outside this
contract. Evidence corruption never resets the operation to unused.

## Evidence roles and reader questions

Expected outcomes live in `test_execution_demo.py` and this scenario contract.
The provider never reads them. The generated directory separately retains
scenario inputs, admission artifacts, provider originals, adapter records,
actual outputs, the raw artifact manifest, and recomputed verification.

`provider_files_observed` lists files actually inspected in `sandbox/`, including
files preserved by a closed gate. The manifest's `actual_output` role names that
storage location; it does not attribute every file there to this attempt. For a
verified refusal, `provider_execution_count: 0` and `effect_state: not_started`
refer to the requested operation, while a nonempty observed-file list can report
pre-existing files. The embedded gate snapshot and after-refusal snapshot support
this distinction; file presence alone cannot establish a verified refusal.
Retaining same-operation execution originals while replacing adapter records
with a refusal is an inconsistent capture, even when its manifest and snapshots
are regenerated. It is not covered by the limit on authenticating fully rewritten,
self-consistent histories.

`source.json.files` is compared with the reader's current source-file bytes.
The producer and reader share `demo_contract.REQUIRED_SOURCE_FILES`, an explicit
12-file reference-package snapshot: demo `admission.py`, `demo_contract.py`,
`provider.py`, `run_demo.py`, `test_execution_demo.py`, `verify_evidence.py`,
`README.md`, `CASE-CONTRACT.md`; core `vate_verifier_core.py`; and schemas
`admission-request.schema.json`, `admission-receipt.schema.json`,
`post-execution-receipt.schema.json`. Inclusion of tests and documentation is a
provenance requirement, not a claim that each is a runtime import dependency.
Every listed file must be read as a single regular file within the existing size
bound; no glob, existence filter, or producer declaration defines the set.
A missing file stops recording. At verification it is `incomplete`, with no
source match, even if its declaration is also removed. Missing, extra, or changed
declarations with all files present are `invalid`. Additional files on disk are
outside this fixed snapshot; adding one to `source.json.files` does not extend
the contract. Future additions require explicitly updating the shared list.
If a required Python file is absent before the CLI can import, startup fails
without a success result; a structured JSON report is not guaranteed there.
The report labels this result in `provenance.source_content`. It separately
lists producer-reported fields, including `base_commit` and `python`, under
`provenance.producer_claims` with status `unverified`. These fields are not
authenticated evidence of the historical execution environment. Comparing them
with the reader's present commit or Python would not establish that history,
so no such equality is required. New source records omit `python_executable`;
the verifier does not echo producer-claimed executable paths in its report.
Git is optional producer metadata. If it is unavailable or cannot report a
commit, `base_commit` is `null`; source-file digests are still required and checked.

These demo cases are not registered in a VATE corpus snapshot, so no
`vate-sut-results-2026-09` result or `generated-receipts` corpus-comparison claim
is emitted. The generated admission and post-execution documents can be checked
against the existing schemas; the demo verifier adds the local operation
semantics. The [SUT contract](../../docs/conformance/sut-adapter-contract.md)
still governs actual corpus comparisons.

For a reader walkthrough, answer the same questions using the native files and
this mapping table, then the VATE receipts and the same source information:

| Question | Primary captured evidence |
| --- | --- |
| Which operation was requested and which input reached the provider? | Original/effective preimages, dispatch, provider received bytes. |
| Which files are present, and what did this operation create? | Inspect actual sandbox bytes. For a dispatched attempt, compare the effective input and native result; for a refusal, compare the gate and after-refusal snapshots and report preserved files separately from this operation's effects. |
| Can another permit execute this operation immediately? | Admission eligibility, gate, original attempt observation and retry gate. |
| What evidence is missing or inconsistent? | Required artifact inventory plus semantic checks, never a missing-file-to-zero conversion. |
| Which parties are trusted? | Local source pins, controller/process records, permit and policy origins, and unsigned receipt issuer roles. |

The manifest is also mutable and unsigned: detecting an inconsistent capture
does not make a fully rewritten, self-consistent capture authentic.
