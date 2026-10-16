# Required Record Review Contract

`vate-required-records-local-v2` is an experimental receiver-side contract.
It composes existing VATE assessments without changing their input bytes,
meaning, digest basis or capability declarations. The input document names
ending in `_design` and `design_revision: 2` identify this contract's metadata;
they are not VATE specification version numbers.

## Receiver inputs

The trusted receiving application selects the selection bytes, permitted path
bases and source root. A submission cannot choose code or the OpenSSL program.
All metadata is a UTF-8 JSON object. Duplicate keys, unknown fields, floats,
non-finite numbers, invalid Unicode and integers outside the exact JSON integer
range `[-9007199254740991, 9007199254740991]` are rejected. Boolean values are
not accepted as integer fields. Metadata depth is at most 16.

Identifiers are nonempty strings of at most 256 UTF-8 bytes, without ASCII
control characters or DEL. Times use UTC `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`, with
1–6 fractional digits when a fraction is present. Fractions are right-padded
to microseconds, not rounded. The checker does not obtain these times from a
clock or verify the truth of a receiver's time assertion.

### Raw references

Every ref has exactly these six fields:

| Field | Value |
| --- | --- |
| `path_base` | A name mapped by the caller to a permitted local directory. |
| `path` | Relative POSIX path, at most 2048 UTF-8 bytes; no backslash, control character, empty component, `.` or `..`. |
| `media_type` | Nonempty identifier describing the selected bytes. |
| `digest_basis` | `raw_file_sha256`. |
| `digest` | Exactly `{"alg":"sha-256","value":"<64 lowercase hex characters>"}`. |
| `byte_length` | Exact nonnegative raw file size within the applicable cap. |

References are local; URLs are not fetched. Resolution beneath a selected root
rejects symlink components and non-regular files, and reads bounded bytes.
The root itself is a caller-selected, resolved trust setting. The source root
and same-user processes are also within the trusted local environment; this is
not a hostile-process filesystem snapshot or operating-system sandbox.

Raw references do not replace the existing receipt object digest or signature
domain. Matching raw bytes are deduplicated only after their selected identity
and receipt basis have been checked. `input_refs` records read identities and
errors; successful cached reads can be reused.

### Selection

The selection has exactly:

- `document_type: receiver_selection_design`, `design_revision: 2`;
- `receiver_id`, `review_set_selected_at`, `snapshot_selected_at`,
  `assessment_time`, `assessment_cutoff`;
- `review_set_ref`, `submission_snapshot_ref`, `selection_basis_ref`;
- `native_policy_refs`, with exactly `s3` and `signature`, each a ref or null.

`review_set_selected_at <= assessment_time` and
`assessment_cutoff <= snapshot_selected_at <= assessment_time` are required.
The snapshot's `as_of` must equal the cutoff. A review set selected after the
cutoff is reported as `after_cutoff`; otherwise it is `before_or_at_cutoff`.
Neither value establishes selection before the deadline.

A selected policy reference must be readable and match its raw identity.
Null policy with a requested native check produces a missing-policy result;
it is not treated as an unrequested check. Signature policy evaluation time is
defined by the [signature contract](../recipient-signature-authority/CONTRACT.md),
and is not replaced by the review cutoff.

### Review set

The review set requires `document_type: receiver_review_set_design`,
`design_revision: 2`, `review_set_id`, positive integer `revision`, `namespace`,
`population_basis_refs`, `collection_scope: receiver_selected_set_only` and
`requirements`. A basis-ref list has 1–16 refs. Requirements are at most 256.
The only optional top-level fields are the three revision refs below.

Each requirement has exactly these required fields:

| Field | Rule |
| --- | --- |
| `requirement_id` | Unique identifier within the review set. |
| `subject` | `kind`, `operation_id`, `native_context`, and `attempt_id` only for attempts. |
| `record_kind` | `admission` or `post_execution`. Attempts support only `post_execution`. |
| `binding_profile` | `vate_receipt_operation_context` for operations; `vate_s3_attempt_context` for attempts. |
| `obligation` | `required`, `undetermined` or `waived_by_receiver`. |
| `basis_refs` | 1–16 refs selected by the receiver. |
| `requested_native_checks` | A possibly empty array of distinct names from the finite list below. |

The only optional requirement fields are `due_at` and `waiver_ref`.
`required` requires a deadline and forbids a waiver. `waived_by_receiver`
requires a waiver ref. Other obligations also forbid a waiver. An optional
deadline must always be a valid time.

`subject.kind` is `operation` or `attempt`. Its native context has exactly
`transaction_id`, `runtime`, `effective_request_hash` and `action_binding`.
The binding has type `profile_defined_digest`, one of the preimage profiles
below, canonicalization
`vate-v0.3-fixture-json;ascii-escaped;sorted;compact;no-floats`, and a
`sha-256` digest with 64 lowercase hex digits. The effective request hash is
`sha-256:<that same digest value>`. The original must expose this typed context
under the existing VATE receipt profile; matching a label alone is insufficient.

| Preimage profile | Admission request action | Supported subjects |
| --- | --- | --- |
| `vate-local-s3-observation-v1` | `s3.put_object` | Operation and S3 attempt |
| `vate-demo-file-set-v1` | `demo.create_file_set` | Operation only |

An admission's action must match its preimage profile. Post-execution receipts
expose the profile in their execution action binding. For file-set admissions,
select `attenuation.effective_request_hash` when `decision.outcome` is
`attenuate`, and `request.input_hash` for `allow` or `deny`. The original
input hash stays original when narrowed. Missing or unrecognized hash-selection
metadata remains unsupported. S3 admission extraction uses `request.input_hash`.
The selected hash must match the action binding digest. Unknown profiles and
canonicalizations remain unsupported. File-set operation requirements use
`vate_receipt_operation_context` and the unchanged receipt originals; they do
not accept `vate_s3_attempt_context`. The native receipt assessment remains
separate from operation-level record presence. The checker does not invoke the
file-set execution-evidence verifier or validate the complete demo artifact set.

Semantic identity uses namespace, typed context, record kind and explicit
attempt ID. The checker rejects two operation labels for the same context,
one label for different contexts, duplicate semantic subjects, and overlapping
operation/attempt requirements for the same context and record kind.

The recognized request names are `receipt_linkage`, `s3_observation_binding`,
`signatures_and_issuer_authority`, `independent_execution_observation`,
`operation_population_coverage`, and `current_permission_to_execute`.
These names do not imply support: the last three remain unsupported.

### Submission snapshot and receipt events

The snapshot requires exactly `document_type: submission_snapshot_design`,
`design_revision: 2`, `snapshot_id`, `as_of`, `inventory_state`,
`collection_basis_ref` and `entries`. Inventory is `closed`, `partial` or
`unavailable`. At most 256 entries are accepted.

Each entry requires `entry_id`, `source_namespace`, `native_input_kind` and
`originals`; optional fields are `candidate_for` and `detached_proofs`.
Entry IDs are unique. `candidate_for` is at most 256 identifier hints; hints
never establish binding, exclusion or a smaller uncertainty scope.

For `receipt_pair`, originals has exactly `admission` and `post`. For
`s3_bundle`, it has exactly all 18 names in `required_records.MEMBERS`; these
are the unchanged member names of the existing S3 contract. Each value is an
event or null for an unsupplied member. Unknown input kinds can carry up to
18 named originals and remain unknown candidates in the same namespace.
Detached proofs, when present, have exactly `admission` and `post`, each an
event or null, outside the S3 bundle.

An event has exactly `ref`, `received_at`, `cutoff_membership` and
`receipt_basis_ref`. Its time is a UTC timestamp or null.

| Membership | Receiver assertion and required time relationship |
| --- | --- |
| `included` | Present within the cutoff. If known, receipt time is at or before the cutoff. |
| `after` | Received after the cutoff. If known, receipt time is after the cutoff. |
| `unknown` | Cutoff membership is unestablished; receipt time must be null. |

Known receipt times may not exceed `assessment_time`. The membership is a
receiver-selected collection assumption, not cryptographic time evidence.
An unreadable or mismatched event basis makes that event unknown. Later
supporting files do not complete a past S3 attempt binding.

## Binding and aggregation

Candidates are `matched`, `excluded`, `unknown` or `absent`. A different
receiver namespace, a known after-cutoff event, or a different typed context
in a recognized receipt can establish exclusion. Unreadable originals,
unsupported profiles or broken identifiers in the same namespace are unknown.
An explicit null member is absent. Structural or pin errors are never repaired
to create a native success.

For a supported S3 attempt, all 18 original members must be included, readable and pinned.
The complete native S3 result must report `request_binding: matched`,
`attempt_binding: response_linked`, `post_observation_binding: matched` and
`source_trust: accepted_local_assumption`. The attempt ID must match the
selected subject, and the valid post receipt identifier must equal
`post-<attempt ID>`. A different explicit attempt ID establishes exclusion.
When the explicit attempt ID matches but the post identifier does not follow
the supported rule, the candidate remains unknown. This includes the saved
`-later-observation` suffix, other unsupported forms and malformed identifiers;
no suffix is removed to create a match. Such a candidate also prevents another
post from being treated as the only possible record for that attempt.
Operation-level presence does not require native semantic success.

After deduplicating identical raw originals:

1. A receiver waiver yields `waived_by_receiver`.
2. Undetermined obligation, non-closed inventory, unknown competitors,
   unprocessed candidates or multiple distinct matching originals yield
   `unresolved`.
3. A required row with exactly one remaining match yields `present`.
4. With no match or uncertainty, a required row yields `pending` while cutoff
   is at or before its deadline, and `missing` afterward.

All receipt events are retained. One known receipt at or before the deadline
establishes `on_time`. If only late times are known but a resend time is
unknown, timeliness remains `unknown`. For attempts, binding may be reused
only from a known matching bundle with the same 18 actual raw member bytes,
namespace and selected policy. Matching post bytes alone cannot repair an
unknown bundle. The original unknown diagnostic and reuse reference remain.

`binding_available_at` describes when all supporting S3 original receipt times
are known to have arrived; it is separate from the required record's arrival.
The required record can be present with a bad signature, denied issuer grant,
or contradictory receipt assessment. These are separate questions.

## Native calls and reports

The complete existing API responses or structured execution errors are stored
in `native_calls`. A full signature response already contains its receipt
assessment and is reused. A policy, key or OpenSSL setup failure before that
assessment is retained alongside a separate pinned receipt assessment.
Source, wrapper or API integrity errors do not permit a fallback bypass.
S3 uses fixed copies of the supplied included members without repairing its
manifest; an independently available receipt assessment is kept separately.

Native call identity includes input bytes, proofs, policy, requested checks,
source identity and environment configuration. Coverage deduplication never
selects a favorable native result among different calls. `check_support`
records the requested, statically supported and unsupported check names;
actual execution is described by the referenced calls. Core API capability
declarations and `not_checked` remain unchanged.

The report includes selected metadata and raw identities, ref read diagnostics,
full receipt events and candidates, per-requirement coverage/timeliness,
native call references and complete responses, source identities, limits,
usage, processing diagnostics and unprocessed entry IDs. It has no aggregate
PASS, trust, execution permission or `requirements_satisfied` value.

`review_set_status` is `selected`, `selected_empty`, `not_assessed` or `invalid`.
Absent selection, unavailable required selection refs and evaluation limits
can prevent assessment. Invalid structure or a mismatched selected pin is
invalid. These states do not create invented requirement results.

## One revision

Revision 1 forbids history fields. Later revisions require
`previous_review_set_ref`, `previous_report_ref` and `revision_basis_ref`.
The checker requires the same review-set ID and namespace, exactly one revision
increment, an accepted prior report under this contract bound to the previous
review-set raw identity, and a non-regressing cutoff. Old requirement IDs remain;
withdrawal uses a waiver. An existing ID cannot change subject or record kind.

The selected prior report and originals are not rewritten. History refs remain
in the new report. This is a check of one supplied revision step, not recursive
history authentication, a receiver identity service or a history database.

## Python interface and limits

`Reviewer(path_bases=..., source_root=..., openssl=None,
openssl_sha256=None, limits=None).assess(selection_bytes)` returns a report.
`None` produces a not-assessed selection result. Invalid constructor limits can
raise `Problem`; filesystem roots and executable configuration are trusted
caller inputs. Native evaluation uses the same Python interpreter with its
installed dependencies in isolated child processes.

The report records composer hashes captured when its loaded module code matches
its source bytes, and the pinned native-source manifest. Stale cached code
produces an error instead of a claimed loaded-source hash. Composer files are
checked before and after assessment and in each native worker. Updating the composer requires a fresh
Python process. Source-validation failures appear in `diagnostics` and set
`invocation_errors`, including reviews with no native calls or no requirements.
They do not erase an independently established operation-level receipt. These
checks assume caller-controlled code and storage; they are not code signing or
a defense against a process that can replace the running implementation.

| Bound | Default |
| --- | --- |
| Selection, ordinary metadata/receipt/basis file | 1 MiB each |
| Metadata / receipt JSON depth | 16 / 32 |
| Requirements / entries | 256 / 256 |
| S3 member / whole native bundle | 256 KiB / 2 MiB, inherited S3 validation |
| Signature policy / proof | 64 KiB / 4 KiB, inherited signature limits |
| Current-input ref reads | 16 MiB total, counting acquired bytes |
| Prior report / separate history-read budget | 128 MiB; JSON depth 64 |
| Native process starts | 64 |
| One native result / retained native result budget | 2 MiB / 16 MiB |
| Overall processing deadline | 60 seconds |
| Serialized report bound | 128 MiB |

`limits` can shrink `bytes`, `history_bytes`, `native_calls`,
`native_result_bytes` and `seconds` using positive integers; it cannot enlarge
defaults. The native result budget reserves capacity before starting a call.
The `usage.native_calls` counter counts stored call records, including
configuration/limit errors; it is not a count of successful evaluations.

Deadline checks cover reads, native waits, candidate comparisons and report
preparation. Native subprocesses have hard deadlines; remaining Python work
uses cooperative checks and may finish diagnostics after the deadline. It is
not an immediate timer interrupt or a complete memory-usage guarantee.
Unprocessed candidates remain unknown. An independent native failure does not
erase an already established operation-level presence, but missing native
attempt evidence cannot establish an attempt binding.

If comparison details exceed the report bound, the result is not assessed,
with requirements/counts omitted and input identities/full native results
retained. A prior report has its separate size budget so a normal generated
report larger than the metadata cap can be used in the next revision.

The CLI requires selection, caller-selected bases, source root and a new output
path. `--openssl` and `--openssl-sha256` configure optional signature calls.
It creates the report exclusively. Exit 0 means report generation; semantic
missing/pending/unresolved or native mismatches alone do not change that exit.
Exit 64 covers invalid/unavailable selected inputs, ref acquisition errors,
processing limits and native execution errors. An output-file failure prints
a structured error instead of overwriting a prior report.
