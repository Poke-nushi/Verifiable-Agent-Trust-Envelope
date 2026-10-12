# Local S3 observation contract

Identifier: `vate-local-s3-observation-v1`. This implementation contract composes
with existing VATE admission and receipt checks. It does not change normative
schemas, decision values, reason codes or digest rules. Exact field sets are
implemented in `contract.py` and `assess_observation.py`.

## Operation and inputs

The operation is a conditional single-part `s3.put_object`, with a body of
0–4096 bytes, a receiver-selected endpoint profile and bucket, and a single
ASCII key component. Keys `.` and `..` are rejected. PUT uses `If-None-Match: *`;
an attempt file is created exclusively before dispatch. This is not a distributed
replay-prevention or exactly-once mechanism.

A usable successful response requires HTTP 200, curl exit 0, no capture error
and a nonempty version ID other than `null`. GET uses separate read credentials.
The offline assessor never follows a URL or loads executable code from a bundle.

| Original | Role |
| --- | --- |
| `effective-request.json` | Operation, target, input digest/length and create condition; excludes the version learned after PUT |
| `permit.json` | Unsigned local permit binding the request hash, operation, active status and validity window |
| `admission-request.json`, `admission-decision.json`, `admission.json` | Core input and decision, and a local admission receipt carrying action bindings; reconstructed during assessment |
| `attempt.json` | Pre-dispatch operation/attempt/transaction/runtime, admission digest, request hash, target, body reference and time |
| `put-request.json`, `put-transport.json` | Method, target, condition, attempt/body references, capture times, status and response references |
| `get-request.json`, `get-transport.json` | Target, requested/returned version, collector, times, status and response references |
| `put-body.bin`, `put-response-body.bin`, `get-body.bin` | Sent body, PUT response and actual read-back body |
| `put-headers.txt`, `get-headers.txt` | Response header bytes emitted by curl; status, version and length are parsed again during assessment |
| `post.json` | Unsigned post-execution receipt created by the adapter from observations |
| `sources.json`, `manifest.json` | Capture/checker source hashes, inventory and raw artifact hashes |

The headers are curl's captured representation, not an independent wire trace.
Sources and manifests check local integrity; they are not signatures.

## Digests and file handling

JSON object hashing uses sorted keys, compact separators, ASCII escaping and
SHA-256, consistently with the reused VATE checker. Raw file descriptors hash
the exact bytes and record their lengths. The contract rejects floats, duplicate
JSON keys and boolean values used in place of integer lengths.

The assessor opens one bundle directory and reads a bounded flat set of names
through its directory descriptor. It rejects symlinks, nonregular files, extra
names, files larger than 256 KiB, aggregate bytes larger than 2 MiB, and inventory,
digest or length differences. Missing originals and contradictory references to
present originals have distinct diagnostics.

## Request, attempt and result binding

The admitted request and body are checked again before dispatch. Immediately
before invoking curl, the collector checks its current time against the admission
window again. A known expiry aborts the invocation and records `DispatchAborted`
with no curl exit/status. This local check does not impose a server-side deadline.
The assessor
reconstructs the admission from the permit and effective request, compares the
core inputs/decision, and binds the recorded attempt and PUT to that admission.

A result view contains the contract, endpoint profile, bucket, key, observed
version ID, read-back body digest and byte length. Its object hash becomes
`result.output_hash`. A supported success post must contain exactly one matching
`s3.put_object` side effect, outcome `success` and no policy violations. The
comparison preserves JSON types and checks the whole result object.

Transaction, runtime, request hash and action binding must agree across the
admission, attempt and post. Execution start/end must match PUT capture times.
PUT must fall inside the admission window, GET must start after the PUT response,
and the post must be issued after GET completes. These are collector clock
checks, not independent timestamps from inside the storage service.

## Outputs and precedence

`receipt_check` contains the unmodified output of the existing Receipt Linkage
Example, including its reasons and `not_checked` list. Added fields are
`request_binding`, `target_observation`, `attempt_binding`,
`post_observation_binding`, `source_trust` and `version_scope`.

`source_trust` requires a receiver policy outside the bundle that explicitly
accepts this local unsigned collector/store and target. Its source hashes must
equal both the captured source hashes and the currently installed local files.
A source change therefore requires new evidence; old captures are not silently
relabeled as results of a newer implementation.

| Assessment | Meaning |
| --- | --- |
| `supported_under_local_assumptions` | Receipt/request/target/post match, the attempt is response-linked, a specific version is observed, local trust is accepted and no diagnostic remains |
| `contradictory` | Readable known-contract records disagree about a target, version, body, reference or time |
| `insufficient` | Required originals, version, source or trust policy are missing/invalid, or bundle integrity cannot be established |
| `unsupported` | The bundle or a required component uses an unknown contract or unsupported result semantics |

An unknown bundle contract, receiver-policy contract, or receipt version/profile
is unsupported; a damaged manifest/bundle is
insufficient. Among readable components, confirmed contradictions take precedence,
then unsupported semantics, then insufficient evidence. Unknown components are
not interpreted using the known contract's rules. Diagnostics from other readable
components remain available.

Posts with outcomes `failed`, `partial_success` or `cancelled` have no supported
result projection here. Observing an object is not enough to call such a post
false. A latest-object GET after loss of the PUT response can match the expected
bytes while leaving the attempt unknown and the assessment insufficient.
403, 404, timeout and 5xx observations do not prove non-execution or absence.
Incomplete transfers may retain headers and only part of the body. Their short
body, or missing curl status output, is insufficient evidence rather than a
contradiction; contradictory references or targets remain independently reportable.
Every assessment has `retry_authorized: false`.

## Trust boundary

The permit, receipts and captures are unsigned and controlled by one local
operator. A party able to regenerate all records consistently can fabricate
such a bundle. TLS, JOSE/PKI, independent provenance, durability, concurrent
writers and completeness of all side effects are outside this example.

Capture is specific to the pinned SeaweedFS fixture. Assessment is a separate
offline step, but reuse with another implementation requires checking its native
response semantics and receiver policy; a field mapping alone establishes neither.
