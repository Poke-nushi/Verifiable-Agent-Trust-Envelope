# External Evidence Vector Pins

## Status

This document records pinned external evidence vector slices that may be useful
for VATE corpus review.

These source slices are non-normative review inputs and do not imply VATE
certification, create a dependency on the external project, or substitute
adjacent protocol identifiers for VATE digest descriptors. Unless a section
explicitly says otherwise, they are referenced rather than carried in the VATE
conformance corpus. A carried source file binds only the named bytes; any VATE
case derived from it remains a separately labelled VATE projection and does not
adopt the external project's full semantics.

Any `canon_pin`, `canon_version`, or other native canonicalisation identifier
recorded below is source metadata for referenced or candidate external material.
It is not a VATE canonicalisation profile, does not alter the VATE digest basis,
and does not by itself make that canonicalisation discipline a VATE dependency.

## AlgoVoi JCS Conformance Vectors - First Slice

Source repository:

- `https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors`

Pinned commit:

- `abd612d05c6164e791faabefaa15cffe7ad2af4a`

Source discussion:

- `https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2#issuecomment-4806833659`

License:

- Apache-2.0

Status:

- non-normative external evidence inputs
- referenced, not vendored
- no default-runner dependency added
- no VATE certification, endorsement, production approval, or general
  compatibility claim
- no descriptor substitution

### Slice 1: PEF v1

Path:

- `vectors/pef_v1/pef_v1.json`

Vector IDs:

- `pef_v1_001`
- `pef_v1_002`
- `pef_v1_003`
- `pef_v1_004`
- `pef_v1_005`
- `pef_v1_006`
- `pef_v1_007`
- `pef_v1_008`

Adjacent descriptors:

- `expected_receipt_hash`
- `expected_frame_id`

Descriptor boundary:

- `expected_receipt_hash` remains the PEF receipt hash.
- `expected_frame_id` remains the PEF frame or preimage identifier.
- Neither value is a VATE digest descriptor unless a future VATE profile
  explicitly defines that equivalence.

Named basis:

- `canon_pin = urn:x402:canonicalisation:jcs-rfc8785-v1`
- `pef_version = 1`

VATE review question:

- Can a VATE SUT consume PEF-shaped adjacent payment evidence while preserving
  the boundary between PEF-native identifiers and VATE artifact or evidence
  descriptors?

### Slice 2: execution_ref v1

Path:

- `vectors/execution_ref_v1/execution_ref_v1.json`

Positive vector IDs:

- `ex-allow-committed`
- `ex-allow-skipped`
- `ex-allow-reversed`
- `ex-refer-failed`

Negative vector IDs:

- `ex-neg-decision-swap`
- `ex-neg-outcome-swap`
- `ex-neg-timestamp-1ms`
- `ex-neg-scope-swap`
- `ex-neg-rfc3339-timestamp`

Adjacent descriptor:

- `expected_execution_ref`

Descriptor boundary:

- `expected_execution_ref` remains the execution-ref descriptor.
- It is not a VATE `effective_request_hash`, VATE admission receipt digest, or
  VATE artifact digest.

Named basis:

- `rfc8785-jcs + sha256`
- `sha256:`-prefixed digest string

VATE review questions:

- Can post-execution evidence be bound to the exact admission or decision basis
  without relying on identity correlation alone?
- Do timestamp and semantic-equivalence mutations fail before local policy
  evaluation when digest binding changes?

### Slice 3: AP2 OMH v0

Path:

- `vectors/ap2_omh_v0/ap2-omh-v0.json`

Vector IDs:

- `ap2-omh-v0-baseline-001`
- `ap2-omh-v0-object-key-order-002`
- `ap2-omh-v0-array-order-003`
- `ap2-omh-v0-optional-fields-004`
- `ap2-omh-v0-currency-minor-unit-005`
- `ap2-omh-v0-unicode-nfc-006a`
- `ap2-omh-v0-unicode-nfd-006b`

Selected object:

- `mandate_body`

Adjacent descriptor:

- `expected_open_mandate_hash`

Descriptor boundary:

- `open_mandate_hash` remains AP2's own descriptor.
- It is not a VATE digest descriptor by default.

Named basis:

- RFC 8785 canonical bytes over the selected AP2 mandate body
- SHA-256 digest encoded in the adjacent AP2 descriptor form

VATE review question:

- Can a VATE SUT bind an embedded AP2 mandate evidence object by selected-object
  bytes and digest without redefining AP2 or treating AP2's descriptor as VATE's
  descriptor?

## Agent Security Harness RCL - Carry-Plus-Projection Slice

Source repository:

- `https://github.com/msaleme/red-team-blue-team-agent-fabric`

Discussion and handoff record:

- `https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/30`
- mapping correction:
  `https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/30#issuecomment-5209176439`
- source-author handoff:
  `https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/30#issuecomment-5281915833`
- VATE acknowledgement:
  `https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/30#issuecomment-5282295933`

License:

- Apache-2.0

Pinned complete source fixture:

- commit: `825986680dc53fa776038db814b8d1da1dfcba9c`
- source path: `fixtures/rcl/rcl-oracle-fixtures.v1.json`
- raw full-file SHA-256:
  `4164151383605d9d68230d81cc9ae1dd31eb5cfb3fb1348289abf71ee64773ea`
- carried path:
  `conformance/al2-vate-v0.3/external/rcl/rcl-oracle-fixtures.v1.json`
- carriage: vendored complete file with exact source bytes

Pinned source harness:

- commit: `d6b7184e0d205672463f7f3284571e9e6a3e797d`
- path: `protocol_tests/receipt_claim_harness.py`

Selected vector IDs and source pointers:

- RCL-005: `/fixtures/4`
- RCL-006: `/fixtures/5`
- RCL-008: `/fixtures/7`

Selected objects and claims:

- `receipt.action`
- `receipt.action.params`
- `receipt.claims.authorization.params_digest`
- `receipt.claims.occurrence.action_digest`
- the other-action and settled-result preimages named by the pinned harness

Named source object basis:

- SHA-256 over
  `json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')`
- not RFC 8785 / JCS

VATE review questions:

- Can an authorization claim for different parameters deny admission without
  corrupting the admitted action binding?
- Can a successful settled occurrence be rejected for binding to another
  action without describing execution itself as failed?
- Does a full-pipeline positive control prevent reject-everything behavior from
  passing the slice?

Corpus use:

- the complete source file is raw-byte-bound by the corpus manifest;
- the canonical VATE cases are `rcl-005-authorization-params-mismatch`,
  `rcl-006-occurrence-action-linkage-mismatch`, and
  `rcl-008-full-pipeline-acceptance-control`;
- all requests, receipts, post-execution receipts, action/params objects, and
  selected preimages outside the complete source file are labelled derived
  VATE projections;
- the projection record is
  `examples/interop/rcl-to-vate/rcl-005-006-008-projection-map.v1.json`;
- the detailed boundary is documented in
  `docs/interop/rcl-receipt-claim-projection.md`.

Descriptor and validation boundary:

- source-profile Ed25519 and authority checks remain separate from VATE
  projection validation;
- the source action digests are not substituted into VATE `input_hash` or
  `execution.effective_request_hash`;
- the case-local RCL-005 mapping descriptor is not a generic VATE field;
- there is no `pairing` in this three-case slice;
- this is not an external SUT run, independent implementation result,
  compatibility claim, adoption signal, endorsement, certification, or
  production approval.

## Deferred Candidate: service_trust_v0

`service_trust_v0` is not pinned in this first slice. It is recorded here as a
deferred second-slice candidate for signed service trust evidence or
verifier-side service admission evidence.

Reason:

- The first pinned slice remains limited to the three non-normative review
  inputs listed above.
- This candidate has a richer signed-provider shape than the unsigned
  content-addressed sets in the first slice.
- A future pin should still identify the exact VATE case or review question
  before treating it as part of an external review slice.

Path:

- `vectors/service_trust_v0/service_trust_v0.json`

Candidate vector names:

- `known-service-scored`
- `unknown-service-null`
- `timestamp-ms-canonicalization`
- `null-score-not-default`
- `batch-composition`

Candidate VATE track:

- signed service trust evidence
- verifier-side service admission evidence

Selected evidence object:

- per-service signed trust verdict over the `service_url` input and scored
  result

Provider and provenance:

- provider: `did:web:supership.crestsystems.ai`
- operator: Supership / Crest Deployment Systems LLC
- category: `service_trust`
- provenance caveat: this is a third-party provider set; AlgoVoi provides the
  conformance vectors, not the trust scoring itself

Discovery and verification boundary:

- risk-check discovery: `https://supership.crestsystems.ai/.well-known/risk-check.json`
- JWKS: `https://supership.crestsystems.ai/.well-known/jwks.json`
- signing: EdDSA / Ed25519
- canonicalization: JCS RFC 8785 + SHA-256
- `canon_version`: `jcs-rfc8785-v1`

Adjacent references:

- x402 risk-check thread: `https://github.com/x402-foundation/x402/issues/2421`
- pinned external vector metadata also references x402 risk-check extension PR
  `#2422` and shared canonicalization PR `#2436`

Descriptor boundary:

- `service_trust` remains its own descriptor.
- A VATE SUT may bind the canonical JSON bytes of the selected trust verdict
  and may verify the EdDSA signature against the provider JWKS, but it must
  still emit its own VATE admission result.
- This candidate does not imply VATE endorsement of the provider, the trust
  scoring method, the x402 risk-check extension, or any A2A equivalence.
