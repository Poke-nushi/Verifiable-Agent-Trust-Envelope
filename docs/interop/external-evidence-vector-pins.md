# External Evidence Vector Pins

## Status

This document records pinned external evidence vector slices that may be useful
for VATE corpus review.

These slices are non-normative review inputs. They are not part of the VATE
conformance corpus, do not imply VATE certification, do not create a dependency
on the external project, and do not substitute adjacent protocol identifiers for
VATE digest descriptors.

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
