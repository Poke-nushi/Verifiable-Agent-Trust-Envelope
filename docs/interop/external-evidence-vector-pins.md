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

## Deferred: service_trust_v0

`service_trust_v0` is not pinned in this first slice.

Reason:

- The mapping to a specific VATE case or review question is not yet defined.
- The name alone should not be used to infer A2A equivalence.
- A future pin should identify the selected evidence object, descriptor basis,
  signature or trust boundary, and exact VATE case mapping.
