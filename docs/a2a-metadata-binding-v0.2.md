# A2A Metadata Binding v0.2
## Reference-only binding for VATE admission and receipt artifacts

## Status

This is a proposed binding for `VATE AL2 Verifier Admission Profile v0.2`.
It is intentionally small.

It asks A2A to carry references to VATE artifacts, not the full VATE artifact bodies.

## Design Goal

A2A owns discovery, Agent Cards, task exchange, transport bindings, and extension governance.
VATE owns verifier-side admission decisions, attenuation semantics, status influence, and receipts.

The binding keeps that boundary clear.

## Extension URI

The draft URI for this repository is:

```text
https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.2
```

This URI is a draft namespace.
A future profile may move to a persistent namespace such as `w3id.org` after that namespace is controlled and documented.

## Agent Card Declaration

An A2A agent that understands this binding may declare the extension in its Agent Card:

```json
{
  "uri": "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.2",
  "description": "Carries VATE admission and receipt references in A2A metadata.",
  "required": false,
  "params": {
    "profiles": [
      "VATE-AL2-Verifier-Admission-v0.2"
    ],
    "accepted_reference_modes": [
      "by_reference",
      "reference_plus_digest"
    ],
    "supported_phases": [
      "admission_requested",
      "admission_issued",
      "post_execution_receipt_issued"
    ]
  }
}
```

## Metadata Object

The VATE object should be placed under the extension URI key inside A2A `metadata`.

The object should contain:

- `profile`
- `phase`
- `transaction_id`
- `assurance_level`
- one primary artifact reference, such as `admission_request`, `admission_receipt`, or `post_execution_receipt`
- `evidence_refs` when useful
- `issuer`
- `issued_at`
- `expires_at` when the reference is time-bound

The metadata object should not contain the full receipt body by default.

## Phase Values

This binding defines three phase values:

- `admission_requested`
- `admission_issued`
- `post_execution_receipt_issued`

`admission_requested` means the sender is presenting or referencing a request for verifier admission.

`admission_issued` means the verifier decision exists and can be dereferenced or validated by digest.

`post_execution_receipt_issued` means execution evidence exists and is linked to an admission receipt.

## Reference Rules

VATE references in A2A metadata should include a digest when the object is dereferenceable.

At minimum:

- `uri`
- `media_type`
- `digest.alg`
- `digest.value`

The verifier must not treat an A2A Agent Card as sufficient proof of current task authority.
The verifier must evaluate the referenced artifacts against local policy before accepting a risky external write.

## Examples

Example files:

- `examples/a2a/metadata-admission-requested.json`
- `examples/a2a/metadata-admission-issued.json`
- `examples/a2a/metadata-post-execution-issued.json`

## Compatibility Notes

This binding does not require an A2A core state-machine change.
It also does not define payment state, request signatures, identity registries, or runtime disclosure formats.

Those may be consumed as evidence references by VATE.

