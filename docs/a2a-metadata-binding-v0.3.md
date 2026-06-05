# A2A Metadata Binding v0.3
## Reference-only binding for VATE admission and receipt artifacts

## Status

This is a proposed binding for `VATE AL2 Verifier Admission Profile v0.3`.
It is intentionally small.

It asks A2A to carry references to VATE artifacts, not the full VATE artifact bodies.

For the consolidated A2A-oriented review path, start with
`docs/a2a/README.md` and
`docs/a2a/vate-a2a-extension-profile-v0.3.md`.

## Design Goal

A2A owns discovery, Agent Cards, task exchange, transport bindings, and extension governance.
VATE owns verifier-side admission decisions, attenuation semantics, status influence, and receipts.

The binding keeps that boundary clear.

## Extension URI

The draft URI for this repository is:

```text
https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.3
```

This URI is a draft namespace.
A future profile may move to a persistent namespace such as `w3id.org` after that namespace is controlled and documented.

For the consolidated community profile draft, see
`docs/a2a/vate-a2a-extension-profile-v0.3.md`.

For an A2A v1.0-shaped extension sketch using `supportedInterfaces[]`,
`capabilities.extensions`, optional `A2A-Extensions` activation, and signed
Agent Card evidence references, see
`docs/a2a-v1-extension-sketch-2026-05.md`.

## Agent Card Declaration

An A2A agent that understands this binding may declare the extension in its Agent Card:

```json
{
  "uri": "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.3",
  "description": "Carries VATE admission and receipt references in A2A metadata.",
  "required": false,
  "params": {
    "profiles": [
      "VATE-AL2-Verifier-Admission-v0.3"
    ],
    "accepted_reference_modes": [
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
- optional `policy_snapshot` reference for deployments that need to reconstruct the policy basis for a decision
- `evidence_refs` when useful
- `issuer`
- `issued_at`
- `expires_at` when the reference is time-bound
- optional `extensions` for explicitly separated extension data
- optional `annotations` for non-normative debugging or review data

The metadata object should not contain the full receipt body by default.
It should also avoid carrying policy semantics directly.
When audit traceability requires the concrete policy basis, use an optional digest-bound `policy_snapshot` reference rather than embedding policy rules in A2A metadata.
When a profile cannot disclose the concrete reason basis, the portable receipt
can carry an opaque or withheld reason signal; A2A metadata should still avoid
embedding the sensitive basis itself.
When a profile defines an `action_binding` digest, A2A metadata may point to the
artifact that contains that binding, but the binding does not replace the
admission receipt reference or post-execution receipt reference.
The v0.3 metadata schema closes the core object; future fields should live under
explicit `extensions` or `annotations` rather than appearing beside normative
fields.

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
For the v0.3 AL2 conformance boundary, digest-bound references are required for
the artifact references evaluated by the corpus. A pure `by_reference` pointer
without a digest may be useful as advisory discovery metadata, but it is not a
passing AL2 conformance reference.

The reusable artifact and evidence reference schemas are intentionally
algorithm-extensible. The AL2 v0.3 profile schemas and conformance-facing
artifact references are stricter: `digest.alg` must be `sha-256` and
`digest.value` must be a lowercase 64-character hexadecimal digest.

At minimum:

- `uri`
- `media_type`
- `digest.alg`
- `digest.value`

The A2A metadata schema validates artifact reference `uri` values as absolute
URI-shaped strings. This does not make a referenced location trusted or
reachable; verifier implementations still need dereference controls, media type
pinning, digest checks, and local trust policy before using the artifact.
The dependency-free adapter demo performs a lightweight metadata shape check
before dereferencing `local:` fixture URIs. Malformed VATE metadata is mapped to
a fail-closed VATE denial with `SCHEMA_INVALID` and `FAIL_CLOSED`.

For `admission_issued`, the required decision digest is the `admission_receipt.digest`.
An optional `policy_snapshot.digest` can be added when the verifier wants consumers or auditors to reconstruct the policy basis for the decision.
When both the admission receipt and A2A metadata carry `policy_snapshot`, the `uri`, `media_type`, and `digest` values should match.
The digest should cover the canonical policy snapshot artifact, not a human-readable policy label or mutable policy URL.
The current conformance fixtures use SHA-256 over sorted-key compact JSON and encode the digest value as lowercase hexadecimal.

The verifier must not treat an A2A Agent Card as sufficient proof of current task authority.
The verifier must evaluate the referenced artifacts against local policy before accepting a risky external write.

## Signed Agent Card Digest Target

For the v0.3 byte-level fixture, the digest target is the canonicalized A2A
Agent Card payload, not the HTTP response envelope, discovery URL, mutable
cache entry, or VATE admission request.

The fixture uses the same dependency-free JSON byte basis as the v0.3
conformance corpus: sorted object keys, no insignificant whitespace, UTF-8
bytes, and lowercase SHA-256 hex digests.

The validation responsibility is deliberately split:

- A2A owns whether the Agent Card shape and signature packaging match A2A rules.
- VATE consumes the signed Agent Card or validation result as adjacent evidence.
- The verifier still decides whether the issuer, key, endpoint, extension
  declaration, freshness, runtime binding, and local policy permit the action.

The signed Agent Card fixture is byte-level only. It fixes the protected header,
payload digest, detached payload bytes, and signing-input digest. It does not
claim production ECDSA verification.
The public JWK used by the Agent Card trust-bundle fixture is fixture material
for key id and trust-bundle binding checks, not production ECDSA validation.
It is included in the AL2 v0.3 conformance corpus as
`allow-a2a-signed-agent-card-evidence`, so external SUT comparison must report
the referenced proof, Agent Card payload, trust bundle, and admission receipt
artifacts.

## Conformance Review Path

The current AL2 v0.3 corpus lives under `conformance/al2-vate-v0.3/`, with its
case count recorded in `corpus.json` as `summary.case_count`. For external
implementations, start with `docs/conformance/external-sut-quickstart.md` and
use `compare` against the exact corpus snapshot identified by `corpus.json`.

For published or shared review bundles, `docs/conformance/report-integrity.md`
documents `verify-bundle`, which checks the local digest chain among the corpus,
SUT result, conformance report, and implementation report. It is not a
production signature profile and does not replace external proof review.

The package-private helpers in `packages/vate-core-ts/` and
`packages/vate-a2a-ts/` show TypeScript examples for digest descriptors,
artifact references, SUT result entry shaping, A2A metadata shape validation,
and optional activation header checks. They do not fetch remote artifacts or
perform production JOSE, PKI, or A2A SDK middleware behavior.

## Examples

Example files:

- `examples/a2a/metadata-admission-requested.json`
- `examples/a2a/metadata-admission-requested-with-signed-agent-card.json`
- `examples/a2a/metadata-admission-issued.json`
- `examples/a2a/metadata-post-execution-issued.json`
- `examples/a2a/agent-card-v1-vate-extension.example.json`
- `examples/jose/jose-detached-a2a-agent-card.example.json`

## Compatibility Notes

This binding does not require an A2A core state-machine change.
It also does not define payment state, request signatures, identity registries, or runtime disclosure formats.

Those may be consumed as evidence references by VATE.
