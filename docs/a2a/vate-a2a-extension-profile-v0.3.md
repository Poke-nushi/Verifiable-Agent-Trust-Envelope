# VATE A2A Extension Profile v0.3
## Metadata-only admission and receipt references

## Status

This is a community profile draft for carrying VATE admission and receipt
references through A2A metadata.

It is not an official A2A extension. It does not require an A2A core change.
It is intended to make the A2A extension-review boundary reviewable.

## Problem

A2A can carry delegated task flow between agents.
For risky external digital writes, the relying party still needs a verifier-side
decision about whether the action may proceed as requested, proceed with
narrower constraints, or be denied.

Discovery metadata, OAuth or MCP authorization evidence, AP2 mandates, VC/JWT
credentials, and signed Agent Cards can be useful evidence. They are not the
same thing as a verifier admission decision.

## Non-Goals

This profile does not define:

- an A2A core state-machine change;
- a new A2A RPC method;
- a payment protocol;
- a verifier policy language;
- an identity registry;
- a global trust score;
- a receipt storage service;
- production JOSE or PKI verification.

## Extension Class

The VATE A2A profile is a data/profile extension:

- data-only because A2A metadata carries references, not full VATE artifacts;
- profile-like because those references have VATE AL2 admission semantics;
- not a method extension because it adds no A2A RPC method;
- not a state-machine extension because VATE phases are metadata phases, not
  new A2A task states.

## Extension URI

The current draft extension URI is:

```text
https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.3
```

This is a repository-scoped draft namespace.
A persistent namespace such as `w3id.org` can be considered only after namespace
control, redirect behavior, external review, and implementation-report evidence
exist. See [Namespace Migration](../namespace-migration.md).

## Agent Card Declaration

An A2A Agent Card can advertise optional VATE support under
`capabilities.extensions`:

```json
{
  "uri": "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.3",
  "description": "Carries digest-bound VATE admission and receipt references in A2A metadata.",
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

The declaration is evidence of advertised support. It is not sufficient
authority for a risky write.

## Activation

For HTTP-based A2A bindings, a client can request VATE metadata semantics with
the `A2A-Extensions` header when the deployment uses extension activation.

The extension should remain optional during early interop. If a deployment later
marks it required, unsupported extension handling remains an A2A capability
issue. VATE verification failures remain VATE admission outcomes.

## Metadata Placement

The VATE metadata object should be placed under the extension URI key inside A2A
core object metadata:

```text
metadata["https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.3"]
```

The metadata object carries references. It should not embed full VATE artifacts
or verifier policy semantics.

## Metadata Object

The object contains:

- `profile`
- `phase`
- `transaction_id`
- `assurance_level`
- `issuer`
- `issued_at`
- one or more phase-specific artifact references
- optional `decision` for admission results
- optional `expires_at`
- optional `policy_snapshot` reference
- optional `evidence_refs`
- optional `extensions` for registered or deployment-specific extension data
- optional `annotations` for non-normative debugging or review data

The profile currently defines three phases:

- `admission_requested`
- `admission_issued`
- `post_execution_receipt_issued`

## Artifact Reference Rules

Conformance-facing references must be digest-bound.

At minimum, an artifact reference contains:

- `type`
- `uri`
- `media_type`
- `digest.alg`
- `digest.value`

The metadata schema requires artifact reference `uri` values to be absolute
URI-shaped strings. This is shape validation only: the verifier still treats
every URI as untrusted input until dereference policy, media type, size,
digest, and local trust checks have been applied.

For the v0.3 AL2 corpus, digest-bound references use SHA-256 with lowercase
hexadecimal values. A pure pointer without a digest may be useful as advisory
discovery metadata, but it is not enough for AL2 conformance-facing evidence.

The digest covers the referenced artifact bytes or the profile-defined
canonical JSON byte basis. It does not cover a mutable URL label or a human
description of the artifact.

The v0.3 A2A metadata schema keeps the core object closed. Future or
deployment-specific data belongs under explicit `extensions` or `annotations`
fields, not beside normative fields. Unknown extension data must not grant
authority unless a profile registers and validates it.

## Receipt Phases

`admission_requested`:

- references an admission request;
- indicates that a verifier decision is being requested or presented for
  evaluation.

`admission_issued`:

- references an admission receipt;
- can include `decision` with `allow`, `attenuate`, or `deny`;
- can include a digest-bound policy snapshot reference when audit needs require
  the policy basis to be reconstructable.

`post_execution_receipt_issued`:

- references both the admission receipt and the post-execution receipt;
- lets an implementation link observed execution evidence back to the
  admission decision.

## Attenuation Example

`attenuate` is the main reason to carry admission receipt references instead of
only a yes/no status.

Example:

```text
requested: transfer USD 10000
admitted: max USD 500, approval required above USD 100, expires in 10 minutes
receipt records: original_request_hash, effective_request_hash, evidence_refs,
policy_snapshot.digest, reason_codes
```

A2A metadata should still carry only the digest-bound admission receipt
reference. The full attenuation object belongs in the VATE admission receipt.

## Failure Mapping

VATE verification failures should not become new A2A task states.

Examples:

- missing required A2A extension support: A2A extension capability failure;
- malformed VATE metadata: request validation failure or VATE `SCHEMA_INVALID`;
- digest mismatch: VATE deny with `DIGEST_MISMATCH` and `FAIL_CLOSED`;
- stale status evidence: VATE deny with status freshness reason codes;
- signed Agent Card treated as sufficient authority: verifier implementation
  error, because Agent Card evidence still needs local policy evaluation.

## Security Requirements

The verifier must fail closed or deny when a review-critical reference cannot be
validated.

Verifier implementations should check:

- metadata schema;
- artifact digest and media type;
- issuer and trust-anchor policy;
- status, freshness, and replay windows;
- audience, action, resource, transaction, and runtime binding;
- attenuation constraints;
- post-execution linkage.

Dereferencing artifacts must be safe for the verifier environment. A URL in A2A
metadata is untrusted input until scheme, host, media type, digest, size, and
policy constraints have been applied.
The reference adapter demo follows that ordering for local fixtures: it validates
the VATE metadata object and digest descriptor shape before resolving the
referenced `local:` admission request.

If a deployment uses JOSE/JCS proof packaging, the production proof boundary is
defined separately in
[VATE JOSE/JCS Proof Profile v0.3](../profiles/vate-proof-profile-jose-jcs-v0.3.md).
The current AL2 corpus still uses dependency-free byte-level proof fixtures.

## Examples

Agent Card and metadata examples:

- `examples/a2a/agent-card-v1-vate-extension.example.json`
- `examples/a2a/metadata-admission-requested.json`
- `examples/a2a/metadata-admission-requested-with-signed-agent-card.json`
- `examples/a2a/metadata-admission-issued.json`
- `examples/a2a/metadata-post-execution-issued.json`

Receipt examples:

- `examples/receipts/admission-allow.example.json`
- `examples/receipts/admission-attenuate-max-amount.example.json`
- `examples/receipts/admission-deny-digest-mismatch.example.json`
- `examples/receipts/post-execution-success.example.json`

Schema:

- `schemas/a2a-vate-metadata.schema.json`

## Review Questions

- Is this metadata-only, by-reference admission and receipt pattern compatible
  with the A2A extension model?
- Should the profile remain entirely adjacent until independent implementation
  reports exist?
- Are the phase names clear enough without becoming A2A task states?
- Are the digest-bound reference requirements narrow enough for interop and
  strict enough for review?
