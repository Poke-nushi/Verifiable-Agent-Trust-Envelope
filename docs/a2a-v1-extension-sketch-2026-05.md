# A2A v1.0 Extension Sketch for VATE

## Status

This is a public sketch for how the current VATE AL2 admission artifacts could
fit into the A2A v1.0 extension model.

It is not an official A2A extension and does not require an A2A core change.
The goal is to make the boundary reviewable before any SDK middleware or
governed extension proposal exists.

For the consolidated community profile draft and review entry point, see
`docs/a2a/README.md` and
`docs/a2a/vate-a2a-extension-profile-v0.3.md`.

## A2A v1.0 Surface Used

This sketch relies on the following A2A v1.0 mechanisms:

- Agent Cards declare supported extensions under `capabilities.extensions`.
- A2A v1.0 Agent Cards use `supportedInterfaces[]`; each interface declares
  `url`, `protocolBinding`, and `protocolVersion`.
- Clients can request extension activation with the `A2A-Extensions` header.
- Custom extension data belongs in `metadata` on A2A core objects, not in new
  top-level core fields.
- Agent Cards may carry `signatures[]` using JWS over a canonicalized Agent
  Card payload.

References:

- <https://a2a-protocol.org/latest/topics/extensions/>
- <https://a2a-protocol.org/latest/specification/>
- <https://a2a-protocol.org/latest/whats-new-v1/>

## Extension Class

VATE should be treated as a data/profile extension:

- data-only because A2A metadata carries digest-bound references to VATE
  artifacts;
- profile-like because the VATE metadata object narrows the meaning of those
  references for `AL2` external digital write admission;
- not a method extension because it adds no new A2A RPC method;
- not a state-machine extension because `admission_requested`,
  `admission_issued`, and `post_execution_receipt_issued` are VATE metadata
  phases, not new A2A task states.

## Extension URI

The current draft URI remains:

```text
https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.3
```

This is a repository-scoped draft namespace. A persistent URI can be considered
only after the extension shape has survived review.

## Agent Card Declaration

An A2A v1.0 Agent Card can advertise VATE support as an optional extension:

```json
{
  "capabilities": {
    "extensions": [
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
          ],
          "signed_agent_card_binding": {
            "mode": "digest_bound_reference",
            "evidence_type": "signed_agent_card",
            "required": false
          }
        }
      }
    ]
  }
}
```

See `examples/a2a/agent-card-v1-vate-extension.example.json` for a complete
A2A-shaped Agent Card example.

## Activation

For HTTP-based A2A bindings, a client that wants the VATE metadata semantics for
a request can send:

```http
A2A-Extensions: https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.3
```

The extension should remain `required: false` during early interop. If a later
deployment marks it `required: true`, the A2A layer should handle unsupported or
unactivated extension behavior as an A2A extension capability failure. VATE
verification failures remain VATE admission outcomes and should be represented
with VATE reason codes in the admission receipt.

## Signed Agent Card Binding

A signed Agent Card can help bind an agent's advertised identity, endpoints, and
extension support to an integrity-protected discovery artifact. It does not, by
itself, authorize a risky external write.

When the evidence is an A2A Agent Card signature, the referenced signature
material should follow A2A v1.0 Agent Card signing rules. In particular, the
protected JWS header is expected to carry `alg`, `typ`, and `kid`.

For the v0.3 byte-level fixture, the digest-bound artifact is the canonicalized
Agent Card payload shown in
`examples/a2a/agent-card-v1-vate-extension.example.json`. The detached proof
fixture is `examples/jose/jose-detached-a2a-agent-card.example.json`, and the
corpus-bound case is `allow-a2a-signed-agent-card-evidence`.

VATE should consume signed Agent Card material only as evidence:

- as an `evidence_refs[]` item with `type: "signed_agent_card"`;
- with a digest-bound reference to the fetched Agent Card or signature-bearing
  Agent Card artifact;
- with local verifier policy deciding whether the Agent Card issuer, signature
  key, extension declaration, endpoint, and freshness are acceptable.

This sketch does not make A2A Agent Card signature verification a VATE core
operation. A verifier may either validate the signed Agent Card itself or consume
an A2A-compliant validation result as adjacent evidence.

The verifier must still evaluate the VATE admission request, trust bundle,
runtime binding, permit window, status freshness, replay protection, local
policy, and post-execution linkage.

## Metadata Flow

1. Discovery: the remote agent publishes an Agent Card that declares the VATE
   extension.
2. Optional activation: the client includes the VATE extension URI in
   `A2A-Extensions`.
3. Admission request: A2A metadata carries a VATE `admission_requested` object
   with a digest-bound `admission_request` reference and optional signed Agent
   Card evidence reference.
4. Admission response: the verifier returns an A2A-shaped response whose
   metadata carries `admission_issued` and a digest-bound `admission_receipt`
   reference.
5. After execution: a later task update, message, or artifact can carry
   `post_execution_receipt_issued` with digest-bound references to both the
   admission receipt and post-execution receipt.

## Current Review Artifacts

The current repository review package includes the AL2 v0.3 corpus under
`conformance/al2-vate-v0.3/`, with its current case count recorded in
`corpus.json` as `summary.case_count`. The A2A-specific signed Agent Card case
is `allow-a2a-signed-agent-card-evidence`.

External implementers should use `docs/conformance/external-sut-quickstart.md`
as the command-first path and use `compare` for SUT result comparison. The
repository `run` command remains a fixture and reference-runner integrity check,
not an external implementation result.

For report sharing, `docs/conformance/report-integrity.md` documents
`verify-bundle` as a local digest-chain check for the corpus, SUT result,
conformance report, and implementation report. It is not a production signature
profile.

The package-private TypeScript helpers in `packages/vate-core-ts/` and
`packages/vate-a2a-ts/` are review aids for digest-bound references, SUT result
shaping, metadata validation, and optional activation checks. They are not an
A2A SDK middleware package.

## Failure Mapping

VATE verification failures should not be converted into new A2A task states.
They should produce normal A2A responses or errors appropriate to the transport,
with VATE decision detail in metadata and receipts.

Examples:

- Missing required A2A extension support: A2A extension capability failure.
- Bad VATE metadata shape: A2A request validation failure or VATE
  `SCHEMA_INVALID`, depending on where validation runs.
- Digest mismatch: VATE deny with `DIGEST_MISMATCH` and `FAIL_CLOSED`.
- Stale status evidence: VATE deny with `STATUS_STALE` and `FAIL_CLOSED`.
- Unsupported signed Agent Card key or algorithm: VATE deny with trust or proof
  reason codes, not a new A2A state.

## Non-Goals

This sketch does not define:

- an official A2A extension namespace;
- an A2A SDK middleware package;
- a new A2A RPC method;
- a new A2A task state;
- an identity registry;
- a payment protocol;
- production JOSE or PKI requirements beyond consuming A2A Agent Card
  signatures as evidence.

## Open Review Questions

- Should the VATE extension remain entirely adjacent, or should it eventually
  use the A2A extension governance process?
- Should signed Agent Card evidence be optional for all AL2 cases, or required
  for cross-organization interop fixtures?
- Should a future production profile keep the v0.3 digest target as the
  canonicalized Agent Card payload, or move to an implementation-defined bundle
  containing the card plus signature metadata?
- Should SDK middleware live outside this repository until at least one
  non-reference implementation can emit a SUT result file that passes `compare`
  against the same corpus snapshot and has a locally verified report bundle?
