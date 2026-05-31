# A2A Review Package For VATE v0.3

## Status

This directory is a review package for a VATE community profile draft that uses
A2A metadata to carry digest-bound admission and receipt references.

This is not an official A2A extension, endorsement, certification, SDK,
middleware package, or general compatibility proof. It does not require an A2A
core change and does not make A2A responsible for verifier policy, payment
semantics, identity registries, or receipt storage.

## Short Position

A2A carries task flow.
VATE carries verifier-side admission decision semantics.

The proposed A2A-facing surface is intentionally small:

- an optional Agent Card extension declaration;
- optional extension activation by A2A transport conventions;
- a VATE metadata object under the extension URI key;
- digest-bound references to VATE artifacts.

The full admission request, verifier policy, attenuation details, evidence
bodies, admission receipt, and post-execution receipt stay outside A2A core
objects.

## Read Order

1. [VATE A2A Extension Profile v0.3](vate-a2a-extension-profile-v0.3.md)
2. [A2A Metadata Binding v0.3](../a2a-metadata-binding-v0.3.md)
3. [A2A v1.0 Extension Sketch](../a2a-v1-extension-sketch-2026-05.md)
4. [A2A Maintainer Brief](../a2a-maintainer-brief-v0.3.md)
5. [Receipt Audit Walkthrough v0.3.1](../receipt-audit-walkthrough-v0.3.1.md)
6. [A2A Issue Update Draft](../a2a-issue-update-2026-05.md)

Related examples:

- `examples/a2a/agent-card-v1-vate-extension.example.json`
- `examples/a2a/metadata-admission-requested.json`
- `examples/a2a/metadata-admission-requested-with-signed-agent-card.json`
- `examples/a2a/metadata-admission-issued.json`
- `examples/a2a/metadata-post-execution-issued.json`

Related schema:

- `schemas/a2a-vate-metadata.schema.json`

Related conformance and implementation review aids:

- `conformance/al2-vate-v0.3/`
- `docs/interop/payment-evidence-frame-crosswalk.md`
- `docs/conformance/external-sut-quickstart.md`
- `docs/conformance/sut-adapter-contract.md`
- `docs/conformance/report-integrity.md`
- `docs/receipt-audit-walkthrough-v0.3.1.md`
- `packages/vate-core-ts/README.md`
- `packages/vate-a2a-ts/README.md`

The current AL2 v0.3 corpus case count is recorded in
`conformance/al2-vate-v0.3/corpus.json` as `summary.case_count`. Use `compare`
for external SUT review. Use `run` only to check this repository's committed
fixtures and reference runner behavior. `verify-bundle` is a local digest-chain
check across the corpus, SUT result, conformance report, and implementation
report; it is not a production signature profile.

The package-private TypeScript helpers cover digest descriptors, artifact
references, SUT result entry shaping, A2A metadata shape validation, and optional
activation header checks. They are not official A2A extensions, endorsements,
certifications, SDKs, middleware packages, production verifiers, or general
compatibility proofs.

## Review Question

The narrow question for A2A-oriented review is:

> Is this metadata-only, by-reference admission and receipt pattern compatible
> with the A2A extension model, or should it remain entirely as an adjacent
> community profile?

Either outcome is acceptable for this draft.

Passing an external SUT comparison means only that one submitted SUT result
matched one corpus snapshot under the repository comparison rules. It does not
imply certification, endorsement, production approval, or general compatibility
with future corpus snapshots.

## Non-Authority Rule

A VATE object inside A2A metadata is not proof of authority by itself.

A verifier still has to evaluate:

- metadata shape;
- referenced artifact digests;
- media type expectations;
- issuer and trust-anchor policy;
- status and freshness;
- replay protection;
- audience, action, and resource scope;
- local policy;
- post-execution linkage where applicable.

Likewise, an A2A Agent Card extension declaration or signed Agent Card is
evidence, not sufficient authority for a risky external write.

## Official A2A References

This review package is shaped around the public A2A extension model:

- <https://a2a-protocol.org/latest/topics/extensions/>
- <https://a2a-protocol.org/latest/topics/extension-and-binding-governance/>
- <https://a2a-protocol.org/latest/specification/>
