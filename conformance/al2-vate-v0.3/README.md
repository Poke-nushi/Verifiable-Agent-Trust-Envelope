# VATE AL2 v0.3 Draft Conformance Corpus

This directory contains a runnable machine-readable corpus for the `VATE AL2 Verifier Admission Profile v0.3`.

It is not a production endorsement suite.
It is an interoperability review and implementation aid.
It does not grant a badge, endorsement, production approval, or a general
compatibility claim.

The corpus makes the v0.3 draft easier to evaluate by naming the minimum expected verifier outcomes:

- admit a valid request
- accept byte-bound detached JWS fixtures for runtime attestation and A2A signed Agent Card evidence
- narrow a request with machine-readable attenuation
- deny an expired permit
- deny an audience mismatch
- deny an MCP/OAuth request that would widen upstream tool authority
- deny MCP/OAuth requests where token presence, resource indicators, or tool
  classes do not jointly authorize the same target action
- deny stale runtime proof before policy or attenuation can admit execution
- deny stale, revoked, replayed, tampered, mismatched, and untrusted inputs
- consume AP2 Human Not Present payment-authority evidence without redefining AP2
- link a post-execution receipt back to the admitted effective request

Schema-invalid admission request receipts may include a digest-bound reference to
the rejected admission request solely as rejected-input binding. That reference
is not evidence that the request's `evidence_refs` were resolved.
For the empty `evidence_refs` case, diagnostic text should identify the empty
array condition while keeping `SCHEMA_INVALID` as the normative reason code.

## Files

- `conformance-case.schema.json` - common shape for the case files
- `corpus.json` - language-neutral corpus index for non-reference implementations
- `cases/allow-valid-admission.json`
- `cases/allow-valid-basic-external-write.json`
- `cases/allow-mcp-oauth-transport-bound.json`
- `cases/allow-replay-state-unused.json`
- `cases/allow-status-fresh-at-boundary.json`
- `cases/allow-valid-with-status-fresh.json`
- `cases/allow-valid-with-policy-snapshot.json`
- `cases/allow-jose-detached-runtime-attestation.json`
- `cases/allow-a2a-signed-agent-card-evidence.json`
- `cases/attenuate-max-amount.json`
- `cases/attenuate-target-scope.json`
- `cases/attenuate-requires-new-permit.json`
- `cases/deny-attenuation-approval-string.json`
- `cases/deny-attenuation-legacy-effective-constraints.json`
- `cases/deny-attenuation-malformed-money.json`
- `cases/deny-attenuation-negative-amount.json`
- `cases/deny-attenuation-unsafe-path.json`
- `cases/deny-attenuation-max-amount-type-edge.json`
- `cases/deny-expired-permit.json`
- `cases/deny-not-yet-valid-permit.json`
- `cases/deny-audience-mismatch.json`
- `cases/deny-empty-evidence-refs.json`
- `cases/deny-mcp-oauth-overscope.json`
- `cases/deny-mcp-oauth-upstream-denied.json`
- `cases/deny-token-passthrough-as-authority.json`
- `cases/deny-resource-indicator-drift.json`
- `cases/deny-mcp-tool-class-mismatch.json`
- `cases/deny-digest-mismatch.json`
- `cases/deny-digest-mismatch-before-policy.json`
- `cases/deny-jose-alg-none.json`
- `cases/deny-jose-hs256-downgrade.json`
- `cases/deny-jose-es384-not-allowed.json`
- `cases/deny-jose-crit-unsupported.json`
- `cases/deny-jose-payload-digest-mismatch.json`
- `cases/deny-policy-snapshot-mismatch.json`
- `cases/deny-ambiguous-trust-anchor.json`
- `cases/deny-alg-not-allowed.json`
- `cases/deny-evidence-type-not-allowed.json`
- `cases/deny-kid-mismatch.json`
- `cases/deny-signature-tampered.json`
- `cases/deny-unknown-trust-anchor.json`
- `cases/deny-trust-anchor-expired.json`
- `cases/deny-trust-anchor-not-yet-valid.json`
- `cases/deny-trust-anchor-revoked.json`
- `cases/deny-runtime-mismatch.json`
- `cases/deny-runtime-proof-stale.json`
- `cases/deny-status-revoked.json`
- `cases/deny-status-stale-fail-closed.json`
- `cases/deny-status-stale-just-over-boundary.json`
- `cases/deny-replay-detected.json`
- `cases/deny-replay-state-replayed.json`
- `cases/interop-ap2-ucp-commerce-evidence.json`
- `cases/allow-ap2-hnp-preauthorized-mandate.json`
- `cases/deny-ap2-hnp-stale-mandate.json`
- `cases/attenuate-ap2-hnp-amount-overrun.json`
- `cases/deny-ap2-hnp-replay.json`
- `cases/post-execution-admission-digest-mismatch.json`
- `cases/post-execution-after-admission-expiry.json`
- `cases/post-execution-after-deny.json`
- `cases/post-execution-allow-effective-constraints-exceeded.json`
- `cases/post-execution-ap2-hnp-linkage-success.json`
- `cases/post-execution-effective-constraints-aggregate-exceeded.json`
- `cases/post-execution-effective-constraints-exceeded.json`
- `cases/post-execution-finish-after-admission-expiry.json`
- `cases/post-execution-runtime-mismatch.json`
- `cases/post-execution-transaction-mismatch.json`
- `cases/interop-oap-decision-evidence.json`
- `cases/post-execution-linkage-success.json`
- `cases/post-execution-linkage-mismatch.json`

## Run

```bash
python3 scripts/vate_conformance.py run \
  --corpus-root conformance/al2-vate-v0.3 \
  --report /tmp/vate-conformance-report.json
```

The report is machine-readable JSON and follows:

- `schemas/conformance-report.schema.json`

`run` checks repository fixtures and reference-runner behavior only. It is not
an external SUT comparison result.

For external SUT implementation reports, use `compare` with a SUT result file:

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --report /tmp/vate-sut-compare-report.json \
  --implementation-report /tmp/vate-sut-implementation-report.json
```

The implementation report follows:

- `schemas/implementation-report.schema.json`

Publication guidance is in:

- `docs/conformance/external-sut-quickstart.md`
- `docs/conformance/report-integrity.md`

To regenerate the language-neutral corpus index:

```bash
python3 scripts/vate_conformance.py index \
  --corpus-root conformance/al2-vate-v0.3 \
  --out conformance/al2-vate-v0.3/corpus.json
```

The corpus index follows:

- `schemas/conformance-corpus.schema.json`

## Digest Canonicalization

For this dependency-free fixture runner, digest checks use canonical JSON bytes produced by sorting object keys and removing insignificant whitespace before applying SHA-256.
The digest value is encoded as lowercase hexadecimal in the policy snapshot fixtures.
Future profiles may replace this with a named external canonicalization scheme, but conformance cases must state which digest basis they use.

This v0.3 digest basis is limited to fixtures. It does not define duplicate-key
handling, Unicode normalization, floating-point normalization, or a production
signed-JSON profile.

## Runner Boundary

`python3 scripts/vate_conformance.py run` checks the committed fixture artifacts
with the reference runner.
It is a repository fixture integrity check, not an external implementation
conformance result.

`python3 scripts/vate_conformance.py compare` checks an external SUT result file
against the same corpus snapshot. Independent implementation review should use
`compare`, not `run` alone.

## Detached JWS Fixture Checks

The `jose_checks` cases do not perform production signature verification.
They fix the byte-level detached JWS basis that a production verifier must preserve before signature verification:

- protected header canonical bytes and base64url encoding
- detached payload canonical bytes and base64url encoding
- detached payload SHA-256 digest
- signing input digest over `BASE64URL(protected) || "." || BASE64URL(payload)`
- protected header `alg`, `kid`, `typ`, and `crit` rejection behavior
- trust-bundle binding for issuer, key id, algorithm, and evidence type

## Intent

A verifier implementation should be able to load each case, resolve the referenced example artifacts or apply the described mutation, and compare its output to the `expected` block and any referenced expected receipt artifact.

The `expected.admission_decision` value is limited to `allow`, `attenuate`, or `deny`.
Post-execution cases use `expected.post_execution_outcome` so execution results do not expand the admission decision vocabulary.
`expected.should_execute` records the execution gate separately from the admission
decision, so an attenuated case can still be non-executable when a fresh permit
is required.
For post-execution cases, `expected.should_execute` restates the pre-execution
admission gate. It does not state whether the post-execution receipt is valid.

`al2_context_checks` records the minimum verifier context needed for selected
AL2 cases:

- freshness windows for status and runtime proof evidence
- runtime binding inputs
- replay key / nonce state

This is deliberately smaller than the existing `conformance/al2-http/` corpus.
It focuses on the profile semantics that matter for A2A-adjacent admission and receipt handling.
