# VATE AL2 v0.2 Mini Conformance Corpus

This directory contains a runnable machine-readable corpus for the `VATE AL2 Verifier Admission Profile v0.2`.

It is not a certification suite.
It is an interoperability review and implementation aid.

The corpus makes the v0.2 draft easier to evaluate by naming the minimum expected verifier outcomes:

- admit a valid request
- narrow a request with machine-readable attenuation
- deny an expired permit
- deny an audience mismatch
- deny stale, revoked, replayed, tampered, mismatched, and untrusted inputs
- link a post-execution receipt back to the admitted effective request

## Files

- `conformance-case.schema.json` - common shape for the case files
- `cases/allow-valid-admission.json`
- `cases/allow-valid-basic-external-write.json`
- `cases/allow-mcp-oauth-transport-bound.json`
- `cases/allow-valid-with-status-fresh.json`
- `cases/allow-valid-with-policy-snapshot.json`
- `cases/attenuate-max-amount.json`
- `cases/attenuate-target-scope.json`
- `cases/attenuate-requires-new-permit.json`
- `cases/deny-expired-permit.json`
- `cases/deny-not-yet-valid-permit.json`
- `cases/deny-audience-mismatch.json`
- `cases/deny-digest-mismatch.json`
- `cases/deny-policy-snapshot-mismatch.json`
- `cases/deny-signature-tampered.json`
- `cases/deny-unknown-trust-anchor.json`
- `cases/deny-runtime-mismatch.json`
- `cases/deny-status-revoked.json`
- `cases/deny-status-stale-fail-closed.json`
- `cases/deny-replay-detected.json`
- `cases/interop-ap2-ucp-commerce-evidence.json`
- `cases/interop-oap-decision-evidence.json`
- `cases/post-execution-linkage-success.json`
- `cases/post-execution-linkage-mismatch.json`

## Run

```bash
python3 scripts/vate_conformance.py run \
  --corpus-root conformance/al2-vate-v0.2 \
  --report /tmp/vate-conformance-report.json
```

The report is machine-readable JSON and follows:

- `schemas/conformance-report.schema.json`

To also write a machine-readable implementation report for one run:

```bash
python3 scripts/vate_conformance.py run \
  --corpus-root conformance/al2-vate-v0.2 \
  --report /tmp/vate-conformance-report.json \
  --implementation-report /tmp/vate-implementation-report.json \
  --implementation-name "Example VATE verifier" \
  --implementation-type "verifier" \
  --implementation-version "0.1.0" \
  --implementation-language "Python 3"
```

The implementation report follows:

- `schemas/implementation-report.schema.json`

## Digest Canonicalization

For this dependency-free fixture runner, digest checks use canonical JSON bytes produced by sorting object keys and removing insignificant whitespace before applying SHA-256.
The digest value is encoded as lowercase hexadecimal in the policy snapshot fixtures.
Future profiles may replace this with a named external canonicalization scheme, but conformance cases must state which digest basis they use.

## Intent

A verifier implementation should be able to load each case, resolve the referenced example artifacts or apply the described mutation, and compare its output to the `expected` block and any referenced expected receipt artifact.

The `expected.admission_decision` value is limited to `allow`, `attenuate`, or `deny`.
Post-execution cases use `expected.post_execution_outcome` so execution results do not expand the admission decision vocabulary.

This is deliberately smaller than the existing `conformance/al2-http/` corpus.
It focuses on the profile semantics that matter for A2A-adjacent admission and receipt handling.
