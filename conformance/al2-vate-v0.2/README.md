# VATE AL2 v0.2 Mini Conformance Corpus

This directory contains a small machine-readable corpus for the `VATE AL2 Verifier Admission Profile v0.2`.

It is not a certification suite.
It is a review and implementation aid.

The corpus makes the v0.2 draft easier to evaluate by naming the minimum expected verifier outcomes:

- admit a valid request
- narrow a request with machine-readable attenuation
- deny an expired permit
- deny an audience mismatch
- link a post-execution receipt back to the admitted effective request

## Files

- `conformance-case.schema.json` - common shape for the case files
- `cases/allow-valid-admission.json`
- `cases/attenuate-max-amount.json`
- `cases/deny-expired-permit.json`
- `cases/deny-audience-mismatch.json`
- `cases/post-execution-linkage-success.json`

## Intent

A verifier implementation should be able to load each case, resolve the referenced example artifacts or apply the described mutation, and compare its output to the `expected` block and any referenced expected receipt artifact.

The `expected.admission_decision` value is limited to `allow`, `attenuate`, or `deny`.
Post-execution cases use `expected.post_execution_outcome` so execution results do not expand the admission decision vocabulary.

This is deliberately smaller than the existing `conformance/al2-http/` corpus.
It focuses on the profile semantics that matter for A2A-adjacent admission and receipt handling.
