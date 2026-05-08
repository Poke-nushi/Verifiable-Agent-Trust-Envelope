# @vate/reference-core

## Status

This is a package-private TypeScript reference helper for VATE draft work.
It is included to make digest-bound artifact handling and SUT result shaping
easier to review from TypeScript.

It is not a published SDK, a certification tool, a production verifier, or a
replacement for the Python conformance runner.

## Scope

The package currently covers:

- sorted-key compact JSON bytes for the v0.2 fixture digest basis;
- SHA-256 digest descriptors using lowercase hexadecimal values;
- digest-bound artifact reference checks against caller-supplied bytes;
- schema-shaped SUT result entries for `schemas/sut-result.schema.json`.

The helper deliberately does not:

- fetch remote artifact URIs;
- verify JOSE, JCS, PKI, Sigstore, or signed git proofs;
- decide issuer trust, status freshness, replay, or local policy;
- imply production readiness, endorsement, or general compatibility.

## Verification

From the repository root:

```bash
npm ci
npm run ts:check
npm run ts:test
```
