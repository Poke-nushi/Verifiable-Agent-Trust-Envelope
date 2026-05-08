# @vate/reference-a2a

## Status

This is a package-private TypeScript reference helper for the VATE A2A metadata
binding draft.

It is not an official A2A extension, an A2A SDK, an A2A middleware package, or a
production verifier.

## Scope

The package currently covers:

- extracting the VATE metadata object from an A2A-like `metadata` container;
- validating that object against `schemas/a2a-vate-metadata.schema.json`;
- checking optional `A2A-Extensions` activation for the VATE extension URI;
- building an `admission_issued` metadata object with digest-bound references.

The helper validates metadata shape only. A verifier still has to evaluate
referenced artifact digests, issuer trust, status freshness, replay protection,
scope, local policy, and post-execution linkage where applicable.

## Verification

From the repository root:

```bash
npm ci
npm run ts:check
npm run ts:test
```
