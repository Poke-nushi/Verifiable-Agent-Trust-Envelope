# Language-Neutral Conformance Corpus Format

## Status

This note defines the language-neutral shape of the `VATE AL2 Verifier Admission v0.2` conformance corpus.

It is an implementation aid, not a production endorsement program.
It lets non-Python implementations discover cases, resolve artifacts, and publish comparable reports without depending on the reference runner internals.

## Corpus Index

Each runnable corpus SHOULD publish a `corpus.json` index at the corpus root.

For the v0.2 AL2 corpus:

- index: `conformance/al2-vate-v0.2/corpus.json`
- schema: `schemas/conformance-corpus.schema.json`
- case schema: `conformance/al2-vate-v0.2/conformance-case.schema.json`
- report schema: `schemas/conformance-report.schema.json`
- implementation report schema: `schemas/implementation-report.schema.json`

The index contains:

- corpus version and profile id
- corpus root and case schema path
- case count and category counts
- a digest basis for snapshot comparison
- a sorted case list with expected outcome and reason codes
- a manifest of case files and referenced artifacts with raw SHA-256 digests
- runner commands for reproducing the index and a conformance report

## Digest Basis

The corpus index digest is computed over the sorted `manifest` array.

The manifest includes:

- all JSON files under the corpus root except `corpus.json`
- artifacts referenced by case files, including examples outside the corpus root

The manifest intentionally excludes `corpus.json` to avoid a self-referential digest.

Each manifest entry records:

- `path` - repository-relative path
- `sha256` - raw file SHA-256 digest in lowercase hexadecimal

The digest value is the SHA-256 of canonical JSON bytes for the manifest array.
The current reference canonicalization sorts object keys and removes insignificant whitespace.

## Implementation Flow

A non-reference implementation can run the corpus without importing Python code:

1. Load `corpus.json`.
2. Load each case listed in `cases[].path`.
3. Resolve any case `artifacts` relative to the repository root.
4. Execute the verifier behavior implied by the case.
5. Compare the verifier output to the case `expected` block and profile-specific checks.
6. Write a report matching `schemas/conformance-report.schema.json`.
7. Optionally publish an implementation report matching `schemas/implementation-report.schema.json`.

Implementations MAY use the reference runner as a comparison oracle, but the corpus index is the portable contract.

For external systems under test, use:

- `docs/conformance/sut-adapter-contract.md`
- `schemas/sut-result.schema.json`
- `python3 scripts/vate_conformance.py compare`

## Freshness Rule

When case files or referenced artifacts change, regenerate `corpus.json`:

```bash
python3 scripts/vate_conformance.py index \
  --corpus-root conformance/al2-vate-v0.2 \
  --out conformance/al2-vate-v0.2/corpus.json
```

`scripts/check_repo.py` fails if the committed corpus index is stale.

## Claim Boundary

Passing the corpus means the implementation matched this draft fixture set for one corpus snapshot.

It does not imply:

- production readiness
- security review completion
- authorization to make a branded conformance claim
- compatibility with future VATE profiles
