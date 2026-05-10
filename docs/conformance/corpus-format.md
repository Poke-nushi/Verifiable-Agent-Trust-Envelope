# Language-Neutral Conformance Corpus Format

## Status

This note defines the language-neutral shape of the `VATE AL2 Verifier Admission v0.3` conformance corpus.

It is an implementation aid, not a production endorsement program.
It lets non-Python implementations discover cases, resolve artifacts, and publish comparable reports without depending on the reference runner internals.

## Artifact Versioning

The `2026-07` strings in conformance report versions, schema IDs, fixture
versions, and deterministic fixture timestamps identify the July 2026 target
interop artifact line. They are not publication dates. Exact corpus snapshots
are identified by the `corpus.json` manifest digest and the digest fields in
generated reports.

See `docs/conformance/artifact-versioning.md` for the rule on when to keep or
change date-stamped conformance artifact identifiers.

## Corpus Index

Each runnable corpus SHOULD publish a `corpus.json` index at the corpus root.

For the v0.3 AL2 corpus:

- index: `conformance/al2-vate-v0.3/corpus.json`
- schema: `schemas/conformance-corpus.schema.json`
- case schema: `conformance/al2-vate-v0.3/conformance-case.schema.json`
- report schema: `schemas/conformance-report.schema.json`
- implementation report schema: `schemas/implementation-report.schema.json`

The index contains:

- corpus version and profile id
- corpus root and case schema path
- case count and category counts
- a digest basis for snapshot comparison
- a sorted case list with expected outcome, execution gate, primary reason
  projection, and reason codes
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

This is a v0.3 fixture digest basis, not a production canonicalization profile.
It keeps the dependency-free corpus reproducible, but it does not define
duplicate-key rejection, Unicode normalization, floating-point number
normalization, streaming payload handling, or a general signed-JSON profile.

Until a production profile is selected, fixture artifacts SHOULD avoid:

- JSON numbers that require floating-point normalization
- duplicate object keys
- semantically significant Unicode normalization choices
- digest comparisons over bytes whose encoding is not named by the case

Future production-oriented profiles should either name a standard JSON
canonicalization profile, such as RFC 8785 / JCS, or bind signatures and digests
to exact media bytes without reserializing JSON.

## Digest Strictness Boundary

The reusable artifact and evidence reference schemas are intentionally
algorithm-extensible so adjacent protocols can carry `sha-384`, `sha-512`, or
future digest algorithms where a later profile permits them.

The AL2 v0.3 profile schemas and conformance-facing artifact references are
stricter: descriptor `digest.alg` values must be `sha-256`, and descriptor
`digest.value` values must be lowercase 64-character hexadecimal strings.
Profile hash fields such as `input_hash` and `effective_request_hash` use the
separate `sha-256:<64 lowercase hex>` string form.

## Runner Boundary

The reference runner has two distinct roles:

- `run` checks the repository fixture artifacts and emits the reference report
  shape for one corpus snapshot.
- `compare` checks an external SUT result file against the same corpus snapshot.

`run` is useful for fixture integrity and reference behavior. It is not, by
itself, evidence that an independent implementation passed the corpus. External
implementation review should use `compare` with a SUT result file matching
`schemas/sut-result.schema.json`.

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

## Profile-Specific Checks

Some cases include profile-specific check arrays in addition to the `expected`
block. For the AL2 v0.3 corpus:

- `integrity_checks` bind referenced artifacts to expected digests
- `artifact_reference_checks` bind digest references across requests, receipts,
  and metadata
- `trust_checks` bind issuer, key, algorithm, evidence type, and validity-window
  decisions to a trust bundle
- `jose_checks` bind detached JWS fixture bytes before production signature
  verification; external SUT results must artifact-bind the referenced proof
  package, detached payload, and trust bundle
- `attenuation_checks` validate machine-readable attenuation boundaries
- `linkage_checks` bind post-execution receipts to admission digest,
  admission receipt id, admission decision, transaction, runtime, effective
  request hash, validity window, and side-effect constraints
- `al2_context_checks` validate minimum freshness, replay, and binding context
  and require external SUT reports to bind that context back to request, receipt,
  transaction, runtime, and evidence inputs. Each check must state its expected
  result explicitly with `expect_fresh`, `expect_match`, or `expect_replayed`.
  Replay context `state` values are restricted to `unused`, `consumed`, or
  `replayed`; unknown states fail the fixture check.
- evidence vocabulary checks require canonical generic `type` values, registered
  protocol hints, and registered type/hint combinations on admission request
  references and receipt evidence

An external implementation should treat those arrays as part of the case
contract, not as optional comments.

`linkage_checks[]` is intentionally kind-specific. A check is not complete just
because it names a `kind` and `reason_code`:

- `transaction_id`, `runtime`, `effective_request_hash`, and `path_match`
  require `admission_path`, `post_execution_path`, and `expect_match`
- `admission_digest` requires `post_execution_path` and `expect_match`; the
  admission artifact defaults to `admission_receipt` when `artifact` is omitted
- `admission_receipt_id` and `admission_decision` require `expect_match`; their
  admission and post-execution paths are fixed by the profile
- `admission_executable`, `admission_time_window`, and
  `effective_constraints` require `expect_valid`
- `policy_violation` requires `value` and `expect_present`

For `max_amount`, `effective_constraints` checks aggregate
`post_execution.result.side_effects[].amount` values in the admitted currency.
Two side effects that are individually below the cap can still fail if their
sum exceeds it.

`admission_time_window` covers both execution start and finish. In the v0.3
corpus, execution that starts before admission expiry but finishes after
admission expiry is still invalid and maps to `POST_EXEC_ADMISSION_EXPIRED`.

`effective_constraints` uses `attenuation.effective_constraints` for attenuated
admissions. For allow-path post-execution cases, it uses
`admission_receipt.request.constraints` when those constraints are recorded on
the receipt.

The `path_match` kind is a generic escape hatch for draft fixtures that need to
compare two explicitly named paths before a narrower linkage kind exists. It
maps to `POST_EXEC_LINKAGE_MISMATCH`.

For external systems under test, use:

- `docs/conformance/sut-adapter-contract.md`
- `schemas/sut-result.schema.json`
- `python3 scripts/vate_conformance.py compare`

## Freshness Rule

When case files or referenced artifacts change, regenerate `corpus.json`:

```bash
python3 scripts/vate_conformance.py index \
  --corpus-root conformance/al2-vate-v0.3 \
  --out conformance/al2-vate-v0.3/corpus.json
```

`scripts/check_repo.py` fails if the committed corpus index is stale.

## Claim Boundary

Passing the corpus means the implementation matched this draft fixture set for one corpus snapshot.

It does not imply:

- production readiness
- security review completion
- authorization to make a branded conformance claim
- compatibility with future VATE profiles
