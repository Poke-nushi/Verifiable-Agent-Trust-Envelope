# SUT Adapter Contract

## Status

This note defines the result contract for comparing an external system under test (SUT) against the `VATE AL2 Verifier Admission v0.3` corpus.

It does not require an implementation to use Python.
The Python runner is only a comparison tool for the published corpus expectations.

For a shorter command-first path, start with
`docs/conformance/external-sut-quickstart.md`, then return to this contract for
field-level requirements.

Digest-basis terminology is defined in `docs/conformance/digest-basis.md`.
This contract uses that terminology rather than relying on an unnamed
"canonical JSON" scheme.

## Goal

An external verifier should be able to:

1. Load `conformance/al2-vate-v0.3/corpus.json`.
2. Execute each listed case in its own runtime.
3. Emit a SUT result file matching `schemas/sut-result.schema.json`.
4. Compare that file against the corpus with the reference runner.
5. Publish the comparison report and, optionally, an implementation report.

This keeps the conformance surface language-neutral while preserving exact expected outcomes and reason codes.

## SUT Result Shape

A SUT result file records one implementation run against one corpus snapshot.
The `2026-07` suffix in the current `version` value identifies the target
interop artifact line, not the date the SUT result was generated. The exact
corpus snapshot is identified by `corpus.digest`. See
`docs/conformance/artifact-versioning.md`.

Required top-level fields:

- `version` - currently `vate-sut-results-2026-07`
- `profile` - currently `VATE-AL2-Verifier-Admission-v0.3`
- `generated_at` - a valid RFC3339 date-time. The current runner accepts zero
  through six fractional-second digits and rejects higher precision rather than
  rounding or truncating it.
- optional `artifact_mode` - `corpus-fixture-validation` by default, or
  `generated-receipts` when the SUT also submits its own receipt bytes
- `implementation` - an object with non-empty `name`, `type`, `version`, and
  `language` fields
- `corpus.digest`
- `results`

Each result entry represents one corpus case:

- `case_id`
- `status` - `completed`, `skipped`, or `error`
- `outcome` - the verifier's observed outcome
- `should_execute` - whether the verifier result permits immediate execution
- `reason_codes` - the verifier's machine-readable reason codes in order; the
  comparison report derives `actual_primary_reason_code` from the first
  non-terminal code
- optional `checks` - case-specific check names with `pass: true` when the expected check was satisfied
- required `artifacts` for the case's declared or legacy-derived evaluated inputs
- optional per-case `artifact_mode` override
- required `generated_artifacts` when the effective mode is `generated-receipts`
- optional `limitations`

The example file is:

- `examples/conformance/sut-results-pass.example.json`

The command-first authoring path is:

- `docs/conformance/external-sut-quickstart.md`

For TypeScript contributors, `packages/vate-core-ts` includes a package-private
helper for constructing schema-shaped result entries. It is an implementation
aid only; `compare` remains the repository comparison command for external SUT
review.

## Artifact Roles

The result contract separates three artifact roles that must not be conflated:

1. A case-level `sut_inputs[]` array, when present, is the authoritative list of
   corpus artifacts supplied to the external SUT. The result records them in
   `results[].artifacts.input_artifacts[]` with matching `case_artifact`, `role`,
   corpus-relative `uri`, declared `media_type`, and raw SHA-256 digest. An
   unlisted expected receipt is not an evaluated input.
2. A case with a `kind: status` context check must declare `sut_inputs[]` and
   include its status context with `role: status_evidence`. Non-status cases
   without `sut_inputs[]` retain the legacy receipt, context, and proof
   reference rules under `results[].artifacts`.
3. `results[].generated_artifacts` identifies receipt bytes produced by the
   SUT. These fields are required only in `generated-receipts` mode and are
   never required to be byte-identical to the corpus receipt fixtures.

The default `corpus-fixture-validation` mode preserves the existing fixed-vector
comparison path. It checks that submitted references match the corpus fixture
digests; it does not establish that the SUT evaluated those bytes or issued a
receipt. An independent receipt-generation result should opt into
`generated-receipts` explicitly.

## Evaluated Corpus Artifact References

SUT results must be artifact-backed for the inputs declared by each case. This
keeps the comparison report from becoming a bare assertion detached from the
evidence the implementation evaluated.

When a case defines `sut_inputs[]`, each listed entry requires one
`artifacts.input_artifacts[]` reference with:

- matching `case_artifact` and `role` values;
- `uri` equal to the case artifact path and `media_type` equal to the value
  declared by `sut_inputs[]`;
- `digest.alg` set to `sha-256`; and
- `digest.value` equal to the raw corpus artifact SHA-256.

`compare` rejects duplicate (`case_artifact`, `role`) keys, unknown fields in an
input reference or its digest descriptor, and every sibling field beside
`input_artifacts` for that explicit case. This prevents an expected receipt
from being silently reintroduced under either a legacy or aliased field name.

Status-context inputs contain observed status and freshness facts. They do not
contain expected VATE reason codes. The runner derives `STATUS_REVOKED`,
`STATUS_STALE`, or `STATUS_UNAVAILABLE` from the declared checks and observed
input values. Status-context timestamps use the same zero-through-six
fractional-second digit limit as `generated_at`; higher precision fails closed
instead of being truncated during freshness comparison. Status-context inputs
must use the exact published context version
and field set; unknown fields fail closed. Removing `sut_inputs[]` from a status
case is invalid and does not downgrade that case to the legacy artifact lane.

The following rules apply to legacy cases without `sut_inputs[]`.

When the corpus case lists an `admission_receipt`, the result entry must include
`artifacts.admission_receipt`. When it lists a `post_execution_receipt`, the
result entry must include `artifacts.post_execution_receipt`.

Receipt artifact references require:

- `uri`
- `media_type`
- `digest.alg` set to `sha-256`
- `digest.value` as lowercase SHA-256 hex

When the corpus case includes `al2_context_checks`, the result entry must
include `artifacts.verification_context[]` entries with:

- `kind` - the context check kind, such as `binding`, `freshness`, or `replay`
- `case_artifact` - the corpus artifact key used for the context check
- `uri`
- `digest.alg` set to `sha-256`
- `digest.value` as lowercase SHA-256 hex
- `context_bindings[]` - the receipt, request, transaction, runtime, and
  evidence objects that the context check was evaluated against

Each `verification_context[]` entry must use a distinct logical key formed by
(`case_artifact`, `kind`). `compare` rejects duplicate logical keys even when
their digest or nested bindings differ, so array order cannot select the
context used for comparison.

Each `context_bindings[]` entry names a `role` and `source_artifact`.
Artifact roles such as `admission_receipt` and `admission_request` carry the raw
artifact SHA-256 digest. Value roles such as `transaction_id` and `runtime`
carry the source path and observed value. Evidence roles carry the source path,
evidence type, and digest of the selected evidence object embedded in the source
artifact. For the current v0.3.x comparison path, that embedded evidence-object
digest uses the VATE v0.3 fixture JSON byte basis defined in
`docs/conformance/digest-basis.md`: object keys sorted, insignificant whitespace
removed, UTF-8 bytes, and SHA-256 lowercase hexadecimal.

For the current v0.3.x comparison path, the required binding subset is derived
from the artifacts present in each case:

- when the case includes an `admission_receipt`, bind its raw artifact digest
  and its `request.transaction_id` value when present;
- when the case includes an `admission_request`, bind its raw artifact digest;
- for a `binding` context check, bind `subject.runtime` from the admission
  receipt when present;
- identify the context evidence type using the first matching rule: a
  `runtime_attestation` or `status_bundle` source selects that same type;
  otherwise a runtime `binding` check selects `runtime_attestation`, and a
  `replay` check selects `admission_request`; and
- bind every matching evidence object from admission receipt `evidence[]` and
  admission request `evidence_refs[]` with its source path and digest.

`compare` requires every binding derived by these rules. Additional
schema-valid bindings are allowed only when they use a distinct logical key;
they do not replace a missing required binding. A binding's logical key is the
tuple (`role`, `source_artifact`, `path`, `evidence_type`), with omitted fields
represented as absent. Two entries with the same logical key are rejected even
when their digest or value differs, so array order never selects a winning
binding. JSON Schema validates each entry's shape, while `compare` enforces this
composite uniqueness rule. The required subset therefore depends on both the
context check and the case artifacts; the check `kind` alone is not sufficient.

For example, `deny-runtime-proof-stale` requires five bindings: the admission
receipt digest, its transaction id, the admission request digest, the embedded
`runtime_attestation` evidence in the receipt, and the corresponding
`runtime_attestation` evidence reference in the request.

The selected evidence object must be identified by the case or profile. Do not
use ordinary language-runtime JSON serialization as an implicit canonicalization
scheme, and do not silently substitute adjacent protocol identifiers such as PEF
`frame_id`, PEF `receipt_hash`, AP2 mandate hashes, or A2A artifact identifiers
for a VATE digest descriptor unless a VATE profile explicitly defines that
equivalence.

This lets `compare` detect SUT reports that cite a context fixture without
binding it back to the request, receipt, transaction, runtime, or evidence it was
supposed to validate.

When the corpus case includes `jose_checks`, the result entry must include
`artifacts.proof_artifacts[]` entries for each referenced `proof_package`,
`detached_payload`, and `trust_bundle` artifact:

- `kind` - one of `jose_proof_package`, `jose_detached_payload`, or
  `jose_trust_bundle`
- `case_artifact` - the corpus artifact key used by the JOSE check
- `uri`
- `media_type`
- `digest.alg` set to `sha-256`
- `digest.value` as lowercase SHA-256 hex

Each `proof_artifacts[]` entry must likewise use a distinct logical key formed
by (`case_artifact`, `kind`). `compare` rejects duplicate logical keys rather
than selecting one by array order.

The current comparison command validates the presence and descriptor shape of
these evaluated corpus artifact references, and checks their SHA-256 digest
values against the corpus artifacts required by the case. It does not fetch
arbitrary remote URIs or verify external signatures. For local report-bundle digest-chain
verification, use `scripts/vate_conformance.py verify-bundle` as documented in
`docs/conformance/report-integrity.md`.

The passing example SUT file uses `corpus-fixture-validation`. Explicit-input
status cases use `artifacts.input_artifacts[]`; legacy cases retain their prior
artifact fields. Replacing corpus input digests with independently generated
receipt digests remains incorrect.

## Generated Receipt Artifacts

For a case that exercises SUT-produced receipt output, set either the top-level
or per-result `artifact_mode` to `generated-receipts` and add:

```json
{
  "artifact_mode": "generated-receipts",
  "generated_artifacts": {
    "admission_receipt": {
      "uri": "https://implementation.example/vate/admission/receipt-1.json",
      "local_path": "artifacts/receipt-1.json",
      "media_type": "application/vate-admission-receipt+json",
      "digest": { "alg": "sha-256", "value": "<raw-file-sha256>" }
    }
  }
}
```

`uri` is the publication identifier. `local_path` is required when `uri` is
remote and must be a relative path contained by the directory holding the SUT
result. Absolute paths, parent traversal, symlink escapes, and files over 8 MiB
are rejected. `compare` does not fetch the network. It reads the bounded local
bytes, verifies their raw SHA-256 digest, parses the JSON object, and checks a
selected schema-aligned shape plus bounded semantic projection against the case.
Generated admission and post-execution references
must use `application/vate-admission-receipt+json` and
`application/vate-post-execution-receipt+json`, respectively.

For admission receipts, `receipt_id`, verifier identity, proof packaging, and
human-readable summary may differ. The fixed case clock, request, subject,
evidence, policy, ordered reason codes, decision visibility fields, decision,
and attenuation remain part of the semantic comparison. For post-execution
receipts, receipt id, issuer, proof packaging, and the concrete admission
URI/id/digest may differ, but the relationship between the generated admission
and post-execution pair must preserve the case's intended match or mismatch.
The post-execution `admission.uri` must equal the generated admission artifact
reference `uri`.
The case's linkage checks are then rerun against that pair. This permits
independent identifiers without weakening transaction, runtime,
effective-request, decision, expiry, or side-effect linkage checks.

Only generated admission and post-execution receipt roles required by the case
are accepted. Extra or unknown generated artifact keys fail closed. A top-level
`generated-receipts` default cannot be downgraded per case. For a mixed result,
use `corpus-fixture-validation` as the default and opt selected cases into
`generated-receipts`. The conformance and implementation reports expose the
effective per-case mode and aggregate mode counts.

A generated receipt pass does not prove who produced the file, verify its
signature, or establish a controlled publication origin. Publish the generated
files and implementation source or build reference with the report when
provenance matters.

The JSON Schema validates the portable result shape only. It does not know which
artifacts are required by a particular corpus case and, by itself, does not prove
artifact-backed compliance. Use `compare` against the exact corpus snapshot to
enforce case-dependent artifact requirements and digest matches.

## Compare Command

```bash
python3 scripts/vate_conformance.py compare \
  --corpus-root conformance/al2-vate-v0.3 \
  --sut-results examples/conformance/sut-results-pass.example.json \
  --report /tmp/vate-sut-compare-report.json
```

The command writes a normal VATE conformance report shape:

- `schemas/conformance-report.schema.json`

To also write an implementation report for the external SUT result, add
`--implementation-report`. The implementation identity is copied from the SUT
result file, and optional publication metadata can be supplied with
`--conformance-report-uri`, `--implementation-report-uri`,
`--publication-controlled-origin`, and `--publication-immutability`.

It exits non-zero when:

- the SUT result file has the wrong version or profile
- the SUT result corpus digest does not match the current corpus
- a case is missing
- a case id is duplicated or unknown
- a case is skipped or errored
- outcome, `should_execute`, reason codes, or required checks do not match the corpus expectation
- a generated-receipts case omits local generated receipt bytes, submits the
  wrong digest, changes bounded semantics, or fails post-execution linkage

## Check Semantics

`results[].checks[].pass` means the implementation satisfied the expected check named by the corpus case.

For example, if a negative case says:

```json
{ "name": "decision.outcome", "expected": "fail" }
```

then a SUT result should report:

```json
{ "name": "decision.outcome", "pass": true }
```

The SUT does not need to reproduce the reference runner's internal boolean model.
It only needs to state whether the named expected check was satisfied.

`should_execute` is separate from `outcome`. A case can have
`outcome: "attenuate"` while `should_execute: false` when the attenuation
requires a fresh permit before execution can proceed.

For post-execution cases, `should_execute` still refers to the pre-execution
admission gate. It does not mean the post-execution receipt or observed side
effect is valid.

The SUT result file is an input to comparison, not a standalone proof package.
Reviewers should inspect referenced artifacts and implementation reports when a
result is used outside local development.

## Claim Boundary

Passing `compare` means the SUT result file matched one corpus snapshot.

It does not imply:

- production readiness
- independent security review
- endorsement
- compatibility with future corpus snapshots
