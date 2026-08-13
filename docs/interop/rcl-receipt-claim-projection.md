# RCL Receipt-Claim Source-to-VATE Projection

## Status

This package adds three VATE-authored cases to the canonical AL2 v0.3 corpus:
RCL-005, RCL-006, and the RCL-008 acceptance control. Each request, receipt,
post-execution receipt, action object, and params object outside the carried
source fixture is a **derived VATE projection**. None is a source RCL artifact.

The package is conformance-development input for one discussion-draft corpus
snapshot. It is not an external SUT run, independent implementation result,
semantic-equivalence result, compatibility claim, adoption signal,
endorsement, certification, or production approval.

## Source And License

Source repository:

- `https://github.com/msaleme/red-team-blue-team-agent-fabric`

Discussion and handoff record:

- VATE issue: `https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/30`
- VATE mapping correction:
  `https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/30#issuecomment-5209176439`
- source-author handoff:
  `https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/30#issuecomment-5281915833`
- VATE acknowledgement:
  `https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/30#issuecomment-5282295933`

The source repository is licensed under Apache-2.0. Its pinned revision
contains an Apache License 2.0 `LICENSE` file and no `NOTICE` file. VATE also
uses Apache-2.0; the repository-root `LICENSE` supplies the license text for
the carried fixture. This section supplies the source attribution and exact
provenance.

Pinned source fixture:

- commit: `825986680dc53fa776038db814b8d1da1dfcba9c`
- source path: `fixtures/rcl/rcl-oracle-fixtures.v1.json`
- carried path:
  `conformance/al2-vate-v0.3/external/rcl/rcl-oracle-fixtures.v1.json`
- complete-file raw SHA-256:
  `4164151383605d9d68230d81cc9ae1dd31eb5cfb3fb1348289abf71ee64773ea`
- carriage mode: complete pinned file, byte for byte

Pinned source harness:

- commit: `d6b7184e0d205672463f7f3284571e9e6a3e797d`
- path: `protocol_tests/receipt_claim_harness.py`

The source case pointers are `/fixtures/4` for RCL-005, `/fixtures/5` for
RCL-006, and `/fixtures/7` for RCL-008. No per-case source extraction is
presented as original source bytes. The smaller action and params files are
value-preserving derived VATE projections and are labelled accordingly in
their filenames and the projection record.

The reviewable provenance and mapping record is:

- `examples/interop/rcl-to-vate/rcl-005-006-008-projection-map.v1.json`

It records the source repository, fixture and harness commits, source path,
case pointer, selected preimage, digest basis, projection classification, and
artifact path for every derived object.

## Digest Boundaries

The complete source fixture uses raw SHA-256 over the exact carried file
bytes. The corpus manifest records that raw digest.

The source harness hashes selected JSON values with:

```text
json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

The selected source values in this slice contain only ASCII strings and
integers, but the named source basis is still not RFC 8785/JCS. The current
VATE fixture-object basis uses the same Python serialization expression for
these committed object comparisons. Matching outputs here do not establish a
general canonicalization equivalence.

The VATE `input_hash` and `execution.effective_request_hash` fields are not
populated from a source RCL action or occurrence digest. They share the
separate derived preimage:

- `examples/interop/rcl-to-vate/request-basis.derived-vate-projection.json`

Likewise, VATE `result.output_hash` uses the derived settled-result mapping
preimage in `result-basis-settled.derived-vate-projection.json`; it is not the
source `claims.occurrence.outcome_digest`.

## Case Mapping

| Source case | VATE case | Phase | Machine-checked projection |
|---|---|---|---|
| RCL-005 | `rcl-005-authorization-params-mismatch` | admission only | The selected `action_params` object does not match the source authorization descriptor on the case-local mapping path; the real action binding still matches. |
| RCL-006 | `rcl-006-occurrence-action-linkage-mismatch` | full pipeline | Admission binds the selected action; the successful post-execution receipt binds the source occurrence's other-action digest; `path_match` rejects the linkage. |
| RCL-008 | `rcl-008-full-pipeline-acceptance-control` | full pipeline | Admission and post-execution action bindings both match the selected action and the successful settled result is accepted. |

### RCL-005

The source `claims.authorization.params_digest` is represented as a VATE
`{ "alg": "sha-256", "value": "..." }` descriptor at:

```text
admission_receipt.request.mapping_only.source_authorization.params_digest
```

`mapping_only` is a case-local extension selected explicitly by this case's
`artifact_reference_checks`. It is not a generic VATE authorization field,
does not change the v0.3 schema, and cannot grant authority. The check hashes
the derived `action_params` object and requires `expect_match: false`.

The admission receipt keeps
`request.action_binding.digest` bound to the actual selected action. Its
decision is `deny`, its execution gate is false, and its ordered reasons are
`ACTION_NOT_PERMITTED` followed by `FAIL_CLOSED`. There is no post-execution
receipt in this case.

### RCL-006

The shared admission receipt is valid and executable. Its action binding uses
the admitted source action digest. The post-execution receipt keeps
`result.outcome: success` because the source occurrence claim is built from a
settled result; the claim verifier rejects the action linkage, not execution
itself.

The post-execution action binding uses the occurrence claim's other-action
digest. `artifact_reference_checks` recomputes the admitted and other-action
preimages as match and mismatch against both binding paths. A
`linkage_checks.kind: path_match` check requires `expect_match: false` and
produces `POST_EXEC_LINKAGE_MISMATCH`.

No source action digest is copied into VATE `input_hash` or
`execution.effective_request_hash`.

### RCL-008

RCL-008 remains a positive full-pipeline control. The valid authorization
params descriptor, admitted action binding, occurrence action binding,
admission link, transaction, runtime, time window, and VATE request-chain hash
all match. The expected post-execution outcome remains `success`.

A verifier that rejects every case cannot pass this control. There is no
`pairing` object in any of the three cases; RCL-005 stops at admission while
RCL-008 deliberately retains its post-execution phase.

## Validation Split

Source-profile validation and VATE projection validation remain separate.

The source harness command is:

```bash
python3 -m protocol_tests.receipt_claim_harness --simulate --json
```

That source command checks the source Ed25519 envelopes, authority-specific
attestations, and claim-level outcomes. The VATE reference runner does not
perform those checks and must not be cited as having done so.

The VATE projection command is:

```bash
python3 scripts/vate_conformance.py run \
  --corpus-root conformance/al2-vate-v0.3 \
  --report /tmp/vate-conformance-report.json
```

That command validates the committed VATE projection relations and corpus
fixtures only. `compare` remains the separate command for an external SUT
result.
