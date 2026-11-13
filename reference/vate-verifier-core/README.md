# VATE Verifier Core

This directory contains a dependency-free reference verifier core for the active `VATE AL2 Admission Interop Profile 2026-09`.

It is not production-ready.
The default admission entry checks the original purchase request, admission
context and any reduced cap before returning a receipt. It uses the
[request-binding v1 contract](../request-binding/CONTRACT.md).

Existing callers should follow the
[request-binding migration guide](../request-binding/MIGRATION.md).

## API Shape

```python
result = verifier.admit(admission_request_bytes, original=original_operation_bytes, now=now)
```

Supply the original UTF-8 bytes for both objects. `now` is a timezone-aware
datetime; omitting it uses the current UTC time. The returned `BoundAdmission`
contains immutable bytes:

- `request`, `original`, and `effective` (the last is absent for denial)
- `receipt` and the independently recomputed `assessment`
- `core_result`, the intermediate policy result
- `runtime_evidence` and `runtime_verification` when a configured runtime
  verifier is used (both are absent on the local-policy-only path)

Read the final decision from `receipt`, not `core_result`. A purchase above the
effective cap is denied even when the intermediate policy result proposes
attenuation. `require_new_permit=True` produces a non-executable candidate when
the cap is narrowed.

Calls without `original` raise `TypeError`. Invalid or unsupported raw inputs
raise `ValueError` without returning an admission. The previous dictionary-only
call is no longer a supported admission entry. The current default supports
`vate-purchase-cap-request-v1`; other operation profiles need their own
validated adapter.

The default entry requires one `local_policy` evidence reference matching the
configured policy's canonical digest, `policy_ref` (or `local` when absent),
and `application/json` media type. It rejects unmatched or unsupported evidence
before policy evaluation and replay-state consumption. The final receipt names
the check `vate-local-policy-content-v1`; it establishes policy-content identity,
while principal, actor and runtime authentication require their own verifier.

To require runtime evidence, configure a `RuntimeEvidenceVerifier` and supply
the referenced bytes through `evidence_artifacts`. The
[runtime integration contract](../request-binding/RUNTIME-EVIDENCE.md) defines
the adapter result, request-context binding and freshness checks. With this
configuration, missing or failed runtime evidence prevents admission. An
`allow` or `attenuate` receipt, including a new-permit candidate, cannot outlive
the evidence's validity or freshness limit.
The application supplies the trusted authentication adapter; the core does
not choose keys or treat a submitted verification result as authentication.

`_evaluate_policy` is a private primitive that produces a receipt candidate
without checking preimages. The file-set and S3 examples use it after their own
profile checks. It must not be exposed as an admission endpoint. Receipt-pair
linkage checks remain available through `validate_post_execution_linkage`;
they do not inspect request preimages.

Generated receipt timestamps preserve the supplied clock's microsecond precision
and use UTC. If a request has already expired, its denial receipt records
`issued_at` and `expires_at` at the judgment time. The decision remains `deny`,
with the original reason codes; the request is unchanged. Unexpired request
expiry values retain their original timestamp representation.

## Run The Self-Test

```bash
python3 reference/vate-verifier-core/vate_verifier_core.py self-test
```

The self-test exercises the policy primitive and receipt linkage:

- allow
- attenuate
- deny
- receipt generation
- post-execution linkage validation

Test the public entry and A2A adapter, including missing or mismatched originals:

```bash
python3 -m unittest discover -s reference/request-binding -p 'test_*.py'
```

The [entry-point coverage](../request-binding/ENTRYPOINTS.md) identifies the
current adapters, limited readers and historical replay paths.

## Limits

This core does not implement production JOSE, VC, DID, or PKI processing.
The default entry produces bound purchase-cap receipts. Its private policy and
proof hooks also support deterministic conformance fixtures.

The core also applies defensive local bounds when parsing `max_amount` and
side-effect `amount` values: amounts must be finite, non-negative decimals with
at most 64 text characters, 18 integer digits, and 8 fractional digits. These
bounds are reference-core guardrails only. They do not narrow the reusable JSON
schemas or the public VATE contract for every implementation.

Timestamp comparisons accept the reference runner's RFC3339 form: an explicit
time zone and at most six fractional-second digits. Uppercase and lowercase
`T`/`Z` and numeric offsets are supported. Unsupported precision is rejected
before comparison, so it cannot be silently truncated to a permitted instant.
One through six fractional digits are interpreted consistently on Python 3.10
and later; internal zero-padding does not rewrite receipt text or its digest.
This is a reference-core input bound, not a change to the public receipt schemas.
