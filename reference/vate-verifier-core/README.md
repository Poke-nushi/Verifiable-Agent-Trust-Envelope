# VATE Verifier Core

This directory contains a dependency-free reference verifier core for the active `VATE AL2 Admission Interop Profile 2026-09`.

It is intentionally small and not production-ready.
The purpose is to make admission behavior testable before binding it to A2A, MCP, HTTP, or another transport.

## API Shape

```python
decision = verifier.admit(admission_request, now=now)
```

The returned object contains:

- `decision`
- `reason_codes`
- `admission_receipt`

Generated receipt timestamps preserve the supplied clock's microsecond precision
and use UTC. If a request has already expired, its denial receipt records
`issued_at` and `expires_at` at the judgment time. The decision remains `deny`,
with the original reason codes; the request is unchanged. Unexpired request
expiry values retain their original timestamp representation.

## Run The Self-Test

```bash
python3 reference/vate-verifier-core/vate_verifier_core.py self-test
```

The self-test exercises:

- allow
- attenuate
- deny
- receipt generation
- post-execution linkage validation

## Limits

This core does not implement production JOSE, VC, DID, or PKI processing.
It provides hooks and deterministic behavior for conformance fixtures.

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
