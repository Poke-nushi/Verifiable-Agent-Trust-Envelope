# Runtime evidence integration

This draft Python integration contract attaches a verifier-selected runtime
authentication adapter to `VateVerifier.admit`. It extends the
[request-binding entry](CONTRACT.md) with an evidence body and an authenticated
result for that body. The base receipt schemas and receiver binding assessment
retain their existing meanings.

## Configuration and inputs

The application MUST configure a `RuntimeEvidenceVerifier` from
`request_binding.py`, using these fields:

| Field | Requirement |
| --- | --- |
| `method` | Nonempty identifier for the configured verification method, recorded in the receipt. |
| `media_type` | Exact evidence media type accepted by this adapter. |
| `protocol_hint` | Absent/`None`, or a hint allowed for `runtime_attestation`. The request MUST match this selection. |
| `max_age_seconds` | Positive integer representable as a Python `timedelta`; booleans are invalid. |
| `verify` | Trusted callable taking `(evidence_bytes, RuntimeEvidenceContext)` and returning `AuthenticatedRuntimeClaims`, or raising on failure. |

Pass this object as the constructor's `runtime_evidence_verifier`. Supplying
configuration makes runtime evidence mandatory for every public `admit` call
on that verifier. A request MUST contain exactly one `local_policy` reference
and one `runtime_attestation` reference. With no adapter configured, the
existing local-policy-only entry remains available and rejects runtime proofs.

`admit` accepts keyword-only `evidence_artifacts`, a mapping from the runtime
reference's URI to its exact immutable `bytes`. The map MUST contain exactly
that one entry. The body MUST be nonempty and at most 2 MiB. Its raw SHA-256
MUST match the reference before the adapter is called. The core MUST NOT fetch
URIs, load code, or select a verifier or keys from submitted content.
The local-policy reference MUST still match the configured policy.

## Adapter responsibilities

The adapter is trusted application code, outside the untrusted artifact
boundary. Its implementation and trust configuration MUST be selected by the
operator, independently of the request. A Python type is an API boundary, not
an isolation boundary against compromised application code.

The adapter MUST authenticate the exact evidence bytes and validate the
issuer's authority to assert the runtime and the claims below. It MUST enforce
its selected format's algorithm, key, issuer, revocation and claim-validation
rules, including any required proof of possession or authenticated channel.
It MUST return values derived from the authenticated evidence or authenticated
observation. It MUST NOT fill missing claims by copying expected values from
`RuntimeEvidenceContext`. A signature over an unrelated object, or a bare
runtime identity without the required request-context binding, is insufficient.

The callable MUST return the exact `AuthenticatedRuntimeClaims` type:

| Field | Meaning |
| --- | --- |
| `artifact_sha256` | Lowercase raw SHA-256 of the bytes actually authenticated. |
| `context_hash` | Authenticated request-context hash defined below. |
| `runtime` | Authenticated runtime identifier. |
| `audience` | Authenticated audience for this use. |
| `issuer` | Authenticated issuer authorized by the adapter's trust configuration. |
| `issued_at` | Evidence issuance time used for the local freshness limit. |
| `not_before` | Earliest valid evaluation time. |
| `valid_until` | Last valid evaluation time, inclusive. |

All fields MUST be nonempty strings. Times MUST use the core's RFC3339 form,
with an explicit offset and at most six fractional digits. An adapter for a
format with an exclusive expiry MUST convert it to a conservative inclusive
bound; for a microsecond-resolution expiry instant, subtract one microsecond.
Unsupported temporal semantics MUST be rejected instead of rounded upward.

`RuntimeEvidenceContext` contains immutable original/admission/reference bytes,
the expected context hash, runtime, audience and caller-selected evaluation
time. These are comparison inputs, not authenticated claims. Verification
failure, unavailable verification, booleans, serialized dictionaries and
malformed results MUST prevent admission. Adapter exception details are not
copied into the public error. Authentication should have no irreversible
consume-once side effect: a later issuance failure permits retry.
The adapter MUST NOT change the verifier configuration. A policy or adapter
change detected after the callback MUST fail before policy evaluation.

## Request-context binding

`runtime_context_hash(admission_request_bytes, original_bytes)` validates the
same preimages as the admission entry, then computes:

```text
H({
  "contract": "vate-runtime-admission-context-v1",
  "admission": A with runtime_attestation entries removed from evidence_refs
})
```

`H` is the existing `sha-256:` hash over the sorted, compact, ASCII-escaped JSON
basis in [CONTRACT.md](CONTRACT.md#bytes-and-hashes). All admission fields and
the local-policy reference remain covered, including request/transaction IDs,
principal, actor, runtime, audience, action, target, original input hash,
constraints and request times. The proof's own reference is excluded to avoid a
self-digest. This hash is not the raw admission artifact digest. The returned
receipt still binds the complete admission bytes, including the runtime proof
reference, through `request_binding.admission_request_ref`.

The authenticated context hash, runtime, audience and artifact SHA-256 MUST
match the values independently computed from the call. Binding principal and
actor labels inside this context does not authenticate their authority.

## Time and issuance

The core MUST check:

- `issued_at <= now` and `not_before <= now <= valid_until`;
- ordered validity bounds and `issued_at <= valid_until`;
- `now - issued_at <= max_age_seconds`.

Freshness and normalized validity boundaries are inclusive. Future-issued,
not-yet-valid, expired or stale evidence MUST be rejected before policy
execution and replay-state consumption. Successful verification is followed
by the existing policy and preimage checks. A denial remains a denial.
For `allow` or `attenuate`, including a new-permit candidate, receipt expiry
MUST be no later than the request expiry, `valid_until`, or
`issued_at + max_age_seconds`, whichever is earliest.

The final receipt records runtime verification with the configured method and
evaluation time. A policy or replay denial does not change a successful proof
check to a failed authentication. Reference order does not select the method.
The private `core_result` remains intermediate; consumers MUST read the final
receipt and the separate verification record.

`BoundAdmission` retains the runtime body in `runtime_evidence` and a JSON
verification record in `runtime_verification`, both immutable bytes. Both are
`None` on the local-policy-only path. The record follows
[`runtime-verification.schema.json`](schemas/runtime-verification.schema.json)
and identifies the raw admission, original and evidence references, selected
method, authenticated claims, evaluation time and usable deadline. Failure to
serialize any returned artifact MUST roll back a newly consumed replay ID.
Previously committed IDs MUST remain consumed.

## Receiving and remaining boundaries

A saved verification record or receipt is a producer statement. Receiving it
MUST NOT substitute for the receiver's own selected authentication adapter and
trust policy. `assess_request_binding` and TypeScript `assessRequestBinding`
continue to report `evidence.authentication` and `execution.actual_input` as
`not_checked`, even for receipts generated through this integration. The
conformance runner's request-binding coverage continues to measure content
relationships, not execution of this authentication adapter.

This contract does not supply a production JOSE/PKI or SPIFFE adapter. A protocol
hint alone does not establish support for that protocol. The HMAC adapter in
`test_runtime_evidence.py` is a test fixture using a per-test private key, not a
public evidence format. It exercises authenticated-body verification and
context/time rejection at this integration boundary.

Checks use the supplied evaluation time; they do not observe dispatch, prove
that an action ran, establish principal/actor authorization, or provide durable
cross-process replay protection. Applications MUST recheck the applicable
validity and revocation conditions at their execution boundary and MUST NOT
change verifier configuration concurrently with admission.
