# AP2 Human Not Present Evidence To VATE

## Status

This is a focused interoperability note for VATE-authored, AP2-style Human Not Present payment-authority projections.

It does not define AP2, Verifiable Intent, payment settlement, wallet UX, PSP behavior, or merchant checkout.
It only shows how a VATE AL2 verifier can consume a normalized Human Not Present payment-authority projection as evidence before admitting a risky purchase action.

The JSON fixtures in this directory are normalized VATE projections for
conformance review. They are not AP2 wire objects, do not claim conformance to
the AP2 Payment Mandate JSON Schema or SD-JWT packaging, and do not establish
that an AP2-native verifier accepted the source payment authority. The replay
case's authoritative normalized input uses `application/json`. The
`application/ap2-mandate+json` strings retained in three older fixed fixtures
are historical repository-local illustrative labels preserved for their pinned
external-review history; they do not denote an official AP2 media type or
AP2-native wire conformance.

## Boundary

Human Not Present payment authority is adjacent evidence.

VATE's role is to bind that evidence to:

- actor
- principal
- runtime
- merchant audience
- requested action
- amount limit
- freshness window
- one-time-use or replay state
- local verifier policy

The verifier then emits an admission receipt with `allow`, `attenuate`, or `deny`.
If execution proceeds, the post-execution receipt links the observed purchase back to the admission receipt and effective request hash.

## Fixture Set

The fixture directory is:

- `examples/interop/ap2-human-not-present-to-vate/`

The conformance cases are:

- `conformance/al2-vate-v0.3/cases/allow-ap2-hnp-preauthorized-mandate.json`
- `conformance/al2-vate-v0.3/cases/deny-ap2-hnp-stale-mandate.json`
- `conformance/al2-vate-v0.3/cases/attenuate-ap2-hnp-amount-overrun.json`
- `conformance/al2-vate-v0.3/cases/deny-ap2-hnp-replay.json`
- `conformance/al2-vate-v0.3/cases/post-execution-ap2-hnp-linkage-success.json`

## What The Cases Prove

| Case | Expected result | Why it matters |
|---|---|---|
| Pre-authorized projection | `allow` | A current, bounded Human Not Present payment-authority projection can be consumed as adjacent evidence. |
| Stale projection | `deny` | Expired projected authority evidence must fail closed. |
| Amount overrun | `attenuate` | The verifier can narrow a request to the projected authority limit instead of treating payment limits as natural-language policy. |
| Supplied replay state | `deny` | A supplied VATE-local replay-state input that marks the normalized payment-authority consume key as consumed must fail closed before execution. |
| Post-execution linkage | `success` | The final side effect can be linked back to the admitted request and payment authority reference. |

The conformance cases also check digest-bound references from the admission request, admission receipt, and post-execution receipt back to the referenced mandate or receipt artifact.

For `deny-ap2-hnp-replay`, the authoritative SUT inputs are the normalized
payment-authority artifact and a separate VATE-local replay-state context. The
context's `replay_key` uses the SHA-256 digest of the normalized authority
object under the limited VATE v0.3 fixture JSON basis (sorted object keys,
insignificant whitespace removed). Its `nonce` is a recorded observation value;
it is not the stable consume key. Neither value is asserted to equal an
AP2-native closed-mandate hash, receipt-reference hash, transaction ID, or
presentation nonce.

The external-SUT `input_artifacts[]` reference separately uses the raw file
SHA-256 required by the current comparison contract. The object digest used in
the fixture consume key and the raw-file digest used to pin the supplied bytes
are distinct VATE digest classes and must not be substituted for each other.

The committed corpus evaluates the supplied replay-state value and pins the
input bytes. It does not demonstrate a durable or atomic consume operation.

## Evidence Shape

The VATE receipt uses a generic evidence type with an informative protocol hint:

```json
{
  "type": "payment_mandate",
  "protocol_hint": "ap2_human_not_present"
}
```

This keeps the conformance surface stable while AP2 and FIDO workstreams evolve.
Implementations must not assume that `protocol_hint` alone proves authority; local policy still decides which issuers, proof methods, freshness windows, and amount limits are acceptable.

The VATE digest descriptors in these examples use the VATE fixture digest
basis. They must not be substituted for AP2-defined hashes or identifiers, and
an AP2-native reference hash must not be treated as the VATE artifact digest
unless a future profile defines and verifies that translation.

## Current Non-Goals

- no AP2 signature profile
- no FIDO governance claim
- no broad commerce profile
- no PSP or wallet integration
- no merchant order lifecycle model
- no AP2-native schema, SD-JWT, or receipt-reference-hash conformance claim
- no durable or atomic consume-once store validation
- no restart, concurrency, or value-emitting-boundary replay test
- no production endorsement claim
