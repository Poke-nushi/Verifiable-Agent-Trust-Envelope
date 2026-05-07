# AP2 Human Not Present Evidence To VATE

## Status

This is a focused interoperability note for AP2-style Human Not Present payment authority.

It does not define AP2, Verifiable Intent, payment settlement, wallet UX, PSP behavior, or merchant checkout.
It only shows how a VATE AL2 verifier can consume a Human Not Present mandate as evidence before admitting a risky purchase action.

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

- `conformance/al2-vate-v0.2/cases/allow-ap2-hnp-preauthorized-mandate.json`
- `conformance/al2-vate-v0.2/cases/deny-ap2-hnp-stale-mandate.json`
- `conformance/al2-vate-v0.2/cases/attenuate-ap2-hnp-amount-overrun.json`
- `conformance/al2-vate-v0.2/cases/deny-ap2-hnp-replay.json`
- `conformance/al2-vate-v0.2/cases/post-execution-ap2-hnp-linkage-success.json`

## What The Cases Prove

| Case | Expected result | Why it matters |
|---|---|---|
| Pre-authorized mandate | `allow` | A current, bounded Human Not Present mandate can be consumed as payment-authority evidence. |
| Stale mandate | `deny` | Expired mandate evidence must fail closed. |
| Amount overrun | `attenuate` | The verifier can narrow a request to the mandate limit instead of treating payment limits as natural-language policy. |
| Replay | `deny` | One-time-use mandates require replay detection before execution. |
| Post-execution linkage | `success` | The final side effect can be linked back to the admitted request and payment authority reference. |

The conformance cases also check digest-bound references from the admission request, admission receipt, and post-execution receipt back to the referenced mandate or receipt artifact.

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

## Current Non-Goals

- no AP2 signature profile
- no FIDO governance claim
- no broad commerce profile
- no PSP or wallet integration
- no merchant order lifecycle model
- no certification claim
