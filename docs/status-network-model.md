# Status Network Model

This note proposes a baseline model for the status layer (`ASN`) in this draft.

The goal is to make revocation, suspension, attenuation, and freshness checks explicit rather than implicit.

## Why This Draft Needs A Status Layer

Signed artifacts alone are not enough.

An agent passport, runtime proof, or mission permit may still be structurally valid even when it should no longer be trusted because:

- the controller revoked authority
- a runtime was quarantined after suspicious behavior
- a permit was attenuated after risk increased
- a verifier can no longer obtain fresh enough status information

For that reason, this draft treats status as a first-class protocol concern.

## Core Objects

At minimum, a status-capable deployment of this draft needs:

- a status issuer or authority
- status entries for `APC`, `ARP`, and `AMP`
- freshness metadata
- a verifier policy for fail-open or fail-closed behavior

Receipts (`AER`) may also have status, but for the minimal model they are usually append-only evidence objects rather than revocable authority artifacts.
Admission receipts record the verifier decision at policy-evaluation time.
Post-execution receipts record or reference what happened later and should link back to the admission receipt when one exists.

## Core State Vocabulary

The core vocabulary in this draft should stay small:

- `active`
- `suspended`
- `revoked`
- `quarantined`
- `attenuated`

Suggested meaning:

- `active`: valid for normal use
- `suspended`: temporarily blocked pending review
- `revoked`: permanently invalid for trust decisions
- `quarantined`: blocked because of suspected compromise or abnormal behavior
- `attenuated`: still usable, but only under narrower policy than originally granted

When a verifier honors an `attenuated` status entry, the admission receipt should carry a structured `attenuations[]` list describing the field narrowed, the original value, the applied value, the reason code, and the source status reference.

Profiles or extensions may add finer detail such as `degraded`, `disputed`, or physical-only states.
The core vocabulary above is the interoperable baseline for v0.1.

## Minimal Status Document Shape

The minimal status document can be modeled as:

```json
{
  "version": "asn-0.1",
  "issuer": { "id": "status:example:authority" },
  "generated_at": "2026-04-17T00:00:00Z",
  "next_update_at": "2026-04-17T00:30:00Z",
  "entries": {
    "passport": {
      "id": "appc:123",
      "state": "active",
      "last_changed_at": "2026-04-16T23:55:00Z",
      "reason": "good-standing"
    },
    "runtime": {
      "id": "arp:456",
      "state": "active",
      "last_changed_at": "2026-04-16T23:58:00Z",
      "reason": "fresh-attestation"
    },
    "permit": {
      "id": "amp:789",
      "state": "attenuated",
      "last_changed_at": "2026-04-16T23:59:00Z",
      "reason": "policy-tightened",
      "effect": {
        "mode": "narrow",
        "require_new_permit": false,
        "constraints": {
          "max_amount_usd": 0,
          "max_redelegation_depth": 0,
          "tool_allowlist": ["read_file"],
          "approval": {
            "mode": "human_required"
          }
        }
      }
    }
  }
}
```

This shape is intentionally simple.

More advanced deployments may instead use:

- bitstring or compressed status lists
- per-object status endpoints
- CAEP-style event delivery
- stapled status assertions bundled into a verifier request

## Freshness Expectations

Verifier behavior should depend on assurance level.

Suggested defaults:

| Assurance level | Freshness expectation | Typical verifier stance |
|---|---|---|
| `AL1` | cached status may be acceptable for longer periods | often fail-soft |
| `AL2` | status should be recent and bounded by `next_update_at` | usually fail-closed for writes |
| `AL3` | near-real-time status is preferred | fail-closed |
| `AL4` | continuous or tightly bounded status plus runtime assurance | fail-closed |

The important point is not the exact number of seconds.
The important point is that each profile states:

- how fresh status must be
- what happens when freshness cannot be established
- whether attenuation can be honored automatically or requires a new permit

## Pull, Push, And Stapled Modes

Three delivery styles are useful:

1. Pull
   The verifier resolves status from a network location or federation path.
2. Push
   A status authority sends signed change events to subscribed verifiers or policy engines.
3. Stapled
   The caller attaches a recent status assertion to the request, and the verifier decides whether that stapled proof is fresh enough.

This draft should allow all three.
The protocol value is in consistent semantics, not in forcing one transport.

## Minimal Service Shape

A practical minimal service can expose:

- `GET /status/bundle`
- `GET /status/stapled`
- `GET /events/latest`
- `GET /status/passport/{id}`
- `GET /status/runtime/{id}`
- `GET /status/permit/{id}`

The important point is not the exact URL layout.
The important point is that each response carries:

- a signed status payload
- freshness metadata such as `generated_at` and `next_update_at`
- a stable way to bind the response to the presented artifacts

In the reference demo, these responses are packaged as compact JWS tokens so that the verifier exercises both signature verification and retrieval mode handling.

## Attenuation Matters

`attenuated` is particularly useful for agent systems.

In many cases, the correct response is not full revocation.
Instead, the status layer should be able to express:

- lower transaction limits
- narrower tool allowlists
- reduced redelegation depth
- approval escalation requirements

That means a verifier may need both:

- the original permit
- the current status assertion that narrows its usable scope

## Minimal Attenuation Shape

A minimal machine-readable attenuation effect can be represented as:

```json
{
  "effect": {
    "mode": "narrow",
    "require_new_permit": false,
    "constraints": {
      "max_amount_usd": 0,
      "max_redelegation_depth": 0,
      "tool_allowlist": ["read_file"],
      "approval": {
        "mode": "human_required"
      }
    }
  }
}
```

Interpretation:

- `mode: narrow` means the artifact is still usable only under the listed narrower constraints
- `require_new_permit: true` means a verifier should not continue automatically even if it understands the constraints
- `constraints` describe the effective narrowed scope that the verifier or policy engine should apply

## Privacy And Federation Notes

Status systems can create correlation risks.

For that reason, deployments of this draft should prefer:

- pairwise identifiers where practical
- minimized status lookups for low-risk contexts
- federation models that do not require a single global registry

OpenID Federation, CAEP-style signaling, and VC status methods are relevant adjacent building blocks, but this draft still needs its own profile guidance about which object states affect verifier outcomes.

## Minimal Verifier Rules

At minimum, a verifier should answer four questions:

1. Is the status document fresh enough for this assurance profile?
2. Do the status entries refer to the exact `APC`, `ARP`, and `AMP` objects being presented?
3. Are those entries in a state compatible with the requested operation?
4. If an object is `attenuated`, does local policy know how to narrow the execution safely, and does the `effect` object say whether a new permit is required?

If the verifier cannot answer those questions confidently, it should deny or step up review rather than continuing as if nothing changed.
