# JWS Packaging And Status Delivery

This note describes the packaging and delivery choices used by the reference demo.

The intent is not to freeze the final wire format for all deployments of this draft.
The intent is to move the repository from ad hoc inline `proof` objects toward a transport pattern that looks more like real implementation work.

## Payload Versus Package

Trust envelope payloads and packaging should be treated as separate layers.

- The decoded payload carries the semantic fields such as actor, audience, runtime reference, and permit constraints.
- The package carries the signature, signer key identifier, and transport representation.

In the reference demo:

- `*.json` files are decoded trust envelope payloads.
- `*.jws` files are compact JWS packages for those payloads.

The JSON Schemas in `schemas/` validate the decoded payloads, not the compact token representation.

## Compact JWS In The Demo

Each artifact is emitted twice:

- human-readable JSON payload
- compact JWS token for verifier consumption

The demo uses ES256-style compact JWS packaging backed by OpenSSL-generated P-256 keys.

| Object | Payload file | Package file | Demo signer |
|---|---|---|---|
| `APC` | `passport-credential.json` | `passport-credential.jws` | issuer |
| `ARP` | `runtime-proof.json` | `runtime-proof.jws` | attestor |
| `AMP` | `mission-permit.json` | `mission-permit.jws` | broker |
| `AER` | `execution-receipt.json` | `execution-receipt.jws` | runtime |

The verifier reads the compact JWS files and resolves public keys from `trust-bundle.json`.
For receipts, the signer role is also reflected in the payload via `issuer_role`.

## Why This Matters

This split improves the draft in three ways:

1. It separates payload modeling from transport packaging.
2. It makes verifier logic closer to actual inter-service verification.
3. It makes future migration toward VC-style or JOSE-based profiles easier.

## Status Delivery Modes In The Demo

The reference demo also adds a minimal status service.

Three delivery modes are supported:

- `pull`
  The verifier fetches the current status snapshot from the service at verification time.
- `stapled`
  The caller carries a recent status snapshot as a signed compact token.
- `push`
  The caller carries a recent signed status event that represents the latest pushed update.

These modes intentionally share the same semantics while differing in transport.

## Minimal Service Endpoints

The demo service exposes:

- `GET /status/bundle`
  returns a signed status snapshot for pull verification
- `GET /status/stapled`
  returns a signed status snapshot suitable for local stapling
- `GET /events/latest`
  returns a signed status event for push-style verification
- `GET /status/passport/{id}`
- `GET /status/runtime/{id}`
- `GET /status/permit/{id}`
  return signed per-object status entries

## Status Payload Shapes

The service emits three related payload types before JWS packaging:

- `asn-0.1`
  snapshot-style status bundle
- `asn-event-0.1`
  push event carrying current status entries
- `asn-entry-0.1`
  per-object pull entry

The verifier normalizes them to a common `entries` structure before applying the trust envelope checks.
When a permit is `attenuated`, the normalized entry may also carry an `effect` object that narrows allowable execution.

## What This Still Does Not Solve

The demo is still intentionally narrow.

It does not yet provide:

- VC data model packaging
- federation-aware trust discovery
- remote key rotation
- transparency logs
- hardware-backed runtime attestation
- CAEP-compatible live subscriptions

Those are still future work, but the demo now exercises the correct boundary between payload, package, and status retrieval.
