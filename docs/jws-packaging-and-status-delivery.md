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

The Minimal and HTTP demos use the local `openssl` executable to sign and
verify compact JWS artifacts against their demo trust bundle. The Python
v0.3 corpus runner checks committed fixtures using the standard library.
The [JOSE/JCS proof profile](profiles/vate-proof-profile-jose-jcs-v0.2.md)
describes the separate production proof boundary.

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
  return one signed status entry for the requested object

## Status Payload Shapes

The service emits three related payload types before JWS packaging:

- `asn-0.1`
  snapshot-style status bundle
- `asn-event-0.1`
  push event carrying current status entries
- `asn-entry-0.1`
  a single passport, runtime, or permit entry for individual lookup

The verifier requires the passport, runtime, and permit entries together in
one signed snapshot or event. In pull mode it fetches `/status/bundle`. The
stapled snapshot and push event each carry the same three entries. Individual
lookups are available for inspection. The verifier does not assemble them.
For each delivery, the service reads the status store and checks the new
signature against its registered status public key before returning the token.
Every `attenuated` entry requires an `effect` object containing `mode: narrow`,
a `constraints` object, and a boolean `require_new_permit`. Both demos stop
when any entry requires a new permit or when a passport or runtime is narrowed.
They also stop if an entry supplies narrowing constraints without the
`attenuated` state.
The HTTP demo applies supported permit constraints to the admission decision.

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
