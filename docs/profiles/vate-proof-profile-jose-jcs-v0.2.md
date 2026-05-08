# VATE JOSE/JCS Proof Profile v0.2
## Review boundary for production proof verification

## Status

This is a review profile for future production proof verification.

It does not change the v0.2 AL2 conformance claim. The current corpus still
uses dependency-free byte-level detached JWS fixtures and does not verify real
ECDSA, EdDSA, PKI, DID, or certificate-chain signatures.

The purpose of this profile is to define the proof boundary before adding a
JOSE or JCS dependency to the reference runner.

## Standards Basis

This profile is intended to align with:

- JSON Web Signature (JWS), RFC 7515:
  <https://datatracker.ietf.org/doc/html/rfc7515>
- JSON Web Token Best Current Practices, RFC 8725:
  <https://datatracker.ietf.org/doc/html/rfc8725>
- JSON Canonicalization Scheme (JCS), RFC 8785:
  <https://datatracker.ietf.org/doc/html/rfc8785>
- CFRG curves and EdDSA for JOSE, RFC 8037:
  <https://www.rfc-editor.org/rfc/rfc8037>

## Profile Boundary

This profile defines how a verifier should validate signed VATE and adjacent
evidence artifacts when a deployment chooses JOSE/JCS proof packaging.

It does not define:

- a global PKI;
- DID resolution;
- a certificate path-building profile;
- a Sigstore profile;
- an A2A trust registry;
- identity issuance;
- payment authorization semantics;
- verifier policy language.

## Production Claim Boundary

Passing the current v0.2 AL2 corpus does not mean this proof profile has been
implemented.

An implementation may report support for this profile only when it actually
performs the verification steps below and records the implementation boundary in
its implementation report.

## Payload Canonicalization

When the signed payload is JSON, the production profile should use RFC 8785 JCS
as the canonical byte basis unless a narrower profile names another exact byte
basis.

The signed JSON payload must avoid inputs that make canonicalization ambiguous
or implementation-dependent:

- duplicate object keys;
- non-finite numbers;
- floats whose representation is not stable across implementations;
- implementation-dependent Unicode normalization;
- parsing a different byte stream from the one covered by the digest.

The digest target must be named before verification starts. A verifier must not
verify a reserialized object unless the profile explicitly says that the
reserialized JCS form is the signing and digest basis.

## JWS Packaging

The profile should support compact JWS and detached JWS where the exact payload
bytes are available to the verifier.

For detached payloads, the verifier reconstructs the signing input from:

```text
BASE64URL(protected-header) || "." || BASE64URL(payload-bytes)
```

The verifier must not accept a detached proof for a different artifact, media
type, transaction, audience, or digest target.

## Protected Header Requirements

The JWS must use a protected header.

The protected header must contain:

- `alg`
- `kid`
- `typ`

The verifier must not use unprotected header values for trust decisions.

If `crit` is present, every critical header parameter must be understood and
allowed by the active profile. Unknown critical headers fail closed.

## Algorithm Policy

The verifier must use an explicit algorithm allowlist.

Allowed algorithms are deployment choices, but the initial review candidates
are:

- `ES256` for broad JOSE library support;
- `EdDSA` with Ed25519 where RFC 8037 support is reliable.

The verifier must reject:

- `none`;
- algorithms not listed by local verifier policy;
- algorithms not allowed by the matched trust anchor;
- symmetric/asymmetric algorithm confusion;
- a header-selected algorithm that conflicts with trust-bundle policy;
- a key type that is incompatible with the selected algorithm.

## Key And Issuer Resolution

The verifier must resolve `kid` and issuer information under local policy.

At minimum:

- `kid` resolves to exactly one active trust anchor;
- the trust anchor is valid at verification time;
- the trust anchor is not revoked, disabled, suspended, or expired;
- the trust anchor allows the evidence type being verified;
- the trust anchor allows the selected algorithm;
- the issuer is allowed for the verifier's deployment context.

Ambiguous issuer or key resolution fails closed.

## Status, Revocation, And Freshness

Proof validity is not enough. A verifier must also evaluate freshness and
status according to the selected profile.

The profile should define:

- status source priority;
- maximum age;
- clock skew;
- fail-open or fail-closed behavior;
- revocation and suspension semantics;
- how status evidence is bound to the artifact being evaluated.

For AL2 risky writes, missing or stale status for review-critical evidence
should fail closed unless a narrower deployment profile explicitly permits a
different behavior.

## Replay And Transaction Binding

The signed payload or associated proof context should bind to the current
transaction when replay matters.

The verifier should check:

- nonce or replay key;
- transaction id;
- audience or verifier id;
- action or operation id;
- resource or target id;
- issued-at and expiration window;
- original request hash;
- effective request hash after attenuation;
- policy snapshot digest where policy reconstruction is required.

Replayed, expired, or cross-audience proofs fail closed.

## Artifact Dereference Rules

A URI in A2A metadata or a VATE artifact reference is untrusted input.

Before dereferencing, the verifier should apply local policy for:

- allowed URI schemes;
- allowed hosts or trust domains;
- redirects;
- maximum response size;
- timeout;
- content type;
- media type pinning;
- digest verification before semantic use;
- network isolation to prevent SSRF.

The verifier should fetch and parse only the artifact whose media type and
digest match the reference. A mutable URL alone is not a proof target.

## Detached Artifact Substitution

Detached proofs are vulnerable to substitution if the verifier accepts the right
signature over the wrong payload.

The verifier must bind:

- proof package;
- payload bytes;
- artifact reference digest;
- media type;
- transaction or audience context;
- expected artifact type.

Any mismatch fails closed.

## Failure Reason Mapping

Implementations should map proof failures to existing AL2 reason codes where
possible:

| Failure | Preferred reason code |
| --- | --- |
| malformed JOSE or missing required protected header | `SCHEMA_INVALID` |
| unsupported or disallowed algorithm | `ALG_NOT_ALLOWED` |
| `alg: none` | `ALG_NOT_ALLOWED` |
| unknown trust anchor | `UNKNOWN_TRUST_ANCHOR` |
| ambiguous trust anchor | `SCHEMA_INVALID` |
| trust anchor not authorized for evidence type | `ISSUER_NOT_AUTHORIZED` |
| revoked trust anchor | `TRUST_ANCHOR_REVOKED` |
| expired trust anchor | `TRUST_ANCHOR_EXPIRED` |
| not-yet-valid trust anchor | `TRUST_ANCHOR_NOT_YET_VALID` |
| invalid signature | `SIGNATURE_INVALID` |
| payload or artifact digest mismatch | `DIGEST_MISMATCH` |
| stale status evidence | `STATUS_STALE` |
| replayed proof or nonce | `REPLAY_DETECTED` |

Denial receipts should include `FAIL_CLOSED` when proof failure prevents
execution.

## Relationship To Current Fixtures

The v0.2 AL2 corpus currently checks:

- protected header bytes;
- detached payload bytes;
- base64url encoding;
- detached payload SHA-256 digest;
- signing-input digest;
- `alg=none` rejection;
- unsupported `crit` rejection;
- trust-bundle issuer, key id, algorithm, status, validity, and evidence-type
  checks.

Those checks are byte-level and dependency-free. They are useful conformance
review aids, but they are not production cryptographic signature verification.

## Implementation Dependency Gate

The reference runner should not add a JOSE or JCS dependency without an explicit
dependency decision.

Before adding one, record:

- exact package name and pinned version;
- package manager or installer behavior;
- lifecycle scripts or native rebuild behavior;
- maintenance status;
- security history;
- supported algorithms;
- how RFC 8785 canonicalization is implemented or tested;
- how negative fixtures will prove algorithm confusion, detached substitution,
  and critical-header behavior.
