# Runtime JWT / ES256 integration contract

This optional reference adapter implements `vate-runtime-jwt-es256-v1` for
the [runtime evidence integration](../request-binding/RUNTIME-EVIDENCE.md).
It authenticates an issuer's request-bound statement about a runtime under
application-selected trust. It does not authenticate the submitting caller,
principal or actor, or prove that execution occurred.

## Wire format

The evidence is a compact, signed JWT with media type `application/jwt` and no
`protocol_hint`. The full token is the raw evidence artifact. Its digest in
the admission request MUST cover exactly those bytes, without a trailing
newline. The token MUST be at most 65,536 bytes, with three nonempty,
canonical unpadded base64url segments separated by two periods. Whitespace,
padding, detached payloads, JWS JSON serialization and nested JWTs are outside
this profile.

The protected header MUST contain exactly:

| Field | Value |
| --- | --- |
| `alg` | `ES256` |
| `typ` | `vate-runtime-evidence+jwt` |
| `kid` | A nonempty application-selected key identifier, at most 1,024 characters |

The decoded header is limited to 4,096 bytes. Both header and payload MUST be
UTF-8 JSON objects without duplicate keys, invalid Unicode, floating-point
numbers or unsupported integer ranges. They use the bounded JSON domain of
the request-binding module. They need not be canonically serialized: the
signature covers the original encoded segments.

The payload MUST contain exactly:

| Claim | Meaning |
| --- | --- |
| `iss` | Issuer identifier matched to an operator grant |
| `sub` | Runtime identifier asserted by that issuer |
| `aud` | One audience string; arrays are outside this profile |
| `iat` | Token issuance time |
| `nbf` | Earliest token acceptance time |
| `exp` | Exclusive token expiry |
| `vate_context_hash` | `sha-256:<64 lowercase hex>` from `runtime_context_hash(admission_bytes, original_bytes)` |

String claims MUST be nonempty and at most 1,024 characters, without C0 control
characters or surrogate code points. Dates MUST be integer JWT NumericDates
from `0` through `253402300799`. This deliberately bounded profile does not
accept fractional dates. `typ` and the private `vate_context_hash` claim are
local integration identifiers, not registered JWT types or generic OIDC or
SPIFFE claims.

The signing input is the ASCII bytes of the original first segment, a period,
and the original second segment. The signature MUST be the 64-byte ES256
`R || S` value. Node's built-in `crypto.verify` performs P-256/SHA-256
verification with `ieee-p1363` encoding. No cryptographic arithmetic is
implemented by this adapter. The operator's key MUST be a 91-byte DER SPKI
encoding of an uncompressed P-256 public key; the native backend parses and
checks the selected key and curve.

These rules use [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html),
[RFC 7518 §3.4](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4), and
[RFC 7519 §4.1](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1).
The algorithm, issuer/subject, audience and explicit-type checks follow the
applicable guidance in [RFC 8725 §3](https://www.rfc-editor.org/rfc/rfc8725.html#section-3).
This profile's required claims and restrictions are additional application rules.

## Operator trust

`RuntimeJwtVerifier` requires an explicit profile selector, an absolute path
to an existing Node.js 22+ executable, its expected SHA-256, a trusted
`trust_policy_provider`, `max_token_age_seconds`, and
`max_policy_age_seconds`. The freshness limits are positive integers at most
`2147483647`. The subprocess timeout is finite and in `(0, 60]` seconds.
The Python reference core and conformance runner do not depend on this
optional backend.

The provider MUST be application-controlled code returning an exact frozen
`RuntimeTrustPolicy` with integer `issued_at`, `expires_at`, and a tuple of
zero to 128 frozen `RuntimeIssuerGrant` objects. The caller is responsible
for authenticating the source of these snapshots, supplying fresh revocation
information and maintaining a trustworthy evaluation clock. A received JWT or
its sender MUST NOT supply this provider or its grants.

The complete validated snapshot MUST also fit the request-binding encoder's
2 MiB (2,097,152 byte) limit. This bound applies to the adapter's internal
sorted, compact, ASCII-escaped JSON representation, including the base64 SPKI
values. The per-field character and grant-count limits do not replace this
total byte limit.

Each grant has `issuer`, `kid`, `public_key_spki` (immutable DER bytes),
`runtime`, `audience`, inclusive `not_before`, exclusive `expires_at`, and a
boolean `revoked` flag. Strings have the bounds above. Dates have the same
integer domain as JWT dates, and start MUST precede end.

A matching grant requires exact equality of issuer, key identifier, runtime
and audience. Wildcards and prefix matching are not supported. A policy MUST
NOT contain duplicate grant identities or different keys for the same
`(issuer, kid)`. A matching revoked grant, absent grant, unavailable provider,
invalid policy, expired policy or stale snapshot MUST prevent admission.
Removing a grant or marking it revoked takes effect on subsequent verifier
calls when the provider returns the updated snapshot.

The adapter reads the provider for each call and again after signature
verification. An observed snapshot change MUST fail the call. These reads do
not establish an atomic transaction with an external authority or execution;
the provider MUST supply internally consistent snapshots. The adapter does
not fetch JWKS, process certificate chains, perform online revocation
discovery, or select URLs or code from token content. `kid` is used only for
an in-memory exact lookup against the configured grants.

## Acceptance and time

At the supplied, timezone-aware evaluation time `now`, the adapter MUST check:

- `iat < exp`, `nbf < exp`, `iat <= now`, `nbf <= now < exp`;
- `now - iat <= max_token_age_seconds`;
- `policy.issued_at <= now < policy.expires_at` and
  `now - policy.issued_at <= max_policy_age_seconds`;
- the grant covers both `iat` and `now`, and is not revoked;
- the exact JWT signature verifies with the matching grant's public key;
- the authenticated `sub`, `aud` and `vate_context_hash` match the independently
  computed admission context.

There is no clock-skew allowance. The core uses inclusive microsecond bounds,
so the returned `AuthenticatedRuntimeClaims.valid_until` MUST be the earliest
of token `exp - 1 microsecond`, grant `expires_at - 1 microsecond`, policy
`expires_at - 1 microsecond`, and `policy.issued_at + max_policy_age_seconds`.
`not_before` is the later of the token and grant start. `issued_at` is derived
from the signed `iat`. The artifact digest covers the entire exact JWT.

The ordinary admission path applies its own context checks, token freshness,
purchase policy and replay checks. For `allow` and `attenuate`, including
new-permit candidates, receipt expiry is limited by the request, the bounds
above and token freshness. A policy denial remains a denial. Authentication
failure returns no admission and consumes no new replay ID.

## Backend and receiving boundaries

The native process receives only the selected public key, original signing
input and signature through stdin. Its environment excludes inherited
`NODE_OPTIONS` and user OpenSSL configuration. The executable digest and
helper-file digest are checked before and after signature verification. The
backend result must match the exact transport input digest and expected
result shape. Failure, timeout or unexpected output MUST prevent acceptance.
These checks are not dynamic-library attestation or protection against a
compromised application or host.

`RuntimeJwtError.code` is a local diagnostic. `VateVerifier.admit` exposes the
existing sanitized `RUNTIME_EVIDENCE_VERIFICATION_FAILED` error for adapter
failures. It does not return raw backend errors or change public reason-code
registries.

The saved token and runtime-verification record remain producer artifacts.
Python/TypeScript receiver binding assessments still report evidence
authentication and actual execution as `not_checked`. Retain the applicable
trust snapshot separately when an audit requires it; the receipt does not
embed or authenticate that snapshot. Signature bytes or their digest are not
replay identifiers: admission retains its existing request-ID replay scope.

The optional [`VateVerifier.dispatch` integration](../request-binding/DISPATCH.md)
uses this adapter again before a configured synchronous callback, with a
shared guard for cooperating local trust updates.
This reference adapter is not production-ready. Caller proof of possession,
principal/actor authority, distributed revocation ordering and durable
cross-process replay remain separate integration work.
