# Caller authority integration contract

This optional implementation aid, `vate-caller-jwt-es256-v1`, applies to the
ordinary Python [purchase-cap entry](../request-binding/CONTRACT.md). The
existing AL2 profile, artifact family and operation digest basis are unchanged.

## Signed instruction

The actor signs the complete raw admission-request bytes and original-operation
bytes through SHA-256 digest claims. The full admission includes principal,
actor, runtime, audience, action, target, declared constraints, request ID,
operation ID, request validity and evidence references. The caller proof is
supplied separately, avoiding a self-reference cycle.

This authenticates the actor key's approval of those bytes under a selected
grant. It does not prove the identity of a relay, current transport-channel
possession, a human interaction or the runtime's execution. It is an
application-specific signed instruction, not a general OAuth access token,
OIDC ID token or DPoP proof. A valid instruction can be relayed. Admission
replay and operation-attempt consumption are enforced by the selected store.

The token MUST use the [runtime adapter's compact encoding and ES256 backend
restrictions](../runtime-jwt/CONTRACT.md#wire-format): canonical unpadded
base64url, strict UTF-8 JSON without duplicate keys, at most 65,536 token bytes,
a 4,096-byte decoded header and a 64-byte ES256 `R || S` signature. The header
MUST contain exactly `alg: ES256`, `typ: vate-caller-proof+jwt`, and `kid`.
The runtime token type and runtime claims MUST NOT be accepted here.

The payload MUST contain exactly these fields:

| Claim | Required value |
| --- | --- |
| `iss`, `sub` | Both equal the admission's actor identifier |
| `aud` | The admission's one audience string |
| `iat`, `nbf`, `exp` | Integer JWT NumericDates; expiry is exclusive |
| `grant_id` | Exact grant identifier selected from the authority snapshot |
| `request_sha256` | Lowercase 64-character SHA-256 of the complete admission bytes |
| `original_sha256` | Lowercase 64-character SHA-256 of the original operation bytes |

Dates use the runtime adapter's bounded NumericDate domain and no skew
allowance. All non-digest identifiers MUST be nonempty strings of at most
1,024 characters, without C0 controls or surrogates. Signature validation,
algorithm restriction, exact issuer/subject/audience checks and distinct token
typing follow the applicable [RFC 8725 guidance](https://www.rfc-editor.org/rfc/rfc8725.html#section-3).
The exact claim set and local type are additional application rules, not a
registered JWT profile.

## Application-selected authority

`CallerJwtAuthorizer` requires `expected_profile`, an `authority_id`, the
existing Node executable path and expected digest, a trusted
`authority_policy_provider`, positive integer `max_token_age_seconds` and
`max_policy_age_seconds` (at most 2147483647), and the backend timeout.
`authority_id` identifies the application-selected authority source. It is
configuration, not a token assertion or authentication mechanism for that source.

The optional `authority_source_configuration_id` is an application-selected
nonempty identifier included in the adapter descriptor. The
[authenticated snapshot integration](../authority-updates/CONTRACT.md) uses it
to bind the selected intake configuration and anchored store. It does not
authenticate a provider by itself.

The provider MUST return an exact frozen `AuthorityPolicy` with integer
`issued_at`, `expires_at` and a tuple of zero to 128 frozen `DelegationGrant`
objects. A grant contains:

- `grant_id`, `principal`, `actor`, `kid` and a DER P-256 `public_key_spki`;
- exact `runtime`, `audience`, `resource` and `action`;
- three-uppercase-letter `currency`, a supported decimal-string `max_amount`
  and a tuple of one to 32 distinct `tool_allowlist` identifiers;
- inclusive `not_before`, exclusive `expires_at` and boolean `revoked`.

The authority MUST establish both the principal's permission for this scope
and delegation to the actor. Key possession or equality of subject labels
does not establish either permission. The application MUST authenticate the
snapshot source, constrain its authority scope, and supply fresh revocation
information. Received tokens or requests MUST NOT select the provider or
supply their own trusted grants. The adapter itself fetches no URLs.

Duplicate grant IDs or different keys for the same `(actor, kid)` MUST fail the
whole snapshot. The internally encoded snapshot, including public keys, MUST
fit the binding encoder's 2 MiB bound. Public keys and dates use the runtime
adapter's supported domains. Identifiers use exact equality, without wildcards.
Permission changes and dispatches in one process MUST share the
[`DispatchBoundary.update()` guard](../request-binding/DISPATCH.md#update-order-and-concurrency).
Cross-process permission updates require application-provided ordering;
SQLite replay state does not order remote authority updates.

## Required checks

Before policy evaluation or new admission replay consumption, the adapter MUST:

1. Validate the original and admission using the existing purchase-cap contract.
2. Check token structure, type, algorithm, exact raw digests, actor and audience.
3. Check `iat < exp`, `nbf < exp`, `iat <= now`, `nbf <= now < exp` and
   `now - iat <= max_token_age_seconds`.
4. Select one current, unrevoked grant from a current, fresh authority snapshot.
   The grant MUST cover both token issuance and evaluation time.
5. Match principal, actor, runtime, audience, action, resource and key ID.
6. Require the original declared cap and actual amount to use the grant's
   currency, with `actual <= declared cap <= grant cap`. Every declared tool
   and the actual tool MUST be within the grant's tool set. A larger declared
   scope MUST be rejected even if local policy would subsequently narrow it.
7. Verify the signature with the selected actor key. Read the snapshot again
   and reject any observed change during signature verification.

The generic `CallerAuthorityVerifier` interface can support another trusted
application adapter. It receives immutable raw inputs and returns typed
`AuthenticatedCallerClaims` derived from authentication and authorization.
The core independently checks their exact proof/request/original digests,
principal, actor, runtime, audience and validity/freshness. A dictionary or
boolean verification result is rejected. The core sanitizes adapter exceptions.
The generic interface does not itself implement the provider's authorization
semantics; its `configuration_id` MUST identify those semantics and trust scope.

`allow` and `attenuate` receipts, including new-permit candidates, MUST expire
no later than either runtime or caller authorization's usable deadline. The
caller deadline intersects token expiry, grant expiry, snapshot expiry and
both freshness limits. Exclusive expiries become inclusive microsecond bounds.
Local attenuation can narrow the authorized scope further. The cap applies to
one request, not cumulative spending; distinct operation IDs are not an
independent determination that two requests represent different business orders.

## Dispatch and recovery

Selecting `caller_authorizer` requires the runtime verifier, dispatch boundary
and durable store. Both `admit(..., caller_proof=...)` and
`dispatch(..., caller_proof=...)` MUST require proof bytes. Supplying proof
without a configured authorizer MUST fail rather than ignore it.

Dispatch MUST reauthenticate runtime evidence and caller proof and reevaluate
current authority before the existing final clock checks and durable attempt
claim. The usable deadline is the minimum of the old receipt expiry and the
new runtime/caller deadlines. Time spent in verification, replay-lock waiting,
SQLite locking or commit MUST NOT extend it. A fresh proof or grant MUST NOT
renew an old receipt.

Authority is reevaluated against a current grant for the same exact request
and subjects; admission does not pin the original grant ID. If G1 is revoked
and G2 independently authorizes the same signed instruction, a valid proof
under G2 can dispatch the pending admission within its original deadline.
Revoking G1 alone is therefore not permanent cancellation of that operation.
Operation cancellation and remote in-flight cancellation are separate policies.

The store MUST retain no caller token. `restore_admission(request_id)` restores
only existing bound artifacts and does not authenticate a caller. Dispatch
still requires supplied proof and current authority. Each stored row's configuration
pins the optional authority mode, descriptor and generic helper source;
the concrete adapter's descriptor pins its profile, authority ID, freshness
limits, backend configuration and loaded source identities. Current grants
may change without changing that descriptor.

The concrete authorizer MUST use its installed class and selected ES256 backend
from the identified sources. A retained older class or backend MUST NOT acquire
a new implementation identity through module reload. Unstamped subclasses are
unsupported; integrations using other implementations should supply the generic
`CallerAuthorityVerifier` with their own explicit configuration identity.

Removing or changing the configured authorizer MUST prevent dispatch of an
old local object or restoration of its stored row. This is a per-admission
configuration check, not a store-wide mandatory authentication policy.
Application code remains trusted and can configure other admissions differently.
It MUST require the appropriate authority mode at every exposed entry. Source
changes also make old stored configurations incompatible; recovery across code
upgrades requires a separately defined migration and cannot silently repin rows.

The same request ID cannot be admitted again in the shared store. Multiple
pending requests for one operation are permitted; only one operation attempt
can be claimed. A failed callback or uncertain post-claim result remains
consumed under the [durable-state contract](../request-binding/DURABLE-STATE.md).
These properties do not provide exactly-once external effects or global replay
protection across independent stores.

## Local record and scope

The pre-dispatch checkpoint adds `caller_authorization`, conforming to
[`caller-authorization.schema.json`](../request-binding/schemas/caller-authorization.schema.json).
It contains proof and input digest references, identities, the current authority
and grant IDs, validity and verification metadata. Raw proof bytes are absent
from the checkpoint, receipt and stored bound values. The default example
exports no caller token. Applications remain responsible for their own logs.

The receiver's binding assessment still reports evidence authentication and
actual execution as `not_checked`. A received checkpoint does not confer local
dispatch authority. TypeScript receiver checks do not implement this adapter.
General IAM, arbitrary delegation chains, authenticated remote trust delivery,
transport peer identity, provider idempotency and independent effects remain
outside this reference integration.
