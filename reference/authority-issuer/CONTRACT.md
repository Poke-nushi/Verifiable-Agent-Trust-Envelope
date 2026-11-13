# Selected Hydra/OpenFGA issuer contract

`vate-hydra-openfga-authority-issuer-v1` is an implementation aid for the
[authenticated snapshot contract](../authority-updates/CONTRACT.md). It uses
that contract's wire format, signature verification, grant semantics and
anchored local store without changing the conformance corpus or AL2 profile.

## Registration and trust

The host MUST select one immutable `Registration` before intake: OAuth issuer,
subject, client and audience; OpenFGA store/model IDs and user/object; one
runtime issuer grant; and one delegation grant. The host MUST establish the
mapping from those service identities to the VATE identities and permitted
resource/action. The selected OpenFGA object MUST be dedicated to that
principal/client/resource binding. Objects MUST NOT be shared across mappings
to different actors or resources. Both policy writers MUST address that
selected object; this fixed-registration model does not expand a global user
permission into permissions for multiple clients. An OAuth bearer alone MUST NOT choose that mapping or supply
actor/runtime keys. The token provider and signer are trusted host callbacks.

`selected_scope` commits the registration, selected service base URLs, explicit
loopback-development flags, supported model identity and snapshot TTL using
the repository's sorted compact JSON object hash. The receiver's selected
scope MUST match it. Changing any of these inputs requires explicit source
reselection; this adapter supplies no stored-admission migration. Credentials
may rotate without changing the endpoint/registration identity. Actor/runtime
key changes also require reselection in this fixed-registration producer;
the more general snapshot receiver can accept key changes in higher revisions.

Runtime trust and the purchase currency/cap/tool allowlist are operator
restrictions. Hydra/OpenFGA do not attest the runtime, possession of the actor's
key or the purchase amount. The existing runtime and caller proof adapters
perform their respective checks at admission and dispatch.

## Source decisions

The adapter MUST POST the application-selected token to the selected Hydra
admin introspection endpoint. `active` MUST be a JSON boolean. An inactive
result produces no delegation grants and MUST NOT call the PDP. An active
result MUST exactly match the selected `iss`, `sub`, `client_id`, single-element
`aud` array and `token_use: access_token`. `iat` and `exp`, and `nbf` if present,
MUST be integer NumericDates in the existing runtime domain, excluding booleans.
At the observation start, issuance and not-before MUST have passed, and expiry
MUST be in the future. Missing or mismatched active-token metadata fails the
publication. Scope is not converted into permission.

The adapter MUST fetch the selected authorization model by its explicit ID.
Its semantics MUST match `MODEL` in `authority_issuer.py`: `can_execute` is the
intersection of direct `user_permission` and `delegation` relationships for
the same selected user/object. Protobuf's
omitted/default empty fields are normalized only at known locations; other
fields remain part of the comparison. The subsequent single Check MUST use
the selected model, user and object, relation `can_execute`, and
`HIGHER_CONSISTENCY`. It MUST NOT add caller-provided contextual tuples.
The returned `allowed` MUST be boolean. Denial produces no delegation grant;
malformed or unavailable responses fail publication.

These rules use the token-introspection model in
[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html), OpenFGA's
[intersection semantics](https://openfga.dev/docs/modeling/multiple-restrictions)
and [higher-consistency reads](https://openfga.dev/docs/interacting/consistency).
Higher consistency bypasses OpenFGA's check cache. It does not make the
introspection and Check reads one distributed transaction or prove that a
permission remains unchanged after the Check completes.

## Publication and persistence

A dedicated issuer `AuthorityStore` MUST retain the selected anchor, revision,
clock high-water mark and availability state. It is separate from both the
recipient authority store and the dispatch replay store. The publisher MUST
mark its ledger unavailable before polling and take that persisted time as
the observation start. Only one poll at a time per publisher object is allowed.
The host MUST run only one publisher for each registration; this is not a
distributed sequence allocator.

Snapshot `iat` and `nbf` are the observation start rounded down to integer
seconds. `exp` is at most `iat + ttl_seconds` (1–300 seconds), and for a permitted
delegation no later than the OAuth token expiry. The selected maximum snapshot
age MUST be at least that TTL. The grant's not-before is the maximum of its
registered start and token `iat`/`nbf`; its expiry is the minimum of its
registered end and token expiry. An expired registered grant is absent even
when a replacement OAuth token is active. A newer token issuance may require a
new caller proof; it does not automatically preserve a pending operation's
authority.

The next revision MUST be greater than the last accepted revision and at least
the selected minimum. The signer MUST return the exact constructed payload.
Before publication, the issuer store MUST verify its selected ES256 signature,
context and window at the current time, including the existing post-verification
freshness check. Failed source reads, signing or persistence return no snapshot.
Exceptions exposed to the caller contain a fixed publication-failure code,
not source response or credential text. Retrying requires a fresh observation.
Local time, application code, state files and anchors remain trusted as in the
receiver contract.

Publication and delivery are separate. The host MUST propagate a failed
refresh to the recipient's unavailable state and arrange further polling.
Failure in the issuer process alone does not notify a recipient that already
holds a still-current snapshot. The last accepted snapshot can remain usable
until its expiry or maximum age if no delivery failure/update is observed.
Permission restoration may authorize a pending receipt still within all its
original proof, grant and receipt limits; it does not undo an already attempted
dispatch or provide irreversible cancellation.

## Transport and operational limits

`JsonService` uses selected HTTPS endpoints with certificate/hostname checking,
no proxies or redirects, identity encoding, strict object JSON and a 128 KiB
response bound. It uses socket timeouts and checks an elapsed deadline while
reading the body; it is not a process-level wall-clock watchdog for DNS or
TLS/header processing. The development exception permits HTTP only at literal
`127.0.0.1` when explicitly enabled. Source credentials are selected by the host
and are not serialized in the registration.

The host MUST protect the introspection endpoint and policy writers, arrange
least-privilege service credentials, keep the authority signing key durable
and protected, and select an acceptable update interval/freshness window.
The native fixture demonstrates one controlled mapping with synthetic consent
and a recording callback. It does not establish remote peer identity, real
resource effects, distributed ordering, full JOSE/PKI coverage, or production
deployment assurance.
