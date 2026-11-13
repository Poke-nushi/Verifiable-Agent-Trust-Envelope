# Authenticated authority snapshot contract

`vate-authority-snapshot-v1` is an optional implementation aid for the ordinary
Python purchase-cap entry. It does not change the AL2 profile, artifact family,
operation digest basis or receiver assessment contract.

## Selection and wire format

The application MUST independently select a frozen `AuthoritySelection`:
`issuer`, `audience`, `scope`, `epoch`, `kid`, P-256 DER `public_key_spki`,
`minimum_revision` and `max_snapshot_age_seconds`. Identifiers use the runtime
adapter's nonempty, control-free string domain. Minimum revision MUST be an
integer from 1 through 9007199254740991, excluding booleans. Maximum age MUST be
a positive integer no greater than 2147483647 seconds.

The application MUST establish that the selected authority may issue runtime
trust and principal permission/delegation decisions for the selected scope.
Signature validity authenticates the selected source's statements; it does not
independently establish a principal's permission. Inputs MUST NOT select their
own authority, root key, scope or epoch. Root selection and its replacement are
operator actions; this contract provides no automatic root-key or epoch migration.

The compact JWS MUST satisfy the existing
[runtime wire restrictions](../runtime-jwt/CONTRACT.md#wire-format), including
strict JSON, canonical unpadded base64url, the 65536-byte complete token limit,
4096-byte decoded header limit and 64-byte ES256 `R || S` signature. The header
MUST contain exactly `alg: ES256`, `typ: vate-authority-snapshot+jwt` and the
selected `kid`. Runtime tokens and caller proofs MUST NOT be accepted as policy
snapshots. Explicit typing, algorithm and issuer/audience restrictions follow
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html#section-3); the local claim
set and type are additional application rules.

The payload MUST contain exactly:

| Claim | Meaning |
| --- | --- |
| `iss`, `aud`, `scope`, `epoch` | Exact matches to the selected authority context |
| `revision` | Complete snapshot revision, at least the selected minimum |
| `iat`, `nbf`, `exp` | Integer JWT NumericDates in the runtime adapter's supported domain |
| `runtime_grants` | Array of zero to 128 runtime issuer grants |
| `delegation_grants` | Array of zero to 128 principal-to-actor delegation grants |

The verifier MUST require `iat < exp`, `nbf < exp`, `iat <= now`,
`nbf <= now < exp` and `now - iat <= max_snapshot_age_seconds`. Expiry is
exclusive, maximum age inclusive, and no clock skew is allowed. The complete
token bound may limit the number of grants below the per-array maximum.

Each grant MUST contain exactly the fields of the existing
[`RuntimeIssuerGrant`](../runtime-jwt/CONTRACT.md) or
[`DelegationGrant`](../caller-authority/CONTRACT.md#application-selected-authority),
including explicit boolean `revoked`. On the wire, `public_key_spki_base64`
replaces `public_key_spki`, using canonical padded standard base64 for a 91-byte
P-256 SPKI. `tool_allowlist` is a JSON array. All existing grant semantics,
date ranges, key consistency and duplicate-identity checks apply. Snapshot
`iat` and `exp` supply each adapter's policy issuance and expiry.

[`snapshot-claims.schema.json`](snapshot-claims.schema.json) describes the JSON
shape. Signature checks, selected-context equality, key validity, cross-field
date relationships and policy semantics remain verifier checks beyond the schema.
The schema alone does not authenticate a snapshot.

## Complete updates and recovery

Both grant arrays MUST be replaced atomically as one complete snapshot. An
absent or revoked grant supplies no current permission. A higher revision may
replace actor/runtime keys, change grants, or restore permission. This is
current-grant evaluation, not irreversible operation cancellation.

`AuthorityStore.accept(raw)` MUST authenticate and validate the candidate at the
current trusted time before changing policy state. It MUST recheck freshness
after signature verification. Under the common update lock:

- A lower revision MUST fail without reinstalling it.
- The same revision and identical canonical decoded payload MUST be idempotent.
  A different ECDSA signature over that payload does not create a conflict.
- The same revision with a different currently valid, authenticated payload
  MUST persist a conflict and block policy leases.
- Only a strictly higher valid revision may clear that conflict. Its `iat`
  MUST NOT precede the last accepted issuance time.
- A valid current-or-new snapshot may clear a transport-unavailable flag when
  no unresolved same-revision conflict exists.

Payload equality uses the existing sorted compact JSON encoder and SHA-256;
array order remains significant. It is not general semantic equivalence.
Expired, stale, malformed or unauthenticated unsolicited candidates are rejected
without replacing current permissions. Conflict detection therefore concerns
currently usable candidates, not a proof of consistency across all signed history.

Reopening MUST preserve revision, accepted payload, conflict, unavailability and
highest observed UTC time. All time observations made by intake, lease getters
and the dispatch clock MUST be persisted before supplying permissions or time.
A later lower time MUST fail, including after restart. The local clock remains
trusted; this does not establish independent time or identify the newest
snapshot the authority has issued but this store has never seen.

Expired or stale saved state MUST still permit a valid newer update. Reading
the saved revision/digest metadata MUST NOT require the old snapshot to be
currently executable. Corrupt metadata MUST fail rather than reset the store.

## Store, lock and managed entry

This store is separate from the existing dispatch replay/attempt store.
Creation is explicit in a new private directory. Reopening requires the
independently retained anchor, which binds selection, UUID and directory,
database and lock-file identities. Missing, replaced, corrupt or unexpected
state MUST NOT be recreated automatically. The directory, ancestors, files,
anchor and application code are trusted. Inode/digest checks detect some
replacement and corruption; they do not prevent an administrator from restoring
old contents into the same trusted files. Distributed storage, network
filesystems and Windows are unsupported.

Every update and policy lease MUST hold the same anchored exclusive POSIX file
lock. Acquisition is nonblocking both within the store object and across
processes. `AUTHORITY_BUSY` or reentrant failure means the update was not
applied and the caller must explicitly retry. A lease MUST authenticate the
stored snapshot and check freshness before use. Provider getters MUST require
that thread's active lease, check current time, and return its immutable policy.
Forked handles MUST fail; a child must reopen independently. Child cleanup MUST
close inherited lock descriptors without explicitly unlocking the parent's lease.

`ManagedAuthorityVerifier` MUST acquire the ordinary dispatch boundary before
the source lease for admission, restore and dispatch. It MUST hold the lease
through the entire ordinary dispatch callback, releasing it on return or
exception. Updates that complete before the next lease are observed by that
lease. An update cannot report success during a held callback lease. Applications
MUST NOT make a callback wait for an updater whose success requires that lease
to end. There is no permission-state commit after the callback merely to
release a lease.

The facade supplies existing runtime and caller adapters with these lease-only
providers. The ordinary verifier retains its proof, request-binding, receipt
deadline and durable attempt checks. New permissions or keys MUST NOT extend
an old receipt. Runtime evidence is part of the original request and cannot
simply be replaced when its signing key is removed; a new instruction/admission
may be required. A new caller proof may authorize the exact existing request
under current grants, as defined by the caller contract.

The caller descriptor includes `authority_source_configuration_id`, binding the
selected source, its anchor, verifier configuration and intake/store/facade
sources. Grant contents may update without changing this configuration. A source
change MUST NOT silently relabel stored admissions. Installed class/source
identity checks reject retained old implementations after source replacement or
reload. They are not isolation from malicious application code in the same process.

Applications MUST require the managed path at each exposed entry that needs
this policy. An unguarded inner admission or dispatch cannot obtain permissions
from the lease-only providers. Direct ordinary restore does not call providers
and is not itself permission to execute. `dispatch_status` reads attempt state
without authorizing another attempt.

## HTTPS delivery and refresh failures

`HttpsSnapshotSource` accepts only an operator-selected HTTPS URL without userinfo
or fragment. It MUST use certificate and hostname validation with the system or
explicitly selected CA bundle, following HTTPS endpoint verification in
[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.3.4).
TLS 1.2 is the minimum. It MUST refuse redirects, environment proxies and encoded
response bodies, and accept only status 200 with media type `application/jwt`.
The response MUST fit the token limit. The selected signature is still required
even when HTTPS succeeds. No authority credentials are sent by this helper.

The helper uses a positive socket timeout up to 30 seconds and checks an overall
deadline before and after each bounded body read. These checks do not forcibly
cancel system DNS resolution or an operating-system call already blocked; they
are not a hard wall-clock cancellation guarantee. Applications needing that
guarantee must isolate and supervise transport separately.

`refresh(fetch)` retrieves bytes outside the lease lock, then validates and
installs under that lock. Any fetch or acceptance failure MUST return failure.
It attempts to persist an unavailable flag, preventing subsequent leases until
a valid current-or-new snapshot recovers the store. If the store is busy or
inaccessible, this marking can also fail: the refresh still fails and MUST NOT
be described as an acknowledged revocation or acknowledged suspension. A slow
failed refresh may mark unavailable after another refresh succeeds; applications
should serialize refresh scheduling if they need to avoid this conservative stop.

There is no background updater. The application chooses refresh frequency and
retries and must distinguish delivery, successful installation and callback
acceptance. Cached permission is usable only within expiry and maximum age.
This contract does not guarantee immediate remote revocation, cancellation
after acceptance, global rollback protection across independent stores, or
exactly-once external effects. IAM-to-grant translation and the issuing authority's
operation remain application responsibilities.
