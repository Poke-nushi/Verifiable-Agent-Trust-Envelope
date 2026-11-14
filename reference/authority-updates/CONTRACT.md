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

Reopening after a process restart requires the original directory, database and
lock-file device/inode pairs. After host restarts, remounts or container
recreation, the store can be reopened only if those identities and the trusted
contents remain intact.
On a mismatch, preserve the original files and retained anchor and stop managed
operations for investigation. Applications MUST NOT manufacture a new anchor,
reset time/revision, or recreate either store to resume work. Re-anchoring and
state migration are outside this contract; the
[dispatch store](../request-binding/DURABLE-STATE.md#configure-and-reopen) has the
same continuity requirement.

Every update and policy lease MUST hold the same anchored exclusive POSIX file
lock. Acquisition is nonblocking both within the store object and across
processes. `AUTHORITY_BUSY` or reentrant failure means the update was not
applied and the caller must explicitly retry. A lease MUST authenticate the
stored snapshot and check freshness before use. Provider getters MUST require
that thread's active lease, check current time, and return its immutable policy.
Forked handles MUST fail; a child must reopen independently. Child cleanup MUST
close inherited lock descriptors without explicitly unlocking the parent's lease.

`AUTHORITY_STORE_UNAVAILABLE` covers I/O failure while accessing the anchored
store or acquiring its lock. An unrelated I/O exception raised by a lease's
consumer propagates unchanged; the lease and lock are still released.
Source identity checks at lease, intake, status and managed-entry boundaries
report unavailable or changed implementation source as
`AUTHORITY_IMPLEMENTATION_CHANGED`; refresh wraps intake failures as
`AUTHORITY_REFRESH_FAILED` even when it cannot record unavailability. During
admission or dispatch clock sampling, the dispatch boundary instead normalizes
failures from the authority clock callback to `DISPATCH_CLOCK_UNAVAILABLE`;
see the [durable admission clock contract](../request-binding/DURABLE-STATE.md#admission-and-restore).

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
An explicit CA bundle may be supplied as `ca_file` or as nonempty `ca_data`
(PEM text or DER bytes), but not both.

The helper uses a positive socket timeout up to 30 seconds and checks an overall
deadline before and after each bounded body read. These checks do not forcibly
cancel system DNS resolution or an operating-system call already blocked; they
are not a hard wall-clock cancellation guarantee. Applications needing that
guarantee must isolate and supervise transport separately.

### Supervised HTTPS acquisition

`SupervisedHttpsSnapshotSource` is an optional POSIX fetch callable for that
isolation. Each call MUST use a fresh child running the existing HTTPS checks.
Only the parent calls `AuthorityStore.refresh`; the worker MUST NOT open or
change the authority or dispatch stores. Transport success supplies untrusted
bytes to the existing signature, context, revision and freshness checks.

Configuration MUST select an HTTPS URL and a positive timeout no greater than
30 seconds. An explicit CA file MUST contain at most 1 MiB of PEM or DER data;
its bytes are captured at construction and passed over the private input pipe.
Later changes to that CA path MUST NOT change an existing source's trust.
Without an explicit bundle the worker uses its Python installation's default
CA locations. Environment-selected CA paths, proxies, TLS key logging, Python
paths and loader settings MUST NOT be inherited.
Parent-side configuration validation MUST NOT load environmental CA paths or
TLS key-log settings and MUST NOT temporarily modify the application environment.

The application trusts its running Python installation and the installed
helper sources. The source captures executable and helper digests at
construction and MUST reject detected changes before or after a call. Loaded
helper code MUST match its source identity. These are local change checks, not
independent software provenance or isolation from malicious host code.

The parent MUST bound its request to 2 MiB and the worker's output to the
65536-byte token limit. It MUST return output only after complete pipe input,
output EOF and a zero worker exit status observed within the parent deadline.
Empty or excessive output, worker failure and timeout MUST return failure,
without returning a partial body or logging worker diagnostics. The child runs
with isolated Python imports and no inherited application environment; it
spawns no additional processes.

The deadline starts before the parent starts a dedicated owner thread and covers
worker startup, DNS, TLS, response reads and worker exit. Ownership MUST be
recorded before starting that thread. The thread owns process creation through
cleanup, so Python's main-thread SIGINT handling cannot interrupt its `Popen`
construction and lose the child handle. This helper does not replace signal
handlers or change signal masks.

After validating the private request and its timeout, the worker MUST start its
own deadline before constructing the TLS source. It uses the configured timeout
and covers TLS setup, DNS, retrieval, source rechecks and pipe output. Expiry
MUST terminate the worker with a nonzero status, including when its supervising
application has exited without cleanup. This worker-local timer does not cover
interpreter startup or request validation. The parent deadline still covers
those stages while the parent is alive. Reaping an orphan remains the
responsibility of its OS parent or deployment supervisor; the worker timer does
not establish that cleanup occurred.

On timeout, failure or interruption the parent MUST request cancellation and
attempt to close pipes, kill and reap any remaining child, allowing up to three
additional seconds to confirm cleanup. If startup is still blocked, ownership
MUST remain pending; when it proceeds, the owner MUST stop and reap its child.
Unconfirmed cleanup MUST never return success. Ordinary failures report
`AUTHORITY_FETCH_CLEANUP_FAILED`; a caller's `KeyboardInterrupt` or `SystemExit`
MUST propagate even when cleanup is unconfirmed. The instance MUST expose
`cleanup_required` until cleanup completes. Its diagnostic `pending_worker_pid`
may be `None` while startup has not supplied a handle and MUST NOT be used as
the cleanup-completion test.

Cancellation before the owner enters its acquisition task MUST close a startup
gate that prevents that attempt from ever creating a child. If no thread identity
is available yet, cleanup may then complete: a thread that starts later MUST exit
without entering acquisition. A missing thread identity alone MUST NOT clear
an attempt whose owner has already entered acquisition.

It MUST refuse further fetches until cleanup confirms either that startup has
been cancelled at this gate, or that the owner has finished and any child is
reaped. The application MUST preserve an instance with unconfirmed cleanup
and investigate or clean up its pending attempt before replacing it or starting
another attempt. Concurrent
use of one instance MUST return busy. A forked process MUST construct its own
source and MUST NOT use the inherited instance to fetch or clean up its parent's
worker. OS process creation, scheduling and termination can themselves be delayed.
This is a supervised transport deadline, not a hard real-time guarantee for
the complete refresh, signature validation or store access.

Use the callable through `source.refresh(fetch)` to apply the failure handling
below. Refresh normalizes ordinary fetch failures to `AUTHORITY_REFRESH_FAILED`
and propagates interruptions; callers MUST also check `fetch.cleanup_required`
after either outcome. Calling the fetch alone does not change permission
state. Refresh scheduling and serialization across callers remain application
responsibilities; this
helper does not start a background updater or serialize complete refreshes.

### Installation and failure state

`refresh(fetch)` retrieves bytes outside the lease lock, then validates and
installs under that lock. Any fetch or acceptance failure MUST return failure.
It attempts to persist an unavailable flag, including on `KeyboardInterrupt`
or `SystemExit`, then propagates the interruption without normalizing it as an
ordinary error. A recorded flag prevents subsequent leases until a valid
current-or-new snapshot recovers the store. If the store is busy or
inaccessible, or failure recording is itself interrupted, this marking can fail:
the refresh still fails and MUST NOT
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

## Cooperative refresh lifecycle

`RefreshingAuthorityVerifier` is an optional application integration aid over
`ManagedAuthorityVerifier`, `AuthorityStore` and `SupervisedHttpsSnapshotSource`.
It does not change the snapshot profile or VATE wire contracts. Its caller MUST
give it exclusive use of the supplied fetch instance and route participating
admission, restore and dispatch calls through the coordinator. Direct use of
the underlying verifier, another coordinator or another process does not share
its local execution gate or retry schedule.

### Scheduling and local readiness

Construction MUST start with refresh required, regardless of the persisted
store's availability or snapshot lifetime. `poll()` MUST serialize cleanup,
fetch, verification and installation with other calls on that instance. The
managed entry points MUST perform a due refresh before invoking the underlying
verifier. Concurrent or reentrant calls MUST raise `snapshot.AuthorityError`
with `cause == "AUTHORITY_REFRESH_BUSY"`; they MUST NOT start another refresh
or callback. Other coordinator failures use the same exception type and its
`cause` code. Exceptions from the managed verifier retain their existing types.

A successful due poll returns the store's installation metadata. Before the
next due time it returns `None`; this includes the retry interval following a
failure. A managed call during that retry interval MUST instead raise
`AuthorityError` with code `AUTHORITY_REFRESH_RETRY_WAIT`. A poll failure MUST
propagate. Once a due refresh attempt begins, failure of cleanup, acquisition,
verification or installation MUST close this coordinator's execution gate even
if the shared store cannot acknowledge an unavailable flag. It MUST NOT be
reported as acknowledged suspension of other users of the store.

Source or configuration checks that fail before the due-time decision MUST
reject that call without changing the local readiness, retry schedule or last
refresh failure. After those checks recover, subsequent calls use the existing
deadline and MUST repeat the source, configuration and permission checks before
execution. Stop requests and clock failures follow their separate rules below.

The application selects finite positive refresh and retry intervals in seconds
and drives `poll()` when no managed calls arrive. Intervals start after an
attempt completes, using an application-selected monotonic clock. Non-numeric,
non-finite, negative or backwards clock observations and unrepresentable future
deadlines MUST block further attempts on that instance with
`AUTHORITY_REFRESH_CLOCK_INVALID`. Cleanup and history inspection remain
available. The monotonic schedule is process-local; the store's separate
persistent wall-clock, revision, freshness and expiry checks remain unchanged.
Neither an interval nor successful polling extends permission or receipt life.

Pending supervised-fetch cleanup MUST complete before acquisition can start.
A cleanup failure MUST block this coordinator and enter its retry interval;
it does not establish that the shared store was marked unavailable. Ordinary
refresh failures retain the existing `AUTHORITY_REFRESH_FAILED` behavior.
The coordinator MUST NOT include raw exception text, tokens or endpoint data in
its status record.

`RefreshStatus` reports only local scheduling observations. Its phase is
`refresh_required`, `refreshed`, `retry_wait`, `clock_failed`, `stop_requested`
or `stopped`. `refreshed` means a successful installation with no refresh yet
due; it MUST NOT be interpreted as permission to execute a particular request,
store health, current remote authority or a completed external effect.
`last_installed_revision` describes the last successful installation completed
by this instance, including one followed by a stop request or scheduling error.
It is not necessarily the current shared-store revision. A busy
instance may refuse a status read. Invalid time detected while reading status
raises the clock error and latches `clock_failed` for subsequent reads.

### Stop and restart

`request_stop()` requests a cooperative stop. After source and configuration
checks, the coordinator MUST serialize its final stop check and acceptance of
each managed call with stop requests. Passing that check is the handoff boundary:
if stop is recorded first, the call MUST be rejected; if the call is accepted
first, it may invoke managed verification and its callback even after
`request_stop()` returns. The stop request MUST NOT wait for managed verification
or callback completion. A stop request during acquisition MUST prevent that call
from being accepted after acquisition completes, even if the snapshot was
installed. `close()` MUST request stop and acknowledge completion only after
obtaining exclusive ownership and completing pending fetch cleanup. Busy or
failed cleanup MUST leave the instance in `stop_requested`; callers MUST retain
it and retry cleanup. A completed close is idempotent. A stopped instance cannot
be restarted.

`KeyboardInterrupt`, `SystemExit` and other non-ordinary interruptions MUST
propagate and request stop rather than schedule automatic retry. Already
accepted callbacks or external effects may finish. Neither `request_stop()` nor
`close()` establishes remote cancellation. The application still owns abrupt
process-termination supervision and host-level cleanup.

After process restart, the application MUST reopen the original stores with
their independently retained anchors and construct new verifier, fetch and
coordinator instances. A forked child MUST NOT use or close an inherited
coordinator (`AUTHORITY_REFRESH_FORK_REOPEN_REQUIRED`). Construction does not
recreate, clear or re-anchor either store. A valid current-or-new authenticated
snapshot is required before managed calls resume, subject to the existing
conflict and issuance rules. A successfully installed revocation remains a
revocation. Durable attempt history MUST remain authoritative when deciding
whether a retained admission may be dispatched.

`dispatch_status()` reads the underlying durable history without polling or
requiring local refresh readiness, including after close. It retains the
underlying store and configuration checks and is not a new execution path.
This lifecycle provides no deployment-wide scheduler, cross-process refresh
fence, storage migration, root-key recovery, immediate remote revocation or
exactly-once external effect guarantee.
