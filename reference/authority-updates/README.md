# Receive signed authority updates

Connect an application's signed permission feed to the ordinary Python purchase
verifier. Each complete snapshot supplies runtime trust and principal-to-actor
delegation grants. The integration authenticates the selected source, retains
its revision across process restarts, and reevaluates current permissions before
the dispatch callback.

This optional reference integration adds an HTTPS intake helper and a separate
local policy store to the existing [runtime](../runtime-jwt/README.md) and
[caller](../caller-authority/README.md) adapters. It uses Python's standard
library and the existing Node.js 22+ ES256 backend. The store requires a trusted
local POSIX filesystem. This discussion-draft implementation is not
production-ready.

## Run the local example

From the repository root, using an existing Node.js 22+ installation:

```bash
VATE_NODE="$(command -v node)"
VATE_NODE_SHA="$(shasum -a 256 "$VATE_NODE" | awk '{print $1}')"
python3 reference/authority-updates/run_example.py \
  --node "$VATE_NODE" --node-sha256 "$VATE_NODE_SHA" \
  --output /tmp/vate-authority-updates-example
```

Use a new output directory for each run. Selecting an installed binary by its
current hash is sufficient for this local example; deployment must establish
the approved binary independently.

The example admits a signed instruction under revision 1, applies a revocation
at revision 2, and reopens both local stores. It rejects revision 1 and prevents
the revoked instruction from reaching the callback. Revision 3 restores the
grant, allowing one recording callback within the original receipt's lifetime.
It performs no purchase or network request.

`RUN.json` records observations, source hashes and artifact digests. The output
includes the original receipt, dispatch checkpoint, final state and illustrative
snapshot claims. Private keys and the caller token are not exported. Temporary
stores are removed when the example ends; an application must retain its own
stores and their independently held anchors.

```bash
python3 -m unittest discover -s reference/authority-updates -p 'test_*.py'
```

HTTPS tests use a disposable loopback server and a temporary certificate created
with an existing OpenSSL executable. `VATE_TRIAL_OPENSSL` can select that
executable. They make no connection to a real authority service.

## Connect an authority feed

The application selects the authority's public key, issuer, audience, scope,
epoch, minimum revision and maximum snapshot age. The feed cannot choose its
own trusted key. Construct `SnapshotVerifier` with that `AuthoritySelection`,
then create an `AuthorityStore` as `source` and retain its anchor independently.
After a process restart, reopen the store with that anchor and the same directory, database
and lock-file identities. The [storage contract](CONTRACT.md#store-lock-and-managed-entry)
defines the conditions for host restarts and the stop-on-mismatch behavior.

Call `source.refresh(HttpsSnapshotSource(selected_url))` to fetch and apply a
complete signed snapshot. The HTTPS helper verifies the server certificate and
hostname and refuses redirects. `source.accept(snapshot_bytes)` supports another
application-owned delivery path; it still requires the selected signature and
snapshot checks.

Construct `ManagedAuthorityVerifier` with that store, the existing durable
dispatch store, local policy and callback. Use its `admit`, `restore_admission`
and `dispatch` methods for the managed path. [run_example.py](run_example.py)
shows the wiring, and the [contract](CONTRACT.md) defines the wire format and
failure behavior.

A successful update becomes visible to subsequent managed operations. An
update attempted while a callback holds the policy lease returns busy and must
be retried; it has not applied the revocation. A completed update cannot cancel
an already accepted remote effect. The application controls refresh frequency
and must handle failures. A failed refresh blocks new leases when that failure
can be recorded; a busy or inaccessible store cannot acknowledge that block.
Cached information expires under the selected age and expiry limits.

## Bound each HTTPS attempt

Use `SupervisedHttpsSnapshotSource` when DNS, TLS or response reads must run in
a disposable process. The parent enforces an attempt deadline, limits returned
bytes and checks that the worker has exited before returning data. Connect it to
the same authority store:

```python
from supervised_https import SupervisedHttpsSnapshotSource

fetch = SupervisedHttpsSnapshotSource(
    selected_url,
    ca_file=selected_ca_file,
    timeout_seconds=5,
)
try:
    installed = source.refresh(fetch)
except BaseException as failure:
    try:
        if fetch.cleanup_required:
            fetch.cleanup_pending()
    except BaseException as cleanup_failure:
        raise failure from cleanup_failure
    raise
```

Use `ca_file=None` for the worker's default CA locations. An explicit PEM or DER
bundle is captured when `fetch` is constructed, so replacing the file does not
change that instance's trust. The helper requires POSIX and uses the running
application's trusted Python installation. Its worker does not inherit proxy, CA-path,
TLS key-log or Python-path environment settings.
Parent-side configuration validation also ignores environmental CA paths and
TLS key-log settings.

The deadline covers worker startup and retrieval, with up to three additional
seconds to reap a stopped worker. OS scheduling and process creation can add
delay; signature verification and store access have their own boundaries.
After validating its private request, the worker starts its own timer with the
configured timeout, before TLS setup and retrieval. That timer can end a stalled
fetch even if the application exits abruptly. It does not cover worker startup
or reap an orphan; deployment process supervision remains necessary.
Through `source.refresh`, ordinary transport and installation errors are reported
as `AUTHORITY_REFRESH_FAILED`. Interruptions such as `KeyboardInterrupt` and
`SystemExit` propagate after an attempt to record the store as unavailable.
After any failure or interruption, check `fetch.cleanup_required`. When true,
preserve `fetch`, investigate the unfinished attempt and call
`fetch.cleanup_pending()`. Startup may still be pending before a PID is available;
`pending_worker_pid` is diagnostic and can be `None` even when cleanup is required.
The cleanup method returns normally once the owner and worker have finished,
or startup has been cancelled before acquisition could begin.
On failure the method raises and retains ownership.
The `fetch` instance refuses another attempt until cleanup succeeds. Cleanup
does not make the failed refresh successful, so the example propagates that
failure even after cleanup. After forking, construct a new fetch instance;
an inherited one cannot manage the parent's worker.

A recorded refresh failure survives reopening the store;
an authenticated current-or-new snapshot can restore availability subject to
the existing conflict rules. Restoring availability does not restore a grant
that the new snapshot revokes.

Serialize complete `source.refresh(fetch)` calls and choose the retry schedule
in the application. The helper performs one attempt per call. A successful
fetch alone has not installed a snapshot, and a failed refresh against a busy
or inaccessible store cannot acknowledge that permissions have been blocked.
Another interruption during failure recording can also prevent that acknowledgement.
See the [supervision contract](CONTRACT.md#supervised-https-acquisition) for
the bounds and failure behavior.

## Coordinate refresh, retry and shutdown

Use `RefreshingAuthorityVerifier` to route one application's managed calls
through a shared refresh schedule. Pass the existing `ManagedAuthorityVerifier`
as `managed` and give the coordinator exclusive use of its supervised `fetch`:

```python
from refresh_lifecycle import RefreshingAuthorityVerifier

session = RefreshingAuthorityVerifier(
    verifier=managed,
    fetch=fetch,
    refresh_interval_seconds=5,
    retry_interval_seconds=2,
)
session.poll()
```

Use `session.admit`, `session.restore_admission` and `session.dispatch` with the
same arguments as the managed verifier. Each checks whether refresh is due
before proceeding. The first call requires a successfully installed snapshot,
even when the reopened store contains an unexpired snapshot. Complete refreshes
and managed calls are serialized within this instance; competing calls raise
`snapshot.AuthorityError` with `cause == "AUTHORITY_REFRESH_BUSY"`.

The application calls `poll()` from its scheduler while no requests arrive.
It returns installation metadata when it refreshes, `None` before the next
attempt is due, and raises on failure. Coordinator errors use
`snapshot.AuthorityError`; its `cause` attribute carries the error code.
Errors from managed verification retain their existing exception types.
`status().next_attempt_in_seconds` provides the delay for that scheduler.
The selected intervals start after each attempt ends. Choose them with the
snapshot age, expiry and expected delivery
latency in mind; the store still rejects expired or stale permissions.

A failed refresh blocks this session's managed calls until a later scheduled
attempt installs a valid snapshot. This local block also applies when the
store is busy and cannot persist its unavailable flag. Managed calls during the retry
interval raise `AuthorityError` with code `AUTHORITY_REFRESH_RETRY_WAIT`;
pending worker cleanup must succeed before another fetch. `status()` reports
local scheduling state and the last revision installed by this session,
including an installation followed by a stop request or scheduling error. It
does not report a permission decision or confirm that other callers are blocked.

Source or configuration checks that fail before a refresh attempt reject that
call without changing local readiness or the retry schedule. After those checks
recover, calls resume under the existing refresh deadline and permission checks.

Request shutdown, then confirm it:

```python
session.request_stop()
session.close()
```

`request_stop()` prevents further handoffs to managed verification. The handoff
is accepted at a final stop check after source and configuration checks; that
decision and stop requests are serialized. A call accepted first may still start
managed verification and complete its callback after `request_stop()` returns.
If stop is requested during acquisition, acquisition may finish, but that call
cannot be accepted for managed verification. `close()` returns
successfully only when no call holds the session and pending fetch cleanup has
succeeded. If it raises a busy or cleanup error, shutdown remains unconfirmed;
retain the session and retry `close()`. Interruptions such as `KeyboardInterrupt`
propagate and request this same stop. The application must also arrange process
supervision for abrupt
termination; requesting stop cannot cancel an accepted remote effect.

After a process restart, reopen both stores with their retained anchors and
construct a new fetch and session. The new session requires a refresh before
using retained admissions. Revision, clock and dispatch-attempt history remain
in their original stores; refreshing does not extend a receipt's lifetime or
authorize repeating an attempted dispatch. `dispatch_status()` remains available
without refreshing, including after `close()`, to inspect that history.

This coordinator starts no background updater and serializes only calls routed
through it. The [lifecycle contract](CONTRACT.md#cooperative-refresh-lifecycle)
defines its timing, stop and recovery rules. The focused tests include a real
loopback HTTPS feed and fresh Python processes reopening both stores:

```bash
python3 -B -m unittest discover -s reference/authority-updates -p 'test_refresh_lifecycle.py' -v
```

The recovery tests also terminate local processes during retrieval, before and
after snapshot installation, and around dispatch handoff, attempt recording and
callback completion. They reopen the same anchored stores and check that a new
refresh is required, installed revocation and revision/clock history remain in
force, receipts are unchanged, and consumed attempts cannot execute again.
An attempt recorded before termination remains consumed even if its callback
never ran; an uncertain external outcome is not permission to retry.

```bash
python3 -B -m unittest discover -s reference/authority-updates -p 'test_lifecycle_recovery.py' -v
```

These are process-exit checks on one host, with synthetic signed snapshots and
loopback HTTPS. They do not test host reboot, storage loss or migration, or
independent recovery of an external effect.

## Remaining integration work

The [selected Hydra/OpenFGA issuer](../authority-issuer/README.md) translates one
fixed authentication/authorization mapping into these grants and exercises
native local revocation through dispatch. An optional
[macOS Keychain signer](../authority-keychain/README.md) preserves one selected
signing key across publisher process restarts. Broader IAM mappings and
deployment-specific key custody remain application responsibilities. The
snapshot format is specific to this purchase profile. Selecting and rotating the authority's
root key, migrating stored admissions across source changes, and arranging
deployment-wide scheduling and recovery require separate application policies.

Actor and runtime keys can change through higher complete snapshots. Independent
stores do not share a global revision or replay fence. Caller/runtime network peer identity,
remote operation cancellation and independently verified effects remain separate
boundaries. The TypeScript receiver assesses existing receipt bindings; it does
not implement this Python policy intake or dispatch adapter.
