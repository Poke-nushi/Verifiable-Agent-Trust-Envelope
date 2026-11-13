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
Through `source.refresh`, ordinary transport and installation errors are reported
as `AUTHORITY_REFRESH_FAILED`. Interruptions such as `KeyboardInterrupt` and
`SystemExit` propagate after an attempt to record the store as unavailable.
After any failure or interruption, check `fetch.cleanup_required`. When true,
preserve `fetch`, investigate the unfinished attempt and call
`fetch.cleanup_pending()`. Startup may still be pending before a PID is available;
`pending_worker_pid` is diagnostic and can be `None` even when cleanup is required.
The cleanup method returns normally once the owner and worker have finished,
or startup has been cancelled before acquisition could begin. In that latter
case, a thread that starts later exits without creating a worker.
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

## Remaining integration work

The [selected Hydra/OpenFGA issuer](../authority-issuer/README.md) translates one
fixed authentication/authorization mapping into these grants and exercises
native local revocation through dispatch. An optional
[macOS Keychain signer](../authority-keychain/README.md) preserves one selected
signing key across publisher process restarts. Broader IAM mappings and
deployment-specific key custody remain application responsibilities. The
snapshot format is specific to this purchase profile. Selecting and rotating the authority's
root key, migrating stored admissions across source changes, and arranging
update scheduling and recovery require separate application policies.

Actor and runtime keys can change through higher complete snapshots. Independent
stores do not share a global revision or replay fence. Caller/runtime network peer identity,
remote operation cancellation and independently verified effects remain separate
boundaries. The TypeScript receiver assesses existing receipt bindings; it does
not implement this Python policy intake or dispatch adapter.
