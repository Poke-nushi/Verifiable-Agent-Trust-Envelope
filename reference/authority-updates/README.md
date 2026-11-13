# Receive signed authority updates

Connect an application's signed permission feed to the ordinary Python purchase
verifier. Each complete snapshot supplies runtime trust and principal-to-actor
delegation grants. The integration authenticates the selected source, retains
its revision across restarts, and reevaluates current permissions before the
dispatch callback.

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
On restart, reopen the store with that anchor.

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

## Remaining integration work

The [selected Hydra/OpenFGA issuer](../authority-issuer/README.md) translates one
fixed authentication/authorization mapping into these grants and exercises
native local revocation through dispatch. Broader IAM mappings and durable
signing-key operation remain application responsibilities. The snapshot format
is specific to this purchase profile. Selecting and rotating the authority's
root key, migrating stored admissions across source changes, and arranging
reliable update delivery require separate application policies.

Actor and runtime keys can change through higher complete snapshots. Independent
stores do not share a global revision or replay fence. Caller/runtime network peer identity,
remote operation cancellation and independently verified effects remain separate
boundaries. The TypeScript receiver assesses existing receipt bindings; it does
not implement this Python policy intake or dispatch adapter.
