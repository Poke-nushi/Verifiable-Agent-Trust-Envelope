# Carry service authority changes into VATE dispatch

This optional Python adapter turns a selected Hydra token-introspection result
and an OpenFGA permission decision into signed VATE authority snapshots. The
existing [authority receiver](../authority-updates/README.md) consumes those
snapshots and rechecks permission before dispatching an admitted operation.

The native example connects real local Hydra and OpenFGA processes to that
path. It exercises owner-permission withdrawal, delegation withdrawal, OAuth
token revocation, failed delivery, recovery and store reopening. The final
operation is a recording callback; login and consent are synthetic fixtures.
This is an implementation and interoperability review aid, not production
approval or a general IAM compatibility result.

The [planned migration path](../planned-migration/README.md) retains this fixed
registration while moving the signing key, installed program and stores.
Publication after the move rereads current service authority before new work.

## One selected registration

The issuing application registers one OAuth subject/client/audience, one
OpenFGA store/model/user/object, and the corresponding VATE principal, actor,
runtime, resource and action. Actor/runtime public keys and purchase constraints
come from this registration. OAuth scope does not grant purchase authority.

One OpenFGA object is dedicated to the registered principal/client/resource
binding. Its `can_execute` check intersects direct `user_permission` and
`delegation` relationships for the selected user. The adapter selects an explicit model version and
checks its shape before using that result. An inactive token or a denied check
produces an empty delegation list. An unavailable or invalid source produces
no snapshot. The purchase cap and tool list are additional registered VATE
restrictions; OpenFGA does not evaluate the purchase amount in this example.

The selected snapshot scope includes a digest of the registration and endpoints.
Changing that mapping requires explicit source reselection. Renewing an OAuth
credential through the application-owned token provider does not extend the
registered grant's lifetime. See [CONTRACT.md](CONTRACT.md) for the exact rules.

## Run the native example

Use an existing Node.js 22+ executable, an existing OpenSSL with `req -addext`,
and the pinned macOS arm64 binaries for Hydra 26.2.0 and OpenFGA 1.22.1. This
fixture checks their binary SHA-256 values in
[`native_fixture.py`](native_fixture.py); it does not download or install them.
Place those two binaries at `bin/hydra` and `bin/openfga` under the selected
native directory. Other binary versions/platforms have not been exercised by
this fixture.

From the repository root, replace the executable paths and digests below with
the independently selected local values. The output directory must be new.

```sh
python3 reference/authority-issuer/run_native.py \
  --native-root /path/to/pinned-native-directory \
  --node /path/to/node --node-sha256 NODE_BINARY_SHA256 \
  --openssl /path/to/openssl --openssl-sha256 OPENSSL_BINARY_SHA256 \
  --output /tmp/vate-authority-issuer-example
```

The run uses temporary databases and credentials, binds service ports to
loopback, and stops its child processes. A temporary TLS endpoint delivers
signed snapshots to the receiver with certificate and hostname verification.
The native service connections themselves use explicitly enabled loopback HTTP
and Hydra development mode. They are not a deployment transport example.

`RUN.json` records matched observations, binary/source digests and artifact
digests. The bundle includes signed snapshots, selected public keys, receipts,
the pre-dispatch check, service observations and redacted logs. It excludes
private signing keys, OAuth access tokens and caller proofs. The fixture signer
keeps its ephemeral private key in a child process and cannot recover that key
after the process exits.

For persistent signing-key integration, the optional
[macOS Keychain signer](../authority-keychain/README.md) supplies the same
callback interface and tests fresh publisher processes against one retained key
and revision ledger. The native Hydra/OpenFGA example above continues to use
its disposable in-memory signer. The process-recovery example below connects
the persistent signer to the same native services.

Unit tests use existing Node/OpenSSL and disposable local endpoints; they do
not need Hydra/OpenFGA binaries:

```sh
python3 -B -m unittest discover -s reference/authority-issuer -p 'test_*.py' -v
```

## Run the process-recovery example

[`run_lifecycle.py`](run_lifecycle.py) connects native Hydra/OpenFGA, a persistent
Keychain signing key, supervised HTTPS acquisition and the refresh coordinator
to durable admission and dispatch. Publisher and recipient run in separate
Python processes. Restarted processes reopen their original stores with the
retained anchors and selected authority key.

Use the same pinned binaries and executable selections as above, plus the
existing macOS Swift compiler with Security and CryptoKit. The controller
compiles the existing Keychain helpers, creates one disposable test Keychain,
and removes it after stopping its processes. It checks that the user's default
Keychain and search-list settings are unchanged at completion.

```sh
python3 -B reference/authority-issuer/run_lifecycle.py \
  --native-root /path/to/pinned-native-directory \
  --node /path/to/node --node-sha256 NODE_BINARY_SHA256 \
  --openssl /path/to/openssl --openssl-sha256 OPENSSL_BINARY_SHA256 \
  --output /tmp/vate-authority-lifecycle-example
```

The example checks permission, delegation and OAuth withdrawal; a locked
signing key; failed HTTPS delivery; Hydra stop/restart with its original
database; and fresh publisher/recipient processes. A recipient must fetch and
verify an update after restart before resuming managed calls. A consumed
attempt remains unavailable for retry, including when the recipient exits
inside its recording callback before recording completion.

`RUN.json` records matched observations, source/binary digests and artifact
digests. Saved artifacts include signed snapshots, original receipts, effective requests, dispatch
checkpoints, retained attempt statuses and recording-callback observations.
Only a completed, successful run writes `RUN.json`; partial observations from
a failed run are not a passing result. Credentials, caller proofs and private
keys stay outside the saved bundle.

This exercises process recovery on one host with the original stores, anchors
and authority key. OpenFGA and the fixture actor/runtime signers stay alive
while publisher/recipient processes restart. Host reboot, key loss/rotation,
storage migration and recovery of a real external effect require separate
operational procedures. The service connections and synthetic login/consent
retain the native fixture conditions described above.

## Integrating an issuing application

Select the registration and source credentials independently of incoming VATE
requests. Supply a token provider for that registration and a signing callback
for the selected authority key. Keep a separate, anchored `AuthorityStore` as
the publisher's revision and clock ledger. Reopen that store after restart;
do not recreate it to recover from a read or verification failure.

Every publication polls the services again. Its validity starts before those
requests, so slow service responses or signing cannot renew the observation.
The application must connect publication failures to delivery failures, call
the recipient's `refresh` operation, and enforce its selected freshness limit.
The example's TLS feed demonstrates that connection. A running recipient does
not learn about a remote revocation until an update arrives; an undelivered
update remains bounded by the last snapshot's expiry.

One publisher per registration is supported. Independent concurrent publishers,
deployment-specific signing-key custody, root-key/epoch migration, deployment-wide
delivery/recovery and independent deployment testing remain integration work. The
service reads are sequential, not an atomic transaction across Hydra and
OpenFGA. This adapter connects to the Python admission and dispatch path; the
TypeScript component checks receipt content.
