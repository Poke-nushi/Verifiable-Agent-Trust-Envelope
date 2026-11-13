# Keep authority signing keys across publisher restarts

This optional macOS signer connects a persistent Keychain key to the
[authority issuer](../authority-issuer/README.md). A publisher can reopen its
existing revision ledger and sign the next snapshot with the same selected
key. A locked, missing, ambiguous or different key stops publication.

The Python callback invokes a pinned local Swift helper. Apple's Security
framework performs P-256 signing; CryptoKit converts the signature to the
ES256 representation. The private key stays behind the Keychain API. The
helper checks the stored key's non-extractable attribute and the independently
selected public key before signing. The existing authority verifier then
checks the complete signed snapshot before the issuer returns it.

This is a macOS integration and review aid. It uses the **file-based Keychain**,
including deprecated APIs for explicit Keychain selection and provisioning.
Apple recommends the data-protection Keychain for supported application
contexts; see [TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).
This backend is optional: applications can supply another Keychain, KMS or HSM
signing callback without changing VATE's snapshot format. This implementation
does not establish hardware-backed custody or production readiness.

## Prepare an issuing host

Use an existing macOS Swift compiler with Security and CryptoKit, and the
existing Node.js 22+ verifier backend. No package installation is required.

1. Provision a dedicated file-based Keychain through the host's administration
   process. Keep its file owned by the issuing account with mode `0600`, and
   unlock it through that process. The signer does not accept a password or
   unlock a Keychain.
2. Build the helper into its final, issuing-account-owned executable location.
   Protect it from other users' writes and record its SHA-256 independently.
   Keychain access also depends on the helper's code identity and ACL; a new
   build may require deliberate host-side access provisioning.
3. Explicitly provision one key, then select the returned public SPKI in the
   issuer and recipient configurations. Never select an authority public key
   from an incoming snapshot.

From the repository root, replacing the paths with the selected local paths:

```sh
/usr/bin/swiftc reference/authority-keychain/keychain_bridge.swift \
  -o /absolute/path/vate-keychain-bridge
```

```sh
/absolute/path/vate-keychain-bridge provision \
  /absolute/path/authority.keychain-db vate.authority.selected
```

`provision` prints a JSON object containing the public SPKI in base64 and
`private_key_extractable: false`. It refuses an existing matching tag. Use the
same helper's `public-key` command with the same path and tag to inspect that
public configuration later. Neither command exports a private key. Runtime
signing only invokes `sign`; it cannot create a replacement key.

## Connect the callback

Make this directory and the existing reference modules available on the
application's Python import path. `selection` below is the same independently
configured `AuthoritySelection` used by the publisher's `SnapshotVerifier`.

```python
from keychain_signer import KeychainSigner, PROFILE

signer = KeychainSigner(
    expected_profile=PROFILE,
    helper="/absolute/path/vate-keychain-bridge",
    helper_sha256="INDEPENDENTLY_SELECTED_BINARY_SHA256",
    keychain="/absolute/path/authority.keychain-db",
    application_tag="vate.authority.selected",
    selection=selection,
)
```

Pass `signer` to the existing `AuthorityIssuer` constructor. Retain the issuer's
`AuthorityStore` and its independently protected anchor across restarts.
Reopening requires the same selected authority and anchored filesystem
identities. A new process must not create a new ledger to bypass a missing,
corrupt or mismatched one. Key custody and the revision/clock ledger are
separate responsibilities; preserving only the key does not preserve history.

[`fixture_publish.py`](fixture_publish.py) contains a complete wiring example:
imports, registration, authority selection, verifier, signer and issuer, with
separate ledger creation and reopening paths. It uses simulated IAM responses
and a fixed test clock. Supply the application's own services, registration,
clock and protected anchor storage when integrating that wiring.

The issuing account, helper, host configuration and Keychain ACL are trusted.
Anyone who controls that account or can invoke its authorized signing helper
may be able to sign. This helper is a local callback backend, not an
authenticated multi-tenant signing service. Protect the account and execution
environment accordingly. See [CONTRACT.md](CONTRACT.md) for the exact boundary.

## Run the checks

```sh
python3 -B -m unittest discover -s reference/authority-keychain -p 'test_*.py' -v
```

On macOS, these tests compile the helpers and use disposable dedicated
Keychains. They exercise real signatures verified by Node, same-key reuse,
locked/missing/wrong keys, non-extractable-key enforcement, duplicate tags and
repeated provisioning. Separate publisher processes exercise a persisted
revision ledger, retained permission withdrawal, publication failure, explicit
unlock recovery and old-snapshot rejection. IAM responses in these tests are
simulated; the separate issuer example exercises real Hydra/OpenFGA.

The test-only `fixture_keychain_admin.swift` creates, locks, unlocks and deletes
only its disposable Keychain. Its random password stays in test-process memory
and is passed through stdin. Tests do not change the user's default Keychain or
install permissive access rules. On other operating systems, native tests are
skipped; wrapper failure tests still run.

Process restart is covered; host reboot, unattended unlock, Keychain migration,
key/epoch rotation, recovery after key loss and supervised delivery remain
deployment work. Replacing or recovering a key requires explicit trust
reselection, not automatic re-provisioning.
