# Optional macOS authority signer contract

Profile: `vate-macos-keychain-authority-signer-v1`.
Local bridge contract: `vate-keychain-es256-v1`.
These identifiers describe an optional implementation interface, not a new
conformance artifact family or a change to the authority snapshot profile.

## Selection and trust

The host MUST independently select the helper executable and its SHA-256,
Keychain file, application tag and `AuthoritySelection`. It MUST protect the
helper, configuration, issuing account, Keychain access policy and publisher
ledger. A digest check is not a defense against a compromised host or a party
able to alter executable files between checking and execution.

The wrapper resolves absolute helper/Keychain paths at construction and checks
regular-file ownership by the current account. The helper MUST be executable
and neither file may be writable by another account. The Keychain file MUST
have no group/other permission bits. The wrapper rechecks these requirements
and the helper digest before and after each signature request. At either check,
a missing file, a helper-digest mismatch or failure of any listed file
requirement MUST prevent the callback from returning a token. These checks do
not pin the Keychain's contents or filesystem identity across the signing
operation.

The native helper MUST search only the explicitly selected file-based Keychain,
not the user's default search list. The Keychain MUST be unlocked. Exactly one
private P-256 key must match the tag. The key MUST report signing capability,
256-bit size and `kSecAttrIsExtractable == false`. Its public SPKI MUST equal
the configured authority public key before any signature operation.

The non-extractable attribute is an OS key property. This profile does not
assert Secure Enclave storage, resistance to a compromised issuing account,
hardware attestation, independent caller authorization or complete PKI.
The helper exposes a local signing capability to its authorized host account.
Other callers MUST be isolated by the host's account and execution controls.

## Provisioning and runtime operations

`provision PATH TAG` is an explicit administrative operation. It MUST refuse
an existing matching private-key tag and MUST NOT replace, remove or relabel
an existing key. It generates the key in the selected Keychain, requests
non-extractability at the top-level generation attributes and verifies the
stored result. Provisioning must be serialized by the administrator. If a
failed or concurrent operation leaves an ambiguous tag, subsequent operations
MUST reject it; the helper provides no automatic cleanup or replacement.

`public-key PATH TAG` exposes only the public SPKI and checked extractability
attribute. `sign` receives one bounded JSON request through stdin. None of
these commands accepts a password, unlocks a Keychain, modifies ACLs, changes
the default/search list, exports a private key or performs network access.
UI interaction is disabled for the helper process. Runtime key lookup or
signing failure MUST NOT invoke provisioning or retry with another key.

The Python callback accepts only the exact ES256 authority-snapshot header and
claims field set, with the selected issuer, audience, scope, epoch and `kid`.
The callback encodes the header and payload using the existing snapshot JSON
encoding. The complete token MUST fit the existing 64 KiB limit.

The bridge request contains exactly `contract`, `keychain_path`,
`application_tag`, `expected_public_key_spki_base64` and `signing_input_base64`.
Its total size MUST NOT exceed 128 KiB. The helper verifies the selected key,
signs the original `header.payload` bytes using ECDSA/SHA-256 and uses
CryptoKit's DER-to-raw conversion for the 64-byte JOSE signature. It verifies
that signature against the selected public key before returning it.

The bridge result contains exactly `contract`, `request_sha256` and
`signature_base64`. The wrapper checks the exact request digest, canonical
base64 and signature length. Stdout is bounded to 2048 bytes and elapsed
subprocess time to a configured value in `(0, 10]` seconds. It inherits no
loader/preload environment settings, invokes no shell, discards stderr, and
terminates/reaps a timed-out helper. Errors use stable causes and MUST NOT
include request contents, credentials, private keys or OS diagnostics.

The callback's output is not an admission decision. `AuthorityIssuer.publish`
MUST still pass it through the configured `AuthorityStore.accept`, including
independent signature, exact payload, authority context, freshness and revision
checks. A wrong signature or stale result MUST NOT become a published update.

## Restart and failure handling

The host MUST reopen the existing anchored issuer ledger with the same
selection after a process restart. It MUST NOT create a ledger automatically
after an open, read, verification or key lookup failure. The signing key and
the ledger MUST both be retained. The existing ledger contract determines
revision, clock rollback, filesystem-identity and conflicting-update handling.

The issuer marks its ledger unavailable before polling sources and signing.
Failure emits no new snapshot and does not advance its accepted revision.
The unavailable state survives a process restart. After host-authorized
recovery, a new publication MUST poll sources again and advance from the
retained revision. It MUST NOT republish an old permit from a cache.

A local publication failure does not itself notify a remote recipient. The
application MUST connect publication/delivery failures to its update refresh
and freshness controls. A recipient that has not received a revocation remains
bounded by its last accepted snapshot's validity and selected maximum age.

This backend supports the existing single-publisher registration contract.
Host reboot/unlock automation, key or epoch rotation, portable ledger recovery,
Keychain backup/restoration and distributed publishing are outside this
profile. The file-based Keychain APIs are platform-specific and partly
deprecated; their availability, code-signing identity and ACL behavior must be
checked in the chosen deployment environment.
