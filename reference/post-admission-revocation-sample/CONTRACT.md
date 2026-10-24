# Decision and evidence contract

This sample implements `local-runtime-revocation-demo-v1` for one runtime key,
one status authority, one local provider, and one `demo.create_file_set`
operation. It preserves the earlier VATE admission while recording a later
provider decision and the operation's observed effects.

## Inputs and signatures

The recipient selects the authority public key, runtime public key, issuer,
runtime, provider, operation, original admission, and status epoch in
`selection.json`. The original admission is recomputed using the bundled VATE
demo modules. It is unsigned; it is not authenticated by the later signatures.

For the eight synthetic runs, the fixture constructs this selection from its
disposable public keys and fixed operation; no manual selection file is needed.
When checking evidence from someone else, the recipient must independently
select the expected keys and context rather than adopting the received export's
own selection as authoritative.

The authority signs key status. The runtime signs a separate proof that binds
the receiver/provider, operation, input bytes, original admission, attempt ID,
nonce, and validity window. Both signatures use the sample's constrained ES256
JWS format. `kid` is an alias, not the source of key authority. This is not
general-purpose JOSE or certificate-chain validation.

`raw_sha256` identifies the original bytes. `signing_input_sha256` identifies the
signed header/payload independent of ECDSA signature variation. Authenticated
different statements at the same status version create a conflict, even if an
authenticated statement is expired. Signing the same input again does not.
Malformed encodings, invalid signatures, unauthorized keys, and different
subjects do not create a status conflict for the selected subject.

## Ordering and provider acceptance

Every submit freshly reads the configured local authority file. Notifications
do not replace that required read. A previous attempt's successful read cannot
be reused. A restart invalidates attempts created by the earlier provider
instance.

Cryptographic verification occurs before acquiring the acceptance-decision
database write lock.
After verification and lock acquisition, `checked_at` is used to check the
admission, attempt, runtime proof, and status time bounds. Time spent verifying
or waiting for the lock cannot preserve an earlier freshness decision.
Freshness at `checked_at` does not establish freshness at commit completion or
at the later filesystem effect.

Admission is current only within the intersection of the permit's and original
admission receipt's validity periods: at or after both `issued_at` values and
strictly before both `expires_at` values. Original timestamps retain their
microsecond precision when compared with the integer-second `checked_at`.
The refusal reason `admission_expired` covers either side of this interval,
including a check before the original allow was issued. It does not reissue or
rewrite that earlier allow.

Status updates and acceptance use the same SQLite store. If a revocation commits
before acceptance, the provider prevents new acceptance. If acceptance commits
first, a later revocation does not undo it. Database acceptance and the two file
writes are separate operations.

The database prevents repeated acceptance of the selected operation and nonce.
An accepted operation without a confirmed complete result remains `unknown`;
the recovery path queries saved state and never repeats its effects. Partial
effects remain on disk and remain `unknown`.

If commit fails, the writer rolls back/closes its transaction and releases the
worker lock. Query uses a new database connection and snapshot and checks that
the worker has stopped. Missing, corrupt, or replaced databases are not silently
recreated as active stores.

## Unavailable verification and recovery

Failure to run the signature tool, including a timeout, produces `unknown`
rather than a false signature-invalid decision. The attempt is consumed. The
record keeps authenticated status inputs and the local observation that
verification was unavailable. Query/export can inspect those records after the
tool is available again.

The separate reader checks the bindings between that observation and the
original inputs. It does not prove that the tool was unavailable at the earlier
time, and does not recognize an unverified original as a valid signature.

`query`/`export` validate the exact anchor fields, types, and selected-input hash
before opening the database. Unavailable local state produces JSON with
`accepted: null`, `files: null`, `retry_effect: false`, and exit code 2, rather
than creating a replacement store. `export` can successfully export a recorded
unknown outcome; export success does not imply operation success.

## Export and separate reader

`anchor.json` contains the selected-input hash, store ID, and database device and
inode. Retain it independently of a received export. This prevents accidental
substitution of a different live store with the same selected inputs. The sample
uses bounded JSON integers; filesystems whose device/inode values exceed the
sample's supported integer range have not been validated.

The reader checks signatures, original bytes, selected inputs, event ordering,
acceptance/refusal reasons, and the consistency of observed results. It checks
the export against the independently supplied selection and anchor. It does not
reopen the database or independently observe the provider's filesystem.

`effect_observed` requires acceptance, a matching native result, and both expected
files. `not_accepted` requires no acceptance/native result, no observed files,
and a local observation after the old worker is excluded. Otherwise the result
is `unknown`. Rejected requests may still reach the provider's handler;
rejection does not mean there were zero handler calls.

## Limits of the result

Clock readings, fetch/tool availability, and file observations are local provider
assertions. This sample does not establish independent timestamps, completeness
of a malicious provider's history, or protection against OS compromise and
database rollback. It does not guarantee immediate stopping before a remote
revocation has reached this store, cancellation after acceptance, or exactly one
successful completion.

The demonstrated path ends at the provider database and evidence export. A
networked authority, external provider, and receipt-inbox integration are not
included. The sample does not change the VATE semantic profile, common schemas,
or digest basis. Test results describe the stated local cases and environments,
not production approval or general compatibility.
