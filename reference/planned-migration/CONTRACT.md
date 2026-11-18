# Planned local key, program and storage migration

`vate-local-planned-migration-v1` is an optional implementation interface for
the managed Python purchase-cap path. It preserves admission artifacts and
consumed operation history while changing the selected authority key, installed
program and local store locations. It does not change receipt payloads, the AL2
profile, the corpus artifact line or their digest bases.

## Supported transition and custody

The source program is commit
`675847669851070728431fd1ebd1415f57ad411e`. Its selected runtime sources are
pinned in `supported-source.json`. The destination program is the independently
selected installed source tree; its complete migration runtime manifest is
captured in the plan and enforced when migrated stores are used. An unknown
source, a changed target runtime or a later arbitrary upgrade MUST be refused.
Keep the original installed source tree intact through migration and readback.

The source is a fixed main-branch commit, not the `v0.6.0` release, which has
no managed stores for this transition. Do not admit work through the destination
program against unmigrated stores: a history containing admissions from that
program is not a supported source. The destination manifest pins every file in
`MIGRATION_SOURCES`, including its selected example and signing-helper code.
Changing any of those files requires a separately defined transition; a target
store from this migration cannot be migrated again by this same interface.

The deployment MUST have one administrator, one host and trusted local storage.
All seven databases MUST reside on the same filesystem device. The administrator
MUST stop and drain the publisher and recipient applications before migration.
Execution MUST use `ManagedAuthorityVerifier` with the selected shared recipient
authority and dispatch stores. Existing authority locks are a checked barrier
against a still-running managed callback; a busy lock stops migration.
Inherited migration handles MUST NOT be used after a process fork. The child
closes inherited migration lock descriptors without releasing the parent's locks.

The administrator MUST retain the original stores, independently trusted anchors,
old root key and source program. Provision a distinct new key and key ID without
removing the old key. Select both roots independently for the same issuer,
audience, scope, epoch and maximum snapshot age. The migration MUST NOT infer
trust in the new key from a received token. Each root signs an exact, empty-grant
snapshot challenge which is verified against its selected public key. Those
challenges are key-use checks, not IAM observations or execution permissions.
Their revision is reserved for confirmation. The destination's minimum revision
MUST be strictly greater, so reinstalling a confirmation cannot conflict with a
live authority update even while the confirmation's time window remains valid.

Key loss or compromise, stale-backup recovery, host failover, network storage,
online migration, multiple sites, epoch changes and arbitrary version-to-version
conversion are outside this transition. The administrator, installed interpreter,
callbacks, files and their ancestors remain trusted. The checks do not resist an
administrator who edits the database and its integrity records or rolls back
all trusted files in place.

## Preparation

`PlannedMigration.prepare` takes the three original store handles, old source
directory and explicitly selected new authority. It MUST validate the old
anchors and source identity before allocating new files. The destination
directory MUST be new, private and separate from every source directory.

Preparation creates a migration journal and three destination directories.
Destination databases initially contain only a `prepared` marker. They MUST
NOT pass ordinary store initialization or grant authority as fresh empty stores.
Preparation does not retire or rewrite source records. The returned journal
anchor MUST be retained independently before running the move. Startup MUST
reopen this journal using that anchor; it MUST NOT infer trust from a discovered
journal or recreate a missing one.

An interrupted initial allocation may leave an incomplete directory. Preserve
it for investigation; initialization never overwrites or automatically repairs
an existing destination. No source data changes before preparation completes.

## One atomic move

`run` holds the migration lock and both original authority locks. It attaches
the three source and three destination databases to the real-file migration
journal. Every database MUST use rollback-journal `DELETE` mode and
`synchronous=EXTRA`. Every data query and database-specific PRAGMA MUST name its
schema. Missing participants, unexpected schemas, wrong identities or corrupt
records MUST fail without a reset.

Within one write transaction, the implementation MUST:

1. Validate all original identities, records and signed authority originals.
   Saved signatures are assessed at a historical valid instant for integrity;
   this check MUST NOT supply current permission.
2. Derive a confirmation revision from the final locked states. It MUST be at
   least both original configured minimums, the selected new minimum, and one
   more than the largest accepted revision. The destination minimum MUST be
   one greater than that confirmation revision. Exhaustion MUST fail before
   signing or source retirement. Migration time MUST not precede any retained
   clock high-water.
3. Add a `retired` marker to each source. All original tables, receipts, request
   preimages, runtime proofs, verification records, configuration bytes,
   checkpoints, replay decisions and operation rows MUST remain unchanged.
4. Copy those original rows into the destination files. Only the authority
   selection and explicit startup blocking flags change. Preserve the old signed
   snapshot and revision/issuance/time floors. No old snapshot may supply a
   policy lease under the new root.
5. Bind target markers to the migration ID, final target anchors and installed
   runtime manifest. Store the result and source-history digests in the journal.
6. Commit source retirement, all target records and markers, and the journal
   outcome together.

Each source-history digest is SHA-256 of the sorted-key, compact ASCII-escaped
JSON object mapping table names to rows ordered by their primary key. Blob
values use `{"bytes_hex":"<lowercase hex>"}`; other SQL values retain their
JSON types. The implementation streams that same byte sequence rather than
applying a single external artifact's 2 MiB limit to the complete history.
Admission and operation validation and retained-row comparison also process
history one row at a time. Admission configuration bytes retain the source
store's 2 MiB per-record limit; journal records retain their 1 MiB limit.
Individual artifact limits and the receipt/corpus digest bases are unchanged.

The old program's exact-schema checks reject both retired and migrated stores.
The new program rejects `retired` and `prepared` stores, and validates the
target anchor and runtime manifest before using a migrated store. Merely writing
an anchor for another path does not satisfy these conditions.

The atomicity relies on SQLite's
[attached-database transaction conditions](https://www.sqlite.org/lang_attach.html)
and [super-journal protocol](https://www.sqlite.org/atomiccommit.html#_multi_file_commit),
including their operating-system and filesystem assumptions. Process-exit tests
do not establish power-loss or host-reboot durability.

## Interruption, retry and readback

A process exit before commit leaves a recoverable uncommitted move. SQLite
restores the source stores and prepared destinations. A process exit after
commit leaves the source stores retired and the journal containing the committed
result. A lost commit acknowledgement MUST NOT be treated as a rollback.

Reopen the same journal with its original anchor and run it again. If a committed
result exists, the implementation MUST inspect that result and retained history
without copying data, signing again, resetting a clock/revision, or replacing
subsequent target attempts. If it is uncommitted, it MUST repeat validation and
use the current locked source state. An inconsistent or unavailable result
requires investigation; it MUST NOT trigger creation of empty stores.

The stop-and-drain requirement also applies to committed readback: `run` acquires
a write reservation across the seven databases. Running it alongside target
applications can make their calls fail on busy state. Readback is a maintenance
operation, not a live health check.

The committed result has a separate digest in the journal. Readback MUST check
that digest, every participant's database identity/version, current authority
originals and all dispatch record digests, including rows added after migration.
Historical signature checks do not provide a current policy lease. These checks
detect inconsistent local state; they do not authenticate an administrator's
rewriting of both data and integrity records.

Retain the journal, participants and any SQLite sidecars at their original
locations. SQLite alone performs hot-journal and super-journal recovery. The
application MUST NOT delete sidecars, move participant files during recovery,
or remove a retirement marker. There is no automatic rollback to the old
configuration after a committed move.

## Permissions and pending work after the move

The returned result establishes state migration, not operational readiness.
The new publisher MUST use the selected new key and retained ledger to observe
the same current IAM sources again. Its new snapshot MUST meet the new minimum
revision and retained issuance/time floors. The recipient MUST authenticate and
install that snapshot before granting a lease. Migration itself MUST NOT change
a revoked or absent grant into a permission. Old-key updates are rejected. An
actual later grant restoration remains a new authority decision under the
existing snapshot contract.

All old admissions remain available for historical inspection. Their
`ready` status means no attempt was recorded; it MUST NOT be displayed as
permission to execute under the new configuration. This transition changes the
installed source and authority source identity, so old admissions MUST fail
restore with the original configuration bytes preserved.

For an unattempted operation, obtain a new request ID, caller proof and runtime
evidence bound to that new request. Keep the same stable operation ID. Normal
admission and current permission checks apply again. Replacing only the request
ID and caller proof does not make the old runtime evidence valid for the new
request. A consumed, returned or outcome-unknown operation remains blocked even
with a new request ID and new proofs; it requires provider reconciliation.

Unchanged-program/configuration restart continues to use the existing
[restore conditions](../request-binding/DURABLE-STATE.md#admission-and-restore).
It is a separate path and MUST NOT be reported as a migration test.

## Failure causes

`run` normalizes lower-level failures to `MigrationError`; its `cause` identifies
the failed condition. `prepare` and construction may also propagate filesystem,
parsing and existing store exceptions (`OSError`, request-binding `Invalid`,
`AuthorityError` or `StateError`). No cause authorizes a
reset, removal of markers, or creation of replacement empty stores.

| Causes | Meaning |
| --- | --- |
| `MIGRATION_BUSY`, `MIGRATION_FORK_REOPEN_REQUIRED` | A required lock is held, or the process inherited a handle across fork. |
| `MIGRATION_CONFIGURATION_INVALID`, `MIGRATION_AUTHORITY_MISMATCH` | Selected stores, roots or authority context do not meet the transition. |
| `MIGRATION_PATH_INVALID`, `MIGRATION_FILESYSTEM_UNSUPPORTED` | Paths or filesystem placement are unsupported. |
| `MIGRATION_ANCHOR_INVALID`, `MIGRATION_FILE_IDENTITY_CHANGED`, `MIGRATION_LOCK_CHANGED`, `MIGRATION_SIDECAR_INVALID` | The retained anchor or filesystem identities/sidecars do not validate. |
| `MIGRATION_PROGRAM_CHANGED`, `MIGRATION_SOURCE_UNSUPPORTED`, `MIGRATION_ADMISSION_SOURCE_UNSUPPORTED` | The selected runtime or recorded admission source is unsupported or changed. |
| `MIGRATION_DB_MODE_INVALID`, `MIGRATION_SCHEMA_CHANGED`, `MIGRATION_IDENTITY_CHANGED` | Database mode, structure or stored identity differs. |
| `MIGRATION_JOURNAL_INVALID`, `MIGRATION_RECORD_INVALID`, `MIGRATION_MARKER_CHANGED` | Journal, canonical record or migration marker is inconsistent. |
| `MIGRATION_DATA_CORRUPT`, `MIGRATION_HISTORY_CHANGED`, `MIGRATION_RESULT_CHANGED` | Stored data, retained history or committed result fails integrity checks. |
| `MIGRATION_CLOCK_ROLLBACK`, `MIGRATION_AUTHORITY_ROLLBACK`, `MIGRATION_REVISION_EXHAUSTED` | A retained time/revision floor cannot be preserved. |
| `MIGRATION_KEY_CONFIRMATION_FAILED` | The signer's verified payload differs from the selected challenge. |
| `MIGRATION_FAILED` | A lower-level filesystem, SQLite, parsing or signature operation failed; no detailed external callback error is exposed. |

Ordinary store access after migration uses existing store error types. The
shared marker guard reports `STATE_MIGRATION_INACTIVE`,
`STATE_MIGRATION_ANCHOR_CHANGED`, `STATE_MIGRATION_INVALID`, `STATE_IDENTIFIER_INVALID` or
`STATE_IMPLEMENTATION_CHANGED`; authority stores preserve these cause strings
inside `AuthorityError`. Other existing store validation causes can also apply.

## Evidence boundary

The example uses old-program state, distinct destination files and keys, current
authorization intake and recording callbacks. It does not claim external resource
effects, independent external-SUT conformance, deployment approval or general
JOSE/PKI validation. Existing historical receipt and interoperability records
remain attached to their original source versions.
