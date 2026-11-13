# Durable admission and dispatch state

This optional Python contract preserves admission replay decisions and consumed
callback attempts across interpreter restarts and cooperating processes on one
host. It extends [dispatch-time revalidation](DISPATCH.md) with a local SQLite
store. All participating verifiers MUST select the same store, verifier ID and
operation scope. The default entry without `state_store` remains process-local.

## Configure and reopen

The application MUST explicitly initialize a new store before its first use:

```python
state = binding.durable_state_module()
store = state.DurableStateStore.create(
    state_directory,
    scope="purchases-for-this-application",
    verifier_id="urn:example:verifier",
)
expected_anchor = store.anchor
```

The directory MUST not already exist. Its parent MUST exist on a trusted local
filesystem. Creation uses private directory/file permissions. The application
MUST retain `expected_anchor` independently in its trusted configuration before
admitting work. It is canonical JSON bytes identifying the store, scope,
verifier, directory and database device/inode pairs. It is an identity anchor,
not a signature or secret. Reading an anchor from an arbitrary received bundle
does not establish trust in that store.

Every later startup MUST reopen that existing store with the retained anchor:

```python
store = state.DurableStateStore(
    state_directory,
    expected_anchor=expected_anchor,
)
boundary = binding.DispatchBoundary(execute=execute_operation)
verifier = binding.core.VateVerifier(
    verifier_id="urn:example:verifier",
    policy=local_policy,
    runtime_evidence_verifier=adapter.as_runtime_verifier(),
    dispatch_boundary=boundary,
    state_store=store,
)
```

Missing, replaced, corrupt, incompatible or busy state MUST stop the affected
call. Reopening uses SQLite `mode=rw`; it never creates a missing database.
Applications MUST NOT handle these errors by creating a fresh store, changing
the scope or removing replay rows. Initialization failure can leave a partial
directory and requires operator investigation. Automatic migration, backup
restore and pruning are not supplied by this contract.

## Admission and restore

Normal `admit` retains the exact eight `BoundAdmission` values, configuration
identity and request/operation IDs in one write transaction. Denials and
new-permit candidates retain admission replay state too. A duplicate
`request_id` is rejected. An already consumed `transaction_id` is rejected even
if the caller selects a different request ID. Here the admission request's
`transaction_id` is the purchase operation's stable `operation_id`.

Two requests for one operation can be admitted before either dispatches. They
compete for the same operation-level attempt. The first committed claim
prevents either request from entering another callback. Identifier comparisons
are exact strings; the application MUST keep the same ID for the same logical
operation. Changing the operation ID creates a different operation under this
contract and does not establish a safe business retry.

After reopening, use the selected trusted store to restore a pending admission:

```python
with boundary.update():
    admitted = verifier.restore_admission(request_id)
result = verifier.dispatch(admitted)
```

`restore_admission` accepts only an ID, reads the stored raw artifacts,
recomputes binding and registers the returned object with this verifier. It
does not accept a received receipt or a serialized `BoundAdmission` as dispatch
authority. Only an executable, unconsumed admission can be restored. Restore
does not authenticate runtime evidence or renew validity: `dispatch` still
checks current evidence, trust information and time before callback entry.

The stored configuration pins the exact policy content, verifier ID,
fail-closed setting, scope, runtime adapter descriptor (method, media type,
freshness bound and protocol hint), and loaded core/binding/store source
digests. Restore rejects a mismatch, including an implementation upgrade.
Changed files under an already loaded implementation are rejected too.
Status inspection remains possible without a configured runtime adapter.

The loaded-source identity is set only when the executing module code matches
a compilation of the same source bytes. A stale timestamp-valid Python cache
therefore cannot claim the current source identity. The actual verifier class's
defining core path and verified digest MUST also match the core used by binding;
a previously loaded verifier cannot silently use a newer helper's identity.
Custom verifier subclasses cannot inherit this implementation identity.
Durable admission and
restore require a Python implementation exposing the module frame/code check;
they fail closed when that identity cannot be established. This is a check
against accidental source/cache mismatch, not isolation from code able to
modify the running interpreter.

Python callback/provider implementations and external issuer configuration are
application-owned. Their semantics are not identified by the adapter descriptor
or by these three source digests. On restart and across processes, the operator
MUST preserve the scope's callback destination and authority policy. Current
trust snapshots can refresh; each dispatch must use the current authenticated
source. Code/configuration migration needs an explicit process that preserves
all replay fences; changing identity or discarding state is not a migration.

## Durable claim before callback

The store uses SQLite `BEGIN IMMEDIATE` to serialize writers. Admission
creation and the operation claim each commit atomically. The claim stores the
owner request, raw pre-dispatch checkpoint and its digest before callback
entry. SQLite is configured for rollback-journal `DELETE` mode and
`synchronous=EXTRA`. Every operation opens, validates and closes a connection;
connections are not shared between threads or inherited for worker use.

Clock samples used by the initial check, completed-authentication check and
claim are read after acquiring the database write lock. Their UTC high-water
mark persists in the same transaction, so a subsequent lower observation,
including after restart, is rejected. The final check after claim commit also
counts commit latency against the deadline. This last sample is guarded by
the process-local boundary. This is not an independent trusted-time source.

The claim is never released automatically. A process exit before callback
entry can therefore consume an operation without executing it. A process exit
during or after the callback can leave its outcome unknown. This favors
preventing duplicate callbacks over automatic recovery of unfinished work.
It does not provide exactly-once external effects.

The shared store orders operation claims; it does not deliver revocations or
serialize trust updates across processes. Each process still needs the
dispatch contract's update guard and a current authenticated provider. SQLite
locking does not make local checks atomic with a remote operation's acceptance.

## Read status and reconcile

```python
status = verifier.dispatch_status(request_id)
status_json_bytes = status.record
checkpoint_bytes_or_none = status.checkpoint
```

The immutable snapshot follows
[`durable-dispatch-status.schema.json`](schemas/durable-dispatch-status.schema.json).
It contains the store-anchor digest, scope, request/operation IDs, attempt owner
and raw digest references to the admission request, receipt and checkpoint.

| State | Meaning |
| --- | --- |
| `ready` | An executable admission is retained and no operation claim is present. Current authorization and validity still need dispatch checks. |
| `not_executable` | Admission was denied or requires a new permit. |
| `attempt_consumed` | The claim committed; callback entry and outcome have not been recorded. It may still be running or may have stopped. |
| `callback_returned` | The synchronous callback returned an allowed value and that state was saved. It does not establish external acceptance or success. |
| `outcome_unknown` | The durable claim remains, but the post-claim path did not produce a confirmed local return record. This can include expiry before callback entry. |
| `operation_already_attempted` | Another admitted request owns this operation's claim. The checkpoint belongs to that `attempt_request_id`, while the request/receipt references describe the requested row. |

A snapshot is not permission to dispatch and cannot reserve an operation.
Even a `ready` result can become consumed before the next call. None of these
states is an independently observed effect or a post-execution receipt.

Ordinary pre-claim errors raise binding `Invalid` and do not invoke the
callback. A claim/storage error can have an uncertain commit outcome; it also
raises `Invalid`, consumes that object's local retry eligibility and MUST
lead to status inspection through a fresh store read. A persisted `ready`
admission may be explicitly restored and undergo all checks again. An
uncertain admission write must likewise be inspected before re-admission:

- Reopen the same store with the independently retained anchor and call
  `dispatch_status(request_id)`.
- If reading succeeds and returns `ready`, use explicit restore, not another
  `admit`. A non-executable or consumed state does not authorize dispatch.
- `Invalid` with `cause=STATE_ADMISSION_NOT_FOUND` means that this request row
  was absent from a successfully validated store. Only in this branch after
  an uncertain admission write may the application explicitly repeat normal
  `admit` with the original request and stable operation ID. All current
  authentication, policy, replay and operation checks still apply.
- An unavailable, missing, corrupt or replaced database is not an absent
  request row. Other storage errors require investigation and MUST NOT be
  treated as permission to re-admit or initialize an empty store.

After a confirmed claim, an ordinary exception (including post-commit expiry,
callback errors or failure to record return) raises `DispatchAttemptError`
with the checkpoint. `BaseException` interruptions propagate. A return-state
commit error may still leave `callback_returned` on disk; an error must not be
used as evidence of no callback or no effect. All consumed states require
application/provider reconciliation, not a new admission or store reset.
The API has no reset/release method.

## Trust and operational limits

The directory, its ancestors, database, sidecars and retained anchor MUST be
protected from untrusted modification. The store checks file identities,
schema, database identity and artifact digests. It rejects symlink database
and sidecar files. These are local integrity checks, not authenticated storage
against an administrator who can rewrite the database and its digests or
roll back the database in place. A copied database on another host is outside
the anchor contract. Replicated/network filesystems and host failover are not
supported. Hardware and filesystem guarantees are outside the local tests.

Raw requests, receipts and runtime evidence remain in the database. Operators
must protect and retain them as sensitive application state; encryption at
rest and a safe archival policy are not supplied here. Claim rows MUST NOT be
deleted merely because receipts expire. The reference store is unbounded and
uses an integrity check per connection; it has no measured throughput claim.

The optional [caller authority adapter](../caller-authority/CONTRACT.md) adds
actor-signed instructions and principal-to-actor authorization. Caller tokens
are supplied again at dispatch and are not stored. Its configuration is pinned
per admission, with current grants rechecked after restore.

This remains a reference integration, not production approval. Transport caller
possession, authenticated trust delivery, provider
idempotency, external acceptance deadlines and independent effect observation
remain separate responsibilities. TypeScript's receiver binding assessment
does not implement this Python state store or gain execution authority from it.

The local regression suite exercises concurrent spawned interpreters,
process exits after claim/during callback/after return, lost commit
acknowledgements, unavailable state, clock rollback rejection and expired work after
lock or commit delay. The JWT integration checks real ES256 authentication
after reopening. These tests use local callbacks and no external operation.

SQLite behavior references: [transactions](https://www.sqlite.org/lang_transaction.html),
[`synchronous`](https://www.sqlite.org/pragma.html#pragma_synchronous), and
[Python SQLite URI mode](https://docs.python.org/3.10/library/sqlite3.html#how-to-work-with-sqlite-uris).
