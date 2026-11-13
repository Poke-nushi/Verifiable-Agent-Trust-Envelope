# Dispatch-time revalidation

This draft Python contract connects `VateVerifier.admit` to a synchronous
application callback through `VateVerifier.dispatch`. It applies to the
[`vate-purchase-cap-request-v1`](CONTRACT.md) entry with a configured
[`RuntimeEvidenceVerifier`](RUNTIME-EVIDENCE.md). It preserves the admission
receipt and performs a new authentication check before handing the effective
operation to the callback.

## Configuration and local issuance

The application MUST select a `DispatchBoundary` before admission and pass it
as the verifier constructor's `dispatch_boundary`:

```python
boundary = binding.DispatchBoundary(execute=execute_operation)
verifier = binding.core.VateVerifier(
    verifier_id="urn:example:verifier",
    policy=local_policy,
    runtime_evidence_verifier=adapter.as_runtime_verifier(),
    dispatch_boundary=boundary,
)
with boundary.update():
    admitted = verifier.admit(
        admission_request_bytes,
        original=original_operation_bytes,
        evidence_artifacts={runtime_evidence_uri: runtime_evidence_bytes},
    )
result = verifier.dispatch(admitted)
```

`execute_operation(effective_bytes, checkpoint_bytes)` MUST be a trusted,
synchronous callable selected by the application. It MUST use the supplied
effective operation for its submission. The callback MUST NOT substitute the
original operation, widen its constraints, defer submission to an unguarded
queue, or automatically retry a submission whose outcome is unknown. Coroutine
and generator functions are rejected; a deferred return value is rejected
after callback entry and consumes the attempt. These checks cannot detect an
arbitrary callback's hidden scheduling or side effects.

`DispatchBoundary` uses the current UTC clock by default. An application MAY
select `clock`, a callable returning a timezone-aware `datetime`, for a
controlled environment. The clock MUST be trusted and free of side effects.
`dispatch` accepts no per-call clock, replacement input, or callback.

Without a state store, only the identical `BoundAdmission` object issued by the same verifier with
that boundary is eligible. The verifier retains its immutable values and
issuance configuration in memory. A copied object, serialized receipt,
deserialized verification record, another verifier's admission, or admission
created before boundary configuration MUST NOT be dispatched. A denial or
new-permit candidate MUST NOT receive a dispatch entry. This local issuance
rule does not establish the authenticity of a receipt received elsewhere.

The optional [durable state store](DURABLE-STATE.md) adds admission replay and
operation-level attempt control across restarts and cooperating processes. Its
`restore_admission` path registers an object from the selected trusted store;
the same dispatch-time checks still apply. The steps below describe the
default in-memory mode. The durable contract specifies persistence, recovery
and error handling when `state_store` is configured.

## Checks before callback entry

The implementation MUST:

1. Check the retained issuance identity, original values and attempt state.
2. Require the same local policy content, verifier ID, fail-closed setting,
   runtime verifier object and dispatch boundary as at issuance. A changed
   local policy requires a new admission, even if it is less restrictive.
3. Recompute the receipt's binding to the original, admission and effective
   bytes and require an immediately executable final decision.
4. Read the boundary clock and require the admission receipt's inclusive
   validity window to contain that time.
5. Authenticate the retained runtime evidence bytes again using the configured
   adapter and current application trust information. The saved verification
   record MUST NOT replace this call. The adapter contract's digest, context,
   runtime, audience, issuer, validity and freshness checks still apply.
6. Read the clock after verification and construct the pre-dispatch record.
   Its `usable_until` is the earlier of the existing receipt expiry and the
   newly verified evidence's usable deadline. A trust refresh MUST NOT extend
   the old admission receipt.
7. Recheck configuration, acquire the replay-state lock and read the clock
   after record construction and any lock wait. Normalize clock values to UTC
   instants before comparison. Reject a time before receipt issuance, beyond
   the usable deadline, or below a previously observed instant on this
   boundary, including across daylight-saving transitions.
8. Mark the attempt consumed in memory, then call the configured callback
   with exactly the admitted effective bytes and the pre-dispatch record.

Authentication, clock, serialization and configuration failures before step 8
MUST leave the callback uncalled. They do not consume the dispatch attempt;
the same issued object can be retried if the checks subsequently pass within
the original validity window. Admission replay state remains consumed.
Changing the trusted adapter or boundary requires new admission; resetting
the boundary is not a way to dispatch an old object.

## Update order and concurrency

All local writers of trust snapshots, revocation information and configuration
read by dispatch MUST use this boundary's `update()` context:

```python
with boundary.update():
    current_trust_policy = refreshed_trust_policy
```

The adapter's provider MUST read the same application-controlled state.
Replacing a provider's backing snapshot under this guard is supported; the
configured runtime verifier object remains the same. Updates MUST NOT race
admission, whose existing configuration-concurrency restriction still applies.
The API example also runs `admit` inside `boundary.update()` to serialize it
with cooperating update threads using the same guard.

One boundary holds its lock from the first dispatch check through synchronous
callback return or exception. A completed update is visible to the following
dispatch. An updater waiting for an active dispatch takes effect after that
callback leaves. A received notification is not effective merely because its
updater is waiting. Nested dispatch or `update()` from the active callback or
verifier is rejected. Callbacks and providers MUST NOT wait for another thread
that needs this same guard. Applications sharing trust state across several
verifiers MUST use a common boundary for those dispatches and updates.

This orders cooperating state updates in one process. It does not synchronize
with a remote issuer, external provider acceptance or an updater bypassing the
guard. The adapter remains responsible for authenticating the trust source,
rejecting stale snapshots and reflecting revocation information it receives.
Delivery delay and rollback of that external source require their own controls.

## Attempts and records

Concurrent dispatch of one issued object can enter the callback at most once
on this verifier instance. Once step 8 is reached, a normal return, exception,
cancellation or deferred result MUST leave the attempt consumed. In particular,
an exception does not prove that the callback caused no effect. Reconciliation
with the operation provider is required before a new authorized attempt.

Pre-entry rejection raises `Invalid`, with a stable `cause`, and that call
does not invoke the callback. `DISPATCH_ALREADY_ATTEMPTED` means an earlier
call already consumed the attempt; it does not imply that earlier call caused
no effect. An ordinary callback `Exception`, including `Invalid`, or a deferred
return raises the distinct `DispatchAttemptError` with the fixed message
`DISPATCH_OUTCOME_UNCONFIRMED` and the prepared `checkpoint` bytes. Callback
error details are not included in this error. This means the attempt is
consumed and the operation outcome requires reconciliation.

Interruptions derived directly from `BaseException`, such as
`KeyboardInterrupt` and `SystemExit`, propagate. An interruption can arrive
before or after attempt consumption; it MUST NOT be interpreted as evidence
that execution was never attempted. No automatic retry with a fresh admission
is authorized by an exception. Process-local attempt state still prevents a
second callback entry with the same object after consumption.

`DispatchResult.checkpoint` is immutable JSON bytes following
[`pre-dispatch.schema.json`](schemas/pre-dispatch.schema.json). Validators MUST
register [`runtime-verification.schema.json`](schemas/runtime-verification.schema.json)
under its `$id` to resolve the embedded verification record. When optional
[caller authority](../caller-authority/CONTRACT.md) is configured, dispatch also
requires `caller_proof` and includes a fresh `caller_authorization` record;
register [`caller-authorization.schema.json`](schemas/caller-authorization.schema.json)
under its `$id` for that record. The checkpoint
contains raw digest references to the admission receipt, request, original and
effective operation, the newly computed runtime verification, `checked_at`
after authentication, and the conservative usable deadline. The final clock
read after serialization can be later than `checked_at`.

The callback receives the checkpoint before any result is available.
`DispatchResult.value` is the callback's application-defined return value.
The checkpoint proves no independent callback entry, external acceptance or
effect. A callback can save it even when the subsequent operation fails.
Neither it nor a successful callback return is a post-execution receipt.
The original receiver assessment retains `evidence.authentication` and
`execution.actual_input` as `not_checked`.

The entry is a reference integration and is not production-ready. By default, state is
process-local and retained for the verifier's lifetime; it provides no durable
or cross-process replay control. A restart loses both admission and dispatch
state. The optional [caller authority adapter](../caller-authority/README.md)
adds actor-signed request authorization under selected principal-to-actor grants.
Transport caller possession, deadlines at external
acceptance, cancellation of an in-flight operation and independent effect
observation remain application/provider responsibilities. The final local
clock check cannot make an external action atomic with that check.

The [signed local example](../runtime-jwt/README.md#recheck-before-dispatch)
exercises this entry with ES256 evidence and a recording callback.
