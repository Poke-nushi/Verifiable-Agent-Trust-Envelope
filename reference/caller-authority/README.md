# Authorize a signed purchase instruction

Require an actor's signature over the exact admission request and original
operation, then check the principal's permission and delegation to that actor.
The adapter checks the resource, action, runtime, audience, currency, amount
cap and allowed tools against application-selected grants. The ordinary Python
entry repeats these checks immediately before its dispatch callback, including
after restoring a pending admission from local durable state.

This is an optional reference integration for the purchase-cap profile. It
uses the existing Node.js 22+ ES256 backend and adds no package dependency.
It authenticates the actor's signed instruction; it does not identify the
network peer relaying it. It is not production-ready.

## Run the local example

From the repository root, using an existing Node.js 22+ installation:

```bash
VATE_NODE="$(command -v node)"
VATE_NODE_SHA="$(shasum -a 256 "$VATE_NODE" | awk '{print $1}')"
python3 reference/caller-authority/run_example.py \
  --node "$VATE_NODE" --node-sha256 "$VATE_NODE_SHA" \
  --output /tmp/vate-caller-authority-example
```

Choose a new output directory for each run. The hash selects the installed
binary for this local experiment; deployment must establish its approved
binary independently.

The example generates ephemeral signing keys inside Node. It admits a signed
instruction, observes a revoked grant preventing callback entry, restores the
grant, reopens the durable store, and invokes one local recording callback.
Another restore is rejected because the operation attempt was consumed.
It performs no purchase or network request.

`RUN.json` contains the observations, source hashes and exported artifact
digests. `pre-dispatch.json` includes the current authority and grant identifiers,
the proof digest and the checked request references. The caller token and
private keys are not exported. The temporary SQLite store is removed when
the example ends; deployed integrations must retain their store and anchor.

```bash
python3 -m unittest discover -s reference/caller-authority -p 'test_*.py'
```

## Integrate with the ordinary Python entry

Construct `CallerJwtAuthorizer` with an application-owned authority-policy
provider and pass `as_caller_authorizer()` as `VateVerifier.caller_authorizer`.
This mode requires a runtime verifier, a `DispatchBoundary` and a
`DurableStateStore` configured before admission. Supply the caller token as
`caller_proof` to both `admit` and `dispatch`. Restoring a pending admission
does not restore or renew that token.

When admission shares state with local permission updates, use the same
boundary guard for admission and every update:

```python
with verifier.dispatch_boundary.update():
    admitted = verifier.admit(
        admission_bytes,
        original=original_bytes,
        evidence_artifacts=runtime_artifacts,
        caller_proof=caller_token,
    )
result = verifier.dispatch(admitted, caller_proof=caller_token)
```

The [contract](CONTRACT.md) defines the token, authority provider, durable
configuration and current-grant semantics. [run_example.py](run_example.py)
shows the complete wiring. The application must authenticate its permission
source and require this mode at every exposed entry that needs it. Local
grant fixtures demonstrate the checks; they do not establish real-world
authority or an authenticated remote update channel.

The receipt and receiver assessment retain their existing format. Receiver
assessment checks the content bindings; it does not authenticate a received
caller-verification record or establish external execution. The TypeScript
receiver can assess those bindings, but does not implement this Python
authority or durable-dispatch adapter.
