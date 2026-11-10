# OAuth first-hop delegation revocation

Reproduce a user → A → B path in which revoking user → A denies B while
B's issued token, child grant and independent user permission remain unchanged.
The trial uses Ory Hydra 26.2.0 for OAuth and OpenFGA 1.22.1 for stored
relationship checks. Its 14 cases expose the policy inputs, changes, HTTP
observations and fixture action counts for comparison with another implementation.

## Get the standalone package

The [fixed download](https://vate.rognalia.com/downloads/oauth-first-hop-revocation/2026-11-10/oauth-first-hop-revocation-trial-20261110.zip)
contains the runner, model, grant bindings, 18 offline regressions, native
preparation helpers, expected results and saved synthetic evidence.
It uses **Python 3.14 and macOS arm64**, with Python's standard library only.
The two native executables are installed separately. The source package is
Apache-2.0; the executables retain their own licenses.

The [package identity](oauth-first-hop-revocation-trial.package.json) records
the ZIP size, SHA-256 and manifest hash. This is a separate trial from the
[ten-case permission-change trial and optional VATE example](oauth-persisted-grant-trial.md).
Its case numbers are local to this package. It does not produce VATE receipts.

Use a new directory. Extraction runs only after the downloaded bytes match
the fixed SHA-256:

```sh
curl --fail --location --remote-name https://vate.rognalia.com/downloads/oauth-first-hop-revocation/2026-11-10/oauth-first-hop-revocation-trial-20261110.zip &&
python3 -I -S -c 'import hashlib,pathlib,sys; p=pathlib.Path("oauth-first-hop-revocation-trial-20261110.zip"); sys.exit(0 if hashlib.sha256(p.read_bytes()).hexdigest()=="f34795280c075cb6bf45220afeab13bac58c1c9b76f0610b69fa335776876926" else "ZIP digest mismatch")' &&
unzip oauth-first-hop-revocation-trial-20261110.zip &&
cd oauth-first-hop-revocation-trial-20261110
```

From the extracted directory, check payload integrity and archive handling:

```sh
python3 -B verify_package.py &&
python3 -B test_package.py -v
```

Download the official pinned archives, verify their hashes and extract the
executables into `native/`:

```sh
python3 -B setup_native.py --download
```

The README also describes setup from already downloaded archives. The helper
refuses an existing destination. No native binaries are bundled in the ZIP.

Run the trial, choosing a new output directory:

```sh
python3 -B run_chain.py --native-root native --output runs/reproduction-01
```

Success exits with code 0 and reports `all_matched: true`, 14 cases,
`operations_executed: 2` and `owned_processes_stopped: true`. The action count
stays at two after first-hop revocation. Run the offline enforcement regressions:

```sh
python3 -B test_chain.py -v
```

The services are development-mode native child processes bound to `127.0.0.1`,
using synthetic identities and temporary credentials. They are not a VM or an
OS sandbox. Use a machine suitable for local test services. The runner stops
its own processes and discards temporary runtime data on normal completion or
handled failure. Offline regressions mock policy HTTP results and token claims;
they are separate from the native trial.

## What must stay unchanged in the main case

Case `10-first-hop-revoked-child-unchanged` first permits the calendar fixture
action, removes only the first-hop enabled tuple, then denies another request.
Its before/after evidence checks all of these together:

- The same token remains active, with unchanged introspection claims.
- The child's enabled tuple, parent reference and grant descriptions remain.
- The independent user-permission check still permits the action.
- Both native services remain healthy.
- The request is denied by the chain check and adds no calendar action.

Case 11 evaluates an intentionally incomplete leaf-only control against the
same state. That control would permit; it does not execute an action.

## Who can change each input

| Stored state | Writer in this trial |
| --- | --- |
| First-hop and child enabled tuples | The same AS-role credential, through the fixture management API |
| Independent user permission | Resource-owner credential, through that API |
| Grant identities, credential binding and parent relation | Trusted fixture setup |

Neither API role may rewrite parent bindings or create new grants. The AS
role cannot change user permission or bypass the adapter to write directly
to OpenFGA; the owner role cannot change either grant. These are rules of the
trial's management adapter, not permissions supplied by Hydra itself.
The two hops do not have independently authenticated grantor writers.

The Hydra token has subject `alice` and client ID `agent-b`. A fixed mapping
selects `agent:b` and its child grant. This exercises stored delegation state;
it does not implement A authenticating to issue B a credential or an OAuth
token-exchange/delegation-issuance protocol.

## Controls and evidence

| Cases | Observation |
| --- | --- |
| 01–04 | Initial permit and AS/owner writer separation, including direct backend bypass refusal |
| 05–06 | Parent rebinding and caller-supplied parent selection refused |
| 07 | User-permission revocation denies despite an enabled chain |
| 08–09 | Missing or additional parent binding refused |
| 09b | Legitimate parent revoked and only an extra parent enabled: model permits, fixed-parent guard denies |
| 10–11 | First-hop revocation denies with unchanged child/token; leaf-only control would permit |
| 12–13 | PDP unavailability denies after active-token validation; revoked token denies without policy access |

The fixed-parent guard requires exactly the configured parent before the
effective-grant check. Cases 08, 09 and 09b inject fixture faults with the
trusted setup credential. Case 09b separates the guard's effect from the
OpenFGA model's ability to find another permitted path. It does not establish
that alternative authorized paths must be rejected in every delegation design.

Read the saved `evidence/` directory or a new run's output in this order:

1. The run's `RESULT.json` and the package root's `EXPECTED.json` give the case
   observations and their expected values. `RESULT.json` also records
   the source hashes, component pins and cleanup status.
2. `FIRST-HOP-REVOCATION.json` records the main case's 15 assertions and
   before/after state. `EXTRA-PARENT-CONTROL.json` records case 09b's 12 assertions.
3. `EVENTS.json` links OpenFGA and health HTTP starts to responses or failures
   by request ID. PDP failure has a failed attempt; an inactive token has no
   policy attempt. OAuth credentials, headers and exception bodies are omitted.
4. `MANIFEST.json` binds the saved output bytes. The package-level
   `PACKAGE-MANIFEST.json` also covers the code, documentation and saved evidence.

`verify_package.py` checks saved bytes; it does not replay native decisions.
The runner's source hashes in `SOURCE-IDENTITY.json` match the saved run.
Manifests are local integrity records, not signed attestations.

## Scope of the result

The trial covers one fixed user, delegation path, resource and action, with
sequential checks. Login/consent, policy administration and the calendar action
are fixture code. General graph semantics, arbitrary-depth delegation,
independent per-hop authorities, concurrent-update atomicity, signed records,
real calendar operations and AuthZEN wire conformance are outside this trial.
It is an interoperability review aid, not production-ready software or a
general OAuth/AuthZEN compatibility result.

Native execution was tested on macOS arm64 with Python 3.14.8. To compare your
implementation, recreate the selected case inputs and state changes in your
own harness, then compare its observations with `EXPECTED.json`. Record your
version, writer rules and parent-selection rules alongside the result. This
runner starts its own Hydra/OpenFGA fixture; it has no external-implementation
connection option. Preserve differences in those rules when interpreting a
different outcome.

Official releases: [Hydra 26.2.0](https://github.com/ory/hydra/releases/tag/v26.2.0)
and [OpenFGA 1.22.1](https://github.com/openfga/openfga/releases/tag/v1.22.1).
