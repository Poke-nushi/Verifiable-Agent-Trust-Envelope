# Border relay evidence receiving CLI

Check a CROSSING-002 relay record against a receiver's selected key, relay role
and request context. The CLI returns separate results for the evidence
reference, DSSE signature, relay role, requester, task/context, recipient,
action, nonce and validity window. A valid signature can therefore accompany a
requester mismatch; a missing key remains unevaluated.

This experimental receiving example targets the
[CROSSING-002 relay format at `78b592b`](https://github.com/Silentpartnercoding/minority-prophet-border/tree/78b592b87d50a8634350c8afed32ef4b228a264d/experiments/a2a-mcp-crossing-002).
It uses VATE's existing JCS helper and Node's Ed25519 verification. The supplied
request and mandate are comparison inputs; their authority credentials are not
verified. Results describe these receiving checks, not permission to execute
an action. It is not production-ready or a general DSSE verifier.

## Try the five examples

Requirements: Node.js 22.18.0+ in the 22.x line (or a newer release with
`import.meta.main`) and the repository's existing TypeScript build tools.
Run from the repository root, after installing the locked workspace dependencies
using the repository's normal setup.

```bash
npm run ts:check
vate_border_example="$(mktemp -d)"
node reference/border-receiving-cli/demo.mjs --output "$vate_border_example/cases"
node reference/border-receiving-cli/receive.mjs \
  --message "$vate_border_example/cases/normal/message.json" \
  --envelope "$vate_border_example/cases/normal/envelope.json" \
  --request "$vate_border_example/cases/normal/request.json" \
  --policy "$vate_border_example/cases/normal/policy.json"
```

The generator creates a fresh directory with five four-file examples and a
manifest of their hashes. It generates test keys in memory and saves only public
keys and signed records. These are synthetic examples, not Border's captured
runs. A new invocation generates different keys; rerunning the receiver on the
same saved files produces the same report.

Replace `normal` in the four input paths to try another example:

| Directory | Signature | Relay role | Requester binding | `checks_status` |
| --- | --- | --- | --- | --- |
| `normal` | verified | matched | matched | matched |
| `different-caller` | verified | matched | mismatched | mismatched |
| `missing-key` | not_assessed | not_assessed | matched | not_assessed |
| `invalid-signature` | mismatched | not_assessed | matched | mismatched |
| `untrusted-relay` | verified | mismatched | matched | mismatched |

## Supply your own four files

The caller supplies each path explicitly. The receiver reads regular files,
emits JSON to stdout, and does not fetch references, execute a tool or modify
the inputs. Each file has a 1 MiB limit. Derived JSON submitted to the JCS helper
has the same limit; numeric expansion beyond it returns an input error.
Original UTF-8 bytes are validated before
JSON parsing can erase duplicate names. The existing JCS helper also rejects
invalid Unicode, non-finite numbers and excessive nesting.

| Input | Source and contents |
| --- | --- |
| `--message` | Retained A2A message with `taskId`, `contextId`, the relay extension and `metadata.crossing_relay.attestation_ref`. |
| `--envelope` | Original JSON encoding of the referenced DSSE envelope. Its decoded payload and signature retain their exact bytes. |
| `--request` | Receiver-supplied expected requester, receiver, presenter, task, context, nonce, tool, arguments, evaluation time and modeled mandate. Do not derive these expectations from the attestation being checked. |
| `--policy` | Receiver-selected profile, digest basis, public verification keys and allowed relay roles. Do not copy trust settings from the supplied envelope. |

`request.json` requires these fields:

```json
{
  "authority_context": "modeled",
  "evaluation_time": "2026-08-18T12:00:00Z",
  "requester_id": "caller-a",
  "receiver_id": "receiver-b",
  "presenter_id": "relay-r",
  "task_id": "example-task",
  "context_id": "example-context",
  "nonce": "example-nonce",
  "tool": "interop.echo",
  "arguments": { "payload": "synthetic example" },
  "mandate": {
    "schema": "authorized-invocation/v1",
    "relationship": "MANDATE",
    "requester_id": "caller-a",
    "executor_id": "receiver-b",
    "request_id": "example-task",
    "nonce": "example-nonce",
    "action_digest": "sha256:5b846f0ba94c31b5cca882fdcaea1bf1c006de03e8076410424923336fe51853",
    "not_before": "2026-08-18T11:00:00Z",
    "expires_at": "2026-08-18T13:00:00Z"
  }
}
```

This illustrates the request shape. Use the generated four-file sets together
for runnable inputs. Preserve all fields in an actual mandate: the digest covers
the whole object, while the receiver checks only the fields described in
[CONTRACT.md](CONTRACT.md).

A policy without a supplied key is valid:

```json
{
  "profile": "border-crossing-002-ed25519-v0",
  "digest_basis": "rfc8785-jcs",
  "verification_keys": [],
  "relay_roles": []
}
```

For a known key, follow the generated `policy.json`: a key entry contains its
`keyid`, SHA-256 of its Ed25519 SPKI DER bytes, and those bytes in standard
base64. A separate role binds that key hash to the relay ID, receiver ID and
exact predicate type. Adding a key enables signature checking; the role grants
only the selected relay claim within this example.

The captured experiment's original public key must be supplied to verify its
original signature. If a new run is needed, retain its public key and signed
evidence together as a separate run.

## Read the result

- `checks` gives a status and reason for each check. These reasons belong to
  this example, not the VATE conformance reason-code registry.
- In an evaluation report, `checks_status` summarizes the selected checks: `matched`, `mismatched`,
  `not_assessed`, or `error`.
- `authenticated_relay_bindings` is evaluated only after both the signature
  and receiver-selected relay role succeed. Otherwise it stays `not_assessed`,
  even if an unsigned field comparison exposes a mismatch.
- `inputs` records raw SHA-256 and byte length for all four supplied files.
  `evidence` records SHA-256 hashes of the decoded payload, signing input and
  selected key. It does not include those contents.
- `not_assessed` retains mandate/authority signatures, real peer authentication,
  current key status, durable replay protection, execution permission and outcome.

Exit **0** means a report was emitted, including mismatch or missing-key reports.
It is not a success or allow signal. Exit **64** means malformed input,
unsupported receiver configuration or a local file/argument error; **70** means
an internal or cryptographic-backend error. These error reports contain stable
codes rather than input contents or local paths.

Input errors use a compact report containing `kind`, `profile`,
`checks_status: "invalid_input"`, `reason` and `input`. Internal failures can
use the same compact shape with `checks_status: "error"`. These reports have
no `checks`, `inputs` or `evidence` fields; consumers must handle this shape
before reading individual check results.

The CLI does not establish what an authenticated relay actually observed, nor
whether the receiver's supplied context is true. It checks the recorded claim
against that context. A dishonest trusted relay can sign a false claim.

## Verification

```bash
npm run ts:check
node --test reference/border-receiving-cli/test_receive.mjs
```

The suite includes valid signatures with contradictory bindings, unknown keys,
roles, signed noncanonical payloads, altered bytes, duplicate JSON names,
invalid dates, input-size expansion and file limits. It also checks both CLIs
through symlinks and confirms that importing either module does not execute its CLI.
The demo and test signatures use Node/OpenSSL; agreement within that environment
is not evidence of independent cryptographic implementations.
