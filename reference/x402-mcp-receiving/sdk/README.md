# Reproduce the SDK capture

`capture_sdk.py` runs x402's fixed Python client and payment wrapper against
local test doubles, then exports their actual results for the VATE reader.
Reproduction is optional; the [saved-capture replay](../README.md#replay-captured-sdk-results-into-inbox)
needs no x402 installation.

## Exact source and dependencies

Use source commit
[`2ef9f3872fbc0cfc93b1143f26ed668d13a7725e`](https://github.com/x402-foundation/x402/tree/2ef9f3872fbc0cfc93b1143f26ed668d13a7725e).
Its version label is `2.27.0`, but the PyPI release with that label has different
MCP implementation files ([retained hash comparison](RELEASE-COMPARISON.json)).
Installing `x402==2.27.0` does not reproduce these
captures. [SOURCE.json](SOURCE.json) records the archive digest and 429 selected
source/license files; [DEPENDENCIES.json](DEPENDENCIES.json) records the six
exact dependency versions. No SDK source is bundled here.

The capture was run on macOS with Python 3.14.8. The wheel hashes in
[requirements.lock](requirements.lock) cover CPython 3.14 macOS and manylinux
builds, plus the platform-independent packages. Use a disposable environment;
this executes external SDK code and pydantic's native module. Installation uses
wheels only, with dependencies and hashes fixed. It does not change VATE's
runtime dependencies.

From the VATE repository root, fetch and check the source archive:

```bash
vate_x402_sdk="$(mktemp -d)"
curl --fail --location \
  https://codeload.github.com/x402-foundation/x402/tar.gz/2ef9f3872fbc0cfc93b1143f26ed668d13a7725e \
  --output "$vate_x402_sdk/source.tar.gz"
python3 - "$vate_x402_sdk/source.tar.gz" <<'PY'
import hashlib
import pathlib
import sys
expected = "be37c284e4efe5f816c3663ca403c3907e06d33701b0c9c28c06253893c0cf72"
if hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest() != expected:
    raise SystemExit("source archive hash mismatch")
PY
```

After that hash check succeeds, extract and install the fixed dependencies:

```bash
tar -xzf "$vate_x402_sdk/source.tar.gz" -C "$vate_x402_sdk"
python3.14 -m venv "$vate_x402_sdk/runtime"
"$vate_x402_sdk/runtime/bin/python" -m pip install \
  --only-binary=:all: --no-deps --require-hashes \
  -r reference/x402-mcp-receiving/sdk/requirements.lock
"$vate_x402_sdk/runtime/bin/python" -m pip check
```

Capture four cases, then another attempt of the declined-reapproval case:

```bash
"$vate_x402_sdk/runtime/bin/python" -B \
  reference/x402-mcp-receiving/sdk/capture_sdk.py \
  --sdk-source "$vate_x402_sdk/x402-2ef9f3872fbc0cfc93b1143f26ed668d13a7725e" \
  --out "$vate_x402_sdk/first"
"$vate_x402_sdk/runtime/bin/python" -B \
  reference/x402-mcp-receiving/sdk/capture_sdk.py \
  --sdk-source "$vate_x402_sdk/x402-2ef9f3872fbc0cfc93b1143f26ed668d13a7725e" \
  --out "$vate_x402_sdk/second" \
  --case 03-reapproval-return --attempt-id application-call-002
```

Pass these new `first` and `second` paths to `run_sdk_examples.py` and
`check_second_attempt.py` from the [main instructions](../README.md).
Output directories must not exist. A failed run may leave partial evidence;
only a run with a final `CAPTURE-MANIFEST.json` is complete.

## What executes

The harness checks all selected source hashes, copies those files into a fresh
temporary import tree, and excludes pre-existing bytecode and unlisted modules.
It checks the six installed dependency versions before importing the SDK.
The capture manifest records the harness hash, every saved JSON file, and the
29 SDK modules loaded in these runs. The source snapshot is removed on exit.

Actual SDK code handles the payment challenge, approval callbacks, payload
submission, payment wrapper, response recovery and returned result. The harness
supplies an in-process transport, a test-only cash scheme, facilitator answers,
a local handler and approval/response/metering hooks. The test asset is allowed
with a per-payment cap; general spend controls are not disabled. In two cases
the cancellation-dispatcher factory alone is overridden to inject a timeout.

| Case | Injection and observed SDK path |
| --- | --- |
| `01-cancel-unknown` | The metering hook exceeds the allowed amount; the injected cancellation failure produces the unknown marker. No handler or test settlement runs. |
| `02-upfront-and-unknown` | The test facilitator settles before the handler. The metering and cancellation faults then produce an error and unknown marker while the success receipt remains. |
| `03-reapproval-return` | Test verification rejects the submitted payload. A recovery hook handles the corrective offer; the application declines the second approval. The SDK returns the retained paid-call result without another payload submission. |
| `04-success-control` | The local handler and test settlement each run once and return an ordinary success result. |

Each case records two in-process tool calls: an unpaid probe and one payload
submission. Each creates one test payload. The second capture repeats case 03
with a new receiver-chosen attempt label; the same request/result can therefore
be retained as a different attempt.

`request.json` and `receiver-plan.json` are written before the SDK call.
`native-sdk-result.json` exports all five call-result attributes; the receipt
uses Pydantic JSON/alias serialization. `native-tool-results.json` retains both
tool returns, with all four raw-result attributes. `capture.json` wraps the
unchanged exported result with source/context labels and local observations.
`TRACE.json` records callbacks, counts, test doubles and result types. The final
manifest hashes these files; the VATE replay checks the inventory before use.

The Python audit hook blocks socket connect/sendto/name-resolution/bind events;
these runs recorded zero attempts. It is not an operating-system sandbox.
There is no MCP wire connection, wallet, cryptographic payment signature,
real settlement/cancellation or external side effect.
Neither a saved trace nor its unsigned hash manifest establishes those facts
for someone else's capture.
