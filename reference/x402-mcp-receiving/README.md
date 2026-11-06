# x402 MCP result receiving example

Keep a reported unknown cancellation outcome, a payment receipt and a tool error visible
as separate observations. This VATE reader retains the original request and SDK
result even when the client declines a new payment approval. An optional
[Recipient Inbox](../recipient-inbox/README.md) connection preserves successive
attempts without replacing earlier evidence.

The example targets the Python MCP implementation at
[x402 `2ef9f38`](https://github.com/x402-foundation/x402/tree/2ef9f3872fbc0cfc93b1143f26ed668d13a7725e).
It is an experimental local export contract, not an x402 or MCP wire format.
The reader uses only Python's standard library and does not call tools or
payment services. It reports what the supplied records say; it does not verify
settlement or grant execution or retry permission. It is not production-ready.

## Try the reader

Requirements: Python 3.11+ on Linux or macOS. From the repository root:

```bash
vate_x402_demo="$(mktemp -d)"
python3 -S -B reference/x402-mcp-receiving/run_examples.py \
  --out "$vate_x402_demo/synthetic"
```

This checks five **handwritten synthetic exports**, retains their original
bytes and confirms that re-reading them produces the same observations. The
whole folder can be copied out of the repository for this command and the
standalone reader tests. No SDK or network connection is needed.

| Fixture | What remains visible |
| --- | --- |
| `01-cancel-unknown` | The exact cancellation-unknown marker, independent of the tool error. |
| `02-upfront-and-unknown` | A reported upfront success receipt together with unknown cancellation. |
| `03-reapproval-return` | A retained return value when the exporter reports reapproval denial. |
| `04-reapproval-exception-result` | The result retained under an exception's `result` attribute. |
| `05-reapproval-exception-mcp-result` | The result retained under an exception's `mcp_result` attribute. |

## Replay captured SDK results into Inbox

[captures/first](captures/first/CAPTURE-MANIFEST.json) contains four runs of the
**actual pinned SDK code with local test doubles**. They exercise unknown
cancellation, upfront settlement followed by unknown cancellation, declined
reapproval, and an ordinary success control. The exception-carrier examples
above are synthetic; these captured SDK runs use the synchronous return path.

The test doubles provide the transport, payment scheme, facilitator and tool.
They perform no real payment, signature verification or external tool action.
The SDK client and payment wrapper run in process; this is not an MCP wire
transport test. [SDK reproduction](sdk/README.md) explains how the captures were
made and how to take new ones.

Use the repository's Python environment with its existing
[development requirements](../../requirements-dev.txt) installed. For a fresh
checkout without that environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
```

The following replays the saved files; it does not import or execute the SDK:

```bash
vate_x402_intake="$(mktemp -d)"
.venv/bin/python -B reference/x402-mcp-receiving/run_sdk_examples.py \
  --capture reference/x402-mcp-receiving/captures/first \
  --inbox-source-root . \
  --out "$vate_x402_intake/first"
.venv/bin/python -B reference/x402-mcp-receiving/check_second_attempt.py \
  --first-intake "$vate_x402_intake/first" \
  --capture reference/x402-mcp-receiving/captures/second \
  --inbox-source-root . \
  --out "$vate_x402_intake/second"
```

The first command checks saved-file hashes, CLI/API agreement, exact original
retention, duplicate delivery and persistence after reopening Inbox. It also
runs 16 negative controls for changed bytes, wrong attempt, wrong request and
wrong SDK commit. The second command copies that database and adds another
captured attempt of the same operation. It checks that all four earlier entries
remain unchanged, while the new attempt has a separate entry. Both commands store evidence without running
Inbox's native semantic assessment.

The saved inventories identify the local test inputs and capture code. They
are unsigned records, not proof of an exporter's identity or of external events.

## Read your selected export

Supply three UTF-8 JSON files as described in [CONTRACT.md](CONTRACT.md):

- A receiver selection: expected server, operation and attempt labels, plus the
  raw SHA-256 of the selected request and capture.
- The application-level SDK request: tool name and arguments.
- An export of the supported SDK result fields and local observations.

Use the first synthetic example to see the complete input shapes:

```bash
vate_x402_read="$(mktemp -d)"
python3 -S -B reference/x402-mcp-receiving/receive.py \
  --selection reference/x402-mcp-receiving/fixtures/01-cancel-unknown/selection.json \
  --request reference/x402-mcp-receiving/fixtures/01-cancel-unknown/request.json \
  --capture reference/x402-mcp-receiving/fixtures/01-cancel-unknown/capture.json \
  --out "$vate_x402_read/received"
```

Choose the expected operation and request independently of the returned result.
The capture digest selects the exact received bytes; it does not authenticate
them. Never use a payment transaction identifier as an operation or attempt ID.
The exported `request.json` is not a signed request or a JSON-RPC transcript.

## Interpret the report

`status: inspected` means the supported export was read. Inspect the individual
fields even when the command exits successfully:

- `checks.receiver_selected_bytes` compares raw bytes with the receiver's
  selected hashes; `checks.declared_context` compares exporter labels.
- `observations.cancellation` records the exact unknown marker if present.
  Absence is `not_reported`, not a successful cancellation.
- `observations.receipts` records every supported receipt location separately.
  A header-subset match does not reproduce the native SDK's full parser.
- `observations.tool_result` keeps SDK and raw error flags separate, including
  whether their content agrees. Exporter claims about phase, recovery and
  reapproval remain explicitly labeled.

Authenticity and issuer authority, authenticated operation/attempt binding,
native settlement, cancellation/refund outcome, tool outcome, admission linkage,
execution/retry permission and the identity of a previous result all remain
`not_assessed`. Every report has `is_execution_ticket: false`.

Exit 0 means a report and bundle were saved, including mismatches or unsupported
profiles. Exit 64 means an input/output error; 2 means invalid CLI arguments;
70 means an unexpected internal error. Output directories must be new. The
bundle contains the three original files, report and hash manifest.

## Tests

Standalone reader tests, with no site packages:

```bash
python3 -S -B -m unittest discover \
  -s reference/x402-mcp-receiving -p test_receive.py -v
```

All tests, including Inbox storage and saved-capture integrity:

```bash
.venv/bin/python -B -m unittest discover \
  -s reference/x402-mcp-receiving -p 'test_*.py' -v
```

CI runs these on Python 3.11 and 3.14, plus the saved SDK replay and second-attempt
check. It does not download or run the external SDK. The reader's fixed upstream
references are listed in [SOURCE-MANIFEST.json](SOURCE-MANIFEST.json).
