# Local receiving contract

`vate-local-x402-mcp-receiving-v1` is an experimental VATE receiving example.
It is not a shared VATE schema, an x402/MCP wire format or a signature profile.
The fixed source references are in [SOURCE-MANIFEST.json](SOURCE-MANIFEST.json).

## Inputs

The API `assess(selection=bytes, request=bytes, capture=bytes)` and the CLI
consume the same three JSON objects. Extra outer keys and missing required
fields are input errors.

| Object | Required fields |
| --- | --- |
| `selection` | `profile`, `context`, `request_sha256`, `capture_sha256` |
| `request` | `name`, `arguments` (object) |
| `capture` | `export_profile`, `sdk`, `client_kind`, `origin`, `context`, `request_sha256`, `carrier`, `exception_type`, `result`, `local_observations` |
| `context` | `server_id`, `operation_id`, `attempt_id` |
| `result` | `content`, `is_error`, `payment_made`, `payment_response`, `raw_result` |
| `raw_result` | `content`, `is_error`, `meta`, `structured_content` |
| `local_observations` | `payment_phase`, `reapproval`, `client_recovered` |

The selection's profile is `vate-local-x402-mcp-receiving-v1`. The capture's
export profile is `local-x402-python-mcp-export-v1`; `sdk` must equal
`{"package":"x402","version":"2.27.0","source_commit":"2ef9f3872fbc0cfc93b1143f26ed668d13a7725e"}`.
The source commit is essential: the version label alone is not this contract.

- `client_kind`: `sync`, `async` or `session`.
- `origin`: `synthetic_fixture`, `retained_sdk_export` or `unknown`.
- `carrier`: `return`, `exception.result` or `exception.mcp_result`. A normal
  return requires null `exception_type`; an exception carrier requires a name.
  Exception messages, stacks and arbitrary attributes are not exported.
- `payment_phase`: `before_handler` or `unknown`; `reapproval`: `denied` or
  `not_recorded`; `client_recovered`: boolean or null. These are unauthenticated
  exporter claims, not conclusions inferred from a receipt.
- `is_error` and `payment_made` are booleans without numeric/string coercion.
  `payment_response` is retained as a receipt candidate; null means absent.
  Raw `meta` is an object and
  `structured_content` is an object or null.
- Content is an array of at most 128 objects with string `type`. Text blocks
  require a string `text`; other blocks are retained without full MCP validation.

IDs contain 1–256 printable, non-space ASCII characters. Digests are lowercase
64-character hexadecimal SHA-256 values. Each input is at most 1 MiB; nesting
is limited to 48 levels and number tokens to 128 characters. JSON must be UTF-8,
with no duplicate keys, non-finite numbers or isolated Unicode surrogates.
Decimal parsing preserves numeric values without binary floating-point rounding;
comparisons keep booleans distinct from numbers. All input hashes cover raw
bytes, not canonical JSON.

The exporter copies explicit attributes from SDK objects. The reader never
unpickles objects, imports a class named by input, or fetches an input URL.
`meta`, `is_error` and `structured_content` are SDK attribute names, not implicit
aliases for wire `_meta`, `isError` or `structuredContent` fields.

## Assessment order and observations

The reader parses all three objects and validates the selection first. It then
checks the profile, selected byte hashes, request shape, supported export/SDK
pin, and declared context/request hash. A mismatch or unsupported profile stops
semantic observations. Malformed input is an input error. This early-return
order does not diagnose every later field in a mismatched export.

`receiver_selected_bytes: matched` identifies the selected bytes only.
`declared_context: matched` identifies matching exporter labels only. Neither
authenticates the capture or its relation to a real operation. The receiver
supplies its expected labels and request independently. A new attempt needs a
new attempt label even when the request and result bytes otherwise agree.

Cancellation is `reported_unknown` only when a standalone raw text block
exactly equals `Payment cancellation outcome unknown`. Otherwise it is
`not_reported`. The marker does not prove that cancellation was invoked or
completed, or that a handler did or did not run.

Receipt observations retain all four surfaces without selecting a winner:

1. SDK `payment_response` summary.
2. Raw metadata `x402/payment-response`.
3. Raw structured content with that key.
4. A raw text block containing a JSON object with that key.

The checked header subset comprises a boolean `success`, string `transaction`,
a nonempty string `network`, and optional string-or-null `amount`, `payer`,
`errorReason` and `errorMessage`. Unrecognized values retain their location.
Proofs and extensions are not validated. `header_subset_location_match` means
that subset and a candidate location match: metadata, or a failure receipt in
a tool-error body. It is not equivalence with the native parser's validation,
precedence or reconciliation. A success receipt in body text is not promoted
to successful reconciliation. `distinct_values` counts different retained
values without deciding whether they describe separate phases or conflict.

Source pointers address locations in the saved capture. For embedded JSON text,
the pointer addresses the entire text field. Invalid JSON-looking text remains
in the original with a diagnostic. Summary and raw error flags are independent;
`content_views_equal` compares their content. Results remain retained even when
reapproval is declined. Authenticity of their claimed earlier origin remains
unassessed.

## Outputs and storage

A report records input byte lengths and hashes, reader source hash, fixed target
version, separate observations and the explicit unassessed checks listed in
the [README](README.md#interpret-the-report). It does not copy arbitrary IDs,
result text, URLs, payees or transaction values into the derived report.
Original input files retain those values. `status: inspected` is an observation
status, not successful settlement or tool execution.

The reader compares its executing module code with freshly compiled source at
import. A stale cache fails with `reader_source_mismatch`; later source change
or deletion fails with `reader_source_changed`. The source hash identifies a
local reader file, not an attestation of the complete execution environment.

The CLI creates a new 0700 directory and writes the three original inputs,
report, then manifest as 0600 files. Existing outputs are refused; a failed
write may leave an incomplete directory. Retry with a new destination.
Inputs must be regular files; final-component symlinks and FIFOs are rejected.
Size/mtime changes during reading are rejected. Parent-directory symlinks are
not a path sandbox. No paths within an input are followed.

The CLI exits 0 after saving a report, including mismatch/not-assessed reports;
2 for argument errors; 64 for input/storage errors; 70 for unexpected internal
errors. Input error JSON omits paths, source bodies and stacks. Direct Python
calls with invalid path types, NULs or unencodable paths raise `InputError`
with `invalid_file_path`.

`inbox_connection.retain` receives a caller-initialized local Inbox. It stores
three originals and the report as `local_x402_mcp_export`, without projecting
admission or post-execution receipts. `received_at` remains null. Identical
intake is idempotent; changed captures or reader reports produce separate
entries. Existing original slots remain untouched. The generic Inbox reviewer
does not support native semantic assessment of this kind. No `prepare/run`,
payment resend/cancellation or tool execution occurs.
