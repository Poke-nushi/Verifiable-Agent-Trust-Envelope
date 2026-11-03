# ACS capture reader v1 — local contract

Offline reader for the saved ACS #435 log shapes. Profile:
`vate-local-acs-log-reader-v1`. It consumes observations, never issues an
admission receipt, authorization, execution ticket or retry instruction.

## Inputs

See [INPUT-FORMATS.md](INPUT-FORMATS.md) for the four JSONL shapes and optional
command timestamp files.

`assess(inputs, selection_raw, *, command_timestamps=None)` accepts an exact
plain dict of four keys in `inputs`:
`host_audit`, `guardian_envelopes`, `host_events`, `proxy`. Values are immutable
Python `bytes`, or explicit `None` for absence. Each is JSONL; every line is an
object. A missing file, empty file, JSON null or malformed JSON is not absence.
The CLI requires a path or explicit `--NAME-absent` for each source.

The optional `command_timestamps` argument is either `None` (disabled), or an
exact plain dict with `command_start` and `command_end`, each immutable bytes
or explicit `None`. These files contain one UTC timestamp, not JSON. If either
CLI timestamp option is used, both sides require a path or their respective
`--command-start-absent` / `--command-end-absent` flag. Omitting all timestamp
options omits command timestamp sources, observations and comparisons.
Each timestamp path option accepts one occurrence; repeated paths for the same
side are rejected before any input files are read.

Selection is JSON bytes with exactly `profile`, `request_id`, `acs_session_id`,
`host_session_id`. IDs are selected by the receiver, 1–256 characters without
ASCII whitespace/control characters. This selection scopes the supplied files;
it does not authenticate their origin, sessions, identifiers or membership in
one capture. V1 supports string RPC IDs and ACS version 0.1.0 only.

Bounds: 1 MiB per input (including selection), depth 32 for all JSON. The four
JSONL sources additionally allow at most 512 lines and 65536 bytes per line;
selection is one JSON document and has no separate line-count/line-size limit. Duplicate
JSON keys, invalid UTF-8/lone surrogates, nonfinite numbers and numbers outside
the safe-integer magnitude are rejected. Fractional numbers remain Decimal;
fields requiring integers reject booleans and decimal-token values. LF and
CRLF are accepted. Blank lines are rejected. An optional final LF is retained
in the source digest. Each report reference includes source key, one-based
line and SHA-256 of original line bytes excluding LF (including CR if present).
The entire source digest identifies the exact JSONL, including line endings.
Expanded result/hello request-response associations share a 1024-record budget;
exceeding it is an input error. Reused IDs cannot cause unbounded report expansion.

The CLI reads bounded regular files and rejects final symlinks where
O_NOFOLLOW is available. Parent path components are not sandboxed. It follows
no paths or URLs embedded in inputs, invokes no external commands and uses no
network or added dependency. File paths and exception details are not echoed.

## Interpreted fields and ambiguity

Host audit records for the selected request retain posture, posture source,
failure kind, outcome, timestamp and session. Supported posture/outcome pairs
are proceed/proceeded and deny/blocked, for steps/toolCallRequest and the
selected host session. Unsupported combinations remain not_assessed.

Guardian toolCallRequest request/response records retain their own judgment.
The outer logged RPC ID, JSON-RPC ID and inner request_id must agree. Requests
must also agree with their logged method. Only final allow/deny responses are
interpreted as supported decisions; other decisions, versions, progress and
RPC errors cannot establish a binding. Missing records, unsupported records
and repeated/conflicting records are distinct. Repeated records are retained,
not silently deduplicated, ordered into a winner, or overwritten.

The host/Guardian relation is matched_by_rpc_id only with one supported host
record, one supported selected-session Guardian request, one supported final
response, and no other request using that RPC ID anywhere in the supplied
Guardian log. This means identifier equality within selected capture files,
not authentication or a proven causal relationship.

Handshake observations pair a hello request in the selected ACS session with
its response using the logged RPC ID and JSON-RPC ID. An unknown inner
request_id field in a hello response is never used for selection. Reused hello
IDs prevent confirmation. Only negotiated version
0.1.0, proceed/deny and timeout_config containing only positive default_ms are
interpreted. Per-method/unknown timeout configuration stays not_assessed.
A matching fallback means equality of reported values, not an authorization.
Hello request observations remain visible even when their responses are absent.
For each recognized request method (toolCallRequest, toolCallResult, hello), a
known method on either the outer log or inner envelope triggers envelope,
direction, ID and method checks before session or request selection. This applies
to all recognized envelopes in the supplied Guardian log, including unselected
RPCs; corrupt envelopes are input errors, not missing observations. Unknown
methods remain opaque. Their inner request_id extensions are never counted as
RPC identity; reuse counts use outer logged or JSON-RPC IDs only.

Result hooks have their own RPC IDs and responses. An allow response to a
toolCallResult is never an allow for the original toolCallRequest. No action
reference extension is implemented. Result-to-request and execution-to-request
binding therefore remain unresolved, including when an extra reference field
appears. Unknown fields are retained in originals, not trusted or interpreted.
If a result RPC ID is reused in any supplied session or method, a nonempty
candidate response group is ambiguous and response_association is unresolved.
With no candidate responses, the group remains not_observed while the request
reuse count and unresolved association remain visible. The result request
and candidate response records remain visible, without choosing a pairing.

### Guardian log order

Every result hook in the selected ACS session has `order_vs_selected_request`.
This compares that result notification with the receiver-selected Guardian
tool-request observation; it does not select a result for that request.
`selected_request_source` identifies the request's original line and hash.
`result_seq` and `selected_request_seq` retain supported top-level `seq`
values, or null when missing or unsupported.
If no unique supported selected request can be used, including RPC ID reuse,
both `selected_request_source` and `selected_request_seq` are null. This can
occur even when `guardian_request.status` is `observed`; the request's own
observation remains in `guardian_request`.

With one supported selected request, no reuse of its RPC ID anywhere in the
Guardian log, and a supported result hook with a unique RPC ID:

- `file_order` records whether the result row is before or after the request
  row in the supplied file.
- `sequence_order` reports `observed_sequence_order` only when every supplied
  Guardian row has a nonnegative integer-token `seq` no greater than
  9007199254740991, strictly increasing in file order. Gaps are allowed.
  Missing, invalid, repeated or decreasing sequence values leave this field
  `unresolved`. The reader neither sorts the log nor repairs its sequence.
- `recorded_time_order` compares Guardian `recorded_at` timestamps. Its signed
  `delta_microseconds` is result minus selected request. Equal or reversed
  clock readings do not change file or sequence order.

File and sequence comparisons set `clock_comparison_required` to false.
Without unique supported request/result observations, all three comparisons
remain `unresolved`. Missing or inconsistent sequence metadata alone leaves
the separate file and timestamp comparisons available. Within the reader's
JSON bounds, invalid sequence metadata does not itself make the whole log
invalid input.

These are observations within the supplied Guardian log, identified by its
file and line hashes. They do not authenticate the logger, establish collection
completeness or actual network arrival, or bind either RPC to an execution.
`same_action_proven` remains false and request-to-result/execution links remain
`unresolved`. Hooks are compared separately; their order, timestamps and
responses never choose one as the selected request's result.

### Host tool observations

Host tool observations retain reported status, exit code and tool interval.
An outer tool_use event must contain an inner part.type of tool.
An exact bash command-text hash match is only a candidate cue. No command or
output text is copied into the report. The host interval may include Guardian
waiting; its start is not mapped to dispatch. Multiple candidates remain
multiple. The observed host outcome is not independent execution evidence.
The command-text comparison is null if either command is unavailable or the
supported bash comparison does not apply; false requires two comparable texts.

## Time and trust

Timestamp comparisons are between reported source wall clocks only. The
Guardian response time is not arrival at the host. The output makes no claim
about clock synchronization, whether a host received/applied a late decision,
settlement versus dispatch, cancellation, or the moment of actual effects.
Decision commitment and dispatch remain unknown. Event time is never used as
receiver arrival time. A reversed reported tool interval is invalid input.

`delta_microseconds` is a JSON integer. Consumers that read JSON numbers as
binary64 floating-point values may round integers outside the safe range
of -9007199254740991 to 9007199254740991. Use an integer-preserving JSON reader
when exact values outside that range are needed. This applies to both the
Guardian-to-host timestamp comparison and each hook's `recorded_time_order`.

### Optional command self-timestamps

Each timestamp file contains `YYYY-MM-DDTHH:MM:SS[.fffffffff]Z`, with zero to
nine fractional digits (omit the dot when there is no fraction). Years 0001–9999
and valid calendar dates are accepted; hour 24, leap seconds, offsets, whitespace
and additional lines are rejected. A final LF or CRLF is optional. The same
file/line hash conventions apply; the exact timestamp text is retained as
`reported_at`. The 1 MiB file and 65536-byte line bounds also apply.

`command_self_timestamps.start` and `.end` are independent observation groups.
The caller supplies their labels and capture membership; the files contain no
action or session ID. Pair, request and execution bindings stay `unresolved`,
even if command text or times match other records. The reader does not extract
timestamps from shell commands, stdout or filenames.

`timing.command_self_timestamp_comparisons` contains `start_vs_host_fallback_log`,
`end_vs_start`, and `guardian_response_vs_start`. They report start minus fallback,
end minus start, and Guardian response minus start, respectively. Differences use
integer arithmetic and are returned as decimal **strings** in `delta_nanoseconds`, preserving large values
for JSON consumers. Original timestamp precision does not establish clock accuracy.
Missing or ambiguous supported observations leave the affected comparison
`unresolved`; Guardian comparisons also require a unique selected request.

The comparison basis is receiver-supplied files and unverified source wall
clocks. No common execution or causal ordering is established. In particular,
`end_vs_start` is the difference between two supplied stamps, not a proven
command runtime. Reversed or equal stamps remain visible as `before` or `equal`;
they are not reordered or rejected as though they were a bound execution interval.
These observations never populate `dispatch_at` or `decision_committed_at`, nor
change the host decision, Guardian decision, result-hook judgment or action links.

Signature, issuer authority, log completeness, independent execution,
execution/retry permission and ACS conformance remain explicitly not_assessed.
There is no whole-report valid/trusted/pass flag. Exit 0 means a report was
generated, including absence, ambiguity and unassessed cases; 64 means invalid
input and 70 means an unexpected internal error. Output is deterministic for
identical inputs. Raw source identity, line identity and weak ID/text matching
are distinct from authenticated evidence.

## Existing VATE storage integration

`run_example.py` takes the four hash-pinned, self-authored synthetic logs in
`SAMPLE-PINS.json`. It reads host logs
first and adds Guardian/proxy logs in a second local stage. This is not a replay
of the original network timing. It stores originals and derived reader reports
as distinct opaque records in recipient-inbox, leaves received_at unknown,
and exports both assessments and all original bytes. The required-record review
set is explicitly empty; its selected_empty result verifies persistence/history,
not native ACS semantic support. The separate reader reports perform the narrow
interpretation described above.
The example uses the bounded regular-file reader for pins, sources and selection,
checks each source hash immediately, and validates both reader stages before
creating the new output directory. example_invoked_acs_host=false describes this
example's behavior. Its input records are invented and do not assert an actual
host or Guardian run. The inbox example needs a trusted whole VATE source tree
and its existing validation dependencies; the reader and tests use only Python's
standard library. `--source-root` selects that tree when the sample folder is
copied elsewhere.

## Pinned published capture replay

`check_capture.py --directory PATH` reads four locally supplied files named by
`PUBLISHED-CAPTURE.json`. It checks each raw SHA-256 and byte length immediately,
uses the pinned `published-selection.json`, and verifies the complete report's
raw-byte hash including its final LF. It fetches nothing and executes no capture
scripts. A missing or changed source is an input error. A successful replay means
that these capture bytes produced the pinned reading, not that their origin,
contents or execution are authenticated. Use `acs_reader.py` directly for new
captures, with a receiver-selected set of IDs, rather than changing the pins.
