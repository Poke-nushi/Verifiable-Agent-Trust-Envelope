# Supported capture formats

These are the four logging shapes understood by this reader, not a general ACS
logging specification. Each file is JSONL: one JSON object per line. The examples
below are invented records using the IDs in [selection.example.json](selection.example.json).
See [CONTRACT.md](CONTRACT.md) for bounds, error handling and association rules.

| CLI input | Selection and interpreted fields | Complete synthetic file |
| --- | --- | --- |
| `--host-audit` | Selects `rpc_id`; checks the host session and retains the reported fallback. | [host-audit.jsonl](fixtures/synthetic/host-audit.jsonl) |
| `--guardian-envelopes` | Interprets logged hello, tool-request and result-hook JSON-RPC exchanges using the ACS session. | [guardian-envelopes.jsonl](fixtures/synthetic/guardian-envelopes.jsonl) |
| `--host-events` | Selects `type: tool_use` in the host session; retains tool records as candidates. | [host-events.jsonl](fixtures/synthetic/host-events.jsonl) |
| `--proxy` | Selects `rpc_id` and `method`; retains reported proxy events. | [proxy.jsonl](fixtures/synthetic/proxy.jsonl) |

IDs must be nonempty strings of at most 256 characters without ASCII whitespace
or control characters. UTC text timestamps use `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`;
offset timestamps are not supported. Host tool intervals use integer Unix epoch
milliseconds. When a source is unavailable, use its explicit `--NAME-absent`
flag; do not create an empty placeholder file.

## Host audit

For a selected `rpc_id`, the reader requires `recorded_at`, `session_id`,
`posture`, `posture_source`, `outcome`, and `failure.kind`. All except the time
use the identifier-string rule above. A supported observation also has
`method: steps/toolCallRequest`, the selected host session and either
`proceed` / `proceeded` or `deny` / `blocked` as its posture/outcome pair.

```jsonl
{"recorded_at":"2026-01-01T00:00:05.000Z","rpc_id":"demo-request-main","method":"steps/toolCallRequest","session_id":"demo-host-session","posture":"proceed","posture_source":"negotiated","outcome":"proceeded","failure":{"kind":"timeout"}}
```

Other posture/outcome combinations remain `not_assessed`. More than one
selected host record is retained as ambiguity.

## Guardian envelopes

Every recognized row needs `recorded_at`, `direction`, `rpc_id`, `method` and
an `envelope` object. The envelope uses `jsonrpc: "2.0"` and an `id` equal to
the outer `rpc_id`. A request repeats the outer method in `envelope.method`;
its `params` contains the same `request_id`, a `timestamp`, a `metadata` object
with `session_id`, and a `payload` object.
Supported requests use `acs_version: "0.1.0"` in `params`.

An original tool-request and its final response can look like this:

```jsonl
{"recorded_at":"2026-01-01T00:00:08.000Z","direction":"request","rpc_id":"demo-request-main","method":"steps/toolCallRequest","envelope":{"jsonrpc":"2.0","id":"demo-request-main","method":"steps/toolCallRequest","params":{"acs_version":"0.1.0","request_id":"demo-request-main","timestamp":"2026-01-01T00:00:08.000Z","metadata":{"session_id":"demo-acs-session"},"payload":{"tool":{"name":"bash"},"raw_command":"printf DEMO_MAIN"}}}}
{"recorded_at":"2026-01-01T00:00:08.132Z","direction":"response","rpc_id":"demo-request-main","method":"steps/toolCallRequest","envelope":{"jsonrpc":"2.0","id":"demo-request-main","result":{"acs_version":"0.1.0","request_id":"demo-request-main","type":"final","decision":"deny","reason_codes":["DEMO_RULE_DENY"]}}}
```

A response envelope omits `method` and contains exactly one of `result` or
`error`, each an object. Tool-request and result-hook results repeat
`request_id`. Supported decisions have `acs_version: "0.1.0"`, `type: "final"`
and `decision: "allow"` or `"deny"`. An RPC error is retained without a decision.

| Exchange | Additional fields used |
| --- | --- |
| `steps/toolCallRequest` | Request `payload.tool.name`; optional string or null `payload.raw_command`. The response's optional `reason_codes` is an array of at most 64 identifier strings. |
| `steps/toolCallResult` | Request `payload.exit_status` is retained when `success` or `failure`. Each hook uses its own RPC ID; its response is associated with that hook. |
| `handshake/hello` | Request `acs_version` must be `0.1.0` for a supported observation. A supported response has `negotiated_version: "0.1.0"`, `on_decision_failure: "proceed"` or `"deny"`, and `timeout_config` containing only a positive integer `default_ms`. Hello responses do not need an inner `request_id`. |

Envelopes for recognized methods are checked before session selection. An invalid
envelope for another request in the same file is still an input error. Unknown
methods and extension fields do not establish action links or authenticate IDs.

## Host events

The reader selects rows with `type: "tool_use"` and the selected host `sessionID`.
Their `part` must have `type: "tool"`, the same `sessionID`, and identifier
strings for `callID` and `tool`. `state` needs an identifier-string `status`
and objects for `input`, `metadata` and `time`. The start and end times are
nonnegative integer epoch milliseconds, with end no earlier than start.
`input.command` is optional text; `metadata.exit` is an optional integer.
Either may be null.

```jsonl
{"type":"tool_use","sessionID":"demo-host-session","part":{"type":"tool","sessionID":"demo-host-session","callID":"demo-call-main","tool":"bash","state":{"status":"completed","input":{"command":"printf DEMO_MAIN"},"metadata":{"exit":0},"time":{"start":1767225600000,"end":1767225605200}}}}
```

This record is a host-reported candidate. Its `callID` is not treated as the
ACS request ID, and its interval start is not treated as dispatch time.

## Proxy events

The reader selects rows with the chosen `rpc_id` and
`method: "steps/toolCallRequest"`. It requires a UTC `t_wall` timestamp and an
identifier-string `event`. An optional `decision` is retained only when `allow`
or `deny`. Proxy events are observations, not evidence that the host applied a
response.

```jsonl
{"t_wall":"2026-01-01T00:00:08.132Z","event":"response","method":"steps/toolCallRequest","rpc_id":"demo-request-main","decision":"deny"}
```

If your logs use another shape, preserve those originals and document any
transformation separately. The report's source hashes identify exactly the
files supplied to this reader.
