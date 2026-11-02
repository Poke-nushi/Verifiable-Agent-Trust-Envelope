# ACS Log Reader

Read saved ACS 0.1.0 captures while keeping the host's effective decision
separate from the Guardian's answer. The report preserves file and line hashes,
result-hook responses, and unresolved links to execution records. An optional
[Recipient Inbox](../recipient-inbox/README.md) example retains the originals
and successive readings when more logs arrive.

The reader runs offline with Python 3.10 or later on Linux or macOS. It uses
only the standard library. Copy this entire folder to run the reader and its
tests independently of a VATE checkout.

## Try the synthetic capture

From this folder, run:

```bash
python3 -B acs_reader.py \
  --selection selection.example.json \
  --host-audit fixtures/synthetic/host-audit.jsonl \
  --guardian-envelopes fixtures/synthetic/guardian-envelopes.jsonl \
  --host-events fixtures/synthetic/host-events.jsonl \
  --proxy fixtures/synthetic/proxy.jsonl
```

The JSON output matches [example-report.json](example-report.json). The input
files contain invented test data, including IDs, times, commands and outcomes;
they were not emitted by a running host or Guardian.

| Report field | Reading of this example |
| --- | --- |
| `host_effective_decision` | Host reports a timeout followed by negotiated `proceed` / `proceeded`. |
| `guardian_decision` | Guardian reports `deny` for the original request. |
| `result_hook_observations` | Result notifications have separate IDs and their own `allow` responses. |
| `bindings.request_to_result` and `bindings.request_to_execution` | `unresolved`: the capture has no supported action reference. |
| `timing` | Guardian response is recorded 3.132 seconds after the host fallback; host arrival, commitment and dispatch times remain unknown. |

A result-hook `allow` never replaces the original request's decision. A late
Guardian decision never overwrites the recorded host decision.

## Read your capture

Create a selection file containing the request ID and both session IDs from
your capture. Host and ACS sessions may use different identifiers:

```json
{
  "profile": "vate-local-acs-log-reader-v1",
  "request_id": "your-request-rpc-id",
  "acs_session_id": "your-acs-session-id",
  "host_session_id": "your-host-session-id"
}
```

Pass that file and your four JSONL paths using the same CLI options as above.
Use `--guardian-envelopes-absent`, for example, instead of the corresponding
path option when that input has not been received. An unreadable or empty file
is an input error, not an absent source.

Check [INPUT-FORMATS.md](INPUT-FORMATS.md) for the required fields and examples
of each JSONL shape. These are specific capture formats, not every ACS message
or host logging format. Use a new selection for a new
request. Reused IDs and multiple candidate records remain visible as ambiguity.

To reproduce the reading of AngeYobo's published ACS #435 capture, follow
[PUBLISHED-CAPTURE.md](PUBLISHED-CAPTURE.md). It provides fixed source links,
raw hashes and a local replay command. The upstream logs and scripts are not
included in this folder.

### Include command start and end stamps

If the command records its own start and end timestamps in separate files,
pass them with `--command-start` and `--command-end`. For the synthetic example:

```bash
python3 -B acs_reader.py \
  --selection selection.example.json \
  --host-audit fixtures/synthetic/host-audit.jsonl \
  --guardian-envelopes fixtures/synthetic/guardian-envelopes.jsonl \
  --host-events fixtures/synthetic/host-events.jsonl \
  --proxy fixtures/synthetic/proxy.jsonl \
  --command-start fixtures/synthetic/command-start.txt \
  --command-end fixtures/synthetic/command-end.txt
```

The report retains each timestamp and its source hash and compares the supplied
times with the host fallback and Guardian response. It preserves up to nine
fractional digits; `delta_nanoseconds` values are decimal strings. Use
`--command-end-absent`, for example, if only the start file has arrived.
Omitting both timestamp options keeps the original report unchanged.

Command stamps remain separate from the host's exact dispatch or
decision-commitment time. The files alone do not establish that the stamps
describe one execution or link it to an approval. See the
[input format](INPUT-FORMATS.md#command-self-timestamps-optional) and
[time contract](CONTRACT.md#optional-command-self-timestamps).

## Keep originals and both readings

This optional storage example requires the **whole VATE checkout or source
archive** and its existing `jsonschema==4.26.0` validation dependency. Use the
[repository environment setup](../receipt-linkage-example/README.md#run-the-examples).
From the repository root, choose a new output directory:

```bash
.venv/bin/python -B reference/acs-log-reader/run_example.py \
  --out /tmp/vate-acs-inbox
```

The example reads the bundled synthetic host logs first, then adds the Guardian
and proxy logs. The output contains `reader-report-1.json`, `reader-report-2.json`,
both storage reports, `SUMMARY.json` and `inbox-export/`. Originals and derived
reports are separate entries, and the first reading remains available. Source
timestamps are not substituted for receiver arrival times.

ACS interpretation is in the separate reader reports. The storage reports use
an empty required-record review set (`selected_empty`, zero native calls), so
they describe storage and history rather than a native ACS assessment. When
this folder is copied elsewhere, pass `--source-root` with the path to the
trusted whole VATE tree.

## Tests

From this folder:

```bash
python3 -S -B -m unittest discover -s . -p 'test_*.py' -v
```

Tests use the self-authored fixture and local mutations. They cover missing
inputs, malformed JSON, conflicting/reused IDs, incorrect direction/method
labels, numeric bounds, file handling, output identity and command comparison.
They also cover optional timestamp precision, missing and invalid stamps,
reversed reported order, source hashes and unchanged four-log reports.
They require no network access or host/Guardian process.

## Interpret the result

Exit 0 means that the reader generated a report, including unavailable,
ambiguous or unassessed cases. Exit 64 means invalid input; 70 means an
unexpected internal error. Read the individual report fields, not the exit
code alone.

Observation groups such as `host_effective_decision` and `guardian_decision`
use these statuses:

| Status | Meaning |
| --- | --- |
| `observed` | One supported record is present in this group. |
| `unavailable` | The corresponding source was explicitly marked absent. |
| `not_observed` | The source was supplied, but no record for this group was found. |
| `not_assessed` | One candidate record is present, but it does not meet this reader's supported conditions. |
| `ambiguous` | Multiple candidate records are present, or RPC ID reuse makes a result-hook response association ambiguous. |

For associations, `unresolved` means that the corresponding relationship has
not been established. A group can be `observed` while its association with
another record remains `unresolved`.

This experimental interoperability review aid does not authenticate log
issuers or signatures, establish complete collection or actual effects, or
grant execution or retry permission. It does not establish ACS conformance
or production readiness. See [CONTRACT.md](CONTRACT.md) for the exact field,
identity and time rules, and [NOTICE](NOTICE) for sources and licensing.
