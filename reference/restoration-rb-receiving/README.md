# VATE Restoration RB receiving example

Read a Revocation Boundary (RB) Statement, compare its declared target with
receiver-selected values, and check an optional local observation against its
counts. Preserve the original inputs and each reading for later inspection.

The reader covers the RB record rules of
[Restoration Evidence -00 §5.5](https://www.ietf.org/archive/id/draft-gilda-audit-restoration-evidence-00.txt).
It reports record consistency, receiver binding, plan binding and observation
consistency separately. Signature verification, issuer authority, evidence
sufficiency for a receiver's decision, and permission to resume remain
`not_assessed`. This is an experimental technical example, not a production
verifier or a general compatibility result.

The comparison is pinned to `probityai/agent-evidence-vectors` commit
`1177028f6276f439768ab7d02fb734054832612c` (`v0.31.2`).
[SOURCE-PINS.json](SOURCE-PINS.json) records the source URLs and raw-file hashes;
[CONTRACT.md](CONTRACT.md#sources-and-rule-interpretation) describes the selected
rules and local interpretation. The examples below generate their own inputs.

## Run three examples

Use Python 3.11–3.14 on macOS or Linux. The reader and synthetic examples use
only the Python standard library. Commands below start at the VATE repository
root. Choose a fresh work directory:

```sh
rb_work_dir="$(mktemp -d "${TMPDIR:-/tmp}/vate-rb.XXXXXX")"
```

```sh
python3 -E -s -B reference/restoration-rb-receiving/run_examples.py --out "$rb_work_dir/examples"
```

The generated directories contain self-authored synthetic Statements, receiver
selections, test plans, observations, reports and raw-file manifests.

| Example | Declared RB result | Observation check |
| --- | --- | --- |
| `no_commit` | No post-revocation commit observed | Consistent under local assumptions |
| `commit_observed` | Post-revocation commit observed | Consistent under local assumptions |
| `not_established` | Not established | Incomplete observation; derived counts remain null |

All three have internally consistent RB records. A `passed` record check does
not mean that work stopped. Inspect the declared result and the separate checks.

## Read selected originals

```sh
python3 -E -s -B reference/restoration-rb-receiving/rb_receiving.py \
  --statement "$rb_work_dir/examples/commit_observed/statement.json" \
  --selection "$rb_work_dir/examples/commit_observed/selection.json" \
  --test-plan "$rb_work_dir/examples/commit_observed/test_plan.json" \
  --observation "$rb_work_dir/examples/commit_observed/observation.json" \
  --out "$rb_work_dir/reading"
```

For another producer's record, choose the expected incident, producer, sink,
observer, credential, clock, revocation time, window and plan digest yourself.
The generated selection is an example, not a way to trust a sender's choices.
Exact identity matches compare declarations; they do not authenticate them.

For your own Statement, create a selection file using the Receiver selection
section in [CONTRACT.md](CONTRACT.md#receiver-selection). Start with only
`--statement`, `--selection` and a new `--out` directory. Add `--test-plan` and
`--observation` when you have matching inputs in the local formats described
in that contract.

`--test-plan` and `--observation` are optional. Their absence remains explicit in
the report. The output directory must be new. It retains input bytes unchanged,
`report.json` and a `MANIFEST.json` of raw SHA-256 identities. Another reading goes
to another directory. CLI exit 0 means the report was written, including reports
of invalid or incomplete records. Exit 2 means missing or invalid command-line
arguments; exit 64 means an input/configuration/I/O error.

The JSON output is also available through `assess(statement_bytes,
selection_bytes, test_plan=..., observation=...)`. The reader does no network
fetches.

## Capture the file boundary

This uses the existing VATE runtime-key revocation sample to create real local
files with disposable test keys and its fixed synthetic clock. It requires
OpenSSL on PATH and the complete VATE source tree.

```sh
python3 -E -s -B reference/restoration-rb-receiving/run_capture.py --out "$rb_work_dir/capture"
```

The declared boundary is the successful return of `fsync` for `first.txt`.
One initial task writes two files; it counts as one attempt. Revocation before
acceptance leaves zero files. Revocation after acceptance allows two files,
with the first file's boundary observed after revocation. The third case keeps
the complete capture separately but supplies a deliberately partial observation
to the reader. Its unknown result stays unknown rather than substituting zero.
Each capture requires one stored revocation at the selected time and the
expected submission outcome. A failed revocation injection stops the capture
before that case's RB report is written.

`CAPTURE.json` links the controlled trace, selected opaque credential alias and
existing VATE evidence. The existing sample's reader checks its own evidence.
The RB reader checks the supplied observation assertions; it does not replay
those signatures or independently read the provider's files. The selected
boundary does not establish directory-entry durability, cancellation after
acceptance or independent timestamps.

Attempt start and finish are measured immediately around submission, before
advancing the clock for the later query. A `closed` capture accounts for the
finite set of attempts issued by this harness. It does not claim continuous
observation of every possible operation throughout the declared window.

## Retain successive readings in Recipient Inbox

Use the existing VATE environment with `jsonschema` available. The example
first reads a Statement without the
observation, then reads the same Statement with the observation and retains
both reports and original inputs.

```sh
.venv/bin/python -E -s -B reference/restoration-rb-receiving/run_examples.py \
  --with-inbox --out "$rb_work_dir/inbox-example"
```

The Inbox example uses an empty required-record set to exercise storage,
history and export. RB entries remain opaque to Required Records; this command
does not register a native RB requirement or turn an RB into a VATE admission
or post-execution receipt.

## Run tests

```sh
python3 -E -s -B reference/restoration-rb-receiving/test_rb_receiving.py
```

```sh
python3 -E -s -B -O reference/restoration-rb-receiving/test_rb_receiving.py
```

Capture regression tests also require OpenSSL and the VATE source tree:

```sh
python3 -E -s -B reference/restoration-rb-receiving/test_capture.py
```

```sh
python3 -E -s -B -O reference/restoration-rb-receiving/test_capture.py
```

The `Restoration RB receiving` workflow runs these tests on Python 3.11 and
3.14. It also runs the reader and synthetic examples from a copied folder,
and capture and Inbox examples from a Git source archive.

See [CONTRACT.md](CONTRACT.md) for input fields, interpretation choices, local
observation semantics and the meaning of each report field. The standalone
reader, synthetic examples and reader tests can be copied together with
[LICENSE](LICENSE). Capture and Inbox paths require the selected VATE source
tree; `--source-root` selects it when running from a copied folder.
