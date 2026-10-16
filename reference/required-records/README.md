# Required Record Review

Find missing records within a receiver-selected set of operations or known
attempts. This Python API and JSON CLI start from the receiver's requirements,
so an operation omitted from the submission still appears in the report.
They distinguish an absent record from an unreadable, ambiguous or incompletely
collected candidate, and retain the complete receipt, S3 and optional signature
assessments alongside that finding.

The experimental contract is `vate-required-records-local-v2`. It covers VATE
receipts with the existing S3 action context, including explicitly identified
S3 attempts. It is an implementation aid alongside the existing specification;
it does not change the `VATE-AL2-Verifier-Admission-v0.3` semantic profile.

For persistent intake, late-arrival reassessment and retained history, use
[Recipient Inbox](../recipient-inbox/README.md). It prepares these same review
inputs from stored originals without inferring the required set or collection
closure.

## Try an omitted operation

Use a trusted checkout or source archive of the **whole repository**, Linux or
macOS, Python 3.10 or later, and the existing `jsonschema==4.26.0` dependency.
The [environment setup](../receipt-linkage-example/README.md#run-the-examples)
installs it in the interpreter's environment. Evaluation is offline.

From the repository root, choose a new report path:

```bash
.venv/bin/python -B reference/required-records/required_records.py \
  --selection reference/required-records/examples/operation-B-missing/selection.json \
  --base "inputs=$PWD/reference/required-records/examples/operation-B-missing" \
  --base "repository=$PWD" \
  --source-root "$PWD" \
  --output /tmp/vate-required-records.json
```

The saved example selects two required post-execution records and supplies only
A's receipt pair. Its report contains `A: present`, `B: missing`, and A's complete
receipt assessment. The required set, deadline and arrival information are
synthetic receiver decisions. The underlying receipts are unchanged archived
S3 inputs; this command does not perform a new S3 operation.

Exit 0 means a report was generated, including reports with missing records or
failed semantic checks. Exit 64 indicates an input, configuration, processing
limit or evaluator execution error. Read `invocation_errors`, each requirement
and the native results. Existing output files are never overwritten.

## Choose what must be present

For another review, the receiving application supplies three pinned JSON
documents under the [input contract](CONTRACT.md#receiver-inputs):

1. A **review set**: the required operation or known attempt, expected record
   kind, deadline, obligation and the receiver's basis for that requirement.
   Obtain this set independently of the received records.
2. A **submission snapshot**: the listed originals and their raw-byte
   references, receiver namespace, receipt events and collection state.
   `closed` applies only to the selected collection scope. Use `partial` or
   `unavailable` when that inventory is incomplete or unavailable.
3. A **selection**: the receiver's chosen review set, snapshot, cutoff and
   policies. The caller also selects allowed filesystem roots, evaluator
   sources and, when requested, the OpenSSL executable.

The receiver determines the requirement and collection assumptions. A hash
checks the selected bytes; it does not establish who selected them, whether an
obligation is legitimate, or whether a receipt time is independently proven.
An operation label and the optional candidate hints do not establish binding:
the checker compares the original's typed context with the selected subject.

For S3 attempt requirements, supply the complete existing 18-member bundle.
The additional attempt binding requires the selected native relationships and
the saved generator's explicit post-ID rule. Keep detached proofs outside that
bundle. A non-success outcome or missing response can leave an attempt
`unresolved` even when an operation-level receipt is `present`.
A post identifier outside the supported rule, including the saved later
observation suffix, also leaves the same explicit attempt `unresolved`.

## Interpret the result

| `record_coverage` | Meaning within the selected review |
| --- | --- |
| `present` | One distinct original binds to this requirement, with no unresolved competitor. |
| `missing` | No matching or potentially matching candidate remains, the inventory is closed and the cutoff is after the deadline. |
| `pending` | The same absence conditions hold, but the cutoff has not passed the deadline. |
| `unresolved` | Binding, uniqueness, inventory, obligation or processing is incomplete. |
| `waived_by_receiver` | The receiver selected a waiver and supplied its basis. |

`timeliness` separately describes the required record's receipt time. A record
received exactly at its deadline is on time. Unknown arrival times remain
unknown unless another receipt event proves an on-time arrival. `review_set_selection_timing` compares selection with the cutoff;
`before_or_at_cutoff` does not say the requirement was chosen before its due
date. All dates come from the selected input, not the machine clock.

`present` does not mean the signature, issuer authority or receipt contents
passed. Read the referenced full responses in `native_calls`. Static
`check_support` lists component capabilities, not completed checks. Unsupported
requests, source identities, errors and existing `not_checked` fields remain
visible. There is no aggregate pass or permission-to-execute value.

## Call from Python

The caller controls the module path and source tree. Keep selected inputs and
older results unchanged when producing a revised review.

```python
from pathlib import Path
import sys

root = Path("/path/to/VATE")
sys.path.insert(0, str(root / "reference/required-records"))
from required_records import Reviewer

inputs = root / "reference/required-records/examples/operation-B-missing"
reviewer = Reviewer(
    path_bases={"inputs": inputs, "repository": root},
    source_root=root,
)
report = reviewer.assess((inputs / "selection.json").read_bytes())
print(report["review_set_status"], report["invocation_errors"])
for row in report["requirements"]:
    print(row["requirement_id"], row["record_coverage"], row["timeliness"])
```

The [contract](CONTRACT.md#python-interface-and-limits) defines errors, limits,
reference resolution and source identification. `Reviewer.assess(None)` returns
a not-assessed report; it does not invent requirements from submitted receipts.

## Reproduce the ten controls

The optional signature controls use the existing P-256 / SHA-256 example.
Select an installed OpenSSL 3 or 4 executable and record its hash after checking
its source and version. On macOS the system LibreSSL is not a substitute. See
the [signature example](../recipient-signature-authority/README.md) for selection
and policy details. Its public test keys are unsuitable for real identities.

```bash
export VATE_TRIAL_OPENSSL=/absolute/path/to/openssl
"$VATE_TRIAL_OPENSSL" version
export VATE_TRIAL_OPENSSL_SHA256="$(
  .venv/bin/python -c 'import hashlib,os,pathlib; print(hashlib.sha256(pathlib.Path(os.environ["VATE_TRIAL_OPENSSL"]).read_bytes()).hexdigest())'
)"
.venv/bin/python -B reference/required-records/run_examples.py \
  --openssl "$VATE_TRIAL_OPENSSL" \
  --openssl-sha256 "$VATE_TRIAL_OPENSSL_SHA256" \
  --output /tmp/vate-required-record-controls
.venv/bin/python -B -m unittest discover \
  -s reference/required-records -p 'test_*.py' -v
```

Use a new output directory for each run. `SUMMARY.json` lists the ten controls,
their comparisons with [EXPECTATIONS.json](EXPECTATIONS.json), environment and
input/report hashes. Each control retains the selected originals and complete
report. Controls include unknown receipt times, incomplete inventories, late
S3 support, signature-policy failure, semantic aliases and one waiver revision.
Synthetic signatures can differ between runs; compare the expected findings
and keep each run's original bytes.

Keep the source tree and the source identities with a result when updating.
The checker pins the existing evaluator sources. A changed native source is a
diagnosed error, not an invitation to regenerate the pins automatically.
Its own source hashes identify the loaded implementation; updating these files
requires a fresh Python process. Source-validation errors remain visible even
when no native evaluation is needed. The caller must choose a trusted
distribution. The source archive runs without Git history.

## Scope and remaining limits

This review does not establish all activity, unknown attempts, independent
execution or timestamp evidence, business authority for requirements, or
permission to execute or retry. Collection governance and issuer/key selection
remain with the receiver. General JOSE/PKI verification is outside the existing
signature example. There is no production-readiness or endorsement claim.

The fixed S3 evaluator on Python 3.10 accepts whole seconds and exactly 3 or 6
fractional digits. Use Python 3.11 or later for S3 timestamps with other 1–6
digit fractions; preserve received bytes. Receiver metadata and receipt-pair
assessment accept 1–6 fractional digits on the supported interpreters.
