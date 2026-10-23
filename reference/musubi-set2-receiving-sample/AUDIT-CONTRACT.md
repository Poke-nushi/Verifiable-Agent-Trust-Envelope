# A/C audit and dataset receiving extension

This opt-in example connects published audit bytes to a selected MUSUBI
execution receipt, then connects dataset bytes to the audit's declared digest.
It retains both the earlier assessment and the additional assessment in the
same Inbox. The base VATE schema, digest rules and upstream evaluator are unchanged.

## Selection and prerequisites

The selection opts in with
`audit_binding_profile: horizon-estimate-audit-dataset-linkage-1`.
Without this field, the base contract's behavior is unchanged. An unknown profile
is an input error.

An `audit_original` requirement names an `execution_requirement`. A
`dataset_original` names an `audit_requirement`. Each prerequisite must exist,
be required, have the expected kind, and name the same selected occurrence.
An audit is processed before its dataset regardless of requirement order.
The base requirement must pass its own request/item/bundle/log identity checks.
The selected files must be in the verified acquisition manifest.

Each supported audit must match the selected receipt's
`outcome.response_sha256` as raw bytes. That outcome must have `kind: result`
and `stage: audited`. The bounded reader supports
`type: horizon-shield.estimate-audit.v0`, with 1–256 object lines. Every line
must declare a lowercase SHA-256 `dataset_sha256`, and this profile requires
all lines to name the same dataset digest. A selected dataset is checked as raw
bytes against that digest; its contents are not interpreted by this extension.

Japanese audit/dataset text stays in the original bytes. It is not reserialized
or fed through the base adapter's ASCII-only object digest function. Existing
input file/count/byte bounds and duplicate JSON key/float rejection apply.

## Assessment states

The base states remain. This profile adds `unresolved`: a supplied audit or
dataset has a selected prerequisite that is missing, ambiguous, contradictory
or unsupported. The input is retained without promoting its binding status.

| Observation | Binding | Meaning |
| --- | --- | --- |
| Required original has no candidate | `not_received` | No selected original |
| More than one candidate | `ambiguous` | No automatic choice |
| Original is optional | `not_selected` | Outside the selected question |
| Named prerequisite is not bound | `unresolved` | Cannot establish this dependent link |
| Raw digest differs; known audit shape is malformed | `contradictory` | Selected evidence fails the named check |
| Unknown audit type; more than one dataset digest | `unsupported` | Retained, outside this reader's interpretation |
| Supported raw digests and prerequisite links match | `bound` | Published byte linkage established |

`semantic_assessment: digest_linkage_checked` additionally requires the selected
execution to have exactly one attached row from a successful native evaluation.
Native refusal, evaluator failure or missing/ambiguous native rows leave these
records `unassessed`, even if their byte linkage is `bound`.
The field records a digest linkage check, not audit-quality assessment.
The result retains the upstream delegation, budget and acceptance fields in
their original form. `claim_scope: published_digest_linkage_only` applies.

A dataset digest in an audit is the audit author's declaration. Matching it
does not independently show that the dataset was used in an actual execution,
that its prices or contents are correct, or that the work was formally accepted.
These questions require their own evidence and authority rules.

## Fixed example and provenance

`sample/audit-manifest.json` includes the original 68 source files and two
supplementary files. Each row names its source commit. `sample/audit-sources.json`
records immutable source URLs, raw SHA-256, byte length and Git blob ID for the
two additions. The audit and dataset come from different commits; the manifest
does not relabel them as a single upstream snapshot.

The A and C receipts reference the same audit raw hash. Both occurrences have
separate selected execution prerequisites, request hashes and linkage records.
The dataset is likewise stored once by content while its selected links remain
separate. This is valid shared content, not a reason to interchange receipts.

The new selection explicitly selects C's audit, previously optional, and adds
three dataset requirements. `changed_selection` preserves the full change.
The baseline has 21 requirements (9 bound, 10 missing, 2 optional); the audit
selection has 24 (13 bound, 10 missing, 1 optional). These totals concern
different selected sets and are not a percentage-completion comparison.

B's audit and dataset remain missing. The sample does not infer formal
acceptance, rail originals or an unspecified raw-transport response from this
audit object. C's formal acceptance remains outside the selected question;
the native `accepted: null` remains visible for all three occurrences.
The overall evidence state stays `partial`.

## Local execution

Follow [Prepare](README.md#prepare) to create a runtime, or use an existing
prepared runtime that passes the base sample's environment and source checks.
Run from this sample directory, with absolute paths and a new
output directory outside both the sample and the runtime:

```bash
"/absolute/prepared/environment/venv/bin/python" -B run_audit_example.py \
  --vate-root "/absolute/VATE/checkout" \
  --environment "/absolute/prepared/environment" \
  --output "/absolute/new/audit-example-output"
```

This starts a fresh two-step example: fixed baseline, then additional originals.
It does not modify an earlier experiment database or claim the sources arrived
late from an external sender. Existing installations need no new packages.
Native replay still requires macOS sandbox-exec and has no network access.

The output includes `baseline/`, `audits/`, `inbox.sqlite` and
`AUDIT-EXAMPLE.json`. The new export retains the old assessment and can restore
the additional raw files. Inspect `audits/assessment.json` for individual links,
unchanged native judgments and changed selection. Saved output recovery uses
the base contract's `recover_output.py` command and recovery receipt. It restores
one completed assessment, without repeating evaluation or updating history.

`verify_audits.py` tests linkage and optionally actual native/storage integration.
Its explicit `--portable` test mode substitutes saved native output and uses a
marked test runtime. Portable tests establish adapter/storage behavior, not
native signature verification or Linux support for the macOS replay sandbox.
The [verification record](../../docs/interop/horizon51-set2-audit-receiving/README.md)
contains the observed results and source references.
