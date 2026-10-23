# Audit extension validation

Validation performed on 2026-10-23, with the parser correction and checks below
completed on 2026-10-24. Additional original hashes and immutable URLs are in
`sample/audit-sources.json`. This record concerns the opt-in audit profile and
the receiver's native-output error handling.

## Runtime checks

| Environment | Completed checks |
| --- | --- |
| macOS arm64, Python 3.11.14 / 3.13.3 / 3.14.8 | 21 audit unit cases and 27 binding/native-output cases per runtime |
| macOS arm64, Python 3.14.8 | Five integration scenarios using the actual sandboxed native evaluator, including the final audit-reader code in the public sample layout |
| macOS arm64, Python 3.11.14 / 3.13.3 / 3.14.8 | CLI suite: 18 cases; output-recovery suite: 37 cases; five audit/storage scenarios using a marked saved-output test double |
| Linux x86_64, Python 3.12.15 / 3.14.8 | 21 audit unit cases, 27 binding/native-output cases, five actual Inbox/storage scenarios and two focused native-output retention/recovery cases per runtime; native replay replaced by explicitly marked test doubles |

All listed checks passed. The final audit-reader code was exercised with the
actual native evaluator on macOS / Python 3.14.8. The common portable CI entry
point also passed from a Git-free source copy on each listed macOS Python,
including all existing CLI/recovery cases and the added audit/storage cases.
Its saved-output test double does not execute native signature verification.

Linux checks used
Linux 6.8.0-117-generic with glibc 2.36, running through x86_64 emulation.
Containers had no network, ran as a non-root user, and received read-only
source inputs and hash-checked dependencies from the existing locks.

## Observed behavior

- The two-step example retained the baseline assessment and its selected
  requirements, recorded the changed selection, and restored both new
  originals from the additional assessment's export.
- A valid signed receipt from C could not satisfy A's selected prerequisite.
  Real native shallow-anchor refusal remained unassessed. Successful macOS
  native runs preserved the expected upstream stdout byte for byte.
- After an injected export failure, recovery restored the saved assessment
  and its originals without reevaluation or database-byte changes.
- Each Linux lane performed real Inbox storage, history, export and recovery
  operations. The native evaluator ran zero times there. The five exports per
  lane were checked again after copying them to macOS: all 909 retained files
  matched their declared lengths and SHA-256 hashes.
- B's audit and dataset remained missing, and formal acceptance remained
  `null`. The complete assessment remained `partial`.

## Native-output parsing and recovery

An evaluator output containing a 5,000-digit JSON integer exceeded Python's
configured 4,300-digit parsing limit. Before the correction, its `ValueError`
escaped before the assessment was saved. The receiver now records it as
`recorded_evaluator_error`, retains the original stdout bytes, and leaves the
semantic assessment unassessed. The receiving CLI returns exit code 64.

The regression checks cover both a small JSON object and an otherwise valid
settlement with the oversized integer in an extra field. The base and audit
selections retain their 9 and 13 bound records, respectively, with one completed
Inbox run each. Recovery restores the same assessment and stdout without
reevaluation or database-byte changes. Its CLI reports `output_recovered` while
preserving the saved evaluator-error status and exit code 64.

These outputs are synthetic fault injections, not observed failures of the
pinned upstream evaluator. Normal success and refusal checks still pass, and
the actual macOS native run retains the expected stdout SHA-256.

## Independent review and repository checks

An additional coding-agent review ran 13 probes and the final 21 audit unit
cases. All passed. These included a 5,000-digit JSON integer retained as an
invalid audit instead of aborting the assessment, separate request links for
shared bytes, and saved-output recovery with history preserved. Its storage
probes used a marked native-output test double and did not execute native
signature verification.

The parser correction received a separate follow-up review. Seven related
checks and two independent Inbox/recovery probes passed on Python 3.11.14,
including reproduction against the pre-correction receiver. Native execution
and the runtime matrix were verified separately as listed above.

The repository's required script compilation, repository check, strict
schema check, corpus run, example comparison with implementation report,
and report-bundle integrity check all passed. The VATE core, schemas, corpus,
base originals and upstream evaluator remain unchanged.

## Limits

Earlier broad Linux reruns of all 18 existing CLI and 35 existing recovery cases
were stopped because execution in the emulated environment was slow. They
are incomplete, not passing runs. The completed Linux lanes cover the added
audit behavior, binding/native-output cases, five storage scenarios and two
focused retention/recovery cases listed above. The full CLI and now-37-case
recovery suites were not repeated on Linux in this follow-up. Actual native
evaluator execution on Linux was not tested.

Windows, Intel macOS, process/power-loss recovery, database repair, and
independent third-party operation were not tested here. Matching published
audit and dataset bytes does not establish actual runtime dataset use or
the correctness of the audit contents.

No third-party independent use, live experiment, new signature, formal
acceptance or audit-quality judgment is established by these local checks.
