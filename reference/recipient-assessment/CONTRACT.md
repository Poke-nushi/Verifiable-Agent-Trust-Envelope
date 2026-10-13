# Local recipient API contract

Identifier: `vate-recipient-assessment-api-v1`. This is the calling and reporting
contract of the local reference API. Existing VATE receipt schemas, digest rules,
reason codes and `vate-local-s3-observation-v1` retain their meanings.

## Calls and original inputs

`RecipientAssessor` requires `expected_api_contract`. Its optional `source_root`
selects a trusted repository tree or source archive; the default is the tree
containing this API. `timeout_seconds` bounds each worker invocation and defaults
to 30 seconds. It must be a positive finite number within the running platform's
supported timeout range. It is not a deadline for the operation described by a
receipt.

| Call | Inputs | Native evaluator |
| --- | --- | --- |
| `assess_receipts(admission, post, requested_checks=())` | Each original is `bytes` or `None`. Empty bytes are supplied invalid input, not an absent original. | `RecipientExample.assess` |
| `assess_s3(bundle, receiver_policy, requested_checks=())` | A local bundle path and receiver-selected policy bytes. | S3 `assess`, after the existing policy decoder |
| `capabilities()` | None | Static supported and unsupported check names for each evaluator |

The API passes receipt bytes without normalizing or reserializing them. Receipt
and S3 parsing retain their distinct numeric rules. Receiver policy bytes are
decoded using the existing S3 decoder. Malformed policy JSON is an API input
error; a decoded policy whose contract or trust conditions are unsuitable is
evaluated under the native S3 rules.

Each receipt is limited to 1 MiB and the policy to 256 KiB before worker
serialization. Exceeding a limit raises `INPUT_SIZE_ERROR` without invoking the
native evaluator. The S3 bundle retains its native per-file and aggregate limits.

`None` means an original was not supplied. It never establishes that execution
did not occur. Input references are read locally; the evaluators do not fetch
referenced URLs or execute the operation.

The receiver is responsible for selecting its policy independently of a
producer's evidence. Supplying policy through a separate API argument does not
by itself establish independent provenance or a trusted issuer.
The file-oriented CLI requires the resolved policy path to be outside the
resolved bundle directory. The bytes API cannot establish where policy bytes
originated; the receiver's selection responsibility applies to both interfaces.

## Response fields

| Field | Meaning |
| --- | --- |
| `api_contract` | The local response contract. Callers must request a supported contract explicitly. |
| `wrapper.version`, `wrapper.source_files` | Wrapper implementation version and raw source hashes. |
| `evaluator.id`, `evaluator.source_files` | Selected native evaluator and the pinned local source closure it uses. |
| `invocation.status` | `returned` means the native call returned. It is not an evidence verdict. |
| `requested_checks` | The caller's requested names, separated into supported and unsupported capabilities. |
| `inputs` | Identity of the receipt and policy bytes passed, plus the selected S3 bundle path where applicable. |
| `native_result` | The complete native result without renamed fields, reordered reasons or a combined success classification. |

Raw hashes and lengths for receipt/policy inputs describe the bytes actually
passed to the worker. The S3 bundle path identifies a selection, not an immutable
snapshot. The native bundle reader performs its existing bounded inventory and
digest checks. The wrapper does not separately reread files and claim those
hashes identify every byte evaluated.

`linkage_checks_run` reports native receipt check groups invoked, including
conditional checks. It is not a record that every possible branch ran. The S3
evaluator does not expose a full per-check execution trace; its stage values
remain native reported states. Neither a field's presence nor `not_assessed`
is converted into an execution claim.

## Requested checks

| Name | `receipt_pair` | `s3_observation` |
| --- | --- | --- |
| `receipt_linkage` | Supported under existing receipt input and constraint rules | Supported through the same receipt evaluator |
| `s3_observation_binding` | Unsupported | Supported within the local S3 contract |
| `signatures_and_issuer_authority` | Unsupported | Unsupported |
| `independent_execution_observation` | Unsupported | Unsupported |
| `operation_population_coverage` | Unsupported | Unsupported |
| `current_permission_to_execute` | Unsupported | Unsupported |

Supported describes evaluator capability, not evidence acceptance or execution
of every conditional check. The requested names do not select or skip native
checks: an empty list and a partial list both run the complete native assessment.
Requested unsupported checks remain explicit even
when native output reports a match. Unknown names are errors. There is no
`requirements_satisfied` or equivalent acceptance flag.

## Errors and CLI status

`AssessmentError` has `code`, `detail` and `as_dict()`. Its JSON form contains
`api_contract`, `invocation.status: error` and `error`; it has no `native_result`.
An unavailable evaluator, source drift, invalid API request or worker timeout is
an invocation/configuration error, not a native mismatch or an execution failure.

Branch on `code`; `detail` is diagnostic text and is not a stable string contract.

| Code | Condition |
| --- | --- |
| `UNKNOWN_API_CONTRACT` | The requested API contract is not supported. |
| `INVALID_CONFIGURATION` | The source-root configuration or worker timeout is invalid, CLI policy/bundle path resolution fails, or the policy path resolves inside the bundle. |
| `INPUT_TYPE_ERROR` | Receipt/policy bytes, bundle path or requested-check collection has the wrong type. |
| `INPUT_SIZE_ERROR` | A receipt or policy exceeds its input limit. |
| `INPUT_FILE_ERROR` | A CLI input cannot be read as a regular local file. |
| `INVALID_CHECK_REQUEST` | A requested check name is duplicated. |
| `UNKNOWN_CHECK` | A requested check name is not in the capability inventory. |
| `POLICY_INVALID` | Policy bytes fail the native S3 decoder or do not form an object. |
| `SOURCE_MANIFEST_ERROR` | The fixed evaluator manifest cannot be read or differs from its pin. |
| `SOURCE_UNAVAILABLE` | A required native source cannot be read or its path contains a symlink. |
| `SOURCE_MISMATCH` | A native source differs from its fixed hash. |
| `WRAPPER_SOURCE_UNAVAILABLE` | Wrapper source files cannot be read during an identity check. |
| `WRAPPER_SOURCE_CHANGED` | Wrapper source files changed after the API was imported. |
| `WRAPPER_CODE_MISMATCH` | Loaded API code differs from its source, including stale bytecode, or the source cannot be compiled. |
| `WORKER_START_FAILED` | The local worker cannot be started. |
| `WORKER_TIMEOUT` | The worker exceeds the configured timeout. |
| `WORKER_FAILED` | The worker exits unsuccessfully without a valid API response. |
| `WORKER_PROTOCOL_ERROR` | The private worker response has an invalid format or evaluator identity. |
| `EVALUATOR_UNAVAILABLE` | A native evaluator or its installed dependency cannot be imported. |
| `EVALUATOR_ERROR` | A native invocation raises an unexpected exception. |
| `CLI_USAGE_ERROR` | Required CLI arguments are missing or invalid. |

Put `--api-contract`, optional `--source-root` and `--timeout` before the CLI
subcommand. Evaluation subcommands accept repeatable `--check` arguments.
The CLI prints one JSON response to stdout, except that `--help` prints usage
text and exits 0.

| Exit | Meaning |
| --- | --- |
| 0 | Receipt `matched` or S3 `supported_under_local_assumptions`, with no unsupported requested check |
| 1 | Receipt `mismatch` or S3 `contradictory` |
| 2 | Receipt `not_assessed` or S3 `insufficient` |
| 3 | S3 native `unsupported` |
| 4 | At least one requested check is unsupported; inspect the retained native result separately |
| 64 | API, input, configuration or invocation error |

For a returned assessment, exit 4 takes precedence over exits 0 through 3 when
any requested check is unsupported. The native result remains in the response.

`capabilities` exits 0 when its description is returned. A zero exit never grants
execution or retry permission. A returned assessment is still available on the
nonzero native-verdict exits.

## Compatibility and source identity

The API contract fixes the meaning of these fields and the two calling paths.
An incompatible field, input or meaning change requires a new API contract.
An implementation update may retain this contract only while preserving those
promises. Unknown contracts are rejected before native evaluation.

The API checks its native source pins before and after evaluation. It does not
regenerate expected hashes to accept a changed source. API contract equality does
not establish equal evaluator bytes, equal evidence, or trust in the code supplier.
Deploy trusted local code where evidence producers cannot modify it, and retain
the source identity with its assessment.

Source hashes are local identification data, not signed attestation that those
bytes executed. The checks before and after evaluation are not an atomic
snapshot against concurrent replacement. Interpreter and installed dependency
versions are outside `source_files` identity.

Replacing wrapper files after import causes `WRAPPER_SOURCE_CHANGED`. Start a
fresh process or import the new installation in a fresh context when updating;
an already loaded API must not report newer on-disk bytes as its own identity.
If a fresh import loads stale bytecode instead of matching source code, the API
rejects it with `WRAPPER_CODE_MISMATCH`; restore a consistent installation before
retrying.

Existing S3 captures still require equality among receiver-policy source hashes,
captured source hashes and the installed native sources. Updating the wrapper
does not rewrite those captures or their old assessments. Updating a native
evaluator requires a separately reviewed compatibility/provenance decision;
changing a version label or resealing a manifest is not that decision.

The vector index preserves raw input identity and ordered semantic expectations.
Use it with application-specific controls when checking an update.
