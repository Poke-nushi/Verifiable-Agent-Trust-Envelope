# Pulse external SUT bounded-attempt starter

This directory is a public-candidate starter for the solicited reciprocal
VATE-to-Pulse external SUT attempt. It is not an adapter, a completed run,
organic adoption, a formal audit, endorsement, certification, production
approval, or a general compatibility claim.

The reciprocal work has two independent caps: VATE-to-Pulse is at most one
business day, and Pulse-to-VATE is separately at most one business day. Both
clocks start only after an immutable starter publication, not from local
preparation. Either side may stop with a recorded partial result or blocker.
Neither attempt validates or endorses the other project. A bounded Pulse note
does not complete Pulse Issue #18, and a VATE comparison result is not a Pulse
security review. `manifest.json` records these boundaries as exact booleans
and enums; they are not inferred from prose polarity.

The attempt is fixed to:

- VATE source commit
  `5a37f87de0190da44e619b1800261637e83dd7ed`
- VATE corpus `conformance/al2-vate-v0.3`, with 75 cases, 212 manifest
  artifacts, and digest
  `988aae7d03dd5bb743e8e03e6ab1120ce8735a4837ac818ffd9d665de0c1e370`
- Pulse verifier commit
  `e06a6cbfe3ddb965c8fc70f50838f5014ec2038e`
- exactly these VATE cases:
  - `allow-ap2-hnp-preauthorized-mandate`
  - `attenuate-ap2-hnp-amount-overrun`
  - `deny-ap2-hnp-stale-mandate`

An attempt window does not start from this unexecuted local template. If this
starter is later published, the invitation must identify an immutable commit
containing this directory. That publication event starts both separately
capped clocks.

## Files and evidence roles

- `manifest.json` records both exact pins, the Pulse source files reviewed at
  that pin, every selected VATE case/artifact path and raw SHA-256, each
  four-file case-closure digest, the 12-entry selected-set digest, the
  structured claim/timebox/candidate-execution contracts, and the fixed Pulse
  input closure: 142 primitive leaves plus 42 containers.
- `mapping-worksheet.template.json` is a candidate-owned mapping and
  scaffolding worksheet. It records source JSON Pointers, transforms, Pulse
  destinations, dependencies, provenance, ownership, open decisions, and all
  142 required Pulse input leaves individually. JOSE/SD-JWT, Payment Receipt,
  public-JWK, x402, and EIP-3009 leaves are not represented only as families.
- `pulse-sut-result.template.json` is a schema-valid, deliberately unexecuted
  result/run-record template. Its three selected-case sentinels are
  `skipped`/`unmapped`; it contains no copied expected result or checks. A
  completed, partial, or blocked copy must add the other 72 corpus cases as
  explicit `skipped`/`out-of-scope` entries.
- `scripts/check_pulse_external_sut_starter.py` is the standard-library,
  fail-closed validator in the repository root. It verifies source bytes from
  the fixed VATE Git object, not from the current checkout.

The VATE admission receipts listed in `manifest.json` are comparison-only
artifacts. Their result-record references prove only which fixed VATE fixture
the VATE comparison uses. They are not SUT output. They must not be read by the
mapper, copied into Pulse input, or used to choose a Pulse or VATE result.

## Checkout model

Use distinct locations for the published starter, fixed VATE source, frozen
Pulse verifier, candidate-owned mapper, and run output:

```bash
export VATE_KIT_REPO=/absolute/path/to/vate-checkout-containing-this-starter
export VATE_SOURCE_REPO=/absolute/path/to/vate-checkout-at-5a37f87de0190da44e619b1800261637e83dd7ed
export PULSE_REPO=/absolute/path/to/pulse-checkout-at-e06a6cbfe3ddb965c8fc70f50838f5014ec2038e
export PULSE_MAPPING_REPO=/absolute/path/to/candidate-controlled-mapping-checkout
export CANDIDATE_PYTHON_RUNTIME=/absolute/operator-selected/path/to/python3
export CANDIDATE_NODE_RUNTIME=/absolute/operator-selected/path/to/node
export RUN_DIR=/absolute/path/to/candidate-controlled-run-directory
mkdir -p "$RUN_DIR/pulse-inputs"

test "$(git -C "$VATE_SOURCE_REPO" rev-parse HEAD)" = \
  5a37f87de0190da44e619b1800261637e83dd7ed
test "$(git -C "$PULSE_REPO" rev-parse HEAD)" = \
  e06a6cbfe3ddb965c8fc70f50838f5014ec2038e

python3 "$VATE_KIT_REPO/scripts/check_pulse_external_sut_starter.py" \
  --source-repo "$VATE_SOURCE_REPO" \
  --pulse-repo "$PULSE_REPO" \
  --candidate-python-runtime "$CANDIDATE_PYTHON_RUNTIME" \
  --candidate-node-runtime "$CANDIDATE_NODE_RUNTIME" \
  --self-test
```

The full validator self-test explicitly supplies both runtimes because it tests
both launcher contracts. A candidate completed or completed-subset bundle must
instead supply exactly the one runtime corresponding to its recorded logical
command; it must never supply both.

The validator recomputes all 212 raw manifest hashes and the corpus digest
from the fixed VATE commit. With `--pulse-repo`, it also requires the exact
Pulse HEAD, a clean tracked worktree, and the recorded raw hashes for the
reviewed verifier surface. It rejects zero-byte public files, duplicate JSON
keys and selected paths, pin/digest drift, incomplete selected-case closure or
worksheet coverage, prefilled result sentinels, and common secret-like
material.

`--strict-json` is only a byte/JSON/secret hygiene check; arbitrary valid JSON
is not proof of a completed trial. `--run-bundle
RUN_DIR/pulse-sut-result.json` activates the starter-specific closed contract.
It rejects unknown fields, missing 142-leaf or 42-container closure, path
escape, symlink or zero-byte references, hash drift, unresolved worksheet
decisions, unbound case/report/projection records, malformed raw Pulse reports,
and overrun mismatch normalization.

In `completed` mode, `--mapping-repo`, `--pulse-repo`, and exactly one of
`--candidate-python-runtime` or `--candidate-node-runtime` are mandatory.
The validator requires the recorded mapping commit to be the mapping checkout's
HEAD, all tracked and non-ignored untracked worktree state to be clean, the
recorded repository to equal its origin, and the bundle copy/hash to equal that
commit's Git blob. Its `working_tree_scope` is identity and cleanliness checks
only: candidate code is never executed from that live checkout. For every
map, project, and sensitivity invocation, the validator reconstructs a new
temporary execution tree from the recorded Git commit's blobs only. Ignored or
untracked files in the checkout cannot enter that export. It separately
requires the frozen Pulse HEAD and tracked worktree, replays all three recorded
Pulse inputs through `verifyConformanceCase`, checks input hashes immediately
before and after replay, and requires the replayed reports and local
Node.js/npm/Pulse package versions to equal the raw run record exactly. A
self-consistent invented report therefore cannot satisfy completed mode.

The same repository binding, candidate execution, independent recomputation,
and live Pulse replay gates apply to every case listed in
`completed_case_ids` in a `partial` or `blocked` record. A zero-completed-case
blocker may remain `evidence_class: unverified-recorded` without candidate
execution. A partial or blocked record with completed cases must instead use
`candidate-executed-subset` and supply both repositories; hash-only or
self-reported output cannot call a case completed.

The secret scan rejects strong indicators including PEM private keys, JWK
private `d`, `privateKey`/`secretKey` assignments, common token forms, and
unapproved 32-byte hexadecimal values without printing the suspected value.
It is defense in depth, not a complete secret-discovery guarantee; the
candidate must still review the bundle manually and keep private signing
material outside it.

## Candidate-owned mapping boundary

Copy the worksheet into `RUN_DIR` and pin its completed raw hash and the exact
candidate-owned mapping/projection source in the run record. Resolve each
`open_mapping_decision` before executing. The starter intentionally leaves the
asset, decimals/conversion rule, EVM participants, fixture-key generation, and
Pulse-to-VATE projection with the Pulse-side candidate.

Worksheet `0.5` provenance records a leaf's **direct value origin**.
`vate-derived` means that the leaf is copied or deterministically transformed
directly from the eligible VATE admission-request or AP2-mandate bytes.
`non-vate-scaffolding` means that the candidate directly selected or generated
the value. A candidate-generated value does not automatically become
`vate-derived` merely because VATE-derived inputs influence it transitively.
For example, signatures, compact JWTs, `inputHash`, and synthetic settlement
transactions may remain `non-vate-scaffolding` when their direct origin is a
candidate generator. Record that transitive influence through leaf
dependencies, generator records, and sensitivity replay instead.

The template leaves execution date and the four payee name/website leaves with
`provenance: open_mapping_decision`. If a candidate derives one directly from
VATE `issued_at` or merchant bytes, its completed source pointer, dependencies,
transform, and provenance must say so. If it uses fixed candidate metadata,
those fields must instead retain the worksheet/scaffold source and
`non-vate-scaffolding` provenance. Completed worksheets may contain only
`vate-derived` or `non-vate-scaffolding`; the open sentinel is template-only.

Keep that mapping/projection source in `PULSE_MAPPING_REPO` (or another
candidate-controlled repository) at its own exact, clean commit. Do not advance
or patch the separate `PULSE_REPO` frozen-verifier checkout to accommodate the
mapper. Record the repository locator, commit, executable entrypoint, exact
argument array, and raw SHA-256 in `external_run.mapping_source`, using
`repository_path`/`entrypoint` for the committed executable path and
`bundle_path` for its byte-identical run-bundle copy. The validator checks only
that the local checkout's `remote.origin.url` equals this locator; it does not
fetch the remote or prove that the URL is public, available, or candidate
owned. It is self-reported offline provenance, not a remote-publication claim.

## Candidate executable interface and safety boundary

The recorded command must use exactly one of these forms; `-c`/`--eval` and
additional arguments are rejected:

```text
python3 -I -S -B <tracked-entrypoint.py>
node --no-addons --no-global-search-paths <tracked-entrypoint.js|mjs|cjs>
```

The validator never resolves the launcher through the candidate repository or
ambient `PATH`. The operator must select an absolute runtime path on the CLI.
It is preflighted once, and the saved realpath is passed to every map, project,
and sensitivity execution with `shell=False`. The working directory is a fresh
commit export, never `PULSE_MAPPING_REPO`. Canonical JSON is provided on stdin
and the only allowed result channel is JSON stdout.
`candidate_execution.runtime` records the logical name, requested absolute
path and file type, realpath and file type, raw SHA-256, and actual `--version`;
`candidate_execution.commit_export` records the regular-file count, total
bytes, and SHA-256 inventory digest for the commit closure.

Immediately before and after every candidate invocation, and once after the
whole execution sequence, the validator requires the selected runtime path,
realpath, file types, file identity, executable mode, and raw hash to equal the
preflight snapshot. Relative paths, runtimes below the candidate repository or
a fresh export, and runtimes in `.venv`, `venv`, `node_modules`, `build`, or
`dist` paths are rejected. Only the matching CLI option is accepted:

```text
--candidate-python-runtime /absolute/operator-selected/python3
--candidate-node-runtime /absolute/operator-selected/node
```

The selection and recorded bytes are operator-controlled environment facts.
They do not prove the operating system or runtime supply chain, publisher, or
absence of malicious code. Review and sandbox requirements still apply.

The export enumerates every recursive Git tree entry at the recorded commit,
requires modes `100644` or `100755`, hashes every raw blob, and rejects
symlinks, submodules, special files, native/bytecode artifacts, and tracked
`node_modules`, virtual-environment, cache, `dist`, or `build` paths. Each
invocation gets a newly materialized export plus empty temporary `HOME` and
`TMPDIR`. The environment contains no repository paths or credentials;
`PYTHONPATH`, `NODE_PATH`, and other ambient package-search settings are unset,
and Python receives `-I -S -B`, `PYTHONNOUSERSITE`, and
`PYTHONDONTWRITEBYTECODE`. A full
path/type/mode/size/hash snapshot before and after execution must be identical,
so export, home, or temp writes fail validation.

Candidate code must use only Python's standard library or Node built-ins plus
source/data files tracked in that commit. The validator rejects external
package imports, native addons, child-process/network-capable imports, and
non-literal Node imports as defense in depth. No package installation or
runtime network access is permitted. This is an evidence contract and source
policy, not an OS-level security sandbox against deliberately obfuscated
malicious code.

On POSIX, stdout and stderr are read incrementally rather than captured without
a bound. Stdout is capped at 32 MiB, stderr at 1 MiB, and execution at 45
seconds. Overflow, timeout, or a descendant retaining output pipes kills the
whole process group; output bytes are not copied into failure messages.
Completed candidate execution validation is therefore currently POSIX-only.

Candidate code is untrusted code. A VATE maintainer must not run an unreviewed
candidate repository directly on a maintainer workstation. Execution belongs
in the candidate's environment, or only after explicit code review and an
appropriate sandbox. This starter validates reproducible execution evidence;
it is not tamper-proof proof of an honest implementation and does not claim to
exclude every malicious candidate.

The executable supports exactly two operations:

- `map` stdin has `interfaceVersion`, `operation`, and `items`. Each item has
  an opaque `workItemId` and `eligibleInput` containing exactly
  `admissionRequest` and `ap2Mandate`. It contains no VATE case document or
  case ID, `/expected` subtree, admission receipt, post-execution receipt, or
  prior verdict. Stdout has one item with only `workItemId` and
  `pulseInputRaw`; that UTF-8 string must be byte-identical to the replayed
  Pulse input file.
- `project` receives the same eligible input plus the fresh raw Pulse report,
  but still no VATE expected result or receipt. Stdout contains the opaque work
  item and the six closed projection fields recorded in the run: relation,
  Pulse outcome class, projected outcome, execution gate, reason codes, and
  checks.

The validator reruns both operations and requires byte-exact stdout against
the recorded map/projection outputs. It independently recomputes:

- exact USD minor units and declared
  `asset_units_per_usd × 10^decimals` atomic values without binary floating
  point;
- the signed permitted amount as `min(request, mandate limit)`, while x402
  requirements retain the requested amount so overrun remains visible;
- exact source merchant to every Pulse `Merchant.id`/`ap2PayeeId` binding;
- evaluation epoch, execution date, and the intersection of request expiry,
  mandate window, and x402 timeout;
- VATE replay nonce to AP2 expected nonce, generated closed-mandate reference,
  and base64url-decoded EIP-3009 nonce; and
- source-derived allow, overrun, or stale class without a case-ID verdict
  table or expected-result lookup.

For candidate evidence, the validator also randomizes amount, merchant,
evaluation time/window, and replay nonce one at a time for every completed
case and reruns the mapper.
The validator computes the diff across all 142 primitive leaves for every
probe. If a changed leaf claims `source_document: worksheet` and
`provenance: non-vate-scaffolding`, validation fails regardless of its recorded
dependencies because the replay contradicts that worksheet-owned direct-origin
claim.
Candidate-generator descendants are not rejected on that basis; their
transitive influence remains visible in the diff and dependency/generator
records. The relevant independently recomputed destination must still change
correctly; the nonce probe must propagate through the generated closed
reference to the EIP-3009 nonce, and unrelated work items must stay
byte-identical. These checks reject a no-op or fixed hardcoded fixture on the
tested paths, but do not imply an adversarial-proof guarantee. Source text
scanning is defense in depth, not the primary control and not a claim that all
obfuscation is detectable.

The completed source must implement the recorded rules, including:

- exact USD decimal to Pulse ISO minor units without binary floating point;
- a separately declared asset, decimals, and exact conversion to atomic units;
- VATE merchant text to Pulse `Merchant.id`, never implicitly to `payTo`;
- the fixed evaluation time and a window that never widens VATE bounds;
- VATE replay nonce in the terminal key-binding input, followed by Pulse's
  closed-mandate-reference and EIP-3009 nonce derivation;
- newly generated AP2, x402, EIP-3009, settlement, Payment Receipt, signature,
  and public-key fields after applying the VATE-derived values; and
- a predeclared projection from raw Pulse report fields only.

The template already contains one inventory row for every required primitive
leaf. The completed worksheet must retain that exact sorted 142-leaf set and
the 42-container contract, resolve every open decision, and keep each row's
source document/JSON Pointer, dependencies, exact transform, Pulse destination,
`vate-derived` or `non-vate-scaffolding` provenance, and candidate ownership.
Record public keys, public fixture-key derivation labels, compact artifacts,
and signatures, but do not persist non-public signing material.
Set the copied worksheet status and each resolved scaffolding section to
`completed`, change every resolved row/inventory owner to `candidate_owned`,
and replace nulls and `open_mapping_decision` instructions with the actual
candidate rule. Do not edit the starter template in place.

If sensitivity replay or another completed-contract check exposes an incorrect
provenance declaration, do not rewrite the worksheet or generated records to
make already captured evidence pass. Correct the candidate mapping source,
then regenerate the worksheet, candidate map output, Pulse inputs, generated
records, raw Pulse reports, projection output, and their hashes as one fresh
evidence chain.

The completed bundle also contains two closed, hash-bound records:

- `eligible-input-manifest.json` lists, one-to-one for each completed case,
  only the fixed VATE admission request and AP2 mandate bytes admitted to the
  mapper. It explicitly excludes the VATE case `/expected` subtree, VATE
  admission receipt, and any post-execution receipt.
- `generated-records.json` binds every one of the 142 Pulse JSON primitive
  leaf values to its raw Pulse input value digest, worksheet source pointer,
  dependency list, transform, provenance, and ownership. It also binds the
  public outputs of the five declared generator records. Dependency targets
  must exist, use an allowed type, and form an acyclic graph; source pointers
  must resolve. Exact copies inherit `vate-derived` provenance.

The generated record also binds the completed worksheet hash and candidate map
stdout path/hash. Together with the eligible-input request, byte-exact mapper
stdout, per-case Pulse input hashes, pre/post replay hashes, raw Pulse output,
and projection stdout, this forms one bundle-local hash chain.

This machine-covered inventory is deliberately limited to the frozen Pulse
input JSON's 142 primitive leaves and 42 containers. It does not claim to
extract or independently verify compact JOSE/SD-JWT internal headers, claims,
salts, signature components, EIP-3009 signature internals, or private keys.
Public generated values are recorded by digest; non-public signing material
must not be included.

These shortcuts invalidate the attempt:

- returning a verdict from the case ID;
- reading the VATE case `/expected` block or admission receipt to build input
  or choose output;
- hashing VATE bytes beside an otherwise unchanged Pulse fixture;
- treating this worksheet as a VATE-authored completed Pulse adapter; or
- rewriting Pulse reject/non-attenuate behavior into a VATE `attenuate` pass.

The selected-case projection is closed. Allow requires `consistent: true`, no
failures, `accept`, and `match`. Overrun requires only
`AP2_X402_AMOUNT_MISMATCH`, `non-attenuate`, and the explicit VATE/Pulse
`mismatch`. Stale requires `EIP3009_VALID_BEFORE_EXPIRED`, permits only the
related `AP2_MANDATE_TIME_INVALID` companion, and maps to `reject`/`match`.
`AP2_OPEN_MANDATE_UNVERIFIED` or any unrelated reason cannot stand in for a
stale match. `error` and `unsupported` are never completed selected outcomes,
and an outcome class may not contradict raw `consistent`/failure state.

## Exact frozen-verifier invocation

The candidate-owned mapper writes one strict JSON Pulse case per selected VATE
case at these paths:

```bash
export PULSE_INPUT_ALLOW="$RUN_DIR/pulse-inputs/allow-ap2-hnp-preauthorized-mandate.pulse-input.json"
export PULSE_INPUT_OVERRUN="$RUN_DIR/pulse-inputs/attenuate-ap2-hnp-amount-overrun.pulse-input.json"
export PULSE_INPUT_STALE="$RUN_DIR/pulse-inputs/deny-ap2-hnp-stale-mandate.pulse-input.json"
```

Validate the starter, the frozen Pulse checkout, and all three raw input files
before invoking Pulse. Install only the already pinned Pulse lockfile:

```bash
python3 "$VATE_KIT_REPO/scripts/check_pulse_external_sut_starter.py" \
  --source-repo "$VATE_SOURCE_REPO" \
  --pulse-repo "$PULSE_REPO" \
  --strict-json "$PULSE_INPUT_ALLOW" \
  --strict-json "$PULSE_INPUT_OVERRUN" \
  --strict-json "$PULSE_INPUT_STALE"

cd "$PULSE_REPO"
npm ci
```

The exact replay driver is the following command. It imports and calls the
frozen `verifyConformanceCase` export directly once for each input and writes
only the returned report array. Capture the three input hashes immediately
before and after this command; they must be identical.

```bash
cd "$PULSE_REPO"

node --import tsx --input-type=module --eval '
import { readFile } from "node:fs/promises";
import { verifyConformanceCase } from "./src/verifier.ts";
const reports = [];
for (const path of process.argv.slice(1)) {
  const value = JSON.parse(await readFile(path, "utf8"));
  reports.push(await verifyConformanceCase(value));
}
process.stdout.write(JSON.stringify(reports));
' -- \
  "$PULSE_INPUT_ALLOW" \
  "$PULSE_INPUT_OVERRUN" \
  "$PULSE_INPUT_STALE" \
  > "$RUN_DIR/replayed-pulse-reports.json"
```

The candidate-owned run orchestration must place that report array unchanged
in `raw-pulse-output.json`. The raw record is a closed object with exactly
`recordVersion`, `pulseVerifierCommit`, `runtime`, `execution`, `inputs`, and
`reports`. Use record version `vate-pulse-raw-verifier-output-0.3`. Record:

- `runtime.nodeVersion`, `runtime.npmVersion`, and the frozen Pulse
  `package.json` version;
- `execution.workingDirectory` as `$PULSE_REPO`, `execution.entryPoint` as
  `src/verifier.ts#verifyConformanceCase`, and `execution.driverSha256` as
  `723479d08f55f0954ee1494556fd8da9ed812a55b53c9a5204d5414c47e980f2`;
- the exact logical command array shown above, with each absolute input path
  represented as `$RUN_DIR/<bundle-relative-path>`; and
- for each selected case, its VATE case ID, opaque `vate-pulse-work-item-N`
  Pulse ID, bundle-relative
  input path, and equal raw SHA-256 values immediately before and after replay.

The completed-bundle validator independently executes the same driver from the
frozen Pulse checkout. It requires exact parsed-JSON equality between each
recorded report object and the fresh replay result; the candidate's mapping or
projection code is not permitted to substitute for this call.

Validate and hash the resulting records:

```bash
python3 "$VATE_KIT_REPO/scripts/check_pulse_external_sut_starter.py" \
  --source-repo "$VATE_SOURCE_REPO" \
  --pulse-repo "$PULSE_REPO" \
  --strict-json "$RUN_DIR/raw-pulse-output.json"

shasum -a 256 \
  "$PULSE_INPUT_ALLOW" \
  "$PULSE_INPUT_OVERRUN" \
  "$PULSE_INPUT_STALE" \
  "$RUN_DIR/raw-pulse-output.json" \
  "$RUN_DIR/mapping-worksheet.json" \
  "$RUN_DIR/eligible-input-manifest.json" \
  "$RUN_DIR/generated-records.json"
```

On Windows PowerShell, use the built-in equivalent (no added dependency):

```powershell
Get-FileHash -Algorithm SHA256 -Path @(
  $env:PULSE_INPUT_ALLOW
  $env:PULSE_INPUT_OVERRUN
  $env:PULSE_INPUT_STALE
  "$env:RUN_DIR/raw-pulse-output.json"
  "$env:RUN_DIR/mapping-worksheet.json"
  "$env:RUN_DIR/eligible-input-manifest.json"
  "$env:RUN_DIR/generated-records.json"
)
```

This calls the frozen `verifyConformanceCase` export directly and does not use
Pulse bundle expectations to determine a report. The resulting file preserves
the three returned report objects without post-processing, records the runtime,
and binds each input's raw SHA-256 immediately before and after verification.
Keep this raw file unchanged; projection happens in a separate candidate-owned
step.

## Result, compare, and report bundle

Copy `pulse-sut-result.template.json` into `RUN_DIR/pulse-sut-result.json`.
Replace every sentinel only from the completed worksheet, pinned projection
source, the three Pulse inputs, and `raw-pulse-output.json`. Record each exact
VATE source path/hash and bundle-local byte copy, each raw Pulse input hash,
the one raw output hash, and the starter-manifest/worksheet/mapping-source
hashes. Every reference must be a non-empty, regular, non-symlink file below
`RUN_DIR`. Replace
`implementation.source`, `implementation.commit`, and `implementation.version`
with the candidate-owned mapping identity, and replace `implementation.type`
with `external-verifier-projection`; keep `implementation.upstream_verifier` at
the frozen Pulse pin.

A completed file contains exactly 75 result entries in corpus order: the three
selected cases as `completed`, followed by the other 72 cases as explicit
closed-schema `skipped`/`out-of-scope` records. The latter make no SUT claim.
The fixed VATE runner treats every skipped case as a comparison failure; this
is intentionally preserved rather than hidden or normalized.

Each `external_run.case_runs[].vate_inputs` record includes the selected VATE
admission receipt only as a digest-bound `comparison-only` closure copy. Its
presence does not claim Pulse read or generated it. Do not add it to a mapping
source, Pulse input, raw report, or projection, and do not copy its decision,
checks, or receipt fields into `results[]`.

Before compare, validate the completed run bundle with the closed contract:

```bash
python3 "$VATE_KIT_REPO/scripts/check_pulse_external_sut_starter.py" \
  --source-repo "$VATE_SOURCE_REPO" \
  --mapping-repo "$PULSE_MAPPING_REPO" \
  --pulse-repo "$PULSE_REPO" \
  --candidate-python-runtime "$CANDIDATE_PYTHON_RUNTIME" \
  --run-bundle "$RUN_DIR/pulse-sut-result.json"
```

The command above is the Python-mapper form. If `mapping_source.command` begins
with logical `node`, omit the Python option and provide only
`--candidate-node-runtime "$CANDIDATE_NODE_RUNTIME"`.

This is the semantic starter/run-record gate. A successful `--strict-json`
check by itself is not sufficient. The checked-in template is intentionally
not a valid `--run-bundle` input. A completed run can pass only as
`evidence_class: candidate-executed` with both repositories supplied and all
completed-only gates satisfied.

## Partial and blocked attempt records

The same result contract may honestly stop as `partial` or `blocked` without
being upgraded to a completed three-case result. Use
`evidence_class: candidate-executed-subset` when at least one case completed,
or `unverified-recorded` for a zero-completed-case blocker, plus the closed
`external_run.attempt` object:

- `stage` is one of `source-validation`, `mapping`, `generation`,
  `pulse-install`, `pulse-replay`, `projection`, or `comparison`;
- `reason_code` is one of `TIMEBOX_REACHED`, `ENVIRONMENT_BLOCKER`,
  `MAPPING_BLOCKER`, `GENERATION_BLOCKER`, `REPLAY_BLOCKER`,
  `PROJECTION_BLOCKER`, or `COMPARISON_BLOCKER`;
- `details` is a non-empty factual description;
- `completed_case_ids` and `incomplete_case_ids` are ordered, disjoint, and
  together equal the three selected cases; and
- `evidence` is a closed list of regular, bundle-local, non-empty file/hash
  records. Every completed case must bind both a Pulse input and raw Pulse
  output; an incomplete case cannot claim generated or replay evidence.

A `partial` record completes one or two selected cases. A `blocked` record may
complete zero, one, or two, but must retain at least one incomplete case. Both
still contain all 75 result entries; incomplete selected cases remain the
closed unmapped sentinel and the 72 unselected cases remain out of scope.
Every claimed completed subset receives the same mapping-repository
HEAD/blob/cleanliness, standard executable, independent recomputation,
sensitivity, frozen Pulse replay, raw-report, and projection gates as completed
mode. These checks run only for that subset. A zero-completed-case blocker may
omit candidate, worksheet, eligible-input, generated, and replay records, but
must retain a closed blocker record and selected-case partition. Neither status
is conformance or a completed three-case external SUT result.

Validate a partial/blocked record with completed cases using the same two-repo
command as completed mode:

```bash
python3 "$VATE_KIT_REPO/scripts/check_pulse_external_sut_starter.py" \
  --source-repo "$VATE_SOURCE_REPO" \
  --mapping-repo "$PULSE_MAPPING_REPO" \
  --pulse-repo "$PULSE_REPO" \
  --candidate-python-runtime "$CANDIDATE_PYTHON_RUNTIME" \
  --run-bundle "$RUN_DIR/pulse-sut-result.json"
```

Use only the Node runtime option for a Node mapper. A zero-completed-case
blocker omits `--mapping-repo`, `--pulse-repo`, and both runtime options.

The validator's `--self-test` mode creates VATE-authored temporary positive
fixtures only to exercise the validator. They are permanently labeled
`evidence_class: validator-self-test`; the completed self-test additionally
declares frozen Pulse fixture-core reuse. Candidate mode rejects that evidence
class, the `.invalid` test repository identity, and unchanged fixture cores,
so these fixtures cannot be promoted into candidate completed evidence.

First run the fixed VATE fixture check. This is repository fixture validation,
not Pulse evidence:

```bash
python3 "$VATE_SOURCE_REPO/scripts/vate_conformance.py" run \
  --corpus-root "$VATE_SOURCE_REPO/conformance/al2-vate-v0.3" \
  --report "$RUN_DIR/vate-reference-run.json"
```

At the fixed pin, this fixture run must report 75/75 passing cases. That result
validates the VATE fixture set; it says nothing about the Pulse mapping.

Then compare the candidate-owned result and always retain the actual exit code
and reports. A partial, skipped, unsupported, or mismatched attempt is a valid
recorded outcome; it is not a pass:

```bash
set +e
python3 "$VATE_SOURCE_REPO/scripts/vate_conformance.py" compare \
  --corpus-root "$VATE_SOURCE_REPO/conformance/al2-vate-v0.3" \
  --sut-results "$RUN_DIR/pulse-sut-result.json" \
  --report "$RUN_DIR/vate-compare-report.json" \
  --implementation-report "$RUN_DIR/vate-implementation-report.json" \
  --conformance-report-uri "vate-compare-report.json" \
  --implementation-report-uri "vate-implementation-report.json"
COMPARE_EXIT=$?
set -e
printf '%s\n' "$COMPARE_EXIT" > "$RUN_DIR/vate-compare.exit-code.txt"
```

For a contract-valid completed three-case bundle, the fixed runner is expected
to exit `1` and report `total: 75`, `passed: 2`, `failed: 73`, and `skipped:
72`. The allow and stale selected cases match; amount-overrun remains the one
selected mismatch because VATE expects `attenuate` while Pulse reports a
reject/non-attenuate result. The generated implementation report is therefore
`fail`. This failure is the intended bounded observation, not an error to
rewrite into a pass.

Verify the local digest chain independently of whether the semantic comparison
passed. Preserve this command's exit code too:

```bash
set +e
python3 "$VATE_SOURCE_REPO/scripts/vate_conformance.py" verify-bundle \
  --corpus-root "$VATE_SOURCE_REPO/conformance/al2-vate-v0.3" \
  --sut-results "$RUN_DIR/pulse-sut-result.json" \
  --conformance-report "$RUN_DIR/vate-compare-report.json" \
  --implementation-report "$RUN_DIR/vate-implementation-report.json" \
  --report "$RUN_DIR/vate-bundle-verification.json"
BUNDLE_EXIT=$?
set -e
printf '%s\n' "$BUNDLE_EXIT" > "$RUN_DIR/vate-bundle.exit-code.txt"

shasum -a 256 \
  "$RUN_DIR/pulse-sut-result.json" \
  "$RUN_DIR/vate-compare-report.json" \
  "$RUN_DIR/vate-implementation-report.json" \
  "$RUN_DIR/vate-bundle-verification.json"
```

A `verify-bundle` pass establishes only that the local corpus, SUT result, and
two reports form the recorded digest chain. It does not turn a failing or
partial `compare` report into semantic conformance. For the fixed completed
three-case contract above, its expected integrity result is 27/27 checks
passing while the semantic compare and implementation report remain failing.

In particular, if Pulse reports rejection or another non-attenuate result for
`attenuate-ap2-hnp-amount-overrun`, retain that observation and the VATE
comparison mismatch. Do not normalize it to `attenuate`, mark unsupported
checks true, or describe the bounded attempt as general compatibility.
