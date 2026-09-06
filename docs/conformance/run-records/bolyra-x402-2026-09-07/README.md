# Bolyra / x402: one-case partial external SUT run

Bolyra's native `verifyClassical` accepted a matching request and rejected a
request for a different audience and one requesting an uncovered capability.
The x402 `runEvcVerifier` command host returned the same allow/deny
outcomes. VATE's maintainer replayed the candidate's unchanged runner and wrapper
on 7 September 2026: all three native verdicts and host decisions reproduced,
and the issued presentation matched the candidate's output byte-for-byte.

This solicited experiment covers one partial VATE case with two auxiliary
controls. The comparison preserves native reasons, unreported VATE checks and
the absence of a receipt-fixture reference. It does not establish full-corpus
conformance, adoption, endorsement or production approval.

## Sources and fixed inputs

- [Candidate report, scripts and raw outputs](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/57#issuecomment-5561003269)
  from `saneGuy`; [saved report](candidate-report.md).
- [Fixed three-input packet and agreed experiment](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/57).
- Bolyra: [`511ccbba1a3c929f5803b233fdfd21e0b82bb913`](https://github.com/bolyra/bolyra/tree/511ccbba1a3c929f5803b233fdfd21e0b82bb913),
  `integrations/mpp-payments` (`@bolyra/mpp 0.4.0`).
- x402 command host: [`992f78e37178dc4d249eeb0e2dc0720120282dd1`](https://github.com/saneGuy/x402/tree/992f78e37178dc4d249eeb0e2dc0720120282dd1),
  the `saneGuy/x402` source used in [PR #3376](https://github.com/x402-foundation/x402/pull/3376).
- VATE: `v0.4.0`, [`cc072ef86f54791213a3e603a65b2f24f64b1b6d`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/cc072ef86f54791213a3e603a65b2f24f64b1b6d),
  76 corpus cases and 216 manifest artifacts.
- Corpus digest: `b2a281e372b2e1d6b49be219c715fa69c0b2be237d29a6e1f0dda9c0659b6130`.
- Selected case: `deny-audience-mismatch`.

The [packet](input-packet.json) records the raw hashes of the fixed
[case](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/cc072ef86f54791213a3e603a65b2f24f64b1b6d/conformance/al2-vate-v0.3/cases/deny-audience-mismatch.json) and
[base request](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/cc072ef86f54791213a3e603a65b2f24f64b1b6d/examples/admission-request.example.json). The
[source manifest](source-manifest.json) records 17 unchanged source and package
files, with raw SHA-256 and Git blob identifiers.

## Native observations

One `issueMandate` call creates a presentation using the packet's public
disposable test key. The same presentation is reused unchanged in all three
requests.

| Input | Change from P | Native `verifyClassical` | Host `runEvcVerifier` |
| --- | --- | --- | --- |
| P | Matching audience and issued small capability | `allow`, `kind=classical` | `allow` |
| N1 | Only `request.project_key` changes | `deny`, `request_mismatch`, `detail.field=project_key` | `deny`, `request_mismatch` |
| N2 | Only `request.granted_capabilities` changes to an uncovered capability | `deny`, `request_mismatch`, `detail.field=granted_capabilities` | `deny`, `request_mismatch` |

The two denials remain distinguishable in native output. The host deliberately
returns the common decision/code pair, dropping `message`, `detail` and `kind`.
The classical allow emits no `consume_nonces`, so this run reserves no nonces.
The packet's nonce is unsigned correlation metadata, not a replay control.

The harness exercises the native verifier and command host directly. It issues
no application decision receipt and uses no application retention path. Captured
test output is separate from retained application evidence. Bolyra's
[receipt-instance binding](https://github.com/bolyra/bolyra/blob/511ccbba1a3c929f5803b233fdfd21e0b82bb913/spec/receipt-instance-binding-v1.md)
belongs to a separate application receipt layer, which this probe does not
exercise. Payment routing and settlement are outside the experiment.

## Mapping and VATE comparison

The fixed VATE base request's `/target/audience` maps to the mandate's signed
`project_key`; base `/audience` maps to `request.project_key`. N1 applies the
case's `/audience` mutation. This is a bounded field mapping, not an assertion
that VATE audience and x402 payee semantics are equivalent. Agent, model,
program, capability tier, fixed clock and disposable key are native test
scaffolding; the other VATE request fields are not evaluated.

The [projection script](project_replay.py) reads the saved native output and
records N1 as `deny` / `should_execute: false`. It retains `request_mismatch`
without adding VATE reason codes or unperformed named checks. It neither runs
Bolyra nor reads an expected receipt.

The fixed VATE runner returns exit `1`, with agreement on the refusal and six
comparison differences:

- native `request_mismatch` differs from `AUDIENCE_MISMATCH, FAIL_CLOSED`;
- the primary reason consequently differs;
- `request.audience` has no submitted VATE named check;
- `target.audience` has no submitted VATE named check;
- `admission_receipt.decision` has no submitted VATE named check;
- the legacy case requires `artifacts.admission_receipt`, but this run did not
  evaluate that receipt fixture, so no reference is submitted.

The native field check supports the partial mapping; it does not emit VATE's
separate named-check records. P and N2 are auxiliary controls. The remaining
75 corpus cases were not executed. Thus the report's `0 passed / 76 failed`
means one partial comparison with differences plus 75 unexecuted cases, not
76 failed native executions.

All three report schemas validate, and `verify-bundle` passes 54/54 local
consistency checks. Read the [SUT result](sut-results.json),
[comparison](compare-report.json), [implementation report](implementation-report.json)
and [bundle verification](bundle-verification.json) together. The generated
implementation report omits custom native evidence and detailed limitations.

## Reviewer replay

| | Candidate report | VATE-maintainer replay |
| --- | --- | --- |
| Platform | macOS arm64 | macOS arm64 |
| Node | 24.13.0 | 24.19.0 |
| tsx | 4.23.13 | 4.23.13 |
| Bolyra dependencies | Committed MPP lockfile; circomlibjs 0.1.7 | Same lockfile; SDK 0.6.1, receipts 0.10.0, circomlibjs 0.1.7 |
| esbuild | Not supplied | 0.28.2 |

This reproduces the reported outputs under the recorded reviewer environment,
with a different Node patch version. The pinned source hashes were checked
before and after execution. Dependency installation scripts were disabled;
outbound IP connections were denied during native execution.

The successful harness run is saved in [stdout](harness.stdout.txt),
[stderr](harness.stderr.txt) and [native-report.json](native-report.json).
Three additional calls to the unchanged wrapper captured each input's raw
stdio and exit status: all stdout bytes matched the candidate's posted verdicts,
all stderr streams were empty, and every wrapper exited `0`.

An initial reviewer attempt used a long temporary path, causing tsx's Unix-pipe
startup to fail with `EINVAL`. The host failed closed with `nonzero_exit` while
direct native calls matched. A short temporary directory resolved that setup
failure without changing the candidate code, inputs or dependencies. The initial
setup attempt is excluded from the VATE comparison.

[replay.json](replay.json) records the successful calls, output hashes and setup
history. Machine-specific executable and directory prefixes are normalized in
that metadata; saved outputs are byte-unmodified. The [manifest](MANIFEST.json)
identifies the record's raw file bytes.

## Reproduce the native run

Use a writable copy of this record outside the VATE checkout, Node 24.19.0, and
the included harness lockfile. Obtain the pinned Bolyra source under
`bolyra-pin/` and the two pinned x402 files under `evc/`:

```sh
git clone --no-checkout https://github.com/bolyra/bolyra.git bolyra-pin
git -C bolyra-pin checkout --detach 511ccbba1a3c929f5803b233fdfd21e0b82bb913
mkdir evc
curl -fsSL https://raw.githubusercontent.com/saneGuy/x402/992f78e37178dc4d249eeb0e2dc0720120282dd1/typescript/packages/extensions/src/authorization-evidence/evcHost.ts -o evc/evcHost.ts
curl -fsSL https://raw.githubusercontent.com/saneGuy/x402/992f78e37178dc4d249eeb0e2dc0720120282dd1/typescript/packages/extensions/src/authorization-evidence/types.ts -o evc/types.ts
```

Check these files against `source-manifest.json`. Restore dependencies from the
two lockfiles, with lifecycle scripts disabled:

```sh
npm --prefix bolyra-pin/integrations/mpp-payments ci --ignore-scripts
npm ci --ignore-scripts
```

Run the unchanged candidate harness with a short temporary directory. It writes
fresh `issued-mandate.json`, `trusted-operators.json` and `report.json`:

```sh
python3 - <<'PY'
import os, subprocess, tempfile
with tempfile.TemporaryDirectory(prefix="vate-x402-", dir="/tmp") as temporary:
    environment = dict(os.environ, TMPDIR=temporary)
    subprocess.run(["node", "--import", "tsx", "runner.mjs"],
                   env=environment, check=True)
PY
```

Check the fresh `report.json` against the native and host outcomes in the table
above. A successful harness process exit alone does not establish matching host
results; a host `nonzero_exit` must remain a failed replay.

The host invokes `[tsx, wrapper.mjs]` using the packet's 10-second timeout and
1 MiB stdout limit. [runner.mjs](runner.mjs) calls the native verifier and then
the host; [wrapper.mjs](wrapper.mjs) calls the same native verifier over stdio.
The [constructor](construct-requests.mjs) only assembles requests using native
`issueMandate`. The published raw-output files and replay metadata describe the
saved reviewer run; a fresh run needs its own captured outputs and metadata.

## Rebuild the saved VATE comparison

Copy this complete record into the same `docs/conformance/run-records/` path
in a separate VATE checkout at `cc072ef`. From that record directory, set
`VATE_CHECKOUT` to the checkout root and run:

```sh
python3 -B project_replay.py
python3 "$VATE_CHECKOUT/scripts/vate_conformance.py" compare \
  --corpus-root "$VATE_CHECKOUT/conformance/al2-vate-v0.3" \
  --sut-results sut-results.json --report compare-report.json \
  --implementation-report implementation-report.json \
  --conformance-report-uri compare-report.json
python3 "$VATE_CHECKOUT/scripts/vate_conformance.py" verify-bundle \
  --corpus-root "$VATE_CHECKOUT/conformance/al2-vate-v0.3" \
  --sut-results sut-results.json --conformance-report compare-report.json \
  --implementation-report implementation-report.json \
  --report bundle-verification.json
```

`compare` exits `1` for the recorded differences; `verify-bundle` exits `0`.
Regenerated reports have new check times and digests. The saved manifest
identifies the original published files.
