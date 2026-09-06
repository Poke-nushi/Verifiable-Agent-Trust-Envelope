@Poke-nushi Run complete against your packet `vate-bolyra-x402-audience-2026-09-06-v1`, all three source-based predictions confirmed.

**Environment:** macOS arm64, node v24.13.0, tsx v4.23.13. Bolyra pin `511ccbba1a3c929f5803b233fdfd21e0b82bb913` (`integrations/mpp-payments`, `npm ci` from its committed lockfile; circomlibjs 0.1.7). x402 pin `992f78e37178dc4d249eeb0e2dc0720120282dd1` (`evcHost.ts` + `types.ts` taken verbatim from that commit; the host module is dependency-free). Your `construct-requests.mjs` and `input-packet.json` used byte-for-byte as posted. One `issueMandate` call with the packet options; the returned presentation reused unchanged in all three requests.

| Input | Native `verifyClassical` | Host `runEvcVerifier` |
| --- | --- | --- |
| P | `allow` | `allow` |
| N1 | `deny` / `request_mismatch`, `detail.field=project_key` | `deny` / `request_mismatch` |
| N2 | `deny` / `request_mismatch`, `detail.field=granted_capabilities` | `deny` / `request_mismatch` |

The two denials are distinct at the native layer (`detail.field` = `project_key` vs `granted_capabilities`) and indistinguishable at the host boundary (same `decision`/`code` pair), matching both your reading and the deliberate narrowing described on the PR.

Two observations you asked to have recorded:
- The classical allow emitted no `consume_nonces` (P's verdict is `{"verdict":"allow","kind":"classical"}`), matching the pinned source; the host allow therefore involved no nonce reservation.
- Native verdicts carry `kind: "classical"`, which the host's closed-verdict schema accepts and then drops along with `message`/`detail`.

**Retention:** no application record is retained by this harness. `verifyClassical` and `runEvcVerifier` were exercised directly; nothing in this run issued a decision receipt, so there is no signed artifact binding the diagnosis to the evaluated input here. The files below are captured test output, not application retention. In the Bolyra stack that association is receipt-layer work (`spec/receipt-instance-binding-v1.md`) and exists only when an application issues a receipt, which this probe deliberately did not.

<details>
<summary>Raw wrapper stdio and exit status per input</summary>

**P** stdin: `request-P.json` (below) · stdout:
```json
{"verdict":"allow","kind":"classical"}
```
stderr: empty (0 bytes) · exit status: 0
**N1** stdin: `request-N1.json` (below) · stdout:
```json
{"verdict":"deny","code":"request_mismatch","message":"request project_key does not match the signed binding","detail":{"field":"project_key","request":"https://unexpected.example/a2a","binding":"https://agent.example/a2a"},"kind":"classical"}
```
stderr: empty (0 bytes) · exit status: 0
**N2** stdin: `request-N2.json` (below) · stdout:
```json
{"verdict":"deny","code":"request_mismatch","message":"granted capability \"mpp:financial:medium\" is not covered by the signed binding","detail":{"field":"granted_capabilities","capability":"mpp:financial:medium"},"kind":"classical"}
```
stderr: empty (0 bytes) · exit status: 0

</details>

<details>
<summary>Issued mandate (from the packet's disposable fixture key)</summary>

```json
{
  "presentation": "eyJidnAiOjEsImFnZW50Ijp7ImVudmVsb3BlIjp7InZlcnNpb24iOiIxLjAuMCIsImNpcmN1aXQiOnsibmFtZSI6IkFnZW50UG9saWN5IiwidmVyc2lvbiI6IjEuMC4wIn0sInByb29mVHlwZSI6Imdyb3RoMTYiLCJwdWJsaWNTaWduYWxzIjpbIjEiLCIyIiwiMTUwOTU2ODEzMzczMzM2NDM0MDMwNzAwMjk3MTg2NTkyNjEwMzg1MDQ0NjMxMjU2NjEyMTUyODQ0OTEwNzU2ODE5ODU5NzY1NzQ4NjUiLCI0IiwiMTc4ODY1NjQwMCIsIjMiXSwicHJvb2YiOnsicGlfYSI6WyIxIiwiMiJdLCJwaV9iIjpbWyIxIiwiMiJdLFsiMyIsIjQiXV0sInBpX2MiOlsiNSIsIjYiXX19LCJjcmVkZW50aWFsIjp7Im1vZGVsX2hhc2giOiIxMjU1NTc2NjExMzg2MTU0OTI5MzI1NDc2MzYwNjc3MDQ2NDM0ODM1ODY3MDEyNTk1MjgyNjIyMjA2NTM0NjY1NDcwMDY1NjU3OTIxOSIsIm9wZXJhdG9yX3B1YmtleSI6eyJ4IjoiMTgzNzA3NzEzOTk5MjgxNjY1NzQzMDI0MjcyMzc5ODYwMTM0MTMzNjkyMzM4ODM4MTMxNTE4NDQ4MjA3MDI3MTg0NDgwODcxNTU2MzEiLCJ5IjoiMTcxOTA2MDYwMzkwNjQxNTA2MzEyNzMzNzE0MjQ1NzQxNzYwNjc4NTAzMDEwMjkxODc5OTYxNjUxODQ3NjM5OTY5Nzk3MTAwODE1ODYifSwicGVybWlzc2lvbl9iaXRtYXNrIjoiNCIsImV4cGlyeSI6MTc4ODY1NjQwMH19LCJiaW5kaW5nIjp7ImFnZW50X25hbWUiOiJ2YXRlLWJvdW5kYXJ5LXByb2JlIiwicHJvamVjdF9rZXkiOiJodHRwczovL2FnZW50LmV4YW1wbGUvYTJhIiwicHJvZ3JhbSI6Ing0MDIiLCJtb2RlbCI6InZhdGUtYm91bmRhcnktcHJvYmUtdjEiLCJjYXBhYmlsaXRpZXMiOlsibXBwOmZpbmFuY2lhbDpzbWFsbCJdLCJleHBpcnkiOjE3ODg2NTY0MDB9LCJzaWciOnsiUjgiOnsieCI6IjY0NzM4Njc5ODg5OTIzMzU1MTk2OTY3NzY5OTc3OTI1NzIyMDA4NDEzOTY2NzE3MTAwNTc5Mjg3NjA1MDkxMzE2OTMwMzk2MzgwMDkiLCJ5IjoiMTU3NDE1MzA1NjUzMTUxMjk1Mjc4MDU3MjMxODgxOTg2MjcwODgxODAzMzQxMDMzMzMzODE0MzE1NzIyNDI2OTQ3MjQ5NzA0NjkzNSJ9LCJTIjoiMTY3ODY0MzkyMTI1NTkwMTk4NDQ1Njk2OTEwNzc4NDQwNTI5NzkxMjUwOTA5MDkzODM4ODE1ODgxOTMyNDY2OTQ3NzI2ODI0ODQyMyJ9LCJub25jZSI6InZhdGUtYXVkaWVuY2UtcHJvYmUtMjAyNi0wOS0wNi12MSJ9",
  "capabilities": [
    "mpp:financial:small"
  ],
  "operatorPublicKey": {
    "x": "18370771399928166574302427237986013413369233883813151844820702718448087155631",
    "y": "17190606039064150631273371424574176067850301029187996165184763996979710081586"
  }
}
```

</details>

<details>
<summary>The three EVC requests (request field per id; common fields: version 1, now_unix 1788652800, bundle = the presentation above)</summary>

```json
{
  "P": {
    "agent_name": "vate-boundary-probe",
    "project_key": "https://agent.example/a2a",
    "program": "x402",
    "model": "vate-boundary-probe-v1",
    "granted_capabilities": [
      "mpp:financial:small"
    ]
  },
  "N1": {
    "agent_name": "vate-boundary-probe",
    "project_key": "https://unexpected.example/a2a",
    "program": "x402",
    "model": "vate-boundary-probe-v1",
    "granted_capabilities": [
      "mpp:financial:small"
    ]
  },
  "N2": {
    "agent_name": "vate-boundary-probe",
    "project_key": "https://agent.example/a2a",
    "program": "x402",
    "model": "vate-boundary-probe-v1",
    "granted_capabilities": [
      "mpp:financial:medium"
    ]
  }
}
```

</details>

<details>
<summary>wrapper.mjs (spawned by the host as `[tsx, wrapper.mjs]`)</summary>

```js
// EVC stdin/stdout wrapper: reads exactly one JSON request from stdin, runs the
// pinned native verifyClassical, writes exactly one closed verdict object to
// stdout, exits 0 for both allow and deny. No other stdout writes.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const { verifyClassical } = await import(
  join(here, 'bolyra-pin/integrations/mpp-payments/src/classical.ts')
);

const trustedOperators = JSON.parse(
  readFileSync(join(here, 'trusted-operators.json'), 'utf8'),
);

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));

const verdict = await verifyClassical(request, trustedOperators);
process.stdout.write(JSON.stringify(verdict));
process.exit(0);
```

</details>

<details>
<summary>runner.mjs (harness: native runs + host runs)</summary>

```js
// Harness for VATE #57: constructs P/N1/N2 via the packet's constructor, runs
// each through the pinned native verifyClassical, then through the pinned
// runEvcVerifier spawning wrapper.mjs. Prints one JSON report to stdout.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { constructRequests } from './construct-requests.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const mpp = join(here, 'bolyra-pin/integrations/mpp-payments/src');

const { issueMandate } = await import(join(mpp, 'issue.ts'));
const { verifyClassical } = await import(join(mpp, 'classical.ts'));
const { runEvcVerifier } = await import(join(here, 'evc/evcHost.ts'));

const packet = JSON.parse(readFileSync(join(here, 'input-packet.json'), 'utf8'));
const { issued, trustedOperators, requests } = await constructRequests(issueMandate, packet);

writeFileSync(join(here, 'trusted-operators.json'), JSON.stringify(trustedOperators));
writeFileSync(
  join(here, 'issued-mandate.json'),
  JSON.stringify(
    { presentation: issued.presentation, capabilities: issued.capabilities, operatorPublicKey: issued.operatorPublicKey },
    null,
    2,
  ),
);

const tsxBin = join(here, 'node_modules/.bin/tsx');
const report = { packet_id: packet.packet_id, runs: [] };

for (const { id, input } of requests) {
  const native = await verifyClassical(input, trustedOperators);
  const host = await runEvcVerifier(input, {
    command: [tsxBin, join(here, 'wrapper.mjs')],
    timeoutMs: packet.host_options.timeoutMs,
    maxStdoutBytes: packet.host_options.maxStdoutBytes,
  });
  report.runs.push({ id, request: input.request, native, host });
}

writeFileSync(join(here, 'report.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));
```

</details>