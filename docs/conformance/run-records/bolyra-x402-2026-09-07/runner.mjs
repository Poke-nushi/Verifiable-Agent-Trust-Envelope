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
