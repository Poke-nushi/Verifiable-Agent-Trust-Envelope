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
