// Fixture only: the private key exists solely in this child process's memory.
import { generateKeyPairSync, sign } from 'node:crypto';
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
process.stdout.write(publicKey.export({ type: 'spki', format: 'der' }).toString('base64') + '\n');
let buffered = '';
process.stdin.setEncoding('ascii');
process.stdin.on('data', chunk => {
  buffered += chunk;
  if (buffered.length > 150000) process.exit(2);
  let end;
  while ((end = buffered.indexOf('\n')) !== -1) {
    const input = buffered.slice(0, end);
    buffered = buffered.slice(end + 1);
    if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(input)) process.exit(2);
    const signature = sign('sha256', Buffer.from(input, 'ascii'), { key: privateKey, dsaEncoding: 'ieee-p1363' });
    process.stdout.write(signature.toString('base64url') + '\n');
  }
});
