// Synthetic examples only. The generated private key never leaves memory.
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { canonicalizeJcsJson } from '../../packages/vate-core-ts/dist/index.js';
import { PROFILE, PAYLOAD_TYPE, PREDICATE_TYPE, EXTENSION } from './receive.mjs';

export const bytes = value => Buffer.from(JSON.stringify(value));
export const jcs = value => Buffer.from(canonicalizeJcsJson(bytes(value)));
const hash = value => createHash('sha256').update(value).digest('hex');
export const digest = value => 'sha256:' + hash(jcs(value));

export function fixture() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const der = publicKey.export({ format: 'der', type: 'spki' });
  const keyHash = hash(der);
  const request = {
    authority_context: 'modeled', evaluation_time: '2026-08-18T12:00:00Z',
    requester_id: 'caller-a', receiver_id: 'receiver-b', presenter_id: 'relay-r',
    task_id: 'example-task', context_id: 'example-context', nonce: 'example-nonce',
    tool: 'interop.echo', arguments: { payload: 'synthetic example' },
  };
  const action = { type: request.tool, target: request.task_id, payload_digest: digest(request.arguments) };
  request.mandate = {
    schema: 'authorized-invocation/v1', relationship: 'MANDATE', mandate_id: 'example-mandate',
    requester_id: request.requester_id, executor_id: request.receiver_id, request_id: request.task_id,
    nonce: request.nonce, action_digest: digest(action), not_before: '2026-08-18T11:00:00Z',
    expires_at: '2026-08-18T13:00:00Z', signature: 'MODELED-NOT-A-CRYPTOGRAPHIC-SIGNATURE',
  };
  const predicate = {
    schema: 'crossing-relay-attestation/v0', relay_id: request.presenter_id,
    upstream_peer: request.requester_id, requester_id: request.requester_id, downstream: request.receiver_id,
    task_id: request.task_id, context_id: request.context_id, action_digest: digest(action),
    mandate_digest: digest(request.mandate), nonce: request.nonce,
    not_before: '2026-08-18T11:45:00Z', expires_at: '2026-08-18T12:10:00Z',
  };
  const statement = { _type: 'https://in-toto.io/Statement/v1', predicateType: PREDICATE_TYPE,
    subject: [{ name: 'relay-attestation', digest: { sha256: hash(jcs(predicate)) } }], predicate };
  const message = { messageId: 'example-message', taskId: request.task_id, contextId: request.context_id,
    extensions: [EXTENSION], metadata: { crossing_relay: { attestation_ref: { media_type: PAYLOAD_TYPE, digest: '' } } } };
  const policy = { profile: PROFILE, digest_basis: 'rfc8785-jcs',
    verification_keys: [{ keyid: 'example-test-key', key_sha256: keyHash, spki_der_base64: der.toString('base64') }],
    relay_roles: [{ key_sha256: keyHash, relay_id: request.presenter_id, receiver_id: request.receiver_id, predicate_type: PREDICATE_TYPE }] };
  const packet = { message, envelope: null, request, policy };
  function seal({ refreshSubject = true, payload = null } = {}) {
    if (refreshSubject) statement.subject[0].digest.sha256 = hash(jcs(statement.predicate));
    const body = payload ?? jcs(statement);
    // Independently spell out PAE in the producer; do not call the receiver.
    const type = Buffer.from(PAYLOAD_TYPE);
    const signingInput = Buffer.concat([Buffer.from('DSSEv1 ' + type.length + ' '), type,
      Buffer.from(' ' + body.length + ' '), body]);
    packet.envelope = { payloadType: PAYLOAD_TYPE, payload: body.toString('base64'),
      signatures: [{ keyid: 'example-test-key', sig: sign(null, signingInput, privateKey).toString('base64') }] };
    refreshReference();
  }
  function refreshReference() { message.metadata.crossing_relay.attestation_ref.digest = digest(packet.envelope); }
  function inputs() { return Object.fromEntries(Object.entries(packet).map(([name, value]) => [name, bytes(value)])); }
  seal();
  return { packet, statement, seal, refreshReference, inputs };
}

export function writeDemo(output) {
  // mkdir without recursive mode refuses to overwrite an existing destination.
  mkdirSync(output);
  const cases = [
    ['normal', 'matched', f => {}],
    ['different-caller', 'mismatched', f => { f.statement.predicate.upstream_peer = 'caller-c'; f.seal(); }],
    ['missing-key', 'not_assessed', f => { f.packet.policy.verification_keys = []; f.packet.policy.relay_roles = []; }],
    ['invalid-signature', 'mismatched', f => {
      const sig = Buffer.from(f.packet.envelope.signatures[0].sig, 'base64'); sig[0] ^= 1;
      f.packet.envelope.signatures[0].sig = sig.toString('base64'); f.refreshReference();
    }],
    ['untrusted-relay', 'mismatched', f => { f.packet.policy.relay_roles = []; }],
  ];
  const manifest = { kind: 'synthetic-border-receiving-examples', private_keys_saved: false, cases: [] };
  for (const [name, expected, change] of cases) {
    const f = fixture(); change(f);
    const dir = join(output, name); mkdirSync(dir);
    const files = {};
    for (const [input, raw] of Object.entries(f.inputs())) {
      writeFileSync(join(dir, input + '.json'), raw, { flag: 'wx' });
      files[input] = { bytes: raw.length, sha256: hash(raw) };
    }
    manifest.cases.push({ name, expected_checks_status: expected, inputs: files });
  }
  writeFileSync(join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
  return manifest;
}
if (import.meta.main) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== '--output') throw new Error('usage');
    const manifest = writeDemo(resolve(process.argv[3]));
    process.stdout.write(JSON.stringify({ cases: manifest.cases.length, private_keys_saved: false }) + '\n');
  } catch {
    process.stderr.write('Use --output NEW_DIRECTORY with an existing parent; output is never overwritten.\n');
    process.exitCode = 64;
  }
}
