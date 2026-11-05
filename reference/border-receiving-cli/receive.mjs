// Experimental CROSSING-002 receiver; no execution or network operations.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { canonicalizeJcsJson, JCS_INPUT_LIMITS, JcsInputError } from '../../packages/vate-core-ts/dist/index.js';

export const PROFILE = 'border-crossing-002-ed25519-v0';
export const PAYLOAD_TYPE = 'application/vnd.in-toto+json';
export const PREDICATE_TYPE = 'https://minority-prophet.dev/experiments/a2a-mcp-crossing-002/relay-attestation/v0';
export const EXTENSION = 'https://minority-prophet.dev/experiments/a2a-mcp-crossing-002/relay/v0';
export const MAX_BYTES = JCS_INPUT_LIMITS.maxBytes;
const KIND = 'border-crossing-002-receiving-check';
const SPKI_PREFIX = '302a300506032b6570032100';
const HEX = /^[0-9a-f]{64}$/;
const NATIVE_DIGEST = /^sha256:[0-9a-f]{64}$/;
// Public encoded-point constants, as listed by libsodium 1.0.18. See NOTICE.
// Compare y with its sign bit masked; this covers both signs of every torsion point.
const SMALL_ORDER_Y = new Set([
  '00'.repeat(32), '01' + '00'.repeat(31),
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ec' + 'ff'.repeat(30) + '7f',
]);
const FIELD_P = (1n << 255n) - 19n;
const SCALAR_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const littleInteger = raw => BigInt('0x' + Buffer.from(raw).reverse().toString('hex'));
function canonicalNonSmallOrderPoint(raw) {
  const y = Buffer.from(raw);
  y[31] &= 0x7f;
  return littleInteger(y) < FIELD_P && !SMALL_ORDER_Y.has(y.toString('hex'));
}
const INPUTS = ['message', 'envelope', 'request', 'policy'];
const CHECKS = ['format', 'envelope_reference', 'payload_canonical', 'subject_digest',
  'signature', 'relay_role', 'action_digest', 'mandate_digest', 'requester_binding',
  'task_context_binding', 'receiver_binding', 'presenter_binding', 'nonce_binding', 'validity_window'];
const BINDINGS = CHECKS.filter(name => !['signature', 'relay_role'].includes(name));
export const sha256 = raw => createHash('sha256').update(raw).digest('hex');
const jsonBytes = value => Buffer.from(JSON.stringify(value));
const canonical = (value, input) => validatedJcsBytes(jsonBytes(value), input);
const digest = (value, input) => 'sha256:' + sha256(canonical(value, input));
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, fields) => object(value) && Object.keys(value).length === fields.length && fields.every(k => Object.hasOwn(value, k));
const identifier = value => typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\x00-\x20\x7f]/.test(value);

export class InputError extends Error {
  constructor(code, input) {
    super(code);
    this.name = 'InputError';
    this.code = code;
    this.input = input;
  }
}
function requireInput(condition, code, input) {
  if (!condition) throw new InputError(code, input);
}
function validatedJcsBytes(raw, input) {
  try {
    return Buffer.from(canonicalizeJcsJson(raw));
  } catch (error) {
    if (error instanceof JcsInputError) throw new InputError('JCS_' + error.code.toUpperCase(), input);
    throw error;
  }
}
function parse(raw, input) {
  requireInput(raw instanceof Uint8Array, 'INVALID_BYTES', input);
  return JSON.parse(validatedJcsBytes(raw, input).toString('utf8'));
}
function decodeBase64(value, input) {
  requireInput(typeof value === 'string' && value.length > 0 && value.length <= MAX_BYTES &&
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value), 'INVALID_BASE64', input);
  const raw = Buffer.from(value, 'base64');
  requireInput(raw.toString('base64') === value, 'NONCANONICAL_BASE64', input);
  return raw;
}
function timestamp(value, input) {
  requireInput(typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value), 'INVALID_TIMESTAMP', input);
  const time = Date.parse(value);
  const normalized = value.includes('.') ? value : value.replace('Z', '.000Z');
  requireInput(Number.isFinite(time) && new Date(time).toISOString() === normalized, 'INVALID_TIMESTAMP', input);
  return time;
}

/** DSSE v1 PAE covers exact payload bytes; keyid is only an untrusted hint. */
export function pae(payloadType, payload) {
  const type = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([Buffer.from(`DSSEv1 ${type.length} `), type,
    Buffer.from(` ${payload.length} `), payload]);
}

function receiverPolicy(policy) {
  requireInput(exact(policy, ['profile', 'digest_basis', 'verification_keys', 'relay_roles']) &&
    policy.profile === PROFILE && policy.digest_basis === 'rfc8785-jcs', 'UNSUPPORTED_RECEIVER_POLICY', 'policy');
  requireInput(Array.isArray(policy.verification_keys) && policy.verification_keys.length <= 16 &&
    Array.isArray(policy.relay_roles) && policy.relay_roles.length <= 32, 'INVALID_POLICY_COLLECTION', 'policy');
  const keys = new Map();
  const hashes = new Set();
  for (const item of policy.verification_keys) {
    requireInput(exact(item, ['keyid', 'key_sha256', 'spki_der_base64']) && identifier(item.keyid) &&
      typeof item.key_sha256 === 'string' && HEX.test(item.key_sha256), 'INVALID_KEY_ENTRY', 'policy');
    const der = decodeBase64(item.spki_der_base64, 'policy');
    requireInput(der.length === 44 && der.toString('hex').startsWith(SPKI_PREFIX) && sha256(der) === item.key_sha256 &&
      !keys.has(item.keyid) && !hashes.has(item.key_sha256), 'INVALID_OR_DUPLICATE_ED25519_KEY', 'policy');
    requireInput(canonicalNonSmallOrderPoint(der.subarray(12)), 'UNSUPPORTED_ED25519_POINT', 'policy');
    let key;
    try {
      key = createPublicKey({ key: der, type: 'spki', format: 'der' });
    } catch {
      throw new InputError('INVALID_ED25519_KEY', 'policy');
    }
    requireInput(key.asymmetricKeyType === 'ed25519', 'INVALID_ED25519_KEY', 'policy');
    keys.set(item.keyid, { key, hash: item.key_sha256 });
    hashes.add(item.key_sha256);
  }
  const roles = new Set();
  for (const role of policy.relay_roles) {
    requireInput(exact(role, ['key_sha256', 'relay_id', 'receiver_id', 'predicate_type']) &&
      hashes.has(role.key_sha256) && identifier(role.relay_id) && identifier(role.receiver_id) &&
      role.predicate_type === PREDICATE_TYPE, 'INVALID_RELAY_ROLE', 'policy');
    const id = JSON.stringify([role.key_sha256, role.relay_id, role.receiver_id, role.predicate_type]);
    requireInput(!roles.has(id), 'DUPLICATE_RELAY_ROLE', 'policy');
    roles.add(id);
  }
  return { keys, roles };
}

function receiverRequest(request) {
  requireInput(exact(request, ['authority_context', 'evaluation_time', 'requester_id', 'receiver_id',
    'presenter_id', 'task_id', 'context_id', 'nonce', 'tool', 'arguments', 'mandate']) &&
    request.authority_context === 'modeled' && object(request.arguments), 'UNSUPPORTED_RECEIVER_REQUEST', 'request');
  for (const key of ['requester_id', 'receiver_id', 'presenter_id', 'task_id', 'context_id', 'nonce', 'tool']) {
    requireInput(identifier(request[key]), 'INVALID_REQUEST_IDENTIFIER', 'request');
  }
  const mandate = request.mandate;
  requireInput(object(mandate) && mandate.schema === 'authorized-invocation/v1' && mandate.relationship === 'MANDATE',
    'UNSUPPORTED_MANDATE', 'request');
  for (const key of ['requester_id', 'executor_id', 'request_id', 'nonce']) {
    requireInput(identifier(mandate[key]), 'INVALID_MANDATE_IDENTIFIER', 'request');
  }
  requireInput(typeof mandate.action_digest === 'string' && NATIVE_DIGEST.test(mandate.action_digest), 'INVALID_MANDATE_DIGEST', 'request');
  return {
    now: timestamp(request.evaluation_time, 'request'),
    start: timestamp(mandate.not_before, 'request'),
    end: timestamp(mandate.expires_at, 'request'),
    action: { type: request.tool, target: request.task_id, payload_digest: digest(request.arguments, 'request') },
  };
}

/** All four parameters are original UTF-8 bytes, never pre-parsed objects. */
export function assessBorderRelay(inputs) {
  const raw = {};
  const parsed = {};
  for (const name of INPUTS) {
    requireInput(inputs?.[name] instanceof Uint8Array && inputs[name].byteLength <= MAX_BYTES, 'INVALID_OR_OVERSIZED_INPUT', name);
    raw[name] = Buffer.from(inputs[name]);
    parsed[name] = parse(raw[name], name);
  }
  const { message, envelope, request, policy } = parsed;
  const trusted = receiverPolicy(policy);
  const expected = receiverRequest(request);
  const report = {
    kind: KIND, profile: PROFILE, checks_status: 'not_assessed',
    inputs: Object.fromEntries(INPUTS.map(name => [name, { sha256: sha256(raw[name]), bytes: raw[name].length }])),
    checks: Object.fromEntries(CHECKS.map(name => [name, { status: 'not_assessed', reason: 'NOT_EVALUATED' }])),
    authenticated_relay_bindings: 'not_assessed',
    evidence: { payload_sha256: null, signing_input_sha256: null, selected_key_sha256: null },
    not_assessed: ['mandate_and_authority_signatures', 'actual_peer_authentication', 'live_key_status',
      'durable_replay_protection', 'execution_permission', 'execution_outcome'],
  };
  const set = (name, status, reason) => { report.checks[name] = { status, reason }; };
  const match = (name, condition, reason) => set(name, condition ? 'matched' : 'mismatched', condition ? 'MATCHED' : reason);
  const finish = () => {
    const states = Object.values(report.checks).map(check => check.status);
    report.checks_status = states.includes('error') ? 'error' : states.includes('mismatched') ? 'mismatched'
      : states.includes('not_assessed') ? 'not_assessed' : 'matched';
    if (report.checks.signature.status === 'verified' && report.checks.relay_role.status === 'matched') {
      report.authenticated_relay_bindings = BINDINGS.every(name => report.checks[name].status === 'matched') ? 'matched' : 'mismatched';
    }
    return report;
  };

  requireInput(object(message) && identifier(message.taskId) && identifier(message.contextId) &&
    Array.isArray(message.extensions) && message.extensions.every(identifier) && object(message.metadata) &&
    exact(message.metadata.crossing_relay, ['attestation_ref']) &&
    exact(message.metadata.crossing_relay.attestation_ref, ['media_type', 'digest']), 'INVALID_MESSAGE', 'message');
  const reference = message.metadata.crossing_relay.attestation_ref;
  requireInput(typeof reference.digest === 'string' && NATIVE_DIGEST.test(reference.digest) &&
    typeof reference.media_type === 'string', 'INVALID_ATTESTATION_REFERENCE', 'message');
  requireInput(object(envelope), 'INVALID_ENVELOPE', 'envelope');
  if (!exact(envelope, ['payloadType', 'payload', 'signatures']) || envelope.payloadType !== PAYLOAD_TYPE ||
      !Array.isArray(envelope.signatures) || envelope.signatures.length !== 1 ||
      !exact(envelope.signatures[0], ['keyid', 'sig'])) {
    set('format', 'not_assessed', 'UNSUPPORTED_ENVELOPE');
    return finish();
  }
  requireInput(identifier(envelope.signatures[0].keyid), 'INVALID_KEY_HINT', 'envelope');
  const payload = decodeBase64(envelope.payload, 'envelope');
  const signature = decodeBase64(envelope.signatures[0].sig, 'envelope');
  requireInput(signature.length === 64, 'INVALID_ED25519_SIGNATURE_LENGTH', 'envelope');
  requireInput(canonicalNonSmallOrderPoint(signature.subarray(0, 32)) && littleInteger(signature.subarray(32)) < SCALAR_L,
    'INVALID_ED25519_SIGNATURE_ENCODING', 'envelope');
  const statement = parse(payload, 'payload');
  report.evidence.payload_sha256 = sha256(payload);
  const signingInput = pae(envelope.payloadType, payload);
  report.evidence.signing_input_sha256 = sha256(signingInput);
  if (!exact(statement, ['_type', 'predicateType', 'predicate', 'subject']) ||
      statement._type !== 'https://in-toto.io/Statement/v1' || statement.predicateType !== PREDICATE_TYPE ||
      !object(statement.predicate) || statement.predicate.schema !== 'crossing-relay-attestation/v0') {
    set('format', 'not_assessed', 'UNSUPPORTED_STATEMENT');
    return finish();
  }
  const att = statement.predicate;
  requireInput(exact(att, ['schema', 'relay_id', 'upstream_peer', 'requester_id', 'downstream', 'task_id',
    'context_id', 'action_digest', 'mandate_digest', 'nonce', 'not_before', 'expires_at']), 'INVALID_PREDICATE', 'payload');
  for (const key of ['relay_id', 'upstream_peer', 'requester_id', 'downstream', 'task_id', 'context_id', 'nonce']) {
    requireInput(identifier(att[key]), 'INVALID_ATTESTED_IDENTIFIER', 'payload');
  }
  requireInput([att.action_digest, att.mandate_digest].every(v => typeof v === 'string' && NATIVE_DIGEST.test(v)) &&
    Array.isArray(statement.subject) && statement.subject.length === 1 &&
    exact(statement.subject[0], ['name', 'digest']) && statement.subject[0].name === 'relay-attestation' &&
    exact(statement.subject[0].digest, ['sha256']) && typeof statement.subject[0].digest.sha256 === 'string' &&
    HEX.test(statement.subject[0].digest.sha256), 'INVALID_STATEMENT_DIGEST', 'payload');
  const start = timestamp(att.not_before, 'payload');
  const end = timestamp(att.expires_at, 'payload');
  match('format', reference.media_type === PAYLOAD_TYPE && message.extensions.filter(v => v === EXTENSION).length === 1, 'MESSAGE_PROFILE_MISMATCH');
  match('envelope_reference', digest(envelope, 'envelope') === reference.digest, 'ENVELOPE_REFERENCE_MISMATCH');
  match('payload_canonical', validatedJcsBytes(payload, 'payload').equals(payload), 'PAYLOAD_NOT_JCS_BYTES');
  match('subject_digest', sha256(canonical(att, 'payload')) === statement.subject[0].digest.sha256, 'SUBJECT_DIGEST_MISMATCH');
  const selected = trusted.keys.get(envelope.signatures[0].keyid);
  if (!selected) {
    set('signature', 'not_assessed', 'KEY_NOT_PROVIDED');
  } else {
    report.evidence.selected_key_sha256 = selected.hash;
    try {
      const verified = verify(null, signingInput, selected.key, signature);
      set('signature', verified ? 'verified' : 'mismatched', verified ? 'SIGNATURE_VERIFIED' : 'SIGNATURE_MISMATCH');
    } catch {
      set('signature', 'error', 'CRYPTO_BACKEND_ERROR');
    }
  }
  if (report.checks.signature.status === 'verified') {
    const role = JSON.stringify([selected.hash, att.relay_id, request.receiver_id, statement.predicateType]);
    match('relay_role', trusted.roles.has(role), 'RELAY_ROLE_NOT_GRANTED');
  } else {
    set('relay_role', 'not_assessed', 'SIGNATURE_NOT_VERIFIED');
  }
  match('action_digest', digest(expected.action, 'request') === att.action_digest && att.action_digest === request.mandate.action_digest, 'ACTION_DIGEST_MISMATCH');
  match('mandate_digest', digest(request.mandate, 'request') === att.mandate_digest, 'MANDATE_DIGEST_MISMATCH');
  match('requester_binding', att.upstream_peer === request.requester_id && att.requester_id === request.requester_id &&
    request.mandate.requester_id === request.requester_id, 'REQUESTER_BINDING_MISMATCH');
  match('task_context_binding', message.taskId === request.task_id && att.task_id === request.task_id &&
    request.mandate.request_id === request.task_id && message.contextId === request.context_id && att.context_id === request.context_id,
  'TASK_CONTEXT_BINDING_MISMATCH');
  match('receiver_binding', att.downstream === request.receiver_id && request.mandate.executor_id === request.receiver_id, 'RECEIVER_BINDING_MISMATCH');
  match('presenter_binding', request.presenter_id === att.relay_id, 'PRESENTER_BINDING_MISMATCH');
  match('nonce_binding', request.nonce === att.nonce && request.mandate.nonce === request.nonce, 'NONCE_BINDING_MISMATCH');
  match('validity_window', start < end && start <= expected.now && expected.now < end &&
    expected.start < expected.end && expected.start <= expected.now && expected.now < expected.end, 'OUTSIDE_VALIDITY_WINDOW');
  return finish();
}

/** Local regular files only. Bounded read also handles growth after fstat. */
export function readInputFile(path, input) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (constants.O_NOFOLLOW ?? 0));
    const info = fstatSync(fd);
    requireInput(info.isFile() && info.size <= MAX_BYTES, 'NOT_A_BOUNDED_REGULAR_FILE', input);
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let count = 0;
    while (count < buffer.length) {
      const got = readSync(fd, buffer, count, buffer.length - count, null);
      if (got === 0) break;
      count += got;
    }
    requireInput(count <= MAX_BYTES, 'INPUT_TOO_LARGE', input);
    return buffer.subarray(0, count);
  } catch (error) {
    if (error instanceof InputError) throw error;
    throw new InputError('INPUT_FILE_UNREADABLE', input);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export function main(args) {
  if (args.length === 1 && args[0] === '--help') {
    process.stdout.write('Usage: node receive.mjs --message FILE --envelope FILE --request FILE --policy FILE\n');
    return 0;
  }
  try {
    requireInput(args.length === 8, 'USAGE', 'arguments');
    const files = new Map();
    for (let i = 0; i < args.length; i += 2) {
      const name = args[i].slice(2);
      requireInput(args[i].startsWith('--') && INPUTS.includes(name) && !files.has(name) &&
        typeof args[i + 1] === 'string' && !args[i + 1].startsWith('--'), 'USAGE', 'arguments');
      files.set(name, args[i + 1]);
    }
    const report = assessBorderRelay(Object.fromEntries(INPUTS.map(name => [name, readInputFile(files.get(name), name)])));
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    return report.checks_status === 'error' ? 70 : 0;
  } catch (error) {
    const known = error instanceof InputError;
    process.stdout.write(JSON.stringify({ kind: KIND, profile: PROFILE, checks_status: known ? 'invalid_input' : 'error',
      reason: known ? error.code : 'INTERNAL_ERROR', input: known ? error.input : null }) + '\n');
    return known ? 64 : 70;
  }
}
if (typeof import.meta.main !== 'boolean') {
  throw new Error('Node.js with import.meta.main is required (22.18.0+ on Node 22).');
}
if (import.meta.main) {
  process.exitCode = main(process.argv.slice(2));
}
