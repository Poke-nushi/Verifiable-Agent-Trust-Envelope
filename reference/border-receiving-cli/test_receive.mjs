import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { assessBorderRelay, InputError, MAX_BYTES, pae, readInputFile } from './receive.mjs';
import { digest, fixture, writeDemo } from './demo.mjs';

const cli = fileURLToPath(new URL('./receive.mjs', import.meta.url));
const demoCli = fileURLToPath(new URL('./demo.mjs', import.meta.url));
const assess = f => assessBorderRelay(f.inputs());
const check = (result, name, status, reason) => {
  assert.equal(result.checks[name].status, status);
  if (reason) assert.equal(result.checks[name].reason, reason);
};
const rejected = (inputs, input, code) => assert.throws(() => assessBorderRelay(inputs),
  error => error instanceof InputError && error.input === input && (!code || error.code === code));

test('normal signed record satisfies the bounded checks, never grants execution', () => {
  const f = fixture(); const result = assess(f);
  assert.equal(result.checks_status, 'matched');
  assert.equal(result.authenticated_relay_bindings, 'matched');
  check(result, 'signature', 'verified');
  assert.ok(result.not_assessed.includes('execution_permission'));
  assert.ok(result.not_assessed.includes('mandate_and_authority_signatures'));
  for (const [name, raw] of Object.entries(f.inputs())) {
    assert.equal(result.inputs[name].sha256, createHash('sha256').update(raw).digest('hex'));
  }
});
test('valid signature with another authenticated caller is a binding mismatch', () => {
  const f = fixture(); f.statement.predicate.upstream_peer = 'caller-c'; f.seal();
  const r = assess(f); check(r, 'signature', 'verified');
  check(r, 'requester_binding', 'mismatched', 'REQUESTER_BINDING_MISMATCH');
  assert.equal(r.authenticated_relay_bindings, 'mismatched');
});
test('no key remains unassessed even when all visible bindings match', () => {
  const f = fixture(); f.packet.policy.verification_keys = []; f.packet.policy.relay_roles = [];
  const r = assess(f); check(r, 'signature', 'not_assessed', 'KEY_NOT_PROVIDED');
  assert.equal(r.checks_status, 'not_assessed'); assert.equal(r.authenticated_relay_bindings, 'not_assessed');
});
test('unverified content can expose a mismatch without becoming authenticated', () => {
  const f = fixture(); f.packet.policy.verification_keys = []; f.packet.policy.relay_roles = [];
  f.statement.predicate.upstream_peer = 'caller-c'; f.seal(); const r = assess(f);
  assert.equal(r.checks_status, 'mismatched'); assert.equal(r.authenticated_relay_bindings, 'not_assessed');
});
test('a cryptographically valid key does not supply a relay role', () => {
  const f = fixture(); f.packet.policy.relay_roles = [];
  const r = assess(f); check(r, 'signature', 'verified'); check(r, 'relay_role', 'mismatched', 'RELAY_ROLE_NOT_GRANTED');
  assert.equal(r.authenticated_relay_bindings, 'not_assessed');
});
test('corrupted signature is distinct from missing key', () => {
  const f = fixture(); const sig = Buffer.from(f.packet.envelope.signatures[0].sig, 'base64'); sig[12] ^= 1;
  f.packet.envelope.signatures[0].sig = sig.toString('base64'); f.refreshReference();
  const r = assess(f); check(r, 'signature', 'mismatched', 'SIGNATURE_MISMATCH');
  check(r, 'relay_role', 'not_assessed'); assert.equal(r.authenticated_relay_bindings, 'not_assessed');
});
test('a different receiver-selected Ed25519 key does not validate the old signature', () => {
  const f = fixture(); f.packet.policy = fixture().packet.policy;
  check(assess(f), 'signature', 'mismatched', 'SIGNATURE_MISMATCH');
});
test('keyid is not treated as signed authority or a fallback to another key', () => {
  const f = fixture(); f.packet.envelope.signatures[0].keyid = 'unknown'; f.refreshReference();
  check(assess(f), 'signature', 'not_assessed', 'KEY_NOT_PROVIDED');
});
test('DSSE PAE uses byte lengths and exact body', () => {
  assert.equal(pae('é', Buffer.from('✓')).toString('utf8'), 'DSSEv1 2 é 3 ✓');
  const f = fixture(); const raw = Buffer.from(f.packet.envelope.payload, 'base64');
  const key = createPublicKey({key: Buffer.from(f.packet.policy.verification_keys[0].spki_der_base64, 'base64'), format: 'der', type: 'spki'});
  assert.equal(verify(null, raw, key, Buffer.from(f.packet.envelope.signatures[0].sig, 'base64')), false);
});
test('signed noncanonical JSON is verified on exact bytes but fails the selected byte rule', () => {
  const f = fixture(); f.seal({payload: Buffer.from(JSON.stringify(f.statement, null, 2))});
  const r = assess(f); check(r, 'signature', 'verified'); check(r, 'payload_canonical', 'mismatched');
});
test('changing payload serialization without resigning fails the signature', () => {
  const f = fixture(); f.packet.envelope.payload = Buffer.from(JSON.stringify(f.statement, null, 2)).toString('base64'); f.refreshReference();
  check(assess(f), 'signature', 'mismatched');
});

const bindingMutations = [
  ['message task', f => { f.packet.message.taskId = 'other'; }, 'task_context_binding'],
  ['message context', f => { f.packet.message.contextId = 'other'; }, 'task_context_binding'],
  ['expected task', f => { f.packet.request.task_id = 'other'; }, 'task_context_binding'],
  ['expected context', f => { f.packet.request.context_id = 'other'; }, 'task_context_binding'],
  ['expected requester', f => { f.packet.request.requester_id = 'other'; }, 'requester_binding'],
  ['expected receiver', f => { f.packet.request.receiver_id = 'other'; }, 'receiver_binding'],
  ['expected presenter', f => { f.packet.request.presenter_id = 'other'; }, 'presenter_binding'],
  ['expected nonce', f => { f.packet.request.nonce = 'other'; }, 'nonce_binding'],
  ['actual arguments', f => { f.packet.request.arguments.payload = 'changed'; }, 'action_digest'],
  ['actual tool', f => { f.packet.request.tool = 'other'; }, 'action_digest'],
  ['mandate body', f => { f.packet.request.mandate.mandate_id = 'other'; }, 'mandate_digest'],
  ['before validity', f => { f.packet.request.evaluation_time = '2026-08-18T11:44:59Z'; }, 'validity_window'],
  ['at expiry', f => { f.packet.request.evaluation_time = '2026-08-18T12:10:00Z'; }, 'validity_window'],
  ['reference', f => { f.packet.message.metadata.crossing_relay.attestation_ref.digest = 'sha256:' + '0'.repeat(64); }, 'envelope_reference'],
  ['wrong extension', f => { f.packet.message.extensions = ['https://example.invalid/other']; }, 'format'],
  ['wrong media type', f => { f.packet.message.metadata.crossing_relay.attestation_ref.media_type = 'application/json'; }, 'format'],
];
for (const [name, mutate, failed] of bindingMutations) test(name + ' mismatch with a still-valid signature', () => {
  const f = fixture(); mutate(f); const r = assess(f);
  check(r, 'signature', 'verified'); check(r, failed, 'mismatched'); assert.equal(r.checks_status, 'mismatched');
});
const resignedBindingMutations = [
  ['mandate', 'requester_id', 'other', 'requester_binding'],
  ['mandate', 'executor_id', 'other', 'receiver_binding'],
  ['mandate', 'request_id', 'other', 'task_context_binding'],
  ['mandate', 'nonce', 'other', 'nonce_binding'],
  ['mandate', 'action_digest', 'sha256:' + '0'.repeat(64), 'action_digest'],
  ['predicate', 'downstream', 'other', 'receiver_binding'],
  ['predicate', 'task_id', 'other', 'task_context_binding'],
  ['predicate', 'context_id', 'other', 'task_context_binding'],
  ['predicate', 'nonce', 'other', 'nonce_binding'],
];
for (const [source, field, value, failed] of resignedBindingMutations) test(
  source + ' ' + field + ' mismatch survives refreshed digests and signature', () => {
    const f = fixture();
    if (source === 'mandate') {
      f.packet.request.mandate[field] = value;
      f.statement.predicate.mandate_digest = digest(f.packet.request.mandate);
    } else {
      f.statement.predicate[field] = value;
    }
    f.seal();
    const r = assess(f);
    check(r, 'signature', 'verified');
    for (const name of ['relay_role', 'envelope_reference', 'payload_canonical', 'subject_digest', 'mandate_digest']) {
      check(r, name, 'matched');
    }
    check(r, failed, 'mismatched');
    assert.deepEqual(Object.entries(r.checks).filter(([, result]) => result.status === 'mismatched').map(([name]) => name), [failed]);
    assert.equal(r.checks_status, 'mismatched');
    assert.equal(r.authenticated_relay_bindings, 'mismatched');
  });
test('attested requester cannot substitute for upstream identity', () => {
  const f = fixture(); f.statement.predicate.requester_id = 'other'; f.seal();
  check(assess(f), 'requester_binding', 'mismatched');
});
test('signed subject mismatch is not hidden by valid crypto', () => {
  const f = fixture(); f.statement.subject[0].digest.sha256 = 'f'.repeat(64); f.seal({refreshSubject:false});
  const r = assess(f); check(r, 'signature', 'verified'); check(r, 'subject_digest', 'mismatched');
});
test('relay scope binds key digest, named relay, recipient and predicate', () => {
  const f = fixture(); f.statement.predicate.relay_id = 'other-relay'; f.packet.request.presenter_id = 'other-relay'; f.seal();
  const r = assess(f); check(r, 'presenter_binding', 'matched'); check(r, 'relay_role', 'mismatched');
});
test('relay interval with end before start does not match', () => {
  const f = fixture(); f.statement.predicate.expires_at = '2026-08-18T11:40:00Z'; f.seal();
  check(assess(f), 'validity_window', 'mismatched');
});
test('mandate interval is checked independently of relay interval', () => {
  const f = fixture(); f.packet.request.mandate.expires_at = '2026-08-18T12:00:00Z';
  check(assess(f), 'validity_window', 'mismatched');
});
test('validity includes the lower endpoint', () => {
  const f = fixture(); f.packet.request.evaluation_time = '2026-08-18T11:45:00Z';
  check(assess(f), 'validity_window', 'matched');
});

for (const name of ['message', 'envelope', 'request', 'policy']) {
  test(name + ' rejects duplicate names before parsing can erase them', () => {
    const raw = fixture().inputs(); raw[name] = Buffer.from('{"x":1,"x":2}'); rejected(raw, name, 'JCS_DUPLICATE_KEY');
  });
  test(name + ' enforces a byte bound', () => {
    const raw = fixture().inputs(); raw[name] = Buffer.alloc(MAX_BYTES + 1); rejected(raw, name);
  });
}
test('payload rejects duplicate escaped keys before crypto', () => {
  const f = fixture(); f.packet.envelope.payload = Buffer.from('{"x":1,"\\u0078":2}').toString('base64'); f.refreshReference();
  rejected(f.inputs(), 'payload', 'JCS_DUPLICATE_KEY');
});
test('invalid UTF-8 cannot be repaired by decoding', () => {
  const raw = fixture().inputs(); raw.envelope = Buffer.from([0xc0,0xaf]); rejected(raw, 'envelope', 'JCS_INVALID_UTF8');
});
for (const field of ['arguments', 'mandate']) {
  test('canonical expansion in ' + field + ' is a request input error, not an internal failure', () => {
    const f = fixture();
    f.packet.request[field].expanded_numbers = 'NUMERIC_EXPANSION';
    const inputs = f.inputs();
    const numberArray = '[' + Array(50000).fill('1e20').join(',') + ']';
    inputs.request = Buffer.from(inputs.request.toString().replace('"NUMERIC_EXPANSION"', numberArray));
    assert.ok(inputs.request.length < MAX_BYTES);
    rejected(inputs, 'request', 'JCS_INPUT_TOO_LARGE');
    const root = mkdtempSync(join(tmpdir(), 'vate-border-expanded-'));
    try {
      const args = [];
      for (const [name, raw] of Object.entries(inputs)) {
        const path = join(root, name + '.json'); writeFileSync(path, raw);
        args.push('--' + name, path);
      }
      const run = spawnSync(process.execPath, [cli, ...args], {encoding:'utf8'});
      assert.equal(run.status, 64); assert.equal(run.stderr, '');
      const report = JSON.parse(run.stdout);
      assert.equal(report.checks_status, 'invalid_input');
      assert.equal(report.reason, 'JCS_INPUT_TOO_LARGE');
      assert.equal(report.input, 'request');
      assert.ok(!run.stdout.includes(root));
    } finally { rmSync(root, {recursive:true, force:true}); }
    // The same numeric spelling is accepted when the derived JSON fits.
    inputs.request = Buffer.from(inputs.request.toString().replace(numberArray, '[1e20,1e20]'));
    assert.equal(assessBorderRelay(inputs).checks_status, 'mismatched');
  });
}
test('invalid dates do not roll into the next month', () => {
  const f = fixture(); f.packet.request.evaluation_time = '2026-02-30T12:00:00Z'; rejected(f.inputs(), 'request', 'INVALID_TIMESTAMP');
});
test('the policy cannot silently choose another digest basis', () => {
  const f = fixture(); f.packet.policy.digest_basis = 'fixture-json'; rejected(f.inputs(), 'policy', 'UNSUPPORTED_RECEIVER_POLICY');
});
test('unsupported envelope forms return not assessed', () => {
  for (const change of [f=>{f.packet.envelope.payloadType='application/json';}, f=>{f.packet.envelope.signatures.push(f.packet.envelope.signatures[0]);}, f=>{f.packet.envelope.extra=true;}]) {
    const f=fixture(); change(f); const r=assess(f); assert.equal(r.checks_status,'not_assessed');
    check(r,'format','not_assessed','UNSUPPORTED_ENVELOPE');
  }
});
test('another predicate never gets evaluated under the relay contract', () => {
  const f=fixture(); f.statement.predicateType='https://example.invalid/other'; f.seal();
  check(assess(f),'format','not_assessed','UNSUPPORTED_STATEMENT');
});
test('noncanonical base64 and wrong signature lengths are rejected', () => {
  const f=fixture(); f.packet.envelope.signatures[0].sig += '\n'; rejected(f.inputs(),'envelope','INVALID_BASE64');
  f.packet.envelope.signatures[0].sig=Buffer.alloc(63).toString('base64'); rejected(f.inputs(),'envelope','INVALID_ED25519_SIGNATURE_LENGTH');
});
test('ambiguous or corrupt receiver keys and roles are rejected', () => {
  for (const change of [
    f=>f.packet.policy.verification_keys.push(f.packet.policy.verification_keys[0]),
    f=>{f.packet.policy.verification_keys[0].key_sha256='0'.repeat(64);},
    f=>f.packet.policy.relay_roles.push(f.packet.policy.relay_roles[0]),
    f=>{f.packet.policy.relay_roles[0].key_sha256='0'.repeat(64);},
  ]) { const f=fixture(); change(f); rejected(f.inputs(),'policy'); }
});
test('a purported non-modeled authority context is unsupported', () => {
  const f=fixture(); f.packet.request.authority_context='verified'; rejected(f.inputs(),'request','UNSUPPORTED_RECEIVER_REQUEST');
});

test('receiver rejects small-order and noncanonical public points, for both sign bits', () => {
  // Public point encodings from the libsodium 1.0.18 list; see NOTICE.
  const points = ['00'.repeat(32), '01'+'00'.repeat(31),
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    'ec'+'ff'.repeat(30)+'7f', 'ed'+'ff'.repeat(30)+'7f', 'ee'+'ff'.repeat(30)+'7f'];
  for (const hex of points) for (const signBit of [0,128]) {
    const f=fixture(); const point=Buffer.from(hex,'hex'); point[31]|=signBit;
    const der=Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),point]);
    const key=f.packet.policy.verification_keys[0];
    key.spki_der_base64=der.toString('base64');key.key_sha256=createHash('sha256').update(der).digest('hex');
    f.packet.policy.relay_roles[0].key_sha256=key.key_sha256;
    rejected(f.inputs(),'policy','UNSUPPORTED_ED25519_POINT');
  }
});
test('small-order R and noncanonical S are rejected before verification', () => {
  for (const mutate of [s=>{s.fill(0,0,32);s[0]=1;},s=>s.fill(255,32)]) {
    const f=fixture();const sig=Buffer.from(f.packet.envelope.signatures[0].sig,'base64');mutate(sig);
    f.packet.envelope.signatures[0].sig=sig.toString('base64');f.refreshReference();
    rejected(f.inputs(),'envelope','INVALID_ED25519_SIGNATURE_ENCODING');
  }
});

test('CLI demo is portable, emits all five expected outcomes, and does not overwrite input', () => {
  const root=mkdtempSync(join(tmpdir(),'vate-border-cli-'));
  try {
    const dir=join(root,'example with spaces'); const manifest=writeDemo(dir);
    assert.throws(()=>writeDemo(dir));
    for(const item of manifest.cases) {
      const args=['message','envelope','request','policy'].flatMap(name=>['--'+name,join(dir,item.name,name+'.json')]);
      const run=spawnSync(process.execPath,[cli,...args],{cwd:tmpdir(),encoding:'utf8'});
      assert.equal(run.status,0,run.stderr); assert.equal(run.stderr,'');
      const r=JSON.parse(run.stdout); assert.equal(r.checks_status,item.expected_checks_status);
      for(const name of ['message','envelope','request','policy']) assert.equal(r.inputs[name].sha256,item.inputs[name].sha256);
    }
  } finally {rmSync(root,{recursive:true,force:true});}
});
test('CLI reports usage and read errors without leaking input or paths', () => {
  const args=['message','envelope','request','policy'].flatMap(name=>['--'+name,'/missing/private-secret-path']);
  for(const argv of [[],args,[...args.slice(0,6),'--message','file']]) {
    const run=spawnSync(process.execPath,[cli,...argv],{encoding:'utf8'});
    assert.equal(run.status,64); assert.equal(JSON.parse(run.stdout).checks_status,'invalid_input');
    assert.ok(!run.stdout.includes('private-secret')); assert.equal(run.stderr,'');
  }
});
test('symlink entry points generate examples and emit receiving reports, help and usage errors', () => {
  const root = mkdtempSync(join(tmpdir(), 'vate-border-entry-'));
  try {
    const receiverLink = join(root, 'receiver.mjs'), demoLink = join(root, 'generator.mjs');
    symlinkSync(cli, receiverLink); symlinkSync(demoCli, demoLink);
    const dir = join(root, 'generated');
    const generated = spawnSync(process.execPath, [demoLink, '--output', dir], {cwd:tmpdir(), encoding:'utf8'});
    assert.equal(generated.status, 0, generated.stderr);
    assert.deepEqual(JSON.parse(generated.stdout), {cases:5, private_keys_saved:false});
    const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
    for (const item of manifest.cases) {
      const args = ['message','envelope','request','policy'].flatMap(name => ['--' + name, join(dir,item.name,name+'.json')]);
      const run = spawnSync(process.execPath, [receiverLink, ...args], {cwd:tmpdir(), encoding:'utf8'});
      assert.equal(run.status, 0, run.stderr); assert.equal(run.stderr, '');
      assert.equal(JSON.parse(run.stdout).checks_status, item.expected_checks_status);
    }
    const help = spawnSync(process.execPath, [receiverLink, '--help'], {encoding:'utf8'});
    assert.equal(help.status, 0); assert.match(help.stdout, /^Usage: node receive\.mjs /);
    const usage = spawnSync(process.execPath, [receiverLink], {encoding:'utf8'});
    assert.equal(usage.status, 64); assert.equal(JSON.parse(usage.stdout).reason, 'USAGE');
    const duplicate = spawnSync(process.execPath, [demoLink, '--output', dir], {encoding:'utf8'});
    assert.equal(duplicate.status, 64);
  } finally { rmSync(root, {recursive:true, force:true}); }
});
test('importing either module does not execute its CLI even if argv names that file', () => {
  const root = mkdtempSync(join(tmpdir(), 'vate-border-import-'));
  try {
    const dir = join(root, 'must-not-exist');
    for (const [entry, args] of [[cli, ['--help']], [demoCli, ['--output', dir]]]) {
      const source = 'process.argv = ' + JSON.stringify([process.execPath, entry, ...args]) + ';\n' +
        'await import(' + JSON.stringify(pathToFileURL(entry).href) + ');\n' +
        'process.stdout.write("import-only\\n");';
      const run = spawnSync(process.execPath, ['--input-type=module', '--eval', source], {cwd:tmpdir(), encoding:'utf8'});
      assert.equal(run.status, 0, run.stderr); assert.equal(run.stderr, '');
      assert.equal(run.stdout, 'import-only\n'); assert.equal(existsSync(dir), false);
    }
  } finally { rmSync(root, {recursive:true, force:true}); }
});
test('file reader rejects directories and symlinks and detects oversize', () => {
  const dir=mkdtempSync(join(tmpdir(),'vate-border-files-'));
  try {
    const file=join(dir,'input');writeFileSync(file,'{}');
    assert.equal(readInputFile(file,'message').toString(),'{}');
    assert.throws(()=>readInputFile(dir,'message'),InputError);
    if(process.platform!=='win32') {symlinkSync(file,join(dir,'link'));assert.throws(()=>readInputFile(join(dir,'link'),'message'),InputError);}
    writeFileSync(file,Buffer.alloc(MAX_BYTES+1));assert.throws(()=>readInputFile(file,'message'),InputError);
  } finally {rmSync(dir,{recursive:true,force:true});}
});
