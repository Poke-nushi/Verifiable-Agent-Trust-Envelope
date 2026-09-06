import assert from 'node:assert/strict';

/** Assemble the three requests using one call to the supplied native issueMandate. */
export async function constructRequests(issueMandate, packet) {
  assert.equal(typeof issueMandate, 'function');
  assert.deepEqual(packet.request_contexts.map(row => row.id), ['P', 'N1', 'N2']);
  assert.match(packet.issuance.operator_private_key_hex, /^[0-9a-f]{64}$/);
  const issued = await issueMandate({
    ...structuredClone(packet.issuance.options),
    operatorPrivateKey: Buffer.from(packet.issuance.operator_private_key_hex, 'hex'),
  });
  assert.equal(typeof issued.presentation, 'string');
  assert.ok(issued.presentation.length > 0);
  assert.deepEqual(issued.capabilities, ['mpp:financial:small']);
  assert.match(issued.operatorPublicKey.x, /^[0-9]+$/);
  assert.match(issued.operatorPublicKey.y, /^[0-9]+$/);

  return {
    issued,
    trustedOperators: [structuredClone(issued.operatorPublicKey)],
    requests: packet.request_contexts.map(row => ({
      id: row.id,
      input: {
        ...structuredClone(packet.evc_common),
        bundle: issued.presentation,
        request: structuredClone(row.request),
      },
    })),
  };
}
