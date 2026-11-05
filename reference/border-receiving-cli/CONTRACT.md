# CROSSING-002 receiving contract

This is the local contract for `receive.mjs`, selected explicitly by
`policy.profile = border-crossing-002-ed25519-v0` and
`policy.digest_basis = rfc8785-jcs`. It does not change a VATE profile, schema,
corpus digest basis, admission decision or receipt type.

## Supported evidence

The source format is the relay experiment in
[Border `78b592b87d50a8634350c8afed32ef4b228a264d`](https://github.com/Silentpartnercoding/minority-prophet-border/tree/78b592b87d50a8634350c8afed32ef4b228a264d/experiments/a2a-mcp-crossing-002).
The receiver is implemented here; the synthetic demo is separate from that
experiment's original captures.

- Message extension: `https://minority-prophet.dev/experiments/a2a-mcp-crossing-002/relay/v0`.
- Reference media type and DSSE payload type: `application/vnd.in-toto+json`.
- Statement `_type`: `https://in-toto.io/Statement/v1`.
- Predicate type: `https://minority-prophet.dev/experiments/a2a-mcp-crossing-002/relay-attestation/v0`.
- Predicate schema: `crossing-relay-attestation/v0`.
- One subject named `relay-attestation` with a lowercase 64-hex SHA-256 digest.
- One Ed25519 signature, with required `keyid` and standard padded base64 `sig`.
- Modeled mandate schema `authorized-invocation/v1`, relationship `MANDATE`.

The envelope, signature item, statement and predicate have closed field sets.
Other envelope/statement versions and multiple signatures return
`not_assessed`; they are not retried as JWS, another DSSE profile or another
digest basis. The policy and request also have closed field sets. Unknown
receiver configuration is an input error.

The A2A message can contain other members, but the selected relay metadata
contains only `attestation_ref`, whose fields are `media_type` and `digest`.
The required relay extension occurs once. This receiver does not validate the
whole A2A message or other extensions.

## Bytes and signatures

All four JSON files and the decoded payload pass the existing VATE JCS input
validator on original bytes. The envelope reference hashes its JCS form,
including its signature. The subject digest hashes the JCS predicate. The
mandate digest hashes the whole supplied mandate. `sha256:` prefixes are
required on native references; the subject uses bare lowercase hex.

The receiver derives the expected action from the supplied request:

```text
action = {
  type: request.tool,
  target: request.task_id,
  payload_digest: "sha256:" + SHA256(JCS(request.arguments))
}
```

Its JCS digest must equal both the relay's `action_digest` and the supplied
mandate's `action_digest`. No digest is selected by trying alternatives.

Ed25519 verifies the
[DSSE v1 PAE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
of the exact decoded payload:

```text
"DSSEv1 " + byte_length(payloadType) + " " + UTF8(payloadType)
  + " " + byte_length(payload) + " " + payload
```

The payload is not reserialized before signature verification. Its equality
to JCS bytes is a separate check. Base64 must round-trip exactly. Verification
uses Node's `crypto.verify(null, paeBytes, ed25519Key, signature)`.

`keyid` is an unauthenticated lookup hint. Only receiver-selected keys are
used; no URL, embedded key or alternative key is tried. Public keys must be
44-byte RFC 8410 Ed25519 SPKI DER with prefix `302a300506032b6570032100`, a
matching SHA-256 and a unique key ID/hash. A separate role names the key hash,
relay ID, receiver ID and predicate type. A signature alone grants no role.

The receiver rejects noncanonical encodings and the known small-order points
for both the public key and signature R, and requires signature S below the
Ed25519 group order. The point constants are identified in [NOTICE](NOTICE).
These input checks precede Node/OpenSSL verification; they do not implement
elliptic-curve verification or establish key ownership and current status.

## Binding and time checks

All comparisons use exact string equality; this contract supports one hop
without task/context ID translation.

| Check | Required correspondence |
| --- | --- |
| Requester | Signed `upstream_peer` and `requester_id`, expected requester, and mandate requester agree. |
| Task/context | Message, signed predicate and expected task/context agree; mandate `request_id` equals expected task. |
| Receiver | Signed `downstream`, expected receiver, and mandate executor agree. |
| Presenter | Expected session presenter equals the signed relay ID. Its actual authentication is outside this checker. |
| Nonce | Signed, expected and mandate nonces agree. This is equality, not persistent consumption. |
| Time | Explicit evaluation time is inside both relay and mandate intervals: `not_before <= time < expires_at`, with start strictly before end. |

Timestamps use UTC `YYYY-MM-DDTHH:mm:ssZ` or exactly three fractional digits.
Invalid calendar dates, offsets and leap seconds are input errors. A historical
evaluation time produces a historical assessment, not current validity.

The mandate's remaining fields are preserved in its digest, not independently
validated. Request authority, executor authority and credential proofs are not
evaluated. The required `authority_context: modeled` keeps that distinction in
the input contract; arbitrary authority strings are never accepted as proof.

## Results and resource limits

Checks use `matched`, `mismatched`, `not_assessed`, `error`, or the signature's
`verified`. Summary precedence is error, mismatch, not assessed, then matched.
Known mismatches may be reported from unverified content; the separate
`authenticated_relay_bindings` stays `not_assessed` until signature and role
both succeed. A matched result means only the selected checks matched the
receiver's inputs.

Input/configuration/file/argument errors instead emit a compact JSON object
with `kind`, `profile`, `checks_status: "invalid_input"`, `reason` and `input`,
and exit 64. Unhandled internal errors use the same shape with status `error`
and exit 70. A cryptographic-backend error caught during evaluation retains
the evaluation report with the signature check set to `error` and exits 70.
Compact reports do not contain individual checks or input/evidence hashes.

Every raw input and each derived JSON serialization submitted to the JCS helper
is limited to 1 MiB, with JCS nesting limited to 64. Numeric canonicalization
can expand a short spelling. If a derived serialization exceeds the limit,
the CLI returns `invalid_input`, `JCS_INPUT_TOO_LARGE` and the source input name,
with exit 64. Policy lists are limited to 16 keys and 32 roles.
IDs are 1–256 characters without ASCII control
characters or spaces. Paths come only from CLI arguments, not document fields.
Regular-file reads are bounded and reject final symlinks where the platform
provides `O_NOFOLLOW`. Output contains input hashes, not copied input contents.

No network, tool execution, persistent nonce store, key-status fetch, receipt
issuance or report signing is performed. A caller must treat the JSON report
as local evaluation output, not an authenticated transferable receipt.
