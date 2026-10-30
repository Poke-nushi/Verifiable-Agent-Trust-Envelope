# Local JCS / ES256 Receipt Trial Contract

This implementation aid has the explicit adapter selector
`vate-local-jcs-signature-authority-trial-v1` and signature selector
`vate-local-jcs-es256-detached-v1`. Neither is a normative VATE profile or an
IANA-registered media type.

## Signed content

The detached compact JWS is exactly:

```text
BASE64URL(protected_header_bytes)..BASE64URL(signature_bytes)
```

Base64url is unpadded and canonical. The proof is UTF-8 ASCII without BOM,
whitespace or a trailing newline. The signature is the 64-byte ES256 `R || S`
representation, not ASN.1 DER. The protected header is a strict JSON object
with exactly these members:

- `alg`: exactly `ES256`;
- `kid`: the lowercase 64-character SHA-256 of a receiver-selected SPKI DER key;
- `typ`: the receiver's expected record type.

The receipt adapter selects these types:

| Input | Required protected `typ` |
| --- | --- |
| Admission | `urn:vate:local:jcs-es256:admission:v1` |
| Post-execution | `urn:vate:local:jcs-es256:post_execution:v1` |

Duplicate decoded member names, invalid UTF-8, invalid Unicode and malformed
JSON are rejected. No `crit`, `b64`, embedded key, certificate, key URL or other
header extension is accepted. No unprotected header or embedded payload is
accepted. Unknown algorithms and keys do not trigger discovery or fallback.

Header shape is checked before unsupported features. A non-object header,
missing required member, non-string `alg`/`kid`/`typ`, or malformed `kid` is
`invalid/INVALID_DETACHED_JWS`. The `alg` string must be nonempty printable
ASCII without spaces or control characters. Duplicate members, malformed JSON
and invalid Unicode use the same invalid result.

Once these checks pass, additional members produce
`not_assessed/UNSUPPORTED_PROTECTED_HEADER`. With exactly the required members,
an unrecognized algorithm produces `not_assessed/UNSUPPORTED_ALGORITHM`.
For `ES256`, a `typ` different from the receiver's expected type is
`invalid/RECEIPT_TYPE_MISMATCH`;
a well-formed `kid` absent from the receiver's keyring is
`not_assessed/UNKNOWN_KEY`. These classifications describe this local contract.

The signing input is exactly:

```text
ASCII(original_protected_header_segment) || ASCII(".") ||
ASCII(BASE64URL(JCS(original_payload_bytes)))
```

Verification uses SHA-256 and ECDSA P-256. The original protected header segment
is retained byte for byte. Only the payload is canonicalized. This combines
[RFC 7515 detached content](https://www.rfc-editor.org/rfc/rfc7515.html#appendix-F),
[RFC 7518 ES256](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4) and
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) through this explicit
local contract. Selecting ES256 alone does not imply that an arbitrary issuer
uses JCS or this preimage.

## Receiver keys

Supply 1–16 distinct entries with exactly `key_sha256` and `spki_der_base64`.
Each key is 91-byte named-curve P-256 SPKI DER with an uncompressed public point,
canonical padded base64 and its matching SHA-256. The Node key importer checks
the public point. All supplied keys, including unused ones, must be valid.
Explicit curve parameters, compressed points, other curves, private keys and
other algorithms are unsupported. Invalid configuration is an invocation error.

The receiver establishes the association between the key, issuer and role.
The `kid` fingerprint is a lookup key, not identity or authority evidence by
itself. Node's built-in [crypto.verify](https://nodejs.org/docs/latest-v22.x/api/crypto.html#cryptoverifyalgorithm-data-key-signature-callback)
uses the `ieee-p1363` signature encoding.

## Payload and authority interpretation

The signature helper applies the existing
[JCS input contract](../../docs/conformance/digest-basis.md#explicit-external-jcs-digest-check):
original bytes, strict duplicate-key/Unicode validation, binary64 numbers,
1 MiB maximum and 64-container depth limit. A verified signature binds the
JCS payload, not the exact whitespace or original number spelling.

The receipt adapter reuses the
[existing authority context and policy](../recipient-signature-authority/CONTRACT.md).
It accepts only that context's VATE v0.3 S3 receipts, `proof: {"format":"none"}`
and integer-only JSON with at most 32 levels. Proofs in this experiment are
detached; the receipt's original `proof` member is not relabeled.

The adapter additionally requires **all JSON integers to be within
`[-(2^53-1), 2^53-1]`** before assessing authority. This prevents Python's
arbitrary-precision integers from giving a different meaning to a value rounded
by JCS. A valid signature on fractional numbers, unsafe integers, another receipt
profile or an unsupported context leaves issuer authority `not_assessed`.
The original receipt assessment is still returned separately.

The selected receiver policy binds issuer ID, role, record kind, key, transaction,
runtime and complete action binding by exact equality. Both signed `issued_at`
and receiver-selected `evaluation_time` must fall within the grant's half-open
interval; issuance must not be after evaluation. UTC timestamps retain up to
six fractional digits. The inner action-binding digest continues to use the
existing VATE fixture basis. It does not become JCS by virtue of this signature.

Authority is evaluated only after a verified signature. A registered key with
no matching grant is denied. An unknown key, missing proof, unsupported context
or failed signature cannot supply authority. Removing or rotating a local grant
does not invalidate the cryptographic signature; it changes the policy result.
This adapter does not retrieve keys, certificates, revocations or a trusted clock.

## Results and execution boundary

The adapter accepts optional `bytes` for admission, post-execution and their
proofs, plus required policy bytes. Bounds are 1 MiB per receipt, 4 KiB per proof
and 64 KiB for policy. Configuration requires this adapter contract, an absolute
trusted Node path and its expected SHA-256. Build TypeScript before constructing
the adapter.

`JcsRecipientTrial.assess` returns:

- `signatures`: per-record `verified`, `invalid`, `not_assessed` or `error`, with
  a reason, key fingerprint and available source/proof/canonical/signing-input
  SHA-256 identities;
- `issuer_authority`: the existing `authorized_under_policy`, `denied` or
  `not_assessed` result;
- `receipt_assessment`: the complete original Recipient Assessment API result;
- receiver evaluation time, input identities and selected runtime/source identities.

When present, `key_sha256` records the protected header's claimed `kid`.
`UNKNOWN_KEY` means the receiver has not matched that value to a registered key.
Only `verified` confirms that the signature is valid under the corresponding
receiver-selected key; issuer authority remains a separate result.

`proof_sha256` identifies the supplied proof bytes. ECDSA permits different
valid signature bytes for the same signing input, so this digest is not a
unique identifier for the signed content or a replay-detection key.

`SIGNATURE_MISMATCH` is a failed mathematical check. `MISSING_RECEIPT`,
`MISSING_PROOF`, `UNKNOWN_KEY`, `UNSUPPORTED_ALGORITHM` and
`UNSUPPORTED_PROTECTED_HEADER` are unperformed checks. Malformed proofs or JCS
payloads and a different protected type are invalid under this contract.
Backend failure is `error`, not a bad-signature verdict. A required check that
is invalid, unperformed or errored remains unsatisfied.

`bridge.mjs` is a fixed local transport for the Python adapter. Its base64 JSON
request is generated by Python and is not a signed input format. Its bounded
response must carry the matching request, source and proof hashes, complete
record results and validated key list. No caller-supplied command or script is
executed. Node's environment excludes `NODE_OPTIONS` and user OpenSSL config.
The selected executable and built bridge sources are checked before and after
each subprocess. Source snapshots detect changes after initialization; they do
not authenticate a checkout or establish that a build matches its TypeScript.

The existing authority module and Recipient API retain fixed source pins.
The signature subprocess has a configurable timeout in `(0, 60]` seconds,
default 10; the receipt worker retains its own 30-second timeout. The snapshot
and executable hashes do not attest dynamic libraries or the local host.

There is no combined trust decision. Signature and issuer checks do not override
linkage failures, establish receipt schema validity, detect every replay,
demonstrate an actual operation or grant current permission to execute it.
