# Experimental Signature and Authority Contract

This contract defines the inputs and results of
`vate-local-signature-authority-p256-trial-v1`. It applies to the example in
this directory. It does not change VATE receipt schemas, the conformance corpus,
the existing receipt-linkage digest basis, or the Recipient Assessment API.

## Python interface

Import from the trusted source tree and pass original `bytes`; an unavailable
receipt or proof is `None`. Receiver policy is required.

```python
from pathlib import Path
import os
import sys

root = Path("/path/to/VATE")
sys.path.insert(0, str(root / "reference/recipient-signature-authority"))
from recipient_trial import CONTRACT, RecipientTrial, TrialError

inputs = Path("/tmp/vate-signature-example/fixtures")
try:
    assessor = RecipientTrial(
        expected_contract=CONTRACT,
        openssl=os.environ["VATE_TRIAL_OPENSSL"],
        openssl_sha256=os.environ["VATE_TRIAL_OPENSSL_SHA256"],
        source_root=root,
    )
    report = assessor.assess(
        (inputs / "admission.json").read_bytes(),
        (inputs / "post.json").read_bytes(),
        admission_proof=(inputs / "admission-proof.json").read_bytes(),
        post_proof=(inputs / "post-proof.json").read_bytes(),
        receiver_policy=(root / "reference/recipient-signature-authority/receiver-policy.example.json").read_bytes(),
    )
except TrialError as error:
    print(error.as_dict())
else:
    print(report["signatures"])
    print(report["issuer_authority"])
    print(report["receipt_assessment"])
```

`source_root` defaults to the repository containing this module. The receiver
selects it and the absolute OpenSSL path independently of the input records.
`timeout_seconds` (CLI `--timeout`) limits each OpenSSL subprocess separately.
It defaults to 10 seconds; explicit values must be finite numbers greater than
0 and at most 60. The existing receipt-assessment worker has a separate
30-second timeout. This setting does not change that worker timeout or impose
a deadline on the whole `assess()` call.

The existing API's three wrapper files must match `API_PINS`. Their bytes are
checked before loading, and the API checks its own evaluator sources. Preserve
the whole source tree in a checkout or archive. A source mismatch requires an
explicit compatibility review, not automatic repinning from received data.

## Bytes and proof

Each receipt is at most 1 MiB, each detached proof at most 4 KiB, and receiver
policy at most 64 KiB. Proof and policy JSON reject duplicate keys, non-integer
numbers, invalid UTF-8, excess nesting and unknown fields.

Authority context extraction applies the same strict JSON parsing rules to
the entire receipt, including annotations, while allowing unrelated fields.
A receipt containing non-integer JSON numbers, duplicate keys, invalid UTF-8
or excess nesting leaves authority `not_assessed`, even if its signature is
`verified`. The receipt assessment retains its separate result. Preserve the
signed original bytes; rewriting the receipt to satisfy these rules changes
the signing input.

A proof has exactly these fields:

| Field | Value |
| --- | --- |
| `contract` | `vate-local-detached-p256-sha256-trial-v1` |
| `key_sha256` | Lowercase SHA-256 of the registered SPKI DER public-key bytes |
| `signature_base64` | Canonical standard base64 of an 8–72 byte DER ECDSA signature |

The signing input is:

```text
ASCII("VATE local detached P-256 SHA-256 receipt trial v1")
|| 0x00 || ASCII(receipt_kind) || 0x00 || original_receipt_bytes
```

`receipt_kind` is `admission` or `post_execution`. OpenSSL receives
`pkeyutl -verify -rawin -digest sha256`; it hashes this complete input and
verifies ECDSA with P-256. Whitespace and trailing newlines are signed.
Receipt-linkage comparison still uses its existing JSON object digest.

Keys are exactly 91-byte named-curve P-256 SPKI DER with an uncompressed point.
Other curves, compressed points, explicit parameters and Ed25519 are outside
this contract. Each registered key must also pass OpenSSL `pkey -pubcheck`.
A malformed or unusable registered key fails the invocation, including a key
not used by either proof. Unknown proof keys are not fetched.

## Authority and time

A policy has exactly `contract`, `evaluation_time`, `verification_keys` and
`grants`. The contract is
`vate-local-issuer-authority-p256-policy-trial-v1`.
There are 1–16 keys, each containing `key_sha256` and
`spki_der_base64`, and 0–64 grants. An empty grant list denies authority even
when signatures verify.

Each grant contains these exact fields:

- `issuer_id`, `issuer_role`, `receipt_kind`, `key_sha256`
- `transaction_id`, `runtime`, `action_binding`
- `valid_from`, `valid_until`

Grant matching is exact: there are no wildcards, prefixes or implicit identity
mappings. Admission issuer identity comes from `verifier.id`, with role
`verifier`; post-execution identity and role come from `issuer.id` and
`issuer.role`. These contexts are considered only after signature verification.

The operation scope is the complete `vate-local-s3-observation-v1` binding
descriptor, plus transaction and runtime. The admission `request.input_hash`
or post-execution `execution.effective_request_hash` must agree with the
binding digest. This example does not recompute the digest from target/body
bytes; that is a separate [S3 observation check](../s3-observation-example/CONTRACT.md).
Supported receipts retain `proof: {"format": "none"}` internally; the added
proof remains detached. Other receipt proof formats or action-binding profiles
are not reinterpreted.

| Check | Compared time | Precision and endpoints | Source |
| --- | --- | --- | --- |
| Issuer authority in this example | Both receipt `issued_at` and policy `evaluation_time` inside the grant interval; `issued_at <= evaluation_time` | UTC `Z`, 0–6 fractional digits, microsecond comparison; start included, end excluded | Signed record's claimed issuance time and receiver-selected evaluation time/policy |
| Preserved receipt linkage | Recorded execution start and finish inside the admission window, in order | Up to microseconds; both window endpoints included | Stored admission and post-execution records |
| Existing crosswalk CW-08 | PUT start and finish inside the NENRIN grant window; receipt execution time equals PUT finish text | Fixed six fractional digits; both endpoints included | Captured transport times and reconstructed NENRIN records |
| Pinned NENRIN native window check | Receipt execution time within the grant window | Millisecond comparison; both endpoints included | NENRIN grant/receipt fields |

The last two rows describe the separate
[NENRIN–VATE crosswalk](../nenrin-s3-crosswalk-example/README.md); this example
does not run that crosswalk or the NENRIN checkers. A timestamp comparison does
not establish clock independence or physical event order. A signed
`issued_at` is the issuer's claim, not a trusted observation of signature
creation. No wall clock, certificate chain, external revocation service or
historical policy service is consulted.

Grant success concerns authority to **issue the record** under this exact
policy. It is not permission to perform the operation. Authority also does not
replace full receipt validation: a signed record can satisfy the authority
context while other fields leave the existing receipt assessment unassessed.

## Results and failures

| Result | Status | Meaning |
| --- | --- | --- |
| Signature | `verified` | Selected key verified this receipt kind and original bytes |
| Signature | `invalid` | Recognized native verification failure; it does not identify whether bytes, key or signature caused it |
| Signature | `not_assessed` | Receipt/proof missing, key unregistered, or proof unsupported/malformed |
| Signature | `error` | Timeout, unavailable/changed executable or unrecognized native output |
| Authority | `authorized_under_policy` | Verified key, record context and both times match a receiver grant |
| Authority | `denied` | Signature verified, but no applicable issuer/key/scope/time grant |
| Authority | `not_assessed` | Signature not verified or required authority context unsupported |

Recognized verification failure can also result from malformed DER. Do not
infer from `invalid` alone that signature arithmetic was reached.
Key-validation failures raise `TrialError` before the receipt assessment;
per-receipt signature errors remain in the returned report and suppress that
receipt's authority assessment.

Reports preserve the complete `receipt_assessment`, key validation results,
input byte identities, receiver evaluation time, executable identity and
native stdout/stderr/return code. Base64 copies retain the exact native output
bytes. A timeout has `complete: false`, unknown return code and any partial
output already captured.

OpenSSL runs with the default provider, an empty configuration and a restricted
environment. Its executable hash is checked before each process starts and
again when a process result is returned, including a nonzero exit code.
A timeout returns an error with any captured partial output, without a
post-process executable hash check.
This does not attest shared libraries, the host or transient concurrent
replacement. Select a trusted runtime and source tree before using the API.

The CLI returns JSON and exit 0 when a report is available, including invalid,
denied and mismatch findings. Invocation/configuration errors and per-receipt
verifier execution errors return exit 64. No overall `trusted`, authorization
to retry, or permission-to-execute field is added.

## Reproduction and updates

`run_trial.py` creates test signatures, saves each control's exact inputs and
complete result, and checks the original API response against `BASELINE.json`.
It also checks the twelve pinned source/input files in that baseline.
`RUN.json` describes that local run; it is not a signed execution attestation.

Retain originals, policy bytes, proof bytes, runtime identity and previous
results when changing keys or grants. Revoking a grant changes policy
acceptance without making a mathematically valid signature invalid. Moving a
key into the keyring does not grant it an issuer role.

The example performs no new S3 operation. Its public test-key signatures were
created after the stored operation. They do not establish that a grant or
signature existed before the write, identify a real issuer, or show complete
execution evidence. General JOSE/PKI and completeness checking require
separate contracts.

OpenSSL interfaces:
[pkeyutl](https://docs.openssl.org/3.0/man1/openssl-pkeyutl/),
[pkey](https://docs.openssl.org/3.0/man1/openssl-pkey/).
