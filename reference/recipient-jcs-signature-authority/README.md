# JCS Signature and Issuer Authority Example

Verify a detached ES256 signature over a JCS JSON payload, then check whether
the receiver's policy authorizes that issuer to issue the record. This example
returns signature verification, issuer authority and VATE receipt linkage as
separate results.

The TypeScript signature helper uses Node's built-in cryptography. The Python
adapter reuses the existing
[issuer policy](../recipient-signature-authority/CONTRACT.md#authority-and-time)
and [Recipient Assessment API](../recipient-assessment/README.md). This is a
local experimental signing contract for the saved VATE S3 receipt shape.
It is not a normative VATE signature profile or a production verifier.

## Run the example

Use a trusted checkout of the whole repository, Node 22, the existing TypeScript
workspace dependencies, Python 3.10 or later, and the repository's existing
`jsonschema==4.26.0` environment. OpenSSL 3 or 4 is needed only to generate the
synthetic signatures. The actual assessment needs Node and Python; it does not
invoke the OpenSSL command or contact a key service.

Follow the [repository environment setup](../../README.md#verification) and
activate your Python environment before running the commands below. They use
`python3` from that environment.
Keep `jsonschema` in that interpreter's environment because the receipt worker
ignores `PYTHONPATH` and user-site packages.

If `openssl` on `PATH` is LibreSSL, including the macOS system executable, set
`VATE_TRIAL_OPENSSL` to the absolute path of an installed OpenSSL 3 or 4
executable before generating the example signatures or running the tests.

From the repository root:

```bash
npm ci --ignore-scripts
npm run ts:check
python3 -B reference/recipient-jcs-signature-authority/run_trial.py \
  --output /tmp/vate-jcs-signature-example
```

Choose a new output directory for each run. The generator uses the installed
`node` on `PATH` and `VATE_TRIAL_OPENSSL` if set, otherwise `openssl` on `PATH`.
Select trusted executables before running it. It records their paths and hashes.

The output includes the original inputs, each control's inputs and result,
`MANIFEST.json` and `SUMMARY.json`. The signatures use **public test scalars
1, 2 and 3**, which are unsuitable for real identities. The generator signs
previously saved receipts after the recorded operation. It derives synthetic
grants from those receipts to exercise the controls. It does not demonstrate
signing by the original service or an external implementation.

The following columns describe the post-execution receipt:

| Control | Signature | Issuer authority | Receipt linkage |
| --- | --- | --- | --- |
| Matching inputs | `verified` | `authorized_under_policy` | `matched` |
| Whitespace changed | `verified` | `authorized_under_policy` | `matched` |
| Issuer changed without a new signature | `invalid` | `not_assessed` | `matched` |
| Valid signature from an ungranted issuer | `verified` | `denied` | `matched` |
| Receiver grant expired | `verified` | `denied` | `matched` |
| Missing proof | `not_assessed` | `not_assessed` | `matched` |
| Key absent from the receiver keyring | `not_assessed` | `not_assessed` | `matched` |
| Valid signature and grant, wrong admission reference | `verified` | `authorized_under_policy` | `mismatch` |

Whitespace and JSON member order can change without invalidating a JCS
signature. The source-byte digest still changes. Changes to signed JSON content
are checked under the JCS data model, including its binary64 number rules.
The [contract](CONTRACT.md) defines the narrower integer-only receipt context
accepted for authority assessment.

## Assess supplied originals

Select the signing contract with the issuer before accepting its proofs. This
example accepts a detached compact JWS with protected `alg`, `kid` and `typ`
fields. A proof under the older
[raw-byte P-256 contract](../recipient-signature-authority/CONTRACT.md)
is a different input and is not retried under this contract.

Select an absolute path to the trusted Node executable and record its SHA-256.
A hash identifies the selected runtime; it does not establish supplier trust.

```bash
export VATE_JCS_NODE=/absolute/path/to/node
export VATE_JCS_NODE_SHA256="$(
  python3 -c 'import hashlib,os,pathlib; print(hashlib.sha256(pathlib.Path(os.environ["VATE_JCS_NODE"]).read_bytes()).hexdigest())'
)"
python3 -B reference/recipient-jcs-signature-authority/jcs_recipient_trial.py \
  --trial-contract vate-local-jcs-signature-authority-trial-v1 \
  --node "$VATE_JCS_NODE" \
  --node-sha256 "$VATE_JCS_NODE_SHA256" \
  --admission /tmp/vate-jcs-signature-example/admission.json \
  --post /tmp/vate-jcs-signature-example/post.json \
  --admission-proof /tmp/vate-jcs-signature-example/admission.jws \
  --post-proof /tmp/vate-jcs-signature-example/post.jws \
  --receiver-policy /tmp/vate-jcs-signature-example/receiver-policy.json
```

For other inputs, supply a policy established independently by the receiver.
The [existing policy contract](../recipient-signature-authority/CONTRACT.md)
binds the issuer, role, record kind, public key, transaction, runtime, action
binding and validity interval. Registering a verification key alone grants no
authority. Select the evaluation time and grant validity from the receiver's
approved context; the example does not retrieve current revocation information.

Omit unavailable receipt or proof arguments. Exit `0` means a report was
returned, including invalid signatures, denied authority and linkage mismatches.
Exit `64` means configuration, input or verifier execution failed. Command-line
syntax errors use argparse's exit `2`. Inspect the result fields before acting.

`receipt_assessment` retains the complete existing API response, including its
unsupported `signatures_and_issuer_authority` request. The additional
`signatures` and `issuer_authority` fields contain this example's separate
checks. Authority means permission to **issue this record under the supplied
policy**. It does not establish current permission to execute an operation.
There is no combined trust or execution-approval value.

## Use the signature helper separately

`JcsEs256Verifier` in
[@vate/reference-core](../../packages/vate-core-ts/README.md)
accepts original JSON bytes, detached proof bytes, receiver-selected P-256
public keys and an expected protected `typ`. It verifies this one explicit
JCS/JWS profile. It does not interpret the payload as a receipt or grant
issuer authority. Applications must establish their own payload schema and
receiver policy.

Its [minimal JavaScript example](../../packages/vate-core-ts/README.md#check-a-jcs-signature)
shows how to load the test inputs and read the signature result.

## Verification

```bash
npm run ts:check
npm run ts:test
python3 -B -m unittest discover \
  -s reference/recipient-jcs-signature-authority -p 'test_*.py' -v
```

The controls include OpenSSL-generated signatures verified through Node, changed
content, wrong record kind, unknown keys, ungranted issuers, scope and time
mismatches, key rotation, missing inputs, unsupported receipt contexts and
invalid runtime responses. Node and the signing command both use OpenSSL-based
cryptography; this is a check across interfaces, not independent cryptographic
implementations.

These local tests do not establish interoperability with an external service,
PKI or JOSE support beyond this contract, replay protection, current key status,
actual execution, or production readiness.
