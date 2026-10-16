# Recipient Signature and Issuer Authority Example

Check a detached signature and receiver-selected record-issuing authority
alongside VATE's existing receipt assessment. The Python API and JSON CLI return
three separate results: signature verification, authority under the supplied
policy, and the complete receipt-linkage assessment.

This experimental example uses P-256 / SHA-256 through an existing OpenSSL
executable. Its local proof and policy contracts are implementation aids, not a
normative VATE signature profile. The stored receipts and existing Recipient
Assessment API remain unchanged.

## Run the example

Use a trusted checkout or source archive of the whole repository, Python 3.10
or later, the existing `jsonschema==4.26.0` dependency, and OpenSSL 3 or 4 with its
default provider on Linux or macOS. The [existing environment
setup](../receipt-linkage-example/README.md#run-the-examples) supplies the Python
dependency. Keep it in the interpreter's environment; the receipt worker ignores
`PYTHONPATH` and user-site packages.

Select an installed OpenSSL executable through your receiving application.
Review its source and version before recording its hash. The hash identifies
the selected executable; it does not authenticate its supplier or shared
libraries. Set an absolute path below; on macOS, the system's LibreSSL is not a
substitute for OpenSSL 3 or 4.

From the repository root:

```bash
export VATE_TRIAL_OPENSSL=/absolute/path/to/openssl
"$VATE_TRIAL_OPENSSL" version
export VATE_TRIAL_OPENSSL_SHA256="$(
  .venv/bin/python -c 'import hashlib,os,pathlib; print(hashlib.sha256(pathlib.Path(os.environ["VATE_TRIAL_OPENSSL"]).read_bytes()).hexdigest())'
)"
.venv/bin/python -B reference/recipient-signature-authority/run_trial.py \
  --openssl "$VATE_TRIAL_OPENSSL" \
  --openssl-sha256 "$VATE_TRIAL_OPENSSL_SHA256" \
  --output /tmp/vate-signature-example
```

Choose a new output directory for each run. The command generates synthetic
detached signatures over the saved S3 receipt pair and writes ten control
directories, original inputs, full results and `RUN.json`. The signing keys use
public test scalars 1, 2 and 3. They are unsuitable for any real identity or
authority. Signatures are added after the recorded operation and may differ
between runs; compare the expected findings and retain each run's original bytes.

The archived `BASELINE.json` remains tied to its original source identity.
The trial and tests reproduce it with the
[fixed historical runtime](../historical-runtime/README.md) and compare current
behavior separately, including the current code hashes. `RUN.json` identifies
the historical replay report and the separate check that the current matching
response differs only in its verified source identities.

## Read the three results

The following columns describe the post-execution receipt:

| Control | Signature | Issuer authority | Receipt linkage |
| --- | --- | --- | --- |
| Matching inputs | `verified` | `authorized_under_policy` | `matched` |
| Newline appended to the signed original | `invalid` | `not_assessed` | `matched` |
| Valid signature, ungranted issuer | `verified` | `denied` | `matched` |
| Valid signature and grant, wrong admission reference | `verified` | `authorized_under_policy` | `mismatch` |
| Missing post-execution receipt | `not_assessed` | `not_assessed` | `not_assessed` |

The other controls cover a missing proof, wrong operation scope, expired
authority, and old/new keys under a changed grant. A key in the verification
keyring does not itself grant authority. A successful signature and authority
result does not override a contradictory or unavailable receipt assessment.

`receipt_assessment` contains the complete existing
`vate-recipient-assessment-api-v1` result, including its unsupported
`signatures_and_issuer_authority` requirement. The additional `signatures`
and `issuer_authority` fields describe this example's separate checks.
There is no combined trust or permission-to-execute value.

## Select receiver policy

[receiver-policy.example.json](receiver-policy.example.json) contains only the
public test keys and fixed example grants. The fixture generator derives these
synthetic grants from the stored receipts to exercise the controls. For another
receipt pair, select the policy independently:

1. Establish which issuer may issue each kind of record through the receiver's
   own trust process. Bind an approved public key to that issuer and role.
   Neither the receipt nor a key fingerprint establishes this relationship.
2. Register its named-curve P-256 public key as SPKI DER in
   `verification_keys`. Registration permits verification only.
3. Add a grant for the exact issuer, role, receipt kind, key, transaction,
   runtime and complete action binding that the receiver intends to accept.
   Select that scope from the receiver's approved request/context; do not
   generate real grants from the received record.
4. Select `evaluation_time` and a grant interval. Both the signed `issued_at`
   and the receiver's evaluation time must be inside
   `[valid_from, valid_until)`. The example does not consult a clock or
   revocation service for you.

The [contract](CONTRACT.md#authority-and-time) defines the fields, time precision,
boundaries and sources. Record-issuing authority is distinct from authorization
to execute an operation. No NENRIN-to-VATE identity mapping is inferred.

## Assess supplied originals

After the example run above, this command evaluates its saved originals through
the CLI. For another pair, supply the receiver's policy and detached proofs
under the same [experimental contract](CONTRACT.md).

```bash
.venv/bin/python -B reference/recipient-signature-authority/recipient_trial.py \
  --trial-contract vate-local-signature-authority-p256-trial-v1 \
  --openssl "$VATE_TRIAL_OPENSSL" \
  --openssl-sha256 "$VATE_TRIAL_OPENSSL_SHA256" \
  --admission /tmp/vate-signature-example/fixtures/admission.json \
  --post /tmp/vate-signature-example/fixtures/post.json \
  --admission-proof /tmp/vate-signature-example/fixtures/admission-proof.json \
  --post-proof /tmp/vate-signature-example/fixtures/post-proof.json \
  --receiver-policy reference/recipient-signature-authority/receiver-policy.example.json
```

Omit an unavailable receipt or proof argument. Exit 0 means a report was
returned, including reports with invalid signatures, denied authority or
mismatched linkage. Exit 64 indicates a configuration, invocation or verifier
execution error. Inspect the separate result fields before acting.

The [Python example](CONTRACT.md#python-interface) shows the same call from an
application. `BASELINE.json` retains the original API response and hashes of
its twelve source/input files. Run the regression checks with the selected
OpenSSL executable:

```bash
.venv/bin/python -B -m unittest discover \
  -s reference/recipient-signature-authority -p 'test_*.py' -v
```

## Evidence boundary

This example verifies the supplied bytes under the supplied keys and record
policy. It does not establish real-world issuer identity, authority at the
original operation, when a signature was created, or the order of a write and a
later commitment. Complete JOSE/PKI validation, certificate/revocation handling,
independent execution evidence and a complete set of required records remain
outside this contract. See [known gaps](../../docs/known-gaps.md).
