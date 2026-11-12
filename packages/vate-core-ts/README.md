# @vate/reference-core

## Status

This package provides request-binding receiver checks, digest, artifact-reference,
SUT-result and explicitly selected JCS signature helpers for VATE draft
implementation reviews.

It is package-private and unpublished. Use the Python conformance runner for
corpus checks and external SUT comparisons. This package is not a production
verifier or a certification tool.

## Scope

The package currently covers:

- sorted-key compact JSON bytes for the v0.3 fixture digest basis;
- SHA-256 digest descriptors using lowercase hexadecimal values;
- RFC 8785 JCS bytes and explicit external JSON digest assessment;
- one explicit local JCS / detached JWS ES256 signature profile;
- digest-bound artifact reference checks against caller-supplied bytes;
- schema-shaped SUT result entries for `schemas/sut-result.schema.json`;
- distinct `corpus-fixture-validation` and `generated-receipts` evidence fields;
- explicit original/effective request binding for the purchase-cap v1 contract;

`stableJsonString`, `stableJsonBytes`, and `digestDescriptorForJson` use the
[limited Python fixture input contract](../../docs/conformance/digest-basis.md#typescript-object-helper-input-contract).
Numeric values must be known Python integers within JavaScript's safe integer
range; fractional numbers, unsafe integers, and negative zero are rejected.
Parsing `1.0` or `1e0` into a JavaScript value loses information needed for this
basis, so arbitrary source JSON must retain its original input for computation
with the Python runner.

The helper deliberately does not:

- fetch remote artifact URIs;
- provide general JOSE, PKI, Sigstore, or signed git proof verification;
- decide issuer trust, status freshness, replay, or local policy;
- imply production readiness, endorsement, or general compatibility.

## Check Request Binding

`assessRequestBinding` checks the original operation, effective operation and
admission context against a receipt using the
[request-binding v1 contract](../../reference/request-binding/CONTRACT.md).
Pass the original UTF-8 bytes in a native `Map`, keyed by their digest URIs,
and the receiver's independently selected admission-request reference:

```typescript
import { assessRequestBinding, requestBindingReference } from "@vate/reference-core";

const artifacts = new Map([
  [requestBindingReference(originalBytes).uri, originalBytes],
  [requestBindingReference(effectiveBytes).uri, effectiveBytes],
  [requestBindingReference(admissionBytes).uri, admissionBytes],
]);
const assessment = assessRequestBinding(receiptBytes, artifacts, {
  requiredContract: "vate-request-binding-v1",
  expectedAdmissionRequestRef: requestBindingReference(receiverSelectedAdmissionBytes),
});
```

All byte variables above are `Uint8Array`. For a denial, omit effective bytes.
The required contract defaults to v1. Missing preimages, declarations or receiver
pins leave `binding_requirement_met` false, including when the status is
`not_checked`. A successful assessment on a denial or new-permit candidate
still has `decision_allows_immediate_execution: false`. Neither field verifies
issuer authority or an actual dispatch.

Receipt evidence must preserve the selected admission's references, including
type, URI, digest and protocol hint. Missing, extra or duplicate references fail
the binding check. Evidence authentication is reported separately as
`evidence.authentication: not_checked`, even if the receipt asserts verification.

The checker reads raw JSON before canonicalizing: duplicate keys, floating-point
tokens, unsafe integers and unpaired Unicode surrogates fail. Amounts use exact
decimal-string comparisons. `requestBindingObjectHash` computes the canonical
operation hash from strict raw JSON; `requestBindingReference` hashes exact bytes.
Their digest bases are distinct. The fixture basis remains separate from JCS.

`createSutResultEntry` accepts `requestBindingArtifacts` to include the local,
digest-bound preimage-manifest reference consumed by the Python runner. It
records the reference; `compare` performs the verification. See the
[ordinary-runner example](../../reference/request-binding/README.md#use-the-ordinary-runner)
for both SUT modes and bundle verification.

The package implements the receiver check. Admission policy evaluation and the
default `VateVerifier.admit` generation entry remain in Python. The parity tests invoke the
Python checker and compare complete assessments for valid and mutated inputs.

## Check an External JCS Reference

Use `assessExternalJsonDigest` when an adjacent profile selects RFC 8785 JCS
and SHA-256 for a known JSON preimage. Pass the original UTF-8 bytes and the
explicit reference. The helper checks digest equality and retains both raw
input and canonical digest identities. It does not select the preimage, verify
a signature, or decide whether an action is permitted.

From the repository root, build the package and check the pinned APS
`action_ref` preimage example:

```bash
npm run ts:check
node packages/vate-core-ts/examples/assess-external-json.mjs \
  packages/vate-core-ts/test/fixtures/aps-jcs/action-ref-preimage.json \
  rfc8785-jcs sha-256 \
  956fb10ca09e093086c856517a8f93c11416f5b84b0a01634bc5ebfff41670d3
```

The result is `matched`. `source_digest` identifies the indented source file;
`computed_digest` identifies the JCS bytes. The example preserves all four
fields from APS's `v09-action-ref-tuple`: `agentId`, `actionType`, `scopeRequired`
and `timestamp`. It hashes that complete preimage, not a receipt envelope.
[SOURCES.json](test/fixtures/aps-jcs/SOURCES.json) pins the APS source and records
the extraction. The upstream test data retains its
[Apache-2.0 license](test/fixtures/aps-jcs/LICENSE) and
[notice](test/fixtures/aps-jcs/NOTICE). This is a saved test vector, not a live
APS receipt or an APS verifier execution.

For another input, supply the path to its complete profile-selected JSON
preimage, a basis selector, an algorithm and an expected digest. This command
reads a local regular file with a bounded read and does not fetch references.
Exit codes are `0` for `matched`, `1` for `mismatched`, `2` for `invalid_input`, `3` for `not_assessed`,
and `64` for invalid usage, an unavailable verifier build, or an unreadable/non-regular file.
For assessment exits `0`–`3`, read the JSON `status` on stdout. Empty stdout means
no assessment was returned; it is not a digest mismatch result.

Only the exact local selector `rfc8785-jcs` and algorithm `sha-256` are
supported. A required check that returns `not_assessed` remains unsatisfied;
the helper does not try the VATE fixture basis. The
[input contract](../../docs/conformance/digest-basis.md#explicit-external-jcs-digest-check)
defines duplicate-key rejection, UTF-8 and Unicode validation, binary64 number
conversion, and the 1 MiB / 64-container limits. Existing fixture helpers and
historical digest rules retain their separate behavior.

## Check a JCS Signature

`JcsEs256Verifier` verifies the experimental
`vate-local-jcs-es256-detached-v1` profile using Node's built-in cryptography.
Supply the explicit profile, receiver-selected P-256 public keys, original
payload bytes, detached JWS bytes and the receiver's expected protected `typ`.
A matching signature establishes that the JCS payload verifies under the
selected key; it does not establish issuer authority or permission to execute.

The [JCS signature and issuer authority example](../../reference/recipient-jcs-signature-authority/README.md)
connects this helper to the existing receipt policy and linkage assessment.
Its [contract](../../reference/recipient-jcs-signature-authority/CONTRACT.md)
specifies the signing input, exact header and key encodings, limits and result
states. Other JOSE algorithms, key discovery and implicit preimage selection are
outside this helper.

After running the linked example, verify its saved admission proof from the
repository root:

```bash
node --input-type=module <<'JS'
import { readFileSync } from "node:fs";
import { JcsEs256Verifier, JCS_ES256_PROFILE } from "./packages/vate-core-ts/dist/index.js";

const folder = "/tmp/vate-jcs-signature-example";
const policy = JSON.parse(readFileSync(`${folder}/receiver-policy.json`, "utf8"));
const verifier = new JcsEs256Verifier({
  expectedProfile: JCS_ES256_PROFILE,
  verificationKeys: policy.verification_keys,
});
const result = verifier.verify({
  source: readFileSync(`${folder}/admission.json`),
  proof: readFileSync(`${folder}/admission.jws`),
  expectedType: "urn:vate:local:jcs-es256:admission:v1",
});
console.log(JSON.stringify(result, null, 2));
JS
```

This returns `verified` for the synthetic example. The helper does not consume
`policy.grants`; use the Python adapter for this receipt context's separate
authority and linkage results.

## Verification

From the repository root:

```bash
npm ci --ignore-scripts
npm run ts:check
npm run ts:test
```
