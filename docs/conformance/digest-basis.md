# Digest Basis For VATE AL2 v0.3.x

## Status

This note defines digest-basis terminology for the VATE AL2 v0.3.x
conformance and external SUT review path.

It is an interoperability clarification. It is not a production signature
profile, does not add a JOSE or JCS dependency to the reference runner, and does
not change the current corpus comparison rules by itself.

## Digest Classes

VATE uses several digest bases. Implementations MUST NOT silently substitute one
basis for another.

| Digest class | Basis | Status | Purpose |
|---|---|---|---|
| Raw artifact digest | Exact artifact bytes as published in the corpus or produced by the SUT | Active v0.3.x basis | Artifact reference integrity |
| Corpus manifest digest | SHA-256 over the sorted manifest array using the VATE v0.3 fixture JSON byte basis | Active v0.3.x fixture basis | Corpus snapshot identity |
| Report or SUT-result file digest | SHA-256 over the complete JSON file using the VATE v0.3 fixture JSON byte basis | Active v0.3.x report-bundle basis | Local report-bundle digest-chain checking |
| Current fixture/object JSON digest | JSON object keys sorted, insignificant whitespace removed, UTF-8 bytes, SHA-256 lowercase hex | Active v0.3.x limited basis | Dependency-free comparison of selected JSON values |
| Embedded evidence-object digest | The case or profile names the selected evidence object and the digest basis used for that object | Must be explicit; do not leave this as only "canonical JSON" | Cross-artifact context binding in SUT results |
| Explicit external JCS digest | RFC 8785 bytes of a caller-selected JSON preimage, then SHA-256 | Package-private TypeScript reference helper; separate from corpus and report-bundle rules | Check a digest supplied by an adjacent profile |
| Future production-oriented JSON profile | RFC 8785 / JCS, or exact media bytes, when explicitly selected by a future profile | Candidate future/profile basis | Production-oriented cross-runtime or signed-object stability |
| Adjacent protocol-native digest | Adjacent protocol-defined values such as PEF `receipt_hash`, PEF `frame_id`, AP2 mandate hashes, or A2A artifact identifiers | Adjacent metadata by default | Adjacent evidence integrity or correlation |

Corpus manifest paths are repository-relative paths serialized with POSIX `/`
separators, independent of the operating system running the reference runner.

## Select the Preimage and Basis

Before recomputing a reference, identify the selected bytes or object, the
serialization rule and version, the hash algorithm, and the digest encoding.
The algorithm alone (`sha-256`) does not identify the preimage or byte rule.
Use the case or adjacent profile to select them; do not try several rules until
one digest matches.

For example, the [NENRIN–VATE S3 crosswalk](../../reference/nenrin-s3-crosswalk-example/README.md#digest-rules-and-input-validation)
hashes the complete nine-field effective-request object under its VATE fixture
basis. Its `body_digest` separately hashes the raw PUT body. The NENRIN action
object has another preimage and uses `musubi-canonical-v0`. None of these
references selects the full bundle merely because it contains that object.

An unknown basis leaves that digest check unassessed. It cannot satisfy a
required digest check. The receiver's assessment or admission policy determines
the resulting insufficiency or denial; `not_assessed` is not itself an
execution decision. The crosswalk and the external JCS helper both retain an
unassessed finding instead of substituting another basis.

## Fixture JSON and RFC 8785 JCS

The fixture basis and [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html)
are distinct even when particular inputs yield the same bytes.

| Input detail | Current Python fixture basis | RFC 8785 JCS |
|---|---|---|
| String `é` | ASCII escape `\u00e9` | Literal UTF-8 `é` |
| Parsed numeric token `1.0` | Python float serialized as `1.0` | ECMAScript number serialized as `1` |
| Property-name ordering | Unicode code points | UTF-16 code units, recursively |
| Unicode normalization | No normalization performed | No normalization performed; preserve string data |

ASCII-only content does not guarantee equality: number serialization can still
differ. Non-ASCII raw body bytes do not by themselves create a JSON
canonicalization difference when the JSON preimage contains only their
hexadecimal digest. Keep the raw body and the containing JSON object separate.

## Current VATE v0.3 Fixture JSON Byte Basis

The current dependency-free runner serializes selected JSON values with sorted
object keys and no insignificant whitespace before applying SHA-256. In
implementation terms, the current Python runner uses:

```text
json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
```

This basis is intentionally limited. It keeps the current fixture corpus and
report-bundle checks reproducible without adding dependencies, but it is not a
production JSON canonicalization profile. It does not define duplicate-key
rejection, Unicode normalization, floating-point normalization, streaming
payload handling, or a general signed-JSON profile.

Do not relabel this current basis as RFC 8785 / JCS unless the runner, fixtures,
schemas, examples, and comparison rules have been updated to use that profile.

Input validation is also specific to the consumer. The general fixture basis
does not define duplicate-key rejection. The S3 crosswalk adds a strict parser
that rejects duplicates, floating-point tokens, negative zero, unsafe integers,
isolated surrogates and excessive nesting. Those crosswalk restrictions do not
retroactively change all VATE fixture JSON or impose JCS number semantics.

### TypeScript Object Helper Input Contract

The package-private TypeScript `stableJsonString`, `stableJsonBytes`, and
`digestDescriptorForJson` helpers reproduce this Python basis for strings,
booleans, null, arrays, and plain objects whose numeric values are known to be
Python integers within JavaScript's safe integer range
(`-9007199254740991` through `9007199254740991`). They escape non-ASCII strings
with lowercase `\u` sequences, sort keys by Unicode code point, and preserve
integer-like keys and literal `__proto__` members. They do not normalize Unicode.

These helpers reject fractional numbers, negative zero, non-finite numbers,
and integers outside the safe range. This is a TypeScript helper limitation;
it does not change the Python fixture basis or prohibit floating-point values
in the conformance runner.

Do not use these object helpers to recompute the digest of arbitrary parsed
JSON. JavaScript loses numeric representation information: `JSON.parse("1.0")`
and `JSON.parse("1e0")` both produce `1`, while Python parses those tokens as
floats and serializes them as `1.0`. The helper cannot detect that loss from the
resulting JavaScript value. Even a safe integer value requires a source contract
that excludes floating-point tokens and prior numeric rounding.

For an object outside that contract, retain the original input and compute its
fixture bytes with the Python runner before hashing those bytes. Hashing the raw
source file instead is valid only when the artifact or profile calls for a raw
artifact digest; it is not a substitute for the fixture/object JSON digest.

The TypeScript correction aligns its supported strings and object keys with the
existing Python basis. Digests previously produced by the TypeScript helper for
non-ASCII text, integer-like keys, or dropped `__proto__` members must be
recomputed from the source object. Published corpus and historical report-bundle
digests retain their existing basis and bytes.

## Explicit External JCS Digest Check

The package-private TypeScript helper exposes `canonicalizeJcsJson` and
`assessExternalJsonDigest`. Supply original UTF-8 JSON bytes containing the
complete preimage selected by the adjacent profile. Parsing into an object
first would lose duplicate property names; removing or selecting fields is a
separate profile responsibility.

`assessExternalJsonDigest` accepts the local selector `rfc8785-jcs` and a
`{ "alg": "sha-256", "value": "<64 lowercase hex characters>" }` descriptor.
This selector is an API choice, not a registered A2A identifier or an assertion
that adjacent protocols use that spelling. Map a profile's stated basis to the
selector only when its byte rules and preimage are known. Prefixes such as
`sha256:` are not part of this helper's `value` field.

The parser rejects duplicate names after escape decoding, including nested and
escaped-equivalent duplicates, invalid UTF-8, isolated surrogates, Unicode
noncharacters and numbers that convert to infinity. It emits recursively sorted
UTF-16 property names, ECMAScript number and string encodings, and preserves
nulls and array order.
It performs no Unicode normalization. Numeric tokens use binary64 conversion,
including rounding, underflow and negative-zero serialization as `0`; use
strings when the external profile needs exact larger integers or decimal data.

The helper accepts at most 1,048,576 input bytes and 64 nested containers, and
rejects a UTF-8 byte-order mark. These are local input limits, not changes to
JCS. Rejected input produces no canonical bytes or computed digest.

| Result | Meaning |
|---|---|
| `matched` | Computed JCS SHA-256 equals the supplied digest |
| `mismatched` | A valid JCS preimage yields a different digest |
| `not_assessed` | The basis or algorithm is unsupported; no alternate basis was tried |
| `invalid_input` | The reference or source violates the input contract; `reason` identifies why |

For assessed inputs, `source_digest` hashes the original file bytes and
`computed_digest` hashes the JCS bytes. Retain the original file when recording
the result. A match establishes that relationship only: it does not validate
the selected preimage's schema, signatures, issuer authority or execution.

The [command example](../../packages/vate-core-ts/README.md#check-an-external-jcs-reference)
uses a pinned APS `action_ref` preimage test vector. This additive path does not
replace `stableJsonBytes`, the Python runner, existing corpus digests, historical
reports, or `musubi-canonical-v0`.

## Reproduce the Byte and Rejection Checks

Run these from the repository root with the existing Python and Node.js
development environments:

```bash
python3 -B -m unittest discover \
  -s reference/nenrin-s3-crosswalk-example/tests -p 'test_*.py' -v
npm run ts:check
npm run ts:test
```

| Question | Existing or added executable check |
|---|---|
| Is the complete effective request hashed, separately from the raw body and NENRIN action? | [`test_crosswalk.py`](../../reference/nenrin-s3-crosswalk-example/tests/test_crosswalk.py): `test_request_hash_is_full_canonical_object_not_pretty_file`, `test_request_body_structured_result_and_native_action_bases_distinct` |
| Does an unknown crosswalk basis remain unassessed? | Same file: `test_unknown_profiles_not_reinterpreted`, `test_unknown_algorithm_is_unassessed` |
| How do VATE and musubi bytes differ, and which inputs does the crosswalk reject? | Same file: `test_hand_written_canonical_byte_contrast`, `test_strict_parser_and_bounds` |
| Do TypeScript fixture helpers retain the Python basis? | [`digest.test.ts`](../../packages/vate-core-ts/test/digest.test.ts): Japanese text, escaped strings, key ordering, numeric restrictions |
| Does the JCS helper follow the RFC examples and reject ambiguous input? | [`jcs.test.ts`](../../packages/vate-core-ts/test/jcs.test.ts): sections 3.2.2–3.2.4, Appendix B finite-number vectors, duplicate keys, Unicode, syntax and resource limits |
| Can an adjacent test preimage be checked without falling back to the fixture basis? | [`external-json-digest.test.ts`](../../packages/vate-core-ts/test/external-json-digest.test.ts): pinned APS vectors, preimage mutations, explicit basis selection, raw/canonical identities and CLI results |

The [APS source manifest](../../packages/vate-core-ts/test/fixtures/aps-jcs/SOURCES.json)
pins the upstream commit, raw file hashes, license, and the extracted example's
origin. The twelve upstream expected byte strings and hashes are test data,
not a new run of the APS implementation or a live signed receipt. The upstream
description of its ASCII key-order case says “Unicode code point”; the JCS
rule tested here is UTF-16 code-unit order, including non-BMP property names.

## Embedded Evidence-Object Digest

When a SUT result binds an embedded evidence object, the selected object MUST be
clear from the case or profile. The digest covers that selected JSON object, not
automatically the full source artifact and not automatically an adjacent
protocol identifier found inside the artifact.

For the current v0.3.x corpus, `compare` expects the same VATE v0.3 fixture JSON
byte basis described above for generated evidence context bindings. A future
profile may instead name RFC 8785 / JCS, exact media bytes, or another explicit
basis, but that is a profile change and should come with matching runner,
fixture, example, and comparison-rule updates.

The phrase "canonical JSON digest" should not appear in SUT-facing guidance
without naming the actual digest basis.

## Adjacent Protocol Digest Boundary

Adjacent protocol identifiers can be useful evidence metadata, but they are not
VATE digest descriptors by default.

For example:

- PEF `receipt_hash` remains the PEF receipt hash.
- PEF `frame_id` remains the PEF frame or preimage identifier.
- AP2, A2A, x402, or other adjacent identifiers remain values under their own
  profile rules.

A VATE case may consume those artifacts as adjacent evidence, but it must still
be clear whether the VATE digest descriptor binds exact artifact bytes, a
selected embedded JSON object, or another profile-defined basis. Do not
substitute adjacent protocol hashes for VATE digest descriptors unless a future
VATE profile explicitly defines that equivalence.

## Withheld Basis Boundary

A receipt with `reason_visibility: withheld` is still a digest-bound portable
record.

The disclosed portable receipt surface should remain recomputable under its
stated digest basis. Withheld policy or evidence basis material is not proven by
the public receipt bytes unless a profile supplies a protected audit reference,
policy snapshot reference, or another digest-bound commitment to that hidden
material.
