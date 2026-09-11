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
| Future production-oriented JSON profile | RFC 8785 / JCS, or exact media bytes, when explicitly selected by a future profile | Candidate future/profile basis | Production-oriented cross-runtime or signed-object stability |
| Adjacent protocol-native digest | Adjacent protocol-defined values such as PEF `receipt_hash`, PEF `frame_id`, AP2 mandate hashes, or A2A artifact identifiers | Adjacent metadata by default | Adjacent evidence integrity or correlation |

Corpus manifest paths are repository-relative paths serialized with POSIX `/`
separators, independent of the operating system running the reference runner.

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
