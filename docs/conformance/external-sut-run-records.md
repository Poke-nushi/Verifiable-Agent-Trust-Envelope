# External SUT Run Records

## Status

This document records externally supplied SUT run artifacts that were useful for
VATE conformance review.

These records are review evidence only. They are not part of the VATE
conformance corpus, do not imply VATE certification, do not imply endorsement or
production approval, and do not create a passing full-corpus or general
compatibility claim.

Each record identifies the external artifact location, the reviewed revision or
digest, the corpus snapshot, the local comparison result, and the boundary under
which the result was used.

## AlgoVoi Three-Case External Adapter Run

Source discussion:

- `https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2`
- acknowledgement after local verification:
  `https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2#issuecomment-4893127607`

External artifact location:

- `https://gist.github.com/chopmob-cloud/d3f7d257fc4cf9e61e788449047b926b`

Reviewed gist git revision:

- `e150d5cacb038d3fed9cc3267320a1d547fe18b7`

Implementation identifier reported by the submitted SUT result:

- name: `algovoi-external-adapter-sut`
- type: `external-adapter-review`
- version: `0.4`
- language: `python`
- source: `https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors`

Corpus:

- profile: `VATE-AL2-Verifier-Admission-v0.3`
- digest basis: repository corpus manifest digest
- digest: `835864092b7afde1c751c4e2cad40aa8265b4ebb95234873c9b8d20f664cb2f6`

Submitted artifact files:

| File | Raw file SHA-256 | VATE canonical JSON digest |
|---|---|---|
| `sut-result.algovoi.json` | `dad99bbfd238bbc9fc002fcaf1e88e89282fabaae2241b526d78a47456479c74` | `ef6bd37bd68ef1b1c2f2a79212896c43ebbb76f9d4e76f1ee49888d68656f2c9` |
| `compare-report.json` | `6f90f6198b7c4d32dd5e40816fba7b0f586434f163649cb7656c94bfc0a4d042` | `fcb4f5760c227ab4ec8f5887c3e7dcd59f62e4f625fb772111bc15c272d779c9` |
| `implementation-report.json` | `9d9358b3c2e7b4d8948952a9824e5c150421b9be047492d6e4408f09361291c3` | `cd5ec88ae5273911c408fa1f496b6c21fdff972721f006793f3dbda6cc7bdd55` |

The VATE canonical JSON digest basis is `json-sorted-no-whitespace`, matching
the report and bundle-integrity fields used by the v0.3.x reference runner. The
raw file SHA-256 values are recorded only as fetched file-byte identifiers.

Starter cases included in the submitted SUT result:

- `allow-valid-admission`
- `attenuate-max-amount`
- `deny-digest-mismatch-before-policy`

Local verification result:

- SUT result schema validation: pass
- conformance report schema validation: pass
- implementation report schema validation: pass
- `compare`: `3 passed / 69 failed / 0 skipped / 72 total`
- `compare` fatal errors: none
- remaining failed cases: all `sut result missing`
- `verify-bundle`: `23 passed / 0 failed`

Publication and durability caveat:

- the submitted implementation report did not include a `publication` block;
- the gist is an external mutable location and is not vendored into this
  repository;
- this record pins the reviewed gist git revision and artifact digests so the
  review can be traced, but it does not make the external gist immutable or
  maintainer-controlled by VATE.

Claim boundary:

- this is schema-valid external adapter-run evidence for three starter cases;
- it records one implementation run against one corpus snapshot;
- the implementation report status is `fail`, because the submitted SUT result
  intentionally covers only three cases from the 72-case corpus;
- this is not certification, endorsement, production approval, a passing
  full-corpus claim, or a general compatibility claim.
