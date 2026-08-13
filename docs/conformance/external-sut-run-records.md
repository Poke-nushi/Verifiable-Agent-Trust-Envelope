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

## Snapshot Applicability

The two AlgoVoi records below were evaluated against corpus digest
`835864092b7afde1c751c4e2cad40aa8265b4ebb95234873c9b8d20f664cb2f6`,
the digest recorded by the archived `v0.3.2` release. They remain review
evidence for that exact pinned snapshot.

A later 72-case `main` snapshot recorded corpus digest
`0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`.
The 75-case snapshot introduced by the RCL carry-plus-projection change records
corpus digest
`988aae7d03dd5bb743e8e03e6ab1120ce8735a4837ac818ffd9d665de0c1e370`.
The AlgoVoi records validate neither subsequent snapshot nor any future corpus
bytes. Reviewers should resolve the current digest from
`conformance/al2-vate-v0.3/corpus.json`; a submission for a different digest
requires its own comparison record.

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

| File | Raw file SHA-256 | `json-sorted-no-whitespace` SHA-256 |
|---|---|---|
| `sut-result.algovoi.json` | `dad99bbfd238bbc9fc002fcaf1e88e89282fabaae2241b526d78a47456479c74` | `ef6bd37bd68ef1b1c2f2a79212896c43ebbb76f9d4e76f1ee49888d68656f2c9` |
| `compare-report.json` | `6f90f6198b7c4d32dd5e40816fba7b0f586434f163649cb7656c94bfc0a4d042` | `fcb4f5760c227ab4ec8f5887c3e7dcd59f62e4f625fb772111bc15c272d779c9` |
| `implementation-report.json` | `9d9358b3c2e7b4d8948952a9824e5c150421b9be047492d6e4408f09361291c3` | `cd5ec88ae5273911c408fa1f496b6c21fdff972721f006793f3dbda6cc7bdd55` |

The third column uses the `json-sorted-no-whitespace` basis used by the report
and bundle-integrity fields in the v0.3.x reference runner. The raw file SHA-256
values are recorded only as fetched file-byte identifiers.

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

## AlgoVoi Eight-Case External Adapter Run

This is a deeper slice from the same AlgoVoi implementation line as the
three-case record above. It is not evidence from a second independent SUT. The
two slices overlap on `attenuate-max-amount`.

Source discussion:

- submitted result:
  `https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2#issuecomment-4967746389`
- acknowledgement after local verification:
  `https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2#issuecomment-4968971467`

External artifact location:

- `https://gist.github.com/chopmob-cloud/4828df3cb7458ca2bb27c87a73783d68`

Reviewed gist git revision:

- `676bf8bbb13037fcea33e87c56f403f7b4e496a4`

Implementation identifier reported by the submitted SUT result:

- name: `AlgoVoi external VATE SUT`
- type: `external-verifier`
- version: `0.2.0`
- language: `python`
- source: `https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors`
- reported commit: `external-adapter-8case-slice`

Corpus:

- source commit: `d467139a230358a7253204a5360665c637789c9d`
- profile: `VATE-AL2-Verifier-Admission-v0.3`
- digest basis: repository corpus manifest digest
- digest: `835864092b7afde1c751c4e2cad40aa8265b4ebb95234873c9b8d20f664cb2f6`

Submitted artifact files:

| File | Raw file SHA-256 | `json-sorted-no-whitespace` SHA-256 |
|---|---|---|
| `sut-result.algovoi.json` | `6ee98fc280de9800e8f6fe3e1745170e0b024812fb33ce3b82f28eedcb9045b1` | `e4e385f1c0ab269a928ca5c4a2bd0d14fa68af8cabac2d4290afe25355a28933` |
| `compare-report.json` | `47b716f88fd4fae528d7ff59804f1c0c8b877761298c58ae2faad7320540ef9e` | `51c178aa9642d58e626333c3db087dbbfb18c694bd232024f9af31c2e84414b1` |
| `implementation-report.json` | `f4d5bc5e22f1e51336154256827dc4624cd16b6f276f9b4df34b6984747671ad` | `0216b09d7220823af8332e4fee2017d17e8a9582562081506f2585975138f032` |
| `bundle-verification.json` | `667c4bd609d59fa897576575200e200e28a8b20b1f3da10f72869f136f74ae4a` | `f17ee0e298525149acaf6bd706afbab6ee7102f0ac296eb35db8955490f4da00` |

The third column uses the `json-sorted-no-whitespace` basis used by the report
and bundle-integrity fields in the v0.3.x reference runner. The raw file SHA-256
values are recorded only as fetched file-byte identifiers.

Cases included in the submitted SUT result:

- `deny-status-revoked`
- `deny-runtime-proof-stale`
- `attenuate-max-amount`
- `attenuate-target-scope`
- `attenuate-requires-new-permit`
- `post-execution-effective-constraints-exceeded`
- `post-execution-effective-constraints-aggregate-exceeded`
- `post-execution-runtime-mismatch`

Local verification result on 2026-07-27:

- SUT result shape validation: pass
- conformance report shape validation: pass
- implementation report shape validation: pass
- `compare`: `8 passed / 64 failed / 0 skipped / 72 total`
- remaining failed cases: all `sut result missing`
- implementation report status: `fail`, as required for partial `8/72` coverage
- `verify-bundle`: `23 passed / 0 failed`

Independence and interpretation boundary:

- the submitter reports that outcome, `should_execute`, and reason codes were
  derived from receipt artifacts without copying corpus expected values;
- the submitted bundle contains results and reports; this record did not
  independently review the adapter implementation source, so it does not
  independently establish that derivation method;
- the local comparison confirms that the eight submitted results match this
  corpus snapshot under the repository comparison rules;
- this is a broader slice from the same AlgoVoi implementation line as the
  three-case record, not multi-implementation agreement and not evidence for
  the remaining 64 cases.

Publication and durability caveat:

- the gist is an external mutable location and is not vendored into this
  repository;
- the submitted report URIs are relative references inside that external
  bundle;
- this record pins the reviewed gist git revision and artifact digests so the
  review can be traced, but it does not make the external gist immutable or
  maintainer-controlled by VATE.

Claim boundary:

- this is external adapter-run review evidence for eight cases;
- it records one implementation run against one corpus snapshot;
- the implementation report status is `fail`, because the submitted SUT result
  intentionally covers only eight cases from the 72-case corpus;
- this is not certification, endorsement, production approval, a passing
  full-corpus claim, general compatibility, or a second independent SUT result.
