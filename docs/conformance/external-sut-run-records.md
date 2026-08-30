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
The Pulse record below was evaluated against the 75-case snapshot at VATE
commit `5a37f87de0190da44e619b1800261637e83dd7ed`. That snapshot records 212
manifest artifacts and corpus digest
`988aae7d03dd5bb743e8e03e6ab1120ce8735a4837ac818ffd9d665de0c1e370`.

The 76-case `main` snapshot at commit
`094146757709be01912abf9308781057c81067ad` records 216 manifest artifacts and
corpus digest
`195aad6651911be243b5ccbc87fa93d5ca9e46b3ccde1b14cb4688b2089473d7`.
The records below validate only their named snapshot and no later or future
corpus bytes. Reviewers should resolve the current digest from
`conformance/al2-vate-v0.3/corpus.json`; a submission for a different digest
requires its own comparison record.

## Pulse Three-Case Bounded External SUT Run

This is a solicited, candidate-executed external SUT record for three selected
AP2 human-not-present cases. The Pulse maintainer supplied the mapping and
projection source, generated fresh Pulse inputs, executed the frozen native
Pulse verifier, preserved its raw reports, and published the resulting VATE
comparison bundle. VATE supplied the fixed input contract and later performed
a focused intake confirmation. This is not organic adoption or a full-corpus
Pulse implementation.

Source discussion:

- accepted reciprocal scope and fixed pins:
  `https://github.com/shibutatsu/pulse-ap2-x402-conformance/issues/18#issuecomment-5448061291`
- corrected candidate delivery:
  `https://github.com/shibutatsu/pulse-ap2-x402-conformance/issues/18#issuecomment-5466231021`
- VATE focused confirmation:
  `https://github.com/shibutatsu/pulse-ap2-x402-conformance/issues/18#issuecomment-5468193500`

External artifact location:

- corrected evidence directory:
  `https://github.com/shibutatsu/pulse-ap2-x402-conformance/tree/3bb52c400535f28ee3f5d2e0a2bdb01e9c45c407/evidence/vate-pulse-bounded-2026-08-30`
- evidence correction PR:
  `https://github.com/shibutatsu/pulse-ap2-x402-conformance/pull/55`
- evidence merge commit:
  `3bb52c400535f28ee3f5d2e0a2bdb01e9c45c407`

Fixed revisions:

- VATE source and corpus:
  `5a37f87de0190da44e619b1800261637e83dd7ed`
- corrected VATE starter and validator:
  `04e2cfaaca1843b67d88d558ccbf4e69d4f14179`
- candidate-owned mapper and worksheet:
  `1ee413652f11e720a0da7ffb318e91d87a447d4c`
- frozen Pulse verifier:
  `e06a6cbfe3ddb965c8fc70f50838f5014ec2038e`
- frozen Pulse entry point: `src/verifier.ts#verifyConformanceCase`

Implementation identifier reported by the submitted SUT result:

- name: `Pulse AP2-x402 external VATE attempt`
- type: `external-verifier-projection`
- version: `vate-pulse-mapper/0.2`
- language: `Python standard library`
- source: `https://github.com/shibutatsu/pulse-ap2-x402-conformance.git`
- candidate commit: `1ee413652f11e720a0da7ffb318e91d87a447d4c`

Candidate execution record:

- evidence class: `candidate-executed`
- attempt status: `completed`
- mapper command: `python3 -I -S -B mapper.py`
- recorded runtime: Python `3.14.4`
- recorded runtime raw SHA-256:
  `02a8df1726463faedb3adef289b3d1bdeabb7785c837fd8c174023aeeeb4d312`
- mapper commit export: two tracked regular files, 135652 total bytes, inventory
  SHA-256
  `502815fd598e123ed603329936653840aaee038c80f4819b50f1fa6beb145631`
- the candidate record declares no external packages, runtime network access,
  or writes to the fresh commit export;
- the run contract includes four randomized sensitivity dimensions for each
  selected case: amount, merchant, evaluation time, and replay nonce.

Selected results:

| VATE case | Frozen Pulse observation | Relation to VATE |
|---|---|---|
| `allow-ap2-hnp-preauthorized-mandate` | `allow`; `EVIDENCE_VERIFIED`, `POLICY_MATCH` | match |
| `attenuate-ap2-hnp-amount-overrun` | `deny`; `AP2_X402_AMOUNT_MISMATCH` | explicit mismatch: VATE expects `attenuate` |
| `deny-ap2-hnp-stale-mandate` | `deny`; `PERMIT_EXPIRED`, `FAIL_CLOSED` | match |

Key submitted artifacts:

| File | Raw file SHA-256 | `json-sorted-no-whitespace` SHA-256 |
|---|---|---|
| `starter-manifest.json` | `af8a13ff90a48f442b4306d44e4944b854bea019215adfccf0b11805d6c1d266` | `34a8ea2210e7d74bd363bf4e3f668adb07d3c691d8a253cc1bef5d7d6a468c37` |
| `mapping-source/mapper.py` | `85c87df9a5e4d33c6d68078212a7f94f3271c22b8a69d5c20f526b3879073efb` | n/a |
| `mapping-worksheet.json` | `270ae12d7dd4e3ef0149a26ef234c53aee4d40a74e93f74c49c93e5f813cd91c` | `5476e0064ad295561e3948f1c6ad718dfc2583c6c93db82ced97e6f22fbdcb1d` |
| `raw-pulse-output.json` | `12d024b44ff5ddbe3aa3ebf0d116a762fdb1376dc4950399b7380515628d8e96` | `5777a10c3849e6b608a71345f149998d9880949a0455f972df8da51fa640d32f` |
| `pulse-sut-result.json` | `71739b6e4bbf9e30075bfb1e15415cc9e23f37923188bba87b9ab967f59c61e9` | `edfd466c3bd6de3e6819109dcafc03348107ce4c7697bd520c9042117e09d00c` |
| `vate-compare-report.json` | `013ce2e58849f88606244edb5825ea892ccae1eddf2afcd8fc7e99e0cf719006` | `92e7d9db4de1d0bf0b30aa94ee71eeec11ea70e2d38c5a36f64750e11dbf349e` |
| `vate-implementation-report.json` | `2754ca5a6754042aef6e927c119ddf1ab853f0a93129982d4c740c2c71a132d1` | `a0c30a9b3ecf61d389ad12cd1caffd6c13c170cc307aab477ccdfd28873da49c` |
| `vate-bundle-verification.json` | `d5701305f1af32133a301f9f42710bbeeed5fb5f3f90370b334e47fa9aba84ed` | `1aa323f4514808a44dcc3eb990934d8632655a6694374878d326ecfbb9fecfab` |

The third column uses the `json-sorted-no-whitespace` basis used by the fixed
VATE runner for report and bundle-integrity descriptors. Raw SHA-256 values
identify the fetched file bytes at the evidence merge commit.

VATE focused confirmation on 2026-08-30:

- the candidate delta from the original delivery commit `ce125db` to the
  corrected commit `1ee4136` changed only `mapping-worksheet.json`;
- `mapper.py` remained byte-identical;
- the five corrected worksheet leaves now identify the direct VATE source,
  source pointer, dependency, transform, and `vate-derived` provenance;
- all 15 evidence references named by the corrected run record matched their
  raw SHA-256 values;
- fixed VATE reference run: `75 passed / 0 failed`;
- `compare`: `2 passed / 73 failed / 72 skipped / 75 total`, exit `1`;
- implementation report status: `fail`;
- `verify-bundle`: `27 passed / 0 failed`, exit `0`.

Result interpretation:

- exactly three selected cases were executed; the other 72 entries are
  explicit `skipped` / `out-of-scope` records;
- the fixed runner counts every skipped entry as a comparison failure, so the
  `73 failed` summary means one executed semantic mismatch plus 72 unexecuted
  cases, not 73 failed Pulse executions;
- the amount-overrun result is retained as a real design difference: VATE
  records `attenuate`, while frozen Pulse reports a deny/non-attenuate result;
- the `27/27` bundle result establishes the recorded local digest chain. It
  does not convert the semantic mismatch into a pass.

Runtime and replay boundary:

- the corrected candidate evidence records Python `3.14.4` and its runtime
  digest;
- the VATE maintainer host used for the focused confirmation exposed Python
  `3.14.3`, so that pass did not claim byte-identical reproduction of the
  candidate runtime;
- the mapper is unchanged from the earlier intake, where its map and projection
  outputs and the frozen Pulse reports were reproduced under a separately
  recorded reviewer runtime, including all 12 sensitivity probes;
- this disclosed runtime difference limits the replay claim but does not change
  the candidate-owned execution record or the observed three-case results.

Claim boundary:

- this is one solicited, bounded external SUT run against one fixed 75-case
  VATE snapshot;
- it records two matching selected decisions and one explicit semantic
  mismatch;
- it does not validate the current 76-case corpus or the other 72 cases in the
  fixed snapshot;
- it is not a Pulse security audit, organic adoption, endorsement,
  certification, production approval, passing full-corpus result, or general
  compatibility claim;
- it does not complete Pulse Issue #18.

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
