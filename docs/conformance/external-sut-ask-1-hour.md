# One-Hour External SUT Or Corpus Review Request

## Status

This is the smallest useful external review path for the current
`VATE-AL2-Verifier-Admission-v0.3` discussion-draft corpus.

It is not a request for adoption, endorsement, certification, production
approval, standardization, or official A2A / MCP compatibility.

## Goal

The narrow question is:

> Can someone outside the repository reference runner understand the v0.3 AL2
> corpus well enough to review it, question it, or produce a comparable SUT
> result file?

A failing, partial, skipped, unsupported, or critical result is useful when it
identifies what was attempted and what was unclear.

## Useful Outcomes

Any one of these is useful:

1. Review the corpus and identify unclear cases, reason codes, checks, or
   artifact-binding requirements.
2. Produce a draft SUT result file for some or all v0.3 AL2 cases.
3. Run `compare` against a SUT result file and share the report outcome.
4. Publish an implementation report for one implementation run against one
   corpus snapshot.
5. Report that the task was too ambiguous or too expensive to complete, with
   notes about where the instructions failed.

You do not need to produce a passing report for the review to be useful.

## Smallest Useful Review

If a full adapter or full-corpus pass is too much for a first review, pick three
cases and report where the boundary is unclear.

Suggested starter set:

- `allow-valid-admission`
- `attenuate-max-amount`
- `deny-digest-mismatch-before-policy`

That is enough to test whether the basic `allow`, `attenuate`, and fail-closed
paths are understandable without treating the Python reference runner as the
primary specification. A reviewer may choose different cases if another boundary
looks more important.

## Scope

- Target corpus: `conformance/al2-vate-v0.3`
- Expected time: about 60 minutes for a first-pass corpus review; longer for a
  real adapter, implementation run, or generated artifact bundle
- Primary intake thread:
  [issue #2](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2)
- Full external SUT path:
  [External SUT Quickstart](external-sut-quickstart.md)

## Non-Goals

This is not:

- certification;
- endorsement;
- production approval;
- a request for A2A adoption;
- an MCP, OAuth, AP2, VC, or payment-protocol replacement;
- a production JOSE / PKI / Sigstore verification review;
- a general compatibility claim.

## Suggested Review Focus

Useful questions include:

- Are `allow`, `attenuate`, and `deny` outcomes clear enough?
- Is `should_execute` understandable for attenuation and fail-closed cases?
- Are reason codes specific and ordered enough?
- Are digest-bound artifact references practical for an external SUT?
- Are admission receipts and post-execution receipts linked tightly enough?
- Are MCP/OAuth, A2A, AP2, commerce, and adjacent-evidence boundaries clear?
- Does any wording imply certification, endorsement, production approval, or
  official adjacent-protocol compatibility?

## Suggested Comment Shape

When commenting on issue #2, include as much of this as practical:

```text
Review type:
Implementation language or tool:
Corpus snapshot:
Used the repository reference runner: yes/no
Attempted cases:
If this was a three-case review, why these cases:
Produced SUT result file: yes/no
Produced generated artifacts or bundle: yes/no
Ran compare: yes/no
Generated implementation report: yes/no
Unclear cases or fields:
Boundary or overclaim concerns:
Notes:
```

Do not paste secrets, private credentials, access tokens, production logs, or
sensitive customer data into the issue.

## Claim Boundary

A passing `compare` report means only that one submitted SUT result matched one
corpus snapshot under this repository's comparison rules.

It does not imply certification, endorsement, production readiness, official
compatibility, future compatibility, or a complete security review.
