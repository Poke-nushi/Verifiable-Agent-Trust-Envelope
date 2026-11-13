# Public Claim Boundary

This note is the short public boundary for README text, roadmap text, release
notes, GitHub issues, outreach notes, and implementation reports.

VATE is a discussion-draft verifier-side admission and receipt profile for
risky AI-agent actions. It composes with A2A, MCP/OAuth, AP2/VC-style evidence,
and related systems, while recording the relying party's pre-execution decision:
`allow`, `attenuate`, or `deny`.

It does not replace, validate, certify, or officially extend those adjacent
protocols.
It is not an A2A core proposal or a universal trust layer.

## Safe Summary

Use this summary when a short public description is needed:

> VATE is a discussion-draft verifier-side admission and receipt profile for
> risky AI-agent actions. It records the relying party's pre-execution decision
> - allow, attenuate, or deny - using digest-bound evidence references, without
> replacing or officially extending A2A, MCP/OAuth, AP2, VC, or related systems.
> It is not an A2A core proposal or a universal trust layer.

## What The Repository Is

It is accurate to describe this repository as:

- a public Apache-2.0 specification draft;
- a verifier-side admission and receipt model;
- a discussion draft for risky external agent actions;
- a reference runner and fixture corpus for review;
- an external SUT comparison aid;
- an implementation reporting format for one implementation run against one
  corpus snapshot;
- a place to collect technical review and independent implementation evidence.

## What The Repository Is Not

Do not describe this repository as:

- production-ready;
- a certification program;
- an endorsement, approval, or compatibility badge;
- an official A2A extension;
- an A2A core proposal;
- a universal trust layer;
- an MCP, OAuth, AP2, VC, or OpenID replacement;
- a complete security review;
- a production JOSE/JCS, PKI, Sigstore, or signed-git verification profile;
- proof that an implementation is generally compatible with future corpus
  versions or unrelated deployments.

## Report And Command Boundaries

Use these meanings consistently:

- `run` checks this repository's committed corpus fixtures and reference runner
  behavior. It is a repository fixture integrity check, not an external
  implementation result.
- `compare` checks an external SUT result file against one corpus snapshot. A
  passing comparison means the submitted SUT result matched that snapshot under
  the repository comparison rules.
- A `corpus-fixture-validation` comparison checks that submitted artifact
  references match exact corpus fixture digests. It does not prove that the SUT
  read or evaluated those bytes, and it is not evidence that the SUT issued
  receipts.
- A `generated-receipts` comparison additionally checks locally supplied
  receipt digests, schema-aligned bounded receipt semantics, and applicable
  post-execution linkage. The submitting party identifies those files as SUT
  output; the comparison does not prove execution, authorship, provenance,
  signature validity, source independence, or production readiness.
- `verify-bundle` checks the local digest chain among the corpus, SUT result,
  conformance report, and implementation report. It is not a production
  signature profile and does not replace external proofs.
- An implementation report records one implementation run against one corpus
  snapshot. It is not an endorsement, certification, or production approval.

## Optional Python Execution Integrations

The optional [runtime](../reference/runtime-jwt/README.md) and
[caller-authority](../reference/caller-authority/README.md) integrations verify
ES256 signatures under their named profiles and operator-selected keys and
grants. Describe these as reference implementations for the supported purchase
profile. Signature validity, issuer authority and current permission to execute
are separate checks. Corpus proof-artifact checks remain byte-level checks.

[Dispatch revalidation](../reference/request-binding/DISPATCH.md) calls the
configured runtime verifier and, when selected, caller authorizer before
invoking the configured local callback.
[Durable state](../reference/request-binding/DURABLE-STATE.md) preserves consumed
attempts within one selected store and operation scope. These checks do not
establish enforcement at an arbitrary remote service or exactly-once external
effects.

[Authority updates](../reference/authority-updates/README.md) apply authenticated
snapshots to subsequent policy leases; expiry and age limits bound cached use.
The [Hydra/OpenFGA issuer example](../reference/authority-issuer/README.md) covers
one explicitly selected identity, resource and permission mapping. Describe
its results as local integration observations, without implying instantaneous
revocation, general IAM compatibility or production readiness.

## Allowed Phrasing

These phrases are safe when they match the artifact being discussed:

- "discussion draft"
- "specification draft"
- "reference runner"
- "fixture integrity check"
- "external SUT comparison"
- "implementation report"
- "one implementation run against one corpus snapshot"
- "digest-bound artifact references"
- "review aid"
- "not production-ready"
- "no certification, endorsement, or production approval implied"

## Discouraged Phrasing

Avoid these unless the surrounding sentence narrows the claim clearly:

- "compatible" without naming the exact corpus snapshot and comparison rules;
- "conformance" without saying whether this is `run`, `compare`, or a future
  governance process;
- "A2A extension" without saying metadata-only, optional, by reference, and not
  official;
- "MCP/OAuth solution" without saying VATE consumes adjacent authorization
  evidence and never widens upstream authority;
- "AP2 integration" without saying AP2 artifacts are adjacent payment-authority
  evidence, not VATE-defined payment semantics;
- "JOSE proof support" without distinguishing byte-level corpus checks from
  signature verification in a named optional reference profile, with its
  selected backend, keys and authority policy.

## Forbidden Phrasing

Do not use these as public claims for the current repository state:

- "VATE is certified"
- "certification-ready"
- "production-approved"
- "official compatibility"
- "A2A-approved"
- "A2A official extension"
- "A2A core proposal"
- "universal trust layer"
- "AP2 validates VATE"
- "VATE solves MCP authorization"
- "VATE provides agent identity"
- "complete JOSE/PKI validation"
- "complete security review"
- "production-grade verifier"
- "general compatibility proof"

If future work creates any of these claims, it needs a separate governance,
security, and release decision. Do not imply it from a passing report.

## Adjacent Protocol Boundary

Use this mental model:

- A2A carries the task and optional metadata references.
- MCP and OAuth provide tool, resource, and authorization context.
- AP2, VC, OpenID, workload identity, and related systems can provide evidence.
- VATE records the relying party's verifier-side decision before execution and
  links it to post-execution evidence where applicable.

Adjacent artifacts are evidence inputs. They are not sufficient authority by
themselves unless the selected VATE profile and local verifier policy evaluate
them as sufficient for the requested action.
