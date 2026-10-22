# Contributing to Verifiable Agent Trust Envelope

Verifiable Agent Trust Envelope is an open discussion draft about verifier-side admission decisions and receipts for risky external AI-agent actions.
This repository is intended to evolve into a clearer protocol discussion space for specifications, profiles, schemas, and conformance-oriented artifacts.

## Contributions That Help Most

- tightening interoperability with existing standards
- reducing ambiguity in the object model or threat model
- improving example artifacts and JSON Schemas
- clarifying assurance levels and profile boundaries
- mapping this draft more precisely onto A2A, MCP, OAuth, VC, and workload identity systems
- proposing well-scoped extensions for P2P, external exchange, or physical AI
- contributing attack scenarios, failure modes, or operational counterexamples

## Ground Rules

- this draft is **not** a replacement for A2A or MCP
- this draft is **not** an A2A core proposal or universal trust layer
- this draft is **not** a rejection of OAuth, OpenID, or VC
- the core should stay small
- domain-specific concerns should move into profiles or extensions
- this draft should not assume a single global registry or a single issuer
- privacy-preserving and pairwise presentation should be preferred where appropriate
- capability and authority must remain separate concepts
- runtime proof and stable identity must not be conflated

## How to Frame an Issue or PR

Please include the following when possible.

### 1. Problem

- What is unclear?
- What is risky?
- What conflicts with an existing standard or deployment reality?

### 2. Change Type

Use one or more of:

- `core`
- `profile`
- `extension`
- `editorial`
- `schema`
- `reference`

### 3. Source Quality

Indicate the strength of the source you are relying on:

- `final standard`
- `RFC / Recommendation`
- `working draft`
- `official product doc`
- `OSS implementation`
- `ecosystem signal`

### 4. Compatibility Impact

- relationship to A2A
- relationship to MCP
- relationship to OAuth / OpenID
- relationship to VC / DID
- privacy or deployability impact

## Evaluation Priorities

Changes are evaluated in roughly this order:

1. correctness
2. security
3. interoperability
4. deployability
5. privacy
6. clarity

## Changes That Should Be Avoided

- embedding a universal reputation score into the core
- assuming vendor-specific or chain-specific lock-in
- making legal identity or KYC mandatory for all use cases
- mixing settlement logic into the core protocol
- weakening receipts or status handling for high-risk use cases

## What Good PRs Usually Look Like

- spec, examples, and schemas stay consistent
- date-sensitive references include dates
- official sources are preferred when available
- normative proposals are clearly separated from informative discussion
- new concepts are introduced only when existing concepts cannot absorb the problem cleanly

## Near-Term Priorities

The [roadmap](ROADMAP.md) connects admission, executed requests, outcome
evidence and recipient review. Useful contributions include:

1. reproduce the published execution paths and report an unclear or
   inconsistent evidence relationship;
2. test whether a recipient can distinguish an observed outcome, an unresolved
   attempt and missing evidence from the supplied artifacts;
3. identify what must change in an adapter or mapping when a source format or
   its evidence semantics changes;
4. contribute partial external SUT results with the evaluated inputs, native
   output, generated artifacts and remaining unsupported cases identified;
5. clarify how the existing A2A metadata profile can carry the required
   references while leaving evidence assessment with the recipient.

For a local execution review, start with the
[Execution Evidence Demo](reference/execution-evidence-demo/README.md) or the
[Vaara reproduction package](docs/interop/vaara-execution-reproduction.md).
For a corpus or SUT review, use the
[one-hour review request](docs/conformance/external-sut-ask-1-hour.md).
Share a reproducible result or question in
[issue #2](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2),
identifying which path and source version you used. An execution-evidence
review can use its native records without a VATE SUT result file.

## Checking GitHub Actions Workflows

Run the same workflow check used by CI from the repository root:

```bash
bash scripts/check_workflows.sh
```

The script runs [actionlint](https://github.com/rhysd/actionlint) 1.7.12 on all
workflow files. It supports macOS and Linux on arm64 and x86_64, using Bash,
curl, tar, and shasum. On the first run it downloads the official release
archive to `${XDG_CACHE_HOME:-$HOME/.cache}/vate/actionlint/1.7.12/`.
Every run verifies the archive against a SHA-256 checksum pinned in the
script before extracting and executing it. Later runs use the cached archive.
If checksum verification fails, remove the named cached archive and retry.

Optional ShellCheck and Pyflakes integrations are disabled so that installed
tools do not change the check between machines. Workflow syntax, expressions,
job dependencies, and matrix references are checked by actionlint itself.
CI runs this command in `Repository checks`, whose result is required by
`CI complete`. Runtime tests remain separate checks.

When updating actionlint, update the version and all four archive checksums
in the script from the same official release, and run the check again.

## CI Python Startup

The execution-evidence and source-archive jobs prepare standard-library
bytecode once in their disposable setup-python interpreter. This lets ordinary
test subprocesses reuse Python's compiled modules when the runner's interpreter
has no usable bytecode cache. The helper excludes third-party
packages, test directories, symlinks, and repository code.

The existing `-B` and `PYTHONDONTWRITEBYTECODE` settings still prevent automatic
bytecode writes by test processes. They permit reading the prepared standard
library. Isolated workers retain their empty private bytecode prefix.
Local development does not require running this CI-only helper.

## Related Documents

- `README.md`
- `ROADMAP.md`
- `docs/known-gaps.md`
- `docs/conformance/external-sut-quickstart.md`
- `docs/verifiable-agent-trust-envelope-spec-v0.1.md`
- `docs/standards-and-ecosystem-landscape-2026-04.md`
- `schemas/*.schema.json`
