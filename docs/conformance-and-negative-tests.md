# Conformance And Negative Tests

This note sketches how implementations of this draft can move from examples to repeatable interoperability checks.

The immediate goal is not a formal certification program.
The immediate goal is to make it possible for different implementations to prove that they interpret the same artifact relationships and failure cases in comparable ways.

## Why Conformance Matters Early

Protocol drafts often look clearer on paper than they behave in code.

For this draft, conformance work matters early because a verifier must correctly combine:

- identity artifacts
- runtime proof
- mission-scoped permission
- status information
- admission and post-execution receipts

If two implementations disagree on the order or meaning of those checks, the protocol will fragment even if the JSON shapes look similar.

## Minimal Conformance Surface

An early conformance profile for this draft should at least test whether an implementation can:

- parse `APC`, `ARP`, `AMP`, and `AER` artifacts
- verify compact JWS or equivalent proof packaging
- resolve signer trust anchors
- verify actor / subject / audience bindings
- evaluate permit time windows
- apply status outcomes across pull, stapled, and push delivery modes
- emit a machine-readable verification result

For a first pass, the output can be a simple report of named checks with boolean results.
That is enough to compare behavior across implementations before introducing a heavier test harness.

## Negative Tests Matter As Much As Happy Paths

Happy-path examples are useful, but they are not enough.

This draft needs negative tests that show the verifier rejects:

- tampered signed artifacts
- stale or revoked status
- runtime-to-permit binding mismatches
- audience mismatches
- receipts that reference the wrong permit, runtime, or admission receipt
- permits whose validity window does not cover the execution

These cases are important because many real failures are not signature failures.
They are semantic failures across otherwise well-formed objects.

## Suggested Negative Test Categories

### 1. Signature Integrity

- passport content changes without a new issuer signature
- runtime proof changes without a new attestor signature
- permit changes without a new broker signature
- post-execution receipt changes without a new runtime or verifier signature

### 2. Binding Integrity

- runtime subject does not match the passport subject
- permit actor does not match the passport alias
- permit proof-of-possession key does not match the runtime-presented key
- receipt signer does not match the declared `issuer_role`
- receipt `issuer_role` conflicts with the observed signer role

### 3. Audience And Scope Integrity

- runtime challenge audience differs from the permit audience
- receipt verifier differs from the permit audience
- permit action or resource exceeds local policy

### 4. Time And Freshness

- permit expires before execution begins
- runtime proof expires before execution finishes
- status freshness window is stale

### 5. Status Outcomes

- permit is revoked
- runtime is quarantined
- passport is suspended
- permit is attenuated but no machine-readable `effect` is present
- permit is attenuated but local policy does not know how to narrow execution safely

## What The Demo Implements

The `reference/minimal-al2-demo` directory now includes:

- a positive validation path with compact JWS verification
- a local trust bundle for signer resolution
- a status service with pull, stapled, and push delivery modes
- negative test bundles that intentionally fail selected checks

This is still not a language-neutral certification program.
But it now includes a concrete verifier-centered wedge and a machine-readable corpus under `conformance/al2-http/`.

The better question is "does the verifier fail for the right reason?"

## Current Corpus Layout

The current repository ships a narrow AL2 corpus for the HTTP verifier wedge:

- `conformance/al2-http/positive/allow-active/`
- `conformance/al2-http/positive/attenuate-tool-narrow/`
- `conformance/al2-http/negative/deny-revoked/`
- `conformance/al2-http/negative/deny-unknown-effect/`
- `conformance/al2-http/verification-report.schema.json`

These cases are replayed by `reference/http-verifier-demo/http_verifier_demo.py run-corpus`.
They are intentionally scoped to the current v0.1 battlefield:

- external digital write
- local verifier policy
- allow / attenuate / deny branching
- verifier-signed receipts

## Recommended Next Step

The next step after the local demo and AL2 HTTP corpus is a broader shared test corpus:

- canonical input bundles
- expected verification reports
- expected failed check names
- profile metadata such as `AL2`

That corpus could later back:

- CLI validators
- SDK test fixtures
- CI conformance runs
- interoperability bake-offs between independent implementations
