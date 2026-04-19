# HTTP Verifier Demo

This directory contains a narrow verifier-centered wedge for AL2-style external digital write flows.

It is intentionally focused:

- it exposes a single `POST /execute` API
- it expects `app_context.passport`, `app_context.runtime_proof`, and `app_context.mission_permit`
- it evaluates the trust envelope artifacts in verifier order: status -> identity -> runtime -> permit -> policy
- it returns one of three decisions: `allow`, `attenuate`, or `deny`
- it emits a verifier-signed execution receipt

## Start Here

If you want the fastest path:

1. run `generate-demo`
2. run `serve` against `allow-active`
3. run `execute-demo`
4. inspect `verification_report` and the emitted verifier receipt

This demo is the most direct illustration of the current repository thesis:
an external verifier decides `allow / attenuate / deny` from the trust envelope artifacts plus local policy.

## Why This Demo Exists

The repository already contains `reference/minimal-al2-demo/`, which focuses on packaging, status delivery, and negative checks for this draft.

This verifier demo adds the missing adoption wedge:

- how an external service can request the trust envelope artifacts
- where local policy fits into evaluation
- how attenuation becomes an operational decision rather than only a status label
- how a relying party can emit a verifier-signed `AER`

## Scenarios

`generate-demo` produces four scenario directories:

- `allow-active`
- `attenuate-tool-narrow`
- `deny-revoked`
- `deny-unknown-effect`

Each scenario directory contains:

- trust envelope payloads and compact JWS packages
- `request.json`
- `trust-bundle.json`
- verifier keys

## Commands

Generate the demo bundle:

```bash
python3 reference/http-verifier-demo/http_verifier_demo.py generate-demo --out /tmp/app-http-demo
```

Run the verifier for one scenario:

```bash
python3 reference/http-verifier-demo/http_verifier_demo.py serve --dir /tmp/app-http-demo/scenarios/allow-active
```

Execute the scenario request:

```bash
python3 reference/http-verifier-demo/http_verifier_demo.py execute-demo --dir /tmp/app-http-demo/scenarios/allow-active --base-url http://127.0.0.1:8050
```

Replay the conformance corpus:

```bash
python3 reference/http-verifier-demo/http_verifier_demo.py run-corpus --corpus-root conformance/al2-http
```

## Output

Each executed scenario writes:

- `http-verifier-response.json`
- `verifier-execution-receipt.json`
- `verifier-execution-receipt.jws`

The response includes:

- normalized `verification_report`
- detailed named checks
- signed execution receipt

## What This Demo Shows Best

- where the trust envelope artifacts appear in a real verifier request
- how local verifier policy fits into the decision
- how `attenuated` can become an operational branch instead of a descriptive label
- how a relying party can emit a verifier-signed `AER`

## Limits

This is still a demo profile:

- the policy model is local JSON, not a shared standard
- status delivery is stapled in this wedge to keep the path narrow
- trust distribution is still local file based
- receipt semantics are educational, not compliance-grade

It does **not** yet show:

- inter-organizational trust discovery
- a final VC or production JOSE profile
- hardware-backed runtime attestation
- a full agent-to-agent delegation flow
