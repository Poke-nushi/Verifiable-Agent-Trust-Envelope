# Minimal AL2 Demo

This directory contains a small reference demo for an AL2-style flow for this draft.

It is intentionally limited:

- it is educational, not production-grade
- it uses compact JWS packaging backed by local OpenSSL keys rather than a full VC stack
- it is designed to illustrate artifact generation, status retrieval, and verification order

## Start Here

If you only want one quick path through the demo:

1. run `generate-demo`
2. run `serve-status`
3. run `verify-demo --status-mode pull`
4. inspect `verification-report.json`

Use this demo if you want to understand the artifact lifecycle before looking at the HTTP verifier wedge.

## What it does

The demo can:

- generate decoded trust envelope payloads plus compact JWS packages
- generate a trust bundle with public keys
- run a minimal HTTP status service
- verify the resulting chain in `pull`, `stapled`, or `push` status modes
- validate receipt signer role semantics via `issuer_role`
- validate machine-readable attenuation effects for `attenuated` permit status
- fetch stapled or push status artifacts from the service
- generate negative test bundles and show which validation checks fail

## Why the demo uses compact JWS

The repository currently avoids Python package dependencies.  
To keep the demo runnable with a stock Python 3 installation while still showing a real package boundary, it uses the local `openssl` binary to generate keys and sign compact JWS tokens.

That makes it suitable for:

- lifecycle illustration
- verifier ordering tests
- payload versus packaging separation
- trust-bundle based verification
- minimal status service testing
- negative test / conformance sketching

It does not make it suitable for:

- real deployment
- inter-organizational trust
- interoperable VC production verification
- hardware attestation or federation

## Commands

Generate a full demo bundle:

```bash
python3 reference/minimal-al2-demo/trust_envelope_demo.py generate-demo --out /tmp/app-demo
```

Run the status service:

```bash
python3 reference/minimal-al2-demo/trust_envelope_demo.py serve-status --dir /tmp/app-demo --port 8042
```

Verify by pulling fresh status at request time:

```bash
python3 reference/minimal-al2-demo/trust_envelope_demo.py verify-demo --dir /tmp/app-demo --status-mode pull --status-base http://127.0.0.1:8042
```

Fetch stapled and push artifacts from the service:

```bash
python3 reference/minimal-al2-demo/trust_envelope_demo.py fetch-status --dir /tmp/app-demo --status-base http://127.0.0.1:8042 --mode all
```

Verify local stapled or push status:

```bash
python3 reference/minimal-al2-demo/trust_envelope_demo.py verify-demo --dir /tmp/app-demo --status-mode stapled
python3 reference/minimal-al2-demo/trust_envelope_demo.py verify-demo --dir /tmp/app-demo --status-mode push
```

Run negative tests against the bundle:

```bash
python3 reference/minimal-al2-demo/trust_envelope_demo.py run-negative-tests --dir /tmp/app-demo
```

## Output Files

The generator writes:

- `trust-bundle.json`
- `passport-credential.json`
- `passport-credential.jws`
- `runtime-proof.json`
- `runtime-proof.jws`
- `mission-permit.json`
- `mission-permit.jws`
- `execution-receipt.json`
- `execution-receipt.jws`
- `status-store.json`
- `stapled-status.jws`
- `push-status-event.jws`
- `keys/*.pem`

The generated payloads now include:

- `mission-permit.json` with `issued_at`
- `execution-receipt.json` with `receipt_phase`, `issuer_role`, `policy_id`, `policy_version`, `evidence_refs`, and `artifact_digests`
- status artifacts that may carry an `effect` object when a permit is attenuated

The verifier writes:

- `verification-report.json`

The negative test runner writes:

- `negative-test-report.json`
- `negative-cases/*/verification-report.json`

## Recommended Use

Treat this demo as a protocol sketch:

- useful for validating assumptions
- useful for showing the trust envelope artifact relationships
- useful for showing payload versus package boundaries
- useful for showing status retrieval mode differences
- useful for showing verifier-side failure modes

## What This Demo Does Not Yet Show

- a final interoperable VC packaging profile
- remote trust distribution
- higher-assurance runtime attestation
- production-grade receipt and evidence handling
- a complete enterprise delegated identity integration

The next natural step after this demo is a reference implementation with:

- VC or profile-specific JOSE packaging instead of the current demo profile
- remote trust distribution instead of local PEM files
- explicit status service policy and cache rules
- conformance vectors that multiple implementations can share
