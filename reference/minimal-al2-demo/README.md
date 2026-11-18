# Minimal AL2 Demo

This directory contains a small reference demo for an AL2-style flow for this draft.

It is intentionally limited:

- it is educational, not production-grade
- it uses compact JWS packaging backed by local OpenSSL keys rather than a full VC stack
- it is designed to illustrate artifact generation, status retrieval, and verification order

This demo uses the earlier AER profile. Its report's `request_binding` field
marks v0.3 purchase-cap preimage binding `not_checked` and the binding
requirement unmet. The [current binding example](../request-binding/README.md)
provides that separate assessment.

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
- verify each artifact with a registered P-256 public key in the expected signer role
- check that the runtime signed a `post_execution` receipt and that its execution interval falls within the passport, runtime proof, and permit validity periods
- check a signed narrowing instruction for `mode: narrow`, a `constraints` object, and an explicit `require_new_permit: false`
- fetch stapled or push status artifacts from the service
- generate negative test bundles and show which validation checks fail

## Why the demo uses compact JWS

The demo uses stock Python 3 and the local `openssl` binary to generate keys
and sign compact JWS tokens.

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

Use a dedicated output directory. Regenerating a complete demo installs fresh
keys and artifacts together and clears reports from the previous generation.
If the directory is incomplete or contains other files, generation stops and
leaves it intact. Choose a fresh directory to keep both sets.

If an interrupted update leaves `.<name>.vate-update` beside the demo, first
confirm that no generator is running. If the output is missing and the
update directory contains `previous`, move it back to the original output path.
Move the remaining update directory aside before retrying.

Run the status service:

```bash
python3 reference/minimal-al2-demo/trust_envelope_demo.py serve-status --dir /tmp/app-demo --port 8042
```

Leave the service running. In a second terminal at the repository root, verify using status from the service:

```bash
python3 reference/minimal-al2-demo/trust_envelope_demo.py verify-demo --dir /tmp/app-demo --status-mode pull --status-base http://127.0.0.1:8042
```

Pull verification fetches `/status/bundle` for all three objects. The
individual status endpoints let you inspect one passport, runtime, or permit.
The service signs from its status store and checks each new token against its
registered status key. If the signing key and registration disagree, the
service returns HTTP 500. Once the key is restored, clients can fetch fresh
tokens even if their saved copies are missing.

To save stapled and push artifacts locally, first save any reports you need.
Receiving a new token clears the top-level verification and negative-test
reports. Run the verifier again for the delivery mode you want to check.

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
- status artifacts with a required `effect` on every `attenuated` entry

The verifier writes:

- `verification-report.json`

Each `verify-demo` run replaces the previous report. Check its `ok` field:
the CLI can exit successfully while reporting a rejected verification.
Unavailable status, invalid signatures, unauthorized signer roles, and unusable
input produce `ok: false` with the failed checks. Timestamps require a UTC
offset and must be exactly representable in microseconds. In every delivery
mode, the signed `generated_at` and `next_update_at` must cover the verification
time recorded in `checked_at`. The signed execution must have finished by
that instant. The generated example records a completed, instantaneous
synthetic action. Pull uses the window in the status store. Regenerate an expired demo
bundle to start a new run. The bundle must contain status entries for the
presented passport, runtime, and permit. Failed signature or role checks stop
interpretation of the affected payloads.

Each `attenuated` entry requires an `effect` with `mode: narrow`, a
`constraints` object, and a boolean `require_new_permit`. A reissue request
from any entry fails verification, including an otherwise active entry.
Minimal also rejects a narrowed passport or runtime, and any nonempty
narrowing constraints on an entry whose state is not `attenuated`. For a permit,
an explicit `{}` supplies an empty set of changes. A successful Minimal check
confirms the instruction's structure and reissue flag. The
[HTTP verifier demo](../http-verifier-demo/README.md#signer-authority-and-attenuation)
computes effective permit constraints and checks the submitted resource,
tool, and approval reference against them.

The mission permit must have a non-empty string `transaction_id` and a
non-empty `actions` array containing only non-empty strings. Invalid permit
scope produces `verification_input`. The receipt must carry the same
`transaction_id`; a missing, malformed, or different value fails
`receipt_transaction_binding`. Both failures produce `ok: false` in all three
status delivery modes. This demo checks the signed permit/receipt chain; it
does not compare a separately submitted action request or apply the HTTP
demo's local maximum-age policy.

Signer roles come from the verifier's local `trust-bundle.json`, using the
authenticated key's `owner`: `issuer` for the passport, `attestor` for the
runtime proof, `broker` for the mission permit, and `runtime` for this demo's
execution receipt. Status must be signed by a `status` key in all three delivery
modes. A valid signature from another known role fails verification. The
generic `verify_compact_jws` helper checks packaging and signatures;
`verify_role_bound_jws` adds the caller-selected role check used by these demo
entrypoints. Callers of the generic helper must supply their own issuer
authority policy.

Subject, actor, audience, and receipt references must match as non-empty
strings. For the demo's `cnf-kid` binding, the runtime proof and permit
identify a registered runtime-owned ES256 key. They may both omit the
public-key fingerprint. When supplied, both fingerprints must match the
registered public key. The receipt must also be signed by that key.
Each compact JWS segment must use unpadded base64url in its canonical form.
Signed JSON objects must use unique member names and finite numbers that
the demo can read without losing decimal precision.

Verification reads the trust bundle, signed artifact files, and only the
selected status delivery. Decoded artifact JSON and `status-store.json` are
generator/service inputs. A registered public key that is unavailable,
unreadable, or inconsistent with its local fingerprint stops the command.
Restore the key and rerun verification. The previous report is removed
before each attempt.
The bundle directory must be writable. This local demo does not support
concurrent verification runs writing to the same report path.

The negative test runner writes:

- `negative-test-report.json`
- `negative-cases/*/verification-report.json`

The command removes the previous summary before reading its inputs. It writes
a new summary after installing the full set of case reports. Exit status zero
means each case reported every failure listed in its expectations. The summary
also lists any additional failures. If an expected failure is missing, the
command exits unsuccessfully. If the run stops before publishing a summary,
the individual reports may still belong to the previous run.

## What This Demo Does Not Yet Show

- a final interoperable VC packaging profile
- remote trust distribution
- higher-assurance runtime attestation
- production-grade receipt and evidence handling
- a complete enterprise delegated identity integration

Future implementation work for this demo could include:

- VC or profile-specific JOSE packaging instead of the current demo profile
- remote trust distribution instead of local PEM files
- explicit status service policy and cache rules
- conformance vectors that multiple implementations can share
