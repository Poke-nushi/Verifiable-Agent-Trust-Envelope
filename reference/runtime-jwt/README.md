# Signed runtime evidence for admission

This adapter verifies ES256-signed runtime evidence and passes authenticated
claims to the ordinary Python `VateVerifier.admit` entry. It checks that the
configured issuer may assert the specified runtime and audience, and that the
signed evidence belongs to the current request. Invalid signatures, missing
authority, stale trust information and expired evidence stop admission.

Use it when a runtime evidence issuer can produce the narrow JWT payload in
the [integration contract](CONTRACT.md). The current admission path supports
[`vate-purchase-cap-request-v1`](../request-binding/CONTRACT.md#objects-and-identifiers).
The issuer signs the request-context
hash defined by [request binding](../request-binding/RUNTIME-EVIDENCE.md#request-context-binding).
The application supplies its trusted public keys and issuer grants. This is a
reference integration and is not production-ready.

## Try the local example

From the repository root, select an existing Node.js 22+ executable. Python
uses only the standard library, and this optional adapter uses
Node's built-in crypto. No npm install or TypeScript build is needed for this
adapter.

```bash
runtime_node="$(command -v node)"
runtime_node_sha="$(python3 -c 'import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$runtime_node")"
python3 reference/runtime-jwt/run_example.py \
  --node "$runtime_node" \
  --node-sha256 "$runtime_node_sha" \
  --output /tmp/vate-runtime-jwt-example
```

The output directory must not already exist. The example generates an
ephemeral P-256 signing key, creates a JWT, and runs the normal admission
entry. The private key stays in the fixture process and is discarded. The
output contains the token, public trust snapshot, request, receipt,
verification record and a digest manifest in `RUN.json`.

Expected observations are an `attenuate` receipt, a non-executable new-permit
candidate, and rejection for a different request, an invalid signature,
expired evidence and a revoked issuer grant. The evaluation clock is fixed
at `2026-11-12T00:00:01Z` for this local example. No purchase is dispatched.

## Connect an issuer

Configure `RuntimeJwtVerifier` from `runtime_jwt.py` with the explicit profile,
the selected Node executable and its expected digest, token and trust-policy
freshness limits, and an application-owned policy provider. The provider
returns `RuntimeTrustPolicy` snapshots containing `RuntimeIssuerGrant`
entries. Use its authenticated source of key and revocation information;
the local fixture issuer is only for tests and examples.
The [example's admission wiring](run_example.py) shows the constructor and
per-call inputs.

Pass `adapter.as_runtime_verifier()` as the core constructor's
`runtime_evidence_verifier`. On each `admit` call, supply the raw JWT bytes in
`evidence_artifacts` under the URI in the `runtime_attestation` reference.
That reference uses `application/jwt`, the raw token's SHA-256, and no protocol
hint. The request also retains its required `local_policy` reference.

The [contract](CONTRACT.md#operator-trust) specifies the exact configuration
and payload fields. Trust is checked on every call. For `allow` and `attenuate`,
including new-permit candidates, receipt expiry is limited by the applicable
evidence, grant and trust-snapshot deadlines.
Read the final decision from `result.receipt`; `result.core_result` is
intermediate. New-permit candidates require their additional permit before
execution.

This adapter authenticates the issuer's statement about a runtime. The
application still needs to authenticate its caller, establish principal and
actor authority, and select an execution boundary. Receiving
the saved receipt does not replace a receiver's own authentication: the
binding assessor retains `evidence.authentication = not_checked`.

## Recheck before dispatch

The optional [`VateVerifier.dispatch` entry](../request-binding/DISPATCH.md)
reauthenticates the saved token against current application trust before
calling a configured synchronous operation. Configure `DispatchBoundary`
before admission and apply trust updates through `boundary.update()`.
Its callback receives the exact admitted effective bytes and a separate
pre-dispatch check record. A completed local revocation update prevents the
following dispatch; an update waiting on an active callback takes effect when
that callback leaves.

Run a local recording callback with the same selected Node executable:

```bash
python3 reference/runtime-jwt/run_dispatch_example.py \
  --node "$runtime_node" \
  --node-sha256 "$runtime_node_sha" \
  --output /tmp/vate-runtime-jwt-dispatch
```

The [example wiring](run_dispatch_example.py) admits signed evidence, records
one callback, and rejects repeat invocation, post-admission revocation and
expiry. `RUN.json` records callback counts and raw artifact digests, including
`pre-dispatch.json`. No purchase or network submission occurs. This guard is
process-local: applications still need authenticated revocation delivery,
durable replay control and provider-side handling of deadlines and uncertain
outcomes. The optional Python [durable state store](../request-binding/DURABLE-STATE.md)
provides request replay and operation-attempt control across restarts and
cooperating processes on the same host. Restored admissions authenticate the
saved JWT against current trust before dispatch. The check record is not
evidence of an external effect.

## Run the checks

```bash
python3 -B -m unittest discover -s reference/runtime-jwt -p 'test_*.py' -v
```

The suite exercises real local ES256 signatures through admission, the
published RFC 7515 Appendix A.3 signature vector, expiry boundaries, issuer
grants, trust refresh, malformed inputs, backend failures and dispatch-time
revalidation. Its results
apply to this integration profile and selected backend.
