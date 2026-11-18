# HTTP Verifier Demo

This directory demonstrates verifier admission for AL2-style external digital
write requests. `POST /execute` evaluates the request and writes local decision
artifacts; execution of the requested external operation is outside this demo.

It is intentionally focused:

- it exposes a single `POST /execute` API
- it reads a compact JWS from each of the four `app_context` entries (`passport`, `runtime_proof`, `mission_permit`, and `status`)
- it evaluates the trust envelope artifacts in verifier order: status -> identity -> runtime -> permit -> policy
- it returns one of three decisions: `allow`, `attenuate`, or `deny`
- it emits a verifier-signed admission receipt when authorized, usable input
  artifacts supply the receipt's identity and references

This demo uses the earlier AER profile. `verification_report.request_binding`
marks v0.3 purchase-cap preimage binding `not_checked` and the binding
requirement unmet. For that contract, use the
[current core admission API](../vate-verifier-core/README.md) and its bound
original/effective request artifacts.

## Start Here

If you want the fastest path:

1. run `generate-demo`
2. run `serve` against `allow-active`
3. run `execute-demo`
4. inspect `verification_report` and the emitted admission receipt

With the example policy, run `execute-demo` within five minutes of
`generate-demo`. After that, even `allow-active` returns `deny` because its
status and runtime evidence are too old. Stop the server, rerun
`generate-demo`, restart `serve`, and run `execute-demo` again.

## Why This Demo Exists

The repository already contains `reference/minimal-al2-demo/`, which focuses on packaging, status delivery, and negative checks for this draft.

The HTTP demo shows:

- how an external service can request the trust envelope artifacts
- where local policy fits into evaluation
- how attenuation becomes an operational decision rather than only a status label
- how a relying party can emit a verifier-signed admission-phase `AER`

## Scenarios

`generate-demo` produces four scenario directories:

- `allow-active`
- `attenuate-tool-narrow`
- `deny-revoked`
- `deny-unknown-effect`

Each scenario directory contains the inputs for an admission decision:

- trust envelope payloads and compact JWS packages
- `request.json`
- `trust-bundle.json`
- verifier keys

Running `execute-demo` supplies the admission result. Execution of the
requested operation would require a separate runtime and its own receipt.

## Commands

Generate the demo bundle:

```bash
python3 reference/http-verifier-demo/http_verifier_demo.py generate-demo --out /tmp/app-http-demo
```

By default, generation uses
[`policies/al2-http-verifier.example.json`](../../policies/al2-http-verifier.example.json).
To use an existing policy, replace the policy path in this command:

```bash
python3 reference/http-verifier-demo/http_verifier_demo.py generate-demo --out /tmp/app-http-demo --policy /path/to/policy.json
```

Generation validates the selected file against the [local policy contract](../../schemas/verifier-policy.schema.json)
before replacing an existing demo. It saves those same bytes in
`/tmp/app-http-demo/policy.json` and sets the runtime proof and mission permit
audiences to the policy's `verifier_id`. Edit the copy and restart the server to change a
threshold. If you edit the copy's verifier identity, stop the server and
regenerate with `--policy /tmp/app-http-demo/policy.json` to retain the edit.

Use a dedicated output directory. Generation prepares the new keys and all
four scenarios before replacing a complete demo. Replacement clears previous
HTTP responses and admission receipts. It also retires the identical
synthetic execution receipts that earlier generators copied into
the base and every scenario. If you have added or changed an execution receipt,
generate into a new directory to keep that evidence. An incomplete demo,
an unexpected file, or a symbolic link makes generation stop with the directory
intact. A new directory may contain the `policy.json` explicitly selected
with `--policy`. Both demos use the same
[recovery steps for an interrupted update](../minimal-al2-demo/README.md#commands).

`serve` reads that copy unless you select a file with `--policy`. A missing
or invalid file makes startup exit before listening and clears the selected
scenario's previous response and receipt files. The error names the policy
path. Use UTF-8 JSON with unique member names in policies, requests, and signed
artifacts. The demo rejects non-finite numbers and numeric literals it cannot
read without losing decimal precision.

Run the verifier for one scenario:

```bash
python3 reference/http-verifier-demo/http_verifier_demo.py serve --dir /tmp/app-http-demo/scenarios/allow-active
```

Leave the server running. In a second terminal at the repository root, execute the scenario request:

```bash
python3 reference/http-verifier-demo/http_verifier_demo.py execute-demo --dir /tmp/app-http-demo/scenarios/allow-active --base-url http://127.0.0.1:8050
```

Replay the conformance corpus:

```bash
python3 reference/http-verifier-demo/http_verifier_demo.py run-corpus --corpus-root conformance/al2-http
```

## Output

Each reported decision writes `http-verifier-response.json`. When
`verification_report.receipt_emitted` is true, it also writes:

- `verifier-admission-receipt.json`
- `verifier-admission-receipt.jws`

The response includes:

- normalized `verification_report`
- detailed named checks
- signed admission receipt, when emitted

For a request with non-empty `transaction_id`, `requested_action`,
`requested_resource`, and `requested_tool`, failed artifact signatures,
unauthorized signer roles, or unusable artifact payloads return HTTP 200 with
`decision: deny`, named failed checks, and
`verification_report.receipt_emitted: false`. The response then omits
`admission_receipt` and `admission_receipt_jws`; unauthenticated or unauthorized
fields are not used to construct a receipt. Policy denials over usable,
authorized artifacts can still include a denial receipt.

The server and `execute-demo` clear their previous response and receipt files
before processing a new attempt. A reported rejection replaces the response
file. If it emits a denial receipt, that receipt replaces the earlier one;
otherwise no receipt remains. Malformed JSON or missing request
identifiers produce HTTP 400 without a new verification report. An unregistered
key ID produces a denial. The verifier checks each receipt signature against
its registered verifier-role public key before returning the receipt. Each
registered ES256 key used for verification must be an EC public key on P-256.
A different curve, a missing or unreadable key, a mismatched signing key,
or a signing or storage failure returns HTTP 500 without a decision receipt. Restore the verifier
before retrying. The output directory must be
writable. Stop the server before regenerating its demo, and run requests
sequentially when they share output paths.

## Signer Authority and Attenuation

The verifier requires both a valid signature and the expected signer role in
its local `trust-bundle.json`. The key's `owner` must be `issuer` for a passport,
`attestor` for a runtime proof, `broker` for a mission permit, and `status` for
status. A known key with another role cannot authorize that artifact. These
checks run before the artifact supplies identities or policy input.

The permit's `cnf-kid` binding and runtime proof must identify the same
runtime-owned ES256 key. When they include a public-key fingerprint, both
must match the registered public key. The passport and the policy each use
one of the five assurance levels `AL0` through `AL4`.

The mission permit must have a non-empty string `transaction_id` and a
non-empty `actions` array containing only non-empty strings. The transaction
must equal the request's `transaction_id`, and `requested_action` must exactly
match one of the action names. Malformed permit scope produces
`verification_input` without a receipt. A valid but different transaction
produces `permit_transaction_binding`; an action outside the list produces
`permit_action_scope`. These policy denials can include a signed denial receipt.
An optional `principal` appears in the signed receipt only when the permit
supplies a non-empty string.

The policy's `freshness` object must explicitly set `status_max_age_seconds`,
`runtime_max_age_seconds`, and `permit_max_age_seconds` to positive integer
seconds. Existing policies that omit `permit_max_age_seconds` must add it;
choose an age limit for the intended use. The example's 600 seconds is a local
policy value. The passport must be valid at verification time. Status, runtime
proof, and mission permit must also meet their respective maximum ages.
Timestamps require a UTC offset and must be exactly representable in
microseconds. Equality at the age limit is accepted. A permit outside either
limit fails `permit_window`. All four windows use the same decision time.
An admission receipt records the start of evaluation in `started_at` and
the decision time in `finished_at`. The report records that same decision
time in `checked_at`.
The same scope and freshness checks apply to attenuation.

The HTTP verifier denies a request when signed status marks its passport,
runtime, or permit as `suspended`, `revoked`, or `quarantined`. A local policy
that includes any of these states in `accepted_states` is invalid.

Python callers passing a policy to `verify_execute_request` must supply the
same fields as a policy file. Action, resource, and accepted-state lists
contain exact names. An empty list accepts no member. For a well-formed
request, an invalid policy with a usable `policy_id` and `policy_version`
returns `deny` with `verification_input` and no receipt. If either identifier
is missing or unusable, the call raises `ValueError` because it cannot
attribute a report.

Attenuation retains the original permit's obligations:

- `tool_allowlist` is a list of non-empty tool names. Narrowing takes the
  intersection; an empty result permits no tool.
- `approval` starts from the permit's top-level requirement. An additional
  `constraints.approval` or status effect may keep its mode or strengthen
  `policy_auto` to `human_required`. Removing a human-approval requirement,
  selecting an unknown mode, or replacing an existing approval field such as
  `policy_ref` is rejected. Omitted approval fields are retained.
- `human_required` needs a non-empty, non-whitespace `approval_ref` string in
  the request. This demo checks its presence; it does not authenticate a human
  approval record.
- Supported numeric limits use the smaller value, and an exact resource scope
  must stay unchanged. The policy's handler selection must match these field
  semantics. Unknown fields or malformed effect values are rejected.

An `attenuate` report records the effective amount and redelegation limits.
The verifier checks the submitted resource, tool, and approval reference.
It does not compare values in `request_payload` with the two numeric limits.

Every `attenuated` status entry requires an `effect` with `mode: narrow`, a
`constraints` object, and a boolean `require_new_permit`. For a permit,
an explicit `{}` keeps its original constraints. A reissue request from any
of the three entries requires a new permit, even on an otherwise active
entry. Nonempty narrowing constraints require the `attenuated` state.
This demo applies narrowing
only to permits. It denies a narrowed passport or runtime even when the
local policy lists that state as acceptable.

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
