# Foreign acceptance: HS51 WAR bindings

The opt-in `hs51-war-bindings-v0-1` profile verifies a signed foreign work
acceptance record against a selected MUSUBI request, execution receipt and
criteria commitment. It retains the result alongside the native settlement.
The native `accepted: null` and all earlier assessments remain unchanged.

## Receiver selection

Set `acceptance_binding_profile` to `hs51-war-bindings-v0-1` in the selection.
`acceptance_verification` selects the external verifier SHA-256 and a list of
TSA root references, each with `path` and raw `sha256` in the acquisition
manifest. These roots come from the receiver's selection, not the incoming
record. A required acceptance requirement also names `execution_requirement`
and `criteria_requirement`. Both must be required, refer to the same selected
occurrence, bind to the fixed log, and have a native result attached.

The checker key and criteria hash come from the selected, verified criteria
commitment. The response digest and producer key come from the selected
execution receipt. Record filenames and the supplied key list do not establish
authority. A valid APS record sharing the same audit digest cannot fill a
MUSUBI occurrence; A cannot fill B or C.

## Verifier and execution

Select one exact Work Acceptance Record verifier in
`acceptance_verification.verifier_sha256`:

| WAR profile | Source | Raw SHA-256 |
| --- | --- | --- |
| 1.4.8 | [`3e53aac`](https://github.com/maximusrufus/work-acceptance-record/blob/3e53aac24ee5298b2316a10dceeaddb99695cc8c/verifier/war_verify.py) | `508855993696357745f94e2405dbe9205421e62f42c678db3487e342c9fda359` |
| 1.4.3, retained for reproduction | [`6bb7d0b`](https://github.com/maximusrufus/work-acceptance-record/blob/6bb7d0b9246c3c535aba9c294d26181496d00614/verifier/war_verify.py) | `a8a63a9fcfdcf578bfb256c222af22f189263aaec79af182b384008a68cec5dc` |
| 1.4.1, retained for reproduction | [`6b2f730`](https://github.com/maximusrufus/work-acceptance-record/blob/6b2f730b81e0818826f274742d883c2b475d5227/verifier/war_verify.py) | `ac3ac35d9356cbb5f3371c19a2113ad03c1fd486c247a2ed586bdfdbdd32ae49` |

Supply the selected source with `receiving.py --acceptance-verifier`. Both the
receiver and worker check its bytes against that selection before execution.
Results from another verifier pin cannot fill the selected requirement.
The sample does not download, install or bundle the verifier. The example
selects the pin matching the explicitly supplied supported source.

The adapter copies the pinned verifier and its own wrapper into the existing
macOS sandbox. It uses the prepared Python runtime, denies networking and
Keychain access, caps the worker CPU at 30 seconds and waits at most 90 seconds.
Source bytes, roots, input, stdout, stderr, execution metadata and verification
findings are retained with the assessment. Timeout, failed sandbox or malformed
worker output leaves the record unassessed and reports an evaluator error.
Portable checks exercise parsing, cryptography, binding and storage; full
native replay requires macOS.

## Receiver-derived key inputs

For 1.4.3 and 1.4.8, the adapter builds a two-key input from the selected checker and
producer bindings. The checker key comes from the verified criteria commitment;
the producer key comes from the verified execution receipt. The received
checker key must match the selected checker. An omitted producer key is supplied
from that execution receipt; a supplied contradictory producer key or duplicate
key ID is rejected. The two selected party keys must be distinct.

For 1.4.8, the adapter also supplies `relying_party_keys` from these verified
native bindings to both WAR's independence derivation and receipt verification.
It ignores any `relying_party_keys` field in the incoming acceptance file.
The supplied list is saved as `provenance.war_relying_party_key_input`, with
`war_relying_party_key_input_basis: receiver_selected_MUSUBI_bindings`.

The original acceptance file remains unchanged. The derived key input is saved
as `provenance.war_key_input`, alongside `selected_bindings` and the verifier
source identity. `declared.independence` retains the signed claim;
`derived_independence` records the selected WAR rule's result. These are key/name
checks, not an assessment of organizational independence.

Selections of 1.4.3 retain their original two-key path without the additional
relying-party input; 1.4.1 retains its incoming-key path. To change verifier
versions, use a new selection and a new assessment. Retain the earlier assessment
with its original pin. The [1.4.8 validation](WAR148-VALIDATION.md),
[1.4.3 validation](WAR143-VALIDATION.md) and [1.4.1 validation](ACCEPTANCE-VALIDATION.md)
describe their separate runs.

## Checked content

The supported receipt schema is `trilatic.acceptance-receipt/1.2`, using
JCS-RFC8785, SHA-256 and Ed25519. Its bindings sidecar must use
`invinoveritas.work-acceptance-bindings/v0`. The adapter checks the receipt and
sidecar signatures against the selected checker, the sidecar's receipt digest,
and the selected occurrence, request, execution, criteria, audit and producer
bindings. Sidecar signing excludes `signature` and the optional `producer`
member. That unsigned member supplies no authority.

With 1.4.8 selected, both signature checks require the signature's encoded
Ed25519 `R` point to be canonical and prime-order under that WAR profile.
Historical selections continue to use their pinned verifier's signature rules.

The criteria bytes must match their selected digest and the signed result rows.
The adapter checks supplied RFC 3161 tokens for imprint, signature and chain
against the selected roots, including additional supplied criteria tokens.
Commitment timing must precede checking under the token accuracy rules.
Text descriptions of an additional TSA are retained as claims, not counted as
verified tokens. The work verdict is recomputed from the signed result rows.
Token accuracy diagnostics use `accuracy_ms_decimal`, a decimal string or
`null`, so sub-millisecond precision survives storage and recovery. Timing
comparisons use the verifier's numeric accuracy value. Non-finite or negative
accuracy is rejected.

Input is bounded to 256 KiB per record, depth 24 and 4,096 JSON nodes. Duplicate
keys, non-finite values, floating-point numbers, unsafe integers and invalid
Unicode are rejected in both the acceptance JSON and the decoded criteria JSON.
This profile accepts Unicode strings with JCS processing;
it does not change the base MUSUBI object's ASCII digest subset.

## Results and limits

| Verification result | `binding_status` | `semantic_assessment` | Work verdict |
| --- | --- | --- | --- |
| `verified` | `bound` | `foreign_acceptance_verified` | Signed `pass`, `fail` or `incomplete`, recomputed from result rows. |
| `rejected` | `contradictory` | `unassessed` | Unassessed. A signature, binding, content or proof check failed. |
| `unsupported` | `unsupported` | `unassessed` | Unassessed. The record uses another profile/version/suite or an unsupported TSA algorithm. |
| `unavailable` or evaluator failure | `unresolved` | `unassessed` | Unassessed. Required verification conditions could not be established. |

A signed work failure is a verified record, not an evaluator failure. Missing,
ambiguous and unselected candidates retain those states. Required evidence can
remain `partial` after acceptance records verify. In the fixed three-stage
example, B's audit/dataset links and the six rail/raw-response requirements
have no selected originals. The [B follow-up](ACCEPTANCE-VALIDATION.md#b-audit-follow-up)
establishes the two B links in a later assessment; the six other requirements
remain unbound. Their [binding rules are unsupported](CONTRACT.md#rail-and-raw-response-requirements),
so their completion cannot be inferred from the arrival of files.

Acceptance verification binds the signed audit digest; it does not require
the audit bytes to be present or verify their contents. An audit/dataset link,
a verified foreign work verdict and native `accepted: null` answer different
questions and remain separate in the saved result.
An unsupported TSA algorithm does not mask a separate invalid signature,
untrusted chain or imprint mismatch; those failures result in `rejected`.
An internal evaluator failure is retained as `recorded_evaluator_error` and
returns CLI exit code 64, including when its saved output is recovered.

These checks verify the published acceptance record and its aggregation. They
do not re-evaluate the audit contents, assert organizational independence, check
current certificate revocation or OpenTimestamps, or insert an acceptance entry
into the MUSUBI log. This is a fixed-source interoperability sample; it does not
establish production readiness or general PKI compatibility.
