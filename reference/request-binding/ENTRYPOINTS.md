# Request-preimage coverage by entry point

The current admission API requires the purchase-cap preimages. Other operation
profiles and receipt readers have the boundaries below. A successful linkage,
signature or corpus check alone is not a request-preimage assessment.

| Entry point | Preimage behavior | Result boundary |
| --- | --- | --- |
| [`VateVerifier.admit`](../vate-verifier-core/README.md) | Requires original admission and purchase-operation bytes; validates hashes, context, exact cap transformation and resulting payload constraints. Requires one `local_policy` reference matching the verifier-selected policy before policy/replay evaluation. Missing or unsupported inputs raise before an admission is returned. | Returns bound receipt and assessment bytes. The local-policy check establishes content identity; `core_result` is an intermediate policy result. |
| [A2A metadata adapter](../a2a-metadata-adapter-demo/README.md) | Uses the default API; requires the demo-local original reference and checks the metadata transaction against the admission request. | Missing or mismatched preimages produce a rejected task. Post metadata remains synthetic. |
| [File-set admission](../execution-evidence-demo/admission.py) | Validates the operation and local permit's operation ID/input hash, reconstructs the allowed file subset, and recomputes authorization before dispatch. | Uses its own `vate-demo-file-set-v1` contract, not the purchase-cap transformation. |
| [S3 admission and assessment](../s3-observation-example/contract.py) | Validates the S3 effective operation and local permit hash before policy evaluation; the assessor reconstructs admission and checks the supplied request/observation records. | Uses `vate-local-s3-observation-v1`; local records do not prove independent execution or current permission. |
| Python `assess_request_binding` / [TypeScript `assessRequestBinding`](../../packages/vate-core-ts/README.md#check-request-binding) | Require the receipt, raw preimages, supported contract and independently selected admission reference. Check the exact correspondence of receipt and request evidence references. Missing declarations or inputs leave the binding requirement unmet. | Check content relationships; retain evidence authentication and dispatch observation as `not_checked`. |
| [TypeScript A2A metadata helpers](../../packages/vate-a2a-ts/README.md) | Validate metadata shape and extension activation; do not dereference receipt or request preimages. | Metadata success does not establish request binding. Use the receiver checker on the referenced bytes. |
| [Ordinary `run`, `compare`, `verify-bundle`](README.md#use-the-ordinary-runner) | Enforce each case's required binding and recompute it when verifying a bundle. New reports state case requirements and binding coverage. | The legacy 76-case corpus has zero required preimage checks. The separate purchase-cap corpus requires them in all four cases. |
| [Receipt-pair reader](../receipt-linkage-example/recipient_example.py) and [recipient API](../recipient-assessment/vate_recipient.py) | Receipt-pair assessment lists `request_hash_preimages` in `not_checked`; its `record_linkage` result only describes receipt relationships. The S3 evaluator retains its separate preimage checks. | No aggregate execution permission is returned. Use the binding assessor for purchase-cap preimages. |
| [Signature assessment](../recipient-signature-authority/recipient_trial.py), [JCS signature assessment](../recipient-jcs-signature-authority/jcs_recipient_trial.py), [required records](../required-records/required_records.py), and receipt intake | Compose the selected native reader and retain its result. Signatures, record availability and intake status do not add request-preimage coverage. | Inspect the selected native assessment and `not_checked` fields. |
| [Minimal AL2](../minimal-al2-demo/trust_envelope_demo.py) and [HTTP verifier](../http-verifier-demo/http_verifier_demo.py) | Earlier AER demo profiles; reports explicitly mark this request-binding contract `not_checked` with an unmet binding requirement. | Their own demo checks and old receipt hash meanings remain distinct from v0.3 purchase-cap binding. |
| [Frozen runtime](../historical-runtime/e845a6a8/MANIFEST.json), runtime-handoff and post-admission-revocation packages, and imported upstream samples | Retain their pinned code, data and original profile meanings. Historical replay is explicitly selected. | Replaying a saved result does not add the new binding checks. |

`_evaluate_policy` is a private primitive used by the purchase-cap, file-set and
S3 implementations and policy unit tests. It does not check request preimages
and must not be used as an admission endpoint.

Live receipt-reader source manifests identify the installed code. Archived
manifests, captures and corpus cases retain their original source identities
when the live reader changes.

This coverage concerns request content and transformations. Production issuer
trust, general evidence/context verification, arbitrary operation profiles,
freshness at dispatch and new-permit lineage require their own contracts and
implementation checks.
