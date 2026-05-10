# A2A Metadata Adapter Demo

This demo shows how VATE can sit adjacent to A2A without requiring A2A core changes.

It does not use the official A2A SDK.
The purpose is to show a dependency-free A2A-shaped adapter:

- Agent Card declares the VATE extension URI
- task metadata carries a digest-bound admission request reference
- the adapter resolves the referenced artifact
- the VATE verifier core returns `allow`, `attenuate`, or `deny`
- the task response carries an admission receipt reference, not the full receipt body
- the demo also emits a follow-up `post_execution_receipt_issued` metadata example for the admitted request
- digest mismatch is mapped to a rejected task response with `DIGEST_MISMATCH` and `FAIL_CLOSED`
- malformed VATE metadata is checked before local fixture dereference and mapped to `SCHEMA_INVALID` with `FAIL_CLOSED`
- missing extension metadata or a non-object task message is mapped to a rejected task response with `SCHEMA_INVALID` and `FAIL_CLOSED`
- for those malformed A2A input paths, the task response records the rejected input as a digest-bound demo-local `demo_local_failure_source`, while the generated admission receipt does not classify it as admission-request evidence

For the A2A v1.0-shaped extension sketch, see
`docs/a2a-v1-extension-sketch-2026-05.md`.

`demo_local_failure_source` is a non-normative demo response-envelope field
used to make local fail-closed behavior reviewable. It is not part of the v0.3
admission receipt schema contract and external implementations should not treat
it as a portable receipt extension without defining their own extension
contract.

## Run

```bash
python3 reference/a2a-metadata-adapter-demo/a2a_metadata_adapter_demo.py run-demo
```

The command prints an A2A-shaped response JSON to stdout.
