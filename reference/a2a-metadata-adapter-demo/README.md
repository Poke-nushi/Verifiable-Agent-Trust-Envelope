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

For the A2A v1.0-shaped extension sketch, see
`docs/a2a-v1-extension-sketch-2026-05.md`.

## Run

```bash
python3 reference/a2a-metadata-adapter-demo/a2a_metadata_adapter_demo.py run-demo
```

The command prints an A2A-shaped response JSON to stdout.
