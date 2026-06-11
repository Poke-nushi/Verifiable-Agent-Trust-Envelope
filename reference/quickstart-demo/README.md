# VATE Quickstart Demo

This is a dependency-free terminal demo for the current VATE v0.3 corpus line.
It narrates three committed corpus cases:

- `allow-valid-admission`
- `attenuate-max-amount`
- `deny-digest-mismatch-before-policy`

Run it from the repository root:

```bash
python3 reference/quickstart-demo/run_demo.py
```

The demo reads values from committed corpus and receipt fixtures at runtime. It
does not define new schema fields, new expected results, or a new verifier
behavior.

Useful options:

```bash
python3 reference/quickstart-demo/run_demo.py --list
python3 reference/quickstart-demo/run_demo.py --case attenuate-max-amount
python3 reference/quickstart-demo/run_demo.py --case attenuate-max-amount --json
```

This is a discussion draft demo. No certification, endorsement, or production
approval is implied. See [docs/public-claim-boundary.md](../../docs/public-claim-boundary.md).
