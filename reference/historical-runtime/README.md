# Fixed Historical Replay

Replay the saved S3 captures and original recipient vectors with the source
identity they recorded. The `e845a6a8/` snapshot contains 107 unchanged files:
the required runtime, receipt expectations and fixed vector inputs from
commit `e845a6a8c118135e8e6a3e8de5a692f8536670c4`.
`e845a6a8/MANIFEST.json` records their raw SHA-256 hashes.
The replay helper checks the fixed manifest and every listed file before use.

From the repository root:

```bash
.venv/bin/python -B reference/s3-observation-example/run_examples.py \
  --runtime historical-e845a6a8
.venv/bin/python -B reference/recipient-assessment/run_vectors.py
```

The first command replays four saved observations. The second checks the
13 original vectors, including their complete native-result expectations.
The signature tests also reproduce the original `BASELINE.json` with this
snapshot. The archived files and results keep their original identities.
The NENRIN crosswalk reads its 36 pinned files from the same snapshot and
verifies them against its unchanged `b3b6d4f9` source hashes.

For new assessments, use the current receipt, recipient API or inbox entry
point. The archived runtime retains the old diagnostic-amplification behavior;
it exists for fixed-record reproduction. Runtime selection is explicit, with
no fallback to older code based on submitted input.

A saved S3 capture, its receiver policy and the installed evaluator must agree
on their source hashes. Passing an old capture and old policy to the current
evaluator therefore does not establish source trust. Retain the old record
for historical replay; do not rewrite its source declaration to represent a
new capture.

Current S3 regression tests generate separate offline derivatives. Their
provenance lists original hashes and changed source/manifest/policy fields.
Those derivatives exercise current code, not a new storage operation.
The [receipt checker](../receipt-linkage-example/README.md#diagnostic-limits)
describes current diagnostic limits.
