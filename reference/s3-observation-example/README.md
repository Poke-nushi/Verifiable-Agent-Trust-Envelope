# S3 Observation Example

Connect a VATE admission and execution receipt to bytes read back from a storage
service. This example records an authorized object upload, captures its returned
version ID, and checks that a later read of that version agrees with the permitted
request and the reported result.

The included captures come from a local SeaweedFS 4.48 instance. You can replay
them offline, inspect the originals, or create a fresh capture on macOS arm64.

```text
Local permit → VATE admission → request/body check → PUT → returned version ID
                                                        ↓
VATE post-execution receipt ← version-specific GET with separate read credentials
                ↓
Offline assessment: receipt linkage + request + attempt + observed result
```

This extends the [Receipt Linkage Example](../receipt-linkage-example/README.md):
matching receipts alone do not connect a report to the bytes observed at its
target. The added checks bind the admitted request, captured PUT, selected object
version and result projection while retaining the existing checker's output.

## Replay the included captures

From the repository root, use Python 3.10 or later on Linux or macOS and the
repository's existing `jsonschema` dependency (`requirements-dev.txt`). No
SeaweedFS binary, service, credentials or network connection is needed for replay.

For other bundles with 1–6 fractional-second digits in their timestamps, use
Python 3.11 or later. On Python 3.10, the fixed S3 evaluator accepts whole seconds
or exactly 3 or 6 fractional digits; other lengths can leave an assessment
`insufficient`. Select a compatible interpreter without rewriting received
receipts or capture artifacts.

```bash
python3 reference/s3-observation-example/run_examples.py
```

The command exits successfully when all four assessments match their expected
results. A successful replay includes the two deliberately insufficient cases:

| Capture | What was observed | Assessment |
| --- | --- | --- |
| `supported` | PUT returned a version; GET of that version returned the permitted bytes | `supported_under_local_assumptions` |
| `actual-403` | A later GET without credentials returned HTTP 403 | `insufficient` |
| `actual-404` | A later GET requested a nonexistent version and returned HTTP 404 | `insufficient` |
| `historical-v1` | After a separate setup overwrite, GET of the original version still returned the original bytes | `supported_under_local_assumptions` |

The last row concerns the named historical version, not the current latest object.
The 403/404 rows do not establish that the original upload failed or that retrying
it is permitted. Every assessment returns `retry_authorized: false`.

For a complete assessment of one bundle:

```bash
python3 reference/s3-observation-example/assess_cli.py \
  --bundle reference/s3-observation-example/inputs/seaweedfs-4.48/instance/bundles/supported \
  --trust reference/s3-observation-example/inputs/seaweedfs-4.48/instance/receiver-policy.json
```

The receiver policy is a separate input, outside each bundle. In this example it
explicitly accepts the local unsigned collector and store and fixes the endpoint,
bucket and source hashes. A bundle cannot establish its own trust merely by
carrying consistent hashes. `receipt_check` preserves the existing checker's
reason codes and `not_checked` list; see [CONTRACT.md](CONTRACT.md) for the added
assessment fields and decision rules.

`assess_cli.py` checks the policy's filesystem location, including case and
Unicode aliases for the same bundle directory, before reading the policy. It
returns the fixed evaluator's complete JSON and exit codes: 0 for supported,
1 for contradictory, 2 for insufficient, and 3 for unsupported. Invalid policy
placement returns `insufficient` with a `receiver_configuration` diagnostic and
exit 2.

Use this entry point for direct assessments. The original
`assess_observation.py` remains byte-for-byte fixed for historical reproductions
and the Recipient Assessment API. Its historical CLI uses a lexical path check
that can miss filesystem aliases. The new entry point is outside the captured
source-pin set; `source_trust` describes the fixed evaluator and capture sources,
not the new CLI's bytes. Location checking does not establish who selected or
issued the policy, or prevent concurrent filesystem replacement.

For calls from another application, the
[Recipient Assessment API](../recipient-assessment/README.md) provides a
versioned Python and JSON CLI entry point. It preserves this complete assessment
and the existing source-pin and receiver-policy requirements.

## Inspect and test

- [Included originals and provenance](inputs/seaweedfs-4.48/README.md): four
  bundles, native control responses, source hashes and capture conditions.
- [Contract](CONTRACT.md): accepted inputs, digest bases, classifications and
  trust assumptions.
- `contract.py`, `capture_s3.py`, `assess_observation.py`: local authorization,
  capture and offline assessment respectively.
- `native_fixture.py`, `sandbox_macos.py`, `run_trial.py`: optional native run.

Run the offline acceptance checks:

```bash
python3 reference/s3-observation-example/test_assessment.py
python3 -m unittest discover -s reference/s3-observation-example -p 'test_native_fixture.py' -v
python3 -m unittest discover -s reference/s3-observation-example -p 'test_assess_cli.py' -v
```

These checks replay stored captures and mutate separate copies to test changed
targets, bodies, versions, attempt references, receipt fields, missing originals,
unknown contracts and malformed bundles. Synthetic cases are identified in the
output; they are not additional SeaweedFS measurements. The first command writes its
copies and `RESULTS.json` to a new temporary directory and prints the location.
The second checks cleanup exception paths using mocks, without starting processes.
The third checks policy placement and preserves the fixed CLI's native results.
Alias tests run only where the filesystem equates the selected spellings;
the distinct-case directory control runs on case-sensitive filesystems.

## Create a fresh local capture

Native capture currently supports **macOS arm64 only**, using `/usr/bin/curl`,
`sandbox-exec`, `lsof` and an already downloaded SeaweedFS binary matching
[SEAWEEDFS-PIN.json](SEAWEEDFS-PIN.json). The pin links the upstream release and
records the archive and binary hashes. The script checks the binary before
starting it; it does not download or install software.

Supply that binary and a new output directory:

```bash
python3 reference/s3-observation-example/run_trial.py \
  --weed /absolute/path/to/weed \
  --output /tmp/vate-s3-observation-run
```

Each run creates a new permit, operation, attempt, temporary bucket and three
sets of credentials. It binds eight temporary ports to loopback and restricts
the storage process and curl with a macOS sandbox. Setup controls include a
conditional duplicate PUT, denied observer writes/deletes, a denied read of
another bucket, and a separate overwrite for the historical-version check.
These setup controls are distinct from the VATE-authorized upload.

On exit the fixture stops the process, removes its credential file and temporary
sockets, checks for credential residues, and records cleanup in
`instance/LIFECYCLE.json`. Incomplete cleanup makes the run fail and preserves
its diagnostics; a still-running process leaves its work directory in place.
It retains the test database and operational files in
the selected output directory for inspection. Review that directory before
sharing it; the included public inputs contain only selected evidence files.
The recorded capture required forced process termination, so it does not test
clean shutdown or restart durability.

To assess your new capture, pass its output directory with `--input` to
`run_examples.py` or with `--run` to `test_assessment.py`.

## Scope and reuse

The evaluated operation is a conditional, single-part `s3.put_object` of at most
4096 bytes, with a simple ASCII key, versioning, and a version-specific read.
The example leaves the public VATE schemas, corpus, reason codes and digest
rules unchanged. Its `vate-local-s3-observation-v1` contract is an implementation
example, not a new normative VATE profile.

The maintainer controls the unsigned permit, collector, clock and storage
instance. Separate read credentials demonstrate a permission boundary in that
fixture; they do not create an independent witness. The result checks consistency
under these explicit local trust assumptions, not signed provenance, durable
storage, complete side-effect coverage or current permission to execute again.

SeaweedFS supplies the storage API; the local adapter creates the VATE receipts.
This is a maintainer-run integration example, not SeaweedFS adoption of VATE or
an external VATE SUT result. Other storage systems and independently operated
collectors have not been evaluated. Their response meanings and trust policies
must be established before reusing this assessment contract.
