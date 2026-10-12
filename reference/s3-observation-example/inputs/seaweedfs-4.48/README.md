# Included local capture

These originals were captured on 2026-10-12 by the VATE maintainer using
SeaweedFS 4.48 (`530be3e37337488ecc34d58441e0bc476e121c93`) on macOS arm64.
The [runtime pin](../../SEAWEEDFS-PIN.json) identifies the upstream binary.
[PROVENANCE.json](PROVENANCE.json) records the run ID, repository base, capture
sources and SHA-256 of every retained evidence file.

The four bundles share one original authorized PUT. They add actual GET
observations: successful version-specific read, unauthenticated 403, nonexistent
version 404, and historical-version read after a separate setup overwrite.
`instance/native-controls/` contains the separate setup and permission probes.
There are 16 distinct HTTP exchanges across these files; copied references to
the original PUT are not counted as new executions.

The local adapter generated the admission and post-execution receipts; SeaweedFS
returned the storage responses. The receiver policy explicitly accepts the local
unsigned collector/store. These are local integration records, not an external
VATE implementation result or independent proof of execution.

Selected evidence was copied byte-for-byte. Database files, credentials, server
logs and the machine-specific launch command were excluded. Loopback ports,
temporary directory names and a stopped process ID remain in the lifecycle
record as capture metadata. The recorded process required SIGKILL after the
shutdown timeout; restart durability was not measured.

Use [the replay command](../../README.md#replay-the-included-captures) to assess
these files. Acceptance-test mutations are produced in a separate output
directory and do not change these originals.
