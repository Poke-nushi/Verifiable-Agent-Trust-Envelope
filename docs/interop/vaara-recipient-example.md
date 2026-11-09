# Receive Vaara evidence and retain reassessment history

Select a saved MCP call, check its Vaara attestation and execution receipt, and
retain the earlier and later assessments in VATE's Recipient Inbox. This fixed
example keeps native verification, tool-name/argument binding and call
association separate, with the original evidence available for inspection.

The saved evidence comes from an unmodified local Vaara **2.17.0** stdio proxy.
Two calls with identical arguments received responses; a third server invocation
ended before responding. Replay reads those artifacts without issuing MCP calls
or retrying the recorded operation.

## Download and verify

[Download the recipient example](https://vate.rognalia.com/downloads/vaara-recipient/2026-11-09/vaara-recipient-example-20261109-r2.zip)
(201,288 bytes). [Package identity](vaara-recipient-example.package.json) records
the archive hash, manifest hash, source pins and tested environment. The ZIP
contains 58 files; `PACKAGE-MANIFEST.json` lists the 57 payload files.

Download into a new directory and check the bytes before extraction:

```sh
curl --fail --location --remote-name https://vate.rognalia.com/downloads/vaara-recipient/2026-11-09/vaara-recipient-example-20261109-r2.zip &&
python3 -I -S -c 'import hashlib,pathlib,sys; p=pathlib.Path("vaara-recipient-example-20261109-r2.zip"); sys.exit(0 if hashlib.sha256(p.read_bytes()).hexdigest()=="9fa7d3d39dd7e331cec5938afab6c0ea97c3305447802a10dd6b3d128e965aed" else "ZIP digest mismatch")' &&
unzip vaara-recipient-example-20261109-r2.zip &&
cd vaara-recipient-example
```

The package includes the receiving scripts, unchanged captured evidence, an
example public key and selection, and the required VATE source files. The native
Vaara runtime and Python environments are installed separately. Read `README.md`
and `NOTICES.md` in the extracted package for the complete procedure and license
information. The package is Apache-2.0; separately installed dependencies retain
their own licenses.

## Run with the tested environment

Use **macOS arm64, Python 3.14 and `/usr/bin/sandbox-exec`**. The tested receiver
uses Python 3.14.8 and `jsonschema==4.26.0`. A separate native environment must
contain the six exact wheel versions and hashes in `requirements.lock`; an
existing matching environment can be reused. Other platform/payload sets remain
unverified. No separate VATE source checkout is required.

Set the paths to the receiving interpreter and native runtime, then configure
and replay from the extracted package directory:

```sh
VATE_RECEIVER_PYTHON=/absolute/path/to/receiving-environment/bin/python
VAARA_RUNTIME_DIR=/absolute/path/to/native-runtime
"$VATE_RECEIVER_PYTHON" -B recipient.py configure --native-runtime "$VAARA_RUNTIME_DIR" --output runtime.local.json
"$VATE_RECEIVER_PYTHON" -B recipient.py replay --capture evidence --selection example-trust/selection.json --runtime-config runtime.local.json --output replay-01
```

The commands refuse existing destinations. `runtime.local.json` contains local
installation paths and should remain local. The package README includes the
hash-pinned wheel installation and test commands.

| Delivery case | Call association | Native signature/back-link check | Tool name and arguments |
| --- | --- | --- | --- |
| Receipt withheld | `receipt_missing` | `not_run` | `matched` |
| Another call's complete pair | `different_attestation` | `matched` | `matched` |
| Selected call's receipt delivered | `matched_selected_capture` | `matched` | `matched` |

`SUMMARY.json` records these results and Inbox revisions 1 and 2. `before/`,
`swapped_pair/` and `after/` retain inputs and native outputs. `export/` preserves
both assessments and their evidence. A nonzero exit means an expected result
was not reached; available inspection records and diagnostics are retained.

## Read the result

Two complete pairs can have valid native signatures and the same argument
commitment while belonging to different calls. Here, call association comes
from a receiver-selected collector manifest and request/key hashes. The
receiver trusts that collector's origin; the manifest hash fixes its bytes.
This does not establish a native signature binding to the JSON-RPC ID or
independently authenticate the collector.

The captured request 103 has a signed `unobserved` receipt after its server
ended before responding. All three receipts omit a result commitment. Valid
signatures therefore do not settle that execution outcome or verify result
content. Later result recovery, concurrent-call association and permission to
execute or retry are outside this example.

Inbox's generic review uses an empty requirement set to retain history;
`completed` is not Vaara validation. Receipt delivery is staged locally, with
arrival times unspecified. This is an experimental review aid, not production
approval or general compatibility evidence.

Native checks call Vaara's receipt handler and argument-commitment API directly,
skipping the general CLI startup that initializes global hooks. Subprocesses
have bounded execution/logs, temporary-directory-only writes and denied network
access. The sandbox does not hide home-directory contents. See the package
README for installed-payload checks and receiving-process file access.

## Sources and related example

`VATE-SOURCES.json` pins the included VATE files to
[`1c04c5545ee6891a34f4fffdf7772af544ba811f`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/1c04c5545ee6891a34f4fffdf7772af544ba811f).
The installed Vaara 2.17.0 payload was compared with
[`90311e7214c8a20a86af7a58e400ead661355984`](https://github.com/vaaraio/vaara/tree/90311e7214c8a20a86af7a58e400ead661355984).
`NATIVE-PACKAGES.json` and `requirements.lock` identify the separate native
payload. No private key or installed native runtime is bundled.

For the earlier local execution experiment through a credential gateway and
file handler, use the separate
[Vaara → VATE reproduction package](vaara-execution-reproduction.md).
Its historical source pins, evidence and download remain unchanged.
