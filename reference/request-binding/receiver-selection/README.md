# Which purchase does this receipt pair describe?

A and B are separate requests for the same USD 24.50 order. A receiver with
a saved request can check both whether the admission receipt belongs to that
request and whether the result belongs to that admission. The records are
unsigned, synthetic fixtures. No purchase was sent.

| Receiver's saved request | Admission and purchase inputs | Result receipt | Link between receipts | Binding to saved request |
| --- | --- | --- | --- | --- |
| A | A | A | Matched | Matches |
| A | B | B | Matched | Mismatch |
| B | B | B | Matched | Matches |
| No saved request | B | B | Matched | Unchecked |
| A with earlier expiry | A | A | Matched | Mismatch |
| A | A | B | Mismatch | Matches |

The first four cases retain the v1 inputs and per-case decisions. The last two
are additional controls in `vate-purchase-receiver-selection-v2`. In the
fifth case the saved request expires one second earlier. Its request and
transaction IDs are the same as A's. The changed expiry gives the saved bytes
a different digest. In the sixth case
the admission matches the saved request A. B's result belongs to a different
admission.

## Replay the six cases

If you are using the ZIP, keep it beside its companion `.zip.sha256` file
and the extracted directory. The first command checks the archive. The second
checks the extracted reference code, schemas, documentation and inputs listed
in `PACKAGE-SHA256SUMS`. On macOS, run

```bash
shasum -a 256 -c vate-purchase-receiver-selection-v2.zip.sha256 &&
  (cd vate-purchase-receiver-selection-v2 && shasum -a 256 -c PACKAGE-SHA256SUMS)
```

On Linux with GNU coreutils, run

```bash
sha256sum --check vate-purchase-receiver-selection-v2.zip.sha256 &&
  (cd vate-purchase-receiver-selection-v2 && sha256sum --check PACKAGE-SHA256SUMS)
```

The reference reader uses Python 3.10 or later on macOS or Linux and
`jsonschema==4.26.0`. If you need a new environment, run these commands from
the root of the VATE checkout or the extracted ZIP. This setup needs access
to the packages, and replay itself runs offline.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
```

From a VATE checkout, run the reader with the environment that has this
dependency installed.

```bash
.venv/bin/python -I -B reference/request-binding/receiver-selection/check.py
```

The standalone ZIP has `check.py` and its reference sources in the extracted
package directory. Run this from that directory to save the observed decisions
in a file you can compare or share.

```bash
.venv/bin/python -I -B check.py > my-results.json
```

The command writes the six observed case results as JSON to stdout. Exit 0
means every case produced its expected pair and binding decisions.

## Run your own receiver

1. Read the case IDs and input selections in [vectors.json](vectors.json).
   For each case, read `receiver/<receiver_request>.json` as the receiver's
   previously saved admission request. A JSON `null` selection means no
   receiver reference is available. Read the admission receipt and the three
   purchase inputs from `deliveries/<delivery>/`. Use `post-execution.json`
   from that same directory unless the case specifies `post_delivery`. In
   that case take only the result receipt from `deliveries/<post_delivery>/`.
2. Check the selected admission and result receipts as a pair. For request
   binding, use the admission receipt and its three raw files
   `admission-request.json`, `original.json` and `effective.json`.
   Key each of those files by `urn:sha256:<lowercase SHA-256 of its exact bytes>`.
   Derive the expected admission reference from the receiver's saved bytes,
   or leave it absent. Preserve exact bytes when resolving all references.
   [Purchase request-binding rules](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/83443e52ddfb18aa3f17ea6539d8bc31ae8a5dff/reference/request-binding/CONTRACT.md) · [Receipt-pair assessment](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/83443e52ddfb18aa3f17ea6539d8bc31ae8a5dff/reference/recipient-assessment/CONTRACT.md)
3. Write a JSON object with the `vector_set` from the case file and a `cases`
   object keyed by case ID. Return `record_linkage` from the pair assessment.
   Under `request_binding` return `status`, `pass`, `binding_requirement_met`
   and `selection_cause`. The last field is the cause on the
   `receiver.admission_request` check, or JSON `null` when it matched.
   [expected.json](expected.json) gives the complete result shape and values.
4. Save your reader's output as `my-results.json`. From the directory
   containing `check.py`, use the command below to compare it. The same
   command also accepts the reference output saved above. Comparison uses
   the Python standard library and works with just the vector directory.

```bash
python3 -I -B check.py --compare my-results.json
```

[SHA256SUMS](SHA256SUMS) pins the raw inputs, case assignments and expected
results. The `generator_revision` in [vectors.json](vectors.json) identifies
the VATE code that issued the fixture admissions. When reporting a run, include
your reader's revision, the SHA-256 of `SHA256SUMS`, and your case results.
Use the package matching the report's `vector_set` when comparing an older
run. The separate purchase-cap conformance corpus exercises admission
decisions and request transformations.
