# Replay a purchase assessment before and after its result arrives

A recipient saves purchase request A and receives the corresponding admission. The result receipt arrives later. This example uses [Recipient Inbox](../README.md) to retain both assessments and the [purchase reader](../../request-binding/README.md) to check the admission against the request the recipient saved. It uses two synthetic USD 24.50 purchases from the [receiver-selection examples](../../request-binding/receiver-selection/README.md).

| What the recipient has at the cutoff | Saved request A and admission | Admission and result receipt |
| --- | --- | --- |
| A's admission and purchase inputs | Match | `not_assessed` |
| A's admission and A's result | Match | `matched` |
| A's admission and B's result | Match | `mismatch` |

The two possible deliveries have separate histories. From the latest export of either history, the recipient can reproduce both its earlier and later decisions. Reassessment reads saved records. The example makes no purchase or payment.

## Run both histories

Use a trusted VATE checkout or unpacked repository source on Linux or macOS with Python 3.10 or later. From the repository root, use the project's Python environment. To create it on a fresh checkout, run the following commands.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
```

```sh
work=$(mktemp -d)
example=reference/recipient-inbox/purchase-late-result
.venv/bin/python -IB "$example/run_example.py" --output "$work/purchases"
```

Open `$work/purchases/SUMMARY.json` for the four decisions and their digests. For each delivery, the command starts a new process when the result arrives, copies the latest Inbox export and replays it in a third process. Both purchase decisions must match their saved bytes. Inbox reports must match in every field except elapsed processing time.

The summary's `same_inventory_cutoff` section holds the assessment time fixed with all three deliveries registered. At the earlier cutoff the result is excluded and the link is `not_assessed`. At the later cutoff the same result is included and the link is `matched`. The cutoff uses the recipient's recorded arrival time.

## Replay a saved export

Keeping the same source and Python environment, run the following command in the same shell. Its evidence input is the copy of the latest export for A. The original SQLite database and the earlier export are unnecessary for this step.

```sh
.venv/bin/python -IB "$example/trial.py" replay "$work/purchases/export-A" "$work/replay-A"
```

In `$work/replay-A`, the two `revision-*-purchase-decision.json` files contain both checks and references to the saved request, admission and any result available at the cutoff. Follow those references into the export's `objects/` directory for the original bytes.

Use `export-B` and a fresh output directory to replay the mismatched result. Its `revision-2-inbox-report.json` records the receipt checks that caused the mismatch. Inbox records the evaluator's source hashes and the Python executable's path and identity in each job.
