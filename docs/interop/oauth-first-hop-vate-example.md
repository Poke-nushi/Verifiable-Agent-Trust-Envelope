# Replay OAuth first-hop revocation records with VATE

Can a receiver tell which calendar request ran when an agent's parent delegation
was revoked and the execution receipt arrived late? This package replays records
from the [14-case OAuth first-hop trial](oauth-first-hop-revocation-trial.md).
It compares receipt code from an earlier VATE commit (`c32df11e`) and from
v0.7.0 (`d96d31a2`) using the same OAuth interpretation.

## Download and replay

The [fixed ZIP](https://vate.rognalia.com/downloads/oauth-first-hop-vate/2026-11-19/oauth-first-hop-vate-v0.7.0.zip)
includes both readers and two saved captures. The [package identity](oauth-first-hop-vate-example.package.json)
records the archive digest and the exact VATE commits. On macOS arm64 with
Python 3.14, start in a new directory and verify the ZIP before extracting it.

```sh
curl --fail --location --remote-name https://vate.rognalia.com/downloads/oauth-first-hop-vate/2026-11-19/oauth-first-hop-vate-v0.7.0.zip &&
printf '%s\n' '0283813ffd0e1201240f4c3db8347fa50a0b1ec770f1ef2d532e4154d89048ba  oauth-first-hop-vate-v0.7.0.zip' | shasum -a 256 -c - &&
unzip -q oauth-first-hop-vate-v0.7.0.zip &&
cd oauth-first-hop-vate-v0.7.0
```

Install the pinned Python dependencies once, then replay the first saved capture.
The replay runs offline.

```sh
python3.14 -m venv ../oauth-replay-env &&
../oauth-replay-env/bin/python -m pip install --only-binary=:all: --require-hashes -r requirements.lock &&
../oauth-replay-env/bin/python -B reproduce.py --output ../oauth-results
```

In `../oauth-results/RESULT.json`, `same_receiving_results: true` means the two
readers agreed on the three selected observations after their source identities
were checked. The 14 native cases include the following observations.

| Selected request | Recorded outcome | Calendar action count |
| --- | --- | --- |
| Before revocation | Permitted. The execution receipt and fixture output correspond to the selected request. | 1 → 2 |
| After removing the user → A grant | Denied. B's token stays active, the child grant stays enabled and the user's calendar permission remains in place. | 2 → 2 |
| Parent lookup unavailable | HTTP 503. The policy evaluation could not finish. | 2 → 2 |

## Follow the late receipt

Open `../oauth-results/recomputed.json`. Across its seven revisions, a later
denial and a different request's result both leave the earlier request pending.
The matching execution receipt completes that request in revision 6. Revision 7
retains a conflicting receipt alongside the earlier evidence.

Each revision's `inbox_run_status` records whether the Inbox accepted that
revision. All seven are `completed` in the standard replay. The OAuth assessment
of each request is in `report.attempts`. The fixture trusts its local collector
and uses unsigned records from synthetic operations.

The bundled README includes commands for the second capture, the receipt and
OAuth test suites, and a fresh loopback run with Ory Hydra 26.2.0 and OpenFGA
1.22.1. Only the fresh run needs those two executables.
