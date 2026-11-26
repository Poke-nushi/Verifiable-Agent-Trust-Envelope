# OAuth and signed authority checks with OpenFGA 1.23.0

Revoking the user's delegation to agent A stopped agent B's next calendar
operation on both OpenFGA 1.22.1 and 1.23.0. B kept the same active OAuth
token and child grant. In a separate purchase example, the issuer signed
OpenFGA's updated permission decision into a VATE authority snapshot.
The receiver used that snapshot to stop a pending purchase before dispatch.

The two versions produced identical observations in all 14 first-hop cases
and all 20 signed-issuer checks on macOS arm64 with Ory Hydra 26.2.0.
[Compare the observations by case](observations.json).

| Observation | Result on each version |
| --- | --- |
| First-hop delegation withdrawn | The next resource request changed from HTTP 200 to 403. The user's own calendar permission remained valid. The cumulative action count stayed at two. |
| Only an alternative parent remains enabled | OpenFGA found the alternative path. The resource rejected the request because the trial requires the originally selected parent. |
| Parent lookup unavailable | The resource returned HTTP 503. The action count stayed at two. |
| Owner permission or delegation withdrawn in OpenFGA | The pending purchase produced zero additional recording callbacks. |
| Delivery restored and permission checked again | The original admitted purchase reached the recording callback once. |

The [first-hop trial](../oauth-first-hop-revocation-trial.md) defines the
delegation cases. Its `EXPECTED.json` names the fields in each observation.
For the [signed issuer](../../../reference/authority-issuer/README.md), the
recovery observation `[1, true, true]` means one callback, the same effective
request at dispatch, and the original admission receipt retained byte for byte.

OpenFGA 1.23.0 includes the [upstream fix for incorrect authorization during
timeouts and cancellations](https://github.com/openfga/openfga/security/advisories/GHSA-637h-v79h-mvqf).
These runs exercised ordinary authorization and deliberate service shutdown.
Server-deadline and cancellation behavior under load was outside the comparison.

## Run with OpenFGA 1.23.0

Use macOS arm64, Python 3.14, Git, and a checkout containing commit
`fac9d94c4c8093fdfb32491413794c9ac0a6411f`. Run the following blocks from
the repository root in the same shell.

```sh
repo=$(pwd -P)
profile="$repo/docs/interop/openfga-1.23.0"
work=$(mktemp -d)
curl --fail --location --output "$work/trial.zip" \
  https://vate.rognalia.com/downloads/oauth-first-hop-revocation/2026-11-10/oauth-first-hop-revocation-trial-20261110.zip &&
python3.14 -B "$profile/prepare.py" --trial-zip "$work/trial.zip" --output "$work/source"
```

The helper verifies the published trial ZIP, copies its runtime files and
exports the pinned VATE source. It applies [the version and digest
changes](native-pins.patch) to those copies. The authorization model, grant
bindings and expected observations are identical to those in the 1.22.1 run.

```sh
python3.14 -B "$work/source/trial/setup_native.py" --download --destination "$work/native" &&
python3.14 -B "$work/source/trial/run_chain.py" --native-root "$work/native" --output "$work/first-hop"
```

The setup helper verifies the two official archives before extracting the
executables. To reuse previously downloaded archives, replace `--download` with
`--archives /path/to/archives`. The runner starts temporary loopback services.
Open `$work/first-hop/RESULT.json` for the 14 case results and
`$work/first-hop/FIRST-HOP-REVOCATION.json` for the state before and after
revocation.

For the signed issuer, set `NODE_BIN` to a trusted Node.js 22+ executable
and `OPENSSL_BIN` to a trusted OpenSSL executable with `req -addext` support.
Set `NODE_SHA256` and `OPENSSL_SHA256` to their independently selected
SHA-256 values. This run used Node.js 22.23.4 and OpenSSL 4.0.3.
Their binary hashes are in [the comparison record](observations.json).

```sh
python3.14 -B "$work/source/vate/reference/authority-issuer/run_native.py" \
  --native-root "$work/native" \
  --node "${NODE_BIN:?set NODE_BIN}" --node-sha256 "${NODE_SHA256:?set NODE_SHA256}" \
  --openssl "${OPENSSL_BIN:?set OPENSSL_BIN}" --openssl-sha256 "${OPENSSL_SHA256:?set OPENSSL_SHA256}" \
  --output "$work/issuer"
```

`$work/issuer/RUN.json` records the 20 observations and one recording
callback. Its eight signed authority snapshots are in the same directory.
Both runners require a new output directory for each execution.
