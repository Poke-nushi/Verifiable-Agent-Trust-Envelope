# Signed sidecar swap: two acceptance receipts

This negative control tests whether a reader binds a signed sidecar to the
acceptance receipt it actually names. The two sidecars have valid signatures,
but each is paired with the other acceptance receipt.

The control was prepared by Poke-nushi for the comparison in
[Horizon Shield #51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51#issuecomment-6250996314).
The original issued rehearsal records are from
[babyblueviper1/preaction-governance-conformance at
`a77ff8fabe46a30aaf3e50d10c8c3a9f003713f9`](https://github.com/babyblueviper1/preaction-governance-conformance/tree/a77ff8fabe46a30aaf3e50d10c8c3a9f003713f9/examples/work-acceptance-issuer).

These files are non-normative comparison inputs, outside the VATE conformance
corpus.

## Files and derivation

| File | Bytes | SHA-256 of exact file bytes |
| --- | ---: | --- |
| `hs51-rehearsal-caseA-audit-only.swapped-sidecar.json` | 19822 | `32744cfc7104dcb5bb59daf7305f9b7fe4887ce4da81886040003f73ef836ada` |
| `hs51-rehearsal-caseA-with-fixture.swapped-sidecar.json` | 19642 | `561ce33bad29cac89261ae1a7d06a7c71a9d118103667e9ef940d04083846860` |

Only the complete top-level `bindings_sidecar` JSON values were exchanged,
including their existing signatures. Each exchanged value retains its source
bytes. Every byte outside that value is unchanged from its own source file.
No new receipt or signature was issued for this control.

`control-manifest.json` records the original file hashes, the donor for each
sidecar, and the expected results. The source wrapper's `description`,
`inputs`, and `expected` fields remain unchanged. Read them as descriptions of
the original rehearsal and its receipt-level checks, alongside this control's
manifest.

From this directory, check the two file digests with:

```sh
shasum -a 256 -c SHA256SUMS
```

## Expected observations

| Check | Audit-only record | With-fixture record |
| --- | --- | --- |
| Acceptance-record signature | valid | valid |
| Sidecar signature | valid | valid |
| Native verdict recomputed from signed criteria results | `incomplete` | `pass` |
| Sidecar names this acceptance receipt | **false** | **false** |
| Sidecar names the original execution receipt | true | true |
| Sidecar names the original request occurrence | true | true |

The failing relation compares `bindings_sidecar.receipt_sha256` with SHA-256
of the JCS-canonical **inner** `inputs.receipt.receipt` object. It does not hash
the whole wrapper or the signature envelope. The manifest lists both the
computed receipt digest and the different digest carried by each sidecar.

The original [`war_check.py`](https://github.com/babyblueviper1/preaction-governance-conformance/blob/a77ff8fabe46a30aaf3e50d10c8c3a9f003713f9/examples/work-acceptance-record-cold/war_check.py)
checks the acceptance record and recomputes its verdict; it does not check
the sidecar join. It therefore continues to agree with the unchanged native
`expected` fields. A reader checking the cross-record relation should report
both receipt-binding mismatches while preserving those native results.

The execution and request originals are in Horizon Shield at
[`dcbdc5d27e4f87b0785fe6af4303df15bd46dd3a`](https://github.com/ogasurfproject-jpg/horizon-shield/tree/dcbdc5d27e4f87b0785fe6af4303df15bd46dd3a/workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0/rehearsal/live_smoke).
The execution relation hashes the exact bytes of `receipt.json`; the occurrence
relation hashes the JCS-canonical `call.json.request` object, including `type`.

Local verification checked the four acceptance/sidecar signatures with pure
Python and Node Ed25519 implementations. The original execution receipt's
signature was checked separately. The acceptance and sidecar checks used the
checker key independently published in the
[checker key document](https://api.babyblueviper.com/.well-known/invinoveritas-checker-keys.json)
retrieved on 2026-10-18 at 14:35:09 UTC (530 bytes; raw SHA-256
`2a4eb3cc1cf71402f0331ebd42d652cfde0f50fdb81685689fe1788c7e70d403`).
No model judgment was rerun. Timestamp checks were
limited to message imprints and parsed times; TSA signatures and trust chains
were not verified. These are derived rehearsal controls, not pilot records.

## Source attribution

The source repository publishes these examples under the MIT license.
Its copyright and permission notice are preserved in
[`UPSTREAM-LICENSE.txt`](UPSTREAM-LICENSE.txt). The modified pairing is the
change introduced by this control; the signed record contents remain those
issued by the original checker.
