# Horizon #51 replacement witness inputs

This directory preserves four signed items from the
[replacement input set posted by the Horizon #51 organizer](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51#issuecomment-6281335113).
Each JSON file is copied byte-for-byte from that post, including its existing
signature. These items belong to credential `horizon-shield-51-buyer-2` and log
`nenrin:ca2a-companion:pilot51`.

The [MUSUBI pilot profile, §3](https://github.com/ogasurfproject-jpg/horizon-shield/blob/283bee47f24e96ccf6ed66492b918c3c1d35c95b/workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0/PILOT_v0.md#3-objects)
defines budget policies and criteria commitments as restrictions that the
companion's witnessed lane can carry.

## Items

| File | Bytes | Meaning |
| --- | ---: | --- |
| [budget.json](items/budget.json) | 391 | Principal-signed policy setting the credential's aggregate budget to `20000 JPY-testnet`. |
| [criteria_A.json](items/criteria_A.json) | 614 | Buyer-signed commitment binding request A to the shared acceptance criteria. |
| [criteria_B.json](items/criteria_B.json) | 614 | Buyer-signed commitment binding request B to the shared acceptance criteria. |
| [criteria_C.json](items/criteria_C.json) | 614 | Buyer-signed commitment binding request C to the shared acceptance criteria. |

The three criteria commitments contain digests of the requests and criteria
document, together with the buyer, checker and observed Bitcoin block. They
are commitments intended to be fixed before execution, not acceptance verdicts. All three
refer to the same criteria document, with SHA-256
`6d62ca38527015ac9c31612653171b0d05547591b9bfd4be33593e513ab534b9`.

The source post also contains the credential, requests, tasks and trust
configuration needed to interpret this set. Use that replacement set together;
do not mix it with the earlier `horizon-shield-51-buyer-1` inputs.

## Byte integrity

[SHA256SUMS](SHA256SUMS) lists the raw-file SHA-256 for each item. The files are
compact JSON without a trailing newline. These checksums include the existing
signatures; reformatting or adding a newline changes the raw-file checksum.

From this directory, check all four files on macOS:

```sh
shasum -a 256 -c SHA256SUMS
```

Or on Linux with GNU coreutils:

```sh
sha256sum -c SHA256SUMS
```

For reproducible references, use each file's GitHub URL pinned to a full Git
commit SHA. A branch URL can change. A checksum match establishes byte equality
with this manifest; it does not verify a signature or timestamp proof.

## Witness status

The VATE maintainer's [four witness acknowledgements](acknowledgements/README.md)
are available with their OpenTimestamps digests. They attest receipt and
publication of these originals; experiment results are separate.

A verified anchor supplies an upper bound on when the acknowledgement had
been signed, under the
[MUSUBI companion profile](https://github.com/ogasurfproject-jpg/horizon-shield/blob/6b4841af9083ddfe6eb9f9cfe253d2c97743f290/workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0/COMPANION_v0_1.md).
The acknowledgement alone does not establish that upper bound or attest that
the budget or criteria are sensible, that a payment settled, or that the work
succeeded.
