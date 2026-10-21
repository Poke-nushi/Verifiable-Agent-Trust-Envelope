# Horizon #51 witness acknowledgements

The VATE maintainer (`Poke-nushi`) signed these four acknowledgements after
receiving and publishing the [replacement input originals](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/36aa794cf2f93ceed91d291002a0ec3b616ec9f6/docs/interop/horizon51-witness/2026-10-22-replacement/README.md).
They use log `nenrin:ca2a-companion:pilot51` and the previously published
[Ed25519 witness key](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/36aa794cf2f93ceed91d291002a0ec3b616ec9f6/docs/interop/horizon51-witness/public-key.json).

## Acknowledgements and timestamp digests

Each file is the complete acknowledgement, including its signature, encoded as
RFC 8785/JCS bytes without a trailing newline. These files have no `anchor`
field. Their raw-file SHA-256 values below are the acknowledgement digests to
submit to OpenTimestamps; they are distinct from the original `item_sha256`
values inside the acknowledgements.

| Item | Acknowledgement | SHA-256 for OpenTimestamps |
| --- | --- | --- |
| [budget](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/36aa794cf2f93ceed91d291002a0ec3b616ec9f6/docs/interop/horizon51-witness/2026-10-22-replacement/items/budget.json) | [budget.jcs](budget.jcs) | `902525f591fc05949a62137c85ad046087cf52addb3276e132dd7d7be8c797a2` |
| [criteria A](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/36aa794cf2f93ceed91d291002a0ec3b616ec9f6/docs/interop/horizon51-witness/2026-10-22-replacement/items/criteria_A.json) | [criteria_A.jcs](criteria_A.jcs) | `6feb40a5c67c85f69238104e793f4d13156a2660bfa9cca6f7bf8b9795679634` |
| [criteria B](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/36aa794cf2f93ceed91d291002a0ec3b616ec9f6/docs/interop/horizon51-witness/2026-10-22-replacement/items/criteria_B.json) | [criteria_B.jcs](criteria_B.jcs) | `290bd476a05042790f89a962d9ee1b4655d4937fa056158df6be7ad442f7e522` |
| [criteria C](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/36aa794cf2f93ceed91d291002a0ec3b616ec9f6/docs/interop/horizon51-witness/2026-10-22-replacement/items/criteria_C.json) | [criteria_C.jcs](criteria_C.jcs) | `e99bb95e4d11192894bb7fea3258c9766beec729ff690b485f374a9604913a31` |

All four acknowledgements name Bitcoin block `972415` in `seen_block`:

```text
00000000000000000000f519db50a92872e84ce68125d13889d9b2a16f24b198
```

This block was observed through Blockstream's public Bitcoin API before signing.

## Verification and scope

Check the published bytes against [SHA256SUMS](SHA256SUMS), from this directory:

```sh
shasum -a 256 -c SHA256SUMS
```

On Linux with GNU coreutils:

```sh
sha256sum -c SHA256SUMS
```

A matching checksum establishes byte equality. Verify each Ed25519 signature
against the witness key and each `item_sha256` against the corresponding
original, following [MUSUBI companion v0.1, sections 3–4](https://github.com/ogasurfproject-jpg/horizon-shield/blob/6b4841af9083ddfe6eb9f9cfe253d2c97743f290/workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0/COMPANION_v0_1.md#3-acknowledgement).
Use full Git commit SHA URLs when passing these files to another verifier.

Each acknowledgement attests receipt and publication of its named item. This
publication contains no OpenTimestamps or Bitcoin anchor proofs; a signature
alone does not establish the upper time bound required by the profile. The
acknowledgements do not report payment settlement, acceptance verdicts, or
experiment results.
