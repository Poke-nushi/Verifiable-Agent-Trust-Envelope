# Receipt Protocol Store: Reuse Of VATE Receipt Checks

## Result

[hhh7666](https://github.com/hhh7666) connected Receipt Protocol's in-memory
store to VATE's existing receipt checker and returned a fixed R17 round-trip
report on 10 October 2026. The VATE maintainer reproduced that path on
11 October 2026 (JST): both retrieved receipts were byte-for-byte unchanged,
and the complete checker result matched the result on the originals.

This is a concrete example of an external developer reusing VATE's receipt
checks after storage and retrieval. The store supplies the originals; the
recipient runs VATE's checks on their relationship.

## Sources And Reproduction

- [Contributor's report](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2#issuecomment-6097856240), following a [request for this round trip](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2#issuecomment-6097450251).
- [VATE maintainer's reproduction and storage finding](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/2#issuecomment-6100439962).
- Receipt Protocol POC: [`35a5afbdf1fb299f283e4057bff25001275917ff`](https://github.com/hhh7666/receipt-protocol/tree/35a5afbdf1fb299f283e4057bff25001275917ff/reference/store-poc).
- VATE example: [`b8bc649f7956989aa38f026882fcb5fc65d0411a`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/b8bc649f7956989aa38f026882fcb5fc65d0411a/reference/receipt-linkage-example).

The maintainer used macOS arm64, Node.js 22.16.0, Python 3.14.3 and the existing
`jsonschema==4.26.0` dependency. The four POC source files and the VATE source
export remained unchanged. Network access was disabled during execution.

At these pins, place `receipt-protocol/` and the VATE checkout named
`vate-test/` beside each other in a disposable directory without spaces.
Prepare `vate-test/.venv` using the [example's setup instructions](../../reference/receipt-linkage-example/README.md#run-the-examples).
The upstream script resolves `../../../vate-test` from `reference/store-poc/`;
this is one level above the path printed in the contributor's comment.

```sh
cd receipt-protocol/reference/store-poc
node r17-roundtrip.mjs
node negative-tests.mjs
```

The round-trip script writes retrieved copies into `tmp-r17/` and invokes
`vate-test/.venv/bin/python` on them. It does not execute the original operation.

## Maintainer Observations

| Check | Observed result |
| --- | --- |
| Unmodified upstream R17 script | Seven assertions passed; exit 0. |
| Unmodified upstream regression script | Nine assertions passed; exit 0. |
| Admission and post-execution originals after retrieval | 1,690 and 2,037 bytes respectively; both exactly equal to their inputs. |
| Direct and retrieved-input checker runs | Complete JSON results equal; `record_linkage: matched`, `core_result.outcome: success`, exit 0. |
| VATE's existing synthetic runtime-mismatch pair through the store | `mismatch`, `POST_EXEC_RUNTIME_MISMATCH`, exit 1 as expected. |

The runtime-mismatch check was an additional maintainer check, separate from
the contributor's R17 script. R17 also matches when checked directly, without
this store.

## Connection Conditions

These notes describe the tested integration and the recipient's remaining
responsibilities; they introduce no new VATE schema or protocol requirement.

| Responsibility | Condition for this path |
| --- | --- |
| Select and retrieve records | The caller selects the admission/post pair and supplies local files. The checker does not fetch receipt URIs or infer authority from a transaction-ID lookup. |
| Preserve stored originals | Storage uses SHA-256 of raw bytes. For this mutable-Buffer API, the store needs its own copy on insertion and a separate copy on retrieval. The recipient compares retrieved bytes with its reference originals. |
| Check VATE linkage | The recipient uses VATE's JSON-object digest and receipt rules. A raw-byte storage hash is not the admission digest referenced by a VATE post-execution receipt. |
| Preserve the assessment | Retain `matched`, `mismatch` or `not_assessed`, the reasons and `not_checked`. Missing input remains unassessed; it is not evidence that the operation failed or never ran. |
| Maintain the connection | Pin the source and checker dependencies. The POC adds a retrieval/file handoff and assumes the directory layout above; it does not translate a different native receipt format into VATE. |
| Establish trust and effects | Issuer authority, signatures, request-hash preimages, complete effect evidence and current execution permission remain separate from receipt-pair matching. |

### Storage limitation at the tested pin

`storeReceipt()` retains the caller's mutable Buffer, and `getReceiptRaw()`
returns that same Buffer. The maintainer observed that changing either the
input Buffer after insertion or a retrieved Buffer changes the stored bytes
while leaving the lookup digest unchanged. The successful R17 path did not
mutate those buffers. Copying bytes at insertion and retrieval, with regression
checks for both paths, was recommended in the linked maintainer response.
No corrected version is evaluated in this record.

## Scope And Acknowledgement

The records are supplied VATE fixtures and the checker is VATE's implementation.
This partial reuse is not an independently implemented VATE verifier or an
external-SUT corpus comparison. The trial does not evaluate original execution,
issuer authentication, production operation, durable storage or tenant isolation.

Thanks to [hhh7666](https://github.com/hhh7666) for building the storage POC,
providing the pinned round trip and connecting retrieved originals to VATE's
receipt checks.
