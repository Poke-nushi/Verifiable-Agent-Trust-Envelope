# Horizon #51 witness key

The VATE maintainer's dedicated Ed25519 public key for the
[Horizon #51 pilot](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51)
is in [public-key.json](public-key.json).

- Acknowledgement type: `musubi.ca2a.witness-ack.v0`.
- Log ID: `nenrin:ca2a-companion:pilot51`.
- Profile: [MUSUBI companion v0.1, sections 3–4](https://github.com/ogasurfproject-jpg/horizon-shield/blob/6b4841af9083ddfe6eb9f9cfe253d2c97743f290/workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0/COMPANION_v0_1.md).

Before an acknowledgement is issued, the run's published trust configuration
must name this key and the other independent witness key, with threshold 2.
The maintainer authenticates and publishes each agreed item, then signs its
acknowledgement using the latest Bitcoin block independently observed by the
maintainer. The item and acknowledgement remain publicly available here.

The witness acknowledgement attests receipt and publication of the named
item. A verified anchor supplies the upper time bound under the profile;
the acknowledgement alone does not. It does not attest that the budget or
criteria are sensible, that a payment settled, or that the work succeeded.

No pilot acknowledgement or run result has been issued here.
