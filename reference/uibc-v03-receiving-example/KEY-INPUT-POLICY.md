# Ed25519 public-key input policy

The receiver excludes known small-order encodings and noncanonical y values
before invoking the signature backend. These restrictions apply to Ed25519
public keys, not HMAC shared keys.

`reader/ed25519_key_policy.py` rejects:

- y coordinates at or above `2^255 - 19`, after masking the sign bit for this
  range check only;
- five canonical y encodings from the fixed small-order table, with either
  sign bit. The table's p and p+1 aliases are already excluded by the range check.

The actual key bytes and signed payload are never normalized. This is a bounded
input restriction, not a general on-curve, prime-subgroup or mixed-order
validation algorithm. Signature verification, including its R and S handling,
remains the cryptography backend's responsibility. Passing the input gate does
not establish key ownership or authority.

## Observable behavior

A receiver-selected excluded key raises `InputError` before opening the
package. The CLI reports `invalid_input` and exits 64. An excluded recorded
key instead leaves `signature` as `not_assessed`, with a specific reason, and
does not invoke the backend. A known mismatch in the selected key or recorded
key identifier remains a mismatch.

These are this example's receiving conditions. The pinned UIBC verifier is
not claimed to apply the same exclusions. The 22-condition S4/S5/S6 comparison
and these additional input-policy tests are separate evidence.

The regression suite covers a fixed identity-key counterexample without
changing its signature, 48 excluded encodings in recorded and selected key
positions, and 12 normally generated keys with both sign-bit values. It also
checks that missing seals, incompatible key modes and unsupported profiles
retain specific diagnostic reasons.

## Provenance and license

- [RFC 8032 §5.1.3](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.3)
  defines the y-coordinate range and sign bit.
- The small-order constants derive from `ge25519_has_small_order` in
  [libsodium commit 45b09a6, line 1022](https://github.com/jedisct1/libsodium/blob/45b09a607d596e40adbff9ab812e47d85175c053/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L1022).
  Its license is retained as `reader/LIBSODIUM-LICENSE.txt`; libsodium is not
  installed or executed by this example.
- `reader/key-input-vectors.json` was derived from that fixed table and the RFC
  range, independently of the reader's constants. It contains 10 encodings
  associated with the five canonical y values (including two invalid negative-zero
  encodings) and 38 encodings for the 19 out-of-range y values with both signs.
