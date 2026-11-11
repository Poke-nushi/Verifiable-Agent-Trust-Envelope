"""Bounded public-key input restrictions; signature verification stays in OpenSSL.

RFC 8032 section 5.1.3 defines the y-coordinate range and sign bit.
The five canonical y encodings below are the small-order entries from
libsodium ge25519_has_small_order at 45b09a607d596e40adbff9ab812e47d85175c053.
Its p and p+1 aliases are covered by the range check. Both sign bits are
rejected for each listed y. See ../KEY-INPUT-POLICY.md for scope/provenance.

This is NOT an on-curve or prime-subgroup validator. It does not implement
point arithmetic, key generation, signing, or signature verification.
"""

FIELD_MODULUS = (1 << 255) - 19
Y_MASK = (1 << 255) - 1
SMALL_ORDER_Y = frozenset(bytes.fromhex(value) for value in (
    "00" * 32,
    "01" + "00" * 31,
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ec" + "ff" * 30 + "7f",
))


def public_key_issue(value: bytes) -> str | None:
    """Return an unsupported-input reason, or None to continue verification.

None means only that these bounded exclusions did not match. It does not
establish key validity, ownership, authority, or subgroup membership.
"""
    if not isinstance(value, bytes) or len(value) != 32:
        return "invalid_ed25519_public_key"
    y = int.from_bytes(value, "little") & Y_MASK
    if y >= FIELD_MODULUS:
        return "noncanonical_ed25519_public_key"
    if y.to_bytes(32, "little") in SMALL_ORDER_Y:
        return "small_order_ed25519_public_key"
    return None
