"""
reproduce_checksum_bug.py — standalone reproduction of the F1 checksum defect.

This is a *read-only* demonstration of WHY the original encoding was wrong.
It does not generate any forgery material; it only shows that the buggy
encoder returns (0, 0, 0) for every legal checksum value, while the fixed
encoder returns the correct three base-16 digits.

The bug (V0): `base_w(c.to_bytes(32, "big"), 3)`.
Because c <= 960 fits in two bytes, the 32-byte big-endian buffer is
zero-padded; `base_w` reads the leading zero nibbles and always yields
(0, 0, 0). The three checksum hash chains are then revealed at position 0
(the secret itself), silently defeating the WOTS+ checksum binding.

The fix (V1): the plain three base-16 digits of c, which for (w=16, len2=3)
is identical to the RFC 8391 / FIPS 205 encoding (see tests/test_checksum.py).
"""

from __future__ import annotations

W = 16
LEN2 = 3
MAX_CHECKSUM = 960  # len1*(w-1) = 64*15


def buggy_checksum_digits(c: int) -> list[int]:
    """Reproduce the ORIGINAL implementation's encoding mistake.

    Equivalent to ``base_w(c.to_bytes(32, 'big'), 3)``: it takes the first
    three hexadecimal digits of the 32-byte zero-padded buffer, which are
    always zero for c <= 960.
    """
    buf = c.to_bytes(32, "big")
    return [
        (buf[0] >> 4) & 0x0F,
        buf[0] & 0x0F,
        (buf[1] >> 4) & 0x0F,
    ]


def fixed_custom_checksum_digits(c: int) -> list[int]:
    """The CORRECT three base-16 digit decomposition of c (the fix)."""
    if not 0 <= c <= MAX_CHECKSUM:
        raise ValueError("checksum out of range")
    return [
        (c >> 8) & 0x0F,
        (c >> 4) & 0x0F,
        c & 0x0F,
    ]


def main() -> None:
    print("c      buggy(V0)            fixed(V1)")
    print("-" * 48)
    all_buggy_zero = True
    for c in [0, 1, 15, 16, 255, 256, 960]:
        b = buggy_checksum_digits(c)
        f = fixed_custom_checksum_digits(c)
        if b != [0, 0, 0]:
            all_buggy_zero = False
        print(f"{c:3d}    {tuple(b)}    {tuple(f)}")

    # Exhaustive check over the full legal range (V0 must be constant).
    assert all(buggy_checksum_digits(c) == [0, 0, 0]
               for c in range(MAX_CHECKSUM + 1)), \
        "unexpected: buggy encoder varied with c"
    assert all_buggy_zero, "buggy encoder was not constant (0,0,0)"

    # V1 must vary and reconstruct c.
    seen = {tuple(fixed_custom_checksum_digits(c))
            for c in range(MAX_CHECKSUM + 1)}
    assert len(seen) == MAX_CHECKSUM + 1, "fixed encoder not injective"
    for c in range(MAX_CHECKSUM + 1):
        d = fixed_custom_checksum_digits(c)
        assert ((d[0] << 8) | (d[1] << 4) | d[2]) == c

    print("-" * 48)
    print("[ok] V0 (buggy) is constant (0,0,0) for all c in [0, 960]")
    print("[ok] V1 (fixed) is injective and reconstructs c")
    print("[note] V1 equals the RFC 8391 / FIPS 205 encoding for (w=16,len2=3)")


if __name__ == "__main__":
    main()
