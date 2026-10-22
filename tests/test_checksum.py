"""
tests/test_checksum.py — WOTS+ checksum verification (P0-1 / F1).

Provides an INDEPENDENT reference checksum implementation (deliberately not
importing the production code's internals) and asserts it agrees with the
fixed ``wots.wots_checksum`` across boundaries and random values.

Context: the original implementation encoded the checksum via
``base_w(checksum.to_bytes(32, 'big'), 3)``, which is always ``[0, 0, 0]`` for
c <= 960. The fixed code does a correct integer base-W decomposition. This file
locks in the corrected behaviour and rejects out-of-range inputs.
"""

import math
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest
import wots as prod  # fixed production implementation

# ---- independent reference (does NOT use prod's internals) -------------------
N = 32
W = 16
LOG_W = 4                                # log2(W)
LEN1 = (8 * N + (LOG_W - 1)) // LOG_W     # 64
LEN2 = math.floor(math.log2(LEN1 * (W - 1)) / math.log2(W)) + 1  # 3
MAX_CHECKSUM = LEN1 * (W - 1)            # 960


def ref_checksum_to_digits(c: int):
    """Correct integer base-W decomposition into LEN2 most-significant-first
    digits, with strict range validation."""
    if not isinstance(c, int):
        raise TypeError("checksum must be an integer")
    if not 0 <= c <= MAX_CHECKSUM:
        raise ValueError("checksum out of range")
    return [(c >> 8) & 0xF, (c >> 4) & 0xF, c & 0xF]


def ref_checksum_from_digits(digits):
    if len(digits) != LEN1:
        raise ValueError("invalid message digit count")
    if any((not isinstance(d, int)) or d < 0 or d >= W for d in digits):
        raise ValueError("invalid base-w digit")
    return sum((W - 1) - d for d in digits)


# ---- reference-only property tests -----------------------------------------
def test_ref_boundaries():
    for c in [0, 1, 15, 16, 255, 256, 959, 960]:
        d = ref_checksum_to_digits(c)
        decoded = (d[0] << 8) | (d[1] << 4) | d[2]
        assert decoded == c, (c, d, decoded)


def test_ref_out_of_range_rejected():
    for c in [-1, 961, 1000, 5000]:
        with pytest.raises(ValueError):
            ref_checksum_to_digits(c)


def test_ref_extremes():
    assert ref_checksum_from_digits([15] * LEN1) == 0
    assert ref_checksum_from_digits([0] * LEN1) == MAX_CHECKSUM


def test_ref_message_digit_errors():
    with pytest.raises(ValueError):
        ref_checksum_from_digits([15] * (LEN1 - 1))      # wrong length
    with pytest.raises(ValueError):
        ref_checksum_from_digits([16] + [15] * (LEN1 - 1))  # illegal digit
    with pytest.raises(ValueError):
        ref_checksum_from_digits([-1] + [15] * (LEN1 - 1))  # negative digit


# ---- cross-check: production must agree with the independent reference -----
def test_prod_matches_ref_on_boundaries():
    for c in [0, 1, 15,16, 255, 256, 959, 960]:
        assert prod.wots_checksum(c) == ref_checksum_to_digits(c), c


def test_prod_matches_ref_on_random():
    rng = random.Random(1234)
    for _ in range(2000):
        c = rng.randint(0, MAX_CHECKSUM)
        assert prod.wots_checksum(c) == ref_checksum_to_digits(c)


def test_prod_rejects_out_of_range():
    for c in [-1, 961, 1000]:
        with pytest.raises(ValueError):
            prod.wots_checksum(c)


def test_checksum_varies_with_message():
    """F1 core property (post-fix): checksum digits vary with the message so
    the three checksum-chain secrets are no longer emitted in cleartext."""
    import hashlib
    seen = set()
    for m in [b"", b"a", b"hello", os.urandom(20), b"different message"]:
        digest = hashlib.sha256(b"HBS-PQ-MSG-v1" + m).digest()
        md = prod.base_w(digest, LEN1)
        c = sum(W - 1 - d for d in md)
        seen.add(tuple(prod.wots_checksum(c)))
    assert len(seen) >= 2, "checksum digits must vary across messages"


# ---------------------------------------------------------------------------
# F1 framing (responds to reviewer note 2.4): the CORRECTED custom encoding is
# mathematically identical to the RFC 8391 / FIPS 205 checksum encoding for the
# parameter set used here (w=16, len2=3). The defect was reading three digits
# from a 32-byte zero-padded buffer (always zero), NOT a deviation from the
# standard encoding. These helpers make that equivalence explicit and tested.
# ---------------------------------------------------------------------------

def checksum_value(digits, w=16):
    """Inverse of the encoding: recover the integer checksum from its len1
    message base-w digits. Asserts the canonical length and digit range."""
    assert len(digits) == LEN1
    assert all(0 <= d < w for d in digits)
    return sum((w - 1) - d for d in digits)


def encode_custom_checksum(c):
    """Paper's custom integer decomposition, not FIPS 205 encoding per se.

    For 0 <= c <= 960 this is exactly the 3-digit base-16 representation of
    c (c0 = floor(c/256), c1 = floor((c mod 256)/16), c2 = c mod 16)."""
    if not 0 <= c <= MAX_CHECKSUM:
        raise ValueError("checksum out of range")
    return [(c >> 8) & 0x0F, (c >> 4) & 0x0F, c & 0x0F]


def encode_rfc8391_checksum(c):
    """RFC 8391 / FIPS 205 WOTS+ checksum encoding for n=32, w=16, len2=3.

    The standard specifies a left shift by 8 - (len2*log2(w) mod 8) = 4 bits,
    then takes len2 base-w digits from the high end. For this parameter set
    the result is identical to the plain 3-digit base-16 decomposition above."""
    if not 0 <= c <= MAX_CHECKSUM:
        raise ValueError("checksum out of range")
    shifted = c << 4                      # align to the 12-bit (len2*4) field
    encoded = shifted.to_bytes(2, "big")   # 2 bytes hold up to 16 bits
    return [(encoded[0] >> 4) & 0x0F,
            encoded[0] & 0x0F,
            (encoded[1] >> 4) & 0x0F]


def test_custom_encoding_matches_rfc8391_for_this_parameter_set():
    """F1 framing (reviewer note 2.4). For w=16, len2=3 the custom three-hex
    decomposition and the RFC 8391 shifted encoding coincide for every legal
    c. The paper therefore characterises the defect as a zero-padded-buffer
    read, not as a deviation from the standard encoding."""
    for c in range(MAX_CHECKSUM + 1):
        assert encode_custom_checksum(c) == encode_rfc8391_checksum(c)
    # spot checks quoted in the paper
    for c, exp in [(0, (0, 0, 0)), (1, (0, 0, 1)), (16, (0, 1, 0)),
                   (256, (1, 0, 0)), (960, (3, 12, 0))]:
        assert encode_custom_checksum(c) == list(exp)


def test_checksum_boundaries():
    """Independent boundary checks on both encoders (reviewer template 1.2)."""
    for c in [0, 1, 15, 16, 255, 256, 959, 960]:
        cd = encode_custom_checksum(c)
        rd = encode_rfc8391_checksum(c)
        # each is three base-16 digits
        assert len(cd) == LEN2 and len(rd) == LEN2
        assert all(0 <= d < W for d in cd + rd)
        # the three digits reconstruct c
        decoded = (cd[0] << 8) | (cd[1] << 4) | cd[2]
        assert decoded == c, (c, cd, decoded)


def test_checksum_out_of_range_rejected():
    for c in [-1, 961, 1000, 5000]:
        with pytest.raises(ValueError):
            encode_custom_checksum(c)
        with pytest.raises(ValueError):
            encode_rfc8391_checksum(c)
