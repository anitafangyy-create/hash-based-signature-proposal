"""
tests/test_properties.py — property-style tests for the WOTS+ checksum
encoding (P2: property and mutation testing).

Uses only the stdlib (no Hypothesis dependency). Properties pinned:
  * for every legal checksum c in [0, 960]: output length == 3, every digit
    in [0, 15], and decoding the digits returns exactly c;
  * production encoding agrees with the independent reference encoder for
    ALL 961 legal values (differential property, complements the exhaustive
    RFC 8391 audit in experiments/audit_checksum_rfc.py);
  * out-of-range / non-integer inputs raise ValueError (no silent truncation);
  * base_w over a 32-byte digest yields exactly 64 digits in [0, 15]
    (message-digit property, no padding leftovers).

Scope note: these properties pin the tested implementation's behaviour for
this parameter set (n=32, w=16, len1=64, len2=3); they are not a proof for
arbitrary parameters.
"""

import math
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest
import wots as prod

W = 16
LOG_W = 4
LEN1 = 64
LEN2 = 3
MAX_CHECKSUM = LEN1 * (W - 1)  # 960

# Independent reference (mirrors the RFC 8391 integer-decomposition path;
# does NOT import production internals).
def ref_checksum_to_digits(c: int) -> list:
    if not isinstance(c, int) or not 0 <= c <= MAX_CHECKSUM:
        raise ValueError("checksum out of range")
    return [(c >> 8) & 0xF, (c >> 4) & 0xF, c & 0xF]


def decode(digits) -> int:
    return (digits[0] << 8) | (digits[1] << 4) | digits[2]


# ---- exhaustive + random property checks ------------------------------------
def test_all_legal_checksums_roundtrip():
    for c in range(0, MAX_CHECKSUM + 1):
        d = prod.wots_checksum(c)
        assert len(d) == LEN2, (c, d)
        assert all(0 <= x < W for x in d), (c, d)
        assert decode(d) == c, (c, d)


def test_random_checksums_roundtrip():
    rng = random.Random(20261022)  # fixed seed; deterministic
    for _ in range(500):
        c = rng.randint(0, MAX_CHECKSUM)
        d = prod.wots_checksum(c)
        assert len(d) == LEN2 and decode(d) == c, (c, d)


def test_production_equals_reference_for_all_inputs():
    """Differential property: 961/961 agreement with the independent
    reference encoder (same statement as the RFC 8391 audit)."""
    mismatches = []
    for c in range(0, MAX_CHECKSUM + 1):
        if prod.wots_checksum(c) != ref_checksum_to_digits(c):
            mismatches.append((c, prod.wots_checksum(c), ref_checksum_to_digits(c)))
    assert mismatches == [], f"{len(mismatches)} mismatches, first: {mismatches[:3]}"


def test_out_of_range_rejected_no_silent_truncation():
    # wots_checksum raises ValueError for both out-of-range integers and
    # non-integer inputs (single guard: isinstance check + range check).
    for bad in [-1, MAX_CHECKSUM + 1, 2 ** 16, 2 ** 32 - 1]:
        with pytest.raises(ValueError):
            prod.wots_checksum(bad)
    for bad in ["960", None, 1.0]:  # type: ignore[arg-type]
        with pytest.raises((ValueError, TypeError)):
            prod.wots_checksum(bad)  # type: ignore[arg-type]


def test_base_w_message_digits_property():
    # a 32-byte digest maps to exactly 64 digits, no padding, no leftovers
    digest = bytes(range(32))
    digits = prod.base_w(digest, LEN1)
    assert len(digits) == LEN1
    assert all(0 <= d < W for d in digits)
    # reconstruction: 4 bits per digit, big-endian, ms-nibble first
    bits = "".join(f"{d:04b}" for d in digits)
    assert int(bits, 2).to_bytes(32, "big") == digest
