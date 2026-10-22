"""End-to-end F1 regression tests: the defect must be observable at the
signature level, not only at the encoder level.

The point of this file is the asymmetry in rows A/B: a buggy signature is
accepted by the buggy verifier but REJECTED by the independent verifier. If
both accepted, the "fix" would be unverifiable; if both rejected, the round-trip
claim in the paper would be wrong.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))

import pytest  # noqa: E402

from wots import WOTSKeyPair, LEN1, LEN2  # noqa: E402
from experiment_checksum_forgery import (  # noqa: E402
    sign_with, verify_with, independent_verify, buggy_checksum_digits,
)


def _key_and_msg(tag: str):
    return WOTSKeyPair.generate(), tag.encode()


def test_row_a_buggy_signature_passes_buggy_verifier():
    """A: shared wrong encoder -> round trip is green (the failure mode)."""
    for t in range(3):
        kp, msg = _key_and_msg(f"row-a-{t}")
        sig = sign_with(kp, msg, buggy=True)
        assert verify_with(msg, sig, kp.pk, buggy=True), \
            "buggy sign/verify round trip unexpectedly failed"


def test_row_b_buggy_signature_rejected_by_independent_verifier():
    """B: the independent verifier rejects it — proves the acceptance in row A
    came from sharing the error, not from correctness."""
    for t in range(3):
        kp, msg = _key_and_msg(f"row-b-{t}")
        sig = sign_with(kp, msg, buggy=True)
        assert not independent_verify(msg, sig, kp.pk), \
            "independent verifier accepted a buggy signature"


def test_row_c_fixed_signature_passes_independent_verifier():
    for t in range(3):
        kp, msg = _key_and_msg(f"row-c-{t}")
        sig = sign_with(kp, msg, buggy=False)
        assert independent_verify(msg, sig, kp.pk)


def test_row_d_fixed_signature_passes_production_and_rejects_tamper():
    kp, msg = _key_and_msg("row-d")
    sig = sign_with(kp, msg, buggy=False)
    assert WOTSKeyPair.verify(msg, sig, kp.pk)
    tampered = list(sig)
    tampered[5] = bytes([tampered[5][0] ^ 0x01]) + tampered[5][1:]
    assert not WOTSKeyPair.verify(msg, tampered, kp.pk)


def test_buggy_encoding_is_constant_zero():
    for c in range(0, 961, 37):
        assert buggy_checksum_digits(c) == [0, 0, 0]


def test_buggy_signature_exposes_raw_checksum_chain_secrets():
    """The defect's concrete damage: sk[64..66] is transmitted verbatim."""
    for t in range(3):
        kp, msg = _key_and_msg(f"leak-{t}")
        sig = sign_with(kp, msg, buggy=True)
        for j in range(LEN2):
            assert sig[LEN1 + j] == kp.sk[LEN1 + j], \
                "buggy signature did not expose the raw checksum-chain secret"


def test_fixed_signature_does_not_expose_raw_checksum_chain_secrets():
    for t in range(3):
        kp, msg = _key_and_msg(f"noleak-{t}")
        sig = sign_with(kp, msg, buggy=False)
        for j in range(LEN2):
            assert sig[LEN1 + j] != kp.sk[LEN1 + j], \
                "fixed signature exposed a raw checksum-chain secret"
