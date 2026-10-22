"""
tests/test_signature_properties.py — Experiment E1: functional, boundary, and
negative tests across message sizes, tree heights, and signature modes.

Covers (reviewer template, §3 "实验 E1"):
  * message lengths: 0, 1, 31, 32, 64, 256, 1024, 4096 bytes
  * contents: all-zero, all-0xff, incrementing, fixed-random
  * heights: h in {1, 2, 3, 4, 7}
  * modes: explicit (OTS pk transmitted) and compact (rebuilt from sig)
For every combination we check:
  1. a valid signature is accepted;
  2. a changed message is rejected;
  3. a single flipped chain value is rejected;
  4. a single flipped authentication-path node is rejected;
  5. a wrong / out-of-range leaf index is rejected;
  6. a truncated OTS signature is rejected (no unhandled exception).

Uses the real benchmark harness (experiment_v2.GenericMSS), which already
carries the F3 leaf-index / auth-path-length hardening.
"""

import os
import sys
import math
import dataclasses

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import experiment_v2 as ev  # GenericMSS, GenericSignature

# --- message corpus ---------------------------------------------------------
def _corpus():
    rng = __import__("random").Random(20261021)
    cases = []
    for length in [0, 1, 31, 32, 64, 256, 1024, 4096]:
        cases.append((b"\x00" * length, f"zeros-{length}"))
        cases.append((b"\xff" * length, f"ff-{length}"))
        cases.append((bytes((i % 256) for i in range(length)),
                     f"incr-{length}"))
        cases.append((rng.randbytes(length), f"rand-{length}"))
    return cases


MESSAGES = _corpus()
HEIGHTS = [1, 2, 3, 4, 7]
MODES = [("explicit", False), ("compact", True)]
KINDS = [("wots", "wots")]


def _flip_first_byte(buf: bytes) -> bytes:
    return bytes([buf[0] ^ 0xFF]) + buf[1:]


# Build one scheme per (kind, height, compact) and reuse it across messages —
# GenericMSS is the stateless benchmark harness and does not enforce one-time use.
def _scheme(kind, height, compact):
    return ev.GenericMSS(height, kind, compact)


# 1) valid sign/verify ------------------------------------------------------
@pytest.mark.parametrize("kind", [k for k, _ in KINDS])
@pytest.mark.parametrize("height", HEIGHTS)
@pytest.mark.parametrize("mode_name,compact", MODES)
def test_valid_signature(kind, height, mode_name, compact):
    s = _scheme(kind, height, compact)
    for msg, _ in MESSAGES:
        sig = s.sign(msg, 0)
        assert s.verify(msg, sig), f"valid sig rejected ({mode_name},h={height})"


# 2) changed message --------------------------------------------------------
@pytest.mark.parametrize("kind", [k for k, _ in KINDS])
@pytest.mark.parametrize("height", HEIGHTS)
@pytest.mark.parametrize("mode_name,compact", MODES)
def test_modified_message_rejected(kind, height, mode_name, compact):
    s = _scheme(kind, height, compact)
    for msg, _ in MESSAGES:
        sig = s.sign(msg, 0)
        assert not s.verify(msg + b"\x00", sig), \
            f"modified message accepted ({mode_name},h={height})"


# 3) flipped chain value ----------------------------------------------------
@pytest.mark.parametrize("kind", [k for k, _ in KINDS])
@pytest.mark.parametrize("height", HEIGHTS)
@pytest.mark.parametrize("mode_name,compact", MODES)
def test_tampered_chain_value_rejected(kind, height, mode_name, compact):
    s = _scheme(kind, height, compact)
    for msg, _ in MESSAGES:
        sig = s.sign(msg, 0)
        bad = dataclasses.replace(
            sig, ots_sig=[_flip_first_byte(sig.ots_sig[0])] + sig.ots_sig[1:])
        assert not s.verify(msg, bad), \
            f"tampered chain accepted ({mode_name},h={height})"


# 4) flipped auth-path node -------------------------------------------------
@pytest.mark.parametrize("kind", [k for k, _ in KINDS])
@pytest.mark.parametrize("height", HEIGHTS)
@pytest.mark.parametrize("mode_name,compact", MODES)
def test_tampered_auth_node_rejected(kind, height, mode_name, compact):
    s = _scheme(kind, height, compact)
    for msg, _ in MESSAGES:
        sig = s.sign(msg, 0)
        if not sig.auth_path:
            continue
        bad = dataclasses.replace(
            sig, auth_path=[_flip_first_byte(sig.auth_path[0])] + sig.auth_path[1:])
        assert not s.verify(msg, bad), \
            f"tampered auth node accepted ({mode_name},h={height})"


# 5) wrong / out-of-range leaf index ---------------------------------------
@pytest.mark.parametrize("kind", [k for k, _ in KINDS])
@pytest.mark.parametrize("height", HEIGHTS)
@pytest.mark.parametrize("mode_name,compact", MODES)
def test_wrong_leaf_index_rejected(kind, height, mode_name, compact):
    s = _scheme(kind, height, compact)
    msg = b"index-binding-probe"
    sig = s.sign(msg, 0)
    n = 2 ** height
    if n > 1:
        wrong = dataclasses.replace(sig, leaf_index=1)
        assert not s.verify(msg, wrong), \
            f"wrong leaf index accepted ({mode_name},h={height})"
    # out-of-range: -1 and n (== 2^h) must both be rejected
    assert not s.verify(msg, dataclasses.replace(sig, leaf_index=-1))
    assert not s.verify(msg, dataclasses.replace(sig, leaf_index=n))


# 6) truncated OTS signature ------------------------------------------------
@pytest.mark.parametrize("kind", [k for k, _ in KINDS])
@pytest.mark.parametrize("height", HEIGHTS)
@pytest.mark.parametrize("mode_name,compact", MODES)
def test_truncated_signature_rejected(kind, height, mode_name, compact):
    s = _scheme(kind, height, compact)
    msg = b"truncation-probe"
    sig = s.sign(msg, 0)
    short = dataclasses.replace(sig, ots_sig=sig.ots_sig[:-1])
    assert not s.verify(msg, short), \
        f"truncated OTS sig accepted ({mode_name},h={height})"
    # also reject a malformed auth path (wrong length)
    bad_auth = dataclasses.replace(sig, auth_path=sig.auth_path[:-1])
    assert not s.verify(msg, bad_auth), \
        f"short auth path accepted ({mode_name},h={height})"
