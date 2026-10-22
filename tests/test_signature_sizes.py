"""
tests/test_signature_sizes.py — Experiment E4 size guard (reviewer §4.2).

Prevents table / graph / real-serialization drift for the on-the-wire
signature size. For the WOTS+ MSS prototype at h=7:

    S_explicit = 67*32 (ots sig) + 67*32 (ots pk) + 7*32 (auth) = 4512 B
    S_compact  = 67*32 (ots sig)             + 7*32 (auth) = 2368 B

The leaf index is ceil(h/8) bytes (1 B at h <= 8), so the full wire object
is 4513 / 2369 B. These are computed from the paper's definition; the test
also measures the ACTUAL serialized component lengths from a real signature
object so a change in the code cannot silently diverge from the paper.
"""

import os
import sys
import math

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import experiment_v2 as ev  # GenericMSS

N = 32
LENGTH = 67  # WOTS+ chains


def expected_signature_size(h, compact, include_index=True):
    ots_signature = LENGTH * N                       # 2144
    ots_public_key = 0 if compact else LENGTH * N    # 0 or 2144
    auth_path = h * N                                # 224 at h=7
    index_bytes = (h + 7) // 8 if include_index else 0  # 1 at h<=8
    return ots_signature + ots_public_key + auth_path + index_bytes


# --- analytic expectations (paper Table 2 / §3.3.2) -------------------------
def test_wots_size_expectations():
    assert expected_signature_size(7, False) == 4513
    assert expected_signature_size(7, True) == 2369
    assert expected_signature_size(7, False, include_index=False) == 4512
    assert expected_signature_size(7, True, include_index=False) == 2368


@pytest.mark.parametrize("height", [1, 2, 3, 4, 7])
@pytest.mark.parametrize("mode_name,compact", [("explicit", False),
                                               ("compact", True)])
def test_wots_core_size_matches_code(height, mode_name, compact):
    core = ev.GenericMSS.signature_bytes("wots", height, compact)
    assert core == expected_signature_size(height, compact, include_index=False)


# --- real serialized component lengths (catches code/table drift) -----------
def _real_core_size(sig, height):
    ots_sig = sum(len(x) for x in sig.ots_sig)
    ots_pk = 0 if sig.ots_pk is None else sum(len(x) for x in sig.ots_pk)
    auth = sum(len(x) for x in sig.auth_path)
    assert len(sig.ots_sig) == LENGTH, "unexpected OTS signature length"
    if sig.ots_pk is not None:
        assert len(sig.ots_pk) == LENGTH, "unexpected OTS public-key length"
    assert len(sig.auth_path) == height, "unexpected auth-path length"
    return ots_sig + ots_pk + auth


@pytest.mark.parametrize("height", [1, 3, 7])
@pytest.mark.parametrize("mode_name,compact", [("explicit", False),
                                               ("compact", True)])
def test_wots_real_components_match_table(height, mode_name, compact):
    s = ev.GenericMSS(height, "wots", compact)
    sig = s.sign(b"size-guard", 0)
    real = _real_core_size(sig, s.height)
    assert real == expected_signature_size(height, compact, include_index=False)
    # full wire object includes the ceil(h/8)-byte leaf index
    assert real + (height + 7) // 8 == \
        expected_signature_size(height, compact, include_index=True)


def test_lamport_core_size_matches_table():
    # Lamport MSS: 256*32 (sig) + 2*256*32 (pk[0]+pk[1]) + h*32 (auth)
    for height in [1, 7]:
        core = ev.GenericMSS.signature_bytes("lamport", height, False)
        expected = 256 * N + 2 * 256 * N + height * N
        assert core == expected
    assert ev.GenericMSS.signature_bytes("lamport", 7, False) == 24800
