"""
tests/test_compact.py — F2: compact vs explicit WOTS+MSS verification.

The production code (experiment_v2.GenericMSS) rebuilds the OTS public key from
the signature in compact mode (FIPS 205 pkFromSig). These tests verify:
* explicit and compact signatures both verify;
* compact rejects a modified message;
* compact rejects a modified authentication path;
* compact rejects truncated input.

(NB: the cryptographic logic in GenericMSS was already correct; the defect the
paper must fix is the *pseudocode*, which referenced ``sigma.otspk`` in compact
mode — a field that does not exist there. These tests pin the correct behaviour
so the pseudocode can be rewritten to match.)
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from experiment_v2 import GenericMSS, GenericSignature


def _mss(height=3, compact=False):
    return GenericMSS(height, "wots", compact=compact)


def test_explicit_and_compact_agree():
    mss = _mss(height=3)
    msg = b"compact-mode regression test"
    exp = mss.sign(msg, 0)                 # compact=False -> ots_pk present
    cmp = GenericSignature(ots_sig=exp.ots_sig, ots_pk=None,
                          auth_path=exp.auth_path, leaf_index=exp.leaf_index)
    assert mss.verify(msg, exp)
    assert mss.verify(msg, cmp)


def test_compact_rejects_modified_message():
    mss = _mss(compact=True)
    msg = b"original message"
    sig = mss.sign(msg, 0)
    assert mss.verify(msg, sig)
    assert not mss.verify(b"modified message", sig)


def test_compact_rejects_modified_auth_path():
    mss = _mss(compact=True)
    msg = b"authentication path test"
    sig = mss.sign(msg, 0)
    assert mss.verify(msg, sig)
    tampered = GenericSignature(
        ots_sig=list(sig.ots_sig),
        ots_pk=None,
        auth_path=[os.urandom(32) if i == 0 else p
                  for i, p in enumerate(sig.auth_path)],
        leaf_index=sig.leaf_index,
    )
    assert not mss.verify(msg, tampered)


def test_compact_rejects_truncated_input():
    mss = _mss(compact=True)
    msg = b"truncation test"
    sig = mss.sign(msg, 0)
    assert mss.verify(msg, sig)
    truncated = GenericSignature(
        ots_sig=sig.ots_sig[:-1], ots_pk=None,
        auth_path=sig.auth_path, leaf_index=sig.leaf_index)
    assert not mss.verify(msg, truncated)


def test_compact_round_trip_various_heights():
    for h in (1, 2, 4, 7):
        mss = _mss(height=h, compact=True)
        msg = b"h=%d" % h
        sig = mss.sign(msg, 0)
        assert mss.verify(msg, sig)
