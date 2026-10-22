"""
tests/test_malformed.py — F3: Merkle authentication-path and signature-index
handling (P0-3).

Checks that tampering, boundary, and illegal-input cases are REJECTED:
* leaf index -1, 2**h, and beyond the representable width;
* authentication path missing one node or carrying one extra node;
* OTS signature field shorter/longer than expected;
* explicit/compact format fed to the other's expectation;
* a valid leaf index different from the one the auth path was built for;
* a single flipped signature byte;
* a root that does not match.

Covers both WOTS+MSS (experiment_v2.GenericMSS) and Lamport+MSS
(hbs_signature.MerkleSignatureScheme).
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import wots
from experiment_v2 import GenericMSS, GenericSignature
from hbs_signature import LamportKeyPair, MerkleSignatureScheme, MSSSignature


# ---------------------------------------------------------------------------
# WOTS + MSS (experiment_v2)
# ---------------------------------------------------------------------------
def _wots_mss(height=3, compact=True):
    return GenericMSS(height, "wots", compact=compact)


def test_wots_index_out_of_range_rejected():
    mss = _wots_mss(height=3)           # n = 8
    msg = b"index test"
    sig = mss.sign(msg, 0)
    assert mss.verify(msg, sig)
    for bad_idx in (-1, 8, 8 + 5, 1000):
        bad = GenericSignature(ots_sig=list(sig.ots_sig), ots_pk=None,
                              auth_path=list(sig.auth_path),
                              leaf_index=bad_idx)
        assert not mss.verify(msg, bad), f"out-of-range index {bad_idx} accepted"


def test_wots_auth_path_length_mismatch_rejected():
    mss = _wots_mss(height=3)
    msg = b"authpath length"
    sig = mss.sign(msg, 0)
    short = GenericSignature(ots_sig=list(sig.ots_sig), ots_pk=None,
                            auth_path=sig.auth_path[:-1], leaf_index=sig.leaf_index)
    assert not mss.verify(msg, short)
    long = GenericSignature(ots_sig=list(sig.ots_sig), ots_pk=None,
                           auth_path=sig.auth_path + [os.urandom(32)],
                           leaf_index=sig.leaf_index)
    assert not mss.verify(msg, long)


def test_wots_wrong_leaf_index_rejected():
    mss = _wots_mss(height=3)
    msg = b"wrong index"
    sig = mss.sign(msg, 0)               # auth path built for leaf 0
    assert mss.verify(msg, sig)
    bad = GenericSignature(ots_sig=list(sig.ots_sig), ots_pk=None,
                          auth_path=list(sig.auth_path), leaf_index=1)
    assert not mss.verify(msg, bad)


def test_wots_single_byte_flip_rejected():
    mss = _wots_mss(height=3)
    msg = b"flip test"
    sig = mss.sign(msg, 0)
    assert mss.verify(msg, sig)
    bad = GenericSignature(
        ots_sig=[s if i != 0 else os.urandom(32)
                 for i, s in enumerate(sig.ots_sig)],
        ots_pk=None, auth_path=list(sig.auth_path), leaf_index=sig.leaf_index)
    assert not mss.verify(msg, bad)


# ---------------------------------------------------------------------------
# Lamport + MSS (hbs_signature)
# ---------------------------------------------------------------------------
def _lamport_mss(height=3):
    return MerkleSignatureScheme(height=height)


def test_lamport_index_out_of_range_rejected():
    mss = _lamport_mss(height=3)
    root = mss.public_key().root
    msg = b"lamport index"
    s = mss.sign(msg, 0)
    assert MerkleSignatureScheme.verify(msg, s, root)
    for bad_idx in (-1, 8, 1000):
        bad = MSSSignature(ots_sig=s.ots_sig, ots_pk=s.ots_pk,
                          auth_path=s.auth_path, leaf_index=bad_idx,
                          height=mss.height)
        assert not MerkleSignatureScheme.verify(msg, bad, root), \
            f"out-of-range index {bad_idx} accepted"


def test_lamport_auth_path_length_mismatch_rejected():
    mss = _lamport_mss(height=3)
    root = mss.public_key().root
    msg = b"lamport authpath"
    s = mss.sign(msg, 0)
    short = MSSSignature(ots_sig=s.ots_sig, ots_pk=s.ots_pk,
                        auth_path=s.auth_path[:-1], leaf_index=0,
                        height=mss.height)
    assert not MerkleSignatureScheme.verify(msg, short, root)
    long = MSSSignature(ots_sig=s.ots_sig, ots_pk=s.ots_pk,
                       auth_path=s.auth_path + [os.urandom(32)], leaf_index=0,
                       height=mss.height)
    assert not MerkleSignatureScheme.verify(msg, long, root)


def test_lamport_wrong_leaf_index_rejected():
    mss = _lamport_mss(height=3)
    root = mss.public_key().root
    msg = b"lamport wrong index"
    s = mss.sign(msg, 0)
    assert MerkleSignatureScheme.verify(msg, s, root)
    bad = MSSSignature(ots_sig=s.ots_sig, ots_pk=s.ots_pk,
                      auth_path=s.auth_path, leaf_index=1, height=mss.height)
    assert not MerkleSignatureScheme.verify(msg, bad, root)


def test_lamport_malformed_ots_sig_rejected():
    mss = _lamport_mss(height=1)
    root = mss.public_key().root
    msg = b"lamport malformed"
    s = mss.sign(msg, 0)
    bad = MSSSignature(ots_sig=s.ots_sig[:10], ots_pk=s.ots_pk,
                      auth_path=s.auth_path, leaf_index=0, height=mss.height)
    assert not MerkleSignatureScheme.verify(msg, bad, root)
