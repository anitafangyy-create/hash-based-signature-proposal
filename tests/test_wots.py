"""
tests/test_wots.py — WOTS+ round-trip, tamper rejection, and the F1 secret-leak
reproduction (P0-1 / F1).

F1 (checksum defect) — precise statement:
* With the ORIGINAL (defective) implementation the checksum digits are always
  ``[0, 0, 0]``; the signer therefore emits the RAW chain secrets at the three
  checksum positions (indices LEN1..LEN1+LEN2-1). A single observed signature
  leaks those three secrets in cleartext. This is a secret-leakage weakness of
  a one-time signature, NOT a universal forgery capability.
* With the FIXED implementation the checksum digits vary with the message and
  the signature at those positions is ``chain(sk, 0, digit)`` (not the raw
  secret), so the three secrets are no longer leaked.
"""

import importlib.machinery
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import wots as prod

ORIG_PATH = os.path.join(ROOT, "artifact", "original", "wots.py.orig")


def _load_original_wots():
    # NOTE: the deferred .orig file uses @dataclass; under Python 3.14.3 the
    # dataclass machinery resolves cls.__module__ against sys.modules, so the
    # module MUST be registered there before exec_module or it raises
    # AttributeError: 'NoneType' object has no attribute '__dict__'.
    loader = importlib.machinery.SourceFileLoader("wots_orig", ORIG_PATH)
    spec = importlib.util.spec_from_loader("wots_orig", loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    loader.exec_module(mod)
    return mod


def test_wots_roundtrip_and_tamper():
    kp = prod.WOTSKeyPair.generate()
    msg = b"WOTS+ round-trip"
    sig = kp.sign(msg)
    assert prod.WOTSKeyPair.verify(msg, sig, kp.pk)
    bad = list(sig)
    bad[0] = os.urandom(prod.N)
    assert not prod.WOTSKeyPair.verify(msg, bad, kp.pk)
    assert not prod.WOTSKeyPair.verify(b"wrong", sig, kp.pk)
    assert not prod.WOTSKeyPair.verify(msg, sig[:10], kp.pk)   # malformed


def test_fixed_secret_protected():
    """FIXED code: the signature at checksum positions is NOT the raw secret."""
    kp = prod.WOTSKeyPair.generate()
    msg = b"fixed implementation message"
    sig = kp.sign(msg)
    for i in range(prod.LEN1, prod.LEN):
        assert sig[i] != kp.sk[i], f"checksum secret leaked at {i}"


def test_original_checksum_constant_and_secret_leaked():
    """ORIGINAL (defective) code: checksum digits constant [0,0,0]; the three
    checksum secrets are emitted in cleartext by every signature."""
    orig = _load_original_wots()
    kp = orig.WOTSKeyPair.generate()

    # (a) checksum digits independent of the message -> always [0,0,0]
    #     NOTE: the ORIGINAL defective code inlines the checksum as
    #     base_w(checksum.to_bytes(N, "big"), LEN2); it has no wots_checksum()
    #     helper. We reproduce exactly that logic here.
    msgs = [b"m1", b"m2", b"a longer message for variety", os.urandom(40)]
    observed = set()
    for m in msgs:
        digest = orig.H_message(m)
        md = orig.base_w(digest, orig.LEN1)
        c = sum(orig.W - 1 - d for d in md)
        observed.add(tuple(orig.base_w(c.to_bytes(orig.N, "big"), orig.LEN2)))
    assert observed == {(0, 0, 0)}, f"expected constant [0,0,0], got {observed}"

    # (b) secret leakage: signature at checksum positions equals the raw secret
    sig = kp.sign(b"leak check")
    for i in range(orig.LEN1, orig.LEN):
        assert sig[i] == kp.sk[i], f"expected raw secret at {i} in defective code"

    # (c) a defective signature is accepted by the defective verifier
    assert orig.WOTSKeyPair.verify(b"leak check", sig, kp.pk)
