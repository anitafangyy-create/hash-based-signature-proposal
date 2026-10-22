"""
tests/test_ref_verify.py — verifies the independence criteria for the
independent reference verifier (reviewer note 2.3).

ref_verify.py must:
  1. NOT import the production implementation's base_w / wots_checksum /
     chain / pkFromSig.
  2. independently implement message parsing, checksum encoding, chain iteration.
  3. be driven by serialized bytes (the KAT), not by production objects.
  4. use fixed test vectors with explicit expected results.
  5. run BOTH valid and negative cases (not just "both accept True").
"""

import os
import sys
import json
import types
import importlib.util
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Load ref_verify.py by path so we control whether the production module is
# imported. It must NOT import 'wots' on its own.
_REF_PATH = os.path.join(ROOT, "ref_verify.py")
_spec = importlib.util.spec_from_file_location("ref_verify", _REF_PATH)
ref = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ref)


def test_ref_verify_is_independent_of_production():
    """Criterion 1: ref_verify re-implements primitives, does not import wots."""
    imported_modules = [v.__name__ for v in ref.__dict__.values()
                       if isinstance(v, types.ModuleType)]
    assert "wots" not in imported_modules, \
        "ref_verify must not import the production wots module"
    for name in ("H", "H_message", "chain", "base_w",
                 "wots_checksum", "digits_of", "pk_from_sig",
                 "verify_independent"):
        assert hasattr(ref, name), f"ref_verify missing independent {name}"


def _load_kat():
    kat = json.loads(
        (ROOT and open(os.path.join(ROOT, "kat_wots.json"))).read())
    sk = [bytes.fromhex(x) for x in kat["sk"]]
    pk = [bytes.fromhex(x) for x in kat["pk"]]
    sig = [bytes.fromhex(x) for x in kat["sig"]]
    msg = bytes.fromhex(kat["message_hex"])
    return sk, pk, sig, msg


def test_kat_valid_signature_accepted():
    """Criterion 4/5: the fixed-vector valid signature is accepted."""
    _, pk, sig, msg = _load_kat()
    assert ref.verify_independent(sig, pk, msg)


def test_kat_wrong_message_rejected():
    """Criterion 5: negative case — a different message is rejected."""
    _, pk, sig, msg = _load_kat()
    assert not ref.verify_independent(sig, pk, b"not-the-signed-message")


def test_kat_tampered_chain_value_rejected():
    """Criterion 5: negative case — flipping a signature chain value is rejected."""
    _, pk, sig, msg = _load_kat()
    bad = list(sig)
    bad[0] = bytes([bad[0][0] ^ 1]) + bad[0][1:]
    assert not ref.verify_independent(bad, pk, msg)


def test_kat_wrong_length_rejected():
    """Criterion 5: negative case — a truncated/extended signature is rejected."""
    _, pk, sig, msg = _load_kat()
    assert not ref.verify_independent(sig[:-1], pk, msg)
    assert not ref.verify_independent(sig + [pk[0]], pk, msg)


def test_ref_and_production_agree_on_valid_vector():
    """Both verifiers must agree on the valid KAT; this is a cross-check,
    not a shared-implementation check (ref does not import prod)."""
    import wots as prod
    _, pk, sig, msg = _load_kat()
    assert prod.WOTSKeyPair.verify(msg, sig, pk)
    assert ref.verify_independent(sig, pk, msg)
    # and they must disagree (both reject) on the tampered vector
    bad = list(sig)
    bad[0] = bytes([bad[0][0] ^ 1]) + bad[0][1:]
    assert not prod.WOTSKeyPair.verify(msg, bad, pk)
    assert not ref.verify_independent(bad, pk, msg)
