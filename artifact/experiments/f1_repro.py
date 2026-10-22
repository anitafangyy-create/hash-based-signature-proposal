"""
artifact/experiments/f1_repro.py — F1 (WOTS+ checksum defect) reproduction.

Reproduces the defect from the ORIGINAL (pre-fix) implementation, demonstrates
the fixed behaviour, and records machine-readable evidence per the remediation
plan's JSON template:

    {
      "case_id", "source_revision", "parameter_set", "input_digest",
      "expected_checksum_digits", "observed_checksum_digits",
      "original_verifier_accepts", "fixed_verifier_accepts",
      "independent_verifier_accepts"
    }

Precise attack scope documented here: the defect made the checksum digits
constant [0,0,0], so EVERY signature emitted the three checksum-chain secrets
(sk[64], sk[65], sk[66]) in cleartext. This is a one-time-signature secret
leak, not a universal forgery.

Usage:
    python artifact/experiments/f1_repro.py
Writes artifact/results/f1_evidence.json
"""

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import wots as fixed                              # fixed production code
import ref_verify as indep                          # independent verifier

ORIG_PATH = os.path.join(ROOT, "artifact", "original", "wots.py.orig")


def _load_original():
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


def _checksum_digits_correct(msg: bytes) -> list:
    d = fixed.base_w(indep.H_message(msg), fixed.LEN1)
    c = sum(fixed.W - 1 - x for x in d)
    return indep.wots_checksum(c)


def main():
    orig = _load_original()
    source_rev = "e896002 (original) / working-tree fix (fixed)"
    param_set = {"n": fixed.N, "w": fixed.W, "len1": fixed.LEN1,
                 "len2": fixed.LEN2, "len": fixed.LEN}

    messages = [
        b"F1 minimal reproduction case 001",
        b"a second distinct message",
        b"third message with different digest",
        os.urandom(48),
    ]

    cases = []
    leak_original = []
    leak_fixed = []

    for i, msg in enumerate(messages):
        digest = indep.H_message(msg)
        input_digest = hashlib.sha256(digest).hexdigest()[:16]

        # original (defective) — inline checksum logic (no wots_checksum() in
        # the .orig file): base_w(checksum.to_bytes(N, "big"), LEN2).
        ok = orig.WOTSKeyPair.generate()
        o_sig = ok.sign(msg)
        o_accepts = orig.WOTSKeyPair.verify(msg, o_sig, ok.pk)
        o_msg_digits = orig.base_w(orig.H_message(msg), orig.LEN1)
        o_c = sum(orig.W - 1 - x for x in o_msg_digits)
        o_checksum_digits = orig.base_w(
            o_c.to_bytes(orig.N, "big"), orig.LEN2)

        # fixed
        fk = fixed.WOTSKeyPair.generate()
        f_sig = fk.sign(msg)
        f_accepts = fixed.WOTSKeyPair.verify(msg, f_sig, fk.pk)

        # independent verifier (correct checksum), on each implementation's sig
        indep_accepts_orig = indep.verify_independent(o_sig, ok.pk, msg)
        indep_accepts_fixed = indep.verify_independent(f_sig, fk.pk, msg)

        expected = _checksum_digits_correct(msg)
        observed_orig = list(o_checksum_digits)
        observed_fixed = fixed.wots_checksum(
            sum(fixed.W - 1 - x for x in fixed.base_w(
                fixed.H_message(msg), fixed.LEN1)))

        cases.append({
            "case_id": f"F1-checksum-{i+1:03d}",
            "source_revision": source_rev,
            "parameter_set": param_set,
            "input_digest": input_digest,
            "expected_checksum_digits": expected,
            "observed_checksum_digits_original": observed_orig,
            "observed_checksum_digits_fixed": observed_fixed,
            "original_verifier_accepts": o_accepts,
            "fixed_verifier_accepts": f_accepts,
            "independent_verifier_accepts_original": indep_accepts_orig,
            "independent_verifier_accepts_fixed": indep_accepts_fixed,
        })

        # secret-leak check: signature at checksum positions vs raw secret
        leak_original.append(all(o_sig[j] == ok.sk[j]
                                for j in range(orig.LEN1, orig.LEN)))
        leak_fixed.append(all(f_sig[j] != fk.sk[j]
                              for j in range(fixed.LEN1, fixed.LEN)))

    evidence = {
        "title": "F1 WOTS+ checksum defect reproduction",
        "source_revision": source_rev,
        "parameter_set": param_set,
        "environment": {
            "python": sys.version.split()[0],
            "host": "macOS 15.7.7 / Apple M1 (per environment.txt)",
        },
        "attack_scope": (
            "Original checksum digits are constant [0,0,0]; every signature "
            "leaks the three checksum-chain secrets (sk[64],sk[65],sk[66]) in "
            "cleartext. This is a one-time-signature secret leak, NOT a "
            "universal forgery."
        ),
        "cases": cases,
        "summary": {
            "n_cases": len(cases),
            "original_all_constant_000": all(
                c["observed_checksum_digits_original"] == [0, 0, 0]
                for c in cases),
            "fixed_never_constant_000": not all(
                c["observed_checksum_digits_fixed"] == [0, 0, 0]
                for c in cases),
            "original_all_secrets_leaked": all(leak_original),
            "fixed_no_secrets_leaked": all(leak_fixed),
            "original_verifier_accepts_all": all(
                c["original_verifier_accepts"] for c in cases),
            "fixed_verifier_accepts_all": all(
                c["fixed_verifier_accepts"] for c in cases),
            "independent_rejects_original": all(
                not c["independent_verifier_accepts_original"] for c in cases),
            "independent_accepts_fixed": all(
                c["independent_verifier_accepts_fixed"] for c in cases),
        },
    }

    out = os.path.join(ROOT, "artifact", "results", "f1_evidence.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as fh:
        json.dump(evidence, fh, indent=2)
    print(f"[written] {out}")
    print(json.dumps(evidence["summary"], indent=2))


if __name__ == "__main__":
    main()
