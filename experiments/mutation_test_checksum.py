"""
experiments/mutation_test_checksum.py — mutation testing of the WOTS+
checksum encoding fix (P2).

Three single-point mutants of the *encoding* are injected into
``wots.wots_checksum`` (not into the reference, which stays independent):

  M1 wrong base        : divides by 15 instead of 16 (off-by-one base)
  M2 reversed digits   : most-significant / least-significant order flipped
  M3 zero-padded buffer: re-introduces the original defect
                         (base_w(c.to_bytes(32,'big'), 3) -> always [0,0,0])

For each mutant we ask two detectors:
  D1 exhaustive differential: number of mismatches vs the independent
     reference encoder over all c in [0, 960]  (a.k.a. audit_checksum_rfc)
  D2 test-suite detector   : does tests/test_checksum.py FAIL when the
     mutant is active? (run in-process via pytest)

Output: results/mutation_test_checksum.json — a table of mutant -> detected
by differential, detected by the test suite, mismatch counts.

Scope: mutation results characterize the *checksum encoder and its tests*;
they are not a claim about the whole test suite's general effectiveness.
"""

import hashlib
import json
import math
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import wots as prod

W = 16
LOG_W = 4
LEN1 = 64
LEN2 = 3
MAX_CHECKSUM = LEN1 * (W - 1)  # 960


# ---- independent reference encoder (no production internals) ----------------
def ref_checksum_to_digits(c: int) -> list:
    return [(c >> 8) & 0xF, (c >> 4) & 0xF, c & 0xF]


# ---- mutants ----------------------------------------------------------------
def m1_wrong_base(c: int) -> list:
    digits = []
    cc = c
    for _ in range(LEN2):
        digits.append(cc % (W - 1))     # wrong base: 15 instead of 16
        cc //= (W - 1)
    digits.reverse()
    return digits


def m2_reversed_digits(c: int) -> list:
    digits = []
    cc = c
    for _ in range(LEN2):
        digits.append(cc % W)
        cc //= W
    return digits                        # not reversed -> LSB-first order


def m3_zeropadded_buffer(c: int) -> list:
    # original defect: base_w over a 32-byte zero-padded buffer
    return prod.base_w(c.to_bytes(32, "big"), LEN2)   # always [0, 0, 0]


MUTANTS = {
    "M1_wrong_base": m1_wrong_base,
    "M2_reversed_digits": m2_reversed_digits,
    "M3_zeropadded_buffer": m3_zeropadded_buffer,
}


def differential_mismatches(impl) -> int:
    n = 0
    for c in range(0, MAX_CHECKSUM + 1):
        try:
            if impl(c) != ref_checksum_to_digits(c):
                n += 1
        except Exception:
            n += 1
    return n


def suite_detector() -> bool:
    """True if tests/test_checksum.py fails under the active mutant."""
    import pytest
    code = pytest.main(["tests/test_checksum.py", "-q", "--no-header",
                        "--tb=no", "-p", "no:cacheprovider"])
    return code != 0


def run() -> dict:
    real = prod.wots_checksum
    results = {}
    for name, mutant in MUTANTS.items():
        prod.wots_checksum = mutant
        mism = differential_mismatches(mutant)
        detected_by_suite = suite_detector()
        results[name] = {
            "differential_mismatches_961": mism,
            "detected_by_differential": mism > 0,
            "detected_by_test_suite": detected_by_suite,
        }
    prod.wots_checksum = real  # always restore

    # sanity: the real implementation must be clean for both detectors
    mism_real = differential_mismatches(real)
    suite_real = suite_detector()
    return {
        "summary": {
            "mutants": len(MUTANTS),
            "legal_checksums": MAX_CHECKSUM + 1,
            "real_impl_differential_mismatches": mism_real,
            "real_impl_suite_fails": suite_real,
        },
        "per_mutant": results,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


if __name__ == "__main__":
    out = run()
    dst = os.path.join(ROOT, "results", "mutation_test_checksum.json")
    with open(dst, "w") as f:
        json.dump(out, f, indent=2)
    s = out["summary"]
    print(f"real impl: differential mismatches={s['real_impl_differential_mismatches']}, "
          f"suite fails={s['real_impl_suite_fails']}")
    for name, r in out["per_mutant"].items():
        print(f"{name}: diff_mismatches={r['differential_mismatches_961']} "
              f"detected_diff={r['detected_by_differential']} "
              f"detected_suite={r['detected_by_test_suite']}")
