#!/usr/bin/env python3
"""Exhaustive differential audit of the WOTS+ checksum encoding against
RFC 8391 (XMSS/WOTS+), written as an *independent* reference encoder.

Reviewer requirement (external review, 2026-10-22, P0-1): the paper's F1
claim that the fixed checksum encoding is equivalent to RFC 8391 / FIPS 205
must not rest on self-tests alone.  This script therefore:

  1. Implements the checksum encoding *directly from the RFC*, without
     importing ``wots.py`` for the encoding path:
       - RFC 8391 Algorithm 1 (base_w, Section 2.6);
       - RFC 8391 Algorithm 5 (WOTS_sign, Section 3.1.5), checksum part:
         csum = sum_{i=0}^{len1-1} (w - 1 - M_i)
         csum = csum << (8 - ((len2 * lg(w)) % 8))          # left-align
         len2_bytes = ceil(len2 * lg(w) / 8)
         C = base_w(toByte(csum, len2_bytes), w, len2)
       with w = 16, len1 = 64, len2 = 3, lg(w) = 4, so that
       csum in [0, 960] and the shift is 8 - (12 % 8) = 4.
  2. Exhaustively compares the RFC reference digits against the
     implementation under audit (``wots.wots_checksum``) for every
     c in [0, 960], both (a) at the checksum-integer level and (b) through
     the full message->base_w->checksum->base_w pipeline.
  3. Reproduces the pre-fix defect: ``base_w(c.to_bytes(32, 'big'), 3)``
     returns the constant [0, 0, 0] for every c in [0, 960] (the original
     bug, frozen in artifact/original/wots.py.orig).
  4. Writes machine-readable evidence to results/checksum_rfc_audit.json.

The reference encoder and the implementation use structurally different
paths (RFC left-align shift + big-endian 2-byte pack + bit-extraction vs.
integer base-16 decomposition), so an identical shared algorithmic
assumption cannot explain agreement.

Run:  python experiments/audit_checksum_rfc.py
"""
from __future__ import annotations

import datetime
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---- RFC 8391 parameters (Section 5 tables; w=16 for all sets) ----
W = 16
LG_W = 4
N = 32
LEN1 = (8 * N) // LG_W          # 64
LEN2 = 3                        # floor(log_w(len1*(w-1))) + 1 = 3
LEN = LEN1 + LEN2               # 67
CSUM_MAX = LEN1 * (W - 1)       # 960
SHIFT = 8 - ((LEN2 * LG_W) % 8)  # 8 - (12 % 8) = 4
LEN2_BYTES = (LEN2 * LG_W + 7) // 8  # 2


def rfc_base_w(x: bytes, w: int, out_len: int) -> list[int]:
    """RFC 8391 Algorithm 1 (Section 2.6), verbatim."""
    basew: list[int] = []
    inp = 0
    bits = 0
    total = 0
    for _ in range(out_len):
        if bits == 0:
            total = x[inp]
            inp += 1
            bits += 8
        bits -= LG_W
        basew.append((total >> bits) & (w - 1))
    return basew


def rfc_checksum_digits_from_csum(csum: int) -> list[int]:
    """RFC 8391 Algorithm 5, checksum part, at the checksum-integer level."""
    assert 0 <= csum <= CSUM_MAX, csum
    csum = csum << SHIFT
    return rfc_base_w(csum.to_bytes(LEN2_BYTES, "big"), W, LEN2)


def rfc_message_digits(msg: bytes) -> list[int]:
    """RFC 8391 Algorithm 5 step 1: base_w(M, w, len1)."""
    assert len(msg) == N
    return rfc_base_w(msg, W, LEN1)


def rfc_full_checksum_digits(msg_digits: list[int]) -> list[int]:
    """RFC 8391 Algorithm 5 steps 2-4: checksum over message digits."""
    assert len(msg_digits) == LEN1
    csum = sum(W - 1 - d for d in msg_digits)
    return rfc_checksum_digits_from_csum(csum)


def reference_pipeline(msg: bytes) -> list[int]:
    """Complete RFC 8391 base-w message || checksum representation."""
    md = rfc_message_digits(msg)
    return md + rfc_full_checksum_digits(md)


# ---- implementation under audit ----
def impl_checksum_digits(csum: int) -> list[int]:
    from wots import wots_checksum  # noqa: PLC0415  (comparison target only)
    return wots_checksum(csum)


def defective_original(csum: int) -> list[int]:
    """Pre-fix bug, frozen in artifact/original/wots.py.orig:
    base_w(c.to_bytes(32, 'big'), LEN2)."""
    return rfc_base_w(csum.to_bytes(32, "big"), W, LEN2)


def greedy_msg_digits_for_csum(csum: int) -> list[int]:
    """Any len1 digits with sum(W-1-d_i) == csum (i.e. sum(d_i) == 960-csum)."""
    remaining = CSUM_MAX - csum
    digits: list[int] = []
    for _ in range(LEN1):
        take = min(15, remaining)
        digits.append(take)
        remaining -= take
    assert remaining == 0 and len(digits) == LEN1
    return digits


def main() -> None:
    results = {
        "title": "WOTS+ checksum encoding: exhaustive differential audit "
                 "vs. RFC 8391",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "method": {
            "reference": "RFC 8391 (XMSS) Section 2.6 Algorithm 1 (base_w) "
                          "and Section 3.1.5 Algorithm 5 (WOTS_sign), "
                          "implemented independently in this script; "
                          "PQClean wots.c (sphincs-sha2-128s-simple/clean) "
                          "uses the identical path: "
                          "csum << ((8 - ((WOTS_LEN2*WOTS_LOGW)%8))%8); "
                          "ull_to_bytes(2); base_w(...,WOTS_LEN2,...)",
            "parameters": {"w": W, "lg_w": LG_W, "n": N, "len1": LEN1,
                           "len2": LEN2, "len": LEN, "csum_max": CSUM_MAX,
                           "shift": SHIFT, "len2_bytes": LEN2_BYTES},
            "implementation_under_audit": "wots.wots_checksum "
                                           "(integer base-16 decomposition)",
        },
        "boundary_cases": [],
        "exhaustive": {"c_start": 0, "c_end": CSUM_MAX, "mismatches": []},
        "defective_original": {
            "behavior": "base_w(c.to_bytes(32,'big'),16,3) on c in [0,960]",
            "distinct_outputs": None,
        },
    }

    # 1. Boundary cases from the external review table.
    for c in [0, 1, 15, 16, 255, 256, 960]:
        ref = rfc_checksum_digits_from_csum(c)
        impl = impl_checksum_digits(c)
        results["boundary_cases"].append({
            "c": c, "rfc8391": ref, "implementation": impl,
            "equal": ref == impl,
        })

    # 2. Exhaustive comparison, c in [0, 960], with per-value outputs saved.
    mism = []
    per_value: list[list] = []
    for c in range(0, CSUM_MAX + 1):
        ref_int = rfc_checksum_digits_from_csum(c)
        impl = impl_checksum_digits(c)
        # full-pipeline comparison: message digits with this checksum value
        msg_digits = greedy_msg_digits_for_csum(c)
        ref_pp = rfc_full_checksum_digits(msg_digits)
        per_value.append([c, ref_int, ref_pp, impl])
        if ref_int != impl or ref_pp != impl:
            mism.append({"c": c, "rfc_integer": ref_int,
                         "rfc_pipeline": ref_pp, "implementation": impl})
    results["exhaustive"]["checked"] = CSUM_MAX + 1
    results["exhaustive"]["mismatches"] = mism
    results["exhaustive"]["per_value"] = per_value

    # 3. Pre-fix defect reproduction.
    outs = {tuple(defective_original(c)) for c in range(0, CSUM_MAX + 1)}
    results["defective_original"]["distinct_outputs"] = \
        [list(o) for o in sorted(outs)]

    ok = (len(mism) == 0 and
          all(b["equal"] for b in results["boundary_cases"]) and
          results["defective_original"]["distinct_outputs"] == [[0, 0, 0]])
    results["verdict"] = ("EQUAL: implementation == RFC 8391 reference for "
                          "all c in [0,960]" if ok else "MISMATCH")

    out_path = ROOT / "results" / "checksum_rfc_audit.json"
    out_path.write_text(json.dumps(results, indent=2) + "\n")
    print("[written]", out_path)

    # human-readable summary
    print("boundary cases:")
    for b in results["boundary_cases"]:
        print(f"  c={b['c']:>3}  rfc8391={b['rfc8391']}  "
              f"implementation={b['implementation']}  equal={b['equal']}")
    print("exhaustive: %d values checked, %d mismatches"
          % (results["exhaustive"]["checked"],
             len(results["exhaustive"]["mismatches"])))
    print("defective original distinct outputs:",
          results["defective_original"]["distinct_outputs"])
    print("verdict:", results["verdict"])
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
