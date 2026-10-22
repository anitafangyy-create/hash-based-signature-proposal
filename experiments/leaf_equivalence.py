"""
experiments/leaf_equivalence.py — F2: exhaustive explicit-vs-compact
equivalence over ALL leaves of the h=7 WOTS+MSS configuration.

Tree height h=7 -> 128 leaves. For every leaf k in 0..127 we:
  * sign message m_k with the explicit-format MSS and re-serialize as
    compact (OTS public key omitted, rebuilt from the signature);
  * check the explicit signature verifies;
  * check the compact signature verifies;
  * check the OTS public key rebuilt from the signature (pkFromSig) equals
    the transmitted explicit public key;
  * check both formats reject a modified message;
  * check both formats reject a modified authentication path;
  * check both formats reject a truncated authentication path;
  * check both formats reject a truncated OTS signature;
  * check an out-of-range leaf index is rejected.

Output: results/leaf_equivalence.json (per-leaf rows + summary).

This is a full coverage of the 128-leaf parameter set, not a proof for every
possible tree height.
"""

import hashlib
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from experiment_v2 import GenericMSS, GenericSignature, _reconstruct_pk  # noqa: E402

HEIGHT = 7
N_LEAVES = 2 ** HEIGHT  # 128


def tamper_first_byte(x: bytes) -> bytes:
    return bytes([x[0] ^ 0xFF]) + x[1:]


def run() -> dict:
    mss = GenericMSS(HEIGHT, "wots", compact=False)
    rows = []
    failures = []

    def check(name: str, k: int, ok: bool):
        if not ok:
            failures.append({"leaf": k, "check": name})

    for k in range(N_LEAVES):
        msg = f"leaf-equivalence #{k}".encode()
        exp = mss.sign(msg, k)
        cmp = GenericSignature(ots_sig=exp.ots_sig, ots_pk=None,
                               auth_path=exp.auth_path, leaf_index=exp.leaf_index)

        check("explicit_verifies", k, mss.verify(msg, exp))
        check("compact_verifies", k, mss.verify(msg, cmp))
        rebuilt = _reconstruct_pk(exp.ots_sig, msg, "wots")
        check("pkfromsig_equals_explicit_pk", k, rebuilt == exp.ots_pk)

        bad_msg = b"tampered-" + msg
        check("explicit_rejects_bad_msg", k, not mss.verify(bad_msg, exp))
        check("compact_rejects_bad_msg", k, not mss.verify(bad_msg, cmp))

        bad_path = [tamper_first_byte(s) if i == 0 else s
                    for i, s in enumerate(exp.auth_path)]
        cmp_bad_path = GenericSignature(ots_sig=exp.ots_sig, ots_pk=None,
                                        auth_path=bad_path, leaf_index=exp.leaf_index)
        check("explicit_rejects_bad_path", k, not mss.verify(msg, GenericSignature(
            ots_sig=exp.ots_sig, ots_pk=exp.ots_pk, auth_path=bad_path,
            leaf_index=exp.leaf_index)))
        check("compact_rejects_bad_path", k, not mss.verify(msg, cmp_bad_path))

        truncated_path = exp.auth_path[:-1]
        check("explicit_rejects_truncated_path", k, not mss.verify(msg, GenericSignature(
            ots_sig=exp.ots_sig, ots_pk=exp.ots_pk, auth_path=truncated_path,
            leaf_index=exp.leaf_index)))
        check("compact_rejects_truncated_path", k, not mss.verify(msg, GenericSignature(
            ots_sig=exp.ots_sig, ots_pk=None, auth_path=truncated_path,
            leaf_index=exp.leaf_index)))

        truncated_ots = exp.ots_sig[:-1]
        check("explicit_rejects_truncated_ots", k, not mss.verify(msg, GenericSignature(
            ots_sig=truncated_ots, ots_pk=exp.ots_pk, auth_path=exp.auth_path,
            leaf_index=exp.leaf_index)))
        check("compact_rejects_truncated_ots", k, not mss.verify(msg, GenericSignature(
            ots_sig=truncated_ots, ots_pk=None, auth_path=exp.auth_path,
            leaf_index=exp.leaf_index)))

        check("out_of_range_index_rejected", k, not mss.verify(msg, GenericSignature(
            ots_sig=exp.ots_sig, ots_pk=exp.ots_pk, auth_path=exp.auth_path,
            leaf_index=N_LEAVES)))
        check("negative_index_rejected", k, not mss.verify(msg, GenericSignature(
            ots_sig=exp.ots_sig, ots_pk=exp.ots_pk, auth_path=exp.auth_path,
            leaf_index=-1)))

        def ots_sig_bytes(sig):
            return sum(len(x) for x in sig.ots_sig) if isinstance(sig.ots_sig, list) else len(sig.ots_sig)

        def ots_pk_bytes(pk):
            return sum(len(x) for x in pk) if isinstance(pk, list) else len(pk)

        rows.append({
            "leaf": k,
            "explicit_bytes": ots_sig_bytes(exp) + ots_pk_bytes(exp.ots_pk)
                              + sum(len(s) for s in exp.auth_path),
            "compact_bytes": ots_sig_bytes(exp) + sum(len(s) for s in exp.auth_path),
            "pkfromsig_matches": rebuilt == exp.ots_pk,
        })

    summary = {
        "height": HEIGHT,
        "leaves": N_LEAVES,
        "checks_per_leaf": 12,
        "total_checks": N_LEAVES * 12,
        "failures": failures,
        "passed": not failures,
        "explicit_core_bytes": rows[0]["explicit_bytes"],
        "compact_core_bytes": rows[0]["compact_bytes"],
        "reduction_bytes": rows[0]["explicit_bytes"] - rows[0]["compact_bytes"],
        "reduction_pct": round(100 * (1 - rows[0]["compact_bytes"] / rows[0]["explicit_bytes"]), 1),
        "generated": "deterministic",
    }
    return {"summary": summary, "per_leaf": rows}


if __name__ == "__main__":
    out = run()
    dst = os.path.join(ROOT, "results", "leaf_equivalence.json")
    with open(dst, "w") as f:
        json.dump(out, f, indent=2)
    s = out["summary"]
    print(f"leaves={s['leaves']} checks={s['total_checks']} "
          f"failures={len(s['failures'])} passed={s['passed']}")
    print(f"explicit={s['explicit_core_bytes']}B compact={s['compact_core_bytes']}B "
          f"reduction={s['reduction_bytes']}B ({s['reduction_pct']}%)")
