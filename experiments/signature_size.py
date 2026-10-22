"""
signature_size.py — explicit size accounting for F2.

Keeps payload size, serialized size, public-key size, and state/storage size
as SEPARATE quantities, and checks the accounting against the real
serialization constants exported by the implementation rather than trusting
the arithmetic alone.

Run:  python experiments/signature_size.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wots import WOTSKeyPair, LEN1, LEN2, LEN, N, W   # noqa: E402


def calculate_signature_sizes(n: int = N, len1: int = LEN1, len2: int = LEN2,
                              height: int = 7, index_bytes: int = 1,
                              header_bytes: int = 0) -> dict:
    """Derive every size quantity from first principles.

    ``header_bytes`` defaults to 0 because the prototype has no framing
    header; pass a non-zero value only for a format that actually has one,
    and never mix configurations in the same table row.
    """
    if min(n, len1, len2, height, index_bytes, header_bytes) < 0:
        raise ValueError("size parameters must be non-negative")
    if n == 0 or len1 == 0:
        raise ValueError("n and len1 must be positive")

    elements = len1 + len2
    ots_sig = elements * n
    ots_pk = elements * n
    auth_path = height * n
    explicit_payload = ots_sig + ots_pk + auth_path
    compact_payload = ots_sig + auth_path
    return {
        "w": W,
        "n_bytes": n,
        "len1": len1,
        "len2": len2,
        "tree_height": height,
        "wots_elements": elements,
        "ots_signature_bytes": ots_sig,
        "ots_public_key_bytes": ots_pk,
        "authentication_path_bytes": auth_path,
        "explicit_payload_bytes": explicit_payload,
        "compact_payload_bytes": compact_payload,
        "explicit_serialized_bytes": explicit_payload + index_bytes + header_bytes,
        "compact_serialized_bytes": compact_payload + index_bytes + header_bytes,
        "public_key_bytes": n,                       # Merkle root only
        "tree_storage_bytes": (2 ** (height + 1) - 1) * n,   # all nodes
        "full_ots_key_storage_bytes": (2 ** height) * ots_pk,
    }


def cross_check_against_code(sizes: dict) -> dict:
    """Verify the accounting against the constants the code actually uses."""
    code_ots_sig = WOTSKeyPair.sig_bytes()
    code_ots_pk = WOTSKeyPair.pk_bytes()
    return {
        "code_ots_signature_bytes": code_ots_sig,
        "accounting_ots_signature_bytes": sizes["ots_signature_bytes"],
        "code_ots_public_key_bytes": code_ots_pk,
        "accounting_ots_public_key_bytes": sizes["ots_public_key_bytes"],
        "ots_signature_matches": code_ots_sig == sizes["ots_signature_bytes"],
        "ots_public_key_matches": code_ots_pk == sizes["ots_public_key_bytes"],
    }


def main() -> None:
    print("=== F2 size accounting (w=16, n=32, len1=64, len2=3) ===\n")
    table = {}
    for h in (1, 4, 7):
        s = calculate_signature_sizes(height=h)
        table[h] = s
        print(f"height h={h}  (capacity 2^{h} = {2**h} signatures)")
        print(f"  WOTS+ elements           : {s['wots_elements']}")
        print(f"  OTS signature            : {s['ots_signature_bytes']:,} B")
        print(f"  OTS public key           : {s['ots_public_key_bytes']:,} B")
        print(f"  authentication path      : {s['authentication_path_bytes']:,} B")
        print(f"  explicit payload         : {s['explicit_payload_bytes']:,} B")
        print(f"  compact payload          : {s['compact_payload_bytes']:,} B")
        print(f"  public key (Merkle root) : {s['public_key_bytes']} B")
        print(f"  full tree storage        : {s['tree_storage_bytes']:,} B")
        print(f"  full OTS key storage     : "
              f"{s['full_ots_key_storage_bytes']:,} B")
        print(f"  compaction saving        : "
              f"{s['explicit_payload_bytes'] - s['compact_payload_bytes']:,} B "
              f"({s['explicit_payload_bytes'] / s['compact_payload_bytes']:.2f}x)")
        print()

    chk = cross_check_against_code(table[7])
    print("cross-check against implementation constants:")
    for k, v in chk.items():
        print(f"  {k:<38} {v}")
    assert chk["ots_signature_matches"] and chk["ots_public_key_matches"], \
        "size accounting disagrees with the implementation"

    out = ROOT / "experiments" / "size_accounting.json"
    out.write_text(json.dumps({"by_height": table, "cross_check": chk},
                              indent=2))
    print(f"\n[written] {out}")


if __name__ == "__main__":
    main()
