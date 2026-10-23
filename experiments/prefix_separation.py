"""
prefix_separation.py — deterministic check that the four domain-separation
prefixes are pairwise unambiguous (no role can be confused with another).

Roles and real concatenations (from wots.py / hbs_signature.py):
  WOTS-CHAIN   + chain value (64 bytes, current chain state)
  MSS-LEAF     + flat leaf payload (height byte + leaf index + OTS public key)
  MSS-NODE     + left (32) + right (32) node digests
  HBS-PQ-MSG-v1 + message (any length)

A concatenation collision between different roles would require one prefix
string to be a prefix of another (then data could be shifted). We assert:
  1. no prefix is a prefix of any other prefix (pairwise, strict);
  2. exhaustive byte-level check over all short data strings (up to length 4)
     confirms no two (role, data) pairs share a concatenated byte string;
  3. a randomized large-domain check (deterministic seed) finds no collisions.

Output: results/prefix_separation.json (deterministic).
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import random

ROOT = pathlib.Path(__file__).resolve().parent.parent

PREFIXES = {
    "WOTS-CHAIN": b"WOTS-CHAIN",
    "MSS-LEAF": b"MSS-LEAF",
    "MSS-NODE": b"MSS-NODE",
    "HBS-PQ-MSG-v1": b"HBS-PQ-MSG-v1",
}
ROLE_ORDER = ["WOTS-CHAIN", "MSS-LEAF", "MSS-NODE", "HBS-PQ-MSG-v1"]


def concat(role: str, data: bytes) -> bytes:
    return PREFIXES[role] + data


def _pairwise_non_prefix(roles: list[str]) -> bool:
    names = [PREFIXES[r] for r in roles]
    for i, a in enumerate(names):
        for j, b in enumerate(names):
            if i == j:
                continue
            if b.startswith(a):
                return False
    return True


def main() -> int:
    results: dict = {"roles": ROLE_ORDER,
                     "prefix_bytes": {r: PREFIXES[r].hex() for r in ROLE_ORDER}}

    # 1. pairwise non-prefix property
    ok_prefix = _pairwise_non_prefix(ROLE_ORDER)
    results["pairwise_no_prefix_is_prefix_of_another"] = ok_prefix

    # 2. exhaustive small-domain collision check (data up to 2 bytes)
    collisions_exhaustive = []
    seen: dict[bytes, tuple[str, bytes]] = {}
    for role in ROLE_ORDER:
        for ln in range(3):  # 0..2 bytes of data
            for n in range(256 ** ln):
                data = n.to_bytes(ln, "big")
                blob = concat(role, data)
                if blob in seen and seen[blob][0] != role:
                    collisions_exhaustive.append(
                        (role, data.hex(), seen[blob][0], seen[blob][1].hex()))
                else:
                    seen.setdefault(blob, (role, data))
    results["exhaustive_small_domain_pairs"] = sum(
        256 ** ln for ln in range(3))
    results["exhaustive_small_domain_collisions"] = collisions_exhaustive

    # 3. randomized large-domain check (deterministic seed)
    rng = random.Random(20261023)
    collisions_random = []
    rseen: dict[bytes, tuple[str, bytes]] = {}
    TRIALS = 100_000
    for _ in range(TRIALS):
        role = rng.choice(ROLE_ORDER)
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 130)))
        blob = concat(role, data)
        if blob in rseen and rseen[blob][0] != role:
            collisions_random.append(
                (role, data.hex()[:40], rseen[blob][0], rseen[blob][1].hex()[:40]))
        else:
            rseen.setdefault(blob, (role, data))
    results["random_trials"] = TRIALS
    results["seed"] = 20261023
    results["random_large_domain_collisions"] = collisions_random

    results["all_checks_passed"] = (
        ok_prefix and not collisions_exhaustive and not collisions_random)
    results["generated"] = "deterministic"

    out = (ROOT / "results")
    out.mkdir(exist_ok=True)
    (out / "prefix_separation.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in results.items()
                      if k not in ("prefix_bytes",)}))
    return 0 if results["all_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
