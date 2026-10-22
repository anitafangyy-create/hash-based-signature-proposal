"""
Comparative benchmark: Lamport-OBS-based MSS vs WOTS+-based MSS.

Builds a generic Merkle signature scheme where the OTS layer can be
swapped. Measures keygen / sign / verify latency and on-the-wire sizes
for both choices across tree heights.
"""

from __future__ import annotations

import time
import gc
import statistics
import dataclasses
import json
from pathlib import Path

import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hbs_signature import H, H_message, LamportKeyPair, HASH_LEN
from wots import WOTSKeyPair, base_w, wots_checksum, LEN1, LEN, W, chain

OUT = Path(__file__).resolve().parent
MSG = b"Lamport vs WOTS+ comparative benchmark"


# ---------------------------------------------------------------------------
# Generic Merkle signature scheme (pluggable OTS; optional compact mode)
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class GenericSignature:
    ots_sig: list
    ots_pk: object            # None when compact (rebuilt from ots_sig)
    auth_path: list[bytes]
    leaf_index: int


def _hash_leaf(pk: object, kind: str) -> bytes:
    if kind == "lamport":
        flat = b"".join(pk[0]) + b"".join(pk[1])
    else:  # wots
        flat = b"".join(pk)
    return H(b"MSS-LEAF" + flat)


def _reconstruct_pk(ots_sig: list, msg: bytes, kind: str) -> object:
    """Standard XMSS/WOTS-Merkle technique: rebuild the OTS public key from
    the signature alone, so it need not be transmitted.

    * Lamport: each revealed preimage hashes to the corresponding public
      value; the message digest tells us which bit value each position held.
      NOTE: compact mode is NOT applicable to raw Lamport in this scheme
      because the leaf commits to the *full* OTS public key; see the paper
      (a Lamport signature reveals only the preimages for the actual bit
      values, so the other half is not recoverable). This branch is kept for
      reference only and is not exercised by the compact benchmark.
    * WOTS+: each chain end is chain(sig_i, d_i, w-1-d_i) (FIPS 205 pkFromSig),
      which is fully recoverable from the signature + message.
    """
    if kind == "lamport":
        digest = H_message(msg)
        pk0: list = [b""] * 256
        pk1: list = [b""] * 256
        k = 0
        for byte in digest:
            for j in range(8):
                bit = (byte >> j) & 1
                if bit == 0:
                    pk0[k] = H(ots_sig[k])
                else:
                    pk1[k] = H(ots_sig[k])
                k += 1
        return [pk0, pk1]
    # wots
    md = base_w(H_message(msg), LEN1)
    c = sum(W - 1 - d for d in md)
    D = md + wots_checksum(c)
    return [chain(ots_sig[i], D[i], W - 1 - D[i]) for i in range(LEN)]


class GenericMSS:
    def __init__(self, height: int, kind: str, compact: bool = False):
        assert kind in ("lamport", "wots")
        self.kind = kind
        self.height = height
        self.compact = compact
        self.n = 2 ** height
        self.ots_keys = []
        for _ in range(self.n):
            if kind == "lamport":
                self.ots_keys.append(LamportKeyPair.generate())
            else:
                self.ots_keys.append(WOTSKeyPair.generate())
        self.leaf_hashes = [_hash_leaf(kp.pk, kind) for kp in self.ots_keys]
        self.root = self._build_tree()

    def _build_tree(self) -> bytes:
        layer = self.leaf_hashes[:]
        for _ in range(self.height):
            layer = [H(b"MSS-NODE" + layer[i] + layer[i + 1])
                     for i in range(0, len(layer), 2)]
        return layer[0]

    def _auth_path(self, idx: int) -> list[bytes]:
        path, layer, cur = [], self.leaf_hashes[:], idx
        for _ in range(self.height):
            path.append(layer[cur ^ 1])
            layer = [H(b"MSS-NODE" + layer[i] + layer[i + 1])
                     for i in range(0, len(layer), 2)]
            cur //= 2
        return path

    def sign(self, msg: bytes, idx: int) -> GenericSignature:
        # NOTE: benchmark-only harness. It intentionally re-signs the same
        # leaf for throughput timing and does NOT enforce one-time use.
        # The deployment API (hbs_signature.MerkleSignatureScheme) enforces
        # single-use of each OTS key to avoid secret leakage.
        kp = self.ots_keys[idx]
        return GenericSignature(
            ots_sig=kp.sign(msg),
            ots_pk=None if self.compact else kp.pk,
            auth_path=self._auth_path(idx),
            leaf_index=idx,
        )

    def verify(self, msg: bytes, sig: GenericSignature) -> bool:
        # F3 hardening: bind the leaf index and authentication-path length so
        # that an out-of-range index or a wrong-length auth path is rejected
        # (previously the fold loop only used the low 'height' bits of the
        # index, so indices sharing those bits could still fold to the root).
        if not (isinstance(sig.leaf_index, int) and 0 <= sig.leaf_index < self.n):
            return False
        if len(sig.auth_path) != self.height:
            return False
        # Reject a wrong-length OTS signature before any chain reconstruction,
        # so a truncated/extended signature returns False instead of raising.
        expected_ots = LEN if self.kind == "wots" else HASH_LEN * 8
        if len(sig.ots_sig) != expected_ots:
            return False
        kp_cls = LamportKeyPair if self.kind == "lamport" else WOTSKeyPair
        ots_pk = sig.ots_pk
        if ots_pk is None:
            # Compact mode: recover the OTS public key from the signature
            # (pkFromSig). There is no transmitted PK to check against, and
            # re-running the OTS verify against the key we just reconstructed
            # is an identity comparison that only doubles the chain work --
            # the same double-pass defect that was fixed in the C port. Soundness
            # comes from the Merkle path: a forged signature reconstructs to a
            # different leaf, so the path check fails.
            ots_pk = _reconstruct_pk(sig.ots_sig, msg, self.kind)
        else:
            if not kp_cls.verify(msg, sig.ots_sig, ots_pk):
                return False
        cur = _hash_leaf(ots_pk, self.kind)
        idx = sig.leaf_index
        for sibling in sig.auth_path:
            cur = H(b"MSS-NODE" + (cur if idx & 1 == 0 else sibling)
                    + (sibling if idx & 1 == 0 else cur))
            idx //= 2
        return cur == self.root

    # -- size helpers --
    @staticmethod
    def signature_bytes(kind: str, height: int, compact: bool) -> int:
        if kind == "lamport":
            ots_sig = LamportKeyPair.sig_size_bytes()
            ots_pk = LamportKeyPair.pk_size_bytes()
        else:
            ots_sig = WOTSKeyPair.sig_bytes()
            ots_pk = WOTSKeyPair.pk_bytes()
        extra = 0 if compact else ots_pk
        return ots_sig + extra + height * 32


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def _iqr(xs: list) -> float:
    """Interquartile range with linear-interpolation quantiles."""
    xs = sorted(xs)
    n = len(xs)
    if n == 1:
        return 0.0

    def _q(p: float) -> float:
        idx = p * (n - 1)
        lo = int(idx)
        hi = min(lo + 1, n - 1)
        return xs[lo] + (idx - lo) * (xs[hi] - xs[lo])

    return _q(0.75) - _q(0.25)


def bench(kind: str, height: int, compact: bool, repeats: int = 31, warmup: int = 3):
    # Uniform warm-up matching the native C harness (§5.5): a few full
    # keygen+sign+verify iterations before timing settle OS caches, branch
    # prediction, and GC, so the first *timed* iteration is no longer cold.
    for _ in range(warmup):
        m = GenericMSS(height, kind, compact=compact)
        s = m.sign(MSG, 0)
        assert m.verify(MSG, s)
    gc.collect()

    kg = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        mss = GenericMSS(height, kind, compact=compact)
        kg.append(time.perf_counter() - t0)
    sign_sig = mss.sign(MSG, 0)
    # Disable GC only around the sub-millisecond sign/verify measurements:
    # the key-generation garbage is collected above, and GC pauses would
    # otherwise dominate single-iteration timings on an unpinned host.
    gc.collect()
    gc.disable()
    try:
        st, vt = [], []
        for _ in range(repeats):
            t0 = time.perf_counter()
            mss.sign(MSG, 0)
            st.append(time.perf_counter() - t0)
        gc.collect()
        for _ in range(repeats):
            t0 = time.perf_counter()
            assert mss.verify(MSG, sign_sig)
            vt.append(time.perf_counter() - t0)
    finally:
        gc.enable()
    return {
        "kind": kind,
        "height": height,
        "compact": compact,
        "n_signatures": 2 ** height,
        "key_gen_ms": round(statistics.median(kg) * 1000, 2),
        "key_gen_iqr": round(_iqr(kg) * 1000, 2),
        "sign_ms": round(statistics.median(st) * 1000, 3),
        "sign_iqr": round(_iqr(st) * 1000, 3),
        "verify_ms": round(statistics.median(vt) * 1000, 3),
        "verify_iqr": round(_iqr(vt) * 1000, 3),
        "signature_bytes": GenericMSS.signature_bytes(kind, height, compact),
        "pubkey_bytes": 32,
        # Raw per-iteration samples retained for traceability (cf. §5.1.1).
        "raw_key_gen_ms": [round(x * 1000, 4) for x in kg],
        "raw_sign_ms": [round(x * 1000, 4) for x in st],
        "raw_verify_ms": [round(x * 1000, 4) for x in vt],
    }


def main():
    print(f"{'kind':<8} {'cmp':>3} {'h':>2} {'N':>5} {'keygen(ms)':>11} "
          f"{'sign(ms)':>9} {'verify(ms)':>11} {'sig(B)':>8}")
    rows = []
    for kind in ("lamport", "wots"):
        for h in range(1, 8):
            r = bench(kind, h, compact=False)
            rows.append(r)
            tag = "exp"
            print(f"{kind:<8} {tag:>3} {h:>2} {r['n_signatures']:>5} "
                  f"{r['key_gen_ms']:>11.2f} {r['sign_ms']:>9.3f} "
                  f"{r['verify_ms']:>11.3f} {r['signature_bytes']:>8}")
        # Compact mode (OTS public key rebuilt from signature) is applicable
        # only to WOTS+; raw Lamport's leaf commits to the full OTS pk and is
        # not reconstructable, so we do not emit compact Lamport rows.
        if kind == "wots":
            for h in range(1, 8):
                r = bench(kind, h, compact=True)
                rows.append(r)
                tag = "cmp"
                print(f"{kind:<8} {tag:>3} {h:>2} {r['n_signatures']:>5} "
                      f"{r['key_gen_ms']:>11.2f} {r['sign_ms']:>9.3f} "
                      f"{r['verify_ms']:>11.3f} {r['signature_bytes']:>8}")

    (OUT / "results_v2.json").write_text(json.dumps(rows, indent=2))
    print(f"\n[written] {OUT/'results_v2.json'}")


if __name__ == "__main__":
    main()
