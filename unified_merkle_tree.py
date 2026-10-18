"""
Unified Merkle Tree for Post-Quantum Shielded Bitcoin
======================================================

A single append-only Merkle tree whose leaves carry a one-byte type tag:

    Leaf type 0x01  -> WOTS+ OTS public key (post-quantum signature spend,
                       BIP-0360 Pay-to-Merkle-Root path)
    Leaf type 0x02  -> Shielded-note commitment (Zcash-style private transfer,
                       cf. Shielded Bitcoin Section 9:
                       ℓ_j = H_leaf(const_salt, h_body, j, pk_eph,j,
                                            ct_j^note, h_aux,j))

The two leaf types share the same tree, the same 32-byte root, and the same
Merkle-path verification gate. This is the structural convergence of:

  * Shielded Bitcoin (allocinit, 2026)  -- append-only note Merkle tree,
    nullifier set, deterministic replay over Bitcoin history; and
  * BIP-0360 Pay-to-Merkle-Root          -- 32-byte root commitment, reserves
    OP_SUCCESSx for a future post-quantum signature opcode.

We measure:
  1. Witness footprint for spending each leaf type at various tree depths;
  2. Root-update cost when appending a new note/OTS leaf;
  3. On-chain size delta vs. the two-deployed-separate-trees baseline.

Threat context (see paper Section 9 "Post-Quantum Privacy for Bitcoin L1"):
  Shielded Bitcoin's ECDH note encryption (pk_d = [sk_view]G_d,
  pk_eph = [sk_eph]G_d) collapses under Shor's algorithm for long-exposure
  attacks on historical envelopes. The hash-based components (note tree,
  nullifier derivation, h_leaf / h_body / h_nf) survive quantum adversaries
  with only Grover-grade degradation. This prototype quantifies the on-chain
  footprint of the hybrid tree that keeps the quantum-resistant parts while
  leaving the ECC KEM to a future PQ upgrade.
"""
from __future__ import annotations

import os
import json
import time
import dataclasses
from pathlib import Path

from hbs_signature import H
from wots import WOTSKeyPair, N, LEN

OUT = Path(__file__).parent

# ---------------------------------------------------------------------------
# Leaf type tags (one byte, prepended before the domain-separated leaf hash)
# ---------------------------------------------------------------------------
LEAF_TAG_OTS = 0x01      # WOTS+ OTS public key commitment
LEAF_TAG_NOTE = 0x02     # Shielded-note commitment


# ---------------------------------------------------------------------------
# Leaf representations
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class OTSLeaf:
    """A WOTS+ public key leaf.

    The leaf hash is the domain-separated hash over the tag + the WOTS+ pk
    concatenation. On spend the witness carries the WOTS+ signature, the
    public key, the leaf script (future OP_WOTS_VERIFY), and the Merkle path.
    """
    wots_pk: list[bytes]
    w: int = 16

    def leaf_hash(self) -> bytes:
        inner = b"".join(self.wots_pk)
        return H(b"UMT-LEAF" + bytes([LEAF_TAG_OTS]) + inner)

    def witness_size(self, wots_sig: list[bytes], depth: int) -> int:
        # count(1) + wots_sig(L*n) + wots_pk(L*n) + leaf script(3)
        # + control block(1 + 32*depth)
        control = 1 + 32 * depth
        return (1
                + sum(len(x) for x in wots_sig)
                + sum(len(x) for x in self.wots_pk)
                + 3
                + control)


@dataclasses.dataclass
class NoteLeaf:
    """A shielded-note commitment leaf.

    Mirror of Shielded Bitcoin Section 9:
        ℓ_j = H_leaf(const_salt, h_body, j, pk_eph,j, ct_j^note, h_aux,j)

    We model the public bytes that must appear in the spend witness:
      * h_body        : 32-byte binding hash over the whole envelope
      * output_index  : 4 bytes (uint32)
      * pk_eph        : 33 bytes compressed secp256k1 today; PQ-KEM upgrade
                        will be ~1184 B (ML-KEM-1024)
      * ct_note       : AEAD ciphertext; plaintext is (v, d, r_seed) = 8+11+32
                        = 51 B, plus 16 B AEAD tag -> ~67 B; we round to 80 B
                        to leave room for overhead
      * h_aux         : optional auxiliary hash, 32 B
      * zk_proof      : the shielded-transfer proof. Groth16 on BLS12-381 is
                        ~192 B; Halo2 PLONK ranges 1-2 KB. We use 256 B as a
                        representative midpoint (consistent with the paper's
                        "succinct zero-knowledge proof" claim).
    """
    h_body: bytes          # 32 B
    output_index: int      # uint32
    pk_eph: bytes          # 33 B (secp256k1 compressed) today
    ct_note: bytes         # ~80 B
    h_aux: bytes           # 32 B
    zk_proof: bytes        # ~256 B

    def leaf_hash(self) -> bytes:
        inner = (self.h_body
                 + self.output_index.to_bytes(4, "big")
                 + self.pk_eph
                 + self.ct_note
                 + self.h_aux)
        return H(b"UMT-LEAF" + bytes([LEAF_TAG_NOTE]) + inner)

    def witness_size(self, depth: int) -> int:
        # The note-spend witness on a unified Merkle tree carries:
        #   count(1) + output_index(4) + h_body(32) + pk_eph(len)
        #   + ct_note(len) + h_aux(32) + zk_proof(len)
        #   + nullifier(32) + Merkle path (32*depth)
        control = 32 * depth  # no control block needed; tag is in leaf hash
        return (1
                + 4
                + 32
                + len(self.pk_eph)
                + len(self.ct_note)
                + 32
                + len(self.zk_proof)
                + 32           # nullifier nf
                + control)


# ---------------------------------------------------------------------------
# Append-only unified Merkle tree
# ---------------------------------------------------------------------------
class UnifiedMerkleTree:
    """Append-only hash tree over a mix of OTSLeaf and NoteLeaf objects.

    The tree is rebuilt from the full leaf list on append (a prototype; the
    production Shielded Bitcoin replay layer uses an incremental Merkle tree
    with $O(log n)$ root update). We measure both:
      * naive rebuild time (this prototype), and
      * incremental update cost (analytic $O(\log n)$ hash evaluations).
    """

    def __init__(self) -> None:
        self.leaves: list[bytes] = []
        self._objects: list = []

    def append(self, leaf) -> tuple[bytes, float]:
        """Append a leaf. Returns (new_root, rebuild_seconds).

        The returned rebuild_seconds is the naive full-rebuild cost in this
        Python prototype; the analytic incremental cost is
        $32 * \\log_2(n)$ SHA-256 evaluations."""
        t0 = time.perf_counter()
        self._objects.append(leaf)
        self.leaves.append(leaf.leaf_hash())
        root = self._rebuild()
        dt = time.perf_counter() - t0
        return root, dt

    def _rebuild(self) -> bytes:
        layer = list(self.leaves)
        if not layer:
            raise ValueError("empty tree")
        while len(layer) > 1:
            # left-pad to even by duplicating the last leaf if odd
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            layer = [H(b"UMT-NODE" + layer[i] + layer[i + 1])
                     for i in range(0, len(layer), 2)]
        return layer[0]

    @property
    def root(self) -> bytes:
        return self._rebuild()

    def depth(self) -> int:
        return max(0, (len(self.leaves) - 1).bit_length())

    def auth_path(self, idx: int) -> list[bytes]:
        layer = list(self.leaves)
        # pad to power-of-two for path extraction
        n = len(layer)
        path = []
        cur = idx
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            path.append(layer[cur ^ 1])
            layer = [H(b"UMT-NODE" + layer[i] + layer[i + 1])
                     for i in range(0, len(layer), 2)]
            cur //= 2
        return path


# ---------------------------------------------------------------------------
# Experiment
# ---------------------------------------------------------------------------
def make_note_leaf() -> NoteLeaf:
    return NoteLeaf(
        h_body=os.urandom(32),
        output_index=0,
        pk_eph=b"\x02" + os.urandom(32),   # compressed secp256k1, 33 B
        ct_note=os.urandom(80),
        h_aux=os.urandom(32),
        zk_proof=os.urandom(256),
    )


def run_experiment() -> dict:
    print("=" * 72)
    print("Unified Merkle Tree: mixed OTS (WOTS+) + Note (Shielded Bitcoin)")
    print("=" * 72)

    # --- Build a mixed tree: 8 leaves, alternating note / OTS -------------
    tree = UnifiedMerkleTree()
    leaves_objs = []
    rebuild_times = []

    # Start with 1 note leaf
    note0 = make_note_leaf()
    root, dt = tree.append(note0)
    leaves_objs.append(("note", note0))
    rebuild_times.append(dt)

    # Alternate: OTS, note, OTS, note, ... up to 8 leaves
    kp0 = WOTSKeyPair.generate()
    ots0 = OTSLeaf(wots_pk=kp0.pk)
    root, dt = tree.append(ots0)
    leaves_objs.append(("ots", ots0))
    rebuild_times.append(dt)

    kp1 = WOTSKeyPair.generate()
    note1 = make_note_leaf()
    root, dt = tree.append(note1)
    leaves_objs.append(("note", note1))
    rebuild_times.append(dt)

    ots1 = OTSLeaf(wots_pk=kp1.pk)
    root, dt = tree.append(ots1)
    leaves_objs.append(("ots", ots1))
    rebuild_times.append(dt)

    kp2 = WOTSKeyPair.generate()
    note2 = make_note_leaf()
    root, dt = tree.append(note2)
    leaves_objs.append(("note", note2))
    rebuild_times.append(dt)

    ots2 = OTSLeaf(wots_pk=kp2.pk)
    root, dt = tree.append(ots2)
    leaves_objs.append(("ots", ots2))
    rebuild_times.append(dt)

    kp3 = WOTSKeyPair.generate()
    note3 = make_note_leaf()
    root, dt = tree.append(note3)
    leaves_objs.append(("note", note3))
    rebuild_times.append(dt)

    ots3 = OTSLeaf(wots_pk=kp3.pk)
    root, dt = tree.append(ots3)
    leaves_objs.append(("ots", ots3))
    rebuild_times.append(dt)

    depth = tree.depth()
    print(f"\n[tree] {len(tree.leaves)} leaves, depth={depth}")
    print(f"[tree] root = {root.hex()}")

    # --- Witness sizes at depth = 3 (8 leaves) ----------------------------
    print(f"\n[witness] Depth {depth} ({len(tree.leaves)} leaves in tree)")
    wots_sig_0 = kp0.sign(b"unified-tree spend message")
    ots_wit = ots0.witness_size(wots_sig_0, depth=depth)
    note_wit = note0.witness_size(depth=depth)
    print(f"    OTS leaf (WOTS+ w=16) witness: {ots_wit} B")
    print(f"    Note leaf (shielded spend)  witness: {note_wit} B")

    # --- Witness sizes across depths -------------------------------------
    # We rebuild conceptual trees of depth 0..6 (1..64 leaves) and compute
    # witness sizes analytically (they depend only on depth).
    depth_table = []
    for d in range(0, 7):
        # OTS witness at depth d: 1 + sig(2144) + pk(2144) + script(3) + ctrl(1+32d)
        ots_w = 1 + LEN * N + LEN * N + 3 + (1 + 32 * d)
        # Note witness at depth d: 1+4+32+33+80+32+256+32 + 32d
        note_w = 1 + 4 + 32 + 33 + 80 + 32 + 256 + 32 + 32 * d
        depth_table.append({"depth": d,
                            "ots_witness_bytes": ots_w,
                            "note_witness_bytes": note_w})
        print(f"    depth={d} (2^{d} leaves): OTS={ots_w:5d} B  "
              f"Note={note_w:5d} B")

    # --- Root update cost -------------------------------------------------
    print(f"\n[perf] Incremental root update cost")
    print(f"    Naive full rebuild (Python, 8 leaves): "
          f"{sum(rebuild_times)*1000:.3f} ms cumulative")
    # analytic incremental: each append touches depth+1 nodes on the path
    # and the sibling; for depth d that's 2*d hash evaluations.
    print(f"    Analytic incremental (SHA-256 calls per append):")
    for d in range(0, 7):
        hashes = 2 * d
        print(f"      depth={d}: {hashes} SHA-256 evals")

    # --- PQ-KEM upgrade projection ---------------------------------------
    # If we replace secp256k1 ECDH note encryption with ML-KEM-1024:
    #   pk_eph grows from 33 B to 1568 B (Kyber-1024 public key).
    # This is the long-exposure quantum fix.
    pk_eph_secp = 33
    pk_eph_mlkem1024 = 1568  # ML-KEM-1024 pk bytes (FIPS 203)
    delta = pk_eph_mlkem1024 - pk_eph_secp
    print(f"\n[pq-upgrade] Replacing ECDH with ML-KEM-1024 in note encryption:")
    print(f"    pk_eph today (secp256k1 compressed): {pk_eph_secp} B")
    print(f"    pk_eph after ML-KEM-1024:           {pk_eph_mlkem1024} B")
    print(f"    witness growth per note spend:     +{delta} B "
          f"({delta/note_wit*100:.1f}%)")

    # --- Baseline comparison: two separate trees ------------------------
    # Baseline A: BIP-0360 tree only (no shielded) -> OTS witness
    # Baseline B: Shielded Bitcoin note tree only (no PQ OTS) -> note witness
    # Unified tree: one root, one control block, one UTXO commitment
    print(f"\n[baseline] Two-deployed-trees vs. unified tree")
    print(f"    Separate BIP-0360 root (OTS) witness:   {ots_wit} B")
    print(f"    Separate note-tree root (note) witness: {note_wit} B")
    print(f"    Unified tree: same witnesses, but ONE scriptPubKey (34 B)")
    print(f"      instead of two; one replay pass; one root to anchor.")

    result = {
        "tree_size_leaves": len(tree.leaves),
        "tree_depth": depth,
        "tree_root_hex": root.hex(),
        "ots_witness_at_depth3": ots_wit,
        "note_witness_at_depth3": note_wit,
        "depth_table": depth_table,
        "naive_rebuild_ms_cumulative": sum(rebuild_times) * 1000,
        "pk_eph_secp_bytes": pk_eph_secp,
        "pk_eph_mlkem1024_bytes": pk_eph_mlkem1024,
        "pq_witness_delta_bytes": delta,
        "pq_witness_delta_pct": round(delta / note_wit * 100, 1),
    }
    return result


if __name__ == "__main__":
    res = run_experiment()
    out_path = OUT / "unified_tree_results.json"
    out_path.write_text(json.dumps(res, indent=2))
    print(f"\n[written] {out_path}")
