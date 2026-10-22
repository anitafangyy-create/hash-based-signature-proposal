# Response to Round-3 Review — fixes applied

Scope: third peer review of *"An Engineering Evaluation of a Lamport–WOTS+–Merkle Post-Quantum Signature Prototype…"* (now retitled *"An Implementation Audit…: Three Findings…"*). This note records what was changed and, crucially, what the review got **right**. All changes are in `paper.md` / `paper.html` and the code artifacts in this directory.

## P0 — blocking items

### MC1. WOTS+ checksum encoding was genuinely broken (not just mis-described)
**Verdict: confirmed, and worse than a wording error.** The code did
`checksum_digits = base_w(checksum.to_bytes(32, "big"), LEN2)`. Since `c ≤ 960` fits in two bytes, the 32-byte big-endian buffer is zero-padded and `base_w` reads the leading zero nibbles, so the checksum was **always `[0,0,0]`**. The three checksum chains were therefore revealed at position 0 (the secret itself), and the WOTS+ checksum binding was defeated.

Evidence (before fix):
- `c = 464, 504, 477, 497` for four different messages → all decoded to `[0,0,0]`.
- A forgery that raises a message digit (the legal WOTS+ forgery direction) was **accepted**: with checksum ≡ 0, the attacker holds the checksum-chain secrets and can satisfy any checksum.

Fix:
- Replaced with `wots_checksum(c)`: true integer base-16 decomposition, MSB-first (`c=960 → (3,12,0)`, `c=0 → (0,0,0)`), used identically in `sign` and `verify`.
- Added boundary self-tests for `c ∈ {0,1,15,16,960}` in `wots.py`.
- Regenerated the KAT (`kat_wots.json`) and all benchmark data.
- Added `ref_verify.py`, an **independent** verifier that re-implements the primitives, rebuilds the public key from the signature (`pkFromSig`), and now **rejects** the same forgery ("checksum must retreat, attacker lacks lower-secret").
- Paper §3.2.1 now carries an explicit **Corrigendum** documenting the defect, the fix, and the lesson: sign+verify shared the wrong encoding, so round-trip tests passed while security was broken.

### MC2 (P0). Independent reproduction / KAT
Added `ref_verify.py` (independent implementation, not importing `wots.py`'s primitives). It cross-checks the regenerated KAT end-to-end and demonstrates forgery rejection. Reproduce: `python3 ref_verify.py`.

### MC3 (P0). Is the OTS public key really needed on the wire?
**Partly yes — this materially changed the headline size.**
- **WOTS+**: the OTS public key **is** reconstructable from the signature (`pk_i = chain(sig_i, d_i, w-1-d_i)`), so compact mode drops it: **4,512 B → 2,368 B** at `h=7`. Implemented and measured; compact verify rises to ~0.41 ms (extra chain evaluations). This matches the reviewer's ~2,368 B estimate.
- **Raw Lamport**: compact mode is **not** applicable in this scheme. The leaf commits to the *full* OTS public key `H(pk[0]||pk[1])`, but a Lamport signature reveals only the preimages for the actual bit values; the other 256 public values are unrecoverable. Lamport+MSS therefore stays at 24,800 B. This asymmetry is reported as a concrete finding, not hidden.
- Tables 1/2, abstract, §3.3.2, §5.4, fig5/6/7 and `results_v2.json` were updated to report both explicit and compact sizes.

## P1 — decides whether the paper stands

- **Security boundary**: §3.4 now states the work is "an engineering benchmark of a custom hash-chain and Merkle-signature prototype, **without a claimed cryptographic security level**." Explicitly: no formal reduction, no reduction-loss quantification, no multi-target analysis, and (post-corrigendum) no working security reduction.
- **Algorithm definition**: §3.2.1–3.2.4 now give the exact digest, base-$w$ bit order, checksum encoding, chain input layout, serialization, per-field lengths, error handling, and sign/verify pseudocode.
- **Testing beyond round-trip**: checksum boundary tests, malformed input, wrong auth path, OOB index, one-time-key reuse, plus the independent verifier and a targeted forgery attempt.
- **Fair comparison**: Table 1 adds stateful XMSS-SHA256_10_256 (2,504 B) and LMS SHA256 M24 H10 (1,624 B) baselines, and marks each row's state model and security status. It remains a size comparison, explicitly not a Pareto claim.

## P2 — quality

- **Statistics**: 31 repetitions with median + IQR (was 3); Table 2 covers all `h=1..7`; the `h=2` keygen IQR outlier is annotated as GC/scheduler noise.
- **Removed speculation**: the "10–100× faster" native claim is deleted; §7.5 now says no quantitative speedup is claimed.
- **References**: expanded 13 → 18 (WOTS+ [14], XMSS [15], SPHINCS+ [16], Merkle 1987 [17], NIST PQC resource [18]); added §2.4 related work. BIP-0360 is cited as a **draft** with access date.
- **Appendix C**: checksums updated; `ref_verify.py` added; the stale "§9" cross-reference fixed.

## Native benchmark (added in this revision)
The "no same-environment benchmark" objection is now addressed. We built a controlled **native C** benchmark (`native_bench/`, `native_results.json`, `native_benchmark.md`, §5.5):
- PQClean (commit `0586a82`) ML-DSA-44/65 and SLH-DSA-SHA2-128s/128f, plus a C port of the prototype, compiled with clang 17 `-O3` on the same Apple M1, same harness, 64-byte message, `clock_gettime`, warm-up, 101 reps (standards) / 31 (prototype).
- **Result 1:** the Python/C gap is only **~1.4–1.9×** for this workload (Python WOTS+MSS h=7: 61.3 / 0.277 / 0.214 ms; C: ~33–42 / 0.17–0.20 / 0.12–0.15 ms). The earlier "10–100× in C/Rust" claim is refuted and removed.
- **Result 2:** stateful WOTS+MSS sign/verify (~0.18 / ~0.15 ms) is of the same order as ML-DSA-44 (~0.30 / ~0.09 ms) and far faster than SLH-DSA-128f (~25 / 1.44 ms) or 128s (~536 / 0.54 ms), at the cost of stateful key generation (~40 ms) and a 128-signature capacity.
- **Result 3:** compact 2,368 B sits between ML-DSA-44 (2,420 B) and LMS (1,624 B); explicit 4,512 B sits between ML-DSA-65 (3,309 B) and SLH-DSA-128s (7,856 B).

Caveats stated in the paper: stateful vs. stateless models; no security proof; single unpinned host; PQClean clean C (not AVX2); keygen comparison is skewed by statefulness.

### P0 follow-up (1): three-session benchmark
The single-run numbers above were replaced by **three independent sessions** in rotated scheme order with a 12 s cooldown (`native_bench/run_sessions.py`, `native_results_sessions.json`). Table 4 now reports the **cross-session median with the [min–max] range of the per-session medians**. This is the honest response to "one run on an unpinned laptop": most per-session medians varied by under ~20% (a few fast operations, notably ML-DSA signing/verification, varied more). Cross-session medians (h=7): ML-DSA-44 0.060/0.204/0.064 ms; SLH-DSA-128f 1.119/27.703/1.548; SLH-DSA-128s 78.016/593.730/0.544; WOTS+MSS explicit 35.739/0.186/0.131 (4,512 B); compact 35.307/0.177/0.246 (2,368 B).

### P0 follow-up (2): durable-state / fault-injection demo
The paper previously *analyzed* state management without implementing it. We added `state_demo/durable_state.py` (append-only hash-chained log, atomic head replacement, separate high-water mark, exclusive file lock) and `state_demo/test_state.py`. **6/6 tests pass:**
1. reuse denied by the allocator and by the MSS API;
2. a crash after reserve (before signing) burns the leaf; the next reservation returns a different leaf;
3. restoring an older state directory is detected via the surviving high-water mark;
4. eight concurrent processes receive eight distinct leaves;
5. a tampered/truncated log is rejected by the hash chain;
6. capacity is enforced.
Residual risk is stated explicitly in the paper: rolling back *all* local state, including the high-water mark, is undetectable without a trusted monotonic anchor (secure element / remote transparency log). The demo does not pretend otherwise.

## What this revision does **not** do (honest limits)
1. **No formal security proof.** The construction remains an unkeyed, prefix-separated prototype; a reduction for this concrete instantiation is future work and a precondition for any stronger claim.
2. **Single host** (Apple M1), unpinned. Latency medians drift ~20–30% across runs; only the ordering, not exact microseconds, is robust. Sizes are exact.

## Narrative restructure (P1)
The manuscript is now organized around **one claim and three findings** instead of a list of caveats:
- **Title:** *"An Implementation Audit of a Lamport–WOTS+–Merkle Post-Quantum Signature Prototype: Three Findings and a Comparison Against NIST Standards."*
- **Abstract and §1.1–1.2:** state the audit and the three findings—F1 (checksum defect that round-trip tests missed), F2 (WOTS+ compaction vs. Lamport), F3 (Python/C gap and stateful performance).
- **§1.3 "Scope and non-claims":** the non-conformance, no-security-level, no-Pareto, and no-deployment disclaimers are stated **once** here.
- **§3.4 / §4 / §7:** point back to §1.3 instead of repeating the same caveats; §7 is now a compact limitations list (stateful/stateless, no FORS, no proof, side channels, hash choice, KAT scope, no hybrid, Python vs. C) plus the Bitcoin scope.
- **§6** is retitled *"What the Tests Establish, and State Management"*: the negative tests and the F1 lesson, followed by the six fault-injection results—no separate "security analysis" that only disclaims.
- **Table/figure numbering** was reordered by appearance: Table 1 = FIPS 205 relationship, Table 2 = sizes, Table 3 = Python heights, Table 4 = native; Figures 1–3 in appearance order.

## Net effect on the paper's claims
- The signature-size result got **stronger and better justified** (2,368 B compact with a standard, explainable technique), while the *security* claim got **weaker and explicit** (no proven level).
- The checksum bug is disclosed rather than hidden, and the paper now uses it to argue why independent verification matters — which is itself a defensible contribution for an engineering-evaluation paper.
