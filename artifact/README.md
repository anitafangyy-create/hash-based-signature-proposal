# Artifact package — reproducibility guide

This directory bundles everything needed to **reproduce** the corrected results
of the paper *“An Implementation Audit of a Lamport–WOTS+–Merkle Post-Quantum
Signature Prototype: Three Findings and a Comparison Against NIST Standards.”*

The guiding principle of the remediation was: **freeze the original defective
version, reproduce the problem, fix the code, then re-run the experiments** — not
the reverse. The package is organised to make that path auditable.

## Layout

```
artifact/
  README.md                     # this file
  environment.txt               # exact host / toolchain / commit metadata
  original/                     # FROZEN pre-fix code + the diff that fixed it
    wots.py.orig                #   pre-fix WOTS+ (defective checksum encoding)
    hbs_signature.py.orig       #   pre-fix Merkle scheme
    ref_verify.py.orig          #   pre-fix independent verifier
    before-fix.patch            #   diff of the crypto fixes applied to wots.py/hbs_signature.py
  src/                          # CURRENT (fixed) source under audit
    wots.py                     #   fixed checksum; range-validated
    hbs_signature.py            #   fixed Merkle verify (index/auth-path binding)
    ref_verify.py               #   independent verifier (rebuilds pk from sig)
    unified_merkle_tree.py
  experiments/
    f1_repro.py                 #   reproduces F1 (checksum defect) -> results/f1_evidence.json
    summarize.py                #   re-derives median/IQR/P95 from raw bench data -> results/bench_summary.csv
  results/
    f1_evidence.json            #   machine-readable F1 reproduction evidence
    bench_summary.csv           #   median/IQR/P95 per (scheme, h, mode)
```

## 1. Reproduce F1 (the WOTS+ checksum defect) and its fix

```bash
python artifact/experiments/f1_repro.py        # -> artifact/results/f1_evidence.json
```

`f1_repro.py` loads the **frozen pre-fix** `wots.py.orig`, demonstrates that the
original checksum digits are constant `[0,0,0]` (leaking the three checksum-chain
secrets `sk[64..66]` in cleartext), then compares against the fixed code and an
independent verifier. The output JSON records, per case, the expected vs.
observed checksum digits and whether each of the three verifiers
(original / fixed / independent) accepts the signature. The precise attack scope
is documented in the JSON’s `attack_scope` field: it is a one-time-signature
secret leak, **not** a universal forgery.

## 2. Run the regression / correctness tests

```bash
pytest tests/ -q
```

Covers: checksum boundaries (test_checksum), WOTS+ round-trip / tamper /
fixed-vs-original secret leak (test_wots), explicit-vs-compact agreement and
malformed rejection (test_compact), and the F3 index-binding / auth-path
hardening (test_malformed, both WOTS+MSS and Lamport+MSS).

## 3. Reproduce the native cross-implementation benchmark (§5.5)

```bash
cd native_bench && bash build.sh          # clones PQClean @ 0586a82, builds, runs -> ../native_results.json
python native_bench/run_sessions.py native_bench/_build   # 3 sessions -> ../native_results_sessions.json
python artifact/experiments/summarize.py  # -> artifact/results/bench_summary.csv
```

Both harnesses (`bench_std.c`, `bench_proto.c`) apply a **uniform 3-iteration
warm-up** (key generation, signing, verification) before timing, and every
scheme runs **31 repetitions**. The reported table values are cross-session
medians with the min–max range of the three per-session medians. Raw
per-iteration timings are embedded in the JSON, so `summarize.py` can recompute
median / IQR / P95 independently.

## 4. Reproduce the Python benchmark (§5.2–5.3)

```bash
python experiment_v2.py        # -> results_v2.json
python make_native_chart.py    # -> fig8_native_benchmark.png (native figure)
```

## 5. Environment and integrity

- `artifact/environment.txt` records the exact host (macOS 15.7.7, Apple M1),
  Python (3.14.3), compiler (Apple clang 17.0.0), and PQClean commit
  (`0586a82`).
- The manuscript's Appendix C (in the sibling directory
  `../hash-based-signature-paper/paper.md`) lists SHA-256 checksums (first 16
  hex) of the primary artifacts, with paths relative to this repository;
  regenerate with `shasum -a 256 <file>` on the tagged release.

## Note on the original vs. fixed code

`artifact/original/*.orig` are byte-for-byte the code at git baseline
`e896002` (pre-fix). `artifact/src/*` is the **fixed** code that produces the
corrected results in the paper. `artifact/original/before-fix.patch` is the diff
that turned one into the other.

## Round-4 additions (F1 end-to-end evidence, statistics, size accounting)

These entries are part of the same frozen snapshot (`git HEAD e896002ed4d36e59033bbae9a13b8888bb6ff670`).
They are **not** duplicated into `artifact/` because they import from the repository root; run them from
the repository root instead:

```bash
# F1 end-to-end forgery experiment (A/B/C/D matrix, leakage probe, reuse scenario)
python experiments/experiment_checksum_forgery.py      # -> experiments/forgery_results.json

# F3 statistics from the retained raw samples (median / IQR / P95 / bootstrap 95% CI)
python experiments/analyze_results.py                  # -> results/bench_stats.{csv,json}

# F2 size accounting, asserted against the constants the code uses
python experiments/signature_size.py                   # -> experiments/size_accounting.json

# full correctness + negative suite (118 tests, incl. the 7 end-to-end F1 regressions)
python -m pytest -q tests/
```

Recorded results of this snapshot:

- F1 matrix: buggy signature accepted 20/20 by the buggy verifier, **rejected 20/20** by the independent
  verifier; fixed signature accepted 20/20 by both; single-byte tamper rejected 0/20.
- F1 leakage: raw `sk[64..66]` disclosed **10/10** under the buggy encoding, **0/10** under the fixed one.
- F1 forgery condition: 0/20,000 sampled message pairs dominate; analytic probability ≈ 2.6e-18 under an
  independent-uniform-digit model (a model-derived figure, not an empirical rate).
- F1 reuse scenario (32 signatures, explicit extra assumption): forgery **accepted** by the independent
  verifier; the same attack against the fixed implementation is **blocked**.
- F2: compact and explicit verification cost the same (Table 3: 0.213 vs 0.222 ms at h=7). An earlier
  Python double pass inflated compact verify to 0.417 ms; it has been removed.
