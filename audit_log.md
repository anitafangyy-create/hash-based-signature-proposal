# Audit Log — hash-based-signature-proposal

Reproduction log for the paper *An Empirical Implementation Audit of a
Hash-Based Signature Prototype: Correctness, State Management, and
Performance*. Each experiment below records the actual command, exit code,
output artifact, and its SHA-256.

## Environment

- OS: macOS 15.7.7 (Apple M1, unpinned CPU)
- Python: CPython 3.14.7
- Compiler: Apple clang 17.0.0 (`-O3 -std=c99`)
- Git commit: `f7e6a28` (tag `round6-review-ready`)
- External: PQClean commit `0586a82`, variant `clean` (portable C, not AVX2)
- Parameters: n=32, w=16, heights h=1..7 (2^h <= 128 signatures per key)

## One-command gate

`make reproduce` runs, in order: checksum RFC audit (961), leaf equivalence
(128 leaves), mutation testing (3 mutants), F1 defect reproduction, pytest
(123 tests), state fault injection (10/10), randomized scheduling stress
(1000x8 = 8,000 reservations), then regenerates `vectors/manifest.json`. Every step exits non-zero on
failure. The full transcript is captured below with exit codes.

```
$ make reproduce
$ echo $?  -> 0
```

## Experiments

| # | Command | Exit | Artifact | SHA-256 (16) |
|---|---|---|---|---|
| 1 | `python3 experiments/audit_checksum_rfc.py` | 0 | `results/checksum_rfc_audit.json` | see Appendix C |
| 2 | `python3 experiments/leaf_equivalence.py` | 0 | `results/leaf_equivalence.json` | see Appendix C |
| 3 | `python3 experiments/mutation_test_checksum.py` | 0 | `results/mutation_test_checksum.json` | see Appendix C |
| 4 | `python3 experiments/reproduce_checksum_bug.py` | 0 | `artifact/f1_repro.py` evidence | see Appendix C |
| 5 | `python3 -m pytest -q tests/` | 0 | 123 passed | — |
| 6 | `python3 state_demo/test_state.py` | 0 | 10/10 passed | see Appendix C |
| 7 | `python3 experiments/state_stress.py --rounds 1000 --processes 8` | 0 | `results/state_stress.json` (8,000 reservations, 0 duplicates, restart-verified) | see Appendix C |
| 8 | `python3 experiments/benchmark_state.py --reps 1000` | 0 | `results/state_overhead.json` | see Appendix C |
| 9 | `python3 experiments/make_manifest.py` | 0 | `vectors/manifest.json` | see Appendix C |

The paper's recorded timings (`results_v2.json`, `native_results_sessions.json`)
are snapshots from the tagged release; regenerating them is documented in
README (`make benchmark`, `make benchmark-native`) and is intentionally
**not** part of `make reproduce` because CI/virtualized hosts are not valid
timing environments.

## Artifacts

- `results/reproduction/SHA256SUMS.txt` — full working-tree SHA-256 manifest
  (104 files, excludes `.git/`, `__pycache__/`, `.DS_Store`, `native_bench/_build/`, itself).
- Full digests for all paper-referenced files: Appendix C of the manuscript
  (56 rows), cross-checked 0 mismatches at tag time.
