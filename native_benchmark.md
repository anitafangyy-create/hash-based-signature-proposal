# Native cross-implementation benchmark

This document reports a **same-machine, same-language** comparison of the
research prototype against PQClean's clean C implementations of ML-DSA (FIPS
204) and SLH-DSA / SPHINCS+ (FIPS 205). It was added in response to the review
comment that the paper's latency numbers were Python-only and therefore not
comparable to native standard implementations.

## What was built

- **PQClean** (commit `0586a82`) provides the reference C implementations:
  `ml-dsa-44`, `ml-dsa-65`, `sphincs-sha2-128s-simple`, `sphincs-sha2-128f-simple`.
  PQClean's SPHINCS+ implementations are the code base from which FIPS 205
  SLH-DSA was standardized; we label them "SLH-DSA-SHA2-128{s,f} (PQClean)".
- **A C port of the prototype** (`native_bench/bench_proto.c`): WOTS+ (n=32,
  w=16, len1=64, len2=3, len=67), Lamport, and Merkle aggregation, with the
  *corrected* checksum encoding. It reuses PQClean's `common/sha2.c` and
  `randombytes.c` so the hash primitive is identical across all binaries.
- **One uniform harness** (`native_bench/bench_std.c` + wrappers): 64-byte
  message, a **uniform 3-iteration warm-up** (key generation, signing, and
  verification) applied identically before timing in both the standards harness
  and the prototype port, `clock_gettime(CLOCK_MONOTONIC)`, median + IQR (linear
  interpolation) and minimum over repetitions. **Three independent sessions**
  in rotated scheme order with a 12 s cooldown; 31 repetitions for every scheme
  per session. Reported values are cross-session medians with the [min–max]
  range of the per-session medians.
- Each scheme is linked as a **separate executable** (each with its own copy of
  PQClean `common/`) to avoid duplicate-symbol conflicts.

## Environment

| Item | Value |
|---|---|
| CPU | Apple M1 (arm64), 8 GB |
| OS | macOS 15.7.7 (Darwin 24.6.0) |
| Compiler | Apple clang 17.0.0, `-O3 -std=c99` |
| PQClean commit | `0586a82` |
| Timing | `clock_gettime(CLOCK_MONOTONIC)` |
| Repetitions | 31 (every scheme) |
| Message | 64 bytes, fixed |
| Pinning | none (single process, single thread) |
| Build | PQClean **clean** (portable C), not AVX2 |

## Results (h = 7; milliseconds unless noted; cross-session median [min–max])

| Scheme | keygen | sign | verify | signature |
|---|---:|---:|---:|---:|
| ML-DSA-44 (L2, stateless) | 0.058 [0.057–0.073] | 0.181 [0.175–0.215] | 0.062 [0.061–0.079] | 2,420 B |
| ML-DSA-65 (L3, stateless) | 0.114 [0.111–0.136] | 0.331 [0.318–0.338] | 0.102 [0.102–0.129] | 3,309 B |
| SLH-DSA-128f (L1, stateless) | 1.058 [1.052–1.325] | 25.021 [24.834–32.465] | 1.485 [1.441–1.809] | 17,088 B |
| SLH-DSA-128s (L1, stateless) | 68.560 [68.245–89.642] | 526.265 [520.139–687.626] | 0.512 [0.512–0.623] | 7,856 B |
| Lamport+MSS h=7 (stateful) | 35.873 [35.848–36.011] | 0.052 [0.052–0.052] | 0.110 [0.110–0.110] | 24,800 B |
| WOTS+MSS h=7 explicit (stateful) | 32.698 [32.646–32.857] | 0.171 [0.169–0.171] | 0.124 [0.123–0.126] | 4,512 B |
| WOTS+MSS h=7 compact (stateful) | 32.741 [32.686–32.822] | 0.170 [0.169–0.174] | 0.125 [0.123–0.125] | 2,368 B |

All `verify_ok = 1`. Per-session medians and within-session IQR/min are in
`native_results_sessions.json`; per-session raw rows are included there too.

## Findings

1. **The Python/C gap for this workload is small — about 1.3–1.5×** (cross-session
   medians). Compare the Python WOTS+MSS h=7
   numbers (49.80 ms keygen, 0.234 ms sign, 0.166 ms verify; Table 3 of the paper)
   with the C port (32.6–32.9 ms, 0.169–0.171 ms, 0.123–0.126 ms). The earlier
   draft's speculative "10–100× faster in C/Rust" is therefore **wrong for this
   workload**, because the Python version is dominated by `hashlib` (C) and the
   C version is dominated by thousands of small SHA-256 calls.
2. **Stateful WOTS+MSS signing and verification are of the same order as
   ML-DSA-44 and far faster than SLH-DSA.** At h=7, WOTS+MSS signs in ~0.17 ms
   and verifies in ~0.12–0.13 ms (explicit / compact); ML-DSA-44 is
   ~0.18 / ~0.06 ms; SLH-DSA-128f is ~25.0 / ~1.49 ms and 128s is ~526 /
   ~0.51 ms. The advantage comes from statefulness (no FORS/hypertree) and
   disappears as a general claim because the key supports only 2^h = 128
   signatures.
3. **Key generation is the price of statefulness.** WOTS+MSS keygen (~33 ms)
   builds 128 OTS key pairs and the Merkle tree, versus ~0.06–0.11 ms for
   ML-DSA (O(1) keygen) and ~69 ms for SLH-DSA-128s. This is a structural
   difference, not an implementation artifact.
4. **Sizes:** compact WOTS+MSS (2,368 B) sits between ML-DSA-44 (2,420 B) and
   LMS (1,452 B); explicit WOTS+MSS (4,512 B) sits between ML-DSA-65 (3,309 B)
   and SLH-DSA-128s (7,856 B). The standard sizes are exact and independent of
   timing noise.

## Limitations

- **Stateful vs. stateless.** Our rows have a hard capacity of 2^h; the standard
  rows are stateless. Keygen, sign, and verify comparisons therefore measure
  different operational models, not interchangeable schemes.
- **No security proof** for the prototype (unkeyed, prefix-separated), so the
  comparison says nothing about security-per-byte or security-per-millisecond.
- **Single unpinned host.** We ran three independent sessions in rotated order
  with a 12 s cooldown. Per-session medians for the prototype rows varied by
  under ~2%; the standard-scheme rows varied by roughly 22–32% across sessions
  on this host state (thermal/frequency/background effects; largest for the
  SLH-DSA signers and the ML-DSA key generators). The minimum and per-session
  data are recorded in `native_results_sessions.json`; only the ordering, not
  the exact microseconds, should be treated as robust.
- **PQClean clean C, not AVX2.** Optimized builds would change absolute numbers
  for all schemes; the clean build is the fairest like-for-like reference.
- **64-byte message.** Longer messages would change absolute costs; hashing is
  not the dominant term for SLH-DSA signing.

## Reproduce

```bash
cd native_bench
./build.sh            # clones PQClean, builds 5 executables, writes ../native_results.json
```

Requires clang, git, network access, and python3.
