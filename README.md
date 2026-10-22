# An Implementation Audit of a Lamport–WOTS+–Merkle Post-Quantum Signature Prototype

Code, experiments, and reproducible evidence for the manuscript

> **An Implementation Audit of a Lamport–WOTS+–Merkle Post-Quantum Signature
> Prototype: Three Findings and a Comparison Against NIST Standards**

This repository contains the audited research prototype and all reproducible
evidence behind the paper: a Python implementation of a stateful
Lamport / WOTS+–Merkle hash-based signature scheme, an independent verifier,
known-answer vectors, negative and fault-injection tests, Python and native C
benchmarks, and the fix record. **The manuscript (`paper.md` / `paper.html`),
the review reports, and the HTML renderer live in the sibling repository
`hash-based-signature-paper/`** (next to this directory).

**Honest positioning (same as the paper):** this is an *implementation audit*,
not a new signature construction. The prototype is **not** FIPS 205 / RFC 8391
conformant, **no security level and no security proof are claimed**, and the
benchmarks are single-host, implementation-specific measurements.

## The three findings

| Finding | Summary |
|---|---|
| **F1 — Correctness** | The original implementation encoded the WOTS+ checksum as `base_w(c.to_bytes(32,'big'), 3)`; the zero-padded 32-byte buffer made the three checksum digits always `(0,0,0)`, revealing three chain secrets per signature. Sign and verify shared the same wrong encoding, so all round-trip tests passed. Fixed, reproduced, and bounded end to end. |
| **F2 — Compact signatures** | The OTS public key is rebuilt from the signature during verification, dropping 2,144 B of public-key transport (4,512 B → 2,368 B core signature at tree height 7). |
| **F3 — Engineering comparison** | Python and native C benchmarks against PQClean's ML-DSA / SLH-DSA on one Apple M1, with a documented measurement protocol. |

## Repository layout

| Path | Purpose |
|---|---|
| `wots.py` | WOTS+-inspired one-time signature (with checksum boundary tests and RFC 8391 equivalence check) |
| `hbs_signature.py` | Lamport + Merkle scheme; deployment-API class is Lamport-only (disclosed in §3.3.2) |
| `ref_verify.py` | Independent verifier (rebuilds the OTS public key from the signature) |
| `experiment_v2.py` | Python benchmark harness (3-iteration warm-up, 31 reps, raw samples) |
| `experiments/` | Benchmark, forgery, checksum-bug, RFC 8391 audit, and manifest scripts |
| `tests/` | 118-test pytest suite (7 files) |
| `state_demo/` | Durable-state fault-injection demo (8/8 tests) |
| `results/` | `bench_stats`, raw timing samples, `checksum_rfc_audit.json` |
| `results_v2.json` | Final Python benchmark data (authoritative for Table 3) |
| `native_results_sessions.json` | Final native benchmark, 3 sessions (Table 4) |
| `native_results_sessions_old_defective.json` | Archived *defective* (concurrently contaminated) session, kept as evidence |
| `native_bench/` | Native C harness + PQClean integration (build output excluded) |
| `vectors/` | KAT vectors + provenance manifest |
| `artifact/` | Reproducibility package (original defect files, before-fix patch, README, environment) |
| `legacy/` | Superseded early-stage experiment files (kept for traceability) |

The manuscript, review reports, and `render_html.py` are in the sibling
repository `../hash-based-signature-paper/` (subdirectory `docs/review/` for
the review record).

## Reproduce

All timings in the paper come from the recorded snapshots in
`results_v2.json` and `native_results_sessions.json`; the commands below
regenerate them. Everything runs on Python stdlib only; figures need
matplotlib/numpy; the native benchmark needs a C compiler. For a one-command
evidence gate use `make reproduce` (tests + checksum audit + leaf equivalence
+ mutation tests + forgery reproduction + state demo + manifest).

```bash
python3 wots.py          # self-test (incl. checksum boundary tests)
python3 make_kat.py      # regenerate KAT vector -> kat_wots.json
python3 experiment_v2.py # benchmark -> results_v2.json
python3 ref_verify.py    # independent cross-validation of the KAT
python3 experiments/reproduce_checksum_bug.py  # F1 defect reproduction
python3 experiments/audit_checksum_rfc.py      # exhaustive checksum audit vs. RFC 8391 -> results/checksum_rfc_audit.json
python3 experiments/leaf_equivalence.py        # explicit/compact equivalence over all 128 leaves of h=7 -> results/leaf_equivalence.json
python3 experiments/mutation_test_checksum.py  # 3 encoder mutants, differential + suite detection -> results/mutation_test_checksum.json
python3 experiments/state_stress.py            # randomized scheduling stress (1000x8 = 8000 reservations, restart-verified) -> results/state_stress.json
python3 experiments/benchmark_state.py         # allocator reserve+persist overhead (separate from §5 latencies) -> results/state_overhead.json
python3 experiments/benchmark.py --reps 101     # standardized timing -> results/raw/
python3 experiments/make_manifest.py            # regenerate vectors/manifest.json
python -m pytest -q tests/                      # full correctness + property + negative suite (123 tests)
python3 state_demo/test_state.py                # durable-state fault injection (10/10)
```

Native C benchmark (Apple clang; builds PQClean *clean* implementations):

```bash
cd native_bench && ./build.sh   # clones PQClean @ 0586a82, builds, writes native_results.json
```

## Key evidence

- **Checksum encoding equivalence** — `experiments/audit_checksum_rfc.py` is an
  independent RFC 8391 reference encoder (Algorithm 1 base_w + Algorithm 5
  checksum path). Exhaustive comparison over all `c ∈ [0, 960]`: **961/961,
  zero mismatches** (`results/checksum_rfc_audit.json`, per-value table
  included). PQClean's `wots.c` uses the identical shift/pack/extract path.
- **Explicit/compact equivalence** — `experiments/leaf_equivalence.py`
  verifies both formats over **all 128 leaves** of the `h=7` tree: 1,536
  checks (verification, `pkFromSig` equality, tamper/truncation/index
  rejection), zero failures (`results/leaf_equivalence.json`).
- **Mutation testing** — `experiments/mutation_test_checksum.py` injects three
  single-point mutants (wrong base, reversed digits, zero-padded buffer); all
  are caught by both the exhaustive differential and the test suite
  (`results/mutation_test_checksum.json`).
- **State reliability** — `state_demo/test_state.py` (10/10) covers every
  point of the reserve-then-sign path: concurrency, crash-before-reserve,
  crash-after-reserve, crash-after-signing, log tampering, truncation,
  rollback detection, capacity enforcement, and cross-reopen persistence.
  `experiments/state_stress.py` adds randomized scheduling stress: 1,000 rounds
  × 8 concurrent child processes with random delays, restart-verified after
  each round — **8,000 reservations, 0 duplicate indices, 0 reload
  mismatches, 1,000/1,000 restart rounds reject reuse**
  (`results/state_stress.json`).
- **State overhead** — `experiments/benchmark_state.py` measures the
  allocator's reserve-and-persist path separately (~0.68 ms median, incl.
  3× fsync); this cost is deliberately **not** folded into the §5 signature
  latencies (`results/state_overhead.json`).
- **Forgery experiment** — `experiments/forgery_results.json`: buggy signatures
  accepted 20/20 by the buggy verifier, rejected 20/20 by the independent
  verifier; raw `sk[64..66]` leaked 10/10 (buggy) vs 0/10 (fixed); Monte-Carlo
  forgery-condition search: 0 hits in 20,000 message pairs.
- **KAT anchors** — `kat_wots.json` (sha16 `ee98e45bce997e59`) and
  `vectors/kat.json`; provenance manifest in `vectors/manifest.json`.
- **Reproducibility** — `artifact/` (original defect files, before-fix patch,
  environment record) and the review record in
  `../hash-based-signature-paper/docs/review/`; file digests pinned in the
  manuscript's Appendix C (paths relative to this repository).

## License

MIT — see `LICENSE`. Research prototype; **not for production use**.

## Disclaimer

This is a research artifact. It does not establish security, a security level,
or conformance to WOTS+ / XMSS / LMS / FIPS 205 / RFC 8391. Stateful
hash-based signatures require production-grade state management; see §6.2 of
the paper for the durable-state discussion.
