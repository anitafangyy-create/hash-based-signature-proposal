# Hash-Based Post-Quantum Signature Proposal — Early-Stage Work

Companion materials for the early-stage manuscript

> **A Compact Hash-Based Post-Quantum Signature Scheme: Lamport–WOTS+ with Merkle Trees and an Empirical Comparison Against NIST Standards**

This repository contains the research-prototype implementation, experiments,
figures, and draft manuscript from the **initial scheme-proposal direction**
of the project. This direction was superseded: review feedback concluded the
work should be positioned as an implementation audit rather than a new
signature scheme. The current submission manuscript lives in the sibling
repository `../jce-implementation-audit/`; this repository is kept for
traceability and should not be read as the project's final conclusions.

## Contents (flat layout, as originally developed)

| File | Purpose |
|---|---|
| `paper.md` / `paper.html` | Early draft manuscript |
| `wots.py`, `hbs_signature.py`, `wots_bench.c` | Core prototype implementation (Lamport OTS / WOTS+ / Merkle) |
| `experiment.py` / `results.json` | v1 Lamport experiments |
| `experiment_v2.py` / `results_v2.json` | v2 Lamport vs WOTS+ experiments |
| `bench_1000runs.json` | 1,000-run benchmark record |
| `unified_merkle_tree.py` / `unified_tree_results.json` | Unified Merkle-tree experiments |
| `make_charts.py`, `make_charts_v2.py` | Figure generation (needs matplotlib/numpy) |
| `fig1_signature_size.png` … `fig7_latency_v2.png` | Generated figures |
| `render_html.py` | Markdown → HTML rendering (pure stdlib) |
| `_rewrite_jisa.py` | Draft rewriting helper |

## Reproduce

```bash
python3 wots.py                  # WOTS+ self-check
python3 hbs_signature.py         # Lamport + Merkle self-check
python3 experiment.py            # v1 experiments -> results.json (overwrites)
python3 experiment_v2.py         # v2 experiments -> results_v2.json (overwrites)
python3 unified_merkle_tree.py   # Merkle-tree experiments
python3 make_charts.py           # figures (needs matplotlib)
python3 render_html.py           # paper.md -> paper.html
```

## License

MIT, see `LICENSE`. Research prototype; **not for production use**.

## Disclaimer

This is an early research draft. It does not establish security, a security
level, or conformance to WOTS+/XMSS/LMS. Numbers reported here were produced
by the early implementation and have been superseded by the audited
measurements in `../jce-implementation-audit/`.
