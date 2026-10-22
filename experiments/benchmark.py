"""
experiments/benchmark.py — standardized, reproducible timing tool.

Design goals (reviewer §4.3 / §4.6):
  * every timed operation yields RAW samples, retained for re-analysis;
  * a warm-up policy precedes timing so cold-start variance is excluded;
  * GC can be disabled during timing (documented; NOT a production setting);
  * key generation, signing, and verification are timed SEPARATELY;
  * output is median / IQR / P95, plus a CSV and a JSON of raw samples.

This measures the Python prototype only. The native C comparison lives in
``native_bench/``; the two are never mixed (see paper Appendix B and §5.5).
"""

from __future__ import annotations

import argparse
import csv
import gc
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import experiment_v2 as ev  # GenericMSS

MESSAGE = b"benchmark-canonical-message-of-64-bytes-abcdefghijklmnopqrstuvwxyz0123456789"

HEIGHTS = [1, 3, 7]
KINDS = [("wots", "wots")]


def benchmark(operation, warmup: int = 5, repetitions: int = 101,
              disable_gc: bool = True):
    """Time ``operation()``. Returns a list of durations in nanoseconds."""
    for _ in range(warmup):
        operation()
    samples = []
    gc_was_enabled = gc.isenabled()
    try:
        if disable_gc:
            gc.disable()
        for _ in range(repetitions):
            start = time.perf_counter_ns()
            operation()
            end = time.perf_counter_ns()
            samples.append(end - start)
    finally:
        if gc_was_enabled:
            gc.enable()
    return samples


def _percentile(sorted_xs, p):
    if not sorted_xs:
        return 0.0
    idx = round((len(sorted_xs) - 1) * p)
    return sorted_xs[idx]


def summarize(samples_ns):
    xs = sorted(samples_ns)
    return {
        "n": len(xs),
        "median_ms": _percentile(xs, 0.5) / 1e6,
        "iqr_ms": (_percentile(xs, 0.75) - _percentile(xs, 0.25)) / 1e6,
        "p95_ms": _percentile(xs, 0.95) / 1e6,
        "min_ms": xs[0] / 1e6,
        "max_ms": xs[-1] / 1e6,
    }


def run(height: int, kind: str, compact: bool, repetitions: int):
    rows = []
    raw = {}

    # --- key generation (each rep builds 2**height OTS keys + tree) ---
    kg_samples = benchmark(
        lambda: ev.GenericMSS(height, kind, compact),
        warmup=3, repetitions=min(repetitions, 31), disable_gc=True)
    rows.append(("keygen", height, compact, kg_samples))
    raw[f"h{height}_{'compact' if compact else 'explicit'}_keygen_ns"] = kg_samples

    scheme = ev.GenericMSS(height, kind, compact)
    sig = scheme.sign(MESSAGE, 0)

    # --- signing (re-sign the same leaf; no one-time enforcement here) ---
    sg_samples = benchmark(
        lambda: scheme.sign(MESSAGE, 0),
        warmup=3, repetitions=repetitions, disable_gc=True)
    rows.append(("sign", height, compact, sg_samples))
    raw[f"h{height}_{'compact' if compact else 'explicit'}_sign_ns"] = sg_samples

    # --- verification ---
    vf_samples = benchmark(
        lambda: scheme.verify(MESSAGE, sig),
        warmup=3, repetitions=repetitions, disable_gc=True)
    rows.append(("verify", height, compact, vf_samples))
    raw[f"h{height}_{'compact' if compact else 'explicit'}_verify_ns"] = vf_samples

    return rows, raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=101,
                    help="sign/verify repetitions (keygen capped at 31)")
    ap.add_argument("--out-dir", default=str(ROOT / "results" / "raw"))
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_rows = []
    all_raw = {}
    for kind_label, kind in KINDS:
        for height in HEIGHTS:
            for compact in (False, True):
                rows, raw = run(height, kind, compact, args.reps)
                all_raw.update(raw)
                for op, h, c, samples in rows:
                    s = summarize(samples)
                    summary_rows.append({
                        "scheme": f"{kind_label}+MSS",
                        "height": h,
                        "mode": "compact" if c else "explicit",
                        "operation": op,
                        **s,
                    })

    # raw samples
    raw_path = out_dir / "benchmark_raw.json"
    raw_path.write_text(json.dumps(all_raw, indent=2))

    # summary CSV
    csv_path = out_dir / "benchmark_summary.csv"
    fields = ["scheme", "height", "mode", "operation",
              "n", "median_ms", "iqr_ms", "p95_ms", "min_ms", "max_ms"]
    with csv_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in summary_rows:
            w.writerow(r)

    # console
    print(f"Python benchmark (prototype only). reps(sign/verify)={args.reps}, "
          f"reps(keygen)<=31. Warm-up applied; GC disabled during timing.")
    print(f"{'scheme':<12}{'h':>3}{'mode':>10}{'op':>9}"
          f"{'median_ms':>12}{'iqr_ms':>10}{'p95_ms':>10}")
    for r in summary_rows:
        print(f"{r['scheme']:<12}{r['height']:>3}{r['mode']:>10}"
              f"{r['operation']:>9}{r['median_ms']:>12.4f}"
              f"{r['iqr_ms']:>10.4f}{r['p95_ms']:>10.4f}")
    print(f"\nraw samples -> {raw_path}")
    print(f"summary CSV -> {csv_path}")


if __name__ == "__main__":
    main()
