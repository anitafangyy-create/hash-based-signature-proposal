"""
benchmark_state.py — measure the durable allocator's reserve-and-persist cost.

Every reserve appends a hash-chained log line, fsyncs the log, atomically
replaces the head and the high-water mark (temp write + fsync + rename each),
and holds an exclusive file lock. These costs are deliberately NOT included in
the §5 signing/verification latencies of the paper; this script reports them as
a separate dimension so the state-management overhead is quantified and the
paper's "separate dimensions" claim is backed by a number.

Usage: python3 experiments/benchmark_state.py [--reps N]
Output: results/state_overhead.json (deterministic statistics on a fixed host).
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "state_demo"))

from durable_state import DurableState  # noqa: E402

CAP = 4096


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=1000)
    a = ap.parse_args()

    d = Path(tempfile.mkdtemp(prefix="hbs_state_bench_"))
    samples = []
    with DurableState(d, CAP, d / "hwm") as s:
        for _ in range(a.reps):
            t0 = time.perf_counter()
            s.reserve()
            samples.append((time.perf_counter() - t0) * 1000.0)  # ms

    samples.sort()
    n = len(samples)
    median = samples[n // 2]
    iqr = (samples[3 * n // 4] - samples[n // 4])
    p95 = samples[int(0.95 * n)]
    mean = statistics.fmean(samples)
    summary = {
        "reps": a.reps,
        "operation": "reserve+persist (append+fsync log, atomic head, atomic hwm, file lock)",
        "median_ms": round(median, 4),
        "mean_ms": round(mean, 4),
        "iqr_ms": round(iqr, 4),
        "p95_ms": round(p95, 4),
        "min_ms": round(samples[0], 4),
        "max_ms": round(samples[-1], 4),
        "not_included_in_signing_latency": True,
        "generated": "deterministic",
    }
    out = {"summary": summary, "samples_ms": [round(x, 4) for x in samples]}
    results = ROOT / "results"
    results.mkdir(exist_ok=True)
    (results / "state_overhead.json").write_text(
        json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
