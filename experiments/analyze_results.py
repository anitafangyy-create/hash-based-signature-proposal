"""
analyze_results.py — statistics for the F3 benchmark.

Reads the raw per-iteration samples retained in ``results_v2.json`` and
reports, for every (kind, height, mode) x (keygen, sign, verify):

    n, median, IQR, P95, and a bootstrap 95% confidence interval for the median.

Reporting only the median (as an earlier draft did) hides dispersion on an
unpinned host; a bootstrap CI on the median is the honest way to say how
precise the point estimate actually is.

Run:  python experiments/analyze_results.py
Writes: results/bench_stats.csv, results/bench_stats.json
"""

from __future__ import annotations

import csv
import json
import random
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "results_v2.json"
OUT_DIR = ROOT / "results"
OUT_DIR.mkdir(exist_ok=True)

BOOTSTRAP = 2000
SEED = 20261022


def percentile(sorted_xs: list[float], p: float) -> float:
    """Linear-interpolation percentile on a pre-sorted list."""
    if not sorted_xs:
        return float("nan")
    idx = p * (len(sorted_xs) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(sorted_xs) - 1)
    return sorted_xs[lo] + (idx - lo) * (sorted_xs[hi] - sorted_xs[lo])


def iqr(sorted_xs: list[float]) -> float:
    return percentile(sorted_xs, 0.75) - percentile(sorted_xs, 0.25)


def bootstrap_ci_median(xs: list[float], rounds: int = BOOTSTRAP,
                        seed: int = SEED) -> tuple[float, float]:
    """Percentile bootstrap confidence interval for the median."""
    rng = random.Random(seed)
    meds = []
    n = len(xs)
    for _ in range(rounds):
        sample = [xs[rng.randrange(n)] for _ in range(n)]
        meds.append(statistics.median(sample))
    meds.sort()
    return percentile(meds, 0.025), percentile(meds, 0.975)


def mode_name(row: dict) -> str:
    return "compact" if row.get("compact") else "explicit"


def main() -> None:
    rows = json.loads(SRC.read_text())
    rng = random.Random(SEED)
    out = []
    for r in rows:
        for op, key in (("keygen", "raw_key_gen_ms"),
                        ("sign", "raw_sign_ms"),
                        ("verify", "raw_verify_ms")):
            raw = r.get(key)
            if not raw:
                continue
            s = sorted(raw)
            lo, hi = bootstrap_ci_median(raw, seed=rng.randrange(10**9))
            out.append({
                "kind": r["kind"],
                "mode": mode_name(r),
                "height": r["height"],
                "operation": op,
                "samples": len(s),
                "median_ms": round(statistics.median(s), 4),
                "iqr_ms": round(iqr(s), 4),
                "p95_ms": round(percentile(s, 0.95), 4),
                "ci95_low_ms": round(lo, 4),
                "ci95_high_ms": round(hi, 4),
                "min_ms": round(s[0], 4),
                "max_ms": round(s[-1], 4),
            })

    (OUT_DIR / "bench_stats.json").write_text(json.dumps(out, indent=2))
    with (OUT_DIR / "bench_stats.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)

    print(f"{'kind':<8}{'mode':<9}{'h':>2} {'op':<7}{'n':>5}"
          f"{'median':>10}{'p95':>10}   95% CI")
    for o in out:
        if o["height"] in (1, 7):
            print(f"{o['kind']:<8}{o['mode']:<9}{o['height']:>2} "
                  f"{o['operation']:<7}{o['samples']:>5}"
                  f"{o['median_ms']:>10.3f}{o['p95_ms']:>10.3f}   "
                  f"[{o['ci95_low_ms']:.3f}, {o['ci95_high_ms']:.3f}]")
    print(f"\n[written] {OUT_DIR/'bench_stats.csv'} ({len(out)} rows)")
    print(f"[written] {OUT_DIR/'bench_stats.json'}")


if __name__ == "__main__":
    main()
