"""
artifact/experiments/summarize.py — benchmark summarizer (P1-1).

Reads the merged native benchmark JSON produced by native_bench/build.sh
(default: ../../native_results.json, i.e. repo-root native_results.json) and
re-derives robust statistics from the per-iteration raw timings so the
reported numbers are reproducible and not dependent on the C harness's own
pre-aggregation.

Outputs:
  * artifact/results/bench_summary.csv  — one row per (scheme/kind, h, mode)
  * a Markdown summary table printed to stdout.

Statistics per phase (keygen / sign / verify):
  * median_ms : median of per-iteration timings (ms)
  * iqr_ms    : inter-quartile range (Q3 - Q1), ms
  * p95_ms    : 95th percentile (linear interpolation), ms  [blank if no raw]

When the source JSON lacks a ``*_raw_us`` array (older runs), the median/IQR
are taken from the pre-aggregated ``*_ms`` fields and p95 is left blank.

Config table (experiment parameters, mirrored from the harness):
  n (message bytes) : 64
  reps              : 31        (per-phase timing samples)
  warm-up           : 3 iters   (keygen + sign + verify, UNIFIED across proto & std)
  compiler          : clang -O3 (portable C, no AVX2)
  timing            : clock_gettime(CLOCK_MONOTONIC)
  PQClean pin       : see environment.pqclean_commit in the JSON
"""

import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_IN = os.path.join(REPO_ROOT, "native_results.json")
OUT_CSV = os.path.join(REPO_ROOT, "artifact", "results", "bench_summary.csv")


def _quantile(v, p):
    if not v:
        return None
    s = sorted(v)
    n = len(s)
    idx = p * (n - 1)
    lo = int(idx)
    hi = lo + 1 if lo + 1 < n else n - 1
    return s[lo] + (idx - lo) * (s[hi] - s[lo])


def _stats(entry):
    """Return per-phase (median_ms, iqr_ms, p95_ms) for keygen/sign/verify."""
    out = {}
    for phase in ("keygen", "sign", "verify"):
        raw_key = f"{phase}_raw_us"
        med_key = f"{phase}_ms"
        iqr_key = f"{phase}_iqr"
        if raw_key in entry and entry[raw_key]:
            us = [float(x) for x in entry[raw_key]]
            med = _quantile(us, 0.5)
            q1 = _quantile(us, 0.25)
            q3 = _quantile(us, 0.75)
            p95 = _quantile(us, 0.95)
            out[phase] = (med / 1000.0, (q3 - q1) / 1000.0, p95 / 1000.0)
        else:
            med = entry.get(med_key)
            iqr = entry.get(iqr_key)
            out[phase] = (med, iqr, None)
    return out


def _row(group, label, entry, compact=None, h=None, n=None, sig_bytes=None):
    s = _stats(entry)
    return {
        "group": group,
        "scheme": label,
        "compact": "" if compact is None else ("true" if compact else "false"),
        "h": "" if h is None else h,
        "n": "" if n is None else n,
        "sig_bytes": "" if sig_bytes is None else sig_bytes,
        "keygen_median_ms": s["keygen"][0],
        "keygen_iqr_ms": s["keygen"][1],
        "keygen_p95_ms": s["keygen"][2],
        "sign_median_ms": s["sign"][0],
        "sign_iqr_ms": s["sign"][1],
        "sign_p95_ms": s["sign"][2],
        "verify_median_ms": s["verify"][0],
        "verify_iqr_ms": s["verify"][1],
        "verify_p95_ms": s["verify"][2],
        "verify_ok": entry.get("verify_ok"),
    }


def _fmt(x):
    if x is None or x == "":
        return ""
    if isinstance(x, float):
        return f"{x:.4f}"
    return str(x)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_IN
    with open(src) as fh:
        data = json.load(fh)

    rows = []
    for e in data.get("standards", []):
        rows.append(_row("standard", e.get("scheme", "?"), e))
    for e in data.get("prototype", []):
        rows.append(_row(
            "prototype",
            f"{e.get('kind','?')}{'/compact' if e.get('compact') else ''}",
            e, compact=e.get("compact"), h=e.get("h"),
            n=e.get("n"), sig_bytes=e.get("sig_bytes")))

    cols = ["group", "scheme", "compact", "h", "n", "sig_bytes",
            "keygen_median_ms", "keygen_iqr_ms", "keygen_p95_ms",
            "sign_median_ms", "sign_iqr_ms", "sign_p95_ms",
            "verify_median_ms", "verify_iqr_ms", "verify_p95_ms",
            "verify_ok"]

    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    with open(OUT_CSV, "w") as fh:
        fh.write(",".join(cols) + "\n")
        for r in rows:
            fh.write(",".join(_fmt(r[c]) for c in cols) + "\n")
    print(f"[written] {OUT_CSV}")

    env = data.get("environment", {})
    print("\n=== Experiment configuration ===")
    for k in ("cpu", "compiler", "pqclean_commit", "reps",
              "message_bytes", "timing", "note"):
        if k in env:
            print(f"  {k}: {env[k]}")

    print("\n=== Summary (median [IQR] ms; p95 where available) ===")
    hdr = f"{'scheme':<18} {'mode':>7} {'h':>3} {'kg_med':>9} {'sg_med':>9} {'vf_med':>9} {'vf_p95':>9} {'sig_B':>8} ok"
    print(hdr)
    for r in rows:
        mode = r["compact"] if r["compact"] != "" else "-"
        h = r["h"] if r["h"] != "" else "-"
        sig = r["sig_bytes"] if r["sig_bytes"] != "" else "-"
        print(f"{r['scheme']:<18} {str(mode):>7} {str(h):>3} "
              f"{_fmt(r['keygen_median_ms']):>9} "
              f"{_fmt(r['sign_median_ms']):>9} "
              f"{_fmt(r['verify_median_ms']):>9} "
              f"{_fmt(r['verify_p95_ms']):>9} "
              f"{str(sig):>8} {r['verify_ok']}")


if __name__ == "__main__":
    main()
