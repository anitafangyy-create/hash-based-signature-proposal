"""run_sessions.py — run the native benchmark in N independent sessions.

Each session invokes the five pre-built executables in a rotated order (to
spread thermal/frequency effects across schemes) with a cooldown between
sessions. Per-session medians are then summarised across sessions: the
cross-session median plus the min/max range, which is the honest way to
report a benchmark on an unpinned host.

Usage:
    python3 native_bench/run_sessions.py /path/to/dir/with/binaries
"""
from __future__ import annotations

import json
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORK = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "_build"
OUT = HERE.parent / "native_results_sessions.json"

BINS = {
    "mldsa44": "bench_mldsa44",
    "mldsa65": "bench_mldsa65",
    "sphincs128f": "bench_sphincs128f",
    "sphincs128s": "bench_sphincs128s",
    "proto": "bench_proto",
}

# Rotated orders: the heavy 128s run appears at different positions so that no
# single scheme is always measured on a cold / hot machine.
ORDERS = [
    ["mldsa44", "mldsa65", "sphincs128f", "sphincs128s", "proto"],
    ["proto", "sphincs128s", "sphincs128f", "mldsa65", "mldsa44"],
    ["mldsa65", "sphincs128s", "mldsa44", "sphincs128f", "proto"],
]
COOLDOWN_S = 12


def key_of(r: dict) -> str:
    if "scheme" in r:
        return r["scheme"]
    return f'{r["kind"]}|{r["compact"]}|{r["h"]}'


def main() -> None:
    sessions = []
    for si, order in enumerate(ORDERS, 1):
        if si > 1:
            print(f"[cooldown] {COOLDOWN_S}s before session {si}", flush=True)
            time.sleep(COOLDOWN_S)
        rows = []
        for name in order:
            exe = WORK / BINS[name]
            if not exe.exists():
                raise SystemExit(f"missing binary: {exe}")
            out = subprocess.check_output([str(exe)], text=True)
            for line in out.splitlines():
                if line.strip():
                    rows.append(json.loads(line))
        sessions.append({"session": si, "order": order, "rows": rows})
        print(f"[session {si}] {len(rows)} rows", flush=True)

    # ---- summarise across sessions -------------------------------------
    per_key = defaultdict(dict)  # key -> session -> row (first row per session)
    for s in sessions:
        for r in s["rows"]:
            per_key[key_of(r)].setdefault(s["session"], r)

    summary = {}
    for k, by_session in per_key.items():
        entry = {}
        for metric in ("keygen_ms", "sign_ms", "verify_ms"):
            vals = [by_session[si][metric] for si in sorted(by_session)
                    if metric in by_session[si]]
            if not vals:
                continue
            med = statistics.median(vals)
            entry[metric] = {
                "session_medians": vals,
                "median": med,
                "min": min(vals),
                "max": max(vals),
                "spread_pct": ((max(vals) - min(vals)) / med * 100.0) if med else 0.0,
            }
        first = by_session[sorted(by_session)[0]]
        for f in ("scheme", "kind", "compact", "h", "pk", "sk", "sig", "sig_bytes"):
            if f in first:
                entry[f] = first[f]
        summary[k] = entry

    out = {
        "environment": {
            "cpu": "Apple M1 (arm64)",
            "compiler": "Apple clang 17.0.0",
            "pqclean_commit": "0586a82",
            "sessions": len(ORDERS),
            "cooldown_s": COOLDOWN_S,
            "reps_standards": 31,
            "reps_prototype": 31,
            "message_bytes": 64,
            "timing": "clock_gettime(CLOCK_MONOTONIC)",
            "note": ("Rotated session order; no CPU pinning; PQClean clean C. "
                     "Reported values are cross-session medians with the "
                     "min/max range across the per-session medians."),
        },
        "sessions": sessions,
        "summary": summary,
    }
    OUT.write_text(json.dumps(out, indent=2))
    print(f"[written] {OUT}", flush=True)


if __name__ == "__main__":
    main()
