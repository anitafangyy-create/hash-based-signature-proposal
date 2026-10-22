"""
state_stress.py — randomized scheduling stress test for the durable allocator.

Each round launches `P` child processes that reserve one leaf each after a
per-process random delay (a test-only pause point), then restarts the
allocator and asserts (a) no duplicate leaves within the round, (b) the
reloaded used-set matches the allocated leaves, and (c) every used leaf is
rejected by reserve_specific after restart. The random seed is fixed so a
failure is reproducible.

Usage:
    python3 experiments/state_stress.py [--rounds N] [--processes P] [--seed S]
Output: results/state_stress.json (deterministic given the seed).
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE.parent / "state_demo"))

from durable_state import DurableState, ReuseDenied  # noqa: E402

CAP = 2048
_PY = sys.executable


def _child_reserve_sleep(d: str, h: str, delay_ms: str) -> None:
    time.sleep(int(delay_ms) / 1000.0)  # test-only pause before reserving
    with DurableState(d, CAP, h) as s:
        leaf = s.reserve()
    print(leaf, flush=True)


def run_round(tmp: Path, nproc: int, rng: random.Random) -> dict:
    d, h = tmp / "state", tmp / "state.hwm"
    delays = [rng.randrange(0, 21) for _ in range(nproc)]  # 0–20 ms
    procs = [
        subprocess.Popen(
            [_PY, __file__, "--child-reserve-sleep", str(d), str(h), str(delay)],
            stdout=subprocess.PIPE, text=True)
        for delay in delays
    ]
    leaves = []
    for p in procs:
        out, _ = p.communicate()
        if p.returncode != 0:
            return {"round": None, "ok": False, "reason": "child failed"}
        leaves.append(int(out.strip().splitlines()[-1]))
    duplicates = nproc - len(set(leaves))
    with DurableState(d, CAP, h) as s:
        reloaded = s.used_leaves()
        reused = 0
        for leaf in leaves:
            try:
                s.reserve_specific(leaf)
            except ReuseDenied:
                reused += 1
        ok = duplicates == 0 and reloaded == set(leaves) and reused == nproc
        return {
            "ok": ok,
            "duplicates": duplicates,
            "reloaded_matches": reloaded == set(leaves),
            "reuse_rejected_after_restart": reused == nproc,
            "delays_ms": delays,
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=50)
    ap.add_argument("--processes", type=int, default=8)
    ap.add_argument("--seed", type=int, default=20261022)
    ap.add_argument("--child-reserve-sleep", nargs=3)
    a = ap.parse_args()

    if a.child_reserve_sleep:
        _child_reserve_sleep(*a.child_reserve_sleep)
        return 0

    rng = random.Random(a.seed)
    root = Path(tempfile.mkdtemp(prefix="hbs_stress_"))
    rounds = []
    for i in range(a.rounds):
        r = run_round(root / f"r{i}", a.processes, rng)
        r["round"] = i
        rounds.append(r)

    n_ok = sum(1 for r in rounds if r["ok"])
    summary = {
        "rounds": a.rounds,
        "processes_per_round": a.processes,
        "seed": a.seed,
        "total_reservations": a.rounds * a.processes,
        "failed_rounds": a.rounds - n_ok,
        "duplicate_leaves_total": sum(r["duplicates"] for r in rounds),
        "reload_mismatches": sum(0 if r["reloaded_matches"] else 1 for r in rounds),
        "reuse_rejections_after_restart_total": sum(r["reuse_rejected_after_restart"] for r in rounds),
        "all_passed": n_ok == a.rounds,
        "generated": "deterministic",
    }
    out = {"summary": summary, "rounds": rounds}
    results = ROOT / "results"
    results.mkdir(exist_ok=True)
    (results / "state_stress.json").write_text(
        json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary))
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
