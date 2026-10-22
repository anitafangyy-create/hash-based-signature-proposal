"""
test_state.py — fault-injection tests for the durable one-time-key allocator.

Tests (10 fault-injection scenarios, each logged as structured JSON):
  1. reuse denied (durable allocator and the deployment MSS API)
  2. crash after reserve burns the leaf; it is never reused        [S3]
  3. partial rollback (restoring an older state dir) is detected  [S7]
  4. concurrent reservations are distinct (exclusive file lock)   [S1]
  5. a tampered log entry is detected (hash chain)                [S6]
  6. capacity is enforced                                         [S8]
  7. durable state persists across re-open (on-disk high-water mark)
  8. log truncation detected (head pointing past the log)         [S7]
  9. crash before reserve: state untouched, allocator continues   [S2]
 10. crash after signing: burned leaf never reused                [S4/S5]

Usage: python3 state_demo/test_state.py
Exit code 0 iff all tests pass. Structured per-scenario and summary logs are
emitted as JSON lines (machine-readable) in addition to the human summary.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

from durable_state import (  # noqa: E402
    DurableState,
    ReuseDenied,
    RollbackDetected,
    TamperDetected,
    CapacityExhausted,
)

CAP = 16


def _child_reserve(d: str, h: str) -> None:
    with DurableState(d, CAP, h) as s:
        leaf = s.reserve()
    print(leaf, flush=True)


def _child_crash(d: str, h: str) -> None:
    s = DurableState(d, CAP, h)
    s.__enter__()
    leaf = s.reserve()
    print(leaf, flush=True)
    os._exit(1)  # simulate a crash after reservation, before signing


def _child_crash_before_reserve(d: str, h: str) -> None:
    # S2: crash before any reservation — no state change must occur.
    s = DurableState(d, CAP, h)
    s.__enter__()
    print("ready", flush=True)
    os._exit(1)


def _child_sign_crash(d: str, h: str) -> None:
    # S4/S5: reserve, complete signing, then crash before returning the
    # signature. The burned leaf must never be reallocated on restart.
    sys.path.insert(0, str(ROOT))
    from hbs_signature import MerkleSignatureScheme
    s = DurableState(d, CAP, h)
    s.__enter__()
    leaf = s.reserve()
    MerkleSignatureScheme(height=4).sign(b"m", leaf)  # signing completes
    print(leaf, flush=True)
    os._exit(1)  # crash after signing, before the result is returned


def _main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--child-reserve", nargs=2)
    ap.add_argument("--child-crash", nargs=2)
    ap.add_argument("--child-crash-before", nargs=2)
    ap.add_argument("--child-sign-crash", nargs=2)
    a = ap.parse_args()
    if a.child_reserve:
        _child_reserve(*a.child_reserve)
        return 0
    if a.child_crash:
        _child_crash(*a.child_crash)
        return 0
    if a.child_crash_before:
        _child_crash_before_reserve(*a.child_crash_before)
        return 0
    if a.child_sign_crash:
        _child_sign_crash(*a.child_sign_crash)
        return 0

    root = Path(tempfile.mkdtemp(prefix="hbs_state_demo_"))
    results = []

    def check(name, fn):
        try:
            fn()
            results.append((name, True, ""))
            print(f"[PASS] {name}")
            print(json.dumps({"scenario": name, "status": "PASS"}))
        except Exception as e:  # noqa: BLE001
            results.append((name, False, f"{type(e).__name__}: {e}"))
            print(f"[FAIL] {name}: {type(e).__name__}: {e}")
            print(json.dumps({"scenario": name, "status": "FAIL",
                              "error": f"{type(e).__name__}: {e}"}))

    # 1. reuse denied -------------------------------------------------
    def t_reuse():
        d, h = root / "reuse", root / "reuse.hwm"
        with DurableState(d, CAP, h) as s:
            leaf = s.reserve()
        with DurableState(d, CAP, h) as s2:
            try:
                s2.reserve_specific(leaf)
            except ReuseDenied:
                pass
            else:
                raise AssertionError("durable allocator allowed reuse")
        from hbs_signature import MerkleSignatureScheme
        mss = MerkleSignatureScheme(height=4)
        mss.sign(b"m", leaf)
        try:
            mss.sign(b"m", leaf)
        except ValueError:
            pass
        else:
            raise AssertionError("MSS allowed one-time-key reuse")
    check("reuse denied (allocator + MSS)", t_reuse)

    # 2. crash burns the leaf ----------------------------------------
    def t_crash():
        d, h = root / "crash", root / "crash.hwm"
        p = subprocess.run(
            [sys.executable, __file__, "--child-crash", str(d), str(h)],
            capture_output=True, text=True)
        if p.returncode == 0:
            raise AssertionError("child was expected to crash")
        burned = int(p.stdout.strip().splitlines()[-1])
        with DurableState(d, CAP, h) as s:
            if burned not in s.used_leaves():
                raise AssertionError("burned leaf not recorded")
            nxt = s.reserve()
            if nxt == burned:
                raise AssertionError("burned leaf was reused")
    check("crash after reserve burns leaf (no reuse)", t_crash)

    # 3. partial rollback detected ------------------------------------
    def t_rollback():
        d, h = root / "rb", root / "rb.hwm"
        with DurableState(d, CAP, h) as s:
            s.reserve()
        backup = root / "rb_backup"
        shutil.copytree(d, backup)
        with DurableState(d, CAP, h) as s:
            s.reserve()
        shutil.rmtree(d)
        shutil.copytree(backup, d)  # restore older state; hwm survives
        try:
            with DurableState(d, CAP, h):
                pass
        except RollbackDetected:
            pass
        else:
            raise AssertionError("rollback not detected")
    check("partial rollback detected (high-water mark)", t_rollback)

    # 4. concurrent reservations distinct -----------------------------
    def t_concurrent():
        d, h = root / "cc", root / "cc.hwm"
        n = 8
        procs = [
            subprocess.Popen(
                [sys.executable, __file__, "--child-reserve", str(d), str(h)],
                stdout=subprocess.PIPE, text=True)
            for _ in range(n)
        ]
        leaves = []
        for p in procs:
            out, _ = p.communicate()
            if p.returncode != 0:
                raise AssertionError("child reserve failed")
            leaves.append(int(out.strip().splitlines()[-1]))
        if len(set(leaves)) != n:
            raise AssertionError(f"duplicate leaves: {leaves}")
        with DurableState(d, CAP, h) as s:
            if s.used_leaves() != set(leaves):
                raise AssertionError("state disagrees with allocated leaves")
    check(f"concurrent reservations distinct (n={8})", t_concurrent)

    # 5. tampered log detected ----------------------------------------
    def t_tamper():
        d, h = root / "tp", root / "tp.hwm"
        with DurableState(d, CAP, h) as s:
            s.reserve()
        with open(d / "consumed.log", "a") as f:
            f.write(json.dumps({"seq": 2, "leaf": 5,
                                "prev": "00" * 32, "hash": "00" * 32}) + "\n")
        try:
            with DurableState(d, CAP, h):
                pass
        except TamperDetected:
            pass
        else:
            raise AssertionError("tamper not detected")
    check("tampered log detected (hash chain)", t_tamper)

    # 6. capacity enforced --------------------------------------------
    def t_capacity():
        d, h = root / "cap", root / "cap.hwm"
        with DurableState(d, 2, h) as s:
            s.reserve()
            s.reserve()
            try:
                s.reserve()
            except CapacityExhausted:
                pass
            else:
                raise AssertionError("capacity not enforced")
    check("capacity enforced", t_capacity)

    # 7. durable state persists across re-open --------------------------
    def t_persist():
        d, h = root / "persist", root / "persist.hwm"
        with DurableState(d, CAP, h) as s:
            a = s.reserve()
            b = s.reserve()
        # new handle on the same on-disk state (simulates a fresh process)
        with DurableState(d, CAP, h) as s2:
            if s2.used_leaves() != {a, b}:
                raise AssertionError("persisted state not reloaded")
            c = s2.reserve()
            if c in (a, b):
                raise AssertionError("reused a persisted leaf")
            if s2.used_leaves() != {a, b, c}:
                raise AssertionError("used-set inconsistent after re-open")
    check("durable state persists across re-open", t_persist)

    # 8. log truncation detected ----------------------------------------
    def t_truncate():
        d, h = root / "trunc", root / "trunc.hwm"
        with DurableState(d, CAP, h) as s:
            s.reserve()
            s.reserve()
        # drop the last committed log line so the persisted head points past
        # the log; reload must raise TamperDetected rather than silently heal.
        lines = (d / "consumed.log").read_text().splitlines()
        (d / "consumed.log").write_text("\n".join(lines[:-1]) + "\n")
        try:
            with DurableState(d, CAP, h):
                pass
        except TamperDetected:
            pass
        else:
            raise AssertionError("log truncation not detected")
    check("log truncation detected (head beyond log)", t_truncate)

    # 9. crash before reserve: no state change ---------------------------
    def t_crash_before():
        d, h = root / "cb", root / "cb.hwm"
        p = subprocess.run(
            [sys.executable, __file__, "--child-crash-before", str(d), str(h)],
            capture_output=True, text=True)
        if p.returncode == 0:
            raise AssertionError("child was expected to crash")
        if "ready" not in p.stdout:
            raise AssertionError("child did not reach the ready point")
        with DurableState(d, CAP, h) as s:
            if s.used_leaves() != set():
                raise AssertionError("crash before reserve left state behind")
            first = s.reserve()
            if first != 0:
                raise AssertionError("allocator did not start from leaf 0")
    check("crash before reserve leaves state untouched (S2)", t_crash_before)

    # 10. crash after signing: burned leaf never reused -------------------
    def t_sign_crash():
        d, h = root / "sc", root / "sc.hwm"
        p = subprocess.run(
            [sys.executable, __file__, "--child-sign-crash", str(d), str(h)],
            capture_output=True, text=True)
        if p.returncode == 0:
            raise AssertionError("child was expected to crash")
        burned = int(p.stdout.strip().splitlines()[-1])
        with DurableState(d, CAP, h) as s:
            if burned not in s.used_leaves():
                raise AssertionError("burned leaf not recorded after signing")
            nxt = s.reserve()
            if nxt == burned:
                raise AssertionError("post-signing crash reallocated the used leaf")
    check("crash after signing never reallocates the used leaf (S4/S5)", t_sign_crash)

    ok = sum(1 for _, o, _ in results if o)
    summary = {
        "passed": ok,
        "total": len(results),
        "all_passed": ok == len(results),
        "scenarios": [n for n, o, _ in results if o],
    }
    print(json.dumps({"summary": summary}))
    print(f"\n{ok}/{len(results)} tests passed")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(_main())
