"""
experiments/make_manifest.py — generate vectors/manifest.json.

Records the provenance needed to reproduce every experimental result: source
revision, interpreter/compiler versions, build parameters, the KAT DRBG seed,
the test timestamp, and SHA-256 digests of the primary inputs (reviewer §5,
"manifest.json" requirement). Run after any change to the cited files.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors"
VECTORS.mkdir(exist_ok=True)


def _git_head() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return "uncommitted-working-tree"


def _clang_version() -> str:
    try:
        out = subprocess.run(
            ["clang", "--version"], capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.splitlines()[0].strip()
    except Exception:
        pass
    return "Apple clang (version not probed)"


def _sha256(path: Path) -> str:
    if not path.exists():
        return "MISSING"
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main():
    files = [
        "wots.py", "hbs_signature.py", "experiment_v2.py", "ref_verify.py",
        "kat_wots.json",
        "native_bench/bench_proto.c", "native_bench/bench_std.c",
        "native_bench/build.sh",
        "experiments/audit_checksum_rfc.py", "results/checksum_rfc_audit.json",
        "experiments/leaf_equivalence.py", "results/leaf_equivalence.json",
        "experiments/mutation_test_checksum.py", "results/mutation_test_checksum.json",
    ]
    inputs = {f: _sha256(ROOT / f) for f in files}

    manifest = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_revision": _git_head(),
        "interpreter": {
            "python": sys.version.split()[0],
            "implementation": sys.implementation.name,
        },
        "compiler": {
            "name": _clang_version(),
            "flags": "-O3 -std=c99",
        },
        "external": {
            "pqclean_commit": "0586a82",
            "pqclean_variant": "clean (portable C, not AVX2)",
        },
        "kat": {
            "drbg": "SHA-256 counter mode",
            "seed": "HBS-PQ-WOTS-KAT-v1-2026",
            "message_hex": "506f73742d7175616e74756d207369676e6174757265204b4154"
                          "20766563746f72202330",
            "file": "kat_wots.json",
            "sha256": inputs["kat_wots.json"],
        },
        "pytest_seed_note": (
            "pytest is run with default RNG; checksum/signature tests use fixed "
            "seeds (Random(1234) in test_checksum.py, Random(20261021) in "
            "test_signature_properties.py) so results are deterministic."),
        "input_digests_sha256": inputs,
        "result_artifacts": {
            "python_benchmark": "results_v2.json",
            "native_benchmark": "native_results_sessions.json",
            "native_raw_sessions": "native_bench/run_sessions.py",
            "checksum_repro": "experiments/reproduce_checksum_bug.py",
            "f1_evidence": "artifact/results/f1_evidence.json",
            "benchmark_raw": "results/raw/benchmark_raw.json",
        },
        "note": (
            "This manifest ties every reported number to a specific code "
            "revision and input. Python and native C measurements are kept in "
            "separate files and never mixed (see paper §5.1 and §5.5)."),
    }

    out = VECTORS / "manifest.json"
    out.write_text(json.dumps(manifest, indent=2))
    print(f"wrote {out}")
    print(json.dumps(manifest, indent=2)[:600] + "\n...")


if __name__ == "__main__":
    main()
