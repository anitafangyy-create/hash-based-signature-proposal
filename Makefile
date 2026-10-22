# One-command reproduction entry points.
#
#   make reproduce   -> full correctness gate: tests + checksum audits +
#                       forgery reproduction + state demo + leaf equivalence
#   make verify      -> fast gate: pytest + state demo (no experiments)
#   make benchmark   -> Python benchmark harness (writes results_v2.json)
#   make benchmark-native -> C benchmark (native_bench/build.sh)
#   make analyze     -> recompute summary statistics from raw samples
#
# Every target fails with a non-zero exit code on the first error.

.PHONY: reproduce verify benchmark benchmark-native analyze manifest stress

PY ?= python3
# Default stress size matches the paper's reported evidence (1000 rounds x 8
# processes = 8000 reservations, restart-verified). Use STRESS_ROUNDS=50 for a
# fast gate; the paper/README/reproduce default stays at 1000.
STRESS_ROUNDS ?= 1000
STRESS_PROCS ?= 8

reproduce: ## full correctness gate (no timing benchmarks)
	$(PY) experiments/audit_checksum_rfc.py
	$(PY) experiments/leaf_equivalence.py
	$(PY) experiments/mutation_test_checksum.py
	$(PY) experiments/reproduce_checksum_bug.py
	$(PY) -m pytest -q tests/
	$(PY) state_demo/test_state.py
	$(PY) experiments/state_stress.py --rounds $(STRESS_ROUNDS) --processes $(STRESS_PROCS)
	$(PY) experiments/make_manifest.py

stress: ## randomized scheduling stress (STRESS_ROUNDS / STRESS_PROCS)
	$(PY) experiments/state_stress.py --rounds $(STRESS_ROUNDS) --processes $(STRESS_PROCS)

verify: ## fast gate for CI / day-to-day changes
	$(PY) -m pytest -q tests/
	$(PY) state_demo/test_state.py

benchmark: ## Python benchmark -> results_v2.json (overwrites recorded snapshot)
	$(PY) experiment_v2.py

benchmark-native: ## native C benchmark -> native_results.json
	cd native_bench && ./build.sh

analyze: ## recompute bench_stats from raw samples
	$(PY) experiments/benchmark.py --reps 101
	$(PY) experiments/analyze_results.py

manifest: ## refresh provenance manifest
	$(PY) experiments/make_manifest.py
