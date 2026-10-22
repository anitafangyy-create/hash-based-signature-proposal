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

.PHONY: reproduce verify benchmark benchmark-native analyze manifest

PY ?= python3

reproduce: ## full correctness gate (no timing benchmarks)
	$(PY) experiments/audit_checksum_rfc.py
	$(PY) experiments/leaf_equivalence.py
	$(PY) experiments/mutation_test_checksum.py
	$(PY) experiments/reproduce_checksum_bug.py
	$(PY) -m pytest -q tests/
	$(PY) state_demo/test_state.py
	$(PY) experiments/make_manifest.py

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
