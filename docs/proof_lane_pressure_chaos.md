# Proof-Lane Pressure Chaos Profile

The proof-lane pressure chaos profile extends the chaos scenario DSL with deterministic preflight scenarios for RCH and proof-admission pressure. It lives in `artifacts/chaos_scenario_dsl_contract_v1.json` under `proof_lane_pressure_profile`.

## Source Files

- Contract: `artifacts/chaos_scenario_dsl_contract_v1.json`
- Fixture corpus: `tests/fixtures/proof_lane_pressure_chaos/proof_lane_pressure_scenarios.json`
- E2E wrapper: `scripts/run_proof_lane_pressure_chaos_e2e.sh`
- Report surface: `scripts/swarm_pressure_preflight_report.py`
- Contract tests: `tests/chaos_scenario_dsl_contract.rs`

## Covered Scenarios

The profile covers these pressure states without allocating large memory, burning CPU, sleeping on wall clock time, running Cargo, running RCH, mutating git, mutating Beads, sending Agent Mail, or deleting files:

- memory envelope exceeded
- time envelope exceeded
- stale exact filter with zero executed tests
- remote admission denied
- local fallback attempted
- dirty peer-owned release blocker
- cancellation/obligation pressure warning

Each scenario feeds `swarm_pressure_preflight_report.py` with inline manifest, proof-status, freshness, admission, or dirty-tree receipt data. The expected result is an exact operator decision plus exact blocker and warning kind sets.

## Running

Run the focused contract lane through RCH:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_chaos_proof_lane_pressure" CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test chaos_scenario_dsl_contract proof_lane_pressure -- --nocapture
```

Run the script directly for detailed logs:

```bash
scripts/run_proof_lane_pressure_chaos_e2e.sh \
  --repo-path . \
  --fixture tests/fixtures/proof_lane_pressure_chaos/proof_lane_pressure_scenarios.json \
  --output-dir target/proof-lane-pressure-chaos-e2e \
  --generated-at 2026-06-05T08:55:00Z
```

The script writes per-scenario `scenario.json`, `preflight_input.json`, and `preflight_report.json` files under the chosen output directory. It logs scenario ID, pressure dimensions, injected pressure facts, expected decision, actual decision, blocker kinds, warning kinds, and the detailed blocker/warning reasons emitted by the report.

## Proof Boundary

This profile is a deterministic guard/report test. It proves that current preflight inputs are parsed, normalized, aggregated, and compared consistently. It does not prove compiler correctness, runtime behavioral correctness, RCH worker isolation, OS-level memory limits, or live cancellation quiescence. Those claims still require their canonical RCH proof lanes.
