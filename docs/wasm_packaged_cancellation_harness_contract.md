# WASM Packaged Cancellation Harness Contract

Contract ID: `wasm-packaged-cancellation-harness-v1`  
Bead: `asupersync-3qv04.8.4.2`

## Purpose

Define the standalone Browser Edition E2E harness for the user-visible
invariants that make Asupersync distinct from generic wasm glue:

1. interrupted bootstrap can recover cleanly,
2. render/lifecycle restarts cancel and drain losers,
3. nested cancellation cascades reach quiescence before close,
4. shutdown cancellation still resolves obligations cleanly.

This harness is intentionally scoped to dedicated files so it can progress in
parallel with other packaged-harness lanes without contending on the shared
orchestrator surfaces.

## Contract Artifacts

- Contract artifact: `artifacts/wasm_packaged_cancellation_harness_v1.json`
- Runner script: `scripts/test_wasm_packaged_cancellation_e2e.sh`
- Contract tests: `tests/wasm_packaged_cancellation_harness_contract.rs`
- Shared schema: `artifacts/wasm_e2e_log_schema_v1.json`

## Scenario Flow

Scenario ID: `e2e-wasm-packaged-cancellation-quiescence`  
Suite Scenario ID: `E2E-SUITE-WASM-PACKAGED-CANCELLATION`

Required step sequence:

1. `cancelled_bootstrap_retry_recovery`
2. `render_restart_loser_drain`
3. `nested_cancel_cascade_quiescence`
4. `shutdown_obligation_cleanup`

All step commands MUST be `rch exec -- ...` routed.

## Structured Logging Contract

`log.jsonl` entries MUST conform to `wasm-e2e-log-schema-v1` required fields:

- `ts`
- `level`
- `scenario_id`
- `run_id`
- `event`
- `msg`

The harness also records:

- `abi_version` + `abi_fingerprint`
- `browser` and `build` metadata
- `evidence_ids`
- scenario/step-specific `extra` payload

## Artifact Bundle Layout

Run bundle root:

`target/e2e-results/wasm_packaged_cancellation/e2e-runs/{scenario_id}/{run_id}/`

Required files:

- `run-metadata.json`
- `log.jsonl`
- `perf-summary.json`
- `summary.json`
- `steps.ndjson`

`run-metadata.json` MUST use schema version `wasm-e2e-run-metadata-v1` and
include package version and wasm artifact identifier extensions:

- `package_versions`
- `wasm_artifact_identifiers`

`perf-summary.json` MUST use schema version `wasm-budget-summary-v1` and emit:

- `M-PERF-03B` (cancel response p95)

When direct browser timing breakdown is unavailable in CI, the harness emits an
artifact-derived estimate using `cancellation-step-budget-model-v1`. That model
records separate `request_to_abort_ms`, `loser_drain_ms`, and
`shutdown_cleanup_ms` components derived from the packaged wasm artifact size
budget envelope and the fixed cancellation-step catalog.

The harness MUST also export a stable copy of that summary to:

- `artifacts/wasm_packaged_cancellation_perf_summary.json`

## Usage

Execute:

```bash
bash ./scripts/test_wasm_packaged_cancellation_e2e.sh
```

Dry-run:

```bash
WASM_PACKAGED_CANCELLATION_DRY_RUN=1 bash ./scripts/test_wasm_packaged_cancellation_e2e.sh
```

Dry-run mode MUST still emit `perf-summary.json` and
`artifacts/wasm_packaged_cancellation_perf_summary.json` from the packaged wasm
artifact without executing the step commands.

## Validation

Contract tests:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-wasm-packaged-cancellation cargo test --test wasm_packaged_cancellation_harness_contract -- --nocapture
```

Targeted runner contract:

```bash
WASM_PACKAGED_CANCELLATION_DRY_RUN=1 bash ./scripts/test_wasm_packaged_cancellation_e2e.sh
python3 scripts/check_perf_regression.py \
  --budgets .github/wasm_perf_budgets.json \
  --profile core-min \
  --measurements artifacts/wasm_packaged_cancellation_perf_summary.json \
  --require-metric M-PERF-03B
```

## Cross-References

- `docs/wasm_e2e_log_schema.md`
- `artifacts/wasm_qa_evidence_matrix_v1.json`
- `tests/nextjs_bootstrap_harness.rs`
- `tests/react_wasm_strictmode_harness.rs`
- `tests/close_quiescence_regression.rs`
- `tests/cancel_obligation_invariants.rs`
