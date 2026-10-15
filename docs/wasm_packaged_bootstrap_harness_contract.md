# WASM Packaged Bootstrap Harness Contract

Contract ID: `wasm-packaged-bootstrap-harness-v1`  
Bead: `asupersync-3qv04.8.4.1`

## Purpose

Define the canonical baseline Browser Edition E2E harness for packaged artifacts:

1. initial package/module load,
2. bootstrap to runtime-ready,
3. reload/remount cycle,
4. clean shutdown.

This harness is the common baseline that downstream WASM QA beads build on for
latency, memory, cancellation, host-bridge, and cross-browser coverage.

## Contract Artifacts

- Contract artifact: `artifacts/wasm_packaged_bootstrap_harness_v1.json`
- Runner script: `scripts/test_wasm_packaged_bootstrap_e2e.sh`
- Contract tests: `tests/wasm_packaged_bootstrap_harness_contract.rs`
- Shared schema: `artifacts/wasm_e2e_log_schema_v1.json`

## Scenario Flow

Scenario ID: `e2e-wasm-packaged-bootstrap-load-reload`  
Suite Scenario ID: `E2E-SUITE-WASM-PACKAGED-BOOTSTRAP`

Required step sequence:

1. `packaged_module_load`
2. `bootstrap_to_runtime_ready`
3. `reload_remount_cycle`
4. `clean_shutdown`

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

`target/e2e-results/wasm_packaged_bootstrap/e2e-runs/{scenario_id}/{run_id}/`

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

`perf-summary.json` MUST use schema version `wasm-budget-summary-v1` and emit
the startup + steady-state budget metrics consumed by the perf-validation beads:

- `M-PERF-02A` (desktop Chromium cold init p95)
- `M-PERF-02B` (mid-tier mobile cold init p95)
- `M-PERF-03A` (steady-state heap p95)

When direct browser timing breakdown is unavailable in CI, the harness emits an
artifact-derived estimate using:

- `artifact-budget-model-v1` for cold-init latency (`download_ms`,
  `instantiate_ms`, `bootstrap_ms`)
- `artifact-memory-envelope-v1` for steady-state heap envelope
  (`wasm_module_mib`, `js_bridge_mib`, `runtime_state_mib`,
  `steady_buffers_mib`, `shutdown_reserve_mib`)

Both models mirror the declared hard-budget thresholds in
`.github/wasm_perf_budgets.json`.

The harness MUST also export a stable copy of that summary to:

- `artifacts/wasm_packaged_bootstrap_perf_summary.json`

## Usage

Execute:

```bash
bash ./scripts/test_wasm_packaged_bootstrap_e2e.sh
```

Dry-run:

```bash
WASM_PACKAGED_BOOTSTRAP_DRY_RUN=1 bash ./scripts/test_wasm_packaged_bootstrap_e2e.sh
```

Dry-run mode MUST still emit `perf-summary.json` and
`artifacts/wasm_packaged_bootstrap_perf_summary.json` from the packaged wasm
artifact without executing the step commands.

## Validation

Contract tests:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-wasm-packaged-bootstrap cargo test --test wasm_packaged_bootstrap_harness_contract -- --nocapture
```

Log-schema alignment:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-wasm-packaged-log-schema cargo test --test wasm_e2e_log_schema_contract -- --nocapture
```

Startup-budget gate dry-run:

```bash
WASM_PACKAGED_BOOTSTRAP_DRY_RUN=1 bash ./scripts/test_wasm_packaged_bootstrap_e2e.sh
python3 scripts/check_perf_regression.py \
  --budgets .github/wasm_perf_budgets.json \
  --profile core-min \
  --measurements artifacts/wasm_budget_summary.json \
  --measurements artifacts/wasm_packaged_bootstrap_perf_summary.json \
  --require-metric M-PERF-01A \
  --require-metric M-PERF-01B \
  --require-metric M-PERF-02A \
  --require-metric M-PERF-02B \
  --require-metric M-PERF-03A
```

## Cross-References

- `docs/wasm_e2e_log_schema.md`
- `artifacts/wasm_qa_evidence_matrix_v1.json`
- `scripts/run_all_e2e.sh`
