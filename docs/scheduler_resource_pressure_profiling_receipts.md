# Scheduler Resource Pressure Profiling Receipts

This document is the operator runbook for
`scheduler-resource-pressure-profiling-receipts-v1`. The canonical contract is
`artifacts/scheduler_resource_pressure_profiling_receipts_v1.json`, the helper
is `scripts/scheduler_resource_pressure_profiling_receipts.py`, and the
contract verifier is
`tests/scheduler_resource_pressure_profiling_receipts_contract.rs`.

The receipt lane is intentionally scoped. It proves that scheduler/resource
pressure profiling scenarios are named, bounded, attributable to concrete
source paths, and paired with remote-required refresh commands. It does not
prove fresh benchmark numbers, real-host throughput, scheduler regression
closure, RCH fleet health, or production admission-control safety.

## Scenario Catalog

| Scenario | Pressure surface | Primary attribution |
| --- | --- | --- |
| `scheduler-spawn-storm` | Scheduler spawn storms across global and local ready queues | `src/runtime/scheduler/three_lane.rs`, `src/runtime/scheduler/local_queue.rs`, `src/runtime/scheduler/worker.rs` |
| `obligation-cleanup-drain` | Cancellation drain and obligation cleanup cost | `src/runtime/state.rs`, `src/runtime/obligation_table.rs`, `src/cancel/progress_certificate.rs` |
| `proof-lane-report-generation` | Proof-lane parsing, status classification, and report generation | `scripts/swarm_pressure_preflight_report.py`, `tests/swarm_pressure_preflight_report_contract.rs` |
| `dirty-tree-correlation` | Dirty-tree ownership and reservation correlation | `scripts/dirty_tree_ownership_receipt.py`, `scripts/claim_reservation_receipt.py` |

Each row carries the required fields `scenario_id`, `scenario_family`,
`command`, `environment`, `data_hash`, `top_hot_paths`,
`memory_observations`, `operator_interpretation`, `proof_boundary`,
`rch_refresh_command`, and `source_refs`.

## Proof Boundary

The committed artifact is a deterministic receipt contract. It is useful for
routing operator attention and preventing vague performance claims, but it is
not a benchmark report. Treat every row as `contract-receipt` until its
`rch_refresh_command` has been run and a fresh artifact from that command is
attached to the lane being claimed.

The helper is non-mutating. It does not run Cargo, RCH, Git, Beads, Agent Mail,
or cache writes. It only reads a bounded fixture/contract and emits JSON or
Markdown.

## RCH Refresh Commands

All refresh commands are remote-required and include an isolated
`CARGO_TARGET_DIR`. Local Cargo fallback is not admissible for profiling
refresh evidence.

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_profile_scheduler_spawn_storm CARGO_INCREMENTAL=0 CARGO_PROFILE_BENCH_DEBUG=0 cargo bench -p asupersync --bench methodology_baselines --features test-internals -- methodology/task_spawn --noplot
```

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_profile_obligation_cleanup CARGO_INCREMENTAL=0 CARGO_PROFILE_BENCH_DEBUG=0 cargo bench -p asupersync --bench methodology_baselines --features test-internals -- methodology/task_cancellation --noplot
```

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_profile_proof_lane_report CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 bash scripts/run_swarm_pressure_preflight_report_e2e.sh --run-id profile-proof-lane-report
```

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_profile_dirty_tree_correlation CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 bash scripts/run_dirty_tree_ownership_receipt_e2e.sh --run-id profile-dirty-tree-correlation
```

## Deterministic E2E Receipt

The bounded E2E wrapper writes a JSON receipt, Markdown receipt, and log file
under `target/scheduler-resource-pressure-profiling-receipts/`.

```bash
bash scripts/run_scheduler_resource_pressure_profiling_receipts_e2e.sh --run-id local-check
```

The log fields are stable: `bead_id`, `scenario_id`, `scenario_family`,
`status`, `data_hash`, `top_hot_path`, `memory_ceiling_mb`,
`operator_action`, `artifact_path`, and `first_failure`.

Use the focused RCH verifier for this contract:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_scheduler_resource_pressure_profiling_receipts CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test scheduler_resource_pressure_profiling_receipts_contract -- --nocapture
```
