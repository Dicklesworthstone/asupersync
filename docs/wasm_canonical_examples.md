# WASM Canonical Examples Catalog

Contract ID: `wasm-canonical-examples-v1`  
Bead: `asupersync-umelq.16.3`
Downstream Bead: `asupersync-3qv04.9.3.1`

## Purpose

Define the canonical Browser Edition examples for:

1. Vanilla JS runtime embedding plus durable storage/artifact exercise
2. Dedicated-worker bootstrap, storage/artifact export handoff, and shutdown coordination
3. Shared-worker coordinator attach/reuse/fallback with explicit downgrade truth
4. Rust-authored browser fixture workflow with explicit lifecycle/capability boundaries
5. TypeScript outcome/cancellation modeling
6. React provider + hook lifecycle patterns
7. Next.js App Router bootstrap boundaries

Each example must stay deterministic, preserve structured-concurrency invariants,
and provide replayable commands and artifact paths.

## Invariant Contract

Every example in this catalog must preserve:

- `no_orphan_tasks`
- `cancelled_losers_are_drained`
- `region_close_implies_quiescence`
- `no_obligation_leaks`
- `explicit_capability_boundaries`

## Example Matrix

| Surface | Canonical Scenario IDs | Deterministic Harness | Replay Artifact Pointers |
| --- | --- | --- | --- |
| Vanilla JS | `vanilla.storage_artifact_bundle`, `vanilla.behavior_loser_drain_replay`, `vanilla.negative_skipped_loser_detection`, `vanilla.timing_mid_computation_drain`, `L6-BUNDLER-VITE` | `tests/e2e/combinator/cancel_correctness/browser_loser_drain.rs`, `scripts/validate_vite_vanilla_consumer.sh` | `target/e2e-results/vite_vanilla_consumer/<timestamp>/summary.json`, `artifacts/onboarding/vanilla.behavior_loser_drain_replay.log`, `artifacts/onboarding/vanilla.negative_skipped_loser_detection.log` |
| Dedicated Worker | `worker.runtime_support_matrix`, `worker.storage_artifact_diagnostics`, `worker.storage_artifact_export_handoff`, `worker.coordinator_protocol`, `L6-BUNDLER-DEDICATED-WORKER` | `tests/wasm_browser_feasibility_matrix.rs`, `tests/wasm_js_exports_coverage_contract.rs`, `src/net/worker_channel.rs`, `scripts/validate_dedicated_worker_consumer.sh` | `artifacts/onboarding/worker.runtime_support_matrix.log`, `artifacts/onboarding/worker.storage_artifact_diagnostics.log`, `artifacts/onboarding/worker.coordinator_protocol.log`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json`; the reviewed summary bundle must preserve `scenario_inventory` plus artifact pointers under `artifacts` |
| Shared Worker | `shared_worker_attach_baseline`, `shared_worker_multi_page_reuse`, `shared_worker_protocol_mismatch_fallback`, `shared_worker_attach_crash_fallback`, `shared_worker_client_detach_cleanup`, `L6-SHARED-WORKER-COORDINATOR` | `tests/wasm_browser_feasibility_matrix.rs`, `scripts/validate_shared_worker_consumer.sh`, `tests/fixtures/shared-worker-consumer/scripts/check-browser-run.mjs` | `artifacts/onboarding/shared_worker.support_matrix.log`, `target/e2e-results/shared_worker_consumer/<timestamp>/summary.json`, `target/e2e-results/shared_worker_consumer/<timestamp>/browser-run.json` |
| Rust Browser | `RUST-BROWSER-CONSUMER`, `repository_maintained_rust_browser_fixture`, `L6-RUST-BROWSER-CONSUMER` | `tests/wasm_rust_browser_example_contract.rs`, `scripts/validate_rust_browser_consumer.sh` | `target/e2e-results/rust_browser_consumer/<timestamp>/summary.json`, `target/e2e-results/rust_browser_consumer/<timestamp>/browser-run.json` |
| TypeScript | `TS-TYPE-VANILLA`, `TS-TYPE-REACT`, `TS-TYPE-NEXT` | `scripts/check_wasm_typescript_type_model_policy.py` | `artifacts/wasm_typescript_type_model_summary.json`, `artifacts/wasm_typescript_type_model_log.ndjson` |
| React | `react_ref.task_group_cancel`, `react_ref.retry_after_transient_failure`, `react_ref.bulkhead_isolation`, `react_ref.tracing_hook_transition` | `tests/react_wasm_strictmode_harness.rs` | `artifacts/onboarding/react.behavior_strict_mode_double_invocation.log`, `artifacts/onboarding/react.timing_restart_churn.log` |
| Next.js | `next_ref.template_deploy`, `next_ref.cache_revalidation_reinit`, `next_ref.hard_navigation_rebootstrap`, `next_ref.cancel_retry_runtime_init` | `tests/nextjs_bootstrap_harness.rs` | `artifacts/onboarding/next.behavior_bootstrap_harness.log`, `artifacts/onboarding/next.timing_navigation_churn.log` |

## Structured Logging Requirements

At minimum, example execution logs must include:

- `scenario_id`
- `step_id`
- `runtime_profile`
- `diagnostic_category`
- `repro_command`
- `outcome`
- `trace_artifact_hint`

Framework-specific logs may add extra fields, but these fields are mandatory.

## Maintained Vanilla Browser Example

Maintained vanilla Browser Edition example source:

- `tests/fixtures/vite-vanilla-consumer`
- validation harness: `scripts/validate_vite_vanilla_consumer.sh`

This fixture is the canonical low-friction browser-only entrypoint for:

- `@asupersync/browser` package import resolution
- packaged WASM artifact loading through a real Vite consumer build
- explicit `BrowserStorage` diagnostics plus deterministic IndexedDB key cleanup
- explicit `BrowserArtifactStore` persist/export/clear flows on the browser main thread
- deterministic artifact output under `target/e2e-results/vite_vanilla_consumer/`

Primary deterministic validation command:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_vite_vanilla_consumer.sh
```

## Maintained Dedicated Worker Example

Maintained dedicated-worker Browser Edition example source:

- `tests/fixtures/dedicated-worker-consumer`
- validation harness: `scripts/validate_dedicated_worker_consumer.sh`

This fixture is the canonical worker entrypoint for:

- `@asupersync/browser` direct runtime bootstrap inside a dedicated worker
- worker-safe `BrowserStorage` exercise over the IndexedDB-backed browser lane
- worker-safe `BrowserArtifactStore` export handoff via `exportArchive()`
- actionable `downloadArchive()` failure guidance proving downloads stay main-thread-only
- explicit quota-guard coverage proving retention failures surface as
  `quota_exceeded` instead of silently retaining unbounded worker artifacts
- explicit worker startup, main-thread handoff, and graceful shutdown messaging
- deterministic artifact output under `target/e2e-results/dedicated_worker_consumer/`

The dedicated-worker summary is expected to retain these bundle markers:

- `worker_storage_support_marker`
- `worker_storage_roundtrip_marker`
- `worker_artifact_export_marker`
- `worker_artifact_download_guard_marker`
- `worker_artifact_quota_guard_marker`
- `worker_artifact_cleanup_marker`
- `browser_final_phase_is_shutdown_complete`
- `browser_shutdown_reason`
- `browser_shutdown_reason_is_fixture_handoff_complete`

The dedicated-worker summary bundle must also preserve top-level
`scenario_inventory` plus artifact pointers under `artifacts` so
release-governance reviews can trace `summary.json`, `browser-run.json`, and
supporting logs without rerunning the fixture.

Primary deterministic validation commands:

```bash
python3 scripts/run_browser_onboarding_checks.py --scenario worker
PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh
```

## Maintained Shared-Worker Example

Maintained shared-worker coordinator example source:

- `tests/fixtures/shared-worker-consumer`
- validation harness: `scripts/validate_shared_worker_consumer.sh`

This fixture is the canonical guarded shared-worker example for:

- bounded coordinator attach from browser main-thread or dedicated-worker callers
- same-origin multi-page reuse without widening direct-runtime claims
- explicit downgrade on protocol mismatch or crash-before-handshake
- topology snapshot and client-detach coverage through the public coordinator client
- deterministic artifact output under `target/e2e-results/shared_worker_consumer/`

The shared-worker summary is expected to retain these contract markers:

- `shared-worker-selection-baseline`
- `shared-worker-selection-reuse`
- `shared-worker-selection-protocol-mismatch`
- `shared-worker-selection-crash-fallback`
- `shared-worker-coordinator-attach`
- `shared-worker-coordinator-topology-snapshot`
- `shared-worker-coordinator-protocol-mismatch`
- `shared-worker-coordinator-crash-before-handshake`
- `shared-worker-coordinator-detach`

The reviewed shared-worker bundle must also preserve `scenario_inventory`
covering attach, reuse, protocol mismatch fallback, crash fallback, and client
detach cleanup so guarded-lane reviews do not collapse into one smoke marker.

Primary deterministic validation commands:

```bash
python3 scripts/run_browser_onboarding_checks.py --scenario shared_worker
PATH=/usr/bin:$PATH bash scripts/validate_shared_worker_consumer.sh
```

## Maintained Rust Browser Example

Maintained Rust-authored browser example source:

- `tests/fixtures/rust-browser-consumer`
- validation harness: `scripts/validate_rust_browser_consumer.sh`

This fixture is the canonical Rust-authored browser example for:

- the truthful repository-maintained browser-facing Rust workflow
- a real wasm package layout that stages generated `pkg/` output next to a frontend consumer
- a dedicated-worker companion bundle at
  `tests/fixtures/rust-browser-consumer/src/worker.ts` for preferred-lane
  selection and downgrade coverage
- provider/helper-driven structured-concurrency lifecycle evidence instead of a fabricated public browser `RuntimeBuilder` story
- explicit browser capability reporting, one successful completion path, and one unmount-driven cancellation path
- execution-ladder downgrade evidence for `missing_webassembly` and
  `candidate_host_role_mismatch` when the preferred host lane is unavailable
- deterministic artifact output under `target/e2e-results/rust_browser_consumer/`

The Rust-browser summary is expected to retain these contract markers:

- `RUST-BROWSER-CONSUMER`
- `repository_maintained_rust_browser_fixture`
- `ready_phase = "ready"`
- `disposed_phase = "disposed"`
- `completed_task_outcome = "ok"`
- `cancel_event_count = 1`

Primary deterministic validation command:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_rust_browser_consumer.sh
```

## Maintained Next.js Example

Maintained Next App Router example source:

- `tests/fixtures/next-turbopack-consumer`
- validation harness: `scripts/validate_next_turbopack_consumer.sh`

This fixture is the canonical Next.js example for:

- `@asupersync/next` import resolution through a real consumer build
- explicit client direct-runtime ownership via `createNextBootstrapAdapter(...)`
- explicit node/server bridge-only handling via `createNextServerBridgeAdapter(...)`
- explicit edge diagnostics that keep direct runtime execution out of edge code

Primary deterministic validation command:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_next_turbopack_consumer.sh
```

## Canonical Repro Commands

Run all example lanes (preferred CI/replay bundle):

```bash
python3 scripts/run_browser_onboarding_checks.py --scenario all
```

Run lane-scoped bundles:

```bash
python3 scripts/run_browser_onboarding_checks.py --scenario vanilla
python3 scripts/run_browser_onboarding_checks.py --scenario worker
python3 scripts/run_browser_onboarding_checks.py --scenario shared_worker
python3 scripts/run_browser_onboarding_checks.py --scenario react
python3 scripts/run_browser_onboarding_checks.py --scenario next
```

Run the maintained vanilla Vite fixture directly:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_vite_vanilla_consumer.sh
```

Run the maintained dedicated-worker fixture directly:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh
```

Run the maintained shared-worker fixture directly:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_shared_worker_consumer.sh
```

Run the maintained Rust-browser fixture directly:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_rust_browser_consumer.sh
```

Run the maintained Next fixture directly:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_next_turbopack_consumer.sh
```

Run focused TypeScript contract checks:

```bash
python3 scripts/check_wasm_typescript_type_model_policy.py \
  --policy .github/wasm_typescript_type_model_policy.json \
  --only-scenario TS-TYPE-VANILLA

python3 scripts/check_wasm_typescript_type_model_policy.py \
  --policy .github/wasm_typescript_type_model_policy.json \
  --only-scenario TS-TYPE-REACT

python3 scripts/check_wasm_typescript_type_model_policy.py \
  --policy .github/wasm_typescript_type_model_policy.json \
  --only-scenario TS-TYPE-NEXT
```

Run deterministic harnesses directly:

```bash
rch exec -- cargo test --lib worker_channel::tests::coordinator_ -- --nocapture
rch exec -- cargo test --test react_wasm_strictmode_harness -- --nocapture
rch exec -- cargo test --test nextjs_bootstrap_harness -- --nocapture
```

## Drift-Detection Test Contract

The following test enforces this catalog remains synchronized with the harnesses
and command bundles:

- `tests/wasm_canonical_examples_harness.rs`

If this test fails, update this document and the referenced harness/doc surfaces
in the same change set.
