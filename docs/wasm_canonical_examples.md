# WASM Canonical Examples Catalog

Contract ID: `wasm-canonical-examples-v1`  
Bead: `asupersync-umelq.16.3`

## Purpose

Define the canonical Browser Edition examples for:

1. Vanilla JS runtime embedding
2. TypeScript outcome/cancellation modeling
3. React provider + hook lifecycle patterns
4. Next.js App Router bootstrap boundaries

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
| Vanilla JS | `vanilla.behavior_loser_drain_replay`, `vanilla.negative_skipped_loser_detection`, `vanilla.timing_mid_computation_drain` | `tests/e2e/combinator/cancel_correctness/browser_loser_drain.rs` | `artifacts/onboarding/vanilla.behavior_loser_drain_replay.log`, `artifacts/onboarding/vanilla.negative_skipped_loser_detection.log` |
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

## Canonical Repro Commands

Run all example lanes (preferred CI/replay bundle):

```bash
python3 scripts/run_browser_onboarding_checks.py --scenario all
```

Run framework-scoped lanes:

```bash
python3 scripts/run_browser_onboarding_checks.py --scenario vanilla
python3 scripts/run_browser_onboarding_checks.py --scenario react
python3 scripts/run_browser_onboarding_checks.py --scenario next
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

Run deterministic React/Next harnesses directly:

```bash
rch exec -- cargo test --test react_wasm_strictmode_harness -- --nocapture
rch exec -- cargo test --test nextjs_bootstrap_harness -- --nocapture
```

## Drift-Detection Test Contract

The following test enforces this catalog remains synchronized with the harnesses
and command bundles:

- `tests/wasm_canonical_examples_harness.rs`

If this test fails, update this document and the referenced harness/doc surfaces
in the same change set.
