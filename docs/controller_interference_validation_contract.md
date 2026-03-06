# Controller Interference Validation Contract

Bead: `asupersync-1508v.3.6`

## Purpose

This contract validates that multiple controllers operating on the same runtime do not create feedback loops, respect timescale separation, and fall back conservatively when tail-SLO guardrails break. It is the final gate before controllers can be composed in production.

## Contract Artifacts

1. Canonical artifact: `artifacts/controller_interference_validation_v1.json`
2. Smoke runner: `scripts/run_controller_interference_validation_smoke.sh`
3. Invariant suite: `tests/controller_interference_validation_contract.rs`

## Interference Model

Controllers targeting overlapping snapshot fields can create positive feedback loops:

| Pair ID | Controllers | Shared Observable | Risk |
|---------|------------|-------------------|------|
| SCHED-ADMIT | SCHED-GOVERNOR + ADMISSION-GATE | ready_queue_len | Park/wake oscillation vs admission tightening |
| SCHED-RETRY | SCHED-GOVERNOR + RETRY-BACKOFF | active_timers | Worker parking vs retry timer bursts |
| ADMIT-RETRY | ADMISSION-GATE + RETRY-BACKOFF | outstanding_obligations | Admission tightening vs retry flood |

Interference is detected by counting decision oscillations (action A, then opposite action B, then A again) within a sliding window of epochs. If the oscillation count exceeds the threshold (4) within the window (8 epochs), an interference alarm is raised.

## Timescale Separation

Controllers are assigned to timescale tiers with increasing epoch multipliers:

| Tier | Multiplier | Controllers | Rationale |
|------|-----------|-------------|-----------|
| FAST | 1x | SCHED-GOVERNOR | Per-epoch latency response |
| MEDIUM | 4x | ADMISSION-GATE | Multi-epoch steady-state observation |
| SLOW | 8x | RETRY-BACKOFF | Full retry cycle observation |

The separation invariant requires that each slower tier has a strictly larger epoch multiplier than any faster tier, with a minimum ratio of 2x between adjacent tiers.

## Tail-SLO Fallback Gates

When a tail-latency SLO is breached:

1. All non-Shadow controllers are rolled back to Shadow within the fallback deadline (2 epochs)
2. Fallback flags are set on each rolled-back controller
3. Conservative comparator values take immediate effect
4. Recovery requires fresh calibration and full promotion pipeline
5. Fallback flags are cleared only after calibration exceeds threshold

## Sequential Validity

Within a single epoch, controller decisions are applied in registration order (by `ControllerId`). Each controller observes the state after the previous controller's decision has been recorded. If a decision would differ under pre- vs post-decision snapshots, a drift alarm is logged.

## Structured Logging Contract

Interference and fallback logs MUST include:

- `interference_pair_id`: Which controller pair
- `oscillation_count`: Number of oscillations in window
- `oscillation_detected`: Boolean alarm flag
- `timescale_tier`: Controller's tier assignment
- `epoch_multiplier`: Tier's epoch multiplier
- `slo_field_id`: Which SLO field was checked
- `slo_breached`: Whether the SLO was breached
- `fallback_deadline_remaining`: Epochs remaining before forced fallback
- `sequential_order`: Controller's position in the decision sequence
- `drift_detected`: Whether drift alarm was raised

## Comparator-Smoke Runner

Canonical runner: `scripts/run_controller_interference_validation_smoke.sh`

The runner reads `artifacts/controller_interference_validation_v1.json` and emits:

1. Per-scenario bundle manifests with schema `controller-interference-validation-smoke-bundle-v1`
2. Aggregate run report with schema `controller-interference-validation-smoke-run-report-v1`

Examples:

```bash
bash ./scripts/run_controller_interference_validation_smoke.sh --list
bash ./scripts/run_controller_interference_validation_smoke.sh --scenario CIV-SMOKE-INTERFERENCE --dry-run
bash ./scripts/run_controller_interference_validation_smoke.sh --execute
```

## Validation

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa033 cargo test --test controller_interference_validation_contract -- --nocapture
```

## Cross-References

- `artifacts/controller_interference_validation_v1.json`
- `scripts/run_controller_interference_validation_smoke.sh`
- `tests/controller_interference_validation_contract.rs`
- `src/runtime/kernel.rs` -- ControllerRegistry, promotion pipeline, rollback
- `artifacts/bounded_controller_synthesis_v1.json` -- Controller domains
- `artifacts/decision_plane_validation_v1.json` -- Decision plane lifecycle
- `artifacts/digital_twin_v1.json` -- Twin stages
