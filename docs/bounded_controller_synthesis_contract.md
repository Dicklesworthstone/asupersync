# Bounded Controller Synthesis Contract

Bead: `asupersync-1508v.3.5`

## Purpose

This contract defines how bounded controller artifacts are synthesized from the digital twin model and replay workload corpus. Instead of heuristic knob tuning, each controller domain declares explicit state variables, a small discrete action set, weighted loss terms, and calibration hooks. The resulting policy tables are deterministic, versioned, and AA-02 artifact-compatible.

## Contract Artifacts

1. Canonical artifact: `artifacts/bounded_controller_synthesis_v1.json`
2. Smoke runner: `scripts/run_bounded_controller_synthesis_smoke.sh`
3. Invariant suite: `tests/bounded_controller_synthesis_contract.rs`

## Controller Domains

Each domain represents one decision surface in the runtime:

| Domain ID | Description | Action Count |
|-----------|-------------|--------------|
| SCHED-GOVERNOR | Cancel-streak limit and worker park/wake | 5 |
| ADMISSION-GATE | Root region task limits and backpressure | 3 |
| RETRY-BACKOFF | Exponential delay tuning for retries | 3 |

Each domain specifies:
- **State variables**: Snapshot fields driving decisions
- **Action set**: Small, discrete actions the controller can take
- **Loss terms**: Weighted objectives for policy optimization
- **Seam IDs**: Control seams from AA-01 inventory
- **Twin stages**: Digital twin stages from AA-03.1
- **Conservative comparator**: Static baseline for before/after comparison

## Loss Model

Each domain has weighted loss terms summing to 1.0. Total loss for a decision:

```
L(state, action) = sum(weight_i * loss_i(state, action))
```

Loss terms are evaluated against replay workload observations. A lower total loss is better.

## Calibration Protocol

1. Select workload IDs from replay corpus
2. Run twin model with synthesized policy
3. Compare predicted vs observed loss terms
4. Compute calibration score as `1 - mean_absolute_error`
5. Reject if calibration below threshold (0.8)

A holdout fraction (20%) guards against overfitting to the replay corpus.

## Artifact Format Compatibility

Synthesized controller artifacts conform to the AA-02 `controller-artifact-manifest-v1` schema, including integrity fields, fallback pointers, and snapshot version ranges. They are directly loadable by the `ControllerRegistry`.

## Structured Logging Contract

Synthesis and evaluation logs MUST include:

- `domain_id`: Controller domain
- `controller_name`: Human-readable name
- `action_id`: Action chosen
- `state_vector`: Discretized state at decision time
- `loss_terms`: Individual loss values
- `total_loss`: Weighted sum
- `calibration_score`: Current calibration
- `workload_id`: Replay workload driving the evaluation
- `snapshot_id`: Snapshot at decision time
- `policy_version`: Policy table version
- `comparator_baseline`: Conservative baseline result
- `improvement_ratio`: Improvement over baseline
- `within_budget`: Budget compliance
- `fallback_triggered`: Whether fallback was activated

## Comparator-Smoke Runner

Canonical runner: `scripts/run_bounded_controller_synthesis_smoke.sh`

The runner reads `artifacts/bounded_controller_synthesis_v1.json` and emits:

1. Per-scenario bundle manifests with schema `bounded-controller-synthesis-smoke-bundle-v1`
2. Aggregate run report with schema `bounded-controller-synthesis-smoke-run-report-v1`

Examples:

```bash
bash ./scripts/run_bounded_controller_synthesis_smoke.sh --list
bash ./scripts/run_bounded_controller_synthesis_smoke.sh --scenario BCS-SMOKE-DOMAINS --dry-run
bash ./scripts/run_bounded_controller_synthesis_smoke.sh --scenario BCS-SMOKE-DOMAINS --execute
```

## Validation

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_bounded_controller_synthesis cargo test -p asupersync --test bounded_controller_synthesis_contract -- --nocapture
```

## Cross-References

- `artifacts/bounded_controller_synthesis_v1.json`
- `scripts/run_bounded_controller_synthesis_smoke.sh`
- `tests/bounded_controller_synthesis_contract.rs`
- `src/runtime/kernel.rs` -- ControllerRegistry, artifact verification
- `artifacts/digital_twin_v1.json` -- Twin stages
- `artifacts/controller_artifact_contract_v1.json` -- AA-02 format
- `artifacts/runtime_control_seam_inventory_v1.json` -- Seam IDs
- `artifacts/runtime_workload_corpus_v1.json` -- Replay workloads
