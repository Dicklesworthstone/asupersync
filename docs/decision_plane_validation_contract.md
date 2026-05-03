# Decision Plane Validation Contract

Bead: `asupersync-1508v.2.6`

## Purpose

This contract defines deterministic validation scenarios for decision-plane controller operations: shadow execution, canary gating, promotion pipeline, rollback drills, hold/release lifecycle, and evidence-ledger completeness. It ensures that controller rollout cannot bypass verification gates and that failed rollouts produce actionable recovery commands.

## Contract Artifacts

1. Canonical artifact: `artifacts/decision_plane_validation_v1.json`
2. Smoke runner: `scripts/run_decision_plane_validation_smoke.sh`
3. Invariant suite: `tests/decision_plane_validation_contract.rs`

## State Transition Model

Controllers follow a strict promotion pipeline:

```
Shadow --> Canary --> Active
  ^                    |
  |   (rollback)       |
  +--------------------+
  ^         ^
  |  Hold --+ (blocks promotion, release restores prior mode)
  +--- Fallback (any rollback activates fallback flag)
```

Valid transitions:
- `Shadow -> Canary` (requires calibration >= threshold AND epochs >= min_shadow_epochs)
- `Canary -> Active` (requires calibration >= threshold AND epochs >= min_canary_epochs)
- Any mode -> `Hold` (operator-initiated investigation pause)
- `Hold -> (prior mode)` (release restores mode before hold)
- `Canary/Active -> Shadow` (rollback on regression, budget, manual, or fallback)

Invalid transitions:
- `Shadow -> Active` (must pass through Canary)
- `Hold -> (any promotion)` (must release first)

## Rollback Contract

Rollback always targets Shadow mode. Each rollback reason produces a `RecoveryCommand` with:

1. Controller identity (ID, name)
2. Mode transition (from, to)
3. Rollback reason with structured payload
4. Policy ID governing the decision
5. Snapshot ID at time of rollback
6. Actionable remediation steps

Rollback of a controller already in Shadow is a no-op (returns `None`).

## Evidence Ledger Contract

Every state transition MUST produce an `EvidenceLedgerEntry` containing:

- Sequential entry ID
- Controller ID
- Snapshot ID (when available)
- Event type (Registered, Promoted, RolledBack, Held, Released, Deregistered, PromotionRejected, DecisionRecorded)
- Policy ID
- Timestamp

Promotion rejections are also recorded, ensuring the ledger captures both successful and failed attempts.

## Structured Logging Contract

Decision-plane operations MUST emit structured logs including:

- `controller_id`: Controller under operation
- `controller_name`: Human-readable name
- `mode`: Current controller mode
- `previous_mode`: Mode before transition
- `policy_id`: Promotion policy governing the operation
- `calibration_score`: Current calibration score
- `epochs_in_mode`: Epochs spent in current mode
- `budget_overruns`: Accumulated budget overruns
- `decision_label`: Label of the decision being recorded
- `snapshot_id`: Snapshot ID for the operation
- `verdict`: Outcome of the operation
- `rejection_reason`: Why a promotion was rejected
- `rollback_reason`: Why a rollback was triggered
- `fallback_active`: Whether fallback is currently active
- `recovery_command`: Recovery command payload (on rollback)
- `ledger_entry_count`: Total ledger entries for this controller

## Comparator-Smoke Runner

Canonical runner: `scripts/run_decision_plane_validation_smoke.sh`

The runner reads `artifacts/decision_plane_validation_v1.json` and emits:

1. Per-scenario bundle manifests with schema `decision-plane-validation-smoke-bundle-v1`
2. Aggregate run report with schema `decision-plane-validation-smoke-run-report-v1`
3. For `AA023-SMOKE-CONTROLLER-LEDGER`, deterministic exported controller-state artifacts:
   - `.decision-plane-validation-smoke-artifacts/run_*/AA023-SMOKE-CONTROLLER-LEDGER/controller_snapshot_ledger.json`
   - `.decision-plane-validation-smoke-artifacts/run_*/AA023-SMOKE-CONTROLLER-LEDGER/controller_snapshot_planner_rows.json`

Examples:

```bash
# List scenarios
bash ./scripts/run_decision_plane_validation_smoke.sh --list

# Dry-run one scenario
bash ./scripts/run_decision_plane_validation_smoke.sh --scenario AA023-SMOKE-TRANSITIONS --dry-run

# Execute one scenario
bash ./scripts/run_decision_plane_validation_smoke.sh --scenario AA023-SMOKE-TRANSITIONS --execute
```

## Validation

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa023 cargo test --test decision_plane_validation_contract -- --nocapture
```

## Cross-References

- `artifacts/decision_plane_validation_v1.json`
- `scripts/run_decision_plane_validation_smoke.sh`
- `tests/decision_plane_validation_contract.rs`
- `src/runtime/kernel.rs` -- ControllerRegistry, promotion pipeline, evidence ledger
- `docs/controller_artifact_contract.md` -- AA-02.2 artifact format
- `artifacts/controller_artifact_contract_v1.json`
