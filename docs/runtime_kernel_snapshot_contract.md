# RuntimeKernelSnapshot and Controller Registration Contract

Bead: `asupersync-1508v.2.4`

## Purpose

This contract defines the canonical runtime snapshot surface and controller registration requirements for AA-02.1.

It makes three things explicit and stable:

1. The `RuntimeKernelSnapshot` schema controllers are allowed to observe
2. The `ControllerRegistration` metadata and validation rules required before participation
3. The deterministic smoke and invariant checks that guard the contract over time

This contract is intentionally anchored to `src/runtime/kernel.rs` and the runtime decision-plane invariants (determinism, auditability, no ambient authority).

## Contract Artifacts

1. Canonical artifact: `artifacts/runtime_kernel_snapshot_contract_v1.json`
2. Comparator-smoke runner: `scripts/run_runtime_kernel_snapshot_smoke.sh`
3. Invariant suite: `tests/runtime_kernel_snapshot_contract.rs`

## Snapshot Scope and Versioning

`RuntimeKernelSnapshot` is versioned by `SnapshotVersion { major, minor }` with the current schema version `1.0` (`SNAPSHOT_VERSION` in `src/runtime/kernel.rs`).

Version rules:

1. Major changes are incompatible and require explicit controller upgrade.
2. Minor changes are additive-compatible when required fields remain available.
3. Snapshot IDs are monotonic (`SnapshotId(u64)`) for deterministic replay and audit ordering.
4. Snapshot timestamps are logical runtime time, not ambient wall-clock authority.

The full typed field catalog, units, ownership, and update cadence is defined in `artifacts/runtime_kernel_snapshot_contract_v1.json` under `snapshot_schema.fields`.

## Required Controller Registration Contract

Each controller registration must provide:

1. `name`
2. `min_version` and `max_version`
3. `required_fields`
4. `target_seams`
5. `initial_mode`
6. `proof_artifact_id` (optional)
7. `budget` (`max_decisions_per_epoch`, `max_decision_latency_us`)

Validation rejects registrations that violate these constraints (empty names, invalid version ranges, unsupported fields, empty seam targets, zero decision budget, duplicate names).

## Mandatory Controller Metadata Surface

AA-02.1 requires metadata beyond the pure snapshot payload. The contract requires the following controller-observation metadata to be present in decision/evidence bundles:

1. `decisions_this_epoch`
2. `fallback_active`
3. `calibration_score`
4. `last_action_label`
5. `proof_artifact_id`
6. `budget_max_decisions_per_epoch`
7. `budget_max_decision_latency_us`

This keeps controller behavior auditable and supports conservative rollback when calibration or fallback conditions regress.

## Compatibility and Upgrade or Downgrade Semantics

1. Registration is rejected if snapshot major version falls outside controller declared range.
2. Unsupported required fields are rejected during registration.
3. Controllers can run in `Shadow` mode while supporting a reduced field set.
4. Promotion to `Canary` or `Active` requires deterministic evidence quality and calibration stability.
5. Conservative fallback remains available when runtime evidence indicates degraded confidence.

## Structured Logging Contract

Decision-plane logs must include:

- `snapshot_id`
- `snapshot_version`
- `controller_id`
- `controller_name`
- `controller_mode`
- `decision_label`
- `fallback_active`
- `calibration_score`
- `proof_artifact_id`
- `decisions_this_epoch`
- `budget_max_decisions_per_epoch`
- `budget_max_decision_latency_us`
- `registration_status`
- `rejection_code`
- `rejection_reason`
- `required_fields`
- `target_seams`

These fields support deterministic replay and direct root-cause analysis for rejected registrations and degraded decision quality.

## Comparator-Smoke Runner

Canonical runner: `scripts/run_runtime_kernel_snapshot_smoke.sh`

The runner reads `artifacts/runtime_kernel_snapshot_contract_v1.json`, supports deterministic dry-run or execute modes, and emits:

1. Per-scenario manifests with schema `runtime-kernel-snapshot-smoke-bundle-v1`
2. Aggregate run report with schema `runtime-kernel-snapshot-smoke-run-report-v1`

Examples:

```bash
# List scenarios
bash ./scripts/run_runtime_kernel_snapshot_smoke.sh --list

# Dry-run one scenario
bash ./scripts/run_runtime_kernel_snapshot_smoke.sh --scenario AA02-SMOKE-REGISTRATION-VALIDATION --dry-run

# Execute one scenario
bash ./scripts/run_runtime_kernel_snapshot_smoke.sh --scenario AA02-SMOKE-REGISTRATION-VALIDATION --execute
```

## Validation

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa021 cargo test --test runtime_kernel_snapshot_contract -- --nocapture
```

Invariant coverage locks:

1. doc section and cross-reference stability
2. artifact schema/version invariants
3. snapshot field ownership and source anchoring
4. registration validation rule coverage
5. smoke command `rch` routing and report schema stability

## Cross-References

- `src/runtime/kernel.rs`
- `src/runtime/mod.rs`
- `artifacts/runtime_kernel_snapshot_contract_v1.json`
- `scripts/run_runtime_kernel_snapshot_smoke.sh`
- `tests/runtime_kernel_snapshot_contract.rs`
- `artifacts/runtime_control_seam_inventory_v1.json`
- `docs/runtime_control_seam_inventory_contract.md`
