# Controller Artifact Format and Verifier Contract

Bead: `asupersync-1508v.2.5`

## Purpose

This contract defines the proof-carrying controller artifact format and deterministic verifier behavior for AA-02.2.

It standardizes one fail-closed load unit containing:

1. Controller manifest metadata
2. Compatibility range and required snapshot fields
3. Assumptions and budget caps
4. Fallback pointer and rollback surface
5. Hash/signature chain material and deterministic verifier verdict

## Contract Artifacts

1. Canonical artifact contract: `artifacts/controller_artifact_contract_v1.json`
2. Verifier smoke runner: `scripts/run_controller_artifact_verifier_smoke.sh`
3. Invariant suite: `tests/controller_artifact_contract.rs`

## Artifact Manifest Format

Each controller artifact manifest must include:

1. `artifact_id`
2. `manifest_schema_version`
3. `controller_name`
4. `controller_version`
5. `snapshot_version_range` (`min`, `max`)
6. `required_snapshot_fields`
7. `target_seams`
8. `assumptions`
9. `bounds` (`max_decisions_per_epoch`, `max_decision_latency_us`)
10. `fallback` (`fallback_policy_id`, `rollback_pointer`, `activation_conditions`)
11. `payload` (`policy_table_ref`, `compatibility_notes`)
12. `integrity` (`payload_hash`, `hash_chain`, `signature_chain`)

The canonical field-level schema, typed expectations, and required keys are in `artifacts/controller_artifact_contract_v1.json`.

## Verifier Contract

The verifier is deterministic and fail-closed.

Verdict classes:

1. `accept`
2. `reject_missing_field`
3. `reject_hash_mismatch`
4. `reject_signature_mismatch`
5. `reject_version_mismatch`
6. `reject_schema_mismatch`

Verifier guarantees:

1. No partial success state is treated as usable.
2. Rejection reasons are deterministic and machine-readable.
3. Fallback metadata is always available when verdict is rejection.
4. Verification decisions are replayable from artifact content and verifier version.

## Required Test and Evidence Matrix

AA-02.2 requires deterministic coverage for:

1. happy-path accept verdict
2. malformed manifest rejection
3. hash mismatch rejection
4. signature mismatch rejection
5. version mismatch rejection
6. fallback activation pointer presence on rejected artifacts

`artifacts/controller_artifact_contract_v1.json` includes deterministic `verification_cases` covering each of these outcomes.

## Structured Logging Contract

Verifier output logs must include:

- `artifact_id`
- `controller_name`
- `verifier_schema_version`
- `verdict`
- `rejection_code`
- `rejection_reason`
- `payload_hash`
- `hash_chain_ok`
- `signature_chain_ok`
- `snapshot_version_min`
- `snapshot_version_max`
- `runtime_snapshot_version`
- `fallback_policy_id`
- `rollback_pointer`

## Smoke Runner

Canonical runner: `scripts/run_controller_artifact_verifier_smoke.sh`

The runner loads verification cases from `artifacts/controller_artifact_contract_v1.json` and emits:

1. per-case bundle manifests with schema `controller-artifact-verifier-smoke-bundle-v1`
2. aggregate run report with schema `controller-artifact-verifier-smoke-run-report-v1`

Examples:

```bash
# List verification cases
bash ./scripts/run_controller_artifact_verifier_smoke.sh --list

# Dry-run one case
bash ./scripts/run_controller_artifact_verifier_smoke.sh --case AA02-CASE-HASH-MISMATCH --dry-run

# Execute one case
bash ./scripts/run_controller_artifact_verifier_smoke.sh --case AA02-CASE-HASH-MISMATCH --execute
```

## Validation

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa022 cargo test --test controller_artifact_contract -- --nocapture
```

## Cross-References

- `artifacts/controller_artifact_contract_v1.json`
- `scripts/run_controller_artifact_verifier_smoke.sh`
- `tests/controller_artifact_contract.rs`
- `docs/runtime_kernel_snapshot_contract.md`
- `artifacts/runtime_kernel_snapshot_contract_v1.json`
- `src/runtime/kernel.rs`
