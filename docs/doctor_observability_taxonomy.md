# doctor Advanced Observability Taxonomy Contract

## Scope

This document defines the advanced observability layer for `doctor_asupersync`.
It is intentionally layered on top of baseline structured logging so operators
can triage faster without changing baseline event envelopes.

Advanced taxonomy is implemented in `src/observability/diagnostics.rs` via:

- `advanced_observability_contract()`
- `classify_baseline_log_event(...)`
- `classify_baseline_log_events(...)`

## Versioning

- `contract_version`: `doctor-observability-v1`
- `baseline_contract_version`: `doctor-logging-v1`

Compatibility policy:

1. Additive class/dimension introduction is allowed in `v1`.
2. Semantic redefinition of existing classes, severity rules, or conflict
   behavior requires a contract version bump.
3. Unknown baseline `flow_id`, `event_kind`, or `outcome_class` is a hard
   validation error.

## Advanced Event Classes

1. `command_lifecycle`: execution command start/complete and gate telemetry
2. `integration_reliability`: cross-system adapter/sync/error boundaries
3. `remediation_safety`: remediation apply/verify lifecycle
4. `replay_determinism`: replay start/complete determinism posture
5. `verification_governance`: verification summary and promotion posture

## Severity Semantics

1. `info`: expected transition, no immediate intervention
2. `warning`: cancellation or degraded path requiring review
3. `error`: actionable failure impacting reliability/correctness
4. `critical`: contract/taxonomy contradiction that must be fixed first

## Troubleshooting Dimensions

1. `cancellation_path`
2. `contract_compliance`
3. `determinism`
4. `external_dependency`
5. `operator_action`
6. `recovery_planning`
7. `runtime_invariant`

These dimensions are emitted in deterministic lexical order.

## Deterministic Mapping Rules

Classification input tuple:

- `flow_id`
- `event_kind`
- `outcome_class`

Resolution order:

1. Base severity by outcome:
   - `success -> info`
   - `cancelled -> warning`
   - `failed -> error`
2. Apply event-kind semantics (class + baseline dimensions + narrative/action).
3. Detect conflicts and escalate:
   - Flow/event mismatch => add `FlowEventMismatch`, escalate to `critical`
   - `integration_error` with `success` outcome => add `OutcomeEventMismatch`,
     escalate to at least `error`
4. Add outcome dimensions:
   - `cancelled` adds `cancellation_path`
   - `failed` adds `recovery_planning`
5. Sort/dedup dimensions and conflicts for deterministic output.

## Operator Narrative Contract

Every classified event returns:

1. `event_class`
2. `severity`
3. `dimensions[]`
4. `narrative` (operator-facing sentence)
5. `recommended_action`
6. `conflicts[]`

`recommended_action` is automatically hardened when conflicts exist:
it explicitly requires conflict resolution before trusting downstream automation.

## Validation Surface

Deterministic unit coverage includes:

1. schema ordering checks (classes/dimensions)
2. baseline known-event classification correctness
3. flow/event conflict escalation to `critical`
4. outcome/event conflict handling (`integration_error` + `success`)
5. deterministic repeated stream classification
6. unknown-token hard-failure behavior

## rch Validation Commands

```bash
rch exec -- env CARGO_TARGET_DIR=target/rch_chartreuse_2b4jj_2_7 cargo test -p asupersync --lib advanced_observability -- --nocapture
rch exec -- env CARGO_TARGET_DIR=target/rch_chartreuse_2b4jj_2_7 cargo check --all-targets
rch exec -- env CARGO_TARGET_DIR=target/rch_chartreuse_2b4jj_2_7 cargo clippy --all-targets -- -D warnings
rch exec -- cargo fmt --check
```
