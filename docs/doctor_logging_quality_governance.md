# doctor Logging-Quality Governance

Bead: `asupersync-2b4jj.6.7`

## Purpose

Define how new logging-quality rules are introduced, modified, or retired
without destabilizing established diagnostics quality gates.

## Rule Lifecycle

### Introduction

1. New rules must be proposed with a rule ID (`LQ-{CATEGORY}-{SEQ}`), severity,
   description, and at least one golden test case demonstrating violation detection.
2. Categories: `ENV` (envelope), `COR` (correlation), `TAX` (taxonomy).
3. New rules start at `warning` severity for one release cycle, then may be
   promoted to `error` if no false-positive reports are filed.
4. The fixture `tests/fixtures/doctor_logging_quality/log_quality_rules.json`
   is the canonical rule registry.

### Modification

1. Changing a rule's severity from `warning` to `error` requires:
   - Zero false-positive reports in the prior release cycle.
   - At least one golden test covering the promoted rule.
2. Relaxing a rule (error -> warning) requires a comment in the fixture's
   change log explaining the rationale.
3. Format-rule changes (e.g., regex patterns) require updating all affected
   golden fixtures and re-running the full validator suite.

### Retirement

1. Rules may be retired by moving them to a `retired_rules` section in the
   fixture with an expiry date and reason.
2. Retired rules must remain in the fixture for at least one release cycle
   for audit traceability.

## Suppression Policy

1. Known-benign violations may be suppressed via `suppression_entries` in the
   rule fixture.
2. Every suppression must include:
   - `suppression_id`: unique identifier.
   - `rule_id`: the rule being suppressed.
   - `reason`: human-readable justification.
   - `scope`: flow/scenario constraint limiting the suppression.
   - `expires`: date after which the suppression is invalid.
3. Maximum 10 active suppressions at any time.
4. Suppressions must be reviewed every 30 days; expired suppressions must be
   removed or renewed with updated justification.
5. Suppressed violations score 0 deduction (do not lower quality score).

## Quality Scoring

- **Max score**: 100
- **Error violation**: -10 points each
- **Warning violation**: -3 points each
- **Suppressed violation**: 0 points
- **Pass threshold**: >= 80
- **Warn threshold**: >= 60
- **Fail**: < 60

## Severity Classification

Severity levels in ascending order: `info`, `warning`, `error`, `critical`.

Default severity by outcome class:
- `success` -> `info`
- `cancelled` -> `warning`
- `failed` -> `error`

Conflict escalation (e.g., flow/event mismatch) always escalates to `critical`.

## Determinism Invariants

1. Validator output must be deterministic: same input -> same violations list.
2. Violation lists are sorted by `(event_index, rule_id)`.
3. Quality score computation is pure: `max_score - sum(deductions)`.

## CI Integration

Validation commands:

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_logging_docs cargo test --test doctor_logging_quality_validators -- --nocapture
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_logging_docs cargo check --all-targets
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_logging_docs cargo clippy --all-targets -- -D warnings
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_logging_docs cargo fmt --check
```

## Cross-References

- `docs/doctor_logging_contract.md` — baseline structured logging contract
- `docs/doctor_observability_taxonomy.md` — advanced observability layer
- `docs/doctor_performance_budget_contract.md` — performance budget gates
- `tests/fixtures/doctor_logging_quality/log_quality_rules.json` — canonical rules
- `tests/fixtures/doctor_logging_quality/sample_event_stream.json` — golden stream
