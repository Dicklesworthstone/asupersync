# Semantic CI Signal Quality (SEM-10.5)

This document defines the SEM-10.5 guardrail for verification signal quality.

## Goal

Keep semantic gates trusted and maintainable by enforcing:

1. Low deterministic replay instability (flake rate)
2. Low false-positive proxy rate
3. Bounded runtime cost against profile budgets
4. Concise failure output with direct links to deep diagnostics artifacts

## Gate Command

```bash
bash scripts/check_semantic_signal_quality.sh \
  --report target/semantic-verification/verification_report.json \
  --dashboard target/semantic-verification/flake/<run-id>/variance_dashboard.json \
  --output target/semantic-verification/signal-quality/signal_quality_report.json
```

Defaults:

- `max_flake_rate_pct = 0`
- `max_false_positive_rate_pct = 5`
- `max_runtime_ratio = 1.0`

The command exits non-zero when thresholds are violated.

## Metrics

- `flake_rate_pct`:
  - `unstable_suite_count / suite_count * 100`
- `false_positive_proxy_rate_pct`:
  - percentage of unstable suites with `outcomes.fail == 0`
- `runtime_ratio`:
  - `verification_report.total_duration_s / profile_contract.runtime_budget_s`

## Diagnostics Link Contract

Signal-quality output must include:

1. Existing required profile artifacts from `verification_report.profile_contract.required_artifacts`
2. Variance events NDJSON pointer (`variance_events_ndjson`)
3. Variance summary pointer (`summary`)

If links are missing, the gate fails.

## Extension and Maintenance Guidance

When adding a new semantic verification suite:

1. Update `scripts/run_semantic_verification.sh` profile contracts
2. Ensure suite artifacts are listed in `required_artifacts`
3. Ensure suite outputs include stable deep-log pointers
4. Add or update fixture coverage in:
   - `tests/fixtures/semantic_signal_quality/*`
   - `tests/semantic_signal_quality_contract.rs`
5. Keep thresholds explicit; do not silently relax defaults

When tuning thresholds:

1. Document rationale and expected tradeoffs in this file
2. Add a fixture reproducing the targeted behavior
3. Verify deterministic rerun commands remain accurate

## Deterministic Rerun

The signal-quality report embeds rerun commands for:

1. Unified verification runner
2. Flake detector
3. Signal-quality checker itself

This keeps CI failures reproducible and debuggable without ad-hoc command
discovery.
