# Nightly Stress, Soak, and Flake-Burndown Automation

**Bead**: `asupersync-umelq.18.10`
**Status**: Active
**Dependencies**: `asupersync-umelq.18.9` (golden trace corpus), `asupersync-umelq.18.5` (flake governance)

## Purpose

Automate nightly stress/soak pipeline execution with trend-aware flake analytics,
ownership-routed burndown reporting, and reliability regression gates that block
release channel promotion when quality degrades.

## Architecture

```
scripts/run_nightly_stress_soak.sh       Orchestrator: runs stress/soak suites in sequence
  |-> cargo test (stress suites)         cancellation_stress_e2e, obligation_leak_stress, scheduler_stress
  |-> cargo test (soak suites)           tokio_quic_h3_soak_adversarial
  |-> scripts/run_semantic_flake_detector.sh  Flake detection pass
  |-> scripts/generate_flake_burndown_report.sh  Trend analysis + burndown

Outputs:
  target/nightly-stress/{run_id}/
    run_manifest.json        Per-suite pass/fail/duration/artifact pointers
    trend_report.json        Historical trend metrics (flake rate, MTTF, pass rate)
    burndown_report.json     Flake burndown tracking with owner routing
    suite_logs/              Per-suite stdout/stderr capture
```

## Runner Contract (`scripts/run_nightly_stress_soak.sh`)

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--run-id ID` | `nightly-YYYYMMDDTHHMMSSZ` | Unique run identifier |
| `--suites NAMES` | `all` | Comma-separated suite filter |
| `--timeout SECS` | `3600` | Per-suite timeout |
| `--ci` | `false` | CI mode: exit 1 on regression |
| `--json` | `true` | Emit JSON manifests |
| `--trend-window N` | `14` | Days of history for trend analysis |
| `--stress-schedules N` | `1000000` | Obligation stress schedule count |
| `-h, --help` | | Show usage |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All suites passed, no trend regressions |
| 1 | Suite failure or trend regression detected |
| 2 | Configuration error |

### Suite Registry

| Suite ID | Test Target | Category |
|----------|-------------|----------|
| `cancellation_stress` | `tests/cancellation_stress_e2e.rs` | stress |
| `obligation_leak` | `tests/obligation_leak_stress.rs` | stress |
| `scheduler_fairness` | `tests/scheduler_stress_fairness_e2e.rs` | stress |
| `quic_h3_soak` | `tests/tokio_quic_h3_soak_adversarial.rs` | soak |
| `flake_detection` | `scripts/run_semantic_flake_detector.sh` | flake |

## Run Manifest Schema (`run_manifest.json`)

```json
{
  "schema_version": "nightly-stress-manifest-v1",
  "run_id": "nightly-20260304T030000Z",
  "started_at_utc": "2026-03-04T03:00:00Z",
  "finished_at_utc": "2026-03-04T04:15:00Z",
  "total_duration_secs": 4500,
  "overall_result": "pass",
  "suites": [
    {
      "id": "cancellation_stress",
      "category": "stress",
      "result": "pass",
      "duration_secs": 120,
      "tests_run": 8,
      "tests_passed": 8,
      "tests_failed": 0,
      "log_file": "suite_logs/cancellation_stress.log",
      "repro_command": "cargo test --test cancellation_stress_e2e -- --nocapture"
    }
  ],
  "environment": {
    "rust_version": "nightly-2026-03-01",
    "os": "linux",
    "arch": "x86_64",
    "obligation_stress_schedules": 1000000
  }
}
```

## Trend Report Schema (`trend_report.json`)

```json
{
  "schema_version": "nightly-trend-report-v1",
  "run_id": "nightly-20260304T030000Z",
  "window_days": 14,
  "runs_in_window": 12,
  "metrics": {
    "overall_pass_rate_pct": 100.0,
    "flake_rate_pct": 0.0,
    "mean_duration_secs": 4200,
    "duration_variance_pct": 8.5,
    "mean_time_to_failure_hours": null,
    "regression_detected": false
  },
  "per_suite": [
    {
      "id": "cancellation_stress",
      "pass_rate_pct": 100.0,
      "flake_rate_pct": 0.0,
      "mean_duration_secs": 115,
      "trend": "stable"
    }
  ],
  "regressions": []
}
```

## Burndown Report Schema (`burndown_report.json`)

```json
{
  "schema_version": "nightly-burndown-report-v1",
  "generated_at_utc": "2026-03-04T04:15:00Z",
  "summary": {
    "total_open_flakes": 0,
    "critical_flakes": 0,
    "high_flakes": 0,
    "medium_flakes": 0,
    "overdue_sla_count": 0,
    "resolved_last_7d": 2,
    "new_last_7d": 0,
    "burndown_trend": "improving"
  },
  "open_items": [],
  "owner_routing": [],
  "sla_breaches": [],
  "history": [
    {
      "date": "2026-03-03",
      "open_flakes": 0,
      "resolved": 1,
      "new": 0
    }
  ]
}
```

## Reliability Regression Gates

A **trend regression** is detected when any of the following hold compared to
the rolling window:

1. `overall_pass_rate_pct` drops by more than 5 percentage points
2. `flake_rate_pct` exceeds the governance policy threshold (0%)
3. Any suite `mean_duration_secs` increases by more than 50%
4. Any new critical/high severity flake appears in quarantine

When `--ci` mode is active and a regression is detected, the script exits with
code 1 and the release channel promotion is blocked.

## CI Integration

Add to `.github/workflows/nightly-stress.yml`:

```yaml
name: Nightly Stress & Soak
on:
  schedule:
    - cron: '0 3 * * *'
  workflow_dispatch:

jobs:
  stress-soak:
    runs-on: ubuntu-latest
    timeout-minutes: 120
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: bash scripts/run_nightly_stress_soak.sh --ci --json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: nightly-stress-${{ github.run_id }}
          path: target/nightly-stress/
          retention-days: 90
```

## Forensic Artifact Retention

All nightly run artifacts are retained for 90 days in CI. Local runs archive
to `target/nightly-stress/{run_id}/`. Each run includes:

- Per-suite stdout/stderr logs
- Variance dashboard from flake detector
- Quarantine manifest snapshot
- Trend report with historical window
- Burndown report with owner routing

## Cross-References

| Resource | Path |
|----------|------|
| Flake governance policy | `.github/wasm_flake_governance_policy.json` |
| Flake detector | `scripts/run_semantic_flake_detector.sh` |
| Golden trace verifier | `docs/replay-debugging.md` |
| Failure replay cookbook | `docs/semantic_failure_replay_cookbook.md` |
| Cancellation stress tests | `tests/cancellation_stress_e2e.rs` |
| Obligation leak stress tests | `tests/obligation_leak_stress.rs` |
| QUIC/H3 soak scenarios | `tests/tokio_quic_h3_soak_adversarial.rs` |
