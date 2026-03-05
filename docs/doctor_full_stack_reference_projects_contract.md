# doctor_asupersync Full-Stack Reference Projects Contract

**Bead**: `asupersync-2b4jj.6.5`  
**Parent**: Track 6 - Quality gates, packaging, and rollout  
**Primary Runner**: `scripts/test_doctor_full_stack_reference_projects_e2e.sh`  
**Validation Tests**: `tests/doctor_full_stack_reference_project_matrix.rs`

## Purpose

Define deterministic, reproducible full-stack doctor regression coverage across
reference-project complexity bands. This contract ensures the suite verifies
workflow behavior end-to-end with explicit failure classification and replay
metadata, not single-stage smoke checks.

## Dogfood Rollout Addendum (`asupersync-2b4jj.6.4`)

This addendum defines the rollout and adoption-success metric contract used to
pilot `doctor_asupersync` on `asupersync` and at least one additional reference
profile. It is intentionally attached to this full-stack matrix contract so
rollout decisions are grounded in deterministic suite artifacts.

### Required Adoption Metrics

All rollout summaries must include the following quantitative metrics:

1. `diagnosis_time_delta_pct`: relative change in diagnosis-path runtime between
   `run1` and `run2` for the selected diagnosis baseline profile.
2. `false_positive_rate_pct`: share of stage failures in `run1` that do not
   reproduce in `run2` for the same profile/stage pair.
3. `false_negative_rate_pct`: share of stage passes in `run1` that fail in
   `run2` for the same profile/stage pair.
4. `remediation_success_rate_pct`: pass ratio for remediation/reporting stages
   in the `large` profile.
5. `operator_confidence_score`: deterministic 0-100 score computed from rollout
   quality signals (diagnosis delta, false-positive rate, false-negative rate,
   remediation success rate, determinism stability).

### Metric Definitions (Deterministic Form)

Use only values derivable from run artifacts:

1. `diagnosis_time_delta_pct`:
   `((run2_diagnosis_seconds - run1_diagnosis_seconds) / max(run1_diagnosis_seconds, 1)) * 100`
2. `false_positive_rate_pct`:
   `(count(run1_failed_and_run2_passed_pairs) / max(total_stage_pairs, 1)) * 100`
3. `false_negative_rate_pct`:
   `(count(run1_passed_and_run2_failed_pairs) / max(total_stage_pairs, 1)) * 100`
4. `remediation_success_rate_pct`:
   `(large_profile_passed_remediation_stage_count / max(large_profile_total_remediation_stage_count, 1)) * 100`
5. `operator_confidence_score`:
   deterministic weighted score with explicit weights and clamped [0,100]
   output. The formula and weights must be logged in the summary artifact.

### Rollout Decision Gate

Rollout remains blocked unless all conditions hold:

1. Track-6 quality-gate dependencies are green (`2b4jj.6.6`, `2b4jj.6.7`,
   `2b4jj.6.8`).
   Dependency statuses are provided via
   `QUALITY_GATE_2B4JJ_6_6_STATUS`, `QUALITY_GATE_2B4JJ_6_7_STATUS`,
   `QUALITY_GATE_2B4JJ_6_8_STATUS`; any non-`green` value blocks rollout.
2. `false_positive_rate_pct` and `false_negative_rate_pct` are each at or below
   declared thresholds.
3. `remediation_success_rate_pct` is at or above declared threshold.
4. Determinism check for profile outcomes remains green.
5. Summary includes explicit decision: `continue`, `hold`, or `rollback`,
   with rationale and follow-up actions.

### Structured Logging Requirements

In addition to stage-level logging fields, rollout summaries must include:

1. `rollout_decision`
2. `rollout_gate_status`
3. `adoption_metrics`
4. `adoption_metric_thresholds`
5. `operator_confidence_signals`
6. `quality_gate_dependencies`
7. `quality_gate_failures`
8. `followup_actions`
9. `artifact_links`

### Artifact Requirements

The final summary bundle must include deterministic pointers to:

1. `run1.json`
2. `run2.json`
3. `profiles.final.json`
4. rollout-level adoption metric summary (embedded in `summary.json`)
5. per-failure repro commands for any gate breach

## Reference Project Matrix

The suite must include exactly three profile bands:

1. `small`
2. `medium`
3. `large`

Profile-to-stage mapping:

| Profile | Stage Scripts |
|---|---|
| `small` | `scripts/test_doctor_workspace_scan_e2e.sh`, `scripts/test_doctor_invariant_analyzer_e2e.sh` |
| `medium` | `scripts/test_doctor_orchestration_state_machine_e2e.sh`, `scripts/test_doctor_scenario_coverage_packs_e2e.sh` |
| `large` | `scripts/test_doctor_remediation_verification_e2e.sh`, `scripts/test_doctor_remediation_failure_injection_e2e.sh`, `scripts/test_doctor_report_export_e2e.sh` |

## Orchestration Controls

Runner behavior requirements:

1. Execute selected profile stages twice (`run1`, `run2`).
2. Preserve stage order per profile.
3. Capture per-stage status, exit code, timings, and log path.
4. Build per-profile report objects with stage-level outcomes.
5. Emit a run-level summary that maps each profile to a terminal state.

## Deterministic Seed Handling

Seed policy:

1. Base seed: `TEST_SEED` (default `4242`).
2. Profile seed derivation: `<base-seed>:<profile-id>`.
3. All stage scripts inherit the profile-scoped `TEST_SEED`.
4. Same inputs must yield identical profile outcome state across `run1` and `run2`.

## Scenario Selection

`PROFILE_MODE` contract:

1. `all` (default): execute `small`, `medium`, `large`.
2. `small`: execute only `small`.
3. `medium`: execute only `medium`.
4. `large`: execute only `large`.

Any other value is invalid and must fail fast with a contract error.

## Failure Classification

Stage failures must classify into one of:

1. `timeout` (exit code `124`)
2. `workspace_scan_failure`
3. `invariant_analyzer_failure`
4. `orchestration_failure`
5. `remediation_or_reporting_failure`
6. `unknown_failure`

The class is attached to the stage record and propagated to failed profile
summaries.

## Structured Logging and Transcript Requirements

Each stage record must contain:

1. `profile_id`
2. `run_id`
3. `stage_id`
4. `script`
5. `started_ts`
6. `ended_ts`
7. `status`
8. `exit_code`
9. `failure_class`
10. `log_file`
11. `summary_path` (if available from stage runner output)
12. `summary_status`
13. `repro_command`

This preserves command provenance and artifact linkage needed for deterministic
replay triage.

## Final Report Contract

Final summary output must be `e2e-suite-summary-v3` and include:

1. `suite_id = doctor_full_stack_reference_projects_e2e`
2. `scenario_id = E2E-SUITE-DOCTOR-FULLSTACK-REFERENCE-PROJECTS`
3. deterministic run timestamps and seed
4. `run1_report`, `run2_report`, and `profiles.final.json` pointers
5. pass/fail counts by profile
6. failed profile entries with failure classes and repro commands

Artifact root:

`target/e2e-results/doctor_full_stack_reference_projects/artifacts_<timestamp>/`

## CI Validation

Required quality gates:

1. `rch exec -- cargo test --features cli --test doctor_full_stack_reference_project_matrix -- --nocapture`
2. `PROFILE_MODE=all ./scripts/test_doctor_full_stack_reference_projects_e2e.sh`
3. `rch exec -- cargo fmt --check`
4. `rch exec -- cargo check --all-targets`
5. `rch exec -- cargo clippy --all-targets -- -D warnings`

If unrelated pre-existing failures block global linting, they must be recorded
with file paths and not misattributed to this bead.

## Cross-References

1. `docs/doctor_e2e_harness_contract.md`
2. `docs/doctor_logging_contract.md`
3. `docs/doctor_scenario_composer_contract.md`
4. `docs/doctor_remediation_recipe_contract.md`
5. `scripts/test_doctor_full_stack_reference_projects_e2e.sh`
6. `tests/doctor_full_stack_reference_project_matrix.rs`
