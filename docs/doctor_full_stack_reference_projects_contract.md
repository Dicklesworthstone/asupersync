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
