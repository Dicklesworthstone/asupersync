# doctor_asupersync E2E Harness Core Contract

## Scope

This contract defines deterministic e2e harness primitives for Track 3
(`asupersync-2b4jj.3.6`):

- deterministic harness configuration parsing
- stage-level seed propagation and transcript generation
- deterministic artifact-index generation for replay/debug workflows
- explicit lifecycle and failure-taxonomy requirements
- strict dependency linkage to execution + logging contracts

The schema is represented by `E2eHarnessCoreContract` in
`src/cli/doctor/mod.rs`.

## Contract Version

- `doctor-e2e-harness-v1`
- depends on execution adapter `doctor-exec-adapter-v1`
- depends on logging contract `doctor-logging-v1`

## Output Schema

```json
{
  "contract_version": "doctor-e2e-harness-v1",
  "execution_adapter_version": "doctor-exec-adapter-v1",
  "logging_contract_version": "doctor-logging-v1",
  "required_config_fields": [
    "correlation_id",
    "expected_outcome",
    "requested_by",
    "run_id",
    "scenario_id",
    "script_id",
    "seed",
    "timeout_secs"
  ],
  "required_transcript_fields": [
    "correlation_id",
    "events",
    "run_id",
    "scenario_id",
    "seed"
  ],
  "required_artifact_index_fields": [
    "artifact_class",
    "artifact_id",
    "artifact_path",
    "checksum_hint"
  ],
  "lifecycle_states": ["cancelled", "completed", "failed", "running", "started"],
  "failure_taxonomy": [
    {
      "code": "config_missing",
      "severity": "high",
      "retryable": false,
      "operator_action": "Provide all required config fields and retry."
    },
    {
      "code": "script_timeout",
      "severity": "medium",
      "retryable": true,
      "operator_action": "Increase timeout budget or reduce scenario scope."
    }
  ]
}
```

## Determinism and Safety Invariants

1. Required-field arrays are lexical, duplicate-free, and include all mandatory keys.
2. Config parsing fails closed when any required field is missing or empty.
3. `run_id`, `scenario_id`, `correlation_id`, `seed`, and `script_id` must be slug-like.
4. `timeout_secs` must parse as `u32` and be greater than zero.
5. `expected_outcome` must be one of `success|failed|cancelled`.
6. Lifecycle states must include deterministic progression anchors: `started`, `running`, and one terminal state (`completed|failed|cancelled`).
7. Failure taxonomy must include `config_missing`, `invalid_seed`, and `script_timeout` with valid severity classes.

## Config and Seed Semantics

`parse_e2e_harness_config(contract, raw)`:

1. Validates contract first.
2. Enforces all required config fields.
3. Parses timeout and validates outcome class.
4. Emits normalized deterministic `E2eHarnessConfig`.

`propagate_harness_seed(seed, stage)`:

1. Requires slug-like root seed and stage id.
2. Produces deterministic stage seed as `<seed>-<stage>`.
3. Fails closed on invalid input.

## Transcript Semantics

`build_e2e_harness_transcript(contract, config, stages)`:

1. Requires non-empty stage list.
2. Requires all stage ids slug-like.
3. Emits ordered events with 1-based `sequence`.
4. Applies deterministic state policy:
   - first stage: `started`
   - intermediate stages: `running`
   - final stage: terminal state from `expected_outcome`
5. Emits deterministic per-stage `propagated_seed` for replay joins.

## Artifact Index Semantics

`build_e2e_harness_artifact_index(contract, transcript)` emits lexical
artifact entries for:

- `structured_log`
- `summary`
- `transcript`

All artifact paths are rooted at:

`artifacts/<run_id>/doctor/e2e/`

Each entry includes deterministic `checksum_hint` values suitable for
cross-artifact correlation and replay indexing.

## Logging and Replay Requirements

Harness output must preserve these correlation keys across transcript and
artifact records:

- `run_id`
- `scenario_id`
- `correlation_id`
- `seed`
- stage sequence + terminal outcome

These guarantees align with `doctor-logging-v1` and the execution adapter to
keep scenario replay deterministic and auditable.

## Scenario Coverage Packs Extension

Track 3 scenario-coverage packs (`asupersync-2b4jj.3.5`) are represented by
`DoctorScenarioCoveragePacksContract` and `DoctorScenarioCoveragePackSmokeReport`
in `src/cli/doctor/mod.rs`.

Contract version:

- `doctor-scenario-coverage-packs-v1`
- depends on `doctor-e2e-harness-v1`
- depends on `doctor-logging-v1`

Canonical CLI exports:

- `asupersync doctor scenario-coverage-pack-contract --format json`
- `asupersync doctor scenario-coverage-pack-smoke --selection-mode all --seed seed-4242 --format json`

Minimum required packs (must always exist):

1. `pack-cancellation`
2. `pack-retry`
3. `pack-degraded-dependency`
4. `pack-recovery`

Each pack must define:

1. deterministic `stages` (slug-like ids) for transcript generation
2. canonical `workflow_variant` and `expected_outcome`
3. `required_artifact_classes` = `structured_log`, `summary`, `transcript`
4. `failure_cluster` for failure clustering and triage joins

Policy for adding a new high-value pack:

1. Specify the new workflow gap and why existing four packs do not cover it.
2. Add deterministic stages and expected terminal-outcome oracle.
3. Add/extend unit tests covering selection behavior and oracle checks.
4. Ensure `scripts/test_doctor_scenario_coverage_packs_e2e.sh` validates the new pack.
5. Keep contract arrays lexically sorted and update `minimum_required_pack_ids` only when justified.

## Remediation Failure-Injection Extension

Track 4 remediation safety (`asupersync-2b4jj.4.4`) extends harness coverage with:

- `scripts/test_doctor_remediation_failure_injection_e2e.sh`
  - deterministic repeated execution via `rch`
  - required guided-remediation failure-path tests
  - deterministic pass-set diff checks and required-test enforcement
  - `e2e-suite-summary-v3` artifact output under
    `target/e2e-results/doctor_remediation_failure_injection/`

Failure taxonomy assertions for this extension focus on:

1. approval gating containment (`blocked_pending_approval`)
2. partial apply failure requiring rollback (`partial_apply_failed`, `rollback_recommended`)
3. diagnostic completeness (`decision_rationale`, `rollback_instructions`, `recovery_instructions`)
