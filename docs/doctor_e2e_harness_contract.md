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
