# doctor_asupersync Scenario Composer Contract

## Scope

This contract defines deterministic behavior for Track 3 scenario composition and
run-queue management (`asupersync-2b4jj.3.2`):

- reusable scenario template catalog
- deterministic request-to-queue entry composition
- queue ordering and dispatch policy semantics
- queue capacity and failure taxonomy requirements
- dependency contract versions required for execution + logging joins

The schema is represented by `ScenarioComposerContract` in
`src/cli/doctor/mod.rs`.

## Contract Version

- `doctor-scenario-composer-v1`
- depends on execution adapter `doctor-exec-adapter-v1`
- depends on logging contract `doctor-logging-v1`

## Output Schema

```json
{
  "contract_version": "doctor-scenario-composer-v1",
  "execution_adapter_version": "doctor-exec-adapter-v1",
  "logging_contract_version": "doctor-logging-v1",
  "required_request_fields": [
    "correlation_id",
    "requested_by",
    "run_id",
    "seed",
    "template_id"
  ],
  "required_run_fields": [
    "command_classes",
    "correlation_id",
    "priority",
    "queue_id",
    "required_artifacts",
    "retries_remaining",
    "run_id",
    "seed",
    "state",
    "template_id"
  ],
  "scenario_templates": [
    {
      "template_id": "scenario_regression_bundle",
      "description": "Full regression execution with replay-ready transcript capture.",
      "required_command_classes": ["cargo_check", "cargo_clippy", "cargo_test"],
      "required_artifacts": ["structured_log", "summary_report", "transcript"],
      "default_priority": 180,
      "max_retries": 2,
      "requires_replay_seed": true
    }
  ],
  "queue_policy": {
    "max_concurrent_runs": 2,
    "max_queue_depth": 32,
    "dispatch_order": "priority_then_run_id",
    "priority_bands": ["p0_critical", "p1_high", "p2_normal", "p3_low"],
    "cancellation_policy": "cancel_duplicate_run_id"
  },
  "failure_taxonomy": [
    {
      "code": "queue_full",
      "severity": "medium",
      "retryable": true,
      "operator_action": "Drain queue or increase queue budget in policy."
    }
  ]
}
```

## Determinism and Safety Invariants

1. `required_request_fields` and `required_run_fields` are lexical, duplicate-free, and include all required keys.
2. `scenario_templates` is non-empty and lexical by `template_id`.
3. Each template has non-empty description, lexical duplicate-free command/artifact lists, and `max_retries <= 8`.
4. Every `required_command_classes` member must exist in `doctor-exec-adapter-v1`.
5. If `requires_replay_seed=true`, template `default_priority` must be at least `100`.
6. Queue policy is bounded and deterministic:
   - `max_concurrent_runs > 0`
   - `max_queue_depth > 0`
   - `max_concurrent_runs <= max_queue_depth`
   - `dispatch_order == "priority_then_run_id"`
   - `cancellation_policy == "cancel_duplicate_run_id"`
7. Failure taxonomy is non-empty, lexical by `code`, and includes:
   - `invalid_seed`
   - `queue_full`
   - `unknown_template`
8. Failure severity must be one of `critical|high|medium|low`; `operator_action` must be non-empty.

## Compose Semantics

`compose_scenario_run(contract, request)` performs deterministic validation and
composition:

1. Validate the full contract before composing.
2. Require non-empty `run_id` and `requested_by`.
3. Require slug-like `correlation_id`.
4. Resolve `template_id` from `scenario_templates`; unknown template fails closed.
5. If template requires replay seed, `seed` must be non-empty and slug-like.
6. Use `priority_override` when provided, else template `default_priority`.
7. Emit queue entry with deterministic fields:
   - `queue_id = "queue-" + run_id`
   - initial `state = "queued"`
   - template command/artifact requirements copied directly

## Queue Build and Dispatch Semantics

`build_scenario_run_queue(contract, requests)`:

1. Validate contract and queue depth (`requests.len() <= max_queue_depth`).
2. Compose each request with `compose_scenario_run`.
3. Sort deterministically by:
   - descending `priority`
   - ascending `run_id`
   - ascending `template_id`

`dispatch_scenario_run_queue(contract, entries)`:

1. Validate contract and queue depth (`entries.len() <= max_queue_depth`).
2. Re-sort entries with the same deterministic ordering.
3. Mark first `max_concurrent_runs` entries as `running`.
4. Leave all remaining entries as `queued`.

## Failure Taxonomy and Runbook

- `invalid_seed`: caller supplied invalid or missing seed for seed-required template.
- `unknown_template`: caller referenced template not present in contract.
- `queue_full`: queue exceeded `max_queue_depth`; drain queue or adjust policy.

These failures are deterministic and suitable for replay in unit/E2E artifact
flows.

## Logging and Correlation Requirements

Scenario flows must preserve correlation and replay lineage with:

- `run_id`
- `template_id`
- `correlation_id`
- `seed`
- queue state transitions (`queued`/`running`)

These fields align with `doctor-logging-v1` for deterministic joins across
scenario decisions, execution commands, and diagnostics artifacts.
