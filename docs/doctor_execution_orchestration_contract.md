# doctor_asupersync Execution Orchestration Contract

## Scope

This contract defines deterministic behavior for the Track 3 `rch`-backed command
execution adapter (`asupersync-2b4jj.3.1`):

- command normalization and class-aware routing
- `rch` invocation wrapping for heavy cargo lanes
- timeout/cancellation state-machine semantics
- failure taxonomy and fallback behavior when `rch` is unavailable
- artifact-manifest requirements for replay/audit workflows

## Contract Version

- `doctor-exec-adapter-v1`
- depends on logging contract `doctor-logging-v1`

## Output Schema

The adapter contract is represented by `ExecutionAdapterContract`:

```json
{
  "contract_version": "doctor-exec-adapter-v1",
  "logging_contract_version": "doctor-logging-v1",
  "required_request_fields": ["command_class", "command_id", "correlation_id", "prefer_remote", "raw_command"],
  "required_result_fields": ["artifact_manifest", "command_id", "exit_code", "outcome_class", "route", "routed_command", "state"],
  "command_classes": [
    {
      "class_id": "cargo_test",
      "label": "cargo test",
      "allowed_prefixes": ["cargo test"],
      "force_rch": true,
      "default_timeout_secs": 1800
    }
  ],
  "route_policies": [
    {
      "policy_id": "remote_rch_default",
      "condition": "prefer_remote_and_rch_available",
      "route": "remote_rch",
      "retry_strategy": "bounded_backoff",
      "max_retries": 2
    }
  ],
  "timeout_profiles": [
    {
      "class_id": "cargo_test",
      "soft_timeout_secs": 1500,
      "hard_timeout_secs": 1800,
      "cancel_grace_secs": 30
    }
  ],
  "state_transitions": [
    {"from_state": "planned", "trigger": "enqueue", "to_state": "queued"},
    {"from_state": "queued", "trigger": "start", "to_state": "running"},
    {"from_state": "running", "trigger": "cancel", "to_state": "cancel_requested"},
    {"from_state": "cancel_requested", "trigger": "cancel_completed", "to_state": "cancelled"}
  ],
  "failure_taxonomy": [
    {
      "code": "rch_unavailable",
      "severity": "medium",
      "retryable": true,
      "operator_action": "Apply local fallback policy and log route downgrade."
    }
  ],
  "artifact_manifest_fields": ["command_provenance", "outcome_class", "run_id", "scenario_id", "trace_id", "transcript_path", "worker_route"]
}
```

## Determinism + Safety Invariants

1. All string arrays are lexical, duplicate-free, and non-empty.
2. Command classes are lexical by `class_id`; timeout profiles must exactly match class IDs.
3. `force_rch=true` classes must use cargo-prefixed allowed command patterns.
4. Route policies must include both:
   - `remote_rch_default`
   - `local_fallback_on_rch_unavailable`
5. Timeouts obey `soft_timeout_secs <= hard_timeout_secs` and non-zero cancellation grace.
6. State transitions are deterministic and include mandatory cancellation edges:
   - `running --cancel--> cancel_requested`
   - `cancel_requested --cancel_completed--> cancelled`
   - `cancel_requested --cancel_timeout--> failed`
7. Failure taxonomy includes at least:
   - `command_failed`
   - `command_timeout`
   - `invalid_transition`
   - `rch_unavailable`

## Command Planning Semantics

`plan_execution_command` behavior:

1. Normalize raw command by collapsing whitespace.
2. Enforce class-specific `allowed_prefixes`.
3. If remote route selected, wrap as:
   - `rch exec -- <normalized-command>`
4. If `rch` is unavailable, apply fallback policy deterministically.
5. Emit plan with deterministic initial state `planned` and manifest field requirements.

## State-Machine Semantics

`advance_execution_state` validates contract and allows only declared edges.
Invalid `(state, trigger)` pairs fail closed with deterministic error text.

## Failure Taxonomy and Runbook

- `command_failed`: inspect stderr and open remediation workflow.
- `command_timeout`: retry with bounded policy and attach transcript artifact.
- `invalid_transition`: abort run and emit state-machine diagnostics.
- `rch_unavailable`: downgrade to local route, record downgrade in structured logs.

## Logging + Artifact Requirements

Every execution lane must retain replay/audit pointers in manifest fields:

- `run_id`
- `scenario_id`
- `trace_id`
- `command_provenance`
- `worker_route`
- `outcome_class`
- `transcript_path`

These fields align with `doctor-logging-v1` to keep command lineage and replay
artifacts deterministic across unit and E2E flows.
