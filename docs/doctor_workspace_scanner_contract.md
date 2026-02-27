# doctor scan-workspace and screen-contracts Contracts

## Scope

`asupersync doctor scan-workspace` provides deterministic discovery of:

- Cargo workspace members
- capability-flow surfaces referenced by each member
- evidence paths for each detected surface
- non-fatal scan warnings

This contract defines the output schema and determinism guarantees for
`asupersync-2b4jj.2.1`.

`asupersync doctor screen-contracts` provides deterministic screen-to-engine
payload contracts for primary `doctor_asupersync` surfaces, including typed
request/response schemas, state transitions, and rejection-envelope semantics
for success/cancel/failure flows.

## Command

```bash
asupersync doctor scan-workspace --root <workspace-root>
```

## Output Schema

The command emits a `WorkspaceScanReport`.

```json
{
  "root": "string",
  "workspace_manifest": "string",
  "scanner_version": "doctor-workspace-scan-v1",
  "taxonomy_version": "capability-surfaces-v1",
  "members": [
    {
      "name": "string",
      "relative_path": "string",
      "manifest_path": "string",
      "rust_file_count": 0,
      "capability_surfaces": ["string"]
    }
  ],
  "capability_edges": [
    {
      "member": "string",
      "surface": "string",
      "evidence_count": 0,
      "sample_files": ["string"]
    }
  ],
  "warnings": ["string"],
  "events": [
    {
      "phase": "string",
      "level": "info|warn",
      "message": "string",
      "path": "string|null"
    }
  ]
}
```

## Determinism Guarantees

1. Member ordering is lexical by `relative_path`.
2. Surface ordering is lexical by `surface`.
3. Edge ordering is lexical by `(member, surface)`.
4. Sample file ordering is lexical by relative path.
5. Wildcard expansion (`path/*`) is deterministic.
6. Missing members and unsupported globs are emitted as warnings, not hard failures.

## Surface Taxonomy (v1)

- `cx`
- `scope`
- `runtime`
- `channel`
- `sync`
- `lab`
- `trace`
- `net`
- `io`
- `http`
- `cancel`
- `obligation`

## Warning Semantics

Warnings are advisory and do not fail the command.

Current warning classes:

- missing member manifest (`member missing Cargo.toml`)
- missing wildcard base (`wildcard base missing`)
- unsupported workspace glob form (`unsupported workspace member glob pattern`)
- malformed workspace arrays (`malformed workspace array`, `unterminated workspace array`)
- malformed package metadata (`malformed package name field`, `missing package name`)

## Structured Event Semantics

`events` is deterministic and intended for machine-parsed diagnostics.

- `phase` identifies scan step boundaries (`scan_start`, `workspace_manifest`, `member_discovery`, `member_scan`, `scan_complete`).
- `level` distinguishes informational (`info`) from anomaly (`warn`) records.
- `path` carries the relevant manifest/member path when available.
- Event ordering is stable across runs for identical workspace contents.

## Compatibility Notes

- New fields must be additive and backward-compatible.
- Existing fields are stable for consumers in doctor track 2.
- Taxonomy expansion should append new surfaces without renaming existing labels.
- Event-phase expansion should add new phase labels without changing existing semantics.

---

## doctor screen-contracts Contract

## Command

```bash
asupersync doctor screen-contracts
```

## Output Schema

The command emits a `ScreenEngineContract`.

```json
{
  "contract_version": "doctor-screen-engine-v1",
  "operator_model_version": "doctor-operator-model-v1",
  "global_request_fields": ["contract_version", "correlation_id", "rerun_context", "screen_id"],
  "global_response_fields": ["contract_version", "correlation_id", "outcome_class", "screen_id", "state"],
  "compatibility": {
    "minimum_reader_version": "doctor-screen-engine-v1",
    "supported_reader_versions": ["doctor-screen-engine-v1"],
    "migration_guidance": [
      {
        "from_version": "doctor-screen-engine-v0",
        "to_version": "doctor-screen-engine-v1",
        "breaking": false,
        "required_actions": ["string"]
      }
    ]
  },
  "screens": [
    {
      "id": "string",
      "label": "string",
      "personas": ["string"],
      "request_schema": {
        "schema_id": "string",
        "required_fields": [
          { "key": "string", "field_type": "string", "description": "string" }
        ],
        "optional_fields": [
          { "key": "string", "field_type": "string", "description": "string" }
        ]
      },
      "response_schema": {
        "schema_id": "string",
        "required_fields": [
          { "key": "string", "field_type": "string", "description": "string" }
        ],
        "optional_fields": [
          { "key": "string", "field_type": "string", "description": "string" }
        ]
      },
      "states": ["cancelled", "failed", "idle", "loading", "ready"],
      "transitions": [
        {
          "from_state": "string",
          "to_state": "string",
          "trigger": "string",
          "outcome": "success|cancelled|failed"
        }
      ]
    }
  ],
  "error_envelope": {
    "required_fields": [
      "contract_version",
      "correlation_id",
      "error_code",
      "error_message",
      "rerun_context",
      "validation_failures"
    ],
    "retryable_codes": ["cancelled_request", "stale_contract_version", "transient_engine_failure"]
  }
}
```

## Canonical Screen Surfaces (v1)

- `artifact_audit`
- `bead_command_center`
- `decision_ledger`
- `evidence_timeline`
- `gate_status_board`
- `incident_console`
- `replay_inspector`
- `runtime_health`
- `scenario_workbench`

## Screen Contract Invariants

1. `screens` are lexically ordered by `id` with unique IDs.
2. Request/response field keys are lexically sorted and duplicate-free.
3. Required and optional field sets are disjoint.
4. Every screen defines lexically sorted `states` containing at least `idle` and `loading`.
5. Every screen includes loading-exit transitions for `success`, `cancelled`, and `failed`.
6. Transition `from_state`/`to_state` values must reference declared `states`.
7. Compatibility versions are lexically sorted, duplicate-free, and include `minimum_reader_version`.
8. Error envelope keys and retryable codes are lexically sorted and duplicate-free.

## Exchange and Rejection Semantics

- Contract-conformant exchanges use `correlation_id` + `rerun_context` for replayable traceability.
- Simulated outcomes are normalized to:
  - `success` -> state `ready`
  - `cancelled` -> state `cancelled`
  - `failed` -> state `failed`
- Rejected payloads emit `RejectedPayloadLog` with deterministic `validation_failures`
  plus `contract_version`, `correlation_id`, and `rerun_context`.

## Migration Guidance and Consumer Expectations

Current migration guidance (`v0` -> `v1`) requires downstream consumers to:

1. Accept explicit per-screen transition envelopes instead of implicit status toggles.
2. Require `correlation_id` + `rerun_context` on every request.
3. Validate response payload ordering by schema field key.

Downstream expectations for future versions:

- Additive fields are allowed when `contract_version` is unchanged.
- Any semantic behavior change (state semantics, required fields, or error envelope meaning)
  must bump `contract_version` and include a `migration_guidance` entry.
- Consumers should gate by `supported_reader_versions` and fail closed for unknown versions.
