# doctor Structured Logging Contract

## Scope

`asupersync doctor logging-contract` emits the baseline structured logging contract
for `doctor_asupersync` core flows.

This contract defines:

- the required event envelope for deterministic diagnostics
- required correlation primitives and formatting rules
- allowed outcome classes and event taxonomy
- per-flow required/optional fields for execution, replay, remediation, and integration
- compatibility/versioning policy for downstream consumers

## Command

```bash
asupersync doctor logging-contract
```

## Contract Version

- `contract_version`: `doctor-logging-v1`
- Additive field extensions are allowed inside `v1`.
- Semantic changes to required fields, formatting rules, or outcome semantics require a version bump.

## Output Schema

```json
{
  "contract_version": "doctor-logging-v1",
  "envelope_required_fields": [
    {
      "key": "string",
      "field_type": "string|enum",
      "format_rule": "string",
      "description": "string"
    }
  ],
  "correlation_primitives": [
    {
      "key": "run_id|scenario_id|trace_id|command_provenance|outcome_class",
      "format_rule": "string",
      "purpose": "string"
    }
  ],
  "outcome_classes": ["cancelled", "failed", "success"],
  "core_flows": [
    {
      "flow_id": "execution|replay|remediation|integration",
      "description": "string",
      "required_fields": ["string"],
      "optional_fields": ["string"],
      "event_kinds": ["string"]
    }
  ],
  "event_taxonomy": ["string"],
  "compatibility": {
    "minimum_reader_version": "doctor-logging-v1",
    "supported_reader_versions": ["doctor-logging-v1"],
    "migration_guidance": [
      {
        "from_version": "doctor-logging-v0",
        "to_version": "doctor-logging-v1",
        "breaking": false,
        "required_actions": ["string"]
      }
    ]
  }
}
```

## Required Envelope Fields

`doctor-logging-v1` requires these fields on every event:

1. `artifact_pointer`
2. `command_provenance`
3. `flow_id`
4. `outcome_class`
5. `run_id`
6. `scenario_id`
7. `trace_id`

## Correlation Primitive Formatting Rules

1. `run_id`: `run-[a-z0-9._:/-]+`
2. `scenario_id`: `[a-z0-9._:/-]+`
3. `trace_id`: `trace-[a-z0-9._:/-]+`
4. `command_provenance`: single-line shell command
5. `outcome_class`: `cancelled|failed|success`

## Core Flow Coverage

`core_flows` include deterministic requirements for:

- `execution` (build/test/lint gate events)
- `replay` (deterministic replay verification events)
- `remediation` (guided fix + verification events)
- `integration` (adapter and cross-system boundary events)

Each flow must:

1. define lexically sorted, unique `required_fields`
2. define lexically sorted, unique `optional_fields`
3. define lexically sorted, unique `event_kinds`
4. require all correlation primitives
5. keep `event_kinds` as a subset of global `event_taxonomy`

## Determinism + Validation Expectations

`validate_structured_logging_contract` enforces schema and ordering invariants.

`emit_structured_log_event` enforces:

- required field presence
- non-empty required values
- formatting rules for correlation primitives
- flow/event taxonomy compatibility

`run_structured_logging_smoke` and
`validate_structured_logging_event_stream` provide deterministic smoke coverage
across all four core flows and enforce lexical stream ordering by:

- `flow_id`
- `event_kind`
- `trace_id`

## Consumer Guidance

1. Fail closed on unknown `contract_version`.
2. Validate event envelopes before rendering/export.
3. Preserve `command_provenance` and `artifact_pointer` for replay and audit.
4. Treat unknown flow IDs/event kinds as schema violations, not soft warnings.
5. Require explicit migration handling whenever `contract_version` changes.
