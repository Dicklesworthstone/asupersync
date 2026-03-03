# WASM Pilot Telemetry, SLO, and Observability Contract

Contract ID: `wasm-pilot-observability-contract-v1`  
Primary bead: `asupersync-umelq.17.2`

## Goal

Define deterministic pilot telemetry and SLO evaluation rules that produce:

1. schema-stable telemetry summaries,
2. actionable alerts with owner routing and remediation pointers,
3. deterministic replay linkage for incident drills,
4. wasm/native parity checks across supported frameworks.

## Canonical Evaluator

Script:

- `scripts/evaluate_wasm_pilot_cohort.py`

Self-test:

```bash
python3 scripts/evaluate_wasm_pilot_cohort.py --self-test
```

Telemetry/SLO evaluation run:

```bash
python3 scripts/evaluate_wasm_pilot_cohort.py \
  --telemetry-input artifacts/pilot/pilot_observability_events.json \
  --telemetry-output artifacts/pilot/pilot_observability_summary.json \
  --telemetry-log-output artifacts/pilot/pilot_observability_alerts.ndjson
```

Deterministic e2e failure-injection gate:

```bash
bash scripts/test_wasm_pilot_observability_e2e.sh
```

## Telemetry Input Schema

Input must be either:

- object: `{ "events": [ ... ], "seed": <optional>, "parity_tolerance_pct_default": <optional> }`
- array: `[ ...events ]`

Each event must include:

- `scenario_id`
- `framework` (`vanilla`, `react`, `next`)
- `profile_family` (`wasm`, `native`)
- `signal_name`
- `signal_source`
- `signal_value`
- `threshold_kind` (`max` or `min`)
- `threshold_value`
- `capability_surface`
- `owner_route`
- `replay_command`
- `trace_pointer`
- `remediation_pointer`

Optional:

- `parity_tolerance_pct` (defaults to global default, then `5.0`)

## Output Contracts

Summary JSON schema:

- `schema_version = asupersync-pilot-observability-v1`
- `status` (`pass`/`fail`)
- `event_count`
- `alerts_count`
- `ci_parity_ok`
- `threshold_evaluations[]` (threshold gate decisions)
- `aggregations[]` (signal aggregation rows)
- `parity_checks[]` (wasm/native signal parity checks)
- `alerts[]` (actionable incident alerts)
- `incident_drill_links[]` (`replay_command` + `trace_pointer`)
- `owner_routes[]`

Alert log NDJSON events:

- `pilot_slo_alert` entries for each threshold breach
- one terminal `pilot_slo_gate_summary` entry with pass/fail and parity state

## Alerting and Owner Routing Rules

An alert is emitted when `threshold_kind` evaluation fails:

- `max`: `signal_value > threshold_value`
- `min`: `signal_value < threshold_value`

Every alert carries:

- signal metadata (`signal_name`, `signal_source`, `framework`, `profile_family`)
- threshold metadata (`threshold_kind`, `threshold_value`, `signal_value`)
- capability metadata (`capability_surface`)
- routing metadata (`owner_route`)
- replay metadata (`replay_command`, `trace_pointer`)
- remediation metadata (`remediation_pointer`)

Severity:

- `critical` when breach magnitude is at least 50% beyond threshold
- otherwise `high`

## CI Parity Contract

Parity check compares latest wasm/native values for each (`framework`, `signal_name`):

- `delta_pct = |wasm - native| / max(|native|, 1e-9) * 100`
- breach when `delta_pct > tolerance_pct`

CI parity gate:

- `ci_parity_ok = true` only when no parity breaches are present
- overall status is `fail` if either threshold alerts exist or parity breaches exist

## Incident Drill Linkage Requirement

All failure paths must preserve deterministic replay references:

- replay command reproducible as written,
- trace pointer stable and machine-parseable,
- owner route included for escalation.

Pilot observability artifacts are non-compliant if any alert is missing replay linkage.
