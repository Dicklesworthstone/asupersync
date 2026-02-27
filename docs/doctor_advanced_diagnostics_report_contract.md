# doctor Advanced Diagnostics Report Extension Contract

## Scope

`doctor-advanced-report-v1` defines report-extension semantics layered on top of
`doctor-core-report-v1`.

It adds deterministic sections for:

1. remediation deltas
2. trust-score transitions
3. collaboration/audit-trail provenance
4. troubleshooting playbook guidance

The extension schema is explicitly mapped to advanced observability taxonomy
outputs (`doctor-observability-v1`).

## Layering

Dependencies:

1. Core report contract: `doctor-core-report-v1`
2. Advanced observability taxonomy: `doctor-observability-v1`
3. Structured logging baseline: `doctor-logging-v1`

Integration handoff gate remains:

- `asupersync-2b4jj.5.5`

## Contract Highlights

`AdvancedDiagnosticsReportExtensionContract` defines:

1. `required_extension_sections`
2. required field sets for each extension section
3. outcome class allow-list
4. taxonomy mapping allow-lists (class/dimension/severity)
5. compatibility and migration guidance

## Extension Payload

`AdvancedDiagnosticsReportExtension` attaches to one base core report via:

1. `base_report_id`
2. `base_report_schema_version`

Sections:

1. `remediation_deltas[]`
2. `trust_transitions[]`
3. `collaboration_trail[]`
4. `troubleshooting_playbooks[]`

All ID vectors are deterministic and lexically ordered.

## Compatibility and Mapping Rules

1. Extension contract version must be `doctor-advanced-report-v1`.
2. Base contract version must be `doctor-core-report-v1`.
3. Taxonomy contract version must be `doctor-observability-v1`.
4. Taxonomy fields in extension payloads must belong to taxonomy allow-lists.
5. `base_report_id` must match the linked core report ID.
6. Command/evidence/finding references must resolve against linked core report.

## Fixture-Driven Validation

`advanced_diagnostics_report_bundle()` ships deterministic fixtures:

1. `advanced_failure_path`
2. `advanced_happy_path`

`run_advanced_diagnostics_report_smoke(...)` validates generation/consumption and
emits deterministic structured-log events for integration/remediation/replay
flows.

## Validation Commands

```bash
rch exec -- env CARGO_TARGET_DIR=target/rch_chartreuse_2b4jj_5_8 cargo test -p asupersync --lib advanced_diagnostics_report -- --nocapture
rch exec -- env CARGO_TARGET_DIR=target/rch_chartreuse_2b4jj_5_8 cargo check --all-targets
rch exec -- env CARGO_TARGET_DIR=target/rch_chartreuse_2b4jj_5_8 cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
