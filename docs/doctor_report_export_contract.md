# doctor_asupersync Report Export Contract

This document defines the deterministic report-export contract for bead
`asupersync-2b4jj.5.4`.

## Command

```bash
asupersync --format json doctor report-export \
  --fixture-id advanced_failure_path \
  --out-dir target/e2e-results/doctor_report_export/artifacts \
  --format markdown,json
```

`--fixture-id` is optional. When omitted, all advanced fixtures are exported.

## Output Schema (`doctor-report-export-v1`)

Required top-level fields:

- `schema_version` (`doctor-report-export-v1`)
- `core_schema_version` (`doctor-core-report-v1`)
- `extension_schema_version` (`doctor-advanced-report-v1`)
- `export_root`
- `formats` (array containing `markdown` and/or `json`)
- `exports` (non-empty array)
- `rerun_commands` (array, at least 2 commands)

Required `exports[*]` fields:

- `fixture_id`
- `report_id`
- `output_files` (deterministic sorted list of markdown/json file paths)
- `finding_count`
- `evidence_count`
- `command_count`
- `remediation_outcome_count`
- `validation_status` (`valid`)

## Exported Report Document Shape

For each fixture, the JSON/markdown backend renders a deterministic report
containing:

- summary (`status`, `overall_outcome`, finding totals)
- findings with `evidence_refs` and `command_refs`
- evidence links (`artifact_pointer`, `replay_pointer`, `franken_trace_id`)
- command provenance (`tool`, `exit_code`, `outcome_class`, command text)
- remediation outcomes (`previous_status -> next_status`, taxonomy mapping)
- trust transitions (`previous_score -> next_score`, rationale)
- collaboration trail (`thread_id`, `message_ref`, `bead_ref`)
- troubleshooting playbooks (`ordered_steps`, refs)

## Determinism and Validation Rules

- Core and advanced contracts are validated before export.
- Advanced fixture linkage is validated with
  `validate_advanced_diagnostics_report_extension(...)`.
- Output vectors are normalized deterministically (lexical ordering for ID-based
  sections and refs) before serialization.
- Unknown fixture IDs fail closed with `invalid_argument` and a list of
  available fixture IDs.
- Output file names are deterministic:
  - `<fixture>_report_export.json`
  - `<fixture>_report_export.md`

## E2E Coverage

Deterministic end-to-end validation:

```bash
bash scripts/test_doctor_report_export_e2e.sh
```

This suite verifies:

- repeat-run deterministic command output
- export payload contract conformance
- deterministic JSON and markdown artifact paths/content
- required markdown sections for evidence/provenance/remediation/trust/collaboration/playbooks
