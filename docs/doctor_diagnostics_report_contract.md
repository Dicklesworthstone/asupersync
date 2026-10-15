# doctor Core Diagnostics Report Contract

## Scope

`asupersync doctor report-contract` emits the **core diagnostics report** contract
and deterministic fixture bundle for baseline `doctor_asupersync` rendering and
report-consumption paths.

This contract is intentionally limited to core semantics:

- required report envelope sections (`summary`, `findings`, `evidence`, `commands`, `provenance`)
- required field sets per section
- deterministic ordering and reference-integrity rules
- baseline fixture set (happy path, partial-data path, baseline failure path)
- compatibility policy for `doctor-core-report-v1`

Advanced extension semantics are specified in
`docs/doctor_advanced_diagnostics_report_contract.md` (`doctor-advanced-report-v1`),
owned by bead `asupersync-2b4jj.5.8`.

## Command

```bash
asupersync doctor report-contract
```

## Contract Version

- `contract_version`: `doctor-core-report-v1`
- additive fields may ship inside `v1`
- semantic changes to required sections/fields/order rules require a version bump

## Output Schema

```json
{
  "contract": {
    "contract_version": "doctor-core-report-v1",
    "required_sections": ["commands", "evidence", "findings", "provenance", "summary"],
    "summary_required_fields": ["critical_findings", "overall_outcome", "status", "total_findings"],
    "finding_required_fields": ["command_refs", "evidence_refs", "finding_id", "severity", "status", "title"],
    "evidence_required_fields": ["artifact_pointer", "evidence_id", "franken_trace_id", "outcome_class", "replay_pointer", "source"],
    "command_required_fields": ["command", "command_id", "exit_code", "outcome_class", "tool"],
    "provenance_required_fields": ["generated_at", "generated_by", "run_id", "scenario_id", "seed", "trace_id"],
    "outcome_classes": ["cancelled", "failed", "success"],
    "logging_contract_version": "doctor-logging-v1",
    "evidence_schema_version": "doctor-evidence-v1",
    "compatibility": {
      "minimum_reader_version": "doctor-core-report-v1",
      "supported_reader_versions": ["doctor-core-report-v1"],
      "migration_guidance": [{ "from_version": "doctor-core-report-v0", "to_version": "doctor-core-report-v1", "breaking": false, "required_actions": ["..."] }]
    },
    "advanced_extension_bead": "asupersync-2b4jj.5.8",
    "integration_gate_beads": ["asupersync-2b4jj.5.3", "asupersync-2b4jj.5.5"]
  },
  "fixtures": [
    {
      "fixture_id": "baseline_failure_path|happy_path|partial_data_path",
      "description": "string",
      "report": {
        "schema_version": "doctor-core-report-v1",
        "report_id": "doctor-report-*",
        "summary": { "status": "healthy|degraded|failed", "overall_outcome": "success|cancelled|failed", "total_findings": 0, "critical_findings": 0 },
        "findings": [
          {
            "finding_id": "string",
            "title": "string",
            "severity": "critical|high|medium|low",
            "status": "open|in_progress|resolved",
            "evidence_refs": ["evidence-id"],
            "command_refs": ["command-id"]
          }
        ],
        "evidence": [
          {
            "evidence_id": "string",
            "source": "string",
            "artifact_pointer": "string",
            "replay_pointer": "string",
            "outcome_class": "success|cancelled|failed",
            "franken_trace_id": "trace-*"
          }
        ],
        "commands": [
          {
            "command_id": "string",
            "command": "single-line command",
            "tool": "slug",
            "exit_code": 0,
            "outcome_class": "success|cancelled|failed"
          }
        ],
        "provenance": {
          "run_id": "run-*",
          "scenario_id": "slug",
          "trace_id": "trace-*",
          "seed": "string",
          "generated_by": "string",
          "generated_at": "RFC3339-like string"
        }
      }
    }
  ]
}
```

## Determinism and Validation Rules

1. `required_sections` and all `*_required_fields` arrays are lexically sorted and duplicate-free.
2. `findings`, `evidence`, and `commands` lists are lexically ordered by their stable IDs.
3. `summary.total_findings == findings.len()`.
4. `summary.critical_findings` equals the count of findings with severity `critical`.
5. Every finding reference must resolve:
   - `evidence_refs` -> existing `evidence_id`
   - `command_refs` -> existing `command_id`
6. `run_id` must match `run-*`, `trace_id` must match `trace-*`, and all required provenance fields are non-empty.
7. Core fixture bundle must be deterministic across repeated runs.

## Fixture Coverage (Core)

`doctor-core-report-v1` fixture pack includes:

1. `happy_path`: healthy, successful run with deterministic replay pointers.
2. `partial_data_path`: degraded/cancelled run with minimal still-valid envelope.
3. `baseline_failure_path`: failed run with critical finding and failed gate evidence.

These fixtures are baseline-only and intentionally avoid advanced extension payloads.
Advanced extension fixtures are documented in
`docs/doctor_advanced_diagnostics_report_contract.md`.

## Structured Logging + Interop Expectations

Core-report smoke validation emits deterministic structured events through
`doctor-logging-v1` (`integration` flow, `verification_summary` event kind).

Full cross-system interoperability signoff remains gated by:

- `asupersync-2b4jj.5.3`
- `asupersync-2b4jj.5.5`

## Cross-System Compatibility Matrix (`asupersync-2b4jj.5.5`)

| Surface | Version | Mandatory compatibility assertions |
|---|---|---|
| Beads/BV command center | `doctor-beads-command-center-v1` | IDs and priorities remain deterministic under `br ready --json` + `bv --robot-triage`; snapshot parse failures fail closed into explicit `parse_failure` events. |
| Agent Mail pane | `doctor-agent-mail-pane-v1` | Inbox/outbox/contact normalization keeps deterministic ordering; `ack_required` transitions are explicit and thread continuity never silently drops rows. |
| Report export | `doctor-report-export-v1` | `core_schema_version` remains `doctor-core-report-v1`; advanced fixtures preserve cross-system provenance metadata (`collaboration_channels`, mismatch diagnostics flags). |
| FrankenSuite export | `doctor-frankensuite-export-v1` | `source_schema_version` remains `doctor-core-report-v1`; evidence/decision export counts and artifact references remain deterministic across reruns. |

CI gate expectations for this matrix:

1. `TEST_SEED=5150 RCH_BIN=~/.local/bin/rch bash scripts/test_doctor_advanced_provenance_e2e.sh`
2. `TEST_SEED=4242 RCH_BIN=~/.local/bin/rch bash scripts/test_doctor_frankensuite_export_e2e.sh`
3. `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_diagnostics_docs cargo test -p asupersync --features cli --test doctor_advanced_provenance_contract`

## Consumer Guidance

1. Fail closed on unknown `contract_version` or `schema_version`.
2. Validate ordering and reference integrity before rendering/exporting reports.
3. Preserve command/evidence pointers exactly for replay and audit reproducibility.
4. Treat missing required sections as hard schema violations.
