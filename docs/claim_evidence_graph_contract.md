# Claim/Evidence Graph Contract

Bead: `asupersync-1508v.10.4`

## Purpose

This contract defines the graph schema that connects runtime claims to their supporting evidence, governing policies, replay traces, workloads, tests, and rollback triggers. It is the default closure language for the entire ascension program.

## Contract Artifacts

1. Canonical artifact: `artifacts/claim_evidence_graph_v1.json`
2. Smoke runner: `scripts/run_claim_evidence_graph_smoke.sh`
3. Invariant suite: `tests/claim_evidence_graph_contract.rs`

## Graph Schema

### Node Types

| Type | Description | Key Fields |
|------|-------------|------------|
| CLAIM | Verifiable runtime assertion | claim_id, category, status |
| EVIDENCE | Supporting/refuting artifact | evidence_id, kind, source_artifact |
| POLICY | Evaluation/promotion rule | policy_id, enforcement |
| TRACE | Replayable execution trace | trace_id, workload_id |
| WORKLOAD | Reproducible workload | workload_id, profile |
| TEST | Deterministic test | test_id, test_file, kind |
| ROLLBACK | Claim-violation trigger | rollback_id, claim_id, command |

### Edge Types

| Edge | From | To | Meaning |
|------|------|----|---------|
| SUPPORTS | EVIDENCE | CLAIM | Evidence supports claim |
| REFUTES | EVIDENCE | CLAIM | Evidence refutes claim |
| GOVERNS | POLICY | CLAIM | Policy governs claim evaluation |
| PRODUCES | TEST | EVIDENCE | Test produces evidence |
| REPLAYS | TRACE | WORKLOAD | Trace replays workload |
| OBSERVES | TRACE | EVIDENCE | Trace produces observations |
| TRIGGERS | CLAIM | ROLLBACK | Claim violation triggers rollback |

### Claim Lifecycle

Claims progress through: `asserted` -> `evidenced` -> `verified` -> (optionally `revoked`).

- `asserted`: Claim stated but no evidence linked
- `evidenced`: At least one SUPPORTS edge exists
- `verified`: Mandatory policies satisfied and evidence validated
- `revoked`: Claim invalidated by REFUTES evidence or policy change

## Bundle Contract

An artifact bundle packages claims, evidence, policies, and edges into a single validatable unit.

Required sections: `claims`, `evidence`, `policies`, `edges`
Optional sections: `traces`, `workloads`, `tests`, `rollbacks`

### Validation Rules

| Rule | Severity | Description |
|------|----------|-------------|
| V-CLAIM-EVIDENCE | error | Evidenced/verified claims need SUPPORTS edges |
| V-EDGE-REFS | error | All edge endpoints reference existing nodes |
| V-POLICY-COVERAGE | error | Safety claims governed by mandatory policy |
| V-ROLLBACK-COMMAND | error | Rollbacks have non-empty commands |
| V-TEST-EVIDENCE | warning | test_result evidence has PRODUCES edge |
| V-TRACE-WORKLOAD | warning | Traces REPLAYS exactly one workload |

## Structured Logging Contract

Validation logs MUST include:

- `bundle_id`, `bundle_version`: Bundle identity
- `validation_rule_id`, `validation_severity`, `validation_pass`, `validation_message`: Per-rule results
- `claim_id`, `claim_status`: Claim context
- `evidence_count`, `policy_count`, `edge_count`: Graph statistics
- `node_type`: Node type being validated
- `graph_connected`: Whether the graph is connected

## Comparator-Smoke Runner

Canonical runner: `scripts/run_claim_evidence_graph_smoke.sh`

Examples:

```bash
bash ./scripts/run_claim_evidence_graph_smoke.sh --list
bash ./scripts/run_claim_evidence_graph_smoke.sh --scenario CEG-SMOKE-SCHEMA --dry-run
bash ./scripts/run_claim_evidence_graph_smoke.sh --execute
```

## Validation

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_claim_evidence_graph cargo test -p asupersync --test claim_evidence_graph_contract --features test-internals -- --nocapture
```

## Cross-References

- `artifacts/claim_evidence_graph_v1.json`
- `scripts/run_claim_evidence_graph_smoke.sh`
- `tests/claim_evidence_graph_contract.rs`
- `src/runtime/kernel.rs` -- ControllerRegistry, evidence ledger
- `artifacts/runtime_control_seam_inventory_v1.json` -- Seam IDs
- `artifacts/runtime_workload_corpus_v1.json` -- Replay workloads
- `artifacts/decision_plane_validation_v1.json` -- Decision plane
