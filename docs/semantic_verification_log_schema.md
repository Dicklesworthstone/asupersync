# Semantic Verification Log Schema (SEM-12.7)

**Bead**: `asupersync-3cddg.12.7`
**Parent**: SEM-12 Comprehensive Verification Fabric
**Author**: SapphireHill
**Date**: 2026-03-02
**Schema Version**: `sem-verification-log-v1`
**Inputs**:
- `docs/semantic_contract_schema.md` (SEM-04.1, 47 rule IDs)
- `docs/semantic_verification_matrix.md` (SEM-12.1, evidence classes)
- `src/trace/event.rs` (TraceEvent schema v1)
- `src/lab/runtime.rs` (LabRunReport, SporkHarnessReport)

---

## 1. Purpose

This document defines the deterministic structured logging schema for semantic
verification. Every verification tool (unit test, property test, oracle check,
e2e witness, CI gate) must emit log entries conforming to this schema so that:

1. Coverage claims in the verification matrix are machine-verifiable.
2. Failures carry sufficient context for one-command reproduction.
3. Correlation IDs connect evidence across tools and runs.
4. Artifact retention is automated and auditable.

---

## 2. Log Entry Schema

### 2.1 Envelope Fields (required on every entry)

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | Must be `"sem-verification-log-v1"` |
| `entry_id` | string | Unique entry ID: `"svl-{run_id}-{seq}"` |
| `run_id` | string | Unique run ID (UUID or `"{seed}-{timestamp}"`) |
| `seq` | u64 | Monotonically increasing within a run |
| `timestamp_ns` | u64 | Virtual nanoseconds (lab) or wall-clock ns (CI) |
| `phase` | string | One of: `setup`, `execute`, `check`, `teardown` |

### 2.2 Rule Identification Fields (required)

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | string | Canonical rule ID, e.g. `"rule.cancel.request"` |
| `rule_number` | u32 | Rule number 1-47 from gap matrix |
| `domain` | string | One of: `cancel`, `obligation`, `region`, `outcome`, `ownership`, `combinator`, `capability`, `determinism` |

### 2.3 Evidence Fields (required)

| Field | Type | Description |
|-------|------|-------------|
| `evidence_class` | string | One of: `UT`, `PT`, `OC`, `E2E`, `LOG`, `DOC`, `CI` |
| `scenario_id` | string | Stable scenario identifier (e.g. `"WF-TIE.1"`, `"ADR-001"`) |
| `verdict` | string | One of: `pass`, `fail`, `skip`, `error` |
| `verdict_reason` | string? | Required when verdict is `fail` or `error` |

### 2.4 Reproduction Fields (required when verdict != skip)

| Field | Type | Description |
|-------|------|-------------|
| `seed` | u64 | Deterministic seed for the test |
| `trace_fingerprint` | u64? | Canonical Foata trace fingerprint (when available) |
| `repro_command` | string | One-command reproduction string |

### 2.5 Correlation Fields (optional)

| Field | Type | Description |
|-------|------|-------------|
| `parent_run_id` | string? | Parent run (e.g. CI job that triggered this) |
| `thread_id` | string? | Agent mail thread ID for coordination |
| `artifact_path` | string? | Path to detailed artifact (crash pack, trace) |
| `artifact_hash` | string? | SHA-256 of artifact for integrity |
| `oracle_name` | string? | Oracle that produced this verdict |
| `witness_id` | string? | Witness ID from witness pack (W1.1, W5.2, etc.) |

### 2.6 Context Fields (optional)

| Field | Type | Description |
|-------|------|-------------|
| `config_hash` | u64? | LabConfigSummary config hash |
| `commit_hash` | string? | Git commit hash |
| `steps` | u64? | Scheduler steps executed |
| `duration_ns` | u64? | Wall-clock duration |
| `violation_category` | string? | From InvariantViolation (obligation_leak, etc.) |

---

## 3. Rule-ID Taxonomy

The 47 canonical rule IDs use dot-separated hierarchical naming:

```
{prefix}.{domain}.{name}

Prefixes:
  rule   — behavioral transition rule
  inv    — invariant (must always hold)
  def    — definition (structural type constraint)
  prog   — progress property (liveness)
  comb   — combinator behavior
  law    — algebraic law
```

### 3.1 Complete Rule-ID Table

| # | Rule ID | Domain |
|---|---------|--------|
| 1 | `rule.cancel.request` | cancel |
| 2 | `rule.cancel.acknowledge` | cancel |
| 3 | `rule.cancel.drain` | cancel |
| 4 | `rule.cancel.finalize` | cancel |
| 5 | `inv.cancel.idempotence` | cancel |
| 6 | `inv.cancel.propagates_down` | cancel |
| 7 | `def.cancel.reason_kinds` | cancel |
| 8 | `def.cancel.severity_ordering` | cancel |
| 9 | `prog.cancel.drains` | cancel |
| 10 | `rule.cancel.checkpoint_masked` | cancel |
| 11 | `inv.cancel.mask_bounded` | cancel |
| 12 | `inv.cancel.mask_monotone` | cancel |
| 13 | `rule.obligation.reserve` | obligation |
| 14 | `rule.obligation.commit` | obligation |
| 15 | `rule.obligation.abort` | obligation |
| 16 | `rule.obligation.leak` | obligation |
| 17 | `inv.obligation.no_leak` | obligation |
| 18 | `inv.obligation.linear` | obligation |
| 19 | `inv.obligation.bounded` | obligation |
| 20 | `inv.obligation.ledger_empty_on_close` | obligation |
| 21 | `prog.obligation.resolves` | obligation |
| 22 | `rule.region.close_begin` | region |
| 23 | `rule.region.close_cancel_children` | region |
| 24 | `rule.region.close_children_done` | region |
| 25 | `rule.region.close_run_finalizer` | region |
| 26 | `rule.region.close_complete` | region |
| 27 | `inv.region.quiescence` | region |
| 28 | `prog.region.close_terminates` | region |
| 29 | `def.outcome.four_valued` | outcome |
| 30 | `def.outcome.severity_lattice` | outcome |
| 31 | `def.outcome.join_semantics` | outcome |
| 32 | `def.cancel.reason_ordering` | outcome |
| 33 | `inv.ownership.single_owner` | ownership |
| 34 | `inv.ownership.task_owned` | ownership |
| 35 | `def.ownership.region_tree` | ownership |
| 36 | `rule.ownership.spawn` | ownership |
| 37 | `comb.join` | combinator |
| 38 | `comb.race` | combinator |
| 39 | `comb.timeout` | combinator |
| 40 | `inv.combinator.loser_drained` | combinator |
| 41 | `law.race.never_abandon` | combinator |
| 42 | `law.join.assoc` | combinator |
| 43 | `law.race.comm` | combinator |
| 44 | `inv.capability.no_ambient` | capability |
| 45 | `def.capability.cx_scope` | capability |
| 46 | `inv.determinism.replayable` | determinism |
| 47 | `def.determinism.seed_equivalence` | determinism |

---

## 4. Oracle-to-Rule Mapping

Oracle temporal invariant names map to rule IDs as follows:

| Oracle Name | Rule IDs |
|-------------|----------|
| `task_leak` | #33, #34 |
| `obligation_leak` | #16, #17 |
| `quiescence` | #27 |
| `cancellation_protocol` | #1-4, #6 |
| `loser_drain` | #40 |
| `region_tree` | #35 |
| `deadline_monotone` | #11, #19 |
| `determinism` | #46, #47 |
| `ambient_authority` | #44, #45 |
| `finalizer` | #25 |

---

## 5. Correlation ID Design

### 5.1 Run ID

Format: `svr-{seed:016x}-{wall_ns:016x}`

- Deterministic prefix (`seed`) allows grouping runs by seed family.
- Wall-clock suffix prevents collisions across calendar runs.

### 5.2 Entry ID

Format: `svl-{run_id}-{seq:06}`

- Monotonic within a run. Parseable for sorting and range queries.

### 5.3 Cross-Tool Correlation

When a unit test triggers an oracle check which emits a LOG entry:

```
UT entry:  { run_id: "svr-...", evidence_class: "UT", rule_id: "inv.cancel.idempotence" }
OC entry:  { run_id: "svr-...", evidence_class: "OC", rule_id: "inv.cancel.idempotence",
             parent_run_id: "svr-..." }
```

The `parent_run_id` field links the oracle check to the test that invoked it.

---

## 6. Artifact Naming Convention

### 6.1 Directory Structure

```
artifacts/
  sem-verification/
    {run_id}/
      summary.json          — VerificationRunSummary
      entries.ndjson         — newline-delimited log entries
      crash-{seed}.pack     — crash pack (on failure)
      trace-{seed}.replay   — replay trace (on failure)
```

### 6.2 Naming Rules

- All filenames are lowercase with hyphens.
- Seeds in filenames are zero-padded hex: `{seed:016x}`.
- Crash packs use the existing `crashpack-{seed}-{fingerprint}` format.
- Summary files are always `summary.json`.

---

## 7. Retention Policy

### 7.1 Retention Windows

| Artifact Type | Local | CI | Archive |
|--------------|:-----:|:--:|:-------:|
| `summary.json` | 30 days | 90 days | indefinite |
| `entries.ndjson` | 7 days | 30 days | on failure only |
| Crash packs | 30 days | 90 days | indefinite |
| Replay traces | 7 days | 30 days | on failure only |

### 7.2 Retention Rules

1. **Failure artifacts are never auto-deleted.** They move to archive after
   the CI window expires.
2. **Passing run entries** are deleted after the local/CI window unless
   explicitly pinned.
3. **Summary files** are retained indefinitely for coverage tracking.
4. **Retention is enforced by the verification runner**, not by external cron.

---

## 8. Schema Validation Contract

A valid log entry MUST:

1. Have `schema_version == "sem-verification-log-v1"`.
2. Have a non-empty `rule_id` matching a known canonical ID from section 3.1.
3. Have `evidence_class` in `{UT, PT, OC, E2E, LOG, DOC, CI}`.
4. Have `verdict` in `{pass, fail, skip, error}`.
5. Have `verdict_reason` when `verdict` is `fail` or `error`.
6. Have `seed` and `repro_command` when `verdict` is not `skip`.
7. Have `entry_id` matching `svl-{run_id}-{seq}` format.
8. Have monotonically increasing `seq` within the same `run_id`.

Validation failures are themselves logged with `evidence_class: "LOG"` and
`verdict: "error"`, `violation_category: "schema_validation_failure"`.

---

## 9. Verification Run Summary Schema

The per-run summary aggregates entries into a coverage report:

```json
{
  "schema_version": "sem-verification-summary-v1",
  "run_id": "svr-...",
  "seed": 42,
  "timestamp": "2026-03-02T09:00:00Z",
  "commit_hash": "abc123",
  "total_entries": 47,
  "verdicts": {
    "pass": 45,
    "fail": 0,
    "skip": 2,
    "error": 0
  },
  "coverage": {
    "rules_tested": 45,
    "rules_total": 47,
    "rules_skipped": ["inv.capability.no_ambient", "def.capability.cx_scope"],
    "domains": {
      "cancel": { "tested": 12, "total": 12 },
      "obligation": { "tested": 9, "total": 9 },
      "region": { "tested": 7, "total": 7 },
      "outcome": { "tested": 4, "total": 4 },
      "ownership": { "tested": 4, "total": 4 },
      "combinator": { "tested": 7, "total": 7 },
      "capability": { "tested": 0, "total": 2 },
      "determinism": { "tested": 2, "total": 2 }
    }
  },
  "evidence_classes": {
    "UT": 25,
    "PT": 6,
    "OC": 8,
    "E2E": 4,
    "LOG": 2,
    "CI": 2
  },
  "failures": [],
  "artifacts": ["summary.json", "entries.ndjson"]
}
```

---

## 10. Integration Points

### 10.1 Existing Infrastructure Mapping

| Existing Field | Maps To |
|---------------|---------|
| `LabRunReport.refinement_firewall_rule_id` | `rule_id` |
| `ReproManifest.invariant_ids` | `rule_id[]` |
| `OracleReport` oracle names | `oracle_name` → `rule_id` via section 4 |
| `TraceEvent.kind.stable_name()` | `evidence_class: "LOG"` entries |
| `SporkHarnessReport.verdict` | `verdict` |
| `CrashPackConfig.seed` | `seed` |
| `LabTraceCertificateSummary.event_hash` | `trace_fingerprint` |

### 10.2 Downstream Consumers

1. **SEM-12.6**: Cross-artifact witness-replay scripts consume `entries.ndjson`.
2. **SEM-12.9**: CI runner validates `summary.json` against coverage thresholds.
3. **SEM-12.14**: Coverage gate enforces global UT/PT/E2E thresholds, per-domain thresholds, and logging completeness checks.
4. **SEM-09.3**: Gate evaluation reads summary verdicts.

---

## 11. SEM-12.14 Coverage and Logging Gate Policy

`scripts/run_semantic_verification.sh` enforces this policy in full/forensics
profiles (and CI mode without suite filters). The gate is reported as
`quality_gates.semantic_coverage_logging_gate`.

### 11.1 Global Thresholds

| Evidence class | Minimum coverage |
|----------------|:----------------:|
| UT | 100% |
| PT | 40% |
| E2E | 60% |

These values are read from `docs/semantic_verification_matrix.md` section 5.1.

### 11.2 Per-Domain Thresholds (UT/PT/E2E)

| Domain | UT min | PT min | E2E min |
|--------|:------:|:------:|:-------:|
| cancel | 100% | 25% | 25% |
| obligation | 100% | 20% | 20% |
| region | 100% | 15% | 15% |
| outcome | 100% | 25% | 0% |
| ownership | 100% | 0% | 0% |
| combinator | 100% | 40% | 40% |
| capability | 0% | 0% | 0% |
| determinism | 100% | 0% | 100% |

Per-domain percentages are computed from the rule rows in section 4 of
`docs/semantic_verification_matrix.md`.

### 11.3 Logging Completeness Checks

Before verification can pass, the gate requires:

1. `semantic_log_schema_validation` and `semantic_witness_replay_e2e` suites pass.
2. Required schema field coverage is documented:
   `schema_version`, `entry_id`, `run_id`, `seq`, `rule_id`, `evidence_class`,
   `verdict`, `seed`, `repro_command`, `parent_run_id`, `thread_id`,
   `artifact_path`, `artifact_hash`.
3. Artifact linkage contract is present (`summary.json`, `entries.ndjson`).
4. Correlation-link requirement is present (cross-tool correlation language and
   ID linkage semantics).

### 11.4 Policy Evolution and Audit Trail

Threshold or required-field changes must include:

1. A bead reference in commit metadata (for example `asupersync-3cddg.12.14`).
2. A policy rationale in this section describing risk/benefit.
3. Updated runner tests (`tests/semantic_verification_runner.rs`) covering the
   changed contract.
4. A deterministic gate run artifact in `target/semantic-verification/`.

Initial policy record:
- `policy_id`: `sem.coverage.logging.gate.v1`
- `introduced_by`: `asupersync-3cddg.12.14`
- `introduced_on`: `2026-03-02`

---

## 12. Schema Evolution Policy

1. **Schema version is immutable.** New fields require a new version string.
2. **Additive changes** (new optional fields) are permitted within a version
   if they do not change validation semantics.
3. **Breaking changes** (new required fields, changed types, removed fields)
   require incrementing the version: `sem-verification-log-v2`.
4. **Old versions remain valid.** Consumers must handle `v1` entries even
   after `v2` is introduced.
5. **Version changes require review metadata** in the commit message
   describing the semantic impact.
