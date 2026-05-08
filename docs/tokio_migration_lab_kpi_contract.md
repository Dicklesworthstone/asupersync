# User-Journey Migration Lab KPI Contract

**Bead**: `asupersync-2oh2u.11.10` ([T9.10])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Date**: 2026-03-04
**Purpose**: Define migration lab methodology, persona archetypes, service
archetypes, friction KPIs, success thresholds, and artifact requirements
for reproducible migration validation.

---

## 1. Scope

This contract governs the execution and evaluation of user-journey migration
labs that validate real-world usability of the Tokio replacement stack.

Prerequisites:
- `asupersync-2oh2u.10.12` (T8.12: e2e logging enforcement)
- `asupersync-2oh2u.11.2` (T9.2: migration cookbooks)

---

## 2. Persona Archetypes

| Persona ID | Archetype | Description | Primary Track |
|-----------|-----------|-------------|---------------|
| P-01 | REST API Developer | Builds JSON REST services with middleware | T5 |
| P-02 | gRPC Service Developer | Builds protobuf-based RPC services | T5 |
| P-03 | Data Pipeline Engineer | Builds DB-backed processing pipelines | T6 |
| P-04 | Real-Time Networking Engineer | Builds QUIC/WebSocket applications | T4 |
| P-05 | Platform/Infra Engineer | Manages runtime, signals, fs operations | T3 |
| P-06 | Integration Engineer | Bridges existing Tokio-locked ecosystem | T7 |

---

## 3. Service Archetypes

| Archetype ID | Service Type | Tracks Exercised | Complexity |
|-------------|-------------|-----------------|------------|
| S-01 | REST CRUD API | T2, T5, T6 | Low |
| S-02 | gRPC Microservice | T2, T5 | Medium |
| S-03 | Event-Driven Pipeline | T2, T6 | Medium |
| S-04 | Real-Time WebSocket Server | T2, T4 | High |
| S-05 | CLI Tool with fs/process/signal | T2, T3 | Low |
| S-06 | Hybrid Tokio-Compat Service | T2, T7 | High |

---

## 4. Friction KPIs

### 4.1 KPI Definitions

| KPI ID | Metric | Unit | Description |
|--------|--------|------|-------------|
| FK-01 | Time to First Successful Build | minutes | Time from migration start to first clean compilation |
| FK-02 | Time to All Tests Passing | minutes | Time from start to all unit+e2e tests green |
| FK-03 | Defect Escape Rate | count per service | Bugs found post-migration that existed pre-migration |
| FK-04 | Recovery Latency | minutes | Time to rollback and restore service after migration failure |
| FK-05 | Rollback Frequency | ratio | Fraction of lab runs requiring rollback |
| FK-06 | Support Burden | questions per service | Count of docs/cookbook lookups needed during migration |
| FK-07 | Code Change Volume | lines changed | Total lines added/removed/modified |
| FK-08 | Performance Delta | percentage | p99 latency change post-migration vs baseline |

### 4.2 Success Thresholds

| KPI ID | Threshold | Hard-Fail | Soft-Fail |
|--------|-----------|-----------|-----------|
| FK-01 | <= 30 min | > 60 min | > 30 min |
| FK-02 | <= 60 min | > 120 min | > 60 min |
| FK-03 | 0 defects | >= 3 | >= 1 |
| FK-04 | <= 10 min | > 30 min | > 10 min |
| FK-05 | <= 10% | > 30% | > 10% |
| FK-06 | <= 5 lookups | > 15 | > 5 |
| FK-07 | <= 500 lines (S-01) | > 2000 | > 500 |
| FK-08 | <= 10% regression | > 50% | > 10% |

---

## 5. Lab Run Protocol

### 5.1 Lab Setup

```
1. Select persona (P-01..P-06) and service archetype (S-01..S-06)
2. Prepare baseline: build and test the service on tokio runtime
3. Record baseline metrics (compilation time, test count, p99 latency)
4. Start timer for FK-01
```

### 5.2 Migration Execution

```
1. Apply migration cookbook recipes for relevant tracks
2. Record each compilation attempt (pass/fail, duration)
3. Record each test run (pass count, fail count)
4. Note all cookbook/doc lookups (FK-06)
5. Stop timer when all tests pass (FK-02)
```

### 5.3 Verification

```
1. Run e2e service scripts (T5.12 patterns)
2. Verify structured log output (schema fields, correlation IDs)
3. Run performance benchmark (compare with baseline)
4. Record FK-03..FK-08 measurements
```

### 5.4 Artifact Emission

Every lab run MUST emit:
- `migration_lab_results.json` (structured KPI measurements)
- `migration_lab_log.md` (narrative timeline)
- Correlation IDs linking to e2e log entries
- Replay pointers for failed steps

---

## 6. Results Schema

### 6.1 Lab Results JSON

```json
{
  "schema_version": "migration-lab-results-v1",
  "lab_id": "lab-S01-P01-001",
  "persona_id": "P-01",
  "service_archetype": "S-01",
  "started_at": "2026-03-04T00:00:00Z",
  "completed_at": "2026-03-04T01:00:00Z",
  "kpis": {
    "FK-01": { "value": 15, "unit": "minutes", "threshold": 30, "status": "pass" },
    "FK-02": { "value": 45, "unit": "minutes", "threshold": 60, "status": "pass" }
  },
  "outcome": "pass",
  "artifacts": [],
  "follow_up_beads": []
}
```

### 6.2 Follow-Up Bead Schema

When a KPI exceeds its hard-fail threshold, a follow-up bead MUST be created:

| Field | Required | Description |
|-------|----------|-------------|
| kpi_id | yes | Which KPI failed |
| measured_value | yes | Actual measurement |
| threshold | yes | Expected threshold |
| severity | yes | hard-fail or soft-fail |
| remediation_hypothesis | yes | Proposed fix |
| owner | yes | Assigned agent/team |

---

## 7. Quality Gates

| Gate ID | Gate | Hard-Fail |
|---------|------|-----------|
| ML-01 | All personas represented | < 4 personas covered |
| ML-02 | All service archetypes covered | < 3 archetypes tested |
| ML-03 | KPI thresholds defined | any KPI without threshold |
| ML-04 | Artifact completeness | lab run missing required artifacts |
| ML-05 | Follow-up bead creation | hard-fail KPI without follow-up |
| ML-06 | Structured log compliance | lab artifacts without correlation IDs |

---

## 8. CI Commands

```
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_migration_lab_kpi_docs cargo test --test tokio_migration_lab_kpi_enforcement -- --nocapture
```

---

## 9. Downstream Binding

This contract is a prerequisite for:
- `asupersync-2oh2u.11.11` (T9.11: diagnostics and error-message UX)
- `asupersync-2oh2u.11.9` (T9.9: GA readiness checklist)
- `asupersync-2oh2u.10.9` (T8.9: replacement-readiness gate aggregator)
