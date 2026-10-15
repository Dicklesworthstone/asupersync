# Operator Enablement Pack: Incident Drills, Runbooks, and Support Decision Trees

**Bead**: `asupersync-2oh2u.11.12` ([T9.12])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Date**: 2026-03-04
**Purpose**: Produce a comprehensive operator enablement pack with symptom-based
runbooks, executable incident drills, escalation decision trees, support handoff
templates, and postmortem checklists grounded in structured logs and replay
artifacts.

---

## 1. Scope

This pack equips operations teams with deterministic procedures for detecting,
triaging, containing, and resolving incidents across all Tokio-replacement
surfaces. Every procedure is grounded in:

- Diagnostics UX failure modes from `asupersync-2oh2u.11.11` (T9.11)
- Migration lab KPIs from `asupersync-2oh2u.11.10` (T9.10)
- External validation evidence from `asupersync-2oh2u.11.7` (T9.7)
- Incident-response playbooks from `asupersync-2oh2u.10.10` (T8.10)

Prerequisites:
- `asupersync-2oh2u.11.11` (T9.11: diagnostics UX hardening)
- `asupersync-2oh2u.11.10` (T9.10: migration lab KPIs)
- `asupersync-2oh2u.11.7` (T9.7: external validation)
- `asupersync-2oh2u.10.10` (T8.10: incident-response playbooks)

Downstream:
- `asupersync-2oh2u.11.8` (T9.8: replacement claim RFC)

---

## 2. Symptom-Based Runbooks

### 2.1 Symptom Catalog

| Symptom ID | Observable Signal | Likely Cause | Triage Entry |
|-----------|------------------|-------------|-------------|
| SY-01 | Connection pool acquire timeout > 1s | Pool exhaustion (IC-11) | §2.2.1 |
| SY-02 | gRPC deadline exceeded across services | Timeout propagation failure (IC-09) | §2.2.2 |
| SY-03 | Monotonically increasing FD count | File handle leak (IC-03) | §2.2.3 |
| SY-04 | Message ordering violations in consumer | Rebalance storm (IC-14) | §2.2.4 |
| SY-05 | HTTP 503 spike during deployment | Routing mismatch (IC-08) | §2.2.5 |
| SY-06 | tokio-compat adapter panic | Bridge incompatibility (IC-15) | §2.2.6 |
| SY-07 | QUIC handshake failure rate > 0.5% | Connection migration issue (IC-06) | §2.2.7 |
| SY-08 | Structured log schema violation | Golden corpus drift (GC-xx) | §2.2.8 |

### 2.2 Runbook Entries

#### 2.2.1 Pool Exhaustion (SY-01)

**Correlation**: Use `correlation_id` from pool acquire timeout log entry.

**Steps**:
1. Check pool metrics: `active_connections`, `idle_connections`, `max_size`
2. Verify no connection leaks via FD count (`DR-02`)
3. Check for long-running transactions holding connections
4. If pool full: increase `max_size` or enable connection recycling
5. If leak confirmed: identify unclosed connections via replay pointer

**Replay**: `cargo test --test e2e_t6_data_path -- pool_exhaustion --nocapture`

#### 2.2.2 Timeout Propagation Failure (SY-02)

**Steps**:
1. Trace correlation ID across service boundaries
2. Verify deadline propagation in gRPC metadata
3. Check middleware chain ordering for timeout interceptor
4. Verify region boundary does not swallow deadlines

**Replay**: `cargo test --test web_grpc_e2e_service_scripts -- timeout --nocapture`

#### 2.2.3 File Handle Leak (SY-03)

**Steps**:
1. Monitor `/proc/self/fd` count over 60s window
2. Cross-reference with cancellation events in structured logs
3. Verify drop guards execute on all async paths
4. Check for missing `region.close()` calls

**Replay**: `cargo test --test tokio_fs_process_signal_e2e -- fd_leak --nocapture`

#### 2.2.4 Message Ordering Violation (SY-04)

**Steps**:
1. Check consumer group assignment stability
2. Verify partition-level sequence counters
3. Look for concurrent consumer commits without ordering lock
4. Check for message deserialization failures causing skips

**Replay**: `cargo test --test e2e_t6_data_path -- ordering --nocapture`

#### 2.2.5 HTTP 503 During Deployment (SY-05)

**Steps**:
1. Verify routing table update timing vs traffic drain
2. Check health check endpoints responding correctly
3. Verify graceful shutdown SIGTERM handler
4. Review middleware ordering for new deployment

**Replay**: `cargo test --test web_grpc_e2e_service_scripts -- routing --nocapture`

#### 2.2.6 Adapter Panic (SY-06)

**Steps**:
1. Capture panic backtrace from structured logs
2. Identify which tokio-compat adapter triggered the panic
3. Check for type mismatch between tokio and asupersync futures
4. Verify adapter version matches runtime version

**Replay**: `cargo test --test tokio_interop_support_matrix -- adapter --nocapture`

#### 2.2.7 QUIC Handshake Failure (SY-07)

**Steps**:
1. Check TLS certificate validity and chain
2. Verify QUIC transport parameter negotiation
3. Check for NAT rebinding during migration
4. Review connection migration configuration

**Replay**: `cargo test --test tokio_quic_h3_e2e_scenario_manifest -- handshake --nocapture`

#### 2.2.8 Log Schema Violation (SY-08)

**Steps**:
1. Compare violating entry against golden corpus manifest
2. Identify which field is missing or malformed
3. Check for schema version mismatch
4. Verify structured logging middleware is applied

**Replay**: `cargo test --test tokio_golden_log_corpus_enforcement -- schema --nocapture`

---

## 3. Escalation Decision Trees

### 3.1 Severity Escalation Matrix

| Current State | Condition | Action | Target |
|--------------|-----------|--------|--------|
| Detected | SEV-1 confirmed | Page on-call immediately | On-call engineer |
| Detected | SEV-2 confirmed | Alert within 5 minutes | On-call engineer |
| Triage | Root cause unknown after 15 min | Escalate to track lead | Track lead |
| Containment | Data integrity at risk | Escalate to program lead | Program lead |
| Containment | Rollback needed | Execute rollback playbook | On-call + track lead |
| Resolution | Fix requires code change | Create hotfix bead | Track lead |
| Post-incident | Impact > 100 users | Schedule post-mortem | Team lead |

### 3.2 Communication Templates

| Template ID | Trigger | Audience | Content |
|------------|---------|----------|---------|
| CT-01 | SEV-1 detected | Engineering team | Impact summary + ETA |
| CT-02 | Rollback initiated | Stakeholders | Rollback scope + timeline |
| CT-03 | Resolution confirmed | All affected | Root cause + prevention |
| CT-04 | Post-mortem scheduled | Team | Agenda + timeline |

---

## 4. Support Handoff Templates

### 4.1 Handoff Document Schema

```json
{
  "schema_version": "support-handoff-v1",
  "handoff_id": "HO-20260304-001",
  "incident_id": "INC-20260304-001",
  "from_role": "On-call engineer",
  "to_role": "Track lead",
  "timestamp": "2026-03-04T12:30:00Z",
  "status_summary": "Pool exhaustion detected and contained",
  "correlation_ids": ["inc-20260304-abc123"],
  "actions_taken": [
    "Increased pool max_size from 50 to 100",
    "Identified connection leak in transaction handler"
  ],
  "pending_actions": [
    "Fix connection drop guard in async path",
    "Add pool exhaustion alert threshold"
  ],
  "replay_pointers": [
    "cargo test --test e2e_t6_data_path -- pool_exhaustion"
  ],
  "diagnostic_artifacts": [
    "artifacts/incident_INC-20260304-001_logs.ndjson"
  ]
}
```

### 4.2 Postmortem Checklist

| Check ID | Item | Status |
|---------|------|--------|
| PM-01 | Timeline of events documented | [ ] |
| PM-02 | Root cause identified and verified | [ ] |
| PM-03 | All correlation IDs traced end-to-end | [ ] |
| PM-04 | Replay pointers validate reproduction | [ ] |
| PM-05 | Detection rule performance reviewed | [ ] |
| PM-06 | Response time vs SLA comparison | [ ] |
| PM-07 | Follow-up beads created for prevention | [ ] |
| PM-08 | Runbook updates identified | [ ] |
| PM-09 | Golden corpus updated if schema changed | [ ] |
| PM-10 | Drill schedule updated if gap found | [ ] |

---

## 5. Drill Execution Guide

### 5.1 Pre-Drill Checklist

| Step | Action | Verification |
|------|--------|-------------|
| PD-01 | Notify team of drill window | Acknowledgements received |
| PD-02 | Verify monitoring dashboards accessible | All panels loading |
| PD-03 | Confirm rollback procedures ready | Rollback scripts tested |
| PD-04 | Set up structured log capture | Correlation IDs flowing |
| PD-05 | Record baseline metrics | p50/p99 latency noted |

### 5.2 Drill Execution Scripts

```bash
# Drill 1: Pool exhaustion (T6)
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_operator_docs cargo test --test e2e_t6_data_path -- pool_exhaustion --nocapture

# Drill 2: I/O deadlock (T2)
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_operator_docs cargo test --test tokio_io_parity_audit -- deadlock --nocapture

# Drill 3: gRPC degradation (T5)
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_operator_docs cargo test --test web_grpc_e2e_service_scripts -- degradation

# Drill 4: Adapter panic (T7)
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_operator_docs cargo test --test tokio_interop_support_matrix -- panic_injection --nocapture
```

### 5.3 Post-Drill Report Schema

```json
{
  "schema_version": "drill-report-v1",
  "drill_id": "DR-20260304-001",
  "drill_type": "DRILL-01",
  "executed_at": "2026-03-04T14:00:00Z",
  "detection_time_seconds": 3,
  "response_time_seconds": 45,
  "resolution_time_seconds": 180,
  "sla_met": true,
  "gaps_identified": [],
  "correlation_id": "drill-20260304-abc123",
  "runbook_updates_needed": false
}
```

---

## 6. Quality Gates

| Gate ID | Name | Condition | Evidence |
|---------|------|-----------|----------|
| OE-01 | Symptom catalog complete | All 8 SY-xx entries with triage | This document §2.1 |
| OE-02 | Runbook entries executable | Each SY-xx has replay pointer | This document §2.2 |
| OE-03 | Escalation matrix defined | Severity-based escalation paths | This document §3.1 |
| OE-04 | Communication templates defined | CT-01..CT-04 for key events | This document §3.2 |
| OE-05 | Handoff schema versioned | support-handoff-v1 with required fields | This document §4.1 |
| OE-06 | Postmortem checklist complete | PM-01..PM-10 items | This document §4.2 |
| OE-07 | Drill execution guide complete | Pre-drill, scripts, report schema | This document §5 |
| OE-08 | Correlation IDs throughout | All procedures reference correlation chains | This document |

---

## 7. Evidence Links

| Artifact | Reference |
|----------|-----------|
| Diagnostics UX contract | `docs/tokio_diagnostics_ux_hardening_contract.md` |
| Migration lab KPI contract | `docs/tokio_migration_lab_kpi_contract.md` |
| External validation packs | `docs/tokio_external_validation_benchmark_packs.md` |
| Incident-response playbooks | `docs/tokio_incident_response_rollback_playbooks.md` |
| Golden log corpus | `docs/tokio_golden_log_corpus_contract.md` |
| Cross-track logging gates | `docs/tokio_cross_track_e2e_logging_gate_contract.md` |

---

## 8. CI Integration

Validation:
```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_operator_docs cargo test --test tokio_operator_enablement_enforcement
```

---

## Appendix A: Cross-References

| Bead | Relationship | Description |
|------|-------------|-------------|
| `asupersync-2oh2u.11.11` | Prerequisite | Diagnostics UX hardening |
| `asupersync-2oh2u.11.10` | Prerequisite | Migration lab KPIs |
| `asupersync-2oh2u.11.7` | Prerequisite | External validation |
| `asupersync-2oh2u.10.10` | Prerequisite | Incident-response playbooks |
| `asupersync-2oh2u.11.8` | Downstream | Replacement claim RFC |
