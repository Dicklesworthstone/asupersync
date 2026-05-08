# Incident-Response and Rollback Playbooks for Replacement Features

**Bead**: `asupersync-2oh2u.10.10` ([T8.10])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Date**: 2026-03-04
**Purpose**: Define deterministic incident-response and rollback playbooks for
newly replaced ecosystem surfaces, covering detection, triage, containment,
rollback flows, and post-incident review.

---

## 1. Scope

This contract governs incident-response and rollback playbooks for all
Tokio-replacement tracks (T2–T7). Playbooks are grounded in:

- Diagnostics UX failure modes from `asupersync-2oh2u.11.11` (T9.11)
- Golden log corpus entries from `asupersync-2oh2u.10.13` (T8.13)
- Cross-track e2e log-quality gates from `asupersync-2oh2u.10.12` (T8.12)

Prerequisites:
- `asupersync-2oh2u.11.11` (T9.11: diagnostics UX hardening)

Downstream:
- `asupersync-2oh2u.10.9` (T8.9: replacement-readiness gate aggregator)
- `asupersync-2oh2u.11.12` (T9.12: operator enablement pack)

---

## 2. Incident Classification Matrix

### 2.1 Severity Levels

| Severity | Code | Detection SLA | Response SLA | Resolution SLA | Escalation Trigger |
|----------|------|---------------|--------------|----------------|--------------------|
| Critical | SEV-1 | < 1 min | < 5 min | < 30 min | Automated page |
| High | SEV-2 | < 5 min | < 15 min | < 2 hours | On-call alert |
| Medium | SEV-3 | < 15 min | < 30 min | < 8 hours | Ticket created |
| Low | SEV-4 | < 60 min | < 4 hours | < 48 hours | Backlog prioritized |

### 2.2 Track-Specific Incident Classes

| Class ID | Track | Category | Description | Default Severity |
|----------|-------|----------|-------------|-----------------|
| IC-01 | T2 | I/O | Async read/write deadlock or data corruption | SEV-1 |
| IC-02 | T2 | I/O | Codec frame boundary violation | SEV-2 |
| IC-03 | T3 | FS | File handle leak under cancellation | SEV-2 |
| IC-04 | T3 | Process | Zombie process accumulation | SEV-2 |
| IC-05 | T3 | Signal | Signal handler registration failure | SEV-1 |
| IC-06 | T4 | QUIC | Connection migration failure | SEV-2 |
| IC-07 | T4 | HTTP/3 | QPACK header decompression error | SEV-2 |
| IC-08 | T5 | Web | HTTP routing mismatch under load | SEV-2 |
| IC-09 | T5 | gRPC | Service reflection unavailable | SEV-3 |
| IC-10 | T5 | Middleware | Compression negotiation failure | SEV-3 |
| IC-11 | T6 | Database | Connection pool exhaustion | SEV-1 |
| IC-12 | T6 | Database | Transaction isolation violation | SEV-1 |
| IC-13 | T6 | Messaging | Message ordering guarantee violation | SEV-1 |
| IC-14 | T6 | Messaging | Consumer group rebalance storm | SEV-2 |
| IC-15 | T7 | Interop | Adapter bridge panic under tokio-compat | SEV-1 |
| IC-16 | T7 | Interop | Type conversion silent truncation | SEV-2 |

---

## 3. Detection Playbooks

### 3.1 Automated Detection Rules

| Rule ID | Class | Signal | Detection Method | Threshold |
|---------|-------|--------|-----------------|-----------|
| DR-01 | IC-01 | I/O stall | No progress on read/write for > 5s | 5s timeout |
| DR-02 | IC-03 | FD count | `/proc/self/fd` count exceeding baseline × 2 | 2x baseline |
| DR-03 | IC-04 | Zombie PIDs | waitpid WNOHANG returning 0 for > 60s | 60s threshold |
| DR-04 | IC-11 | Pool wait time | p99 acquire latency > 500ms | 500ms p99 |
| DR-05 | IC-13 | Sequence gaps | Message sequence number discontinuity | Any gap |
| DR-06 | IC-15 | Panic hook | Adapter bridge panic counter > 0 | > 0 |

### 3.2 Structured Log Correlation

All incident detection emits structured logs conforming to the cross-track
e2e schema:

```json
{
  "schema_version": "incident-detection-v1",
  "incident_class": "IC-11",
  "severity": "SEV-1",
  "correlation_id": "inc-20260304-abc123",
  "detection_rule": "DR-04",
  "detected_at": "2026-03-04T12:00:00Z",
  "context": {
    "pool_name": "primary_pg",
    "wait_p99_ms": 620,
    "active_connections": 100,
    "max_connections": 100
  },
  "replay_pointer": "cargo test --test e2e_t6_data_path -- pool_exhaustion --nocapture"
}
```

---

## 4. Triage Decision Trees

### 4.1 Universal Triage Flow

```text
INCIDENT DETECTED
  │
  ├─ SEV-1/SEV-2? ──→ IMMEDIATE CONTAINMENT (§5)
  │                     │
  │                     ├─ Data integrity at risk? ──→ EMERGENCY ROLLBACK (§6.1)
  │                     │
  │                     └─ Performance only? ──→ TARGETED MITIGATION (§5.2)
  │
  └─ SEV-3/SEV-4? ──→ SCHEDULED INVESTIGATION
                        │
                        ├─ Regression detected? ──→ ROLLBACK (§6.2)
                        │
                        └─ New failure mode? ──→ DOCUMENT + PATCH (§7)
```

### 4.2 Track-Specific Triage Rules

#### T2 (I/O) Triage
- IC-01: Check `io::AsyncRead`/`AsyncWrite` cancel-safety. Verify codec
  buffer state via replay pointer. If deadlock confirmed, rollback to
  tokio-compat adapter.
- IC-02: Inspect frame boundary logs. Cross-reference with golden corpus
  entry `t2_io_e2e_success`. Check for partial frame delivery.

#### T5 (Web/gRPC) Triage
- IC-08: Compare routing table against expected configuration. Check for
  middleware ordering regression. Use `rch exec 'cargo test --test web_grpc_e2e_service_scripts'`.
- IC-09: Verify gRPC reflection service registration. Check server builder
  configuration.

#### T6 (Database/Messaging) Triage
- IC-11: Check pool metrics (active, idle, max). Verify connection leak via
  `DR-02` FD count. If pool exhausted, enable connection recycling.
- IC-13: Verify consumer group assignment. Check partition offsets. Use
  `rch exec 'cargo test --test e2e_t6_data_path'` to reproduce.

---

## 5. Containment Procedures

### 5.1 Emergency Containment

For SEV-1 incidents:

1. **Isolate**: Remove affected service from load balancer rotation
2. **Preserve**: Capture diagnostic snapshot (structured logs + heap dump)
3. **Correlate**: Link incident to correlation ID chain
4. **Decide**: Rollback (§6) or hotfix based on triage tree

### 5.2 Targeted Mitigation

For performance-only incidents:

1. **Rate limit**: Apply backpressure to affected path
2. **Scale**: Add capacity if resource-bound
3. **Monitor**: Verify mitigation via detection rule threshold
4. **Root cause**: Schedule investigation within response SLA

---

## 6. Rollback Playbooks

### 6.1 Emergency Rollback (Revert to Last-Known-Good)

```bash
# Step 1: Identify last-known-good deployment
git log --oneline --grep="asupersync-2oh2u" | head -10

# Step 2: Revert to last-known-good
# (operator selects commit based on deployment history)
git revert HEAD --no-edit

# Step 3: Verify rollback
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_operator_docs cargo test --test tokio_cross_track_e2e_logging_enforcement
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_operator_docs cargo test --test tokio_golden_log_corpus_enforcement

# Step 4: Confirm service health
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_operator_docs cargo test --lib health
```

### 6.2 Gradual Rollback (Feature-Flag Controlled)

| Step | Action | Verification | Rollback Criterion |
|------|--------|-------------|-------------------|
| RB-01 | Disable replacement feature flag | Health check passes | Flag confirmed off |
| RB-02 | Route traffic to tokio-compat adapter | Latency within budget | p99 < 2× baseline |
| RB-03 | Verify data integrity | Golden corpus regression | Zero violations |
| RB-04 | Generate incident report | Structured log export | Correlation chain complete |

### 6.3 Track-Specific Rollback Conditions

| Track | Rollback Trigger | Rollback Target | Verification Command |
|-------|-----------------|-----------------|---------------------|
| T2 | Data corruption detected | tokio::io adapter | `cargo test --test tokio_io_parity_audit` |
| T3 | Resource leak > 2× baseline | tokio::fs/process | `cargo test --test tokio_fs_process_signal_e2e` |
| T4 | QUIC handshake failure rate > 1% | Previous QUIC impl | `cargo test --test tokio_quic_h3_e2e_scenario_manifest` |
| T5 | HTTP 5xx rate > 0.1% | Previous web stack | `cargo test --test web_grpc_e2e_service_scripts` |
| T6 | Connection pool timeout > 5s | Previous pool impl | `cargo test --test e2e_t6_data_path` |
| T7 | Adapter panic count > 0 | Direct tokio dependency | `cargo test --test tokio_interop_support_matrix` |

---

## 7. Post-Incident Review

### 7.1 Incident Report Schema

```json
{
  "schema_version": "incident-report-v1",
  "incident_id": "INC-20260304-001",
  "incident_class": "IC-11",
  "severity": "SEV-1",
  "detected_at": "2026-03-04T12:00:00Z",
  "resolved_at": "2026-03-04T12:25:00Z",
  "correlation_ids": ["inc-20260304-abc123"],
  "root_cause": "Connection pool max_size not adjusted for new driver",
  "remediation": "Increased pool max_size from 50 to 100",
  "rollback_used": false,
  "follow_up_bead": "asupersync-2oh2u.X.Y",
  "replay_pointer": "cargo test --test e2e_t6_data_path -- pool_exhaustion",
  "diagnostic_artifacts": [
    "artifacts/incident_INC-20260304-001_logs.ndjson",
    "artifacts/incident_INC-20260304-001_metrics.json"
  ]
}
```

### 7.2 Post-Incident Checklist

| Step | Action | Owner |
|------|--------|-------|
| PIR-01 | Capture full structured log chain with correlation IDs | On-call |
| PIR-02 | Link replay pointers for reproduction | On-call |
| PIR-03 | Run golden corpus regression to verify no schema drift | CI |
| PIR-04 | Update detection rules if new failure mode | Track owner |
| PIR-05 | File follow-up bead with remediation hypothesis | Track owner |
| PIR-06 | Schedule post-mortem within 48 hours | Team lead |

---

## 8. Drill Framework

### 8.1 Incident Drill Types

| Drill ID | Description | Frequency | Track |
|----------|-------------|-----------|-------|
| DRILL-01 | Connection pool exhaustion simulation | Monthly | T6 |
| DRILL-02 | I/O deadlock injection | Monthly | T2 |
| DRILL-03 | Signal handler race condition | Quarterly | T3 |
| DRILL-04 | gRPC service degradation | Monthly | T5 |
| DRILL-05 | Adapter bridge panic injection | Monthly | T7 |
| DRILL-06 | QUIC connection migration failure | Quarterly | T4 |

### 8.2 Drill Execution Protocol

1. **Announce**: Notify team of scheduled drill window
2. **Inject**: Trigger failure condition via test harness
3. **Detect**: Verify automated detection fires within SLA
4. **Respond**: Execute triage and containment per playbook
5. **Verify**: Confirm resolution and generate drill report
6. **Review**: Assess detection/response gaps and update playbooks

### 8.3 Drill Verification Commands

```bash
# T6 pool exhaustion drill
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_operator_docs cargo test --test e2e_t6_data_path -- pool_exhaustion --nocapture

# T2 I/O deadlock drill
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_operator_docs cargo test --test tokio_io_parity_audit -- deadlock_injection --nocapture

# T5 gRPC degradation drill
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_operator_docs cargo test --test web_grpc_e2e_service_scripts -- degradation
```

---

## 9. Quality Gates

| Gate ID | Name | Condition | Evidence |
|---------|------|-----------|----------|
| IR-01 | Incident classes complete | All 16 IC-xx classes defined with severity | This document §2.2 |
| IR-02 | Detection rules mapped | DR-xx rules cover SEV-1/SEV-2 classes | This document §3.1 |
| IR-03 | Triage trees executable | Decision trees cover all tracks | This document §4 |
| IR-04 | Rollback procedures tested | RB-xx steps have verification commands | This document §6 |
| IR-05 | Incident report schema defined | JSON schema with required fields | This document §7.1 |
| IR-06 | Drill framework operational | DRILL-xx entries with frequency and commands | This document §8 |
| IR-07 | Structured logging aligned | Detection logs conform to e2e schema | T8.12 cross-reference |
| IR-08 | Correlation chain complete | All playbooks reference correlation IDs | This document throughout |

---

## 10. Evidence Links

| Artifact | Reference |
|----------|-----------|
| Diagnostics UX contract | `docs/tokio_diagnostics_ux_hardening_contract.md` |
| Golden log corpus | `tests/fixtures/logging_golden_corpus/manifest.json` |
| Cross-track logging gates | `docs/tokio_cross_track_e2e_logging_gate_contract.md` |
| Migration runbook (web/gRPC) | `docs/tokio_web_grpc_migration_runbook.md` |
| Migration cookbooks | `docs/tokio_migration_cookbooks.md` |
| I/O parity audit | `docs/tokio_io_parity_audit.md` |
| FS/process/signal e2e | `docs/tokio_fs_process_signal_e2e.md` |
| T6 data-path e2e | `docs/tokio_t6_data_path_e2e_contract.md` |

---

## 11. CI Integration

Validation:
```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_operator_docs cargo test --test tokio_incident_response_rollback_enforcement
```

---

## Appendix A: Cross-References

| Bead | Relationship | Description |
|------|-------------|-------------|
| `asupersync-2oh2u.11.11` | Prerequisite | Diagnostics UX hardening (failure modes, MTTR) |
| `asupersync-2oh2u.10.13` | Prerequisite | Golden log corpus (schema baselines) |
| `asupersync-2oh2u.10.12` | Prerequisite | Cross-track e2e logging gates |
| `asupersync-2oh2u.10.9` | Downstream | Replacement-readiness gate aggregator |
| `asupersync-2oh2u.11.12` | Downstream | Operator enablement pack |
| `asupersync-2oh2u.11.9` | Downstream | GA readiness checklist |
