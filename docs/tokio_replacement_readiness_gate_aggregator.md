# Replacement-Readiness Gate Aggregator

**Bead**: `asupersync-2oh2u.10.9` ([T8.9])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Date**: 2026-03-04
**Purpose**: Compute deterministic go/no-go replacement-readiness status from
explicit cross-track evidence: feature parity, unit/e2e quality, structured-log
quality, performance/security budgets, migration-lab outcomes, and operations
readiness.

---

## 1. Scope

The readiness gate aggregator is the final quality checkpoint before declaring
any Tokio-replacement track surface ready for production use. It aggregates
evidence from all prerequisite tracks and produces a deterministic verdict.

Prerequisites:
- `asupersync-2oh2u.11.10` (T9.10: migration lab KPIs)
- `asupersync-2oh2u.10.13` (T8.13: golden log corpus)
- `asupersync-2oh2u.10.12` (T8.12: cross-track e2e logging gates)
- `asupersync-2oh2u.10.11` (T8.11: unit-test coverage thresholds)
- `asupersync-2oh2u.2.8` (T2.8: I/O conformance gates)
- `asupersync-2oh2u.10.8` (T8.8: security/authority audits)
- `asupersync-2oh2u.10.7` (T8.7: performance regression budgets)
- `asupersync-2oh2u.10.10` (T8.10: incident-response playbooks)

Downstream:
- `asupersync-2oh2u.11.5` (T9.5: release channels)
- `asupersync-2oh2u.11.8` (T9.8: replacement claim RFC)
- `asupersync-2oh2u.11.9` (T9.9: GA readiness checklist)

---

## 2. Gate Taxonomy

### 2.1 Evidence Dimensions

| Dimension ID | Name | Source | Weight |
|-------------|------|--------|--------|
| RG-DIM-01 | Feature Parity | T1 parity contracts (C01-C28) | 25% |
| RG-DIM-02 | Unit Test Quality | T8.11 quality thresholds | 15% |
| RG-DIM-03 | E2E Logging Quality | T8.12 log-quality gates | 10% |
| RG-DIM-04 | Performance Budget | T8.7 regression budgets | 15% |
| RG-DIM-05 | Security Audit | T8.8 authority-flow audit | 10% |
| RG-DIM-06 | Migration Lab Outcomes | T9.10 friction KPIs | 10% |
| RG-DIM-07 | Golden Corpus Conformance | T8.13 schema evolution | 5% |
| RG-DIM-08 | Operations Readiness | T8.10 incident playbooks | 10% |

### 2.2 Gate Evaluation Rules

Each dimension produces one of:

| Status | Meaning | Gate Impact |
|--------|---------|-------------|
| PASS | All evidence satisfies thresholds | Contributes weighted score |
| SOFT_FAIL | Evidence exists but below threshold | Warning; may proceed with waiver |
| HARD_FAIL | Evidence missing, stale, or invalid | Blocks readiness |
| NOT_APPLICABLE | Dimension not relevant for track | Excluded from score |

### 2.3 Aggregation Formula

```text
readiness_score = Σ(dimension_weight × dimension_pass) / Σ(applicable_weights)

GO verdict:     readiness_score >= 0.85 AND zero HARD_FAIL
CONDITIONAL:    readiness_score >= 0.70 AND zero HARD_FAIL
NO_GO:          readiness_score < 0.70 OR any HARD_FAIL
```

---

## 3. Per-Track Readiness Profiles

### 3.1 Track Evidence Requirements

| Track | Required Dimensions | Notes |
|-------|-------------------|-------|
| T2 (I/O) | RG-DIM-01..08 | Full coverage required |
| T3 (FS/Process/Signal) | RG-DIM-01..08 | Full coverage required |
| T4 (QUIC/H3) | RG-DIM-01..08 | Full coverage required |
| T5 (Web/gRPC) | RG-DIM-01..08 | Full coverage required |
| T6 (Database/Messaging) | RG-DIM-01..08 | Full coverage required |
| T7 (Interop) | RG-DIM-01..06, 08 | RG-DIM-07 optional for adapter layer |

### 3.2 Evidence Freshness Rules

| Evidence Type | Maximum Age | Staleness Action |
|---------------|-------------|------------------|
| Test results | 7 days | Re-run required |
| Performance benchmarks | 14 days | Re-run with latest code |
| Security audit | 30 days | Re-audit if code changed |
| Migration lab results | 30 days | Re-run if track changed |
| Golden corpus | 7 days | Verify schema drift |

---

## 4. Gate Output Schema

### 4.1 Machine-Readable Output

```json
{
  "schema_version": "readiness-gate-v1",
  "evaluation_id": "RG-20260304-001",
  "evaluated_at": "2026-03-04T12:00:00Z",
  "track": "T6",
  "verdict": "GO",
  "readiness_score": 0.92,
  "dimensions": [
    {
      "id": "RG-DIM-01",
      "name": "Feature Parity",
      "status": "PASS",
      "weight": 0.25,
      "evidence_ref": "docs/tokio_functional_parity_contracts.md",
      "evidence_age_days": 3,
      "details": "28/28 contracts satisfied"
    }
  ],
  "hard_fails": [],
  "soft_fails": [],
  "waivers": [],
  "risk_register_link": "docs/tokio_capability_risk_register.md",
  "correlation_id": "rg-eval-20260304-abc123"
}
```

### 4.2 Human-Readable Summary

The gate output includes a decision rationale section with:

- Overall verdict with confidence level
- Per-dimension status with actionable diagnostics
- Owner attribution for any failures
- Risk register references for known gaps
- Recommended next steps

---

## 5. Hard-Fail Diagnostics

### 5.1 Missing Evidence

When evidence is absent or cannot be located:

```json
{
  "diagnostic": "HARD_FAIL: Missing evidence for RG-DIM-02 (Unit Test Quality)",
  "expected_artifact": "tests/tokio_unit_quality_threshold_contract.md",
  "owner": "Track T6 lead",
  "remediation": "Run unit test quality evaluation: cargo test --test tokio_db_messaging_unit_test_matrix",
  "replay_pointer": "cargo test --test tokio_unit_quality_threshold_enforcement"
}
```

### 5.2 Stale Evidence

When evidence exceeds maximum age:

```json
{
  "diagnostic": "HARD_FAIL: Stale evidence for RG-DIM-04 (Performance Budget)",
  "artifact": "artifacts/perf_regression_T6_20260220.json",
  "evidence_age_days": 12,
  "max_age_days": 7,
  "owner": "Track T6 lead",
  "remediation": "Re-run performance benchmarks with current code"
}
```

### 5.3 Invalid Evidence

When evidence fails validation:

```json
{
  "diagnostic": "HARD_FAIL: Invalid evidence for RG-DIM-03 (E2E Logging Quality)",
  "artifact": "artifacts/e2e_log_quality_T5.json",
  "validation_error": "Missing required field: correlation_id in 3 entries",
  "owner": "Track T5 lead",
  "remediation": "Fix structured logging in e2e test suite"
}
```

---

## 6. Waiver Process

### 6.1 Waiver Conditions

A SOFT_FAIL may be waived when:

| Condition | Required Approval | Max Duration |
|-----------|-------------------|--------------|
| Known limitation with workaround | Track lead | 30 days |
| Upstream dependency not yet available | Program lead | 60 days |
| Non-functional regression within budget | Track lead | 14 days |

### 6.2 Waiver Schema

```json
{
  "waiver_id": "WV-20260304-001",
  "dimension": "RG-DIM-04",
  "track": "T6",
  "reason": "Pool warm-up latency 5% above budget; fix scheduled for next sprint",
  "approved_by": "Track T6 lead",
  "expires_at": "2026-03-18T00:00:00Z",
  "follow_up_bead": "asupersync-2oh2u.X.Y"
}
```

---

## 7. Quality Gates

| Gate ID | Name | Condition | Evidence |
|---------|------|-----------|----------|
| RG-01 | Dimensions complete | All 8 RG-DIM-xx dimensions defined with weights | This document §2.1 |
| RG-02 | Evaluation rules deterministic | PASS/SOFT_FAIL/HARD_FAIL criteria explicit | This document §2.2 |
| RG-03 | Aggregation formula defined | Score formula and verdict thresholds specified | This document §2.3 |
| RG-04 | Output schema versioned | readiness-gate-v1 schema with required fields | This document §4.1 |
| RG-05 | Hard-fail diagnostics actionable | Missing/stale/invalid diagnostics with owner attribution | This document §5 |
| RG-06 | Waiver process defined | Conditions, approval, expiry documented | This document §6 |
| RG-07 | Evidence freshness enforced | Maximum age rules per evidence type | This document §3.2 |
| RG-08 | Per-track profiles defined | Required dimensions per track listed | This document §3.1 |

---

## 8. Evidence Links

| Artifact | Reference |
|----------|-----------|
| Feature parity contracts | `docs/tokio_functional_parity_contracts.md` |
| Unit test quality thresholds | `docs/tokio_unit_quality_threshold_contract.md` |
| Cross-track logging gates | `docs/tokio_cross_track_e2e_logging_gate_contract.md` |
| Performance regression budgets | `docs/tokio_track_performance_regression_budgets.md` |
| Security/authority audit | `docs/tokio_capability_security_authority_audit.md` |
| Migration lab KPI contract | `docs/tokio_migration_lab_kpi_contract.md` |
| Golden log corpus | `docs/tokio_golden_log_corpus_contract.md` |
| Incident-response playbooks | `docs/tokio_incident_response_rollback_playbooks.md` |
| Capability risk register | `docs/tokio_capability_risk_register.md` |
| Replacement roadmap | `docs/tokio_replacement_roadmap.md` |

---

## 9. CI Integration

Validation:
```bash
cargo test --test tokio_replacement_readiness_gate_enforcement
rch exec 'cargo test --test tokio_replacement_readiness_gate_enforcement'
```

---

## Appendix A: Cross-References

| Bead | Relationship | Description |
|------|-------------|-------------|
| `asupersync-2oh2u.11.10` | Prerequisite | Migration lab KPIs |
| `asupersync-2oh2u.10.13` | Prerequisite | Golden log corpus |
| `asupersync-2oh2u.10.12` | Prerequisite | Cross-track e2e logging gates |
| `asupersync-2oh2u.10.11` | Prerequisite | Unit-test coverage thresholds |
| `asupersync-2oh2u.2.8` | Prerequisite | I/O conformance gates |
| `asupersync-2oh2u.10.8` | Prerequisite | Security/authority audits |
| `asupersync-2oh2u.10.7` | Prerequisite | Performance regression budgets |
| `asupersync-2oh2u.10.10` | Prerequisite | Incident-response playbooks |
| `asupersync-2oh2u.11.5` | Downstream | Release channels and stabilization |
| `asupersync-2oh2u.11.8` | Downstream | Replacement claim RFC |
| `asupersync-2oh2u.11.9` | Downstream | GA readiness checklist |
