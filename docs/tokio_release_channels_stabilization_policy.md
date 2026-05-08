# Release Channels and Stabilization Policy for Replacement Surfaces

**Bead**: `asupersync-2oh2u.11.5` ([T9.5])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Date**: 2026-03-04
**Purpose**: Define release channels, promotion criteria, stabilization policy,
and rollback triggers for Tokio-replacement surfaces with objective,
evidence-based gates at each stability tier.

---

## 1. Scope

This policy governs the lifecycle of all Tokio-replacement API surfaces from
initial development through general availability. It is grounded in:

- Readiness gate aggregator from `asupersync-2oh2u.10.9` (T8.9)
- Migration lab KPI outcomes from `asupersync-2oh2u.11.10` (T9.10)
- Compatibility matrix from `asupersync-2oh2u.11.3` (T9.3)
- Incident-response playbooks from `asupersync-2oh2u.10.10` (T8.10)

Prerequisites:
- `asupersync-2oh2u.11.10` (T9.10: migration lab KPIs)
- `asupersync-2oh2u.10.9` (T8.9: readiness gate aggregator)
- `asupersync-2oh2u.11.3` (T9.3: compatibility matrix)
- `asupersync-2oh2u.10.10` (T8.10: incident-response playbooks)

Downstream:
- `asupersync-2oh2u.11.7` (T9.7: external validation)
- `asupersync-2oh2u.11.6` (T9.6: compatibility governance)

---

## 2. Release Channels

### 2.1 Channel Definitions

| Channel | Stability | API Guarantee | Audience | Cadence |
|---------|-----------|---------------|----------|---------|
| Alpha | Experimental | None; breaking changes expected | Contributors, early adopters | On-demand |
| Beta | Stabilizing | Semver-soft; deprecation warnings before removal | Integration testers, pilot users | Monthly |
| RC | Release Candidate | Semver-hard; no API breaks without RFC | Production pilots | As-needed |
| GA | General Availability | Full semver; LTS commitment | All users | Per roadmap |

### 2.2 Channel Feature Flags

Each replacement surface is gated by a feature flag:

```toml
[features]
# Alpha surfaces (opt-in)
tokio-replace-io-alpha = []
tokio-replace-fs-alpha = []
tokio-replace-quic-alpha = []
tokio-replace-web-alpha = []
tokio-replace-db-alpha = []
tokio-replace-interop-alpha = []

# Beta surfaces (opt-in, more stable)
tokio-replace-io-beta = ["tokio-replace-io-alpha"]
tokio-replace-fs-beta = ["tokio-replace-fs-alpha"]

# GA surfaces (default-on)
tokio-replace-io = ["tokio-replace-io-beta"]
```

---

## 3. Promotion Criteria

### 3.1 Alpha Entry

| Gate ID | Criterion | Evidence Source | Threshold |
|---------|-----------|----------------|-----------|
| PC-A01 | Functional parity contracts defined | T1.2 parity contracts | Contract exists |
| PC-A02 | Core API surface implemented | Track implementation | Compiles, basic tests pass |
| PC-A03 | Unit test coverage baseline | T8.11 thresholds | >= 60% line coverage |
| PC-A04 | No known soundness bugs | Audit records | Zero HIGH/CRITICAL open bugs |
| PC-A05 | Basic documentation exists | API docs | `#[doc]` on public items |

### 3.2 Alpha to Beta Promotion

| Gate ID | Criterion | Evidence Source | Threshold |
|---------|-----------|----------------|-----------|
| PC-B01 | Readiness gate CONDITIONAL or higher | T8.9 aggregator | Score >= 0.70 |
| PC-B02 | Unit test quality threshold | T8.11 | >= 80% line coverage |
| PC-B03 | E2E suite passing | Track e2e tests | All scenarios pass |
| PC-B04 | Structured logging conformant | T8.12 gates | Zero LQ-xx hard-fails |
| PC-B05 | Performance within 2x budget | T8.7 budgets | p99 latency <= 2× baseline |
| PC-B06 | Migration cookbook available | T9.2 cookbooks | Track cookbook complete |
| PC-B07 | No known HIGH/CRITICAL bugs | Audit records | Zero open HIGH+ bugs |

### 3.3 Beta to RC Promotion

| Gate ID | Criterion | Evidence Source | Threshold |
|---------|-----------|----------------|-----------|
| PC-R01 | Readiness gate GO | T8.9 aggregator | Score >= 0.85 |
| PC-R02 | Migration lab KPIs pass | T9.10 lab results | Zero FK-xx hard-fails |
| PC-R03 | Golden corpus regression clean | T8.13 corpus | Zero schema violations |
| PC-R04 | Security audit complete | T8.8 audit | No unmitigated findings |
| PC-R05 | Performance within 1.2x budget | T8.7 budgets | p99 latency <= 1.2× baseline |
| PC-R06 | Incident playbook tested | T8.10 drills | At least 1 drill executed |
| PC-R07 | Compatibility matrix published | T9.3 matrix | All entries rationale-backed |
| PC-R08 | API review complete | RFC process | Approved by 2+ reviewers |

### 3.4 RC to GA Promotion

| Gate ID | Criterion | Evidence Source | Threshold |
|---------|-----------|----------------|-----------|
| PC-G01 | 14-day soak with zero SEV-1/SEV-2 | Production metrics | Zero incidents |
| PC-G02 | Migration lab friction KPIs all pass | T9.10 | Zero soft/hard-fails |
| PC-G03 | Performance at or below budget | T8.7 budgets | p99 <= baseline |
| PC-G04 | 3+ external validation reports | T9.7 | Positive assessment |
| PC-G05 | Deprecation notices published | Changelog | All replaced APIs flagged |
| PC-G06 | LTS commitment documented | Release notes | Support timeline defined |

---

## 4. Rollback Triggers

### 4.1 Automatic Rollback Conditions

| Trigger ID | Channel | Condition | Action |
|-----------|---------|-----------|--------|
| RT-01 | Beta/RC/GA | SEV-1 incident within 24h of promotion | Immediate rollback |
| RT-02 | Beta/RC/GA | Readiness score drops below channel minimum | Rollback within 4h |
| RT-03 | RC/GA | Migration lab hard-fail on any FK-xx KPI | Pause promotion |
| RT-04 | GA | 3+ SEV-2 incidents in 7-day window | Evaluation + possible rollback |
| RT-05 | Any | Security vulnerability (CVSS >= 7.0) | Emergency rollback |

### 4.2 Manual Rollback Authority

| Channel | Rollback Authority | Escalation Path |
|---------|-------------------|-----------------|
| Alpha | Track lead | None required |
| Beta | Track lead + program lead | Engineering VP within 2h |
| RC | Program lead + 2 reviewers | Engineering VP within 1h |
| GA | Program lead + engineering VP | CTO within 30min |

---

## 5. Stabilization Timeline

### 5.1 Expected Duration Per Channel

| Channel | Minimum Duration | Typical Duration | Maximum Duration |
|---------|-----------------|------------------|-----------------|
| Alpha | 2 weeks | 4 weeks | 12 weeks |
| Beta | 4 weeks | 8 weeks | 16 weeks |
| RC | 2 weeks | 4 weeks | 8 weeks |
| GA | Indefinite | N/A | N/A |

### 5.2 Track-Specific Timeline Estimates

| Track | Alpha Target | Beta Target | RC Target | GA Target |
|-------|-------------|-------------|-----------|-----------|
| T2 (I/O) | Complete | +4 weeks | +8 weeks | +12 weeks |
| T3 (FS/Process/Signal) | Complete | +4 weeks | +8 weeks | +12 weeks |
| T4 (QUIC/H3) | Complete | +6 weeks | +12 weeks | +16 weeks |
| T5 (Web/gRPC) | In progress | +8 weeks | +14 weeks | +18 weeks |
| T6 (Database/Messaging) | In progress | +8 weeks | +14 weeks | +18 weeks |
| T7 (Interop) | In progress | +6 weeks | +10 weeks | +14 weeks |

---

## 6. Exception Handling

### 6.1 Waiver Process

When a promotion gate cannot be satisfied:

1. **Document**: File waiver request with justification and risk assessment
2. **Assess**: Track lead evaluates risk vs. blocking impact
3. **Approve**: Per rollback authority table (§4.2)
4. **Monitor**: Enhanced monitoring for waived dimension
5. **Remediate**: Follow-up bead created with deadline

### 6.2 Waiver Schema

```json
{
  "schema_version": "promotion-waiver-v1",
  "waiver_id": "WV-T6-20260304-001",
  "track": "T6",
  "channel_transition": "Beta -> RC",
  "gate_id": "PC-R05",
  "justification": "Performance 1.3x baseline; optimization bead filed",
  "risk_level": "Medium",
  "approved_by": "Program lead",
  "expires_at": "2026-04-04T00:00:00Z",
  "follow_up_bead": "asupersync-2oh2u.X.Y",
  "monitoring_plan": "Daily p99 latency review until remediated"
}
```

---

## 7. Owner Responsibilities

### 7.1 Role Matrix

| Role | Alpha | Beta | RC | GA |
|------|-------|------|-----|-----|
| Track Lead | Gate compliance | Promotion request | Soak monitoring | Incident response |
| Program Lead | Oversight | Approval | Approval + soak | Rollback authority |
| QA Lead | Test coverage | Lab validation | Regression suite | Ongoing verification |
| Ops Lead | N/A | Playbook review | Drill execution | Production monitoring |

---

## 8. Quality Gates

| Gate ID | Name | Condition | Evidence |
|---------|------|-----------|----------|
| SP-01 | Channel definitions complete | Alpha/Beta/RC/GA with guarantees | This document §2.1 |
| SP-02 | Promotion criteria measurable | PC-xx gates with thresholds | This document §3 |
| SP-03 | Rollback triggers defined | RT-xx with automatic conditions | This document §4.1 |
| SP-04 | Rollback authority clear | Per-channel authority matrix | This document §4.2 |
| SP-05 | Timeline estimates provided | Per-track duration estimates | This document §5 |
| SP-06 | Exception handling documented | Waiver process with schema | This document §6 |
| SP-07 | Owner responsibilities assigned | Role matrix per channel | This document §7 |
| SP-08 | Feature flags defined | Per-track channel flags | This document §2.2 |

---

## 9. Evidence Links

| Artifact | Reference |
|----------|-----------|
| Readiness gate aggregator | `docs/tokio_replacement_readiness_gate_aggregator.md` |
| Migration lab KPI contract | `docs/tokio_migration_lab_kpi_contract.md` |
| Compatibility matrix | `docs/tokio_compatibility_limitation_matrix.md` |
| Incident-response playbooks | `docs/tokio_incident_response_rollback_playbooks.md` |
| Cross-track logging gates | `docs/tokio_cross_track_e2e_logging_gate_contract.md` |
| Performance regression budgets | `docs/tokio_track_performance_regression_budgets.md` |
| Replacement roadmap | `docs/tokio_replacement_roadmap.md` |

---

## 10. CI Integration

Validation:
```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_policy_docs cargo test --test tokio_release_channels_stabilization_enforcement
```

---

## Appendix A: Cross-References

| Bead | Relationship | Description |
|------|-------------|-------------|
| `asupersync-2oh2u.11.10` | Prerequisite | Migration lab KPIs |
| `asupersync-2oh2u.10.9` | Prerequisite | Readiness gate aggregator |
| `asupersync-2oh2u.11.3` | Prerequisite | Compatibility matrix |
| `asupersync-2oh2u.10.10` | Prerequisite | Incident-response playbooks |
| `asupersync-2oh2u.11.7` | Downstream | External validation |
| `asupersync-2oh2u.11.6` | Downstream | Compatibility governance |
