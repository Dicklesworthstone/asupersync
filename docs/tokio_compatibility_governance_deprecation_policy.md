# Compatibility Governance and Deprecation Policy

**Bead**: `asupersync-2oh2u.11.6` ([T9.6])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Author**: SapphireHill (claude-code / opus-4.6)
**Date**: 2026-03-04
**Policy Version**: 1.0.0
**Dependencies**: `asupersync-2oh2u.11.10` (migration lab KPIs), `asupersync-2oh2u.11.5` (release channels)
**Purpose**: Define compatibility governance, API stability commitments,
deprecation policy, breaking-change management, exception handling,
escalation paths, and enforcement mechanisms for Tokio-replacement
surfaces across all release channels.

---

## 1. Scope

This policy governs how API compatibility is maintained, how deprecations are
communicated, and how breaking changes are managed across the replacement
surface lifecycle. It is grounded in:

- Release channels from `asupersync-2oh2u.11.5` (T9.5)
- Migration lab outcomes from `asupersync-2oh2u.11.10` (T9.10)
- Compatibility matrix from `asupersync-2oh2u.11.3` (T9.3)

Prerequisites:
- `asupersync-2oh2u.11.10` (T9.10: migration lab KPIs)
- `asupersync-2oh2u.11.5` (T9.5: release channels)

Downstream:
- `asupersync-2oh2u.11.8` (T9.8: replacement claim RFC)

---

## 2. Compatibility Tiers

### 2.1 API Stability Levels

| Tier | Guarantee | Deprecation Notice | Removal Horizon | Applies To |
|------|-----------|-------------------|----------------|------------|
| Stable | Full semver | >= 2 minor releases | Next major only | GA surfaces |
| Provisional | Semver-soft | >= 1 minor release | Next minor allowed | Beta surfaces |
| Experimental | None | Best-effort | Any release | Alpha surfaces |
| Internal | None | None | Any commit | Private APIs |

### 2.2 Compatibility Dimensions

| Dimension ID | Name | Description | Enforcement |
|-------------|------|-------------|-------------|
| CD-01 | Source compatibility | Code compiles without changes | CI gate |
| CD-02 | Binary compatibility | ABI preserved across patch releases | Symbol checks |
| CD-03 | Behavioral compatibility | Observable behavior unchanged | E2E tests |
| CD-04 | Performance compatibility | Latency/throughput within budget | Benchmark gate |
| CD-05 | Wire compatibility | Protocol/serialization format preserved | Conformance tests |
| CD-06 | Configuration compatibility | Config keys and defaults preserved | Schema validation |

---

## 3. Deprecation Process

### 3.1 Deprecation Lifecycle

```text
PROPOSAL ──→ REVIEW ──→ APPROVED ──→ DEPRECATED ──→ REMOVED
   │           │           │             │              │
   │           │           │             │              └─ Next major release
   │           │           │             └─ #[deprecated] + migration guide
   │           │           └─ Governance board approval
   │           └─ Impact assessment complete
   └─ RFC filed with rationale
```

### 3.2 Deprecation Notice Requirements

| Requirement ID | Description |
|---------------|-------------|
| DN-01 | `#[deprecated(since, note)]` attribute on all deprecated items |
| DN-02 | Migration guide with before/after code examples |
| DN-03 | Changelog entry describing deprecation and rationale |
| DN-04 | Compiler warning with actionable replacement suggestion |
| DN-05 | Deprecation notice minimum duration per stability tier |

### 3.3 Deprecation Impact Assessment

Before deprecating any Stable or Provisional API:

| Step | Action | Owner |
|------|--------|-------|
| DIA-01 | Usage analysis across known consumers | Track lead |
| DIA-02 | Migration complexity estimate (FK-01 KPI) | QA lead |
| DIA-03 | Performance impact of replacement path | Performance engineer |
| DIA-04 | Compatibility matrix update | Governance board |
| DIA-05 | Migration cookbook entry | Documentation lead |

---

## 4. Breaking Change Management

### 4.1 Breaking Change Classification

| Class | Description | Allowed In | Approval Required |
|-------|-------------|-----------|-------------------|
| BC-01 | Type signature change | Major only | Governance board |
| BC-02 | Behavioral change (observable) | Major only | Governance board + RFC |
| BC-03 | Default value change | Minor (with deprecation) | Track lead |
| BC-04 | Feature removal | Major only | Governance board |
| BC-05 | Wire format change | Major only | Governance board + RFC |
| BC-06 | Performance regression > 10% | Blocked until fixed | Track lead |

### 4.2 Breaking Change RFC Process

1. **File RFC**: Author submits breaking change proposal with:
   - Technical rationale and alternatives considered
   - Impact assessment on known consumers
   - Migration path with estimated effort
   - Timeline and deprecation schedule

2. **Review period**: Minimum 14 days for Stable APIs, 7 days for Provisional

3. **Governance vote**: Quorum of 3+ governance board members

4. **Implementation**: Breaking change lands with:
   - Migration guide
   - Deprecation warnings in preceding release
   - Automated migration tool where feasible

---

## 5. Governance Board

### 5.1 Composition

| Role | Responsibility | Vote Weight |
|------|---------------|-------------|
| Program Lead | Final authority on cross-track decisions | 2 |
| Track Leads (T2-T7) | Domain expertise for affected tracks | 1 each |
| QA Lead | Quality and test coverage impact | 1 |
| Community Representative | User impact assessment | 1 |

### 5.2 Decision Thresholds

| Decision Type | Threshold | Quorum |
|--------------|-----------|--------|
| Deprecation (Stable) | 2/3 majority | 5 members |
| Breaking change (Stable) | 3/4 majority | 5 members |
| Deprecation (Provisional) | Simple majority | 3 members |
| Emergency rollback | Program Lead unilateral | 1 member |

---

## 6. Version Policy

### 6.1 Semver Rules

| Version Component | Incremented When |
|------------------|-----------------|
| Major (X.0.0) | Breaking changes, API removals |
| Minor (0.X.0) | New features, deprecations, non-breaking additions |
| Patch (0.0.X) | Bug fixes, security patches, documentation |

### 6.2 Pre-release Identifiers

| Identifier | Meaning | Example |
|-----------|---------|---------|
| `-alpha.N` | Experimental; no stability | 1.0.0-alpha.3 |
| `-beta.N` | Stabilizing; semver-soft | 1.0.0-beta.2 |
| `-rc.N` | Release candidate; semver-hard | 1.0.0-rc.1 |

### 6.3 Support Policy

| Release Type | Support Duration | Security Patches |
|-------------|-----------------|-----------------|
| Current major | Until next major + 6 months | Yes |
| Previous major (LTS) | 18 months from next major | Yes |
| Older majors | Community only | Critical only |

---

## 7. Ecosystem Compatibility

### 7.1 Minimum Supported Rust Version (MSRV)

| Channel | MSRV Policy |
|---------|-------------|
| Alpha | Latest stable Rust |
| Beta | Latest stable - 2 releases |
| GA | Latest stable - 4 releases (6-month window) |

### 7.2 Third-Party Crate Compatibility

Per the interop target ranking (T7.1):

| Tier | Crates | Compatibility Commitment |
|------|--------|------------------------|
| Critical | reqwest, axum, tonic | Full test coverage; breakage = SEV-1 |
| High | tower, hyper, deadpool | Integration tests; breakage = SEV-2 |
| Medium | rdkafka, redis, sqlx | Adapter tests; breakage = SEV-3 |
| Low | Remaining ecosystem | Best-effort |

---

## 8. Exception and Waiver Handling

### 8.1 Waiver Types

| Type | ID | Scope | Approval | Max Duration |
|------|----|-------|----------|-------------|
| Deprecation window reduction | WV-01 | Shorten deprecation window | Program Lead + 2 reviewers | 1 release cycle |
| Breaking change in stable | WV-02 | Permit BC-xx in RC/GA without full window | Program Lead + Engineering VP | 1 patch release |
| Performance budget override | WV-03 | Accept regression above threshold | Track Lead + QA Lead | Until next minor release |
| Gate bypass | WV-04 | Skip specific quality gate | Program Lead | 1 promotion cycle |

### 8.2 Waiver Constraints

All waivers must:
1. Document justification with evidence of necessity
2. Include risk assessment with blast-radius analysis
3. Specify follow-up bead with deadline for remediation
4. Be recorded in the waiver register (§8.3)
5. Trigger enhanced monitoring for affected surface
6. Expire automatically; no indefinite waivers

### 8.3 Waiver Register Schema

```json
{
  "schema_version": "compat-waiver-v1",
  "waiver_id": "WV-T6-20260304-001",
  "type": "WV-01",
  "surface": "tokio-replace-db",
  "channel": "Beta",
  "justification": "Security fix requires removing vulnerable API without full window",
  "risk_level": "Medium",
  "blast_radius": "3 downstream crates",
  "approved_by": ["Program Lead", "Reviewer A", "Reviewer B"],
  "created_at": "2026-03-04T00:00:00Z",
  "expires_at": "2026-04-04T00:00:00Z",
  "follow_up_bead": "asupersync-2oh2u.X.Y",
  "monitoring_plan": "Daily usage telemetry review",
  "status": "active"
}
```

---

## 9. Escalation Paths

### 9.1 Escalation Triggers and Chains

| Trigger | ID | First Response | Escalation 1 | Escalation 2 | Timeline |
|---------|-----|---------------|-------------|-------------|----------|
| Compatibility regression | ESC-01 | Track Lead triages | Program Lead within 4h | Engineering VP within 8h | 24h resolution |
| Deprecation window dispute | ESC-02 | Track Lead + author | Program Lead within 24h | Engineering VP within 48h | 1 week resolution |
| Emergency breaking change | ESC-03 | Track Lead + Program Lead | Engineering VP within 2h | CTO within 4h | Same-day resolution |
| Waiver request denied | ESC-04 | Program Lead review | Engineering VP appeal | Board review | 1 week resolution |
| Security vulnerability | ESC-05 | Track Lead + Program Lead | Engineering VP within 1h | Hotfix release within 8h | Same-day resolution |

### 9.2 Emergency Process

For security vulnerabilities (CVSS >= 7.0) or data-loss bugs:

| Step | ID | Action | Owner | Duration |
|------|----|--------|-------|----------|
| Triage | EM-01 | Classify severity, assess blast radius | Track Lead | 1h |
| Hotfix | EM-02 | Implement minimal fix | Author | 4h |
| Fast-track review | EM-03 | Single reviewer approval sufficient | Program Lead | 2h |
| Release | EM-04 | Patch release with advisory | Program Lead | 8h total |
| Retroactive RFC | EM-05 | File RFC within 72h post-release | Author | 72h |
| Post-mortem | EM-06 | Document incident and process improvements | Track Lead | 1 week |

---

## 10. Invariant Preservation

All governance decisions must preserve the five core invariants:

| Invariant | ID | Governance Constraint |
|-----------|----|--------------------|
| No ambient authority | INV-1 | No change may introduce ambient runtime access |
| Structured concurrency | INV-2 | No change may bypass region-scoped task ownership |
| Cancellation is a protocol | INV-3 | No change may introduce silent cancellation |
| No obligation leaks | INV-4 | No change may create untracked obligations |
| Outcome severity lattice | INV-5 | No change may violate severity ordering |

Any proposed change that would weaken an invariant requires:
- Explicit invariant-impact assessment in the RFC
- Formal proof update if Lean theorem is affected
- Program Lead + Engineering VP approval
- Enhanced monitoring post-release

---

## 11. Staleness and Freshness Policy

| Metric | Warning Threshold | Hard-Fail Threshold | Action |
|--------|------------------|--------------------|---------|
| Compatibility matrix age | 30 days | 60 days | Block promotions until refreshed |
| Deprecation log review | 14 days | 30 days | Escalate to Program Lead |
| Waiver register audit | 30 days | 60 days | All active waivers expire |
| Policy document age | 90 days | 180 days | Mandatory review cycle |

---

## 12. Deprecation Register Schema

### 12.1 Machine-Readable Format

```json
{
  "schema_version": "deprecation-register-v1",
  "entries": [
    {
      "dep_id": "DEP-001",
      "surface": "tokio-replace-io",
      "api": "AsyncReadCompat::read_buf",
      "stage": "DEP-S2",
      "reason": "Replaced by zero-copy AsyncRead::poll_read_vectored",
      "replacement": "Use AsyncRead::poll_read_vectored with IoSliceMut",
      "since_version": "0.3.0",
      "removal_target": "0.5.0",
      "cookbook_ref": "docs/tokio_migration_cookbooks.md#T2",
      "limitation_ref": "L-02",
      "created_at": "2026-03-04T00:00:00Z",
      "owner_track": "T2"
    }
  ],
  "summary": {
    "total_deprecations": 0,
    "active_warnings": 0,
    "soft_removed": 0,
    "hard_removed": 0
  }
}
```

---

## 13. Audit Cadence

| Activity | Frequency | Owner | Output |
|----------|-----------|-------|--------|
| Compatibility matrix review | Monthly | Track Leads | Updated compatibility matrix |
| Deprecation log review | Bi-weekly | QA Lead | Deprecation status report |
| Waiver register audit | Monthly | Program Lead | Expired waiver cleanup |
| Gate effectiveness review | Quarterly | Engineering VP | Gate configuration updates |
| Policy version review | Semi-annual | Program Lead + Engineering VP | Policy version bump |

---

## 14. Quality Gates

| Gate ID | Name | Condition | Evidence |
|---------|------|-----------|----------|
| CG-01 | Stability tiers defined | Stable/Provisional/Experimental/Internal | This document §2.1 |
| CG-02 | Compatibility dimensions defined | CD-01..CD-06 with enforcement | This document §2.2 |
| CG-03 | Deprecation lifecycle complete | PROPOSAL→REMOVED with requirements | This document §3 |
| CG-04 | Breaking change classification | BC-01..BC-06 with approval matrix | This document §4.1 |
| CG-05 | Governance board defined | Composition and decision thresholds | This document §5 |
| CG-06 | Version policy explicit | Semver rules and support duration | This document §6 |
| CG-07 | MSRV policy defined | Per-channel MSRV commitments | This document §7.1 |
| CG-08 | Ecosystem compatibility tiered | Critical/High/Medium/Low tiers | This document §7.2 |
| CG-09 | Exception handling complete | WV-01..WV-04 with constraints | This document §8 |
| CG-10 | Escalation paths defined | ESC-01..ESC-05 with timelines | This document §9 |
| CG-11 | Invariant preservation rules | All 5 invariants constrained | This document §10 |
| CG-12 | Staleness thresholds set | Warning + hard-fail per metric | This document §11 |

---

## 15. Evidence Links

| Artifact | Reference |
|----------|-----------|
| Release channels | `docs/tokio_release_channels_stabilization_policy.md` |
| Migration lab KPI contract | `docs/tokio_migration_lab_kpi_contract.md` |
| Compatibility matrix | `docs/tokio_compatibility_limitation_matrix.md` |
| Interop target ranking | `docs/tokio_interop_target_ranking.md` |
| Migration cookbooks | `docs/tokio_migration_cookbooks.md` |
| Replacement roadmap | `docs/tokio_replacement_roadmap.md` |

---

## 16. CI Integration

Validation:
```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_policy_docs cargo test --test tokio_compatibility_governance_enforcement
```

---

## 17. Downstream Binding

This policy directly feeds:
- `asupersync-2oh2u.11.8` (T9.8): Final replacement claim RFC — compatibility
  governance decisions, escalation paths, and deprecation policy are incorporated
  into the sign-off record

---

## Appendix A: Cross-References

| Bead | Relationship | Description |
|------|-------------|-------------|
| `asupersync-2oh2u.11.10` | Prerequisite | Migration lab KPIs |
| `asupersync-2oh2u.11.5` | Prerequisite | Release channels |
| `asupersync-2oh2u.11.3` | Prerequisite | Compatibility matrix |
| `asupersync-2oh2u.11.8` | Downstream | Replacement claim RFC |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-03-04 | SapphireHill | Initial release with enriched governance |
