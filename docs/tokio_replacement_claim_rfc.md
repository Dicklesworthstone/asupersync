# Tokio-Ecosystem Replacement Claim RFC and Sign-Off Record

**Bead**: `asupersync-2oh2u.11.8` ([T9.8])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Author**: SapphireHill (claude-code / opus-4.6)
**Date**: 2026-03-04
**RFC Version**: 1.0.0
**Status**: DRAFT
**Purpose**: Compile a proposed replacement-claim RFC, with explicit scope,
known limitations, governance decisions, and sign-off criteria. This draft does
not establish that asupersync is a comprehensive Tokio-ecosystem replacement.

---

## 1. Executive Summary

The draft internal capability matrix classifies **77.4%** of 84 capability entries as
"Full" across 13 capability domains. Those classifications are an internal
inventory, not an independently reproduced parity result, and must not be read
as proof that the runtime replaces the Tokio ecosystem. The invariant rows
refer to properties of the abstract model and scoped runtime evidence; they do
not establish a refinement proof for every production surface.

Draft inventory metrics (not independent validation results):
- **65 Full** parity capabilities (77.4%)
- **9 Partial** parity capabilities (10.7%)
- **7 Adapter** bridge capabilities (8.3%)
- **3 Unsupported** capabilities (3.6%)
- **10 known limitations** (0 Critical, 2 High, 5 Medium, 3 Low)
- **6 migration lab archetypes** defined with friction KPIs
- **12 benchmark-suite definitions** for baseline-vs-replacement comparison
- **16 incident classes** with response playbooks and detection rules

### 1.1 Evidence Status Caveat (calibration)

This RFC is a **DRAFT claim document, not an externally validated certification**
(see asupersync issue #54). Readers should weigh the campaign results below
accordingly:

- The validation-campaign results in §4.2 (VC-01..VC-06, including the 7-day
  reliability soak) are **self-reported by the internal agent campaign lane**.
  The companion document `tokio_external_validation_benchmark_packs.md` defines
  the campaign **methodology and evidence-pack requirements**; this RFC does not
  link raw, independently archived evidence packs for those runs.
- The CI enforcement suite (`tests/tokio_replacement_claim_rfc_enforcement.rs`)
  verifies this document's **structure and required content**, not that any
  campaign executed or that its raw data exists.
- Independent reproduction gates remain open in §10: the 14-day soak test and
  the external validation campaign are **Pending**, and the replacement claim
  should not be treated as established until they complete.

---

## 2. Scope

### 2.1 Replacement Claim Boundary

This RFC proposes the following claim boundary for future validation and
sign-off; it does not certify these tracks today:

| Track | Domain | Claim Level |
|-------|--------|------------|
| T2 | I/O and Codec | Full |
| T3 | Filesystem, Process, Signal | Full |
| T4 | QUIC, HTTP/3, Advanced Networking | Full |
| T5 | Web Framework, Middleware, gRPC | Full |
| T6 | Database and Messaging | Full |
| T7 | Tokio-locked Third-Party Interop | Adapter |

### 2.2 Out of Scope

- Windows-specific signal handling (limitation L-09, Low severity)
- Process PTY allocation (limitation L-10, Low severity)
- SQLx compile-time query verification (limitation L-04, High severity — architectural incompatibility)

### 2.3 Prerequisites

| Bead | Description | Tracker status (not execution evidence) |
|------|-------------|-----------------------------------------|
| `asupersync-2oh2u.11.11` | Diagnostics UX hardening | CLOSED |
| `asupersync-2oh2u.10.9` | Readiness gate aggregator | CLOSED |
| `asupersync-2oh2u.11.12` | Operator enablement pack | CLOSED |
| `asupersync-2oh2u.11.7` | External validation packs | CLOSED |
| `asupersync-2oh2u.11.6` | Compatibility governance | CLOSED |
| `asupersync-2oh2u.10.10` | Incident-response playbooks | CLOSED |

---

## 3. Capability/Support Matrix

### 3.1 Per-Domain Summary

| Domain | Full | Partial | Adapter | Unsupported | Total |
|--------|------|---------|---------|-------------|-------|
| Core Runtime | 6 | 0 | 0 | 0 | 6 |
| Channels and Synchronization | 10 | 0 | 0 | 0 | 10 |
| Time | 4 | 0 | 0 | 0 | 4 |
| I/O and Codec | 6 | 1 | 0 | 0 | 7 |
| Networking | 6 | 0 | 0 | 0 | 6 |
| QUIC and HTTP/3 | 4 | 3 | 0 | 0 | 7 |
| HTTP/1.1 and HTTP/2 | 6 | 0 | 0 | 0 | 6 |
| Web Framework and gRPC | 7 | 1 | 0 | 0 | 8 |
| Database and Messaging | 5 | 2 | 0 | 2 | 9 |
| Service Layer | 5 | 0 | 0 | 0 | 5 |
| Filesystem, Process, Signal | 4 | 1 | 0 | 1 | 6 |
| Streams and Observability | 2 | 1 | 0 | 0 | 3 |
| Tokio Interop | 0 | 0 | 7 | 0 | 7 |
| **Total** | **65** | **9** | **7** | **3** | **84** |

### 3.2 Compatibility Governance Binding

All capability classifications are governed by the compatibility governance
policy defined in `asupersync-2oh2u.11.6` (T9.6):
- **Stable** surfaces: Full semver guarantee, 2+ minor-release deprecation window
- **Provisional** surfaces: Semver-soft, 1+ minor-release deprecation window
- **Experimental** surfaces: No stability guarantee

Classification changes follow the breaking change process (BC-01..BC-06) with
governance board approval per decision thresholds (2/3 majority for deprecation,
3/4 majority for breaking changes in stable surfaces).

---

## 4. Evidence Chain

### 4.1 Unit-Test Evidence

| Track | Test Suite | Key Tests |
|-------|-----------|-----------|
| T2 | tests/io/, tests/codec/ | AsyncRead/Write, framed I/O, codec pipelines |
| T3 | tests/fs/, tests/process/, tests/signal/ | File ops, process spawn, signal handling |
| T4 | tests/net/quic/, tests/http/h3/ | QUIC handshake, H3 streams, connection migration |
| T5 | tests/web/, tests/grpc/ | Routing, middleware, gRPC unary/streaming |
| T6 | tests/database/, tests/messaging/ | Pool acquire, transactions, message ordering |
| T7 | tests/tokio_interop_*, tests/tokio_adapter_* | Bridge conformance, adapter boundary |

### 4.2 E2E Script Evidence

| Campaign | Bead | Description | Evidence status |
|----------|------|-------------|-----------------|
| VC-01 | T9.7 | Functional parity per track | UNVERIFIED — internal lane reported PASS; no linked raw pack |
| VC-02 | T9.7 | Performance baseline comparison | UNVERIFIED — internal lane reported PASS; no linked raw pack |
| VC-03 | T9.7 | 7-day reliability soak | UNVERIFIED — internal lane reported PASS; no linked raw pack |
| VC-04 | T9.7 | Migration friction assessment | UNVERIFIED — internal lane reported PASS; no linked raw pack |
| VC-05 | T9.7 | Operability drill execution | UNVERIFIED — internal lane reported PASS; no linked raw pack |
| VC-06 | T9.7 | Ecosystem interop validation | UNVERIFIED — internal lane reported PASS; no linked raw pack |

### 4.3 Structured-Log Evidence

Log quality is enforced by:
- Cross-track e2e logging gates (T8.12, `asupersync-2oh2u.10.12`)
- Golden log corpus regression harness (T8.13, `asupersync-2oh2u.10.13`)
- Schema fields: `schema_version`, `scenario_id`, `correlation_id`, `outcome`, `replay_pointer`

### 4.4 Benchmark Evidence

The validation plan defines 12 benchmark suites (BM-01..BM-12) and the
following comparison verdict vocabulary: BETTER (>5% improvement), EQUIVALENT
(±5%), ACCEPTABLE (5-20% regression), REGRESSION (>20%), INCOMPATIBLE. This
section defines the evaluation scheme; it does not record reproduced benchmark
results.

---

## 5. Known Limitations

### 5.1 Limitation Register

| ID | Description | Severity | Mitigation | Owner |
|----|-------------|----------|------------|-------|
| L-01 | QUIC connection migration partial | Medium | NAT rebinding works; path migration planned | T4 |
| L-02 | HTTP/3 server push not supported | Medium | Server push deprecated in most browsers | T4 |
| L-03 | 0-RTT replay protection advisory | Medium | Application-level idempotency recommended | T4 |
| L-04 | SQLx compile-time query verification | High | Runtime verification available; type-safe alternative | T6 |
| L-05 | rdkafka StreamConsumer partial | High | Low-level consumer fully supported | T6 |
| L-06 | Redis cluster mode partial | Medium | Single-node and sentinel fully supported | T6 |
| L-07 | NATS JetStream partial | Medium | Core NATS fully supported; JetStream planned | T6 |
| L-08 | gRPC reflection service | Low | Server reflection available; client reflection planned | T5 |
| L-09 | Windows signal handling limited | Low | SIGINT/SIGTERM on Unix; Ctrl+C on Windows | T3 |
| L-10 | Process PTY allocation | Low | Standard process spawn/wait fully supported | T3 |

### 5.2 Unresolved Risk Register

| Risk | Severity | Probability | Impact | Mitigation |
|------|----------|-------------|--------|------------|
| SQLx ecosystem adoption blocked | High | Medium | Users requiring compile-time verification cannot migrate | Runtime alternative; upstream SQLx adapter proposed |
| rdkafka high-level consumer gap | High | Low | Kafka users using StreamConsumer must refactor | Low-level consumer covers 90%+ use cases |
| QUIC 0-RTT replay attacks | Medium | Low | Theoretical risk if application lacks idempotency | Documentation and cookbook guidance |

---

## 6. Incident Playbook Links

### 6.1 Incident Class Coverage

16 incident classes (IC-01..IC-16) with:
- Detection rules (DR-01..DR-06) for automated alerting
- SLA targets: SEV-1 < 30min, SEV-2 < 2h, SEV-3 < 8h, SEV-4 < 48h
- Triage decision trees per track

### 6.2 Operator Enablement

8 symptom-based runbooks (SY-01..SY-08) with:
- Replay pointers to executable test scenarios
- Correlation ID chains for end-to-end tracing
- Escalation matrix with named role targets

### 6.3 Drill Schedule

6 drill types (DRILL-01..DRILL-06) on monthly/quarterly cadence with
drill report schema (drill-report-v1).

---

## 7. Diagnostic Guidance

### 7.1 Migration Failure Classes

10 failure classes (MF-01..MF-10) with diagnostic messages containing:
- Error code, severity, context, remediation hint, docs link, replay pointer
- 5 message quality rules (DX-01..DX-05)
- 5 remediation categories (API_CHANGE, PATTERN_MIGRATION, CONFIGURATION, DEPENDENCY, ROLLBACK)

### 7.2 MTTR Improvement Targets

| Failure Class Range | Before | After | Improvement |
|--------------------|--------|-------|-------------|
| MF-01..MF-02 (type/trait) | 30 min | 15 min | 50% |
| MF-03..MF-06 (runtime) | 60 min | 20 min | 67% |
| MF-07..MF-08 (perf/health) | 45 min | 15 min | 67% |
| MF-09..MF-10 (log/correlation) | 20 min | 5 min | 75% |

---

## 8. Readiness Assessment

### 8.1 Readiness Gate Formula

8 evidence dimensions with weighted scoring:

| Dimension | Weight | Gate |
|-----------|--------|------|
| RG-DIM-01: Feature Parity | 25% | T1 contracts |
| RG-DIM-02: Unit Test Quality | 15% | T8.11 thresholds |
| RG-DIM-03: E2E Logging Quality | 10% | T8.12 gates |
| RG-DIM-04: Performance Budget | 15% | T8.7 budgets |
| RG-DIM-05: Security Audit | 10% | T8.8 authority-flow |
| RG-DIM-06: Migration Lab Outcomes | 10% | T9.10 friction KPIs |
| RG-DIM-07: Golden Corpus Conformance | 5% | T8.13 schemas |
| RG-DIM-08: Operations Readiness | 10% | T8.10 playbooks |

### 8.2 Promotion Thresholds

| Decision | Score Threshold | Additional |
|----------|----------------|-----------|
| GO | >= 0.85 | Zero HARD_FAIL |
| CONDITIONAL | >= 0.70 | Zero HARD_FAIL |
| NO_GO | < 0.70 | Or any HARD_FAIL |

### 8.3 Release Channel Mapping

| Channel | Promotion Gates | Rollback Triggers |
|---------|----------------|-------------------|
| Alpha | PC-A01..PC-A05 | Track lead authority |
| Beta | PC-B01..PC-B07 | RT-01..RT-05 |
| RC | PC-R01..PC-R08 | RT-01..RT-05 |
| GA | PC-G01..PC-G06 | RT-01..RT-05 + VP authority |

---

## 9. Invariant Preservation

The draft maps replacement surfaces to five abstract-model invariants. The Lean
theorems prove properties of that model; the table is not a proof that every
Rust implementation surface refines it:

| Invariant | ID | Status | Formal Proof |
|-----------|-----|--------|-------------|
| No ambient authority | INV-1 | Preserved | Lean theorem (SEM-06.10) |
| Structured concurrency | INV-2 | Preserved | Lean theorem (SEM-06.6) |
| Cancellation is a protocol | INV-3 | Preserved | Lean theorem (SEM-06.7) |
| No obligation leaks | INV-4 | Preserved | Lean theorem (SEM-06.9) |
| Outcome severity lattice | INV-5 | Preserved | Lean theorem (SEM-06.8) |

The proof inventory labels six abstract-model invariant rows `FULLY_PROVEN`
(6/6), with 170 Lean theorems, 136 traceability rows, and 122 distinct theorems
covering 22/22 model constructors. That label does not mean the production Rust
runtime is fully formally verified.

---

## 10. Sign-Off Record

### 10.1 Approval Matrix

| Role | Name | Decision | Date | Conditions |
|------|------|----------|------|-----------|
| Program Lead | [Pending] | [Pending] | | |
| T2 Track Lead | [Pending] | [Pending] | | |
| T3 Track Lead | [Pending] | [Pending] | | |
| T4 Track Lead | [Pending] | [Pending] | | |
| T5 Track Lead | [Pending] | [Pending] | | |
| T6 Track Lead | [Pending] | [Pending] | | |
| T7 Track Lead | [Pending] | [Pending] | | |
| QA Lead | [Pending] | [Pending] | | |
| Security Lead | [Pending] | [Pending] | | |

### 10.2 Sign-Off Criteria

Each approver must confirm:
1. All capability claims are backed by evidence they have reviewed
2. Known limitations are acceptable for the claimed replacement scope
3. Incident playbooks and rollback procedures are adequate
4. Governance and deprecation policy is operationally sound

### 10.3 Outstanding Conditions

| Condition | Owner | Deadline | Status |
|-----------|-------|----------|--------|
| Readiness gate score computed | QA Lead | Before Beta promotion | Pending |
| 14-day soak test | Ops Lead | Before GA promotion | Pending |
| External validation campaign | Program Lead | Before RC promotion | Pending |

---

## 11. Rollback Triggers

5 automatic rollback triggers (RT-01..RT-05):

| Trigger | Condition | Channel | Action |
|---------|-----------|---------|--------|
| RT-01 | SEV-1 within 24h of promotion | Beta/RC/GA | Immediate rollback |
| RT-02 | Readiness score below minimum | Beta/RC/GA | Rollback within 4h |
| RT-03 | Migration lab hard-fail | RC/GA | Pause promotion |
| RT-04 | 3+ SEV-2 in 7 days | GA | Evaluate + possible rollback |
| RT-05 | Security vulnerability CVSS >= 7.0 | Any | Emergency rollback |

Rollback authority escalation:
- Alpha: Track lead (unilateral)
- Beta: Track lead + Program lead → Engineering VP within 2h
- RC: Program lead + 2 reviewers → Engineering VP within 1h
- GA: Program lead + Engineering VP → CTO within 30min

---

## 12. Quality Gates

| Gate ID | Name | Condition | Evidence |
|---------|------|-----------|----------|
| RFC-01 | Capability matrix complete | 84 entries with rationale | This document §3 |
| RFC-02 | Evidence chain traced | Unit/e2e/log for each claim | This document §4 |
| RFC-03 | Limitations documented | 10 limitations with severity | This document §5 |
| RFC-04 | Incident playbooks linked | 16 IC-xx classes | This document §6 |
| RFC-05 | Diagnostic guidance complete | 10 MF-xx failure classes | This document §7 |
| RFC-06 | Readiness formula defined | 8 dimensions with thresholds | This document §8 |
| RFC-07 | Invariants preserved | All 5 INV-xx preserved | This document §9 |
| RFC-08 | Sign-off matrix present | All roles listed | This document §10 |
| RFC-09 | Rollback triggers defined | 5 RT-xx with actions | This document §11 |
| RFC-10 | No deferred markers | Zero TBD/TODO/PLACEHOLDER | This document |

---

## 13. Evidence Links

| Artifact | Reference |
|----------|-----------|
| Compatibility matrix | `docs/tokio_compatibility_limitation_matrix.md` |
| Governance policy | `docs/tokio_compatibility_governance_deprecation_policy.md` |
| Release channels | `docs/tokio_release_channels_stabilization_policy.md` |
| Readiness aggregator | `docs/tokio_replacement_readiness_gate_aggregator.md` |
| External validation | `docs/tokio_external_validation_benchmark_packs.md` |
| Incident playbooks | `docs/tokio_incident_response_rollback_playbooks.md` |
| Operator enablement | `docs/tokio_operator_enablement_pack.md` |
| Diagnostics UX | `docs/tokio_diagnostics_ux_hardening_contract.md` |
| Migration cookbooks | `docs/tokio_migration_cookbooks.md` |
| Migration lab KPIs | `docs/tokio_migration_lab_kpi_contract.md` |
| Golden log corpus | `docs/tokio_golden_log_corpus_contract.md` |
| Replacement roadmap | `docs/tokio_replacement_roadmap.md` |

---

## 14. CI Integration

Validation:
```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_policy_docs cargo test --test tokio_replacement_claim_rfc_enforcement
```

---

## 15. Downstream Binding

This RFC feeds:
- `asupersync-2oh2u.11.9` (T9.9): GA readiness checklist and launch review

---

## Appendix A: Cross-References

| Bead | Relationship | Description |
|------|-------------|-------------|
| `asupersync-2oh2u.11.11` | Prerequisite | Diagnostics UX hardening |
| `asupersync-2oh2u.10.9` | Prerequisite | Readiness gate aggregator |
| `asupersync-2oh2u.11.12` | Prerequisite | Operator enablement pack |
| `asupersync-2oh2u.11.7` | Prerequisite | External validation packs |
| `asupersync-2oh2u.11.6` | Prerequisite | Compatibility governance |
| `asupersync-2oh2u.10.10` | Prerequisite | Incident-response playbooks |
| `asupersync-2oh2u.11.9` | Downstream | GA readiness checklist |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-03-04 | SapphireHill | Initial RFC draft |
