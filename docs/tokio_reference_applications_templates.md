# Production-Grade Reference Applications and Templates

**Bead**: `asupersync-2oh2u.11.4` ([T9.4])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Date**: 2026-03-04
**Purpose**: Deliver production-grade reference applications and templates that
exercise complete replacement paths, include deterministic test harnesses, and
provide reusable operational instrumentation for adopters.

---

## 1. Scope

Reference applications demonstrate end-to-end usage of asupersync replacement
surfaces in realistic production scenarios. Each reference app covers:

- Complete API surface exercise for its target track
- Structured logging with correlation IDs and redaction
- Cancellation-safe patterns and region-based concurrency
- Migration-lab and incident-drill scripts for validation
- Deployment configuration and operational instrumentation

Prerequisites:
- `asupersync-2oh2u.10.13` (T8.13: golden log corpus)
- `asupersync-2oh2u.10.12` (T8.12: cross-track e2e logging gates)
- `asupersync-2oh2u.11.2` (T9.2: migration cookbooks)

Downstream:
- `asupersync-2oh2u.11.7` (T9.7: external validation)

---

## 2. Reference Application Catalog

### 2.1 Application Matrix

| App ID | Name | Target Track | Complexity | Description |
|--------|------|-------------|------------|-------------|
| RA-01 | io-echo-server | T2 (I/O) | Low | TCP echo server with codec framing |
| RA-02 | fs-batch-processor | T3 (FS/Process/Signal) | Medium | File batch processor with graceful shutdown |
| RA-03 | quic-file-transfer | T4 (QUIC/H3) | High | QUIC-based file transfer with connection migration |
| RA-04 | web-api-gateway | T5 (Web/gRPC) | High | REST + gRPC gateway with middleware stack |
| RA-05 | db-connection-pool | T6 (Database) | Medium | PostgreSQL connection pool with transaction management |
| RA-06 | message-pipeline | T6 (Messaging) | Medium | Kafka consumer/producer pipeline with exactly-once |
| RA-07 | interop-bridge | T7 (Interop) | Medium | tokio-compat bridge for gradual migration |
| RA-08 | full-stack-demo | Multi-track | High | Combined web+db+messaging service |

### 2.2 Per-Application Structure

Each reference application follows a standard layout:

```text
examples/<app-id>/
├── src/
│   ├── main.rs           # Entry point with region-based concurrency
│   ├── config.rs         # Configuration with env/file loading
│   └── instrumentation.rs # Structured logging + metrics setup
├── tests/
│   ├── unit/             # Unit tests with deterministic replay
│   ├── integration/      # Integration tests with test fixtures
│   └── e2e/              # End-to-end scenario tests
├── scripts/
│   ├── migration_lab.sh  # Migration lab execution script
│   ├── incident_drill.sh # Incident drill simulation
│   └── deploy.sh         # Deployment validation script
├── fixtures/
│   └── golden/           # Golden test fixtures
├── Cargo.toml
└── README.md
```

---

## 3. Application Requirements

### 3.1 Test Suite Requirements

| Requirement ID | Category | Description | Coverage Target |
|---------------|----------|-------------|-----------------|
| TR-01 | Unit | Core business logic coverage | >= 80% line coverage |
| TR-02 | Integration | Service boundary tests | All external interfaces |
| TR-03 | E2E | Full scenario coverage | Success, failure, cancellation, recovery |
| TR-04 | Cancellation | Cancel-safety verification | All async paths |
| TR-05 | Determinism | Reproducible test results | Zero flaky tests |

### 3.2 Structured Logging Requirements

| Requirement ID | Category | Description |
|---------------|----------|-------------|
| SL-01 | Schema | Conform to e2e logging schema (T8.12) |
| SL-02 | Correlation | Include correlation IDs on all requests |
| SL-03 | Redaction | Redact Bearer tokens, credentials, PII |
| SL-04 | Replay | Include replay pointers for failure scenarios |
| SL-05 | Golden | Validate against golden corpus entries (T8.13) |

### 3.3 Operational Requirements

| Requirement ID | Category | Description |
|---------------|----------|-------------|
| OP-01 | Health | Expose health check endpoints |
| OP-02 | Metrics | Export latency, error rate, throughput metrics |
| OP-03 | Config | Support env-based configuration |
| OP-04 | Graceful | Handle SIGTERM with graceful shutdown |
| OP-05 | Diagnostics | Emit actionable error messages per T9.11 |

---

## 4. Template Library

### 4.1 Reusable Templates

| Template ID | Name | Description | Target Audience |
|------------|------|-------------|-----------------|
| TM-01 | async-service-skeleton | Minimal async service with region, health, logging | New services |
| TM-02 | migration-harness | Test harness for validating tokio→asupersync migration | Migrators |
| TM-03 | incident-drill-template | Incident simulation and response measurement | Operators |
| TM-04 | performance-benchmark | Benchmark harness with budget comparison | Performance engineers |
| TM-05 | cancellation-test-suite | Cancel-safety verification test patterns | Library authors |
| TM-06 | structured-log-validator | Log schema validation utility | DevOps |

### 4.2 Template Requirements

Each template includes:

- Working `Cargo.toml` with minimal dependencies
- Inline documentation explaining design choices
- Example output and expected behavior
- Integration with migration cookbooks (T9.2) where applicable

---

## 5. Migration Lab Integration

### 5.1 Lab Scripts Per Application

Each reference application includes a migration lab script that:

1. Sets up the pre-migration (tokio-based) version
2. Executes migration steps from the relevant cookbook (T9.2)
3. Validates post-migration behavior via e2e tests
4. Measures friction KPIs (T9.10) during the migration
5. Generates structured lab results in `migration-lab-results-v1` format

### 5.2 Incident Drill Integration

Each reference application includes drill scripts that:

1. Inject failure conditions per incident class (T8.10)
2. Verify detection rules fire within SLA
3. Execute containment and rollback procedures
4. Generate drill report with timing measurements

---

## 6. Documentation Requirements

### 6.1 Per-Application Documentation

| Doc ID | Section | Content |
|--------|---------|---------|
| DOC-01 | Architecture | System design with component diagram |
| DOC-02 | Deployment | Environment setup and deployment steps |
| DOC-03 | Configuration | All configuration options with defaults |
| DOC-04 | Troubleshooting | Common issues and resolution steps |
| DOC-05 | Migration Guide | Step-by-step migration from tokio equivalent |
| DOC-06 | Evidence Links | Links to relevant test suites and contracts |

---

## 7. Quality Gates

| Gate ID | Name | Condition | Evidence |
|---------|------|-----------|----------|
| RA-G01 | Application catalog complete | All 8 RA-xx apps defined with track mapping | This document §2.1 |
| RA-G02 | Standard structure defined | Per-app directory layout specified | This document §2.2 |
| RA-G03 | Test suite requirements met | TR-01..TR-05 coverage targets defined | This document §3.1 |
| RA-G04 | Logging requirements met | SL-01..SL-05 conformance rules defined | This document §3.2 |
| RA-G05 | Operational requirements met | OP-01..OP-05 for production readiness | This document §3.3 |
| RA-G06 | Template library defined | TM-01..TM-06 templates cataloged | This document §4.1 |
| RA-G07 | Migration lab integration specified | Lab script requirements defined | This document §5 |
| RA-G08 | Documentation requirements defined | DOC-01..DOC-06 per app | This document §6 |

---

## 8. Evidence Links

| Artifact | Reference |
|----------|-----------|
| Golden log corpus | `docs/tokio_golden_log_corpus_contract.md` |
| Cross-track logging gates | `docs/tokio_cross_track_e2e_logging_gate_contract.md` |
| Migration cookbooks | `docs/tokio_migration_cookbooks.md` |
| Migration lab KPI contract | `docs/tokio_migration_lab_kpi_contract.md` |
| Diagnostics UX contract | `docs/tokio_diagnostics_ux_hardening_contract.md` |
| Incident-response playbooks | `docs/tokio_incident_response_rollback_playbooks.md` |

---

## 9. CI Integration

Validation:
```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_policy_docs cargo test --test tokio_reference_applications_enforcement
```

---

## Appendix A: Cross-References

| Bead | Relationship | Description |
|------|-------------|-------------|
| `asupersync-2oh2u.10.13` | Prerequisite | Golden log corpus |
| `asupersync-2oh2u.10.12` | Prerequisite | Cross-track e2e logging gates |
| `asupersync-2oh2u.11.2` | Prerequisite | Migration cookbooks |
| `asupersync-2oh2u.11.7` | Downstream | External validation |
