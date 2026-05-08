# Diagnostics and Error-Message UX Hardening Contract

**Bead**: `asupersync-2oh2u.11.11` ([T9.11])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Date**: 2026-03-04
**Purpose**: Convert top migration failure modes into improved diagnostics,
actionable remediation hints, operator-friendly error messages, and security-safe
error output with deterministic test coverage.

---

## 1. Scope

This contract governs error-message UX hardening for migration failure modes
identified in the T9.10 migration labs and earlier track work. It covers:

- Diagnostic message taxonomy and severity classification
- Remediation hint framework
- Error output redaction compliance
- MTTR/MTTU improvement measurement
- Golden-log regression for diagnostic messages

Prerequisites:
- `asupersync-2oh2u.11.10` (T9.10: migration lab KPIs)
- `asupersync-2oh2u.10.13` (T8.13: golden log corpus)

---

## 2. Failure Mode Taxonomy

### 2.1 Migration Failure Classes

| Class ID | Category | Description | Severity |
|----------|----------|-------------|----------|
| MF-01 | Compilation | Type mismatch during API replacement | High |
| MF-02 | Compilation | Missing trait implementation | High |
| MF-03 | Runtime | Deadlock from incorrect concurrency model | Critical |
| MF-04 | Runtime | Resource leak (connection, file handle) | High |
| MF-05 | Runtime | Timeout/cancellation propagation failure | High |
| MF-06 | Behavioral | Silent data loss (dropped messages) | Critical |
| MF-07 | Behavioral | Performance regression (> 2x latency) | Medium |
| MF-08 | Operational | Incorrect health check behavior | Medium |
| MF-09 | Operational | Log schema version mismatch | Low |
| MF-10 | Operational | Missing correlation IDs in traces | Low |

### 2.2 Severity Levels

| Level | MTTR Target | Description |
|-------|-------------|-------------|
| Critical | < 5 min | Data loss or deadlock — immediate rollback |
| High | < 15 min | Compilation failure or resource leak |
| Medium | < 30 min | Performance issue or health check error |
| Low | < 60 min | Log schema or tracing gap |

---

## 3. Diagnostic Message Requirements

### 3.1 Message Structure

Every diagnostic MUST include:

| Field | Required | Description |
|-------|----------|-------------|
| error_code | yes | Unique error identifier (MF-01..MF-10) |
| severity | yes | Critical/High/Medium/Low |
| message | yes | Human-readable description |
| context | yes | What was being attempted |
| remediation | yes | Concrete steps to resolve |
| docs_link | no | Link to relevant cookbook/runbook |
| replay_pointer | yes | Command to reproduce |

### 3.2 Message Quality Rules

| Rule ID | Rule | Example |
|---------|------|---------|
| DX-01 | Use active voice | "Connection pool exhausted" not "Pool was exhausted" |
| DX-02 | Include concrete values | "Timeout after 30s (limit: 10s)" not "Timeout exceeded" |
| DX-03 | Suggest next action | "Run `cargo test --test ...` to verify fix" |
| DX-04 | No jargon without context | "Region (structured scope)" not just "Region" |
| DX-05 | Redaction-safe | No credentials, PII, or raw tokens in messages |

---

## 4. Remediation Hint Framework

### 4.1 Hint Categories

| Category | Description | Example |
|----------|-------------|---------|
| API_CHANGE | Function signature changed | "Replace `spawn()` with `region.spawn()`" |
| PATTERN_MIGRATION | Design pattern replacement | "Use structured concurrency instead of free spawns" |
| CONFIGURATION | Config value adjustment | "Set `max_connections = 100` in pool config" |
| DEPENDENCY | Dependency update needed | "Add `asupersync-tokio-compat` to Cargo.toml" |
| ROLLBACK | Revert and retry | "Restore previous version; see runbook section 4.1" |

### 4.2 Hint Actionability

Every remediation hint MUST be:
1. Specific (not "check the docs")
2. Executable (contains a concrete command or code change)
3. Verifiable (includes a test or check command)

---

## 5. Error Output Redaction

### 5.1 Redaction Rules

Diagnostic messages MUST NOT contain:
- Bearer tokens or API keys
- Database connection strings with credentials
- Raw IP addresses in production contexts
- PII (email, phone, SSN)
- Stack traces from user code (only framework traces)

### 5.2 Redaction Compliance Gate

All diagnostic output is subject to LQ-04 (redaction compliance) from T8.12.

---

## 6. MTTR/MTTU Improvement Measurement

### 6.1 Baseline

The migration lab (T9.10) establishes baseline MTTR per failure class.

### 6.2 Improvement Targets

| Failure Class | Baseline MTTR | Target MTTR | Improvement |
|-------------|---------------|-------------|-------------|
| MF-01..MF-02 | 30 min | 15 min | 50% |
| MF-03..MF-06 | 60 min | 20 min | 67% |
| MF-07..MF-08 | 45 min | 15 min | 67% |
| MF-09..MF-10 | 20 min | 5 min | 75% |

---

## 7. Quality Gates

| Gate ID | Gate | Hard-Fail |
|---------|------|-----------|
| DX-G01 | All failure classes covered | < 8 classes |
| DX-G02 | Diagnostics have remediation | any MF without remediation |
| DX-G03 | Message quality rules followed | any rule violation |
| DX-G04 | Redaction compliance | any credential leak |
| DX-G05 | MTTR targets defined | missing improvement targets |
| DX-G06 | Replay pointers present | any diagnostic without replay |

---

## 8. CI Commands

```
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_conformance_docs cargo test --test tokio_diagnostics_ux_enforcement -- --nocapture
```

---

## 9. Downstream Binding

This contract is a prerequisite for:
- `asupersync-2oh2u.11.9` (T9.9: GA readiness checklist)
- `asupersync-2oh2u.10.9` (T8.9: replacement-readiness gate aggregator)
