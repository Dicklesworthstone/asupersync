# Cross-Track E2E Logging Schema, Redaction, and Log-Quality Gate Contract

**Bead**: `asupersync-2oh2u.10.12` ([T8.12])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Date**: 2026-03-04
**Purpose**: enforce shared e2e logging contracts (schema versioning, correlation IDs,
redaction policy, log-quality scoring) across all Tokio-replacement tracks as hard CI
gates for replacement-track closure.

---

## 1. Scope

This contract governs e2e logging quality policy for the following prerequisite
e2e test suites:

- `asupersync-2oh2u.2.10` (Async I/O protocol e2e with structured logging)
- `asupersync-2oh2u.5.12` (web/gRPC e2e service scripts)
- `asupersync-2oh2u.7.11` (interoperability e2e with compatibility logs)

Additionally, the following track-adjacent e2e suites are scanned:

- `tests/tokio_quic_h3_e2e_scenario_manifest.rs` (T4 QUIC/H3 e2e)
- `tests/e2e_t6_data_path.rs` (T6 database/messaging data-path)
- `tests/tokio_fs_process_signal_e2e.rs` (T3 fs/process/signal e2e)

---

## 2. Shared E2E Log Schema Contract

Every cross-track e2e suite MUST emit structured log entries conforming to:

| Field | Required | Description |
|---|---|---|
| `schema_version` | yes | versioned schema identifier |
| `scenario_id` | yes | deterministic scenario identifier |
| `correlation_id` | yes | unique per-request correlation token |
| `phase` | yes | execution phase (setup, execute, verify, teardown) |
| `outcome` | yes | result (pass, fail, skip, error) |
| `detail` | yes | human-readable description |
| `replay_pointer` | yes | deterministic rerun command |

### 2.1 Schema Version Pinning

All suites MUST pin schema versions. Known schema versions:

- `e2e-suite-summary-v3` (orchestrator summaries)
- `raptorq-e2e-log-v1` (RaptorQ e2e entries)
- `1.0` (T5.12 service scripts)

### 2.2 Correlation ID Format

Correlation IDs MUST follow slug format: `[a-zA-Z0-9._:-]+`

---

## 3. Redaction Policy

### 3.1 Redaction Modes

| Mode | Behavior |
|---|---|
| `strict` | redact all PII, credentials, tokens |
| `metadata_only` | redact PII but preserve structural metadata |
| `none` | FORBIDDEN in CI — fail closed |

### 3.2 Redaction Patterns

E2E suites MUST NOT emit:

- Bearer tokens in log output
- Raw passwords or secrets
- PII (email, phone, SSN patterns)
- Internal IP addresses in production contexts

### 3.3 CI Enforcement

`ARTIFACT_REDACTION_MODE=none` MUST fail the CI gate.

---

## 4. Log-Quality Scoring

### 4.1 Quality Gates

| Gate ID | Gate | Hard-Fail Conditions |
|---|---|---|
| `LQ-01` | Schema conformance | any e2e suite missing required schema fields |
| `LQ-02` | Correlation ID presence | any e2e entry without correlation_id |
| `LQ-03` | Replay pointer validity | any entry with empty or non-actionable replay_pointer |
| `LQ-04` | Redaction compliance | any suite emitting `ARTIFACT_REDACTION_MODE=none` |
| `LQ-05` | Phase coverage | any suite missing setup/execute/verify phases |
| `LQ-06` | Deterministic outcomes | non-reproducible results across identical seeds |

### 4.2 Quality Score Threshold

`LOG_QUALITY_MIN_SCORE` >= 80 (out of 100).

Scoring components:
- Schema completeness (25 points)
- Correlation coverage (25 points)
- Redaction compliance (25 points)
- Replay actionability (25 points)

---

## 5. Required Artifacts

Every T8.12 evaluation run MUST emit:

- `tokio_e2e_logging_manifest.json`
- `tokio_e2e_logging_report.md`
- `tokio_e2e_redaction_audit.json`
- `tokio_e2e_logging_triage_pointers.txt`

---

## 6. Manifest Schema

Each e2e suite entry in `tokio_e2e_logging_manifest.json`:

| Field | Required | Description |
|---|---|---|
| `suite_id` | yes | e2e test file identifier |
| `track_id` | yes | source track (T2..T7) |
| `bead_id` | yes | owning bead |
| `schema_version` | yes | log schema version |
| `correlation_ids_present` | yes | boolean |
| `replay_pointers_present` | yes | boolean |
| `redaction_mode` | yes | strict/metadata_only |
| `quality_score` | yes | 0..100 |
| `gate_results` | yes | LQ-01..LQ-06 pass/fail |

---

## 7. Failure Routing

Failures MUST include:

- `gate_id` (LQ-01..LQ-06)
- `suite_id`
- `track_id`
- `severity`
- `repro_command`

---

## 8. CI Commands

Required command tokens:

- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_conformance_docs cargo test --test tokio_cross_track_e2e_logging_enforcement -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_conformance_docs cargo test --test e2e_log_quality_schema -- --nocapture`

---

## 9. Downstream Binding

This contract is a blocker for:

- `asupersync-2oh2u.10.13` (final cross-track integration attestation)
- `asupersync-2oh2u.10.9` (final replacement-readiness aggregator)
