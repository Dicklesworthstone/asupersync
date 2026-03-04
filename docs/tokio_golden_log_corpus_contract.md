# Golden Log Corpus and Schema-Evolution Regression Contract

**Bead**: `asupersync-2oh2u.10.13` ([T8.13])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Date**: 2026-03-04
**Purpose**: establish a deterministic golden corpus of cross-track log entries,
enforce schema versioning and evolution rules, and provide regression tooling
to prevent silent logging drift across replacement tracks.

---

## 1. Scope

This contract governs the golden log corpus maintained under
`tests/fixtures/logging_golden_corpus/` and the schema-evolution regression
tests that validate it.

Prerequisite contracts:
- `asupersync-2oh2u.10.12` (T8.12: cross-track e2e logging enforcement)

---

## 2. Golden Corpus Structure

### 2.1 Manifest

`manifest.json` follows the `logging-golden-manifest-v1` schema:

| Field | Required | Description |
|---|---|---|
| `schema_version` | yes | manifest schema identifier |
| `description` | yes | human-readable corpus description |
| `bead_id` | yes | owning bead |
| `owner` | yes | agent/team owner |
| `created` | yes | ISO-8601 date |
| `update_policy` | yes | review gates and checklist |
| `schema_versions` | yes | map of known log schema versions |
| `fixtures` | yes | array of fixture descriptors |
| `change_log` | yes | array of change entries |

### 2.2 Fixture Files

Each fixture file follows a per-track golden entry format:

| Field | Required | Description |
|---|---|---|
| `fixture_id` | yes | unique fixture identifier |
| `schema_version` | yes | log schema version |
| `track_id` | yes | source track (T2..T7 or cross-track) |
| `description` | yes | human-readable description |
| `entry` | yes | golden log entry conforming to schema |
| `invariants` | yes | list of invariant descriptions |

---

## 3. Schema Evolution Rules

### 3.1 Version Pinning

All golden entries MUST pin their schema version. Known versions:
- `e2e-suite-summary-v3`
- `raptorq-e2e-log-v1`
- `raptorq-unit-log-v1`
- `1.0` (T5 service scripts)
- `quic-h3-forensic-manifest.v1`

### 3.2 Breaking vs Non-Breaking Changes

| Change Type | Classification | Action Required |
|---|---|---|
| Add optional field | non-breaking | update corpus, no version bump |
| Remove required field | BREAKING | version bump + migration note |
| Rename required field | BREAKING | version bump + migration note |
| Change field semantics | BREAKING | version bump + migration note |
| Add new schema version | non-breaking | register in manifest |

### 3.3 Schema Version Drift Detection

Tests MUST detect when a live e2e suite's effective schema version differs
from the golden corpus entry's pinned version.

---

## 4. Update Policy

### 4.1 Review Gates

Every corpus update MUST:
1. Pass the update policy checklist in `manifest.json`
2. Include a `change_log` entry with justification
3. Set `drift_justification_required: true`

### 4.2 Drift Justification

When a golden fixture is updated, the change log MUST include:
- Date and author
- Action (create/update/deprecate)
- Affected fixtures list
- Justification explaining why the change is correct

---

## 5. Quality Gates

| Gate ID | Gate | Hard-Fail Conditions |
|---|---|---|
| `GC-01` | Manifest integrity | manifest missing or unparseable |
| `GC-02` | Fixture file presence | any fixture file referenced but missing |
| `GC-03` | Schema field completeness | golden entry missing required fields |
| `GC-04` | Correlation ID format | correlation_id not matching slug regex |
| `GC-05` | Redaction compliance | golden entry containing forbidden patterns |
| `GC-06` | Schema version consistency | fixture schema_version != manifest entry |
| `GC-07` | Change log integrity | change_log empty or missing required fields |
| `GC-08` | Invariant coverage | fixture missing invariants list |

---

## 6. Required Artifacts

Every T8.13 evaluation run MUST produce or validate:

- `tests/fixtures/logging_golden_corpus/manifest.json`
- Per-track golden fixture files (T2..T7)
- Failure and redaction golden fixtures

---

## 7. CI Commands

```
rch exec -- cargo test --test tokio_golden_log_corpus_enforcement -- --nocapture
```

---

## 8. Downstream Binding

This contract is a prerequisite for:
- `asupersync-2oh2u.11.11` (T9.11: diagnostics and error-message UX)
- `asupersync-2oh2u.11.2` (T9.2: migration cookbooks)
- `asupersync-2oh2u.10.9` (T8.9: replacement-readiness gate aggregator)
