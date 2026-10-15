# T6.13 — End-to-End Data-Path Scripts with Detailed Reliability Logging

**Bead**: `asupersync-2oh2u.6.13`
**Track**: T6 (Database and messaging ecosystem closure)
**Depends on**: T6.12 (exhaustive unit-test matrix)
**Unblocks**: T8.12 (cross-track e2e logging schema), T9.2 (migration cookbooks)
**Status**: Enforced

## Purpose

Validate full-lifecycle data-path workflows across all T6 database and messaging
subsystems through end-to-end scenarios with deterministic seeds, correlation IDs,
structured reliability logging, and fault injection. These tests serve as the
integration proof that individual T6.2-T6.10 contracts compose correctly under
realistic operational conditions.

## Scope

| Domain | Coverage |
|--------|----------|
| Pool lifecycle | Init, acquire, use, return, stats invariants, close, warm-up |
| Retry/backoff | Transient failure recovery, exhaustion, timeout integration, policy builder |
| Fault injection | Connect faults, validation faults, interleaved concurrent faults |
| Error classification | Cross-backend normalization (PG/MySQL/SQLite), messaging variants |
| Messaging data path | Kafka producer→consumer, Redis/NATS/JetStream error variants |
| Reliability logging | Correlation IDs, retry attempt tracking, pool stats snapshots |

## 1. Scenario Matrix

| ID | Title | Category | Domains |
|----|-------|----------|---------|
| DP-01 | Pool lifecycle full path | pool_lifecycle | pool, stats |
| DP-02 | Pool exhaustion backpressure | pool_lifecycle | pool, backpressure |
| DP-03 | Pool retry on transient connect failure | retry | pool, fault_injection |
| DP-04 | Retry exhaustion error propagation | retry | pool, error_propagation |
| DP-05 | Pool close rejection | pool_lifecycle | pool, close |
| DP-06 | Validation failure discard + reconnect | fault_injection | pool, validation |
| DP-07 | Stale eviction | pool_lifecycle | pool, eviction |
| DP-08 | Retry delay formula verification | retry | backoff, policy |
| DP-09 | Concurrent pool with interleaved faults | concurrency | pool, fault_injection |
| DP-10 | Pool warm-up | pool_lifecycle | pool, warm_up |
| DP-11a | PostgreSQL error classification data path | error_classification | postgres |
| DP-11b | MySQL error classification data path | error_classification | mysql |
| DP-11c | SQLite error classification data path | error_classification | sqlite |
| DP-12 | Cross-backend error normalization | error_classification | cross_backend |
| DP-13 | Messaging error variant data path | error_classification | kafka, redis, nats, jetstream |
| DP-14 | Kafka producer→consumer data path | messaging_data_path | kafka |
| DP-15 | Pool stats invariants under load | pool_lifecycle | pool, stats |
| DP-16 | Retry policy builder round-trip | retry | policy |
| DP-17 | Discard no resource leak | pool_lifecycle | pool, discard |
| DP-18 | Retry timeout integration | retry | pool, timeout |
| DP-19 | RetryPolicy::none() produces zero retries | retry | policy |
| DP-20 | Full data path (warm→acquire→fault→retry→recover) | integration | pool, retry, fault_injection |

## 2. Reliability Logging Requirements

### RL-01: Correlation IDs
Every scenario MUST emit `correlation_id` fields in tracing spans with the format
`T6.13:<scenario>:step-<n>` for cross-scenario trace correlation.

### RL-02: Retry Attempt Tracking
Retry scenarios MUST log `attempts` count and `elapsed_ms` for each retry sequence.

### RL-03: Pool Stats Snapshots
Pool lifecycle scenarios MUST log `total`, `idle`, `active`, and
`total_acquisitions` at each state transition.

### RL-04: Error Classification Logging
Error classification scenarios MUST log `is_transient`, `is_retryable`,
`is_connection_error`, and `error_code` for each error variant tested.

### RL-05: Fault Injection Context
Fault injection scenarios MUST log `fail_count`, `connect_calls`, and
`validate_calls` counters at injection and recovery points.

## 3. Runner Script Contract

The shell runner (`scripts/test_t6_data_path_e2e.sh`) MUST:

1. Emit `e2e-suite-summary-v3` schema-compliant `summary.json`.
2. Extract correlation IDs, retry attempts, and pool stats into artifact files.
3. Run with `--features "sqlite,postgres,mysql"` to enable all backend tests.
4. Report failure patterns (panics, assertion failures, resource leaks).
5. Include reproducible `repro_command` with seed and log-level settings.

## 4. Artifact Requirements

### ART-01: Summary JSON
Must contain all `e2e-suite-summary-v3` fields plus T6.13-specific:
- `bead_id`: `"asupersync-2oh2u.6.13"`
- `track`: `"T6"`
- `domains`: array of tested domains
- `correlation_ids_extracted`: count of extracted correlation IDs

### ART-02: Reliability Signal Files
- `correlation_ids.txt`: All correlation IDs from the run
- `retry_attempts.txt`: Retry attempt counts per scenario
- `pool_stats.txt`: Pool stats snapshots
- `error_classifications.txt`: Error classification results
- `seeds.txt`: Deterministic seeds used

## 5. Acceptance Criteria Mapping

| Criterion | Evidence |
|-----------|----------|
| E2E scenarios cover full T6 data-path workflows | DP-01 through DP-20 (20 scenarios) |
| Logs include schema-validated reliability signals | RL-01 through RL-05 |
| Correlation IDs present | RL-01, ART-02 |
| Redaction checks | Runner extracts and validates patterns |
| Replay linkage | Deterministic seeds in ART-02, repro_command in ART-01 |
| Failure drills validate retry/idempotency/rollback | DP-03, DP-04, DP-18, DP-19, DP-20 |
| Artifacts reproducible | seed + repro_command in summary.json |
| Mapped to migration packs | Unblocks T6.11 via T6.12 closure, T9.2 directly |

## 6. Implementation Status

| Category | Scenarios | Status |
|----------|-----------|--------|
| Pool lifecycle (DP-01,02,05,07,10,15,17) | 7 | Enforced |
| Retry/backoff (DP-03,04,08,16,18,19) | 6 | Enforced |
| Fault injection (DP-06,09,20) | 3 | Enforced |
| Error classification (DP-11a,11b,11c,12,13) | 5 | Enforced |
| Messaging data path (DP-14) | 1 | Enforced (feature-gated) |
| Contract/artifact checks | 3 | Enforced |
| **Total** | **25** | |

## 7. Contract Dependencies

```
T6.12 (unit-test matrix) ──────────> T6.13 (THIS: e2e data-path)
                                         ↓
                                     T8.12 (cross-track logging)
                                     T9.2 (migration cookbooks)
```

## References

- `tests/e2e_t6_data_path.rs` — Test implementation
- `scripts/test_t6_data_path_e2e.sh` — Runner script
- `docs/tokio_t6_data_path_e2e_contract.json` — JSON artifact
- `src/database/pool.rs` — Pool lifecycle and `get_with_retry`
- `src/combinator/retry.rs` — RetryPolicy and calculate_delay
- `src/database/postgres.rs` — PostgreSQL error classification
- `src/database/mysql.rs` — MySQL error classification
- `src/database/sqlite.rs` — SQLite error classification
- `src/messaging/redis.rs` — Redis error variants
- `src/messaging/kafka.rs` — Kafka error variants
- `src/messaging/nats.rs` — NATS error variants
- `src/messaging/jetstream.rs` — JetStream error variants
