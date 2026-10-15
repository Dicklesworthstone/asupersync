# Crash Recovery Validation Contract

Bead: `asupersync-1508v.9.6`

## Purpose

This contract defines soak tests, fault injection points, recovery metrics, and reproducibility requirements for crash-only mode validation. Every recovery failure must be reproducible; unreproducible failures block graduation.

## Contract Artifacts

1. Canonical artifact: `artifacts/crash_recovery_validation_v1.json`
2. Smoke runner: `scripts/run_crash_recovery_validation_smoke.sh`
3. Invariant suite: `tests/crash_recovery_validation_contract.rs`

## Soak Scenarios

| Scenario | Description |
|----------|-------------|
| SOAK-REPEATED-CRASH | 100 crash/recover cycles, check for leaks |
| SOAK-RESTART-STORM | 8 concurrent domain crashes under load |
| SOAK-PARTIAL-RECOVERY | Nested crashes during recovery |
| SOAK-STUCK-CLEANUP | Crash with 50 pending obligations |

## Fault Injection Points

| Point | Expected Behavior |
|-------|-----------------|
| FI-JOURNAL-WRITE | Remain CRASHING, retry or tombstone |
| FI-REPLAY-MID | Re-attempt from last checkpoint |
| FI-HOOK-TIMEOUT | Hook aborted, recovery proceeds |
| FI-AUTHORITY-RESTORE | Authority stays narrow, retry next epoch |
| FI-PARENT-CANCEL | Child tombstoned immediately |

## Recovery Metrics

| Metric | SLO |
|--------|-----|
| RM-MTTR | <= 5000ms |
| RM-REPLAY-SUCCESS-RATE | >= 0.99 |
| RM-OBLIGATION-RECOVERY-RATE | >= 0.95 |
| RM-INVARIANT-PRESERVATION | 1.0 |
| RM-EVIDENCE-COMPLETENESS | 1.0 |

## Reproducibility

- **RR-DETERMINISTIC-REPLAY**: Crash pack + pinned commit = reproducible failure
- **RR-JOURNAL-REPLAY-IDEMPOTENT**: Same journal twice = same state
- **RR-CRASH-PACK-SELF-CONTAINED**: All data needed in the pack
- **RR-UNREPRODUCIBLE-BLOCKS-GRADUATION**: No graduation without reproducibility

## Validation

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa093 cargo test --test crash_recovery_validation_contract -- --nocapture
```

## Cross-References

- `artifacts/crash_recovery_validation_v1.json`
- `artifacts/crash_only_region_semantics_v1.json` -- Crash state machine
- `artifacts/failure_domain_compiler_v1.json` -- Failure domains
- `src/trace/crashpack.rs` -- CrashPack format
