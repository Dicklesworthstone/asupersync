# Crash-Only Region Semantics Contract

Bead: `asupersync-1508v.9.4`

## Purpose

This contract defines crash-only execution semantics for supervised regions: explicit state machines for crash and recovery, a deterministic journal format for replay, and a microreboot protocol that interacts cleanly with structured cancellation and obligation settlement.

## Contract Artifacts

1. Canonical artifact: `artifacts/crash_only_region_semantics_v1.json`
2. Smoke runner: `scripts/run_crash_only_region_smoke.sh`
3. Invariant suite: `tests/crash_only_region_contract.rs`

## Crash State Machine

Regions follow a strict state machine: RUNNING -> DRAINING or CRASHING -> JOURNALED -> RECOVERING or TOMBSTONED.

| State | Description |
|-------|------------|
| RUNNING | Actively executing tasks and settling obligations |
| DRAINING | Graceful shutdown: no new tasks, existing run to completion |
| CRASHING | Unrecoverable fault detected, journal checkpoint being written |
| JOURNALED | Crash journal is durable, state frozen for replay |
| RECOVERING | Microreboot in progress, replaying journal |
| QUIESCED | Graceful drain complete, all obligations settled |
| TOMBSTONED | Terminal: resources released, no revival |

### State Machine Invariants

- **CSM-NO-SKIP**: No transition may skip intermediate states
- **CSM-TOMBSTONE-TERMINAL**: TOMBSTONED is absorbing
- **CSM-CRASH-ALWAYS-JOURNALS**: CRASHING must reach JOURNALED before any other state
- **CSM-RECOVER-NEEDS-JOURNAL**: RECOVERING requires a valid JOURNALED predecessor

## Journal Format

Journals are deterministic, sequenced logs sufficient for crash recovery.

### Entry Types

| Entry | Purpose |
|-------|---------|
| JE-REGION-OPEN | Region opened with configuration |
| JE-TASK-SPAWN | Task spawned in region |
| JE-OBLIGATION-ENTER | Obligation entered |
| JE-OBLIGATION-SETTLE | Obligation settled (fulfilled or abandoned) |
| JE-DECISION-APPLIED | Controller decision applied |
| JE-CHECKPOINT | Periodic state checkpoint for truncation |
| JE-CRASH-MARKER | Crash event at point of failure |
| JE-RECOVERY-COMPLETE | Recovery replay finished |

### Ordering Rules

- **JO-MONOTONIC-SEQ**: Sequence numbers strictly increasing within a region
- **JO-EPOCH-MONOTONIC**: Epoch values non-decreasing
- **JO-OPEN-BEFORE-SPAWN**: Region open precedes task spawn
- **JO-ENTER-BEFORE-SETTLE**: Obligation enter precedes settle
- **JO-CHECKPOINT-TRUNCATABLE**: Pre-checkpoint entries may be truncated

## Microreboot Protocol

Four-phase protocol for restarting a crashed region without full runtime restart:

1. **MR-ISOLATE**: Fence the crashed region, cancel in-flight I/O
2. **MR-REPLAY**: Replay journal from last checkpoint
3. **MR-RECONCILE**: Re-enter pending obligations, abandon unrecoverable ones
4. **MR-RESUME**: Transition to RUNNING, re-register with scheduler

### Budget Constraints

- Max replay entries: 10,000
- Max recovery wall clock: 5,000ms
- Max consecutive microreboots: 3
- Exponential backoff: 100ms base, 2x multiplier, 10s cap

## Cancellation Interaction

- **CR-CANCEL-FENCE**: Cancel signals suppressed during microreboot until MR-RESUME
- **CR-PARENT-PROPAGATE**: Parent cancel during recovery aborts to TOMBSTONED
- **CR-CHILD-ABANDON**: Child regions of crashed region receive immediate cancellation

## Supervision Mapping

| Strategy | Crash-Only Behavior |
|----------|-------------------|
| Stop | CRASHING -> JOURNALED -> TOMBSTONED |
| Restart | CRASHING -> JOURNALED -> RECOVERING -> RUNNING |
| Escalate | CRASHING -> JOURNALED -> TOMBSTONED + parent notification |

## Validation

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_crash_only_region cargo test -p asupersync --test crash_only_region_contract --features test-internals -- --nocapture
```

## Cross-References

- `artifacts/crash_only_region_semantics_v1.json`
- `src/supervision.rs` -- SupervisionStrategy, RestartConfig
- `src/runtime/kernel.rs` -- RecoveryCommand, ControllerRegistry
- `src/trace/crashpack.rs` -- CrashPack deterministic repro format
- `src/signal/shutdown.rs` -- ShutdownController
