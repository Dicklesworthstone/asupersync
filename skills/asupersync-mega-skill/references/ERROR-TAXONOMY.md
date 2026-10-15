# Error Taxonomy and Diagnostics

## Table of Contents

- [Error Types](#error-types)
- [ASUP-Exxx Error-Code Registry](#asup-exxx-error-code-registry)
- [SQLite Diagnosed Errors](#sqlite-diagnosed-errors)
- [Common Runtime Errors](#common-runtime-errors)
- [Outcome Handling](#outcome-handling)
- [Diagnostics Surfaces](#diagnostics-surfaces)
- [Debugging Workflow](#debugging-workflow)

## Error Types

Source: `src/error.rs`, `src/error/`

### Core Error

```rust
pub struct Error {
    kind: ErrorKind,
    message: Option<String>,
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
    context: ErrorContext,
}
```

Category and recoverability are derived from the kind: `kind.category()`,
`kind.recoverability()`, `kind.recovery_action()`, `kind.asup_code()`.

### ErrorKind Variants (grouped, selected)

| Group | Kinds |
|-------|-------|
| Cancellation | `Cancelled`, `CancelTimeout` (cleanup budget exceeded) |
| Budgets | `DeadlineExceeded`, `PollQuotaExhausted`, `CostQuotaExhausted` |
| Channels | `ChannelClosed`, `ChannelFull`, `ChannelEmpty` |
| Obligations | `ObligationLeak`, `ObligationAlreadyResolved`, `RegionFinalized` |
| Regions / ownership | `RegionClosed`, `TaskNotOwned`, `AdmissionDenied` |
| RaptorQ enc/dec | `InvalidEncodingParams`, `DataTooLarge`, `EncodingFailed`, `CorruptedSymbol`, `InsufficientSymbols`, `DecodingFailed`, ... |
| Transport | `RoutingFailed`, `DispatchFailed`, `StreamEnded`, `SinkRejected`, `ConnectionLost`, `ConnectionRefused`, `ProtocolError`, `RateLimited`, `InvalidInput`, `OperationFailed` |
| Distributed | `RecoveryFailed`, `LeaseExpired`, `LeaseRenewalFailed`, `CoordinationFailed`, `QuorumNotReached`, `NodeUnavailable`, `PartitionDetected` |
| Internal / config / user | `Internal`, `InvalidStateTransition`, `ConfigError`, `User` |

`ErrorCategory` mirrors these groups (`Cancellation`, `Budget`, `Channel`,
`Obligation`, `Region`, `Encoding`, `Decoding`, `Transport`, `Distributed`,
`Internal`, `User`).

### Recoverability

```rust
pub enum Recoverability {
    Transient,   // Temporary; retry may succeed
    Permanent,   // Retry will not help
    Unknown,     // Depends on context; caller must decide
}
```

### RecoveryAction

```rust
pub enum RecoveryAction {
    RetryImmediately,
    RetryWithBackoff(BackoffHint),
    RetryWithNewConnection,
    Propagate,
    Escalate,
    Custom,
}
```

## ASUP-Exxx Error-Code Registry

Source: `docs/error_codes/registry.json` (canonical), plus per-code pages such
as `docs/error_codes/ASUP-E001.md`.

Stable user-facing error tokens in the `ASUP-Exxx` namespace; `ErrorKind::asup_code()`
maps kinds to codes (e.g. `ObligationLeak -> ASUP-E101`, `CancelTimeout -> ASUP-E301`,
`ConfigError -> ASUP-E901`). Ranges by area:

| Range | Area |
|-------|------|
| E0xx | core-runtime (spawn, admission, availability, budgets) |
| E1xx | obligations (permit/ack/lease lifecycle, leaks) |
| E2xx | channels-sync |
| E3xx | cancellation-drain (E301 cancel-drain-timeout, E302 race-loser-not-drained, E303 finalizer-timeout) |
| E4xx | lab-replay (E401 replay-divergence, E402 futurelock-detected, E403 lab-seed-nondeterminism, E404 snapshot-artifact-invalid) |
| E5xx | net-http |
| E6xx | database |
| E7xx | distributed-remote |
| E8xx | raptorq |
| E9xx | config-build |

Each registry entry carries name, summary, probable causes, and remediation;
treat the registry as the source of truth for the current code list.

### ASUP-E004: local scheduler unavailable

`Cx::spawn_local` needs the thread-local lane of an active scheduler worker and
that lane must belong to the same runtime as the `Cx`. Ambient context alone is
insufficient. A direct `Runtime::block_on`, `#[asupersync::main]` /
`#[asupersync::test]` body, `run_test`, or `run_test_with_cx` can therefore
return `SpawnError::LocalSchedulerUnavailable`.

For a real `!Send` local-task test, enter a worker through
`runtime.block_on(runtime.handle().spawn(async { ... }))`, fetch `Cx::current()`
inside it, acquire the non-Send state inside the local future, then call
`spawn_local`. A foreign-runtime local lane must fail closed rather than accept
or reroute the task.

## SQLite Diagnosed Errors

Source: `src/database/sqlite.rs` behind the `sqlite` feature.

The additive v0.4.9 `SqliteOperationError` family is distinct from the core
`ASUP-Exxx` registry. Call a separately named `*_diagnosed` API when an operator
needs stable operation, category, retry disposition, and SQLite primary or
extended codes. Match the non-exhaustive `SqliteOperation` /
`SqliteErrorCategory` / `SqliteRetryDisposition` enums with a wildcard arm.

Established methods continue returning `SqliteError`. Structured cancellation
remains `Outcome::Cancelled`, not a retryable database error. Ordinary `Debug`,
`Display`, and `Error::source` traversal intentionally omit raw SQL, bound
values, paths, and engine prose; `legacy_error()`, `into_legacy()`, and
`engine_source()` are explicit disclosure boundaries.

## Common Runtime Errors

### "ObligationLeak detected"

**Cause**: A runtime-tracked obligation (permit, ack, lease, or guard) remained
pending when its owner completed or its region finalized.

```rust
// Commit the reserved channel effect.
let permit = tx.reserve(cx).await?;
permit.try_send(message)?; // or match send(message)'s Outcome to recover the value

// Or abandon it explicitly.
let permit = tx.reserve(cx).await?;
permit.abort();
```

An MPSC `SendPermit` also aborts its slot on `Drop`; dropping that guard is
cancel-safe and is not, by itself, an `ObligationLeak`. Diagnose ASUP-E101 from
the runtime's obligation record and owner evidence rather than inferring a leak
from every dropped reservation-shaped value.

**Policy**: Configurable via `ObligationLeakResponse`:
- `Panic` -- shipped default; fail fast with diagnostics
- `Log` -- practical production starting point
- `Recover` -- abort the leaked path, continue
- `Silent` -- rare, intentional only

Threshold-based escalation: `LeakEscalation` in runtime config.

If a leak is detected during thread unwinding, `Panic` downgrades to `Log` to avoid double-panic aborts.

### Cancel drain timeout (`CancelTimeout` / ASUP-E301)

**Cause**: Cancellation was requested but drain did not complete within budget --
typically a region stuck waiting for children that won't complete.

```rust
// Fix: add checkpoints in loops
loop {
    cx.checkpoint()?;  // Allows cancellation
    // ... work ...
}
```

### Futurelock detected (ASUP-E402)

**Cause**: Task holding obligations but not making progress. Surfaces as
`InvariantViolation::Futurelock` in lab reports and
`TraceEventKind::FuturelockDetected` in traces (there is no
`FuturelockViolation` error kind).

```rust
// WRONG: await while holding permit
let permit = tx.reserve(cx).await?;
other_thing.await;  // If blocks forever -> futurelock
permit.send(msg);

// RIGHT: minimize hold duration
let msg = other_thing.await;
let permit = tx.reserve(cx).await?;
permit.try_send(msg)?; // or handle send(msg)'s Outcome explicitly
```

### Deterministic Test Drift

**Symptom**: Same seed produces different results.

**Check for**:
- `std::time::Instant::now()` (use `cx.now()`)
- `rand::random()` (use `cx.random_u64()`)
- `HashMap/HashSet` (use `DetHashMap/DetHashSet`)
- Non-deterministic I/O (use `VirtualTcp`)

### Channel Errors

| Error | Cause |
|-------|-------|
| `SendError::Disconnected(value)` | All receivers dropped |
| `SendError::Cancelled(value)` | Send operation cancelled |
| `SendError::Full(value)` | Bounded channel at capacity (try_send) |
| `RecvError::Disconnected` | All senders dropped (mpsc) |
| `RecvError::Cancelled` | Receive operation cancelled |
| `RecvError::Empty` | No item available (try_recv) |
| `broadcast::RecvError::Lagged(n)` | Broadcast receiver fell behind by n messages |
| `broadcast::RecvError::Closed` | All broadcast senders dropped (broadcast/watch use `Closed`, not `Disconnected`) |

## Outcome Handling

```rust
match outcome {
    Outcome::Ok(val) => { /* success */ }
    Outcome::Err(e) => { /* application error */ }
    Outcome::Cancelled(reason) => {
        // Structured: reason.kind tells you why
        match reason.kind {
            CancelKind::User => { /* explicit cancel */ }
            CancelKind::Timeout => { /* deadline exceeded */ }
            CancelKind::Deadline => { /* deadline budget exhausted */ }
            CancelKind::PollQuota => { /* poll quota exhausted */ }
            CancelKind::CostBudget => { /* cost budget exhausted */ }
            CancelKind::FailFast => { /* sibling failed */ }
            CancelKind::RaceLost => { /* lost a race */ }
            CancelKind::ParentCancelled => { /* parent region cancelled */ }
            CancelKind::ResourceUnavailable => { /* required resource unavailable */ }
            CancelKind::Shutdown => { /* runtime shutdown */ }
            CancelKind::LinkedExit => { /* linked task exited abnormally */ }
        }
    }
    Outcome::Panicked(payload) => { /* task panicked */ }
}
```

One possible HTTP-edge policy is `Ok -> 200`, domain `Err -> 4xx/5xx`,
`Cancelled -> 499`, and `Panicked -> 500`. That is application policy, not a
universal mapping performed by `Outcome` itself.

## Diagnostics Surfaces

### TaskInspector

Source: `src/observability/task_inspector.rs`

Introspects live task state: blocked reasons, obligation holdings, budget usage, cancellation status.

### CancellationExplanation

Source: `src/observability/diagnostics.rs`

Traces full cancel propagation chain: who requested cancellation, why, and what was affected.

### TaskBlockedExplanation

Identifies what a task is waiting on: lock, channel receive, semaphore, another task, etc.

### ObligationLeak Diagnostics

Pinpoints which obligation was not resolved, who held it, and when.

### Spectral Health Monitor

Source: `src/observability/spectral_health.rs`

Early-warning severity model over live wait graph: `none / watch / warning / critical`.

### Progress Certificates

Source: `src/cancel/progress_certificate.rs`

Drain phase: `warmup`, `rapid_drain`, `slow_tail`, `stalled`, `quiescent`, plus conditional range-bounded Freedman/Azuma calculations. Under the implemented range-only cap, raw Freedman is never tighter and the selected envelope equals Azuma. The same-history plug-in makes both current-horizon tails the trivial bound `1`. The separate `converging` flag is an accepted-history empirical status guarded by stall, rebound count and magnitude, latest-step, and dropped-sample checks; it is not a tail-gated probability or termination guarantee. Non-finite or materially negative telemetry is dropped, which also suppresses the remaining-step estimate and terminal phase. Gross credit is diagnostic bookkeeping, not probability evidence.

## Debugging Workflow

1. Reproduce in the consumer's execution class. Scheduler, wakeup, parked-I/O,
   local-task, shutdown, and cancellation-delivery defects require a native
   runtime reproducer; Lab-only evidence is insufficient.
2. Add a fixed-seed `LabRuntime` model when deterministic exploration applies.
3. Enable trace capture and futurelock detection.
4. Check oracle failures (quiescence, obligation leak, loser drain).
5. Use `TaskInspector` for live task state.
6. Use `CancellationExplanation` for the cancel chain.
7. Preserve crashpack/replay artifacts and old-red/new-green evidence.
8. Use the evidence ledger for subtle failures.
