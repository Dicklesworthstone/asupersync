# Error Taxonomy and Diagnostics

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

Source: `docs/error_codes/registry.json` (canonical), `docs/error_codes/ASUP-Exxx.md` per-code pages.

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

## Common Runtime Errors

### "ObligationLeak detected"

**Cause**: Task completed while holding an obligation (permit, ack, lease).

```rust
// WRONG: permit dropped without send/abort
let permit = tx.reserve(cx).await?;
return Outcome::ok(());  // Leak!

// RIGHT: always resolve obligations
let permit = tx.reserve(cx).await?;
permit.send(message);  // Resolved
```

**Policy**: Configurable via `ObligationLeakResponse`:
- `Panic` -- fail fast (good for lab/CI)
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
permit.send(msg);
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
            CancelKind::FailFast => { /* sibling failed */ }
            CancelKind::RaceLost => { /* lost a race */ }
            CancelKind::ParentCancelled => { /* parent region cancelled */ }
            CancelKind::Shutdown => { /* runtime shutdown */ }
            // Also: Deadline, PollQuota, CostBudget (budget exhaustion)
            // and ResourceUnavailable.
        }
    }
    Outcome::Panicked(payload) => { /* task panicked */ }
}
```

HTTP mapping: `Ok -> 200`, `Err -> 4xx/5xx`, `Cancelled -> 499`, `Panicked -> 500`.

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

1. Reproduce under `LabRuntime` with fixed seed
2. Enable trace capture and futurelock detection
3. Check oracle failures (quiescence, obligation leak, loser drain)
4. Use `TaskInspector` for live task state
5. Use `CancellationExplanation` for cancel chain
6. Preserve crashpack and replay artifacts
7. Use evidence ledger for subtle failures
