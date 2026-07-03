# Error Taxonomy and Diagnostics

## Error Types

Source: `src/error.rs`, `src/error/`

### Core Error

```rust
pub struct Error {
    kind: ErrorKind,
    category: ErrorCategory,
    recoverability: Recoverability,
    // ...
}
```

### ErrorKind Variants

| Kind | Meaning |
|------|---------|
| `Cancelled` | Operation cancelled via cancellation protocol |
| `Timeout` | Deadline exceeded |
| `BudgetExhausted` | Poll quota or cost quota exceeded |
| `ObligationLeak` | Permit/ack/lease not resolved before region close |
| `RegionCloseTimeout` | Region stuck waiting for children |
| `FuturelockViolation` | Task holding obligations without poll progress |
| `ChannelClosed` | Sender/receiver dropped |
| `ChannelFull` | Bounded channel at capacity |
| `LockPoisoned` | Panic while holding lock |
| `IoError` | Underlying I/O error |
| `ProtocolError` | Wire protocol violation |
| `ConnectionError` | Connection-level failure |
| `Internal` | Runtime internal error |

### Recoverability

```rust
pub enum Recoverability {
    Recoverable,     // Retry may succeed
    NonRecoverable,  // Retry will not help
    Unknown,         // Caller must decide
}
```

### RecoveryAction

```rust
pub enum RecoveryAction {
    Retry,
    RetryWithBackoff(BackoffHint),
    Abort,
    Escalate,
}
```

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

### "RegionCloseTimeout"

**Cause**: Region stuck waiting for children that won't complete.

```rust
// Fix: add checkpoints in loops
loop {
    cx.checkpoint()?;  // Allows cancellation
    // ... work ...
}
```

### "FuturelockViolation"

**Cause**: Task holding obligations but not making progress.

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
| `RecvError::Disconnected` | All senders dropped |
| `RecvError::Cancelled` | Receive operation cancelled |
| `RecvError::Empty` | No item available (try_recv) |
| `broadcast::RecvError::Lagged(n)` | Broadcast receiver fell behind by n messages |

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

Drain phase: `warmup`, `rapid_drain`, `slow_tail`, `stalled`, `quiescent`. With Freedman/Azuma confidence bounds.

## Debugging Workflow

1. Reproduce under `LabRuntime` with fixed seed
2. Enable trace capture and futurelock detection
3. Check oracle failures (quiescence, obligation leak, loser drain)
4. Use `TaskInspector` for live task state
5. Use `CancellationExplanation` for cancel chain
6. Preserve crashpack and replay artifacts
7. Use evidence ledger for subtle failures
