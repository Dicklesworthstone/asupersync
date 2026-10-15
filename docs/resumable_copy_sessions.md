# Resumable in-process copy sessions

`io::CopySession` and `io::BidirectionalCopySession` keep read-ahead, accepted-write
counters, EOF, flush, and half-close state in a caller-owned object. Their `run`
futures borrow that object. Dropping a borrowing future does not drop its bytes.
This supplies an additive alternative to the private-read-ahead cancellation
boundary of `copy`, `copy_with_progress`, and `copy_bidirectional`. Those existing
APIs and their published behavior are unchanged. `copy_buf` remains appropriate
when the caller already owns an `AsyncBufRead` buffer.

## One-way transfer

```rust,ignore
use asupersync::io::CopySession;

// reader and writer are existing, explicitly supplied AsyncRead/AsyncWrite owners.
let mut transfer = CopySession::with_capacity(reader, writer, 16 * 1024)?;
let total_written = transfer.run(&cx).await?;
assert!(transfer.is_complete());
assert_eq!(transfer.progress().written, total_written);
let (reader, writer, pending) = transfer.into_parts();
assert!(pending.is_empty());
```

A run returns cumulative bytes accepted by the writer, including previous runs.
One-way completion requires actual source EOF and a successful final flush; it
never implicitly calls `poll_shutdown`. Repeating a completed run returns the
same counters without polling an endpoint, even after later context cancellation.

The endpoints can also be mutable references, and need not be `Clone`, `Sync`, or
`'static`. A run is `Send` when its retained endpoints are `Send`. There is no
spawned task, hidden executor, or background cleanup.

## Pausing without skipping or duplicating data

Retain the session outside the future that can be cancelled or dropped. Dropping
`transfer.run(&cx)` releases the exclusive borrow and its cancellation wake
registration. The transfer's buffer, cursors, counters and endpoints remain.
Call `run` again on that same session to resume. Do not construct a new session
around the advanced source and discard the old buffer.

Cooperative cancellation returns `io::ErrorKind::Interrupted` without forcing an
additional write or silently clearing pending bytes. Use a live context for a
subsequent run. The explicit context controls copy cancellation; endpoint
implementations retain their own runtime and capability requirements. An active
run owns a cancellation registration, so aborting a genuinely parked native task
does not require another source or destination I/O event.

Ordinary I/O errors are preserved, not automatically retried or rewritten as
success. Pending bytes and known progress remain available. The caller must
check whether its endpoint protocol permits continuation; an error kind alone
is not evidence of safe reconnect or replay. Reported writes measure acceptance
by `AsyncWrite`, not peer acknowledgement, fsync, application commit, or exactly-once
external effects. A broken provider that commits bytes without reporting its
progress cannot be made resumable by this wrapper.

For known completed I/O operations, each direction maintains:

```
read - written == buffered
```

`pending_bytes()` borrows the unwritten one-way suffix. `into_parts()` returns
`(reader, writer, pending)`, not just the endpoints: the source has already
advanced past those bytes. To continue manually, send the suffix before reading
more. Dropping the session itself still discards its buffer. This is not crash
recovery, durable checkpointing, source rewind, or network reconnection.

## Duplex forwarding and half-close

```rust,ignore
use asupersync::io::BidirectionalCopySession;

let mut tunnel = BidirectionalCopySession::with_capacities(a, b, 8192, 8192)?;
let (a_to_b, b_to_a) = tunnel.run(&cx).await?;
assert!(tunnel.is_complete());
assert!(tunnel.progress().a_to_b.write_shutdown);
assert!(tunnel.progress().b_to_a.write_shutdown);
```

The engine interleaves both directions; a pending A-to-B write does not suppress
B-to-A reads, writes, or close progress. EOF from A first drains A-to-B read-ahead,
flushes B, and shuts down B's write direction. It continues forwarding B-to-A,
including responses produced only after the peer sees that half-close. Providers
must support independent write-side shutdown for this pattern.

Both EOF and successful write-side shutdown are retained across dropped runs,
cancellation, flush errors, and interrupted shutdowns. A successful half-close
is not repeated when another run resumes. Completion requires both directions;
raw temporary `Pending` is never EOF. Duplex extraction returns
`(a, b, pending_a_to_b, pending_b_to_a)` without rolling back existing half-closes.

## Resource and failure boundaries

Default read-ahead is 8 KiB for one-way copying and 8 KiB per duplex direction.
Explicit capacities must be positive; fallible allocation happens before I/O.
These are buffer bounds, not bounds on endpoint-owned buffering, allocations,
kernel socket queues or caller-retained objects. Per-poll transfer steps are
bounded and yield cooperatively. Time spent inside an arbitrary blocking poll,
callback, or destructor is outside that bound.

Provider panics propagate unchanged and leave a sticky poisoned state. Impossible
write counts also poison the state. Subsequent runs refuse before retrying the
ambiguous operation. Duplex poison fences *both* directions because they share
endpoints. Known buffered bytes remain inspectable; their presence does not
establish what an unwinding provider committed externally. Progress Debug output
contains counts and states, not endpoint Debug or copied payloads.

## Validation targets and current evidence

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib io::copy_session::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --test copy_session_native
```

The 21 unit tests include a 465-case one-way interruption/error matrix and a
168-case pair-of-duplex-offsets matrix, plus explicit poison, half-close,
backpressure, wake cleanup, counter-boundary and extraction regressions. A
negative control exercises the legacy copy future with the same stalled-write
sequence, demonstrating why restarting without retained read-ahead is insufficient. Four
native tests use real loopback TCP endpoints and current-thread/two-worker
runtimes. A controlled write gate witnesses the actual copy's `Pending` before
aborting its task. The task must return the retained session after acknowledging
cancellation, and the same session resumes with a live context to produce exact
peer-visible bytes and completed half-closes. Gate fixtures are controlled
backpressure, not a claim to simulate TCP or replace the native networking path.

These tests were authored but **not compiled or executed** in the authoring
environment: it had no Rust compiler, Cargo, rustfmt or RCH. Source review,
lexical delimiter checks and Git blob comparisons do not establish native
behavior, formatting, performance, or release readiness. Run the authorized
RCH lanes, including the existing native cancellation contract, before release.
