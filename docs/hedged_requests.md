# Region-owned hedged requests

`Cx::hedge_drained_with` starts a primary attempt and makes a backup eligible
after a delay. Both receive their actual runtime-admitted child context. It is
usable from a normal runtime task without borrowing `RuntimeState`, addressing
the implementation portion of R37b / `asupersync-bi2462.90`.

`Cx::hedge_drained_with_timeout` adds one overall deadline covering admission,
the initial delay and both attempts. Starting the backup does not restart the
timeout. For example, with two owned mutable channel receivers:

```rust,ignore
let result = cx.hedge_drained_with_timeout(
    Duration::from_millis(25), // backup eligibility delay
    Duration::from_secs(2),   // overall result deadline, not cleanup deadline
    move |child| async move { primary.recv(&child).await },
    move |child| async move { backup.recv(&child).await },
).await;
```

Use each supplied `child` for cancellation-aware operations. Capturing a
separate parent context recreates the caller-context cancellation hazard.
Factories and futures must be owned, `Send` and `'static`; they need not share
one concrete future type. Synchronous factory construction also runs inside
the admitted task, so its panic follows normal child-panic handling.

## Selection and cleanup

These APIs select the first terminal attempt, not the first application-level
success. When `T` is a `Result`, an application `Err` is still a completed
value. They are not retry policies, idempotency mechanisms or exactly-once
execution. Both attempts can perform effects; callers must choose operations
that are safe to duplicate.

Selection, cancellation, loser drain and panic precedence reuse the existing
`Scope::race_all` engine. A fast primary cancels the waiting backup without
waiting out the delay. The primary publishes completion itself, so a delayed
owner does not cause a backup to be invoked after completion is observed.
A backup suppressed this way waits for cancellation instead of publishing a
synthetic result that could hide the primary's value or panic.

An overall deadline is checked before invoking either attempt, after an
attempt completes, and immediately before starting a delayed backup. The
backup wait is capped at the overall deadline. A result completed at or after
the deadline is ineligible. Timely results remain eligible even when draining
the loser takes the operation past its deadline.

Ordinary return and timeout return both wait for admitted loser cleanup. A
loser's panic takes precedence over successful selection or timeout. Dropping
the outer future requests cancellation; the owning region remains the
asynchronous cleanup boundary. Uncooperative user code can prevent draining.
Neither the hedge delay nor the overall result deadline bounds cleanup time.

## Capability and resource costs

An untimed hedge admits two region-owned task slots, including the backup's
waiting task. A timed hedge admits three, including its deadline task. The
backup factory is not invoked merely because its task slot was admitted.

A nonzero hedge delay requires the explicit context's timer capability. A
zero-delay untimed hedge does not need time authority. Timed hedges always
require time authority; zero duration refuses before either factory runs.
No ambient clock, detached worker, dependency or public signature replacement
is introduced. The legacy `Scope::hedge` and prebuilt-future timeout APIs are
unchanged.

## Execution status

`tests/hedge_factory_native.rs` contains fourteen regression tests using real
current-thread and multi-worker tasks, including pending channel receives with
live senders, withheld asynchronous cleanup, cancelled timer waits, synchronous
factory panics, cleanup panics, authority refusal and unpolled-owner cases.
These are authored tests, **not passing execution evidence**: Rust/Cargo,
rustfmt and RCH were unavailable in the authoring environment. The bead remains
unclosed pending the required execution and remaining acceptance criteria.

Run on the repository's authorized Rust execution path:

```sh
cargo test -p asupersync --test hedge_factory_native -- --nocapture
cargo test -p asupersync --features proc-macros --test race_factory_native -- --nocapture
cargo test -p asupersync --test runtime_abort_vs_cancel_semantics_audit
```

The existing factory-timeout regressions are important because timed races and
timed hedges now share the same private absolute-deadline engine.
