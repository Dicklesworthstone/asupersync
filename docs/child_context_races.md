# Races whose losing operations receive child cancellation

The context-aware form of `race!` accepts one factory per branch:

```rust,ignore
let result = asupersync::race!(cx, {
    move |child| async move { primary.recv(&child).await },
    move |child| async move { backup.recv(&child).await },
});
```

The factory receives its actual runtime-admitted child `Cx`. Use that context
for every cancel-aware operation in the branch. The winner does not cancel the
parent. Every admitted loser receives the existing race-lost cancellation and
is joined through the existing `Scope::race_all` engine before normal return.
A branch may perform asynchronous cleanup before terminating.

Named branches and `timeout: duration` accept the same factory syntax. All
branches must be factories or all must be prebuilt futures; mixing them emits an
explicit diagnostic. Factories must take exactly one argument. Return types must
agree, and captures/futures must satisfy the existing owned `Send + 'static`
task requirements. To use a function value, wrap it in `move |child| function(child)`.

Without macros, pass `Vec<asupersync::cx::RaceFactory<T>>` to
`cx.race_drained_with`. The corresponding methods are
`race_drained_with_named`, `race_drained_with_timeout` and
`race_drained_with_timeout_named`. They reuse the existing race engine rather
than inventing another winner, panic or child-retirement protocol.

## Migrating the hazardous prebuilt form

A future built as `async move { receiver.recv(&parent_cx).await }` can keep waiting
when its child task loses: cancelling the child does not cancel `parent_cx`.
Replace that branch with `move |child| async move { receiver.recv(&child).await }`.
Capturing a different parent context inside a factory recreates the same bug;
no macro can rewrite capabilities hidden inside application code.

Existing prebuilt-future forms and methods are unchanged for compatibility.
In particular their legacy timeout behavior is not silently changed. This
addition does not claim that arbitrary parent-context futures became cancellable.

## Timeout and resource semantics

Factory timeouts require the explicit context's timer capability and one extra
region-owned task slot. One absolute deadline covers admission and execution.
The deadline branch competes normally; expiry cancels and drains user branches
before returning the timeout error. A value completed at or after the deadline
is ineligible. Timely completion may be returned after loser cleanup finishes.
The timer branch itself observes child cancellation when it loses.

The timeout is not a preemptive cleanup deadline. A noncooperative loser can
keep draining forever. Dropping the outer future requests cancellation, but
synchronous Drop cannot join children; the owning region remains the cleanup
boundary. Synchronous admission refusal cancels and drains the admitted prefix.
Empty input and missing timer authority are explicit refusals, not success.

## Validation scope

`tests/race_factory_native.rs` exercises native current-thread and two-worker
contexts. Channel senders remain alive and never send; the tests witness a real
pending receive, observe its race-lost cancellation, withhold asynchronous
cleanup, and require the race to remain pending until that cleanup is released.
The same controls exercise timeout, loser panic, factory admission and all four
macro forms. Existing prebuilt parser/expansion checks are preserved.

The authoring environment has no Rust/Cargo/rustfmt/RCH toolchain. These are
uncompiled test sources, not passing-test evidence. Required execution includes
the native cancellation baseline, the macro unit tests, and this native target:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-race-factory-validation cargo test -p asupersync --test runtime_abort_vs_cancel_semantics_audit
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-race-factory-validation cargo test -p asupersync-macros
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-race-factory-validation cargo test -p asupersync --features proc-macros --test race_factory_native -- --nocapture
```

This addresses the child-context factory portion of bridge-plan R37. It does
not establish full R37 closure, native/lab panic-path equivalence, or a repaired
`hedge`/legacy timeout surface.

## Heterogeneous blocking selection

The blocking `select!` form also accepts factories, including with `biased`:

```rust,ignore
let result = asupersync::select!(cx, {
    value = move |child| read_number(child) => value.to_string(),
    value = move |child| read_text(child) => value,
});
```

Per-branch input values may have different types; handler outputs still share
one type. As with the existing prebuilt implementation, each handler belongs to
its branch future. It may therefore run when a losing operation completes during
drain. This is not a promise of winner-only handler side effects. Put child-aware
cleanup inside the factory's future and avoid using the parent context there.

Factory lists cannot contain an `else` arm: that form polls inline without child
task ownership, so fabricating a child context would be misleading. Existing
prebuilt `else` selection remains nonblocking, source ordered, and usable with
borrowed/non-Send futures and a context that has no spawn authority.

The native target additionally includes heterogeneous blocking/biased selection,
a non-Send `else` compatibility control, and a real one-hour sleep loser that
must observe cancellation and finish cleanup within the test watchdog. These
remain uncompiled/unexecuted sources until the named Rust validation runs.
