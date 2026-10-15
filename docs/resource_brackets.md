# Runtime-owned resource brackets

`Cx::spawn_bracket` implements acquire → use → subtree drain → asynchronous
release. It addresses the existing `combinator::bracket` drop path's inability to
wait for external readiness: that legacy path polls release with a noop waker
and a bounded spin loop. The legacy API is unchanged. This API admits a real
controller task before acquisition and keeps cleanup on the runtime.

## Public use

Types live in `asupersync::cx::resource_bracket`. Inside a registered task, use
the runtime-supplied `Cx`; do not construct a replacement runtime or detached
context. For example, this connection's shutdown is part of its bracket:

```rust,ignore
use asupersync::cx::{Cx, resource_bracket::{BracketConfig, BracketUseFuture}};
use asupersync::io::AsyncWriteExt;
use asupersync::net::TcpStream;
use asupersync::types::Outcome;
use std::{io, net::SocketAddr};

async fn send_request(cx: &Cx, address: SocketAddr) {
    let mut handle = cx.spawn_bracket(
        BracketConfig::new(128),
        move |_acquire_cx| async move {
            match TcpStream::connect(address).await {
                Ok(stream) => Outcome::Ok(stream),
                Err(error) => Outcome::Err(error),
            }
        },
        |_use_cx, stream: &mut TcpStream| -> BracketUseFuture<'_, (), io::Error> {
            Box::pin(async move {
                match stream.write_all(b"request\n").await {
                    Ok(()) => Outcome::Ok(()),
                    Err(error) => Outcome::Err(error),
                }
            })
        },
        |_release_cx, mut stream: TcpStream| async move {
            match stream.shutdown().await {
                Ok(()) => Outcome::Ok(()),
                Err(error) => Outcome::Err(error),
            }
        },
    ).expect("controller admission");
    let report = handle.join().await.expect("controller supplied its report");
    // A successful join is not successful use or successful cleanup.
    assert!(report.is_success(), "{report:?}");
}
```

Acquire and use share the application error type. Release can use a different
error type. The resource and all output/error types require `Send`, not `Clone`
or `Sync`. Use only borrows `&mut R`; it cannot consume the resource accidentally
or return a reference tied to that borrow. It may deliberately mutate or replace
resource contents, for which the application remains responsible.

## Ownership and ordering

Acquisition and use execute in the same newly admitted child region. Their Cx
carries the actual task identity, region, driver capabilities and met budget.
Tasks and nested regions created through that context remain in this subtree.
After the body joins, the controller closes the subtree and waits for descendants
and registered finalizers before passing the resource to release. Even a failed
finalizer is recorded independently and does not suppress release once the
region is quiescent. A descendant failure prevents `is_success()` from returning
true even when acquisition, use and release all returned success.

Release runs on the controller, outside the subtree it drains. It must await any
cleanup work it starts. Work initiated through independently captured capabilities
is outside the bracket; the API cannot account for arbitrary external effects.

The implementation never invokes a user callback or polls a user future while
holding its resource/report mutex. A return guard restores the resource to the
controller's slot if the body future is retired unexpectedly. Factory/poll panics
and future-retirement panics are captured separately. In particular, a resource
returned by acquire is preserved even if that acquire future's destructor panics;
use is then skipped and release is still attempted after drain.

## Cancellation and finite masking

`handle.abort()` requests controller cancellation. The controller acknowledges
it and requests cancellation of the entire use subtree, then continues joining,
closing and releasing. Dropping the handle requests the same protocol without
synchronously polling cleanup. The enclosing region's barrier is required when
the handle is dropped and no final report can be joined.

Dropping a borrowing `handle.join()` future does not request cancellation and
does not discard a completed report. A later join resumes observation. Terminal
report publication is independent of the cancelled context's send operations.

`release_masked_polls` bounds how many release polls call `Cx::masked`. After the
allowance, the same release future continues unmasked, so cancel-aware operations
can return their cancellation outcome. Exhaustion never silently drops release.
With a nonzero allowance, release construction and future retirement are also
masked. Masking does not hide raw `is_cancel_requested`/`cancelled` observation,
relax effect capabilities, or make blocking callbacks preemptible.

This allowance is not a deadline. Returning polls, eventual wakes, descendant
termination, settled obligations and progressing finalizers/cleanup are still
required. Runtime hard-abort, runtime destruction and process exit can prevent
release. An acquisition that fails or panics without returning a resource must
clean up its own partial acquisitions. Resources already captured by factories
before controller admission retain that caller-side ownership responsibility.

## Interpreting the report

`BracketReport` retains acquisition, use, body-task terminal, region closure,
release, controller-task terminal, observed cancellation and infrastructure errors.
`BracketPhase` preserves a returned typed outcome alongside any future-destructor
panic. Cleanup failure never replaces the original work outcome. Reading only
`join().is_ok()` or only `usage.outcome` is insufficient.

If region close refuses, release is not invoked: quiescence was not established.
`unreleased` returns the retained resource so its owner can establish a safe
cleanup boundary. It is not an automatic retry, and dropping that report drops
the resource without asynchronous cleanup. Successful release may itself be
non-durable; this API adds no remote acknowledgement, rollback atomicity,
reconnection, persistence, general finalizer registration or exactly-once claim.

## Validation targets and evidence boundary

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_resource_brackets cargo test -p asupersync --lib cx::resource_bracket::
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_resource_brackets cargo test -p asupersync --test resource_bracket_native
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_native_parked_task_cancellation cargo test -p asupersync --locked --test runtime_abort_vs_cancel_semantics_audit -- --nocapture
```

The original single-resource coverage includes fifteen unit/lab tests and four native tests. Lab
coverage includes actual nested-region finalizers gated at Pending, successful
and failing finalizers, non-Clone/Send-only resources, late acquisition after
cancellation, phase-retirement panics, dual errors and finite masking. The legacy
inline bracket is retained as a negative control for externally-woken cleanup.

Native tests use real TCP and current-thread/two-worker runtimes. They witness
use parking before cancellation or handle drop, then witness an actual socket
read returning Pending during release. Only then may the peer acknowledge the
release message. The tests require exactly the expected bytes, resumed join
observations and an enclosing-region barrier. Their watchdog is a test bound,
not a bracket termination guarantee.

These tests were authored but NOT compiled or executed in the authoring session:
Rust, Cargo, rustfmt and RCH were unavailable. Source review, lexical delimiter
checks and Git blob comparisons are not native behavioral proof. Run the
repository-authorized RCH lanes before relying on this code in production.

## Multiple resources and failed startup

`Cx::spawn_resource_scope(config, capacity, work)` reuses the same controller for
multi-step acquisition and resource use. Types live under
`asupersync::cx::resource_bracket::stack`. The controller owns an initially empty
`ResourceStack<C>` BEFORE calling work. Work receives a `ResourceScope<'_, C>`:
it can reserve, register, and borrow heterogeneous resources, but cannot close,
extract, or replace the stack itself. Dropping the facade does not drop resources.

Every resource and release factory is owned together. `ResourceKey<T>` is typed
and specific to its stack; it does not clone or keep T alive. A key from another
stack never aliases a same-numbered slot. There is no ownership-extraction API.
As with any mutable reference, deliberately replacing T through `get_mut` changes
what release owns; cleanup of the extracted original is then the caller's job.

After work returns an error, acknowledges cancellation, or panics, the bracket
still joins its body and drains its child region. Only then does it close the
stack. Cleanup is sequential, last-registered first: dependent newer resources
finish releasing before older resources start. A release error, cancellation,
factory panic, poll panic, or future-destructor panic is recorded without skipping
older entries. All cleanup errors share the chosen type C, which may itself be an
enum; resource types can differ and need only Send, not Clone or Sync.

```rust,ignore
use asupersync::{Cx, types::Outcome};
use asupersync::cx::resource_bracket::BracketConfig;
use std::cell::Cell;

async fn startup(cx: &Cx) {
    let mut handle = cx.spawn_resource_scope::<(), &'static str, &'static str, _>(
        BracketConfig::new(16), 2,
        |_, mut resources| Box::pin(async move {
            let counter = resources.try_insert(Cell::new(1_u8), |_, value| async move {
                assert_eq!(value.get(), 2);
                Outcome::Ok(())
            }).expect("first slot");
            resources.get(&counter).unwrap().set(2);
            resources.try_insert(String::from("temporary state"), |_, value| async move {
                asupersync::runtime::yield_now().await;
                assert_eq!(value, "temporary state");
                Outcome::Ok(())
            }).expect("second slot");
            Outcome::Err("a later startup step failed")
        }),
    ).expect("controller submission");
    let report = handle.join().await.expect("controller report");
    assert!(!report.is_success()); // successful cleanup is not successful startup
    let cleanup = report.cleanup.as_ref().unwrap();
    assert!(cleanup.is_success());
    assert_eq!(cleanup.entries[0].index, 1);
    assert_eq!(cleanup.entries[1].index, 0);
}
```

### Reserve before effects

For real fallible acquisition, call `resources.reserve()` BEFORE beginning the
operation. A refusal performs no acquisition. An unused reservation borrows the
stack exclusively, spends no registration slot, and can simply be dropped.
`slot.acquire(&cx, acquire_factory, release_factory).await` checks cancellation
before invoking acquisition and returns `BracketPhase<ResourceKey<T>, E>`.

A successfully returned resource is installed into its reserved owner with no
intervening checkpoint or await. Cancellation arriving during acquisition cannot
strand that returned value. A future-destructor panic after acquisition also
preserves the key/resource alongside `retirement_panic`. Inspect both phase
fields: an Ok key with that panic is NOT a successful setup. The work callback
chooses whether an acquisition error is recoverable or should become its returned
work outcome; ignoring an individual phase error does not automatically override
that work outcome. The scope's lifecycle acquisition field describes creation of
the stack, not each individual resource acquisition.

An acquisition that fails without returning a resource remains responsible for
its partial effects. Dropping an in-progress borrowing acquisition drops that
acquisition future but preserves older registered resources. Already-acquired
values can use `try_insert`; refusal returns BOTH the original value and factory.
Neither dropping that refusal nor capturing a resource before scope submission
provides an implicit asynchronous cleanup guarantee.

### Retained cleanup and reports

A borrowing handle join can be dropped and resumed; dropping the HANDLE requests
cancellation and leaves runtime ownership to the containing region. The scope
report preserves the existing lifecycle plus `cleanup`, containing every entry's
exact outcome and independent retirement panic in actual LIFO order. Any failed
entry makes the lifecycle release return Err(()) and prevents whole-scope success;
the full typed cause is retained in cleanup. If region closure fails, release is
withheld and the entire stack remains in `lifecycle.unreleased`. Do not close that
stack until independently establishing quiescence.

The finite masked-poll allowance applies to the WHOLE stack release future, not
an independently reset allowance for each entry. Pending cleanup is retained when
that allowance ends and continues unmasked. A nonterminating newer release blocks
older ones: there is no unsafe timeout that releases dependencies underneath it.
At most sixteen immediately-ready releases run per outer stack poll, followed by
a requested continuation. This bounds callback count, not time within callbacks.
Registration count bounds resources and report entries, not payload bytes, child
work, resource boxes, or allocator overhead. Result metadata is reserved before
acquisition, so recording cleanup outcomes does not grow the result vector.

`ResourceStack` can also be owned directly. Its `close(&cx)` stores the active
release future and completed reports in the stack, so dropping that borrowing
wait does not restart or discard cleanup. Completed close is idempotent and seals
registration permanently. Standalone close adds no cancellation mask and assumes
that its caller already established quiescence. Dropping the ENTIRE standalone
stack performs ordinary Rust destruction only. Prefer the runtime-owned scope
when an interrupted work future must not own the only cleanup path.

This adds no arbitrary-region finalizer registration, durable cleanup,
exactly-once effects, or universal termination guarantee. Resources used through
independently captured capabilities remain outside the owned subtree. Every
release must finish its own spawned work. Runtime destruction, hard abort,
process exit, and nonreturning callbacks remain outside the cleanup guarantee.

### Resource-stack validation

The stack/scope addition contains twenty unit/lab tests and six native tests,
including Send-only resources and errors, late acquisition, acquisition retirement
panic, bounded metadata admission, resumable close, finite masking, and distinct
startup/cleanup outcomes. Native cases cover current-thread and two-worker
runtimes, explicit abort AND handle drop. They witness body/descendant parking,
then hold a cancelled descendant at a second Pending before permitting its exit.
No resource release may start before that drain. Newer cleanup then writes exact
bytes over loopback TCP and must park awaiting an ACK before the peer is allowed
to send it; only after that cleanup completes may the older resource release.
Failed multi-step startup also preserves its original error while a newer release
panics and an older one still completes. All native cases close the owning region.

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_resource_stack cargo test -p asupersync --lib cx::resource_bracket::stack::
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_resource_stack cargo test -p asupersync --test resource_stack_native
```

These tests have NOT been compiled or run in the authoring environment. Rust,
Cargo, rustfmt, RCH and UBS were unavailable. Source/API inspection and exact Git
blob comparisons do not establish Rust typing, native liveness, performance, or
release readiness. The existing single-resource and native parked-cancellation
lanes remain required and are not replaced by these new targets.
