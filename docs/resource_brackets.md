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
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib cx::resource_bracket::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --test resource_bracket_native
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --locked --test runtime_abort_vs_cancel_semantics_audit -- --nocapture
```

The focused source includes fifteen unit/lab tests and four native tests. Lab
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
