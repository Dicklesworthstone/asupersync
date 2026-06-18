//! Loser-drain behavior proof for the `race!` macro engine (u1z5hn.6 AC2).
//!
//! The `race!` macro expands to the drain-correct `Cx::race_drained*` family —
//! proven *structurally* by the macro crate's token tests
//! (`asupersync-macros/src/race.rs`). This file pins the *observable behavior*
//! the macro promises and the original drop-only `race!` lied about: a losing
//! branch is protocol-cancelled **and drained** — driven through its own
//! cancellation path to termination — before the race resolves.
//!
//! # What discriminates drain from drop
//!
//! A `Drop`-only signal cannot tell the two apart: dropping a loser future at
//! its suspend point still runs the destructors of its live locals. The signal
//! that *only* fires under a real drain is **code that runs after the
//! suspension point, in response to observed cancellation**. A dropped future
//! never advances past where it was parked, so that code never executes; a
//! drained future is polled once more after `abort`, observes its task's
//! cancellation via `Cx::current().checkpoint()`, runs its post-cancel
//! resolution, and returns.
//!
//! Each loser here parks (self-waking) until its own task is cancelled, then
//! flips a `resolved` flag and returns. Because the loser never completes on
//! its own, it can never tie the immediately-ready winner — the winner is
//! deterministic — and the loser can only set `resolved` by being drained.
//! `Scope::race_all` (which `race_drained` delegates to) aborts every pending
//! loser and *awaits its join* on the ordinary-winner path, so the resolution
//! has run by the time `race_drained` returns.

#![allow(missing_docs)]

use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use asupersync::cx::Cx;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

fn boxed<T: Send + 'static>(
    fut: impl Future<Output = T> + Send + 'static,
) -> Pin<Box<dyn Future<Output = T> + Send>> {
    Box::pin(fut)
}

/// Parks (self-waking) until *this task* is cancelled, then resolves. Only a
/// real cancel+drain drives it to `Ready`; it never completes on its own.
async fn park_until_cancelled() -> u32 {
    std::future::poll_fn(|poll_cx| match Cx::current() {
        Some(task_cx) if task_cx.checkpoint().is_err() => Poll::Ready(0_u32),
        _ => {
            poll_cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}

/// A losing branch that resolves a held obligation when (and only when) it is
/// drained. `resolved` is set on the post-cancellation code path — it stays
/// `false` if the future is merely dropped at its suspend point.
fn draining_loser(resolved: Arc<AtomicBool>) -> Pin<Box<dyn Future<Output = u32> + Send>> {
    boxed(async move {
        let value = park_until_cancelled().await;
        // Post-cancellation resolution: reached only by a drained (re-polled
        // after abort) future, never by a dropped one.
        resolved.store(true, Ordering::SeqCst);
        value
    })
}

#[test]
fn race_drained_returns_winner_and_drains_loser() {
    let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
    let resolved = Arc::new(AtomicBool::new(false));
    let resolved_for_branch = Arc::clone(&resolved);
    let resolved_for_read = Arc::clone(&resolved);

    let (winner_value, resolved_before_return) =
        LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");

            // Winner: ready on the first poll with a sentinel value.
            let winner = boxed(async { 7_u32 });
            // Loser: parks until cancelled, then runs its resolution.
            let loser = draining_loser(resolved_for_branch);

            let result = cx
                .race_drained(vec![winner, loser])
                .await
                .expect("the immediately-ready branch resolves as the winner");

            // Sampled at the instant race_drained resolves.
            let drained = resolved_for_read.load(Ordering::SeqCst);
            (result, drained)
        });

    assert_eq!(
        winner_value, 7,
        "the immediately-ready branch must win against a park-until-cancelled loser"
    );
    assert!(
        resolved_before_return,
        "loser must be DRAINED — its post-cancellation resolution run — before race_drained \
         returns; drop-only semantics would abandon the loser at its suspend point and never run it"
    );
}

#[test]
fn race_drained_drains_every_loser_in_an_n_ary_race() {
    let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());

    // Three park-until-cancelled losers, one instant winner: every loser must
    // be drained, exercising the N-ary drain loop (lifts the fixed Race2/3/4
    // arity ceiling).
    let flags: Vec<Arc<AtomicBool>> = (0..3).map(|_| Arc::new(AtomicBool::new(false))).collect();
    let flags_for_async = flags.clone();

    let (winner_value, all_resolved) = LabRuntimeTarget::block_on(&mut runtime, async move {
        let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");

        let mut branches: Vec<Pin<Box<dyn Future<Output = u32> + Send>>> = Vec::new();
        // Winner first: immediately ready.
        branches.push(boxed(async { 1_u32 }));
        // Losers: each resolves its obligation only when drained.
        for flag in &flags_for_async {
            branches.push(draining_loser(Arc::clone(flag)));
        }

        let result = cx
            .race_drained(branches)
            .await
            .expect("the immediately-ready branch wins the N-ary race");
        let resolved = flags_for_async
            .iter()
            .all(|flag| flag.load(Ordering::SeqCst));
        (result, resolved)
    });

    assert_eq!(winner_value, 1, "the ready branch must win the 4-way race");
    assert!(
        all_resolved,
        "all three losing branches must be drained (resolved) before race_drained returns"
    );
}

#[test]
fn race_drained_single_branch_resolves_to_that_branch() {
    // Degenerate but legal: a one-branch race spawns a single task and returns
    // its value — exercises the spawn+race_all wiring with no losers.
    let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
    let value = LabRuntimeTarget::block_on(&mut runtime, async move {
        let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");
        cx.race_drained(vec![boxed(async { 42_u32 })])
            .await
            .expect("single-branch race resolves to that branch")
    });
    assert_eq!(value, 42);
}
