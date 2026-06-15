//! Loser-drain behavior proof for the `race!` macro engine (u1z5hn.6 AC2).
//!
//! The `race!` macro expands to the drain-correct `Cx::race_drained*` family —
//! proven *structurally* by the macro crate's token tests
//! (`asupersync-macros/src/race.rs`). This file pins the *observable behavior*
//! the macro promises and the original drop-only `race!` lied about: a losing
//! branch is protocol-cancelled **and drained** — its future fully torn down —
//! before the race resolves.
//!
//! The discriminating construction is a loser that **never completes on its
//! own** (`std::future::pending`) while holding a `Drop`-tracking guard. With
//! the old `Cx::race` (drop-the-losers) semantics the winner value could
//! surface while a loser was merely cancel-requested; here the loser can only
//! reach its guard's `Drop` by being force-finalized through the runtime's
//! cancel lane, which `Scope::race_all` triggers (`abort_with_reason` + an
//! awaited `join`) for every pending loser on the ordinary-winner path. We
//! sample the guard from inside the same task at the instant `race_drained`
//! returns and require it already dropped.
//!
//! A pending-forever loser also makes the winner deterministic: a branch that
//! is never self-ready can never tie the immediately-ready winner, so no
//! scheduler interleaving can flip which branch wins.

#![allow(missing_docs)]

use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use asupersync::cx::Cx;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A guard whose `Drop` records that the future owning it was torn down. Stands
/// in for a loser-held obligation/finalizer that must resolve, not leak.
struct DrainGuard(Arc<AtomicBool>);

impl Drop for DrainGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn boxed<T: Send + 'static>(
    fut: impl Future<Output = T> + Send + 'static,
) -> Pin<Box<dyn Future<Output = T> + Send>> {
    Box::pin(fut)
}

/// A branch that holds `guard` and never completes on its own — only a real
/// cancel+drain tears it (and the guard) down.
fn pending_loser(guard: DrainGuard) -> Pin<Box<dyn Future<Output = u32> + Send>> {
    boxed(async move {
        let _guard = guard;
        std::future::pending::<u32>().await
    })
}

#[test]
fn race_drained_returns_winner_and_drains_pending_loser() {
    let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
    let loser_drained = Arc::new(AtomicBool::new(false));
    let loser_drained_for_guard = Arc::clone(&loser_drained);
    let loser_drained_for_read = Arc::clone(&loser_drained);

    let (winner_value, drained_before_return) =
        LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");

            // Winner: ready on the first poll with a sentinel value.
            let winner = boxed(async { 7_u32 });
            // Loser: holds a drain-tracking guard and parks forever.
            let loser = pending_loser(DrainGuard(loser_drained_for_guard));

            let result = cx
                .race_drained(vec![winner, loser])
                .await
                .expect("the immediately-ready branch resolves as the winner");

            // Sampled at the instant race_drained resolves: the loser must
            // already be drained (its future + guard torn down).
            let drained = loser_drained_for_read.load(Ordering::SeqCst);
            (result, drained)
        });

    assert_eq!(
        winner_value, 7,
        "the immediately-ready branch must win against a never-ready loser"
    );
    assert!(
        drained_before_return,
        "loser must be drained (its future torn down) BEFORE race_drained returns; \
         drop-only semantics would leave the loser live past the winner value"
    );
    assert!(
        loser_drained.load(Ordering::SeqCst),
        "loser drain flag must remain set after the race completes"
    );
}

#[test]
fn race_drained_drains_every_loser_in_an_n_ary_race() {
    let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());

    // Three pending-forever losers, one instant winner: every loser must be
    // drained, exercising the N-ary drain loop (lifts the fixed Race2/3/4
    // arity ceiling).
    let flags: Vec<Arc<AtomicBool>> = (0..3).map(|_| Arc::new(AtomicBool::new(false))).collect();
    let flags_for_async = flags.clone();

    let (winner_value, all_drained) = LabRuntimeTarget::block_on(&mut runtime, async move {
        let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");

        let mut branches: Vec<Pin<Box<dyn Future<Output = u32> + Send>>> = Vec::new();
        // Winner first: immediately ready.
        branches.push(boxed(async { 1_u32 }));
        // Losers: each holds a drain guard and parks forever.
        for flag in &flags_for_async {
            branches.push(pending_loser(DrainGuard(Arc::clone(flag))));
        }

        let result = cx
            .race_drained(branches)
            .await
            .expect("the immediately-ready branch wins the N-ary race");
        let drained = flags_for_async
            .iter()
            .all(|flag| flag.load(Ordering::SeqCst));
        (result, drained)
    });

    assert_eq!(winner_value, 1, "the ready branch must win the 4-way race");
    assert!(
        all_drained,
        "all three losing branches must be drained before race_drained returns"
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
