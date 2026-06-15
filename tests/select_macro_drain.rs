//! Behavior proofs for the `select!` macro (u1z5hn.6 AC2 / AC3 / AC6).
//!
//! `select!` is the heterogeneous, N-ary member of the race family. The macro
//! crate's token tests (`asupersync-macros/src/select.rs`) pin its *structure*;
//! this file pins the *observable behavior* it promises:
//!
//! * **AC2 / drain** — the blocking (no-`else`) form routes each branch through
//!   the proven `Cx::race_drained` engine, so a losing branch is
//!   protocol-cancelled **and drained** (its post-cancellation code runs to
//!   termination) before `select!` returns — never merely dropped.
//! * **AC3 / N-ary + else + biased** — branches of *different* future types are
//!   selected over (handlers unify to one type); the drain loop holds at high
//!   arity; the non-blocking `else` arm is a Go-style default; `biased` is
//!   accepted and still drains.
//! * **AC6 / determinism** — same seed ⇒ same winner across replays. The
//!   blocking form's same-turn tie-break is the lab's *seeded* scheduler RNG
//!   (replay-stable, not source order); the `else` form polls in strict source
//!   order (seed-independent).
//!
//! # What discriminates drain from drop
//!
//! A `Drop`-only signal cannot tell the two apart. The signal that *only* fires
//! under a real drain is code that runs **after the suspension point, in
//! response to observed cancellation**. Each loser here parks (self-waking)
//! until its own task is cancelled, then flips a `resolved` flag and returns —
//! a dropped future never advances past its park, a drained one does.

#![allow(missing_docs)]

use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use asupersync::cx::Cx;
use asupersync::select;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

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

/// A losing branch (string-typed, to exercise heterogeneity) that resolves a
/// held obligation only when drained — `resolved` is set on the
/// post-cancellation path, never on a drop.
async fn draining_loser_string(resolved: Arc<AtomicBool>) -> String {
    let value = park_until_cancelled().await;
    resolved.store(true, Ordering::SeqCst);
    format!("drained:{value}")
}

/// A u32-typed losing branch, same drain semantics.
async fn draining_loser_u32(resolved: Arc<AtomicBool>) -> u32 {
    let value = park_until_cancelled().await;
    resolved.store(true, Ordering::SeqCst);
    value
}

#[test]
fn select_blocking_returns_winner_and_drains_heterogeneous_loser() {
    let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
    let resolved = Arc::new(AtomicBool::new(false));
    let resolved_branch = Arc::clone(&resolved);
    let resolved_read = Arc::clone(&resolved);

    let (winner, drained) = LabRuntimeTarget::block_on(&mut runtime, async move {
        let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");

        // Heterogeneous branch futures: a u32 winner vs a String loser. Both
        // handler arms yield `&'static str`, so the per-branch future list is
        // homogeneous and routes through the drain-correct engine.
        let result: &'static str = select!(cx, {
            _w = async { 7_u32 } => "winner",
            _l = draining_loser_string(resolved_branch) => "loser",
        })
        .expect("the instantly-ready branch resolves as the winner");

        (result, resolved_read.load(Ordering::SeqCst))
    });

    assert_eq!(
        winner, "winner",
        "the instantly-ready branch must beat a park-until-cancelled loser"
    );
    assert!(
        drained,
        "the losing branch must be cancelled AND drained — its post-cancellation \
         resolution run — before select! returns; drop-only semantics would abandon it"
    );
}

#[test]
fn select_blocking_drains_every_loser_at_arity_8() {
    // The drain loop is arity-agnostic (a `Vec` of spawned tasks); arity 8 with
    // one winner + seven parked losers exercises the N-ary expansion the macro
    // generates. (Lower arities 2/3/5 drive the identical engine.)
    let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
    let flags: Vec<Arc<AtomicBool>> = (0..7).map(|_| Arc::new(AtomicBool::new(false))).collect();
    let f0 = Arc::clone(&flags[0]);
    let f1 = Arc::clone(&flags[1]);
    let f2 = Arc::clone(&flags[2]);
    let f3 = Arc::clone(&flags[3]);
    let f4 = Arc::clone(&flags[4]);
    let f5 = Arc::clone(&flags[5]);
    let f6 = Arc::clone(&flags[6]);

    let (winner, all_drained) = LabRuntimeTarget::block_on(&mut runtime, async move {
        let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");

        let result: u32 = select!(cx, {
            _w = async { 100_u32 } => 100_u32,
            _l0 = draining_loser_u32(f0) => 0_u32,
            _l1 = draining_loser_u32(f1) => 0_u32,
            _l2 = draining_loser_u32(f2) => 0_u32,
            _l3 = draining_loser_u32(f3) => 0_u32,
            _l4 = draining_loser_u32(f4) => 0_u32,
            _l5 = draining_loser_u32(f5) => 0_u32,
            _l6 = draining_loser_u32(f6) => 0_u32,
        })
        .expect("the instantly-ready branch wins the 8-way select");

        let all = flags.iter().all(|flag| flag.load(Ordering::SeqCst));
        (result, all)
    });

    assert_eq!(winner, 100, "the ready branch must win the 8-way select");
    assert!(
        all_drained,
        "all seven losing branches must be drained before select! returns"
    );
}

#[test]
fn select_else_form_is_source_order_for_every_seed() {
    // The non-blocking `else` form polls in strict source order: with two
    // instantly-ready branches the first listed always wins, for every seed.
    for seed in 0..8 {
        let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::new().with_seed(seed));
        let winner = LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");
            select!(cx, {
                _a = async { 1_u32 } => "first",
                _b = async { 2_u32 } => "second",
                else => "neither",
            })
        });
        assert_eq!(
            winner, "first",
            "non-blocking source-order select must pick branch 0 for seed {seed}"
        );
    }
}

#[test]
fn select_else_runs_when_no_branch_is_ready() {
    let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
    let outcome = LabRuntimeTarget::block_on(&mut runtime, async move {
        let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");
        // The only branch is never ready (parks forever); the else default runs
        // immediately. The polled-once branch is dropped (this path does not
        // drain — the documented non-blocking opt-out).
        select!(cx, {
            _never = core::future::pending::<u32>() => "branch",
            else => "default",
        })
    });
    assert_eq!(
        outcome, "default",
        "no branch ready in the same turn ⇒ the else handler runs immediately"
    );
}

#[test]
fn select_biased_blocking_form_still_drains() {
    // `biased` is accepted on the blocking form and is still drain-correct.
    let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
    let resolved = Arc::new(AtomicBool::new(false));
    let resolved_branch = Arc::clone(&resolved);
    let resolved_read = Arc::clone(&resolved);

    let (winner, drained) = LabRuntimeTarget::block_on(&mut runtime, async move {
        let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");
        let result: u32 = select!(cx, biased, {
            _w = async { 5_u32 } => 5_u32,
            _l = draining_loser_u32(resolved_branch) => 0_u32,
        })
        .expect("ready branch wins the biased select");
        (result, resolved_read.load(Ordering::SeqCst))
    });

    assert_eq!(
        winner, 5,
        "biased select must still resolve to the ready branch"
    );
    assert!(drained, "biased select must still drain its loser");
}

/// Runs a two-instantly-ready blocking `select!` under a fixed seed and returns
/// the winning branch's value. The same-turn tie-break is the lab's seeded
/// scheduler RNG, so this is a deterministic function of `seed`.
fn run_two_ready_select(seed: u64) -> u32 {
    let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::new().with_seed(seed));
    LabRuntimeTarget::block_on(&mut runtime, async move {
        let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");
        select!(cx, {
            _a = async { 10_u32 } => 10_u32,
            _b = async { 20_u32 } => 20_u32,
        })
        .expect("a ready branch wins")
    })
}

#[test]
fn select_blocking_winner_is_replay_stable_per_seed() {
    // AC6: same seed ⇒ same winner across replays. (Across *different* seeds the
    // winner may differ — the tie-break is the seeded RNG, not source order.)
    for seed in 0..8 {
        let first = run_two_ready_select(seed);
        let second = run_two_ready_select(seed);
        assert_eq!(
            first, second,
            "seed {seed} must select the same winner across replays"
        );
        assert!(
            first == 10 || first == 20,
            "winner must be one of the two branch values, got {first}"
        );
    }
}
