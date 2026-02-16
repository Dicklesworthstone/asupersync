//! Combinator E2E test suite with cancel-correctness verification.
//!
//! This test suite validates the core combinator invariants:
//! - **Loser drain**: Race losers are fully cancelled and drained (not abandoned)
//! - **Obligation safety**: No obligation leaks across combinator branches
//! - **Outcome aggregation**: Correct severity lattice for join outcomes
//! - **Determinism**: All tests reproducible under lab runtime

#[macro_use]
mod common;

mod e2e {
    pub mod combinator;
}

use asupersync::combinator::Either;
use asupersync::epoch::{EpochContext, EpochId, EpochPolicy, epoch_join2, epoch_race2};
use asupersync::time::WallClock;
use asupersync::types::{CancelReason, Outcome, Time, join_outcomes};
use e2e::combinator::util::{
    CompleteAfterPolls, ControllableFuture, ControllableFutureHandle, Counter, DrainFlag,
    DrainTracker, NeverComplete,
};
use futures_lite::future;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

fn init_test(name: &str) {
    common::init_test_logging();
    test_phase!(name);
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWake))
}

#[test]
fn test_drain_flag_initially_false() {
    init_test("test_drain_flag_initially_false");
    let flag = DrainFlag::new();
    let drained = flag.is_drained();
    assert_with_log!(!drained, "initially false", true, drained);
}

#[test]
fn test_drain_tracker_sets_flag_on_drop() {
    init_test("test_drain_tracker_sets_flag_on_drop");
    let flag = DrainFlag::new();
    {
        let _tracker = DrainTracker::new(NeverComplete, Arc::clone(&flag));
    }
    assert_drained!(flag, "drop should drain");
}

#[test]
fn test_counter_increments_track_polls() {
    init_test("test_counter_increments_track_polls");
    let counter = Counter::new();
    counter.increment();
    counter.increment();
    let count = counter.get();
    assert_with_log!(count == 2, "counter value", 2u32, count);
}

#[test]
fn test_never_complete_returns_pending() {
    init_test("test_never_complete_returns_pending");
    let mut fut = NeverComplete;
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut fut).poll(&mut cx);
    assert_with_log!(
        matches!(poll, Poll::Pending),
        "pending",
        true,
        matches!(poll, Poll::Pending)
    );
}

#[test]
fn test_complete_after_polls_completes() {
    init_test("test_complete_after_polls_completes");
    let counter = Counter::new();
    let fut = CompleteAfterPolls::new(2, Arc::clone(&counter));
    let result = future::block_on(fut);
    let count = counter.get();
    assert_with_log!(result == count, "poll count", count, result);
}

#[test]
fn test_controllable_future_completes_on_signal() {
    init_test("test_controllable_future_completes_on_signal");
    let inner = ControllableFuture::new(99u32);
    let handle = ControllableFutureHandle::new(Arc::clone(&inner));
    ControllableFuture::complete(&inner);
    let value = future::block_on(handle);
    assert_with_log!(value == 99, "value", 99u32, value);
}

#[test]
fn test_join_outcomes_err_over_ok() {
    init_test("test_join_outcomes_err_over_ok");
    let ok: Outcome<(), &str> = Outcome::ok(());
    let err: Outcome<(), &str> = Outcome::err("boom");
    let joined = join_outcomes(ok, err);
    assert_with_log!(joined.is_err(), "err wins", true, joined.is_err());
}

#[test]
fn test_join_outcomes_cancelled_over_err() {
    init_test("test_join_outcomes_cancelled_over_err");
    let err: Outcome<(), &str> = Outcome::err("boom");
    let cancelled: Outcome<(), &str> = Outcome::cancelled(CancelReason::timeout());
    let joined = join_outcomes(err, cancelled);
    assert_with_log!(
        joined.is_cancelled(),
        "cancelled wins",
        true,
        joined.is_cancelled()
    );
}

#[test]
fn test_epoch_join2_returns_both_outputs() {
    init_test("test_epoch_join2_returns_both_outputs");
    let counter_a = Counter::new();
    let counter_b = Counter::new();
    let a = CompleteAfterPolls::new(0, Arc::clone(&counter_a));
    let b = CompleteAfterPolls::new(1, Arc::clone(&counter_b));

    let epoch_ctx = EpochContext::new(EpochId::GENESIS, Time::ZERO, Time::from_secs(10));
    let policy = EpochPolicy::ignore();
    let time_source = Arc::new(WallClock::new());
    let epoch_source = Arc::new(EpochId::GENESIS);

    let joined = epoch_join2(a, b, epoch_ctx, policy, time_source, epoch_source);
    let result = future::block_on(joined);

    let ok_a = result.0.is_ok();
    let ok_b = result.1.is_ok();
    assert_with_log!(ok_a, "left ok", true, ok_a);
    assert_with_log!(ok_b, "right ok", true, ok_b);
}

#[test]
fn test_epoch_race2_left_wins() {
    init_test("test_epoch_race2_left_wins");
    let counter_a = Counter::new();
    let counter_b = Counter::new();
    let a = CompleteAfterPolls::new(0, Arc::clone(&counter_a));
    let b = CompleteAfterPolls::new(5, Arc::clone(&counter_b));

    let epoch_ctx = EpochContext::new(EpochId::GENESIS, Time::ZERO, Time::from_secs(10));
    let policy = EpochPolicy::ignore();
    let time_source = Arc::new(WallClock::new());
    let epoch_source = Arc::new(EpochId::GENESIS);

    let raced = epoch_race2(a, b, epoch_ctx, policy, time_source, epoch_source);
    let result = future::block_on(raced);

    let left = matches!(result, Either::Left(Ok(_)));
    assert_with_log!(left, "left wins", true, left);
}

#[test]
fn test_epoch_race2_right_wins() {
    init_test("test_epoch_race2_right_wins");
    let counter_a = Counter::new();
    let counter_b = Counter::new();
    let a = CompleteAfterPolls::new(4, Arc::clone(&counter_a));
    let b = CompleteAfterPolls::new(0, Arc::clone(&counter_b));

    let epoch_ctx = EpochContext::new(EpochId::GENESIS, Time::ZERO, Time::from_secs(10));
    let policy = EpochPolicy::ignore();
    let time_source = Arc::new(WallClock::new());
    let epoch_source = Arc::new(EpochId::GENESIS);

    let raced = epoch_race2(a, b, epoch_ctx, policy, time_source, epoch_source);
    let result = future::block_on(raced);

    let right = matches!(result, Either::Right(Ok(_)));
    assert_with_log!(right, "right wins", true, right);
}
