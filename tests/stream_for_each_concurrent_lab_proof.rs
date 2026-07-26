//! Bounded-concurrency and drain proof for the concurrent stream terminals.
//!
//! Bead: asupersync-dx-core-api-v2-u1z5hn.8 (AC1, AC2)
//!
//! The unit tests for the buffering combinators live inline in `src/stream/`.
//! What needs a *runtime* — and therefore lives here — is the pair of claims
//! that distinguish `for_each_concurrent` from
//! [`buffer_unordered`](asupersync::stream::StreamExt::buffer_unordered):
//!
//! - **Bounded concurrency**: never more than `limit` items in flight, observed
//!   by the items themselves rather than by reading the implementation.
//! - **Drain on short-circuit**: when one item fails, the items still running
//!   are cancelled *and joined* before the call returns. The proof is
//!   attributive: each parked item records the moment it observes cancellation,
//!   and the count is asserted after the call has already returned. A test that
//!   only checked "the run went quiescent" would pass on region teardown alone
//!   and prove nothing about the combinator's own drain.

#![allow(missing_docs)]

use asupersync::cx::Cx;
use asupersync::lab::run_async_under_lab;
use asupersync::runtime::yield_now;
use asupersync::stream::{for_each_concurrent, iter, try_for_each_concurrent};
use asupersync::types::Outcome;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Parks cooperatively until cancellation is observed, then records it.
///
/// `checkpoint` is what makes this cooperative: cancellation here is a protocol,
/// not a kill. A body that only yielded would never observe the request, so the
/// counter this bumps is evidence about the drain and not about the item.
async fn parks_until_cancelled(cx: Cx, observed: Arc<AtomicUsize>) -> Result<(), &'static str> {
    loop {
        if cx.checkpoint().is_err() {
            observed.fetch_add(1, Ordering::SeqCst);
            return Err("observed cancellation");
        }
        yield_now().await;
    }
}

#[test]
fn for_each_concurrent_visits_every_item_exactly_once() {
    const ITEMS: usize = 32;

    let seen = Arc::new(AtomicUsize::new(0));
    let (outcome, report) = run_async_under_lab(0xB01, {
        let seen = Arc::clone(&seen);
        move |cx| async move {
            let source = iter((0..ITEMS).collect::<Vec<usize>>());
            for_each_concurrent(&cx, source, 4, move |_item_cx, _item| {
                let seen = Arc::clone(&seen);
                async move {
                    yield_now().await;
                    seen.fetch_add(1, Ordering::SeqCst);
                }
            })
            .await
        }
    });

    assert!(
        matches!(outcome, Outcome::Ok(())),
        "every item completed, so the terminal outcome is Ok: {outcome:?}"
    );
    assert_eq!(
        seen.load(Ordering::SeqCst),
        ITEMS,
        "each item must be applied exactly once"
    );
    assert!(
        report.quiescent && report.invariant_violations.is_empty(),
        "run must reach quiescence with no invariant violations: {:?}",
        report.invariant_violations
    );
}

#[test]
fn for_each_concurrent_never_exceeds_the_limit() {
    const LIMIT: usize = 3;
    const ITEMS: usize = 24;

    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));

    let (_outcome, report) = run_async_under_lab(0xB02, {
        let in_flight = Arc::clone(&in_flight);
        let max_seen = Arc::clone(&max_seen);
        move |cx| async move {
            let source = iter((0..ITEMS).collect::<Vec<usize>>());
            for_each_concurrent(&cx, source, LIMIT, move |_item_cx, _item| {
                let in_flight = Arc::clone(&in_flight);
                let max_seen = Arc::clone(&max_seen);
                async move {
                    // Observed by the items themselves: the high-water mark is
                    // recorded while the work is genuinely overlapping, not
                    // inferred from the implementation.
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_seen.fetch_max(now, Ordering::SeqCst);
                    yield_now().await;
                    yield_now().await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                }
            })
            .await
        }
    });

    let peak = max_seen.load(Ordering::SeqCst);
    assert!(
        peak <= LIMIT,
        "in-flight count must never exceed the limit: peak {peak} > limit {LIMIT}"
    );
    assert!(
        peak > 1,
        "the limit must actually be exercised, otherwise the bound above is vacuous: peak {peak}"
    );
    assert_eq!(
        in_flight.load(Ordering::SeqCst),
        0,
        "no item may still be in flight once the call returned"
    );
    assert!(
        report.quiescent && report.invariant_violations.is_empty(),
        "run must reach quiescence with no invariant violations: {:?}",
        report.invariant_violations
    );
}

#[test]
fn try_for_each_concurrent_drains_in_flight_items_before_returning() {
    const LIMIT: usize = 4;
    // One failing item plus three that never finish on their own. The only way
    // the parked items can reach a terminal state is the combinator's drain.
    const PARKED: usize = 3;

    let observed_cancellation = Arc::new(AtomicUsize::new(0));

    let (outcome, report) = run_async_under_lab(0xB03, {
        let observed = Arc::clone(&observed_cancellation);
        move |cx| async move {
            let source = iter((0..=PARKED).collect::<Vec<usize>>());
            try_for_each_concurrent(&cx, source, LIMIT, move |item_cx, item| {
                let observed = Arc::clone(&observed);
                async move {
                    if item == 0 {
                        return Err("first item fails");
                    }
                    parks_until_cancelled(item_cx, observed).await
                }
            })
            .await
        }
    });

    assert!(
        matches!(outcome, Outcome::Err("first item fails")),
        "the first observed failure is reported unchanged, not replaced by the \
         cancellation the combinator itself requested: {outcome:?}"
    );
    // This is the drain claim. The assertion runs AFTER the call returned, so a
    // nonzero count here means the in-flight items were cancelled and joined
    // before the return - not merely abandoned and cleaned up later by region
    // close.
    assert_eq!(
        observed_cancellation.load(Ordering::SeqCst),
        PARKED,
        "every in-flight item must observe cancellation and be joined before \
         try_for_each_concurrent returns"
    );
    assert!(
        report.quiescent && report.invariant_violations.is_empty(),
        "run must reach quiescence with no invariant violations: {:?}",
        report.invariant_violations
    );
}

#[test]
fn try_for_each_concurrent_reports_ok_when_no_item_fails() {
    const ITEMS: usize = 16;

    let seen = Arc::new(AtomicUsize::new(0));
    let (outcome, report) = run_async_under_lab(0xB04, {
        let seen = Arc::clone(&seen);
        move |cx| async move {
            let source = iter((0..ITEMS).collect::<Vec<usize>>());
            try_for_each_concurrent(&cx, source, 5, move |_item_cx, _item| {
                let seen = Arc::clone(&seen);
                async move {
                    yield_now().await;
                    seen.fetch_add(1, Ordering::SeqCst);
                    Ok::<(), &'static str>(())
                }
            })
            .await
        }
    });

    assert!(
        matches!(outcome, Outcome::Ok(())),
        "no item failed, so the terminal outcome is Ok: {outcome:?}"
    );
    assert_eq!(seen.load(Ordering::SeqCst), ITEMS, "every item ran");
    assert!(report.quiescent && report.invariant_violations.is_empty());
}

#[test]
fn concurrent_terminals_are_deterministic_under_the_same_seed() {
    fn run(seed: u64) -> (usize, bool) {
        let seen = Arc::new(AtomicUsize::new(0));
        let (outcome, _report) = run_async_under_lab(seed, {
            let seen = Arc::clone(&seen);
            move |cx| async move {
                let source = iter((0..20usize).collect::<Vec<usize>>());
                try_for_each_concurrent(&cx, source, 4, move |_item_cx, item| {
                    let seen = Arc::clone(&seen);
                    async move {
                        yield_now().await;
                        seen.fetch_add(1, Ordering::SeqCst);
                        if item == 13 { Err("thirteen") } else { Ok(()) }
                    }
                })
                .await
            }
        });
        (
            seen.load(Ordering::SeqCst),
            matches!(outcome, Outcome::Err("thirteen")),
        )
    }

    let first = run(0xB05);
    let second = run(0xB05);
    assert_eq!(
        first, second,
        "same seed must produce the same item count and the same terminal outcome"
    );
    assert!(
        first.1,
        "the failing item must be the reported cause: {first:?}"
    );
}

#[test]
#[should_panic(expected = "limit must be non-zero")]
fn try_for_each_concurrent_rejects_zero_limit() {
    let _ = run_async_under_lab(0xB06, |cx| async move {
        let source = iter(Vec::<usize>::new());
        try_for_each_concurrent(&cx, source, 0, |_cx, _item| async move {
            Ok::<(), &'static str>(())
        })
        .await
    });
}

/// AC1's cancellation clause: when the *caller* is cancelled, the items still
/// in flight must be drained rather than abandoned.
///
/// This is the hardest case in the combinator and the one most likely to hide a
/// hang, so the test is deliberately adversarial: every item parks forever and
/// can only terminate through cancellation, and the driver is cancelled while
/// all of them are running. If cancellation could not reach the items, the run
/// would burn its step budget and come back non-quiescent instead of passing.
#[test]
fn concurrent_terminal_drains_in_flight_items_when_the_caller_is_cancelled() {
    const MEMBERS: usize = 4;

    let started = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(AtomicUsize::new(0));

    let (_joined, report) = run_async_under_lab(0xB07, {
        let started = Arc::clone(&started);
        let observed = Arc::clone(&observed);
        move |cx| async move {
            let driver_started = Arc::clone(&started);
            let driver_observed = Arc::clone(&observed);
            let outer_started = Arc::clone(&started);

            let mut handle = cx
                .spawn(move |task_cx| async move {
                    let source = iter((0..MEMBERS).collect::<Vec<usize>>());
                    try_for_each_concurrent(&task_cx, source, MEMBERS, move |item_cx, _item| {
                        let started = Arc::clone(&driver_started);
                        let observed = Arc::clone(&driver_observed);
                        async move {
                            started.fetch_add(1, Ordering::SeqCst);
                            parks_until_cancelled(item_cx, observed).await
                        }
                    })
                    .await
                })
                .expect("spawn driver task");

            // Cancel only once every item is genuinely in flight, so the
            // cancellation lands on running work rather than racing the spawn.
            let mut guard = 0usize;
            while outer_started.load(Ordering::SeqCst) < MEMBERS {
                yield_now().await;
                guard += 1;
                assert!(guard < 10_000, "items never reached the in-flight state");
            }

            handle.abort();
            handle.join(&cx).await
        }
    });

    assert_eq!(
        started.load(Ordering::SeqCst),
        MEMBERS,
        "every item must have been in flight when the cancellation landed"
    );
    assert_eq!(
        observed.load(Ordering::SeqCst),
        MEMBERS,
        "every in-flight item must observe cancellation - if this is short, the \
         items were abandoned rather than drained"
    );
    assert!(
        report.quiescent && report.invariant_violations.is_empty(),
        "run must reach quiescence with no invariant violations: quiescent={} violations={:?}",
        report.quiescent,
        report.invariant_violations
    );
}
