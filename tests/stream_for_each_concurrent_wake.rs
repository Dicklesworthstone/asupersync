//! Concurrent stream terminals must park without spinning and retain both
//! completion and cancellation wakeups. These cases complement the drain and
//! concurrency proofs for asupersync-dx-core-api-v2-u1z5hn.8.

#![allow(missing_docs)]

use asupersync::cx::Cx;
use asupersync::lab::run_async_under_lab;
use asupersync::runtime::{JoinError, yield_now};
use asupersync::stream::{Stream, try_for_each_concurrent};
use asupersync::sync::{OwnedSemaphorePermit, Semaphore};
use asupersync::types::Outcome;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

struct Source {
    next: usize,
    end: usize,
    quiet: bool,
}

impl Stream for Source {
    type Item = usize;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<usize>> {
        if self.next < self.end {
            let item = self.next;
            self.next += 1;
            Poll::Ready(Some(item))
        } else if self.quiet {
            // No source wakeup can accidentally rescue a missing completion
            // or cancellation registration.
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }
}

async fn parked_item(
    cx: Cx,
    gate: Arc<Semaphore>,
    started: Arc<AtomicUsize>,
    finished: Arc<AtomicUsize>,
) -> Result<(), &'static str> {
    started.fetch_add(1, Ordering::SeqCst);
    // Unlike a checkpoint/yield loop, this child does not keep the scheduler
    // busy. Only a real semaphore release or cancellation wakes it.
    let result = OwnedSemaphorePermit::acquire(gate, &cx, 1).await;
    finished.fetch_add(1, Ordering::SeqCst);
    match result {
        Ok(_permit) => Err("gate opened"),
        Err(_) => Err("child cancelled"),
    }
}

fn check_wait(end: usize, limit: usize, quiet: bool, cancel: bool) {
    const MEMBERS: usize = 2;
    let gate = Arc::new(Semaphore::new(0));
    let started = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    let finished_at_return = Arc::new(AtomicUsize::new(0));
    let polls = Arc::new(AtomicUsize::new(0));

    let ((idle_polls, saw_expected_outcome), report) = run_async_under_lab(0xB100, {
        let gate = Arc::clone(&gate);
        let started = Arc::clone(&started);
        let finished = Arc::clone(&finished);
        let finished_at_return = Arc::clone(&finished_at_return);
        let polls = Arc::clone(&polls);
        move |cx| async move {
            let item_gate = Arc::clone(&gate);
            let item_started = Arc::clone(&started);
            let item_finished = Arc::clone(&finished);
            let driver_polls = Arc::clone(&polls);
            let mut driver = cx
                .spawn(move |driver_cx| async move {
                    let source = Source {
                        next: 0,
                        end,
                        quiet,
                    };
                    let mut work = pin!(try_for_each_concurrent(
                        &driver_cx,
                        source,
                        limit,
                        move |item_cx, _item| parked_item(
                            item_cx,
                            Arc::clone(&item_gate),
                            Arc::clone(&item_started),
                            Arc::clone(&item_finished),
                        ),
                    ));
                    let outcome = poll_fn(|task| {
                        driver_polls.fetch_add(1, Ordering::SeqCst);
                        work.as_mut().poll(task)
                    })
                    .await;
                    // Capture this INSIDE the caller, immediately after the
                    // combinator returns. Region teardown cannot satisfy it.
                    finished_at_return.store(finished.load(Ordering::SeqCst), Ordering::SeqCst);
                    if cancel {
                        matches!(outcome, Outcome::Cancelled(_))
                    } else {
                        matches!(outcome, Outcome::Err("gate opened"))
                    }
                })
                .expect("spawn stream driver");

            let mut turns = 0;
            while started.load(Ordering::SeqCst) < MEMBERS {
                turns += 1;
                assert!(turns < 10_000, "children did not start");
                yield_now().await;
            }
            // Flush finite admission notifications before measuring an idle
            // interval. No child, source, or cancellation event occurs here.
            for _ in 0..16 {
                yield_now().await;
            }
            let before = polls.load(Ordering::SeqCst);
            for _ in 0..32 {
                yield_now().await;
            }
            let idle_polls = polls.load(Ordering::SeqCst) - before;

            if cancel {
                driver.abort();
            } else {
                gate.add_permits(1);
            }
            let joined = driver.join(&cx).await;
            // Cancellation may dominate the driver's returned value at its
            // task boundary; the in-body drain observation remains decisive.
            let saw_expected_outcome = if cancel {
                matches!(joined, Err(JoinError::Cancelled(_)) | Ok(true))
            } else {
                matches!(joined, Ok(true))
            };
            (idle_polls, saw_expected_outcome)
        }
    });

    assert_eq!(idle_polls, 0, "an idle stream driver must not self-wake");
    assert!(
        saw_expected_outcome,
        "the wake must deliver the triggering outcome"
    );
    assert_eq!(started.load(Ordering::SeqCst), MEMBERS, "no extra admission");
    assert_eq!(
        finished_at_return.load(Ordering::SeqCst),
        MEMBERS,
        "both children must terminate before the combinator returns"
    );
    assert!(
        report.quiescent && report.invariant_violations.is_empty(),
        "quiescent={} violations={:?}",
        report.quiescent,
        report.invariant_violations
    );
}

#[test]
fn capacity_wait_parks_and_wakes_on_completion() {
    check_wait(3, 2, false, false);
}

#[test]
fn capacity_wait_parks_and_wakes_on_cancellation() {
    check_wait(3, 2, false, true);
}

#[test]
fn exhausted_source_wait_parks_and_wakes_on_completion() {
    check_wait(2, 3, false, false);
}

#[test]
fn exhausted_source_wait_parks_and_wakes_on_cancellation() {
    check_wait(2, 3, false, true);
}

#[test]
fn quiet_source_wait_parks_and_wakes_on_completion() {
    check_wait(2, 3, true, false);
}

#[test]
fn quiet_source_wait_parks_and_wakes_on_cancellation() {
    check_wait(2, 3, true, true);
}
