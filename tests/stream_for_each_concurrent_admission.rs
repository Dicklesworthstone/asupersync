//! Always-ready sources must not turn a large concurrency limit into an
//! unbounded admission burst. Exercise the real combinator and spawned tasks,
//! including cancellation while it is suspended at an admission boundary.

#![allow(missing_docs)]

use asupersync::lab::{LabConfig, run_async_under_lab_with_config};
use asupersync::runtime::{JoinError, yield_now};
use asupersync::stream::{Stream, for_each_concurrent, try_for_each_concurrent};
use asupersync::sync::{OwnedSemaphorePermit, Semaphore};
use asupersync::types::Outcome;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

const ITEMS: usize = 4096;

/// Admitting and running `ITEMS` children records about 20,500 trace events
/// (5,100 for the cancelled run), and the lab-test contract fails a run whose
/// trace overflowed its buffer (`scenario_failed_due_to_trace_truncation`).
/// The default buffer keeps 4096.
fn lab_config(seed: u64) -> LabConfig {
    LabConfig::new(seed).trace_capacity(1 << 16)
}

struct CountedSource {
    admitted: Arc<AtomicUsize>,
}

impl Stream for CountedSource {
    type Item = usize;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<usize>> {
        let item = self.admitted.load(Ordering::SeqCst);
        if item == ITEMS {
            Poll::Ready(None)
        } else {
            self.admitted.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Some(item))
        }
    }
}

#[test]
fn a_large_limit_yields_admission_without_losing_or_duplicating_items() {
    let admitted = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new((0..ITEMS).map(|_| AtomicUsize::new(0)).collect::<Vec<_>>());
    let ((first_burst, outcome), report) = run_async_under_lab_with_config(lab_config(0xB200), {
        let admitted = Arc::clone(&admitted);
        let seen = Arc::clone(&seen);
        move |cx| async move {
            let source = CountedSource {
                admitted: Arc::clone(&admitted),
            };
            let mut work = pin!(for_each_concurrent(&cx, source, usize::MAX, move |_, item| {
                let seen = Arc::clone(&seen);
                async move {
                    seen[item].fetch_add(1, Ordering::SeqCst);
                }
            }));
            // Observe one actual poll, then resume the SAME future. No mock
            // spawn gateway or alternate admission implementation is involved.
            let first = poll_fn(|task| Poll::Ready(work.as_mut().poll(task))).await;
            let first_burst = admitted.load(Ordering::SeqCst);
            let outcome = match first {
                Poll::Pending => work.await,
                Poll::Ready(outcome) => outcome,
            };
            (first_burst, outcome)
        }
    });

    assert!(
        first_burst > 0 && first_burst < ITEMS,
        "unbounded burst: {first_burst}"
    );
    assert!(matches!(outcome, Outcome::Ok(())));
    assert_eq!(admitted.load(Ordering::SeqCst), ITEMS);
    for (item, count) in seen.iter().enumerate() {
        assert_eq!(count.load(Ordering::SeqCst), 1, "item {item}");
    }
    assert!(
        report.quiescent && report.invariant_violations.is_empty(),
        "quiescent={} violations={:?}",
        report.quiescent,
        report.invariant_violations
    );
}

#[test]
fn cancellation_at_an_admission_yield_stops_growth_and_drains_started_children() {
    let admitted = Arc::new(AtomicUsize::new(0));
    let first_burst = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    let finished_at_return = Arc::new(AtomicUsize::new(0));

    let (joined, report) = run_async_under_lab_with_config(lab_config(0xB201), {
        let admitted = Arc::clone(&admitted);
        let first_burst = Arc::clone(&first_burst);
        let started = Arc::clone(&started);
        let finished = Arc::clone(&finished);
        let finished_at_return = Arc::clone(&finished_at_return);
        move |cx| async move {
            let driver_admitted = Arc::clone(&admitted);
            let driver_first_burst = Arc::clone(&first_burst);
            let item_started = Arc::clone(&started);
            let item_finished = Arc::clone(&finished);
            let mut driver = cx
                .spawn(move |driver_cx| async move {
                    let gate = Arc::new(Semaphore::new(0));
                    let source = CountedSource {
                        admitted: Arc::clone(&driver_admitted),
                    };
                    let mut work = pin!(try_for_each_concurrent(
                        &driver_cx,
                        source,
                        usize::MAX,
                        move |item_cx, _item| {
                            let gate = Arc::clone(&gate);
                            let started = Arc::clone(&item_started);
                            let finished = Arc::clone(&item_finished);
                            async move {
                                started.fetch_add(1, Ordering::SeqCst);
                                let _result = OwnedSemaphorePermit::acquire(gate, &item_cx, 1).await;
                                finished.fetch_add(1, Ordering::SeqCst);
                                Err::<(), &'static str>("child cancelled")
                            }
                        },
                    ));
                    let first = poll_fn(|task| Poll::Ready(work.as_mut().poll(task))).await;
                    driver_first_burst.store(
                        driver_admitted.load(Ordering::SeqCst),
                        Ordering::SeqCst,
                    );

                    let outcome = match first {
                        Poll::Ready(outcome) => outcome,
                        Poll::Pending => {
                            // Hold the observed suspension until the root has
                            // started every admitted child and cancels us.
                            // This wait wakes on cancellation, not on a timer.
                            let resume = Arc::new(Semaphore::new(0));
                            let _ = OwnedSemaphorePermit::acquire(resume, &driver_cx, 1).await;
                            work.await
                        }
                    };
                    finished_at_return.store(finished.load(Ordering::SeqCst), Ordering::SeqCst);
                    matches!(outcome, Outcome::Cancelled(_))
                })
                .expect("spawn admission driver");

            let mut turns = 0;
            loop {
                let burst = first_burst.load(Ordering::SeqCst);
                if burst > 0 && started.load(Ordering::SeqCst) == burst {
                    break;
                }
                turns += 1;
                assert!(turns < 50_000, "admitted children did not start");
                yield_now().await;
            }
            driver.abort();
            driver.join(&cx).await
        }
    });

    let burst = first_burst.load(Ordering::SeqCst);
    assert!(burst > 0 && burst < ITEMS, "unbounded burst: {burst}");
    assert_eq!(
        admitted.load(Ordering::SeqCst),
        burst,
        "no post-cancel admission"
    );
    assert_eq!(started.load(Ordering::SeqCst), burst);
    assert_eq!(
        finished_at_return.load(Ordering::SeqCst),
        burst,
        "drain before return"
    );
    assert!(matches!(joined, Ok(true) | Err(JoinError::Cancelled(_))));
    assert!(
        report.quiescent && report.invariant_violations.is_empty(),
        "quiescent={} violations={:?}",
        report.quiescent,
        report.invariant_violations
    );
}
