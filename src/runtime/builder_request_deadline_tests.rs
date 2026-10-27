//! Native execution-boundary deadline journeys for asupersync-pev2xi.

use super::{Runtime, RuntimeBuilder};
use crate::channel::mpsc as async_mpsc;
use crate::cx::{ChildRegionSpec, Cx};
use crate::record::RegionLimits;
use crate::runtime::RuntimeState;
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, CancelKind, Time};
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::task::Poll;
use std::time::Duration;

const MODES: [(bool, bool); 4] = [(true, false), (true, true), (false, false), (false, true)];

fn builder(current_thread: bool, sharded: bool) -> RuntimeBuilder {
    let builder = if current_thread {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(2)
    };
    builder.with_sharded_state(sharded)
}

#[derive(Clone, Copy, Debug)]
enum Entry {
    Root,
    Request,
    CurrentRequest,
    AdmissionRefused,
}

fn drive<F: Future>(runtime: &Runtime, entry: Entry, budget: Budget, future: F) -> F::Output {
    match entry {
        Entry::Root | Entry::AdmissionRefused => runtime.block_on_with_budget(budget, future),
        Entry::Request => runtime.block_on_with_cx(runtime.request_cx_with_budget(budget), future),
        Entry::CurrentRequest => runtime.block_on(async {
            let outer = Cx::current().unwrap();
            let output =
                Runtime::block_on_current_with_cx(runtime.request_cx_with_budget(budget), future)
                    .expect("current runtime installed");
            assert_eq!(Cx::current().unwrap().task_id(), outer.task_id());
            assert!(
                !outer.is_cancel_requested(),
                "deadline stays request scoped"
            );
            output
        }),
    }
}

#[test]
fn deadlines_wake_parked_native_roots_requests_and_admission_fallbacks() {
    for (current_thread, sharded) in MODES {
        for entry in [
            Entry::Root,
            Entry::Request,
            Entry::CurrentRequest,
            Entry::AdmissionRefused,
        ] {
            let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(5_000)));
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let deadline = Time::from_millis(5_050);
            let (sender, mut receiver) = async_mpsc::channel::<u8>(1);
            let (parked_tx, parked_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let join = std::thread::spawn({
                let timer = timer.clone();
                move || {
                    let mut builder =
                        builder(current_thread, sharded).with_timer_driver(timer.clone());
                    if matches!(entry, Entry::AdmissionRefused) {
                        builder = builder.root_region_limits(RegionLimits {
                            max_tasks: Some(0),
                            ..RegionLimits::UNLIMITED
                        });
                    }
                    let runtime = builder.build().unwrap();
                    let mut parked_tx = Some(parked_tx);
                    let mut polls = 0;
                    let (result, cx) = drive(
                        &runtime,
                        entry,
                        Budget::INFINITE.with_deadline(deadline),
                        poll_fn(|task_cx| {
                            polls += 1;
                            let cx = Cx::current().expect("native request context");
                            // The low-level receive retains a data waker only;
                            // the direct driver must supply its cancellation wake.
                            match receiver.poll_recv(&cx, task_cx) {
                                Poll::Ready(result) => Poll::Ready((result, cx)),
                                Poll::Pending => {
                                    if let Some(tx) = parked_tx.take() {
                                        tx.send(timer.pending_count()).unwrap();
                                    }
                                    Poll::Pending
                                }
                            }
                        }),
                    );
                    done_tx
                        .send((result, cx, polls, runtime.is_quiescent()))
                        .unwrap();
                }
            });

            let parked = parked_rx.recv_timeout(Duration::from_secs(2));
            // Advance only the clock. The actual native caller/worker timer
            // turn must wake the request; no test thread processes the wheel.
            clock.advance_to(deadline);
            let completed = done_rx.recv_timeout(Duration::from_secs(2));
            let deadline_woke_it = completed.is_ok();
            // A missing deadline wake is rescued by channel disconnection,
            // so the failed regression does not strand a runtime thread.
            drop(sender);
            let (result, cx, polls, quiescent) = completed
                .or_else(|_| done_rx.recv_timeout(Duration::from_secs(2)))
                .expect("request must finish after the rescue wake");
            join.join().unwrap();

            assert_eq!(parked.unwrap(), 1, "{entry:?}: exactly one deadline timer");
            assert!(
                deadline_woke_it,
                "{entry:?}: parked request missed its deadline"
            );
            assert_eq!(result, Err(async_mpsc::RecvError::Cancelled));
            assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::Deadline);
            assert!(polls >= 2, "the wait actually parked before cancellation");
            assert!(cx.inner.read().cancel_waker_registrations.is_empty());
            assert_eq!(timer.pending_count(), 0);
            assert!(quiescent);
        }
    }
}

#[test]
fn an_already_due_request_deadline_is_processed_without_a_checkpoint() {
    for (current_thread, sharded) in MODES {
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(20)));
        let timer = TimerDriverHandle::with_virtual_clock(clock);
        let runtime = builder(current_thread, sharded)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        for entry in [Entry::Request, Entry::CurrentRequest] {
            let started = std::time::Instant::now();
            let cx = drive(
                &runtime,
                entry,
                Budget::INFINITE.with_deadline(Time::from_millis(10)),
                poll_fn(|task_cx| {
                    let cx = Cx::current().unwrap();
                    // A worker may already have collected the due timer and
                    // still be dispatching its callback when this poll runs.
                    // Wait for that delivery without checkpoint enforcement.
                    if cx.is_cancel_requested() || started.elapsed() >= Duration::from_secs(2) {
                        Poll::Ready(cx)
                    } else {
                        task_cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }),
            );
            assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::Deadline);
            assert_eq!(timer.pending_count(), 0);
        }
    }
}

#[test]
fn request_construction_is_lazy_and_repeated_execution_keeps_one_deadline() {
    for (current_thread, sharded) in MODES {
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(100)));
        let timer = TimerDriverHandle::with_virtual_clock(clock);
        let runtime = builder(current_thread, sharded)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let cx =
            runtime.request_cx_with_budget(Budget::INFINITE.with_deadline(Time::from_millis(200)));
        assert_eq!(
            timer.pending_count(),
            0,
            "constructors do not start requests"
        );
        for _ in 0..2 {
            runtime.block_on_with_cx(cx.clone(), async {
                assert_eq!(timer.pending_count(), 1);
                assert_eq!(
                    Cx::current().unwrap().budget().deadline,
                    Some(Time::from_millis(200))
                );
            });
            assert_eq!(
                timer.pending_count(),
                1,
                "retained request keeps its original deadline"
            );
        }
        drop(cx);
        assert_eq!(
            timer.pending_count(),
            0,
            "dropping the request removes the timer"
        );

        for budget in [Budget::INFINITE, Budget::INFINITE.with_deadline(Time::MAX)] {
            for entry in [Entry::Request, Entry::CurrentRequest] {
                drive(&runtime, entry, budget, async {
                    assert_eq!(timer.pending_count(), 0);
                });
            }
        }
        assert!(runtime.is_quiescent());
    }
}

#[test]
fn normal_masked_requests_arm_but_prior_cancellation_does_not_start_a_timer() {
    for (current_thread, sharded) in MODES {
        let timer = TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::new()));
        let runtime = builder(current_thread, sharded)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let budget = Budget::INFINITE.with_deadline(Time::from_millis(50));
        let masked = runtime.request_cx_with_budget(budget);
        masked.masked(|| {
            runtime.block_on_with_cx(masked.clone(), async {
                assert_eq!(
                    timer.pending_count(),
                    1,
                    "a cancellation mask is not a cleanup exemption"
                );
            });
        });
        drop(masked);
        assert_eq!(timer.pending_count(), 0);

        let cancelled = runtime.request_cx_with_budget(budget);
        cancelled.cancel_with(CancelKind::User, Some("request already cancelled"));
        runtime.block_on_with_cx(cancelled.clone(), async {
            assert_eq!(timer.pending_count(), 0);
            assert_eq!(
                Cx::current().unwrap().cancel_reason().unwrap().kind,
                CancelKind::User
            );
        });
        assert_eq!(cancelled.cancel_reason().unwrap().kind, CancelKind::User);
    }
}

fn run_cleanup_adapters(runtime: &Runtime, timer: &TimerDriverHandle) {
    let cleanup = Cx::current().expect("real finalizer context");
    assert!(cleanup.inner.read().mask_depth > 0);
    assert!(
        cleanup.budget().deadline.is_some(),
        "infrastructure retains its deadline"
    );
    assert_eq!(timer.pending_count(), 0);
    runtime.block_on_with_cx(cleanup.clone(), async {
        assert_eq!(
            timer.pending_count(),
            0,
            "executing a finalizer must not arm it"
        );
        // A same-task scope must retain the exemption even though it has its
        // own cancellation envelope and may execute without the parent mask.
        Runtime::block_on_current_with_cx(cleanup.derive_cancel_scope(), async {
            assert_eq!(timer.pending_count(), 0);
        })
        .expect("nested cleanup adapter runtime");
    });
    assert_eq!(timer.pending_count(), 0);
}

#[test]
fn actual_scheduled_finalizers_keep_the_deadline_exemption_in_both_adapters() {
    for (current_thread, sharded) in MODES {
        let timer = TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::new()));
        let runtime = builder(current_thread, sharded)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let ran = Arc::new(AtomicBool::new(false));
        runtime.block_on(async {
            let child = Cx::current()
                .unwrap()
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let cleanup_runtime = runtime.clone();
            let cleanup_timer = timer.clone();
            let ran = Arc::clone(&ran);
            assert!(
                runtime
                    .inner
                    .state
                    .lock()
                    .unwrap()
                    .register_async_finalizer(child.region_id(), async move {
                        run_cleanup_adapters(&cleanup_runtime, &cleanup_timer);
                        ran.store(true, Ordering::SeqCst);
                    },)
            );
            child.close().await.unwrap();
        });
        assert!(
            ran.load(Ordering::SeqCst),
            "a real admitted finalizer was polled"
        );
        assert_eq!(timer.pending_count(), 0);
        assert!(runtime.is_quiescent());
    }
}

#[test]
fn actual_failed_start_inline_finalizers_keep_the_deadline_exemption() {
    let timer = TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::new()));
    let runtime = RuntimeBuilder::current_thread()
        .with_timer_driver(timer.clone())
        .build()
        .unwrap();
    let mut state = RuntimeState::new();
    state.set_timer_driver(timer.clone());
    let region = state.create_root_region(Budget::INFINITE);
    let ran = Arc::new(AtomicBool::new(false));
    let cleanup_ran = Arc::clone(&ran);
    let cleanup_timer = timer.clone();
    assert!(state.register_async_finalizer(region, async move {
        run_cleanup_adapters(&runtime, &cleanup_timer);
        cleanup_ran.store(true, Ordering::SeqCst);
    }));
    let record = state.region_mut(region).unwrap();
    assert!(record.begin_close(None));
    assert!(record.begin_finalize());
    assert!(state.drive_failed_start_async_finalizer_inline(region));
    assert!(
        ran.load(Ordering::SeqCst),
        "the real rollback finalizer was polled"
    );
    assert_eq!(timer.pending_count(), 0);
}
