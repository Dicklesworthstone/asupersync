#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use crate::runtime::blocking_pool::{BlockingPoolOptions, BlockingQueuePolicy};
use crate::runtime::config::BlockingPoolAffinityProfile;
use crate::runtime::{JoinError, RootDrainOutcome, RuntimeBuilder};
use std::sync::atomic::AtomicUsize;
use std::sync::{Barrier, Weak, mpsc};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(5);

fn policy(capacity: usize) -> BlockingAdmissionPolicy {
    BlockingAdmissionPolicy::Bounded {
        max_queued: NonZeroUsize::new(capacity).unwrap(),
    }
}

fn pool(capacity: usize) -> BlockingPool {
    BlockingPool::with_config_and_policies(
        1,
        1,
        BlockingPoolOptions {
            thread_name_prefix: "bounded-admission".to_owned(),
            ..Default::default()
        },
        BlockingQueuePolicy::Fifo,
        policy(capacity),
    )
}

fn hold_worker(pool: &BlockingPoolHandle) -> (BlockingTaskHandle, mpsc::Sender<()>) {
    let (entered, entry) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let task = pool
        .try_spawn(move || {
            entered.send(()).unwrap();
            gate.recv_timeout(WAIT).unwrap();
        })
        .unwrap();
    entry.recv_timeout(WAIT).unwrap();
    (task, release)
}

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(30))
        .expect("bounded blocking admission scenario must terminate");
    thread.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

struct CaptureProbe {
    pool: BlockingPoolHandle,
    drops: Arc<AtomicUsize>,
}

impl Drop for CaptureProbe {
    fn drop(&mut self) {
        // Actual reentry would deadlock if destruction held either mutex.
        let _ = self.pool.try_spawn(|| {});
        let _waiter_count = self.pool.inner.admission.waiters.lock().len();
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

struct WakeProbe {
    pool: Weak<BlockingPoolInner>,
    signal: mpsc::Sender<()>,
}

impl std::task::Wake for WakeProbe {
    fn wake(self: Arc<Self>) {
        if let Some(pool) = self.pool.upgrade() {
            // Real lock acquisition tolerates other threads holding them and
            // detects same-thread wake-under-lock by the outer test timeout.
            drop(pool.mutex.lock());
            drop(pool.admission.waiters.lock());
        }
        self.signal.send(()).unwrap();
    }
}

fn wake_probe(pool: &BlockingPool) -> (Waker, mpsc::Receiver<()>) {
    let (signal, receive) = mpsc::channel();
    let waker = Waker::from(Arc::new(WakeProbe {
        pool: Arc::downgrade(&pool.inner),
        signal,
    }));
    (waker, receive)
}

#[test]
fn refusal_recovers_work_and_running_jobs_do_not_consume_queue_capacity() {
    bounded(|| {
        let pool = pool(1);
        let (running, release) = hold_worker(&pool.handle());
        let queued = pool.try_spawn(|| {}).unwrap();
        assert_eq!(pool.pending_count(), 1);
        assert_eq!(pool.busy_threads(), 1);

        let drops = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let capture = CaptureProbe {
            pool: pool.handle(),
            drops: Arc::clone(&drops),
        };
        let called = Arc::clone(&calls);
        let rejected = pool
            .try_spawn(move || {
                called.fetch_add(1, Ordering::SeqCst);
                drop(capture);
            })
            .unwrap_err();
        assert_eq!(rejected.kind(), BlockingSpawnErrorKind::Saturated);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(pool.pending_count(), 1);

        let old_api_called = Arc::clone(&calls);
        let refused = pool.spawn(move || {
            old_api_called.fetch_add(100, Ordering::SeqCst);
        });
        assert!(refused.is_cancelled());
        assert!(refused.is_done());
        assert_eq!(pool.pending_count(), 1);

        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        let retried = pool.try_spawn(rejected.into_inner()).unwrap();
        assert!(retried.wait_timeout(WAIT));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(
            pool.try_spawn(|| {}).unwrap_err().kind(),
            BlockingSpawnErrorKind::Shutdown
        );
    });
}

#[test]
fn waiting_submission_parks_and_resumes_after_dequeue() {
    bounded(|| {
        let pool = pool(1);
        let (running, release) = hold_worker(&pool.handle());
        let queued = pool.try_spawn(|| {}).unwrap();
        let called = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&called);
        let mut submission = pool.submit(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let (waker, wake) = wake_probe(&pool);
        let mut context = Context::from_waker(&waker);
        assert!(Pin::new(&mut submission).poll(&mut context).is_pending());
        assert!(Pin::new(&mut submission).poll(&mut context).is_pending());
        assert_eq!(pool.inner.admission.waiters.lock().len(), 1);
        assert!(matches!(wake.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert_eq!(called.load(Ordering::SeqCst), 0);

        release.send(()).unwrap();
        wake.recv_timeout(WAIT).unwrap();
        let accepted = futures_lite::future::block_on(submission).unwrap();
        assert!(accepted.wait_timeout(WAIT));
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        assert_eq!(called.load(Ordering::SeqCst), 1);
        assert!(pool.inner.admission.waiters.lock().is_empty());
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn dropping_a_waiting_submission_removes_registration_and_retires_work_outside_locks() {
    bounded(|| {
        let pool = pool(1);
        let (running, release) = hold_worker(&pool.handle());
        let queued = pool.try_spawn(|| {}).unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let capture = CaptureProbe {
            pool: pool.handle(),
            drops: Arc::clone(&drops),
        };
        let mut submission = pool.submit(move || drop(capture));
        let mut context = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut submission).poll(&mut context).is_pending());
        assert_eq!(pool.inner.admission.waiters.lock().len(), 1);
        drop(submission);
        assert!(pool.inner.admission.waiters.lock().is_empty());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(pool.pending_count(), 1);
        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn shutdown_wakes_waiting_submission_and_returns_its_uninvoked_work() {
    bounded(|| {
        let pool = pool(1);
        let (running, release) = hold_worker(&pool.handle());
        let queued = pool.try_spawn(|| {}).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        let mut submission = pool.submit(move || {
            called.fetch_add(1, Ordering::SeqCst);
        });
        let (waker, wake) = wake_probe(&pool);
        assert!(
            Pin::new(&mut submission)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        pool.shutdown();
        wake.recv_timeout(WAIT).unwrap();
        let refused = futures_lite::future::block_on(submission).unwrap_err();
        assert_eq!(refused.kind(), BlockingSpawnErrorKind::Shutdown);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(pool.inner.admission.waiters.lock().is_empty());
        refused.into_inner()();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn concurrent_cohort_submissions_share_one_hard_queue_bound() {
    bounded(|| {
        let pool = BlockingPool::with_config_and_policies(
            1,
            1,
            BlockingPoolOptions {
                affinity_profile: BlockingPoolAffinityProfile::CohortBiased {
                    local_queue_soft_limit: 1,
                    spill_check_interval: 1,
                },
                cohort_count: Some(2),
                ..Default::default()
            },
            BlockingQueuePolicy::Fifo,
            policy(3),
        );
        let (running, release) = hold_worker(&pool.handle());
        let start = Arc::new(Barrier::new(9));
        let results = std::thread::scope(|scope| {
            let submitters: Vec<_> = (0..8)
                .map(|index| {
                    let handle = pool.handle();
                    let start = Arc::clone(&start);
                    scope.spawn(move || {
                        start.wait();
                        handle
                            .try_spawn_on_cohort_with_priority(index % 2, || {}, 128)
                            .map_err(|error| error.kind())
                    })
                })
                .collect();
            start.wait();
            submitters
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 3);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(BlockingSpawnErrorKind::Saturated)))
                .count(),
            5
        );
        assert_eq!(pool.pending_count(), 3);
        let metrics = pool.affinity_metrics();
        assert_eq!(
            metrics.global_pending_count + metrics.cohort_pending_counts.iter().sum::<usize>(),
            3
        );
        release.send(()).unwrap();
        for task in results.into_iter().filter_map(Result::ok) {
            assert!(task.wait_timeout(WAIT));
        }
        assert!(running.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn bounded_cohort_queue_keeps_priority_selection() {
    bounded(|| {
        let pool = BlockingPool::with_config_and_policies(
            1,
            1,
            BlockingPoolOptions {
                affinity_profile: BlockingPoolAffinityProfile::CohortBiased {
                    local_queue_soft_limit: 4,
                    spill_check_interval: 8,
                },
                cohort_count: Some(1),
                ..Default::default()
            },
            BlockingQueuePolicy::Priority {
                max_priority_streak: NonZeroUsize::new(4).unwrap(),
            },
            policy(2),
        );
        let (running, release) = hold_worker(&pool.handle());
        let (order, received) = mpsc::channel();
        let low_sender = order.clone();
        let low = pool
            .try_spawn_on_cohort_with_priority(0, move || low_sender.send(1).unwrap(), 1)
            .unwrap();
        let high = pool
            .try_spawn_on_cohort_with_priority(0, move || order.send(200).unwrap(), 200)
            .unwrap();
        assert_eq!(
            pool.try_spawn(|| {}).unwrap_err().kind(),
            BlockingSpawnErrorKind::Saturated
        );
        release.send(()).unwrap();
        assert_eq!(received.recv_timeout(WAIT).unwrap(), 200);
        assert_eq!(received.recv_timeout(WAIT).unwrap(), 1);
        assert!(low.wait_timeout(WAIT));
        assert!(high.wait_timeout(WAIT));
        assert!(running.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn ordinary_async_blocking_waits_for_capacity_without_inline_or_fallback_execution() {
    bounded(|| {
        struct PinnedCapture {
            _pin: std::marker::PhantomPinned,
        }
        let pool = pool(1);
        let (running, release) = hold_worker(&pool.handle());
        let queued = pool.try_spawn(|| {}).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        let pinned = PinnedCapture {
            _pin: std::marker::PhantomPinned,
        };
        let mut operation = Box::pin(crate::runtime::spawn_blocking::spawn_blocking_on_pool(
            pool.handle(),
            move || {
                let _pinned = std::hint::black_box(pinned);
                called.fetch_add(1, Ordering::SeqCst);
                std::thread::current().name().unwrap().to_owned()
            },
        ));
        assert!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(pool.inner.admission.waiters.lock().len(), 1);
        release.send(()).unwrap();
        let thread_name = futures_lite::future::block_on(operation);
        assert!(
            thread_name.starts_with("bounded-admission-blocking-"),
            "{thread_name}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn drained_cancellation_retains_waiting_captures_until_a_blocking_worker_retires_them() {
    bounded(|| {
        for workers in [1, 2] {
            let builder = if workers == 1 {
                RuntimeBuilder::current_thread()
            } else {
                RuntimeBuilder::new().worker_threads(workers)
            };
            let runtime = builder
                .enable_platform_reactor(false)
                .blocking_threads(1, 1)
                .blocking_admission_policy(policy(1))
                .build()
                .unwrap();
            let pool = runtime.blocking_handle().unwrap();
            assert_eq!(pool.admission_policy(), policy(1));
            let (running, release_pool) = hold_worker(&pool);
            let queued = pool.try_spawn(|| {}).unwrap();
            let (dropping, drop_entered) = mpsc::channel();
            let (release_drop, drop_gate) = mpsc::channel();
            let drops = Arc::new(AtomicUsize::new(0));
            struct BlockingCapture {
                dropping: mpsc::Sender<String>,
                gate: mpsc::Receiver<()>,
                drops: Arc<AtomicUsize>,
            }
            impl Drop for BlockingCapture {
                fn drop(&mut self) {
                    self.dropping
                        .send(std::thread::current().name().unwrap().to_owned())
                        .unwrap();
                    self.gate.recv_timeout(WAIT).unwrap();
                    self.drops.fetch_add(1, Ordering::SeqCst);
                }
            }
            let capture = BlockingCapture {
                dropping,
                gate: drop_gate,
                drops: Arc::clone(&drops),
            };
            let calls = Arc::new(AtomicUsize::new(0));
            let called = Arc::clone(&calls);
            let mut task = runtime
                .spawn_blocking_drained(move |_| {
                    called.fetch_add(1, Ordering::SeqCst);
                    drop(capture);
                    42_u8
                })
                .unwrap();
            runtime.block_on(async {
                let deadline = Instant::now() + WAIT;
                while pool.inner.admission.waiters.lock().is_empty() {
                    assert!(
                        Instant::now() < deadline,
                        "drained work must reach pending admission"
                    );
                    crate::runtime::yield_now::yield_now().await;
                }
            });
            task.abort_with_reason(crate::types::CancelReason::user(
                "cancel while awaiting pool capacity",
            ));
            let report = runtime.shutdown_drained(Duration::from_millis(20));
            assert_eq!(report.outcome, RootDrainOutcome::TimedOut, "{report:?}");
            assert!(report.live_tasks > 0);
            assert!(!task.is_finished());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            assert!(matches!(
                drop_entered.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));

            release_pool.send(()).unwrap();
            // Releasing capacity only wakes the admission future. Keep driving
            // a current-thread runtime until that future publishes the cancelled
            // envelope and its capture destructor actually starts.
            let deadline = Instant::now() + WAIT;
            let drop_thread = loop {
                match drop_entered.try_recv() {
                    Ok(thread) => break thread,
                    Err(mpsc::TryRecvError::Empty) => {
                        assert!(Instant::now() < deadline, "capture retirement must start");
                        let report = runtime.shutdown_drained(Duration::from_millis(1));
                        assert_eq!(report.outcome, RootDrainOutcome::TimedOut, "{report:?}");
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        panic!("capture retirement sender disappeared");
                    }
                }
            };
            assert!(drop_thread.contains("-blocking-"), "{drop_thread}");
            assert_eq!(pool.busy_threads(), 1);
            let report = runtime.shutdown_drained(Duration::from_millis(20));
            assert_eq!(report.outcome, RootDrainOutcome::TimedOut, "{report:?}");
            assert!(
                !task.is_finished(),
                "drain must wait for capture destruction"
            );
            release_drop.send(()).unwrap();
            let report = runtime.shutdown_drained(WAIT);
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
            assert!(matches!(
                futures_lite::future::block_on(task.join()),
                Err(JoinError::Cancelled(_))
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(running.wait_timeout(WAIT));
            assert!(queued.wait_timeout(WAIT));
        }
    });
}
