//! Native exact-generation replacement journeys for the dynamic supervisor.
#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::pedantic, clippy::nursery)]

use asupersync::channel::{mpsc, oneshot};
use asupersync::cx::{
    Cx, DynamicChildReplacement, DynamicSupervisorConfig, DynamicSupervisorError,
    DynamicWorkerConfig,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::supervision::{
    BackoffStrategy, ManagedGeneration, ManagedRestartMode, RestartPolicy, SupervisionConfig,
};
use asupersync::types::Outcome;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};
use std::time::Duration;

fn policy() -> DynamicWorkerConfig {
    DynamicWorkerConfig::new(
        ManagedRestartMode::Temporary,
        SupervisionConfig::new(0, Duration::from_secs(60))
            .with_restart_policy(RestartPolicy::OneForOne)
            .with_backoff(BackoffStrategy::None),
    )
}

#[derive(Default)]
struct CleanupGate {
    open: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}

impl CleanupGate {
    async fn wait(&self) {
        poll_fn(|cx| {
            if self.open.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            let replacement = cx.waker().clone();
            let retired = self
                .waiter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .replace(replacement);
            drop(retired);
            if self.open.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }

    fn release(&self) {
        self.open.store(true, Ordering::Release);
        let waiter = self
            .waiter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}

async fn cancellation_worker(cx: Cx) -> Outcome<(), &'static str> {
    let (_keep_sender, mut stopped) = mpsc::channel::<()>(1);
    assert!(matches!(
        stopped.recv(&cx).await,
        Err(mpsc::RecvError::Cancelled)
    ));
    Outcome::Cancelled(cx.cancel_reason().expect("worker cancellation is attributed"))
}

fn runtime_case<F, Fut>(parallel: bool, case: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if parallel {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else {
        RuntimeBuilder::current_thread().build().unwrap()
    };
    runtime.block_on(async move {
        let cx = Cx::current().expect("native runtime installs a context");
        case(cx).await;
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
}

#[test]
fn replacement_waits_for_old_cleanup_and_stales_the_old_generation() {
    for parallel in [false, true] {
        runtime_case(parallel, |cx| async move {
            let mut owner = cx
                .open_dynamic_supervisor::<&'static str>(DynamicSupervisorConfig::new(1))
                .await
                .unwrap();
            let (started, mut start_witness) = oneshot::channel();
            let (cleaning, mut cleanup_witness) = oneshot::channel();
            let signals = Arc::new(Mutex::new(Some((started, cleaning))));
            let gate = Arc::new(CleanupGate::default());
            let old_gate = Arc::clone(&gate);
            let old_signals = Arc::clone(&signals);
            let old = owner
                .start_worker(
                    "service",
                    policy(),
                    move |worker: Cx, _: ManagedGeneration| {
                        let (started, cleaning) = old_signals
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                            .expect("temporary worker starts once");
                        let gate = Arc::clone(&old_gate);
                        async move {
                            started.send_blocking(()).unwrap();
                            let outcome = cancellation_worker(worker).await;
                            cleaning.send_blocking(()).unwrap();
                            gate.wait().await;
                            outcome
                        }
                    },
                )
                .await
                .unwrap();
            start_witness.recv(&cx).await.unwrap();

            let new_calls = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&new_calls);
            let (new_started, mut new_start_witness) = oneshot::channel();
            let new_started = Arc::new(Mutex::new(Some(new_started)));
            let replacement_signal = Arc::clone(&new_started);
            let mut replacement = Box::pin(owner.replace_worker(
                &old,
                policy(),
                move |worker: Cx, _: ManagedGeneration| {
                    counted.fetch_add(1, Ordering::SeqCst);
                    replacement_signal
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                        .expect("replacement factory starts once")
                        .send_blocking(())
                        .unwrap();
                    async move { cancellation_worker(worker).await }
                },
            ));

            poll_fn(|task| {
                assert!(
                    replacement.as_mut().poll(task).is_pending(),
                    "old asynchronous cleanup must delay replacement admission"
                );
                Poll::Ready(())
            })
            .await;
            cleanup_witness.recv(&cx).await.unwrap();
            assert_eq!(
                new_calls.load(Ordering::SeqCst),
                0,
                "replacement factory cannot run while old cleanup is held"
            );
            gate.release();

            let DynamicChildReplacement {
                previous,
                replacement,
            } = replacement.await.unwrap();
            assert!(previous.stop_requested);
            assert!(previous.close.is_ok());
            let old_report = previous.supervisor.unwrap();
            assert_eq!((old_report.started, old_report.joined), (1, 1));
            let new = replacement.unwrap();
            new_start_witness.recv(&cx).await.unwrap();
            assert_eq!(new_calls.load(Ordering::SeqCst), 1);
            assert_eq!(old.name(), new.name());
            assert_ne!(old.generation(), new.generation());
            assert_ne!(old.region_id(), new.region_id());
            assert!(matches!(
                owner.request_stop(&old),
                Err(DynamicSupervisorError::StaleChild)
            ));

            let stale_calls = Arc::new(AtomicUsize::new(0));
            let stale_counted = Arc::clone(&stale_calls);
            assert!(matches!(
                owner
                    .replace_worker(
                        &old,
                        policy(),
                        move |_: Cx, _: ManagedGeneration| {
                            stale_counted.fetch_add(1, Ordering::SeqCst);
                            async { Outcome::Ok(()) }
                        },
                    )
                    .await,
                Err(DynamicSupervisorError::StaleChild)
            ));
            assert_eq!(
                stale_calls.load(Ordering::SeqCst),
                0,
                "stale identity is refused before replacement factory invocation"
            );

            let completed = owner.terminate_child(&new).await.unwrap();
            assert!(completed.stop_requested);
            assert!(completed.close.is_ok());
            assert!(owner.is_empty());
            assert!(owner.shutdown().await.close.is_ok());
        });
    }
}

#[test]
fn failed_replacement_admission_preserves_the_old_completion_receipt() {
    for parallel in [false, true] {
        runtime_case(parallel, |cx| async move {
            let mut owner = cx
                .open_dynamic_supervisor::<&'static str>(DynamicSupervisorConfig::new(1))
                .await
                .unwrap();
            let (started, mut start_witness) = oneshot::channel();
            let started = Arc::new(Mutex::new(Some(started)));
            let old_started = Arc::clone(&started);
            let old = owner
                .start_worker(
                    "service",
                    policy(),
                    move |worker: Cx, _: ManagedGeneration| {
                        old_started
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                            .expect("old worker starts once")
                            .send_blocking(())
                            .unwrap();
                        async move { cancellation_worker(worker).await }
                    },
                )
                .await
                .unwrap();
            start_witness.recv(&cx).await.unwrap();

            let mut invalid = policy();
            invalid.supervision.storm_threshold = Some(f64::NAN);
            let calls = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&calls);
            let DynamicChildReplacement {
                previous,
                replacement,
            } = owner
                .replace_worker(
                    &old,
                    invalid,
                    move |_: Cx, _: ManagedGeneration| {
                        counted.fetch_add(1, Ordering::SeqCst);
                        async { Outcome::Ok(()) }
                    },
                )
                .await
                .unwrap();
            assert!(previous.stop_requested);
            assert!(previous.close.is_ok());
            assert_eq!(
                previous.supervisor.unwrap().joined,
                1,
                "old receipt survives replacement refusal"
            );
            assert!(matches!(
                replacement,
                Err(DynamicSupervisorError::WorkerConfiguration(_))
            ));
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "invalid replacement configuration cannot invoke its factory"
            );
            assert!(owner.is_empty(), "failed admission does not reserve the name");
            assert!(matches!(
                owner.request_stop(&old),
                Err(DynamicSupervisorError::StaleChild)
            ));

            let next = owner
                .start_worker(
                    "service",
                    policy(),
                    |_: Cx, _: ManagedGeneration| async { Outcome::Ok(()) },
                )
                .await
                .unwrap();
            assert_ne!(old.generation(), next.generation());
            assert_eq!(old.name(), next.name());
            assert!(owner.wait_child(&next).await.unwrap().close.is_ok());
            assert!(owner.shutdown().await.close.is_ok());
        });
    }
}
