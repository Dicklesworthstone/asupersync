//! Public dynamic-worker journeys on native current-thread and parallel runtimes.
//! No test double replaces the scheduler, admission, channels or managed driver.

#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::mpsc;
use asupersync::cx::{Cx, DynamicSupervisorConfig, DynamicWorkerConfig};
use asupersync::runtime::RuntimeBuilder;
use asupersync::supervision::{
    BackoffStrategy, ManagedGeneration, ManagedRestartMode, RestartPolicy, SupervisionConfig,
};
use asupersync::types::{Budget, Outcome};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn policy() -> DynamicWorkerConfig {
    DynamicWorkerConfig::new(
        ManagedRestartMode::Transient,
        SupervisionConfig::new(2, Duration::from_secs(60))
            .with_restart_policy(RestartPolicy::OneForOne)
            .with_backoff(BackoffStrategy::None),
    )
}

fn native_journey(parallel: bool) {
    let runtime = if parallel {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else {
        RuntimeBuilder::current_thread().build().unwrap()
    };
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on_with_cx(cx.clone(), async move {
        let mut controller = cx.spawn(|cx| async move {
            let mut owner = cx.open_dynamic_supervisor::<&'static str>(
                DynamicSupervisorConfig::new(2),
            ).await.unwrap();
            let (ready_tx, mut ready_rx) = mpsc::channel::<ManagedGeneration>(1);
            let calls = Arc::new(AtomicUsize::new(0));
            let retired = Arc::new(AtomicUsize::new(0));
            let worker_calls = Arc::clone(&calls);
            let worker_retired = Arc::clone(&retired);
            let service = owner.start_worker("service", policy(), move |cx: Cx, generation: ManagedGeneration| {
                let ready = ready_tx.clone();
                let retired = Arc::clone(&worker_retired);
                worker_calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    let (_keep_sender, mut stop) = mpsc::channel::<()>(1);
                    ready.send(&cx, generation).await.unwrap();
                    let error = stop.recv(&cx).await.expect_err("service ends through cancellation");
                    assert!(matches!(error, mpsc::RecvError::Cancelled));
                    // Actual asynchronous application cleanup, not a fabricated
                    // native region-finalizer receipt.
                    asupersync::runtime::yield_now().await;
                    retired.fetch_add(1, Ordering::SeqCst);
                    Outcome::Cancelled(cx.cancel_reason().expect("retained cancellation attribution"))
                }
            }).await.unwrap();
            let real_generation = ready_rx.recv(&cx).await.unwrap();
            assert_eq!(real_generation.number, 1);
            assert_ne!(real_generation.task, cx.task_id());
            let restarting = owner.start_worker("retry", policy(), |_: Cx, generation: ManagedGeneration| async move {
                if generation.number == 1 { Outcome::Err("transient native failure") }
                else { Outcome::Ok(()) }
            }).await.unwrap();
            let finished = owner.wait_child(&restarting).await.unwrap();
            assert!(finished.close.is_ok());
            let report = finished.supervisor.unwrap();
            assert!(report.outcome.is_ok());
            assert_eq!(report.started, 2);
            assert_eq!(report.joined, 2);
            assert_eq!(report.restart_batches, 1);
            assert_eq!(report.children[0].generation.number, 2);
            assert_eq!(calls.load(Ordering::SeqCst), 1, "other worker's restarts stay isolated");
            assert_eq!(retired.load(Ordering::SeqCst), 0);
            let group = owner.terminate_children(&[service]).await.unwrap();
            assert_eq!(group.len(), 1);
            let stopped = group.into_iter().next().unwrap().unwrap();
            assert!(stopped.stop_requested);
            assert!(stopped.close.is_ok());
            let report = stopped.supervisor.unwrap();
            assert_eq!(report.started, 1);
            assert_eq!(report.joined, 1);
            assert_eq!(report.restart_batches, 0);
            assert_eq!(retired.load(Ordering::SeqCst), 1);
            assert!(owner.is_empty());
            let shutdown = owner.shutdown().await;
            assert!(shutdown.close.is_ok());
        }).unwrap();
        controller.join(&cx).await.unwrap();
    });
}

#[test]
fn native_current_thread_dynamic_workers_restart_and_drain() {
    native_journey(false);
}

#[test]
fn native_parallel_dynamic_workers_restart_and_drain() {
    native_journey(true);
}
