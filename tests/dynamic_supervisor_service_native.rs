//! Public native-runtime journeys. A host watchdog bounds a stuck regression;
//! it is not a runtime cancellation or arbitrary-finalizer responsiveness claim.

use asupersync::channel::{mpsc, oneshot};
use asupersync::cx::supervisor_service::DynamicServiceError;
use asupersync::cx::{Cx, DynamicSupervisorConfig, DynamicWorkerConfig};
use asupersync::runtime::RuntimeBuilder;
use asupersync::supervision::{BackoffStrategy, ManagedGeneration, ManagedRestartMode, SupervisionConfig};
use asupersync::types::{Budget, Outcome};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn config() -> DynamicWorkerConfig {
    DynamicWorkerConfig::new(ManagedRestartMode::Temporary,
        SupervisionConfig::new(0, Duration::from_secs(60)).with_backoff(BackoffStrategy::None))
}

fn journey(multithread: bool) {
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else {
        RuntimeBuilder::current_thread().build().unwrap()
    };
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on_with_cx(cx.clone(), async move {
        let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox::<String>(
            DynamicSupervisorConfig::new(8), 8).unwrap();
        let executed = Arc::new(AtomicUsize::new(0));
        let mut callers = Vec::new();
        for index in 0..4 {
            let client = client.clone();
            let executed = Arc::clone(&executed);
            callers.push(cx.spawn(move |caller_cx| async move {
                let mut admission = client.submit_worker(&caller_cx, format!("request-{index}"), config(),
                    move |_: Cx, _: ManagedGeneration| {
                        let executed = Arc::clone(&executed);
                        async move {
                            asupersync::runtime::yield_now().await;
                            executed.fetch_add(1, Ordering::SeqCst);
                            Outcome::Err(format!("domain-{index}"))
                        }
                    }).unwrap();
                let mut child = admission.admitted(&caller_cx).await.unwrap();
                let id = child.id().clone();
                let result = child.join().await.unwrap();
                assert_eq!(result.id, id);
                assert!(result.close.is_ok());
                let report = result.supervisor.unwrap();
                assert_eq!((report.started, report.joined), (1, 1));
                assert!(matches!(&report.children[0].outcome,
                    Outcome::Err(message) if message == &format!("domain-{index}")));
            }).unwrap());
        }
        for mut caller in callers { caller.join(&cx).await.unwrap(); }
        assert_eq!(executed.load(Ordering::SeqCst), 4);

        let (ready, mut ready_rx) = oneshot::channel();
        let (release, receiver) = mpsc::channel::<()>(1);
        let setup = Arc::new(Mutex::new(Some((ready, receiver))));
        let cleanup = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&cleanup);
        let mut admission = client.submit_worker(&cx, "drain-preserves-work", config(),
            move |worker_cx: Cx, _: ManagedGeneration| {
                let (ready, mut receiver) = setup.lock().unwrap().take().unwrap();
                let count = Arc::clone(&count);
                async move {
                    ready.send_blocking(()).unwrap();
                    receiver.recv(&worker_cx).await.expect("graceful drain does not cancel this worker");
                    // Real application cleanup, not a claimed runtime-registered finalizer.
                    asupersync::runtime::yield_now().await;
                    count.fetch_add(1, Ordering::SeqCst);
                    Outcome::Ok(())
                }
            }).unwrap();
        let mut child = admission.admitted(&cx).await.unwrap();
        ready_rx.recv(&cx).await.unwrap();
        service.begin_drain();
        assert!(matches!(client.submit_worker(&cx, "late", config(),
            |_: Cx, _: ManagedGeneration| async { Outcome::Ok(()) }), Err(DynamicServiceError::Closed)));
        release.try_send(()).unwrap();
        let completion = child.join().await.unwrap();
        assert!(!completion.stop_requested);
        assert!(completion.close.is_ok());
        assert!(completion.supervisor.unwrap().children[0].outcome.is_ok());
        assert_eq!(cleanup.load(Ordering::SeqCst), 1);
        let report = service.join().await.unwrap();
        assert!(report.task_outcome.is_ok());
        let owner = report.supervision.unwrap();
        assert!(owner.children.is_empty());
        assert!(owner.close.is_ok());
    });
}

fn watched(multithread: bool) {
    let (done, result) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(|| journey(multithread));
        let _ = done.send(outcome);
    });
    let outcome = result.recv_timeout(Duration::from_secs(30))
        .expect("native service journey did not complete within host watchdog");
    worker.join().expect("watchdog worker terminated");
    if let Err(payload) = outcome { std::panic::resume_unwind(payload); }
}

#[test]
fn current_thread_service_runs_independent_callers_and_gracefully_drains() { watched(false); }

#[test]
fn two_worker_service_runs_independent_callers_and_gracefully_drains() { watched(true); }
