//! Real native worker cancellation/restart with receive-side redelivery.
//! Gates witness actual Pending states; no sleeps choose the schedule.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::{ack, oneshot};
use asupersync::cx::{ChildRegionSpec, Cx, DynamicSupervisorConfig, DynamicWorkerConfig};
use asupersync::runtime::RuntimeBuilder;
use asupersync::supervision::{BackoffStrategy, ManagedGeneration, ManagedRestartMode, SupervisionConfig};
use asupersync::types::{Budget, Outcome};
use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

async fn witness_pending<F: Future>(future: F, observed: oneshot::Sender<()>) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut observed = Some(observed);
    poll_fn(|cx| {
        let result = future.as_mut().poll(cx);
        if result.is_pending() {
            if let Some(observed) = observed.take() { observed.send_blocking(()).unwrap(); }
        }
        result
    }).await
}

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(30))
        .expect("native acknowledged queue journey must finish including region close");
    thread.join().unwrap();
    if let Err(payload) = result { std::panic::resume_unwind(payload); }
}

async fn cancelled_delivery(cx: Cx) {
    let (tx, rx) = ack::channel(1);
    tx.send(&cx, String::from("retain this exact unfinished job")).await.unwrap();
    let worker_rx = rx.clone();
    let (observed, mut witness) = oneshot::channel();
    let (_keep_sender, mut blocked) = oneshot::channel::<()>();
    let mut worker = cx.spawn(move |worker| async move {
        let delivery = worker_rx.recv_with_ack(&worker).await.unwrap();
        let sequence = delivery.sequence();
        let result = witness_pending(blocked.recv(&worker), observed).await;
        assert!(matches!(result, Err(oneshot::RecvError::Cancelled)));
        drop(delivery); // settles Ack and returns the value before holder exit
        sequence
    }).unwrap();
    witness.recv(&cx).await.unwrap();
    assert_eq!((tx.stats().queued, tx.stats().in_flight), (0, 1));
    assert_eq!(tx.try_send(&cx, String::from("cannot bypass unfinished work")).unwrap_err().error, ack::QueueError::Full);
    worker.abort();
    let sequence = worker.join(&cx).await.expect("acknowledged cancellation preserves typed return");
    let replacement = rx.recv_with_ack(&cx).await.unwrap();
    assert_eq!(replacement.sequence(), sequence);
    assert_eq!(replacement.attempts(), 2);
    assert_eq!(replacement.ack(), "retain this exact unfinished job");
    tx.close_and_drain(&cx).await.unwrap();
    assert_eq!(tx.stats().unfinished(), 0);
    assert!(!tx.stats().abandoned);
}

async fn cancelled_producer(cx: Cx) {
    let (tx, rx) = ack::channel(1);
    tx.send(&cx, 7).await.unwrap();
    let held = rx.recv_with_ack(&cx).await.unwrap();
    let worker_tx = tx.clone();
    let (observed, mut witness) = oneshot::channel();
    let mut producer = cx.spawn(move |worker| async move {
        match witness_pending(worker_tx.reserve(&worker), observed).await {
            Err(error) => error,
            Ok(_) => panic!("unacknowledged delivery must retain the only credit"),
        }
    }).unwrap();
    witness.recv(&cx).await.unwrap();
    producer.abort();
    assert_eq!(producer.join(&cx).await.unwrap(), ack::QueueError::Cancelled);
    assert_eq!((tx.stats().queued, tx.stats().reserved, tx.stats().in_flight), (0, 0, 1));
    assert_eq!(held.ack(), 7);
    tx.close_and_drain(&cx).await.unwrap();
}

async fn supervised_panic(cx: Cx) {
    let (tx, rx) = ack::channel(1);
    tx.send(&cx, String::from("retry after a real worker panic")).await.unwrap();
    let mut supervisor = cx.open_dynamic_supervisor::<String>(DynamicSupervisorConfig::new(1)).await.unwrap();
    let policy = DynamicWorkerConfig::new(
        ManagedRestartMode::Transient,
        SupervisionConfig::new(1, Duration::from_secs(60)).with_backoff(BackoffStrategy::None),
    );
    let log = Arc::new(Mutex::new(Vec::new()));
    let worker_log = Arc::clone(&log);
    let worker_rx = rx.clone(); // keeper rx remains outside every worker generation
    let (observed, mut witness) = oneshot::channel();
    let observed = Arc::new(Mutex::new(Some(observed)));
    let (crash, crash_rx) = oneshot::channel::<()>();
    let crash_rx = Arc::new(Mutex::new(Some(crash_rx)));
    let child = supervisor.start_worker("retry-worker", policy, move |worker: Cx, generation: ManagedGeneration| {
        let rx = worker_rx.clone();
        let log = Arc::clone(&worker_log);
        let observed = Arc::clone(&observed);
        let crash_rx = Arc::clone(&crash_rx);
        async move {
            let delivery = rx.recv_with_ack(&worker).await.unwrap();
            log.lock().unwrap().push((delivery.sequence(), delivery.attempts(), generation.number));
            if generation.number == 1 {
                let mut crash_rx = crash_rx.lock().unwrap().take().unwrap();
                let observed = observed.lock().unwrap().take().unwrap();
                witness_pending(crash_rx.recv_uninterruptible(), observed).await.unwrap();
                panic!("native worker failed with an outstanding acknowledged-queue delivery");
            }
            assert_eq!(delivery.ack(), "retry after a real worker panic");
            Outcome::<(), String>::Ok(())
        }
    }).await.unwrap();
    witness.recv(&cx).await.unwrap();
    assert_eq!((tx.stats().queued, tx.stats().in_flight), (0, 1));
    // Seal before the crash: the redelivery must not require new send admission.
    tx.close();
    {
        let mut drain = std::pin::pin!(tx.wait_drained(&cx));
        poll_fn(|task| {
            assert!(drain.as_mut().poll(task).is_pending());
            Poll::Ready(())
        }).await;
    }
    crash.send_blocking(()).unwrap();
    let completion = supervisor.wait_child(&child).await.unwrap();
    assert!(completion.close.is_ok());
    let report = completion.supervisor.unwrap();
    assert_eq!((report.started, report.joined, report.restart_batches), (2, 2, 1));
    assert!(report.outcome.is_ok());
    assert!(report.children[0].outcome.is_ok());
    {
        let rows = log.lock().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, rows[1].0);
        assert_eq!((rows[0].1, rows[0].2, rows[1].1, rows[1].2), (1, 1, 2, 2));
    }
    tx.wait_drained(&cx).await.unwrap();
    assert!(!tx.stats().abandoned);
    assert!(supervisor.shutdown().await.close.is_ok());
}

fn journey(multithread: bool, scenario: u8) {
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else { RuntimeBuilder::current_thread().build().unwrap() };
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on_with_cx(owner.clone(), async move {
        let boundary = owner.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        // All checked item obligations belong to actual admitted tasks, not the
        // embedding thread's request context or an untracked testing context.
        let mut orchestrator = boundary.cx().spawn(move |cx| async move {
            match scenario {
                0 => cancelled_delivery(cx).await,
                1 => cancelled_producer(cx).await,
                2 => supervised_panic(cx).await,
                3 => bounded_poison_restarts(cx).await,
                4 => cancelled_receipt_observer(cx).await,
                5 => exhaustion_releases_native_backpressure(cx).await,
                _ => unreachable!(),
            }
        }).unwrap();
        orchestrator.join(&owner).await.unwrap();
        // The queue drain is not a replacement for the runtime ownership barrier.
        boundary.close().await.unwrap();
    });
}

#[test]
fn delivery_abort_redelivers_on_current_thread() { bounded(|| journey(false, 0)); }
#[test]
fn delivery_abort_redelivers_on_two_workers() { bounded(|| journey(true, 0)); }
#[test]
fn parked_producer_abort_releases_no_unowned_credit_current_thread() { bounded(|| journey(false, 1)); }
#[test]
fn parked_producer_abort_releases_no_unowned_credit_two_workers() { bounded(|| journey(true, 1)); }
#[test]
fn managed_worker_panic_retries_same_job_current_thread() { bounded(|| journey(false, 2)); }
#[test]
fn managed_worker_panic_retries_same_job_two_workers() { bounded(|| journey(true, 2)); }

fn delivery_limit(count: u64) -> ack::RetryPolicy {
    ack::RetryPolicy::limited(std::num::NonZeroU64::new(count).unwrap())
}

async fn bounded_poison_restarts(cx: Cx) {
    let (tx, rx) = ack::channel(2);
    let mut poison = tx.send_tracked_with_policy(&cx, String::from("poison"), delivery_limit(2)).await.unwrap();
    let mut healthy = tx.send_tracked(&cx, String::from("healthy")).await.unwrap();
    let poison_id = poison.sequence();
    let healthy_id = healthy.sequence();
    let mut supervisor = cx.open_dynamic_supervisor::<String>(DynamicSupervisorConfig::new(1)).await.unwrap();
    let policy = DynamicWorkerConfig::new(
        ManagedRestartMode::Transient,
        SupervisionConfig::new(2, Duration::from_secs(60)).with_backoff(BackoffStrategy::None),
    );
    let log = Arc::new(Mutex::new(Vec::new()));
    let worker_log = Arc::clone(&log);
    let worker_rx = rx.clone();
    let (observed, mut witness) = oneshot::channel();
    let observed = Arc::new(Mutex::new(Some(observed)));
    let (crash, crash_rx) = oneshot::channel::<()>();
    let crash_rx = Arc::new(Mutex::new(Some(crash_rx)));
    let child = supervisor.start_worker("bounded-retry-worker", policy, move |worker: Cx, generation: ManagedGeneration| {
        let rx = worker_rx.clone();
        let log = Arc::clone(&worker_log);
        let observed = Arc::clone(&observed);
        let crash_rx = Arc::clone(&crash_rx);
        async move {
            loop {
                let mut item = match rx.recv_with_ack(&worker).await {
                    Ok(item) => item,
                    Err(ack::QueueError::Closed) => return Outcome::Ok(()),
                    Err(error) => return Outcome::Err(format!("unexpected work refusal: {error}")),
                };
                log.lock().unwrap().push((item.sequence(), item.deliveries(), generation.number));
                if item.sequence() == healthy_id {
                    assert_eq!(item.ack(), "healthy");
                    continue;
                }
                assert_eq!(item.sequence(), poison_id);
                item.push('!');
                if generation.number == 1 {
                    let mut crash_rx = crash_rx.lock().unwrap().take().unwrap();
                    let observed = observed.lock().unwrap().take().unwrap();
                    witness_pending(crash_rx.recv_uninterruptible(), observed).await.unwrap();
                }
                // Real worker-future unwind, not an encoded Outcome::Panicked.
                // The second dropped delivery must return the job, not requeue it.
                panic!("native poison job failed while owning its tracked delivery");
            }
        }
    }).await.unwrap();
    witness.recv(&cx).await.unwrap();
    assert_eq!((tx.stats().queued, tx.stats().in_flight), (1, 1));
    assert!(poison.try_take().unwrap().is_none());
    assert!(healthy.try_take().unwrap().is_none());
    tx.close();
    crash.send_blocking(()).unwrap();
    let completion = supervisor.wait_child(&child).await.unwrap();
    assert!(completion.close.is_ok());
    let report = completion.supervisor.unwrap();
    assert_eq!((report.started, report.joined, report.restart_batches), (3, 3, 2));
    assert!(report.outcome.is_ok());
    assert!(report.children[0].outcome.is_ok());
    assert_eq!(
        *log.lock().unwrap(),
        vec![(poison_id, 1, 1), (healthy_id, 1, 2), (poison_id, 2, 2)],
    );
    let result = poison.wait(&cx).await.unwrap();
    assert_eq!((result.sequence, result.attempts, result.deliveries), (poison_id, 2, 2));
    assert!(matches!(result.outcome, ack::SettlementOutcome::RetryExhausted(value) if value == "poison!!"));
    let result = healthy.wait(&cx).await.unwrap();
    assert_eq!(result.sequence, healthy_id);
    assert!(matches!(result.outcome, ack::SettlementOutcome::Acknowledged));
    assert_eq!(tx.wait_drained(&cx).await, Err(ack::QueueError::Rejected));
    assert_eq!(tx.stats().unfinished(), 0);
    assert!(!tx.stats().abandoned);
    assert!(supervisor.shutdown().await.close.is_ok());
}

async fn cancelled_receipt_observer(cx: Cx) {
    let (tx, rx) = ack::channel(1);
    let mut receipt = tx.send_tracked_with_policy(&cx, String::from("return without cancellation loss"), delivery_limit(1)).await.unwrap();
    let sequence = receipt.sequence();
    let (observed, mut witness) = oneshot::channel();
    let mut observer = cx.spawn(move |observer| async move {
        let result = witness_pending(receipt.wait(&observer), observed).await;
        (receipt, result)
    }).unwrap();
    witness.recv(&cx).await.unwrap();
    // No worker owns the item: cancelling its receipt wait must not retract it.
    assert_eq!((tx.stats().queued, tx.stats().in_flight), (1, 0));
    observer.abort();
    let (mut receipt, result) = observer.join(&cx).await
        .expect("acknowledged observer cancellation preserves the owned receipt");
    assert_eq!(result.unwrap_err(), ack::ReceiptError::Cancelled);
    assert_eq!(receipt.sequence(), sequence);
    assert_eq!(tx.stats().queued, 1);
    let item = rx.recv_with_ack(&cx).await.unwrap();
    assert_eq!((item.sequence(), item.deliveries()), (sequence, 1));
    item.reject().unwrap();
    let result = receipt.wait(&cx).await.unwrap();
    assert!(matches!(result.outcome, ack::SettlementOutcome::Rejected(value) if value == "return without cancellation loss"));
    assert_eq!(tx.close_and_drain(&cx).await, Err(ack::QueueError::Rejected));
    assert!(!tx.stats().abandoned);
}

async fn exhaustion_releases_native_backpressure(cx: Cx) {
    let (tx, rx) = ack::channel(1);
    let mut poison = tx.send_tracked_with_policy(&cx, 71, delivery_limit(1)).await.unwrap();
    let held = rx.recv_with_ack(&cx).await.unwrap();
    let worker_tx = tx.clone();
    let (observed, mut witness) = oneshot::channel();
    let mut producer = cx.spawn(move |producer| async move {
        let permit = witness_pending(worker_tx.reserve(&producer), observed).await.unwrap();
        // Settle the send obligation before the producer exits. The returned
        // receipt is not itself an outstanding queue or runtime obligation.
        permit.send_tracked(73).unwrap()
    }).unwrap();
    witness.recv(&cx).await.unwrap();
    assert_eq!((tx.stats().queued, tx.stats().reserved, tx.stats().in_flight), (0, 0, 1));
    assert!(poison.try_take().unwrap().is_none());
    held.nack();
    let mut next = producer.join(&cx).await.unwrap();
    let result = poison.wait(&cx).await.unwrap();
    assert_eq!(result.deliveries, 1);
    assert!(matches!(result.outcome, ack::SettlementOutcome::RetryExhausted(71)));
    assert_eq!(rx.recv_with_ack(&cx).await.unwrap().ack(), 73);
    assert!(matches!(next.wait(&cx).await.unwrap().outcome, ack::SettlementOutcome::Acknowledged));
    assert_eq!(tx.close_and_drain(&cx).await, Err(ack::QueueError::Rejected));
    assert_eq!(tx.stats().unfinished(), 0);
}

#[test]
fn poison_budget_returns_payload_after_real_worker_restarts_current_thread() { bounded(|| journey(false, 3)); }
#[test]
fn poison_budget_returns_payload_after_real_worker_restarts_two_workers() { bounded(|| journey(true, 3)); }
#[test]
fn parked_receipt_abort_preserves_work_and_resumable_receipt_current_thread() { bounded(|| journey(false, 4)); }
#[test]
fn parked_receipt_abort_preserves_work_and_resumable_receipt_two_workers() { bounded(|| journey(true, 4)); }
#[test]
fn retry_exhaustion_wakes_a_parked_producer_current_thread() { bounded(|| journey(false, 5)); }
#[test]
fn retry_exhaustion_wakes_a_parked_producer_two_workers() { bounded(|| journey(true, 5)); }
