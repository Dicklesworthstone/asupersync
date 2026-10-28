//! Native witnesses for opt-in blocking priorities and unchanged FIFO defaults.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::runtime::config::BlockingPoolAffinityProfile;
use asupersync::runtime::{
    BlockingPool, BlockingPoolHandle, BlockingPoolOptions, BlockingQueuePolicy, BlockingTaskHandle,
    RuntimeBuilder,
};
use asupersync::types::Budget;
use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(5);

fn priority_policy(streak: usize) -> BlockingQueuePolicy {
    BlockingQueuePolicy::Priority {
        max_priority_streak: NonZeroUsize::new(streak).unwrap(),
    }
}

/// Release on panic as well, so failed assertions cannot strand the worker.
struct HeldWorker {
    release: Option<mpsc::Sender<()>>,
    task: BlockingTaskHandle,
}

impl Drop for HeldWorker {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        let _ = self.task.wait_timeout(WAIT);
    }
}

fn hold_worker(pool: &BlockingPoolHandle) -> HeldWorker {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let task = pool.spawn(move || {
        let _ = started_tx.send(());
        let _ = release_rx.recv();
    });
    let held = HeldWorker {
        release: Some(release_tx),
        task,
    };
    started_rx.recv_timeout(WAIT).expect("worker starts");
    held
}

fn receive_order(rx: &mpsc::Receiver<&'static str>, count: usize) -> Vec<&'static str> {
    (0..count)
        .map(|_| rx.recv_timeout(WAIT).expect("queued task executes"))
        .collect()
}

#[test]
fn existing_constructors_keep_fifo_even_with_priority_metadata() {
    let pool = BlockingPool::with_config(1, 1, BlockingPoolOptions::default());
    let handle = pool.handle();
    assert_eq!(pool.queue_policy(), BlockingQueuePolicy::Fifo);
    assert_eq!(handle.queue_policy(), BlockingQueuePolicy::Fifo);
    let held = hold_worker(&handle);
    let (tx, rx) = mpsc::channel();
    for (priority, label) in [(0, "first"), (255, "second"), (128, "third")] {
        let tx = tx.clone();
        handle.spawn_with_priority(move || tx.send(label).unwrap(), priority);
    }
    drop(held);
    assert_eq!(receive_order(&rx, 3), ["first", "second", "third"]);
    assert!(pool.shutdown_and_wait(WAIT));
    assert_eq!(pool.pending_count(), 0);
}

#[test]
fn opt_in_priorities_prefer_urgent_work_and_preserve_fifo_ties() {
    let policy = priority_policy(8);
    let pool =
        BlockingPool::with_config_and_queue_policy(1, 1, BlockingPoolOptions::default(), policy);
    let handle = pool.handle();
    assert_eq!(pool.queue_policy(), policy);
    assert_eq!(handle.queue_policy(), policy);
    let held = hold_worker(&handle);
    let (tx, rx) = mpsc::channel();
    let low_tx = tx.clone();
    let low = pool.spawn_with_priority(move || low_tx.send("low").unwrap(), 0);
    let high_a_tx = tx.clone();
    let high_a = handle.spawn_with_priority(move || high_a_tx.send("high-a").unwrap(), 255);
    let high_b = pool.spawn_with_priority(move || tx.send("high-b").unwrap(), 255);
    drop(held);
    assert_eq!(receive_order(&rx, 3), ["high-a", "high-b", "low"]);
    for task in [low, high_a, high_b] {
        assert!(task.wait_timeout(WAIT));
    }
    assert!(pool.shutdown_and_wait(WAIT));
}

#[test]
fn lower_priority_classes_run_while_high_and_low_backlogs_remain() {
    let pool = BlockingPool::with_config_and_queue_policy(
        1,
        1,
        BlockingPoolOptions::default(),
        priority_policy(2),
    );
    let handle = pool.handle();
    let held = hold_worker(&handle);
    let (tx, rx) = mpsc::channel();
    for _ in 0..32 {
        let high_tx = tx.clone();
        handle.spawn_with_priority(move || high_tx.send("high").unwrap(), 255);
        let low_tx = tx.clone();
        handle.spawn_with_priority(move || low_tx.send("low").unwrap(), 0);
    }
    handle.spawn_with_priority(move || tx.send("middle").unwrap(), 127);
    drop(held);
    let first = receive_order(&rx, 6);
    assert!(
        first.contains(&"low"),
        "lowest class must receive a fairness turn"
    );
    assert!(
        first.contains(&"middle"),
        "a busy lowest class must not monopolize fairness"
    );
    assert!(pool.shutdown_and_wait(WAIT));
    assert_eq!(pool.pending_count(), 0);
}

#[test]
fn cohort_priority_selection_preserves_foreign_cohort_progress() {
    let pool = BlockingPool::with_config_and_queue_policy(
        1,
        1,
        BlockingPoolOptions {
            affinity_profile: BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 128,
                spill_check_interval: 2,
            },
            cohort_count: Some(2),
            ..Default::default()
        },
        priority_policy(8),
    );
    let handle = pool.handle();
    let held = hold_worker(&handle);
    let (tx, rx) = mpsc::channel();
    for _ in 0..48 {
        let tx = tx.clone();
        handle.spawn_on_cohort(0, move || tx.send("local").unwrap());
    }
    let low_tx = tx.clone();
    pool.spawn_on_cohort_with_priority(1, move || low_tx.send("foreign-low").unwrap(), 0);
    handle.spawn_on_cohort_with_priority(1, move || tx.send("foreign-high").unwrap(), 255);
    drop(held);
    let order = receive_order(&rx, 50);
    let high = order
        .iter()
        .position(|&label| label == "foreign-high")
        .unwrap();
    let low = order
        .iter()
        .position(|&label| label == "foreign-low")
        .unwrap();
    assert!(
        high < 17,
        "foreign cohort must be visited while local work remains"
    );
    assert!(
        high < low,
        "foreign queue must honor explicit task priority"
    );
    assert!(
        low < 34,
        "foreign turns must continue after the first selection"
    );
    assert!(pool.shutdown_and_wait(WAIT));
    assert_eq!(pool.pending_count(), 0);
    let metrics = pool.affinity_metrics();
    assert_eq!(metrics.cohort_pending_counts, [0, 0]);
    assert_eq!(metrics.global_pending_count, 0);
}

struct SubmitOnDrop {
    pool: BlockingPoolHandle,
    tx: mpsc::Sender<&'static str>,
}

impl Drop for SubmitOnDrop {
    fn drop(&mut self) {
        let tx = self.tx.clone();
        self.pool
            .spawn_with_priority(move || tx.send("drop-child").unwrap(), 255);
    }
}

#[test]
fn cancelling_priority_work_drops_captures_outside_queue_locks() {
    // A locking regression may strand a worker holding the admission mutex.
    // On a failed assertion, do not hang again in BlockingPool::drop; drop the
    // pool explicitly only after the witness has completed and shut down.
    let pool = std::mem::ManuallyDrop::new(BlockingPool::with_config_and_queue_policy(
        1,
        1,
        BlockingPoolOptions::default(),
        priority_policy(8),
    ));
    let handle = pool.handle();
    let held = hold_worker(&handle);
    let (tx, rx) = mpsc::channel();
    let ran = Arc::new(AtomicBool::new(false));
    let ran_task = Arc::clone(&ran);
    let capture = SubmitOnDrop {
        pool: handle.clone(),
        tx,
    };
    let cancelled = handle.spawn_with_priority(
        move || {
            ran_task.store(true, Ordering::Release);
            drop(capture);
        },
        255,
    );
    cancelled.cancel();
    drop(held);
    assert!(
        cancelled.wait_timeout(WAIT),
        "capture destruction must complete"
    );
    assert_eq!(rx.recv_timeout(WAIT).unwrap(), "drop-child");
    assert!(!ran.load(Ordering::Acquire));
    assert!(cancelled.is_cancelled());
    assert!(pool.shutdown_and_wait(WAIT));
    assert_eq!(pool.pending_count(), 0);
    drop(std::mem::ManuallyDrop::into_inner(pool));
}

#[test]
fn priority_shutdown_drains_accepted_work_and_rejects_new_work() {
    let pool = BlockingPool::with_config_and_queue_policy(
        1,
        1,
        BlockingPoolOptions::default(),
        priority_policy(2),
    );
    let handle = pool.handle();
    let held = hold_worker(&handle);
    let (tx, rx) = mpsc::channel();
    let low_tx = tx.clone();
    let low = handle.spawn_with_priority(move || low_tx.send("low").unwrap(), 0);
    let high = handle.spawn_with_priority(move || tx.send("high").unwrap(), 255);
    let panicked = handle.spawn_with_priority(|| panic!("contained blocking panic"), 254);
    let cancelled = handle.spawn_with_priority(|| panic!("cancelled closure must not run"), 253);
    cancelled.cancel();
    pool.shutdown();
    let rejected = handle.spawn_with_priority(|| panic!("closed admission must not run"), 255);
    assert!(rejected.is_done());
    assert!(rejected.is_cancelled());
    drop(held);
    assert!(pool.shutdown_and_wait(WAIT));
    for task in [low, high, panicked, cancelled] {
        assert!(task.is_done());
    }
    let mut completed = receive_order(&rx, 2);
    completed.sort_unstable();
    assert_eq!(completed, ["high", "low"]);
    assert_eq!(pool.pending_count(), 0);
    assert_eq!(pool.active_threads(), 0);
    assert_eq!(pool.busy_threads(), 0);
}

#[test]
fn runtime_builder_applies_priority_to_async_budget_inheritance() {
    let policy = priority_policy(8);
    let runtime = RuntimeBuilder::new()
        .worker_threads(1)
        .blocking_threads(1, 1)
        .enable_platform_reactor(false)
        .blocking_queue_policy(policy)
        .build()
        .unwrap();
    let handle = runtime.blocking_handle().expect("configured blocking pool");
    assert_eq!(handle.queue_policy(), policy);
    let held = hold_worker(&handle);
    let (tx, rx) = mpsc::channel();
    let background_tx = tx.clone();
    let background = handle.spawn(move || background_tx.send("background").unwrap());
    runtime.block_on_with_budget(Budget::new().with_priority(255), async move {
        let work = asupersync::runtime::spawn_blocking(move || tx.send("async").unwrap());
        let mut work = pin!(work);
        let mut held = Some(held);
        poll_fn(|cx| {
            let result = work.as_mut().poll(cx);
            if held.is_some() {
                assert!(
                    result.is_pending(),
                    "held worker cannot finish the queued work"
                );
                assert_eq!(handle.pending_count(), 2);
                drop(held.take());
            }
            result
        })
        .await;
    });
    assert!(background.wait_timeout(WAIT));
    assert_eq!(receive_order(&rx, 2), ["async", "background"]);
    assert!(runtime.shutdown_timeout(WAIT));
}
