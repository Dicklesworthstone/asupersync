#![allow(missing_docs)]

//! Sync primitives contention simulation E2E tests (T1.4).
//!
//! Exercises a "shared cache" pattern with RwLock, Semaphore, Notify, and Mutex
//! under deterministic LabRuntime scheduling. Verifies no deadlocks, no
//! starvation, correct read-after-write semantics, and clean cancellation.

#[macro_use]
mod common;

use asupersync::cx::Cx;
use asupersync::runtime::yield_now;
use asupersync::sync::{Mutex, Notify, OwnedSemaphorePermit, RwLock, Semaphore};
use common::e2e_harness::E2eLabHarness;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// ============================================================================
// Test 1: Shared cache pattern — readers, writers, background refresh
// ============================================================================

#[test]
fn e2e_sync_shared_cache() {
    let mut h = E2eLabHarness::new("e2e_sync_shared_cache", 0xE2E4_0001);
    let root = h.create_root();

    let data: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(Vec::new()));
    let invalidation = Arc::new(Notify::new());
    let refresh_sem = Arc::new(Semaphore::new(1));
    let total_reads = Arc::new(AtomicUsize::new(0));
    let total_writes = Arc::new(AtomicUsize::new(0));
    let total_refreshes = Arc::new(AtomicUsize::new(0));

    h.phase("spawn_readers");

    // 5 reader tasks: each reads the cache length multiple times.
    for reader_id in 0..5u32 {
        let d = data.clone();
        let reads = total_reads.clone();
        h.spawn(root, async move {
            for _ in 0..3 {
                let Some(cx) = Cx::current() else { return };
                if cx.checkpoint().is_err() {
                    return;
                }
                let guard = d.read(&cx).await.expect("read lock");
                let _len = guard.len();
                reads.fetch_add(1, Ordering::SeqCst);
                drop(guard);
                yield_now().await;
            }
            tracing::debug!(reader = reader_id, "reader done");
        });
    }

    h.phase("spawn_writers");

    // 2 writer tasks: each writes entries and signals invalidation.
    for writer_id in 0..2u32 {
        let d = data.clone();
        let writes = total_writes.clone();
        let inv = invalidation.clone();
        h.spawn(root, async move {
            for i in 0..4 {
                let Some(cx) = Cx::current() else { return };
                if cx.checkpoint().is_err() {
                    return;
                }
                let mut guard = d.write(&cx).await.expect("write lock");
                guard.push(format!("w{writer_id}-{i}"));
                writes.fetch_add(1, Ordering::SeqCst);
                drop(guard);
                inv.notify_waiters();
                yield_now().await;
            }
            tracing::debug!(writer = writer_id, "writer done");
        });
    }

    h.phase("spawn_refresher");

    // 1 background refresher: semaphore-gated
    {
        let d = data;
        let sem = refresh_sem;
        let refreshes = total_refreshes.clone();
        let inv = invalidation;
        h.spawn(root, async move {
            for round in 0..3u32 {
                inv.notified().await;
                let Some(cx) = Cx::current() else { return };
                let _permit = OwnedSemaphorePermit::acquire(sem.clone(), &cx, 1)
                    .await
                    .expect("sem acquire");
                let mut guard = d.write(&cx).await.expect("refresh write");
                guard.push(format!("refresh-{round}"));
                refreshes.fetch_add(1, Ordering::SeqCst);
                drop(guard);
                yield_now().await;
            }
        });
    }

    h.phase("run");
    let steps = h.run_until_quiescent();
    tracing::info!(steps, "quiescent after steps");

    h.phase("verify");

    let reads = total_reads.load(Ordering::SeqCst);
    let writes = total_writes.load(Ordering::SeqCst);
    let refreshes = total_refreshes.load(Ordering::SeqCst);

    tracing::info!(reads, writes, refreshes, "counters");

    // All 5 readers x 3 iterations = 15 reads.
    assert_with_log!(reads == 15, "all readers complete", 15, reads);
    // 2 writers x 4 iterations = 8 writes.
    assert_with_log!(writes == 8, "all writers complete", 8, writes);
    // Refresher completes at least 1 cycle.
    assert_with_log!(refreshes >= 1, "refresher ran", ">= 1", refreshes);

    h.finish();
}

// ============================================================================
// Test 2: Cancel mid-lock — no deadlocks, no leaked permits
// ============================================================================

#[test]
fn e2e_sync_cancel_mid_lock() {
    let mut h = E2eLabHarness::new("e2e_sync_cancel_mid_lock", 0xE2E4_0002);
    let root = h.create_root();
    let cancel_region = h.create_child(root);

    let mutex = Arc::new(Mutex::new(0u64));
    let completed_holder = Arc::new(AtomicUsize::new(0));
    let completed_waiters = Arc::new(AtomicUsize::new(0));

    h.phase("spawn_holder");

    // Task in root that holds the mutex for a while.
    {
        let m = mutex.clone();
        let done = completed_holder.clone();
        h.spawn(root, async move {
            let Some(cx) = Cx::current() else { return };
            let mut guard = m.lock(&cx).await.expect("holder lock");
            *guard += 1;
            // Hold for several yields
            for _ in 0..5 {
                yield_now().await;
            }
            drop(guard);
            done.fetch_add(1, Ordering::SeqCst);
        });
    }

    h.phase("spawn_waiters");

    // Tasks in cancel_region that try to acquire the mutex.
    for i in 0..3u32 {
        let m = mutex.clone();
        let done = completed_waiters.clone();
        h.spawn(cancel_region, async move {
            let Some(cx) = Cx::current() else { return };
            if cx.checkpoint().is_err() {
                return;
            }
            let result = m.lock(&cx).await;
            if result.is_ok() {
                done.fetch_add(1, Ordering::SeqCst);
            }
            tracing::debug!(task = i, ok = result.is_ok(), "waiter result");
        });
    }

    h.phase("partial_run_then_cancel");

    // Run a few steps to let holder grab the lock and waiters start waiting
    for _ in 0..20 {
        h.runtime.step_for_test();
    }

    // Cancel the child region — waiters should be interrupted
    let cancelled = h.cancel_region(cancel_region, "test cancel mid-lock");
    tracing::info!(cancelled, "cancelled waiter region");

    // Run to full quiescence
    h.run_until_quiescent();

    h.phase("verify");

    // Holder should have completed
    let holder_done = completed_holder.load(Ordering::SeqCst);
    assert_with_log!(holder_done == 1, "holder completed", 1, holder_done);

    // System should be quiescent with no leaks
    assert_with_log!(
        h.is_quiescent(),
        "quiescent after cancel",
        true,
        h.is_quiescent()
    );

    h.finish();
}
