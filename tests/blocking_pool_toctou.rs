//! Regression test for a `BlockingPool` spawn/shutdown TOCTOU race.

use asupersync::runtime::{BlockingPool, BlockingTaskHandle};
#[cfg(feature = "test-internals")]
use asupersync::{Cx, runtime::spawn_blocking};
#[cfg(feature = "test-internals")]
use futures_lite::future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const RACE_ATTEMPTS: usize = 256;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const HANDLE_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug)]
enum SpawnApi {
    Pool,
    Handle,
}

fn spawn_with_api(
    api: SpawnApi,
    pool: &BlockingPool,
    executions: Arc<AtomicUsize>,
) -> BlockingTaskHandle {
    match api {
        SpawnApi::Pool => pool.spawn(move || {
            executions.fetch_add(1, Ordering::AcqRel);
        }),
        SpawnApi::Handle => pool.handle().spawn(move || {
            executions.fetch_add(1, Ordering::AcqRel);
        }),
    }
}

fn assert_race_outcome(
    api: SpawnApi,
    attempt: usize,
    handle: &BlockingTaskHandle,
    executions: usize,
) -> Result<(), String> {
    match (handle.is_cancelled(), executions) {
        (true, 0) | (false, 1) => Ok(()),
        (true, count) => Err(format!(
            "{api:?} attempt {attempt}: rejected spawn still executed {count} time(s)",
        )),
        (false, count) => Err(format!(
            "{api:?} attempt {attempt}: accepted spawn executed {count} time(s), expected exactly one",
        )),
    }
}

fn run_spawn_shutdown_race(api: SpawnApi) -> Result<(), String> {
    for attempt in 0..RACE_ATTEMPTS {
        let pool = Arc::new(BlockingPool::new(1, 1));
        let executions = Arc::new(AtomicUsize::new(0));

        let executions_for_task = Arc::clone(&executions);
        let pool_for_spawn = Arc::clone(&pool);
        let pool_for_shutdown = Arc::clone(&pool);

        let spawn_thread =
            std::thread::spawn(move || spawn_with_api(api, &pool_for_spawn, executions_for_task));

        let shutdown_thread = std::thread::spawn(move || {
            pool_for_shutdown.shutdown();
        });

        let handle = match spawn_thread.join() {
            Ok(handle) => handle,
            Err(_) => return Err(format!("{api:?} attempt {attempt}: spawn thread panicked")),
        };
        if shutdown_thread.join().is_err() {
            return Err(format!(
                "{api:?} attempt {attempt}: shutdown thread panicked",
            ));
        }

        if !pool.shutdown_and_wait(DRAIN_TIMEOUT) {
            return Err(format!(
                "{api:?} attempt {attempt}: pool did not drain after shutdown",
            ));
        }
        if !handle.wait_timeout(HANDLE_TIMEOUT) {
            return Err(format!(
                "{api:?} attempt {attempt}: task handle was never completed",
            ));
        }
        if pool.pending_count() != 0 {
            return Err(format!(
                "{api:?} attempt {attempt}: shutdown left {} queued blocking task(s)",
                pool.pending_count(),
            ));
        }
        if pool.active_threads() != 0 {
            return Err(format!(
                "{api:?} attempt {attempt}: shutdown left {} active blocking worker(s)",
                pool.active_threads(),
            ));
        }

        assert_race_outcome(api, attempt, &handle, executions.load(Ordering::Acquire))?;
    }

    Ok(())
}

#[test]
fn pool_spawn_shutdown_race_completes_or_cancels() -> Result<(), String> {
    run_spawn_shutdown_race(SpawnApi::Pool)
}

#[test]
fn handle_spawn_shutdown_race_completes_or_cancels() -> Result<(), String> {
    run_spawn_shutdown_race(SpawnApi::Handle)
}

#[cfg(feature = "test-internals")]
#[test]
fn embedder_context_routes_spawn_blocking_to_caller_owned_pool() {
    let pool = BlockingPool::new(1, 1);
    let cx = Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));

    let thread_name = {
        let _guard = Cx::set_current(Some(cx));
        future::block_on(spawn_blocking(|| {
            std::thread::current()
                .name()
                .unwrap_or("unnamed")
                .to_owned()
        }))
    };

    assert!(
        thread_name.contains("-blocking-"),
        "spawn_blocking bypassed the caller-owned pool: {thread_name}"
    );
    assert!(pool.shutdown_and_wait(DRAIN_TIMEOUT));
}
