#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
#![cfg(feature = "test-internals")]
//! Regression coverage for create-time acquire timeouts in `GenericPool`.

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::sync::{GenericPool, Pool, PoolConfig, PoolError};
use asupersync::types::Budget;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;

mod common;

#[test]
fn pool_creation_respects_acquire_timeout() {
    common::init_test_logging();

    let mut runtime = LabRuntime::new(LabConfig::new(0x5157_9001).max_steps(10_000));
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let factory = || async move {
        // Sleep long enough that the acquire timeout must fire first.
        let now = Cx::current()
            .and_then(|current| current.timer_driver())
            .map_or_else(asupersync::time::wall_now, |driver| driver.now());
        asupersync::time::sleep(now, Duration::from_secs(100)).await;
        Ok::<(), std::io::Error>(())
    };

    let config = PoolConfig::with_max_size(2).acquire_timeout(Duration::from_millis(50));

    // Acquire timeout follows the task Cx timer driver, not the pool's wall-clock
    // resource age getter.
    let pool = Arc::new(GenericPool::new(factory, config));
    let acquire_outcome = Arc::new(Mutex::new(None));

    let pool_for_task = Arc::clone(&pool);
    let outcome_for_task = Arc::clone(&acquire_outcome);
    let (task_id, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().expect("lab task should install a current Cx");
            let start = serde_json::json!({
                "phase": "acquire_started",
                "timeout_ms": 50_u64,
            });
            tracing::info!(event = %start, "pool_timeout_lab_checkpoint");

            let result = pool_for_task.acquire(&cx).await.map(|_| ());
            let completion = serde_json::json!({
                "phase": "acquire_completed",
                "status": match &result {
                    Ok(()) => "ok",
                    Err(PoolError::Timeout) => "timeout",
                    Err(PoolError::Closed) => "closed",
                    Err(PoolError::CreateFailed(_)) => "create_failed",
                    Err(PoolError::Cancelled) => "cancelled",
                },
            });
            tracing::info!(event = %completion, "pool_timeout_lab_checkpoint");
            *outcome_for_task.lock() = Some(result);
        })
        .expect("lab timeout task should spawn");
    runtime
        .scheduler
        .lock()
        .schedule(task_id, Budget::INFINITE.priority);

    runtime.step_for_test();
    let pending = serde_json::json!({
        "phase": "before_advance",
        "virtual_time_ns": runtime.now().as_nanos(),
        "completed": acquire_outcome.lock().is_some(),
    });
    tracing::info!(event = %pending, "pool_timeout_lab_checkpoint");
    assert!(
        acquire_outcome.lock().is_none(),
        "acquire should remain pending before virtual time advances"
    );

    runtime.advance_time(
        Duration::from_millis(60)
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64,
    );
    let advanced = serde_json::json!({
        "phase": "after_advance",
        "virtual_time_ns": runtime.now().as_nanos(),
    });
    tracing::info!(event = %advanced, "pool_timeout_lab_checkpoint");

    runtime.run_until_quiescent();

    let poll2 = acquire_outcome
        .lock()
        .take()
        .expect("lab acquire result should be recorded");
    assert!(
        matches!(poll2, Err(PoolError::Timeout)),
        "Should timeout during creation"
    );
    let violations = runtime.oracles.check_all(runtime.now());
    assert!(
        violations.is_empty(),
        "lab timeout regression should leave runtime invariants clean: {violations:?}"
    );
}
