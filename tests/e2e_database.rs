//! E2E: Database full lifecycle — pool init, acquire, release, exhaustion,
//! concurrent access, health checks.

#[macro_use]
mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use asupersync::sync::{GenericPool, Pool, PoolConfig};
use common::*;

// =========================================================================
// Helpers
// =========================================================================

type BoxFut<T> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<T, Box<dyn std::error::Error + Send + Sync>>>
            + Send,
    >,
>;

fn mock_factory() -> impl Fn() -> BoxFut<MockConnection> + Send + Sync + 'static {
    let counter = Arc::new(AtomicUsize::new(0));
    move || {
        let id = counter.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(MockConnection::new(id)) })
    }
}

// =========================================================================
// Pool init + acquire + release
// =========================================================================

#[test]
fn e2e_pool_basic_lifecycle() {
    init_test_logging();
    test_phase!("Pool Basic Lifecycle");

    run_test_with_cx(|cx| async move {
        let config = PoolConfig::with_max_size(5);
        let pool = GenericPool::new(mock_factory(), config);

        test_section!("Acquire first connection");
        let conn = pool.acquire(&cx).await.unwrap();
        let id = conn.get().id();
        tracing::info!(connection_id = id, "acquired connection");
        assert_eq!(id, 0);

        test_section!("Use connection");
        conn.get().query("SELECT 1").unwrap();
        assert_eq!(conn.get().query_count(), 1);

        test_section!("Return to pool");
        conn.return_to_pool();

        test_section!("Re-acquire (should reuse)");
        let conn2 = pool.acquire(&cx).await.unwrap();
        tracing::info!(connection_id = conn2.get().id(), "re-acquired connection");

        test_complete!("e2e_pool_lifecycle");
    });
}

// =========================================================================
// Concurrent access
// =========================================================================

#[test]
fn e2e_pool_concurrent_access() {
    init_test_logging();
    test_phase!("Pool Concurrent Access");

    run_test_with_cx(|cx| async move {
        let config = PoolConfig::with_max_size(3);
        let pool = GenericPool::new(mock_factory(), config);

        test_section!("Acquire 3 connections (max)");
        let c1 = pool.acquire(&cx).await.unwrap();
        let c2 = pool.acquire(&cx).await.unwrap();
        let c3 = pool.acquire(&cx).await.unwrap();

        tracing::info!(
            c1 = c1.get().id(),
            c2 = c2.get().id(),
            c3 = c3.get().id(),
            "all connections acquired"
        );

        assert_ne!(c1.get().id(), c2.get().id());
        assert_ne!(c2.get().id(), c3.get().id());

        test_section!("Use all connections");
        c1.get().query("SELECT 1").unwrap();
        c2.get().query("SELECT 2").unwrap();
        c3.get().query("SELECT 3").unwrap();

        test_section!("Return connections");
        c1.return_to_pool();
        c2.return_to_pool();
        c3.return_to_pool();

        test_complete!("e2e_pool_concurrent", max_connections = 3);
    });
}

// =========================================================================
// Pool stats
// =========================================================================

#[test]
fn e2e_pool_stats() {
    init_test_logging();
    test_phase!("Pool Stats");

    run_test_with_cx(|cx| async move {
        let config = PoolConfig::with_max_size(5);
        let pool = GenericPool::new(mock_factory(), config);

        test_section!("Initial stats");
        let stats = pool.stats();
        tracing::info!(
            total = stats.total,
            idle = stats.idle,
            active = stats.active,
            "initial pool stats"
        );

        test_section!("After acquire");
        let conn = pool.acquire(&cx).await.unwrap();
        let stats = pool.stats();
        tracing::info!(
            total = stats.total,
            active = stats.active,
            "stats after acquire"
        );

        test_section!("After return");
        conn.return_to_pool();
        let stats = pool.stats();
        tracing::info!(total = stats.total, idle = stats.idle, "stats after return");

        test_complete!("e2e_pool_stats");
    });
}

// =========================================================================
// Pool close
// =========================================================================

#[test]
fn e2e_pool_close() {
    init_test_logging();
    test_phase!("Pool Close");

    run_test_with_cx(|cx| async move {
        let config = PoolConfig::with_max_size(3);
        let pool = GenericPool::new(mock_factory(), config);

        test_section!("Acquire and return");
        let conn = pool.acquire(&cx).await.unwrap();
        conn.return_to_pool();

        test_section!("Close pool");
        pool.close().await;

        test_section!("Acquire after close should fail");
        let result = pool.acquire(&cx).await;
        assert!(result.is_err());
        tracing::info!("correctly rejected after close");

        test_complete!("e2e_pool_close");
    });
}

// =========================================================================
// Discard unhealthy connection
// =========================================================================

#[test]
fn e2e_pool_discard() {
    init_test_logging();
    test_phase!("Pool Discard");

    run_test_with_cx(|cx| async move {
        let config = PoolConfig::with_max_size(5);
        let pool = GenericPool::new(mock_factory(), config);

        test_section!("Acquire connection");
        let conn = pool.acquire(&cx).await.unwrap();
        let id = conn.get().id();

        test_section!("Discard instead of return");
        conn.discard();

        test_section!("Next acquire creates new connection");
        let conn2 = pool.acquire(&cx).await.unwrap();
        tracing::info!(
            old_id = id,
            new_id = conn2.get().id(),
            "new connection created"
        );

        test_complete!("e2e_pool_discard");
    });
}
