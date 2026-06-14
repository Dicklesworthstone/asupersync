//! Integration proof for runtime-mutable DB-pool max size + managed-resize
//! application (br-asupersync-adaptive-control-plane-yj2nxx.7, first slice).
//!
//! yj2nxx.2 landed the managed pool-sizing controller (the recommendation
//! brain). This proves the live-application path on the sync `DbPool`: the cap
//! enforced by capacity checks is now `current_max_size()`, adjustable within
//! `[config.min_idle, config.max_size]` via `set_max_size` /
//! `apply_pool_sizing_decision`. A shrink blocks new creates (existing
//! connections drain naturally); the configured `max_size` stays the hard
//! ceiling. Lives as a standalone integration test (one small crate linking the
//! lib) so it is immune to peer `#[cfg(test)]` breakage in the shared tree.
//!
//! The `database` module is gated on a backend feature, so this test is too;
//! run with e.g. `--features postgres` (the lightest, dependency-free backend).
#![cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]

use std::sync::atomic::{AtomicUsize, Ordering};

use asupersync::database::pool::{ConnectionManager, DbPool, DbPoolConfig, DbPoolError};
use asupersync::runtime::pool_sizing::{
    PoolSizingAction, PoolSizingBounds, PoolSizingControllerState, PoolSizingPolicy,
    PoolSizingTarget, PoolWorkloadEstimate, decide_pool_sizing,
};

#[derive(Debug)]
struct MockConn {
    _id: usize,
}

#[derive(Debug)]
struct MockErr;

impl std::fmt::Display for MockErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mock connection error")
    }
}

impl std::error::Error for MockErr {}

/// Minimal connection manager: hands out fresh `MockConn`s, always valid.
struct CountingManager {
    next_id: AtomicUsize,
}

impl CountingManager {
    fn new() -> Self {
        Self {
            next_id: AtomicUsize::new(1),
        }
    }
}

impl ConnectionManager for CountingManager {
    type Connection = MockConn;
    type Error = MockErr;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        Ok(MockConn {
            _id: self.next_id.fetch_add(1, Ordering::SeqCst),
        })
    }

    fn is_valid(&self, _conn: &Self::Connection) -> bool {
        true
    }
}

#[test]
fn set_max_size_clamps_into_configured_bounds() {
    // Default min_idle is 1; with_max_size sets the ceiling to 8.
    let pool = DbPool::new(CountingManager::new(), DbPoolConfig::with_max_size(8));
    assert_eq!(pool.current_max_size(), 8, "live cap starts at the ceiling");

    // Above the ceiling clamps down to config.max_size.
    assert_eq!(pool.set_max_size(100), 8);
    assert_eq!(pool.current_max_size(), 8);

    // Below the floor (min_idle = 1) clamps up to the floor.
    assert_eq!(pool.set_max_size(0), 1);
    assert_eq!(pool.current_max_size(), 1);

    // In-range values are applied verbatim.
    assert_eq!(pool.set_max_size(5), 5);
    assert_eq!(pool.current_max_size(), 5);

    // The configured ceiling (stats.max_size) is unchanged by live resizing.
    assert_eq!(pool.stats().max_size, 8);
}

#[test]
fn shrink_blocks_new_creates_then_grow_restores_capacity() {
    let pool = DbPool::new(
        CountingManager::new(),
        DbPoolConfig::with_max_size(4).validate_on_checkout(false),
    );

    // Shrink the live cap to 2.
    assert_eq!(pool.set_max_size(2), 2);

    // Two held connections exhaust the shrunk cap (no idle to reuse).
    let c1 = pool.get().expect("first create under cap");
    let c2 = pool.get().expect("second create under cap");
    assert_eq!(pool.stats().total, 2);

    // The third create is refused: total (2) >= live cap (2).
    let refused = pool.get();
    assert!(
        matches!(refused, Err(DbPoolError::Full)),
        "shrunk cap must block a new create, got {:?}",
        refused.err()
    );

    // Grow the cap back to the configured ceiling and the create succeeds.
    assert_eq!(pool.set_max_size(4), 4);
    let c3 = pool.get().expect("create allowed after growing the cap");
    assert_eq!(pool.stats().total, 3);

    drop((c1, c2, c3));
}

#[test]
fn apply_pool_sizing_decision_drives_the_live_cap() {
    let pool = DbPool::new(CountingManager::new(), DbPoolConfig::with_max_size(8));
    assert_eq!(pool.current_max_size(), 8);

    // A managed controller decision computed from the pool's own bounds.
    let bounds = PoolSizingBounds::new(1, 8);
    let policy =
        PoolSizingPolicy::managed(bounds, PoolSizingTarget::conservative_wait_probability());
    let state = PoolSizingControllerState {
        current_size: pool.current_max_size(),
        last_resize_epoch: 0,
    };
    // No observed load => recommendation collapses to the floor; managed mode
    // therefore resizes 8 -> 1.
    let idle_estimate = PoolWorkloadEstimate::new(0, 0, 0);
    let decision = decide_pool_sizing(policy, state, idle_estimate, 5);
    assert!(
        matches!(decision.action, PoolSizingAction::Resize { .. }),
        "expected a managed resize, got {:?}",
        decision.action
    );

    let applied = pool.apply_pool_sizing_decision(&decision);
    assert_eq!(
        applied,
        Some(1),
        "the resize is applied and clamped to the floor"
    );
    assert_eq!(pool.current_max_size(), 1);

    // An advisory (ObserveOnly) decision is a no-op on the live cap.
    let advisory_policy = PoolSizingPolicy::advisory(bounds);
    let advisory_state = PoolSizingControllerState {
        current_size: pool.current_max_size(),
        last_resize_epoch: 0,
    };
    let advisory_decision = decide_pool_sizing(advisory_policy, advisory_state, idle_estimate, 6);
    assert_eq!(advisory_decision.action, PoolSizingAction::ObserveOnly);
    assert_eq!(
        pool.apply_pool_sizing_decision(&advisory_decision),
        None,
        "advisory decisions never mutate the live cap"
    );
    assert_eq!(
        pool.current_max_size(),
        1,
        "advisory apply left the cap unchanged"
    );
}
