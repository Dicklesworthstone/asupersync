//! Behavioral regression test for the sync `DbPool::get_for_client`
//! capacity-slot leak on the auth-validation failure arms
//! (br-asupersync-c5d0q, fix in commit d5b3f8026).
//!
//! The bug: the sync `get_for_client` takes the validated connection out of
//! the internal `ValidationGuard` before the auth-state checks, then on the
//! two auth-validation failure arms disconnects the connection WITHOUT
//! decrementing the pool's `total` count — so the guard's `Drop` rollback no
//! longer applies and each occurrence permanently leaks one capacity slot.
//! With `max_size = 1`, one leaked slot pins the pool at capacity with zero
//! live connections, so every later acquire returns `DbPoolError::Full`
//! forever.
//!
//! These tests exercise the fix end-to-end through the public API. They live
//! as a standalone integration test (one small crate linking the lib) because
//! the lib unit-test target stalls on the conformance dev-dep / OOMs at the
//! test-binary link, so `cargo test -p asupersync --lib` is not a reliable
//! proof lane.
//!
//! Gated behind a database feature to match the existing `tests/pool_leak.rs`
//! convention; run with e.g. `--features postgres`.
#![cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use asupersync::database::pool::{ConnectionManager, DbPool, DbPoolConfig, DbPoolError};

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

/// A connection manager whose reported authentication state can be driven to
/// drift between return-time and the next checkout, with a toggle for whether
/// `clear_authentication_state` succeeds. The drift state lives behind `Arc`s
/// that the test retains after the manager is moved into the pool.
struct AuthDriftManager {
    next_id: AtomicUsize,
    auth_state: Arc<Mutex<Option<String>>>,
    clear_ok: Arc<AtomicBool>,
}

impl ConnectionManager for AuthDriftManager {
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

    fn authentication_state(&self, _conn: &Self::Connection) -> Option<String> {
        self.auth_state.lock().unwrap().clone()
    }

    fn clear_authentication_state(&self, _conn: &mut Self::Connection) -> bool {
        self.clear_ok.load(Ordering::SeqCst)
    }
}

/// Builds a `max_size == 1` pool with checkout + auth-state validation enabled,
/// returning the pool plus handles to drive the manager's drift state.
fn build_pool() -> (
    DbPool<AuthDriftManager>,
    Arc<Mutex<Option<String>>>,
    Arc<AtomicBool>,
) {
    let auth_state = Arc::new(Mutex::new(None::<String>));
    let clear_ok = Arc::new(AtomicBool::new(true));
    let manager = AuthDriftManager {
        next_id: AtomicUsize::new(1),
        auth_state: Arc::clone(&auth_state),
        clear_ok: Arc::clone(&clear_ok),
    };
    let pool = DbPool::new(
        manager,
        DbPoolConfig::with_max_size(1)
            .validate_on_checkout(true)
            .validate_authentication_state(true),
    );
    (pool, auth_state, clear_ok)
}

#[test]
fn auth_mismatch_rejection_does_not_leak_capacity_slot() {
    let (pool, auth_state, _clear_ok) = build_pool();

    // Seed the idle list with a connection authenticated for "c1" (the return
    // path records `manager.authentication_state()`).
    *auth_state.lock().unwrap() = Some("c1".to_string());
    {
        let _conn = pool
            .get_for_client("c1")
            .expect("first acquire creates a connection");
    }
    assert_eq!(pool.stats().idle, 1, "connection should return to idle");
    assert_eq!(pool.stats().total, 1);

    // Auth state drifts to a different client between return and the next
    // checkout, tripping the AuthenticationMismatch arm.
    *auth_state.lock().unwrap() = Some("c2".to_string());
    let err = pool
        .get_for_client("c1")
        .expect_err("auth-state mismatch must be rejected");
    assert!(
        matches!(err, DbPoolError::AuthenticationMismatch { .. }),
        "expected AuthenticationMismatch, got {err:?}"
    );

    // Regression assertion: the rejected connection must free its capacity
    // slot. With the leak, `total` stays pinned at max_size (1).
    assert_eq!(
        pool.stats().total,
        0,
        "auth-mismatch rejection must not leak a pool capacity slot"
    );

    // And the pool must remain usable afterwards.
    *auth_state.lock().unwrap() = Some("c1".to_string());
    assert!(
        pool.get_for_client("c1").is_ok(),
        "pool must be usable again after an auth-mismatch rejection"
    );
}

#[test]
fn clear_auth_failure_discard_does_not_leak_capacity_slot() {
    let (pool, auth_state, clear_ok) = build_pool();

    // Seed the idle list with a connection that has no recorded auth client
    // (`authenticated_for == None`).
    *auth_state.lock().unwrap() = None;
    {
        let _conn = pool
            .get_for_client("c1")
            .expect("first acquire creates a connection");
    }
    assert_eq!(pool.stats().total, 1);

    // On checkout the connection now reports an unexpected client and the
    // manager cannot scrub it, driving the clear-auth-failure discard arm.
    *auth_state.lock().unwrap() = Some("intruder".to_string());
    clear_ok.store(false, Ordering::SeqCst);

    // With the slot leaked the retry inside `get_for_client` would observe a
    // full pool (total == max_size) and return `Full` forever. With the slot
    // freed the retry takes the create path (which does not re-validate auth)
    // and succeeds.
    let result = pool.get_for_client("c1");
    assert!(
        result.is_ok(),
        "clear-auth-failure discard must free the slot so the pool stays usable, got {:?}",
        result.err()
    );
}
