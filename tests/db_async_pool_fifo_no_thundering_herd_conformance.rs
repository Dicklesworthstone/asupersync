//! Conformance proof for the [`AsyncDbPool`] FIFO waiter queue (eeexl1.5 AC3).
//!
//! The pool's async `get` parks saturated acquirers in an arrival-ordered
//! waiter queue instead of failing fast with `DbPoolError::Full`, and each
//! freed slot wakes *exactly one* waiter — the queue head — rather than every
//! parked caller. The inline unit tests in `src/database/pool.rs` pin the
//! two-waiter ordering and the budget-exhaustion timeout; this external crate
//! exercises the same public surface at full strength:
//!
//! * `async_pool_admits_n_plus_five_acquirers_in_strict_fifo_order` — with
//!   `N` slots held and `N + 5` acquirers parked, every single release admits
//!   the FIFO-front waiter and *only* that waiter, walked across all `N + 5`.
//! * `async_pool_multi_slot_release_wakes_only_the_freed_count` — freeing two
//!   of three slots admits exactly the two front waiters and leaves the rest
//!   queued (no thundering herd at a multi-slot release boundary).
//! * `async_pool_acquire_budget_exhaustion_surfaces_asup_e601` — budget
//!   exhaustion yields `AcquireTimeout` carrying the stable `[ASUP-E601]`
//!   token, and the timed-out caller leaves the waiter queue empty again.
//!
//! Determinism comes from `DbPoolStats::pending_waiters`: the harness only
//! advances after observing the queue depth it expects, so waiter enqueue
//! order matches spawn order without timing guesses. The wake chain is bounded
//! by live capacity, so a release can never admit more waiters than slots it
//! freed.
//!
//! Gated on `test-internals` (for `Cx::for_testing`) plus any database feature
//! (the `database` module only compiles with one enabled). Run e.g. with
//! `--features sqlite,test-internals`.
#![cfg(all(
    feature = "test-internals",
    any(feature = "sqlite", feature = "postgres", feature = "mysql")
))]

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use asupersync::cx::Cx;
use asupersync::database::pool::{AsyncConnectionManager, AsyncDbPool, DbPoolConfig, DbPoolError};
use asupersync::types::Outcome;
use futures_lite::future::block_on;

// ─── Mock async connection manager ──────────────────────────────────────────

/// Opaque in-memory connection: the pool's queueing behaviour is independent of
/// the backend, so the connection carries no state of its own.
#[derive(Debug)]
struct MockConn;

/// Always-successful manager: every `connect` succeeds and every connection
/// validates, isolating the FIFO waiter queue / wake logic under test. The
/// error type is `std::io::Error` because `connect` never fails here, so a
/// bespoke never-constructed error type would be dead code.
struct MockManager;

impl AsyncConnectionManager for MockManager {
    type Connection = MockConn;
    type Error = std::io::Error;

    // These bodies have nothing to await, so they return ready futures
    // directly rather than `async fn` (which would trip `clippy::unused_async`).
    fn connect(
        &self,
        _cx: &Cx,
    ) -> impl std::future::Future<Output = Outcome<Self::Connection, Self::Error>> + Send {
        std::future::ready(Outcome::Ok(MockConn))
    }

    fn is_valid(
        &self,
        _cx: &Cx,
        _conn: &mut Self::Connection,
    ) -> impl std::future::Future<Output = bool> + Send {
        std::future::ready(true)
    }
}

// ─── Harness helpers ─────────────────────────────────────────────────────────

/// A parked acquirer running on its own OS thread. It blocks in `get`, reports
/// its label once it acquires, then holds the connection until the harness
/// signals it to return — letting the test choreograph admission order.
struct Waiter {
    handle: JoinHandle<()>,
    release: Sender<()>,
}

fn spawn_waiter(
    pool: &Arc<AsyncDbPool<MockManager>>,
    label: usize,
    acquired: Sender<usize>,
) -> Waiter {
    let pool = Arc::clone(pool);
    let (release, release_rx): (Sender<()>, Receiver<()>) = mpsc::channel();
    let handle = thread::spawn(move || {
        let cx = Cx::for_testing();
        let lease = block_on(pool.get(&cx)).expect("a queued waiter eventually acquires a slot");
        acquired.send(label).expect("report acquisition label");
        // Hold the slot until the harness releases us, so the FIFO admission
        // order is driven by the test rather than by thread scheduling.
        let _ = release_rx.recv();
        lease.return_to_pool();
    });
    Waiter { handle, release }
}

/// Spins until the pool reports exactly `target` parked waiters, so the harness
/// never races ahead of an enqueue/dequeue it depends on.
fn wait_for_pending(pool: &AsyncDbPool<MockManager>, target: usize, context: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let pending = pool.stats().pending_waiters;
        if pending == target {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for pending_waiters == {target} ({context}); last observed {pending}"
        );
        thread::sleep(Duration::from_millis(2));
    }
}

fn recv_one(acquired: &Receiver<usize>, context: &str) -> usize {
    acquired
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|_| panic!("a waiter must acquire after a release ({context})"))
}

fn build_pool(max_size: usize) -> Arc<AsyncDbPool<MockManager>> {
    Arc::new(AsyncDbPool::new(
        MockManager,
        DbPoolConfig::with_max_size(max_size)
            .validate_on_checkout(false)
            .connection_timeout(Duration::from_secs(30)),
    ))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn async_pool_admits_n_plus_five_acquirers_in_strict_fifo_order() {
    const SLOTS: usize = 2;
    const WAITERS: usize = SLOTS + 5;

    let pool = build_pool(SLOTS);

    // Saturate the pool: every slot is held on the main thread.
    let cx = Cx::for_testing();
    let mut holders = Vec::with_capacity(SLOTS);
    for _ in 0..SLOTS {
        holders.push(block_on(pool.get(&cx)).expect("holder acquires a free slot"));
    }
    assert_eq!(
        pool.stats().pending_waiters,
        0,
        "no waiters before saturation"
    );

    // Enqueue N+5 acquirers one at a time, confirming each parks before the
    // next is spawned — this makes the queue order deterministic.
    let (acq_tx, acq_rx) = mpsc::channel::<usize>();
    let mut waiters = Vec::with_capacity(WAITERS);
    for label in 0..WAITERS {
        waiters.push(spawn_waiter(&pool, label, acq_tx.clone()));
        wait_for_pending(&pool, label + 1, "enqueueing acquirers in order");
    }
    drop(acq_tx);

    // Each release must admit exactly the FIFO-front waiter and nobody else.
    // First the two held slots, then each newly admitted waiter hands its slot
    // to the next in line.
    let mut remaining = WAITERS;
    for expected in 0..WAITERS {
        if expected < SLOTS {
            holders
                .pop()
                .expect("a held slot to release")
                .return_to_pool();
        } else {
            waiters[expected - SLOTS]
                .release
                .send(())
                .expect("hand the slot to the next waiter");
        }

        let admitted = recv_one(&acq_rx, "single release admits the queue head");
        assert_eq!(
            admitted, expected,
            "a single freed slot must admit the FIFO-front waiter, in arrival order"
        );
        assert!(
            acq_rx.try_recv().is_err(),
            "a single release must wake exactly one waiter (no thundering herd)"
        );

        remaining -= 1;
        wait_for_pending(
            &pool,
            remaining,
            "queue depth drops by exactly one per release",
        );
    }

    // Release the final two slot-holders and join every worker cleanly.
    for waiter in &waiters[(WAITERS - SLOTS)..] {
        waiter.release.send(()).expect("release a final holder");
    }
    for waiter in waiters {
        waiter
            .handle
            .join()
            .expect("waiter thread completes cleanly");
    }

    let stats = pool.stats();
    assert_eq!(stats.pending_waiters, 0, "queue fully drained");
    assert_eq!(
        usize::try_from(stats.total_creates).expect("create count fits usize"),
        SLOTS,
        "every acquirer reused one of the N slots"
    );
    assert_eq!(
        stats.total_timeouts, 0,
        "no acquirer timed out in the FIFO walk"
    );
}

#[test]
fn async_pool_multi_slot_release_wakes_only_the_freed_count() {
    const SLOTS: usize = 3;
    const WAITERS: usize = 5;
    const FREE_AT_ONCE: usize = 2;

    let pool = build_pool(SLOTS);

    let cx = Cx::for_testing();
    let mut holders = Vec::with_capacity(SLOTS);
    for _ in 0..SLOTS {
        holders.push(block_on(pool.get(&cx)).expect("holder acquires a free slot"));
    }

    let (acq_tx, acq_rx) = mpsc::channel::<usize>();
    let mut waiters = Vec::with_capacity(WAITERS);
    for label in 0..WAITERS {
        waiters.push(spawn_waiter(&pool, label, acq_tx.clone()));
        wait_for_pending(&pool, label + 1, "enqueueing acquirers in order");
    }
    drop(acq_tx);

    // Free two of three slots back-to-back. The wake chain is bounded by live
    // capacity, so exactly the two FIFO-front waiters acquire; the third slot
    // stays held, so the remaining three acquirers stay parked.
    for _ in 0..FREE_AT_ONCE {
        holders
            .pop()
            .expect("a held slot to release")
            .return_to_pool();
    }

    let mut admitted = [
        recv_one(&acq_rx, "first of two freed slots admits a waiter"),
        recv_one(&acq_rx, "second of two freed slots admits a waiter"),
    ];
    admitted.sort_unstable();
    assert_eq!(
        admitted,
        [0, 1],
        "freeing two slots admits exactly the two FIFO-front waiters"
    );

    wait_for_pending(
        &pool,
        WAITERS - FREE_AT_ONCE,
        "remaining acquirers stay queued",
    );
    assert!(
        acq_rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "freeing two slots must not wake the still-queued waiters (no thundering herd)"
    );

    // Drain the rest in FIFO order so every worker thread can finish: hand the
    // two live slots to the next two waiters, then free the last held slot.
    waiters[0]
        .release
        .send(())
        .expect("front holder yields its slot");
    assert_eq!(recv_one(&acq_rx, "third waiter admitted"), 2);
    waiters[1]
        .release
        .send(())
        .expect("second holder yields its slot");
    assert_eq!(recv_one(&acq_rx, "fourth waiter admitted"), 3);
    holders.pop().expect("the final held slot").return_to_pool();
    assert_eq!(recv_one(&acq_rx, "fifth waiter admitted"), 4);

    for waiter in &waiters[2..] {
        waiter.release.send(()).expect("release a drained waiter");
    }
    for waiter in waiters {
        waiter
            .handle
            .join()
            .expect("waiter thread completes cleanly");
    }

    let stats = pool.stats();
    assert_eq!(stats.pending_waiters, 0, "queue fully drained");
    assert_eq!(stats.total_timeouts, 0, "no acquirer timed out");
}

#[test]
fn async_pool_acquire_budget_exhaustion_surfaces_asup_e601() {
    // A single slot with a tight acquire budget so the parked second acquirer
    // times out promptly instead of waiting the default budget.
    let tight = AsyncDbPool::new(
        MockManager,
        DbPoolConfig::with_max_size(1)
            .validate_on_checkout(false)
            .connection_timeout(Duration::from_millis(120)),
    );

    let cx = Cx::for_testing();
    let holder = block_on(tight.get(&cx)).expect("holder takes the only slot");

    let waiter_cx = Cx::for_testing();
    let started = Instant::now();
    let outcome = block_on(tight.get(&waiter_cx));
    let elapsed = started.elapsed();

    let err = outcome.expect_err("a saturated single-slot pool must not hand out a second lease");
    assert!(
        matches!(err, DbPoolError::AcquireTimeout),
        "budget exhaustion while parked must yield AcquireTimeout, got {err:?}"
    );
    assert!(
        err.to_string().starts_with("[ASUP-E601]"),
        "AcquireTimeout must lead with the stable ASUP-E601 token, got: {err}"
    );
    assert!(
        elapsed >= Duration::from_millis(90),
        "the acquirer should wait close to the full budget before timing out, observed {elapsed:?}"
    );

    let stats = tight.stats();
    assert_eq!(
        stats.total_timeouts, 1,
        "budget exhaustion records exactly one timeout"
    );
    assert_eq!(
        stats.pending_waiters, 0,
        "a timed-out acquirer removes itself from the FIFO queue"
    );

    holder.return_to_pool();
}
