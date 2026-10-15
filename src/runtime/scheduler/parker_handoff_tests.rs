//! GH #83: exercise both sides of the waiter-publication/handoff boundary.
//! Timeouts are watchdogs, never success criteria or latency benchmarks.
use super::*;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

const WATCHDOG: Duration = Duration::from_secs(5);

fn wait_for_waiter(parker: &Parker) -> bool {
    let until = Instant::now() + WATCHDOG;
    while !parker.wait_committed_for_test() && Instant::now() < until {
        thread::yield_now();
    }
    parker.wait_committed_for_test() && parker.waiting_count_for_test() == 1
}

// A broken readiness predicate must fail the assertion, not hang this test's
// thread forever. The rescue permit is sent only after the result is captured.
fn assert_returns_without_wake(test: impl FnOnce(Parker) + Send + 'static) {
    let parker = Parker::new();
    let rescue = parker.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let waiter = thread::spawn(move || {
        test(parker);
        let _ = done_tx.send(());
    });
    let result = done_rx.recv_timeout(WATCHDOG);
    rescue.unpark();
    waiter.join().expect("conditional parking fixture");
    assert_eq!(result, Ok(()), "the check needed an external rescue wake");
}

#[test]
fn readiness_is_checked_after_waiter_publication_for_both_wait_kinds() {
    for timed in [false, true] {
        assert_returns_without_wake(move |parker| {
            let ready = || {
                assert_eq!(parker.waiting_count_for_test(), 1);
                true
            };
            if timed {
                parker.park_timeout_unless(Duration::from_secs(60), ready);
            } else {
                parker.park_unless(ready);
            }
            assert_eq!(parker.waiting_count_for_test(), 0);
            assert!(!parker.wait_committed_for_test());
            assert!(!parker.notification_pending_for_test());
            assert!(!parker.unpark_if_waiting());
        });
    }
}

#[test]
fn a_released_leader_is_observed_even_when_the_promotion_scan_found_no_waiter() {
    for timed in [false, true] {
        assert_returns_without_wake(move |parker| {
            let polling = AtomicBool::new(true);
            polling.store(false, Ordering::Release);
            std::sync::atomic::fence(Ordering::SeqCst);
            assert!(!parker.unpark_if_waiting());
            let ready = || !polling.load(Ordering::Acquire);
            if timed {
                parker.park_timeout_unless(Duration::from_secs(60), ready);
            } else {
                parker.park_unless(ready);
            }
            assert_eq!(parker.waiting_count_for_test(), 0);
        });
    }
}

#[test]
fn a_waiter_that_already_checked_the_leader_receives_the_handoff_permit() {
    for timed in [false, true] {
        let parker = Parker::new();
        let polling = Arc::new(AtomicBool::new(true));
        let (checked_tx, checked_rx) = mpsc::channel();
        let (leave_check_tx, leave_check_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let waiter_parker = parker.clone();
        let waiter_polling = polling.clone();
        let waiter = thread::spawn(move || {
            let ready = || {
                // Intentionally hold the check open to force the crossing:
                // publication -> old flag read -> release -> signal -> wait.
                let ready = !waiter_polling.load(Ordering::Acquire);
                checked_tx.send(ready).expect("report readiness sample");
                let _ = leave_check_rx.recv_timeout(WATCHDOG);
                ready
            };
            if timed {
                waiter_parker.park_timeout_unless(Duration::from_secs(60), ready);
            } else {
                waiter_parker.park_unless(ready);
            }
            let _ = done_tx.send(());
        });
        let checked = checked_rx.recv_timeout(WATCHDOG);
        polling.store(false, Ordering::Release);
        std::sync::atomic::fence(Ordering::SeqCst);
        let promoted_parker = parker.clone();
        let promoter = thread::spawn(move || promoted_parker.unpark_if_waiting());
        // The promoter may now wait for the predicate's mutex, or may acquire
        // it after the condvar releases it. Either schedule must deliver once.
        let _ = leave_check_tx.send(());
        let done = done_rx.recv_timeout(WATCHDOG);
        // Rescue a broken implementation before joining, then assert failure.
        parker.unpark();
        let promoted = promoter.join().expect("promoter did not panic");
        waiter.join().expect("waiter did not panic");
        assert_eq!(checked, Ok(false));
        assert!(promoted, "a live waiter was promoted");
        assert_eq!(done, Ok(()), "handoff did not need watchdog rescue");
        assert_eq!(parker.waiting_count_for_test(), 0);
    }
}

#[test]
fn existing_permits_and_zero_timeouts_keep_their_fast_path_semantics() {
    let parker = Parker::new();
    parker.unpark();
    parker.park_unless(|| panic!("a pending permit bypasses the predicate"));
    assert!(!parker.notification_pending_for_test());
    parker.unpark();
    parker.park_timeout_unless(WATCHDOG, || panic!("timed permit bypass"));
    assert!(!parker.notification_pending_for_test());
    parker.park_timeout_unless(Duration::ZERO, || panic!("zero timeout bypass"));
    assert_eq!(parker.waiting_count_for_test(), 0);
}

#[test]
fn a_panicking_readiness_check_withdraws_the_waiter_under_the_mutex() {
    for timed in [false, true] {
        assert_returns_without_wake(move |parker| {
            let result = std::panic::catch_unwind(|| {
                if timed {
                    parker.park_timeout_unless(WATCHDOG, || panic!("readiness panic"));
                } else {
                    parker.park_unless(|| panic!("readiness panic"));
                }
            });
            assert!(result.is_err());
            assert_eq!(parker.waiting_count_for_test(), 0);
            assert!(!parker.unpark_if_waiting(), "no phantom waiter remains");
            // Recovering a poisoned mutex must not break subsequent real waits.
            parker.unpark();
            parker.park();
            assert!(!parker.notification_pending_for_test());
            parker.park_unless(|| true);
            assert_eq!(parker.waiting_count_for_test(), 0);
        });
    }
}

#[test]
fn an_ordinary_unpark_still_releases_a_conditionally_parked_waiter() {
    let parker = Parker::new();
    let parked = parker.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let waiter = thread::spawn(move || {
        parked.park_unless(|| false);
        let _ = done_tx.send(());
    });
    let committed = wait_for_waiter(&parker);
    parker.unpark();
    let result = done_rx.recv_timeout(WATCHDOG);
    parker.unpark();
    waiter.join().expect("ordinary unpark waiter");
    assert!(committed, "waiter finished its readiness check");
    assert_eq!(result, Ok(()));
    assert_eq!(parker.waiting_count_for_test(), 0);
}
