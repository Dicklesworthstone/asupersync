//! Property tests for the Outcome severity lattice, functor/monad laws,
//! Severity round-trip, and timer wheel invariants.

mod common;

use asupersync::time::{CoalescingConfig, TimerWheel, TimerWheelConfig};
use asupersync::types::Time;
use asupersync::types::cancel::{CancelKind, CancelReason};
use asupersync::types::outcome::{Outcome, PanicPayload, Severity, join_outcomes};
use common::{init_test_logging, test_proptest_config};
use proptest::prelude::*;
use std::sync::Arc;
use std::task::{Wake, Waker};
use std::time::Duration;

// ============================================================================
// Helpers
// ============================================================================

/// Noop waker for timer registration.
struct NoopWaker;
impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}

// ============================================================================
// Arbitrary Generators
// ============================================================================

fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Ok),
        Just(Severity::Err),
        Just(Severity::Cancelled),
        Just(Severity::Panicked),
    ]
}

/// Generate an Outcome<i32, i32> with a specific severity.
fn arb_outcome() -> impl Strategy<Value = Outcome<i32, i32>> {
    prop_oneof![
        any::<i32>().prop_map(Outcome::ok),
        any::<i32>().prop_map(Outcome::err),
        Just(Outcome::cancelled(CancelReason::timeout())),
        Just(Outcome::panicked(PanicPayload::new("test"))),
    ]
}

fn arb_cancel_reason() -> impl Strategy<Value = CancelReason> {
    prop_oneof![
        Just(CancelReason::new(CancelKind::User)),
        Just(CancelReason::new(CancelKind::Timeout)),
        Just(CancelReason::new(CancelKind::Deadline)),
        Just(CancelReason::new(CancelKind::PollQuota)),
        Just(CancelReason::new(CancelKind::CostBudget)),
        Just(CancelReason::new(CancelKind::FailFast)),
        Just(CancelReason::new(CancelKind::RaceLost)),
        Just(CancelReason::new(CancelKind::ParentCancelled)),
        Just(CancelReason::new(CancelKind::ResourceUnavailable)),
        Just(CancelReason::new(CancelKind::Shutdown)),
    ]
}

// ============================================================================
// Severity Round-Trip & Ordering
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// Severity::from_u8(as_u8()) is identity for valid values.
    #[test]
    fn severity_u8_roundtrip(sev in arb_severity()) {
        init_test_logging();
        let byte = sev.as_u8();
        let parsed = Severity::from_u8(byte);
        prop_assert_eq!(parsed, Some(sev));
    }

    /// Invalid severity values (>3) return None.
    #[test]
    fn severity_u8_invalid(v in 4u8..=255) {
        init_test_logging();
        prop_assert!(Severity::from_u8(v).is_none());
    }

    /// Severity has exactly 4 values: Ok < Err < Cancelled < Panicked.
    #[test]
    fn severity_total_order(a in arb_severity(), b in arb_severity()) {
        init_test_logging();
        // Total order: exactly one of a < b, a == b, a > b
        let lt = a < b;
        let eq = a == b;
        let gt = a > b;
        prop_assert!(
            u8::from(lt) + u8::from(eq) + u8::from(gt) == 1,
            "total order violated for {:?} vs {:?}", a, b
        );
    }
}

// ============================================================================
// Outcome Severity Consistency
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Outcome.severity() matches the variant.
    #[test]
    fn outcome_severity_matches_variant(o in arb_outcome()) {
        init_test_logging();
        let expected = match &o {
            Outcome::Ok(_) => Severity::Ok,
            Outcome::Err(_) => Severity::Err,
            Outcome::Cancelled(_) => Severity::Cancelled,
            Outcome::Panicked(_) => Severity::Panicked,
        };
        prop_assert_eq!(o.severity(), expected);
    }

    /// severity_u8() is consistent with severity().as_u8().
    #[test]
    fn outcome_severity_u8_consistent(o in arb_outcome()) {
        init_test_logging();
        prop_assert_eq!(o.severity_u8(), o.severity().as_u8());
    }

    /// Exactly one predicate is true for each variant.
    #[test]
    fn outcome_exactly_one_predicate(o in arb_outcome()) {
        init_test_logging();
        let count = u8::from(o.is_ok())
            + u8::from(o.is_err())
            + u8::from(o.is_cancelled())
            + u8::from(o.is_panicked());
        prop_assert_eq!(count, 1, "exactly one predicate should be true");
    }
}

// ============================================================================
// Join (Lattice) Laws
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(300))]

    /// Join is commutative on severity: severity(join(a,b)) == severity(join(b,a)).
    #[test]
    fn join_commutative_severity(a in arb_outcome(), b in arb_outcome()) {
        init_test_logging();
        let ab = join_outcomes(a.clone(), b.clone()).severity();
        let ba = join_outcomes(b, a).severity();
        prop_assert_eq!(ab, ba);
    }

    /// Join takes the worse severity: severity(join(a,b)) == max(severity(a), severity(b)).
    #[test]
    fn join_takes_worse(a in arb_outcome(), b in arb_outcome()) {
        init_test_logging();
        let joined_sev = join_outcomes(a.clone(), b.clone()).severity();
        let max_sev = a.severity().max(b.severity());
        prop_assert_eq!(joined_sev, max_sev);
    }

    /// Join is idempotent on severity: severity(join(a,a)) == severity(a).
    #[test]
    fn join_idempotent(a in arb_outcome()) {
        init_test_logging();
        let sev = a.severity();
        let joined_sev = join_outcomes(a.clone(), a).severity();
        prop_assert_eq!(joined_sev, sev);
    }

    /// Ok is the identity for join: join(Ok, x) has same severity as x.
    #[test]
    fn join_ok_is_identity(x in arb_outcome()) {
        init_test_logging();
        let ok: Outcome<i32, i32> = Outcome::ok(0);
        let joined_sev = join_outcomes(ok, x.clone()).severity();
        prop_assert_eq!(joined_sev, x.severity());
    }

    /// Panicked dominates all: join(x, Panicked) always has Panicked severity.
    #[test]
    fn join_panicked_dominates(x in arb_outcome()) {
        init_test_logging();
        let panic: Outcome<i32, i32> = Outcome::panicked(PanicPayload::new("panic"));
        let joined = join_outcomes(x, panic);
        prop_assert_eq!(joined.severity(), Severity::Panicked);
    }
}

// ============================================================================
// Functor Laws: map
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// map preserves severity (it only transforms the Ok value).
    #[test]
    fn map_preserves_severity(o in arb_outcome(), shift in any::<i32>()) {
        init_test_logging();
        let original_sev = o.severity();
        let mapped = o.map(|x| x.wrapping_add(shift));
        prop_assert_eq!(mapped.severity(), original_sev);
    }

    /// map(id) == id (functor identity law on severity + value).
    #[test]
    fn map_identity(v in any::<i32>()) {
        init_test_logging();
        let o: Outcome<i32, i32> = Outcome::ok(v);
        let mapped = o.map(|x| x);
        prop_assert!(matches!(mapped, Outcome::Ok(x) if x == v));
    }

    /// map_err preserves severity.
    #[test]
    fn map_err_preserves_severity(o in arb_outcome(), shift in any::<i32>()) {
        init_test_logging();
        let original_sev = o.severity();
        let mapped = o.map_err(|e| e.wrapping_add(shift));
        prop_assert_eq!(mapped.severity(), original_sev);
    }
}

// ============================================================================
// Monad Laws: and_then
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// and_then on non-Ok outcomes preserves the original outcome's severity.
    #[test]
    fn and_then_short_circuits_non_ok(reason in arb_cancel_reason()) {
        init_test_logging();
        // Cancelled short-circuits
        let cancelled: Outcome<i32, i32> = Outcome::cancelled(reason);
        let result = cancelled.and_then(|x| Outcome::ok(x + 1));
        prop_assert!(result.is_cancelled());

        // Panicked short-circuits
        let panicked: Outcome<i32, i32> = Outcome::panicked(PanicPayload::new("p"));
        let result = panicked.and_then(|x| Outcome::ok(x + 1));
        prop_assert!(result.is_panicked());
    }

    /// Left identity: and_then(Ok(v), f) == f(v).
    #[test]
    fn and_then_left_identity(v in any::<i32>()) {
        init_test_logging();
        let f = |x: i32| -> Outcome<i32, i32> { Outcome::ok(x.wrapping_mul(2)) };
        let o: Outcome<i32, i32> = Outcome::ok(v);
        let via_and_then = o.and_then(f);
        let direct = f(v);
        // Both should be Ok with the same value
        prop_assert_eq!(via_and_then.severity(), direct.severity());
        if let (Outcome::Ok(a), Outcome::Ok(b)) = (&via_and_then, &direct) {
            prop_assert_eq!(a, b);
        }
    }

    /// Right identity: and_then(m, Ok) == m (severity preserved).
    #[test]
    fn and_then_right_identity(o in arb_outcome()) {
        init_test_logging();
        let original_sev = o.severity();
        let result = o.and_then(Outcome::ok);
        prop_assert_eq!(result.severity(), original_sev);
    }
}

// ============================================================================
// into_result / From<Result> Round-Trip
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// From<Result<T,E>> -> Outcome -> into_result preserves Ok values.
    #[test]
    fn result_outcome_roundtrip_ok(v in any::<i32>()) {
        init_test_logging();
        let result: Result<i32, i32> = Ok(v);
        let outcome: Outcome<i32, i32> = result.into();
        prop_assert!(outcome.is_ok());
        let back = outcome.into_result();
        prop_assert!(matches!(back, Ok(x) if x == v));
    }

    /// From<Result<T,E>> -> Outcome preserves Err values.
    #[test]
    fn result_outcome_roundtrip_err(e in any::<i32>()) {
        init_test_logging();
        let result: Result<i32, i32> = Err(e);
        let outcome: Outcome<i32, i32> = result.into();
        prop_assert!(outcome.is_err());
    }
}

// ============================================================================
// Timer Wheel: Registration & Cancellation Invariants
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Registering n timers makes wheel.len() == n.
    #[test]
    fn timer_wheel_len_tracks_registrations(count in 1usize..=50) {
        init_test_logging();
        let mut wheel = TimerWheel::new();
        let now = wheel.current_time();
        for i in 0..count {
            let deadline = Time::from_nanos(now.as_nanos() + (i as u64 + 1) * 1_000_000);
            wheel.register(deadline, noop_waker());
        }
        prop_assert_eq!(wheel.len(), count);
    }

    /// Cancelling a timer decrements len.
    #[test]
    fn timer_wheel_cancel_decrements(count in 2usize..=20) {
        init_test_logging();
        let mut wheel = TimerWheel::new();
        let now = wheel.current_time();
        let mut handles = Vec::new();
        for i in 0..count {
            let deadline = Time::from_nanos(now.as_nanos() + (i as u64 + 1) * 1_000_000);
            handles.push(wheel.register(deadline, noop_waker()));
        }
        prop_assert_eq!(wheel.len(), count);

        // Cancel the first timer
        let cancelled = wheel.cancel(&handles[0]);
        prop_assert!(cancelled, "cancel should return true for active timer");
        prop_assert_eq!(wheel.len(), count - 1);

        // Double cancel returns false
        let double = wheel.cancel(&handles[0]);
        prop_assert!(!double, "double cancel should return false");
        prop_assert_eq!(wheel.len(), count - 1);
    }

    /// Expired timers fire when time advances past their deadline.
    #[test]
    fn timer_wheel_fires_on_advance(delay_ms in 1u64..=100) {
        init_test_logging();
        let mut wheel = TimerWheel::new();
        let now = wheel.current_time();
        let deadline = Time::from_nanos(now.as_nanos() + delay_ms * 1_000_000);
        wheel.register(deadline, noop_waker());
        prop_assert_eq!(wheel.len(), 1);

        // Advance past deadline
        let future = Time::from_nanos(deadline.as_nanos() + 1_000_000);
        let wakers = wheel.collect_expired(future);
        prop_assert!(!wakers.is_empty(), "timer should have fired");
    }

    /// Timers that haven't reached their deadline don't fire.
    #[test]
    fn timer_wheel_no_premature_fire(delay_ms in 10u64..=1000) {
        init_test_logging();
        let mut wheel = TimerWheel::new();
        let now = wheel.current_time();
        let deadline = Time::from_nanos(now.as_nanos() + delay_ms * 1_000_000);
        wheel.register(deadline, noop_waker());

        // Advance to half the deadline
        let half = Time::from_nanos(now.as_nanos() + (delay_ms / 2) * 1_000_000);
        let wakers = wheel.collect_expired(half);
        prop_assert!(
            wakers.is_empty(),
            "timer should not fire before deadline (delay={}ms, advanced to {}ms)",
            delay_ms, delay_ms / 2
        );
    }

    /// Cancelled timers don't fire.
    #[test]
    fn timer_wheel_cancelled_doesnt_fire(delay_ms in 1u64..=100) {
        init_test_logging();
        let mut wheel = TimerWheel::new();
        let now = wheel.current_time();
        let deadline = Time::from_nanos(now.as_nanos() + delay_ms * 1_000_000);
        let handle = wheel.register(deadline, noop_waker());
        wheel.cancel(&handle);

        // Advance past deadline
        let future = Time::from_nanos(deadline.as_nanos() + 1_000_000);
        let wakers = wheel.collect_expired(future);
        prop_assert!(wakers.is_empty(), "cancelled timer should not fire");
    }
}

// ============================================================================
// Timer Wheel: Duration Validation
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// try_register rejects timers exceeding max_timer_duration.
    #[test]
    fn timer_wheel_rejects_too_long(extra_secs in 1u64..=100) {
        init_test_logging();
        let config = TimerWheelConfig::new().max_timer_duration(Duration::from_secs(60));
        let wheel_config = config;
        let mut wheel = TimerWheel::with_config(
            Time::ZERO,
            wheel_config,
            CoalescingConfig::default(),
        );
        let deadline = Time::from_nanos((60 + extra_secs) * 1_000_000_000);
        let result = wheel.try_register(deadline, noop_waker());
        prop_assert!(result.is_err(), "timer exceeding max_duration should be rejected");
    }

    /// Timers within max_duration are accepted.
    #[test]
    fn timer_wheel_accepts_within_limit(secs in 1u64..=59) {
        init_test_logging();
        let config = TimerWheelConfig::new().max_timer_duration(Duration::from_secs(60));
        let mut wheel = TimerWheel::with_config(
            Time::ZERO,
            config,
            CoalescingConfig::default(),
        );
        let deadline = Time::from_nanos(secs * 1_000_000_000);
        let result = wheel.try_register(deadline, noop_waker());
        prop_assert!(result.is_ok(), "timer within max_duration should be accepted");
    }
}

// ============================================================================
// Timer Wheel: Overflow Handling
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(50))]

    /// Timers beyond wheel range go to overflow but still fire when time advances.
    #[test]
    fn timer_wheel_overflow_fires(hours in 1u64..=6) {
        init_test_logging();
        // Default max_timer_duration is 7 days, max_wheel_duration is 24 hours
        let mut wheel = TimerWheel::new();
        let now = wheel.current_time();
        let deadline = Time::from_nanos(now.as_nanos() + hours * 3_600_000_000_000);
        wheel.register(deadline, noop_waker());

        // The timer may be in overflow if beyond wheel range
        let total = wheel.len();
        prop_assert_eq!(total, 1, "timer should be tracked");

        // Advance past deadline
        let future = Time::from_nanos(deadline.as_nanos() + 1_000_000);
        let wakers = wheel.collect_expired(future);
        prop_assert!(!wakers.is_empty(), "overflow timer should fire");
    }
}

// ============================================================================
// Timer Wheel: Clear
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(50))]

    /// clear() empties the wheel completely.
    #[test]
    fn timer_wheel_clear(count in 1usize..=30) {
        init_test_logging();
        let mut wheel = TimerWheel::new();
        let now = wheel.current_time();
        for i in 0..count {
            let deadline = Time::from_nanos(now.as_nanos() + (i as u64 + 1) * 1_000_000);
            wheel.register(deadline, noop_waker());
        }
        prop_assert_eq!(wheel.len(), count);
        wheel.clear();
        prop_assert!(wheel.is_empty());
        prop_assert_eq!(wheel.len(), 0);
    }
}
