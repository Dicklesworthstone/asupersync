use super::*;
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, CancelKind, RegionId, TaskId};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

fn virtual_owner(budget: Budget, now: Time) -> (Cx, Arc<VirtualClock>, TimerDriverHandle) {
    let clock = Arc::new(VirtualClock::starting_at(now));
    let driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let cx = Cx::new_with_drivers(
        RegionId::new_for_test(0, 1),
        TaskId::new_for_test(0, 0),
        budget,
        None,
        None,
        None,
        Some(driver.clone()),
        None,
    );
    (cx, clock, driver)
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn driverless_reconnect_delay_uses_owner_clock_under_foreign_virtual_poller() {
    let owner = Cx::for_testing();
    let (foreign, _, driver) = virtual_owner(Budget::INFINITE, Time::MAX);
    let delay = Duration::from_secs(60);
    let options = EventSourceOptions::default().reconnect(ReconnectPolicy::new(1, delay));
    let mut source = EventSource::with_options(
        &owner,
        HttpClient::new(),
        "http://example.test/events",
        options,
    )
    .unwrap();
    let _poller = foreign.set_current_restricted();
    let before = {
        let _owner = owner.clone().set_current_restricted();
        owner.now()
    };
    assert!(source.schedule_reconnect());
    let after = {
        let _owner = owner.set_current_restricted();
        source.cx.now()
    };
    let State::Waiting(sleep) = &source.state else {
        panic!("retry must own its pending delay");
    };
    assert!(sleep.deadline() >= before + delay);
    assert!(sleep.deadline() <= after + delay);
    assert!(driver.is_empty());
}

#[test]
fn masked_budget_expiry_keeps_backoff_parked_then_unmask_wakes_exact_owner() {
    let at = Time::from_millis(10);
    let (owner, clock, driver) = virtual_owner(Budget::INFINITE.with_deadline(at), Time::ZERO);
    let options = EventSourceOptions::default()
        .reconnect(ReconnectPolicy::new(1, Duration::from_secs(60)));
    let mut source = EventSource::with_options(
        &owner,
        HttpClient::new(),
        "http://example.test/events",
        options,
    )
    .unwrap();
    assert!(source.schedule_reconnect());
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    let mut task = Context::from_waker(&waker);
    assert!(Pin::new(&mut source).poll_next(&mut task).is_pending());
    let before_unmask = owner.masked(|| {
        clock.advance_to(at);
        assert_eq!(driver.process_timers(), 1);
        for _ in 0..4 {
            assert!(Pin::new(&mut source).poll_next(&mut task).is_pending());
            assert!(source.deadline.is_none());
            assert_eq!(source.observed_deadline, Some(at));
        }
        assert!(!source.is_terminated());
        count.0.load(Ordering::SeqCst)
    });
    assert!(count.0.load(Ordering::SeqCst) > before_unmask);
    assert!(matches!(
        Pin::new(&mut source).poll_next(&mut task),
        Poll::Ready(Some(Err(EventSourceError::Cancelled(reason))))
            if reason.kind == CancelKind::Deadline
    ));
    assert!(source.is_terminated());
    assert!(driver.is_empty());
    assert!(owner.inner.read().cancel_waker_registrations.is_empty());
}

#[test]
fn server_retry_overflow_is_clamped_to_explicit_wait_bound() {
    let (owner, _, _) = virtual_owner(Budget::INFINITE, Time::from_secs(10));
    let options = EventSourceOptions::default().reconnect(
        ReconnectPolicy::new(1, Duration::from_secs(1))
            .with_max_retry_delay(Duration::from_secs(2)),
    );
    let mut source = EventSource::with_options(
        &owner,
        HttpClient::new(),
        "http://example.test/events",
        options,
    )
    .unwrap();
    source.retry_millis = Some(u64::MAX);
    assert!(source.schedule_reconnect());
    let State::Waiting(sleep) = &source.state else {
        panic!("retry must own its pending delay");
    };
    assert_eq!(sleep.deadline(), Time::from_secs(12));
}
