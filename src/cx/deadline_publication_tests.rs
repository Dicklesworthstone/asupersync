//! Deadline registration races exercised through the real timer driver.

use super::Cx;
use crate::runtime::reactor::{Events, Interest, LabReactor, Reactor, Source, Token};
use crate::time::{
    CoalescingConfig, TimerDriver, TimerDriverHandle, TimerWheelConfig, VirtualClock,
};
use crate::types::{Budget, CancelKind, RegionId, TaskId, Time};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Wake, Waker};
use std::time::Duration;

/// Timer registration notifies its reactors after unlocking the wheel but
/// before returning the handle. The hook forces that publication interleaving
/// without sleeps or a production-only testing seam.
struct RegistrationHook {
    reactor: LabReactor,
    hook: Mutex<Option<Box<dyn FnMut() + Send>>>,
}

impl Reactor for RegistrationHook {
    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        self.reactor.register(source, token, interest)
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        self.reactor.modify(token, interest)
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        self.reactor.deregister(token)
    }

    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
        self.reactor.poll(events, timeout)
    }

    fn wake(&self) -> io::Result<()> {
        let hook = self.hook.lock().unwrap().take();
        if let Some(mut hook) = hook {
            hook();
            *self.hook.lock().unwrap() = Some(hook);
        }
        self.reactor.wake()
    }

    fn registration_count(&self) -> usize {
        self.reactor.registration_count()
    }
}

fn hook_registration(
    timer: &TimerDriverHandle,
    hook: impl FnMut() + Send + 'static,
) -> Arc<dyn Reactor> {
    let reactor: Arc<dyn Reactor> = Arc::new(RegistrationHook {
        reactor: LabReactor::new(),
        hook: Mutex::new(Some(Box::new(hook))),
    });
    timer.register_deadline_reactor(Arc::downgrade(&reactor));
    reactor
}

fn context(timer: &TimerDriverHandle, deadline: Time) -> Cx {
    Cx::new_with_drivers(
        RegionId::new_for_test(0, 1),
        TaskId::new_for_test(0, 0),
        Budget::INFINITE.with_deadline(deadline),
        None,
        None,
        None,
        Some(timer.clone()),
        None,
    )
}

fn short_horizon_timer(clock: &Arc<VirtualClock>) -> TimerDriverHandle {
    TimerDriverHandle::new(Arc::new(TimerDriver::with_clock_and_config(
        Arc::clone(clock),
        TimerWheelConfig {
            max_wheel_duration: Duration::from_millis(10),
            max_timer_duration: Duration::from_millis(10),
        },
        CoalescingConfig::default(),
    )))
}

struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn already_due_callback_before_handle_publication_is_replayed() {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(20)));
    let timer = TimerDriverHandle::with_virtual_clock(clock);
    let cx = context(&timer, Time::from_millis(10));
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let token = cx.refresh_cancel_waker(None, &Waker::from(Arc::clone(&wakes)));
    let fired = Arc::new(AtomicUsize::new(0));
    let _reactor = hook_registration(&timer, {
        let timer = timer.clone();
        let fired = Arc::clone(&fired);
        move || {
            fired.fetch_add(timer.process_timers(), Ordering::SeqCst);
        }
    });

    cx.arm_budget_deadline();

    assert_eq!(fired.load(Ordering::SeqCst), 1);
    assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::Deadline);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    assert_eq!(timer.pending_count(), 0);
    cx.clear_cancel_waker(token);
}

#[test]
fn early_callback_before_publication_rearms_until_the_real_deadline() {
    let clock = Arc::new(VirtualClock::new());
    let timer = short_horizon_timer(&clock);
    let cx = context(&timer, Time::from_millis(25));
    let fired = Arc::new(AtomicUsize::new(0));
    let _reactor = hook_registration(&timer, {
        let clock = Arc::clone(&clock);
        let timer = timer.clone();
        let fired = Arc::clone(&fired);
        let mut first = true;
        move || {
            if first {
                first = false;
                clock.advance_to(Time::from_millis(10));
                fired.fetch_add(timer.process_timers(), Ordering::SeqCst);
            }
        }
    });

    cx.arm_budget_deadline();
    assert_eq!(fired.load(Ordering::SeqCst), 1);
    assert!(!cx.is_cancel_requested());
    assert_eq!(timer.pending_count(), 1, "the early wake must be replaced");

    clock.advance_to(Time::from_millis(25));
    assert_eq!(timer.process_timers(), 1);
    assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::Deadline);
    assert_eq!(timer.pending_count(), 0);
}

#[test]
fn repeated_early_callbacks_during_rearm_keep_one_timer_and_constant_stack() {
    let clock = Arc::new(VirtualClock::new());
    let timer = short_horizon_timer(&clock);
    let cx = context(&timer, Time::from_millis(640));
    let fired = Arc::new(AtomicUsize::new(0));
    let _reactor = hook_registration(&timer, {
        let clock = Arc::clone(&clock);
        let timer = timer.clone();
        let fired = Arc::clone(&fired);
        let mut step = 0;
        move || {
            step += 1;
            clock.advance_to(Time::from_millis(step * 10));
            fired.fetch_add(timer.process_timers(), Ordering::SeqCst);
            // Native timer drivers refresh this floor before parking. Here
            // the unpublished callback has only recorded wake debt, so the
            // wheel is empty and the next replacement notifies the hook.
            let _ = timer.next_deadline();
        }
    });

    cx.arm_budget_deadline();

    assert_eq!(fired.load(Ordering::SeqCst), 64);
    assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::Deadline);
    assert_eq!(timer.pending_count(), 0, "no overwritten replacement leaks");
}

#[test]
fn registry_closed_during_registration_refuses_and_removes_the_timer() {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(clock);
    let cx = context(&timer, Time::from_millis(50));
    let _reactor = hook_registration(&timer, {
        let cx = cx.clone();
        move || {
            let retired = cx.inner.write().take_cancel_wakers();
            drop(retired);
        }
    });

    cx.arm_budget_deadline();

    assert!(cx.inner.read().cancel_waker_registry_closed);
    assert!(cx.inner.read().budget_deadline_timer.is_none());
    assert_eq!(timer.pending_count(), 0);
    assert!(!cx.is_cancel_requested());
}

#[test]
fn a_reentrant_arm_wins_once_and_the_redundant_handle_is_removed() {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let cx = context(&timer, Time::from_millis(50));
    let _reactor = hook_registration(&timer, {
        let cx = cx.clone();
        move || cx.arm_budget_deadline()
    });

    cx.arm_budget_deadline();
    assert_eq!(timer.pending_count(), 1);
    clock.advance_to(Time::from_millis(50));
    assert_eq!(timer.process_timers(), 1);
    assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::Deadline);
}

#[test]
fn a_losing_arm_cannot_rearm_through_the_winners_published_slot() {
    let clock = Arc::new(VirtualClock::new());
    let timer = short_horizon_timer(&clock);
    let cx = context(&timer, Time::from_millis(25));
    let fired = Arc::new(AtomicUsize::new(0));
    let _reactor = hook_registration(&timer, {
        let cx = cx.clone();
        let clock = Arc::clone(&clock);
        let timer = timer.clone();
        let fired = Arc::clone(&fired);
        let mut first = true;
        move || {
            if first {
                first = false;
                // This inner arm publishes before the outer arm returns.
                cx.arm_budget_deadline();
                clock.advance_to(Time::from_millis(10));
                fired.fetch_add(timer.process_timers(), Ordering::SeqCst);
            }
        }
    });

    cx.arm_budget_deadline();

    assert_eq!(fired.load(Ordering::SeqCst), 2, "both initial timers fired");
    assert!(!cx.is_cancel_requested());
    assert_eq!(
        timer.pending_count(),
        1,
        "only the winner may replace itself"
    );
    clock.advance_to(Time::from_millis(25));
    assert_eq!(timer.process_timers(), 1);
    assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::Deadline);
    assert_eq!(timer.pending_count(), 0);
}

#[test]
fn registry_closure_during_horizon_replacement_removes_that_registration() {
    let clock = Arc::new(VirtualClock::new());
    let timer = short_horizon_timer(&clock);
    let cx = context(&timer, Time::from_millis(25));
    let _reactor = hook_registration(&timer, {
        let cx = cx.clone();
        let clock = Arc::clone(&clock);
        let timer = timer.clone();
        let mut first = true;
        move || {
            if first {
                first = false;
                clock.advance_to(Time::from_millis(10));
                let _ = timer.process_timers();
                let _ = timer.next_deadline();
            } else {
                let retired = cx.inner.write().take_cancel_wakers();
                drop(retired);
            }
        }
    });

    cx.arm_budget_deadline();
    assert!(cx.inner.read().cancel_waker_registry_closed);
    assert!(cx.inner.read().budget_deadline_timer.is_none());
    assert_eq!(timer.pending_count(), 0);
    assert!(!cx.is_cancel_requested());
}
