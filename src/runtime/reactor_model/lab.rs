//! Attach the readiness model before a lab runtime can mint task capabilities.

use super::{Event, Interest, LabReactorModel, ModelState, ReadinessMode, Token};
use crate::lab::{LabConfig, LabRuntime};
use crate::runtime::IoDriverHandle;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;

// This token is never registered. LabReactor uses its queued deadline to keep
// virtual time at now, then discards the event before fault/chaos processing.
// Consequently it cannot become an I/O trace, a task wake, or a random draw.
pub(super) const CLOCK_PUMP_TOKEN: Token = Token::new(usize::MAX);

impl LabRuntime {
    /// Creates a fresh lab runtime driven by a stateful readiness model.
    ///
    /// The returned model is the runtime's actual I/O backend, not a second
    /// reactor beside it. Registrations inherited through task capabilities use
    /// this model. Scheduled conditions, the runtime's automatic time advances,
    /// and its existing event-injection/chaos handle share one event queue and
    /// clock. Scripted reactor-operation failures reach the runtime's driver.
    ///
    /// Unlike [`Self::new`], this opt-in constructor enforces one-shot, edge, or
    /// level delivery. `mode` selects the default for registrations without an
    /// explicit trigger flag. Call [`LabReactorModel::clear_ready`] when a
    /// simulated read or write reaches `WouldBlock`; the model does not supply
    /// socket contents or infer when an application drained them.
    ///
    /// Use the returned handle to script conditions and inspect state. Advance
    /// time through the runtime, and let it poll the driver. Do not independently
    /// poll/advance the model or register/modify/deregister sources through the
    /// raw [`Self::lab_reactor`] handle: that bypasses the owning state machine.
    /// Raw event/fault injection remains available, but changing a raw fault
    /// configuration does not clear conditions already latched by the model.
    /// Direct `set_ready` assertions do not pass through raw event chaos.
    ///
    /// `Token::new(usize::MAX)` is reserved for an internal, non-delivered clock
    /// marker in this paired mode. Standalone models do not reserve it. Clearing
    /// readiness may leave one harmless due marker until the next driver poll.
    ///
    /// Replay must reconstruct this constructor, mode, and I/O script. A lab
    /// dispatch recording alone does not serialize the readiness/failure script.
    /// Existing `LabConfig` and [`Self::new`] semantics are unchanged.
    ///
    /// ```
    /// use asupersync::lab::{LabConfig, LabRuntime};
    /// use asupersync::runtime::reactor_model::ReadinessMode;
    ///
    /// let (mut lab, model) =
    ///     LabRuntime::with_reactor_model(LabConfig::new(7), ReadinessMode::OneShot);
    /// lab.advance_time(1_000_000);
    /// assert_eq!(lab.now(), model.now());
    /// ```
    #[must_use]
    pub fn with_reactor_model(
        config: LabConfig,
        mode: ReadinessMode,
    ) -> (Self, Arc<LabReactorModel>) {
        let mut runtime = Self::new(config);
        let model = Arc::new(LabReactorModel {
            events: Arc::clone(runtime.lab_reactor()),
            state: Mutex::new(ModelState::default()),
            mode,
            paired_clock: true,
        });
        // No task or region has been created yet, so no Cx can retain the
        // replaced driver. Timers, spawn gateways and entropy stay untouched.
        runtime
            .state
            .set_io_driver(IoDriverHandle::new(model.clone()));
        (runtime, model)
    }
}

impl LabReactorModel {
    /// Make latched readiness visible to LabRuntime's existing deadline picker.
    /// All callers hold `state`, keeping enqueue/consume bookkeeping serialized.
    pub(super) fn queue_clock_pump(&self, state: &mut ModelState) {
        if !self.paired_clock
            || state.clock_pump_pending
            || !state
                .registrations
                .values()
                .any(|registration| !registration.deliverable().is_empty())
        {
            return;
        }
        self.events.inject_event(
            CLOCK_PUMP_TOKEN,
            Event::new(CLOCK_PUMP_TOKEN, Interest::NONE),
            Duration::ZERO,
        );
        state.clock_pump_pending = true;
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::runtime::reactor::{Events, Reactor};
    use crate::runtime::reactor_model::ReactorOperation;
    use crate::types::{Budget, Time};
    use std::future::poll_fn;
    use std::io;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::task::{Poll, Wake, Waker};

    struct CountWakes(AtomicUsize);

    impl Wake for CountWakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn paired_runtime_shares_clock_and_uses_model_registration_failures() {
        let (mut lab, model) =
            LabRuntime::with_reactor_model(LabConfig::new(7), ReadinessMode::OneShot);
        assert!(Arc::ptr_eq(lab.lab_reactor(), &model.events));
        lab.advance_time(1_000_000);
        assert_eq!(model.now(), lab.now());
        let driver = lab.state.io_driver_handle().unwrap();
        model
            .fail_next(ReactorOperation::Register, None, io::ErrorKind::OutOfMemory)
            .unwrap();
        let error = driver
            .register(&std::io::stdin(), Interest::READABLE, Waker::noop().clone())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert!(driver.is_empty());
        assert_eq!(model.registration_count(), 0);
        assert_eq!(
            model.fault_stats(ReactorOperation::Register).injected_failures,
            1
        );
    }

    #[test]
    fn paired_rearm_exposes_immediate_deadline_and_failed_poll_keeps_it() {
        let (lab, model) =
            LabRuntime::with_reactor_model(LabConfig::new(8), ReadinessMode::OneShot);
        let driver = lab.state.io_driver_handle().unwrap();
        let count = Arc::new(CountWakes(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut registration = driver
            .register(&std::io::stdin(), Interest::READABLE, waker.clone())
            .unwrap();
        let token = registration.token();
        model.set_ready(token, Interest::READABLE).unwrap();
        assert_eq!(lab.lab_reactor().next_event_time(), Some(Time::ZERO));
        assert_eq!(driver.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), 1);
        assert_eq!(lab.lab_reactor().next_event_time(), None);
        assert_eq!(driver.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), 0);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);

        assert!(registration.rearm(Interest::READABLE, &waker).unwrap());
        assert_eq!(lab.lab_reactor().next_event_time(), Some(Time::ZERO));
        model
            .fail_next(ReactorOperation::Poll, None, io::ErrorKind::Interrupted)
            .unwrap();
        assert!(driver.turn_with(Some(Duration::ZERO), |_, _| {}).is_err());
        assert_eq!(lab.lab_reactor().next_event_time(), Some(Time::ZERO));
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(driver.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), 1);
        assert_eq!(count.0.load(Ordering::SeqCst), 2);
        assert_eq!(lab.lab_reactor().next_event_time(), None);
        drop(registration);
        assert_eq!(model.registration_count(), 0);
    }

    #[test]
    fn paired_level_delivery_keeps_clock_due_until_conditions_are_cleared() {
        let (lab, model) =
            LabRuntime::with_reactor_model(LabConfig::new(9), ReadinessMode::Level);
        let token = Token::new(3);
        model
            .register(&std::io::stdin(), token, Interest::READABLE)
            .unwrap();
        let mut events = Events::with_capacity(4);
        for _ in 0..100 {
            model.set_ready(token, Interest::READABLE).unwrap();
        }
        for _ in 0..3 {
            assert_eq!(model.poll(&mut events, Some(Duration::ZERO)).unwrap(), 1);
            assert_eq!(lab.lab_reactor().next_event_time(), Some(Time::ZERO));
            assert_eq!(
                events.iter().copied().collect::<Vec<_>>(),
                vec![Event::readable(token)]
            );
        }
        model.clear_ready(token, Interest::READABLE).unwrap();
        assert_eq!(model.poll(&mut events, Some(Duration::ZERO)).unwrap(), 0);
        assert_eq!(lab.lab_reactor().next_event_time(), None);
        assert_eq!(lab.lab_reactor().chaos_stats().decision_points, 0);
        model.deregister(token).unwrap();
    }

    #[test]
    fn clock_marker_is_reserved_only_for_paired_models() {
        let (lab, model) =
            LabRuntime::with_reactor_model(LabConfig::new(10), ReadinessMode::OneShot);
        assert_eq!(
            model
                .register(&std::io::stdin(), CLOCK_PUMP_TOKEN, Interest::READABLE)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(lab.lab_reactor().registration_count(), 0);
        let standalone = LabReactorModel::new();
        standalone
            .register(&std::io::stdin(), CLOCK_PUMP_TOKEN, Interest::READABLE)
            .unwrap();
        standalone.deregister(CLOCK_PUMP_TOKEN).unwrap();
    }

    #[test]
    fn ordinary_lab_runtime_retains_legacy_repeatable_event_injection() {
        let lab = LabRuntime::new(LabConfig::new(11));
        let driver = lab.state.io_driver_handle().unwrap();
        let count = Arc::new(CountWakes(AtomicUsize::new(0)));
        let registration = driver
            .register(
                &std::io::stdin(),
                Interest::READABLE,
                Waker::from(count.clone()),
            )
            .unwrap();
        for expected in 1..=2 {
            lab.lab_reactor()
                .set_ready(registration.token(), Event::readable(registration.token()));
            assert_eq!(driver.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), 1);
            assert_eq!(count.0.load(Ordering::SeqCst), expected);
        }
    }

    // This future never self-wakes. Its second poll can only come from the
    // runtime's own IoDriver delivering a scripted model condition.
    fn run_waiter(immediate: bool) -> (u64, usize) {
        let (mut lab, model) =
            LabRuntime::with_reactor_model(LabConfig::new(12), ReadinessMode::OneShot);
        let driver = lab.state.io_driver_handle().unwrap();
        let token_slot = Arc::new(Mutex::new(None));
        let published = token_slot.clone();
        let polls = Arc::new(AtomicUsize::new(0));
        let task_polls = polls.clone();
        let observed = Arc::new(AtomicU64::new(u64::MAX));
        let task_observed = observed.clone();
        let task_model = model.clone();
        let task_driver = driver.clone();
        let mut registration = None;
        let future = poll_fn(move |cx| {
            task_polls.fetch_add(1, Ordering::SeqCst);
            if registration.is_none() {
                let guard = task_driver
                    .register(&std::io::stdin(), Interest::READABLE, cx.waker().clone())
                    .unwrap();
                *published.lock() = Some(guard.token());
                if !immediate {
                    task_model
                        .schedule_ready(guard.token(), Interest::READABLE, Duration::from_secs(5))
                        .unwrap();
                }
                registration = Some(guard);
                return Poll::Pending;
            }
            let guard = registration.take().unwrap();
            assert_eq!(
                task_model.readiness(guard.token()).unwrap(),
                Interest::READABLE
            );
            task_observed.store(task_model.now().as_nanos(), Ordering::SeqCst);
            task_model
                .clear_ready(guard.token(), Interest::READABLE)
                .unwrap();
            drop(guard);
            Poll::Ready(())
        });
        let region = lab.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = lab
            .state
            .create_task(region, Budget::INFINITE, future)
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert!(lab.scheduler.lock().is_empty());

        let later = if immediate {
            let later = driver
                .register(&std::io::stdin(), Interest::WRITABLE, Waker::noop().clone())
                .unwrap();
            model
                .schedule_ready(later.token(), Interest::WRITABLE, Duration::from_secs(10))
                .unwrap();
            model
                .set_ready(token_slot.lock().unwrap(), Interest::READABLE)
                .unwrap();
            Some(later)
        } else {
            None
        };
        let _report = lab.run_with_auto_advance();
        assert_eq!(lab.now(), model.now());
        drop(later);
        assert!(driver.is_empty());
        assert_eq!(model.registration_count(), 0);
        (observed.load(Ordering::SeqCst), polls.load(Ordering::SeqCst))
    }

    #[test]
    fn runtime_auto_advance_wakes_a_parked_task_at_the_scripted_deadline() {
        assert_eq!(run_waiter(false), (5_000_000_000, 2));
    }

    #[test]
    fn latched_readiness_runs_before_a_later_event_advances_virtual_time() {
        assert_eq!(run_waiter(true), (0, 2));
    }
}
