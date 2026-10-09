//! Stateful, deterministic readiness model for reactor-driven I/O.
//!
//! [`LabReactor`] is an event injector: two injected events can produce two
//! notifications without a re-arm. [`LabReactorModel`] adds the missing state
//! machine, so an [`IoDriver`](super::IoDriver) test can detect forgotten
//! re-arms, premature disarming, and readiness lost during an interest change.
//!
//! Conditions persist until [`clear_ready`](LabReactorModel::clear_ready).
//! The default matches the native runtime's one-shot registration policy;
//! explicit edge triggering and an opt-in level-triggered default are also
//! supported. Scheduled conditions use the existing lab reactor's virtual clock.
//! No OS I/O, background thread, wall clock, or ambient runtime is introduced.
//!
//! This is an opt-in model, not a change to legacy `LabReactor` semantics or the
//! default `LabRuntime`. Supply an `Arc<LabReactorModel>` wherever a `Reactor`
//! is accepted. It models readiness, not the contents of a socket: simulated
//! reads/writes must explicitly clear conditions when they reach `WouldBlock`.
//! It does not emulate descriptor identity, kernel queue ordering, or socket
//! read/write errors. Events in one batch are coalesced and sorted by token.
//!
//! ```
//! # #[cfg(unix)]
//! # fn main() -> std::io::Result<()> {
//! use asupersync::runtime::reactor::{Events, Interest, Reactor, Token};
//! use asupersync::runtime::reactor_model::LabReactorModel;
//! use std::time::Duration;
//!
//! let reactor = LabReactorModel::new();
//! let token = Token::new(1);
//! reactor.register(&std::io::stdin(), token, Interest::READABLE)?;
//! reactor.set_ready(token, Interest::READABLE)?;
//! let mut events = Events::with_capacity(4);
//! assert_eq!(reactor.poll(&mut events, Some(Duration::ZERO))?, 1);
//! assert_eq!(reactor.poll(&mut events, Some(Duration::ZERO))?, 0);
//! reactor.modify(token, Interest::READABLE)?; // re-arm without losing readiness
//! assert_eq!(reactor.poll(&mut events, Some(Duration::ZERO))?, 1);
//! reactor.clear_ready(token, Interest::READABLE)?; // simulated read drained it
//! # Ok(())
//! # }
//! # #[cfg(not(unix))]
//! # fn main() {}
//! ```

use super::reactor::{Event, Events, Interest, LabReactor, Reactor, Source, Token};
use crate::types::Time;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

/// Delivery policy for registrations without explicit trigger flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ReadinessMode {
    /// Deliver once, then require `modify` to re-arm (the native runtime default).
    #[default]
    OneShot,
    /// Deliver while a matching condition remains set.
    Level,
}

const READINESS: Interest = Interest::from_bits(
    Interest::READABLE.bits()
        | Interest::WRITABLE.bits()
        | Interest::ERROR.bits()
        | Interest::HUP.bits()
        | Interest::PRIORITY.bits(),
);

#[derive(Debug)]
struct RegistrationState {
    interest: Interest,
    ready: Interest,
    edges: Interest,
    armed: bool,
}

impl RegistrationState {
    fn set_ready(&mut self, ready: Interest) {
        self.edges |= ready & !self.ready;
        self.ready |= ready;
    }

    fn deliverable(&self) -> Interest {
        if !self.armed {
            return Interest::NONE;
        }
        let ready = if self.interest.is_edge_triggered() {
            self.ready & self.edges
        } else {
            self.ready
        };
        // Native reactors report error/hangup even when not requested.
        ready & (self.interest | Interest::ERROR | Interest::HUP) & READINESS
    }

    fn is_one_shot(&self, mode: ReadinessMode) -> bool {
        self.interest.is_oneshot()
            || self.interest.is_dispatch()
            || (!self.interest.is_edge_triggered() && mode == ReadinessMode::OneShot)
    }
}

#[derive(Debug, Default)]
struct ModelState {
    registrations: BTreeMap<Token, RegistrationState>,
}

/// An opt-in readiness state machine backed by the existing lab event clock.
///
/// `register` arms a source. A one-shot delivery disarms it, but does not erase
/// its readiness. `modify` re-arms it and samples existing conditions, including
/// conditions established while disarmed or while not selected by its interest.
/// Edge-triggered registrations deliver newly asserted conditions; clearing and
/// reasserting a condition produces another edge. Explicit `ONESHOT` or
/// `DISPATCH` flags take precedence over the default mode and `EDGE_TRIGGERED`.
///
/// Like `LabReactor`, `poll(None)` advances to the next scheduled condition,
/// or returns immediately when none exists. It never blocks a real thread.
#[derive(Debug)]
pub struct LabReactorModel {
    events: LabReactor,
    state: Mutex<ModelState>,
    mode: ReadinessMode,
}

impl Default for LabReactorModel {
    fn default() -> Self {
        Self::new()
    }
}

impl LabReactorModel {
    /// Creates a model with native-style one-shot delivery by default.
    #[must_use]
    pub fn new() -> Self {
        Self::with_mode(ReadinessMode::OneShot)
    }

    /// Creates a model with an explicit default delivery policy.
    #[must_use]
    pub fn with_mode(mode: ReadinessMode) -> Self {
        Self {
            events: LabReactor::new(),
            state: Mutex::new(ModelState::default()),
            mode,
        }
    }

    /// Returns the current virtual time.
    #[must_use]
    pub fn now(&self) -> Time {
        self.events.now()
    }

    /// Returns now for deliverable readiness, otherwise the next scheduled time.
    ///
    /// A scheduled condition need not produce a notification: the registration
    /// might be disarmed or interested in another direction when it becomes due.
    #[must_use]
    pub fn next_event_time(&self) -> Option<Time> {
        let state = self.state.lock();
        if state
            .registrations
            .values()
            .any(|registration| !registration.deliverable().is_empty())
        {
            Some(self.events.now())
        } else {
            self.events.next_event_time()
        }
    }

    /// Advances virtual time; due scheduled conditions are applied on the next poll.
    pub fn advance_time(&self, duration: Duration) {
        self.events.advance_time(duration);
    }

    /// Advances virtual time monotonically to `target`.
    pub fn advance_time_to(&self, target: Time) {
        self.events.advance_time_to(target);
    }

    /// Asserts persistent conditions immediately, without consuming virtual time.
    ///
    /// Reasserting an already-set condition does not create another edge.
    ///
    /// # Errors
    /// Rejects trigger flags in `ready` and unregistered tokens.
    pub fn set_ready(&self, token: Token, ready: Interest) -> io::Result<()> {
        validate_readiness(ready)?;
        let mut state = self.state.lock();
        let registration = state.registrations.get_mut(&token).ok_or_else(not_registered)?;
        registration.set_ready(ready);
        Ok(())
    }

    /// Clears conditions, for example after a simulated read reaches `WouldBlock`.
    ///
    /// This clears current conditions, not future scheduled assertions.
    ///
    /// # Errors
    /// Rejects trigger flags in `ready` and unregistered tokens.
    pub fn clear_ready(&self, token: Token, ready: Interest) -> io::Result<()> {
        validate_readiness(ready)?;
        let mut state = self.state.lock();
        let registration = state.registrations.get_mut(&token).ok_or_else(not_registered)?;
        registration.ready &= !ready;
        registration.edges &= !ready;
        Ok(())
    }

    /// Schedules persistent conditions to become set after a virtual delay.
    ///
    /// The scheduled assertion is applied during a poll even when the source
    /// is disarmed. Deregistration discards every queued assertion for its token.
    ///
    /// # Errors
    /// Rejects trigger flags in `ready` and unregistered tokens.
    pub fn schedule_ready(&self, token: Token, ready: Interest, delay: Duration) -> io::Result<()> {
        validate_readiness(ready)?;
        let state = self.state.lock();
        if !state.registrations.contains_key(&token) {
            return Err(not_registered());
        }
        self.events.inject_event(token, Event::new(token, ready), delay);
        Ok(())
    }

    /// Reports whether the registration is armed, for an exact test-state witness.
    ///
    /// # Errors
    /// Returns `NotFound` for an unregistered token.
    pub fn is_armed(&self, token: Token) -> io::Result<bool> {
        self.state
            .lock()
            .registrations
            .get(&token)
            .map(|registration| registration.armed)
            .ok_or_else(not_registered)
    }

    /// Returns currently asserted conditions, including unrequested readiness.
    ///
    /// Scheduled assertions not yet processed by a poll are not included.
    ///
    /// # Errors
    /// Returns `NotFound` for an unregistered token.
    pub fn readiness(&self, token: Token) -> io::Result<Interest> {
        self.state
            .lock()
            .registrations
            .get(&token)
            .map(|registration| registration.ready)
            .ok_or_else(not_registered)
    }
}

fn not_registered() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "readiness model token not registered")
}

fn validate_readiness(ready: Interest) -> io::Result<()> {
    if !(ready & !READINESS).is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "readiness conditions cannot contain trigger flags",
        ));
    }
    Ok(())
}

impl Reactor for LabReactorModel {
    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        let mut state = self.state.lock();
        if state.registrations.contains_key(&token) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "token already registered"));
        }
        // The injector must retain conditions even when not currently selected.
        // Delivery policy is owned solely by this model, not the event queue.
        self.events.register(source, token, READINESS)?;
        state.registrations.insert(
            token,
            RegistrationState {
                interest,
                ready: Interest::NONE,
                edges: Interest::NONE,
                armed: true,
            },
        );
        Ok(())
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        let mut state = self.state.lock();
        let registration = state.registrations.get_mut(&token).ok_or_else(not_registered)?;
        registration.interest = interest;
        registration.armed = true;
        // A native re-arm samples readiness again, even in edge-triggered mode.
        registration.edges = registration.ready;
        Ok(())
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        let mut state = self.state.lock();
        if !state.registrations.contains_key(&token) {
            return Err(not_registered());
        }
        self.events.deregister(token)?;
        state.registrations.remove(&token);
        Ok(())
    }

    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
        events.clear();
        let mut state = self.state.lock();
        let already_ready = state
            .registrations
            .values()
            .any(|registration| !registration.deliverable().is_empty());
        let timeout = if already_ready { Some(Duration::ZERO) } else { timeout };
        // Reuse the caller's event buffer for the underlying queue, then replace
        // injected occurrences with one coalesced notification per ready source.
        self.events.poll(events, timeout)?;
        for event in events.iter() {
            if let Some(registration) = state.registrations.get_mut(&event.token) {
                registration.set_ready(event.ready & READINESS);
            }
        }
        events.clear();
        for (&token, registration) in &mut state.registrations {
            let ready = registration.deliverable();
            if ready.is_empty() {
                continue;
            }
            events.push(Event::new(token, ready));
            registration.edges &= !ready;
            if registration.is_one_shot(self.mode) {
                registration.armed = false;
            }
        }
        Ok(events.len())
    }

    fn wake(&self) -> io::Result<()> {
        self.events.wake()
    }

    fn registration_count(&self) -> usize {
        self.state.lock().registrations.len()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::runtime::IoDriverHandle;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    fn register(model: &LabReactorModel, token: Token, interest: Interest) {
        model.register(&std::io::stdin(), token, interest).unwrap();
    }

    fn poll(model: &LabReactorModel) -> Vec<Event> {
        let mut events = Events::with_capacity(8);
        let count = model.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(count, events.len());
        events.iter().copied().collect()
    }

    #[test]
    fn default_oneshot_requires_rearm_but_keeps_undrained_readiness() {
        let model = LabReactorModel::new();
        let token = Token::new(1);
        register(&model, token, Interest::READABLE);
        model.set_ready(token, Interest::READABLE).unwrap();
        assert_eq!(poll(&model), vec![Event::readable(token)]);
        assert!(!model.is_armed(token).unwrap());
        assert!(poll(&model).is_empty(), "missing re-arm must not be hidden");
        model.modify(token, Interest::READABLE).unwrap();
        assert_eq!(poll(&model), vec![Event::readable(token)]);
        model.clear_ready(token, Interest::READABLE).unwrap();
        model.modify(token, Interest::READABLE).unwrap();
        assert!(poll(&model).is_empty());
        assert!(model.is_armed(token).unwrap());
    }

    #[test]
    fn level_readiness_repeats_without_advancing_virtual_time_until_drained() {
        let model = LabReactorModel::with_mode(ReadinessMode::Level);
        let token = Token::new(2);
        register(&model, token, Interest::READABLE);
        model.set_ready(token, Interest::READABLE).unwrap();
        let mut events = Events::with_capacity(8);
        for _ in 0..3 {
            assert_eq!(model.poll(&mut events, Some(Duration::from_secs(30))).unwrap(), 1);
            assert_eq!(model.now(), Time::ZERO);
        }
        model.clear_ready(token, Interest::READABLE).unwrap();
        assert_eq!(model.poll(&mut events, Some(Duration::from_secs(2))).unwrap(), 0);
        assert_eq!(model.now(), Time::from_secs(2));
    }

    #[test]
    fn edge_notifications_need_a_transition_or_an_explicit_rearm() {
        let model = LabReactorModel::new();
        let token = Token::new(3);
        let interest = Interest::READABLE | Interest::EDGE_TRIGGERED;
        register(&model, token, interest);
        model.set_ready(token, Interest::READABLE).unwrap();
        assert_eq!(poll(&model), vec![Event::readable(token)]);
        assert!(model.is_armed(token).unwrap());
        model.set_ready(token, Interest::READABLE).unwrap();
        assert!(poll(&model).is_empty());
        model.clear_ready(token, Interest::READABLE).unwrap();
        model.set_ready(token, Interest::READABLE).unwrap();
        assert_eq!(poll(&model), vec![Event::readable(token)]);
        model.modify(token, interest).unwrap();
        assert_eq!(poll(&model), vec![Event::readable(token)]);
    }

    #[test]
    fn explicit_oneshot_and_dispatch_override_level_and_edge_delivery() {
        for flag in [Interest::ONESHOT, Interest::DISPATCH] {
            for edge in [Interest::NONE, Interest::EDGE_TRIGGERED] {
                let model = LabReactorModel::with_mode(ReadinessMode::Level);
                let token = Token::new(4);
                let interest = Interest::READABLE | flag | edge;
                register(&model, token, interest);
                model.set_ready(token, Interest::READABLE).unwrap();
                assert_eq!(poll(&model).len(), 1);
                model.clear_ready(token, Interest::READABLE).unwrap();
                model.set_ready(token, Interest::READABLE).unwrap();
                assert!(poll(&model).is_empty());
                model.modify(token, interest).unwrap();
                assert_eq!(poll(&model), vec![Event::readable(token)]);
            }
        }
    }

    #[test]
    fn interest_changes_reveal_conditions_that_were_not_previously_selected() {
        let model = LabReactorModel::new();
        let token = Token::new(5);
        register(&model, token, Interest::READABLE);
        model.schedule_ready(token, Interest::WRITABLE, Duration::ZERO).unwrap();
        assert!(poll(&model).is_empty());
        assert_eq!(model.readiness(token).unwrap(), Interest::WRITABLE);
        assert!(model.is_armed(token).unwrap());
        model.modify(token, Interest::WRITABLE).unwrap();
        assert_eq!(poll(&model), vec![Event::writable(token)]);
    }

    #[test]
    fn errors_and_hangup_are_reported_even_without_explicit_interest() {
        let model = LabReactorModel::new();
        let token = Token::new(6);
        register(&model, token, Interest::NONE);
        let ready = Interest::ERROR | Interest::HUP;
        model.set_ready(token, ready).unwrap();
        assert_eq!(poll(&model), vec![Event::new(token, ready)]);
        assert!(poll(&model).is_empty());
        model.modify(token, Interest::NONE).unwrap();
        assert_eq!(poll(&model), vec![Event::new(token, ready)]);
    }

    #[test]
    fn same_turn_conditions_coalesce_in_stable_token_order() {
        let model = LabReactorModel::new();
        for index in [9, 2, 7] {
            let token = Token::new(index);
            register(&model, token, Interest::READABLE | Interest::WRITABLE);
            model.schedule_ready(token, Interest::WRITABLE, Duration::ZERO).unwrap();
            model.schedule_ready(token, Interest::READABLE, Duration::ZERO).unwrap();
        }
        assert_eq!(
            poll(&model),
            [2, 7, 9].map(|index| Event::new(Token::new(index), Interest::READABLE | Interest::WRITABLE))
        );
    }

    #[test]
    fn scheduled_conditions_survive_disarming_without_spurious_notifications() {
        let model = LabReactorModel::new();
        let token = Token::new(8);
        register(&model, token, Interest::READABLE | Interest::WRITABLE);
        model.set_ready(token, Interest::READABLE).unwrap();
        assert_eq!(poll(&model).len(), 1);
        model.clear_ready(token, Interest::READABLE).unwrap();
        model.schedule_ready(token, Interest::WRITABLE, Duration::from_millis(10)).unwrap();
        assert_eq!(model.next_event_time(), Some(Time::from_nanos(10_000_000)));
        let mut events = Events::with_capacity(4);
        assert_eq!(model.poll(&mut events, None).unwrap(), 0);
        assert_eq!(model.now(), Time::from_nanos(10_000_000));
        assert_eq!(model.next_event_time(), None);
        model.modify(token, Interest::WRITABLE).unwrap();
        assert_eq!(model.next_event_time(), Some(model.now()));
        assert_eq!(poll(&model), vec![Event::writable(token)]);
    }

    #[test]
    fn deregistration_clears_scheduled_and_latched_conditions_before_token_reuse() {
        let model = LabReactorModel::new();
        let token = Token::new(9);
        register(&model, token, Interest::READABLE);
        model.set_ready(token, Interest::READABLE).unwrap();
        model.schedule_ready(token, Interest::READABLE, Duration::from_secs(1)).unwrap();
        model.deregister(token).unwrap();
        assert_eq!(model.registration_count(), 0);
        assert_eq!(model.next_event_time(), None);
        register(&model, token, Interest::READABLE);
        model.advance_time(Duration::from_secs(2));
        assert!(poll(&model).is_empty());
        assert_eq!(model.readiness(token).unwrap(), Interest::NONE);
    }

    #[test]
    fn wake_interrupts_a_virtual_wait_without_consuming_future_readiness() {
        let model = LabReactorModel::new();
        let token = Token::new(10);
        register(&model, token, Interest::READABLE);
        model.schedule_ready(token, Interest::READABLE, Duration::from_secs(5)).unwrap();
        model.wake().unwrap();
        let mut events = Events::with_capacity(4);
        assert_eq!(model.poll(&mut events, None).unwrap(), 0);
        assert_eq!(model.now(), Time::ZERO);
        assert_eq!(model.poll(&mut events, None).unwrap(), 1);
        assert_eq!(model.now(), Time::from_secs(5));
    }

    #[test]
    fn invalid_readiness_and_unknown_tokens_do_not_mutate_the_model() {
        let model = LabReactorModel::new();
        let token = Token::new(11);
        assert_eq!(model.set_ready(token, Interest::READABLE).unwrap_err().kind(), io::ErrorKind::NotFound);
        register(&model, token, Interest::READABLE);
        for invalid in [Interest::ONESHOT, Interest::EDGE_TRIGGERED, Interest::DISPATCH] {
            assert_eq!(model.set_ready(token, invalid).unwrap_err().kind(), io::ErrorKind::InvalidInput);
            assert_eq!(model.schedule_ready(token, invalid, Duration::ZERO).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
        assert_eq!(model.readiness(token).unwrap(), Interest::NONE);
        assert_eq!(model.next_event_time(), None);
    }

    struct CountWakes(AtomicUsize);

    impl Wake for CountWakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn production_driver_rearm_is_required_to_observe_persistent_readiness_again() {
        let model = Arc::new(LabReactorModel::new());
        let driver = IoDriverHandle::new(model.clone());
        let count = Arc::new(CountWakes(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut registration = driver.register(&std::io::stdin(), Interest::READABLE, waker.clone()).unwrap();
        let token = registration.token();
        model.set_ready(token, Interest::READABLE).unwrap();
        assert_eq!(driver.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), 1);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(driver.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), 0);
        assert!(registration.rearm(Interest::READABLE, &waker).unwrap());
        assert_eq!(driver.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), 1);
        assert_eq!(count.0.load(Ordering::SeqCst), 2);
        drop(registration);
        assert!(driver.is_empty());
        assert_eq!(model.registration_count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_oneshot_matches_native_epoll_on_an_undrained_socket() {
        use crate::runtime::reactor::EpollReactor;
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let native = EpollReactor::new().unwrap();
        let model = LabReactorModel::new();
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        let token = Token::new(17);
        native.register(&reader, token, Interest::READABLE).unwrap();
        model.register(&reader, token, Interest::READABLE).unwrap();
        writer.write_all(b"ready").unwrap();
        model.set_ready(token, Interest::READABLE).unwrap();

        let compare = |expected: usize| {
            let mut actual = Events::with_capacity(4);
            assert_eq!(native.poll(&mut actual, Some(Duration::ZERO)).unwrap(), expected);
            assert_eq!(poll(&model), actual.iter().copied().collect::<Vec<_>>());
        };
        compare(1);
        compare(0); // no missing re-arm may be hidden by the model
        native.modify(token, Interest::READABLE).unwrap();
        model.modify(token, Interest::READABLE).unwrap();
        compare(1); // the data is still unread; no new write or edge is needed

        let mut bytes = [0_u8; 5];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ready");
        model.clear_ready(token, Interest::READABLE).unwrap();
        native.modify(token, Interest::READABLE).unwrap();
        model.modify(token, Interest::READABLE).unwrap();
        compare(0);
        native.deregister(token).unwrap();
        model.deregister(token).unwrap();
    }
}
