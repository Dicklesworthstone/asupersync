//! Deterministic lab reactor for testing.
//!
//! The [`LabReactor`] provides a virtual reactor implementation for deterministic
//! testing of async I/O code. Instead of interacting with the OS, it uses virtual
//! time and injected events.
//!
//! # Features
//!
//! - **Virtual time**: Time advances only through poll() timeouts
//! - **Event injection**: Test code can inject events at specific times
//! - **Deterministic**: Same events + same poll sequence = same results
//!
//! # Example
//!
//! ```ignore
//! use asupersync::runtime::reactor::{LabReactor, Interest, Event, Token};
//! use std::time::Duration;
//!
//! let reactor = LabReactor::new();
//! let token = Token::new(1);
//!
//! // Register a virtual source
//! reactor.register(&source, token, Interest::READABLE)?;
//!
//! // Inject an event 10ms in the future
//! reactor.inject_event(token, Event::readable(token), Duration::from_millis(10));
//!
//! // Poll with timeout - advances virtual time
//! let mut events = Events::with_capacity(10);
//! reactor.poll(&mut events, Some(Duration::from_millis(15)))?;
//! assert_eq!(events.len(), 1);
//! ```

use super::{Event, Interest, Reactor, Source, Token};
use crate::types::Time;
use std::collections::{BinaryHeap, HashMap};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// A timed event in the lab reactor.
///
/// Events are ordered by delivery time, with sequence numbers breaking ties
/// for deterministic ordering when events occur at the same time.
#[derive(Debug, PartialEq, Eq)]
struct TimedEvent {
    /// When to deliver this event (virtual time).
    time: Time,
    /// Sequence number for deterministic ordering of same-time events.
    sequence: u64,
    /// The actual event to deliver.
    event: Event,
}

impl PartialOrd for TimedEvent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimedEvent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Min-heap: earliest time first, then by sequence for determinism
        other
            .time
            .cmp(&self.time)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

/// A virtual socket state.
#[derive(Debug)]
struct VirtualSocket {
    interest: Interest,
}

/// A deterministic reactor for testing.
///
/// This reactor operates in virtual time and allows test code to inject
/// events at specific points. It's used by the lab runtime for deterministic
/// testing of async I/O code.
#[derive(Debug)]
pub struct LabReactor {
    inner: Mutex<LabInner>,
    /// Wake flag for simulating reactor wakeup.
    woken: AtomicBool,
}

#[derive(Debug)]
struct LabInner {
    sockets: HashMap<Token, VirtualSocket>,
    pending: BinaryHeap<TimedEvent>,
    time: Time,
    /// Monotonic sequence counter for deterministic same-time event ordering.
    next_sequence: u64,
}

impl LabReactor {
    /// Creates a new lab reactor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(LabInner {
                sockets: HashMap::new(),
                pending: BinaryHeap::new(),
                time: Time::ZERO,
                next_sequence: 0,
            }),
            woken: AtomicBool::new(false),
        }
    }

    /// Injects an event into the reactor at a specific delay from now.
    ///
    /// The event will be delivered when virtual time advances past the delay.
    /// This is the primary mechanism for testing I/O-dependent code.
    /// Events scheduled at the same time are delivered in insertion order.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to associate with the event
    /// * `event` - The event to inject
    /// * `delay` - How far in the future to deliver the event
    ///
    /// # Aliases
    ///
    /// This method is also known as `schedule_event()` in the spec.
    pub fn inject_event(&self, token: Token, mut event: Event, delay: Duration) {
        let mut inner = self.inner.lock().unwrap();
        let time = inner.time.saturating_add_nanos(delay.as_nanos() as u64);
        let sequence = inner.next_sequence;
        inner.next_sequence += 1;
        event.token = token;
        inner.pending.push(TimedEvent {
            time,
            sequence,
            event,
        });
    }

    /// Alias for `inject_event` to match the spec terminology.
    ///
    /// Schedules an event for future delivery at a specific delay from now.
    pub fn schedule_event(&self, token: Token, event: Event, delay: Duration) {
        self.inject_event(token, event, delay);
    }

    /// Makes a source immediately ready for the specified event type.
    ///
    /// The event will be delivered on the next call to `poll()`.
    /// Multiple calls to `set_ready()` for the same token append events.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to make ready
    /// * `event` - The event type (readable, writable, etc.)
    pub fn set_ready(&self, token: Token, event: Event) {
        self.inject_event(token, event, Duration::ZERO);
    }

    /// Returns the current virtual time.
    #[must_use]
    pub fn now(&self) -> Time {
        self.inner.lock().unwrap().time
    }

    /// Advances virtual time by the specified duration.
    ///
    /// This is useful for testing timeout behavior without going through poll().
    pub fn advance_time(&self, duration: Duration) {
        let mut inner = self.inner.lock().unwrap();
        inner.time = inner.time.saturating_add_nanos(duration.as_nanos() as u64);
    }

    /// Advances virtual time to a specific target time.
    ///
    /// If the target time is before the current time, this is a no-op.
    /// Events scheduled between the current time and target time will be
    /// delivered on the next `poll()` call.
    ///
    /// # Arguments
    ///
    /// * `target` - The target virtual time to advance to
    pub fn advance_time_to(&self, target: Time) {
        let mut inner = self.inner.lock().unwrap();
        if target > inner.time {
            inner.time = target;
        }
    }

    /// Checks if the reactor has been woken.
    ///
    /// Clears the wake flag and returns its previous value.
    pub fn check_and_clear_wake(&self) -> bool {
        self.woken.swap(false, Ordering::SeqCst)
    }
}

impl Default for LabReactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Reactor for LabReactor {
    fn register(&self, _source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.sockets.contains_key(&token) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "token already registered",
            ));
        }
        inner.sockets.insert(token, VirtualSocket { interest });
        Ok(())
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        match inner.sockets.get_mut(&token) {
            Some(socket) => {
                socket.interest = interest;
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "token not registered",
            )),
        }
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.sockets.remove(&token).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "token not registered",
            ));
        }

        // Clean up any scheduled events for this token.
        // Since BinaryHeap doesn't support retain, we rebuild without the token's events.
        let old_pending = std::mem::take(&mut inner.pending);
        inner.pending = old_pending
            .into_iter()
            .filter(|te| te.event.token != token)
            .collect();

        Ok(())
    }

    fn poll(&self, events: &mut super::Events, timeout: Option<Duration>) -> io::Result<usize> {
        // Clear wake flag at poll entry
        self.woken.store(false, Ordering::SeqCst);

        let mut inner = self.inner.lock().unwrap();

        // Advance time if timeout provided (simulated)
        if let Some(d) = timeout {
            inner.time = inner.time.saturating_add_nanos(d.as_nanos() as u64);
        }

        let mut count = 0;
        // Pop events that are due
        while let Some(te) = inner.pending.peek() {
            if te.time <= inner.time {
                let te = inner.pending.pop().unwrap();
                if inner.sockets.contains_key(&te.event.token) {
                    events.push(te.event);
                    count += 1;
                }
            } else {
                break;
            }
        }

        Ok(count)
    }

    fn wake(&self) -> io::Result<()> {
        self.woken.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn registration_count(&self) -> usize {
        self.inner.lock().unwrap().sockets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSource;
    impl std::os::fd::AsRawFd for MockSource {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            0
        }
    }

    #[test]
    fn delivers_injected_event() {
        let reactor = LabReactor::new();
        let token = Token::new(1);
        let source = MockSource;

        reactor
            .register(&source, token, Interest::readable())
            .unwrap();

        reactor.inject_event(token, Event::readable(token), Duration::from_millis(10));

        let mut events = crate::runtime::reactor::Events::with_capacity(10);

        // Poll before time - should be empty
        reactor
            .poll(&mut events, Some(Duration::from_millis(5)))
            .unwrap();
        assert!(events.is_empty());

        // Poll after time - should have event
        reactor
            .poll(&mut events, Some(Duration::from_millis(10)))
            .unwrap();
        assert_eq!(events.iter().count(), 1);
    }

    #[test]
    fn modify_interest() {
        let reactor = LabReactor::new();
        let token = Token::new(1);
        let source = MockSource;

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();
        assert_eq!(reactor.registration_count(), 1);

        // Modify to writable
        reactor.modify(token, Interest::WRITABLE).unwrap();

        // Should fail for non-existent token
        let result = reactor.modify(Token::new(999), Interest::READABLE);
        assert!(result.is_err());
    }

    #[test]
    fn deregister_by_token() {
        let reactor = LabReactor::new();
        let token = Token::new(1);
        let source = MockSource;

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();
        assert_eq!(reactor.registration_count(), 1);

        reactor.deregister(token).unwrap();
        assert_eq!(reactor.registration_count(), 0);

        // Deregister again should fail
        let result = reactor.deregister(token);
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_register_fails() {
        let reactor = LabReactor::new();
        let token = Token::new(1);
        let source = MockSource;

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();

        // Second registration with same token should fail
        let result = reactor.register(&source, token, Interest::WRITABLE);
        assert!(result.is_err());
    }

    #[test]
    fn wake_sets_flag() {
        let reactor = LabReactor::new();

        assert!(!reactor.check_and_clear_wake());

        reactor.wake().unwrap();
        assert!(reactor.check_and_clear_wake());

        // Flag should be cleared
        assert!(!reactor.check_and_clear_wake());
    }

    #[test]
    fn registration_count_and_is_empty() {
        let reactor = LabReactor::new();
        let source = MockSource;

        assert!(reactor.is_empty());
        assert_eq!(reactor.registration_count(), 0);

        reactor
            .register(&source, Token::new(1), Interest::READABLE)
            .unwrap();
        assert!(!reactor.is_empty());
        assert_eq!(reactor.registration_count(), 1);

        reactor
            .register(&source, Token::new(2), Interest::WRITABLE)
            .unwrap();
        assert_eq!(reactor.registration_count(), 2);

        reactor.deregister(Token::new(1)).unwrap();
        assert_eq!(reactor.registration_count(), 1);

        reactor.deregister(Token::new(2)).unwrap();
        assert!(reactor.is_empty());
    }

    #[test]
    fn virtual_time_advances() {
        let reactor = LabReactor::new();

        assert_eq!(reactor.now(), Time::ZERO);

        reactor.advance_time(Duration::from_secs(1));
        assert_eq!(reactor.now().as_nanos(), 1_000_000_000);

        // Poll also advances time
        let mut events = crate::runtime::reactor::Events::with_capacity(10);
        reactor
            .poll(&mut events, Some(Duration::from_millis(500)))
            .unwrap();
        assert_eq!(reactor.now().as_nanos(), 1_500_000_000);
    }

    #[test]
    fn advance_time_to_target() {
        let reactor = LabReactor::new();

        assert_eq!(reactor.now(), Time::ZERO);

        // Advance to 1 second
        reactor.advance_time_to(Time::from_nanos(1_000_000_000));
        assert_eq!(reactor.now().as_nanos(), 1_000_000_000);

        // Advancing to past time is a no-op
        reactor.advance_time_to(Time::from_nanos(500_000_000));
        assert_eq!(reactor.now().as_nanos(), 1_000_000_000);

        // Advance further
        reactor.advance_time_to(Time::from_nanos(2_000_000_000));
        assert_eq!(reactor.now().as_nanos(), 2_000_000_000);
    }

    #[test]
    fn set_ready_delivers_immediately() {
        let reactor = LabReactor::new();
        let token = Token::new(1);
        let source = MockSource;

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();

        // Set ready immediately
        reactor.set_ready(token, Event::readable(token));

        let mut events = crate::runtime::reactor::Events::with_capacity(10);

        // Poll with zero timeout should still deliver the event
        reactor
            .poll(&mut events, Some(Duration::ZERO))
            .unwrap();
        assert_eq!(events.iter().count(), 1);
    }

    #[test]
    fn same_time_events_delivered_in_order() {
        let reactor = LabReactor::new();
        let source = MockSource;

        // Register multiple tokens
        let token1 = Token::new(1);
        let token2 = Token::new(2);
        let token3 = Token::new(3);

        reactor.register(&source, token1, Interest::READABLE).unwrap();
        reactor.register(&source, token2, Interest::READABLE).unwrap();
        reactor.register(&source, token3, Interest::READABLE).unwrap();

        // Schedule all at the same time (10ms from now)
        // They should be delivered in insertion order: 1, 2, 3
        reactor.schedule_event(token1, Event::readable(token1), Duration::from_millis(10));
        reactor.schedule_event(token2, Event::readable(token2), Duration::from_millis(10));
        reactor.schedule_event(token3, Event::readable(token3), Duration::from_millis(10));

        let mut events = crate::runtime::reactor::Events::with_capacity(10);

        // Advance time past the scheduled time
        reactor.poll(&mut events, Some(Duration::from_millis(15))).unwrap();

        // Should have 3 events in order
        let collected: Vec<_> = events.iter().collect();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0].token, token1);
        assert_eq!(collected[1].token, token2);
        assert_eq!(collected[2].token, token3);
    }

    #[test]
    fn different_time_events_delivered_in_time_order() {
        let reactor = LabReactor::new();
        let source = MockSource;

        let token1 = Token::new(1);
        let token2 = Token::new(2);
        let token3 = Token::new(3);

        reactor.register(&source, token1, Interest::READABLE).unwrap();
        reactor.register(&source, token2, Interest::READABLE).unwrap();
        reactor.register(&source, token3, Interest::READABLE).unwrap();

        // Schedule in reverse order of delivery time
        // token3 at 5ms, token1 at 10ms, token2 at 15ms
        reactor.schedule_event(token3, Event::readable(token3), Duration::from_millis(5));
        reactor.schedule_event(token1, Event::readable(token1), Duration::from_millis(10));
        reactor.schedule_event(token2, Event::readable(token2), Duration::from_millis(15));

        let mut events = crate::runtime::reactor::Events::with_capacity(10);

        // Poll to 20ms - all events should be delivered
        reactor.poll(&mut events, Some(Duration::from_millis(20))).unwrap();

        // Should be in time order: token3, token1, token2
        let collected: Vec<_> = events.iter().collect();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0].token, token3);
        assert_eq!(collected[1].token, token1);
        assert_eq!(collected[2].token, token2);
    }

    #[test]
    fn schedule_event_alias_works() {
        let reactor = LabReactor::new();
        let token = Token::new(1);
        let source = MockSource;

        reactor.register(&source, token, Interest::READABLE).unwrap();

        // Use schedule_event (alias for inject_event)
        reactor.schedule_event(token, Event::readable(token), Duration::from_millis(10));

        let mut events = crate::runtime::reactor::Events::with_capacity(10);
        reactor.poll(&mut events, Some(Duration::from_millis(15))).unwrap();

        assert_eq!(events.iter().count(), 1);
    }

    #[test]
    fn events_before_current_time_delivered_immediately() {
        let reactor = LabReactor::new();
        let source = MockSource;
        let token = Token::new(1);

        reactor.register(&source, token, Interest::READABLE).unwrap();

        // First advance time
        reactor.advance_time(Duration::from_millis(100));

        // Schedule event at current time (delay = 0)
        reactor.schedule_event(token, Event::readable(token), Duration::ZERO);

        let mut events = crate::runtime::reactor::Events::with_capacity(10);

        // Poll with zero timeout should deliver
        reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();

        assert_eq!(events.iter().count(), 1);
    }

    #[test]
    fn deregister_cleans_up_scheduled_events() {
        let reactor = LabReactor::new();
        let source = MockSource;

        let token1 = Token::new(1);
        let token2 = Token::new(2);

        reactor.register(&source, token1, Interest::READABLE).unwrap();
        reactor.register(&source, token2, Interest::READABLE).unwrap();

        // Schedule events for both tokens
        reactor.schedule_event(token1, Event::readable(token1), Duration::from_millis(10));
        reactor.schedule_event(token2, Event::readable(token2), Duration::from_millis(10));
        reactor.schedule_event(token1, Event::readable(token1), Duration::from_millis(20));

        // Deregister token1
        reactor.deregister(token1).unwrap();

        let mut events = crate::runtime::reactor::Events::with_capacity(10);

        // Advance time past all scheduled events
        reactor.poll(&mut events, Some(Duration::from_millis(25))).unwrap();

        // Should only have token2's event (token1's events were cleaned up)
        let collected: Vec<_> = events.iter().collect();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].token, token2);
    }

    /// Integration test verifying IoDriver correctly dispatches wakers with LabReactor.
    mod io_driver_integration {
        use super::*;
        use crate::runtime::io_driver::IoDriver;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::task::{Wake, Waker};

        struct FlagWaker {
            flag: AtomicBool,
            count: AtomicUsize,
        }

        impl Wake for FlagWaker {
            fn wake(self: Arc<Self>) {
                self.flag.store(true, Ordering::SeqCst);
                self.count.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.flag.store(true, Ordering::SeqCst);
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn create_test_waker() -> (Waker, Arc<FlagWaker>) {
            let state = Arc::new(FlagWaker {
                flag: AtomicBool::new(false),
                count: AtomicUsize::new(0),
            });
            (Waker::from(state.clone()), state)
        }

        #[test]
        fn io_driver_with_lab_reactor_dispatches_wakers() {
            let reactor = Arc::new(LabReactor::new());
            let mut driver = IoDriver::new(reactor.clone());
            let source = MockSource;

            // Register with IoDriver
            let (waker, waker_state) = create_test_waker();
            let token = driver
                .register(&source, Interest::READABLE, waker)
                .expect("register");

            // Waker should not be woken yet
            assert!(!waker_state.flag.load(Ordering::SeqCst));

            // Inject an event for our token
            reactor.inject_event(token, Event::readable(token), Duration::ZERO);

            // Turn the driver - should dispatch the waker
            let count = driver
                .turn(Some(Duration::from_millis(10)))
                .expect("turn");

            assert!(count >= 1);
            assert!(waker_state.flag.load(Ordering::SeqCst));
            assert_eq!(waker_state.count.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn io_driver_with_lab_reactor_multiple_wakers() {
            let reactor = Arc::new(LabReactor::new());
            let mut driver = IoDriver::new(reactor.clone());
            let source = MockSource;

            // Register multiple wakers
            let (waker1, state1) = create_test_waker();
            let (waker2, state2) = create_test_waker();
            let (waker3, state3) = create_test_waker();

            let token1 = driver.register(&source, Interest::READABLE, waker1).unwrap();
            let _token2 = driver.register(&source, Interest::READABLE, waker2).unwrap();
            let token3 = driver.register(&source, Interest::READABLE, waker3).unwrap();

            // Inject events for tokens 1 and 3 only
            reactor.inject_event(token1, Event::readable(token1), Duration::ZERO);
            reactor.inject_event(token3, Event::readable(token3), Duration::ZERO);

            // Turn should dispatch wakers 1 and 3
            let count = driver.turn(Some(Duration::from_millis(10))).unwrap();

            assert_eq!(count, 2);
            assert!(state1.flag.load(Ordering::SeqCst));
            assert!(!state2.flag.load(Ordering::SeqCst)); // Not woken
            assert!(state3.flag.load(Ordering::SeqCst));
        }
    }
}
