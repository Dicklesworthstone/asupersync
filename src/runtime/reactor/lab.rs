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
#[derive(Debug, PartialEq, Eq)]
struct TimedEvent {
    time: Time,
    event: Event,
}

impl PartialOrd for TimedEvent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimedEvent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Min-heap: earliest time first
        other.time.cmp(&self.time)
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
            }),
            woken: AtomicBool::new(false),
        }
    }

    /// Injects an event into the reactor at a specific delay from now.
    ///
    /// The event will be delivered when virtual time advances past the delay.
    /// This is the primary mechanism for testing I/O-dependent code.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to associate with the event
    /// * `event` - The event to inject
    /// * `delay` - How far in the future to deliver the event
    pub fn inject_event(&self, token: Token, mut event: Event, delay: Duration) {
        let mut inner = self.inner.lock().unwrap();
        let time = inner.time.saturating_add_nanos(delay.as_nanos() as u64);
        event.token = token;
        inner.pending.push(TimedEvent { time, event });
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
}
