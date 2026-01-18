//! Deterministic lab reactor for testing.

use super::{Event, Interest, Reactor, Source, Token}; // Added Source to import
use crate::types::Time;
use std::collections::{BinaryHeap, HashMap};
use std::io;
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
    // buffer, etc.
}

/// A deterministic reactor for testing.
#[derive(Debug)]
pub struct LabReactor {
    inner: Mutex<LabInner>,
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
        }
    }

    /// Injects an event into the reactor.
    pub fn inject_event(&self, token: Token, mut event: Event, delay: Duration) {
        let mut inner = self.inner.lock().unwrap();
        let time = inner.time.saturating_add_nanos(delay.as_nanos() as u64);
        event.token = token;
        inner.pending.push(TimedEvent { time, event });
    }
}

impl Default for LabReactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Reactor for LabReactor {
    fn register(&self, _source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        self.inner
            .lock()
            .unwrap()
            .sockets
            .insert(token, VirtualSocket { interest });
        Ok(())
    }

    fn deregister(&self, _source: &dyn Source, token: Token) -> io::Result<()> {
        self.inner.lock().unwrap().sockets.remove(&token);
        Ok(())
    }

    fn poll(&self, events: &mut super::Events, timeout: Option<Duration>) -> io::Result<usize> {
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
}
