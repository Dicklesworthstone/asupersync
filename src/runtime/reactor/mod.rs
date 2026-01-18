//! Reactor abstraction for I/O event multiplexing.

pub mod interest;
pub mod lab;

pub use interest::Interest;
pub use lab::LabReactor;

use std::io;
use std::time::Duration;

/// Token identifying a registered source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Token(pub usize);

impl Token {
    /// Creates a new token.
    #[must_use]
    pub const fn new(val: usize) -> Self {
        Self(val)
    }
}

/// I/O event from the reactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Event {
    /// Token identifying the registered source.
    pub token: Token,
    /// True if the source is readable.
    pub readable: bool,
    /// True if the source is writable.
    pub writable: bool,
    /// True if an error was reported.
    pub error: bool,
    /// True if the source reported hangup.
    pub hangup: bool,
}

impl Event {
    /// Creates a readable event.
    #[must_use]
    pub const fn readable(token: Token) -> Self {
        Self {
            token,
            readable: true,
            writable: false,
            error: false,
            hangup: false,
        }
    }

    /// Creates a writable event.
    #[must_use]
    pub const fn writable(token: Token) -> Self {
        Self {
            token,
            readable: false,
            writable: true,
            error: false,
            hangup: false,
        }
    }

    /// Creates an error event.
    #[must_use]
    pub const fn errored(token: Token) -> Self {
        Self {
            token,
            readable: false,
            writable: false,
            error: true,
            hangup: false,
        }
    }
}

/// Buffer for events.
#[derive(Debug)]
pub struct Events {
    pub(crate) inner: Vec<Event>,
}

impl Events {
    /// Creates a new events buffer with capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    /// Clears the buffer.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Iterates over events.
    pub fn iter(&self) -> std::slice::Iter<'_, Event> {
        self.inner.iter()
    }

    /// Pushes an event (internal use).
    pub(crate) fn push(&mut self, event: Event) {
        self.inner.push(event);
    }

    /// Returns true if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<'a> IntoIterator for &'a Events {
    type Item = &'a Event;
    type IntoIter = std::slice::Iter<'a, Event>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for Events {
    type Item = Event;
    type IntoIter = std::vec::IntoIter<Event>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

/// Registration handle returned by the reactor.
#[derive(Debug)]
pub struct Registration {
    /// The token associated with this registration.
    pub token: Token,
}

/// Trait for an I/O reactor.
pub trait Reactor: Send + Sync {
    /// Registers interest in I/O events.
    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()>;

    /// Deregisters a source.
    fn deregister(&self, source: &dyn Source, token: Token) -> io::Result<()>;

    /// Polls for events, blocking up to `timeout`.
    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize>;
}

/// Trait for an I/O source.
pub trait Source: std::os::fd::AsRawFd + Send + Sync {}

impl<T: std::os::fd::AsRawFd + Send + Sync> Source for T {}
