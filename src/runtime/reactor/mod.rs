//! Reactor abstraction for I/O event multiplexing.
//!
//! This module provides the [`Reactor`] trait and associated types for platform-agnostic
//! I/O event notification. The reactor is the core of the async runtime's I/O system,
//! monitoring registered sources and notifying the runtime when they become ready.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         Runtime                                  │
//! │  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐   │
//! │  │    Tasks      │────│   Scheduler   │────│   IoDriver    │   │
//! │  └───────────────┘    └───────────────┘    └───────┬───────┘   │
//! │                                                     │           │
//! │  ┌──────────────────────────────────────────────────┼─────────┐ │
//! │  │                     Reactor                       │         │ │
//! │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────▼───────┐ │ │
//! │  │  │ Token Slab  │  │ Interest    │  │    Platform API     │ │ │
//! │  │  │ (waker map) │  │ Registry    │  │ (epoll/kqueue/IOCP) │ │ │
//! │  │  └─────────────┘  └─────────────┘  └─────────────────────┘ │ │
//! │  └────────────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Types
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`Reactor`] | Trait for I/O event notification backends |
//! | [`Interest`] | Bitflags for readable/writable/error events |
//! | [`Events`] | Container for poll results |
//! | [`Event`] | Single readiness notification |
//! | [`Token`] | Identifier linking registrations to events |
//! | [`Registration`] | RAII handle for registered sources |
//! | [`Source`] | Trait for I/O objects that can be registered |
//!
//! # Platform Backends
//!
//! | Platform | Backend | Module |
//! |----------|---------|--------|
//! | Linux | epoll | `linux.rs` |
//! | macOS/BSD | kqueue | `macos.rs` |
//! | Windows | IOCP | `windows.rs` |
//! | Testing | virtual | `lab.rs` |
//!
//! # Usage Pattern
//!
//! ```ignore
//! use asupersync::runtime::reactor::{Reactor, Interest, Events, Token};
//!
//! // 1. Register a source
//! let token = Token::new(42);
//! reactor.register(&socket, token, Interest::READABLE)?;
//!
//! // 2. Poll for events
//! let mut events = Events::with_capacity(64);
//! loop {
//!     let n = reactor.poll(&mut events, Some(Duration::from_secs(1)))?;
//!
//!     for event in &events {
//!         match event.token {
//!             token if event.is_readable() => handle_read(token),
//!             token if event.is_writable() => handle_write(token),
//!             _ => {}
//!         }
//!     }
//!     events.clear();
//! }
//!
//! // 3. Deregister when done
//! reactor.deregister(token)?;
//! ```
//!
//! # Edge vs Level Triggering
//!
//! Implementations prefer edge-triggered mode where available:
//!
//! | Mode | Behavior | Use Case |
//! |------|----------|----------|
//! | **Edge** | Fire once on state *change* | High-performance servers |
//! | **Level** | Fire while state *persists* | Simple applications |
//!
//! Edge-triggered requires fully draining the source before re-waiting.
//! The [`Interest::EDGE_TRIGGERED`] flag enables edge mode when supported.
//!
//! # Cancel Safety
//!
//! The [`Registration`] type provides RAII deregistration. When a `Registration`
//! is dropped (e.g., due to task cancellation), it automatically deregisters from
//! the reactor. This prevents:
//!
//! - Dangling registrations for closed sources
//! - Spurious wakeups to cancelled tasks
//! - Resource leaks in the reactor's token slab

pub mod interest;
pub mod lab;
mod registration;
pub mod source;
pub mod token;

#[cfg(target_os = "linux")]
pub mod epoll;

pub use interest::Interest;
pub use lab::{FaultConfig, LabReactor};
#[allow(unused_imports)]
pub(crate) use registration::ReactorHandle;
pub use registration::Registration;
pub use source::{next_source_id, Source, SourceId, SourceWrapper};
pub use token::{SlabToken, TokenSlab};

#[cfg(target_os = "linux")]
pub use epoll::EpollReactor;

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
///
/// Represents a single readiness notification for a registered source.
///
/// # Example
///
/// ```ignore
/// use asupersync::runtime::reactor::{Event, Interest, Token};
///
/// let event = Event::new(Token::new(1), Interest::READABLE | Interest::WRITABLE);
/// assert!(event.is_readable());
/// assert!(event.is_writable());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// Token identifying the registered source.
    pub token: Token,
    /// Readiness flags that triggered.
    pub ready: Interest,
}

impl Event {
    /// Creates a new event with specified token and readiness flags.
    #[must_use]
    pub const fn new(token: Token, ready: Interest) -> Self {
        Self { token, ready }
    }

    /// Creates a readable event.
    #[must_use]
    pub const fn readable(token: Token) -> Self {
        Self {
            token,
            ready: Interest::READABLE,
        }
    }

    /// Creates a writable event.
    #[must_use]
    pub const fn writable(token: Token) -> Self {
        Self {
            token,
            ready: Interest::WRITABLE,
        }
    }

    /// Creates an error event.
    #[must_use]
    pub const fn errored(token: Token) -> Self {
        Self {
            token,
            ready: Interest::ERROR,
        }
    }

    /// Creates a hangup event.
    #[must_use]
    pub const fn hangup(token: Token) -> Self {
        Self {
            token,
            ready: Interest::HUP,
        }
    }

    /// Returns true if the source is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.ready.is_readable()
    }

    /// Returns true if the source is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.ready.is_writable()
    }

    /// Returns true if an error was reported.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.ready.is_error()
    }

    /// Returns true if the source reported hangup.
    #[must_use]
    pub const fn is_hangup(&self) -> bool {
        self.ready.is_hup()
    }
}

/// Container for I/O events returned by poll().
///
/// Re-use across poll() calls to avoid allocation.
///
/// # Example
///
/// ```ignore
/// use asupersync::runtime::reactor::Events;
///
/// let mut events = Events::with_capacity(64);
/// // ... poll ...
/// for event in &events {
///     println!("Token {:?} is ready: {:?}", event.token, event.ready);
/// }
/// events.clear();
/// ```
#[derive(Debug)]
pub struct Events {
    inner: Vec<Event>,
    capacity: usize,
}

impl Events {
    /// Creates a new events buffer with the given capacity.
    ///
    /// The capacity limits the maximum number of events that can be stored.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Clears all events, maintaining capacity.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Pushes an event.
    ///
    /// Events beyond capacity are silently dropped to prevent unbounded growth.
    pub(crate) fn push(&mut self, event: Event) {
        if self.inner.len() < self.capacity {
            self.inner.push(event);
        }
    }

    /// Returns the number of events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if no events are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the capacity (maximum number of events).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Iterates over events.
    pub fn iter(&self) -> std::slice::Iter<'_, Event> {
        self.inner.iter()
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

/// Platform-agnostic reactor for I/O event notification.
///
/// A reactor provides the core I/O multiplexing functionality for an async runtime.
/// It monitors registered I/O sources (sockets, files, pipes) for readiness events
/// and notifies the runtime when sources become readable, writable, or encounter errors.
///
/// # Platform Backends
///
/// | Platform | Backend | Module |
/// |----------|---------|--------|
/// | Linux | epoll | `linux.rs` |
/// | macOS/BSD | kqueue | `macos.rs` |
/// | Windows | IOCP | `windows.rs` |
/// | Testing | virtual | `lab.rs` |
///
/// # Thread Safety
///
/// Reactor implementations must be thread-safe (`Send + Sync`). Typically the reactor
/// is shared across the runtime via `Arc<dyn Reactor>`. All methods use interior
/// mutability and are safe to call from multiple threads concurrently.
///
/// # Cancellation Safety
///
/// When a [`Registration`] is dropped, it automatically deregisters from the reactor.
/// This ensures cancel-safety: cancelled tasks don't leave dangling registrations that
/// could cause spurious wakeups or resource leaks.
///
/// # Edge vs Level Triggering
///
/// Implementations should prefer edge-triggered mode where available:
/// - **epoll**: Uses `EPOLLET` (edge-triggered)
/// - **kqueue**: Edge-triggered by default (level with `EV_CLEAR`)
/// - **IOCP**: Completion-based (neither edge nor level)
///
/// Edge-triggered mode requires callers to fully drain readable/writable state
/// before re-waiting, but provides better performance under high load.
///
/// # Example
///
/// ```ignore
/// use asupersync::runtime::reactor::{Reactor, Interest, Events};
/// use std::time::Duration;
///
/// fn poll_loop(reactor: &dyn Reactor) -> io::Result<()> {
///     let mut events = Events::with_capacity(64);
///
///     loop {
///         // Block until events or timeout
///         let n = reactor.poll(&mut events, Some(Duration::from_secs(1)))?;
///
///         for event in &events {
///             if event.is_readable() {
///                 // Handle readable source
///             }
///             if event.is_writable() {
///                 // Handle writable source
///             }
///         }
///
///         events.clear();
///     }
/// }
/// ```
pub trait Reactor: Send + Sync {
    /// Registers interest in I/O events for a source.
    ///
    /// Creates a new registration for the given source, associating it with the
    /// provided token and interest flags. The token will be included in any events
    /// generated for this source.
    ///
    /// # Arguments
    ///
    /// * `source` - The I/O source to register (must implement [`Source`])
    /// * `token` - A unique token to identify this registration in events
    /// * `interest` - The events to monitor (readable, writable, error, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails:
    /// - `io::ErrorKind::AlreadyExists` - Source is already registered
    /// - `io::ErrorKind::InvalidInput` - Source fd/handle is invalid
    /// - `io::ErrorKind::OutOfMemory` - Too many registrations
    /// - Platform-specific errors from epoll_ctl/kevent/CreateIoCompletionPort
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Calls `epoll_ctl(EPOLL_CTL_ADD)`
    /// - **macOS**: Calls `kevent()` with `EV_ADD`
    /// - **Windows**: Associates with IOCP
    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()>;

    /// Modifies the interest set for an existing registration.
    ///
    /// Changes which events are monitored for a previously registered source.
    /// This is more efficient than deregistering and re-registering.
    ///
    /// # Arguments
    ///
    /// * `token` - The token identifying the registration
    /// * `interest` - The new interest flags to monitor
    ///
    /// # Errors
    ///
    /// Returns an error if modification fails:
    /// - `io::ErrorKind::NotFound` - Token not registered
    /// - `io::ErrorKind::InvalidInput` - Invalid interest flags
    /// - Platform-specific errors
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Calls `epoll_ctl(EPOLL_CTL_MOD)`
    /// - **macOS**: Calls `kevent()` with `EV_ADD` (idempotent)
    /// - **Windows**: Re-posts completion notification
    fn modify(&self, token: Token, interest: Interest) -> io::Result<()>;

    /// Deregisters a previously registered source by token.
    ///
    /// Removes the source from the reactor's set of monitored sources.
    /// After deregistration, no more events will be generated for this source.
    ///
    /// This method is called automatically by [`Registration::drop()`].
    /// Direct calls are only needed for explicit deregistration with error handling.
    ///
    /// # Arguments
    ///
    /// * `token` - The token identifying the registration to remove
    ///
    /// # Errors
    ///
    /// Returns an error if deregistration fails:
    /// - `io::ErrorKind::NotFound` - Token not registered
    /// - Platform-specific errors
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Calls `epoll_ctl(EPOLL_CTL_DEL)`
    /// - **macOS**: Calls `kevent()` with `EV_DELETE`
    /// - **Windows**: Disassociates from IOCP
    fn deregister(&self, token: Token) -> io::Result<()>;

    /// Polls for I/O events, blocking up to `timeout`.
    ///
    /// Waits for I/O events on registered sources and fills the events buffer
    /// with any that occur. This is the main driver method for an async runtime.
    ///
    /// # Arguments
    ///
    /// * `events` - Buffer to store received events (cleared before use)
    /// * `timeout` - Maximum time to wait:
    ///   - `None`: Block indefinitely until an event occurs
    ///   - `Some(Duration::ZERO)`: Non-blocking poll, return immediately
    ///   - `Some(d)`: Block up to duration `d`
    ///
    /// # Returns
    ///
    /// The number of events placed in `events`. Returns `Ok(0)` on timeout
    /// with no events.
    ///
    /// # Errors
    ///
    /// Returns an error if polling fails:
    /// - `io::ErrorKind::Interrupted` - Signal interrupted the wait
    /// - Platform-specific errors from epoll_wait/kevent/GetQueuedCompletionStatus
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Calls `epoll_wait()`
    /// - **macOS**: Calls `kevent()`
    /// - **Windows**: Calls `GetQueuedCompletionStatusEx()`
    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize>;

    /// Wakes the reactor from a blocking [`poll()`](Self::poll) call.
    ///
    /// This method signals the reactor to return from poll() early, even if
    /// no I/O events are pending. It's used when:
    /// - New tasks are spawned and need to be scheduled
    /// - Timers fire and need to be processed
    /// - The runtime is shutting down
    ///
    /// Must be safe to call from any thread, including threads not involved
    /// in the reactor's poll loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the wake signal cannot be sent:
    /// - Platform-specific errors from eventfd/pipe/PostQueuedCompletionStatus
    ///
    /// # Implementation Notes
    ///
    /// - **Linux**: Write to eventfd registered with the epoll
    /// - **macOS**: Write to a self-pipe or use EVFILT_USER
    /// - **Windows**: Call `PostQueuedCompletionStatus()`
    ///
    /// Implementations should coalesce multiple wake() calls into a single
    /// wakeup to avoid thundering herd issues.
    fn wake(&self) -> io::Result<()>;

    /// Returns the number of active registrations.
    ///
    /// Useful for diagnostics and capacity planning.
    fn registration_count(&self) -> usize;

    /// Returns `true` if no sources are currently registered.
    ///
    /// Equivalent to `self.registration_count() == 0`, but may be more efficient.
    fn is_empty(&self) -> bool {
        self.registration_count() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    // Event tests
    #[test]
    fn event_new() {
        init_test("event_new");
        let event = Event::new(Token::new(42), Interest::READABLE | Interest::WRITABLE);
        crate::assert_with_log!(event.token.0 == 42, "token id", 42usize, event.token.0);
        crate::assert_with_log!(
            event.is_readable(),
            "readable flag",
            true,
            event.is_readable()
        );
        crate::assert_with_log!(
            event.is_writable(),
            "writable flag",
            true,
            event.is_writable()
        );
        crate::assert_with_log!(
            !event.is_error(),
            "error flag unset",
            false,
            event.is_error()
        );
        crate::assert_with_log!(
            !event.is_hangup(),
            "hangup flag unset",
            false,
            event.is_hangup()
        );
        crate::test_complete!("event_new");
    }

    #[test]
    fn event_readable() {
        init_test("event_readable");
        let event = Event::readable(Token::new(1));
        crate::assert_with_log!(
            event.is_readable(),
            "readable flag",
            true,
            event.is_readable()
        );
        crate::assert_with_log!(
            !event.is_writable(),
            "writable flag unset",
            false,
            event.is_writable()
        );
        crate::assert_with_log!(
            !event.is_error(),
            "error flag unset",
            false,
            event.is_error()
        );
        crate::assert_with_log!(
            !event.is_hangup(),
            "hangup flag unset",
            false,
            event.is_hangup()
        );
        crate::test_complete!("event_readable");
    }

    #[test]
    fn event_writable() {
        init_test("event_writable");
        let event = Event::writable(Token::new(2));
        crate::assert_with_log!(
            !event.is_readable(),
            "readable flag unset",
            false,
            event.is_readable()
        );
        crate::assert_with_log!(
            event.is_writable(),
            "writable flag",
            true,
            event.is_writable()
        );
        crate::assert_with_log!(
            !event.is_error(),
            "error flag unset",
            false,
            event.is_error()
        );
        crate::assert_with_log!(
            !event.is_hangup(),
            "hangup flag unset",
            false,
            event.is_hangup()
        );
        crate::test_complete!("event_writable");
    }

    #[test]
    fn event_errored() {
        init_test("event_errored");
        let event = Event::errored(Token::new(3));
        crate::assert_with_log!(
            !event.is_readable(),
            "readable flag unset",
            false,
            event.is_readable()
        );
        crate::assert_with_log!(
            !event.is_writable(),
            "writable flag unset",
            false,
            event.is_writable()
        );
        crate::assert_with_log!(event.is_error(), "error flag", true, event.is_error());
        crate::assert_with_log!(
            !event.is_hangup(),
            "hangup flag unset",
            false,
            event.is_hangup()
        );
        crate::test_complete!("event_errored");
    }

    #[test]
    fn event_hangup() {
        init_test("event_hangup");
        let event = Event::hangup(Token::new(4));
        crate::assert_with_log!(
            !event.is_readable(),
            "readable flag unset",
            false,
            event.is_readable()
        );
        crate::assert_with_log!(
            !event.is_writable(),
            "writable flag unset",
            false,
            event.is_writable()
        );
        crate::assert_with_log!(
            !event.is_error(),
            "error flag unset",
            false,
            event.is_error()
        );
        crate::assert_with_log!(event.is_hangup(), "hangup flag", true, event.is_hangup());
        crate::test_complete!("event_hangup");
    }

    #[test]
    fn event_combined_flags() {
        init_test("event_combined_flags");
        let event = Event::new(
            Token::new(5),
            Interest::READABLE | Interest::ERROR | Interest::HUP,
        );
        crate::assert_with_log!(
            event.is_readable(),
            "readable flag",
            true,
            event.is_readable()
        );
        crate::assert_with_log!(
            !event.is_writable(),
            "writable flag unset",
            false,
            event.is_writable()
        );
        crate::assert_with_log!(event.is_error(), "error flag", true, event.is_error());
        crate::assert_with_log!(event.is_hangup(), "hangup flag", true, event.is_hangup());
        crate::test_complete!("event_combined_flags");
    }

    // Events container tests
    #[test]
    fn events_with_capacity() {
        init_test("events_with_capacity");
        let events = Events::with_capacity(64);
        crate::assert_with_log!(
            events.capacity() == 64,
            "capacity",
            64usize,
            events.capacity()
        );
        crate::assert_with_log!(events.len() == 0, "len", 0usize, events.len());
        crate::assert_with_log!(events.is_empty(), "is_empty", true, events.is_empty());
        crate::test_complete!("events_with_capacity");
    }

    #[test]
    fn events_push_and_iterate() {
        init_test("events_push_and_iterate");
        let mut events = Events::with_capacity(10);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::writable(Token::new(2)));
        events.push(Event::errored(Token::new(3)));

        crate::assert_with_log!(events.len() == 3, "len", 3usize, events.len());
        crate::assert_with_log!(!events.is_empty(), "not empty", false, events.is_empty());

        let tokens: Vec<usize> = events.iter().map(|e| e.token.0).collect();
        crate::assert_with_log!(
            tokens == vec![1, 2, 3],
            "tokens order",
            vec![1, 2, 3],
            tokens
        );
        crate::test_complete!("events_push_and_iterate");
    }

    #[test]
    fn events_clear() {
        init_test("events_clear");
        let mut events = Events::with_capacity(10);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::readable(Token::new(2)));

        crate::assert_with_log!(events.len() == 2, "len before clear", 2usize, events.len());
        events.clear();
        crate::assert_with_log!(events.len() == 0, "len after clear", 0usize, events.len());
        crate::assert_with_log!(
            events.is_empty(),
            "empty after clear",
            true,
            events.is_empty()
        );
        // Capacity is maintained
        crate::assert_with_log!(
            events.capacity() == 10,
            "capacity maintained",
            10usize,
            events.capacity()
        );
        crate::test_complete!("events_clear");
    }

    #[test]
    fn events_capacity_limit_respected() {
        init_test("events_capacity_limit_respected");
        let mut events = Events::with_capacity(3);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::readable(Token::new(2)));
        events.push(Event::readable(Token::new(3)));
        // This should be silently dropped
        events.push(Event::readable(Token::new(4)));
        events.push(Event::readable(Token::new(5)));

        crate::assert_with_log!(events.len() == 3, "len capped", 3usize, events.len());
        crate::assert_with_log!(
            events.capacity() == 3,
            "capacity",
            3usize,
            events.capacity()
        );

        let tokens: Vec<usize> = events.iter().map(|e| e.token.0).collect();
        crate::assert_with_log!(
            tokens == vec![1, 2, 3],
            "tokens retained",
            vec![1, 2, 3],
            tokens
        );
        crate::test_complete!("events_capacity_limit_respected");
    }

    #[test]
    fn events_into_iter_ref() {
        init_test("events_into_iter_ref");
        let mut events = Events::with_capacity(10);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::writable(Token::new(2)));

        let mut count = 0;
        for event in &events {
            let ok = event.is_readable() || event.is_writable();
            crate::assert_with_log!(ok, "event readable or writable", true, ok);
            count += 1;
        }
        crate::assert_with_log!(count == 2, "iter count", 2usize, count);
        crate::test_complete!("events_into_iter_ref");
    }

    #[test]
    fn events_into_iter_owned() {
        init_test("events_into_iter_owned");
        let mut events = Events::with_capacity(10);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::writable(Token::new(2)));

        let collected: Vec<Event> = events.into_iter().collect();
        crate::assert_with_log!(
            collected.len() == 2,
            "collected len",
            2usize,
            collected.len()
        );
        crate::assert_with_log!(
            collected[0].is_readable(),
            "first readable",
            true,
            collected[0].is_readable()
        );
        crate::assert_with_log!(
            collected[1].is_writable(),
            "second writable",
            true,
            collected[1].is_writable()
        );
        crate::test_complete!("events_into_iter_owned");
    }

    #[test]
    fn events_zero_capacity() {
        init_test("events_zero_capacity");
        let mut events = Events::with_capacity(0);
        crate::assert_with_log!(
            events.capacity() == 0,
            "capacity zero",
            0usize,
            events.capacity()
        );
        crate::assert_with_log!(events.len() == 0, "len zero", 0usize, events.len());

        // Should be silently dropped
        events.push(Event::readable(Token::new(1)));
        crate::assert_with_log!(events.len() == 0, "len stays zero", 0usize, events.len());
        crate::test_complete!("events_zero_capacity");
    }

    // Token tests
    #[test]
    fn token_new() {
        init_test("token_new");
        let token = Token::new(123);
        crate::assert_with_log!(token.0 == 123, "token id", 123usize, token.0);
        crate::test_complete!("token_new");
    }

    #[test]
    fn token_equality() {
        init_test("token_equality");
        let t1 = Token::new(1);
        let t2 = Token::new(1);
        let t3 = Token::new(2);

        crate::assert_with_log!(t1 == t2, "t1 == t2", t2, t1);
        crate::assert_with_log!(t1 != t3, "t1 != t3", true, t1 != t3);
        crate::test_complete!("token_equality");
    }

    #[test]
    fn token_ordering() {
        init_test("token_ordering");
        let t1 = Token::new(1);
        let t2 = Token::new(2);

        crate::assert_with_log!(t1 < t2, "t1 < t2", true, t1 < t2);
        crate::assert_with_log!(t2 > t1, "t2 > t1", true, t2 > t1);
        crate::test_complete!("token_ordering");
    }
}
