//! macOS/BSD kqueue-based reactor implementation.
//!
//! This module provides [`KqueueReactor`], a reactor implementation that uses
//! kqueue for efficient I/O event notification with edge-triggered mode.
//!
//! # Safety
//!
//! This module uses `unsafe` code to interface with the `polling` crate's
//! low-level kqueue operations. The unsafe operations are:
//!
//! - `Poller::add()`: Registers a file descriptor with kqueue
//! - `Poller::modify()`: Modifies interest flags for a registered fd
//! - `Poller::delete()`: Removes a file descriptor from kqueue
//!
//! These are unsafe because the compiler cannot verify that file descriptors
//! remain valid for the duration of their registration. The `KqueueReactor`
//! maintains this invariant through careful bookkeeping and expects callers
//! to properly manage source lifetimes.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       KqueueReactor                              │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
//! │  │   Poller    │  │  notify()   │  │    registration map     │  │
//! │  │  (polling)  │  │  (builtin)  │  │   HashMap<Token, info>  │  │
//! │  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Thread Safety
//!
//! `KqueueReactor` is `Send + Sync` and can be shared across threads via `Arc`.
//! Internal state is protected by `Mutex` for registration/deregistration,
//! while `poll()` and `wake()` are lock-free for performance.
//!
//! # Edge-Triggered Mode
//!
//! Kqueue uses edge-triggered behavior by default (with EV_CLEAR).
//! Events fire when state *changes*, not while the condition persists.
//! Applications must read/write until `EAGAIN` before the next event.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::runtime::reactor::{KqueueReactor, Reactor, Interest, Events};
//! use std::net::TcpListener;
//!
//! let reactor = KqueueReactor::new()?;
//! let listener = TcpListener::bind("127.0.0.1:0")?;
//!
//! // Register the listener with kqueue (edge-triggered mode)
//! reactor.register(&listener, Token::new(1), Interest::READABLE)?;
//!
//! // Poll for events
//! let mut events = Events::with_capacity(64);
//! let count = reactor.poll(&mut events, Some(Duration::from_secs(1)))?;
//! ```

// Allow unsafe code for kqueue FFI operations via the polling crate.
// The unsafe operations (add, modify, delete) are necessary because the
// compiler cannot verify file descriptor validity at compile time.
#![allow(unsafe_code)]

use super::{Event, Events, Interest, Reactor, Source, Token};
use parking_lot::Mutex;
use polling::{Event as PollEvent, Poller};
use std::collections::HashMap;
use std::io;
use std::os::fd::BorrowedFd;
use std::time::Duration;

/// Registration state for a source.
#[derive(Debug)]
struct RegistrationInfo {
    /// The raw file descriptor (for bookkeeping).
    raw_fd: i32,
    /// The current interest flags.
    interest: Interest,
}

/// macOS/BSD kqueue-based reactor with edge-triggered mode.
///
/// This reactor uses the `polling` crate to interface with kqueue,
/// providing efficient I/O event notification for async operations.
///
/// # Features
///
/// - `register()`: Adds fd to kqueue with EV_CLEAR (edge-triggered)
/// - `modify()`: Updates interest flags for a registered fd
/// - `deregister()`: Removes fd from kqueue
/// - `poll()`: Waits for and collects ready events
/// - `wake()`: Interrupts a blocking poll from another thread
///
/// # Edge-Triggered Mode
///
/// Kqueue naturally supports edge-triggered semantics via EV_CLEAR.
/// Events fire when state *changes*, not while the condition persists.
/// Applications must read/write until `EAGAIN` before the next event.
///
/// # Platform Support
///
/// This reactor is only available on macOS, FreeBSD, OpenBSD, NetBSD,
/// and DragonFlyBSD (platforms that support kqueue).
pub struct KqueueReactor {
    /// The polling instance (wraps kqueue on macOS/BSD).
    poller: Poller,
    /// Maps tokens to registration info for bookkeeping.
    registrations: Mutex<HashMap<Token, RegistrationInfo>>,
}

impl KqueueReactor {
    /// Creates a new kqueue-based reactor.
    ///
    /// This initializes a `Poller` instance which creates a kqueue fd internally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `kqueue()` fails (e.g., out of file descriptors)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let reactor = KqueueReactor::new()?;
    /// assert!(reactor.is_empty());
    /// ```
    pub fn new() -> io::Result<Self> {
        let poller = Poller::new()?;

        Ok(Self {
            poller,
            registrations: Mutex::new(HashMap::new()),
        })
    }

    /// Converts our Interest flags to polling crate's event.
    fn interest_to_poll_event(token: Token, interest: Interest) -> PollEvent {
        let key = token.0;
        let readable = interest.is_readable();
        let writable = interest.is_writable();

        match (readable, writable) {
            (true, true) => PollEvent::all(key),
            (true, false) => PollEvent::readable(key),
            (false, true) => PollEvent::writable(key),
            (false, false) => PollEvent::none(key),
        }
    }

    /// Converts polling crate's event to our Interest type.
    fn poll_event_to_interest(event: &PollEvent) -> Interest {
        let mut interest = Interest::NONE;

        if event.readable {
            interest = interest.add(Interest::READABLE);
        }
        if event.writable {
            interest = interest.add(Interest::WRITABLE);
        }

        interest
    }
}

impl Reactor for KqueueReactor {
    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        let raw_fd = source.as_raw_fd();

        // Check for duplicate registration first
        let mut regs = self.registrations.lock();
        if regs.contains_key(&token) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "token already registered",
            ));
        }

        // Create the polling event with the token as the key
        let event = Self::interest_to_poll_event(token, interest);

        // SAFETY: We trust that the caller maintains the invariant that the
        // source (and its file descriptor) remains valid until deregistered.
        // The BorrowedFd is only used for the duration of this call.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };

        // Add to kqueue via the polling crate
        self.poller.add(&borrowed_fd, event)?;

        // Track the registration for modify/deregister
        regs.insert(token, RegistrationInfo { raw_fd, interest });

        Ok(())
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        let mut regs = self.registrations.lock();
        let info = regs
            .get_mut(&token)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "token not registered"))?;

        // Create the new polling event
        let event = Self::interest_to_poll_event(token, interest);

        // SAFETY: We stored the raw_fd during registration and trust it's still valid.
        // The caller is responsible for ensuring the fd remains valid until deregistered.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(info.raw_fd) };

        // Modify the kqueue registration
        self.poller.modify(&borrowed_fd, event)?;

        // Update our bookkeeping
        info.interest = interest;

        Ok(())
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        let mut regs = self.registrations.lock();
        let info = regs
            .remove(&token)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "token not registered"))?;

        // SAFETY: We stored the raw_fd during registration and trust it's still valid.
        // The caller is responsible for ensuring the fd remains valid until deregistered.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(info.raw_fd) };

        // Remove from kqueue
        self.poller.delete(&borrowed_fd)?;

        Ok(())
    }

    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
        events.clear();

        // Allocate buffer for polling events (polling 2.x uses Vec<Event>)
        let capacity = events.capacity().max(1);
        let mut poll_events: Vec<PollEvent> = Vec::with_capacity(capacity);

        self.poller.wait(&mut poll_events, timeout)?;

        // Convert polling events to our Event type
        let mut count = 0;
        for poll_event in &poll_events {
            let token = Token(poll_event.key);
            let interest = Self::poll_event_to_interest(poll_event);
            events.push(Event::new(token, interest));
            count += 1;
        }

        Ok(count)
    }

    fn wake(&self) -> io::Result<()> {
        // The polling crate has a built-in notify mechanism
        self.poller.notify()
    }

    fn registration_count(&self) -> usize {
        self.registrations.lock().len()
    }
}

impl std::fmt::Debug for KqueueReactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reg_count = self.registrations.lock().len();
        f.debug_struct("KqueueReactor")
            .field("registration_count", &reg_count)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use nix::unistd::{close, dup};
    use std::io::{self, Read, Write};
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[derive(Debug)]
    struct RawFdSource(RawFd);

    impl AsRawFd for RawFdSource {
        fn as_raw_fd(&self) -> RawFd {
            self.0
        }
    }

    #[test]
    fn create_reactor() {
        init_test("kqueue_create_reactor");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        crate::assert_with_log!(
            reactor.is_empty(),
            "reactor empty",
            true,
            reactor.is_empty()
        );
        crate::assert_with_log!(
            reactor.registration_count() == 0,
            "registration count",
            0usize,
            reactor.registration_count()
        );
        crate::test_complete!("kqueue_create_reactor");
    }

    #[test]
    fn register_and_deregister() {
        init_test("kqueue_register_and_deregister");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(42);
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("register failed");

        crate::assert_with_log!(
            reactor.registration_count() == 1,
            "registration count",
            1usize,
            reactor.registration_count()
        );
        crate::assert_with_log!(
            !reactor.is_empty(),
            "reactor not empty",
            false,
            reactor.is_empty()
        );

        reactor.deregister(token).expect("deregister failed");

        crate::assert_with_log!(
            reactor.registration_count() == 0,
            "registration count",
            0usize,
            reactor.registration_count()
        );
        crate::assert_with_log!(
            reactor.is_empty(),
            "reactor empty",
            true,
            reactor.is_empty()
        );
        crate::test_complete!("kqueue_register_and_deregister");
    }

    #[test]
    fn deregister_not_found() {
        init_test("kqueue_deregister_not_found");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let result = reactor.deregister(Token::new(999));
        crate::assert_with_log!(result.is_err(), "deregister fails", true, result.is_err());
        let kind = result.unwrap_err().kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::NotFound,
            "not found kind",
            io::ErrorKind::NotFound,
            kind
        );
        crate::test_complete!("kqueue_deregister_not_found");
    }

    #[test]
    fn modify_interest() {
        init_test("kqueue_modify_interest");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(1);
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("register failed");

        // Modify updates our bookkeeping
        reactor
            .modify(token, Interest::WRITABLE)
            .expect("modify failed");

        // Verify bookkeeping was updated
        let regs = reactor.registrations.lock();
        let info = regs.get(&token).unwrap();
        crate::assert_with_log!(
            info.interest == Interest::WRITABLE,
            "interest updated",
            Interest::WRITABLE,
            info.interest
        );
        drop(regs);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("kqueue_modify_interest");
    }

    #[test]
    fn modify_not_found() {
        init_test("kqueue_modify_not_found");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let result = reactor.modify(Token::new(999), Interest::READABLE);
        crate::assert_with_log!(result.is_err(), "modify fails", true, result.is_err());
        let kind = result.unwrap_err().kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::NotFound,
            "not found kind",
            io::ErrorKind::NotFound,
            kind
        );
        crate::test_complete!("kqueue_modify_not_found");
    }

    #[test]
    fn wake_unblocks_poll() {
        init_test("kqueue_wake_unblocks_poll");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let mut events = Events::with_capacity(64);

        // Spawn a thread to wake us
        let reactor_ref = &reactor;
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                reactor_ref.wake().expect("wake failed");
            });

            // This should return early due to wake
            let start = std::time::Instant::now();
            let _count = reactor
                .poll(&mut events, Some(Duration::from_secs(5)))
                .expect("poll failed");

            // Should return quickly, not wait 5 seconds
            let elapsed = start.elapsed();
            crate::assert_with_log!(
                elapsed < Duration::from_secs(1),
                "poll woke early",
                true,
                elapsed < Duration::from_secs(1)
            );
        });
        crate::test_complete!("kqueue_wake_unblocks_poll");
    }

    #[test]
    fn poll_timeout() {
        init_test("kqueue_poll_timeout");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let mut events = Events::with_capacity(64);

        let start = std::time::Instant::now();
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(50)))
            .expect("poll failed");

        // Should return after ~50ms with no events
        let elapsed = start.elapsed();
        crate::assert_with_log!(
            elapsed >= Duration::from_millis(40),
            "elapsed lower bound",
            true,
            elapsed >= Duration::from_millis(40)
        );
        crate::assert_with_log!(
            elapsed < Duration::from_millis(200),
            "elapsed upper bound",
            true,
            elapsed < Duration::from_millis(200)
        );
        crate::assert_with_log!(count == 0, "no events", 0usize, count);
        crate::test_complete!("kqueue_poll_timeout");
    }

    #[test]
    fn poll_non_blocking() {
        init_test("kqueue_poll_non_blocking");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let mut events = Events::with_capacity(64);

        let start = std::time::Instant::now();
        let count = reactor
            .poll(&mut events, Some(Duration::ZERO))
            .expect("poll failed");

        // Should return immediately
        let elapsed = start.elapsed();
        crate::assert_with_log!(
            elapsed < Duration::from_millis(10),
            "poll returns quickly",
            true,
            elapsed < Duration::from_millis(10)
        );
        crate::assert_with_log!(count == 0, "no events", 0usize, count);
        crate::test_complete!("kqueue_poll_non_blocking");
    }

    #[test]
    fn poll_writable() {
        init_test("kqueue_poll_writable");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(1);
        reactor
            .register(&sock1, token, Interest::WRITABLE)
            .expect("register failed");

        let mut events = Events::with_capacity(64);
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");

        // Socket should be immediately writable
        crate::assert_with_log!(count >= 1, "has events", true, count >= 1);

        let mut found = false;
        for event in events.iter() {
            if event.token == token && event.is_writable() {
                found = true;
                break;
            }
        }
        crate::assert_with_log!(found, "expected writable event for token", true, found);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("kqueue_poll_writable");
    }

    #[test]
    fn poll_readable() {
        init_test("kqueue_poll_readable");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let (sock1, mut sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(1);
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("register failed");

        // Write some data to make sock1 readable
        sock2.write_all(b"hello").expect("write failed");

        let mut events = Events::with_capacity(64);
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");

        // Socket should be readable now
        crate::assert_with_log!(count >= 1, "has events", true, count >= 1);

        let mut found = false;
        for event in events.iter() {
            if event.token == token && event.is_readable() {
                found = true;
                break;
            }
        }
        crate::assert_with_log!(found, "expected readable event for token", true, found);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("kqueue_poll_readable");
    }

    #[test]
    fn edge_triggered_requires_drain() {
        init_test("kqueue_edge_triggered_requires_drain");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let (mut read_sock, mut write_sock) =
            UnixStream::pair().expect("failed to create unix stream pair");
        read_sock
            .set_nonblocking(true)
            .expect("failed to set nonblocking");

        let token = Token::new(7);
        reactor
            .register(&read_sock, token, Interest::READABLE)
            .expect("register failed");

        write_sock.write_all(b"hello").expect("write failed");

        let mut events = Events::with_capacity(64);
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");
        crate::assert_with_log!(count >= 1, "has events", true, count >= 1);

        let mut buf = [0_u8; 1];
        let read_count = read_sock.read(&mut buf).expect("read failed");
        crate::assert_with_log!(read_count == 1, "read one byte", 1usize, read_count);

        let count = reactor
            .poll(&mut events, Some(Duration::ZERO))
            .expect("poll failed");
        crate::assert_with_log!(count == 0, "no new edge before drain", 0usize, count);

        let mut drain_buf = [0_u8; 16];
        loop {
            match read_sock.read(&mut drain_buf) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => panic!("drain failed: {err}"),
            }
        }

        write_sock.write_all(b"world").expect("write failed");
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");
        crate::assert_with_log!(count >= 1, "edge after new data", true, count >= 1);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("kqueue_edge_triggered_requires_drain");
    }

    #[test]
    fn duplicate_register_fails() {
        init_test("kqueue_duplicate_register_fails");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(1);
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("first register should succeed");

        // Second registration with same token should fail
        let result = reactor.register(&sock1, token, Interest::WRITABLE);
        crate::assert_with_log!(result.is_err(), "duplicate fails", true, result.is_err());
        let kind = result.unwrap_err().kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::AlreadyExists,
            "already exists kind",
            io::ErrorKind::AlreadyExists,
            kind
        );

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("kqueue_duplicate_register_fails");
    }

    #[test]
    fn register_invalid_fd_fails() {
        init_test("kqueue_register_invalid_fd_fails");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let dup_fd = dup(sock1.as_raw_fd()).expect("dup failed");
        close(dup_fd).expect("close failed");

        let invalid = RawFdSource(dup_fd);
        let result = reactor.register(&invalid, Token::new(99), Interest::READABLE);
        crate::assert_with_log!(
            result.is_err(),
            "invalid fd register",
            true,
            result.is_err()
        );
        crate::test_complete!("kqueue_register_invalid_fd_fails");
    }

    #[test]
    fn deregister_closed_fd_returns_error() {
        init_test("kqueue_deregister_closed_fd_returns_error");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(77);
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("register failed");

        drop(sock1);
        let result = reactor.deregister(token);
        crate::assert_with_log!(result.is_err(), "closed fd error", true, result.is_err());
        crate::test_complete!("kqueue_deregister_closed_fd_returns_error");
    }

    #[test]
    fn multiple_registrations() {
        init_test("kqueue_multiple_registrations");
        let reactor = KqueueReactor::new().expect("failed to create reactor");

        let (sock1, _) = UnixStream::pair().expect("failed to create unix stream pair");
        let (sock2, _) = UnixStream::pair().expect("failed to create unix stream pair");
        let (sock3, _) = UnixStream::pair().expect("failed to create unix stream pair");

        reactor
            .register(&sock1, Token::new(1), Interest::READABLE)
            .expect("register 1 failed");
        reactor
            .register(&sock2, Token::new(2), Interest::WRITABLE)
            .expect("register 2 failed");
        reactor
            .register(&sock3, Token::new(3), Interest::both())
            .expect("register 3 failed");

        let count = reactor.registration_count();
        crate::assert_with_log!(count == 3, "registration count", 3usize, count);

        reactor
            .deregister(Token::new(2))
            .expect("deregister failed");
        let count = reactor.registration_count();
        crate::assert_with_log!(count == 2, "after deregister", 2usize, count);

        reactor
            .deregister(Token::new(1))
            .expect("deregister failed");
        reactor
            .deregister(Token::new(3))
            .expect("deregister failed");
        let count = reactor.registration_count();
        crate::assert_with_log!(count == 0, "after deregister all", 0usize, count);
        crate::test_complete!("kqueue_multiple_registrations");
    }

    #[test]
    fn interest_to_poll_event_mapping() {
        init_test("kqueue_interest_to_poll_event_mapping");
        // Test readable
        let event = KqueueReactor::interest_to_poll_event(Token::new(1), Interest::READABLE);
        crate::assert_with_log!(event.readable, "readable set", true, event.readable);
        crate::assert_with_log!(!event.writable, "writable unset", false, event.writable);

        // Test writable
        let event = KqueueReactor::interest_to_poll_event(Token::new(2), Interest::WRITABLE);
        crate::assert_with_log!(!event.readable, "readable unset", false, event.readable);
        crate::assert_with_log!(event.writable, "writable set", true, event.writable);

        // Test both
        let event = KqueueReactor::interest_to_poll_event(Token::new(3), Interest::both());
        crate::assert_with_log!(event.readable, "readable set", true, event.readable);
        crate::assert_with_log!(event.writable, "writable set", true, event.writable);

        // Test none
        let event = KqueueReactor::interest_to_poll_event(Token::new(4), Interest::NONE);
        crate::assert_with_log!(!event.readable, "readable unset", false, event.readable);
        crate::assert_with_log!(!event.writable, "writable unset", false, event.writable);
        crate::test_complete!("kqueue_interest_to_poll_event_mapping");
    }

    #[test]
    fn poll_event_to_interest_mapping() {
        init_test("kqueue_poll_event_to_interest_mapping");
        let event = PollEvent::all(1);
        let interest = KqueueReactor::poll_event_to_interest(&event);
        crate::assert_with_log!(
            interest.is_readable(),
            "all readable",
            true,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_writable(),
            "all writable",
            true,
            interest.is_writable()
        );

        let event = PollEvent::readable(2);
        let interest = KqueueReactor::poll_event_to_interest(&event);
        crate::assert_with_log!(
            interest.is_readable(),
            "readable set",
            true,
            interest.is_readable()
        );
        crate::assert_with_log!(
            !interest.is_writable(),
            "writable unset",
            false,
            interest.is_writable()
        );

        let event = PollEvent::writable(3);
        let interest = KqueueReactor::poll_event_to_interest(&event);
        crate::assert_with_log!(
            !interest.is_readable(),
            "readable unset",
            false,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_writable(),
            "writable set",
            true,
            interest.is_writable()
        );
        crate::test_complete!("kqueue_poll_event_to_interest_mapping");
    }

    #[test]
    fn debug_impl() {
        init_test("kqueue_debug_impl");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let debug_text = format!("{:?}", reactor);
        crate::assert_with_log!(
            debug_text.contains("KqueueReactor"),
            "debug contains type",
            true,
            debug_text.contains("KqueueReactor")
        );
        crate::assert_with_log!(
            debug_text.contains("registration_count"),
            "debug contains registration_count",
            true,
            debug_text.contains("registration_count")
        );
        crate::test_complete!("kqueue_debug_impl");
    }
}
