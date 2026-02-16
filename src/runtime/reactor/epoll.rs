//! Linux epoll-based reactor implementation.
//!
//! This module provides [`EpollReactor`], a reactor implementation that uses
//! Linux epoll for efficient I/O event notification with edge-triggered mode.
//!
//! # Safety
//!
//! This module uses `unsafe` code to interface with the `polling` crate's
//! low-level epoll operations. The unsafe operations are:
//!
//! - `Poller::add()`: Registers a file descriptor with epoll
//! - `Poller::modify()`: Modifies interest flags for a registered fd
//! - `Poller::delete()`: Removes a file descriptor from epoll
//!
//! These are unsafe because the compiler cannot verify that file descriptors
//! remain valid for the duration of their registration. The `EpollReactor`
//! maintains this invariant through careful bookkeeping and expects callers
//! to properly manage source lifetimes.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       EpollReactor                               │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
//! │  │   Poller    │  │  notify()   │  │    registration map     │  │
//! │  │  (polling)  │  │  (builtin)  │  │   HashMap<Token, info>  │  │
//! │  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Thread Safety
//!
//! `EpollReactor` is `Send + Sync` and can be shared across threads via `Arc`.
//! Internal state is protected by `Mutex` for registration/deregistration,
//! while `poll()` and `wake()` are lock-free for performance.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::runtime::reactor::{EpollReactor, Reactor, Interest, Events};
//! use std::net::TcpListener;
//!
//! let reactor = EpollReactor::new()?;
//! let listener = TcpListener::bind("127.0.0.1:0")?;
//!
//! // Register the listener with epoll (edge-triggered mode)
//! reactor.register(&listener, Token::new(1), Interest::READABLE)?;
//!
//! // Poll for events
//! let mut events = Events::with_capacity(64);
//! let count = reactor.poll(&mut events, Some(Duration::from_secs(1)))?;
//! ```

// Allow unsafe code for epoll FFI operations via the polling crate.
// The unsafe operations (add, modify, delete) are necessary because the
// compiler cannot verify file descriptor validity at compile time.
#![allow(unsafe_code)]

use super::{Event, Events, Interest, Reactor, Source, Token};
use libc::{fcntl, F_GETFD};
use parking_lot::Mutex;
use polling::{Event as PollEvent, Events as PollEvents, Poller};
use std::collections::HashMap;
use std::io;
use std::num::NonZeroUsize;
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

#[derive(Debug)]
struct ReactorState {
    tokens: HashMap<Token, RegistrationInfo>,
    fds: HashMap<i32, Token>,
}

impl ReactorState {
    fn new() -> Self {
        Self {
            tokens: HashMap::new(),
            fds: HashMap::new(),
        }
    }
}

/// Linux epoll-based reactor with edge-triggered mode.
///
/// This reactor uses the `polling` crate to interface with Linux epoll,
/// providing efficient I/O event notification for async operations.
///
/// # Features
///
/// - `register()`: Adds fd to epoll with EPOLLET (edge-triggered)
/// - `modify()`: Updates interest flags for a registered fd
/// - `deregister()`: Removes fd from epoll
/// - `poll()`: Waits for and collects ready events
/// - `wake()`: Interrupts a blocking poll from another thread
///
/// # Edge-Triggered Mode
///
/// This reactor uses edge-triggered mode (`EPOLLET`) for efficiency.
/// Events fire when state *changes*, not while the condition persists.
/// Applications must read/write until `EAGAIN` before the next event.
pub struct EpollReactor {
    /// The polling instance (wraps epoll on Linux).
    poller: Poller,
    /// Reactor state (tokens and fds maps) protected by a mutex.
    state: Mutex<ReactorState>,
    /// Reusable polling event buffer to avoid per-poll allocations.
    poll_events: Mutex<PollEvents>,
}

const DEFAULT_POLL_EVENTS_CAPACITY: usize = 64;

impl EpollReactor {
    /// Creates a new epoll-based reactor.
    ///
    /// This initializes a `Poller` instance which creates an epoll fd internally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `epoll_create1()` fails (e.g., out of file descriptors)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let reactor = EpollReactor::new()?;
    /// assert!(reactor.is_empty());
    /// ```
    pub fn new() -> io::Result<Self> {
        let poller = Poller::new()?;

        Ok(Self {
            poller,
            state: Mutex::new(ReactorState::new()),
            poll_events: Mutex::new(PollEvents::with_capacity(
                NonZeroUsize::new(DEFAULT_POLL_EVENTS_CAPACITY).expect("non-zero capacity"),
            )),
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

impl Reactor for EpollReactor {
    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        let raw_fd = source.as_raw_fd();

        // Check for duplicate registration first
        let mut state = self.state.lock();
        if state.tokens.contains_key(&token) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "token already registered",
            ));
        }

        if state.fds.contains_key(&raw_fd) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "fd already registered",
            ));
        }

        // Ensure the file descriptor is still valid before registering.
        // This catches cases where the fd was closed but the value reused.
        if unsafe { fcntl(raw_fd, F_GETFD) } == -1 {
            return Err(io::Error::last_os_error());
        }

        // Create the polling event with the token as the key
        let event = Self::interest_to_poll_event(token, interest);

        // SAFETY: We trust that the caller maintains the invariant that the
        // source (and its file descriptor) remains valid until deregistered.
        // The BorrowedFd is only used for the duration of this call.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };

        // SAFETY: `borrowed_fd` remains valid for the duration of registration and
        // is explicitly removed in `deregister`.
        unsafe {
            self.poller.add(&borrowed_fd, event)?;
        }

        // Track the registration for modify/deregister
        state
            .tokens
            .insert(token, RegistrationInfo { raw_fd, interest });
        state.fds.insert(raw_fd, token);
        drop(state);

        Ok(())
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        let mut state = self.state.lock();
        let raw_fd = state
            .tokens
            .get(&token)
            .map(|info| info.raw_fd)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "token not registered"))?;

        // Create the new polling event
        let event = Self::interest_to_poll_event(token, interest);

        // SAFETY: We stored the raw_fd during registration and trust it's still valid.
        // The caller is responsible for ensuring the fd remains valid until deregistered.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };

        // Modify the epoll registration. If the kernel reports stale registration state,
        // clean stale bookkeeping so fd-number reuse does not get blocked indefinitely.
        let result = match self.poller.modify(borrowed_fd, event) {
            Ok(()) => {
                if let Some(info) = state.tokens.get_mut(&token) {
                    info.interest = interest;
                }
                Ok(())
            }
            Err(err) => match err.raw_os_error() {
                Some(libc::ENOENT) => {
                    if let Some(info) = state.tokens.remove(&token) {
                        state.fds.remove(&info.raw_fd);
                    }
                    Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "token not registered",
                    ))
                }
                Some(libc::EBADF) => {
                    let fd_still_valid = unsafe { fcntl(raw_fd, F_GETFD) } != -1;
                    if fd_still_valid {
                        Err(err)
                    } else {
                        if let Some(info) = state.tokens.remove(&token) {
                            state.fds.remove(&info.raw_fd);
                        }
                        Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "token not registered",
                        ))
                    }
                }
                _ => Err(err),
            },
        };
        drop(state);
        result
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        let mut state = self.state.lock();
        let info = state
            .tokens
            .get(&token)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "token not registered"))?;

        // SAFETY: We stored the raw_fd during registration and trust it's still valid.
        // The caller is responsible for ensuring the fd remains valid until deregistered.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(info.raw_fd) };
        // Determine whether the target fd itself is valid so EBADF can be
        // interpreted correctly (target closed vs reactor poller invalid).
        let fd_still_valid = unsafe { fcntl(info.raw_fd, F_GETFD) } != -1;

        // Remove from epoll. If the fd was already closed or removed by the kernel,
        // treat it as already deregistered from reactor bookkeeping perspective.
        match self.poller.delete(borrowed_fd) {
            Ok(()) => {
                if let Some(info) = state.tokens.remove(&token) {
                    state.fds.remove(&info.raw_fd);
                }
                drop(state);
                Ok(())
            }
            Err(err) => match err.raw_os_error() {
                Some(libc::ENOENT) => {
                    if let Some(info) = state.tokens.remove(&token) {
                        state.fds.remove(&info.raw_fd);
                    }
                    drop(state);
                    Ok(())
                }
                // Treat EBADF as benign only when the target fd itself is closed.
                Some(libc::EBADF) if !fd_still_valid => {
                    if let Some(info) = state.tokens.remove(&token) {
                        state.fds.remove(&info.raw_fd);
                    }
                    drop(state);
                    Ok(())
                }
                _ => {
                    drop(state);
                    Err(err)
                }
            },
        }
    }

    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
        events.clear();

        let requested_capacity =
            NonZeroUsize::new(events.capacity().max(1)).expect("capacity >= 1");
        let mut poll_events = self.poll_events.lock();
        if poll_events.capacity().get() < requested_capacity.get() {
            *poll_events = PollEvents::with_capacity(requested_capacity);
        } else {
            poll_events.clear();
        }

        self.poller.wait(&mut poll_events, timeout)?;

        // Convert polling events to our Event type.
        // `Events` may drop entries when capacity is reached, so the return
        // value must reflect events actually stored, not raw epoll events seen.
        for poll_event in poll_events.iter() {
            let token = Token(poll_event.key);
            let interest = Self::poll_event_to_interest(&poll_event);
            events.push(Event::new(token, interest));
        }

        drop(poll_events);
        Ok(events.len())
    }

    fn wake(&self) -> io::Result<()> {
        // The polling crate has a built-in notify mechanism
        self.poller.notify()
    }

    fn registration_count(&self) -> usize {
        self.state.lock().tokens.len()
    }
}

impl std::fmt::Debug for EpollReactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reg_count = self.state.lock().tokens.len();
        f.debug_struct("EpollReactor")
            .field("registration_count", &reg_count)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::io::{self, Read, Write};
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

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
        init_test("create_reactor");
        let reactor = EpollReactor::new().expect("failed to create reactor");
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
        crate::test_complete!("create_reactor");
    }

    #[test]
    fn register_and_deregister() {
        init_test("register_and_deregister");
        let reactor = EpollReactor::new().expect("failed to create reactor");
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
        crate::test_complete!("register_and_deregister");
    }

    #[test]
    fn deregister_not_found() {
        init_test("deregister_not_found");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let result = reactor.deregister(Token::new(999));
        crate::assert_with_log!(result.is_err(), "deregister fails", true, result.is_err());
        let kind = result.unwrap_err().kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::NotFound,
            "not found kind",
            io::ErrorKind::NotFound,
            kind
        );
        crate::test_complete!("deregister_not_found");
    }

    #[test]
    fn modify_interest() {
        init_test("modify_interest");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(1);
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("register failed");

        // Modify updates our bookkeeping (but not the actual epoll due to API limitations)
        reactor
            .modify(token, Interest::WRITABLE)
            .expect("modify failed");

        // Verify bookkeeping was updated
        let state = reactor.state.lock();
        let info = state.tokens.get(&token).unwrap();
        crate::assert_with_log!(
            info.interest == Interest::WRITABLE,
            "interest updated",
            Interest::WRITABLE,
            info.interest
        );
        drop(state);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("modify_interest");
    }

    #[test]
    fn modify_not_found() {
        init_test("modify_not_found");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let result = reactor.modify(Token::new(999), Interest::READABLE);
        crate::assert_with_log!(result.is_err(), "modify fails", true, result.is_err());
        let kind = result.unwrap_err().kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::NotFound,
            "not found kind",
            io::ErrorKind::NotFound,
            kind
        );
        crate::test_complete!("modify_not_found");
    }

    #[test]
    fn wake_unblocks_poll() {
        init_test("wake_unblocks_poll");
        let reactor = EpollReactor::new().expect("failed to create reactor");
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
        crate::test_complete!("wake_unblocks_poll");
    }

    #[test]
    fn poll_timeout() {
        init_test("poll_timeout");
        let reactor = EpollReactor::new().expect("failed to create reactor");
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
        crate::test_complete!("poll_timeout");
    }

    #[test]
    fn poll_non_blocking() {
        init_test("poll_non_blocking");
        let reactor = EpollReactor::new().expect("failed to create reactor");
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
        crate::test_complete!("poll_non_blocking");
    }

    #[test]
    fn poll_writable() {
        init_test("poll_writable");
        let reactor = EpollReactor::new().expect("failed to create reactor");
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
        for event in &events {
            if event.token == token && event.is_writable() {
                found = true;
                break;
            }
        }
        crate::assert_with_log!(found, "expected writable event for token", true, found);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("poll_writable");
    }

    #[test]
    fn poll_readable() {
        init_test("poll_readable");
        let reactor = EpollReactor::new().expect("failed to create reactor");
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
        for event in &events {
            if event.token == token && event.is_readable() {
                found = true;
                break;
            }
        }
        crate::assert_with_log!(found, "expected readable event for token", true, found);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("poll_readable");
    }

    #[test]
    fn poll_zero_capacity_reports_zero_events_stored() {
        init_test("poll_zero_capacity_reports_zero_events_stored");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (sock1, mut sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(11);
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("register failed");

        sock2.write_all(b"x").expect("write failed");

        let mut events = Events::with_capacity(0);
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");

        crate::assert_with_log!(events.is_empty(), "events empty", true, events.is_empty());
        crate::assert_with_log!(count == 0, "count is stored events", 0usize, count);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("poll_zero_capacity_reports_zero_events_stored");
    }

    #[test]
    fn edge_triggered_requires_drain() {
        init_test("edge_triggered_requires_drain");
        let reactor = EpollReactor::new().expect("failed to create reactor");
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
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => panic!("drain failed: {err}"),
            }
        }

        // Re-arm the registration. The polling crate uses an internal oneshot-style
        // mechanism, so after receiving an event, we must call modify to re-arm
        // before new events will be delivered.
        reactor
            .modify(token, Interest::READABLE)
            .expect("modify for rearm failed");

        write_sock.write_all(b"world").expect("write failed");
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut found = false;
        while Instant::now() < deadline {
            let count = reactor
                .poll(&mut events, Some(Duration::from_millis(100)))
                .expect("poll failed");
            if count == 0 {
                continue;
            }
            for event in &events {
                if event.token == token && event.is_readable() {
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        crate::assert_with_log!(found, "edge after new data", true, found);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("edge_triggered_requires_drain");
    }

    #[test]
    fn duplicate_register_fails() {
        init_test("duplicate_register_fails");
        let reactor = EpollReactor::new().expect("failed to create reactor");
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
        crate::test_complete!("duplicate_register_fails");
    }

    #[test]
    fn register_invalid_fd_fails() {
        init_test("register_invalid_fd_fails");
        let reactor = EpollReactor::new().expect("failed to create reactor");

        let invalid = RawFdSource(-1);
        let result = reactor.register(&invalid, Token::new(99), Interest::READABLE);
        crate::assert_with_log!(
            result.is_err(),
            "invalid fd register",
            true,
            result.is_err()
        );
        crate::test_complete!("register_invalid_fd_fails");
    }

    #[test]
    fn deregister_closed_fd_is_best_effort() {
        init_test("deregister_closed_fd_is_best_effort");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(77);
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("register failed");

        drop(sock1);
        let result = reactor.deregister(token);
        crate::assert_with_log!(
            result.is_ok(),
            "closed fd cleanup succeeds",
            true,
            result.is_ok()
        );
        crate::assert_with_log!(
            reactor.registration_count() == 0,
            "registration removed from bookkeeping",
            0usize,
            reactor.registration_count()
        );
        crate::test_complete!("deregister_closed_fd_is_best_effort");
    }

    #[test]
    fn modify_closed_fd_cleans_stale_bookkeeping_for_fd_reuse() {
        init_test("modify_closed_fd_cleans_stale_bookkeeping_for_fd_reuse");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (old_sock, _old_peer) = UnixStream::pair().expect("failed to create unix stream pair");
        let stale_fd = old_sock.as_raw_fd();
        let stale_token = Token::new(89);
        reactor
            .register(&old_sock, stale_token, Interest::READABLE)
            .expect("stale registration failed");
        drop(old_sock);

        let modify_result = reactor.modify(stale_token, Interest::WRITABLE);
        crate::assert_with_log!(
            modify_result.is_err(),
            "modify on closed fd fails",
            true,
            modify_result.is_err()
        );
        let modify_kind = modify_result.unwrap_err().kind();
        crate::assert_with_log!(
            modify_kind == io::ErrorKind::NotFound,
            "closed fd modify maps to not found",
            io::ErrorKind::NotFound,
            modify_kind
        );
        crate::assert_with_log!(
            reactor.registration_count() == 0,
            "closed fd modify removes stale bookkeeping",
            0usize,
            reactor.registration_count()
        );

        let (new_sock, mut write_peer) =
            UnixStream::pair().expect("failed to create second unix stream pair");
        let new_sock_fd = new_sock.as_raw_fd();
        // Force fd-number reuse so stale bookkeeping and new source collide on raw fd.
        let dup_result = unsafe { libc::dup2(new_sock_fd, stale_fd) };
        crate::assert_with_log!(
            dup_result == stale_fd,
            "dup2 reused stale fd slot",
            stale_fd,
            dup_result
        );

        let reused_source = RawFdSource(stale_fd);
        let new_token = Token::new(90);
        reactor
            .register(&reused_source, new_token, Interest::READABLE)
            .expect("register reused fd after stale cleanup failed");

        write_peer.write_all(b"x").expect("write failed");
        let mut events = Events::with_capacity(8);
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");
        crate::assert_with_log!(count >= 1, "has events", true, count >= 1);
        let mut found = false;
        for event in &events {
            if event.token == new_token && event.is_readable() {
                found = true;
                break;
            }
        }
        crate::assert_with_log!(found, "readable event for reused fd token", true, found);

        reactor
            .deregister(new_token)
            .expect("deregister reused fd token failed");
        // SAFETY: If dup2 created a distinct extra descriptor at `stale_fd`,
        // close it to avoid leaks. When source==target, `new_sock` already owns it.
        if stale_fd != new_sock_fd {
            let close_result = unsafe { libc::close(stale_fd) };
            crate::assert_with_log!(close_result == 0, "close duplicated fd", 0, close_result);
        }
        crate::test_complete!("modify_closed_fd_cleans_stale_bookkeeping_for_fd_reuse");
    }

    #[test]
    fn reused_fd_cannot_register_under_new_token_until_stale_token_removed() {
        init_test("reused_fd_cannot_register_under_new_token_until_stale_token_removed");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (old_sock, _old_peer) = UnixStream::pair().expect("failed to create unix stream pair");
        let stale_fd = old_sock.as_raw_fd();
        let stale_token = Token::new(87);
        reactor
            .register(&old_sock, stale_token, Interest::READABLE)
            .expect("stale registration failed");
        drop(old_sock);

        let (new_sock, mut write_peer) =
            UnixStream::pair().expect("failed to create second unix stream pair");
        let new_sock_fd = new_sock.as_raw_fd();
        // Force fd-number reuse so stale bookkeeping and new source collide on raw fd.
        let dup_result = unsafe { libc::dup2(new_sock_fd, stale_fd) };
        crate::assert_with_log!(
            dup_result == stale_fd,
            "dup2 reused stale fd slot",
            stale_fd,
            dup_result
        );

        let reused_source = RawFdSource(stale_fd);
        let new_token = Token::new(88);

        let duplicate_result = reactor.register(&reused_source, new_token, Interest::READABLE);
        crate::assert_with_log!(
            duplicate_result.is_err(),
            "duplicate fd registration rejected while stale token exists",
            true,
            duplicate_result.is_err()
        );
        let duplicate_kind = duplicate_result.unwrap_err().kind();
        crate::assert_with_log!(
            duplicate_kind == io::ErrorKind::AlreadyExists,
            "duplicate fd reports already exists",
            io::ErrorKind::AlreadyExists,
            duplicate_kind
        );

        reactor
            .deregister(stale_token)
            .expect("stale token deregister should succeed");
        reactor
            .register(&reused_source, new_token, Interest::READABLE)
            .expect("register reused fd after stale cleanup failed");

        write_peer.write_all(b"x").expect("write failed");
        let mut events = Events::with_capacity(8);
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");
        crate::assert_with_log!(count >= 1, "has events", true, count >= 1);
        let mut found = false;
        for event in &events {
            if event.token == new_token && event.is_readable() {
                found = true;
                break;
            }
        }
        crate::assert_with_log!(found, "readable event for reused fd token", true, found);

        reactor
            .deregister(new_token)
            .expect("deregister reused fd token failed");
        // SAFETY: If dup2 created a distinct extra descriptor at `stale_fd`,
        // close it to avoid leaks. When source==target, `new_sock` already owns it.
        if stale_fd != new_sock_fd {
            let close_result = unsafe { libc::close(stale_fd) };
            crate::assert_with_log!(close_result == 0, "close duplicated fd", 0, close_result);
        }
        crate::test_complete!(
            "reused_fd_cannot_register_under_new_token_until_stale_token_removed"
        );
    }

    #[test]
    fn multiple_registrations() {
        init_test("multiple_registrations");
        let reactor = EpollReactor::new().expect("failed to create reactor");

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
        crate::test_complete!("multiple_registrations");
    }

    #[test]
    fn interest_to_poll_event_mapping() {
        init_test("interest_to_poll_event_mapping");
        // Test readable
        let event = EpollReactor::interest_to_poll_event(Token::new(1), Interest::READABLE);
        crate::assert_with_log!(event.readable, "readable set", true, event.readable);
        crate::assert_with_log!(!event.writable, "writable unset", false, event.writable);

        // Test writable
        let event = EpollReactor::interest_to_poll_event(Token::new(2), Interest::WRITABLE);
        crate::assert_with_log!(!event.readable, "readable unset", false, event.readable);
        crate::assert_with_log!(event.writable, "writable set", true, event.writable);

        // Test both
        let event = EpollReactor::interest_to_poll_event(Token::new(3), Interest::both());
        crate::assert_with_log!(event.readable, "readable set", true, event.readable);
        crate::assert_with_log!(event.writable, "writable set", true, event.writable);

        // Test none
        let event = EpollReactor::interest_to_poll_event(Token::new(4), Interest::NONE);
        crate::assert_with_log!(!event.readable, "readable unset", false, event.readable);
        crate::assert_with_log!(!event.writable, "writable unset", false, event.writable);
        crate::test_complete!("interest_to_poll_event_mapping");
    }

    #[test]
    fn poll_event_to_interest_mapping() {
        init_test("poll_event_to_interest_mapping");
        let event = PollEvent::all(1);
        let interest = EpollReactor::poll_event_to_interest(&event);
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
        let interest = EpollReactor::poll_event_to_interest(&event);
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
        let interest = EpollReactor::poll_event_to_interest(&event);
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
        crate::test_complete!("poll_event_to_interest_mapping");
    }

    #[test]
    fn debug_impl() {
        init_test("debug_impl");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let debug_text = format!("{reactor:?}");
        crate::assert_with_log!(
            debug_text.contains("EpollReactor"),
            "debug contains type",
            true,
            debug_text.contains("EpollReactor")
        );
        crate::assert_with_log!(
            debug_text.contains("registration_count"),
            "debug contains registration_count",
            true,
            debug_text.contains("registration_count")
        );
        crate::test_complete!("debug_impl");
    }
}
