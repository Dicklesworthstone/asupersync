//! Linux epoll-based reactor implementation.
//!
//! This module provides [`EpollReactor`], a reactor implementation that uses
//! Linux epoll for efficient I/O event notification on Linux-family targets.
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
//! Internal state is protected by `Mutex` for registration/deregistration.
//! `wake()` is lock-free; `poll()` acquires a short-lived mutex on the
//! reused event buffer for the duration of the kernel wait. Concurrent
//! `poll()` callers are expected to be serialized externally (the runtime
//! `IoDriver` uses an `is_polling` CAS to enforce this leader/follower
//! discipline).
//!
//! # Trigger Modes
//!
//! Registrations default to oneshot delivery, matching the portable reactor
//! contract used by the runtime's Unix backends. Callers can opt into
//! edge-triggered behavior with [`Interest::EDGE_TRIGGERED`].
//!
//! # Example
//!
//! ```ignore
//! use asupersync::runtime::reactor::{EpollReactor, Reactor, Interest, Events};
//! use std::net::TcpListener;
//!
//! let reactor = EpollReactor::new()?;
//! let mut listener = TcpListener::bind("127.0.0.1:0")?;
//!
//! // Register the listener with epoll
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
use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use libc::{F_GETFD, fcntl};
use parking_lot::Mutex;
use polling::{Event as PollEvent, Events as PollEvents, PollMode, Poller};
use std::collections::HashSet;
use std::io;
use std::num::NonZeroUsize;
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    /// Tokens whose bookkeeping was forcibly cleaned up because the kernel
    /// reported the watched descriptor as invalid (e.g. the fd was closed
    /// before re-arm). A subsequent `deregister` on such a token must
    /// succeed idempotently rather than being indistinguishable from a
    /// token that was never registered. The set is cleared lazily by
    /// `deregister` and bounded by the number of concurrently orphaned
    /// tokens, so it does not grow without bound.
    orphaned: HashSet<Token>,
}

impl ReactorState {
    fn new() -> Self {
        Self {
            tokens: HashMap::with_capacity(64),
            fds: HashMap::with_capacity(64),
            orphaned: HashSet::new(),
        }
    }
}

/// Linux epoll-based reactor.
///
/// This reactor uses the `polling` crate to interface with Linux epoll,
/// providing efficient I/O event notification for async operations.
///
/// # Features
///
/// - `register()`: Adds fd to epoll with caller-selected trigger mode
/// - `modify()`: Updates interest flags for a registered fd
/// - `deregister()`: Removes fd from epoll
/// - `poll()`: Waits for and collects ready events
/// - `wake()`: Interrupts a blocking poll from another thread
///
/// Registrations default to oneshot delivery to match the portable reactor
/// abstraction. Callers can request edge-triggered semantics via
/// [`Interest::EDGE_TRIGGERED`].
///
/// # Platform Support
///
/// This reactor is only available on Linux-family targets that expose epoll.
pub struct EpollReactor {
    /// The polling instance (wraps epoll on Linux).
    poller: Poller,
    /// Reactor state (tokens and fds maps) protected by a mutex.
    state: Mutex<ReactorState>,
    /// Reusable polling event buffer to avoid per-poll allocations.
    poll_events: Mutex<PollEvents>,
    /// Fast registration count (avoids mutex for read-only queries).
    registration_count: AtomicUsize,
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
            registration_count: AtomicUsize::new(0),
        })
    }

    #[inline]
    fn validate_supported_interest(interest: Interest) -> io::Result<()> {
        if interest.is_dispatch() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Interest::DISPATCH is not supported by the epoll reactor",
            ));
        }

        Ok(())
    }

    /// Converts our Interest flags to polling crate's event.
    #[inline]
    fn interest_to_poll_event(token: Token, interest: Interest) -> PollEvent {
        let key = token.0;
        let readable = interest.is_readable();
        let writable = interest.is_writable();

        let mut event = match (readable, writable) {
            (true, true) => PollEvent::all(key),
            (true, false) => PollEvent::readable(key),
            (false, true) => PollEvent::writable(key),
            (false, false) => PollEvent::none(key),
        };

        if interest.is_hup() {
            event = event.with_interrupt();
        }
        if interest.is_priority() {
            event = event.with_priority();
        }

        event
    }

    /// Converts our interest mode flags to polling crate poll mode.
    #[inline]
    fn interest_to_poll_mode(interest: Interest) -> PollMode {
        if interest.is_edge_triggered() {
            if interest.is_oneshot() {
                PollMode::EdgeOneshot
            } else {
                PollMode::Edge
            }
        } else {
            // Preserve the portable Unix reactor contract: non-edge
            // registrations fire once and must be re-armed with modify().
            PollMode::Oneshot
        }
    }

    /// Converts polling crate's event to our Interest type.
    ///
    /// The `polling` epoll backend folds `HUP`/`ERR` into both read and write
    /// readiness. Mask the generic readiness booleans with the registration's
    /// requested directions so we do not synthesize readiness the caller never
    /// asked for while still preserving explicit side-band conditions.
    #[inline]
    fn poll_event_to_interest(
        event: &PollEvent,
        registered_interest: Option<Interest>,
    ) -> Interest {
        let mut observed_readiness = Interest::NONE;

        if event.readable {
            observed_readiness = observed_readiness.add(Interest::READABLE);
        }
        if event.writable {
            observed_readiness = observed_readiness.add(Interest::WRITABLE);
        }

        let mut interest = match registered_interest {
            Some(registered) => observed_readiness & registered,
            None => observed_readiness,
        };

        if event.is_interrupt() {
            interest = interest.add(Interest::HUP);
        }
        if event.is_priority()
            && registered_interest.is_none_or(|registered| registered.is_priority())
        {
            interest = interest.add(Interest::PRIORITY);
        }
        if event.is_err() == Some(true) {
            interest = interest.add(Interest::ERROR);
        }

        interest
    }

    #[inline]
    fn translate_poll_event(state: &ReactorState, poll_event: &PollEvent) -> Option<Event> {
        let token = Token(poll_event.key);
        let registered_interest = state.tokens.get(&token).map(|info| info.interest)?;
        let interest = Self::poll_event_to_interest(poll_event, Some(registered_interest));
        (!interest.is_empty()).then_some(Event::new(token, interest))
    }
}

#[inline]
fn should_resize_poll_events(current: usize, target: usize) -> bool {
    current < target || target.checked_mul(4).is_some_and(|t4| current >= t4)
}

impl Reactor for EpollReactor {
    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        Self::validate_supported_interest(interest)?;

        let raw_fd = source.as_raw_fd();

        // `BorrowedFd::borrow_raw(-1)` is a checked precondition violation on
        // recent Rust toolchains and panics in debug builds. Reject the
        // sentinel value here with a well-typed error rather than letting the
        // panic escape. Callers routinely pass the result of `as_raw_fd()`
        // from a source that may not currently hold a descriptor.
        if raw_fd < 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }

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

        // Create the polling event with the token as the key
        let event = Self::interest_to_poll_event(token, interest);
        let mode = Self::interest_to_poll_mode(interest);

        // SAFETY: We trust that the caller maintains the invariant that the
        // source (and its file descriptor) remains valid until deregistered.
        // The BorrowedFd is only used for the duration of this call.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };

        // SAFETY: `borrowed_fd` remains valid for the duration of registration and
        // is explicitly removed in `deregister`.
        //
        // Do not preflight the fd with `fcntl(F_GETFD)` here. A separate validity
        // probe widens the close/reuse race window without making registration
        // safer: the only authoritative answer is whether `epoll_ctl(ADD)` accepts
        // the descriptor at the moment we install the kernel watch.
        unsafe {
            self.poller.add_with_mode(&borrowed_fd, event, mode)?;
        }

        // Track the registration for modify/deregister
        state
            .tokens
            .insert(token, RegistrationInfo { raw_fd, interest });
        state.fds.insert(raw_fd, token);
        // A successful (re-)registration supersedes any orphan record for
        // this token so the next `deregister` reflects the real kernel
        // state instead of being short-circuited by a stale tombstone.
        state.orphaned.remove(&token);
        drop(state);

        // Increment registration count after successful registration
        self.registration_count.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        Self::validate_supported_interest(interest)?;

        let mut state = self.state.lock();
        // Destructure for split borrows so the entry on `tokens` doesn't
        // block access to `fds`/`orphaned` in error-cleanup paths.
        let ReactorState {
            tokens,
            fds,
            orphaned,
        } = &mut *state;

        let entry = match tokens.entry(token) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ));
            }
        };

        let raw_fd = entry.get().raw_fd;

        // Create the new polling event
        let event = Self::interest_to_poll_event(token, interest);
        let mode = Self::interest_to_poll_mode(interest);

        // SAFETY: We stored the raw_fd during registration and trust it's still valid.
        // The caller is responsible for ensuring the fd remains valid until deregistered.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };

        // Modify the epoll registration. If the kernel reports stale registration state,
        // clean stale bookkeeping so fd-number reuse does not get blocked indefinitely.
        // The entry is reused for both the success update and error removal, saving a
        // second HashMap lookup on the hot path.
        match self.poller.modify_with_mode(borrowed_fd, event, mode) {
            Ok(()) => {
                entry.into_mut().interest = interest;
                drop(state);
                Ok(())
            }
            Err(err) => match err.raw_os_error() {
                Some(libc::ENOENT) => {
                    let info = entry.remove();
                    fds.remove(&info.raw_fd);
                    orphaned.insert(token);
                    drop(state);
                    // Decrement count after removing registration
                    self.registration_count.fetch_sub(1, Ordering::Relaxed);
                    Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "token not registered",
                    ))
                }
                Some(libc::EBADF) if unsafe { fcntl(raw_fd, F_GETFD) } == -1 => {
                    // Determine whether the target fd itself is valid so EBADF can be
                    // interpreted correctly (target closed vs reactor poller invalid).
                    // Evaluated AFTER the modify attempt to prevent TOCTOU race.
                    // We must remove it to prevent leaking the token if the fd was concurrently reused.
                    let info = entry.remove();
                    fds.remove(&info.raw_fd);
                    // Record the orphaned token so the caller's follow-up
                    // `deregister` succeeds idempotently. Without this a
                    // conscientious cleanup loop would observe `NotFound`
                    // and surface the failure, even though there is nothing
                    // left to tear down.
                    orphaned.insert(token);
                    drop(state);
                    // Decrement count after removing registration
                    self.registration_count.fetch_sub(1, Ordering::Relaxed);
                    Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "token not registered",
                    ))
                }
                _ => {
                    drop(state);
                    Err(err)
                }
            },
        }
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        let mut state = self.state.lock();
        let info = match state.tokens.get(&token) {
            Some(info) => info,
            None => {
                // If a previous modify/deregister already cleaned this token
                // up because the kernel reported its fd as closed, honor the
                // idempotent-cleanup contract: the caller asked us to tear it
                // down and there is nothing left. Consume the tombstone so
                // the next deregister of a genuinely-unknown token still
                // surfaces NotFound.
                let was_orphaned = state.orphaned.remove(&token);
                drop(state);
                return if was_orphaned {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "token not registered",
                    ))
                };
            }
        };

        // SAFETY: We stored the raw_fd during registration and trust it's still valid.
        // The caller is responsible for ensuring the fd remains valid until deregistered.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(info.raw_fd) };
        // Remove from epoll. Only drop bookkeeping once the source is
        // definitely gone from the kernel or the target fd itself is already
        // closed. Keeping the entry on hard failures preserves accurate retry
        // semantics for Registration::deregister().
        match self.poller.delete(borrowed_fd) {
            Ok(()) => {
                if let Some(info) = state.tokens.remove(&token) {
                    state.fds.remove(&info.raw_fd);
                    drop(state);
                    // Decrement count only if we actually removed a registration
                    self.registration_count.fetch_sub(1, Ordering::Relaxed);
                } else {
                    drop(state);
                }
                Ok(())
            }
            Err(err) => match err.raw_os_error() {
                Some(libc::ENOENT) => {
                    if let Some(info) = state.tokens.remove(&token) {
                        state.fds.remove(&info.raw_fd);
                        drop(state);
                        // Decrement count only if we actually removed a registration
                        self.registration_count.fetch_sub(1, Ordering::Relaxed);
                    } else {
                        drop(state);
                    }
                    Ok(())
                }
                Some(libc::EBADF) if unsafe { fcntl(info.raw_fd, F_GETFD) } == -1 => {
                    // Determine whether the target fd itself is valid so EBADF can be
                    // interpreted correctly (target closed vs reactor poller invalid).
                    // Evaluated AFTER the delete attempt to prevent TOCTOU race.
                    if let Some(info) = state.tokens.remove(&token) {
                        state.fds.remove(&info.raw_fd);
                        drop(state);
                        // Decrement count only if we actually removed a registration
                        self.registration_count.fetch_sub(1, Ordering::Relaxed);
                    } else {
                        drop(state);
                    }
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

        let current = poll_events.capacity().get();
        let target = requested_capacity.get();

        // Resize if too small OR significantly too large (hysteresis to prevent thrashing).
        // If we strictly enforced equality, allocators rounding up (e.g. 60 -> 64)
        // would cause reallocation on every poll.
        if should_resize_poll_events(current, target) {
            *poll_events = PollEvents::with_capacity(requested_capacity);
        } else {
            poll_events.clear();
        }

        self.poller.wait(&mut poll_events, timeout)?;

        let state = self.state.lock();

        // Convert polling events to our Event type. Preserve explicit side-band
        // conditions (error/hangup/priority) while masking generic readiness
        // against the registration's requested directions.
        for poll_event in poll_events.iter() {
            if let Some(event) = Self::translate_poll_event(&state, &poll_event) {
                events.push(event);
            }
        }

        drop(state);
        drop(poll_events);
        Ok(events.len())
    }

    fn wake(&self) -> io::Result<()> {
        // The polling crate has a built-in notify mechanism
        self.poller.notify()
    }

    fn registration_count(&self) -> usize {
        self.registration_count.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for EpollReactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reg_count = self.registration_count.load(Ordering::Relaxed);
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
    use std::sync::atomic::{AtomicI32, Ordering};
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

    #[derive(Debug)]
    struct FdRestoreGuard {
        target_fd: RawFd,
        saved_fd: Option<RawFd>,
    }

    impl FdRestoreGuard {
        fn new(target_fd: RawFd, saved_fd: RawFd) -> Self {
            Self {
                target_fd,
                saved_fd: Some(saved_fd),
            }
        }

        fn restore(&mut self) -> (i32, i32) {
            let saved_fd = self
                .saved_fd
                .take()
                .expect("restore guard must hold a saved fd");
            let restore_result = unsafe { libc::dup2(saved_fd, self.target_fd) };
            let close_saved = unsafe { libc::close(saved_fd) };
            (restore_result, close_saved)
        }
    }

    impl Drop for FdRestoreGuard {
        fn drop(&mut self) {
            let Some(saved_fd) = self.saved_fd.take() else {
                return;
            };

            let _ = unsafe { libc::dup2(saved_fd, self.target_fd) };
            let _ = unsafe { libc::close(saved_fd) };
        }
    }

    // Prefer a very high descriptor so fd-reuse tests avoid low-numbered
    // process-wide fds used by unrelated concurrent tests.
    const FD_REUSE_TEST_MIN_FD: RawFd = 50_000;
    const FD_REUSE_TEST_FD_STRIDE: RawFd = 64;
    static NEXT_FD_REUSE_TEST_MIN_FD: AtomicI32 = AtomicI32::new(FD_REUSE_TEST_MIN_FD);

    fn next_fd_reuse_test_min_fd() -> RawFd {
        NEXT_FD_REUSE_TEST_MIN_FD.fetch_add(FD_REUSE_TEST_FD_STRIDE, Ordering::Relaxed)
    }

    fn dup_fd_at_least(fd: RawFd, min_fd: RawFd) -> RawFd {
        // Some test hosts run with low RLIMIT_NOFILE values where high minima
        // return EINVAL. Retry with progressively lower minima while still
        // preferring high fd numbers to reduce collision risk in parallel tests.
        let fallback_minima = [min_fd, 16_384, 4_096, 1_024, 256];
        for candidate_min in fallback_minima {
            // SAFETY: `fcntl(F_DUPFD_CLOEXEC, ...)` duplicates an existing fd
            // into an unowned raw descriptor >= `candidate_min`.
            let dup_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, candidate_min) };
            if dup_fd >= 0 {
                return dup_fd;
            }

            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINVAL) {
                continue;
            }

            unreachable!("failed to duplicate fd {fd} at/above {candidate_min}: {err}");
        }

        unreachable!(
            "failed to duplicate fd {fd}: invalid min fd for all candidates starting at {min_fd}"
        );
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
    fn dispatch_interest_is_rejected() {
        init_test("dispatch_interest_is_rejected");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let register_err = reactor
            .register(&sock1, Token::new(77), Interest::dispatch())
            .expect_err("dispatch interest should be rejected");
        crate::assert_with_log!(
            register_err.kind() == io::ErrorKind::InvalidInput,
            "register rejects unsupported dispatch interest",
            io::ErrorKind::InvalidInput,
            register_err.kind()
        );

        reactor
            .register(&sock1, Token::new(78), Interest::READABLE)
            .expect("readable register should succeed");
        let modify_err = reactor
            .modify(Token::new(78), Interest::dispatch())
            .expect_err("dispatch modify should be rejected");
        crate::assert_with_log!(
            modify_err.kind() == io::ErrorKind::InvalidInput,
            "modify rejects unsupported dispatch interest",
            io::ErrorKind::InvalidInput,
            modify_err.kind()
        );

        reactor
            .deregister(Token::new(78))
            .expect("deregister after rejected modify should succeed");
        crate::test_complete!("dispatch_interest_is_rejected");
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

        // Modify updates both the kernel registration and the local bookkeeping.
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
            let count = reactor
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
            crate::assert_with_log!(count == 0, "wake emits no readiness", 0usize, count);
            crate::assert_with_log!(
                events.is_empty(),
                "wake leaves event set empty",
                true,
                events.is_empty()
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
        let wait_for = Duration::from_millis(50);
        let deadline = start + wait_for;
        let mut count = 0usize;
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            count += reactor
                .poll(&mut events, Some(remaining))
                .expect("poll failed");
            if count > 0 {
                break;
            }
        }

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

        crate::assert_with_log!(
            !events.is_empty(),
            "events not empty",
            false,
            events.is_empty()
        );
        crate::assert_with_log!(count == 1, "count is stored events", 1usize, count);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("poll_zero_capacity_reports_zero_events_stored");
    }

    #[test]
    fn poll_events_resize_hysteresis_thresholds() {
        init_test("poll_events_resize_hysteresis_thresholds");
        let too_small = should_resize_poll_events(7, 8);
        let within_band = should_resize_poll_events(16, 8);
        let too_large = should_resize_poll_events(32, 8);

        crate::assert_with_log!(too_small, "resize when too small", true, too_small);
        crate::assert_with_log!(
            !within_band,
            "no resize within hysteresis band",
            true,
            !within_band
        );
        crate::assert_with_log!(too_large, "resize at 4x threshold", true, too_large);
        crate::test_complete!("poll_events_resize_hysteresis_thresholds");
    }

    #[test]
    fn poll_events_resize_hysteresis_saturates_at_usize_max() {
        init_test("poll_events_resize_hysteresis_saturates_at_usize_max");
        let target = usize::MAX - 1;
        let current_max = usize::MAX;

        let no_resize_at_max = should_resize_poll_events(current_max, target);
        let no_resize_at_equal = should_resize_poll_events(target, target);

        crate::assert_with_log!(
            !no_resize_at_max,
            "near-max current stays within hysteresis",
            true,
            !no_resize_at_max
        );
        crate::assert_with_log!(
            !no_resize_at_equal,
            "equal current/target does not resize",
            true,
            !no_resize_at_equal
        );
        crate::test_complete!("poll_events_resize_hysteresis_saturates_at_usize_max");
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
            .register(&read_sock, token, Interest::READABLE.with_edge_triggered())
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
                Err(err) => unreachable!("drain failed: {err}"),
            }
        }

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
    fn deregister_delete_failure_preserves_bookkeeping_for_retry() {
        init_test("deregister_delete_failure_preserves_bookkeeping_for_retry");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");
        let fd_reuse_min = next_fd_reuse_test_min_fd();

        let token = Token::new(78);
        let registered_fd = sock1.as_raw_fd();
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("register failed");

        let poller_fd = reactor.poller.as_raw_fd();
        let saved_poller_fd = dup_fd_at_least(poller_fd, fd_reuse_min);
        let mut poller_restore = FdRestoreGuard::new(poller_fd, saved_poller_fd);
        let replacement_fd = dup_fd_at_least(sock1.as_raw_fd(), fd_reuse_min);
        let replace_result = unsafe { libc::dup2(replacement_fd, poller_fd) };
        crate::assert_with_log!(
            replace_result == poller_fd,
            "replace poller fd with non-epoll descriptor",
            poller_fd,
            replace_result
        );
        let close_replacement = unsafe { libc::close(replacement_fd) };
        crate::assert_with_log!(
            close_replacement == 0,
            "close duplicated replacement fd",
            0,
            close_replacement
        );

        let err = reactor
            .deregister(token)
            .expect_err("deregister should fail when poller fd is replaced");
        let errno = err
            .raw_os_error()
            .expect("poller replacement should preserve errno");
        crate::assert_with_log!(
            errno != libc::ENOENT && errno != libc::EBADF,
            "non-epoll replacement yields hard delete failure",
            "errno != ENOENT && errno != EBADF",
            errno
        );

        let state = reactor.state.lock();
        crate::assert_with_log!(
            state.tokens.contains_key(&token),
            "token bookkeeping preserved after hard delete failure",
            true,
            state.tokens.contains_key(&token)
        );
        crate::assert_with_log!(
            state.fds.get(&registered_fd) == Some(&token),
            "fd bookkeeping preserved after hard delete failure",
            true,
            state.fds.get(&registered_fd) == Some(&token)
        );
        drop(state);

        let (restore_result, close_saved) = poller_restore.restore();
        crate::assert_with_log!(
            restore_result == poller_fd,
            "restore poller fd",
            poller_fd,
            restore_result
        );
        crate::assert_with_log!(close_saved == 0, "close saved poller fd", 0, close_saved);

        reactor
            .deregister(token)
            .expect("retry deregister after poller restore failed");
        let state = reactor.state.lock();
        crate::assert_with_log!(
            !state.tokens.contains_key(&token),
            "token bookkeeping removed after successful retry",
            false,
            state.tokens.contains_key(&token)
        );
        crate::assert_with_log!(
            !state.fds.contains_key(&registered_fd),
            "fd bookkeeping removed after successful retry",
            true,
            !state.fds.contains_key(&registered_fd)
        );
        drop(state);
        crate::test_complete!("deregister_hard_delete_failure_preserves_bookkeeping_for_retry");
    }

    #[test]
    fn modify_failure_preserves_bookkeeping_when_poller_fd_closed() {
        init_test("modify_failure_preserves_bookkeeping_when_poller_fd_closed");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");
        let fd_reuse_min = next_fd_reuse_test_min_fd();

        let token = Token::new(79);
        let registered_fd = sock1.as_raw_fd();
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("register failed");

        let poller_fd = reactor.poller.as_raw_fd();
        let saved_poller_fd = dup_fd_at_least(poller_fd, fd_reuse_min);
        let mut poller_restore = FdRestoreGuard::new(poller_fd, saved_poller_fd);

        // Replace the poller's descriptor with a valid but non-epoll fd so
        // `epoll_ctl` fails when the reactor invokes it. Using `dup2`
        // (rather than `libc::close(poller_fd)`) keeps `poller_fd` a live
        // descriptor throughout the test and — critically — prevents the
        // kernel from reassigning that fd number to a parallel test's
        // allocation. A raw `close(poller_fd)` left the fd number free
        // and racing tests routinely hit a fatal `IO Safety violation:
        // owned file descriptor already closed` abort when their OwnedFd
        // was silently closed underneath them by the later restore dup2.
        let replacement_fd = dup_fd_at_least(sock1.as_raw_fd(), fd_reuse_min);
        let replace_result = unsafe { libc::dup2(replacement_fd, poller_fd) };
        crate::assert_with_log!(
            replace_result == poller_fd,
            "replace poller fd with non-epoll descriptor",
            poller_fd,
            replace_result
        );
        let close_replacement = unsafe { libc::close(replacement_fd) };
        crate::assert_with_log!(
            close_replacement == 0,
            "close duplicated replacement fd",
            0,
            close_replacement
        );

        let err = reactor
            .modify(token, Interest::WRITABLE)
            .expect_err("modify should fail when poller fd is a non-epoll descriptor");
        let errno = err
            .raw_os_error()
            .expect("poller replacement should preserve errno");
        // `epoll_ctl(non-epoll-fd, ...)` returns `EINVAL`; `epoll_ctl(closed-fd, ...)`
        // returns `EBADF`. Either outcome proves the reactor surfaced the
        // kernel error without corrupting its bookkeeping, which is the
        // invariant this test protects.
        crate::assert_with_log!(
            errno != libc::ENOENT,
            "non-epoll replacement yields a hard epoll_ctl failure (EINVAL or EBADF)",
            "errno != ENOENT",
            errno
        );

        let state = reactor.state.lock();
        crate::assert_with_log!(
            state.tokens.contains_key(&token),
            "token bookkeeping preserved after modify failure from invalid poller",
            true,
            state.tokens.contains_key(&token)
        );
        crate::assert_with_log!(
            state.fds.get(&registered_fd) == Some(&token),
            "fd bookkeeping preserved after modify failure from invalid poller",
            true,
            state.fds.get(&registered_fd) == Some(&token)
        );
        drop(state);

        let (restore_result, close_saved) = poller_restore.restore();
        crate::assert_with_log!(
            restore_result == poller_fd,
            "restore poller fd",
            poller_fd,
            restore_result
        );
        crate::assert_with_log!(close_saved == 0, "close saved poller fd", 0, close_saved);

        reactor
            .modify(token, Interest::WRITABLE)
            .expect("retry modify after poller restore failed");

        // Cleanup
        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("modify_failure_preserves_bookkeeping_when_poller_fd_closed");
    }

    #[test]
    fn modify_closed_fd_cleans_stale_bookkeeping_for_fd_reuse() {
        init_test("modify_closed_fd_cleans_stale_bookkeeping_for_fd_reuse");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (old_sock, _old_peer) = UnixStream::pair().expect("failed to create unix stream pair");
        let fd_reuse_min = next_fd_reuse_test_min_fd();
        let stale_fd = dup_fd_at_least(old_sock.as_raw_fd(), fd_reuse_min);
        let stale_source = RawFdSource(stale_fd);
        let stale_token = Token::new(89);
        reactor
            .register(&stale_source, stale_token, Interest::READABLE)
            .expect("stale registration failed");
        let close_stale_result = unsafe { libc::close(stale_fd) };
        crate::assert_with_log!(
            close_stale_result == 0,
            "close duplicated stale fd before modify",
            0,
            close_stale_result
        );

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
        if stale_fd != new_sock_fd {
            let close_result = unsafe { libc::close(stale_fd) };
            if close_result != 0 {
                let errno = io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or_default();
                crate::assert_with_log!(
                    errno == libc::EBADF,
                    "close reused duplicated fd or already closed",
                    libc::EBADF,
                    errno
                );
            }
        }
        crate::test_complete!("modify_closed_fd_cleans_stale_bookkeeping_for_fd_reuse");
    }

    #[test]
    fn reused_fd_cannot_register_under_new_token_until_stale_token_removed() {
        init_test("reused_fd_cannot_register_under_new_token_until_stale_token_removed");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (old_sock, _old_peer) = UnixStream::pair().expect("failed to create unix stream pair");
        let fd_reuse_min = next_fd_reuse_test_min_fd();
        let stale_fd = dup_fd_at_least(old_sock.as_raw_fd(), fd_reuse_min);
        let stale_source = RawFdSource(stale_fd);
        let stale_token = Token::new(87);
        reactor
            .register(&stale_source, stale_token, Interest::READABLE)
            .expect("stale registration failed");
        let close_stale_result = unsafe { libc::close(stale_fd) };
        crate::assert_with_log!(
            close_stale_result == 0,
            "close duplicated stale fd before reuse",
            0,
            close_stale_result
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
        if stale_fd != new_sock_fd {
            let close_result = unsafe { libc::close(stale_fd) };
            if close_result != 0 {
                let errno = io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or_default();
                crate::assert_with_log!(
                    errno == libc::EBADF,
                    "close reused duplicated fd or already closed",
                    libc::EBADF,
                    errno
                );
            }
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

        // Test priority + interrupt extras
        let event = EpollReactor::interest_to_poll_event(
            Token::new(5),
            Interest::READABLE
                .add(Interest::PRIORITY)
                .add(Interest::HUP),
        );
        crate::assert_with_log!(event.readable, "readable set", true, event.readable);
        crate::assert_with_log!(
            event.is_priority(),
            "priority set",
            true,
            event.is_priority()
        );
        crate::assert_with_log!(event.is_interrupt(), "hup set", true, event.is_interrupt());
        crate::test_complete!("interest_to_poll_event_mapping");
    }

    #[test]
    fn poll_event_to_interest_mapping() {
        init_test("poll_event_to_interest_mapping");
        let event = PollEvent::all(1);
        let interest = EpollReactor::poll_event_to_interest(&event, None);
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
        let interest = EpollReactor::poll_event_to_interest(&event, None);
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
        let interest = EpollReactor::poll_event_to_interest(&event, None);
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

        let event = PollEvent::readable(4).with_priority().with_interrupt();
        let interest = EpollReactor::poll_event_to_interest(&event, None);
        crate::assert_with_log!(
            interest.is_readable(),
            "readable set",
            true,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_priority(),
            "priority set",
            true,
            interest.is_priority()
        );
        crate::assert_with_log!(interest.is_hup(), "hup set", true, interest.is_hup());
        crate::test_complete!("poll_event_to_interest_mapping");
    }

    #[test]
    fn poll_event_to_interest_masks_unregistered_directions() {
        init_test("poll_event_to_interest_masks_unregistered_directions");

        let readable_hup = PollEvent::all(9).with_interrupt();
        let interest =
            EpollReactor::poll_event_to_interest(&readable_hup, Some(Interest::READABLE));
        crate::assert_with_log!(
            interest.is_readable(),
            "registered readable preserved",
            true,
            interest.is_readable()
        );
        crate::assert_with_log!(
            !interest.is_writable(),
            "unregistered writable masked out",
            false,
            interest.is_writable()
        );
        crate::assert_with_log!(interest.is_hup(), "hup preserved", true, interest.is_hup());

        let writable_err = PollEvent::all(10).with_interrupt();
        let interest =
            EpollReactor::poll_event_to_interest(&writable_err, Some(Interest::WRITABLE));
        crate::assert_with_log!(
            !interest.is_readable(),
            "unregistered readable masked out",
            false,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_writable(),
            "registered writable preserved",
            true,
            interest.is_writable()
        );
        crate::assert_with_log!(interest.is_hup(), "hup preserved", true, interest.is_hup());

        let priority = PollEvent::readable(11).with_priority();
        let interest = EpollReactor::poll_event_to_interest(&priority, Some(Interest::PRIORITY));
        crate::assert_with_log!(
            !interest.is_readable(),
            "readable masked when only priority registered",
            false,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_priority(),
            "priority preserved when requested",
            true,
            interest.is_priority()
        );

        let interest = EpollReactor::poll_event_to_interest(&priority, Some(Interest::READABLE));
        crate::assert_with_log!(
            interest.is_readable(),
            "readable preserved for readable registration",
            true,
            interest.is_readable()
        );
        crate::assert_with_log!(
            !interest.is_priority(),
            "priority suppressed when not requested",
            false,
            interest.is_priority()
        );

        crate::test_complete!("poll_event_to_interest_masks_unregistered_directions");
    }

    #[test]
    fn translate_poll_event_drops_unknown_tokens() {
        init_test("translate_poll_event_drops_unknown_tokens");

        let state = ReactorState::new();
        let poll_event = PollEvent::readable(4242).with_interrupt();

        let translated = EpollReactor::translate_poll_event(&state, &poll_event);
        crate::assert_with_log!(
            translated.is_none(),
            "unknown token events dropped",
            true,
            translated.is_none()
        );

        crate::test_complete!("translate_poll_event_drops_unknown_tokens");
    }

    #[test]
    fn translate_poll_event_drops_masked_empty_interest() {
        init_test("translate_poll_event_drops_masked_empty_interest");

        let token = Token::new(31337);
        let mut state = ReactorState::new();
        state.tokens.insert(
            token,
            RegistrationInfo {
                raw_fd: -1,
                interest: Interest::PRIORITY,
            },
        );

        let poll_event = PollEvent::readable(token.0);
        let translated = EpollReactor::translate_poll_event(&state, &poll_event);
        crate::assert_with_log!(
            translated.is_none(),
            "masked empty readiness dropped",
            true,
            translated.is_none()
        );

        crate::test_complete!("translate_poll_event_drops_masked_empty_interest");
    }

    #[test]
    fn interest_to_poll_mode_mapping() {
        init_test("interest_to_poll_mode_mapping");

        let mode = EpollReactor::interest_to_poll_mode(Interest::READABLE);
        crate::assert_with_log!(
            mode == PollMode::Oneshot,
            "default oneshot",
            true,
            mode == PollMode::Oneshot
        );

        let mode = EpollReactor::interest_to_poll_mode(Interest::READABLE.with_edge_triggered());
        crate::assert_with_log!(
            mode == PollMode::Edge,
            "edge mode",
            true,
            mode == PollMode::Edge
        );

        let mode = EpollReactor::interest_to_poll_mode(Interest::READABLE.with_oneshot());
        crate::assert_with_log!(
            mode == PollMode::Oneshot,
            "oneshot mode",
            true,
            mode == PollMode::Oneshot
        );

        let mode = EpollReactor::interest_to_poll_mode(
            Interest::READABLE.with_edge_triggered().with_oneshot(),
        );
        crate::assert_with_log!(
            mode == PollMode::EdgeOneshot,
            "edge oneshot mode",
            true,
            mode == PollMode::EdgeOneshot
        );
        crate::test_complete!("interest_to_poll_mode_mapping");
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

    // ONESHOT conformance tests (5 tests required for asupersync-x9k6a1)

    #[test]
    fn oneshot_fire_then_silence_until_rearm() {
        init_test("oneshot_fire_then_silence_until_rearm");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (mut read_sock, mut write_sock) =
            UnixStream::pair().expect("failed to create unix stream pair");
        read_sock
            .set_nonblocking(true)
            .expect("failed to set nonblocking");

        let token = Token::new(101);
        // Register with ONESHOT (default non-edge mode)
        reactor
            .register(&read_sock, token, Interest::READABLE.with_oneshot())
            .expect("register with oneshot failed");

        // Write data to trigger readable event
        write_sock.write_all(b"test").expect("write failed");

        // First poll should return the event
        let mut events = Events::with_capacity(64);
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");
        crate::assert_with_log!(count >= 1, "first poll has events", true, count >= 1);

        let mut found = false;
        for event in &events {
            if event.token == token && event.is_readable() {
                found = true;
                break;
            }
        }
        crate::assert_with_log!(found, "first poll found readable event", true, found);

        // Read some data but not all (socket still has data)
        let mut buf = [0u8; 2];
        let read_count = read_sock.read(&mut buf).expect("partial read failed");
        crate::assert_with_log!(read_count == 2, "partial read", 2usize, read_count);

        // Second poll should return NO events (ONESHOT fired, not re-armed)
        events.clear();
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(50)))
            .expect("second poll failed");
        crate::assert_with_log!(
            count == 0,
            "second poll no events (oneshot silence)",
            0usize,
            count
        );

        // Re-arm by modifying interest
        reactor
            .modify(token, Interest::READABLE.with_oneshot())
            .expect("re-arm modify failed");

        // Third poll should now return events again
        events.clear();
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("third poll failed");
        crate::assert_with_log!(
            count >= 1,
            "third poll has events after re-arm",
            true,
            count >= 1
        );

        let mut found_after_rearm = false;
        for event in &events {
            if event.token == token && event.is_readable() {
                found_after_rearm = true;
                break;
            }
        }
        crate::assert_with_log!(
            found_after_rearm,
            "third poll found readable after re-arm",
            true,
            found_after_rearm
        );

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("oneshot_fire_then_silence_until_rearm");
    }

    #[test]
    fn oneshot_rearm_preserves_interest() {
        init_test("oneshot_rearm_preserves_interest");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (read_sock, mut write_sock) =
            UnixStream::pair().expect("failed to create unix stream pair");
        read_sock
            .set_nonblocking(true)
            .expect("failed to set nonblocking");

        let token = Token::new(102);
        // Register with complex interest: READABLE + PRIORITY + ONESHOT
        let complex_interest = Interest::READABLE.add(Interest::PRIORITY).with_oneshot();
        reactor
            .register(&read_sock, token, complex_interest)
            .expect("register with complex oneshot interest failed");

        // Trigger event
        write_sock.write_all(b"data").expect("write failed");

        // Poll to fire the oneshot
        let mut events = Events::with_capacity(64);
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");
        crate::assert_with_log!(count >= 1, "oneshot fired", true, count >= 1);

        // Re-arm with same complex interest
        reactor
            .modify(token, complex_interest)
            .expect("re-arm with complex interest failed");

        // Verify bookkeeping preserved the complex interest
        let state = reactor.state.lock();
        let info = state.tokens.get(&token).unwrap();
        crate::assert_with_log!(
            info.interest == complex_interest,
            "complex interest preserved after re-arm",
            complex_interest,
            info.interest
        );
        crate::assert_with_log!(
            info.interest.is_readable(),
            "readable preserved",
            true,
            info.interest.is_readable()
        );
        crate::assert_with_log!(
            info.interest.is_priority(),
            "priority preserved",
            true,
            info.interest.is_priority()
        );
        crate::assert_with_log!(
            info.interest.is_oneshot(),
            "oneshot preserved",
            true,
            info.interest.is_oneshot()
        );
        drop(state);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("oneshot_rearm_preserves_interest");
    }

    #[test]
    fn oneshot_concurrent_modify_wait_deterministic() {
        init_test("oneshot_concurrent_modify_wait_deterministic");
        let reactor = std::sync::Arc::new(EpollReactor::new().expect("failed to create reactor"));
        let (read_sock, mut write_sock) =
            UnixStream::pair().expect("failed to create unix stream pair");
        read_sock
            .set_nonblocking(true)
            .expect("failed to set nonblocking");

        let token = Token::new(103);
        reactor
            .register(&read_sock, token, Interest::READABLE.with_oneshot())
            .expect("register failed");

        // Make socket readable
        write_sock.write_all(b"concurrent").expect("write failed");

        // Concurrent modify and poll operations
        let reactor_clone = reactor.clone();
        std::thread::scope(|s| {
            let modifier_handle = s.spawn(|| {
                // Rapid re-arm attempts
                for i in 0..10 {
                    let result = reactor_clone.modify(token, Interest::READABLE.with_oneshot());
                    if result.is_err() {
                        break; // Token may have been deregistered
                    }
                    if i % 3 == 0 {
                        std::thread::sleep(Duration::from_micros(100));
                    }
                }
            });

            let poller_handle = s.spawn(|| {
                let mut total_events = 0;
                for _ in 0..20 {
                    let mut events = Events::with_capacity(64);
                    match reactor_clone.poll(&mut events, Some(Duration::from_millis(5))) {
                        Ok(count) => total_events += count,
                        Err(_) => break,
                    }
                }
                total_events
            });

            modifier_handle.join().expect("modifier thread panicked");
            let total_events = poller_handle.join().expect("poller thread panicked");

            // The exact number isn't deterministic due to timing, but should be reasonable
            crate::assert_with_log!(
                total_events < 50,
                "concurrent operations don't create event storms",
                true,
                total_events < 50
            );
        });

        // Verify reactor state is consistent after concurrent operations
        let final_count = reactor.registration_count();
        crate::assert_with_log!(
            final_count <= 1,
            "registration count consistent after concurrent ops",
            true,
            final_count <= 1
        );

        // Clean up if still registered
        let _ = reactor.deregister(token);
        crate::test_complete!("oneshot_concurrent_modify_wait_deterministic");
    }

    #[test]
    fn oneshot_auto_rearm_on_specific_events() {
        init_test("oneshot_auto_rearm_on_specific_events");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (read_sock, mut write_sock) =
            UnixStream::pair().expect("failed to create unix stream pair");
        read_sock
            .set_nonblocking(true)
            .expect("failed to set nonblocking");

        let token = Token::new(104);
        // Register for both readable and writable with oneshot
        reactor
            .register(&read_sock, token, Interest::both().with_oneshot())
            .expect("register failed");

        // Socket should be immediately writable
        let mut events = Events::with_capacity(64);
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");
        crate::assert_with_log!(count >= 1, "writable event fired", true, count >= 1);

        let mut found_writable = false;
        for event in &events {
            if event.token == token && event.is_writable() {
                found_writable = true;
                break;
            }
        }
        crate::assert_with_log!(
            found_writable,
            "initial writable event",
            true,
            found_writable
        );

        // After oneshot fires, no more events until re-arm
        events.clear();
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(50)))
            .expect("poll failed");
        crate::assert_with_log!(count == 0, "no events after oneshot", 0usize, count);

        // Re-arm for readable only
        reactor
            .modify(token, Interest::READABLE.with_oneshot())
            .expect("re-arm for readable failed");

        // Write data to trigger readable
        write_sock.write_all(b"readable").expect("write failed");

        events.clear();
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");
        crate::assert_with_log!(count >= 1, "readable event after re-arm", true, count >= 1);

        let mut found_readable = false;
        for event in &events {
            if event.token == token && event.is_readable() {
                found_readable = true;
                break;
            }
        }
        crate::assert_with_log!(
            found_readable,
            "readable event after re-arm",
            true,
            found_readable
        );

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("oneshot_auto_rearm_on_specific_events");
    }

    #[test]
    fn oneshot_close_before_rearm_no_leak() {
        init_test("oneshot_close_before_rearm_no_leak");
        let reactor = EpollReactor::new().expect("failed to create reactor");
        let (read_sock, mut write_sock) =
            UnixStream::pair().expect("failed to create unix stream pair");
        read_sock
            .set_nonblocking(true)
            .expect("failed to set nonblocking");

        let token = Token::new(105);
        let raw_fd = read_sock.as_raw_fd();

        reactor
            .register(&read_sock, token, Interest::READABLE.with_oneshot())
            .expect("register failed");

        // Fire the oneshot
        write_sock.write_all(b"fire").expect("write failed");
        let mut events = Events::with_capacity(64);
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");
        crate::assert_with_log!(count >= 1, "oneshot fired", true, count >= 1);

        // Close the socket BEFORE attempting re-arm
        drop(read_sock);

        // Verify fd is closed
        let fd_closed = unsafe { fcntl(raw_fd, F_GETFD) } == -1;
        crate::assert_with_log!(fd_closed, "fd closed before re-arm", true, fd_closed);

        // Attempt to re-arm after close should fail gracefully
        let modify_result = reactor.modify(token, Interest::READABLE.with_oneshot());
        crate::assert_with_log!(
            modify_result.is_err(),
            "modify after close fails",
            true,
            modify_result.is_err()
        );

        // Verify no registration leak
        let registration_count = reactor.registration_count();
        crate::assert_with_log!(
            registration_count == 0,
            "no registration leak after close-before-rearm",
            0usize,
            registration_count
        );

        // Deregister should also succeed (idempotent cleanup)
        let deregister_result = reactor.deregister(token);
        crate::assert_with_log!(
            deregister_result.is_ok(),
            "deregister after close succeeds",
            true,
            deregister_result.is_ok()
        );

        crate::test_complete!("oneshot_close_before_rearm_no_leak");
    }
}
