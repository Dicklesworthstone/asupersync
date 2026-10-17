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
use hashbrown::HashMap;
use hashbrown::hash_map::Entry;
use parking_lot::Mutex;
use polling::{Event as PollEvent, Events as PollEvents, PollMode, Poller};
use std::collections::HashSet;
use std::io;
use std::num::NonZeroUsize;
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// File descriptor identity for TOCTOU race detection.
///
/// Used to detect if a file descriptor has been closed and reused
/// during registration, which would create a race condition where
/// epoll ends up watching a different resource than intended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FdIdentity {
    /// Device ID of the file
    dev: libc::dev_t,
    /// Inode number of the file
    ino: libc::ino_t,
    /// File type and mode
    mode: libc::mode_t,
}

impl FdIdentity {
    /// Get the identity of a file descriptor.
    ///
    /// Returns None if the fd is invalid or if fstat fails.
    fn from_fd(raw_fd: i32) -> Option<Self> {
        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::fstat(raw_fd, &mut stat_buf) };
        if result == 0 {
            Some(FdIdentity {
                dev: stat_buf.st_dev,
                ino: stat_buf.st_ino,
                mode: stat_buf.st_mode,
            })
        } else {
            None
        }
    }
}

/// Registration state for a source.
#[derive(Debug)]
struct RegistrationInfo {
    /// The raw file descriptor (for bookkeeping).
    raw_fd: i32,
    /// The current interest flags.
    interest: Interest,
    /// File descriptor identity to detect reuse/TOCTOU races.
    fd_identity: FdIdentity,
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

    #[inline]
    fn fd_no_longer_matches(raw_fd: i32, expected: FdIdentity) -> bool {
        FdIdentity::from_fd(raw_fd).is_none_or(|current| current != expected)
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

        // Capture fd identity before any operations for TOCTOU detection
        let pre_identity = FdIdentity::from_fd(raw_fd).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid file descriptor")
        })?;

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
        // We perform epoll_ctl first, then immediately validate that the fd
        // identity hasn't changed to detect TOCTOU races. This minimizes the
        // window where the fd could be closed and reused.
        unsafe {
            self.poller.add_with_mode(&borrowed_fd, event, mode)?;
        }

        // Immediately after epoll_ctl succeeds, validate fd identity hasn't changed
        let post_identity = FdIdentity::from_fd(raw_fd).ok_or_else(|| {
            // If we can't get identity after successful epoll_ctl, the fd was closed
            // Try to clean up the epoll registration
            let _ = self.poller.delete(borrowed_fd);
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "fd became invalid during registration (possible TOCTOU race)",
            )
        })?;

        if pre_identity != post_identity {
            // FD was reused during registration - this is a TOCTOU race
            // Try to clean up the epoll registration for the new fd
            let _ = self.poller.delete(borrowed_fd);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fd identity changed during registration (TOCTOU race detected)",
            ));
        }

        // Now we're confident the fd is the same one we intended to register
        // Track the registration for modify/deregister
        state.tokens.insert(
            token,
            RegistrationInfo {
                raw_fd,
                interest,
                fd_identity: post_identity,
            },
        );
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
            Err(err) => {
                let target_fd_stale = Self::fd_no_longer_matches(raw_fd, entry.get().fd_identity);
                let stale_registration =
                    err.raw_os_error() == Some(libc::ENOENT) || target_fd_stale;
                if stale_registration {
                    // Determine whether the target fd itself is valid so hard
                    // epoll_ctl failures can be interpreted correctly (target
                    // closed/reused vs reactor poller invalid). Evaluate this
                    // AFTER the modify attempt to prevent a TOCTOU race. If the
                    // identity no longer matches, remove bookkeeping regardless
                    // of the specific errno; full-suite fd churn can reuse the
                    // raw fd slot before the syscall and surface EINVAL/EPERM
                    // instead of EBADF.
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
                } else {
                    drop(state);
                    Err(err)
                }
            }
        }
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        let mut state = self.state.lock();
        let (raw_fd, fd_identity) = match state.tokens.get(&token) {
            Some(info) => (info.raw_fd, info.fd_identity),
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
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
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
            Err(err) => {
                let target_fd_stale = Self::fd_no_longer_matches(raw_fd, fd_identity);
                let stale_registration =
                    err.raw_os_error() == Some(libc::ENOENT) || target_fd_stale;
                if stale_registration {
                    // Determine whether the target fd itself is valid so hard
                    // epoll_ctl failures can be interpreted correctly (target
                    // closed/reused vs reactor poller invalid). Evaluate this
                    // AFTER the delete attempt to prevent a TOCTOU race. If the
                    // identity no longer matches, cleanup is already complete
                    // from the reactor contract's point of view regardless of
                    // whether the kernel surfaced ENOENT, EBADF, EINVAL, or
                    // another fd-reuse-shaped errno.
                    if let Some(info) = state.tokens.remove(&token) {
                        state.fds.remove(&info.raw_fd);
                        drop(state);
                        // Decrement count only if we actually removed a registration
                        self.registration_count.fetch_sub(1, Ordering::Relaxed);
                    } else {
                        drop(state);
                    }
                    Ok(())
                } else {
                    drop(state);
                    Err(err)
                }
            }
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
#[path = "epoll_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "epoll_conformance_tests.rs"]
pub mod epoll_conformance_tests;

#[cfg(test)]
#[path = "epoll_epoll_conformance_integration_inline_tests.rs"]
mod epoll_conformance_integration;
