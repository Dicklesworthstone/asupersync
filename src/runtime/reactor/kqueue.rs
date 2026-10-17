//! macOS/BSD kqueue-based reactor implementation.
//!
//! This module provides [`KqueueReactor`], a reactor implementation that uses
//! kqueue for efficient I/O event notification on BSD-family platforms.
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
//! Internal state is protected by `Mutex` for registration/deregistration.
//! `wake()` is lock-free; `poll()` acquires a short-lived mutex on the
//! reused event buffer for the duration of the kernel wait. Concurrent
//! `poll()` callers are expected to be serialized externally (the runtime
//! `IoDriver` uses an `is_polling` CAS to enforce this leader/follower
//! discipline).
//!
//! # Edge-Triggered Mode
//!
//! Registrations default to oneshot delivery, matching the portable reactor
//! contract across backends. Callers can opt into edge-triggered behavior with
//! [`Interest::EDGE_TRIGGERED`], which maps to `EV_CLEAR`.
//! [`Interest::DISPATCH`] and [`Interest::PRIORITY`] are rejected because the
//! `polling` crate does not expose portable support for native `EV_DISPATCH`
//! or OOB/priority registration through this backend.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::runtime::reactor::{KqueueReactor, Reactor, Interest, Events};
//! use std::net::TcpListener;
//!
//! let reactor = KqueueReactor::new()?;
//! let mut listener = TcpListener::bind("127.0.0.1:0")?;
//!
//! // Register the listener with kqueue
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
use polling::{Event as PollEvent, Events as PollingEvents, PollMode, Poller};
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

/// macOS/BSD kqueue-based reactor.
///
/// This reactor uses the `polling` crate to interface with kqueue,
/// providing efficient I/O event notification for async operations.
///
/// # Features
///
/// - `register()`: Adds fd to kqueue with caller-selected trigger mode
/// - `modify()`: Updates interest flags for a registered fd
/// - `deregister()`: Removes fd from kqueue
/// - `poll()`: Waits for and collects ready events
/// - `wake()`: Interrupts a blocking poll from another thread
///
/// Registrations default to oneshot delivery to match the rest of the reactor
/// abstraction. Callers can request edge-triggered semantics via
/// [`Interest::EDGE_TRIGGERED`]. [`Interest::DISPATCH`] and
/// [`Interest::PRIORITY`] are rejected because this backend cannot express
/// them faithfully through the `polling` crate.
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
    /// Reusable polling event buffer to avoid per-poll allocations.
    poll_events: Mutex<PollingEvents>,
}

const DEFAULT_POLL_EVENTS_CAPACITY: usize = 64;

#[inline]
fn should_resize_poll_events(current: usize, target: usize) -> bool {
    current < target || target.checked_mul(4).is_some_and(|t4| current >= t4)
}

impl KqueueReactor {
    #[inline]
    fn validate_supported_interest(interest: Interest) -> io::Result<()> {
        if interest.is_dispatch() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Interest::DISPATCH is not supported by the kqueue reactor",
            ));
        }

        if interest.is_priority() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Interest::PRIORITY is not supported by the kqueue reactor",
            ));
        }

        Ok(())
    }

    #[inline]
    const fn interest_to_poll_mode(interest: Interest) -> PollMode {
        let single_shot = interest.is_oneshot();
        if interest.is_edge_triggered() {
            if single_shot {
                PollMode::EdgeOneshot
            } else {
                PollMode::Edge
            }
        } else {
            // Preserve the reactor's default oneshot semantics when callers
            // do not explicitly request edge-triggered delivery.
            PollMode::Oneshot
        }
    }

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
            poll_events: Mutex::new(PollingEvents::with_capacity(
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

    /// Converts a polling event into reactor readiness while recovering the
    /// kqueue-specific EOF signal that `polling` encodes as readable+writable.
    ///
    /// As with the epoll backend, generic readiness bits are masked by the
    /// registration's requested directions so we do not synthesize readiness
    /// the caller never asked for. For single-direction registrations,
    /// `polling` reports EOF as readable+writable; in that case we preserve
    /// the registered direction and surface the extra bit as `HUP`.
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

        let eof_for_single_direction = event.readable
            && event.writable
            && registered_interest
                .is_some_and(|registered| registered.is_readable() ^ registered.is_writable());

        if eof_for_single_direction {
            interest = interest.add(Interest::HUP);
        }

        interest
    }
}

impl Reactor for KqueueReactor {
    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        Self::validate_supported_interest(interest)?;
        let raw_fd = source.as_raw_fd();

        // Check for duplicate registration first
        let mut regs = self.registrations.lock();
        if regs.contains_key(&token) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "token already registered",
            ));
        }
        if regs.values().any(|info| info.raw_fd == raw_fd) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "fd already registered",
            ));
        }

        // Ensure the file descriptor is still valid before registering.
        if unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } == -1 {
            return Err(io::Error::last_os_error());
        }

        // Create the polling event with the token as the key
        let event = Self::interest_to_poll_event(token, interest);

        // SAFETY: We trust that the caller maintains the invariant that the
        // source (and its file descriptor) remains valid until deregistered.
        // The BorrowedFd is only used for the duration of this call.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };

        let mode = Self::interest_to_poll_mode(interest);

        // Add to kqueue via the polling crate with the caller-selected mode.
        // SAFETY: the caller must uphold the invariant that `source` remains valid
        // (and thus its raw fd remains open) until `deregister()` is called.
        unsafe { self.poller.add_with_mode(&borrowed_fd, event, mode)? };

        // Track the registration for modify/deregister
        regs.insert(token, RegistrationInfo { raw_fd, interest });

        Ok(())
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        Self::validate_supported_interest(interest)?;
        let mut regs = self.registrations.lock();
        let entry = match regs.entry(token) {
            std::collections::hash_map::Entry::Occupied(entry) => entry,
            std::collections::hash_map::Entry::Vacant(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ));
            }
        };
        let raw_fd = entry.get().raw_fd;

        // Create the new polling event
        let event = Self::interest_to_poll_event(token, interest);

        // SAFETY: We stored the raw_fd during registration and trust it's still valid.
        // The caller is responsible for ensuring the fd remains valid until deregistered.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };

        let mode = Self::interest_to_poll_mode(interest);

        // Modify the kqueue registration with the caller-selected mode.
        match self.poller.modify_with_mode(borrowed_fd, event, mode) {
            Ok(()) => {
                entry.into_mut().interest = interest;
                Ok(())
            }
            Err(err) => match err.raw_os_error() {
                Some(libc::ENOENT) => {
                    entry.remove();
                    Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "token not registered",
                    ))
                }
                Some(libc::EBADF) => {
                    let fd_still_valid = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } != -1;
                    if fd_still_valid {
                        Err(err)
                    } else {
                        entry.remove();
                        Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "token not registered",
                        ))
                    }
                }
                _ => Err(err),
            },
        }
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        let mut regs = self.registrations.lock();
        let info = regs
            .get(&token)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "token not registered"))?;

        // SAFETY: We stored the raw_fd during registration and trust it's still valid.
        // The caller is responsible for ensuring the fd remains valid until deregistered.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(info.raw_fd) };
        // Determine whether the target fd itself is valid so EBADF can be
        // interpreted correctly (target closed vs poller invalid).
        let fd_still_valid = unsafe { libc::fcntl(info.raw_fd, libc::F_GETFD) } != -1;

        // Remove from kqueue. Only drop bookkeeping once the source is
        // definitely gone from the kernel or the target fd itself is already
        // closed. Keeping the entry on hard failures preserves accurate retry
        // semantics for Registration::deregister().
        match self.poller.delete(borrowed_fd) {
            Ok(()) => {
                regs.remove(&token);
                Ok(())
            }
            Err(err) => match err.raw_os_error() {
                Some(libc::ENOENT) => {
                    regs.remove(&token);
                    Ok(())
                }
                Some(libc::EBADF) if !fd_still_valid => {
                    regs.remove(&token);
                    Ok(())
                }
                _ => Err(err),
            },
        }
    }

    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
        events.clear();

        let requested_capacity = NonZeroUsize::new(events.capacity().max(1)).expect("max(1)");
        let mut poll_events = self.poll_events.lock();

        let current = poll_events.capacity().get();
        let target = requested_capacity.get();

        if should_resize_poll_events(current, target) {
            *poll_events = PollingEvents::with_capacity(requested_capacity);
        } else {
            poll_events.clear();
        }

        self.poller.wait(&mut poll_events, timeout)?;

        let registrations = self.registrations.lock();

        // Convert polling events to our Event type.
        //
        // br-asupersync-3uog0t: skip events whose intersection of observed
        // kernel readiness with the source's registered interest is
        // `Interest::NONE`. Without this guard, the kqueue path emits
        // empty-interest events (e.g., kernel reports READABLE for a
        // WRITABLE-only registration with no HUP/error overlap), causing
        // spurious waker dispatches and wasting events-buffer slots. Mirrors
        // the existing filter on the epoll path
        // (`Self::translate_poll_event` returns `Option<Event>` and skips
        // empty-interest results).
        for poll_event in poll_events.iter() {
            let token = Token(poll_event.key);
            let registered_interest = registrations.get(&token).map(|info| info.interest);
            let interest = Self::poll_event_to_interest(&poll_event, registered_interest);
            if interest.is_empty() {
                continue;
            }
            events.push(Event::new(token, interest));
        }

        drop(registrations);
        drop(poll_events);
        Ok(events.len())
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
#[path = "kqueue_inline_tests.rs"]
mod tests;
