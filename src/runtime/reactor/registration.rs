//! RAII registration handle for I/O sources.
//!
//! This module provides the [`Registration`] type that represents an active I/O
//! registration with the reactor. When dropped, it automatically deregisters
//! from the reactor, ensuring no leaked registrations and enabling cancel-safety.
//!
//! # Design
//!
//! The registration holds a weak reference to the reactor, allowing graceful
//! handling when the reactor is dropped before all registrations. This design
//! is critical for cancel-correctness:
//!
//! 1. When a task is cancelled, its I/O futures are dropped
//! 2. Dropping futures drops their Registration
//! 3. Registration::drop() deregisters from reactor
//! 4. No dangling registrations, no wakeup of dead tasks
//!
//! # Example
//!
//! ```ignore
//! use asupersync::runtime::reactor::{Registration, Interest, Token};
//!
//! // Registration is created by the reactor when registering a source
//! let registration = reactor.register(source, Interest::READABLE)?;
//!
//! // Change interest later
//! registration.set_interest(Interest::READABLE | Interest::WRITABLE)?;
//!
//! // Automatic deregistration when dropped
//! drop(registration);
//! ```

use super::{Interest, Token};
use std::cell::Cell;
use std::io;
use std::marker::PhantomData;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Weak;

/// Internal trait for reactor operations needed by Registration.
///
/// This trait is implemented by reactors to support RAII deregistration
/// and interest modification. It uses interior mutability since Registration
/// only holds a shared reference.
pub trait ReactorHandle: Send + Sync {
    /// Deregisters a source by its token.
    ///
    /// This is called from Registration::drop(). Errors are ignored since
    /// the source may already be gone or the reactor may be shutting down.
    fn deregister_by_token(&self, token: Token) -> io::Result<()>;

    /// Modifies the interest set for a registered source.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid or the reactor operation fails.
    fn modify_interest(&self, token: Token, interest: Interest) -> io::Result<()>;
}

/// Handle to an active I/O source registration.
///
/// Dropping a Registration automatically deregisters from the reactor.
/// This ensures no leaked registrations and is cancel-safe.
///
/// # Thread Safety
///
/// `Registration` is `Send` but `!Sync`:
/// - It can be moved between threads (e.g., if an owning task migrates).
/// - It cannot be shared concurrently because it uses interior mutability (`Cell`)
///   for interest bookkeeping.
///
/// Reactor backends must treat deregistration/interest modification as thread-safe.
///
/// # Cancel-Safety
///
/// When a task holding a Registration is cancelled:
/// 1. The task's future is dropped
/// 2. The Registration is dropped as part of the future
/// 3. The Drop impl deregisters from the reactor
/// 4. No stale wakeups can occur for the cancelled task
pub struct Registration {
    /// Token identifying this registration in the reactor's slab.
    token: Token,
    /// Weak reference to reactor (allows safe drop if reactor gone).
    reactor: Weak<dyn ReactorHandle>,
    /// Current interest (for modify operations).
    interest: Cell<Interest>,
    /// When true, Drop will not attempt to deregister (used by `deregister()` to avoid double calls).
    disarmed: Cell<bool>,
    /// Marker to keep the type `!Sync` (it already is via `Cell`, but keep an explicit marker
    /// so the intent is obvious when refactoring fields).
    _marker: PhantomData<std::cell::Cell<()>>,
}

impl Registration {
    /// Creates a new registration.
    ///
    /// This is called internally by the reactor when registering a source.
    #[cfg(test)]
    pub(crate) fn new(token: Token, reactor: Weak<dyn ReactorHandle>, interest: Interest) -> Self {
        Self {
            token,
            reactor,
            interest: Cell::new(interest),
            disarmed: Cell::new(false),
            _marker: PhantomData,
        }
    }

    /// Returns the token identifying this registration.
    #[inline]
    #[must_use]
    pub fn token(&self) -> Token {
        self.token
    }

    /// Returns the current interest set.
    #[inline]
    #[must_use]
    pub fn interest(&self) -> Interest {
        self.interest.get()
    }

    /// Modifies the interest set for this registration.
    ///
    /// This allows changing which events the source is monitored for
    /// without deregistering and re-registering.
    ///
    /// # Errors
    ///
    /// Returns an error if the reactor is no longer available or if
    /// the modify operation fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Start monitoring only for reads
    /// let registration = reactor.register(source, Interest::READABLE)?;
    ///
    /// // Later, also monitor for writes
    /// registration.set_interest(Interest::READABLE | Interest::WRITABLE)?;
    /// ```
    #[inline]
    pub fn set_interest(&self, interest: Interest) -> io::Result<()> {
        if let Some(reactor) = self.reactor.upgrade() {
            reactor.modify_interest(self.token, interest)?;
            self.interest.set(interest);
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "reactor has been dropped",
            ))
        }
    }

    /// Returns `true` if the registration is still active.
    ///
    /// A registration becomes inactive when the reactor is dropped.
    /// Inactive registrations will no-op on drop and fail on set_interest.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.reactor.strong_count() > 0
    }

    /// Explicitly deregisters without waiting for drop.
    ///
    /// This is useful when you want to handle deregistration errors
    /// explicitly rather than ignoring them (as drop does).
    ///
    /// # Errors
    ///
    /// Returns an error if the reactor is no longer available or if
    /// the deregister operation fails. A `NotFound` error is treated
    /// as already deregistered.
    pub fn deregister(self) -> io::Result<()> {
        // IMPORTANT: never `mem::forget` a `Registration`. It holds a `Weak`, and leaking it
        // can keep the reactor's allocation alive indefinitely via the weak refcount.
        //
        // If explicit deregistration succeeds, we "disarm" Drop so it doesn't attempt a second
        // deregistration.
        //
        // If it fails (and the error is not NotFound), we make a best-effort *second* attempt.
        // If that retry succeeds (or reports NotFound), this explicit deregistration succeeded
        // and should return Ok.
        //
        // If the error persists, DO NOT disarm Drop. `self` is consumed here, so callers have no
        // retry surface left. Leaving Drop armed gives the registration one final best-effort
        // cleanup pass instead of stranding the reactor entry.
        let this = self;

        this.reactor.upgrade().map_or_else(
            || {
                // Reactor already gone, nothing to do (and nothing for Drop to do either).
                this.disarmed.set(true);
                Ok(())
            },
            |reactor| {
                let outcome = match deregister_no_panic(&*reactor, this.token) {
                    Some(Ok(())) => Ok(()),
                    Some(Err(err)) if err.kind() == io::ErrorKind::NotFound => Ok(()),
                    Some(Err(first_err)) => {
                        // Best-effort retry on ordinary errors.
                        match deregister_no_panic(&*reactor, this.token) {
                            Some(Ok(())) => Ok(()),
                            Some(Err(err)) if err.kind() == io::ErrorKind::NotFound => Ok(()),
                            Some(Err(_)) | None => Err(first_err),
                        }
                    }
                    // Reactor panicked while deregistering: surface the error and
                    // don't attempt a second deregister call.
                    None => panicked_deregister_result(),
                };
                if outcome.is_ok() {
                    this.disarmed.set(true);
                }
                outcome
            },
        )
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        if self.disarmed.get() {
            return;
        }
        if let Some(reactor) = self.reactor.upgrade() {
            // Best-effort cleanup: retry once on non-NotFound errors to reduce
            // stale-registration risk if the first deregister attempt fails transiently.
            if let Some(Err(err)) = deregister_no_panic(&*reactor, self.token) {
                if err.kind() != io::ErrorKind::NotFound {
                    let _ = deregister_no_panic(&*reactor, self.token);
                }
            }
        }
    }
}

fn deregister_no_panic(reactor: &dyn ReactorHandle, token: Token) -> Option<io::Result<()>> {
    panic::catch_unwind(AssertUnwindSafe(|| reactor.deregister_by_token(token))).ok()
}

fn panicked_deregister_result() -> io::Result<()> {
    Err(io::Error::other("reactor deregister panicked"))
}

impl std::fmt::Debug for Registration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registration")
            .field("token", &self.token)
            .field("interest", &self.interest.get())
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "registration_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "registration_conformance_tests.rs"]
pub mod registration_conformance_tests;

#[cfg(test)]
#[path = "registration_registration_conformance_integration_inline_tests.rs"]
mod registration_conformance_integration;
