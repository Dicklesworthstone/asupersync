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
        // and should return Ok. Only persistent failures return Err. We then disarm Drop to
        // avoid repeated deregistration attempts on a consumed handle.
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
                this.disarmed.set(true);
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
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Test reactor for testing Registration RAII behavior.
    struct TestReactor {
        deregistered: AtomicBool,
        deregister_count: AtomicUsize,
        last_token: Mutex<Option<Token>>,
        last_interest: Mutex<Option<Interest>>,
    }

    impl TestReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                deregistered: AtomicBool::new(false),
                deregister_count: AtomicUsize::new(0),
                last_token: Mutex::new(None),
                last_interest: Mutex::new(None),
            })
        }

        fn was_deregistered(&self) -> bool {
            self.deregistered.load(Ordering::SeqCst)
        }

        fn deregister_count(&self) -> usize {
            self.deregister_count.load(Ordering::SeqCst)
        }
    }

    impl ReactorHandle for TestReactor {
        fn deregister_by_token(&self, token: Token) -> io::Result<()> {
            self.deregistered.store(true, Ordering::SeqCst);
            self.deregister_count.fetch_add(1, Ordering::SeqCst);
            *self.last_token.lock() = Some(token);
            Ok(())
        }

        fn modify_interest(&self, token: Token, interest: Interest) -> io::Result<()> {
            *self.last_token.lock() = Some(token);
            *self.last_interest.lock() = Some(interest);
            Ok(())
        }
    }

    struct FlakyReactor {
        deregister_count: AtomicUsize,
    }

    impl FlakyReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                deregister_count: AtomicUsize::new(0),
            })
        }

        fn deregister_count(&self) -> usize {
            self.deregister_count.load(Ordering::SeqCst)
        }
    }

    impl ReactorHandle for FlakyReactor {
        fn deregister_by_token(&self, _token: Token) -> io::Result<()> {
            let call = self.deregister_count.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                Err(io::Error::other("injected failure"))
            } else {
                Ok(())
            }
        }

        fn modify_interest(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Ok(())
        }
    }

    struct AlwaysFailReactor {
        deregister_count: AtomicUsize,
    }

    impl AlwaysFailReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                deregister_count: AtomicUsize::new(0),
            })
        }

        fn deregister_count(&self) -> usize {
            self.deregister_count.load(Ordering::SeqCst)
        }
    }

    impl ReactorHandle for AlwaysFailReactor {
        fn deregister_by_token(&self, _token: Token) -> io::Result<()> {
            self.deregister_count.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("persistent failure"))
        }

        fn modify_interest(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Ok(())
        }
    }

    struct PanickingReactor {
        deregister_count: AtomicUsize,
    }

    impl PanickingReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                deregister_count: AtomicUsize::new(0),
            })
        }

        fn deregister_count(&self) -> usize {
            self.deregister_count.load(Ordering::SeqCst)
        }
    }

    impl ReactorHandle for PanickingReactor {
        fn deregister_by_token(&self, _token: Token) -> io::Result<()> {
            self.deregister_count.fetch_add(1, Ordering::SeqCst);
            panic!("injected deregister panic")
        }

        fn modify_interest(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Ok(())
        }
    }

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn drop_deregisters() {
        init_test("drop_deregisters");
        let reactor = TestReactor::new();
        let token = Token::new(42);

        {
            let _reg = Registration::new(
                token,
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            );
            let was = reactor.was_deregistered();
            crate::assert_with_log!(!was, "not deregistered in scope", false, was);
        }

        let was = reactor.was_deregistered();
        crate::assert_with_log!(was, "deregistered on drop", true, was);
        let last_token = *reactor.last_token.lock();
        crate::assert_with_log!(
            last_token == Some(token),
            "last token recorded",
            Some(token),
            last_token
        );
        crate::test_complete!("drop_deregisters");
    }

    #[test]
    fn set_interest_updates_reactor() {
        init_test("set_interest_updates_reactor");
        let reactor = TestReactor::new();
        let token = Token::new(1);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        crate::assert_with_log!(
            reg.interest() == Interest::READABLE,
            "initial interest",
            Interest::READABLE,
            reg.interest()
        );

        reg.set_interest(Interest::WRITABLE).unwrap();

        crate::assert_with_log!(
            reg.interest() == Interest::WRITABLE,
            "interest updated",
            Interest::WRITABLE,
            reg.interest()
        );
        let last_interest = *reactor.last_interest.lock();
        crate::assert_with_log!(
            last_interest == Some(Interest::WRITABLE),
            "reactor saw interest update",
            Some(Interest::WRITABLE),
            last_interest
        );
        crate::test_complete!("set_interest_updates_reactor");
    }

    #[test]
    fn handles_reactor_dropped() {
        init_test("handles_reactor_dropped");
        let token = Token::new(1);

        let reg = {
            let reactor = TestReactor::new();
            Registration::new(
                token,
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            )
            // reactor is dropped here
        };

        // Registration should not panic when reactor is gone
        let active = reg.is_active();
        crate::assert_with_log!(!active, "inactive after reactor drop", false, active);

        // set_interest should fail gracefully
        let result = reg.set_interest(Interest::WRITABLE);
        crate::assert_with_log!(result.is_err(), "set_interest fails", true, result.is_err());

        // drop should not panic
        drop(reg);
        crate::test_complete!("handles_reactor_dropped");
    }

    #[test]
    fn is_active() {
        init_test("is_active");
        let reactor = TestReactor::new();
        let token = Token::new(1);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let active = reg.is_active();
        crate::assert_with_log!(active, "active before drop", true, active);

        drop(reactor);

        let active_after = reg.is_active();
        crate::assert_with_log!(!active_after, "inactive after drop", false, active_after);
        crate::test_complete!("is_active");
    }

    #[test]
    fn explicit_deregister() {
        init_test("explicit_deregister");
        let reactor = TestReactor::new();
        let token = Token::new(1);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let result = reg.deregister();
        crate::assert_with_log!(result.is_ok(), "deregister ok", true, result.is_ok());
        let was = reactor.was_deregistered();
        crate::assert_with_log!(was, "reactor deregistered", true, was);
        let count = reactor.deregister_count();
        crate::assert_with_log!(count == 1, "deregister count", 1usize, count);
        // Note: reg is consumed, so drop won't run again
        crate::test_complete!("explicit_deregister");
    }

    #[test]
    fn explicit_deregister_when_reactor_gone() {
        init_test("explicit_deregister_when_reactor_gone");
        let token = Token::new(1);

        let reg = {
            let reactor = TestReactor::new();
            Registration::new(
                token,
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            )
        };

        // Should succeed even though reactor is gone
        let result = reg.deregister();
        crate::assert_with_log!(result.is_ok(), "deregister ok", true, result.is_ok());
        crate::test_complete!("explicit_deregister_when_reactor_gone");
    }

    #[test]
    fn explicit_deregister_transient_error_recovers_and_returns_ok() {
        init_test("explicit_deregister_transient_error_recovers_and_returns_ok");
        let reactor = FlakyReactor::new();
        let token = Token::new(7);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let result = reg.deregister();
        crate::assert_with_log!(
            result.is_ok(),
            "deregister succeeds after retry",
            true,
            result.is_ok()
        );
        let count = reactor.deregister_count();
        crate::assert_with_log!(count == 2, "best-effort cleanup attempted", 2usize, count);
        crate::test_complete!("explicit_deregister_transient_error_recovers_and_returns_ok");
    }

    #[test]
    fn explicit_deregister_persistent_error_returns_err_after_retry() {
        init_test("explicit_deregister_persistent_error_returns_err_after_retry");
        let reactor = AlwaysFailReactor::new();
        let token = Token::new(8);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let result = reg.deregister();
        crate::assert_with_log!(
            result.is_err(),
            "persistent failures surface an error",
            true,
            result.is_err()
        );
        let count = reactor.deregister_count();
        crate::assert_with_log!(count == 2, "retry attempted once", 2usize, count);
        crate::test_complete!("explicit_deregister_persistent_error_returns_err_after_retry");
    }

    #[test]
    fn drop_retries_after_transient_deregister_error() {
        init_test("drop_retries_after_transient_deregister_error");
        let reactor = FlakyReactor::new();
        let token = Token::new(11);

        {
            let _reg = Registration::new(
                token,
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            );
        }

        let count = reactor.deregister_count();
        crate::assert_with_log!(
            count == 2,
            "drop retries deregister once after transient error",
            2usize,
            count
        );
        crate::test_complete!("drop_retries_after_transient_deregister_error");
    }

    #[test]
    fn drop_swallows_panicking_reactor_deregister() {
        init_test("drop_swallows_panicking_reactor_deregister");
        let reactor = PanickingReactor::new();
        let token = Token::new(12);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(reg)));
        crate::assert_with_log!(
            dropped.is_ok(),
            "drop must not panic even if deregister panics",
            true,
            dropped.is_ok()
        );
        let count = reactor.deregister_count();
        crate::assert_with_log!(count == 1, "single deregister attempt", 1usize, count);
        crate::test_complete!("drop_swallows_panicking_reactor_deregister");
    }

    #[test]
    fn explicit_deregister_panicking_reactor_returns_error() {
        init_test("explicit_deregister_panicking_reactor_returns_error");
        let reactor = PanickingReactor::new();
        let token = Token::new(13);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let result = reg.deregister();
        crate::assert_with_log!(
            result.is_err(),
            "explicit deregister surfaces panic as error",
            true,
            result.is_err()
        );
        let kind = result
            .as_ref()
            .err()
            .map_or(io::ErrorKind::Other, io::Error::kind);
        crate::assert_with_log!(
            kind == io::ErrorKind::Other,
            "panic maps to io::ErrorKind::Other",
            io::ErrorKind::Other,
            kind
        );
        let count = reactor.deregister_count();
        crate::assert_with_log!(count == 1, "single deregister attempt", 1usize, count);
        crate::test_complete!("explicit_deregister_panicking_reactor_returns_error");
    }

    #[test]
    fn token_accessor() {
        init_test("token_accessor");
        let reactor = TestReactor::new();
        let token = Token::new(999);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        crate::assert_with_log!(reg.token() == token, "token accessor", token, reg.token());
        crate::test_complete!("token_accessor");
    }

    #[test]
    fn debug_impl() {
        init_test("debug_impl");
        let reactor = TestReactor::new();
        let token = Token::new(42);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let debug_text = format!("{reg:?}");
        crate::assert_with_log!(
            debug_text.contains("Registration"),
            "debug includes type",
            true,
            debug_text.contains("Registration")
        );
        crate::assert_with_log!(
            debug_text.contains("42"),
            "debug includes token",
            true,
            debug_text.contains("42")
        );
        crate::test_complete!("debug_impl");
    }

    #[test]
    fn multiple_registrations() {
        init_test("multiple_registrations");
        let reactor = TestReactor::new();

        {
            let _reg1 = Registration::new(
                Token::new(1),
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            );
            let _reg2 = Registration::new(
                Token::new(2),
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::WRITABLE,
            );

            let count = reactor.deregister_count();
            crate::assert_with_log!(count == 0, "no deregisters yet", 0usize, count);
        }

        // Both should have been deregistered
        let count = reactor.deregister_count();
        crate::assert_with_log!(count == 2, "two deregisters", 2usize, count);
        crate::test_complete!("multiple_registrations");
    }
}
