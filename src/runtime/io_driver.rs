//! I/O driver that bridges reactor events to task wakers.
//!
//! The [`IoDriver`] is the core component that connects the platform-specific
//! reactor (epoll/kqueue/IOCP) with the runtime's task scheduling system.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐    poll()    ┌─────────────┐
//! │   Reactor    │ ──────────▶  │  IoDriver   │
//! │(epoll/kqueue)│              │(waker slab) │
//! └──────────────┘              └──────┬──────┘
//!                                      │ wake tasks
//!                                      ▼
//!                               ┌─────────────┐
//!                               │  Scheduler  │
//!                               │(task queues)│
//!                               └─────────────┘
//! ```
//!
//! # Usage
//!
//! The runtime's main loop calls [`IoDriver::turn()`] to process I/O events:
//!
//! ```ignore
//! loop {
//!     // 1. Run ready tasks
//!     while let Some(task) = scheduler.pop_ready() {
//!         task.poll();
//!     }
//!
//!     // 2. Process timers
//!     timer_wheel.advance(now);
//!
//!     // 3. Wait for I/O (or next timer deadline)
//!     let timeout = timer_wheel.next_deadline().map(|d| d - now);
//!     io_driver.turn(timeout)?;
//! }
//! ```

use crate::runtime::reactor::{
    Event, Events, Interest, Reactor, SlabToken, Source, Token, TokenSlab,
};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, Weak};
use std::task::Waker;
use std::time::Duration;

/// Default capacity for the events buffer.
const DEFAULT_EVENTS_CAPACITY: usize = 1024;

/// Statistics for I/O driver diagnostics.
///
/// Tracks operation counts for monitoring and debugging.
#[derive(Debug, Clone, Default)]
pub struct IoStats {
    /// Number of times poll() was called.
    pub polls: u64,
    /// Total number of events received from the reactor.
    pub events_received: u64,
    /// Number of wakers successfully dispatched.
    pub wakers_dispatched: u64,
    /// Number of events with unknown tokens (missing waker).
    pub unknown_tokens: u64,
    /// Number of waker registrations.
    pub registrations: u64,
    /// Number of waker deregistrations.
    pub deregistrations: u64,
}

/// Driver for I/O event processing.
///
/// `IoDriver` owns the reactor and a token→waker mapping. It processes I/O
/// readiness events from the reactor and wakes the corresponding task wakers.
///
/// # Thread Safety
///
/// `IoDriver` is designed for single-threaded use within a runtime worker.
/// For cross-thread wakeup, use [`wake()`](Self::wake).
pub struct IoDriver {
    /// The platform-specific reactor.
    reactor: Arc<dyn Reactor>,
    /// Slab mapping tokens to wakers.
    wakers: TokenSlab,
    /// Interest sets for registered tokens.
    interests: HashMap<Token, Interest>,
    /// Pre-allocated events buffer to avoid allocation per turn.
    events: Events,
    /// Statistics for diagnostics.
    stats: IoStats,
}

impl IoDriver {
    /// Creates a new I/O driver with the given reactor.
    ///
    /// # Arguments
    ///
    /// * `reactor` - The platform reactor to use for I/O event notification
    #[must_use]
    pub fn new(reactor: Arc<dyn Reactor>) -> Self {
        Self {
            reactor,
            wakers: TokenSlab::new(),
            interests: HashMap::new(),
            events: Events::with_capacity(DEFAULT_EVENTS_CAPACITY),
            stats: IoStats::default(),
        }
    }

    /// Creates a new I/O driver with custom events buffer capacity.
    ///
    /// Use this when you need more or fewer events per poll cycle.
    #[must_use]
    pub fn with_capacity(reactor: Arc<dyn Reactor>, events_capacity: usize) -> Self {
        Self {
            reactor,
            wakers: TokenSlab::new(),
            interests: HashMap::new(),
            events: Events::with_capacity(events_capacity),
            stats: IoStats::default(),
        }
    }

    /// Returns a reference to the underlying reactor.
    #[must_use]
    pub fn reactor(&self) -> &Arc<dyn Reactor> {
        &self.reactor
    }

    /// Registers an I/O source with a waker.
    ///
    /// The waker will be called when the source becomes ready according to
    /// the specified interest flags.
    ///
    /// # Arguments
    ///
    /// * `source` - The I/O source to register
    /// * `interest` - Events to monitor (readable, writable, etc.)
    /// * `waker` - Waker to call when source is ready
    ///
    /// # Returns
    ///
    /// The token assigned to this registration. This token appears in events
    /// from the reactor and is used for deregistration.
    ///
    /// # Errors
    ///
    /// Returns an error if reactor registration fails.
    pub fn register(
        &mut self,
        source: &dyn Source,
        interest: Interest,
        waker: Waker,
    ) -> io::Result<Token> {
        // Allocate a slot in the waker slab
        let slab_token = self.wakers.insert(waker);
        let token = Token::new(slab_token.to_usize());

        // Register with the reactor
        match self.reactor.register(source, token, interest) {
            Ok(()) => {
                self.interests.insert(token, interest);
                self.stats.registrations += 1;
                Ok(token)
            }
            Err(e) => {
                // Remove waker on registration failure
                let _ = self.wakers.remove(slab_token);
                Err(e)
            }
        }
    }

    /// Registers a waker and returns a token.
    ///
    /// This is a lower-level method that only stores the waker without
    /// registering with the reactor. Use [`register()`](Self::register)
    /// for the full registration flow.
    pub fn register_waker(&mut self, waker: Waker) -> Token {
        let slab_token = self.wakers.insert(waker);
        self.stats.registrations += 1;
        Token::new(slab_token.to_usize())
    }

    /// Updates the waker for an existing registration.
    ///
    /// Call this when the task's waker has changed (e.g., between polls).
    ///
    /// # Returns
    ///
    /// `true` if the waker was updated, `false` if the token was not found.
    pub fn update_waker(&mut self, token: Token, waker: Waker) -> bool {
        let slab_token = SlabToken::from_usize(token.0);
        self.wakers.get_mut(slab_token).is_some_and(|slot| {
            *slot = waker;
            true
        })
    }

    /// Modifies the interest set for an existing registration.
    ///
    /// This forwards to the underlying reactor and does not touch waker state.
    pub fn modify_interest(&mut self, token: Token, interest: Interest) -> io::Result<()> {
        self.reactor.modify(token, interest)?;
        self.interests.insert(token, interest);
        Ok(())
    }

    /// Deregisters an I/O source.
    ///
    /// Removes the source from the reactor and frees the waker slot.
    ///
    /// # Errors
    ///
    /// Returns an error if reactor deregistration fails. A
    /// `NotFound` error is treated as already deregistered and the
    /// local waker state is still cleaned up.
    pub fn deregister(&mut self, token: Token) -> io::Result<()> {
        // Deregister from reactor first, but treat "not found" as already removed.
        match self.reactor.deregister(token) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }

        // Remove waker from slab
        let slab_token = SlabToken::from_usize(token.0);
        if self.wakers.remove(slab_token).is_some() {
            self.stats.deregistrations += 1;
        }
        self.interests.remove(&token);

        Ok(())
    }

    /// Deregisters a waker by its key.
    ///
    /// This is a lower-level method that only removes the waker without
    /// deregistering from the reactor.
    pub fn deregister_waker(&mut self, token: Token) {
        let slab_token = SlabToken::from_usize(token.0);
        if self.wakers.remove(slab_token).is_some() {
            self.stats.deregistrations += 1;
        }
    }

    /// Processes pending I/O events, waking relevant tasks.
    ///
    /// This is the main driver method, called by the runtime's event loop.
    /// It polls the reactor for ready events and dispatches wakers for each.
    ///
    /// # Arguments
    ///
    /// * `timeout` - How long to wait for events:
    ///   - `None`: Block indefinitely
    ///   - `Some(Duration::ZERO)`: Non-blocking poll
    ///   - `Some(d)`: Block up to `d`
    ///
    /// # Returns
    ///
    /// The number of events received from the reactor.
    ///
    /// # Errors
    ///
    /// Returns an error if the reactor poll fails.
    pub fn turn(&mut self, timeout: Option<Duration>) -> io::Result<usize> {
        self.turn_with(timeout, |_, _| {})
    }

    /// Processes pending I/O events, invoking a callback per event.
    ///
    /// This is useful for recording traces or metrics alongside normal
    /// waker dispatch. The callback is invoked before waking the task.
    pub fn turn_with<F>(&mut self, timeout: Option<Duration>, mut on_event: F) -> io::Result<usize>
    where
        F: FnMut(&Event, Option<Interest>),
    {
        // Clear previous events
        self.events.clear();

        // Poll the reactor
        let n = self.reactor.poll(&mut self.events, timeout)?;
        self.stats.polls += 1;
        self.stats.events_received += n as u64;

        // Dispatch wakers for ready events
        for event in &self.events {
            let interest = self.interests.get(&event.token).copied();
            on_event(event, interest);
            let slab_token = SlabToken::from_usize(event.token.0);
            if let Some(waker) = self.wakers.get(slab_token) {
                waker.wake_by_ref();
                self.stats.wakers_dispatched += 1;
            } else {
                self.stats.unknown_tokens += 1;
            }
        }

        Ok(n)
    }

    /// Wakes the driver from a blocking poll.
    ///
    /// This is safe to call from any thread. Use it when:
    /// - New tasks are spawned
    /// - Timers fire
    /// - The runtime is shutting down
    ///
    /// # Errors
    ///
    /// Returns an error if the reactor wake fails.
    pub fn wake(&self) -> io::Result<()> {
        self.reactor.wake()
    }

    /// Returns current statistics.
    #[must_use]
    pub fn stats(&self) -> &IoStats {
        &self.stats
    }

    /// Returns the number of registered wakers.
    #[must_use]
    pub fn waker_count(&self) -> usize {
        self.wakers.len()
    }

    /// Returns `true` if no wakers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.wakers.is_empty()
    }
}

/// Shared handle to an [`IoDriver`].
///
/// This wrapper provides interior mutability for registering and updating
/// wakers from async I/O types while keeping the driver single-threaded.
#[derive(Debug, Clone)]
pub struct IoDriverHandle {
    inner: Arc<Mutex<IoDriver>>,
}

impl IoDriverHandle {
    /// Creates a new handle with the default events buffer capacity.
    #[must_use]
    pub fn new(reactor: Arc<dyn Reactor>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(IoDriver::new(reactor))),
        }
    }

    /// Creates a new handle with a custom events buffer capacity.
    #[must_use]
    pub fn with_capacity(reactor: Arc<dyn Reactor>, events_capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(IoDriver::with_capacity(
                reactor,
                events_capacity,
            ))),
        }
    }

    /// Registers a source with the reactor and associates the waker.
    pub fn register(
        &self,
        source: &dyn Source,
        interest: Interest,
        waker: Waker,
    ) -> io::Result<IoRegistration> {
        let token = {
            let mut driver = self.inner.lock().expect("lock poisoned");
            driver.register(source, interest, waker)?
        };
        Ok(IoRegistration::new(
            token,
            Arc::downgrade(&self.inner),
            interest,
        ))
    }

    /// Updates the waker for an existing registration.
    #[must_use]
    pub fn update_waker(&self, token: Token, waker: Waker) -> bool {
        let mut driver = self.inner.lock().expect("lock poisoned");
        driver.update_waker(token, waker)
    }

    /// Returns true if the driver has no registered wakers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let driver = self.inner.lock().expect("lock poisoned");
        driver.is_empty()
    }

    /// Returns the number of registered wakers.
    #[must_use]
    pub fn waker_count(&self) -> usize {
        let driver = self.inner.lock().expect("lock poisoned");
        driver.waker_count()
    }

    /// Returns a snapshot of the current I/O stats.
    #[must_use]
    pub fn stats(&self) -> IoStats {
        let driver = self.inner.lock().expect("lock poisoned");
        driver.stats().clone()
    }

    /// Processes pending I/O events with a per-event callback.
    pub fn turn_with<F>(&self, timeout: Option<Duration>, on_event: F) -> io::Result<usize>
    where
        F: FnMut(&Event, Option<Interest>),
    {
        let mut driver = self.inner.lock().expect("lock poisoned");
        driver.turn_with(timeout, on_event)
    }

    /// Returns a lock guard for direct access to the driver.
    pub fn lock(&self) -> std::sync::MutexGuard<'_, IoDriver> {
        self.inner.lock().expect("lock poisoned")
    }

    /// Attempts to acquire the lock for direct access to the driver.
    pub fn try_lock(&self) -> std::sync::TryLockResult<std::sync::MutexGuard<'_, IoDriver>> {
        self.inner.try_lock()
    }
}

/// RAII handle for a registered I/O source.
///
/// Dropping this handle will automatically deregister the source and
/// remove its waker from the driver.
#[derive(Debug)]
pub struct IoRegistration {
    token: Token,
    interest: Interest,
    driver: Weak<Mutex<IoDriver>>,
}

impl IoRegistration {
    fn new(token: Token, driver: Weak<Mutex<IoDriver>>, interest: Interest) -> Self {
        Self {
            token,
            interest,
            driver,
        }
    }

    /// Returns the registration token.
    #[must_use]
    pub fn token(&self) -> Token {
        self.token
    }

    /// Returns the current interest set.
    #[must_use]
    pub fn interest(&self) -> Interest {
        self.interest
    }

    /// Returns true if the driver is still alive.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.driver.strong_count() > 0
    }

    /// Updates the interest set for this registration.
    pub fn set_interest(&mut self, interest: Interest) -> io::Result<()> {
        let Some(driver) = self.driver.upgrade() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "I/O driver has been dropped",
            ));
        };
        {
            let mut guard = driver.lock().expect("lock poisoned");
            guard.modify_interest(self.token, interest)?;
        }
        self.interest = interest;
        Ok(())
    }

    /// Updates the waker for this registration.
    #[must_use]
    pub fn update_waker(&self, waker: Waker) -> bool {
        self.driver.upgrade().is_some_and(|driver| {
            let mut guard = driver.lock().expect("lock poisoned");
            guard.update_waker(self.token, waker)
        })
    }

    /// Explicitly deregisters without waiting for drop.
    pub fn deregister(self) -> io::Result<()> {
        if let Some(driver) = self.driver.upgrade() {
            let result = {
                let mut guard = driver.lock().expect("lock poisoned");
                guard.deregister(self.token)
            };
            match result {
                Ok(()) => {
                    std::mem::forget(self);
                    Ok(())
                }
                Err(err) => Err(err),
            }
        } else {
            std::mem::forget(self);
            Ok(())
        }
    }
}

impl Drop for IoRegistration {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.upgrade() {
            let mut guard = driver.lock().expect("lock poisoned");
            let _ = guard.deregister(self.token);
        }
    }
}

impl std::fmt::Debug for IoDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoDriver")
            .field("waker_count", &self.wakers.len())
            .field("events_capacity", &self.events.capacity())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::runtime::reactor::{Event, Interest, LabReactor, Token};
    use crate::test_utils::init_test_logging;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::Wake;

    /// A simple waker that sets a flag and counts wakes.
    struct FlagWaker {
        flag: AtomicBool,
        count: AtomicUsize,
    }

    impl Wake for FlagWaker {
        fn wake(self: Arc<Self>) {
            self.flag.store(true, Ordering::SeqCst);
            self.count.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.flag.store(true, Ordering::SeqCst);
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Creates a simple waker that sets a flag when woken.
    fn create_test_waker() -> (Waker, Arc<FlagWaker>) {
        let waker_state = Arc::new(FlagWaker {
            flag: AtomicBool::new(false),
            count: AtomicUsize::new(0),
        });
        let waker = Waker::from(waker_state.clone());
        (waker, waker_state)
    }

    struct TestFdSource;
    impl std::os::fd::AsRawFd for TestFdSource {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            0
        }
    }

    struct NotFoundReactor;

    impl Reactor for NotFoundReactor {
        fn register(&self, _source: &dyn Source, _token: Token, _interest: Interest) -> io::Result<()> {
            Ok(())
        }

        fn modify(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Ok(())
        }

        fn deregister(&self, _token: Token) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::NotFound, "not registered"))
        }

        fn poll(&self, _events: &mut Events, _timeout: Option<Duration>) -> io::Result<usize> {
            Ok(0)
        }

        fn wake(&self) -> io::Result<()> {
            Ok(())
        }

        fn registration_count(&self) -> usize {
            0
        }
    }

    struct FlakyReactor {
        deregister_calls: AtomicUsize,
    }

    impl FlakyReactor {
        fn new() -> Self {
            Self {
                deregister_calls: AtomicUsize::new(0),
            }
        }

        fn deregister_calls(&self) -> usize {
            self.deregister_calls.load(Ordering::SeqCst)
        }
    }

    impl Reactor for FlakyReactor {
        fn register(&self, _source: &dyn Source, _token: Token, _interest: Interest) -> io::Result<()> {
            Ok(())
        }

        fn modify(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Ok(())
        }

        fn deregister(&self, _token: Token) -> io::Result<()> {
            let call = self.deregister_calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                Err(io::Error::new(io::ErrorKind::Other, "injected failure"))
            } else {
                Ok(())
            }
        }

        fn poll(&self, _events: &mut Events, _timeout: Option<Duration>) -> io::Result<usize> {
            Ok(0)
        }

        fn wake(&self) -> io::Result<()> {
            Ok(())
        }

        fn registration_count(&self) -> usize {
            0
        }
    }

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn io_driver_new() {
        init_test("io_driver_new");
        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriver::new(reactor);

        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::assert_with_log!(
            driver.waker_count() == 0,
            "waker count",
            0usize,
            driver.waker_count()
        );
        crate::assert_with_log!(
            driver.stats().polls == 0,
            "polls",
            0usize,
            driver.stats().polls
        );
        crate::test_complete!("io_driver_new");
    }

    #[test]
    fn io_driver_with_capacity() {
        init_test("io_driver_with_capacity");
        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriver::with_capacity(reactor, 256);

        crate::assert_with_log!(
            driver.events.capacity() == 256,
            "events capacity",
            256usize,
            driver.events.capacity()
        );
        crate::test_complete!("io_driver_with_capacity");
    }

    #[test]
    fn io_driver_register_full_flow() {
        init_test("io_driver_register_full_flow");
        let reactor = Arc::new(LabReactor::new());
        let mut driver = IoDriver::new(reactor);
        let source = TestFdSource;

        let (waker, _) = create_test_waker();
        let token = driver
            .register(&source, Interest::READABLE, waker)
            .expect("register should succeed");

        crate::assert_with_log!(
            driver.waker_count() == 1,
            "waker count",
            1usize,
            driver.waker_count()
        );
        crate::assert_with_log!(
            !driver.is_empty(),
            "driver not empty",
            false,
            driver.is_empty()
        );
        crate::assert_with_log!(
            driver.stats().registrations == 1,
            "registrations",
            1usize,
            driver.stats().registrations
        );

        // Token should be 0 (first slab entry)
        crate::assert_with_log!(token.0 == 0, "token id", 0usize, token.0);
        crate::test_complete!("io_driver_register_full_flow");
    }

    #[test]
    fn io_driver_deregister() {
        init_test("io_driver_deregister");
        let reactor = Arc::new(LabReactor::new());
        let mut driver = IoDriver::new(reactor);
        let source = TestFdSource;

        let (waker, _) = create_test_waker();
        let token = driver
            .register(&source, Interest::READABLE, waker)
            .expect("register should succeed");

        crate::assert_with_log!(
            driver.waker_count() == 1,
            "waker count",
            1usize,
            driver.waker_count()
        );

        driver.deregister(token).expect("deregister should succeed");

        crate::assert_with_log!(
            driver.waker_count() == 0,
            "waker count",
            0usize,
            driver.waker_count()
        );
        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::assert_with_log!(
            driver.stats().deregistrations == 1,
            "deregistrations",
            1usize,
            driver.stats().deregistrations
        );
        crate::test_complete!("io_driver_deregister");
    }

    #[test]
    fn io_driver_deregister_not_found_cleans_waker() {
        init_test("io_driver_deregister_not_found_cleans_waker");
        let reactor = Arc::new(NotFoundReactor);
        let mut driver = IoDriver::new(reactor);

        let (waker, _) = create_test_waker();
        let token = driver.register_waker(waker);

        crate::assert_with_log!(
            driver.waker_count() == 1,
            "waker count",
            1usize,
            driver.waker_count()
        );

        let result = driver.deregister(token);
        crate::assert_with_log!(result.is_ok(), "deregister ok", true, result.is_ok());

        crate::assert_with_log!(
            driver.waker_count() == 0,
            "waker count",
            0usize,
            driver.waker_count()
        );
        crate::assert_with_log!(
            driver.stats().deregistrations == 1,
            "deregistrations",
            1usize,
            driver.stats().deregistrations
        );
        crate::test_complete!("io_driver_deregister_not_found_cleans_waker");
    }

    #[test]
    fn io_driver_update_waker() {
        init_test("io_driver_update_waker");
        let reactor = Arc::new(LabReactor::new());
        let mut driver = IoDriver::new(reactor);

        let (waker1, _) = create_test_waker();
        let (waker2, _) = create_test_waker();

        let token = driver.register_waker(waker1);

        // Update should succeed for existing token
        let updated = driver.update_waker(token, waker2.clone());
        crate::assert_with_log!(updated, "update succeeds", true, updated);

        // Update should fail for non-existent token
        let updated_missing = driver.update_waker(Token::new(999), waker2);
        crate::assert_with_log!(
            !updated_missing,
            "update missing fails",
            false,
            updated_missing
        );
        crate::test_complete!("io_driver_update_waker");
    }

    #[test]
    fn io_registration_deregister_error_allows_drop_retry() {
        init_test("io_registration_deregister_error_allows_drop_retry");
        let reactor = Arc::new(FlakyReactor::new());
        let reactor_handle: Arc<dyn Reactor> = reactor.clone();
        let driver = IoDriverHandle::new(reactor_handle);
        let source = TestFdSource;

        let (waker, _) = create_test_waker();
        let reg = driver
            .register(&source, Interest::READABLE, waker)
            .expect("register should succeed");

        let result = reg.deregister();
        crate::assert_with_log!(result.is_err(), "deregister fails", true, result.is_err());

        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        let calls = reactor.deregister_calls();
        crate::assert_with_log!(calls == 2, "deregister retried", 2usize, calls);
        crate::test_complete!("io_registration_deregister_error_allows_drop_retry");
    }

    #[test]
    fn io_driver_turn_dispatches_wakers() {
        init_test("io_driver_turn_dispatches_wakers");
        let reactor = Arc::new(LabReactor::new());
        let source = TestFdSource;

        // Register waker first to get the token
        let (waker, waker_state) = create_test_waker();
        let mut driver = IoDriver::new(reactor.clone());
        let token = driver.register_waker(waker);

        // Now register the source with the reactor using the same token
        reactor
            .register(&source, token, Interest::READABLE)
            .expect("register should succeed");

        // Inject an event for our token
        reactor.inject_event(token, Event::readable(token), Duration::ZERO);

        // Waker should not be woken yet
        let initial = waker_state.flag.load(Ordering::SeqCst);
        crate::assert_with_log!(!initial, "waker not yet woken", false, initial);

        // Turn should dispatch the waker
        let count = driver
            .turn(Some(Duration::from_millis(10)))
            .expect("turn should succeed");

        crate::assert_with_log!(count == 1, "event count", 1usize, count);
        let flag = waker_state.flag.load(Ordering::SeqCst);
        crate::assert_with_log!(flag, "waker fired", true, flag);
        let wake_count = waker_state.count.load(Ordering::SeqCst);
        crate::assert_with_log!(wake_count == 1, "wake count", 1usize, wake_count);

        // Check stats
        crate::assert_with_log!(
            driver.stats().polls == 1,
            "polls",
            1usize,
            driver.stats().polls
        );
        crate::assert_with_log!(
            driver.stats().events_received == 1,
            "events received",
            1usize,
            driver.stats().events_received
        );
        crate::assert_with_log!(
            driver.stats().wakers_dispatched == 1,
            "wakers dispatched",
            1usize,
            driver.stats().wakers_dispatched
        );
        crate::assert_with_log!(
            driver.stats().unknown_tokens == 0,
            "unknown tokens",
            0usize,
            driver.stats().unknown_tokens
        );
        crate::test_complete!("io_driver_turn_dispatches_wakers");
    }

    #[test]
    fn io_driver_turn_handles_unknown_tokens() {
        init_test("io_driver_turn_handles_unknown_tokens");
        let reactor = Arc::new(LabReactor::new());
        let source = TestFdSource;

        // Register source directly with reactor (no waker in driver)
        let token = Token::new(999);
        reactor
            .register(&source, token, Interest::READABLE)
            .expect("register should succeed");

        // Inject event for the token
        reactor.inject_event(token, Event::readable(token), Duration::ZERO);

        let mut driver = IoDriver::new(reactor);

        // Turn should handle the unknown token gracefully
        let count = driver
            .turn(Some(Duration::from_millis(10)))
            .expect("turn should succeed");

        crate::assert_with_log!(count == 1, "event count", 1usize, count);
        crate::assert_with_log!(
            driver.stats().events_received == 1,
            "events received",
            1usize,
            driver.stats().events_received
        );
        crate::assert_with_log!(
            driver.stats().wakers_dispatched == 0,
            "wakers dispatched",
            0usize,
            driver.stats().wakers_dispatched
        );
        crate::assert_with_log!(
            driver.stats().unknown_tokens == 1,
            "unknown tokens",
            1usize,
            driver.stats().unknown_tokens
        );
        crate::test_complete!("io_driver_turn_handles_unknown_tokens");
    }

    #[test]
    fn io_driver_stale_token_does_not_wake_new_waker() {
        init_test("io_driver_stale_token_does_not_wake_new_waker");
        let reactor = Arc::new(LabReactor::new());
        let source = TestFdSource;
        let mut driver = IoDriver::new(reactor.clone());

        let (waker1, _) = create_test_waker();
        let token1 = driver.register_waker(waker1);
        driver.deregister_waker(token1);

        let (waker2, state2) = create_test_waker();
        let token2 = driver.register_waker(waker2);

        crate::assert_with_log!(token1 != token2, "token rotates", true, token1 != token2);

        reactor
            .register(&source, token1, Interest::READABLE)
            .expect("register should succeed");
        reactor.inject_event(token1, Event::readable(token1), Duration::ZERO);

        let count = driver
            .turn(Some(Duration::from_millis(10)))
            .expect("turn should succeed");

        crate::assert_with_log!(count == 1, "event count", 1usize, count);
        let flag2 = state2.flag.load(Ordering::SeqCst);
        crate::assert_with_log!(!flag2, "new waker not fired", false, flag2);
        crate::assert_with_log!(
            driver.stats().unknown_tokens == 1,
            "unknown tokens",
            1usize,
            driver.stats().unknown_tokens
        );
        crate::test_complete!("io_driver_stale_token_does_not_wake_new_waker");
    }

    #[test]
    fn io_driver_wake() {
        init_test("io_driver_wake");
        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriver::new(reactor.clone());

        // Wake should succeed
        driver.wake().expect("wake should succeed");

        // Verify the reactor was woken
        let woke = reactor.check_and_clear_wake();
        crate::assert_with_log!(woke, "reactor woke", true, woke);
        crate::test_complete!("io_driver_wake");
    }

    #[test]
    fn io_driver_multiple_wakers() {
        init_test("io_driver_multiple_wakers");
        let reactor = Arc::new(LabReactor::new());
        let source = TestFdSource;
        let mut driver = IoDriver::new(reactor.clone());

        // Register multiple wakers
        let (waker1, state1) = create_test_waker();
        let (waker2, state2) = create_test_waker();
        let (waker3, state3) = create_test_waker();

        let token1 = driver.register_waker(waker1);
        let token2 = driver.register_waker(waker2);
        let token3 = driver.register_waker(waker3);

        crate::assert_with_log!(
            driver.waker_count() == 3,
            "waker count",
            3usize,
            driver.waker_count()
        );

        // Register sources with reactor
        reactor
            .register(&source, token1, Interest::READABLE)
            .unwrap();
        reactor
            .register(&source, token2, Interest::READABLE)
            .unwrap();
        reactor
            .register(&source, token3, Interest::READABLE)
            .unwrap();

        // Inject events for tokens 1 and 3 only
        reactor.inject_event(token1, Event::readable(token1), Duration::ZERO);
        reactor.inject_event(token3, Event::readable(token3), Duration::ZERO);

        // Turn should dispatch wakers 1 and 3
        let count = driver
            .turn(Some(Duration::from_millis(10)))
            .expect("turn should succeed");

        crate::assert_with_log!(count == 2, "event count", 2usize, count);
        let flag1 = state1.flag.load(Ordering::SeqCst);
        let flag2 = state2.flag.load(Ordering::SeqCst);
        let flag3 = state3.flag.load(Ordering::SeqCst);
        crate::assert_with_log!(flag1, "waker1 fired", true, flag1);
        crate::assert_with_log!(!flag2, "waker2 not fired", false, flag2);
        crate::assert_with_log!(flag3, "waker3 fired", true, flag3);

        crate::assert_with_log!(
            driver.stats().wakers_dispatched == 2,
            "wakers dispatched",
            2usize,
            driver.stats().wakers_dispatched
        );
        crate::test_complete!("io_driver_multiple_wakers");
    }

    #[test]
    fn io_driver_debug() {
        init_test("io_driver_debug");
        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriver::new(reactor);

        let debug_text = format!("{driver:?}");
        crate::assert_with_log!(
            debug_text.contains("IoDriver"),
            "debug contains type",
            true,
            debug_text.contains("IoDriver")
        );
        crate::assert_with_log!(
            debug_text.contains("waker_count"),
            "debug contains waker_count",
            true,
            debug_text.contains("waker_count")
        );
        crate::test_complete!("io_driver_debug");
    }

    #[test]
    fn io_stats_default() {
        init_test("io_stats_default");
        let stats = IoStats::default();
        crate::assert_with_log!(stats.polls == 0, "polls", 0usize, stats.polls);
        crate::assert_with_log!(
            stats.events_received == 0,
            "events received",
            0usize,
            stats.events_received
        );
        crate::assert_with_log!(
            stats.wakers_dispatched == 0,
            "wakers dispatched",
            0usize,
            stats.wakers_dispatched
        );
        crate::assert_with_log!(
            stats.unknown_tokens == 0,
            "unknown tokens",
            0usize,
            stats.unknown_tokens
        );
        crate::assert_with_log!(
            stats.registrations == 0,
            "registrations",
            0usize,
            stats.registrations
        );
        crate::assert_with_log!(
            stats.deregistrations == 0,
            "deregistrations",
            0usize,
            stats.deregistrations
        );
        crate::test_complete!("io_stats_default");
    }

    /// Integration test verifying IoDriver works with EpollReactor for real I/O.
    #[cfg(target_os = "linux")]
    mod epoll_integration {
        use super::*;
        use crate::runtime::reactor::EpollReactor;
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        #[test]
        fn io_driver_with_epoll_reactor_dispatches_waker() {
            super::init_test("io_driver_with_epoll_reactor_dispatches_waker");
            let reactor = Arc::new(EpollReactor::new().expect("create reactor"));
            let mut driver = IoDriver::new(reactor);

            // Create a unix socket pair
            let (sock_read, mut sock_write) = UnixStream::pair().expect("create socket pair");

            // Register with IoDriver (full flow)
            let (waker, waker_state) = create_test_waker();
            let token = driver
                .register(&sock_read, Interest::READABLE, waker)
                .expect("register should succeed");

            // Waker should not be woken yet
            let initial = waker_state.flag.load(Ordering::SeqCst);
            crate::assert_with_log!(!initial, "waker not yet woken", false, initial);

            // Write data to make sock_read readable
            sock_write.write_all(b"hello").expect("write failed");

            // Turn should poll epoll and dispatch waker
            let count = driver
                .turn(Some(Duration::from_millis(100)))
                .expect("turn should succeed");

            // Should have received the readable event and woken the waker
            crate::assert_with_log!(count >= 1, "event count", true, count >= 1);
            let flag = waker_state.flag.load(Ordering::SeqCst);
            crate::assert_with_log!(flag, "waker fired", true, flag);
            let wake_count = waker_state.count.load(Ordering::SeqCst);
            crate::assert_with_log!(wake_count == 1, "wake count", 1usize, wake_count);

            // Cleanup
            driver.deregister(token).expect("deregister should succeed");
            crate::test_complete!("io_driver_with_epoll_reactor_dispatches_waker");
        }

        #[test]
        fn io_driver_with_epoll_reactor_writable() {
            super::init_test("io_driver_with_epoll_reactor_writable");
            let reactor = Arc::new(EpollReactor::new().expect("create reactor"));
            let mut driver = IoDriver::new(reactor);

            // Create a unix socket pair
            let (sock1, _sock2) = UnixStream::pair().expect("create socket pair");

            // Register for writable
            let (waker, waker_state) = create_test_waker();
            let token = driver
                .register(&sock1, Interest::WRITABLE, waker)
                .expect("register should succeed");

            // Turn should immediately see writable event
            let count = driver
                .turn(Some(Duration::from_millis(100)))
                .expect("turn should succeed");

            crate::assert_with_log!(count >= 1, "event count", true, count >= 1);
            let flag = waker_state.flag.load(Ordering::SeqCst);
            crate::assert_with_log!(flag, "waker fired", true, flag);

            driver.deregister(token).expect("deregister should succeed");
            crate::test_complete!("io_driver_with_epoll_reactor_writable");
        }
    }
}
