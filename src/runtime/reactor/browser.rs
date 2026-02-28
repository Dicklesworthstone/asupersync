//! Browser reactor stub for wasm32 targets.
//!
//! This module provides a [`BrowserReactor`] that implements the [`Reactor`]
//! trait for browser environments. In production browser builds, the reactor
//! bridges browser event sources (fetch completions, WebSocket events,
//! microtask queue) to the runtime's event notification system.
//!
//! # Current Status
//!
//! This is a **scaffold implementation** (asupersync-umelq.4.4). Registration
//! bookkeeping and token semantics are implemented, while browser host event
//! integration (`queueMicrotask`, fetch/WebSocket wiring) remains stubbed.
//! The actual wasm-bindgen bridge will be added by subsequent beads once the
//! ABI contract (umelq.8.x) is finalized.
//!
//! # Browser Event Model
//!
//! Unlike native epoll/kqueue/IOCP, the browser has no blocking poll.
//! Instead, the browser reactor integrates with the browser event loop:
//!
//! - **Registrations**: Map to browser event listeners (fetch, WebSocket,
//!   MessagePort, etc.)
//! - **Poll**: Returns immediately with any pending events from the
//!   microtask/macrotask queue (non-blocking only)
//! - **Wake**: Schedules a microtask via `queueMicrotask()` or
//!   `Promise.resolve().then()`
//!
//! # Invariants Preserved
//!
//! - Token-based registration/deregistration model unchanged
//! - Interest flags (readable/writable) still apply to browser streams
//! - Event batching preserved for efficiency
//! - Thread safety: wasm32 is single-threaded but `Send + Sync` bounds
//!   satisfied for API compatibility

use super::{Events, Interest, Reactor, Source, Token};
use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

/// Browser reactor configuration.
#[derive(Debug, Clone)]
pub struct BrowserReactorConfig {
    /// Maximum events returned per poll call.
    pub max_events_per_poll: usize,
    /// Whether to coalesce rapid wake signals.
    pub coalesce_wakes: bool,
}

impl Default for BrowserReactorConfig {
    fn default() -> Self {
        Self {
            max_events_per_poll: 64,
            coalesce_wakes: true,
        }
    }
}

/// Browser-based reactor for wasm32 targets.
///
/// Stub implementation providing the [`Reactor`] trait contract for browser
/// environments. Methods return appropriate stub responses (empty polls,
/// no-op registrations) until wasm-bindgen integration is completed.
///
/// # Usage
///
/// ```ignore
/// use asupersync::runtime::reactor::browser::BrowserReactor;
///
/// let reactor = BrowserReactor::new(Default::default());
/// // Wire into RuntimeBuilder::with_reactor(Arc::new(reactor))
/// ```
#[derive(Debug)]
pub struct BrowserReactor {
    config: BrowserReactorConfig,
    registrations: Mutex<BTreeMap<Token, Interest>>,
    wake_pending: AtomicBool,
}

impl BrowserReactor {
    /// Creates a new browser reactor with the given configuration.
    #[must_use]
    pub fn new(config: BrowserReactorConfig) -> Self {
        Self {
            config,
            registrations: Mutex::new(BTreeMap::new()),
            wake_pending: AtomicBool::new(false),
        }
    }

    fn registrations_mut(&self) -> io::Result<MutexGuard<'_, BTreeMap<Token, Interest>>> {
        self.registrations
            .lock()
            .map_err(|_| io::Error::other("browser reactor registry lock poisoned"))
    }
}

impl Default for BrowserReactor {
    fn default() -> Self {
        Self::new(BrowserReactorConfig::default())
    }
}

impl Reactor for BrowserReactor {
    fn register(&self, _source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        // TODO(umelq.7.x): Wire to browser event listener registration.
        // Current scaffold keeps deterministic token bookkeeping so runtime
        // semantics match native backends even before wasm host bindings land.
        let mut registrations = self.registrations_mut()?;
        if registrations.contains_key(&token) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("token {token:?} already registered"),
            ));
        }
        registrations.insert(token, interest);
        drop(registrations);
        Ok(())
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        // TODO(umelq.7.x): Update browser event listener interest.
        let mut registrations = self.registrations_mut()?;
        let slot = registrations.get_mut(&token).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("token {token:?} not registered"),
            )
        })?;
        *slot = interest;
        drop(registrations);
        Ok(())
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        // TODO(umelq.7.x): Remove browser event listener.
        let removed = self.registrations_mut()?.remove(&token);
        if removed.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("token {token:?} not registered"),
            ));
        }
        Ok(())
    }

    fn poll(&self, _events: &mut Events, _timeout: Option<Duration>) -> io::Result<usize> {
        // TODO(umelq.5.x): Drain pending browser events from microtask queue.
        //
        // Browser poll semantics differ from native:
        // - Never blocks (timeout is advisory only)
        // - Returns events from completed fetch/WS/timer callbacks
        // - Must yield back to browser event loop promptly
        //
        // For now, return 0 events (no I/O ready).
        self.wake_pending.store(false, Ordering::Release);
        Ok(0)
    }

    fn wake(&self) -> io::Result<()> {
        // TODO(umelq.5.x): Schedule microtask via queueMicrotask() or
        // Promise.resolve().then() to trigger re-poll.
        //
        // Coalescing: multiple wake() calls before the next poll produce
        // only one microtask dispatch.
        if self.config.coalesce_wakes {
            self.wake_pending.store(true, Ordering::Release);
        }
        Ok(())
    }

    fn registration_count(&self) -> usize {
        self.registrations
            .lock()
            .map_or(0, |registrations| registrations.len())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Fake source for testing (browser reactor ignores the source entirely).
    struct TestFdSource;
    impl std::os::fd::AsRawFd for TestFdSource {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            0
        }
    }

    #[test]
    fn browser_reactor_starts_empty() {
        let reactor = BrowserReactor::default();
        assert_eq!(reactor.registration_count(), 0);
        assert!(reactor.is_empty());
    }

    #[test]
    fn browser_reactor_poll_returns_zero_events() {
        let reactor = BrowserReactor::default();
        let mut events = Events::with_capacity(64);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 0, "stub poll returns no events");
    }

    #[test]
    fn browser_reactor_wake_is_noop() {
        let reactor = BrowserReactor::default();
        assert!(reactor.wake().is_ok());
    }

    #[test]
    fn browser_reactor_register_deregister_tracks_count() {
        let reactor = BrowserReactor::default();
        let source = TestFdSource;
        let token = Token::new(1);

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();
        assert_eq!(reactor.registration_count(), 1);

        reactor.deregister(token).unwrap();
        assert_eq!(reactor.registration_count(), 0);
    }

    #[test]
    fn browser_reactor_modify_is_noop() {
        let reactor = BrowserReactor::default();
        let source = TestFdSource;
        let token = Token::new(1);
        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();
        assert!(reactor.modify(token, Interest::WRITABLE).is_ok());
    }

    #[test]
    fn browser_reactor_config_defaults() {
        let config = BrowserReactorConfig::default();
        assert_eq!(config.max_events_per_poll, 64);
        assert!(config.coalesce_wakes);
    }

    #[test]
    fn browser_reactor_deregister_unknown_returns_not_found() {
        let reactor = BrowserReactor::default();
        let err = reactor.deregister(Token::new(99)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert_eq!(reactor.registration_count(), 0);
    }

    #[test]
    fn browser_reactor_wake_coalesce_flag() {
        let reactor = BrowserReactor::default();
        assert!(
            !reactor
                .wake_pending
                .load(std::sync::atomic::Ordering::Acquire)
        );
        reactor.wake().unwrap();
        assert!(
            reactor
                .wake_pending
                .load(std::sync::atomic::Ordering::Acquire)
        );
        // Poll clears the flag
        let mut events = Events::with_capacity(4);
        reactor.poll(&mut events, None).unwrap();
        assert!(
            !reactor
                .wake_pending
                .load(std::sync::atomic::Ordering::Acquire)
        );
    }

    #[test]
    fn browser_reactor_multiple_register() {
        let reactor = BrowserReactor::default();
        let source = TestFdSource;

        reactor
            .register(&source, Token::new(1), Interest::READABLE)
            .unwrap();
        reactor
            .register(&source, Token::new(2), Interest::WRITABLE)
            .unwrap();
        reactor
            .register(&source, Token::new(3), Interest::READABLE)
            .unwrap();
        assert_eq!(reactor.registration_count(), 3);

        reactor.deregister(Token::new(2)).unwrap();
        assert_eq!(reactor.registration_count(), 2);

        reactor.deregister(Token::new(1)).unwrap();
        reactor.deregister(Token::new(3)).unwrap();
        assert_eq!(reactor.registration_count(), 0);
        assert!(reactor.is_empty());
    }

    #[test]
    fn browser_reactor_register_duplicate_token_fails() {
        let reactor = BrowserReactor::default();
        let source = TestFdSource;
        let token = Token::new(7);
        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();

        let err = reactor
            .register(&source, token, Interest::WRITABLE)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn browser_reactor_modify_unknown_token_returns_not_found() {
        let reactor = BrowserReactor::default();
        let err = reactor
            .modify(Token::new(404), Interest::READABLE)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
