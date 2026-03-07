//! Browser reactor for browser-like event loop targets.
//!
//! This module provides a [`BrowserReactor`] that implements the [`Reactor`]
//! trait for browser environments. In production browser builds, the reactor
//! bridges browser event sources (fetch completions, WebSocket events,
//! microtask queue) to the runtime's event notification system.
//!
//! # Current Status
//!
//! This backend maintains deterministic registration bookkeeping plus a
//! wake-driven pending-event queue:
//!
//! - `wake()` snapshots registered interests into a pending queue
//! - `poll()` drains pending events in bounded batches
//! - repeated wake calls are coalesced when configured
//!
//! Browser host-source wiring (fetch/WebSocket/stream callbacks) still lands
//! in follow-on beads, but the reactor no longer hardcodes `poll() -> 0`.
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
/// Browser reactor implementation preserving the [`Reactor`] trait contract
/// for browser environments. It maintains deterministic registration
/// bookkeeping and wake-driven pending-event draining while host callback
/// wiring lands in follow-on integration work.
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
    pending_events: Mutex<Vec<super::Event>>,
    wake_pending: AtomicBool,
}

impl BrowserReactor {
    /// Creates a new browser reactor with the given configuration.
    #[must_use]
    pub fn new(config: BrowserReactorConfig) -> Self {
        Self {
            config,
            registrations: Mutex::new(BTreeMap::new()),
            pending_events: Mutex::new(Vec::new()),
            wake_pending: AtomicBool::new(false),
        }
    }

    fn registrations_mut(&self) -> io::Result<MutexGuard<'_, BTreeMap<Token, Interest>>> {
        self.registrations
            .lock()
            .map_err(|_| io::Error::other("browser reactor registry lock poisoned"))
    }

    fn pending_events_mut(&self) -> io::Result<MutexGuard<'_, Vec<super::Event>>> {
        self.pending_events
            .lock()
            .map_err(|_| io::Error::other("browser reactor pending queue lock poisoned"))
    }

    fn snapshot_readiness_events(&self) -> io::Result<Vec<super::Event>> {
        let registrations = self.registrations_mut()?;
        let mut events = Vec::with_capacity(registrations.len());
        for (token, interest) in registrations.iter() {
            let ready = *interest
                & (Interest::READABLE
                    | Interest::WRITABLE
                    | Interest::ERROR
                    | Interest::HUP
                    | Interest::PRIORITY);
            if !ready.is_empty() {
                events.push(super::Event::new(*token, ready));
            }
        }
        drop(registrations);
        Ok(events)
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

        let mut pending = self.pending_events_mut()?;
        pending.retain(|event| event.token != token);
        let queue_empty = pending.is_empty();
        drop(pending);
        if queue_empty {
            self.wake_pending.store(false, Ordering::Release);
        }
        Ok(())
    }

    fn poll(&self, events: &mut Events, _timeout: Option<Duration>) -> io::Result<usize> {
        // Browser poll is always non-blocking and drains any events that were
        // queued by wake() and future host callback integrations.
        events.clear();

        let mut pending = self.pending_events_mut()?;
        if pending.is_empty() {
            self.wake_pending.store(false, Ordering::Release);
            return Ok(0);
        }

        let batch_limit = if self.config.max_events_per_poll == 0 {
            usize::MAX
        } else {
            self.config.max_events_per_poll
        };
        let n = pending.len().min(batch_limit);
        for event in pending.drain(..n) {
            events.push(event);
        }

        let still_pending = !pending.is_empty();
        drop(pending);
        self.wake_pending.store(still_pending, Ordering::Release);
        Ok(n)
    }

    fn wake(&self) -> io::Result<()> {
        // Coalescing: multiple wake() calls before the next poll produce only
        // one queued dispatch batch.
        if self.config.coalesce_wakes
            && self
                .wake_pending
                .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return Ok(());
        }

        self.wake_pending.store(true, Ordering::Release);
        let snapshot = self.snapshot_readiness_events()?;
        if snapshot.is_empty() {
            // No registrations to snapshot — clear wake_pending so future
            // wake() calls are not incorrectly coalesced away.
            self.wake_pending.store(false, Ordering::Release);
            return Ok(());
        }

        self.pending_events_mut()?.extend(snapshot);
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
    fn browser_reactor_poll_returns_zero_events_when_no_pending_work() {
        let reactor = BrowserReactor::default();
        let mut events = Events::with_capacity(64);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 0);
        assert!(events.is_empty());
    }

    #[test]
    fn browser_reactor_wake_without_registrations_keeps_poll_empty() {
        let reactor = BrowserReactor::default();
        reactor.wake().unwrap();
        let mut events = Events::with_capacity(8);
        assert_eq!(reactor.poll(&mut events, Some(Duration::ZERO)).unwrap(), 0);
        assert!(events.is_empty());
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
        let source = TestFdSource;
        assert!(
            !reactor
                .wake_pending
                .load(std::sync::atomic::Ordering::Acquire)
        );

        // Wake with no registrations should NOT leave wake_pending set
        // (empty snapshot clears it to avoid coalescing away future wakes).
        reactor.wake().unwrap();
        assert!(
            !reactor
                .wake_pending
                .load(std::sync::atomic::Ordering::Acquire),
            "wake with empty registry must clear wake_pending"
        );

        // Wake with a registration should set wake_pending.
        reactor
            .register(&source, Token::new(1), Interest::READABLE)
            .unwrap();
        reactor.wake().unwrap();
        assert!(
            reactor
                .wake_pending
                .load(std::sync::atomic::Ordering::Acquire),
            "wake with registration must set wake_pending"
        );

        // Poll clears the flag.
        let mut events = Events::with_capacity(4);
        reactor.poll(&mut events, None).unwrap();
        assert!(
            !reactor
                .wake_pending
                .load(std::sync::atomic::Ordering::Acquire),
            "poll must clear wake_pending"
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

    #[test]
    fn browser_reactor_wake_enqueues_events_for_registered_tokens() {
        let reactor = BrowserReactor::default();
        let source = TestFdSource;
        let read_token = Token::new(1);
        let write_token = Token::new(2);

        reactor
            .register(&source, read_token, Interest::READABLE)
            .unwrap();
        reactor
            .register(&source, write_token, Interest::WRITABLE)
            .unwrap();

        reactor.wake().unwrap();
        let mut events = Events::with_capacity(8);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 2);
        assert_eq!(events.len(), 2);
        let mut saw_read = false;
        let mut saw_write = false;
        for event in &events {
            if event.token == read_token {
                saw_read = event.is_readable();
            }
            if event.token == write_token {
                saw_write = event.is_writable();
            }
        }
        assert!(saw_read);
        assert!(saw_write);
    }

    #[test]
    fn browser_reactor_poll_respects_max_events_per_poll() {
        let reactor = BrowserReactor::new(BrowserReactorConfig {
            max_events_per_poll: 1,
            coalesce_wakes: true,
        });
        let source = TestFdSource;

        reactor
            .register(&source, Token::new(1), Interest::READABLE)
            .unwrap();
        reactor
            .register(&source, Token::new(2), Interest::READABLE)
            .unwrap();

        reactor.wake().unwrap();
        let mut events = Events::with_capacity(4);
        let first = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(first, 1);
        assert_eq!(events.len(), 1);

        events.clear();
        let second = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(second, 1);
        assert_eq!(events.len(), 1);

        events.clear();
        let third = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(third, 0);
        assert!(events.is_empty());
    }

    #[test]
    fn browser_reactor_wake_with_empty_snapshot_clears_pending_flag() {
        // Regression: wake() on an empty registry used to leave wake_pending
        // as true, causing the next wake() (after a registration is added) to
        // be incorrectly coalesced away.
        let reactor = BrowserReactor::default();

        // Wake with no registrations — snapshot is empty.
        reactor.wake().unwrap();
        assert!(
            !reactor
                .wake_pending
                .load(std::sync::atomic::Ordering::Acquire),
            "wake_pending must be cleared when snapshot is empty"
        );

        // Now register and wake again — must NOT be coalesced.
        let source = TestFdSource;
        reactor
            .register(&source, Token::new(1), Interest::READABLE)
            .unwrap();
        reactor.wake().unwrap();

        let mut events = Events::with_capacity(4);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 1, "wake after empty snapshot must not be coalesced");
    }
}
