//! Browser reactor for browser-like event loop targets.
//!
//! This module provides a [`BrowserReactor`] that implements the [`Reactor`]
//! trait for browser environments. In production browser builds, the reactor
//! bridges browser event sources (fetch completions, WebSocket events,
//! microtask queue) to the runtime's event notification system.
//!
//! # Current Status
//!
//! This backend provides both deterministic registration bookkeeping and
//! real browser host listener wiring:
//!
//! - `wake()` acts as a pure wakeup signal and never invents readiness
//! - `poll()` drains pending events in bounded batches
//! - repeated host readiness notifications are coalesced when configured
//! - [`BrowserReactor::register_message_port`] and
//!   [`BrowserReactor::register_broadcast_channel`] attach real
//!   `wasm_bindgen` closure listeners that deliver events via
//!   [`BrowserReactor::notify_ready`]
//! - deregistration detaches host listeners and cleans up closures
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
//! - **Wake**: Nudges the non-blocking poll loop without creating I/O events
//!
//! # Invariants Preserved
//!
//! - Token-based registration/deregistration model unchanged
//! - Interest flags (readable/writable) still apply to browser streams
//! - Event batching preserved for efficiency
//! - Thread safety: wasm32 is single-threaded but `Send + Sync` bounds
//!   satisfied for API compatibility

use super::{Events, Interest, Reactor, Source, Token};
use parking_lot::{Mutex, MutexGuard};
#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
#[cfg(target_arch = "wasm32")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
#[cfg(target_arch = "wasm32")]
use web_sys::{BroadcastChannel, EventTarget, MessageEvent, MessagePort};

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
/// bookkeeping and wake-driven pending-event draining, with real host
/// listener wiring for MessagePort and BroadcastChannel sources.
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
    inner: Arc<BrowserReactorInner>,
    #[cfg(target_arch = "wasm32")]
    reactor_id: u64,
}

#[derive(Debug)]
struct BrowserReactorInner {
    config: BrowserReactorConfig,
    registrations: Mutex<BTreeMap<Token, Interest>>,
    pending_events: Mutex<Vec<super::Event>>,
    wake_pending: AtomicBool,
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrowserHostBindingKind {
    MessagePort,
    BroadcastChannel,
}

#[cfg(any(test, target_arch = "wasm32"))]
impl BrowserHostBindingKind {
    const fn label(self) -> &'static str {
        match self {
            Self::MessagePort => "MessagePort",
            Self::BroadcastChannel => "BroadcastChannel",
        }
    }
}

#[cfg(target_arch = "wasm32")]
static NEXT_BROWSER_REACTOR_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(target_arch = "wasm32")]
const BROWSER_MESSAGE_EVENT: &str = "message";
#[cfg(target_arch = "wasm32")]
const BROWSER_MESSAGE_ERROR_EVENT: &str = "messageerror";

#[cfg(target_arch = "wasm32")]
thread_local! {
    static BROWSER_HOST_BINDINGS: RefCell<BTreeMap<(u64, Token), BrowserHostBinding>> =
        RefCell::new(BTreeMap::new());
}

#[cfg(target_arch = "wasm32")]
enum BrowserHostBinding {
    MessagePort(MessagePortBinding),
    BroadcastChannel(BroadcastChannelBinding),
}

#[cfg(target_arch = "wasm32")]
impl BrowserHostBinding {
    fn kind(&self) -> BrowserHostBindingKind {
        match self {
            Self::MessagePort(_) => BrowserHostBindingKind::MessagePort,
            Self::BroadcastChannel(_) => BrowserHostBindingKind::BroadcastChannel,
        }
    }

    fn attach(&self) -> io::Result<()> {
        match self {
            Self::MessagePort(binding) => binding.attach(),
            Self::BroadcastChannel(binding) => binding.attach(),
        }
    }

    fn detach(self) {
        match self {
            Self::MessagePort(binding) => binding.detach(),
            Self::BroadcastChannel(binding) => binding.detach(),
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn browser_host_listener_error(err: &JsValue, op: &str) -> io::Error {
    let detail = err.as_string().unwrap_or_else(|| format!("{err:?}"));
    io::Error::other(format!("{op} failed: {detail}"))
}

#[cfg(target_arch = "wasm32")]
fn attach_browser_message_listeners(
    target: &EventTarget,
    on_message: &Closure<dyn FnMut(MessageEvent)>,
    on_message_error: &Closure<dyn FnMut(MessageEvent)>,
    message_op: &str,
    message_error_op: &str,
) -> io::Result<()> {
    target
        .add_event_listener_with_callback(
            BROWSER_MESSAGE_EVENT,
            on_message.as_ref().unchecked_ref(),
        )
        .map_err(|err| browser_host_listener_error(&err, message_op))?;

    if let Err(err) = target.add_event_listener_with_callback(
        BROWSER_MESSAGE_ERROR_EVENT,
        on_message_error.as_ref().unchecked_ref(),
    ) {
        detach_browser_message_listeners(target, on_message, on_message_error);
        return Err(browser_host_listener_error(&err, message_error_op));
    }

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn detach_browser_message_listeners(
    target: &EventTarget,
    on_message: &Closure<dyn FnMut(MessageEvent)>,
    on_message_error: &Closure<dyn FnMut(MessageEvent)>,
) {
    let _ = target.remove_event_listener_with_callback(
        BROWSER_MESSAGE_EVENT,
        on_message.as_ref().unchecked_ref(),
    );
    let _ = target.remove_event_listener_with_callback(
        BROWSER_MESSAGE_ERROR_EVENT,
        on_message_error.as_ref().unchecked_ref(),
    );
}

#[cfg(target_arch = "wasm32")]
struct MessagePortBinding {
    port: MessagePort,
    on_message: Closure<dyn FnMut(MessageEvent)>,
    on_message_error: Closure<dyn FnMut(MessageEvent)>,
}

#[cfg(target_arch = "wasm32")]
impl MessagePortBinding {
    fn new(inner: Arc<BrowserReactorInner>, token: Token, port: &MessagePort) -> Self {
        let readable_inner = Arc::clone(&inner);
        let on_message = Closure::wrap(Box::new(move |_event: MessageEvent| {
            let _ = readable_inner.notify_ready(token, Interest::READABLE);
        }) as Box<dyn FnMut(MessageEvent)>);

        let error_inner = Arc::clone(&inner);
        let on_message_error = Closure::wrap(Box::new(move |_event: MessageEvent| {
            let _ = error_inner.notify_ready(token, Interest::ERROR);
        }) as Box<dyn FnMut(MessageEvent)>);

        Self {
            port: port.clone(),
            on_message,
            on_message_error,
        }
    }

    fn attach(&self) -> io::Result<()> {
        let target: &EventTarget = AsRef::<EventTarget>::as_ref(&self.port);
        attach_browser_message_listeners(
            target,
            &self.on_message,
            &self.on_message_error,
            "MessagePort.addEventListener(message)",
            "MessagePort.addEventListener(messageerror)",
        )?;
        self.port.start();
        Ok(())
    }

    fn detach(self) {
        let target: &EventTarget = AsRef::<EventTarget>::as_ref(&self.port);
        detach_browser_message_listeners(target, &self.on_message, &self.on_message_error);
    }
}

#[cfg(target_arch = "wasm32")]
struct BroadcastChannelBinding {
    channel: BroadcastChannel,
    on_message: Closure<dyn FnMut(MessageEvent)>,
    on_message_error: Closure<dyn FnMut(MessageEvent)>,
}

#[cfg(target_arch = "wasm32")]
impl BroadcastChannelBinding {
    fn new(inner: Arc<BrowserReactorInner>, token: Token, channel: &BroadcastChannel) -> Self {
        let readable_inner = Arc::clone(&inner);
        let on_message = Closure::wrap(Box::new(move |_event: MessageEvent| {
            let _ = readable_inner.notify_ready(token, Interest::READABLE);
        }) as Box<dyn FnMut(MessageEvent)>);

        let error_inner = Arc::clone(&inner);
        let on_message_error = Closure::wrap(Box::new(move |_event: MessageEvent| {
            let _ = error_inner.notify_ready(token, Interest::ERROR);
        }) as Box<dyn FnMut(MessageEvent)>);

        Self {
            channel: channel.clone(),
            on_message,
            on_message_error,
        }
    }

    fn attach(&self) -> io::Result<()> {
        let target: &EventTarget = AsRef::<EventTarget>::as_ref(&self.channel);
        attach_browser_message_listeners(
            target,
            &self.on_message,
            &self.on_message_error,
            "BroadcastChannel.addEventListener(message)",
            "BroadcastChannel.addEventListener(messageerror)",
        )
    }

    fn detach(self) {
        let target: &EventTarget = AsRef::<EventTarget>::as_ref(&self.channel);
        detach_browser_message_listeners(target, &self.on_message, &self.on_message_error);
    }
}

impl BrowserReactorInner {
    fn new(config: BrowserReactorConfig) -> Self {
        Self {
            config,
            registrations: Mutex::new(BTreeMap::new()),
            pending_events: Mutex::new(Vec::new()),
            wake_pending: AtomicBool::new(false),
        }
    }

    fn registrations_mut(&self) -> MutexGuard<'_, BTreeMap<Token, Interest>> {
        self.registrations.lock()
    }

    fn pending_events_mut(&self) -> MutexGuard<'_, Vec<super::Event>> {
        self.pending_events.lock()
    }

    fn readiness_mask() -> Interest {
        Interest::READABLE
            | Interest::WRITABLE
            | Interest::ERROR
            | Interest::HUP
            | Interest::PRIORITY
    }

    fn disarm_oneshot(interest: Interest) -> Interest {
        interest.remove(Self::readiness_mask())
    }

    /// Enqueue readiness discovered by browser host callbacks.
    ///
    /// Host bridges (fetch completion, WebSocket events, stream callbacks)
    /// should call this to deliver token readiness into the reactor queue.
    ///
    /// Returns `Ok(true)` when an event is queued or coalesced, and `Ok(false)`
    /// when the token is unknown or the readiness does not intersect the
    /// token's registered interest.
    fn notify_ready(&self, token: Token, ready: Interest) -> bool {
        let registrations = self.registrations_mut();
        let Some(interest) = registrations.get(&token).copied() else {
            return false;
        };
        let effective = ready & interest & Self::readiness_mask();

        if effective.is_empty() {
            return false;
        }

        // Keep registration lookup and queue insertion atomic under the same
        // lock order used by modify()/deregister() so host callbacks cannot
        // enqueue stale readiness after a concurrent interest change/remove.
        let mut pending = self.pending_events_mut();
        if self.config.coalesce_wakes || interest.is_oneshot() {
            if let Some(existing) = pending.iter_mut().find(|event| event.token == token) {
                existing.ready |= effective;
                drop(pending);
                drop(registrations);
                self.wake_pending.store(true, Ordering::Release);
                return true;
            }
        }

        pending.push(super::Event::new(token, effective));
        drop(pending);
        drop(registrations);
        self.wake_pending.store(true, Ordering::Release);
        true
    }

    #[cfg(test)]
    fn notify_ready_with_barriers(
        &self,
        token: Token,
        ready: Interest,
        after_interest: &std::sync::Barrier,
        continue_after_interest: &std::sync::Barrier,
    ) -> bool {
        let registrations = self.registrations_mut();
        let Some(interest) = registrations.get(&token).copied() else {
            return false;
        };
        let effective = ready & interest & Self::readiness_mask();

        if effective.is_empty() {
            return false;
        }

        after_interest.wait();
        continue_after_interest.wait();

        let mut pending = self.pending_events_mut();
        if self.config.coalesce_wakes || interest.is_oneshot() {
            if let Some(existing) = pending.iter_mut().find(|event| event.token == token) {
                existing.ready |= effective;
                drop(pending);
                drop(registrations);
                self.wake_pending.store(true, Ordering::Release);
                return true;
            }
        }

        pending.push(super::Event::new(token, effective));
        drop(pending);
        drop(registrations);
        self.wake_pending.store(true, Ordering::Release);
        true
    }

    fn register(&self, token: Token, interest: Interest) -> io::Result<()> {
        let mut registrations = self.registrations_mut();
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
        let mut registrations = self.registrations_mut();
        let slot = registrations.get_mut(&token).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("token {token:?} not registered"),
            )
        })?;
        *slot = interest;
        drop(registrations);

        let readiness = interest & Self::readiness_mask();
        let mut pending = self.pending_events_mut();
        pending.retain_mut(|event| {
            if event.token != token {
                return true;
            }
            event.ready &= readiness;
            !event.ready.is_empty()
        });
        let still_pending = !pending.is_empty();
        drop(pending);
        self.wake_pending.store(still_pending, Ordering::Release);
        Ok(())
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        let removed = self.registrations_mut().remove(&token);
        if removed.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("token {token:?} not registered"),
            ));
        }

        let mut pending = self.pending_events_mut();
        pending.retain(|event| event.token != token);
        let queue_empty = pending.is_empty();
        drop(pending);
        if queue_empty {
            self.wake_pending.store(false, Ordering::Release);
        }
        Ok(())
    }

    fn poll(&self, events: &mut Events) -> usize {
        events.clear();

        let mut registrations = self.registrations_mut();
        let mut pending = self.pending_events_mut();
        if pending.is_empty() {
            self.wake_pending.store(false, Ordering::Release);
            return 0;
        }

        let batch_limit = if self.config.max_events_per_poll == 0 {
            usize::MAX
        } else {
            self.config.max_events_per_poll
        };
        let n = pending.len().min(batch_limit);
        let mut oneshot_tokens = Vec::new();
        for event in pending.drain(..n) {
            if registrations
                .get(&event.token)
                .is_some_and(super::interest::Interest::is_oneshot)
                && !oneshot_tokens.contains(&event.token)
            {
                oneshot_tokens.push(event.token);
            }
            events.push(event);
        }

        for token in oneshot_tokens {
            if let Some(interest) = registrations.get_mut(&token) {
                if interest.is_oneshot() {
                    *interest = Self::disarm_oneshot(*interest);
                }
            }
        }

        let still_pending = !pending.is_empty();
        drop(pending);
        drop(registrations);
        self.wake_pending.store(still_pending, Ordering::Release);
        n
    }

    fn wake(&self) {
        let still_pending = !self.pending_events_mut().is_empty();
        self.wake_pending.store(still_pending, Ordering::Release);
    }

    fn registration_count(&self) -> usize {
        self.registrations.lock().len()
    }
}

impl BrowserReactor {
    /// Creates a new browser reactor with the given configuration.
    #[must_use]
    pub fn new(config: BrowserReactorConfig) -> Self {
        Self {
            inner: Arc::new(BrowserReactorInner::new(config)),
            #[cfg(target_arch = "wasm32")]
            reactor_id: NEXT_BROWSER_REACTOR_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    #[cfg(any(test, target_arch = "wasm32"))]
    fn message_source_interest_mask() -> Interest {
        Interest::READABLE | Interest::ERROR
    }

    #[cfg(any(test, target_arch = "wasm32"))]
    fn validate_message_source_interest(
        kind: BrowserHostBindingKind,
        interest: Interest,
    ) -> io::Result<()> {
        let unsupported = interest & !Self::message_source_interest_mask();
        if interest.is_empty() || !unsupported.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} sources only support READABLE and ERROR interests, got {interest:?}",
                    kind.label()
                ),
            ));
        }
        Ok(())
    }

    /// Enqueue readiness discovered by browser host callbacks.
    ///
    /// Host bridges (fetch completion, WebSocket events, stream callbacks)
    /// should call this to deliver token readiness into the reactor queue.
    ///
    /// Returns `Ok(true)` when an event is queued or coalesced, and `Ok(false)`
    /// when the token is unknown or the readiness does not intersect the
    /// token's registered interest.
    pub fn notify_ready(&self, token: Token, ready: Interest) -> io::Result<bool> {
        Ok(self.inner.notify_ready(token, ready))
    }

    #[cfg(test)]
    fn notify_ready_with_barriers(
        &self,
        token: Token,
        ready: Interest,
        after_interest: &std::sync::Barrier,
        continue_after_interest: &std::sync::Barrier,
    ) -> bool {
        self.inner
            .notify_ready_with_barriers(token, ready, after_interest, continue_after_interest)
    }

    #[cfg(test)]
    fn wake_pending(&self) -> bool {
        self.inner.wake_pending.load(Ordering::Acquire)
    }

    #[cfg(target_arch = "wasm32")]
    fn host_binding_key(&self, token: Token) -> (u64, Token) {
        (self.reactor_id, token)
    }

    #[cfg(target_arch = "wasm32")]
    fn install_host_binding(&self, token: Token, binding: BrowserHostBinding) -> io::Result<()> {
        BROWSER_HOST_BINDINGS.with(|bindings| {
            let mut bindings = bindings.borrow_mut();
            let key = self.host_binding_key(token);
            if bindings.contains_key(&key) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("token {token:?} already has a browser host binding"),
                ));
            }
            binding.attach()?;
            bindings.insert(key, binding);
            Ok(())
        })
    }

    #[cfg(target_arch = "wasm32")]
    fn remove_host_binding(&self, token: Token) {
        let binding = BROWSER_HOST_BINDINGS
            .with(|bindings| bindings.borrow_mut().remove(&self.host_binding_key(token)));
        if let Some(binding) = binding {
            binding.detach();
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn host_binding_kind(&self, token: Token) -> Option<BrowserHostBindingKind> {
        BROWSER_HOST_BINDINGS.with(|bindings| {
            bindings
                .borrow()
                .get(&self.host_binding_key(token))
                .map(BrowserHostBinding::kind)
        })
    }

    #[cfg(target_arch = "wasm32")]
    fn remove_all_host_bindings(&self) {
        let keys = BROWSER_HOST_BINDINGS.with(|bindings| {
            bindings
                .borrow()
                .keys()
                .copied()
                .filter(|(reactor_id, _)| *reactor_id == self.reactor_id)
                .collect::<Vec<_>>()
        });
        for key in keys {
            let binding = BROWSER_HOST_BINDINGS.with(|bindings| bindings.borrow_mut().remove(&key));
            if let Some(binding) = binding {
                binding.detach();
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn register_message_binding(
        &self,
        token: Token,
        interest: Interest,
        kind: BrowserHostBindingKind,
        binding: BrowserHostBinding,
    ) -> io::Result<()> {
        Self::validate_message_source_interest(kind, interest)?;
        self.inner.register(token, interest)?;
        if let Err(err) = self.install_host_binding(token, binding) {
            let _ = self.inner.deregister(token);
            return Err(err);
        }
        Ok(())
    }

    /// Register a [`MessagePort`] with real browser host listener wiring.
    ///
    /// This attaches non-clobbering `message` / `messageerror` listeners for
    /// the lifetime of the registration. Supported interests are limited to
    /// `READABLE` and `ERROR`.
    #[cfg(target_arch = "wasm32")]
    pub fn register_message_port(
        &self,
        port: &MessagePort,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        self.register_message_binding(
            token,
            interest,
            BrowserHostBindingKind::MessagePort,
            BrowserHostBinding::MessagePort(MessagePortBinding::new(
                Arc::clone(&self.inner),
                token,
                port,
            )),
        )
    }

    /// Register a [`BroadcastChannel`] with real browser host listener wiring.
    ///
    /// This attaches non-clobbering `message` / `messageerror` listeners for
    /// the lifetime of the registration. Supported interests are limited to
    /// `READABLE` and `ERROR`.
    #[cfg(target_arch = "wasm32")]
    pub fn register_broadcast_channel(
        &self,
        channel: &BroadcastChannel,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        self.register_message_binding(
            token,
            interest,
            BrowserHostBindingKind::BroadcastChannel,
            BrowserHostBinding::BroadcastChannel(BroadcastChannelBinding::new(
                Arc::clone(&self.inner),
                token,
                channel,
            )),
        )
    }
}

impl Default for BrowserReactor {
    fn default() -> Self {
        Self::new(BrowserReactorConfig::default())
    }
}

impl Reactor for BrowserReactor {
    fn register(&self, _source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        // Generic browser registrations keep deterministic token bookkeeping.
        // Concrete message-based host sources can opt into real listener wiring
        // through register_message_port()/register_broadcast_channel().
        self.inner.register(token, interest)
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        #[cfg(target_arch = "wasm32")]
        if let Some(kind) = self.host_binding_kind(token) {
            Self::validate_message_source_interest(kind, interest)?;
        }

        self.inner.modify(token, interest)
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        self.inner.deregister(token)?;
        #[cfg(target_arch = "wasm32")]
        self.remove_host_binding(token);
        Ok(())
    }

    fn poll(&self, events: &mut Events, _timeout: Option<Duration>) -> io::Result<usize> {
        // Browser poll is always non-blocking and drains events queued by
        // notify_ready() and host callback integrations.
        Ok(self.inner.poll(events))
    }

    fn wake(&self) -> io::Result<()> {
        // Browser poll is already non-blocking, so wake must never fabricate
        // token readiness. Host integrations publish actual readiness via
        // notify_ready(); wake only preserves the existing pending/not-pending
        // state so runtime nudges do not turn into false I/O events.
        self.inner.wake();
        Ok(())
    }

    fn registration_count(&self) -> usize {
        self.inner.registration_count()
    }
}

#[cfg(target_arch = "wasm32")]
impl Drop for BrowserReactor {
    fn drop(&mut self) {
        self.remove_all_host_bindings();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

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
    fn browser_reactor_modify_updates_interest() {
        let reactor = BrowserReactor::default();
        let source = TestFdSource;
        let token = Token::new(1);
        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();
        assert!(reactor.modify(token, Interest::WRITABLE).is_ok());

        assert!(reactor.notify_ready(token, Interest::WRITABLE).unwrap());
        let mut events = Events::with_capacity(4);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 1);
        let event = events.iter().next().expect("single event");
        assert!(!event.is_readable());
        assert!(event.is_writable());
    }

    #[test]
    fn browser_reactor_config_defaults() {
        let config = BrowserReactorConfig::default();
        assert_eq!(config.max_events_per_poll, 64);
        assert!(config.coalesce_wakes);
    }

    #[test]
    fn browser_reactor_message_port_interest_validation_accepts_readable_and_error() {
        BrowserReactor::validate_message_source_interest(
            BrowserHostBindingKind::MessagePort,
            Interest::READABLE | Interest::ERROR,
        )
        .unwrap();
    }

    #[test]
    fn browser_reactor_message_port_interest_validation_rejects_empty_interest() {
        let err = BrowserReactor::validate_message_source_interest(
            BrowserHostBindingKind::MessagePort,
            Interest::empty(),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn browser_reactor_broadcast_channel_interest_validation_rejects_writable_flags() {
        let err = BrowserReactor::validate_message_source_interest(
            BrowserHostBindingKind::BroadcastChannel,
            Interest::READABLE | Interest::WRITABLE,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn browser_reactor_deregister_unknown_returns_not_found() {
        let reactor = BrowserReactor::default();
        let err = reactor.deregister(Token::new(99)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert_eq!(reactor.registration_count(), 0);
    }

    #[test]
    fn browser_reactor_wake_flag_tracks_pending_host_readiness_only() {
        let reactor = BrowserReactor::default();
        let source = TestFdSource;
        assert!(!reactor.wake_pending());

        // Wake with no registrations should NOT leave wake_pending set
        // because there is still no queued host readiness.
        reactor.wake().unwrap();
        assert!(
            !reactor.wake_pending(),
            "wake with empty registry must keep wake_pending clear"
        );

        // Registering alone still must not mark readiness pending.
        reactor
            .register(&source, Token::new(1), Interest::READABLE)
            .unwrap();
        reactor.wake().unwrap();
        assert!(
            !reactor.wake_pending(),
            "wake must not mark readiness pending without host events"
        );

        assert!(
            reactor
                .notify_ready(Token::new(1), Interest::READABLE)
                .unwrap()
        );
        assert!(
            reactor.wake_pending(),
            "host readiness should mark wake_pending"
        );

        // Poll clears the flag.
        let mut events = Events::with_capacity(4);
        reactor.poll(&mut events, None).unwrap();
        assert!(!reactor.wake_pending(), "poll must clear wake_pending");
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
    fn browser_reactor_wake_does_not_emit_synthetic_readiness_for_registered_tokens() {
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
        assert_eq!(n, 0);
        assert!(events.is_empty());
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

        assert!(
            reactor
                .notify_ready(Token::new(1), Interest::READABLE)
                .unwrap()
        );
        assert!(
            reactor
                .notify_ready(Token::new(2), Interest::READABLE)
                .unwrap()
        );
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
    fn browser_reactor_wake_without_host_readiness_keeps_pending_flag_clear() {
        let reactor = BrowserReactor::default();

        // Wake with no registrations.
        reactor.wake().unwrap();
        assert!(
            !reactor.wake_pending(),
            "wake_pending must stay clear when no host readiness exists"
        );

        // Registering a token still must not make wake() fabricate readiness.
        let source = TestFdSource;
        reactor
            .register(&source, Token::new(1), Interest::READABLE)
            .unwrap();
        reactor.wake().unwrap();
        assert!(
            !reactor.wake_pending(),
            "registered tokens alone must not mark readiness pending"
        );

        let mut events = Events::with_capacity(4);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 0);
        assert!(events.is_empty());
    }

    #[test]
    fn browser_reactor_notify_ready_ignores_unknown_token() {
        let reactor = BrowserReactor::default();
        let queued = reactor
            .notify_ready(Token::new(42), Interest::READABLE)
            .unwrap();
        assert!(!queued);
    }

    #[test]
    fn browser_reactor_notify_ready_masks_by_registered_interest() {
        let reactor = BrowserReactor::default();
        let source = TestFdSource;
        let token = Token::new(3);

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();
        assert!(!reactor.notify_ready(token, Interest::WRITABLE).unwrap());
        assert!(reactor.notify_ready(token, Interest::READABLE).unwrap());

        let mut events = Events::with_capacity(4);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 1);
        assert_eq!(events.len(), 1);
        let event = events.iter().next().expect("single event");
        assert!(event.is_readable());
        assert!(!event.is_writable());
    }

    #[test]
    fn browser_reactor_modify_scrubs_stale_pending_readiness() {
        let reactor = BrowserReactor::default();
        let source = TestFdSource;
        let token = Token::new(7);

        reactor
            .register(&source, token, Interest::READABLE | Interest::WRITABLE)
            .unwrap();
        assert!(reactor.notify_ready(token, Interest::WRITABLE).unwrap());

        reactor.modify(token, Interest::READABLE).unwrap();

        let mut events = Events::with_capacity(4);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(
            n, 0,
            "modify should discard queued readiness that no longer matches interest"
        );

        assert!(reactor.notify_ready(token, Interest::READABLE).unwrap());
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 1);
        let event = events.iter().next().expect("single event");
        assert!(event.is_readable());
        assert!(!event.is_writable());
    }

    #[test]
    fn browser_reactor_deregister_scrubs_pending_host_readiness() {
        let reactor = BrowserReactor::default();
        let source = TestFdSource;
        let token = Token::new(8);

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();
        assert!(reactor.notify_ready(token, Interest::READABLE).unwrap());

        reactor.deregister(token).unwrap();

        let mut events = Events::with_capacity(4);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 0);
        assert!(events.is_empty());
    }

    #[test]
    fn browser_reactor_notify_ready_coalesces_same_token_when_enabled() {
        let reactor = BrowserReactor::default();
        let source = TestFdSource;
        let token = Token::new(9);

        reactor
            .register(&source, token, Interest::READABLE | Interest::WRITABLE)
            .unwrap();
        assert!(reactor.notify_ready(token, Interest::READABLE).unwrap());
        assert!(reactor.notify_ready(token, Interest::WRITABLE).unwrap());

        let mut events = Events::with_capacity(4);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 1);
        assert_eq!(events.len(), 1);
        let event = events.iter().next().expect("single event");
        assert!(event.is_readable());
        assert!(event.is_writable());
    }

    #[test]
    fn browser_reactor_oneshot_disarms_after_first_delivered_event() {
        let reactor = BrowserReactor::default();
        let source = TestFdSource;
        let token = Token::new(10);

        reactor
            .register(&source, token, Interest::READABLE.with_oneshot())
            .unwrap();

        assert!(reactor.notify_ready(token, Interest::READABLE).unwrap());

        let mut events = Events::with_capacity(4);
        let first = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(first, 1);
        assert_eq!(events.len(), 1);
        assert!(events.iter().next().expect("single event").is_readable());

        events.clear();
        assert!(
            !reactor.notify_ready(token, Interest::READABLE).unwrap(),
            "oneshot token must stay disarmed until modify() re-arms it"
        );
        assert_eq!(reactor.poll(&mut events, Some(Duration::ZERO)).unwrap(), 0);

        reactor
            .modify(token, Interest::READABLE.with_oneshot())
            .unwrap();
        assert!(reactor.notify_ready(token, Interest::READABLE).unwrap());
        assert_eq!(reactor.poll(&mut events, Some(Duration::ZERO)).unwrap(), 1);
        assert!(events.iter().next().expect("rearmed event").is_readable());
    }

    #[test]
    fn browser_reactor_oneshot_coalesces_duplicate_ready_notifications_even_without_coalesce() {
        let reactor = BrowserReactor::new(BrowserReactorConfig {
            max_events_per_poll: 64,
            coalesce_wakes: false,
        });
        let source = TestFdSource;
        let token = Token::new(12);

        reactor
            .register(
                &source,
                token,
                (Interest::READABLE | Interest::WRITABLE).with_oneshot(),
            )
            .unwrap();

        assert!(reactor.notify_ready(token, Interest::READABLE).unwrap());
        assert!(reactor.notify_ready(token, Interest::WRITABLE).unwrap());

        let mut events = Events::with_capacity(4);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 1, "oneshot tokens must yield a single delivered event");
        let event = events.iter().next().expect("single event");
        assert!(event.is_readable());
        assert!(event.is_writable());

        events.clear();
        assert!(
            !reactor.notify_ready(token, Interest::READABLE).unwrap(),
            "oneshot token remains disarmed after delivery"
        );
        assert_eq!(reactor.poll(&mut events, Some(Duration::ZERO)).unwrap(), 0);
    }

    #[test]
    fn browser_reactor_notify_ready_keeps_distinct_events_when_coalesce_disabled() {
        let reactor = BrowserReactor::new(BrowserReactorConfig {
            max_events_per_poll: 64,
            coalesce_wakes: false,
        });
        let source = TestFdSource;
        let token = Token::new(11);

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();
        assert!(reactor.notify_ready(token, Interest::READABLE).unwrap());
        assert!(reactor.notify_ready(token, Interest::READABLE).unwrap());

        let mut events = Events::with_capacity(4);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 2);
        assert_eq!(events.len(), 2);
        let mut iter = events.iter();
        assert!(iter.next().expect("first event").is_readable());
        assert!(iter.next().expect("second event").is_readable());
    }

    #[test]
    fn browser_reactor_wake_preserves_pending_host_readiness_without_adding_more() {
        let reactor = BrowserReactor::default();
        let source = TestFdSource;
        let readable = Token::new(21);
        let writable = Token::new(22);

        reactor
            .register(&source, readable, Interest::READABLE)
            .unwrap();
        reactor
            .register(&source, writable, Interest::WRITABLE)
            .unwrap();

        assert!(reactor.notify_ready(readable, Interest::READABLE).unwrap());
        reactor.wake().unwrap();

        let mut events = Events::with_capacity(4);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 1);

        let mut saw_readable = false;
        for event in &events {
            if event.token == readable {
                saw_readable = event.is_readable();
            }
            assert_ne!(
                event.token, writable,
                "wake must not synthesize readiness for unrelated registered tokens"
            );
        }

        assert!(saw_readable);
    }

    #[test]
    fn browser_reactor_deregister_clears_event_from_racing_notify_ready() {
        let reactor = Arc::new(BrowserReactor::default());
        let source = TestFdSource;
        let token = Token::new(31);
        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();

        let after_interest = Arc::new(Barrier::new(2));
        let continue_after_interest = Arc::new(Barrier::new(2));

        let notify_reactor = Arc::clone(&reactor);
        let notify_after_interest = Arc::clone(&after_interest);
        let notify_continue = Arc::clone(&continue_after_interest);
        let notify = std::thread::spawn(move || {
            notify_reactor.notify_ready_with_barriers(
                token,
                Interest::READABLE,
                &notify_after_interest,
                &notify_continue,
            )
        });

        after_interest.wait();

        let deregister_reactor = Arc::clone(&reactor);
        let deregister = std::thread::spawn(move || {
            deregister_reactor
                .deregister(token)
                .expect("deregister should succeed");
        });

        continue_after_interest.wait();

        assert!(notify.join().unwrap());
        deregister.join().unwrap();

        let mut events = Events::with_capacity(4);
        let n = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert_eq!(n, 0, "deregister must remove the queued event");
        assert!(events.is_empty());
    }
}
