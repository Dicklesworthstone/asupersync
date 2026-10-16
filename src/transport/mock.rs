//! Deterministic in-memory transport for testing.
//!
//! This module provides in-memory, deterministic transport components for
//! exercising transport behavior without real I/O.

use crate::security::authenticated::AuthenticatedSymbol;
use crate::time::Sleep;
use crate::transport::error::{SinkError, StreamError};
use crate::transport::{SymbolSink, SymbolStream};
use crate::types::{Symbol, Time};
use crate::util::DetRng;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

/// br-asupersync-emcu9j: deterministic time source for the deterministic transport's
/// default config. Always returns `Time::ZERO` so tests using
/// `SimTransportConfig::default()` (or `::reliable()`/`::lossy()` —
/// both delegate to default) start with a known, replay-stable clock
/// reading. Tests that genuinely need wall-clock time must either
/// build the config via [`SimTransportConfig::with_wall_clock_time`]
/// (the explicit, grep-able opt-in) or install a Cx-rooted virtual
/// clock via the `time_getter` field directly.
///
/// Pre-fix the default `time_getter` was `wall_clock_now`, which
/// silently captured wall-clock readings into every test using the
/// default config. That broke the lab-runtime invariant 'tests are
/// replayable': the same scenario produced different time values
/// across runs; latency-dependent assertions (e.g. 'less than 50ms')
/// passed on fast machines and failed on slow ones. The new default
/// is deterministic; tests that need wall-clock must opt in.
fn deterministic_zero_time() -> Time {
    Time::ZERO
}

/// Configuration for deterministic transport behavior.
#[derive(Debug, Clone)]
pub struct SimTransportConfig {
    /// Base latency added to every operation.
    pub base_latency: Duration,
    /// Random latency jitter (uniform distribution 0..jitter).
    pub latency_jitter: Duration,
    /// Probability (0.0-1.0) of symbol loss.
    pub loss_rate: f64,
    /// Probability (0.0-1.0) of symbol duplication.
    pub duplication_rate: f64,
    /// Probability (0.0-1.0) of symbol corruption.
    pub corruption_rate: f64,
    /// Maximum symbols in flight before backpressure.
    pub capacity: usize,
    /// Seed for deterministic random behavior (None uses a deterministic seed).
    pub seed: Option<u64>,
    /// Whether to preserve symbol ordering.
    pub preserve_order: bool,
    /// Error injection: fail after N successful operations.
    pub fail_after: Option<usize>,
    /// Time source used for deterministic latency deadlines.
    ///
    /// Defaults to wall time. Override this in tests to drive non-zero latency
    /// deterministically without sleeping.
    pub time_getter: fn() -> Time,
}

impl Default for SimTransportConfig {
    fn default() -> Self {
        Self {
            base_latency: Duration::ZERO,
            latency_jitter: Duration::ZERO,
            loss_rate: 0.0,
            duplication_rate: 0.0,
            corruption_rate: 0.0,
            capacity: 1024,
            seed: None,
            preserve_order: true,
            fail_after: None,
            // br-asupersync-emcu9j: deterministic default time source.
            // Pre-fix this defaulted to `wall_clock_now`, silently
            // capturing wall-clock readings into every test using the
            // deterministic transport. Replace with `deterministic_zero_time` so
            // replays produce identical traces; tests that need real
            // wall-clock must opt in via `with_wall_clock_time()` or
            // by setting `time_getter` directly.
            time_getter: deterministic_zero_time,
        }
    }
}

impl SimTransportConfig {
    /// br-asupersync-emcu9j: explicit, grep-able opt-in for callers
    /// that genuinely need wall-clock time in the deterministic transport. Defaults
    /// (`reliable`, `lossy`, `with_latency`, `Default::default`) all
    /// install the deterministic `Time::ZERO` source; tests that
    /// must observe wall-clock progress wire it through this builder.
    #[inline]
    #[must_use]
    pub fn with_wall_clock_time(mut self) -> Self {
        self.time_getter = wall_clock_now;
        self
    }

    /// Create config for reliable, zero-latency transport (unit tests).
    #[inline]
    #[must_use]
    pub fn reliable() -> Self {
        Self::default()
    }

    /// Create config modeling a lossy network.
    #[inline]
    #[must_use]
    pub fn lossy(loss_rate: f64) -> Self {
        Self {
            loss_rate,
            ..Self::default()
        }
    }

    /// Create config modeling network latency.
    #[inline]
    #[must_use]
    pub fn with_latency(base: Duration, jitter: Duration) -> Self {
        Self {
            base_latency: base,
            latency_jitter: jitter,
            ..Self::default()
        }
    }

    /// Create deterministic config for reproducible tests.
    #[inline]
    #[must_use]
    pub fn deterministic(seed: u64) -> Self {
        Self {
            seed: Some(seed),
            ..Self::default()
        }
    }

    /// Override the time source used for deterministic latency.
    #[inline]
    #[must_use]
    pub fn with_time_getter(mut self, time_getter: fn() -> Time) -> Self {
        self.time_getter = time_getter;
        self
    }
}

/// Node identifier for deterministic network topologies.
pub type NodeId = u64;

/// Deterministic link configuration between two nodes.
#[derive(Debug, Clone)]
pub struct SimLink {
    /// Transport behavior for this link.
    pub config: SimTransportConfig,
}

/// Deterministic network topology for transport tests.
#[derive(Debug)]
pub struct SimNetwork {
    nodes: HashSet<NodeId>,
    links: HashMap<(NodeId, NodeId), SimLink>,
    default_config: SimTransportConfig,
}

impl SimNetwork {
    /// Create a fully-connected network of N nodes.
    #[must_use]
    pub fn fully_connected(n: usize, config: SimTransportConfig) -> Self {
        let mut nodes = HashSet::new();
        let mut links = HashMap::new();
        for i in 0..n {
            nodes.insert(i as NodeId);
        }
        for &from in &nodes {
            for &to in &nodes {
                if from != to {
                    links.insert(
                        (from, to),
                        SimLink {
                            config: config.clone(),
                        },
                    );
                }
            }
        }
        Self {
            nodes,
            links,
            default_config: config,
        }
    }

    /// Create a ring topology.
    #[must_use]
    pub fn ring(n: usize, config: SimTransportConfig) -> Self {
        let mut nodes = HashSet::new();
        let mut links = HashMap::new();
        for i in 0..n {
            nodes.insert(i as NodeId);
        }
        if n < 2 {
            return Self {
                nodes,
                links,
                default_config: config,
            };
        }
        for i in 0..n {
            let from = i as NodeId;
            let to = ((i + 1) % n) as NodeId;
            links.insert(
                (from, to),
                SimLink {
                    config: config.clone(),
                },
            );
            links.insert(
                (to, from),
                SimLink {
                    config: config.clone(),
                },
            );
        }
        Self {
            nodes,
            links,
            default_config: config,
        }
    }

    /// Partition the network (some nodes can't reach others).
    pub fn partition(&mut self, group_a: &[NodeId], group_b: &[NodeId]) {
        for &a in group_a {
            for &b in group_b {
                self.links.remove(&(a, b));
                self.links.remove(&(b, a));
            }
        }
    }

    /// Heal a partition by restoring links with the default config.
    pub fn heal_partition(&mut self, group_a: &[NodeId], group_b: &[NodeId]) {
        for &a in group_a {
            for &b in group_b {
                if a == b {
                    continue;
                }
                if self.nodes.contains(&a) && self.nodes.contains(&b) {
                    self.links.insert(
                        (a, b),
                        SimLink {
                            config: self.default_config.clone(),
                        },
                    );
                    self.links.insert(
                        (b, a),
                        SimLink {
                            config: self.default_config.clone(),
                        },
                    );
                }
            }
        }
    }

    /// Get a transport pair for communication between two nodes.
    ///
    /// If the link is missing, returns a closed channel pair.
    #[must_use]
    #[allow(clippy::option_if_let_else)] // if-let-else is clearer than map_or_else here
    pub fn transport(&self, from: NodeId, to: NodeId) -> (SimChannelSink, SimChannelStream) {
        if let Some(link) = self.links.get(&(from, to)) {
            sim_channel(link.config.clone())
        } else {
            closed_channel(self.default_config.clone())
        }
    }
}

// NOTE: This deterministic transport is deterministic with respect to loss/duplication/corruption and
// (when `preserve_order` is enabled) delivery order. Non-zero latency can also be driven
// deterministically by overriding `SimTransportConfig::with_time_getter(...)` so tests can
// advance a test clock instead of sleeping on wall time.

#[derive(Debug)]
struct Delay {
    sleep: Sleep,
    #[allow(dead_code)] // stored for potential delay reset
    time_getter: fn() -> Time,
}

impl Delay {
    fn new(duration: Duration, time_getter: fn() -> Time) -> Self {
        let deadline = time_getter()
            .saturating_add_nanos(duration.as_nanos().min(u128::from(u64::MAX)) as u64);
        Self {
            sleep: Sleep::with_time_getter(deadline, time_getter),
            time_getter,
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        Pin::new(&mut self.sleep).poll(cx)
    }
}

/// A waiter entry with tracking flag to prevent unbounded queue growth.
#[derive(Debug)]
struct SimWaiter {
    waker: Waker,
    /// Flag indicating if this waiter is still queued. When woken, this is set to false.
    queued: Arc<AtomicBool>,
}

fn upsert_sim_waiter(waiters: &mut Vec<SimWaiter>, queued: &Arc<AtomicBool>, waker: &Waker) {
    if let Some(existing) = waiters
        .iter_mut()
        .find(|entry| Arc::ptr_eq(&entry.queued, queued))
    {
        if !existing.waker.will_wake(waker) {
            existing.waker.clone_from(waker);
        }
    } else {
        waiters.push(SimWaiter {
            waker: waker.clone(),
            queued: Arc::clone(queued),
        });
    }
}

fn pop_next_queued_waiter(waiters: &mut Vec<SimWaiter>) -> Option<SimWaiter> {
    waiters.retain(|entry| entry.queued.load(Ordering::Acquire));
    if waiters.is_empty() {
        None
    } else {
        // Match the real transport channel wake order so tests exercise the
        // same fairness semantics instead of a test-only LIFO queue.
        Some(waiters.remove(0))
    }
}

#[derive(Debug)]
struct SimQueueState {
    queue: VecDeque<AuthenticatedSymbol>,
    delayed_in_flight: usize,
    sent_symbols: Vec<AuthenticatedSymbol>,
    send_wakers: Vec<SimWaiter>,
    recv_wakers: Vec<SimWaiter>,
    closed: bool,
    rng: DetRng,
}

#[derive(Debug)]
struct SimQueue {
    config: SimTransportConfig,
    state: Mutex<SimQueueState>,
}

impl SimQueue {
    fn new(config: SimTransportConfig) -> Self {
        let seed = config.seed.unwrap_or(1);
        Self {
            config,
            state: Mutex::new(SimQueueState {
                queue: VecDeque::new(),
                delayed_in_flight: 0,
                sent_symbols: Vec::new(),
                send_wakers: Vec::new(),
                recv_wakers: Vec::new(),
                closed: false,
                rng: DetRng::new(seed),
            }),
        }
    }

    fn close(&self) {
        let mut state = self.state.lock();
        state.closed = true;
        let send_wakers = std::mem::take(&mut state.send_wakers);
        let recv_wakers = std::mem::take(&mut state.recv_wakers);
        drop(state);
        for waiter in send_wakers {
            waiter.queued.store(false, Ordering::Release);
            waiter.waker.wake();
        }
        for waiter in recv_wakers {
            waiter.queued.store(false, Ordering::Release);
            waiter.waker.wake();
        }
    }
}

fn in_flight_len(state: &SimQueueState) -> usize {
    state.queue.len().saturating_add(state.delayed_in_flight)
}

#[derive(Debug)]
struct PendingSymbol {
    symbol: AuthenticatedSymbol,
    delay: Delay,
}

/// Deterministic symbol sink for testing send operations.
pub struct SimSymbolSink {
    inner: Arc<SimQueue>,
    delay: Option<Delay>,
    operation_count: usize,
    /// Tracks if we already have a waiter registered to prevent unbounded queue growth.
    waiter: Option<Arc<AtomicBool>>,
}

impl SimSymbolSink {
    /// Create a new deterministic sink with given configuration.
    #[must_use]
    pub fn new(config: SimTransportConfig) -> Self {
        Self::from_shared(Arc::new(SimQueue::new(config)))
    }

    fn from_shared(inner: Arc<SimQueue>) -> Self {
        Self {
            inner,
            delay: None,
            operation_count: 0,
            waiter: None,
        }
    }

    /// Get all symbols that were successfully "sent" (post-loss/dup/corrupt).
    #[must_use]
    pub fn sent_symbols(&self) -> Vec<AuthenticatedSymbol> {
        let state = self.inner.state.lock();
        state.sent_symbols.clone()
    }

    /// Get count of sent symbols.
    #[must_use]
    pub fn sent_count(&self) -> usize {
        let state = self.inner.state.lock();
        state.sent_symbols.len()
    }

    /// Clear the sent symbols buffer.
    pub fn clear(&self) {
        let mut state = self.inner.state.lock();
        state.sent_symbols.clear();
    }

    /// Reset the operation counter (for fail_after behavior).
    pub fn reset_operation_counter(&mut self) {
        self.operation_count = 0;
    }
}

/// Deterministic symbol stream for testing receive operations.
pub struct SimSymbolStream {
    inner: Arc<SimQueue>,
    pending: Option<PendingSymbol>,
    operation_count: usize,
    /// Tracks if we already have a waiter registered to prevent unbounded queue growth.
    waiter: Option<Arc<AtomicBool>>,
}

impl SimSymbolStream {
    /// Create a new deterministic stream with given configuration.
    #[must_use]
    pub fn new(config: SimTransportConfig) -> Self {
        Self::from_shared(Arc::new(SimQueue::new(config)))
    }

    /// Create from a list of symbols to deliver.
    #[must_use]
    pub fn from_symbols(symbols: Vec<AuthenticatedSymbol>, config: SimTransportConfig) -> Self {
        let shared = Arc::new(SimQueue::new(config));
        {
            let mut state = shared.state.lock();
            state.queue.extend(symbols);
        }
        Self::from_shared(shared)
    }

    fn from_shared(inner: Arc<SimQueue>) -> Self {
        Self {
            inner,
            pending: None,
            operation_count: 0,
            waiter: None,
        }
    }

    /// Add a symbol to the stream dynamically.
    pub fn push(&self, symbol: AuthenticatedSymbol) -> Result<(), StreamError> {
        let mut state = self.inner.state.lock();
        if state.closed {
            return Err(StreamError::Closed);
        }
        state.queue.push_back(symbol);
        let waiter = pop_next_queued_waiter(&mut state.recv_wakers);
        drop(state);
        if let Some(waiter) = waiter {
            waiter.queued.store(false, Ordering::Release);
            waiter.waker.wake();
        }
        Ok(())
    }

    /// Push multiple symbols.
    pub fn push_all(
        &self,
        symbols: impl IntoIterator<Item = AuthenticatedSymbol>,
    ) -> Result<(), StreamError> {
        for symbol in symbols {
            self.push(symbol)?;
        }
        Ok(())
    }

    /// Signal end of stream.
    pub fn close(&self) {
        self.inner.close();
    }

    /// Check if all symbols have been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let state = self.inner.state.lock();
        self.pending.is_none() && state.queue.is_empty()
    }

    /// Reset the operation counter (for fail_after behavior).
    pub fn reset_operation_counter(&mut self) {
        self.operation_count = 0;
    }
}

/// Deterministic channel sink (alias of SimSymbolSink).
pub type SimChannelSink = SimSymbolSink;

/// Deterministic channel stream (alias of SimSymbolStream).
pub type SimChannelStream = SimSymbolStream;

/// Create a connected deterministic transport pair (sender/receiver).
#[must_use]
pub fn sim_channel(config: SimTransportConfig) -> (SimChannelSink, SimChannelStream) {
    let shared = Arc::new(SimQueue::new(config));
    channel_from_shared(shared)
}

fn channel_from_shared(shared: Arc<SimQueue>) -> (SimChannelSink, SimChannelStream) {
    (
        SimChannelSink::from_shared(shared.clone()),
        SimChannelStream::from_shared(shared),
    )
}

fn closed_channel(config: SimTransportConfig) -> (SimChannelSink, SimChannelStream) {
    let shared = Arc::new(SimQueue::new(config));
    shared.close();
    channel_from_shared(shared)
}

impl SymbolSink for SimSymbolSink {
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let this = self.get_mut();
        let mut state = this.inner.state.lock();
        if state.closed {
            return Poll::Ready(Err(SinkError::Closed));
        }
        if this.inner.config.capacity == 0 {
            return Poll::Ready(Err(SinkError::BufferFull));
        }
        if in_flight_len(&state) < this.inner.config.capacity {
            // Mark as no longer queued if we had a waiter
            if let Some(waiter) = this.waiter.as_ref() {
                waiter.store(false, Ordering::Release);
            }
            Poll::Ready(Ok(()))
        } else {
            // Only register waiter once to prevent unbounded queue growth.
            let mut new_waiter = None;
            match this.waiter.as_ref() {
                Some(waiter) if !waiter.load(Ordering::Acquire) => {
                    // We were woken but capacity isn't available yet - re-register
                    waiter.store(true, Ordering::Release);
                    upsert_sim_waiter(&mut state.send_wakers, waiter, cx.waker());
                }
                Some(waiter) => {
                    // Refresh only when the executor changes this task's waker.
                    upsert_sim_waiter(&mut state.send_wakers, waiter, cx.waker());
                }
                None => {
                    // First time waiting - create new waiter
                    let waiter = Arc::new(AtomicBool::new(true));
                    upsert_sim_waiter(&mut state.send_wakers, &waiter, cx.waker());
                    new_waiter = Some(waiter);
                }
            }
            drop(state);
            if let Some(waiter) = new_waiter {
                this.waiter = Some(waiter);
            }
            Poll::Pending
        }
    }

    #[allow(clippy::useless_let_if_seq)] // Can't convert to expression due to early return
    fn poll_send(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), SinkError>> {
        let this = self.get_mut();

        let mut delay_ready = false;
        if let Some(delay) = this.delay.as_mut() {
            if delay.poll(cx).is_pending() {
                return Poll::Pending;
            }
            this.delay = None;
            delay_ready = true;
        }

        let inner = &this.inner;
        let delay_field = &mut this.delay;
        let op_count = &mut this.operation_count;

        if !delay_ready {
            let mut state = inner.state.lock();
            if state.closed {
                return Poll::Ready(Err(SinkError::Closed));
            }
            if inner.config.capacity == 0 || in_flight_len(&state) >= inner.config.capacity {
                return Poll::Ready(Err(SinkError::BufferFull));
            }
            if let Some(limit) = inner.config.fail_after {
                if *op_count >= limit {
                    return Poll::Ready(Err(SinkError::SendFailed {
                        reason: "fail_after limit reached".to_string(),
                    }));
                }
            }

            let delay = sample_latency(&inner.config, &mut state.rng);
            drop(state);
            if delay > Duration::ZERO {
                let mut delay = Delay::new(delay, inner.config.time_getter);
                if delay.poll(cx).is_pending() {
                    *delay_field = Some(delay);
                    return Poll::Pending;
                }
            }
        }

        let mut state = inner.state.lock();
        if state.closed {
            return Poll::Ready(Err(SinkError::Closed));
        }
        if inner.config.capacity == 0 || in_flight_len(&state) >= inner.config.capacity {
            return Poll::Ready(Err(SinkError::BufferFull));
        }
        if let Some(limit) = inner.config.fail_after {
            if *op_count >= limit {
                return Poll::Ready(Err(SinkError::SendFailed {
                    reason: "fail_after limit reached".to_string(),
                }));
            }
        }

        // Check loss/corruption/duplication while holding state lock
        let loss_rate = inner.config.loss_rate;
        let corruption_rate = inner.config.corruption_rate;
        let duplication_rate = inner.config.duplication_rate;
        let capacity = inner.config.capacity;

        let should_lose = chance(&mut state.rng, loss_rate);
        if should_lose {
            drop(state);
            *op_count = op_count.saturating_add(1);
            return Poll::Ready(Ok(()));
        }

        let mut delivered = symbol;
        if chance(&mut state.rng, corruption_rate) {
            delivered = corrupt_symbol(&delivered, &mut state.rng);
        }

        state.queue.push_back(delivered.clone());
        state.sent_symbols.push(delivered.clone());

        if chance(&mut state.rng, duplication_rate) && state.queue.len() < capacity {
            state.queue.push_back(delivered.clone());
            state.sent_symbols.push(delivered);
        }

        let recv_waiter = pop_next_queued_waiter(&mut state.recv_wakers);
        drop(state);
        *op_count = op_count.saturating_add(1);
        if let Some(waiter) = recv_waiter {
            waiter.queued.store(false, Ordering::Release);
            waiter.waker.wake();
        }

        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        self.inner.close();
        Poll::Ready(Ok(()))
    }
}

impl SymbolStream for SimSymbolStream {
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        let this = self.get_mut();

        if let Some(pending) = this.pending.as_mut() {
            if pending.delay.poll(cx).is_pending() {
                return Poll::Pending;
            }
            let pending = this.pending.take().expect("pending symbol missing");
            let send_waiter = {
                let mut state = this.inner.state.lock();
                debug_assert!(
                    state.delayed_in_flight > 0,
                    "delayed receive completed without reserving in-flight capacity"
                );
                state.delayed_in_flight = state.delayed_in_flight.saturating_sub(1);
                pop_next_queued_waiter(&mut state.send_wakers)
            };
            if let Some(waiter) = send_waiter {
                waiter.queued.store(false, Ordering::Release);
                waiter.waker.wake();
            }
            return Poll::Ready(Some(Ok(pending.symbol)));
        }

        if let Some(limit) = this.inner.config.fail_after {
            if this.operation_count >= limit {
                return Poll::Ready(Some(Err(StreamError::Reset)));
            }
        }

        let mut state = this.inner.state.lock();
        let symbol = if state.queue.is_empty() {
            None
        } else if this.inner.config.preserve_order {
            state.queue.pop_front()
        } else {
            let len = state.queue.len();
            let idx = state.rng.next_usize(len);
            state.queue.remove(idx)
        };

        if let Some(symbol) = symbol {
            this.operation_count = this.operation_count.saturating_add(1);
            // Mark as no longer queued if we had a waiter
            if let Some(waiter) = this.waiter.as_ref() {
                waiter.store(false, Ordering::Release);
            }
            let delay = sample_latency(&this.inner.config, &mut state.rng);
            let send_waiter = if delay > Duration::ZERO {
                state.delayed_in_flight = state.delayed_in_flight.saturating_add(1);
                None
            } else {
                pop_next_queued_waiter(&mut state.send_wakers)
            };
            drop(state);
            if let Some(waiter) = send_waiter {
                waiter.queued.store(false, Ordering::Release);
                waiter.waker.wake();
            }
            if delay > Duration::ZERO {
                let pending = PendingSymbol {
                    symbol,
                    delay: Delay::new(delay, this.inner.config.time_getter),
                };
                this.pending = Some(pending);
                if this
                    .pending
                    .as_mut()
                    .expect("pending symbol missing")
                    .delay
                    .poll(cx)
                    .is_pending()
                {
                    return Poll::Pending;
                }
                let pending = this.pending.take().expect("pending symbol missing");
                let send_waiter = {
                    let mut state = this.inner.state.lock();
                    debug_assert!(
                        state.delayed_in_flight > 0,
                        "immediate delayed delivery completed without reserving in-flight capacity"
                    );
                    state.delayed_in_flight = state.delayed_in_flight.saturating_sub(1);
                    pop_next_queued_waiter(&mut state.send_wakers)
                };
                if let Some(waiter) = send_waiter {
                    waiter.queued.store(false, Ordering::Release);
                    waiter.waker.wake();
                }
                return Poll::Ready(Some(Ok(pending.symbol)));
            }
            return Poll::Ready(Some(Ok(symbol)));
        }

        if state.closed {
            return Poll::Ready(None);
        }

        // Only register waiter once to prevent unbounded queue growth.
        let mut new_waiter = None;
        match this.waiter.as_ref() {
            Some(waiter) if !waiter.load(Ordering::Acquire) => {
                // We were woken but no message yet - re-register
                waiter.store(true, Ordering::Release);
                upsert_sim_waiter(&mut state.recv_wakers, waiter, cx.waker());
            }
            Some(waiter) => {
                // Refresh only when the executor changes this task's waker.
                upsert_sim_waiter(&mut state.recv_wakers, waiter, cx.waker());
            }
            None => {
                // First time waiting - create new waiter
                let waiter = Arc::new(AtomicBool::new(true));
                upsert_sim_waiter(&mut state.recv_wakers, &waiter, cx.waker());
                new_waiter = Some(waiter);
            }
        }
        drop(state);
        if let Some(waiter) = new_waiter {
            this.waiter = Some(waiter);
        }
        Poll::Pending
    }

    #[allow(clippy::significant_drop_tightening)] // Lock release timing is fine
    fn size_hint(&self) -> (usize, Option<usize>) {
        let state = self.inner.state.lock();
        let len = state.queue.len() + usize::from(self.pending.is_some());
        (len, Some(len))
    }

    fn is_exhausted(&self) -> bool {
        let state = self.inner.state.lock();
        self.pending.is_none() && state.closed && state.queue.is_empty()
    }
}

impl Drop for SimSymbolStream {
    fn drop(&mut self) {
        if self.pending.is_none() {
            return;
        }

        let send_waiter = {
            let mut state = self.inner.state.lock();
            if state.delayed_in_flight == 0 {
                None
            } else {
                state.delayed_in_flight -= 1;
                pop_next_queued_waiter(&mut state.send_wakers)
            }
        };
        if let Some(waiter) = send_waiter {
            waiter.queued.store(false, Ordering::Release);
            waiter.waker.wake();
        }
    }
}

fn chance(rng: &mut DetRng, probability: f64) -> bool {
    if probability <= 0.0 {
        return false;
    }
    if probability >= 1.0 {
        return true;
    }
    let sample = f64::from(rng.next_u32()) / f64::from(u32::MAX);
    sample < probability
}

fn sample_latency(config: &SimTransportConfig, rng: &mut DetRng) -> Duration {
    if config.base_latency == Duration::ZERO && config.latency_jitter == Duration::ZERO {
        return Duration::ZERO;
    }
    let jitter_nanos = std::cmp::min(config.latency_jitter.as_nanos(), u128::from(u64::MAX)) as u64;
    let jitter = if jitter_nanos == 0 {
        Duration::ZERO
    } else {
        let extra = if jitter_nanos == u64::MAX {
            rng.next_u64()
        } else {
            rng.next_u64() % (jitter_nanos + 1)
        };
        Duration::from_nanos(extra)
    };
    config.base_latency.saturating_add(jitter)
}

fn corrupt_symbol(symbol: &AuthenticatedSymbol, rng: &mut DetRng) -> AuthenticatedSymbol {
    let tag = *symbol.tag();
    let original = symbol.symbol().clone();
    let mut data = original.data().to_vec();
    if data.is_empty() {
        data.push(0xFF);
    } else {
        let idx = rng.next_usize(data.len());
        data[idx] ^= 0xFF;
    }
    let corrupted = Symbol::new(original.id(), data, original.kind());
    // Corruption invalidates any prior verification; downstream consumers must
    // re-verify the mutated payload against its tag.
    AuthenticatedSymbol::from_parts(corrupted, tag)
}

#[cfg(test)]
#[path = "mock_inline_tests.rs"]
mod tests;
