//! Deterministic transport simulator for testing.
//!
//! This module provides in-memory, deterministic transport components for
//! exercising transport behavior without real I/O. The module name is legacy;
//! types are explicitly labeled as simulator/test components.

use crate::security::authenticated::AuthenticatedSymbol;
use crate::transport::error::{SinkError, StreamError};
use crate::transport::{SymbolSink, SymbolStream};
use crate::types::Symbol;
use crate::util::DetRng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

/// Configuration for simulated transport behavior.
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
        }
    }
}

impl SimTransportConfig {
    /// Create config for reliable, zero-latency transport (unit tests).
    #[must_use]
    pub fn reliable() -> Self {
        Self::default()
    }

    /// Create config simulating a lossy network.
    #[must_use]
    pub fn lossy(loss_rate: f64) -> Self {
        Self {
            loss_rate,
            ..Self::default()
        }
    }

    /// Create config simulating network latency.
    #[must_use]
    pub fn with_latency(base: Duration, jitter: Duration) -> Self {
        Self {
            base_latency: base,
            latency_jitter: jitter,
            ..Self::default()
        }
    }

    /// Create deterministic config for reproducible tests.
    #[must_use]
    pub fn deterministic(seed: u64) -> Self {
        Self {
            seed: Some(seed),
            ..Self::default()
        }
    }
}

/// Node identifier for simulated network topologies.
pub type NodeId = u64;

/// Simulated link configuration between two nodes.
#[derive(Debug, Clone)]
pub struct SimLink {
    /// Transport behavior for this link.
    pub config: SimTransportConfig,
}

/// Simulated network topology for transport tests.
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
        if n == 0 {
            return Self {
                nodes,
                links,
                default_config: config,
            };
        }
        for i in 0..n {
            nodes.insert(i as NodeId);
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

#[derive(Debug)]
struct DelayState {
    waker: Option<Waker>,
    spawned: bool,
}

#[derive(Debug)]
struct Delay {
    deadline: Instant,
    state: Arc<Mutex<DelayState>>,
}

impl Delay {
    fn new(duration: Duration) -> Self {
        let now = Instant::now();
        let deadline = now.checked_add(duration).unwrap_or(now);
        Self {
            deadline,
            state: Arc::new(Mutex::new(DelayState {
                waker: None,
                spawned: false,
            })),
        }
    }

    fn poll(&self, cx: &Context<'_>) -> Poll<()> {
        if Instant::now() >= self.deadline {
            return Poll::Ready(());
        }

        let mut state = self.state.lock().expect("mock delay lock poisoned");
        state.waker = Some(cx.waker().clone());

        if !state.spawned {
            state.spawned = true;
            let deadline = self.deadline;
            let state_clone = Arc::clone(&self.state);
            drop(state);
            // ubs:ignore — intentional fire-and-forget: short-lived timer thread
            // self-terminates after sleeping; JoinHandle detach is correct here
            std::thread::spawn(move || {
                let now = Instant::now();
                if deadline > now {
                    std::thread::sleep(deadline - now);
                }
                let mut state = state_clone.lock().expect("mock delay lock poisoned");
                if let Some(waker) = state.waker.take() {
                    waker.wake();
                }
                state.spawned = false;
            });
        }

        Poll::Pending
    }
}

/// A waiter entry with tracking flag to prevent unbounded queue growth.
#[derive(Debug)]
struct SimWaiter {
    waker: Waker,
    /// Flag indicating if this waiter is still queued. When woken, this is set to false.
    queued: Arc<AtomicBool>,
}

#[derive(Debug)]
struct SimQueueState {
    queue: VecDeque<AuthenticatedSymbol>,
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
                sent_symbols: Vec::new(),
                send_wakers: Vec::new(),
                recv_wakers: Vec::new(),
                closed: false,
                rng: DetRng::new(seed),
            }),
        }
    }

    fn close(&self) {
        let mut state = self.state.lock().expect("sim queue lock poisoned");
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

#[derive(Debug)]
struct PendingSymbol {
    symbol: AuthenticatedSymbol,
    delay: Delay,
}

/// Simulated symbol sink for testing send operations.
pub struct SimSymbolSink {
    inner: Arc<SimQueue>,
    delay: Option<Delay>,
    operation_count: usize,
    /// Tracks if we already have a waiter registered to prevent unbounded queue growth.
    waiter: Option<Arc<AtomicBool>>,
}

impl SimSymbolSink {
    /// Create a new simulated sink with given configuration.
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
        let state = self.inner.state.lock().expect("sim queue lock poisoned");
        state.sent_symbols.clone()
    }

    /// Get count of sent symbols.
    #[must_use]
    pub fn sent_count(&self) -> usize {
        let state = self.inner.state.lock().expect("sim queue lock poisoned");
        state.sent_symbols.len()
    }

    /// Clear the sent symbols buffer.
    pub fn clear(&self) {
        let mut state = self.inner.state.lock().expect("sim queue lock poisoned");
        state.sent_symbols.clear();
    }

    /// Reset the operation counter (for fail_after behavior).
    pub fn reset_operation_counter(&mut self) {
        self.operation_count = 0;
    }
}

/// Simulated symbol stream for testing receive operations.
pub struct SimSymbolStream {
    inner: Arc<SimQueue>,
    pending: Option<PendingSymbol>,
    operation_count: usize,
    /// Tracks if we already have a waiter registered to prevent unbounded queue growth.
    waiter: Option<Arc<AtomicBool>>,
}

impl SimSymbolStream {
    /// Create a new simulated stream with given configuration.
    #[must_use]
    pub fn new(config: SimTransportConfig) -> Self {
        Self::from_shared(Arc::new(SimQueue::new(config)))
    }

    /// Create from a list of symbols to deliver.
    #[must_use]
    pub fn from_symbols(symbols: Vec<AuthenticatedSymbol>, config: SimTransportConfig) -> Self {
        let shared = Arc::new(SimQueue::new(config));
        {
            let mut state = shared.state.lock().expect("sim queue lock poisoned");
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
        let mut state = self.inner.state.lock().expect("sim queue lock poisoned");
        if state.closed {
            return Err(StreamError::Closed);
        }
        state.queue.push_back(symbol);
        let waiter = state.recv_wakers.pop();
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
        let state = self.inner.state.lock().expect("sim queue lock poisoned");
        state.queue.is_empty()
    }

    /// Reset the operation counter (for fail_after behavior).
    pub fn reset_operation_counter(&mut self) {
        self.operation_count = 0;
    }
}

/// Simulated channel sink (alias of SimSymbolSink).
pub type SimChannelSink = SimSymbolSink;

/// Simulated channel stream (alias of SimSymbolStream).
pub type SimChannelStream = SimSymbolStream;

/// Create a connected simulated transport pair (sender/receiver).
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
        let mut state = this.inner.state.lock().expect("mock queue lock poisoned");
        if state.closed {
            return Poll::Ready(Err(SinkError::Closed));
        }
        if state.queue.len() < this.inner.config.capacity {
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
                    state.send_wakers.push(SimWaiter {
                        waker: cx.waker().clone(),
                        queued: Arc::clone(waiter),
                    });
                }
                Some(_) => {} // Still queued, no need to re-register
                None => {
                    // First time waiting - create new waiter
                    let waiter = Arc::new(AtomicBool::new(true));
                    state.send_wakers.push(SimWaiter {
                        waker: cx.waker().clone(),
                        queued: Arc::clone(&waiter),
                    });
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
        if let Some(delay) = this.delay.as_ref() {
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
            let mut state = inner.state.lock().expect("mock queue lock poisoned");
            if state.closed {
                return Poll::Ready(Err(SinkError::Closed));
            }
            if inner.config.capacity == 0 || state.queue.len() >= inner.config.capacity {
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
                let delay = Delay::new(delay);
                if delay.poll(cx).is_pending() {
                    *delay_field = Some(delay);
                    return Poll::Pending;
                }
            }
        }

        let mut state = inner.state.lock().expect("mock queue lock poisoned");
        if state.closed {
            return Poll::Ready(Err(SinkError::Closed));
        }
        if inner.config.capacity == 0 || state.queue.len() >= inner.config.capacity {
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

        let recv_waiter = state.recv_wakers.pop();
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

        if let Some(pending) = this.pending.as_ref() {
            if pending.delay.poll(cx).is_pending() {
                return Poll::Pending;
            }
            let pending = this.pending.take().expect("pending symbol missing");
            return Poll::Ready(Some(Ok(pending.symbol)));
        }

        if let Some(limit) = this.inner.config.fail_after {
            if this.operation_count >= limit {
                return Poll::Ready(Some(Err(StreamError::Reset)));
            }
        }

        let mut state = this.inner.state.lock().expect("mock queue lock poisoned");
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
            let send_waiter = state.send_wakers.pop();
            drop(state);
            if let Some(waiter) = send_waiter {
                waiter.queued.store(false, Ordering::Release);
                waiter.waker.wake();
            }
            if delay > Duration::ZERO {
                let pending = PendingSymbol {
                    symbol,
                    delay: Delay::new(delay),
                };
                this.pending = Some(pending);
                if this
                    .pending
                    .as_ref()
                    .expect("pending symbol missing")
                    .delay
                    .poll(cx)
                    .is_pending()
                {
                    return Poll::Pending;
                }
                let pending = this.pending.take().expect("pending symbol missing");
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
                state.recv_wakers.push(SimWaiter {
                    waker: cx.waker().clone(),
                    queued: Arc::clone(waiter),
                });
            }
            Some(_) => {} // Still queued, no need to re-register
            None => {
                // First time waiting - create new waiter
                let waiter = Arc::new(AtomicBool::new(true));
                state.recv_wakers.push(SimWaiter {
                    waker: cx.waker().clone(),
                    queued: Arc::clone(&waiter),
                });
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
        let state = self.inner.state.lock().expect("mock queue lock poisoned");
        let len = state.queue.len() + usize::from(self.pending.is_some());
        (len, Some(len))
    }

    fn is_exhausted(&self) -> bool {
        let state = self.inner.state.lock().expect("mock queue lock poisoned");
        self.pending.is_none() && state.closed && state.queue.is_empty()
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
    let verified = symbol.is_verified();
    let original = symbol.symbol().clone();
    let mut data = original.data().to_vec();
    if data.is_empty() {
        data.push(0xFF);
    } else {
        let idx = rng.next_usize(data.len());
        data[idx] ^= 0xFF;
    }
    let corrupted = Symbol::new(original.id(), data, original.kind());
    if verified {
        AuthenticatedSymbol::new_verified(corrupted, tag)
    } else {
        AuthenticatedSymbol::from_parts(corrupted, tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::tag::AuthenticationTag;
    use crate::transport::{SymbolSinkExt, SymbolStreamExt};
    use crate::types::{Symbol, SymbolId, SymbolKind};
    use futures_lite::future;
    use std::task::Poll;

    fn create_symbol(i: u32) -> AuthenticatedSymbol {
        let id = SymbolId::new_for_test(1, 0, i);
        let symbol = Symbol::new(id, vec![i as u8], SymbolKind::Source);
        let tag = AuthenticationTag::zero();
        AuthenticatedSymbol::new_verified(symbol, tag)
    }

    #[test]
    fn test_sim_channel_reliable() {
        let (mut sink, mut stream) = sim_channel(SimTransportConfig::reliable());
        let s1 = create_symbol(1);
        let s2 = create_symbol(2);

        future::block_on(async {
            sink.send(s1.clone()).await.unwrap();
            sink.send(s2.clone()).await.unwrap();

            let r1 = stream.next().await.unwrap().unwrap();
            let r2 = stream.next().await.unwrap().unwrap();

            assert_eq!(r1, s1);
            assert_eq!(r2, s2);
        });
    }

    fn run_lossy(seed: u64) -> usize {
        let config = SimTransportConfig {
            loss_rate: 0.5,
            seed: Some(seed),
            capacity: 1024,
            ..SimTransportConfig::default()
        };
        let (mut sink, mut stream) = sim_channel(config);

        future::block_on(async {
            for i in 0..100 {
                sink.send(create_symbol(i)).await.unwrap();
            }
            sink.close().await.unwrap();

            let mut count = 0usize;
            while let Some(item) = stream.next().await {
                if item.is_ok() {
                    count += 1;
                }
            }
            count
        })
    }

    #[test]
    fn test_sim_channel_loss_deterministic() {
        let count1 = run_lossy(42);
        let count2 = run_lossy(42);
        assert_eq!(count1, count2);
        assert!(count1 < 100);
    }

    #[test]
    fn test_sim_channel_duplication() {
        let config = SimTransportConfig {
            duplication_rate: 1.0,
            capacity: 128,
            ..SimTransportConfig::deterministic(7)
        };
        let (mut sink, mut stream) = sim_channel(config);

        future::block_on(async {
            for i in 0..10 {
                sink.send(create_symbol(i)).await.unwrap();
            }
            sink.close().await.unwrap();

            let mut count = 0usize;
            while let Some(item) = stream.next().await {
                if item.is_ok() {
                    count += 1;
                }
            }
            assert_eq!(count, 20);
        });
    }

    #[test]
    fn test_sim_channel_fail_after() {
        let config = SimTransportConfig {
            fail_after: Some(2),
            ..SimTransportConfig::default()
        };
        let (mut sink, _stream) = sim_channel(config);

        future::block_on(async {
            sink.send(create_symbol(1)).await.unwrap();
            sink.send(create_symbol(2)).await.unwrap();
            let err = sink.send(create_symbol(3)).await.unwrap_err();
            assert!(matches!(err, SinkError::SendFailed { .. }));
        });
    }

    #[test]
    fn test_sim_channel_backpressure_pending() {
        let config = SimTransportConfig {
            capacity: 1,
            ..SimTransportConfig::default()
        };
        let (mut sink, _stream) = sim_channel(config);

        future::block_on(async {
            sink.send(create_symbol(1)).await.unwrap();
        });

        let mut poll_result = None;
        future::block_on(future::poll_fn(|cx| {
            poll_result = Some(Pin::new(&mut sink).poll_ready(cx));
            Poll::Ready(())
        }));

        assert!(matches!(poll_result, Some(Poll::Pending)));
    }
}
