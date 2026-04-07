//! Load balancing strategies for service sets.
//!
//! Distributes requests across multiple backends using configurable strategies:
//!
//! - [`RoundRobin`]: Rotates through backends in order.
//! - [`PowerOfTwoChoices`]: Picks the least-loaded of two random backends.
//! - [`Weighted`]: Distributes proportionally to configured weights.
//!
//! # Integration with Discovery
//!
//! Load balancers can be paired with a [`Discover`](super::Discover) instance
//! to dynamically add and remove backends as the topology changes.

use parking_lot::Mutex;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use super::Service;
use super::discover::{Change, Discover};

fn tracked_probe_waker() -> (Waker, Arc<AtomicBool>) {
    struct TrackWaker(Arc<AtomicBool>);

    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let woke = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(TrackWaker(Arc::clone(&woke))));
    (waker, woke)
}

fn poll_service_ready_once<S, Request>(service: &mut S) -> (Poll<Result<(), S::Error>>, bool)
where
    S: Service<Request>,
{
    let (waker, woke) = tracked_probe_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = service.poll_ready(&mut cx);
    (poll, woke.load(Ordering::SeqCst))
}

fn backend_matches_service<S>(backend: &Backend<S>, expected: &S) -> bool
where
    S: Eq,
{
    backend.service.lock().eq(expected)
}

fn backends_contain_service<S>(backends: &[Arc<Backend<S>>], expected: &S) -> bool
where
    S: Eq,
{
    backends
        .iter()
        .any(|backend| backend_matches_service(backend, expected))
}

// ─── Load metric ──────────────────────────────────────────────────────────

/// Per-backend load tracking.
struct LoadMetric {
    /// Number of in-flight requests.
    in_flight: AtomicU64,
}

impl LoadMetric {
    fn new() -> Self {
        Self {
            in_flight: AtomicU64::new(0),
        }
    }

    fn load(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
    }

    fn increment(&self) {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
    }

    fn decrement(&self) {
        // Use fetch_update to prevent underflow wrapping.
        let _ = self
            .in_flight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }
}

/// Ensures an in-flight load increment is rolled back if dispatch unwinds
/// before ownership transfers to a `LoadBalancedFuture`.
struct LoadMetricGuard {
    load_metric: Option<Arc<LoadMetric>>,
}

impl LoadMetricGuard {
    fn new(load_metric: Arc<LoadMetric>) -> Self {
        load_metric.increment();
        Self {
            load_metric: Some(load_metric),
        }
    }

    fn defuse(mut self) -> Arc<LoadMetric> {
        self.load_metric
            .take()
            .expect("load metric guard must still hold the metric")
    }
}

impl Drop for LoadMetricGuard {
    fn drop(&mut self) {
        if let Some(load_metric) = self.load_metric.take() {
            load_metric.decrement();
        }
    }
}

/// Ensures an in-flight load is released if a future poll unwinds or completes
/// before the future is restored to the balancer wrapper.
struct LoadMetricPollGuard {
    load_metric: Option<Arc<LoadMetric>>,
    release_on_drop: bool,
}

impl LoadMetricPollGuard {
    fn new(load_metric: Option<Arc<LoadMetric>>) -> Self {
        Self {
            load_metric,
            release_on_drop: true,
        }
    }

    fn restore(mut self) -> Option<Arc<LoadMetric>> {
        self.release_on_drop = false;
        self.load_metric.take()
    }
}

impl Drop for LoadMetricPollGuard {
    fn drop(&mut self) {
        if self.release_on_drop {
            if let Some(load_metric) = self.load_metric.take() {
                load_metric.decrement();
            }
        }
    }
}

// ─── Strategy trait ───────────────────────────────────────────────────────

/// Selects which backend to dispatch a request to.
pub trait Strategy: fmt::Debug + Send + Sync {
    /// Select a backend index from the available set.
    ///
    /// `loads` contains the current in-flight count for each backend.
    /// Returns `None` if no backends are available.
    fn pick(&self, loads: &[u64]) -> Option<usize>;

    /// Returns whether `index` is a backend this strategy is allowed to select.
    ///
    /// `call_balanced()` uses this during readiness fallback probing so
    /// strategy-level exclusion rules continue to hold even when the first
    /// picked backend is not immediately ready.
    fn permits_index(&self, index: usize, loads: &[u64]) -> bool {
        index < loads.len()
    }

    /// Reconciles strategy topology state with an already-materialized backend set.
    ///
    /// This is used during constructor-time initialization, where the balancer
    /// starts with an existing backend list rather than replaying insert events.
    fn sync_backend_count(&self, _count: usize) {}

    /// Notifies the strategy that a backend was inserted at `index`.
    ///
    /// Strategies with per-backend state can override this to keep their
    /// topology metadata aligned with the balancer's backend list.
    fn on_backend_inserted(&self, _index: usize) {}

    /// Notifies the strategy that a backend was removed from `index`.
    ///
    /// Strategies with per-backend state can override this to keep their
    /// topology metadata aligned with the balancer's backend list.
    fn on_backend_removed(&self, _index: usize) {}
}

// ─── RoundRobin ───────────────────────────────────────────────────────────

/// Cycles through backends in sequential order.
#[derive(Debug)]
pub struct RoundRobin {
    next: AtomicUsize,
}

impl RoundRobin {
    /// Create a new round-robin strategy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next: AtomicUsize::new(0),
        }
    }
}

impl Default for RoundRobin {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for RoundRobin {
    fn pick(&self, loads: &[u64]) -> Option<usize> {
        if loads.is_empty() {
            return None;
        }
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % loads.len();
        Some(idx)
    }
}

// ─── PowerOfTwoChoices ────────────────────────────────────────────────────

/// Picks the least-loaded of two randomly chosen backends.
///
/// This provides near-optimal load distribution with O(1) selection,
/// avoiding the thundering-herd problem of pure random selection.
#[derive(Debug)]
pub struct PowerOfTwoChoices {
    counter: AtomicUsize,
}

impl PowerOfTwoChoices {
    /// Create a new P2C strategy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counter: AtomicUsize::new(0),
        }
    }

    /// Simple deterministic scatter using a counter-based hash.
    fn pseudo_random(&self, n: usize) -> usize {
        let c = self.counter.fetch_add(1, Ordering::Relaxed) as u64;
        // Use a 64-bit multiplicative hash, then fold it back into usize so
        // the spread stays deterministic on both 32-bit and 64-bit targets.
        let hash = c
            .wrapping_mul(6_364_136_223_846_793_005_u64)
            .wrapping_add(1);
        let folded = hash ^ (hash >> 32);
        (folded as usize) % n
    }
}

impl Default for PowerOfTwoChoices {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for PowerOfTwoChoices {
    fn pick(&self, loads: &[u64]) -> Option<usize> {
        match loads.len() {
            0 => None,
            1 => Some(0),
            n => {
                let a = self.pseudo_random(n);
                let mut b = self.pseudo_random(n);
                // Ensure b != a when possible.
                if b == a {
                    b = (a + 1) % n;
                }
                if loads[a] <= loads[b] {
                    Some(a)
                } else {
                    Some(b)
                }
            }
        }
    }
}

// ─── Weighted ─────────────────────────────────────────────────────────────

/// Distributes requests proportionally to configured weights.
///
/// Backends with higher weights receive proportionally more traffic.
/// Uses smooth weighted round-robin (SWRR) for even distribution.
#[derive(Debug)]
pub struct Weighted {
    state: Mutex<WeightedState>,
}

struct WeightedState {
    weights: Vec<u32>,
    current_weights: Vec<i64>,
    active_backend_count: usize,
}

impl fmt::Debug for WeightedState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WeightedState")
            .field("weights", &self.weights)
            .field("current_weights", &self.current_weights)
            .field("active_backend_count", &self.active_backend_count)
            .finish()
    }
}

impl Weighted {
    /// Create a new weighted strategy with the given weights.
    ///
    /// Each weight corresponds to a backend index. A weight of 0 means
    /// the backend will never be selected.
    #[must_use]
    pub fn new(weights: Vec<u32>) -> Self {
        let len = weights.len();
        Self {
            state: Mutex::new(WeightedState {
                weights,
                current_weights: vec![0; len],
                active_backend_count: len,
            }),
        }
    }
}

impl Strategy for Weighted {
    fn pick(&self, loads: &[u64]) -> Option<usize> {
        if loads.is_empty() {
            return None;
        }

        let mut state = self.state.lock();
        let len = loads.len().min(state.active_backend_count);
        if len == 0 || state.weights.is_empty() {
            return None;
        }

        // Ensure state vectors cover at least `len` entries before indexing.
        if state.weights.len() < len {
            state.weights.resize(len, 1);
        }
        if state.current_weights.len() < len {
            state.current_weights.resize(len, 0);
        }

        let total_weight: i64 = state.weights[..len].iter().map(|&w| i64::from(w)).sum();

        if total_weight == 0 {
            return None;
        }

        // SWRR: add effective weight, pick max, subtract total.
        let mut best_idx = 0;
        let mut best_weight = i64::MIN;

        for i in 0..len {
            let ew = i64::from(state.weights[i]);
            state.current_weights[i] += ew;
            if state.current_weights[i] > best_weight {
                best_weight = state.current_weights[i];
                best_idx = i;
            }
        }

        state.current_weights[best_idx] -= total_weight;
        drop(state);

        Some(best_idx)
    }

    fn permits_index(&self, index: usize, loads: &[u64]) -> bool {
        if index >= loads.len() {
            return false;
        }

        let state = self.state.lock();
        if index >= state.active_backend_count {
            return false;
        }

        state
            .weights
            .get(index)
            .copied()
            .is_some_and(|weight| weight > 0)
    }

    fn sync_backend_count(&self, count: usize) {
        let mut state = self.state.lock();
        if state.weights.len() < count {
            state.weights.resize(count, 1);
        }
        state.current_weights.resize(count, 0);
        state.active_backend_count = count;
    }

    fn on_backend_inserted(&self, index: usize) {
        let mut state = self.state.lock();
        let index = index.min(state.active_backend_count);
        if index < state.active_backend_count || index >= state.weights.len() {
            state.weights.insert(index, 1);
        }
        state.current_weights.insert(index, 0);
        state.active_backend_count += 1;
    }

    fn on_backend_removed(&self, index: usize) {
        let mut state = self.state.lock();
        if index >= state.active_backend_count {
            return;
        }

        state.active_backend_count -= 1;
        if index < state.weights.len() {
            state.weights.remove(index);
        }
        if index < state.current_weights.len() {
            state.current_weights.remove(index);
        }
    }
}

// ─── LoadBalancer ─────────────────────────────────────────────────────────

/// Load balancing error.
#[derive(Debug)]
pub enum LoadBalanceError<E> {
    /// No backends available.
    NoBackends,
    /// Backends exist, but none are currently ready to accept work.
    NoReadyBackends,
    /// The load-balanced future was polled after it had already completed.
    PolledAfterCompletion,
    /// Inner service error.
    Inner(E),
}

impl<E: fmt::Display> fmt::Display for LoadBalanceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBackends => write!(f, "no backends available"),
            Self::NoReadyBackends => write!(f, "no ready backends available"),
            Self::PolledAfterCompletion => {
                write!(f, "load-balanced future polled after completion")
            }
            Self::Inner(e) => write!(f, "backend error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for LoadBalanceError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoBackends | Self::NoReadyBackends | Self::PolledAfterCompletion => None,
            Self::Inner(e) => Some(e),
        }
    }
}

/// A load-balanced service that distributes requests across backends.
///
/// Backends are managed as a dynamic set: use [`update_from_discover`](Self::update_from_discover)
/// to apply topology changes from a [`Discover`] source.
pub struct LoadBalancer<S, T: Strategy> {
    backends: Mutex<Vec<Arc<Backend<S>>>>,
    strategy: T,
}

struct Backend<S> {
    service: Mutex<S>,
    load: Arc<LoadMetric>,
}

impl<S: fmt::Debug, T: Strategy> fmt::Debug for LoadBalancer<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let backends = self.backends.lock();
        f.debug_struct("LoadBalancer")
            .field("backends", &backends.len())
            .field("strategy", &self.strategy)
            .finish()
    }
}

impl<S, T: Strategy> LoadBalancer<S, T> {
    /// Create a new load balancer with the given strategy and backends.
    #[must_use]
    pub fn new(strategy: T, backends: Vec<S>) -> Self {
        let backends: Vec<_> = backends
            .into_iter()
            .map(|s| {
                Arc::new(Backend {
                    service: Mutex::new(s),
                    load: Arc::new(LoadMetric::new()),
                })
            })
            .collect();
        strategy.sync_backend_count(backends.len());
        Self {
            backends: Mutex::new(backends),
            strategy,
        }
    }

    /// Create an empty load balancer.
    #[must_use]
    pub fn empty(strategy: T) -> Self {
        strategy.sync_backend_count(0);
        Self {
            backends: Mutex::new(Vec::new()),
            strategy,
        }
    }

    /// Add a backend service.
    pub fn push(&self, service: S) {
        let mut backends = self.backends.lock();
        let index = backends.len();
        backends.push(Arc::new(Backend {
            service: Mutex::new(service),
            load: Arc::new(LoadMetric::new()),
        }));
        drop(backends);
        self.strategy.on_backend_inserted(index);
    }
    /// Get the number of backends.
    pub fn len(&self) -> usize {
        self.backends.lock().len()
    }

    /// Returns true if there are no backends.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.backends.lock().is_empty()
    }

    /// Get per-backend in-flight counts.
    #[must_use]
    pub fn loads(&self) -> Vec<u64> {
        self.backends.lock().iter().map(|b| b.load.load()).collect()
    }

    /// Get the strategy reference.
    #[must_use]
    pub fn strategy(&self) -> &T {
        &self.strategy
    }
}

impl<S, T: Strategy> LoadBalancer<S, T>
where
    S: Clone,
{
    /// Remove a backend by index, returning the service.
    pub fn remove(&self, index: usize) -> Option<S> {
        let mut backends = self.backends.lock();
        let backend = if index < backends.len() {
            let removed = backends.remove(index);
            self.strategy.on_backend_removed(index);
            Some(removed)
        } else {
            None
        };
        drop(backends);
        backend.map(|backend| backend.service.lock().clone())
    }
}

impl<S, T: Strategy> LoadBalancer<S, T>
where
    S: Eq,
{
    /// Apply topology changes from a [`Discover`] source.
    ///
    /// This method is available when the discovered key type matches the
    /// backend value stored by the balancer.
    pub fn update_from_discover<D>(&self, discover: &D) -> Result<(), DiscoverUpdateError<D::Error>>
    where
        D: Discover<Key = S>,
    {
        let changes = discover
            .poll_discover()
            .map_err(DiscoverUpdateError::Discover)?;
        let endpoints = discover.endpoints();

        let mut backends = self.backends.lock();
        for change in changes {
            match change {
                Change::Insert(service) => {
                    if backends_contain_service(&backends, &service) {
                        continue;
                    }

                    let index = backends.len();
                    backends.push(Arc::new(Backend {
                        service: Mutex::new(service),
                        load: Arc::new(LoadMetric::new()),
                    }));
                    self.strategy.on_backend_inserted(index);
                }
                Change::Remove(service) => {
                    if let Some(index) = backends
                        .iter()
                        .position(|backend| backend_matches_service(backend, &service))
                    {
                        backends.remove(index);
                        self.strategy.on_backend_removed(index);
                    }
                }
            }
        }

        let mut index = 0;
        while index < backends.len() {
            if endpoints
                .iter()
                .any(|service| backend_matches_service(&backends[index], service))
            {
                index += 1;
                continue;
            }

            backends.remove(index);
            self.strategy.on_backend_removed(index);
        }

        for service in endpoints {
            if backends_contain_service(&backends, &service) {
                continue;
            }

            let index = backends.len();
            backends.push(Arc::new(Backend {
                service: Mutex::new(service),
                load: Arc::new(LoadMetric::new()),
            }));
            self.strategy.on_backend_inserted(index);
        }

        drop(backends);

        Ok(())
    }
}

impl<S, T: Strategy> LoadBalancer<S, T> {
    /// Pick a backend and dispatch a request through it.
    ///
    /// Returns an error if no backends are available or the strategy
    /// cannot select a backend.
    pub fn call_balanced<Request>(
        &self,
        req: Request,
    ) -> Result<LoadBalancedFuture<S::Future, S>, LoadBalanceError<S::Error>>
    where
        S: Service<Request>,
    {
        let backends = self.backends.lock();

        if backends.is_empty() {
            return Err(LoadBalanceError::NoBackends);
        }

        let loads: Vec<u64> = backends.iter().map(|b| b.load.load()).collect();
        let backend_handles = backends.clone();
        let idx = self
            .strategy
            .pick(&loads)
            .ok_or(LoadBalanceError::NoReadyBackends)?;
        drop(backends);

        if idx >= backend_handles.len() {
            return Err(LoadBalanceError::NoBackends);
        }

        let mut first_error = None;
        let mut req = Some(req);

        for offset in 0..backend_handles.len() {
            let candidate_idx = (idx + offset) % backend_handles.len();
            if !self.strategy.permits_index(candidate_idx, &loads) {
                continue;
            }
            let backend = &backend_handles[candidate_idx];
            let mut svc = backend.service.lock();

            let (mut readiness, woke_during_poll) =
                poll_service_ready_once::<S, Request>(&mut *svc);
            if matches!(readiness, Poll::Pending) && woke_during_poll {
                // Preserve same-turn readiness edges from backends that
                // self-wake during `poll_ready` and become callable on the
                // immediate follow-up poll, without spinning forever on a
                // repeatedly self-waking-but-still-pending backend.
                let (next_readiness, _) = poll_service_ready_once::<S, Request>(&mut *svc);
                readiness = next_readiness;
            }

            match readiness {
                Poll::Ready(Ok(())) => {
                    let load_guard = LoadMetricGuard::new(Arc::clone(&backend.load));
                    let fut = svc.call(
                        req.take()
                            .expect("load-balanced request must be consumed once"),
                    );
                    let load_metric = load_guard.defuse();
                    drop(svc);

                    return Ok(LoadBalancedFuture {
                        inner: Some(fut),
                        service_marker: PhantomData,
                        load_metric: Some(load_metric),
                    });
                }
                Poll::Ready(Err(err)) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
                Poll::Pending => {}
            }
        }
        if let Some(err) = first_error {
            return Err(LoadBalanceError::Inner(err));
        }
        Err(LoadBalanceError::NoReadyBackends)
    }
}

/// Future returned by load-balanced dispatch.
pub struct LoadBalancedFuture<F, S> {
    inner: Option<F>,
    service_marker: PhantomData<fn() -> S>,
    /// Load metric to decrement when the future completes or is dropped.
    load_metric: Option<Arc<LoadMetric>>,
}

impl<F, S> fmt::Debug for LoadBalancedFuture<F, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadBalancedFuture").finish()
    }
}

impl<F, S, T, E> Future for LoadBalancedFuture<F, S>
where
    F: Future<Output = Result<T, E>> + Unpin,
{
    type Output = Result<T, LoadBalanceError<E>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        let Some(mut inner) = this.inner.take() else {
            return Poll::Ready(Err(LoadBalanceError::PolledAfterCompletion));
        };

        let load_guard = LoadMetricPollGuard::new(this.load_metric.take());
        match Pin::new(&mut inner).poll(cx) {
            Poll::Ready(Ok(response)) => Poll::Ready(Ok(response)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(LoadBalanceError::Inner(err))),
            Poll::Pending => {
                let load_metric = load_guard.restore();
                this.inner = Some(inner);
                this.load_metric = load_metric;
                Poll::Pending
            }
        }
    }
}

impl<F, S> Drop for LoadBalancedFuture<F, S> {
    fn drop(&mut self) {
        // Decrement in-flight counter if the future is dropped before completion.
        if let Some(load) = self.load_metric.take() {
            load.decrement();
        }
    }
}

// ─── Discovery integration ────────────────────────────────────────────────

/// Error from load balancer discovery updates.
#[derive(Debug)]
pub enum DiscoverUpdateError<D> {
    /// Discovery returned an error.
    Discover(D),
}

impl<D: fmt::Display> fmt::Display for DiscoverUpdateError<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discover(e) => write!(f, "discovery error: {e}"),
        }
    }
}

impl<D: std::error::Error + 'static> std::error::Error for DiscoverUpdateError<D> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Discover(e) => Some(e),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::collections::VecDeque;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::task::{Context, Poll, Wake, Waker};

    fn noop_waker() -> Waker {
        struct NoopWaker;

        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
            fn wake_by_ref(self: &Arc<Self>) {}
        }

        Waker::from(Arc::new(NoopWaker))
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // ================================================================
    // RoundRobin
    // ================================================================

    #[test]
    fn round_robin_cycles() {
        init_test("round_robin_cycles");
        let rr = RoundRobin::new();
        let loads = [0, 0, 0];
        assert_eq!(rr.pick(&loads), Some(0));
        assert_eq!(rr.pick(&loads), Some(1));
        assert_eq!(rr.pick(&loads), Some(2));
        assert_eq!(rr.pick(&loads), Some(0)); // wraps
        crate::test_complete!("round_robin_cycles");
    }

    #[test]
    fn round_robin_single() {
        let rr = RoundRobin::new();
        let loads = [5];
        assert_eq!(rr.pick(&loads), Some(0));
        assert_eq!(rr.pick(&loads), Some(0));
    }

    #[test]
    fn round_robin_empty() {
        let rr = RoundRobin::new();
        assert_eq!(rr.pick(&[]), None);
    }

    #[test]
    fn round_robin_default() {
        let rr = RoundRobin::default();
        assert_eq!(rr.pick(&[0, 0]), Some(0));
    }

    #[test]
    fn round_robin_debug() {
        let rr = RoundRobin::new();
        let dbg = format!("{rr:?}");
        assert!(dbg.contains("RoundRobin"));
    }

    // ================================================================
    // PowerOfTwoChoices
    // ================================================================

    #[test]
    fn p2c_prefers_lowerload_metric() {
        init_test("p2c_prefers_lowerload_metric");
        let p2c = PowerOfTwoChoices::new();
        // With one heavily loaded and others at 0, P2C should mostly avoid it.
        let loads = [100, 0, 0, 0];
        let mut picked_zero = 0u32;
        for _ in 0..100 {
            let idx = p2c.pick(&loads).unwrap();
            if loads[idx] == 0 {
                picked_zero += 1;
            }
        }
        // Should pick a zero-load backend most of the time.
        assert!(picked_zero > 50, "picked_zero={picked_zero}");
        crate::test_complete!("p2c_prefers_lowerload_metric");
    }

    #[test]
    fn p2c_single_backend() {
        let p2c = PowerOfTwoChoices::new();
        assert_eq!(p2c.pick(&[42]), Some(0));
    }

    #[test]
    fn p2c_empty() {
        let p2c = PowerOfTwoChoices::new();
        assert_eq!(p2c.pick(&[]), None);
    }

    #[test]
    fn p2c_two_backends() {
        let p2c = PowerOfTwoChoices::new();
        let loads = [10, 0];
        // With only two backends, should always pick the one with lower load.
        for _ in 0..10 {
            assert_eq!(p2c.pick(&loads), Some(1));
        }
    }

    #[test]
    fn p2c_equalload_metrics() {
        let p2c = PowerOfTwoChoices::new();
        let loads = [5, 5, 5];
        // All loads equal — should still return a valid index.
        for _ in 0..10 {
            let idx = p2c.pick(&loads).unwrap();
            assert!(idx < 3);
        }
    }

    #[test]
    fn p2c_default() {
        let p2c = PowerOfTwoChoices::default();
        let idx = p2c.pick(&[0, 0]);
        assert!(idx == Some(0) || idx == Some(1));
    }

    #[test]
    fn p2c_debug() {
        let p2c = PowerOfTwoChoices::new();
        let dbg = format!("{p2c:?}");
        assert!(dbg.contains("PowerOfTwoChoices"));
    }

    // ================================================================
    // Weighted
    // ================================================================

    #[test]
    fn weighted_proportional() {
        init_test("weighted_proportional");
        let w = Weighted::new(vec![3, 1]);
        let loads = [0, 0];
        let mut counts = [0u32; 2];
        for _ in 0..400 {
            let idx = w.pick(&loads).unwrap();
            counts[idx] += 1;
        }
        // 3:1 ratio means ~300 vs ~100.
        assert!(counts[0] == 300, "counts={counts:?}");
        assert!(counts[1] == 100, "counts={counts:?}");
        crate::test_complete!("weighted_proportional");
    }

    #[test]
    fn weighted_swrr_distribution() {
        init_test("weighted_swrr_distribution");
        // SWRR should interleave, not batch.
        let w = Weighted::new(vec![2, 1]);
        let loads = [0, 0];
        let mut pattern = Vec::new();
        for _ in 0..6 {
            pattern.push(w.pick(&loads).unwrap());
        }
        // With weights 2:1, SWRR gives: [0, 1, 0, 0, 1, 0] pattern (repeating).
        assert_eq!(pattern, vec![0, 1, 0, 0, 1, 0]);
        crate::test_complete!("weighted_swrr_distribution");
    }

    #[test]
    fn weighted_all_zero() {
        let w = Weighted::new(vec![0, 0, 0]);
        assert_eq!(w.pick(&[0, 0, 0]), None);
    }

    #[test]
    fn weighted_single() {
        let w = Weighted::new(vec![5]);
        assert_eq!(w.pick(&[0]), Some(0));
    }

    #[test]
    fn weighted_empty() {
        let w = Weighted::new(vec![]);
        assert_eq!(w.pick(&[]), None);
    }

    #[test]
    fn weighted_debug() {
        let w = Weighted::new(vec![1, 2]);
        let dbg = format!("{w:?}");
        assert!(dbg.contains("Weighted"));
    }

    // ================================================================
    // LoadBalanceError
    // ================================================================

    #[test]
    fn error_no_backends_display() {
        let err: LoadBalanceError<std::io::Error> = LoadBalanceError::NoBackends;
        assert_eq!(format!("{err}"), "no backends available");
    }

    #[test]
    fn error_inner_display() {
        let inner = std::io::Error::other("fail");
        let err: LoadBalanceError<std::io::Error> = LoadBalanceError::Inner(inner);
        assert!(format!("{err}").contains("backend error"));
    }

    #[test]
    fn error_polled_after_completion_display() {
        let err: LoadBalanceError<std::io::Error> = LoadBalanceError::PolledAfterCompletion;
        assert_eq!(
            format!("{err}"),
            "load-balanced future polled after completion"
        );
    }

    #[test]
    fn error_source() {
        use std::error::Error;
        let err: LoadBalanceError<std::io::Error> = LoadBalanceError::NoBackends;
        assert!(err.source().is_none());

        let done: LoadBalanceError<std::io::Error> = LoadBalanceError::PolledAfterCompletion;
        assert!(done.source().is_none());

        let inner = std::io::Error::other("fail");
        let err = LoadBalanceError::Inner(inner);
        assert!(err.source().is_some());
    }

    #[test]
    fn error_debug() {
        let err: LoadBalanceError<std::io::Error> = LoadBalanceError::NoBackends;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NoBackends"));
    }

    // ================================================================
    // LoadBalancer
    // ================================================================

    // Simple mock service for testing.
    #[derive(Clone, Debug)]
    struct MockService {
        id: usize,
    }

    impl MockService {
        fn new(id: usize) -> Self {
            Self { id }
        }
    }

    #[derive(Clone, Debug)]
    struct PanicOnCallService;

    impl Service<u32> for PanicOnCallService {
        type Response = ();
        type Error = ();
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            panic!("panic during call construction");
        }
    }

    #[derive(Clone, Debug)]
    struct PanicOnPollService;

    struct PanicOnPollFuture;

    impl Future for PanicOnPollFuture {
        type Output = Result<u32, std::io::Error>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<<Self as Future>::Output> {
            panic!("panic during future poll");
        }
    }

    impl Service<u32> for PanicOnPollService {
        type Response = u32;
        type Error = std::io::Error;
        type Future = PanicOnPollFuture;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            PanicOnPollFuture
        }
    }

    #[derive(Clone, Debug)]
    struct PendingOnceService {
        response: u32,
    }

    struct PendingOnceFuture {
        response: u32,
        pending_once: bool,
    }

    impl Future for PendingOnceFuture {
        type Output = Result<u32, std::io::Error>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.pending_once {
                self.pending_once = false;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(Ok(self.response))
            }
        }
    }

    impl Service<u32> for PendingOnceService {
        type Response = u32;
        type Error = std::io::Error;
        type Future = PendingOnceFuture;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            PendingOnceFuture {
                response: self.response,
                pending_once: true,
            }
        }
    }

    #[derive(Clone, Debug)]
    struct ErrorService;

    impl Service<u32> for ErrorService {
        type Response = u32;
        type Error = std::io::Error;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            std::future::ready(Err(std::io::Error::other("backend failed")))
        }
    }

    #[derive(Clone, Debug, Default)]
    struct ReadyArmService {
        armed: bool,
        response: u32,
        is_pending: bool,
    }

    impl ReadyArmService {
        fn new(response: u32) -> Self {
            Self {
                armed: false,
                response,
                is_pending: false,
            }
        }

        fn pending() -> Self {
            Self {
                armed: false,
                response: 0,
                is_pending: true,
            }
        }
    }

    impl Service<u32> for ReadyArmService {
        type Response = u32;
        type Error = ();
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.is_pending {
                Poll::Pending
            } else {
                self.armed = true;
                Poll::Ready(Ok(()))
            }
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            assert!(!self.is_pending, "pending backend must not be called");
            assert!(self.armed, "call must be preceded by poll_ready");
            self.armed = false;
            std::future::ready(Ok(self.response))
        }
    }

    #[derive(Clone, Debug)]
    struct SingleUseService {
        remaining_calls: usize,
        response: u32,
    }

    impl SingleUseService {
        fn new(response: u32) -> Self {
            Self {
                remaining_calls: 1,
                response,
            }
        }
    }

    impl Service<u32> for SingleUseService {
        type Response = u32;
        type Error = ();
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.remaining_calls > 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            assert!(
                self.remaining_calls > 0,
                "single-use backend must not be called twice"
            );
            self.remaining_calls -= 1;
            std::future::ready(Ok(self.response))
        }
    }

    #[derive(Clone, Debug)]
    struct WakeDuringPollReadyService {
        woke_once: bool,
        armed: bool,
        becomes_ready_after_wake: bool,
        response: u32,
    }

    impl WakeDuringPollReadyService {
        fn new(response: u32) -> Self {
            Self {
                woke_once: false,
                armed: false,
                becomes_ready_after_wake: true,
                response,
            }
        }

        fn pending_forever() -> Self {
            Self {
                woke_once: false,
                armed: false,
                becomes_ready_after_wake: false,
                response: 0,
            }
        }
    }

    impl Service<u32> for WakeDuringPollReadyService {
        type Response = u32;
        type Error = ();
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.woke_once && self.becomes_ready_after_wake {
                self.armed = true;
                Poll::Ready(Ok(()))
            } else {
                self.woke_once = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            assert!(self.armed, "call must be preceded by ready after self-wake");
            self.armed = false;
            std::future::ready(Ok(self.response))
        }
    }

    #[derive(Debug)]
    struct ScriptedDiscover<K, E> {
        polls: Mutex<VecDeque<Result<Vec<Change<K>>, E>>>,
        endpoints: Mutex<Vec<K>>,
    }

    impl<K, E> ScriptedDiscover<K, E> {
        fn new(polls: Vec<Result<Vec<Change<K>>, E>>) -> Self {
            Self {
                polls: Mutex::new(polls.into()),
                endpoints: Mutex::new(Vec::new()),
            }
        }
    }

    impl<K, E> Discover for ScriptedDiscover<K, E>
    where
        K: Clone + Eq + std::hash::Hash + fmt::Debug + Send + Sync + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        type Key = K;
        type Error = E;

        fn poll_discover(&self) -> Result<Vec<Change<K>>, Self::Error> {
            let Some(next) = self.polls.lock().pop_front() else {
                return Ok(Vec::new());
            };
            let changes = next?;

            let mut endpoints = self.endpoints.lock();
            for change in &changes {
                match change {
                    Change::Insert(endpoint) => {
                        if !endpoints.contains(endpoint) {
                            endpoints.push(endpoint.clone());
                        }
                    }
                    Change::Remove(endpoint) => {
                        if let Some(index) = endpoints.iter().position(|item| item == endpoint) {
                            endpoints.remove(index);
                        }
                    }
                }
            }

            drop(endpoints);

            Ok(changes)
        }

        fn endpoints(&self) -> Vec<Self::Key> {
            self.endpoints.lock().clone()
        }
    }

    #[test]
    fn lb_new_and_len() {
        init_test("lb_new_and_len");
        let lb = LoadBalancer::new(
            RoundRobin::new(),
            vec![MockService::new(1), MockService::new(2)],
        );
        assert_eq!(lb.len(), 2);
        assert!(!lb.is_empty());
        crate::test_complete!("lb_new_and_len");
    }

    #[test]
    fn lb_empty() {
        let lb = LoadBalancer::<MockService, _>::empty(RoundRobin::new());
        assert!(lb.is_empty());
        assert_eq!(lb.len(), 0);
    }

    #[test]
    fn lb_empty_preserves_weighted_configuration_for_future_backends() {
        init_test("lb_empty_preserves_weighted_configuration_for_future_backends");
        let lb = LoadBalancer::<String, _>::empty(Weighted::new(vec![3, 1]));

        let state = lb.strategy().state.lock();
        assert!(
            state.current_weights.is_empty(),
            "empty balancer must not retain live SWRR state without live backends"
        );
        assert_eq!(
            state.weights,
            vec![3, 1],
            "empty balancer must preserve deferred configured weights for later insertions"
        );
        assert_eq!(
            state.active_backend_count, 0,
            "empty balancer should report zero live weighted backends"
        );
        drop(state);

        lb.push("backend-a".to_string());
        lb.push("backend-b".to_string());

        let loads = lb.loads();
        let pattern: Vec<_> = (0..4)
            .map(|_| {
                lb.strategy()
                    .pick(&loads)
                    .expect("weighted strategy should use preserved deferred weights")
            })
            .collect();
        assert_eq!(pattern, vec![0, 0, 1, 0]);
        crate::test_complete!("lb_empty_preserves_weighted_configuration_for_future_backends");
    }

    #[test]
    fn lb_push() {
        let lb = LoadBalancer::<MockService, _>::empty(RoundRobin::new());
        lb.push(MockService::new(1));
        lb.push(MockService::new(2));
        assert_eq!(lb.len(), 2);
    }

    #[test]
    fn lb_remove() {
        let lb = LoadBalancer::new(RoundRobin::new(), vec![MockService::new(1)]);
        let svc = lb.remove(0);
        assert!(svc.is_some());
        assert_eq!(svc.unwrap().id, 1);
        assert!(lb.is_empty());
    }

    #[test]
    fn lb_remove_out_of_bounds() {
        let lb = LoadBalancer::new(RoundRobin::new(), vec![MockService::new(1)]);
        assert!(lb.remove(5).is_none());
    }

    #[test]
    fn lbload_metrics() {
        let lb = LoadBalancer::new(
            RoundRobin::new(),
            vec![MockService::new(1), MockService::new(2)],
        );
        let loads = lb.loads();
        assert_eq!(loads, vec![0, 0]);
    }

    #[test]
    fn lb_strategy() {
        let lb = LoadBalancer::new(RoundRobin::new(), vec![MockService::new(1)]);
        let _ = lb.strategy();
    }

    #[test]
    fn lb_debug() {
        let lb = LoadBalancer::new(RoundRobin::new(), vec![MockService::new(1)]);
        let dbg = format!("{lb:?}");
        assert!(dbg.contains("LoadBalancer"));
    }

    #[test]
    fn lb_panic_during_call_does_not_leak_load_metric() {
        init_test("lb_panic_during_call_does_not_leak_load_metric");
        let lb = LoadBalancer::new(RoundRobin::new(), vec![PanicOnCallService]);

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = lb.call_balanced(7);
        }));

        assert!(
            panic.is_err(),
            "call_balanced should propagate the backend panic"
        );
        assert_eq!(
            lb.loads(),
            vec![0],
            "panic path must roll back the in-flight increment"
        );
        crate::test_complete!("lb_panic_during_call_does_not_leak_load_metric");
    }

    #[test]
    fn lb_call_balanced_polls_ready_before_dispatch() {
        init_test("lb_call_balanced_polls_ready_before_dispatch");
        let lb = LoadBalancer::new(RoundRobin::new(), vec![ReadyArmService::new(41)]);

        let mut fut = lb
            .call_balanced(7)
            .expect("ready backend should dispatch successfully");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let output = Pin::new(&mut fut).poll(&mut cx);

        assert!(matches!(output, Poll::Ready(Ok(41))));
        assert_eq!(lb.loads(), vec![0]);
        crate::test_complete!("lb_call_balanced_polls_ready_before_dispatch");
    }

    #[test]
    fn lb_balanced_future_repoll_after_success_is_fail_closed() {
        init_test("lb_balanced_future_repoll_after_success_is_fail_closed");
        let lb = LoadBalancer::new(RoundRobin::new(), vec![ReadyArmService::new(41)]);

        let mut fut = lb
            .call_balanced(7)
            .expect("ready backend should dispatch successfully");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok(41))));
        assert_eq!(lb.loads(), vec![0]);

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(LoadBalanceError::PolledAfterCompletion))
        ));
        assert_eq!(lb.loads(), vec![0]);
        crate::test_complete!("lb_balanced_future_repoll_after_success_is_fail_closed");
    }

    #[test]
    fn lb_balanced_future_repoll_after_error_is_fail_closed() {
        init_test("lb_balanced_future_repoll_after_error_is_fail_closed");
        let lb = LoadBalancer::new(RoundRobin::new(), vec![ErrorService]);

        let mut fut = lb
            .call_balanced(7)
            .expect("erroring backend should still dispatch a future");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut fut).poll(&mut cx);
        match first {
            Poll::Ready(Err(LoadBalanceError::Inner(err))) => {
                assert_eq!(err.to_string(), "backend failed");
            }
            other => panic!("expected inner backend error, got {other:?}"),
        }
        assert_eq!(lb.loads(), vec![0]);

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(LoadBalanceError::PolledAfterCompletion))
        ));
        assert_eq!(lb.loads(), vec![0]);
        crate::test_complete!("lb_balanced_future_repoll_after_error_is_fail_closed");
    }

    #[test]
    fn lb_balanced_future_panic_fails_closed_and_releases_load_metric() {
        init_test("lb_balanced_future_panic_fails_closed_and_releases_load_metric");
        let lb = LoadBalancer::new(RoundRobin::new(), vec![PanicOnPollService]);

        let mut fut = lb
            .call_balanced(7)
            .expect("ready backend should dispatch a future");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = Pin::new(&mut fut).poll(&mut cx);
        }));
        assert!(panic.is_err(), "inner panic should propagate");
        assert_eq!(
            lb.loads(),
            vec![0],
            "panic path must release in-flight load"
        );

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(LoadBalanceError::PolledAfterCompletion))
        ));
        assert_eq!(
            lb.loads(),
            vec![0],
            "repoll must not resurrect in-flight load"
        );
        crate::test_complete!("lb_balanced_future_panic_fails_closed_and_releases_load_metric");
    }

    #[test]
    fn lb_balanced_future_pending_poll_restores_inner_and_load_metric() {
        init_test("lb_balanced_future_pending_poll_restores_inner_and_load_metric");
        let lb = LoadBalancer::new(RoundRobin::new(), vec![PendingOnceService { response: 17 }]);

        let mut fut = lb
            .call_balanced(7)
            .expect("ready backend should dispatch a future");
        assert_eq!(lb.loads(), vec![1], "dispatch increments in-flight load");

        let (waker, woke) = tracked_probe_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut fut).poll(&mut cx);
        assert!(
            first.is_pending(),
            "first poll should preserve pending future"
        );
        assert!(
            woke.load(Ordering::SeqCst),
            "pending future should re-wake caller"
        );
        assert_eq!(
            lb.loads(),
            vec![1],
            "pending poll must keep load reserved for the in-flight future"
        );

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(second, Poll::Ready(Ok(17))));
        assert_eq!(lb.loads(), vec![0], "completion releases the load metric");
        crate::test_complete!("lb_balanced_future_pending_poll_restores_inner_and_load_metric");
    }

    #[test]
    fn lb_call_balanced_skips_pending_backend() {
        init_test("lb_call_balanced_skips_pending_backend");
        let lb = LoadBalancer::new(
            RoundRobin::new(),
            vec![ReadyArmService::pending(), ReadyArmService::new(99)],
        );

        let mut fut = lb
            .call_balanced(7)
            .expect("second backend is ready and should be selected");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let output = Pin::new(&mut fut).poll(&mut cx);

        assert!(matches!(output, Poll::Ready(Ok(99))));
        assert_eq!(lb.loads(), vec![0, 0]);
        crate::test_complete!("lb_call_balanced_skips_pending_backend");
    }

    #[test]
    fn lb_call_balanced_reports_when_all_backends_pending() {
        init_test("lb_call_balanced_reports_when_all_backends_pending");
        let lb = LoadBalancer::new(RoundRobin::new(), vec![ReadyArmService::pending()]);

        let err = lb
            .call_balanced(7)
            .expect_err("all-pending backends should not be called");

        assert!(matches!(err, LoadBalanceError::NoReadyBackends));
        assert_eq!(lb.loads(), vec![0]);
        crate::test_complete!("lb_call_balanced_reports_when_all_backends_pending");
    }

    #[test]
    fn lb_call_balanced_reports_no_ready_when_strategy_declines_all_backends() {
        init_test("lb_call_balanced_reports_no_ready_when_strategy_declines_all_backends");
        let lb = LoadBalancer::new(Weighted::new(vec![0]), vec![ReadyArmService::new(17)]);

        let err = lb
            .call_balanced(7)
            .expect_err("zero-weight strategy should decline all backends");

        assert!(matches!(err, LoadBalanceError::NoReadyBackends));
        assert_eq!(lb.loads(), vec![0]);
        crate::test_complete!(
            "lb_call_balanced_reports_no_ready_when_strategy_declines_all_backends"
        );
    }

    #[test]
    fn lb_call_balanced_skips_zero_weight_ready_backend_during_weighted_fallback() {
        init_test("lb_call_balanced_skips_zero_weight_ready_backend_during_weighted_fallback");
        let lb = LoadBalancer::new(
            Weighted::new(vec![1, 0, 1]),
            vec![
                ReadyArmService::pending(),
                ReadyArmService::new(11),
                ReadyArmService::new(22),
            ],
        );

        let mut fut = lb
            .call_balanced(7)
            .expect("fallback should skip zero-weight backend and reach selectable ready backend");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let output = Pin::new(&mut fut).poll(&mut cx);

        assert!(matches!(output, Poll::Ready(Ok(22))));
        assert_eq!(lb.loads(), vec![0, 0, 0]);
        crate::test_complete!(
            "lb_call_balanced_skips_zero_weight_ready_backend_during_weighted_fallback"
        );
    }

    #[test]
    fn lb_call_balanced_rejects_only_ready_zero_weight_backend() {
        init_test("lb_call_balanced_rejects_only_ready_zero_weight_backend");
        let lb = LoadBalancer::new(
            Weighted::new(vec![1, 0]),
            vec![ReadyArmService::pending(), ReadyArmService::new(17)],
        );

        let err = lb
            .call_balanced(7)
            .expect_err("zero-weight backend must remain unselectable during fallback");

        assert!(matches!(err, LoadBalanceError::NoReadyBackends));
        assert_eq!(lb.loads(), vec![0, 0]);
        crate::test_complete!("lb_call_balanced_rejects_only_ready_zero_weight_backend");
    }

    #[test]
    fn lb_call_balanced_repolls_backend_after_self_wake() {
        init_test("lb_call_balanced_repolls_backend_after_self_wake");
        let lb = LoadBalancer::new(RoundRobin::new(), vec![WakeDuringPollReadyService::new(77)]);

        let mut fut = lb
            .call_balanced(7)
            .expect("self-woken backend should become ready on immediate repoll");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let output = Pin::new(&mut fut).poll(&mut cx);

        assert!(matches!(output, Poll::Ready(Ok(77))));
        assert_eq!(lb.loads(), vec![0]);
        crate::test_complete!("lb_call_balanced_repolls_backend_after_self_wake");
    }

    #[test]
    fn lb_call_balanced_skips_repeatedly_self_waking_pending_backend() {
        init_test("lb_call_balanced_skips_repeatedly_self_waking_pending_backend");
        let lb = LoadBalancer::new(
            RoundRobin::new(),
            vec![
                WakeDuringPollReadyService::pending_forever(),
                WakeDuringPollReadyService::new(88),
            ],
        );

        let mut fut = lb
            .call_balanced(7)
            .expect("balancer should skip a backend that stays pending after one self-wake");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let output = Pin::new(&mut fut).poll(&mut cx);

        assert!(matches!(output, Poll::Ready(Ok(88))));
        assert_eq!(lb.loads(), vec![0, 0]);
        crate::test_complete!("lb_call_balanced_skips_repeatedly_self_waking_pending_backend");
    }

    #[test]
    fn lb_call_balanced_preserves_backend_local_state() {
        init_test("lb_call_balanced_preserves_backend_local_state");
        let lb = LoadBalancer::new(RoundRobin::new(), vec![SingleUseService::new(55)]);

        let mut first = lb
            .call_balanced(7)
            .expect("single-use backend should accept the first request");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let output = Pin::new(&mut first).poll(&mut cx);

        assert!(matches!(output, Poll::Ready(Ok(55))));
        assert_eq!(lb.loads(), vec![0]);

        let err = lb
            .call_balanced(8)
            .expect_err("stored backend state should reject a second request");
        assert!(matches!(err, LoadBalanceError::NoReadyBackends));
        assert_eq!(lb.loads(), vec![0]);
        crate::test_complete!("lb_call_balanced_preserves_backend_local_state");
    }

    #[test]
    fn lb_update_from_discover_applies_insert_remove_and_dedupes() {
        init_test("lb_update_from_discover_applies_insert_remove_and_dedupes");
        let discover = ScriptedDiscover::<String, std::io::Error>::new(vec![
            Ok(vec![
                Change::Insert("backend-a".to_string()),
                Change::Insert("backend-a".to_string()),
                Change::Insert("backend-b".to_string()),
            ]),
            Ok(vec![
                Change::Remove("missing".to_string()),
                Change::Remove("backend-a".to_string()),
                Change::Insert("backend-c".to_string()),
                Change::Insert("backend-c".to_string()),
            ]),
            Ok(vec![Change::Insert("backend-b".to_string())]),
        ]);
        let lb = LoadBalancer::empty(RoundRobin::new());

        lb.update_from_discover(&discover)
            .expect("initial inserts should apply");
        assert_eq!(lb.len(), 2);
        assert_eq!(
            discover.endpoints(),
            vec!["backend-a".to_string(), "backend-b".to_string()]
        );

        lb.update_from_discover(&discover)
            .expect("removes and inserts should apply");
        assert_eq!(lb.len(), 2);
        assert_eq!(
            discover.endpoints(),
            vec!["backend-b".to_string(), "backend-c".to_string()]
        );

        lb.update_from_discover(&discover)
            .expect("duplicate inserts should be ignored");
        assert_eq!(lb.len(), 2);

        let mut remaining = vec![
            lb.remove(0).expect("backend-b should remain"),
            lb.remove(0).expect("backend-c should remain"),
        ];
        remaining.sort();
        assert_eq!(
            remaining,
            vec!["backend-b".to_string(), "backend-c".to_string()]
        );
        crate::test_complete!("lb_update_from_discover_applies_insert_remove_and_dedupes");
    }

    #[test]
    fn lb_update_from_discover_reconciles_late_joiner_against_snapshot() {
        init_test("lb_update_from_discover_reconciles_late_joiner_against_snapshot");
        let discover = ScriptedDiscover::<String, std::io::Error>::new(vec![Ok(vec![
            Change::Insert("backend-a".to_string()),
            Change::Insert("backend-b".to_string()),
        ])]);
        let first = LoadBalancer::empty(RoundRobin::new());
        let late = LoadBalancer::empty(RoundRobin::new());

        first
            .update_from_discover(&discover)
            .expect("first balancer should consume discovery inserts");
        assert_eq!(
            discover.endpoints(),
            vec!["backend-a".to_string(), "backend-b".to_string()]
        );

        late.update_from_discover(&discover)
            .expect("late balancer should reconcile from snapshot");
        assert_eq!(late.len(), 2);

        let mut remaining = vec![
            late.remove(0).expect("backend-a should be present"),
            late.remove(0).expect("backend-b should be present"),
        ];
        remaining.sort();
        assert_eq!(
            remaining,
            vec!["backend-a".to_string(), "backend-b".to_string()]
        );
        crate::test_complete!("lb_update_from_discover_reconciles_late_joiner_against_snapshot");
    }

    #[test]
    fn lb_update_from_static_discovery_is_idempotent() {
        init_test("lb_update_from_static_discovery_is_idempotent");
        let discover = super::super::discover::StaticList::new(vec![
            "backend-a".to_string(),
            "backend-b".to_string(),
            "backend-a".to_string(),
        ]);
        let lb = LoadBalancer::empty(RoundRobin::new());

        lb.update_from_discover(&discover)
            .expect("first static discovery poll should populate backends");
        assert_eq!(lb.len(), 2);

        lb.update_from_discover(&discover)
            .expect("subsequent static discovery polls should be no-ops");
        assert_eq!(lb.len(), 2);
        crate::test_complete!("lb_update_from_static_discovery_is_idempotent");
    }

    #[test]
    fn lb_weighted_discovery_insert_syncs_strategy_state() {
        init_test("lb_weighted_discovery_insert_syncs_strategy_state");
        let discover = super::super::discover::StaticList::new(vec![
            "backend-a".to_string(),
            "backend-b".to_string(),
        ]);
        let lb = LoadBalancer::new(Weighted::new(vec![3]), vec!["backend-a".to_string()]);

        lb.update_from_discover(&discover)
            .expect("discovery insert should keep weighted strategy aligned");
        assert_eq!(lb.len(), 2);

        let loads = lb.loads();
        let pattern: Vec<_> = (0..4)
            .map(|_| {
                lb.strategy()
                    .pick(&loads)
                    .expect("weighted strategy should select both discovered backends")
            })
            .collect();
        assert_eq!(pattern, vec![0, 0, 1, 0]);
        crate::test_complete!("lb_weighted_discovery_insert_syncs_strategy_state");
    }

    #[test]
    fn lb_weighted_push_syncs_strategy_state() {
        init_test("lb_weighted_push_syncs_strategy_state");
        let lb = LoadBalancer::new(Weighted::new(vec![3]), vec!["backend-a".to_string()]);

        lb.push("backend-b".to_string());
        assert_eq!(lb.len(), 2);

        let loads = lb.loads();
        let pattern: Vec<_> = (0..4)
            .map(|_| {
                lb.strategy()
                    .pick(&loads)
                    .expect("weighted strategy should track manually pushed backends")
            })
            .collect();
        assert_eq!(pattern, vec![0, 0, 1, 0]);
        crate::test_complete!("lb_weighted_push_syncs_strategy_state");
    }

    #[test]
    fn lb_new_syncs_weighted_strategy_state_for_initial_backends() {
        init_test("lb_new_syncs_weighted_strategy_state_for_initial_backends");
        let lb = LoadBalancer::new(
            Weighted::new(vec![1]),
            vec!["backend-a".to_string(), "backend-b".to_string()],
        );

        let loads = lb.loads();
        let pattern: Vec<_> = (0..4)
            .map(|_| {
                lb.strategy()
                    .pick(&loads)
                    .expect("weighted strategy should see both constructor backends")
            })
            .collect();
        assert_eq!(pattern, vec![0, 1, 0, 1]);
        crate::test_complete!("lb_new_syncs_weighted_strategy_state_for_initial_backends");
    }

    #[test]
    fn lb_new_preserves_deferred_weight_for_later_backend_insert() {
        init_test("lb_new_preserves_deferred_weight_for_later_backend_insert");
        let lb = LoadBalancer::new(Weighted::new(vec![9, 4]), vec!["backend-a".to_string()]);

        let state = lb.strategy().state.lock();
        assert_eq!(
            state.weights,
            vec![9, 4],
            "constructor reconciliation must preserve caller-supplied deferred weights"
        );
        assert_eq!(
            state.current_weights,
            vec![0],
            "constructor reconciliation must keep only live SWRR state for materialized backends"
        );
        assert_eq!(
            state.active_backend_count, 1,
            "constructor reconciliation must track the live backend count separately"
        );
        drop(state);

        lb.push("backend-b".to_string());
        let loads = lb.loads();
        let picks: Vec<_> = (0..13)
            .map(|_| {
                lb.strategy()
                    .pick(&loads)
                    .expect("weighted strategy should activate the preserved deferred weight")
            })
            .collect();
        assert_eq!(picks.iter().filter(|&&idx| idx == 0).count(), 9);
        assert_eq!(picks.iter().filter(|&&idx| idx == 1).count(), 4);
        crate::test_complete!("lb_new_preserves_deferred_weight_for_later_backend_insert");
    }

    #[test]
    fn lb_weighted_remove_reindexes_strategy_weights() {
        init_test("lb_weighted_remove_reindexes_strategy_weights");
        let lb = LoadBalancer::new(
            Weighted::new(vec![10, 1, 1]),
            vec![
                "backend-a".to_string(),
                "backend-b".to_string(),
                "backend-c".to_string(),
            ],
        );

        let removed = lb.remove(0).expect("first backend should be removable");
        assert_eq!(removed, "backend-a");
        assert_eq!(lb.len(), 2);

        let loads = lb.loads();
        let pattern: Vec<_> = (0..4)
            .map(|_| {
                lb.strategy()
                    .pick(&loads)
                    .expect("weighted strategy should keep remaining weights aligned")
            })
            .collect();
        assert_eq!(pattern, vec![0, 1, 0, 1]);
        crate::test_complete!("lb_weighted_remove_reindexes_strategy_weights");
    }

    #[test]
    fn lb_update_from_discover_propagates_errors() {
        init_test("lb_update_from_discover_propagates_errors");
        let discover = ScriptedDiscover::new(vec![Err(std::io::Error::other("discovery failed"))]);
        let lb = LoadBalancer::<String, _>::empty(RoundRobin::new());

        let err = lb
            .update_from_discover(&discover)
            .expect_err("discovery errors should bubble up");

        assert!(matches!(err, DiscoverUpdateError::Discover(_)));
        assert!(format!("{err}").contains("discovery failed"));
        assert!(lb.is_empty());
        crate::test_complete!("lb_update_from_discover_propagates_errors");
    }

    // ================================================================
    // LoadMetric
    // ================================================================

    #[test]
    fn load_metric_increment_decrement() {
        let m = LoadMetric::new();
        assert_eq!(m.load(), 0);
        m.increment();
        m.increment();
        assert_eq!(m.load(), 2);
        m.decrement();
        assert_eq!(m.load(), 1);
    }

    // ================================================================
    // DiscoverUpdateError
    // ================================================================

    #[test]
    fn discover_update_error_display() {
        let err = DiscoverUpdateError::Discover(std::io::Error::other("fail"));
        assert!(format!("{err}").contains("discovery error"));
    }

    #[test]
    fn discover_update_error_source() {
        use std::error::Error;
        let err = DiscoverUpdateError::Discover(std::io::Error::other("fail"));
        assert!(err.source().is_some());
    }

    #[test]
    fn discover_update_error_debug() {
        let err = DiscoverUpdateError::Discover(std::io::Error::other("fail"));
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Discover"));
    }

    // ================================================================
    // LoadBalancedFuture
    // ================================================================

    #[test]
    fn balanced_future_debug() {
        let fut = LoadBalancedFuture::<_, ()> {
            inner: Some(std::future::ready(42)),
            service_marker: PhantomData,
            load_metric: None,
        };
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("LoadBalancedFuture"));
    }
}
