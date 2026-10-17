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
//! Load balancers can be paired with a [`Discover`] instance
//! to dynamically add and remove backends as the topology changes.

use crate::types::Time;
use parking_lot::Mutex;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use super::Service;
use super::discover::{Change, Discover};

fn tracked_probe_waker() -> (Waker, Arc<AtomicBool>) {
    struct TrackWaker(Arc<AtomicBool>);

    use std::task::Wake;
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

fn poll_service_ready_once<S, Request>(
    service: &mut S,
    probe_waker: &Waker,
    probe_woke: &AtomicBool,
) -> (Poll<Result<(), S::Error>>, bool)
where
    S: Service<Request>,
{
    probe_woke.store(false, Ordering::SeqCst);
    let mut cx = Context::from_waker(probe_waker);
    let poll = service.poll_ready(&mut cx);
    (poll, probe_woke.load(Ordering::SeqCst))
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

fn duration_to_nanos(duration: std::time::Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

type SlowStartTimeGetter = Arc<dyn Fn() -> Time + Send + Sync + 'static>;

/// Configuration for gradually re-admitting newly inserted backends.
#[derive(Clone)]
pub struct SlowStartConfig {
    window: std::time::Duration,
    time_getter: SlowStartTimeGetter,
}

impl SlowStartConfig {
    /// Create a slow-start configuration with a wall-clock time source.
    #[must_use]
    pub fn new(window: std::time::Duration) -> Self {
        Self {
            window,
            time_getter: Arc::new(wall_clock_now),
        }
    }

    /// Set a deterministic time source.
    #[must_use]
    pub fn with_time_getter<F>(mut self, time_getter: F) -> Self
    where
        F: Fn() -> Time + Send + Sync + 'static,
    {
        self.time_getter = Arc::new(time_getter);
        self
    }

    /// Returns the configured ramp window.
    #[must_use]
    pub const fn window(&self) -> std::time::Duration {
        self.window
    }

    fn window_nanos(&self) -> u64 {
        duration_to_nanos(self.window)
    }

    fn now_nanos(&self) -> u64 {
        (self.time_getter)().as_nanos()
    }
}

impl fmt::Debug for SlowStartConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlowStartConfig")
            .field("window", &self.window)
            .field("time_getter", &"<fn>")
            .finish()
    }
}

#[derive(Clone, Copy)]
struct SlowStartView {
    now_nanos: u64,
    window_nanos: u64,
}

#[derive(Debug)]
struct SlowStartGate {
    activated_at_nanos: AtomicU64,
    attempts: AtomicU64,
    accepted: AtomicU64,
    warm: AtomicBool,
}

impl SlowStartGate {
    fn warm() -> Self {
        Self {
            activated_at_nanos: AtomicU64::new(0),
            attempts: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            warm: AtomicBool::new(true),
        }
    }

    fn start(&self, now_nanos: u64) {
        self.activated_at_nanos.store(now_nanos, Ordering::Relaxed);
        self.attempts.store(0, Ordering::Relaxed);
        self.accepted.store(0, Ordering::Relaxed);
        self.warm.store(false, Ordering::Relaxed);
    }

    fn mark_warm(&self) {
        self.warm.store(true, Ordering::Relaxed);
    }

    fn is_unrestricted(&self, view: SlowStartView) -> bool {
        if self.warm.load(Ordering::Relaxed) {
            return true;
        }

        if self.elapsed_nanos(view) >= view.window_nanos {
            self.mark_warm();
            return true;
        }

        false
    }

    fn permits(&self, view: SlowStartView) -> bool {
        if self.is_unrestricted(view) {
            return true;
        }

        let elapsed = self.elapsed_nanos(view);
        if elapsed == 0 {
            return false;
        }

        let attempt = self.attempts.fetch_add(1, Ordering::Relaxed) + 1;
        let allowance = ramp_allowance(attempt, elapsed, view.window_nanos);

        loop {
            let accepted = self.accepted.load(Ordering::Relaxed);
            if allowance <= accepted {
                return false;
            }

            if self
                .accepted
                .compare_exchange_weak(
                    accepted,
                    accepted.saturating_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    fn elapsed_nanos(&self, view: SlowStartView) -> u64 {
        let activated_at = self.activated_at_nanos.load(Ordering::Relaxed);
        view.now_nanos.saturating_sub(activated_at)
    }
}

fn ramp_allowance(attempt: u64, elapsed_nanos: u64, window_nanos: u64) -> u64 {
    let allowance = (u128::from(attempt) * u128::from(elapsed_nanos)) / u128::from(window_nanos);
    u64::try_from(allowance).unwrap_or(u64::MAX)
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
        // Use try_update to prevent underflow wrapping.
        let _ = self
            .in_flight
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
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

    /// Returns whether `candidate` is allowed as a same-call fallback after the
    /// strategy's initially picked backend at `picked` could not accept work.
    ///
    /// The default preserves the normal selection filter. Strategies with
    /// ordered failover semantics, such as gRPC `pick_first`, can widen the
    /// allowed set here without weakening their primary selection rule.
    fn permits_fallback_index(&self, _picked: usize, candidate: usize, loads: &[u64]) -> bool {
        self.permits_index(candidate, loads)
    }

    /// Returns the backend index to probe on a given dispatch attempt.
    ///
    /// Attempt `0` is always the primary strategy pick. Later attempts are
    /// same-call fallback probes. The default preserves the existing wrapped
    /// order so strategies keep probing from the originally selected index.
    fn candidate_for_attempt(&self, picked: usize, attempt: usize, len: usize) -> Option<usize> {
        (attempt < len).then_some((picked + attempt) % len)
    }

    /// Records which backend actually accepted a dispatch.
    ///
    /// Strategies with sticky affinity can use this to preserve the chosen
    /// backend across later calls instead of recomputing from scratch.
    fn note_dispatch(&self, _picked: usize, _chosen: usize, _loads: &[u64]) {}

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

    /// Notifies the strategy that the backend list was reordered.
    ///
    /// `new_to_old[new_index]` gives the previous index of the backend now
    /// stored at `new_index`. Strategies with index-coupled state can use this
    /// to preserve affinity or per-backend bookkeeping across snapshot
    /// reconciliations that keep the same backend set but change ordering.
    fn on_backends_reordered(&self, _new_to_old: &[usize]) {}
}

// ─── RoundRobin ───────────────────────────────────────────────────────────

/// Cycles through backends in sequential order.
#[derive(Debug, Default)]
pub struct RoundRobin {
    next: AtomicUsize,
}

impl RoundRobin {
    /// Create a new round-robin strategy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

// ─── PickFirst ────────────────────────────────────────────────────────────

/// Always picks the first backend until it fails.
///
/// This implements the gRPC pick_first load balancing policy which maintains
/// connection affinity by using the first backend in the list until it becomes
/// unavailable, then failing over to the next available backend.
#[derive(Debug)]
pub struct PickFirst {
    active: AtomicUsize,
}

impl PickFirst {
    const NO_ACTIVE_BACKEND: usize = usize::MAX;

    /// Create a new pick-first strategy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: AtomicUsize::new(Self::NO_ACTIVE_BACKEND),
        }
    }
}

impl Default for PickFirst {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for PickFirst {
    fn pick(&self, loads: &[u64]) -> Option<usize> {
        if loads.is_empty() {
            return None;
        }
        let active = self.active.load(Ordering::Relaxed);
        if active < loads.len() {
            Some(active)
        } else {
            Some(0)
        }
    }

    fn permits_index(&self, index: usize, loads: &[u64]) -> bool {
        if index >= loads.len() {
            return false;
        }
        let active = self.active.load(Ordering::Relaxed);
        if active < loads.len() {
            index == active
        } else {
            index == 0
        }
    }

    fn permits_fallback_index(&self, picked: usize, candidate: usize, loads: &[u64]) -> bool {
        picked < loads.len() && candidate < loads.len()
    }

    fn candidate_for_attempt(&self, picked: usize, attempt: usize, len: usize) -> Option<usize> {
        if picked >= len || attempt >= len {
            return None;
        }
        if attempt == 0 {
            return Some(picked);
        }
        let natural = attempt - 1;
        if natural < picked {
            Some(natural)
        } else {
            let shifted = natural + 1;
            (shifted < len).then_some(shifted)
        }
    }

    fn note_dispatch(&self, _picked: usize, chosen: usize, loads: &[u64]) {
        if chosen < loads.len() {
            self.active.store(chosen, Ordering::Relaxed);
        }
    }

    fn sync_backend_count(&self, count: usize) {
        let active = self.active.load(Ordering::Relaxed);
        if count == 0 || active >= count {
            self.active
                .store(Self::NO_ACTIVE_BACKEND, Ordering::Relaxed);
        }
    }

    fn on_backend_removed(&self, index: usize) {
        let active = self.active.load(Ordering::Relaxed);
        if active == Self::NO_ACTIVE_BACKEND {
            return;
        }
        if index < active {
            self.active.store(active - 1, Ordering::Relaxed);
        }
    }

    fn on_backends_reordered(&self, new_to_old: &[usize]) {
        let active = self.active.load(Ordering::Relaxed);
        if active == Self::NO_ACTIVE_BACKEND {
            return;
        }

        if let Some((new_index, _)) = new_to_old
            .iter()
            .enumerate()
            .find(|(_, old_index)| **old_index == active)
        {
            self.active.store(new_index, Ordering::Relaxed);
        } else {
            self.active
                .store(Self::NO_ACTIVE_BACKEND, Ordering::Relaxed);
        }
    }
}

// ─── PowerOfTwoChoices ────────────────────────────────────────────────────

/// Picks the least-loaded of two randomly chosen backends.
///
/// This provides near-optimal load distribution with O(1) selection,
/// avoiding the thundering-herd problem of pure random selection.
#[derive(Debug, Default)]
pub struct PowerOfTwoChoices {
    counter: AtomicUsize,
}

impl PowerOfTwoChoices {
    /// Create a new P2C strategy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

    fn note_dispatch(&self, picked: usize, chosen: usize, _loads: &[u64]) {
        if picked == chosen {
            return;
        }

        let mut state = self.state.lock();
        let len = state
            .active_backend_count
            .min(state.weights.len())
            .min(state.current_weights.len());
        if picked >= len || chosen >= len {
            return;
        }

        let total_weight: i64 = state.weights[..len].iter().map(|&w| i64::from(w)).sum();
        if total_weight == 0 {
            return;
        }

        // `pick()` already debited the speculative choice. When readiness
        // fallback dispatches elsewhere, move that single SWRR debit to the
        // backend that actually handled the request so future picks stay fair.
        state.current_weights[picked] += total_weight;
        state.current_weights[chosen] -= total_weight;
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

    fn on_backends_reordered(&self, new_to_old: &[usize]) {
        let mut state = self.state.lock();
        let reordered_weights: Vec<u32> = new_to_old
            .iter()
            .map(|&old_index| state.weights.get(old_index).copied().unwrap_or(1))
            .collect();
        let reordered_current_weights: Vec<i64> = new_to_old
            .iter()
            .map(|&old_index| {
                state
                    .current_weights
                    .get(old_index)
                    .copied()
                    .unwrap_or_default()
            })
            .collect();
        state.weights = reordered_weights;
        state.current_weights = reordered_current_weights;
        state.active_backend_count = new_to_old.len();
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
    slow_start: Option<SlowStartConfig>,
}

struct Backend<S> {
    service: Mutex<S>,
    load: Arc<LoadMetric>,
    probe_waker: Waker,
    probe_woke: Arc<AtomicBool>,
    slow_start: SlowStartGate,
}

impl<S> Backend<S> {
    fn new(service: S) -> Self {
        let (probe_waker, probe_woke) = tracked_probe_waker();
        Self {
            service: Mutex::new(service),
            load: Arc::new(LoadMetric::new()),
            probe_waker,
            probe_woke,
            slow_start: SlowStartGate::warm(),
        }
    }
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
            .map(|s| Arc::new(Backend::new(s)))
            .collect();
        strategy.sync_backend_count(backends.len());
        Self {
            backends: Mutex::new(backends),
            strategy,
            slow_start: None,
        }
    }

    /// Create an empty load balancer.
    #[must_use]
    pub fn empty(strategy: T) -> Self {
        strategy.sync_backend_count(0);
        Self {
            backends: Mutex::new(Vec::new()),
            strategy,
            slow_start: None,
        }
    }

    /// Enable slow-start for subsequently inserted backends.
    ///
    /// Backends that already exist when this method is called are treated as
    /// warm. New or recovered backends ramp from zero traffic share to their
    /// normal strategy share across the configured window.
    #[must_use]
    pub fn with_slow_start(mut self, config: SlowStartConfig) -> Self {
        for backend in self.backends.lock().iter() {
            backend.slow_start.mark_warm();
        }
        self.slow_start = Some(config);
        self
    }

    /// Get the slow-start configuration, if enabled.
    #[must_use]
    pub fn slow_start(&self) -> Option<&SlowStartConfig> {
        self.slow_start.as_ref()
    }

    /// Add a backend service.
    pub fn push(&self, service: S) {
        let mut backends = self.backends.lock();
        let index = backends.len();
        backends.push(self.new_inserted_backend(service, index > 0));
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

    fn new_inserted_backend(&self, service: S, should_ramp: bool) -> Arc<Backend<S>> {
        let backend = Arc::new(Backend::new(service));
        let Some(config) = self.slow_start.as_ref().filter(|_| should_ramp) else {
            return backend;
        };

        let window_nanos = config.window_nanos();
        if window_nanos == 0 {
            backend.slow_start.mark_warm();
        } else {
            backend.slow_start.start(config.now_nanos());
        }
        backend
    }

    fn slow_start_view(&self, backends: &[Arc<Backend<S>>]) -> Option<SlowStartView> {
        let config = self.slow_start.as_ref()?;
        let window_nanos = config.window_nanos();
        if window_nanos == 0 {
            return None;
        }

        let view = SlowStartView {
            now_nanos: config.now_nanos(),
            window_nanos,
        };
        let has_unrestricted_backend = backends
            .iter()
            .any(|backend| backend.slow_start.is_unrestricted(view));

        has_unrestricted_backend.then_some(view)
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
    S: Eq + Clone,
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
        let initial_snapshot = backends.is_empty();
        for change in changes {
            match change {
                Change::Insert(service) => {
                    if backends_contain_service(&backends, &service) {
                        continue;
                    }

                    let index = backends.len();
                    backends.push(self.new_inserted_backend(service, !initial_snapshot));
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

        for service in &endpoints {
            if backends_contain_service(&backends, service) {
                continue;
            }

            let index = backends.len();
            backends.push(self.new_inserted_backend(service.clone(), !initial_snapshot));
            self.strategy.on_backend_inserted(index);
        }

        let needs_reorder = backends.len() == endpoints.len()
            && endpoints
                .iter()
                .zip(backends.iter())
                .any(|(endpoint, backend)| !backend_matches_service(backend, endpoint));

        if needs_reorder {
            let mut drained: Vec<Option<Arc<Backend<S>>>> = backends.drain(..).map(Some).collect();
            let mut reordered = Vec::with_capacity(endpoints.len());
            let mut new_to_old = Vec::with_capacity(endpoints.len());

            for endpoint in &endpoints {
                let old_index = drained
                    .iter()
                    .position(|candidate| {
                        candidate
                            .as_ref()
                            .is_some_and(|backend| backend_matches_service(backend, endpoint))
                    })
                    .expect("discovery snapshot diverged from reconciled backend set");
                reordered.push(
                    drained[old_index]
                        .take()
                        .expect("backend already moved during reorder"),
                );
                new_to_old.push(old_index);
            }

            *backends = reordered;
            self.strategy.on_backends_reordered(&new_to_old);
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
        let slow_start_view = self.slow_start_view(&backend_handles);
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
            let Some(candidate_idx) =
                self.strategy
                    .candidate_for_attempt(idx, offset, backend_handles.len())
            else {
                continue;
            };
            let permitted = if offset == 0 {
                self.strategy.permits_index(candidate_idx, &loads)
            } else {
                self.strategy
                    .permits_fallback_index(idx, candidate_idx, &loads)
            };
            if !permitted {
                continue;
            }
            let backend = &backend_handles[candidate_idx];
            if slow_start_view.is_some_and(|view| !backend.slow_start.permits(view)) {
                continue;
            }
            let release_scope = super::service::ReadinessReleaseScope::new();
            let mut svc = backend.service.lock();

            let (mut readiness, woke_during_poll) = poll_service_ready_once::<S, Request>(
                &mut *svc,
                &backend.probe_waker,
                backend.probe_woke.as_ref(),
            );
            if matches!(readiness, Poll::Pending) && woke_during_poll {
                // Preserve same-turn readiness edges from backends that
                // self-wake during `poll_ready` and become callable on the
                // immediate follow-up poll, without spinning forever on a
                // repeatedly self-waking-but-still-pending backend.
                let (next_readiness, _) = poll_service_ready_once::<S, Request>(
                    &mut *svc,
                    &backend.probe_waker,
                    backend.probe_woke.as_ref(),
                );
                readiness = next_readiness;
            }

            match readiness {
                Poll::Ready(Ok(())) => {
                    let load_guard = LoadMetricGuard::new(Arc::clone(&backend.load));
                    let fut = svc.call(
                        req.take()
                            .expect("load-balanced request must be consumed once"),
                    );
                    self.strategy.note_dispatch(idx, candidate_idx, &loads);
                    let load_metric = load_guard.defuse();
                    drop(svc);

                    let future = LoadBalancedFuture {
                        inner: Some(fut),
                        service_marker: PhantomData,
                        load_metric: Some(load_metric),
                    };
                    // The future owns the load decrement before deferred
                    // cleanup can reenter or panic after the service unlocks.
                    drop(release_scope);
                    return Ok(future);
                }
                Poll::Ready(Err(err)) => {
                    let release = svc.release_readiness();
                    drop(svc);
                    drop(release);
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
                Poll::Pending => {
                    let release = svc.release_readiness();
                    drop(svc);
                    drop(release);
                }
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
#[path = "load_balance_inline_tests.rs"]
mod tests;
