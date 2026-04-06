//! Hedge middleware layer.
//!
//! The [`HedgeLayer`] wraps a cloneable service to issue a backup (hedge)
//! request when the primary request takes too long. The first response
//! to complete is returned, reducing tail latency.
//!
//! This is a latency-optimisation technique from the paper "The Tail at
//! Scale" (Dean & Barroso, 2013).

use super::{Layer, Service};
use crate::time::{Sleep, wall_now};
use crate::types::Time;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

fn wall_clock_now() -> Time {
    wall_now()
}

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

// ─── HedgeLayer ───────────────────────────────────────────────────────────

/// A layer that applies hedging to a service.
#[derive(Debug, Clone)]
pub struct HedgeLayer {
    config: HedgeConfig,
}

impl HedgeLayer {
    /// Create a new hedge layer with the given configuration.
    #[must_use]
    pub fn new(config: HedgeConfig) -> Self {
        Self { config }
    }

    /// Create a hedge layer with a fixed delay threshold.
    #[must_use]
    pub fn with_delay(delay: Duration) -> Self {
        Self::new(HedgeConfig::new(delay))
    }
}

impl<S: Clone> Layer<S> for HedgeLayer {
    type Service = Hedge<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Hedge::new(inner, self.config.clone())
    }
}

// ─── HedgeConfig ──────────────────────────────────────────────────────────

/// Configuration for the hedge middleware.
#[derive(Debug, Clone)]
pub struct HedgeConfig {
    /// Duration to wait before sending the hedge request.
    pub delay: Duration,
    /// Maximum number of outstanding hedge requests.
    pub max_pending: u32,
    time_getter: fn() -> Time,
}

impl HedgeConfig {
    /// Create a new hedge configuration with the given delay.
    #[must_use]
    pub fn new(delay: Duration) -> Self {
        Self {
            delay,
            max_pending: 10,
            time_getter: wall_clock_now,
        }
    }

    /// Set the maximum number of concurrent hedge requests.
    #[must_use]
    pub fn max_pending(mut self, max: u32) -> Self {
        self.max_pending = max;
        self
    }

    /// Set the time source used for hedge deadlines.
    #[must_use]
    pub fn with_time_getter(mut self, time_getter: fn() -> Time) -> Self {
        self.time_getter = time_getter;
        self
    }

    /// Returns the time source used for hedge deadlines.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }
}

// ─── HedgeError ───────────────────────────────────────────────────────────

/// Error from the hedge middleware.
#[derive(Debug)]
pub enum HedgeError<E> {
    /// The caller attempted `call()` without a preceding successful `poll_ready()`.
    NotReady,
    /// The hedge future was polled after it had already completed.
    PolledAfterCompletion,
    /// The inner service returned an error.
    Inner(E),
    /// Both primary and hedge requests failed.
    BothFailed {
        /// Error from the primary request.
        primary: E,
        /// Error from the hedge request.
        hedge: E,
    },
}

impl<E: fmt::Display> fmt::Display for HedgeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReady => write!(f, "poll_ready required before call"),
            Self::PolledAfterCompletion => write!(f, "hedge future polled after completion"),
            Self::Inner(e) => write!(f, "service error: {e}"),
            Self::BothFailed { primary, .. } => {
                write!(f, "both primary and hedge failed: {primary}")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for HedgeError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotReady | Self::PolledAfterCompletion => None,
            Self::Inner(e) | Self::BothFailed { primary: e, .. } => Some(e),
        }
    }
}

// ─── Hedge service ────────────────────────────────────────────────────────

/// A service that hedges requests to reduce tail latency.
///
/// When a request takes longer than the configured delay, a second
/// (hedge) request is sent to the same service. The first response
/// to arrive is returned.
///
/// Each successful `poll_ready` authorizes exactly one subsequent `call`.
pub struct Hedge<S> {
    inner: S,
    config: HedgeConfig,
    stats: Arc<HedgeStats>,
    /// Tracks whether this clone has observed readiness for one call.
    ready_observed: bool,
}

struct HedgeStats {
    /// Total requests processed.
    total: AtomicU64,
    /// Hedge requests sent.
    hedged: AtomicU64,
    /// Times the hedge response won.
    hedge_wins: AtomicU64,
    /// Number of hedge requests currently occupying a pending slot.
    pending: AtomicU64,
}

impl HedgeStats {
    fn record_hedge(&self) {
        self.hedged.fetch_add(1, Ordering::Relaxed);
    }

    fn try_acquire_pending_slot(&self, max_pending: u32) -> bool {
        if max_pending == 0 {
            return false;
        }

        let max_pending = u64::from(max_pending);
        loop {
            let current = self.pending.load(Ordering::Acquire);
            if current >= max_pending {
                return false;
            }
            if self
                .pending
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn release_pending_slot(&self) {
        let _ = self
            .pending
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(1)
            });
    }

    fn finish_started_hedge(&self, hedge_won: bool) {
        if hedge_won {
            self.hedge_wins.fetch_add(1, Ordering::Relaxed);
        }
        self.release_pending_slot();
    }
}

impl<S> Hedge<S> {
    /// Create a new hedge service.
    #[must_use]
    pub fn new(inner: S, config: HedgeConfig) -> Self {
        Self {
            inner,
            config,
            stats: Arc::new(HedgeStats {
                total: AtomicU64::new(0),
                hedged: AtomicU64::new(0),
                hedge_wins: AtomicU64::new(0),
                pending: AtomicU64::new(0),
            }),
            ready_observed: false,
        }
    }

    /// Get the configured delay threshold.
    #[must_use]
    pub fn delay(&self) -> Duration {
        self.config.delay
    }

    /// Get the maximum pending hedge limit.
    #[must_use]
    pub fn max_pending(&self) -> u32 {
        self.config.max_pending
    }

    /// Total requests processed.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.stats.total.load(Ordering::Relaxed)
    }

    /// Number of hedge requests sent.
    #[must_use]
    pub fn hedged_requests(&self) -> u64 {
        self.stats.hedged.load(Ordering::Relaxed)
    }

    /// Number of times the hedge response arrived first.
    #[must_use]
    pub fn hedge_wins(&self) -> u64 {
        self.stats.hedge_wins.load(Ordering::Relaxed)
    }

    /// Get the hedge rate (hedged / total).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn hedge_rate(&self) -> f64 {
        let total = self.total_requests();
        if total == 0 {
            return 0.0;
        }
        self.hedged_requests() as f64 / total as f64
    }

    /// Record that a request was processed.
    pub fn record_request(&self) {
        self.stats.total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a hedge request was sent.
    pub fn record_hedge(&self) {
        self.stats.hedged.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that the hedge response won.
    pub fn record_hedge_win(&self) {
        self.stats.hedge_wins.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a reference to the inner service.
    #[must_use]
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Get a mutable reference to the inner service.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Get a reference to the configuration.
    #[must_use]
    pub fn config(&self) -> &HedgeConfig {
        &self.config
    }
}

impl<S: fmt::Debug> fmt::Debug for Hedge<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hedge")
            .field("inner", &self.inner)
            .field("delay", &self.config.delay)
            .field("max_pending", &self.config.max_pending)
            .field("total", &self.total_requests())
            .field("hedged", &self.hedged_requests())
            .field("hedge_wins", &self.hedge_wins())
            .finish_non_exhaustive()
    }
}

impl<S: Clone> Clone for Hedge<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config.clone(),
            stats: Arc::clone(&self.stats),
            // Readiness tickets are handle-local and must not be cloned.
            ready_observed: false,
        }
    }
}

impl<S, Request> Service<Request> for Hedge<S>
where
    S: Service<Request> + Clone + Unpin,
    S::Future: Unpin,
    Request: Clone + Unpin,
{
    type Response = S::Response;
    type Error = HedgeError<S::Error>;
    type Future = HedgeFuture<S, Request>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.inner.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                self.ready_observed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.ready_observed = false;
                Poll::Ready(Err(HedgeError::Inner(e)))
            }
            Poll::Pending => {
                self.ready_observed = false;
                Poll::Pending
            }
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if !std::mem::replace(&mut self.ready_observed, false) {
            return HedgeFuture::not_ready();
        }

        let primary = self.inner.call(req.clone());
        let hedge_service = if self.config.max_pending == 0 {
            None
        } else {
            Some(self.inner.clone())
        };
        self.record_request();
        HedgeFuture::new(
            primary,
            hedge_service,
            req,
            &self.config,
            Arc::clone(&self.stats),
        )
    }
}

/// Future returned by the [`Hedge`] service.
pub struct HedgeFuture<S, Request>
where
    S: Service<Request>,
{
    state: HedgeFutureState<S, Request>,
}

enum HedgeFutureState<S, Request>
where
    S: Service<Request>,
{
    NotReady,
    Running {
        primary: Option<S::Future>,
        hedge_service: Option<S>,
        hedge_request: Option<Request>,
        hedge_future: Option<S::Future>,
        sleep: Sleep,
        time_getter: fn() -> Time,
        max_pending: u32,
        stats: Arc<HedgeStats>,
        slot_held: bool,
        delay_elapsed: bool,
        primary_error: Option<Box<S::Error>>,
        hedge_error: Option<Box<S::Error>>,
    },
    Done,
}

impl<S, Request> fmt::Debug for HedgeFuture<S, Request>
where
    S: Service<Request>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HedgeFuture").finish()
    }
}

impl<S, Request> HedgeFuture<S, Request>
where
    S: Service<Request>,
{
    #[must_use]
    fn not_ready() -> Self {
        Self {
            state: HedgeFutureState::NotReady,
        }
    }

    #[must_use]
    fn new(
        primary: S::Future,
        hedge_service: Option<S>,
        request: Request,
        config: &HedgeConfig,
        stats: Arc<HedgeStats>,
    ) -> Self {
        let deadline = (config.time_getter)().saturating_add_nanos(duration_to_nanos(config.delay));
        Self {
            state: HedgeFutureState::Running {
                primary: Some(primary),
                hedge_service,
                hedge_request: Some(request),
                hedge_future: None,
                sleep: Sleep::with_time_getter(deadline, config.time_getter),
                time_getter: config.time_getter,
                max_pending: config.max_pending,
                stats,
                slot_held: false,
                delay_elapsed: false,
                primary_error: None,
                hedge_error: None,
            },
        }
    }
}

impl<S, Request> Drop for HedgeFuture<S, Request>
where
    S: Service<Request>,
{
    fn drop(&mut self) {
        if let HedgeFutureState::Running {
            stats,
            slot_held: true,
            ..
        } = &mut self.state
        {
            stats.release_pending_slot();
        }
    }
}

#[allow(clippy::too_many_lines)]
impl<S, Request> Future for HedgeFuture<S, Request>
where
    S: Service<Request> + Clone + Unpin,
    S::Future: Unpin,
    Request: Clone + Unpin,
{
    type Output = Result<S::Response, HedgeError<S::Error>>;

    #[allow(clippy::too_many_lines)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();

        loop {
            match &mut this.state {
                HedgeFutureState::NotReady => {
                    this.state = HedgeFutureState::Done;
                    return Poll::Ready(Err(HedgeError::NotReady));
                }
                HedgeFutureState::Done => {
                    return Poll::Ready(Err(HedgeError::PolledAfterCompletion));
                }
                HedgeFutureState::Running {
                    primary,
                    hedge_service,
                    hedge_request,
                    hedge_future,
                    sleep,
                    time_getter,
                    max_pending,
                    stats,
                    slot_held,
                    delay_elapsed,
                    primary_error,
                    hedge_error,
                } => {
                    let mut progressed = false;

                    if let Some(primary_future) = primary.as_mut() {
                        match Pin::new(primary_future).poll(cx) {
                            Poll::Ready(Ok(response)) => {
                                if *slot_held {
                                    stats.finish_started_hedge(false);
                                    *slot_held = false;
                                }
                                this.state = HedgeFutureState::Done;
                                return Poll::Ready(Ok(response));
                            }
                            Poll::Ready(Err(err)) => {
                                *primary = None;
                                *primary_error = Some(Box::new(err));
                                progressed = true;
                            }
                            Poll::Pending => {}
                        }
                    }

                    if let Some(hedge_request_future) = hedge_future.as_mut() {
                        match Pin::new(hedge_request_future).poll(cx) {
                            Poll::Ready(Ok(response)) => {
                                if *slot_held {
                                    stats.finish_started_hedge(true);
                                    *slot_held = false;
                                }
                                this.state = HedgeFutureState::Done;
                                return Poll::Ready(Ok(response));
                            }
                            Poll::Ready(Err(err)) => {
                                if *slot_held {
                                    stats.release_pending_slot();
                                    *slot_held = false;
                                }
                                *hedge_future = None;
                                *hedge_error = Some(Box::new(err));
                                progressed = true;
                            }
                            Poll::Pending => {}
                        }
                    }

                    if primary.is_none() {
                        if let Some(hedge_err) = hedge_error.take() {
                            let primary_err = primary_error
                                .take()
                                .expect("primary error must exist when primary future is gone");
                            this.state = HedgeFutureState::Done;
                            return Poll::Ready(Err(HedgeError::BothFailed {
                                primary: *primary_err,
                                hedge: *hedge_err,
                            }));
                        }

                        if hedge_future.is_none() {
                            // No hedge in flight. Release any held slot and
                            // propagate the primary error rather than holding
                            // a pending slot indefinitely while the hedge
                            // service may never become ready.
                            if *slot_held {
                                stats.release_pending_slot();
                                *slot_held = false;
                            }
                            let primary_err = primary_error
                                .take()
                                .expect("primary error must exist when primary future is gone");
                            this.state = HedgeFutureState::Done;
                            return Poll::Ready(Err(HedgeError::Inner(*primary_err)));
                        }
                    }

                    if hedge_service.is_some() && (primary.is_some() || *slot_held) {
                        // Track whether the hedge delay has elapsed. Once
                        // the sleep fires we must never re-poll it (Sleep
                        // asserts on poll-after-completion). The flag is
                        // independent of slot acquisition so it survives
                        // across re-polls when slot acquisition fails.
                        if !*delay_elapsed {
                            if sleep.poll_with_time(time_getter()).is_ready() {
                                *delay_elapsed = true;
                            } else {
                                let _ = Pin::new(sleep).poll(cx);
                            }
                        }

                        if *delay_elapsed {
                            if !*slot_held {
                                if stats.try_acquire_pending_slot(*max_pending) {
                                    *slot_held = true;
                                    progressed = true;
                                } else if primary.is_some() {
                                    return Poll::Pending;
                                }
                            }

                            if *slot_held
                                && hedge_future.is_none()
                                && let Some(service) = hedge_service.as_mut()
                            {
                                match service.poll_ready(cx) {
                                    Poll::Ready(Ok(())) => {
                                        let request = hedge_request
                                            .take()
                                            .expect("hedge request must exist before dispatch");
                                        let future = service.call(request);
                                        *hedge_future = Some(future);
                                        *hedge_service = None;
                                        stats.record_hedge();
                                        progressed = true;
                                    }
                                    Poll::Ready(Err(err)) => {
                                        stats.release_pending_slot();
                                        *slot_held = false;
                                        *hedge_service = None;
                                        *hedge_request = None;
                                        *hedge_error = Some(Box::new(err));
                                        progressed = true;
                                    }
                                    Poll::Pending => {}
                                }
                            }
                        }
                    }

                    if primary.is_none()
                        && hedge_future.is_none()
                        && *slot_held
                        && hedge_service.is_none()
                    {
                        let primary_err = primary_error
                            .take()
                            .expect("primary error must exist when primary future is gone");
                        let hedge_err = hedge_error
                            .take()
                            .expect("hedge error must exist when hedge dispatch failed");
                        stats.release_pending_slot();
                        *slot_held = false;
                        this.state = HedgeFutureState::Done;
                        return Poll::Ready(Err(HedgeError::BothFailed {
                            primary: *primary_err,
                            hedge: *hedge_err,
                        }));
                    }

                    if progressed {
                        continue;
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::collections::VecDeque;
    use std::future::Future as StdFuture;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Arc::new(NoopWaker).into()
    }

    std::thread_local! {
        static TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.with(std::cell::Cell::get))
    }

    fn set_test_time(t: u64) {
        TEST_NOW.with(|now| now.set(t));
    }

    #[derive(Debug)]
    struct TimedPlan {
        ready_at: u64,
        result: Result<u32, &'static str>,
    }

    impl TimedPlan {
        fn ok_at(ready_at: u64, value: u32) -> Self {
            Self {
                ready_at,
                result: Ok(value),
            }
        }

        fn err_at(ready_at: u64, err: &'static str) -> Self {
            Self {
                ready_at,
                result: Err(err),
            }
        }
    }

    #[derive(Clone, Debug)]
    struct TimedService {
        plans: Arc<Mutex<VecDeque<TimedPlan>>>,
        calls: Arc<AtomicUsize>,
    }

    impl TimedService {
        fn new(plans: Vec<TimedPlan>, calls: Arc<AtomicUsize>) -> Self {
            Self {
                plans: Arc::new(Mutex::new(plans.into())),
                calls,
            }
        }
    }

    #[derive(Debug)]
    struct TimedFuture {
        ready_at: u64,
        result: Option<Result<u32, &'static str>>,
    }

    impl StdFuture for TimedFuture {
        type Output = Result<u32, &'static str>;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if TEST_NOW.with(std::cell::Cell::get) >= self.ready_at {
                Poll::Ready(
                    self.result
                        .take()
                        .expect("timed future must only complete once"),
                )
            } else {
                Poll::Pending
            }
        }
    }

    impl Service<u32> for TimedService {
        type Response = u32;
        type Error = &'static str;
        type Future = TimedFuture;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let plan = self
                .plans
                .lock()
                .pop_front()
                .expect("timed service exhausted test plans");
            TimedFuture {
                ready_at: plan.ready_at,
                result: Some(plan.result),
            }
        }
    }

    // ================================================================
    // HedgeConfig
    // ================================================================

    #[test]
    fn config_new() {
        init_test("config_new");
        let config = HedgeConfig::new(Duration::from_millis(100));
        assert_eq!(config.delay, Duration::from_millis(100));
        assert_eq!(config.max_pending, 10);
        crate::test_complete!("config_new");
    }

    #[test]
    fn config_max_pending() {
        let config = HedgeConfig::new(Duration::from_millis(50)).max_pending(5);
        assert_eq!(config.max_pending, 5);
    }

    #[test]
    fn config_debug_clone() {
        let config = HedgeConfig::new(Duration::from_millis(100));
        let dbg = format!("{config:?}");
        assert!(dbg.contains("HedgeConfig"));
        let cloned = config.clone();
        assert_eq!(cloned.delay, Duration::from_millis(100));
        assert_eq!(config.delay, Duration::from_millis(100));
    }

    #[test]
    fn config_with_time_getter() {
        set_test_time(55);
        let config = HedgeConfig::new(Duration::from_nanos(5)).with_time_getter(test_time);
        assert_eq!((config.time_getter())(), Time::from_nanos(55));
    }

    // ================================================================
    // HedgeLayer
    // ================================================================

    #[test]
    fn layer_new() {
        let layer = HedgeLayer::new(HedgeConfig::new(Duration::from_millis(100)));
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("HedgeLayer"));
    }

    #[test]
    fn layer_with_delay() {
        let layer = HedgeLayer::with_delay(Duration::from_millis(200));
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("HedgeLayer"));
    }

    #[test]
    fn layer_clone() {
        let layer = HedgeLayer::with_delay(Duration::from_millis(100));
        let cloned = layer.clone();
        assert_eq!(cloned.config.delay, Duration::from_millis(100));
        assert_eq!(layer.config.delay, Duration::from_millis(100));
    }

    // ================================================================
    // Hedge service
    // ================================================================

    #[derive(Clone, Debug)]
    struct MockSvc;

    #[derive(Clone, Debug)]
    struct PanicOnCallService;

    #[derive(Clone, Debug)]
    struct RequiresReadyService {
        ready: bool,
        calls: Arc<AtomicUsize>,
    }

    impl Service<u32> for PanicOnCallService {
        type Response = ();
        type Error = ();
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            panic!("panic during hedge call construction");
        }
    }

    impl Service<u32> for RequiresReadyService {
        type Response = u32;
        type Error = &'static str;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.ready = true;
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: u32) -> Self::Future {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let was_ready = std::mem::replace(&mut self.ready, false);
            if was_ready {
                std::future::ready(Ok(req))
            } else {
                std::future::ready(Err("not ready"))
            }
        }
    }

    #[test]
    fn hedge_new() {
        init_test("hedge_new");
        let hedge = Hedge::new(MockSvc, HedgeConfig::new(Duration::from_millis(100)));
        assert_eq!(hedge.delay(), Duration::from_millis(100));
        assert_eq!(hedge.max_pending(), 10);
        assert_eq!(hedge.total_requests(), 0);
        assert_eq!(hedge.hedged_requests(), 0);
        assert_eq!(hedge.hedge_wins(), 0);
        assert!((hedge.hedge_rate() - 0.0).abs() < f64::EPSILON);
        crate::test_complete!("hedge_new");
    }

    #[test]
    fn hedge_stats() {
        init_test("hedge_stats");
        let hedge = Hedge::new(MockSvc, HedgeConfig::new(Duration::from_millis(100)));
        hedge.record_request();
        hedge.record_request();
        hedge.record_hedge();
        hedge.record_hedge_win();
        assert_eq!(hedge.total_requests(), 2);
        assert_eq!(hedge.hedged_requests(), 1);
        assert_eq!(hedge.hedge_wins(), 1);
        assert!((hedge.hedge_rate() - 0.5).abs() < f64::EPSILON);
        crate::test_complete!("hedge_stats");
    }

    #[test]
    fn hedge_call_panic_does_not_overcount_total_requests() {
        init_test("hedge_call_panic_does_not_overcount_total_requests");
        let mut hedge = Hedge::new(
            PanicOnCallService,
            HedgeConfig::new(Duration::from_millis(100)),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let ready = hedge.poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _f = hedge.call(7);
        }));
        let panicked = panic.is_err();
        crate::assert_with_log!(panicked, "inner call panicked", true, panicked);

        let total = hedge.total_requests();
        crate::assert_with_log!(total == 0, "total requests", 0, total);
        crate::test_complete!("hedge_call_panic_does_not_overcount_total_requests");
    }

    #[test]
    fn hedge_call_without_poll_ready_fails_closed() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            RequiresReadyService {
                ready: false,
                calls: Arc::clone(&calls),
            },
            HedgeConfig::new(Duration::from_millis(100)),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = hedge.call(7);
        let result = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(HedgeError::NotReady))));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(hedge.total_requests(), 0);
    }

    #[test]
    fn hedge_ready_window_is_consumed_by_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            RequiresReadyService {
                ready: false,
                calls: Arc::clone(&calls),
            },
            HedgeConfig::new(Duration::from_millis(100)),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first_ready = hedge.poll_ready(&mut cx);
        assert!(matches!(first_ready, Poll::Ready(Ok(()))));

        let mut first = hedge.call(11);
        let first_result = Pin::new(&mut first).poll(&mut cx);
        assert!(matches!(first_result, Poll::Ready(Ok(11))));

        let mut second = hedge.call(22);
        let second_result = Pin::new(&mut second).poll(&mut cx);
        assert!(matches!(
            second_result,
            Poll::Ready(Err(HedgeError::NotReady))
        ));

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(hedge.total_requests(), 1);
    }

    #[test]
    fn hedge_clone_does_not_inherit_ready_window() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            RequiresReadyService {
                ready: false,
                calls: Arc::clone(&calls),
            },
            HedgeConfig::new(Duration::from_millis(100)),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = hedge.poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let mut clone = hedge.clone();
        let mut fut = clone.call(99);
        let result = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(HedgeError::NotReady))));

        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(clone.total_requests(), 0);
    }

    #[test]
    fn hedge_primary_completes_before_delay_without_backup() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![TimedPlan::ok_at(5, 11), TimedPlan::ok_at(20, 22)],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10)).with_time_getter(test_time),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future = hedge.call(7);
        let res = Pin::new(&mut future).poll(&mut cx);
        assert!(res.is_pending(), "Expected pending, got {res:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        set_test_time(5);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(11))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(hedge.hedged_requests(), 0);
        assert_eq!(hedge.hedge_wins(), 0);
    }

    #[test]
    fn hedge_dispatches_backup_after_delay_and_backup_can_win() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![TimedPlan::ok_at(30, 11), TimedPlan::ok_at(12, 22)],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10))
                .max_pending(1)
                .with_time_getter(test_time),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future = hedge.call(7);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        set_test_time(10);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(hedge.hedged_requests(), 1);

        set_test_time(12);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(22))));
        assert_eq!(hedge.hedge_wins(), 1);
    }

    #[test]
    fn hedge_backup_can_rescue_primary_error() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![
                    TimedPlan::err_at(30, "primary failed"),
                    TimedPlan::ok_at(12, 77),
                ],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10))
                .max_pending(1)
                .with_time_getter(test_time),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future = hedge.call(7);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());

        set_test_time(10);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        set_test_time(12);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(77))));
        assert_eq!(hedge.hedged_requests(), 1);
        assert_eq!(hedge.hedge_wins(), 1);
    }

    #[test]
    fn hedge_reports_both_failed_when_primary_and_backup_fail() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![
                    TimedPlan::err_at(30, "primary failed"),
                    TimedPlan::err_at(12, "hedge failed"),
                ],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10))
                .max_pending(1)
                .with_time_getter(test_time),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future = hedge.call(7);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        set_test_time(10);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        set_test_time(12);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        set_test_time(30);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            result,
            Poll::Ready(Err(HedgeError::BothFailed {
                primary: "primary failed",
                hedge: "hedge failed"
            }))
        ));
    }

    #[test]
    fn hedge_max_pending_zero_disables_backup_dispatch() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![TimedPlan::ok_at(30, 11), TimedPlan::ok_at(12, 22)],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10))
                .max_pending(0)
                .with_time_getter(test_time),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future = hedge.call(7);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        set_test_time(10);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(hedge.hedged_requests(), 0);

        set_test_time(30);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(11))));
    }

    #[test]
    fn hedge_inner() {
        let hedge = Hedge::new(42u32, HedgeConfig::new(Duration::from_millis(100)));
        assert_eq!(*hedge.inner(), 42);
    }

    #[test]
    fn hedge_inner_mut() {
        let mut hedge = Hedge::new(42u32, HedgeConfig::new(Duration::from_millis(100)));
        *hedge.inner_mut() = 99;
        assert_eq!(*hedge.inner(), 99);
    }

    #[test]
    fn hedge_config_ref() {
        let hedge = Hedge::new(MockSvc, HedgeConfig::new(Duration::from_millis(100)));
        assert_eq!(hedge.config().delay, Duration::from_millis(100));
    }

    #[test]
    fn hedge_debug() {
        let hedge = Hedge::new(MockSvc, HedgeConfig::new(Duration::from_millis(100)));
        let dbg = format!("{hedge:?}");
        assert!(dbg.contains("Hedge"));
    }

    #[test]
    fn hedge_clone() {
        let hedge = Hedge::new(MockSvc, HedgeConfig::new(Duration::from_millis(100)));
        hedge.record_request();
        let cloned = hedge.clone();
        // Clone shares hedge statistics but not readiness tickets.
        assert_eq!(cloned.total_requests(), 1);
        assert_eq!(cloned.delay(), Duration::from_millis(100));
        assert_eq!(hedge.total_requests(), 1);
    }

    #[test]
    fn hedge_layer_applies() {
        init_test("hedge_layer_applies");
        let layer = HedgeLayer::with_delay(Duration::from_millis(50));
        let svc = layer.layer(MockSvc);
        assert_eq!(svc.delay(), Duration::from_millis(50));
        crate::test_complete!("hedge_layer_applies");
    }

    // ================================================================
    // HedgeError
    // ================================================================

    #[test]
    fn error_inner_display() {
        let err: HedgeError<std::io::Error> = HedgeError::Inner(std::io::Error::other("fail"));
        assert!(format!("{err}").contains("service error"));
    }

    #[test]
    fn error_not_ready_display() {
        let err: HedgeError<std::io::Error> = HedgeError::NotReady;
        assert_eq!(format!("{err}"), "poll_ready required before call");
    }

    #[test]
    fn error_polled_after_completion_display() {
        let err: HedgeError<std::io::Error> = HedgeError::PolledAfterCompletion;
        assert_eq!(format!("{err}"), "hedge future polled after completion");
    }

    #[test]
    fn error_both_failed_display() {
        let err: HedgeError<std::io::Error> = HedgeError::BothFailed {
            primary: std::io::Error::other("p"),
            hedge: std::io::Error::other("h"),
        };
        assert!(format!("{err}").contains("both primary and hedge failed"));
    }

    #[test]
    fn error_source() {
        use std::error::Error;
        let err: HedgeError<std::io::Error> = HedgeError::Inner(std::io::Error::other("fail"));
        assert!(err.source().is_some());

        let not_ready: HedgeError<std::io::Error> = HedgeError::NotReady;
        assert!(not_ready.source().is_none());

        let done: HedgeError<std::io::Error> = HedgeError::PolledAfterCompletion;
        assert!(done.source().is_none());
    }

    #[test]
    fn error_debug() {
        let err: HedgeError<std::io::Error> = HedgeError::Inner(std::io::Error::other("fail"));
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Inner"));
    }

    #[test]
    fn error_debug_includes_polled_after_completion() {
        let err: HedgeError<std::io::Error> = HedgeError::PolledAfterCompletion;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PolledAfterCompletion"));
    }

    // ================================================================
    // HedgeFuture
    // ================================================================

    #[test]
    fn hedge_future_debug() {
        set_test_time(0);
        let fut = HedgeFuture::new(
            TimedFuture {
                ready_at: 5,
                result: Some(Ok(42)),
            },
            None::<TimedService>,
            7_u32,
            &HedgeConfig::new(Duration::from_nanos(10)).with_time_getter(test_time),
            Arc::new(HedgeStats {
                total: AtomicU64::new(0),
                hedged: AtomicU64::new(0),
                hedge_wins: AtomicU64::new(0),
                pending: AtomicU64::new(0),
            }),
        );
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("HedgeFuture"));
    }

    /// Regression: hedge delay elapses, slot acquired, but service.poll_ready
    /// returns Pending. On next poll, the completed Sleep must NOT be
    /// re-polled (which would panic).
    #[test]
    fn hedge_does_not_repoll_completed_sleep_when_slot_held() {
        // Use a dedicated time source to avoid races with other tests
        // that share the module-level TEST_NOW static.
        static LOCAL_NOW: AtomicU64 = AtomicU64::new(0);
        fn local_time() -> Time {
            Time::from_nanos(LOCAL_NOW.load(Ordering::SeqCst))
        }

        // A service that returns Pending from poll_ready on the first calls,
        // then Ready(Ok(())) once the countdown reaches zero.
        #[derive(Clone, Debug)]
        struct DelayedReadyService {
            ready_countdown: Arc<AtomicUsize>,
            calls: Arc<AtomicUsize>,
        }

        impl Service<u32> for DelayedReadyService {
            type Response = u32;
            type Error = &'static str;
            type Future = TimedFuture;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                let prev = self.ready_countdown.fetch_sub(1, Ordering::SeqCst);
                if prev > 0 {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(()))
                }
            }

            fn call(&mut self, _req: u32) -> Self::Future {
                self.calls.fetch_add(1, Ordering::SeqCst);
                TimedFuture {
                    ready_at: 0,
                    result: Some(Ok(99)),
                }
            }
        }

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        LOCAL_NOW.store(0, Ordering::SeqCst);
        let calls = Arc::new(AtomicUsize::new(0));
        let svc = DelayedReadyService {
            // Pending twice: once on the first try after slot acquire
            // (within the same poll's progress loop), then again on the
            // next external poll which re-enters with slot_held=true.
            ready_countdown: Arc::new(AtomicUsize::new(2)),
            calls: Arc::clone(&calls),
        };
        let stats = Arc::new(HedgeStats {
            total: AtomicU64::new(0),
            hedged: AtomicU64::new(0),
            hedge_wins: AtomicU64::new(0),
            pending: AtomicU64::new(0),
        });

        // Primary future that never completes (stays Pending).
        let primary = TimedFuture {
            ready_at: u64::MAX,
            result: Some(Ok(0)),
        };

        // Use a large delay so other tests' TEST_NOW values cannot
        // accidentally elapse it.
        let config = HedgeConfig::new(Duration::from_millis(1))
            .with_time_getter(local_time)
            .max_pending(5);
        let mut fut = HedgeFuture::new(primary, Some(svc), 42_u32, &config, stats);

        // Poll 1: timer not elapsed yet, both primary and hedge pending.
        let p1 = Pin::new(&mut fut).poll(&mut cx);
        assert!(p1.is_pending());

        // Advance time past the delay.
        LOCAL_NOW.store(2_000_000, Ordering::SeqCst);

        // Poll 2: timer elapses, slot acquired, poll_ready returns Pending
        // twice (once in progress loop, once after re-enter). Returns Pending
        // because the service is not yet ready.
        let p2 = Pin::new(&mut fut).poll(&mut cx);
        assert!(p2.is_pending());

        // Poll 3: this used to panic ("Sleep polled after completion") before
        // the fix. Now it should skip the sleep (slot_held=true), re-poll
        // poll_ready which returns Ready, dispatch the hedge, and the hedge
        // future completes immediately.
        let p3 = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(p3, Poll::Ready(Ok(99))));
    }

    #[test]
    fn hedge_future_second_poll_fails_closed() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        set_test_time(0);
        let mut fut = HedgeFuture::new(
            TimedFuture {
                ready_at: 0,
                result: Some(Ok(42)),
            },
            None::<TimedService>,
            7_u32,
            &HedgeConfig::new(Duration::from_nanos(10)).with_time_getter(test_time),
            Arc::new(HedgeStats {
                total: AtomicU64::new(0),
                hedged: AtomicU64::new(0),
                hedge_wins: AtomicU64::new(0),
                pending: AtomicU64::new(0),
            }),
        );

        let first = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok(42))));

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(HedgeError::PolledAfterCompletion))
        ));
    }
}
