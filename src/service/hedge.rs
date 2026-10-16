//! Hedge middleware layer.
//!
//! The [`HedgeLayer`] wraps a cloneable service to issue a backup (hedge)
//! request when the primary request takes too long. The first response
//! to complete is returned, reducing tail latency.
//!
//! This is a latency-optimisation technique from the paper "The Tail at
//! Scale" (Dean & Barroso, 2013).

use super::{Layer, Service};
use crate::combinator::PeakEwmaHedgeController;
use crate::time::{Sleep, wall_now};
use crate::types::Time;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
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

    /// Create a hedge layer with an adaptive delay controller.
    #[must_use]
    pub fn with_adaptive_delay(controller: Arc<PeakEwmaHedgeController>) -> Self {
        let initial_delay = controller.current_delay();
        Self::new(HedgeConfig::new(initial_delay).with_adaptive_delay(controller))
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
    /// A custom time source, or `None` for the runtime's clock. The runtime's
    /// clock is `wall_now`, which reads the ambient timer driver, so the hedge
    /// delay waits on that driver or, off the runtime, on the shared fallback
    /// timer. A custom getter makes every request's `Sleep` poll that getter
    /// from a thread of its own (br-asupersync-1sxucf).
    time_getter: Option<fn() -> Time>,
    /// Optional adaptive delay controller based on Peak-EWMA. When set, each
    /// request's hedge delay tracks the controller's current estimate rather
    /// than the static `delay`, and successful primary responses observe their
    /// latency into the controller (asupersync-m82nx1).
    adaptive_controller: Option<Arc<PeakEwmaHedgeController>>,
}

impl HedgeConfig {
    /// Create a new hedge configuration with the given delay.
    #[must_use]
    pub fn new(delay: Duration) -> Self {
        Self {
            delay,
            max_pending: 10,
            time_getter: None,
            adaptive_controller: None,
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
        self.time_getter = Some(time_getter);
        self
    }

    /// Set an adaptive delay controller to dynamically calculate hedge delays.
    #[must_use]
    pub fn with_adaptive_delay(mut self, controller: Arc<PeakEwmaHedgeController>) -> Self {
        self.adaptive_controller = Some(controller);
        self
    }

    /// Returns the time source used for hedge deadlines.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        match self.time_getter {
            Some(time_getter) => time_getter,
            None => wall_clock_now,
        }
    }

    /// Returns a reference to the adaptive controller, if configured.
    #[must_use]
    pub fn adaptive_controller(&self) -> Option<&Arc<PeakEwmaHedgeController>> {
        self.adaptive_controller.as_ref()
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
    /// Wakers of hedge futures parked waiting for a pending slot to free up.
    /// `pending` is shared across all hedge futures cloned from one `Hedge`, so a
    /// future that loses the slot race must be re-woken when another future
    /// releases its slot — otherwise it parks only on its (slow) primary and its
    /// hedge is silently never dispatched even while a slot is available.
    slot_waiters: parking_lot::Mutex<Vec<Waker>>,
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

    /// Register a waker to be notified when a pending slot frees up. Deduped via
    /// `Waker::will_wake` so repeated polls of the same future don't accumulate
    /// duplicate entries.
    fn register_slot_waiter(&self, waker: &Waker) {
        let mut waiters = self.slot_waiters.lock();
        if waiters.iter().any(|existing| existing.will_wake(waker)) {
            return;
        }
        waiters.push(waker.clone());
    }

    fn release_pending_slot(&self) {
        let released = self
            .pending
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(1)
            })
            .is_ok();
        if !released {
            return;
        }

        // Bare wakers are notifications, not slot grants. A registered future
        // may complete before release, or a selected live future may be dropped
        // before it re-polls and acquires. Detach every current waiter so those
        // stale entries cannot strand a live peer behind an available slot.
        // Wake only after releasing the mutex because a custom waker may
        // synchronously re-enter and register again.
        let waiters = {
            let mut waiters = self.slot_waiters.lock();
            std::mem::take(&mut *waiters)
        };
        for waker in waiters {
            waker.wake();
        }
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
                slot_waiters: parking_lot::Mutex::new(Vec::new()),
            }),
            ready_observed: false,
        }
    }

    /// Get the configured delay threshold.
    #[must_use]
    pub fn delay(&self) -> Duration {
        match &self.config.adaptive_controller {
            Some(controller) => controller.current_delay(),
            None => self.config.delay,
        }
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

    fn release_readiness(&mut self) -> super::ReadinessRelease {
        self.ready_observed = false;
        self.inner.release_readiness()
    }

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
        hedge_service: Option<super::service::ReadinessService<S, Request>>,
        hedge_request: Option<Request>,
        hedge_future: Option<S::Future>,
        sleep: Sleep,
        time_getter: fn() -> Time,
        start_time: Time,
        adaptive_controller: Option<Arc<PeakEwmaHedgeController>>,
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
        let time_getter = config.time_getter();
        let start_time = time_getter();
        let delay = match &config.adaptive_controller {
            Some(controller) => controller.current_delay(),
            None => config.delay,
        };
        let deadline = start_time.saturating_add_nanos(duration_to_nanos(delay));
        let sleep = match config.time_getter {
            Some(time_getter) => Sleep::with_time_getter(deadline, time_getter),
            None => Sleep::new(deadline),
        };
        Self {
            state: HedgeFutureState::Running {
                primary: Some(primary),
                hedge_service: hedge_service.map(super::service::ReadinessService::new),
                hedge_request: Some(request),
                hedge_future: None,
                sleep,
                time_getter,
                start_time,
                adaptive_controller: config.adaptive_controller.clone(),
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
                    start_time,
                    adaptive_controller,
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
                                if let Some(controller) = adaptive_controller.as_ref() {
                                    let elapsed_nanos = time_getter().duration_since(*start_time);
                                    controller.observe(Duration::from_nanos(elapsed_nanos));
                                }
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
                            } else if Pin::new(sleep).poll(cx).is_ready() {
                                // The registering poll completed the Sleep, so
                                // decide now instead of polling it again
                                // (asupersync-bi2462.168). Sleep completes early
                                // when the current task is cancelled, and a
                                // cancelled task starts no backup; otherwise
                                // the delay passed between the two clock reads.
                                if crate::cx::Cx::current()
                                    .is_some_and(|current| current.is_cancel_requested())
                                {
                                    *hedge_service = None;
                                    *hedge_request = None;
                                } else {
                                    *delay_elapsed = true;
                                }
                            }
                        }

                        if *delay_elapsed {
                            if !*slot_held {
                                if stats.try_acquire_pending_slot(*max_pending) {
                                    *slot_held = true;
                                    progressed = true;
                                } else if primary.is_some() {
                                    // Park for a freed slot. Register BEFORE the
                                    // final re-check so a concurrent release
                                    // can't be missed (register-then-recheck
                                    // closes the lost-wakeup race). Without this
                                    // the future parks only on its slow primary
                                    // and its hedge never fires even once a slot
                                    // is freed by another hedge future.
                                    stats.register_slot_waiter(cx.waker());
                                    if stats.try_acquire_pending_slot(*max_pending) {
                                        *slot_held = true;
                                        progressed = true;
                                    } else {
                                        return Poll::Pending;
                                    }
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
#[path = "hedge_inline_tests.rs"]
mod tests;
