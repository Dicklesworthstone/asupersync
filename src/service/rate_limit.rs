//! Rate limiting middleware layer.
//!
//! The [`RateLimitLayer`] wraps a service to limit the rate of requests using
//! a token bucket algorithm. Requests are only allowed when tokens are available.

use super::{Layer, Service};
use crate::types::Time;
use parking_lot::Mutex;
use pin_project::pin_project;
use slab::Slab;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

/// A layer that rate-limits requests using a token bucket.
///
/// The rate limiter allows `rate` requests per `period`. Requests beyond the
/// limit will cause `poll_ready` to return `Poll::Pending` until more tokens
/// become available.
///
/// # Example
///
/// ```ignore
/// use asupersync::service::{ServiceBuilder, ServiceExt};
/// use asupersync::service::rate_limit::RateLimitLayer;
/// use std::time::Duration;
///
/// let svc = ServiceBuilder::new()
///     .layer(RateLimitLayer::new(100, Duration::from_secs(1)))  // 100 req/sec
///     .service(my_service);
/// ```
#[derive(Debug, Clone)]
pub struct RateLimitLayer {
    /// Tokens added per period.
    rate: u64,
    /// Duration of each period.
    period: Duration,
    time_getter: fn() -> Time,
}

impl RateLimitLayer {
    /// Creates a new rate limit layer.
    ///
    /// # Arguments
    ///
    /// * `rate` - Maximum requests allowed per period
    /// * `period` - The time period for the rate limit
    #[must_use]
    pub const fn new(rate: u64, period: Duration) -> Self {
        Self {
            rate,
            period,
            time_getter: wall_clock_now,
        }
    }

    /// Creates a new rate limit layer with a custom time source.
    #[must_use]
    pub const fn with_time_getter(rate: u64, period: Duration, time_getter: fn() -> Time) -> Self {
        Self {
            rate,
            period,
            time_getter,
        }
    }

    /// Returns the rate (tokens per period).
    #[must_use]
    pub const fn rate(&self) -> u64 {
        self.rate
    }

    /// Returns the period duration.
    #[must_use]
    pub const fn period(&self) -> Duration {
        self.period
    }

    /// Returns the time source used by this layer.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimit::with_time_getter(inner, self.rate, self.period, self.time_getter)
    }
}

/// A service that rate-limits requests using a token bucket.
///
/// The token bucket refills at a rate of `rate` tokens per `period`.
/// Each request consumes one token. When no tokens are available,
/// `poll_ready` returns `Poll::Pending`.
#[derive(Debug)]
pub struct RateLimit<S> {
    inner: S,
    /// Shared token-bucket state. Cloned services must coordinate available
    /// capacity through the same bucket so cloning cannot multiply throughput.
    state: Arc<Mutex<SharedRateLimitState>>,
    /// Number of tokens reserved by successful `poll_ready` calls that have not
    /// yet been consumed by `call()`. Reservations are handle-local because a
    /// fresh clone must not be able to spend another handle's readiness grant.
    ///
    /// Because clones share the bucket, abandoning a granted reservation must
    /// return the token to the shared bucket on drop instead of leaking shared
    /// capacity until the next refill window.
    reservations: LocalReservationState,
    /// Maximum tokens (bucket capacity).
    rate: u64,
    /// Period for refilling tokens.
    period: Duration,
    time_getter: fn() -> Time,
    /// Timer for sleeping when tokens are exhausted.
    sleep: Option<crate::time::Sleep>,
}

#[derive(Debug)]
struct SharedRateLimitState {
    /// Current number of available tokens in the shared bucket.
    tokens: u64,
    /// Last time the bucket state was refilled.
    last_refill: Option<Time>,
    /// Exhausted handles waiting for either a refund or the deadline refill.
    waiters: Slab<RateLimitWaiter>,
    /// Generation component for stable waiter handles across slab slot reuse.
    next_waiter_id: u64,
}

#[derive(Debug)]
struct RateLimitWaiter {
    id: u64,
    registration: Arc<RegisteredRateLimitWaker>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RateLimitWaiterHandle {
    slot: usize,
    id: u64,
}

/// Arc-owned executor waker stored beneath the shared bucket mutex.
///
/// RawWaker clone, wake, and final destruction all happen after the mutex is
/// released. Under-lock registry operations only move or clone this Arc.
#[derive(Debug)]
struct RegisteredRateLimitWaker {
    waker: Waker,
}

impl RegisteredRateLimitWaker {
    #[inline]
    fn new(waker: &Waker) -> Arc<Self> {
        Arc::new(Self {
            waker: waker.clone(),
        })
    }

    #[inline]
    fn will_wake(&self, waker: &Waker) -> bool {
        self.waker.will_wake(waker)
    }

    #[inline]
    fn wake_by_ref(&self) {
        self.waker.wake_by_ref();
    }
}

#[inline]
const fn max_bucket_tokens(rate: u64, zero_period: bool) -> u64 {
    // `u64::max` (Ord::max) is not const-stable on the pinned nightly-2026-07-05
    // (E0658 const_cmp); express the `rate.max(1)` clamp with plain const-legal
    // comparison instead so the crate keeps building without an unstable feature.
    if zero_period && rate < 1 { 1 } else { rate }
}

#[inline]
fn waiter_by_handle(
    state: &SharedRateLimitState,
    handle: RateLimitWaiterHandle,
) -> Option<&RateLimitWaiter> {
    let waiter = state.waiters.get(handle.slot)?;
    (waiter.id == handle.id).then_some(waiter)
}

#[inline]
fn remove_waiter_locked(
    state: &mut SharedRateLimitState,
    handle: &mut Option<RateLimitWaiterHandle>,
) -> Option<Arc<RegisteredRateLimitWaker>> {
    let handle = handle.take()?;
    waiter_by_handle(state, handle)?;
    state
        .waiters
        .try_remove(handle.slot)
        .map(|removed| removed.registration)
}

#[inline]
fn restore_tokens_locked(
    state: &mut SharedRateLimitState,
    count: u64,
    max_tokens: u64,
) -> Slab<RateLimitWaiter> {
    if count == 0 {
        return Slab::new();
    }
    let was_empty = state.tokens == 0;
    state.tokens = state.tokens.saturating_add(count).min(max_tokens);
    if was_empty && state.tokens > 0 {
        std::mem::take(&mut state.waiters)
    } else {
        Slab::new()
    }
}

#[inline]
fn retire_registration_after_unlock(registration: Option<Arc<RegisteredRateLimitWaker>>) {
    let Some(registration) = registration else {
        return;
    };
    if let Err(payload) =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(registration)))
    {
        std::mem::forget(payload);
    }
}

fn wake_waiters_after_unlock(waiters: Slab<RateLimitWaiter>) {
    for (_, waiter) in waiters {
        let registration = waiter.registration;
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            registration.wake_by_ref();
        })) {
            std::mem::forget(payload);
        }
        retire_registration_after_unlock(Some(registration));
    }
}

#[inline]
fn restore_tokens_and_wake(state: &Arc<Mutex<SharedRateLimitState>>, count: u64, max_tokens: u64) {
    let waiters = {
        let mut state = state.lock();
        restore_tokens_locked(&mut state, count, max_tokens)
    };
    wake_waiters_after_unlock(waiters);
}

impl<S: Clone> Clone for RateLimit<S> {
    fn clone(&self) -> Self {
        let state = Arc::clone(&self.state);
        Self {
            inner: self.inner.clone(),
            state: Arc::clone(&state),
            // Readiness reservations are handle-local and must not be inherited
            // by a fresh clone, or a clone can spend another handle's poll_ready
            // reservation without performing its own readiness check.
            reservations: LocalReservationState::new(
                state,
                max_bucket_tokens(self.rate, self.period.is_zero()),
            ),
            rate: self.rate,
            period: self.period,
            time_getter: self.time_getter,
            sleep: None, // Sleep state is not cloned
        }
    }
}

impl<S> RateLimit<S> {
    /// Creates a new rate-limited service.
    ///
    /// # Arguments
    ///
    /// * `inner` - The inner service to wrap
    /// * `rate` - Maximum requests per period
    /// * `period` - The time period
    #[must_use]
    pub fn new(inner: S, rate: u64, period: Duration) -> Self {
        let state = Arc::new(Mutex::new(SharedRateLimitState {
            tokens: rate, // Start with full bucket
            last_refill: None,
            waiters: Slab::new(),
            next_waiter_id: 0,
        }));
        Self {
            inner,
            state: Arc::clone(&state),
            reservations: LocalReservationState::new(
                state,
                max_bucket_tokens(rate, period.is_zero()),
            ),
            rate,
            period,
            time_getter: wall_clock_now,
            sleep: None,
        }
    }

    /// Creates a new rate-limited service with a custom time source.
    #[must_use]
    pub fn with_time_getter(
        inner: S,
        rate: u64,
        period: Duration,
        time_getter: fn() -> Time,
    ) -> Self {
        let state = Arc::new(Mutex::new(SharedRateLimitState {
            tokens: rate,
            last_refill: None,
            waiters: Slab::new(),
            next_waiter_id: 0,
        }));
        Self {
            inner,
            state: Arc::clone(&state),
            reservations: LocalReservationState::new(
                state,
                max_bucket_tokens(rate, period.is_zero()),
            ),
            rate,
            period,
            time_getter,
            sleep: None,
        }
    }

    /// Returns the rate (tokens per period).
    #[must_use]
    pub const fn rate(&self) -> u64 {
        self.rate
    }

    /// Returns the period duration.
    #[must_use]
    pub const fn period(&self) -> Duration {
        self.period
    }

    /// Returns the time source used by this rate limiter.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }

    /// Returns the current number of available tokens.
    #[inline]
    #[must_use]
    pub fn available_tokens(&self) -> u64 {
        self.state.lock().tokens
    }

    #[cfg(test)]
    #[inline]
    #[must_use]
    fn reserved_tokens(&self) -> u64 {
        self.reservations.reserved_tokens
    }

    /// Returns a reference to the inner service.
    #[inline]
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Returns a mutable reference to the inner service.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consumes the rate limiter, returning the inner service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Refills tokens based on elapsed time.
    #[inline]
    fn refill_state_locked(
        state: &mut SharedRateLimitState,
        rate: u64,
        period: Duration,
        now: Time,
    ) {
        let last_refill = state.last_refill.unwrap_or(now);
        let elapsed_nanos = now.as_nanos().saturating_sub(last_refill.as_nanos());
        let period_nanos = {
            let nanos = period.as_nanos();
            if nanos <= u128::from(u64::MAX) {
                nanos as u64
            } else {
                u64::MAX
            }
        };

        if period_nanos == 0 {
            // Zero period means "no throttling": always make at least one token
            // available so poll_ready never stalls even when rate == 0.
            state.tokens = rate.max(1);
            state.last_refill = Some(now);
            return;
        }

        if period_nanos > 0 && elapsed_nanos > 0 {
            // Calculate how many periods have passed
            let periods = elapsed_nanos / period_nanos;
            if periods > 0 {
                // Add tokens for complete periods
                let new_tokens = periods.saturating_mul(rate);
                state.tokens = state.tokens.saturating_add(new_tokens).min(rate);
                // Update last_refill to the last complete period boundary
                let refill_time =
                    last_refill.saturating_add_nanos(periods.saturating_mul(period_nanos));
                state.last_refill = Some(refill_time);
            }
        } else if state.last_refill.is_none() {
            state.last_refill = Some(now);
        }
    }

    /// Refills tokens based on elapsed time.
    #[cfg(test)]
    fn refill(&self, now: Time) {
        let waiters = {
            let mut state = self.state.lock();
            let was_empty = state.tokens == 0;
            Self::refill_state_locked(&mut state, self.rate, self.period, now);
            if was_empty && state.tokens > 0 {
                std::mem::take(&mut state.waiters)
            } else {
                Slab::new()
            }
        };
        wake_waiters_after_unlock(waiters);
    }

    /// Polls readiness with an explicit time value.
    ///
    /// This mirrors [`Service::poll_ready`] while taking the current logical
    /// time as an explicit parameter for deterministic tests.
    pub fn poll_ready_with_time<Request>(
        &mut self,
        now: Time,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), RateLimitError<S::Error>>>
    where
        S: Service<Request>,
    {
        if self.reservations.reserved_tokens > 0 {
            self.reservations.retire_waiter();
            let mut reservation_restore_guard = ExistingReservationGuard::new(
                Arc::clone(&self.state),
                &mut self.reservations.reserved_tokens,
                self.rate,
                self.period.is_zero(),
                true,
            );

            return match self.inner.poll_ready(cx).map_err(RateLimitError::Inner) {
                Poll::Ready(Ok(())) => {
                    reservation_restore_guard.defuse();
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => {
                    reservation_restore_guard.defuse();
                    Poll::Pending
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            };
        }

        let period_nanos = {
            let nanos = self.period.as_nanos();
            if nanos <= u128::from(u64::MAX) {
                nanos as u64
            } else {
                u64::MAX
            }
        };
        // These values are declared before each lock guard so unwinding always
        // releases the bucket mutex before a hostile RawWaker can be destroyed.
        let mut incoming_waker: Option<Arc<RegisteredRateLimitWaker>> = None;
        let mut retired_registration: Option<Arc<RegisteredRateLimitWaker>> = None;
        let mut waiters_to_wake = Slab::new();
        let (acquired_token, next_deadline) = loop {
            let mut state = self.state.lock();
            Self::refill_state_locked(&mut state, self.rate, self.period, now);

            if state.tokens > 0 {
                retired_registration =
                    remove_waiter_locked(&mut state, &mut self.reservations.waiter);
                state.tokens -= 1;

                // A refill can make more than one token runnable. Wake the
                // remaining exhausted handles so capacity is not left idle.
                if state.tokens > 0 {
                    waiters_to_wake = std::mem::take(&mut state.waiters);
                }
                break (true, None);
            }

            let next_deadline = state
                .last_refill
                .map(|last_refill| last_refill.saturating_add_nanos(period_nanos));

            if let Some(handle) = self.reservations.waiter {
                if let Some(waiter) = waiter_by_handle(&state, handle) {
                    if waiter.registration.will_wake(cx.waker()) {
                        break (false, next_deadline);
                    }

                    if incoming_waker.is_some() {
                        let waiter = state
                            .waiters
                            .get_mut(handle.slot)
                            .expect("validated rate-limit waiter must remain registered");
                        let incoming = incoming_waker
                            .take()
                            .expect("prepared rate-limit Waker must be available");
                        retired_registration =
                            Some(std::mem::replace(&mut waiter.registration, incoming));
                        break (false, next_deadline);
                    }
                } else {
                    // A refund or refill may have detached this registration
                    // before its owner was polled again. The generation check
                    // prevents a stale handle from removing a reused slot.
                    self.reservations.waiter = None;
                }
            }

            if incoming_waker.is_none() {
                drop(state);
                incoming_waker = Some(RegisteredRateLimitWaker::new(cx.waker()));
                continue;
            }

            // Reserve before insertion and keep the prepared registration's
            // Arc outside the mutex. Even if Slab insertion unexpectedly
            // panics, its under-lock clone cannot be the final RawWaker owner.
            state.waiters.reserve(1);
            let id = state.next_waiter_id;
            state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
            let registration = incoming_waker
                .as_ref()
                .expect("prepared rate-limit Waker must be available");
            let slot = state.waiters.insert(RateLimitWaiter {
                id,
                registration: Arc::clone(registration),
            });
            self.reservations.waiter = Some(RateLimitWaiterHandle { slot, id });
            break (false, next_deadline);
        };

        // Once a token has been removed from the bucket, arm its refund before
        // retiring any executor-owned state. In particular, dropping an old
        // Sleep can run an arbitrary RawWaker destructor.
        let mut token_restore_guard = if acquired_token {
            Some(ReservedTokenGuard::new(
                Arc::clone(&self.state),
                self.rate,
                self.period.is_zero(),
                true,
            ))
        } else {
            None
        };

        retire_registration_after_unlock(incoming_waker);
        retire_registration_after_unlock(retired_registration);
        wake_waiters_after_unlock(waiters_to_wake);

        if !acquired_token {
            if let Some(next_deadline) = next_deadline {
                let need_new_sleep = self
                    .sleep
                    .as_ref()
                    .is_none_or(|sleep| sleep.deadline() != next_deadline);
                if need_new_sleep {
                    drop(self.sleep.take());
                    self.sleep = Some(crate::time::Sleep::new(next_deadline));
                }

                // `poll_deadline`, not the cancel-aware `poll`: in a cancelled
                // task `poll` is Ready at once, and every poll_ready then
                // dropped the Sleep, woke itself and built a new one, a busy
                // loop until the refill. The refill timer is a deadline.
                let timer_ready = self
                    .sleep
                    .as_mut()
                    .is_some_and(|sleep| std::pin::Pin::new(sleep).poll_deadline(cx).is_ready());
                if timer_ready {
                    // `take` clears the field before arbitrary Waker
                    // destruction, avoiding a second drop during unwinding.
                    drop(self.sleep.take());
                    cx.waker().wake_by_ref();
                }
            } else {
                // Defensive fallback for a malformed state whose exhausted
                // bucket lacks a refill anchor.
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }

        // Clear the field before running Sleep's Waker destructor. The armed
        // token guard restores capacity if that destructor panics.
        drop(self.sleep.take());
        let inner = &mut self.inner;
        let reserved_tokens = &mut self.reservations.reserved_tokens;
        let token_restore_guard = token_restore_guard
            .as_mut()
            .expect("acquired rate-limit token must arm its refund guard");

        match inner.poll_ready(cx).map_err(RateLimitError::Inner) {
            Poll::Ready(Ok(())) => {
                *reserved_tokens += 1;
                token_restore_guard.defuse();
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// Error returned by rate-limited services.
#[derive(Debug)]
pub enum RateLimitError<E> {
    /// The caller attempted `call()` without a preceding successful `poll_ready()`.
    NotReady,
    /// Rate limit exceeded (should not normally be seen - poll_ready handles this).
    RateLimitExceeded,
    /// The future was polled after it had already completed.
    PolledAfterCompletion,
    /// The inner service returned an error.
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for RateLimitError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReady => write!(f, "poll_ready required before call"),
            Self::RateLimitExceeded => write!(f, "rate limit exceeded"),
            Self::PolledAfterCompletion => write!(f, "future polled after completion"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for RateLimitError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotReady | Self::RateLimitExceeded | Self::PolledAfterCompletion => None,
            Self::Inner(e) => Some(e),
        }
    }
}

impl<S, Request> Service<Request> for RateLimit<S>
where
    S: Service<Request>,
{
    type Response = S::Response;
    type Error = RateLimitError<S::Error>;
    type Future = RateLimitFuture<S::Future, S::Error>;

    fn release_readiness(&mut self) -> super::ReadinessRelease {
        let reservations = std::mem::replace(
            &mut self.reservations,
            LocalReservationState::new(
                Arc::clone(&self.state),
                max_bucket_tokens(self.rate, self.period.is_zero()),
            ),
        );
        let sleep = self.sleep.take();
        let outer = super::ReadinessRelease::new(move || drop((reservations, sleep)));
        let inner = self.inner.release_readiness();
        super::ReadinessRelease::new(move || drop((inner, outer)))
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let now = (self.time_getter)();
        self.poll_ready_with_time::<Request>(now, cx)
    }

    #[inline]
    fn call(&mut self, req: Request) -> Self::Future {
        if self.reservations.reserved_tokens == 0 {
            return RateLimitFuture::immediate_error(RateLimitError::NotReady);
        }

        self.reservations.reserved_tokens -= 1;
        let mut token_restore_guard = ReservedTokenGuard::new(
            Arc::clone(&self.state),
            self.rate,
            self.period.is_zero(),
            true,
        );
        let future = self.inner.call(req);
        token_restore_guard.defuse();
        RateLimitFuture::new(future)
    }
}

#[derive(Debug)]
struct LocalReservationState {
    state: Arc<Mutex<SharedRateLimitState>>,
    reserved_tokens: u64,
    max_tokens: u64,
    waiter: Option<RateLimitWaiterHandle>,
}

impl LocalReservationState {
    fn new(state: Arc<Mutex<SharedRateLimitState>>, max_tokens: u64) -> Self {
        Self {
            state,
            reserved_tokens: 0,
            max_tokens,
            waiter: None,
        }
    }

    fn retire_waiter(&mut self) {
        if self.waiter.is_none() {
            return;
        }

        let retired = {
            let mut state = self.state.lock();
            remove_waiter_locked(&mut state, &mut self.waiter)
        };
        retire_registration_after_unlock(retired);
    }
}

impl Drop for LocalReservationState {
    fn drop(&mut self) {
        let (retired, waiters) = {
            let mut state = self.state.lock();
            let retired = remove_waiter_locked(&mut state, &mut self.waiter);
            let waiters = restore_tokens_locked(&mut state, self.reserved_tokens, self.max_tokens);
            (retired, waiters)
        };
        retire_registration_after_unlock(retired);
        wake_waiters_after_unlock(waiters);
    }
}

struct ReservedTokenGuard {
    state: Arc<Mutex<SharedRateLimitState>>,
    rate: u64,
    zero_period: bool,
    armed: bool,
}

impl ReservedTokenGuard {
    fn new(
        state: Arc<Mutex<SharedRateLimitState>>,
        rate: u64,
        zero_period: bool,
        armed: bool,
    ) -> Self {
        Self {
            state,
            rate,
            zero_period,
            armed,
        }
    }

    fn defuse(&mut self) {
        self.armed = false;
    }
}

impl Drop for ReservedTokenGuard {
    fn drop(&mut self) {
        if self.armed {
            restore_tokens_and_wake(
                &self.state,
                1,
                max_bucket_tokens(self.rate, self.zero_period),
            );
        }
    }
}

struct ExistingReservationGuard<'a> {
    state: Arc<Mutex<SharedRateLimitState>>,
    reserved_tokens: &'a mut u64,
    rate: u64,
    zero_period: bool,
    armed: bool,
}

impl<'a> ExistingReservationGuard<'a> {
    fn new(
        state: Arc<Mutex<SharedRateLimitState>>,
        reserved_tokens: &'a mut u64,
        rate: u64,
        zero_period: bool,
        armed: bool,
    ) -> Self {
        Self {
            state,
            reserved_tokens,
            rate,
            zero_period,
            armed,
        }
    }

    fn defuse(&mut self) {
        self.armed = false;
    }
}

impl Drop for ExistingReservationGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            *self.reserved_tokens = self.reserved_tokens.saturating_sub(1);
            restore_tokens_and_wake(
                &self.state,
                1,
                max_bucket_tokens(self.rate, self.zero_period),
            );
        }
    }
}

/// Future returned by [`RateLimit`] service.
#[pin_project(project = RateLimitFutureProj)]
pub struct RateLimitFuture<F, E> {
    #[pin]
    state: RateLimitFutureState<F, E>,
}

#[pin_project(project = RateLimitFutureStateProj)]
enum RateLimitFutureState<F, E> {
    Inner {
        #[pin]
        inner: F,
    },
    Error {
        error: Option<RateLimitError<E>>,
    },
    Done,
}

impl<F, E> RateLimitFuture<F, E> {
    /// Creates a new rate-limited future.
    #[must_use]
    pub fn new(inner: F) -> Self {
        Self {
            state: RateLimitFutureState::Inner { inner },
        }
    }

    /// Creates a future that resolves to an immediate rate-limit error.
    #[must_use]
    pub fn immediate_error(error: RateLimitError<E>) -> Self {
        Self {
            state: RateLimitFutureState::Error { error: Some(error) },
        }
    }
}

impl<F, T, E> Future for RateLimitFuture<F, E>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = Result<T, RateLimitError<E>>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        match this.state.as_mut().project() {
            RateLimitFutureStateProj::Inner { inner } => match inner.poll(cx) {
                Poll::Ready(Ok(response)) => {
                    this.state.set(RateLimitFutureState::Done);
                    Poll::Ready(Ok(response))
                }
                Poll::Ready(Err(error)) => {
                    this.state.set(RateLimitFutureState::Done);
                    Poll::Ready(Err(RateLimitError::Inner(error)))
                }
                Poll::Pending => Poll::Pending,
            },
            RateLimitFutureStateProj::Error { error } => {
                let error = error
                    .take()
                    .unwrap_or(RateLimitError::PolledAfterCompletion);
                this.state.set(RateLimitFutureState::Done);
                Poll::Ready(Err(error))
            }
            RateLimitFutureStateProj::Done => {
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            }
        }
    }
}

impl<F: std::fmt::Debug, E> std::fmt::Debug for RateLimitFuture<F, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.state {
            RateLimitFutureState::Inner { inner } => f
                .debug_struct("RateLimitFuture")
                .field("state", &"Inner")
                .field("inner", inner)
                .finish(),
            RateLimitFutureState::Error { .. } => f
                .debug_struct("RateLimitFuture")
                .field("state", &"ImmediateError")
                .finish(),
            RateLimitFutureState::Done => f
                .debug_struct("RateLimitFuture")
                .field("state", &"Done")
                .finish(),
        }
    }
}

#[cfg(test)]
#[path = "rate_limit_inline_tests.rs"]
mod tests;
