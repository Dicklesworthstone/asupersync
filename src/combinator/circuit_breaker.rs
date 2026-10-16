//! Circuit breaker combinator for failure detection and prevention.
//!
//! The circuit breaker pattern prevents cascading failures by detecting failing
//! operations and temporarily "opening" the circuit to avoid overwhelming failing
//! services.
//!
//! # State Machine
//!
//! The circuit breaker has three states:
//! - **Closed**: Normal operation, tracking failures
//! - **Open**: Failure detected, rejecting calls immediately
//! - **Half-Open**: Testing if service recovered with limited probes
//!
//! # Example
//!
//! ```
//! use asupersync::combinator::circuit_breaker::*;
//! use asupersync::types::Time;
//! use std::time::Duration;
//!
//! let policy = CircuitBreakerPolicy {
//!     failure_threshold: 5,
//!     success_threshold: 2,
//!     open_duration: Duration::from_secs(30),
//!     ..Default::default()
//! };
//!
//! let breaker = CircuitBreaker::new(policy);
//!
//! // Execute operation with circuit breaker
//! let now = Time::from_millis(0);
//! match breaker.call(now, || {
//!     // Your operation here
//!     Ok::<_, &str>(42)
//! }) {
//!     Ok(value) => println!("Got: {}", value),
//!     Err(CircuitBreakerError::Open { remaining }) => {
//!         println!("Circuit open, retry after {:?}", remaining);
//!     }
//!     Err(CircuitBreakerError::Inner(e)) => println!("Operation failed: {}", e),
//!     _ => {}
//! }
//! ```

use parking_lot::RwLock;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::types::Time;

// =========================================================================
// Policy Configuration
// =========================================================================

/// Maximum allowed value for `half_open_max_probes` (16 bits).
pub const MAX_HALF_OPEN_PROBES: u32 = 0xFFFF;
/// Minimum allowed value for `half_open_max_probes`.
pub const MIN_HALF_OPEN_PROBES: u32 = 1;

const fn normalize_half_open_max_probes(max_probes: u32) -> u32 {
    if max_probes == 0 {
        MIN_HALF_OPEN_PROBES
    } else if max_probes > MAX_HALF_OPEN_PROBES {
        MAX_HALF_OPEN_PROBES
    } else {
        max_probes
    }
}

/// Circuit breaker configuration.
#[derive(Clone)]
pub struct CircuitBreakerPolicy {
    /// Name for logging/metrics.
    pub name: String,

    /// Number of consecutive failures before opening (count-based).
    pub failure_threshold: u32,

    /// Number of successes in half-open to close circuit.
    pub success_threshold: u32,

    /// Duration to stay open before transitioning to half-open.
    pub open_duration: Duration,

    /// Maximum concurrent probes in half-open state.
    ///
    /// Clamped to [`MIN_HALF_OPEN_PROBES`]..=[`MAX_HALF_OPEN_PROBES`].
    pub half_open_max_probes: u32,

    /// Predicate to determine if error counts as failure.
    pub failure_predicate: FailurePredicate,

    /// Optional sliding window configuration.
    pub sliding_window: Option<SlidingWindowConfig>,

    /// Callback for state changes.
    pub on_state_change: Option<StateChangeCallback>,
}

impl fmt::Debug for CircuitBreakerPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CircuitBreakerPolicy")
            .field("name", &self.name)
            .field("failure_threshold", &self.failure_threshold)
            .field("success_threshold", &self.success_threshold)
            .field("open_duration", &self.open_duration)
            .field("half_open_max_probes", &self.half_open_max_probes)
            .field("failure_predicate", &self.failure_predicate)
            .field("sliding_window", &self.sliding_window)
            .field("on_state_change", &self.on_state_change.is_some())
            .finish()
    }
}

/// Predicate for determining failures.
#[derive(Clone)]
pub enum FailurePredicate {
    /// All errors are failures.
    AllErrors,

    /// Only specific error types (function pointer for determinism).
    ByType(fn(&str) -> bool),

    /// Custom predicate.
    Custom(Arc<dyn Fn(&str) -> bool + Send + Sync>),
}

impl fmt::Debug for FailurePredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllErrors => write!(f, "AllErrors"),
            Self::ByType(_) => write!(f, "ByType(...)"),
            Self::Custom(_) => write!(f, "Custom(...)"),
        }
    }
}

impl FailurePredicate {
    /// Check if an error message counts as a failure.
    fn is_failure(&self, error: &str) -> bool {
        match self {
            Self::AllErrors => true,
            Self::ByType(pred) => pred(error),
            Self::Custom(pred) => pred(error),
        }
    }

    /// Returns true if this predicate always treats all errors as failures,
    /// so callers can skip formatting the error string entirely.
    fn is_all_errors(&self) -> bool {
        matches!(self, Self::AllErrors)
    }
}

/// Sliding window configuration for rate-based failure detection.
#[derive(Clone, Debug)]
pub struct SlidingWindowConfig {
    /// Window size (time-based).
    pub window_duration: Duration,

    /// Minimum calls before evaluating failure rate.
    pub minimum_calls: u32,

    /// Failure rate threshold (0.0 - 1.0).
    pub failure_rate_threshold: f64,
}

/// Callback type for state changes.
pub type StateChangeCallback = Arc<dyn Fn(State, State, &CircuitBreakerMetrics) + Send + Sync>;

impl Default for CircuitBreakerPolicy {
    fn default() -> Self {
        Self {
            name: "default".into(),
            failure_threshold: 5,
            success_threshold: 2,
            open_duration: Duration::from_secs(30),
            half_open_max_probes: 1,
            failure_predicate: FailurePredicate::AllErrors,
            sliding_window: None,
            on_state_change: None,
        }
    }
}

// =========================================================================
// State Machine
// =========================================================================

/// Circuit breaker state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Normal operation, tracking failures.
    Closed {
        /// Number of consecutive failures.
        failures: u32,
    },

    /// Rejecting all calls, waiting for open_duration.
    Open {
        /// Timestamp when circuit opened (milliseconds since epoch).
        since_millis: u64,
    },

    /// Testing recovery with limited probes.
    HalfOpen {
        /// Epoch counter to prevent stale probe poisoning.
        epoch: u32,
        /// Number of probes currently active.
        probes_active: u32,
        /// Number of successful probes.
        successes: u32,
    },
}

impl Default for State {
    fn default() -> Self {
        Self::Closed { failures: 0 }
    }
}

impl State {
    /// Pack state into u64 for atomic operations.
    /// Format: [state_type:8][data:56]
    fn to_bits(self) -> u64 {
        match self {
            Self::Closed { failures } => u64::from(failures) << 8,
            Self::Open { since_millis } => 1 | (since_millis << 8),
            Self::HalfOpen {
                epoch,
                probes_active,
                successes,
            } => {
                2 | ((u64::from(epoch) & 0xFF_FFFF) << 8)
                    | ((u64::from(probes_active) & 0xFFFF) << 32)
                    | ((u64::from(successes) & 0xFFFF) << 48)
            }
        }
    }

    /// Unpack state from u64.
    fn from_bits(bits: u64) -> Self {
        let state_type = bits & 0xFF;
        match state_type {
            1 => Self::Open {
                since_millis: bits >> 8,
            },
            2 => Self::HalfOpen {
                epoch: ((bits >> 8) & 0xFF_FFFF) as u32,
                probes_active: ((bits >> 32) & 0xFFFF) as u32,
                successes: ((bits >> 48) & 0xFFFF) as u32,
            },
            _ => Self::Closed {
                failures: (bits >> 8) as u32,
            },
        }
    }
}

// =========================================================================
// Sliding Window Implementation
// =========================================================================

/// Time-based sliding window for failure rate calculation.
struct SlidingWindow {
    config: SlidingWindowConfig,
    /// Ring buffer of (timestamp_ms, is_failure) entries.
    entries: VecDeque<(u64, bool)>,
    success_count: u32,
    failure_count: u32,
}

impl SlidingWindow {
    fn new(config: SlidingWindowConfig) -> Self {
        Self {
            config,
            entries: VecDeque::with_capacity(1024),
            success_count: 0,
            failure_count: 0,
        }
    }

    /// Remove entries outside the window.
    fn cleanup(&mut self, now_millis: u64) {
        let window_span =
            u64::try_from(self.config.window_duration.as_millis()).unwrap_or(u64::MAX);
        let window_start = now_millis.saturating_sub(window_span);
        while let Some((ts, is_failure)) = self.entries.front() {
            if *ts < window_start {
                if *is_failure {
                    self.failure_count = self.failure_count.saturating_sub(1);
                } else {
                    self.success_count = self.success_count.saturating_sub(1);
                }
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }

    fn record_success(&mut self, now_millis: u64) {
        self.cleanup(now_millis);
        self.entries.push_back((now_millis, false));
        self.success_count = self.success_count.saturating_add(1);
    }

    fn record_failure(&mut self, now_millis: u64) {
        self.cleanup(now_millis);
        self.entries.push_back((now_millis, true));
        self.failure_count = self.failure_count.saturating_add(1);
    }

    fn failure_rate(&self) -> f64 {
        let total = self.success_count.saturating_add(self.failure_count);
        if total == 0 {
            return 0.0;
        }
        f64::from(self.failure_count) / f64::from(total)
    }

    fn should_open(&self) -> bool {
        let total = self.success_count.saturating_add(self.failure_count);
        if total < self.config.minimum_calls {
            return false;
        }
        self.failure_rate() >= self.config.failure_rate_threshold
    }

    fn reset(&mut self) {
        self.entries.clear();
        self.success_count = 0;
        self.failure_count = 0;
    }
}

// =========================================================================
// Metrics & Observability
// =========================================================================

/// Metrics exposed by circuit breaker.
#[derive(Clone, Debug, Default)]
pub struct CircuitBreakerMetrics {
    /// Total successful calls.
    pub total_success: u64,

    /// Total failed calls (counted as failures).
    pub total_failure: u64,

    /// Total calls rejected due to open state.
    pub total_rejected: u64,

    /// Total calls not counted as failures.
    pub total_ignored_errors: u64,

    /// Number of times circuit opened.
    pub times_opened: u64,

    /// Number of times circuit closed from half-open.
    pub times_closed: u64,

    /// Current failure streak.
    pub current_failure_streak: u32,

    /// Current state.
    pub current_state: State,

    /// Sliding window stats (if enabled).
    pub sliding_window_failure_rate: Option<f64>,
}

// =========================================================================
// Core Implementation
// =========================================================================

/// Thread-safe circuit breaker.
pub struct CircuitBreaker {
    policy: CircuitBreakerPolicy,

    // Atomic state representation
    state_bits: AtomicU64,

    // Monotonic source for HalfOpen epochs. Failed Open CAS attempts may
    // consume generations, but the counter is never reset so stale permits
    // cannot re-enter a later recovery episode before the packed 24-bit wrap.
    open_generation: AtomicU64,

    // Metrics (needs lock for complex updates like state changes)
    // Hot counters are shadowed in atomics below.
    metrics: RwLock<CircuitBreakerMetrics>,

    // Sliding window (if enabled)
    sliding_window: Option<RwLock<SlidingWindow>>,

    // Hot atomic counters to avoid RwLock on every call
    total_success: AtomicU64,
    total_failure: AtomicU64,
    total_rejected: AtomicU64,
    total_ignored_errors: AtomicU64,
    times_opened: AtomicU64,
    times_closed: AtomicU64,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given policy.
    #[must_use]
    pub fn new(mut policy: CircuitBreakerPolicy) -> Self {
        // Clamp probes to supported range so half-open accounting cannot violate
        // caller policy by allowing zero or overflowing values.
        policy.half_open_max_probes = normalize_half_open_max_probes(policy.half_open_max_probes);

        // Clamp success_threshold to [1, 0xFFFF]. The upper bound is because the value
        // is packed into 16 bits in State::HalfOpen (overflow would trap in HalfOpen).
        // The lower bound prevents 0 from behaving identically to 1 (would close on
        // the first probe regardless, confusing callers who expect "no probes needed").
        policy.success_threshold = policy.success_threshold.clamp(1, 0xFFFF);

        // Clamp failure_threshold to at least 1 so that 0 does not silently behave
        // like 1 (opening the circuit on the very first failure).
        policy.failure_threshold = policy.failure_threshold.max(1);

        let sliding_window = policy
            .sliding_window
            .as_ref()
            .map(|config| RwLock::new(SlidingWindow::new(config.clone())));

        Self {
            policy,
            state_bits: AtomicU64::new(State::default().to_bits()),
            open_generation: AtomicU64::new(0),
            metrics: RwLock::new(CircuitBreakerMetrics::default()),
            sliding_window,
            total_success: AtomicU64::new(0),
            total_failure: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
            total_ignored_errors: AtomicU64::new(0),
            times_opened: AtomicU64::new(0),
            times_closed: AtomicU64::new(0),
        }
    }

    /// Get current state.
    #[must_use]
    pub fn state(&self) -> State {
        State::from_bits(self.state_bits.load(Ordering::Acquire))
    }

    /// Get current metrics.
    ///
    /// This combines the atomic counters with the rare event counters
    /// guarded by the RwLock.
    #[must_use]
    pub fn metrics(&self) -> CircuitBreakerMetrics {
        CircuitBreakerMetrics {
            total_success: self.total_success.load(Ordering::Relaxed),
            total_failure: self.total_failure.load(Ordering::Relaxed),
            total_rejected: self.total_rejected.load(Ordering::Relaxed),
            total_ignored_errors: self.total_ignored_errors.load(Ordering::Relaxed),
            times_opened: self.times_opened.load(Ordering::Relaxed),
            times_closed: self.times_closed.load(Ordering::Relaxed),
            current_failure_streak: match self.state() {
                State::Closed { failures } => failures,
                _ => 0,
            },
            current_state: self.state(),
            sliding_window_failure_rate: self
                .sliding_window
                .as_ref()
                .map(|w| w.read().failure_rate()),
        }
    }

    /// Get the policy name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.policy.name
    }

    /// Check if call should be allowed.
    ///
    /// Returns `Ok(permit)` if the call should proceed, or `Err` if rejected.
    pub fn should_allow(&self, now: Time) -> Result<Permit, CircuitBreakerError<()>> {
        let now_millis = now.as_millis();

        let mut current_bits = self.state_bits.load(Ordering::Acquire);
        loop {
            let state = State::from_bits(current_bits);

            match state {
                State::Closed { .. } => {
                    return Ok(Permit::Normal);
                }

                State::Open { since_millis } => {
                    let elapsed = Duration::from_millis(now_millis.saturating_sub(since_millis));
                    if elapsed >= self.policy.open_duration {
                        // Transition to half-open
                        let epoch =
                            (self.open_generation.load(Ordering::Relaxed) & 0xFF_FFFF) as u32;
                        let new_state = State::HalfOpen {
                            epoch,
                            probes_active: 1,
                            successes: 0,
                        };
                        match self.state_bits.compare_exchange_weak(
                            current_bits,
                            new_state.to_bits(),
                            Ordering::Release,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => {
                                // State changed, update locked metrics and callback
                                let callback_metrics = self.update_state_metrics(state, new_state);
                                if let Some(ref cb) = self.policy.on_state_change {
                                    cb(state, new_state, &callback_metrics);
                                }
                                return Ok(Permit::Probe { epoch });
                            }
                            Err(actual) => {
                                current_bits = actual;
                                continue;
                            }
                        }
                    }
                    // Track rejection
                    self.total_rejected.fetch_add(1, Ordering::Relaxed);
                    let remaining = self
                        .policy
                        .open_duration
                        .checked_sub(elapsed)
                        .unwrap_or(Duration::ZERO);
                    return Err(CircuitBreakerError::Open { remaining });
                }

                State::HalfOpen {
                    epoch,
                    probes_active,
                    successes,
                } => {
                    if probes_active < self.policy.half_open_max_probes {
                        // Try to acquire probe slot
                        let new_state = State::HalfOpen {
                            epoch,
                            probes_active: probes_active + 1,
                            successes,
                        };
                        match self.state_bits.compare_exchange_weak(
                            current_bits,
                            new_state.to_bits(),
                            Ordering::Release,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => {
                                return Ok(Permit::Probe { epoch });
                            }
                            Err(actual) => {
                                current_bits = actual;
                                continue;
                            }
                        }
                    }
                    // Max probes active, reject
                    self.total_rejected.fetch_add(1, Ordering::Relaxed);
                    return Err(CircuitBreakerError::HalfOpenFull);
                }
            }
        }
    }

    /// Like [`should_allow`](Self::should_allow), but returns an RAII
    /// [`PermitGuard`] that releases the permit's half-open probe slot on drop
    /// if no outcome was recorded — so a cancelled or abandoned guarded
    /// operation cannot leak a half-open probe and stall recovery (5vzqse).
    /// Record the outcome via the guard's
    /// [`record_success`](PermitGuard::record_success) /
    /// [`record_failure`](PermitGuard::record_failure) /
    /// [`record_ignored`](PermitGuard::record_ignored); dropping it without
    /// recording is treated as ignored (neutral, frees the slot).
    pub fn acquire_guarded(&self, now: Time) -> Result<PermitGuard<'_>, CircuitBreakerError<()>> {
        let permit = self.should_allow(now)?;
        Ok(PermitGuard {
            breaker: self,
            permit: Some(permit),
        })
    }

    /// Record a successful call.
    #[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
    pub fn record_success(&self, permit: Permit, now: Time) {
        let now_millis = now.as_millis();
        self.total_success.fetch_add(1, Ordering::Relaxed);

        // Optimistic check for Happy Path (Closed + No Failures) to avoid CAS loop overhead
        if permit == Permit::Normal {
            let current_bits = self.state_bits.load(Ordering::Acquire);
            if State::from_bits(current_bits) == (State::Closed { failures: 0 }) {
                // Already clean, just check sliding window
                self.check_sliding_window_success(now_millis, permit, false);
                return;
            }
        }

        let mut closed_by_this_probe = false;
        let callback_event = match permit {
            Permit::Normal => {
                // Reset failure count in Closed state if needed
                let mut current_bits = self.state_bits.load(Ordering::Acquire);
                loop {
                    let state = State::from_bits(current_bits);
                    match state {
                        State::Closed { failures } if failures > 0 => {
                            let new_state = State::Closed { failures: 0 };
                            match self.state_bits.compare_exchange_weak(
                                current_bits,
                                new_state.to_bits(),
                                Ordering::Release,
                                Ordering::Acquire,
                            ) {
                                Ok(_) => {
                                    break;
                                }
                                Err(actual) => current_bits = actual,
                            }
                        }
                        _ => break,
                    }
                }
                None
            }
            Permit::Probe {
                epoch: permit_epoch,
            } => {
                let mut event = None;
                let mut current_bits = self.state_bits.load(Ordering::Acquire);
                loop {
                    let state = State::from_bits(current_bits);
                    match state {
                        State::HalfOpen {
                            epoch,
                            probes_active,
                            successes,
                        } if epoch == permit_epoch => {
                            let new_successes = successes.saturating_add(1);
                            if new_successes >= self.policy.success_threshold {
                                // Transition to Closed
                                let new_state = State::Closed { failures: 0 };
                                match self.state_bits.compare_exchange_weak(
                                    current_bits,
                                    new_state.to_bits(),
                                    Ordering::Release,
                                    Ordering::Acquire,
                                ) {
                                    Ok(_) => {
                                        closed_by_this_probe = true;
                                        self.times_closed.fetch_add(1, Ordering::Relaxed);
                                        let mut m = self.metrics.write();
                                        m.current_state = new_state;
                                        if self.policy.on_state_change.is_some() {
                                            self.populate_metrics_snapshot(&mut m);
                                            event = Some((state, new_state, m.clone()));
                                        }
                                        break;
                                    }
                                    Err(actual) => current_bits = actual,
                                }
                            } else {
                                // Increment successes, decrement probes
                                let new_state = State::HalfOpen {
                                    epoch,
                                    probes_active: probes_active.saturating_sub(1),
                                    successes: new_successes,
                                };
                                match self.state_bits.compare_exchange_weak(
                                    current_bits,
                                    new_state.to_bits(),
                                    Ordering::Release,
                                    Ordering::Acquire,
                                ) {
                                    Ok(_) => break,
                                    Err(actual) => current_bits = actual,
                                }
                            }
                        }
                        _ => break,
                    }
                }
                event
            }
        };

        if let Some((from, to, m)) = callback_event {
            if let Some(ref cb) = self.policy.on_state_change {
                cb(from, to, &m);
            }
        }

        self.check_sliding_window_success(now_millis, permit, closed_by_this_probe);
    }

    /// Helper to update metrics on state change.
    fn update_state_metrics(&self, _old: State, new: State) -> CircuitBreakerMetrics {
        let mut m = self.metrics.write();
        m.current_state = new;
        self.populate_metrics_snapshot(&mut m);
        m.clone()
    }

    /// Helper to populate a metrics struct with current atomic values.
    fn populate_metrics_snapshot(&self, m: &mut CircuitBreakerMetrics) {
        m.total_success = self.total_success.load(Ordering::Relaxed);
        m.total_failure = self.total_failure.load(Ordering::Relaxed);
        m.total_rejected = self.total_rejected.load(Ordering::Relaxed);
        m.total_ignored_errors = self.total_ignored_errors.load(Ordering::Relaxed);
        m.current_failure_streak = match self.state() {
            State::Closed { failures } => failures,
            _ => 0,
        };
        m.times_opened = self.times_opened.load(Ordering::Relaxed);
        m.times_closed = self.times_closed.load(Ordering::Relaxed);
    }

    /// Attempt one transition to `Open` and apply its side effects exactly once.
    ///
    /// The private generation reservation precedes the Release CAS. A caller
    /// that observes the published `Open` with Acquire may therefore load that
    /// generation (or a newer losing reservation) before minting a HalfOpen
    /// permit. Losing CAS attempts may skip private generations, but cannot
    /// change metrics, window contents, or callbacks.
    fn try_transition_to_open(&self, expected_bits: u64, now_millis: u64) -> Result<(), u64> {
        let from = State::from_bits(expected_bits);
        let new_state = State::Open {
            since_millis: now_millis,
        };

        // Hold the window guard across publication so an immediate zero-delay
        // HalfOpen recovery cannot record into the old window before reset.
        let mut window = self.sliding_window.as_ref().map(|window| window.write());
        self.open_generation.fetch_add(1, Ordering::Relaxed);

        self.state_bits.compare_exchange(
            expected_bits,
            new_state.to_bits(),
            Ordering::Release,
            Ordering::Acquire,
        )?;

        if let Some(window) = window.as_mut() {
            window.reset();
        }
        drop(window);

        self.times_opened.fetch_add(1, Ordering::Relaxed);
        let callback_metrics = {
            let mut metrics = self.metrics.write();
            metrics.current_state = new_state;
            if self.policy.on_state_change.is_some() {
                self.populate_metrics_snapshot(&mut metrics);
                Some(metrics.clone())
            } else {
                None
            }
        };

        if let (Some(callback), Some(metrics)) = (&self.policy.on_state_change, callback_metrics) {
            callback(from, new_state, &metrics);
        }

        Ok(())
    }

    /// Whether a finished call's outcome goes into the sliding window. An
    /// ordinary call's only while Closed. A probe's (the recovery sample)
    /// only while its own half-open episode is current, or when its success
    /// just closed the breaker (`closed_by_this_probe`: Closed carries no
    /// epoch to tell the closing probe from a stale one). Call it with the
    /// window lock held; opening clears the window under the same lock.
    /// Calls admitted before an open that finish after it, ordinary calls
    /// and probes of an episode that already re-opened alike, belong to the
    /// period the open already judged. Recording their failures refilled the
    /// cleared window, so the next half-open probe's successful close
    /// tripped the breaker again at once (br-asupersync-e9gn8y).
    fn window_records_outcomes(&self, permit: Permit, closed_by_this_probe: bool) -> bool {
        match permit {
            Permit::Normal => matches!(self.state(), State::Closed { .. }),
            Permit::Probe {
                epoch: permit_epoch,
            } => {
                closed_by_this_probe
                    || matches!(
                        self.state(),
                        State::HalfOpen { epoch, .. } if epoch == permit_epoch
                    )
            }
        }
    }

    fn check_sliding_window_success(
        &self,
        now_millis: u64,
        permit: Permit,
        closed_by_this_probe: bool,
    ) {
        let window_triggered = self.sliding_window.as_ref().is_some_and(|window| {
            let mut w = window.write();
            if !self.window_records_outcomes(permit, closed_by_this_probe) {
                return false;
            }
            w.record_success(now_millis);
            w.should_open()
        });

        if window_triggered {
            self.trigger_open_from_window(now_millis);
        }
    }

    fn trigger_open_from_window(&self, now_millis: u64) {
        let mut current_bits = self.state_bits.load(Ordering::Acquire);
        loop {
            let state = State::from_bits(current_bits);

            // Only transition if currently Closed
            if !matches!(state, State::Closed { .. }) {
                break;
            }

            match self.try_transition_to_open(current_bits, now_millis) {
                Ok(()) => break,
                Err(actual) => current_bits = actual,
            }
        }
    }

    /// Release a permit without counting the call as a success or a failure.
    ///
    /// Used when a higher layer's failure classifier decides a completed call
    /// is neither (for example an HTTP 4xx, or a cancelled call, that should not
    /// trip the breaker). The call is tallied in
    /// [`CircuitBreakerMetrics::total_ignored_errors`], and a half-open probe
    /// permit is released so the trial slot is freed — without recording a
    /// success toward closing the circuit. This is the neutral counterpart to
    /// [`Self::record_success`] / [`Self::record_failure`] and mirrors the
    /// behaviour `record_failure` already applies to predicate-ignored errors.
    pub fn record_ignored(&self, permit: Permit) {
        self.total_ignored_errors.fetch_add(1, Ordering::Relaxed);

        // Free the half-open probe slot if this was a probe call, leaving the
        // success count (which drives closing) untouched.
        if let Permit::Probe {
            epoch: permit_epoch,
        } = permit
        {
            let mut current_bits = self.state_bits.load(Ordering::Acquire);
            loop {
                let state = State::from_bits(current_bits);
                match state {
                    State::HalfOpen {
                        epoch,
                        probes_active,
                        successes,
                    } if epoch == permit_epoch => {
                        let new_state = State::HalfOpen {
                            epoch,
                            probes_active: probes_active.saturating_sub(1),
                            successes,
                        };
                        match self.state_bits.compare_exchange_weak(
                            current_bits,
                            new_state.to_bits(),
                            Ordering::Release,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => break,
                            Err(actual) => current_bits = actual,
                        }
                    }
                    _ => break,
                }
            }
        }
    }

    /// Record a failed call, classifying `error` through the configured failure
    /// predicate to decide whether it trips the breaker.
    pub fn record_failure(&self, permit: Permit, error: &str, now: Time) {
        // Check if this error counts as a failure.
        // For AllErrors predicates, skip the string inspection entirely.
        let counts_as_failure = self.policy.failure_predicate.is_all_errors()
            || self.policy.failure_predicate.is_failure(error);
        self.record_failure_classified(permit, counts_as_failure, now);
    }

    /// Record a failure whose classification has already been decided.
    ///
    /// A panic unwinding out of a guarded operation is an *unconditional* hard
    /// failure (`counts_as_failure = true`): the failure predicate classifies
    /// domain error *values*, not panics, so routing a `"Panic"` sentinel string
    /// through it would let a selective `ByType`/`Custom` predicate silently
    /// swallow a panicking dependency and never open the breaker.
    #[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
    fn record_failure_classified(&self, permit: Permit, counts_as_failure: bool, now: Time) {
        let now_millis = now.as_millis();

        if !counts_as_failure {
            self.total_ignored_errors.fetch_add(1, Ordering::Relaxed);

            // Still need to release probe if applicable
            if let Permit::Probe {
                epoch: permit_epoch,
            } = permit
            {
                let mut current_bits = self.state_bits.load(Ordering::Acquire);
                loop {
                    let state = State::from_bits(current_bits);
                    match state {
                        State::HalfOpen {
                            epoch,
                            probes_active,
                            successes,
                        } if epoch == permit_epoch => {
                            let new_state = State::HalfOpen {
                                epoch,
                                probes_active: probes_active.saturating_sub(1),
                                successes,
                            };
                            match self.state_bits.compare_exchange_weak(
                                current_bits,
                                new_state.to_bits(),
                                Ordering::Release,
                                Ordering::Acquire,
                            ) {
                                Ok(_) => break,
                                Err(actual) => current_bits = actual,
                            }
                        }
                        _ => break,
                    }
                }
            }
            return;
        }

        self.total_failure.fetch_add(1, Ordering::Relaxed);

        // Check sliding window if enabled
        let window_triggered = self.sliding_window.as_ref().is_some_and(|window| {
            let mut w = window.write();
            if !self.window_records_outcomes(permit, false) {
                return false;
            }
            w.record_failure(now_millis);
            w.should_open()
        });

        match permit {
            Permit::Normal => {
                let mut current_bits = self.state_bits.load(Ordering::Acquire);
                loop {
                    let state = State::from_bits(current_bits);
                    match state {
                        State::Closed { failures } => {
                            let new_failures = failures.saturating_add(1);

                            if new_failures >= self.policy.failure_threshold || window_triggered {
                                match self.try_transition_to_open(current_bits, now_millis) {
                                    Ok(()) => break,
                                    Err(actual) => current_bits = actual,
                                }
                            } else {
                                let new_state = State::Closed {
                                    failures: new_failures,
                                };
                                match self.state_bits.compare_exchange_weak(
                                    current_bits,
                                    new_state.to_bits(),
                                    Ordering::Release,
                                    Ordering::Acquire,
                                ) {
                                    Ok(_) => {
                                        break;
                                    }
                                    Err(actual) => current_bits = actual,
                                }
                            }
                        }
                        _ => break,
                    }
                }
            }
            Permit::Probe {
                epoch: permit_epoch,
            } => {
                let mut current_bits = self.state_bits.load(Ordering::Acquire);
                loop {
                    let state = State::from_bits(current_bits);
                    match state {
                        State::HalfOpen { epoch, .. } if epoch == permit_epoch => {
                            // Probe failed -> Reopen
                            match self.try_transition_to_open(current_bits, now_millis) {
                                Ok(()) => break,
                                Err(actual) => current_bits = actual,
                            }
                        }
                        _ => break,
                    }
                }
            }
        }
    }

    /// Execute an operation with circuit breaker protection.
    ///
    /// This is a convenience method that combines `should_allow`, operation
    /// execution, and result recording.
    pub fn call<T, E, F>(&self, now: Time, op: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Result<T, E>,
        E: fmt::Display,
    {
        struct CallGuard<'a> {
            cb: &'a CircuitBreaker,
            permit: Option<Permit>,
            now: Time,
        }

        impl Drop for CallGuard<'_> {
            fn drop(&mut self) {
                if let Some(permit) = self.permit.take() {
                    // A panic unwound out of the operation (or the call returned
                    // without recording an explicit outcome). A panic is an
                    // unconditional hard failure — it must trip the breaker
                    // regardless of the failure predicate, which only classifies
                    // domain error values, not panics.
                    self.cb.record_failure_classified(permit, true, self.now);
                }
            }
        }

        // Check if call is allowed
        let permit = self.should_allow(now).map_err(|e| match e {
            CircuitBreakerError::Open { remaining } => CircuitBreakerError::Open { remaining },
            CircuitBreakerError::HalfOpenFull => CircuitBreakerError::HalfOpenFull,
            CircuitBreakerError::Inner(()) => unreachable!(),
        })?;

        let mut guard = CallGuard {
            cb: self,
            permit: Some(permit),
            now,
        };

        // Execute the operation
        match op() {
            Ok(value) => {
                if let Some(p) = guard.permit.take() {
                    self.record_success(p, now);
                }
                Ok(value)
            }
            Err(e) => {
                let error_str = if self.policy.failure_predicate.is_all_errors() {
                    String::new()
                } else {
                    e.to_string()
                };

                if let Some(p) = guard.permit.take() {
                    self.record_failure(p, &error_str, now);
                }
                Err(CircuitBreakerError::Inner(e))
            }
        }
    }

    /// Manually reset the circuit breaker to closed state.
    ///
    /// Uses a CAS loop to avoid silently overwriting a concurrent state
    /// transition (e.g., a probe failure transitioning HalfOpen → Open).
    /// The reset succeeds from any non-Closed state; if the circuit is
    /// already Closed the counters are still zeroed.
    pub fn reset(&self) {
        let new_bits = State::Closed { failures: 0 }.to_bits();
        let mut current = self.state_bits.load(Ordering::Acquire);
        loop {
            match self.state_bits.compare_exchange_weak(
                current,
                new_bits,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }

        // Deliberately keep `open_generation` monotonic: a permit from before
        // manual reset must not match a later HalfOpen recovery episode.
        if let Some(ref window) = self.sliding_window {
            window.write().reset();
        }
    }
}

impl fmt::Debug for CircuitBreaker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CircuitBreaker")
            .field("name", &self.policy.name)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

// =========================================================================
// Error Types
// =========================================================================

/// Errors from circuit breaker.
#[derive(Debug, Clone)]
pub enum CircuitBreakerError<E> {
    /// Circuit is open, call rejected.
    Open {
        /// Time remaining until half-open transition.
        remaining: Duration,
    },

    /// Circuit is half-open with max probes active.
    HalfOpenFull,

    /// Underlying operation error.
    Inner(E),
}

impl<E: fmt::Display> fmt::Display for CircuitBreakerError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { remaining } => write!(f, "circuit open, retry after {remaining:?}"),
            Self::HalfOpenFull => write!(f, "circuit half-open, max probes active"),
            Self::Inner(e) => write!(f, "{e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for CircuitBreakerError<E> {}

// =========================================================================
// Permit Types
// =========================================================================

/// Permit indicating what type of call this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permit {
    /// Normal call in closed state.
    Normal,
    /// Probe call in half-open state.
    Probe {
        /// Private Open-generation counter preventing stale probe poisoning.
        epoch: u32,
    },
}

// =========================================================================
// Permit Guard (RAII)
// =========================================================================

/// RAII wrapper around a circuit-breaker [`Permit`].
///
/// `should_allow` hands back a bare [`Permit`] whose half-open probe slot leaks
/// unless the caller remembers to pass it to one of `record_*`. This guard makes
/// that automatic: record the call's outcome with
/// [`record_success`](Self::record_success),
/// [`record_failure`](Self::record_failure), or
/// [`record_ignored`](Self::record_ignored); if the guard is dropped without any
/// of those — e.g. the guarded future is cancelled — it records the call as
/// ignored (neutral: frees a half-open probe slot without counting toward
/// success/failure), preventing a leaked probe that would stall recovery
/// (5vzqse). Obtain one via [`CircuitBreaker::acquire_guarded`].
pub struct PermitGuard<'a> {
    breaker: &'a CircuitBreaker,
    permit: Option<Permit>,
}

impl std::fmt::Debug for PermitGuard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PermitGuard")
            .field("permit", &self.permit)
            .finish_non_exhaustive()
    }
}

impl PermitGuard<'_> {
    /// The permit held by this guard (`None` once an outcome has been recorded).
    #[must_use]
    pub fn permit(&self) -> Option<Permit> {
        self.permit
    }

    /// Record the guarded call as a success, consuming the guard.
    pub fn record_success(mut self, now: Time) {
        if let Some(permit) = self.permit.take() {
            self.breaker.record_success(permit, now);
        }
    }

    /// Record the guarded call as a failure, consuming the guard.
    pub fn record_failure(mut self, error: &str, now: Time) {
        if let Some(permit) = self.permit.take() {
            self.breaker.record_failure(permit, error, now);
        }
    }

    /// Record the guarded call as ignored (neutral), consuming the guard.
    pub fn record_ignored(mut self) {
        if let Some(permit) = self.permit.take() {
            self.breaker.record_ignored(permit);
        }
    }
}

impl Drop for PermitGuard<'_> {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            // The outcome was never recorded (e.g. the guarded operation was
            // cancelled). Release the (possibly half-open probe) slot neutrally
            // so it is not leaked (5vzqse).
            self.breaker.record_ignored(permit);
        }
    }
}

// =========================================================================
// Builder Pattern
// =========================================================================

/// Builder for `CircuitBreakerPolicy`.
#[derive(Default)]
pub struct CircuitBreakerPolicyBuilder {
    policy: CircuitBreakerPolicy,
}

impl CircuitBreakerPolicyBuilder {
    /// Create a new builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the circuit breaker name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.policy.name = name.into();
        self
    }

    /// Set the failure threshold.
    #[must_use]
    pub const fn failure_threshold(mut self, threshold: u32) -> Self {
        self.policy.failure_threshold = threshold;
        self
    }

    /// Set the success threshold for closing from half-open.
    #[must_use]
    pub const fn success_threshold(mut self, threshold: u32) -> Self {
        self.policy.success_threshold = threshold;
        self
    }

    /// Set the open duration.
    #[must_use]
    pub const fn open_duration(mut self, duration: Duration) -> Self {
        self.policy.open_duration = duration;
        self
    }

    /// Set the maximum concurrent probes in half-open state.
    ///
    /// This value is clamped to [`MIN_HALF_OPEN_PROBES`]..=[`MAX_HALF_OPEN_PROBES`].
    #[must_use]
    pub const fn half_open_max_probes(mut self, max_probes: u32) -> Self {
        self.policy.half_open_max_probes = normalize_half_open_max_probes(max_probes);
        self
    }

    /// Set a custom failure predicate.
    #[must_use]
    pub fn failure_predicate(mut self, predicate: FailurePredicate) -> Self {
        self.policy.failure_predicate = predicate;
        self
    }

    /// Enable sliding window failure rate detection.
    #[must_use]
    pub fn sliding_window(
        mut self,
        window_duration: Duration,
        minimum_calls: u32,
        failure_rate_threshold: f64,
    ) -> Self {
        self.policy.sliding_window = Some(SlidingWindowConfig {
            window_duration,
            minimum_calls,
            failure_rate_threshold,
        });
        self
    }

    /// Set a state change callback.
    #[must_use]
    pub fn on_state_change(mut self, callback: StateChangeCallback) -> Self {
        self.policy.on_state_change = Some(callback);
        self
    }

    /// Build the policy.
    #[must_use]
    pub fn build(self) -> CircuitBreakerPolicy {
        self.policy
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
#[path = "circuit_breaker_inline_tests.rs"]
mod tests;
