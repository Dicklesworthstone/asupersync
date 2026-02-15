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
//! ```ignore
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

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::types::Time;

// =========================================================================
// Policy Configuration
// =========================================================================

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
                probes_active,
                successes,
            } => 2 | ((u64::from(probes_active) & 0xFF_FFFF) << 8) | (u64::from(successes) << 32),
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
                probes_active: ((bits >> 8) & 0xFF_FFFF) as u32,
                successes: (bits >> 32) as u32,
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
        let window_start =
            now_millis.saturating_sub(self.config.window_duration.as_millis() as u64);
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
        self.success_count += 1;
    }

    fn record_failure(&mut self, now_millis: u64) {
        self.cleanup(now_millis);
        self.entries.push_back((now_millis, true));
        self.failure_count += 1;
    }

    fn failure_rate(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            return 0.0;
        }
        f64::from(self.failure_count) / f64::from(total)
    }

    fn should_open(&self) -> bool {
        let total = self.success_count + self.failure_count;
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

    // Metrics (needs lock for complex updates)
    metrics: RwLock<CircuitBreakerMetrics>,

    // Sliding window (if enabled)
    sliding_window: Option<RwLock<SlidingWindow>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given policy.
    #[must_use]
    pub fn new(policy: CircuitBreakerPolicy) -> Self {
        let sliding_window = policy
            .sliding_window
            .as_ref()
            .map(|config| RwLock::new(SlidingWindow::new(config.clone())));

        Self {
            policy,
            state_bits: AtomicU64::new(State::default().to_bits()),
            metrics: RwLock::new(CircuitBreakerMetrics::default()),
            sliding_window,
        }
    }

    /// Get current state.
    #[must_use]
    pub fn state(&self) -> State {
        State::from_bits(self.state_bits.load(Ordering::SeqCst))
    }

    /// Get current metrics.
    #[must_use]
    pub fn metrics(&self) -> CircuitBreakerMetrics {
        self.metrics.read().expect("lock poisoned").clone()
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

        loop {
            let current_bits = self.state_bits.load(Ordering::SeqCst);
            let state = State::from_bits(current_bits);

            match state {
                State::Closed { .. } => {
                    return Ok(Permit::Normal);
                }

                State::Open { since_millis } => {
                    let elapsed = Duration::from_millis(now_millis.saturating_sub(since_millis));
                    if elapsed >= self.policy.open_duration {
                        // Transition to half-open
                        let new_state = State::HalfOpen {
                            probes_active: 1,
                            successes: 0,
                        };
                        if self
                            .state_bits
                            .compare_exchange(
                                current_bits,
                                new_state.to_bits(),
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            )
                            .is_ok()
                        {
                            let callback_metrics = {
                                let mut metrics = self.metrics.write().expect("lock poisoned");
                                metrics.current_state = new_state;
                                if self.policy.on_state_change.is_some() {
                                    Some(metrics.clone())
                                } else {
                                    None
                                }
                            };

                            if let Some(metrics) = callback_metrics {
                                if let Some(ref cb) = self.policy.on_state_change {
                                    cb(state, new_state, &metrics);
                                }
                            }
                            return Ok(Permit::Probe);
                        }
                        // CAS failed, retry
                        continue;
                    }
                    // Track rejection
                    self.metrics.write().expect("lock poisoned").total_rejected += 1;
                    let remaining = self
                        .policy
                        .open_duration
                        .checked_sub(elapsed)
                        .unwrap_or(Duration::ZERO);
                    return Err(CircuitBreakerError::Open { remaining });
                }

                State::HalfOpen {
                    probes_active,
                    successes,
                } => {
                    if probes_active < self.policy.half_open_max_probes {
                        // Try to acquire probe slot
                        let new_state = State::HalfOpen {
                            probes_active: probes_active + 1,
                            successes,
                        };
                        if self
                            .state_bits
                            .compare_exchange(
                                current_bits,
                                new_state.to_bits(),
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            )
                            .is_ok()
                        {
                            return Ok(Permit::Probe);
                        }
                        // CAS failed, retry
                        continue;
                    }
                    // Max probes active, reject
                    self.metrics.write().expect("lock poisoned").total_rejected += 1;
                    return Err(CircuitBreakerError::HalfOpenFull);
                }
            }
        }
    }

    /// Record a successful call.
    #[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
    pub fn record_success(&self, permit: Permit, now: Time) {
        let now_millis = now.as_millis();

        let callback_event = {
            let mut metrics = self.metrics.write().expect("lock poisoned");
            metrics.total_success += 1;
            let mut event = None;

            match permit {
                Permit::Normal => {
                    // Reset failure count in Closed state if needed
                    loop {
                        let current_bits = self.state_bits.load(Ordering::SeqCst);
                        let state = State::from_bits(current_bits);
                        match state {
                            State::Closed { failures } if failures > 0 => {
                                let new_state = State::Closed { failures: 0 };
                                if self
                                    .state_bits
                                    .compare_exchange(
                                        current_bits,
                                        new_state.to_bits(),
                                        Ordering::SeqCst,
                                        Ordering::SeqCst,
                                    )
                                    .is_ok()
                                {
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                    metrics.current_failure_streak = 0;
                }
                Permit::Probe => {
                    loop {
                        let current_bits = self.state_bits.load(Ordering::SeqCst);
                        let state = State::from_bits(current_bits);
                        match state {
                            State::HalfOpen {
                                probes_active,
                                successes,
                            } => {
                                let new_successes = successes + 1;
                                if new_successes >= self.policy.success_threshold {
                                    // Transition to Closed
                                    let new_state = State::Closed { failures: 0 };
                                    if self
                                        .state_bits
                                        .compare_exchange(
                                            current_bits,
                                            new_state.to_bits(),
                                            Ordering::SeqCst,
                                            Ordering::SeqCst,
                                        )
                                        .is_ok()
                                    {
                                        metrics.times_closed += 1;
                                        metrics.current_state = new_state;
                                        metrics.current_failure_streak = 0;
                                        if self.policy.on_state_change.is_some() {
                                            event = Some((state, new_state, metrics.clone()));
                                        }
                                        break;
                                    }
                                } else {
                                    // Increment successes, decrement probes
                                    let new_state = State::HalfOpen {
                                        probes_active: probes_active.saturating_sub(1),
                                        successes: new_successes,
                                    };
                                    if self
                                        .state_bits
                                        .compare_exchange(
                                            current_bits,
                                            new_state.to_bits(),
                                            Ordering::SeqCst,
                                            Ordering::SeqCst,
                                        )
                                        .is_ok()
                                    {
                                        break;
                                    }
                                }
                            }
                            _ => break,
                        }
                    }
                }
            }
            event
        };

        if let Some((from, to, m)) = callback_event {
            if let Some(ref cb) = self.policy.on_state_change {
                cb(from, to, &m);
            }
        }

        // Check sliding window after recording success - may trigger open
        // if failure rate threshold is exceeded once minimum_calls is reached
        let window_triggered = self.sliding_window.as_ref().is_some_and(|window| {
            let mut w = window.write().expect("lock poisoned");
            w.record_success(now_millis);
            w.should_open()
        });

        if window_triggered {
            let callback_event = {
                let mut metrics = self.metrics.write().expect("lock poisoned");
                // Transition to Open due to window (use CAS to avoid clobbering concurrent transitions)
                let mut event = None;
                loop {
                    let current_bits = self.state_bits.load(Ordering::SeqCst);
                    let state = State::from_bits(current_bits);

                    // Only transition if not already Open
                    if matches!(state, State::Open { .. }) {
                        break;
                    }

                    let new_state = State::Open {
                        since_millis: now_millis,
                    };
                    if self
                        .state_bits
                        .compare_exchange(
                            current_bits,
                            new_state.to_bits(),
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok()
                    {
                        metrics.times_opened += 1;
                        metrics.current_state = new_state;

                        if let Some(ref w) = self.sliding_window {
                            w.write().expect("lock poisoned").reset();
                        }

                        if self.policy.on_state_change.is_some() {
                            event = Some((state, new_state, metrics.clone()));
                        }
                        break;
                    }
                }
                event
            };

            if let Some((from, to, m)) = callback_event {
                if let Some(ref cb) = self.policy.on_state_change {
                    cb(from, to, &m);
                }
            }
        }
    }

    /// Record a failed call.
    #[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
    pub fn record_failure(&self, permit: Permit, error: &str, now: Time) {
        let now_millis = now.as_millis();

        // Check if this error counts as a failure
        let counts_as_failure = self.policy.failure_predicate.is_failure(error);

        if !counts_as_failure {
            self.metrics
                .write()
                .expect("lock poisoned")
                .total_ignored_errors += 1;

            // Still need to release probe if applicable
            if matches!(permit, Permit::Probe) {
                loop {
                    let current_bits = self.state_bits.load(Ordering::SeqCst);
                    let state = State::from_bits(current_bits);
                    match state {
                        State::HalfOpen {
                            probes_active,
                            successes,
                        } => {
                            let new_state = State::HalfOpen {
                                probes_active: probes_active.saturating_sub(1),
                                successes,
                            };
                            if self
                                .state_bits
                                .compare_exchange(
                                    current_bits,
                                    new_state.to_bits(),
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                )
                                .is_ok()
                            {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            }
            return;
        }

        // Check sliding window if enabled (before acquiring metrics lock)
        let (window_triggered, failure_rate) =
            self.sliding_window
                .as_ref()
                .map_or((false, None), |window| {
                    let mut w = window.write().expect("lock poisoned");
                    w.record_failure(now_millis);
                    (w.should_open(), Some(w.failure_rate()))
                });

        let callback_event = {
            let mut metrics = self.metrics.write().expect("lock poisoned");
            metrics.total_failure += 1;
            if let Some(rate) = failure_rate {
                metrics.sliding_window_failure_rate = Some(rate);
            }
            let mut event = None;

            match permit {
                Permit::Normal => loop {
                    let current_bits = self.state_bits.load(Ordering::SeqCst);
                    let state = State::from_bits(current_bits);
                    match state {
                        State::Closed { failures } => {
                            let new_failures = failures + 1;
                            metrics.current_failure_streak = new_failures;

                            if new_failures >= self.policy.failure_threshold || window_triggered {
                                let new_state = State::Open {
                                    since_millis: now_millis,
                                };
                                if self
                                    .state_bits
                                    .compare_exchange(
                                        current_bits,
                                        new_state.to_bits(),
                                        Ordering::SeqCst,
                                        Ordering::SeqCst,
                                    )
                                    .is_ok()
                                {
                                    metrics.times_opened += 1;
                                    metrics.current_state = new_state;
                                    if self.policy.on_state_change.is_some() {
                                        event = Some((state, new_state, metrics.clone()));
                                    }
                                    if let Some(ref w) = self.sliding_window {
                                        w.write().expect("lock poisoned").reset();
                                    }
                                    break;
                                }
                            } else {
                                let new_state = State::Closed {
                                    failures: new_failures,
                                };
                                if self
                                    .state_bits
                                    .compare_exchange(
                                        current_bits,
                                        new_state.to_bits(),
                                        Ordering::SeqCst,
                                        Ordering::SeqCst,
                                    )
                                    .is_ok()
                                {
                                    break;
                                }
                            }
                        }
                        _ => break,
                    }
                },
                Permit::Probe => {
                    loop {
                        let current_bits = self.state_bits.load(Ordering::SeqCst);
                        let state = State::from_bits(current_bits);
                        match state {
                            State::HalfOpen {
                                probes_active: _,
                                successes: _,
                            } => {
                                // Probe failed -> Reopen
                                let new_state = State::Open {
                                    since_millis: now_millis,
                                };
                                if self
                                    .state_bits
                                    .compare_exchange(
                                        current_bits,
                                        new_state.to_bits(),
                                        Ordering::SeqCst,
                                        Ordering::SeqCst,
                                    )
                                    .is_ok()
                                {
                                    metrics.times_opened += 1;
                                    metrics.current_state = new_state;
                                    if self.policy.on_state_change.is_some() {
                                        event = Some((state, new_state, metrics.clone()));
                                    }
                                    if let Some(ref w) = self.sliding_window {
                                        w.write().expect("lock poisoned").reset();
                                    }
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                }
            }
            event
        };

        if let Some((from, to, m)) = callback_event {
            if let Some(ref cb) = self.policy.on_state_change {
                cb(from, to, &m);
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
        // Check if call is allowed
        let permit = self.should_allow(now).map_err(|e| match e {
            CircuitBreakerError::Open { remaining } => CircuitBreakerError::Open { remaining },
            CircuitBreakerError::HalfOpenFull => CircuitBreakerError::HalfOpenFull,
            CircuitBreakerError::Inner(()) => unreachable!(),
        })?;

        // Execute the operation
        match op() {
            Ok(value) => {
                self.record_success(permit, now);
                Ok(value)
            }
            Err(e) => {
                let error_str = e.to_string();
                self.record_failure(permit, &error_str, now);
                Err(CircuitBreakerError::Inner(e))
            }
        }
    }

    /// Manually reset the circuit breaker to closed state.
    pub fn reset(&self) {
        {
            let mut metrics = self.metrics.write().expect("lock poisoned");
            let new_state = State::Closed { failures: 0 };
            self.state_bits.store(new_state.to_bits(), Ordering::SeqCst);
            metrics.current_state = new_state;
            metrics.current_failure_streak = 0;
        }

        if let Some(ref window) = self.sliding_window {
            window.write().expect("lock poisoned").reset();
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
    Probe,
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
    #[must_use]
    pub const fn half_open_max_probes(mut self, max_probes: u32) -> Self {
        self.policy.half_open_max_probes = max_probes;
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
mod tests {
    use super::*;

    // =========================================================================
    // State Bit Packing Tests
    // =========================================================================

    #[test]
    fn state_bits_roundtrip_closed() {
        let state = State::Closed { failures: 42 };
        let bits = state.to_bits();
        let recovered = State::from_bits(bits);
        assert_eq!(state, recovered);
    }

    #[test]
    fn state_bits_roundtrip_open() {
        let state = State::Open {
            since_millis: 123_456_789,
        };
        let bits = state.to_bits();
        let recovered = State::from_bits(bits);
        assert_eq!(state, recovered);
    }

    #[test]
    fn state_bits_roundtrip_half_open() {
        let state = State::HalfOpen {
            probes_active: 3,
            successes: 7,
        };
        let bits = state.to_bits();
        let recovered = State::from_bits(bits);
        assert_eq!(state, recovered);
    }

    // =========================================================================
    // Basic State Machine Tests
    // =========================================================================

    #[test]
    fn new_circuit_starts_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy::default());
        assert_eq!(cb.state(), State::Closed { failures: 0 });
    }

    #[test]
    fn closed_allows_calls() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy::default());
        let now = Time::from_millis(0);

        assert!(cb.should_allow(now).is_ok());
    }

    #[test]
    fn failures_increment_count() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 5,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        for i in 0..4 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_failure(permit, "test error", now);

            assert_eq!(cb.state(), State::Closed { failures: i + 1 });
            assert_eq!(cb.metrics().current_failure_streak, i + 1);
        }
    }

    #[test]
    fn threshold_failures_opens_circuit() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 3,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        for _ in 0..3 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_failure(permit, "test error", now);
        }

        assert!(matches!(cb.state(), State::Open { .. }));
    }

    #[test]
    fn open_circuit_rejects_calls() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_secs(30),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        // Should be rejected
        let result = cb.should_allow(now);
        assert!(matches!(
            result,
            Err(CircuitBreakerError::Open { remaining }) if remaining == Duration::from_secs(30)
        ));

        // Verify rejection was tracked
        assert_eq!(cb.metrics().total_rejected, 1);
    }

    #[test]
    fn open_transitions_to_half_open_after_duration() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_secs(10),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        // After open_duration, should allow probe
        let later = Time::from_millis(11_000);
        let result = cb.should_allow(later);
        assert!(result.is_ok());
        assert!(matches!(cb.state(), State::HalfOpen { .. }));
    }

    #[test]
    fn open_to_half_open_updates_metrics_state() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_secs(10),
            ..Default::default()
        });

        let now = Time::from_millis(0);
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        let later = Time::from_millis(11_000);
        let result = cb.should_allow(later);
        assert!(matches!(result, Ok(Permit::Probe)));
        assert!(matches!(
            cb.metrics().current_state,
            State::HalfOpen {
                probes_active: 1,
                successes: 0
            }
        ));
    }

    #[test]
    fn half_open_limits_concurrent_probes() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_millis(0),
            half_open_max_probes: 1,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        // First probe allowed
        let probe1 = cb.should_allow(now);
        assert!(probe1.is_ok());

        // Second probe rejected (max 1)
        let probe2 = cb.should_allow(now);
        assert!(matches!(probe2, Err(CircuitBreakerError::HalfOpenFull)));
    }

    #[test]
    fn successful_probes_close_circuit() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            success_threshold: 2,
            open_duration: Duration::from_millis(0),
            half_open_max_probes: 5,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        // Two successful probes
        for _ in 0..2 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_success(permit, now);
        }

        assert_eq!(cb.state(), State::Closed { failures: 0 });
    }

    #[test]
    fn failed_probe_reopens_circuit() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_millis(0),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open -> half-open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        // Get probe permit
        let permit = cb.should_allow(now).unwrap();

        // Probe fails
        cb.record_failure(permit, "probe fail", now);

        // Should be open again
        assert!(matches!(cb.state(), State::Open { .. }));
    }

    // =========================================================================
    // Success Resets Failure Count
    // =========================================================================

    #[test]
    fn success_resets_failure_count() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 5,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // 3 failures
        for _ in 0..3 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_failure(permit, "fail", now);
        }
        assert_eq!(cb.metrics().current_failure_streak, 3);

        // 1 success resets
        let permit = cb.should_allow(now).unwrap();
        cb.record_success(permit, now);

        assert_eq!(cb.metrics().current_failure_streak, 0);
        assert_eq!(cb.state(), State::Closed { failures: 0 });
    }

    // =========================================================================
    // Failure Predicate Tests
    // =========================================================================

    #[test]
    fn failure_predicate_filters_errors() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            failure_predicate: FailurePredicate::ByType(|e| e.contains("timeout")),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Non-matching error doesn't count
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "network error", now);
        assert_eq!(cb.state(), State::Closed { failures: 0 });
        assert_eq!(cb.metrics().total_ignored_errors, 1);

        // Matching error opens circuit
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "timeout error", now);
        assert!(matches!(cb.state(), State::Open { .. }));
    }

    // =========================================================================
    // Sliding Window Tests
    // =========================================================================

    #[test]
    fn sliding_window_tracks_failure_rate() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1000, // High count threshold
            sliding_window: Some(SlidingWindowConfig {
                window_duration: Duration::from_mins(1),
                minimum_calls: 10,
                failure_rate_threshold: 0.5,
            }),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // 10 calls: 6 failures (60% failure rate)
        for i in 0..10 {
            let permit = cb.should_allow(now).unwrap();
            if i < 6 {
                cb.record_failure(permit, "fail", now);
            } else {
                cb.record_success(permit, now);
            }
        }

        // Should be open due to 60% > 50% threshold
        assert!(matches!(cb.state(), State::Open { .. }));
    }

    #[test]
    fn sliding_window_minimum_calls_required() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1000,
            sliding_window: Some(SlidingWindowConfig {
                window_duration: Duration::from_mins(1),
                minimum_calls: 10,
                failure_rate_threshold: 0.5,
            }),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Only 5 failures (below minimum_calls)
        for _ in 0..5 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_failure(permit, "fail", now);
        }

        // Should still be closed (minimum not met)
        // Failure count is 5
        assert_eq!(cb.state(), State::Closed { failures: 5 });
    }

    // =========================================================================
    // Metrics Tests
    // =========================================================================

    #[test]
    fn metrics_track_calls() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 100,
            ..Default::default()
        });
        let now = Time::from_millis(0);

        // 3 successes, 2 failures
        for _ in 0..3 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_success(permit, now);
        }
        for _ in 0..2 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_failure(permit, "fail", now);
        }

        let metrics = cb.metrics();
        assert_eq!(metrics.total_success, 3);
        assert_eq!(metrics.total_failure, 2);
    }

    #[test]
    fn metrics_track_rejections() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_mins(1),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        // Try to call (will be rejected)
        for _ in 0..5 {
            let _ = cb.should_allow(now);
        }

        assert_eq!(cb.metrics().total_rejected, 5);
    }

    // =========================================================================
    // State Change Callback Tests
    // =========================================================================

    #[test]
    fn state_change_callback_invoked() {
        use std::sync::atomic::AtomicUsize;

        let callback_count = Arc::new(AtomicUsize::new(0));
        let callback_count_clone = callback_count.clone();

        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            on_state_change: Some(Arc::new(move |_from, _to, _| {
                callback_count_clone.fetch_add(1, Ordering::SeqCst);
            })),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        assert_eq!(callback_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn state_change_callback_invoked_for_open_to_half_open() {
        use std::sync::atomic::AtomicUsize;

        let callback_count = Arc::new(AtomicUsize::new(0));
        let callback_count_clone = callback_count.clone();

        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_secs(10),
            on_state_change: Some(Arc::new(move |_from, _to, _| {
                callback_count_clone.fetch_add(1, Ordering::SeqCst);
            })),
            ..Default::default()
        });

        let now = Time::from_millis(0);
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        let later = Time::from_millis(11_000);
        let permit = cb.should_allow(later);
        assert!(matches!(permit, Ok(Permit::Probe)));

        // 1 transition for Closed->Open and 1 transition for Open->HalfOpen.
        assert_eq!(callback_count.load(Ordering::SeqCst), 2);
    }

    // =========================================================================
    // Concurrent Access Tests
    // =========================================================================

    #[test]
    fn concurrent_calls_safe() {
        use std::thread;

        let cb = Arc::new(CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 100,
            ..Default::default()
        }));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let cb = cb.clone();
                thread::spawn(move || {
                    let now = Time::from_millis(0);
                    for _ in 0..100 {
                        if let Ok(permit) = cb.should_allow(now) {
                            cb.record_success(permit, now);
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // No panics = success
        assert_eq!(cb.metrics().total_success, 1000);
    }

    // =========================================================================
    // Call Helper Tests
    // =========================================================================

    #[test]
    fn call_executes_and_records_success() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy::default());
        let now = Time::from_millis(0);

        let result = cb.call(now, || Ok::<_, &str>(42));

        assert_eq!(result.unwrap(), 42);
        assert_eq!(cb.metrics().total_success, 1);
    }

    #[test]
    fn call_executes_and_records_failure() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 5,
            ..Default::default()
        });
        let now = Time::from_millis(0);

        let result: Result<i32, CircuitBreakerError<&str>> = cb.call(now, || Err("error"));

        assert!(matches!(result, Err(CircuitBreakerError::Inner("error"))));
        assert_eq!(cb.metrics().total_failure, 1);
    }

    #[test]
    fn call_rejects_when_open() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_mins(1),
            ..Default::default()
        });
        let now = Time::from_millis(0);

        // Open the circuit
        let _ = cb.call(now, || Err::<i32, _>("fail"));

        // Next call should be rejected
        let mut called = false;
        let result: Result<i32, CircuitBreakerError<&str>> = cb.call(now, || {
            called = true;
            Ok(42)
        });

        assert!(!called, "Operation should not have been called");
        assert!(matches!(result, Err(CircuitBreakerError::Open { .. })));
    }

    // =========================================================================
    // Builder Tests
    // =========================================================================

    #[test]
    fn builder_creates_policy() {
        let policy = CircuitBreakerPolicyBuilder::new()
            .name("test")
            .failure_threshold(10)
            .success_threshold(3)
            .open_duration(Duration::from_mins(1))
            .half_open_max_probes(2)
            .build();

        assert_eq!(policy.name, "test");
        assert_eq!(policy.failure_threshold, 10);
        assert_eq!(policy.success_threshold, 3);
        assert_eq!(policy.open_duration, Duration::from_mins(1));
        assert_eq!(policy.half_open_max_probes, 2);
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn reset_clears_state() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            ..Default::default()
        });
        let now = Time::from_millis(0);

        // Open the circuit
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);
        assert!(matches!(cb.state(), State::Open { .. }));

        // Reset
        cb.reset();

        assert_eq!(cb.state(), State::Closed { failures: 0 });
        assert_eq!(cb.metrics().current_failure_streak, 0);
    }

    // =========================================================================
    // Display Tests
    // =========================================================================

    #[test]
    fn error_display() {
        let open: CircuitBreakerError<&str> = CircuitBreakerError::Open {
            remaining: Duration::from_secs(30),
        };
        assert!(open.to_string().contains("circuit open"));

        let half_open: CircuitBreakerError<&str> = CircuitBreakerError::HalfOpenFull;
        assert!(half_open.to_string().contains("half-open"));

        let inner: CircuitBreakerError<&str> = CircuitBreakerError::Inner("test error");
        assert_eq!(inner.to_string(), "test error");
    }

    // =========================================================================
    // Regression Tests for Bug Fixes
    // =========================================================================

    #[test]
    fn halfopen_bit_packing_large_probes_active() {
        // Regression: probes_active > 16M (24-bit max) would corrupt successes
        // field due to bit overlap in to_bits(). Now probes_active is masked to
        // 24 bits in encoding, matching the decode mask.
        let state = State::HalfOpen {
            probes_active: 0x00FF_FFFF, // max 24-bit value
            successes: 42,
        };
        let roundtripped = State::from_bits(state.to_bits());
        assert_eq!(
            roundtripped,
            State::HalfOpen {
                probes_active: 0x00FF_FFFF,
                successes: 42,
            }
        );

        // Value exceeding 24 bits gets truncated (saturated by mask)
        let overflow = State::HalfOpen {
            probes_active: 0x01FF_FFFF, // 25 bits - bit 24 set
            successes: 7,
        };
        let rt = State::from_bits(overflow.to_bits());
        // The high bit is lost, but successes must remain uncorrupted
        assert_eq!(
            rt,
            State::HalfOpen {
                probes_active: 0x00FF_FFFF,
                successes: 7,
            }
        );
    }

    #[test]
    fn halfopen_bit_packing_successes_isolated() {
        // Verify successes field is completely independent of probes_active
        for probes in [0u32, 1, 255, 0x00FF_FFFF] {
            for succ in [0u32, 1, 100, u32::MAX] {
                let state = State::HalfOpen {
                    probes_active: probes,
                    successes: succ,
                };
                let rt = State::from_bits(state.to_bits());
                match rt {
                    State::HalfOpen {
                        probes_active: p,
                        successes: s,
                    } => {
                        assert_eq!(p, probes, "probes_active mismatch for ({probes}, {succ})");
                        assert_eq!(s, succ, "successes mismatch for ({probes}, {succ})");
                    }
                    _ => panic!("Expected HalfOpen"),
                }
            }
        }
    }
}
