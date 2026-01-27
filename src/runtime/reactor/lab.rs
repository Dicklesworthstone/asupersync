//! Deterministic lab reactor for testing.
//!
//! The [`LabReactor`] provides a virtual reactor implementation for deterministic
//! testing of async I/O code. Instead of interacting with the OS, it uses virtual
//! time and injected events.
//!
//! # Features
//!
//! - **Virtual time**: Time advances only through poll() timeouts
//! - **Event injection**: Test code can inject events at specific times
//! - **Deterministic**: Same events + same poll sequence = same results
//!
//! # Example
//!
//! ```ignore
//! use asupersync::runtime::reactor::{LabReactor, Interest, Event, Token};
//! use std::time::Duration;
//!
//! let reactor = LabReactor::new();
//! let token = Token::new(1);
//!
//! // Register a virtual source
//! reactor.register(&source, token, Interest::READABLE)?;
//!
//! // Inject an event 10ms in the future
//! reactor.inject_event(token, Event::readable(token), Duration::from_millis(10));
//!
//! // Poll with timeout - advances virtual time
//! let mut events = Events::with_capacity(10);
//! reactor.poll(&mut events, Some(Duration::from_millis(15)))?;
//! assert_eq!(events.len(), 1);
//! ```

use super::{Event, Interest, Reactor, Source, Token};
use crate::lab::chaos::{ChaosConfig, ChaosRng, ChaosStats};
use crate::tracing_compat::debug;
use crate::types::Time;
use std::collections::{BinaryHeap, HashMap};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// A timed event in the lab reactor.
///
/// Events are ordered by delivery time, with sequence numbers breaking ties
/// for deterministic ordering when events occur at the same time.
#[derive(Debug, PartialEq, Eq)]
struct TimedEvent {
    /// When to deliver this event (virtual time).
    time: Time,
    /// Sequence number for deterministic ordering of same-time events.
    sequence: u64,
    /// The actual event to deliver.
    event: Event,
    /// Whether delay injection has already been applied.
    delayed: bool,
}

impl PartialOrd for TimedEvent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimedEvent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Min-heap: earliest time first, then by sequence for determinism
        other
            .time
            .cmp(&self.time)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

/// Per-token fault injection configuration.
///
/// Allows fine-grained control over I/O behavior for individual tokens during testing.
/// This enables simulating connection failures, errors, and network partitions
/// on a per-connection basis, complementing the global chaos injection.
///
/// # Determinism
///
/// When `error_probability` is non-zero, fault injection uses a deterministic RNG
/// seeded from the token value, ensuring reproducible behavior across test runs.
///
/// # Example
///
/// ```ignore
/// use asupersync::runtime::reactor::{LabReactor, FaultConfig, Token, Interest};
/// use std::io;
///
/// let reactor = LabReactor::new();
/// let token = Token::new(1);
///
/// // Configure token to occasionally fail with connection reset
/// let config = FaultConfig::new()
///     .with_error_probability(0.1)
///     .with_error_kinds(vec![io::ErrorKind::ConnectionReset]);
/// reactor.set_fault_config(token, config);
///
/// // Or inject an immediate error
/// reactor.inject_error(token, io::ErrorKind::BrokenPipe);
///
/// // Or simulate connection close
/// reactor.inject_close(token);
/// ```
#[derive(Debug, Clone, Default)]
pub struct FaultConfig {
    /// One-shot error to inject on next event delivery.
    /// Cleared after delivery.
    pub pending_error: Option<io::ErrorKind>,
    /// Whether the connection is closed (delivers HUP on next poll).
    /// Once set, remains set until explicitly cleared.
    pub closed: bool,
    /// Whether this token is partitioned (events are dropped, not delivered).
    pub partitioned: bool,
    /// Probability of random error injection (0.0 - 1.0).
    pub error_probability: f64,
    /// Possible error kinds for random injection.
    pub error_kinds: Vec<io::ErrorKind>,
}

impl FaultConfig {
    /// Creates a new fault config with no faults configured.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the probability of random error injection.
    #[must_use]
    pub fn with_error_probability(mut self, prob: f64) -> Self {
        self.error_probability = prob.clamp(0.0, 1.0);
        self
    }

    /// Sets the possible error kinds for random injection.
    #[must_use]
    pub fn with_error_kinds(mut self, kinds: Vec<io::ErrorKind>) -> Self {
        self.error_kinds = kinds;
        self
    }

    /// Sets the partitioned state.
    #[must_use]
    pub fn with_partitioned(mut self, partitioned: bool) -> Self {
        self.partitioned = partitioned;
        self
    }

    /// Sets a pending error to inject on next event.
    #[must_use]
    pub fn with_pending_error(mut self, kind: io::ErrorKind) -> Self {
        self.pending_error = Some(kind);
        self
    }

    /// Marks the connection as closed.
    #[must_use]
    pub fn with_closed(mut self, closed: bool) -> Self {
        self.closed = closed;
        self
    }
}

/// Per-token fault injection state.
#[derive(Debug)]
struct FaultState {
    config: FaultConfig,
    /// Per-token RNG for deterministic random fault injection.
    /// Seeded from the token value for reproducibility.
    rng: ChaosRng,
    /// Last error kind injected (for diagnostics).
    last_error_kind: Option<io::ErrorKind>,
    /// Count of injected errors.
    injected_error_count: u64,
    /// Count of injected closes.
    injected_close_count: u64,
    /// Count of dropped events (partition).
    dropped_event_count: u64,
}

impl FaultState {
    fn new(token: Token, config: FaultConfig) -> Self {
        // Create deterministic RNG seeded from token for reproducibility
        let seed = token.0 as u64;
        Self {
            config,
            rng: ChaosRng::new(seed),
            last_error_kind: None,
            injected_error_count: 0,
            injected_close_count: 0,
            dropped_event_count: 0,
        }
    }

    /// Checks if a random error should be injected based on probability.
    fn should_inject_random_error(&mut self) -> bool {
        let prob = self.config.error_probability;
        if prob <= 0.0 || self.config.error_kinds.is_empty() {
            return false;
        }
        if prob >= 1.0 {
            return true;
        }
        self.rng.next_f64() < prob
    }

    /// Returns a random error kind from the configured list.
    fn next_error_kind(&mut self) -> Option<io::ErrorKind> {
        if self.config.error_kinds.is_empty() {
            return None;
        }
        let idx = (self.rng.next_u64() as usize) % self.config.error_kinds.len();
        Some(self.config.error_kinds[idx])
    }
}

/// A virtual socket state.
#[derive(Debug)]
struct VirtualSocket {
    interest: Interest,
    /// Per-token fault injection state.
    fault: Option<FaultState>,
}

#[derive(Debug)]
struct LabChaos {
    config: ChaosConfig,
    rng: ChaosRng,
    stats: ChaosStats,
    last_io_error_kind: Option<io::ErrorKind>,
}

impl LabChaos {
    fn new(config: ChaosConfig) -> Self {
        Self {
            rng: ChaosRng::from_config(&config),
            stats: ChaosStats::new(),
            last_io_error_kind: None,
            config,
        }
    }
}

/// A deterministic reactor for testing.
///
/// This reactor operates in virtual time and allows test code to inject
/// events at specific points. It's used by the lab runtime for deterministic
/// testing of async I/O code.
#[derive(Debug)]
pub struct LabReactor {
    inner: Mutex<LabInner>,
    /// Wake flag for simulating reactor wakeup.
    woken: AtomicBool,
}

#[derive(Debug)]
struct LabInner {
    sockets: HashMap<Token, VirtualSocket>,
    pending: BinaryHeap<TimedEvent>,
    time: Time,
    /// Monotonic sequence counter for deterministic same-time event ordering.
    next_sequence: u64,
    chaos: Option<LabChaos>,
}

impl LabReactor {
    /// Creates a new lab reactor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(LabInner {
                sockets: HashMap::new(),
                pending: BinaryHeap::new(),
                time: Time::ZERO,
                next_sequence: 0,
                chaos: None,
            }),
            woken: AtomicBool::new(false),
        }
    }

    /// Creates a new lab reactor with chaos injection enabled.
    #[must_use]
    pub fn with_chaos(config: ChaosConfig) -> Self {
        Self {
            inner: Mutex::new(LabInner {
                sockets: HashMap::new(),
                pending: BinaryHeap::new(),
                time: Time::ZERO,
                next_sequence: 0,
                chaos: Some(LabChaos::new(config)),
            }),
            woken: AtomicBool::new(false),
        }
    }

    /// Injects an event into the reactor at a specific delay from now.
    ///
    /// The event will be delivered when virtual time advances past the delay.
    /// This is the primary mechanism for testing I/O-dependent code.
    /// Events scheduled at the same time are delivered in insertion order.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to associate with the event
    /// * `event` - The event to inject
    /// * `delay` - How far in the future to deliver the event
    ///
    /// # Aliases
    ///
    /// This method is also known as `schedule_event()` in the spec.
    pub fn inject_event(&self, token: Token, mut event: Event, delay: Duration) {
        let mut inner = self.inner.lock().unwrap();
        let time = inner.time.saturating_add_nanos(delay.as_nanos() as u64);
        let sequence = inner.next_sequence;
        inner.next_sequence += 1;
        event.token = token;
        inner.pending.push(TimedEvent {
            time,
            sequence,
            event,
            delayed: false,
        });
    }

    /// Alias for `inject_event` to match the spec terminology.
    ///
    /// Schedules an event for future delivery at a specific delay from now.
    pub fn schedule_event(&self, token: Token, event: Event, delay: Duration) {
        self.inject_event(token, event, delay);
    }

    /// Makes a source immediately ready for the specified event type.
    ///
    /// The event will be delivered on the next call to `poll()`.
    /// Multiple calls to `set_ready()` for the same token append events.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to make ready
    /// * `event` - The event type (readable, writable, etc.)
    pub fn set_ready(&self, token: Token, event: Event) {
        self.inject_event(token, event, Duration::ZERO);
    }

    /// Returns the current virtual time.
    #[must_use]
    pub fn now(&self) -> Time {
        self.inner.lock().unwrap().time
    }

    /// Returns the next scheduled event time, if any.
    ///
    /// This is useful for driving the lab runtime forward to the next I/O event
    /// without relying on wall-clock time.
    #[must_use]
    pub fn next_event_time(&self) -> Option<Time> {
        let inner = self.inner.lock().unwrap();
        inner.pending.peek().map(|event| event.time)
    }

    /// Advances virtual time by the specified duration.
    ///
    /// This is useful for testing timeout behavior without going through poll().
    pub fn advance_time(&self, duration: Duration) {
        let mut inner = self.inner.lock().unwrap();
        inner.time = inner.time.saturating_add_nanos(duration.as_nanos() as u64);
    }

    /// Advances virtual time to a specific target time.
    ///
    /// If the target time is before the current time, this is a no-op.
    /// Events scheduled between the current time and target time will be
    /// delivered on the next `poll()` call.
    ///
    /// # Arguments
    ///
    /// * `target` - The target virtual time to advance to
    pub fn advance_time_to(&self, target: Time) {
        let mut inner = self.inner.lock().unwrap();
        if target > inner.time {
            inner.time = target;
        }
    }

    /// Checks if the reactor has been woken.
    ///
    /// Clears the wake flag and returns its previous value.
    pub fn check_and_clear_wake(&self) -> bool {
        self.woken.swap(false, Ordering::SeqCst)
    }

    // ========================================================================
    // Per-token fault injection API
    // ========================================================================

    /// Sets the fault configuration for a specific token.
    ///
    /// This enables per-connection fault injection, allowing tests to simulate
    /// failures on specific connections while others remain healthy.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to configure faults for
    /// * `config` - The fault configuration to apply
    ///
    /// # Returns
    ///
    /// Returns `Err` if the token is not registered.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::runtime::reactor::{LabReactor, FaultConfig, Token};
    /// use std::io;
    ///
    /// let reactor = LabReactor::new();
    /// let token = Token::new(1);
    /// // ... register token ...
    ///
    /// let config = FaultConfig::new()
    ///     .with_error_probability(0.5)
    ///     .with_error_kinds(vec![io::ErrorKind::ConnectionReset]);
    /// reactor.set_fault_config(token, config)?;
    /// ```
    pub fn set_fault_config(&self, token: Token, config: FaultConfig) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        match inner.sockets.get_mut(&token) {
            Some(socket) => {
                socket.fault = Some(FaultState::new(token, config));
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "token not registered",
            )),
        }
    }

    /// Clears fault configuration for a token.
    ///
    /// Removes any per-token fault injection, returning to normal behavior.
    ///
    /// # Returns
    ///
    /// Returns `Err` if the token is not registered.
    pub fn clear_fault_config(&self, token: Token) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        match inner.sockets.get_mut(&token) {
            Some(socket) => {
                socket.fault = None;
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "token not registered",
            )),
        }
    }

    /// Injects an immediate error for the next event on a token.
    ///
    /// The next event delivered for this token will be converted to an error
    /// event with the specified `ErrorKind`. This is a one-shot operation;
    /// subsequent events are not affected unless `inject_error` is called again.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to inject an error for
    /// * `kind` - The error kind to inject
    ///
    /// # Returns
    ///
    /// Returns `Err` if the token is not registered.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::runtime::reactor::{LabReactor, Token};
    /// use std::io;
    ///
    /// let reactor = LabReactor::new();
    /// let token = Token::new(1);
    /// // ... register token ...
    ///
    /// // The next event for this token will be an error
    /// reactor.inject_error(token, io::ErrorKind::BrokenPipe)?;
    /// ```
    pub fn inject_error(&self, token: Token, kind: io::ErrorKind) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        match inner.sockets.get_mut(&token) {
            Some(socket) => {
                if let Some(ref mut fault) = socket.fault {
                    fault.config.pending_error = Some(kind);
                } else {
                    let mut config = FaultConfig::new();
                    config.pending_error = Some(kind);
                    socket.fault = Some(FaultState::new(token, config));
                }
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "token not registered",
            )),
        }
    }

    /// Injects a connection close (HUP) for a token.
    ///
    /// Schedules a HUP event for the token, simulating the remote end closing
    /// the connection. The HUP event will be delivered on the next poll.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to close
    ///
    /// # Returns
    ///
    /// Returns `Err` if the token is not registered.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::runtime::reactor::{LabReactor, Token};
    ///
    /// let reactor = LabReactor::new();
    /// let token = Token::new(1);
    /// // ... register token ...
    ///
    /// // Simulate remote close
    /// reactor.inject_close(token)?;
    /// // Next poll will deliver HUP event
    /// ```
    pub fn inject_close(&self, token: Token) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();

        // Verify token is registered
        if !inner.sockets.contains_key(&token) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "token not registered",
            ));
        }

        // Mark socket as closed and schedule HUP event
        if let Some(socket) = inner.sockets.get_mut(&token) {
            if let Some(ref mut fault) = socket.fault {
                fault.config.closed = true;
                fault.injected_close_count += 1;
            } else {
                let config = FaultConfig::new().with_closed(true);
                let mut fault_state = FaultState::new(token, config);
                fault_state.injected_close_count = 1;
                socket.fault = Some(fault_state);
            }
        }

        // Schedule the HUP event for immediate delivery
        let time = inner.time;
        let sequence = inner.next_sequence;
        inner.next_sequence += 1;
        inner.pending.push(TimedEvent {
            time,
            sequence,
            event: Event::hangup(token),
            delayed: false,
        });

        debug!(
            target: "fault",
            token = token.0,
            injection = "close",
            "injected connection close"
        );

        drop(inner);
        Ok(())
    }

    /// Sets the partition state for a token.
    ///
    /// When partitioned, events for this token are dropped rather than delivered,
    /// simulating a network partition. This is useful for testing timeout handling
    /// and partition recovery.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to partition
    /// * `partitioned` - `true` to enable partition, `false` to disable
    ///
    /// # Returns
    ///
    /// Returns `Err` if the token is not registered.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::runtime::reactor::{LabReactor, Token, Interest, Event};
    /// use std::time::Duration;
    ///
    /// let reactor = LabReactor::new();
    /// let token = Token::new(1);
    /// // ... register token ...
    ///
    /// // Simulate network partition
    /// reactor.partition(token, true)?;
    /// reactor.inject_event(token, Event::readable(token), Duration::ZERO);
    ///
    /// // Event will be dropped, not delivered
    /// let mut events = Events::with_capacity(10);
    /// reactor.poll(&mut events, Some(Duration::ZERO))?;
    /// assert!(events.is_empty());
    ///
    /// // Restore connectivity
    /// reactor.partition(token, false)?;
    /// ```
    pub fn partition(&self, token: Token, partitioned: bool) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        match inner.sockets.get_mut(&token) {
            Some(socket) => {
                if let Some(ref mut fault) = socket.fault {
                    fault.config.partitioned = partitioned;
                } else if partitioned {
                    let config = FaultConfig::new().with_partitioned(true);
                    socket.fault = Some(FaultState::new(token, config));
                }
                // If not partitioned and no fault state, nothing to do

                debug!(
                    target: "fault",
                    token = token.0,
                    partitioned = partitioned,
                    "partition state changed"
                );

                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "token not registered",
            )),
        }
    }

    /// Returns the last error kind injected for a token (for diagnostics).
    pub fn last_injected_error(&self, token: Token) -> Option<io::ErrorKind> {
        let inner = self.inner.lock().unwrap();
        inner
            .sockets
            .get(&token)
            .and_then(|s| s.fault.as_ref())
            .and_then(|f| f.last_error_kind)
    }

    /// Returns fault injection statistics for a token.
    ///
    /// Returns `(injected_errors, injected_closes, dropped_events)`.
    pub fn fault_stats(&self, token: Token) -> Option<(u64, u64, u64)> {
        let inner = self.inner.lock().unwrap();
        inner.sockets.get(&token).and_then(|s| {
            s.fault.as_ref().map(|f| {
                (
                    f.injected_error_count,
                    f.injected_close_count,
                    f.dropped_event_count,
                )
            })
        })
    }
}

impl Default for LabReactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Reactor for LabReactor {
    fn register(&self, _source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.sockets.contains_key(&token) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "token already registered",
            ));
        }
        inner.sockets.insert(
            token,
            VirtualSocket {
                interest,
                fault: None,
            },
        );
        drop(inner);
        Ok(())
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        match inner.sockets.get_mut(&token) {
            Some(socket) => {
                socket.interest = interest;
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "token not registered",
            )),
        }
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.sockets.remove(&token).is_none() {
            drop(inner);
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "token not registered",
            ));
        }

        // Clean up any scheduled events for this token.
        // Since BinaryHeap doesn't support retain, we rebuild without the token's events.
        let old_pending = std::mem::take(&mut inner.pending);
        inner.pending = old_pending
            .into_iter()
            .filter(|te| te.event.token != token)
            .collect();

        drop(inner);
        Ok(())
    }

    #[allow(clippy::too_many_lines, clippy::significant_drop_tightening)]
    fn poll(&self, events: &mut super::Events, timeout: Option<Duration>) -> io::Result<usize> {
        // Clear wake flag at poll entry
        self.woken.store(false, Ordering::SeqCst);

        let (delivered_events, count) = {
            let mut inner = self.inner.lock().unwrap();

            // Advance time if timeout provided (simulated)
            if let Some(d) = timeout {
                inner.time = inner.time.saturating_add_nanos(d.as_nanos() as u64);
            }

            let mut ready_events = Vec::new();
            let mut delivered_events = Vec::new();

            // Pop events that are due
            while let Some(te) = inner.pending.peek() {
                if te.time <= inner.time {
                    let te = inner.pending.pop().unwrap();
                    if inner.sockets.contains_key(&te.event.token) {
                        ready_events.push(te);
                    }
                } else {
                    break;
                }
            }

            {
                let LabInner {
                    sockets,
                    pending,
                    time,
                    next_sequence,
                    chaos,
                } = &mut *inner;

                for timed in ready_events {
                    let event = timed.event;
                    let token = event.token;

                    // ================================================================
                    // Per-token fault injection (checked first, before global chaos)
                    // ================================================================
                    if let Some(socket) = sockets.get_mut(&token) {
                        if let Some(ref mut fault) = socket.fault {
                            // Check partition - drop events silently
                            if fault.config.partitioned {
                                fault.dropped_event_count += 1;
                                debug!(
                                    target: "fault",
                                    token = token.0,
                                    injection = "partition_drop",
                                    "event dropped due to partition"
                                );
                                continue;
                            }

                            let mut injected_error = fault.config.pending_error.take();
                            if let Some(kind) = injected_error {
                                fault.last_error_kind = Some(kind);
                                fault.injected_error_count += 1;
                                debug!(
                                    target: "fault",
                                    token = token.0,
                                    injection = "pending_error",
                                    error_kind = ?kind,
                                    "injected pending error"
                                );
                            }

                            // Check random error injection
                            if injected_error.is_none() && fault.should_inject_random_error() {
                                if let Some(kind) = fault.next_error_kind() {
                                    fault.last_error_kind = Some(kind);
                                    fault.injected_error_count += 1;
                                    debug!(
                                        target: "fault",
                                        token = token.0,
                                        injection = "random_error",
                                        error_kind = ?kind,
                                        "injected random error"
                                    );
                                    injected_error = Some(kind);
                                }
                            }

                            if injected_error.is_some() {
                                delivered_events.push(Event::errored(token));
                                continue;
                            }
                        }
                    }

                    // ================================================================
                    // Global chaos injection (if enabled)
                    // ================================================================
                    let delivered = if let Some(chaos) = chaos.as_mut() {
                        let config = &chaos.config;

                        // Check for delay injection
                        if !timed.delayed && chaos.rng.should_inject_delay(config) {
                            let delay = chaos.rng.next_delay(config);
                            if !delay.is_zero() {
                                let sequence = *next_sequence;
                                *next_sequence += 1;
                                let delayed_time =
                                    time.saturating_add_nanos(delay.as_nanos() as u64);
                                pending.push(TimedEvent {
                                    time: delayed_time,
                                    sequence,
                                    event,
                                    delayed: true,
                                });
                                chaos.stats.record_delay(delay);
                                debug!(
                                    target: "chaos",
                                    token = token.0,
                                    injection = "io_delay",
                                    delay_ns = delay.as_nanos() as u64
                                );
                                continue;
                            }
                        }

                        // Check for error injection
                        let mut injected = false;
                        let mut delivered_event = event;
                        if chaos.rng.should_inject_io_error(config) {
                            if let Some(kind) = chaos.rng.next_io_error_kind(config) {
                                delivered_event = Event::errored(token);
                                chaos.last_io_error_kind = Some(kind);
                                chaos.stats.record_io_error();
                                debug!(
                                    target: "chaos",
                                    token = token.0,
                                    injection = "io_error",
                                    error_kind = ?kind
                                );
                                injected = true;
                            }
                        }

                        if !injected {
                            chaos.stats.record_no_injection();
                        }

                        Some(delivered_event)
                    } else {
                        // No chaos - deliver event as-is
                        Some(event)
                    };

                    if let Some(delivered_event) = delivered {
                        delivered_events.push(delivered_event);
                    }
                }
            }

            let count = delivered_events.len();
            (delivered_events, count)
        };

        for event in delivered_events {
            events.push(event);
        }

        Ok(count)
    }

    fn wake(&self) -> io::Result<()> {
        self.woken.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn registration_count(&self) -> usize {
        self.inner.lock().unwrap().sockets.len()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    struct MockSource;
    impl std::os::fd::AsRawFd for MockSource {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            0
        }
    }

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn delivers_injected_event() {
        init_test("delivers_injected_event");
        let reactor = LabReactor::new();
        let token = Token::new(1);
        let source = MockSource;

        reactor
            .register(&source, token, Interest::readable())
            .unwrap();

        reactor.inject_event(token, Event::readable(token), Duration::from_millis(10));

        let mut events = crate::runtime::reactor::Events::with_capacity(10);

        // Poll before time - should be empty
        reactor
            .poll(&mut events, Some(Duration::from_millis(5)))
            .unwrap();
        crate::assert_with_log!(
            events.is_empty(),
            "events empty before time",
            true,
            events.is_empty()
        );

        // Poll after time - should have event
        reactor
            .poll(&mut events, Some(Duration::from_millis(10)))
            .unwrap();
        let count = events.iter().count();
        crate::assert_with_log!(count == 1, "event delivered", 1usize, count);
        crate::test_complete!("delivers_injected_event");
    }

    #[test]
    fn modify_interest() {
        init_test("modify_interest");
        let reactor = LabReactor::new();
        let token = Token::new(1);
        let source = MockSource;

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();
        crate::assert_with_log!(
            reactor.registration_count() == 1,
            "registration count",
            1usize,
            reactor.registration_count()
        );

        // Modify to writable
        reactor.modify(token, Interest::WRITABLE).unwrap();

        // Should fail for non-existent token
        let result = reactor.modify(Token::new(999), Interest::READABLE);
        crate::assert_with_log!(
            result.is_err(),
            "modify missing fails",
            true,
            result.is_err()
        );
        crate::test_complete!("modify_interest");
    }

    #[test]
    fn deregister_by_token() {
        init_test("deregister_by_token");
        let reactor = LabReactor::new();
        let token = Token::new(1);
        let source = MockSource;

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();
        crate::assert_with_log!(
            reactor.registration_count() == 1,
            "registration count",
            1usize,
            reactor.registration_count()
        );

        reactor.deregister(token).unwrap();
        crate::assert_with_log!(
            reactor.registration_count() == 0,
            "registration count",
            0usize,
            reactor.registration_count()
        );

        // Deregister again should fail
        let result = reactor.deregister(token);
        crate::assert_with_log!(
            result.is_err(),
            "deregister missing fails",
            true,
            result.is_err()
        );
        crate::test_complete!("deregister_by_token");
    }

    #[test]
    fn duplicate_register_fails() {
        init_test("duplicate_register_fails");
        let reactor = LabReactor::new();
        let token = Token::new(1);
        let source = MockSource;

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();

        // Second registration with same token should fail
        let result = reactor.register(&source, token, Interest::WRITABLE);
        crate::assert_with_log!(result.is_err(), "duplicate fails", true, result.is_err());
        crate::test_complete!("duplicate_register_fails");
    }

    #[test]
    fn wake_sets_flag() {
        init_test("wake_sets_flag");
        let reactor = LabReactor::new();

        let was_set = reactor.check_and_clear_wake();
        crate::assert_with_log!(!was_set, "wake flag initially false", false, was_set);

        reactor.wake().unwrap();
        let now_set = reactor.check_and_clear_wake();
        crate::assert_with_log!(now_set, "wake flag set", true, now_set);

        // Flag should be cleared
        let cleared = reactor.check_and_clear_wake();
        crate::assert_with_log!(!cleared, "wake flag cleared", false, cleared);
        crate::test_complete!("wake_sets_flag");
    }

    #[test]
    fn registration_count_and_is_empty() {
        init_test("registration_count_and_is_empty");
        let reactor = LabReactor::new();
        let source = MockSource;

        crate::assert_with_log!(
            reactor.is_empty(),
            "reactor empty",
            true,
            reactor.is_empty()
        );
        crate::assert_with_log!(
            reactor.registration_count() == 0,
            "registration count",
            0usize,
            reactor.registration_count()
        );

        reactor
            .register(&source, Token::new(1), Interest::READABLE)
            .unwrap();
        crate::assert_with_log!(
            !reactor.is_empty(),
            "reactor not empty",
            false,
            reactor.is_empty()
        );
        crate::assert_with_log!(
            reactor.registration_count() == 1,
            "registration count",
            1usize,
            reactor.registration_count()
        );

        reactor
            .register(&source, Token::new(2), Interest::WRITABLE)
            .unwrap();
        crate::assert_with_log!(
            reactor.registration_count() == 2,
            "registration count",
            2usize,
            reactor.registration_count()
        );

        reactor.deregister(Token::new(1)).unwrap();
        crate::assert_with_log!(
            reactor.registration_count() == 1,
            "registration count",
            1usize,
            reactor.registration_count()
        );

        reactor.deregister(Token::new(2)).unwrap();
        crate::assert_with_log!(
            reactor.is_empty(),
            "reactor empty",
            true,
            reactor.is_empty()
        );
        crate::test_complete!("registration_count_and_is_empty");
    }

    #[test]
    fn virtual_time_advances() {
        init_test("virtual_time_advances");
        let reactor = LabReactor::new();

        crate::assert_with_log!(
            reactor.now() == Time::ZERO,
            "initial time",
            Time::ZERO,
            reactor.now()
        );

        reactor.advance_time(Duration::from_secs(1));
        crate::assert_with_log!(
            reactor.now().as_nanos() == 1_000_000_000,
            "time after advance",
            1_000_000_000u64,
            reactor.now().as_nanos()
        );

        // Poll also advances time
        let mut events = crate::runtime::reactor::Events::with_capacity(10);
        reactor
            .poll(&mut events, Some(Duration::from_millis(500)))
            .unwrap();
        crate::assert_with_log!(
            reactor.now().as_nanos() == 1_500_000_000,
            "time after poll",
            1_500_000_000u64,
            reactor.now().as_nanos()
        );
        crate::test_complete!("virtual_time_advances");
    }

    #[test]
    fn advance_time_to_target() {
        init_test("advance_time_to_target");
        let reactor = LabReactor::new();

        crate::assert_with_log!(
            reactor.now() == Time::ZERO,
            "initial time",
            Time::ZERO,
            reactor.now()
        );

        // Advance to 1 second
        reactor.advance_time_to(Time::from_nanos(1_000_000_000));
        crate::assert_with_log!(
            reactor.now().as_nanos() == 1_000_000_000,
            "time after advance",
            1_000_000_000u64,
            reactor.now().as_nanos()
        );

        // Advancing to past time is a no-op
        reactor.advance_time_to(Time::from_nanos(500_000_000));
        crate::assert_with_log!(
            reactor.now().as_nanos() == 1_000_000_000,
            "time unchanged",
            1_000_000_000u64,
            reactor.now().as_nanos()
        );

        // Advance further
        reactor.advance_time_to(Time::from_nanos(2_000_000_000));
        crate::assert_with_log!(
            reactor.now().as_nanos() == 2_000_000_000,
            "time advanced",
            2_000_000_000u64,
            reactor.now().as_nanos()
        );
        crate::test_complete!("advance_time_to_target");
    }

    #[test]
    fn set_ready_delivers_immediately() {
        init_test("set_ready_delivers_immediately");
        let reactor = LabReactor::new();
        let token = Token::new(1);
        let source = MockSource;

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();

        // Set ready immediately
        reactor.set_ready(token, Event::readable(token));

        let mut events = crate::runtime::reactor::Events::with_capacity(10);

        // Poll with zero timeout should still deliver the event
        reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        let count = events.iter().count();
        crate::assert_with_log!(count == 1, "event delivered", 1usize, count);
        crate::test_complete!("set_ready_delivers_immediately");
    }

    #[test]
    fn same_time_events_delivered_in_order() {
        init_test("same_time_events_delivered_in_order");
        let reactor = LabReactor::new();
        let source = MockSource;

        // Register multiple tokens
        let token1 = Token::new(1);
        let token2 = Token::new(2);
        let token3 = Token::new(3);

        reactor
            .register(&source, token1, Interest::READABLE)
            .unwrap();
        reactor
            .register(&source, token2, Interest::READABLE)
            .unwrap();
        reactor
            .register(&source, token3, Interest::READABLE)
            .unwrap();

        // Schedule all at the same time (10ms from now)
        // They should be delivered in insertion order: 1, 2, 3
        reactor.schedule_event(token1, Event::readable(token1), Duration::from_millis(10));
        reactor.schedule_event(token2, Event::readable(token2), Duration::from_millis(10));
        reactor.schedule_event(token3, Event::readable(token3), Duration::from_millis(10));

        let mut events = crate::runtime::reactor::Events::with_capacity(10);

        // Advance time past the scheduled time
        reactor
            .poll(&mut events, Some(Duration::from_millis(15)))
            .unwrap();

        // Should have 3 events in order
        let collected: Vec<_> = events.iter().collect();
        crate::assert_with_log!(collected.len() == 3, "event count", 3usize, collected.len());
        crate::assert_with_log!(
            collected[0].token == token1,
            "first token",
            token1,
            collected[0].token
        );
        crate::assert_with_log!(
            collected[1].token == token2,
            "second token",
            token2,
            collected[1].token
        );
        crate::assert_with_log!(
            collected[2].token == token3,
            "third token",
            token3,
            collected[2].token
        );
        crate::test_complete!("same_time_events_delivered_in_order");
    }

    #[test]
    fn different_time_events_delivered_in_time_order() {
        init_test("different_time_events_delivered_in_time_order");
        let reactor = LabReactor::new();
        let source = MockSource;

        let token1 = Token::new(1);
        let token2 = Token::new(2);
        let token3 = Token::new(3);

        reactor
            .register(&source, token1, Interest::READABLE)
            .unwrap();
        reactor
            .register(&source, token2, Interest::READABLE)
            .unwrap();
        reactor
            .register(&source, token3, Interest::READABLE)
            .unwrap();

        // Schedule in reverse order of delivery time
        // token3 at 5ms, token1 at 10ms, token2 at 15ms
        reactor.schedule_event(token3, Event::readable(token3), Duration::from_millis(5));
        reactor.schedule_event(token1, Event::readable(token1), Duration::from_millis(10));
        reactor.schedule_event(token2, Event::readable(token2), Duration::from_millis(15));

        let mut events = crate::runtime::reactor::Events::with_capacity(10);

        // Poll to 20ms - all events should be delivered
        reactor
            .poll(&mut events, Some(Duration::from_millis(20)))
            .unwrap();

        // Should be in time order: token3, token1, token2
        let collected: Vec<_> = events.iter().collect();
        crate::assert_with_log!(collected.len() == 3, "event count", 3usize, collected.len());
        crate::assert_with_log!(
            collected[0].token == token3,
            "first token",
            token3,
            collected[0].token
        );
        crate::assert_with_log!(
            collected[1].token == token1,
            "second token",
            token1,
            collected[1].token
        );
        crate::assert_with_log!(
            collected[2].token == token2,
            "third token",
            token2,
            collected[2].token
        );
        crate::test_complete!("different_time_events_delivered_in_time_order");
    }

    #[test]
    fn schedule_event_alias_works() {
        init_test("schedule_event_alias_works");
        let reactor = LabReactor::new();
        let token = Token::new(1);
        let source = MockSource;

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();

        // Use schedule_event (alias for inject_event)
        reactor.schedule_event(token, Event::readable(token), Duration::from_millis(10));

        let mut events = crate::runtime::reactor::Events::with_capacity(10);
        reactor
            .poll(&mut events, Some(Duration::from_millis(15)))
            .unwrap();

        let count = events.iter().count();
        crate::assert_with_log!(count == 1, "event delivered", 1usize, count);
        crate::test_complete!("schedule_event_alias_works");
    }

    #[test]
    fn events_before_current_time_delivered_immediately() {
        init_test("events_before_current_time_delivered_immediately");
        let reactor = LabReactor::new();
        let source = MockSource;
        let token = Token::new(1);

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();

        // First advance time
        reactor.advance_time(Duration::from_millis(100));

        // Schedule event at current time (delay = 0)
        reactor.schedule_event(token, Event::readable(token), Duration::ZERO);

        let mut events = crate::runtime::reactor::Events::with_capacity(10);

        // Poll with zero timeout should deliver
        reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();

        let count = events.iter().count();
        crate::assert_with_log!(count == 1, "event delivered", 1usize, count);
        crate::test_complete!("events_before_current_time_delivered_immediately");
    }

    #[test]
    fn deregister_cleans_up_scheduled_events() {
        init_test("deregister_cleans_up_scheduled_events");
        let reactor = LabReactor::new();
        let source = MockSource;

        let token1 = Token::new(1);
        let token2 = Token::new(2);

        reactor
            .register(&source, token1, Interest::READABLE)
            .unwrap();
        reactor
            .register(&source, token2, Interest::READABLE)
            .unwrap();

        // Schedule events for both tokens
        reactor.schedule_event(token1, Event::readable(token1), Duration::from_millis(10));
        reactor.schedule_event(token2, Event::readable(token2), Duration::from_millis(10));
        reactor.schedule_event(token1, Event::readable(token1), Duration::from_millis(20));

        // Deregister token1
        reactor.deregister(token1).unwrap();

        let mut events = crate::runtime::reactor::Events::with_capacity(10);

        // Advance time past all scheduled events
        reactor
            .poll(&mut events, Some(Duration::from_millis(25)))
            .unwrap();

        // Should only have token2's event (token1's events were cleaned up)
        let collected: Vec<_> = events.iter().collect();
        crate::assert_with_log!(collected.len() == 1, "event count", 1usize, collected.len());
        crate::assert_with_log!(
            collected[0].token == token2,
            "remaining token",
            token2,
            collected[0].token
        );
        crate::test_complete!("deregister_cleans_up_scheduled_events");
    }

    #[test]
    fn io_chaos_injects_error_events() {
        init_test("io_chaos_injects_error_events");
        let config = ChaosConfig::new(7)
            .with_io_error_probability(1.0)
            .with_io_error_kinds(vec![io::ErrorKind::TimedOut]);

        let reactor = LabReactor::with_chaos(config);
        let token = Token::new(1);
        let source = MockSource;

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();
        reactor.set_ready(token, Event::readable(token));

        let mut events = crate::runtime::reactor::Events::with_capacity(10);
        reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();

        let event = events.iter().next().expect("event");
        crate::assert_with_log!(event.is_error(), "event is error", true, event.is_error());

        let last_kind = reactor
            .inner
            .lock()
            .unwrap()
            .chaos
            .as_ref()
            .and_then(|chaos| chaos.last_io_error_kind);
        crate::assert_with_log!(
            last_kind == Some(io::ErrorKind::TimedOut),
            "last error kind",
            Some(io::ErrorKind::TimedOut),
            last_kind
        );
        crate::test_complete!("io_chaos_injects_error_events");
    }

    #[test]
    fn io_chaos_delays_events() {
        init_test("io_chaos_delays_events");
        let config = ChaosConfig::new(11)
            .with_delay_probability(1.0)
            .with_delay_range(Duration::from_millis(5)..Duration::from_millis(6));

        let reactor = LabReactor::with_chaos(config);
        let token = Token::new(1);
        let source = MockSource;

        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();
        reactor.set_ready(token, Event::readable(token));

        let mut events = crate::runtime::reactor::Events::with_capacity(10);
        reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        crate::assert_with_log!(
            events.is_empty(),
            "initial poll empty",
            true,
            events.is_empty()
        );

        let delayed_at = reactor
            .inner
            .lock()
            .unwrap()
            .pending
            .peek()
            .map(|te| te.time)
            .expect("delayed event");

        reactor.advance_time_to(delayed_at);
        events.clear();
        reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
        let count = events.iter().count();
        crate::assert_with_log!(count == 1, "delayed event delivered", 1usize, count);
        crate::test_complete!("io_chaos_delays_events");
    }

    #[test]
    fn io_chaos_is_deterministic_with_same_seed() {
        init_test("io_chaos_is_deterministic_with_same_seed");
        let config = ChaosConfig::new(123)
            .with_io_error_probability(0.5)
            .with_io_error_kinds(vec![io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut]);

        let reactor_a = LabReactor::with_chaos(config.clone());
        let reactor_b = LabReactor::with_chaos(config);

        let token_a = Token::new(1);
        let token_b = Token::new(1);
        let source = MockSource;

        reactor_a
            .register(&source, token_a, Interest::READABLE)
            .unwrap();
        reactor_b
            .register(&source, token_b, Interest::READABLE)
            .unwrap();

        reactor_a.set_ready(token_a, Event::readable(token_a));
        reactor_b.set_ready(token_b, Event::readable(token_b));

        let mut events_a = crate::runtime::reactor::Events::with_capacity(10);
        let mut events_b = crate::runtime::reactor::Events::with_capacity(10);

        reactor_a.poll(&mut events_a, Some(Duration::ZERO)).unwrap();
        reactor_b.poll(&mut events_b, Some(Duration::ZERO)).unwrap();

        let ready_a = events_a.iter().next().expect("event").ready;
        let ready_b = events_b.iter().next().expect("event").ready;
        crate::assert_with_log!(ready_a == ready_b, "ready matches", ready_b, ready_a);

        let last_a = reactor_a
            .inner
            .lock()
            .unwrap()
            .chaos
            .as_ref()
            .and_then(|chaos| chaos.last_io_error_kind);
        let last_b = reactor_b
            .inner
            .lock()
            .unwrap()
            .chaos
            .as_ref()
            .and_then(|chaos| chaos.last_io_error_kind);
        crate::assert_with_log!(last_a == last_b, "last error kind", last_b, last_a);
        crate::test_complete!("io_chaos_is_deterministic_with_same_seed");
    }

    /// Integration test verifying IoDriver correctly dispatches wakers with LabReactor.
    mod io_driver_integration {
        use super::*;
        use crate::runtime::io_driver::IoDriver;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::task::{Wake, Waker};

        struct FlagWaker {
            flag: AtomicBool,
            count: AtomicUsize,
        }

        impl Wake for FlagWaker {
            fn wake(self: Arc<Self>) {
                self.flag.store(true, Ordering::SeqCst);
                self.count.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.flag.store(true, Ordering::SeqCst);
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn create_test_waker() -> (Waker, Arc<FlagWaker>) {
            let state = Arc::new(FlagWaker {
                flag: AtomicBool::new(false),
                count: AtomicUsize::new(0),
            });
            (Waker::from(state.clone()), state)
        }

        #[test]
        fn io_driver_with_lab_reactor_dispatches_wakers() {
            super::init_test("io_driver_with_lab_reactor_dispatches_wakers");
            let reactor = Arc::new(LabReactor::new());
            let mut driver = IoDriver::new(reactor.clone());
            let source = MockSource;

            // Register with IoDriver
            let (waker, waker_state) = create_test_waker();
            let token = driver
                .register(&source, Interest::READABLE, waker)
                .expect("register");

            // Waker should not be woken yet
            let initial = waker_state.flag.load(Ordering::SeqCst);
            crate::assert_with_log!(!initial, "waker not yet woken", false, initial);

            // Inject an event for our token
            reactor.inject_event(token, Event::readable(token), Duration::ZERO);

            // Turn the driver - should dispatch the waker
            let count = driver.turn(Some(Duration::from_millis(10))).expect("turn");

            crate::assert_with_log!(count >= 1, "events dispatched", true, count >= 1);
            let flag = waker_state.flag.load(Ordering::SeqCst);
            crate::assert_with_log!(flag, "waker fired", true, flag);
            let wake_count = waker_state.count.load(Ordering::SeqCst);
            crate::assert_with_log!(wake_count == 1, "wake count", 1usize, wake_count);
            crate::test_complete!("io_driver_with_lab_reactor_dispatches_wakers");
        }

        #[test]
        fn io_driver_with_lab_reactor_multiple_wakers() {
            super::init_test("io_driver_with_lab_reactor_multiple_wakers");
            let reactor = Arc::new(LabReactor::new());
            let mut driver = IoDriver::new(reactor.clone());
            let source = MockSource;

            // Register multiple wakers
            let (waker1, state1) = create_test_waker();
            let (waker2, state2) = create_test_waker();
            let (waker3, state3) = create_test_waker();

            let token1 = driver
                .register(&source, Interest::READABLE, waker1)
                .unwrap();
            let _token2 = driver
                .register(&source, Interest::READABLE, waker2)
                .unwrap();
            let token3 = driver
                .register(&source, Interest::READABLE, waker3)
                .unwrap();

            // Inject events for tokens 1 and 3 only
            reactor.inject_event(token1, Event::readable(token1), Duration::ZERO);
            reactor.inject_event(token3, Event::readable(token3), Duration::ZERO);

            // Turn should dispatch wakers 1 and 3
            let count = driver.turn(Some(Duration::from_millis(10))).unwrap();

            crate::assert_with_log!(count == 2, "dispatch count", 2usize, count);
            let flag1 = state1.flag.load(Ordering::SeqCst);
            let flag2 = state2.flag.load(Ordering::SeqCst);
            let flag3 = state3.flag.load(Ordering::SeqCst);
            crate::assert_with_log!(flag1, "waker1 fired", true, flag1);
            crate::assert_with_log!(!flag2, "waker2 not fired", false, flag2);
            crate::assert_with_log!(flag3, "waker3 fired", true, flag3);
            crate::test_complete!("io_driver_with_lab_reactor_multiple_wakers");
        }
    }

    /// Per-token fault injection tests.
    mod fault_injection {
        use super::*;

        fn approx_eq(lhs: f64, rhs: f64) -> bool {
            (lhs - rhs).abs() < f64::EPSILON
        }

        #[test]
        fn fault_config_builder() {
            super::init_test("fault_config_builder");

            let config = FaultConfig::new()
                .with_error_probability(0.5)
                .with_error_kinds(vec![
                    io::ErrorKind::BrokenPipe,
                    io::ErrorKind::ConnectionReset,
                ])
                .with_partitioned(true)
                .with_closed(true)
                .with_pending_error(io::ErrorKind::TimedOut);

            let approx = approx_eq(config.error_probability, 0.5);
            crate::assert_with_log!(
                approx,
                "error_probability",
                0.5f64,
                config.error_probability
            );
            crate::assert_with_log!(
                config.error_kinds.len() == 2,
                "error_kinds len",
                2usize,
                config.error_kinds.len()
            );
            crate::assert_with_log!(config.partitioned, "partitioned", true, config.partitioned);
            crate::assert_with_log!(config.closed, "closed", true, config.closed);
            crate::assert_with_log!(
                config.pending_error == Some(io::ErrorKind::TimedOut),
                "pending_error",
                Some(io::ErrorKind::TimedOut),
                config.pending_error
            );

            crate::test_complete!("fault_config_builder");
        }

        #[test]
        fn fault_config_probability_clamped() {
            super::init_test("fault_config_probability_clamped");

            let config_low = FaultConfig::new().with_error_probability(-0.5);
            let config_high = FaultConfig::new().with_error_probability(1.5);

            let low_ok = approx_eq(config_low.error_probability, 0.0);
            crate::assert_with_log!(low_ok, "clamped to 0", 0.0f64, config_low.error_probability);
            let high_ok = approx_eq(config_high.error_probability, 1.0);
            crate::assert_with_log!(
                high_ok,
                "clamped to 1",
                1.0f64,
                config_high.error_probability
            );

            crate::test_complete!("fault_config_probability_clamped");
        }

        #[test]
        fn set_and_clear_fault_config() {
            super::init_test("set_and_clear_fault_config");

            let reactor = LabReactor::new();
            let token = Token::new(1);
            let source = MockSource;

            reactor
                .register(&source, token, Interest::READABLE)
                .unwrap();

            // Set fault config
            let config = FaultConfig::new().with_partitioned(true);
            reactor.set_fault_config(token, config).unwrap();

            // Verify fault is set
            let has_fault = reactor
                .inner
                .lock()
                .unwrap()
                .sockets
                .get(&token)
                .and_then(|s| s.fault.as_ref())
                .is_some();
            crate::assert_with_log!(has_fault, "fault config set", true, has_fault);

            // Clear fault config
            reactor.clear_fault_config(token).unwrap();

            let has_fault = reactor
                .inner
                .lock()
                .unwrap()
                .sockets
                .get(&token)
                .and_then(|s| s.fault.as_ref())
                .is_some();
            crate::assert_with_log!(!has_fault, "fault config cleared", false, has_fault);

            crate::test_complete!("set_and_clear_fault_config");
        }

        #[test]
        fn set_fault_config_unregistered_token_fails() {
            super::init_test("set_fault_config_unregistered_token_fails");

            let reactor = LabReactor::new();
            let token = Token::new(999);

            let result = reactor.set_fault_config(token, FaultConfig::new());
            crate::assert_with_log!(result.is_err(), "unregistered fails", true, result.is_err());

            crate::test_complete!("set_fault_config_unregistered_token_fails");
        }

        #[test]
        fn inject_error_one_shot() {
            super::init_test("inject_error_one_shot");

            let reactor = LabReactor::new();
            let token = Token::new(1);
            let source = MockSource;

            reactor
                .register(&source, token, Interest::READABLE)
                .unwrap();

            // Inject error
            reactor
                .inject_error(token, io::ErrorKind::BrokenPipe)
                .unwrap();

            // Schedule a readable event
            reactor.set_ready(token, Event::readable(token));

            let mut events = crate::runtime::reactor::Events::with_capacity(10);
            reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();

            // First event should be error
            let event = events.iter().next().expect("event");
            crate::assert_with_log!(
                event.is_error(),
                "first event is error",
                true,
                event.is_error()
            );

            // Verify last error kind recorded
            let last_error = reactor.last_injected_error(token);
            crate::assert_with_log!(
                last_error == Some(io::ErrorKind::BrokenPipe),
                "last error recorded",
                Some(io::ErrorKind::BrokenPipe),
                last_error
            );

            // Second event should be normal (one-shot)
            events.clear();
            reactor.set_ready(token, Event::readable(token));
            reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();

            let event = events.iter().next().expect("event");
            crate::assert_with_log!(
                event.is_readable(),
                "second event is readable",
                true,
                event.is_readable()
            );

            crate::test_complete!("inject_error_one_shot");
        }

        #[test]
        fn inject_close_delivers_hup() {
            super::init_test("inject_close_delivers_hup");

            let reactor = LabReactor::new();
            let token = Token::new(1);
            let source = MockSource;

            reactor
                .register(&source, token, Interest::READABLE)
                .unwrap();

            // Inject close
            reactor.inject_close(token).unwrap();

            let mut events = crate::runtime::reactor::Events::with_capacity(10);
            reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();

            // Should receive HUP event
            let event = events.iter().next().expect("event");
            crate::assert_with_log!(event.is_hangup(), "received HUP", true, event.is_hangup());

            // Verify stats
            let stats = reactor.fault_stats(token);
            crate::assert_with_log!(stats.is_some(), "has stats", true, stats.is_some());
            let (errors, closes, dropped) = stats.unwrap();
            crate::assert_with_log!(closes == 1, "close count", 1u64, closes);
            crate::assert_with_log!(errors == 0, "error count", 0u64, errors);
            crate::assert_with_log!(dropped == 0, "dropped count", 0u64, dropped);

            crate::test_complete!("inject_close_delivers_hup");
        }

        #[test]
        fn partition_drops_events() {
            super::init_test("partition_drops_events");

            let reactor = LabReactor::new();
            let token = Token::new(1);
            let source = MockSource;

            reactor
                .register(&source, token, Interest::READABLE)
                .unwrap();

            // Enable partition
            reactor.partition(token, true).unwrap();

            // Schedule events
            reactor.set_ready(token, Event::readable(token));
            reactor.set_ready(token, Event::writable(token));

            let mut events = crate::runtime::reactor::Events::with_capacity(10);
            reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();

            // Events should be dropped
            crate::assert_with_log!(events.is_empty(), "events dropped", true, events.is_empty());

            // Verify stats
            let stats = reactor.fault_stats(token);
            let (_, _, dropped) = stats.unwrap();
            crate::assert_with_log!(dropped == 2, "dropped count", 2u64, dropped);

            // Disable partition
            reactor.partition(token, false).unwrap();

            // Schedule another event
            reactor.set_ready(token, Event::readable(token));
            events.clear();
            reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();

            // Event should be delivered
            crate::assert_with_log!(events.len() == 1, "event delivered", 1usize, events.len());

            crate::test_complete!("partition_drops_events");
        }

        #[test]
        fn random_error_injection() {
            super::init_test("random_error_injection");

            let reactor = LabReactor::new();
            let token = Token::new(42); // Use specific token for deterministic RNG
            let source = MockSource;

            reactor
                .register(&source, token, Interest::READABLE)
                .unwrap();

            // Configure 100% error probability
            let config = FaultConfig::new()
                .with_error_probability(1.0)
                .with_error_kinds(vec![io::ErrorKind::ConnectionReset]);
            reactor.set_fault_config(token, config).unwrap();

            // Schedule a readable event
            reactor.set_ready(token, Event::readable(token));

            let mut events = crate::runtime::reactor::Events::with_capacity(10);
            reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();

            // Should be error
            let event = events.iter().next().expect("event");
            crate::assert_with_log!(event.is_error(), "error injected", true, event.is_error());

            let last_error = reactor.last_injected_error(token);
            crate::assert_with_log!(
                last_error == Some(io::ErrorKind::ConnectionReset),
                "error kind",
                Some(io::ErrorKind::ConnectionReset),
                last_error
            );

            crate::test_complete!("random_error_injection");
        }

        #[test]
        fn per_token_fault_isolated() {
            super::init_test("per_token_fault_isolated");

            let reactor = LabReactor::new();
            let token1 = Token::new(1);
            let token2 = Token::new(2);
            let source = MockSource;

            reactor
                .register(&source, token1, Interest::READABLE)
                .unwrap();
            reactor
                .register(&source, token2, Interest::READABLE)
                .unwrap();

            // Partition only token1
            reactor.partition(token1, true).unwrap();

            // Schedule events for both
            reactor.set_ready(token1, Event::readable(token1));
            reactor.set_ready(token2, Event::readable(token2));

            let mut events = crate::runtime::reactor::Events::with_capacity(10);
            reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();

            // Only token2's event should be delivered
            crate::assert_with_log!(events.len() == 1, "one event", 1usize, events.len());
            let event = events.iter().next().expect("event");
            crate::assert_with_log!(
                event.token == token2,
                "token2 delivered",
                token2,
                event.token
            );

            crate::test_complete!("per_token_fault_isolated");
        }

        #[test]
        fn fault_injection_deterministic_with_same_token() {
            super::init_test("fault_injection_deterministic_with_same_token");

            // Two reactors with same token should produce same random fault sequence
            let reactor_a = LabReactor::new();
            let reactor_b = LabReactor::new();
            let token = Token::new(123); // Same token = same RNG seed
            let source = MockSource;

            reactor_a
                .register(&source, token, Interest::READABLE)
                .unwrap();
            reactor_b
                .register(&source, token, Interest::READABLE)
                .unwrap();

            // Configure 50% error probability with multiple kinds
            let config = FaultConfig::new()
                .with_error_probability(0.5)
                .with_error_kinds(vec![
                    io::ErrorKind::WouldBlock,
                    io::ErrorKind::TimedOut,
                    io::ErrorKind::ConnectionReset,
                ]);

            reactor_a.set_fault_config(token, config.clone()).unwrap();
            reactor_b.set_fault_config(token, config).unwrap();

            // Run multiple events and compare outcomes
            let mut results_a = Vec::new();
            let mut results_b = Vec::new();

            for _ in 0..10 {
                reactor_a.set_ready(token, Event::readable(token));
                reactor_b.set_ready(token, Event::readable(token));

                let mut events_a = crate::runtime::reactor::Events::with_capacity(10);
                let mut events_b = crate::runtime::reactor::Events::with_capacity(10);

                reactor_a.poll(&mut events_a, Some(Duration::ZERO)).unwrap();
                reactor_b.poll(&mut events_b, Some(Duration::ZERO)).unwrap();

                results_a.push(events_a.iter().next().map(|e| e.ready));
                results_b.push(events_b.iter().next().map(|e| e.ready));
            }

            crate::assert_with_log!(
                results_a == results_b,
                "deterministic results",
                results_b,
                results_a
            );

            crate::test_complete!("fault_injection_deterministic_with_same_token");
        }

        #[test]
        fn inject_error_creates_fault_state_if_missing() {
            super::init_test("inject_error_creates_fault_state_if_missing");

            let reactor = LabReactor::new();
            let token = Token::new(1);
            let source = MockSource;

            reactor
                .register(&source, token, Interest::READABLE)
                .unwrap();

            // No fault config set, inject error should create one
            reactor
                .inject_error(token, io::ErrorKind::TimedOut)
                .unwrap();

            let has_fault = reactor
                .inner
                .lock()
                .unwrap()
                .sockets
                .get(&token)
                .and_then(|s| s.fault.as_ref())
                .is_some();
            crate::assert_with_log!(has_fault, "fault state created", true, has_fault);

            crate::test_complete!("inject_error_creates_fault_state_if_missing");
        }

        #[test]
        fn per_token_fault_with_global_chaos() {
            super::init_test("per_token_fault_with_global_chaos");

            // Per-token faults should take precedence over global chaos
            let config = ChaosConfig::new(42)
                .with_io_error_probability(1.0)
                .with_io_error_kinds(vec![io::ErrorKind::TimedOut]);

            let reactor = LabReactor::with_chaos(config);
            let token1 = Token::new(1);
            let token2 = Token::new(2);
            let source = MockSource;

            reactor
                .register(&source, token1, Interest::READABLE)
                .unwrap();
            reactor
                .register(&source, token2, Interest::READABLE)
                .unwrap();

            // Partition token1 (per-token fault)
            reactor.partition(token1, true).unwrap();

            // Schedule events for both
            reactor.set_ready(token1, Event::readable(token1));
            reactor.set_ready(token2, Event::readable(token2));

            let mut events = crate::runtime::reactor::Events::with_capacity(10);
            reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();

            // token1 should be dropped (per-token partition)
            // token2 should be error (global chaos)
            crate::assert_with_log!(events.len() == 1, "one event", 1usize, events.len());

            let event = events.iter().next().expect("event");
            crate::assert_with_log!(
                event.token == token2,
                "token2 delivered",
                token2,
                event.token
            );
            crate::assert_with_log!(
                event.is_error(),
                "token2 has error (global chaos)",
                true,
                event.is_error()
            );

            crate::test_complete!("per_token_fault_with_global_chaos");
        }

        #[test]
        fn inject_close_unregistered_token_fails() {
            super::init_test("inject_close_unregistered_token_fails");

            let reactor = LabReactor::new();
            let token = Token::new(999);

            let result = reactor.inject_close(token);
            crate::assert_with_log!(result.is_err(), "unregistered fails", true, result.is_err());

            crate::test_complete!("inject_close_unregistered_token_fails");
        }

        #[test]
        fn partition_unregistered_token_fails() {
            super::init_test("partition_unregistered_token_fails");

            let reactor = LabReactor::new();
            let token = Token::new(999);

            let result = reactor.partition(token, true);
            crate::assert_with_log!(result.is_err(), "unregistered fails", true, result.is_err());

            crate::test_complete!("partition_unregistered_token_fails");
        }
    }
}
