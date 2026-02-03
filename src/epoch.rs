//! Epoch model types for time-bounded distributed operations.
//!
//! This module defines the core primitives for epoch-based coordination:
//! - `EpochId`: Unique identifier for an epoch
//! - `EpochConfig`: Configuration for epoch behavior
//! - `Epoch`: Full epoch state with metadata
//! - `EpochBarrier`: Synchronization primitive for epoch transitions
//! - `EpochClock`: Monotonic epoch progression
//! - `SymbolValidityWindow`: Epoch range for symbol validity

use crate::combinator::{
    Bulkhead, BulkheadError, CircuitBreaker, CircuitBreakerError, Either, Select,
};
use crate::error::{Error, ErrorKind};
use crate::observability::LogEntry;
use crate::time::TimeSource;
use crate::types::Time;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

// ============================================================================
// EpochId - Core Identifier
// ============================================================================

/// Unique identifier for an epoch in the distributed system.
///
/// Epochs are monotonically increasing identifiers that define logical time
/// boundaries. Within an epoch, operations have consistent semantics; across
/// epoch boundaries, behavior may change (e.g., configuration updates,
/// membership changes).
///
/// # Properties
///
/// - Epochs are totally ordered: `EpochId(a) < EpochId(b)` iff `a < b`
/// - Epochs are monotonic: once epoch N is reached, epoch N-1 will never recur
/// - Epoch 0 is the "genesis" epoch, used for initialization
///
/// # Example
///
/// ```ignore
/// let current = EpochId::GENESIS;
/// let next = current.next();
/// assert!(current.is_before(next));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpochId(pub u64);

impl EpochId {
    /// The genesis (initial) epoch.
    pub const GENESIS: Self = Self(0);

    /// Maximum epoch value.
    pub const MAX: Self = Self(u64::MAX);

    /// Creates a new epoch ID.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the next epoch.
    ///
    /// # Panics
    ///
    /// Panics if incrementing would overflow.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// Returns the next epoch, saturating at MAX.
    #[must_use]
    pub const fn saturating_next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Returns the previous epoch, if any.
    #[must_use]
    pub const fn prev(self) -> Option<Self> {
        if self.0 == 0 {
            None
        } else {
            Some(Self(self.0 - 1))
        }
    }

    /// Returns true if this epoch is before another.
    #[must_use]
    pub const fn is_before(self, other: Self) -> bool {
        self.0 < other.0
    }

    /// Returns true if this epoch is after another.
    #[must_use]
    pub const fn is_after(self, other: Self) -> bool {
        self.0 > other.0
    }

    /// Returns the difference between epochs.
    #[must_use]
    pub const fn distance(self, other: Self) -> u64 {
        self.0.abs_diff(other.0)
    }

    /// Returns the raw epoch value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for EpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Epoch({})", self.0)
    }
}

impl From<u64> for EpochId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<EpochId> for u64 {
    fn from(epoch: EpochId) -> Self {
        epoch.0
    }
}

// ============================================================================
// EpochConfig - Configuration
// ============================================================================

/// Configuration for epoch behavior.
#[derive(Debug, Clone)]
pub struct EpochConfig {
    /// Target duration for each epoch.
    pub target_duration: Time,

    /// Minimum duration before epoch transition is allowed.
    pub min_duration: Time,

    /// Maximum duration before forced epoch transition.
    pub max_duration: Time,

    /// Grace period after epoch end before resources are reclaimed.
    pub grace_period: Time,

    /// Number of epochs to retain for historical queries.
    pub retention_epochs: u32,

    /// Whether to require quorum for epoch transitions.
    pub require_quorum: bool,

    /// Quorum size for epoch transitions (if required).
    pub quorum_size: u32,
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            target_duration: Time::from_secs(60),
            min_duration: Time::from_secs(30),
            max_duration: Time::from_secs(120),
            grace_period: Time::from_secs(10),
            retention_epochs: 10,
            require_quorum: false,
            quorum_size: 0,
        }
    }
}

impl EpochConfig {
    /// Creates a config for short-lived epochs (testing).
    #[must_use]
    pub fn short_lived() -> Self {
        Self {
            target_duration: Time::from_millis(100),
            min_duration: Time::from_millis(50),
            max_duration: Time::from_millis(200),
            grace_period: Time::from_millis(20),
            retention_epochs: 5,
            require_quorum: false,
            quorum_size: 0,
        }
    }

    /// Creates a config for long-lived epochs (production).
    #[must_use]
    pub fn long_lived() -> Self {
        Self {
            target_duration: Time::from_secs(300),
            min_duration: Time::from_secs(120),
            max_duration: Time::from_secs(600),
            grace_period: Time::from_secs(30),
            retention_epochs: 20,
            require_quorum: true,
            quorum_size: 3,
        }
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), Box<Error>> {
        if self.min_duration > self.target_duration {
            return Err(Box::new(
                Error::new(ErrorKind::InvalidEncodingParams)
                    .with_message("min_duration must not exceed target_duration"),
            ));
        }
        if self.target_duration > self.max_duration {
            return Err(Box::new(
                Error::new(ErrorKind::InvalidEncodingParams)
                    .with_message("target_duration must not exceed max_duration"),
            ));
        }
        if self.require_quorum && self.quorum_size == 0 {
            return Err(Box::new(
                Error::new(ErrorKind::InvalidEncodingParams)
                    .with_message("quorum_size must be > 0 when require_quorum is true"),
            ));
        }
        Ok(())
    }
}

// ============================================================================
// Epoch - Full State
// ============================================================================

/// State of an epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochState {
    /// Epoch is being prepared (not yet active).
    Preparing,

    /// Epoch is currently active.
    Active,

    /// Epoch is ending (grace period).
    Ending,

    /// Epoch has ended.
    Ended,
}

impl EpochState {
    /// Returns true if the epoch is currently accepting operations.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns true if the epoch has terminated.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Ended)
    }

    /// Returns true if operations can still complete (active or ending).
    #[must_use]
    pub const fn allows_completion(self) -> bool {
        matches!(self, Self::Active | Self::Ending)
    }
}

/// Full epoch state with metadata.
#[derive(Debug, Clone)]
pub struct Epoch {
    /// Unique identifier.
    pub id: EpochId,

    /// Current state.
    pub state: EpochState,

    /// When this epoch started.
    pub started_at: Time,

    /// When this epoch is expected to end.
    pub expected_end: Time,

    /// When this epoch actually ended (if ended).
    pub ended_at: Option<Time>,

    /// Configuration for this epoch.
    pub config: EpochConfig,

    /// Number of operations executed in this epoch.
    pub operation_count: u64,

    /// Custom metadata.
    pub metadata: HashMap<String, String>,
}

impl Epoch {
    /// Creates a new epoch.
    #[must_use]
    pub fn new(id: EpochId, started_at: Time, config: EpochConfig) -> Self {
        let expected_end = Time::from_nanos(
            started_at
                .as_nanos()
                .saturating_add(config.target_duration.as_nanos()),
        );
        Self {
            id,
            state: EpochState::Active,
            started_at,
            expected_end,
            ended_at: None,
            config,
            operation_count: 0,
            metadata: HashMap::new(),
        }
    }

    /// Creates the genesis epoch.
    #[must_use]
    pub fn genesis(config: EpochConfig) -> Self {
        Self::new(EpochId::GENESIS, Time::ZERO, config)
    }

    /// Returns the duration of this epoch (or elapsed time if still active).
    #[must_use]
    pub fn duration(&self, now: Time) -> Duration {
        let end = self.ended_at.unwrap_or(now);
        Duration::from_nanos(end.as_nanos().saturating_sub(self.started_at.as_nanos()))
    }

    /// Returns true if the epoch has exceeded its maximum duration.
    #[must_use]
    pub fn is_overdue(&self, now: Time) -> bool {
        let max_end = Time::from_nanos(
            self.started_at
                .as_nanos()
                .saturating_add(self.config.max_duration.as_nanos()),
        );
        now > max_end
    }

    /// Returns true if the epoch can transition (met minimum duration).
    #[must_use]
    pub fn can_transition(&self, now: Time) -> bool {
        let min_end = Time::from_nanos(
            self.started_at
                .as_nanos()
                .saturating_add(self.config.min_duration.as_nanos()),
        );
        now >= min_end
    }

    /// Returns the time remaining until expected end.
    #[must_use]
    pub fn remaining(&self, now: Time) -> Option<Duration> {
        if now >= self.expected_end {
            None
        } else {
            Some(Duration::from_nanos(
                self.expected_end.as_nanos() - now.as_nanos(),
            ))
        }
    }

    /// Records an operation.
    pub fn record_operation(&mut self) {
        self.operation_count += 1;
    }

    /// Begins the ending phase (grace period).
    pub fn begin_ending(&mut self, _now: Time) -> Result<(), Box<Error>> {
        if self.state != EpochState::Active {
            return Err(Box::new(
                Error::new(ErrorKind::InvalidStateTransition)
                    .with_message(format!("Cannot end epoch in state {:?}", self.state)),
            ));
        }
        self.state = EpochState::Ending;
        Ok(())
    }

    /// Completes the epoch.
    pub fn complete(&mut self, now: Time) -> Result<(), Box<Error>> {
        if !matches!(self.state, EpochState::Active | EpochState::Ending) {
            return Err(Box::new(
                Error::new(ErrorKind::InvalidStateTransition)
                    .with_message(format!("Cannot complete epoch in state {:?}", self.state)),
            ));
        }
        self.state = EpochState::Ended;
        self.ended_at = Some(now);
        Ok(())
    }

    /// Adds metadata to the epoch.
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    // Logging integration
    fn log_created(&self) -> LogEntry {
        LogEntry::info("Epoch created")
            .with_field("epoch_id", format!("{}", self.id))
            .with_field("started_at", format!("{}", self.started_at))
            .with_field("expected_end", format!("{}", self.expected_end))
    }

    fn log_state_change(&self, old_state: EpochState) -> LogEntry {
        LogEntry::info("Epoch state changed")
            .with_field("epoch_id", format!("{}", self.id))
            .with_field("from_state", format!("{old_state:?}"))
            .with_field("to_state", format!("{:?}", self.state))
    }

    fn log_completed(&self) -> LogEntry {
        LogEntry::info("Epoch completed")
            .with_field("epoch_id", format!("{}", self.id))
            .with_field("operations", format!("{}", self.operation_count))
            .with_field("duration", format!("{:?}", self.ended_at))
    }
}

// ============================================================================
// SymbolValidityWindow - Symbol Epoch Ranges
// ============================================================================

/// Defines the epoch range during which a symbol is valid.
///
/// Symbols are bound to specific epoch windows. Outside this window,
/// operations involving the symbol should fail with epoch mismatch errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolValidityWindow {
    /// First epoch where the symbol is valid (inclusive).
    pub start: EpochId,

    /// Last epoch where the symbol is valid (inclusive).
    pub end: EpochId,
}

impl SymbolValidityWindow {
    /// Creates a new validity window.
    ///
    /// # Panics
    ///
    /// Panics if end is before start.
    #[must_use]
    pub fn new(start: EpochId, end: EpochId) -> Self {
        assert!(
            !end.is_before(start),
            "end epoch must not be before start epoch"
        );
        Self { start, end }
    }

    /// Creates a single-epoch validity window.
    #[must_use]
    pub fn single(epoch: EpochId) -> Self {
        Self {
            start: epoch,
            end: epoch,
        }
    }

    /// Creates an infinite validity window (all epochs).
    #[must_use]
    pub fn infinite() -> Self {
        Self {
            start: EpochId::GENESIS,
            end: EpochId::MAX,
        }
    }

    /// Creates a window from the given epoch onward.
    #[must_use]
    pub fn from_epoch(start: EpochId) -> Self {
        Self {
            start,
            end: EpochId::MAX,
        }
    }

    /// Creates a window up to and including the given epoch.
    #[must_use]
    pub fn until_epoch(end: EpochId) -> Self {
        Self {
            start: EpochId::GENESIS,
            end,
        }
    }

    /// Returns true if the given epoch is within this window.
    #[must_use]
    pub fn contains(&self, epoch: EpochId) -> bool {
        epoch >= self.start && epoch <= self.end
    }

    /// Returns true if this window overlaps with another.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Returns the intersection of two windows, if any.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Option<Self> {
        let start = std::cmp::max(self.start, other.start);
        let end = std::cmp::min(self.end, other.end);
        if start <= end {
            Some(Self { start, end })
        } else {
            None
        }
    }

    /// Returns the span of this window in epochs.
    ///
    /// Returns `u64::MAX` if the span would overflow (e.g., for infinite windows).
    #[must_use]
    pub fn span(&self) -> u64 {
        (self.end.0 - self.start.0).saturating_add(1)
    }

    /// Extends the window to include the given epoch.
    #[must_use]
    pub fn extend_to(&self, epoch: EpochId) -> Self {
        Self {
            start: std::cmp::min(self.start, epoch),
            end: std::cmp::max(self.end, epoch),
        }
    }
}

impl Default for SymbolValidityWindow {
    fn default() -> Self {
        Self::infinite()
    }
}

// ============================================================================
// EpochBarrier - Synchronization Primitive
// ============================================================================

/// Reason for a barrier to be triggered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BarrierTrigger {
    /// All participants arrived.
    AllArrived,

    /// Timeout was reached.
    Timeout,

    /// Barrier was cancelled.
    Cancelled,

    /// Epoch transition was forced.
    Forced,
}

/// Result of waiting at a barrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierResult {
    /// How the barrier was triggered.
    pub trigger: BarrierTrigger,

    /// Number of participants that arrived.
    pub arrived: u32,

    /// Total expected participants.
    pub expected: u32,

    /// Time when barrier was triggered.
    pub triggered_at: Time,
}

/// Synchronization primitive for coordinating epoch transitions.
///
/// An `EpochBarrier` allows multiple participants to synchronize at an epoch
/// boundary. All participants must arrive at the barrier before the epoch
/// can transition.
///
/// # Thread Safety
///
/// `EpochBarrier` is thread-safe and can be shared across tasks.
#[derive(Debug)]
pub struct EpochBarrier {
    /// The epoch this barrier is for.
    epoch: EpochId,

    /// Number of expected participants.
    expected: u32,

    /// Number of participants that have arrived.
    arrived: AtomicU64,

    /// Participant IDs that have arrived.
    participants: RwLock<Vec<String>>,

    /// Whether the barrier has been triggered.
    triggered: RwLock<Option<BarrierResult>>,

    /// Timeout for the barrier.
    timeout: Option<Time>,

    /// Creation time.
    created_at: Time,
}

impl EpochBarrier {
    /// Creates a new epoch barrier.
    #[must_use]
    pub fn new(epoch: EpochId, expected: u32, created_at: Time) -> Self {
        Self {
            epoch,
            expected,
            arrived: AtomicU64::new(0),
            participants: RwLock::new(Vec::with_capacity(expected as usize)),
            triggered: RwLock::new(None),
            timeout: None,
            created_at,
        }
    }

    /// Sets a timeout for the barrier.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Time) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Returns the epoch this barrier is for.
    #[must_use]
    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    /// Returns the number of expected participants.
    #[must_use]
    pub fn expected(&self) -> u32 {
        self.expected
    }

    /// Returns the number of arrived participants.
    #[must_use]
    pub fn arrived(&self) -> u32 {
        self.arrived.load(Ordering::SeqCst) as u32
    }

    /// Returns the number of participants still expected.
    #[must_use]
    pub fn remaining(&self) -> u32 {
        self.expected.saturating_sub(self.arrived())
    }

    /// Returns true if the barrier has been triggered.
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        self.triggered.read().expect("lock poisoned").is_some()
    }

    /// Returns the barrier result if triggered.
    #[must_use]
    pub fn result(&self) -> Option<BarrierResult> {
        self.triggered.read().expect("lock poisoned").clone()
    }

    /// Registers arrival at the barrier.
    ///
    /// Returns `Ok(Some(result))` if this arrival triggered the barrier,
    /// `Ok(None)` if still waiting for more arrivals.
    pub fn arrive(
        &self,
        participant_id: &str,
        now: Time,
    ) -> Result<Option<BarrierResult>, Box<Error>> {
        // Fast check if already triggered
        if self.is_triggered() {
            return Err(Box::new(
                Error::new(ErrorKind::InvalidStateTransition)
                    .with_message("Barrier already triggered"),
            ));
        }

        // Check for timeout
        if let Some(timeout) = self.timeout {
            let deadline = Time::from_nanos(
                self.created_at
                    .as_nanos()
                    .saturating_add(timeout.as_nanos()),
            );
            if now > deadline {
                let result = BarrierResult {
                    trigger: BarrierTrigger::Timeout,
                    arrived: self.arrived(),
                    expected: self.expected,
                    triggered_at: now,
                };
                let mut triggered = self.triggered.write().expect("lock poisoned");
                if triggered.is_some() {
                    return Err(Box::new(
                        Error::new(ErrorKind::InvalidStateTransition)
                            .with_message("Barrier already triggered"),
                    ));
                }
                *triggered = Some(result.clone());
                drop(triggered);
                return Ok(Some(result));
            }
        }

        // Record arrival
        {
            let mut participants = self.participants.write().expect("lock poisoned");
            if participants.contains(&participant_id.to_string()) {
                return Err(Box::new(
                    Error::new(ErrorKind::InvalidStateTransition)
                        .with_message("Participant already arrived"),
                ));
            }
            participants.push(participant_id.to_string());
        }

        let arrived = self.arrived.fetch_add(1, Ordering::SeqCst) + 1;

        // Check if all arrived
        if arrived >= u64::from(self.expected) {
            let result = BarrierResult {
                trigger: BarrierTrigger::AllArrived,
                arrived: arrived as u32,
                expected: self.expected,
                triggered_at: now,
            };
            let mut triggered = self.triggered.write().expect("lock poisoned");
            if triggered.is_some() {
                return Err(Box::new(
                    Error::new(ErrorKind::InvalidStateTransition)
                        .with_message("Barrier already triggered"),
                ));
            }
            *triggered = Some(result.clone());
            drop(triggered);
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Forces the barrier to trigger.
    pub fn force_trigger(&self, now: Time) -> BarrierResult {
        let result = BarrierResult {
            trigger: BarrierTrigger::Forced,
            arrived: self.arrived(),
            expected: self.expected,
            triggered_at: now,
        };
        *self.triggered.write().expect("lock poisoned") = Some(result.clone());
        result
    }

    /// Cancels the barrier.
    pub fn cancel(&self, now: Time) -> BarrierResult {
        let result = BarrierResult {
            trigger: BarrierTrigger::Cancelled,
            arrived: self.arrived(),
            expected: self.expected,
            triggered_at: now,
        };
        *self.triggered.write().expect("lock poisoned") = Some(result.clone());
        result
    }

    /// Returns the list of arrived participants.
    #[must_use]
    pub fn participants(&self) -> Vec<String> {
        self.participants.read().expect("lock poisoned").clone()
    }

    // Logging integration
    fn log_arrival(&self, participant: &str) -> LogEntry {
        LogEntry::debug("Epoch barrier arrival")
            .with_field("epoch_id", format!("{}", self.epoch))
            .with_field("participant", participant)
            .with_field("arrived", format!("{}", self.arrived()))
            .with_field("expected", format!("{}", self.expected))
    }

    fn log_triggered(&self, result: &BarrierResult) -> LogEntry {
        LogEntry::info("Epoch barrier triggered")
            .with_field("epoch_id", format!("{}", self.epoch))
            .with_field("trigger", format!("{:?}", result.trigger))
            .with_field("arrived", format!("{}", result.arrived))
            .with_field("expected", format!("{}", result.expected))
    }
}

// ============================================================================
// EpochClock - Monotonic Epoch Progression
// ============================================================================

/// A clock that tracks monotonic epoch progression.
///
/// The epoch clock maintains the current epoch and provides methods for
/// querying and advancing epochs.
#[derive(Debug)]
pub struct EpochClock {
    /// Current epoch.
    current: AtomicU64,

    /// Configuration.
    config: EpochConfig,

    /// Historical epochs.
    history: RwLock<Vec<Epoch>>,

    /// Current active epoch (if any).
    active_epoch: RwLock<Option<Epoch>>,
}

impl EpochClock {
    /// Creates a new epoch clock with the given configuration.
    #[must_use]
    pub fn new(config: EpochConfig) -> Self {
        Self {
            current: AtomicU64::new(0),
            config,
            history: RwLock::new(Vec::new()),
            active_epoch: RwLock::new(None),
        }
    }

    /// Initializes the clock with the genesis epoch.
    pub fn initialize(&self, started_at: Time) {
        let epoch = Epoch::new(EpochId::GENESIS, started_at, self.config.clone());
        *self.active_epoch.write().expect("lock poisoned") = Some(epoch);
    }

    /// Returns the current epoch ID.
    #[must_use]
    pub fn current(&self) -> EpochId {
        EpochId(self.current.load(Ordering::SeqCst))
    }

    /// Returns the current active epoch, if any.
    #[must_use]
    pub fn active_epoch(&self) -> Option<Epoch> {
        self.active_epoch.read().expect("lock poisoned").clone()
    }

    /// Advances to the next epoch.
    ///
    /// Returns the new epoch ID.
    pub fn advance(&self, now: Time) -> Result<EpochId, Box<Error>> {
        let mut active = self.active_epoch.write().expect("lock poisoned");

        // Complete current epoch if exists
        if let Some(ref mut epoch) = *active {
            if !epoch.can_transition(now) && !epoch.is_overdue(now) {
                return Err(Box::new(
                    Error::new(ErrorKind::InvalidStateTransition)
                        .with_message("Epoch has not met minimum duration"),
                ));
            }
            epoch.complete(now)?;

            // Move to history
            let mut history = self.history.write().expect("lock poisoned");
            history.push(epoch.clone());

            // Trim history if needed
            let retention = self.config.retention_epochs as usize;
            let len = history.len();
            if len > retention {
                history.drain(0..len - retention);
            }
        }

        // Advance to next epoch
        let prev = self.current.fetch_add(1, Ordering::SeqCst);
        let new_id = EpochId(prev.saturating_add(1));
        let new_epoch = Epoch::new(new_id, now, self.config.clone());
        *active = Some(new_epoch);
        drop(active); // Explicit drop to avoid significant drop warning

        Ok(new_id)
    }

    /// Returns epochs in the historical range.
    #[must_use]
    pub fn history(&self) -> Vec<Epoch> {
        self.history.read().expect("lock poisoned").clone()
    }

    /// Returns a specific historical epoch by ID.
    #[must_use]
    pub fn get_epoch(&self, id: EpochId) -> Option<Epoch> {
        // Check active epoch first
        if let Some(ref active) = *self.active_epoch.read().expect("lock poisoned") {
            if active.id == id {
                return Some(active.clone());
            }
        }

        // Check history
        self.history
            .read()
            .expect("lock poisoned")
            .iter()
            .find(|e| e.id == id)
            .cloned()
    }

    // Logging integration
    #[allow(clippy::unused_self)]
    fn log_advance(&self, from: EpochId, to: EpochId) -> LogEntry {
        LogEntry::info("Epoch advanced")
            .with_field("from_epoch", format!("{from}"))
            .with_field("to_epoch", format!("{to}"))
    }
}

// ============================================================================
// Epoch Context + Policy (Combinator Integration)
// ============================================================================

/// Source of the current epoch for transition detection.
pub trait EpochSource: Send + Sync {
    /// Returns the current epoch ID.
    fn current(&self) -> EpochId;
}

impl EpochSource for EpochClock {
    fn current(&self) -> EpochId {
        self.current()
    }
}

impl EpochSource for EpochId {
    fn current(&self) -> EpochId {
        *self
    }
}

/// Context for epoch-scoped operations.
#[derive(Debug, Clone)]
pub struct EpochContext {
    /// Current epoch ID.
    pub epoch_id: EpochId,
    /// Epoch start time.
    pub started_at: Time,
    /// Epoch deadline (when this epoch ends).
    pub deadline: Time,
    /// Maximum operations allowed in this epoch.
    pub operation_budget: Option<u32>,
    operations_used: Arc<AtomicU32>,
}

impl EpochContext {
    /// Creates a new epoch context.
    #[must_use]
    pub fn new(epoch_id: EpochId, started_at: Time, deadline: Time) -> Self {
        Self {
            epoch_id,
            started_at,
            deadline,
            operation_budget: None,
            operations_used: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Sets an operation budget for this epoch.
    #[must_use]
    pub fn with_operation_budget(mut self, budget: u32) -> Self {
        self.operation_budget = Some(budget);
        self
    }

    /// Returns true if the epoch has expired at the given time.
    #[must_use]
    pub fn is_expired(&self, now: Time) -> bool {
        now >= self.deadline
    }

    /// Returns true if the operation budget is exhausted.
    #[must_use]
    pub fn is_budget_exhausted(&self) -> bool {
        self.operation_budget
            .is_some_and(|limit| self.operations_used.load(Ordering::Acquire) >= limit)
    }

    /// Attempts to record an operation.
    ///
    /// Returns false if the operation budget is exhausted.
    #[must_use]
    pub fn record_operation(&self) -> bool {
        if let Some(limit) = self.operation_budget {
            let mut current = self.operations_used.load(Ordering::Acquire);
            loop {
                if current >= limit {
                    return false;
                }
                match self.operations_used.compare_exchange(
                    current,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return true,
                    Err(actual) => current = actual,
                }
            }
        } else {
            self.operations_used.fetch_add(1, Ordering::AcqRel);
            true
        }
    }

    /// Returns the number of operations recorded.
    #[must_use]
    pub fn operations_used(&self) -> u32 {
        self.operations_used.load(Ordering::Acquire)
    }

    /// Returns remaining time in this epoch.
    #[must_use]
    pub fn remaining_time(&self, now: Time) -> Option<Duration> {
        if now >= self.deadline {
            None
        } else {
            Some(Duration::from_nanos(
                self.deadline.as_nanos() - now.as_nanos(),
            ))
        }
    }

    fn log_created(&self) -> LogEntry {
        LogEntry::debug("Epoch context created")
            .with_field("epoch_id", format!("{}", self.epoch_id))
            .with_field("deadline_ms", format!("{}", self.deadline.as_millis()))
            .with_field("operation_budget", format!("{:?}", self.operation_budget))
    }

    fn log_expired(&self, now: Time) -> LogEntry {
        LogEntry::warn("Epoch expired")
            .with_field("epoch_id", format!("{}", self.epoch_id))
            .with_field("deadline_ms", format!("{}", self.deadline.as_millis()))
            .with_field("current_time_ms", format!("{}", now.as_millis()))
    }

    fn log_budget_exhausted(&self) -> LogEntry {
        LogEntry::info("Epoch operation budget exhausted")
            .with_field("epoch_id", format!("{}", self.epoch_id))
            .with_field("operations_used", format!("{}", self.operations_used()))
    }
}

/// Behavior when an epoch transition occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EpochTransitionBehavior {
    /// Abort all pending operations immediately.
    #[default]
    AbortAll,
    /// Allow currently-executing operations to complete.
    DrainExecuting,
    /// Fail fast with an error.
    Fail,
    /// Ignore epoch transitions (epoch-agnostic operations).
    Ignore,
}

/// Policy for epoch-aware combinators.
#[derive(Debug, Clone)]
pub struct EpochPolicy {
    /// Behavior when epoch transitions during operation.
    pub on_transition: EpochTransitionBehavior,
    /// Whether to check epoch on each poll.
    pub check_on_poll: bool,
    /// Whether to propagate epoch context to child futures.
    pub propagate_to_children: bool,
    /// Grace period after epoch deadline before hard abort.
    pub grace_period: Option<Time>,
}

impl Default for EpochPolicy {
    fn default() -> Self {
        Self {
            on_transition: EpochTransitionBehavior::AbortAll,
            check_on_poll: true,
            propagate_to_children: true,
            grace_period: None,
        }
    }
}

impl EpochPolicy {
    /// Creates a strict policy that aborts immediately on epoch transition.
    #[must_use]
    pub fn strict() -> Self {
        Self::default()
    }

    /// Creates a lenient policy that drains executing operations.
    #[must_use]
    pub fn lenient() -> Self {
        Self {
            on_transition: EpochTransitionBehavior::DrainExecuting,
            check_on_poll: false,
            propagate_to_children: true,
            grace_period: Some(Time::from_millis(100)),
        }
    }

    /// Creates an ignore policy for epoch-agnostic operations.
    #[must_use]
    pub fn ignore() -> Self {
        Self {
            on_transition: EpochTransitionBehavior::Ignore,
            check_on_poll: false,
            propagate_to_children: false,
            grace_period: None,
        }
    }
}

/// Wrapper that makes any future epoch-aware.
pub struct EpochScoped<F, TS: TimeSource, ES: EpochSource> {
    inner: F,
    epoch_ctx: EpochContext,
    policy: EpochPolicy,
    time_source: Arc<TS>,
    epoch_source: Arc<ES>,
    started: bool,
}

impl<F, TS: TimeSource, ES: EpochSource> EpochScoped<F, TS, ES> {
    /// Wraps a future with epoch awareness.
    #[must_use]
    pub fn new(
        inner: F,
        epoch_ctx: EpochContext,
        policy: EpochPolicy,
        time_source: Arc<TS>,
        epoch_source: Arc<ES>,
    ) -> Self {
        Self {
            inner,
            epoch_ctx,
            policy,
            time_source,
            epoch_source,
            started: false,
        }
    }

    /// Returns the current epoch context.
    #[must_use]
    pub fn epoch_context(&self) -> &EpochContext {
        &self.epoch_ctx
    }

    /// Returns the epoch policy.
    #[must_use]
    pub fn policy(&self) -> &EpochPolicy {
        &self.policy
    }
}

fn effective_deadline(deadline: Time, grace: Option<Time>) -> Time {
    grace.map_or(deadline, |grace| {
        Time::from_nanos(deadline.as_nanos().saturating_add(grace.as_nanos()))
    })
}

fn check_epoch<TS: TimeSource, ES: EpochSource>(
    epoch_ctx: &EpochContext,
    policy: &EpochPolicy,
    time_source: &TS,
    epoch_source: &ES,
    started: bool,
) -> Result<(), EpochError> {
    let now = time_source.now();
    if now >= effective_deadline(epoch_ctx.deadline, policy.grace_period) {
        return Err(EpochError::Expired {
            epoch: epoch_ctx.epoch_id,
        });
    }

    if !policy.check_on_poll && started {
        return Ok(());
    }

    let current = epoch_source.current();
    if current == epoch_ctx.epoch_id {
        Ok(())
    } else {
        match policy.on_transition {
            EpochTransitionBehavior::Ignore => Ok(()),
            EpochTransitionBehavior::DrainExecuting => {
                if started {
                    Ok(())
                } else {
                    Err(EpochError::TransitionOccurred {
                        from: epoch_ctx.epoch_id,
                        to: current,
                    })
                }
            }
            EpochTransitionBehavior::Fail | EpochTransitionBehavior::AbortAll => {
                Err(EpochError::TransitionOccurred {
                    from: epoch_ctx.epoch_id,
                    to: current,
                })
            }
        }
    }
}

impl<F, TS, ES> Future for EpochScoped<F, TS, ES>
where
    F: Future + Unpin,
    TS: TimeSource,
    ES: EpochSource,
{
    type Output = Result<F::Output, EpochError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.started {
            if let Err(err) = check_epoch(
                &self.epoch_ctx,
                &self.policy,
                self.time_source.as_ref(),
                self.epoch_source.as_ref(),
                false,
            ) {
                return Poll::Ready(Err(err));
            }

            self.started = true;
            if !self.epoch_ctx.record_operation() {
                let budget = self.epoch_ctx.operation_budget.unwrap_or(0);
                return Poll::Ready(Err(EpochError::BudgetExhausted {
                    epoch: self.epoch_ctx.epoch_id,
                    budget,
                    used: self.epoch_ctx.operations_used(),
                }));
            }
        }

        if let Err(err) = check_epoch(
            &self.epoch_ctx,
            &self.policy,
            self.time_source.as_ref(),
            self.epoch_source.as_ref(),
            true,
        ) {
            return Poll::Ready(Err(err));
        }

        Pin::new(&mut self.inner).poll(cx).map(Ok)
    }
}

/// Future for epoch-aware select.
///
/// Note: the losing future is dropped (not drained) when the winner
/// resolves. This is safe because `EpochScoped` wrappers do not hold
/// obligations. If the inner futures hold obligations, callers should
/// use [`Scope::race`](crate::cx::Scope::race) instead.
pub struct EpochSelect<A, B, TS: TimeSource, ES: EpochSource> {
    inner: Select<EpochScoped<A, TS, ES>, EpochScoped<B, TS, ES>>,
}

impl<A, B, TS: TimeSource, ES: EpochSource> EpochSelect<A, B, TS, ES> {
    /// Creates a new epoch-aware select combinator.
    #[must_use]
    pub fn new(
        a: A,
        b: B,
        epoch_ctx: EpochContext,
        policy: EpochPolicy,
        time_source: Arc<TS>,
        epoch_source: Arc<ES>,
    ) -> Self {
        let scoped_a = EpochScoped::new(
            a,
            epoch_ctx.clone(),
            policy.clone(),
            Arc::clone(&time_source),
            Arc::clone(&epoch_source),
        );
        let scoped_b = EpochScoped::new(b, epoch_ctx, policy, time_source, epoch_source);
        Self {
            inner: Select::new(scoped_a, scoped_b),
        }
    }
}

impl<A, B, TS, ES> Future for EpochSelect<A, B, TS, ES>
where
    A: Future + Unpin,
    B: Future + Unpin,
    TS: TimeSource,
    ES: EpochSource,
{
    type Output = Either<Result<A::Output, EpochError>, Result<B::Output, EpochError>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

/// Future for epoch-aware join of two operations.
pub struct EpochJoin2<A, B, TS: TimeSource, ES: EpochSource>
where
    A: Future + Unpin,
    B: Future + Unpin,
{
    a: EpochScoped<A, TS, ES>,
    b: EpochScoped<B, TS, ES>,
    a_done: Option<Result<A::Output, EpochError>>,
    b_done: Option<Result<B::Output, EpochError>>,
}

impl<A, B, TS, ES> Unpin for EpochJoin2<A, B, TS, ES>
where
    A: Future + Unpin,
    B: Future + Unpin,
    TS: TimeSource,
    ES: EpochSource,
{
}

impl<A, B, TS, ES> EpochJoin2<A, B, TS, ES>
where
    A: Future + Unpin,
    B: Future + Unpin,
    TS: TimeSource,
    ES: EpochSource,
{
    /// Creates a new epoch-aware join combinator.
    #[must_use]
    pub fn new(
        a: A,
        b: B,
        epoch_ctx: EpochContext,
        policy: EpochPolicy,
        time_source: Arc<TS>,
        epoch_source: Arc<ES>,
    ) -> Self {
        Self {
            a: EpochScoped::new(
                a,
                epoch_ctx.clone(),
                policy.clone(),
                Arc::clone(&time_source),
                Arc::clone(&epoch_source),
            ),
            b: EpochScoped::new(b, epoch_ctx, policy, time_source, epoch_source),
            a_done: None,
            b_done: None,
        }
    }
}

impl<A, B, TS, ES> Future for EpochJoin2<A, B, TS, ES>
where
    A: Future + Unpin,
    B: Future + Unpin,
    TS: TimeSource,
    ES: EpochSource,
{
    type Output = (Result<A::Output, EpochError>, Result<B::Output, EpochError>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = Pin::get_mut(self);

        if this.a_done.is_none() {
            if let Poll::Ready(val) = Pin::new(&mut this.a).poll(cx) {
                this.a_done = Some(val);
            }
        }

        if this.b_done.is_none() {
            if let Poll::Ready(val) = Pin::new(&mut this.b).poll(cx) {
                this.b_done = Some(val);
            }
        }

        match (&this.a_done, &this.b_done) {
            (Some(_), Some(_)) => Poll::Ready((
                this.a_done.take().expect("a_done missing"),
                this.b_done.take().expect("b_done missing"),
            )),
            _ => Poll::Pending,
        }
    }
}

/// Future for epoch-aware race of two operations.
pub struct EpochRace2<A, B, TS: TimeSource, ES: EpochSource> {
    a: EpochScoped<A, TS, ES>,
    b: EpochScoped<B, TS, ES>,
}

impl<A, B, TS: TimeSource, ES: EpochSource> EpochRace2<A, B, TS, ES> {
    /// Creates a new epoch-aware race combinator.
    #[must_use]
    pub fn new(
        a: A,
        b: B,
        epoch_ctx: EpochContext,
        policy: EpochPolicy,
        time_source: Arc<TS>,
        epoch_source: Arc<ES>,
    ) -> Self {
        Self {
            a: EpochScoped::new(
                a,
                epoch_ctx.clone(),
                policy.clone(),
                Arc::clone(&time_source),
                Arc::clone(&epoch_source),
            ),
            b: EpochScoped::new(b, epoch_ctx, policy, time_source, epoch_source),
        }
    }
}

impl<A, B, TS, ES> Future for EpochRace2<A, B, TS, ES>
where
    A: Future + Unpin,
    B: Future + Unpin,
    TS: TimeSource,
    ES: EpochSource,
{
    type Output = Either<Result<A::Output, EpochError>, Result<B::Output, EpochError>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Poll::Ready(val) = Pin::new(&mut self.a).poll(cx) {
            return Poll::Ready(Either::Left(val));
        }
        if let Poll::Ready(val) = Pin::new(&mut self.b).poll(cx) {
            return Poll::Ready(Either::Right(val));
        }
        Poll::Pending
    }
}

/// Helper to create an epoch-aware select combinator.
#[must_use]
pub fn epoch_select<A, B, TS, ES>(
    a: A,
    b: B,
    epoch_ctx: EpochContext,
    policy: EpochPolicy,
    time_source: Arc<TS>,
    epoch_source: Arc<ES>,
) -> EpochSelect<A, B, TS, ES>
where
    A: Future + Unpin,
    B: Future + Unpin,
    TS: TimeSource,
    ES: EpochSource,
{
    EpochSelect::new(a, b, epoch_ctx, policy, time_source, epoch_source)
}

/// Helper to create an epoch-aware join combinator.
#[must_use]
pub fn epoch_join2<A, B, TS, ES>(
    a: A,
    b: B,
    epoch_ctx: EpochContext,
    policy: EpochPolicy,
    time_source: Arc<TS>,
    epoch_source: Arc<ES>,
) -> EpochJoin2<A, B, TS, ES>
where
    A: Future + Unpin,
    B: Future + Unpin,
    TS: TimeSource,
    ES: EpochSource,
{
    EpochJoin2::new(a, b, epoch_ctx, policy, time_source, epoch_source)
}

/// Helper to create an epoch-aware race combinator.
#[must_use]
pub fn epoch_race2<A, B, TS, ES>(
    a: A,
    b: B,
    epoch_ctx: EpochContext,
    policy: EpochPolicy,
    time_source: Arc<TS>,
    epoch_source: Arc<ES>,
) -> EpochRace2<A, B, TS, ES>
where
    A: Future + Unpin,
    B: Future + Unpin,
    TS: TimeSource,
    ES: EpochSource,
{
    EpochRace2::new(a, b, epoch_ctx, policy, time_source, epoch_source)
}

/// Errors from epoch-aware bulkhead operations.
#[derive(Debug, Clone)]
pub enum EpochBulkheadError<E> {
    /// Epoch constraint violation.
    Epoch(EpochError),
    /// Bulkhead-specific error.
    Bulkhead(BulkheadError<E>),
}

impl<E: fmt::Display> fmt::Display for EpochBulkheadError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Epoch(e) => write!(f, "{e}"),
            Self::Bulkhead(e) => write!(f, "{e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for EpochBulkheadError<E> {}

/// Errors from epoch-aware circuit breaker operations.
#[derive(Debug, Clone)]
pub enum EpochCircuitBreakerError<E> {
    /// Epoch constraint violation.
    Epoch(EpochError),
    /// Circuit breaker error.
    CircuitBreaker(CircuitBreakerError<E>),
}

impl<E: fmt::Display> fmt::Display for EpochCircuitBreakerError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Epoch(e) => write!(f, "{e}"),
            Self::CircuitBreaker(e) => write!(f, "{e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for EpochCircuitBreakerError<E> {}

fn ensure_epoch_ready<TS: TimeSource, ES: EpochSource>(
    epoch_ctx: &EpochContext,
    policy: &EpochPolicy,
    time_source: &TS,
    epoch_source: &ES,
) -> Result<(), EpochError> {
    check_epoch(epoch_ctx, policy, time_source, epoch_source, false)
}

/// Execute a bulkhead operation with epoch checks.
pub fn bulkhead_call_in_epoch<T, E, F, TS, ES>(
    bulkhead: &Bulkhead,
    epoch_ctx: &EpochContext,
    policy: &EpochPolicy,
    time_source: &TS,
    epoch_source: &ES,
    op: F,
) -> Result<T, EpochBulkheadError<E>>
where
    F: FnOnce() -> Result<T, E>,
    E: fmt::Display,
    TS: TimeSource,
    ES: EpochSource,
{
    ensure_epoch_ready(epoch_ctx, policy, time_source, epoch_source)
        .map_err(EpochBulkheadError::Epoch)?;
    bulkhead.call(op).map_err(EpochBulkheadError::Bulkhead)
}

/// Execute a weighted bulkhead operation with epoch checks.
pub fn bulkhead_call_weighted_in_epoch<T, E, F, TS, ES>(
    bulkhead: &Bulkhead,
    weight: u32,
    epoch_ctx: &EpochContext,
    policy: &EpochPolicy,
    time_source: &TS,
    epoch_source: &ES,
    op: F,
) -> Result<T, EpochBulkheadError<E>>
where
    F: FnOnce() -> Result<T, E>,
    E: fmt::Display,
    TS: TimeSource,
    ES: EpochSource,
{
    ensure_epoch_ready(epoch_ctx, policy, time_source, epoch_source)
        .map_err(EpochBulkheadError::Epoch)?;
    bulkhead
        .call_weighted(weight, op)
        .map_err(EpochBulkheadError::Bulkhead)
}

/// Execute a circuit breaker call with epoch checks.
pub fn circuit_breaker_call_in_epoch<T, E, F, TS, ES>(
    breaker: &CircuitBreaker,
    epoch_ctx: &EpochContext,
    policy: &EpochPolicy,
    time_source: &TS,
    epoch_source: &ES,
    op: F,
) -> Result<T, EpochCircuitBreakerError<E>>
where
    F: FnOnce() -> Result<T, E>,
    E: fmt::Display,
    TS: TimeSource,
    ES: EpochSource,
{
    ensure_epoch_ready(epoch_ctx, policy, time_source, epoch_source)
        .map_err(EpochCircuitBreakerError::Epoch)?;
    let now = time_source.now();
    breaker
        .call(now, op)
        .map_err(EpochCircuitBreakerError::CircuitBreaker)
}

fn log_epoch_transition(from: EpochId, to: EpochId, behavior: EpochTransitionBehavior) -> LogEntry {
    LogEntry::info("Epoch transition")
        .with_field("from_epoch", format!("{from}"))
        .with_field("to_epoch", format!("{to}"))
        .with_field("behavior", format!("{behavior:?}"))
}

// ============================================================================
// Epoch Errors
// ============================================================================

/// Error types for epoch operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochError {
    /// Epoch has expired.
    Expired {
        /// The expired epoch.
        epoch: EpochId,
    },
    /// Epoch operation budget exhausted.
    BudgetExhausted {
        /// The epoch that exceeded its budget.
        epoch: EpochId,
        /// The configured operation budget.
        budget: u32,
        /// Operations used so far.
        used: u32,
    },

    /// Epoch transition occurred during operation.
    TransitionOccurred {
        /// The epoch when the operation started.
        from: EpochId,
        /// The epoch when the operation ended.
        to: EpochId,
    },

    /// Epoch mismatch.
    Mismatch {
        /// The expected epoch.
        expected: EpochId,
        /// The actual epoch.
        actual: EpochId,
    },

    /// Symbol validity window violation.
    ValidityViolation {
        /// The epoch of the symbol.
        symbol_epoch: EpochId,
        /// The validity window.
        window: SymbolValidityWindow,
    },

    /// Barrier timeout.
    BarrierTimeout {
        /// The epoch of the barrier.
        epoch: EpochId,
        /// Number of participants arrived.
        arrived: u32,
        /// Number of expected participants.
        expected: u32,
    },
}

impl std::fmt::Display for EpochError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired { epoch } => write!(f, "epoch {epoch} expired"),
            Self::BudgetExhausted {
                epoch,
                budget,
                used,
            } => write!(f, "epoch {epoch} budget exhausted: used {used}/{budget}"),
            Self::TransitionOccurred { from, to } => {
                write!(f, "epoch transition from {from} to {to}")
            }
            Self::Mismatch { expected, actual } => {
                write!(f, "epoch mismatch: expected {expected}, got {actual}")
            }
            Self::ValidityViolation {
                symbol_epoch,
                window,
            } => {
                write!(
                    f,
                    "symbol epoch {symbol_epoch} outside validity window [{}, {}]",
                    window.start, window.end
                )
            }
            Self::BarrierTimeout {
                epoch,
                arrived,
                expected,
            } => {
                write!(
                    f,
                    "barrier timeout for epoch {epoch}: {arrived}/{expected} arrived"
                )
            }
        }
    }
}

impl std::error::Error for EpochError {}

impl From<EpochError> for Error {
    fn from(e: EpochError) -> Self {
        match e {
            EpochError::Expired { .. } => {
                Self::new(ErrorKind::LeaseExpired).with_message(e.to_string())
            }
            EpochError::BudgetExhausted { .. } => {
                Self::new(ErrorKind::PollQuotaExhausted).with_message(e.to_string())
            }
            EpochError::TransitionOccurred { .. } => {
                Self::new(ErrorKind::Cancelled).with_message(e.to_string())
            }
            EpochError::Mismatch { .. } => {
                Self::new(ErrorKind::InvalidStateTransition).with_message(e.to_string())
            }
            EpochError::ValidityViolation { .. } => {
                Self::new(ErrorKind::ObjectMismatch).with_message(e.to_string())
            }
            EpochError::BarrierTimeout { .. } => {
                Self::new(ErrorKind::ThresholdTimeout).with_message(e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::combinator::{BulkheadPolicy, CircuitBreakerPolicy};
    use crate::time::VirtualClock;
    use futures_lite::future::block_on;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[derive(Debug)]
    struct TestEpochSource {
        current: AtomicU64,
    }

    impl TestEpochSource {
        fn new(epoch: EpochId) -> Self {
            Self {
                current: AtomicU64::new(epoch.as_u64()),
            }
        }

        fn set(&self, epoch: EpochId) {
            self.current.store(epoch.as_u64(), Ordering::Release);
        }
    }

    impl EpochSource for TestEpochSource {
        fn current(&self) -> EpochId {
            EpochId(self.current.load(Ordering::Acquire))
        }
    }

    // Test 1: EpochId ordering and arithmetic
    #[test]
    fn test_epoch_id_ordering() {
        init_test("test_epoch_id_ordering");
        let e1 = EpochId(5);
        let e2 = EpochId(10);

        let before = e1.is_before(e2);
        crate::assert_with_log!(before, "e1 before e2", true, before);
        let after = e2.is_after(e1);
        crate::assert_with_log!(after, "e2 after e1", true, after);
        let same_before = e1.is_before(e1);
        crate::assert_with_log!(!same_before, "e1 before e1", false, same_before);
        let dist12 = e1.distance(e2);
        crate::assert_with_log!(dist12 == 5, "distance 1->2", 5, dist12);
        let dist21 = e2.distance(e1);
        crate::assert_with_log!(dist21 == 5, "distance 2->1", 5, dist21);
        crate::test_complete!("test_epoch_id_ordering");
    }

    // Test 2: EpochId next/prev
    #[test]
    fn test_epoch_id_navigation() {
        init_test("test_epoch_id_navigation");
        let e = EpochId(5);

        crate::assert_with_log!(e.next() == EpochId(6), "next", EpochId(6), e.next());
        crate::assert_with_log!(
            e.prev() == Some(EpochId(4)),
            "prev",
            Some(EpochId(4)),
            e.prev()
        );
        let genesis_prev_none = EpochId::GENESIS.prev().is_none();
        crate::assert_with_log!(
            genesis_prev_none,
            "genesis prev none",
            true,
            genesis_prev_none
        );
        crate::assert_with_log!(
            EpochId::MAX.saturating_next() == EpochId::MAX,
            "max saturating_next",
            EpochId::MAX,
            EpochId::MAX.saturating_next()
        );
        crate::test_complete!("test_epoch_id_navigation");
    }

    // Test 3: EpochConfig validation
    #[test]
    fn test_epoch_config_validation() {
        init_test("test_epoch_config_validation");
        let valid = EpochConfig::default();
        let valid_ok = valid.validate().is_ok();
        crate::assert_with_log!(valid_ok, "valid ok", true, valid_ok);

        let invalid_min = EpochConfig {
            min_duration: Time::from_secs(100),
            target_duration: Time::from_secs(60),
            ..EpochConfig::default()
        };
        let invalid_min_err = invalid_min.validate().is_err();
        crate::assert_with_log!(invalid_min_err, "invalid min err", true, invalid_min_err);

        let invalid_quorum = EpochConfig {
            require_quorum: true,
            quorum_size: 0,
            ..EpochConfig::default()
        };
        let invalid_quorum_err = invalid_quorum.validate().is_err();
        crate::assert_with_log!(
            invalid_quorum_err,
            "invalid quorum err",
            true,
            invalid_quorum_err
        );
        crate::test_complete!("test_epoch_config_validation");
    }

    // Test 4: Epoch lifecycle
    #[test]
    fn test_epoch_lifecycle() {
        init_test("test_epoch_lifecycle");
        let config = EpochConfig::default();
        let mut epoch = Epoch::new(EpochId(1), Time::from_millis(0), config);

        crate::assert_with_log!(
            epoch.state == EpochState::Active,
            "state active",
            EpochState::Active,
            epoch.state
        );
        let active = epoch.state.is_active();
        crate::assert_with_log!(active, "is_active", true, active);

        epoch.begin_ending(Time::from_secs(60)).unwrap();
        crate::assert_with_log!(
            epoch.state == EpochState::Ending,
            "state ending",
            EpochState::Ending,
            epoch.state
        );
        let allows = epoch.state.allows_completion();
        crate::assert_with_log!(allows, "allows completion", true, allows);

        epoch.complete(Time::from_secs(70)).unwrap();
        crate::assert_with_log!(
            epoch.state == EpochState::Ended,
            "state ended",
            EpochState::Ended,
            epoch.state
        );
        let terminal = epoch.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        crate::test_complete!("test_epoch_lifecycle");
    }

    // Test 5: Epoch transition timing
    #[test]
    fn test_epoch_transition_timing() {
        init_test("test_epoch_transition_timing");
        let config = EpochConfig {
            min_duration: Time::from_secs(30),
            target_duration: Time::from_secs(60),
            max_duration: Time::from_secs(120),
            ..EpochConfig::default()
        };
        let epoch = Epoch::new(EpochId(1), Time::from_secs(0), config);

        // Before min duration
        let can = epoch.can_transition(Time::from_secs(20));
        crate::assert_with_log!(!can, "before min", false, can);

        // After min duration
        let can = epoch.can_transition(Time::from_secs(40));
        crate::assert_with_log!(can, "after min", true, can);

        // Not overdue yet
        let overdue = epoch.is_overdue(Time::from_secs(100));
        crate::assert_with_log!(!overdue, "not overdue", false, overdue);

        // Overdue
        let overdue = epoch.is_overdue(Time::from_secs(130));
        crate::assert_with_log!(overdue, "overdue", true, overdue);
        crate::test_complete!("test_epoch_transition_timing");
    }

    // Test 6: SymbolValidityWindow contains
    #[test]
    fn test_validity_window_contains() {
        init_test("test_validity_window_contains");
        let window = SymbolValidityWindow::new(EpochId(4), EpochId(10));

        let contains4 = window.contains(EpochId(4));
        crate::assert_with_log!(contains4, "contains 4", true, contains4);
        let contains5 = window.contains(EpochId(5));
        crate::assert_with_log!(contains5, "contains 5", true, contains5);
        let contains7 = window.contains(EpochId(7));
        crate::assert_with_log!(contains7, "contains 7", true, contains7);
        let contains10 = window.contains(EpochId(10));
        crate::assert_with_log!(contains10, "contains 10", true, contains10);
        let contains11 = window.contains(EpochId(11));
        crate::assert_with_log!(!contains11, "contains 11", false, contains11);
        crate::test_complete!("test_validity_window_contains");
    }

    // Test 7: SymbolValidityWindow overlap
    #[test]
    fn test_validity_window_overlap() {
        init_test("test_validity_window_overlap");
        let w1 = SymbolValidityWindow::new(EpochId(1), EpochId(5));
        let w2 = SymbolValidityWindow::new(EpochId(4), EpochId(8));
        let w3 = SymbolValidityWindow::new(EpochId(6), EpochId(10));

        let w1_w2 = w1.overlaps(&w2);
        crate::assert_with_log!(w1_w2, "w1 overlaps w2", true, w1_w2);
        let w2_w1 = w2.overlaps(&w1);
        crate::assert_with_log!(w2_w1, "w2 overlaps w1", true, w2_w1);
        let w1_w3 = w1.overlaps(&w3);
        crate::assert_with_log!(!w1_w3, "w1 overlaps w3", false, w1_w3);

        let intersection = w1.intersection(&w2);
        crate::assert_with_log!(
            intersection == Some(SymbolValidityWindow::new(EpochId(4), EpochId(5))),
            "intersection",
            Some(SymbolValidityWindow::new(EpochId(4), EpochId(5))),
            intersection
        );
        crate::test_complete!("test_validity_window_overlap");
    }

    // Test 8: SymbolValidityWindow special constructors
    #[test]
    fn test_validity_window_constructors() {
        init_test("test_validity_window_constructors");
        let single = SymbolValidityWindow::single(EpochId(5));
        let span = single.span();
        crate::assert_with_log!(span == 1, "single span", 1, span);
        let contains5 = single.contains(EpochId(5));
        crate::assert_with_log!(contains5, "contains 5", true, contains5);
        let contains4 = single.contains(EpochId(4));
        crate::assert_with_log!(!contains4, "contains 4", false, contains4);

        let infinite = SymbolValidityWindow::infinite();
        let contains_genesis = infinite.contains(EpochId::GENESIS);
        crate::assert_with_log!(contains_genesis, "contains genesis", true, contains_genesis);
        let contains_max = infinite.contains(EpochId::MAX);
        crate::assert_with_log!(contains_max, "contains max", true, contains_max);

        let from = SymbolValidityWindow::from_epoch(EpochId(5));
        let contains4 = from.contains(EpochId(4));
        crate::assert_with_log!(!contains4, "from contains 4", false, contains4);
        let contains5 = from.contains(EpochId(5));
        crate::assert_with_log!(contains5, "from contains 5", true, contains5);
        let contains_max = from.contains(EpochId::MAX);
        crate::assert_with_log!(contains_max, "from contains max", true, contains_max);
        crate::test_complete!("test_validity_window_constructors");
    }

    // Test 9: EpochBarrier basic operation
    #[test]
    fn test_epoch_barrier_basic() {
        init_test("test_epoch_barrier_basic");
        let barrier = EpochBarrier::new(EpochId(1), 3, Time::ZERO);

        let remaining = barrier.remaining();
        crate::assert_with_log!(remaining == 3, "remaining", 3, remaining);
        let triggered = barrier.is_triggered();
        crate::assert_with_log!(!triggered, "triggered", false, triggered);

        barrier.arrive("node1", Time::from_secs(1)).unwrap();
        let arrived = barrier.arrived();
        crate::assert_with_log!(arrived == 1, "arrived", 1, arrived);
        let remaining = barrier.remaining();
        crate::assert_with_log!(remaining == 2, "remaining", 2, remaining);

        barrier.arrive("node2", Time::from_secs(2)).unwrap();
        let arrived = barrier.arrived();
        crate::assert_with_log!(arrived == 2, "arrived", 2, arrived);

        let result = barrier.arrive("node3", Time::from_secs(3)).unwrap();
        let some = result.is_some();
        crate::assert_with_log!(some, "result some", true, some);
        let trigger = result.unwrap().trigger;
        crate::assert_with_log!(
            trigger == BarrierTrigger::AllArrived,
            "trigger",
            BarrierTrigger::AllArrived,
            trigger
        );
        let triggered = barrier.is_triggered();
        crate::assert_with_log!(triggered, "triggered", true, triggered);
        crate::test_complete!("test_epoch_barrier_basic");
    }

    // Test 10: EpochBarrier duplicate arrival
    #[test]
    fn test_epoch_barrier_duplicate() {
        init_test("test_epoch_barrier_duplicate");
        let barrier = EpochBarrier::new(EpochId(1), 2, Time::ZERO);

        barrier.arrive("node1", Time::from_secs(1)).unwrap();

        // Duplicate arrival should fail
        let result = barrier.arrive("node1", Time::from_secs(2));
        let err = result.is_err();
        crate::assert_with_log!(err, "duplicate err", true, err);
        crate::test_complete!("test_epoch_barrier_duplicate");
    }

    // Test 11: EpochBarrier timeout
    #[test]
    fn test_epoch_barrier_timeout() {
        init_test("test_epoch_barrier_timeout");
        let barrier =
            EpochBarrier::new(EpochId(1), 3, Time::ZERO).with_timeout(Time::from_secs(10));

        barrier.arrive("node1", Time::from_secs(1)).unwrap();

        // Arrival after timeout
        let result = barrier.arrive("node2", Time::from_secs(15)).unwrap();
        let some = result.is_some();
        crate::assert_with_log!(some, "result some", true, some);
        let trigger = result.unwrap().trigger;
        crate::assert_with_log!(
            trigger == BarrierTrigger::Timeout,
            "trigger",
            BarrierTrigger::Timeout,
            trigger
        );
        crate::test_complete!("test_epoch_barrier_timeout");
    }

    // Test 12: EpochClock advance
    #[test]
    fn test_epoch_clock_advance() {
        init_test("test_epoch_clock_advance");
        let config = EpochConfig::short_lived();
        let clock = EpochClock::new(config);
        clock.initialize(Time::ZERO);

        crate::assert_with_log!(
            clock.current() == EpochId::GENESIS,
            "current genesis",
            EpochId::GENESIS,
            clock.current()
        );

        // Advance after minimum duration
        let new_epoch = clock.advance(Time::from_millis(100)).unwrap();
        crate::assert_with_log!(new_epoch == EpochId(1), "new epoch", EpochId(1), new_epoch);
        crate::assert_with_log!(
            clock.current() == EpochId(1),
            "current",
            EpochId(1),
            clock.current()
        );
        crate::test_complete!("test_epoch_clock_advance");
    }

    // Test 13: EpochClock history retention
    #[test]
    fn test_epoch_clock_history() {
        init_test("test_epoch_clock_history");
        let config = EpochConfig {
            min_duration: Time::from_millis(10),
            target_duration: Time::from_millis(50),
            max_duration: Time::from_millis(100),
            retention_epochs: 3,
            ..EpochConfig::default()
        };
        let clock = EpochClock::new(config);
        clock.initialize(Time::ZERO);

        // Advance through multiple epochs
        for i in 1..=5 {
            clock.advance(Time::from_millis(i * 20)).unwrap();
        }

        let history = clock.history();
        let within = history.len() <= 3;
        crate::assert_with_log!(within, "history len <= 3", true, within);
        crate::test_complete!("test_epoch_clock_history");
    }

    // Test 14: EpochError display
    #[test]
    fn test_epoch_error_display() {
        init_test("test_epoch_error_display");
        let expired = EpochError::Expired { epoch: EpochId(5) };
        let expired_str = expired.to_string();
        let has_num = expired_str.contains('5');
        crate::assert_with_log!(has_num, "contains 5", true, has_num);
        let has_expired = expired_str.contains("expired");
        crate::assert_with_log!(has_expired, "contains expired", true, has_expired);

        let transition = EpochError::TransitionOccurred {
            from: EpochId(1),
            to: EpochId(2),
        };
        let transition_str = transition.to_string();
        let has_transition = transition_str.contains("transition");
        crate::assert_with_log!(has_transition, "contains transition", true, has_transition);
        crate::test_complete!("test_epoch_error_display");
    }

    // Test 15: Epoch metadata
    #[test]
    fn test_epoch_metadata() {
        init_test("test_epoch_metadata");
        let config = EpochConfig::default();
        let mut epoch = Epoch::new(EpochId(1), Time::ZERO, config);

        epoch.set_metadata("version", "1.0.0");
        epoch.set_metadata("leader", "node-1");

        let expected_version = "1.0.0".to_string();
        let expected_leader = "node-1".to_string();
        let version = epoch.metadata.get("version");
        crate::assert_with_log!(
            version == Some(&expected_version),
            "version",
            Some(&expected_version),
            version
        );
        let leader = epoch.metadata.get("leader");
        crate::assert_with_log!(
            leader == Some(&expected_leader),
            "leader",
            Some(&expected_leader),
            leader
        );
        crate::test_complete!("test_epoch_metadata");
    }

    // Test 16: EpochContext budget tracking
    #[test]
    fn test_epoch_context_budget() {
        init_test("test_epoch_context_budget");
        let ctx =
            EpochContext::new(EpochId(1), Time::ZERO, Time::from_secs(10)).with_operation_budget(1);
        let first = ctx.record_operation();
        crate::assert_with_log!(first, "first record", true, first);
        let second = ctx.record_operation();
        crate::assert_with_log!(!second, "second record", false, second);
        let exhausted = ctx.is_budget_exhausted();
        crate::assert_with_log!(exhausted, "exhausted", true, exhausted);
        let used = ctx.operations_used();
        crate::assert_with_log!(used == 1, "operations used", 1, used);
        crate::test_complete!("test_epoch_context_budget");
    }

    // Test 17: EpochScoped expires when past deadline
    #[test]
    fn test_epoch_scoped_expired() {
        init_test("test_epoch_scoped_expired");
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(5)));
        let epoch = EpochContext::new(EpochId(1), Time::ZERO, Time::from_secs(1));
        let source = Arc::new(TestEpochSource::new(EpochId(1)));
        let policy = EpochPolicy::strict();

        let fut = EpochScoped::new(Box::pin(async { 42u32 }), epoch, policy, clock, source);
        let result = block_on(fut);
        let expired = matches!(result, Err(EpochError::Expired { .. }));
        crate::assert_with_log!(expired, "expired", true, expired);
        crate::test_complete!("test_epoch_scoped_expired");
    }

    // Test 18: EpochScoped detects transitions
    #[test]
    fn test_epoch_scoped_transition() {
        init_test("test_epoch_scoped_transition");
        let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        let source = Arc::new(TestEpochSource::new(EpochId(1)));
        source.set(EpochId(2));

        let epoch = EpochContext::new(EpochId(1), Time::ZERO, Time::from_secs(10));
        let policy = EpochPolicy::strict();
        let fut = EpochScoped::new(Box::pin(async { 7u8 }), epoch, policy, clock, source);
        let result = block_on(fut);
        let transitioned = matches!(result, Err(EpochError::TransitionOccurred { .. }));
        crate::assert_with_log!(transitioned, "transitioned", true, transitioned);
        crate::test_complete!("test_epoch_scoped_transition");
    }

    // Test 19: Epoch-select completes left branch
    #[test]
    fn test_epoch_select_left() {
        init_test("test_epoch_select_left");
        let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        let source = Arc::new(TestEpochSource::new(EpochId(1)));
        let epoch = EpochContext::new(EpochId(1), Time::ZERO, Time::from_secs(10));
        let policy = EpochPolicy::strict();

        let fut = epoch_select(
            Box::pin(async { 1u8 }),
            Box::pin(async { 2u8 }),
            epoch,
            policy,
            clock,
            source,
        );
        let result = block_on(fut);
        match result {
            Either::Left(Ok(v)) => {
                crate::assert_with_log!(v == 1, "left result", 1, v);
            }
            _ => panic!("unexpected select result"),
        }
        crate::test_complete!("test_epoch_select_left");
    }

    // Test 20: Bulkhead/CircuitBreaker epoch wrappers
    #[test]
    fn test_epoch_wrapped_bulkhead_and_circuit_breaker() {
        init_test("test_epoch_wrapped_bulkhead_and_circuit_breaker");

        let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        let epoch_source = Arc::new(TestEpochSource::new(EpochId(1)));
        let policy = EpochPolicy::strict();
        let epoch_ctx = EpochContext::new(EpochId(1), Time::ZERO, Time::from_secs(10));

        let bulkhead = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            ..Default::default()
        });
        let breaker = CircuitBreaker::new(CircuitBreakerPolicy::default());

        let bulkhead_result = bulkhead_call_in_epoch(
            &bulkhead,
            &epoch_ctx,
            &policy,
            &*clock,
            &*epoch_source,
            || Ok::<_, &str>(5u32),
        )
        .expect("bulkhead call should succeed");
        crate::assert_with_log!(bulkhead_result == 5, "bulkhead result", 5, bulkhead_result);

        let breaker_result = circuit_breaker_call_in_epoch(
            &breaker,
            &epoch_ctx,
            &policy,
            &*clock,
            &*epoch_source,
            || Ok::<_, &str>(9u32),
        )
        .expect("circuit breaker call should succeed");
        crate::assert_with_log!(breaker_result == 9, "breaker result", 9, breaker_result);
        crate::test_complete!("test_epoch_wrapped_bulkhead_and_circuit_breaker");
    }

    // ============================================================================
    // Additional Epoch Tests (asupersync-ups)
    // ============================================================================

    // Test 21: EpochId overflow handling (saturating at MAX)
    #[test]
    fn test_epoch_id_overflow_saturation() {
        init_test("test_epoch_id_overflow_saturation");
        let max_epoch = EpochId::MAX;

        // saturating_next should stay at MAX
        let saturated = max_epoch.saturating_next();
        crate::assert_with_log!(
            saturated == EpochId::MAX,
            "saturating_next at MAX",
            EpochId::MAX,
            saturated
        );

        // Multiple saturating_next calls should all return MAX
        let double_saturated = saturated.saturating_next();
        crate::assert_with_log!(
            double_saturated == EpochId::MAX,
            "double saturating_next",
            EpochId::MAX,
            double_saturated
        );

        crate::test_complete!("test_epoch_id_overflow_saturation");
    }

    // Test 22: EpochId next overflow panic
    #[test]
    #[should_panic(expected = "attempt to add with overflow")]
    fn test_epoch_id_next_overflow_panics() {
        init_test("test_epoch_id_next_overflow_panics");
        let max_epoch = EpochId::MAX;
        // This should panic due to overflow
        let _ = max_epoch.next();
    }

    // Test 23: EpochBarrier force trigger
    #[test]
    fn test_epoch_barrier_force_trigger() {
        init_test("test_epoch_barrier_force_trigger");
        let barrier = EpochBarrier::new(EpochId(1), 5, Time::ZERO);

        // Only one participant arrived
        barrier.arrive("node1", Time::from_secs(1)).unwrap();
        let arrived = barrier.arrived();
        crate::assert_with_log!(arrived == 1, "arrived before force", 1, arrived);

        // Force trigger before all arrive
        let result = barrier.force_trigger(Time::from_secs(2));
        crate::assert_with_log!(
            result.trigger == BarrierTrigger::Forced,
            "trigger type",
            BarrierTrigger::Forced,
            result.trigger
        );
        crate::assert_with_log!(result.arrived == 1, "arrived in result", 1, result.arrived);
        crate::assert_with_log!(
            result.expected == 5,
            "expected in result",
            5,
            result.expected
        );

        // Barrier should now be triggered
        let triggered = barrier.is_triggered();
        crate::assert_with_log!(triggered, "is_triggered", true, triggered);

        crate::test_complete!("test_epoch_barrier_force_trigger");
    }

    // Test 24: EpochBarrier cancel
    #[test]
    fn test_epoch_barrier_cancel() {
        init_test("test_epoch_barrier_cancel");
        let barrier = EpochBarrier::new(EpochId(2), 3, Time::ZERO);

        barrier.arrive("node1", Time::from_secs(1)).unwrap();
        barrier.arrive("node2", Time::from_secs(2)).unwrap();

        // Cancel before all arrive
        let result = barrier.cancel(Time::from_secs(3));
        crate::assert_with_log!(
            result.trigger == BarrierTrigger::Cancelled,
            "trigger type",
            BarrierTrigger::Cancelled,
            result.trigger
        );
        crate::assert_with_log!(result.arrived == 2, "arrived", 2, result.arrived);

        // Further arrivals should fail since barrier is triggered
        let late_arrival = barrier.arrive("node3", Time::from_secs(4));
        let err = late_arrival.is_err();
        crate::assert_with_log!(err, "late arrival err", true, err);

        crate::test_complete!("test_epoch_barrier_cancel");
    }

    // Test 25: EpochClock advance before minimum duration fails
    #[test]
    fn test_epoch_clock_advance_too_early() {
        init_test("test_epoch_clock_advance_too_early");
        let config = EpochConfig {
            min_duration: Time::from_secs(30),
            target_duration: Time::from_secs(60),
            max_duration: Time::from_secs(120),
            ..EpochConfig::default()
        };
        let clock = EpochClock::new(config);
        clock.initialize(Time::ZERO);

        // Try to advance before minimum duration
        let result = clock.advance(Time::from_secs(10));
        let err = result.is_err();
        crate::assert_with_log!(err, "advance too early err", true, err);

        // Epoch should still be GENESIS
        crate::assert_with_log!(
            clock.current() == EpochId::GENESIS,
            "still genesis",
            EpochId::GENESIS,
            clock.current()
        );

        crate::test_complete!("test_epoch_clock_advance_too_early");
    }

    // Test 26: EpochClock advance when overdue
    #[test]
    fn test_epoch_clock_advance_overdue() {
        init_test("test_epoch_clock_advance_overdue");
        let config = EpochConfig {
            min_duration: Time::from_secs(30),
            target_duration: Time::from_secs(60),
            max_duration: Time::from_secs(120),
            ..EpochConfig::default()
        };
        let clock = EpochClock::new(config);
        clock.initialize(Time::ZERO);

        // Advance when overdue (past max_duration) - should succeed
        let result = clock.advance(Time::from_secs(150));
        let ok = result.is_ok();
        crate::assert_with_log!(ok, "advance when overdue ok", true, ok);
        crate::assert_with_log!(
            clock.current() == EpochId(1),
            "advanced to epoch 1",
            EpochId(1),
            clock.current()
        );

        crate::test_complete!("test_epoch_clock_advance_overdue");
    }

    // Test 27: EpochContext expiry check
    #[test]
    fn test_epoch_context_expiry() {
        init_test("test_epoch_context_expiry");
        let ctx = EpochContext::new(EpochId(1), Time::ZERO, Time::from_secs(10));

        // Not expired before deadline
        let expired_before = ctx.is_expired(Time::from_secs(5));
        crate::assert_with_log!(!expired_before, "not expired at t=5", false, expired_before);

        // Expired at deadline
        let expired_at = ctx.is_expired(Time::from_secs(10));
        crate::assert_with_log!(expired_at, "expired at t=10", true, expired_at);

        // Expired after deadline
        let expired_after = ctx.is_expired(Time::from_secs(15));
        crate::assert_with_log!(expired_after, "expired at t=15", true, expired_after);

        // Check remaining time
        let remaining = ctx.remaining_time(Time::from_secs(3));
        crate::assert_with_log!(
            remaining == Some(Duration::from_secs(7)),
            "remaining at t=3",
            Some(Duration::from_secs(7)),
            remaining
        );

        let no_remaining = ctx.remaining_time(Time::from_secs(12));
        crate::assert_with_log!(
            no_remaining.is_none(),
            "no remaining at t=12",
            true,
            no_remaining.is_none()
        );

        crate::test_complete!("test_epoch_context_expiry");
    }

    // Test 28: SymbolValidityWindow extend_to
    #[test]
    fn test_validity_window_extend() {
        init_test("test_validity_window_extend");
        let window = SymbolValidityWindow::new(EpochId(5), EpochId(10));

        // Extend to include earlier epoch
        let extended_earlier = window.extend_to(EpochId(2));
        crate::assert_with_log!(
            extended_earlier.start == EpochId(2),
            "extended start",
            EpochId(2),
            extended_earlier.start
        );
        crate::assert_with_log!(
            extended_earlier.end == EpochId(10),
            "extended end unchanged",
            EpochId(10),
            extended_earlier.end
        );

        // Extend to include later epoch
        let extended_later = window.extend_to(EpochId(15));
        crate::assert_with_log!(
            extended_later.start == EpochId(5),
            "extended start unchanged",
            EpochId(5),
            extended_later.start
        );
        crate::assert_with_log!(
            extended_later.end == EpochId(15),
            "extended end",
            EpochId(15),
            extended_later.end
        );

        // Extend to epoch already in window (no change)
        let no_change = window.extend_to(EpochId(7));
        crate::assert_with_log!(
            no_change == window,
            "no change for contained epoch",
            window,
            no_change
        );

        crate::test_complete!("test_validity_window_extend");
    }

    // Test 29: Epoch state predicates comprehensive
    #[test]
    fn test_epoch_state_predicates_comprehensive() {
        init_test("test_epoch_state_predicates_comprehensive");

        // Preparing state
        let preparing = EpochState::Preparing;
        crate::assert_with_log!(
            !preparing.is_active(),
            "preparing not active",
            false,
            preparing.is_active()
        );
        crate::assert_with_log!(
            !preparing.is_terminal(),
            "preparing not terminal",
            false,
            preparing.is_terminal()
        );
        crate::assert_with_log!(
            !preparing.allows_completion(),
            "preparing not allows_completion",
            false,
            preparing.allows_completion()
        );

        // Active state
        let active = EpochState::Active;
        crate::assert_with_log!(
            active.is_active(),
            "active is_active",
            true,
            active.is_active()
        );
        crate::assert_with_log!(
            !active.is_terminal(),
            "active not terminal",
            false,
            active.is_terminal()
        );
        crate::assert_with_log!(
            active.allows_completion(),
            "active allows_completion",
            true,
            active.allows_completion()
        );

        // Ending state
        let ending = EpochState::Ending;
        crate::assert_with_log!(
            !ending.is_active(),
            "ending not active",
            false,
            ending.is_active()
        );
        crate::assert_with_log!(
            !ending.is_terminal(),
            "ending not terminal",
            false,
            ending.is_terminal()
        );
        crate::assert_with_log!(
            ending.allows_completion(),
            "ending allows_completion",
            true,
            ending.allows_completion()
        );

        // Ended state
        let ended = EpochState::Ended;
        crate::assert_with_log!(
            !ended.is_active(),
            "ended not active",
            false,
            ended.is_active()
        );
        crate::assert_with_log!(
            ended.is_terminal(),
            "ended is_terminal",
            true,
            ended.is_terminal()
        );
        crate::assert_with_log!(
            !ended.allows_completion(),
            "ended not allows_completion",
            false,
            ended.allows_completion()
        );

        crate::test_complete!("test_epoch_state_predicates_comprehensive");
    }

    // Test 30: Epoch operation counting
    #[test]
    fn test_epoch_operation_counting() {
        init_test("test_epoch_operation_counting");
        let config = EpochConfig::default();
        let mut epoch = Epoch::new(EpochId(1), Time::ZERO, config);

        crate::assert_with_log!(
            epoch.operation_count == 0,
            "initial count",
            0,
            epoch.operation_count
        );

        epoch.record_operation();
        crate::assert_with_log!(
            epoch.operation_count == 1,
            "after first",
            1,
            epoch.operation_count
        );

        epoch.record_operation();
        epoch.record_operation();
        crate::assert_with_log!(
            epoch.operation_count == 3,
            "after three",
            3,
            epoch.operation_count
        );

        crate::test_complete!("test_epoch_operation_counting");
    }

    // Test 31: Epoch remaining time calculation
    #[test]
    fn test_epoch_remaining_time() {
        init_test("test_epoch_remaining_time");
        let config = EpochConfig {
            target_duration: Time::from_secs(100),
            ..EpochConfig::default()
        };
        let mut epoch = Epoch::new(EpochId(1), Time::from_secs(10), config);

        // Active epoch - duration is elapsed time
        let duration_active = epoch.duration(Time::from_secs(25));
        crate::assert_with_log!(
            duration_active == Duration::from_secs(15),
            "active duration",
            Duration::from_secs(15),
            duration_active
        );

        // Complete the epoch
        epoch.begin_ending(Time::from_secs(50)).unwrap();
        epoch.complete(Time::from_secs(60)).unwrap();

        // Completed epoch - duration is fixed
        let duration_ended = epoch.duration(Time::from_secs(100));
        crate::assert_with_log!(
            duration_ended == Duration::from_secs(50),
            "ended duration",
            Duration::from_secs(50),
            duration_ended
        );

        crate::test_complete!("test_epoch_remaining_time");
    }

    // Test 32: EpochPolicy variants
    #[test]
    fn test_epoch_policy_variants() {
        init_test("test_epoch_policy_variants");

        let strict = EpochPolicy::strict();
        crate::assert_with_log!(
            strict.on_transition == EpochTransitionBehavior::AbortAll,
            "strict aborts",
            EpochTransitionBehavior::AbortAll,
            strict.on_transition
        );
        crate::assert_with_log!(
            strict.check_on_poll,
            "strict checks",
            true,
            strict.check_on_poll
        );

        let lenient = EpochPolicy::lenient();
        crate::assert_with_log!(
            lenient.on_transition == EpochTransitionBehavior::DrainExecuting,
            "lenient drains",
            EpochTransitionBehavior::DrainExecuting,
            lenient.on_transition
        );
        crate::assert_with_log!(
            !lenient.check_on_poll,
            "lenient no check",
            false,
            lenient.check_on_poll
        );
        crate::assert_with_log!(
            lenient.grace_period.is_some(),
            "lenient has grace",
            true,
            lenient.grace_period.is_some()
        );

        let ignore = EpochPolicy::ignore();
        crate::assert_with_log!(
            ignore.on_transition == EpochTransitionBehavior::Ignore,
            "ignore ignores",
            EpochTransitionBehavior::Ignore,
            ignore.on_transition
        );
        crate::assert_with_log!(
            !ignore.propagate_to_children,
            "ignore no propagate",
            false,
            ignore.propagate_to_children
        );

        crate::test_complete!("test_epoch_policy_variants");
    }
}
