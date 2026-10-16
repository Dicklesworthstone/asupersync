//! Multipath symbol aggregation infrastructure.
//!
//! This module provides symbol aggregation from multiple transport paths:
//! - `TransportPath`: Represents a single transport path with characteristics
//! - `PathSet`: Manages multiple paths to a destination
//! - `SymbolDeduplicator`: Filters duplicate symbols
//! - `SymbolReorderer`: Buffers and reorders symbols
//! - `MultipathAggregator`: Main aggregation orchestrator

use crate::distributed::encoding::PathQualitySnapshot;
use crate::error::{Error, ErrorKind};
use crate::types::Time;
use crate::types::symbol::{ObjectId, Symbol, SymbolId};
use parking_lot::RwLock;
use smallvec::SmallVec;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

// ============================================================================
// Path Types
// ============================================================================

/// Unique identifier for a transport path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathId(pub u64);

impl PathId {
    /// Creates a new path ID.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for PathId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Path({})", self.0)
    }
}

/// State of a transport path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PathState {
    /// Path is active and healthy.
    Active = 0,

    /// Path is experiencing issues but still usable.
    Degraded = 1,

    /// Path is temporarily unavailable.
    Unavailable = 2,

    /// Path has been permanently closed.
    Closed = 3,
}

impl PathState {
    /// Returns true if the path can be used for receiving.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }

    /// Stable lowercase identifier for logs and replay artifacts.
    #[must_use]
    pub const fn state_id(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
            Self::Closed => "closed",
        }
    }

    /// Converts from a raw `u8` value.
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Active,
            1 => Self::Degraded,
            2 => Self::Unavailable,
            _ => Self::Closed,
        }
    }
}

/// Characteristics of a transport path.
#[derive(Debug, Clone)]
pub struct PathCharacteristics {
    /// Estimated latency in milliseconds.
    pub latency_ms: u32,

    /// Estimated bandwidth in bytes per second.
    pub bandwidth_bps: u64,

    /// Estimated packet loss rate (0.0 - 1.0).
    pub loss_rate: f64,

    /// Path jitter in milliseconds.
    pub jitter_ms: u32,

    /// Whether this is a primary path.
    pub is_primary: bool,

    /// Path priority (lower = higher priority).
    pub priority: u32,
}

impl Default for PathCharacteristics {
    fn default() -> Self {
        Self {
            latency_ms: 50,
            bandwidth_bps: 1_000_000, // 1 Mbps
            loss_rate: 0.01,          // 1%
            jitter_ms: 10,
            is_primary: false,
            priority: 100,
        }
    }
}

impl PathCharacteristics {
    /// Creates characteristics for a high-quality path.
    #[must_use]
    pub fn high_quality() -> Self {
        Self {
            latency_ms: 10,
            bandwidth_bps: 10_000_000, // 10 Mbps
            loss_rate: 0.001,          // 0.1%
            jitter_ms: 2,
            is_primary: true,
            priority: 10,
        }
    }

    /// Creates characteristics for a backup path.
    #[must_use]
    pub fn backup() -> Self {
        Self {
            latency_ms: 100,
            bandwidth_bps: 500_000, // 500 Kbps
            loss_rate: 0.05,        // 5%
            jitter_ms: 30,
            is_primary: false,
            priority: 200,
        }
    }

    /// Exports these configured path characteristics for adaptive RaptorQ block layout.
    ///
    /// The current transport model tracks latency, loss, and jitter rather than
    /// a direct reorder-depth EWMA, so jitter is converted into a conservative
    /// replay-stable reorder proxy.
    #[must_use]
    pub fn encoding_path_quality(&self) -> PathQualitySnapshot {
        PathQualitySnapshot::from_loss_rate(
            self.latency_ms,
            self.loss_rate,
            reorder_depth_from_jitter_ms(self.jitter_ms),
        )
    }

    /// Calculates an overall quality score (higher = better).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn quality_score(&self) -> f64 {
        if !self.loss_rate.is_finite() {
            return 0.0;
        }

        let latency_score = 1000.0 / (f64::from(self.latency_ms) + 1.0);
        // Guard against log10(0) = -inf: treat zero bandwidth as minimal positive value.
        let bandwidth_score = (self.bandwidth_bps.max(1) as f64).log10();
        let bounded_loss = self.loss_rate.clamp(0.0, 1.0);
        let loss_score = 1.0 - bounded_loss;
        let jitter_score = 100.0 / (f64::from(self.jitter_ms) + 1.0);

        // Weighted combination
        latency_score * 0.3 + bandwidth_score * 0.3 + loss_score * 0.3 + jitter_score * 0.1
    }
}

fn reorder_depth_from_jitter_ms(jitter_ms: u32) -> u16 {
    u16::try_from(jitter_ms / 10).unwrap_or(u16::MAX)
}

fn reorder_depth_from_duplicate_pressure(duplicates: u64, received: u64) -> u16 {
    if duplicates == 0 || received == 0 {
        return 0;
    }

    let depth = duplicates.saturating_mul(8).div_ceil(received);
    u16::try_from(depth).unwrap_or(u16::MAX)
}

/// A transport path for symbol transmission.
#[derive(Debug)]
pub struct TransportPath {
    /// Unique identifier.
    pub id: PathId,

    /// Human-readable name.
    pub name: String,

    /// Current state (stored as `AtomicU8` for interior mutability through `Arc`).
    state: AtomicU8,

    /// Path characteristics.
    pub characteristics: PathCharacteristics,

    /// Remote endpoint address.
    pub remote_address: String,

    /// Symbols received on this path.
    pub symbols_received: AtomicU64,

    /// Symbols lost/dropped on this path.
    pub symbols_lost: AtomicU64,

    /// Duplicate symbols received on this path.
    pub duplicates_received: AtomicU64,

    /// Last activity time (nanoseconds, atomic for lock-free updates).
    pub last_activity: AtomicU64,

    /// Creation time.
    pub created_at: Time,
}

impl TransportPath {
    /// Creates a new transport path.
    #[must_use]
    pub fn new(id: PathId, name: impl Into<String>, remote: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            state: AtomicU8::new(PathState::Active as u8),
            characteristics: PathCharacteristics::default(),
            remote_address: remote.into(),
            symbols_received: AtomicU64::new(0),
            symbols_lost: AtomicU64::new(0),
            duplicates_received: AtomicU64::new(0),
            last_activity: AtomicU64::new(0),
            created_at: Time::ZERO,
        }
    }

    /// Sets path characteristics.
    #[must_use]
    pub fn with_characteristics(mut self, chars: PathCharacteristics) -> Self {
        self.characteristics = chars;
        self
    }

    /// Returns the current path state.
    #[must_use]
    pub fn state(&self) -> PathState {
        PathState::from_u8(self.state.load(Ordering::Relaxed))
    }

    /// Updates the path state.
    pub fn set_state(&self, state: PathState) {
        self.state.store(state as u8, Ordering::Relaxed);
    }

    /// Records symbol receipt.
    pub fn record_receipt(&self, now: Time) {
        self.symbols_received.fetch_add(1, Ordering::Relaxed);
        self.last_activity.store(now.as_nanos(), Ordering::Relaxed);
    }

    /// Records a duplicate.
    pub fn record_duplicate(&self) {
        self.duplicates_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a loss.
    pub fn record_loss(&self) {
        self.symbols_lost.fetch_add(1, Ordering::Relaxed);
    }

    /// Exports live path counters for adaptive RaptorQ block layout.
    ///
    /// Observed loss takes precedence once the path has traffic; otherwise the
    /// configured path loss estimate is used. Reorder depth combines the
    /// configured jitter proxy with duplicate-pressure observed on this path.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn encoding_path_quality(&self) -> PathQualitySnapshot {
        let received = self.symbols_received.load(Ordering::Relaxed);
        let lost = self.symbols_lost.load(Ordering::Relaxed);
        let total = received.saturating_add(lost);
        let loss_rate = if total == 0 {
            self.characteristics.loss_rate
        } else {
            lost as f64 / total as f64
        };
        let duplicates = self.duplicates_received.load(Ordering::Relaxed);
        let reorder_depth = reorder_depth_from_jitter_ms(self.characteristics.jitter_ms)
            .max(reorder_depth_from_duplicate_pressure(duplicates, received));

        PathQualitySnapshot::from_loss_rate(
            self.characteristics.latency_ms,
            loss_rate,
            reorder_depth,
        )
    }

    /// Returns the effective loss rate.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn effective_loss_rate(&self) -> f64 {
        let received = self.symbols_received.load(Ordering::Relaxed);
        let lost = self.symbols_lost.load(Ordering::Relaxed);
        let total = received.saturating_add(lost);
        if total == 0 {
            0.0
        } else {
            lost as f64 / total as f64
        }
    }

    /// Returns the duplicate rate.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn duplicate_rate(&self) -> f64 {
        let received = self.symbols_received.load(Ordering::Relaxed);
        let duplicates = self.duplicates_received.load(Ordering::Relaxed);
        if received == 0 {
            0.0
        } else {
            duplicates as f64 / received as f64
        }
    }
}

// ============================================================================
// Path Set
// ============================================================================

/// Policy for path selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathSelectionPolicy {
    /// Use all available paths.
    #[default]
    UseAll,

    /// Use only primary paths.
    PrimaryOnly,

    /// Use paths with best quality score.
    BestQuality {
        /// Number of paths to select.
        count: usize,
    },

    /// Use paths by priority.
    ByPriority {
        /// Number of paths to select.
        count: usize,
    },

    /// Round-robin across paths.
    RoundRobin,
}

impl PathSelectionPolicy {
    /// Stable identifier for structured transport decision logs.
    #[must_use]
    pub const fn policy_id(self) -> &'static str {
        match self {
            Self::UseAll => "use-all",
            Self::PrimaryOnly => "primary-only",
            Self::BestQuality { .. } => "best-quality",
            Self::ByPriority { .. } => "by-priority",
            Self::RoundRobin => "round-robin",
        }
    }

    /// Returns the requested path count for bounded policies.
    #[must_use]
    pub const fn requested_path_count(self) -> Option<usize> {
        match self {
            Self::BestQuality { count } | Self::ByPriority { count } => Some(count),
            Self::UseAll | Self::PrimaryOnly | Self::RoundRobin => None,
        }
    }

    /// Returns true when the requested policy activates preview-only multipath behavior.
    #[must_use]
    pub const fn is_experimental_preview(self) -> bool {
        matches!(
            self,
            Self::UseAll | Self::BestQuality { .. } | Self::ByPriority { .. }
        )
    }
}

/// Reason why a transport policy could not be honored exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSelectionDowngradeReason {
    /// No usable paths were available.
    NoUsablePaths,

    /// The requested primary path set was unavailable, so a conservative backup should be used.
    NoPrimaryPath,

    /// Fewer usable paths were available than the policy requested.
    RequestedPathsUnavailable {
        /// Number of paths requested by the policy.
        requested: usize,
        /// Number of usable paths actually available.
        available: usize,
    },
}

impl PathSelectionDowngradeReason {
    /// Stable identifier for structured logs and artifacts.
    #[must_use]
    pub const fn reason_id(self) -> &'static str {
        match self {
            Self::NoUsablePaths => "no-usable-paths",
            Self::NoPrimaryPath => "no-primary-path",
            Self::RequestedPathsUnavailable { .. } => "requested-paths-unavailable",
        }
    }
}

/// Opt-in gate for preview transport behavior above the conservative baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExperimentalTransportGate {
    /// Disable preview behavior and keep the conservative path active.
    #[default]
    Disabled,

    /// Allow preview multipath path selection while keeping coded transport fail-closed.
    MultipathPreview,
}

impl ExperimentalTransportGate {
    /// Stable identifier for structured transport decision logs.
    #[must_use]
    pub const fn gate_id(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::MultipathPreview => "multipath-preview",
        }
    }
}

/// Preview-only coding policy requests for experimental transport decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportCodingPolicy {
    /// Keep the conservative non-coded transport path.
    #[default]
    Disabled,

    /// Request a metadata-only RaptorQ-backed FEC preview.
    RaptorQFecPreview,

    /// Request a metadata-only RLNC preview.
    RlncPreview,
}

impl TransportCodingPolicy {
    /// Stable identifier for structured transport decision logs.
    #[must_use]
    pub const fn policy_id(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::RaptorQFecPreview => "raptorq-fec-preview",
            Self::RlncPreview => "rlnc-preview",
        }
    }
}

/// Preview-specific downgrade reason emitted by the experimental transport seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExperimentalTransportDowngradeReason {
    /// Preview path selection was requested without enabling the experimental gate.
    ExperimentalGateDisabled,

    /// Coded transport remains blocked on the RaptorQ correctness-closure program.
    RaptorQClosurePending,
}

impl ExperimentalTransportDowngradeReason {
    /// Stable identifier for structured transport decision logs.
    #[must_use]
    pub const fn reason_id(self) -> &'static str {
        match self {
            Self::ExperimentalGateDisabled => "experimental-gate-disabled",
            Self::RaptorQClosurePending => "raptorq-closure-pending",
        }
    }
}

/// Replayable metadata describing a single experimental transport decision request.
#[derive(Debug, Clone)]
pub struct TransportExperimentContext {
    /// Stable workload identifier from the benchmark vocabulary.
    pub workload_id: String,

    /// Correlation identifier linking the decision to a replayable benchmark run.
    pub benchmark_correlation_id: String,
}

impl TransportExperimentContext {
    /// Creates a new transport experiment context.
    #[must_use]
    pub fn new(
        workload_id: impl Into<String>,
        benchmark_correlation_id: impl Into<String>,
    ) -> Self {
        Self {
            workload_id: workload_id.into(),
            benchmark_correlation_id: benchmark_correlation_id.into(),
        }
    }
}

/// Path-selection output with explicit downgrade/fallback metadata.
#[derive(Debug, Clone)]
pub struct PathSelectionDecision {
    /// Policy that was requested by the caller.
    pub policy: PathSelectionPolicy,

    /// Number of usable paths considered when the decision was made.
    pub available_path_count: usize,

    /// Paths selected under the requested policy without applying any fallback.
    pub selected: SmallVec<[Arc<TransportPath>; 4]>,

    /// Conservative fallback paths the caller may use if the requested policy cannot be honored.
    pub fallback: SmallVec<[Arc<TransportPath>; 4]>,

    /// Usable paths considered by the effective policy but not selected.
    pub rejected: SmallVec<[Arc<TransportPath>; 4]>,

    /// Conservative fallback policy associated with `fallback`.
    pub fallback_policy: Option<PathSelectionPolicy>,

    /// Explicit downgrade reason when the requested policy could not be honored exactly.
    pub downgrade_reason: Option<PathSelectionDowngradeReason>,
}

impl PathSelectionDecision {
    /// Creates an empty decision for the requested policy.
    #[must_use]
    pub fn new(policy: PathSelectionPolicy) -> Self {
        Self {
            policy,
            available_path_count: 0,
            selected: SmallVec::new(),
            fallback: SmallVec::new(),
            rejected: SmallVec::new(),
            fallback_policy: None,
            downgrade_reason: None,
        }
    }

    /// Stable identifier for the requested policy.
    #[must_use]
    pub const fn policy_id(&self) -> &'static str {
        self.policy.policy_id()
    }

    /// Requested path count for bounded policies, if any.
    #[must_use]
    pub const fn requested_path_count(&self) -> Option<usize> {
        self.policy.requested_path_count()
    }

    /// Number of usable paths considered when the decision was made.
    #[must_use]
    pub const fn available_path_count(&self) -> usize {
        self.available_path_count
    }

    /// Number of paths selected under the requested policy.
    #[must_use]
    pub fn selected_path_count(&self) -> usize {
        self.selected.len()
    }

    /// Number of conservative fallback paths, if any.
    #[must_use]
    pub fn fallback_path_count(&self) -> usize {
        self.fallback.len()
    }

    /// Number of usable paths rejected by the effective policy.
    #[must_use]
    pub fn rejected_path_count(&self) -> usize {
        self.rejected.len()
    }

    /// Stable identifier for the fallback policy, if any.
    #[must_use]
    pub fn fallback_policy_id(&self) -> Option<&'static str> {
        self.fallback_policy.map(PathSelectionPolicy::policy_id)
    }

    /// Stable identifier for the downgrade reason, if any.
    #[must_use]
    pub fn downgrade_reason_id(&self) -> Option<&'static str> {
        self.downgrade_reason
            .map(PathSelectionDowngradeReason::reason_id)
    }

    /// Selected path identifiers in decision order.
    #[must_use]
    pub fn selected_ids(&self) -> SmallVec<[PathId; 4]> {
        self.selected.iter().map(|path| path.id).collect()
    }

    /// Fallback path identifiers in decision order.
    #[must_use]
    pub fn fallback_ids(&self) -> SmallVec<[PathId; 4]> {
        self.fallback.iter().map(|path| path.id).collect()
    }

    /// Rejected path identifiers in deterministic base path order.
    #[must_use]
    pub fn rejected_ids(&self) -> SmallVec<[PathId; 4]> {
        self.rejected.iter().map(|path| path.id).collect()
    }
}

/// Preview transport decision envelope emitted above the low-level path-selection primitives.
#[derive(Debug, Clone)]
pub struct TransportExperimentDecision {
    /// Replay metadata describing where this decision came from.
    pub context: TransportExperimentContext,

    /// Gate state used for the decision.
    pub gate: ExperimentalTransportGate,

    /// Path policy the caller requested.
    pub requested_path_policy: PathSelectionPolicy,

    /// Effective path policy after conservative fallback.
    pub effective_path_policy: PathSelectionPolicy,

    /// Path-selection decision for the effective policy.
    pub path_decision: PathSelectionDecision,

    /// Coding policy the caller requested.
    pub requested_coding_policy: TransportCodingPolicy,

    /// Effective coding policy after conservative fallback.
    pub effective_coding_policy: TransportCodingPolicy,

    /// Preview downgrade reason, when the requested experimental path could not be honored.
    pub downgrade_reason: Option<ExperimentalTransportDowngradeReason>,

    /// Full preview downgrade reason vector in deterministic decision order.
    pub downgrade_reasons: SmallVec<[ExperimentalTransportDowngradeReason; 2]>,
}

impl TransportExperimentDecision {
    const FAIRNESS_POLICY_ID: &'static str = "transport-multipath-fairness-v1";

    fn format_path_ids(ids: &[PathId]) -> String {
        ids.iter()
            .map(|id| id.0.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn path_role(
        path: &TransportPath,
        selected_ids: &[PathId],
        fallback_ids: &[PathId],
    ) -> &'static str {
        if selected_ids.contains(&path.id) {
            "selected"
        } else if fallback_ids.contains(&path.id) {
            "fallback"
        } else {
            "rejected"
        }
    }

    fn format_pressure_snapshot(&self) -> String {
        let selected_ids = self.path_decision.selected_ids();
        let fallback_ids = self.path_decision.fallback_ids();
        let mut paths = BTreeMap::new();
        for path in self
            .path_decision
            .selected
            .iter()
            .chain(self.path_decision.fallback.iter())
            .chain(self.path_decision.rejected.iter())
        {
            paths.entry(path.id).or_insert(path.as_ref());
        }

        paths
            .values()
            .map(|path| {
                let role =
                    Self::path_role(path, selected_ids.as_slice(), fallback_ids.as_slice());
                let state = path.state().state_id();
                let loss_rate = if path.characteristics.loss_rate.is_finite() {
                    path.characteristics.loss_rate.clamp(0.0, 1.0)
                } else {
                    1.0
                };
                let latency_ms = path.characteristics.latency_ms;
                let bandwidth_bps = path.characteristics.bandwidth_bps;
                let priority = path.characteristics.priority;
                format!(
                    "{}:{state}:latency_ms={latency_ms}:bandwidth_bps={bandwidth_bps}:loss_rate={loss_rate:.6}:priority={priority}:role={role}",
                    path.id.0
                )
            })
            .collect::<Vec<_>>()
            .join("|")
    }

    fn fairness_state(&self) -> String {
        let requested_policy = self.path_policy_id();
        let effective_policy = self.effective_path_policy_id();
        let available = self.path_decision.available_path_count();
        let selected = self.path_decision.selected_path_count();
        let rejected = self.path_decision.rejected_path_count();
        let fallback = self.path_decision.fallback_path_count();
        format!(
            "requested_policy={requested_policy};effective_policy={effective_policy};available={available};selected={selected};rejected={rejected};fallback={fallback}"
        )
    }

    fn format_downgrade_reasons(reasons: &[ExperimentalTransportDowngradeReason]) -> String {
        reasons
            .iter()
            .map(|reason| reason.reason_id())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Stable identifier for the preview gate.
    #[must_use]
    pub const fn gate_id(&self) -> &'static str {
        self.gate.gate_id()
    }

    /// Stable identifier for the requested path policy.
    #[must_use]
    pub const fn path_policy_id(&self) -> &'static str {
        self.requested_path_policy.policy_id()
    }

    /// Stable identifier for the effective path policy.
    #[must_use]
    pub const fn effective_path_policy_id(&self) -> &'static str {
        self.effective_path_policy.policy_id()
    }

    /// Requested path count for bounded policies, if any.
    #[must_use]
    pub const fn requested_path_count(&self) -> Option<usize> {
        self.requested_path_policy.requested_path_count()
    }

    /// Stable identifier for the requested coding policy.
    #[must_use]
    pub const fn coding_policy_id(&self) -> &'static str {
        self.requested_coding_policy.policy_id()
    }

    /// Stable identifier for the effective coding policy.
    #[must_use]
    pub const fn effective_coding_policy_id(&self) -> &'static str {
        self.effective_coding_policy.policy_id()
    }

    /// Stable identifier for the preview downgrade reason, if any.
    #[must_use]
    pub fn downgrade_reason_id(&self) -> Option<&'static str> {
        self.downgrade_reason
            .map(ExperimentalTransportDowngradeReason::reason_id)
    }

    /// Stable identifiers for every preview downgrade reason, in decision order.
    #[must_use]
    pub fn downgrade_reason_ids(&self) -> SmallVec<[&'static str; 2]> {
        self.downgrade_reasons
            .iter()
            .map(|reason| reason.reason_id())
            .collect()
    }

    /// Serializes the decision into stable key/value fields for structured logs or artifacts.
    #[must_use]
    pub fn log_fields(&self) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        let selected_ids = self.path_decision.selected_ids();
        let fallback_ids = self.path_decision.fallback_ids();
        let rejected_ids = self.path_decision.rejected_ids();

        fields.insert("workload_id".to_owned(), self.context.workload_id.clone());
        fields.insert(
            "benchmark_correlation_id".to_owned(),
            self.context.benchmark_correlation_id.clone(),
        );
        fields.insert("experimental_gate_id".to_owned(), self.gate_id().to_owned());
        fields.insert(
            "path_policy_id".to_owned(),
            self.path_policy_id().to_owned(),
        );
        fields.insert(
            "effective_path_policy_id".to_owned(),
            self.effective_path_policy_id().to_owned(),
        );
        fields.insert(
            "requested_path_count".to_owned(),
            self.requested_path_count()
                .map_or_else(|| "all".to_owned(), |count| count.to_string()),
        );
        fields.insert(
            "path_count".to_owned(),
            self.path_decision.available_path_count().to_string(),
        );
        fields.insert(
            "selected_path_count".to_owned(),
            self.path_decision.selected_path_count().to_string(),
        );
        fields.insert(
            "fallback_path_count".to_owned(),
            self.path_decision.fallback_path_count().to_string(),
        );
        fields.insert(
            "rejected_path_count".to_owned(),
            self.path_decision.rejected_path_count().to_string(),
        );
        fields.insert(
            "selected_path_ids".to_owned(),
            Self::format_path_ids(selected_ids.as_slice()),
        );
        fields.insert(
            "fallback_path_ids".to_owned(),
            Self::format_path_ids(fallback_ids.as_slice()),
        );
        fields.insert(
            "rejected_path_ids".to_owned(),
            Self::format_path_ids(rejected_ids.as_slice()),
        );
        fields.insert(
            "path_pressure_snapshot".to_owned(),
            self.format_pressure_snapshot(),
        );
        fields.insert(
            "fairness_policy_id".to_owned(),
            Self::FAIRNESS_POLICY_ID.to_owned(),
        );
        fields.insert("fairness_state".to_owned(), self.fairness_state());
        fields.insert(
            "fallback_policy_id".to_owned(),
            self.path_decision
                .fallback_policy_id()
                .unwrap_or("")
                .to_owned(),
        );
        fields.insert(
            "path_downgrade_reason".to_owned(),
            self.path_decision
                .downgrade_reason_id()
                .unwrap_or("")
                .to_owned(),
        );
        fields.insert(
            "downgrade_reason".to_owned(),
            self.downgrade_reason_id().unwrap_or("").to_owned(),
        );
        fields.insert(
            "downgrade_reasons".to_owned(),
            Self::format_downgrade_reasons(self.downgrade_reasons.as_slice()),
        );
        fields.insert(
            "coding_policy_id".to_owned(),
            self.coding_policy_id().to_owned(),
        );
        fields.insert(
            "effective_coding_policy_id".to_owned(),
            self.effective_coding_policy_id().to_owned(),
        );
        fields
    }
}

/// Manages a set of paths to a destination.
#[derive(Debug)]
pub struct PathSet {
    /// All registered paths.
    paths: RwLock<HashMap<PathId, Arc<TransportPath>>>,

    /// Selection policy.
    policy: PathSelectionPolicy,

    /// Round-robin counter.
    rr_counter: AtomicU64,

    /// Next path ID.
    next_id: AtomicU64,
}

impl PathSet {
    /// Creates a new path set.
    #[must_use]
    pub fn new(policy: PathSelectionPolicy) -> Self {
        Self {
            paths: RwLock::new(HashMap::new()),
            policy,
            rr_counter: AtomicU64::new(0),
            next_id: AtomicU64::new(0),
        }
    }

    /// Registers a new path.
    pub fn register(&self, path: TransportPath) -> PathId {
        let id = path.id;
        let arc = Arc::new(path);
        self.paths.write().insert(id, arc);
        let next = id.0.saturating_add(1);
        let mut observed = self.next_id.load(Ordering::Relaxed);
        while observed < next {
            match self.next_id.compare_exchange_weak(
                observed,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
        id
    }

    /// Creates and registers a new path.
    pub fn create_path(
        &self,
        name: impl Into<String>,
        remote: impl Into<String>,
        chars: PathCharacteristics,
    ) -> PathId {
        let id = PathId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let path = TransportPath::new(id, name, remote).with_characteristics(chars);
        self.register(path)
    }

    /// Gets a path by ID.
    #[must_use]
    pub fn get(&self, id: PathId) -> Option<Arc<TransportPath>> {
        self.paths.read().get(&id).cloned()
    }

    /// Removes a path.
    pub fn remove(&self, id: PathId) -> Option<Arc<TransportPath>> {
        self.paths.write().remove(&id)
    }

    fn usable_paths_sorted(&self) -> Vec<Arc<TransportPath>> {
        // Keep transport path selection replayable by normalizing the base
        // ordering before policy-specific filtering or rotation.
        let mut usable: Vec<_> = {
            let paths = self.paths.read();
            paths
                .values()
                .filter(|path| path.state().is_usable())
                .cloned()
                .collect()
        };
        usable.sort_by_key(|path| path.id);
        usable
    }

    fn select_best_quality(
        usable: &[Arc<TransportPath>],
        count: usize,
    ) -> SmallVec<[Arc<TransportPath>; 4]> {
        let mut ranked = usable.to_vec();
        ranked.sort_by(|a, b| {
            b.characteristics
                .quality_score()
                .partial_cmp(&a.characteristics.quality_score())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.id.cmp(&b.id))
        });
        ranked.into_iter().take(count).collect()
    }

    fn select_by_priority(
        usable: &[Arc<TransportPath>],
        count: usize,
    ) -> SmallVec<[Arc<TransportPath>; 4]> {
        let mut ranked = usable.to_vec();
        ranked.sort_by_key(|path| (path.characteristics.priority, path.id));
        ranked.into_iter().take(count).collect()
    }

    /// Returns path selection plus explicit downgrade/fallback metadata.
    #[must_use]
    pub fn select_paths_with_decision(&self) -> PathSelectionDecision {
        self.select_paths_with_decision_for(self.policy)
    }

    /// Returns path selection plus explicit downgrade/fallback metadata for an arbitrary policy.
    #[must_use]
    pub fn select_paths_with_decision_for(
        &self,
        policy: PathSelectionPolicy,
    ) -> PathSelectionDecision {
        let usable = self.usable_paths_sorted();
        let mut decision = PathSelectionDecision::new(policy);
        decision.available_path_count = usable.len();

        match policy {
            PathSelectionPolicy::UseAll => {
                if usable.is_empty() {
                    decision.downgrade_reason = Some(PathSelectionDowngradeReason::NoUsablePaths);
                } else {
                    decision.selected = usable.iter().cloned().collect();
                }
            }

            PathSelectionPolicy::PrimaryOnly => {
                if usable.is_empty() {
                    decision.downgrade_reason = Some(PathSelectionDowngradeReason::NoUsablePaths);
                } else {
                    let primaries: SmallVec<[Arc<TransportPath>; 4]> = usable
                        .iter()
                        .filter(|path| path.characteristics.is_primary)
                        .cloned()
                        .collect();
                    if primaries.is_empty() {
                        decision.fallback_policy =
                            Some(PathSelectionPolicy::BestQuality { count: 1 });
                        decision.fallback = Self::select_best_quality(&usable, 1);
                        decision.downgrade_reason =
                            Some(PathSelectionDowngradeReason::NoPrimaryPath);
                    } else {
                        decision.selected = primaries;
                    }
                }
            }

            PathSelectionPolicy::BestQuality { count } => {
                decision.selected = Self::select_best_quality(&usable, count);
                if usable.is_empty() {
                    decision.downgrade_reason = Some(PathSelectionDowngradeReason::NoUsablePaths);
                } else if decision.selected.len() < count {
                    decision.downgrade_reason =
                        Some(PathSelectionDowngradeReason::RequestedPathsUnavailable {
                            requested: count,
                            available: decision.selected.len(),
                        });
                }
            }

            PathSelectionPolicy::ByPriority { count } => {
                decision.selected = Self::select_by_priority(&usable, count);
                if usable.is_empty() {
                    decision.downgrade_reason = Some(PathSelectionDowngradeReason::NoUsablePaths);
                } else if decision.selected.len() < count {
                    decision.downgrade_reason =
                        Some(PathSelectionDowngradeReason::RequestedPathsUnavailable {
                            requested: count,
                            available: decision.selected.len(),
                        });
                }
            }

            PathSelectionPolicy::RoundRobin => {
                if usable.is_empty() {
                    decision.downgrade_reason = Some(PathSelectionDowngradeReason::NoUsablePaths);
                } else {
                    let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                    decision.selected.push(usable[idx % usable.len()].clone());
                }
            }
        }

        decision.rejected = usable
            .iter()
            .filter(|path| {
                !decision
                    .selected
                    .iter()
                    .any(|selected| selected.id == path.id)
            })
            .cloned()
            .collect();
        decision
    }

    /// Returns all usable paths based on the selection policy.
    #[must_use]
    pub fn select_paths(&self) -> Vec<Arc<TransportPath>> {
        self.select_paths_with_decision().selected.into_vec()
    }

    /// Updates path state.
    pub fn set_state(&self, id: PathId, state: PathState) -> bool {
        self.paths.read().get(&id).is_some_and(|path| {
            path.set_state(state);
            true
        })
    }

    /// Returns the number of paths.
    #[must_use]
    pub fn count(&self) -> usize {
        self.paths.read().len()
    }

    /// Returns the number of usable paths.
    #[must_use]
    pub fn usable_count(&self) -> usize {
        self.paths
            .read()
            .values()
            .filter(|p| p.state().is_usable())
            .count()
    }

    /// Returns aggregate statistics.
    #[must_use]
    pub fn stats(&self) -> PathSetStats {
        let paths = self.paths.read();

        let mut total_received = 0u64;
        let mut total_lost = 0u64;
        let mut total_duplicates = 0u64;
        let mut total_bandwidth = 0u64;

        for path in paths.values() {
            total_received =
                total_received.saturating_add(path.symbols_received.load(Ordering::Relaxed));
            total_lost = total_lost.saturating_add(path.symbols_lost.load(Ordering::Relaxed));
            total_duplicates =
                total_duplicates.saturating_add(path.duplicates_received.load(Ordering::Relaxed));
            if path.state().is_usable() {
                total_bandwidth =
                    total_bandwidth.saturating_add(path.characteristics.bandwidth_bps);
            }
        }

        PathSetStats {
            path_count: paths.len(),
            usable_count: paths.values().filter(|p| p.state().is_usable()).count(),
            total_received,
            total_lost,
            total_duplicates,
            aggregate_bandwidth_bps: total_bandwidth,
        }
    }
}

/// Statistics for a path set.
#[derive(Debug, Clone)]
pub struct PathSetStats {
    /// Total number of paths.
    pub path_count: usize,
    /// Number of usable paths.
    pub usable_count: usize,
    /// Total symbols received.
    pub total_received: u64,
    /// Total symbols lost.
    pub total_lost: u64,
    /// Total duplicates received.
    pub total_duplicates: u64,
    /// Aggregate bandwidth of usable paths.
    pub aggregate_bandwidth_bps: u64,
}

// ============================================================================
// Symbol Deduplicator
// ============================================================================

/// Configuration for deduplication.
#[derive(Debug, Clone)]
pub struct DeduplicatorConfig {
    /// Maximum symbols to track per object.
    pub max_symbols_per_object: usize,

    /// Maximum objects to track.
    pub max_objects: usize,

    /// TTL for deduplication entries.
    pub entry_ttl: Time,

    /// Whether to track receive path.
    pub track_path: bool,
}

impl Default for DeduplicatorConfig {
    fn default() -> Self {
        Self {
            max_symbols_per_object: 10_000,
            max_objects: 1_000,
            entry_ttl: Time::from_secs(300),
            track_path: true,
        }
    }
}

/// Tracks seen symbols for deduplication.
#[derive(Debug)]
struct ObjectDeduplicationState {
    /// Symbols seen for this object.
    seen: HashSet<SymbolId>,

    /// When each symbol was first seen.
    first_seen: HashMap<SymbolId, Time>,

    /// Which path each symbol arrived on first.
    first_path: HashMap<SymbolId, PathId>,

    /// When this state was created.
    #[allow(dead_code)]
    created_at: Time,

    /// Last activity time.
    last_activity: Time,
}

impl ObjectDeduplicationState {
    fn new(created_at: Time) -> Self {
        Self {
            seen: HashSet::new(),
            first_seen: HashMap::new(),
            first_path: HashMap::new(),
            created_at,
            last_activity: created_at,
        }
    }
}

/// Filters duplicate symbols across multiple paths.
#[derive(Debug)]
pub struct SymbolDeduplicator {
    /// Per-object deduplication state.
    objects: RwLock<HashMap<ObjectId, ObjectDeduplicationState>>,

    /// Configuration.
    config: DeduplicatorConfig,

    /// Total duplicates detected.
    duplicates_detected: AtomicU64,

    /// Total unique symbols processed.
    unique_symbols: AtomicU64,
}

impl SymbolDeduplicator {
    /// Creates a new deduplicator.
    #[must_use]
    pub fn new(config: DeduplicatorConfig) -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
            config,
            duplicates_detected: AtomicU64::new(0),
            unique_symbols: AtomicU64::new(0),
        }
    }

    /// Checks if a symbol is a duplicate.
    ///
    /// Returns `true` if the symbol is new (not a duplicate).
    /// Returns `false` if the symbol has been seen before.
    pub fn check_and_record(&self, symbol: &Symbol, path: PathId, now: Time) -> bool {
        let object_id = symbol.object_id();
        let symbol_id = symbol.id();

        let mut objects = self.objects.write();

        // Enforce max_objects: if at capacity and this is a new object,
        // treat the symbol as unique but skip recording to bound memory.
        if !objects.contains_key(&object_id) && objects.len() >= self.config.max_objects {
            drop(objects);
            self.unique_symbols.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        if self.config.max_symbols_per_object == 0 {
            drop(objects);
            self.unique_symbols.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        // Get or create object state
        let state = objects
            .entry(object_id)
            .or_insert_with(|| ObjectDeduplicationState::new(now));

        // Check if already seen
        if state.seen.contains(&symbol_id) {
            drop(objects);
            self.duplicates_detected.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Enforce max_symbols_per_object: stop *recording* beyond the limit, but
        // still report the symbol as unique so it is delivered. The `seen` set
        // is per-OBJECT (across all of its source blocks), so a multi-block
        // transfer legitimately accumulates far more than the per-object cap;
        // discarding symbols past the cap here would starve the RaptorQ decoder
        // and break the transfer. Membership can no longer be tested past the
        // cap, so consumers that count *unique* progress must de-duplicate by
        // symbol id themselves (see `collect_fungible_symbols_until`, fyihql).
        if state.seen.len() >= self.config.max_symbols_per_object {
            drop(objects);
            self.unique_symbols.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        // Record new symbol
        state.seen.insert(symbol_id);
        state.first_seen.insert(symbol_id, now);
        if self.config.track_path {
            state.first_path.insert(symbol_id, path);
        }
        state.last_activity = now;

        drop(objects);
        self.unique_symbols.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Returns the path that first delivered a symbol.
    #[must_use]
    pub fn first_path(&self, object_id: ObjectId, symbol_id: SymbolId) -> Option<PathId> {
        let objects = self.objects.read();
        objects
            .get(&object_id)
            .and_then(|state| state.first_path.get(&symbol_id).copied())
    }

    /// Prunes old entries.
    pub fn prune(&self, now: Time) -> usize {
        let mut objects = self.objects.write();
        let ttl_nanos = self.config.entry_ttl.as_nanos();

        let mut pruned = 0;
        objects.retain(|_, state| {
            let age = now
                .as_nanos()
                .saturating_sub(state.last_activity.as_nanos());
            let keep = age < ttl_nanos;
            if !keep {
                pruned += 1;
            }
            keep
        });

        pruned
    }

    /// Returns statistics.
    #[must_use]
    pub fn stats(&self) -> DeduplicatorStats {
        let objects = self.objects.read();
        let total_tracked: usize = objects.values().map(|s| s.seen.len()).sum();

        DeduplicatorStats {
            objects_tracked: objects.len(),
            symbols_tracked: total_tracked,
            duplicates_detected: self.duplicates_detected.load(Ordering::Relaxed),
            unique_symbols: self.unique_symbols.load(Ordering::Relaxed),
        }
    }

    /// Clears all state for an object (e.g., after decoding completes).
    pub fn clear_object(&self, object_id: ObjectId) {
        self.objects.write().remove(&object_id);
    }
}

/// Deduplicator statistics.
#[derive(Debug, Clone)]
pub struct DeduplicatorStats {
    /// Objects being tracked.
    pub objects_tracked: usize,
    /// Symbols being tracked.
    pub symbols_tracked: usize,
    /// Total duplicates detected.
    pub duplicates_detected: u64,
    /// Total unique symbols processed.
    pub unique_symbols: u64,
}

// ============================================================================
// Symbol Reorderer
// ============================================================================

/// Configuration for reordering.
#[derive(Debug, Clone)]
pub struct ReordererConfig {
    /// Maximum out-of-order symbols to buffer per object.
    pub max_buffer_per_object: usize,

    /// Maximum time to wait for out-of-order symbols.
    pub max_wait_time: Time,

    /// Whether to deliver immediately without waiting.
    pub immediate_delivery: bool,

    /// Maximum gap in sequence before giving up.
    pub max_sequence_gap: u32,

    /// Fail-open backstop on the number of tracked `(object, block)` reorder
    /// states. Past this cap, a brand-new object's symbols are delivered
    /// immediately without buffering — no symbol is lost (RaptorQ symbols are
    /// order-independent, so skipping reordering for an overflow object is
    /// safe), and memory stays bounded under a flood of distinct object/block
    /// ids. Sized generously, well above any realistic in-flight working set, so
    /// it never bites normal transfers (s53kt5).
    pub max_objects: usize,

    /// Idle TTL after which an *empty* reorder state is reclaimed by
    /// [`SymbolReorderer::prune`]. Bounds the otherwise unbounded per-object map
    /// for objects/blocks that completed or were abandoned without an
    /// `object_complete` clear (s53kt5).
    pub entry_ttl: Time,
}

impl Default for ReordererConfig {
    fn default() -> Self {
        Self {
            max_buffer_per_object: 1_000,
            max_wait_time: Time::from_millis(100),
            immediate_delivery: false,
            max_sequence_gap: 100,
            max_objects: 65_536,
            entry_ttl: Time::from_secs(300),
        }
    }
}

/// Buffered symbol waiting for delivery.
#[derive(Debug)]
struct BufferedSymbol {
    /// The symbol.
    symbol: Symbol,
    /// When it was received.
    received_at: Time,
    /// Path it was received on.
    #[allow(dead_code)] // retained for future path-aware reorder diagnostics
    path: PathId,
}

struct ReorderProcessResult {
    ready: Vec<Symbol>,
}

impl ReorderProcessResult {
    fn accepted(ready: Vec<Symbol>) -> Self {
        Self { ready }
    }
}

/// Per-object reordering state.
#[derive(Debug)]
struct ObjectReorderState {
    /// Next expected sequence number (unwrapped to 64-bit to handle wrap-around).
    next_expected: u64,

    /// Buffered out-of-order symbols (keyed by unwrapped sequence).
    buffer: BTreeMap<u64, BufferedSymbol>,

    /// Last delivery time. Read by [`SymbolReorderer::prune`] to reclaim empty,
    /// idle reorder states.
    last_delivery: Time,
}

impl ObjectReorderState {
    fn new() -> Self {
        Self {
            // Start at a high base to prevent underflow (wrapping to u64::MAX)
            // if a late duplicate arrives before the first expected symbol.
            // (1_u64 << 32) mod 2^32 is exactly 0, matching the protocol start seq.
            next_expected: 1_u64 << 32,
            buffer: BTreeMap::new(),
            last_delivery: Time::ZERO,
        }
    }
}

/// Buffers and reorders symbols to deliver in sequence.
#[derive(Debug)]
pub struct SymbolReorderer {
    /// Per-object-and-block reordering state.
    objects: RwLock<HashMap<(ObjectId, u8), ObjectReorderState>>,

    /// Configuration.
    config: ReordererConfig,

    /// Symbols delivered in order.
    in_order_deliveries: AtomicU64,

    /// Symbols delivered out of order (after buffering).
    reordered_deliveries: AtomicU64,

    /// Symbols that timed out waiting.
    timeout_deliveries: AtomicU64,
}

impl SymbolReorderer {
    /// Creates a new reorderer.
    #[must_use]
    pub fn new(config: ReordererConfig) -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
            config,
            in_order_deliveries: AtomicU64::new(0),
            reordered_deliveries: AtomicU64::new(0),
            timeout_deliveries: AtomicU64::new(0),
        }
    }

    fn process_with_status(&self, symbol: Symbol, path: PathId, now: Time) -> ReorderProcessResult {
        self.process_with_late_policy(symbol, path, now, false)
    }

    fn process_unique_with_status(
        &self,
        symbol: Symbol,
        path: PathId,
        now: Time,
    ) -> ReorderProcessResult {
        self.process_with_late_policy(symbol, path, now, true)
    }

    fn process_with_late_policy(
        &self,
        symbol: Symbol,
        path: PathId,
        now: Time,
        deliver_late_unique: bool,
    ) -> ReorderProcessResult {
        if self.config.immediate_delivery {
            return ReorderProcessResult::accepted(vec![symbol]);
        }

        let object_id = symbol.object_id();
        let sbn = symbol.sbn();
        let seq = symbol.esi();

        let mut objects = self.objects.write();

        // Fail-open backstop: past the per-reorderer object cap, do not create a
        // new `(object, block)` reorder state. Deliver the symbol immediately
        // instead — this bounds memory under a flood of distinct ids without
        // dropping a symbol, since RaptorQ symbols are order-independent and the
        // decoder tolerates any arrival order. The TTL prune keeps steady-state
        // well below the cap, so this only triggers under pathological load
        // (s53kt5).
        if !objects.contains_key(&(object_id, sbn)) && objects.len() >= self.config.max_objects {
            drop(objects);
            return ReorderProcessResult::accepted(vec![symbol]);
        }

        let state = objects
            .entry((object_id, sbn))
            .or_insert_with(ObjectReorderState::new);

        let mut ready = Vec::with_capacity(1);

        // Check if this is the expected symbol
        #[allow(clippy::cast_possible_wrap)]
        let diff = seq.wrapping_sub(state.next_expected as u32) as i32;

        if diff == 0 {
            // Deliver immediately
            ready.push(symbol);
            state.next_expected = state.next_expected.wrapping_add(1);
            state.last_delivery = now;
            self.in_order_deliveries.fetch_add(1, Ordering::Relaxed);

            // Check buffer for consecutive symbols
            while let Some(buffered) = state.buffer.remove(&state.next_expected) {
                ready.push(buffered.symbol);
                state.next_expected = state.next_expected.wrapping_add(1);
                self.reordered_deliveries.fetch_add(1, Ordering::Relaxed);
            }
            drop(objects);
            return ReorderProcessResult::accepted(ready);
        }

        if diff > 0 {
            // Out of order - buffer it.
            #[allow(clippy::cast_sign_loss)]
            let gap = diff as u64;
            let seq_unwrapped = state.next_expected + gap;

            if gap <= u64::from(self.config.max_sequence_gap)
                && state.buffer.len() < self.config.max_buffer_per_object
            {
                state.buffer.insert(
                    seq_unwrapped,
                    BufferedSymbol {
                        symbol,
                        received_at: now,
                        path,
                    },
                );
                drop(objects);
                return ReorderProcessResult::accepted(ready);
            }

            // Either gap is too large, or buffer is full.
            // Give up waiting on missing sequence and advance.
            // First, insert the current symbol into the buffer to ensure chronological sorting.
            state.buffer.insert(
                seq_unwrapped,
                BufferedSymbol {
                    symbol,
                    received_at: now,
                    path,
                },
            );

            // Deliver all buffered symbols (in sequence order) before resetting.
            for (seq, buffered) in std::mem::take(&mut state.buffer) {
                ready.push(buffered.symbol);
                self.timeout_deliveries.fetch_add(1, Ordering::Relaxed);
                state.next_expected = seq.wrapping_add(1);
            }
            state.last_delivery = now;
            drop(objects);
            return ReorderProcessResult::accepted(ready);
        }

        // A standalone reorderer cannot distinguish a late duplicate from a late
        // unique symbol, so it preserves the strict historical drop behavior.
        // MultipathAggregator calls the unique-symbol path after dedup succeeds,
        // where late RaptorQ symbols are still useful to the decoder.
        if deliver_late_unique {
            ready.push(symbol);
            self.timeout_deliveries.fetch_add(1, Ordering::Relaxed);
            // Record the delivery so `prune` does not treat an actively
            // late-delivering stream as idle and reclaim its sequence base
            // (s53kt5).
            state.last_delivery = now;
            drop(objects);
            return ReorderProcessResult::accepted(ready);
        }

        // Late duplicate: ignore it, but keep dedup state intact.
        drop(objects);
        ReorderProcessResult::accepted(ready)
    }

    /// Processes an incoming symbol.
    ///
    /// Returns symbols ready for delivery (may be empty, one, or multiple).
    pub fn process(&self, symbol: Symbol, path: PathId, now: Time) -> Vec<Symbol> {
        self.process_with_status(symbol, path, now).ready
    }

    /// Flushes timed-out symbols.
    ///
    /// Returns symbols that have waited too long.
    pub fn flush_timeouts(&self, now: Time) -> Vec<Symbol> {
        let mut objects = self.objects.write();
        let max_wait_nanos = self.config.max_wait_time.as_nanos();
        let mut flushed = Vec::with_capacity(4);

        for state in objects.values_mut() {
            let flushed_before = flushed.len();

            // Find the highest sequence number that has timed out.
            // Any symbol with seq <= max_timeout_seq must be flushed to preserve order,
            // because we are about to advance next_expected past it.
            let mut max_timeout_seq = None;

            for (&seq_unwrapped, buffered) in &state.buffer {
                let wait_time = now
                    .as_nanos()
                    .saturating_sub(buffered.received_at.as_nanos());
                if wait_time >= max_wait_nanos {
                    max_timeout_seq = Some(seq_unwrapped);
                }
            }

            if let Some(cutoff) = max_timeout_seq {
                // Drain everything up to cutoff
                // BTreeMap::split_off returns keys >= argument.
                // We want to keep keys > cutoff, so we split at cutoff + 1.
                let to_flush = if cutoff == u64::MAX {
                    // No key can be greater than u64::MAX.
                    std::mem::take(&mut state.buffer)
                } else {
                    let keep = state.buffer.split_off(&(cutoff + 1));
                    std::mem::replace(&mut state.buffer, keep)
                };

                for (_, buffered) in to_flush {
                    flushed.push(buffered.symbol);
                    // We treat these as timeout deliveries because they are forced out
                    // by a timeout event (either their own or a later symbol's).
                    self.timeout_deliveries.fetch_add(1, Ordering::Relaxed);
                }

                if cutoff >= state.next_expected {
                    state.next_expected = cutoff.wrapping_add(1);
                }
            }

            // Drain any consecutive buffered symbols that are now deliverable.
            while let Some(buffered) = state.buffer.remove(&state.next_expected) {
                flushed.push(buffered.symbol);
                state.next_expected = state.next_expected.wrapping_add(1);
                self.reordered_deliveries.fetch_add(1, Ordering::Relaxed);
            }

            // If this state delivered any timed-out symbols, record the delivery
            // so `prune` does not subsequently treat an actively flush-draining
            // stream as idle and reclaim its sequence base mid-stream (s53kt5).
            if flushed.len() > flushed_before {
                state.last_delivery = now;
            }
        }

        drop(objects);
        flushed
    }

    /// Reclaims reorder states that are *empty and idle* — i.e. hold no buffered
    /// symbols and have seen no delivery within `entry_ttl`. These are the
    /// `(object, block)` entries that completed or were abandoned without an
    /// `object_complete` clear, which would otherwise accumulate forever (one
    /// permanent entry per distinct id ever observed). Active streams (recent
    /// delivery) and states still holding deliverable-but-not-yet-flushed
    /// symbols are retained, so pruning never resets the sequence base of a live
    /// stream. Returns the number of states dropped (s53kt5).
    pub fn prune(&self, now: Time) -> usize {
        let mut objects = self.objects.write();
        let ttl_nanos = self.config.entry_ttl.as_nanos();

        let mut pruned = 0;
        objects.retain(|_, state| {
            if !state.buffer.is_empty() {
                return true;
            }
            let idle = now
                .as_nanos()
                .saturating_sub(state.last_delivery.as_nanos());
            let keep = idle < ttl_nanos;
            if !keep {
                pruned += 1;
            }
            keep
        });

        pruned
    }

    /// Returns statistics.
    #[must_use]
    pub fn stats(&self) -> ReordererStats {
        let objects = self.objects.read();
        let total_buffered: usize = objects.values().map(|s| s.buffer.len()).sum();

        ReordererStats {
            objects_tracked: objects.len(),
            symbols_buffered: total_buffered,
            in_order_deliveries: self.in_order_deliveries.load(Ordering::Relaxed),
            reordered_deliveries: self.reordered_deliveries.load(Ordering::Relaxed),
            timeout_deliveries: self.timeout_deliveries.load(Ordering::Relaxed),
        }
    }

    /// Clears state for a specific object.
    pub fn clear_object(&self, object_id: ObjectId) {
        self.objects
            .write()
            .retain(|(id, _sbn), _| *id != object_id);
    }
}

/// Reorderer statistics.
#[derive(Debug, Clone)]
pub struct ReordererStats {
    /// Objects being tracked.
    pub objects_tracked: usize,
    /// Symbols currently buffered.
    pub symbols_buffered: usize,
    /// Symbols delivered in order.
    pub in_order_deliveries: u64,
    /// Symbols delivered after reordering.
    pub reordered_deliveries: u64,
    /// Symbols delivered after timeout.
    pub timeout_deliveries: u64,
}

// ============================================================================
// Multipath Aggregator
// ============================================================================

/// Configuration for the aggregator.
#[derive(Debug, Clone)]
pub struct AggregatorConfig {
    /// Deduplicator configuration.
    pub dedup: DeduplicatorConfig,

    /// Reorderer configuration.
    pub reorder: ReordererConfig,

    /// Path selection policy.
    pub path_policy: PathSelectionPolicy,

    /// Opt-in gate for preview transport behavior.
    pub experiment_gate: ExperimentalTransportGate,

    /// Preview coded-transport policy request.
    pub coding_policy: TransportCodingPolicy,

    /// Whether to enable reordering.
    pub enable_reordering: bool,

    /// Flush interval for timeouts.
    pub flush_interval: Time,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            dedup: DeduplicatorConfig::default(),
            reorder: ReordererConfig::default(),
            path_policy: PathSelectionPolicy::UseAll,
            experiment_gate: ExperimentalTransportGate::Disabled,
            coding_policy: TransportCodingPolicy::Disabled,
            enable_reordering: true,
            flush_interval: Time::from_millis(50),
        }
    }
}

/// Result of processing a symbol.
#[derive(Debug)]
pub struct ProcessResult {
    /// Symbols ready for delivery to decoder.
    pub ready: Vec<Symbol>,

    /// Whether the symbol was a duplicate.
    pub was_duplicate: bool,

    /// Path the symbol arrived on.
    pub path: PathId,
}

/// Result of processing one fungible RaptorQ symbol.
#[derive(Debug)]
pub struct FungibleProcessResult {
    /// Unique symbol ready for immediate decoder ingestion.
    pub ready: Option<Symbol>,

    /// Whether the symbol was a duplicate already seen on another path.
    pub was_duplicate: bool,

    /// Path the symbol arrived on.
    pub path: PathId,

    /// First path that delivered this symbol, when tracked.
    pub first_path: Option<PathId>,
}

/// Multi-source collection progress for one fungible RaptorQ object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiSourceFungibleReport {
    /// Object being collected.
    pub object_id: ObjectId,

    /// Unique symbols required by the caller before decode can proceed.
    pub target_unique_symbols: usize,

    /// Unique symbols accepted for `object_id`.
    pub unique_symbols: usize,

    /// Duplicate arrivals skipped across all paths.
    pub duplicate_symbols: usize,

    /// Paths that contributed at least one unique symbol.
    pub contributing_paths: Vec<PathId>,

    /// True once `unique_symbols >= target_unique_symbols`.
    pub complete: bool,
}

/// The main multipath aggregator.
#[derive(Debug)]
pub struct MultipathAggregator {
    /// Path set.
    paths: Arc<PathSet>,

    /// Deduplicator.
    dedup: SymbolDeduplicator,

    /// Reorderer.
    reorderer: SymbolReorderer,

    /// Configuration.
    config: AggregatorConfig,

    /// Total symbols processed.
    total_processed: AtomicU64,

    /// Last flush time (nanoseconds, atomic for lock-free check).
    last_flush: AtomicU64,
}

impl MultipathAggregator {
    /// Creates a new aggregator.
    #[must_use]
    pub fn new(config: AggregatorConfig) -> Self {
        let paths = Arc::new(PathSet::new(config.path_policy));

        Self {
            paths,
            dedup: SymbolDeduplicator::new(config.dedup.clone()),
            reorderer: SymbolReorderer::new(config.reorder.clone()),
            config,
            total_processed: AtomicU64::new(0),
            last_flush: AtomicU64::new(0),
        }
    }

    /// Returns the path set for configuration.
    #[must_use]
    pub fn paths(&self) -> &Arc<PathSet> {
        &self.paths
    }

    /// Plans an opt-in experimental transport decision while preserving a conservative fallback.
    #[must_use]
    pub fn experimental_transport_decision(
        &self,
        context: TransportExperimentContext,
    ) -> TransportExperimentDecision {
        let requested_path_policy = self.config.path_policy;
        let requested_coding_policy = self.config.coding_policy;

        let (effective_path_policy, gate_downgrade_reason) = if self.config.experiment_gate
            == ExperimentalTransportGate::Disabled
            && requested_path_policy.is_experimental_preview()
        {
            (
                PathSelectionPolicy::RoundRobin,
                Some(ExperimentalTransportDowngradeReason::ExperimentalGateDisabled),
            )
        } else {
            (requested_path_policy, None)
        };

        let path_decision = self
            .paths
            .select_paths_with_decision_for(effective_path_policy);

        let (effective_coding_policy, coding_downgrade_reason) = match requested_coding_policy {
            TransportCodingPolicy::Disabled => (TransportCodingPolicy::Disabled, None),
            TransportCodingPolicy::RaptorQFecPreview | TransportCodingPolicy::RlncPreview => (
                TransportCodingPolicy::Disabled,
                Some(ExperimentalTransportDowngradeReason::RaptorQClosurePending),
            ),
        };

        let mut downgrade_reasons = SmallVec::<[ExperimentalTransportDowngradeReason; 2]>::new();
        if let Some(reason) = gate_downgrade_reason {
            downgrade_reasons.push(reason);
        }
        if let Some(reason) = coding_downgrade_reason {
            downgrade_reasons.push(reason);
        }
        let downgrade_reason = downgrade_reasons.first().copied();

        TransportExperimentDecision {
            context,
            gate: self.config.experiment_gate,
            requested_path_policy,
            effective_path_policy,
            path_decision,
            requested_coding_policy,
            effective_coding_policy,
            downgrade_reason,
            downgrade_reasons,
        }
    }

    /// Processes an incoming symbol from a path.
    pub fn process(&self, symbol: Symbol, path: PathId, now: Time) -> ProcessResult {
        self.total_processed.fetch_add(1, Ordering::Relaxed);

        // Record path activity
        if let Some(p) = self.paths.get(path) {
            p.record_receipt(now);
        }

        // Check for duplicates
        let is_unique = self.dedup.check_and_record(&symbol, path, now);

        if !is_unique {
            // Duplicate - record and discard
            if let Some(p) = self.paths.get(path) {
                p.record_duplicate();
            }
            return ProcessResult {
                ready: vec![],
                was_duplicate: true,
                path,
            };
        }

        // Process through reorderer if enabled
        let reorder_result = if self.config.enable_reordering {
            self.reorderer.process_unique_with_status(symbol, path, now)
        } else {
            ReorderProcessResult::accepted(vec![symbol])
        };
        ProcessResult {
            ready: reorder_result.ready,
            was_duplicate: false,
            path,
        }
    }

    /// Processes an incoming RaptorQ symbol as fungible decoder input.
    ///
    /// RaptorQ does not require symbol ordering: any unique symbols for the
    /// object can advance decode. This path therefore uses the existing
    /// cross-path deduplicator and bypasses sequence reordering, which keeps
    /// multi-source collection from stalling behind gaps that another peer may
    /// fill later.
    pub fn process_fungible_symbol(
        &self,
        symbol: Symbol,
        path: PathId,
        now: Time,
    ) -> FungibleProcessResult {
        self.total_processed.fetch_add(1, Ordering::Relaxed);
        let object_id = symbol.object_id();
        let symbol_id = symbol.id();

        if let Some(p) = self.paths.get(path) {
            p.record_receipt(now);
        }

        let is_unique = self.dedup.check_and_record(&symbol, path, now);
        if !is_unique {
            if let Some(p) = self.paths.get(path) {
                p.record_duplicate();
            }
            return FungibleProcessResult {
                ready: None,
                was_duplicate: true,
                path,
                first_path: self.dedup.first_path(object_id, symbol_id),
            };
        }

        FungibleProcessResult {
            ready: Some(symbol),
            was_duplicate: false,
            path,
            first_path: Some(path),
        }
    }

    /// Collects unique fungible symbols until the requested decode target is met.
    ///
    /// The iterator is consumed only until `target_unique_symbols` matching
    /// symbols have arrived. This is the multi-source ATP/RaptorQ core: no peer
    /// needs to have a complete set alone, because the union of unique symbols
    /// across paths is enough.
    pub fn collect_fungible_symbols_until<I>(
        &self,
        object_id: ObjectId,
        target_unique_symbols: usize,
        symbols: I,
        now: Time,
    ) -> MultiSourceFungibleReport
    where
        I: IntoIterator<Item = (Symbol, PathId)>,
    {
        let mut unique_symbols = 0usize;
        let mut duplicate_symbols = 0usize;
        let mut contributing_paths = BTreeSet::new();
        // Count uniqueness by symbol id locally rather than trusting the
        // deduplicator's verdict alone. Past its per-object cap the dedup can no
        // longer record (and therefore no longer detect) symbols — it passes
        // them through as "unique" so the decoder is never starved — so a
        // re-presented duplicate would otherwise inflate `unique_symbols` and
        // let the target be reached with fewer than `target_unique_symbols`
        // distinct symbols (a false completion, fyihql). This set is bounded by
        // `target_unique_symbols` because the loop stops once the target is met.
        let mut counted: HashSet<SymbolId> = HashSet::new();

        for (symbol, path) in symbols {
            if unique_symbols >= target_unique_symbols {
                break;
            }
            let result = self.process_fungible_symbol(symbol, path, now);
            if result.was_duplicate {
                duplicate_symbols = duplicate_symbols.saturating_add(1);
                continue;
            }
            if let Some(symbol) = result.ready {
                if symbol.object_id() == object_id {
                    if counted.insert(symbol.id()) {
                        unique_symbols = unique_symbols.saturating_add(1);
                        contributing_paths.insert(path);
                    } else {
                        duplicate_symbols = duplicate_symbols.saturating_add(1);
                    }
                }
            }
        }

        MultiSourceFungibleReport {
            object_id,
            target_unique_symbols,
            unique_symbols,
            duplicate_symbols,
            contributing_paths: contributing_paths.into_iter().collect(),
            complete: unique_symbols >= target_unique_symbols,
        }
    }

    /// Flushes any timed-out symbols.
    pub fn flush(&self, now: Time) -> Vec<Symbol> {
        // Check flush interval (lock-free CAS)
        let interval_nanos = self.config.flush_interval.as_nanos();
        loop {
            let last_nanos = self.last_flush.load(Ordering::Acquire);
            if now.as_nanos().saturating_sub(last_nanos) < interval_nanos {
                return vec![];
            }
            if self
                .last_flush
                .compare_exchange_weak(
                    last_nanos,
                    now.as_nanos(),
                    Ordering::Release,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break;
            }
        }

        // Flush reorderer timeouts
        let flushed = self.reorderer.flush_timeouts(now);

        // Prune deduplicator
        self.dedup.prune(now);
        // Prune the reorderer's per-(object, block) states so empty, idle
        // entries do not accumulate without bound (s53kt5).
        self.reorderer.prune(now);

        flushed
    }

    /// Notifies that an object has been fully decoded.
    ///
    /// Clears all state for the object.
    pub fn object_complete(&self, object_id: ObjectId) {
        self.dedup.clear_object(object_id);
        self.reorderer.clear_object(object_id);
    }

    /// Returns aggregate statistics.
    #[must_use]
    pub fn stats(&self) -> AggregatorStats {
        AggregatorStats {
            paths: self.paths.stats(),
            dedup: self.dedup.stats(),
            reorder: self.reorderer.stats(),
            total_processed: self.total_processed.load(Ordering::Relaxed),
        }
    }
}

/// Aggregator statistics.
#[derive(Debug, Clone)]
pub struct AggregatorStats {
    /// Path set statistics.
    pub paths: PathSetStats,
    /// Deduplicator statistics.
    pub dedup: DeduplicatorStats,
    /// Reorderer statistics.
    pub reorder: ReordererStats,
    /// Total symbols processed.
    pub total_processed: u64,
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors from aggregation.
#[derive(Debug, Clone)]
pub enum AggregationError {
    /// Path not found.
    PathNotFound {
        /// The path ID.
        path: PathId,
    },

    /// Path is unavailable.
    PathUnavailable {
        /// The path ID.
        path: PathId,
    },

    /// Buffer overflow.
    BufferOverflow {
        /// The object ID.
        object_id: ObjectId,
    },

    /// Invalid symbol sequence.
    InvalidSequence {
        /// The object ID.
        object_id: ObjectId,
        /// Expected sequence number.
        expected: u32,
        /// Received sequence number.
        received: u32,
    },
}

impl std::fmt::Display for AggregationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathNotFound { path } => write!(f, "path {path} not found"),
            Self::PathUnavailable { path } => write!(f, "path {path} unavailable"),
            Self::BufferOverflow { object_id } => {
                write!(f, "buffer overflow for object {object_id:?}")
            }
            Self::InvalidSequence {
                object_id,
                expected,
                received,
            } => {
                write!(
                    f,
                    "invalid sequence for object {object_id:?}: expected {expected}, got {received}"
                )
            }
        }
    }
}

impl std::error::Error for AggregationError {}

impl From<AggregationError> for Error {
    fn from(e: AggregationError) -> Self {
        Self::new(ErrorKind::StreamEnded).with_message(e.to_string())
    }
}

#[cfg(test)]
#[path = "aggregator_inline_tests.rs"]
mod tests;
