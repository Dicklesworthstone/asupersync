//! Multipath symbol aggregation infrastructure.
//!
//! This module provides symbol aggregation from multiple transport paths:
//! - `TransportPath`: Represents a single transport path with characteristics
//! - `PathSet`: Manages multiple paths to a destination
//! - `SymbolDeduplicator`: Filters duplicate symbols
//! - `SymbolReorderer`: Buffers and reorders symbols
//! - `MultipathAggregator`: Main aggregation orchestrator

use crate::error::{Error, ErrorKind};
use crate::types::Time;
use crate::types::symbol::{ObjectId, Symbol, SymbolId};
use parking_lot::RwLock;
use smallvec::SmallVec;
use std::collections::{BTreeMap, HashMap, HashSet};
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

    /// Calculates an overall quality score (higher = better).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn quality_score(&self) -> f64 {
        let latency_score = 1000.0 / (f64::from(self.latency_ms) + 1.0);
        // Guard against log10(0) = -inf: treat zero bandwidth as minimal positive value.
        let bandwidth_score = (self.bandwidth_bps.max(1) as f64).log10();
        let loss_score = 1.0 - self.loss_rate.clamp(0.0, 1.0);
        let jitter_score = 100.0 / (f64::from(self.jitter_ms) + 1.0);

        // Weighted combination
        latency_score * 0.3 + bandwidth_score * 0.3 + loss_score * 0.3 + jitter_score * 0.1
    }
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
}

impl TransportExperimentDecision {
    fn format_path_ids(ids: &[PathId]) -> String {
        ids.iter()
            .map(|id| id.0.to_string())
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

    /// Serializes the decision into stable key/value fields for structured logs or artifacts.
    #[must_use]
    pub fn log_fields(&self) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        let selected_ids = self.path_decision.selected_ids();
        let fallback_ids = self.path_decision.fallback_ids();

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
            "selected_path_ids".to_owned(),
            Self::format_path_ids(selected_ids.as_slice()),
        );
        fields.insert(
            "fallback_path_ids".to_owned(),
            Self::format_path_ids(fallback_ids.as_slice()),
        );
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
                    decision.selected = usable.into_iter().collect();
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

        // Enforce max_symbols_per_object: stop recording beyond the limit.
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

    /// Rolls back a previously recorded symbol so a later retransmission can be
    /// treated as unique again.
    ///
    /// Returns `true` when a recorded symbol was actually removed.
    fn rollback_record(&self, object_id: ObjectId, symbol_id: SymbolId) -> bool {
        let mut objects = self.objects.write();
        let mut remove_object = false;
        {
            let Some(state) = objects.get_mut(&object_id) else {
                return false;
            };
            if !state.seen.remove(&symbol_id) {
                return false;
            }
            state.first_seen.remove(&symbol_id);
            state.first_path.remove(&symbol_id);

            if state.seen.is_empty() {
                remove_object = true;
            } else {
                state.last_activity = state
                    .first_seen
                    .values()
                    .copied()
                    .max()
                    .unwrap_or(state.created_at);
            }
        }
        if remove_object {
            objects.remove(&object_id);
        }

        drop(objects);
        // Saturating decrement — a double-rollback (caller bug) must not
        // wrap the counter to u64::MAX.
        let _ = self
            .unique_symbols
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
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
}

impl Default for ReordererConfig {
    fn default() -> Self {
        Self {
            max_buffer_per_object: 1_000,
            max_wait_time: Time::from_millis(100),
            immediate_delivery: false,
            max_sequence_gap: 100,
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
    rollback_dedup_record: bool,
}

impl ReorderProcessResult {
    fn accepted(ready: Vec<Symbol>) -> Self {
        Self {
            ready,
            rollback_dedup_record: false,
        }
    }
}

/// Per-object reordering state.
#[derive(Debug)]
struct ObjectReorderState {
    /// Next expected sequence number (unwrapped to 64-bit to handle wrap-around).
    next_expected: u64,

    /// Buffered out-of-order symbols (keyed by unwrapped sequence).
    buffer: BTreeMap<u64, BufferedSymbol>,

    /// Last delivery time.
    #[allow(dead_code)]
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
        if self.config.immediate_delivery {
            return ReorderProcessResult::accepted(vec![symbol]);
        }

        let object_id = symbol.object_id();
        let sbn = symbol.sbn();
        let seq = symbol.esi();

        let mut objects = self.objects.write();
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
            // Deliver all buffered symbols (in sequence order) before resetting.
            for (_, buffered) in std::mem::take(&mut state.buffer) {
                ready.push(buffered.symbol);
                self.timeout_deliveries.fetch_add(1, Ordering::Relaxed);
            }
            state.next_expected = seq_unwrapped.wrapping_add(1);
            state.last_delivery = now;
            ready.push(symbol);
            self.in_order_deliveries.fetch_add(1, Ordering::Relaxed);
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
        }

        drop(objects);
        flushed
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

        TransportExperimentDecision {
            context,
            gate: self.config.experiment_gate,
            requested_path_policy,
            effective_path_policy,
            path_decision,
            requested_coding_policy,
            effective_coding_policy,
            downgrade_reason: gate_downgrade_reason.or(coding_downgrade_reason),
        }
    }

    /// Processes an incoming symbol from a path.
    pub fn process(&self, symbol: Symbol, path: PathId, now: Time) -> ProcessResult {
        self.total_processed.fetch_add(1, Ordering::Relaxed);
        let object_id = symbol.object_id();
        let symbol_id = symbol.id();

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
            self.reorderer.process_with_status(symbol, path, now)
        } else {
            ReorderProcessResult::accepted(vec![symbol])
        };
        if reorder_result.rollback_dedup_record {
            let _ = self.dedup.rollback_record(object_id, symbol_id);
        }

        ProcessResult {
            ready: reorder_result.ready,
            was_duplicate: false,
            path,
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
mod tests {
    use super::*;

    fn test_path(id: u64) -> TransportPath {
        TransportPath::new(
            PathId(id),
            format!("path-{id}"),
            format!("10.0.0.{id}:8080"),
        )
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // Test 1: Path state predicates
    #[test]
    fn test_path_state() {
        init_test("test_path_state");
        let active = PathState::Active.is_usable();
        crate::assert_with_log!(active, "active usable", true, active);
        let degraded = PathState::Degraded.is_usable();
        crate::assert_with_log!(degraded, "degraded usable", true, degraded);
        let unavailable = PathState::Unavailable.is_usable();
        crate::assert_with_log!(!unavailable, "unavailable not usable", false, unavailable);
        let closed = PathState::Closed.is_usable();
        crate::assert_with_log!(!closed, "closed not usable", false, closed);
        crate::test_complete!("test_path_state");
    }

    // Test 2: Path characteristics quality score
    #[test]
    fn test_quality_score() {
        init_test("test_quality_score");
        let high = PathCharacteristics::high_quality();
        let backup = PathCharacteristics::backup();

        let high_score = high.quality_score();
        let backup_score = backup.quality_score();
        let higher = high_score > backup_score;
        crate::assert_with_log!(higher, "high > backup quality", true, higher);
        crate::test_complete!("test_quality_score");
    }

    // Test 3: Path statistics
    #[test]
    fn test_path_statistics() {
        init_test("test_path_statistics");
        let path = test_path(1);

        path.record_receipt(Time::from_secs(1));
        path.record_receipt(Time::from_secs(2));
        path.record_duplicate();
        path.record_loss();

        let received = path.symbols_received.load(Ordering::Relaxed);
        crate::assert_with_log!(received == 2, "symbols_received", 2, received);
        let duplicates = path.duplicates_received.load(Ordering::Relaxed);
        crate::assert_with_log!(duplicates == 1, "duplicates_received", 1, duplicates);
        let duplicate_rate = path.duplicate_rate();
        crate::assert_with_log!(
            duplicate_rate > 0.0,
            "duplicate_rate > 0",
            true,
            duplicate_rate > 0.0
        );
        let loss_rate = path.effective_loss_rate();
        crate::assert_with_log!(
            loss_rate > 0.0,
            "effective_loss_rate > 0",
            true,
            loss_rate > 0.0
        );
        crate::test_complete!("test_path_statistics");
    }

    // Test 4: PathSet selection - UseAll
    #[test]
    fn test_path_set_use_all() {
        init_test("test_path_set_use_all");
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        set.register(test_path(3));
        set.register(test_path(1));
        set.register(test_path(2));

        let selected = set.select_paths();
        let len = selected.len();
        crate::assert_with_log!(len == 3, "selected len", 3, len);
        let ids: Vec<PathId> = selected.iter().map(|path| path.id).collect();
        crate::assert_with_log!(
            ids == vec![PathId(1), PathId(2), PathId(3)],
            "use_all returns stable PathId order",
            vec![PathId(1), PathId(2), PathId(3)],
            ids
        );
        crate::test_complete!("test_path_set_use_all");
    }

    // Test 4.1: PathSet selection skips unusable paths
    #[test]
    fn test_path_set_skips_unusable() {
        init_test("test_path_set_skips_unusable");
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        let down = test_path(1);
        down.set_state(PathState::Unavailable);
        let up = test_path(2);
        up.set_state(PathState::Active);

        set.register(down);
        set.register(up);

        let selected = set.select_paths();
        let len = selected.len();
        crate::assert_with_log!(len == 1, "selected len", 1, len);
        let id = selected[0].id;
        crate::assert_with_log!(id == PathId(2), "selected path id", PathId(2), id);
        crate::test_complete!("test_path_set_skips_unusable");
    }

    // Test 5: PathSet selection - BestQuality
    #[test]
    fn test_path_set_best_quality() {
        init_test("test_path_set_best_quality");
        let set = PathSet::new(PathSelectionPolicy::BestQuality { count: 2 });

        set.register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        set.register(test_path(2).with_characteristics(PathCharacteristics::backup()));
        set.register(test_path(3).with_characteristics(PathCharacteristics::default()));

        let selected = set.select_paths();
        let len = selected.len();
        crate::assert_with_log!(len == 2, "selected len", 2, len);
        // First should be high quality
        let first_score = selected[0].characteristics.quality_score();
        let second_score = selected[1].characteristics.quality_score();
        let ordered = first_score > second_score;
        crate::assert_with_log!(ordered, "quality order", true, ordered);
        crate::test_complete!("test_path_set_best_quality");
    }

    #[test]
    fn test_path_set_best_quality_tie_breaks_by_path_id() {
        init_test("test_path_set_best_quality_tie_breaks_by_path_id");
        let set = PathSet::new(PathSelectionPolicy::BestQuality { count: 2 });

        let tied = || PathCharacteristics {
            latency_ms: 25,
            bandwidth_bps: 2_000_000,
            loss_rate: 0.01,
            jitter_ms: 4,
            is_primary: false,
            priority: 100,
        };
        set.register(test_path(9).with_characteristics(tied()));
        set.register(test_path(2).with_characteristics(tied()));
        set.register(test_path(5).with_characteristics(PathCharacteristics::backup()));

        let selected = set.select_paths();
        let ids: Vec<PathId> = selected.iter().map(|path| path.id).collect();
        crate::assert_with_log!(
            ids == vec![PathId(2), PathId(9)],
            "best-quality ties prefer lower PathId",
            vec![PathId(2), PathId(9)],
            ids
        );

        crate::test_complete!("test_path_set_best_quality_tie_breaks_by_path_id");
    }

    // Test 5.1: PathSet selection - ByPriority
    #[test]
    fn test_path_set_by_priority() {
        init_test("test_path_set_by_priority");
        let set = PathSet::new(PathSelectionPolicy::ByPriority { count: 2 });

        set.register(test_path(1).with_characteristics(PathCharacteristics {
            priority: 50,
            ..Default::default()
        }));
        set.register(test_path(2).with_characteristics(PathCharacteristics {
            priority: 10,
            ..Default::default()
        }));
        set.register(test_path(3).with_characteristics(PathCharacteristics {
            priority: 30,
            ..Default::default()
        }));

        let selected = set.select_paths();
        let mut priorities: Vec<u32> = selected
            .iter()
            .map(|p| p.characteristics.priority)
            .collect();
        priorities.sort_unstable();
        crate::assert_with_log!(
            priorities == vec![10, 30],
            "priority selection",
            vec![10, 30],
            priorities
        );
        crate::test_complete!("test_path_set_by_priority");
    }

    #[test]
    fn test_path_set_by_priority_tie_breaks_by_path_id() {
        init_test("test_path_set_by_priority_tie_breaks_by_path_id");
        let set = PathSet::new(PathSelectionPolicy::ByPriority { count: 2 });

        set.register(test_path(8).with_characteristics(PathCharacteristics {
            priority: 10,
            ..Default::default()
        }));
        set.register(test_path(3).with_characteristics(PathCharacteristics {
            priority: 10,
            ..Default::default()
        }));
        set.register(test_path(5).with_characteristics(PathCharacteristics {
            priority: 20,
            ..Default::default()
        }));

        let selected = set.select_paths();
        let ids: Vec<PathId> = selected.iter().map(|path| path.id).collect();
        crate::assert_with_log!(
            ids == vec![PathId(3), PathId(8)],
            "priority ties prefer lower PathId",
            vec![PathId(3), PathId(8)],
            ids
        );

        crate::test_complete!("test_path_set_by_priority_tie_breaks_by_path_id");
    }

    #[test]
    fn test_path_set_primary_only_exposes_conservative_fallback() {
        init_test("test_path_set_primary_only_exposes_conservative_fallback");
        let set = PathSet::new(PathSelectionPolicy::PrimaryOnly);

        set.register(test_path(3).with_characteristics(PathCharacteristics::backup()));
        set.register(test_path(1).with_characteristics(PathCharacteristics {
            latency_ms: 15,
            bandwidth_bps: 4_000_000,
            loss_rate: 0.02,
            jitter_ms: 3,
            is_primary: false,
            priority: 20,
        }));

        let selected = set.select_paths();
        crate::assert_with_log!(
            selected.is_empty(),
            "primary_only keeps existing empty selection behavior",
            true,
            selected.is_empty()
        );

        let decision = set.select_paths_with_decision();
        crate::assert_with_log!(
            decision.selected.is_empty(),
            "decision selected remains empty",
            true,
            decision.selected.is_empty()
        );
        crate::assert_with_log!(
            decision.fallback_policy_id() == Some("best-quality"),
            "fallback policy id",
            Some("best-quality"),
            decision.fallback_policy_id()
        );
        crate::assert_with_log!(
            decision.downgrade_reason_id() == Some("no-primary-path"),
            "downgrade reason id",
            Some("no-primary-path"),
            decision.downgrade_reason_id()
        );
        let fallback_ids = decision.fallback_ids();
        let expected_ids = [PathId(1)];
        crate::assert_with_log!(
            fallback_ids.as_slice() == expected_ids.as_slice(),
            "fallback picks best available path",
            expected_ids.as_slice(),
            fallback_ids.as_slice()
        );

        crate::test_complete!("test_path_set_primary_only_exposes_conservative_fallback");
    }

    #[test]
    fn test_path_set_best_quality_reports_requested_paths_unavailable() {
        init_test("test_path_set_best_quality_reports_requested_paths_unavailable");
        let set = PathSet::new(PathSelectionPolicy::BestQuality { count: 2 });

        set.register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        let unavailable = test_path(2).with_characteristics(PathCharacteristics::backup());
        unavailable.set_state(PathState::Unavailable);
        set.register(unavailable);

        let decision = set.select_paths_with_decision();
        let selected_ids = decision.selected_ids();
        let expected_ids = [PathId(1)];
        crate::assert_with_log!(
            selected_ids.as_slice() == expected_ids.as_slice(),
            "best-quality keeps usable selection",
            expected_ids.as_slice(),
            selected_ids.as_slice()
        );
        crate::assert_with_log!(
            decision.fallback.is_empty(),
            "no separate fallback paths needed",
            true,
            decision.fallback.is_empty()
        );
        crate::assert_with_log!(
            decision.downgrade_reason
                == Some(PathSelectionDowngradeReason::RequestedPathsUnavailable {
                    requested: 2,
                    available: 1,
                }),
            "downgrade records insufficient usable paths",
            Some(PathSelectionDowngradeReason::RequestedPathsUnavailable {
                requested: 2,
                available: 1,
            }),
            decision.downgrade_reason
        );

        crate::test_complete!("test_path_set_best_quality_reports_requested_paths_unavailable");
    }

    #[test]
    fn test_experimental_transport_decision_gate_disabled_falls_back_to_round_robin() {
        init_test("test_experimental_transport_decision_gate_disabled_falls_back_to_round_robin");

        let aggregator = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::UseAll,
            experiment_gate: ExperimentalTransportGate::Disabled,
            ..AggregatorConfig::default()
        });

        aggregator
            .paths()
            .register(test_path(3).with_characteristics(PathCharacteristics::backup()));
        aggregator
            .paths()
            .register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        aggregator.paths().register(test_path(2));

        let decision = aggregator.experimental_transport_decision(TransportExperimentContext::new(
            "TW-MULTIPATH",
            "aa08-gate-disabled-001",
        ));

        crate::assert_with_log!(
            decision.path_policy_id() == "use-all",
            "requested policy id preserved",
            "use-all",
            decision.path_policy_id()
        );
        crate::assert_with_log!(
            decision.effective_path_policy_id() == "round-robin",
            "effective policy falls back to conservative round-robin",
            "round-robin",
            decision.effective_path_policy_id()
        );
        crate::assert_with_log!(
            decision.downgrade_reason_id() == Some("experimental-gate-disabled"),
            "preview gate downgrade emitted",
            Some("experimental-gate-disabled"),
            decision.downgrade_reason_id()
        );
        crate::assert_with_log!(
            decision.path_decision.selected_path_count() == 1,
            "round-robin selects one conservative path",
            1,
            decision.path_decision.selected_path_count()
        );
        let selected_ids = decision.path_decision.selected_ids();
        let expected_ids = [PathId(1)];
        crate::assert_with_log!(
            selected_ids.as_slice() == expected_ids.as_slice(),
            "conservative round-robin remains deterministic",
            expected_ids.as_slice(),
            selected_ids.as_slice()
        );

        crate::test_complete!(
            "test_experimental_transport_decision_gate_disabled_falls_back_to_round_robin"
        );
    }

    #[test]
    fn test_experimental_transport_decision_preview_honors_multipath_policy() {
        init_test("test_experimental_transport_decision_preview_honors_multipath_policy");

        let aggregator = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::BestQuality { count: 2 },
            experiment_gate: ExperimentalTransportGate::MultipathPreview,
            ..AggregatorConfig::default()
        });

        aggregator
            .paths()
            .register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        aggregator
            .paths()
            .register(test_path(2).with_characteristics(PathCharacteristics {
                latency_ms: 20,
                bandwidth_bps: 5_000_000,
                loss_rate: 0.01,
                jitter_ms: 5,
                is_primary: false,
                priority: 20,
            }));
        aggregator
            .paths()
            .register(test_path(3).with_characteristics(PathCharacteristics::backup()));

        let decision = aggregator.experimental_transport_decision(TransportExperimentContext::new(
            "TW-MULTIPATH",
            "aa08-preview-001",
        ));

        crate::assert_with_log!(
            decision.effective_path_policy_id() == "best-quality",
            "preview gate honors requested multipath policy",
            "best-quality",
            decision.effective_path_policy_id()
        );
        crate::assert_with_log!(
            decision.downgrade_reason.is_none(),
            "no gate downgrade when preview enabled",
            true,
            decision.downgrade_reason.is_none()
        );
        let selected_ids = decision.path_decision.selected_ids();
        let expected_ids = [PathId(1), PathId(2)];
        crate::assert_with_log!(
            selected_ids.as_slice() == expected_ids.as_slice(),
            "best-quality preview selects deterministic top paths",
            expected_ids.as_slice(),
            selected_ids.as_slice()
        );

        crate::test_complete!(
            "test_experimental_transport_decision_preview_honors_multipath_policy"
        );
    }

    #[test]
    fn test_experimental_transport_decision_coding_preview_stays_fail_closed() {
        init_test("test_experimental_transport_decision_coding_preview_stays_fail_closed");

        let aggregator = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::RoundRobin,
            experiment_gate: ExperimentalTransportGate::MultipathPreview,
            coding_policy: TransportCodingPolicy::RaptorQFecPreview,
            ..AggregatorConfig::default()
        });

        aggregator.paths().register(test_path(7));

        let decision = aggregator.experimental_transport_decision(TransportExperimentContext::new(
            "TW-BURST",
            "aa08-coding-001",
        ));

        crate::assert_with_log!(
            decision.coding_policy_id() == "raptorq-fec-preview",
            "requested coding policy id preserved",
            "raptorq-fec-preview",
            decision.coding_policy_id()
        );
        crate::assert_with_log!(
            decision.effective_coding_policy_id() == "disabled",
            "coding preview falls back until RaptorQ closure completes",
            "disabled",
            decision.effective_coding_policy_id()
        );
        crate::assert_with_log!(
            decision.downgrade_reason_id() == Some("raptorq-closure-pending"),
            "coding downgrade reason emitted",
            Some("raptorq-closure-pending"),
            decision.downgrade_reason_id()
        );

        let log_fields = decision.log_fields();
        crate::assert_with_log!(
            log_fields.get("workload_id").map(String::as_str) == Some("TW-BURST"),
            "workload id logged",
            Some("TW-BURST"),
            log_fields.get("workload_id").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("path_count").map(String::as_str) == Some("1"),
            "usable path count logged",
            Some("1"),
            log_fields.get("path_count").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("selected_path_ids").map(String::as_str) == Some("7"),
            "selected path ids logged",
            Some("7"),
            log_fields.get("selected_path_ids").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("fallback_path_count").map(String::as_str) == Some("0"),
            "fallback path count logged",
            Some("0"),
            log_fields.get("fallback_path_count").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields
                .get("benchmark_correlation_id")
                .map(String::as_str)
                == Some("aa08-coding-001"),
            "benchmark correlation logged",
            Some("aa08-coding-001"),
            log_fields
                .get("benchmark_correlation_id")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("downgrade_reason").map(String::as_str)
                == Some("raptorq-closure-pending"),
            "downgrade reason logged",
            Some("raptorq-closure-pending"),
            log_fields.get("downgrade_reason").map(String::as_str)
        );

        crate::test_complete!(
            "test_experimental_transport_decision_coding_preview_stays_fail_closed"
        );
    }

    #[test]
    fn test_experimental_transport_decision_logs_fallback_inventory() {
        init_test("test_experimental_transport_decision_logs_fallback_inventory");

        let aggregator = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::PrimaryOnly,
            experiment_gate: ExperimentalTransportGate::MultipathPreview,
            ..AggregatorConfig::default()
        });

        aggregator
            .paths()
            .register(test_path(3).with_characteristics(PathCharacteristics::backup()));
        aggregator
            .paths()
            .register(test_path(1).with_characteristics(PathCharacteristics {
                latency_ms: 15,
                bandwidth_bps: 4_000_000,
                loss_rate: 0.02,
                jitter_ms: 3,
                is_primary: false,
                priority: 20,
            }));

        let decision = aggregator.experimental_transport_decision(TransportExperimentContext::new(
            "TW-HANDOFF",
            "aa08-fallback-001",
        ));
        let log_fields = decision.log_fields();

        crate::assert_with_log!(
            log_fields.get("path_count").map(String::as_str) == Some("2"),
            "available path inventory logged",
            Some("2"),
            log_fields.get("path_count").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("selected_path_ids").map(String::as_str) == Some(""),
            "selected path ids stay empty when no primary path is usable",
            Some(""),
            log_fields.get("selected_path_ids").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("fallback_path_count").map(String::as_str) == Some("1"),
            "fallback path count logged",
            Some("1"),
            log_fields.get("fallback_path_count").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("fallback_path_ids").map(String::as_str) == Some("1"),
            "fallback path ids logged",
            Some("1"),
            log_fields.get("fallback_path_ids").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("path_downgrade_reason").map(String::as_str) == Some("no-primary-path"),
            "path downgrade reason logged",
            Some("no-primary-path"),
            log_fields.get("path_downgrade_reason").map(String::as_str)
        );

        crate::test_complete!("test_experimental_transport_decision_logs_fallback_inventory");
    }

    fn assert_transport_decision_log_keyset(fields: &BTreeMap<String, String>) {
        let actual: std::collections::BTreeSet<&str> = fields.keys().map(String::as_str).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "workload_id",
            "benchmark_correlation_id",
            "experimental_gate_id",
            "path_policy_id",
            "effective_path_policy_id",
            "requested_path_count",
            "path_count",
            "selected_path_count",
            "fallback_path_count",
            "selected_path_ids",
            "fallback_path_ids",
            "fallback_policy_id",
            "path_downgrade_reason",
            "downgrade_reason",
            "coding_policy_id",
            "effective_coding_policy_id",
        ]
        .into_iter()
        .collect();

        crate::assert_with_log!(
            actual == expected,
            "transport decision log fields stay aligned with the AA-08 contract keyset",
            format!("{expected:?}"),
            format!("{actual:?}")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_experimental_transport_decision_log_fields_cover_contract_modes() {
        init_test("test_experimental_transport_decision_log_fields_cover_contract_modes");

        let gate_disabled = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::UseAll,
            experiment_gate: ExperimentalTransportGate::Disabled,
            ..AggregatorConfig::default()
        });
        gate_disabled
            .paths()
            .register(test_path(3).with_characteristics(PathCharacteristics::backup()));
        gate_disabled
            .paths()
            .register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        gate_disabled.paths().register(test_path(2));

        let gate_disabled_fields = gate_disabled
            .experimental_transport_decision(TransportExperimentContext::new(
                "TW-MULTIPATH",
                "aa08-gate-contract-001",
            ))
            .log_fields();
        assert_transport_decision_log_keyset(&gate_disabled_fields);
        crate::assert_with_log!(
            gate_disabled_fields
                .get("requested_path_count")
                .map(String::as_str)
                == Some("all"),
            "unbounded policies log requested_path_count as all",
            Some("all"),
            gate_disabled_fields
                .get("requested_path_count")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            gate_disabled_fields
                .get("effective_path_policy_id")
                .map(String::as_str)
                == Some("round-robin"),
            "gate-disabled preview logs conservative effective policy",
            Some("round-robin"),
            gate_disabled_fields
                .get("effective_path_policy_id")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            gate_disabled_fields
                .get("selected_path_count")
                .map(String::as_str)
                == Some("1"),
            "gate-disabled preview logs the conservative selected path count",
            Some("1"),
            gate_disabled_fields
                .get("selected_path_count")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            gate_disabled_fields
                .get("path_downgrade_reason")
                .map(String::as_str)
                == Some(""),
            "gate-level fallback keeps path_downgrade_reason empty",
            Some(""),
            gate_disabled_fields
                .get("path_downgrade_reason")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            gate_disabled_fields
                .get("downgrade_reason")
                .map(String::as_str)
                == Some("experimental-gate-disabled"),
            "gate-level fallback logs the preview downgrade reason",
            Some("experimental-gate-disabled"),
            gate_disabled_fields
                .get("downgrade_reason")
                .map(String::as_str)
        );

        let bounded_preview = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::BestQuality { count: 2 },
            experiment_gate: ExperimentalTransportGate::MultipathPreview,
            ..AggregatorConfig::default()
        });
        bounded_preview
            .paths()
            .register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        bounded_preview
            .paths()
            .register(test_path(2).with_characteristics(PathCharacteristics {
                latency_ms: 20,
                bandwidth_bps: 5_000_000,
                loss_rate: 0.01,
                jitter_ms: 5,
                is_primary: false,
                priority: 20,
            }));
        bounded_preview
            .paths()
            .register(test_path(3).with_characteristics(PathCharacteristics::backup()));

        let bounded_preview_fields = bounded_preview
            .experimental_transport_decision(TransportExperimentContext::new(
                "TW-MULTIPATH",
                "aa08-bounded-contract-001",
            ))
            .log_fields();
        assert_transport_decision_log_keyset(&bounded_preview_fields);
        crate::assert_with_log!(
            bounded_preview_fields
                .get("requested_path_count")
                .map(String::as_str)
                == Some("2"),
            "bounded multipath preview logs requested path count",
            Some("2"),
            bounded_preview_fields
                .get("requested_path_count")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            bounded_preview_fields
                .get("selected_path_ids")
                .map(String::as_str)
                == Some("1,2"),
            "bounded multipath preview logs deterministic selected path ids",
            Some("1,2"),
            bounded_preview_fields
                .get("selected_path_ids")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            bounded_preview_fields
                .get("fallback_path_ids")
                .map(String::as_str)
                == Some(""),
            "bounded preview leaves fallback inventory empty when the request is honored",
            Some(""),
            bounded_preview_fields
                .get("fallback_path_ids")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            bounded_preview_fields
                .get("downgrade_reason")
                .map(String::as_str)
                == Some(""),
            "bounded preview leaves gate-level downgrade empty when honored",
            Some(""),
            bounded_preview_fields
                .get("downgrade_reason")
                .map(String::as_str)
        );

        let primary_fallback = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::PrimaryOnly,
            experiment_gate: ExperimentalTransportGate::MultipathPreview,
            ..AggregatorConfig::default()
        });
        primary_fallback
            .paths()
            .register(test_path(3).with_characteristics(PathCharacteristics::backup()));
        primary_fallback
            .paths()
            .register(test_path(1).with_characteristics(PathCharacteristics {
                latency_ms: 15,
                bandwidth_bps: 4_000_000,
                loss_rate: 0.02,
                jitter_ms: 3,
                is_primary: false,
                priority: 20,
            }));

        let primary_fallback_fields = primary_fallback
            .experimental_transport_decision(TransportExperimentContext::new(
                "TW-HANDOFF",
                "aa08-path-fallback-001",
            ))
            .log_fields();
        assert_transport_decision_log_keyset(&primary_fallback_fields);
        crate::assert_with_log!(
            primary_fallback_fields
                .get("fallback_policy_id")
                .map(String::as_str)
                == Some("best-quality"),
            "primary-path fallback logs the conservative fallback policy",
            Some("best-quality"),
            primary_fallback_fields
                .get("fallback_policy_id")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            primary_fallback_fields
                .get("fallback_path_ids")
                .map(String::as_str)
                == Some("1"),
            "primary-path fallback logs deterministic fallback path ids",
            Some("1"),
            primary_fallback_fields
                .get("fallback_path_ids")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            primary_fallback_fields
                .get("path_downgrade_reason")
                .map(String::as_str)
                == Some("no-primary-path"),
            "primary-path fallback logs the path-level downgrade reason",
            Some("no-primary-path"),
            primary_fallback_fields
                .get("path_downgrade_reason")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            primary_fallback_fields
                .get("downgrade_reason")
                .map(String::as_str)
                == Some(""),
            "primary-path fallback keeps gate-level downgrade empty",
            Some(""),
            primary_fallback_fields
                .get("downgrade_reason")
                .map(String::as_str)
        );

        crate::test_complete!(
            "test_experimental_transport_decision_log_fields_cover_contract_modes"
        );
    }

    #[test]
    fn test_path_set_register_advances_next_id() {
        init_test("test_path_set_register_advances_next_id");

        let set = PathSet::new(PathSelectionPolicy::RoundRobin);
        set.register(test_path(0));

        let created = set.create_path(
            "generated",
            "localhost:9000",
            PathCharacteristics::default(),
        );
        crate::assert_with_log!(
            created == PathId(1),
            "create_path advances beyond caller-supplied ids",
            PathId(1),
            created
        );
        crate::assert_with_log!(
            set.get(PathId(0)).is_some(),
            "original registered path is preserved",
            true,
            set.get(PathId(0)).is_some()
        );

        crate::test_complete!("test_path_set_register_advances_next_id");
    }

    // Test 6: Deduplicator basic operation
    #[test]
    fn test_deduplicator_basic() {
        init_test("test_deduplicator_basic");
        let dedup = SymbolDeduplicator::new(DeduplicatorConfig::default());

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let path = PathId(1);
        let now = Time::ZERO;

        // First time - not duplicate
        let first = dedup.check_and_record(&symbol, path, now);
        crate::assert_with_log!(first, "first record", true, first);

        // Second time - duplicate
        let second = dedup.check_and_record(&symbol, path, now);
        crate::assert_with_log!(!second, "second duplicate", false, second);

        let stats = dedup.stats();
        crate::assert_with_log!(
            stats.unique_symbols == 1,
            "unique_symbols",
            1,
            stats.unique_symbols
        );
        crate::assert_with_log!(
            stats.duplicates_detected == 1,
            "duplicates_detected",
            1,
            stats.duplicates_detected
        );
        crate::test_complete!("test_deduplicator_basic");
    }

    // Test 7: Deduplicator tracks first path
    #[test]
    fn test_deduplicator_tracks_path() {
        init_test("test_deduplicator_tracks_path");
        let config = DeduplicatorConfig {
            track_path: true,
            ..Default::default()
        };
        let dedup = SymbolDeduplicator::new(config);

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let path1 = PathId(1);
        let path2 = PathId(2);

        dedup.check_and_record(&symbol, path1, Time::ZERO);
        dedup.check_and_record(&symbol, path2, Time::ZERO); // Duplicate

        let first = dedup.first_path(symbol.object_id(), symbol.id());
        crate::assert_with_log!(first == Some(path1), "first path", Some(path1), first);
        crate::test_complete!("test_deduplicator_tracks_path");
    }

    // Test 8: Reorderer in-order delivery
    #[test]
    fn test_reorderer_in_order() {
        init_test("test_reorderer_in_order");
        let config = ReordererConfig {
            immediate_delivery: false,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        let path = PathId(1);
        let now = Time::ZERO;

        // Deliver symbols in order
        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let s1 = Symbol::new_for_test(1, 0, 1, &[1]);
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);

        let ready0 = reorderer.process(s0, path, now);
        let ready1 = reorderer.process(s1, path, now);
        let ready2 = reorderer.process(s2, path, now);

        let len0 = ready0.len();
        crate::assert_with_log!(len0 == 1, "ready0 len", 1, len0);
        let len1 = ready1.len();
        crate::assert_with_log!(len1 == 1, "ready1 len", 1, len1);
        let len2 = ready2.len();
        crate::assert_with_log!(len2 == 1, "ready2 len", 1, len2);

        let stats = reorderer.stats();
        crate::assert_with_log!(
            stats.in_order_deliveries == 3,
            "in_order_deliveries",
            3,
            stats.in_order_deliveries
        );
        crate::assert_with_log!(
            stats.reordered_deliveries == 0,
            "reordered_deliveries",
            0,
            stats.reordered_deliveries
        );
        crate::test_complete!("test_reorderer_in_order");
    }

    // Test 9: Reorderer out-of-order buffering
    #[test]
    fn test_reorderer_out_of_order() {
        init_test("test_reorderer_out_of_order");
        let config = ReordererConfig {
            immediate_delivery: false,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        let path = PathId(1);
        let now = Time::ZERO;

        // Deliver out of order: 0, 2, 1
        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);
        let s1 = Symbol::new_for_test(1, 0, 1, &[1]);

        let ready0 = reorderer.process(s0, path, now);
        let len0 = ready0.len();
        crate::assert_with_log!(len0 == 1, "ready0 len", 1, len0); // s0 delivered

        let ready2 = reorderer.process(s2, path, now);
        let len2 = ready2.len();
        crate::assert_with_log!(len2 == 0, "ready2 len", 0, len2); // s2 buffered, waiting for s1

        let ready1 = reorderer.process(s1, path, now);
        let len1 = ready1.len();
        crate::assert_with_log!(len1 == 2, "ready1 len", 2, len1); // s1 and s2 delivered

        let stats = reorderer.stats();
        crate::assert_with_log!(
            stats.in_order_deliveries == 2,
            "in_order_deliveries",
            2,
            stats.in_order_deliveries
        );
        crate::assert_with_log!(
            stats.reordered_deliveries == 1,
            "reordered_deliveries",
            1,
            stats.reordered_deliveries
        );
        crate::test_complete!("test_reorderer_out_of_order");
    }

    // Test 10: Reorderer timeout flush
    #[test]
    fn test_reorderer_timeout() {
        init_test("test_reorderer_timeout");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_wait_time: Time::from_millis(100),
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        let path = PathId(1);

        // Deliver out of order: 0, 2 (skip 1)
        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);

        reorderer.process(s0, path, Time::ZERO);
        reorderer.process(s2, path, Time::from_millis(10));

        // Before timeout
        let flushed = reorderer.flush_timeouts(Time::from_millis(50));
        let len_before = flushed.len();
        crate::assert_with_log!(len_before == 0, "flushed before len", 0, len_before);

        // After timeout
        let flushed = reorderer.flush_timeouts(Time::from_millis(200));
        let len_after = flushed.len();
        crate::assert_with_log!(len_after == 1, "flushed after len", 1, len_after); // s2 flushed
        crate::test_complete!("test_reorderer_timeout");
    }

    // Test 10.1: Reorderer gap too large gives up and advances
    #[test]
    fn test_reorderer_gap_too_large_advances() {
        init_test("test_reorderer_gap_too_large_advances");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_sequence_gap: 2,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        let path = PathId(1);
        let now = Time::ZERO;

        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let s5 = Symbol::new_for_test(1, 0, 5, &[5]);
        let s6 = Symbol::new_for_test(1, 0, 6, &[6]);

        let out0 = reorderer.process(s0, path, now);
        crate::assert_with_log!(out0.len() == 1, "out0 len", 1, out0.len());

        // Gap 4 > max_sequence_gap => deliver immediately and advance
        let out5 = reorderer.process(s5, path, now);
        crate::assert_with_log!(out5.len() == 1, "out5 len", 1, out5.len());

        let out6 = reorderer.process(s6, path, now);
        crate::assert_with_log!(out6.len() == 1, "out6 len", 1, out6.len());

        crate::test_complete!("test_reorderer_gap_too_large_advances");
    }

    // Test 11: MultipathAggregator basic flow
    #[test]
    fn test_aggregator_basic() {
        init_test("test_aggregator_basic");
        let config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(config);

        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);

        let result = aggregator.process(symbol.clone(), path, Time::ZERO);
        crate::assert_with_log!(
            !result.was_duplicate,
            "first not duplicate",
            false,
            result.was_duplicate
        );

        // Duplicate
        let result2 = aggregator.process(symbol, path, Time::ZERO);
        crate::assert_with_log!(
            result2.was_duplicate,
            "duplicate flagged",
            true,
            result2.was_duplicate
        );
        let ready_empty = result2.ready.is_empty();
        crate::assert_with_log!(ready_empty, "ready empty", true, ready_empty);
        crate::test_complete!("test_aggregator_basic");
    }

    // Test 11.1: MultipathAggregator deduplicates across paths
    #[test]
    fn test_aggregator_multi_path_dedup() {
        init_test("test_aggregator_multi_path_dedup");
        let config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(config);

        let p1 =
            aggregator
                .paths()
                .create_path("p1", "localhost:1", PathCharacteristics::default());
        let p2 = aggregator
            .paths()
            .create_path("p2", "localhost:2", PathCharacteristics::backup());

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);

        let first = aggregator.process(symbol.clone(), p1, Time::ZERO);
        crate::assert_with_log!(
            !first.was_duplicate,
            "first unique",
            false,
            first.was_duplicate
        );

        let second = aggregator.process(symbol, p2, Time::ZERO);
        crate::assert_with_log!(
            second.was_duplicate,
            "duplicate across paths",
            true,
            second.was_duplicate
        );

        let stats = aggregator.dedup.stats();
        crate::assert_with_log!(
            stats.unique_symbols == 1,
            "unique symbols",
            1,
            stats.unique_symbols
        );
        crate::assert_with_log!(
            stats.duplicates_detected == 1,
            "duplicates detected",
            1,
            stats.duplicates_detected
        );

        let path = aggregator.paths().get(p2);
        crate::assert_with_log!(path.is_some(), "path exists", true, path.is_some());
        if let Some(path) = path {
            let duplicates = path.duplicates_received.load(Ordering::Relaxed);
            crate::assert_with_log!(duplicates == 1, "path duplicates", 1, duplicates);
        }

        crate::test_complete!("test_aggregator_multi_path_dedup");
    }

    // Test 12: MultipathAggregator object completion
    #[test]
    fn test_aggregator_object_complete() {
        init_test("test_aggregator_object_complete");
        let config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(config);

        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let object_id = symbol.object_id();

        aggregator.process(symbol.clone(), path, Time::ZERO);

        // Clear state
        aggregator.object_complete(object_id);

        // Same symbol is now "new" again
        let result = aggregator.process(symbol, path, Time::ZERO);
        crate::assert_with_log!(
            !result.was_duplicate,
            "post-complete not duplicate",
            false,
            result.was_duplicate
        );
        crate::test_complete!("test_aggregator_object_complete");
    }

    // Test 13: PathSet aggregate stats
    #[test]
    fn test_path_set_stats() {
        init_test("test_path_set_stats");
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        let p1 = set.create_path(
            "p1",
            "a",
            PathCharacteristics {
                bandwidth_bps: 1_000_000,
                ..Default::default()
            },
        );
        let p2 = set.create_path(
            "p2",
            "b",
            PathCharacteristics {
                bandwidth_bps: 2_000_000,
                ..Default::default()
            },
        );

        if let Some(path) = set.get(p1) {
            path.symbols_received.store(100, Ordering::Relaxed);
        }
        if let Some(path) = set.get(p2) {
            path.symbols_received.store(200, Ordering::Relaxed);
        }

        let stats = set.stats();
        crate::assert_with_log!(stats.path_count == 2, "path_count", 2, stats.path_count);
        crate::assert_with_log!(
            stats.total_received == 300,
            "total_received",
            300,
            stats.total_received
        );
        crate::assert_with_log!(
            stats.aggregate_bandwidth_bps == 3_000_000,
            "aggregate_bandwidth_bps",
            3_000_000,
            stats.aggregate_bandwidth_bps
        );
        crate::test_complete!("test_path_set_stats");
    }

    // Test 14: Immediate delivery mode
    #[test]
    fn test_immediate_delivery() {
        init_test("test_immediate_delivery");
        let config = ReordererConfig {
            immediate_delivery: true,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        // Out of order should still deliver immediately
        let s5 = Symbol::new_for_test(1, 0, 5, &[5]);
        let ready = reorderer.process(s5, PathId(1), Time::ZERO);

        let len = ready.len();
        crate::assert_with_log!(len == 1, "ready len", 1, len);
        crate::test_complete!("test_immediate_delivery");
    }

    // Test 15: Aggregator stats
    #[test]
    fn test_aggregator_stats() {
        init_test("test_aggregator_stats");
        let config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(config);

        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        for i in 0..10 {
            let symbol = Symbol::new_for_test(1, 0, i, &[i as u8]);
            aggregator.process(symbol, path, Time::ZERO);
        }

        let stats = aggregator.stats();
        crate::assert_with_log!(
            stats.total_processed == 10,
            "total_processed",
            10,
            stats.total_processed
        );
        crate::assert_with_log!(
            stats.paths.path_count == 1,
            "path_count",
            1,
            stats.paths.path_count
        );
        crate::test_complete!("test_aggregator_stats");
    }

    // ========================================================================
    // Audit regression tests
    // ========================================================================

    #[test]
    fn flush_respects_interval_gating() {
        init_test("flush_respects_interval_gating");
        let config = AggregatorConfig {
            flush_interval: Time::from_millis(100),
            ..Default::default()
        };
        let aggregator = MultipathAggregator::new(config);
        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        // Process a symbol with out-of-order ESI to put something in the reorderer buffer
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);
        aggregator.process(s2, path, Time::ZERO);

        // Flush too soon — should return empty
        let early = aggregator.flush(Time::from_millis(50));
        crate::assert_with_log!(
            early.is_empty(),
            "flush before interval returns empty",
            true,
            early.is_empty()
        );

        // Flush after interval — should succeed
        let later = aggregator.flush(Time::from_millis(200));
        // Symbol 2 was buffered waiting for 0,1 — if max_wait_time passed, it should flush
        // (default max_wait_time is 100ms, and symbol was received at t=0, flush at t=200)
        crate::assert_with_log!(
            later.len() == 1,
            "flush after interval returns buffered symbol",
            1,
            later.len()
        );

        crate::test_complete!("flush_respects_interval_gating");
    }

    #[test]
    fn dedup_prune_removes_expired_objects() {
        init_test("dedup_prune_removes_expired_objects");
        let config = DeduplicatorConfig {
            entry_ttl: Time::from_secs(10),
            ..Default::default()
        };
        let dedup = SymbolDeduplicator::new(config);
        let path = PathId(1);

        // Record a symbol at t=0
        let s = Symbol::new_for_test(1, 0, 0, &[1]);
        dedup.check_and_record(&s, path, Time::ZERO);

        let before = dedup.stats();
        crate::assert_with_log!(
            before.objects_tracked == 1,
            "1 object tracked before prune",
            1,
            before.objects_tracked
        );

        // Prune at t=5 (within TTL) — should keep
        let pruned_early = dedup.prune(Time::from_secs(5));
        crate::assert_with_log!(pruned_early == 0, "nothing pruned early", 0, pruned_early);

        // Prune at t=15 (past TTL) — should remove
        let pruned_late = dedup.prune(Time::from_secs(15));
        crate::assert_with_log!(pruned_late == 1, "1 object pruned", 1, pruned_late);

        let after = dedup.stats();
        crate::assert_with_log!(
            after.objects_tracked == 0,
            "0 objects after prune",
            0,
            after.objects_tracked
        );

        crate::test_complete!("dedup_prune_removes_expired_objects");
    }

    #[test]
    fn reorderer_late_duplicate_ignored() {
        init_test("reorderer_late_duplicate_ignored");
        let config = ReordererConfig {
            immediate_delivery: false,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);
        let now = Time::ZERO;

        // Deliver 0, 1, 2 in order
        reorderer.process(Symbol::new_for_test(1, 0, 0, &[0]), path, now);
        reorderer.process(Symbol::new_for_test(1, 0, 1, &[1]), path, now);
        reorderer.process(Symbol::new_for_test(1, 0, 2, &[2]), path, now);

        // Late duplicate: seq 0 again
        let late = reorderer.process(Symbol::new_for_test(1, 0, 0, &[0]), path, now);
        crate::assert_with_log!(
            late.is_empty(),
            "late duplicate produces no output",
            true,
            late.is_empty()
        );

        let stats = reorderer.stats();
        crate::assert_with_log!(
            stats.in_order_deliveries == 3,
            "still 3 in-order deliveries",
            3,
            stats.in_order_deliveries
        );

        crate::test_complete!("reorderer_late_duplicate_ignored");
    }

    #[test]
    fn path_set_round_robin_cycles() {
        init_test("path_set_round_robin_cycles");
        let set = PathSet::new(PathSelectionPolicy::RoundRobin);

        set.register(test_path(2));
        set.register(test_path(1));

        // RoundRobin should select one path per call, cycling through
        let mut ids = Vec::new();
        for _ in 0..4 {
            let selected = set.select_paths();
            crate::assert_with_log!(
                selected.len() == 1,
                "round robin selects 1",
                1,
                selected.len()
            );
            ids.push(selected[0].id);
        }

        crate::assert_with_log!(
            ids == vec![PathId(1), PathId(2), PathId(1), PathId(2)],
            "round robin follows stable PathId order",
            vec![PathId(1), PathId(2), PathId(1), PathId(2)],
            ids
        );

        crate::test_complete!("path_set_round_robin_cycles");
    }

    #[test]
    fn path_set_remove_path() {
        init_test("path_set_remove_path");
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        let id = set.register(test_path(1));
        set.register(test_path(2));

        crate::assert_with_log!(set.count() == 2, "2 paths", 2, set.count());

        let removed = set.remove(id);
        crate::assert_with_log!(removed.is_some(), "removed path", true, removed.is_some());
        crate::assert_with_log!(set.count() == 1, "1 path after remove", 1, set.count());

        // Remove again — should return None
        let removed_again = set.remove(id);
        crate::assert_with_log!(
            removed_again.is_none(),
            "double remove returns None",
            true,
            removed_again.is_none()
        );

        crate::test_complete!("path_set_remove_path");
    }

    #[test]
    fn aggregation_error_display_variants() {
        init_test("aggregation_error_display_variants");

        let e1 = AggregationError::PathNotFound { path: PathId(42) };
        crate::assert_with_log!(
            e1.to_string().contains("42"),
            "path not found contains id",
            true,
            e1.to_string().contains("42")
        );

        let e2 = AggregationError::PathUnavailable { path: PathId(7) };
        crate::assert_with_log!(
            e2.to_string().contains("unavailable"),
            "path unavailable display",
            true,
            e2.to_string().contains("unavailable")
        );

        let e3 = AggregationError::InvalidSequence {
            object_id: ObjectId::new(0, 1),
            expected: 5,
            received: 10,
        };
        let msg = e3.to_string();
        crate::assert_with_log!(
            msg.contains("expected 5") && msg.contains("got 10"),
            "invalid sequence display",
            true,
            msg.contains("expected 5") && msg.contains("got 10")
        );

        crate::test_complete!("aggregation_error_display_variants");
    }

    // ========================================================================
    // Bug-fix regression tests
    // ========================================================================

    /// Regression: large gap reset must drain buffered symbols, not drop them.
    #[test]
    fn reorderer_large_gap_delivers_buffered_before_reset() {
        init_test("reorderer_large_gap_delivers_buffered_before_reset");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_sequence_gap: 3,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);
        let now = Time::ZERO;

        // Deliver seq 0 in-order.
        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let out0 = reorderer.process(s0, path, now);
        crate::assert_with_log!(out0.len() == 1, "s0 delivered", 1, out0.len());

        // Buffer seq 2 and 3 (out-of-order, waiting for seq 1).
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);
        let s3 = Symbol::new_for_test(1, 0, 3, &[3]);
        let out2 = reorderer.process(s2, path, now);
        let out3 = reorderer.process(s3, path, now);
        crate::assert_with_log!(out2.is_empty(), "s2 buffered", 0, out2.len());
        crate::assert_with_log!(out3.is_empty(), "s3 buffered", 0, out3.len());

        // Now deliver seq 100 — gap is 99 > max_sequence_gap(3).
        // Buffered symbols 2 and 3 must be delivered, not dropped.
        let s100 = Symbol::new_for_test(1, 0, 100, &[100]);
        let out100 = reorderer.process(s100, path, now);
        crate::assert_with_log!(
            out100.len() == 3,
            "large gap delivers buffered + new",
            3,
            out100.len()
        );

        crate::test_complete!("reorderer_large_gap_delivers_buffered_before_reset");
    }

    /// Regression: dedup must enforce max_objects limit.
    #[test]
    fn dedup_enforces_max_objects() {
        init_test("dedup_enforces_max_objects");
        let config = DeduplicatorConfig {
            max_objects: 2,
            ..Default::default()
        };
        let dedup = SymbolDeduplicator::new(config);
        let path = PathId(1);

        // Record symbols for 2 different objects — both should be tracked.
        let s1 = Symbol::new_for_test(1, 0, 0, &[1]);
        let s2 = Symbol::new_for_test(2, 0, 0, &[2]);
        crate::assert_with_log!(
            dedup.check_and_record(&s1, path, Time::ZERO),
            "obj1 unique",
            true,
            true
        );
        crate::assert_with_log!(
            dedup.check_and_record(&s2, path, Time::ZERO),
            "obj2 unique",
            true,
            true
        );

        // Third object exceeds max_objects — should still return true (unique)
        // but NOT be tracked (so a duplicate won't be detected).
        let s3 = Symbol::new_for_test(3, 0, 0, &[3]);
        let result = dedup.check_and_record(&s3, path, Time::ZERO);
        crate::assert_with_log!(result, "obj3 treated as unique", true, result);

        let stats = dedup.stats();
        crate::assert_with_log!(
            stats.objects_tracked == 2,
            "only 2 objects tracked",
            2,
            stats.objects_tracked
        );
        crate::assert_with_log!(
            stats.unique_symbols == 3,
            "all unique symbols counted",
            3,
            stats.unique_symbols
        );

        crate::test_complete!("dedup_enforces_max_objects");
    }

    /// Regression: dedup must enforce max_symbols_per_object limit.
    #[test]
    fn dedup_enforces_max_symbols_per_object() {
        init_test("dedup_enforces_max_symbols_per_object");
        let config = DeduplicatorConfig {
            max_symbols_per_object: 3,
            ..Default::default()
        };
        let dedup = SymbolDeduplicator::new(config);
        let path = PathId(1);

        // Record 3 symbols for object 1 — all should be tracked.
        for i in 0..3 {
            let s = Symbol::new_for_test(1, 0, i, &[i as u8]);
            let unique = dedup.check_and_record(&s, path, Time::ZERO);
            crate::assert_with_log!(unique, "symbol unique", true, unique);
        }

        // 4th symbol for same object exceeds limit — treated as unique
        // but not recorded.
        let s4 = Symbol::new_for_test(1, 0, 3, &[3]);
        let result = dedup.check_and_record(&s4, path, Time::ZERO);
        crate::assert_with_log!(result, "over-limit symbol treated as unique", true, result);

        let stats = dedup.stats();
        crate::assert_with_log!(
            stats.symbols_tracked == 3,
            "only 3 symbols tracked",
            3,
            stats.symbols_tracked
        );
        crate::assert_with_log!(
            stats.unique_symbols == 4,
            "all unique symbols counted",
            4,
            stats.unique_symbols
        );

        crate::test_complete!("dedup_enforces_max_symbols_per_object");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn aggregator_buffer_full_forces_flush() {
        init_test("aggregator_buffer_full_forces_flush");
        let config = AggregatorConfig {
            reorder: ReordererConfig {
                immediate_delivery: false,
                max_buffer_per_object: 1,
                max_sequence_gap: 10,
                ..Default::default()
            },
            ..Default::default()
        };
        let aggregator = MultipathAggregator::new(config);
        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        // Deliver seq 0, buffer seq 2, then flush seq 2 and deliver seq 3 because the reorder buffer is full.
        let seq0 = aggregator.process(Symbol::new_for_test(1, 0, 0, &[0]), path, Time::ZERO);
        crate::assert_with_log!(
            seq0.ready.len() == 1,
            "seq0 delivered immediately",
            1,
            seq0.ready.len()
        );

        let seq2 = aggregator.process(
            Symbol::new_for_test(1, 0, 2, &[2]),
            path,
            Time::from_millis(1),
        );
        crate::assert_with_log!(
            seq2.ready.is_empty(),
            "seq2 buffered with no output",
            true,
            seq2.ready.is_empty()
        );

        let first_seq3 = aggregator.process(
            Symbol::new_for_test(1, 0, 3, &[3]),
            path,
            Time::from_millis(2),
        );
        crate::assert_with_log!(
            !first_seq3.was_duplicate,
            "buffer-full flush is not classified as duplicate",
            false,
            first_seq3.was_duplicate
        );
        crate::assert_with_log!(
            first_seq3.ready.len() == 2,
            "buffer-full flush produces buffered output",
            2,
            first_seq3.ready.len()
        );
        crate::assert_with_log!(
            first_seq3.ready[0].esi() == 2,
            "buffer-full flush produces seq2",
            2,
            first_seq3.ready[0].esi()
        );
        crate::assert_with_log!(
            first_seq3.ready[1].esi() == 3,
            "buffer-full flush produces seq3",
            3,
            first_seq3.ready[1].esi()
        );

        let stats = aggregator.dedup.stats();
        crate::assert_with_log!(
            stats.unique_symbols == 3,
            "dedup unique count tracks the three delivered symbols",
            3,
            stats.unique_symbols
        );
        crate::assert_with_log!(
            stats.symbols_tracked == 3,
            "dedup tracks the three delivered symbols only",
            3,
            stats.symbols_tracked
        );

        crate::test_complete!("aggregator_buffer_full_forces_flush");
    }

    /// Flush timeout advances next_expected and drains consecutive.
    #[test]
    fn flush_timeout_drains_consecutive_after_advance() {
        init_test("flush_timeout_drains_consecutive_after_advance");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_wait_time: Time::from_millis(50),
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);

        // Deliver seq 0.
        reorderer.process(Symbol::new_for_test(1, 0, 0, &[0]), path, Time::ZERO);

        // Buffer seq 2 at t=0 (will time out at t=50).
        reorderer.process(Symbol::new_for_test(1, 0, 2, &[2]), path, Time::ZERO);

        // Buffer seq 3 at t=40 (will time out at t=90).
        reorderer.process(
            Symbol::new_for_test(1, 0, 3, &[3]),
            path,
            Time::from_millis(40),
        );

        // Flush at t=60: seq 2 timed out (waited 60ms > 50ms).
        // Seq 3 has NOT timed out (waited 20ms < 50ms).
        // After flushing seq 2, next_expected advances to 3,
        // and the consecutive drain pops seq 3 from the buffer.
        let flushed = reorderer.flush_timeouts(Time::from_millis(60));
        crate::assert_with_log!(
            flushed.len() == 2,
            "seq 2 flushed + seq 3 drained",
            2,
            flushed.len()
        );

        let stats = reorderer.stats();
        crate::assert_with_log!(
            stats.symbols_buffered == 0,
            "buffer empty after drain",
            0,
            stats.symbols_buffered
        );

        crate::test_complete!("flush_timeout_drains_consecutive_after_advance");
    }

    #[test]
    fn reorderer_large_gap_u32_max_does_not_overflow() {
        init_test("reorderer_large_gap_u32_max_does_not_overflow");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_sequence_gap: 1,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);

        // seq=u32::MAX when next_expected=0 is a late duplicate in wrapping
        // arithmetic (u32::MAX is logically just before 0), so it is dropped.
        let out = reorderer.process(Symbol::new_for_test(1, 0, u32::MAX, &[1]), path, Time::ZERO);
        crate::assert_with_log!(
            out.is_empty(),
            "u32::MAX is late dup (wrapping)",
            true,
            out.is_empty()
        );

        // Verify a genuine forward gap still works: seq=2 when next_expected=0.
        let out2 = reorderer.process(Symbol::new_for_test(1, 0, 2, &[2]), path, Time::ZERO);
        // gap=2 > max_sequence_gap=1, so gap-too-large branch delivers it.
        crate::assert_with_log!(out2.len() == 1, "forward gap delivered", 1, out2.len());

        crate::test_complete!("reorderer_large_gap_u32_max_does_not_overflow");
    }

    #[test]
    fn flush_timeouts_handles_large_seq_cutoff() {
        init_test("flush_timeouts_handles_large_seq_cutoff");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_wait_time: Time::from_millis(1),
            // Allow a forward gap up to i32::MAX (half the u32 space) which
            // is the maximum representable forward distance in wrapping arithmetic.
            max_sequence_gap: i32::MAX as u32,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);

        // Forward gap of 100 from next_expected=0 → buffered.
        let out = reorderer.process(Symbol::new_for_test(1, 0, 100, &[9]), path, Time::ZERO);
        crate::assert_with_log!(
            out.is_empty(),
            "seq=100 symbol buffered",
            true,
            out.is_empty()
        );

        let flushed = reorderer.flush_timeouts(Time::from_millis(2));
        crate::assert_with_log!(
            flushed.len() == 1,
            "flush emits buffered symbol",
            1,
            flushed.len()
        );
        crate::assert_with_log!(
            flushed[0].esi() == 100,
            "flushed esi is 100",
            100,
            flushed[0].esi()
        );

        crate::test_complete!("flush_timeouts_handles_large_seq_cutoff");
    }

    // =========================================================================
    // Wave 29: Data-type trait coverage
    // =========================================================================

    #[test]
    fn path_id_debug_clone_copy_display() {
        let id = PathId::new(42);
        assert!(format!("{id:?}").contains("42"));
        assert_eq!(format!("{id}"), "Path(42)");
        let cloned = id;
        let copied = id; // Copy
        assert_eq!(cloned, copied);
        assert_eq!(id.0, 42);
    }

    #[test]
    fn path_id_ord_hash() {
        use std::collections::HashSet;
        let a = PathId(1);
        let b = PathId(2);
        assert!(a < b);
        assert!(b > a);
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        set.insert(a); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn path_state_debug_clone_copy_eq() {
        let state = PathState::Active;
        assert!(format!("{state:?}").contains("Active"));
        let cloned = state;
        let copied = state; // Copy
        assert_eq!(cloned, copied);
        assert_ne!(PathState::Active, PathState::Closed);
    }

    #[test]
    fn path_state_from_u8_all_variants() {
        assert_eq!(PathState::from_u8(0), PathState::Active);
        assert_eq!(PathState::from_u8(1), PathState::Degraded);
        assert_eq!(PathState::from_u8(2), PathState::Unavailable);
        assert_eq!(PathState::from_u8(3), PathState::Closed);
        assert_eq!(PathState::from_u8(255), PathState::Closed); // fallback
    }

    #[test]
    fn path_characteristics_debug_clone_default() {
        let chars = PathCharacteristics::default();
        assert!(format!("{chars:?}").contains("PathCharacteristics"));
        assert_eq!(chars.latency_ms, 50);
        assert_eq!(chars.bandwidth_bps, 1_000_000);
        assert!((chars.loss_rate - 0.01).abs() < f64::EPSILON);
        assert_eq!(chars.jitter_ms, 10);
        assert!(!chars.is_primary);
        assert_eq!(chars.priority, 100);
        let cloned = chars.clone();
        assert_eq!(cloned.latency_ms, chars.latency_ms);
    }

    #[test]
    fn path_selection_policy_debug_clone_copy_default() {
        let policy = PathSelectionPolicy::default();
        assert_eq!(policy, PathSelectionPolicy::UseAll);
        assert!(format!("{policy:?}").contains("UseAll"));
        let cloned = policy;
        let copied = policy; // Copy
        assert_eq!(cloned, copied);
    }

    #[test]
    fn path_set_stats_debug_clone() {
        let stats = PathSetStats {
            path_count: 3,
            usable_count: 2,
            total_received: 100,
            total_lost: 5,
            total_duplicates: 10,
            aggregate_bandwidth_bps: 5_000_000,
        };
        assert!(format!("{stats:?}").contains("PathSetStats"));
        let stats2 = stats;
        assert_eq!(stats2.path_count, 3);
        assert_eq!(stats2.total_received, 100);
    }

    #[test]
    fn deduplicator_config_debug_clone_default() {
        let config = DeduplicatorConfig::default();
        assert!(format!("{config:?}").contains("DeduplicatorConfig"));
        assert_eq!(config.max_symbols_per_object, 10_000);
        assert_eq!(config.max_objects, 1_000);
        assert!(config.track_path);
        let cloned = config.clone();
        assert_eq!(cloned.max_objects, config.max_objects);
    }

    #[test]
    fn deduplicator_stats_debug_clone() {
        let stats = DeduplicatorStats {
            objects_tracked: 5,
            symbols_tracked: 50,
            duplicates_detected: 3,
            unique_symbols: 47,
        };
        assert!(format!("{stats:?}").contains("DeduplicatorStats"));
        let stats2 = stats;
        assert_eq!(stats2.objects_tracked, 5);
    }

    #[test]
    fn reorderer_config_debug_clone_default() {
        let config = ReordererConfig::default();
        assert!(format!("{config:?}").contains("ReordererConfig"));
        assert_eq!(config.max_buffer_per_object, 1_000);
        assert!(!config.immediate_delivery);
        assert_eq!(config.max_sequence_gap, 100);
        let cloned = config.clone();
        assert_eq!(cloned.max_buffer_per_object, config.max_buffer_per_object);
    }

    #[test]
    fn reorderer_stats_debug_clone() {
        let stats = ReordererStats {
            objects_tracked: 2,
            symbols_buffered: 10,
            in_order_deliveries: 50,
            reordered_deliveries: 5,
            timeout_deliveries: 1,
        };
        assert!(format!("{stats:?}").contains("ReordererStats"));
        let stats2 = stats;
        assert_eq!(stats2.symbols_buffered, 10);
    }

    #[test]
    fn aggregator_config_debug_clone_default() {
        let config = AggregatorConfig::default();
        assert!(format!("{config:?}").contains("AggregatorConfig"));
        assert!(config.enable_reordering);
        assert_eq!(config.path_policy, PathSelectionPolicy::UseAll);
        let cloned = config.clone();
        assert_eq!(cloned.enable_reordering, config.enable_reordering);
    }

    #[test]
    fn aggregation_error_debug_clone() {
        let err = AggregationError::PathNotFound { path: PathId(1) };
        assert!(format!("{err:?}").contains("PathNotFound"));
        let cloned = err;
        assert!(format!("{cloned}").contains("not found"));
    }

    #[test]
    fn aggregation_error_is_std_error() {
        let err: &dyn std::error::Error = &AggregationError::PathUnavailable { path: PathId(1) };
        let _ = format!("{err}");
        assert!(err.source().is_none());
    }

    #[test]
    fn aggregation_error_into_error() {
        let err = AggregationError::BufferOverflow {
            object_id: ObjectId::new(0, 1),
        };
        let generic: Error = err.into();
        let msg = format!("{generic}");
        assert!(msg.contains("buffer overflow") || msg.contains("overflow"));
    }

    #[test]
    fn transport_path_state_transitions() {
        let path = test_path(1);
        assert_eq!(path.state(), PathState::Active);
        path.set_state(PathState::Degraded);
        assert_eq!(path.state(), PathState::Degraded);
        path.set_state(PathState::Closed);
        assert_eq!(path.state(), PathState::Closed);
    }

    #[test]
    fn transport_path_zero_stats_rates() {
        let path = test_path(1);
        assert!((path.effective_loss_rate() - 0.0).abs() < f64::EPSILON);
        assert!((path.duplicate_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn process_result_debug() {
        let result = ProcessResult {
            ready: vec![],
            was_duplicate: false,
            path: PathId(1),
        };
        assert!(format!("{result:?}").contains("ProcessResult"));
    }

    // ========================================================================
    // Audit regression: quality_score with zero bandwidth (SapphireHill 2026-03-12)
    // ========================================================================

    #[test]
    fn quality_score_zero_bandwidth_is_finite() {
        init_test("quality_score_zero_bandwidth_is_finite");
        let chars = PathCharacteristics {
            bandwidth_bps: 0,
            ..Default::default()
        };
        let score = chars.quality_score();
        crate::assert_with_log!(
            score.is_finite(),
            "zero bandwidth produces finite score",
            true,
            score.is_finite()
        );
        crate::assert_with_log!(
            score >= 0.0,
            "zero bandwidth score is non-negative",
            true,
            score >= 0.0
        );
        crate::test_complete!("quality_score_zero_bandwidth_is_finite");
    }
}
