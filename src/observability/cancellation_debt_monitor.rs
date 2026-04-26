//! Cancellation Debt Accumulation Monitor
//!
//! Tracks when cancellation work accumulates faster than it can be processed,
//! potentially leading to resource exhaustion or delayed cleanup. Provides
//! early warning and debt management capabilities.

use crate::types::{CancelKind, CancelReason};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

/// br-asupersync-i40ap4 — maximum bytes of cancel-reason text retained per
/// pending entry. Caps the per-entry memory cost so an attacker who controls
/// `CancelReason` text cannot amplify the leak proportional to message
/// length. Anything past this is truncated with a `…` suffix.
const DEFAULT_MAX_CANCEL_REASON_BYTES: usize = 64;

/// br-asupersync-i40ap4 — default cap on pending entries per `WorkType`.
/// When `record_pending_work`/`queue_work` would exceed this, the oldest
/// entry of that work type is evicted and an Emergency alert is generated.
const DEFAULT_MAX_PENDING_PER_WORK_TYPE: usize = 10_000;

/// Truncate a string at a UTF-8 boundary not exceeding `max_bytes` bytes.
/// If truncated, append `…` (which costs 3 bytes in UTF-8). The returned
/// string therefore never exceeds `max_bytes + 3` bytes.
fn truncate_to_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    // Find last char boundary at or before max_bytes.
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + 3);
    out.push_str(&s[..end]);
    out.push('…');
    out
}

/// Configuration for the cancellation debt monitor.
#[derive(Debug, Clone)]
pub struct CancellationDebtConfig {
    /// Maximum queue depth before triggering debt alerts.
    pub max_queue_depth: usize,
    /// Maximum time cancellation work can remain pending.
    pub max_pending_duration: Duration,
    /// Sampling window for processing rate calculations.
    pub rate_sampling_window: Duration,
    /// Minimum processing rate (items/sec) before triggering alerts.
    pub min_processing_rate: f64,
    /// Debt threshold as percentage of queue capacity.
    pub debt_threshold_percentage: f64,
    /// Enable automatic debt relief mechanisms.
    pub enable_auto_relief: bool,
    /// Maximum memory for debt tracking.
    pub max_tracking_memory_mb: usize,
    /// br-asupersync-i40ap4 — Cap on pending entries per `WorkType`. When a
    /// new entry would exceed this, the oldest entry of that work type is
    /// evicted (and an Emergency alert fires once per overflow event).
    pub max_pending_per_work_type: usize,
    /// br-asupersync-i40ap4 — Maximum bytes of cancel-reason text retained
    /// per pending entry. Bounds attacker amplification through long
    /// `CancelReason` messages.
    pub max_cancel_reason_bytes: usize,
}

impl Default for CancellationDebtConfig {
    fn default() -> Self {
        Self {
            max_queue_depth: 10_000,
            max_pending_duration: Duration::from_secs(30),
            rate_sampling_window: Duration::from_secs(60),
            min_processing_rate: 100.0,      // 100 items/sec minimum
            debt_threshold_percentage: 75.0, // 75% of capacity
            enable_auto_relief: false,       // Conservative default
            max_tracking_memory_mb: 50,
            max_pending_per_work_type: DEFAULT_MAX_PENDING_PER_WORK_TYPE,
            max_cancel_reason_bytes: DEFAULT_MAX_CANCEL_REASON_BYTES,
        }
    }
}

/// Types of cancellation work that can accumulate debt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkType {
    /// Task cancellation cleanup.
    TaskCleanup,
    /// Region closure cleanup.
    RegionCleanup,
    /// Resource finalization.
    ResourceFinalization,
    /// Obligation settlement.
    ObligationSettlement,
    /// Waker cleanup.
    WakerCleanup,
    /// Channel cleanup.
    ChannelCleanup,
}

/// A piece of cancellation work pending processing.
#[derive(Debug, Clone)]
pub struct PendingWork {
    /// Unique identifier for this work item.
    pub work_id: u64,
    /// Type of work.
    pub work_type: WorkType,
    /// Entity responsible for the work.
    pub entity_id: String,
    /// When the work was queued.
    pub queued_at: SystemTime,
    /// Priority level (higher = more urgent).
    pub priority: u32,
    /// Estimated processing cost (arbitrary units).
    pub estimated_cost: u32,
    /// br-asupersync-i40ap4 — Cancellation reason text, truncated at
    /// [`CancellationDebtConfig::max_cancel_reason_bytes`]. Was previously
    /// `format!("{cancel_reason:?}")` of the full `CancelReason` (which
    /// could be attacker-controlled and arbitrarily long).
    pub cancel_reason: String,
    /// br-asupersync-i40ap4 — Cancel kind stored as the typed enum (Copy,
    /// no allocation). Was previously `format!("{cancel_kind:?}")`, which
    /// allocated a fresh String per pending entry.
    pub cancel_kind: CancelKind,
    /// Dependencies that must complete first.
    pub dependencies: Vec<u64>,
}

/// Snapshot of debt accumulation state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebtSnapshot {
    /// Current time of snapshot.
    pub snapshot_time: SystemTime,
    /// Total pending work items.
    pub total_pending: usize,
    /// Pending work by type.
    pub pending_by_type: HashMap<WorkType, usize>,
    /// Current debt percentage (0-100).
    pub debt_percentage: f64,
    /// Processing rate over last window.
    pub processing_rate: f64,
    /// Queue depth by entity.
    pub entity_queue_depths: HashMap<String, usize>,
    /// Oldest pending work age.
    pub oldest_work_age: Duration,
    /// Memory usage for debt tracking.
    pub memory_usage_mb: f64,
    /// Current alert level.
    pub alert_level: DebtAlertLevel,
}

/// Alert levels for debt accumulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebtAlertLevel {
    /// Normal operation, no issues.
    Normal,
    /// Elevated debt levels, monitoring recommended.
    Watch,
    /// High debt levels, intervention recommended.
    Warning,
    /// Critical debt levels, immediate action required.
    Critical,
    /// Debt overflow, system may be unstable.
    Emergency,
}

impl DebtAlertLevel {
    /// br-asupersync-37sffr — encode as u8 for lock-free `AtomicU8` storage
    /// in [`CancellationDebtMonitor`].
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Watch => 1,
            Self::Warning => 2,
            Self::Critical => 3,
            Self::Emergency => 4,
        }
    }

    /// br-asupersync-37sffr — decode from a u8 written by [`Self::as_u8`].
    /// Out-of-range values cannot occur via this API but defensively
    /// decode to `Normal`.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Watch,
            2 => Self::Warning,
            3 => Self::Critical,
            4 => Self::Emergency,
            _ => Self::Normal,
        }
    }
}

/// A debt alert notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebtAlert {
    /// Alert level.
    pub level: DebtAlertLevel,
    /// Alert message.
    pub message: String,
    /// Affected work type.
    pub work_type: Option<WorkType>,
    /// Affected entity.
    pub entity_id: Option<String>,
    /// Current metric value.
    pub metric_value: f64,
    /// Threshold that was exceeded.
    pub threshold: f64,
    /// When alert was generated.
    pub generated_at: SystemTime,
    /// Suggested remediation actions.
    pub remediation_suggestions: Vec<String>,
}

/// Statistics for processing rate calculation.
#[derive(Debug)]
struct ProcessingStats {
    /// Items processed in the current window.
    items_processed: VecDeque<(SystemTime, usize)>,
    /// Total items processed since startup.
    total_processed: AtomicU64,
    /// Last processing rate calculation.
    last_rate: f64,
    /// Rate calculation timestamp.
    last_rate_time: SystemTime,
}

impl ProcessingStats {
    fn new() -> Self {
        Self {
            items_processed: VecDeque::new(),
            total_processed: AtomicU64::new(0),
            last_rate: 0.0,
            last_rate_time: super::replayable_system_time(),
        }
    }

    fn record_processing(&mut self, count: usize, now: SystemTime) {
        self.items_processed.push_back((now, count));
        self.total_processed
            .fetch_add(count as u64, Ordering::Relaxed);

        // Keep only samples within the window
        let cutoff = now - Duration::from_secs(60); // 1 minute window
        while let Some(&(time, _)) = self.items_processed.front() {
            if time < cutoff {
                self.items_processed.pop_front();
            } else {
                break;
            }
        }
    }

    fn calculate_rate(&mut self, window: Duration, now: SystemTime) -> f64 {
        // Only recalculate if enough time has passed
        if now
            .duration_since(self.last_rate_time)
            .unwrap_or(Duration::ZERO)
            < Duration::from_secs(5)
        {
            return self.last_rate;
        }

        let cutoff = now - window;
        let total_in_window: usize = self
            .items_processed
            .iter()
            .filter(|&&(time, _)| time >= cutoff)
            .map(|&(_, count)| count)
            .sum();

        let rate = if window.as_secs() > 0 {
            total_in_window as f64 / window.as_secs() as f64
        } else {
            0.0
        };

        self.last_rate = rate;
        self.last_rate_time = now;
        rate
    }
}

/// Cancellation debt accumulation monitor.
///
/// br-asupersync-37sffr — All four state guards now use `parking_lot::Mutex`
/// (faster acquire/release than `std::sync::Mutex`, no poison panic on a
/// monitor-internal panic). `current_alert_level` is a lock-free `AtomicU8`
/// since the value is a 5-variant `Copy` enum.
pub struct CancellationDebtMonitor {
    config: CancellationDebtConfig,
    /// Pending work by work type.
    pending_work: Arc<Mutex<HashMap<WorkType, HashMap<u64, PendingWork>>>>,
    /// Processing statistics by work type.
    processing_stats: Arc<Mutex<HashMap<WorkType, ProcessingStats>>>,
    /// Next work ID.
    next_work_id: AtomicU64,
    /// Current alert level (encoded via [`DebtAlertLevel::as_u8`] /
    /// [`DebtAlertLevel::from_u8`]).
    current_alert_level: AtomicU8,
    /// Recent alerts.
    recent_alerts: Arc<Mutex<VecDeque<DebtAlert>>>,
    /// Total memory usage estimate.
    memory_usage_bytes: AtomicUsize,
    /// br-asupersync-i40ap4 — Count of evictions triggered by per-work-type
    /// cap overflow since startup. Surfaced via [`Self::eviction_count`].
    eviction_count: AtomicU64,
}

impl CancellationDebtMonitor {
    /// Creates a new debt monitor with the given configuration.
    #[must_use]
    pub fn new(config: CancellationDebtConfig) -> Self {
        Self {
            config,
            pending_work: Arc::new(Mutex::new(HashMap::new())),
            processing_stats: Arc::new(Mutex::new(HashMap::new())),
            next_work_id: AtomicU64::new(1),
            current_alert_level: AtomicU8::new(DebtAlertLevel::Normal.as_u8()),
            recent_alerts: Arc::new(Mutex::new(VecDeque::new())),
            memory_usage_bytes: AtomicUsize::new(0),
            eviction_count: AtomicU64::new(0),
        }
    }

    /// br-asupersync-i40ap4 — Number of pending-work entries evicted because
    /// they would have exceeded `config.max_pending_per_work_type`.
    #[must_use]
    pub fn eviction_count(&self) -> u64 {
        self.eviction_count.load(Ordering::Relaxed)
    }

    /// Creates a debt monitor with default configuration.
    #[must_use]
    pub fn default() -> Self {
        Self::new(CancellationDebtConfig::default())
    }

    /// Queue a new piece of cancellation work.
    ///
    /// br-asupersync-i40ap4 — `cancel_reason` is truncated at
    /// `config.max_cancel_reason_bytes` to bound per-entry memory cost
    /// (an attacker who controls `CancelReason` text cannot amplify the
    /// leak proportional to message length). `cancel_kind` is stored as
    /// the typed enum (Copy) rather than a freshly-allocated Debug String.
    /// If inserting this entry would exceed `config.max_pending_per_work_type`
    /// for `work_type`, the oldest entry of that type is evicted first and
    /// `eviction_count()` is incremented.
    pub fn queue_work(
        &self,
        work_type: WorkType,
        entity_id: String,
        priority: u32,
        estimated_cost: u32,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
        dependencies: Vec<u64>,
    ) -> u64 {
        let work_id = self.next_work_id.fetch_add(1, Ordering::Relaxed);
        let now = super::replayable_system_time();

        let cancel_reason_text =
            truncate_to_bytes(&format!("{cancel_reason}"), self.config.max_cancel_reason_bytes);
        let work = PendingWork {
            work_id,
            work_type,
            entity_id,
            queued_at: now,
            priority,
            estimated_cost,
            cancel_reason: cancel_reason_text,
            cancel_kind,
            dependencies,
        };

        // Update memory usage estimate
        let work_size = std::mem::size_of::<PendingWork>()
            + work.entity_id.len()
            + work.cancel_reason.len();
        self.memory_usage_bytes
            .fetch_add(work_size, Ordering::Relaxed);

        // Add to pending work — evicting the oldest entry of this work type
        // if we would otherwise exceed the per-WorkType cap.
        let evicted_for_alert = {
            let mut pending = self.pending_work.lock();
            let map = pending.entry(work_type).or_default();
            let evicted = if map.len() >= self.config.max_pending_per_work_type {
                // Find the oldest entry (smallest queued_at). Linear scan is
                // OK since the cap bounds the search size.
                let oldest_id = map
                    .iter()
                    .min_by_key(|(_, w)| w.queued_at)
                    .map(|(id, _)| *id);
                oldest_id.and_then(|id| map.remove(&id)).map(|w| {
                    let evicted_size = std::mem::size_of::<PendingWork>()
                        + w.entity_id.len()
                        + w.cancel_reason.len();
                    self.memory_usage_bytes
                        .fetch_sub(evicted_size, Ordering::Relaxed);
                    self.eviction_count.fetch_add(1, Ordering::Relaxed);
                    w.work_id
                })
            } else {
                None
            };
            map.insert(work_id, work);
            evicted
        };

        if let Some(evicted_id) = evicted_for_alert {
            self.generate_alert(DebtAlert {
                level: DebtAlertLevel::Emergency,
                message: format!(
                    "evicted oldest pending {work_type:?} (work_id={evicted_id}) — \
                     per-type cap of {} reached (br-asupersync-i40ap4)",
                    self.config.max_pending_per_work_type
                ),
                work_type: Some(work_type),
                entity_id: None,
                metric_value: self.config.max_pending_per_work_type as f64,
                threshold: self.config.max_pending_per_work_type as f64,
                generated_at: now,
                remediation_suggestions: vec![
                    "Investigate why pending work is not being completed".to_string(),
                    "Increase max_pending_per_work_type if eviction is benign".to_string(),
                ],
            });
        }

        // Check if we need to trigger debt alerts
        self.check_debt_levels();

        work_id
    }

    /// Mark work as completed and remove from pending.
    pub fn complete_work(&self, work_id: u64) -> bool {
        let now = super::replayable_system_time();
        let mut found_work = None;

        // Find and remove the work
        {
            let mut pending = self.pending_work.lock();
            for (work_type, work_map) in pending.iter_mut() {
                if let Some(work) = work_map.remove(&work_id) {
                    found_work = Some((*work_type, work));
                    break;
                }
            }
        }

        if let Some((work_type, work)) = found_work {
            // Update memory usage
            let work_size = std::mem::size_of::<PendingWork>()
                + work.entity_id.len()
                + work.cancel_reason.len()
                /* br-asupersync-i40ap4: cancel_kind is now CancelKind enum (no allocation) */;
            self.memory_usage_bytes
                .fetch_sub(work_size, Ordering::Relaxed);

            // Update processing statistics
            {
                let mut stats = self.processing_stats.lock();
                stats
                    .entry(work_type)
                    .or_insert_with(ProcessingStats::new)
                    .record_processing(1, now);
            }

            true
        } else {
            false
        }
    }

    /// Complete multiple work items at once (batch completion).
    pub fn complete_work_batch(&self, work_ids: &[u64]) -> usize {
        let now = super::replayable_system_time();
        let mut completed_count = 0;
        let mut completed_by_type: HashMap<WorkType, usize> = HashMap::new();

        // Process completions
        {
            let mut pending = self.pending_work.lock();
            for &work_id in work_ids {
                for (work_type, work_map) in pending.iter_mut() {
                    if let Some(work) = work_map.remove(&work_id) {
                        completed_count += 1;
                        *completed_by_type.entry(*work_type).or_default() += 1;

                        // Update memory usage
                        let work_size = std::mem::size_of::<PendingWork>()
                            + work.entity_id.len()
                            + work.cancel_reason.len()
                            /* br-asupersync-i40ap4: cancel_kind is now CancelKind enum (no allocation) */;
                        self.memory_usage_bytes
                            .fetch_sub(work_size, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }

        // Update processing statistics
        {
            let mut stats = self.processing_stats.lock();
            for (work_type, count) in completed_by_type {
                stats
                    .entry(work_type)
                    .or_insert_with(ProcessingStats::new)
                    .record_processing(count, now);
            }
        }

        completed_count
    }

    /// Get current debt snapshot.
    pub fn get_debt_snapshot(&self) -> DebtSnapshot {
        let now = super::replayable_system_time();
        let pending = self.pending_work.lock();

        // Calculate totals
        let mut total_pending = 0;
        let mut pending_by_type = HashMap::new();
        let mut entity_queue_depths = HashMap::new();
        let mut oldest_work_age = Duration::ZERO;

        for (work_type, work_map) in pending.iter() {
            let type_count = work_map.len();
            total_pending += type_count;
            pending_by_type.insert(*work_type, type_count);

            for work in work_map.values() {
                // Track queue depth per entity
                *entity_queue_depths
                    .entry(work.entity_id.clone())
                    .or_default() += 1;

                // Find oldest work
                if let Ok(age) = now.duration_since(work.queued_at) {
                    oldest_work_age = oldest_work_age.max(age);
                }
            }
        }

        // Calculate debt percentage
        let debt_percentage = if self.config.max_queue_depth > 0 {
            (total_pending as f64 / self.config.max_queue_depth as f64) * 100.0
        } else {
            0.0
        };

        // Calculate processing rate
        let processing_rate = {
            let mut stats = self.processing_stats.lock();
            let mut total_rate = 0.0;
            for (_, stat) in stats.iter_mut() {
                total_rate += stat.calculate_rate(self.config.rate_sampling_window, now);
            }
            total_rate
        };

        // Memory usage
        let memory_usage_mb =
            self.memory_usage_bytes.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0);

        // Current alert level
        let alert_level = DebtAlertLevel::from_u8(self.current_alert_level.load(Ordering::Relaxed));

        DebtSnapshot {
            snapshot_time: now,
            total_pending,
            pending_by_type,
            debt_percentage,
            processing_rate,
            entity_queue_depths,
            oldest_work_age,
            memory_usage_mb,
            alert_level,
        }
    }

    /// Get pending work for a specific entity.
    pub fn get_entity_pending_work(&self, entity_id: &str) -> Vec<PendingWork> {
        let pending = self.pending_work.lock();
        let mut result = Vec::new();

        for work_map in pending.values() {
            for work in work_map.values() {
                if work.entity_id == entity_id {
                    result.push(work.clone());
                }
            }
        }

        result.sort_by(|a, b| b.priority.cmp(&a.priority));
        result
    }

    /// Get the highest priority pending work items.
    pub fn get_priority_work(&self, limit: usize) -> Vec<PendingWork> {
        let pending = self.pending_work.lock();
        let mut result = Vec::new();

        for work_map in pending.values() {
            for work in work_map.values() {
                result.push(work.clone());
            }
        }

        result.sort_by(|a, b| {
            // Sort by priority desc, then by age desc
            match b.priority.cmp(&a.priority) {
                std::cmp::Ordering::Equal => b.queued_at.cmp(&a.queued_at),
                other => other,
            }
        });

        result.truncate(limit);
        result
    }

    /// Get recent debt alerts.
    pub fn get_recent_alerts(&self, limit: usize) -> Vec<DebtAlert> {
        let alerts = self.recent_alerts.lock();
        alerts.iter().rev().take(limit).cloned().collect()
    }

    /// Clear old alerts beyond a certain age.
    pub fn clear_old_alerts(&self, max_age: Duration) {
        let cutoff = super::replayable_system_time() - max_age;
        let mut alerts = self.recent_alerts.lock();
        alerts.retain(|alert| alert.generated_at > cutoff);
    }

    /// Force cleanup of old pending work (emergency debt relief).
    pub fn emergency_cleanup(&self, max_age: Duration) -> usize {
        let cutoff = super::replayable_system_time() - max_age;
        let mut cleaned_count = 0;

        {
            let mut pending = self.pending_work.lock();
            for work_map in pending.values_mut() {
                let before_count = work_map.len();
                work_map.retain(|_, work| work.queued_at > cutoff);
                cleaned_count += before_count - work_map.len();
            }
        }

        if cleaned_count > 0 {
            self.generate_alert(DebtAlert {
                level: DebtAlertLevel::Emergency,
                message: format!("Emergency cleanup removed {cleaned_count} stale work items"),
                work_type: None,
                entity_id: None,
                metric_value: cleaned_count as f64,
                threshold: 0.0,
                generated_at: super::replayable_system_time(),
                remediation_suggestions: vec![
                    "Investigate why work items are not being processed".to_string(),
                    "Check for deadlocks or blocked entities".to_string(),
                    "Consider increasing processing capacity".to_string(),
                ],
            });
        }

        cleaned_count
    }

    /// Check current debt levels and trigger alerts if needed.
    fn check_debt_levels(&self) {
        let snapshot = self.get_debt_snapshot();
        let new_alert_level = self.calculate_alert_level(&snapshot);

        // br-asupersync-37sffr — atomic compare-and-update on the alert
        // level. Multiple cancel hot-path callers may race here; only one
        // observes the transition and emits the alert.
        let new_byte = new_alert_level.as_u8();
        let prev_byte = self.current_alert_level.swap(new_byte, Ordering::AcqRel);
        if prev_byte != new_byte {
            let old_level = DebtAlertLevel::from_u8(prev_byte);
            self.generate_debt_level_alert(old_level, new_alert_level, &snapshot);
        }

        // Check for specific threshold violations
        self.check_threshold_violations(&snapshot);
    }

    /// Calculate alert level based on current snapshot.
    fn calculate_alert_level(&self, snapshot: &DebtSnapshot) -> DebtAlertLevel {
        // Emergency: Memory usage > 90% or debt > 95%
        if snapshot.memory_usage_mb > (self.config.max_tracking_memory_mb as f64 * 0.9)
            || snapshot.debt_percentage > 95.0
        {
            return DebtAlertLevel::Emergency;
        }

        // Critical: Debt > 90% or very slow processing
        if snapshot.debt_percentage > 90.0
            || (snapshot.processing_rate < self.config.min_processing_rate * 0.1
                && snapshot.total_pending > 100)
        {
            return DebtAlertLevel::Critical;
        }

        // Warning: Debt above threshold or slow processing
        if snapshot.debt_percentage > self.config.debt_threshold_percentage
            || snapshot.processing_rate < self.config.min_processing_rate * 0.5
        {
            return DebtAlertLevel::Warning;
        }

        // Watch: Debt > 50% or oldest work is aging
        if snapshot.debt_percentage > 50.0
            || snapshot.oldest_work_age > self.config.max_pending_duration * 2
        {
            return DebtAlertLevel::Watch;
        }

        DebtAlertLevel::Normal
    }

    /// Generate alert for debt level changes.
    fn generate_debt_level_alert(
        &self,
        _old_level: DebtAlertLevel,
        new_level: DebtAlertLevel,
        snapshot: &DebtSnapshot,
    ) {
        let message = match new_level {
            DebtAlertLevel::Emergency => {
                "EMERGENCY: Cancellation debt overflow detected".to_string()
            }
            DebtAlertLevel::Critical => {
                "CRITICAL: Severe cancellation debt accumulation".to_string()
            }
            DebtAlertLevel::Warning => "WARNING: Elevated cancellation debt levels".to_string(),
            DebtAlertLevel::Watch => "WATCH: Cancellation debt increasing".to_string(),
            DebtAlertLevel::Normal => "INFO: Cancellation debt levels normal".to_string(),
        };

        let remediation_suggestions = match new_level {
            DebtAlertLevel::Emergency => vec![
                "Execute emergency cleanup immediately".to_string(),
                "Scale up processing capacity".to_string(),
                "Investigate system bottlenecks".to_string(),
            ],
            DebtAlertLevel::Critical => vec![
                "Increase cancellation processing rate".to_string(),
                "Consider work prioritization".to_string(),
                "Check for deadlocks or stuck entities".to_string(),
            ],
            DebtAlertLevel::Warning => vec![
                "Monitor processing rates closely".to_string(),
                "Optimize cancellation handlers".to_string(),
                "Consider load shedding if applicable".to_string(),
            ],
            DebtAlertLevel::Watch => vec![
                "Monitor debt accumulation trends".to_string(),
                "Verify processing pipeline health".to_string(),
            ],
            DebtAlertLevel::Normal => vec!["Continue monitoring".to_string()],
        };

        self.generate_alert(DebtAlert {
            level: new_level,
            message,
            work_type: None,
            entity_id: None,
            metric_value: snapshot.debt_percentage,
            threshold: match new_level {
                DebtAlertLevel::Emergency => 95.0,
                DebtAlertLevel::Critical => 90.0,
                DebtAlertLevel::Warning => self.config.debt_threshold_percentage,
                DebtAlertLevel::Watch => 50.0,
                DebtAlertLevel::Normal => 0.0,
            },
            generated_at: snapshot.snapshot_time,
            remediation_suggestions,
        });
    }

    /// Check for specific threshold violations.
    fn check_threshold_violations(&self, snapshot: &DebtSnapshot) {
        // Check processing rate violations by type
        let stats = self.processing_stats.lock();
        for (work_type, stat) in stats.iter() {
            if stat.last_rate < self.config.min_processing_rate * 0.1 {
                self.generate_alert(DebtAlert {
                    level: DebtAlertLevel::Warning,
                    message: format!(
                        "Very slow processing rate for {:?}: {:.1}/sec",
                        work_type, stat.last_rate
                    ),
                    work_type: Some(*work_type),
                    entity_id: None,
                    metric_value: stat.last_rate,
                    threshold: self.config.min_processing_rate * 0.1,
                    generated_at: snapshot.snapshot_time,
                    remediation_suggestions: vec![
                        format!("Optimize {:?} processing handlers", work_type),
                        "Check for blocking operations".to_string(),
                    ],
                });
            }
        }

        // Check for entities with excessive queue depths
        for (entity_id, &depth) in &snapshot.entity_queue_depths {
            if depth > 1000 {
                self.generate_alert(DebtAlert {
                    level: DebtAlertLevel::Warning,
                    message: format!("Entity {entity_id} has excessive queue depth: {depth}"),
                    work_type: None,
                    entity_id: Some(entity_id.clone()),
                    metric_value: depth as f64,
                    threshold: 1000.0,
                    generated_at: snapshot.snapshot_time,
                    remediation_suggestions: vec![
                        "Investigate entity-specific bottlenecks".to_string(),
                        "Check for resource leaks in entity cleanup".to_string(),
                    ],
                });
            }
        }
    }

    /// Generate and store an alert.
    #[allow(unused_variables)]
    fn generate_alert(&self, alert: DebtAlert) {
        {
            let mut alerts = self.recent_alerts.lock();
            alerts.push_back(alert.clone());

            // Keep alerts bounded
            while alerts.len() > 1000 {
                alerts.pop_front();
            }
        }

        crate::tracing_compat::warn!(
            level = ?alert.level,
            work_type = ?alert.work_type,
            entity_id = ?alert.entity_id,
            metric_value = alert.metric_value,
            threshold = alert.threshold,
            generated_at = ?alert.generated_at,
            message = %alert.message,
            "cancellation debt alert"
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::{CancelKind, CancelReason};

    #[test]
    fn test_debt_monitor_creation() {
        let config = CancellationDebtConfig::default();
        let monitor = CancellationDebtMonitor::new(config);

        let snapshot = monitor.get_debt_snapshot();
        assert_eq!(snapshot.total_pending, 0);
        assert_eq!(snapshot.debt_percentage, 0.0);
    }

    #[test]
    fn test_work_lifecycle() {
        let monitor = CancellationDebtMonitor::default();

        let work_id = monitor.queue_work(
            WorkType::TaskCleanup,
            "test-task".to_string(),
            10,
            100,
            &CancelReason::user("test"),
            CancelKind::User,
            Vec::new(),
        );

        let snapshot = monitor.get_debt_snapshot();
        assert_eq!(snapshot.total_pending, 1);
        assert!(
            snapshot
                .pending_by_type
                .contains_key(&WorkType::TaskCleanup)
        );

        let completed = monitor.complete_work(work_id);
        assert!(completed);

        let snapshot = monitor.get_debt_snapshot();
        assert_eq!(snapshot.total_pending, 0);
    }

    #[test]
    fn test_debt_calculation() {
        let mut config = CancellationDebtConfig::default();
        config.max_queue_depth = 100;
        let monitor = CancellationDebtMonitor::new(config);

        // Queue 75 items (should trigger warning at 75% threshold)
        for i in 0..75 {
            monitor.queue_work(
                WorkType::TaskCleanup,
                format!("task-{}", i),
                1,
                10,
                &CancelReason::user("test"),
                CancelKind::User,
                Vec::new(),
            );
        }

        let snapshot = monitor.get_debt_snapshot();
        assert_eq!(snapshot.total_pending, 75);
        assert_eq!(snapshot.debt_percentage, 75.0);
    }

    #[test]
    fn test_batch_completion() {
        let monitor = CancellationDebtMonitor::default();

        let work_ids: Vec<u64> = (0..5)
            .map(|i| {
                monitor.queue_work(
                    WorkType::ResourceFinalization,
                    format!("resource-{}", i),
                    1,
                    50,
                    &CancelReason::user("batch_test"),
                    CancelKind::User,
                    Vec::new(),
                )
            })
            .collect();

        let completed = monitor.complete_work_batch(&work_ids);
        assert_eq!(completed, 5);

        let snapshot = monitor.get_debt_snapshot();
        assert_eq!(snapshot.total_pending, 0);
    }

    #[test]
    fn test_priority_work_retrieval() {
        let monitor = CancellationDebtMonitor::default();

        // Queue work with different priorities
        monitor.queue_work(
            WorkType::TaskCleanup,
            "low-priority".to_string(),
            1,
            10,
            &CancelReason::user("test"),
            CancelKind::User,
            Vec::new(),
        );

        monitor.queue_work(
            WorkType::TaskCleanup,
            "high-priority".to_string(),
            100,
            10,
            &CancelReason::user("test"),
            CancelKind::User,
            Vec::new(),
        );

        let priority_work = monitor.get_priority_work(5);
        assert_eq!(priority_work.len(), 2);
        assert_eq!(priority_work[0].priority, 100); // High priority first
        assert_eq!(priority_work[1].priority, 1);
    }

    #[test]
    fn test_emergency_cleanup() {
        let monitor = CancellationDebtMonitor::default();

        // Queue some work and artificially age it
        monitor.queue_work(
            WorkType::ChannelCleanup,
            "old-work".to_string(),
            1,
            10,
            &CancelReason::user("test"),
            CancelKind::User,
            Vec::new(),
        );

        // Emergency cleanup with very short age (should clean everything)
        let cleaned = monitor.emergency_cleanup(Duration::from_millis(1));
        assert!(cleaned > 0);

        let snapshot = monitor.get_debt_snapshot();
        assert_eq!(snapshot.total_pending, 0);
    }

    /// br-asupersync-i40ap4 — long cancel-reason text is truncated at the
    /// configured byte cap so attacker-controlled reasons cannot amplify
    /// the per-entry memory footprint.
    #[test]
    fn cancel_reason_truncated_at_byte_cap() {
        let mut config = CancellationDebtConfig::default();
        config.max_cancel_reason_bytes = 16;
        let monitor = CancellationDebtMonitor::new(config);

        let long = "A".repeat(10_000);
        let mut reason = CancelReason::new(CancelKind::User);
        reason.message = Some(long);
        let id = monitor.queue_work(
            WorkType::TaskCleanup,
            "entity".into(),
            1,
            1,
            &reason,
            CancelKind::User,
            Vec::new(),
        );

        let work = monitor
            .get_priority_work(10)
            .into_iter()
            .find(|w| w.work_id == id)
            .expect("queued work present");
        // Truncated text is at most max_cancel_reason_bytes + 3 (ellipsis is
        // 3 bytes in UTF-8) and ends with the ellipsis character.
        assert!(
            work.cancel_reason.len() <= 16 + 3,
            "cancel_reason exceeded cap: {} bytes",
            work.cancel_reason.len()
        );
        assert!(
            work.cancel_reason.ends_with('…'),
            "expected ellipsis suffix on truncated reason: {:?}",
            work.cancel_reason
        );
    }

    /// br-asupersync-i40ap4 — short cancel-reason text passes through
    /// unchanged (no spurious truncation).
    #[test]
    fn cancel_reason_short_passes_through() {
        let monitor = CancellationDebtMonitor::default();
        let reason = CancelReason::user("short");
        let id = monitor.queue_work(
            WorkType::TaskCleanup,
            "entity".into(),
            1,
            1,
            &reason,
            CancelKind::User,
            Vec::new(),
        );
        let work = monitor
            .get_priority_work(10)
            .into_iter()
            .find(|w| w.work_id == id)
            .unwrap();
        assert!(!work.cancel_reason.ends_with('…'));
        assert!(!work.cancel_reason.is_empty());
    }

    /// br-asupersync-i40ap4 — once per-WorkType cap is reached, the oldest
    /// entry is evicted on each new insert and `eviction_count` advances.
    #[test]
    fn per_work_type_cap_evicts_oldest() {
        let mut config = CancellationDebtConfig::default();
        config.max_pending_per_work_type = 4;
        let monitor = CancellationDebtMonitor::new(config);

        let mut ids = Vec::new();
        for i in 0..4 {
            ids.push(monitor.queue_work(
                WorkType::TaskCleanup,
                format!("task-{i}"),
                1,
                1,
                &CancelReason::user("x"),
                CancelKind::User,
                Vec::new(),
            ));
        }
        assert_eq!(monitor.get_debt_snapshot().total_pending, 4);
        assert_eq!(monitor.eviction_count(), 0);

        // Inserting a 5th must evict an older entry.
        let _new_id = monitor.queue_work(
            WorkType::TaskCleanup,
            "task-5".into(),
            1,
            1,
            &CancelReason::user("x"),
            CancelKind::User,
            Vec::new(),
        );
        assert_eq!(monitor.get_debt_snapshot().total_pending, 4);
        assert_eq!(monitor.eviction_count(), 1);

        // Sanity: a different WorkType is independently capped.
        for i in 0..4 {
            monitor.queue_work(
                WorkType::ChannelCleanup,
                format!("chan-{i}"),
                1,
                1,
                &CancelReason::user("x"),
                CancelKind::User,
                Vec::new(),
            );
        }
        assert_eq!(monitor.get_debt_snapshot().total_pending, 8);
        assert_eq!(monitor.eviction_count(), 1);
    }

    /// br-asupersync-37sffr — the alert level transitions atomically through
    /// the AtomicU8 store; concurrent observers always see one of the
    /// well-formed enum variants, never a torn/poisoned state.
    #[test]
    fn alert_level_atomic_roundtrip() {
        for level in [
            DebtAlertLevel::Normal,
            DebtAlertLevel::Watch,
            DebtAlertLevel::Warning,
            DebtAlertLevel::Critical,
            DebtAlertLevel::Emergency,
        ] {
            assert_eq!(DebtAlertLevel::from_u8(level.as_u8()), level);
        }
        // Out-of-range bytes defensively decode to Normal.
        assert_eq!(DebtAlertLevel::from_u8(255), DebtAlertLevel::Normal);
        assert_eq!(DebtAlertLevel::from_u8(99), DebtAlertLevel::Normal);
    }

    /// br-asupersync-i40ap4 — `truncate_to_bytes` respects UTF-8 character
    /// boundaries (does not split a multi-byte codepoint mid-sequence).
    #[test]
    fn truncate_to_bytes_respects_utf8_boundaries() {
        // 4-byte UTF-8 codepoint (😀 = U+1F600 = F0 9F 98 80).
        let s = "ABC😀DEF";
        // Cap of 5 forces truncation between A,B,C and the emoji.
        let out = truncate_to_bytes(s, 5);
        assert!(out.is_char_boundary(out.len()));
        // 4 bytes ABC + 3 bytes for ellipsis.
        // The truncation may stop after "ABC" (3 bytes) so the resulting
        // truncated portion is "ABC" + "…".
        assert!(out.starts_with("ABC"));
        assert!(out.ends_with('…'));
        // Cap exceeding the input length leaves it untouched.
        assert_eq!(truncate_to_bytes("hi", 100), "hi");
    }
}
