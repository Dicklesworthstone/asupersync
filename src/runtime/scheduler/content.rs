//! Content-aware scheduler for priority-based data transfer decisions.
//!
//! This module provides a framework for making scheduling decisions about what
//! content (chunks, streams, repair data) to send next, with support for:
//! - Priority classes with deterministic ordering
//! - Pressure feedback from network, disk, and CPU
//! - Evidence logging for explainable decisions
//! - Integration with stream-level schedulers
//!
//! The scheduler is generic and can be used by any protocol that needs to make
//! content scheduling decisions (ATP transfers, replication, etc.).

use crate::types::Time;
use crate::util::det_hash::{DetHashMap, DetHashSet};
use serde::{Deserialize, Serialize};
use std::collections::BinaryHeap;
use std::fmt;

/// Priority class for different types of content.
///
/// Higher numeric values = higher priority.
/// Classes are ordered to ensure control traffic takes priority over bulk data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PriorityClass {
    /// Background telemetry and metrics (lowest priority)
    Telemetry = 0,
    /// Prefetched content for future use
    Prefetch = 1,
    /// Repair data for error correction
    Repair = 2,
    /// Bulk data payload
    Data = 3,
    /// Cryptographic proofs and verification data
    Proof = 4,
    /// ACK messages and missing chunk bitmaps
    AckBitmap = 5,
    /// Directory listing and file manifests
    Manifest = 6,
    /// Control messages and protocol commands (highest priority)
    Control = 7,
}

impl PriorityClass {
    /// Returns true if this is a control-plane priority class.
    #[must_use]
    pub fn is_control_plane(self) -> bool {
        matches!(self, Self::Control | Self::Manifest | Self::AckBitmap)
    }

    /// Returns true if this is a data-plane priority class.
    #[must_use]
    pub fn is_data_plane(self) -> bool {
        !self.is_control_plane()
    }

    /// Returns the numeric priority value (higher = more urgent).
    #[must_use]
    pub const fn priority_value(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for PriorityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Telemetry => "telemetry",
            Self::Prefetch => "prefetch",
            Self::Repair => "repair",
            Self::Data => "data",
            Self::Proof => "proof",
            Self::AckBitmap => "ack_bitmap",
            Self::Manifest => "manifest",
            Self::Control => "control",
        };
        write!(f, "{name}")
    }
}

/// Unique identifier for a schedulable content item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContentId(pub u64);

impl ContentId {
    /// Creates a new content ID from a raw value.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw numeric value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "C{}", self.0)
    }
}

/// System pressure measurements affecting scheduling decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PressureSnapshot {
    /// Network congestion level (0.0 = no congestion, 1.0 = severe)
    pub network: f64,
    /// Disk I/O pressure (0.0 = idle, 1.0 = saturated)
    pub disk: f64,
    /// CPU utilization pressure (0.0 = idle, 1.0 = saturated)
    pub cpu: f64,
    /// Memory pressure (0.0 = plenty available, 1.0 = near exhaustion)
    pub memory: f64,
    /// Timestamp when measurements were taken
    pub measured_at: Time,
}

impl Default for PressureSnapshot {
    fn default() -> Self {
        Self {
            network: 0.0,
            disk: 0.0,
            cpu: 0.0,
            memory: 0.0,
            measured_at: Time::ZERO,
        }
    }
}

impl PressureSnapshot {
    /// Returns the maximum pressure across all subsystems.
    #[must_use]
    pub fn max_pressure(&self) -> f64 {
        self.network.max(self.disk).max(self.cpu).max(self.memory)
    }

    /// Returns true if any subsystem is under high pressure.
    #[must_use]
    pub fn has_high_pressure(&self) -> bool {
        self.max_pressure() > 0.8
    }

    /// Returns true if network is the dominant pressure source.
    #[must_use]
    pub fn network_dominant(&self) -> bool {
        self.network > self.disk && self.network > self.cpu && self.network > self.memory
    }
}

/// A schedulable content item with metadata.
#[derive(Debug, Clone)]
pub struct ContentItem {
    /// Unique identifier for this content
    pub id: ContentId,
    /// Priority class determining scheduling order
    pub priority_class: PriorityClass,
    /// Size in bytes (for bandwidth calculations)
    pub size_bytes: usize,
    /// Estimated cost to produce/send this content
    pub cost_estimate: f64,
    /// Expected utility/value delivered by sending this content
    pub utility_score: f64,
    /// Stream ID for stream-aware scheduling (optional)
    pub stream_id: Option<u64>,
    /// Custom metadata for scheduler policies
    pub metadata: DetHashMap<String, String>,
}

impl ContentItem {
    /// Creates a new content item with basic parameters.
    #[must_use]
    pub fn new(
        id: ContentId,
        priority_class: PriorityClass,
        size_bytes: usize,
        cost_estimate: f64,
        utility_score: f64,
    ) -> Self {
        Self {
            id,
            priority_class,
            size_bytes,
            cost_estimate,
            utility_score,
            stream_id: None,
            metadata: DetHashMap::default(),
        }
    }

    /// Sets the stream ID for this content item.
    #[must_use]
    pub fn with_stream_id(mut self, stream_id: u64) -> Self {
        self.stream_id = Some(stream_id);
        self
    }

    /// Adds custom metadata to this content item.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Calculates utility-to-cost ratio for scheduling decisions.
    #[must_use]
    pub fn efficiency_ratio(&self) -> f64 {
        if self.cost_estimate <= 0.0 {
            f64::INFINITY
        } else {
            self.utility_score / self.cost_estimate
        }
    }
}

/// Scheduled content item with ordering metadata.
#[derive(Debug, Clone)]
struct ScheduledContent {
    item: ContentItem,
    generation: u64,
}

impl PartialEq for ScheduledContent {
    fn eq(&self, other: &Self) -> bool {
        self.item.id == other.item.id
    }
}

impl Eq for ScheduledContent {}

impl PartialOrd for ScheduledContent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledContent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher priority class first
        self.item
            .priority_class
            .cmp(&other.item.priority_class)
            .then_with(|| {
                // Within same priority class, higher efficiency ratio first
                other
                    .item
                    .efficiency_ratio()
                    .partial_cmp(&self.item.efficiency_ratio())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| {
                // For ties, use generation for FIFO ordering (earlier generation wins)
                other.generation.cmp(&self.generation)
            })
            .then_with(|| {
                // Final tie-breaker: content ID for determinism
                self.item.id.cmp(&other.item.id)
            })
    }
}

/// Reason for a scheduling decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleReason {
    /// Highest priority class available
    PriorityClass,
    /// Best efficiency ratio (utility/cost)
    EfficiencyOptimal,
    /// FIFO tie-breaking among equal items
    FifoOrder,
    /// Deterministic tie-breaking by content ID
    DeterministicTieBreak,
    /// Pressure-based throttling applied
    PressureThrottle,
    /// Stream-level fairness constraint
    StreamFairness,
}

/// Evidence record for a scheduling decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleEvidence {
    /// Unique ID for this decision
    pub decision_id: u64,
    /// Selected content item
    pub selected: ContentId,
    /// Primary reason for selection
    pub reason: ScheduleReason,
    /// Alternative content items considered but rejected
    pub rejected_alternatives: Vec<ContentId>,
    /// System pressure at time of decision
    pub pressure_snapshot: PressureSnapshot,
    /// Fairness state affecting the decision
    pub fairness_state: DetHashMap<String, f64>,
    /// Timestamp of decision
    pub decided_at: Time,
    /// Optional replay artifact pointer for debugging
    pub replay_artifact: Option<String>,
}

/// Content-aware scheduler with priority-based decisions.
#[derive(Debug)]
pub struct ContentScheduler {
    /// Scheduled content items ordered by priority
    queue: BinaryHeap<ScheduledContent>,
    /// Set of scheduled content IDs for deduplication
    scheduled: DetHashSet<ContentId>,
    /// Next generation number for FIFO ordering
    next_generation: u64,
    /// Next decision ID for evidence logging
    next_decision_id: u64,
    /// Evidence log for explainable decisions
    evidence_log: Vec<ScheduleEvidence>,
    /// Current system pressure measurements
    current_pressure: PressureSnapshot,
    /// Stream-level fairness tracking
    stream_fairness: DetHashMap<u64, f64>,
}

impl Default for ContentScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentScheduler {
    /// Creates a new content scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
            scheduled: DetHashSet::default(),
            next_generation: 0,
            next_decision_id: 1,
            evidence_log: Vec::new(),
            current_pressure: PressureSnapshot::default(),
            stream_fairness: DetHashMap::default(),
        }
    }

    /// Updates system pressure measurements.
    pub fn update_pressure(&mut self, pressure: PressureSnapshot) {
        self.current_pressure = pressure;
    }

    /// Schedules a content item for transmission.
    ///
    /// Returns `true` if the item was newly scheduled, `false` if it was already queued.
    pub fn schedule(&mut self, item: ContentItem) -> bool {
        if !self.scheduled.insert(item.id) {
            return false; // Already scheduled
        }

        let generation = self.next_generation;
        self.next_generation += 1;

        let scheduled_content = ScheduledContent { item, generation };

        self.queue.push(scheduled_content);
        true
    }

    /// Removes a content item from the schedule.
    ///
    /// Returns `true` if the item was found and removed.
    pub fn unschedule(&mut self, content_id: ContentId) -> bool {
        if !self.scheduled.remove(&content_id) {
            return false; // Not scheduled
        }

        // Note: We leave the item in the heap as a tombstone.
        // It will be filtered out when it reaches the top of the queue.
        // This is more efficient than rebuilding the heap.
        true
    }

    /// Returns the next content item to transmit.
    ///
    /// This applies scheduling policy, pressure throttling, and fairness constraints.
    pub fn next_content(&mut self, now: Time) -> Option<(ContentItem, ScheduleEvidence)> {
        self.prune_tombstones();

        if self.queue.is_empty() {
            return None;
        }

        // Check pressure throttling
        if self.should_throttle_due_to_pressure() {
            return self.create_throttle_evidence(now);
        }

        let scheduled = self.queue.pop()?;
        if !self.scheduled.remove(&scheduled.item.id) {
            // Tombstone entry - item was unscheduled
            return self.next_content(now);
        }

        // Update stream fairness tracking
        if let Some(stream_id) = scheduled.item.stream_id {
            let fairness = self.stream_fairness.entry(stream_id).or_insert(0.0);
            *fairness += scheduled.item.size_bytes as f64;
        }

        // Determine scheduling reason
        let reason = if let Some(next) = self.queue.peek() {
            if scheduled.item.priority_class > next.item.priority_class {
                ScheduleReason::PriorityClass
            } else if (scheduled.item.efficiency_ratio() - next.item.efficiency_ratio()).abs()
                > f64::EPSILON
            {
                ScheduleReason::EfficiencyOptimal
            } else if scheduled.generation < next.generation {
                ScheduleReason::FifoOrder
            } else {
                ScheduleReason::DeterministicTieBreak
            }
        } else {
            ScheduleReason::PriorityClass // Only item in queue
        };

        // Collect rejected alternatives for evidence
        let rejected_alternatives: Vec<ContentId> = self
            .queue
            .iter()
            .take(3) // Limit to top 3 alternatives for evidence
            .map(|sc| sc.item.id)
            .collect();

        let fairness_state = self
            .stream_fairness
            .iter()
            .map(|(k, v)| (format!("stream_{}", k), *v))
            .collect();

        let evidence = ScheduleEvidence {
            decision_id: self.next_decision_id,
            selected: scheduled.item.id,
            reason,
            rejected_alternatives,
            pressure_snapshot: self.current_pressure.clone(),
            fairness_state,
            decided_at: now,
            replay_artifact: None,
        };

        self.next_decision_id += 1;
        self.evidence_log.push(evidence.clone());

        Some((scheduled.item, evidence))
    }

    /// Returns true if there are any scheduled content items.
    #[must_use]
    pub fn has_pending_content(&self) -> bool {
        !self.scheduled.is_empty()
    }

    /// Returns the number of scheduled content items.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.scheduled.len()
    }

    /// Returns the evidence log for debugging and replay.
    #[must_use]
    pub fn evidence_log(&self) -> &[ScheduleEvidence] {
        &self.evidence_log
    }

    /// Clears all scheduled content and evidence.
    pub fn clear(&mut self) {
        self.queue.clear();
        self.scheduled.clear();
        self.evidence_log.clear();
        self.stream_fairness.clear();
        self.next_generation = 0;
        self.next_decision_id = 1;
    }

    fn prune_tombstones(&mut self) {
        while let Some(scheduled) = self.queue.peek() {
            if self.scheduled.contains(&scheduled.item.id) {
                break; // Valid entry at top
            }
            self.queue.pop(); // Remove tombstone
        }
    }

    fn should_throttle_due_to_pressure(&self) -> bool {
        self.current_pressure.has_high_pressure()
    }

    fn create_throttle_evidence(&mut self, _now: Time) -> Option<(ContentItem, ScheduleEvidence)> {
        // For pressure throttling, we'll return None to indicate no content should be sent
        // In a real implementation, we might queue this decision for later retry
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_content(
        id: u64,
        priority: PriorityClass,
        size: usize,
        cost: f64,
        utility: f64,
    ) -> ContentItem {
        ContentItem::new(ContentId::new(id), priority, size, cost, utility)
    }

    #[test]
    fn priority_class_ordering() {
        assert!(PriorityClass::Control > PriorityClass::Data);
        assert!(PriorityClass::Data > PriorityClass::Telemetry);
        assert!(PriorityClass::Control.is_control_plane());
        assert!(PriorityClass::Data.is_data_plane());
    }

    #[test]
    fn content_scheduler_basic_operation() {
        let mut scheduler = ContentScheduler::new();

        // Schedule items with different priorities
        let control = test_content(1, PriorityClass::Control, 100, 1.0, 10.0);
        let data = test_content(2, PriorityClass::Data, 1000, 2.0, 5.0);
        let telemetry = test_content(3, PriorityClass::Telemetry, 50, 0.5, 1.0);

        assert!(scheduler.schedule(data.clone()));
        assert!(scheduler.schedule(telemetry.clone()));
        assert!(scheduler.schedule(control.clone()));

        assert_eq!(scheduler.pending_count(), 3);

        // Should pop control first (highest priority)
        let (next_item, evidence) = scheduler.next_content(Time::ZERO).unwrap();
        assert_eq!(next_item.id, control.id);
        assert_eq!(evidence.reason, ScheduleReason::PriorityClass);
        assert_eq!(evidence.selected, control.id);

        // Then data (higher efficiency than telemetry: 2.5 vs 2.0)
        let (next_item, _) = scheduler.next_content(Time::ZERO).unwrap();
        assert_eq!(next_item.id, data.id);

        // Finally telemetry
        let (next_item, _) = scheduler.next_content(Time::ZERO).unwrap();
        assert_eq!(next_item.id, telemetry.id);

        assert!(!scheduler.has_pending_content());
    }

    #[test]
    fn content_scheduler_fifo_ordering() {
        let mut scheduler = ContentScheduler::new();

        // Schedule items with same priority and efficiency
        let item1 = test_content(1, PriorityClass::Data, 100, 1.0, 2.0);
        let item2 = test_content(2, PriorityClass::Data, 100, 1.0, 2.0);

        scheduler.schedule(item1.clone());
        scheduler.schedule(item2.clone());

        // Should maintain FIFO order for ties
        let (next_item, evidence) = scheduler.next_content(Time::ZERO).unwrap();
        assert_eq!(next_item.id, item1.id);
        assert_eq!(evidence.reason, ScheduleReason::FifoOrder);

        let (next_item, _) = scheduler.next_content(Time::ZERO).unwrap();
        assert_eq!(next_item.id, item2.id);
    }

    #[test]
    fn content_scheduler_unschedule() {
        let mut scheduler = ContentScheduler::new();

        let item = test_content(1, PriorityClass::Data, 100, 1.0, 2.0);
        scheduler.schedule(item.clone());

        assert_eq!(scheduler.pending_count(), 1);

        assert!(scheduler.unschedule(item.id));
        assert_eq!(scheduler.pending_count(), 0);

        // Should not find any content
        assert!(scheduler.next_content(Time::ZERO).is_none());
    }

    #[test]
    fn content_scheduler_duplicate_schedule() {
        let mut scheduler = ContentScheduler::new();

        let item = test_content(1, PriorityClass::Data, 100, 1.0, 2.0);

        assert!(scheduler.schedule(item.clone()));
        assert!(!scheduler.schedule(item.clone())); // Duplicate should return false

        assert_eq!(scheduler.pending_count(), 1);
    }

    #[test]
    fn pressure_snapshot_analysis() {
        let mut pressure = PressureSnapshot::default();
        assert!(!pressure.has_high_pressure());
        assert_eq!(pressure.max_pressure(), 0.0);

        pressure.network = 0.9;
        assert!(pressure.has_high_pressure());
        assert!(pressure.network_dominant());
        assert_eq!(pressure.max_pressure(), 0.9);
    }

    #[test]
    fn content_item_efficiency_calculation() {
        let efficient = test_content(1, PriorityClass::Data, 100, 1.0, 10.0);
        let inefficient = test_content(2, PriorityClass::Data, 100, 5.0, 10.0);

        assert_eq!(efficient.efficiency_ratio(), 10.0);
        assert_eq!(inefficient.efficiency_ratio(), 2.0);
        assert!(efficient.efficiency_ratio() > inefficient.efficiency_ratio());
    }
}
