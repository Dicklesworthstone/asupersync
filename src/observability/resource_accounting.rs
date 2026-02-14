//! Resource accounting for obligations, budgets, and admission control (bd-3fp4g).
//!
//! Provides deterministic, monotone counters for tracking resource usage across
//! the obligation lifecycle, budget consumption, and region admission control.
//! Integrates with the existing [`MetricsProvider`] trait for zero-cost when
//! disabled and with the [`EvidenceLedger`] for decision auditing.
//!
//! # Design Principles
//!
//! 1. **Monotone where expected**: obligation creation counters, admission
//!    rejection counters, and budget consumption counters are monotonically
//!    increasing. Live gauges (pending obligations, live tasks) may decrease.
//! 2. **Deterministic**: all counters use atomic operations with relaxed
//!    ordering (sufficient for monotone counters). No wall-clock dependencies.
//! 3. **Zero hot-path allocations**: uses fixed-size atomic arrays indexed by
//!    `ObligationKind` discriminant and `AdmissionKind` discriminant.
//! 4. **Per-kind granularity**: tracks `SendPermit`, `Ack`, `Lease`, `IoOp`
//!    separately for obligation lifecycle events.
//!
//! # Usage
//!
//! ```
//! use asupersync::observability::resource_accounting::ResourceAccounting;
//! use asupersync::record::ObligationKind;
//! use asupersync::record::region::AdmissionKind;
//!
//! let accounting = ResourceAccounting::new();
//!
//! // Track obligation lifecycle
//! accounting.obligation_reserved(ObligationKind::SendPermit);
//! accounting.obligation_reserved(ObligationKind::Lease);
//! assert_eq!(accounting.obligations_reserved_by_kind(ObligationKind::SendPermit), 1);
//! assert_eq!(accounting.obligations_pending(), 2);
//!
//! accounting.obligation_committed(ObligationKind::SendPermit);
//! assert_eq!(accounting.obligations_pending(), 1);
//!
//! // Track admission control
//! accounting.admission_rejected(AdmissionKind::Task);
//! assert_eq!(accounting.admissions_rejected_by_kind(AdmissionKind::Task), 1);
//!
//! // High-water marks update automatically
//! assert_eq!(accounting.obligations_peak(), 2);
//! ```

use crate::record::region::AdmissionKind;
use crate::record::ObligationKind;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Number of [`ObligationKind`] variants.
const OBLIGATION_KIND_COUNT: usize = 4;
/// Number of [`AdmissionKind`] variants.
const ADMISSION_KIND_COUNT: usize = 4;

/// Maps an `ObligationKind` to its array index.
const fn obligation_index(kind: ObligationKind) -> usize {
    match kind {
        ObligationKind::SendPermit => 0,
        ObligationKind::Ack => 1,
        ObligationKind::Lease => 2,
        ObligationKind::IoOp => 3,
    }
}

/// Maps an `AdmissionKind` to its array index.
const fn admission_index(kind: AdmissionKind) -> usize {
    match kind {
        AdmissionKind::Child => 0,
        AdmissionKind::Task => 1,
        AdmissionKind::Obligation => 2,
        AdmissionKind::HeapBytes => 3,
    }
}

/// All obligation kinds for iteration.
const ALL_OBLIGATION_KINDS: [ObligationKind; OBLIGATION_KIND_COUNT] = [
    ObligationKind::SendPermit,
    ObligationKind::Ack,
    ObligationKind::Lease,
    ObligationKind::IoOp,
];

/// All admission kinds for iteration.
const ALL_ADMISSION_KINDS: [AdmissionKind; ADMISSION_KIND_COUNT] = [
    AdmissionKind::Child,
    AdmissionKind::Task,
    AdmissionKind::Obligation,
    AdmissionKind::HeapBytes,
];

/// Resource accounting for obligations, budgets, and admission control.
///
/// All counters are lock-free atomic operations, safe for concurrent access
/// from any thread. Monotone counters (reserved, committed, aborted, leaked,
/// rejected) never decrease. Live gauges (pending) track current state.
#[derive(Debug)]
pub struct ResourceAccounting {
    // === Obligation lifecycle (per-kind) ===
    /// Total obligations reserved, by kind.
    reserved: [AtomicU64; OBLIGATION_KIND_COUNT],
    /// Total obligations committed, by kind.
    committed: [AtomicU64; OBLIGATION_KIND_COUNT],
    /// Total obligations aborted, by kind.
    aborted: [AtomicU64; OBLIGATION_KIND_COUNT],
    /// Total obligations leaked, by kind.
    leaked: [AtomicU64; OBLIGATION_KIND_COUNT],

    // === Obligation aggregates ===
    /// Currently pending obligations (gauge: can increase and decrease).
    pending: AtomicI64,
    /// Peak pending obligations ever seen.
    pending_peak: AtomicI64,

    // === Budget consumption ===
    /// Total poll quota consumed across all tasks.
    poll_quota_consumed: AtomicU64,
    /// Total cost quota consumed across all tasks.
    cost_quota_consumed: AtomicU64,
    /// Number of times a task exhausted its poll quota.
    poll_quota_exhaustions: AtomicU64,
    /// Number of times a task exhausted its cost quota.
    cost_quota_exhaustions: AtomicU64,
    /// Number of deadline misses observed.
    deadline_misses: AtomicU64,

    // === Admission control ===
    /// Total admission rejections, by kind.
    admission_rejections: [AtomicU64; ADMISSION_KIND_COUNT],
    /// Total successful admissions, by kind.
    admission_successes: [AtomicU64; ADMISSION_KIND_COUNT],

    // === High-water marks ===
    /// Peak live tasks in any single region.
    tasks_peak: AtomicI64,
    /// Peak live children in any single region.
    children_peak: AtomicI64,
    /// Peak heap bytes in any single region.
    heap_bytes_peak: AtomicI64,
}

impl ResourceAccounting {
    /// Creates a new resource accounting instance with all counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            reserved: std::array::from_fn(|_| AtomicU64::new(0)),
            committed: std::array::from_fn(|_| AtomicU64::new(0)),
            aborted: std::array::from_fn(|_| AtomicU64::new(0)),
            leaked: std::array::from_fn(|_| AtomicU64::new(0)),
            pending: AtomicI64::new(0),
            pending_peak: AtomicI64::new(0),
            poll_quota_consumed: AtomicU64::new(0),
            cost_quota_consumed: AtomicU64::new(0),
            poll_quota_exhaustions: AtomicU64::new(0),
            cost_quota_exhaustions: AtomicU64::new(0),
            deadline_misses: AtomicU64::new(0),
            admission_rejections: std::array::from_fn(|_| AtomicU64::new(0)),
            admission_successes: std::array::from_fn(|_| AtomicU64::new(0)),
            tasks_peak: AtomicI64::new(0),
            children_peak: AtomicI64::new(0),
            heap_bytes_peak: AtomicI64::new(0),
        }
    }

    // ================================================================
    // Obligation lifecycle
    // ================================================================

    /// Record that an obligation of the given kind was reserved.
    pub fn obligation_reserved(&self, kind: ObligationKind) {
        self.reserved[obligation_index(kind)].fetch_add(1, Ordering::Relaxed);
        let new_pending = self.pending.fetch_add(1, Ordering::Relaxed) + 1;
        update_peak(&self.pending_peak, new_pending);
    }

    /// Record that an obligation of the given kind was committed.
    pub fn obligation_committed(&self, kind: ObligationKind) {
        self.committed[obligation_index(kind)].fetch_add(1, Ordering::Relaxed);
        self.pending.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record that an obligation of the given kind was aborted.
    pub fn obligation_aborted(&self, kind: ObligationKind) {
        self.aborted[obligation_index(kind)].fetch_add(1, Ordering::Relaxed);
        self.pending.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record that an obligation of the given kind was leaked.
    pub fn obligation_leaked(&self, kind: ObligationKind) {
        self.leaked[obligation_index(kind)].fetch_add(1, Ordering::Relaxed);
        self.pending.fetch_sub(1, Ordering::Relaxed);
    }

    // ================================================================
    // Obligation queries
    // ================================================================

    /// Returns the total number of obligations reserved for a specific kind.
    #[must_use]
    pub fn obligations_reserved_by_kind(&self, kind: ObligationKind) -> u64 {
        self.reserved[obligation_index(kind)].load(Ordering::Relaxed)
    }

    /// Returns the total number of obligations committed for a specific kind.
    #[must_use]
    pub fn obligations_committed_by_kind(&self, kind: ObligationKind) -> u64 {
        self.committed[obligation_index(kind)].load(Ordering::Relaxed)
    }

    /// Returns the total number of obligations aborted for a specific kind.
    #[must_use]
    pub fn obligations_aborted_by_kind(&self, kind: ObligationKind) -> u64 {
        self.aborted[obligation_index(kind)].load(Ordering::Relaxed)
    }

    /// Returns the total number of obligations leaked for a specific kind.
    #[must_use]
    pub fn obligations_leaked_by_kind(&self, kind: ObligationKind) -> u64 {
        self.leaked[obligation_index(kind)].load(Ordering::Relaxed)
    }

    /// Returns the total number of obligations reserved (all kinds).
    #[must_use]
    pub fn obligations_reserved_total(&self) -> u64 {
        self.reserved
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum()
    }

    /// Returns the total number of obligations committed (all kinds).
    #[must_use]
    pub fn obligations_committed_total(&self) -> u64 {
        self.committed
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum()
    }

    /// Returns the total number of obligations leaked (all kinds).
    #[must_use]
    pub fn obligations_leaked_total(&self) -> u64 {
        self.leaked.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    /// Returns the current number of pending obligations.
    #[must_use]
    pub fn obligations_pending(&self) -> i64 {
        self.pending.load(Ordering::Relaxed)
    }

    /// Returns the peak number of pending obligations ever seen.
    #[must_use]
    pub fn obligations_peak(&self) -> i64 {
        self.pending_peak.load(Ordering::Relaxed)
    }

    // ================================================================
    // Budget consumption
    // ================================================================

    /// Record that poll quota was consumed.
    pub fn poll_consumed(&self, amount: u64) {
        self.poll_quota_consumed
            .fetch_add(amount, Ordering::Relaxed);
    }

    /// Record that cost quota was consumed.
    pub fn cost_consumed(&self, amount: u64) {
        self.cost_quota_consumed
            .fetch_add(amount, Ordering::Relaxed);
    }

    /// Record that a task exhausted its poll quota.
    pub fn poll_quota_exhausted(&self) {
        self.poll_quota_exhaustions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a task exhausted its cost quota.
    pub fn cost_quota_exhausted(&self) {
        self.cost_quota_exhaustions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a deadline miss.
    pub fn deadline_missed(&self) {
        self.deadline_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the total poll quota consumed.
    #[must_use]
    pub fn total_poll_consumed(&self) -> u64 {
        self.poll_quota_consumed.load(Ordering::Relaxed)
    }

    /// Returns the total cost quota consumed.
    #[must_use]
    pub fn total_cost_consumed(&self) -> u64 {
        self.cost_quota_consumed.load(Ordering::Relaxed)
    }

    /// Returns the number of poll quota exhaustions.
    #[must_use]
    pub fn total_poll_exhaustions(&self) -> u64 {
        self.poll_quota_exhaustions.load(Ordering::Relaxed)
    }

    /// Returns the number of cost quota exhaustions.
    #[must_use]
    pub fn total_cost_exhaustions(&self) -> u64 {
        self.cost_quota_exhaustions.load(Ordering::Relaxed)
    }

    /// Returns the number of deadline misses.
    #[must_use]
    pub fn total_deadline_misses(&self) -> u64 {
        self.deadline_misses.load(Ordering::Relaxed)
    }

    // ================================================================
    // Admission control
    // ================================================================

    /// Record a successful admission.
    pub fn admission_succeeded(&self, kind: AdmissionKind) {
        self.admission_successes[admission_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rejected admission.
    pub fn admission_rejected(&self, kind: AdmissionKind) {
        self.admission_rejections[admission_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the number of admission rejections for a specific kind.
    #[must_use]
    pub fn admissions_rejected_by_kind(&self, kind: AdmissionKind) -> u64 {
        self.admission_rejections[admission_index(kind)].load(Ordering::Relaxed)
    }

    /// Returns the number of successful admissions for a specific kind.
    #[must_use]
    pub fn admissions_succeeded_by_kind(&self, kind: AdmissionKind) -> u64 {
        self.admission_successes[admission_index(kind)].load(Ordering::Relaxed)
    }

    /// Returns the total number of admission rejections (all kinds).
    #[must_use]
    pub fn admissions_rejected_total(&self) -> u64 {
        self.admission_rejections
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum()
    }

    // ================================================================
    // High-water marks
    // ================================================================

    /// Update the peak tasks gauge.
    pub fn update_tasks_peak(&self, current: i64) {
        update_peak(&self.tasks_peak, current);
    }

    /// Update the peak children gauge.
    pub fn update_children_peak(&self, current: i64) {
        update_peak(&self.children_peak, current);
    }

    /// Update the peak heap bytes gauge.
    pub fn update_heap_bytes_peak(&self, current: i64) {
        update_peak(&self.heap_bytes_peak, current);
    }

    /// Returns the peak tasks count.
    #[must_use]
    pub fn tasks_peak(&self) -> i64 {
        self.tasks_peak.load(Ordering::Relaxed)
    }

    /// Returns the peak children count.
    #[must_use]
    pub fn children_peak(&self) -> i64 {
        self.children_peak.load(Ordering::Relaxed)
    }

    /// Returns the peak heap bytes.
    #[must_use]
    pub fn heap_bytes_peak(&self) -> i64 {
        self.heap_bytes_peak.load(Ordering::Relaxed)
    }

    // ================================================================
    // Snapshot
    // ================================================================

    /// Takes a point-in-time snapshot of all accounting stats.
    #[must_use]
    pub fn snapshot(&self) -> ResourceAccountingSnapshot {
        let mut obligation_stats = Vec::with_capacity(OBLIGATION_KIND_COUNT);
        for &kind in &ALL_OBLIGATION_KINDS {
            let idx = obligation_index(kind);
            obligation_stats.push(ObligationKindStats {
                kind,
                reserved: self.reserved[idx].load(Ordering::Relaxed),
                committed: self.committed[idx].load(Ordering::Relaxed),
                aborted: self.aborted[idx].load(Ordering::Relaxed),
                leaked: self.leaked[idx].load(Ordering::Relaxed),
            });
        }

        let mut admission_stats = Vec::with_capacity(ADMISSION_KIND_COUNT);
        for &kind in &ALL_ADMISSION_KINDS {
            let idx = admission_index(kind);
            admission_stats.push(AdmissionKindStats {
                kind,
                successes: self.admission_successes[idx].load(Ordering::Relaxed),
                rejections: self.admission_rejections[idx].load(Ordering::Relaxed),
            });
        }

        ResourceAccountingSnapshot {
            obligation_stats,
            obligations_pending: self.pending.load(Ordering::Relaxed),
            obligations_peak: self.pending_peak.load(Ordering::Relaxed),
            admission_stats,
            poll_quota_consumed: self.poll_quota_consumed.load(Ordering::Relaxed),
            cost_quota_consumed: self.cost_quota_consumed.load(Ordering::Relaxed),
            poll_quota_exhaustions: self.poll_quota_exhaustions.load(Ordering::Relaxed),
            cost_quota_exhaustions: self.cost_quota_exhaustions.load(Ordering::Relaxed),
            deadline_misses: self.deadline_misses.load(Ordering::Relaxed),
            tasks_peak: self.tasks_peak.load(Ordering::Relaxed),
            children_peak: self.children_peak.load(Ordering::Relaxed),
            heap_bytes_peak: self.heap_bytes_peak.load(Ordering::Relaxed),
        }
    }
}

impl Default for ResourceAccounting {
    fn default() -> Self {
        Self::new()
    }
}

/// Atomically updates a peak gauge if the new value exceeds the current peak.
fn update_peak(peak: &AtomicI64, new_value: i64) {
    let mut current = peak.load(Ordering::Relaxed);
    while new_value > current {
        match peak.compare_exchange_weak(current, new_value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(v) => current = v,
        }
    }
}

// ============================================================================
// Snapshot types
// ============================================================================

/// Point-in-time snapshot of obligation lifecycle stats for a single kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationKindStats {
    /// Obligation kind.
    pub kind: ObligationKind,
    /// Total reserved.
    pub reserved: u64,
    /// Total committed.
    pub committed: u64,
    /// Total aborted.
    pub aborted: u64,
    /// Total leaked.
    pub leaked: u64,
}

impl ObligationKindStats {
    /// Returns the number of obligations that are currently unresolved
    /// (reserved but not yet committed, aborted, or leaked).
    #[must_use]
    pub fn pending(&self) -> u64 {
        self.reserved
            .saturating_sub(self.committed + self.aborted + self.leaked)
    }

    /// Returns the leak rate as a fraction of total reserved.
    #[must_use]
    pub fn leak_rate(&self) -> f64 {
        if self.reserved == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            self.leaked as f64 / self.reserved as f64
        }
    }
}

/// Point-in-time snapshot of admission control stats for a single kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionKindStats {
    /// Admission kind.
    pub kind: AdmissionKind,
    /// Total successful admissions.
    pub successes: u64,
    /// Total rejected admissions.
    pub rejections: u64,
}

impl AdmissionKindStats {
    /// Returns the rejection rate as a fraction of total attempts.
    #[must_use]
    pub fn rejection_rate(&self) -> f64 {
        let total = self.successes + self.rejections;
        if total == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            self.rejections as f64 / total as f64
        }
    }
}

/// Complete snapshot of all resource accounting stats.
#[derive(Debug, Clone)]
pub struct ResourceAccountingSnapshot {
    /// Per-kind obligation lifecycle stats.
    pub obligation_stats: Vec<ObligationKindStats>,
    /// Currently pending obligations.
    pub obligations_pending: i64,
    /// Peak pending obligations ever seen.
    pub obligations_peak: i64,
    /// Per-kind admission control stats.
    pub admission_stats: Vec<AdmissionKindStats>,
    /// Total poll quota consumed.
    pub poll_quota_consumed: u64,
    /// Total cost quota consumed.
    pub cost_quota_consumed: u64,
    /// Number of poll quota exhaustions.
    pub poll_quota_exhaustions: u64,
    /// Number of cost quota exhaustions.
    pub cost_quota_exhaustions: u64,
    /// Number of deadline misses.
    pub deadline_misses: u64,
    /// Peak tasks in any single region.
    pub tasks_peak: i64,
    /// Peak children in any single region.
    pub children_peak: i64,
    /// Peak heap bytes in any single region.
    pub heap_bytes_peak: i64,
}

impl ResourceAccountingSnapshot {
    /// Returns the total number of obligations reserved across all kinds.
    #[must_use]
    pub fn total_reserved(&self) -> u64 {
        self.obligation_stats.iter().map(|s| s.reserved).sum()
    }

    /// Returns the total number of obligations leaked across all kinds.
    #[must_use]
    pub fn total_leaked(&self) -> u64 {
        self.obligation_stats.iter().map(|s| s.leaked).sum()
    }

    /// Returns the total number of admission rejections across all kinds.
    #[must_use]
    pub fn total_rejections(&self) -> u64 {
        self.admission_stats.iter().map(|s| s.rejections).sum()
    }

    /// Returns true if no obligations have ever leaked.
    #[must_use]
    pub fn is_leak_free(&self) -> bool {
        self.total_leaked() == 0
    }

    /// Renders a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();

        writeln!(out, "Resource Accounting Snapshot").ok();
        writeln!(out, "===========================").ok();
        writeln!(out).ok();

        writeln!(out, "Obligations:").ok();
        for s in &self.obligation_stats {
            writeln!(
                out,
                "  {:12}: reserved={:<6} committed={:<6} aborted={:<6} leaked={:<6} pending={}",
                s.kind.as_str(),
                s.reserved,
                s.committed,
                s.aborted,
                s.leaked,
                s.pending()
            )
            .ok();
        }
        writeln!(
            out,
            "  Total pending: {}  Peak: {}",
            self.obligations_pending, self.obligations_peak
        )
        .ok();
        writeln!(out).ok();

        writeln!(out, "Budget:").ok();
        writeln!(
            out,
            "  Poll consumed: {}  Exhaustions: {}",
            self.poll_quota_consumed, self.poll_quota_exhaustions
        )
        .ok();
        writeln!(
            out,
            "  Cost consumed: {}  Exhaustions: {}",
            self.cost_quota_consumed, self.cost_quota_exhaustions
        )
        .ok();
        writeln!(out, "  Deadline misses: {}", self.deadline_misses).ok();
        writeln!(out).ok();

        writeln!(out, "Admission Control:").ok();
        for s in &self.admission_stats {
            writeln!(
                out,
                "  {:12}: admitted={:<6} rejected={:<6} rate={:.1}%",
                format!("{:?}", s.kind),
                s.successes,
                s.rejections,
                s.rejection_rate() * 100.0
            )
            .ok();
        }
        writeln!(out).ok();

        writeln!(out, "High-Water Marks:").ok();
        writeln!(out, "  Tasks peak: {}", self.tasks_peak).ok();
        writeln!(out, "  Children peak: {}", self.children_peak).ok();
        writeln!(out, "  Heap bytes peak: {}", self.heap_bytes_peak).ok();

        out
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obligation_lifecycle_tracking() {
        let acc = ResourceAccounting::new();

        acc.obligation_reserved(ObligationKind::SendPermit);
        acc.obligation_reserved(ObligationKind::SendPermit);
        acc.obligation_reserved(ObligationKind::Lease);

        assert_eq!(
            acc.obligations_reserved_by_kind(ObligationKind::SendPermit),
            2
        );
        assert_eq!(acc.obligations_reserved_by_kind(ObligationKind::Lease), 1);
        assert_eq!(acc.obligations_reserved_by_kind(ObligationKind::Ack), 0);
        assert_eq!(acc.obligations_reserved_total(), 3);
        assert_eq!(acc.obligations_pending(), 3);
        assert_eq!(acc.obligations_peak(), 3);

        acc.obligation_committed(ObligationKind::SendPermit);
        assert_eq!(
            acc.obligations_committed_by_kind(ObligationKind::SendPermit),
            1
        );
        assert_eq!(acc.obligations_pending(), 2);

        acc.obligation_aborted(ObligationKind::SendPermit);
        assert_eq!(
            acc.obligations_aborted_by_kind(ObligationKind::SendPermit),
            1
        );
        assert_eq!(acc.obligations_pending(), 1);

        acc.obligation_leaked(ObligationKind::Lease);
        assert_eq!(acc.obligations_leaked_by_kind(ObligationKind::Lease), 1);
        assert_eq!(acc.obligations_pending(), 0);
        assert_eq!(acc.obligations_leaked_total(), 1);

        // Peak should still be 3
        assert_eq!(acc.obligations_peak(), 3);
    }

    #[test]
    fn peak_updates_correctly() {
        let acc = ResourceAccounting::new();

        // Reserve 5, then resolve 3, then reserve 2 more
        for _ in 0..5 {
            acc.obligation_reserved(ObligationKind::Ack);
        }
        assert_eq!(acc.obligations_peak(), 5);

        for _ in 0..3 {
            acc.obligation_committed(ObligationKind::Ack);
        }
        assert_eq!(acc.obligations_pending(), 2);
        assert_eq!(acc.obligations_peak(), 5); // peak unchanged

        for _ in 0..2 {
            acc.obligation_reserved(ObligationKind::Ack);
        }
        assert_eq!(acc.obligations_pending(), 4);
        assert_eq!(acc.obligations_peak(), 5); // peak still 5

        // Push past peak
        for _ in 0..2 {
            acc.obligation_reserved(ObligationKind::Ack);
        }
        assert_eq!(acc.obligations_peak(), 6);
    }

    #[test]
    fn budget_consumption_tracking() {
        let acc = ResourceAccounting::new();

        acc.poll_consumed(10);
        acc.poll_consumed(5);
        assert_eq!(acc.total_poll_consumed(), 15);

        acc.cost_consumed(100);
        assert_eq!(acc.total_cost_consumed(), 100);

        acc.poll_quota_exhausted();
        acc.poll_quota_exhausted();
        assert_eq!(acc.total_poll_exhaustions(), 2);

        acc.cost_quota_exhausted();
        assert_eq!(acc.total_cost_exhaustions(), 1);

        acc.deadline_missed();
        acc.deadline_missed();
        acc.deadline_missed();
        assert_eq!(acc.total_deadline_misses(), 3);
    }

    #[test]
    fn admission_control_tracking() {
        let acc = ResourceAccounting::new();

        acc.admission_succeeded(AdmissionKind::Task);
        acc.admission_succeeded(AdmissionKind::Task);
        acc.admission_succeeded(AdmissionKind::Task);
        acc.admission_rejected(AdmissionKind::Task);

        assert_eq!(acc.admissions_succeeded_by_kind(AdmissionKind::Task), 3);
        assert_eq!(acc.admissions_rejected_by_kind(AdmissionKind::Task), 1);

        acc.admission_rejected(AdmissionKind::Child);
        acc.admission_rejected(AdmissionKind::Obligation);
        assert_eq!(acc.admissions_rejected_total(), 3);
    }

    #[test]
    fn high_water_marks() {
        let acc = ResourceAccounting::new();

        acc.update_tasks_peak(5);
        assert_eq!(acc.tasks_peak(), 5);

        acc.update_tasks_peak(3); // lower — no change
        assert_eq!(acc.tasks_peak(), 5);

        acc.update_tasks_peak(8); // higher — updates
        assert_eq!(acc.tasks_peak(), 8);

        acc.update_children_peak(2);
        assert_eq!(acc.children_peak(), 2);

        acc.update_heap_bytes_peak(1024);
        assert_eq!(acc.heap_bytes_peak(), 1024);
    }

    #[test]
    fn snapshot_captures_all_stats() {
        let acc = ResourceAccounting::new();

        acc.obligation_reserved(ObligationKind::SendPermit);
        acc.obligation_reserved(ObligationKind::Lease);
        acc.obligation_committed(ObligationKind::SendPermit);
        acc.obligation_leaked(ObligationKind::Lease);
        acc.admission_rejected(AdmissionKind::Task);
        acc.poll_consumed(42);
        acc.deadline_missed();

        let snap = acc.snapshot();

        assert_eq!(snap.total_reserved(), 2);
        assert_eq!(snap.total_leaked(), 1);
        assert_eq!(snap.total_rejections(), 1);
        assert!(!snap.is_leak_free());
        assert_eq!(snap.poll_quota_consumed, 42);
        assert_eq!(snap.deadline_misses, 1);
    }

    #[test]
    fn snapshot_is_leak_free() {
        let acc = ResourceAccounting::new();

        acc.obligation_reserved(ObligationKind::SendPermit);
        acc.obligation_committed(ObligationKind::SendPermit);

        let snap = acc.snapshot();
        assert!(snap.is_leak_free());
    }

    #[test]
    fn obligation_kind_stats_methods() {
        let stats = ObligationKindStats {
            kind: ObligationKind::SendPermit,
            reserved: 10,
            committed: 6,
            aborted: 2,
            leaked: 1,
        };

        assert_eq!(stats.pending(), 1);
        assert!((stats.leak_rate() - 0.1).abs() < 0.001);
    }

    #[test]
    fn obligation_kind_stats_zero_reserved() {
        let stats = ObligationKindStats {
            kind: ObligationKind::Ack,
            reserved: 0,
            committed: 0,
            aborted: 0,
            leaked: 0,
        };

        assert_eq!(stats.pending(), 0);
        assert!(stats.leak_rate().abs() < f64::EPSILON);
    }

    #[test]
    fn admission_kind_stats_rejection_rate() {
        let stats = AdmissionKindStats {
            kind: AdmissionKind::Task,
            successes: 90,
            rejections: 10,
        };

        assert!((stats.rejection_rate() - 0.1).abs() < 0.001);
    }

    #[test]
    fn admission_kind_stats_zero_attempts() {
        let stats = AdmissionKindStats {
            kind: AdmissionKind::Child,
            successes: 0,
            rejections: 0,
        };

        assert!(stats.rejection_rate().abs() < f64::EPSILON);
    }

    #[test]
    fn snapshot_summary_format() {
        let acc = ResourceAccounting::new();
        acc.obligation_reserved(ObligationKind::SendPermit);
        acc.obligation_committed(ObligationKind::SendPermit);
        acc.admission_rejected(AdmissionKind::Task);

        let snap = acc.snapshot();
        let summary = snap.summary();

        assert!(summary.contains("Resource Accounting Snapshot"));
        assert!(summary.contains("send_permit"));
        assert!(summary.contains("Task"));
        assert!(summary.contains("Poll consumed"));
    }

    #[test]
    fn default_is_new() {
        let a = ResourceAccounting::new();
        let b = ResourceAccounting::default();

        assert_eq!(a.obligations_pending(), b.obligations_pending());
        assert_eq!(a.obligations_peak(), b.obligations_peak());
    }

    #[test]
    fn all_obligation_kinds_covered() {
        let acc = ResourceAccounting::new();

        // Ensure all kinds can be tracked without panic
        for &kind in &ALL_OBLIGATION_KINDS {
            acc.obligation_reserved(kind);
            acc.obligation_committed(kind);
        }

        assert_eq!(acc.obligations_reserved_total(), 4);
        assert_eq!(acc.obligations_committed_total(), 4);
        assert_eq!(acc.obligations_pending(), 0);
    }

    #[test]
    fn all_admission_kinds_covered() {
        let acc = ResourceAccounting::new();

        for &kind in &ALL_ADMISSION_KINDS {
            acc.admission_succeeded(kind);
            acc.admission_rejected(kind);
        }

        assert_eq!(acc.admissions_rejected_total(), 4);
    }
}
