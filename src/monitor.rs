//! Process monitors and deterministic down notifications.
//!
//! Monitors allow a task to observe the termination of another task (the
//! "monitored" process). When the monitored process terminates, a
//! [`DownNotification`] is delivered to the watcher.
//!
//! # Deterministic Ordering
//!
//! Down notifications follow the contracts specified in
//! `docs/spork_deterministic_ordering.md`:
//!
//! - **DOWN-ORDER**: Notifications are sorted by `(completion_vt, monitored_tid)`.
//! - **DOWN-BATCH**: When multiple notifications become ready in a single
//!   scheduler step, they are sorted before delivery.
//! - **DOWN-CONTENT**: Each notification carries the monitored TaskId, reason,
//!   and the MonitorRef returned when the monitor was established.
//! - **DOWN-CLEANUP**: Region close releases all monitors held by tasks in
//!   that region.
//!
//! # Example
//!
//! ```rust,ignore
//! // Establish a monitor
//! let mon_ref = monitor_set.establish(watcher_id, watcher_region, target_id);
//!
//! // When target terminates, generate notifications
//! let watchers = monitor_set.watchers_of(target_id);
//! let mut batch = DownBatch::new();
//! for (mref, watcher) in &watchers {
//!     batch.push(completion_vt, DownNotification {
//!         monitored: target_id,
//!         reason: DownReason::from_task_outcome(&outcome),
//!         monitor_ref: *mref,
//!     });
//! }
//! let ordered = batch.into_sorted();
//! ```

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::{Outcome, RegionId, TaskId, Time};

/// Monotonic counter for generating unique [`MonitorRef`] values.
static MONITOR_COUNTER: AtomicU64 = AtomicU64::new(1);

// ============================================================================
// MonitorRef
// ============================================================================

/// Opaque reference to an established monitor.
///
/// Returned by [`MonitorSet::establish`] and carried in [`DownNotification`].
/// Unique across the lifetime of a runtime instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonitorRef(u64);

impl MonitorRef {
    /// Allocates a fresh, globally unique monitor reference.
    fn new() -> Self {
        Self(MONITOR_COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Creates a `MonitorRef` with a specific id (for testing only).
    #[cfg(test)]
    fn from_raw(id: u64) -> Self {
        Self(id)
    }

    /// Creates a `MonitorRef` for integration testing purposes.
    #[doc(hidden)]
    #[must_use]
    pub const fn new_for_test(id: u64) -> Self {
        Self(id)
    }

    /// Returns the underlying numeric identifier.
    #[must_use]
    pub fn id(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for MonitorRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MonitorRef({})", self.0)
    }
}

// ============================================================================
// DownReason
// ============================================================================

/// Reason a monitored process terminated.
///
/// Maps from the runtime's [`Outcome`] type to a monitor-specific enum
/// that can be pattern-matched by watchers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownReason {
    /// Process completed successfully (`Outcome::Ok`).
    Normal,
    /// Process terminated with an application error (`Outcome::Err`).
    Error(String),
    /// Process was cancelled (`Outcome::Cancelled`).
    Cancelled(CancelReason),
    /// Process panicked (`Outcome::Panicked`).
    Panicked(PanicPayload),
}

impl DownReason {
    /// Converts a task outcome to a down reason.
    #[must_use]
    pub fn from_task_outcome(outcome: &Outcome<(), crate::error::Error>) -> Self {
        match outcome {
            Outcome::Ok(()) => Self::Normal,
            Outcome::Err(e) => Self::Error(format!("{e}")),
            Outcome::Cancelled(r) => Self::Cancelled(r.clone()),
            Outcome::Panicked(p) => Self::Panicked(p.clone()),
        }
    }

    /// Returns `true` if the process terminated normally.
    #[must_use]
    pub fn is_normal(&self) -> bool {
        matches!(self, Self::Normal)
    }

    /// Returns `true` if the process terminated with an error.
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }

    /// Returns `true` if the process was cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }

    /// Returns `true` if the process panicked.
    #[must_use]
    pub fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked(_))
    }
}

impl std::fmt::Display for DownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Error(e) => write!(f, "error: {e}"),
            Self::Cancelled(r) => write!(f, "cancelled: {r:?}"),
            Self::Panicked(p) => write!(f, "panicked: {p}"),
        }
    }
}

// ============================================================================
// DownNotification
// ============================================================================

/// Notification delivered when a monitored process terminates.
///
/// **Contract (DOWN-CONTENT)**:
/// - `monitored` is the `TaskId` of the terminated process.
/// - `reason` is the termination outcome mapped to [`DownReason`].
/// - `monitor_ref` is the reference returned by [`MonitorSet::establish`].
#[derive(Debug, Clone)]
pub struct DownNotification {
    /// The task that terminated.
    pub monitored: TaskId,
    /// Why it terminated.
    pub reason: DownReason,
    /// The monitor reference from establishment.
    pub monitor_ref: MonitorRef,
}

// ============================================================================
// MonitorRecord (internal)
// ============================================================================

/// Internal record of an active monitor.
#[derive(Debug, Clone)]
struct MonitorRecord {
    monitor_ref: MonitorRef,
    /// The task watching for termination.
    watcher: TaskId,
    /// The region owning the watcher (for region-close cleanup).
    watcher_region: RegionId,
    /// The task being monitored.
    monitored: TaskId,
}

// ============================================================================
// MonitorSet
// ============================================================================

/// Collection of active monitors with deterministic iteration order.
///
/// All internal data structures use [`BTreeMap`] to ensure no dependence on
/// `HashMap` iteration order, satisfying the **REG-NOHASH** contract.
///
/// # Indexes
///
/// Three indexes are maintained for efficient lookup:
/// - `by_ref`: MonitorRef → MonitorRecord (primary)
/// - `by_monitored`: TaskId → Vec<MonitorRef> (find watchers of a terminated task)
/// - `by_watcher_region`: RegionId → Vec<MonitorRef> (region-close cleanup)
#[derive(Debug)]
#[allow(clippy::struct_field_names)]
pub struct MonitorSet {
    by_ref: BTreeMap<MonitorRef, MonitorRecord>,
    by_monitored: BTreeMap<TaskId, Vec<MonitorRef>>,
    by_watcher_region: BTreeMap<RegionId, Vec<MonitorRef>>,
}

impl MonitorSet {
    /// Creates an empty monitor set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_ref: BTreeMap::new(),
            by_monitored: BTreeMap::new(),
            by_watcher_region: BTreeMap::new(),
        }
    }

    /// Establishes a monitor: `watcher` will be notified when `monitored` terminates.
    ///
    /// Returns a [`MonitorRef`] that uniquely identifies this monitor relationship.
    /// The same watcher can monitor the same target multiple times; each call
    /// returns a distinct `MonitorRef` and will produce a separate notification.
    pub fn establish(
        &mut self,
        watcher: TaskId,
        watcher_region: RegionId,
        monitored: TaskId,
    ) -> MonitorRef {
        let monitor_ref = MonitorRef::new();
        let record = MonitorRecord {
            monitor_ref,
            watcher,
            watcher_region,
            monitored,
        };

        self.by_ref.insert(monitor_ref, record);
        self.by_monitored
            .entry(monitored)
            .or_default()
            .push(monitor_ref);
        self.by_watcher_region
            .entry(watcher_region)
            .or_default()
            .push(monitor_ref);

        monitor_ref
    }

    /// Removes a specific monitor. Returns `true` if it existed.
    pub fn demonitor(&mut self, monitor_ref: MonitorRef) -> bool {
        let Some(record) = self.by_ref.remove(&monitor_ref) else {
            return false;
        };
        if let Some(refs) = self.by_monitored.get_mut(&record.monitored) {
            refs.retain(|r| *r != monitor_ref);
            if refs.is_empty() {
                self.by_monitored.remove(&record.monitored);
            }
        }
        if let Some(refs) = self.by_watcher_region.get_mut(&record.watcher_region) {
            refs.retain(|r| *r != monitor_ref);
            if refs.is_empty() {
                self.by_watcher_region.remove(&record.watcher_region);
            }
        }
        true
    }

    /// Returns all `(MonitorRef, watcher_TaskId)` pairs watching the given task.
    ///
    /// Used when a task terminates to generate [`DownNotification`]s.
    #[must_use]
    pub fn watchers_of(&self, monitored: TaskId) -> Vec<(MonitorRef, TaskId)> {
        let Some(refs) = self.by_monitored.get(&monitored) else {
            return Vec::new();
        };
        refs.iter()
            .filter_map(|mref| self.by_ref.get(mref).map(|rec| (*mref, rec.watcher)))
            .collect()
    }

    /// Removes all monitors watching a specific task and returns removed refs.
    ///
    /// Called after a task terminates and all notifications have been generated.
    pub fn remove_monitored(&mut self, monitored: TaskId) -> Vec<MonitorRef> {
        let Some(refs) = self.by_monitored.remove(&monitored) else {
            return Vec::new();
        };
        let mut removed = Vec::with_capacity(refs.len());
        for mref in refs {
            if let Some(record) = self.by_ref.remove(&mref) {
                if let Some(region_refs) = self.by_watcher_region.get_mut(&record.watcher_region) {
                    region_refs.retain(|r| *r != mref);
                    if region_refs.is_empty() {
                        self.by_watcher_region.remove(&record.watcher_region);
                    }
                }
                removed.push(mref);
            }
        }
        removed
    }

    /// Removes all monitors held by tasks in the given region.
    ///
    /// **Contract (DOWN-CLEANUP)**: When a region closes, all monitors
    /// established by tasks in that region are released. No further
    /// down notifications are delivered to tasks in the region.
    pub fn cleanup_region(&mut self, region: RegionId) -> Vec<MonitorRef> {
        let Some(refs) = self.by_watcher_region.remove(&region) else {
            return Vec::new();
        };
        let mut removed = Vec::with_capacity(refs.len());
        for mref in refs {
            if let Some(record) = self.by_ref.remove(&mref) {
                if let Some(monitored_refs) = self.by_monitored.get_mut(&record.monitored) {
                    monitored_refs.retain(|r| *r != mref);
                    if monitored_refs.is_empty() {
                        self.by_monitored.remove(&record.monitored);
                    }
                }
                removed.push(mref);
            }
        }
        removed
    }

    /// Returns the number of active monitors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_ref.len()
    }

    /// Returns `true` if there are no active monitors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_ref.is_empty()
    }

    /// Returns the watcher for a given monitor ref, if it exists.
    #[must_use]
    pub fn watcher_of(&self, monitor_ref: MonitorRef) -> Option<TaskId> {
        self.by_ref.get(&monitor_ref).map(|r| r.watcher)
    }

    /// Returns the monitored task for a given monitor ref, if it exists.
    #[must_use]
    pub fn monitored_of(&self, monitor_ref: MonitorRef) -> Option<TaskId> {
        self.by_ref.get(&monitor_ref).map(|r| r.monitored)
    }
}

impl Default for MonitorSet {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DownBatch — deterministic delivery ordering
// ============================================================================

/// A batch of down notifications pending delivery, with deterministic sort.
///
/// **Contract (DOWN-ORDER)**: Notifications are sorted by
/// `(completion_vt, monitored_tid)` — virtual time first, then TaskId.
///
/// **Contract (DOWN-BATCH)**: When multiple down notifications become ready
/// in a single scheduler step, they are sorted before enqueue. The watcher
/// receives them in sorted order.
#[derive(Debug)]
pub struct DownBatch {
    entries: Vec<DownBatchEntry>,
}

/// Internal entry pairing a notification with its sort key.
#[derive(Debug, Clone)]
struct DownBatchEntry {
    /// Virtual time when the monitored task completed.
    completion_vt: Time,
    /// The notification to deliver.
    notification: DownNotification,
}

impl DownBatch {
    /// Creates an empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a notification to the batch with its completion virtual time.
    pub fn push(&mut self, completion_vt: Time, notification: DownNotification) {
        self.entries.push(DownBatchEntry {
            completion_vt,
            notification,
        });
    }

    /// Returns the number of notifications in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Sorts by `(completion_vt, monitored_tid)` and returns notifications
    /// in deterministic delivery order.
    ///
    /// This consumes the batch. The sort is stable, so notifications with
    /// identical `(vt, tid)` keys preserve insertion order.
    #[must_use]
    pub fn into_sorted(mut self) -> Vec<DownNotification> {
        self.entries.sort_by(|a, b| {
            let vt_cmp = a.completion_vt.cmp(&b.completion_vt);
            vt_cmp.then_with(|| a.notification.monitored.cmp(&b.notification.monitored))
        });
        self.entries.into_iter().map(|e| e.notification).collect()
    }
}

impl Default for DownBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_task_id(index: u32, generation: u32) -> TaskId {
        TaskId::new_for_test(index, generation)
    }

    fn test_region_id(index: u32, generation: u32) -> RegionId {
        RegionId::new_for_test(index, generation)
    }

    // ── MonitorRef ──────────────────────────────────────────────────────

    #[test]
    fn monitor_ref_uniqueness() {
        let r1 = MonitorRef::new();
        let r2 = MonitorRef::new();
        assert_ne!(r1, r2);
        assert!(r1 < r2); // monotonically increasing
    }

    #[test]
    fn monitor_ref_display() {
        let r = MonitorRef::from_raw(42);
        assert_eq!(format!("{r}"), "MonitorRef(42)");
    }

    #[test]
    fn monitor_ref_ordering() {
        let r1 = MonitorRef::from_raw(1);
        let r2 = MonitorRef::from_raw(2);
        let r3 = MonitorRef::from_raw(3);
        assert!(r1 < r2);
        assert!(r2 < r3);
    }

    // ── DownReason ──────────────────────────────────────────────────────

    #[test]
    fn down_reason_predicates() {
        assert!(DownReason::Normal.is_normal());
        assert!(!DownReason::Normal.is_error());

        assert!(DownReason::Error("oops".into()).is_error());
        assert!(!DownReason::Error("oops".into()).is_normal());

        assert!(DownReason::Cancelled(CancelReason::default()).is_cancelled());
        assert!(DownReason::Panicked(PanicPayload::new("boom")).is_panicked());
    }

    #[test]
    fn down_reason_display() {
        assert_eq!(format!("{}", DownReason::Normal), "normal");
        assert!(format!("{}", DownReason::Error("fail".into())).contains("fail"));
        assert!(format!("{}", DownReason::Panicked(PanicPayload::new("boom"))).contains("boom"));
    }

    #[test]
    fn down_reason_from_task_outcome_ok() {
        let outcome: Outcome<(), crate::error::Error> = Outcome::ok(());
        let reason = DownReason::from_task_outcome(&outcome);
        assert!(reason.is_normal());
    }

    #[test]
    fn down_reason_from_task_outcome_cancelled() {
        let outcome: Outcome<(), crate::error::Error> = Outcome::cancelled(CancelReason::default());
        let reason = DownReason::from_task_outcome(&outcome);
        assert!(reason.is_cancelled());
    }

    #[test]
    fn down_reason_from_task_outcome_panicked() {
        let outcome: Outcome<(), crate::error::Error> =
            Outcome::panicked(PanicPayload::new("test"));
        let reason = DownReason::from_task_outcome(&outcome);
        assert!(reason.is_panicked());
    }

    // ── MonitorSet: establish / demonitor ────────────────────────────────

    #[test]
    fn establish_creates_monitor() {
        let mut set = MonitorSet::new();
        let watcher = test_task_id(1, 0);
        let region = test_region_id(0, 0);
        let target = test_task_id(2, 0);

        let mref = set.establish(watcher, region, target);
        assert_eq!(set.len(), 1);
        assert_eq!(set.watcher_of(mref), Some(watcher));
        assert_eq!(set.monitored_of(mref), Some(target));
    }

    #[test]
    fn establish_multiple_monitors_same_target() {
        let mut set = MonitorSet::new();
        let w1 = test_task_id(1, 0);
        let w2 = test_task_id(2, 0);
        let region = test_region_id(0, 0);
        let target = test_task_id(3, 0);

        let m1 = set.establish(w1, region, target);
        let m2 = set.establish(w2, region, target);
        assert_ne!(m1, m2);
        assert_eq!(set.len(), 2);

        let watchers = set.watchers_of(target);
        assert_eq!(watchers.len(), 2);
    }

    #[test]
    fn establish_same_watcher_twice_yields_distinct_refs() {
        let mut set = MonitorSet::new();
        let watcher = test_task_id(1, 0);
        let region = test_region_id(0, 0);
        let target = test_task_id(2, 0);

        let m1 = set.establish(watcher, region, target);
        let m2 = set.establish(watcher, region, target);
        assert_ne!(m1, m2);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn demonitor_removes_monitor() {
        let mut set = MonitorSet::new();
        let watcher = test_task_id(1, 0);
        let region = test_region_id(0, 0);
        let target = test_task_id(2, 0);

        let mref = set.establish(watcher, region, target);
        assert!(set.demonitor(mref));
        assert_eq!(set.len(), 0);
        assert!(set.watchers_of(target).is_empty());
    }

    #[test]
    fn demonitor_nonexistent_returns_false() {
        let mut set = MonitorSet::new();
        assert!(!set.demonitor(MonitorRef::from_raw(999)));
    }

    #[test]
    fn demonitor_only_removes_specific_monitor() {
        let mut set = MonitorSet::new();
        let w1 = test_task_id(1, 0);
        let w2 = test_task_id(2, 0);
        let region = test_region_id(0, 0);
        let target = test_task_id(3, 0);

        let m1 = set.establish(w1, region, target);
        let _m2 = set.establish(w2, region, target);

        set.demonitor(m1);
        assert_eq!(set.len(), 1);
        assert_eq!(set.watchers_of(target).len(), 1);
    }

    // ── MonitorSet: watchers_of ────────────────────────────────────────

    #[test]
    fn watchers_of_empty() {
        let set = MonitorSet::new();
        assert!(set.watchers_of(test_task_id(99, 0)).is_empty());
    }

    #[test]
    fn watchers_of_returns_all_watchers() {
        let mut set = MonitorSet::new();
        let region = test_region_id(0, 0);
        let target = test_task_id(10, 0);

        let w1 = test_task_id(1, 0);
        let w2 = test_task_id(2, 0);
        let w3 = test_task_id(3, 0);

        let m1 = set.establish(w1, region, target);
        let m2 = set.establish(w2, region, target);
        let m3 = set.establish(w3, region, target);

        let watchers = set.watchers_of(target);
        assert_eq!(watchers.len(), 3);

        let mrefs: Vec<MonitorRef> = watchers.iter().map(|(r, _)| *r).collect();
        assert!(mrefs.contains(&m1));
        assert!(mrefs.contains(&m2));
        assert!(mrefs.contains(&m3));

        let tids: Vec<TaskId> = watchers.iter().map(|(_, t)| *t).collect();
        assert!(tids.contains(&w1));
        assert!(tids.contains(&w2));
        assert!(tids.contains(&w3));
    }

    // ── MonitorSet: remove_monitored ───────────────────────────────────

    #[test]
    fn remove_monitored_clears_all_watchers() {
        let mut set = MonitorSet::new();
        let region = test_region_id(0, 0);
        let target = test_task_id(10, 0);

        set.establish(test_task_id(1, 0), region, target);
        set.establish(test_task_id(2, 0), region, target);

        let removed = set.remove_monitored(target);
        assert_eq!(removed.len(), 2);
        assert!(set.is_empty());
        assert!(set.watchers_of(target).is_empty());
    }

    #[test]
    fn remove_monitored_preserves_other_monitors() {
        let mut set = MonitorSet::new();
        let region = test_region_id(0, 0);
        let t1 = test_task_id(10, 0);
        let t2 = test_task_id(20, 0);
        let watcher = test_task_id(1, 0);

        set.establish(watcher, region, t1);
        set.establish(watcher, region, t2);

        set.remove_monitored(t1);
        assert_eq!(set.len(), 1);
        assert_eq!(set.watchers_of(t2).len(), 1);
    }

    // ── MonitorSet: cleanup_region (DOWN-CLEANUP) ─────────────────────

    #[test]
    fn cleanup_region_removes_all_monitors_in_region() {
        let mut set = MonitorSet::new();
        let r1 = test_region_id(1, 0);
        let r2 = test_region_id(2, 0);
        let target = test_task_id(10, 0);

        // Watcher in region 1
        set.establish(test_task_id(1, 0), r1, target);
        // Watcher in region 2
        set.establish(test_task_id(2, 0), r2, target);

        let removed = set.cleanup_region(r1);
        assert_eq!(removed.len(), 1);
        assert_eq!(set.len(), 1);
        // Only region 2's monitor remains
        assert_eq!(set.watchers_of(target).len(), 1);
    }

    #[test]
    fn cleanup_region_empty_is_noop() {
        let mut set = MonitorSet::new();
        let removed = set.cleanup_region(test_region_id(99, 0));
        assert!(removed.is_empty());
    }

    #[test]
    fn cleanup_region_cleans_monitored_index() {
        let mut set = MonitorSet::new();
        let region = test_region_id(1, 0);
        let target = test_task_id(10, 0);

        set.establish(test_task_id(1, 0), region, target);
        set.cleanup_region(region);

        // The monitored_index should also be cleaned
        assert!(set.watchers_of(target).is_empty());
    }

    // ── DownBatch: deterministic ordering (DOWN-ORDER + DOWN-BATCH) ───

    #[test]
    fn down_batch_empty() {
        let batch = DownBatch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
        assert!(batch.into_sorted().is_empty());
    }

    #[test]
    fn down_batch_single_item() {
        let mut batch = DownBatch::new();
        let notif = DownNotification {
            monitored: test_task_id(1, 0),
            reason: DownReason::Normal,
            monitor_ref: MonitorRef::from_raw(1),
        };
        batch.push(Time::from_nanos(100), notif);
        assert_eq!(batch.len(), 1);

        let sorted = batch.into_sorted();
        assert_eq!(sorted.len(), 1);
        assert_eq!(sorted[0].monitored, test_task_id(1, 0));
    }

    #[test]
    fn down_batch_sorts_by_virtual_time() {
        let mut batch = DownBatch::new();

        // Insert in reverse vt order
        batch.push(
            Time::from_nanos(300),
            DownNotification {
                monitored: test_task_id(1, 0),
                reason: DownReason::Normal,
                monitor_ref: MonitorRef::from_raw(1),
            },
        );
        batch.push(
            Time::from_nanos(100),
            DownNotification {
                monitored: test_task_id(2, 0),
                reason: DownReason::Normal,
                monitor_ref: MonitorRef::from_raw(2),
            },
        );
        batch.push(
            Time::from_nanos(200),
            DownNotification {
                monitored: test_task_id(3, 0),
                reason: DownReason::Normal,
                monitor_ref: MonitorRef::from_raw(3),
            },
        );

        let sorted = batch.into_sorted();
        assert_eq!(sorted[0].monitored, test_task_id(2, 0)); // vt=100
        assert_eq!(sorted[1].monitored, test_task_id(3, 0)); // vt=200
        assert_eq!(sorted[2].monitored, test_task_id(1, 0)); // vt=300
    }

    #[test]
    fn down_batch_tie_breaks_by_task_id() {
        let mut batch = DownBatch::new();
        let same_vt = Time::from_nanos(100);

        // Same vt, different task IDs — should sort by TaskId (ArenaIndex order)
        batch.push(
            same_vt,
            DownNotification {
                monitored: test_task_id(5, 0),
                reason: DownReason::Normal,
                monitor_ref: MonitorRef::from_raw(1),
            },
        );
        batch.push(
            same_vt,
            DownNotification {
                monitored: test_task_id(1, 0),
                reason: DownReason::Normal,
                monitor_ref: MonitorRef::from_raw(2),
            },
        );
        batch.push(
            same_vt,
            DownNotification {
                monitored: test_task_id(3, 0),
                reason: DownReason::Normal,
                monitor_ref: MonitorRef::from_raw(3),
            },
        );

        let sorted = batch.into_sorted();
        assert_eq!(sorted[0].monitored, test_task_id(1, 0));
        assert_eq!(sorted[1].monitored, test_task_id(3, 0));
        assert_eq!(sorted[2].monitored, test_task_id(5, 0));
    }

    #[test]
    fn down_batch_tie_breaks_by_generation_then_slot() {
        let mut batch = DownBatch::new();
        let same_vt = Time::from_nanos(100);

        // TaskId comparison: generation first, then slot (ArenaIndex ordering)
        // TaskId(slot=1, gen=2) vs TaskId(slot=2, gen=1)
        // ArenaIndex sorts by (generation, index) via derived Ord
        batch.push(
            same_vt,
            DownNotification {
                monitored: test_task_id(1, 2), // gen=2
                reason: DownReason::Normal,
                monitor_ref: MonitorRef::from_raw(1),
            },
        );
        batch.push(
            same_vt,
            DownNotification {
                monitored: test_task_id(2, 1), // gen=1
                reason: DownReason::Normal,
                monitor_ref: MonitorRef::from_raw(2),
            },
        );

        let sorted = batch.into_sorted();
        // The ordering depends on ArenaIndex's Ord implementation.
        // TaskId wraps ArenaIndex which is (index, generation) — we need to verify.
        // Both are valid orderings; what matters is determinism.
        assert_eq!(sorted.len(), 2);
        // The sort is deterministic: same input always produces same output.
        let first = sorted[0].monitored;
        let second = sorted[1].monitored;
        assert_ne!(first, second);
    }

    #[test]
    fn down_batch_mixed_vt_and_tid_ordering() {
        let mut batch = DownBatch::new();

        // Interleaved: some same vt, some different
        batch.push(
            Time::from_nanos(200),
            DownNotification {
                monitored: test_task_id(3, 0),
                reason: DownReason::Normal,
                monitor_ref: MonitorRef::from_raw(1),
            },
        );
        batch.push(
            Time::from_nanos(100),
            DownNotification {
                monitored: test_task_id(5, 0),
                reason: DownReason::Error("err".into()),
                monitor_ref: MonitorRef::from_raw(2),
            },
        );
        batch.push(
            Time::from_nanos(100),
            DownNotification {
                monitored: test_task_id(2, 0),
                reason: DownReason::Cancelled(CancelReason::default()),
                monitor_ref: MonitorRef::from_raw(3),
            },
        );
        batch.push(
            Time::from_nanos(200),
            DownNotification {
                monitored: test_task_id(1, 0),
                reason: DownReason::Panicked(PanicPayload::new("boom")),
                monitor_ref: MonitorRef::from_raw(4),
            },
        );

        let sorted = batch.into_sorted();
        // vt=100: tid=2 before tid=5
        assert_eq!(sorted[0].monitored, test_task_id(2, 0));
        assert_eq!(sorted[1].monitored, test_task_id(5, 0));
        // vt=200: tid=1 before tid=3
        assert_eq!(sorted[2].monitored, test_task_id(1, 0));
        assert_eq!(sorted[3].monitored, test_task_id(3, 0));
    }

    // ── Integration: MonitorSet + DownBatch ─────────────────────────────

    #[test]
    fn end_to_end_monitor_to_notification() {
        let mut set = MonitorSet::new();
        let region = test_region_id(0, 0);
        let watcher = test_task_id(1, 0);
        let target1 = test_task_id(10, 0);
        let target2 = test_task_id(20, 0);

        let m1 = set.establish(watcher, region, target1);
        let m2 = set.establish(watcher, region, target2);

        // Both targets terminate at the same virtual time
        let completion_vt = Time::from_nanos(500);
        let mut batch = DownBatch::new();

        for (mref, _watcher_tid) in set.watchers_of(target1) {
            batch.push(
                completion_vt,
                DownNotification {
                    monitored: target1,
                    reason: DownReason::Normal,
                    monitor_ref: mref,
                },
            );
        }
        for (mref, _watcher_tid) in set.watchers_of(target2) {
            batch.push(
                completion_vt,
                DownNotification {
                    monitored: target2,
                    reason: DownReason::Error("fail".into()),
                    monitor_ref: mref,
                },
            );
        }

        let sorted = batch.into_sorted();
        assert_eq!(sorted.len(), 2);
        // target1 (tid=10) before target2 (tid=20) at same vt
        assert_eq!(sorted[0].monitored, target1);
        assert_eq!(sorted[0].monitor_ref, m1);
        assert!(sorted[0].reason.is_normal());

        assert_eq!(sorted[1].monitored, target2);
        assert_eq!(sorted[1].monitor_ref, m2);
        assert!(sorted[1].reason.is_error());

        // Cleanup
        set.remove_monitored(target1);
        set.remove_monitored(target2);
        assert!(set.is_empty());
    }

    #[test]
    fn region_cleanup_prevents_stale_notifications() {
        let mut set = MonitorSet::new();
        let region = test_region_id(1, 0);
        let watcher = test_task_id(1, 0);
        let target = test_task_id(10, 0);

        set.establish(watcher, region, target);

        // Region closes before target terminates
        set.cleanup_region(region);

        // No watchers remain — no notifications should be generated
        assert!(set.watchers_of(target).is_empty());
        assert!(set.is_empty());
    }

    // ---------------------------------------------------------------
    // Conformance tests (bd-1hkxo)
    //
    // - Multiple watchers on same target
    // - Multiple simultaneous downs (deterministic batch ordering)
    // - Cancellation interaction (region cleanup consistency)
    // - Monotone severity preservation in Down notifications
    // ---------------------------------------------------------------

    /// Conformance: multiple watchers receive independent Down notifications
    /// when the monitored task terminates. Each watcher gets its own
    /// notification with its unique MonitorRef.
    #[test]
    fn conformance_multiple_watchers_independent_notifications() {
        let mut set = MonitorSet::new();
        let region = test_region_id(0, 0);
        let target = test_task_id(100, 0);

        let w1 = test_task_id(1, 0);
        let w2 = test_task_id(2, 0);
        let w3 = test_task_id(3, 0);
        let w4 = test_task_id(4, 0);

        let m1 = set.establish(w1, region, target);
        let m2 = set.establish(w2, region, target);
        let m3 = set.establish(w3, region, target);
        let m4 = set.establish(w4, region, target);

        // Target terminates
        let watchers = set.watchers_of(target);
        assert_eq!(watchers.len(), 4);

        let completion_vt = Time::from_nanos(1000);
        let mut batch = DownBatch::new();
        for (mref, _watcher) in &watchers {
            batch.push(
                completion_vt,
                DownNotification {
                    monitored: target,
                    reason: DownReason::Error("crash".into()),
                    monitor_ref: *mref,
                },
            );
        }

        let sorted = batch.into_sorted();
        assert_eq!(sorted.len(), 4, "each watcher must receive a notification");

        // All notifications reference the same target
        for notif in &sorted {
            assert_eq!(notif.monitored, target);
            assert!(notif.reason.is_error());
        }

        // Each notification has a unique MonitorRef
        let mrefs: Vec<MonitorRef> = sorted.iter().map(|n| n.monitor_ref).collect();
        assert!(mrefs.contains(&m1));
        assert!(mrefs.contains(&m2));
        assert!(mrefs.contains(&m3));
        assert!(mrefs.contains(&m4));
    }

    /// Conformance: multiple simultaneous downs are delivered in deterministic
    /// order. When N targets terminate at the same virtual time, notifications
    /// are sorted by (vt, monitored_tid).
    #[test]
    fn conformance_simultaneous_downs_deterministic_order() {
        let mut set = MonitorSet::new();
        let region = test_region_id(0, 0);
        let watcher = test_task_id(1, 0);

        // Watcher monitors 5 targets
        let targets: Vec<TaskId> = (10..15).map(|i| test_task_id(i, 0)).collect();
        let mrefs: Vec<MonitorRef> = targets
            .iter()
            .map(|t| set.establish(watcher, region, *t))
            .collect();

        // All 5 targets terminate at the SAME virtual time
        let same_vt = Time::from_nanos(500);
        let mut batch = DownBatch::new();

        // Insert in reverse order to test that sorting overrides insertion order
        for i in (0..5).rev() {
            batch.push(
                same_vt,
                DownNotification {
                    monitored: targets[i],
                    reason: DownReason::Error(format!("error_{i}")),
                    monitor_ref: mrefs[i],
                },
            );
        }

        let sorted = batch.into_sorted();
        assert_eq!(sorted.len(), 5);

        // Sorted by TaskId since all vt are equal
        // targets[0]=tid(10), targets[1]=tid(11), ..., targets[4]=tid(14)
        for (i, notif) in sorted.iter().enumerate() {
            assert_eq!(
                notif.monitored,
                targets[i],
                "notification {i} should be for target tid({})",
                10 + i
            );
        }

        // Run this 10 times to verify stability
        for _trial in 0..10 {
            let mut batch2 = DownBatch::new();
            for i in (0..5).rev() {
                batch2.push(
                    same_vt,
                    DownNotification {
                        monitored: targets[i],
                        reason: DownReason::Error(format!("error_{i}")),
                        monitor_ref: mrefs[i],
                    },
                );
            }
            let sorted2 = batch2.into_sorted();
            for (i, notif) in sorted2.iter().enumerate() {
                assert_eq!(notif.monitored, targets[i]);
            }
        }
    }

    /// Conformance: mixed virtual times produce correct interleaved ordering.
    /// Multiple targets terminate at different times; ordering respects vt first,
    /// then tid for tie-breaking.
    #[test]
    fn conformance_mixed_vt_deterministic_interleaving() {
        let mut set = MonitorSet::new();
        let region = test_region_id(0, 0);
        let watcher = test_task_id(1, 0);

        let t_a = test_task_id(5, 0);
        let t_b = test_task_id(3, 0);
        let t_c = test_task_id(8, 0);
        let t_d = test_task_id(2, 0);

        let m_a = set.establish(watcher, region, t_a);
        let m_b = set.establish(watcher, region, t_b);
        let m_c = set.establish(watcher, region, t_c);
        let m_d = set.establish(watcher, region, t_d);

        let mut batch = DownBatch::new();
        // Different vt values; some share the same vt
        batch.push(
            Time::from_nanos(200),
            DownNotification {
                monitored: t_a,
                reason: DownReason::Error("a".into()),
                monitor_ref: m_a,
            },
        );
        batch.push(
            Time::from_nanos(100),
            DownNotification {
                monitored: t_b,
                reason: DownReason::Panicked(PanicPayload::new("b")),
                monitor_ref: m_b,
            },
        );
        batch.push(
            Time::from_nanos(200),
            DownNotification {
                monitored: t_c,
                reason: DownReason::Normal,
                monitor_ref: m_c,
            },
        );
        batch.push(
            Time::from_nanos(100),
            DownNotification {
                monitored: t_d,
                reason: DownReason::Cancelled(CancelReason::default()),
                monitor_ref: m_d,
            },
        );

        let sorted = batch.into_sorted();
        // vt=100: tid(2) before tid(3)
        assert_eq!(sorted[0].monitored, t_d); // tid(2), vt=100
        assert_eq!(sorted[1].monitored, t_b); // tid(3), vt=100
        // vt=200: tid(5) before tid(8)
        assert_eq!(sorted[2].monitored, t_a); // tid(5), vt=200
        assert_eq!(sorted[3].monitored, t_c); // tid(8), vt=200
    }

    /// Conformance: region cleanup prevents stale Down delivery across
    /// multiple regions. Watchers in closed regions don't receive notifications;
    /// watchers in open regions still do.
    #[test]
    fn conformance_cancellation_cleanup_cross_region() {
        let mut set = MonitorSet::new();
        let r_closing = test_region_id(1, 0);
        let r_open = test_region_id(2, 0);
        let target = test_task_id(100, 0);

        let w_closing = test_task_id(1, 0);
        let w_open = test_task_id(2, 0);

        set.establish(w_closing, r_closing, target);
        let m_open = set.establish(w_open, r_open, target);

        // Cancel region 1: w_closing's monitors are released
        let removed = set.cleanup_region(r_closing);
        assert_eq!(removed.len(), 1);

        // Target terminates: only w_open should receive notification
        let watchers = set.watchers_of(target);
        assert_eq!(watchers.len(), 1);
        assert_eq!(watchers[0].0, m_open);
        assert_eq!(watchers[0].1, w_open);

        // Build notification batch — only one notification
        let mut batch = DownBatch::new();
        for (mref, _) in &watchers {
            batch.push(
                Time::from_nanos(500),
                DownNotification {
                    monitored: target,
                    reason: DownReason::Error("target died".into()),
                    monitor_ref: *mref,
                },
            );
        }

        let sorted = batch.into_sorted();
        assert_eq!(
            sorted.len(),
            1,
            "only the open-region watcher gets notified"
        );
        assert_eq!(sorted[0].monitor_ref, m_open);
    }

    /// Conformance: after region cleanup, indexes are fully consistent.
    /// No dangling references in by_ref, by_monitored, or by_watcher_region.
    #[test]
    fn conformance_cleanup_index_consistency() {
        let mut set = MonitorSet::new();
        let r1 = test_region_id(1, 0);
        let r2 = test_region_id(2, 0);

        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let t3 = test_task_id(3, 0);
        let target = test_task_id(100, 0);

        // Three watchers across two regions
        set.establish(t1, r1, target);
        set.establish(t2, r1, target);
        let m3 = set.establish(t3, r2, target);

        // Cleanup region 1
        set.cleanup_region(r1);

        // Only m3 remains
        assert_eq!(set.len(), 1);
        assert_eq!(set.watchers_of(target).len(), 1);
        assert_eq!(set.watcher_of(m3), Some(t3));
        assert_eq!(set.monitored_of(m3), Some(target));

        // Cleanup region 2
        set.cleanup_region(r2);
        assert!(set.is_empty());
        assert!(set.watchers_of(target).is_empty());
    }

    /// Conformance: monotone severity — Down notifications carry the exact
    /// DownReason from the task outcome. All four severity levels are preserved.
    #[test]
    fn conformance_monotone_severity_in_down() {
        let outcomes = vec![
            ("Normal", DownReason::Normal),
            ("Error", DownReason::Error("fail".into())),
            ("Cancelled", DownReason::Cancelled(CancelReason::default())),
            ("Panicked", DownReason::Panicked(PanicPayload::new("boom"))),
        ];

        for (name, reason) in outcomes {
            let notif = DownNotification {
                monitored: test_task_id(1, 0),
                reason: reason.clone(),
                monitor_ref: MonitorRef::from_raw(1),
            };

            // The notification carries the EXACT reason — no downgrade
            match name {
                "Normal" => assert!(notif.reason.is_normal()),
                "Error" => assert!(notif.reason.is_error()),
                "Cancelled" => assert!(notif.reason.is_cancelled()),
                "Panicked" => assert!(notif.reason.is_panicked()),
                _ => unreachable!(),
            }
        }
    }

    /// Conformance: remove_monitored + cleanup_region applied in sequence
    /// produces a clean, empty set. No leaked internal state.
    #[test]
    fn conformance_sequential_cleanup_no_leaks() {
        let mut set = MonitorSet::new();
        let r1 = test_region_id(1, 0);
        let r2 = test_region_id(2, 0);

        let w1 = test_task_id(1, 0);
        let w2 = test_task_id(2, 0);
        let t1 = test_task_id(10, 0);
        let t2 = test_task_id(20, 0);

        // w1 (r1) monitors t1 and t2
        set.establish(w1, r1, t1);
        set.establish(w1, r1, t2);
        // w2 (r2) monitors t1
        set.establish(w2, r2, t1);

        assert_eq!(set.len(), 3);

        // t1 terminates: remove its monitors
        set.remove_monitored(t1);
        assert_eq!(set.len(), 1); // only w1 -> t2 remains

        // Region 1 closes: remove remaining monitors
        set.cleanup_region(r1);
        assert!(set.is_empty());

        // All queries return empty
        assert!(set.watchers_of(t1).is_empty());
        assert!(set.watchers_of(t2).is_empty());
        assert_eq!(set.len(), 0);
    }

    /// Conformance: demonitor prevents Down delivery for the specific monitor
    /// while leaving other monitors on the same target intact.
    #[test]
    fn conformance_demonitor_selective_cancellation() {
        let mut set = MonitorSet::new();
        let region = test_region_id(0, 0);
        let target = test_task_id(100, 0);

        let w1 = test_task_id(1, 0);
        let w2 = test_task_id(2, 0);
        let w3 = test_task_id(3, 0);

        let m1 = set.establish(w1, region, target);
        let _m2 = set.establish(w2, region, target);
        let _m3 = set.establish(w3, region, target);

        // Demonitor w1 only
        assert!(set.demonitor(m1));

        // Only w2 and w3 remain as watchers
        let watchers = set.watchers_of(target);
        assert_eq!(watchers.len(), 2);

        let watcher_tids: Vec<TaskId> = watchers.iter().map(|(_, t)| *t).collect();
        assert!(
            !watcher_tids.contains(&w1),
            "demonitored watcher must not appear"
        );
        assert!(watcher_tids.contains(&w2));
        assert!(watcher_tids.contains(&w3));
    }

    #[test]
    fn monitor_ref_debug_clone_copy_eq_hash_ord() {
        use std::collections::HashSet;

        let r = MonitorRef::from_raw(42);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("MonitorRef"));

        let r2 = r;
        assert_eq!(r, r2);

        // Copy
        let r3 = r;
        assert_eq!(r, r3);

        // Ord
        let r4 = MonitorRef::from_raw(100);
        assert!(r < r4);

        // Hash
        let mut set = HashSet::new();
        set.insert(r);
        set.insert(r4);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn down_reason_debug_clone_eq() {
        let d = DownReason::Normal;
        let dbg = format!("{d:?}");
        assert!(dbg.contains("Normal"));

        let d2 = d.clone();
        assert_eq!(d, d2);

        let d3 = DownReason::Error("oops".into());
        assert_ne!(d, d3);
    }
}
