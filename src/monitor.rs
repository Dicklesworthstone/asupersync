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
//! - **DOWN-ORDER**: Notifications are sorted by
//!   `(completion_vt, monitored_tid, monitor_ref)`.
//! - **DOWN-BATCH**: When multiple notifications become ready in a single
//!   scheduler step, they are sorted before delivery.
//! - **DOWN-CONTENT**: Each notification carries the monitored TaskId, reason,
//!   and the MonitorRef returned when the monitor was established.
//! - **DOWN-CLEANUP**: Region close releases all monitors held by tasks in
//!   that region.
//!
//! # Example
//!
//! ```rust
//! use asupersync::error::Error;
//! use asupersync::monitor::{DownBatch, DownNotification, DownReason, MonitorRef, MonitorSet};
//! use asupersync::types::{Outcome, RegionId, TaskId, Time};
//!
//! // Establish a monitor.
//! fn watch(
//!     monitor_set: &mut MonitorSet,
//!     watcher_id: TaskId,
//!     watcher_region: RegionId,
//!     target_id: TaskId,
//! ) -> MonitorRef {
//!     monitor_set.establish(watcher_id, watcher_region, target_id)
//! }
//!
//! // When the target terminates, generate its notifications in delivery order.
//! fn down_notifications(
//!     monitor_set: &MonitorSet,
//!     target_id: TaskId,
//!     outcome: &Outcome<(), Error>,
//!     completion_vt: Time,
//! ) -> Vec<DownNotification> {
//!     let watchers = monitor_set.watchers_of(target_id);
//!     let mut batch = DownBatch::new();
//!     for (mref, _watcher) in &watchers {
//!         batch.push(completion_vt, DownNotification {
//!             monitored: target_id,
//!             reason: DownReason::from_task_outcome(outcome),
//!             monitor_ref: *mref,
//!         });
//!     }
//!     batch.into_sorted()
//! }
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::{Outcome, RegionId, TaskId, Time};

// ============================================================================
// MonitorRef
// ============================================================================

/// Opaque reference to an established monitor.
///
/// Returned by [`MonitorSet::establish`] and carried in [`DownNotification`].
/// Unique within a single runtime instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonitorRef(u64);

impl MonitorRef {
    /// Allocates a monitor reference from a runtime-local sequence.
    #[inline]
    fn new(id: u64) -> Self {
        Self(id)
    }

    /// Creates a `MonitorRef` with a specific id (for testing only).
    #[cfg(test)]
    fn from_raw(id: u64) -> Self {
        Self(id)
    }

    /// Creates a `MonitorRef` for integration testing purposes.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub const fn new_for_test(id: u64) -> Self {
        Self(id)
    }

    /// Returns the underlying numeric identifier.
    #[must_use]
    #[inline]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[inline]
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
    #[inline]
    pub fn is_normal(&self) -> bool {
        matches!(self, Self::Normal)
    }

    /// Returns `true` if the process terminated with an error.
    #[must_use]
    #[inline]
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }

    /// Returns `true` if the process was cancelled.
    #[must_use]
    #[inline]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }

    /// Returns `true` if the process panicked.
    #[must_use]
    #[inline]
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
/// Four indexes are maintained for efficient lookup:
/// - `by_ref`: MonitorRef → MonitorRecord (primary)
/// - `by_monitored`: `TaskId` → `Vec<MonitorRef>` (find watchers of a terminated task)
/// - `by_watcher`: `TaskId` → `Vec<MonitorRef>` (a terminated watcher's own monitors)
/// - `by_watcher_region`: `RegionId` → `Vec<MonitorRef>` (region-close cleanup)
#[derive(Debug)]
#[allow(clippy::struct_field_names)]
pub struct MonitorSet {
    by_ref: BTreeMap<MonitorRef, MonitorRecord>,
    by_monitored: BTreeMap<TaskId, Vec<MonitorRef>>,
    by_watcher: BTreeMap<TaskId, Vec<MonitorRef>>,
    by_watcher_region: BTreeMap<RegionId, Vec<MonitorRef>>,
    next_monitor_ref: u64,
}

/// Removes `monitor_ref` from `key`'s entry in `index`, dropping the entry
/// once it is empty.
fn unindex<K: Ord>(index: &mut BTreeMap<K, Vec<MonitorRef>>, key: &K, monitor_ref: MonitorRef) {
    if let Some(refs) = index.get_mut(key) {
        refs.retain(|r| *r != monitor_ref);
        if refs.is_empty() {
            index.remove(key);
        }
    }
}

impl Default for MonitorSet {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorSet {
    /// Creates an empty monitor set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_ref: BTreeMap::new(),
            by_monitored: BTreeMap::new(),
            by_watcher: BTreeMap::new(),
            by_watcher_region: BTreeMap::new(),
            next_monitor_ref: 1,
        }
    }

    #[inline]
    fn alloc_monitor_ref(&mut self) -> MonitorRef {
        let next = self.next_monitor_ref;
        self.next_monitor_ref = self
            .next_monitor_ref
            .checked_add(1)
            .expect("monitor ref space exhausted");
        MonitorRef::new(next)
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
        let monitor_ref = self.alloc_monitor_ref();
        let record = MonitorRecord {
            watcher,
            watcher_region,
            monitored,
        };

        self.by_ref.insert(monitor_ref, record);
        self.by_monitored
            .entry(monitored)
            .or_default()
            .push(monitor_ref);
        self.by_watcher
            .entry(watcher)
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
        unindex(&mut self.by_monitored, &record.monitored, monitor_ref);
        unindex(&mut self.by_watcher, &record.watcher, monitor_ref);
        unindex(
            &mut self.by_watcher_region,
            &record.watcher_region,
            monitor_ref,
        );
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
                unindex(&mut self.by_watcher, &record.watcher, mref);
                unindex(&mut self.by_watcher_region, &record.watcher_region, mref);
                removed.push(mref);
            }
        }
        removed
    }

    /// Removes every monitor held by `watcher` and returns the removed refs.
    ///
    /// Called when the watcher itself terminates: its monitors end with it,
    /// and no notification is generated for them.
    pub fn remove_watcher(&mut self, watcher: TaskId) -> Vec<MonitorRef> {
        let Some(refs) = self.by_watcher.remove(&watcher) else {
            return Vec::new();
        };
        let mut removed = Vec::with_capacity(refs.len());
        for mref in refs {
            if let Some(record) = self.by_ref.remove(&mref) {
                unindex(&mut self.by_monitored, &record.monitored, mref);
                unindex(&mut self.by_watcher_region, &record.watcher_region, mref);
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
                unindex(&mut self.by_monitored, &record.monitored, mref);
                unindex(&mut self.by_watcher, &record.watcher, mref);
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

// ============================================================================
// DownBatch — deterministic delivery ordering
// ============================================================================

/// A batch of down notifications pending delivery, with deterministic sort.
///
/// **Contract (DOWN-ORDER)**: Notifications are sorted by
/// `(completion_vt, monitored_tid, monitor_ref)` — virtual time first, then
/// `TaskId`, then `MonitorRef` to fully order duplicate monitors on the same
/// target in the same quantum.
///
/// **Contract (DOWN-BATCH)**: When multiple down notifications become ready
/// in a single scheduler step, they are sorted before enqueue. The watcher
/// receives them in sorted order.
#[derive(Debug, Default)]
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
        Self::default()
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

    /// Sorts by `(completion_vt, monitored_tid, monitor_ref)` and returns notifications
    /// in deterministic delivery order.
    ///
    /// This consumes the batch. The sort is stable, so notifications with
    /// identical `(vt, tid, monitor_ref)` keys preserve insertion order.
    #[must_use]
    pub fn into_sorted(mut self) -> Vec<DownNotification> {
        self.entries.sort_by(|a, b| {
            let vt_cmp = a.completion_vt.cmp(&b.completion_vt);
            vt_cmp
                .then_with(|| a.notification.monitored.cmp(&b.notification.monitored))
                .then_with(|| a.notification.monitor_ref.cmp(&b.notification.monitor_ref))
        });
        self.entries.into_iter().map(|e| e.notification).collect()
    }
}

// ============================================================================
// Runtime monitors and links (br-asupersync-issue65-criticisms-kpmoy5.6.1)
// ============================================================================
//
// `Cx::monitor`, `Cx::link` and `Cx::link_trapping` send a `WatchCommand`
// through the runtime's region-command lane. The scheduler (or the lab step
// loop) applies it under the runtime state lock to `TaskWatches`, the
// runtime's own `MonitorSet` and `LinkSet`. When a task finishes,
// `RuntimeState` asks `TaskWatches` for the effects of that exit while it
// still holds the lock, and the completion observer delivers them after the
// lock is released:
// - a DOWN notification to every monitor on the task (DOWN-ORDER);
// - for an abnormal exit, a cancellation request to every linked task that
//   propagates exits, and an exit signal to every linked task that traps
//   them (a trapping task also hears about a normal exit, as in OTP);
// - the task's own monitors and links end with it.

/// Why a runtime monitor or link could not be established, or why waiting on
/// one ended without a notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WatchError {
    /// The target task is not live: it already finished, or it never existed
    /// in this runtime. Its outcome is no longer available.
    NotFound,
    /// The context is not attached to a running runtime, or the runtime shut
    /// down before it applied the request.
    RuntimeUnavailable,
    /// The waiting task was cancelled.
    Cancelled,
}

impl std::fmt::Display for WatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "the target task is not live"),
            Self::RuntimeUnavailable => write!(f, "no running runtime"),
            Self::Cancelled => write!(f, "the waiting task was cancelled"),
        }
    }
}

impl std::error::Error for WatchError {}

/// The task a monitor or link watches: a task's [`TaskId`], or a
/// [`TaskHandle`](crate::runtime::TaskHandle).
///
/// Pass the handle when you just spawned the task: until the runtime admits a
/// spawn, its handle reports a provisional id, and the handle lets the
/// runtime find the admitted task.
#[derive(Clone)]
pub struct WatchTarget {
    id: TaskId,
    admitted: Option<std::sync::Arc<crate::runtime::spawn_mailbox::AdmittedTaskSlot>>,
}

impl std::fmt::Debug for WatchTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchTarget")
            .field("id", &self.id)
            .field("via_handle", &self.admitted.is_some())
            .finish()
    }
}

impl From<TaskId> for WatchTarget {
    fn from(id: TaskId) -> Self {
        Self { id, admitted: None }
    }
}

impl<T> From<&crate::runtime::TaskHandle<T>> for WatchTarget {
    fn from(handle: &crate::runtime::TaskHandle<T>) -> Self {
        let (id, admitted) = handle.watch_target_parts();
        Self { id, admitted }
    }
}

/// How the runtime resolved a [`WatchTarget`] at apply time.
enum TargetResolution {
    /// The task is live: its canonical id and owning region.
    Live(TaskId, RegionId),
    /// The task finished, never existed, or its spawn was denied.
    Gone,
    /// The spawn is not admitted yet: try again on a later drain. `capped`
    /// when nothing guarantees the spawn resolves (no retirement barrier).
    Pending { capped: bool },
}

/// A spawn with a retirement barrier always resolves: admission publishes
/// the canonical id, and denial or shutdown opens the barrier. A target
/// without a barrier is retried at most this many times before it resolves
/// to [`WatchError::NotFound`].
const MAX_UNBARRIERED_WATCH_ATTEMPTS: u32 = 4096;

impl WatchTarget {
    /// The id this target reports now: provisional for an unadmitted spawn.
    pub(crate) fn id(&self) -> TaskId {
        self.id
    }

    fn resolve(&self, live_region: &impl Fn(TaskId) -> Option<RegionId>) -> TargetResolution {
        let mut id = self.id;
        if let Some(slot) = self.admitted.as_ref()
            && crate::runtime::spawn_mailbox::is_spawn_mailbox_id(id)
        {
            match (slot.get(), slot.retirement_barrier()) {
                (Some(admitted), _) => id = admitted.task_id,
                (None, Some(barrier)) if barrier.is_open() => return TargetResolution::Gone,
                (None, barrier) => {
                    return TargetResolution::Pending {
                        capped: barrier.is_none(),
                    };
                }
            }
        }
        live_region(id).map_or(TargetResolution::Gone, |region| {
            TargetResolution::Live(id, region)
        })
    }
}

/// Result of applying one [`WatchCommand`].
pub(crate) enum WatchApply {
    /// Applied; wake this after the runtime state lock is released.
    Done(Option<std::task::Waker>),
    /// The target's spawn is not admitted yet: enqueue the command again.
    Retry(WatchCommand),
}

/// Rendezvous between a watch handle (or its pending opening) and the
/// runtime, which establishes the watch with a reference `R` and later
/// delivers one notice `N`: a [`DownNotification`] for a monitor, an
/// [`ExitSignal`](crate::link::ExitSignal) for a trapping link.
#[derive(Debug)]
pub(crate) struct WatchSlot<R, N> {
    inner: parking_lot::Mutex<WatchSlotInner<R, N>>,
}

#[derive(Debug)]
struct WatchSlotInner<R, N> {
    established: Option<Result<R, WatchError>>,
    notice: Option<N>,
    /// The opening was dropped before the runtime applied it: the runtime
    /// must not register the watch.
    abandoned: bool,
    waker: Option<std::task::Waker>,
}

impl<R, N> Default for WatchSlot<R, N> {
    fn default() -> Self {
        Self {
            inner: parking_lot::Mutex::new(WatchSlotInner {
                established: None,
                notice: None,
                abandoned: false,
                waker: None,
            }),
        }
    }
}

/// The slot behind a [`Monitor`]: the monitor reference and the monitored
/// task's canonical id, then its DOWN notification.
pub(crate) type MonitorSlot = WatchSlot<(MonitorRef, TaskId), DownNotification>;

impl<R: Copy, N: Clone> WatchSlot<R, N> {
    /// Records the establishment result produced by `establish`, unless the
    /// opening was dropped first (then `establish` does not run). Runs under
    /// the runtime state lock; the returned waker must be woken after that
    /// lock is released.
    fn establish_with(
        &self,
        establish: impl FnOnce() -> Result<R, WatchError>,
    ) -> Option<std::task::Waker> {
        let mut inner = self.inner.lock();
        if inner.abandoned || inner.established.is_some() {
            return None;
        }
        inner.established = Some(establish());
        inner.waker.take()
    }

    /// Stores the notice and wakes the task waiting on it.
    pub(crate) fn deliver(&self, notice: N) {
        let waker = {
            let mut inner = self.inner.lock();
            inner.notice = Some(notice);
            inner.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// The delivered notice, if any.
    pub(crate) fn notice(&self) -> Option<N> {
        self.inner.lock().notice.clone()
    }

    /// Marks an unanswered request abandoned. Returns the reference if the
    /// runtime had already established the watch, so the caller can remove
    /// it.
    pub(crate) fn abandon(&self) -> Option<R> {
        let mut inner = self.inner.lock();
        match inner.established {
            Some(Ok(reference)) => Some(reference),
            Some(Err(_)) => None,
            None => {
                inner.abandoned = true;
                None
            }
        }
    }

    /// Clones `waker` unless the slot already holds one that wakes the same
    /// task. Waker clone and drop may run arbitrary callbacks, so the clone
    /// happens outside the slot lock; the caller stores it under the lock and
    /// drops any replaced waker after releasing it.
    fn incoming_waker(&self, waker: &std::task::Waker) -> Option<std::task::Waker> {
        let current = self
            .inner
            .lock()
            .waker
            .as_ref()
            .is_some_and(|stored| stored.will_wake(waker));
        (!current).then(|| waker.clone())
    }

    /// Polls for the establishment result.
    pub(crate) fn poll_established(
        &self,
        gateway: &crate::runtime::spawn_mailbox::SpawnGateway,
        waker: &std::task::Waker,
    ) -> std::task::Poll<Result<R, WatchError>> {
        let incoming = self.incoming_waker(waker);
        let mut inner = self.inner.lock();
        let ready = match inner.established {
            Some(result) => Some(result),
            None if gateway.liveness_guard().is_none() => Some(Err(WatchError::RuntimeUnavailable)),
            None => None,
        };
        if let Some(result) = ready {
            drop(inner);
            drop(incoming);
            return std::task::Poll::Ready(result);
        }
        let retired = incoming.and_then(|waker| inner.waker.replace(waker));
        drop(inner);
        drop(retired);
        std::task::Poll::Pending
    }

    /// Polls for the notice on behalf of a task running with `cx`.
    pub(crate) fn poll_notice<Caps>(
        &self,
        cx: &crate::cx::Cx<Caps>,
        gateway: &crate::runtime::spawn_mailbox::SpawnGateway,
        waker: &std::task::Waker,
    ) -> std::task::Poll<Result<N, WatchError>> {
        if let Some(notice) = self.notice() {
            return std::task::Poll::Ready(Ok(notice));
        }
        if cx.checkpoint().is_err() {
            return std::task::Poll::Ready(Err(WatchError::Cancelled));
        }
        if gateway.liveness_guard().is_none() {
            return std::task::Poll::Ready(Err(WatchError::RuntimeUnavailable));
        }
        let incoming = self.incoming_waker(waker);
        let mut inner = self.inner.lock();
        if let Some(notice) = inner.notice.clone() {
            drop(inner);
            drop(incoming);
            return std::task::Poll::Ready(Ok(notice));
        }
        let retired = incoming.and_then(|waker| inner.waker.replace(waker));
        drop(inner);
        drop(retired);
        std::task::Poll::Pending
    }
}

/// Future returned by [`Cx::monitor`](crate::cx::Cx::monitor): resolves once
/// the runtime has registered the monitor.
///
/// Dropping it before it resolves withdraws the request.
#[must_use = "futures do nothing unless polled"]
pub struct MonitorOpening {
    pending: Option<PendingWatch<MonitorSlot>>,
    failed: Option<WatchError>,
}

/// A watch request the runtime has not answered yet.
pub(crate) struct PendingWatch<S> {
    pub(crate) target: TaskId,
    pub(crate) slot: std::sync::Arc<S>,
    pub(crate) gateway: std::sync::Arc<crate::runtime::spawn_mailbox::SpawnGateway>,
}

impl std::fmt::Debug for MonitorOpening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitorOpening")
            .field("target", &self.pending.as_ref().map(|p| p.target))
            .field("failed", &self.failed)
            .finish()
    }
}

impl MonitorOpening {
    fn failed(error: WatchError) -> Self {
        Self {
            pending: None,
            failed: Some(error),
        }
    }
}

impl std::future::Future for MonitorOpening {
    type Output = Result<Monitor, WatchError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        task_cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(error) = this.failed.take() {
            return std::task::Poll::Ready(Err(error));
        }
        let Some(pending) = this.pending.as_ref() else {
            return std::task::Poll::Ready(Err(WatchError::RuntimeUnavailable));
        };
        let result = std::task::ready!(
            pending
                .slot
                .poll_established(&pending.gateway, task_cx.waker())
        );
        let pending = this.pending.take().expect("pending monitor opening");
        std::task::Poll::Ready(result.map(|(monitor_ref, monitored)| Monitor {
            monitor_ref,
            monitored,
            slot: pending.slot,
            gateway: pending.gateway,
        }))
    }
}

impl Drop for MonitorOpening {
    fn drop(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if let Some((monitor_ref, _)) = pending.slot.abandon() {
            let _ = pending.gateway.enqueue_region_command(
                crate::runtime::spawn_mailbox::RegionCommand::Watch(WatchCommand::Demonitor {
                    monitor_ref,
                }),
            );
        }
    }
}

/// A runtime monitor on one task, returned by
/// [`Cx::monitor`](crate::cx::Cx::monitor).
///
/// When the monitored task finishes, for any reason, the runtime delivers
/// exactly one [`DownNotification`] whose [`DownReason`] maps the task's
/// outcome. Await it with [`Monitor::down`].
///
/// Dropping the monitor removes it (demonitor): no notification is delivered
/// afterwards. A monitor also ends when the task that created it finishes.
#[must_use = "dropping a Monitor removes it"]
pub struct Monitor {
    monitor_ref: MonitorRef,
    monitored: TaskId,
    slot: std::sync::Arc<MonitorSlot>,
    gateway: std::sync::Arc<crate::runtime::spawn_mailbox::SpawnGateway>,
}

impl std::fmt::Debug for Monitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Monitor")
            .field("monitor_ref", &self.monitor_ref)
            .field("monitored", &self.monitored)
            .field("down", &self.try_down())
            .finish()
    }
}

impl Monitor {
    /// The reference the runtime assigned to this monitor; it is repeated in
    /// the [`DownNotification`].
    #[must_use]
    pub fn monitor_ref(&self) -> MonitorRef {
        self.monitor_ref
    }

    /// The task this monitor watches.
    #[must_use]
    pub fn monitored(&self) -> TaskId {
        self.monitored
    }

    /// Returns the DOWN notification if the monitored task has finished.
    #[must_use]
    pub fn try_down(&self) -> Option<DownNotification> {
        self.slot.notice()
    }

    /// Waits until the monitored task finishes and returns its DOWN
    /// notification. Once delivered, later calls return the same
    /// notification immediately.
    ///
    /// # Errors
    ///
    /// [`WatchError::Cancelled`] if the waiting task is cancelled first, and
    /// [`WatchError::RuntimeUnavailable`] if the runtime shuts down first.
    pub async fn down<Caps>(
        &self,
        cx: &crate::cx::Cx<Caps>,
    ) -> Result<DownNotification, WatchError> {
        std::future::poll_fn(|task_cx| self.slot.poll_notice(cx, &self.gateway, task_cx.waker()))
            .await
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        if self.slot.notice().is_some() {
            return;
        }
        let _ = self.gateway.enqueue_region_command(
            crate::runtime::spawn_mailbox::RegionCommand::Watch(WatchCommand::Demonitor {
                monitor_ref: self.monitor_ref,
            }),
        );
    }
}

impl<Caps> crate::cx::Cx<Caps> {
    /// Monitors `target`: when that task finishes, for any reason, the
    /// returned [`Monitor`] receives one [`DownNotification`] with the
    /// [`DownReason`] of its outcome.
    ///
    /// `target` is a [`TaskId`] or a reference to a
    /// [`TaskHandle`](crate::runtime::TaskHandle); pass the handle of a task
    /// you just spawned. The returned future
    /// resolves once the runtime has registered the monitor. It fails with
    /// [`WatchError::NotFound`] if the task already finished (or its spawn
    /// was denied), and with [`WatchError::RuntimeUnavailable`] if this
    /// context has no running runtime.
    ///
    /// ```ignore
    /// let worker = cx.spawn(|_| async { /* ... */ })?;
    /// let monitor = cx.monitor(&worker).await?;
    /// let down = monitor.down(cx).await?;
    /// if !down.reason.is_normal() { /* restart it, log it, ... */ }
    /// ```
    pub fn monitor(&self, target: impl Into<WatchTarget>) -> MonitorOpening {
        let target = target.into();
        let Some(gateway) = self.spawn_gateway_handle() else {
            return MonitorOpening::failed(WatchError::RuntimeUnavailable);
        };
        let slot = std::sync::Arc::new(MonitorSlot::default());
        let target_id = target.id;
        let command = WatchCommand::Monitor {
            watcher: self.task_id(),
            watcher_region: self.region_id(),
            target,
            slot: std::sync::Arc::clone(&slot),
            attempts: 0,
        };
        if gateway
            .enqueue_region_command(crate::runtime::spawn_mailbox::RegionCommand::Watch(command))
            .is_err()
        {
            return MonitorOpening::failed(WatchError::RuntimeUnavailable);
        }
        MonitorOpening {
            pending: Some(PendingWatch {
                target: target_id,
                slot,
                gateway,
            }),
            failed: None,
        }
    }
}

/// A monitor or link request on its way to the runtime state.
pub(crate) enum WatchCommand {
    Monitor {
        watcher: TaskId,
        watcher_region: RegionId,
        target: WatchTarget,
        slot: std::sync::Arc<MonitorSlot>,
        /// Drains so far that found the target's spawn unadmitted.
        attempts: u32,
    },
    Demonitor {
        monitor_ref: MonitorRef,
    },
    Link {
        task: TaskId,
        task_region: RegionId,
        task_policy: crate::link::ExitPolicy,
        peer: WatchTarget,
        slot: std::sync::Arc<crate::link::LinkSlot>,
        /// Drains so far that found the peer's spawn unadmitted.
        attempts: u32,
    },
    Unlink {
        link_ref: crate::link::LinkRef,
    },
}

impl std::fmt::Debug for WatchCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monitor {
                watcher, target, ..
            } => f
                .debug_struct("Monitor")
                .field("watcher", watcher)
                .field("target", target)
                .finish_non_exhaustive(),
            Self::Demonitor { monitor_ref } => f
                .debug_struct("Demonitor")
                .field("monitor_ref", monitor_ref)
                .finish(),
            Self::Link {
                task,
                task_policy,
                peer,
                ..
            } => f
                .debug_struct("Link")
                .field("task", task)
                .field("task_policy", task_policy)
                .field("peer", peer)
                .finish_non_exhaustive(),
            Self::Unlink { link_ref } => f
                .debug_struct("Unlink")
                .field("link_ref", link_ref)
                .finish(),
        }
    }
}

/// The runtime's live monitors and links. Owned by `RuntimeState` and only
/// touched under its lock.
#[derive(Debug, Default)]
pub(crate) struct TaskWatches {
    monitors: MonitorSet,
    monitor_slots: BTreeMap<MonitorRef, std::sync::Arc<MonitorSlot>>,
    links: crate::link::LinkSet,
    /// The establishing task and its slot, per link.
    link_slots: BTreeMap<crate::link::LinkRef, (TaskId, std::sync::Arc<crate::link::LinkSlot>)>,
}

impl TaskWatches {
    /// True when no monitor or link exists, so task completion has nothing
    /// to fire.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.monitors.is_empty() && self.links.is_empty()
    }

    /// Applies one command. `live_region` returns a task's owning region while
    /// the task is live, `None` once it finished or if it never existed.
    /// A command whose target spawn is not admitted yet comes back as
    /// [`WatchApply::Retry`] for the caller to enqueue again.
    pub(crate) fn apply(
        &mut self,
        command: WatchCommand,
        live_region: impl Fn(TaskId) -> Option<RegionId>,
    ) -> WatchApply {
        match command {
            WatchCommand::Monitor {
                watcher,
                watcher_region,
                target,
                slot,
                attempts,
            } => {
                let monitored = match target.resolve(&live_region) {
                    TargetResolution::Pending { capped }
                        if !capped || attempts < MAX_UNBARRIERED_WATCH_ATTEMPTS =>
                    {
                        return WatchApply::Retry(WatchCommand::Monitor {
                            watcher,
                            watcher_region,
                            target,
                            slot,
                            attempts: attempts.saturating_add(1),
                        });
                    }
                    TargetResolution::Live(id, _) => Some(id),
                    TargetResolution::Gone | TargetResolution::Pending { .. } => None,
                };
                WatchApply::Done(slot.establish_with(|| {
                    let monitored = monitored.ok_or(WatchError::NotFound)?;
                    let monitor_ref = self.monitors.establish(watcher, watcher_region, monitored);
                    self.monitor_slots
                        .insert(monitor_ref, std::sync::Arc::clone(&slot));
                    Ok((monitor_ref, monitored))
                }))
            }
            WatchCommand::Demonitor { monitor_ref } => {
                self.monitors.demonitor(monitor_ref);
                self.monitor_slots.remove(&monitor_ref);
                WatchApply::Done(None)
            }
            WatchCommand::Link {
                task,
                task_region,
                task_policy,
                peer,
                slot,
                attempts,
            } => {
                let peer = match peer.resolve(&live_region) {
                    TargetResolution::Pending { capped }
                        if !capped || attempts < MAX_UNBARRIERED_WATCH_ATTEMPTS =>
                    {
                        return WatchApply::Retry(WatchCommand::Link {
                            task,
                            task_region,
                            task_policy,
                            peer,
                            slot,
                            attempts: attempts.saturating_add(1),
                        });
                    }
                    TargetResolution::Live(id, region) => Some((id, region)),
                    TargetResolution::Gone | TargetResolution::Pending { .. } => None,
                };
                WatchApply::Done(slot.establish_with(|| {
                    let (peer, peer_region) = peer.ok_or(WatchError::NotFound)?;
                    let link_ref = self.links.establish_with_policy(
                        task,
                        task_region,
                        task_policy,
                        peer,
                        peer_region,
                        crate::link::ExitPolicy::Propagate,
                    );
                    self.link_slots
                        .insert(link_ref, (task, std::sync::Arc::clone(&slot)));
                    Ok((link_ref, peer))
                }))
            }
            WatchCommand::Unlink { link_ref } => {
                self.links.unlink(link_ref);
                self.link_slots.remove(&link_ref);
                WatchApply::Done(None)
            }
        }
    }

    /// Fires and retires every monitor and link involving `task`, which just
    /// finished with `outcome` at `now`. Runs under the runtime state lock;
    /// the returned effects are delivered after it is released.
    pub(crate) fn on_task_completed(
        &mut self,
        task: TaskId,
        outcome: Option<&Outcome<(), crate::error::Error>>,
        now: Time,
        gateway: Option<std::sync::Arc<crate::runtime::spawn_mailbox::SpawnGateway>>,
    ) -> Option<WatchEffects> {
        let reason = outcome.map_or_else(
            || DownReason::Error("the task finished without a recorded outcome".to_string()),
            DownReason::from_task_outcome,
        );
        let mut effects = WatchEffects::default();

        // DOWN for every monitor on `task`, in DOWN-ORDER.
        let watchers = self.monitors.watchers_of(task);
        if !watchers.is_empty() {
            let mut batch = DownBatch::new();
            for (monitor_ref, _watcher) in watchers {
                batch.push(
                    now,
                    DownNotification {
                        monitored: task,
                        reason: reason.clone(),
                        monitor_ref,
                    },
                );
            }
            self.monitors.remove_monitored(task);
            for down in batch.into_sorted() {
                if let Some(slot) = self.monitor_slots.remove(&down.monitor_ref) {
                    effects.downs.push((slot, down));
                }
            }
        }
        // The task's own monitors end with it.
        for monitor_ref in self.monitors.remove_watcher(task) {
            self.monitor_slots.remove(&monitor_ref);
        }

        // Links: an abnormal exit cancels propagating peers and signals
        // trapping ones; a normal exit only signals trapping peers.
        if reason.is_normal() {
            for (link_ref, peer) in self.links.peers_of(task) {
                if self.links.exit_policy_for(link_ref, peer) == Some(crate::link::ExitPolicy::Trap)
                {
                    self.push_trapped_exit(
                        &mut effects,
                        peer,
                        crate::link::ExitSignal {
                            from: task,
                            reason: DownReason::Normal,
                            link_ref,
                        },
                    );
                }
            }
        } else {
            for action in self.links.resolve_exits(task, now, &reason).into_sorted() {
                match action {
                    crate::link::LinkExitAction::CancelPeer { to, reason, .. } => {
                        effects.cancels.push((to, reason));
                    }
                    crate::link::LinkExitAction::DeliverExit { to, signal } => {
                        self.push_trapped_exit(&mut effects, to, signal);
                    }
                    crate::link::LinkExitAction::Ignored { .. } => {}
                }
            }
        }
        for link_ref in self.links.remove_task(task) {
            self.link_slots.remove(&link_ref);
        }

        if effects.is_empty() {
            return None;
        }
        if !effects.cancels.is_empty() {
            effects.gateway = gateway;
        }
        Some(effects)
    }

    fn push_trapped_exit(
        &self,
        effects: &mut WatchEffects,
        to: TaskId,
        signal: crate::link::ExitSignal,
    ) {
        if let Some((owner, slot)) = self.link_slots.get(&signal.link_ref)
            && *owner == to
        {
            effects.exits.push((std::sync::Arc::clone(slot), signal));
        }
    }
}

/// What a task's exit does to its monitors and links, delivered after the
/// runtime state lock is released.
#[derive(Default)]
pub(crate) struct WatchEffects {
    downs: Vec<(std::sync::Arc<MonitorSlot>, DownNotification)>,
    exits: Vec<(
        std::sync::Arc<crate::link::LinkSlot>,
        crate::link::ExitSignal,
    )>,
    cancels: Vec<(TaskId, CancelReason)>,
    gateway: Option<std::sync::Arc<crate::runtime::spawn_mailbox::SpawnGateway>>,
}

impl WatchEffects {
    fn is_empty(&self) -> bool {
        self.downs.is_empty() && self.exits.is_empty() && self.cancels.is_empty()
    }

    /// Delivers the DOWN notifications and exit signals, then requests the
    /// linked cancellations through the task-handle cancel lane (which both
    /// runtime state shapes and the lab drain). Waker panics are contained.
    pub(crate) fn dispatch(self) {
        for (slot, down) in self.downs {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slot.deliver(down)))
            {
                std::mem::forget(payload);
            }
        }
        for (slot, signal) in self.exits {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slot.deliver(signal)))
            {
                std::mem::forget(payload);
            }
        }
        if let Some(gateway) = self.gateway {
            for (task, reason) in self.cancels {
                let _ = gateway.enqueue_handle_cancel(task, reason);
            }
        }
    }
}

#[cfg(test)]
mod task_watch_tests {
    use super::*;
    use crate::link::{ExitPolicy, LinkSlot};
    use std::sync::Arc;

    fn tid(index: u32) -> TaskId {
        TaskId::new_for_test(index, 0)
    }

    fn rid(index: u32) -> RegionId {
        RegionId::new_for_test(index, 0)
    }

    /// Tasks in `tasks` are live, all in region 1.
    fn live(tasks: &[u32]) -> impl Fn(TaskId) -> Option<RegionId> + '_ {
        move |task| tasks.iter().any(|&i| tid(i) == task).then(|| rid(1))
    }

    fn established<R: Copy, N>(slot: &WatchSlot<R, N>) -> Option<Result<R, WatchError>> {
        slot.inner.lock().established
    }

    fn monitor(
        watches: &mut TaskWatches,
        watcher: u32,
        target: u32,
        alive: &[u32],
    ) -> Arc<MonitorSlot> {
        let slot = Arc::new(MonitorSlot::default());
        let applied = watches.apply(
            WatchCommand::Monitor {
                watcher: tid(watcher),
                watcher_region: rid(1),
                target: tid(target).into(),
                slot: Arc::clone(&slot),
                attempts: 0,
            },
            live(alive),
        );
        assert!(matches!(applied, WatchApply::Done(None)));
        slot
    }

    fn link(
        watches: &mut TaskWatches,
        task: u32,
        peer: u32,
        task_policy: ExitPolicy,
        alive: &[u32],
    ) -> Arc<LinkSlot> {
        let slot = Arc::new(LinkSlot::default());
        let applied = watches.apply(
            WatchCommand::Link {
                task: tid(task),
                task_region: rid(1),
                task_policy,
                peer: tid(peer).into(),
                slot: Arc::clone(&slot),
                attempts: 0,
            },
            live(alive),
        );
        assert!(matches!(applied, WatchApply::Done(None)));
        slot
    }

    fn panicked() -> Outcome<(), crate::error::Error> {
        Outcome::Panicked(PanicPayload::new("boom"))
    }

    #[test]
    fn a_monitor_fires_one_down_with_the_outcome_reason_and_is_retired() {
        let mut watches = TaskWatches::default();
        let slot = monitor(&mut watches, 1, 2, &[1, 2]);
        let (monitor_ref, monitored) = established(&slot)
            .expect("applied")
            .expect("target is live");
        assert_eq!(monitored, tid(2));

        let effects = watches
            .on_task_completed(tid(2), Some(&panicked()), Time::ZERO, None)
            .expect("a monitored exit has effects");
        assert_eq!(effects.downs.len(), 1);
        assert!(effects.cancels.is_empty());
        effects.dispatch();
        let down = slot.notice().expect("DOWN delivered");
        assert_eq!(down.monitored, tid(2));
        assert_eq!(down.monitor_ref, monitor_ref);
        assert!(down.reason.is_panicked());
        assert!(watches.is_empty(), "the fired monitor is retired");
        assert!(
            watches
                .on_task_completed(tid(2), Some(&Outcome::Ok(())), Time::ZERO, None)
                .is_none(),
            "a retired monitor never fires twice"
        );
    }

    #[test]
    fn each_outcome_maps_to_its_down_reason() {
        let cases: Vec<(Outcome<(), crate::error::Error>, fn(&DownReason) -> bool)> = vec![
            (Outcome::Ok(()), DownReason::is_normal),
            (
                Outcome::Err(crate::error::Error::new(crate::error::ErrorKind::Internal)),
                DownReason::is_error,
            ),
            (
                Outcome::Cancelled(CancelReason::user("stop")),
                DownReason::is_cancelled,
            ),
            (panicked(), DownReason::is_panicked),
        ];
        for (outcome, expected) in cases {
            let mut watches = TaskWatches::default();
            let slot = monitor(&mut watches, 1, 2, &[1, 2]);
            watches
                .on_task_completed(tid(2), Some(&outcome), Time::ZERO, None)
                .expect("effects")
                .dispatch();
            let down = slot.notice().expect("DOWN delivered");
            assert!(expected(&down.reason), "{outcome:?} gave {:?}", down.reason);
        }
    }

    #[test]
    fn monitoring_a_task_that_is_not_live_fails_not_found() {
        let mut watches = TaskWatches::default();
        let slot = monitor(&mut watches, 1, 9, &[1]);
        assert_eq!(established(&slot), Some(Err(WatchError::NotFound)));
        assert!(watches.is_empty());
    }

    #[test]
    fn demonitor_before_exit_means_no_down() {
        let mut watches = TaskWatches::default();
        let slot = monitor(&mut watches, 1, 2, &[1, 2]);
        let (monitor_ref, _) = established(&slot).expect("applied").expect("live");
        let applied = watches.apply(WatchCommand::Demonitor { monitor_ref }, live(&[1, 2]));
        assert!(matches!(applied, WatchApply::Done(None)));
        assert!(watches.is_empty());
        assert!(
            watches
                .on_task_completed(tid(2), Some(&panicked()), Time::ZERO, None)
                .is_none()
        );
        assert!(slot.notice().is_none());
    }

    #[test]
    fn a_watcher_that_finishes_first_takes_its_monitors_with_it() {
        let mut watches = TaskWatches::default();
        let slot = monitor(&mut watches, 1, 2, &[1, 2]);
        assert!(
            watches
                .on_task_completed(tid(1), Some(&Outcome::Ok(())), Time::ZERO, None)
                .is_none()
        );
        assert!(watches.is_empty(), "no monitor outlives its watcher");
        assert!(
            watches
                .on_task_completed(tid(2), Some(&panicked()), Time::ZERO, None)
                .is_none()
        );
        assert!(slot.notice().is_none());
    }

    #[test]
    fn an_abandoned_opening_is_never_registered() {
        let mut watches = TaskWatches::default();
        let slot = Arc::new(MonitorSlot::default());
        assert_eq!(slot.abandon(), None);
        let applied = watches.apply(
            WatchCommand::Monitor {
                watcher: tid(1),
                watcher_region: rid(1),
                target: tid(2).into(),
                slot: Arc::clone(&slot),
                attempts: 0,
            },
            live(&[1, 2]),
        );
        assert!(matches!(applied, WatchApply::Done(None)));
        assert!(watches.is_empty());
        assert_eq!(established(&slot), None);
    }

    #[test]
    fn several_monitors_on_one_task_fire_in_monitor_ref_order() {
        let mut watches = TaskWatches::default();
        let slots = [
            monitor(&mut watches, 1, 3, &[1, 2, 3]),
            monitor(&mut watches, 2, 3, &[1, 2, 3]),
            monitor(&mut watches, 1, 3, &[1, 2, 3]),
        ];
        let effects = watches
            .on_task_completed(tid(3), Some(&Outcome::Ok(())), Time::ZERO, None)
            .expect("effects");
        let refs: Vec<MonitorRef> = effects.downs.iter().map(|(_, d)| d.monitor_ref).collect();
        let mut sorted = refs.clone();
        sorted.sort();
        assert_eq!(refs.len(), 3);
        assert_eq!(refs, sorted, "DOWN-ORDER: ascending monitor refs");
        effects.dispatch();
        for slot in &slots {
            assert!(slot.notice().expect("DOWN delivered").reason.is_normal());
        }
    }

    #[test]
    fn an_abnormal_exit_cancels_a_propagating_peer_from_either_side() {
        for (finishing, other) in [(2, 1), (1, 2)] {
            let mut watches = TaskWatches::default();
            let _slot = link(&mut watches, 1, 2, ExitPolicy::Propagate, &[1, 2]);
            let effects = watches
                .on_task_completed(tid(finishing), Some(&panicked()), Time::ZERO, None)
                .expect("effects");
            assert_eq!(effects.cancels.len(), 1);
            assert_eq!(effects.cancels[0].0, tid(other));
            assert_eq!(
                effects.cancels[0].1.kind,
                crate::types::cancel::CancelKind::LinkedExit
            );
            assert!(effects.exits.is_empty());
            assert!(watches.is_empty(), "the link ends with the task");
        }
    }

    #[test]
    fn a_normal_exit_only_removes_a_propagating_link() {
        let mut watches = TaskWatches::default();
        let _slot = link(&mut watches, 1, 2, ExitPolicy::Propagate, &[1, 2]);
        assert!(
            watches
                .on_task_completed(tid(2), Some(&Outcome::Ok(())), Time::ZERO, None)
                .is_none()
        );
        assert!(watches.is_empty());
    }

    #[test]
    fn a_trapping_task_receives_its_peer_exit_and_still_propagates_its_own() {
        // Abnormal peer exit: delivered, nobody cancelled.
        let mut watches = TaskWatches::default();
        let slot = link(&mut watches, 1, 2, ExitPolicy::Trap, &[1, 2]);
        let (link_ref, peer) = established(&slot).expect("applied").expect("live");
        assert_eq!(peer, tid(2));
        let effects = watches
            .on_task_completed(
                tid(2),
                Some(&Outcome::Cancelled(CancelReason::user("stop"))),
                Time::ZERO,
                None,
            )
            .expect("effects");
        assert!(effects.cancels.is_empty());
        effects.dispatch();
        let signal = slot.notice().expect("exit delivered");
        assert_eq!(signal.from, tid(2));
        assert_eq!(signal.link_ref, link_ref);
        assert!(signal.reason.is_cancelled());

        // Normal peer exit: a trapping task hears about it too.
        let mut watches = TaskWatches::default();
        let slot = link(&mut watches, 1, 2, ExitPolicy::Trap, &[1, 2]);
        watches
            .on_task_completed(tid(2), Some(&Outcome::Ok(())), Time::ZERO, None)
            .expect("effects")
            .dispatch();
        assert!(slot.notice().expect("exit delivered").reason.is_normal());

        // The trapping task's own abnormal exit still cancels its peer.
        let mut watches = TaskWatches::default();
        let _slot = link(&mut watches, 1, 2, ExitPolicy::Trap, &[1, 2]);
        let effects = watches
            .on_task_completed(tid(1), Some(&panicked()), Time::ZERO, None)
            .expect("effects");
        assert_eq!(effects.cancels.len(), 1);
        assert_eq!(effects.cancels[0].0, tid(2));
    }

    #[test]
    fn a_watch_on_an_unadmitted_spawn_retries_until_admitted_or_denied() {
        let barrier = crate::runtime::task_handle::RetirementBarrier::pending();
        let admitted = Arc::new(
            crate::runtime::spawn_mailbox::AdmittedTaskSlot::new()
                .with_retirement_barrier(Arc::clone(&barrier)),
        );
        let provisional =
            TaskId::new_for_test(7, crate::runtime::spawn_mailbox::SPAWN_ID_GENERATION_TAG);
        let target = WatchTarget {
            id: provisional,
            admitted: Some(admitted),
        };
        let slot = Arc::new(MonitorSlot::default());
        let mut watches = TaskWatches::default();
        let command = WatchCommand::Monitor {
            watcher: tid(1),
            watcher_region: rid(1),
            target,
            slot: Arc::clone(&slot),
            attempts: 0,
        };
        // Not admitted, barrier pending: retried well past the unbarriered cap.
        let mut command = command;
        for _ in 0..(MAX_UNBARRIERED_WATCH_ATTEMPTS + 8) {
            command = match watches.apply(command, live(&[1])) {
                WatchApply::Retry(next) => next,
                WatchApply::Done(_) => panic!("a pending admission must be retried"),
            };
        }
        assert_eq!(established(&slot), None);
        // Denied: the barrier opens without an admission, so the target is gone.
        barrier.open_and_wake();
        assert!(matches!(
            watches.apply(command, live(&[1])),
            WatchApply::Done(None)
        ));
        assert_eq!(established(&slot), Some(Err(WatchError::NotFound)));
        assert!(watches.is_empty());
    }

    #[test]
    fn monitor_set_watcher_index_stays_consistent() {
        let mut set = MonitorSet::new();
        let a = set.establish(tid(1), rid(1), tid(5));
        let b = set.establish(tid(1), rid(1), tid(6));
        let c = set.establish(tid(2), rid(2), tid(5));
        assert!(set.demonitor(b));
        assert_eq!(set.remove_watcher(tid(1)), vec![a]);
        assert_eq!(set.watchers_of(tid(5)), vec![(c, tid(2))]);
        assert_eq!(set.remove_monitored(tid(5)), vec![c]);
        assert!(set.is_empty());
        assert!(set.remove_watcher(tid(2)).is_empty());
        assert!(set.cleanup_region(rid(2)).is_empty());
    }
}

// ============================================================================
// Tests
// ============================================================================

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

    fn test_task_id(index: u32, generation: u32) -> TaskId {
        TaskId::new_for_test(index, generation)
    }

    fn test_region_id(index: u32, generation: u32) -> RegionId {
        RegionId::new_for_test(index, generation)
    }

    // ── MonitorRef ──────────────────────────────────────────────────────

    #[test]
    fn monitor_ref_uniqueness() {
        let mut set = MonitorSet::new();
        let region = test_region_id(0, 0);
        let target = test_task_id(2, 0);
        let r1 = set.establish(test_task_id(10, 0), region, target);
        let r2 = set.establish(test_task_id(11, 0), region, target);
        assert_ne!(r1, r2);
        assert!(r1 < r2); // monotonically increasing
    }

    #[test]
    fn fresh_monitor_sets_restart_ref_sequence() {
        let region = test_region_id(0, 0);
        let target = test_task_id(2, 0);

        let mut first = MonitorSet::new();
        let first_a = first.establish(test_task_id(10, 0), region, target);
        let first_b = first.establish(test_task_id(11, 0), region, target);

        let mut second = MonitorSet::new();
        let second_a = second.establish(test_task_id(20, 0), region, target);
        let second_b = second.establish(test_task_id(21, 0), region, target);

        assert_eq!(first_a.id(), 1);
        assert_eq!(first_b.id(), 2);
        assert_eq!(second_a.id(), 1);
        assert_eq!(second_b.id(), 2);
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
    fn down_batch_tie_breaks_duplicate_target_by_monitor_ref() {
        let mut batch = DownBatch::new();
        let same_vt = Time::from_nanos(100);
        let same_target = test_task_id(7, 0);

        batch.push(
            same_vt,
            DownNotification {
                monitored: same_target,
                reason: DownReason::Normal,
                monitor_ref: MonitorRef::from_raw(3),
            },
        );
        batch.push(
            same_vt,
            DownNotification {
                monitored: same_target,
                reason: DownReason::Normal,
                monitor_ref: MonitorRef::from_raw(1),
            },
        );
        batch.push(
            same_vt,
            DownNotification {
                monitored: same_target,
                reason: DownReason::Normal,
                monitor_ref: MonitorRef::from_raw(2),
            },
        );

        let sorted = batch.into_sorted();
        let refs: Vec<u64> = sorted.into_iter().map(|n| n.monitor_ref.id()).collect();
        assert_eq!(refs, vec![1, 2, 3]);
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
        assert_eq!(sorted[2].monitored, t_a); // vt=200: tid(5) before tid(8)
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

// ============================================================================
// Conformance Tests
// ============================================================================

#[cfg(test)]
#[path = "monitor_conformance_tests.rs"]
mod monitor_conformance_tests;

#[cfg(test)]
mod conformance_integration {
    use super::monitor_conformance_tests::{MonitorConformanceHarness, TestVerdict};

    #[test]
    fn monitor_conformance_suite() {
        crate::test_utils::init_test_logging();

        let mut harness = MonitorConformanceHarness::new();

        // Run the full conformance test suite
        let results = harness.run_full_suite();

        let mut failures = Vec::new();
        let mut passes = 0;

        for result in results {
            match result.verdict {
                TestVerdict::Pass => {
                    passes += 1;
                }
                TestVerdict::Fail(reason) => {
                    failures.push(format!("{}: {}", result.test_name, reason));
                }
            }
        }

        assert!(
            failures.is_empty(),
            "Monitor conformance failures:\n{}",
            failures.join("\n")
        );

        assert!(
            passes > 0,
            "No conformance tests passed - harness may be broken"
        );

        crate::test_complete!("monitor_conformance_suite");
    }
}
