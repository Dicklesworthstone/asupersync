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
    /// The task that would hold the monitor or link is not live: its spawn
    /// was denied, or it finished before the runtime applied the request.
    WatcherNotFound,
}

impl std::fmt::Display for WatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "the target task is not live"),
            Self::WatcherNotFound => write!(f, "the watching task is not live"),
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

impl TargetResolution {
    /// True when the command should wait for the spawn's admission on a
    /// later drain rather than resolve now.
    fn retry(&self, attempts: u32) -> bool {
        matches!(*self, Self::Pending { capped } if !capped || attempts < MAX_UNBARRIERED_WATCH_ATTEMPTS)
    }

    fn live(self) -> Option<(TaskId, RegionId)> {
        match self {
            Self::Live(id, region) => Some((id, region)),
            Self::Gone | Self::Pending { .. } => None,
        }
    }
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

    /// Resolves the task that will hold a monitor or link. A plain id is the
    /// requesting task itself and is taken as given, in `region`. A spawn
    /// handle (a natively spawned GenServer) resolves like a target: the
    /// request waits for the spawn's admission, and the holder must be live.
    fn resolve_holder(
        &self,
        region: RegionId,
        live_region: &impl Fn(TaskId) -> Option<RegionId>,
    ) -> TargetResolution {
        if self.admitted.is_none() {
            return TargetResolution::Live(self.id, region);
        }
        self.resolve(live_region)
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
///
/// A slot with a sink forwards the notice, with the virtual time of the exit
/// that produced it, instead of storing it for an awaiting handle: a
/// GenServer's monitors and trapped links feed its system-message lane.
pub(crate) struct WatchSlot<R, N> {
    inner: parking_lot::Mutex<WatchSlotInner<R, N>>,
    sink: Option<WatchSink<N>>,
}

/// Forwards a delivered notice and the virtual time of the exit behind it.
pub(crate) type WatchSink<N> = Box<dyn Fn(Time, N) + Send + Sync>;

impl<R: std::fmt::Debug, N: std::fmt::Debug> std::fmt::Debug for WatchSlot<R, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchSlot")
            .field("inner", &self.inner)
            .field("sink", &self.sink.is_some())
            .finish()
    }
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
            sink: None,
        }
    }
}

impl<R, N> WatchSlot<R, N> {
    /// A slot whose notice goes to `sink` instead of an awaiting handle.
    pub(crate) fn with_sink(sink: WatchSink<N>) -> Self {
        Self {
            sink: Some(sink),
            ..Self::default()
        }
    }

    /// Wakes the task waiting on this slot without settling it, so that its
    /// re-poll observes a runtime that went away
    /// (`WatchError::RuntimeUnavailable`).
    pub(crate) fn wake_waiter(&self) {
        let waker = self.inner.lock().waker.take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<R: Send, N: Send> crate::runtime::spawn_mailbox::TeardownWake for WatchSlot<R, N> {
    fn wake_for_teardown(&self) {
        self.wake_waiter();
    }
}

/// Registers `slot` to be woken when the runtime behind `gateway` is torn
/// down, for a handle awaiting it outside the runtime
/// (br-asupersync-werypv).
pub(crate) fn register_for_teardown<R: Send + 'static, N: Send + 'static>(
    gateway: &crate::runtime::spawn_mailbox::SpawnGateway,
    slot: &std::sync::Arc<WatchSlot<R, N>>,
) {
    let watch = std::sync::Arc::downgrade(slot);
    gateway.mailbox().register_teardown_wake(watch);
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

    /// Forwards the notice to the sink, or stores it and wakes the task
    /// waiting on it. `at` is the virtual time of the exit behind it.
    pub(crate) fn deliver(&self, at: Time, notice: N) {
        if let Some(sink) = self.sink.as_ref() {
            sink(at, notice);
            return;
        }
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

/// Future that sets up a monitor or link for a [`GenServer`](crate::gen_server::GenServer).
///
/// A [`GenServerHandle`](crate::gen_server::GenServerHandle) returns it for its
/// server. It resolves to the reference once the runtime has established the
/// watch, and the server then receives the notification in `handle_info` as a
/// [`SystemMsg`](crate::gen_server::SystemMsg). Dropping it before it resolves
/// withdraws the request.
#[must_use = "futures do nothing unless polled"]
pub struct ServerWatchOpening<R: Copy, N: Clone> {
    pending: Option<PendingWatch<WatchSlot<(R, TaskId), N>>>,
    failed: Option<WatchError>,
    withdraw: fn(R) -> WatchCommand,
}

/// [`ServerWatchOpening`] for a monitor.
pub type ServerMonitorOpening = ServerWatchOpening<MonitorRef, DownNotification>;

/// [`ServerWatchOpening`] for a link.
pub type ServerLinkOpening = ServerWatchOpening<crate::link::LinkRef, crate::link::ExitSignal>;

impl<R: Copy + std::fmt::Debug, N: Clone> std::fmt::Debug for ServerWatchOpening<R, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerWatchOpening")
            .field("target", &self.pending.as_ref().map(|p| p.target))
            .field("failed", &self.failed)
            .finish()
    }
}

impl<R: Copy, N: Clone> ServerWatchOpening<R, N> {
    /// Sends `command(slot)` through `gateway` and returns the future that
    /// waits for its establishment. `withdraw` turns an established
    /// reference back into the command that removes it.
    pub(crate) fn open(
        gateway: Option<std::sync::Arc<crate::runtime::spawn_mailbox::SpawnGateway>>,
        target: TaskId,
        slot: WatchSlot<(R, TaskId), N>,
        command: impl FnOnce(std::sync::Arc<WatchSlot<(R, TaskId), N>>) -> WatchCommand,
        withdraw: fn(R) -> WatchCommand,
    ) -> Self
    where
        R: Send + 'static,
        N: Send + 'static,
    {
        let failed = |error| Self {
            pending: None,
            failed: Some(error),
            withdraw,
        };
        let Some(gateway) = gateway else {
            return failed(WatchError::RuntimeUnavailable);
        };
        let slot = std::sync::Arc::new(slot);
        register_for_teardown(&gateway, &slot);
        if gateway
            .enqueue_region_command(crate::runtime::spawn_mailbox::RegionCommand::Watch(
                command(std::sync::Arc::clone(&slot)),
            ))
            .is_err()
        {
            return failed(WatchError::RuntimeUnavailable);
        }
        Self {
            pending: Some(PendingWatch {
                target,
                slot,
                gateway,
            }),
            failed: None,
            withdraw,
        }
    }
}

impl<R: Copy, N: Clone> std::future::Future for ServerWatchOpening<R, N> {
    type Output = Result<R, WatchError>;

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
        this.pending = None;
        std::task::Poll::Ready(result.map(|(reference, _)| reference))
    }
}

impl<R: Copy, N: Clone> Drop for ServerWatchOpening<R, N> {
    fn drop(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if let Some((reference, _)) = pending.slot.abandon() {
            let _ = pending.gateway.enqueue_region_command(
                crate::runtime::spawn_mailbox::RegionCommand::Watch((self.withdraw)(reference)),
            );
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
        register_for_teardown(&gateway, &slot);
        let target_id = target.id;
        let command = WatchCommand::Monitor {
            watcher: self.task_id().into(),
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
        /// The task holding the monitor; `watcher_region` is its region when
        /// it is given by id.
        watcher: WatchTarget,
        watcher_region: RegionId,
        target: WatchTarget,
        slot: std::sync::Arc<MonitorSlot>,
        /// Drains so far that found the watcher's or target's spawn
        /// unadmitted.
        attempts: u32,
    },
    Demonitor {
        monitor_ref: MonitorRef,
    },
    Link {
        /// The task holding the link; `task_region` is its region when it is
        /// given by id.
        task: WatchTarget,
        task_region: RegionId,
        task_policy: crate::link::ExitPolicy,
        peer: WatchTarget,
        slot: std::sync::Arc<crate::link::LinkSlot>,
        /// Drains so far that found the task's or peer's spawn unadmitted.
        attempts: u32,
    },
    Unlink {
        link_ref: crate::link::LinkRef,
    },
}

impl WatchCommand {
    /// The runtime is retiring this command unapplied (teardown): wake the
    /// opening waiting on it, so its re-poll reports
    /// `WatchError::RuntimeUnavailable` instead of waiting forever
    /// (br-asupersync-fbifws).
    pub(crate) fn wake_unapplied(&self) {
        match self {
            Self::Monitor { slot, .. } => slot.wake_waiter(),
            Self::Link { slot, .. } => slot.wake_waiter(),
            Self::Demonitor { .. } | Self::Unlink { .. } => {}
        }
    }
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
    /// A command whose holder's or target's spawn is not admitted yet comes
    /// back as [`WatchApply::Retry`] for the caller to enqueue again.
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
                let holder = watcher.resolve_holder(watcher_region, &live_region);
                let monitored = target.resolve(&live_region);
                if holder.retry(attempts) || monitored.retry(attempts) {
                    return WatchApply::Retry(WatchCommand::Monitor {
                        watcher,
                        watcher_region,
                        target,
                        slot,
                        attempts: attempts.saturating_add(1),
                    });
                }
                let (holder, monitored) = (holder.live(), monitored.live());
                WatchApply::Done(slot.establish_with(|| {
                    let (watcher, watcher_region) = holder.ok_or(WatchError::WatcherNotFound)?;
                    let (monitored, _) = monitored.ok_or(WatchError::NotFound)?;
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
                let holder = task.resolve_holder(task_region, &live_region);
                let resolved_peer = peer.resolve(&live_region);
                if holder.retry(attempts) || resolved_peer.retry(attempts) {
                    return WatchApply::Retry(WatchCommand::Link {
                        task,
                        task_region,
                        task_policy,
                        peer,
                        slot,
                        attempts: attempts.saturating_add(1),
                    });
                }
                let (holder, peer) = (holder.live(), resolved_peer.live());
                WatchApply::Done(slot.establish_with(|| {
                    let (task, task_region) = holder.ok_or(WatchError::WatcherNotFound)?;
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
        let mut effects = WatchEffects {
            at: now,
            ..WatchEffects::default()
        };

        // DOWN for every monitor on `task`, in DOWN-ORDER.
        let watchers = self.monitors.watchers_of(task);
        if !watchers.is_empty() {
            let mut batch = DownBatch::new();
            for &(monitor_ref, _watcher) in &watchers {
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
                let watcher = watchers
                    .iter()
                    .find(|(monitor_ref, _)| *monitor_ref == down.monitor_ref)
                    .map(|&(_, watcher)| watcher);
                if let (Some(slot), Some(watcher)) =
                    (self.monitor_slots.remove(&down.monitor_ref), watcher)
                {
                    effects.downs.push((slot, watcher, down));
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
    /// Virtual time of the exit.
    at: Time,
    /// The slot, the watcher it belongs to, and the DOWN to deliver.
    downs: Vec<(std::sync::Arc<MonitorSlot>, TaskId, DownNotification)>,
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

    /// `(watcher, monitored task, completion time)` for every DOWN this exit
    /// delivers, in delivery order. The lab replays them into its
    /// `down_order` oracle.
    pub(crate) fn down_deliveries(&self) -> impl Iterator<Item = (TaskId, TaskId, Time)> + '_ {
        self.downs
            .iter()
            .map(|(_, watcher, down)| (*watcher, down.monitored, self.at))
    }

    /// Delivers the DOWN notifications and exit signals, then requests the
    /// linked cancellations through the task-handle cancel lane (which both
    /// runtime state shapes and the lab drain). Waker panics are contained.
    pub(crate) fn dispatch(self) {
        let at = self.at;
        for (slot, _watcher, down) in self.downs {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slot.deliver(at, down)))
            {
                std::mem::forget(payload);
            }
        }
        for (slot, signal) in self.exits {
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                slot.deliver(at, signal);
            })) {
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
#[path = "monitor_task_watch_tests_inline_tests.rs"]
mod task_watch_tests;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "monitor_inline_tests.rs"]
mod tests;

// ============================================================================
// Conformance Tests
// ============================================================================

#[cfg(test)]
#[path = "monitor_conformance_tests.rs"]
mod monitor_conformance_tests;

#[cfg(test)]
#[path = "monitor_conformance_integration_inline_tests.rs"]
mod conformance_integration;
