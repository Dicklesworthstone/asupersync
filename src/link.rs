//! Process links and bidirectional exit signal propagation (Spork).
//!
//! Links provide OTP-style bidirectional failure propagation between tasks.
//! When a linked task terminates abnormally, an exit signal is sent to all
//! its link partners. Unlike monitors (which are unidirectional), links
//! connect two tasks symmetrically.
//!
//! # Link vs Monitor
//!
//! | Property     | Monitor               | Link                     |
//! |--------------|-----------------------|--------------------------|
//! | Direction    | Unidirectional        | Bidirectional            |
//! | Normal exit  | Down(Normal) sent     | Link silently removed    |
//! | Abnormal     | Down(reason) sent     | Exit signal propagated   |
//! | Trap         | Always delivered      | Configurable (trap_exit) |
//!
//! # Deterministic Ordering
//!
//! Exit signals follow contracts parallel to monitor DOWN-* contracts:
//!
//! - **EXIT-ORDER**: Exit signals sorted by `(failure_vt, source_tid)`.
//! - **EXIT-BATCH**: Multiple exit signals from a single failure are sorted
//!   before delivery.
//! - **EXIT-CLEANUP**: Region close releases all links held by tasks in
//!   that region.
//! - **EXIT-MONOTONE**: Exit signal reasons cannot downgrade severity
//!   (e.g., a Panicked reason cannot become an Error during propagation).
//!
//! # Bead
//!
//! bd-k4kmq | Parent: bd-pr46z

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::monitor::DownReason;
use crate::types::cancel::{CancelKind, CancelReason};
use crate::types::{RegionId, TaskId, Time};

// ============================================================================
// ExitPolicy — per-link exit signal handling
// ============================================================================

/// Policy controlling how exit signals are handled on one side of a link.
///
/// Each side of a bidirectional link can independently choose its exit policy.
/// The policy is local to the link — it does not affect the link partner's
/// behavior, nor does it change global task behavior.
///
/// # Bead
///
/// bd-khkw7 | Parent: bd-pr46z
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ExitPolicy {
    /// Propagate the exit signal, terminating the linked task.
    ///
    /// This is the default OTP-style behavior: when a linked process
    /// terminates abnormally, its partner is also terminated.
    #[default]
    Propagate,

    /// Trap the exit signal, converting it into a `SystemMsg::Exit` message.
    ///
    /// The receiving task stays alive and receives the exit as an info message
    /// through `handle_info`. This is analogous to OTP's
    /// `process_flag(trap_exit, true)`, but scoped to a specific link.
    Trap,

    /// Silently ignore the exit signal. No message, no termination.
    ///
    /// This is discouraged — explicit is better than silent. Use only when
    /// the receiving task genuinely does not care about its partner's fate
    /// (e.g., fire-and-forget background work).
    Ignore,
}

impl ExitPolicy {
    /// Returns `true` if this policy will propagate exit signals.
    #[must_use]
    pub fn is_propagate(self) -> bool {
        matches!(self, Self::Propagate)
    }

    /// Returns `true` if this policy will trap exit signals as messages.
    #[must_use]
    pub fn is_trap(self) -> bool {
        matches!(self, Self::Trap)
    }

    /// Returns `true` if this policy will silently ignore exit signals.
    #[must_use]
    pub fn is_ignore(self) -> bool {
        matches!(self, Self::Ignore)
    }
}

impl std::fmt::Display for ExitPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Propagate => write!(f, "propagate"),
            Self::Trap => write!(f, "trap"),
            Self::Ignore => write!(f, "ignore"),
        }
    }
}

/// Monotonic counter for generating unique [`LinkRef`] values.
static LINK_COUNTER: AtomicU64 = AtomicU64::new(1);

// ============================================================================
// LinkRef
// ============================================================================

/// Opaque reference to an established link.
///
/// Returned by [`LinkSet::establish`] and used to identify specific links
/// for unlinking. Unique across the lifetime of a runtime instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkRef(u64);

impl LinkRef {
    /// Allocates a fresh, globally unique link reference.
    fn new() -> Self {
        Self(LINK_COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Creates a `LinkRef` with a specific id (for testing only).
    #[cfg(test)]
    fn from_raw(id: u64) -> Self {
        Self(id)
    }

    /// Returns the underlying numeric identifier.
    #[must_use]
    pub fn id(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for LinkRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LinkRef({})", self.0)
    }
}

// ============================================================================
// ExitSignal
// ============================================================================

/// An exit signal delivered to a linked task when its partner terminates abnormally.
///
/// **Contract (EXIT-MONOTONE)**: The `reason` preserves the severity of the
/// original failure. It is never downgraded during propagation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitSignal {
    /// The task that terminated (source of the exit).
    pub from: TaskId,
    /// Why it terminated.
    pub reason: DownReason,
    /// The link reference that triggered this signal.
    pub link_ref: LinkRef,
}

// ============================================================================
// LinkExitAction (bd-khkw7)
// ============================================================================

/// Deterministic action derived from a linked peer's abnormal exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkExitAction {
    /// Cancel the receiver due to a linked exit.
    CancelPeer {
        /// The receiver of the cancellation.
        to: TaskId,
        /// Cancellation reason (may carry a cause chain).
        reason: CancelReason,
        /// Link identity that triggered this action.
        link_ref: LinkRef,
    },

    /// Deliver the exit as an explicit message (trap-exit).
    DeliverExit {
        /// The receiver of the exit signal.
        to: TaskId,
        /// Exit signal payload.
        signal: ExitSignal,
    },

    /// Explicitly suppressed by policy.
    Ignored {
        /// The receiver where the exit would have been delivered/cancelled.
        to: TaskId,
        /// Link identity.
        link_ref: LinkRef,
    },
}

/// Deterministic batch of link-exit actions.
///
/// Ordering is by `(exit_vt, source_tid, target_tid, link_ref_id, kind)` where
/// `kind` is a stable discriminator to make ordering deterministic when keys
/// otherwise tie.
#[derive(Debug)]
pub struct LinkExitBatch {
    entries: Vec<LinkExitBatchEntry>,
}

#[derive(Debug, Clone)]
struct LinkExitBatchEntry {
    exit_vt: Time,
    from: TaskId,
    to: TaskId,
    link_ref: LinkRef,
    action: LinkExitAction,
}

impl LinkExitBatch {
    /// Creates an empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn push(
        &mut self,
        exit_vt: Time,
        from: TaskId,
        to: TaskId,
        link_ref: LinkRef,
        action: LinkExitAction,
    ) {
        self.entries.push(LinkExitBatchEntry {
            exit_vt,
            from,
            to,
            link_ref,
            action,
        });
    }

    fn sort_in_place(&mut self) {
        self.entries.sort_by(|a, b| {
            a.exit_vt
                .cmp(&b.exit_vt)
                .then_with(|| a.from.cmp(&b.from))
                .then_with(|| a.to.cmp(&b.to))
                .then_with(|| a.link_ref.cmp(&b.link_ref))
                .then_with(|| action_kind_rank(&a.action).cmp(&action_kind_rank(&b.action)))
        });
    }

    /// Sorts the batch into deterministic delivery order.
    #[must_use]
    pub fn into_sorted(mut self) -> Vec<LinkExitAction> {
        self.sort_in_place();
        self.entries.into_iter().map(|e| e.action).collect()
    }
}

impl Default for LinkExitBatch {
    fn default() -> Self {
        Self::new()
    }
}

fn action_kind_rank(a: &LinkExitAction) -> u8 {
    match a {
        LinkExitAction::CancelPeer { .. } => 0,
        LinkExitAction::DeliverExit { .. } => 1,
        LinkExitAction::Ignored { .. } => 2,
    }
}

// ============================================================================
// LinkRecord (internal)
// ============================================================================

/// Internal record of an active link between two tasks.
#[derive(Debug, Clone)]
struct LinkRecord {
    link_ref: LinkRef,
    /// One side of the link.
    task_a: TaskId,
    /// Region owning task_a (for region-close cleanup).
    region_a: RegionId,
    /// Exit policy for task_a (controls what happens to task_a when task_b exits).
    policy_a: ExitPolicy,
    /// The other side of the link.
    task_b: TaskId,
    /// Region owning task_b (for region-close cleanup).
    region_b: RegionId,
    /// Exit policy for task_b (controls what happens to task_b when task_a exits).
    policy_b: ExitPolicy,
}

// ============================================================================
// LinkSet
// ============================================================================

/// Collection of active links with deterministic iteration order.
///
/// All internal data structures use [`BTreeMap`] to ensure no dependence on
/// `HashMap` iteration order, satisfying the **REG-NOHASH** contract.
///
/// # Indexes
///
/// Three indexes are maintained for efficient lookup:
/// - `records`: LinkRef → LinkRecord (primary storage)
/// - `task_index`: TaskId → Vec<LinkRef> (find all links involving a task)
/// - `region_index`: RegionId → Vec<LinkRef> (region-close cleanup)
///
/// Since links are bidirectional, each link appears in `task_index` for both
/// task_a and task_b, and in `region_index` for both region_a and region_b
/// (unless they share a region).
#[derive(Debug)]
pub struct LinkSet {
    records: BTreeMap<LinkRef, LinkRecord>,
    task_index: BTreeMap<TaskId, Vec<LinkRef>>,
    region_index: BTreeMap<RegionId, Vec<LinkRef>>,
}

impl LinkSet {
    /// Creates an empty link set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            task_index: BTreeMap::new(),
            region_index: BTreeMap::new(),
        }
    }

    /// Establishes a bidirectional link between two tasks with default
    /// [`ExitPolicy::Propagate`] on both sides.
    ///
    /// Returns a [`LinkRef`] that uniquely identifies this link relationship.
    /// The same pair can be linked multiple times; each call returns a distinct
    /// `LinkRef` and will produce a separate exit signal.
    pub fn establish(
        &mut self,
        task_a: TaskId,
        region_a: RegionId,
        task_b: TaskId,
        region_b: RegionId,
    ) -> LinkRef {
        self.establish_with_policy(
            task_a,
            region_a,
            ExitPolicy::Propagate,
            task_b,
            region_b,
            ExitPolicy::Propagate,
        )
    }

    /// Establishes a bidirectional link with per-side exit policies.
    ///
    /// `policy_a` controls what happens to task_a when task_b terminates
    /// abnormally (and vice versa for `policy_b`).
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Supervisor traps exits from worker, but worker propagates from supervisor
    /// links.establish_with_policy(
    ///     supervisor, r1, ExitPolicy::Trap,   // supervisor traps worker exits
    ///     worker,     r1, ExitPolicy::Propagate, // worker dies if supervisor dies
    /// );
    /// ```
    pub fn establish_with_policy(
        &mut self,
        task_a: TaskId,
        region_a: RegionId,
        policy_a: ExitPolicy,
        task_b: TaskId,
        region_b: RegionId,
        policy_b: ExitPolicy,
    ) -> LinkRef {
        let link_ref = LinkRef::new();
        let record = LinkRecord {
            link_ref,
            task_a,
            region_a,
            policy_a,
            task_b,
            region_b,
            policy_b,
        };

        self.records.insert(link_ref, record);

        // Index both sides
        self.task_index.entry(task_a).or_default().push(link_ref);
        self.task_index.entry(task_b).or_default().push(link_ref);

        // Index both regions (avoid duplicate if same region)
        self.region_index
            .entry(region_a)
            .or_default()
            .push(link_ref);
        if region_b != region_a {
            self.region_index
                .entry(region_b)
                .or_default()
                .push(link_ref);
        }

        link_ref
    }

    /// Removes a specific link. Returns `true` if it existed.
    pub fn unlink(&mut self, link_ref: LinkRef) -> bool {
        let Some(record) = self.records.remove(&link_ref) else {
            return false;
        };
        self.remove_from_task_index(record.task_a, link_ref);
        self.remove_from_task_index(record.task_b, link_ref);
        self.remove_from_region_index(record.region_a, link_ref);
        if record.region_b != record.region_a {
            self.remove_from_region_index(record.region_b, link_ref);
        }
        true
    }

    /// Returns all link partners of a task.
    ///
    /// For each link involving `task`, returns `(LinkRef, peer_TaskId)`.
    /// Used when a task terminates to generate exit signals.
    #[must_use]
    pub fn peers_of(&self, task: TaskId) -> Vec<(LinkRef, TaskId)> {
        let Some(refs) = self.task_index.get(&task) else {
            return Vec::new();
        };
        refs.iter()
            .filter_map(|lref| {
                let rec = self.records.get(lref)?;
                let peer = if rec.task_a == task {
                    rec.task_b
                } else {
                    rec.task_a
                };
                Some((*lref, peer))
            })
            .collect()
    }

    /// Removes all links involving a specific task and returns removed refs.
    ///
    /// Called after a task terminates and all exit signals have been generated.
    pub fn remove_task(&mut self, task: TaskId) -> Vec<LinkRef> {
        let Some(refs) = self.task_index.remove(&task) else {
            return Vec::new();
        };
        let mut removed = Vec::with_capacity(refs.len());
        for lref in refs {
            if let Some(record) = self.records.remove(&lref) {
                // Remove from the peer's task index
                let peer = if record.task_a == task {
                    record.task_b
                } else {
                    record.task_a
                };
                self.remove_from_task_index(peer, lref);

                // Remove from region indexes
                self.remove_from_region_index(record.region_a, lref);
                if record.region_b != record.region_a {
                    self.remove_from_region_index(record.region_b, lref);
                }
                removed.push(lref);
            }
        }
        removed
    }

    /// Removes all links held by tasks in the given region.
    ///
    /// **Contract (EXIT-CLEANUP)**: When a region closes, all links
    /// established by tasks in that region are released. No further
    /// exit signals are delivered to tasks in the region.
    pub fn cleanup_region(&mut self, region: RegionId) -> Vec<LinkRef> {
        let Some(refs) = self.region_index.remove(&region) else {
            return Vec::new();
        };
        let mut removed = Vec::with_capacity(refs.len());
        for lref in refs {
            if let Some(record) = self.records.remove(&lref) {
                // Remove from both tasks' indexes
                self.remove_from_task_index(record.task_a, lref);
                self.remove_from_task_index(record.task_b, lref);

                // Remove from the OTHER region's index (this region was already removed)
                if record.region_b != region {
                    self.remove_from_region_index(record.region_b, lref);
                }
                if record.region_a != region {
                    self.remove_from_region_index(record.region_a, lref);
                }
                removed.push(lref);
            }
        }
        removed
    }

    /// Returns the number of active links.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if there are no active links.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the peer of a task for a given link ref, if it exists.
    #[must_use]
    pub fn peer_of(&self, link_ref: LinkRef, task: TaskId) -> Option<TaskId> {
        let rec = self.records.get(&link_ref)?;
        if rec.task_a == task {
            Some(rec.task_b)
        } else if rec.task_b == task {
            Some(rec.task_a)
        } else {
            None
        }
    }

    /// Returns the exit policy for a task on the given link.
    ///
    /// The exit policy determines what happens to `task` when its link
    /// partner terminates abnormally. Returns `None` if the link or task
    /// is not found.
    #[must_use]
    pub fn exit_policy_for(&self, link_ref: LinkRef, task: TaskId) -> Option<ExitPolicy> {
        let rec = self.records.get(&link_ref)?;
        if rec.task_a == task {
            Some(rec.policy_a)
        } else if rec.task_b == task {
            Some(rec.policy_b)
        } else {
            None
        }
    }

    /// Updates the exit policy for a task on the given link.
    ///
    /// Returns `true` if the link and task were found and the policy was updated.
    pub fn set_exit_policy(&mut self, link_ref: LinkRef, task: TaskId, policy: ExitPolicy) -> bool {
        let Some(rec) = self.records.get_mut(&link_ref) else {
            return false;
        };
        if rec.task_a == task {
            rec.policy_a = policy;
            true
        } else if rec.task_b == task {
            rec.policy_b = policy;
            true
        } else {
            false
        }
    }

    /// Returns all link partners of a task with their exit policies.
    ///
    /// For each link involving `task`, returns `(LinkRef, peer_TaskId, ExitPolicy)`.
    /// The `ExitPolicy` is the policy for `task` (i.e., what happens to `task`
    /// when `peer` terminates abnormally).
    #[must_use]
    pub fn peers_with_policy(&self, task: TaskId) -> Vec<(LinkRef, TaskId, ExitPolicy)> {
        let Some(refs) = self.task_index.get(&task) else {
            return Vec::new();
        };
        refs.iter()
            .filter_map(|lref| {
                let rec = self.records.get(lref)?;
                let (peer, policy) = if rec.task_a == task {
                    (rec.task_b, rec.policy_a)
                } else {
                    (rec.task_a, rec.policy_b)
                };
                Some((*lref, peer, policy))
            })
            .collect()
    }

    /// Resolve exit signals for a crashed task into policy-aware actions.
    ///
    /// When `crashed_task` terminates abnormally at `exit_vt` with `reason`,
    /// this method inspects each link partner's [`ExitPolicy`] and produces
    /// the appropriate [`LinkExitAction`]:
    ///
    /// - [`ExitPolicy::Propagate`] → [`LinkExitAction::CancelPeer`]
    /// - [`ExitPolicy::Trap`] → [`LinkExitAction::DeliverExit`]
    /// - [`ExitPolicy::Ignore`] → [`LinkExitAction::Ignored`]
    ///
    /// The returned [`LinkExitBatch`] is sorted deterministically.
    #[must_use]
    pub fn resolve_exits(
        &self,
        crashed_task: TaskId,
        exit_vt: Time,
        reason: &DownReason,
    ) -> LinkExitBatch {
        // OTP semantics: normal completion silently removes links.
        if matches!(reason, DownReason::Normal) {
            return LinkExitBatch::new();
        }

        let mut batch = LinkExitBatch::new();
        let Some(refs) = self.task_index.get(&crashed_task) else {
            return batch;
        };
        for lref in refs {
            let Some(rec) = self.records.get(lref) else {
                continue;
            };
            let (peer, policy) = if rec.task_a == crashed_task {
                (rec.task_b, rec.policy_b)
            } else {
                (rec.task_a, rec.policy_a)
            };
            let action = match policy {
                ExitPolicy::Propagate => LinkExitAction::CancelPeer {
                    to: peer,
                    reason: linked_exit_cancel_reason(reason),
                    link_ref: *lref,
                },
                ExitPolicy::Trap => LinkExitAction::DeliverExit {
                    to: peer,
                    signal: ExitSignal {
                        from: crashed_task,
                        reason: reason.clone(),
                        link_ref: *lref,
                    },
                },
                ExitPolicy::Ignore => LinkExitAction::Ignored {
                    to: peer,
                    link_ref: *lref,
                },
            };
            batch.push(exit_vt, crashed_task, peer, *lref, action);
        }
        batch.sort_in_place();
        batch
    }

    // -- private helpers --

    fn remove_from_task_index(&mut self, task: TaskId, link_ref: LinkRef) {
        if let Some(refs) = self.task_index.get_mut(&task) {
            refs.retain(|r| *r != link_ref);
            if refs.is_empty() {
                self.task_index.remove(&task);
            }
        }
    }

    fn remove_from_region_index(&mut self, region: RegionId, link_ref: LinkRef) {
        if let Some(refs) = self.region_index.get_mut(&region) {
            refs.retain(|r| *r != link_ref);
            if refs.is_empty() {
                self.region_index.remove(&region);
            }
        }
    }
}

impl Default for LinkSet {
    fn default() -> Self {
        Self::new()
    }
}

fn linked_exit_cancel_reason(exit_reason: &DownReason) -> CancelReason {
    let base = CancelReason::new(CancelKind::LinkedExit).with_message("link exit");
    match exit_reason {
        DownReason::Cancelled(r) => base.with_cause(r.clone()),
        DownReason::Normal | DownReason::Error(_) | DownReason::Panicked(_) => base,
    }
}

// ============================================================================
// ExitBatch — deterministic delivery ordering
// ============================================================================

/// A batch of exit signals pending delivery, with deterministic sort.
///
/// **Contract (EXIT-ORDER)**: Exit signals are sorted by
/// `(failure_vt, source_tid)` — virtual time first, then the TaskId
/// of the task that caused the exit.
///
/// **Contract (EXIT-BATCH)**: When multiple exit signals become ready
/// in a single scheduler step, they are sorted before enqueue. The
/// receiver gets them in sorted order.
#[derive(Debug)]
pub struct ExitBatch {
    entries: Vec<ExitBatchEntry>,
}

/// Internal entry pairing an exit signal with its sort key.
#[derive(Debug, Clone)]
struct ExitBatchEntry {
    /// Virtual time when the source task terminated.
    failure_vt: Time,
    /// The exit signal to deliver.
    signal: ExitSignal,
}

impl ExitBatch {
    /// Creates an empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds an exit signal to the batch with its failure virtual time.
    pub fn push(&mut self, failure_vt: Time, signal: ExitSignal) {
        self.entries.push(ExitBatchEntry { failure_vt, signal });
    }

    /// Returns the number of signals in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Sorts by `(failure_vt, source_tid)` and returns exit signals
    /// in deterministic delivery order.
    ///
    /// This consumes the batch. The sort is stable, so signals with
    /// identical `(vt, tid)` keys preserve insertion order.
    #[must_use]
    pub fn into_sorted(mut self) -> Vec<ExitSignal> {
        self.entries.sort_by(|a, b| {
            let vt_cmp = a.failure_vt.cmp(&b.failure_vt);
            vt_cmp.then_with(|| a.signal.from.cmp(&b.signal.from))
        });
        self.entries.into_iter().map(|e| e.signal).collect()
    }
}

impl Default for ExitBatch {
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
    use crate::types::cancel::CancelReason;
    use crate::types::outcome::PanicPayload;

    fn test_task_id(index: u32, gen: u32) -> TaskId {
        TaskId::new_for_test(index, gen)
    }

    fn test_region_id(index: u32, gen: u32) -> RegionId {
        RegionId::new_for_test(index, gen)
    }

    // ── LinkRef ────────────────────────────────────────────────────────

    #[test]
    fn link_ref_uniqueness() {
        let r1 = LinkRef::new();
        let r2 = LinkRef::new();
        assert_ne!(r1, r2);
        assert!(r1 < r2); // monotonically increasing
    }

    #[test]
    fn link_ref_display() {
        let r = LinkRef::from_raw(42);
        assert_eq!(format!("{r}"), "LinkRef(42)");
    }

    #[test]
    fn link_ref_ordering() {
        let r1 = LinkRef::from_raw(1);
        let r2 = LinkRef::from_raw(2);
        let r3 = LinkRef::from_raw(3);
        assert!(r1 < r2);
        assert!(r2 < r3);
    }

    // ── LinkSet: establish / unlink ────────────────────────────────────

    #[test]
    fn establish_creates_link() {
        let mut set = LinkSet::new();
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        let lref = set.establish(t1, r1, t2, r1);
        assert_eq!(set.len(), 1);
        assert_eq!(set.peer_of(lref, t1), Some(t2));
        assert_eq!(set.peer_of(lref, t2), Some(t1));
    }

    #[test]
    fn establish_bidirectional_peers() {
        let mut set = LinkSet::new();
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        set.establish(t1, r1, t2, r1);

        // Both tasks can see each other as peers
        let peers_of_1 = set.peers_of(t1);
        assert_eq!(peers_of_1.len(), 1);
        assert_eq!(peers_of_1[0].1, t2);

        let peers_of_2 = set.peers_of(t2);
        assert_eq!(peers_of_2.len(), 1);
        assert_eq!(peers_of_2[0].1, t1);
    }

    #[test]
    fn establish_multiple_links_same_pair() {
        let mut set = LinkSet::new();
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        let l1 = set.establish(t1, r1, t2, r1);
        let l2 = set.establish(t1, r1, t2, r1);
        assert_ne!(l1, l2);
        assert_eq!(set.len(), 2);
        assert_eq!(set.peers_of(t1).len(), 2);
    }

    #[test]
    fn establish_cross_region() {
        let mut set = LinkSet::new();
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let r1 = test_region_id(1, 0);
        let r2 = test_region_id(2, 0);

        let lref = set.establish(t1, r1, t2, r2);
        assert_eq!(set.len(), 1);
        assert_eq!(set.peer_of(lref, t1), Some(t2));
    }

    #[test]
    fn unlink_removes_link() {
        let mut set = LinkSet::new();
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        let lref = set.establish(t1, r1, t2, r1);
        assert!(set.unlink(lref));
        assert_eq!(set.len(), 0);
        assert!(set.peers_of(t1).is_empty());
        assert!(set.peers_of(t2).is_empty());
    }

    #[test]
    fn unlink_nonexistent_returns_false() {
        let mut set = LinkSet::new();
        assert!(!set.unlink(LinkRef::from_raw(999)));
    }

    #[test]
    fn unlink_only_removes_specific_link() {
        let mut set = LinkSet::new();
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let t3 = test_task_id(3, 0);
        let r1 = test_region_id(0, 0);

        let l1 = set.establish(t1, r1, t2, r1);
        let _l2 = set.establish(t1, r1, t3, r1);

        set.unlink(l1);
        assert_eq!(set.len(), 1);
        assert_eq!(set.peers_of(t1).len(), 1);
        assert_eq!(set.peers_of(t1)[0].1, t3);
    }

    // ── LinkSet: resolve_exits (bd-khkw7) ──────────────────────────────

    #[test]
    fn resolve_exits_normal_is_silent() {
        let mut set = LinkSet::new();
        let a = test_task_id(1, 0);
        let b = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        set.establish(a, r1, b, r1);

        let batch = set.resolve_exits(a, Time::from_secs(1), &DownReason::Normal);
        assert!(batch.into_sorted().is_empty());
    }

    #[test]
    fn resolve_exits_propagate_cancels_peer_with_linked_exit_kind() {
        let mut set = LinkSet::new();
        let a = test_task_id(1, 0);
        let b = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        let lref =
            set.establish_with_policy(a, r1, ExitPolicy::Propagate, b, r1, ExitPolicy::Propagate);
        let actions = set
            .resolve_exits(
                a,
                Time::from_secs(1),
                &DownReason::Error("boom".to_string()),
            )
            .into_sorted();

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            LinkExitAction::CancelPeer {
                to,
                reason,
                link_ref,
            } => {
                assert_eq!(*to, b);
                assert_eq!(reason.kind, CancelKind::LinkedExit);
                assert_eq!(reason.message, Some("link exit"));
                assert_eq!(*link_ref, lref);
            }
            other => panic!("expected CancelPeer, got {other:?}"),
        }
    }

    #[test]
    fn resolve_exits_trap_delivers_exit_message() {
        let mut set = LinkSet::new();
        let a = test_task_id(1, 0);
        let b = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        let lref = set.establish_with_policy(a, r1, ExitPolicy::Propagate, b, r1, ExitPolicy::Trap);
        let actions = set
            .resolve_exits(
                a,
                Time::from_secs(1),
                &DownReason::Panicked(PanicPayload::new("kaput")),
            )
            .into_sorted();

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            LinkExitAction::DeliverExit { to, signal } => {
                assert_eq!(*to, b);
                assert_eq!(signal.from, a);
                assert_eq!(signal.link_ref, lref);
                assert!(matches!(signal.reason, DownReason::Panicked(_)));
            }
            other => panic!("expected DeliverExit, got {other:?}"),
        }
    }

    #[test]
    fn resolve_exits_ignore_suppresses_exit() {
        let mut set = LinkSet::new();
        let a = test_task_id(1, 0);
        let b = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        let lref =
            set.establish_with_policy(a, r1, ExitPolicy::Propagate, b, r1, ExitPolicy::Ignore);
        let actions = set
            .resolve_exits(
                a,
                Time::from_secs(1),
                &DownReason::Error("boom".to_string()),
            )
            .into_sorted();

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            LinkExitAction::Ignored { to, link_ref } => {
                assert_eq!(*to, b);
                assert_eq!(*link_ref, lref);
            }
            other => panic!("expected Ignored, got {other:?}"),
        }
    }

    #[test]
    fn resolve_exits_cancellation_attaches_cause_chain() {
        let mut set = LinkSet::new();
        let a = test_task_id(1, 0);
        let b = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        set.establish_with_policy(a, r1, ExitPolicy::Propagate, b, r1, ExitPolicy::Propagate);

        let source_cancel = CancelReason::timeout();
        let actions = set
            .resolve_exits(
                a,
                Time::from_secs(1),
                &DownReason::Cancelled(source_cancel.clone()),
            )
            .into_sorted();

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            LinkExitAction::CancelPeer { to, reason, .. } => {
                assert_eq!(*to, b);
                assert_eq!(reason.kind, CancelKind::LinkedExit);
                assert!(reason.cause.is_some());
                assert_eq!(reason.cause.as_deref(), Some(&source_cancel));
            }
            other => panic!("expected CancelPeer, got {other:?}"),
        }
    }

    #[test]
    fn resolve_exits_ordering_is_deterministic() {
        let mut set = LinkSet::new();
        let a = test_task_id(1, 0);
        let b = test_task_id(4, 0);
        let c = test_task_id(3, 0);
        let r1 = test_region_id(0, 0);

        // Establish in reverse target order (b first, then c).
        set.establish_with_policy(a, r1, ExitPolicy::Propagate, b, r1, ExitPolicy::Trap);
        set.establish_with_policy(a, r1, ExitPolicy::Propagate, c, r1, ExitPolicy::Propagate);

        let actions = set
            .resolve_exits(
                a,
                Time::from_secs(1),
                &DownReason::Error("boom".to_string()),
            )
            .into_sorted();

        assert_eq!(actions.len(), 2);

        // Sorted by target TaskId (c=3) before (b=4), regardless of insertion order.
        let to0 = match &actions[0] {
            LinkExitAction::CancelPeer { to, .. } => *to,
            LinkExitAction::DeliverExit { to, .. } => *to,
            LinkExitAction::Ignored { to, .. } => *to,
        };
        let to1 = match &actions[1] {
            LinkExitAction::CancelPeer { to, .. } => *to,
            LinkExitAction::DeliverExit { to, .. } => *to,
            LinkExitAction::Ignored { to, .. } => *to,
        };
        assert_eq!(to0, c);
        assert_eq!(to1, b);
    }

    // ── LinkSet: peers_of ──────────────────────────────────────────────

    #[test]
    fn peers_of_empty() {
        let set = LinkSet::new();
        assert!(set.peers_of(test_task_id(99, 0)).is_empty());
    }

    #[test]
    fn peers_of_returns_all_linked_tasks() {
        let mut set = LinkSet::new();
        let hub = test_task_id(1, 0);
        let r1 = test_region_id(0, 0);

        let t2 = test_task_id(2, 0);
        let t3 = test_task_id(3, 0);
        let t4 = test_task_id(4, 0);

        set.establish(hub, r1, t2, r1);
        set.establish(hub, r1, t3, r1);
        set.establish(hub, r1, t4, r1);

        let peers = set.peers_of(hub);
        assert_eq!(peers.len(), 3);

        let peer_tids: Vec<TaskId> = peers.iter().map(|(_, t)| *t).collect();
        assert!(peer_tids.contains(&t2));
        assert!(peer_tids.contains(&t3));
        assert!(peer_tids.contains(&t4));
    }

    // ── LinkSet: remove_task ───────────────────────────────────────────

    #[test]
    fn remove_task_clears_all_links() {
        let mut set = LinkSet::new();
        let r1 = test_region_id(0, 0);
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let t3 = test_task_id(3, 0);

        set.establish(t1, r1, t2, r1);
        set.establish(t1, r1, t3, r1);

        let removed = set.remove_task(t1);
        assert_eq!(removed.len(), 2);
        assert!(set.is_empty());
        assert!(set.peers_of(t1).is_empty());
        assert!(set.peers_of(t2).is_empty());
        assert!(set.peers_of(t3).is_empty());
    }

    #[test]
    fn remove_task_preserves_unrelated_links() {
        let mut set = LinkSet::new();
        let r1 = test_region_id(0, 0);
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let t3 = test_task_id(3, 0);
        let t4 = test_task_id(4, 0);

        set.establish(t1, r1, t2, r1);
        set.establish(t3, r1, t4, r1); // unrelated to t1

        set.remove_task(t1);
        assert_eq!(set.len(), 1);
        assert_eq!(set.peers_of(t3).len(), 1);
        assert_eq!(set.peers_of(t3)[0].1, t4);
    }

    // ── LinkSet: cleanup_region (EXIT-CLEANUP) ────────────────────────

    #[test]
    fn cleanup_region_removes_all_links_in_region() {
        let mut set = LinkSet::new();
        let r1 = test_region_id(1, 0);
        let r2 = test_region_id(2, 0);
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let t3 = test_task_id(3, 0);

        // t1 (region 1) linked to t2 (region 1)
        set.establish(t1, r1, t2, r1);
        // t1 (region 1) linked to t3 (region 2)
        set.establish(t1, r1, t3, r2);

        let removed = set.cleanup_region(r1);
        assert_eq!(removed.len(), 2);
        assert!(set.is_empty());
    }

    #[test]
    fn cleanup_region_preserves_unrelated_regions() {
        let mut set = LinkSet::new();
        let r1 = test_region_id(1, 0);
        let r2 = test_region_id(2, 0);
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let t3 = test_task_id(3, 0);
        let t4 = test_task_id(4, 0);

        // Region 1 link
        set.establish(t1, r1, t2, r1);
        // Region 2 link (should survive)
        set.establish(t3, r2, t4, r2);

        set.cleanup_region(r1);
        assert_eq!(set.len(), 1);
        assert_eq!(set.peers_of(t3).len(), 1);
    }

    #[test]
    fn cleanup_region_empty_is_noop() {
        let mut set = LinkSet::new();
        let removed = set.cleanup_region(test_region_id(99, 0));
        assert!(removed.is_empty());
    }

    #[test]
    fn cleanup_region_cleans_task_index() {
        let mut set = LinkSet::new();
        let r1 = test_region_id(1, 0);
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);

        set.establish(t1, r1, t2, r1);
        set.cleanup_region(r1);

        assert!(set.peers_of(t1).is_empty());
        assert!(set.peers_of(t2).is_empty());
    }

    // ── ExitBatch: deterministic ordering (EXIT-ORDER + EXIT-BATCH) ───

    #[test]
    fn exit_batch_empty() {
        let batch = ExitBatch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
        assert!(batch.into_sorted().is_empty());
    }

    #[test]
    fn exit_batch_single_item() {
        let mut batch = ExitBatch::new();
        let signal = ExitSignal {
            from: test_task_id(1, 0),
            reason: DownReason::Error("oops".into()),
            link_ref: LinkRef::from_raw(1),
        };
        batch.push(Time::from_nanos(100), signal);
        assert_eq!(batch.len(), 1);

        let sorted = batch.into_sorted();
        assert_eq!(sorted.len(), 1);
        assert_eq!(sorted[0].from, test_task_id(1, 0));
    }

    #[test]
    fn exit_batch_sorts_by_virtual_time() {
        let mut batch = ExitBatch::new();

        // Insert in reverse vt order
        batch.push(
            Time::from_nanos(300),
            ExitSignal {
                from: test_task_id(1, 0),
                reason: DownReason::Error("a".into()),
                link_ref: LinkRef::from_raw(1),
            },
        );
        batch.push(
            Time::from_nanos(100),
            ExitSignal {
                from: test_task_id(2, 0),
                reason: DownReason::Error("b".into()),
                link_ref: LinkRef::from_raw(2),
            },
        );
        batch.push(
            Time::from_nanos(200),
            ExitSignal {
                from: test_task_id(3, 0),
                reason: DownReason::Error("c".into()),
                link_ref: LinkRef::from_raw(3),
            },
        );

        let sorted = batch.into_sorted();
        assert_eq!(sorted[0].from, test_task_id(2, 0)); // vt=100
        assert_eq!(sorted[1].from, test_task_id(3, 0)); // vt=200
        assert_eq!(sorted[2].from, test_task_id(1, 0)); // vt=300
    }

    #[test]
    fn exit_batch_tie_breaks_by_task_id() {
        let mut batch = ExitBatch::new();
        let same_vt = Time::from_nanos(100);

        batch.push(
            same_vt,
            ExitSignal {
                from: test_task_id(5, 0),
                reason: DownReason::Error("x".into()),
                link_ref: LinkRef::from_raw(1),
            },
        );
        batch.push(
            same_vt,
            ExitSignal {
                from: test_task_id(1, 0),
                reason: DownReason::Error("y".into()),
                link_ref: LinkRef::from_raw(2),
            },
        );
        batch.push(
            same_vt,
            ExitSignal {
                from: test_task_id(3, 0),
                reason: DownReason::Error("z".into()),
                link_ref: LinkRef::from_raw(3),
            },
        );

        let sorted = batch.into_sorted();
        assert_eq!(sorted[0].from, test_task_id(1, 0));
        assert_eq!(sorted[1].from, test_task_id(3, 0));
        assert_eq!(sorted[2].from, test_task_id(5, 0));
    }

    // ── Conformance tests (bd-k4kmq) ──────────────────────────────────

    /// Conformance: links are bidirectional. When task A terminates, task B
    /// appears as a peer, and vice versa.
    #[test]
    fn conformance_link_bidirectional_symmetry() {
        let mut set = LinkSet::new();
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        let lref = set.establish(t1, r1, t2, r1);

        // From t1's perspective: t2 is the peer
        assert_eq!(set.peer_of(lref, t1), Some(t2));
        // From t2's perspective: t1 is the peer
        assert_eq!(set.peer_of(lref, t2), Some(t1));
        // From an unrelated task: no peer
        assert_eq!(set.peer_of(lref, test_task_id(99, 0)), None);
    }

    /// Conformance: normal exit removes links silently. Only abnormal exits
    /// should generate exit signals. This test verifies the removal path.
    #[test]
    fn conformance_normal_exit_removes_link_silently() {
        let mut set = LinkSet::new();
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        set.establish(t1, r1, t2, r1);

        // Task t1 exits normally: remove its links, generate no exit signals
        let peers = set.peers_of(t1);
        let mut batch = ExitBatch::new();
        let reason = DownReason::Normal;

        // Normal exit: do NOT push signals (contract: normal exit = silent unlink)
        if !reason.is_normal() {
            for (lref, _peer) in &peers {
                batch.push(
                    Time::ZERO,
                    ExitSignal {
                        from: t1,
                        reason: reason.clone(),
                        link_ref: *lref,
                    },
                );
            }
        }

        assert!(batch.is_empty(), "normal exit must produce no exit signals");

        // Clean up the link
        set.remove_task(t1);
        assert!(set.peers_of(t2).is_empty());
    }

    /// Conformance: abnormal exit generates exit signals to all peers.
    #[test]
    fn conformance_abnormal_exit_propagates_to_all_peers() {
        let mut set = LinkSet::new();
        let r1 = test_region_id(0, 0);
        let t_crash = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let t3 = test_task_id(3, 0);
        let t4 = test_task_id(4, 0);

        set.establish(t_crash, r1, t2, r1);
        set.establish(t_crash, r1, t3, r1);
        set.establish(t_crash, r1, t4, r1);

        // Task t_crash errors out
        let peers = set.peers_of(t_crash);
        let reason = DownReason::Error("crash".into());
        let mut batch = ExitBatch::new();
        let failure_vt = Time::from_nanos(500);

        for (lref, _peer) in &peers {
            batch.push(
                failure_vt,
                ExitSignal {
                    from: t_crash,
                    reason: reason.clone(),
                    link_ref: *lref,
                },
            );
        }

        assert_eq!(batch.len(), 3, "must generate exit signal for each peer");

        let sorted = batch.into_sorted();
        // All signals have the same vt and same source tid — insertion order preserved
        assert_eq!(sorted.len(), 3);
        for sig in &sorted {
            assert_eq!(sig.from, t_crash);
            assert!(sig.reason.is_error());
        }
    }

    /// Conformance: monotone severity — panic propagation cannot be downgraded.
    /// Exit signals carry the original severity verbatim.
    #[test]
    fn conformance_exit_monotone_severity() {
        let reasons = vec![
            ("Error", DownReason::Error("fail".into())),
            ("Cancelled", DownReason::Cancelled(CancelReason::default())),
            ("Panicked", DownReason::Panicked(PanicPayload::new("boom"))),
        ];

        for (name, reason) in reasons {
            let signal = ExitSignal {
                from: test_task_id(1, 0),
                reason: reason.clone(),
                link_ref: LinkRef::from_raw(1),
            };

            // The signal carries the EXACT reason — no downgrade
            match name {
                "Error" => assert!(signal.reason.is_error(), "Error must propagate as Error"),
                "Cancelled" => assert!(
                    signal.reason.is_cancelled(),
                    "Cancelled must propagate as Cancelled"
                ),
                "Panicked" => assert!(
                    signal.reason.is_panicked(),
                    "Panicked must propagate as Panicked"
                ),
                _ => unreachable!(),
            }
        }
    }

    /// Conformance: deterministic delivery order is stable across runs.
    /// Same input → same output, regardless of trial number.
    #[test]
    fn conformance_exit_delivery_order_stable() {
        for _trial in 0..10 {
            let mut batch = ExitBatch::new();

            // Interleaved vt and tid values
            batch.push(
                Time::from_nanos(200),
                ExitSignal {
                    from: test_task_id(3, 0),
                    reason: DownReason::Error("a".into()),
                    link_ref: LinkRef::from_raw(1),
                },
            );
            batch.push(
                Time::from_nanos(100),
                ExitSignal {
                    from: test_task_id(5, 0),
                    reason: DownReason::Error("b".into()),
                    link_ref: LinkRef::from_raw(2),
                },
            );
            batch.push(
                Time::from_nanos(100),
                ExitSignal {
                    from: test_task_id(2, 0),
                    reason: DownReason::Error("c".into()),
                    link_ref: LinkRef::from_raw(3),
                },
            );

            let sorted = batch.into_sorted();
            // vt=100: tid=2 before tid=5
            assert_eq!(sorted[0].from, test_task_id(2, 0));
            assert_eq!(sorted[1].from, test_task_id(5, 0));
            // vt=200: tid=3
            assert_eq!(sorted[2].from, test_task_id(3, 0));
        }
    }

    /// Conformance: region cleanup prevents stale exit delivery.
    /// After a region closes, no exit signals are generated for tasks in it.
    #[test]
    fn conformance_region_cleanup_prevents_stale_exit() {
        let mut set = LinkSet::new();
        let r1 = test_region_id(1, 0);
        let r2 = test_region_id(2, 0);
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);

        set.establish(t1, r1, t2, r2);

        // Region 1 closes before t2 terminates
        set.cleanup_region(r1);

        // t2 terminates: no peers remaining
        assert!(
            set.peers_of(t2).is_empty(),
            "after region cleanup, no exit signals should target closed region"
        );
    }

    /// Conformance: cross-region link cleanup isolates regions.
    #[test]
    fn conformance_cross_region_link_isolation() {
        let mut set = LinkSet::new();
        let r1 = test_region_id(1, 0);
        let r2 = test_region_id(2, 0);
        let r3 = test_region_id(3, 0);

        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let t3 = test_task_id(3, 0);
        let t4 = test_task_id(4, 0);

        // Cross-region links
        set.establish(t1, r1, t2, r2);
        set.establish(t3, r2, t4, r3);

        // Cleanup region 1: only t1-t2 link removed
        set.cleanup_region(r1);
        assert_eq!(set.len(), 1);
        assert!(set.peers_of(t1).is_empty());
        // t3-t4 link survives
        assert_eq!(set.peers_of(t3).len(), 1);
        assert_eq!(set.peers_of(t3)[0].1, t4);
    }

    /// Conformance: end-to-end link lifecycle — establish, failure, signal, cleanup.
    #[test]
    fn conformance_end_to_end_link_lifecycle() {
        let mut set = LinkSet::new();
        let r1 = test_region_id(0, 0);
        let server = test_task_id(1, 0);
        let worker1 = test_task_id(10, 0);
        let worker2 = test_task_id(20, 0);

        // Server links to two workers
        let _l1 = set.establish(server, r1, worker1, r1);
        let _l2 = set.establish(server, r1, worker2, r1);

        assert_eq!(set.len(), 2);
        assert_eq!(set.peers_of(server).len(), 2);

        // Worker1 crashes
        let peers = set.peers_of(worker1);
        assert_eq!(peers.len(), 1); // only server
        assert_eq!(peers[0].1, server);

        let failure_vt = Time::from_nanos(1000);
        let mut batch = ExitBatch::new();
        for (lref, _peer) in &peers {
            batch.push(
                failure_vt,
                ExitSignal {
                    from: worker1,
                    reason: DownReason::Error("worker1 crashed".into()),
                    link_ref: *lref,
                },
            );
        }

        let signals = batch.into_sorted();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].from, worker1);
        assert!(signals[0].reason.is_error());

        // Remove worker1's links
        set.remove_task(worker1);
        assert_eq!(set.len(), 1); // only server-worker2 remains
        assert_eq!(set.peers_of(server).len(), 1);
        assert_eq!(set.peers_of(server)[0].1, worker2);

        // Cleanup everything
        set.remove_task(server);
        assert!(set.is_empty());
    }

    // ── ExitPolicy (bd-khkw7) ────────────────────────────────────────

    #[test]
    fn exit_policy_default_is_propagate() {
        assert_eq!(ExitPolicy::default(), ExitPolicy::Propagate);
    }

    #[test]
    fn exit_policy_predicates() {
        assert!(ExitPolicy::Propagate.is_propagate());
        assert!(!ExitPolicy::Propagate.is_trap());
        assert!(!ExitPolicy::Propagate.is_ignore());

        assert!(!ExitPolicy::Trap.is_propagate());
        assert!(ExitPolicy::Trap.is_trap());
        assert!(!ExitPolicy::Trap.is_ignore());

        assert!(!ExitPolicy::Ignore.is_propagate());
        assert!(!ExitPolicy::Ignore.is_trap());
        assert!(ExitPolicy::Ignore.is_ignore());
    }

    #[test]
    fn exit_policy_display() {
        assert_eq!(format!("{}", ExitPolicy::Propagate), "propagate");
        assert_eq!(format!("{}", ExitPolicy::Trap), "trap");
        assert_eq!(format!("{}", ExitPolicy::Ignore), "ignore");
    }

    #[test]
    fn establish_defaults_to_propagate_policy() {
        let mut set = LinkSet::new();
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        let lref = set.establish(t1, r1, t2, r1);
        assert_eq!(set.exit_policy_for(lref, t1), Some(ExitPolicy::Propagate));
        assert_eq!(set.exit_policy_for(lref, t2), Some(ExitPolicy::Propagate));
    }

    #[test]
    fn establish_with_asymmetric_policy() {
        let mut set = LinkSet::new();
        let supervisor = test_task_id(1, 0);
        let worker = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        // Supervisor traps exits; worker propagates
        let lref = set.establish_with_policy(
            supervisor,
            r1,
            ExitPolicy::Trap,
            worker,
            r1,
            ExitPolicy::Propagate,
        );

        assert_eq!(
            set.exit_policy_for(lref, supervisor),
            Some(ExitPolicy::Trap)
        );
        assert_eq!(
            set.exit_policy_for(lref, worker),
            Some(ExitPolicy::Propagate)
        );
    }

    #[test]
    fn exit_policy_for_unknown_task_returns_none() {
        let mut set = LinkSet::new();
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        let lref = set.establish(t1, r1, t2, r1);
        assert_eq!(set.exit_policy_for(lref, test_task_id(99, 0)), None);
    }

    #[test]
    fn exit_policy_for_unknown_link_returns_none() {
        let set = LinkSet::new();
        assert_eq!(
            set.exit_policy_for(LinkRef::from_raw(999), test_task_id(1, 0)),
            None
        );
    }

    #[test]
    fn set_exit_policy_updates_policy() {
        let mut set = LinkSet::new();
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);
        let r1 = test_region_id(0, 0);

        let lref = set.establish(t1, r1, t2, r1);

        // Change t1 from Propagate to Trap
        assert!(set.set_exit_policy(lref, t1, ExitPolicy::Trap));
        assert_eq!(set.exit_policy_for(lref, t1), Some(ExitPolicy::Trap));
        // t2 unchanged
        assert_eq!(set.exit_policy_for(lref, t2), Some(ExitPolicy::Propagate));
    }

    #[test]
    fn set_exit_policy_unknown_link_returns_false() {
        let mut set = LinkSet::new();
        assert!(!set.set_exit_policy(LinkRef::from_raw(999), test_task_id(1, 0), ExitPolicy::Trap));
    }

    #[test]
    fn peers_with_policy_returns_correct_policies() {
        let mut set = LinkSet::new();
        let supervisor = test_task_id(1, 0);
        let worker_a = test_task_id(2, 0);
        let worker_b = test_task_id(3, 0);
        let r1 = test_region_id(0, 0);

        // Supervisor traps exits from both workers
        set.establish_with_policy(
            supervisor,
            r1,
            ExitPolicy::Trap,
            worker_a,
            r1,
            ExitPolicy::Propagate,
        );
        set.establish_with_policy(
            supervisor,
            r1,
            ExitPolicy::Trap,
            worker_b,
            r1,
            ExitPolicy::Propagate,
        );

        // From supervisor's perspective: both links have Trap policy
        let peers = set.peers_with_policy(supervisor);
        assert_eq!(peers.len(), 2);
        for (_lref, _peer, policy) in &peers {
            assert_eq!(*policy, ExitPolicy::Trap);
        }

        // From worker_a's perspective: Propagate policy
        let peers_a = set.peers_with_policy(worker_a);
        assert_eq!(peers_a.len(), 1);
        assert_eq!(peers_a[0].2, ExitPolicy::Propagate);
    }

    #[test]
    fn peers_with_policy_empty_for_unknown_task() {
        let set = LinkSet::new();
        assert!(set.peers_with_policy(test_task_id(99, 0)).is_empty());
    }

    /// Conformance: trap-exit policy survives through link lifecycle until
    /// unlink or cleanup.
    #[test]
    fn conformance_trap_exit_policy_lifecycle() {
        let mut set = LinkSet::new();
        let r1 = test_region_id(0, 0);
        let server = test_task_id(1, 0);
        let worker = test_task_id(2, 0);

        // Establish with Trap on server side
        let lref = set.establish_with_policy(
            server,
            r1,
            ExitPolicy::Trap,
            worker,
            r1,
            ExitPolicy::Propagate,
        );

        // Worker crashes: server should trap, not propagate
        let peers_of_worker = set.peers_with_policy(worker);
        assert_eq!(peers_of_worker.len(), 1);
        // This is worker's policy (what happens to worker when server dies) = Propagate
        assert_eq!(peers_of_worker[0].2, ExitPolicy::Propagate);

        // From server's perspective when worker dies:
        let server_peers = set.peers_with_policy(server);
        assert_eq!(server_peers.len(), 1);
        assert_eq!(server_peers[0].1, worker); // peer is worker
        assert_eq!(server_peers[0].2, ExitPolicy::Trap); // server traps

        // Policy-aware exit signal generation:
        let failure_vt = Time::from_nanos(1000);
        let reason = DownReason::Error("worker crashed".into());
        let mut propagated = ExitBatch::new();
        let mut trapped: Vec<(TaskId, ExitSignal)> = Vec::new();

        // For each peer of the crashing worker, check their policy
        for (link, peer) in set.peers_of(worker) {
            let policy = set.exit_policy_for(link, peer).unwrap();
            let signal = ExitSignal {
                from: worker,
                reason: reason.clone(),
                link_ref: link,
            };
            match policy {
                ExitPolicy::Propagate => propagated.push(failure_vt, signal),
                ExitPolicy::Trap => trapped.push((peer, signal)),
                ExitPolicy::Ignore => {} // silently dropped
            }
        }

        // Server has Trap policy, so no propagated signals
        assert!(propagated.is_empty());
        // Instead, server receives a trapped exit message
        assert_eq!(trapped.len(), 1);
        assert_eq!(trapped[0].0, server);
        assert_eq!(trapped[0].1.from, worker);

        // Cleanup
        set.remove_task(worker);
        assert!(set.peers_of(server).is_empty());
    }

    /// Conformance: ignore policy silently drops exit signals.
    #[test]
    fn conformance_ignore_policy_drops_signal() {
        let mut set = LinkSet::new();
        let r1 = test_region_id(0, 0);
        let watcher = test_task_id(1, 0);
        let background = test_task_id(2, 0);

        let lref = set.establish_with_policy(
            watcher,
            r1,
            ExitPolicy::Ignore,
            background,
            r1,
            ExitPolicy::Propagate,
        );

        assert_eq!(set.exit_policy_for(lref, watcher), Some(ExitPolicy::Ignore));

        // Background task dies: watcher ignores it
        let peers_of_bg = set.peers_of(background);
        assert_eq!(peers_of_bg.len(), 1);

        let policy = set.exit_policy_for(peers_of_bg[0].0, watcher).unwrap();
        assert!(policy.is_ignore());
    }

    /// Conformance: region cleanup removes links with custom policies.
    #[test]
    fn conformance_region_cleanup_with_policies() {
        let mut set = LinkSet::new();
        let r1 = test_region_id(1, 0);
        let t1 = test_task_id(1, 0);
        let t2 = test_task_id(2, 0);

        set.establish_with_policy(t1, r1, ExitPolicy::Trap, t2, r1, ExitPolicy::Ignore);

        assert_eq!(set.len(), 1);
        set.cleanup_region(r1);
        assert!(set.is_empty());
        assert!(set.peers_with_policy(t1).is_empty());
        assert!(set.peers_with_policy(t2).is_empty());
    }
}
