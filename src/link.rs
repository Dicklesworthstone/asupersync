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
#[derive(Debug, Default)]
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
        Self::default()
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
/// - `task_index`: `TaskId` → `Vec<LinkRef>` (find all links involving a task)
/// - `region_index`: `RegionId` → `Vec<LinkRef>` (region-close cleanup)
///
/// Since links are bidirectional, each link appears in `task_index` for both
/// task_a and task_b, and in `region_index` for both region_a and region_b
/// (unless they share a region).
#[derive(Debug, Default)]
pub struct LinkSet {
    records: BTreeMap<LinkRef, LinkRecord>,
    task_index: BTreeMap<TaskId, Vec<LinkRef>>,
    region_index: BTreeMap<RegionId, Vec<LinkRef>>,
}

impl LinkSet {
    /// Creates an empty link set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        // Self-links are exposed as a single logical edge, so they need one
        // canonical exit policy across introspection, mutation, and delivery.
        let (policy_a, policy_b) = if task_a == task_b {
            (policy_a, policy_a)
        } else {
            (policy_a, policy_b)
        };
        let record = LinkRecord {
            task_a,
            region_a,
            policy_a,
            task_b,
            region_b,
            policy_b,
        };

        self.records.insert(link_ref, record);

        // Index both sides. Self-links are represented once so they remain a
        // single logical link in peer views and exit resolution.
        self.task_index.entry(task_a).or_default().push(link_ref);
        if task_b != task_a {
            self.task_index.entry(task_b).or_default().push(link_ref);
        }

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
    #[inline]
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
            if rec.task_b == task {
                rec.policy_b = policy;
            }
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
#[derive(Debug, Default)]
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
        Self::default()
    }

    /// Adds an exit signal to the batch with its failure virtual time.
    pub fn push(&mut self, failure_vt: Time, signal: ExitSignal) {
        self.entries.push(ExitBatchEntry { failure_vt, signal });
    }

    /// Returns the number of signals in the batch.
    #[must_use]
    #[inline]
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

// ============================================================================
// Runtime links (br-asupersync-issue65-criticisms-kpmoy5.6.1)
// ============================================================================

/// The slot behind a [`Link`]: the link reference and the peer's canonical
/// id, then, for a trapping link, the peer's exit signal.
pub(crate) type LinkSlot = crate::monitor::WatchSlot<(LinkRef, TaskId), ExitSignal>;

/// Future returned by [`Cx::link`](crate::cx::Cx::link) and
/// [`Cx::link_trapping`](crate::cx::Cx::link_trapping): resolves once the
/// runtime has established the link.
///
/// Dropping it before it resolves withdraws the request.
#[must_use = "futures do nothing unless polled"]
pub struct LinkOpening {
    pending: Option<crate::monitor::PendingWatch<LinkSlot>>,
    failed: Option<crate::monitor::WatchError>,
}

impl std::fmt::Debug for LinkOpening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkOpening")
            .field("peer", &self.pending.as_ref().map(|p| p.target))
            .field("failed", &self.failed)
            .finish()
    }
}

impl std::future::Future for LinkOpening {
    type Output = Result<Link, crate::monitor::WatchError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        task_cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(error) = this.failed.take() {
            return std::task::Poll::Ready(Err(error));
        }
        let Some(pending) = this.pending.as_ref() else {
            return std::task::Poll::Ready(Err(crate::monitor::WatchError::RuntimeUnavailable));
        };
        let result = std::task::ready!(
            pending
                .slot
                .poll_established(&pending.gateway, task_cx.waker())
        );
        let pending = this.pending.take().expect("pending link opening");
        std::task::Poll::Ready(result.map(|(link_ref, peer)| Link {
            link_ref,
            peer,
            slot: pending.slot,
            gateway: pending.gateway,
        }))
    }
}

impl Drop for LinkOpening {
    fn drop(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if let Some((link_ref, _)) = pending.slot.abandon() {
            let _ = pending.gateway.enqueue_region_command(
                crate::runtime::spawn_mailbox::RegionCommand::Watch(
                    crate::monitor::WatchCommand::Unlink { link_ref },
                ),
            );
        }
    }
}

/// A runtime link between the calling task and a peer, returned by
/// [`Cx::link`](crate::cx::Cx::link) and
/// [`Cx::link_trapping`](crate::cx::Cx::link_trapping).
///
/// When either task finishes abnormally (error, cancellation or panic), the
/// runtime requests cancellation of the other, with a
/// [`CancelKind::LinkedExit`] reason that carries the cause. A link made
/// with `link_trapping` instead delivers the peer's exit to this handle as an
/// [`ExitSignal`] (including a normal exit), and the calling task keeps
/// running; await it with [`Link::exit`].
///
/// The link lasts until either task finishes or [`Link::unlink`] is called.
/// Dropping this handle does not unlink.
pub struct Link {
    link_ref: LinkRef,
    peer: TaskId,
    slot: std::sync::Arc<LinkSlot>,
    gateway: std::sync::Arc<crate::runtime::spawn_mailbox::SpawnGateway>,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("link_ref", &self.link_ref)
            .field("peer", &self.peer)
            .field("exit", &self.try_exit())
            .finish()
    }
}

impl Link {
    /// The reference the runtime assigned to this link; it is repeated in an
    /// [`ExitSignal`].
    #[must_use]
    pub fn link_ref(&self) -> LinkRef {
        self.link_ref
    }

    /// The linked task.
    #[must_use]
    pub fn peer(&self) -> TaskId {
        self.peer
    }

    /// Returns the peer's exit signal if this is a trapping link and the
    /// peer has finished.
    #[must_use]
    pub fn try_exit(&self) -> Option<ExitSignal> {
        self.slot.notice()
    }

    /// Waits for the peer's exit signal on a trapping link. Once delivered,
    /// later calls return the same signal immediately.
    ///
    /// On a non-trapping link the peer's abnormal exit cancels this task
    /// instead, so this returns [`WatchError::Cancelled`](crate::monitor::WatchError::Cancelled)
    /// then; after a normal peer exit it does not resolve.
    ///
    /// # Errors
    ///
    /// [`WatchError::Cancelled`](crate::monitor::WatchError::Cancelled) if
    /// the waiting task is cancelled first, and
    /// [`WatchError::RuntimeUnavailable`](crate::monitor::WatchError::RuntimeUnavailable)
    /// if the runtime shuts down first.
    pub async fn exit<Caps>(
        &self,
        cx: &crate::cx::Cx<Caps>,
    ) -> Result<ExitSignal, crate::monitor::WatchError> {
        std::future::poll_fn(|task_cx| self.slot.poll_notice(cx, &self.gateway, task_cx.waker()))
            .await
    }

    /// Removes the link. Exits after this point are not propagated.
    pub fn unlink(self) {
        let _ = self.gateway.enqueue_region_command(
            crate::runtime::spawn_mailbox::RegionCommand::Watch(
                crate::monitor::WatchCommand::Unlink {
                    link_ref: self.link_ref,
                },
            ),
        );
    }
}

impl<Caps> crate::cx::Cx<Caps> {
    /// Links the calling task with `peer`, OTP style: when either finishes
    /// abnormally (error, cancellation or panic), the runtime requests
    /// cancellation of the other. A normal exit just removes the link.
    ///
    /// `peer` is a [`TaskId`] or a reference to a
    /// [`TaskHandle`](crate::runtime::TaskHandle); pass the handle of a task
    /// you just spawned. The returned future
    /// resolves once the runtime has established the link. It fails with
    /// [`WatchError::NotFound`](crate::monitor::WatchError::NotFound) if the
    /// peer already finished (or its spawn was denied), and with
    /// [`WatchError::RuntimeUnavailable`](crate::monitor::WatchError::RuntimeUnavailable)
    /// if this context has no running runtime.
    pub fn link(&self, peer: impl Into<crate::monitor::WatchTarget>) -> LinkOpening {
        self.open_link(peer.into(), ExitPolicy::Propagate)
    }

    /// Links the calling task with `peer`, trapping the peer's exits: when
    /// `peer` finishes, for any reason, the returned [`Link`] receives an
    /// [`ExitSignal`] and the calling task keeps running. When the calling
    /// task finishes abnormally, `peer` is still cancelled.
    pub fn link_trapping(&self, peer: impl Into<crate::monitor::WatchTarget>) -> LinkOpening {
        self.open_link(peer.into(), ExitPolicy::Trap)
    }

    fn open_link(&self, peer: crate::monitor::WatchTarget, task_policy: ExitPolicy) -> LinkOpening {
        let Some(gateway) = self.spawn_gateway_handle() else {
            return LinkOpening {
                pending: None,
                failed: Some(crate::monitor::WatchError::RuntimeUnavailable),
            };
        };
        let slot = std::sync::Arc::new(LinkSlot::default());
        crate::monitor::register_for_teardown(&gateway, &slot);
        let peer_id = peer.id();
        let command = crate::monitor::WatchCommand::Link {
            task: self.task_id().into(),
            task_region: self.region_id(),
            task_policy,
            peer,
            slot: std::sync::Arc::clone(&slot),
            attempts: 0,
        };
        if gateway
            .enqueue_region_command(crate::runtime::spawn_mailbox::RegionCommand::Watch(command))
            .is_err()
        {
            return LinkOpening {
                pending: None,
                failed: Some(crate::monitor::WatchError::RuntimeUnavailable),
            };
        }
        LinkOpening {
            pending: Some(crate::monitor::PendingWatch {
                target: peer_id,
                slot,
                gateway,
            }),
            failed: None,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "link_inline_tests.rs"]
mod tests;
