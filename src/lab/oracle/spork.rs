//! Spork-specific oracles for GenServer and supervision invariants (bd-5ogl7).
//!
//! These oracles verify invariants specific to the Spork actor layer:
//!
//! - [`ReplyLinearityOracle`]: Every `Reply<R>` must be sent exactly once (no drops).
//! - [`RegistryLeaseOracle`]: Every `NameLease` must be committed or aborted (no stale names).
//! - [`DownOrderOracle`]: DOWN messages are delivered in a deterministic order.
//! - [`SupervisorQuiescenceOracle`]: Supervisor region close implies full child quiescence.

use crate::actor::ActorId;
use crate::types::{RegionId, TaskId, Time};
use std::collections::{HashMap, HashSet};
use std::fmt;

// ============================================================================
// ReplyLinearityOracle
// ============================================================================

/// A reply was created but never sent (or sent more than once).
#[derive(Debug, Clone)]
pub struct ReplyLinearityViolation {
    /// The server that created the reply.
    pub server: ActorId,
    /// Task that handled the call.
    pub task: TaskId,
    /// Whether the reply was dropped (true) or double-sent (false).
    pub dropped: bool,
    /// Time the call was received.
    pub call_time: Time,
}

impl fmt::Display for ReplyLinearityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.dropped {
            "dropped"
        } else {
            "double-sent"
        };
        write!(
            f,
            "Reply {} by server {:?} (task {:?}) at {:?}",
            kind, self.server, self.task, self.call_time
        )
    }
}

impl std::error::Error for ReplyLinearityViolation {}

/// Oracle for verifying that every GenServer `Reply<R>` is resolved exactly once.
///
/// Tracks call/reply pairs and verifies at check time that every created reply
/// was sent (committed) or explicitly aborted. A reply that is dropped without
/// resolution is a linearity violation.
#[derive(Debug, Default)]
pub struct ReplyLinearityOracle {
    /// Pending replies: (server, task) -> (call_time, resolved, over_resolved).
    pending: HashMap<(ActorId, TaskId), (Time, bool, bool)>,
    /// Count of replies created.
    created_count: usize,
    /// Count of replies resolved (sent or aborted).
    resolved_count: usize,
}

impl ReplyLinearityOracle {
    /// Create a new oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a reply being created (when handle_call is entered).
    pub fn on_reply_created(&mut self, server: ActorId, task: TaskId, time: Time) {
        self.pending.insert((server, task), (time, false, false));
        self.created_count += 1;
    }

    /// Record a reply being sent (committed).
    pub fn on_reply_sent(&mut self, server: ActorId, task: TaskId) {
        if let Some(entry) = self.pending.get_mut(&(server, task)) {
            if entry.1 {
                entry.2 = true;
            } else {
                entry.1 = true;
            }
        }
        self.resolved_count += 1;
    }

    /// Record a reply being aborted (explicit cancellation).
    pub fn on_reply_aborted(&mut self, server: ActorId, task: TaskId) {
        if let Some(entry) = self.pending.get_mut(&(server, task)) {
            if entry.1 {
                entry.2 = true;
            } else {
                entry.1 = true;
            }
        }
        self.resolved_count += 1;
    }

    /// Check for unresolved replies.
    pub fn check(&self) -> Result<(), ReplyLinearityViolation> {
        // Sort for deterministic error reporting.
        let mut keys: Vec<_> = self.pending.keys().copied().collect();
        keys.sort_by_key(|(a, t)| (a.task_id(), *t));

        for (server, task) in keys {
            if let Some(&(call_time, resolved, over_resolved)) = self.pending.get(&(server, task)) {
                if over_resolved {
                    return Err(ReplyLinearityViolation {
                        server,
                        task,
                        dropped: false,
                        call_time,
                    });
                }
                if !resolved {
                    return Err(ReplyLinearityViolation {
                        server,
                        task,
                        dropped: true,
                        call_time,
                    });
                }
            }
        }
        Ok(())
    }

    /// Reset all tracked state.
    pub fn reset(&mut self) {
        self.pending.clear();
        self.created_count = 0;
        self.resolved_count = 0;
    }

    /// Number of replies created.
    #[must_use]
    pub fn created_count(&self) -> usize {
        self.created_count
    }

    /// Number of replies resolved.
    #[must_use]
    pub fn resolved_count(&self) -> usize {
        self.resolved_count
    }
}

// ============================================================================
// RegistryLeaseOracle
// ============================================================================

/// A name lease was not properly resolved before its owning region closed.
#[derive(Debug, Clone)]
pub struct RegistryLeaseViolation {
    /// The name that was leaked.
    pub name: String,
    /// Task holding the leaked lease.
    pub holder: TaskId,
    /// Region that owned the holder.
    pub region: RegionId,
    /// Time the lease was acquired.
    pub acquired_at: Time,
}

impl fmt::Display for RegistryLeaseViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Stale name lease \"{}\" held by {:?} in region {:?} (acquired at {:?})",
            self.name, self.holder, self.region, self.acquired_at
        )
    }
}

impl std::error::Error for RegistryLeaseViolation {}

/// Oracle for verifying that all `NameLease` obligations are resolved.
///
/// Tracks lease acquisition and resolution. At check time, any lease that
/// was not committed (released) or aborted is a linearity violation — a
/// "stale name" that could block future registrations.
#[derive(Debug, Default)]
pub struct RegistryLeaseOracle {
    /// Active leases: name -> (holder, region, acquired_at, resolved?)
    leases: HashMap<String, (TaskId, RegionId, Time, bool)>,
    /// Count of leases acquired.
    acquired_count: usize,
    /// Count of leases resolved.
    resolved_count: usize,
}

impl RegistryLeaseOracle {
    /// Create a new oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a name lease being acquired.
    pub fn on_lease_acquired(
        &mut self,
        name: impl Into<String>,
        holder: TaskId,
        region: RegionId,
        time: Time,
    ) {
        self.leases
            .insert(name.into(), (holder, region, time, false));
        self.acquired_count += 1;
    }

    /// Record a name lease being released (committed).
    pub fn on_lease_released(&mut self, name: &str) {
        if let Some(entry) = self.leases.get_mut(name) {
            entry.3 = true;
        }
        self.resolved_count += 1;
    }

    /// Record a name lease being aborted.
    pub fn on_lease_aborted(&mut self, name: &str) {
        if let Some(entry) = self.leases.get_mut(name) {
            entry.3 = true;
        }
        self.resolved_count += 1;
    }

    /// Check for unresolved leases.
    pub fn check(&self) -> Result<(), RegistryLeaseViolation> {
        let mut names: Vec<_> = self.leases.keys().cloned().collect();
        names.sort();

        for name in names {
            if let Some(&(holder, region, acquired_at, resolved)) = self.leases.get(&name) {
                if !resolved {
                    return Err(RegistryLeaseViolation {
                        name,
                        holder,
                        region,
                        acquired_at,
                    });
                }
            }
        }
        Ok(())
    }

    /// Reset all tracked state.
    pub fn reset(&mut self) {
        self.leases.clear();
        self.acquired_count = 0;
        self.resolved_count = 0;
    }

    /// Number of leases acquired.
    #[must_use]
    pub fn acquired_count(&self) -> usize {
        self.acquired_count
    }

    /// Number of leases resolved.
    #[must_use]
    pub fn resolved_count(&self) -> usize {
        self.resolved_count
    }
}

// ============================================================================
// DownOrderOracle
// ============================================================================

/// DOWN messages were delivered in a non-deterministic order.
#[derive(Debug, Clone)]
pub struct DownOrderViolation {
    /// The monitoring task that received out-of-order DOWNs.
    pub monitor: TaskId,
    /// Expected ordering of DOWN subjects (sorted by task index).
    pub expected: Vec<TaskId>,
    /// Actual delivery order.
    pub actual: Vec<TaskId>,
}

impl fmt::Display for DownOrderViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Non-deterministic DOWN order for monitor {:?}: expected {:?}, got {:?}",
            self.monitor, self.expected, self.actual
        )
    }
}

impl std::error::Error for DownOrderViolation {}

/// Oracle for verifying deterministic DOWN message delivery order.
///
/// Two kinds of record:
/// - [`Self::on_down_delivered`] records DOWNs that became ready together
///   (one simultaneous batch): they must arrive sorted by task index.
/// - [`Self::on_down_delivered_at`] records a DOWN with the completion time
///   of its subject, as the runtime delivers them: one completion at a time,
///   so a monitor's DOWNs must never go back in completion time. Completions
///   at the same virtual time are separate batches and keep the order in
///   which they completed.
///
/// `LabRuntime` feeds the timed form from the runtime's DOWN deliveries
/// (br-asupersync-issue65-criticisms-kpmoy5.6.1).
#[derive(Debug, Default)]
pub struct DownOrderOracle {
    /// For each monitor task, the ordered sequence of
    /// `(completion time if known, DOWN subject)` received.
    delivery_sequences: HashMap<TaskId, Vec<(Option<Time>, TaskId)>>,
    /// Total number of DOWN events recorded.
    down_count: usize,
}

impl DownOrderOracle {
    /// Create a new oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a DOWN message being delivered to a monitor, as part of one
    /// simultaneous batch (ordered by task index).
    pub fn on_down_delivered(&mut self, monitor: TaskId, subject: TaskId) {
        self.record(monitor, subject, None);
    }

    /// Record a DOWN message about `subject`, which completed at
    /// `completion_vt`, being delivered to `monitor`.
    pub fn on_down_delivered_at(&mut self, monitor: TaskId, subject: TaskId, completion_vt: Time) {
        self.record(monitor, subject, Some(completion_vt));
    }

    fn record(&mut self, monitor: TaskId, subject: TaskId, completion_vt: Option<Time>) {
        self.delivery_sequences
            .entry(monitor)
            .or_default()
            .push((completion_vt, subject));
        self.down_count += 1;
    }

    /// Check every monitor's DOWN sequence: batch records sorted by task
    /// index, timed records nondecreasing in completion time.
    pub fn check(&self) -> Result<(), DownOrderViolation> {
        let mut monitors: Vec<_> = self.delivery_sequences.keys().copied().collect();
        monitors.sort();

        for monitor in monitors {
            let Some(sequence) = self.delivery_sequences.get(&monitor) else {
                continue;
            };
            let batch: Vec<TaskId> = sequence
                .iter()
                .filter(|(at, _)| at.is_none())
                .map(|&(_, subject)| subject)
                .collect();
            let mut expected = batch.clone();
            expected.sort();
            if batch != expected {
                return Err(DownOrderViolation {
                    monitor,
                    expected,
                    actual: batch,
                });
            }
            let timed: Vec<(Time, TaskId)> = sequence
                .iter()
                .filter_map(|&(at, subject)| at.map(|at| (at, subject)))
                .collect();
            if timed.windows(2).any(|pair| pair[1].0 < pair[0].0) {
                let mut expected = timed.clone();
                expected.sort_by_key(|&(at, _)| at);
                return Err(DownOrderViolation {
                    monitor,
                    expected: expected.into_iter().map(|(_, subject)| subject).collect(),
                    actual: timed.into_iter().map(|(_, subject)| subject).collect(),
                });
            }
        }
        Ok(())
    }

    /// Reset all tracked state.
    pub fn reset(&mut self) {
        self.delivery_sequences.clear();
        self.down_count = 0;
    }

    /// Number of monitors tracked.
    #[must_use]
    pub fn monitor_count(&self) -> usize {
        self.delivery_sequences.len()
    }

    /// Total number of DOWN events recorded.
    #[must_use]
    pub fn down_count(&self) -> usize {
        self.down_count
    }
}

// ============================================================================
// SupervisorQuiescenceOracle
// ============================================================================

/// A supervisor's region closed but not all children had reached quiescence.
#[derive(Debug, Clone)]
pub struct SupervisorQuiescenceViolation {
    /// The supervisor whose region closed.
    pub supervisor: TaskId,
    /// The supervisor's region.
    pub region: RegionId,
    /// Children that were still active at close time.
    pub active_children: Vec<TaskId>,
    /// Time the region closed.
    pub close_time: Time,
}

impl fmt::Display for SupervisorQuiescenceViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Supervisor {:?} (region {:?}) closed at {:?} with {} active children: {:?}",
            self.supervisor,
            self.region,
            self.close_time,
            self.active_children.len(),
            self.active_children
        )
    }
}

impl std::error::Error for SupervisorQuiescenceViolation {}

/// Oracle for verifying that supervisor tree close implies child quiescence.
///
/// When a supervisor's region closes, all of its children must have already
/// completed or been stopped. If any child is still active at close time,
/// it's a violation of the structured concurrency contract for supervisors.
#[derive(Debug, Default)]
pub struct SupervisorQuiescenceOracle {
    /// Supervisor -> (region, set of child tasks).
    supervisors: HashMap<TaskId, (RegionId, HashSet<TaskId>)>,
    /// Tasks that have completed, with completion time.
    completed_tasks: HashMap<TaskId, Time>,
    /// Regions that have closed, with their close times.
    closed_regions: HashMap<RegionId, Time>,
    /// Total child registration events.
    child_count: usize,
}

impl SupervisorQuiescenceOracle {
    /// Create a new oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a supervisor being created with its region.
    pub fn on_supervisor_created(&mut self, supervisor: TaskId, region: RegionId) {
        self.supervisors
            .entry(supervisor)
            .or_insert_with(|| (region, HashSet::new()));
    }

    /// Record a child being added to a supervisor.
    pub fn on_child_added(&mut self, supervisor: TaskId, child: TaskId) {
        if let Some((_, children)) = self.supervisors.get_mut(&supervisor) {
            children.insert(child);
        }
        self.child_count += 1;
    }

    /// Record a task completing.
    pub fn on_task_completed(&mut self, task: TaskId, time: Time) {
        self.completed_tasks
            .entry(task)
            .and_modify(|completed_at| {
                if time < *completed_at {
                    *completed_at = time;
                }
            })
            .or_insert(time);
    }

    /// Record a region closing.
    pub fn on_region_closed(&mut self, region: RegionId, time: Time) {
        self.closed_regions.insert(region, time);
    }

    /// Check that all closed supervisor regions had quiescent children.
    pub fn check(&self) -> Result<(), SupervisorQuiescenceViolation> {
        let mut sups: Vec<_> = self.supervisors.keys().copied().collect();
        sups.sort();

        for supervisor in sups {
            if let Some((region, children)) = self.supervisors.get(&supervisor) {
                // Only check if the supervisor's region has closed.
                if let Some(&close_time) = self.closed_regions.get(region) {
                    let mut active: Vec<TaskId> = children
                        .iter()
                        .copied()
                        .filter(|c| {
                            self.completed_tasks
                                .get(c)
                                .is_none_or(|completed_at| *completed_at > close_time)
                        })
                        .collect();
                    active.sort();

                    if !active.is_empty() {
                        return Err(SupervisorQuiescenceViolation {
                            supervisor,
                            region: *region,
                            active_children: active,
                            close_time,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Reset all tracked state.
    pub fn reset(&mut self) {
        self.supervisors.clear();
        self.completed_tasks.clear();
        self.closed_regions.clear();
        self.child_count = 0;
    }

    /// Number of supervisors tracked.
    #[must_use]
    pub fn supervisor_count(&self) -> usize {
        self.supervisors.len()
    }

    /// Total number of child registration events.
    #[must_use]
    pub fn child_count(&self) -> usize {
        self.child_count
    }

    /// Number of regions closed.
    #[must_use]
    pub fn closed_region_count(&self) -> usize {
        self.closed_regions.len()
    }
}

#[cfg(test)]
#[path = "spork_inline_tests.rs"]
mod tests;
