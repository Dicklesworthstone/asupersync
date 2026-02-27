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
/// When multiple monitored tasks exit simultaneously, the DOWN messages
/// must be delivered in a deterministic order (sorted by task index).
/// This oracle records DOWN delivery sequences and verifies ordering.
#[derive(Debug, Default)]
pub struct DownOrderOracle {
    /// For each monitor task, the ordered sequence of DOWN subjects received.
    delivery_sequences: HashMap<TaskId, Vec<TaskId>>,
    /// Total number of DOWN events recorded.
    down_count: usize,
}

impl DownOrderOracle {
    /// Create a new oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a DOWN message being delivered to a monitor.
    pub fn on_down_delivered(&mut self, monitor: TaskId, subject: TaskId) {
        self.delivery_sequences
            .entry(monitor)
            .or_default()
            .push(subject);
        self.down_count += 1;
    }

    /// Check that all DOWN delivery sequences are in deterministic order.
    ///
    /// The expected order is sorted by task index (deterministic tiebreak).
    pub fn check(&self) -> Result<(), DownOrderViolation> {
        let mut monitors: Vec<_> = self.delivery_sequences.keys().copied().collect();
        monitors.sort();

        for monitor in monitors {
            if let Some(actual) = self.delivery_sequences.get(&monitor) {
                let mut expected = actual.clone();
                expected.sort();

                if *actual != expected {
                    return Err(DownOrderViolation {
                        monitor,
                        expected,
                        actual: actual.clone(),
                    });
                }
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
mod tests {
    use super::*;
    use crate::types::TaskId;

    fn task(index: u32) -> TaskId {
        TaskId::new_for_test(index, 0)
    }

    fn actor(index: u32) -> ActorId {
        ActorId::from_task(task(index))
    }

    fn region(index: u32) -> RegionId {
        RegionId::new_for_test(index, 0)
    }

    // ReplyLinearityOracle tests

    #[test]
    fn reply_linearity_pass_when_all_resolved() {
        let mut oracle = ReplyLinearityOracle::new();
        oracle.on_reply_created(actor(1), task(1), Time::ZERO);
        oracle.on_reply_sent(actor(1), task(1));
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn reply_linearity_fail_on_dropped_reply() {
        let mut oracle = ReplyLinearityOracle::new();
        oracle.on_reply_created(actor(1), task(1), Time::ZERO);
        // No send or abort.
        let err = oracle.check().unwrap_err();
        assert!(err.dropped);
    }

    #[test]
    fn reply_linearity_pass_on_aborted_reply() {
        let mut oracle = ReplyLinearityOracle::new();
        oracle.on_reply_created(actor(1), task(1), Time::ZERO);
        oracle.on_reply_aborted(actor(1), task(1));
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn reply_linearity_fail_on_double_resolution() {
        let mut oracle = ReplyLinearityOracle::new();
        oracle.on_reply_created(actor(1), task(1), Time::ZERO);
        oracle.on_reply_sent(actor(1), task(1));
        oracle.on_reply_aborted(actor(1), task(1));
        let err = oracle.check().unwrap_err();
        assert!(!err.dropped);
    }

    #[test]
    fn reply_linearity_reset_clears_state() {
        let mut oracle = ReplyLinearityOracle::new();
        oracle.on_reply_created(actor(1), task(1), Time::ZERO);
        oracle.reset();
        assert!(oracle.check().is_ok());
        assert_eq!(oracle.created_count(), 0);
    }

    // RegistryLeaseOracle tests

    #[test]
    fn registry_lease_pass_when_all_resolved() {
        let mut oracle = RegistryLeaseOracle::new();
        oracle.on_lease_acquired("svc", task(1), region(0), Time::ZERO);
        oracle.on_lease_released("svc");
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn registry_lease_fail_on_unreleased_lease() {
        let mut oracle = RegistryLeaseOracle::new();
        oracle.on_lease_acquired("leaked_svc", task(1), region(0), Time::ZERO);
        let err = oracle.check().unwrap_err();
        assert_eq!(err.name, "leaked_svc");
    }

    #[test]
    fn registry_lease_pass_on_aborted_lease() {
        let mut oracle = RegistryLeaseOracle::new();
        oracle.on_lease_acquired("temp", task(1), region(0), Time::ZERO);
        oracle.on_lease_aborted("temp");
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn registry_lease_reset_clears_state() {
        let mut oracle = RegistryLeaseOracle::new();
        oracle.on_lease_acquired("name", task(1), region(0), Time::ZERO);
        oracle.reset();
        assert!(oracle.check().is_ok());
        assert_eq!(oracle.acquired_count(), 0);
    }

    // DownOrderOracle tests

    #[test]
    fn down_order_pass_when_sorted() {
        let mut oracle = DownOrderOracle::new();
        // Deliver DOWNs in sorted order.
        oracle.on_down_delivered(task(10), task(1));
        oracle.on_down_delivered(task(10), task(2));
        oracle.on_down_delivered(task(10), task(3));
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn down_order_fail_when_unsorted() {
        let mut oracle = DownOrderOracle::new();
        // Deliver DOWNs in wrong order.
        oracle.on_down_delivered(task(10), task(3));
        oracle.on_down_delivered(task(10), task(1));
        let err = oracle.check().unwrap_err();
        assert_eq!(err.monitor, task(10));
    }

    #[test]
    fn down_order_pass_with_empty() {
        let oracle = DownOrderOracle::new();
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn down_order_reset_clears_state() {
        let mut oracle = DownOrderOracle::new();
        oracle.on_down_delivered(task(10), task(3));
        oracle.on_down_delivered(task(10), task(1));
        oracle.reset();
        assert!(oracle.check().is_ok());
        assert_eq!(oracle.down_count(), 0);
    }

    // SupervisorQuiescenceOracle tests

    #[test]
    fn supervisor_quiescence_pass_when_all_completed() {
        let mut oracle = SupervisorQuiescenceOracle::new();
        oracle.on_supervisor_created(task(1), region(0));
        oracle.on_child_added(task(1), task(2));
        oracle.on_child_added(task(1), task(3));
        oracle.on_task_completed(task(2), Time::ZERO);
        oracle.on_task_completed(task(3), Time::ZERO);
        oracle.on_region_closed(region(0), Time::ZERO);
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn supervisor_quiescence_fail_with_active_child() {
        let mut oracle = SupervisorQuiescenceOracle::new();
        oracle.on_supervisor_created(task(1), region(0));
        oracle.on_child_added(task(1), task(2));
        // task(2) never completes.
        oracle.on_region_closed(region(0), Time::ZERO);
        let err = oracle.check().unwrap_err();
        assert_eq!(err.active_children, vec![task(2)]);
    }

    #[test]
    fn supervisor_quiescence_pass_when_region_not_closed() {
        let mut oracle = SupervisorQuiescenceOracle::new();
        oracle.on_supervisor_created(task(1), region(0));
        oracle.on_child_added(task(1), task(2));
        // Region NOT closed — should pass (only checks closed regions).
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn supervisor_quiescence_fail_when_child_completes_after_close() {
        let mut oracle = SupervisorQuiescenceOracle::new();
        oracle.on_supervisor_created(task(1), region(0));
        oracle.on_child_added(task(1), task(2));
        oracle.on_region_closed(region(0), Time::from_nanos(100));
        oracle.on_task_completed(task(2), Time::from_nanos(101));
        let err = oracle.check().unwrap_err();
        assert_eq!(err.active_children, vec![task(2)]);
        assert_eq!(err.close_time, Time::from_nanos(100));
    }

    #[test]
    fn supervisor_quiescence_reset_clears_state() {
        let mut oracle = SupervisorQuiescenceOracle::new();
        oracle.on_supervisor_created(task(1), region(0));
        oracle.on_child_added(task(1), task(2));
        oracle.on_region_closed(region(0), Time::ZERO);
        oracle.reset();
        assert!(oracle.check().is_ok());
        assert_eq!(oracle.supervisor_count(), 0);
    }
}
