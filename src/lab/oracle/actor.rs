//! Actor-specific oracles for verifying actor system invariants.
//!
//! These oracles verify actor-specific invariants in lab mode:
//! - [`ActorLeakOracle`]: Detects actors not properly stopped before region close
//! - [`SupervisionOracle`]: Verifies supervision tree behavior (restarts, escalation)
//! - [`MailboxOracle`]: Verifies mailbox invariants (capacity, backpressure)
//!
//! # Usage
//!
//! ```ignore
//! let mut actor_leak = ActorLeakOracle::new();
//! let mut supervision = SupervisionOracle::new();
//! let mut mailbox = MailboxOracle::new();
//!
//! // During execution, record events:
//! actor_leak.on_spawn(actor_id, region_id, time);
//! actor_leak.on_stop(actor_id, time);
//! actor_leak.on_region_close(region_id, time);
//!
//! supervision.on_child_failed(parent_id, child_id, time);
//! supervision.on_restart(child_id, attempt, time);
//!
//! mailbox.on_send(actor_id, time);
//! mailbox.on_receive(actor_id, time);
//! mailbox.on_capacity_set(actor_id, capacity);
//!
//! // At end of test, verify:
//! actor_leak.check(now)?;
//! supervision.check(now)?;
//! mailbox.check(now)?;
//! ```

use crate::actor::ActorId;
use crate::supervision::{EscalationPolicy, RestartPolicy};
use crate::types::{RegionId, Time};
use std::collections::{HashMap, HashSet};
use std::fmt;

// ============================================================================
// ActorLeakOracle
// ============================================================================

/// An actor leak violation.
///
/// This indicates that a region closed while some of its actors had not
/// been properly stopped, violating structured concurrency for actors.
#[derive(Debug, Clone)]
pub struct ActorLeakViolation {
    /// The region that closed with leaked actors.
    pub region: RegionId,
    /// The actors that were not stopped when the region closed.
    pub leaked_actors: Vec<ActorId>,
    /// The time when the region closed.
    pub region_close_time: Time,
}

impl fmt::Display for ActorLeakViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Region {:?} closed at {:?} with {} leaked actor(s): {:?}",
            self.region,
            self.region_close_time,
            self.leaked_actors.len(),
            self.leaked_actors
        )
    }
}

impl std::error::Error for ActorLeakViolation {}

/// Oracle for detecting actor leak violations.
///
/// Tracks actor spawns, stops, and region closes to verify that
/// all actors are stopped before their owning region closes.
#[derive(Debug, Default)]
pub struct ActorLeakOracle {
    /// Actors by region: region -> set of actors spawned in that region.
    actors_by_region: HashMap<RegionId, HashSet<ActorId>>,
    /// Stopped actors with their stop times.
    stopped_actors: HashMap<ActorId, Time>,
    /// Region close records: region -> close_time.
    region_closes: HashMap<RegionId, Time>,
}

impl ActorLeakOracle {
    /// Creates a new actor leak oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an actor spawn event.
    pub fn on_spawn(&mut self, actor: ActorId, region: RegionId, _time: Time) {
        self.actors_by_region
            .entry(region)
            .or_default()
            .insert(actor);
    }

    /// Records an actor stop event.
    pub fn on_stop(&mut self, actor: ActorId, time: Time) {
        self.stopped_actors
            .entry(actor)
            .and_modify(|t| {
                if time < *t {
                    *t = time;
                }
            })
            .or_insert(time);
    }

    /// Records a region close event.
    pub fn on_region_close(&mut self, region: RegionId, time: Time) {
        self.region_closes.insert(region, time);
    }

    /// Verifies the invariant holds.
    ///
    /// Checks that for every closed region, all its actors have stopped.
    /// Returns an error with the first violation found.
    pub fn check(&self, _now: Time) -> Result<(), ActorLeakViolation> {
        for (&region, &close_time) in &self.region_closes {
            let Some(actors) = self.actors_by_region.get(&region) else {
                continue; // No actors spawned in this region
            };

            let mut leaked = Vec::new();

            for &actor in actors {
                let stopped_at = self.stopped_actors.get(&actor);
                let leaked_now = stopped_at.is_none_or(|t| *t > close_time);
                if leaked_now {
                    leaked.push(actor);
                }
            }

            if !leaked.is_empty() {
                return Err(ActorLeakViolation {
                    region,
                    leaked_actors: leaked,
                    region_close_time: close_time,
                });
            }
        }

        Ok(())
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.actors_by_region.clear();
        self.stopped_actors.clear();
        self.region_closes.clear();
    }

    /// Returns the number of tracked actors.
    #[must_use]
    pub fn actor_count(&self) -> usize {
        self.actors_by_region.values().map(HashSet::len).sum()
    }

    /// Returns the number of stopped actors.
    #[must_use]
    pub fn stopped_count(&self) -> usize {
        self.stopped_actors.len()
    }

    /// Returns the number of closed regions.
    #[must_use]
    pub fn closed_region_count(&self) -> usize {
        self.region_closes.len()
    }
}

// ============================================================================
// SupervisionOracle
// ============================================================================

/// A supervision violation.
///
/// Indicates that a supervision tree violated expected behavior:
/// - Restart limits exceeded without escalation
/// - OneForAll/RestForOne policies not followed
/// - Escalation not propagated correctly
#[derive(Debug, Clone)]
pub struct SupervisionViolation {
    /// The kind of supervision violation.
    pub kind: SupervisionViolationKind,
    /// The supervisor that violated the invariant.
    pub supervisor: ActorId,
    /// The child actor involved (if applicable).
    pub child: Option<ActorId>,
    /// The time when the violation occurred.
    pub time: Time,
}

/// Kind of supervision violation.
#[derive(Debug, Clone)]
pub enum SupervisionViolationKind {
    /// Restart limit exceeded without proper escalation.
    RestartLimitExceeded {
        /// Number of restarts attempted.
        restarts: u32,
        /// Maximum allowed restarts.
        max_restarts: u32,
        /// The escalation policy that should have been invoked.
        expected_escalation: EscalationPolicy,
    },
    /// OneForAll policy not followed (sibling not restarted).
    OneForAllNotFollowed {
        /// The actor that failed.
        failed_actor: ActorId,
        /// Siblings that should have been restarted.
        unrestarted_siblings: Vec<ActorId>,
    },
    /// RestForOne policy not followed.
    RestForOneNotFollowed {
        /// The actor that failed.
        failed_actor: ActorId,
        /// Actors started after the failed one that should have restarted.
        unrestarted_successors: Vec<ActorId>,
    },
    /// Escalation not propagated to parent.
    EscalationNotPropagated {
        /// The error that should have been escalated.
        reason: String,
    },
}

impl fmt::Display for SupervisionViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            SupervisionViolationKind::RestartLimitExceeded {
                restarts,
                max_restarts,
                expected_escalation,
            } => {
                write!(
                    f,
                    "Supervisor {:?} exceeded restart limit ({}/{}) at {:?}, expected {:?}",
                    self.supervisor, restarts, max_restarts, self.time, expected_escalation
                )
            }
            SupervisionViolationKind::OneForAllNotFollowed {
                failed_actor,
                unrestarted_siblings,
            } => {
                write!(
                    f,
                    "Supervisor {:?}: OneForAll not followed for {:?}, siblings {:?} not restarted",
                    self.supervisor, failed_actor, unrestarted_siblings
                )
            }
            SupervisionViolationKind::RestForOneNotFollowed {
                failed_actor,
                unrestarted_successors,
            } => {
                write!(
                    f,
                    "Supervisor {:?}: RestForOne not followed for {:?}, successors {:?} not restarted",
                    self.supervisor, failed_actor, unrestarted_successors
                )
            }
            SupervisionViolationKind::EscalationNotPropagated { reason } => {
                write!(
                    f,
                    "Supervisor {:?}: escalation not propagated at {:?}: {}",
                    self.supervisor, self.time, reason
                )
            }
        }
    }
}

impl std::error::Error for SupervisionViolation {}

/// Record of a child failure event.
#[derive(Debug, Clone)]
struct ChildFailure {
    parent: ActorId,
    child: ActorId,
    time: Time,
    reason: String,
}

/// Record of a restart event.
#[derive(Debug, Clone)]
struct RestartEvent {
    actor: ActorId,
    attempt: u32,
    time: Time,
}

/// Record of an escalation event.
#[derive(Debug, Clone)]
struct EscalationEvent {
    from: ActorId,
    to: ActorId,
    time: Time,
    reason: String,
}

/// Configuration for a supervisor being tracked.
#[derive(Debug, Clone)]
struct SupervisorConfig {
    restart_policy: RestartPolicy,
    max_restarts: u32,
    escalation_policy: EscalationPolicy,
    children: Vec<ActorId>,
}

/// Oracle for verifying supervision tree behavior.
///
/// Tracks child failures, restarts, and escalations to verify that
/// supervision policies are correctly followed.
#[derive(Debug, Default)]
pub struct SupervisionOracle {
    /// Supervisor configurations.
    supervisors: HashMap<ActorId, SupervisorConfig>,
    /// Child failures recorded.
    failures: Vec<ChildFailure>,
    /// Restart events recorded.
    restarts: Vec<RestartEvent>,
    /// Escalation events recorded.
    escalations: Vec<EscalationEvent>,
    /// Restart counts per actor within the window.
    restart_counts: HashMap<ActorId, u32>,
    /// Detected violations.
    violations: Vec<SupervisionViolation>,
}

impl SupervisionOracle {
    /// Creates a new supervision oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a supervisor with its configuration.
    pub fn register_supervisor(
        &mut self,
        supervisor: ActorId,
        restart_policy: RestartPolicy,
        max_restarts: u32,
        escalation_policy: EscalationPolicy,
    ) {
        self.supervisors.insert(
            supervisor,
            SupervisorConfig {
                restart_policy,
                max_restarts,
                escalation_policy,
                children: Vec::new(),
            },
        );
    }

    /// Register a child actor under a supervisor.
    pub fn register_child(&mut self, supervisor: ActorId, child: ActorId) {
        if let Some(config) = self.supervisors.get_mut(&supervisor) {
            config.children.push(child);
        }
    }

    /// Records a child failure event.
    pub fn on_child_failed(&mut self, parent: ActorId, child: ActorId, time: Time, reason: String) {
        self.failures.push(ChildFailure {
            parent,
            child,
            time,
            reason,
        });
    }

    /// Records a restart event.
    pub fn on_restart(&mut self, actor: ActorId, attempt: u32, time: Time) {
        self.restarts.push(RestartEvent {
            actor,
            attempt,
            time,
        });
        *self.restart_counts.entry(actor).or_default() = attempt;
    }

    /// Records an escalation event.
    pub fn on_escalation(&mut self, from: ActorId, to: ActorId, time: Time, reason: String) {
        self.escalations.push(EscalationEvent {
            from,
            to,
            time,
            reason,
        });
    }

    /// Verifies the invariants hold.
    pub fn check(&self, _now: Time) -> Result<(), SupervisionViolation> {
        // Check for restart limit violations
        for failure in &self.failures {
            if let Some(config) = self.supervisors.get(&failure.parent) {
                let restart_count = self
                    .restart_counts
                    .get(&failure.child)
                    .copied()
                    .unwrap_or(0);

                // Check if restart limit was exceeded without escalation
                if restart_count > config.max_restarts {
                    // Verify escalation happened (e.from is parent, not failure.from)
                    #[allow(clippy::suspicious_operation_groupings)]
                    let escalated = self
                        .escalations
                        .iter()
                        .any(|e| e.from == failure.parent && e.time >= failure.time);

                    if !escalated && config.escalation_policy != EscalationPolicy::Stop {
                        return Err(SupervisionViolation {
                            kind: SupervisionViolationKind::RestartLimitExceeded {
                                restarts: restart_count,
                                max_restarts: config.max_restarts,
                                expected_escalation: config.escalation_policy,
                            },
                            supervisor: failure.parent,
                            child: Some(failure.child),
                            time: failure.time,
                        });
                    }
                }

                // Check OneForAll policy
                if config.restart_policy == RestartPolicy::OneForAll {
                    let siblings: Vec<_> = config
                        .children
                        .iter()
                        .filter(|&&c| c != failure.child)
                        .copied()
                        .collect();

                    let unrestarted: Vec<_> = siblings
                        .iter()
                        .filter(|&&s| {
                            !self
                                .restarts
                                .iter()
                                .any(|r| r.actor == s && r.time >= failure.time)
                        })
                        .copied()
                        .collect();

                    if !unrestarted.is_empty() {
                        return Err(SupervisionViolation {
                            kind: SupervisionViolationKind::OneForAllNotFollowed {
                                failed_actor: failure.child,
                                unrestarted_siblings: unrestarted,
                            },
                            supervisor: failure.parent,
                            child: Some(failure.child),
                            time: failure.time,
                        });
                    }
                }

                // Check RestForOne policy
                if config.restart_policy == RestartPolicy::RestForOne {
                    let child_idx = config.children.iter().position(|&c| c == failure.child);

                    if let Some(idx) = child_idx {
                        let successors: Vec<_> = config.children[idx + 1..].to_vec();

                        let unrestarted: Vec<_> = successors
                            .iter()
                            .filter(|&&s| {
                                !self
                                    .restarts
                                    .iter()
                                    .any(|r| r.actor == s && r.time >= failure.time)
                            })
                            .copied()
                            .collect();

                        if !unrestarted.is_empty() {
                            return Err(SupervisionViolation {
                                kind: SupervisionViolationKind::RestForOneNotFollowed {
                                    failed_actor: failure.child,
                                    unrestarted_successors: unrestarted,
                                },
                                supervisor: failure.parent,
                                child: Some(failure.child),
                                time: failure.time,
                            });
                        }
                    }
                }
            }
        }

        // Return first recorded violation if any
        if let Some(violation) = self.violations.first() {
            return Err(violation.clone());
        }

        Ok(())
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.supervisors.clear();
        self.failures.clear();
        self.restarts.clear();
        self.escalations.clear();
        self.restart_counts.clear();
        self.violations.clear();
    }

    /// Returns the number of failures recorded.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.failures.len()
    }

    /// Returns the number of restarts recorded.
    #[must_use]
    pub fn restart_count(&self) -> usize {
        self.restarts.len()
    }

    /// Returns the number of escalations recorded.
    #[must_use]
    pub fn escalation_count(&self) -> usize {
        self.escalations.len()
    }
}

// ============================================================================
// MailboxOracle
// ============================================================================

/// A mailbox violation.
///
/// Indicates that a mailbox invariant was violated:
/// - Capacity exceeded without backpressure
/// - Messages lost
/// - Delivery order violated
#[derive(Debug, Clone)]
pub struct MailboxViolation {
    /// The kind of mailbox violation.
    pub kind: MailboxViolationKind,
    /// The actor whose mailbox was violated.
    pub actor: ActorId,
    /// The time when the violation occurred.
    pub time: Time,
}

/// Kind of mailbox violation.
#[derive(Debug, Clone)]
pub enum MailboxViolationKind {
    /// Mailbox capacity exceeded.
    CapacityExceeded {
        /// Current message count.
        current: usize,
        /// Maximum capacity.
        capacity: usize,
    },
    /// Message was lost (sent but never received).
    MessageLost {
        /// Number of messages sent.
        sent: u64,
        /// Number of messages received.
        received: u64,
    },
    /// Backpressure not applied when mailbox full.
    BackpressureNotApplied,
}

impl fmt::Display for MailboxViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            MailboxViolationKind::CapacityExceeded { current, capacity } => {
                write!(
                    f,
                    "Actor {:?} mailbox capacity exceeded: {}/{} at {:?}",
                    self.actor, current, capacity, self.time
                )
            }
            MailboxViolationKind::MessageLost { sent, received } => {
                write!(
                    f,
                    "Actor {:?} lost messages: {} sent, {} received at {:?}",
                    self.actor, sent, received, self.time
                )
            }
            MailboxViolationKind::BackpressureNotApplied => {
                write!(
                    f,
                    "Actor {:?} backpressure not applied when mailbox full at {:?}",
                    self.actor, self.time
                )
            }
        }
    }
}

impl std::error::Error for MailboxViolation {}

/// Mailbox statistics for a single actor.
#[derive(Debug, Default)]
struct MailboxStats {
    capacity: usize,
    backpressure_enabled: bool,
    current_size: usize,
    total_sent: u64,
    total_received: u64,
    high_water_mark: usize,
    stopped_at: Option<Time>,
}

/// Oracle for verifying mailbox invariants.
///
/// Tracks message sends and receives to verify:
/// - Capacity limits are respected
/// - No messages are lost
/// - Backpressure is applied correctly
#[derive(Debug, Default)]
pub struct MailboxOracle {
    /// Per-actor mailbox statistics.
    mailboxes: HashMap<ActorId, MailboxStats>,
    /// Detected violations.
    violations: Vec<MailboxViolation>,
}

impl MailboxOracle {
    /// Creates a new mailbox oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure a mailbox for an actor.
    pub fn configure_mailbox(&mut self, actor: ActorId, capacity: usize, backpressure: bool) {
        self.mailboxes.insert(
            actor,
            MailboxStats {
                capacity,
                backpressure_enabled: backpressure,
                ..Default::default()
            },
        );
    }

    /// Records a message send event.
    pub fn on_send(&mut self, actor: ActorId, time: Time) {
        let stats = self.mailboxes.entry(actor).or_default();
        stats.total_sent += 1;
        stats.current_size += 1;

        if stats.current_size > stats.high_water_mark {
            stats.high_water_mark = stats.current_size;
        }

        // Check capacity violation
        if stats.capacity > 0 && stats.current_size > stats.capacity {
            self.violations.push(MailboxViolation {
                kind: MailboxViolationKind::CapacityExceeded {
                    current: stats.current_size,
                    capacity: stats.capacity,
                },
                actor,
                time,
            });
        }
    }

    /// Records a message receive event.
    pub fn on_receive(&mut self, actor: ActorId, _time: Time) {
        let stats = self.mailboxes.entry(actor).or_default();
        stats.total_received += 1;
        stats.current_size = stats.current_size.saturating_sub(1);
    }

    /// Marks an actor as stopped (no further mailbox progress expected).
    pub fn on_stop(&mut self, actor: ActorId, time: Time) {
        let stats = self.mailboxes.entry(actor).or_default();
        stats.stopped_at = Some(time);
    }

    /// Records a backpressure event (sender blocked).
    pub fn on_backpressure(&mut self, actor: ActorId, applied: bool, time: Time) {
        let stats = self.mailboxes.entry(actor).or_default();
        if stats.backpressure_enabled && !applied && stats.current_size >= stats.capacity {
            self.violations.push(MailboxViolation {
                kind: MailboxViolationKind::BackpressureNotApplied,
                actor,
                time,
            });
        }
    }

    /// Verifies the invariants hold.
    pub fn check(&self, now: Time) -> Result<(), MailboxViolation> {
        // Return first recorded violation if any. These correspond to
        // point-in-time safety properties (e.g. capacity/backpressure) and
        // should take precedence in reports and mutation attribution.
        if let Some(violation) = self.violations.first() {
            return Err(violation.clone());
        }

        // Message accounting checks.
        for (&actor, stats) in &self.mailboxes {
            // If an actor is known-stopped, its mailbox must be fully drained.
            if stats.stopped_at.is_some()
                && (stats.current_size != 0 || stats.total_sent != stats.total_received)
            {
                return Err(MailboxViolation {
                    kind: MailboxViolationKind::MessageLost {
                        sent: stats.total_sent,
                        received: stats.total_received,
                    },
                    actor,
                    time: now,
                });
            }

            // If the mailbox is empty, then `sent == received` must hold; otherwise we'd be
            // claiming there are "in-flight" messages without any queued/pending count.
            if stats.current_size == 0 && stats.total_sent != stats.total_received {
                return Err(MailboxViolation {
                    kind: MailboxViolationKind::MessageLost {
                        sent: stats.total_sent,
                        received: stats.total_received,
                    },
                    actor,
                    time: now,
                });
            }
        }

        Ok(())
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.mailboxes.clear();
        self.violations.clear();
    }

    /// Returns statistics for an actor's mailbox.
    #[must_use]
    pub fn stats(&self, actor: ActorId) -> Option<(u64, u64, usize)> {
        self.mailboxes
            .get(&actor)
            .map(|s| (s.total_sent, s.total_received, s.high_water_mark))
    }

    /// Returns the number of tracked mailboxes.
    #[must_use]
    pub fn mailbox_count(&self) -> usize {
        self.mailboxes.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TaskId;
    use crate::util::ArenaIndex;

    fn actor(n: u32) -> ActorId {
        ActorId::from_task(TaskId::from_arena(ArenaIndex::new(n, 0)))
    }

    fn region(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // ActorLeakOracle tests
    mod actor_leak {
        use super::*;

        #[test]
        fn no_actors_passes() {
            init_test("no_actors_passes");
            let oracle = ActorLeakOracle::new();
            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("no_actors_passes");
        }

        #[test]
        fn all_actors_stopped_passes() {
            init_test("all_actors_stopped_passes");
            let mut oracle = ActorLeakOracle::new();

            oracle.on_spawn(actor(1), region(0), t(10));
            oracle.on_spawn(actor(2), region(0), t(20));

            oracle.on_stop(actor(1), t(50));
            oracle.on_stop(actor(2), t(60));

            oracle.on_region_close(region(0), t(100));

            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("all_actors_stopped_passes");
        }

        #[test]
        fn leaked_actor_fails() {
            init_test("leaked_actor_fails");
            let mut oracle = ActorLeakOracle::new();

            oracle.on_spawn(actor(1), region(0), t(10));
            oracle.on_spawn(actor(2), region(0), t(20));

            // Only actor 1 stops
            oracle.on_stop(actor(1), t(50));

            oracle.on_region_close(region(0), t(100));

            let result = oracle.check(t(100));
            let err = result.is_err();
            crate::assert_with_log!(err, "err", true, err);

            let violation = result.unwrap_err();
            crate::assert_with_log!(
                violation.region == region(0),
                "region",
                region(0),
                violation.region
            );
            crate::assert_with_log!(
                violation.leaked_actors == vec![actor(2)],
                "leaked_actors",
                vec![actor(2)],
                violation.leaked_actors
            );
            crate::test_complete!("leaked_actor_fails");
        }

        #[test]
        fn reset_clears_state() {
            init_test("reset_clears_state");
            let mut oracle = ActorLeakOracle::new();

            oracle.on_spawn(actor(1), region(0), t(10));
            oracle.on_region_close(region(0), t(100));

            // Would fail
            let err = oracle.check(t(100)).is_err();
            crate::assert_with_log!(err, "err", true, err);

            oracle.reset();

            // After reset, no violations
            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("reset_clears_state");
        }
    }

    // SupervisionOracle tests
    mod supervision {
        use super::*;

        #[test]
        fn no_failures_passes() {
            init_test("no_failures_passes");
            let oracle = SupervisionOracle::new();
            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("no_failures_passes");
        }

        #[test]
        fn restart_within_limit_passes() {
            init_test("restart_within_limit_passes");
            let mut oracle = SupervisionOracle::new();

            oracle.register_supervisor(
                actor(0),
                RestartPolicy::OneForOne,
                3,
                EscalationPolicy::Escalate,
            );
            oracle.register_child(actor(0), actor(1));

            oracle.on_child_failed(actor(0), actor(1), t(10), "error".into());
            oracle.on_restart(actor(1), 1, t(20));

            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("restart_within_limit_passes");
        }

        #[test]
        fn one_for_all_siblings_restarted_passes() {
            init_test("one_for_all_siblings_restarted_passes");
            let mut oracle = SupervisionOracle::new();

            oracle.register_supervisor(
                actor(0),
                RestartPolicy::OneForAll,
                3,
                EscalationPolicy::Stop,
            );
            oracle.register_child(actor(0), actor(1));
            oracle.register_child(actor(0), actor(2));
            oracle.register_child(actor(0), actor(3));

            // Actor 2 fails
            oracle.on_child_failed(actor(0), actor(2), t(10), "error".into());

            // All siblings restart (including the failed one)
            oracle.on_restart(actor(1), 1, t(20));
            oracle.on_restart(actor(2), 1, t(20));
            oracle.on_restart(actor(3), 1, t(20));

            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("one_for_all_siblings_restarted_passes");
        }

        #[test]
        fn rest_for_one_successors_restarted_passes() {
            init_test("rest_for_one_successors_restarted_passes");
            let mut oracle = SupervisionOracle::new();

            oracle.register_supervisor(
                actor(0),
                RestartPolicy::RestForOne,
                3,
                EscalationPolicy::Stop,
            );
            oracle.register_child(actor(0), actor(1));
            oracle.register_child(actor(0), actor(2));
            oracle.register_child(actor(0), actor(3));

            // Actor 2 fails - actors 2 and 3 should restart
            oracle.on_child_failed(actor(0), actor(2), t(10), "error".into());
            oracle.on_restart(actor(2), 1, t(20));
            oracle.on_restart(actor(3), 1, t(20));

            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("rest_for_one_successors_restarted_passes");
        }

        #[test]
        fn reset_clears_state() {
            init_test("supervision_reset_clears_state");
            let mut oracle = SupervisionOracle::new();

            oracle.register_supervisor(
                actor(0),
                RestartPolicy::OneForOne,
                1,
                EscalationPolicy::Escalate,
            );
            oracle.on_child_failed(actor(0), actor(1), t(10), "error".into());

            oracle.reset();

            let count = oracle.failure_count();
            crate::assert_with_log!(count == 0, "failure_count", 0, count);
            crate::test_complete!("supervision_reset_clears_state");
        }
    }

    // MailboxOracle tests
    mod mailbox {
        use super::*;

        #[test]
        fn no_messages_passes() {
            init_test("no_messages_passes");
            let oracle = MailboxOracle::new();
            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("no_messages_passes");
        }

        #[test]
        fn balanced_send_receive_passes() {
            init_test("balanced_send_receive_passes");
            let mut oracle = MailboxOracle::new();

            oracle.configure_mailbox(actor(1), 10, true);

            oracle.on_send(actor(1), t(10));
            oracle.on_send(actor(1), t(20));
            oracle.on_receive(actor(1), t(30));
            oracle.on_receive(actor(1), t(40));

            let ok = oracle.check(t(100)).is_ok();
            crate::assert_with_log!(ok, "ok", true, ok);
            crate::test_complete!("balanced_send_receive_passes");
        }

        #[test]
        fn capacity_exceeded_fails() {
            init_test("capacity_exceeded_fails");
            let mut oracle = MailboxOracle::new();

            oracle.configure_mailbox(actor(1), 2, false);

            oracle.on_send(actor(1), t(10));
            oracle.on_send(actor(1), t(20));
            oracle.on_send(actor(1), t(30)); // Exceeds capacity

            let result = oracle.check(t(100));
            let err = result.is_err();
            crate::assert_with_log!(err, "err", true, err);
            crate::test_complete!("capacity_exceeded_fails");
        }

        #[test]
        fn tracks_high_water_mark() {
            init_test("tracks_high_water_mark");
            let mut oracle = MailboxOracle::new();

            oracle.configure_mailbox(actor(1), 10, true);

            oracle.on_send(actor(1), t(10));
            oracle.on_send(actor(1), t(20));
            oracle.on_send(actor(1), t(30));
            oracle.on_receive(actor(1), t(40));
            oracle.on_receive(actor(1), t(50));
            oracle.on_receive(actor(1), t(60));

            let stats = oracle.stats(actor(1));
            let hwm = stats.map_or(0, |(_, _, h)| h);
            crate::assert_with_log!(hwm == 3, "high_water_mark", 3, hwm);
            crate::test_complete!("tracks_high_water_mark");
        }

        #[test]
        fn reset_clears_state() {
            init_test("mailbox_reset_clears_state");
            let mut oracle = MailboxOracle::new();

            oracle.configure_mailbox(actor(1), 10, true);
            oracle.on_send(actor(1), t(10));

            oracle.reset();

            let count = oracle.mailbox_count();
            crate::assert_with_log!(count == 0, "mailbox_count", 0, count);
            crate::test_complete!("mailbox_reset_clears_state");
        }

        #[test]
        fn stopped_with_pending_messages_fails() {
            init_test("stopped_with_pending_messages_fails");
            let mut oracle = MailboxOracle::new();

            oracle.configure_mailbox(actor(1), 10, true);
            oracle.on_send(actor(1), t(10));
            oracle.on_stop(actor(1), t(20));

            let result = oracle.check(t(100));
            let err = result.is_err();
            crate::assert_with_log!(err, "err", true, err);

            let violation = result.unwrap_err();
            match violation.kind {
                MailboxViolationKind::MessageLost { sent, received } => {
                    crate::assert_with_log!(sent == 1, "sent", 1, sent);
                    crate::assert_with_log!(received == 0, "received", 0, received);
                }
                other => {
                    crate::assert_with_log!(false, "kind", "MessageLost", other);
                }
            }

            crate::test_complete!("stopped_with_pending_messages_fails");
        }
    }
}
