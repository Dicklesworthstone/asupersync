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
        // Sort region keys for deterministic violation selection.
        // HashMap iteration order is non-deterministic and would cause
        // flaky oracle verdicts across runs with identical seeds.
        let mut sorted_regions: Vec<_> = self.region_closes.iter().collect();
        sorted_regions.sort_by_key(|&(&region, _)| region);

        for (&region, &close_time) in sorted_regions {
            let Some(actors) = self.actors_by_region.get(&region) else {
                continue; // No actors spawned in this region
            };

            let mut leaked: Vec<_> = actors
                .iter()
                .copied()
                .filter(|actor| {
                    self.stopped_actors
                        .get(actor)
                        .is_none_or(|t| *t > close_time)
                })
                .collect();
            leaked.sort();

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
    #[allow(dead_code)] // retained for debug diagnostics
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
    _to: ActorId,
    time: Time,
    _reason: String,
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
    }

    /// Records an escalation event.
    pub fn on_escalation(&mut self, from: ActorId, to: ActorId, time: Time, reason: String) {
        self.escalations.push(EscalationEvent {
            from,
            _to: to,
            time,
            _reason: reason,
        });
    }

    /// Verifies the invariants hold.
    pub fn check(&self, _now: Time) -> Result<(), SupervisionViolation> {
        // Check for restart limit violations
        for failure in &self.failures {
            if let Some(config) = self.supervisors.get(&failure.parent) {
                let next_failure_time = self.next_failure_time(failure.parent, failure.time);
                let restart_count =
                    self.restart_attempt_in_window(failure.child, failure.time, next_failure_time);

                // Check if restart limit was exceeded
                let escalated =
                    self.escalated_in_window(failure.parent, failure.time, next_failure_time);
                let failure_ordinal =
                    self.failure_ordinal_for_supervisor(failure.parent, failure.time);

                if restart_count > config.max_restarts {
                    // Verify escalation happened (e.from is parent, not failure.from) and it was NOT restarted.
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
                    continue; // Do not check sibling restarts if we correctly escalated/stopped
                }

                if escalated
                    && config.escalation_policy != EscalationPolicy::Stop
                    && failure_ordinal > config.max_restarts
                {
                    // A supervisor may escalate the failure that would exceed
                    // the restart budget without issuing another restart wave.
                    // Earlier failures still have their own bounded windows
                    // and cannot be masked by this later escalation.
                    continue;
                }

                // br-asupersync-l7ni1s: do NOT short-circuit the
                // sibling-restart check just because *some* escalation
                // happened in this window. A properly-implemented
                // OneForAll/RestForOne supervisor must restart siblings
                // on EVERY failure within max_restarts, AND escalate
                // only after the restart-budget is exhausted (handled
                // above). The previous logic — `if escalated { continue }`
                // here — produced FALSE NEGATIVES: a supervisor that
                // skipped the sibling-restart for failure F2 (after
                // restarting siblings for F1 and then escalating once
                // the joint budget exhausted, with F2 still inside the
                // window) was incorrectly accepted by the oracle. By
                // running the OneForAll/RestForOne check for every
                // failure where the per-failure restart_count is still
                // within budget, we catch supervisors that drop sibling
                // restarts the moment ANY escalation hits the window.

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
                        .filter(|&&s| !self.restarted_in_window(s, failure.time, next_failure_time))
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
                                !self.restarted_in_window(s, failure.time, next_failure_time)
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

    fn next_failure_time(&self, parent: ActorId, failure_time: Time) -> Option<Time> {
        self.failures
            .iter()
            .filter(|failure| failure.parent == parent && failure.time > failure_time)
            .map(|failure| failure.time)
            .min()
    }

    fn event_in_failure_window(
        event_time: Time,
        failure_time: Time,
        next_failure_time: Option<Time>,
    ) -> bool {
        event_time >= failure_time
            && next_failure_time.is_none_or(|next_time| event_time < next_time)
    }

    fn restart_attempt_in_window(
        &self,
        actor: ActorId,
        failure_time: Time,
        next_failure_time: Option<Time>,
    ) -> u32 {
        self.restarts
            .iter()
            .filter(|restart| {
                restart.actor == actor
                    && Self::event_in_failure_window(restart.time, failure_time, next_failure_time)
            })
            .map(|restart| restart.attempt)
            .max()
            .unwrap_or(0)
    }

    fn restarted_in_window(
        &self,
        actor: ActorId,
        failure_time: Time,
        next_failure_time: Option<Time>,
    ) -> bool {
        self.restart_attempt_in_window(actor, failure_time, next_failure_time) > 0
    }

    fn escalated_in_window(
        &self,
        supervisor: ActorId,
        failure_time: Time,
        next_failure_time: Option<Time>,
    ) -> bool {
        self.escalations.iter().any(|escalation| {
            escalation.from == supervisor
                && Self::event_in_failure_window(escalation.time, failure_time, next_failure_time)
        })
    }

    fn failure_ordinal_for_supervisor(&self, supervisor: ActorId, failure_time: Time) -> u32 {
        self.failures
            .iter()
            .filter(|failure| failure.parent == supervisor && failure.time <= failure_time)
            .count()
            .try_into()
            .unwrap_or(u32::MAX)
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
        // Sort mailbox keys for deterministic violation selection.
        let mut sorted_actors: Vec<_> = self.mailboxes.iter().collect();
        sorted_actors.sort_by_key(|&(&actor, _)| actor);
        for (&actor, stats) in sorted_actors {
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
#[path = "actor_inline_tests.rs"]
mod tests;
