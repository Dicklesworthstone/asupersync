//! Ambient authority oracle for verifying invariant #6: no ambient authority.
//!
//! This oracle verifies that all observable effects in the system are traceable
//! to explicit capability grants through the `Cx` context. Tasks cannot perform
//! effects without appropriate capabilities.
//!
//! # Invariant
//!
//! From AGENTS.md:
//! > No ambient authority – effects flow through Cx and explicit capabilities
//!
//! Formally: `∀t ∈ tasks, ∀e ∈ effects(t): e.capability ∈ grants(t)`
//!
//! # Usage
//!
//! ```ignore
//! let mut oracle = AmbientAuthorityOracle::new();
//!
//! // During execution, record events:
//! oracle.on_task_created(task_id, parent_task, time);
//! oracle.on_spawn_effect(task_id, child_id, time);
//! oracle.on_time_access(task_id, time);
//! oracle.on_capability_granted(task_id, CapabilityKind::Spawn, time);
//!
//! // At end of test, verify:
//! oracle.check()?;
//! ```

use crate::types::{RegionId, TaskId, Time};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Kinds of capabilities that can be granted to tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityKind {
    /// Can spawn child tasks.
    Spawn,
    /// Can access time (now, sleep).
    Time,
    /// Can trace/log messages.
    Trace,
    /// Can create regions.
    Region,
    /// Can create obligations.
    Obligation,
    /// Full capabilities (default for root tasks).
    Full,
}

impl fmt::Display for CapabilityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn => write!(f, "spawn"),
            Self::Time => write!(f, "time"),
            Self::Trace => write!(f, "trace"),
            Self::Region => write!(f, "region"),
            Self::Obligation => write!(f, "obligation"),
            Self::Full => write!(f, "full"),
        }
    }
}

/// An effect performed by a task.
#[derive(Debug, Clone)]
pub struct Effect {
    /// The task that performed the effect.
    pub task: TaskId,
    /// The kind of capability required.
    pub required: CapabilityKind,
    /// Description of the effect for error messages.
    pub description: String,
    /// When the effect occurred.
    pub time: Time,
}

/// The set of capabilities granted to a task.
#[derive(Debug, Clone, Default)]
pub struct CapabilitySet {
    /// Individual capabilities granted.
    capabilities: HashSet<CapabilityKind>,
}

impl CapabilitySet {
    /// Creates an empty capability set.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Creates a full capability set (all capabilities).
    #[must_use]
    pub fn full() -> Self {
        let mut caps = Self::empty();
        caps.grant(CapabilityKind::Full);
        caps.grant(CapabilityKind::Spawn);
        caps.grant(CapabilityKind::Time);
        caps.grant(CapabilityKind::Trace);
        caps.grant(CapabilityKind::Region);
        caps.grant(CapabilityKind::Obligation);
        caps
    }

    /// Grants a capability.
    pub fn grant(&mut self, cap: CapabilityKind) {
        self.capabilities.insert(cap);
    }

    /// Revokes a capability.
    ///
    /// When revoking a specific capability from a set that contains `Full`,
    /// `Full` is also removed since the set is no longer complete. The
    /// remaining individual capabilities stay intact.
    pub fn revoke(&mut self, cap: CapabilityKind) {
        self.capabilities.remove(&cap);
        // A specific revocation invalidates the Full meta-capability.
        if cap != CapabilityKind::Full {
            self.capabilities.remove(&CapabilityKind::Full);
        }
    }

    /// Checks if a capability is granted.
    #[must_use]
    pub fn has(&self, cap: CapabilityKind) -> bool {
        // Full capability implies all other capabilities
        self.capabilities.contains(&CapabilityKind::Full) || self.capabilities.contains(&cap)
    }

    /// Returns an iterator over granted capabilities.
    pub fn iter(&self) -> impl Iterator<Item = &CapabilityKind> {
        self.capabilities.iter()
    }
}

#[derive(Debug, Clone)]
struct CapabilitySnapshot {
    time: Time,
    event_sequence: u128,
    capabilities: CapabilitySet,
}

#[derive(Debug, Clone)]
struct RecordedEffect {
    effect: Effect,
    event_sequence: u128,
}

/// An ambient authority violation.
///
/// This indicates that a task performed an effect without the required
/// capability, violating the no-ambient-authority invariant.
#[derive(Debug, Clone)]
pub struct AmbientAuthorityViolation {
    /// The task that violated the invariant.
    pub task: TaskId,
    /// The required capability that was missing.
    pub required_capability: CapabilityKind,
    /// Description of the unauthorized effect.
    pub effect_description: String,
    /// The capabilities the task actually had.
    pub granted_capabilities: Vec<CapabilityKind>,
    /// When the violation occurred.
    pub time: Time,
}

impl fmt::Display for AmbientAuthorityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Task {:?} performed '{}' at {:?} without '{}' capability. \
             Granted: {:?}",
            self.task,
            self.effect_description,
            self.time,
            self.required_capability,
            self.granted_capabilities
        )
    }
}

impl std::error::Error for AmbientAuthorityViolation {}

/// Oracle for detecting ambient authority violations.
///
/// Tracks capability grants and effects to verify that all effects are
/// authorized by explicit capabilities.
#[derive(Debug, Default)]
pub struct AmbientAuthorityOracle {
    /// Capabilities granted to each task.
    capabilities: HashMap<TaskId, CapabilitySet>,
    /// Historical capability snapshots for each task.
    capability_history: HashMap<TaskId, Vec<CapabilitySnapshot>>,
    /// Effects performed by tasks, paired with their event ordering.
    effects: Vec<RecordedEffect>,
    /// Parent task relationships for capability inheritance.
    parent_task: HashMap<TaskId, TaskId>,
    /// Region ownership for tasks.
    task_region: HashMap<TaskId, RegionId>,
    /// Root tasks (have full capabilities by default).
    root_tasks: HashSet<TaskId>,
    /// Monotonic event sequence used to order same-timestamp events.
    next_event_sequence: u128,
}

impl AmbientAuthorityOracle {
    /// Creates a new ambient authority oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn next_sequence(&mut self) -> u128 {
        let sequence = self.next_event_sequence;
        self.next_event_sequence = self
            .next_event_sequence
            .checked_add(1)
            .expect("ambient authority oracle event sequence overflow");
        sequence
    }

    fn snapshot_capabilities(&mut self, task: TaskId, time: Time, event_sequence: u128) {
        let capabilities = self.capabilities.get(&task).cloned().unwrap_or_default();
        self.capability_history
            .entry(task)
            .or_default()
            .push(CapabilitySnapshot {
                time,
                event_sequence,
                capabilities,
            });
    }

    fn capabilities_at(
        &self,
        task: TaskId,
        time: Time,
        event_sequence: u128,
    ) -> Option<&CapabilitySet> {
        self.capability_history.get(&task).and_then(|snapshots| {
            snapshots
                .iter()
                .filter(|snapshot| {
                    snapshot.time < time
                        || (snapshot.time == time && snapshot.event_sequence <= event_sequence)
                })
                .max_by(|a, b| {
                    a.time
                        .cmp(&b.time)
                        .then_with(|| a.event_sequence.cmp(&b.event_sequence))
                })
                .map(|snapshot| &snapshot.capabilities)
        })
    }

    fn record_effect(&mut self, effect: Effect) {
        let event_sequence = self.next_sequence();
        self.effects.push(RecordedEffect {
            effect,
            event_sequence,
        });
    }

    /// Records a task creation event.
    ///
    /// If `parent` is `Some`, the child inherits capabilities from the parent.
    /// If `parent` is `None`, the task is a root task with full capabilities.
    pub fn on_task_created(
        &mut self,
        task: TaskId,
        region: RegionId,
        parent: Option<TaskId>,
        time: Time,
    ) {
        let event_sequence = self.next_sequence();
        self.task_region.insert(task, region);

        if let Some(parent_id) = parent {
            self.parent_task.insert(task, parent_id);
            // Child inherits parent's capabilities by default.
            // If the parent is unknown, grant nothing: missing lineage must
            // never escalate into ambient authority.
            let parent_caps = self
                .capabilities_at(parent_id, time, event_sequence)
                .cloned()
                .unwrap_or_default();
            self.capabilities.insert(task, parent_caps);
        } else {
            // Root task has full capabilities
            self.root_tasks.insert(task);
            self.capabilities.insert(task, CapabilitySet::full());
        }

        self.snapshot_capabilities(task, time, event_sequence);
    }

    /// Grants an explicit capability to a task.
    pub fn on_capability_granted(&mut self, task: TaskId, cap: CapabilityKind, time: Time) {
        let event_sequence = self.next_sequence();
        self.capabilities.entry(task).or_default().grant(cap);
        self.snapshot_capabilities(task, time, event_sequence);
    }

    /// Revokes a capability from a task.
    pub fn on_capability_revoked(&mut self, task: TaskId, cap: CapabilityKind, time: Time) {
        let event_sequence = self.next_sequence();
        if let Some(caps) = self.capabilities.get_mut(&task) {
            caps.revoke(cap);
        }
        self.snapshot_capabilities(task, time, event_sequence);
    }

    /// Records a spawn effect.
    pub fn on_spawn_effect(&mut self, task: TaskId, _child: TaskId, time: Time) {
        self.record_effect(Effect {
            task,
            required: CapabilityKind::Spawn,
            description: "spawn child task".to_string(),
            time,
        });
    }

    /// Records a time access effect (now() or sleep()).
    pub fn on_time_access(&mut self, task: TaskId, time: Time) {
        self.record_effect(Effect {
            task,
            required: CapabilityKind::Time,
            description: "access time".to_string(),
            time,
        });
    }

    /// Records a trace effect.
    pub fn on_trace(&mut self, task: TaskId, message: &str, time: Time) {
        self.record_effect(Effect {
            task,
            required: CapabilityKind::Trace,
            description: format!("trace: {message}"),
            time,
        });
    }

    /// Records a region creation effect.
    pub fn on_region_create(&mut self, task: TaskId, _region: RegionId, time: Time) {
        self.record_effect(Effect {
            task,
            required: CapabilityKind::Region,
            description: "create region".to_string(),
            time,
        });
    }

    /// Records an obligation creation effect.
    pub fn on_obligation_create(
        &mut self,
        task: TaskId,
        _obligation: crate::types::ObligationId,
        time: Time,
    ) {
        self.record_effect(Effect {
            task,
            required: CapabilityKind::Obligation,
            description: "create obligation".to_string(),
            time,
        });
    }

    /// Records a generic effect with a custom description.
    pub fn on_effect(
        &mut self,
        task: TaskId,
        required: CapabilityKind,
        description: &str,
        time: Time,
    ) {
        self.record_effect(Effect {
            task,
            required,
            description: description.to_string(),
            time,
        });
    }

    /// Returns the capabilities granted to a task.
    #[must_use]
    pub fn capabilities_for(&self, task: TaskId) -> Option<&CapabilitySet> {
        self.capabilities.get(&task)
    }

    /// Returns whether a task has a specific capability.
    #[must_use]
    pub fn task_has_capability(&self, task: TaskId, cap: CapabilityKind) -> bool {
        self.capabilities
            .get(&task)
            .is_some_and(|caps| caps.has(cap))
    }

    /// Verifies the invariant holds.
    ///
    /// Checks that for every effect performed, the performing task had the
    /// required capability at the time of the effect.
    ///
    /// # Returns
    /// * `Ok(())` if no violations are found
    /// * `Err(AmbientAuthorityViolation)` if a violation is detected
    pub fn check(&self) -> Result<(), AmbientAuthorityViolation> {
        for recorded in &self.effects {
            let effect = &recorded.effect;
            let caps = self.capabilities_at(effect.task, effect.time, recorded.event_sequence);

            let has_cap = caps.is_some_and(|c| c.has(effect.required));

            if !has_cap {
                let granted: Vec<CapabilityKind> = caps
                    .map(|c| c.iter().copied().collect())
                    .unwrap_or_default();

                return Err(AmbientAuthorityViolation {
                    task: effect.task,
                    required_capability: effect.required,
                    effect_description: effect.description.clone(),
                    granted_capabilities: granted,
                    time: effect.time,
                });
            }
        }

        Ok(())
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.capabilities.clear();
        self.capability_history.clear();
        self.effects.clear();
        self.parent_task.clear();
        self.task_region.clear();
        self.root_tasks.clear();
        self.next_event_sequence = 0;
    }

    /// Returns the number of tracked effects.
    #[must_use]
    pub fn effect_count(&self) -> usize {
        self.effects.len()
    }

    /// Returns the number of tracked tasks.
    #[must_use]
    pub fn task_count(&self) -> usize {
        self.capabilities.len()
    }

    /// Returns the number of root tasks.
    #[must_use]
    pub fn root_task_count(&self) -> usize {
        self.root_tasks.len()
    }
}

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
    use crate::util::ArenaIndex;

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
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

    #[test]
    fn empty_oracle_passes() {
        init_test("empty_oracle_passes");
        let oracle = AmbientAuthorityOracle::new();
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("empty_oracle_passes");
    }

    #[test]
    fn root_task_has_full_capabilities() {
        init_test("root_task_has_full_capabilities");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));

        // Root task should have all capabilities
        let has_spawn = oracle.task_has_capability(task(1), CapabilityKind::Spawn);
        crate::assert_with_log!(has_spawn, "has spawn", true, has_spawn);
        let has_time = oracle.task_has_capability(task(1), CapabilityKind::Time);
        crate::assert_with_log!(has_time, "has time", true, has_time);
        let has_trace = oracle.task_has_capability(task(1), CapabilityKind::Trace);
        crate::assert_with_log!(has_trace, "has trace", true, has_trace);
        let has_region = oracle.task_has_capability(task(1), CapabilityKind::Region);
        crate::assert_with_log!(has_region, "has region", true, has_region);
        let has_obligation = oracle.task_has_capability(task(1), CapabilityKind::Obligation);
        crate::assert_with_log!(has_obligation, "has obligation", true, has_obligation);
        crate::test_complete!("root_task_has_full_capabilities");
    }

    #[test]
    fn child_inherits_parent_capabilities() {
        init_test("child_inherits_parent_capabilities");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_task_created(task(2), region(0), Some(task(1)), t(10));

        // Child should inherit parent's full capabilities
        let has_spawn = oracle.task_has_capability(task(2), CapabilityKind::Spawn);
        crate::assert_with_log!(has_spawn, "child has spawn", true, has_spawn);
        let has_time = oracle.task_has_capability(task(2), CapabilityKind::Time);
        crate::assert_with_log!(has_time, "child has time", true, has_time);
        crate::test_complete!("child_inherits_parent_capabilities");
    }

    #[test]
    fn child_with_missing_parent_has_no_capabilities() {
        init_test("child_with_missing_parent_has_no_capabilities");
        let mut oracle = AmbientAuthorityOracle::new();

        // Parent task(99) was never created.
        oracle.on_task_created(task(2), region(0), Some(task(99)), t(10));

        let has_spawn = oracle.task_has_capability(task(2), CapabilityKind::Spawn);
        crate::assert_with_log!(!has_spawn, "child spawn denied", false, has_spawn);
        let has_time = oracle.task_has_capability(task(2), CapabilityKind::Time);
        crate::assert_with_log!(!has_time, "child time denied", false, has_time);

        // Attempting an effect must be flagged as unauthorized.
        oracle.on_spawn_effect(task(2), task(3), t(20));
        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.task == task(2),
            "violation task",
            task(2),
            violation.task
        );
        let empty = violation.granted_capabilities.is_empty();
        crate::assert_with_log!(empty, "capabilities empty", true, empty);
        crate::test_complete!("child_with_missing_parent_has_no_capabilities");
    }

    #[test]
    fn authorized_spawn_passes() {
        init_test("authorized_spawn_passes");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_spawn_effect(task(1), task(2), t(10));
        oracle.on_task_created(task(2), region(0), Some(task(1)), t(10));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("authorized_spawn_passes");
    }

    #[test]
    fn unauthorized_spawn_fails() {
        init_test("unauthorized_spawn_fails");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));
        oracle.on_capability_revoked(task(1), CapabilityKind::Full, t(5));

        // Now task 1 tries to spawn without capability
        oracle.on_spawn_effect(task(1), task(2), t(10));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.task == task(1),
            "violation task",
            task(1),
            violation.task
        );
        crate::assert_with_log!(
            violation.required_capability == CapabilityKind::Spawn,
            "required capability",
            CapabilityKind::Spawn,
            violation.required_capability
        );
        crate::test_complete!("unauthorized_spawn_fails");
    }

    #[test]
    fn unauthorized_time_access_fails() {
        init_test("unauthorized_time_access_fails");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Time, t(5));
        oracle.on_capability_revoked(task(1), CapabilityKind::Full, t(5));

        oracle.on_time_access(task(1), t(10));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.required_capability == CapabilityKind::Time,
            "required capability",
            CapabilityKind::Time,
            violation.required_capability
        );
        crate::test_complete!("unauthorized_time_access_fails");
    }

    #[test]
    fn regranting_capability_passes() {
        init_test("regranting_capability_passes");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));
        oracle.on_capability_revoked(task(1), CapabilityKind::Full, t(5));
        oracle.on_capability_granted(task(1), CapabilityKind::Spawn, t(8));

        oracle.on_spawn_effect(task(1), task(2), t(10));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("regranting_capability_passes");
    }

    #[test]
    fn later_grant_does_not_retroactively_authorize_effect() {
        init_test("later_grant_does_not_retroactively_authorize_effect");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));
        oracle.on_spawn_effect(task(1), task(2), t(10));
        oracle.on_capability_granted(task(1), CapabilityKind::Spawn, t(20));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.time == t(10),
            "violation time",
            t(10),
            violation.time
        );
        crate::test_complete!("later_grant_does_not_retroactively_authorize_effect");
    }

    #[test]
    fn later_revoke_does_not_retroactively_invalidate_effect() {
        init_test("later_revoke_does_not_retroactively_invalidate_effect");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_spawn_effect(task(1), task(2), t(10));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(20));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("later_revoke_does_not_retroactively_invalidate_effect");
    }

    #[test]
    fn capability_lookup_uses_latest_timestamp_not_insertion_order() {
        init_test("capability_lookup_uses_latest_timestamp_not_insertion_order");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_granted(task(1), CapabilityKind::Spawn, t(8));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));
        oracle.on_spawn_effect(task(1), task(2), t(10));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("capability_lookup_uses_latest_timestamp_not_insertion_order");
    }

    #[test]
    fn child_inheritance_uses_parent_capabilities_at_child_creation_time() {
        init_test("child_inheritance_uses_parent_capabilities_at_child_creation_time");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(20));
        oracle.on_task_created(task(2), region(0), Some(task(1)), t(10));
        oracle.on_spawn_effect(task(2), task(3), t(15));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("child_inheritance_uses_parent_capabilities_at_child_creation_time");
    }

    #[test]
    fn later_parent_grant_does_not_retroactively_authorize_child_inheritance() {
        init_test("later_parent_grant_does_not_retroactively_authorize_child_inheritance");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));
        oracle.on_capability_granted(task(1), CapabilityKind::Spawn, t(20));
        oracle.on_task_created(task(2), region(0), Some(task(1)), t(10));
        oracle.on_spawn_effect(task(2), task(3), t(15));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.task == task(2),
            "violation task",
            task(2),
            violation.task
        );
        crate::assert_with_log!(
            violation.required_capability == CapabilityKind::Spawn,
            "required capability",
            CapabilityKind::Spawn,
            violation.required_capability
        );
        crate::test_complete!(
            "later_parent_grant_does_not_retroactively_authorize_child_inheritance"
        );
    }

    #[test]
    fn unknown_task_fails() {
        init_test("unknown_task_fails");
        let mut oracle = AmbientAuthorityOracle::new();

        // Task 1 never created, tries to spawn
        oracle.on_spawn_effect(task(1), task(2), t(10));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.task == task(1),
            "violation task",
            task(1),
            violation.task
        );
        let empty = violation.granted_capabilities.is_empty();
        crate::assert_with_log!(empty, "capabilities empty", true, empty);
        crate::test_complete!("unknown_task_fails");
    }

    #[test]
    fn multiple_effects_all_authorized() {
        init_test("multiple_effects_all_authorized");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));

        oracle.on_spawn_effect(task(1), task(2), t(10));
        oracle.on_time_access(task(1), t(20));
        oracle.on_trace(task(1), "hello", t(30));
        oracle.on_region_create(task(1), region(1), t(40));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        let count = oracle.effect_count();
        crate::assert_with_log!(count == 4, "effect count", 4, count);
        crate::test_complete!("multiple_effects_all_authorized");
    }

    #[test]
    fn child_with_narrowed_capabilities() {
        init_test("child_with_narrowed_capabilities");
        let mut oracle = AmbientAuthorityOracle::new();

        // Parent with full capabilities
        oracle.on_task_created(task(1), region(0), None, t(0));

        // Child inherits, then narrows
        oracle.on_task_created(task(2), region(0), Some(task(1)), t(10));
        oracle.on_capability_revoked(task(2), CapabilityKind::Spawn, t(15));
        oracle.on_capability_revoked(task(2), CapabilityKind::Full, t(15));

        // Child tries to spawn - should fail
        oracle.on_spawn_effect(task(2), task(3), t(20));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.task == task(2),
            "violation task",
            task(2),
            violation.task
        );
        crate::test_complete!("child_with_narrowed_capabilities");
    }

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));
        oracle.on_capability_revoked(task(1), CapabilityKind::Full, t(5));
        oracle.on_spawn_effect(task(1), task(2), t(10));

        // Would fail
        let err = oracle.check().is_err();
        crate::assert_with_log!(err, "oracle err", true, err);

        oracle.reset();

        // After reset, no violations (no effects tracked)
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        let effect_count = oracle.effect_count();
        crate::assert_with_log!(effect_count == 0, "effect count", 0, effect_count);
        let task_count = oracle.task_count();
        crate::assert_with_log!(task_count == 0, "task count", 0, task_count);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn capability_set_full_implies_all() {
        init_test("capability_set_full_implies_all");
        let full = CapabilitySet::full();

        let has_spawn = full.has(CapabilityKind::Spawn);
        crate::assert_with_log!(has_spawn, "has spawn", true, has_spawn);
        let has_time = full.has(CapabilityKind::Time);
        crate::assert_with_log!(has_time, "has time", true, has_time);
        let has_trace = full.has(CapabilityKind::Trace);
        crate::assert_with_log!(has_trace, "has trace", true, has_trace);
        let has_region = full.has(CapabilityKind::Region);
        crate::assert_with_log!(has_region, "has region", true, has_region);
        let has_obligation = full.has(CapabilityKind::Obligation);
        crate::assert_with_log!(has_obligation, "has obligation", true, has_obligation);
        let has_full = full.has(CapabilityKind::Full);
        crate::assert_with_log!(has_full, "has full", true, has_full);
        crate::test_complete!("capability_set_full_implies_all");
    }

    #[test]
    fn capability_set_individual_grants() {
        init_test("capability_set_individual_grants");
        let mut caps = CapabilitySet::empty();

        let has_spawn = caps.has(CapabilityKind::Spawn);
        crate::assert_with_log!(!has_spawn, "spawn missing", false, has_spawn);

        caps.grant(CapabilityKind::Spawn);
        let has_spawn = caps.has(CapabilityKind::Spawn);
        crate::assert_with_log!(has_spawn, "spawn granted", true, has_spawn);
        let has_time = caps.has(CapabilityKind::Time);
        crate::assert_with_log!(!has_time, "time missing", false, has_time);

        caps.grant(CapabilityKind::Time);
        let has_time = caps.has(CapabilityKind::Time);
        crate::assert_with_log!(has_time, "time granted", true, has_time);

        caps.revoke(CapabilityKind::Spawn);
        let has_spawn = caps.has(CapabilityKind::Spawn);
        crate::assert_with_log!(!has_spawn, "spawn revoked", false, has_spawn);
        let has_time = caps.has(CapabilityKind::Time);
        crate::assert_with_log!(has_time, "time still", true, has_time);
        crate::test_complete!("capability_set_individual_grants");
    }

    #[test]
    fn revoke_clears_full_meta_capability() {
        init_test("revoke_clears_full_meta_capability");
        let mut caps = CapabilitySet::full();

        // Full set implies Spawn
        let has_spawn = caps.has(CapabilityKind::Spawn);
        crate::assert_with_log!(has_spawn, "spawn via full", true, has_spawn);

        // Revoke Spawn — should also clear Full
        caps.revoke(CapabilityKind::Spawn);
        let has_spawn = caps.has(CapabilityKind::Spawn);
        crate::assert_with_log!(!has_spawn, "spawn revoked", false, has_spawn);
        let has_full = caps.has(CapabilityKind::Full);
        crate::assert_with_log!(!has_full, "full cleared", false, has_full);

        // Other individual capabilities remain
        let has_time = caps.has(CapabilityKind::Time);
        crate::assert_with_log!(has_time, "time remains", true, has_time);
        let has_trace = caps.has(CapabilityKind::Trace);
        crate::assert_with_log!(has_trace, "trace remains", true, has_trace);
        let has_region = caps.has(CapabilityKind::Region);
        crate::assert_with_log!(has_region, "region remains", true, has_region);
        let has_obligation = caps.has(CapabilityKind::Obligation);
        crate::assert_with_log!(has_obligation, "obligation remains", true, has_obligation);
        crate::test_complete!("revoke_clears_full_meta_capability");
    }

    #[test]
    fn revoke_full_directly_leaves_individual_caps() {
        init_test("revoke_full_directly_leaves_individual_caps");
        let mut caps = CapabilitySet::full();

        // Revoke Full directly — individual caps still present
        caps.revoke(CapabilityKind::Full);
        let has_full = caps.has(CapabilityKind::Full);
        crate::assert_with_log!(!has_full, "full revoked", false, has_full);
        let has_spawn = caps.has(CapabilityKind::Spawn);
        crate::assert_with_log!(has_spawn, "spawn remains", true, has_spawn);
        let has_time = caps.has(CapabilityKind::Time);
        crate::assert_with_log!(has_time, "time remains", true, has_time);
        crate::test_complete!("revoke_full_directly_leaves_individual_caps");
    }

    #[test]
    fn revoke_from_full_then_oracle_detects_violation() {
        init_test("revoke_from_full_then_oracle_detects_violation");
        let mut oracle = AmbientAuthorityOracle::new();

        // Root task with full capabilities
        oracle.on_task_created(task(1), region(0), None, t(0));

        // Revoke only Spawn (Full should also be cleared internally)
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));

        // Attempt spawn — should fail
        oracle.on_spawn_effect(task(1), task(2), t(10));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "violation detected", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.required_capability == CapabilityKind::Spawn,
            "required spawn",
            CapabilityKind::Spawn,
            violation.required_capability
        );
        crate::test_complete!("revoke_from_full_then_oracle_detects_violation");
    }

    #[test]
    fn violation_display() {
        init_test("violation_display");
        let violation = AmbientAuthorityViolation {
            task: task(1),
            required_capability: CapabilityKind::Spawn,
            effect_description: "spawn child task".to_string(),
            granted_capabilities: vec![CapabilityKind::Time, CapabilityKind::Trace],
            time: t(100),
        };

        let s = violation.to_string();
        let has_spawn = s.contains("spawn");
        crate::assert_with_log!(has_spawn, "contains spawn", true, has_spawn);
        let has_time = s.contains("Time");
        crate::assert_with_log!(has_time, "contains Time", true, has_time);
        crate::test_complete!("violation_display");
    }

    #[test]
    fn generic_effect_tracking() {
        init_test("generic_effect_tracking");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_effect(
            task(1),
            CapabilityKind::Time,
            "custom time operation",
            t(10),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        let count = oracle.effect_count();
        crate::assert_with_log!(count == 1, "effect count", 1, count);
        crate::test_complete!("generic_effect_tracking");
    }

    #[test]
    fn multiple_tasks_independent() {
        init_test("multiple_tasks_independent");
        let mut oracle = AmbientAuthorityOracle::new();

        // Task 1: full capabilities
        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_spawn_effect(task(1), task(3), t(10));

        // Task 2: no spawn capability
        oracle.on_task_created(task(2), region(0), None, t(5));
        oracle.on_capability_revoked(task(2), CapabilityKind::Spawn, t(6));
        oracle.on_capability_revoked(task(2), CapabilityKind::Full, t(6));
        // Task 2 does NOT spawn, so no violation

        // Task 2 does access time (which it still has)
        oracle.on_time_access(task(2), t(15));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("multiple_tasks_independent");
    }
}
