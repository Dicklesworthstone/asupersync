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
    pub fn revoke(&mut self, cap: CapabilityKind) {
        self.capabilities.remove(&cap);
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
    /// Effects performed by tasks.
    effects: Vec<Effect>,
    /// Parent task relationships for capability inheritance.
    parent_task: HashMap<TaskId, TaskId>,
    /// Region ownership for tasks.
    task_region: HashMap<TaskId, RegionId>,
    /// Root tasks (have full capabilities by default).
    root_tasks: HashSet<TaskId>,
}

impl AmbientAuthorityOracle {
    /// Creates a new ambient authority oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        _time: Time,
    ) {
        self.task_region.insert(task, region);

        if let Some(parent_id) = parent {
            self.parent_task.insert(task, parent_id);
            // Child inherits parent's capabilities by default
            let parent_caps = self
                .capabilities
                .get(&parent_id)
                .cloned()
                .unwrap_or_else(CapabilitySet::full);
            self.capabilities.insert(task, parent_caps);
        } else {
            // Root task has full capabilities
            self.root_tasks.insert(task);
            self.capabilities.insert(task, CapabilitySet::full());
        }
    }

    /// Grants an explicit capability to a task.
    pub fn on_capability_granted(&mut self, task: TaskId, cap: CapabilityKind, _time: Time) {
        self.capabilities.entry(task).or_default().grant(cap);
    }

    /// Revokes a capability from a task.
    pub fn on_capability_revoked(&mut self, task: TaskId, cap: CapabilityKind, _time: Time) {
        if let Some(caps) = self.capabilities.get_mut(&task) {
            caps.revoke(cap);
        }
    }

    /// Records a spawn effect.
    pub fn on_spawn_effect(&mut self, task: TaskId, _child: TaskId, time: Time) {
        self.effects.push(Effect {
            task,
            required: CapabilityKind::Spawn,
            description: "spawn child task".to_string(),
            time,
        });
    }

    /// Records a time access effect (now() or sleep()).
    pub fn on_time_access(&mut self, task: TaskId, time: Time) {
        self.effects.push(Effect {
            task,
            required: CapabilityKind::Time,
            description: "access time".to_string(),
            time,
        });
    }

    /// Records a trace effect.
    pub fn on_trace(&mut self, task: TaskId, message: &str, time: Time) {
        self.effects.push(Effect {
            task,
            required: CapabilityKind::Trace,
            description: format!("trace: {message}"),
            time,
        });
    }

    /// Records a region creation effect.
    pub fn on_region_create(&mut self, task: TaskId, _region: RegionId, time: Time) {
        self.effects.push(Effect {
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
        self.effects.push(Effect {
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
        self.effects.push(Effect {
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
        for effect in &self.effects {
            let caps = self.capabilities.get(&effect.task);

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
        self.effects.clear();
        self.parent_task.clear();
        self.task_region.clear();
        self.root_tasks.clear();
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
