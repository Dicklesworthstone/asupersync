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
#[path = "ambient_authority_inline_tests.rs"]
mod tests;
