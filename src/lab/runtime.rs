//! Lab runtime for deterministic execution.
//!
//! The lab runtime executes tasks with:
//! - Virtual time (controlled advancement)
//! - Deterministic scheduling (seed-driven)
//! - Trace capture for replay

use super::config::LabConfig;
use crate::record::ObligationKind;
use crate::runtime::RuntimeState;
use crate::trace::event::TraceEventKind;
use crate::trace::TraceBuffer;
use crate::trace::{TraceData, TraceEvent};
use crate::types::ObligationId;
use crate::types::Time;
use crate::util::DetRng;

/// The deterministic lab runtime.
///
/// This runtime is designed for testing and provides:
/// - Virtual time instead of wall-clock time
/// - Deterministic scheduling based on a seed
/// - Trace capture for debugging and replay
#[derive(Debug)]
pub struct LabRuntime {
    /// Runtime state (public for tests and oracle access).
    pub state: RuntimeState,
    /// Configuration.
    config: LabConfig,
    /// Deterministic RNG.
    rng: DetRng,
    /// Current virtual time.
    virtual_time: Time,
    /// Number of steps executed.
    steps: u64,
}

impl LabRuntime {
    /// Creates a new lab runtime with the given configuration.
    #[must_use]
    pub fn new(config: LabConfig) -> Self {
        let rng = config.rng();
        let mut state = RuntimeState::new();
        state.trace = TraceBuffer::new(config.trace_capacity);
        Self {
            state,
            config,
            rng,
            virtual_time: Time::ZERO,
            steps: 0,
        }
    }

    /// Creates a lab runtime with the default configuration.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self::new(LabConfig::new(seed))
    }

    /// Returns the current virtual time.
    #[must_use]
    pub const fn now(&self) -> Time {
        self.virtual_time
    }

    /// Returns the number of steps executed.
    #[must_use]
    pub const fn steps(&self) -> u64 {
        self.steps
    }

    /// Returns a reference to the configuration.
    #[must_use]
    pub const fn config(&self) -> &LabConfig {
        &self.config
    }

    /// Returns a reference to the trace buffer.
    #[must_use]
    pub fn trace(&self) -> &TraceBuffer {
        &self.state.trace
    }

    /// Returns true if the runtime is quiescent.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.state.is_quiescent()
    }

    /// Advances virtual time by the given number of nanoseconds.
    pub fn advance_time(&mut self, nanos: u64) {
        self.virtual_time = self.virtual_time.saturating_add_nanos(nanos);
        self.state.now = self.virtual_time;
    }

    /// Advances time to the given absolute time.
    pub fn advance_time_to(&mut self, time: Time) {
        if time > self.virtual_time {
            self.virtual_time = time;
            self.state.now = self.virtual_time;
        }
    }

    /// Runs until quiescent or max steps reached.
    ///
    /// Returns the number of steps executed.
    pub fn run_until_quiescent(&mut self) -> u64 {
        let start_steps = self.steps;

        while !self.is_quiescent() {
            if let Some(max) = self.config.max_steps {
                if self.steps >= max {
                    break;
                }
            }
            self.step();
        }

        self.steps - start_steps
    }

    /// Executes a single step.
    fn step(&mut self) {
        self.steps += 1;
        // Consume RNG state so schedule tie-breaking is deterministic once we
        // start making scheduler decisions here.
        let _ = self.rng.next_u64();
        self.check_futurelocks();
        // In the full implementation, this would:
        // 1. Pop a task from the scheduler
        // 2. Poll it
        // 3. Handle completion/continuation
        // 4. Update state
    }

    /// Public wrapper for `step()` for use in tests.
    ///
    /// This is useful for testing determinism across multiple step executions.
    pub fn step_for_test(&mut self) {
        self.step();
    }

    /// Checks invariants and returns any violations.
    #[must_use]
    pub fn check_invariants(&self) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();

        // Check for obligation leaks
        let leaks = self.obligation_leaks();
        if !leaks.is_empty() {
            violations.push(InvariantViolation::ObligationLeak { leaks });
        }

        violations.extend(self.futurelock_violations());
        violations
    }

    fn obligation_leaks(&self) -> Vec<ObligationLeak> {
        let mut leaks = Vec::new();

        for (_, obligation) in self.state.obligations.iter() {
            if !obligation.is_pending() {
                continue;
            }

            let holder_terminal = self
                .state
                .tasks
                .get(obligation.holder.arena_index())
                .is_none_or(|t| t.state.is_terminal());
            let region_closed = self
                .state
                .regions
                .get(obligation.region.arena_index())
                .is_none_or(|r| r.state.is_terminal());

            if holder_terminal || region_closed {
                leaks.push(ObligationLeak {
                    obligation: obligation.id,
                    kind: obligation.kind,
                    holder: obligation.holder,
                    region: obligation.region,
                });
            }
        }

        leaks
    }

    fn futurelock_violations(&self) -> Vec<InvariantViolation> {
        let threshold = self.config.futurelock_max_idle_steps;
        if threshold == 0 {
            return Vec::new();
        }

        let current_step = self.steps;
        let mut violations = Vec::new();

        for (_, task) in self.state.tasks.iter() {
            if task.state.is_terminal() {
                continue;
            }

            let mut held = Vec::new();
            for (_, obligation) in self.state.obligations.iter() {
                if obligation.is_pending() && obligation.holder == task.id {
                    held.push(obligation.id);
                }
            }

            if held.is_empty() {
                continue;
            }

            let idle_steps = current_step.saturating_sub(task.last_polled_step);
            if idle_steps > threshold {
                violations.push(InvariantViolation::Futurelock {
                    task: task.id,
                    region: task.owner,
                    idle_steps,
                    held,
                });
            }
        }

        violations
    }

    fn check_futurelocks(&mut self) {
        let violations = self.futurelock_violations();
        if violations.is_empty() {
            return;
        }

        for v in violations {
            let InvariantViolation::Futurelock {
                task,
                region,
                idle_steps,
                held,
            } = v
            else {
                continue;
            };

            let mut held_kinds = Vec::new();
            for oid in &held {
                for (_, obligation) in self.state.obligations.iter() {
                    if obligation.id == *oid {
                        held_kinds.push((obligation.id, obligation.kind));
                        break;
                    }
                }
            }

            let seq = self.state.next_trace_seq();
            self.state.trace.push(TraceEvent::new(
                seq,
                self.virtual_time,
                TraceEventKind::FuturelockDetected,
                TraceData::Futurelock {
                    task,
                    region,
                    idle_steps,
                    held: held_kinds,
                },
            ));

            assert!(
                !self.config.panic_on_futurelock,
                "futurelock detected: {task} in {region} idle={idle_steps} held={held:?}"
            );
        }
    }
}

/// An invariant violation detected by the lab runtime.
#[derive(Debug, Clone)]
pub enum InvariantViolation {
    /// Obligations were not resolved.
    ObligationLeak {
        /// Leaked obligations and diagnostic metadata.
        leaks: Vec<ObligationLeak>,
    },
    /// Tasks were not drained.
    TaskLeak {
        /// Number of leaked tasks.
        count: usize,
    },
    /// A region closed with live children.
    QuiescenceViolation,
    /// A task held obligations but stopped being polled (futurelock).
    Futurelock {
        /// The task that futurelocked.
        task: crate::types::TaskId,
        /// The owning region.
        region: crate::types::RegionId,
        /// How many lab steps since last poll.
        idle_steps: u64,
        /// Held obligations.
        held: Vec<ObligationId>,
    },
}

/// Diagnostic details for a leaked obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationLeak {
    /// The leaked obligation id.
    pub obligation: ObligationId,
    /// Kind of obligation (permit/ack/lease/io).
    pub kind: ObligationKind,
    /// Task that held the obligation.
    pub holder: crate::types::TaskId,
    /// Region that owned the obligation.
    pub region: crate::types::RegionId,
}

impl std::fmt::Display for ObligationLeak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} {:?} holder={:?} region={:?}",
            self.obligation, self.kind, self.holder, self.region
        )
    }
}

impl std::fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObligationLeak { leaks } => {
                write!(f, "{} obligations leaked", leaks.len())
            }
            Self::TaskLeak { count } => write!(f, "{count} tasks leaked"),
            Self::QuiescenceViolation => write!(f, "region closed without quiescence"),
            Self::Futurelock {
                task,
                region,
                idle_steps,
                held,
            } => write!(
                f,
                "futurelock: {task} in {region} idle={idle_steps} held={held:?}"
            ),
        }
    }
}

/// Convenience function for running a test with the lab runtime.
pub fn test<F, R>(seed: u64, f: F) -> R
where
    F: FnOnce(&mut LabRuntime) -> R,
{
    let mut runtime = LabRuntime::with_seed(seed);
    let result = f(&mut runtime);

    // Check invariants
    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "Lab runtime invariant violations: {violations:?}"
    );

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::TaskRecord;
    use crate::record::{ObligationKind, ObligationRecord};
    use crate::types::{Budget, ObligationId, Outcome, TaskId};
    use crate::util::ArenaIndex;

    #[test]
    fn empty_runtime_is_quiescent() {
        let runtime = LabRuntime::with_seed(42);
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn advance_time() {
        let mut runtime = LabRuntime::with_seed(42);
        assert_eq!(runtime.now(), Time::ZERO);

        runtime.advance_time(1_000_000);
        assert_eq!(runtime.now(), Time::from_millis(1));
    }

    #[test]
    fn deterministic_rng() {
        let mut r1 = LabRuntime::with_seed(42);
        let mut r2 = LabRuntime::with_seed(42);

        assert_eq!(r1.rng.next_u64(), r2.rng.next_u64());
    }

    #[test]
    fn futurelock_emits_trace_event() {
        let config = LabConfig::new(42)
            .futurelock_max_idle_steps(3)
            .panic_on_futurelock(false);
        let mut runtime = LabRuntime::new(config);

        let root = runtime.state.create_root_region(Budget::INFINITE);

        // Create a task.
        let task_idx = runtime.state.tasks.insert(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.tasks.get_mut(task_idx).unwrap().id = task_id;

        // Create a pending obligation held by that task.
        let obl_idx = runtime.state.obligations.insert(ObligationRecord::new(
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            ObligationKind::SendPermit,
            task_id,
            root,
        ));
        let obl_id = ObligationId::from_arena(obl_idx);
        runtime.state.obligations.get_mut(obl_idx).unwrap().id = obl_id;

        for _ in 0..4 {
            runtime.step();
        }

        let futurelock = runtime
            .trace()
            .iter()
            .find(|e| e.kind == TraceEventKind::FuturelockDetected)
            .expect("expected futurelock trace event");

        match &futurelock.data {
            TraceData::Futurelock {
                task,
                region,
                idle_steps,
                held,
            } => {
                assert_eq!(*task, task_id);
                assert_eq!(*region, root);
                assert!(*idle_steps > 3);
                assert_eq!(held.as_slice(), &[(obl_id, ObligationKind::SendPermit)]);
            }
            other => panic!("unexpected trace data: {other:?}"),
        }
    }

    #[test]
    #[should_panic(expected = "futurelock detected")]
    fn futurelock_can_panic() {
        let config = LabConfig::new(42).futurelock_max_idle_steps(1);
        let mut runtime = LabRuntime::new(config);

        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.tasks.insert(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.tasks.get_mut(task_idx).unwrap().id = task_id;

        let obl_idx = runtime.state.obligations.insert(ObligationRecord::new(
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            ObligationKind::SendPermit,
            task_id,
            root,
        ));
        let obl_id = ObligationId::from_arena(obl_idx);
        runtime.state.obligations.get_mut(obl_idx).unwrap().id = obl_id;

        // Run enough steps to exceed threshold and trigger panic.
        for _ in 0..3 {
            runtime.step();
        }
    }

    #[test]
    fn obligation_leak_detected_when_holder_completed() {
        let mut runtime = LabRuntime::with_seed(7);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.tasks.insert(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.tasks.get_mut(task_idx).unwrap().id = task_id;

        let obl_idx = runtime.state.obligations.insert(ObligationRecord::new(
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            ObligationKind::SendPermit,
            task_id,
            root,
        ));
        let obl_id = ObligationId::from_arena(obl_idx);
        runtime.state.obligations.get_mut(obl_idx).unwrap().id = obl_id;

        runtime
            .state
            .tasks
            .get_mut(task_idx)
            .unwrap()
            .complete(Outcome::Ok(()));

        let violations = runtime.check_invariants();
        let mut found = false;
        for violation in violations {
            if let InvariantViolation::ObligationLeak { leaks } = violation {
                found = true;
                assert_eq!(leaks.len(), 1);
                let leak = &leaks[0];
                assert_eq!(leak.obligation, obl_id);
                assert_eq!(leak.kind, ObligationKind::SendPermit);
                assert_eq!(leak.holder, task_id);
                assert_eq!(leak.region, root);
            }
        }
        assert!(found, "expected obligation leak violation");
    }

    #[test]
    fn obligation_leak_ignored_when_resolved() {
        let mut runtime = LabRuntime::with_seed(11);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.tasks.insert(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.tasks.get_mut(task_idx).unwrap().id = task_id;

        let obl_idx = runtime.state.obligations.insert(ObligationRecord::new(
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            ObligationKind::Ack,
            task_id,
            root,
        ));
        let obl_id = ObligationId::from_arena(obl_idx);
        runtime.state.obligations.get_mut(obl_idx).unwrap().id = obl_id;

        runtime.state.obligations.get_mut(obl_idx).unwrap().commit();

        runtime
            .state
            .tasks
            .get_mut(task_idx)
            .unwrap()
            .complete(Outcome::Ok(()));

        let violations = runtime.check_invariants();
        assert!(
            !violations
                .iter()
                .any(|v| matches!(v, InvariantViolation::ObligationLeak { .. })),
            "resolved obligations should not report leaks"
        );
    }
}
