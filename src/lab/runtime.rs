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
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

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
    /// Scheduler.
    pub scheduler: Arc<Mutex<crate::runtime::scheduler::PriorityScheduler>>,
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
            scheduler: Arc::new(Mutex::new(crate::runtime::scheduler::PriorityScheduler::new())),
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

        // 1. Pop a task from the scheduler
        let Some(task_id) = self.scheduler.lock().unwrap().pop() else {
            return;
        };

        // 2. Prepare context
        let priority = self
            .state
            .tasks
            .get(task_id.arena_index())
            .and_then(|t| t.cx_inner.as_ref())
            .map(|inner| inner.read().expect("lock poisoned").budget.priority)
            .unwrap_or(0);

        let waker = Waker::from(Arc::new(TaskWaker {
            task_id,
            priority,
            scheduler: self.scheduler.clone(),
        }));
        let mut cx = Context::from_waker(&waker);

        // 3. Poll the task
        let result = if let Some(stored) = self.state.get_stored_future(task_id) {
            stored.poll(&mut cx)
        } else {
            // Task lost (should not happen if consistent)
            return;
        };

        // 4. Handle result
        match result {
            Poll::Ready(()) => {
                // Task completed
                self.state.remove_stored_future(task_id);

                // Update state to Completed if not already terminal
                if let Some(record) = self.state.tasks.get_mut(task_id.arena_index()) {
                    if !record.state.is_terminal() {
                        record.state = crate::record::task::TaskState::Completed(
                            crate::types::Outcome::Ok(()),
                        );
                    }
                }

                // Notify waiters
                let waiters = self.state.task_completed(task_id);

                // Schedule waiters
                let mut sched = self.scheduler.lock().unwrap();
                for waiter in waiters {
                    let prio = self
                        .state
                        .tasks
                        .get(waiter.arena_index())
                        .and_then(|t| t.cx_inner.as_ref())
                        .map(|inner| inner.read().expect("lock poisoned").budget.priority)
                        .unwrap_or(0);
                    sched.schedule(waiter, prio);
                }
            }
            Poll::Pending => {
                // Task yielded. Waker will reschedule it when ready.
                // Note: If the task yielded via `cx.waker().wake_by_ref()`, it might already be scheduled.
                // If it yielded for I/O or other events, it won't be scheduled until that event fires.
            }
        }
    }

    /// Public wrapper for `step()` for use in tests.
    ///
    /// This is useful for testing determinism across multiple step executions.
    pub fn step_for_test(&mut self) {
        self.step();
    }

    /// Checks invariants and returns any violations.
    #[must_use]
    pub fn check_invariants(&mut self) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();

        // Check for obligation leaks
        let leaks = self.obligation_leaks();
        if !leaks.is_empty() {
            for leak in &leaks {
                let _ = self.state.mark_obligation_leaked(leak.obligation);
            }
            violations.push(InvariantViolation::ObligationLeak { leaks });
        }

        violations.extend(self.futurelock_violations());
        violations.extend(self.quiescence_violations());

        // Check for task leaks (non-terminal tasks)
        let task_leak_count = self.task_leaks();
        if task_leak_count > 0 {
            violations.push(InvariantViolation::TaskLeak {
                count: task_leak_count,
            });
        }

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
                .is_none_or(|r| r.state().is_terminal());

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

    fn task_leaks(&self) -> usize {
        self.state
            .tasks
            .iter()
            .filter(|(_, t)| !t.state.is_terminal())
            .count()
    }

    fn quiescence_violations(&self) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();
        for (_, region) in self.state.regions.iter() {
            if region.state().is_terminal() {
                // Check if any children or tasks are NOT terminal
                let live_tasks = region.task_ids().iter().any(|&tid| {
                    self.state
                        .tasks
                        .get(tid.arena_index())
                        .is_some_and(|t| !t.state.is_terminal())
                });

                let live_children = region.child_ids().iter().any(|&rid| {
                    self.state
                        .regions
                        .get(rid.arena_index())
                        .is_some_and(|r| !r.state().is_terminal())
                });

                if live_tasks || live_children {
                    violations.push(InvariantViolation::QuiescenceViolation);
                }
            }
        }
        violations
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

struct TaskWaker {
    task_id: crate::types::TaskId,
    priority: u8,
    scheduler: Arc<Mutex<crate::runtime::scheduler::PriorityScheduler>>,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.scheduler
            .lock()
            .unwrap()
            .schedule(self.task_id, self.priority);
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
    use crate::record::{ObligationAbortReason, ObligationKind, ObligationRecord};
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
            runtime.state.now,
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
            runtime.state.now,
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
            runtime.state.now,
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
            runtime.state.now,
        ));
        let obl_id = ObligationId::from_arena(obl_idx);
        runtime.state.obligations.get_mut(obl_idx).unwrap().id = obl_id;

        runtime
            .state
            .obligations
            .get_mut(obl_idx)
            .unwrap()
            .commit(runtime.state.now);

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

    #[test]
    fn obligation_trace_events_emitted() {
        let mut runtime = LabRuntime::with_seed(21);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.tasks.insert(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.tasks.get_mut(task_idx).unwrap().id = task_id;

        runtime.advance_time_to(Time::from_nanos(10));
        let ob1 = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None);

        runtime.advance_time_to(Time::from_nanos(25));
        runtime.state.commit_obligation(ob1).unwrap();

        runtime.advance_time_to(Time::from_nanos(30));
        let ob2 =
            runtime
                .state
                .create_obligation(ObligationKind::Ack, task_id, root, None);

        runtime.advance_time_to(Time::from_nanos(50));
        runtime
            .state
            .abort_obligation(ob2, ObligationAbortReason::Cancel)
            .unwrap();

        let commit_event = runtime
            .trace()
            .iter()
            .find(|e| e.kind == TraceEventKind::ObligationCommit)
            .expect("commit event");
        match &commit_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                assert_eq!(*obligation, ob1);
                assert_eq!(*task, task_id);
                assert_eq!(*region, root);
                assert_eq!(*kind, ObligationKind::SendPermit);
                assert_eq!(*state, crate::record::ObligationState::Committed);
                assert_eq!(duration_ns, &Some(15));
                assert_eq!(abort_reason, &None);
            }
            other => panic!("unexpected commit data: {other:?}"),
        }

        let abort_event = runtime
            .trace()
            .iter()
            .find(|e| e.kind == TraceEventKind::ObligationAbort)
            .expect("abort event");
        match &abort_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                assert_eq!(*obligation, ob2);
                assert_eq!(*task, task_id);
                assert_eq!(*region, root);
                assert_eq!(*kind, ObligationKind::Ack);
                assert_eq!(*state, crate::record::ObligationState::Aborted);
                assert_eq!(duration_ns, &Some(20));
                assert_eq!(abort_reason, &Some(ObligationAbortReason::Cancel));
            }
            other => panic!("unexpected abort data: {other:?}"),
        }
    }

    #[test]
    fn obligation_leak_emits_trace_event() {
        let mut runtime = LabRuntime::with_seed(22);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.tasks.insert(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.tasks.get_mut(task_idx).unwrap().id = task_id;

        runtime.advance_time_to(Time::from_nanos(100));
        let obligation =
            runtime
                .state
                .create_obligation(ObligationKind::Lease, task_id, root, None);

        runtime.advance_time_to(Time::from_nanos(140));
        runtime
            .state
            .tasks
            .get_mut(task_idx)
            .unwrap()
            .complete(Outcome::Ok(()));

        let violations = runtime.check_invariants();
        assert!(violations
            .iter()
            .any(|v| matches!(v, InvariantViolation::ObligationLeak { .. })));

        let leak_event = runtime
            .trace()
            .iter()
            .find(|e| e.kind == TraceEventKind::ObligationLeak)
            .expect("leak event");
        match &leak_event.data {
            TraceData::Obligation {
                obligation: leaked,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                assert_eq!(*leaked, obligation);
                assert_eq!(*task, task_id);
                assert_eq!(*region, root);
                assert_eq!(*kind, ObligationKind::Lease);
                assert_eq!(*state, crate::record::ObligationState::Leaked);
                assert_eq!(duration_ns, &Some(40));
                assert_eq!(abort_reason, &None);
            }
            other => panic!("unexpected leak data: {other:?}"),
        }
    }
}
