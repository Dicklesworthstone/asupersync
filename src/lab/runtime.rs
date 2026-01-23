//! Lab runtime for deterministic execution.
//!
//! The lab runtime executes tasks with:
//! - Virtual time (controlled advancement)
//! - Deterministic scheduling (seed-driven)
//! - Trace capture for replay
//! - Chaos injection for stress testing

use super::chaos::{ChaosRng, ChaosStats};
use super::config::LabConfig;
use crate::record::ObligationKind;
use crate::runtime::deadline_monitor::{
    default_warning_handler, DeadlineMonitor, DeadlineWarning, MonitorConfig,
};
use crate::runtime::RuntimeState;
use crate::trace::event::TraceEventKind;
use crate::trace::recorder::TraceRecorder;
use crate::trace::replay::{ReplayTrace, TraceMetadata};
use crate::trace::TraceBuffer;
use crate::trace::{TraceData, TraceEvent};
use crate::types::{ObligationId, TaskId};
use crate::types::{Severity, Time};
use crate::util::DetRng;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

/// The deterministic lab runtime.
///
/// This runtime is designed for testing and provides:
/// - Virtual time instead of wall-clock time
/// - Deterministic scheduling based on a seed
/// - Trace capture for debugging and replay
/// - Chaos injection for stress testing
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
    /// Chaos RNG for deterministic fault injection.
    chaos_rng: Option<ChaosRng>,
    /// Statistics about chaos injections.
    chaos_stats: ChaosStats,
    /// Replay recorder for deterministic trace capture.
    replay_recorder: TraceRecorder,
    /// Optional deadline monitor for warning callbacks.
    deadline_monitor: Option<DeadlineMonitor>,
}

impl LabRuntime {
    /// Creates a new lab runtime with the given configuration.
    #[must_use]
    pub fn new(config: LabConfig) -> Self {
        let rng = config.rng();
        let chaos_rng = config.chaos.as_ref().map(ChaosRng::from_config);
        let mut state = RuntimeState::new();
        state.trace = TraceBuffer::new(config.trace_capacity);

        // Initialize replay recorder if configured
        let mut replay_recorder = if let Some(ref rec_config) = config.replay_recording {
            TraceRecorder::with_config(TraceMetadata::new(config.seed), rec_config.clone())
        } else {
            TraceRecorder::disabled()
        };

        // Record initial RNG seed
        replay_recorder.record_rng_seed(config.seed);

        Self {
            state,
            scheduler: Arc::new(Mutex::new(
                crate::runtime::scheduler::PriorityScheduler::new(),
            )),
            config,
            rng,
            virtual_time: Time::ZERO,
            steps: 0,
            chaos_rng,
            chaos_stats: ChaosStats::new(),
            replay_recorder,
            deadline_monitor: None,
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

    /// Returns a reference to the chaos statistics.
    #[must_use]
    pub fn chaos_stats(&self) -> &ChaosStats {
        &self.chaos_stats
    }

    /// Returns true if replay recording is enabled.
    #[must_use]
    pub fn has_replay_recording(&self) -> bool {
        self.replay_recorder.is_enabled()
    }

    /// Returns a reference to the replay recorder.
    #[must_use]
    pub fn replay_recorder(&self) -> &TraceRecorder {
        &self.replay_recorder
    }

    /// Takes the replay trace, leaving an empty trace in place.
    ///
    /// Returns `None` if recording is disabled.
    pub fn take_replay_trace(&mut self) -> Option<ReplayTrace> {
        self.replay_recorder.take()
    }

    /// Finishes recording and returns the replay trace.
    ///
    /// This consumes the replay recorder. Returns `None` if recording is disabled.
    pub fn finish_replay_trace(&mut self) -> Option<ReplayTrace> {
        // Take ownership by replacing with a disabled recorder
        let recorder = std::mem::replace(&mut self.replay_recorder, TraceRecorder::disabled());
        recorder.finish()
    }

    /// Returns true if chaos injection is enabled.
    #[must_use]
    pub fn has_chaos(&self) -> bool {
        self.chaos_rng.is_some() && self.config.has_chaos()
    }

    /// Returns true if the runtime is quiescent.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.state.is_quiescent()
    }

    /// Advances virtual time by the given number of nanoseconds.
    pub fn advance_time(&mut self, nanos: u64) {
        let from = self.virtual_time;
        self.virtual_time = self.virtual_time.saturating_add_nanos(nanos);
        self.state.now = self.virtual_time;
        // Record time advancement
        self.replay_recorder
            .record_time_advanced(from, self.virtual_time);
    }

    /// Advances time to the given absolute time.
    pub fn advance_time_to(&mut self, time: Time) {
        if time > self.virtual_time {
            let from = self.virtual_time;
            self.virtual_time = time;
            self.state.now = self.virtual_time;
            // Record time advancement
            self.replay_recorder
                .record_time_advanced(from, self.virtual_time);
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

    /// Enable deadline monitoring with the default warning handler.
    pub fn enable_deadline_monitoring(&mut self, config: MonitorConfig) {
        self.enable_deadline_monitoring_with_handler(config, default_warning_handler);
    }

    /// Enable deadline monitoring with a custom warning handler.
    pub fn enable_deadline_monitoring_with_handler<F>(&mut self, config: MonitorConfig, f: F)
    where
        F: Fn(DeadlineWarning) + Send + Sync + 'static,
    {
        let mut monitor = DeadlineMonitor::new(config);
        monitor.on_warning(f);
        self.deadline_monitor = Some(monitor);
    }

    /// Returns a mutable reference to the deadline monitor, if enabled.
    pub fn deadline_monitor_mut(&mut self) -> Option<&mut DeadlineMonitor> {
        self.deadline_monitor.as_mut()
    }

    /// Executes a single step.
    fn step(&mut self) {
        self.steps += 1;
        // Consume RNG state so schedule tie-breaking is deterministic once we
        // start making scheduler decisions here.
        let rng_value = self.rng.next_u64();
        self.replay_recorder.record_rng_value(rng_value);
        self.check_futurelocks();

        // 1. Pop a task from the scheduler
        let Some(task_id) = self.scheduler.lock().unwrap().pop() else {
            self.check_deadline_monitor();
            return;
        };

        // Record task scheduling
        self.replay_recorder
            .record_task_scheduled(task_id, self.steps);

        // 2. Pre-poll chaos injection
        if self.inject_pre_poll_chaos(task_id) {
            // Chaos caused the task to be skipped (e.g., cancelled, budget exhausted)
            return;
        }

        // 3. Prepare context
        let priority = self
            .state
            .tasks
            .get(task_id.arena_index())
            .and_then(|t| t.cx_inner.as_ref())
            .map_or(0, |inner| {
                inner.read().expect("lock poisoned").budget.priority
            });

        let waker = Waker::from(Arc::new(TaskWaker {
            task_id,
            priority,
            scheduler: self.scheduler.clone(),
        }));
        let mut cx = Context::from_waker(&waker);
        let current_cx = self
            .state
            .tasks
            .get(task_id.arena_index())
            .and_then(|record| record.cx.clone());
        let _cx_guard = crate::cx::Cx::set_current(current_cx);

        // 4. Poll the task
        let result = if let Some(stored) = self.state.get_stored_future(task_id) {
            stored.poll(&mut cx)
        } else {
            // Task lost (should not happen if consistent)
            return;
        };

        // 5. Handle result
        match result {
            Poll::Ready(()) => {
                // Task completed
                self.state.remove_stored_future(task_id);

                // Record task completion
                self.replay_recorder
                    .record_task_completed(task_id, Severity::Ok);

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
                        .map_or(0, |inner| {
                            inner.read().expect("lock poisoned").budget.priority
                        });
                    sched.schedule(waiter, prio);
                }
            }
            Poll::Pending => {
                // Task yielded. Waker will reschedule it when ready.
                // Note: If the task yielded via `cx.waker().wake_by_ref()`, it might already be scheduled.
                // If it yielded for I/O or other events, it won't be scheduled until that event fires.

                // Record task yielding
                self.replay_recorder.record_task_yielded(task_id);

                // 6. Post-poll chaos injection (spurious wakeups for pending tasks)
                self.inject_post_poll_chaos(task_id, priority);
            }
        }

        self.check_deadline_monitor();
    }

    fn check_deadline_monitor(&mut self) {
        if let Some(monitor) = &mut self.deadline_monitor {
            let now = self.state.now;
            monitor.check(now, self.state.tasks.iter().map(|(_, record)| record));
        }
    }

    /// Injects chaos before polling a task.
    ///
    /// Returns `true` if the task should be skipped (e.g., cancelled or budget exhausted).
    fn inject_pre_poll_chaos(&mut self, task_id: TaskId) -> bool {
        let Some(chaos_config) = self.config.chaos.clone() else {
            return false;
        };
        let Some(chaos_rng) = &mut self.chaos_rng else {
            return false;
        };

        let mut skip_poll = false;

        // Check for cancellation injection
        if chaos_rng.should_inject_cancel(&chaos_config) {
            skip_poll = true;
        }

        // Check for delay injection
        let delay = if chaos_rng.should_inject_delay(&chaos_config) {
            Some(chaos_rng.next_delay(&chaos_config))
        } else {
            None
        };

        // Check for budget exhaustion injection
        let budget_exhaust = chaos_rng.should_inject_budget_exhaust(&chaos_config);
        if budget_exhaust {
            skip_poll = true;
        }

        // Now apply the injections (no more borrowing chaos_rng)
        if skip_poll && !budget_exhaust {
            // Cancellation was injected
            self.chaos_stats.record_cancel();
            self.inject_cancel(task_id);
        }

        if let Some(d) = delay {
            self.chaos_stats.record_delay(d);
            self.advance_time(d.as_nanos() as u64);
        }

        if budget_exhaust {
            self.chaos_stats.record_budget_exhaust();
            self.inject_budget_exhaust(task_id);
        }

        if !skip_poll {
            self.chaos_stats.record_no_injection();
        }

        skip_poll
    }

    /// Injects chaos after polling a task that returned Pending.
    fn inject_post_poll_chaos(&mut self, task_id: TaskId, priority: u8) {
        let Some(chaos_config) = self.config.chaos.clone() else {
            return;
        };
        let Some(chaos_rng) = &mut self.chaos_rng else {
            return;
        };

        // Check for spurious wakeup storm
        let wakeup_count = if chaos_rng.should_inject_wakeup_storm(&chaos_config) {
            Some(chaos_rng.next_wakeup_count(&chaos_config))
        } else {
            None
        };

        // Apply the injection (no more borrowing chaos_rng)
        if let Some(count) = wakeup_count {
            self.chaos_stats.record_wakeup_storm(count as u64);
            self.inject_spurious_wakes(task_id, priority, count);
        }
    }

    /// Injects a cancellation for a task.
    fn inject_cancel(&mut self, task_id: TaskId) {
        use crate::types::{Budget, CancelReason};

        // Record replay event
        self.replay_recorder.record_cancel_injection(task_id);

        // Mark the task as cancel-requested with chaos reason
        if let Some(record) = self.state.tasks.get_mut(task_id.arena_index()) {
            if !record.state.is_terminal() {
                record.state = crate::record::task::TaskState::CancelRequested {
                    reason: CancelReason::user("chaos-injected"),
                    cleanup_budget: Budget::ZERO,
                };
            }
        }

        // Emit trace event
        let seq = self.state.next_trace_seq();
        self.state.trace.push(TraceEvent::new(
            seq,
            self.virtual_time,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "cancel".to_string(),
                task: Some(task_id),
                detail: "chaos-injected cancellation".to_string(),
            },
        ));
    }

    /// Injects budget exhaustion for a task.
    fn inject_budget_exhaust(&mut self, task_id: TaskId) {
        // Record replay event
        self.replay_recorder
            .record_budget_exhaust_injection(task_id);

        // Set the task's budget quotas to zero
        if let Some(record) = self.state.tasks.get(task_id.arena_index()) {
            if let Some(cx_inner) = &record.cx_inner {
                if let Ok(mut inner) = cx_inner.write() {
                    inner.budget.poll_quota = 0;
                    inner.budget.cost_quota = Some(0);
                }
            }
        }

        // Emit trace event
        let seq = self.state.next_trace_seq();
        self.state.trace.push(TraceEvent::new(
            seq,
            self.virtual_time,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "budget_exhaust".to_string(),
                task: Some(task_id),
                detail: "chaos-injected budget exhaustion".to_string(),
            },
        ));
    }

    /// Injects spurious wakeups for a task.
    fn inject_spurious_wakes(&mut self, task_id: TaskId, priority: u8, count: usize) {
        // Record replay event
        self.replay_recorder
            .record_wakeup_storm_injection(task_id, count as u32);

        // Schedule the task multiple times (spurious wakeups)
        let mut sched = self.scheduler.lock().unwrap();
        for _ in 0..count {
            sched.schedule(task_id, priority);
        }
        drop(sched);

        // Emit trace event
        let seq = self.state.next_trace_seq();
        self.state.trace.push(TraceEvent::new(
            seq,
            self.virtual_time,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "wakeup_storm".to_string(),
                task: Some(task_id),
                detail: format!("chaos-injected {count} spurious wakeups"),
            },
        ));
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
    use crate::runtime::deadline_monitor::WarningReason;
    use crate::types::{Budget, CxInner, ObligationId, Outcome, TaskId};
    use crate::util::ArenaIndex;
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::Duration;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn empty_runtime_is_quiescent() {
        init_test("empty_runtime_is_quiescent");
        let runtime = LabRuntime::with_seed(42);
        let quiescent = runtime.is_quiescent();
        crate::assert_with_log!(quiescent, "quiescent", true, quiescent);
        crate::test_complete!("empty_runtime_is_quiescent");
    }

    #[test]
    fn advance_time() {
        init_test("advance_time");
        let mut runtime = LabRuntime::with_seed(42);
        let now = runtime.now();
        crate::assert_with_log!(now == Time::ZERO, "now", Time::ZERO, now);

        runtime.advance_time(1_000_000);
        let now = runtime.now();
        crate::assert_with_log!(
            now == Time::from_millis(1),
            "now",
            Time::from_millis(1),
            now
        );
        crate::test_complete!("advance_time");
    }

    #[test]
    fn deterministic_rng() {
        init_test("deterministic_rng");
        let mut r1 = LabRuntime::with_seed(42);
        let mut r2 = LabRuntime::with_seed(42);

        let a = r1.rng.next_u64();
        let b = r2.rng.next_u64();
        crate::assert_with_log!(a == b, "rng", b, a);
        crate::test_complete!("deterministic_rng");
    }

    #[test]
    fn deadline_monitor_emits_warning() {
        init_test("deadline_monitor_emits_warning");
        let mut runtime = LabRuntime::with_seed(42);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_clone = Arc::clone(&warnings);

        let config = MonitorConfig {
            check_interval: Duration::from_secs(0),
            warning_threshold_fraction: 1.0,
            checkpoint_timeout: Duration::from_secs(0),
            enabled: true,
        };

        runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
            warnings_clone.lock().unwrap().push(warning);
        });

        let root = runtime.state.create_root_region(Budget::INFINITE);
        let budget = Budget::new().with_deadline(Time::from_millis(10));

        let task_idx = runtime.state.tasks.insert(TaskRecord::new_with_time(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            budget,
            runtime.state.now,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.tasks.get_mut(task_idx).unwrap().id = task_id;

        let mut inner = CxInner::new(root, task_id, budget);
        inner.checkpoint_state.last_checkpoint = None;
        runtime
            .state
            .tasks
            .get_mut(task_idx)
            .unwrap()
            .set_cx_inner(Arc::new(RwLock::new(inner)));

        runtime.step();

        let warnings = warnings.lock().unwrap();
        let warning = warnings.first().expect("expected warning");
        crate::assert_with_log!(
            warning.task_id == task_id,
            "task_id",
            task_id,
            warning.task_id
        );
        crate::assert_with_log!(
            warning.region_id == root,
            "region_id",
            root,
            warning.region_id
        );
        let ok = matches!(
            warning.reason,
            WarningReason::ApproachingDeadline | WarningReason::ApproachingDeadlineNoProgress
        );
        crate::assert_with_log!(ok, "reason", true, ok);
        crate::test_complete!("deadline_monitor_emits_warning");
    }

    #[test]
    fn futurelock_emits_trace_event() {
        init_test("futurelock_emits_trace_event");
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
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                let idle_ok = *idle_steps > 3;
                crate::assert_with_log!(idle_ok, "idle_steps > 3", true, idle_ok);
                let ok = held.as_slice() == [(obl_id, ObligationKind::SendPermit)];
                crate::assert_with_log!(
                    ok,
                    "held",
                    &[(obl_id, ObligationKind::SendPermit)],
                    held.as_slice()
                );
            }
            other => panic!("unexpected trace data: {other:?}"),
        }
        crate::test_complete!("futurelock_emits_trace_event");
    }

    #[test]
    #[should_panic(expected = "futurelock detected")]
    fn futurelock_can_panic() {
        init_test("futurelock_can_panic");
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
        init_test("obligation_leak_detected_when_holder_completed");
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
                let len = leaks.len();
                crate::assert_with_log!(len == 1, "leaks len", 1, len);
                let leak = &leaks[0];
                crate::assert_with_log!(
                    leak.obligation == obl_id,
                    "obligation",
                    obl_id,
                    leak.obligation
                );
                crate::assert_with_log!(
                    leak.kind == ObligationKind::SendPermit,
                    "kind",
                    ObligationKind::SendPermit,
                    leak.kind
                );
                crate::assert_with_log!(leak.holder == task_id, "holder", task_id, leak.holder);
                crate::assert_with_log!(leak.region == root, "region", root, leak.region);
            }
        }
        crate::assert_with_log!(found, "found leak", true, found);
        crate::test_complete!("obligation_leak_detected_when_holder_completed");
    }

    #[test]
    fn obligation_leak_ignored_when_resolved() {
        init_test("obligation_leak_ignored_when_resolved");
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
        let has_leak = violations
            .iter()
            .any(|v| matches!(v, InvariantViolation::ObligationLeak { .. }));
        crate::assert_with_log!(!has_leak, "no leak", false, has_leak);
        crate::test_complete!("obligation_leak_ignored_when_resolved");
    }

    #[test]
    fn obligation_trace_events_emitted() {
        init_test("obligation_trace_events_emitted");
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
        let ob2 = runtime
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
                crate::assert_with_log!(*obligation == ob1, "obligation", ob1, *obligation);
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                crate::assert_with_log!(
                    *kind == ObligationKind::SendPermit,
                    "kind",
                    ObligationKind::SendPermit,
                    *kind
                );
                crate::assert_with_log!(
                    *state == crate::record::ObligationState::Committed,
                    "state",
                    crate::record::ObligationState::Committed,
                    *state
                );
                crate::assert_with_log!(
                    duration_ns == &Some(15),
                    "duration",
                    &Some(15),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason.is_none(),
                    "abort_reason",
                    &None::<crate::record::ObligationAbortReason>,
                    abort_reason
                );
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
                crate::assert_with_log!(*obligation == ob2, "obligation", ob2, *obligation);
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                crate::assert_with_log!(
                    *kind == ObligationKind::Ack,
                    "kind",
                    ObligationKind::Ack,
                    *kind
                );
                crate::assert_with_log!(
                    *state == crate::record::ObligationState::Aborted,
                    "state",
                    crate::record::ObligationState::Aborted,
                    *state
                );
                crate::assert_with_log!(
                    duration_ns == &Some(20),
                    "duration",
                    &Some(20),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason == &Some(ObligationAbortReason::Cancel),
                    "abort_reason",
                    &Some(ObligationAbortReason::Cancel),
                    abort_reason
                );
            }
            other => panic!("unexpected abort data: {other:?}"),
        }
        crate::test_complete!("obligation_trace_events_emitted");
    }

    #[test]
    fn obligation_leak_emits_trace_event() {
        init_test("obligation_leak_emits_trace_event");
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
        let has_leak = violations
            .iter()
            .any(|v| matches!(v, InvariantViolation::ObligationLeak { .. }));
        crate::assert_with_log!(has_leak, "has leak", true, has_leak);

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
                crate::assert_with_log!(*leaked == obligation, "obligation", obligation, *leaked);
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                crate::assert_with_log!(
                    *kind == ObligationKind::Lease,
                    "kind",
                    ObligationKind::Lease,
                    *kind
                );
                crate::assert_with_log!(
                    *state == crate::record::ObligationState::Leaked,
                    "state",
                    crate::record::ObligationState::Leaked,
                    *state
                );
                crate::assert_with_log!(
                    duration_ns == &Some(40),
                    "duration",
                    &Some(40),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason.is_none(),
                    "abort_reason",
                    &None::<crate::record::ObligationAbortReason>,
                    abort_reason
                );
            }
            other => panic!("unexpected leak data: {other:?}"),
        }
        crate::test_complete!("obligation_leak_emits_trace_event");
    }
}
