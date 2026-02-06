//! Lab runtime for deterministic execution.
//!
//! The lab runtime executes tasks with:
//! - Virtual time (controlled advancement)
//! - Deterministic scheduling (seed-driven)
//! - Trace capture for replay
//! - Chaos injection for stress testing

use super::chaos::{ChaosRng, ChaosStats};
use super::config::LabConfig;
use super::oracle::OracleSuite;
use crate::record::task::TaskState;
use crate::record::ObligationKind;
use crate::runtime::config::ObligationLeakResponse;
use crate::runtime::deadline_monitor::{
    default_warning_handler, DeadlineMonitor, DeadlineWarning, MonitorConfig,
};
use crate::runtime::reactor::LabReactor;
use crate::runtime::scheduler::{DispatchLane, ScheduleCertificate};
use crate::runtime::RuntimeState;
use crate::time::VirtualClock;
use crate::trace::event::TraceEventKind;
use crate::trace::recorder::TraceRecorder;
use crate::trace::replay::{ReplayTrace, TraceMetadata};
use crate::trace::scoring::seed_fingerprint;
use crate::trace::TraceBufferHandle;
use crate::trace::{canonicalize::trace_fingerprint, certificate::TraceCertificate};
use crate::trace::{TraceData, TraceEvent};
use crate::types::{ObligationId, TaskId};
use crate::types::{Severity, Time};
use crate::util::{DetEntropy, DetRng};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

/// Summary of a trace certificate built from the current trace buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabTraceCertificateSummary {
    /// Incremental hash of witnessed events.
    pub event_hash: u64,
    /// Total number of events witnessed.
    pub event_count: u64,
    /// Hash of scheduling decisions (from [`ScheduleCertificate`]).
    pub schedule_hash: u64,
}

/// Structured report for a single lab runtime run.
///
/// This is intended as a low-level building block for Spork app harnesses.
/// It contains canonical trace fingerprints and oracle outcomes, but it does
/// not write to stdout/stderr or persist artifacts.
#[derive(Debug, Clone)]
pub struct LabRunReport {
    /// Lab seed driving scheduling determinism.
    pub seed: u64,
    /// Steps executed during the `run_until_quiescent()` call that produced this report.
    pub steps_delta: u64,
    /// Total steps executed by the runtime so far.
    pub steps_total: u64,
    /// Whether the runtime is quiescent at report time.
    pub quiescent: bool,
    /// Virtual time (nanoseconds since epoch) at report time.
    pub now_nanos: u64,
    /// Number of events in the current trace buffer snapshot.
    pub trace_len: usize,
    /// Canonical fingerprint of the trace equivalence class (Foata / Mazurkiewicz).
    pub trace_fingerprint: u64,
    /// Trace certificate summary (event hash/count + schedule hash).
    pub trace_certificate: LabTraceCertificateSummary,
    /// Unified oracle report (stable ordering, serializable).
    pub oracle_report: crate::lab::oracle::OracleReport,
    /// Runtime invariant violations detected by `LabRuntime::check_invariants()`.
    ///
    /// This is distinct from the oracle suite: it's a small set of runtime-level
    /// checks (e.g., obligation leaks, futurelocks, quiescence violations).
    pub invariant_violations: Vec<String>,
}

impl LabRunReport {
    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        json!({
            "seed": self.seed,
            "steps_delta": self.steps_delta,
            "steps_total": self.steps_total,
            "quiescent": self.quiescent,
            "now_nanos": self.now_nanos,
            "trace": {
                "len": self.trace_len,
                "fingerprint": self.trace_fingerprint,
                "certificate": {
                    "event_hash": self.trace_certificate.event_hash,
                    "event_count": self.trace_certificate.event_count,
                    "schedule_hash": self.trace_certificate.schedule_hash,
                }
            },
            "oracles": self.oracle_report.to_json(),
            "invariants": self.invariant_violations,
        })
    }
}

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
    /// Lab reactor for deterministic I/O simulation.
    lab_reactor: Arc<LabReactor>,
    /// Tokens seen for I/O submissions (for trace emission).
    seen_io_tokens: HashSet<usize>,
    /// Scheduler.
    pub scheduler: Arc<Mutex<LabScheduler>>,
    /// Configuration.
    config: LabConfig,
    /// Deterministic RNG.
    rng: DetRng,
    /// Current virtual time.
    virtual_time: Time,
    /// Virtual clock backing the timer driver.
    virtual_clock: Arc<VirtualClock>,
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
    /// Oracle suite for invariant verification.
    pub oracles: OracleSuite,
    /// Schedule certificate for determinism verification.
    certificate: ScheduleCertificate,
}

impl LabRuntime {
    /// Creates a new lab runtime with the given configuration.
    #[must_use]
    pub fn new(config: LabConfig) -> Self {
        let rng = config.rng();
        let chaos_rng = config.chaos.as_ref().map(ChaosRng::from_config);
        let lab_reactor = config.chaos.as_ref().map_or_else(
            || Arc::new(LabReactor::new()),
            |chaos| Arc::new(LabReactor::with_chaos(chaos.clone())),
        );
        let mut state = RuntimeState::with_reactor(lab_reactor.clone());
        state.set_logical_clock_mode(crate::trace::distributed::LogicalClockMode::Lamport);
        state.set_obligation_leak_response(if config.panic_on_obligation_leak {
            ObligationLeakResponse::Panic
        } else {
            ObligationLeakResponse::Log
        });
        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        state.set_timer_driver(crate::time::TimerDriverHandle::with_virtual_clock(
            virtual_clock.clone(),
        ));
        state.set_entropy_source(Arc::new(DetEntropy::new(config.entropy_seed)));
        state.trace = TraceBufferHandle::new(config.trace_capacity);

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
            lab_reactor,
            seen_io_tokens: HashSet::new(),
            scheduler: Arc::new(Mutex::new(LabScheduler::new(config.worker_count))),
            config,
            rng,
            virtual_time: Time::ZERO,
            virtual_clock,
            steps: 0,
            chaos_rng,
            chaos_stats: ChaosStats::new(),
            replay_recorder,
            deadline_monitor: None,
            oracles: OracleSuite::new(),
            certificate: ScheduleCertificate::new(),
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

    /// Returns a handle to the lab reactor for deterministic I/O injection.
    #[must_use]
    pub fn lab_reactor(&self) -> &Arc<LabReactor> {
        &self.lab_reactor
    }

    /// Returns a reference to the trace buffer handle.
    #[must_use]
    pub fn trace(&self) -> &TraceBufferHandle {
        &self.state.trace
    }

    /// Returns a race report derived from the current trace buffer.
    #[must_use]
    pub fn detected_races(&self) -> crate::trace::dpor::RaceReport {
        crate::trace::dpor::detect_hb_races(&self.state.trace.snapshot())
    }

    /// Returns a reference to the chaos statistics.
    #[must_use]
    pub fn chaos_stats(&self) -> &ChaosStats {
        &self.chaos_stats
    }

    /// Returns the schedule certificate for determinism verification.
    #[must_use]
    pub fn certificate(&self) -> &ScheduleCertificate {
        &self.certificate
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
        self.virtual_clock.advance(nanos);
        self.lab_reactor.advance_time(Duration::from_nanos(nanos));
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
            self.virtual_clock.advance_to(time);
            self.lab_reactor.advance_time_to(time);
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

    /// Runs until quiescent (or `max_steps` is reached) and returns a structured report.
    #[must_use]
    pub fn run_until_quiescent_with_report(&mut self) -> LabRunReport {
        let steps_delta = self.run_until_quiescent();
        self.report_with_steps_delta(steps_delta)
    }

    /// Build a structured report for the current runtime state.
    ///
    /// This does not advance execution.
    #[must_use]
    pub fn report(&mut self) -> LabRunReport {
        self.report_with_steps_delta(0)
    }

    fn report_with_steps_delta(&mut self, steps_delta: u64) -> LabRunReport {
        let seed = self.config.seed;
        let quiescent = self.is_quiescent();
        let now = self.now();

        let trace_events = self.trace().snapshot();
        let trace_len = trace_events.len();

        let trace_fingerprint = if trace_events.is_empty() {
            // Mirror explorer behavior: ensure the report fingerprint varies by seed
            // even if trace capture is effectively disabled / empty.
            seed_fingerprint(seed)
        } else {
            trace_fingerprint(&trace_events)
        };

        let schedule_hash = self.certificate().hash();
        let mut certificate = TraceCertificate::new();
        for e in &trace_events {
            certificate.record_event(e);
        }
        certificate.set_schedule_hash(schedule_hash);

        let oracle_report = self.oracles.report(now);
        let invariant_violations = self
            .check_invariants()
            .into_iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>();

        LabRunReport {
            seed,
            steps_delta,
            steps_total: self.steps(),
            quiescent,
            now_nanos: now.as_nanos(),
            trace_len,
            trace_fingerprint,
            trace_certificate: LabTraceCertificateSummary {
                event_hash: certificate.event_hash(),
                event_count: certificate.event_count(),
                schedule_hash: certificate.schedule_hash(),
            },
            oracle_report,
            invariant_violations,
        }
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
    #[allow(clippy::too_many_lines)]
    fn step(&mut self) {
        self.steps += 1;
        // Consume RNG state so schedule tie-breaking is deterministic once we
        // start making scheduler decisions here.
        let rng_value = self.rng.next_u64();
        self.replay_recorder.record_rng_value(rng_value);
        self.check_futurelocks();
        if let Some(timer) = self.state.timer_driver_handle() {
            let _ = timer.process_timers();
        }
        self.poll_io();
        self.schedule_async_finalizers();

        // 1. Choose a worker and pop a task (deterministic multi-worker model)
        let worker_count = self.config.worker_count.max(1);
        let worker_hint = (rng_value as usize) % worker_count;
        let (task_id, dispatch_lane) = {
            let mut sched = self.scheduler.lock().unwrap();
            if let Some((tid, lane)) = sched.pop_for_worker(worker_hint, rng_value) {
                (tid, lane)
            } else if let Some(tid) = sched.steal_for_worker(worker_hint, rng_value.rotate_left(17))
            {
                (tid, DispatchLane::Stolen)
            } else {
                drop(sched);
                self.check_deadline_monitor();
                return;
            }
        };

        // Record task scheduling in certificate and replay recorder
        self.certificate.record(task_id, dispatch_lane, self.steps);
        self.replay_recorder
            .record_task_scheduled(task_id, self.steps);

        // 2. Pre-poll chaos injection
        if self.inject_pre_poll_chaos(task_id) {
            // Chaos caused the task to be skipped (e.g., cancelled, budget exhausted)
            return;
        }

        // 3. Prepare context and enforce budget
        let priority = self.state.task(task_id).map_or(0, |record| {
            record.cx_inner.as_ref().map_or(0, |inner| {
                let mut guard = inner.write().expect("lock poisoned");

                // Enforce poll quota
                if guard.budget.consume_poll().is_none() {
                    guard.cancel_requested = true;
                    if guard.cancel_reason.is_none() {
                        guard.cancel_reason = Some(crate::types::CancelReason::poll_quota());
                    }
                }

                guard.budget.priority
            })
        });

        let waker = Waker::from(Arc::new(TaskWaker {
            task_id,
            priority,
            scheduler: self.scheduler.clone(),
        }));
        let mut cx = Context::from_waker(&waker);

        // Set cancel_waker so abort_with_reason can reschedule cancelled tasks.
        if let Some(record) = self.state.task(task_id) {
            if let Some(inner) = record.cx_inner.as_ref() {
                let cancel_waker = Waker::from(Arc::new(CancelTaskWaker {
                    task_id,
                    priority,
                    scheduler: self.scheduler.clone(),
                }));
                if let Ok(mut guard) = inner.write() {
                    guard.cancel_waker = Some(cancel_waker);
                }
            }
        }

        let current_cx = self
            .state
            .task(task_id)
            .and_then(|record| record.cx.clone());
        let _cx_guard = crate::cx::Cx::set_current(current_cx);

        // 4. Poll the task
        let result = if let Some(stored) = self.state.get_stored_future(task_id) {
            stored.poll(&mut cx)
        } else {
            // Task lost (should not happen if consistent)
            return;
        };
        let cancel_ack = self.consume_cancel_ack(task_id);

        // 5. Handle result
        match result {
            Poll::Ready(outcome) => {
                // Task completed
                self.state.remove_stored_future(task_id);
                self.scheduler.lock().unwrap().forget_task(task_id);

                // Record task completion
                self.replay_recorder
                    .record_task_completed(task_id, Severity::Ok); // Severity is approx here

                // Update state to Completed if not already terminal
                if let Some(record) = self.state.task_mut(task_id) {
                    if !record.state.is_terminal() {
                        let record_outcome = match outcome {
                            crate::types::Outcome::Ok(()) => crate::types::Outcome::Ok(()),
                            crate::types::Outcome::Err(()) => crate::types::Outcome::Err(
                                crate::error::Error::new(crate::error::ErrorKind::Internal),
                            ),
                            crate::types::Outcome::Cancelled(r) => {
                                crate::types::Outcome::Cancelled(r)
                            }
                            crate::types::Outcome::Panicked(p) => {
                                crate::types::Outcome::Panicked(p)
                            }
                        };
                        let mut completed_via_cancel = false;
                        if matches!(record_outcome, crate::types::Outcome::Ok(())) {
                            let should_cancel = matches!(
                                record.state,
                                TaskState::Cancelling { .. } | TaskState::Finalizing { .. }
                            ) || (cancel_ack
                                && matches!(record.state, TaskState::CancelRequested { .. }));
                            if should_cancel {
                                if matches!(record.state, TaskState::CancelRequested { .. }) {
                                    let _ = record.acknowledge_cancel();
                                }
                                if matches!(record.state, TaskState::Cancelling { .. }) {
                                    record.cleanup_done();
                                }
                                if matches!(record.state, TaskState::Finalizing { .. }) {
                                    record.finalize_done();
                                }
                                completed_via_cancel = matches!(
                                    record.state,
                                    TaskState::Completed(crate::types::Outcome::Cancelled(_))
                                );
                            }
                        }
                        if !completed_via_cancel {
                            record.complete(record_outcome);
                        }
                    }
                }

                if let Some(monitor) = &mut self.deadline_monitor {
                    if let Some(record) = self.state.task(task_id) {
                        let now = self.state.now;
                        let duration =
                            Duration::from_nanos(now.duration_since(record.created_at()));
                        let (task_type, deadline) = record
                            .cx_inner
                            .as_ref()
                            .and_then(|inner| inner.read().ok())
                            .map_or_else(
                                || ("default".to_string(), None),
                                |inner| {
                                    (
                                        inner
                                            .task_type
                                            .clone()
                                            .unwrap_or_else(|| "default".to_string()),
                                        inner.budget.deadline,
                                    )
                                },
                            );
                        monitor.record_completion(task_id, &task_type, duration, deadline, now);
                    }
                }

                // Notify waiters
                let waiters = self.state.task_completed(task_id);

                // Schedule waiters
                let mut sched = self.scheduler.lock().unwrap();
                for waiter in waiters {
                    let prio = self
                        .state
                        .task(waiter)
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
            monitor.check(now, self.state.tasks_iter().map(|(_, record)| record));
        }
    }

    fn poll_io(&mut self) {
        let Some(handle) = self.state.io_driver_handle() else {
            return;
        };
        let now = self.state.now;
        let (state, recorder, seen) = (
            &mut self.state,
            &mut self.replay_recorder,
            &mut self.seen_io_tokens,
        );
        if let Err(_error) = handle.turn_with(Some(Duration::ZERO), |event, interest| {
            let token = event.token.0;
            let interest = interest.unwrap_or(event.ready);
            if seen.insert(token) {
                let seq = state.next_trace_seq();
                state.trace.push_event(TraceEvent::io_requested(
                    seq,
                    now,
                    token as u64,
                    interest.bits(),
                ));
            }
            let seq = state.next_trace_seq();
            state.trace.push_event(TraceEvent::io_ready(
                seq,
                now,
                token as u64,
                event.ready.bits(),
            ));
            recorder.record_io_ready(
                token as u64,
                event.is_readable(),
                event.is_writable(),
                event.is_error(),
                event.is_hangup(),
            );
        }) {
            crate::tracing_compat::warn!(
                error = ?_error,
                "lab runtime io_driver poll failed"
            );
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

        let mut skip_poll = chaos_rng.should_inject_cancel(&chaos_config);

        // Check for delay injection
        let delay = chaos_rng
            .should_inject_delay(&chaos_config)
            .then(|| chaos_rng.next_delay(&chaos_config));

        // Check for budget exhaustion injection
        let budget_exhaust = chaos_rng.should_inject_budget_exhaust(&chaos_config);
        skip_poll |= budget_exhaust;

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

        if skip_poll {
            self.reschedule_after_chaos_skip(task_id);
        } else {
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

    fn reschedule_after_chaos_skip(&self, task_id: TaskId) {
        let Some(record) = self.state.task(task_id) else {
            return;
        };
        if record.state.is_terminal() {
            return;
        }
        let priority = record
            .cx_inner
            .as_ref()
            .and_then(|inner| inner.read().ok().map(|cx| cx.budget.priority))
            .unwrap_or(0);
        let mut sched = self.scheduler.lock().unwrap();
        sched.schedule_cancel(task_id, priority);
    }

    fn schedule_async_finalizers(&mut self) {
        let tasks = self.state.drain_ready_async_finalizers();
        if tasks.is_empty() {
            return;
        }
        let mut sched = self.scheduler.lock().unwrap();
        for (task_id, priority) in tasks {
            sched.schedule(task_id, priority);
        }
    }

    fn consume_cancel_ack(&mut self, task_id: TaskId) -> bool {
        let Some(record) = self.state.task_mut(task_id) else {
            return false;
        };
        let Some(inner) = record.cx_inner.as_ref() else {
            return false;
        };
        let mut acknowledged = false;
        if let Ok(mut guard) = inner.write() {
            if guard.cancel_acknowledged {
                guard.cancel_acknowledged = false;
                acknowledged = true;
            }
        }
        if acknowledged {
            let _ = record.acknowledge_cancel();
        }
        acknowledged
    }

    /// Injects a cancellation for a task.
    fn inject_cancel(&mut self, task_id: TaskId) {
        use crate::types::{Budget, CancelReason};

        // Record replay event
        self.replay_recorder.record_cancel_injection(task_id);

        // Mark the task as cancel-requested with chaos reason
        if let Some(record) = self.state.task_mut(task_id) {
            if !record.state.is_terminal() {
                record
                    .request_cancel_with_budget(CancelReason::user("chaos-injected"), Budget::ZERO);
            }
        }

        // Emit trace event
        let seq = self.state.next_trace_seq();
        self.state.trace.push_event(TraceEvent::new(
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
        if let Some(record) = self.state.task(task_id) {
            if let Some(cx_inner) = &record.cx_inner {
                if let Ok(mut inner) = cx_inner.write() {
                    inner.budget.poll_quota = 0;
                    inner.budget.cost_quota = Some(0);
                }
            }
        }

        // Emit trace event
        let seq = self.state.next_trace_seq();
        self.state.trace.push_event(TraceEvent::new(
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
        self.state.trace.push_event(TraceEvent::new(
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

        for (_, obligation) in self.state.obligations_iter() {
            if !obligation.is_pending() {
                continue;
            }

            let holder_terminal = self
                .state
                .task(obligation.holder)
                .is_none_or(|t| t.state.is_terminal());
            let region_closed = self
                .state
                .region(obligation.region)
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
            .tasks_iter()
            .filter(|(_, t)| !t.state.is_terminal())
            .count()
    }

    fn quiescence_violations(&self) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();
        for (_, region) in self.state.regions_iter() {
            if region.state().is_terminal() {
                // Check if any children or tasks are NOT terminal
                let live_tasks = region
                    .task_ids()
                    .iter()
                    .any(|&tid| self.state.task(tid).is_some_and(|t| !t.state.is_terminal()));

                let live_children = region.child_ids().iter().any(|&rid| {
                    self.state
                        .region(rid)
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

        for (_, task) in self.state.tasks_iter() {
            if task.state.is_terminal() {
                continue;
            }

            let mut held = Vec::new();
            for (_, obligation) in self.state.obligations_iter() {
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

    fn check_futurelocks(&self) {
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
                for (_, obligation) in self.state.obligations_iter() {
                    if obligation.id == *oid {
                        held_kinds.push((obligation.id, obligation.kind));
                        break;
                    }
                }
            }

            let seq = self.state.next_trace_seq();
            self.state.trace.push_event(TraceEvent::new(
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

const DEFAULT_LAB_CANCEL_STREAK_LIMIT: usize = 16;

#[derive(Debug)]
/// Deterministic lab scheduler with per-worker queues.
///
/// This is a single-threaded model of multi-worker scheduling used by the lab
/// runtime to simulate parallel execution deterministically.
pub struct LabScheduler {
    workers: Vec<crate::runtime::scheduler::PriorityScheduler>,
    scheduled: HashSet<TaskId>,
    assignments: HashMap<TaskId, usize>,
    next_worker: usize,
    cancel_streak: Vec<usize>,
    cancel_streak_limit: usize,
}

impl LabScheduler {
    fn new(worker_count: usize) -> Self {
        let count = if worker_count == 0 { 1 } else { worker_count };
        let cancel_streak_limit = DEFAULT_LAB_CANCEL_STREAK_LIMIT.max(1);
        Self {
            workers: (0..count)
                .map(|_| crate::runtime::scheduler::PriorityScheduler::new())
                .collect(),
            scheduled: HashSet::new(),
            assignments: HashMap::new(),
            next_worker: 0,
            cancel_streak: vec![0; count],
            cancel_streak_limit,
        }
    }

    fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Returns the configured cancel streak limit for lab scheduling.
    #[must_use]
    pub fn cancel_streak_limit(&self) -> usize {
        self.cancel_streak_limit
    }

    fn assign_worker(&mut self, task: TaskId) -> usize {
        if let Some(&worker) = self.assignments.get(&task) {
            return worker;
        }

        let worker = self.next_worker % self.workers.len();
        self.next_worker = self.next_worker.wrapping_add(1);
        self.assignments.insert(task, worker);
        worker
    }

    /// Schedules a task in the ready lane on its assigned worker.
    pub fn schedule(&mut self, task: TaskId, priority: u8) {
        if !self.scheduled.insert(task) {
            return;
        }

        let worker = self.assign_worker(task);
        self.workers[worker].schedule(task, priority);
    }

    /// Schedules or promotes a task into the cancel lane.
    pub fn schedule_cancel(&mut self, task: TaskId, priority: u8) {
        if self.scheduled.insert(task) {
            let worker = self.assign_worker(task);
            self.workers[worker].schedule_cancel(task, priority);
            return;
        }

        if let Some(&worker) = self.assignments.get(&task) {
            self.workers[worker].move_to_cancel_lane(task, priority);
        }
    }

    /// Schedules a task in the timed lane on its assigned worker.
    pub fn schedule_timed(&mut self, task: TaskId, deadline: Time) {
        if !self.scheduled.insert(task) {
            return;
        }

        let worker = self.assign_worker(task);
        self.workers[worker].schedule_timed(task, deadline);
    }

    fn pop_for_worker(&mut self, worker: usize, rng_hint: u64) -> Option<(TaskId, DispatchLane)> {
        if self.workers.is_empty() {
            return None;
        }

        let worker = worker % self.workers.len();
        let cancel_streak = &mut self.cancel_streak[worker];

        if *cancel_streak < self.cancel_streak_limit {
            if let Some((task, lane)) = self.workers[worker].pop_cancel_with_rng(rng_hint) {
                *cancel_streak += 1;
                self.scheduled.remove(&task);
                self.assignments.insert(task, worker);
                return Some((task, lane));
            }
        }

        if let Some((task, lane)) = self.workers[worker].pop_non_cancel_with_rng(rng_hint) {
            *cancel_streak = 0;
            self.scheduled.remove(&task);
            self.assignments.insert(task, worker);
            return Some((task, lane));
        }

        if let Some((task, lane)) = self.workers[worker].pop_cancel_with_rng(rng_hint) {
            *cancel_streak = 1;
            self.scheduled.remove(&task);
            self.assignments.insert(task, worker);
            return Some((task, lane));
        }

        *cancel_streak = 0;
        None
    }

    fn steal_for_worker(&mut self, thief: usize, rng_hint: u64) -> Option<TaskId> {
        let count = self.workers.len();
        if count <= 1 {
            return None;
        }

        let thief = thief % count;
        let start = (rng_hint as usize) % count;

        for offset in 0..count {
            let victim = (start + offset) % count;
            if victim == thief {
                continue;
            }
            if let Some(task) =
                self.workers[victim].pop_with_rng_hint(rng_hint.wrapping_add(offset as u64))
            {
                self.scheduled.remove(&task);
                self.assignments.insert(task, thief);
                return Some(task);
            }
        }

        None
    }

    fn forget_task(&mut self, task: TaskId) {
        self.scheduled.remove(&task);
        self.assignments.remove(&task);
        for worker in &mut self.workers {
            worker.remove(task);
        }
    }
}

struct TaskWaker {
    task_id: crate::types::TaskId,
    priority: u8,
    scheduler: Arc<Mutex<LabScheduler>>,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.scheduler
            .lock()
            .unwrap()
            .schedule(self.task_id, self.priority);
    }
}

/// Waker that reschedules a task into the cancel lane.
///
/// Set as `cancel_waker` on each task's `CxInner` before polling so that
/// `abort_with_reason` can wake cancelled tasks.
struct CancelTaskWaker {
    task_id: crate::types::TaskId,
    priority: u8,
    scheduler: Arc<Mutex<LabScheduler>>,
}

impl Wake for CancelTaskWaker {
    fn wake(self: Arc<Self>) {
        self.scheduler
            .lock()
            .unwrap()
            .schedule_cancel(self.task_id, self.priority);
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
    /// Actors were not stopped before region close.
    ActorLeak {
        /// Number of leaked actors.
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
            Self::ActorLeak { count } => write!(f, "{count} actors leaked"),
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
    use crate::record::{ObligationAbortReason, ObligationKind};
    use crate::runtime::deadline_monitor::{AdaptiveDeadlineConfig, WarningReason};
    use crate::runtime::reactor::{Event, Interest};
    use crate::types::{Budget, CxInner, Outcome, TaskId};
    use crate::util::ArenaIndex;
    use std::sync::{Arc, Mutex, RwLock};
    use std::task::{Wake, Waker};
    use std::time::Duration;

    #[cfg(unix)]
    struct TestFdSource;
    #[cfg(unix)]
    impl std::os::fd::AsRawFd for TestFdSource {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            0
        }
    }

    #[cfg(unix)]
    struct NoopWaker;
    #[cfg(unix)]
    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    #[cfg(unix)]
    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

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

    #[cfg(unix)]
    #[test]
    fn lab_runtime_records_io_ready_trace() {
        init_test("lab_runtime_records_io_ready_trace");

        let mut runtime = LabRuntime::with_seed(42);
        let handle = runtime.state.io_driver_handle().expect("io driver");
        let waker = noop_waker();
        let source = TestFdSource;

        let registration = handle
            .register(&source, Interest::READABLE, waker)
            .expect("register source");
        let token = registration.token();

        runtime
            .lab_reactor()
            .inject_event(token, Event::readable(token), Duration::from_millis(1));
        runtime.advance_time(1_000_000);
        runtime.step_for_test();

        let mut saw_requested = false;
        let mut saw_ready = false;
        for event in runtime.state.trace.snapshot() {
            if event.kind == TraceEventKind::IoRequested {
                saw_requested = true;
            }
            if event.kind == TraceEventKind::IoReady {
                saw_ready = true;
            }
        }
        crate::assert_with_log!(
            saw_requested,
            "io requested trace recorded",
            true,
            saw_requested
        );
        crate::assert_with_log!(saw_ready, "io ready trace recorded", true, saw_ready);
        crate::test_complete!("lab_runtime_records_io_ready_trace");
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
    fn deterministic_multiworker_schedule() {
        init_test("deterministic_multiworker_schedule");
        let config = LabConfig::new(7).worker_count(4);

        crate::lab::assert_deterministic(config, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            for _ in 0..4 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async {
                        crate::runtime::yield_now::yield_now().await;
                    })
                    .expect("create task");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }
            runtime.run_until_quiescent();
        });

        crate::test_complete!("deterministic_multiworker_schedule");
    }

    #[test]
    fn run_until_quiescent_with_report_is_deterministic() {
        init_test("run_until_quiescent_with_report_is_deterministic");

        let config = LabConfig::new(123).worker_count(4).max_steps(10_000);
        let mut r1 = LabRuntime::new(config.clone());
        let mut r2 = LabRuntime::new(config);

        let setup = |runtime: &mut LabRuntime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            for _ in 0..4 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async {
                        crate::runtime::yield_now::yield_now().await;
                    })
                    .expect("create task");
                runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            }
        };

        setup(&mut r1);
        setup(&mut r2);

        let rep1 = r1.run_until_quiescent_with_report();
        let rep2 = r2.run_until_quiescent_with_report();

        crate::assert_with_log!(rep1.quiescent, "quiescent", true, rep1.quiescent);
        crate::assert_with_log!(rep2.quiescent, "quiescent", true, rep2.quiescent);

        assert_eq!(rep1.trace_fingerprint, rep2.trace_fingerprint);
        assert_eq!(rep1.trace_certificate, rep2.trace_certificate);
        assert_eq!(rep1.oracle_report.to_json(), rep2.oracle_report.to_json());
        assert_eq!(rep1.invariant_violations, rep2.invariant_violations);

        crate::assert_with_log!(
            rep1.oracle_report.all_passed(),
            "oracles passed",
            true,
            rep1.oracle_report.all_passed()
        );
        crate::assert_with_log!(
            rep2.oracle_report.all_passed(),
            "oracles passed",
            true,
            rep2.oracle_report.all_passed()
        );

        crate::test_complete!("run_until_quiescent_with_report_is_deterministic");
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
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };

        runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
            warnings_clone.lock().unwrap().push(warning);
        });

        let root = runtime.state.create_root_region(Budget::INFINITE);
        let budget = Budget::new().with_deadline(Time::from_millis(10));

        let task_idx = runtime.state.insert_task(TaskRecord::new_with_time(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            budget,
            runtime.state.now,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let mut inner = CxInner::new(root, task_id, budget);
        inner.checkpoint_state.last_checkpoint = None;
        runtime
            .state
            .task_mut(task_id)
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
        drop(warnings);
        crate::test_complete!("deadline_monitor_emits_warning");
    }

    #[test]
    fn deadline_monitor_e2e_stuck_detection() {
        init_test("deadline_monitor_e2e_stuck_detection");
        let mut runtime = LabRuntime::with_seed(42);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_clone = Arc::clone(&warnings);

        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::ZERO,
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };

        runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
            warnings_clone.lock().unwrap().push(warning);
        });

        let root = runtime.state.create_root_region(Budget::INFINITE);
        let budget = Budget::new().with_deadline(Time::from_secs(10));
        let (task_id, _handle) = runtime
            .state
            .create_task(root, budget, async {})
            .expect("create task");

        {
            let task = runtime.state.task_mut(task_id).unwrap();
            let cx = task.cx.as_ref().expect("task cx");
            cx.checkpoint_with("starting work").expect("checkpoint");
        }

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
            warning.reason == WarningReason::NoProgress,
            "reason",
            WarningReason::NoProgress,
            warning.reason
        );
        crate::assert_with_log!(
            warning.last_checkpoint_message.as_deref() == Some("starting work"),
            "checkpoint message",
            Some("starting work"),
            warning.last_checkpoint_message.as_deref()
        );
        drop(warnings);
        crate::test_complete!("deadline_monitor_e2e_stuck_detection");
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
        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        // Create a pending obligation held by that task.
        let obl_id = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        for _ in 0..4 {
            runtime.step();
        }

        let futurelock = runtime
            .trace()
            .snapshot()
            .into_iter()
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

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let _ = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

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

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let obl_id = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        runtime
            .state
            .task_mut(task_id)
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

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let obl_id = runtime
            .state
            .create_obligation(ObligationKind::Ack, task_id, root, None)
            .expect("create obligation");
        runtime
            .state
            .commit_obligation(obl_id)
            .expect("commit obligation");

        runtime
            .state
            .task_mut(task_id)
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
    #[allow(clippy::too_many_lines)]
    fn obligation_trace_events_emitted() {
        init_test("obligation_trace_events_emitted");
        let mut runtime = LabRuntime::with_seed(21);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        runtime.advance_time_to(Time::from_nanos(10));
        let ob1 = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .unwrap();

        runtime.advance_time_to(Time::from_nanos(25));
        runtime.state.commit_obligation(ob1).unwrap();

        runtime.advance_time_to(Time::from_nanos(30));
        let ob2 = runtime
            .state
            .create_obligation(ObligationKind::Ack, task_id, root, None)
            .unwrap();

        runtime.advance_time_to(Time::from_nanos(50));
        runtime
            .state
            .abort_obligation(ob2, ObligationAbortReason::Cancel)
            .unwrap();

        let commit_event = runtime
            .trace()
            .snapshot()
            .into_iter()
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
            .snapshot()
            .into_iter()
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

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        runtime.advance_time_to(Time::from_nanos(100));
        let obligation = runtime
            .state
            .create_obligation(ObligationKind::Lease, task_id, root, None)
            .unwrap();

        runtime.advance_time_to(Time::from_nanos(140));
        runtime
            .state
            .task_mut(task_id)
            .unwrap()
            .complete(Outcome::Ok(()));

        let violations = runtime.check_invariants();
        let has_leak = violations
            .iter()
            .any(|v| matches!(v, InvariantViolation::ObligationLeak { .. }));
        crate::assert_with_log!(has_leak, "has leak", true, has_leak);

        let leak_event = runtime
            .trace()
            .snapshot()
            .into_iter()
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
