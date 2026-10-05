//! Bounded native scheduler capture and admission to task-order replay.
//!
//! Enabled through [`crate::runtime::RuntimeBuilder::capture_schedules`]. The
//! runtime's existing trace ring carries canonical task events; this module
//! adds bounded worker context without changing the event wire schema. A
//! snapshot can expose a partial run for diagnosis, but its checked projection
//! refuses eviction, missing scheduler context, and unfinished task lifecycles.
//!
//! A complete capture records poll-entry order. Concurrent polls can overlap,
//! and neither I/O results nor arbitrary user effects are reproduced by this
//! projection. Reconstruct the workload and external inputs before driving it
//! with the Lab's strict production replay API.
//!
//! `Runtime::block_on` registers its caller's root future as a task, for
//! ownership and cancellation, but the caller's thread polls that future
//! itself. No worker ever dispatches it, so the Lab cannot recreate it as a
//! scheduled task. The recorder notes these caller tasks, and the checked
//! projection leaves their observations out: in a replay, the harness plays
//! the caller's part, as it supplies any other external input.

use super::buffer::TraceBufferHandle;
use super::event::{TraceData, TraceEvent, TraceEventKind};
use super::replay::{CompactTaskId, ProductionSchedule, ProjectionError};
use crate::types::{Severity, TaskId};
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Worker context attached to one canonical scheduler observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerEventContext {
    /// Sequence in the runtime's shared trace ring.
    pub event_sequence: u64,
    /// Scheduler worker executing the observation. Wake delivery uses `None`:
    /// the caller may be outside this runtime, so it must not borrow a worker's
    /// identity from unrelated thread-local state.
    pub worker_id: Option<usize>,
    /// Monotone ordinal for this worker, or for unattributed wake deliveries.
    pub worker_sequence: u64,
}

/// A point-in-time native capture with its retention evidence.
///
/// Events and contexts are immutable so the checked projection refers to the
/// exact snapshot whose insertion count was sampled. This receipt covers the
/// runtime trace ring; it is not proof of external inputs or replayed effects.
#[derive(Debug, Clone)]
pub struct ScheduleCaptureSnapshot {
    events: Vec<TraceEvent>,
    contexts: Vec<SchedulerEventContext>,
    caller_tasks: Vec<TaskId>,
    /// Terminal outcome kept for each retained Complete event, by sequence.
    completion_outcomes: BTreeMap<u64, Severity>,
    /// [`Self::completion_outcomes`] by task, without caller tasks.
    terminal_outcomes: Vec<(TaskId, Severity)>,
    total_events: u64,
    capacity: usize,
    worker_count: usize,
}

impl ScheduleCaptureSnapshot {
    /// Canonical events retained at the snapshot boundary, ordered by sequence.
    ///
    /// This includes the observations of [`Self::caller_tasks`], which the
    /// checked projection leaves out.
    #[must_use]
    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    /// Tasks that own a `Runtime::block_on` caller's root future and appear
    /// in [`Self::events`], in ascending order.
    ///
    /// The caller's thread polls such a future itself; no worker dispatches
    /// it. [`Self::production_schedule`] therefore leaves these tasks'
    /// observations out, and a replay harness supplies the caller's effects
    /// as external input.
    #[must_use]
    pub fn caller_tasks(&self) -> &[TaskId] {
        &self.caller_tasks
    }

    /// Terminal outcome of every task whose completion is in [`Self::events`],
    /// except [`Self::caller_tasks`], in ascending task order.
    ///
    /// The runtime keeps each outcome beside its Complete event while the
    /// capture is enabled, and [`Self::production_schedule`] carries them into
    /// the projected completions, so a strict replay can compare them
    /// (br-asupersync-bi2462.8).
    ///
    /// An outcome is the runtime's record of how the task ended. A task whose
    /// future panicked is recorded Panicked whichever API spawned it:
    /// `RuntimeHandle::spawn` also re-raises the payload on its
    /// `JoinHandle`, and a Lab reconstruction made with
    /// `RuntimeState::create_task` records Panicked too (asupersync-6hewgp).
    #[must_use]
    pub fn terminal_outcomes(&self) -> &[(TaskId, Severity)] {
        &self.terminal_outcomes
    }

    /// Worker context for scheduler observations still present in `events`.
    #[must_use]
    pub fn contexts(&self) -> &[SchedulerEventContext] {
        &self.contexts
    }

    /// Total canonical observations inserted since the runtime trace was made.
    #[must_use]
    pub const fn total_events(&self) -> u64 {
        self.total_events
    }

    /// Number of canonical observations evicted before this snapshot.
    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.total_events.saturating_sub(self.events.len() as u64)
    }

    /// Maximum retained event count and maximum retained worker-context count.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of native scheduler workers represented by the recorder.
    #[must_use]
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Builds a production task-order projection only when every recorded task
    /// completed, all inserted observations are retained, and actual polls exist.
    ///
    /// Numerical sequence gaps are allowed: the runtime may reserve a sequence
    /// without inserting an event. The atomic insertion count detects ring
    /// eviction independently of those gaps. This does not attest source-runtime
    /// quiescence or the absence of pending admissions: a snapshot can precede
    /// the next task's admission. Runtime quiescence and effects must still be
    /// checked by the strict replay driver after reconstruction.
    ///
    /// Observations of [`Self::caller_tasks`] are left out of the lifecycle
    /// checks and the projection: a `block_on` caller's root future is not
    /// scheduled work, and a live caller does not make the capture partial.
    ///
    /// Each projected completion carries its task's kept terminal outcome
    /// ([`Self::terminal_outcomes`]), and the strict replay driver compares
    /// them.
    ///
    /// # Errors
    /// Refuses truncated or malformed observations, absent worker context,
    /// unfinished task lifecycles, a completion without a kept outcome, or a
    /// trace without actual task polls.
    pub fn production_schedule(&self) -> Result<ProductionSchedule, ScheduleCaptureError> {
        let dropped_events = self.dropped_events();
        if dropped_events != 0 {
            return Err(ScheduleCaptureError::Truncated { dropped_events });
        }
        if let Some(pair) = self
            .events
            .windows(2)
            .find(|pair| pair[1].seq <= pair[0].seq)
        {
            return Err(ScheduleCaptureError::SourceOrder {
                previous: pair[0].seq,
                next: pair[1].seq,
            });
        }
        let scheduled: Vec<TraceEvent> = self
            .events
            .iter()
            .filter(|event| {
                !matches!(&event.data, TraceData::Task { task, .. }
                    if self.caller_tasks.binary_search(task).is_ok())
            })
            .cloned()
            .collect();
        let mut live = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut outcomes = BTreeMap::new();
        let mut polls = 0usize;
        for event in &scheduled {
            if event.kind == TraceEventKind::Complete
                && let TraceData::Task { task, .. } = &event.data
            {
                let Some(outcome) = self.completion_outcomes.get(&event.seq) else {
                    return Err(ScheduleCaptureError::MissingOutcome {
                        seq: event.seq,
                        task: *task,
                    });
                };
                outcomes.insert(CompactTaskId::from(*task).0, *outcome);
            }
            if is_scheduler_observation(event.kind)
                && self
                    .contexts
                    .binary_search_by_key(&event.seq, |context| context.event_sequence)
                    .is_err()
            {
                return Err(ScheduleCaptureError::MissingSchedulerContext { seq: event.seq });
            }
            if let TraceData::Task { task, .. } = &event.data {
                let valid = match event.kind {
                    TraceEventKind::Spawn => seen.insert(*task) && live.insert(*task),
                    TraceEventKind::Complete => live.remove(task),
                    TraceEventKind::Poll => {
                        polls += 1;
                        live.contains(task)
                    }
                    TraceEventKind::Schedule | TraceEventKind::Yield => live.contains(task),
                    // A cached waker may be invoked after task retirement.
                    TraceEventKind::Wake => seen.contains(task),
                    _ => true,
                };
                if !valid {
                    return Err(ScheduleCaptureError::TaskLifecycle {
                        seq: event.seq,
                        task: *task,
                    });
                }
            }
        }
        if polls == 0 {
            return Err(ScheduleCaptureError::NoPolls);
        }
        if !live.is_empty() {
            return Err(ScheduleCaptureError::UnfinishedTasks { count: live.len() });
        }
        ProductionSchedule::from_runtime_trace(&scheduled)
            .map(|schedule| schedule.with_completion_outcomes(&outcomes))
            .map_err(ScheduleCaptureError::Projection)
    }
}

/// Why a native capture cannot authorize strict task-order replay.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScheduleCaptureError {
    /// The bounded trace ring overwrote observations.
    #[error("native schedule capture evicted {dropped_events} events")]
    Truncated {
        /// Number of lost canonical observations.
        dropped_events: u64,
    },
    /// Observations have duplicate or reversed sequence numbers.
    #[error("native schedule capture sequence is not increasing: {previous} then {next}")]
    SourceOrder {
        /// Earlier observation's sequence.
        previous: u64,
        /// Following observation's sequence.
        next: u64,
    },
    /// A scheduler event is not backed by this recorder's context.
    #[error("native scheduler context missing at sequence {seq}")]
    MissingSchedulerContext {
        /// Sequence of the unsupported observation.
        seq: u64,
    },
    /// No actual future polls were captured.
    #[error("native schedule capture contains no task polls")]
    NoPolls,
    /// A task acted outside its captured spawn/completion lifetime.
    #[error("native task {task:?} has an invalid lifecycle at sequence {seq}")]
    TaskLifecycle {
        /// Sequence at which the task lifetime became invalid.
        seq: u64,
        /// Affected task identity.
        task: TaskId,
    },
    /// The snapshot was taken before all recorded tasks completed.
    #[error("native schedule capture still has {count} unfinished tasks")]
    UnfinishedTasks {
        /// Number of tasks without a terminal observation.
        count: usize,
    },
    /// A task completion has no kept terminal outcome, so its outcome would
    /// be unverifiable rather than reported as success.
    #[error("native task {task:?} completed at sequence {seq} without a kept outcome")]
    MissingOutcome {
        /// Sequence of the Complete observation.
        seq: u64,
        /// Affected task identity.
        task: TaskId,
    },
    /// The retained source cannot be projected into spawn/poll order.
    #[error(transparent)]
    Projection(#[from] ProjectionError),
}

fn is_scheduler_observation(kind: TraceEventKind) -> bool {
    matches!(
        kind,
        TraceEventKind::Schedule
            | TraceEventKind::Poll
            | TraceEventKind::Wake
            | TraceEventKind::Yield
            | TraceEventKind::CancelAck
    )
}

#[derive(Debug)]
struct CaptureContext {
    events: VecDeque<SchedulerEventContext>,
    worker_sequences: Vec<u64>,
    external_sequence: u64,
    /// Registered `block_on` caller tasks, oldest first. Every caller task has
    /// a Spawn in the ring, so at most `capacity` of them can still be
    /// visible; the queue keeps that many.
    caller_tasks: VecDeque<TaskId>,
}

/// One recorder is installed before the builder returns any runtime handles.
/// It owns only the trace ring, so captured wakers cannot retain a runtime.
#[derive(Debug)]
pub(crate) struct ScheduleCaptureRecorder {
    trace: TraceBufferHandle,
    capacity: usize,
    worker_count: usize,
    context: Mutex<CaptureContext>,
}

impl ScheduleCaptureRecorder {
    pub(crate) fn new(trace: TraceBufferHandle, worker_count: usize) -> Self {
        trace.enable_completion_outcomes();
        Self {
            capacity: trace.capacity(),
            trace,
            worker_count,
            context: Mutex::new(CaptureContext {
                events: VecDeque::new(),
                worker_sequences: vec![0; worker_count],
                external_sequence: 0,
                caller_tasks: VecDeque::new(),
            }),
        }
    }

    /// Notes that `task` owns a `block_on` caller's root future, which the
    /// caller's thread polls itself.
    pub(crate) fn note_caller_task(&self, task: TaskId) {
        let mut context = self.context.lock();
        if context.caller_tasks.len() == self.capacity {
            context.caller_tasks.pop_front();
        }
        context.caller_tasks.push_back(task);
    }

    pub(crate) fn record(&self, worker: Option<usize>, build: impl FnOnce(u64) -> TraceEvent) {
        // Lock order is always context -> trace. Ordinary trace producers do
        // not acquire this context, and snapshot takes the same lock order.
        let mut context = self.context.lock();
        let ordinal = if let Some(worker) = worker {
            &mut context.worker_sequences[worker]
        } else {
            &mut context.external_sequence
        };
        let worker_sequence = *ordinal;
        *ordinal = ordinal.saturating_add(1);
        self.trace.record_event(|seq| {
            let event = build(seq);
            debug_assert!(is_scheduler_observation(event.kind));
            debug_assert_eq!(event.seq, seq);
            if context.events.len() == self.capacity {
                context.events.pop_front();
            }
            context.events.push_back(SchedulerEventContext {
                event_sequence: seq,
                worker_id: worker,
                worker_sequence,
            });
            event
        });
    }

    pub(crate) fn snapshot(&self) -> ScheduleCaptureSnapshot {
        let context = self.context.lock();
        let (events, total_events, kept_outcomes) = self.trace.snapshot_with_outcomes();
        let contexts = context
            .events
            .iter()
            .filter(|entry| {
                events
                    .binary_search_by_key(&entry.event_sequence, |event| event.seq)
                    .is_ok()
            })
            .copied()
            .collect();
        let noted: BTreeSet<TaskId> = context.caller_tasks.iter().copied().collect();
        let caller_tasks = events
            .iter()
            .filter_map(|event| match &event.data {
                TraceData::Task { task, .. } if noted.contains(task) => Some(*task),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let kept: BTreeMap<u64, Severity> = kept_outcomes.into_iter().collect();
        let mut completion_outcomes = BTreeMap::new();
        let mut terminal_outcomes = Vec::new();
        for event in &events {
            if event.kind == TraceEventKind::Complete
                && let TraceData::Task { task, .. } = &event.data
                && let Some(outcome) = kept.get(&event.seq)
            {
                completion_outcomes.insert(event.seq, *outcome);
                if caller_tasks.binary_search(task).is_err() {
                    terminal_outcomes.push((*task, *outcome));
                }
            }
        }
        terminal_outcomes.sort_by_key(|(task, _)| *task);
        ScheduleCaptureSnapshot {
            events,
            contexts,
            caller_tasks,
            completion_outcomes,
            terminal_outcomes,
            total_events,
            capacity: self.capacity,
            worker_count: self.worker_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{RegionId, Time};

    fn ids() -> (TaskId, RegionId) {
        (TaskId::new_for_test(0, 1), RegionId::new_for_test(0, 1))
    }

    #[test]
    fn capture_receipt_accepts_completed_polls_and_reserved_sequence_gaps() {
        let trace = TraceBufferHandle::new(16);
        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 2);
        let (task, region) = ids();
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        let _unused = trace.next_seq();
        recorder.record(Some(1), |seq| {
            TraceEvent::schedule(seq, Time::ZERO, task, region)
        });
        recorder.record(Some(1), |seq| {
            TraceEvent::poll(seq, Time::ZERO, task, region)
        });
        trace.record_completion_event(Severity::Ok, |seq| {
            TraceEvent::complete(seq, Time::ZERO, task, region)
        });
        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.total_events(), 4);
        assert_eq!(snapshot.dropped_events(), 0);
        assert_eq!(snapshot.contexts().len(), 2);
        assert_eq!(snapshot.contexts()[1].worker_sequence, 1);
        assert_eq!(snapshot.contexts()[1].worker_id, Some(1));
        assert_eq!(snapshot.production_schedule().unwrap().summary().steps, 1);
    }

    #[test]
    fn capture_receipt_rejects_partial_runs_and_ring_eviction() {
        let trace = TraceBufferHandle::new(3);
        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
        let (task, region) = ids();
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        recorder.record(Some(0), |seq| {
            TraceEvent::poll(seq, Time::ZERO, task, region)
        });
        assert_eq!(
            recorder.snapshot().production_schedule().unwrap_err(),
            ScheduleCaptureError::UnfinishedTasks { count: 1 }
        );
        recorder.record(Some(0), |seq| {
            TraceEvent::yield_task(seq, Time::ZERO, task, region)
        });
        recorder.record(None, |seq| TraceEvent::wake(seq, Time::ZERO, task, region));
        trace.record_completion_event(Severity::Ok, |seq| {
            TraceEvent::complete(seq, Time::ZERO, task, region)
        });
        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.total_events(), 5);
        assert_eq!(snapshot.dropped_events(), 2);
        assert!(snapshot.contexts().len() <= snapshot.capacity());
        assert_eq!(
            snapshot.production_schedule().unwrap_err(),
            ScheduleCaptureError::Truncated { dropped_events: 2 }
        );
    }

    #[test]
    fn capture_projection_leaves_out_block_on_caller_tasks() {
        let trace = TraceBufferHandle::new(16);
        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
        let (task, region) = ids();
        let caller = TaskId::new_for_test(1, 1);
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, caller, region));
        recorder.record(Some(0), |seq| {
            TraceEvent::poll(seq, Time::ZERO, task, region)
        });
        recorder.record(None, |seq| {
            TraceEvent::wake(seq, Time::ZERO, caller, region)
        });
        trace.record_completion_event(Severity::Ok, |seq| {
            TraceEvent::complete(seq, Time::ZERO, task, region)
        });

        // Unnoted, the caller's root looks like a scheduled task that never
        // finished: it is still inside block_on.
        let unnoted = recorder.snapshot();
        assert!(unnoted.caller_tasks().is_empty());
        assert_eq!(
            unnoted.production_schedule().unwrap_err(),
            ScheduleCaptureError::UnfinishedTasks { count: 1 }
        );

        // Noted, it is left out of the projection; a noted task without
        // retained observations is not reported.
        recorder.note_caller_task(caller);
        recorder.note_caller_task(TaskId::new_for_test(9, 1));
        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.caller_tasks(), &[caller]);
        assert_eq!(snapshot.events().len(), 5);
        let schedule = snapshot.production_schedule().unwrap();
        assert_eq!(schedule.summary().spawned, 1);
        assert_eq!(schedule.summary().steps, 1);
        assert_eq!(
            schedule.spawn_order(),
            &[crate::trace::replay::CompactTaskId::from(task)]
        );
    }

    /// br-asupersync-bi2462.8: the kept terminal outcome reaches the
    /// projected completion, a caller task's outcome is left out, and a
    /// completion without a kept outcome is refused instead of reading as Ok.
    #[test]
    fn capture_projection_carries_terminal_outcomes_and_refuses_missing_ones() {
        use crate::trace::replay::ReplayEvent;
        let trace = TraceBufferHandle::new(16);
        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
        let (task, region) = ids();
        let caller = TaskId::new_for_test(1, 1);
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, caller, region));
        recorder.record(Some(0), |seq| {
            TraceEvent::poll(seq, Time::ZERO, task, region)
        });
        trace.record_completion_event(Severity::Cancelled, |seq| {
            TraceEvent::complete(seq, Time::ZERO, task, region)
        });
        trace.record_completion_event(Severity::Panicked, |seq| {
            TraceEvent::complete(seq, Time::ZERO, caller, region)
        });
        recorder.note_caller_task(caller);
        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.terminal_outcomes(), &[(task, Severity::Cancelled)]);
        let schedule = snapshot.production_schedule().unwrap();
        assert!(schedule.carries_outcomes());
        let compact = crate::trace::replay::CompactTaskId::from(task);
        assert_eq!(
            schedule.captured_outcome(compact),
            Some(Severity::Cancelled)
        );
        assert!(schedule.trace().events.iter().any(|event| matches!(
            event,
            ReplayEvent::TaskCompleted { task: completed, outcome: 2 } if *completed == compact
        )));

        // A Complete written without its outcome cannot be projected.
        let bare = TraceBufferHandle::new(16);
        let recorder = ScheduleCaptureRecorder::new(bare.clone(), 1);
        bare.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        recorder.record(Some(0), |seq| {
            TraceEvent::poll(seq, Time::ZERO, task, region)
        });
        bare.record_event(|seq| TraceEvent::complete(seq, Time::ZERO, task, region));
        assert_eq!(
            recorder.snapshot().production_schedule().unwrap_err(),
            ScheduleCaptureError::MissingOutcome { seq: 2, task }
        );
        // A projection built from the trace alone claims no outcomes.
        let plain = ProductionSchedule::from_runtime_trace(recorder.snapshot().events()).unwrap();
        assert!(!plain.carries_outcomes());
        assert_eq!(plain.captured_outcome(compact), None);
    }

    #[test]
    fn capture_receipt_refuses_unbacked_poll_observations() {
        let trace = TraceBufferHandle::new(8);
        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
        let (task, region) = ids();
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        trace.record_event(|seq| TraceEvent::poll(seq, Time::ZERO, task, region));
        trace.record_completion_event(Severity::Ok, |seq| {
            TraceEvent::complete(seq, Time::ZERO, task, region)
        });
        assert_eq!(
            recorder.snapshot().production_schedule().unwrap_err(),
            ScheduleCaptureError::MissingSchedulerContext { seq: 1 }
        );
    }

    #[test]
    fn concurrent_capture_snapshot_keeps_counts_and_context_atomic() {
        let trace = TraceBufferHandle::new(7);
        let recorder = std::sync::Arc::new(ScheduleCaptureRecorder::new(trace.clone(), 2));
        let (task, region) = ids();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..256 {
                    trace.record_event(|seq| TraceEvent::user_trace(seq, Time::ZERO, "ordinary"));
                }
            });
            for worker in 0..2 {
                let recorder = recorder.clone();
                scope.spawn(move || {
                    for _ in 0..256 {
                        recorder.record(Some(worker), |seq| {
                            TraceEvent::poll(seq, Time::ZERO, task, region)
                        });
                    }
                });
            }
            for _ in 0..256 {
                let snapshot = recorder.snapshot();
                assert_eq!(
                    snapshot.total_events(),
                    snapshot.events().len() as u64 + snapshot.dropped_events()
                );
                // This source allocates no unused sequences. Even ordinary
                // producers must publish their count with their ring write.
                assert_eq!(
                    snapshot.total_events(),
                    snapshot.events().last().map_or(0, |event| event.seq + 1)
                );
                let scheduler_events: Vec<_> = snapshot
                    .events()
                    .iter()
                    .filter(|event| is_scheduler_observation(event.kind))
                    .collect();
                assert_eq!(snapshot.contexts().len(), scheduler_events.len());
                for (event, context) in scheduler_events.iter().zip(snapshot.contexts()) {
                    assert_eq!(event.seq, context.event_sequence);
                }
            }
        });
        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.total_events(), 768);
        assert_eq!(snapshot.dropped_events(), 761);
    }
}
