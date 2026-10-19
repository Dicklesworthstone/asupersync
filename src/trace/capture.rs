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

use super::buffer::{CancellationPublicationSnapshot, TraceBufferHandle};
use super::event::{TraceData, TraceEvent, TraceEventKind};
use super::replay::{
    CompactRegionId, CompactTaskId, ProductionCancellationEvent, ProductionCancellationPhase,
    ProductionSchedule, ProjectionError,
};
use crate::types::{Budget, CancelReason, Severity, TaskId};
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

mod archive;
pub use archive::{
    ScheduleCaptureArchive, ScheduleCaptureArchiveError, ScheduleCaptureArchiveLimits,
};

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
    cancellation_publications: CancellationPublicationSnapshot,
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

    /// Builds a checked task-order projection that also injects witnessed task
    /// cancellation requests and checks checkpoint acknowledgements on replay.
    ///
    /// The native runtime currently witnesses region and sibling cancellation
    /// publication. A request is admitted only when its entire publication span
    /// lies between all worker polls; recording a Request after publishing a Cx
    /// flag is insufficient evidence on its own. Acknowledgements retain their
    /// originating task-poll ordinal through their worker context, even if the
    /// same task has already been polled again by another worker.
    ///
    /// This captures task cancellation, with its full reason and effective
    /// cleanup budget. The harness still reconstructs region lifecycle effects,
    /// external inputs, and user effects. Direct Cx cancellation, task-handle
    /// aborts, deadline publication, and unrecorded reason/budget strengthening
    /// are not covered: missing or inconsistent evidence is refused. Every
    /// completion must also carry an authoritative terminal task-Cx witness, so
    /// a silent cancellation followed by an Ok result cannot attest absence of
    /// cancellation. Caller tasks remain external harness work, as in
    /// [`Self::production_schedule`].
    ///
    /// # Errors
    /// Includes all [`Self::production_schedule`] refusals, plus incomplete or
    /// evicted publication witnesses, publication overlapping a native poll,
    /// unrecorded cancellation, reason drift, and acknowledgement order that a
    /// serial Lab execution cannot reproduce.
    pub fn production_schedule_with_cancellation(
        &self,
    ) -> Result<ProductionSchedule, ScheduleCaptureError> {
        let schedule = self.production_schedule()?;
        let cancellations = project_cancellation_events(self)?;
        Ok(schedule.with_cancellation_events(cancellations))
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
    /// Publication witnesses were evicted independently of canonical events.
    #[error("native cancellation capture evicted {dropped_spans} publication witnesses")]
    CancellationWitnessesTruncated {
        /// Number of publication spans whose evidence was lost.
        dropped_spans: u64,
    },
    /// A request lacks a complete, supported publication witness.
    #[error("native task {task:?} has unsupported cancellation publication at sequence {seq}: {reason}")]
    CancellationPublication {
        /// Request or publication-start sequence.
        seq: u64,
        /// Target task.
        task: TaskId,
        /// The missing or unsupported evidence.
        reason: &'static str,
    },
    /// Cancellation became visible while a worker could execute user code.
    #[error("native task {task:?} cancellation at sequence {seq} overlaps a poll of {polling_task:?}")]
    CancellationDuringPoll {
        /// Request sequence.
        seq: u64,
        /// Target task.
        task: TaskId,
        /// Task whose poll intersects the publication span.
        polling_task: TaskId,
    },
    /// Cancellation observations cannot be reproduced in captured poll order.
    #[error("native task {task:?} has invalid cancellation order at sequence {seq}: {reason}")]
    CancellationOrder {
        /// Unsupported observation sequence.
        seq: u64,
        /// Target task.
        task: TaskId,
        /// The lifecycle, attribution, or serial-order inconsistency.
        reason: &'static str,
    },
    /// An acknowledgement or cancelled completion has no captured request.
    #[error("native task {task:?} has cancellation at sequence {seq} without a witnessed request")]
    MissingCancellationRequest {
        /// Acknowledgement or completion sequence.
        seq: u64,
        /// Target task.
        task: TaskId,
    },
    /// A canonical cancellation kind carries an incompatible payload.
    #[error("native cancellation event at sequence {seq} has no cancellation payload")]
    InvalidCancellationEvent {
        /// Malformed event sequence.
        seq: u64,
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

/// Source intervals are closed by Yield or Complete. Keeping their full extent
/// catches a poll that both starts and finishes before Request is finally
/// recorded, while the cancellation publisher is between its flag write and
/// trace insertion.
fn captured_poll_intervals(
    snapshot: &ScheduleCaptureSnapshot,
) -> Result<Vec<(u64, u64, TaskId)>, ScheduleCaptureError> {
    let mut active = BTreeMap::new();
    let mut intervals = Vec::new();
    for event in &snapshot.events {
        let TraceData::Task { task, .. } = &event.data else {
            continue;
        };
        if snapshot.caller_tasks.binary_search(task).is_ok() {
            continue;
        }
        match event.kind {
            TraceEventKind::Poll => {
                if active.insert(*task, event.seq).is_some() {
                    return Err(ScheduleCaptureError::CancellationOrder {
                        seq: event.seq,
                        task: *task,
                        reason: "task entered another poll before its previous poll ended",
                    });
                }
            }
            TraceEventKind::Yield | TraceEventKind::Complete => {
                if let Some(start) = active.remove(task) {
                    intervals.push((start, event.seq, *task));
                } else if event.kind == TraceEventKind::Yield {
                    return Err(ScheduleCaptureError::CancellationOrder {
                        seq: event.seq,
                        task: *task,
                        reason: "task yielded without a captured poll",
                    });
                }
            }
            _ => {}
        }
    }
    intervals.sort_unstable_by_key(|interval| interval.0);
    Ok(intervals)
}

fn witnessed_request_budgets(
    snapshot: &ScheduleCaptureSnapshot,
) -> Result<BTreeMap<u64, Budget>, ScheduleCaptureError> {
    if snapshot.cancellation_publications.dropped_spans != 0 {
        return Err(ScheduleCaptureError::CancellationWitnessesTruncated {
            dropped_spans: snapshot.cancellation_publications.dropped_spans,
        });
    }
    let intervals = captured_poll_intervals(snapshot)?;
    // Prefix maxima make each overlap check logarithmic even when many
    // workers' polls overlap, rather than rescanning every poll per request.
    let mut maximum_end = None;
    let mut prefix_ends = Vec::with_capacity(intervals.len());
    for &(_, end, task) in &intervals {
        if maximum_end.is_none_or(|(previous, _)| end > previous) {
            maximum_end = Some((end, task));
        }
        prefix_ends.push(maximum_end.expect("a poll interval supplies its end"));
    }
    let mut budgets = BTreeMap::new();
    for span in &snapshot.cancellation_publications.spans {
        if snapshot.caller_tasks.binary_search(&span.task).is_ok() {
            continue;
        }
        let refuse = |reason| ScheduleCaptureError::CancellationPublication {
            seq: span.request_sequence.unwrap_or(span.start_sequence),
            task: span.task,
            reason,
        };
        let Some(end) = span.end_sequence else {
            return Err(refuse("publication is unfinished or interrupted"));
        };
        if span.unsupported_mutation {
            return Err(refuse(
                "cancellation was already visible or changed without a supported request",
            ));
        }
        let Some(request_sequence) = span.request_sequence else {
            return Err(refuse("publication has no canonical request"));
        };
        if !(span.start_sequence < request_sequence && request_sequence < end) {
            return Err(refuse("request is outside its publication span"));
        }
        let Some(budget) = span.cleanup_budget else {
            return Err(refuse("effective cleanup budget was not captured"));
        };
        let Ok(event_index) = snapshot
            .events
            .binary_search_by_key(&request_sequence, |event| event.seq)
        else {
            return Err(refuse("canonical request is missing"));
        };
        let event = &snapshot.events[event_index];
        if event.kind != TraceEventKind::CancelRequest
            || !matches!(&event.data, TraceData::Cancel { task, .. } if *task == span.task)
        {
            return Err(refuse("publication identifies a different canonical event"));
        }
        let preceding = intervals.partition_point(|interval| interval.0 < end);
        if preceding > 0 {
            let (poll_end, polling_task) = prefix_ends[preceding - 1];
            if poll_end > span.start_sequence {
                return Err(ScheduleCaptureError::CancellationDuringPoll {
                    seq: request_sequence,
                    task: span.task,
                    polling_task,
                });
            }
        }
        if budgets.insert(request_sequence, budget).is_some() {
            return Err(refuse(
                "canonical request has duplicate publication witnesses",
            ));
        }
    }
    Ok(budgets)
}

fn captured_worker(
    snapshot: &ScheduleCaptureSnapshot,
    seq: u64,
    task: TaskId,
) -> Result<usize, ScheduleCaptureError> {
    let context = snapshot
        .contexts
        .binary_search_by_key(&seq, |context| context.event_sequence)
        .ok()
        .and_then(|index| snapshot.contexts.get(index));
    context
        .and_then(|context| context.worker_id)
        .ok_or(ScheduleCaptureError::CancellationOrder {
            seq,
            task,
            reason: "scheduler observation has no native worker identity",
        })
}

struct CapturedCancellationRequest {
    reason: CancelReason,
    cleanup_budget: Budget,
    last_acknowledged_poll: usize,
}

#[allow(clippy::too_many_lines)]
fn project_cancellation_events(
    snapshot: &ScheduleCaptureSnapshot,
) -> Result<Vec<ProductionCancellationEvent>, ScheduleCaptureError> {
    let budgets = witnessed_request_budgets(snapshot)?;
    let terminals: BTreeMap<_, _> = snapshot
        .cancellation_publications
        .terminals
        .iter()
        .filter_map(|(seq, terminal)| terminal.as_ref().map(|terminal| (*seq, terminal)))
        .collect();
    let mut live = BTreeMap::new();
    let mut last_polls: BTreeMap<TaskId, (usize, usize)> = BTreeMap::new();
    let mut worker_polls: BTreeMap<usize, (TaskId, usize, usize)> = BTreeMap::new();
    let mut requests: BTreeMap<TaskId, CapturedCancellationRequest> = BTreeMap::new();
    let mut dispatches = 0usize;
    let mut last_boundary = None;
    let mut projected = Vec::new();
    for event in &snapshot.events {
        if let TraceData::Task { task, region } = &event.data {
            if snapshot.caller_tasks.binary_search(task).is_ok() {
                continue;
            }
            match event.kind {
                TraceEventKind::Spawn => {
                    live.insert(*task, *region);
                }
                TraceEventKind::Poll => {
                    dispatches += 1;
                    let ordinal = last_polls.get(task).map_or(1, |(ordinal, _)| ordinal + 1);
                    last_polls.insert(*task, (ordinal, dispatches));
                    let worker = captured_worker(snapshot, event.seq, *task)?;
                    worker_polls.insert(worker, (*task, ordinal, dispatches));
                }
                TraceEventKind::Complete => {
                    let Some(terminal) = terminals.get(&event.seq) else {
                        return Err(ScheduleCaptureError::CancellationPublication {
                            seq: event.seq,
                            task: *task,
                            reason: "completion has no authoritative terminal task-Cx witness",
                        });
                    };
                    if terminal.requested {
                        let Some(request) = requests.get(task) else {
                            return Err(ScheduleCaptureError::MissingCancellationRequest {
                                seq: event.seq,
                                task: *task,
                            });
                        };
                        if terminal.reason.as_ref() != Some(&request.reason) {
                            return Err(ScheduleCaptureError::CancellationOrder {
                                seq: event.seq,
                                task: *task,
                                reason: "terminal cancellation reason is missing or differs from the witnessed request",
                            });
                        }
                    } else if terminal.reason.is_some() || requests.contains_key(task) {
                        return Err(ScheduleCaptureError::CancellationOrder {
                            seq: event.seq,
                            task: *task,
                            reason: "terminal cancellation flag disagrees with the captured request or reason",
                        });
                    }
                    if snapshot.completion_outcomes.get(&event.seq) == Some(&Severity::Cancelled)
                        && !requests.contains_key(task)
                    {
                        return Err(ScheduleCaptureError::MissingCancellationRequest {
                            seq: event.seq,
                            task: *task,
                        });
                    }
                    live.remove(task);
                }
                _ => {}
            }
        }
        let phase = match event.kind {
            TraceEventKind::CancelRequest => ProductionCancellationPhase::Request,
            TraceEventKind::CancelAck => ProductionCancellationPhase::Acknowledgement,
            _ => continue,
        };
        let TraceData::Cancel {
            task,
            region,
            reason,
        } = &event.data
        else {
            return Err(ScheduleCaptureError::InvalidCancellationEvent { seq: event.seq });
        };
        if snapshot.caller_tasks.binary_search(task).is_ok() {
            continue;
        }
        let refuse_order = |reason| ScheduleCaptureError::CancellationOrder {
            seq: event.seq,
            task: *task,
            reason,
        };
        if live.get(task) != Some(region) {
            return Err(refuse_order("target is not live in its captured owner region"));
        }
        let preceding_task_polls = last_polls.get(task).map_or(0, |(ordinal, _)| *ordinal);
        let (cleanup_budget, boundary, task_poll_ordinal) = match phase {
            ProductionCancellationPhase::Request => {
                let Some(&cleanup_budget) = budgets.get(&event.seq) else {
                    return Err(ScheduleCaptureError::CancellationPublication {
                        seq: event.seq,
                        task: *task,
                        reason: "request has no witnessed publication span",
                    });
                };
                if requests.contains_key(task) {
                    return Err(refuse_order("repeated or strengthened requests are not supported"));
                }
                requests.insert(
                    *task,
                    CapturedCancellationRequest {
                        reason: reason.clone(),
                        cleanup_budget,
                        last_acknowledged_poll: preceding_task_polls,
                    },
                );
                (cleanup_budget, (dispatches, 1u8), preceding_task_polls)
            }
            ProductionCancellationPhase::Acknowledgement => {
                // Pending futures are restored before their Ack is traced;
                // another worker can already have polled the same task again.
                // This worker's last Poll identifies the actual receipt.
                let worker = captured_worker(snapshot, event.seq, *task)?;
                let Some(&(polling_task, task_poll_ordinal, poll_dispatch)) =
                    worker_polls.get(&worker)
                else {
                    return Err(refuse_order("acknowledgement has no originating worker poll"));
                };
                if polling_task != *task {
                    return Err(refuse_order("acknowledgement does not belong to its worker's latest poll"));
                }
                let Some(request) = requests.get_mut(task) else {
                    return Err(ScheduleCaptureError::MissingCancellationRequest {
                        seq: event.seq,
                        task: *task,
                    });
                };
                if request.reason != *reason {
                    return Err(refuse_order(
                        "acknowledgement reason differs from the witnessed request",
                    ));
                }
                if task_poll_ordinal <= request.last_acknowledged_poll {
                    return Err(refuse_order(
                        "acknowledgement has no new poll after its request or previous acknowledgement",
                    ));
                }
                request.last_acknowledged_poll = task_poll_ordinal;
                (
                    request.cleanup_budget,
                    (poll_dispatch, 0u8),
                    task_poll_ordinal,
                )
            }
        };
        // Native bookkeeping may lag unrelated polls, but it must not cross
        // another cancellation observation in a way serial replay would invert.
        // A poll's Ack precedes a request injected after that same dispatch.
        if last_boundary.is_some_and(|previous| boundary < previous) {
            return Err(refuse_order(
                "cancellation observations invert their originating poll boundaries",
            ));
        }
        last_boundary = Some(boundary);
        projected.push(ProductionCancellationEvent::new(
            event.seq,
            dispatches,
            CompactTaskId::from(*task),
            CompactRegionId::from(*region),
            reason.clone(),
            phase,
            task_poll_ordinal,
            cleanup_budget,
        ));
    }
    Ok(projected)
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
        trace.enable_cancellation_publications();
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
        let (events, total_events, kept_outcomes, cancellation_publications) =
            self.trace.snapshot_with_cancellation_publications();
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
            cancellation_publications,
            total_events,
            capacity: self.capacity,
            worker_count: self.worker_count,
        }
    }
}

#[cfg(test)]
#[path = "capture_inline_tests.rs"]
mod tests;
