//! Trace events and data types.
//!
//! Each event in the trace represents an observable action in the runtime.
//! Events carry sufficient information for replay and analysis.

use crate::monitor::DownReason;
use crate::record::{ObligationAbortReason, ObligationKind, ObligationState};
use crate::trace::distributed::LogicalTime;
use crate::types::{CancelReason, ObligationId, RegionId, TaskId, Time};
use core::fmt;

/// Current schema version for trace events.
pub const TRACE_EVENT_SCHEMA_VERSION: u32 = 1;

/// The kind of trace event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TraceEventKind {
    /// A task was spawned.
    Spawn,
    /// A task was scheduled for execution.
    Schedule,
    /// A task voluntarily yielded.
    Yield,
    /// A task was woken by a waker.
    Wake,
    /// A task was polled.
    Poll,
    /// A task completed.
    Complete,
    /// Cancellation was requested.
    CancelRequest,
    /// Cancellation was acknowledged.
    CancelAck,
    /// A region began closing.
    RegionCloseBegin,
    /// A region completed closing.
    RegionCloseComplete,
    /// A region was created.
    RegionCreated,
    /// A region received a cancellation request.
    RegionCancelled,
    /// An obligation was reserved.
    ObligationReserve,
    /// An obligation was committed.
    ObligationCommit,
    /// An obligation was aborted.
    ObligationAbort,
    /// An obligation was leaked (error).
    ObligationLeak,
    /// Time advanced.
    TimeAdvance,
    /// A timer was scheduled.
    TimerScheduled,
    /// A timer fired.
    TimerFired,
    /// A timer was cancelled.
    TimerCancelled,
    /// I/O interest was requested.
    IoRequested,
    /// I/O became ready.
    IoReady,
    /// I/O result (bytes transferred).
    IoResult,
    /// I/O error injected/observed.
    IoError,
    /// RNG was seeded.
    RngSeed,
    /// RNG value generated.
    RngValue,
    /// Replay checkpoint event.
    Checkpoint,
    /// A task held obligations but stopped being polled (futurelock).
    FuturelockDetected,
    /// Chaos injection occurred.
    ChaosInjection,
    /// User-defined trace point.
    UserTrace,
    /// A monitor was established.
    MonitorCreated,
    /// A monitor was removed.
    MonitorDropped,
    /// A Down notification was delivered.
    DownDelivered,
    /// A link was established.
    LinkCreated,
    /// A link was removed.
    LinkDropped,
    /// An exit signal was delivered to a linked task.
    ExitDelivered,
}

/// Additional data carried by a trace event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceData {
    /// No additional data.
    None,
    /// Task-related data.
    Task {
        /// The task involved.
        task: TaskId,
        /// The region the task belongs to.
        region: RegionId,
    },
    /// Region-related data.
    Region {
        /// The region involved.
        region: RegionId,
        /// The parent region, if any.
        parent: Option<RegionId>,
    },
    /// Obligation-related data.
    Obligation {
        /// The obligation involved.
        obligation: ObligationId,
        /// The task holding the obligation.
        task: TaskId,
        /// The region that owns the obligation.
        region: RegionId,
        /// The kind of obligation.
        kind: ObligationKind,
        /// The obligation state at this event.
        state: ObligationState,
        /// Duration held in nanoseconds, if resolved.
        duration_ns: Option<u64>,
        /// Abort reason, if aborted.
        abort_reason: Option<ObligationAbortReason>,
    },
    /// Cancellation data.
    Cancel {
        /// The task involved.
        task: TaskId,
        /// The region involved.
        region: RegionId,
        /// The reason for cancellation.
        reason: CancelReason,
    },
    /// Region cancellation data.
    RegionCancel {
        /// The region involved.
        region: RegionId,
        /// The reason for cancellation.
        reason: CancelReason,
    },
    /// Time data.
    Time {
        /// The previous time.
        old: Time,
        /// The new time.
        new: Time,
    },
    /// Timer data.
    Timer {
        /// Timer identifier.
        timer_id: u64,
        /// Deadline, if applicable.
        deadline: Option<Time>,
    },
    /// I/O interest request data.
    IoRequested {
        /// I/O token.
        token: u64,
        /// Interest bitflags (readable=1, writable=2, error=4, hangup=8).
        interest: u8,
    },
    /// I/O readiness data.
    IoReady {
        /// I/O token.
        token: u64,
        /// Readiness bitflags (readable=1, writable=2, error=4, hangup=8).
        readiness: u8,
    },
    /// I/O result data.
    IoResult {
        /// I/O token.
        token: u64,
        /// Bytes transferred (negative for errors).
        bytes: i64,
    },
    /// I/O error data.
    IoError {
        /// I/O token.
        token: u64,
        /// Error kind as u8 (maps to io::ErrorKind).
        kind: u8,
    },
    /// RNG seed data.
    RngSeed {
        /// Seed value.
        seed: u64,
    },
    /// RNG value data.
    RngValue {
        /// Generated value.
        value: u64,
    },
    /// Checkpoint data.
    Checkpoint {
        /// Monotonic sequence number.
        sequence: u64,
        /// Active task count.
        active_tasks: u32,
        /// Active region count.
        active_regions: u32,
    },
    /// Futurelock detection data.
    Futurelock {
        /// The task that futurelocked.
        task: TaskId,
        /// The owning region of the task.
        region: RegionId,
        /// How many lab steps since the task was last polled.
        idle_steps: u64,
        /// Obligations held by the task at detection time.
        held: Vec<(ObligationId, ObligationKind)>,
    },
    /// Monitor lifecycle event.
    Monitor {
        /// Monitor reference id.
        monitor_ref: u64,
        /// The task watching for termination.
        watcher: TaskId,
        /// The region owning the watcher (for region-close cleanup).
        watcher_region: RegionId,
        /// The task being monitored.
        monitored: TaskId,
    },
    /// Down notification delivery.
    ///
    /// Includes the deterministic ordering key (`completion_vt`, `monitored`).
    Down {
        /// Monitor reference id from establishment.
        monitor_ref: u64,
        /// The task receiving the notification.
        watcher: TaskId,
        /// The task that terminated.
        monitored: TaskId,
        /// Virtual time of monitored task completion.
        completion_vt: Time,
        /// Why it terminated.
        reason: DownReason,
    },
    /// Link lifecycle event.
    Link {
        /// Link reference id.
        link_ref: u64,
        /// One side of the link.
        task_a: TaskId,
        /// Region owning task_a (for region-close cleanup).
        region_a: RegionId,
        /// The other side of the link.
        task_b: TaskId,
        /// Region owning task_b (for region-close cleanup).
        region_b: RegionId,
    },
    /// Exit signal delivery to a linked task.
    ///
    /// Includes the deterministic ordering key (`failure_vt`, `from`).
    Exit {
        /// Link reference id.
        link_ref: u64,
        /// The task that terminated (source of the exit).
        from: TaskId,
        /// The linked task receiving the exit signal.
        to: TaskId,
        /// Virtual time of failure used for deterministic ordering.
        failure_vt: Time,
        /// Why it terminated.
        reason: DownReason,
    },
    /// User message.
    Message(String),
    /// Chaos injection data.
    Chaos {
        /// Kind of chaos injected (e.g., "cancel", "delay", "budget_exhaust", "wakeup_storm").
        kind: String,
        /// The task affected, if any.
        task: Option<TaskId>,
        /// Additional detail.
        detail: String,
    },
}

/// A trace event in the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    /// Event schema version.
    pub version: u32,
    /// Sequence number (monotonically increasing).
    pub seq: u64,
    /// Timestamp when the event occurred.
    pub time: Time,
    /// Logical clock timestamp for causal ordering.
    ///
    /// When set, enables causal consistency verification across distributed
    /// traces. The logical time is ticked when the event is recorded and
    /// can be used to establish happens-before relationships.
    pub logical_time: Option<LogicalTime>,
    /// The kind of event.
    pub kind: TraceEventKind,
    /// Additional data.
    pub data: TraceData,
}

impl TraceEvent {
    /// Creates a new trace event.
    #[must_use]
    pub fn new(seq: u64, time: Time, kind: TraceEventKind, data: TraceData) -> Self {
        Self {
            version: TRACE_EVENT_SCHEMA_VERSION,
            seq,
            time,
            logical_time: None,
            kind,
            data,
        }
    }

    /// Attaches a logical clock timestamp to this event for causal ordering.
    #[must_use]
    pub fn with_logical_time(mut self, logical_time: LogicalTime) -> Self {
        self.logical_time = Some(logical_time);
        self
    }

    /// Creates a spawn event.
    #[must_use]
    pub fn spawn(seq: u64, time: Time, task: TaskId, region: RegionId) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Spawn,
            TraceData::Task { task, region },
        )
    }

    /// Creates a schedule event.
    #[must_use]
    pub fn schedule(seq: u64, time: Time, task: TaskId, region: RegionId) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Schedule,
            TraceData::Task { task, region },
        )
    }

    /// Creates a yield event.
    #[must_use]
    pub fn yield_task(seq: u64, time: Time, task: TaskId, region: RegionId) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Yield,
            TraceData::Task { task, region },
        )
    }

    /// Creates a wake event.
    #[must_use]
    pub fn wake(seq: u64, time: Time, task: TaskId, region: RegionId) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Wake,
            TraceData::Task { task, region },
        )
    }

    /// Creates a poll event.
    #[must_use]
    pub fn poll(seq: u64, time: Time, task: TaskId, region: RegionId) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Poll,
            TraceData::Task { task, region },
        )
    }

    /// Creates a complete event.
    #[must_use]
    pub fn complete(seq: u64, time: Time, task: TaskId, region: RegionId) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Complete,
            TraceData::Task { task, region },
        )
    }

    /// Creates a cancel request event.
    #[must_use]
    pub fn cancel_request(
        seq: u64,
        time: Time,
        task: TaskId,
        region: RegionId,
        reason: CancelReason,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::CancelRequest,
            TraceData::Cancel {
                task,
                region,
                reason,
            },
        )
    }

    /// Creates a region created event.
    #[must_use]
    pub fn region_created(
        seq: u64,
        time: Time,
        region: RegionId,
        parent: Option<RegionId>,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::RegionCreated,
            TraceData::Region { region, parent },
        )
    }

    /// Creates a region cancelled event.
    #[must_use]
    pub fn region_cancelled(seq: u64, time: Time, region: RegionId, reason: CancelReason) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::RegionCancelled,
            TraceData::RegionCancel { region, reason },
        )
    }

    /// Creates a time advance event.
    #[must_use]
    pub fn time_advance(seq: u64, time: Time, old: Time, new: Time) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::TimeAdvance,
            TraceData::Time { old, new },
        )
    }

    /// Creates a timer scheduled event.
    #[must_use]
    pub fn timer_scheduled(seq: u64, time: Time, timer_id: u64, deadline: Time) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::TimerScheduled,
            TraceData::Timer {
                timer_id,
                deadline: Some(deadline),
            },
        )
    }

    /// Creates a timer fired event.
    #[must_use]
    pub fn timer_fired(seq: u64, time: Time, timer_id: u64) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::TimerFired,
            TraceData::Timer {
                timer_id,
                deadline: None,
            },
        )
    }

    /// Creates a timer cancelled event.
    #[must_use]
    pub fn timer_cancelled(seq: u64, time: Time, timer_id: u64) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::TimerCancelled,
            TraceData::Timer {
                timer_id,
                deadline: None,
            },
        )
    }

    /// Creates an I/O requested event.
    #[must_use]
    pub fn io_requested(seq: u64, time: Time, token: u64, interest: u8) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::IoRequested,
            TraceData::IoRequested { token, interest },
        )
    }

    /// Creates an I/O ready event.
    #[must_use]
    pub fn io_ready(seq: u64, time: Time, token: u64, readiness: u8) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::IoReady,
            TraceData::IoReady { token, readiness },
        )
    }

    /// Creates an I/O result event.
    #[must_use]
    pub fn io_result(seq: u64, time: Time, token: u64, bytes: i64) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::IoResult,
            TraceData::IoResult { token, bytes },
        )
    }

    /// Creates an I/O error event.
    #[must_use]
    pub fn io_error(seq: u64, time: Time, token: u64, kind: u8) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::IoError,
            TraceData::IoError { token, kind },
        )
    }

    /// Creates an RNG seed event.
    #[must_use]
    pub fn rng_seed(seq: u64, time: Time, seed: u64) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::RngSeed,
            TraceData::RngSeed { seed },
        )
    }

    /// Creates an RNG value event.
    #[must_use]
    pub fn rng_value(seq: u64, time: Time, value: u64) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::RngValue,
            TraceData::RngValue { value },
        )
    }

    /// Creates a checkpoint event.
    #[must_use]
    pub fn checkpoint(
        seq: u64,
        time: Time,
        sequence: u64,
        active_tasks: u32,
        active_regions: u32,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Checkpoint,
            TraceData::Checkpoint {
                sequence,
                active_tasks,
                active_regions,
            },
        )
    }

    /// Creates an obligation reserve event.
    #[must_use]
    pub fn obligation_reserve(
        seq: u64,
        time: Time,
        obligation: ObligationId,
        task: TaskId,
        region: RegionId,
        kind: ObligationKind,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::ObligationReserve,
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state: ObligationState::Reserved,
                duration_ns: None,
                abort_reason: None,
            },
        )
    }

    /// Creates an obligation commit event.
    #[must_use]
    pub fn obligation_commit(
        seq: u64,
        time: Time,
        obligation: ObligationId,
        task: TaskId,
        region: RegionId,
        kind: ObligationKind,
        duration_ns: u64,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::ObligationCommit,
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state: ObligationState::Committed,
                duration_ns: Some(duration_ns),
                abort_reason: None,
            },
        )
    }

    /// Creates an obligation abort event.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn obligation_abort(
        seq: u64,
        time: Time,
        obligation: ObligationId,
        task: TaskId,
        region: RegionId,
        kind: ObligationKind,
        duration_ns: u64,
        reason: ObligationAbortReason,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::ObligationAbort,
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state: ObligationState::Aborted,
                duration_ns: Some(duration_ns),
                abort_reason: Some(reason),
            },
        )
    }

    /// Creates an obligation leak event.
    #[must_use]
    pub fn obligation_leak(
        seq: u64,
        time: Time,
        obligation: ObligationId,
        task: TaskId,
        region: RegionId,
        kind: ObligationKind,
        duration_ns: u64,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::ObligationLeak,
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state: ObligationState::Leaked,
                duration_ns: Some(duration_ns),
                abort_reason: None,
            },
        )
    }

    /// Creates a monitor created event.
    #[must_use]
    pub fn monitor_created(
        seq: u64,
        time: Time,
        monitor_ref: u64,
        watcher: TaskId,
        watcher_region: RegionId,
        monitored: TaskId,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::MonitorCreated,
            TraceData::Monitor {
                monitor_ref,
                watcher,
                watcher_region,
                monitored,
            },
        )
    }

    /// Creates a monitor dropped event.
    #[must_use]
    pub fn monitor_dropped(
        seq: u64,
        time: Time,
        monitor_ref: u64,
        watcher: TaskId,
        watcher_region: RegionId,
        monitored: TaskId,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::MonitorDropped,
            TraceData::Monitor {
                monitor_ref,
                watcher,
                watcher_region,
                monitored,
            },
        )
    }

    /// Creates a down delivered event.
    #[must_use]
    pub fn down_delivered(
        seq: u64,
        time: Time,
        monitor_ref: u64,
        watcher: TaskId,
        monitored: TaskId,
        completion_vt: Time,
        reason: DownReason,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::DownDelivered,
            TraceData::Down {
                monitor_ref,
                watcher,
                monitored,
                completion_vt,
                reason,
            },
        )
    }

    /// Creates a link created event.
    #[must_use]
    pub fn link_created(
        seq: u64,
        time: Time,
        link_ref: u64,
        task_a: TaskId,
        region_a: RegionId,
        task_b: TaskId,
        region_b: RegionId,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::LinkCreated,
            TraceData::Link {
                link_ref,
                task_a,
                region_a,
                task_b,
                region_b,
            },
        )
    }

    /// Creates a link dropped event.
    #[must_use]
    pub fn link_dropped(
        seq: u64,
        time: Time,
        link_ref: u64,
        task_a: TaskId,
        region_a: RegionId,
        task_b: TaskId,
        region_b: RegionId,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::LinkDropped,
            TraceData::Link {
                link_ref,
                task_a,
                region_a,
                task_b,
                region_b,
            },
        )
    }

    /// Creates an exit delivered event.
    #[must_use]
    pub fn exit_delivered(
        seq: u64,
        time: Time,
        link_ref: u64,
        from: TaskId,
        to: TaskId,
        failure_vt: Time,
        reason: DownReason,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::ExitDelivered,
            TraceData::Exit {
                link_ref,
                from,
                to,
                failure_vt,
                reason,
            },
        )
    }

    /// Creates a user trace event.
    #[must_use]
    pub fn user_trace(seq: u64, time: Time, message: impl Into<String>) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::UserTrace,
            TraceData::Message(message.into()),
        )
    }
}

impl fmt::Display for TraceEvent {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:06}] {} {:?}", self.seq, self.time, self.kind)?;
        if let Some(ref lt) = self.logical_time {
            write!(f, " @{lt:?}")?;
        }
        match &self.data {
            TraceData::None => {}
            TraceData::Task { task, region } => write!(f, " {task} in {region}")?,
            TraceData::Region { region, parent } => {
                write!(f, " {region}")?;
                if let Some(p) = parent {
                    write!(f, " (parent: {p})")?;
                }
            }
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                write!(
                    f,
                    " {obligation} {kind:?} {state:?} holder={task} region={region}"
                )?;
                if let Some(duration) = duration_ns {
                    write!(f, " duration={duration}ns")?;
                }
                if let Some(reason) = abort_reason {
                    write!(f, " abort_reason={reason}")?;
                }
            }
            TraceData::Cancel {
                task,
                region,
                reason,
            } => write!(f, " {task} in {region} reason={reason}")?,
            TraceData::RegionCancel { region, reason } => {
                write!(f, " {region} reason={reason}")?;
            }
            TraceData::Time { old, new } => write!(f, " {old} -> {new}")?,
            TraceData::Timer { timer_id, deadline } => {
                write!(f, " timer={timer_id}")?;
                if let Some(dl) = deadline {
                    write!(f, " deadline={dl}")?;
                }
            }
            TraceData::IoRequested { token, interest } => {
                write!(f, " io_requested token={token} interest={interest}")?;
            }
            TraceData::IoReady { token, readiness } => {
                write!(f, " io_ready token={token} readiness={readiness}")?;
            }
            TraceData::IoResult { token, bytes } => {
                write!(f, " io_result token={token} bytes={bytes}")?;
            }
            TraceData::IoError { token, kind } => {
                write!(f, " io_error token={token} kind={kind}")?;
            }
            TraceData::RngSeed { seed } => write!(f, " rng_seed={seed}")?,
            TraceData::RngValue { value } => write!(f, " rng_value={value}")?,
            TraceData::Checkpoint {
                sequence,
                active_tasks,
                active_regions,
            } => write!(
                f,
                " checkpoint seq={sequence} tasks={active_tasks} regions={active_regions}"
            )?,
            TraceData::Futurelock {
                task,
                region,
                idle_steps,
                held,
            } => {
                write!(f, " futurelock: {task} in {region} idle={idle_steps}")?;
                write!(f, " held=[")?;
                for (i, (oid, kind)) in held.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{oid}:{kind:?}")?;
                }
                write!(f, "]")?;
            }
            TraceData::Monitor {
                monitor_ref,
                watcher,
                watcher_region,
                monitored,
            } => write!(
                f,
                " monitor_ref={monitor_ref} watcher={watcher} watcher_region={watcher_region} monitored={monitored}"
            )?,
            TraceData::Down {
                monitor_ref,
                watcher,
                monitored,
                completion_vt,
                reason,
            } => write!(
                f,
                " down monitor_ref={monitor_ref} watcher={watcher} monitored={monitored} completion_vt={completion_vt} reason={reason}"
            )?,
            TraceData::Link {
                link_ref,
                task_a,
                region_a,
                task_b,
                region_b,
            } => write!(
                f,
                " link_ref={link_ref} a={task_a} region_a={region_a} b={task_b} region_b={region_b}"
            )?,
            TraceData::Exit {
                link_ref,
                from,
                to,
                failure_vt,
                reason,
            } => write!(
                f,
                " exit link_ref={link_ref} from={from} to={to} failure_vt={failure_vt} reason={reason}"
            )?,
            TraceData::Message(msg) => write!(f, " \"{msg}\"")?,
            TraceData::Chaos { kind, task, detail } => {
                write!(f, " chaos:{kind}")?;
                if let Some(t) = task {
                    write!(f, " task={t}")?;
                }
                write!(f, " {detail}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_event_version_is_set() {
        let event = TraceEvent::new(1, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        assert_eq!(event.version, TRACE_EVENT_SCHEMA_VERSION);
    }
}
