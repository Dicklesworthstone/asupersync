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

impl TraceEventKind {
    /// Canonical list of all trace event kinds.
    ///
    /// Keep this list in sync with the enum definition and
    /// `docs/spork_deterministic_ordering.md` taxonomy section.
    pub const ALL: [Self; 36] = [
        Self::Spawn,
        Self::Schedule,
        Self::Yield,
        Self::Wake,
        Self::Poll,
        Self::Complete,
        Self::CancelRequest,
        Self::CancelAck,
        Self::RegionCloseBegin,
        Self::RegionCloseComplete,
        Self::RegionCreated,
        Self::RegionCancelled,
        Self::ObligationReserve,
        Self::ObligationCommit,
        Self::ObligationAbort,
        Self::ObligationLeak,
        Self::TimeAdvance,
        Self::TimerScheduled,
        Self::TimerFired,
        Self::TimerCancelled,
        Self::IoRequested,
        Self::IoReady,
        Self::IoResult,
        Self::IoError,
        Self::RngSeed,
        Self::RngValue,
        Self::Checkpoint,
        Self::FuturelockDetected,
        Self::ChaosInjection,
        Self::UserTrace,
        Self::MonitorCreated,
        Self::MonitorDropped,
        Self::DownDelivered,
        Self::LinkCreated,
        Self::LinkDropped,
        Self::ExitDelivered,
    ];

    /// Stable, grep-friendly taxonomy name.
    #[must_use]
    pub const fn stable_name(self) -> &'static str {
        match self {
            Self::Spawn => "spawn",
            Self::Schedule => "schedule",
            Self::Yield => "yield",
            Self::Wake => "wake",
            Self::Poll => "poll",
            Self::Complete => "complete",
            Self::CancelRequest => "cancel_request",
            Self::CancelAck => "cancel_ack",
            Self::RegionCloseBegin => "region_close_begin",
            Self::RegionCloseComplete => "region_close_complete",
            Self::RegionCreated => "region_created",
            Self::RegionCancelled => "region_cancelled",
            Self::ObligationReserve => "obligation_reserve",
            Self::ObligationCommit => "obligation_commit",
            Self::ObligationAbort => "obligation_abort",
            Self::ObligationLeak => "obligation_leak",
            Self::TimeAdvance => "time_advance",
            Self::TimerScheduled => "timer_scheduled",
            Self::TimerFired => "timer_fired",
            Self::TimerCancelled => "timer_cancelled",
            Self::IoRequested => "io_requested",
            Self::IoReady => "io_ready",
            Self::IoResult => "io_result",
            Self::IoError => "io_error",
            Self::RngSeed => "rng_seed",
            Self::RngValue => "rng_value",
            Self::Checkpoint => "checkpoint",
            Self::FuturelockDetected => "futurelock_detected",
            Self::ChaosInjection => "chaos_injection",
            Self::UserTrace => "user_trace",
            Self::MonitorCreated => "monitor_created",
            Self::MonitorDropped => "monitor_dropped",
            Self::DownDelivered => "down_delivered",
            Self::LinkCreated => "link_created",
            Self::LinkDropped => "link_dropped",
            Self::ExitDelivered => "exit_delivered",
        }
    }

    /// Stable required field set for taxonomy documentation.
    #[must_use]
    pub const fn required_fields(self) -> &'static str {
        match self {
            Self::Spawn
            | Self::Schedule
            | Self::Yield
            | Self::Wake
            | Self::Poll
            | Self::Complete => "task, region",
            Self::CancelRequest | Self::CancelAck => "task, region, reason",
            Self::RegionCloseBegin | Self::RegionCloseComplete | Self::RegionCreated => {
                "region, parent"
            }
            Self::RegionCancelled => "region, reason",
            Self::ObligationReserve
            | Self::ObligationCommit
            | Self::ObligationAbort
            | Self::ObligationLeak => {
                "obligation, task, region, kind, state, duration_ns, abort_reason"
            }
            Self::TimeAdvance => "old, new",
            Self::TimerScheduled | Self::TimerFired | Self::TimerCancelled => "timer_id, deadline",
            Self::IoRequested => "token, interest",
            Self::IoReady => "token, readiness",
            Self::IoResult => "token, bytes",
            Self::IoError => "token, kind",
            Self::RngSeed => "seed",
            Self::RngValue => "value",
            Self::Checkpoint => "sequence, active_tasks, active_regions",
            Self::FuturelockDetected => "task, region, idle_steps, held",
            Self::ChaosInjection => "kind, task, detail",
            Self::UserTrace => "message",
            Self::MonitorCreated | Self::MonitorDropped => {
                "monitor_ref, watcher, watcher_region, monitored"
            }
            Self::DownDelivered => "monitor_ref, watcher, monitored, completion_vt, reason",
            Self::LinkCreated | Self::LinkDropped => "link_ref, task_a, region_a, task_b, region_b",
            Self::ExitDelivered => "link_ref, from, to, failure_vt, reason",
        }
    }
}

impl fmt::Display for TraceEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_name())
    }
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
        write!(f, "[{:06}] {} {}", self.seq, self.time, self.kind)?;
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
    use crate::monitor::DownReason;
    use crate::record::{ObligationAbortReason, ObligationKind, ObligationState};
    use crate::trace::distributed::LamportTime;
    use crate::types::CancelReason;
    use std::collections::BTreeSet;

    fn task(n: u32) -> TaskId {
        TaskId::new_for_test(n, 1)
    }
    fn region(n: u32) -> RegionId {
        RegionId::new_for_test(n, 1)
    }
    fn obligation(n: u32) -> ObligationId {
        ObligationId::new_for_test(n, 1)
    }

    // ── TraceEventKind basics ──────────────────────────────────────

    #[test]
    fn trace_event_version_is_set() {
        let event = TraceEvent::new(1, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        assert_eq!(event.version, TRACE_EVENT_SCHEMA_VERSION);
    }

    #[test]
    fn trace_event_kind_stable_names_are_unique() {
        let mut names = BTreeSet::new();
        for kind in TraceEventKind::ALL {
            assert!(names.insert(kind.stable_name()));
        }
    }

    #[test]
    fn trace_event_taxonomy_is_documented() {
        const DOC: &str = include_str!("../../docs/spork_deterministic_ordering.md");
        for kind in TraceEventKind::ALL {
            let marker = format!("- `{}` => `{}`", kind.stable_name(), kind.required_fields());
            assert!(
                DOC.contains(&marker),
                "missing taxonomy entry in docs/spork_deterministic_ordering.md for {}",
                kind.stable_name()
            );
        }
    }

    #[test]
    fn all_array_has_36_kinds() {
        assert_eq!(TraceEventKind::ALL.len(), 36);
    }

    #[test]
    fn all_kinds_are_distinct() {
        let set: BTreeSet<TraceEventKind> = TraceEventKind::ALL.iter().copied().collect();
        assert_eq!(set.len(), TraceEventKind::ALL.len());
    }

    #[test]
    fn display_delegates_to_stable_name() {
        for kind in TraceEventKind::ALL {
            assert_eq!(format!("{kind}"), kind.stable_name());
        }
    }

    #[test]
    fn kind_ord_is_consistent_with_eq() {
        for a in TraceEventKind::ALL {
            for b in TraceEventKind::ALL {
                if a == b {
                    assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
                } else {
                    assert_ne!(a.cmp(&b), std::cmp::Ordering::Equal);
                }
            }
        }
    }

    #[test]
    fn required_fields_non_empty_for_all() {
        for kind in TraceEventKind::ALL {
            assert!(
                !kind.required_fields().is_empty(),
                "required_fields empty for {:?}",
                kind
            );
        }
    }

    // ── Constructor tests ──────────────────────────────────────────

    #[test]
    fn spawn_constructor() {
        let e = TraceEvent::spawn(1, Time::ZERO, task(10), region(20));
        assert_eq!(e.kind, TraceEventKind::Spawn);
        assert_eq!(e.seq, 1);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(10),
                region: region(20)
            }
        );
    }

    #[test]
    fn schedule_constructor() {
        let e = TraceEvent::schedule(2, Time::from_nanos(100), task(1), region(2));
        assert_eq!(e.kind, TraceEventKind::Schedule);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(1),
                region: region(2)
            }
        );
    }

    #[test]
    fn yield_task_constructor() {
        let e = TraceEvent::yield_task(3, Time::ZERO, task(5), region(6));
        assert_eq!(e.kind, TraceEventKind::Yield);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(5),
                region: region(6)
            }
        );
    }

    #[test]
    fn wake_constructor() {
        let e = TraceEvent::wake(4, Time::ZERO, task(7), region(8));
        assert_eq!(e.kind, TraceEventKind::Wake);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(7),
                region: region(8)
            }
        );
    }

    #[test]
    fn poll_constructor() {
        let e = TraceEvent::poll(5, Time::ZERO, task(9), region(10));
        assert_eq!(e.kind, TraceEventKind::Poll);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(9),
                region: region(10)
            }
        );
    }

    #[test]
    fn complete_constructor() {
        let e = TraceEvent::complete(6, Time::ZERO, task(11), region(12));
        assert_eq!(e.kind, TraceEventKind::Complete);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(11),
                region: region(12)
            }
        );
    }

    #[test]
    fn cancel_request_constructor() {
        let e =
            TraceEvent::cancel_request(7, Time::ZERO, task(1), region(2), CancelReason::timeout());
        assert_eq!(e.kind, TraceEventKind::CancelRequest);
        match &e.data {
            TraceData::Cancel {
                task: t,
                region: r,
                reason,
            } => {
                assert_eq!(*t, task(1));
                assert_eq!(*r, region(2));
                assert_eq!(reason.kind(), crate::types::CancelKind::Timeout);
            }
            other => panic!("expected Cancel, got {other:?}"),
        }
    }

    #[test]
    fn region_created_constructor_with_parent() {
        let e = TraceEvent::region_created(8, Time::ZERO, region(3), Some(region(1)));
        assert_eq!(e.kind, TraceEventKind::RegionCreated);
        assert_eq!(
            e.data,
            TraceData::Region {
                region: region(3),
                parent: Some(region(1))
            }
        );
    }

    #[test]
    fn region_created_constructor_without_parent() {
        let e = TraceEvent::region_created(9, Time::ZERO, region(3), None);
        assert_eq!(e.kind, TraceEventKind::RegionCreated);
        assert_eq!(
            e.data,
            TraceData::Region {
                region: region(3),
                parent: None
            }
        );
    }

    #[test]
    fn region_cancelled_constructor() {
        let e = TraceEvent::region_cancelled(10, Time::ZERO, region(5), CancelReason::shutdown());
        assert_eq!(e.kind, TraceEventKind::RegionCancelled);
        match &e.data {
            TraceData::RegionCancel { region: r, .. } => assert_eq!(*r, region(5)),
            other => panic!("expected RegionCancel, got {other:?}"),
        }
    }

    #[test]
    fn time_advance_constructor() {
        let e =
            TraceEvent::time_advance(11, Time::ZERO, Time::from_nanos(0), Time::from_nanos(100));
        assert_eq!(e.kind, TraceEventKind::TimeAdvance);
        assert_eq!(
            e.data,
            TraceData::Time {
                old: Time::from_nanos(0),
                new: Time::from_nanos(100)
            }
        );
    }

    #[test]
    fn timer_scheduled_constructor() {
        let e = TraceEvent::timer_scheduled(12, Time::ZERO, 42, Time::from_millis(500));
        assert_eq!(e.kind, TraceEventKind::TimerScheduled);
        assert_eq!(
            e.data,
            TraceData::Timer {
                timer_id: 42,
                deadline: Some(Time::from_millis(500))
            }
        );
    }

    #[test]
    fn timer_fired_constructor() {
        let e = TraceEvent::timer_fired(13, Time::ZERO, 42);
        assert_eq!(e.kind, TraceEventKind::TimerFired);
        assert_eq!(
            e.data,
            TraceData::Timer {
                timer_id: 42,
                deadline: None
            }
        );
    }

    #[test]
    fn timer_cancelled_constructor() {
        let e = TraceEvent::timer_cancelled(14, Time::ZERO, 42);
        assert_eq!(e.kind, TraceEventKind::TimerCancelled);
        assert_eq!(
            e.data,
            TraceData::Timer {
                timer_id: 42,
                deadline: None
            }
        );
    }

    #[test]
    fn io_requested_constructor() {
        let e = TraceEvent::io_requested(15, Time::ZERO, 99, 0x03);
        assert_eq!(e.kind, TraceEventKind::IoRequested);
        assert_eq!(
            e.data,
            TraceData::IoRequested {
                token: 99,
                interest: 0x03
            }
        );
    }

    #[test]
    fn io_ready_constructor() {
        let e = TraceEvent::io_ready(16, Time::ZERO, 99, 0x01);
        assert_eq!(e.kind, TraceEventKind::IoReady);
        assert_eq!(
            e.data,
            TraceData::IoReady {
                token: 99,
                readiness: 0x01
            }
        );
    }

    #[test]
    fn io_result_constructor() {
        let e = TraceEvent::io_result(17, Time::ZERO, 99, 1024);
        assert_eq!(e.kind, TraceEventKind::IoResult);
        assert_eq!(
            e.data,
            TraceData::IoResult {
                token: 99,
                bytes: 1024
            }
        );
    }

    #[test]
    fn io_result_negative_bytes() {
        let e = TraceEvent::io_result(18, Time::ZERO, 99, -1);
        assert_eq!(
            e.data,
            TraceData::IoResult {
                token: 99,
                bytes: -1
            }
        );
    }

    #[test]
    fn io_error_constructor() {
        let e = TraceEvent::io_error(19, Time::ZERO, 99, 13);
        assert_eq!(e.kind, TraceEventKind::IoError);
        assert_eq!(
            e.data,
            TraceData::IoError {
                token: 99,
                kind: 13
            }
        );
    }

    #[test]
    fn rng_seed_constructor() {
        let e = TraceEvent::rng_seed(20, Time::ZERO, 0xDEAD_BEEF);
        assert_eq!(e.kind, TraceEventKind::RngSeed);
        assert_eq!(e.data, TraceData::RngSeed { seed: 0xDEAD_BEEF });
    }

    #[test]
    fn rng_value_constructor() {
        let e = TraceEvent::rng_value(21, Time::ZERO, 42);
        assert_eq!(e.kind, TraceEventKind::RngValue);
        assert_eq!(e.data, TraceData::RngValue { value: 42 });
    }

    #[test]
    fn checkpoint_constructor() {
        let e = TraceEvent::checkpoint(22, Time::ZERO, 7, 3, 2);
        assert_eq!(e.kind, TraceEventKind::Checkpoint);
        assert_eq!(
            e.data,
            TraceData::Checkpoint {
                sequence: 7,
                active_tasks: 3,
                active_regions: 2
            }
        );
    }

    #[test]
    fn obligation_reserve_constructor() {
        let e = TraceEvent::obligation_reserve(
            23,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::SendPermit,
        );
        assert_eq!(e.kind, TraceEventKind::ObligationReserve);
        match &e.data {
            TraceData::Obligation {
                state,
                duration_ns,
                abort_reason,
                ..
            } => {
                assert_eq!(*state, ObligationState::Reserved);
                assert_eq!(*duration_ns, None);
                assert_eq!(*abort_reason, None);
            }
            other => panic!("expected Obligation, got {other:?}"),
        }
    }

    #[test]
    fn obligation_commit_constructor() {
        let e = TraceEvent::obligation_commit(
            24,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::Ack,
            5000,
        );
        assert_eq!(e.kind, TraceEventKind::ObligationCommit);
        match &e.data {
            TraceData::Obligation {
                state,
                duration_ns,
                abort_reason,
                ..
            } => {
                assert_eq!(*state, ObligationState::Committed);
                assert_eq!(*duration_ns, Some(5000));
                assert_eq!(*abort_reason, None);
            }
            other => panic!("expected Obligation, got {other:?}"),
        }
    }

    #[test]
    fn obligation_abort_constructor() {
        let e = TraceEvent::obligation_abort(
            25,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::Lease,
            3000,
            ObligationAbortReason::Cancel,
        );
        assert_eq!(e.kind, TraceEventKind::ObligationAbort);
        match &e.data {
            TraceData::Obligation {
                state,
                duration_ns,
                abort_reason,
                ..
            } => {
                assert_eq!(*state, ObligationState::Aborted);
                assert_eq!(*duration_ns, Some(3000));
                assert_eq!(*abort_reason, Some(ObligationAbortReason::Cancel));
            }
            other => panic!("expected Obligation, got {other:?}"),
        }
    }

    #[test]
    fn obligation_leak_constructor() {
        let e = TraceEvent::obligation_leak(
            26,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::IoOp,
            9000,
        );
        assert_eq!(e.kind, TraceEventKind::ObligationLeak);
        match &e.data {
            TraceData::Obligation {
                state,
                duration_ns,
                abort_reason,
                ..
            } => {
                assert_eq!(*state, ObligationState::Leaked);
                assert_eq!(*duration_ns, Some(9000));
                assert_eq!(*abort_reason, None);
            }
            other => panic!("expected Obligation, got {other:?}"),
        }
    }

    #[test]
    fn monitor_created_constructor() {
        let e = TraceEvent::monitor_created(27, Time::ZERO, 100, task(1), region(2), task(3));
        assert_eq!(e.kind, TraceEventKind::MonitorCreated);
        assert_eq!(
            e.data,
            TraceData::Monitor {
                monitor_ref: 100,
                watcher: task(1),
                watcher_region: region(2),
                monitored: task(3),
            }
        );
    }

    #[test]
    fn monitor_dropped_constructor() {
        let e = TraceEvent::monitor_dropped(28, Time::ZERO, 100, task(1), region(2), task(3));
        assert_eq!(e.kind, TraceEventKind::MonitorDropped);
        assert_eq!(
            e.data,
            TraceData::Monitor {
                monitor_ref: 100,
                watcher: task(1),
                watcher_region: region(2),
                monitored: task(3),
            }
        );
    }

    #[test]
    fn down_delivered_constructor() {
        let e = TraceEvent::down_delivered(
            29,
            Time::ZERO,
            100,
            task(1),
            task(3),
            Time::from_nanos(500),
            DownReason::Normal,
        );
        assert_eq!(e.kind, TraceEventKind::DownDelivered);
        assert_eq!(
            e.data,
            TraceData::Down {
                monitor_ref: 100,
                watcher: task(1),
                monitored: task(3),
                completion_vt: Time::from_nanos(500),
                reason: DownReason::Normal,
            }
        );
    }

    #[test]
    fn link_created_constructor() {
        let e =
            TraceEvent::link_created(30, Time::ZERO, 200, task(1), region(2), task(3), region(4));
        assert_eq!(e.kind, TraceEventKind::LinkCreated);
        assert_eq!(
            e.data,
            TraceData::Link {
                link_ref: 200,
                task_a: task(1),
                region_a: region(2),
                task_b: task(3),
                region_b: region(4),
            }
        );
    }

    #[test]
    fn link_dropped_constructor() {
        let e =
            TraceEvent::link_dropped(31, Time::ZERO, 200, task(1), region(2), task(3), region(4));
        assert_eq!(e.kind, TraceEventKind::LinkDropped);
        assert_eq!(
            e.data,
            TraceData::Link {
                link_ref: 200,
                task_a: task(1),
                region_a: region(2),
                task_b: task(3),
                region_b: region(4),
            }
        );
    }

    #[test]
    fn exit_delivered_constructor() {
        let e = TraceEvent::exit_delivered(
            32,
            Time::ZERO,
            200,
            task(1),
            task(3),
            Time::from_nanos(999),
            DownReason::Normal,
        );
        assert_eq!(e.kind, TraceEventKind::ExitDelivered);
        assert_eq!(
            e.data,
            TraceData::Exit {
                link_ref: 200,
                from: task(1),
                to: task(3),
                failure_vt: Time::from_nanos(999),
                reason: DownReason::Normal,
            }
        );
    }

    #[test]
    fn user_trace_constructor() {
        let e = TraceEvent::user_trace(33, Time::ZERO, "hello");
        assert_eq!(e.kind, TraceEventKind::UserTrace);
        assert_eq!(e.data, TraceData::Message("hello".into()));
    }

    #[test]
    fn user_trace_accepts_string() {
        let e = TraceEvent::user_trace(34, Time::ZERO, String::from("world"));
        assert_eq!(e.data, TraceData::Message("world".into()));
    }

    // ── with_logical_time ──────────────────────────────────────────

    #[test]
    fn with_logical_time_sets_field() {
        let lt = LogicalTime::Lamport(LamportTime::from_raw(42));
        let e = TraceEvent::new(1, Time::ZERO, TraceEventKind::UserTrace, TraceData::None)
            .with_logical_time(lt);
        assert_eq!(
            e.logical_time,
            Some(LogicalTime::Lamport(LamportTime::from_raw(42)))
        );
    }

    #[test]
    fn default_logical_time_is_none() {
        let e = TraceEvent::new(1, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        assert_eq!(e.logical_time, None);
    }

    // ── Display formatting ─────────────────────────────────────────

    #[test]
    fn display_task_event() {
        let e = TraceEvent::spawn(1, Time::ZERO, task(10), region(20));
        let s = format!("{e}");
        assert!(s.contains("spawn"), "expected 'spawn' in {s}");
        assert!(s.contains("[000001]"), "expected seq in {s}");
    }

    #[test]
    fn display_region_with_parent() {
        let e = TraceEvent::region_created(2, Time::ZERO, region(3), Some(region(1)));
        let s = format!("{e}");
        assert!(s.contains("region_created"), "expected kind in {s}");
        assert!(s.contains("parent"), "expected parent in {s}");
    }

    #[test]
    fn display_region_without_parent() {
        let e = TraceEvent::region_created(3, Time::ZERO, region(3), None);
        let s = format!("{e}");
        assert!(s.contains("region_created"), "expected kind in {s}");
        assert!(!s.contains("parent"), "should not contain parent: {s}");
    }

    #[test]
    fn display_obligation_with_duration_and_abort() {
        let e = TraceEvent::obligation_abort(
            4,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::Lease,
            5000,
            ObligationAbortReason::Error,
        );
        let s = format!("{e}");
        assert!(s.contains("obligation_abort"), "expected kind in {s}");
        assert!(s.contains("duration=5000ns"), "expected duration in {s}");
        assert!(s.contains("abort_reason="), "expected abort_reason in {s}");
    }

    #[test]
    fn display_obligation_reserve_no_duration() {
        let e = TraceEvent::obligation_reserve(
            5,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::SendPermit,
        );
        let s = format!("{e}");
        assert!(
            !s.contains("duration="),
            "reserve should not show duration: {s}"
        );
        assert!(
            !s.contains("abort_reason="),
            "reserve should not show abort_reason: {s}"
        );
    }

    #[test]
    fn display_cancel_event() {
        let e =
            TraceEvent::cancel_request(6, Time::ZERO, task(1), region(2), CancelReason::timeout());
        let s = format!("{e}");
        assert!(s.contains("cancel_request"), "expected kind in {s}");
        assert!(s.contains("reason="), "expected reason in {s}");
    }

    #[test]
    fn display_region_cancel() {
        let e = TraceEvent::region_cancelled(7, Time::ZERO, region(5), CancelReason::shutdown());
        let s = format!("{e}");
        assert!(s.contains("region_cancelled"), "expected kind in {s}");
        assert!(s.contains("reason="), "expected reason in {s}");
    }

    #[test]
    fn display_time_advance() {
        let e = TraceEvent::time_advance(8, Time::ZERO, Time::from_nanos(0), Time::from_nanos(100));
        let s = format!("{e}");
        assert!(s.contains("time_advance"), "expected kind in {s}");
        assert!(s.contains("->"), "expected arrow in {s}");
    }

    #[test]
    fn display_timer_with_deadline() {
        let e = TraceEvent::timer_scheduled(9, Time::ZERO, 42, Time::from_millis(500));
        let s = format!("{e}");
        assert!(s.contains("timer=42"), "expected timer id in {s}");
        assert!(s.contains("deadline="), "expected deadline in {s}");
    }

    #[test]
    fn display_timer_without_deadline() {
        let e = TraceEvent::timer_fired(10, Time::ZERO, 42);
        let s = format!("{e}");
        assert!(s.contains("timer=42"), "expected timer id in {s}");
        assert!(!s.contains("deadline="), "should not show deadline: {s}");
    }

    #[test]
    fn display_io_requested() {
        let e = TraceEvent::io_requested(11, Time::ZERO, 99, 0x03);
        let s = format!("{e}");
        assert!(s.contains("io_requested"), "expected kind in {s}");
        assert!(s.contains("token=99"), "expected token in {s}");
        assert!(s.contains("interest=3"), "expected interest in {s}");
    }

    #[test]
    fn display_io_ready() {
        let e = TraceEvent::io_ready(12, Time::ZERO, 99, 0x01);
        let s = format!("{e}");
        assert!(s.contains("io_ready"), "expected kind in {s}");
        assert!(s.contains("readiness=1"), "expected readiness in {s}");
    }

    #[test]
    fn display_io_result() {
        let e = TraceEvent::io_result(13, Time::ZERO, 99, 1024);
        let s = format!("{e}");
        assert!(s.contains("io_result"), "expected kind in {s}");
        assert!(s.contains("bytes=1024"), "expected bytes in {s}");
    }

    #[test]
    fn display_io_error() {
        let e = TraceEvent::io_error(14, Time::ZERO, 99, 13);
        let s = format!("{e}");
        assert!(s.contains("io_error"), "expected kind in {s}");
        assert!(s.contains("kind=13"), "expected kind in {s}");
    }

    #[test]
    fn display_rng_seed() {
        let e = TraceEvent::rng_seed(15, Time::ZERO, 0xCAFE);
        let s = format!("{e}");
        assert!(s.contains("rng_seed=51966"), "expected seed in {s}");
    }

    #[test]
    fn display_rng_value() {
        let e = TraceEvent::rng_value(16, Time::ZERO, 42);
        let s = format!("{e}");
        assert!(s.contains("rng_value=42"), "expected value in {s}");
    }

    #[test]
    fn display_checkpoint() {
        let e = TraceEvent::checkpoint(17, Time::ZERO, 7, 3, 2);
        let s = format!("{e}");
        assert!(s.contains("checkpoint"), "expected kind in {s}");
        assert!(s.contains("seq=7"), "expected seq in {s}");
        assert!(s.contains("tasks=3"), "expected tasks in {s}");
        assert!(s.contains("regions=2"), "expected regions in {s}");
    }

    #[test]
    fn display_futurelock_empty_held() {
        let e = TraceEvent::new(
            18,
            Time::ZERO,
            TraceEventKind::FuturelockDetected,
            TraceData::Futurelock {
                task: task(1),
                region: region(2),
                idle_steps: 10,
                held: vec![],
            },
        );
        let s = format!("{e}");
        assert!(s.contains("futurelock"), "expected kind in {s}");
        assert!(s.contains("idle=10"), "expected idle in {s}");
        assert!(s.contains("held=[]"), "expected empty held in {s}");
    }

    #[test]
    fn display_futurelock_with_held() {
        let e = TraceEvent::new(
            19,
            Time::ZERO,
            TraceEventKind::FuturelockDetected,
            TraceData::Futurelock {
                task: task(1),
                region: region(2),
                idle_steps: 5,
                held: vec![(obligation(10), ObligationKind::SendPermit)],
            },
        );
        let s = format!("{e}");
        assert!(s.contains("held=["), "expected held in {s}");
        assert!(s.contains("SendPermit"), "expected kind in {s}");
    }

    #[test]
    fn display_monitor() {
        let e = TraceEvent::monitor_created(20, Time::ZERO, 100, task(1), region(2), task(3));
        let s = format!("{e}");
        assert!(s.contains("monitor_ref=100"), "expected ref in {s}");
    }

    #[test]
    fn display_down() {
        let e = TraceEvent::down_delivered(
            21,
            Time::ZERO,
            100,
            task(1),
            task(3),
            Time::from_nanos(500),
            DownReason::Normal,
        );
        let s = format!("{e}");
        assert!(s.contains("down"), "expected down in {s}");
        assert!(s.contains("monitor_ref=100"), "expected ref in {s}");
    }

    #[test]
    fn display_link() {
        let e =
            TraceEvent::link_created(22, Time::ZERO, 200, task(1), region(2), task(3), region(4));
        let s = format!("{e}");
        assert!(s.contains("link_ref=200"), "expected ref in {s}");
    }

    #[test]
    fn display_exit() {
        let e = TraceEvent::exit_delivered(
            23,
            Time::ZERO,
            200,
            task(1),
            task(3),
            Time::from_nanos(999),
            DownReason::Normal,
        );
        let s = format!("{e}");
        assert!(s.contains("exit"), "expected exit in {s}");
        assert!(s.contains("link_ref=200"), "expected ref in {s}");
    }

    #[test]
    fn display_message() {
        let e = TraceEvent::user_trace(24, Time::ZERO, "hello world");
        let s = format!("{e}");
        assert!(s.contains("\"hello world\""), "expected msg in {s}");
    }

    #[test]
    fn display_chaos_with_task() {
        let e = TraceEvent::new(
            25,
            Time::ZERO,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "delay".into(),
                task: Some(task(1)),
                detail: "200ns".into(),
            },
        );
        let s = format!("{e}");
        assert!(s.contains("chaos:delay"), "expected kind in {s}");
        assert!(s.contains("task="), "expected task in {s}");
        assert!(s.contains("200ns"), "expected detail in {s}");
    }

    #[test]
    fn display_chaos_without_task() {
        let e = TraceEvent::new(
            26,
            Time::ZERO,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "budget_exhaust".into(),
                task: None,
                detail: "all".into(),
            },
        );
        let s = format!("{e}");
        assert!(s.contains("chaos:budget_exhaust"), "expected kind in {s}");
        assert!(!s.contains("task="), "should not show task: {s}");
    }

    #[test]
    fn display_none_data() {
        let e = TraceEvent::new(27, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        let s = format!("{e}");
        // Should have seq, time, kind but nothing else
        assert!(s.contains("user_trace"), "expected kind in {s}");
    }

    #[test]
    fn display_with_logical_time() {
        let lt = LogicalTime::Lamport(LamportTime::from_raw(42));
        let e = TraceEvent::new(28, Time::ZERO, TraceEventKind::UserTrace, TraceData::None)
            .with_logical_time(lt);
        let s = format!("{e}");
        assert!(s.contains("@"), "expected @lt in {s}");
    }

    // ── Equality and Clone ─────────────────────────────────────────

    #[test]
    fn events_equal_same_fields() {
        let a = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let b = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        assert_eq!(a, b);
    }

    #[test]
    fn events_differ_on_seq() {
        let a = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let b = TraceEvent::spawn(2, Time::ZERO, task(1), region(2));
        assert_ne!(a, b);
    }

    #[test]
    fn events_differ_on_kind() {
        let a = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let b = TraceEvent::schedule(1, Time::ZERO, task(1), region(2));
        assert_ne!(a, b);
    }

    #[test]
    fn events_differ_on_data() {
        let a = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let b = TraceEvent::spawn(1, Time::ZERO, task(1), region(3));
        assert_ne!(a, b);
    }

    #[test]
    fn trace_data_clone() {
        let data = TraceData::Task {
            task: task(1),
            region: region(2),
        };
        let cloned = data.clone();
        assert_eq!(data, cloned);
    }

    #[test]
    fn trace_data_message_eq() {
        let a = TraceData::Message("hello".into());
        let b = TraceData::Message("hello".into());
        assert_eq!(a, b);
    }

    #[test]
    fn trace_data_message_ne() {
        let a = TraceData::Message("hello".into());
        let b = TraceData::Message("world".into());
        assert_ne!(a, b);
    }

    #[test]
    fn trace_data_none_variant() {
        assert_eq!(TraceData::None, TraceData::None);
    }

    #[test]
    fn trace_event_clone() {
        let e = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let c = e.clone();
        assert_eq!(e, c);
    }

    // ── Obligation all-kinds coverage ──────────────────────────────

    #[test]
    fn obligation_reserve_all_kinds() {
        for kind in [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
        ] {
            let e = TraceEvent::obligation_reserve(
                1,
                Time::ZERO,
                obligation(1),
                task(2),
                region(3),
                kind,
            );
            match &e.data {
                TraceData::Obligation { kind: k, .. } => assert_eq!(*k, kind),
                _ => panic!("wrong variant"),
            }
        }
    }

    #[test]
    fn obligation_abort_all_reasons() {
        for reason in [
            ObligationAbortReason::Cancel,
            ObligationAbortReason::Error,
            ObligationAbortReason::Explicit,
        ] {
            let e = TraceEvent::obligation_abort(
                1,
                Time::ZERO,
                obligation(1),
                task(2),
                region(3),
                ObligationKind::SendPermit,
                1000,
                reason,
            );
            match &e.data {
                TraceData::Obligation { abort_reason, .. } => {
                    assert_eq!(*abort_reason, Some(reason));
                }
                _ => panic!("wrong variant"),
            }
        }
    }

    // ── Down with error variant ────────────────────────────────────

    #[test]
    fn down_delivered_with_error_reason() {
        let e = TraceEvent::down_delivered(
            1,
            Time::ZERO,
            50,
            task(1),
            task(2),
            Time::from_nanos(100),
            DownReason::Error("boom".into()),
        );
        match &e.data {
            TraceData::Down { reason, .. } => {
                assert_eq!(*reason, DownReason::Error("boom".into()));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn exit_delivered_with_cancelled_reason() {
        let e = TraceEvent::exit_delivered(
            1,
            Time::ZERO,
            50,
            task(1),
            task(2),
            Time::from_nanos(100),
            DownReason::Cancelled(CancelReason::timeout()),
        );
        match &e.data {
            TraceData::Exit { reason, .. } => {
                matches!(reason, DownReason::Cancelled(_));
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── Edge cases ─────────────────────────────────────────────────

    #[test]
    fn seq_zero() {
        let e = TraceEvent::new(0, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        assert_eq!(e.seq, 0);
    }

    #[test]
    fn seq_max() {
        let e = TraceEvent::new(
            u64::MAX,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        );
        assert_eq!(e.seq, u64::MAX);
    }

    #[test]
    fn time_max() {
        let e = TraceEvent::new(1, Time::MAX, TraceEventKind::UserTrace, TraceData::None);
        assert_eq!(e.time, Time::MAX);
    }

    #[test]
    fn io_result_zero_bytes() {
        let e = TraceEvent::io_result(1, Time::ZERO, 0, 0);
        assert_eq!(e.data, TraceData::IoResult { token: 0, bytes: 0 });
    }

    #[test]
    fn checkpoint_zero_counts() {
        let e = TraceEvent::checkpoint(1, Time::ZERO, 0, 0, 0);
        assert_eq!(
            e.data,
            TraceData::Checkpoint {
                sequence: 0,
                active_tasks: 0,
                active_regions: 0
            }
        );
    }

    #[test]
    fn futurelock_many_held() {
        let held: Vec<_> = (0..100)
            .map(|i| (obligation(i), ObligationKind::SendPermit))
            .collect();
        let e = TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::FuturelockDetected,
            TraceData::Futurelock {
                task: task(1),
                region: region(2),
                idle_steps: 1000,
                held,
            },
        );
        let s = format!("{e}");
        // Should contain all 100 entries
        assert!(s.matches("SendPermit").count() == 100);
    }
}
