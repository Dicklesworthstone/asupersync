//! Trace events and data types.
//!
//! Each event in the trace represents an observable action in the runtime.
//! Events carry sufficient information for replay and analysis.

use crate::record::ObligationKind;
use crate::types::{CancelReason, ObligationId, RegionId, TaskId, Time};
use core::fmt;

/// The kind of trace event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceEventKind {
    /// A task was spawned.
    Spawn,
    /// A task was scheduled for execution.
    Schedule,
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
    /// An obligation was reserved.
    ObligationReserve,
    /// An obligation was committed.
    ObligationCommit,
    /// An obligation was aborted.
    ObligationAbort,
    /// Time advanced.
    TimeAdvance,
    /// A task held obligations but stopped being polled (futurelock).
    FuturelockDetected,
    /// User-defined trace point.
    UserTrace,
}

/// Additional data carried by a trace event.
#[derive(Debug, Clone)]
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
    },
    /// Cancellation data.
    Cancel {
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
    /// User message.
    Message(String),
}

/// A trace event in the runtime.
#[derive(Debug, Clone)]
pub struct TraceEvent {
    /// Sequence number (monotonically increasing).
    pub seq: u64,
    /// Timestamp when the event occurred.
    pub time: Time,
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
            seq,
            time,
            kind,
            data,
        }
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
        _reason: CancelReason,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::CancelRequest,
            TraceData::Task { task, region },
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:06}] {} {:?}", self.seq, self.time, self.kind)?;
        match &self.data {
            TraceData::None => {}
            TraceData::Task { task, region } => write!(f, " {task} in {region}")?,
            TraceData::Region { region, parent } => {
                write!(f, " {region}")?;
                if let Some(p) = parent {
                    write!(f, " (parent: {p})")?;
                }
            }
            TraceData::Obligation { obligation, task } => {
                write!(f, " {obligation} held by {task}")?;
            }
            TraceData::Cancel { reason } => write!(f, " {reason}")?,
            TraceData::Time { old, new } => write!(f, " {old} -> {new}")?,
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
            TraceData::Message(msg) => write!(f, " \"{msg}\"")?,
        }
        Ok(())
    }
}
