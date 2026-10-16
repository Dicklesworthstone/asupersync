//! Symbol broadcast cancellation protocol.
//!
//! This module provides cancellation tokens, broadcast messages, and cleanup
//! coordination for symbol stream operations. Cancellation is a protocol:
//! it propagates correctly to stop generation, abort transmissions, clean up
//! partial symbol sets, and notify peers.
//!
//! [`progress_certificate`] provides auditable drain-progress diagnostics and
//! conditional range-bounded calculations alongside deterministic stall and
//! phase classification.
//!
//! [`ResponsivenessRegistry`] describes stock wait and commit boundaries. Its
//! finite results count **delivered polls of the named operation** or explicit
//! checkpoint calls, not elapsed time, scheduler turns or whole-task cleanup. A query
//! refuses a bound when the selected phase or its context cannot support it.

pub mod progress_certificate;
pub mod protocol_state_machines;
#[cfg(test)]
pub mod protocol_validator_test_suite;
pub mod symbol_cancel;
#[cfg(test)]
pub mod symbol_cancel_golden;

pub use progress_certificate::{
    CertificateVerdict, DrainPhase, EvidenceEntry, ProgressCertificate, ProgressConfig,
    ProgressObservation,
};
pub use protocol_state_machines::{
    CancelProtocolValidator, CancelStateMachine, ChannelContext, ChannelEvent, ChannelState,
    ChannelStateMachine, IoContext, IoEvent, IoState, IoStateMachine, ObligationContext,
    ObligationEvent, ObligationState, ObligationStateMachine, RegionContext, RegionEvent,
    RegionState, RegionStateMachine, TaskContext, TaskEvent, TaskState, TaskStateMachine,
    TimerContext, TimerEvent, TimerState, TimerStateMachine, TransitionResult, ValidationLevel,
};
#[cfg(test)]
pub use protocol_validator_test_suite::{
    BugInjectionConfig, BugInjectionStats, BugInjector, CancelProtocolTestSuite,
    FalsePositiveTestHarness, IntegrationTestConfig, IntegrationTestHarness,
    PerformanceMeasurement, PerformanceTestConfig, PerformanceTestHarness, PropertyTestHarness,
    ProtocolViolationType,
};
pub use symbol_cancel::{
    CancelBroadcastMetrics, CancelBroadcaster, CancelListener, CancelMessage, CancelSink,
    CleanupCoordinator, CleanupHandler, CleanupResult, CleanupStats, PeerId, SymbolCancelToken,
};

/// The boundary a cancellation responsiveness query must reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponsivenessGoal {
    /// A checkpoint acknowledges the cancellation request.
    CancellationObserved,
    /// The named operation returns, possibly preserving an already committed result.
    OperationReturned,
    /// All work, obligations and finalizers owned by the caller have terminated.
    OwnerQuiescent,
}

/// Unit counted by a finite responsiveness result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponsivenessUnit {
    /// Delivered polls of the named future, not global scheduler dispatches.
    OperationPolls,
    /// Explicit calls to a synchronous cancellation checkpoint.
    CheckpointCalls,
}

/// Why the requested bound or budget comparison cannot be established.
///
/// These are query refusals, not changes to an operation's runtime errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponsivenessRefusal {
    /// The inventory has no exact entry or public alias for this name.
    UnknownOperation,
    /// No explicit context was supplied for a context-dependent operation.
    MissingContext,
    /// This operation consults the ambient task context, which was not present.
    MissingAmbientContext,
    /// Cancellation is deferred by an actual or proposed mask.
    Masked {
        /// Current or proposed nesting depth.
        depth: u32,
    },
    /// Nested mask depth exceeds the runtime's existing limit.
    MaskDepthExceeded {
        /// Rejected depth.
        depth: u32,
        /// Runtime-enforced maximum depth.
        maximum: u32,
    },
    /// A committed value, initialized cell, or zero-sized operation can win.
    CompletionMayWin,
    /// A producer, resource factory, initializer, peer or provider must progress.
    ExternalProgress,
    /// A timer must advance; poll counts cannot establish when that happens.
    TimerProgress,
    /// Arbitrary synchronous callbacks, destructors or blocking work must return.
    SynchronousCode,
    /// Mask nesting does not bound the work inside the mask.
    UnboundedMaskBody,
    /// A task, loser, finalizer or region has its own independent cleanup work.
    OwnerProgress,
    /// Bounds describing different goals cannot be silently composed.
    DifferentGoals,
    /// Checkpoint calls and future polls cannot be silently interchanged.
    DifferentUnits,
    /// The socket implementation is unsupported on this compilation target.
    UnsupportedPlatform,
    /// Arithmetic would overflow; saturation is not a proof of a finite bound.
    Overflow,
    /// The supplied poll dimension is smaller than the conditional requirement.
    InsufficientPollBudget {
        /// Conditional delivered-poll requirement.
        required: u64,
        /// Proposed finite poll quota.
        available: u32,
    },
    /// A measured operation did not reach the queried boundary.
    GoalNotObserved,
    /// A measured operation exceeded the published delivered-poll bound.
    PollBoundExceeded {
        /// Published bound in the result's primary unit.
        bound: u64,
        /// Measured steps in the same unit.
        observed: u64,
    },
}

impl std::fmt::Display for ResponsivenessRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "responsiveness bound refused: {self:?}")
    }
}

impl std::error::Error for ResponsivenessRefusal {}

/// Prospective cancellation kind and a snapshot of the relevant context.
///
/// Construct this at the operation's query boundary. The snapshot does not
/// freeze the context, schedule the future, publish cancellation, or prove that
/// a future is parked. A finite answer assumes the **named phase is actually
/// reached**, cancellation is published before a subsequent delivered poll,
/// the requested cancellation kind applies, the context remains unmasked, and
/// locks, callbacks, destructors and nested `poll` calls return. Native wake
/// delivery and fair scheduling must be proved
/// separately. The query does not manufacture them from a detached `Cx`.
#[derive(Debug, Clone, Copy)]
pub struct ResponsivenessQuery {
    kind: crate::types::CancelKind,
    mask_depth: Option<u32>,
    ambient: bool,
}

impl ResponsivenessQuery {
    /// Query without context authority. Context-dependent finite entries refuse.
    #[must_use]
    pub const fn without_context(kind: crate::types::CancelKind) -> Self {
        Self {
            kind,
            mask_depth: None,
            ambient: false,
        }
    }

    /// Snapshot an explicit context and whether it is the current ambient task.
    #[must_use]
    pub fn for_cx<Caps>(cx: &crate::cx::Cx<Caps>, kind: crate::types::CancelKind) -> Self {
        let mask_depth = cx.inner.read().mask_depth;
        let ambient = crate::cx::Cx::current()
            .is_some_and(|current| std::sync::Arc::ptr_eq(&current.inner, &cx.inner));
        Self {
            kind,
            mask_depth: Some(mask_depth),
            ambient,
        }
    }

    /// Evaluate a proposed nesting using the runtime's actual depth limit.
    ///
    /// This is depth arithmetic only. Even legal depth one prevents a stock
    /// cancellation-dependent wait from supplying a finite cancellation bound.
    pub fn with_additional_masks(mut self, additional: u32) -> Result<Self, ResponsivenessRefusal> {
        let depth = self
            .mask_depth
            .ok_or(ResponsivenessRefusal::MissingContext)?;
        self.mask_depth = Some(ResponsivenessRegistry::checked_mask_depth(
            depth, additional,
        )?);
        Ok(self)
    }
}

/// A conditional finite bound, obtained only from a maintained inventory entry.
///
/// The primary unit is explicit: operation polls and synchronous checkpoint
/// calls cannot be interchanged. Neither counts global scheduler dispatches
/// or arbitrary nested I/O calls. Sequential composition preserves the unit;
/// it does not turn the result into a subtree drain bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiniteResponsiveness {
    goal: ResponsivenessGoal,
    unit: ResponsivenessUnit,
    polls: u64,
    io_write_attempts: u64,
}

impl FiniteResponsiveness {
    /// Boundary established by this bound.
    #[must_use]
    pub const fn goal(self) -> ResponsivenessGoal {
        self.goal
    }

    /// Unit for the primary bound.
    #[must_use]
    pub const fn unit(self) -> ResponsivenessUnit {
        self.unit
    }

    /// Maximum steps in [`Self::unit`] after the request is published.
    #[must_use]
    pub const fn steps(self) -> u64 {
        self.polls
    }

    /// Additional best-effort inner write polls in cancellation drain.
    ///
    /// This is a separate unit. Zero means the entry claims no such drain;
    /// it does not mean there are no locks, callbacks or other instructions.
    #[must_use]
    pub const fn io_write_attempts(self) -> u64 {
        self.io_write_attempts
    }

    /// Compose two sequential, same-goal bounds without changing their unit.
    pub fn checked_then(self, next: Self) -> Result<Self, ResponsivenessRefusal> {
        if self.goal != next.goal {
            return Err(ResponsivenessRefusal::DifferentGoals);
        }
        if self.unit != next.unit {
            return Err(ResponsivenessRefusal::DifferentUnits);
        }
        Ok(Self {
            goal: self.goal,
            unit: self.unit,
            polls: self
                .polls
                .checked_add(next.polls)
                .ok_or(ResponsivenessRefusal::Overflow)?,
            io_write_attempts: self
                .io_write_attempts
                .checked_add(next.io_write_attempts)
                .ok_or(ResponsivenessRefusal::Overflow)?,
        })
    }

    /// Compose a finite number of sequential operations. Zero means no work.
    pub fn checked_repeat(self, count: u64) -> Result<Self, ResponsivenessRefusal> {
        Ok(Self {
            goal: self.goal,
            unit: self.unit,
            polls: self
                .polls
                .checked_mul(count)
                .ok_or(ResponsivenessRefusal::Overflow)?,
            io_write_attempts: self
                .io_write_attempts
                .checked_mul(count)
                .ok_or(ResponsivenessRefusal::Overflow)?,
        })
    }

    /// Check **only poll headroom** against a proposed budget.
    ///
    /// No deadline, CPU cost, scheduling fairness, or native quota charging is
    /// inferred. In particular, ordinary native execution does not universally
    /// charge `Budget::consume_poll`; Lab and explicitly budgeted finalizers
    /// have their own charging boundaries. `u32::MAX` retains Budget's unlimited
    /// sentinel meaning. A fit is not a runtime termination certificate.
    pub fn check_poll_budget(
        self,
        budget: crate::types::Budget,
    ) -> Result<Self, ResponsivenessRefusal> {
        if self.unit != ResponsivenessUnit::OperationPolls {
            return Err(ResponsivenessRefusal::DifferentUnits);
        }
        if budget.poll_quota != u32::MAX && self.polls > u64::from(budget.poll_quota) {
            return Err(ResponsivenessRefusal::InsufficientPollBudget {
                required: self.polls,
                available: budget.poll_quota,
            });
        }
        Ok(self)
    }

    /// Check a real measurement in the bound's primary unit.
    ///
    /// The caller must obtain `goal_reached` from the actual checkpoint/result,
    /// not the case label. This is a diagnostic comparison, not an attestation
    /// that the measurement was collected correctly. A missing checkpoint or
    /// retained Pending operation refuses even when its poll count is small.
    pub fn check_observed(
        self,
        polls: u64,
        goal_reached: bool,
    ) -> Result<(), ResponsivenessRefusal> {
        if !goal_reached {
            return Err(ResponsivenessRefusal::GoalNotObserved);
        }
        if polls > self.polls {
            return Err(ResponsivenessRefusal::PollBoundExceeded {
                bound: self.polls,
                observed: polls,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum ResponsivenessRule {
    CheckpointCall,
    Checkpoint,
    ReadyWins,
    Ambient { write_attempts: u64 },
    NativeSocket,
    Sleep,
    Refuse(ResponsivenessRefusal),
}

/// One stock phase and the public aliases which reach it.
///
/// Phase-qualified aliases (for example `Pool::acquire#capacity-wait`) are
/// intentional: a full acquisition can enter a user factory and has a weaker
/// contract. Non-awaiting methods are inventoried too; absence of `.await`
/// does not establish a finite wall-time bound for user callbacks.
#[derive(Debug)]
pub struct ResponsivenessEntry {
    id: &'static str,
    aliases: &'static [&'static str],
    source: &'static str,
    contract: &'static str,
    rule: ResponsivenessRule,
}

impl ResponsivenessEntry {
    /// Stable inventory identifier.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }
    /// Exact public API names or explicitly named subphases.
    #[must_use]
    pub const fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }
    /// Maintained implementation seam, for inspection rather than proof by text.
    #[must_use]
    pub const fn source(&self) -> &'static str {
        self.source
    }
    /// Phase, result precedence, progress premises, and limits of the claim.
    #[must_use]
    pub const fn contract(&self) -> &'static str {
        self.contract
    }

    /// Obtain a finite bound only for the exact goal and context described here.
    pub fn bound(
        &self,
        goal: ResponsivenessGoal,
        query: ResponsivenessQuery,
    ) -> Result<FiniteResponsiveness, ResponsivenessRefusal> {
        if goal == ResponsivenessGoal::OwnerQuiescent {
            return Err(ResponsivenessRefusal::OwnerProgress);
        }
        if let ResponsivenessRule::Refuse(reason) = self.rule {
            return Err(reason);
        }
        let depth = query
            .mask_depth
            .ok_or(ResponsivenessRefusal::MissingContext)?;
        ResponsivenessRegistry::checked_mask_depth(depth, 0)?;
        if depth != 0 {
            return Err(ResponsivenessRefusal::Masked { depth });
        }
        if matches!(self.rule, ResponsivenessRule::ReadyWins)
            && goal == ResponsivenessGoal::CancellationObserved
        {
            return Err(ResponsivenessRefusal::CompletionMayWin);
        }
        if matches!(self.rule, ResponsivenessRule::NativeSocket) && cfg!(target_arch = "wasm32") {
            return Err(ResponsivenessRefusal::UnsupportedPlatform);
        }
        if matches!(
            self.rule,
            ResponsivenessRule::Ambient { .. }
                | ResponsivenessRule::Sleep
                | ResponsivenessRule::NativeSocket
        ) && !query.ambient
        {
            return Err(ResponsivenessRefusal::MissingAmbientContext);
        }
        if matches!(self.rule, ResponsivenessRule::Sleep)
            && matches!(
                query.kind,
                crate::types::CancelKind::Timeout | crate::types::CancelKind::Deadline
            )
        {
            return Err(ResponsivenessRefusal::TimerProgress);
        }
        Ok(FiniteResponsiveness {
            goal,
            unit: if matches!(self.rule, ResponsivenessRule::CheckpointCall) {
                ResponsivenessUnit::CheckpointCalls
            } else {
                ResponsivenessUnit::OperationPolls
            },
            polls: 1,
            io_write_attempts: match self.rule {
                ResponsivenessRule::Ambient { write_attempts }
                    if goal == ResponsivenessGoal::OperationReturned =>
                {
                    write_attempts
                }
                _ => 0,
            },
        })
    }
}

/// Read-only stock responsiveness inventory and conditional budget arithmetic.
///
/// The inventory covers channel wait/commit and adapter families, sync waits,
/// I/O providers/adapters, timers, masking, structured joins and finalization.
/// Unknown API names fail closed. An explicit unbounded classification is not
/// proof that cancellation never works: it means this implementation provides
/// no uniform finite bound for the requested boundary.
///
/// ```
/// use asupersync::{Budget, Cx};
/// use asupersync::cancel::{ResponsivenessGoal, ResponsivenessQuery, ResponsivenessRegistry};
/// use asupersync::types::CancelKind;
/// let cx = Cx::<asupersync::cx::cap::None>::detached_cancel_context();
/// let entry = ResponsivenessRegistry::lookup("sync::Mutex::lock").unwrap();
/// let bound = entry.bound(ResponsivenessGoal::OperationReturned,
///     ResponsivenessQuery::for_cx(&cx, CancelKind::User)).unwrap();
/// assert_eq!(bound.steps(), 1);
/// assert!(bound.check_poll_budget(Budget::INFINITE.with_poll_quota(1)).is_ok());
/// // The detached context does not schedule any future. This only checks the
/// // conditional requirement after the operation receives a cancellation poll.
/// ```
#[derive(Debug)]
pub struct ResponsivenessRegistry;

impl ResponsivenessRegistry {
    /// Every maintained entry, including explicit unsupported phases.
    #[must_use]
    pub const fn entries() -> &'static [ResponsivenessEntry] {
        STOCK_RESPONSIVENESS
    }

    /// Resolve an exact entry ID or public alias.
    ///
    /// An explicitly unsupported family also covers its qualified member names
    /// (for example `io::AsyncReadExt::read_exact`). Only refusal entries have
    /// this prefix behavior; a new method never inherits a finite bound.
    pub fn lookup(name: &str) -> Result<&'static ResponsivenessEntry, ResponsivenessRefusal> {
        STOCK_RESPONSIVENESS
            .iter()
            .find(|entry| entry.id == name || entry.aliases.contains(&name))
            .or_else(|| {
                STOCK_RESPONSIVENESS.iter().find(|entry| {
                    matches!(entry.rule, ResponsivenessRule::Refuse(_))
                        && entry.aliases.iter().any(|alias| {
                            name.strip_prefix(alias)
                                .is_some_and(|suffix| suffix.starts_with("::"))
                        })
                })
            })
            .ok_or(ResponsivenessRefusal::UnknownOperation)
    }

    /// Check nested mask depth against the same constant enforced by `Cx::masked`.
    /// This does not multiply depth by checkpoint interval or invent a body bound.
    pub fn checked_mask_depth(parent: u32, additional: u32) -> Result<u32, ResponsivenessRefusal> {
        let depth = parent
            .checked_add(additional)
            .ok_or(ResponsivenessRefusal::Overflow)?;
        let maximum = crate::types::task_context::MAX_MASK_DEPTH;
        if depth > maximum {
            return Err(ResponsivenessRefusal::MaskDepthExceeded { depth, maximum });
        }
        Ok(depth)
    }
}

macro_rules! responsiveness_entry {
    ($id:literal, [$($alias:literal),+ $(,)?], $source:literal, $rule:expr, $contract:literal) => {
        ResponsivenessEntry { id: $id, aliases: &[$($alias),+], source: $source, rule: $rule, contract: $contract }
    };
}

static STOCK_RESPONSIVENESS: &[ResponsivenessEntry] = &[
    responsiveness_entry!(
        "cx.checkpoint",
        ["Cx::checkpoint", "Cx::checkpoint_with"],
        "src/cx/cx.rs: checkpoint",
        ResponsivenessRule::CheckpointCall,
        "One explicit call acknowledges published cancellation when unmasked. The unit is checkpoint calls, not future polls; the registry inserts none. Evidence callbacks and locks must return."
    ),
    responsiveness_entry!(
        "mpsc.reserve",
        [
            "channel::mpsc::Sender::reserve",
            "channel::mpsc::Sender::reserve_checked",
            "channel::mpsc::Sender::send",
            "channel::mpsc::Sender::send_checked",
            "channel::mpsc::UnboundedSender::reserve",
            "channel::mpsc::UnboundedSender::reserve_checked"
        ],
        "src/channel/mpsc.rs: Reserve::poll_with_registration",
        ResponsivenessRule::Checkpoint,
        "An uncommitted capacity waiter checks before capacity/admission and removes its FIFO registration on cancellation. Checked and legacy variants share the poll path. Held permits are separate liabilities."
    ),
    responsiveness_entry!(
        "mpsc.receive",
        [
            "channel::mpsc::Receiver::recv",
            "channel::mpsc::Receiver::recv_many",
            "channel::mpsc::Receiver::poll_recv",
            "channel::mpsc::Receiver::poll_recv_many",
            "channel::mpsc::UnboundedReceiver::recv",
            "channel::mpsc::UnboundedReceiver::recv_many",
            "channel::mpsc::UnboundedReceiver::poll_recv",
            "channel::mpsc::UnboundedReceiver::poll_recv_many"
        ],
        "src/channel/mpsc.rs: Receiver::poll_recv and poll_recv_many",
        ResponsivenessRule::Checkpoint,
        "A nonzero-limit pending receive checks before consuming data. Zero-limit recv_many is an immediate non-waiting result. Cancellation clears its receive registration; no producer progress is required."
    ),
    responsiveness_entry!(
        "oneshot.receive",
        ["channel::oneshot::Receiver::recv"],
        "src/channel/oneshot.rs: RecvFuture::poll",
        ResponsivenessRule::ReadyWins,
        "A waiting receiver registers a cancellation waker and returns within one delivered poll; a committed value or closure wins over cancellation and need not acknowledge it. Waiter/cancel registration is removed."
    ),
    responsiveness_entry!(
        "broadcast.receive",
        ["channel::broadcast::Receiver::recv"],
        "src/channel/broadcast.rs: poll_recv_with_waiter",
        ResponsivenessRule::Checkpoint,
        "A waiting receiver checks cancellation before reading/cloning the next value and unregisters its waiter. An arbitrary Clone, waker or destructor must return."
    ),
    responsiveness_entry!(
        "watch.changed",
        ["channel::watch::Receiver::changed"],
        "src/channel/watch.rs: Receiver::poll_changed",
        ResponsivenessRule::Checkpoint,
        "A pending change wait checks cancellation on its next poll. Holding a borrowed value/lock is a separate synchronous scope, not a drain guarantee."
    ),
    responsiveness_entry!(
        "session.reserve",
        [
            "channel::session::TrackedSender::reserve",
            "channel::session::TrackedSender::reserve_checked",
            "channel::session::TrackedSender::send",
            "channel::session::TrackedSender::send_checked"
        ],
        "src/channel/session.rs: TrackedSender reserve/send forwarding",
        ResponsivenessRule::Checkpoint,
        "The uncommitted tracked MPSC capacity wait delegates to the same reserve future. Graded token commit/drop and user continuation are outside the wait bound."
    ),
    responsiveness_entry!(
        "mutex.lock",
        [
            "sync::Mutex::lock",
            "sync::Mutex::lock_until",
            "sync::OwnedMutexGuard::lock"
        ],
        "src/sync/mutex.rs: LockFuture::poll",
        ResponsivenessRule::Checkpoint,
        "A contended lock waiter checks before acquisition/deadline and unlinks itself on cancellation. No holder release is required; internal lock and wake callbacks must return."
    ),
    responsiveness_entry!(
        "rwlock.acquire",
        [
            "sync::RwLock::read",
            "sync::RwLock::write",
            "sync::OwnedRwLockReadGuard::read",
            "sync::OwnedRwLockWriteGuard::write"
        ],
        "src/sync/rwlock.rs: borrowed and owned read/write Future::poll",
        ResponsivenessRule::Checkpoint,
        "A contended reader/writer checks before acquisition and cleans its queue registration. Bound is independent of the old holder's progress, not of returning internal lock/waker operations."
    ),
    responsiveness_entry!(
        "semaphore.acquire",
        [
            "sync::Semaphore::acquire",
            "sync::Semaphore::acquire_many",
            "sync::Semaphore::acquire_checked",
            "sync::Semaphore::acquire_many_checked",
            "sync::OwnedSemaphorePermit::acquire",
            "sync::OwnedSemaphorePermit::acquire_checked"
        ],
        "src/sync/semaphore.rs: AcquireFuture::poll_with_registration",
        ResponsivenessRule::Checkpoint,
        "A genuinely parked nonzero acquisition checks before taking physical capacity, unlinks its FIFO node and wakes the successor. Zero-sized acquisition never parks and is separately inventoried."
    ),
    responsiveness_entry!(
        "semaphore.zero",
        [
            "sync::Semaphore::acquire#zero",
            "sync::Semaphore::acquire_checked#zero",
            "sync::OwnedSemaphorePermit::acquire#zero",
            "sync::OwnedSemaphorePermit::acquire_checked#zero"
        ],
        "src/sync/semaphore.rs: count == 0 branch",
        ResponsivenessRule::ReadyWins,
        "Zero permits return success immediately on the first poll, even when cancelled; no obligation is admitted and no cancellation checkpoint is promised."
    ),
    responsiveness_entry!(
        "pool.capacity-wait",
        [
            "sync::Pool::acquire#capacity-wait",
            "sync::GenericPool::acquire_checked#capacity-wait"
        ],
        "src/sync/pool.rs: WaitForNotification::poll and Pool::acquire loop",
        ResponsivenessRule::Checkpoint,
        "Only the actual capacity-notification phase: its checkpoint returns to the acquisition loop which rechecks cancellation and drops the waiter. Returning pending resource notifications/health callbacks is a premise; a factory phase is not covered."
    ),
    responsiveness_entry!(
        "once-cell.wait",
        ["sync::OnceCell::wait"],
        "src/sync/once_cell.rs: CancelAwareWaitInit::poll",
        ResponsivenessRule::ReadyWins,
        "A pending wait owns a cancellation registration and returns after its next poll. Initialization completion wins and may skip acknowledgement; dropping the inner completed wait removes its cell registration."
    ),
    responsiveness_entry!(
        "barrier.wait",
        ["sync::Barrier::wait"],
        "src/sync/barrier.rs: BarrierWaitFuture::poll and finish_cancelled",
        ResponsivenessRule::Checkpoint,
        "A pending arrival checks and acknowledges cancellation, unregistering the old arrival. An already advanced generation retains successful barrier completion, rather than rolling it back."
    ),
    responsiveness_entry!(
        "sleep.cancel",
        ["time::Sleep", "time::sleep", "time::sleep_until"],
        "src/time/sleep.rs: Sleep::poll cancellation branch",
        ResponsivenessRule::Sleep,
        "With the same actual ambient task Cx, published non-Timeout/non-Deadline cancellation acknowledges and returns () within one poll, cancelling the timer. Deadline/Timeout cancellation requires timer progress and does not use this branch."
    ),
    responsiveness_entry!(
        "io.copy",
        ["io::copy", "io::copy_with_progress"],
        "src/io/copy.rs: Copy and CopyWithProgress::poll",
        ResponsivenessRule::Ambient { write_attempts: 4 },
        "Ambient cancellation returns Interrupted in one poll after at most four best-effort nested write polls. Each nested poll must return. Pending stops drain; unwritten private bytes may be lost, so this is not a delivery or drop-cancel-safety guarantee."
    ),
    responsiveness_entry!(
        "io.copy-buf",
        ["io::copy_buf"],
        "src/io/copy.rs: CopyBuf::poll",
        ResponsivenessRule::Ambient { write_attempts: 0 },
        "Ambient cancellation checks before input consumption and returns Interrupted within one poll; buffered input remains caller-owned. Reader/writer callbacks must return."
    ),
    responsiveness_entry!(
        "io.copy-bidirectional",
        ["io::copy_bidirectional"],
        "src/io/copy.rs: CopyBidirectional::poll",
        ResponsivenessRule::Ambient { write_attempts: 8 },
        "Ambient cancellation returns Interrupted in one poll; at most four best-effort nested write calls per direction (eight total). This neither guarantees flush nor preserves private read-ahead on drop."
    ),
    responsiveness_entry!(
        "net.tcp-wait",
        [
            "net::TcpListener::accept",
            "net::TcpListener::poll_accept",
            "net::TcpStream::poll_read",
            "net::TcpStream::poll_read_vectored",
            "net::TcpStream::poll_write",
            "net::TcpStream::poll_write_vectored",
            "net::TcpStream::poll_flush",
            "net::TcpStream::poll_shutdown"
        ],
        "src/net/tcp/listener.rs: poll_accept; src/net/tcp/stream.rs: poll I/O",
        ResponsivenessRule::NativeSocket,
        "Native nonempty pending socket I/O with the actual ambient Cx checks before I/O and returns Interrupted on cancellation. This does not cover hostname resolution, connection setup, TLS, or arbitrary AsyncRead/AsyncWrite implementations."
    ),
    responsiveness_entry!(
        "net.udp-wait",
        [
            "net::UdpSocket::recv",
            "net::UdpSocket::recv_from",
            "net::UdpSocket::poll_recv",
            "net::UdpSocket::poll_recv_from",
            "net::UdpSocket::peek_from",
            "net::UdpSocket::poll_peek_from",
            "net::UdpSocket::send",
            "net::UdpSocket::poll_send"
        ],
        "src/net/udp.rs: single-datagram poll_recv/poll_recv_from/poll_peek_from/poll_send",
        ResponsivenessRule::NativeSocket,
        "Native single-datagram pending I/O with nonempty receive storage and the actual ambient Cx checks before socket I/O. Address resolution, batch loops, browser-unsupported paths and retained transport queues are separate."
    ),
    responsiveness_entry!(
        "channel.synchronous",
        [
            "channel::mpsc::Sender::try_reserve",
            "channel::mpsc::Sender::try_reserve_checked",
            "channel::mpsc::Sender::try_send",
            "channel::mpsc::Sender::try_send_checked",
            "channel::mpsc::Sender::send_evict_oldest",
            "channel::mpsc::Sender::send_evict_oldest_where",
            "channel::mpsc::UnboundedSender::send",
            "channel::mpsc::UnboundedSender::send_checked",
            "channel::mpsc::UnboundedSender::try_reserve",
            "channel::mpsc::UnboundedSender::try_reserve_checked",
            "channel::mpsc::Receiver::try_recv",
            "channel::mpsc::UnboundedReceiver::try_recv",
            "channel::broadcast::Sender::reserve",
            "channel::broadcast::Sender::reserve_checked",
            "channel::broadcast::Sender::send",
            "channel::broadcast::Sender::send_checked",
            "channel::broadcast::Receiver::try_recv",
            "channel::oneshot::Sender::reserve",
            "channel::oneshot::Sender::reserve_checked",
            "channel::oneshot::Sender::send",
            "channel::oneshot::Sender::send_checked",
            "channel::oneshot::Sender::send_blocking",
            "channel::oneshot::Receiver::try_recv",
            "channel::watch::Sender::send",
            "channel::watch::Sender::send_modify",
            "channel::watch::Receiver::borrow",
            "channel::watch::Receiver::borrow_and_update",
            "channel::watch::Receiver::borrow_and_clone",
            "channel::watch::Receiver::borrow_and_update_clone"
        ],
        "src/channel/{mpsc,oneshot,broadcast,watch}.rs: synchronous operations",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::SynchronousCode),
        "No async suspension is promised, but locks, predicates, Clone/Drop and wakers can run arbitrary code. Explicit-Cx checked entrypoints checkpoint; legacy no-Cx operations do not. Neither fact bounds elapsed time or inserts cancellation inside commit."
    ),
    responsiveness_entry!(
        "channel.commit",
        [
            "channel::mpsc::SendPermit::send",
            "channel::mpsc::SendPermit::try_send",
            "channel::mpsc::SendPermit::abort",
            "channel::oneshot::SendPermit::send",
            "channel::oneshot::SendPermit::abort",
            "channel::broadcast::SendPermit::send",
            "channel::session::TrackedPermit::send",
            "channel::session::TrackedPermit::try_send",
            "channel::session::TrackedOneshotPermit::send",
            "channel::session::TrackedPermit::abort",
            "channel::session::TrackedOneshotPermit::abort",
            "channel::mpsc::SendPermit::drop",
            "channel::oneshot::SendPermit::drop",
            "channel::broadcast::SendPermit::drop",
            "channel::mpsc::Receiver::close",
            "channel::mpsc::UnboundedReceiver::close"
        ],
        "src/channel/{mpsc,oneshot,broadcast,session}.rs: permit terminal and drop paths",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::SynchronousCode),
        "Commit/abort/drop has no awaited queue wait but may execute arbitrary payload/notification destructors and callbacks. Holding a permit across user awaits has no cancellation completion bound; ordinary Rust move retains original liability."
    ),
    responsiveness_entry!(
        "session.synchronous",
        [
            "channel::session::TrackedSender::try_reserve",
            "channel::session::TrackedSender::try_reserve_checked",
            "channel::session::TrackedSender::try_send_checked",
            "channel::session::TrackedOneshotSender::reserve",
            "channel::session::TrackedOneshotSender::reserve_checked",
            "channel::session::TrackedOneshotSender::send",
            "channel::session::TrackedOneshotSender::send_checked"
        ],
        "src/channel/session.rs: synchronous forwarding and graded terminal operations",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::SynchronousCode),
        "Delegates underlying synchronous admission/commit with graded proof bookkeeping; this does not create a bounded user-code critical section."
    ),
    responsiveness_entry!(
        "channel.adapters",
        [
            "channel::fault",
            "channel::partition",
            "channel::crash",
            "channel::clock_skew",
            "channel::erasure"
        ],
        "src/channel/{fault,partition,crash,clock_skew,erasure}.rs",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::ExternalProgress),
        "Fault/delay/partition/erasure adapters can add buffering, timers, coding and user progress. All their wait/commit methods are classified here as requiring a separate adapter contract; they never silently inherit base-channel bounds."
    ),
    responsiveness_entry!(
        "sync.synchronous",
        [
            "sync::Mutex::try_lock",
            "sync::Mutex::try_lock_owned",
            "sync::RwLock::try_read",
            "sync::RwLock::try_write",
            "sync::Semaphore::try_acquire",
            "sync::Semaphore::try_acquire_many",
            "sync::Semaphore::try_acquire_checked",
            "sync::Semaphore::try_acquire_many_checked",
            "sync::OwnedSemaphorePermit::try_acquire",
            "sync::OwnedSemaphorePermit::try_acquire_checked",
            "sync::Semaphore::add_permits",
            "sync::Semaphore::close",
            "sync::SemaphorePermit::commit",
            "sync::SemaphorePermit::forget",
            "sync::SemaphorePermit::drop",
            "sync::OwnedSemaphorePermit::drop",
            "sync::MutexGuard::drop",
            "sync::RwLockReadGuard::drop",
            "sync::RwLockWriteGuard::drop",
            "sync::ContendedMutex::lock",
            "sync::OwnedSemaphorePermit",
            "sync::MutexGuard",
            "sync::MappedMutexGuard",
            "sync::OwnedMutexGuard",
            "sync::OwnedMappedMutexGuard",
            "sync::RwLockReadGuard",
            "sync::RwLockWriteGuard",
            "sync::OwnedRwLockReadGuard",
            "sync::OwnedRwLockWriteGuard"
        ],
        "src/sync/{mutex,rwlock,semaphore,contended_mutex}.rs",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::SynchronousCode),
        "Synchronous acquisition/release, mapping/downgrading/forgetting guards and lock-based operations are not a uniform finite cancellation boundary. User-held guards and wake/destructor code require their own progress premises."
    ),
    responsiveness_entry!(
        "pool.full-acquire",
        [
            "sync::Pool::acquire",
            "sync::GenericPool::acquire_checked",
            "sync::GenericPool::warmup"
        ],
        "src/sync/pool.rs: Pool::acquire/create_resource and warmup",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::ExternalProgress),
        "Full acquisition/warmup may await an arbitrary factory under TimeoutFuture. Poll-returning but cancellation-blind factory progress or real deadline progress is required. Capacity-phase cancellation alone is not a bound for the complete operation."
    ),
    responsiveness_entry!(
        "pool.return",
        [
            "sync::Pool::try_acquire",
            "sync::GenericPool::try_acquire_checked",
            "sync::PooledResource::return_to_pool",
            "sync::PooledResource::discard",
            "sync::PooledResource::drop",
            "sync::CheckedPooledResource::return_to_pool",
            "sync::CheckedPooledResource::discard",
            "sync::CheckedPooledResource::drop",
            "sync::Pool::close"
        ],
        "src/sync/pool.rs: checkout, health check, return and close",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::SynchronousCode),
        "Returning physical capacity and liability is distinct from completion of arbitrary resource Drop, health/time callbacks and return wakers. GenericPool close executes these on its first poll; the public Pool trait may provide arbitrary async close work. No uniform cancellation bound is supplied."
    ),
    responsiveness_entry!(
        "once-cell.initialize",
        [
            "sync::OnceCell::get_or_init",
            "sync::OnceCell::get_or_try_init",
            "sync::OnceCell::get_or_init_blocking"
        ],
        "src/sync/once_cell.rs: initialization owner and WaitInit",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::ExternalProgress),
        "Initialization awaits arbitrary user code, or blocks for it; competing initialization waits do not take Cx. The separate cancel-aware wait API must not be confused with ownership of initialization."
    ),
    responsiveness_entry!(
        "notify.wait",
        [
            "sync::Notify::notified",
            "sync::Notify::wait_until",
            "sync::Notified",
            "signal::Signal::recv"
        ],
        "src/sync/notify.rs: Notified::poll; src/signal/signal.rs: Signal::recv",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::ExternalProgress),
        "Notification/signal delivery or predicate progress is required. These futures do not checkpoint caller cancellation. Drop can remove a registration but is not successful signal delivery or owner drain."
    ),
    responsiveness_entry!(
        "notify.publish",
        [
            "sync::Notify::notify_one",
            "sync::Notify::notify_waiters",
            "sync::OnceCell::set"
        ],
        "src/sync/{notify,once_cell}.rs: publication",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::SynchronousCode),
        "Publication may notify user wakers or drop values; no async wait is added, and no callback duration is bounded."
    ),
    responsiveness_entry!(
        "oneshot.closed",
        [
            "channel::oneshot::Sender::poll_closed",
            "channel::oneshot::Receiver::poll_closed"
        ],
        "src/channel/oneshot.rs: poll_closed",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::ExternalProgress),
        "Requires actual peer closure; poll_closed has no Cx cancellation checkpoint."
    ),
    responsiveness_entry!(
        "io.generic",
        [
            "io::AsyncRead",
            "io::AsyncReadVectored",
            "io::AsyncWrite",
            "io::AsyncWriteVectored",
            "io::AsyncSeek",
            "io::AsyncBufRead",
            "io::AsyncReadExt",
            "io::AsyncReadVectoredExt",
            "io::AsyncWriteExt",
            "io::AsyncSeekExt",
            "io::ext",
            "io::ReadU8",
            "io::ReadI8",
            "io::WriteU8",
            "io::WriteI8",
            "io::Read",
            "io::ReadExact",
            "io::ReadToEnd",
            "io::ReadToString",
            "io::ReadVectored",
            "io::Write",
            "io::WriteAll",
            "io::WriteAllBuf",
            "io::WriteVectored",
            "io::Flush",
            "io::Shutdown",
            "io::Seek"
        ],
        "src/io/{read,write,seek}.rs and src/io/ext/",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::ExternalProgress),
        "All generic read/write/exact/all/vectored/typed integer/float/flush/shutdown/seek extension waits depend on provider polling. The traits impose no universal cancellation checkpoint; bounded bytes do not bound Pending retries or a nonreturning provider poll."
    ),
    responsiveness_entry!(
        "io.buffered",
        [
            "io::BufReader",
            "io::BufWriter",
            "io::Chain",
            "io::Take",
            "io::ReadHalf",
            "io::WriteHalf",
            "io::ReadLine",
            "io::read_line",
            "io::ReadLineCancelSafe",
            "io::LineReader",
            "io::Lines",
            "io::ReaderStream",
            "io::StreamReader"
        ],
        "src/io/{buf_reader,buf_writer,split,read,read_line,lines,stream_adapters}.rs",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::ExternalProgress),
        "Every wait/flush/read-line/stream adapter forwards to a generic provider and may loop for a delimiter, EOF or buffered output. Finite storage and per-poll batching do not establish cancellation or terminal progress."
    ),
    responsiveness_entry!(
        "io.write-commit",
        [
            "io::WritePermit::commit",
            "io::WritePermit::abort",
            "io::WritePermit::drop"
        ],
        "src/io/write_permit.rs: WritePermit::commit",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::ExternalProgress),
        "Before commit, local data may be discarded. Commit awaits generic write_all with possible partial writes, without a Cx checkpoint; no finite cancellation or full-delivery bound is inherited from channel permits."
    ),
    responsiveness_entry!(
        "io.host-provider",
        [
            "io::IoCap",
            "io::BrowserReadableStream",
            "io::BrowserWritableStream",
            "io::BrowserMessagePort",
            "io::BrowserMessageChannel",
            "io::BrowserBroadcastChannel",
            "io::BrowserStorageAdapter",
            "io::FetchIoCap",
            "io::TransportIoCap",
            "io::StorageIoCap",
            "io::HostApiIoCap"
        ],
        "src/io/{cap,browser_stream,browser_storage}.rs",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::ExternalProgress),
        "Host/browser capability and stream waits require provider-specific cancellation/progress guarantees. Unsupported target/provider combinations are not finite successes."
    ),
    responsiveness_entry!(
        "net.composite",
        [
            "net::TcpStream::connect",
            "net::TcpStream::connect_timeout",
            "net::UdpSocket::connect",
            "net::UdpSocket::send_to",
            "net::UdpSocket::send_batch_to",
            "net::UdpSocket::send_connected_batch",
            "net::UdpSocket::recv_batch_from",
            "net::UdpSocket::recv_stream",
            "net::UdpSocket::send_sink",
            "net::unix",
            "net::tls",
            "net::quic_native",
            "net::dns",
            "fs",
            "process"
        ],
        "src/net/{tcp,udp,unix,tls,quic_native,dns}; src/fs; src/process",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::ExternalProgress),
        "Resolution, multi-address/batch loops, Unix/TLS/QUIC handshakes, filesystem/blocking operations and process waits need exact provider/phase contracts. This explicit family classification includes their public wait/commit methods; it grants no generic finite inheritance."
    ),
    responsiveness_entry!(
        "time.deadline",
        [
            "time::TimeoutFuture",
            "time::timeout",
            "time::timeout_at",
            "time::budget_sleep",
            "time::budget_timeout",
            "time::with_deadline",
            "time::with_timeout",
            "time::Sleep#deadline-or-timeout-cancel"
        ],
        "src/time/{timeout_future,budget_ext,deadline,sleep}.rs",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::TimerProgress),
        "Deadline observation needs the bound clock/driver to advance and deliver a poll. At exact timeout boundary a completed inner future wins. Budget helpers snapshot/clip deadlines; they do not turn arbitrary future cleanup into a finite successful drain."
    ),
    responsiveness_entry!(
        "time.interval",
        [
            "time::Interval::tick",
            "time::Interval::poll_tick",
            "time::Interval::reset",
            "time::Interval::reset_at",
            "time::Interval::reset_after"
        ],
        "src/time/interval.rs",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::TimerProgress),
        "These are synchronous caller-time queries, not an asynchronously parked tick future. Progress depends on supplied time; missed-tick policy does not imply a cancellation bound."
    ),
    responsiveness_entry!(
        "task.join",
        [
            "runtime::TaskHandle::join",
            "runtime::TaskHandle::join_with_drop_reason",
            "runtime::TaskHandle::poll_join",
            "runtime::TaskHandle::try_join"
        ],
        "src/runtime/task_handle.rs: JoinFuture and uninterruptible result receiver",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::OwnerProgress),
        "Joining preserves actual child termination through a cancellation-independent result channel. Abort requests cancellation but does not preempt or complete a noncooperative child; dropping a join is not draining it."
    ),
    responsiveness_entry!(
        "structured.drain",
        [
            "Scope::join",
            "Scope::join_all",
            "Scope::race",
            "Scope::race_all",
            "Scope::hedge",
            "Scope::quorum",
            "Scope::first_ok",
            "Scope::timeout",
            "Scope::region",
            "Scope::region_with_budget",
            "Scope::region_with_priority",
            "Scope::region_with_budget_and_priority",
            "Scope::region_with_budget_and_capability_budget",
            "combinator::Select",
            "combinator::SelectAll",
            "combinator::SelectAllDrain",
            "combinator::PipelineExecution::run",
            "combinator::execute_map_reduce",
            "Scope::pipeline",
            "Scope::map_reduce",
            "Cx::race",
            "Cx::race_named",
            "Cx::race_timeout",
            "Cx::race_timeout_named",
            "Cx::race_drained",
            "Cx::race_drained_named",
            "Cx::race_drained_timeout",
            "Cx::race_drained_timeout_named",
            "Cx::open_child_region",
            "cx::ChildRegionOpening"
        ],
        "src/cx/scope.rs; src/combinator/{select,pipeline,map_reduce}.rs",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::OwnerProgress),
        "Owned joins/loser drains, pipeline transforms/sinks, map/reducers and region finalizers require all retained children to progress. Generic Select/SelectAll return or drop/return losers according to their own API and do not establish drained quiescence. Finite fanout/storage is not finite cleanup."
    ),
    responsiveness_entry!(
        "finalizer.legacy",
        [
            "Scope::defer_sync",
            "Scope::defer_async",
            "record::Finalizer",
            "record::Finalizer::Async",
            "cx::ChildRegion::close"
        ],
        "src/record/finalizer.rs; src/cx/{scope,child_region}.rs",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::OwnerProgress),
        "Without an explicit shutdown envelope, legacy masked finalizers and region close wait for real user cleanup. A pending callback or nonreturning poll/destructor can prevent quiescence indefinitely."
    ),
    responsiveness_entry!(
        "finalizer.envelope",
        ["supervision::ChildSpec::with_shutdown_budget"],
        "src/record/finalizer.rs: BudgetedFinalizer; src/record/region.rs: shared shutdown budget",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::OwnerProgress),
        "An explicit monotone envelope bounds admitted user polls and observes real timer deadlines, retiring with typed non-success on exhaustion. It does not ensure successful cleanup, wake a forever-Pending child from poll quota alone, preempt synchronous code, charge general native cost, or provide an aggregate subtree bound."
    ),
    responsiveness_entry!(
        "cx.mask",
        ["Cx::masked", "types::task_context::MAX_MASK_DEPTH"],
        "src/cx/cx.rs: Cx::masked; src/types/task_context.rs: MAX_MASK_DEPTH",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::UnboundedMaskBody),
        "Maximum nesting is 64. That bounds guard depth, not time or instructions in arbitrary closures. A mask over a cancellation-dependent wait can withhold its only progress forever; depth times checkpoint interval is not a termination theorem."
    ),
    responsiveness_entry!(
        "runtime.blocking",
        [
            "Cx::spawn_blocking",
            "Cx::spawn_local",
            "runtime::Runtime::block_on",
            "runtime::RuntimeHandle::spawn",
            "stream::StreamExt",
            "transport::SymbolSinkExt",
            "transport::SymbolSink"
        ],
        "src/cx; src/runtime/{blocking_pool,builder}; src/stream",
        ResponsivenessRule::Refuse(ResponsivenessRefusal::OwnerProgress),
        "Arbitrary user futures, blocking closures, stream/sink combinators and task-local work have no uniform checkpoint/termination contract. Cancel requests and scheduler fairness do not preempt a poll which never returns."
    ),
];

#[cfg(test)]
#[path = "mod_responsiveness_tests_inline_tests.rs"]
mod responsiveness_tests;
