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
mod responsiveness_tests {
    use super::*;
    use crate::channel::{broadcast, mpsc, oneshot, session, watch};
    use crate::cx::Cx;
    use crate::sync::{Barrier, Mutex, OnceCell, RwLock, Semaphore};
    use crate::types::{Budget, CancelKind};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    fn poll<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(std::task::Waker::noop()))
    }

    fn returned(cx: &Cx, id: &str) -> FiniteResponsiveness {
        ResponsivenessRegistry::lookup(id)
            .expect("maintained entry")
            .bound(
                ResponsivenessGoal::OperationReturned,
                ResponsivenessQuery::for_cx(cx, CancelKind::User),
            )
            .expect("conditional operation-return bound")
    }

    // These are delivered-poll unit witnesses, deliberately not native scheduler
    // or wake-delivery proofs. Every caller first checks its real parked state.
    fn cancel_parked<F: Future + ?Sized>(cx: &Cx, id: &str, mut future: Pin<&mut F>) -> F::Output {
        assert!(poll(future.as_mut()).is_pending(), "{id}: still withheld");
        let bound = returned(cx, id);
        let before = cx.checkpoint_state().checkpoint_count;
        cx.cancel_with(CancelKind::User, Some("stock responsiveness witness"));
        let result = poll(future);
        bound
            .check_observed(1, result.is_ready())
            .expect("actual return");
        let delta = cx.checkpoint_state().checkpoint_count - before;
        assert!(delta > 0, "{id}: actual checkpoint after publication");
        assert!(
            cx.inner.read().cancel_acknowledged,
            "{id}: actual acknowledgement"
        );
        println!(
            "ASUPERSYNC_RESPONSIVENESS_UNIT {}",
            serde_json::json!({
                "entry": id, "unit": "operation_polls", "post_cancel_polls": 1,
                "checkpoint_delta": delta, "acknowledged": true,
                "scope": "manually_delivered_stock_operation_poll"
            })
        );
        match result {
            Poll::Ready(value) => value,
            Poll::Pending => unreachable!("the measured Ready predicate was required"),
        }
    }

    #[test]
    fn responsiveness_mpsc_and_tracked_capacity_cancel_before_commit() {
        for variant in 0..4 {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = mpsc::channel::<u8>(1);
            sender.try_send(7).expect("actual occupied physical slot");
            let tracked = session::TrackedSender::new(sender.clone());
            let mut wait: Pin<Box<dyn Future<Output = ()> + '_>> = match variant {
                0 => Box::pin(async {
                    assert!(matches!(
                        sender.reserve(&cx).await,
                        Err(mpsc::SendError::Cancelled(()))
                    ));
                }),
                1 => Box::pin(async {
                    assert!(matches!(
                        sender.reserve_checked(&cx).await,
                        Err(mpsc::CheckedSendError::Channel(mpsc::SendError::Cancelled(
                            ()
                        )))
                    ));
                }),
                2 => Box::pin(async {
                    assert!(matches!(
                        tracked.reserve(&cx).await,
                        Err(mpsc::SendError::Cancelled(()))
                    ));
                }),
                _ => Box::pin(async {
                    assert!(matches!(
                        tracked.reserve_checked(&cx).await,
                        Err(mpsc::CheckedSendError::Channel(mpsc::SendError::Cancelled(
                            ()
                        )))
                    ));
                }),
            };
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 1);
            cancel_parked(
                &cx,
                if variant < 2 {
                    "mpsc.reserve"
                } else {
                    "session.reserve"
                },
                wait.as_mut(),
            );
            drop(wait);
            let snapshot = sender.telemetry_snapshot(1);
            assert_eq!(snapshot.send_waiter_count, 0);
            assert_eq!(snapshot.reserved_uncommitted_obligations, 0);
            assert_eq!(snapshot.queued_messages, 1);
            assert_eq!(receiver.try_recv(), Ok(7));
            assert_eq!(receiver.try_recv(), Err(mpsc::RecvError::Empty));
        }
    }

    #[test]
    fn responsiveness_channel_receivers_cancel_from_actual_empty_waits() {
        for many in [false, true] {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = mpsc::channel::<u8>(1);
            let mut values = Vec::new();
            let mut wait: Pin<Box<dyn Future<Output = ()> + '_>> = if many {
                Box::pin(async {
                    assert_eq!(
                        receiver.recv_many(&cx, &mut values, 1).await,
                        Err(mpsc::RecvError::Cancelled)
                    );
                })
            } else {
                Box::pin(async {
                    assert_eq!(receiver.recv(&cx).await, Err(mpsc::RecvError::Cancelled));
                })
            };
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(sender.telemetry_snapshot(2).recv_waiter_count, 1);
            cancel_parked(&cx, "mpsc.receive", wait.as_mut());
            drop(wait);
            assert!(values.is_empty());
            assert_eq!(sender.telemetry_snapshot(2).recv_waiter_count, 0);
            sender
                .try_send(11)
                .expect("cancellation did not close receiver");
            assert_eq!(receiver.try_recv(), Ok(11));
        }
        {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = mpsc::unbounded::<u8>();
            let mut wait = Box::pin(receiver.recv(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(sender.telemetry_snapshot(3).recv_waiter_count, 1);
            assert_eq!(
                cancel_parked(&cx, "mpsc.receive", wait.as_mut()),
                Err(mpsc::RecvError::Cancelled)
            );
            drop(wait);
            assert_eq!(sender.telemetry_snapshot(3).recv_waiter_count, 0);
        }
        {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = oneshot::channel::<u8>();
            let mut wait = Box::pin(receiver.recv(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(sender.telemetry_snapshot(4).recv_waiter_count, 1);
            assert_eq!(
                cancel_parked(&cx, "oneshot.receive", wait.as_mut()),
                Err(oneshot::RecvError::Cancelled)
            );
            drop(wait);
            assert_eq!(sender.telemetry_snapshot(4).recv_waiter_count, 0);
        }
        {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = broadcast::channel::<u8>(1);
            let mut wait = Box::pin(receiver.recv(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(sender.telemetry_snapshot(5).recv_waiter_count, 1);
            assert_eq!(
                cancel_parked(&cx, "broadcast.receive", wait.as_mut()),
                Err(broadcast::RecvError::Cancelled)
            );
            drop(wait);
            assert_eq!(sender.telemetry_snapshot(5).recv_waiter_count, 0);
        }
        {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = watch::channel(9_u8);
            let mut wait = Box::pin(receiver.changed(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(sender.telemetry_snapshot(6).recv_waiter_count, 1);
            assert_eq!(
                cancel_parked(&cx, "watch.changed", wait.as_mut()),
                Err(watch::RecvError::Cancelled)
            );
            drop(wait);
            assert_eq!(sender.telemetry_snapshot(6).recv_waiter_count, 0);
            assert_eq!(*receiver.borrow(), 9);
        }
    }

    #[test]
    fn responsiveness_locks_and_semaphore_do_not_need_holder_release() {
        for owned in [false, true] {
            let cx = Cx::for_testing();
            let mutex = Arc::new(Mutex::new(17_u8));
            let held = mutex.try_lock().expect("actual held mutex");
            let mut wait: Pin<Box<dyn Future<Output = ()> + '_>> = if owned {
                Box::pin(async {
                    assert!(matches!(
                        crate::sync::OwnedMutexGuard::lock(Arc::clone(&mutex), &cx).await,
                        Err(crate::sync::LockError::Cancelled)
                    ));
                })
            } else {
                Box::pin(async {
                    assert!(matches!(
                        mutex.lock(&cx).await,
                        Err(crate::sync::LockError::Cancelled)
                    ));
                })
            };
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(mutex.waiters(), 1);
            cancel_parked(&cx, "mutex.lock", wait.as_mut());
            drop(wait);
            assert_eq!(mutex.waiters(), 0);
            assert_eq!(*held, 17);
            assert!(mutex.try_lock().is_err());
            drop(held);
            assert_eq!(*mutex.try_lock().expect("physical recovery"), 17);
        }
        for variant in 0..4 {
            let cx = Cx::for_testing();
            let lock = Arc::new(RwLock::new(19_u8));
            let held = lock
                .try_write()
                .expect("actual writer excludes all variants");
            let mut wait: Pin<Box<dyn Future<Output = ()> + '_>> = match variant {
                0 => Box::pin(async {
                    assert!(matches!(
                        lock.read(&cx).await,
                        Err(crate::sync::RwLockError::Cancelled)
                    ));
                }),
                1 => Box::pin(async {
                    assert!(matches!(
                        lock.write(&cx).await,
                        Err(crate::sync::RwLockError::Cancelled)
                    ));
                }),
                2 => Box::pin(async {
                    assert!(matches!(
                        crate::sync::OwnedRwLockReadGuard::read(Arc::clone(&lock), &cx).await,
                        Err(crate::sync::RwLockError::Cancelled)
                    ));
                }),
                _ => Box::pin(async {
                    assert!(matches!(
                        crate::sync::OwnedRwLockWriteGuard::write(Arc::clone(&lock), &cx).await,
                        Err(crate::sync::RwLockError::Cancelled)
                    ));
                }),
            };
            assert!(poll(wait.as_mut()).is_pending());
            cancel_parked(&cx, "rwlock.acquire", wait.as_mut());
            drop(wait);
            assert!(lock.try_read().is_err());
            assert_eq!(*held, 19);
            drop(held);
            assert_eq!(
                *lock
                    .try_write()
                    .expect("cancelled queue no longer blocks writer"),
                19
            );
        }
        for variant in 0..4 {
            let cx = Cx::for_testing();
            let semaphore = Arc::new(Semaphore::new(1));
            let held = semaphore.try_acquire(1).expect("physical permit held");
            let mut wait: Pin<Box<dyn Future<Output = ()> + '_>> = match variant {
                0 => Box::pin(async {
                    assert!(matches!(
                        semaphore.acquire(&cx, 1).await,
                        Err(crate::sync::AcquireError::Cancelled)
                    ));
                }),
                1 => Box::pin(async {
                    assert!(matches!(
                        semaphore.acquire_checked(&cx, 1).await,
                        Err(crate::sync::semaphore::CheckedAcquireError::Semaphore(
                            crate::sync::AcquireError::Cancelled
                        ))
                    ));
                }),
                2 => Box::pin(async {
                    assert!(matches!(
                        crate::sync::OwnedSemaphorePermit::acquire(Arc::clone(&semaphore), &cx, 1)
                            .await,
                        Err(crate::sync::AcquireError::Cancelled)
                    ));
                }),
                _ => Box::pin(async {
                    assert!(matches!(
                        crate::sync::OwnedSemaphorePermit::acquire_checked(
                            Arc::clone(&semaphore),
                            &cx,
                            1
                        )
                        .await,
                        Err(crate::sync::semaphore::CheckedAcquireError::Semaphore(
                            crate::sync::AcquireError::Cancelled
                        ))
                    ));
                }),
            };
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(semaphore.telemetry_snapshot(8).waiter_count, 1);
            cancel_parked(&cx, "semaphore.acquire", wait.as_mut());
            drop(wait);
            assert_eq!(semaphore.telemetry_snapshot(8).waiter_count, 0);
            assert_eq!(semaphore.available_permits(), 0);
            drop(held);
            assert_eq!(semaphore.available_permits(), 1);
        }
    }

    fn timer_context() -> (
        Cx,
        Arc<crate::time::VirtualClock>,
        crate::time::TimerDriverHandle,
    ) {
        let clock = Arc::new(crate::time::VirtualClock::new());
        let timer = crate::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let cx = Cx::new_with_drivers(
            crate::types::RegionId::new_for_test(0, 1),
            crate::types::TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        (cx, clock, timer)
    }

    #[test]
    fn responsiveness_pool_cell_and_barrier_cancel_without_external_progress() {
        use crate::sync::{GenericPool, Pool, PoolConfig, PoolError};
        for checked in [false, true] {
            let (cx, _clock, timer) = timer_context();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let pool = GenericPool::new(
                || std::future::ready(Ok::<_, std::io::Error>(23_u8)),
                PoolConfig::with_max_size(1),
            );
            let mut first = pool.acquire(&cx);
            let held = match poll(first.as_mut()) {
                Poll::Ready(Ok(held)) => held,
                Poll::Ready(Err(error)) => panic!("ready factory acquisition failed: {error}"),
                Poll::Pending => panic!("ready factory unexpectedly suspended"),
            };
            drop(first);
            let mut wait: Pin<Box<dyn Future<Output = ()> + '_>> = if checked {
                Box::pin(async {
                    assert!(matches!(
                        pool.acquire_checked(&cx).await,
                        Err(crate::sync::CheckedPoolError::Pool(PoolError::Cancelled))
                    ));
                })
            } else {
                Box::pin(async {
                    assert!(matches!(pool.acquire(&cx).await, Err(PoolError::Cancelled)));
                })
            };
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(pool.stats().waiters, 1);
            assert_eq!(pool.stats().active, 1);
            cancel_parked(&cx, "pool.capacity-wait", wait.as_mut());
            drop(wait);
            assert_eq!(pool.stats().waiters, 0);
            assert_eq!(
                pool.stats().active,
                1,
                "holder did not release to satisfy waiter"
            );
            drop(held);
            assert_eq!(pool.stats().active, 0);
            assert_eq!(pool.stats().idle, 1);
            assert!(poll(pool.close().as_mut()).is_ready());
            assert_eq!(pool.stats().total, 0);
            assert_eq!(timer.pending_count(), 0);
        }
        {
            let cx = Cx::for_testing();
            let cell = OnceCell::<u8>::new();
            let mut wait = Box::pin(cell.wait(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(cell.telemetry_snapshot(9).waiter_count, 1);
            assert_eq!(
                cancel_parked(&cx, "once-cell.wait", wait.as_mut()),
                Err(crate::sync::OnceCellError::Cancelled)
            );
            drop(wait);
            assert_eq!(cell.telemetry_snapshot(9).waiter_count, 0);
            assert!(!cell.is_initialized());
            cell.set(31)
                .expect("cancellation did not initialize or poison cell");
            assert_eq!(cell.get(), Some(&31));
        }
        {
            let cx = Cx::for_testing();
            let barrier = Barrier::new(2);
            let mut wait = Box::pin(barrier.wait(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(barrier.telemetry_snapshot(10).waiter_count, 1);
            assert_eq!(barrier.telemetry_snapshot(10).occupied_units, 1);
            assert!(matches!(
                cancel_parked(&cx, "barrier.wait", wait.as_mut()),
                Err(crate::sync::BarrierWaitError::Cancelled)
            ));
            drop(wait);
            assert_eq!(barrier.telemetry_snapshot(10).waiter_count, 0);
            assert_eq!(barrier.telemetry_snapshot(10).occupied_units, 0);
            assert_eq!(barrier.telemetry_snapshot(10).generation, 0);
        }
    }

    #[test]
    fn responsiveness_ready_values_zero_units_and_barrier_precedence_are_explicit() {
        for closed in [false, true] {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = oneshot::channel::<u8>();
            let mut wait = Box::pin(receiver.recv(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            let before = cx.checkpoint_state().checkpoint_count;
            cx.cancel_with(CancelKind::User, Some("value and cancellation race"));
            if closed {
                drop(sender);
            } else {
                sender
                    .send(&Cx::for_testing(), 41)
                    .expect("independent producer commits real value");
            }
            let result = poll(wait.as_mut());
            assert_eq!(
                result,
                Poll::Ready(if closed {
                    Err(oneshot::RecvError::Closed)
                } else {
                    Ok(41)
                })
            );
            assert_eq!(
                cx.checkpoint_state().checkpoint_count,
                before,
                "ready result precedes checkpoint"
            );
            assert!(!cx.inner.read().cancel_acknowledged);
            returned(&cx, "oneshot.receive")
                .check_observed(1, result.is_ready())
                .unwrap();
            assert_eq!(
                ResponsivenessRegistry::lookup("oneshot.receive")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::CancellationObserved,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::CompletionMayWin)
            );
            drop(wait);
            assert_eq!(receiver.telemetry_snapshot(11).recv_waiter_count, 0);
        }
        {
            let cx = Cx::for_testing();
            let cell = OnceCell::new();
            let mut wait = Box::pin(cell.wait(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            let before = cx.checkpoint_state().checkpoint_count;
            cx.cancel_with(CancelKind::User, Some("initialized value wins"));
            cell.set(43_u8).unwrap();
            assert_eq!(poll(wait.as_mut()), Poll::Ready(Ok(())));
            assert_eq!(cx.checkpoint_state().checkpoint_count, before);
            assert!(!cx.inner.read().cancel_acknowledged);
            drop(wait);
            assert_eq!(cell.telemetry_snapshot(12).waiter_count, 0);
            assert_eq!(
                ResponsivenessRegistry::lookup("once-cell.wait")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::CancellationObserved,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::CompletionMayWin)
            );
        }
        for checked in [false, true] {
            let cx = Cx::for_testing();
            let semaphore = Semaphore::new(0);
            cx.cancel_with(CancelKind::User, Some("zero units do not checkpoint"));
            let before = cx.checkpoint_state().checkpoint_count;
            if checked {
                let mut wait = Box::pin(semaphore.acquire_checked(&cx, 0));
                assert!(matches!(poll(wait.as_mut()), Poll::Ready(Ok(_))));
            } else {
                let mut wait = Box::pin(semaphore.acquire(&cx, 0));
                assert!(matches!(poll(wait.as_mut()), Poll::Ready(Ok(_))));
            }
            assert_eq!(cx.checkpoint_state().checkpoint_count, before);
            assert!(!cx.inner.read().cancel_acknowledged);
            assert_eq!(semaphore.telemetry_snapshot(13).waiter_count, 0);
            assert_eq!(returned(&cx, "semaphore.zero").steps(), 1);
            assert_eq!(
                ResponsivenessRegistry::lookup("semaphore.zero")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::CancellationObserved,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::CompletionMayWin)
            );
        }
        {
            let cx = Cx::for_testing();
            let peer = Cx::for_testing();
            let barrier = Barrier::new(2);
            let mut wait = Box::pin(barrier.wait(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            let mut second = Box::pin(barrier.wait(&peer));
            assert!(matches!(poll(second.as_mut()), Poll::Ready(Ok(_))));
            let before = cx.checkpoint_state().checkpoint_count;
            cx.cancel_with(CancelKind::User, Some("generation already committed"));
            assert!(matches!(poll(wait.as_mut()), Poll::Ready(Ok(_))));
            assert!(cx.checkpoint_state().checkpoint_count > before);
            assert!(cx.inner.read().cancel_acknowledged);
            drop(wait);
            drop(second);
            assert_eq!(barrier.telemetry_snapshot(14).generation, 1);
            assert_eq!(barrier.telemetry_snapshot(14).waiter_count, 0);
            assert_eq!(barrier.telemetry_snapshot(14).occupied_units, 0);
        }
    }

    #[test]
    fn responsiveness_sleep_requires_ambient_context_and_distinguishes_timer_cancellation() {
        use crate::time::Sleep;
        use crate::types::Time;
        {
            let (cx, _clock, timer) = timer_context();
            assert_eq!(
                ResponsivenessRegistry::lookup("sleep.cancel")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::MissingAmbientContext)
            );
            let _ambient = Cx::set_current(Some(cx.clone()));
            let mut wait = Box::pin(Sleep::new(Time::from_secs(1)));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(timer.pending_count(), 1);
            cancel_parked(&cx, "sleep.cancel", wait.as_mut());
            drop(wait);
            assert_eq!(timer.pending_count(), 0);
        }
        for kind in [CancelKind::Timeout, CancelKind::Deadline] {
            let (cx, clock, timer) = timer_context();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let mut wait = Box::pin(Sleep::new(Time::from_secs(1)));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(timer.pending_count(), 1);
            let before = cx.checkpoint_state().checkpoint_count;
            cx.cancel_with(kind, Some("timer completion remains required"));
            assert_eq!(
                ResponsivenessRegistry::lookup("sleep.cancel")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::for_cx(&cx, kind)
                    ),
                Err(ResponsivenessRefusal::TimerProgress)
            );
            for _ in 0..3 {
                assert!(poll(wait.as_mut()).is_pending());
            }
            assert_eq!(cx.checkpoint_state().checkpoint_count, before);
            assert_eq!(timer.pending_count(), 1);
            clock.set(Time::from_secs(1));
            assert_eq!(timer.process_timers(), 1, "actual registered timer fires");
            assert_eq!(poll(wait.as_mut()), Poll::Ready(()));
            drop(wait);
            assert_eq!(timer.pending_count(), 0);
        }
    }

    #[derive(Default)]
    struct WriteState {
        released: bool,
        calls: usize,
        bytes: Vec<u8>,
        waiter: Option<std::task::Waker>,
    }

    struct ControlledIo {
        input: &'static [u8],
        writes: Arc<parking_lot::Mutex<WriteState>>,
    }

    impl ControlledIo {
        fn new() -> (Self, Arc<parking_lot::Mutex<WriteState>>) {
            let writes = Arc::new(parking_lot::Mutex::new(WriteState::default()));
            (
                Self {
                    input: b"0123456789abcdef",
                    writes: Arc::clone(&writes),
                },
                writes,
            )
        }
    }

    impl crate::io::AsyncRead for ControlledIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut crate::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            crate::io::AsyncRead::poll_read(Pin::new(&mut self.input), cx, buf)
        }
    }

    impl crate::io::AsyncWrite for ControlledIo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut state = self.writes.lock();
            state.calls += 1;
            if !state.released {
                state.waiter = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let count = buf.len().min(1);
            state.bytes.extend_from_slice(&buf[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn release_writes(state: &parking_lot::Mutex<WriteState>) {
        let waiter = {
            let mut state = state.lock();
            state.released = true;
            state.waiter.take()
        };
        waiter
            .expect("actual withheld write poll registered a waiter")
            .wake();
    }

    fn cancel_copy<T, F: Future<Output = std::io::Result<T>> + ?Sized>(
        cx: &Cx,
        id: &str,
        mut copy: Pin<&mut F>,
        writers: &[Arc<parking_lot::Mutex<WriteState>>],
        expected_attempts: usize,
    ) {
        assert!(poll(copy.as_mut()).is_pending());
        assert!(
            poll(copy.as_mut()).is_pending(),
            "actual retained prefix stays blocked"
        );
        let previous: Vec<_> = writers
            .iter()
            .map(|writer| {
                let writer = writer.lock();
                assert!(writer.waiter.is_some());
                assert!(writer.bytes.is_empty());
                writer.calls
            })
            .collect();
        let bound = returned(cx, id);
        let before = cx.checkpoint_state().checkpoint_count;
        cx.cancel_with(CancelKind::User, Some("copy cancellation drain"));
        for writer in writers {
            release_writes(writer);
        }
        let result = poll(copy);
        bound.check_observed(1, result.is_ready()).unwrap();
        assert!(
            matches!(result, Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted)
        );
        assert!(cx.checkpoint_state().checkpoint_count > before);
        let attempts: usize = writers
            .iter()
            .zip(previous)
            .map(|(writer, previous)| writer.lock().calls - previous)
            .sum();
        assert_eq!(
            attempts, expected_attempts,
            "causal nested write-poll boundary"
        );
        assert_eq!(u64::try_from(attempts).unwrap(), bound.io_write_attempts());
        for writer in writers {
            let writer = writer.lock();
            assert_eq!(
                writer.bytes.as_slice(),
                if expected_attempts == 0 {
                    b"".as_slice()
                } else {
                    b"0123".as_slice()
                }
            );
            assert!(writer.waiter.is_none());
        }
        println!(
            "ASUPERSYNC_RESPONSIVENESS_IO {}",
            serde_json::json!({
                "entry": id, "post_cancel_polls": 1, "actual_write_attempts": attempts,
                "result": "Interrupted", "scope": "stock_copy_with_controlled_pending_provider",
                "full_delivery": false
            })
        );
    }

    #[test]
    fn responsiveness_copy_variants_enforce_real_bounded_cancel_drain() {
        for progress in [false, true] {
            let cx = Cx::for_testing();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let mut reader = &b"0123456789abcdef"[..];
            let (mut writer, state) = ControlledIo::new();
            let mut observed = Vec::new();
            let mut copy: Pin<Box<dyn Future<Output = std::io::Result<u64>> + '_>> = if progress {
                Box::pin(crate::io::copy_with_progress(
                    &mut reader,
                    &mut writer,
                    |bytes| observed.push(bytes),
                ))
            } else {
                Box::pin(crate::io::copy(&mut reader, &mut writer))
            };
            cancel_copy(&cx, "io.copy", copy.as_mut(), &[state], 4);
            drop(copy);
            assert!(
                reader.is_empty(),
                "private read-ahead consumed the real input"
            );
            assert_eq!(observed, if progress { vec![4] } else { vec![] });
        }
        {
            let cx = Cx::for_testing();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let mut reader = crate::io::BufReader::new(&b"0123456789abcdef"[..]);
            let (mut writer, state) = ControlledIo::new();
            let mut copy = Box::pin(crate::io::copy_buf(&mut reader, &mut writer));
            cancel_copy(&cx, "io.copy-buf", copy.as_mut(), &[state], 0);
            drop(copy);
            // End the cancelled ambient scope before resuming. Installing None
            // is a no-op on the context stack; it does not hide an outer Cx.
            drop(_ambient);
            assert!(Cx::current().is_none());
            let mut retained = Vec::new();
            let mut continuation = Box::pin(crate::io::copy_buf(&mut reader, &mut retained));
            let resumed = poll(continuation.as_mut());
            assert!(
                matches!(&resumed, Poll::Ready(Ok(16))),
                "the full buffered prefix survives cancellation: {resumed:?}"
            );
            drop(continuation);
            assert_eq!(retained, b"0123456789abcdef");
        }
        {
            let cx = Cx::for_testing();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let (mut a, a_state) = ControlledIo::new();
            let (mut b, b_state) = ControlledIo::new();
            let mut copy = Box::pin(crate::io::copy_bidirectional(&mut a, &mut b));
            cancel_copy(
                &cx,
                "io.copy-bidirectional",
                copy.as_mut(),
                &[a_state, b_state],
                8,
            );
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn responsiveness_native_socket_waits_check_before_io_on_delivered_poll() {
        use crate::runtime::io_driver::IoDriverHandle;
        for variant in 0..3 {
            let driver = IoDriverHandle::new(
                crate::runtime::reactor::create_reactor().expect("actual OS reactor"),
            );
            let cx = Cx::new_with_drivers(
                crate::types::RegionId::new_for_test(0, 1),
                crate::types::TaskId::new_for_test(0, 0),
                Budget::INFINITE,
                None,
                Some(driver.clone()),
                None,
                None,
                None,
            );
            let _ambient = Cx::set_current(Some(cx.clone()));
            if variant > 0 {
                let raw = std::net::UdpSocket::bind("127.0.0.1:0").expect("owned real UDP socket");
                let mut socket = crate::net::UdpSocket::from_std(raw).unwrap();
                let mut bytes = [0_u8; 16];
                let mut wait = Box::pin(std::future::poll_fn(|context| {
                    if variant == 1 {
                        socket.poll_recv_from(context, &mut bytes)
                    } else {
                        socket.poll_peek_from(context, &mut bytes)
                    }
                }));
                assert!(poll(wait.as_mut()).is_pending());
                assert_eq!(driver.waker_count(), 1);
                assert!(matches!(cancel_parked(&cx, "net.udp-wait", wait.as_mut()),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted));
                drop(wait);
                drop(socket);
                assert_eq!(bytes, [0_u8; 16]);
            } else {
                let raw =
                    std::net::TcpListener::bind("127.0.0.1:0").expect("owned real TCP listener");
                let listener = crate::net::TcpListener::from_std(raw).unwrap();
                let mut wait = Box::pin(std::future::poll_fn(|context| {
                    listener.poll_accept(context)
                }));
                assert!(poll(wait.as_mut()).is_pending());
                assert_eq!(driver.waker_count(), 1);
                assert!(matches!(cancel_parked(&cx, "net.tcp-wait", wait.as_mut()),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted));
                drop(wait);
                drop(listener);
            }
            assert_eq!(
                driver.waker_count(),
                0,
                "actual socket owner Drop retires reactor registration"
            );
        }
    }

    fn nested_masks(cx: &Cx, remaining: u32, body: &mut dyn FnMut()) {
        if remaining == 0 {
            body();
        } else {
            cx.masked(|| nested_masks(cx, remaining - 1, body));
        }
    }

    #[test]
    fn responsiveness_actual_masks_and_budget_edges_refuse_unsound_composition() {
        let cx = Cx::for_testing();
        let one = returned(&cx, "mutex.lock");
        assert_eq!(one.unit(), ResponsivenessUnit::OperationPolls);
        let three = one.checked_repeat(3).unwrap();
        for quota in [2, 3, 4] {
            let actual = three.check_poll_budget(Budget::INFINITE.with_poll_quota(quota));
            if quota == 2 {
                assert_eq!(
                    actual,
                    Err(ResponsivenessRefusal::InsufficientPollBudget {
                        required: 3,
                        available: 2
                    })
                );
            } else {
                assert_eq!(actual, Ok(three));
            }
        }
        assert_eq!(
            one.check_poll_budget(Budget::INFINITE.with_poll_quota(0)),
            Err(ResponsivenessRefusal::InsufficientPollBudget {
                required: 1,
                available: 0
            })
        );
        assert!(
            one.check_poll_budget(Budget::INFINITE.with_poll_quota(1))
                .is_ok()
        );
        assert!(
            one.check_poll_budget(Budget::INFINITE.with_poll_quota(2))
                .is_ok()
        );
        let empty = one.checked_repeat(0).unwrap();
        assert_eq!(empty.steps(), 0);
        assert!(
            empty
                .check_poll_budget(Budget::INFINITE.with_poll_quota(0))
                .is_ok()
        );
        let largest = one.checked_repeat(u64::MAX).unwrap();
        assert_eq!(
            largest.checked_repeat(2),
            Err(ResponsivenessRefusal::Overflow)
        );
        assert_eq!(
            largest.checked_then(one),
            Err(ResponsivenessRefusal::Overflow)
        );
        assert!(
            largest.check_poll_budget(Budget::INFINITE).is_ok(),
            "unlimited sentinel, not elapsed-time evidence"
        );
        {
            let _ambient = Cx::set_current(Some(cx.clone()));
            assert_eq!(
                returned(&cx, "io.copy").checked_repeat(u64::MAX),
                Err(ResponsivenessRefusal::Overflow),
                "independent inner-write accounting cannot overflow"
            );
        }
        let checkpoint = ResponsivenessRegistry::lookup("Cx::checkpoint")
            .unwrap()
            .bound(
                ResponsivenessGoal::OperationReturned,
                ResponsivenessQuery::for_cx(&cx, CancelKind::User),
            )
            .unwrap();
        assert_eq!(checkpoint.unit(), ResponsivenessUnit::CheckpointCalls);
        assert_eq!(
            one.checked_then(checkpoint),
            Err(ResponsivenessRefusal::DifferentUnits)
        );
        assert_eq!(
            checkpoint.check_poll_budget(Budget::INFINITE),
            Err(ResponsivenessRefusal::DifferentUnits)
        );
        let observed = ResponsivenessRegistry::lookup("mutex.lock")
            .unwrap()
            .bound(
                ResponsivenessGoal::CancellationObserved,
                ResponsivenessQuery::for_cx(&cx, CancelKind::User),
            )
            .unwrap();
        assert_eq!(
            one.checked_then(observed),
            Err(ResponsivenessRefusal::DifferentGoals)
        );
        assert_eq!(
            one.check_observed(2, true),
            Err(ResponsivenessRefusal::PollBoundExceeded {
                bound: 1,
                observed: 2
            })
        );
        assert_eq!(
            ResponsivenessRegistry::checked_mask_depth(u32::MAX, 1),
            Err(ResponsivenessRefusal::Overflow)
        );
        assert_eq!(
            ResponsivenessRegistry::checked_mask_depth(64, 1),
            Err(ResponsivenessRefusal::MaskDepthExceeded {
                depth: 65,
                maximum: 64
            })
        );
        for depth in [1, crate::types::task_context::MAX_MASK_DEPTH] {
            let cx = Cx::for_testing();
            let mutex = Mutex::new(());
            let held = mutex.try_lock().unwrap();
            let mut wait = Box::pin(mutex.lock(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(mutex.waiters(), 1);
            cx.cancel_with(CancelKind::User, Some("actual nested masks"));
            nested_masks(&cx, depth, &mut || {
                let query = ResponsivenessQuery::for_cx(&cx, CancelKind::User);
                assert_eq!(
                    ResponsivenessRegistry::lookup("mutex.lock")
                        .unwrap()
                        .bound(ResponsivenessGoal::OperationReturned, query),
                    Err(ResponsivenessRefusal::Masked { depth })
                );
                assert!(
                    poll(wait.as_mut()).is_pending(),
                    "real mask withholds cancellation while holder remains"
                );
                assert!(!cx.inner.read().cancel_acknowledged);
                assert_eq!(mutex.waiters(), 1);
                if depth == 64 {
                    assert_eq!(
                        query.with_additional_masks(1).unwrap_err(),
                        ResponsivenessRefusal::MaskDepthExceeded {
                            depth: 65,
                            maximum: 64
                        }
                    );
                }
            });
            assert_eq!(cx.inner.read().mask_depth, 0, "all actual guards unwound");
            let outcome = poll(wait.as_mut());
            assert!(matches!(
                outcome,
                Poll::Ready(Err(crate::sync::LockError::Cancelled))
            ));
            one.check_observed(1, outcome.is_ready()).unwrap();
            assert!(cx.inner.read().cancel_acknowledged);
            drop(wait);
            assert_eq!(mutex.waiters(), 0);
            assert!(mutex.try_lock().is_err());
            drop(held);
            assert!(mutex.try_lock().is_ok());
        }
        let before = cx.checkpoint_state().checkpoint_count;
        cx.cancel_with(
            CancelKind::User,
            Some("explicit synchronous checkpoint call"),
        );
        let result = cx.checkpoint();
        checkpoint.check_observed(1, result.is_err()).unwrap();
        assert_eq!(cx.checkpoint_state().checkpoint_count, before + 1);
        assert!(cx.inner.read().cancel_acknowledged);
    }

    #[test]
    fn responsiveness_withheld_notification_and_factory_fail_the_same_boundary_checker() {
        use crate::sync::{GenericPool, Notify, Pool, PoolConfig};
        {
            let cx = Cx::for_testing();
            let notify = Notify::new();
            let mut wait = Box::pin(notify.notified());
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(notify.waiter_count(), 1);
            let wrongly_applied_finite_bound = returned(&cx, "mutex.lock");
            cx.cancel_with(
                CancelKind::User,
                Some("notification deliberately withholds progress"),
            );
            let before = cx.checkpoint_state().checkpoint_count;
            for polls in 1..=3 {
                let result = poll(wait.as_mut());
                assert_eq!(
                    wrongly_applied_finite_bound.check_observed(polls, result.is_ready()),
                    Err(ResponsivenessRefusal::GoalNotObserved),
                    "same checker refuses a mislabeled live wait"
                );
                assert_eq!(notify.waiter_count(), 1);
            }
            assert_eq!(
                cx.checkpoint_state().checkpoint_count,
                before,
                "actual missing checkpoint, not a case label"
            );
            assert_eq!(
                ResponsivenessRegistry::lookup("sync::Notify::notified")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::ExternalProgress)
            );
            assert!(notify.notify_one());
            assert_eq!(poll(wait.as_mut()), Poll::Ready(()));
            drop(wait);
            assert_eq!(notify.waiter_count(), 0);
        }
        {
            let (cx, _clock, timer) = timer_context();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let gate = Arc::new(Notify::new());
            let factory_gate = Arc::clone(&gate);
            let pool = GenericPool::new(
                move || {
                    let gate = Arc::clone(&factory_gate);
                    async move {
                        gate.notified().await;
                        Ok::<_, std::io::Error>(53_u8)
                    }
                },
                PoolConfig::with_max_size(1),
            );
            let mut acquire = pool.acquire(&cx);
            assert!(poll(acquire.as_mut()).is_pending());
            assert_eq!(
                gate.waiter_count(),
                1,
                "actual factory owns the blocked notification"
            );
            assert_eq!(pool.stats().total, 1, "real creating slot is retained");
            // TimeoutFuture itself polls Sleep: User cancellation can finish
            // that sleep. Deadline/Timeout cancellation deliberately cannot,
            // so use the actual kind which makes this a nonprogress witness.
            cx.cancel_with(
                CancelKind::Timeout,
                Some("factory still needs input or actual timer progress"),
            );
            let before = cx.checkpoint_state().checkpoint_count;
            for _ in 0..3 {
                assert!(poll(acquire.as_mut()).is_pending());
            }
            assert_eq!(cx.checkpoint_state().checkpoint_count, before);
            assert_eq!(gate.waiter_count(), 1);
            assert_eq!(
                ResponsivenessRegistry::lookup("sync::Pool::acquire")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::Timeout)
                    ),
                Err(ResponsivenessRefusal::ExternalProgress)
            );
            drop(acquire);
            assert_eq!(
                gate.waiter_count(),
                0,
                "real factory future retired by owner"
            );
            assert_eq!(pool.stats().total, 0, "creating slot rollback");
            assert_eq!(timer.pending_count(), 0);
            assert!(poll(pool.close().as_mut()).is_ready());
        }
        {
            let cx = Cx::for_testing();
            let cell = OnceCell::new();
            let gate = Notify::new();
            let mut initialize = Box::pin(cell.get_or_init(|| async {
                gate.notified().await;
                59_u8
            }));
            assert!(poll(initialize.as_mut()).is_pending());
            assert_eq!(gate.waiter_count(), 1);
            cx.cancel_with(
                CancelKind::User,
                Some("initializer owns independent progress"),
            );
            let before = cx.checkpoint_state().checkpoint_count;
            for _ in 0..3 {
                assert!(poll(initialize.as_mut()).is_pending());
            }
            assert_eq!(cx.checkpoint_state().checkpoint_count, before);
            assert_eq!(
                ResponsivenessRegistry::lookup("once-cell.initialize")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::ExternalProgress)
            );
            assert!(!cell.is_initialized());
            assert!(gate.notify_one());
            assert_eq!(poll(initialize.as_mut()), Poll::Ready(&59));
            drop(initialize);
            assert_eq!(gate.waiter_count(), 0);
            assert_eq!(cell.get(), Some(&59));
        }
        {
            let cx = Cx::for_testing();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let (mut writer, state) = ControlledIo::new();
            let mut permit = crate::io::WritePermit::new(&mut writer);
            permit.stage(b"real staged commit");
            let mut commit = Box::pin(permit.commit());
            assert!(poll(commit.as_mut()).is_pending());
            assert!(state.lock().waiter.is_some());
            cx.cancel_with(CancelKind::User, Some("generic commit does not checkpoint"));
            let before = cx.checkpoint_state().checkpoint_count;
            for _ in 0..3 {
                assert!(poll(commit.as_mut()).is_pending());
            }
            assert_eq!(cx.checkpoint_state().checkpoint_count, before);
            assert!(state.lock().bytes.is_empty());
            assert_eq!(
                ResponsivenessRegistry::lookup("io::WritePermit::commit")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::ExternalProgress)
            );
            release_writes(&state);
            assert!(matches!(poll(commit.as_mut()), Poll::Ready(Ok(()))));
            drop(commit);
            assert_eq!(state.lock().bytes, b"real staged commit");
            assert!(state.lock().waiter.is_none());
        }
    }

    #[test]
    fn responsiveness_inventory_refuses_unknown_unbounded_and_owner_claims() {
        let cx = Cx::for_testing();
        let query = ResponsivenessQuery::for_cx(&cx, CancelKind::User);
        let mut aliases = std::collections::BTreeSet::new();
        let mut finite = 0;
        let mut refused = 0;
        for entry in ResponsivenessRegistry::entries() {
            assert_eq!(
                ResponsivenessRegistry::lookup(entry.id()).unwrap().id(),
                entry.id()
            );
            assert!(!entry.source().is_empty());
            assert!(!entry.contract().is_empty());
            for alias in entry.aliases() {
                assert!(aliases.insert(*alias), "duplicate inventory alias {alias}");
                assert_eq!(
                    ResponsivenessRegistry::lookup(alias).unwrap().id(),
                    entry.id()
                );
            }
            assert_eq!(
                entry.bound(ResponsivenessGoal::OwnerQuiescent, query),
                Err(ResponsivenessRefusal::OwnerProgress)
            );
            if let ResponsivenessRule::Refuse(reason) = entry.rule {
                refused += 1;
                assert_eq!(
                    entry.bound(ResponsivenessGoal::OperationReturned, query),
                    Err(reason)
                );
                assert_eq!(
                    entry.bound(ResponsivenessGoal::CancellationObserved, query),
                    Err(reason)
                );
            } else {
                finite += 1;
                assert_eq!(
                    entry.bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::without_context(CancelKind::User)
                    ),
                    Err(ResponsivenessRefusal::MissingContext)
                );
            }
        }
        assert!(finite > 0 && refused > 0);
        assert_eq!(
            ResponsivenessRegistry::lookup("sync::Mutex::hypothetical_wait").unwrap_err(),
            ResponsivenessRefusal::UnknownOperation,
            "finite families cannot confer bounds on unknown methods"
        );
        assert_eq!(
            ResponsivenessRegistry::lookup("io::AsyncReadExt::read_exact")
                .unwrap()
                .bound(ResponsivenessGoal::OperationReturned, query),
            Err(ResponsivenessRefusal::ExternalProgress)
        );
        assert_eq!(
            ResponsivenessRegistry::lookup("channel::partition::PartitionedSender::send")
                .unwrap()
                .bound(ResponsivenessGoal::OperationReturned, query),
            Err(ResponsivenessRefusal::ExternalProgress)
        );
        assert_eq!(
            ResponsivenessRegistry::lookup("unknown::wait").unwrap_err(),
            ResponsivenessRefusal::UnknownOperation
        );
        for (alias, entry) in [
            ("net::UdpSocket::poll_peek_from", "net.udp-wait"),
            ("net::TcpStream::poll_read_vectored", "net.tcp-wait"),
            ("net::TcpStream::poll_flush", "net.tcp-wait"),
            ("net::TcpStream::poll_shutdown", "net.tcp-wait"),
            ("channel::oneshot::SendPermit::abort", "channel.commit"),
            ("channel::session::TrackedPermit::abort", "channel.commit"),
            (
                "channel::session::TrackedOneshotPermit::abort",
                "channel.commit",
            ),
            (
                "sync::OwnedSemaphorePermit::try_acquire_arc_checked",
                "sync.synchronous",
            ),
            ("sync::OwnedSemaphorePermit::forget", "sync.synchronous"),
            ("sync::OwnedRwLockWriteGuard::downgrade", "sync.synchronous"),
            ("sync::OwnedRwLockReadGuard::try_read", "sync.synchronous"),
            ("sync::OwnedMappedMutexGuard::try_map", "sync.synchronous"),
            ("sync::OwnedMutexGuard::lock", "mutex.lock"),
            (
                "sync::OwnedSemaphorePermit::acquire_checked#zero",
                "semaphore.zero",
            ),
            ("io::read_line", "io.buffered"),
            ("io::ReadU8", "io.generic"),
            ("io::ext::ReadU64Le", "io.generic"),
            ("Cx::race_drained_timeout_named", "structured.drain"),
            ("Cx::open_child_region", "structured.drain"),
        ] {
            assert_eq!(
                ResponsivenessRegistry::lookup(alias).unwrap().id(),
                entry,
                "{alias}"
            );
        }
        assert_eq!(
            ResponsivenessRegistry::lookup("Cx::masked")
                .unwrap()
                .bound(ResponsivenessGoal::OperationReturned, query),
            Err(ResponsivenessRefusal::UnboundedMaskBody)
        );
        println!(
            "ASUPERSYNC_RESPONSIVENESS_INVENTORY {}",
            serde_json::json!({
                "entries": finite + refused, "conditional_finite_phases": finite,
                "refused_phases": refused, "aliases": aliases.len(),
                "scope": "classification_and_arithmetic_not_behavioral_completeness"
            })
        );
    }
}
