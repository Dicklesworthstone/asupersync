//! GenServer: typed request-response and actor-adjacent message loop.
//!
//! GenServer extends the actor model with three message types:
//!
//! - **Call**: synchronous request-response. The caller blocks until the server
//!   replies. A reply obligation is created: the server *must* reply or the
//!   obligation is detected as leaked.
//! - **Cast**: asynchronous fire-and-forget. The sender does not wait for a reply.
//! - **Info**: system/out-of-band notifications (Down/Exit/Timeout), delivered
//!   via [`GenServer::handle_info`].
//!
//! GenServers are region-owned, cancel-safe, and deterministic under the lab
//! runtime. They build on the same two-phase mailbox and supervision infrastructure
//! as plain actors.
//!
//! # Callers must run in a non-root region
//!
//! A call reserves its reply permit as an obligation token scoped to the
//! caller's region, and obligations cannot live in the root region
//! (`[ASUP-E103]`: they would hide leaks and break quiescence). `block_on`'s
//! root task and every `RuntimeHandle::spawn` task run in the root region, as
//! does a `LabRuntime` task created directly under `create_root_region`.
//! [`GenServerHandle::call`] and [`GenServerRef::call`] therefore refuse such
//! callers with [`CallError::Cancelled`] whose reason message starts with
//! `[ASUP-E103]`, instead of panicking inside the token layer
//! (asupersync-0ex6x0); issue calls from a child region (a `Scope` region or
//! a task spawned inside one). Casts carry no reply obligation and are
//! unaffected.
//!
//! # Example
//!
//! ```ignore
//! struct Counter {
//!     count: u64,
//! }
//!
//! enum Request {
//!     Get,
//!     Add(u64),
//! }
//!
//! enum Cast {
//!     Reset,
//! }
//!
//! impl GenServer for Counter {
//!     type Call = Request;
//!     type Reply = u64;
//!     type Cast = Cast;
//!
//!     fn handle_call(&mut self, _cx: &Cx, msg: Request, reply: Reply<u64>)
//!         -> Pin<Box<dyn Future<Output = ()> + Send + '_>>
//!     {
//!         match msg {
//!             Request::Get => { let _ = reply.send(self.count); }
//!             Request::Add(n) => { self.count += n; let _ = reply.send(self.count); }
//!         }
//!         Box::pin(async {})
//!     }
//!
//!     fn handle_cast(&mut self, _cx: &Cx, msg: Cast)
//!         -> Pin<Box<dyn Future<Output = ()> + Send + '_>>
//!     {
//!         match msg {
//!             Cast::Reset => { self.count = 0; }
//!         }
//!         Box::pin(async {})
//!     }
//! }
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::actor::{ActorId, ActorState};
use crate::channel::mpsc;
use crate::channel::oneshot;
use crate::channel::session::{self, TrackedOneshotPermit};
use crate::cx::Cx;
use crate::monitor::{DownNotification, DownReason};
use crate::obligation::graded::{AbortedProof, CommittedProof, SendPermit};
use crate::runtime::{JoinError, SpawnError};
use crate::types::{Budget, CancelReason, CxInner, Outcome, TaskId, Time};

// ============================================================================
// Lifecycle helpers (init/terminate budgets + masking) (bd-3ejoi)
// ============================================================================

/// Temporarily tightens the current task budget for an async phase.
///
/// Budgets in `CxInner` represent remaining budget; to avoid "refunding" budget,
/// we restore the original budget minus any consumption that occurred while the
/// phase budget was active.
struct PhaseBudgetGuard {
    inner: Arc<parking_lot::RwLock<CxInner>>,
    original_budget: Budget,
    original_baseline: Budget,
    phase_baseline: Budget,
    restore_original: bool,
}

impl PhaseBudgetGuard {
    fn enter(cx: &Cx, phase_budget: Budget, restore_original: bool) -> Self {
        let inner = Arc::clone(&cx.inner);
        let (original_budget, original_baseline, phase_baseline) = {
            let mut guard = inner.write();
            let original_budget = guard.budget;
            let original_baseline = guard.budget_baseline;
            let mut phase_baseline = original_budget.meet(phase_budget);
            phase_baseline.priority = original_budget.priority.max(phase_budget.priority);
            guard.budget = phase_baseline;
            guard.budget_baseline = phase_baseline;
            drop(guard);
            (original_budget, original_baseline, phase_baseline)
        };
        Self {
            inner,
            original_budget,
            original_baseline,
            phase_baseline,
            restore_original,
        }
    }
}

impl Drop for PhaseBudgetGuard {
    fn drop(&mut self) {
        if !self.restore_original {
            return;
        }

        let mut guard = self.inner.write();

        let phase_remaining = guard.budget;
        let polls_used = self
            .phase_baseline
            .poll_quota
            .saturating_sub(phase_remaining.poll_quota);

        let cost_used = match (self.phase_baseline.cost_quota, phase_remaining.cost_quota) {
            (Some(base), Some(rem)) => base.saturating_sub(rem),
            _ => 0,
        };

        let restored_cost_quota = self
            .original_budget
            .cost_quota
            .map(|orig| orig.saturating_sub(cost_used));

        guard.budget = Budget {
            deadline: self.original_budget.deadline,
            poll_quota: self.original_budget.poll_quota.saturating_sub(polls_used),
            cost_quota: restored_cost_quota,
            priority: self.original_budget.priority,
        };
        guard.budget_baseline = self.original_baseline;
    }
}

/// Async-friendly cancellation mask guard.
///
/// `Cx::masked(..)` is synchronous-only; GenServer lifecycle hooks are async.
struct AsyncMaskGuard {
    inner: Arc<parking_lot::RwLock<CxInner>>,
}

impl AsyncMaskGuard {
    fn enter(cx: &Cx) -> Self {
        let inner = Arc::clone(&cx.inner);
        {
            let mut guard = inner.write();
            // Enforce mask depth cap to prevent overflow and infinite recursion
            // This maintains INV-MASK-BOUNDED invariant in both debug and release builds
            assert!(
                guard.mask_depth < crate::types::task_context::MAX_MASK_DEPTH,
                "mask depth exceeded MAX_MASK_DEPTH ({}) in AsyncMaskGuard::enter: \
                 this violates INV-MASK-BOUNDED and prevents cancellation from ever \
                 being observed. Reduce nesting of masked sections.",
                crate::types::task_context::MAX_MASK_DEPTH
            );
            guard.mask_depth += 1;
        }
        Self { inner }
    }
}

impl Drop for AsyncMaskGuard {
    fn drop(&mut self) {
        let mut guard = self.inner.write();
        guard.mask_depth = guard.mask_depth.saturating_sub(1);
    }
}

// ============================================================================
// Cast overflow policy
// ============================================================================

/// Policy for handling cast sends when the GenServer mailbox is full.
///
/// When a bounded mailbox reaches capacity, the overflow policy determines
/// what happens to new cast messages. Lossy policies (`DropOldest`) are
/// trace-visible: every dropped message emits a trace event.
///
/// # Default
///
/// The default policy is `Reject`, which returns `CastError::Full` to the
/// sender. This is the safest option and forces callers to handle backpressure
/// explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CastOverflowPolicy {
    /// Reject the new cast when the mailbox is full.
    ///
    /// The sender receives `CastError::Full` and can decide what to do
    /// (retry, drop, log, etc.). No messages are lost silently.
    #[default]
    Reject,

    /// Drop the oldest queued cast to make room for the new cast.
    ///
    /// The dropped message is traced for observability. This is useful for
    /// "latest-value-wins" patterns (e.g., sensor readings, UI state updates)
    /// where stale casts are less valuable than fresh data. Calls and info
    /// messages are never evicted by cast backpressure.
    DropOldest,
}

impl std::fmt::Display for CastOverflowPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reject => write!(f, "Reject"),
            Self::DropOldest => write!(f, "DropOldest"),
        }
    }
}

// ============================================================================
// System messages (bd-188ey)
// ============================================================================

/// Typed system messages delivered to a GenServer via [`GenServer::handle_info`].
///
/// These messages are intended to model OTP-style "out-of-band" notifications
/// (Down/Exit/Timeout) in a cancel-correct, deterministic way.
#[derive(Debug, Clone)]
pub struct DownMsg {
    /// Virtual time at which the monitored task completed (for deterministic ordering).
    pub completion_vt: Time,
    /// The monitor notification payload.
    pub notification: DownNotification,
}

impl DownMsg {
    /// Create a new down system message payload.
    #[must_use]
    pub const fn new(completion_vt: Time, notification: DownNotification) -> Self {
        Self {
            completion_vt,
            notification,
        }
    }
}

/// Payload for an OTP-style `Exit` system message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitMsg {
    /// Virtual time at which the exit was observed/emitted.
    pub exit_vt: Time,
    /// The task that triggered the exit.
    pub from: TaskId,
    /// Why it exited.
    pub reason: DownReason,
}

impl ExitMsg {
    /// Create a new exit system message payload.
    #[must_use]
    pub const fn new(exit_vt: Time, from: TaskId, reason: DownReason) -> Self {
        Self {
            exit_vt,
            from,
            reason,
        }
    }
}

/// Payload for a deterministic timeout tick system message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutMsg {
    /// Virtual time of the tick.
    pub tick_vt: Time,
    /// Timeout identifier (user-defined semantics).
    pub id: u64,
}

impl TimeoutMsg {
    /// Create a new timeout system message payload.
    #[must_use]
    pub const fn new(tick_vt: Time, id: u64) -> Self {
        Self { tick_vt, id }
    }
}

/// Typed system messages delivered to a GenServer via [`GenServer::handle_info`].
#[derive(Debug, Clone)]
pub enum SystemMsg {
    /// OTP-style `Down` notification (monitor fired).
    Down {
        /// Virtual time at which the monitored task completed (for deterministic ordering).
        completion_vt: Time,
        /// The notification payload.
        notification: DownNotification,
    },

    /// OTP-style exit signal (link propagation).
    Exit {
        /// Virtual time at which the exit was observed/emitted.
        exit_vt: Time,
        /// The task that triggered the exit.
        from: TaskId,
        /// Why it exited.
        reason: DownReason,
    },

    /// A deterministic timeout tick.
    Timeout {
        /// Virtual time of the tick.
        tick_vt: Time,
        /// Timeout identifier (user-defined semantics).
        id: u64,
    },
}

impl SystemMsg {
    /// Construct a down-system message.
    #[must_use]
    pub fn down(msg: DownMsg) -> Self {
        msg.into()
    }

    /// Construct an exit-system message.
    #[must_use]
    pub fn exit(msg: ExitMsg) -> Self {
        msg.into()
    }

    /// Construct a timeout-system message.
    #[must_use]
    pub fn timeout(msg: TimeoutMsg) -> Self {
        msg.into()
    }

    const fn vt(&self) -> Time {
        match self {
            Self::Down { completion_vt, .. } => *completion_vt,
            Self::Exit { exit_vt, .. } => *exit_vt,
            Self::Timeout { tick_vt, .. } => *tick_vt,
        }
    }

    const fn kind_rank(&self) -> u8 {
        match self {
            Self::Down { .. } => 0,
            Self::Exit { .. } => 1,
            Self::Timeout { .. } => 2,
        }
    }

    const fn subject_key(&self) -> SystemMsgSubjectKey {
        match self {
            Self::Down { notification, .. } => SystemMsgSubjectKey::Task(notification.monitored),
            Self::Exit { from, .. } => SystemMsgSubjectKey::Task(*from),
            Self::Timeout { id, .. } => SystemMsgSubjectKey::TimeoutId(*id),
        }
    }

    /// Deterministic ordering key for batched system-message delivery.
    ///
    /// Order is:
    /// 1. virtual time (`vt`)
    /// 2. message kind rank (`Down < Exit < Timeout`)
    /// 3. stable subject key (`TaskId` or timeout id)
    ///
    /// This key underpins the app shutdown ordering contract in
    /// `docs/spork_deterministic_ordering.md`.
    #[must_use]
    pub const fn sort_key(&self) -> (Time, u8, SystemMsgSubjectKey) {
        (self.vt(), self.kind_rank(), self.subject_key())
    }
}

impl From<DownMsg> for SystemMsg {
    fn from(value: DownMsg) -> Self {
        Self::Down {
            completion_vt: value.completion_vt,
            notification: value.notification,
        }
    }
}

impl From<ExitMsg> for SystemMsg {
    fn from(value: ExitMsg) -> Self {
        Self::Exit {
            exit_vt: value.exit_vt,
            from: value.from,
            reason: value.reason,
        }
    }
}

impl From<TimeoutMsg> for SystemMsg {
    fn from(value: TimeoutMsg) -> Self {
        Self::Timeout {
            tick_vt: value.tick_vt,
            id: value.id,
        }
    }
}

impl TryFrom<SystemMsg> for DownMsg {
    type Error = SystemMsg;

    fn try_from(value: SystemMsg) -> Result<Self, Self::Error> {
        match value {
            SystemMsg::Down {
                completion_vt,
                notification,
            } => Ok(Self {
                completion_vt,
                notification,
            }),
            other => Err(other),
        }
    }
}

impl TryFrom<SystemMsg> for ExitMsg {
    type Error = SystemMsg;

    fn try_from(value: SystemMsg) -> Result<Self, Self::Error> {
        match value {
            SystemMsg::Exit {
                exit_vt,
                from,
                reason,
            } => Ok(Self {
                exit_vt,
                from,
                reason,
            }),
            other => Err(other),
        }
    }
}

impl TryFrom<SystemMsg> for TimeoutMsg {
    type Error = SystemMsg;

    fn try_from(value: SystemMsg) -> Result<Self, Self::Error> {
        match value {
            SystemMsg::Timeout { tick_vt, id } => Ok(Self { tick_vt, id }),
            other => Err(other),
        }
    }
}

/// Stable subject key used by [`SystemMsg::sort_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SystemMsgSubjectKey {
    /// Messages keyed by task identity (`Down`, `Exit`).
    Task(TaskId),
    /// Timeout tick keyed by timeout id.
    TimeoutId(u64),
}

/// Batched system messages with deterministic sort for shutdown drain paths.
///
/// This is used when a runtime layer accumulates multiple `Down` / `Exit` /
/// `Timeout` messages in one scheduler step and needs replay-stable delivery.
#[derive(Debug, Default)]
pub struct SystemMsgBatch {
    entries: Vec<SystemMsg>,
}

impl SystemMsgBatch {
    /// Creates an empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a message to the batch.
    pub fn push(&mut self, msg: SystemMsg) {
        self.entries.push(msg);
    }

    /// Consumes the batch and returns deterministically ordered messages.
    #[must_use]
    pub fn into_sorted(mut self) -> Vec<SystemMsg> {
        self.entries.sort_by_key(SystemMsg::sort_key);
        self.entries
    }
}

/// A GenServer processes calls (request-response) and casts (fire-and-forget).
///
/// # Cancel Safety
///
/// When a GenServer stops or is cancelled:
/// 1. The mailbox closes (no new messages accepted)
/// 2. Buffered messages are drained: calls receive errors; casts and info
///    messages are processed after a graceful `stop()`, but dropped unhandled
///    when the server was cancelled or aborted
/// 3. `on_stop` runs for cleanup
/// 4. The server state is returned via `GenServerHandle::join`
pub trait GenServer: Send + 'static {
    /// Request type for calls (synchronous request-response).
    type Call: Send + 'static;

    /// Reply type returned to callers.
    type Reply: Send + 'static;

    /// Message type for casts (asynchronous fire-and-forget).
    type Cast: Send + 'static;

    /// Message type for `info` (system/out-of-band notifications).
    ///
    /// Recommended default is [`SystemMsg`]. Servers that want their own info messages
    /// can define an enum that contains `SystemMsg` plus app-specific variants.
    ///
    /// Note: associated type defaults are unstable on Rust stable; implementors
    /// should write `type Info = SystemMsg;` if they only need system messages.
    type Info: Send + 'static;

    /// Handle a call (request-response).
    ///
    /// The `reply` handle **must** be consumed by calling `reply.send(value)`.
    /// Dropping it without sending panics the server. A `LabRuntime` report's
    /// `reply_linearity` oracle also flags it, even when a restarting
    /// supervisor absorbs the panic.
    fn handle_call(
        &mut self,
        cx: &Cx,
        request: Self::Call,
        reply: Reply<Self::Reply>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// Handle a cast (fire-and-forget).
    ///
    /// No reply is expected. The default implementation does nothing.
    fn handle_cast(
        &mut self,
        _cx: &Cx,
        _msg: Self::Cast,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    /// Handle an info message (system/out-of-band).
    ///
    /// Defaults to a no-op.
    fn handle_info(
        &mut self,
        _cx: &Cx,
        _msg: Self::Info,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    /// Called once when the server starts, before processing any messages.
    fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    /// Returns the budget used for the init (`on_start`) phase.
    ///
    /// This budget is met with the task/region budget and applied only for the
    /// duration of `on_start`. Budget consumption during `on_start` is preserved
    /// when restoring the original budget for the message loop.
    fn on_start_budget(&self) -> Budget {
        Budget::INFINITE
    }

    /// Called once when the server stops, after the mailbox is drained.
    fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    /// Returns the budget used for drain + stop (`on_stop`).
    ///
    /// The default is [`Budget::MINIMAL`] for bounded cleanup.
    fn on_stop_budget(&self) -> Budget {
        Budget::MINIMAL
    }

    /// Returns the overflow policy for cast messages when the mailbox is full.
    ///
    /// The default is [`CastOverflowPolicy::Reject`], which returns
    /// `CastError::Full` to the sender.
    ///
    /// Override this to use `DropOldest` for "latest-value-wins" patterns.
    fn cast_overflow_policy(&self) -> CastOverflowPolicy {
        CastOverflowPolicy::Reject
    }
}

/// Handle for sending a reply to a call.
///
/// This is a **linear obligation token**: it **must** be consumed by calling
/// [`send()`](Self::send) or [`abort()`](Self::abort). Dropping without
/// consuming triggers a panic via `ObligationToken<SendPermit>`.
///
/// Backed by [`TrackedOneshotPermit`] from
/// `channel::session`,
/// making "silent reply drop" structurally impossible.
pub struct Reply<R> {
    cx: Cx,
    permit: Option<TrackedOneshotPermit<R>>,
    /// Where this reply's resolution is recorded for the lab's
    /// reply-linearity oracle, and its key there (br-asupersync-52hxjz).
    history: Option<(crate::runtime::state::ReplyHistoryHandle, u64)>,
}

impl<R> Reply<R> {
    fn record(&self, event: fn(u64) -> crate::runtime::state::ReplyHistoryEvent) {
        if let Some((history, call)) = &self.history {
            history.record(event(*call));
        }
    }
}

impl<R: Send + 'static> Reply<R> {
    fn new(cx: &Cx, permit: TrackedOneshotPermit<R>) -> Self {
        // Borrowed: a native runtime has no reply history, so a call costs
        // only these Option checks, not a refcount on the shared gateway.
        let history = cx
            .spawn_gateway_ref()
            .and_then(|gateway| gateway.reply_history().cloned())
            .map(|history| {
                let call = history.next_call();
                history.record(crate::runtime::state::ReplyHistoryEvent::Created {
                    call,
                    server: cx.task_id(),
                    time: cx.now_for_observability(),
                });
                (history, call)
            });
        Self {
            cx: cx.clone(),
            permit: Some(permit),
            history,
        }
    }

    /// Send the reply value to the caller, returning a [`CommittedProof`].
    ///
    /// Consumes the reply handle. If the caller has dropped (e.g., timed out),
    /// the obligation is aborted cleanly (no panic).
    pub fn send(mut self, value: R) -> ReplyOutcome {
        let permit = self
            .permit
            .take()
            .expect("Reply::send called after reply was already consumed");
        self.record(|call| crate::runtime::state::ReplyHistoryEvent::Sent { call });
        match permit.send(value) {
            Ok(proof) => {
                self.cx.trace("gen_server::reply_committed");
                ReplyOutcome::Committed(proof)
            }
            Err(_send_err) => {
                // Receiver (caller) dropped — e.g., timed out. The tracked
                // permit aborts the obligation cleanly in this case.
                self.cx.trace("gen_server::reply_caller_gone");
                ReplyOutcome::CallerGone
            }
        }
    }

    /// Explicitly abort the reply obligation without sending a value.
    ///
    /// Use this when the server intentionally chooses not to reply (e.g.,
    /// delegating to another process). Returns an [`AbortedProof`].
    #[must_use]
    pub fn abort(mut self) -> AbortedProof<SendPermit> {
        self.cx.trace("gen_server::reply_aborted");
        self.record(|call| crate::runtime::state::ReplyHistoryEvent::Aborted { call });
        self.permit
            .take()
            .expect("Reply::abort called after reply was already consumed")
            .abort()
    }

    /// Check if the caller is still waiting for a reply.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.permit
            .as_ref()
            .is_some_and(TrackedOneshotPermit::is_closed)
    }
}

impl<R> Drop for Reply<R> {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };

        if std::thread::panicking() {
            // Preserve the original panic instead of detonating the reply
            // drop-bomb during unwind.
            self.record(|call| crate::runtime::state::ReplyHistoryEvent::Aborted { call });
            let _ = permit.abort();
        } else if self.cx.is_cancel_requested() {
            // Async cancellation: the handler future is being dropped
            // because cx was cancelled mid-handler (e.g. parent region
            // closing). Abort the obligation explicitly so the linearity
            // invariant is satisfied — letting the permit drop here would
            // panic via TrackedOneshotPermit's drop-bomb, the panic would
            // be caught by the run-loop's CatchUnwind, and the supervisor
            // would see JoinError::Panicked for what is actually a clean
            // cancellation. The caller's recv future observes the same
            // RecvError::Closed it would have seen on Reply::abort().
            self.cx.trace("gen_server::reply_aborted_on_cancel");
            self.record(|call| crate::runtime::state::ReplyHistoryEvent::Aborted { call });
            let _ = permit.abort();
        } else {
            // Genuine programmer bug: handler returned without send/abort
            // while the cx was healthy. Let the linearity drop-bomb fire
            // so the supervisor surfaces the leak. The drop is recorded, so
            // the lab's reply-linearity oracle reports it at once, even when
            // a restarting supervisor absorbs the panic.
            self.record(|call| crate::runtime::state::ReplyHistoryEvent::Dropped { call });
            drop(permit);
        }
    }
}

impl<R> std::fmt::Debug for Reply<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply")
            .field("pending", &self.permit.is_some())
            .finish_non_exhaustive()
    }
}

/// Outcome of sending a reply.
pub enum ReplyOutcome {
    /// Reply was successfully delivered, obligation committed.
    Committed(CommittedProof<SendPermit>),
    /// Caller has already gone (e.g., timed out). Obligation was aborted.
    CallerGone,
}

impl std::fmt::Debug for ReplyOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Committed(_) => f.debug_tuple("Committed").finish(),
            Self::CallerGone => write!(f, "CallerGone"),
        }
    }
}

// ============================================================================
// Internal message envelope
// ============================================================================

/// Internal message type wrapping calls/casts/info.
enum Envelope<S: GenServer> {
    Call {
        request: S::Call,
        reply_permit: TrackedOneshotPermit<S::Reply>,
    },
    Cast {
        msg: S::Cast,
    },
    Info {
        msg: S::Info,
    },
}

impl<S: GenServer> std::fmt::Debug for Envelope<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Call { .. } => f.debug_struct("Envelope::Call").finish_non_exhaustive(),
            Self::Cast { .. } => f.debug_struct("Envelope::Cast").finish_non_exhaustive(),
            Self::Info { .. } => f.debug_struct("Envelope::Info").finish_non_exhaustive(),
        }
    }
}

// ============================================================================
// GenServer cell (internal runtime state)
// ============================================================================

struct GenServerCell<S: GenServer> {
    mailbox: mpsc::Receiver<Envelope<S>>,
    state: Arc<GenServerStateCell>,
    _keep_alive: mpsc::Sender<Envelope<S>>,
    /// DOWN notifications and trapped exit signals from the runtime.
    system: Arc<SystemLane<S>>,
}

impl<S: GenServer> Drop for GenServerCell<S> {
    /// A cell dropped before its loop resolved the mailbox (the server's task
    /// was denied admission, or torn down before its first poll) still holds
    /// queued calls whose reply permits are armed obligations. Dropping them
    /// would trip the `[ASUP-E101]` drop bomb on whichever thread drops the
    /// cell, a scheduler worker included. Abort them instead, so their callers
    /// get an error (br-asupersync-c9b5nb). After the loop's own drain
    /// this finds nothing.
    ///
    /// The server can no longer run, so it is `Stopped`: an unrun server
    /// stayed `Created` and reported itself alive forever.
    fn drop(&mut self) {
        self.state.store(ActorState::Stopped);
        self.mailbox.close();
        while let Ok(envelope) = self.mailbox.try_recv() {
            if let Envelope::Call { reply_permit, .. } = envelope {
                let _ = session::TrackedOneshotPermit::abort(reply_permit);
            }
        }
    }
}

/// System messages the runtime delivers to a server outside its bounded
/// mailbox: DOWN notifications of its monitors and exit signals of its
/// trapping links (br-asupersync-issue65-criticisms-kpmoy5.6.1). A full
/// mailbox never loses one. The server loop takes them ahead of the mailbox
/// and drains what is left when it stops.
///
/// Parameterized by the server, not by `S::Info`: a field type naming
/// `S::Info` would make `#[derive(Debug)]` on [`GenServerHandle`] require
/// `S::Info: Debug`, narrowing its public `Debug` impl.
struct SystemLane<S: GenServer> {
    inner: parking_lot::Mutex<SystemLaneInner<S::Info>>,
}

struct SystemLaneInner<I> {
    queue: std::collections::VecDeque<I>,
    waker: Option<std::task::Waker>,
    closed: bool,
}

impl<S: GenServer> std::fmt::Debug for SystemLane<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("SystemLane")
            .field("queued", &inner.queue.len())
            .field("closed", &inner.closed)
            .finish()
    }
}

impl<S: GenServer> SystemLane<S> {
    fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(SystemLaneInner {
                queue: std::collections::VecDeque::new(),
                waker: None,
                closed: false,
            }),
        }
    }

    /// Queues `msg` for the server and wakes it. Dropped once the server
    /// has stopped.
    fn push(&self, msg: S::Info) {
        let waker = {
            let mut inner = self.inner.lock();
            if inner.closed {
                return;
            }
            inner.queue.push_back(msg);
            inner.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Takes the next message, or registers `waker` to hear about one.
    fn poll_next(&self, waker: &std::task::Waker) -> Option<S::Info> {
        let current = {
            let mut inner = self.inner.lock();
            if let Some(msg) = inner.queue.pop_front() {
                return Some(msg);
            }
            inner
                .waker
                .as_ref()
                .is_some_and(|stored| stored.will_wake(waker))
        };
        if current {
            return None;
        }
        // Clone outside the lock (a Waker clone may run arbitrary code), then
        // re-check: a push may have landed in between.
        let incoming = waker.clone();
        let mut inner = self.inner.lock();
        if let Some(msg) = inner.queue.pop_front() {
            drop(inner);
            drop(incoming);
            return Some(msg);
        }
        let retired = inner.waker.replace(incoming);
        drop(inner);
        drop(retired);
        None
    }

    /// Stops accepting messages and returns the ones still queued.
    fn close(&self) -> std::collections::VecDeque<S::Info> {
        let (queue, waker) = {
            let mut inner = self.inner.lock();
            inner.closed = true;
            (std::mem::take(&mut inner.queue), inner.waker.take())
        };
        drop(waker);
        queue
    }
}

#[derive(Debug)]
struct GenServerStateCell {
    state: AtomicU8,
}

impl GenServerStateCell {
    fn new(state: ActorState) -> Self {
        Self {
            state: AtomicU8::new(encode_actor_state(state)),
        }
    }

    fn load(&self) -> ActorState {
        decode_actor_state(self.state.load(Ordering::Acquire))
    }

    fn store(&self, state: ActorState) {
        self.state
            .store(encode_actor_state(state), Ordering::Release);
    }

    /// Moves to `Running` unless `stop()` already asked for `Stopping`, in one
    /// atomic step: a load-then-store let a `stop()` landing in between be
    /// overwritten, leaving the server running and its join pending forever
    /// (br-asupersync-c9b5nb).
    fn start_running(&self) {
        let stopping = encode_actor_state(ActorState::Stopping);
        let running = encode_actor_state(ActorState::Running);
        let mut current = self.state.load(Ordering::Acquire);
        while current != stopping {
            match self.state.compare_exchange_weak(
                current,
                running,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    /// Moves to `Stopping` unless the server already `Stopped`: a stop or
    /// abort after the server finished must not make it look alive again
    /// (br-asupersync-c9b5nb).
    fn request_stop(&self) {
        let stopped = encode_actor_state(ActorState::Stopped);
        let stopping = encode_actor_state(ActorState::Stopping);
        let mut current = self.state.load(Ordering::Acquire);
        while current != stopped {
            match self.state.compare_exchange_weak(
                current,
                stopping,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }
}

const fn encode_actor_state(state: ActorState) -> u8 {
    match state {
        ActorState::Created => 0,
        ActorState::Running => 1,
        ActorState::Stopping => 2,
        ActorState::Stopped => 3,
    }
}

const fn decode_actor_state(value: u8) -> ActorState {
    match value {
        0 => ActorState::Created,
        1 => ActorState::Running,
        2 => ActorState::Stopping,
        _ => ActorState::Stopped,
    }
}

// ============================================================================
// GenServerHandle: external handle for calls and casts
// ============================================================================

/// Handle to a running GenServer.
///
/// Provides typed `call()` and `cast()` methods. The handle owns a sender to
/// the server's mailbox and a oneshot receiver for join.
#[derive(Debug)]
pub struct GenServerHandle<S: GenServer> {
    actor_id: ActorId,
    sender: mpsc::Sender<Envelope<S>>,
    state: Arc<GenServerStateCell>,
    task_id: TaskId,
    receiver: oneshot::Receiver<Result<S, JoinError>>,
    inner: std::sync::Weak<parking_lot::RwLock<CxInner>>,
    completed: bool,
    overflow_policy: CastOverflowPolicy,
    /// Monotonic count of cast envelopes evicted by `try_cast` under
    /// [`CastOverflowPolicy::DropOldest`] (br-asupersync-dqdgcq). Bumped
    /// on every successful eviction regardless of whether `Cx::current()`
    /// is available — the previous Cx-only `cx.trace(...)` route was
    /// invisible to sync callers, masking SLO-relevant lossiness.
    evicted_count: Arc<AtomicU64>,
    /// The server's region; a monitor or link set up through this handle is
    /// held by the server task in it.
    region_id: crate::types::RegionId,
    /// Where the runtime delivers the server's DOWN notifications and
    /// trapped exit signals.
    system: Arc<SystemLane<S>>,
    /// The server task's runtime handle when it was spawned with
    /// [`Cx::spawn_gen_server`]. Admission assigns the task's id and context
    /// after the spawn returns, so the task id, abort and join resolve
    /// through it.
    task: Option<crate::runtime::TaskHandle<()>>,
}

/// Error returned when a call fails.
#[derive(Debug)]
pub enum CallError {
    /// The server has stopped (mailbox disconnected).
    ServerStopped,
    /// The server did not reply (oneshot dropped).
    NoReply,
    /// The call was cancelled, or refused before it was enqueued: a caller
    /// running in the root region receives this variant with a
    /// [`CancelReason::user`] message starting with `[ASUP-E103]`, because
    /// its reply obligation cannot be scoped to the root region (see the
    /// module docs). The enum is exhaustively matchable, so the rejection
    /// rides on this variant rather than a new one.
    Cancelled(CancelReason),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServerStopped => write!(f, "GenServer has stopped"),
            Self::NoReply => write!(f, "GenServer did not reply"),
            Self::Cancelled(reason) => write!(f, "GenServer call cancelled: {reason}"),
        }
    }
}

impl std::error::Error for CallError {}

/// asupersync-0ex6x0: reason message carried by the [`CallError::Cancelled`]
/// a root-region caller receives.
const ROOT_REGION_CALL_REJECTED: &str = "[ASUP-E103] GenServer call issued from a root-region task: the reply obligation must be \
     scoped to a non-root region; call from a child region (a Scope region or a task spawned \
     inside one) instead";

/// Refuses a call whose caller runs in the root region (asupersync-0ex6x0).
///
/// The reply permit is an obligation token minted from the caller's region,
/// and [`ObligationToken::reserve`](crate::obligation::graded::ObligationToken::reserve)
/// panics with `[ASUP-E103]` for the root region. `block_on` and
/// `RuntimeHandle::spawn` tasks live there, so without this check such a
/// caller would panic instead of seeing a typed error. It runs before the
/// mailbox slot is reserved, so a refused call takes nothing from the server.
fn reject_root_region_caller(cx: &Cx) -> Option<CallError> {
    if cx.region_id().as_u64() != 0 {
        return None;
    }
    cx.trace("gen_server::call_rejected_root_region");
    Some(CallError::Cancelled(CancelReason::user(
        ROOT_REGION_CALL_REJECTED,
    )))
}

/// Error returned when a cast fails.
#[derive(Debug)]
pub enum CastError {
    /// The server has stopped (mailbox disconnected).
    ServerStopped,
    /// The mailbox is full.
    Full,
    /// The cast was cancelled.
    Cancelled(CancelReason),
}

impl std::fmt::Display for CastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServerStopped => write!(f, "GenServer has stopped"),
            Self::Full => write!(f, "GenServer mailbox full"),
            Self::Cancelled(reason) => write!(f, "GenServer cast cancelled: {reason}"),
        }
    }
}

impl std::error::Error for CastError {}

/// Error returned when sending an info message fails.
#[derive(Debug)]
pub enum InfoError {
    /// The server has stopped (mailbox disconnected).
    ServerStopped,
    /// The mailbox is full.
    Full,
    /// The send was cancelled.
    Cancelled(CancelReason),
}

impl std::fmt::Display for InfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServerStopped => write!(f, "GenServer has stopped"),
            Self::Full => write!(f, "GenServer mailbox full"),
            Self::Cancelled(reason) => write!(f, "GenServer info cancelled: {reason}"),
        }
    }
}

impl std::error::Error for InfoError {}

impl<S: GenServer> GenServerHandle<S> {
    /// Returns the monotonic count of cast envelopes evicted by this handle's
    /// `try_cast` calls under [`CastOverflowPolicy::DropOldest`]
    /// (br-asupersync-dqdgcq).
    ///
    /// The counter is incremented unconditionally on every successful eviction,
    /// regardless of whether a [`Cx`] is in scope at the point of call — sync
    /// callers (hooks, drivers without an async Cx) can therefore observe
    /// drop pressure that the older `cx.trace(...)`-only path missed entirely.
    /// Suitable for SLO dashboards: poll periodically and expose as a gauge or
    /// derive a delta-rate counter against wall-clock time.
    #[must_use]
    pub fn evicted_count(&self) -> u64 {
        self.evicted_count.load(Ordering::Relaxed)
    }

    /// Send a call (request-response) to the server.
    ///
    /// Blocks until the server replies or the server stops. The reply channel
    /// uses obligation-tracked oneshot from `channel::session`, ensuring that
    /// if the server drops the reply without sending, the obligation token
    /// panics rather than silently losing the reply.
    ///
    /// # Errors
    ///
    /// [`CallError::ServerStopped`] when the server is stopping or its
    /// mailbox is gone, [`CallError::NoReply`] when the server dropped the
    /// reply, and [`CallError::Cancelled`] when `cx` is cancelled or when the
    /// caller runs in the root region (the reason message starts with
    /// `[ASUP-E103]`; see the module docs).
    pub async fn call(&self, cx: &Cx, request: S::Call) -> Result<S::Reply, CallError> {
        if cx.checkpoint().is_err() {
            cx.trace("gen_server::call_rejected_cancelled");
            let reason = cx
                .cancel_reason()
                .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
            return Err(CallError::Cancelled(reason));
        }

        if matches!(
            self.state.load(),
            ActorState::Stopping | ActorState::Stopped
        ) {
            cx.trace("gen_server::call_rejected_stopped");
            return Err(CallError::ServerStopped);
        }

        if let Some(rejected) = reject_root_region_caller(cx) {
            return Err(rejected);
        }

        let send_permit = match self.sender.reserve(cx).await {
            Ok(p) => p,
            Err(e) => {
                let was_cancelled = matches!(e, mpsc::SendError::Cancelled(()));
                if was_cancelled {
                    cx.trace("gen_server::call_send_cancelled");
                    let reason = cx
                        .cancel_reason()
                        .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
                    return Err(CallError::Cancelled(reason));
                }
                cx.trace("gen_server::call_send_failed");
                return Err(CallError::ServerStopped);
            }
        };

        let (reply_tx, mut reply_rx) = session::tracked_oneshot::<S::Reply>();
        // br-asupersync-4taf1b: reply_tx.reserve now propagates a cancelled-Cx
        // error. If we observe one here we map it to CallError::Cancelled so
        // the caller sees the cancel rather than racing to commit a permit
        // into a region that is already draining.
        let reply_permit: session::TrackedOneshotPermit<S::Reply> = match reply_tx.reserve(cx) {
            Ok(p) => p,
            Err(_) => {
                cx.trace("gen_server::call_reply_reserve_cancelled");
                let reason = cx
                    .cancel_reason()
                    .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
                return Err(CallError::Cancelled(reason));
            }
        };
        let envelope: Envelope<S> = Envelope::Call {
            request,
            reply_permit,
        };

        // Use try_send so that if the receiver was dropped between reserve()
        // and now, we can extract the envelope and explicitly abort the
        // reply_permit obligation.  Calling SendPermit::send would silently
        // discard the value on disconnection, dropping the still-armed
        // obligation token and panicking.
        if let Err(e) = send_permit.try_send(envelope) {
            let envelope = match e {
                mpsc::SendError::Disconnected(v)
                | mpsc::SendError::Full(v)
                | mpsc::SendError::Cancelled(v) => v,
            };
            if let Envelope::Call { reply_permit, .. } = envelope {
                let _aborted = session::TrackedOneshotPermit::abort(reply_permit);
            }
            cx.trace("gen_server::call_send_failed");
            return Err(CallError::ServerStopped);
        }

        cx.trace("gen_server::call_enqueued");

        match reply_rx.recv(cx).await {
            Ok(v) => Ok(v),
            Err(oneshot::RecvError::Closed) => {
                cx.trace("gen_server::call_no_reply");
                Err(CallError::NoReply)
            }
            Err(oneshot::RecvError::Cancelled) => {
                cx.trace("gen_server::call_reply_cancelled");
                let reason = cx
                    .cancel_reason()
                    .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
                Err(CallError::Cancelled(reason))
            }
            Err(oneshot::RecvError::PolledAfterCompletion) => {
                unreachable!("GenServer call awaits a fresh reply oneshot recv future")
            }
        }
    }

    /// Send a cast (fire-and-forget) to the server.
    pub async fn cast(&self, cx: &Cx, msg: S::Cast) -> Result<(), CastError> {
        if cx.checkpoint().is_err() {
            cx.trace("gen_server::cast_rejected_cancelled");
            let reason = cx
                .cancel_reason()
                .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
            return Err(CastError::Cancelled(reason));
        }

        if matches!(
            self.state.load(),
            ActorState::Stopping | ActorState::Stopped
        ) {
            cx.trace("gen_server::cast_rejected_stopped");
            return Err(CastError::ServerStopped);
        }
        let envelope: Envelope<S> = Envelope::Cast { msg };
        self.sender.send(cx, envelope).await.map_err(|e| match e {
            mpsc::SendError::Cancelled(_) => {
                cx.trace("gen_server::cast_send_cancelled");
                let reason = cx
                    .cancel_reason()
                    .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
                CastError::Cancelled(reason)
            }
            mpsc::SendError::Disconnected(_) | mpsc::SendError::Full(_) => {
                cx.trace("gen_server::cast_send_failed");
                CastError::ServerStopped
            }
        })
    }

    /// Try to send a cast without blocking.
    ///
    /// Applies the server's [`CastOverflowPolicy`] when the mailbox is full:
    /// - `Reject`: returns `CastError::Full`
    /// - `DropOldest`: evicts the oldest queued cast and enqueues the new one
    pub fn try_cast(&self, msg: S::Cast) -> Result<(), CastError> {
        if matches!(
            self.state.load(),
            ActorState::Stopping | ActorState::Stopped
        ) {
            return Err(CastError::ServerStopped);
        }
        let envelope: Envelope<S> = Envelope::Cast { msg };
        match self.overflow_policy {
            CastOverflowPolicy::Reject => self.sender.try_send(envelope).map_err(|e| match e {
                mpsc::SendError::Disconnected(_) | mpsc::SendError::Cancelled(_) => {
                    CastError::ServerStopped
                }
                mpsc::SendError::Full(_) => CastError::Full,
            }),
            CastOverflowPolicy::DropOldest => {
                match self.sender.send_evict_oldest_where(envelope, |queued| {
                    matches!(queued, Envelope::Cast { .. })
                }) {
                    Ok(Some(_evicted)) => {
                        // Visibility guarantees for lossy drops (br-asupersync-dqdgcq):
                        //
                        // 1. Bump the per-handle eviction counter unconditionally —
                        //    sync callers (no Cx in scope, e.g., hooks invoked from
                        //    a non-async runtime) previously bypassed `cx.trace(...)`
                        //    and the eviction was completely invisible. Operators
                        //    can now read `handle.evicted_count()` regardless of
                        //    caller context.
                        // 2. Emit a tracing-level log so log-aggregation pipelines
                        //    see every drop even when `Cx::current()` is None.
                        // 3. Preserve the existing `cx.trace(...)` breadcrumb when
                        //    a Cx IS available so structured-trace replay continues
                        //    to attribute the eviction to a region/task.
                        let _evicted_total = self
                            .evicted_count
                            .fetch_add(1, Ordering::Relaxed)
                            .saturating_add(1);
                        crate::tracing_compat::warn!(
                            actor_id = ?self.actor_id,
                            evicted_total = _evicted_total,
                            "gen_server::cast_evicted_oldest"
                        );
                        if let Some(cx) = Cx::current() {
                            cx.trace("gen_server::cast_evicted_oldest");
                        }
                        Ok(())
                    }
                    Ok(None) => Ok(()),
                    Err(mpsc::SendError::Disconnected(_) | mpsc::SendError::Cancelled(_)) => {
                        Err(CastError::ServerStopped)
                    }
                    Err(mpsc::SendError::Full(_)) => Err(CastError::Full),
                }
            }
        }
    }

    /// Send an info message (system/out-of-band) to the server.
    pub async fn info(&self, cx: &Cx, msg: S::Info) -> Result<(), InfoError> {
        if cx.checkpoint().is_err() {
            let reason = cx
                .cancel_reason()
                .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
            return Err(InfoError::Cancelled(reason));
        }

        if matches!(
            self.state.load(),
            ActorState::Stopping | ActorState::Stopped
        ) {
            cx.trace("gen_server::info_rejected_stopped");
            return Err(InfoError::ServerStopped);
        }

        let envelope: Envelope<S> = Envelope::Info { msg };
        self.sender.send(cx, envelope).await.map_err(|e| match e {
            mpsc::SendError::Cancelled(_) => {
                let reason = cx
                    .cancel_reason()
                    .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
                InfoError::Cancelled(reason)
            }
            mpsc::SendError::Disconnected(_) => InfoError::ServerStopped,
            mpsc::SendError::Full(_) => InfoError::Full,
        })
    }

    /// Try to send an info message without blocking.
    pub fn try_info(&self, msg: S::Info) -> Result<(), InfoError> {
        if matches!(
            self.state.load(),
            ActorState::Stopping | ActorState::Stopped
        ) {
            return Err(InfoError::ServerStopped);
        }

        let envelope: Envelope<S> = Envelope::Info { msg };
        self.sender.try_send(envelope).map_err(|e| match e {
            mpsc::SendError::Disconnected(_) | mpsc::SendError::Cancelled(_) => {
                InfoError::ServerStopped
            }
            mpsc::SendError::Full(_) => InfoError::Full,
        })
    }

    /// Returns the server's overflow policy for cast messages.
    #[inline]
    #[must_use]
    pub fn cast_overflow_policy(&self) -> CastOverflowPolicy {
        self.overflow_policy
    }

    /// Returns the server's actor ID.
    #[inline]
    #[must_use]
    pub const fn actor_id(&self) -> ActorId {
        self.actor_id
    }

    /// Returns the server's task ID.
    ///
    /// For a server spawned with [`Cx::spawn_gen_server`] this is the
    /// provisional spawn id until the runtime admits the task, and the
    /// task's runtime id afterwards, as for
    /// [`TaskHandle::task_id`](crate::runtime::TaskHandle::task_id).
    #[inline]
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.task
            .as_ref()
            .map_or(self.task_id, crate::runtime::TaskHandle::task_id)
    }

    /// Returns true if the server has finished.
    #[inline]
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.completed
            || ((self.receiver.is_ready() || self.receiver.is_closed())
                && self
                    .task
                    .as_ref()
                    .is_none_or(crate::runtime::TaskHandle::is_finished))
    }

    /// Signals the server to stop gracefully.
    ///
    /// Closes the mailbox and waits for the server to process remaining messages.
    pub fn stop(&self) {
        self.state.request_stop();
        // Ensure a server blocked in `mailbox.recv()` is woken so it can observe
        // the state change and run drain/on_stop deterministically.
        self.sender.wake_receiver();
    }

    /// Request the server to stop immediately by aborting its task.
    ///
    /// Sets `cancel_requested` on the server's context, causing the loop
    /// to exit at the next cancellation check point.
    pub fn abort(&self) {
        self.state.request_stop();
        if let Some(inner) = self.inner.upgrade() {
            let cancel_wakers = {
                let mut guard = inner.write();
                guard.set_cancel_requested(true);
                if guard.cancel_reason.is_none() {
                    guard.cancel_reason = Some(crate::types::CancelReason::user("server aborted"));
                }
                guard.cancel_waker_snapshot()
            };
            for waker in cancel_wakers {
                waker.wake_by_ref();
            }
        } else if let Some(task) = &self.task {
            task.abort_with_reason(crate::types::CancelReason::user("server aborted"));
        }
        self.sender.wake_receiver();
    }

    /// Wait for the server to finish and return its final state.
    ///
    /// For a server spawned with [`Cx::spawn_gen_server`], the join also
    /// waits for the runtime to retire the server task, as
    /// [`TaskHandle::join`](crate::runtime::TaskHandle::join) does.
    pub fn join<'a>(&'a mut self, _cx: &'a Cx) -> GenServerJoinFuture<'a, S> {
        let cx_inner = self.inner.clone();
        let receiver = &mut self.receiver;
        let terminal_state = &mut self.completed;
        GenServerJoinFuture {
            inner: receiver.recv_uninterruptible(),
            cx_inner,
            sender: self.sender.clone(),
            state: Arc::clone(&self.state),
            terminal_state,
            drop_abort_defused: false,
            task: self.task.as_mut(),
            task_exit: None,
        }
    }
}

/// Future returned by [`GenServerHandle::join`].
///
/// This future aborts the server if dropped before completion, ensuring correct
/// cleanup in races and timeouts.
pub struct GenServerJoinFuture<'a, S: GenServer> {
    inner: oneshot::RecvUninterruptibleFuture<'a, Result<S, JoinError>>,
    cx_inner: std::sync::Weak<parking_lot::RwLock<CxInner>>,
    sender: mpsc::Sender<Envelope<S>>,
    state: Arc<GenServerStateCell>,
    terminal_state: &'a mut bool,
    drop_abort_defused: bool,
    /// The server task's runtime handle, for a natively spawned server.
    task: Option<&'a mut crate::runtime::TaskHandle<()>>,
    /// Set once that task has retired: the task's join error, if any.
    task_exit: Option<Option<JoinError>>,
}

impl<S: GenServer> GenServerJoinFuture<'_, S> {
    fn closed_reason(&self) -> crate::types::CancelReason {
        self.cx_inner
            .upgrade()
            .and_then(|inner| inner.read().cancel_reason.clone())
            .unwrap_or_else(|| crate::types::CancelReason::user("join channel closed"))
    }

    fn abort(&self) {
        self.state.request_stop();
        if let Some(inner) = self.cx_inner.upgrade() {
            let cancel_wakers = {
                let mut guard = inner.write();
                guard.set_cancel_requested(true);
                if guard.cancel_reason.is_none() {
                    guard.cancel_reason = Some(crate::types::CancelReason::user("server aborted"));
                }
                guard.cancel_waker_snapshot()
            };
            for waker in cancel_wakers {
                waker.wake_by_ref();
            }
        } else if let Some(task) = self.task.as_deref() {
            task.abort_with_reason(crate::types::CancelReason::user("server aborted"));
        }
        self.sender.wake_receiver();
    }
}

impl<S: GenServer> std::future::Future for GenServerJoinFuture<'_, S> {
    type Output = Result<S, JoinError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = &mut *self;
        if *this.terminal_state {
            return std::task::Poll::Ready(Err(JoinError::PolledAfterCompletion));
        }
        // A natively spawned server publishes its final state before its task
        // retires. Wait for the retirement first, so a joiner never observes
        // the server finished while the runtime still counts its task live.
        if this.task_exit.is_none()
            && let Some(task) = this.task.as_deref_mut()
        {
            match task.poll_join(cx) {
                std::task::Poll::Ready(exit) => this.task_exit = Some(exit.err()),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }

        match std::pin::Pin::new(&mut this.inner).poll(cx) {
            std::task::Poll::Ready(Ok(res)) => {
                *this.terminal_state = true;
                this.drop_abort_defused = true;
                std::task::Poll::Ready(res)
            }
            std::task::Poll::Ready(Err(oneshot::RecvError::Closed)) => {
                *this.terminal_state = true;
                this.drop_abort_defused = true;
                // A native server task that ended without publishing (its
                // spawn was denied, or the runtime shut down) reports why.
                if let Some(Some(exit)) = this.task_exit.take() {
                    return std::task::Poll::Ready(Err(exit));
                }
                let reason = this.closed_reason();
                std::task::Poll::Ready(Err(JoinError::Cancelled(reason)))
            }
            std::task::Poll::Ready(Err(oneshot::RecvError::Cancelled)) => {
                unreachable!("RecvUninterruptibleFuture cannot return Cancelled");
            }
            std::task::Poll::Ready(Err(oneshot::RecvError::PolledAfterCompletion)) => {
                unreachable!(
                    "JoinFuture guards repolls before polling the inner oneshot recv future"
                )
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<S: GenServer> Drop for GenServerJoinFuture<'_, S> {
    fn drop(&mut self) {
        if !*self.terminal_state && !self.drop_abort_defused {
            if self.inner.receiver_finished() {
                return;
            }
            self.abort();
        }
    }
}

/// A lightweight, clonable reference for casting to a GenServer.
///
/// Supports `call()` and `cast()`; it does not support `join()` (use
/// [`GenServerHandle`] for waiting on the final server state).
#[derive(Debug)]
pub struct GenServerRef<S: GenServer> {
    actor_id: ActorId,
    sender: mpsc::Sender<Envelope<S>>,
    state: Arc<GenServerStateCell>,
    overflow_policy: CastOverflowPolicy,
    /// Shared with the handle: evictions through any reference count once.
    evicted_count: Arc<AtomicU64>,
}

impl<S: GenServer> Clone for GenServerRef<S> {
    fn clone(&self) -> Self {
        Self {
            actor_id: self.actor_id,
            sender: self.sender.clone(),
            state: Arc::clone(&self.state),
            overflow_policy: self.overflow_policy,
            evicted_count: Arc::clone(&self.evicted_count),
        }
    }
}

impl<S: GenServer> GenServerRef<S> {
    /// Returns the configured cast overflow policy for this server.
    #[must_use]
    pub const fn cast_overflow_policy(&self) -> CastOverflowPolicy {
        self.overflow_policy
    }

    /// Casts evicted under [`CastOverflowPolicy::DropOldest`] through the
    /// handle or any of its references; the same count as
    /// [`GenServerHandle::evicted_count`].
    #[must_use]
    pub fn evicted_count(&self) -> u64 {
        self.evicted_count.load(Ordering::Relaxed)
    }

    /// Send a call to the server.
    ///
    /// # Errors
    ///
    /// Same contract as [`GenServerHandle::call`]: a caller running in the
    /// root region is refused with [`CallError::Cancelled`] whose reason
    /// message starts with `[ASUP-E103]` (see the module docs).
    pub async fn call(&self, cx: &Cx, request: S::Call) -> Result<S::Reply, CallError> {
        if cx.checkpoint().is_err() {
            cx.trace("gen_server::call_rejected_cancelled");
            let reason = cx
                .cancel_reason()
                .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
            return Err(CallError::Cancelled(reason));
        }

        if matches!(
            self.state.load(),
            ActorState::Stopping | ActorState::Stopped
        ) {
            cx.trace("gen_server::call_rejected_stopped");
            return Err(CallError::ServerStopped);
        }

        if let Some(rejected) = reject_root_region_caller(cx) {
            return Err(rejected);
        }

        let send_permit = match self.sender.reserve(cx).await {
            Ok(p) => p,
            Err(e) => {
                let was_cancelled = matches!(e, mpsc::SendError::Cancelled(()));
                if was_cancelled {
                    cx.trace("gen_server::call_send_cancelled");
                    let reason = cx
                        .cancel_reason()
                        .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
                    return Err(CallError::Cancelled(reason));
                }
                cx.trace("gen_server::call_send_failed");
                return Err(CallError::ServerStopped);
            }
        };

        let (reply_tx, mut reply_rx) = session::tracked_oneshot::<S::Reply>();
        // br-asupersync-4taf1b: reply_tx.reserve now propagates a cancelled-Cx
        // error. If we observe one here we map it to CallError::Cancelled so
        // the caller sees the cancel rather than racing to commit a permit
        // into a region that is already draining.
        let reply_permit: session::TrackedOneshotPermit<S::Reply> = match reply_tx.reserve(cx) {
            Ok(p) => p,
            Err(_) => {
                cx.trace("gen_server::call_reply_reserve_cancelled");
                let reason = cx
                    .cancel_reason()
                    .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
                return Err(CallError::Cancelled(reason));
            }
        };
        let envelope: Envelope<S> = Envelope::Call {
            request,
            reply_permit,
        };

        // Use try_send so that if the receiver was dropped between reserve()
        // and now, we can extract the envelope and explicitly abort the
        // reply_permit obligation.  Calling SendPermit::send would silently
        // discard the value on disconnection, dropping the still-armed
        // obligation token and panicking.
        if let Err(e) = send_permit.try_send(envelope) {
            let envelope = match e {
                mpsc::SendError::Disconnected(v)
                | mpsc::SendError::Full(v)
                | mpsc::SendError::Cancelled(v) => v,
            };
            if let Envelope::Call { reply_permit, .. } = envelope {
                let _aborted = session::TrackedOneshotPermit::abort(reply_permit);
            }
            cx.trace("gen_server::call_send_failed");
            return Err(CallError::ServerStopped);
        }

        cx.trace("gen_server::call_enqueued");

        match reply_rx.recv(cx).await {
            Ok(v) => Ok(v),
            Err(oneshot::RecvError::Closed) => {
                cx.trace("gen_server::call_no_reply");
                Err(CallError::NoReply)
            }
            Err(oneshot::RecvError::Cancelled) => {
                cx.trace("gen_server::call_reply_cancelled");
                let reason = cx
                    .cancel_reason()
                    .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
                Err(CallError::Cancelled(reason))
            }
            Err(oneshot::RecvError::PolledAfterCompletion) => {
                unreachable!("GenServerRef::call awaits a fresh reply oneshot recv future")
            }
        }
    }

    /// Send a cast to the server.
    pub async fn cast(&self, cx: &Cx, msg: S::Cast) -> Result<(), CastError> {
        if cx.checkpoint().is_err() {
            cx.trace("gen_server::cast_rejected_cancelled");
            let reason = cx
                .cancel_reason()
                .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
            return Err(CastError::Cancelled(reason));
        }

        if matches!(
            self.state.load(),
            ActorState::Stopping | ActorState::Stopped
        ) {
            cx.trace("gen_server::cast_rejected_stopped");
            return Err(CastError::ServerStopped);
        }
        let envelope: Envelope<S> = Envelope::Cast { msg };
        self.sender.send(cx, envelope).await.map_err(|e| match e {
            mpsc::SendError::Cancelled(_) => {
                cx.trace("gen_server::cast_send_cancelled");
                let reason = cx
                    .cancel_reason()
                    .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
                CastError::Cancelled(reason)
            }
            mpsc::SendError::Disconnected(_) | mpsc::SendError::Full(_) => {
                cx.trace("gen_server::cast_send_failed");
                CastError::ServerStopped
            }
        })
    }

    /// Try to send a cast without blocking.
    ///
    /// Applies the server's [`CastOverflowPolicy`] when the mailbox is full.
    pub fn try_cast(&self, msg: S::Cast) -> Result<(), CastError> {
        if matches!(
            self.state.load(),
            ActorState::Stopping | ActorState::Stopped
        ) {
            return Err(CastError::ServerStopped);
        }
        let envelope: Envelope<S> = Envelope::Cast { msg };
        match self.overflow_policy {
            CastOverflowPolicy::Reject => self.sender.try_send(envelope).map_err(|e| match e {
                mpsc::SendError::Disconnected(_) | mpsc::SendError::Cancelled(_) => {
                    CastError::ServerStopped
                }
                mpsc::SendError::Full(_) => CastError::Full,
            }),
            CastOverflowPolicy::DropOldest => match self
                .sender
                .send_evict_oldest_where(envelope, |queued| matches!(queued, Envelope::Cast { .. }))
            {
                Ok(Some(evicted)) => {
                    debug_assert!(matches!(evicted, Envelope::Cast { .. }));
                    // Counted and logged as the handle's evictions are
                    // (br-asupersync-dqdgcq, br-asupersync-c9b5nb).
                    let _evicted_total = self
                        .evicted_count
                        .fetch_add(1, Ordering::Relaxed)
                        .saturating_add(1);
                    crate::tracing_compat::warn!(
                        actor_id = ?self.actor_id,
                        evicted_total = _evicted_total,
                        "gen_server::cast_evicted_oldest"
                    );
                    if let Some(cx) = Cx::current() {
                        cx.trace("gen_server::cast_evicted_oldest");
                    }
                    Ok(())
                }
                Ok(None) => Ok(()),
                Err(mpsc::SendError::Disconnected(_) | mpsc::SendError::Cancelled(_)) => {
                    Err(CastError::ServerStopped)
                }
                Err(mpsc::SendError::Full(_)) => Err(CastError::Full),
            },
        }
    }

    /// Send an info message (system/out-of-band) to the server.
    pub async fn info(&self, cx: &Cx, msg: S::Info) -> Result<(), InfoError> {
        if cx.checkpoint().is_err() {
            let reason = cx
                .cancel_reason()
                .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
            return Err(InfoError::Cancelled(reason));
        }

        if matches!(
            self.state.load(),
            ActorState::Stopping | ActorState::Stopped
        ) {
            cx.trace("gen_server::info_rejected_stopped");
            return Err(InfoError::ServerStopped);
        }

        let envelope: Envelope<S> = Envelope::Info { msg };
        self.sender.send(cx, envelope).await.map_err(|e| match e {
            mpsc::SendError::Cancelled(_) => {
                let reason = cx
                    .cancel_reason()
                    .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
                InfoError::Cancelled(reason)
            }
            mpsc::SendError::Disconnected(_) => InfoError::ServerStopped,
            mpsc::SendError::Full(_) => InfoError::Full,
        })
    }

    /// Try to send an info message without blocking.
    pub fn try_info(&self, msg: S::Info) -> Result<(), InfoError> {
        if matches!(
            self.state.load(),
            ActorState::Stopping | ActorState::Stopped
        ) {
            return Err(InfoError::ServerStopped);
        }

        let envelope: Envelope<S> = Envelope::Info { msg };
        self.sender.try_send(envelope).map_err(|e| match e {
            mpsc::SendError::Disconnected(_) | mpsc::SendError::Cancelled(_) => {
                InfoError::ServerStopped
            }
            mpsc::SendError::Full(_) => InfoError::Full,
        })
    }

    /// Returns true if the server has stopped.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    /// Returns true if the server is still alive.
    #[inline]
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.state.load() != ActorState::Stopped
    }

    /// Returns the server's actor ID.
    #[inline]
    #[must_use]
    pub const fn actor_id(&self) -> ActorId {
        self.actor_id
    }
}

impl<S: GenServer> GenServerHandle<S> {
    /// Returns a lightweight, clonable reference for casting.
    #[inline]
    #[must_use]
    pub fn server_ref(&self) -> GenServerRef<S> {
        GenServerRef {
            actor_id: self.actor_id,
            sender: self.sender.clone(),
            state: Arc::clone(&self.state),
            overflow_policy: self.overflow_policy,
            evicted_count: Arc::clone(&self.evicted_count),
        }
    }
}

/// Monitors and links held by the server
/// (br-asupersync-issue65-criticisms-kpmoy5.6.1). Notifications reach the
/// server's [`GenServer::handle_info`] as [`SystemMsg`] values through a lane
/// outside the bounded mailbox, so a full mailbox never loses one. They end
/// when the server stops. `cx` supplies the runtime to send the request
/// through; the server task holds the monitor or link.
impl<S: GenServer> GenServerHandle<S>
where
    S::Info: From<SystemMsg>,
{
    /// Makes the server monitor `target` (a [`TaskId`] or a reference to a
    /// [`TaskHandle`](crate::runtime::TaskHandle)): when that task finishes,
    /// for any reason, `handle_info` receives one [`SystemMsg::Down`] whose
    /// [`DownReason`] maps its outcome.
    ///
    /// The future resolves to the monitor's reference once the runtime has
    /// registered it, or fails with
    /// [`WatchError::NotFound`](crate::monitor::WatchError::NotFound) if the
    /// task already finished.
    pub fn monitor(
        &self,
        cx: &Cx,
        target: impl Into<crate::monitor::WatchTarget>,
    ) -> crate::monitor::ServerMonitorOpening {
        let target = target.into();
        let target_id = target.id();
        let system = Arc::clone(&self.system);
        let slot = crate::monitor::MonitorSlot::with_sink(Box::new(move |at, notification| {
            system.push(S::Info::from(SystemMsg::Down {
                completion_vt: at,
                notification,
            }));
        }));
        let (watcher, watcher_region) = (self.holder(), self.region_id);
        crate::monitor::ServerWatchOpening::open(
            cx.spawn_gateway_handle(),
            target_id,
            slot,
            |slot| crate::monitor::WatchCommand::Monitor {
                watcher,
                watcher_region,
                target,
                slot,
                attempts: 0,
            },
            |monitor_ref| crate::monitor::WatchCommand::Demonitor { monitor_ref },
        )
    }

    /// Removes a monitor made with [`Self::monitor`]: no DOWN for it is
    /// delivered afterwards.
    pub fn demonitor(&self, cx: &Cx, monitor_ref: crate::monitor::MonitorRef) {
        if let Some(gateway) = cx.spawn_gateway_handle() {
            let _ = gateway.enqueue_region_command(
                crate::runtime::spawn_mailbox::RegionCommand::Watch(
                    crate::monitor::WatchCommand::Demonitor { monitor_ref },
                ),
            );
        }
    }

    /// Links the server with `peer`: when either finishes abnormally, the
    /// runtime requests cancellation of the other. A normal exit removes the
    /// link.
    pub fn link(
        &self,
        cx: &Cx,
        peer: impl Into<crate::monitor::WatchTarget>,
    ) -> crate::monitor::ServerLinkOpening {
        self.open_link(cx, peer.into(), crate::link::ExitPolicy::Propagate)
    }

    /// Links the server with `peer`, trapping the peer's exits: when `peer`
    /// finishes, for any reason, `handle_info` receives a [`SystemMsg::Exit`]
    /// and the server keeps running. When the server finishes abnormally,
    /// `peer` is still cancelled.
    pub fn link_trapping(
        &self,
        cx: &Cx,
        peer: impl Into<crate::monitor::WatchTarget>,
    ) -> crate::monitor::ServerLinkOpening {
        self.open_link(cx, peer.into(), crate::link::ExitPolicy::Trap)
    }

    /// Removes a link made with [`Self::link`] or [`Self::link_trapping`].
    pub fn unlink(&self, cx: &Cx, link_ref: crate::link::LinkRef) {
        if let Some(gateway) = cx.spawn_gateway_handle() {
            let _ = gateway.enqueue_region_command(
                crate::runtime::spawn_mailbox::RegionCommand::Watch(
                    crate::monitor::WatchCommand::Unlink { link_ref },
                ),
            );
        }
    }

    fn open_link(
        &self,
        cx: &Cx,
        peer: crate::monitor::WatchTarget,
        task_policy: crate::link::ExitPolicy,
    ) -> crate::monitor::ServerLinkOpening {
        let peer_id = peer.id();
        let system = Arc::clone(&self.system);
        let slot = crate::link::LinkSlot::with_sink(Box::new(
            move |at, signal: crate::link::ExitSignal| {
                system.push(S::Info::from(SystemMsg::Exit {
                    exit_vt: at,
                    from: signal.from,
                    reason: signal.reason,
                }));
            },
        ));
        let (task, task_region) = (self.holder(), self.region_id);
        crate::monitor::ServerWatchOpening::open(
            cx.spawn_gateway_handle(),
            peer_id,
            slot,
            |slot| crate::monitor::WatchCommand::Link {
                task,
                task_region,
                task_policy,
                peer,
                slot,
                attempts: 0,
            },
            |link_ref| crate::monitor::WatchCommand::Unlink { link_ref },
        )
    }

    /// The server task as the holder of a monitor or link. A natively spawned
    /// server is named through its spawn handle, so the runtime holds the
    /// watch under the task's admitted id.
    fn holder(&self) -> crate::monitor::WatchTarget {
        self.task
            .as_ref()
            .map_or_else(|| self.task_id.into(), crate::monitor::WatchTarget::from)
    }
}

// ============================================================================
// GenServer runtime loop
// ============================================================================

/// Default mailbox capacity for GenServers.
pub const DEFAULT_GENSERVER_MAILBOX_CAPACITY: usize = 64;

/// Runs the GenServer message loop.
async fn run_gen_server_loop<S: GenServer>(
    mut server: S,
    cx: Cx,
    cell: &mut GenServerCell<S>,
) -> S {
    use crate::tracing_compat::debug;

    // Only transition to Running if stop() wasn't called before the server started.
    // stop() sets Stopping before scheduling; we must honour that signal so the
    // poll_fn guard in the message loop can detect the pre-stop and break.
    cell.state.start_running();

    // Phase 1: Initialization
    // Skip init when either the Cx is cancelled or the server was pre-stopped
    // (stop() sets Stopping before scheduling, but does not cancel the Cx).
    if cx.checkpoint().is_err() || cell.state.load() == ActorState::Stopping {
        cx.trace("gen_server::init_skipped_cancelled");
    } else {
        cx.trace("gen_server::init");
        let _budget = PhaseBudgetGuard::enter(&cx, server.on_start_budget(), true);
        server.on_start(&cx).await;
    }

    // Phase 2: Message loop with fairness yielding
    // br-asupersync-foa8ir: Add periodic yielding to prevent mailbox starvation
    let mut messages_processed = 0u32;
    const YIELD_INTERVAL: u32 = 8; // Yield every 8 messages for fairness

    loop {
        if cx.checkpoint().is_err() {
            cx.trace("gen_server::cancel_requested");
            break;
        }

        let recv_result = std::future::poll_fn(|task_cx| {
            // DOWN notifications and trapped exit signals go first.
            if let Some(msg) = cell.system.poll_next(task_cx.waker()) {
                return std::task::Poll::Ready(Ok(Envelope::Info { msg }));
            }
            match cell.mailbox.poll_recv(&cx, task_cx) {
                std::task::Poll::Pending if cell.state.load() == ActorState::Stopping => {
                    // Graceful stop requested and mailbox is empty. Break the loop.
                    std::task::Poll::Ready(Err(crate::channel::mpsc::RecvError::Disconnected))
                }
                other => other,
            }
        })
        .await;

        match recv_result {
            Ok(envelope) => {
                dispatch_envelope(&mut server, &cx, envelope).await;

                // Yield periodically to maintain fairness with other tasks.
                // Merely checking the budget is not a scheduling point: a
                // continuously ready mailbox can otherwise monopolize its
                // worker indefinitely.
                messages_processed += 1;
                if messages_processed >= YIELD_INTERVAL {
                    messages_processed = 0;
                    cx.trace("gen_server::yield_after_ready_batch");
                    crate::runtime::yield_now().await;
                }
            }
            Err(crate::channel::mpsc::RecvError::Disconnected) => {
                cx.trace("gen_server::mailbox_disconnected");
                break;
            }
            Err(crate::channel::mpsc::RecvError::Cancelled) => {
                cx.trace("gen_server::recv_cancelled");
                break;
            }
            Err(crate::channel::mpsc::RecvError::Empty) => {
                break;
            }
        }
    }

    cell.state.store(ActorState::Stopping);

    // Determine abort status BEFORE masking. The mask below defers
    // cancellation so on_stop can run deterministically, but that means
    // `cx.checkpoint()` inside the mask always returns Ok — reading abort
    // status after entering the mask would make `is_aborted` permanently
    // false and run user `handle_cast`/`handle_info` for every queued message
    // even on an aborted server. `actor.rs` computes this before masking for
    // exactly this reason; keep the two in sync.
    let is_aborted = cx.checkpoint().is_err();

    // Phase 3+4: Drain + stop hook.
    //
    // Drain+on_stop are cleanup phases. We:
    // - tighten budget to a bounded stop budget
    // - mask cancellation so cleanup can run deterministically
    let _budget = PhaseBudgetGuard::enter(&cx, server.on_stop_budget(), false);
    let _mask = AsyncMaskGuard::enter(&cx);

    // Phase 3: Drain remaining messages.
    // Calls during drain: reply with error (caller should not depend on drain).
    // Casts during drain: process normally if gracefully stopped, skip if aborted.
    // System messages still queued are info messages, drained first.
    cell.mailbox.close();
    let mut pending_system = cell.system.close();

    let mut drained: u64 = 0;
    let mut drain_yield_counter = 0u32;
    while let Some(envelope) = pending_system
        .pop_front()
        .map(|msg| Envelope::Info { msg })
        .or_else(|| cell.mailbox.try_recv().ok())
    {
        match envelope {
            Envelope::Call {
                request: _,
                reply_permit,
            } => {
                let _aborted = session::TrackedOneshotPermit::abort(reply_permit);
                cx.trace("gen_server::drain_abort_call");
            }
            Envelope::Cast { msg } => {
                if !is_aborted {
                    server.handle_cast(&cx, msg).await;
                }
            }
            Envelope::Info { msg } => {
                if !is_aborted {
                    server.handle_info(&cx, msg).await;
                }
            }
        }
        drained += 1;

        // br-asupersync-foa8ir: Yield during drain to prevent starvation.
        drain_yield_counter += 1;
        if drain_yield_counter >= YIELD_INTERVAL {
            drain_yield_counter = 0;
            cx.trace("gen_server::yield_during_drain");
            crate::runtime::yield_now().await;
        }
    }
    if drained > 0 {
        debug!(drained = drained, "gen_server::mailbox_drained");
        cx.trace("gen_server::mailbox_drained");
    }

    // Phase 4: Cleanup
    cx.trace("gen_server::terminate");
    server.on_stop(&cx).await;

    server
}

/// Dispatch a single envelope to the appropriate handler.
async fn dispatch_envelope<S: GenServer>(server: &mut S, cx: &Cx, envelope: Envelope<S>) {
    match envelope {
        Envelope::Call {
            request,
            reply_permit,
        } => {
            let reply = Reply::<S::Reply>::new(cx, reply_permit);
            server.handle_call(cx, request, reply).await;
        }
        Envelope::Cast { msg } => {
            server.handle_cast(cx, msg).await;
        }
        Envelope::Info { msg } => {
            server.handle_info(cx, msg).await;
        }
    }
}

// ============================================================================
// Spawn integration
// ============================================================================

impl<P: crate::types::Policy> crate::cx::Scope<'_, P> {
    /// Spawns a new GenServer in this scope.
    ///
    /// The server runs as a region-owned task. Calls and casts are delivered
    /// through a bounded MPSC channel with two-phase send semantics.
    pub fn spawn_gen_server<S: GenServer>(
        &self,
        state: &mut crate::runtime::state::RuntimeState,
        cx: &Cx,
        server: S,
        mailbox_capacity: usize,
    ) -> Result<(GenServerHandle<S>, crate::runtime::stored_task::StoredTask), SpawnError> {
        use crate::cx::scope::CatchUnwind;
        use crate::runtime::stored_task::StoredTask;
        use crate::tracing_compat::{debug, debug_span};

        let overflow_policy = server.cast_overflow_policy();
        let (msg_tx, msg_rx) = mpsc::channel::<Envelope<S>>(mailbox_capacity);
        let (result_tx, result_rx) = oneshot::channel::<Result<S, JoinError>>();
        let task_id = self.create_task_record(state)?;
        let actor_id = ActorId::from_task(task_id);
        let server_state = Arc::new(GenServerStateCell::new(ActorState::Created));
        let region_id = self.region_id();

        let (child_cx, child_cx_full) = self.build_child_task_cx(state, cx, task_id);

        if let Some(record) = state.task_mut(task_id) {
            record.set_cx_inner(child_cx.inner.clone());
            record.set_cx(child_cx_full.clone());
        }
        let spawned_at = state
            .timer_driver()
            .map_or(state.now, crate::time::TimerDriverHandle::now);
        let spawn_effects = state.prepare_task_spawn_effects(
            task_id,
            region_id,
            self.budget(),
            crate::runtime::state::TaskSpawnSource::Scope,
            spawned_at,
        );

        let inner_weak = Arc::downgrade(&child_cx.inner);
        let state_for_task = Arc::clone(&server_state);
        let system = Arc::new(SystemLane::new());

        let mut cell = GenServerCell {
            mailbox: msg_rx,
            state: Arc::clone(&server_state),
            _keep_alive: msg_tx.clone(),
            system: Arc::clone(&system),
        };

        let wrapped = async move {
            spawn_effects.dispatch();
            let trace_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _span = debug_span!(
                    "gen_server_spawn",
                    task_id = ?task_id,
                    region_id = ?region_id,
                    mailbox_capacity = mailbox_capacity,
                )
                .entered();
                debug!(
                    task_id = ?task_id,
                    region_id = ?region_id,
                    mailbox_capacity = mailbox_capacity,
                    "gen_server spawned"
                );
            }));
            let result = match trace_result {
                Ok(()) => {
                    CatchUnwind {
                        inner: Box::pin(run_gen_server_loop(server, child_cx, &mut cell)),
                    }
                    .await
                }
                Err(payload) => Err(payload),
            };
            match result {
                Ok(server_final) => {
                    publish_server_final(&state_for_task, result_tx, server_final);
                    Outcome::Ok(())
                }
                Err(payload) => {
                    let panic_payload =
                        publish_server_panic(&mut cell, &state_for_task, result_tx, &payload);
                    std::mem::forget(payload);
                    Outcome::Panicked(panic_payload)
                }
            }
        };

        let stored = StoredTask::new_with_id(wrapped, task_id);

        let handle = GenServerHandle {
            actor_id,
            sender: msg_tx,
            state: server_state,
            task_id,
            receiver: result_rx,
            inner: inner_weak,
            completed: false,
            overflow_policy,
            evicted_count: Arc::new(AtomicU64::new(0)),
            region_id,
            system,
            task: None,
        };

        Ok((handle, stored))
    }

    /// Spawns a named GenServer in this scope, registering it in the given
    /// [`NameRegistry`](crate::cx::NameRegistry).
    ///
    /// This combines [`spawn_gen_server`](Self::spawn_gen_server) with
    /// [`NameRegistry::register`](crate::cx::NameRegistry::register) into a
    /// single atomic operation: the name is
    /// acquired *after* the server task is created but *before* it starts
    /// processing messages.
    ///
    /// On success, the returned [`NamedGenServerHandle`] holds both the server
    /// handle and the name lease. The lease is resolved when the handle is
    /// released via [`NamedGenServerHandle::release_name`] or aborted via
    /// [`NamedGenServerHandle::abort_lease`].
    ///
    /// # Errors
    ///
    /// Returns [`NamedSpawnError::Spawn`] if the underlying task spawn fails,
    /// or [`NamedSpawnError::NameTaken`] if the name is already registered.
    /// In the name-taken case, the server task is *not* spawned (it is
    /// abandoned before being stored).
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_named_gen_server<S: GenServer>(
        &self,
        state: &mut crate::runtime::state::RuntimeState,
        cx: &Cx,
        registry: &mut crate::cx::NameRegistry,
        name: impl Into<String>,
        server: S,
        mailbox_capacity: usize,
        now: crate::types::Time,
    ) -> Result<
        (
            NamedGenServerHandle<S>,
            crate::runtime::stored_task::StoredTask,
        ),
        NamedSpawnError,
    > {
        let name = name.into();

        // Phase 1: Spawn the server (creates task record + handle).
        let (handle, stored) = self
            .spawn_gen_server(state, cx, server, mailbox_capacity)
            .map_err(NamedSpawnError::Spawn)?;

        // Phase 2: Register the name under the new task's ID.
        let task_id = handle.task_id();
        let region = self.region_id();

        match registry.register(name, task_id, region, now) {
            Ok(lease) => {
                let named = NamedGenServerHandle {
                    handle,
                    lease: Some(lease),
                };
                Ok((named, stored))
            }
            Err(e) => {
                // Registration failed: clean up the task record that was created
                // by spawn_gen_server to prevent a region quiescence leak.
                // Without this cleanup, the region would have a child task that
                // is never scheduled and can never complete, blocking region close.
                let task_id = handle.task_id();
                if let Some(region_record) = state.region(self.region_id()) {
                    region_record.remove_task(task_id);
                }
                state.remove_task(task_id);
                Err(NamedSpawnError::NameTaken(e))
            }
        }
    }
}

// Teardown result publication must not consult the server's Cx: aborting the
// server cancels that context before the final state is returned. Stopped is
// published before send_blocking wakes a waiting joiner.

/// Publishes the final state of a server whose loop returned.
fn publish_server_final<S: GenServer>(
    state: &GenServerStateCell,
    result_tx: oneshot::Sender<Result<S, JoinError>>,
    server_final: S,
) {
    state.store(ActorState::Stopped);
    let _ = result_tx.send_blocking(Ok(server_final));
}

/// Publishes the panic of a server whose loop panicked, after resolving what
/// it left queued, and returns the panic for the task's outcome.
fn publish_server_panic<S: GenServer>(
    cell: &mut GenServerCell<S>,
    state: &GenServerStateCell,
    result_tx: oneshot::Sender<Result<S, JoinError>>,
    payload: &Box<dyn std::any::Any + Send>,
) -> crate::types::PanicPayload {
    // The loop panicked before its graceful Phase-3 drain ran, so the mailbox
    // may still hold queued `Envelope::Call` envelopes whose reply permits are
    // armed obligations. Dropping the receiver (when `cell` drops) would drop
    // them un-aborted, tripping a secondary `[ASUP-E101] OBLIGATION TOKEN
    // LEAKED` panic inside the mpsc Receiver's Drop during task teardown (a
    // double-fault into the executor drop path). Close and abort queued call
    // permits here, mirroring the graceful drain.
    cell.mailbox.close();
    while let Ok(envelope) = cell.mailbox.try_recv() {
        if let Envelope::Call { reply_permit, .. } = envelope {
            let _ = session::TrackedOneshotPermit::abort(reply_permit);
        }
    }
    // No handler runs after a panic: drop queued system messages.
    drop(cell.system.close());
    let panic_payload =
        crate::types::PanicPayload::new(crate::cx::scope::payload_to_string(payload));
    state.store(ActorState::Stopped);
    let _ = result_tx.send_blocking(Err(JoinError::Panicked(panic_payload.clone())));
    panic_payload
}

impl Cx {
    /// Spawns a GenServer as a task in this context's region, on the native
    /// runtime or the lab runtime alike.
    ///
    /// The server runs the same lifecycle as one spawned with
    /// [`Scope::spawn_gen_server`](crate::cx::Scope::spawn_gen_server):
    /// [`GenServer::on_start`], then calls, casts and info messages from a
    /// bounded mailbox of `mailbox_capacity`, then a drain and
    /// [`GenServer::on_stop`]. The region's close cancels the server.
    ///
    /// The runtime admits the task after this returns, as for
    /// [`Cx::spawn`]: until then the handle's
    /// [`task_id`](GenServerHandle::task_id) is the provisional spawn id.
    /// [`actor_id`](GenServerHandle::actor_id) is fixed here and derives from
    /// that provisional id. Monitors and links set up through the handle are
    /// held by the admitted task. A denied spawn joins as
    /// [`JoinError::Cancelled`].
    ///
    /// Calls must come from a task outside the root region (see
    /// [`CallError::Cancelled`]), so spawn the server where its callers run,
    /// for example in a child region.
    ///
    /// ```ignore
    /// let mut counter = cx.spawn_gen_server(Counter::default(), 32)?;
    /// counter.cast(&cx, Add(2)).await?;
    /// let total = counter.call(&cx, Get).await?;
    /// counter.stop();
    /// let final_state = counter.join(&cx).await?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`] when this context is not
    /// attached to a running runtime or may not spawn.
    pub fn spawn_gen_server<S: GenServer>(
        &self,
        server: S,
        mailbox_capacity: usize,
    ) -> Result<GenServerHandle<S>, SpawnError> {
        let overflow_policy = server.cast_overflow_policy();
        let (msg_tx, msg_rx) = mpsc::channel::<Envelope<S>>(mailbox_capacity);
        let (result_tx, result_rx) = oneshot::channel::<Result<S, JoinError>>();
        let server_state = Arc::new(GenServerStateCell::new(ActorState::Created));
        let system = Arc::new(SystemLane::new());
        let mut cell = GenServerCell {
            mailbox: msg_rx,
            state: Arc::clone(&server_state),
            _keep_alive: msg_tx.clone(),
            system: Arc::clone(&system),
        };
        let state_for_task = Arc::clone(&server_state);

        let task = self.spawn(move |child_cx| async move {
            let result = crate::cx::scope::CatchUnwind {
                inner: Box::pin(run_gen_server_loop(server, child_cx, &mut cell)),
            }
            .await;
            match result {
                Ok(server_final) => publish_server_final(&state_for_task, result_tx, server_final),
                Err(payload) => {
                    publish_server_panic(&mut cell, &state_for_task, result_tx, &payload);
                    // Re-raise, so the runtime records the task as panicked:
                    // its monitors see a panic and its links propagate it.
                    std::panic::resume_unwind(payload);
                }
            }
        })?;

        let task_id = task.task_id();
        Ok(GenServerHandle {
            actor_id: ActorId::from_task(task_id),
            sender: msg_tx,
            state: server_state,
            task_id,
            receiver: result_rx,
            inner: std::sync::Weak::new(),
            completed: false,
            overflow_policy,
            evicted_count: Arc::new(AtomicU64::new(0)),
            region_id: self.region_id(),
            system,
            task: Some(task),
        })
    }
}

// ============================================================================
// Named GenServer handle
// ============================================================================

/// Error from [`Scope::spawn_named_gen_server`](crate::cx::Scope::spawn_named_gen_server).
#[derive(Debug)]
pub enum NamedSpawnError {
    /// The underlying task spawn failed.
    Spawn(SpawnError),
    /// The name was already taken in the registry.
    NameTaken(crate::cx::NameLeaseError),
}

impl std::fmt::Display for NamedSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "named server spawn failed: {e}"),
            Self::NameTaken(e) => write!(f, "named server registration failed: {e}"),
        }
    }
}

impl std::error::Error for NamedSpawnError {}

/// Error returned when releasing a stopped named server's registry entry fails.
#[derive(Debug)]
pub enum ReleaseNameError {
    /// The server is still running; stop + drain or join it first.
    StillRunning,
    /// Resolving the name lease failed.
    Lease(crate::cx::NameLeaseError),
}

impl std::fmt::Display for ReleaseNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StillRunning => write!(f, "named server is still running"),
            Self::Lease(err) => write!(f, "named server lease resolution failed: {err}"),
        }
    }
}

impl std::error::Error for ReleaseNameError {}

/// Handle to a running **named** GenServer.
///
/// Wraps a [`GenServerHandle`] together with a
/// [`NameLease`](crate::cx::NameLease) from the
/// registry. The lease is an obligation (drop bomb): callers must resolve it
/// by calling [`release_name`](Self::release_name) or
/// [`abort_lease`](Self::abort_lease) before dropping.
///
/// All `call`, `cast`, `info` methods delegate to the inner handle.
#[derive(Debug)]
pub struct NamedGenServerHandle<S: GenServer> {
    handle: GenServerHandle<S>,
    lease: Option<crate::cx::NameLease>,
}

impl<S: GenServer> NamedGenServerHandle<S> {
    /// The registered name of this server.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &str {
        self.lease
            .as_ref()
            .map_or("(released)", crate::cx::NameLease::name)
    }

    /// The underlying task ID.
    #[inline]
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.handle.task_id()
    }

    /// The actor ID of this server.
    #[inline]
    #[must_use]
    pub fn actor_id(&self) -> ActorId {
        self.handle.actor_id()
    }

    /// Whether the server has finished execution.
    #[inline]
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    /// Create a lightweight server reference for sending messages.
    #[must_use]
    pub fn server_ref(&self) -> GenServerRef<S> {
        self.handle.server_ref()
    }

    /// Access the inner (unnamed) handle.
    #[must_use]
    pub fn inner(&self) -> &GenServerHandle<S> {
        &self.handle
    }

    /// Signal the server to stop gracefully.
    pub fn stop(&self) {
        self.handle.stop();
    }

    /// Release the name lease (commit) after the server has already stopped.
    ///
    /// Callers should first request graceful shutdown via [`stop`](Self::stop)
    /// and then drive or join the server to completion. This method only
    /// removes the registry entry and resolves the lease once the underlying
    /// server task is no longer live, preserving the invariant that a running
    /// server keeps its name.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseNameError::StillRunning`] if the underlying server
    /// task has not finished yet. Returns [`ReleaseNameError::Lease`] if
    /// the lease was already resolved or moved out via
    /// [`take_lease`](Self::take_lease), or if lease resolution fails. If
    /// the registry no longer holds this lease's entry (`NotFound`, or
    /// `PermissionDenied` after a `Replace`), the lease is aborted and that
    /// error is returned.
    pub fn release_name(
        &mut self,
        registry: &mut crate::cx::NameRegistry,
        now: Time,
    ) -> Result<(), ReleaseNameError> {
        let Some(lease) = self.lease.as_ref() else {
            return Err(ReleaseNameError::Lease(
                crate::cx::NameLeaseError::AlreadyResolved,
            ));
        };
        if !lease.is_active() {
            return Err(ReleaseNameError::Lease(
                crate::cx::NameLeaseError::AlreadyResolved,
            ));
        }

        if !self.handle.is_finished() {
            return Err(ReleaseNameError::StillRunning);
        }

        if let Err(error) = registry.unregister_owned_and_grant(lease, now) {
            // The registry entry is gone or now someone else's (a Replace,
            // a cleanup): this lease can never free it, so abort the lease
            // rather than leave it armed for its drop to panic, and report.
            if let Some(mut lease) = self.lease.take() {
                let _ = lease.abort();
            }
            return Err(ReleaseNameError::Lease(error));
        }
        self.lease
            .take()
            .ok_or(ReleaseNameError::Lease(
                crate::cx::NameLeaseError::AlreadyResolved,
            ))?
            .release()
            .map(|_proof| ())
            .map_err(ReleaseNameError::Lease)
    }

    /// Abort the name lease without stopping the server.
    ///
    /// Use this for cancellation / error paths where the name registration
    /// itself should be rolled back.
    ///
    /// # Errors
    ///
    /// Returns [`crate::cx::NameLeaseError::AlreadyResolved`] if the lease was
    /// already resolved or moved out via [`take_lease`](Self::take_lease).
    /// If the registry no longer holds this lease's entry (`NotFound`, or
    /// `PermissionDenied` after a `Replace`), that error is returned and the
    /// lease is aborted all the same.
    pub fn abort_lease(
        &mut self,
        registry: &mut crate::cx::NameRegistry,
        now: Time,
    ) -> Result<(), crate::cx::NameLeaseError> {
        let Some(lease) = self.lease.as_ref() else {
            return Err(crate::cx::NameLeaseError::AlreadyResolved);
        };
        if !lease.is_active() {
            return Err(crate::cx::NameLeaseError::AlreadyResolved);
        }
        if let Err(error) = registry.unregister_owned_and_grant(lease, now) {
            // The entry is gone or now someone else's (a Replace, a
            // cleanup): report that as before, but resolve the lease, which
            // can never free the entry, instead of leaving it armed for the
            // handle's drop to panic.
            if let Some(mut lease) = self.lease.take() {
                let _ = lease.abort();
            }
            return Err(error);
        }
        self.lease
            .take()
            .ok_or(crate::cx::NameLeaseError::AlreadyResolved)?
            .abort()
            .map(|_proof| ())
    }

    /// Take ownership of the lease (for manual lifecycle management).
    ///
    /// After this call, the handle no longer owns the lease; the caller is
    /// responsible for removing the matching registry entry (for example via
    /// [`crate::cx::NameRegistry::unregister_owned_and_grant`]) and then
    /// resolving the lease obligation.
    pub fn take_lease(&mut self) -> Option<crate::cx::NameLease> {
        self.lease.take()
    }
}

// ============================================================================
// Supervised named-start helper (bd-1hvy1)
// ============================================================================

/// Child-start helper for running a named GenServer under supervision.
///
/// This adapter wires together:
/// 1. Name lease acquisition (`spawn_named_gen_server`)
/// 2. Server task storage in runtime state
/// 3. Deterministic lease/name cleanup on region stop via a sync finalizer
///
/// Use this when building [`crate::supervision::ChildSpec`] entries for named
/// services.
pub struct NamedGenServerStart<S, F>
where
    S: GenServer,
    F: FnMut() -> S + Send + 'static,
{
    registry: Arc<parking_lot::Mutex<crate::cx::NameRegistry>>,
    name: String,
    mailbox_capacity: usize,
    make_server: F,
}

/// Construct a [`NamedGenServerStart`] helper for supervised named services.
#[must_use]
pub fn named_gen_server_start<S, F>(
    registry: Arc<parking_lot::Mutex<crate::cx::NameRegistry>>,
    name: impl Into<String>,
    mailbox_capacity: usize,
    make_server: F,
) -> NamedGenServerStart<S, F>
where
    S: GenServer,
    F: FnMut() -> S + Send + 'static,
{
    NamedGenServerStart {
        registry,
        name: name.into(),
        mailbox_capacity,
        make_server,
    }
}

impl<S, F> crate::supervision::ChildStart for NamedGenServerStart<S, F>
where
    S: GenServer,
    F: FnMut() -> S + Send + 'static,
{
    fn start(
        &mut self,
        scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
        state: &mut crate::runtime::RuntimeState,
        cx: &crate::cx::Cx,
    ) -> Result<TaskId, SpawnError> {
        let now = state.now;
        let server = (self.make_server)();
        let (mut named_handle, stored) = scope
            .spawn_named_gen_server(
                state,
                cx,
                &mut self.registry.lock(),
                self.name.clone(),
                server,
                self.mailbox_capacity,
                now,
            )
            .map_err(|err| match err {
                NamedSpawnError::Spawn(spawn_err) => spawn_err,
                NamedSpawnError::NameTaken(name_err) => SpawnError::NameRegistrationFailed {
                    name: self.name.clone(),
                    reason: name_err.to_string(),
                },
            })?;

        let task_id = named_handle.task_id();
        state.store_spawned_task(task_id, stored);

        let lease_slot = Arc::new(parking_lot::Mutex::new(named_handle.take_lease()));
        let lease_slot_for_finalizer = Arc::clone(&lease_slot);
        let registry_for_finalizer = Arc::clone(&self.registry);
        // The finalizer runs at region close without the runtime state, so it
        // reads the runtime's clock itself: a waiter's deadline is judged at
        // the time of release. A fixed 1 s clock granted the name to waiters
        // long expired and refused ones still waiting (br-asupersync-in4gh8 L1).
        let clock = state.timer_driver().cloned();
        let finalizer_registered = scope.defer_sync(state, move || {
            let lease_to_resolve = lease_slot_for_finalizer.lock().take();
            if let Some(mut lease) = lease_to_resolve {
                let release_now = clock
                    .as_ref()
                    .map_or(now, crate::time::TimerDriverHandle::now);
                let _ = registry_for_finalizer
                    .lock()
                    .unregister_owned_and_grant(&lease, release_now);
                let _ = lease.release();
            }
        });

        if !finalizer_registered {
            let lease_to_abort = lease_slot.lock().take();
            if let Some(mut lease) = lease_to_abort {
                let _ = self.registry.lock().unregister_owned_and_grant(&lease, now);
                let _ = lease.abort();
            }
            if let Some(region_record) = state.region(scope.region_id()) {
                region_record.remove_task(task_id);
            }
            state.remove_task(task_id);
            return Err(SpawnError::RegionClosed(scope.region_id()));
        }

        Ok(task_id)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "gen_server_inline_tests.rs"]
mod tests;

// ============================================================================
// Conformance Tests
// ============================================================================

#[cfg(test)]
#[path = "gen_server_conformance_tests.rs"]
mod gen_server_conformance_tests;

#[cfg(test)]
#[path = "gen_server_conformance_integration_inline_tests.rs"]
mod conformance_integration;
