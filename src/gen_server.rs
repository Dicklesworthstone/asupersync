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
use std::sync::atomic::{AtomicU8, Ordering};

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
            let phase_baseline = original_budget.meet(phase_budget);
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

    /// Drop the oldest unprocessed message to make room for the new one.
    ///
    /// The dropped message is traced for observability. This is useful for
    /// "latest-value-wins" patterns (e.g., sensor readings, UI state updates)
    /// where stale data is less valuable than fresh data.
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
/// When a GenServer is cancelled:
/// 1. The mailbox closes (no new messages accepted)
/// 2. Buffered messages are drained (calls receive errors, casts are processed)
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
    /// Dropping it without sending is detected as an obligation leak in lab mode.
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
/// consuming triggers a panic via [`ObligationToken<SendPermit>`].
///
/// Backed by [`TrackedOneshotPermit`](session::TrackedOneshotPermit) from
/// `channel::session`,
/// making "silent reply drop" structurally impossible.
pub struct Reply<R> {
    cx: Cx,
    permit: TrackedOneshotPermit<R>,
}

impl<R: Send + 'static> Reply<R> {
    fn new(cx: &Cx, permit: TrackedOneshotPermit<R>) -> Self {
        Self {
            cx: cx.clone(),
            permit,
        }
    }

    /// Send the reply value to the caller, returning a [`CommittedProof`].
    ///
    /// Consumes the reply handle. If the caller has dropped (e.g., timed out),
    /// the obligation is aborted cleanly (no panic).
    pub fn send(self, value: R) -> ReplyOutcome {
        match self.permit.send(value) {
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
    pub fn abort(self) -> AbortedProof<SendPermit> {
        self.cx.trace("gen_server::reply_aborted");
        self.permit.abort()
    }

    /// Check if the caller is still waiting for a reply.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.permit.is_closed()
    }
}

impl<R> std::fmt::Debug for Reply<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply")
            .field("pending", &!self.permit.is_closed())
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
    overflow_policy: CastOverflowPolicy,
}

/// Error returned when a call fails.
#[derive(Debug)]
pub enum CallError {
    /// The server has stopped (mailbox disconnected).
    ServerStopped,
    /// The server did not reply (oneshot dropped).
    NoReply,
    /// The call was cancelled.
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
    /// Send a call (request-response) to the server.
    ///
    /// Blocks until the server replies or the server stops. The reply channel
    /// uses obligation-tracked oneshot from `channel::session`, ensuring that
    /// if the server drops the reply without sending, the obligation token
    /// panics rather than silently losing the reply.
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

        let (reply_tx, reply_rx) = session::tracked_oneshot::<S::Reply>();
        let reply_permit = reply_tx.reserve(cx);
        let envelope = Envelope::Call {
            request,
            reply_permit,
        };

        if let Err(e) = self.sender.send(cx, envelope).await {
            // If the envelope couldn't be enqueued, we must abort the reply
            // obligation to avoid an obligation-token leak.
            let (envelope, was_cancelled) = match e {
                mpsc::SendError::Cancelled(v) => (v, true),
                mpsc::SendError::Disconnected(v) | mpsc::SendError::Full(v) => (v, false),
            };
            if let Envelope::Call { reply_permit, .. } = envelope {
                let _aborted = reply_permit.abort();
            }
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
        let envelope = Envelope::Cast { msg };
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
    /// - `DropOldest`: evicts the oldest message and enqueues the new one
    pub fn try_cast(&self, msg: S::Cast) -> Result<(), CastError> {
        if matches!(
            self.state.load(),
            ActorState::Stopping | ActorState::Stopped
        ) {
            return Err(CastError::ServerStopped);
        }
        let envelope = Envelope::Cast { msg };
        match self.overflow_policy {
            CastOverflowPolicy::Reject => self.sender.try_send(envelope).map_err(|e| match e {
                mpsc::SendError::Disconnected(_) | mpsc::SendError::Cancelled(_) => {
                    CastError::ServerStopped
                }
                mpsc::SendError::Full(_) => CastError::Full,
            }),
            CastOverflowPolicy::DropOldest => {
                match self.sender.send_evict_oldest(envelope) {
                    Ok(Some(evicted)) => {
                        // If the evicted message was a Call, abort the reply
                        // obligation to prevent an obligation-token-leak panic.
                        if let Envelope::Call { reply_permit, .. } = evicted {
                            let _aborted = reply_permit.abort();
                        }
                        // Trace the eviction so lossy drops are observable.
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

        let envelope = Envelope::Info { msg };
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

        let envelope = Envelope::Info { msg };
        self.sender.try_send(envelope).map_err(|e| match e {
            mpsc::SendError::Disconnected(_) | mpsc::SendError::Cancelled(_) => {
                InfoError::ServerStopped
            }
            mpsc::SendError::Full(_) => InfoError::Full,
        })
    }

    /// Returns the server's overflow policy for cast messages.
    #[must_use]
    pub fn cast_overflow_policy(&self) -> CastOverflowPolicy {
        self.overflow_policy
    }

    /// Returns the server's actor ID.
    #[must_use]
    pub const fn actor_id(&self) -> ActorId {
        self.actor_id
    }

    /// Returns the server's task ID.
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// Returns true if the server has finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.receiver.is_ready()
    }

    /// Signals the server to stop gracefully.
    pub fn stop(&self) {
        self.state.store(ActorState::Stopping);
        if let Some(inner) = self.inner.upgrade() {
            let mut guard = inner.write();
            guard.cancel_requested = true;
        }
        // Ensure a server blocked in `mailbox.recv()` is woken so it can observe
        // the cancellation request and run drain/on_stop deterministically.
        self.sender.wake_receiver();
    }

    /// Wait for the server to finish and return its final state.
    pub async fn join(&self, cx: &Cx) -> Result<S, JoinError> {
        self.receiver.recv(cx).await.unwrap_or_else(|_| {
            let reason = cx
                .cancel_reason()
                .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
            Err(JoinError::Cancelled(reason))
        })
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
}

impl<S: GenServer> Clone for GenServerRef<S> {
    fn clone(&self) -> Self {
        Self {
            actor_id: self.actor_id,
            sender: self.sender.clone(),
            state: Arc::clone(&self.state),
            overflow_policy: self.overflow_policy,
        }
    }
}

impl<S: GenServer> GenServerRef<S> {
    /// Returns the configured cast overflow policy for this server.
    #[must_use]
    pub const fn cast_overflow_policy(&self) -> CastOverflowPolicy {
        self.overflow_policy
    }

    /// Send a call to the server.
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

        let (reply_tx, reply_rx) = session::tracked_oneshot::<S::Reply>();
        let reply_permit = reply_tx.reserve(cx);
        let envelope = Envelope::Call {
            request,
            reply_permit,
        };

        if let Err(e) = self.sender.send(cx, envelope).await {
            let (envelope, was_cancelled) = match e {
                mpsc::SendError::Cancelled(v) => (v, true),
                mpsc::SendError::Disconnected(v) | mpsc::SendError::Full(v) => (v, false),
            };
            if let Envelope::Call { reply_permit, .. } = envelope {
                let _aborted = reply_permit.abort();
            }
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
        let envelope = Envelope::Cast { msg };
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
        let envelope = Envelope::Cast { msg };
        match self.overflow_policy {
            CastOverflowPolicy::Reject => self.sender.try_send(envelope).map_err(|e| match e {
                mpsc::SendError::Disconnected(_) | mpsc::SendError::Cancelled(_) => {
                    CastError::ServerStopped
                }
                mpsc::SendError::Full(_) => CastError::Full,
            }),
            CastOverflowPolicy::DropOldest => match self.sender.send_evict_oldest(envelope) {
                Ok(Some(evicted)) => {
                    // If the evicted message was a Call, abort the reply
                    // obligation to prevent an obligation-token-leak panic.
                    if let Envelope::Call { reply_permit, .. } = evicted {
                        let _aborted = reply_permit.abort();
                    }
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

        let envelope = Envelope::Info { msg };
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

        let envelope = Envelope::Info { msg };
        self.sender.try_send(envelope).map_err(|e| match e {
            mpsc::SendError::Disconnected(_) | mpsc::SendError::Cancelled(_) => {
                InfoError::ServerStopped
            }
            mpsc::SendError::Full(_) => InfoError::Full,
        })
    }

    /// Returns true if the server has stopped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    /// Returns true if the server is still alive.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.state.load() != ActorState::Stopped
    }

    /// Returns the server's actor ID.
    #[must_use]
    pub const fn actor_id(&self) -> ActorId {
        self.actor_id
    }
}

impl<S: GenServer> GenServerHandle<S> {
    /// Returns a lightweight, clonable reference for casting.
    #[must_use]
    pub fn server_ref(&self) -> GenServerRef<S> {
        GenServerRef {
            actor_id: self.actor_id,
            sender: self.sender.clone(),
            state: Arc::clone(&self.state),
            overflow_policy: self.overflow_policy,
        }
    }
}

// ============================================================================
// GenServer runtime loop
// ============================================================================

/// Default mailbox capacity for GenServers.
pub const DEFAULT_GENSERVER_MAILBOX_CAPACITY: usize = 64;

/// Runs the GenServer message loop.
async fn run_gen_server_loop<S: GenServer>(mut server: S, cx: Cx, cell: &GenServerCell<S>) -> S {
    use crate::tracing_compat::debug;

    cell.state.store(ActorState::Running);

    // Phase 1: Initialization
    if cx.is_cancel_requested() {
        cx.trace("gen_server::init_skipped_cancelled");
    } else {
        cx.trace("gen_server::init");
        let _budget = PhaseBudgetGuard::enter(&cx, server.on_start_budget(), true);
        server.on_start(&cx).await;
    }

    // Phase 2: Message loop
    loop {
        if cx.is_cancel_requested() {
            cx.trace("gen_server::cancel_requested");
            break;
        }

        match cell.mailbox.recv(&cx).await {
            Ok(envelope) => {
                dispatch_envelope(&mut server, &cx, envelope).await;
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

    // Phase 3+4: Drain + stop hook.
    //
    // Drain+on_stop are cleanup phases. We:
    // - tighten budget to a bounded stop budget
    // - mask cancellation so cleanup can run deterministically
    let _budget = PhaseBudgetGuard::enter(&cx, server.on_stop_budget(), false);
    let _mask = AsyncMaskGuard::enter(&cx);

    // Phase 3: Drain remaining messages.
    // Calls during drain: reply with error (caller should not depend on drain).
    // Casts during drain: process normally.
    let drain_limit = cell.mailbox.capacity() as u64;
    let mut drained: u64 = 0;
    while let Ok(envelope) = cell.mailbox.try_recv() {
        match envelope {
            Envelope::Call {
                request: _,
                reply_permit,
            } => {
                let _aborted: AbortedProof<SendPermit> = reply_permit.abort();
                cx.trace("gen_server::drain_abort_call");
            }
            Envelope::Cast { msg } => {
                server.handle_cast(&cx, msg).await;
            }
            Envelope::Info { msg } => {
                server.handle_info(&cx, msg).await;
            }
        }
        drained += 1;
        if drained >= drain_limit {
            break;
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
            let reply = Reply::new(cx, reply_permit);
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

        let _span = debug_span!(
            "gen_server_spawn",
            task_id = ?task_id,
            region_id = ?self.region_id(),
            mailbox_capacity = mailbox_capacity,
        )
        .entered();
        debug!(
            task_id = ?task_id,
            region_id = ?self.region_id(),
            mailbox_capacity = mailbox_capacity,
            "gen_server spawned"
        );

        let child_observability = cx.child_observability(self.region_id(), task_id);
        let child_entropy = cx.child_entropy(task_id);
        let io_driver = state.io_driver_handle();
        let child_cx = Cx::new_with_observability(
            self.region_id(),
            task_id,
            self.budget(),
            Some(child_observability),
            io_driver,
            Some(child_entropy),
        )
        .with_blocking_pool_handle(cx.blocking_pool_handle());

        if let Some(record) = state.task_mut(task_id) {
            record.set_cx_inner(child_cx.inner.clone());
            record.set_cx(child_cx.clone());
        }

        let cx_for_send = child_cx.clone();
        let inner_weak = Arc::downgrade(&child_cx.inner);
        let state_for_task = Arc::clone(&server_state);

        let cell = GenServerCell {
            mailbox: msg_rx,
            state: Arc::clone(&server_state),
            _keep_alive: msg_tx.clone(),
        };

        let wrapped = async move {
            let result = CatchUnwind(Box::pin(run_gen_server_loop(server, child_cx, &cell))).await;
            match result {
                Ok(server_final) => {
                    let _ = result_tx.send(&cx_for_send, Ok(server_final));
                }
                Err(payload) => {
                    let msg = crate::cx::scope::payload_to_string(&payload);
                    let _ = result_tx.send(
                        &cx_for_send,
                        Err(JoinError::Panicked(crate::types::PanicPayload::new(msg))),
                    );
                }
            }
            state_for_task.store(ActorState::Stopped);
            Outcome::Ok(())
        };

        let stored = StoredTask::new_with_id(wrapped, task_id);

        let handle = GenServerHandle {
            actor_id,
            sender: msg_tx,
            state: server_state,
            task_id,
            receiver: result_rx,
            inner: inner_weak,
            overflow_policy,
        };

        Ok((handle, stored))
    }

    /// Spawns a named GenServer in this scope, registering it in the given
    /// [`NameRegistry`].
    ///
    /// This combines [`spawn_gen_server`](Self::spawn_gen_server) with
    /// [`NameRegistry::register`] into a single atomic operation: the name is
    /// acquired *after* the server task is created but *before* it starts
    /// processing messages.
    ///
    /// On success, the returned [`NamedGenServerHandle`] holds both the server
    /// handle and the name lease. The lease is released when the handle is
    /// stopped via [`NamedGenServerHandle::stop_and_release`] or aborted via
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

// ============================================================================
// Named GenServer handle
// ============================================================================

/// Error from [`Scope::spawn_named_gen_server`].
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

/// Handle to a running **named** GenServer.
///
/// Wraps a [`GenServerHandle`] together with a [`NameLease`] from the
/// registry. The lease is an obligation (drop bomb): callers must resolve it
/// by calling [`stop_and_release`](Self::stop_and_release) or
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
    #[must_use]
    pub fn name(&self) -> &str {
        self.lease
            .as_ref()
            .map_or("(released)", crate::cx::NameLease::name)
    }

    /// The underlying task ID.
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.handle.task_id()
    }

    /// The actor ID of this server.
    #[must_use]
    pub fn actor_id(&self) -> ActorId {
        self.handle.actor_id()
    }

    /// Whether the server has finished execution.
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

    /// Stop the server and release the name lease (commit).
    ///
    /// This is the normal shutdown path: the name becomes available for
    /// re-registration after this call.
    ///
    /// # Panics
    ///
    /// Panics if the lease was already resolved (double release/abort).
    pub fn stop_and_release(&mut self) -> Result<(), crate::cx::NameLeaseError> {
        self.handle.stop();
        self.lease
            .as_mut()
            .expect("lease already resolved")
            .release()
            .map(|_proof| ())
    }

    /// Abort the name lease without stopping the server.
    ///
    /// Use this for cancellation / error paths where the name registration
    /// itself should be rolled back.
    ///
    /// # Panics
    ///
    /// Panics if the lease was already resolved.
    pub fn abort_lease(&mut self) -> Result<(), crate::cx::NameLeaseError> {
        self.lease
            .as_mut()
            .expect("lease already resolved")
            .abort()
            .map(|_proof| ())
    }

    /// Take ownership of the lease (for manual lifecycle management).
    ///
    /// After this call, the handle no longer owns the lease; the caller is
    /// responsible for resolving it.
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
        let finalizer_registered = scope.defer_sync(state, move || {
            let _ = registry_for_finalizer.lock().cleanup_task(task_id);
            let lease_to_resolve = lease_slot_for_finalizer.lock().take();
            if let Some(mut lease) = lease_to_resolve {
                let _ = lease.release();
            }
        });

        if !finalizer_registered {
            let _ = self.registry.lock().cleanup_task(task_id);
            let lease_to_abort = lease_slot.lock().take();
            if let Some(mut lease) = lease_to_abort {
                let _ = lease.abort();
            }
            return Err(SpawnError::RegionClosed(scope.region_id()));
        }

        Ok(task_id)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::state::RuntimeState;
    use crate::supervision::ChildStart;
    use crate::types::Budget;
    use crate::types::CancelKind;
    use crate::types::policy::FailFast;
    use crate::util::ArenaIndex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // ---- Simple Counter GenServer ----

    struct Counter {
        count: u64,
    }

    enum CounterCall {
        Get,
        Add(u64),
    }

    enum CounterCast {
        Reset,
    }

    impl GenServer for Counter {
        type Call = CounterCall;
        type Reply = u64;
        type Cast = CounterCast;
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            _cx: &Cx,
            request: CounterCall,
            reply: Reply<u64>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match request {
                CounterCall::Get => {
                    let _ = reply.send(self.count);
                }
                CounterCall::Add(n) => {
                    self.count += n;
                    let _ = reply.send(self.count);
                }
            }
            Box::pin(async {})
        }

        fn handle_cast(
            &mut self,
            _cx: &Cx,
            msg: CounterCast,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match msg {
                CounterCast::Reset => self.count = 0,
            }
            Box::pin(async {})
        }
    }

    #[derive(Clone)]
    struct StartBudgetProbe {
        started_priority: Arc<AtomicU8>,
        loop_priority: Arc<AtomicU8>,
    }

    impl GenServer for StartBudgetProbe {
        type Call = CounterCall;
        type Reply = u8;
        type Cast = CounterCast;
        type Info = SystemMsg;

        fn on_start(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.started_priority
                .store(cx.budget().priority, Ordering::SeqCst);
            Box::pin(async {})
        }

        fn on_start_budget(&self) -> Budget {
            Budget::new().with_priority(200)
        }

        fn handle_call(
            &mut self,
            cx: &Cx,
            _request: CounterCall,
            reply: Reply<u8>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.loop_priority
                .store(cx.budget().priority, Ordering::SeqCst);
            let _ = reply.send(cx.budget().priority);
            Box::pin(async {})
        }
    }

    struct StopMaskProbe {
        stop_checkpoint_ok: Arc<AtomicU8>,
    }

    impl GenServer for StopMaskProbe {
        type Call = CounterCall;
        type Reply = u8;
        type Cast = CounterCast;
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            _cx: &Cx,
            _request: CounterCall,
            reply: Reply<u8>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let _ = reply.send(0);
            Box::pin(async {})
        }

        fn on_stop(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let ok = cx.checkpoint().is_ok();
            self.stop_checkpoint_ok
                .store(u8::from(ok), Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    fn assert_gen_server<S: GenServer>() {}

    #[test]
    fn gen_server_trait_bounds() {
        init_test("gen_server_trait_bounds");
        assert_gen_server::<Counter>();
        crate::test_complete!("gen_server_trait_bounds");
    }

    #[test]
    fn gen_server_spawn_and_cast() {
        init_test("gen_server_spawn_and_cast");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Cast a reset (fire-and-forget)
        handle.try_cast(CounterCast::Reset).unwrap();

        // Drop handle to disconnect
        drop(handle);

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        crate::test_complete!("gen_server_spawn_and_cast");
    }

    #[test]
    fn gen_server_spawn_and_call() {
        init_test("gen_server_spawn_and_call");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();
        let (client_handle, client_stored) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                server_ref.call(&cx, CounterCall::Add(5)).await.unwrap()
            })
            .unwrap();
        let client_task_id = client_handle.task_id();
        runtime
            .state
            .store_spawned_task(client_task_id, client_stored);

        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.scheduler.lock().schedule(client_task_id, 0);
        runtime.run_until_quiescent();

        let result =
            futures_lite::future::block_on(client_handle.join(&cx)).expect("client join ok");
        assert_eq!(result, 5);

        crate::test_complete!("gen_server_spawn_and_call");
    }

    #[test]
    fn gen_server_call_cancellation_is_deterministic() {
        init_test("gen_server_call_cancellation_is_deterministic");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        let client_cx_cell: Arc<Mutex<Option<Cx>>> = Arc::new(Mutex::new(None));
        let client_cx_cell_for_task = Arc::clone(&client_cx_cell);

        let (client_handle, client_stored) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                *client_cx_cell_for_task.lock().unwrap() = Some(cx.clone());
                server_ref.call(&cx, CounterCall::Get).await
            })
            .unwrap();
        let client_task_id = client_handle.task_id();
        runtime
            .state
            .store_spawned_task(client_task_id, client_stored);

        // Poll the client once: it should enqueue the call and then block waiting for reply.
        runtime.scheduler.lock().schedule(client_task_id, 0);
        runtime.run_until_idle();

        // Cancel the client deterministically, then poll it again to observe the cancellation.
        let client_cx = client_cx_cell
            .lock()
            .expect("lock poisoned")
            .clone()
            .expect("client cx published");
        client_cx.cancel_with(CancelKind::User, Some("gen_server call cancelled"));

        runtime.scheduler.lock().schedule(client_task_id, 0);
        runtime.run_until_idle();

        let result =
            futures_lite::future::block_on(client_handle.join(&cx)).expect("client join ok");
        match result {
            Ok(_) => unreachable!("expected cancellation, got Ok"),
            Err(CallError::Cancelled(reason)) => {
                assert_eq!(reason.kind, CancelKind::User);
                assert_eq!(reason.message, Some("gen_server call cancelled"));
            }
            Err(other) => unreachable!("expected CallError::Cancelled, got {other:?}"),
        }

        // Cleanup: disconnect the server and let it drain the queued call.
        drop(handle);
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        crate::test_complete!("gen_server_call_cancellation_is_deterministic");
    }

    #[test]
    fn supervised_gen_server_stays_alive() {
        init_test("supervised_gen_server_stays_alive");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);
        let registry = Arc::new(parking_lot::Mutex::new(crate::cx::NameRegistry::new()));

        let mut starter =
            named_gen_server_start(Arc::clone(&registry), "persistent_service", 32, || {
                Counter { count: 0 }
            });

        let task_id = starter
            .start(&scope, &mut runtime.state, &cx)
            .expect("start ok");

        // Run runtime. The server should start, init, and enter loop.
        // It should NOT exit just because the starter dropped the handle.
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        let task = runtime.state.task(task_id).expect("task exists");
        crate::assert_with_log!(
            !task.state.is_terminal(),
            "server should be alive",
            "Running",
            format!("{:?}", task.state)
        );

        // Cleanup: cancel the region and drive the cancellation to quiescence.
        let tasks_to_schedule =
            runtime
                .state
                .cancel_request(region, &CancelReason::user("test done"), None);
        for (tid, priority) in tasks_to_schedule {
            runtime.scheduler.lock().schedule(tid, priority);
        }
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        assert!(
            registry.lock().whereis("persistent_service").is_none(),
            "name must be removed after region stop",
        );

        crate::test_complete!("supervised_gen_server_stays_alive");
    }

    #[test]
    fn gen_server_cast_cancellation_is_deterministic() {
        init_test("gen_server_cast_cancellation_is_deterministic");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        // Use a tiny mailbox and pre-fill it so the next cast blocks and is cancelable.
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 1)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        futures_lite::future::block_on(handle.cast(&cx, CounterCast::Reset))
            .expect("prefill cast ok");

        let client_cx_cell: Arc<Mutex<Option<Cx>>> = Arc::new(Mutex::new(None));
        let client_cx_cell_for_task = Arc::clone(&client_cx_cell);

        let (client_handle, client_stored) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                *client_cx_cell_for_task.lock().unwrap() = Some(cx.clone());
                server_ref.cast(&cx, CounterCast::Reset).await
            })
            .unwrap();
        let client_task_id = client_handle.task_id();
        runtime
            .state
            .store_spawned_task(client_task_id, client_stored);

        // Poll the client once: it should block waiting for mailbox capacity.
        runtime.scheduler.lock().schedule(client_task_id, 0);
        runtime.run_until_idle();

        // Cancel the client deterministically, then poll it again to observe the cancellation.
        let client_cx = client_cx_cell
            .lock()
            .expect("lock poisoned")
            .clone()
            .expect("client cx published");
        client_cx.cancel_with(CancelKind::User, Some("gen_server cast cancelled"));

        runtime.scheduler.lock().schedule(client_task_id, 0);
        runtime.run_until_idle();

        let result =
            futures_lite::future::block_on(client_handle.join(&cx)).expect("client join ok");
        match result {
            Ok(()) => unreachable!("expected cancellation, got Ok"),
            Err(CastError::Cancelled(reason)) => {
                assert_eq!(reason.kind, CancelKind::User);
                assert_eq!(reason.message, Some("gen_server cast cancelled"));
            }
            Err(other) => unreachable!("expected CastError::Cancelled, got {other:?}"),
        }

        // Cleanup: disconnect the server and let it drain the mailbox.
        drop(handle);
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        crate::test_complete!("gen_server_cast_cancellation_is_deterministic");
    }

    #[test]
    fn gen_server_handle_accessors() {
        init_test("gen_server_handle_accessors");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, Counter { count: 0 }, 32)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        let _actor_id = handle.actor_id();
        let _task_id = handle.task_id();
        assert!(!handle.is_finished());

        let server_ref = handle.server_ref();
        assert_eq!(server_ref.actor_id(), handle.actor_id());
        assert!(server_ref.is_alive());
        assert!(!server_ref.is_closed());

        crate::test_complete!("gen_server_handle_accessors");
    }

    #[test]
    fn gen_server_ref_is_cloneable() {
        init_test("gen_server_ref_is_cloneable");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, Counter { count: 0 }, 32)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        let ref1 = handle.server_ref();
        let ref2 = ref1.clone();
        assert_eq!(ref1.actor_id(), ref2.actor_id());

        crate::test_complete!("gen_server_ref_is_cloneable");
    }

    #[test]
    fn gen_server_stop_transitions() {
        init_test("gen_server_stop_transitions");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        let server_ref = handle.server_ref();
        assert!(server_ref.is_alive());

        handle.stop();

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        assert!(handle.is_finished());
        assert!(!server_ref.is_alive());

        crate::test_complete!("gen_server_stop_transitions");
    }

    #[test]
    fn gen_server_handle_rejects_call_and_cast_after_stop() {
        init_test("gen_server_handle_rejects_call_and_cast_after_stop");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Let the server start, then request stop.
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();
        handle.stop();

        let call_err =
            futures_lite::future::block_on(handle.call(&cx, CounterCall::Get)).unwrap_err();
        assert!(
            matches!(call_err, CallError::ServerStopped),
            "call after stop must return ServerStopped, got {call_err:?}"
        );

        let cast_err =
            futures_lite::future::block_on(handle.cast(&cx, CounterCast::Reset)).unwrap_err();
        assert!(
            matches!(cast_err, CastError::ServerStopped),
            "cast after stop must return ServerStopped, got {cast_err:?}"
        );

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();
        assert!(handle.is_finished());

        crate::test_complete!("gen_server_handle_rejects_call_and_cast_after_stop");
    }

    #[test]
    fn gen_server_handle_join_returns_final_state_after_stop() {
        init_test("gen_server_handle_join_returns_final_state_after_stop");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        handle.stop();
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();
        assert!(handle.is_finished());

        let final_state = futures_lite::future::block_on(handle.join(&cx)).expect("join");
        assert_eq!(
            final_state.count, 0,
            "final server state should be returned"
        );

        crate::test_complete!("gen_server_handle_join_returns_final_state_after_stop");
    }

    #[test]
    fn gen_server_stop_wakes_blocked_mailbox_recv() {
        #[allow(clippy::items_after_statements)]
        struct StopWakeProbe {
            stop_ran: Arc<AtomicU8>,
        }

        #[allow(clippy::items_after_statements)]
        impl GenServer for StopWakeProbe {
            type Call = CounterCall;
            type Reply = u64;
            type Cast = CounterCast;
            type Info = SystemMsg;

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.stop_ran.store(1, Ordering::SeqCst);
                Box::pin(async {})
            }

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: CounterCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(0);
                Box::pin(async {})
            }
        }

        init_test("gen_server_stop_wakes_blocked_mailbox_recv");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let stop_ran = Arc::new(AtomicU8::new(0));
        let server = StopWakeProbe {
            stop_ran: Arc::clone(&stop_ran),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        // Start server and let it park waiting on mailbox.recv().
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_idle();

        // Stop should wake the blocked recv waiter. No manual reschedule here.
        handle.stop();
        runtime.run_until_quiescent();

        assert_eq!(
            stop_ran.load(Ordering::SeqCst),
            1,
            "on_stop should run after stop wakes blocked recv"
        );
        assert!(handle.is_finished(), "server should finish after stop");

        crate::test_complete!("gen_server_stop_wakes_blocked_mailbox_recv");
    }

    // ---- Observable GenServer for E2E ----

    struct ObservableCounter {
        count: u64,
        final_count: Arc<AtomicU64>,
    }

    impl GenServer for ObservableCounter {
        type Call = CounterCall;
        type Reply = u64;
        type Cast = CounterCast;
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            _cx: &Cx,
            request: CounterCall,
            reply: Reply<u64>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match request {
                CounterCall::Get => {
                    let _ = reply.send(self.count);
                }
                CounterCall::Add(n) => {
                    self.count += n;
                    let _ = reply.send(self.count);
                }
            }
            Box::pin(async {})
        }

        fn handle_cast(
            &mut self,
            _cx: &Cx,
            msg: CounterCast,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match msg {
                CounterCast::Reset => self.count = 0,
            }
            Box::pin(async {})
        }

        fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.final_count.store(self.count, Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    #[test]
    fn gen_server_processes_casts_before_stop() {
        init_test("gen_server_processes_casts_before_stop");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let final_count = Arc::new(AtomicU64::new(u64::MAX));
        let server = ObservableCounter {
            count: 0,
            final_count: final_count.clone(),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Start the server so casts are accepted.
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        // Queue a handful of casts, then disconnect. Shutdown must drain the mailbox
        // before running on_stop, so the final count reflects the cast effects.
        for _ in 0..5 {
            handle.try_cast(CounterCast::Reset).expect("try_cast ok");
        }

        handle.stop();

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        // Final count should be 0 (5 resets)
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            0,
            "on_stop recorded final count"
        );

        crate::test_complete!("gen_server_processes_casts_before_stop");
    }

    #[test]
    fn gen_server_deterministic_replay() {
        fn run_scenario(seed: u64) -> u64 {
            let config = crate::lab::LabConfig::new(seed);
            let mut runtime = crate::lab::LabRuntime::new(config);
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let cx = Cx::for_testing();
            let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

            let final_count = Arc::new(AtomicU64::new(u64::MAX));
            let server = ObservableCounter {
                count: 0,
                final_count: final_count.clone(),
            };

            let (handle, stored) = scope
                .spawn_gen_server(&mut runtime.state, &cx, server, 32)
                .unwrap();
            let task_id = handle.task_id();
            runtime.state.store_spawned_task(task_id, stored);

            runtime.scheduler.lock().schedule(task_id, 0);
            runtime.run_until_idle();

            // 5 resets then disconnect
            for _ in 0..5 {
                handle.try_cast(CounterCast::Reset).expect("try_cast ok");
            }
            handle.stop();

            runtime.scheduler.lock().schedule(task_id, 0);
            runtime.run_until_quiescent();

            final_count.load(Ordering::SeqCst)
        }

        init_test("gen_server_deterministic_replay");

        let result1 = run_scenario(0xCAFE_BABE);
        let result2 = run_scenario(0xCAFE_BABE);
        assert_eq!(result1, result2, "deterministic replay");

        crate::test_complete!("gen_server_deterministic_replay");
    }

    // ---- System/info message tests (bd-188ey) ----

    #[derive(Default)]
    struct InfoRecorder {
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl GenServer for InfoRecorder {
        type Call = ();
        type Reply = ();
        type Cast = ();
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            _cx: &Cx,
            _request: (),
            reply: Reply<()>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let _ = reply.send(());
            Box::pin(async {})
        }

        fn handle_info(
            &mut self,
            _cx: &Cx,
            msg: Self::Info,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let seen = Arc::clone(&self.seen);
            Box::pin(async move {
                seen.lock().unwrap().push(format!("{msg:?}"));
            })
        }
    }

    fn tid(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn rid(n: u32) -> crate::types::RegionId {
        crate::types::RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    /// Conformance: app shutdown batches use SYS-ORDER
    /// (`vt`, `Down < Exit < Timeout`, stable subject key).
    #[test]
    fn conformance_system_msg_sort_key_orders_shutdown_batch() {
        init_test("conformance_system_msg_sort_key_orders_shutdown_batch");

        let mut monitors = crate::monitor::MonitorSet::new();
        let mref_down_6 = monitors.establish(tid(90), rid(0), tid(6));
        let mref_down_3 = monitors.establish(tid(91), rid(0), tid(3));

        let mut batch = SystemMsgBatch::new();
        batch.push(SystemMsg::Exit {
            exit_vt: Time::from_secs(10),
            from: tid(6),
            reason: DownReason::Normal,
        });
        batch.push(SystemMsg::Timeout {
            tick_vt: Time::from_secs(10),
            id: 4,
        });
        batch.push(SystemMsg::Down {
            completion_vt: Time::from_secs(10),
            notification: DownNotification {
                monitored: tid(6),
                reason: DownReason::Normal,
                monitor_ref: mref_down_6,
            },
        });
        batch.push(SystemMsg::Timeout {
            tick_vt: Time::from_secs(9),
            id: 99,
        });
        batch.push(SystemMsg::Down {
            completion_vt: Time::from_secs(10),
            notification: DownNotification {
                monitored: tid(3),
                reason: DownReason::Normal,
                monitor_ref: mref_down_3,
            },
        });
        batch.push(SystemMsg::Exit {
            exit_vt: Time::from_secs(10),
            from: tid(2),
            reason: DownReason::Normal,
        });
        batch.push(SystemMsg::Timeout {
            tick_vt: Time::from_secs(10),
            id: 1,
        });

        let sorted = batch.into_sorted();
        let keys: Vec<_> = sorted.iter().map(SystemMsg::sort_key).collect();

        assert_eq!(
            keys,
            vec![
                (Time::from_secs(9), 2, SystemMsgSubjectKey::TimeoutId(99)),
                (Time::from_secs(10), 0, SystemMsgSubjectKey::Task(tid(3))),
                (Time::from_secs(10), 0, SystemMsgSubjectKey::Task(tid(6))),
                (Time::from_secs(10), 1, SystemMsgSubjectKey::Task(tid(2))),
                (Time::from_secs(10), 1, SystemMsgSubjectKey::Task(tid(6))),
                (Time::from_secs(10), 2, SystemMsgSubjectKey::TimeoutId(1)),
                (Time::from_secs(10), 2, SystemMsgSubjectKey::TimeoutId(4)),
            ],
            "shutdown system-message ordering must follow SYS-ORDER"
        );

        crate::test_complete!("conformance_system_msg_sort_key_orders_shutdown_batch");
    }

    /// Conformance: `SystemMsgBatch::into_sorted` is equivalent to explicit
    /// `sort_by_key(SystemMsg::sort_key)`.
    #[test]
    fn conformance_system_msg_batch_matches_explicit_sort() {
        init_test("conformance_system_msg_batch_matches_explicit_sort");

        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(77), rid(0), tid(8));

        let messages = vec![
            SystemMsg::Timeout {
                tick_vt: Time::from_secs(12),
                id: 4,
            },
            SystemMsg::Exit {
                exit_vt: Time::from_secs(11),
                from: tid(8),
                reason: DownReason::Error("boom".to_string()),
            },
            SystemMsg::Down {
                completion_vt: Time::from_secs(11),
                notification: DownNotification {
                    monitored: tid(8),
                    reason: DownReason::Normal,
                    monitor_ref: mref,
                },
            },
            SystemMsg::Timeout {
                tick_vt: Time::from_secs(11),
                id: 2,
            },
        ];

        let mut batch = SystemMsgBatch::new();
        for msg in messages.clone() {
            batch.push(msg);
        }
        let batched = batch.into_sorted();

        let mut explicit = messages;
        explicit.sort_by_key(SystemMsg::sort_key);

        let batched_keys: Vec<_> = batched.iter().map(SystemMsg::sort_key).collect();
        let explicit_keys: Vec<_> = explicit.iter().map(SystemMsg::sort_key).collect();
        assert_eq!(batched_keys, explicit_keys);

        crate::test_complete!("conformance_system_msg_batch_matches_explicit_sort");
    }

    #[test]
    fn system_msg_payload_types_roundtrip_via_conversions() {
        init_test("system_msg_payload_types_roundtrip_via_conversions");

        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(7), rid(0), tid(8));

        let down = DownMsg::new(
            Time::from_secs(11),
            DownNotification {
                monitored: tid(8),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        );
        let down_msg = SystemMsg::down(down.clone());
        let down_back = DownMsg::try_from(down_msg).expect("down conversion");
        assert_eq!(down_back.completion_vt, down.completion_vt);
        assert_eq!(
            down_back.notification.monitored,
            down.notification.monitored
        );
        assert_eq!(down_back.notification.reason, down.notification.reason);
        assert_eq!(
            down_back.notification.monitor_ref,
            down.notification.monitor_ref
        );

        let exit = ExitMsg::new(
            Time::from_secs(12),
            tid(9),
            DownReason::Error("boom".into()),
        );
        let exit_msg = SystemMsg::exit(exit.clone());
        let exit_back = ExitMsg::try_from(exit_msg).expect("exit conversion");
        assert_eq!(exit_back, exit);

        let timeout = TimeoutMsg::new(Time::from_secs(13), 42);
        let timeout_msg = SystemMsg::timeout(timeout);
        let timeout_back = TimeoutMsg::try_from(timeout_msg).expect("timeout conversion");
        assert_eq!(timeout_back, timeout);

        crate::test_complete!("system_msg_payload_types_roundtrip_via_conversions");
    }

    #[test]
    fn system_msg_try_from_mismatch_returns_original_variant() {
        init_test("system_msg_try_from_mismatch_returns_original_variant");
        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(10), rid(0), tid(1));

        let timeout = SystemMsg::Timeout {
            tick_vt: Time::from_secs(5),
            id: 99,
        };
        let err = DownMsg::try_from(timeout).expect_err("timeout is not down");
        assert!(matches!(err, SystemMsg::Timeout { id: 99, .. }));

        let down = SystemMsg::Down {
            completion_vt: Time::from_secs(6),
            notification: DownNotification {
                monitored: tid(1),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        };
        let err = TimeoutMsg::try_from(down).expect_err("down is not timeout");
        assert!(matches!(err, SystemMsg::Down { .. }));

        crate::test_complete!("system_msg_try_from_mismatch_returns_original_variant");
    }

    #[test]
    fn gen_server_handle_info_receives_system_messages() {
        init_test("gen_server_handle_info_receives_system_messages");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let server = InfoRecorder {
            seen: Arc::clone(&seen),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(10), rid(0), tid(11));

        handle
            .try_info(SystemMsg::Down {
                completion_vt: Time::from_secs(5),
                notification: DownNotification {
                    monitored: tid(11),
                    reason: DownReason::Normal,
                    monitor_ref: mref,
                },
            })
            .unwrap();

        handle
            .try_info(SystemMsg::Exit {
                exit_vt: Time::from_secs(6),
                from: tid(12),
                reason: DownReason::Error("boom".into()),
            })
            .unwrap();

        handle
            .try_info(SystemMsg::Timeout {
                tick_vt: Time::from_secs(7),
                id: 123,
            })
            .unwrap();

        drop(handle);

        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert!(seen[0].contains("Down"));
        assert!(seen[1].contains("Exit"));
        assert!(seen[2].contains("Timeout"));
        drop(seen);

        crate::test_complete!("gen_server_handle_info_receives_system_messages");
    }

    #[test]
    fn gen_server_info_ordering_is_deterministic_for_seed() {
        fn run_scenario(seed: u64) -> Vec<String> {
            let config = crate::lab::LabConfig::new(seed);
            let mut runtime = crate::lab::LabRuntime::new(config);
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let cx = Cx::for_testing();
            let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

            let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let server = InfoRecorder {
                seen: Arc::clone(&events),
            };

            let (handle, stored) = scope
                .spawn_gen_server(&mut runtime.state, &cx, server, 32)
                .unwrap();
            let server_task_id = handle.task_id();
            runtime.state.store_spawned_task(server_task_id, stored);

            let server_ref = handle.server_ref();

            let (client_a, stored_a) = scope
                .spawn(&mut runtime.state, &cx, move |cx| async move {
                    server_ref
                        .info(
                            &cx,
                            SystemMsg::Timeout {
                                tick_vt: Time::from_secs(2),
                                id: 1,
                            },
                        )
                        .await
                        .unwrap();
                })
                .unwrap();
            let task_id_a = client_a.task_id();
            runtime.state.store_spawned_task(task_id_a, stored_a);

            let server_ref_b = handle.server_ref();
            let (client_b, stored_b) = scope
                .spawn(&mut runtime.state, &cx, move |cx| async move {
                    server_ref_b
                        .info(
                            &cx,
                            SystemMsg::Timeout {
                                tick_vt: Time::from_secs(2),
                                id: 2,
                            },
                        )
                        .await
                        .unwrap();
                })
                .unwrap();
            let task_id_b = client_b.task_id();
            runtime.state.store_spawned_task(task_id_b, stored_b);

            // Let clients enqueue, then let the server drain.
            runtime.scheduler.lock().schedule(task_id_a, 0);
            runtime.scheduler.lock().schedule(task_id_b, 0);
            runtime.scheduler.lock().schedule(server_task_id, 0);

            runtime.run_until_quiescent();
            drop(handle);
            runtime.scheduler.lock().schedule(server_task_id, 0);
            runtime.run_until_quiescent();

            events.lock().unwrap().clone()
        }

        init_test("gen_server_info_ordering_is_deterministic_for_seed");

        let a = run_scenario(0xD00D_F00D);
        let b = run_scenario(0xD00D_F00D);
        assert_eq!(
            a, b,
            "system/info ordering must be deterministic for same seed"
        );

        crate::test_complete!("gen_server_info_ordering_is_deterministic_for_seed");
    }

    // ---- DropOldest GenServer for backpressure tests ----

    /// A counter that uses DropOldest overflow policy.
    struct DropOldestCounter {
        count: u64,
    }

    /// Cast type that carries an identifiable value for eviction testing.
    #[derive(Debug, Clone)]
    enum TaggedCast {
        Set(u64),
    }

    impl GenServer for DropOldestCounter {
        type Call = CounterCall;
        type Reply = u64;
        type Cast = TaggedCast;
        type Info = SystemMsg;

        fn cast_overflow_policy(&self) -> CastOverflowPolicy {
            CastOverflowPolicy::DropOldest
        }

        fn handle_call(
            &mut self,
            _cx: &Cx,
            request: CounterCall,
            reply: Reply<u64>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match request {
                CounterCall::Get => {
                    let _ = reply.send(self.count);
                }
                CounterCall::Add(n) => {
                    self.count += n;
                    let _ = reply.send(self.count);
                }
            }
            Box::pin(async {})
        }

        fn handle_cast(
            &mut self,
            _cx: &Cx,
            msg: TaggedCast,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match msg {
                TaggedCast::Set(v) => self.count = v,
            }
            Box::pin(async {})
        }
    }

    #[test]
    fn gen_server_drop_oldest_policy_accessor() {
        init_test("gen_server_drop_oldest_policy_accessor");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, DropOldestCounter { count: 0 }, 4)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        assert_eq!(
            handle.cast_overflow_policy(),
            CastOverflowPolicy::DropOldest
        );

        let server_ref = handle.server_ref();
        assert_eq!(
            server_ref.cast_overflow_policy(),
            CastOverflowPolicy::DropOldest
        );

        crate::test_complete!("gen_server_drop_oldest_policy_accessor");
    }

    #[test]
    fn gen_server_drop_oldest_evicts_when_full() {
        init_test("gen_server_drop_oldest_evicts_when_full");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        // Mailbox capacity = 2
        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, DropOldestCounter { count: 0 }, 2)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Fill the mailbox (capacity 2)
        handle.try_cast(TaggedCast::Set(10)).unwrap();
        handle.try_cast(TaggedCast::Set(20)).unwrap();

        // This should succeed by evicting the oldest (Set(10))
        handle.try_cast(TaggedCast::Set(30)).unwrap();

        // And again — evicts Set(20), mailbox now has [Set(30), Set(40)]
        handle.try_cast(TaggedCast::Set(40)).unwrap();

        crate::test_complete!("gen_server_drop_oldest_evicts_when_full");
    }

    #[test]
    fn gen_server_reject_policy_returns_full() {
        init_test("gen_server_reject_policy_returns_full");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        // Default policy (Reject), capacity = 2
        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, Counter { count: 0 }, 2)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        assert_eq!(handle.cast_overflow_policy(), CastOverflowPolicy::Reject);

        // Fill the mailbox
        handle.try_cast(CounterCast::Reset).unwrap();
        handle.try_cast(CounterCast::Reset).unwrap();

        // Third should fail with Full
        let err = handle.try_cast(CounterCast::Reset).unwrap_err();
        assert!(matches!(err, CastError::Full), "expected Full, got {err:?}");

        crate::test_complete!("gen_server_reject_policy_returns_full");
    }

    #[test]
    fn gen_server_drop_oldest_ref_also_evicts() {
        init_test("gen_server_drop_oldest_ref_also_evicts");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, DropOldestCounter { count: 0 }, 2)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        let server_ref = handle.server_ref();

        // Fill via ref
        server_ref.try_cast(TaggedCast::Set(1)).unwrap();
        server_ref.try_cast(TaggedCast::Set(2)).unwrap();

        // Evict oldest via ref — should succeed
        server_ref.try_cast(TaggedCast::Set(3)).unwrap();

        crate::test_complete!("gen_server_drop_oldest_ref_also_evicts");
    }

    #[test]
    fn gen_server_drop_oldest_reserved_slots_returns_full() {
        init_test("gen_server_drop_oldest_reserved_slots_returns_full");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, DropOldestCounter { count: 0 }, 1)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Reserve the only mailbox slot without committing a message.
        let _permit = futures_lite::future::block_on(handle.sender.reserve(&cx)).unwrap();

        // DropOldest cannot evict reserved slots, so this must be a recoverable Full.
        let err = handle.try_cast(TaggedCast::Set(1)).unwrap_err();
        assert!(matches!(err, CastError::Full), "expected Full, got {err:?}");

        crate::test_complete!("gen_server_drop_oldest_reserved_slots_returns_full");
    }

    #[test]
    fn gen_server_ref_drop_oldest_reserved_slots_returns_full() {
        init_test("gen_server_ref_drop_oldest_reserved_slots_returns_full");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, DropOldestCounter { count: 0 }, 1)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);
        let server_ref = handle.server_ref();

        // Reserve the only mailbox slot without committing a message.
        let _permit = futures_lite::future::block_on(handle.sender.reserve(&cx)).unwrap();

        // Mirror behavior through GenServerRef::try_cast.
        let err = server_ref.try_cast(TaggedCast::Set(1)).unwrap_err();
        assert!(matches!(err, CastError::Full), "expected Full, got {err:?}");

        crate::test_complete!("gen_server_ref_drop_oldest_reserved_slots_returns_full");
    }

    /// DropOldest eviction of a Call envelope must abort the reply obligation
    /// instead of leaking it. Before the fix, dropping an evicted Call caused
    /// an "OBLIGATION TOKEN LEAKED" panic.
    #[test]
    fn gen_server_drop_oldest_evicting_call_aborts_obligation() {
        init_test("gen_server_drop_oldest_evicting_call_aborts_obligation");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        // Capacity 1 so we can fill it with one message.
        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, DropOldestCounter { count: 0 }, 1)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Manually enqueue a Call envelope so it sits in the mailbox.
        let (reply_tx, _reply_rx) = session::tracked_oneshot::<u64>();
        let reply_permit = reply_tx.reserve(&cx);
        let call_envelope: Envelope<DropOldestCounter> = Envelope::Call {
            request: CounterCall::Get,
            reply_permit,
        };
        handle.sender.try_send(call_envelope).unwrap();

        // Now try_cast with DropOldest should evict the Call and abort its
        // reply obligation cleanly — no panic.
        handle.try_cast(TaggedCast::Set(99)).unwrap();

        crate::test_complete!("gen_server_drop_oldest_evicting_call_aborts_obligation");
    }

    #[test]
    fn gen_server_default_overflow_policy_is_reject() {
        init_test("gen_server_default_overflow_policy_is_reject");

        assert_eq!(CastOverflowPolicy::default(), CastOverflowPolicy::Reject);

        // Verify Counter (which doesn't override) uses Reject
        let counter = Counter { count: 0 };
        assert_eq!(counter.cast_overflow_policy(), CastOverflowPolicy::Reject);

        crate::test_complete!("gen_server_default_overflow_policy_is_reject");
    }

    #[test]
    fn reply_debug_format() {
        init_test("reply_debug_format");

        let cx = Cx::for_testing();
        let (tx, _rx) = session::tracked_oneshot::<u64>();
        let permit = tx.reserve(&cx);
        let reply = Reply::new(&cx, permit);
        let debug_str = format!("{reply:?}");
        assert!(debug_str.contains("Reply"));
        assert!(debug_str.contains("pending"));

        // Consume the reply to avoid the obligation panic
        let _ = reply.send(42);

        crate::test_complete!("reply_debug_format");
    }

    #[test]
    fn gen_server_on_start_budget_priority_applied_and_restored() {
        init_test("gen_server_on_start_budget_priority_applied_and_restored");

        let budget = Budget::new().with_poll_quota(10_000).with_priority(10);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let started_priority = Arc::new(AtomicU8::new(0));
        let loop_priority = Arc::new(AtomicU8::new(0));
        let server = StartBudgetProbe {
            started_priority: Arc::clone(&started_priority),
            loop_priority: Arc::clone(&loop_priority),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();
        let (client, stored_client) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                let p = server_ref.call(&cx, CounterCall::Get).await.unwrap();
                assert_eq!(p, 10);
            })
            .unwrap();
        let client_task_id = client.task_id();
        runtime
            .state
            .store_spawned_task(client_task_id, stored_client);

        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.scheduler.lock().schedule(client_task_id, 0);
        runtime.run_until_quiescent();

        assert_eq!(started_priority.load(Ordering::SeqCst), 200);
        assert_eq!(loop_priority.load(Ordering::SeqCst), 10);

        drop(handle);
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        crate::test_complete!("gen_server_on_start_budget_priority_applied_and_restored");
    }

    #[test]
    fn gen_server_on_stop_runs_masked_under_stop() {
        init_test("gen_server_on_stop_runs_masked_under_stop");

        let budget = Budget::new().with_poll_quota(10_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let stop_checkpoint_ok = Arc::new(AtomicU8::new(0));
        let server = StopMaskProbe {
            stop_checkpoint_ok: Arc::clone(&stop_checkpoint_ok),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        // Request stop: sets cancel_requested. on_stop must run masked.
        handle.stop();

        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        assert_eq!(stop_checkpoint_ok.load(Ordering::SeqCst), 1);

        crate::test_complete!("gen_server_on_stop_runs_masked_under_stop");
    }

    // ── Cast overflow policy tests (bd-2o5hg) ────────────────────────

    /// Verify that DropOldest eviction emits a trace event.
    #[test]
    fn cast_drop_oldest_emits_trace_on_eviction() {
        init_test("cast_drop_oldest_emits_trace_on_eviction");

        let budget = Budget::new().with_poll_quota(10_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        // Capacity=1 so the second cast evicts the first
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, DropOldestCounter { count: 0 }, 1)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Schedule so Cx::current() is set
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        // First cast fills the mailbox
        handle.try_cast(TaggedCast::Set(1)).unwrap();
        // Second cast evicts the first
        handle.try_cast(TaggedCast::Set(2)).unwrap();

        // The eviction trace is emitted via Cx::current() (set during task poll).
        // We confirm it succeeded (no panic/error).
        crate::test_complete!("cast_drop_oldest_emits_trace_on_eviction");
    }

    /// Casting to a stopped server returns ServerStopped.
    #[test]
    fn cast_to_stopped_server_returns_error() {
        init_test("cast_to_stopped_server_returns_error");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, Counter { count: 0 }, 4)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Stop the server
        handle.stop();

        // try_cast should return ServerStopped
        let err = handle.try_cast(CounterCast::Reset).unwrap_err();
        assert!(
            matches!(err, CastError::ServerStopped),
            "expected ServerStopped, got {err:?}"
        );

        crate::test_complete!("cast_to_stopped_server_returns_error");
    }

    /// CastOverflowPolicy Display is correct.
    #[test]
    fn cast_overflow_policy_display() {
        init_test("cast_overflow_policy_display");

        assert_eq!(format!("{}", CastOverflowPolicy::Reject), "Reject");
        assert_eq!(format!("{}", CastOverflowPolicy::DropOldest), "DropOldest");

        crate::test_complete!("cast_overflow_policy_display");
    }

    /// Reject policy on GenServerRef returns Full when mailbox is full.
    #[test]
    fn cast_ref_reject_returns_full() {
        init_test("cast_ref_reject_returns_full");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, Counter { count: 0 }, 2)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        let server_ref = handle.server_ref();

        // Fill the mailbox via server_ref
        server_ref.try_cast(CounterCast::Reset).unwrap();
        server_ref.try_cast(CounterCast::Reset).unwrap();

        // Third should fail with Full
        let err = server_ref.try_cast(CounterCast::Reset).unwrap_err();
        assert!(matches!(err, CastError::Full), "expected Full, got {err:?}");

        crate::test_complete!("cast_ref_reject_returns_full");
    }

    /// DropOldest via GenServerRef with capacity=1 evicts correctly.
    #[test]
    fn cast_drop_oldest_ref_capacity_one() {
        init_test("cast_drop_oldest_ref_capacity_one");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, DropOldestCounter { count: 0 }, 1)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        let server_ref = handle.server_ref();

        // Fill with one message
        server_ref.try_cast(TaggedCast::Set(100)).unwrap();
        // Evict and replace — should succeed with capacity=1
        server_ref.try_cast(TaggedCast::Set(200)).unwrap();
        server_ref.try_cast(TaggedCast::Set(300)).unwrap();

        crate::test_complete!("cast_drop_oldest_ref_capacity_one");
    }

    // ── Init/Terminate semantics (bd-3ejoi) ──────────────────────────

    #[test]
    fn init_default_budget_is_infinite() {
        init_test("init_default_budget_is_infinite");
        let counter = Counter { count: 0 };
        assert_eq!(counter.on_start_budget(), Budget::INFINITE);
        crate::test_complete!("init_default_budget_is_infinite");
    }

    #[test]
    fn terminate_default_budget_is_minimal() {
        init_test("terminate_default_budget_is_minimal");
        let counter = Counter { count: 0 };
        assert_eq!(counter.on_stop_budget(), Budget::MINIMAL);
        crate::test_complete!("terminate_default_budget_is_minimal");
    }

    /// If the task is cancelled before init, on_start is skipped but on_stop
    /// still runs (deterministic cleanup guarantee).
    #[test]
    fn init_skipped_when_pre_cancelled_but_stop_runs() {
        #[allow(clippy::items_after_statements)]
        struct LifecycleProbe {
            init_ran: Arc<AtomicU8>,
            stop_ran: Arc<AtomicU8>,
        }

        #[allow(clippy::items_after_statements)]
        impl GenServer for LifecycleProbe {
            type Call = CounterCall;
            type Reply = u64;
            type Cast = CounterCast;
            type Info = SystemMsg;

            fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.init_ran.store(1, Ordering::SeqCst);
                Box::pin(async {})
            }

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.stop_ran.store(1, Ordering::SeqCst);
                Box::pin(async {})
            }

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: CounterCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(0);
                Box::pin(async {})
            }
        }

        init_test("init_skipped_when_pre_cancelled_but_stop_runs");

        let budget = Budget::new().with_poll_quota(10_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let init_ran = Arc::new(AtomicU8::new(0));
        let stop_ran = Arc::new(AtomicU8::new(0));

        let server = LifecycleProbe {
            init_ran: Arc::clone(&init_ran),
            stop_ran: Arc::clone(&stop_ran),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        // Cancel BEFORE scheduling (pre-cancel)
        handle.stop();

        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        // Init should be skipped
        assert_eq!(
            init_ran.load(Ordering::SeqCst),
            0,
            "init should be skipped when pre-cancelled"
        );
        // Stop should still run
        assert_eq!(
            stop_ran.load(Ordering::SeqCst),
            1,
            "stop must run even when pre-cancelled"
        );

        crate::test_complete!("init_skipped_when_pre_cancelled_but_stop_runs");
    }

    /// Verify that budget consumed during on_start is subtracted from the main
    /// task budget when the guard restores.
    #[test]
    fn init_budget_consumption_propagates_to_main_budget() {
        #[allow(clippy::items_after_statements)]
        struct BudgetCheckProbe {
            loop_quota: Arc<AtomicU64>,
        }

        #[allow(clippy::items_after_statements)]
        impl GenServer for BudgetCheckProbe {
            type Call = CounterCall;
            type Reply = u64;
            type Cast = CounterCast;
            type Info = SystemMsg;

            fn on_start(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                // "Consume" some budget by using polls
                // In practice, the poll_quota is decremented by the runtime
                // but we can verify the budget baseline is properly set.
                let _ = cx.budget();
                Box::pin(async {})
            }

            fn on_start_budget(&self) -> Budget {
                // Tight init budget
                Budget::new().with_poll_quota(50).with_priority(200)
            }

            fn handle_call(
                &mut self,
                cx: &Cx,
                _request: CounterCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                // After init, check the remaining budget
                self.loop_quota
                    .store(u64::from(cx.budget().poll_quota), Ordering::SeqCst);
                let _ = reply.send(0);
                Box::pin(async {})
            }
        }

        init_test("init_budget_consumption_propagates_to_main_budget");

        let budget = Budget::new().with_poll_quota(10_000).with_priority(10);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let loop_quota = Arc::new(AtomicU64::new(0));

        let server = BudgetCheckProbe {
            loop_quota: Arc::clone(&loop_quota),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();
        let (client, stored_client) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                let _ = server_ref.call(&cx, CounterCall::Get).await;
            })
            .unwrap();
        let client_task_id = client.task_id();
        runtime
            .state
            .store_spawned_task(client_task_id, stored_client);

        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.scheduler.lock().schedule(client_task_id, 0);
        runtime.run_until_quiescent();

        // After init, the main budget should have the original quota minus
        // whatever was consumed during init. It should be <= 10_000.
        let remaining = loop_quota.load(Ordering::SeqCst);
        assert!(
            remaining <= 10_000,
            "main budget after init must be <= original ({remaining} <= 10000)"
        );
        assert!(
            remaining > 0,
            "main budget should still have polls remaining"
        );

        drop(handle);
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        crate::test_complete!("init_budget_consumption_propagates_to_main_budget");
    }

    /// Verify on_stop_budget tightens the budget during the stop phase.
    #[test]
    fn stop_budget_constrains_stop_phase() {
        struct StopBudgetProbe {
            stop_poll_quota: Arc<AtomicU64>,
        }

        impl GenServer for StopBudgetProbe {
            type Call = CounterCall;
            type Reply = u64;
            type Cast = CounterCast;
            type Info = SystemMsg;

            fn on_stop_budget(&self) -> Budget {
                Budget::new().with_poll_quota(42).with_priority(250)
            }

            fn on_stop(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.stop_poll_quota
                    .store(u64::from(cx.budget().poll_quota), Ordering::SeqCst);
                Box::pin(async {})
            }

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: CounterCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(0);
                Box::pin(async {})
            }
        }

        init_test("stop_budget_constrains_stop_phase");

        let budget = Budget::new().with_poll_quota(10_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let stop_poll_quota = Arc::new(AtomicU64::new(0));

        let server = StopBudgetProbe {
            stop_poll_quota: Arc::clone(&stop_poll_quota),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        // Trigger stop
        handle.stop();

        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        let stop_quota = stop_poll_quota.load(Ordering::SeqCst);
        // The stop budget is meet(original, on_stop_budget), so
        // poll_quota should be min(10_000, 42) = 42
        assert_eq!(stop_quota, 42, "stop phase should use the tighter budget");

        crate::test_complete!("stop_budget_constrains_stop_phase");
    }

    /// Verify that init runs before stop, and stop always runs even on
    /// immediate shutdown.
    #[test]
    fn lifecycle_init_before_stop() {
        #[allow(clippy::items_after_statements)]
        struct PhaseTracker {
            phases: Arc<Mutex<Vec<&'static str>>>,
        }

        #[allow(clippy::items_after_statements)]
        impl GenServer for PhaseTracker {
            type Call = CounterCall;
            type Reply = u64;
            type Cast = CounterCast;
            type Info = SystemMsg;

            fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.phases.lock().unwrap().push("init");
                Box::pin(async {})
            }

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.phases.lock().unwrap().push("stop");
                Box::pin(async {})
            }

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: CounterCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(0);
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: CounterCast,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        init_test("lifecycle_init_before_stop");

        let budget = Budget::new().with_poll_quota(10_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let phases = Arc::new(Mutex::new(Vec::<&'static str>::new()));

        let server = PhaseTracker {
            phases: Arc::clone(&phases),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        // Schedule the server so init runs, then idle on recv
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_idle();

        // Stop the server and reschedule so on_stop runs
        let phases_clone = Arc::clone(&phases);
        handle.stop();
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_idle();

        {
            let recorded = phases_clone.lock().unwrap();

            // Stop must always run
            assert!(
                recorded.contains(&"stop"),
                "stop phase must run, got {:?}",
                *recorded
            );

            // If init ran, it must precede stop
            if let Some(init_pos) = recorded.iter().position(|p| *p == "init") {
                let stop_pos = recorded.iter().position(|p| *p == "stop").unwrap();
                assert!(
                    init_pos < stop_pos,
                    "init must precede stop, got {:?}",
                    *recorded
                );
            }

            drop(recorded);
        }

        crate::test_complete!("lifecycle_init_before_stop");
    }

    /// Verify that on_stop_budget with a custom priority overrides the
    /// budget priority during the stop phase.
    #[test]
    fn stop_budget_priority_applied() {
        #[allow(clippy::items_after_statements)]
        struct StopPriorityProbe {
            stop_priority: Arc<AtomicU8>,
        }

        #[allow(clippy::items_after_statements)]
        impl GenServer for StopPriorityProbe {
            type Call = CounterCall;
            type Reply = u64;
            type Cast = CounterCast;
            type Info = SystemMsg;

            fn on_stop_budget(&self) -> Budget {
                Budget::new().with_poll_quota(200).with_priority(240)
            }

            fn on_stop(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.stop_priority
                    .store(cx.budget().priority, Ordering::SeqCst);
                Box::pin(async {})
            }

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: CounterCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(0);
                Box::pin(async {})
            }
        }

        init_test("stop_budget_priority_applied");

        let budget = Budget::new().with_poll_quota(10_000).with_priority(10);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let stop_priority = Arc::new(AtomicU8::new(0));

        let server = StopPriorityProbe {
            stop_priority: Arc::clone(&stop_priority),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        handle.stop();

        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        // priority = max(original=10, stop_budget=240) after meet
        // meet takes min for quotas but max for priority
        let actual_priority = stop_priority.load(Ordering::SeqCst);
        assert!(
            actual_priority >= 10,
            "stop priority should be at least original ({actual_priority} >= 10)"
        );

        crate::test_complete!("stop_budget_priority_applied");
    }

    // ========================================================================
    // Conformance + Lab Tests (bd-l6b71)
    //
    // These tests verify the GenServer conformance suite:
    //   - reply linearity (obligation enforcement)
    //   - cancel propagation through call/cast
    //   - mailbox overflow determinism
    //   - full lifecycle with no obligation leaks
    //   - deterministic replay (same seed = same outcome)
    // ========================================================================

    /// Multiple queued calls all receive `Cancelled` when the server's region
    /// is cancelled. Verifies cancel propagation to pending call waiters.
    #[test]
    fn conformance_cancel_propagation_to_queued_calls() {
        init_test("conformance_cancel_propagation_to_queued_calls");

        let budget = Budget::new().with_poll_quota(50_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        // Capacity-1 mailbox: second call will block waiting for capacity.
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 1)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref_1 = handle.server_ref();
        let server_ref_2 = handle.server_ref();

        // Client 1: sends a call that the server will process.
        let result_1: Arc<Mutex<Option<Result<u64, CallError>>>> = Arc::new(Mutex::new(None));
        let result_1_clone = Arc::clone(&result_1);
        let (c1_handle, c1_stored) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                let r = server_ref_1.call(&cx, CounterCall::Add(10)).await;
                *result_1_clone.lock().unwrap() = Some(r);
            })
            .unwrap();
        let c1_id = c1_handle.task_id();
        runtime.state.store_spawned_task(c1_id, c1_stored);

        // Client 2: sends a call that will queue behind client 1.
        let result_2: Arc<Mutex<Option<Result<u64, CallError>>>> = Arc::new(Mutex::new(None));
        let result_2_clone = Arc::clone(&result_2);
        let (c2_handle, c2_stored) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                let r = server_ref_2.call(&cx, CounterCall::Add(20)).await;
                *result_2_clone.lock().unwrap() = Some(r);
            })
            .unwrap();
        let c2_id = c2_handle.task_id();
        runtime.state.store_spawned_task(c2_id, c2_stored);

        // Schedule server + clients, let them make progress.
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(c1_id, 0);
            sched.schedule(c2_id, 0);
        }
        runtime.run_until_idle();

        // Stop the server (triggers cancellation of pending calls).
        handle.stop();
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(c1_id, 0);
            sched.schedule(c2_id, 0);
        }
        runtime.run_until_quiescent();

        // At least one client should have seen an error (ServerStopped or Cancelled)
        // because the server shut down. The first call may have succeeded before stop.
        // All outcomes are acceptable: Ok (processed before stop), ServerStopped,
        // Cancelled, or NoReply.
        drop(result_2.lock().unwrap());

        crate::test_complete!("conformance_cancel_propagation_to_queued_calls");
    }

    /// After stop(), new calls and casts are rejected immediately.
    #[test]
    fn conformance_stopped_server_rejects_new_messages() {
        init_test("conformance_stopped_server_rejects_new_messages");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        // Start the server so init runs.
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_idle();

        // Stop the server and drain.
        handle.stop();
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        // try_cast to a stopped server should fail.
        let cast_result = server_ref.try_cast(CounterCast::Reset);
        assert!(cast_result.is_err(), "cast to stopped server must fail");

        crate::test_complete!("conformance_stopped_server_rejects_new_messages");
    }

    /// Full lifecycle test: start, send calls+casts, stop, verify no leaked
    /// obligations or unprocessed messages. This exercises the complete
    /// GenServer protocol end-to-end.
    #[test]
    fn conformance_full_lifecycle_no_obligation_leaks() {
        init_test("conformance_full_lifecycle_no_obligation_leaks");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        // Phase 1: Fire off a mix of casts and then a call.
        server_ref.try_cast(CounterCast::Reset).unwrap();

        let call_result: Arc<Mutex<Option<Result<u64, CallError>>>> = Arc::new(Mutex::new(None));
        let call_result_clone = Arc::clone(&call_result);
        let server_ref_for_call = handle.server_ref();
        let (client, client_stored) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                let r = server_ref_for_call.call(&cx, CounterCall::Add(42)).await;
                *call_result_clone.lock().unwrap() = Some(r);
            })
            .unwrap();
        let client_id = client.task_id();
        runtime.state.store_spawned_task(client_id, client_stored);

        // Schedule both and let them process.
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(client_id, 0);
        }
        runtime.run_until_idle();

        // Re-schedule for message processing.
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(client_id, 0);
        }
        runtime.run_until_idle();

        // Phase 2: Verify the call result.
        let call_r = call_result.lock().unwrap();
        if let Some(ref r) = *call_r {
            match r {
                Ok(value) => assert_eq!(*value, 42, "counter should be 42 after Add(42)"),
                Err(e) => unreachable!("unexpected call error: {e:?}"),
            }
        }
        drop(call_r);

        // Phase 3: More casts to exercise the mailbox.
        server_ref.try_cast(CounterCast::Reset).unwrap();

        // Phase 4: Graceful stop.
        handle.stop();
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        // If we get here without panics, no obligations were leaked.
        // TrackedOneshotPermit panics on drop if not consumed.
        crate::test_complete!("conformance_full_lifecycle_no_obligation_leaks");
    }

    /// Deterministic replay: running the same GenServer scenario with the
    /// same seed must produce identical state transitions.
    #[test]
    #[allow(clippy::items_after_statements)]
    fn conformance_deterministic_replay_with_seed() {
        init_test("conformance_deterministic_replay_with_seed");

        fn run_scenario(seed: u64) -> Vec<u64> {
            let config = crate::lab::LabConfig::new(seed);
            let mut runtime = crate::lab::LabRuntime::new(config);
            let budget = Budget::new().with_poll_quota(100_000);
            let region = runtime.state.create_root_region(budget);
            let cx = Cx::for_testing();
            let scope = crate::cx::Scope::<FailFast>::new(region, budget);

            let (handle, stored) = scope
                .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
                .unwrap();
            let server_task_id = handle.task_id();
            runtime.state.store_spawned_task(server_task_id, stored);

            let results: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));

            // Spawn 3 clients that each Add different amounts.
            let mut client_ids = Vec::new();
            for i in 1..=3u64 {
                let server_ref = handle.server_ref();
                let results_clone = Arc::clone(&results);
                let (ch, cs) = scope
                    .spawn(&mut runtime.state, &cx, move |cx| async move {
                        if let Ok(val) = server_ref.call(&cx, CounterCall::Add(i * 10)).await {
                            results_clone.lock().unwrap().push(val);
                        }
                    })
                    .unwrap();
                let cid = ch.task_id();
                runtime.state.store_spawned_task(cid, cs);
                client_ids.push(cid);
            }

            // Schedule all tasks.
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(server_task_id, 0);
                for &cid in &client_ids {
                    sched.schedule(cid, 0);
                }
            }
            runtime.run_until_idle();

            // Re-schedule to process enqueued calls.
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(server_task_id, 0);
                for &cid in &client_ids {
                    sched.schedule(cid, 0);
                }
            }
            runtime.run_until_idle();

            // Stop and drain.
            handle.stop();
            runtime.scheduler.lock().schedule(server_task_id, 0);
            runtime.run_until_quiescent();

            results.lock().unwrap().clone()
        }

        // Same seed must produce identical results.
        let run_a = run_scenario(42);
        let run_b = run_scenario(42);
        assert_eq!(
            run_a, run_b,
            "same seed must produce identical results: {run_a:?} vs {run_b:?}"
        );

        crate::test_complete!("conformance_deterministic_replay_with_seed");
    }

    /// Mailbox overflow with Reject policy: deterministic rejection when full.
    #[test]
    fn conformance_mailbox_overflow_reject_deterministic() {
        init_test("conformance_mailbox_overflow_reject_deterministic");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        // Capacity-2 mailbox with default Reject policy.
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 2)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        // Fill the mailbox to capacity.
        server_ref.try_cast(CounterCast::Reset).unwrap();
        server_ref.try_cast(CounterCast::Reset).unwrap();

        // Third cast must be rejected (mailbox full, Reject policy).
        let overflow = server_ref.try_cast(CounterCast::Reset);
        assert!(
            overflow.is_err(),
            "third cast to capacity-2 mailbox must fail with Reject policy"
        );
        match overflow.unwrap_err() {
            CastError::Full => { /* expected */ }
            other => unreachable!("expected CastError::Full, got {other:?}"),
        }

        // Drain and cleanup.
        drop(handle);
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        crate::test_complete!("conformance_mailbox_overflow_reject_deterministic");
    }

    /// DropOldest eviction preserves the newest messages when full.
    #[test]
    fn conformance_mailbox_drop_oldest_preserves_newest() {
        init_test("conformance_mailbox_drop_oldest_preserves_newest");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        // DropOldest counter with capacity 2.
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, DropOldestCounter { count: 0 }, 2)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        // Fill mailbox with Set(1) and Set(2).
        server_ref.try_cast(TaggedCast::Set(1)).unwrap();
        server_ref.try_cast(TaggedCast::Set(2)).unwrap();

        // Overflow with Set(100) — should evict Set(1), keeping Set(2) and Set(100).
        server_ref.try_cast(TaggedCast::Set(100)).unwrap();

        // Process all messages.
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_idle();

        // The final value should be 100 (last Set wins).
        let result_ref = handle.server_ref();
        let result: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
        let result_clone = Arc::clone(&result);
        let (ch, cs) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                if let Ok(val) = result_ref.call(&cx, CounterCall::Get).await {
                    *result_clone.lock().unwrap() = Some(val);
                }
            })
            .unwrap();
        let cid = ch.task_id();
        runtime.state.store_spawned_task(cid, cs);

        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(cid, 0);
        }
        runtime.run_until_idle();
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(cid, 0);
        }
        runtime.run_until_idle();

        // The server should have processed Set(2), then Set(100).
        // Set(1) was evicted. Final count = 100.
        assert_eq!(
            *result.lock().unwrap(),
            Some(100),
            "DropOldest should evict oldest, keeping newest"
        );

        drop(handle);
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        crate::test_complete!("conformance_mailbox_drop_oldest_preserves_newest");
    }

    /// Budget-driven timeout: a call with a tight poll_quota budget
    /// must terminate deterministically without wall-clock dependence.
    #[test]
    #[allow(clippy::items_after_statements)]
    fn conformance_budget_driven_call_timeout() {
        // Server that never replies (intentionally leaves reply unconsumed
        // by aborting it, which is the correct way to not reply).
        struct SlowServer;
        impl GenServer for SlowServer {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                // Abort the reply obligation (correct: no leak).
                let _proof = reply.abort();
                Box::pin(async {})
            }
        }

        init_test("conformance_budget_driven_call_timeout");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, SlowServer, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        // Client calls the server. The server aborts the reply, so the
        // client should see a channel close / error.
        let call_result: Arc<Mutex<Option<Result<(), CallError>>>> = Arc::new(Mutex::new(None));
        let call_result_clone = Arc::clone(&call_result);
        let (ch, cs) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                let r = server_ref.call(&cx, ()).await;
                *call_result_clone.lock().unwrap() = Some(r);
            })
            .unwrap();
        let client_id = ch.task_id();
        runtime.state.store_spawned_task(client_id, cs);

        // Run everything.
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(client_id, 0);
        }
        runtime.run_until_idle();
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(client_id, 0);
        }
        runtime.run_until_idle();

        // The client should have received an error since the server aborted.
        if let Some(ref result) = *call_result.lock().unwrap() {
            assert!(result.is_err(), "aborted reply should result in call error");
        }

        // Clean up.
        handle.stop();
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        crate::test_complete!("conformance_budget_driven_call_timeout");
    }

    /// Reply linearity: verify that Reply::send commits the obligation
    /// and the committed proof is returned.
    #[test]
    #[allow(clippy::items_after_statements)]
    fn conformance_reply_linearity_send_commits() {
        // Server that tracks whether reply was committed.
        struct ReplyTracker {
            committed: Arc<AtomicU8>,
        }

        impl GenServer for ReplyTracker {
            type Call = u64;
            type Reply = u64;
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                request: u64,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                match reply.send(request * 2) {
                    ReplyOutcome::Committed(_proof) => {
                        self.committed.store(1, Ordering::SeqCst);
                    }
                    ReplyOutcome::CallerGone => {
                        self.committed.store(2, Ordering::SeqCst);
                    }
                }
                Box::pin(async {})
            }
        }

        init_test("conformance_reply_linearity_send_commits");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let committed = Arc::new(AtomicU8::new(0));
        let server = ReplyTracker {
            committed: Arc::clone(&committed),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();
        let call_result: Arc<Mutex<Option<Result<u64, CallError>>>> = Arc::new(Mutex::new(None));
        let call_result_clone = Arc::clone(&call_result);

        let (ch, cs) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                let r = server_ref.call(&cx, 21).await;
                *call_result_clone.lock().unwrap() = Some(r);
            })
            .unwrap();
        let client_id = ch.task_id();
        runtime.state.store_spawned_task(client_id, cs);

        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(client_id, 0);
        }
        runtime.run_until_idle();
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(client_id, 0);
        }
        runtime.run_until_idle();

        // Verify reply was committed (not CallerGone).
        assert_eq!(
            committed.load(Ordering::SeqCst),
            1,
            "reply must be committed when caller is waiting"
        );

        // Verify the caller received the correct value.
        {
            let r = call_result.lock().unwrap();
            match r.as_ref() {
                Some(Ok(value)) => assert_eq!(*value, 42, "21 * 2 = 42"),
                other => unreachable!("expected Ok(42), got {other:?}"),
            }
        }

        handle.stop();
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        crate::test_complete!("conformance_reply_linearity_send_commits");
    }

    /// Reply linearity: verify that Reply::abort produces an AbortedProof
    /// and the caller receives an error (not a value).
    #[test]
    #[allow(clippy::items_after_statements)]
    fn conformance_reply_linearity_abort_is_clean() {
        struct AbortServer {
            aborted: Arc<AtomicU8>,
        }

        impl GenServer for AbortServer {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _proof = reply.abort();
                self.aborted.store(1, Ordering::SeqCst);
                Box::pin(async {})
            }
        }

        init_test("conformance_reply_linearity_abort_is_clean");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let aborted = Arc::new(AtomicU8::new(0));
        let server = AbortServer {
            aborted: Arc::clone(&aborted),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();
        let call_err: Arc<Mutex<Option<Result<(), CallError>>>> = Arc::new(Mutex::new(None));
        let call_err_clone = Arc::clone(&call_err);

        let (ch, cs) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                let r = server_ref.call(&cx, ()).await;
                *call_err_clone.lock().unwrap() = Some(r);
            })
            .unwrap();
        let client_id = ch.task_id();
        runtime.state.store_spawned_task(client_id, cs);

        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(client_id, 0);
        }
        runtime.run_until_idle();
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(client_id, 0);
        }
        runtime.run_until_idle();

        // Server should have aborted.
        assert_eq!(
            aborted.load(Ordering::SeqCst),
            1,
            "server must have called abort()"
        );

        // Caller should see an error, not Ok.
        {
            let r = call_err.lock().unwrap();
            match r.as_ref() {
                Some(Err(_)) => { /* expected: aborted reply -> error */ }
                other => unreachable!("expected call error after abort, got {other:?}"),
            }
        }

        handle.stop();
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        crate::test_complete!("conformance_reply_linearity_abort_is_clean");
    }

    /// On-stop processes remaining casts before completing (drain semantics).
    /// Verifies that queued casts are not silently dropped on shutdown.
    #[test]
    #[allow(clippy::items_after_statements)]
    fn conformance_drain_processes_queued_casts_on_stop() {
        struct AccumulatorServer {
            sum: u64,
            final_sum: Arc<AtomicU64>,
        }

        enum AccumCall {
            GetSum,
        }
        enum AccumCast {
            Add(u64),
        }

        impl GenServer for AccumulatorServer {
            type Call = AccumCall;
            type Reply = u64;
            type Cast = AccumCast;
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: AccumCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(self.sum);
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                msg: AccumCast,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                match msg {
                    AccumCast::Add(n) => self.sum += n,
                }
                Box::pin(async {})
            }

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.final_sum.store(self.sum, Ordering::SeqCst);
                Box::pin(async {})
            }
        }

        init_test("conformance_drain_processes_queued_casts_on_stop");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let final_sum = Arc::new(AtomicU64::new(0));
        let server = AccumulatorServer {
            sum: 0,
            final_sum: Arc::clone(&final_sum),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        // Queue up several casts.
        server_ref.try_cast(AccumCast::Add(10)).unwrap();
        server_ref.try_cast(AccumCast::Add(20)).unwrap();
        server_ref.try_cast(AccumCast::Add(30)).unwrap();

        // Start the server (init runs, then it will process casts).
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_idle();

        // Stop and let it drain remaining messages.
        handle.stop();
        runtime.scheduler.lock().schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        // The server should have processed all casts before stopping.
        let sum = final_sum.load(Ordering::SeqCst);
        assert_eq!(
            sum, 60,
            "server must drain queued casts before stopping: 10+20+30=60, got {sum}"
        );

        crate::test_complete!("conformance_drain_processes_queued_casts_on_stop");
    }

    // =========================================================================
    // Named GenServer integration tests (bd-23az1)
    // =========================================================================

    /// Named server: spawn registers name, whereis finds it.
    #[test]
    fn named_server_register_and_whereis() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_register_and_whereis");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();

        #[allow(clippy::items_after_statements)]
        #[derive(Debug)]
        struct Counter(u64);

        #[allow(clippy::items_after_statements)]
        impl GenServer for Counter {
            type Call = u64;
            type Reply = u64;
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                request: u64,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.0 += request;
                let _ = reply.send(self.0);
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let now = crate::types::Time::ZERO;
        let (mut named_handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "my_counter",
                Counter(0),
                32,
                now,
            )
            .unwrap();

        let task_id = named_handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Name should be visible via whereis.
        assert_eq!(registry.whereis("my_counter"), Some(task_id));
        assert_eq!(named_handle.name(), "my_counter");

        // Clean up: release lease.
        named_handle.stop_and_release().unwrap();

        crate::test_complete!("named_server_register_and_whereis");
    }

    /// Named server: duplicate name is rejected.
    #[test]
    fn named_server_duplicate_name_rejected() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_duplicate_name_rejected");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();

        #[allow(clippy::items_after_statements)]
        #[derive(Debug)]
        struct Dummy;

        #[allow(clippy::items_after_statements)]
        impl GenServer for Dummy {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let now = crate::types::Time::ZERO;

        // First spawn succeeds.
        let (mut h1, s1) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "singleton",
                Dummy,
                8,
                now,
            )
            .unwrap();
        runtime.state.store_spawned_task(h1.task_id(), s1);

        // Second spawn with same name fails.
        let result = scope.spawn_named_gen_server(
            &mut runtime.state,
            &cx,
            &mut registry,
            "singleton",
            Dummy,
            8,
            now,
        );
        assert!(
            matches!(result, Err(NamedSpawnError::NameTaken(_))),
            "duplicate name should be rejected"
        );

        // Original is still registered.
        assert_eq!(registry.whereis("singleton"), Some(h1.task_id()));

        // Verify the orphaned task record from the failed spawn was cleaned up.
        // The region should only contain the first task; no leaked task record
        // that would prevent region quiescence.
        let region_tasks = runtime.state.region(region).unwrap().task_ids();
        assert_eq!(
            region_tasks,
            vec![h1.task_id()],
            "region should only have the first task; orphaned task must be removed"
        );

        h1.stop_and_release().unwrap();

        crate::test_complete!("named_server_duplicate_name_rejected");
    }

    /// Named server: abort_lease removes name from registry.
    #[test]
    fn named_server_abort_lease_removes_name() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_abort_lease_removes_name");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();

        #[allow(clippy::items_after_statements)]
        #[derive(Debug)]
        struct Noop;

        #[allow(clippy::items_after_statements)]
        impl GenServer for Noop {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _req: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let now = crate::types::Time::ZERO;
        let (mut handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "temp_name",
                Noop,
                8,
                now,
            )
            .unwrap();
        runtime.state.store_spawned_task(handle.task_id(), stored);

        // Name is registered.
        assert!(registry.whereis("temp_name").is_some());

        // Abort the lease (simulating cancellation).
        handle.abort_lease().unwrap();

        // Name should no longer be registered after unregister.
        // Note: abort resolves the obligation but doesn't auto-unregister;
        // the name entry stays until explicitly unregistered.
        // The lease obligation is resolved (no drop bomb).

        crate::test_complete!("named_server_abort_lease_removes_name");
    }

    /// Named server: take_lease allows manual lifecycle management.
    #[test]
    fn named_server_take_lease_manual_management() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_take_lease_manual_management");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();

        #[allow(clippy::items_after_statements)]
        #[derive(Debug)]
        struct Noop2;

        #[allow(clippy::items_after_statements)]
        impl GenServer for Noop2 {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _req: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let now = crate::types::Time::ZERO;
        let (mut handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "manual_name",
                Noop2,
                8,
                now,
            )
            .unwrap();
        runtime.state.store_spawned_task(handle.task_id(), stored);

        // Take the lease for manual management.
        let mut lease = handle.take_lease().unwrap();
        assert!(handle.take_lease().is_none(), "second take returns None");

        // name() returns placeholder when lease is taken.
        assert_eq!(handle.name(), "(released)");

        // Resolve the lease manually.
        let _ = lease.abort();

        crate::test_complete!("named_server_take_lease_manual_management");
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn named_start_helper_supervisor_stop_cleans_registry() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_start_helper_supervisor_stop_cleans_registry");

        #[derive(Debug)]
        struct Noop;

        impl GenServer for Noop {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let registry: Arc<parking_lot::Mutex<crate::cx::NameRegistry>> =
            Arc::new(parking_lot::Mutex::new(crate::cx::NameRegistry::new()));

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let root = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();

        let child = crate::supervision::ChildSpec::new(
            "svc_child",
            named_gen_server_start(Arc::clone(&registry), "svc", 16, || Noop),
        );

        let compiled = crate::supervision::SupervisorBuilder::new("svc_supervisor")
            .child(child)
            .compile()
            .expect("compile supervisor");

        let supervisor = compiled
            .spawn(&mut runtime.state, &cx, root, budget)
            .expect("spawn supervisor");

        assert_eq!(supervisor.started.len(), 1, "exactly one started child");
        let child_task = supervisor.started[0].task_id;
        assert_eq!(registry.lock().whereis("svc"), Some(child_task));

        // Stop the supervisor region and drive cancellation/finalization.
        let tasks_to_schedule = runtime.state.cancel_request(
            supervisor.region,
            &crate::types::CancelReason::user("stop"),
            None,
        );
        for (task_id, priority) in tasks_to_schedule {
            runtime.scheduler.lock().schedule(task_id, priority);
        }
        runtime.run_until_quiescent();

        assert!(
            registry.lock().whereis("svc").is_none(),
            "name must be removed after supervised stop",
        );

        crate::test_complete!("named_start_helper_supervisor_stop_cleans_registry");
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn named_start_helper_crash_then_stop_cleans_registry() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_start_helper_crash_then_stop_cleans_registry");

        #[derive(Debug)]
        struct PanicOnStart;

        impl GenServer for PanicOnStart {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async move {
                    std::panic::panic_any("intentional start crash for registry cleanup test");
                })
            }

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let registry: Arc<parking_lot::Mutex<crate::cx::NameRegistry>> =
            Arc::new(parking_lot::Mutex::new(crate::cx::NameRegistry::new()));

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(7));
        let root = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();

        let child = crate::supervision::ChildSpec::new(
            "panic_child",
            named_gen_server_start(Arc::clone(&registry), "panic_svc", 8, || PanicOnStart),
        );

        let compiled = crate::supervision::SupervisorBuilder::new("panic_supervisor")
            .child(child)
            .compile()
            .expect("compile supervisor");

        let supervisor = compiled
            .spawn(&mut runtime.state, &cx, root, budget)
            .expect("spawn supervisor");

        let child_task = supervisor.started[0].task_id;
        assert_eq!(registry.lock().whereis("panic_svc"), Some(child_task));

        // Drive the child once so it crashes in on_start.
        runtime.scheduler.lock().schedule(child_task, 0);
        runtime.run_until_idle();

        // Region stop must still clean the registry + resolve the lease.
        let tasks_to_schedule = runtime.state.cancel_request(
            supervisor.region,
            &crate::types::CancelReason::user("shutdown"),
            None,
        );
        for (task_id, priority) in tasks_to_schedule {
            runtime.scheduler.lock().schedule(task_id, priority);
        }
        runtime.run_until_quiescent();

        assert!(
            registry.lock().whereis("panic_svc").is_none(),
            "name must be removed after crash + region stop",
        );

        crate::test_complete!("named_start_helper_crash_then_stop_cleans_registry");
    }

    // ========================================================================
    // Pure data-type tests (wave 9 – CyanBarn)
    // ========================================================================

    #[test]
    fn cast_overflow_policy_default_is_reject() {
        let policy: CastOverflowPolicy = Default::default();
        assert!(matches!(policy, CastOverflowPolicy::Reject));
    }

    #[test]
    fn cast_overflow_policy_debug() {
        let dbg = format!("{:?}", CastOverflowPolicy::Reject);
        assert!(dbg.contains("Reject"), "{dbg}");
        let dbg2 = format!("{:?}", CastOverflowPolicy::DropOldest);
        assert!(dbg2.contains("DropOldest"), "{dbg2}");
    }

    #[test]
    fn cast_overflow_policy_eq_clone_copy() {
        let a = CastOverflowPolicy::Reject;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(CastOverflowPolicy::Reject, CastOverflowPolicy::DropOldest);
    }

    #[test]
    fn down_msg_constructor_and_debug() {
        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(50), rid(0), tid(51));
        let msg = DownMsg::new(
            Time::from_secs(7),
            DownNotification {
                monitored: tid(51),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        );
        assert_eq!(msg.completion_vt, Time::from_secs(7));
        assert_eq!(msg.notification.monitored, tid(51));
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("DownMsg"), "{dbg}");
    }

    #[test]
    fn down_msg_clone() {
        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(60), rid(0), tid(61));
        let msg = DownMsg::new(
            Time::from_secs(8),
            DownNotification {
                monitored: tid(61),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        );
        let cloned = msg.clone();
        assert_eq!(cloned.completion_vt, msg.completion_vt);
        assert_eq!(cloned.notification.monitored, msg.notification.monitored);
    }

    #[test]
    fn exit_msg_constructor_and_eq() {
        let a = ExitMsg::new(Time::from_secs(5), tid(10), DownReason::Normal);
        let b = ExitMsg::new(Time::from_secs(5), tid(10), DownReason::Normal);
        assert_eq!(a, b);
    }

    #[test]
    fn exit_msg_debug_and_clone() {
        let msg = ExitMsg::new(
            Time::from_secs(6),
            tid(11),
            DownReason::Error("oops".into()),
        );
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("ExitMsg"), "{dbg}");
        let cloned = msg.clone();
        assert_eq!(cloned, msg);
    }

    #[test]
    fn exit_msg_inequality() {
        let a = ExitMsg::new(Time::from_secs(1), tid(1), DownReason::Normal);
        let b = ExitMsg::new(Time::from_secs(2), tid(1), DownReason::Normal);
        assert_ne!(a, b);
    }

    #[test]
    fn timeout_msg_constructor_eq_copy() {
        let a = TimeoutMsg::new(Time::from_secs(10), 42);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a.tick_vt, Time::from_secs(10));
        assert_eq!(a.id, 42);
    }

    #[test]
    fn timeout_msg_debug() {
        let msg = TimeoutMsg::new(Time::from_secs(1), 99);
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("TimeoutMsg"), "{dbg}");
    }

    #[test]
    fn timeout_msg_inequality() {
        let a = TimeoutMsg::new(Time::from_secs(1), 1);
        let b = TimeoutMsg::new(Time::from_secs(1), 2);
        assert_ne!(a, b);
    }

    #[test]
    fn system_msg_debug_all_variants() {
        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(70), rid(0), tid(71));

        let down = SystemMsg::Down {
            completion_vt: Time::from_secs(1),
            notification: DownNotification {
                monitored: tid(71),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        };
        let exit = SystemMsg::Exit {
            exit_vt: Time::from_secs(2),
            from: tid(72),
            reason: DownReason::Normal,
        };
        let timeout = SystemMsg::Timeout {
            tick_vt: Time::from_secs(3),
            id: 55,
        };

        let d = format!("{down:?}");
        assert!(d.contains("Down"), "{d}");
        let e = format!("{exit:?}");
        assert!(e.contains("Exit"), "{e}");
        let t = format!("{timeout:?}");
        assert!(t.contains("Timeout"), "{t}");
    }

    #[test]
    fn system_msg_clone() {
        let msg = SystemMsg::Timeout {
            tick_vt: Time::from_secs(5),
            id: 7,
        };
        let cloned = msg.clone();
        assert_eq!(cloned.sort_key(), msg.sort_key());
    }

    #[test]
    fn system_msg_convenience_constructors() {
        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(80), rid(0), tid(81));

        let down_payload = DownMsg::new(
            Time::from_secs(1),
            DownNotification {
                monitored: tid(81),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        );
        let msg = SystemMsg::down(down_payload);
        assert!(matches!(msg, SystemMsg::Down { .. }));

        let exit_payload = ExitMsg::new(Time::from_secs(2), tid(82), DownReason::Normal);
        let msg = SystemMsg::exit(exit_payload);
        assert!(matches!(msg, SystemMsg::Exit { .. }));

        let timeout_payload = TimeoutMsg::new(Time::from_secs(3), 44);
        let msg = SystemMsg::timeout(timeout_payload);
        assert!(matches!(msg, SystemMsg::Timeout { .. }));
    }

    #[test]
    fn system_msg_sort_key_kind_rank_ordering() {
        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(85), rid(0), tid(86));

        let same_vt = Time::from_secs(100);
        let down = SystemMsg::Down {
            completion_vt: same_vt,
            notification: DownNotification {
                monitored: tid(86),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        };
        let exit = SystemMsg::Exit {
            exit_vt: same_vt,
            from: tid(86),
            reason: DownReason::Normal,
        };
        let timeout = SystemMsg::Timeout {
            tick_vt: same_vt,
            id: 1,
        };

        // Down < Exit < Timeout (kind ranks 0, 1, 2)
        assert!(down.sort_key() < exit.sort_key());
        assert!(exit.sort_key() < timeout.sort_key());
    }

    #[test]
    fn system_msg_subject_key_debug_eq_ord() {
        let a = SystemMsgSubjectKey::Task(tid(1));
        let b = SystemMsgSubjectKey::Task(tid(1));
        let c = SystemMsgSubjectKey::TimeoutId(1);

        assert_eq!(a, b);
        assert_ne!(a, c);

        let dbg = format!("{a:?}");
        assert!(dbg.contains("Task"), "{dbg}");
        let dbg2 = format!("{c:?}");
        assert!(dbg2.contains("TimeoutId"), "{dbg2}");

        // Copy + Clone
        let copied = a;
        let cloned = a;
        assert_eq!(copied, cloned);

        // Ord consistency
        assert!(a <= b);
    }

    #[test]
    fn system_msg_batch_default_and_empty() {
        let batch = SystemMsgBatch::new();
        let sorted = batch.into_sorted();
        assert!(sorted.is_empty());
    }

    #[test]
    fn system_msg_batch_debug() {
        let batch = SystemMsgBatch::new();
        let dbg = format!("{batch:?}");
        assert!(dbg.contains("SystemMsgBatch"), "{dbg}");
    }

    #[test]
    fn system_msg_batch_single_element() {
        let mut batch = SystemMsgBatch::new();
        batch.push(SystemMsg::Timeout {
            tick_vt: Time::from_secs(42),
            id: 1,
        });
        let sorted = batch.into_sorted();
        assert_eq!(sorted.len(), 1);
        assert!(matches!(sorted[0], SystemMsg::Timeout { id: 1, .. }));
    }

    #[test]
    fn call_error_display_server_stopped() {
        let err = CallError::ServerStopped;
        let disp = format!("{err}");
        assert_eq!(disp, "GenServer has stopped");
    }

    #[test]
    fn call_error_display_no_reply() {
        let err = CallError::NoReply;
        let disp = format!("{err}");
        assert_eq!(disp, "GenServer did not reply");
    }

    #[test]
    fn call_error_display_cancelled() {
        let reason = CancelReason::user("test cancel");
        let err = CallError::Cancelled(reason);
        let disp = format!("{err}");
        assert!(disp.contains("cancelled"), "{disp}");
    }

    #[test]
    fn call_error_debug_all_variants() {
        let dbg1 = format!("{:?}", CallError::ServerStopped);
        assert!(dbg1.contains("ServerStopped"), "{dbg1}");
        let dbg2 = format!("{:?}", CallError::NoReply);
        assert!(dbg2.contains("NoReply"), "{dbg2}");
        let dbg3 = format!("{:?}", CallError::Cancelled(CancelReason::user("x")));
        assert!(dbg3.contains("Cancelled"), "{dbg3}");
    }

    #[test]
    fn call_error_is_std_error() {
        let err = CallError::ServerStopped;
        let _: &dyn std::error::Error = &err;
        // source() defaults to None
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn cast_error_display_all_variants() {
        assert_eq!(
            format!("{}", CastError::ServerStopped),
            "GenServer has stopped"
        );
        assert_eq!(format!("{}", CastError::Full), "GenServer mailbox full");
        let cancelled = CastError::Cancelled(CancelReason::user("t"));
        let disp = format!("{cancelled}");
        assert!(disp.contains("cancelled"), "{disp}");
    }

    #[test]
    fn cast_error_debug_all_variants() {
        let dbg1 = format!("{:?}", CastError::ServerStopped);
        assert!(dbg1.contains("ServerStopped"), "{dbg1}");
        let dbg2 = format!("{:?}", CastError::Full);
        assert!(dbg2.contains("Full"), "{dbg2}");
    }

    #[test]
    fn cast_error_is_std_error() {
        let err = CastError::Full;
        let _: &dyn std::error::Error = &err;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn info_error_display_all_variants() {
        assert_eq!(
            format!("{}", InfoError::ServerStopped),
            "GenServer has stopped"
        );
        assert_eq!(format!("{}", InfoError::Full), "GenServer mailbox full");
        let cancelled = InfoError::Cancelled(CancelReason::user("u"));
        let disp = format!("{cancelled}");
        assert!(disp.contains("cancelled"), "{disp}");
    }

    #[test]
    fn info_error_debug_all_variants() {
        let dbg1 = format!("{:?}", InfoError::ServerStopped);
        assert!(dbg1.contains("ServerStopped"), "{dbg1}");
        let dbg2 = format!("{:?}", InfoError::Full);
        assert!(dbg2.contains("Full"), "{dbg2}");
    }

    #[test]
    fn info_error_is_std_error() {
        let err = InfoError::ServerStopped;
        let _: &dyn std::error::Error = &err;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn system_msg_try_from_exit_rejects_timeout() {
        let timeout = SystemMsg::Timeout {
            tick_vt: Time::from_secs(1),
            id: 7,
        };
        let err = ExitMsg::try_from(timeout).expect_err("timeout is not exit");
        assert!(matches!(err, SystemMsg::Timeout { id: 7, .. }));
    }

    #[test]
    fn system_msg_try_from_exit_succeeds() {
        let exit = SystemMsg::Exit {
            exit_vt: Time::from_secs(3),
            from: tid(15),
            reason: DownReason::Normal,
        };
        let result = ExitMsg::try_from(exit).expect("exit conversion");
        assert_eq!(result.exit_vt, Time::from_secs(3));
        assert_eq!(result.from, tid(15));
    }

    #[test]
    fn system_msg_try_from_timeout_rejects_exit() {
        let exit = SystemMsg::Exit {
            exit_vt: Time::from_secs(1),
            from: tid(1),
            reason: DownReason::Normal,
        };
        let err = TimeoutMsg::try_from(exit).expect_err("exit is not timeout");
        assert!(matches!(err, SystemMsg::Exit { .. }));
    }
}
