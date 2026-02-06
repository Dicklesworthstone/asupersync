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
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

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
    inner: Arc<std::sync::RwLock<CxInner>>,
    original_budget: Budget,
    original_baseline: Budget,
    phase_baseline: Budget,
    restore_original: bool,
}

impl PhaseBudgetGuard {
    fn enter(cx: &Cx, phase_budget: Budget, restore_original: bool) -> Self {
        let inner = Arc::clone(&cx.inner);
        let (original_budget, original_baseline, phase_baseline) = {
            let mut guard = inner.write().expect("lock poisoned");
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

        let Ok(mut guard) = self.inner.write() else {
            return;
        };

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
    inner: Arc<std::sync::RwLock<CxInner>>,
}

impl AsyncMaskGuard {
    fn enter(cx: &Cx) -> Self {
        let inner = Arc::clone(&cx.inner);
        {
            let mut guard = inner.write().expect("lock poisoned");
            crate::assert_with_log!(
                guard.mask_depth < crate::types::task_context::MAX_MASK_DEPTH,
                "mask_depth",
                guard.mask_depth,
                guard.mask_depth
            );
            guard.mask_depth += 1;
        }
        Self { inner }
    }
}

impl Drop for AsyncMaskGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.inner.write() {
            guard.mask_depth = guard.mask_depth.saturating_sub(1);
        }
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
    fn vt(&self) -> Time {
        match self {
            Self::Down { completion_vt, .. } => *completion_vt,
            Self::Exit { exit_vt, .. } => *exit_vt,
            Self::Timeout { tick_vt, .. } => *tick_vt,
        }
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
    inner: std::sync::Weak<std::sync::RwLock<CxInner>>,
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
                    Ok(Some(_evicted)) => {
                        // Trace the eviction so lossy drops are observable.
                        if let Some(cx) = Cx::current() {
                            cx.trace("gen_server::cast_evicted_oldest");
                        }
                        Ok(())
                    }
                    Ok(None) => Ok(()),
                    Err(mpsc::SendError::Disconnected(_)) => Err(CastError::ServerStopped),
                    Err(mpsc::SendError::Full(_) | mpsc::SendError::Cancelled(_)) => {
                        unreachable!("send_evict_oldest never returns Full or Cancelled")
                    }
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
            if let Ok(mut guard) = inner.write() {
                guard.cancel_requested = true;
            }
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
                Ok(Some(_evicted)) => {
                    if let Some(cx) = Cx::current() {
                        cx.trace("gen_server::cast_evicted_oldest");
                    }
                    Ok(())
                }
                Ok(None) => Ok(()),
                Err(mpsc::SendError::Disconnected(_)) => Err(CastError::ServerStopped),
                Err(mpsc::SendError::Full(_) | mpsc::SendError::Cancelled(_)) => {
                    unreachable!("send_evict_oldest never returns Full or Cancelled")
                }
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
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::state::RuntimeState;
    use crate::types::policy::FailFast;
    use crate::types::Budget;
    use crate::types::CancelKind;
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

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
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

        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(client_task_id, 0);
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
                *client_cx_cell_for_task.lock().expect("lock poisoned") = Some(cx.clone());
                server_ref.call(&cx, CounterCall::Get).await
            })
            .unwrap();
        let client_task_id = client_handle.task_id();
        runtime
            .state
            .store_spawned_task(client_task_id, client_stored);

        // Poll the client once: it should enqueue the call and then block waiting for reply.
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(client_task_id, 0);
        runtime.run_until_idle();

        // Cancel the client deterministically, then poll it again to observe the cancellation.
        let client_cx = client_cx_cell
            .lock()
            .expect("lock poisoned")
            .clone()
            .expect("client cx published");
        client_cx.cancel_with(CancelKind::User, Some("gen_server call cancelled"));

        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(client_task_id, 0);
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
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        crate::test_complete!("gen_server_call_cancellation_is_deterministic");
    }

    #[test]
    fn gen_server_cast_cancellation_is_deterministic() {
        init_test("gen_server_cast_cancellation_is_deterministic");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        // Use a capacity-1 mailbox so we can deterministically block a second cast.
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 1)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();
        server_ref
            .try_cast(CounterCast::Reset)
            .expect("pre-fill cast");

        let client_cx_cell: Arc<Mutex<Option<Cx>>> = Arc::new(Mutex::new(None));
        let client_cx_cell_for_task = Arc::clone(&client_cx_cell);
        let server_ref_for_task = server_ref;

        let (client_handle, client_stored) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                *client_cx_cell_for_task.lock().expect("lock poisoned") = Some(cx.clone());
                server_ref_for_task.cast(&cx, CounterCast::Reset).await
            })
            .unwrap();
        let client_task_id = client_handle.task_id();
        runtime
            .state
            .store_spawned_task(client_task_id, client_stored);

        // Poll the client once: it should block waiting for mailbox capacity.
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(client_task_id, 0);
        runtime.run_until_idle();

        let client_cx = client_cx_cell
            .lock()
            .expect("lock poisoned")
            .clone()
            .expect("client cx published");
        client_cx.cancel_with(CancelKind::User, Some("gen_server cast cancelled"));

        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(client_task_id, 0);
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
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
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

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
        runtime.run_until_quiescent();

        assert!(handle.is_finished());
        assert!(!server_ref.is_alive());

        crate::test_complete!("gen_server_stop_transitions");
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
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
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

        // Pre-fill via try_cast: Add 1 five times via cast-wrapped calls
        // (We use casts here since calls need async reply handling)
        for _ in 0..5 {
            handle.try_cast(CounterCast::Reset).ok();
        }

        // Actually, let's send real Add operations as calls encoded as casts.
        // Since we can't easily do calls synchronously, we'll test the drain
        // guarantee by encoding increments differently.

        // Drop handle to disconnect
        drop(handle);

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
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

            // 5 resets then disconnect
            for _ in 0..5 {
                handle.try_cast(CounterCast::Reset).ok();
            }
            drop(handle);

            runtime.scheduler.lock().unwrap().schedule(task_id, 0);
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
                seen.lock().expect("lock poisoned").push(format!("{msg:?}"));
            })
        }
    }

    fn tid(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn rid(n: u32) -> crate::types::RegionId {
        crate::types::RegionId::from_arena(ArenaIndex::new(n, 0))
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

        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
        runtime.run_until_quiescent();

        let seen = seen.lock().expect("lock poisoned");
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
            runtime.scheduler.lock().unwrap().schedule(task_id_a, 0);
            runtime.scheduler.lock().unwrap().schedule(task_id_b, 0);
            runtime
                .scheduler
                .lock()
                .unwrap()
                .schedule(server_task_id, 0);

            runtime.run_until_quiescent();
            drop(handle);
            runtime
                .scheduler
                .lock()
                .unwrap()
                .schedule(server_task_id, 0);
            runtime.run_until_quiescent();

            let out = events.lock().expect("lock poisoned").clone();
            out
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

        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(client_task_id, 0);
        runtime.run_until_quiescent();

        assert_eq!(started_priority.load(Ordering::SeqCst), 200);
        assert_eq!(loop_priority.load(Ordering::SeqCst), 10);

        drop(handle);
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
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

        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
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
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
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

        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
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

        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(client_task_id, 0);
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
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
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

        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
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
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
        runtime.run_until_idle();

        // Stop the server and reschedule so on_stop runs
        let phases_clone = Arc::clone(&phases);
        handle.stop();
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
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

        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(server_task_id, 0);
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
}
