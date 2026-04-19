//! Actor abstraction for region-owned, message-driven concurrency.
//!
//! Actors in Asupersync are region-owned tasks that process messages from a
//! bounded mailbox. They integrate with the runtime's structured concurrency
//! model:
//!
//! - **Region-owned**: Actors are spawned within a region and cannot outlive it.
//! - **Cancel-safe mailbox**: Messages use the two-phase reserve/send pattern.
//! - **Lifecycle hooks**: `on_start` and `on_stop` for initialization and cleanup.
//!
//! # Example
//!
//! ```ignore
//! struct Counter {
//!     count: u64,
//! }
//!
//! impl Actor for Counter {
//!     type Message = u64;
//!
//!     async fn handle(&mut self, _cx: &Cx, msg: u64) {
//!         self.count += msg;
//!     }
//! }
//!
//! // In a scope:
//! let (handle, stored) = scope.spawn_actor(
//!     &mut state, &cx, Counter { count: 0 }, 32,
//! )?;
//! state.store_spawned_task(handle.task_id(), stored);
//!
//! // Send messages:
//! handle.send(&cx, 5).await?;
//! handle.send(&cx, 10).await?;
//!
//! // Stop the actor:
//! handle.stop();
//! let result = (&mut handle).join(&cx).await?;
//! assert_eq!(result.count, 15);
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use crate::channel::mpsc;
use crate::channel::mpsc::SendError;
use crate::cx::Cx;
use crate::runtime::{JoinError, SpawnError};
use crate::types::{CxInner, Outcome, RegionId, TaskId, Time};

/// Unique identifier for an actor.
///
/// For now this is a thin wrapper around the actor task's `TaskId`, which already
/// provides arena + generation semantics. Keeping a distinct type avoids mixing
/// actor IDs with generic tasks at call sites.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ActorId(TaskId);

impl ActorId {
    /// Create an actor ID from a task ID.
    #[must_use]
    #[inline]
    pub const fn from_task(task_id: TaskId) -> Self {
        Self(task_id)
    }

    /// Returns the underlying task ID.
    #[must_use]
    #[inline]
    pub const fn task_id(self) -> TaskId {
        self.0
    }
}

impl std::fmt::Debug for ActorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ActorId").field(&self.0).finish()
    }
}

impl std::fmt::Display for ActorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Preserve the compact, deterministic formatting of TaskId while keeping
        // a distinct type at the API level.
        write!(f, "{}", self.0)
    }
}

/// Lifecycle state for an actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorState {
    /// Actor constructed but not yet started.
    Created,
    /// Actor is running and processing messages.
    Running,
    /// Actor is stopping (cancellation requested / mailbox closed).
    Stopping,
    /// Actor has stopped and will not process further messages.
    Stopped,
}

#[derive(Debug)]
struct ActorStateCell {
    state: AtomicU8,
}

impl ActorStateCell {
    #[inline]
    fn new(state: ActorState) -> Self {
        Self {
            state: AtomicU8::new(Self::encode(state)),
        }
    }

    #[inline]
    fn load(&self) -> ActorState {
        Self::decode(self.state.load(Ordering::Acquire))
    }

    #[inline]
    fn store(&self, state: ActorState) {
        self.state.store(Self::encode(state), Ordering::Release);
    }

    #[inline]
    const fn encode(state: ActorState) -> u8 {
        match state {
            ActorState::Created => 0,
            ActorState::Running => 1,
            ActorState::Stopping => 2,
            ActorState::Stopped => 3,
        }
    }

    #[inline]
    const fn decode(value: u8) -> ActorState {
        match value {
            0 => ActorState::Created,
            1 => ActorState::Running,
            2 => ActorState::Stopping,
            _ => ActorState::Stopped,
        }
    }
}

/// Internal runtime state for an actor.
///
/// This is intentionally lightweight and non-opinionated; higher-level actor
/// features (mailbox policies, supervision trees, etc.) can extend this.
struct ActorCell<M> {
    mailbox: mpsc::Receiver<M>,
    state: Arc<ActorStateCell>,
}

/// A message-driven actor that processes messages from a bounded mailbox.
///
/// Actors are the unit of stateful, message-driven concurrency. Each actor:
/// - Owns mutable state (`self`)
/// - Receives messages sequentially (no data races)
/// - Runs inside a region (structured lifetime)
///
/// # Cancel Safety
///
/// When an actor is cancelled (region close, explicit abort), the runtime:
/// 1. Closes the mailbox (no new messages accepted)
/// 2. Calls `on_stop` for cleanup
/// 3. Returns the actor state to the caller via `ActorHandle::join`
pub trait Actor: Send + 'static {
    /// The type of messages this actor can receive.
    type Message: Send + 'static;

    /// Called once when the actor starts, before processing any messages.
    ///
    /// Use this for initialization that requires the capability context.
    /// The default implementation does nothing.
    fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    /// Handle a single message.
    ///
    /// This is called sequentially for each message in the mailbox.
    /// The actor has exclusive access to its state during handling.
    fn handle(
        &mut self,
        cx: &Cx,
        msg: Self::Message,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// Called once when the actor is stopping, after the mailbox is drained.
    ///
    /// Use this for cleanup. The default implementation does nothing.
    fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

/// Handle to a running actor, used to send messages and manage its lifecycle.
///
/// The handle owns:
/// - A sender for the actor's mailbox
/// - A task handle for join/abort operations
///
/// When the handle is dropped, the mailbox sender is dropped, which causes
/// the actor loop to exit after processing remaining messages.
#[derive(Debug)]
pub struct ActorHandle<A: Actor> {
    actor_id: ActorId,
    sender: mpsc::Sender<A::Message>,
    state: Arc<ActorStateCell>,
    task_id: TaskId,
    receiver: crate::channel::oneshot::Receiver<Result<A, JoinError>>,
    inner: std::sync::Weak<parking_lot::RwLock<CxInner>>,
    completed: bool,
}

impl<A: Actor> ActorHandle<A> {
    /// Send a message to the actor using two-phase reserve/send.
    ///
    /// Returns an error if the actor has stopped or the mailbox is full.
    pub async fn send(&self, cx: &Cx, msg: A::Message) -> Result<(), SendError<A::Message>> {
        self.sender.send(cx, msg).await
    }

    /// Try to send a message without blocking.
    ///
    /// Returns `Err(SendError::Full(msg))` if the mailbox is full, or
    /// `Err(SendError::Disconnected(msg))` if the actor has stopped.
    pub fn try_send(&self, msg: A::Message) -> Result<(), SendError<A::Message>> {
        self.sender.try_send(msg)
    }

    /// Returns a lightweight, clonable reference for sending messages.
    #[must_use]
    pub fn sender(&self) -> ActorRef<A::Message> {
        ActorRef {
            actor_id: self.actor_id,
            sender: self.sender.clone(),
            state: Arc::clone(&self.state),
        }
    }

    /// Returns the actor's unique identifier.
    #[must_use]
    pub const fn actor_id(&self) -> ActorId {
        self.actor_id
    }

    /// Returns the task ID of the actor's underlying task.
    #[must_use]
    pub fn task_id(&self) -> crate::types::TaskId {
        self.task_id
    }

    /// Signals the actor to stop gracefully.
    ///
    /// Sets the actor state to `Stopping`. The actor will continue processing
    /// any currently buffered messages in its mailbox. Once the mailbox is
    /// empty, the actor loop will exit and call `on_stop` before returning.
    ///
    /// Unlike [`abort`](Self::abort), this does NOT immediately request
    /// cancellation, allowing the actor to drain pending work. The mailbox is
    /// sealed immediately so new sends fail fast instead of extending shutdown.
    pub fn stop(&self) {
        self.state.store(ActorState::Stopping);
        self.sender.close_receiver();
    }

    /// Returns true if the actor has finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.completed || self.receiver.is_ready() || self.receiver.is_closed()
    }

    /// Wait for the actor to finish and return its final state.
    ///
    /// Blocks until the actor loop completes (mailbox closed or cancelled),
    /// then returns the actor's final state or a join error.
    pub fn join<'a>(&'a mut self, _cx: &'a Cx) -> ActorJoinFuture<'a, A> {
        let cx_inner = self.inner.clone();
        let receiver = &mut self.receiver;
        let terminal_state = &mut self.completed;
        ActorJoinFuture {
            inner: receiver.recv_uninterruptible(),
            cx_inner,
            sender: self.sender.clone(),
            state: Arc::clone(&self.state),
            terminal_state,
            drop_abort_defused: false,
        }
    }

    /// Request the actor to stop immediately by aborting its task.
    ///
    /// Sets `cancel_requested` on the actor's context, causing the actor loop
    /// to exit at the next cancellation check point. The actor will call
    /// `on_stop` before returning.
    pub fn abort(&self) {
        self.state.store(ActorState::Stopping);
        self.sender.close_receiver();
        if let Some(inner) = self.inner.upgrade() {
            let cancel_waker = {
                let mut guard = inner.write();
                guard.cancel_requested = true;
                guard
                    .fast_cancel
                    .store(true, std::sync::atomic::Ordering::Release);
                if guard.cancel_reason.is_none() {
                    guard.cancel_reason = Some(crate::types::CancelReason::user("actor aborted"));
                }
                guard.cancel_waker.clone()
            };
            if let Some(waker) = cancel_waker {
                waker.wake_by_ref();
            }
        }
    }
}

/// Future returned by [`ActorHandle::join`].
///
/// This future aborts the actor if dropped before completion, ensuring correct
/// cleanup in races and timeouts.
pub struct ActorJoinFuture<'a, A: Actor> {
    inner: crate::channel::oneshot::RecvUninterruptibleFuture<'a, Result<A, JoinError>>,
    cx_inner: std::sync::Weak<parking_lot::RwLock<CxInner>>,
    sender: mpsc::Sender<A::Message>,
    state: Arc<ActorStateCell>,
    terminal_state: &'a mut bool,
    drop_abort_defused: bool,
}

impl<A: Actor> ActorJoinFuture<'_, A> {
    fn closed_reason(&self) -> crate::types::CancelReason {
        self.cx_inner
            .upgrade()
            .and_then(|inner| inner.read().cancel_reason.clone())
            .unwrap_or_else(|| crate::types::CancelReason::user("join channel closed"))
    }

    fn abort(&self) {
        self.state.store(ActorState::Stopping);
        self.sender.close_receiver();
        if let Some(inner) = self.cx_inner.upgrade() {
            let cancel_waker = {
                let mut guard = inner.write();
                guard.cancel_requested = true;
                guard
                    .fast_cancel
                    .store(true, std::sync::atomic::Ordering::Release);
                if guard.cancel_reason.is_none() {
                    guard.cancel_reason = Some(crate::types::CancelReason::user("actor aborted"));
                }
                guard.cancel_waker.clone()
            };
            if let Some(waker) = cancel_waker {
                waker.wake_by_ref();
            }
        }
    }
}

impl<A: Actor> std::future::Future for ActorJoinFuture<'_, A> {
    type Output = Result<A, JoinError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = &mut *self;
        if *this.terminal_state {
            return std::task::Poll::Ready(Err(JoinError::PolledAfterCompletion));
        }

        match Pin::new(&mut this.inner).poll(cx) {
            std::task::Poll::Ready(Ok(res)) => {
                *this.terminal_state = true;
                this.drop_abort_defused = true;
                std::task::Poll::Ready(res)
            }
            std::task::Poll::Ready(Err(crate::channel::oneshot::RecvError::Closed)) => {
                *this.terminal_state = true;
                this.drop_abort_defused = true;
                let reason = this.closed_reason();
                std::task::Poll::Ready(Err(JoinError::Cancelled(reason)))
            }
            std::task::Poll::Ready(Err(crate::channel::oneshot::RecvError::Cancelled)) => {
                unreachable!("RecvUninterruptibleFuture cannot return Cancelled");
            }
            std::task::Poll::Ready(Err(
                crate::channel::oneshot::RecvError::PolledAfterCompletion,
            )) => {
                unreachable!(
                    "JoinFuture guards repolls before polling the inner oneshot recv future"
                )
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<A: Actor> Drop for ActorJoinFuture<'_, A> {
    fn drop(&mut self) {
        if !*self.terminal_state && !self.drop_abort_defused {
            if self.inner.receiver_finished() {
                return;
            }
            self.abort();
        }
    }
}

/// A lightweight, clonable reference to an actor's mailbox.
///
/// Use this to send messages to an actor from multiple locations without
/// needing to share the `ActorHandle`.
#[derive(Debug)]
pub struct ActorRef<M> {
    actor_id: ActorId,
    sender: mpsc::Sender<M>,
    state: Arc<ActorStateCell>,
}

// Manual Clone impl without requiring M: Clone, since all fields are
// independently clonable (ActorId is Copy, Sender<M> clones without M: Clone,
// and Arc is always Clone).
impl<M> Clone for ActorRef<M> {
    fn clone(&self) -> Self {
        Self {
            actor_id: self.actor_id,
            sender: self.sender.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

impl<M: Send + 'static> ActorRef<M> {
    /// Send a message to the actor.
    pub async fn send(&self, cx: &Cx, msg: M) -> Result<(), SendError<M>> {
        self.sender.send(cx, msg).await
    }

    /// Reserve a slot in the mailbox (two-phase send: reserve -> commit).
    #[must_use]
    pub fn reserve<'a>(&'a self, cx: &'a Cx) -> mpsc::Reserve<'a, M> {
        self.sender.reserve(cx)
    }

    /// Try to send a message without blocking.
    pub fn try_send(&self, msg: M) -> Result<(), SendError<M>> {
        self.sender.try_send(msg)
    }

    /// Returns true if the actor has stopped (mailbox closed).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    /// Returns true if the actor is still alive (not fully stopped).
    ///
    /// Note: This is best-effort. The definitive shutdown signal is `ActorHandle::join()`.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.state.load() != ActorState::Stopped
    }

    /// Returns the actor's unique identifier.
    #[must_use]
    pub const fn actor_id(&self) -> ActorId {
        self.actor_id
    }
}

// ============================================================================
// ActorContext: Actor-Specific Capability Extension
// ============================================================================

/// Configuration for actor mailbox.
#[derive(Debug, Clone, Copy)]
pub struct MailboxConfig {
    /// Maximum number of messages the mailbox can hold.
    pub capacity: usize,
    /// Whether to use backpressure (block senders) or drop oldest messages.
    pub backpressure: bool,
}

impl Default for MailboxConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_MAILBOX_CAPACITY,
            backpressure: true,
        }
    }
}

impl MailboxConfig {
    /// Create a mailbox config with the specified capacity.
    #[must_use]
    pub const fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            backpressure: true,
        }
    }
}

/// Messages that can be sent to a supervisor about child lifecycle events.
#[derive(Debug, Clone)]
pub enum SupervisorMessage {
    /// A supervised child actor has failed.
    ChildFailed {
        /// The ID of the failed child.
        child_id: ActorId,
        /// Description of the failure.
        reason: String,
    },
    /// A supervised child actor has stopped normally.
    ChildStopped {
        /// The ID of the stopped child.
        child_id: ActorId,
    },
}

/// Actor-specific capability context extending [`Cx`].
///
/// Provides actors with access to:
/// - Self-reference for tell() patterns
/// - Child management for supervision
/// - Self-termination controls
/// - Parent reference for escalation
///
/// All [`Cx`] methods are available through [`Deref`].
///
/// # Example
///
/// ```ignore
/// async fn handle(&mut self, ctx: &ActorContext<'_, MyMessage>, msg: MyMessage) {
///     // Access Cx methods directly
///     if ctx.is_cancel_requested() {
///         return;
///     }
///
///     // Use actor-specific capabilities
///     let my_id = ctx.self_actor_id();
///     ctx.trace("handling message");
/// }
/// ```
pub struct ActorContext<'a, M: Send + 'static> {
    /// Underlying capability context.
    cx: &'a Cx,
    /// Reference to this actor's mailbox sender.
    self_ref: ActorRef<M>,
    /// This actor's unique identifier.
    actor_id: ActorId,
    /// Parent supervisor reference (None for root actors).
    parent: Option<ActorRef<SupervisorMessage>>,
    /// IDs of children currently supervised by this actor.
    children: Vec<ActorId>,
    /// Whether this actor has been requested to stop.
    stopping: bool,
}

#[allow(clippy::elidable_lifetime_names)]
impl<'a, M: Send + 'static> ActorContext<'a, M> {
    /// Create a new actor context.
    ///
    /// This is typically called internally by the actor runtime.
    #[must_use]
    pub fn new(
        cx: &'a Cx,
        self_ref: ActorRef<M>,
        actor_id: ActorId,
        parent: Option<ActorRef<SupervisorMessage>>,
    ) -> Self {
        Self {
            cx,
            self_ref,
            actor_id,
            parent,
            children: Vec::new(),
            stopping: false,
        }
    }

    /// Returns this actor's unique identifier.
    ///
    /// Unlike `self_ref()`, this avoids cloning the actor reference and is
    /// useful for logging, debugging, or identity comparisons.
    #[must_use]
    pub const fn self_actor_id(&self) -> ActorId {
        self.actor_id
    }

    /// Returns the underlying actor ID (alias for `self_actor_id`).
    #[must_use]
    pub const fn actor_id(&self) -> ActorId {
        self.actor_id
    }

    // ========================================================================
    // Child Management Methods
    // ========================================================================

    /// Register a child actor as supervised by this actor.
    ///
    /// Called internally when spawning supervised children.
    pub fn register_child(&mut self, child_id: ActorId) {
        self.children.push(child_id);
    }

    /// Unregister a child actor (after it has stopped).
    ///
    /// Returns true if the child was found and removed.
    pub fn unregister_child(&mut self, child_id: ActorId) -> bool {
        if let Some(pos) = self.children.iter().position(|&id| id == child_id) {
            self.children.swap_remove(pos);
            true
        } else {
            false
        }
    }

    /// Returns the list of currently supervised child actor IDs.
    #[must_use]
    pub fn children(&self) -> &[ActorId] {
        &self.children
    }

    /// Returns true if this actor has any supervised children.
    #[must_use]
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// Returns the number of supervised children.
    #[must_use]
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    // ========================================================================
    // Self-Termination Methods
    // ========================================================================

    /// Request this actor to stop gracefully.
    ///
    /// Sets the stopping flag. The actor loop will exit after the current
    /// message is processed and the mailbox is drained.
    pub fn stop_self(&mut self) {
        self.stopping = true;
    }

    /// Returns true if this actor has been requested to stop.
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        self.stopping
    }

    // ========================================================================
    // Parent Interaction Methods
    // ========================================================================

    /// Returns a reference to the parent supervisor, if any.
    ///
    /// Root actors spawned without supervision return `None`.
    #[must_use]
    pub fn parent(&self) -> Option<&ActorRef<SupervisorMessage>> {
        self.parent.as_ref()
    }

    /// Returns true if this actor has a parent supervisor.
    #[must_use]
    pub fn has_parent(&self) -> bool {
        self.parent.is_some()
    }

    /// Escalate an error to the parent supervisor.
    ///
    /// Sends a `SupervisorMessage::ChildFailed` to the parent if one exists.
    /// Does nothing if this is a root actor.
    pub async fn escalate(&self, reason: String) {
        if let Some(parent) = &self.parent {
            let msg = SupervisorMessage::ChildFailed {
                child_id: self.actor_id,
                reason,
            };
            // Best-effort: ignore send failures (parent may have stopped)
            let _ = parent.send(self.cx, msg).await;
        }
    }

    // ========================================================================
    // Cx Delegation Methods
    // ========================================================================

    /// Check for cancellation and return early if requested.
    ///
    /// This is a convenience method that checks both actor stopping
    /// and Cx cancellation.
    #[allow(clippy::result_large_err)]
    pub fn checkpoint(&self) -> Result<(), crate::error::Error> {
        if self.stopping {
            let reason = crate::types::CancelReason::user("actor stopping")
                .with_region(self.cx.region_id())
                .with_task(self.cx.task_id());
            return Err(crate::error::Error::cancelled(&reason));
        }
        self.cx.checkpoint()
    }

    /// Returns true if cancellation has been requested.
    ///
    /// Checks both actor stopping flag and Cx cancellation.
    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        self.stopping || self.cx.checkpoint().is_err()
    }

    /// Returns the current budget.
    #[must_use]
    pub fn budget(&self) -> crate::types::Budget {
        self.cx.budget()
    }

    /// Returns the deadline from the budget, if set.
    #[must_use]
    pub fn deadline(&self) -> Option<Time> {
        self.cx.budget().deadline
    }

    /// Emit a trace event.
    pub fn trace(&self, event: &str) {
        self.cx.trace(event);
    }

    /// Returns a clonable reference to this actor's mailbox.
    ///
    /// Use this to give other actors a way to send messages to this actor.
    /// The `ActorRef<M>` type is always Clone regardless of whether M is Clone.
    #[must_use]
    pub fn self_ref(&self) -> ActorRef<M> {
        self.self_ref.clone()
    }

    /// Returns a reference to the underlying Cx.
    #[must_use]
    pub const fn cx(&self) -> &Cx {
        self.cx
    }
}

impl<M: Send + 'static> std::ops::Deref for ActorContext<'_, M> {
    type Target = Cx;

    fn deref(&self) -> &Self::Target {
        self.cx
    }
}

impl<M: Send + 'static> std::fmt::Debug for ActorContext<'_, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorContext")
            .field("actor_id", &self.actor_id)
            .field("children", &self.children.len())
            .field("stopping", &self.stopping)
            .field("has_parent", &self.parent.is_some())
            .finish()
    }
}

/// The default mailbox capacity for actors.
pub const DEFAULT_MAILBOX_CAPACITY: usize = 64;

struct OnStopMaskGuard(Arc<parking_lot::RwLock<CxInner>>);

impl Drop for OnStopMaskGuard {
    fn drop(&mut self) {
        let mut g = self.0.write();
        g.mask_depth = g.mask_depth.saturating_sub(1);
    }
}

/// Internal: runs the actor message loop.
///
/// This function is the core of the actor runtime. It:
/// 1. Calls `on_start`
/// 2. Receives and handles messages until the mailbox is closed or cancelled
/// 3. Drains remaining buffered messages (no silent drops)
/// 4. Calls `on_stop`
/// 5. Returns the actor state
async fn run_actor_loop<A: Actor>(mut actor: A, cx: Cx, cell: &mut ActorCell<A::Message>) -> A {
    use crate::tracing_compat::debug;

    // Only transition to Running if stop() wasn't called before the actor started.
    // stop() sets Stopping before scheduling; we must honour that signal so the
    // poll_fn guard in the message loop can detect the pre-stop and break.
    if cell.state.load() != ActorState::Stopping {
        cell.state.store(ActorState::Running);
    }

    // Phase 1: Initialization
    // We always run on_start, even if cancelled or pre-stopped, because
    // it serves as the actor's initial setup and matches the expectation
    // that lifecycle hooks are symmetrically executed.
    cx.trace("actor::on_start");
    actor.on_start(&cx).await;

    // Phase 2: Message loop
    loop {
        // Check for cancellation
        if cx.checkpoint().is_err() {
            cx.trace("actor::cancel_requested");
            break;
        }

        let recv_result = std::future::poll_fn(|task_cx| {
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
            Ok(msg) => {
                actor.handle(&cx, msg).await;
            }
            Err(crate::channel::mpsc::RecvError::Disconnected) => {
                // All senders dropped - graceful shutdown
                cx.trace("actor::mailbox_disconnected");
                break;
            }
            Err(crate::channel::mpsc::RecvError::Cancelled) => {
                // Cancellation requested
                cx.trace("actor::recv_cancelled");
                break;
            }
            Err(crate::channel::mpsc::RecvError::Empty) => {
                // Shouldn't happen with recv() (only try_recv), but handle gracefully
                break;
            }
        }
    }

    cell.state.store(ActorState::Stopping);

    let is_aborted = cx.checkpoint().is_err();

    // Phase 3: Drain remaining buffered messages.
    // Two-phase mailbox guarantee: no message silently dropped (unless aborted).
    // We seal the mailbox to prevent any new reservations or commits, then
    // process remaining messages if gracefully stopped. If aborted, we just
    // empty the mailbox to drop the messages.
    cell.mailbox.close();

    if is_aborted {
        while let Ok(_msg) = cell.mailbox.try_recv() {}
    } else {
        let mut drained: u64 = 0;
        while let Ok(msg) = cell.mailbox.try_recv() {
            actor.handle(&cx, msg).await;
            drained += 1;
        }
        if drained > 0 {
            debug!(drained = drained, "actor::mailbox_drained");
            cx.trace("actor::mailbox_drained");
        }
    }

    // Phase 4: Cleanup — mask cancellation so on_stop runs to completion.
    // Without masking, an aborted actor's on_stop could observe a stale
    // cancel_requested=true and bail early via cx.checkpoint().

    cx.trace("actor::on_stop");
    let inner = cx.inner.clone();
    {
        let mut guard = inner.write();
        assert!(
            guard.mask_depth < crate::types::task_context::MAX_MASK_DEPTH,
            "mask depth exceeded MAX_MASK_DEPTH ({}) in actor::on_stop: \
             this violates INV-MASK-BOUNDED and prevents cancellation from ever \
             being observed. Reduce nesting of masked sections.",
            crate::types::task_context::MAX_MASK_DEPTH
        );
        guard.mask_depth += 1;
    }
    let mask_guard = OnStopMaskGuard(inner);
    actor.on_stop(&cx).await;
    drop(mask_guard);

    actor
}

fn actor_cancel_join_error(cx: &Cx) -> JoinError {
    JoinError::Cancelled(
        cx.cancel_reason()
            .unwrap_or_else(|| crate::types::CancelReason::user("actor supervision cancelled")),
    )
}

fn supervised_restart_timestamp(cx: &Cx) -> u64 {
    cx.timer_driver().map_or_else(
        || crate::time::wall_now().as_nanos(),
        |td| td.now().as_nanos(),
    )
}

async fn wait_supervised_restart_delay(cx: &Cx, delay: Duration) -> Result<(), JoinError> {
    if cx.checkpoint().is_err() {
        return Err(actor_cancel_join_error(cx));
    }
    if delay.is_zero() {
        return Ok(());
    }

    let now = cx
        .timer_driver()
        .map_or_else(crate::time::wall_now, |td| td.now());
    let mut sleeper = crate::time::sleep(now, delay);
    std::future::poll_fn(|task_cx| {
        if cx.checkpoint().is_err() {
            return std::task::Poll::Ready(Err(actor_cancel_join_error(cx)));
        }
        Pin::new(&mut sleeper).poll(task_cx).map(|()| Ok(()))
    })
    .await
}

fn join_result_to_task_outcome<A>(result: &Result<A, JoinError>) -> Outcome<(), ()> {
    match result {
        Ok(_) => Outcome::Ok(()),
        Err(JoinError::Cancelled(reason)) => Outcome::Cancelled(reason.clone()),
        Err(JoinError::Panicked(payload)) => Outcome::Panicked(payload.clone()),
        Err(JoinError::PolledAfterCompletion) => {
            panic!("actor task produced JoinError::PolledAfterCompletion")
        }
    }
}

// Extension for Scope to spawn actors
impl<P: crate::types::Policy> crate::cx::Scope<'_, P> {
    /// Spawns a new actor in this scope with the given mailbox capacity.
    ///
    /// The actor runs as a region-owned task. Messages are delivered through
    /// a bounded MPSC channel with two-phase send semantics.
    ///
    /// # Arguments
    ///
    /// * `state` - Runtime state for task creation
    /// * `cx` - Capability context
    /// * `actor` - The actor instance
    /// * `mailbox_capacity` - Bounded mailbox size
    ///
    /// # Returns
    ///
    /// A tuple of `(ActorHandle, StoredTask)`. The `StoredTask` must be
    /// registered with the runtime via `state.store_spawned_task()`.
    pub fn spawn_actor<A: Actor>(
        &self,
        state: &mut crate::runtime::state::RuntimeState,
        cx: &Cx,
        actor: A,
        mailbox_capacity: usize,
    ) -> Result<(ActorHandle<A>, crate::runtime::stored_task::StoredTask), SpawnError> {
        use crate::channel::oneshot;
        use crate::cx::scope::CatchUnwind;
        use crate::runtime::stored_task::StoredTask;
        use crate::tracing_compat::{debug, debug_span};

        // Create the actor's mailbox
        let (msg_tx, msg_rx) = mpsc::channel::<A::Message>(mailbox_capacity);

        // Create oneshot for returning the actor state
        let (result_tx, result_rx) = oneshot::channel::<Result<A, JoinError>>();

        // Create task record
        let task_id = self.create_task_record(state)?;
        let actor_id = ActorId::from_task(task_id);
        let actor_state = Arc::new(ActorStateCell::new(ActorState::Created));

        let _span = debug_span!(
            "actor_spawn",
            task_id = ?task_id,
            region_id = ?self.region_id(),
            mailbox_capacity = mailbox_capacity,
        )
        .entered();
        debug!(
            task_id = ?task_id,
            region_id = ?self.region_id(),
            mailbox_capacity = mailbox_capacity,
            "actor spawned"
        );

        // Create child context
        let (_, child_cx) = self.build_child_task_cx(state, cx, task_id);

        // Link Cx to TaskRecord
        if let Some(record) = state.task_mut(task_id) {
            record.set_cx_inner(child_cx.inner.clone());
            record.set_cx(child_cx.clone());
        }

        let cx_for_send = child_cx.clone();
        let inner_weak = Arc::downgrade(&child_cx.inner);
        let state_for_task = Arc::clone(&actor_state);

        let mut cell = ActorCell {
            mailbox: msg_rx,
            state: Arc::clone(&actor_state),
        };

        // Create the actor loop future
        let wrapped = async move {
            let result = CatchUnwind {
                inner: Box::pin(run_actor_loop(actor, child_cx, &mut cell)),
            }
            .await;
            let outcome = match result {
                Ok(actor_final) => {
                    let _ = result_tx.send(&cx_for_send, Ok(actor_final));
                    Outcome::Ok(())
                }
                Err(payload) => {
                    let msg = crate::cx::scope::payload_to_string(&payload);
                    let panic_payload = crate::types::PanicPayload::new(msg);
                    let _ = result_tx.send(
                        &cx_for_send,
                        Err(JoinError::Panicked(panic_payload.clone())),
                    );
                    Outcome::Panicked(panic_payload)
                }
            };
            state_for_task.store(ActorState::Stopped);
            outcome
        };

        let stored = StoredTask::new_with_id(wrapped, task_id);

        let handle = ActorHandle {
            actor_id,
            sender: msg_tx,
            state: actor_state,
            task_id,
            receiver: result_rx,
            inner: inner_weak,
            completed: false,
        };

        Ok((handle, stored))
    }

    /// Spawns a supervised actor with explicit supervision semantics.
    ///
    /// Unlike `spawn_actor`, this method takes a factory closure that can
    /// produce new actor instances for restarts. The mailbox persists across
    /// restarts, so messages sent while a restartable failure is being handled
    /// are buffered for the next instance.
    ///
    /// Because [`Actor`] has no explicit error return channel, supervised
    /// crashes are treated as restartable failures when the strategy is
    /// [`crate::supervision::SupervisionStrategy::Restart`]. If supervision
    /// ultimately stops or escalates, the original panic payload is still
    /// surfaced as `JoinError::Panicked`.
    ///
    /// # Arguments
    ///
    /// * `state` - Runtime state for task creation
    /// * `cx` - Capability context
    /// * `factory` - Closure that creates actor instances (called on each restart)
    /// * `strategy` - Supervision strategy (Stop, Restart, Escalate)
    /// * `mailbox_capacity` - Bounded mailbox size
    pub fn spawn_supervised_actor<A, F>(
        &self,
        state: &mut crate::runtime::state::RuntimeState,
        cx: &Cx,
        mut factory: F,
        strategy: crate::supervision::SupervisionStrategy,
        mailbox_capacity: usize,
    ) -> Result<(ActorHandle<A>, crate::runtime::stored_task::StoredTask), SpawnError>
    where
        A: Actor,
        F: FnMut() -> A + Send + 'static,
    {
        use crate::channel::oneshot;
        use crate::runtime::stored_task::StoredTask;
        use crate::supervision::Supervisor;
        use crate::tracing_compat::{debug, debug_span};

        let actor = factory();
        let (msg_tx, msg_rx) = mpsc::channel::<A::Message>(mailbox_capacity);
        let (result_tx, result_rx) = oneshot::channel::<Result<A, JoinError>>();
        let task_id = self.create_task_record(state)?;
        let actor_id = ActorId::from_task(task_id);
        let actor_state = Arc::new(ActorStateCell::new(ActorState::Created));

        let _span = debug_span!(
            "supervised_actor_spawn",
            task_id = ?task_id,
            region_id = ?self.region_id(),
            mailbox_capacity = mailbox_capacity,
        )
        .entered();
        debug!(
            task_id = ?task_id,
            region_id = ?self.region_id(),
            "supervised actor spawned"
        );

        let (_, child_cx) = self.build_child_task_cx(state, cx, task_id);

        if let Some(record) = state.task_mut(task_id) {
            record.set_cx_inner(child_cx.inner.clone());
            record.set_cx(child_cx.clone());
        }

        let cx_for_send = child_cx.clone();
        let inner_weak = Arc::downgrade(&child_cx.inner);
        let region_id = self.region_id();
        let state_for_task = Arc::clone(&actor_state);

        let mut cell = ActorCell {
            mailbox: msg_rx,
            state: Arc::clone(&actor_state),
        };

        let wrapped = async move {
            let result = run_supervised_loop(
                actor,
                &mut factory,
                child_cx,
                &mut cell,
                Supervisor::new(strategy),
                task_id,
                region_id,
            )
            .await;
            let outcome = join_result_to_task_outcome(&result).map_err(|_| ());
            let _ = result_tx.send(&cx_for_send, result);
            state_for_task.store(ActorState::Stopped);
            outcome
        };

        let stored = StoredTask::new_with_id(wrapped, task_id);

        let handle = ActorHandle {
            actor_id,
            sender: msg_tx,
            state: actor_state,
            task_id,
            receiver: result_rx,
            inner: inner_weak,
            completed: false,
        };

        Ok((handle, stored))
    }
}

/// Outcome of a supervised actor run.
#[derive(Debug)]
pub enum SupervisedOutcome {
    /// Actor stopped normally (no failure).
    Stopped,
    /// Actor stopped after restart budget exhaustion.
    RestartBudgetExhausted {
        /// Total restarts before budget was exhausted.
        total_restarts: u32,
    },
    /// Failure was escalated to parent region.
    Escalated,
}

/// Internal: runs a supervised actor loop with restart support.
///
/// The mailbox receiver is shared across restarts — messages sent while the
/// actor is restarting are buffered and processed by the new instance.
async fn run_supervised_loop<A, F>(
    initial_actor: A,
    factory: &mut F,
    cx: Cx,
    cell: &mut ActorCell<A::Message>,
    mut supervisor: crate::supervision::Supervisor,
    task_id: TaskId,
    region_id: RegionId,
) -> Result<A, JoinError>
where
    A: Actor,
    F: FnMut() -> A,
{
    use crate::cx::scope::CatchUnwind;
    use crate::supervision::SupervisionDecision;
    use crate::types::Outcome;

    let mut current_actor = initial_actor;

    loop {
        // Run the actor until it finishes (normally or via panic)
        let result = CatchUnwind {
            inner: Box::pin(run_actor_loop(current_actor, cx.clone(), cell)),
        }
        .await;

        match result {
            Ok(actor_final) => {
                // Actor completed normally — no supervision needed
                return Ok(actor_final);
            }
            Err(payload) => {
                let msg = crate::cx::scope::payload_to_string(&payload);
                let panic_payload = crate::types::PanicPayload::new(msg);
                cx.trace("supervised_actor::failure");

                // Explicit shutdown wins over restart policy. If the owner has
                // already requested stop/abort, a panic during mailbox drain or
                // on_stop is terminal and must not resurrect the actor.
                if cell.state.load() == ActorState::Stopping || cx.checkpoint().is_err() {
                    cx.trace("supervised_actor::shutdown_panic");
                    return Err(JoinError::Panicked(panic_payload));
                }

                // Actors do not have a typed `Err` path. A crash is therefore
                // the only recoverable failure signal available to the actor
                // supervision layer, so present it to the generic supervisor as
                // a restartable failure while preserving the original payload to
                // surface if supervision ultimately stops or escalates.
                let outcome = Outcome::Err(());
                let now = supervised_restart_timestamp(&cx);
                let decision = supervisor.on_failure(task_id, region_id, None, &outcome, now);

                match decision {
                    SupervisionDecision::Restart { delay, .. } => {
                        cx.trace("supervised_actor::restart");

                        // Graceful shutdown may arrive after the crash but
                        // before the delayed restart starts running. That stop
                        // must suppress the restart rather than instantiate a
                        // fresh actor during shutdown.
                        if cell.state.load() == ActorState::Stopping {
                            cx.trace("supervised_actor::restart_suppressed");
                            return Err(JoinError::Panicked(panic_payload));
                        }

                        // Apply backoff delay if the supervisor computed one.
                        if let Some(backoff) = delay {
                            wait_supervised_restart_delay(&cx, backoff).await?;
                        }

                        if cell.state.load() == ActorState::Stopping || cx.checkpoint().is_err() {
                            cx.trace("supervised_actor::restart_suppressed");
                            return Err(JoinError::Panicked(panic_payload));
                        }

                        // Reset actor state so the restarted actor enters
                        // Running instead of staying in Stopping (which
                        // would cause it to exit immediately on empty
                        // mailbox).
                        cell.state.store(ActorState::Created);
                        current_actor = factory();
                    }
                    SupervisionDecision::Stop { .. } => {
                        cx.trace("supervised_actor::stopped");
                        return Err(JoinError::Panicked(panic_payload));
                    }
                    SupervisionDecision::Escalate { .. } => {
                        cx.trace("supervised_actor::escalated");
                        return Err(JoinError::Panicked(panic_payload));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::macaroon::MacaroonToken;
    use crate::cx::registry::{RegistryCap, RegistryHandle};
    use crate::remote::{NodeId, RemoteCap};
    use crate::runtime::state::RuntimeState;
    use crate::security::key::AuthKey;
    use crate::types::Budget;
    use crate::types::SystemPressure;
    use crate::types::policy::FailFast;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn counting_waker(counter: Arc<std::sync::atomic::AtomicUsize>) -> Waker {
        struct CountingWaker {
            counter: Arc<std::sync::atomic::AtomicUsize>,
        }

        impl std::task::Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        Waker::from(Arc::new(CountingWaker { counter }))
    }

    /// Simple counter actor for testing.
    #[derive(Debug)]
    struct Counter {
        count: u64,
        started: bool,
        stopped: bool,
    }

    impl Counter {
        fn new() -> Self {
            Self {
                count: 0,
                started: false,
                stopped: false,
            }
        }
    }

    impl Actor for Counter {
        type Message = u64;

        fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.started = true;
            Box::pin(async {})
        }

        fn handle(&mut self, _cx: &Cx, msg: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.count += msg;
            Box::pin(async {})
        }

        fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.stopped = true;
            Box::pin(async {})
        }
    }

    fn assert_actor<A: Actor>() {}

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CapabilitySnapshot {
        same_registry: bool,
        same_remote: bool,
        same_io: bool,
        same_pressure: bool,
        same_macaroon: bool,
        has_timer: bool,
    }

    struct CapabilityProbeActor {
        snapshot: Arc<parking_lot::Mutex<Option<CapabilitySnapshot>>>,
        expected_registry: Arc<dyn RegistryCap>,
        expected_remote_node: String,
        expected_io: Arc<dyn crate::io::IoCap>,
        expected_pressure: Arc<SystemPressure>,
        expected_macaroon: Arc<MacaroonToken>,
    }

    impl Actor for CapabilityProbeActor {
        type Message = ();

        fn on_start(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let child_registry = cx
                .registry_handle()
                .expect("actor child Cx must inherit registry")
                .as_arc();
            let child_io = cx
                .io_cap_handle()
                .expect("actor child Cx must inherit io capability");
            let child_pressure = cx
                .pressure_handle()
                .expect("actor child Cx must inherit system pressure");
            let child_macaroon = cx
                .macaroon_handle()
                .expect("actor child Cx must inherit macaroon");
            let remote_node = cx
                .remote()
                .map(|remote| remote.local_node().as_str().to_owned());

            *self.snapshot.lock() = Some(CapabilitySnapshot {
                same_registry: Arc::ptr_eq(&child_registry, &self.expected_registry),
                same_remote: remote_node.as_deref() == Some(self.expected_remote_node.as_str()),
                same_io: Arc::ptr_eq(&child_io, &self.expected_io),
                same_pressure: Arc::ptr_eq(&child_pressure, &self.expected_pressure),
                same_macaroon: Arc::ptr_eq(&child_macaroon, &self.expected_macaroon),
                has_timer: cx.has_timer(),
            });

            Box::pin(async {})
        }

        fn handle(&mut self, _cx: &Cx, _msg: ()) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async {})
        }
    }

    fn capability_rich_parent_cx(
        runtime: &crate::lab::LabRuntime,
        region: crate::types::RegionId,
    ) -> (
        Cx,
        Arc<dyn RegistryCap>,
        Arc<dyn crate::io::IoCap>,
        Arc<SystemPressure>,
        Arc<MacaroonToken>,
    ) {
        let registry = crate::cx::NameRegistry::new();
        let registry_handle = RegistryHandle::new(Arc::new(registry));
        let registry_arc = registry_handle.as_arc();
        let io_cap: Arc<dyn crate::io::IoCap> = Arc::new(crate::io::LabIoCap::new());
        let pressure = Arc::new(SystemPressure::with_headroom(0.25));
        let token = MacaroonToken::mint(&AuthKey::from_seed(7), "scope:actor", "actor/tests");

        let parent_cx = Cx::new_with_drivers(
            region,
            crate::types::TaskId::new_for_test(77, 0),
            Budget::INFINITE,
            None,
            None,
            Some(Arc::clone(&io_cap)),
            runtime.state.timer_driver_handle(),
            None,
        )
        .with_registry_handle(Some(registry_handle))
        .with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("actor-origin")))
        .with_pressure(Arc::clone(&pressure))
        .with_macaroon(token);

        let macaroon = parent_cx
            .macaroon_handle()
            .expect("parent actor test Cx must retain macaroon");

        (parent_cx, registry_arc, io_cap, pressure, macaroon)
    }

    #[test]
    fn actor_trait_object_safety() {
        init_test("actor_trait_object_safety");

        // Verify Counter implements Actor with the right bounds
        assert_actor::<Counter>();

        crate::test_complete!("actor_trait_object_safety");
    }

    #[test]
    fn actor_handle_creation() {
        init_test("actor_handle_creation");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let result = scope.spawn_actor(&mut state, &cx, Counter::new(), 32);
        assert!(result.is_ok(), "spawn_actor should succeed");

        let (handle, stored) = result.unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Handle should have valid task ID
        let _tid = handle.task_id();

        // Actor should not be finished yet (not polled)
        assert!(!handle.is_finished());

        crate::test_complete!("actor_handle_creation");
    }

    #[test]
    fn spawn_actor_inherits_child_cx_capabilities() {
        init_test("spawn_actor_inherits_child_cx_capabilities");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);
        let (parent_cx, registry_arc, io_cap, pressure, macaroon) =
            capability_rich_parent_cx(&runtime, region);
        let snapshot = Arc::new(parking_lot::Mutex::new(None));

        let actor = CapabilityProbeActor {
            snapshot: Arc::clone(&snapshot),
            expected_registry: registry_arc,
            expected_remote_node: "actor-origin".to_string(),
            expected_io: io_cap,
            expected_pressure: pressure,
            expected_macaroon: macaroon,
        };

        let (handle, stored) = scope
            .spawn_actor(&mut runtime.state, &parent_cx, actor, 8)
            .expect("spawn actor");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        let observed = snapshot
            .lock()
            .clone()
            .expect("actor on_start should capture inherited capabilities");
        assert_eq!(
            observed,
            CapabilitySnapshot {
                same_registry: true,
                same_remote: true,
                same_io: true,
                same_pressure: true,
                same_macaroon: true,
                has_timer: true,
            }
        );

        drop(handle);
        runtime.run_until_quiescent();

        crate::test_complete!("spawn_actor_inherits_child_cx_capabilities");
    }

    #[test]
    fn spawn_supervised_actor_inherits_child_cx_capabilities() {
        init_test("spawn_supervised_actor_inherits_child_cx_capabilities");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);
        let (parent_cx, registry_arc, io_cap, pressure, macaroon) =
            capability_rich_parent_cx(&runtime, region);
        let snapshot = Arc::new(parking_lot::Mutex::new(None));

        let snapshot_for_factory = Arc::clone(&snapshot);
        let strategy = crate::supervision::SupervisionStrategy::Stop;
        let (handle, stored) = scope
            .spawn_supervised_actor(
                &mut runtime.state,
                &parent_cx,
                move || CapabilityProbeActor {
                    snapshot: Arc::clone(&snapshot_for_factory),
                    expected_registry: Arc::clone(&registry_arc),
                    expected_remote_node: "actor-origin".to_string(),
                    expected_io: Arc::clone(&io_cap),
                    expected_pressure: Arc::clone(&pressure),
                    expected_macaroon: Arc::clone(&macaroon),
                },
                strategy,
                8,
            )
            .expect("spawn supervised actor");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        let observed = snapshot
            .lock()
            .clone()
            .expect("supervised actor on_start should capture inherited capabilities");
        assert_eq!(
            observed,
            CapabilitySnapshot {
                same_registry: true,
                same_remote: true,
                same_io: true,
                same_pressure: true,
                same_macaroon: true,
                has_timer: true,
            }
        );

        drop(handle);
        runtime.run_until_quiescent();

        crate::test_complete!("spawn_supervised_actor_inherits_child_cx_capabilities");
    }

    #[test]
    fn actor_id_generation_distinct() {
        init_test("actor_id_generation_distinct");

        let id1 = ActorId::from_task(TaskId::new_for_test(1, 1));
        let id2 = ActorId::from_task(TaskId::new_for_test(1, 2));
        assert!(id1 != id2, "generation must distinguish actor reuse");

        crate::test_complete!("actor_id_generation_distinct");
    }

    #[test]
    fn actor_ref_is_cloneable() {
        init_test("actor_ref_is_cloneable");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_actor(&mut state, &cx, Counter::new(), 32)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Get multiple refs
        let ref1 = handle.sender();
        let ref2 = ref1.clone();

        // Actor identity is preserved across clones
        assert_eq!(ref1.actor_id(), handle.actor_id());
        assert_eq!(ref2.actor_id(), handle.actor_id());

        // Actor is alive at creation time (even before first poll)
        assert!(ref1.is_alive());
        assert!(ref2.is_alive());

        // Both should be open
        assert!(!ref1.is_closed());
        assert!(!ref2.is_closed());

        crate::test_complete!("actor_ref_is_cloneable");
    }

    // ---- E2E Actor Scenarios ----

    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// Observable counter actor: writes final count to shared state during on_stop.
    /// Used by E2E tests to verify actor behavior without needing join().
    struct ObservableCounter {
        count: u64,
        on_stop_count: Arc<AtomicU64>,
        started: Arc<AtomicBool>,
        stopped: Arc<AtomicBool>,
    }

    impl ObservableCounter {
        fn new(
            on_stop_count: Arc<AtomicU64>,
            started: Arc<AtomicBool>,
            stopped: Arc<AtomicBool>,
        ) -> Self {
            Self {
                count: 0,
                on_stop_count,
                started,
                stopped,
            }
        }
    }

    impl Actor for ObservableCounter {
        type Message = u64;

        fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.started.store(true, Ordering::SeqCst);
            Box::pin(async {})
        }

        fn handle(&mut self, _cx: &Cx, msg: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.count += msg;
            Box::pin(async {})
        }

        fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.on_stop_count.store(self.count, Ordering::SeqCst);
            self.stopped.store(true, Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    fn observable_state() -> (Arc<AtomicU64>, Arc<AtomicBool>, Arc<AtomicBool>) {
        (
            Arc::new(AtomicU64::new(u64::MAX)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// E2E: Actor processes all messages sent before channel disconnect.
    /// Verifies: messages delivered, on_start called, on_stop called.
    #[test]
    fn actor_processes_all_messages() {
        init_test("actor_processes_all_messages");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (on_stop_count, started, stopped) = observable_state();
        let actor = ObservableCounter::new(on_stop_count.clone(), started.clone(), stopped.clone());

        let (handle, stored) = scope
            .spawn_actor(&mut runtime.state, &cx, actor, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Pre-fill mailbox with 5 messages (each adding 1)
        for _ in 0..5 {
            handle.try_send(1).unwrap();
        }

        // Drop handle to disconnect channel — actor will process buffered
        // messages via recv, then see Disconnected and stop gracefully.
        drop(handle);

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        assert_eq!(
            on_stop_count.load(Ordering::SeqCst),
            5,
            "all messages processed"
        );
        assert!(started.load(Ordering::SeqCst), "on_start was called");
        assert!(stopped.load(Ordering::SeqCst), "on_stop was called");

        crate::test_complete!("actor_processes_all_messages");
    }

    /// E2E: Mailbox drain on cancellation.
    /// Pre-fills mailbox, cancels actor before it runs, verifies all messages
    /// are still processed during the drain phase (no silent drops).
    #[test]
    fn actor_drains_mailbox_on_cancel() {
        init_test("actor_drains_mailbox_on_cancel");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (on_stop_count, started, stopped) = observable_state();
        let actor = ObservableCounter::new(on_stop_count.clone(), started.clone(), stopped.clone());

        let (handle, stored) = scope
            .spawn_actor(&mut runtime.state, &cx, actor, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Pre-fill mailbox with 5 messages
        for _ in 0..5 {
            handle.try_send(1).unwrap();
        }

        // Cancel the actor BEFORE running.
        // The actor loop will: on_start → check cancel → break → drain → on_stop
        handle.stop();
        let stopped_ref = handle.sender();
        assert!(
            stopped_ref.is_closed(),
            "stop() seals the mailbox immediately"
        );
        assert!(
            matches!(handle.try_send(99), Err(SendError::Disconnected(99))),
            "stop() must reject new messages instead of extending shutdown"
        );

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        // All 5 messages processed during drain phase
        assert_eq!(
            on_stop_count.load(Ordering::SeqCst),
            5,
            "drain processed all messages"
        );
        assert!(started.load(Ordering::SeqCst), "on_start was called");
        assert!(stopped.load(Ordering::SeqCst), "on_stop was called");

        crate::test_complete!("actor_drains_mailbox_on_cancel");
    }

    /// E2E: ActorRef liveness tracks actor lifecycle (Created -> Stopping -> Stopped).
    #[test]
    fn actor_ref_is_alive_transitions() {
        init_test("actor_ref_is_alive_transitions");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (on_stop_count, started, stopped) = observable_state();
        let actor = ObservableCounter::new(on_stop_count.clone(), started.clone(), stopped.clone());

        let (handle, stored) = scope
            .spawn_actor(&mut runtime.state, &cx, actor, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        let actor_ref = handle.sender();
        assert!(actor_ref.is_alive(), "created actor should be alive");
        assert_eq!(actor_ref.actor_id(), handle.actor_id());

        handle.stop();
        assert!(actor_ref.is_alive(), "stopping actor is still alive");

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        assert!(
            handle.is_finished(),
            "actor should be finished after stop + run"
        );
        assert!(!actor_ref.is_alive(), "finished actor is not alive");

        // Sanity: the actor ran its hooks.
        assert!(started.load(Ordering::SeqCst), "on_start was called");
        assert!(stopped.load(Ordering::SeqCst), "on_stop was called");
        assert_ne!(
            on_stop_count.load(Ordering::SeqCst),
            u64::MAX,
            "on_stop_count updated"
        );

        crate::test_complete!("actor_ref_is_alive_transitions");
    }

    #[test]
    fn dropped_join_future_marks_actor_stopping_like_abort() {
        init_test("dropped_join_future_marks_actor_stopping_like_abort");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (on_stop_count, started, stopped) = observable_state();
        let actor = ObservableCounter::new(on_stop_count.clone(), started.clone(), stopped.clone());

        let (mut handle, stored) = scope
            .spawn_actor(&mut runtime.state, &cx, actor, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();
        assert_eq!(
            handle.state.load(),
            ActorState::Running,
            "actor should be running before join drop requests abort"
        );

        drop(handle.join(&cx));

        assert_eq!(
            handle.state.load(),
            ActorState::Stopping,
            "dropping join future should mirror ActorHandle::abort state transition"
        );
        assert!(
            matches!(handle.try_send(1), Err(SendError::Disconnected(1))),
            "join-drop abort must seal the mailbox immediately"
        );

        runtime.run_until_quiescent();
        assert!(
            handle.is_finished(),
            "actor should stop after join future drop"
        );
        assert!(started.load(Ordering::SeqCst), "on_start should have run");
        assert!(stopped.load(Ordering::SeqCst), "on_stop should have run");
        assert_eq!(
            on_stop_count.load(Ordering::SeqCst),
            0,
            "idle actor should stop without processing phantom messages"
        );

        crate::test_complete!("dropped_join_future_marks_actor_stopping_like_abort");
    }

    #[test]
    fn actor_stop_unblocks_pending_sender_with_disconnect() {
        init_test("actor_stop_unblocks_pending_sender_with_disconnect");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_actor(&mut state, &cx, Counter::new(), 1)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        handle.try_send(1).expect("fill mailbox");
        let sender = handle.sender();
        let mut send_fut = Box::pin(sender.send(&cx, 2));
        let wake_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = counting_waker(Arc::clone(&wake_count));
        let mut task_cx = Context::from_waker(&waker);

        let first_poll = send_fut.as_mut().poll(&mut task_cx);
        assert!(
            matches!(first_poll, Poll::Pending),
            "send should wait while the mailbox is full"
        );

        handle.stop();

        assert_eq!(
            wake_count.load(Ordering::SeqCst),
            1,
            "stop() must wake a sender blocked on mailbox capacity"
        );
        let second_poll = send_fut.as_mut().poll(&mut task_cx);
        assert!(
            matches!(second_poll, Poll::Ready(Err(SendError::Disconnected(2)))),
            "pending sender must fail fast once stop seals the mailbox"
        );

        crate::test_complete!("actor_stop_unblocks_pending_sender_with_disconnect");
    }

    /// E2E: Supervised actor crashes restart under Restart strategy.
    #[test]
    fn supervised_actor_panic_restarts_under_restart_strategy() {
        use std::sync::atomic::AtomicU32;

        #[derive(Debug)]
        struct PanickingCounter {
            count: u64,
            panic_on: u64,
            final_count: Arc<AtomicU64>,
        }

        impl Actor for PanickingCounter {
            type Message = u64;

            fn handle(
                &mut self,
                _cx: &Cx,
                msg: u64,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                assert!(msg != self.panic_on, "threshold exceeded: {msg}");
                self.count += msg;
                Box::pin(async {})
            }

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.final_count.store(self.count, Ordering::SeqCst);
                Box::pin(async {})
            }
        }

        init_test("supervised_actor_panic_restarts_under_restart_strategy");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let final_count = Arc::new(AtomicU64::new(u64::MAX));
        let restart_count = Arc::new(AtomicU32::new(0));
        let fc = final_count.clone();
        let rc = restart_count.clone();

        let strategy = crate::supervision::SupervisionStrategy::Restart(
            crate::supervision::RestartConfig::new(3, std::time::Duration::from_secs(60))
                .with_backoff(crate::supervision::BackoffStrategy::None),
        );

        let (mut handle, stored) = scope
            .spawn_supervised_actor(
                &mut runtime.state,
                &cx,
                move || {
                    rc.fetch_add(1, Ordering::SeqCst);
                    PanickingCounter {
                        count: 0,
                        panic_on: 999,
                        final_count: fc.clone(),
                    }
                },
                strategy,
                32,
            )
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Message sequence:
        // 1. Normal message (count += 1)
        // 2. Panic trigger
        // 3. Queued message that should run on the restarted actor instance
        handle.try_send(1).unwrap();
        handle.try_send(999).unwrap(); // triggers panic
        handle.try_send(1).unwrap();

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();
        handle.abort();
        runtime.run_until_quiescent();

        let join = futures_lite::future::block_on(handle.join(&cx));
        let actor = join.expect("aborting the restarted actor should still return final state");
        assert_eq!(
            restart_count.load(Ordering::SeqCst),
            2,
            "panic must trigger exactly one supervised restart, got {} factory calls",
            restart_count.load(Ordering::SeqCst)
        );
        assert_eq!(
            actor.count, 1,
            "restarted actor should keep the post-crash message count"
        );
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            1,
            "restarted actor should process the queued post-crash message before abort"
        );

        crate::test_complete!("supervised_actor_panic_restarts_under_restart_strategy");
    }

    #[test]
    fn supervised_restart_window_expires_without_timer_driver() {
        use std::thread;

        init_test("supervised_restart_window_expires_without_timer_driver");

        let cx = Cx::new(
            RegionId::testing_default(),
            TaskId::new_for_test(1, 1),
            Budget::INFINITE,
        );
        let mut supervisor =
            crate::supervision::Supervisor::new(crate::supervision::SupervisionStrategy::Restart(
                crate::supervision::RestartConfig::new(1, Duration::from_millis(2))
                    .with_backoff(crate::supervision::BackoffStrategy::None),
            ));
        let outcome = Outcome::Err(());
        let task_id = TaskId::new_for_test(2, 1);

        let first = supervisor.on_failure(
            task_id,
            RegionId::testing_default(),
            None,
            &outcome,
            supervised_restart_timestamp(&cx),
        );
        assert!(
            matches!(
                first,
                crate::supervision::SupervisionDecision::Restart { attempt: 1, .. }
            ),
            "first failure should allow a restart"
        );

        thread::sleep(Duration::from_millis(5));

        let second = supervisor.on_failure(
            task_id,
            RegionId::testing_default(),
            None,
            &outcome,
            supervised_restart_timestamp(&cx),
        );
        assert!(
            matches!(
                second,
                crate::supervision::SupervisionDecision::Restart { attempt: 1, .. }
            ),
            "wall-clock fallback must let the restart window expire without a timer driver"
        );

        crate::test_complete!("supervised_restart_window_expires_without_timer_driver");
    }

    #[test]
    fn supervised_actor_stop_prevents_restart_after_panic() {
        use std::sync::atomic::AtomicU32;

        #[derive(Debug)]
        struct StopThenPanicActor;

        impl Actor for StopThenPanicActor {
            type Message = ();

            fn handle(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                panic!("panic during shutdown");
            }
        }

        init_test("supervised_actor_stop_prevents_restart_after_panic");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let restart_count = Arc::new(AtomicU32::new(0));
        let rc = Arc::clone(&restart_count);
        let strategy = crate::supervision::SupervisionStrategy::Restart(
            crate::supervision::RestartConfig::new(3, Duration::from_secs(60))
                .with_backoff(crate::supervision::BackoffStrategy::None),
        );

        let (mut handle, stored) = scope
            .spawn_supervised_actor(
                &mut runtime.state,
                &cx,
                move || {
                    rc.fetch_add(1, Ordering::SeqCst);
                    StopThenPanicActor
                },
                strategy,
                8,
            )
            .expect("spawn supervised actor");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        handle.try_send(()).expect("queue panic message");
        handle.stop();

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        assert_eq!(
            restart_count.load(Ordering::SeqCst),
            1,
            "explicit stop must suppress supervised restarts"
        );

        let join = futures_lite::future::block_on(handle.join(&cx));
        match join {
            Err(JoinError::Panicked(payload)) => {
                assert_eq!(
                    payload.message(),
                    "panic during shutdown",
                    "shutdown panic should surface without restarting"
                );
            }
            other => panic!("expected shutdown panic without restart, got {other:?}"),
        }

        crate::test_complete!("supervised_actor_stop_prevents_restart_after_panic");
    }

    #[test]
    fn supervised_actor_stop_during_restart_backoff_prevents_new_instance() {
        use std::sync::atomic::AtomicU32;

        #[derive(Debug)]
        struct DelayedRestartActor {
            starts: Arc<AtomicU32>,
        }

        impl Actor for DelayedRestartActor {
            type Message = ();

            fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let starts = Arc::clone(&self.starts);
                Box::pin(async move {
                    starts.fetch_add(1, Ordering::SeqCst);
                })
            }

            fn handle(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                panic!("panic before delayed restart");
            }
        }

        init_test("supervised_actor_stop_during_restart_backoff_prevents_new_instance");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let factory_count = Arc::new(AtomicU32::new(0));
        let starts = Arc::new(AtomicU32::new(0));
        let fc = Arc::clone(&factory_count);
        let starts_for_factory = Arc::clone(&starts);
        let strategy = crate::supervision::SupervisionStrategy::Restart(
            crate::supervision::RestartConfig::new(3, Duration::from_secs(60)).with_backoff(
                crate::supervision::BackoffStrategy::Fixed(Duration::from_secs(5)),
            ),
        );

        let (mut handle, stored) = scope
            .spawn_supervised_actor(
                &mut runtime.state,
                &cx,
                move || {
                    fc.fetch_add(1, Ordering::SeqCst);
                    DelayedRestartActor {
                        starts: Arc::clone(&starts_for_factory),
                    }
                },
                strategy,
                8,
            )
            .expect("spawn supervised actor");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        handle.try_send(()).expect("queue panic message");

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();
        assert_eq!(
            runtime.pending_timer_count(),
            1,
            "supervised actor should be waiting on restart backoff"
        );

        handle.stop();
        let report = runtime.run_with_auto_advance();

        assert!(
            matches!(
                report.termination,
                crate::lab::AutoAdvanceTermination::Quiescent
            ),
            "runtime should quiesce after stop suppresses restart: {report:?}"
        );
        assert_eq!(
            factory_count.load(Ordering::SeqCst),
            1,
            "graceful stop during backoff must prevent a replacement actor from being constructed"
        );
        assert_eq!(
            starts.load(Ordering::SeqCst),
            1,
            "graceful stop during backoff must prevent restarted actor lifecycle hooks from running"
        );

        let join = futures_lite::future::block_on(handle.join(&cx));
        match join {
            Err(JoinError::Panicked(payload)) => {
                assert_eq!(
                    payload.message(),
                    "panic before delayed restart",
                    "original panic should surface when restart is suppressed"
                );
            }
            other => panic!(
                "expected original panic when stop suppresses delayed restart, got {other:?}"
            ),
        }

        crate::test_complete!("supervised_actor_stop_during_restart_backoff_prevents_new_instance");
    }

    #[test]
    fn spawn_actor_panic_surfaces_as_task_outcome() {
        init_test("spawn_actor_panic_surfaces_as_task_outcome");

        #[derive(Debug)]
        struct PanicActor;

        impl Actor for PanicActor {
            type Message = ();

            fn handle(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                panic!("actor boom");
            }
        }

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (mut handle, mut stored) = scope
            .spawn_actor(&mut state, &cx, PanicActor, 8)
            .expect("spawn actor");
        handle.try_send(()).expect("queue panic message");

        let waker = counting_waker(Arc::new(std::sync::atomic::AtomicUsize::new(0)));
        let mut poll_cx = Context::from_waker(&waker);
        match stored.poll(&mut poll_cx) {
            Poll::Ready(Outcome::Panicked(payload)) => {
                assert_eq!(payload.message(), "actor boom", "panic payload preserved");
            }
            other => panic!("panicking actor task must return Outcome::Panicked: {other:?}"),
        }

        let join = std::pin::pin!(handle.join(&cx));
        let mut join = join;
        match join.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Err(JoinError::Panicked(payload))) => {
                assert_eq!(
                    payload.message(),
                    "actor boom",
                    "join preserves panic payload"
                );
            }
            other => panic!("join must surface actor panic: {other:?}"),
        }

        crate::test_complete!("spawn_actor_panic_surfaces_as_task_outcome");
    }

    #[test]
    fn spawn_supervised_actor_panic_surfaces_as_task_outcome() {
        init_test("spawn_supervised_actor_panic_surfaces_as_task_outcome");

        #[derive(Debug)]
        struct PanicActor;

        impl Actor for PanicActor {
            type Message = ();

            fn handle(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                panic!("supervised actor boom");
            }
        }

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (mut handle, mut stored) = scope
            .spawn_supervised_actor(
                &mut state,
                &cx,
                || PanicActor,
                crate::supervision::SupervisionStrategy::Stop,
                8,
            )
            .expect("spawn supervised actor");
        handle.try_send(()).expect("queue panic message");

        let waker = counting_waker(Arc::new(std::sync::atomic::AtomicUsize::new(0)));
        let mut poll_cx = Context::from_waker(&waker);
        match stored.poll(&mut poll_cx) {
            Poll::Ready(Outcome::Panicked(payload)) => {
                assert_eq!(
                    payload.message(),
                    "supervised actor boom",
                    "panic payload preserved"
                );
            }
            other => {
                panic!("panicking supervised actor task must return Outcome::Panicked: {other:?}")
            }
        }

        let join = std::pin::pin!(handle.join(&cx));
        let mut join = join;
        match join.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Err(JoinError::Panicked(payload))) => {
                assert_eq!(
                    payload.message(),
                    "supervised actor boom",
                    "join preserves panic payload"
                );
            }
            other => panic!("join must surface supervised actor panic: {other:?}"),
        }

        crate::test_complete!("spawn_supervised_actor_panic_surfaces_as_task_outcome");
    }

    #[test]
    fn supervised_restart_delay_honors_cancellation() {
        init_test("supervised_restart_delay_honors_cancellation");

        let cx = Cx::for_testing();
        cx.cancel_fast(crate::types::CancelKind::User);

        let mut delay = std::pin::pin!(wait_supervised_restart_delay(
            &cx,
            std::time::Duration::from_secs(60),
        ));
        let first_poll =
            futures_lite::future::block_on(futures_lite::future::poll_once(&mut delay));

        match first_poll {
            Some(Err(JoinError::Cancelled(reason))) => {
                assert_eq!(reason.kind, crate::types::CancelKind::User);
            }
            other => panic!("expected immediate cancellation, got {other:?}"),
        }

        crate::test_complete!("supervised_restart_delay_honors_cancellation");
    }

    /// E2E: Deterministic replay — same seed produces same actor execution.
    #[test]
    fn actor_deterministic_replay() {
        fn run_scenario(seed: u64) -> u64 {
            let config = crate::lab::LabConfig::new(seed);
            let mut runtime = crate::lab::LabRuntime::new(config);
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let cx: Cx = Cx::for_testing();
            let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

            let (on_stop_count, started, stopped) = observable_state();
            let actor = ObservableCounter::new(on_stop_count.clone(), started, stopped);

            let (handle, stored) = scope
                .spawn_actor(&mut runtime.state, &cx, actor, 32)
                .unwrap();
            let task_id = handle.task_id();
            runtime.state.store_spawned_task(task_id, stored);

            for i in 1..=10 {
                handle.try_send(i).unwrap();
            }
            drop(handle);

            runtime.scheduler.lock().schedule(task_id, 0);
            runtime.run_until_quiescent();

            on_stop_count.load(Ordering::SeqCst)
        }

        init_test("actor_deterministic_replay");

        // Run the same scenario twice with the same seed
        let result1 = run_scenario(0xDEAD_BEEF);
        let result2 = run_scenario(0xDEAD_BEEF);

        assert_eq!(
            result1, result2,
            "deterministic replay: same seed → same result"
        );
        assert_eq!(result1, 55, "sum of 1..=10");

        crate::test_complete!("actor_deterministic_replay");
    }

    // ---- ActorContext Tests ----

    #[test]
    fn actor_context_self_reference() {
        init_test("actor_context_self_reference");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_actor(&mut state, &cx, Counter::new(), 32)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Create an ActorContext using the handle's sender
        let actor_ref = handle.sender();
        let actor_id = handle.actor_id();
        let ctx: ActorContext<'_, u64> = ActorContext::new(&cx, actor_ref, actor_id, None);

        // Test self_actor_id() - doesn't require Clone
        assert_eq!(ctx.self_actor_id(), actor_id);
        assert_eq!(ctx.actor_id(), actor_id);

        crate::test_complete!("actor_context_self_reference");
    }

    #[test]
    fn actor_context_child_management() {
        init_test("actor_context_child_management");

        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let mut ctx = ActorContext::new(&cx, actor_ref, actor_id, None);

        // Initially no children
        assert!(!ctx.has_children());
        assert_eq!(ctx.child_count(), 0);
        assert!(ctx.children().is_empty());

        // Register children
        let child1 = ActorId::from_task(TaskId::new_for_test(2, 1));
        let child2 = ActorId::from_task(TaskId::new_for_test(3, 1));

        ctx.register_child(child1);
        assert!(ctx.has_children());
        assert_eq!(ctx.child_count(), 1);

        ctx.register_child(child2);
        assert_eq!(ctx.child_count(), 2);

        // Unregister child
        assert!(ctx.unregister_child(child1));
        assert_eq!(ctx.child_count(), 1);

        // Unregistering non-existent child returns false
        assert!(!ctx.unregister_child(child1));

        crate::test_complete!("actor_context_child_management");
    }

    #[test]
    fn actor_context_stopping() {
        init_test("actor_context_stopping");

        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let mut ctx = ActorContext::new(&cx, actor_ref, actor_id, None);

        // Initially not stopping
        assert!(!ctx.is_stopping());
        assert!(ctx.checkpoint().is_ok());

        // Request stop
        ctx.stop_self();
        assert!(ctx.is_stopping());
        assert!(ctx.checkpoint().is_err());
        assert!(cx.checkpoint().is_ok());
        assert!(ctx.is_cancel_requested());

        crate::test_complete!("actor_context_stopping");
    }

    #[test]
    fn actor_context_parent_none() {
        init_test("actor_context_parent_none");

        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let ctx = ActorContext::new(&cx, actor_ref, actor_id, None);

        // Root actor has no parent
        assert!(!ctx.has_parent());
        assert!(ctx.parent().is_none());

        crate::test_complete!("actor_context_parent_none");
    }

    #[test]
    fn actor_context_cx_delegation() {
        init_test("actor_context_cx_delegation");

        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let ctx = ActorContext::new(&cx, actor_ref, actor_id, None);

        // Test Cx delegation via Deref
        let _budget = ctx.budget();
        ctx.trace("test_event");

        // Test cx() accessor
        let _cx_ref = ctx.cx();

        crate::test_complete!("actor_context_cx_delegation");
    }

    #[test]
    fn actor_context_debug() {
        init_test("actor_context_debug");

        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let ctx = ActorContext::new(&cx, actor_ref, actor_id, None);

        // Debug formatting should work
        let debug_str = format!("{ctx:?}");
        assert!(debug_str.contains("ActorContext"));
        assert!(debug_str.contains("actor_id"));

        crate::test_complete!("actor_context_debug");
    }

    // ---- Invariant Tests ----

    /// Invariant: `ActorStateCell` encode/decode roundtrips correctly for all
    /// valid states, and unknown u8 values map to `Stopped` (fail-safe).
    #[test]
    fn actor_state_cell_encode_decode_roundtrip() {
        init_test("actor_state_cell_encode_decode_roundtrip");

        let states = [
            ActorState::Created,
            ActorState::Running,
            ActorState::Stopping,
            ActorState::Stopped,
        ];

        for &state in &states {
            let cell = ActorStateCell::new(state);
            let loaded = cell.load();
            crate::assert_with_log!(loaded == state, "roundtrip", state, loaded);
        }

        // Unknown values (4+) should map to Stopped (fail-safe).
        for raw in 4_u8..=10 {
            let decoded = ActorStateCell::decode(raw);
            let is_stopped = decoded == ActorState::Stopped;
            crate::assert_with_log!(is_stopped, "unknown u8 -> Stopped", true, is_stopped);
        }

        crate::test_complete!("actor_state_cell_encode_decode_roundtrip");
    }

    /// Invariant: `MailboxConfig::default()` has documented capacity and
    /// backpressure enabled.
    #[test]
    fn mailbox_config_defaults() {
        init_test("mailbox_config_defaults");

        let config = MailboxConfig::default();
        crate::assert_with_log!(
            config.capacity == DEFAULT_MAILBOX_CAPACITY,
            "default capacity",
            DEFAULT_MAILBOX_CAPACITY,
            config.capacity
        );
        crate::assert_with_log!(
            config.backpressure,
            "backpressure enabled by default",
            true,
            config.backpressure
        );

        let custom = MailboxConfig::with_capacity(8);
        crate::assert_with_log!(
            custom.capacity == 8,
            "custom capacity",
            8usize,
            custom.capacity
        );
        crate::assert_with_log!(
            custom.backpressure,
            "with_capacity enables backpressure",
            true,
            custom.backpressure
        );

        crate::test_complete!("mailbox_config_defaults");
    }

    /// Invariant: `try_send` on a full mailbox returns an error without
    /// blocking, and the message is recoverable from the error.
    #[test]
    fn actor_try_send_full_mailbox_returns_error() {
        init_test("actor_try_send_full_mailbox_returns_error");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        // Create actor with capacity=2 mailbox.
        let (handle, stored) = scope
            .spawn_actor(&mut state, &cx, Counter::new(), 2)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Fill the mailbox.
        let ok1 = handle.try_send(1).is_ok();
        crate::assert_with_log!(ok1, "first send ok", true, ok1);
        let ok2 = handle.try_send(2).is_ok();
        crate::assert_with_log!(ok2, "second send ok", true, ok2);

        // Third send should fail — mailbox full.
        let result = handle.try_send(3);
        let is_full = result.is_err();
        crate::assert_with_log!(is_full, "third send fails (full)", true, is_full);

        crate::test_complete!("actor_try_send_full_mailbox_returns_error");
    }

    /// Invariant: `ActorContext` with a parent supervisor set exposes it
    /// and reports `has_parent() == true`.
    #[test]
    fn actor_context_with_parent_supervisor() {
        init_test("actor_context_with_parent_supervisor");

        let cx: Cx = Cx::for_testing();

        // Create parent supervisor channel.
        let (parent_sender, _parent_receiver) = mpsc::channel::<SupervisorMessage>(8);
        let parent_id = ActorId::from_task(TaskId::new_for_test(10, 1));
        let parent_ref = ActorRef {
            actor_id: parent_id,
            sender: parent_sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        // Create child actor context with parent.
        let (child_sender, _child_receiver) = mpsc::channel::<u64>(32);
        let child_id = ActorId::from_task(TaskId::new_for_test(20, 1));
        let child_ref = ActorRef {
            actor_id: child_id,
            sender: child_sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let ctx = ActorContext::new(&cx, child_ref, child_id, Some(parent_ref));

        let has_parent = ctx.has_parent();
        crate::assert_with_log!(has_parent, "has parent", true, has_parent);

        let parent = ctx.parent().expect("parent should be Some");
        let parent_id_matches = parent.actor_id() == parent_id;
        crate::assert_with_log!(
            parent_id_matches,
            "parent id matches",
            true,
            parent_id_matches
        );

        crate::test_complete!("actor_context_with_parent_supervisor");
    }

    // ---- Pure Data Type Tests (no runtime needed) ----

    #[test]
    fn actor_id_debug_format() {
        let id = ActorId::from_task(TaskId::new_for_test(5, 3));
        let dbg = format!("{id:?}");
        assert!(dbg.contains("ActorId"), "{dbg}");
    }

    #[test]
    fn actor_id_display_delegates_to_task_id() {
        let tid = TaskId::new_for_test(7, 2);
        let aid = ActorId::from_task(tid);
        assert_eq!(format!("{aid}"), format!("{tid}"));
    }

    #[test]
    fn actor_id_from_task_roundtrip() {
        let tid = TaskId::new_for_test(3, 1);
        let aid = ActorId::from_task(tid);
        assert_eq!(aid.task_id(), tid);
    }

    #[test]
    fn actor_id_copy_clone() {
        let id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let copied = id; // Copy
        let cloned = id;
        assert_eq!(id, copied);
        assert_eq!(id, cloned);
    }

    #[test]
    fn actor_id_hash_consistency() {
        use crate::util::DetHasher;
        use std::hash::{Hash, Hasher};

        let id1 = ActorId::from_task(TaskId::new_for_test(4, 2));
        let id2 = ActorId::from_task(TaskId::new_for_test(4, 2));
        assert_eq!(id1, id2);

        let mut h1 = DetHasher::default();
        let mut h2 = DetHasher::default();
        id1.hash(&mut h1);
        id2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish(), "equal IDs must hash equal");
    }

    #[test]
    fn actor_state_debug_all_variants() {
        for (state, expected) in [
            (ActorState::Created, "Created"),
            (ActorState::Running, "Running"),
            (ActorState::Stopping, "Stopping"),
            (ActorState::Stopped, "Stopped"),
        ] {
            let dbg = format!("{state:?}");
            assert_eq!(dbg, expected, "ActorState::{expected}");
        }
    }

    #[test]
    fn actor_state_clone_copy_eq() {
        let s = ActorState::Running;
        let copied = s;
        let cloned = s;
        assert_eq!(s, copied);
        assert_eq!(s, cloned);
    }

    #[test]
    fn actor_state_exhaustive_inequality() {
        let all = [
            ActorState::Created,
            ActorState::Running,
            ActorState::Stopping,
            ActorState::Stopped,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn actor_state_cell_sequential_transitions() {
        let cell = ActorStateCell::new(ActorState::Created);
        assert_eq!(cell.load(), ActorState::Created);

        cell.store(ActorState::Running);
        assert_eq!(cell.load(), ActorState::Running);

        cell.store(ActorState::Stopping);
        assert_eq!(cell.load(), ActorState::Stopping);

        cell.store(ActorState::Stopped);
        assert_eq!(cell.load(), ActorState::Stopped);
    }

    #[test]
    fn supervisor_message_debug_child_failed() {
        let msg = SupervisorMessage::ChildFailed {
            child_id: ActorId::from_task(TaskId::new_for_test(1, 1)),
            reason: "panicked".to_string(),
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("ChildFailed"), "{dbg}");
        assert!(dbg.contains("panicked"), "{dbg}");
    }

    #[test]
    fn supervisor_message_debug_child_stopped() {
        let msg = SupervisorMessage::ChildStopped {
            child_id: ActorId::from_task(TaskId::new_for_test(2, 1)),
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("ChildStopped"), "{dbg}");
    }

    #[test]
    fn supervisor_message_clone() {
        let msg = SupervisorMessage::ChildFailed {
            child_id: ActorId::from_task(TaskId::new_for_test(1, 1)),
            reason: "boom".to_string(),
        };
        let cloned = msg.clone();
        let (a, b) = (format!("{msg:?}"), format!("{cloned:?}"));
        assert_eq!(a, b);
    }

    #[test]
    fn supervised_outcome_debug_all_variants() {
        let variants: Vec<SupervisedOutcome> = vec![
            SupervisedOutcome::Stopped,
            SupervisedOutcome::RestartBudgetExhausted { total_restarts: 5 },
            SupervisedOutcome::Escalated,
        ];
        for v in &variants {
            let dbg = format!("{v:?}");
            assert!(!dbg.is_empty());
        }
        assert!(format!("{variants0:?}", variants0 = variants[0]).contains("Stopped"));
        assert!(format!("{variants1:?}", variants1 = variants[1]).contains('5'));
        assert!(format!("{variants2:?}", variants2 = variants[2]).contains("Escalated"));
    }

    #[test]
    fn mailbox_config_debug_clone_copy() {
        let cfg = MailboxConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("MailboxConfig"), "{dbg}");
        assert!(dbg.contains("64"), "{dbg}");

        let copied = cfg;
        let cloned = cfg;
        assert_eq!(copied.capacity, cfg.capacity);
        assert_eq!(cloned.backpressure, cfg.backpressure);
    }

    #[test]
    fn mailbox_config_zero_capacity() {
        let cfg = MailboxConfig::with_capacity(0);
        assert_eq!(cfg.capacity, 0);
        assert!(cfg.backpressure);
    }

    #[test]
    fn mailbox_config_max_capacity() {
        let cfg = MailboxConfig::with_capacity(usize::MAX);
        assert_eq!(cfg.capacity, usize::MAX);
    }

    #[test]
    fn default_mailbox_capacity_is_64() {
        assert_eq!(DEFAULT_MAILBOX_CAPACITY, 64);
    }

    #[test]
    fn actor_context_duplicate_child_registration() {
        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let mut ctx = ActorContext::new(&cx, actor_ref, actor_id, None);
        let child = ActorId::from_task(TaskId::new_for_test(2, 1));

        ctx.register_child(child);
        ctx.register_child(child); // duplicate
        assert_eq!(ctx.child_count(), 2, "register_child does not dedup");

        // Unregister removes first occurrence
        assert!(ctx.unregister_child(child));
        assert_eq!(ctx.child_count(), 1, "one copy remains");
        assert!(ctx.unregister_child(child));
        assert_eq!(ctx.child_count(), 0);
        assert!(!ctx.unregister_child(child), "nothing left to remove");
    }

    #[test]
    fn actor_context_stop_self_is_idempotent() {
        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let mut ctx = ActorContext::new(&cx, actor_ref, actor_id, None);
        ctx.stop_self();
        assert!(ctx.is_stopping());
        ctx.stop_self(); // idempotent
        assert!(ctx.is_stopping());
    }

    #[test]
    fn actor_context_self_ref_returns_working_ref() {
        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let ctx = ActorContext::new(&cx, actor_ref, actor_id, None);
        let self_ref = ctx.self_ref();
        assert_eq!(self_ref.actor_id(), actor_id);
        assert!(self_ref.is_alive());
    }

    #[test]
    fn actor_context_deadline_reflects_budget() {
        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let ctx = ActorContext::new(&cx, actor_ref, actor_id, None);
        // for_testing() Cx has INFINITE budget, which has no deadline
        assert!(ctx.deadline().is_none());
    }

    #[test]
    fn actor_handle_debug() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_actor(&mut state, &cx, Counter::new(), 32)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        let dbg = format!("{handle:?}");
        assert!(dbg.contains("ActorHandle"), "{dbg}");
    }

    #[test]
    fn actor_handle_second_join_fails_closed() {
        init_test("actor_handle_second_join_fails_closed");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (mut handle, stored) = scope
            .spawn_actor(&mut runtime.state, &cx, Counter::new(), 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        handle.stop();
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();
        assert!(handle.is_finished(), "stopped actor should report finished");

        let final_state = futures_lite::future::block_on(handle.join(&cx)).expect("first join");
        assert_eq!(final_state.count, 0, "join should return final actor state");

        let second = futures_lite::future::block_on(handle.join(&cx));
        assert!(
            matches!(second, Err(JoinError::PolledAfterCompletion)),
            "second join must fail closed, got {second:?}"
        );

        crate::test_complete!("actor_handle_second_join_fails_closed");
    }

    #[test]
    fn actor_ref_debug() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_actor(&mut state, &cx, Counter::new(), 32)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        let actor_ref = handle.sender();
        let dbg = format!("{actor_ref:?}");
        assert!(dbg.contains("ActorRef"), "{dbg}");
    }

    #[test]
    fn actor_state_cell_debug() {
        let cell = ActorStateCell::new(ActorState::Running);
        let dbg = format!("{cell:?}");
        assert!(dbg.contains("ActorStateCell"), "{dbg}");
    }

    #[test]
    fn actor_id_clone_copy_eq_hash() {
        use std::collections::HashSet;

        let id = ActorId::from_task(TaskId::new_for_test(1, 0));
        let dbg = format!("{id:?}");
        assert!(dbg.contains("ActorId"));

        let id2 = id;
        assert_eq!(id, id2);

        // Copy
        let id3 = id;
        assert_eq!(id, id3);

        // Hash
        let mut set = HashSet::new();
        set.insert(id);
        set.insert(ActorId::from_task(TaskId::new_for_test(2, 0)));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn actor_state_debug_clone_copy_eq() {
        let s = ActorState::Running;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Running"));

        let s2 = s;
        assert_eq!(s, s2);

        let s3 = s;
        assert_eq!(s, s3);

        assert_ne!(ActorState::Created, ActorState::Stopped);
    }

    #[test]
    fn mailbox_config_debug_clone_copy_default() {
        let c = MailboxConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("MailboxConfig"));

        let c2 = c;
        assert_eq!(c2.capacity, c.capacity);
        assert_eq!(c2.backpressure, c.backpressure);

        // Copy
        let c3 = c;
        assert_eq!(c3.capacity, c.capacity);
    }
}
