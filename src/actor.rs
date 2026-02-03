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
//! let result = handle.join(&cx).await?;
//! assert_eq!(result.count, 15);
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

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
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActorId(TaskId);

impl ActorId {
    /// Create an actor ID from a task ID.
    #[must_use]
    pub const fn from_task(task_id: TaskId) -> Self {
        Self(task_id)
    }

    /// Returns the underlying task ID.
    #[must_use]
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
    fn new(state: ActorState) -> Self {
        Self {
            state: AtomicU8::new(Self::encode(state)),
        }
    }

    fn load(&self) -> ActorState {
        Self::decode(self.state.load(Ordering::Acquire))
    }

    fn store(&self, state: ActorState) {
        self.state.store(Self::encode(state), Ordering::Release);
    }

    const fn encode(state: ActorState) -> u8 {
        match state {
            ActorState::Created => 0,
            ActorState::Running => 1,
            ActorState::Stopping => 2,
            ActorState::Stopped => 3,
        }
    }

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
    actor_id: ActorId,
    owner: RegionId,
    mailbox: mpsc::Receiver<M>,
    state: Arc<ActorStateCell>,
    created_at: Time,
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
    inner: std::sync::Weak<std::sync::RwLock<CxInner>>,
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
    /// Sets the actor state to `Stopping` and requests cancellation so the
    /// actor loop will exit after the current message finishes processing.
    /// The actor will call `on_stop` before returning.
    ///
    /// This is identical to [`abort`](Self::abort) — both request cancellation
    /// and set the Stopping state. A future improvement could differentiate
    /// them by having `stop()` drain buffered messages first.
    pub fn stop(&self) {
        self.state.store(ActorState::Stopping);
        if let Some(inner) = self.inner.upgrade() {
            if let Ok(mut guard) = inner.write() {
                guard.cancel_requested = true;
            }
        }
    }

    /// Returns true if the actor has finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.receiver.is_ready()
    }

    /// Wait for the actor to finish and return its final state.
    ///
    /// Blocks until the actor loop completes (mailbox closed or cancelled),
    /// then returns the actor's final state or a join error.
    pub async fn join(&self, cx: &Cx) -> Result<A, JoinError> {
        self.receiver.recv(cx).await.unwrap_or_else(|_| {
            // The oneshot was dropped without sending — the actor task was
            // cancelled or the runtime shut down. Propagate the actual
            // cancel reason from the Cx if available; fall back to
            // parent-cancelled since this is typically a scope teardown.
            let reason = cx
                .cancel_reason()
                .unwrap_or_else(crate::types::CancelReason::parent_cancelled);
            Err(JoinError::Cancelled(reason))
        })
    }

    /// Request the actor to stop immediately by aborting its task.
    ///
    /// Sets `cancel_requested` on the actor's context, causing the actor loop
    /// to exit at the next cancellation check point. The actor will call
    /// `on_stop` before returning.
    ///
    /// Currently identical to [`stop`](Self::stop). A future improvement
    /// should differentiate them: `stop()` would drain buffered messages
    /// while `abort()` exits immediately.
    pub fn abort(&self) {
        self.state.store(ActorState::Stopping);
        if let Some(inner) = self.inner.upgrade() {
            if let Ok(mut guard) = inner.write() {
                guard.cancel_requested = true;
            }
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
        self.stopping || self.cx.is_cancel_requested()
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

/// Internal: runs the actor message loop.
///
/// This function is the core of the actor runtime. It:
/// 1. Calls `on_start`
/// 2. Receives and handles messages until the mailbox is closed or cancelled
/// 3. Drains remaining buffered messages (no silent drops)
/// 4. Calls `on_stop`
/// 5. Returns the actor state
async fn run_actor_loop<A: Actor>(mut actor: A, cx: Cx, cell: &ActorCell<A::Message>) -> A {
    use crate::tracing_compat::debug;

    cell.state.store(ActorState::Running);

    // Phase 1: Initialization
    cx.trace("actor::on_start");
    actor.on_start(&cx).await;

    // Phase 2: Message loop
    loop {
        // Check for cancellation
        if cx.is_cancel_requested() {
            cx.trace("actor::cancel_requested");
            break;
        }

        match cell.mailbox.recv(&cx).await {
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

    // Phase 3: Drain remaining buffered messages.
    // Two-phase mailbox guarantee: no message silently dropped. Every message
    // that was successfully sent (committed) into the mailbox will be handled
    // before the actor's on_stop runs. We cap the drain to the mailbox
    // capacity to avoid unbounded work if the mailbox is being filled
    // concurrently during shutdown.
    let drain_limit = cell.mailbox.capacity() as u64;
    let mut drained: u64 = 0;
    while let Ok(msg) = cell.mailbox.try_recv() {
        actor.handle(&cx, msg).await;
        drained += 1;
        if drained >= drain_limit {
            break;
        }
    }
    if drained > 0 {
        debug!(drained = drained, "actor::mailbox_drained");
        cx.trace("actor::mailbox_drained");
    }

    // Phase 4: Cleanup
    cx.trace("actor::on_stop");
    actor.on_stop(&cx).await;

    actor
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

        // Link Cx to TaskRecord
        if let Some(record) = state.tasks.get_mut(task_id.arena_index()) {
            record.set_cx_inner(child_cx.inner.clone());
            record.set_cx(child_cx.clone());
        }

        let cx_for_send = child_cx.clone();
        let inner_weak = Arc::downgrade(&child_cx.inner);
        let state_for_task = Arc::clone(&actor_state);

        let cell = ActorCell {
            actor_id,
            owner: self.region_id(),
            mailbox: msg_rx,
            state: Arc::clone(&actor_state),
            created_at: Time::ZERO,
        };

        // Create the actor loop future
        let wrapped = async move {
            let result = CatchUnwind(Box::pin(run_actor_loop(actor, child_cx, &cell))).await;
            match result {
                Ok(actor_final) => {
                    let _ = result_tx.send(&cx_for_send, Ok(actor_final));
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

        let handle = ActorHandle {
            actor_id,
            sender: msg_tx,
            state: actor_state,
            task_id,
            receiver: result_rx,
            inner: inner_weak,
        };

        Ok((handle, stored))
    }

    /// Spawns a supervised actor with automatic restart on failure.
    ///
    /// Unlike `spawn_actor`, this method takes a factory closure that can
    /// produce new actor instances for restarts. The mailbox persists across
    /// restarts, so messages sent during restart are buffered and processed
    /// by the new instance.
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
        );

        if let Some(record) = state.tasks.get_mut(task_id.arena_index()) {
            record.set_cx_inner(child_cx.inner.clone());
            record.set_cx(child_cx.clone());
        }

        let cx_for_send = child_cx.clone();
        let inner_weak = Arc::downgrade(&child_cx.inner);
        let region_id = self.region_id();
        let state_for_task = Arc::clone(&actor_state);

        let cell = ActorCell {
            actor_id,
            owner: self.region_id(),
            mailbox: msg_rx,
            state: Arc::clone(&actor_state),
            created_at: Time::ZERO,
        };

        let wrapped = async move {
            let result = run_supervised_loop(
                actor,
                &mut factory,
                child_cx,
                &cell,
                Supervisor::new(strategy),
                task_id,
                region_id,
            )
            .await;
            let _ = result_tx.send(&cx_for_send, result);
            state_for_task.store(ActorState::Stopped);
            Outcome::Ok(())
        };

        let stored = StoredTask::new_with_id(wrapped, task_id);

        let handle = ActorHandle {
            actor_id,
            sender: msg_tx,
            state: actor_state,
            task_id,
            receiver: result_rx,
            inner: inner_weak,
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
    cell: &ActorCell<A::Message>,
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
        let result = CatchUnwind(Box::pin(run_actor_loop(current_actor, cx.clone(), cell))).await;

        match result {
            Ok(actor_final) => {
                // Actor completed normally — no supervision needed
                return Ok(actor_final);
            }
            Err(payload) => {
                // Actor panicked — consult supervisor.
                // We report this as Failed (not Panicked) because actor crashes
                // are the expected failure mode for supervision. The Erlang/OTP
                // model restarts on crashes; Outcome::Panicked would always Stop.
                let msg = crate::cx::scope::payload_to_string(&payload);
                cx.trace("supervised_actor::failure");

                let outcome = Outcome::err(());
                let now = cx.timer_driver().map_or(0, |td| td.now().as_nanos());
                let decision = supervisor.on_failure(task_id, region_id, None, outcome, now);

                match decision {
                    SupervisionDecision::Restart { .. } => {
                        cx.trace("supervised_actor::restart");
                        current_actor = factory();
                    }
                    SupervisionDecision::Stop { .. } => {
                        cx.trace("supervised_actor::stopped");
                        return Err(JoinError::Panicked(crate::types::PanicPayload::new(msg)));
                    }
                    SupervisionDecision::Escalate { .. } => {
                        cx.trace("supervised_actor::escalated");
                        return Err(JoinError::Panicked(crate::types::PanicPayload::new(msg)));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::state::RuntimeState;
    use crate::types::policy::FailFast;
    use crate::types::Budget;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    /// Simple counter actor for testing.
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

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
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

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
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

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
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

    /// E2E: Supervised actor restarts on panic within budget.
    /// Actor panics on messages >= threshold, supervisor restarts it.
    /// After restart, actor processes subsequent normal messages.
    #[test]
    fn supervised_actor_restarts_on_panic() {
        use std::sync::atomic::AtomicU32;

        struct PanickingCounter {
            count: u64,
            panic_on: u64,
            final_count: Arc<AtomicU64>,
            restart_count: Arc<AtomicU32>,
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

        init_test("supervised_actor_restarts_on_panic");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let final_count = Arc::new(AtomicU64::new(u64::MAX));
        let restart_count = Arc::new(AtomicU32::new(0));
        let fc = final_count.clone();
        let rc = restart_count.clone();

        let strategy = crate::supervision::SupervisionStrategy::Restart(
            crate::supervision::RestartConfig::new(3, std::time::Duration::from_secs(60)),
        );

        let (handle, stored) = scope
            .spawn_supervised_actor(
                &mut runtime.state,
                &cx,
                move || {
                    rc.fetch_add(1, Ordering::SeqCst);
                    PanickingCounter {
                        count: 0,
                        panic_on: 999,
                        final_count: fc.clone(),
                        restart_count: rc.clone(),
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
        // 2. Panic trigger (actor panics, supervisor restarts)
        // 3. Normal message after restart (count += 1 on new instance)
        handle.try_send(1).unwrap();
        handle.try_send(999).unwrap(); // triggers panic
        handle.try_send(1).unwrap(); // processed by restarted actor

        // Drop handle to disconnect channel after the restarted actor processes messages
        drop(handle);

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
        runtime.run_until_quiescent();

        // Factory was called: once for initial + once for restart = fetch_add called twice
        // (first call was during spawn_supervised_actor, so count starts at 1;
        //  restart increments to 2)
        assert!(
            restart_count.load(Ordering::SeqCst) >= 2,
            "factory should have been called at least twice (initial + restart), got {}",
            restart_count.load(Ordering::SeqCst)
        );

        // After restart, actor processes msg=1, then stops => final_count=1
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            1,
            "restarted actor should have processed the post-panic message"
        );

        crate::test_complete!("supervised_actor_restarts_on_panic");
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

            runtime.scheduler.lock().unwrap().schedule(task_id, 0);
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
}
