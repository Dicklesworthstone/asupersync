//! Actor abstraction for region-owned, message-driven concurrency.
//!
//! Actors in Asupersync are region-owned tasks that process messages from a
//! bounded mailbox. They integrate with the runtime's structured concurrency
//! model:
//!
//! - **Region-owned**: Actors are spawned within a region and cannot outlive it.
//! - **Bounded mailbox**: `try_send` never waits; `send` waits for capacity,
//!   and a `send` future dropped while it waits drops its message.
//!   `ActorRef::reserve` is the two-phase reserve/commit that keeps the
//!   message in the caller's hands until a slot is secured.
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
    /// The task waiting out a supervised restart backoff, woken by a stop.
    stop_waker: parking_lot::Mutex<Option<std::task::Waker>>,
}

impl ActorStateCell {
    #[inline]
    fn new(state: ActorState) -> Self {
        Self {
            state: AtomicU8::new(Self::encode(state)),
            stop_waker: parking_lot::Mutex::new(None),
        }
    }

    /// Stores `Stopping` and wakes a supervised restart backoff waiting on it.
    fn request_stop(&self) {
        self.store(ActorState::Stopping);
        let waiter = self.stop_waker.lock().take();
        if let Some(waker) = waiter {
            waker.wake();
        }
    }

    /// Registers the task that a later [`Self::request_stop`] must wake.
    fn register_stop_waker(&self, waker: &std::task::Waker) {
        let mut slot = self.stop_waker.lock();
        if !slot
            .as_ref()
            .is_some_and(|current| current.will_wake(waker))
        {
            *slot = Some(waker.clone());
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

    /// Atomically compare and swap state from `current` to `new`.
    /// Returns true if the swap succeeded, false otherwise.
    #[inline]
    fn compare_and_swap(&self, current: ActorState, new: ActorState) -> bool {
        self.state
            .compare_exchange(
                Self::encode(current),
                Self::encode(new),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
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

impl<M> Drop for ActorCell<M> {
    // The normal exits drain the mailbox. Messages still buffered when the
    // actor's task ends some other way (an abort during a restart backoff, a
    // crash the supervisor stops on, a handler panic in an unsupervised actor)
    // used to drop with the receiver: a panicking message destructor became
    // the task's panic, replacing its real outcome, and a second one aborted
    // the process. Drop them here one at a time, each panic contained.
    fn drop(&mut self) {
        self.mailbox.close();
        while let Ok(msg) = self.mailbox.try_recv() {
            discard_contained(msg);
        }
    }
}

/// Drops one buffered message, containing a panicking destructor; returns
/// whether it dropped cleanly. A caught payload is leaked, because dropping
/// it can panic too.
fn discard_contained<M>(msg: M) -> bool {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(msg))) {
        Ok(()) => true,
        Err(payload) => {
            forget_contained_drop_panic(payload);
            false
        }
    }
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
/// Dropping the handle drops its mailbox sender but does not stop the actor.
/// The actor exits after its remaining messages only once every sender is
/// gone, including each [`ActorRef`] and any live join future. Until then it
/// keeps running in its region, so a `join` without [`stop`](Self::stop),
/// [`abort`](Self::abort) or cancellation does not finish.
#[derive(Debug)]
pub struct ActorHandle<A: Actor> {
    actor_id: ActorId,
    sender: mpsc::Sender<A::Message>,
    state: Arc<ActorStateCell>,
    task_id: TaskId,
    receiver: crate::channel::oneshot::Receiver<Result<A, JoinError>>,
    inner: std::sync::Weak<parking_lot::RwLock<CxInner>>,
    completed: bool,
    /// The actor task's runtime handle when it was spawned with
    /// [`Cx::spawn_actor`]. Admission assigns the task's id and context after
    /// the spawn returns, so the task id, abort and join resolve through it.
    task: Option<crate::runtime::TaskHandle<()>>,
}

impl<A: Actor> ActorHandle<A> {
    /// Send a message to the actor, waiting for mailbox capacity.
    ///
    /// Returns an error if the actor has stopped, or with the message if the
    /// caller is cancelled while waiting. If this future is dropped while it
    /// waits, the message is dropped with it; [`try_send`](Self::try_send)
    /// never waits, and [`ActorRef::reserve`] (via [`sender`](Self::sender))
    /// keeps the message until a slot is secured.
    pub async fn send(&self, cx: &Cx, msg: A::Message) -> Outcome<(), SendError<A::Message>> {
        match self.sender.send(cx, msg).await {
            Ok(()) => Outcome::ok(()),
            Err(e) => Outcome::err(e),
        }
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
    ///
    /// For an actor spawned with [`Cx::spawn_actor`] this is the provisional
    /// spawn id until the runtime admits the task, and the task's runtime id
    /// afterwards, as for
    /// [`TaskHandle::task_id`](crate::runtime::TaskHandle::task_id).
    #[must_use]
    pub fn task_id(&self) -> crate::types::TaskId {
        self.task
            .as_ref()
            .map_or(self.task_id, crate::runtime::TaskHandle::task_id)
    }

    /// Signals the actor to stop gracefully.
    ///
    /// Sets the actor state to `Stopping`. The actor will continue processing
    /// any currently buffered messages in its mailbox. Once the mailbox is
    /// empty, the actor loop will exit and call `on_stop` before returning.
    ///
    /// If this actor is a supervised actor currently waiting out a restart
    /// backoff, the backoff timer is cancelled immediately, restart is
    /// suppressed, and any messages buffered in the mailbox when the stop lands
    /// are dropped with the mailbox without being processed by a new instance.
    ///
    /// Unlike [`abort`](Self::abort), this does NOT immediately request
    /// cancellation, allowing the actor to drain pending work. The mailbox is
    /// sealed immediately so new sends fail fast instead of extending shutdown.
    pub fn stop(&self) {
        self.state.request_stop();
        self.sender.close_receiver();
    }

    /// Returns true if the actor has finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.completed
            || ((self.receiver.is_ready() || self.receiver.is_closed())
                && self
                    .task
                    .as_ref()
                    .is_none_or(crate::runtime::TaskHandle::is_finished))
    }

    /// Wait for the actor to finish and return its final state.
    ///
    /// Blocks until the actor loop completes (mailbox closed or cancelled),
    /// then returns the actor's final state or a join error. For an actor
    /// spawned with [`Cx::spawn_actor`], the join also waits for the runtime
    /// to retire the actor task, as
    /// [`TaskHandle::join`](crate::runtime::TaskHandle::join) does.
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
            task: self.task.as_mut(),
            task_exit: None,
        }
    }

    /// Request the actor to stop immediately by aborting its task.
    ///
    /// Sets `cancel_requested` on the actor's context, causing the actor loop
    /// to exit at the next cancellation check point. The actor will call
    /// `on_stop` before returning.
    pub fn abort(&self) {
        self.state.request_stop();
        self.sender.close_receiver();
        if let Some(inner) = self.inner.upgrade() {
            let cancel_wakers = {
                let mut guard = inner.write();
                guard.set_cancel_requested(true);
                if guard.cancel_reason.is_none() {
                    guard.cancel_reason = Some(crate::types::CancelReason::user("actor aborted"));
                }
                guard.cancel_waker_snapshot()
            };
            for waker in cancel_wakers {
                waker.wake_by_ref();
            }
        } else if let Some(task) = &self.task {
            task.abort_with_reason(crate::types::CancelReason::user("actor aborted"));
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
    /// The actor task's runtime handle, for a natively spawned actor.
    task: Option<&'a mut crate::runtime::TaskHandle<()>>,
    /// Set once that task has retired: the task's join error, if any.
    task_exit: Option<Option<JoinError>>,
}

impl<A: Actor> ActorJoinFuture<'_, A> {
    fn closed_reason(&self) -> crate::types::CancelReason {
        self.cx_inner
            .upgrade()
            .and_then(|inner| inner.read().cancel_reason.clone())
            .unwrap_or_else(|| crate::types::CancelReason::user("join channel closed"))
    }

    fn abort(&self) {
        self.state.request_stop();
        self.sender.close_receiver();
        if let Some(inner) = self.cx_inner.upgrade() {
            let cancel_wakers = {
                let mut guard = inner.write();
                guard.set_cancel_requested(true);
                if guard.cancel_reason.is_none() {
                    guard.cancel_reason = Some(crate::types::CancelReason::user("actor aborted"));
                }
                guard.cancel_waker_snapshot()
            };
            for waker in cancel_wakers {
                waker.wake_by_ref();
            }
        } else if let Some(task) = self.task.as_deref() {
            task.abort_with_reason(crate::types::CancelReason::user("actor aborted"));
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
        // A natively spawned actor publishes its final state before its task
        // retires. Wait for the retirement first, so a joiner never observes
        // the actor finished while the runtime still counts its task live.
        if this.task_exit.is_none()
            && let Some(task) = this.task.as_deref_mut()
        {
            match task.poll_join(cx) {
                std::task::Poll::Ready(exit) => this.task_exit = Some(exit.err()),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
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
                // A native actor task that ended without publishing (its
                // spawn was denied, or the runtime shut down) reports why.
                if let Some(Some(exit)) = this.task_exit.take() {
                    return std::task::Poll::Ready(Err(exit));
                }
                let reason = this.closed_reason();
                std::task::Poll::Ready(Err(JoinError::Cancelled(reason)))
            }
            std::task::Poll::Ready(Err(crate::channel::oneshot::RecvError::Cancelled)) => {
                unreachable!(
                    "RecvUninterruptibleFuture does not consult Cx cancellation and only resolves \
                     to Ok(value), Closed, or PolledAfterCompletion"
                );
            }
            std::task::Poll::Ready(Err(
                crate::channel::oneshot::RecvError::PolledAfterCompletion,
            )) => {
                unreachable!(
                    "ActorJoinFuture sets terminal_state before returning Ready, so a repoll \
                     fails closed before the inner oneshot future can be polled again"
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
    /// Send a message to the actor, waiting for mailbox capacity.
    ///
    /// If this future is dropped while it waits, the message is dropped with
    /// it; [`reserve`](Self::reserve) keeps the message until a slot is
    /// secured.
    pub async fn send(&self, cx: &Cx, msg: M) -> Outcome<(), SendError<M>> {
        match self.sender.send(cx, msg).await {
            Ok(()) => Outcome::ok(()),
            Err(e) => Outcome::err(e),
        }
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
    /// Reserved: no spawn API reads it; a full actor mailbox never evicts a message.
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
/// No spawn API hands one to an actor yet (handlers get `&Cx`). It offers:
/// - Self-reference for tell() patterns
/// - Child management for supervision
/// - Self-termination controls
/// - Parent reference for escalation
///
/// All [`Cx`] methods are available through [`std::ops::Deref`].
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
    /// The runtime does not call this; code that supervises children records them.
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
    /// Sets the flag this context's `checkpoint`, `is_stopping` and `is_cancel_requested`
    /// report. No actor loop reads it: spawned actors get `&Cx`, not a context.
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

async fn catch_graceful_drain_handler<A: Actor>(
    actor: &mut A,
    cx: &Cx,
    msg: A::Message,
) -> std::thread::Result<()> {
    use crate::cx::scope::CatchUnwind;

    // The async wrapper is intentional: `Actor::handle` may panic either while
    // constructing its future or while that future is polled.
    CatchUnwind {
        inner: async { actor.handle(cx, msg).await },
    }
    .await
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
    // Use compare_and_swap to avoid TOCTOU race between load() and store().
    cell.state
        .compare_and_swap(ActorState::Created, ActorState::Running);

    // Phase 1: Initialization
    // We always run on_start, even if cancelled or pre-stopped, because
    // it serves as the actor's initial setup and matches the expectation
    // that lifecycle hooks are symmetrically executed.
    cx.trace("actor::on_start");
    actor.on_start(&cx).await;

    // Phase 2: Message loop with fairness yielding
    // br-asupersync-foa8ir: Add periodic yielding to prevent mailbox starvation
    let mut messages_processed = 0u32;
    const YIELD_INTERVAL: u32 = 8; // Yield every 8 messages for fairness
    let mut pending_drain_message = None;
    let mut graceful_drain_panic = None;

    loop {
        // Check for cancellation
        if cx.checkpoint().is_err() {
            cx.trace("actor::cancel_requested");
            break;
        }

        // Once graceful stop is visible, move all remaining delivery into the
        // explicit drain phase. That phase preserves the first handler panic
        // while continuing to invoke the buffered FIFO tail.
        if cell.state.load() == ActorState::Stopping {
            cx.trace("actor::graceful_drain_requested");
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
                // stop() can race with a ready receive after the loop-top state
                // check. Retain the value for the drain instead of invoking an
                // unprotected shutdown handler on the main-loop path.
                if cell.state.load() == ActorState::Stopping {
                    pending_drain_message = Some(msg);
                    cx.trace("actor::graceful_drain_requested");
                    break;
                }
                actor.handle(&cx, msg).await;

                // Yield periodically to maintain fairness with other tasks.
                // Merely checking the budget is not a scheduling point: a
                // continuously ready mailbox can otherwise monopolize its
                // worker indefinitely.
                messages_processed += 1;
                if messages_processed >= YIELD_INTERVAL {
                    messages_processed = 0;
                    cx.trace("actor::yield_after_ready_batch");
                    crate::runtime::yield_now().await;
                }
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

    let discard_buffered_message = |msg| {
        if !discard_contained(msg) {
            cx.trace("actor::message_drop_panicked_on_abort");
        }
    };

    if is_aborted {
        if let Some(msg) = pending_drain_message {
            discard_buffered_message(msg);
        }
        while let Ok(msg) = cell.mailbox.try_recv() {
            discard_buffered_message(msg);
        }
    } else {
        let mut drained: u64 = 0;
        let mut drain_yield_counter = 0u32;
        loop {
            // An abort or region cancel that lands during the drain ends it
            // like one that landed before it: the buffered tail is dropped.
            if cx.checkpoint().is_err() {
                cx.trace("actor::drain_cancelled");
                if let Some(msg) = pending_drain_message.take() {
                    discard_buffered_message(msg);
                }
                while let Ok(msg) = cell.mailbox.try_recv() {
                    discard_buffered_message(msg);
                }
                break;
            }
            let msg = match pending_drain_message.take() {
                Some(msg) => msg,
                None => match cell.mailbox.try_recv() {
                    Ok(msg) => msg,
                    Err(_) => break,
                },
            };

            if let Err(payload) = catch_graceful_drain_handler(&mut actor, &cx, msg).await {
                cx.trace("actor::handler_panicked_during_drain");
                if graceful_drain_panic.is_none() {
                    graceful_drain_panic = Some(payload);
                }
            }
            drained += 1;

            // br-asupersync-foa8ir: Yield during drain to prevent starvation.
            drain_yield_counter += 1;
            if drain_yield_counter >= YIELD_INTERVAL {
                drain_yield_counter = 0;
                cx.trace("actor::yield_during_drain");
                crate::runtime::yield_now().await;
            }
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
        // Enforce mask depth cap to prevent overflow and infinite recursion
        // This maintains INV-MASK-BOUNDED invariant in both debug and release builds
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
    if let Some(drain_panic) = graceful_drain_panic {
        use crate::cx::scope::CatchUnwind;

        let cleanup = CatchUnwind {
            inner: async { actor.on_stop(&cx).await },
        }
        .await;
        drop(mask_guard);
        if cleanup.is_err() {
            cx.trace("actor::on_stop_panicked_after_drain_panic");
        }
        std::panic::resume_unwind(drain_panic);
    } else {
        actor.on_stop(&cx).await;
        drop(mask_guard);
    }

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

#[inline]
fn try_commit_supervised_restart(state: &ActorStateCell) -> bool {
    state.compare_and_swap(ActorState::Running, ActorState::Created)
}

/// Waits out a supervised restart backoff. Cancellation fails the wait; a
/// stop requested meanwhile ends it early (`Ok`), and the caller's restart
/// commit then sees `Stopping` and suppresses the restart.
async fn wait_supervised_restart_delay(
    cx: &Cx,
    state: &ActorStateCell,
    delay: Duration,
) -> Outcome<(), JoinError> {
    if cx.checkpoint().is_err() {
        return Outcome::err(actor_cancel_join_error(cx));
    }
    if delay.is_zero() {
        return Outcome::ok(());
    }

    let mut sleeper = cx.timer_driver().map_or_else(
        || crate::time::sleep(crate::time::wall_now(), delay),
        |driver| {
            let delay_nanos = u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX);
            let deadline = driver.now().saturating_add_nanos(delay_nanos);
            crate::time::Sleep::with_timer_driver(deadline, driver)
        },
    );
    std::future::poll_fn(|task_cx| {
        if cx.checkpoint().is_err() {
            return std::task::Poll::Ready(Outcome::err(actor_cancel_join_error(cx)));
        }
        // Register before checking, so a stop that lands in between wakes us.
        state.register_stop_waker(task_cx.waker());
        if state.load() == ActorState::Stopping {
            return std::task::Poll::Ready(Outcome::ok(()));
        }
        Pin::new(&mut sleeper)
            .poll(task_cx)
            .map(|()| Outcome::ok(()))
    })
    .await
}

fn join_result_to_task_outcome<A>(result: &Result<A, JoinError>) -> Outcome<(), ()> {
    match result {
        Ok(_) => Outcome::Ok(()),
        Err(JoinError::Cancelled(reason)) => Outcome::Cancelled(reason.clone()),
        Err(JoinError::Panicked(payload)) => Outcome::Panicked(payload.clone()),
        Err(JoinError::PolledAfterCompletion) => {
            // br-supervision-fix.1 — Return error instead of panicking to preserve
            // process isolation. PolledAfterCompletion indicates a runtime bug but
            // should not crash the supervision tree.
            Outcome::Err(())
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
    /// # Panics
    ///
    /// Panics if `mailbox_capacity == 0`. Channel capacity must be non-zero.
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
        let region_id = self.region_id();

        // Create child context
        let (_, child_cx) = self.build_child_task_cx(state, cx, task_id);

        // Link Cx to TaskRecord
        if let Some(record) = state.task_mut(task_id) {
            record.set_cx_inner(child_cx.inner.clone());
            record.set_cx(child_cx.clone());
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
        let state_for_task = Arc::clone(&actor_state);

        let mut cell = ActorCell {
            mailbox: msg_rx,
            state: Arc::clone(&actor_state),
        };

        // Create the actor loop future
        let wrapped = async move {
            spawn_effects.dispatch();
            let result = CatchUnwind {
                inner: Box::pin(async move {
                    {
                        let _span = debug_span!(
                            "actor_spawn",
                            task_id = ?task_id,
                            region_id = ?region_id,
                            mailbox_capacity = mailbox_capacity,
                        )
                        .entered();
                        debug!(
                            task_id = ?task_id,
                            region_id = ?region_id,
                            mailbox_capacity = mailbox_capacity,
                            "actor spawned"
                        );
                    }
                    run_actor_loop(actor, child_cx, &mut cell).await
                }),
            }
            .await;
            state_for_task.store(ActorState::Stopped);
            match result {
                Ok(actor_final) => {
                    let _ = result_tx.send_blocking(Ok(actor_final));
                    Outcome::Ok(())
                }
                Err(payload) => {
                    let msg = crate::cx::scope::payload_to_string(&payload);
                    std::mem::forget(payload);
                    let panic_payload = crate::types::PanicPayload::new(msg);
                    let _ =
                        result_tx.send_blocking(Err(JoinError::Panicked(panic_payload.clone())));
                    Outcome::Panicked(panic_payload)
                }
            }
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
            task: None,
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
    ///
    /// # Panics
    ///
    /// Panics if `mailbox_capacity == 0`. Channel capacity must be non-zero.
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

        let (msg_tx, msg_rx) = mpsc::channel::<A::Message>(mailbox_capacity);
        let (result_tx, result_rx) = oneshot::channel::<Result<A, JoinError>>();
        let task_id = self.create_task_record(state)?;
        let actor_id = ActorId::from_task(task_id);
        let actor_state = Arc::new(ActorStateCell::new(ActorState::Created));
        let region_id = self.region_id();

        let (_, child_cx) = self.build_child_task_cx(state, cx, task_id);

        if let Some(record) = state.task_mut(task_id) {
            record.set_cx_inner(child_cx.inner.clone());
            record.set_cx(child_cx.clone());
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
        let state_for_task = Arc::clone(&actor_state);

        let mut cell = ActorCell {
            mailbox: msg_rx,
            state: Arc::clone(&actor_state),
        };

        let wrapped = async move {
            spawn_effects.dispatch();
            let result = match (crate::cx::scope::CatchUnwind {
                inner: Box::pin(async move {
                    {
                        let _span = debug_span!(
                            "supervised_actor_spawn",
                            task_id = ?task_id,
                            region_id = ?region_id,
                            mailbox_capacity = mailbox_capacity,
                        )
                        .entered();
                        debug!(
                            task_id = ?task_id,
                            region_id = ?region_id,
                            "supervised actor spawned"
                        );
                    }
                    let actor = factory();
                    run_supervised_loop(
                        actor,
                        &mut factory,
                        child_cx,
                        &mut cell,
                        Supervisor::new(strategy)
                            .with_max_evidence_entries(Supervisor::DEFAULT_ACTOR_EVIDENCE_CAPACITY),
                        task_id,
                        region_id,
                    )
                    .await
                }),
            })
            .await
            {
                Ok(result) => result,
                Err(payload) => {
                    let message = crate::cx::scope::payload_to_string(&payload);
                    std::mem::forget(payload);
                    Err(JoinError::Panicked(crate::types::PanicPayload::new(
                        message,
                    )))
                }
            };
            state_for_task.store(ActorState::Stopped);
            let outcome = join_result_to_task_outcome(&result).map_err(|_| ());
            let _ = result_tx.send_blocking(result);
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
            task: None,
        };

        Ok((handle, stored))
    }
}

impl Cx {
    /// Spawns an actor as a task in this context's region, on the native
    /// runtime or the lab runtime alike.
    ///
    /// The actor runs the same lifecycle as one spawned with
    /// [`Scope::spawn_actor`](crate::cx::Scope::spawn_actor):
    /// [`Actor::on_start`], then messages from a bounded mailbox of
    /// `mailbox_capacity`, then [`Actor::on_stop`]. The region's close
    /// cancels the actor.
    ///
    /// The runtime admits the task after this returns, as for [`Cx::spawn`]:
    /// until then the handle's [`task_id`](ActorHandle::task_id) is the
    /// provisional spawn id. [`actor_id`](ActorHandle::actor_id) is fixed
    /// here and derives from that provisional id. A denied spawn joins as
    /// [`JoinError::Cancelled`]. A panic in the actor is the task's outcome
    /// and joins as [`JoinError::Panicked`].
    ///
    /// # Panics
    ///
    /// Panics if `mailbox_capacity == 0`. Channel capacity must be non-zero.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`] when this context is not
    /// attached to a running runtime or may not spawn.
    pub fn spawn_actor<A: Actor>(
        &self,
        actor: A,
        mailbox_capacity: usize,
    ) -> Result<ActorHandle<A>, SpawnError> {
        self.spawn_actor_task(mailbox_capacity, move |child_cx, mut cell| async move {
            let result = crate::cx::scope::CatchUnwind {
                inner: Box::pin(run_actor_loop(actor, child_cx, &mut cell)),
            }
            .await;
            result.map_err(panicked_join_error)
        })
    }

    /// Spawns a supervised actor as a task in this context's region, on the
    /// native runtime or the lab runtime alike.
    ///
    /// Supervision is the same as for
    /// [`Scope::spawn_supervised_actor`](crate::cx::Scope::spawn_supervised_actor):
    /// `factory` builds the first actor and every restart, the mailbox
    /// persists across restarts, and `strategy` decides what a crash does.
    /// When supervision stops or escalates, the crash is the task's outcome
    /// and joins as [`JoinError::Panicked`]. Admission is as for
    /// [`Cx::spawn_actor`].
    ///
    /// # Panics
    ///
    /// Panics if `mailbox_capacity == 0`. Channel capacity must be non-zero.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`] when this context is not
    /// attached to a running runtime or may not spawn.
    pub fn spawn_supervised_actor<A, F>(
        &self,
        mut factory: F,
        strategy: crate::supervision::SupervisionStrategy,
        mailbox_capacity: usize,
    ) -> Result<ActorHandle<A>, SpawnError>
    where
        A: Actor,
        F: FnMut() -> A + Send + 'static,
    {
        self.spawn_actor_task(mailbox_capacity, move |child_cx, mut cell| async move {
            let (task_id, region_id) = (child_cx.task_id(), child_cx.region_id());
            let result = crate::cx::scope::CatchUnwind {
                inner: Box::pin(async move {
                    let actor = factory();
                    run_supervised_loop(
                        actor,
                        &mut factory,
                        child_cx,
                        &mut cell,
                        crate::supervision::Supervisor::new(strategy)
                            .with_max_evidence_entries(crate::supervision::Supervisor::DEFAULT_ACTOR_EVIDENCE_CAPACITY),
                        task_id,
                        region_id,
                    )
                    .await
                }),
            }
            .await;
            result.unwrap_or_else(|payload| Err(panicked_join_error(payload)))
        })
    }

    /// Spawns the task behind [`Self::spawn_actor`] and
    /// [`Self::spawn_supervised_actor`]. `run` drives the actor over its
    /// mailbox and returns the join result, which is published without
    /// consulting the actor's Cx: aborting the actor cancels that context
    /// before the final state is returned.
    fn spawn_actor_task<A, R, Fut>(
        &self,
        mailbox_capacity: usize,
        run: R,
    ) -> Result<ActorHandle<A>, SpawnError>
    where
        A: Actor,
        R: FnOnce(Cx, ActorCell<A::Message>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<A, JoinError>> + Send + 'static,
    {
        let (msg_tx, msg_rx) = mpsc::channel::<A::Message>(mailbox_capacity);
        let (result_tx, result_rx) = crate::channel::oneshot::channel::<Result<A, JoinError>>();
        let actor_state = Arc::new(ActorStateCell::new(ActorState::Created));
        let cell = ActorCell {
            mailbox: msg_rx,
            state: Arc::clone(&actor_state),
        };
        let state_for_task = Arc::clone(&actor_state);

        let task = self.spawn(move |child_cx| async move {
            let result = run(child_cx, cell).await;
            state_for_task.store(ActorState::Stopped);
            let panic = match &result {
                Err(JoinError::Panicked(payload)) => Some(payload.message().to_owned()),
                _ => None,
            };
            let _ = result_tx.send_blocking(result);
            // Re-raise a crash, so the runtime records the task as panicked:
            // its monitors see a panic and its links propagate it.
            if let Some(message) = panic {
                std::panic::resume_unwind(Box::new(message));
            }
        })?;

        let task_id = task.task_id();
        Ok(ActorHandle {
            actor_id: ActorId::from_task(task_id),
            sender: msg_tx,
            state: actor_state,
            task_id,
            receiver: result_rx,
            inner: std::sync::Weak::new(),
            completed: false,
            task: Some(task),
        })
    }
}

/// The join error for an actor whose run panicked. The payload is forgotten
/// rather than dropped, as in the scope spawns: its destructor could panic.
fn panicked_join_error(payload: Box<dyn std::any::Any + Send>) -> JoinError {
    let message = crate::cx::scope::payload_to_string(&payload);
    std::mem::forget(payload);
    JoinError::Panicked(crate::types::PanicPayload::new(message))
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
                            match wait_supervised_restart_delay(&cx, &cell.state, backoff).await {
                                Outcome::Ok(()) => {}
                                Outcome::Err(err) => return Err(err),
                                Outcome::Cancelled(_) => return Err(actor_cancel_join_error(&cx)),
                                Outcome::Panicked(payload) => {
                                    return Err(JoinError::Panicked(payload));
                                }
                            }
                        }

                        if cx.checkpoint().is_err() {
                            cx.trace("supervised_actor::restart_suppressed");
                            return Err(JoinError::Panicked(panic_payload));
                        }

                        // Commit the restart only while the actor is still
                        // Running. A concurrent stop transitions it to
                        // Stopping; the conditional swap must preserve that
                        // shutdown request instead of resurrecting the actor.
                        if !try_commit_supervised_restart(&cell.state) {
                            cx.trace("supervised_actor::restart_suppressed");
                            return Err(JoinError::Panicked(panic_payload));
                        }
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

/// Logs a panic contained while dropping a buffered message, then leaks its
/// payload, because dropping the payload can panic too. An unresolved
/// obligation left in an aborted actor's mailbox panics this way (ASUP-E101);
/// without this the leak would show only as an abort-path trace event
/// (br-asupersync-pk44qd S3).
fn forget_contained_drop_panic(payload: Box<dyn std::any::Any + Send>) {
    crate::tracing_compat::error!(
        panic = %crate::cx::scope::payload_to_string(&payload),
        "a buffered actor message panicked while being dropped; the panic was contained"
    );
    std::mem::forget(payload);
}

#[cfg(test)]
#[path = "actor_inline_tests.rs"]
mod tests;

// ============================================================================
// Conformance Tests
// ============================================================================

#[cfg(test)]
#[path = "actor_conformance_tests.rs"]
mod actor_conformance_tests;

#[cfg(test)]
#[path = "actor_conformance_integration_inline_tests.rs"]
mod conformance_integration;
