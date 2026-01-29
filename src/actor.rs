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
use std::sync::Arc;

use crate::channel::mpsc;
use crate::channel::mpsc::SendError;
use crate::cx::Cx;
use crate::runtime::{JoinError, SpawnError};
use crate::types::CxInner;

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
    sender: mpsc::Sender<A::Message>,
    task_id: crate::types::TaskId,
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
    pub fn sender(&self) -> ActorRef<A> {
        ActorRef {
            sender: self.sender.clone(),
        }
    }

    /// Returns the task ID of the actor's underlying task.
    #[must_use]
    pub fn task_id(&self) -> crate::types::TaskId {
        self.task_id
    }

    /// Signals the actor to stop by closing the mailbox.
    ///
    /// The actor will finish processing any buffered messages, then call
    /// `on_stop` and return its state.
    pub fn stop(&self) {
        // Closing is achieved by dropping our sender clone won't work since
        // we need to keep the handle alive. Instead, we abort the task which
        // triggers cancellation.
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
            Err(JoinError::Cancelled(
                crate::types::CancelReason::race_loser(),
            ))
        })
    }

    /// Request the actor to stop by aborting its task.
    pub fn abort(&self) {
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
pub struct ActorRef<A: Actor> {
    sender: mpsc::Sender<A::Message>,
}

impl<A: Actor> Clone for ActorRef<A> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<A: Actor> ActorRef<A> {
    /// Send a message to the actor.
    pub async fn send(&self, cx: &Cx, msg: A::Message) -> Result<(), SendError<A::Message>> {
        self.sender.send(cx, msg).await
    }

    /// Try to send a message without blocking.
    pub fn try_send(&self, msg: A::Message) -> Result<(), SendError<A::Message>> {
        self.sender.try_send(msg)
    }

    /// Returns true if the actor has stopped (mailbox closed).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
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
async fn run_actor_loop<A: Actor>(mut actor: A, cx: Cx, mailbox: &mpsc::Receiver<A::Message>) -> A {
    use crate::tracing_compat::debug;

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

        match mailbox.recv(&cx).await {
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

    // Phase 3: Drain remaining buffered messages.
    // Two-phase mailbox guarantee: no message silently dropped. Every message
    // that was successfully sent (committed) into the mailbox will be handled
    // before the actor's on_stop runs.
    let mut drained: u64 = 0;
    while let Ok(msg) = mailbox.try_recv() {
        actor.handle(&cx, msg).await;
        drained += 1;
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
        );

        // Link Cx to TaskRecord
        if let Some(record) = state.tasks.get_mut(task_id.arena_index()) {
            record.set_cx_inner(child_cx.inner.clone());
            record.set_cx(child_cx.clone());
        }

        let cx_for_send = child_cx.clone();
        let inner_weak = Arc::downgrade(&child_cx.inner);

        // Create the actor loop future
        let wrapped = async move {
            let result = CatchUnwind(Box::pin(run_actor_loop(actor, child_cx, &msg_rx))).await;
            match result {
                Ok(actor_state) => {
                    let _ = result_tx.send(&cx_for_send, Ok(actor_state));
                }
                Err(payload) => {
                    let msg = crate::cx::scope::payload_to_string(&payload);
                    let _ = result_tx.send(
                        &cx_for_send,
                        Err(JoinError::Panicked(crate::types::PanicPayload::new(msg))),
                    );
                }
            }
        };

        let stored = StoredTask::new(wrapped);

        let handle = ActorHandle {
            sender: msg_tx,
            task_id,
            receiver: result_rx,
            inner: inner_weak,
        };

        Ok((handle, stored))
    }

    /// Spawns a supervised actor with automatic restart on failure.
    ///
    /// Unlike [`spawn_actor`], this method takes a factory closure that can
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

        let wrapped = async move {
            let result = run_supervised_loop(
                actor,
                &mut factory,
                child_cx,
                &msg_rx,
                Supervisor::new(strategy),
                task_id,
                region_id,
            )
            .await;
            let _ = result_tx.send(&cx_for_send, result);
        };

        let stored = StoredTask::new(wrapped);

        let handle = ActorHandle {
            sender: msg_tx,
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
    mailbox: &mpsc::Receiver<A::Message>,
    mut supervisor: crate::supervision::Supervisor,
    task_id: crate::types::TaskId,
    region_id: crate::types::RegionId,
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
        let result =
            CatchUnwind(Box::pin(run_actor_loop(current_actor, cx.clone(), mailbox))).await;

        match result {
            Ok(actor_state) => {
                // Actor completed normally — no supervision needed
                return Ok(actor_state);
            }
            Err(payload) => {
                // Actor panicked — consult supervisor.
                // We report this as Failed (not Panicked) because actor crashes
                // are the expected failure mode for supervision. The Erlang/OTP
                // model restarts on crashes; Outcome::Panicked would always Stop.
                let msg = crate::cx::scope::payload_to_string(&payload);
                cx.trace("supervised_actor::failure");

                let outcome = Outcome::err(());
                let now = 0u64; // Virtual time placeholder for determinism
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
        let cx = Cx::for_testing();
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
    fn actor_ref_is_cloneable() {
        init_test("actor_ref_is_cloneable");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_actor(&mut state, &cx, Counter::new(), 32)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Get multiple refs
        let ref1 = handle.sender();
        let ref2 = ref1.clone();

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
        let cx = Cx::for_testing();
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

        assert_eq!(on_stop_count.load(Ordering::SeqCst), 5, "all messages processed");
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
        let cx = Cx::for_testing();
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
        assert_eq!(on_stop_count.load(Ordering::SeqCst), 5, "drain processed all messages");
        assert!(started.load(Ordering::SeqCst), "on_start was called");
        assert!(stopped.load(Ordering::SeqCst), "on_stop was called");

        crate::test_complete!("actor_drains_mailbox_on_cancel");
    }

    /// E2E: Supervised actor restarts on panic within budget.
    /// Actor panics on messages >= threshold, supervisor restarts it.
    /// After restart, actor processes subsequent normal messages.
    #[test]
    fn supervised_actor_restarts_on_panic() {
        init_test("supervised_actor_restarts_on_panic");

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
                if msg == self.panic_on {
                    panic!("threshold exceeded: {}", msg);
                }
                self.count += msg;
                Box::pin(async {})
            }

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.final_count.store(self.count, Ordering::SeqCst);
                Box::pin(async {})
            }
        }

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
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
        init_test("actor_deterministic_replay");

        fn run_scenario(seed: u64) -> u64 {
            let config = crate::lab::LabConfig::new(seed);
            let mut runtime = crate::lab::LabRuntime::new(config);
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let cx = Cx::for_testing();
            let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

            let (on_stop_count, started, stopped) = observable_state();
            let actor =
                ObservableCounter::new(on_stop_count.clone(), started.clone(), stopped.clone());

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

        // Run the same scenario twice with the same seed
        let result1 = run_scenario(0xDEAD_BEEF);
        let result2 = run_scenario(0xDEAD_BEEF);

        assert_eq!(result1, result2, "deterministic replay: same seed → same result");
        assert_eq!(result1, 55, "sum of 1..=10");

        crate::test_complete!("actor_deterministic_replay");
    }
}
