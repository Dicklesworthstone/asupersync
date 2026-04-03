//! # Asupersync 4.0 — API Skeleton (Plan v4 Edition)
//!
//! A practical, implementation-ready API skeleton matching the Plan v4 design.
//! Focuses on what's achievable in stable Rust with clear tier separation.
//!
//! Key differences from the "Design Bible" skeleton:
//! - Explicit tier separation (Fiber/Task/Actor/Remote)
//! - Simpler capability model (Cx is concrete, not a trait)
//! - Obligation tracking is runtime-checked, not type-level
//! - Session types are a separate optional module
//! - More realistic error handling

#![allow(unused)]
#![forbid(unsafe_code)]

use std::any::Any;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

macro_rules! skeleton_placeholder {
    () => {
        panic!(
            "asupersync_v4_api_skeleton.rs is a design skeleton; use src/ runtime implementation"
        )
    };
}

// ============================================================================
// PART 1: IDENTIFIERS
// ============================================================================

/// Unique identifier for a region in the ownership tree.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct RegionId(pub(crate) u64);

/// Unique identifier for a task/fiber.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct TaskId(pub(crate) u64);

/// Unique identifier for an obligation (permit/ack/lease).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ObligationId(pub(crate) u64);

// ============================================================================
// PART 2: OUTCOME (Four-Valued Result)
// ============================================================================

/// Terminal result of a task or region.
/// Ordered by severity: Ok < Err < Cancelled < Panicked
#[derive(Debug, Clone)]
pub enum Outcome<T, E> {
    Ok(T),
    Err(E),
    Cancelled(CancelReason),
    Panicked(PanicPayload),
}

impl<T, E> Outcome<T, E> {
    pub fn is_terminal(&self) -> bool {
        true
    } // All variants are terminal

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }
    pub fn is_err(&self) -> bool {
        matches!(self, Self::Err(_))
    }
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }
    pub fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked(_))
    }

    pub fn ok(self) -> Option<T> {
        match self {
            Self::Ok(v) => Some(v),
            _ => None,
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Outcome<U, E> {
        match self {
            Self::Ok(v) => Outcome::Ok(f(v)),
            Self::Err(e) => Outcome::Err(e),
            Self::Cancelled(r) => Outcome::Cancelled(r),
            Self::Panicked(p) => Outcome::Panicked(p),
        }
    }

    pub fn map_err<F>(self, f: impl FnOnce(E) -> F) -> Outcome<T, F> {
        match self {
            Self::Ok(v) => Outcome::Ok(v),
            Self::Err(e) => Outcome::Err(f(e)),
            Self::Cancelled(r) => Outcome::Cancelled(r),
            Self::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Convert to standard Result, collapsing Cancelled/Panicked into Err
    pub fn into_result(self) -> Result<T, OutcomeError<E>> {
        match self {
            Self::Ok(v) => Ok(v),
            Self::Err(e) => Err(OutcomeError::Task(e)),
            Self::Cancelled(r) => Err(OutcomeError::Cancelled(r)),
            Self::Panicked(p) => Err(OutcomeError::Panicked(p)),
        }
    }
}

/// Wrapper for non-Ok outcomes when converting to Result.
#[derive(Debug)]
pub enum OutcomeError<E> {
    Task(E),
    Cancelled(CancelReason),
    Panicked(PanicPayload),
}

/// Reason for cancellation with kind and optional message.
#[derive(Debug, Clone)]
pub struct CancelReason {
    pub kind: CancelKind,
    pub message: Option<&'static str>,
}

impl CancelReason {
    pub const fn user(msg: &'static str) -> Self {
        Self {
            kind: CancelKind::User,
            message: Some(msg),
        }
    }
    pub const fn timeout() -> Self {
        Self {
            kind: CancelKind::Timeout,
            message: None,
        }
    }
    pub const fn parent() -> Self {
        Self {
            kind: CancelKind::ParentCancelled,
            message: None,
        }
    }
    pub const fn sibling_failed() -> Self {
        Self {
            kind: CancelKind::FailFast,
            message: None,
        }
    }
    pub const fn shutdown() -> Self {
        Self {
            kind: CancelKind::Shutdown,
            message: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CancelKind {
    User,
    Timeout,
    FailFast,
    ParentCancelled,
    Shutdown,
}

/// Panic payload (opaque, cannot be inspected for safety).
#[derive(Debug, Clone)]
pub struct PanicPayload {
    type_name: &'static str,
    // Actual payload stored internally but not exposed
}

// ============================================================================
// PART 3: BUDGET (Product Semiring with Min)
// ============================================================================

/// Resource budget that propagates through the task tree.
/// Combines by taking the stricter (min) of each component.
#[derive(Clone, Debug)]
pub struct Budget {
    /// Absolute deadline. None = no deadline.
    pub deadline: Option<Instant>,
    /// Max polls before forced yield.
    pub poll_quota: u32,
    /// Cost units (API calls, compute tokens, etc). None = unlimited.
    pub cost_quota: Option<u64>,
    /// Priority level (higher = more important). Combines by max.
    pub priority: u8,
}

impl Budget {
    pub const UNLIMITED: Self = Self {
        deadline: None,
        poll_quota: u32::MAX,
        cost_quota: None,
        priority: 0,
    };

    /// Combine two budgets: min of quotas, max of priority.
    pub fn combine(&self, child: &Budget) -> Budget {
        Budget {
            deadline: min_opt(self.deadline, child.deadline),
            poll_quota: self.poll_quota.min(child.poll_quota),
            cost_quota: min_opt(self.cost_quota, child.cost_quota),
            priority: self.priority.max(child.priority),
        }
    }

    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(min_opt(self.deadline, Some(deadline)).unwrap());
        self
    }

    pub fn with_timeout(self, duration: Duration) -> Self {
        self.with_deadline(Instant::now() + duration)
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Check if deadline has passed.
    pub fn is_expired(&self, now: Instant) -> bool {
        self.deadline.map(|d| now >= d).unwrap_or(false)
    }

    /// Remaining time until deadline (None if no deadline or already passed).
    pub fn remaining(&self, now: Instant) -> Option<Duration> {
        self.deadline.and_then(|d| d.checked_duration_since(now))
    }
}

fn min_opt<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

// ============================================================================
// PART 4: CAPABILITY CONTEXT (Cx)
// ============================================================================

/// The capability context — all effects flow through here.
///
/// Unlike the Design Bible version (trait-based), this is a concrete type.
/// Swapping behavior is done via the runtime, not generic parameters.
/// This is more practical for real Rust code.
///
/// Spec note (math): treat `Cx` methods as an *effect signature* (checkpoint/sleep/trace/reserve/commit…)
/// and each runtime (prod/lab/remote) as a different *handler* for the same effects. This makes
/// determinism, replay, and rewriting laws precise without changing user code.
#[derive(Clone)]
pub struct Cx {
    pub(crate) inner: Arc<CxInner>,
}

pub(crate) struct CxInner {
    pub(crate) region_id: RegionId,
    pub(crate) task_id: TaskId,
    pub(crate) budget: Budget,
    pub(crate) runtime: Arc<RuntimeInner>,
}

impl Cx {
    // === Identity ===

    pub fn region_id(&self) -> RegionId {
        self.inner.region_id
    }
    pub fn task_id(&self) -> TaskId {
        self.inner.task_id
    }

    // === Budget ===

    pub fn budget(&self) -> &Budget {
        &self.inner.budget
    }
    pub fn now(&self) -> Instant {
        self.inner.runtime.now()
    }

    // === Cancellation ===

    /// Non-blocking check: has cancellation been requested?
    pub fn is_cancel_requested(&self) -> bool {
        skeleton_placeholder!()
    }

    /// Cancellation checkpoint. Returns Err(CancelReason) if cancelled.
    /// This is THE primary way to make code cancellation-aware.
    pub async fn checkpoint(&self) -> Result<(), CancelReason> {
        skeleton_placeholder!()
    }

    /// Run a future with cancellation masked (bounded by budget).
    /// Use sparingly — only for critical sections that must complete.
    pub async fn masked<F, T>(&self, fut: F) -> T
    where
        F: Future<Output = T>,
    {
        skeleton_placeholder!()
    }

    // === Scheduling ===

    /// Yield to the scheduler.
    pub async fn yield_now(&self) {
        skeleton_placeholder!()
    }

    /// Sleep until the given instant.
    pub async fn sleep_until(&self, deadline: Instant) {
        skeleton_placeholder!()
    }

    /// Sleep for a duration.
    pub async fn sleep(&self, duration: Duration) {
        self.sleep_until(self.now() + duration).await
    }

    // === Tracing ===

    /// Emit a trace event.
    pub fn trace(&self, event: TraceEvent) {
        skeleton_placeholder!()
    }
}

/// Trace events for observability, replay, and verification.
///
/// Spec note (math): the "right" trace model is a *partial order* (true concurrency),
/// not a single total order. The lab runtime can treat many interleavings as equivalent
/// by quotienting traces with an independence relation (Mazurkiewicz trace semantics),
/// which is the semantic foundation behind optimal DPOR exploration.
#[derive(Debug, Clone)]
pub enum TraceEvent {
    // Task lifecycle
    TaskSpawned {
        region: RegionId,
        task: TaskId,
        name: Option<&'static str>,
    },
    TaskCompleted {
        task: TaskId,
        outcome_kind: &'static str,
    },

    // Cancellation
    CancelRequested {
        target: RegionId,
        reason: CancelReason,
    },
    CancelAcknowledged {
        task: TaskId,
    },

    // Obligations
    ObligationCreated {
        id: ObligationId,
        kind: &'static str,
        holder: TaskId,
    },
    ObligationResolved {
        id: ObligationId,
        how: &'static str,
    },
    ObligationLeaked {
        id: ObligationId,
    }, // Should never happen in correct code

    // Finalizers
    FinalizerRegistered {
        region: RegionId,
        index: usize,
    },
    FinalizerCompleted {
        region: RegionId,
        index: usize,
    },

    // Region lifecycle
    RegionOpened {
        id: RegionId,
        parent: Option<RegionId>,
    },
    RegionClosing {
        id: RegionId,
    },
    RegionClosed {
        id: RegionId,
        outcome_kind: &'static str,
    },

    // Custom
    Custom {
        name: &'static str,
        payload: String,
    },
}

// ============================================================================
// PART 5: POLICY
// ============================================================================

/// Policy determines how a region handles child outcomes.
pub trait Policy: Clone + Send + Sync + 'static {
    type Error: Send + 'static;

    /// Called when a child reaches a terminal state.
    fn on_child_outcome<T>(&self, child: TaskId, outcome: &Outcome<T, Self::Error>)
    -> PolicyAction;

    /// Compute the region's outcome from its children.
    fn aggregate_outcomes<T>(
        &self,
        outcomes: &[Outcome<T, Self::Error>],
    ) -> AggregateDecision<Self::Error>;
}

#[derive(Clone, Debug)]
pub enum PolicyAction {
    Continue,
    CancelSiblings(CancelReason),
    Escalate,
}

pub enum AggregateDecision<E> {
    AllOk,
    FirstError(E),
    Cancelled(CancelReason),
    Panicked(PanicPayload),
}

/// Standard fail-fast policy.
#[derive(Clone, Debug, Default)]
pub struct FailFast;

impl Policy for FailFast {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn on_child_outcome<T>(&self, _: TaskId, outcome: &Outcome<T, Self::Error>) -> PolicyAction {
        match outcome {
            Outcome::Ok(_) | Outcome::Cancelled(_) => PolicyAction::Continue,
            Outcome::Err(_) | Outcome::Panicked(_) => {
                PolicyAction::CancelSiblings(CancelReason::sibling_failed())
            }
        }
    }

    fn aggregate_outcomes<T>(
        &self,
        outcomes: &[Outcome<T, Self::Error>],
    ) -> AggregateDecision<Self::Error> {
        for o in outcomes {
            match o {
                Outcome::Panicked(p) => return AggregateDecision::Panicked(p.clone()),
                Outcome::Cancelled(r) => return AggregateDecision::Cancelled(r.clone()),
                Outcome::Err(_) => {
                    // Can't clone Box<dyn Error>, so we just report first error
                    return AggregateDecision::FirstError("child task failed".into());
                }
                Outcome::Ok(_) => continue,
            }
        }
        AggregateDecision::AllOk
    }
}

/// Collect-all policy: wait for all children, don't cancel on error.
#[derive(Clone, Debug, Default)]
pub struct CollectAll;

impl Policy for CollectAll {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn on_child_outcome<T>(&self, _: TaskId, _: &Outcome<T, Self::Error>) -> PolicyAction {
        PolicyAction::Continue // Never cancel siblings
    }

    fn aggregate_outcomes<T>(
        &self,
        outcomes: &[Outcome<T, Self::Error>],
    ) -> AggregateDecision<Self::Error> {
        // Same as FailFast for aggregation, just different on_child behavior
        FailFast.aggregate_outcomes(outcomes)
    }
}

// ============================================================================
// PART 6: SCOPE AND HANDLES (Tier-Aware)
// ============================================================================

/// A scope provides access to a region for spawning work.
/// The lifetime `'r` ties handles to the region's lifetime.
pub struct Scope<'r, P: Policy = FailFast> {
    pub(crate) region_id: RegionId,
    pub(crate) runtime: Arc<RuntimeInner>,
    pub(crate) _policy: PhantomData<P>,
    pub(crate) _region: PhantomData<&'r ()>,
}

impl<'r, P: Policy> Scope<'r, P> {
    /// Access the capability context for this scope.
    pub fn cx(&self) -> Cx {
        skeleton_placeholder!()
    }

    // === Tier 1: Fibers (same-thread, borrowing) ===

    /// Spawn a fiber that can borrow from the current scope.
    /// Fibers run on the same thread and cannot be Send.
    pub fn spawn_fiber<F, T>(&self, f: F) -> FiberHandle<'r, T>
    where
        F: FnOnce(Cx) -> Pin<Box<dyn Future<Output = T> + 'r>>,
        T: 'r,
    {
        skeleton_placeholder!()
    }

    // === Tier 2: Tasks (parallel, Send) ===

    /// Spawn a parallel task. The future must be Send.
    pub fn spawn<F, Fut, T, E>(&self, f: F) -> TaskHandle<'r, T, E>
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
    {
        skeleton_placeholder!()
    }

    /// Spawn with a name (for debugging/tracing).
    pub fn spawn_named<F, Fut, T, E>(&self, name: &'static str, f: F) -> TaskHandle<'r, T, E>
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
    {
        skeleton_placeholder!()
    }

    // === Tier 3: Child regions ===

    /// Create a child region with its own policy.
    pub async fn region<P2, F, Fut, T>(&self, policy: P2, f: F) -> Outcome<T, P2::Error>
    where
        P2: Policy,
        F: FnOnce(Scope<'_, P2>) -> Fut,
        Fut: Future<Output = Outcome<T, P2::Error>>,
    {
        skeleton_placeholder!()
    }

    // === Combinators ===

    /// Join two handles, waiting for both.
    pub async fn join<T1, T2, E>(
        &self,
        h1: TaskHandle<'r, T1, E>,
        h2: TaskHandle<'r, T2, E>,
    ) -> (Outcome<T1, E>, Outcome<T2, E>)
    where
        T1: Send,
        T2: Send,
        E: Send,
    {
        skeleton_placeholder!()
    }

    /// Race two handles, cancelling the loser.
    pub async fn race<T, E>(
        &self,
        h1: TaskHandle<'r, T, E>,
        h2: TaskHandle<'r, T, E>,
    ) -> Outcome<T, E>
    where
        T: Send,
        E: Send,
    {
        skeleton_placeholder!()
    }

    /// Run with a timeout.
    pub async fn timeout<T, E>(
        &self,
        duration: Duration,
        handle: TaskHandle<'r, T, E>,
    ) -> Outcome<T, E>
    where
        T: Send,
        E: Send,
    {
        skeleton_placeholder!()
    }

    // === Finalization ===

    /// Register an async finalizer (runs during region close, LIFO).
    pub fn defer<F, Fut>(&self, f: F)
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        skeleton_placeholder!()
    }

    /// Register a sync finalizer.
    pub fn defer_sync<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        skeleton_placeholder!()
    }

    // === Cancellation ===

    /// Request cancellation of this region and all descendants.
    pub fn cancel(&self, reason: CancelReason) {
        skeleton_placeholder!()
    }
}

/// Handle to a fiber (same-thread, can borrow).
pub struct FiberHandle<'r, T> {
    task_id: TaskId,
    _marker: PhantomData<&'r T>,
}

impl<'r, T> FiberHandle<'r, T> {
    pub async fn join(self) -> Outcome<T, !>
    where
        T: 'r,
    {
        skeleton_placeholder!()
    }

    pub fn cancel(&self, reason: CancelReason) {
        skeleton_placeholder!()
    }
}

/// Handle to a parallel task.
pub struct TaskHandle<'r, T, E> {
    task_id: TaskId,
    _marker: PhantomData<(&'r (), T, E)>,
}

impl<'r, T, E> TaskHandle<'r, T, E> {
    pub fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// Wait for the task to complete.
    pub async fn join(self) -> Outcome<T, E> {
        skeleton_placeholder!()
    }

    /// Request cancellation.
    pub fn cancel(&self, reason: CancelReason) {
        skeleton_placeholder!()
    }

    /// Check if complete (non-blocking).
    pub fn is_complete(&self) -> bool {
        skeleton_placeholder!()
    }
}

// Dropping a handle does NOT detach the task — the region still owns it.
// This is a core invariant of structured concurrency.

// ============================================================================
// PART 7: TWO-PHASE CHANNELS AND OBLIGATIONS
// ============================================================================

pub mod channel {
    use super::*;

    /// A bounded channel with two-phase send (reserve/commit).
    pub fn bounded<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
        skeleton_placeholder!()
    }

    pub struct Sender<T> {
        _marker: PhantomData<T>,
    }

    impl<T> Sender<T> {
        /// Reserve a slot. Returns a permit that must be committed or dropped.
        pub async fn reserve(&self, cx: &Cx) -> Result<SendPermit<T>, ChannelClosed> {
            skeleton_placeholder!()
        }

        /// Try to reserve without blocking.
        pub fn try_reserve(&self) -> Result<SendPermit<T>, TryReserveError> {
            skeleton_placeholder!()
        }

        /// Convenience: reserve + send in one call (still two-phase internally).
        pub async fn send(&self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
            let permit = self.reserve(cx).await.map_err(|_| SendError(value))?;
            permit.send(value);
            Ok(())
        }
    }

    impl<T> Clone for Sender<T> {
        fn clone(&self) -> Self {
            skeleton_placeholder!()
        }
    }

    /// A permit to send one message. This is a linear obligation.
    /// - Call `send()` to commit
    /// - Drop without sending to abort (releases capacity)
    ///
    /// Spec note (math): this is the operational form of a linear resource in context `Δ`.
    /// `reserve` introduces the resource, and exactly one of `send`/`abort` must eliminate it.
    /// This also corresponds to a simple session type:
    ///
    /// - Sender: `reserve → (send | abort)`
    ///
    /// In later iterations this can be strengthened with typestate/session-typed endpoints,
    /// but the meaning should not change: two-phase effects are cancellation-safe by construction.
    #[must_use = "SendPermit is a linear obligation: call send() or abort()"]
    pub struct SendPermit<T> {
        obligation_id: ObligationId,
        _marker: PhantomData<T>,
    }

    impl<T> SendPermit<T> {
        /// Commit the send. Consumes the permit.
        pub fn send(self, value: T) {
            skeleton_placeholder!()
        }

        /// Explicitly abort. Equivalent to drop but more intentional.
        pub fn abort(self) {
            drop(self)
        }
    }

    impl<T> Drop for SendPermit<T> {
        fn drop(&mut self) {
            // Release capacity, record as aborted
            // In lab mode with strict checking: may panic
        }
    }

    pub struct Receiver<T> {
        _marker: PhantomData<T>,
    }

    impl<T> Receiver<T> {
        /// Receive with acknowledgment token.
        pub async fn recv(&self, cx: &Cx) -> Result<(T, Ack), ChannelClosed> {
            skeleton_placeholder!()
        }

        /// Receive without ack (auto-commits).
        pub async fn recv_auto(&self, cx: &Cx) -> Result<T, ChannelClosed> {
            let (value, ack) = self.recv(cx).await?;
            ack.commit();
            Ok(value)
        }
    }

    /// Acknowledgment token. Must be committed or dropped (nack).
    #[must_use = "Ack is a linear obligation: call commit() or nack()"]
    pub struct Ack {
        obligation_id: ObligationId,
    }

    impl Ack {
        pub fn commit(self) {
            skeleton_placeholder!()
        }

        pub fn nack(self) {
            drop(self)
        }
    }

    impl Drop for Ack {
        fn drop(&mut self) {
            // Record as nack'd
        }
    }

    #[derive(Debug)]
    pub struct ChannelClosed;

    #[derive(Debug)]
    pub struct SendError<T>(pub T);

    #[derive(Debug)]
    pub enum TryReserveError {
        Full,
        Closed,
    }
}

// ============================================================================
// PART 8: STREAMS (Ack-Based)
// ============================================================================

pub mod stream {
    use super::channel::Ack;
    use super::*;

    /// An async stream with backpressure via acks.
    pub trait AckStream {
        type Item;

        /// Get next item with its ack token.
        fn next<'a>(
            &'a mut self,
            cx: &'a Cx,
        ) -> Pin<Box<dyn Future<Output = Option<(Self::Item, Ack)>> + Send + 'a>>;
    }

    /// Combinators for ack streams.
    pub trait AckStreamExt: AckStream + Sized {
        fn map<F, U>(self, f: F) -> Map<Self, F>
        where
            F: FnMut(Self::Item) -> U,
        {
            Map { stream: self, f }
        }

        fn filter<F>(self, f: F) -> Filter<Self, F>
        where
            F: FnMut(&Self::Item) -> bool,
        {
            Filter { stream: self, f }
        }
    }

    impl<S: AckStream> AckStreamExt for S {}

    pub struct Map<S, F> {
        stream: S,
        f: F,
    }

    pub struct Filter<S, F> {
        stream: S,
        f: F,
    }
}

// ============================================================================
// PART 9: ACTORS (Tier 3 - Supervised)
// ============================================================================

pub mod actor {
    use super::*;

    /// An actor is a long-lived task with a mailbox and supervision.
    pub trait Actor: Send + 'static {
        type Message: Send;
        type Error: Send;

        fn handle(
            &mut self,
            msg: Self::Message,
            cx: &Cx,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send;

        /// Called on startup.
        fn on_start(&mut self, _cx: &Cx) -> impl Future<Output = ()> + Send {
            async {}
        }

        /// Called before shutdown.
        fn on_stop(&mut self, _cx: &Cx) -> impl Future<Output = ()> + Send {
            async {}
        }
    }

    /// Handle to a running actor.
    pub struct ActorRef<A: Actor> {
        _marker: PhantomData<A>,
    }

    impl<A: Actor> ActorRef<A> {
        /// Send a message (two-phase).
        pub async fn send(&self, cx: &Cx, msg: A::Message) -> Result<(), ActorStopped> {
            skeleton_placeholder!()
        }

        /// Request graceful stop.
        pub fn stop(&self) {
            skeleton_placeholder!()
        }
    }

    impl<A: Actor> Clone for ActorRef<A> {
        fn clone(&self) -> Self {
            skeleton_placeholder!()
        }
    }

    #[derive(Debug)]
    pub struct ActorStopped;

    /// Supervision policy.
    #[derive(Clone, Debug)]
    pub enum SupervisionStrategy {
        /// Stop on any error.
        Stop,
        /// Restart on error, up to max_restarts in window.
        Restart { max_restarts: u32, window: Duration },
        /// Escalate to parent region.
        Escalate,
    }

    /// Spawn an actor in a scope.
    pub fn spawn<'r, A, P>(
        scope: &Scope<'r, P>,
        actor: A,
        strategy: SupervisionStrategy,
    ) -> ActorRef<A>
    where
        A: Actor,
        P: Policy,
    {
        skeleton_placeholder!()
    }
}

// ============================================================================
// PART 10: REMOTE TASKS (Tier 4 - Distributed)
// ============================================================================

pub mod remote {
    //! Remote tasks (Tier 4 - Distributed).
    //!
    //! Spec note (math):
    //! - Traces across nodes should be causally ordered (vector-clock / happens-before), not forced
    //!   into a fake total order.
    //! - Lease/obligation state should form a join-semilattice so replicas converge (CRDT-style).
    //!   A conflicting join (e.g. "Committed" ⊔ "Aborted") is a deterministic protocol violation
    //!   surfaced in traces, not a heisenbug.
    use super::*;

    /// A named computation that can execute remotely.
    /// NOT a closure — must be a registered, named type.
    pub trait NamedTask: Send + 'static {
        const NAME: &'static str;
        type Input: Send + serde::Serialize + serde::de::DeserializeOwned;
        type Output: Send + serde::Serialize + serde::de::DeserializeOwned;
        type Error: Send + serde::Serialize + serde::de::DeserializeOwned;
    }

    /// Handle to a remote task invocation.
    pub struct RemoteHandle<T: NamedTask> {
        pub(crate) invocation_id: InvocationId,
        pub(crate) lease: Lease,
        _marker: PhantomData<T>,
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    pub struct InvocationId(pub(crate) u128);

    /// A lease bounds how long a remote task can run orphaned.
    #[derive(Clone, Debug)]
    #[must_use = "Lease is an obligation-like token: renew it or let it expire deterministically"]
    pub struct Lease {
        pub(crate) expires_at: Instant,
        pub(crate) obligation_id: ObligationId,
    }

    impl Lease {
        pub fn remaining(&self, now: Instant) -> Option<Duration> {
            self.expires_at.checked_duration_since(now)
        }

        pub fn is_expired(&self, now: Instant) -> bool {
            now >= self.expires_at
        }

        /// Attempt to renew the lease.
        pub async fn renew(&mut self, cx: &Cx, duration: Duration) -> Result<(), LeaseExpired> {
            skeleton_placeholder!()
        }
    }

    #[derive(Debug)]
    pub struct LeaseExpired;

    impl<T: NamedTask> RemoteHandle<T> {
        pub fn invocation_id(&self) -> InvocationId {
            self.invocation_id
        }
        pub fn lease(&self) -> &Lease {
            &self.lease
        }
        pub fn lease_mut(&mut self) -> &mut Lease {
            &mut self.lease
        }

        /// Wait for the remote task to complete.
        pub async fn join(self, cx: &Cx) -> Outcome<T::Output, T::Error> {
            skeleton_placeholder!()
        }

        /// Request cancellation of the remote task (best-effort).
        pub async fn cancel(&self, cx: &Cx) -> Result<(), RemoteError> {
            skeleton_placeholder!()
        }
    }

    #[derive(Debug)]
    pub enum RemoteError {
        LeaseExpired,
        NetworkError(String),
        TaskNotFound,
    }

    /// Invoke a named remote task.
    pub async fn invoke<T: NamedTask>(
        cx: &Cx,
        input: T::Input,
        lease_duration: Duration,
    ) -> Result<RemoteHandle<T>, RemoteError> {
        skeleton_placeholder!()
    }

    // Serde placeholder
    mod serde {
        pub trait Serialize {}
        pub mod de {
            pub trait DeserializeOwned {}
        }
    }
}

// ============================================================================
// PART 11: RUNTIME
// ============================================================================

pub(crate) struct RuntimeInner {
    // Scheduler state, region tree, timers, etc.
    //
    // Spec note (math): the scheduler can be framed as a controller over a potential function
    // `V(Σ)` (a Lyapunov-style "energy") that weights:
    // - number of live children,
    // - outstanding obligations (weighted by age/priority),
    // - remaining finalizers,
    // - deadline slack / poll pressure.
    // Under cooperative checkpoints and bounded masking, cancellation then becomes a convergence
    // argument ("drive V to zero" = quiescence) rather than a best-effort heuristic.
}

impl RuntimeInner {
    fn now(&self) -> Instant {
        skeleton_placeholder!()
    }
}

/// The Asupersync runtime.
pub struct Runtime {
    inner: Arc<RuntimeInner>,
}

pub struct RuntimeBuilder {
    workers: usize,
    enable_io: bool,
}

impl RuntimeBuilder {
    pub fn new() -> Self {
        Self {
            workers: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            enable_io: true,
        }
    }

    pub fn workers(mut self, n: usize) -> Self {
        self.workers = n;
        self
    }

    pub fn enable_io(mut self, enable: bool) -> Self {
        self.enable_io = enable;
        self
    }

    pub fn build(self) -> Runtime {
        skeleton_placeholder!()
    }
}

impl Default for RuntimeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    pub fn new() -> Self {
        RuntimeBuilder::new().build()
    }

    /// Run a scoped computation to completion.
    pub fn run<P, F, Fut, T>(&self, policy: P, f: F) -> Outcome<T, P::Error>
    where
        P: Policy,
        F: for<'r> FnOnce(Scope<'r, P>) -> Fut,
        Fut: Future<Output = Outcome<T, P::Error>>,
        T: Send + 'static,
    {
        skeleton_placeholder!()
    }

    /// Block on a single future (simple entrypoint).
    pub fn block_on<F: Future>(&self, fut: F) -> F::Output {
        skeleton_placeholder!()
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PART 12: LAB RUNTIME (Deterministic Testing)
// ============================================================================

pub mod lab {
    use super::*;

    /// Deterministic runtime for testing.
    pub struct LabRuntime {
        seed: u64,
        virtual_time: u64,
        trace: Vec<TraceEvent>,
        obligation_panic_on_leak: bool,
    }

    impl LabRuntime {
        pub fn new(seed: u64) -> Self {
            Self {
                seed,
                virtual_time: 0,
                trace: Vec::new(),
                obligation_panic_on_leak: true,
            }
        }

        /// Configure whether leaked obligations panic.
        pub fn panic_on_obligation_leak(mut self, panic: bool) -> Self {
            self.obligation_panic_on_leak = panic;
            self
        }

        /// Advance virtual time.
        pub fn advance(&mut self, nanos: u64) {
            self.virtual_time += nanos;
        }

        /// Run until no task can make progress.
        pub fn run_until_stalled(&mut self) {
            skeleton_placeholder!()
        }

        /// Get captured trace.
        pub fn trace(&self) -> &[TraceEvent] {
            &self.trace
        }

        /// Run a scoped test.
        pub fn test<P, F, T>(&mut self, policy: P, f: F) -> Outcome<T, P::Error>
        where
            P: Policy,
            F: for<'r> FnOnce(
                Scope<'r, P>,
            )
                -> Pin<Box<dyn Future<Output = Outcome<T, P::Error>> + 'r>>,
            T: 'static,
        {
            skeleton_placeholder!()
        }
    }

    /// Explore multiple schedules via *trace-class* exploration (DPOR-family).
    ///
    /// Target behavior: explore one representative per Mazurkiewicz trace equivalence class
    /// (optimal DPOR / source-DPOR style), not one per raw interleaving.
    ///
    /// Practically this means:
    /// - define an independence/dependence relation over `TraceEvent`s,
    /// - record happens-before during an execution,
    /// - backtrack only on dependent reorderings,
    /// - use sleep sets / wakeup trees to avoid redundant schedules.
    pub struct Explorer {
        seed: u64,
        max_schedules: usize,
    }

    impl Explorer {
        pub fn new(seed: u64, max_schedules: usize) -> Self {
            Self {
                seed,
                max_schedules,
            }
        }

        pub fn explore<F, T>(&self, test: F) -> ExplorationReport<T>
        where
            F: Fn(&mut LabRuntime) -> T,
        {
            skeleton_placeholder!()
        }
    }

    pub struct ExplorationReport<T> {
        pub schedules_explored: usize,
        pub outcomes: Vec<ScheduleOutcome<T>>,
    }

    pub struct ScheduleOutcome<T> {
        pub seed: u64,
        pub trace: Vec<TraceEvent>,
        pub result: T,
    }

    impl<T> ExplorationReport<T> {
        pub fn all_satisfy<F>(&self, pred: F) -> bool
        where
            F: Fn(&[TraceEvent], &T) -> bool,
        {
            self.outcomes.iter().all(|o| pred(&o.trace, &o.result))
        }
    }

    // === Property Checkers ===

    /// Check: all spawned tasks completed.
    pub fn no_task_leaks(trace: &[TraceEvent]) -> bool {
        let mut spawned = std::collections::HashSet::new();
        let mut completed = std::collections::HashSet::new();

        for event in trace {
            match event {
                TraceEvent::TaskSpawned { task, .. } => {
                    spawned.insert(*task);
                }
                TraceEvent::TaskCompleted { task, .. } => {
                    completed.insert(*task);
                }
                _ => {}
            }
        }

        spawned == completed
    }

    /// Check: all obligations resolved (no leaks).
    pub fn no_obligation_leaks(trace: &[TraceEvent]) -> bool {
        for event in trace {
            if matches!(event, TraceEvent::ObligationLeaked { .. }) {
                return false;
            }
        }
        true
    }

    /// Check: all finalizers ran.
    pub fn all_finalizers_ran(trace: &[TraceEvent]) -> bool {
        let mut registered = std::collections::HashSet::new();
        let mut completed = std::collections::HashSet::new();

        for event in trace {
            match event {
                TraceEvent::FinalizerRegistered { region, index } => {
                    registered.insert((*region, *index));
                }
                TraceEvent::FinalizerCompleted { region, index } => {
                    completed.insert((*region, *index));
                }
                _ => {}
            }
        }

        registered == completed
    }

    /// Check: regions closed after all children.
    pub fn quiescence_on_close(trace: &[TraceEvent]) -> bool {
        // Would need to track region->children relationships
        // and verify ordering in trace
        skeleton_placeholder!()
    }
}

// ============================================================================
// PART 13: CONVENIENCE MACROS
// ============================================================================

/// Run multiple futures in parallel, waiting for all.
#[macro_export]
macro_rules! join {
    ($scope:expr, $($fut:expr),+ $(,)?) => {
        // Expands to nested scope.join() calls
        skeleton_placeholder!()
    };
}

/// Race multiple futures, returning first to complete.
#[macro_export]
macro_rules! race {
    ($scope:expr, $($fut:expr),+ $(,)?) => {
        skeleton_placeholder!()
    };
}

// ============================================================================
// PART 14: TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outcome_severity() {
        let ok: Outcome<i32, &str> = Outcome::Ok(1);
        let err: Outcome<i32, &str> = Outcome::Err("e");
        let cancel: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());

        assert!(ok.is_ok());
        assert!(err.is_err());
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn test_budget_combine() {
        let parent = Budget::UNLIMITED.with_timeout(Duration::from_secs(10));
        let child = Budget::UNLIMITED.with_timeout(Duration::from_secs(5));
        let combined = parent.combine(&child);

        // Child's tighter deadline wins
        assert!(combined.deadline.unwrap() <= parent.deadline.unwrap());
    }

    #[test]
    fn test_cancel_reason_ordering() {
        assert!(CancelKind::User < CancelKind::Shutdown);
        assert!(CancelKind::Timeout < CancelKind::ParentCancelled);
    }
}
