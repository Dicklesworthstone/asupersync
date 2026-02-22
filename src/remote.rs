//! Remote task execution via named computations.
//!
//! This module provides the API for spawning tasks on remote nodes within
//! Asupersync's distributed structured concurrency model. Key design principles:
//!
//! - **No closure shipping**: Remote execution uses *named computations*, not closures.
//!   The caller specifies a computation name (string) and serialized inputs.
//! - **Explicit capability**: All remote operations require [`RemoteCap`], a capability
//!   token held in [`Cx`]. Without it, remote spawning is impossible.
//! - **Region ownership**: Remote handles are owned by the local region and participate
//!   in region close/quiescence. Cancellation propagates to remote nodes.
//! - **Lease-based liveness**: Remote tasks maintain liveness via leases. If a lease
//!   expires, the local region can escalate (cancel, restart, or fail).
//!
//! # Phase 0
//!
//! This is the API surface definition. The actual network transport and remote
//! execution protocol are defined in the remote protocol bead (tmh.1.2). In Phase 0,
//! `spawn_remote` creates a handle but does not perform real network operations.

use crate::channel::oneshot;
use crate::cx::Cx;
use crate::trace::distributed::LogicalTime;
use crate::types::{Budget, CancelReason, ObligationId, RegionId, TaskId, Time};
use crate::util::det_hash::DetHashMap;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

static REMOTE_TASK_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Identifier for a remote node in the cluster.
///
/// Nodes are opaque identifiers. The runtime does not interpret them beyond
/// equality comparison and display. The transport layer maps `NodeId` to
/// actual network addresses.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(String);

impl NodeId {
    /// Creates a new node identifier from a string.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the node identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Node({})", self.0)
    }
}

/// A unique identifier for a remote task.
///
/// Remote task IDs are separate from local [`TaskId`]s because the remote
/// task may not have an arena slot in the local runtime. The local proxy
/// task that owns the [`RemoteHandle`] has a regular `TaskId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteTaskId(u64);

impl RemoteTaskId {
    /// Allocates a new unique remote task ID.
    #[must_use]
    pub fn next() -> Self {
        Self(REMOTE_TASK_COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Creates a remote task ID from a raw value.
    #[must_use]
    pub const fn from_raw(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw numeric identifier.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RemoteTaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RT{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Named computation
// ---------------------------------------------------------------------------

/// Name of a computation that can be executed on a remote node.
///
/// Named computations are the only way to run code remotely. Unlike closure
/// shipping, this approach:
/// - Keeps the set of remotely-executable operations explicit and auditable
/// - Avoids serialization of arbitrary Rust closures (which is unsound)
/// - Allows remote nodes to validate computation names against a registry
///
/// # Example
///
/// ```
/// use asupersync::remote::ComputationName;
///
/// let name = ComputationName::new("encode_block");
/// assert_eq!(name.as_str(), "encode_block");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ComputationName(String);

impl ComputationName {
    /// Creates a new computation name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Returns the computation name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ComputationName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Serialized input
// ---------------------------------------------------------------------------

/// Serialized input for a remote computation.
///
/// The caller is responsible for serialization. The runtime treats this as
/// opaque bytes. The remote node deserializes using the computation's
/// expected schema.
#[derive(Clone, Debug)]
pub struct RemoteInput {
    data: Vec<u8>,
}

impl RemoteInput {
    /// Creates a new remote input from raw bytes.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Creates an empty remote input (for computations that take no arguments).
    #[must_use]
    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }

    /// Returns the serialized data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consumes self and returns the underlying bytes.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Returns the size of the serialized input in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the input is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ---------------------------------------------------------------------------
// RemoteRuntime - High-level transport integration
// ---------------------------------------------------------------------------

/// Abstract interface for the remote runtime (transport + state).
///
/// This trait allows the [`RemoteCap`] to bridge the high-level `spawn_remote`
/// API with the underlying transport (network or virtual harness).
pub trait RemoteRuntime: Send + Sync + fmt::Debug {
    /// Sends a message to the network.
    fn send_message(
        &self,
        destination: &NodeId,
        envelope: MessageEnvelope<RemoteMessage>,
    ) -> Result<(), RemoteError>;

    /// Registers a pending local task expecting a result.
    fn register_task(
        &self,
        task_id: RemoteTaskId,
        tx: oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
    );

    /// Unregisters a pending local task after spawn failure.
    ///
    /// Implementations that keep a pending-results map should remove the
    /// entry for `task_id`. The default implementation is a no-op.
    fn unregister_task(&self, _task_id: RemoteTaskId) {}
}

// ---------------------------------------------------------------------------
// RemoteCap — capability token
// ---------------------------------------------------------------------------

/// Capability token authorizing remote task operations.
///
/// `RemoteCap` is the gate for all remote operations. A [`Cx`] without a
/// `RemoteCap` cannot spawn remote tasks — the call fails at compile time
/// (via the `spawn_remote` signature requiring `&RemoteCap`) or at runtime
/// (via `cx.remote()` returning `None`).
///
/// # Capability Model
///
/// The capability is granted during Cx construction and flows through the
/// capability context. This ensures:
///
/// - Code that doesn't need remote execution never has access to it
/// - Remote authority can be tested by constructing Cx with/without the cap
/// - Auditing which code paths can spawn remote work is straightforward
///
/// # Configuration
///
/// The cap holds optional configuration that governs remote execution policy:
/// - Default lease duration for remote tasks
/// - Budget constraints for remote operations
/// - The transport runtime (if connected)
///
/// # Example
///
/// ```
/// use asupersync::remote::RemoteCap;
///
/// let cap = RemoteCap::new();
/// assert_eq!(cap.default_lease().as_secs(), 30);
/// ```
#[derive(Clone, Debug)]
pub struct RemoteCap {
    /// Default lease duration for remote tasks.
    default_lease: Duration,
    /// Budget ceiling for remote tasks (if set, tighter than region budget).
    remote_budget: Option<Budget>,
    /// Identity used as the origin node for outbound remote protocol messages.
    local_node: NodeId,
    /// The connected remote runtime (transport).
    runtime: Option<Arc<dyn RemoteRuntime>>,
}

impl RemoteCap {
    /// Creates a new `RemoteCap` with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            default_lease: Duration::from_secs(30),
            remote_budget: None,
            local_node: NodeId::new("local"),
            runtime: None,
        }
    }

    /// Sets the default lease duration for remote tasks.
    #[must_use]
    pub fn with_default_lease(mut self, lease: Duration) -> Self {
        self.default_lease = lease;
        self
    }

    /// Sets a budget ceiling for remote tasks.
    #[must_use]
    pub fn with_remote_budget(mut self, budget: Budget) -> Self {
        self.remote_budget = Some(budget);
        self
    }

    /// Sets the local node identity used as protocol origin.
    #[must_use]
    pub fn with_local_node(mut self, node: NodeId) -> Self {
        self.local_node = node;
        self
    }

    /// Attaches a remote runtime (transport).
    #[must_use]
    pub fn with_runtime(mut self, runtime: Arc<dyn RemoteRuntime>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Returns the default lease duration.
    #[must_use]
    pub fn default_lease(&self) -> Duration {
        self.default_lease
    }

    /// Returns the remote budget ceiling, if configured.
    #[must_use]
    pub fn remote_budget(&self) -> Option<&Budget> {
        self.remote_budget.as_ref()
    }

    /// Returns the local node identity used for protocol origin metadata.
    #[must_use]
    pub fn local_node(&self) -> &NodeId {
        &self.local_node
    }

    /// Returns the attached remote runtime, if any.
    #[must_use]
    pub fn runtime(&self) -> Option<&Arc<dyn RemoteRuntime>> {
        self.runtime.as_ref()
    }
}

impl Default for RemoteCap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Remote task state
// ---------------------------------------------------------------------------

/// Lifecycle state of a remote task as observed from the local node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteTaskState {
    /// Spawn request sent, waiting for acknowledgement from remote node.
    Pending,
    /// Remote node acknowledged the spawn; task is running remotely.
    Running,
    /// Remote task completed successfully.
    Completed,
    /// Remote task failed with an error.
    Failed,
    /// Remote task was cancelled.
    Cancelled,
    /// Lease expired without renewal — remote status unknown.
    LeaseExpired,
}

impl fmt::Display for RemoteTaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Running => write!(f, "Running"),
            Self::Completed => write!(f, "Completed"),
            Self::Failed => write!(f, "Failed"),
            Self::Cancelled => write!(f, "Cancelled"),
            Self::LeaseExpired => write!(f, "LeaseExpired"),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during remote task operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteError {
    /// No remote capability available in the context.
    NoCapability,
    /// The remote node is unreachable or unknown.
    NodeUnreachable(String),
    /// The computation name is not registered on the remote node.
    UnknownComputation(String),
    /// The lease expired before the task completed.
    LeaseExpired,
    /// The remote task was cancelled.
    Cancelled(CancelReason),
    /// The remote task panicked.
    RemotePanic(String),
    /// Serialization/deserialization error for inputs or outputs.
    SerializationError(String),
    /// Transport-level error.
    TransportError(String),
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCapability => write!(f, "remote capability not available"),
            Self::NodeUnreachable(node) => write!(f, "node unreachable: {node}"),
            Self::UnknownComputation(name) => {
                write!(f, "unknown computation: {name}")
            }
            Self::LeaseExpired => write!(f, "remote task lease expired"),
            Self::Cancelled(reason) => write!(f, "remote task cancelled: {reason}"),
            Self::RemotePanic(msg) => write!(f, "remote task panicked: {msg}"),
            Self::SerializationError(msg) => write!(f, "serialization error: {msg}"),
            Self::TransportError(msg) => write!(f, "transport error: {msg}"),
        }
    }
}

impl std::error::Error for RemoteError {}

// ---------------------------------------------------------------------------
// RemoteHandle
// ---------------------------------------------------------------------------

/// Handle to a remote task, analogous to [`TaskHandle`](crate::runtime::task_handle::TaskHandle).
///
/// `RemoteHandle` is returned by [`spawn_remote`] and provides:
/// - The remote task ID for identification and tracing
/// - The target node and computation name for debugging
/// - `join()` to await the remote result
/// - `abort()` to request cancellation of the remote task
///
/// # Region Ownership
///
/// The `RemoteHandle` is owned by the local region. When the region closes,
/// all remote handles participate in quiescence: the region waits for remote
/// tasks to complete (or escalates via cancellation/lease expiry).
///
/// # Phase 0
///
/// In Phase 0, the handle wraps a oneshot channel. The actual remote protocol
/// (spawn/ack/cancel/result/heartbeat) is defined in tmh.1.2.
pub struct RemoteHandle {
    /// Unique identifier for this remote task.
    remote_task_id: RemoteTaskId,
    /// Local proxy task ID (if registered in the runtime).
    local_task_id: Option<TaskId>,
    /// Target node.
    node: NodeId,
    /// Computation name.
    computation: ComputationName,
    /// Region that owns this remote task.
    owner_region: RegionId,
    /// Receiver for the remote result.
    receiver: oneshot::Receiver<Result<RemoteOutcome, RemoteError>>,
    /// Lease duration for this task.
    lease: Duration,
    /// Current observed state.
    state: RemoteTaskState,
}

impl fmt::Debug for RemoteHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteHandle")
            .field("remote_task_id", &self.remote_task_id)
            .field("local_task_id", &self.local_task_id)
            .field("node", &self.node)
            .field("computation", &self.computation)
            .field("owner_region", &self.owner_region)
            .field("lease", &self.lease)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl RemoteHandle {
    #[inline]
    fn terminal_state_for_result(result: &Result<RemoteOutcome, RemoteError>) -> RemoteTaskState {
        match result {
            Ok(RemoteOutcome::Success(_)) => RemoteTaskState::Completed,
            Ok(RemoteOutcome::Cancelled(_)) | Err(RemoteError::Cancelled(_)) => {
                RemoteTaskState::Cancelled
            }
            Err(RemoteError::LeaseExpired) => RemoteTaskState::LeaseExpired,
            Ok(RemoteOutcome::Failed(_) | RemoteOutcome::Panicked(_)) | Err(_) => {
                RemoteTaskState::Failed
            }
        }
    }

    /// Returns the remote task ID.
    #[must_use]
    pub fn remote_task_id(&self) -> RemoteTaskId {
        self.remote_task_id
    }

    /// Returns the local proxy task ID, if one was assigned.
    #[must_use]
    pub fn local_task_id(&self) -> Option<TaskId> {
        self.local_task_id
    }

    /// Returns the target node.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// Returns the computation name.
    #[must_use]
    pub fn computation(&self) -> &ComputationName {
        &self.computation
    }

    /// Returns the owning region.
    #[must_use]
    pub fn owner_region(&self) -> RegionId {
        self.owner_region
    }

    /// Returns the lease duration.
    #[must_use]
    pub fn lease(&self) -> Duration {
        self.lease
    }

    /// Returns the current observed state of the remote task.
    #[must_use]
    pub fn state(&self) -> &RemoteTaskState {
        &self.state
    }

    /// Returns true if the remote result is ready.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.receiver.is_ready() || self.receiver.is_closed()
    }

    /// Waits for the remote task to complete and returns its result.
    ///
    /// This method yields until the remote task completes (or fails/cancels).
    ///
    /// # Errors
    ///
    /// Returns `RemoteError` if the remote task failed, was cancelled,
    /// or the lease expired.
    pub async fn join(&mut self, cx: &Cx) -> Result<RemoteOutcome, RemoteError> {
        let result = self.receiver.recv(cx).await.unwrap_or_else(|_| {
            Err(RemoteError::Cancelled(CancelReason::user(
                "remote handle channel closed",
            )))
        });
        self.state = Self::terminal_state_for_result(&result);
        result
    }

    /// Attempts to get the remote task's result without waiting.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(result))` if the remote task has completed
    /// - `Ok(None)` if the remote task is still running
    /// - `Err(RemoteError)` if the remote task failed
    pub fn try_join(&mut self) -> Result<Option<RemoteOutcome>, RemoteError> {
        match self.receiver.try_recv() {
            Ok(result) => {
                self.state = Self::terminal_state_for_result(&result);
                Ok(Some(result?))
            }
            Err(oneshot::TryRecvError::Empty) => Ok(None),
            Err(oneshot::TryRecvError::Closed) => {
                if matches!(
                    self.state,
                    RemoteTaskState::Pending | RemoteTaskState::Running
                ) {
                    self.state = RemoteTaskState::Cancelled;
                }
                Err(RemoteError::Cancelled(CancelReason::user(
                    "remote handle channel closed",
                )))
            }
        }
    }

    /// Requests cancellation of the remote task.
    ///
    /// This is a request — the remote node may not stop immediately.
    /// The cancellation propagates via the remote protocol (Phase 1+).
    ///
    /// In Phase 0, this is a no-op since there is no actual remote node.
    pub fn abort(&self) {
        // Phase 0: No remote node to notify.
        // Phase 1+: Send cancel message via transport.
    }
}

// ---------------------------------------------------------------------------
// spawn_remote
// ---------------------------------------------------------------------------

/// Spawns a named computation on a remote node.
///
/// This is the primary entry point for distributed structured concurrency.
/// The caller specifies:
/// - A target [`NodeId`] identifying where to run the computation
/// - A [`ComputationName`] identifying *what* to run (no closure shipping)
/// - A [`RemoteInput`] containing serialized arguments
///
/// The function requires a [`RemoteCap`] from the [`Cx`], ensuring that
/// remote operations are impossible without explicit capability.
///
/// # Region Ownership
///
/// The returned [`RemoteHandle`] is conceptually owned by the region of
/// the calling task. When the region closes, it waits for all remote
/// handles to resolve (or escalates per policy).
///
/// # Phase 0
///
/// In Phase 0, no actual network communication occurs. The handle is
/// created in [`RemoteTaskState::Pending`] state. The remote protocol
/// (spawn/ack/cancel/result/heartbeat) is defined in tmh.1.2.
///
/// # Errors
///
/// Returns [`RemoteError::NoCapability`] if the context does not have
/// a [`RemoteCap`].
///
/// # Example
///
/// ```ignore
/// use asupersync::remote::{spawn_remote, NodeId, ComputationName, RemoteInput};
///
/// let mut handle = spawn_remote(
///     &cx,
///     NodeId::new("worker-1"),
///     ComputationName::new("encode_block"),
///     RemoteInput::new(serialized_data),
/// )?;
///
/// let result = handle.join(&cx).await?;
/// if let RemoteOutcome::Success(data) = result {
///     // process data
/// }
/// ```
pub fn spawn_remote(
    cx: &Cx,
    node: NodeId,
    computation: ComputationName,
    input: RemoteInput,
) -> Result<RemoteHandle, RemoteError> {
    // Check capability
    let cap = cx.remote().ok_or(RemoteError::NoCapability)?;

    let remote_task_id = RemoteTaskId::next();
    let region = cx.region_id();
    let lease = cap.default_lease();

    cx.trace("spawn_remote");

    // Create the oneshot channel for result delivery.
    let (tx, rx) = oneshot::channel::<Result<RemoteOutcome, RemoteError>>();

    // If a remote runtime is attached, register the task and send the request.
    if let Some(runtime) = cap.runtime() {
        runtime.register_task(remote_task_id, tx);

        let req = SpawnRequest {
            remote_task_id,
            computation: computation.clone(),
            input,
            lease,
            idempotency_key: IdempotencyKey::generate(cx),
            budget: cap.remote_budget,
            origin_node: cap.local_node().clone(),
            origin_region: region,
            origin_task: cx.task_id(),
        };

        // Envelope timestamps always come from the task logical clock.
        let sender_time = cx.logical_now();

        let envelope = MessageEnvelope::new(
            req.origin_node.clone(),
            sender_time,
            RemoteMessage::SpawnRequest(req),
        );
        if let Err(err) = runtime.send_message(&node, envelope) {
            runtime.unregister_task(remote_task_id);
            return Err(err);
        }
    } else {
        // Phase 0: Drop sender (simulates network that never returns)
        // or keep it alive if we want to simulate timeout?
        // Dropping tx means rx.recv() will fail with Closed, which we map to Cancelled.
        // This is fine for Phase 0 stub.
    }

    Ok(RemoteHandle {
        remote_task_id,
        local_task_id: None,
        node,
        computation,
        owner_region: region,
        receiver: rx,
        lease,
        state: RemoteTaskState::Pending,
    })
}

// ===========================================================================
// Lease (tmh.2.1)
// ===========================================================================
//
// A Lease is a time-bounded obligation that keeps remote work alive.
// The holder must renew periodically; expiry triggers cleanup/fencing.
// Leases are obligations (`ObligationKind::Lease`) and block region close.

/// Error type for lease operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    /// The lease has already expired.
    Expired,
    /// The lease has already been released.
    Released,
    /// The lease obligation could not be created (region closed, limit hit).
    CreationFailed(String),
}

impl fmt::Display for LeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => write!(f, "lease expired"),
            Self::Released => write!(f, "lease already released"),
            Self::CreationFailed(msg) => write!(f, "lease creation failed: {msg}"),
        }
    }
}

impl std::error::Error for LeaseError {}

/// A time-bounded obligation that keeps remote work alive.
///
/// Leases are the distributed equivalent of structured ownership. A lease
/// holder must periodically renew the lease; if the lease expires without
/// renewal, the remote side assumes the holder is gone and cleans up.
///
/// # Obligation Integration
///
/// A `Lease` wraps an [`ObligationId`] with `ObligationKind::Lease`. This
/// means the owning region cannot close until the lease is resolved (released
/// or expired). This is how remote tasks participate in region quiescence.
///
/// # Lifecycle
///
/// ```text
/// create() → Active ──renew()──► Active (extended)
///                    │
///                    ├─ release() ──► Released (obligation committed)
///                    │
///                    └─ expires ────► Expired (obligation aborted)
/// ```
///
/// # Example
///
/// ```ignore
/// use asupersync::remote::{Lease, LeaseId};
/// use std::time::Duration;
///
/// let lease = Lease::new(obligation_id, region, task, Duration::from_secs(30), now);
/// assert!(lease.is_active(now));
///
/// // Renew before expiry
/// lease.renew(Duration::from_secs(30), later);
///
/// // Release when done
/// lease.release(even_later);
/// ```
#[derive(Debug)]
pub struct Lease {
    /// The underlying obligation ID.
    obligation_id: ObligationId,
    /// Region owning this lease.
    region: RegionId,
    /// Task holding this lease.
    holder: TaskId,
    /// Absolute expiry time (virtual time in lab, wall time in prod).
    expires_at: Time,
    /// Original lease duration (for diagnostics).
    initial_duration: Duration,
    /// Current state.
    state: LeaseState,
    /// Number of times this lease has been renewed.
    renewal_count: u32,
}

/// State of a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// Lease is active and has not expired.
    Active,
    /// Lease has been explicitly released by the holder.
    Released,
    /// Lease expired without renewal.
    Expired,
}

impl fmt::Display for LeaseState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Released => write!(f, "Released"),
            Self::Expired => write!(f, "Expired"),
        }
    }
}

impl Lease {
    /// Creates a new active lease.
    ///
    /// The `obligation_id` should be created via
    /// `RuntimeState::create_obligation(ObligationKind::Lease, ...)`.
    #[must_use]
    pub fn new(
        obligation_id: ObligationId,
        region: RegionId,
        holder: TaskId,
        duration: Duration,
        now: Time,
    ) -> Self {
        let expires_at = now + duration;
        Self {
            obligation_id,
            region,
            holder,
            expires_at,
            initial_duration: duration,
            state: LeaseState::Active,
            renewal_count: 0,
        }
    }

    /// Returns the underlying obligation ID.
    #[must_use]
    pub fn obligation_id(&self) -> ObligationId {
        self.obligation_id
    }

    /// Returns the owning region.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.region
    }

    /// Returns the holding task.
    #[must_use]
    pub fn holder(&self) -> TaskId {
        self.holder
    }

    /// Returns the absolute expiry time.
    #[must_use]
    pub fn expires_at(&self) -> Time {
        self.expires_at
    }

    /// Returns the initial lease duration.
    #[must_use]
    pub fn initial_duration(&self) -> Duration {
        self.initial_duration
    }

    /// Returns the current lease state.
    #[must_use]
    pub fn state(&self) -> LeaseState {
        self.state
    }

    /// Returns the number of times this lease has been renewed.
    #[must_use]
    pub fn renewal_count(&self) -> u32 {
        self.renewal_count
    }

    /// Returns true if the lease is active (not expired, not released).
    #[must_use]
    pub fn is_active(&self, now: Time) -> bool {
        self.state == LeaseState::Active && now < self.expires_at
    }

    /// Returns true if the lease has expired (time exceeded without renewal).
    #[must_use]
    pub fn is_expired(&self, now: Time) -> bool {
        self.state == LeaseState::Expired
            || (self.state == LeaseState::Active && now >= self.expires_at)
    }

    /// Returns true if the lease has been explicitly released.
    #[must_use]
    pub fn is_released(&self) -> bool {
        self.state == LeaseState::Released
    }

    /// Returns the remaining time before expiry, or zero if expired.
    #[must_use]
    pub fn remaining(&self, now: Time) -> Duration {
        if now >= self.expires_at {
            Duration::ZERO
        } else {
            let nanos = self.expires_at.duration_since(now);
            Duration::from_nanos(nanos)
        }
    }

    /// Renews the lease by extending the expiry from `now`.
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::Expired` if the lease has already expired.
    /// Returns `LeaseError::Released` if the lease was already released.
    pub fn renew(&mut self, duration: Duration, now: Time) -> Result<(), LeaseError> {
        match self.state {
            LeaseState::Released => return Err(LeaseError::Released),
            LeaseState::Expired => return Err(LeaseError::Expired),
            LeaseState::Active => {}
        }
        if now >= self.expires_at {
            self.state = LeaseState::Expired;
            return Err(LeaseError::Expired);
        }
        self.expires_at = now + duration;
        self.renewal_count += 1;
        Ok(())
    }

    /// Explicitly releases the lease.
    ///
    /// This resolves the underlying obligation as committed (clean release).
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::Released` if already released.
    /// Returns `LeaseError::Expired` if already expired.
    pub fn release(&mut self, now: Time) -> Result<(), LeaseError> {
        match self.state {
            LeaseState::Released => return Err(LeaseError::Released),
            LeaseState::Expired => return Err(LeaseError::Expired),
            LeaseState::Active => {}
        }
        self.state = LeaseState::Released;
        // The caller is responsible for committing the obligation in RuntimeState.
        // This method just updates the lease state.
        let _ = now; // used by caller for obligation commit timestamp
        Ok(())
    }

    /// Marks the lease as expired.
    ///
    /// Called by the runtime when it detects that the lease has passed its
    /// expiry time without renewal. The underlying obligation should be
    /// aborted with `ObligationAbortReason::Cancel`.
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::Released` if already released.
    pub fn mark_expired(&mut self) -> Result<(), LeaseError> {
        match self.state {
            LeaseState::Released => return Err(LeaseError::Released),
            LeaseState::Expired => return Ok(()), // idempotent
            LeaseState::Active => {}
        }
        self.state = LeaseState::Expired;
        Ok(())
    }
}

// ===========================================================================
// Idempotency Store (tmh.2.2)
// ===========================================================================
//
// The remote side uses an IdempotencyStore to deduplicate spawn requests.
// Each entry maps an IdempotencyKey to its recorded outcome. Entries expire
// after a configurable TTL to bound memory usage.

/// Recorded outcome of a previously-processed idempotent request.
#[derive(Clone, Debug)]
pub struct IdempotencyRecord {
    /// The key for this record.
    pub key: IdempotencyKey,
    /// The remote task ID assigned to this request.
    pub remote_task_id: RemoteTaskId,
    /// The computation that was requested.
    pub computation: ComputationName,
    /// When this record was created.
    pub created_at: Time,
    /// When this record expires (for eviction).
    pub expires_at: Time,
    /// The outcome, if the request has completed.
    pub outcome: Option<RemoteOutcome>,
}

/// Decision from the idempotency store when a request arrives.
#[derive(Clone, Debug)]
pub enum DedupDecision {
    /// New request — not seen before. Proceed with execution.
    New,
    /// Duplicate request — already processed. Return cached result.
    Duplicate(IdempotencyRecord),
    /// Conflict — same key but different parameters. Reject.
    Conflict,
}

/// Store for tracking idempotent request deduplication.
///
/// The remote node uses this to ensure exactly-once execution semantics.
/// When a `SpawnRequest` arrives:
/// 1. Check the store for the idempotency key
/// 2. If new: record and execute
/// 3. If duplicate: return cached ack/result
/// 4. If conflict (same key, different params): reject
///
/// Entries are evicted after their TTL expires.
///
/// # Thread Safety
///
/// The store is designed for single-threaded use within the deterministic
/// lab runtime. For production multi-threaded use, wrap in a lock.
pub struct IdempotencyStore {
    entries: DetHashMap<IdempotencyKey, IdempotencyRecord>,
    /// Default TTL for new entries.
    default_ttl: Duration,
}

impl IdempotencyStore {
    /// Creates a new idempotency store with the given default TTL.
    #[must_use]
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            entries: DetHashMap::default(),
            default_ttl,
        }
    }

    /// Checks whether a request with the given key has been seen before.
    ///
    /// This does NOT insert the key — call [`record`](Self::record) to do that.
    #[must_use]
    pub fn check(&self, key: &IdempotencyKey, computation: &ComputationName) -> DedupDecision {
        self.entries.get(key).map_or(DedupDecision::New, |record| {
            if record.computation == *computation {
                DedupDecision::Duplicate(record.clone())
            } else {
                DedupDecision::Conflict
            }
        })
    }

    /// Records a new idempotent request.
    ///
    /// Returns `true` if the entry was inserted (new key).
    /// Returns `false` if the key already existed (no update).
    pub fn record(
        &mut self,
        key: IdempotencyKey,
        remote_task_id: RemoteTaskId,
        computation: ComputationName,
        now: Time,
    ) -> bool {
        use std::collections::hash_map::Entry;
        match self.entries.entry(key) {
            Entry::Vacant(e) => {
                let expires_at = now + self.default_ttl;
                e.insert(IdempotencyRecord {
                    key,
                    remote_task_id,
                    computation,
                    created_at: now,
                    expires_at,
                    outcome: None,
                });
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Updates the outcome of a previously-recorded request.
    ///
    /// Returns `true` if the record was found and updated.
    pub fn complete(&mut self, key: &IdempotencyKey, outcome: RemoteOutcome) -> bool {
        match self.entries.get_mut(key) {
            Some(record) => {
                record.outcome = Some(outcome);
                true
            }
            None => false,
        }
    }

    /// Evicts expired entries.
    ///
    /// Returns the number of entries evicted.
    pub fn evict_expired(&mut self, now: Time) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, record| now < record.expires_at);
        before - self.entries.len()
    }

    /// Returns the number of entries in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Debug for IdempotencyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdempotencyStore")
            .field("entries", &self.entries.len())
            .field("default_ttl", &self.default_ttl)
            .finish()
    }
}

// ===========================================================================
// Saga Framework (tmh.2.3)
// ===========================================================================
//
// A Saga is a sequence of steps where each step has a forward action and a
// compensation. On failure, compensations run in reverse order. This is the
// distributed equivalent of structured finalizers.

/// Identifier for a saga step.
pub type StepIndex = usize;

/// A recorded compensation for a saga step.
///
/// Compensations are stored as boxed closures that take the step output
/// and undo the effect. In Phase 0, compensations are synchronous functions
/// that return a description of what was undone.
///
/// In Phase 1+, compensations will be async and budget-constrained.
struct CompensationEntry {
    /// Index of the step this compensation belongs to.
    step: StepIndex,
    /// Description of the step (for tracing).
    description: String,
    /// The compensation function.
    compensate: Box<dyn FnOnce() -> String + Send>,
}

impl fmt::Debug for CompensationEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompensationEntry")
            .field("step", &self.step)
            .field("description", &self.description)
            .finish_non_exhaustive()
    }
}

/// State of a saga.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SagaState {
    /// Saga is executing forward steps.
    Running,
    /// Saga completed all steps successfully.
    Completed,
    /// Saga is executing compensations (rolling back).
    Compensating,
    /// Saga finished compensating (all compensations ran).
    Aborted,
}

impl fmt::Display for SagaState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => write!(f, "Running"),
            Self::Completed => write!(f, "Completed"),
            Self::Compensating => write!(f, "Compensating"),
            Self::Aborted => write!(f, "Aborted"),
        }
    }
}

/// Error from a saga step.
#[derive(Debug, Clone)]
pub struct SagaStepError {
    /// Which step failed.
    pub step: StepIndex,
    /// Description of the step.
    pub description: String,
    /// The error message.
    pub message: String,
}

impl fmt::Display for SagaStepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "saga step {} ({}) failed: {}",
            self.step, self.description, self.message
        )
    }
}

impl std::error::Error for SagaStepError {}

/// A record of a compensation that was executed during saga abort.
#[derive(Debug, Clone)]
pub struct CompensationResult {
    /// The step index that was compensated.
    pub step: StepIndex,
    /// Description of the step.
    pub description: String,
    /// Description of what the compensation did.
    pub result: String,
}

/// Saga: a sequence of steps with structured compensations.
///
/// Each step has a forward action and a compensation. If any step fails,
/// all previously-completed compensations run in reverse order. This is
/// the distributed equivalent of structured finalizers.
///
/// # Design Principles
///
/// - **Compensations are deterministic**: Given the same inputs, compensations
///   produce the same effects. This enables lab testing of failure scenarios.
/// - **Reverse order**: Compensations run last-to-first, ensuring that
///   later steps' effects are undone before earlier steps'.
/// - **Budget-aware**: In Phase 1+, compensations will be budget-constrained
///   (they are finalizers, which run under masked cancellation).
/// - **Trace-aware**: Each step and compensation emits trace events.
///
/// # API Pattern
///
/// The compensation closure captures its own context. The forward action
/// returns a value for the caller to use in subsequent steps.
///
/// ```ignore
/// use asupersync::remote::Saga;
///
/// let mut saga = Saga::new();
///
/// // Step 1: Create resource — compensation captures what it needs
/// let id = "resource-1".to_string();
/// let id_for_comp = id.clone();
/// saga.step(
///     "create resource",
///     || Ok(id),
///     move || format!("deleted {id_for_comp}"),
/// )?;
///
/// // Step 2: Configure — no value needed for compensation
/// saga.step("configure", || Ok(()), || "reset config".into())?;
///
/// // Complete on success
/// saga.complete();
/// ```
pub struct Saga {
    /// Current state.
    state: SagaState,
    /// Registered compensations (in forward order; executed in reverse).
    compensations: Vec<CompensationEntry>,
    /// Number of completed steps.
    completed_steps: StepIndex,
    /// Results from compensation execution (if aborted).
    compensation_results: Vec<CompensationResult>,
}

impl fmt::Debug for Saga {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Saga")
            .field("state", &self.state)
            .field("completed_steps", &self.completed_steps)
            .field("compensations", &self.compensations.len())
            .field("compensation_results", &self.compensation_results)
            .finish()
    }
}

impl Saga {
    /// Creates a new empty saga.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: SagaState::Running,
            compensations: Vec::new(),
            completed_steps: 0,
            compensation_results: Vec::new(),
        }
    }

    /// Returns the current saga state.
    #[must_use]
    pub fn state(&self) -> SagaState {
        self.state
    }

    /// Returns the number of completed steps.
    #[must_use]
    pub fn completed_steps(&self) -> StepIndex {
        self.completed_steps
    }

    /// Returns the compensation results (populated after abort).
    #[must_use]
    pub fn compensation_results(&self) -> &[CompensationResult] {
        &self.compensation_results
    }

    /// Executes a forward step and registers its compensation.
    ///
    /// The forward action runs immediately. If it succeeds, the compensation
    /// closure is registered for potential rollback. If it fails, the saga
    /// enters the compensating state and runs all registered compensations
    /// in reverse order.
    ///
    /// The compensation closure should capture whatever context it needs
    /// to undo the forward action's effect (e.g., clone the resource ID
    /// before passing it to the step).
    ///
    /// # Errors
    ///
    /// Returns `SagaStepError` if the forward action fails. In that case,
    /// compensations have already been executed before this returns.
    pub fn step<T>(
        &mut self,
        description: &str,
        action: impl FnOnce() -> Result<T, String>,
        compensate: impl FnOnce() -> String + Send + 'static,
    ) -> Result<T, SagaStepError> {
        assert_eq!(
            self.state,
            SagaState::Running,
            "cannot add steps to a saga that is not Running"
        );

        let step_idx = self.completed_steps;

        match action() {
            Ok(value) => {
                self.compensations.push(CompensationEntry {
                    step: step_idx,
                    description: description.to_string(),
                    compensate: Box::new(compensate),
                });
                self.completed_steps += 1;
                Ok(value)
            }
            Err(msg) => {
                let err = SagaStepError {
                    step: step_idx,
                    description: description.to_string(),
                    message: msg,
                };
                self.run_compensations();
                Err(err)
            }
        }
    }

    /// Marks the saga as successfully completed.
    ///
    /// After completion, the registered compensations are dropped (they
    /// are no longer needed since all steps succeeded).
    ///
    /// # Panics
    ///
    /// Panics if the saga is not in `Running` state.
    pub fn complete(&mut self) {
        assert_eq!(
            self.state,
            SagaState::Running,
            "can only complete a Running saga"
        );
        self.state = SagaState::Completed;
        self.compensations.clear();
    }

    /// Explicitly aborts the saga, running compensations in reverse order.
    ///
    /// This is called when the caller wants to roll back, even if no step
    /// has failed. For example, when cancellation is requested.
    ///
    /// # Panics
    ///
    /// Panics if the saga is not in `Running` state.
    pub fn abort(&mut self) {
        assert_eq!(
            self.state,
            SagaState::Running,
            "can only abort a Running saga"
        );
        self.run_compensations();
    }

    /// Runs compensations in reverse order.
    fn run_compensations(&mut self) {
        self.state = SagaState::Compensating;
        let compensations: Vec<_> = self.compensations.drain(..).collect();
        for entry in compensations.into_iter().rev() {
            let result_desc = (entry.compensate)();
            self.compensation_results.push(CompensationResult {
                step: entry.step,
                description: entry.description,
                result: result_desc,
            });
        }
        self.state = SagaState::Aborted;
    }
}

impl Default for Saga {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Saga {
    fn drop(&mut self) {
        if self.state == SagaState::Running {
            // Unwind or early return: execute compensations to prevent leaks.
            // If we are already panicking, running compensations that panic will abort the process.
            self.run_compensations();
        }
    }
}

//
//   1. SpawnRequest  — originator → remote node
//   2. SpawnAck      — remote node → originator
//   3. CancelRequest — originator → remote node (or reverse for lease expiry)
//   4. ResultDelivery — remote node → originator
//   5. LeaseRenewal  — bidirectional heartbeat/renewal
//
// All messages carry the RemoteTaskId for correlation. The protocol is
// idempotent: duplicate SpawnRequests with the same IdempotencyKey are
// deduplicated by the remote node.

// ---------------------------------------------------------------------------
// Idempotency key
// ---------------------------------------------------------------------------

/// Idempotency key for exactly-once remote spawn semantics.
///
/// The originator generates a unique key per spawn request. The remote node
/// uses this to deduplicate retried requests (e.g., after network partition
/// recovery). Keys are 128-bit random values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(u128);

impl IdempotencyKey {
    /// Generates a new random idempotency key from the context's entropy.
    #[must_use]
    pub fn generate(cx: &Cx) -> Self {
        let high = cx.random_u64();
        let low = cx.random_u64();
        Self((u128::from(high) << 64) | u128::from(low))
    }

    /// Creates an idempotency key from a raw value (for testing/deserialization).
    #[must_use]
    pub const fn from_raw(value: u128) -> Self {
        Self(value)
    }

    /// Returns the raw 128-bit value.
    #[must_use]
    pub const fn raw(self) -> u128 {
        self.0
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IK-{:032x}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Protocol messages
// ---------------------------------------------------------------------------

/// Envelope for protocol messages with logical time metadata.
///
/// The `sender_time` field carries the sender's logical clock snapshot,
/// enabling causal ordering across nodes without relying on wall clocks.
#[derive(Clone, Debug)]
pub struct MessageEnvelope<T> {
    /// Logical identity of the sender.
    pub sender: NodeId,
    /// Logical time at send.
    pub sender_time: LogicalTime,
    /// The wrapped protocol message.
    pub payload: T,
}

impl<T> MessageEnvelope<T> {
    /// Creates a new message envelope.
    #[must_use]
    pub fn new(sender: NodeId, sender_time: LogicalTime, payload: T) -> Self {
        Self {
            sender,
            sender_time,
            payload,
        }
    }
}

/// Transport hook for Phase 1+ remote protocol integration.
///
/// Implementations are responsible for framing, handshake, and delivery of
/// `RemoteMessage` envelopes between nodes. The runtime remains transport-agnostic.
pub trait RemoteTransport {
    /// Send a protocol message to a target node.
    ///
    /// Implementations should perform version checks and framing at the
    /// transport layer.
    fn send(
        &mut self,
        to: &NodeId,
        envelope: MessageEnvelope<RemoteMessage>,
    ) -> Result<(), RemoteError>;

    /// Try to receive the next inbound protocol message.
    ///
    /// Returns `None` if no message is available.
    fn try_recv(&mut self) -> Option<MessageEnvelope<RemoteMessage>>;
}

/// A message in the remote structured concurrency protocol.
///
/// All protocol messages are tagged with the enum variant for dispatch.
/// Each message carries the `RemoteTaskId` for correlation.
#[derive(Clone, Debug)]
pub enum RemoteMessage {
    /// Request to spawn a named computation on a remote node.
    SpawnRequest(SpawnRequest),
    /// Acknowledgement of a spawn request (accepted or rejected).
    SpawnAck(SpawnAck),
    /// Request to cancel a running remote task.
    CancelRequest(CancelRequest),
    /// Delivery of a remote task's terminal result.
    ResultDelivery(ResultDelivery),
    /// Lease renewal / heartbeat for an active remote task.
    LeaseRenewal(LeaseRenewal),
}

impl RemoteMessage {
    /// Returns the remote task ID associated with this message.
    #[must_use]
    pub fn remote_task_id(&self) -> RemoteTaskId {
        match self {
            Self::SpawnRequest(m) => m.remote_task_id,
            Self::SpawnAck(m) => m.remote_task_id,
            Self::CancelRequest(m) => m.remote_task_id,
            Self::ResultDelivery(m) => m.remote_task_id,
            Self::LeaseRenewal(m) => m.remote_task_id,
        }
    }
}

// ---------------------------------------------------------------------------
// SpawnRequest
// ---------------------------------------------------------------------------

/// Request to spawn a named computation on a remote node.
///
/// Contains all information needed to start a remote task:
/// - What to run (computation name + serialized inputs)
/// - Who is asking (origin node, region, task)
/// - How long to keep it alive (lease)
/// - Deduplication key (idempotency)
///
/// # Idempotency
///
/// The `idempotency_key` ensures exactly-once execution. If the remote node
/// receives a duplicate SpawnRequest (same key), it returns the existing
/// SpawnAck without re-executing.
#[derive(Clone, Debug)]
pub struct SpawnRequest {
    /// Unique identifier for this remote task.
    pub remote_task_id: RemoteTaskId,
    /// Name of the computation to execute.
    pub computation: ComputationName,
    /// Serialized input data.
    pub input: RemoteInput,
    /// Requested lease duration.
    pub lease: Duration,
    /// Idempotency key for deduplication.
    pub idempotency_key: IdempotencyKey,
    /// Budget constraints for the remote task (optional).
    pub budget: Option<Budget>,
    /// Node that originated the request.
    pub origin_node: NodeId,
    /// Region that owns the remote task on the originator.
    pub origin_region: RegionId,
    /// Task that spawned the remote task on the originator.
    pub origin_task: TaskId,
}

// ---------------------------------------------------------------------------
// SpawnAck
// ---------------------------------------------------------------------------

/// Acknowledgement of a spawn request.
///
/// Sent by the remote node back to the originator to confirm or reject
/// the spawn request.
#[derive(Clone, Debug)]
pub struct SpawnAck {
    /// The remote task ID from the original request.
    pub remote_task_id: RemoteTaskId,
    /// Whether the spawn was accepted or rejected.
    pub status: SpawnAckStatus,
    /// The node that will execute the task (may differ from target if redirected).
    pub assigned_node: NodeId,
}

/// Status of a spawn acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpawnAckStatus {
    /// The remote node accepted the spawn request; task is running.
    Accepted,
    /// The remote node rejected the spawn request.
    Rejected(SpawnRejectReason),
}

/// Reason for rejecting a spawn request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpawnRejectReason {
    /// The computation name is not registered on the remote node.
    UnknownComputation,
    /// The remote node is at capacity and cannot accept more tasks.
    CapacityExceeded,
    /// The remote node is shutting down.
    NodeShuttingDown,
    /// The input data is invalid for this computation.
    InvalidInput(String),
    /// The idempotency key was already used with different parameters.
    IdempotencyConflict,
}

impl fmt::Display for SpawnRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownComputation => write!(f, "unknown computation"),
            Self::CapacityExceeded => write!(f, "capacity exceeded"),
            Self::NodeShuttingDown => write!(f, "node shutting down"),
            Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            Self::IdempotencyConflict => write!(f, "idempotency conflict"),
        }
    }
}

// ---------------------------------------------------------------------------
// CancelRequest
// ---------------------------------------------------------------------------

/// Request to cancel a running remote task.
///
/// Sent by the originator to request cancellation, or by the remote node
/// to propagate a lease-expiry cancellation back.
#[derive(Clone, Debug)]
pub struct CancelRequest {
    /// The remote task ID to cancel.
    pub remote_task_id: RemoteTaskId,
    /// The cancellation reason.
    pub reason: CancelReason,
    /// The node sending the cancel request.
    pub origin_node: NodeId,
}

// ---------------------------------------------------------------------------
// ResultDelivery
// ---------------------------------------------------------------------------

/// Delivery of a remote task's terminal result.
///
/// Sent by the remote node to the originator when the task completes
/// (success, failure, cancellation, or panic).
#[derive(Clone, Debug)]
pub struct ResultDelivery {
    /// The remote task ID.
    pub remote_task_id: RemoteTaskId,
    /// The terminal outcome.
    pub outcome: RemoteOutcome,
    /// Wall-clock execution time on the remote node.
    pub execution_time: Duration,
}

/// Terminal outcome of a remote task execution.
///
/// This mirrors the local [`Outcome`](crate::types::Outcome) lattice but
/// carries serialized data instead of typed values.
#[derive(Clone, Debug)]
pub enum RemoteOutcome {
    /// The computation completed successfully. Payload is serialized output.
    Success(Vec<u8>),
    /// The computation failed with an application error.
    Failed(String),
    /// The computation was cancelled.
    Cancelled(CancelReason),
    /// The computation panicked.
    Panicked(String),
}

impl RemoteOutcome {
    /// Returns the severity level of this outcome.
    #[must_use]
    pub fn severity(&self) -> crate::types::Severity {
        match self {
            Self::Success(_) => crate::types::Severity::Ok,
            Self::Failed(_) => crate::types::Severity::Err,
            Self::Cancelled(_) => crate::types::Severity::Cancelled,
            Self::Panicked(_) => crate::types::Severity::Panicked,
        }
    }

    /// Returns true if this outcome represents success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }
}

impl fmt::Display for RemoteOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success(_) => write!(f, "Success"),
            Self::Failed(msg) => write!(f, "Failed: {msg}"),
            Self::Cancelled(reason) => write!(f, "Cancelled: {reason}"),
            Self::Panicked(msg) => write!(f, "Panicked: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// LeaseRenewal
// ---------------------------------------------------------------------------

/// Lease renewal / heartbeat for an active remote task.
///
/// Sent periodically by the remote node to the originator (or vice versa)
/// to confirm the task is still alive and extend the lease.
///
/// If no renewal is received within the lease window, the originator
/// transitions the handle to [`RemoteTaskState::LeaseExpired`] and may
/// escalate (cancel, retry, or fail the region).
#[derive(Clone, Debug)]
pub struct LeaseRenewal {
    /// The remote task ID.
    pub remote_task_id: RemoteTaskId,
    /// Requested new lease duration (from now).
    pub new_lease: Duration,
    /// Current state of the remote task.
    pub current_state: RemoteTaskState,
    /// Node sending the renewal.
    pub node: NodeId,
}

// ---------------------------------------------------------------------------
// Session-typed protocol states
// ---------------------------------------------------------------------------

/// Errors surfaced by the session-typed remote protocol state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteProtocolError {
    /// Message correlated to a different remote task id than this session.
    RemoteTaskIdMismatch {
        /// Expected task id.
        expected: RemoteTaskId,
        /// Actual task id from the message.
        got: RemoteTaskId,
    },
    /// Spawn acknowledgement status did not match the expected transition.
    UnexpectedAckStatus {
        /// Expected status label.
        expected: &'static str,
        /// Actual status.
        got: SpawnAckStatus,
    },
}

impl fmt::Display for RemoteProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemoteTaskIdMismatch { expected, got } => {
                write!(f, "remote task id mismatch: expected {expected}, got {got}")
            }
            Self::UnexpectedAckStatus { expected, got } => write!(
                f,
                "unexpected spawn ack status: expected {expected}, got {got:?}"
            ),
        }
    }
}

impl std::error::Error for RemoteProtocolError {}

/// Origin-side session state: prior to sending a spawn request.
#[derive(Debug)]
pub struct OriginInit;
/// Origin-side session state: spawn request sent, awaiting ack.
#[derive(Debug)]
pub struct OriginSpawned;
/// Origin-side session state: remote task running.
#[derive(Debug)]
pub struct OriginRunning;
/// Origin-side session state: cancellation request sent.
#[derive(Debug)]
pub struct OriginCancelSent;
/// Origin-side session state: lease expired without renewal.
#[derive(Debug)]
pub struct OriginLeaseExpired;
/// Origin-side session state: terminal result received.
#[derive(Debug)]
pub struct OriginCompleted;
/// Origin-side session state: spawn rejected by remote.
#[derive(Debug)]
pub struct OriginRejected;

/// Remote-side session state: prior to receiving a spawn request.
#[derive(Debug)]
pub struct RemoteInit;
/// Remote-side session state: spawn request received, awaiting ack response.
#[derive(Debug)]
pub struct RemoteSpawnReceived;
/// Remote-side session state: cancel received before ack was sent.
#[derive(Debug)]
pub struct RemoteCancelPending;
/// Remote-side session state: remote task running.
#[derive(Debug)]
pub struct RemoteRunning;
/// Remote-side session state: cancel received while running.
#[derive(Debug)]
pub struct RemoteCancelReceived;
/// Remote-side session state: terminal result sent.
#[derive(Debug)]
pub struct RemoteCompleted;
/// Remote-side session state: spawn rejected.
#[derive(Debug)]
pub struct RemoteRejected;

/// Session-typed protocol state machine for the originator.
#[must_use = "OriginSession must be advanced to completion or rejected"]
#[derive(Debug)]
pub struct OriginSession<S> {
    remote_task_id: RemoteTaskId,
    _state: PhantomData<S>,
}

impl OriginSession<OriginInit> {
    /// Creates a new origin-side session for a given remote task id.
    pub fn new(remote_task_id: RemoteTaskId) -> Self {
        Self {
            remote_task_id,
            _state: PhantomData,
        }
    }

    /// Send a spawn request, transitioning into `OriginSpawned`.
    pub fn send_spawn(
        self,
        req: &SpawnRequest,
    ) -> Result<OriginSession<OriginSpawned>, RemoteProtocolError> {
        self.ensure_id(req.remote_task_id)?;
        Ok(self.transition())
    }
}

impl<S> OriginSession<S> {
    /// Returns the correlated remote task id.
    #[must_use]
    pub fn remote_task_id(&self) -> RemoteTaskId {
        self.remote_task_id
    }

    fn ensure_id(&self, got: RemoteTaskId) -> Result<(), RemoteProtocolError> {
        if self.remote_task_id == got {
            Ok(())
        } else {
            Err(RemoteProtocolError::RemoteTaskIdMismatch {
                expected: self.remote_task_id,
                got,
            })
        }
    }

    fn transition<T>(self) -> OriginSession<T> {
        OriginSession {
            remote_task_id: self.remote_task_id,
            _state: PhantomData,
        }
    }
}

/// Outcome of a spawn acknowledgement on the origin side.
pub enum OriginAckOutcome {
    /// Spawn accepted; session is running.
    Accepted(OriginSession<OriginRunning>),
    /// Spawn rejected; session ends.
    Rejected(OriginSession<OriginRejected>),
}

impl OriginSession<OriginSpawned> {
    /// Receive the spawn acknowledgement and transition to running or rejected.
    pub fn recv_spawn_ack(self, ack: &SpawnAck) -> Result<OriginAckOutcome, RemoteProtocolError> {
        self.ensure_id(ack.remote_task_id)?;
        match ack.status {
            SpawnAckStatus::Accepted => Ok(OriginAckOutcome::Accepted(self.transition())),
            SpawnAckStatus::Rejected(_) => Ok(OriginAckOutcome::Rejected(self.transition())),
        }
    }

    /// Send a cancellation before receiving the spawn ack.
    pub fn send_cancel(
        self,
        cancel: &CancelRequest,
    ) -> Result<OriginSession<OriginCancelSent>, RemoteProtocolError> {
        self.ensure_id(cancel.remote_task_id)?;
        Ok(self.transition())
    }
}

impl OriginSession<OriginRunning> {
    /// Receive a lease renewal while running.
    pub fn recv_lease_renewal(self, renewal: &LeaseRenewal) -> Result<Self, RemoteProtocolError> {
        self.ensure_id(renewal.remote_task_id)?;
        Ok(self)
    }

    /// Send a cancellation request while running.
    pub fn send_cancel(
        self,
        cancel: &CancelRequest,
    ) -> Result<OriginSession<OriginCancelSent>, RemoteProtocolError> {
        self.ensure_id(cancel.remote_task_id)?;
        Ok(self.transition())
    }

    /// Receive the terminal result.
    pub fn recv_result(
        self,
        result: &ResultDelivery,
    ) -> Result<OriginSession<OriginCompleted>, RemoteProtocolError> {
        self.ensure_id(result.remote_task_id)?;
        Ok(self.transition())
    }

    /// Mark the lease as expired without renewal.
    pub fn lease_expired(self) -> OriginSession<OriginLeaseExpired> {
        self.transition()
    }
}

impl OriginSession<OriginCancelSent> {
    /// Receive the terminal result after cancellation.
    pub fn recv_result(
        self,
        result: &ResultDelivery,
    ) -> Result<OriginSession<OriginCompleted>, RemoteProtocolError> {
        self.ensure_id(result.remote_task_id)?;
        Ok(self.transition())
    }

    /// Accept a lease renewal while waiting for completion.
    pub fn recv_lease_renewal(self, renewal: &LeaseRenewal) -> Result<Self, RemoteProtocolError> {
        self.ensure_id(renewal.remote_task_id)?;
        Ok(self)
    }
}

impl OriginSession<OriginLeaseExpired> {
    /// Send a cancellation request after lease expiry.
    pub fn send_cancel(
        self,
        cancel: &CancelRequest,
    ) -> Result<OriginSession<OriginCancelSent>, RemoteProtocolError> {
        self.ensure_id(cancel.remote_task_id)?;
        Ok(self.transition())
    }

    /// Receive a late terminal result after lease expiry.
    pub fn recv_result(
        self,
        result: &ResultDelivery,
    ) -> Result<OriginSession<OriginCompleted>, RemoteProtocolError> {
        self.ensure_id(result.remote_task_id)?;
        Ok(self.transition())
    }
}

/// Session-typed protocol state machine for the remote node.
#[must_use = "RemoteSession must be advanced to completion or rejected"]
#[derive(Debug)]
pub struct RemoteSession<S> {
    remote_task_id: RemoteTaskId,
    _state: PhantomData<S>,
}

impl RemoteSession<RemoteInit> {
    /// Creates a new remote-side session for a given remote task id.
    pub fn new(remote_task_id: RemoteTaskId) -> Self {
        Self {
            remote_task_id,
            _state: PhantomData,
        }
    }

    /// Receive a spawn request.
    pub fn recv_spawn(
        self,
        req: &SpawnRequest,
    ) -> Result<RemoteSession<RemoteSpawnReceived>, RemoteProtocolError> {
        self.ensure_id(req.remote_task_id)?;
        Ok(self.transition())
    }
}

impl<S> RemoteSession<S> {
    /// Returns the correlated remote task id.
    #[must_use]
    pub fn remote_task_id(&self) -> RemoteTaskId {
        self.remote_task_id
    }

    fn ensure_id(&self, got: RemoteTaskId) -> Result<(), RemoteProtocolError> {
        if self.remote_task_id == got {
            Ok(())
        } else {
            Err(RemoteProtocolError::RemoteTaskIdMismatch {
                expected: self.remote_task_id,
                got,
            })
        }
    }

    fn transition<T>(self) -> RemoteSession<T> {
        RemoteSession {
            remote_task_id: self.remote_task_id,
            _state: PhantomData,
        }
    }
}

impl RemoteSession<RemoteSpawnReceived> {
    /// Send an accepted spawn acknowledgement.
    pub fn send_ack_accepted(
        self,
        ack: &SpawnAck,
    ) -> Result<RemoteSession<RemoteRunning>, RemoteProtocolError> {
        self.ensure_id(ack.remote_task_id)?;
        match ack.status {
            SpawnAckStatus::Accepted => Ok(self.transition()),
            SpawnAckStatus::Rejected(_) => Err(RemoteProtocolError::UnexpectedAckStatus {
                expected: "Accepted",
                got: ack.status.clone(),
            }),
        }
    }

    /// Send a rejected spawn acknowledgement.
    pub fn send_ack_rejected(
        self,
        ack: &SpawnAck,
    ) -> Result<RemoteSession<RemoteRejected>, RemoteProtocolError> {
        self.ensure_id(ack.remote_task_id)?;
        match ack.status {
            SpawnAckStatus::Rejected(_) => Ok(self.transition()),
            SpawnAckStatus::Accepted => Err(RemoteProtocolError::UnexpectedAckStatus {
                expected: "Rejected",
                got: ack.status.clone(),
            }),
        }
    }

    /// Receive a cancellation before the spawn ack is sent.
    pub fn recv_cancel(
        self,
        cancel: &CancelRequest,
    ) -> Result<RemoteSession<RemoteCancelPending>, RemoteProtocolError> {
        self.ensure_id(cancel.remote_task_id)?;
        Ok(self.transition())
    }
}

impl RemoteSession<RemoteCancelPending> {
    /// Send an accepted spawn acknowledgement while a cancel is pending.
    pub fn send_ack_accepted(
        self,
        ack: &SpawnAck,
    ) -> Result<RemoteSession<RemoteCancelReceived>, RemoteProtocolError> {
        self.ensure_id(ack.remote_task_id)?;
        match ack.status {
            SpawnAckStatus::Accepted => Ok(self.transition()),
            SpawnAckStatus::Rejected(_) => Err(RemoteProtocolError::UnexpectedAckStatus {
                expected: "Accepted",
                got: ack.status.clone(),
            }),
        }
    }

    /// Send a rejected spawn acknowledgement while a cancel is pending.
    pub fn send_ack_rejected(
        self,
        ack: &SpawnAck,
    ) -> Result<RemoteSession<RemoteRejected>, RemoteProtocolError> {
        self.ensure_id(ack.remote_task_id)?;
        match ack.status {
            SpawnAckStatus::Rejected(_) => Ok(self.transition()),
            SpawnAckStatus::Accepted => Err(RemoteProtocolError::UnexpectedAckStatus {
                expected: "Rejected",
                got: ack.status.clone(),
            }),
        }
    }
}

impl RemoteSession<RemoteRunning> {
    /// Receive a cancellation while running.
    pub fn recv_cancel(
        self,
        cancel: &CancelRequest,
    ) -> Result<RemoteSession<RemoteCancelReceived>, RemoteProtocolError> {
        self.ensure_id(cancel.remote_task_id)?;
        Ok(self.transition())
    }

    /// Send a lease renewal heartbeat.
    pub fn send_lease_renewal(self, renewal: &LeaseRenewal) -> Result<Self, RemoteProtocolError> {
        self.ensure_id(renewal.remote_task_id)?;
        Ok(self)
    }

    /// Send the terminal result.
    pub fn send_result(
        self,
        result: &ResultDelivery,
    ) -> Result<RemoteSession<RemoteCompleted>, RemoteProtocolError> {
        self.ensure_id(result.remote_task_id)?;
        Ok(self.transition())
    }
}

impl RemoteSession<RemoteCancelReceived> {
    /// Send the terminal result after cancellation.
    pub fn send_result(
        self,
        result: &ResultDelivery,
    ) -> Result<RemoteSession<RemoteCompleted>, RemoteProtocolError> {
        self.ensure_id(result.remote_task_id)?;
        Ok(self.transition())
    }
}

// ---------------------------------------------------------------------------
// Trace events for protocol messages
// ---------------------------------------------------------------------------

/// Trace event names for remote protocol messages.
///
/// These are used with `cx.trace()` to emit structured trace events
/// that represent the remote message flow. They enable deterministic
/// replay and debugging of distributed scenarios in the lab runtime.
pub mod trace_events {
    /// Emitted when a spawn request is created.
    pub const SPAWN_REQUEST_CREATED: &str = "remote::spawn_request_created";
    /// Emitted when a spawn request is sent to the transport.
    pub const SPAWN_REQUEST_SENT: &str = "remote::spawn_request_sent";
    /// Emitted when a spawn ack is received.
    pub const SPAWN_ACK_RECEIVED: &str = "remote::spawn_ack_received";
    /// Emitted when a spawn request is rejected.
    pub const SPAWN_REJECTED: &str = "remote::spawn_rejected";
    /// Emitted when a cancel request is sent.
    pub const CANCEL_SENT: &str = "remote::cancel_sent";
    /// Emitted when a cancel request is received on the remote side.
    pub const CANCEL_RECEIVED: &str = "remote::cancel_received";
    /// Emitted when a result is delivered.
    pub const RESULT_DELIVERED: &str = "remote::result_delivered";
    /// Emitted when a lease renewal is sent.
    pub const LEASE_RENEWAL_SENT: &str = "remote::lease_renewal_sent";
    /// Emitted when a lease renewal is received.
    pub const LEASE_RENEWAL_RECEIVED: &str = "remote::lease_renewal_received";
    /// Emitted when a lease expires without renewal.
    pub const LEASE_EXPIRED: &str = "remote::lease_expired";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    #[test]
    fn node_id_basics() {
        let node = NodeId::new("worker-1");
        assert_eq!(node.as_str(), "worker-1");
        assert_eq!(format!("{node}"), "Node(worker-1)");

        let node2 = NodeId::new("worker-1");
        assert_eq!(node, node2);

        let node3 = NodeId::new("worker-2");
        assert_ne!(node, node3);
    }

    #[test]
    fn computation_name_basics() {
        let name = ComputationName::new("encode_block");
        assert_eq!(name.as_str(), "encode_block");
        assert_eq!(format!("{name}"), "encode_block");

        let name2 = ComputationName::new("encode_block");
        assert_eq!(name, name2);
    }

    #[test]
    fn remote_input_basics() {
        let input = RemoteInput::new(vec![1, 2, 3]);
        assert_eq!(input.data(), &[1, 2, 3]);
        assert_eq!(input.len(), 3);
        assert!(!input.is_empty());

        let empty = RemoteInput::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let owned = input.into_data();
        assert_eq!(owned, vec![1, 2, 3]);
    }

    #[test]
    fn remote_cap_defaults() {
        let cap = RemoteCap::new();
        assert_eq!(cap.default_lease(), Duration::from_secs(30));
        assert!(cap.remote_budget().is_none());
        assert_eq!(cap.local_node().as_str(), "local");
    }

    #[test]
    fn remote_cap_builder() {
        let cap = RemoteCap::new()
            .with_default_lease(Duration::from_mins(1))
            .with_remote_budget(Budget::INFINITE)
            .with_local_node(NodeId::new("origin-a"));
        assert_eq!(cap.default_lease(), Duration::from_mins(1));
        assert!(cap.remote_budget().is_some());
        assert_eq!(cap.local_node().as_str(), "origin-a");
    }

    #[derive(Debug, Default)]
    struct CaptureRuntime {
        sent: Mutex<Vec<(NodeId, MessageEnvelope<RemoteMessage>)>>,
    }

    impl RemoteRuntime for CaptureRuntime {
        fn send_message(
            &self,
            destination: &NodeId,
            envelope: MessageEnvelope<RemoteMessage>,
        ) -> Result<(), RemoteError> {
            self.sent.lock().push((destination.clone(), envelope));
            Ok(())
        }

        fn register_task(
            &self,
            _task_id: RemoteTaskId,
            _tx: oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
        ) {
            // Intentionally dropped in this capture runtime.
        }
    }

    #[derive(Debug, Default)]
    struct FailingSendRuntime {
        registered: Mutex<Vec<RemoteTaskId>>,
        unregistered: Mutex<Vec<RemoteTaskId>>,
    }

    impl RemoteRuntime for FailingSendRuntime {
        fn send_message(
            &self,
            _destination: &NodeId,
            _envelope: MessageEnvelope<RemoteMessage>,
        ) -> Result<(), RemoteError> {
            Err(RemoteError::TransportError("simulated send failure".into()))
        }

        fn register_task(
            &self,
            task_id: RemoteTaskId,
            _tx: oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
        ) {
            self.registered.lock().push(task_id);
        }

        fn unregister_task(&self, task_id: RemoteTaskId) {
            self.unregistered.lock().push(task_id);
        }
    }

    #[test]
    fn spawn_remote_uses_cap_local_node_for_origin() {
        let runtime = Arc::new(CaptureRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let _ = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let (destination, envelope) = {
            let sent = runtime.sent.lock();
            assert_eq!(sent.len(), 1);
            sent[0].clone()
        };
        assert_eq!(destination.as_str(), "worker-1");
        assert_eq!(envelope.sender.as_str(), "origin-a");
        match &envelope.payload {
            RemoteMessage::SpawnRequest(req) => {
                assert_eq!(req.origin_node.as_str(), "origin-a");
            }
            other => unreachable!("expected SpawnRequest, got {other:?}"),
        }
    }

    #[test]
    fn spawn_remote_send_failure_unregisters_pending_task() {
        let runtime = Arc::new(FailingSendRuntime::default());
        let cap = RemoteCap::new().with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let err = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect_err("spawn_remote should fail when send_message fails");
        match err {
            RemoteError::TransportError(msg) => {
                assert!(msg.contains("simulated send failure"));
            }
            other => unreachable!("expected TransportError, got {other:?}"),
        }

        let registered = runtime.registered.lock().clone();
        let unregistered = runtime.unregistered.lock().clone();

        assert_eq!(registered.len(), 1);
        assert_eq!(unregistered, registered);
    }

    #[test]
    fn remote_task_id_uniqueness() {
        let id1 = RemoteTaskId::next();
        let id2 = RemoteTaskId::next();
        assert_ne!(id1, id2);
        assert!(id2.raw() > id1.raw());
    }

    #[test]
    fn remote_task_state_display() {
        assert_eq!(format!("{}", RemoteTaskState::Pending), "Pending");
        assert_eq!(format!("{}", RemoteTaskState::Running), "Running");
        assert_eq!(format!("{}", RemoteTaskState::Completed), "Completed");
        assert_eq!(format!("{}", RemoteTaskState::LeaseExpired), "LeaseExpired");
    }

    #[test]
    fn remote_error_display() {
        let err = RemoteError::NoCapability;
        assert_eq!(format!("{err}"), "remote capability not available");

        let err = RemoteError::NodeUnreachable("worker-9".into());
        assert!(format!("{err}").contains("worker-9"));

        let err = RemoteError::UnknownComputation("bad_fn".into());
        assert!(format!("{err}").contains("bad_fn"));
    }

    #[test]
    fn spawn_remote_without_cap_fails() {
        let cx: Cx = Cx::for_testing();
        assert!(!cx.has_remote());

        let result = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode"),
            RemoteInput::empty(),
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), RemoteError::NoCapability);
    }

    #[test]
    fn spawn_remote_with_cap_succeeds() {
        let cx: Cx = Cx::for_testing_with_remote(RemoteCap::new());
        assert!(cx.has_remote());

        let result = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![42]),
        );
        assert!(result.is_ok());

        let handle = result.unwrap();
        assert_eq!(handle.node().as_str(), "worker-1");
        assert_eq!(handle.computation().as_str(), "encode_block");
        assert_eq!(*handle.state(), RemoteTaskState::Pending);
        assert_eq!(handle.lease(), Duration::from_secs(30));
        assert!(handle.local_task_id().is_none());
    }

    #[test]
    fn remote_handle_debug() {
        let cx: Cx = Cx::for_testing_with_remote(RemoteCap::new());
        let handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("compute"),
            RemoteInput::empty(),
        )
        .unwrap();

        let debug = format!("{handle:?}");
        assert!(debug.contains("RemoteHandle"));
        assert!(debug.contains("n1"));
        assert!(debug.contains("compute"));
    }

    #[test]
    fn remote_handle_not_finished_initially() {
        let cx: Cx = Cx::for_testing_with_remote(RemoteCap::new());
        let handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("add"),
            RemoteInput::empty(),
        )
        .unwrap();

        // Phase 0: sender is dropped immediately, so channel closure is terminal.
        assert!(handle.is_finished());
    }

    #[test]
    fn remote_handle_try_join_pending() {
        let cx: Cx = Cx::for_testing_with_remote(RemoteCap::new());
        let mut handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("work"),
            RemoteInput::empty(),
        )
        .unwrap();

        // Phase 0: sender is dropped, so try_join returns Cancelled.
        // In Phase 1+, the transport holds the sender and try_join returns None.
        let result = handle.try_join();
        // Either None (transport holds sender) or Cancelled (Phase 0 sender dropped)
        assert!(result.is_ok() || matches!(result, Err(RemoteError::Cancelled(_))));
    }

    #[test]
    fn remote_handle_join_updates_terminal_state() {
        let cx: Cx = Cx::for_testing_with_remote(RemoteCap::new());
        let mut handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("join-state"),
            RemoteInput::empty(),
        )
        .expect("spawn");

        let result = futures_lite::future::block_on(handle.join(&cx));
        assert!(matches!(result, Err(RemoteError::Cancelled(_))));
        assert_eq!(*handle.state(), RemoteTaskState::Cancelled);
        assert!(handle.is_finished());
    }

    #[test]
    fn remote_handle_try_join_updates_terminal_state() {
        let cx: Cx = Cx::for_testing_with_remote(RemoteCap::new());
        let mut handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("try-join-state"),
            RemoteInput::empty(),
        )
        .expect("spawn");

        let result = handle.try_join();
        assert!(matches!(result, Err(RemoteError::Cancelled(_))));
        assert_eq!(*handle.state(), RemoteTaskState::Cancelled);
    }

    #[test]
    fn remote_handle_try_join_maps_cancelled_outcome_state() {
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = oneshot::channel::<Result<RemoteOutcome, RemoteError>>();
        tx.send(
            &cx,
            Ok(RemoteOutcome::Cancelled(CancelReason::user(
                "cancelled remotely",
            ))),
        )
        .expect("send outcome");

        let mut handle = RemoteHandle {
            remote_task_id: RemoteTaskId::next(),
            local_task_id: None,
            node: NodeId::new("n1"),
            computation: ComputationName::new("compute"),
            owner_region: cx.region_id(),
            receiver: rx,
            lease: Duration::from_secs(30),
            state: RemoteTaskState::Pending,
        };

        let result = handle.try_join().expect("result").expect("outcome");
        assert!(matches!(result, RemoteOutcome::Cancelled(_)));
        assert_eq!(*handle.state(), RemoteTaskState::Cancelled);
    }

    #[test]
    fn remote_handle_abort_no_panic() {
        let cx: Cx = Cx::for_testing_with_remote(RemoteCap::new());
        let handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("long_task"),
            RemoteInput::empty(),
        )
        .unwrap();

        // Phase 0: abort is a no-op, just verify it doesn't panic.
        handle.abort();
    }

    #[test]
    fn remote_cap_custom_lease_propagates() {
        let cap = RemoteCap::new().with_default_lease(Duration::from_mins(2));
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("slow"),
            RemoteInput::empty(),
        )
        .unwrap();

        assert_eq!(handle.lease(), Duration::from_mins(2));
    }

    // -----------------------------------------------------------------------
    // Protocol tests (tmh.1.2)
    // -----------------------------------------------------------------------

    #[test]
    fn idempotency_key_generate() {
        let cx: Cx = Cx::for_testing();
        let k1 = IdempotencyKey::generate(&cx);
        let k2 = IdempotencyKey::generate(&cx);
        // Keys should be unique (with overwhelming probability)
        assert_ne!(k1, k2);
        assert_ne!(k1.raw(), 0);
    }

    #[test]
    fn idempotency_key_from_raw() {
        let key = IdempotencyKey::from_raw(0xDEAD_BEEF);
        assert_eq!(key.raw(), 0xDEAD_BEEF);
        let display = format!("{key}");
        assert!(display.starts_with("IK-"));
        assert!(display.contains("deadbeef"));
    }

    #[test]
    fn spawn_request_construction() {
        let cx: Cx = Cx::for_testing();
        let req = SpawnRequest {
            remote_task_id: RemoteTaskId::next(),
            computation: ComputationName::new("encode_block"),
            input: RemoteInput::new(vec![1, 2, 3]),
            lease: Duration::from_mins(1),
            idempotency_key: IdempotencyKey::generate(&cx),
            budget: None,
            origin_node: NodeId::new("origin-1"),
            origin_region: cx.region_id(),
            origin_task: cx.task_id(),
        };

        assert_eq!(req.computation.as_str(), "encode_block");
        assert_eq!(req.input.len(), 3);
        assert_eq!(req.lease, Duration::from_mins(1));
        assert_eq!(req.origin_node.as_str(), "origin-1");
    }

    #[test]
    fn spawn_ack_accepted() {
        let ack = SpawnAck {
            remote_task_id: RemoteTaskId::next(),
            status: SpawnAckStatus::Accepted,
            assigned_node: NodeId::new("worker-3"),
        };
        assert_eq!(ack.status, SpawnAckStatus::Accepted);
        assert_eq!(ack.assigned_node.as_str(), "worker-3");
    }

    #[test]
    fn spawn_ack_rejected() {
        let ack = SpawnAck {
            remote_task_id: RemoteTaskId::next(),
            status: SpawnAckStatus::Rejected(SpawnRejectReason::CapacityExceeded),
            assigned_node: NodeId::new("worker-1"),
        };
        assert_eq!(
            ack.status,
            SpawnAckStatus::Rejected(SpawnRejectReason::CapacityExceeded)
        );
    }

    #[test]
    fn spawn_reject_reason_display() {
        assert_eq!(
            format!("{}", SpawnRejectReason::UnknownComputation),
            "unknown computation"
        );
        assert_eq!(
            format!("{}", SpawnRejectReason::CapacityExceeded),
            "capacity exceeded"
        );
        assert_eq!(
            format!("{}", SpawnRejectReason::NodeShuttingDown),
            "node shutting down"
        );
        assert!(
            format!("{}", SpawnRejectReason::InvalidInput("bad data".into())).contains("bad data")
        );
        assert_eq!(
            format!("{}", SpawnRejectReason::IdempotencyConflict),
            "idempotency conflict"
        );
    }

    #[test]
    fn cancel_request_construction() {
        let req = CancelRequest {
            remote_task_id: RemoteTaskId::next(),
            reason: CancelReason::user("user abort"),
            origin_node: NodeId::new("origin-1"),
        };
        assert_eq!(req.origin_node.as_str(), "origin-1");
    }

    #[test]
    fn result_delivery_success() {
        let delivery = ResultDelivery {
            remote_task_id: RemoteTaskId::next(),
            outcome: RemoteOutcome::Success(vec![42]),
            execution_time: Duration::from_millis(150),
        };
        assert!(delivery.outcome.is_success());
        assert_eq!(delivery.outcome.severity(), crate::types::Severity::Ok);
        assert_eq!(delivery.execution_time, Duration::from_millis(150));
    }

    #[test]
    fn result_delivery_failure() {
        let delivery = ResultDelivery {
            remote_task_id: RemoteTaskId::next(),
            outcome: RemoteOutcome::Failed("out of memory".into()),
            execution_time: Duration::from_secs(5),
        };
        assert!(!delivery.outcome.is_success());
        assert_eq!(delivery.outcome.severity(), crate::types::Severity::Err);
    }

    #[test]
    fn remote_outcome_display() {
        assert_eq!(format!("{}", RemoteOutcome::Success(vec![])), "Success");
        assert!(format!("{}", RemoteOutcome::Failed("oops".into())).contains("oops"));
        assert!(
            format!("{}", RemoteOutcome::Cancelled(CancelReason::user("done")))
                .contains("Cancelled")
        );
        assert!(format!("{}", RemoteOutcome::Panicked("boom".into())).contains("boom"));
    }

    #[test]
    fn lease_renewal_construction() {
        let renewal = LeaseRenewal {
            remote_task_id: RemoteTaskId::next(),
            new_lease: Duration::from_secs(30),
            current_state: RemoteTaskState::Running,
            node: NodeId::new("worker-1"),
        };
        assert_eq!(renewal.new_lease, Duration::from_secs(30));
        assert_eq!(renewal.current_state, RemoteTaskState::Running);
    }

    #[test]
    fn remote_message_task_id_dispatch() {
        let rtid = RemoteTaskId::next();
        let cx: Cx = Cx::for_testing();

        let spawn_msg = RemoteMessage::SpawnRequest(SpawnRequest {
            remote_task_id: rtid,
            computation: ComputationName::new("test"),
            input: RemoteInput::empty(),
            lease: Duration::from_secs(30),
            idempotency_key: IdempotencyKey::generate(&cx),
            budget: None,
            origin_node: NodeId::new("n1"),
            origin_region: cx.region_id(),
            origin_task: cx.task_id(),
        });
        assert_eq!(spawn_msg.remote_task_id(), rtid);

        let ack_msg = RemoteMessage::SpawnAck(SpawnAck {
            remote_task_id: rtid,
            status: SpawnAckStatus::Accepted,
            assigned_node: NodeId::new("n2"),
        });
        assert_eq!(ack_msg.remote_task_id(), rtid);

        let cancel_msg = RemoteMessage::CancelRequest(CancelRequest {
            remote_task_id: rtid,
            reason: CancelReason::user("test"),
            origin_node: NodeId::new("n1"),
        });
        assert_eq!(cancel_msg.remote_task_id(), rtid);

        let result_msg = RemoteMessage::ResultDelivery(ResultDelivery {
            remote_task_id: rtid,
            outcome: RemoteOutcome::Success(vec![]),
            execution_time: Duration::ZERO,
        });
        assert_eq!(result_msg.remote_task_id(), rtid);

        let renewal_msg = RemoteMessage::LeaseRenewal(LeaseRenewal {
            remote_task_id: rtid,
            new_lease: Duration::from_secs(30),
            current_state: RemoteTaskState::Running,
            node: NodeId::new("n2"),
        });
        assert_eq!(renewal_msg.remote_task_id(), rtid);
    }

    fn test_spawn_request(cx: &Cx, remote_task_id: RemoteTaskId) -> SpawnRequest {
        SpawnRequest {
            remote_task_id,
            computation: ComputationName::new("compute"),
            input: RemoteInput::empty(),
            lease: Duration::from_secs(30),
            idempotency_key: IdempotencyKey::generate(cx),
            budget: None,
            origin_node: NodeId::new("origin-1"),
            origin_region: cx.region_id(),
            origin_task: cx.task_id(),
        }
    }

    fn test_ack_accepted(remote_task_id: RemoteTaskId) -> SpawnAck {
        SpawnAck {
            remote_task_id,
            status: SpawnAckStatus::Accepted,
            assigned_node: NodeId::new("worker-1"),
        }
    }

    fn test_ack_rejected(remote_task_id: RemoteTaskId) -> SpawnAck {
        SpawnAck {
            remote_task_id,
            status: SpawnAckStatus::Rejected(SpawnRejectReason::CapacityExceeded),
            assigned_node: NodeId::new("worker-1"),
        }
    }

    fn test_cancel(remote_task_id: RemoteTaskId) -> CancelRequest {
        CancelRequest {
            remote_task_id,
            reason: CancelReason::user("cancel"),
            origin_node: NodeId::new("origin-1"),
        }
    }

    fn test_result(remote_task_id: RemoteTaskId, outcome: RemoteOutcome) -> ResultDelivery {
        ResultDelivery {
            remote_task_id,
            outcome,
            execution_time: Duration::ZERO,
        }
    }

    fn test_renewal(remote_task_id: RemoteTaskId) -> LeaseRenewal {
        LeaseRenewal {
            remote_task_id,
            new_lease: Duration::from_secs(10),
            current_state: RemoteTaskState::Running,
            node: NodeId::new("worker-1"),
        }
    }

    #[test]
    fn origin_session_cancel_flow() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let origin = OriginSession::<OriginInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let origin = origin.send_spawn(&req).unwrap();
        let ack = test_ack_accepted(rtid);
        let outcome = origin.recv_spawn_ack(&ack).unwrap();
        assert!(matches!(outcome, OriginAckOutcome::Accepted(_)));
        let origin = match outcome {
            OriginAckOutcome::Accepted(session) => session,
            OriginAckOutcome::Rejected(_) => return,
        };
        let origin = origin.recv_lease_renewal(&test_renewal(rtid)).unwrap();
        let origin = origin.send_cancel(&test_cancel(rtid)).unwrap();
        let result = test_result(
            rtid,
            RemoteOutcome::Cancelled(CancelReason::user("cancelled")),
        );
        let origin = origin.recv_result(&result).unwrap();
        assert_eq!(origin.remote_task_id(), rtid);
    }

    #[test]
    fn origin_session_reject_flow() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let origin = OriginSession::<OriginInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let origin = origin.send_spawn(&req).unwrap();
        let ack = test_ack_rejected(rtid);
        let outcome = origin.recv_spawn_ack(&ack).unwrap();
        assert!(matches!(outcome, OriginAckOutcome::Rejected(_)));
        if let OriginAckOutcome::Rejected(session) = outcome {
            assert_eq!(session.remote_task_id(), rtid);
        }
    }

    #[test]
    fn remote_session_cancel_before_ack_flow() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let remote = RemoteSession::<RemoteInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let remote = remote.recv_spawn(&req).unwrap();
        let remote = remote.recv_cancel(&test_cancel(rtid)).unwrap();
        let remote = remote.send_ack_accepted(&test_ack_accepted(rtid)).unwrap();
        let result = test_result(rtid, RemoteOutcome::Cancelled(CancelReason::user("done")));
        let remote = remote.send_result(&result).unwrap();
        assert_eq!(remote.remote_task_id(), rtid);
    }

    #[test]
    fn protocol_id_mismatch_is_error() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let origin = OriginSession::<OriginInit>::new(rtid);
        let req = test_spawn_request(&cx, RemoteTaskId::next());
        let err = origin.send_spawn(&req).unwrap_err();
        assert!(matches!(
            err,
            RemoteProtocolError::RemoteTaskIdMismatch { .. }
        ));
    }

    #[test]
    fn protocol_ack_status_mismatch_is_error() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let remote = RemoteSession::<RemoteInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let remote = remote.recv_spawn(&req).unwrap();
        let ack = test_ack_rejected(rtid);
        let err = remote.send_ack_accepted(&ack).unwrap_err();
        assert!(matches!(
            err,
            RemoteProtocolError::UnexpectedAckStatus { .. }
        ));
    }

    #[test]
    fn trace_event_names_are_namespaced() {
        // Verify all trace events follow the "remote::" namespace convention.
        assert!(trace_events::SPAWN_REQUEST_CREATED.starts_with("remote::"));
        assert!(trace_events::SPAWN_REQUEST_SENT.starts_with("remote::"));
        assert!(trace_events::SPAWN_ACK_RECEIVED.starts_with("remote::"));
        assert!(trace_events::SPAWN_REJECTED.starts_with("remote::"));
        assert!(trace_events::CANCEL_SENT.starts_with("remote::"));
        assert!(trace_events::CANCEL_RECEIVED.starts_with("remote::"));
        assert!(trace_events::RESULT_DELIVERED.starts_with("remote::"));
        assert!(trace_events::LEASE_RENEWAL_SENT.starts_with("remote::"));
        assert!(trace_events::LEASE_RENEWAL_RECEIVED.starts_with("remote::"));
        assert!(trace_events::LEASE_EXPIRED.starts_with("remote::"));
    }

    // -----------------------------------------------------------------------
    // Lease tests (tmh.2.1)
    // -----------------------------------------------------------------------

    fn test_obligation_id() -> ObligationId {
        ObligationId::new_for_test(0, 0)
    }

    fn test_region_id() -> RegionId {
        RegionId::new_for_test(0, 0)
    }

    fn test_task_id() -> TaskId {
        TaskId::new_for_test(0, 0)
    }

    #[test]
    fn lease_creation() {
        let now = Time::from_secs(10);
        let lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );
        assert!(lease.is_active(now));
        assert!(!lease.is_expired(now));
        assert!(!lease.is_released());
        assert_eq!(lease.renewal_count(), 0);
        assert_eq!(lease.initial_duration(), Duration::from_secs(30));
        assert_eq!(lease.expires_at(), Time::from_secs(40));
    }

    #[test]
    fn lease_remaining_time() {
        let now = Time::from_secs(10);
        let lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );
        let remaining = lease.remaining(Time::from_secs(20));
        assert_eq!(remaining, Duration::from_secs(20));

        // At expiry: zero remaining
        let remaining = lease.remaining(Time::from_secs(40));
        assert_eq!(remaining, Duration::ZERO);

        // Past expiry: zero remaining
        let remaining = lease.remaining(Time::from_secs(50));
        assert_eq!(remaining, Duration::ZERO);
    }

    #[test]
    fn lease_expiry_detection() {
        let now = Time::from_secs(10);
        let lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        // Before expiry
        assert!(!lease.is_expired(Time::from_secs(39)));
        assert!(lease.is_active(Time::from_secs(39)));

        // At expiry boundary
        assert!(lease.is_expired(Time::from_secs(40)));
        assert!(!lease.is_active(Time::from_secs(40)));

        // After expiry
        assert!(lease.is_expired(Time::from_secs(50)));
    }

    #[test]
    fn lease_renew_extends_expiry() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        // Renew at t=25 for another 30s
        let result = lease.renew(Duration::from_secs(30), Time::from_secs(25));
        assert!(result.is_ok());
        assert_eq!(lease.expires_at(), Time::from_secs(55));
        assert_eq!(lease.renewal_count(), 1);

        // Renew again at t=50
        let result = lease.renew(Duration::from_secs(30), Time::from_secs(50));
        assert!(result.is_ok());
        assert_eq!(lease.expires_at(), Time::from_secs(80));
        assert_eq!(lease.renewal_count(), 2);
    }

    #[test]
    fn lease_renew_after_expiry_fails() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        // Try to renew after expiry
        let result = lease.renew(Duration::from_secs(30), Time::from_secs(50));
        assert_eq!(result, Err(LeaseError::Expired));
        assert_eq!(lease.state(), LeaseState::Expired);
    }

    #[test]
    fn lease_release() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        let result = lease.release(Time::from_secs(20));
        assert!(result.is_ok());
        assert!(lease.is_released());
        assert_eq!(lease.state(), LeaseState::Released);
    }

    #[test]
    fn lease_double_release_fails() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        lease.release(Time::from_secs(20)).unwrap();
        let result = lease.release(Time::from_secs(25));
        assert_eq!(result, Err(LeaseError::Released));
    }

    #[test]
    fn lease_renew_after_release_fails() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        lease.release(Time::from_secs(20)).unwrap();
        let result = lease.renew(Duration::from_secs(30), Time::from_secs(25));
        assert_eq!(result, Err(LeaseError::Released));
    }

    #[test]
    fn lease_mark_expired() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        let result = lease.mark_expired();
        assert!(result.is_ok());
        assert_eq!(lease.state(), LeaseState::Expired);

        // Idempotent
        let result = lease.mark_expired();
        assert!(result.is_ok());
    }

    #[test]
    fn lease_mark_expired_after_release_fails() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        lease.release(Time::from_secs(20)).unwrap();
        let result = lease.mark_expired();
        assert_eq!(result, Err(LeaseError::Released));
    }

    #[test]
    fn lease_state_display() {
        assert_eq!(format!("{}", LeaseState::Active), "Active");
        assert_eq!(format!("{}", LeaseState::Released), "Released");
        assert_eq!(format!("{}", LeaseState::Expired), "Expired");
    }

    #[test]
    fn lease_error_display() {
        assert_eq!(format!("{}", LeaseError::Expired), "lease expired");
        assert_eq!(
            format!("{}", LeaseError::Released),
            "lease already released"
        );
        assert!(format!("{}", LeaseError::CreationFailed("full".into())).contains("full"));
    }

    // -----------------------------------------------------------------------
    // Idempotency store tests (tmh.2.2)
    // -----------------------------------------------------------------------

    #[test]
    fn idempotency_store_new_request() {
        let mut store = IdempotencyStore::new(Duration::from_mins(5));
        assert!(store.is_empty());

        let key = IdempotencyKey::from_raw(1);
        let decision = store.check(&key, &ComputationName::new("encode"));
        assert!(matches!(decision, DedupDecision::New));

        let inserted = store.record(
            key,
            RemoteTaskId::next(),
            ComputationName::new("encode"),
            Time::from_secs(10),
        );
        assert!(inserted);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn idempotency_store_duplicate_detection() {
        let mut store = IdempotencyStore::new(Duration::from_mins(5));
        let key = IdempotencyKey::from_raw(42);
        let comp = ComputationName::new("encode");

        store.record(key, RemoteTaskId::next(), comp.clone(), Time::from_secs(10));

        // Same key, same computation → Duplicate
        let decision = store.check(&key, &comp);
        assert!(matches!(decision, DedupDecision::Duplicate(_)));

        // Trying to record again returns false
        let inserted = store.record(key, RemoteTaskId::next(), comp, Time::from_secs(20));
        assert!(!inserted);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn idempotency_store_conflict_detection() {
        let mut store = IdempotencyStore::new(Duration::from_mins(5));
        let key = IdempotencyKey::from_raw(42);

        store.record(
            key,
            RemoteTaskId::next(),
            ComputationName::new("encode"),
            Time::from_secs(10),
        );

        // Same key, DIFFERENT computation → Conflict
        let decision = store.check(&key, &ComputationName::new("decode"));
        assert!(matches!(decision, DedupDecision::Conflict));
    }

    #[test]
    fn idempotency_store_complete_outcome() {
        let mut store = IdempotencyStore::new(Duration::from_mins(5));
        let key = IdempotencyKey::from_raw(99);

        store.record(
            key,
            RemoteTaskId::next(),
            ComputationName::new("work"),
            Time::from_secs(10),
        );

        // Complete with success
        let updated = store.complete(&key, RemoteOutcome::Success(vec![1, 2, 3]));
        assert!(updated);

        // Check returns duplicate with outcome
        let decision = store.check(&key, &ComputationName::new("work"));
        assert!(matches!(decision, DedupDecision::Duplicate(_)));
        if let DedupDecision::Duplicate(record) = decision {
            assert!(record.outcome.is_some());
            assert!(record.outcome.unwrap().is_success());
        }
    }

    #[test]
    fn idempotency_store_complete_unknown_key() {
        let mut store = IdempotencyStore::new(Duration::from_mins(5));
        let key = IdempotencyKey::from_raw(999);

        // Complete on unknown key returns false
        let updated = store.complete(&key, RemoteOutcome::Failed("oops".into()));
        assert!(!updated);
    }

    #[test]
    fn idempotency_store_eviction() {
        let mut store = IdempotencyStore::new(Duration::from_mins(1));

        // Insert at t=10 (expires at t=70)
        store.record(
            IdempotencyKey::from_raw(1),
            RemoteTaskId::next(),
            ComputationName::new("a"),
            Time::from_secs(10),
        );

        // Insert at t=50 (expires at t=110)
        store.record(
            IdempotencyKey::from_raw(2),
            RemoteTaskId::next(),
            ComputationName::new("b"),
            Time::from_secs(50),
        );
        assert_eq!(store.len(), 2);

        // Evict at t=80: key 1 expired (70), key 2 still live (110)
        let evicted = store.evict_expired(Time::from_secs(80));
        assert_eq!(evicted, 1);
        assert_eq!(store.len(), 1);

        // Key 2 is still there
        let decision = store.check(&IdempotencyKey::from_raw(2), &ComputationName::new("b"));
        assert!(matches!(decision, DedupDecision::Duplicate(_)));

        // Key 1 is gone
        let decision = store.check(&IdempotencyKey::from_raw(1), &ComputationName::new("a"));
        assert!(matches!(decision, DedupDecision::New));
    }

    #[test]
    fn idempotency_store_debug() {
        let store = IdempotencyStore::new(Duration::from_mins(1));
        let debug = format!("{store:?}");
        assert!(debug.contains("IdempotencyStore"));
        assert!(debug.contains("entries"));
    }

    // -----------------------------------------------------------------------
    // Saga tests (tmh.2.3)
    // -----------------------------------------------------------------------

    #[test]
    fn saga_successful_completion() {
        let mut saga = Saga::new();
        assert_eq!(saga.state(), SagaState::Running);
        assert_eq!(saga.completed_steps(), 0);

        let r1: Result<String, _> = saga.step(
            "create resource",
            || Ok("resource-1".to_string()),
            || "deleted resource-1".to_string(),
        );
        assert!(r1.is_ok());
        assert_eq!(r1.unwrap(), "resource-1");
        assert_eq!(saga.completed_steps(), 1);

        let r2: Result<(), _> = saga.step("configure", || Ok(()), || "reset config".to_string());
        assert!(r2.is_ok());
        assert_eq!(saga.completed_steps(), 2);

        saga.complete();
        assert_eq!(saga.state(), SagaState::Completed);
        assert!(saga.compensation_results().is_empty());
    }

    #[test]
    fn saga_step_failure_runs_compensations_reverse() {
        use std::sync::Arc;

        let order = Arc::new(Mutex::new(Vec::new()));

        let o1 = Arc::clone(&order);
        let mut saga = Saga::new();

        saga.step(
            "step-0",
            || Ok(()),
            move || {
                o1.lock().push(0);
                "comp-0".to_string()
            },
        )
        .unwrap();

        let o2 = Arc::clone(&order);
        saga.step(
            "step-1",
            || Ok(()),
            move || {
                o2.lock().push(1);
                "comp-1".to_string()
            },
        )
        .unwrap();

        let o3 = Arc::clone(&order);
        // Step 2 fails
        let result: Result<(), SagaStepError> = saga.step(
            "step-2",
            || Err("boom".to_string()),
            move || {
                o3.lock().push(2);
                "comp-2".to_string()
            },
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.step, 2);
        assert!(err.message.contains("boom"));

        // Saga should be aborted
        assert_eq!(saga.state(), SagaState::Aborted);

        // Compensations should have run in reverse: step-1, step-0
        // (step-2 never succeeded, so no compensation for it)
        let comps = saga.compensation_results();
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[0].step, 1); // step-1 first (reverse order)
        assert_eq!(comps[1].step, 0); // step-0 second

        // Verify execution order: 1 then 0 (reverse)
        let executed = order.lock().clone();
        assert_eq!(executed, vec![1, 0]);
    }

    #[test]
    fn saga_explicit_abort() {
        use std::sync::Arc;

        let compensated = Arc::new(Mutex::new(Vec::new()));
        let mut saga = Saga::new();

        let c1 = Arc::clone(&compensated);
        saga.step(
            "step-0",
            || Ok(()),
            move || {
                c1.lock().push("step-0");
                "undid step-0".to_string()
            },
        )
        .unwrap();

        let c2 = Arc::clone(&compensated);
        saga.step(
            "step-1",
            || Ok(()),
            move || {
                c2.lock().push("step-1");
                "undid step-1".to_string()
            },
        )
        .unwrap();

        // Explicitly abort (e.g., due to cancellation)
        saga.abort();
        assert_eq!(saga.state(), SagaState::Aborted);

        let comps = saga.compensation_results();
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[0].description, "step-1"); // reverse order
        assert_eq!(comps[1].description, "step-0");

        let executed = compensated.lock().clone();
        assert_eq!(executed, vec!["step-1", "step-0"]);
    }

    #[test]
    fn saga_first_step_failure_no_compensations() {
        let mut saga = Saga::new();

        // First step fails — nothing to compensate
        let result: Result<(), _> = saga.step("fail-step", || Err("bad".to_string()), String::new);
        assert!(result.is_err());
        assert_eq!(saga.state(), SagaState::Aborted);
        assert!(saga.compensation_results().is_empty());
    }

    #[test]
    fn saga_state_display() {
        assert_eq!(format!("{}", SagaState::Running), "Running");
        assert_eq!(format!("{}", SagaState::Completed), "Completed");
        assert_eq!(format!("{}", SagaState::Compensating), "Compensating");
        assert_eq!(format!("{}", SagaState::Aborted), "Aborted");
    }

    #[test]
    fn saga_step_error_display() {
        let err = SagaStepError {
            step: 3,
            description: "deploy".to_string(),
            message: "timeout".to_string(),
        };
        let text = format!("{err}");
        assert!(text.contains('3'));
        assert!(text.contains("deploy"));
        assert!(text.contains("timeout"));
    }

    #[test]
    fn saga_debug() {
        let saga = Saga::new();
        let debug = format!("{saga:?}");
        assert!(debug.contains("Saga"));
        assert!(debug.contains("Running"));
    }

    #[test]
    fn saga_default_trait() {
        let saga = Saga::default();
        assert_eq!(saga.state(), SagaState::Running);
    }

    // -----------------------------------------------------------------------
    // Invariant tests — lease boundary conditions (B6: asupersync-3narc.2.6)
    // -----------------------------------------------------------------------

    /// Invariant: renewing a lease at exactly `now == expires_at` must fail
    /// with `LeaseError::Expired`, because `is_expired` uses `>=`.
    #[test]
    fn lease_renew_at_exact_expiry_boundary_fails() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );
        // expires_at == 40; renew at exactly 40
        let result = lease.renew(Duration::from_secs(30), Time::from_secs(40));
        assert_eq!(result, Err(LeaseError::Expired));
        assert_eq!(lease.state(), LeaseState::Expired);
        // Once expired by renew, subsequent renew must also fail
        let result2 = lease.renew(Duration::from_secs(30), Time::from_secs(35));
        assert_eq!(result2, Err(LeaseError::Expired));
    }

    /// Invariant: a zero-duration lease is immediately expired at its creation time,
    /// since `expires_at = now + Duration::ZERO = now` and `is_expired` uses `>=`.
    #[test]
    fn lease_zero_duration_immediately_expired() {
        let now = Time::from_secs(100);
        let lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::ZERO,
            now,
        );
        assert!(
            lease.is_expired(now),
            "zero-duration lease must be expired at creation time"
        );
        assert!(
            !lease.is_active(now),
            "zero-duration lease must not be active at creation time"
        );
        assert_eq!(lease.remaining(now), Duration::ZERO);
    }

    /// Invariant: `is_active` and `is_expired` are complementary for Active-state leases.
    /// For any time `t`, exactly one of `is_active(t)` or `is_expired(t)` is true
    /// when the lease state is Active.
    #[test]
    fn lease_active_and_expired_are_complementary() {
        let now = Time::from_secs(10);
        let lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );
        // Test several time points: before, at, and after expiry
        for t in [0, 5, 10, 20, 39, 40, 41, 100] {
            let time = Time::from_secs(t);
            let active = lease.is_active(time);
            let expired = lease.is_expired(time);
            assert!(
                active != expired,
                "at t={t}: is_active={active}, is_expired={expired} — must be complementary"
            );
        }
    }

    /// Invariant: releasing then trying to renew gives Released, not Expired.
    /// The state transition Release takes precedence in error reporting.
    #[test]
    fn lease_release_then_renew_gives_released_error() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );
        lease.release(Time::from_secs(15)).unwrap();
        let result = lease.renew(Duration::from_secs(30), Time::from_secs(15));
        assert_eq!(result, Err(LeaseError::Released));
    }

    // -----------------------------------------------------------------------
    // Invariant tests — idempotency store (B6: asupersync-3narc.2.6)
    // -----------------------------------------------------------------------

    /// Invariant: eviction removes completed entries too, not just pending ones.
    /// Completion status does not exempt an entry from TTL-based eviction.
    #[test]
    fn idempotency_store_evicts_completed_entries_on_ttl() {
        let mut store = IdempotencyStore::new(Duration::from_mins(1));
        let key = IdempotencyKey::from_raw(1);
        let comp = ComputationName::new("work");

        // Record at t=10 (expires at t=70)
        store.record(key, RemoteTaskId::next(), comp.clone(), Time::from_secs(10));
        // Complete with success
        store.complete(&key, RemoteOutcome::Success(vec![42]));
        assert_eq!(store.len(), 1);

        // Evict at t=80 — should remove the completed entry
        let evicted = store.evict_expired(Time::from_secs(80));
        assert_eq!(evicted, 1);
        assert!(store.is_empty());

        // Re-check: the key should be New again
        let decision = store.check(&key, &comp);
        assert!(matches!(decision, DedupDecision::New));
    }

    /// Invariant: checking a completed entry with a Failed outcome still returns
    /// Duplicate (not New), and the cached outcome is available.
    #[test]
    fn idempotency_store_check_after_failed_returns_duplicate_with_outcome() {
        let mut store = IdempotencyStore::new(Duration::from_mins(5));
        let key = IdempotencyKey::from_raw(77);
        let comp = ComputationName::new("fragile_op");

        store.record(key, RemoteTaskId::next(), comp.clone(), Time::from_secs(10));
        store.complete(&key, RemoteOutcome::Failed("disk full".into()));

        let decision = store.check(&key, &comp);
        match decision {
            DedupDecision::Duplicate(record) => {
                assert!(record.outcome.is_some());
                let outcome = record.outcome.unwrap();
                assert!(!outcome.is_success());
                assert!(matches!(outcome, RemoteOutcome::Failed(msg) if msg.contains("disk full")));
            }
            other => panic!("expected Duplicate, got {other:?}"),
        }
    }

    /// Invariant: completing the same key twice overwrites the outcome.
    /// The last `complete()` call wins.
    #[test]
    fn idempotency_store_complete_overwrites_outcome() {
        let mut store = IdempotencyStore::new(Duration::from_mins(5));
        let key = IdempotencyKey::from_raw(88);
        let comp = ComputationName::new("retry_op");

        store.record(key, RemoteTaskId::next(), comp.clone(), Time::from_secs(10));

        // First complete: Failed
        store.complete(&key, RemoteOutcome::Failed("transient".into()));
        // Second complete: Success (overwrites)
        store.complete(&key, RemoteOutcome::Success(vec![1, 2, 3]));

        let decision = store.check(&key, &comp);
        match decision {
            DedupDecision::Duplicate(record) => {
                let outcome = record.outcome.expect("outcome should be set");
                assert!(outcome.is_success(), "latest complete should win");
            }
            other => panic!("expected Duplicate, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Invariant tests — saga (B6: asupersync-3narc.2.6)
    // -----------------------------------------------------------------------

    /// Invariant: calling `step()` after `complete()` must panic.
    /// A completed saga must not accept new steps.
    #[test]
    #[should_panic(expected = "not Running")]
    fn saga_step_after_complete_panics() {
        let mut saga = Saga::new();
        saga.step("step-0", || Ok(()), || "comp-0".to_string())
            .unwrap();
        saga.complete();
        assert_eq!(saga.state(), SagaState::Completed);

        // This must panic
        let _: Result<(), _> = saga.step("step-1", || Ok(()), || "comp-1".to_string());
    }

    /// Invariant: calling `step()` after `abort()` must panic.
    /// An aborted saga must not accept new steps.
    #[test]
    #[should_panic(expected = "not Running")]
    fn saga_step_after_abort_panics() {
        let mut saga = Saga::new();
        saga.step("step-0", || Ok(()), || "comp-0".to_string())
            .unwrap();
        saga.abort();
        assert_eq!(saga.state(), SagaState::Aborted);

        // This must panic
        let _: Result<(), _> = saga.step("step-1", || Ok(()), || "comp-1".to_string());
    }

    /// Invariant: calling `complete()` after `abort()` must panic.
    #[test]
    #[should_panic(expected = "Running")]
    fn saga_complete_after_abort_panics() {
        let mut saga = Saga::new();
        saga.step("step-0", || Ok(()), || "comp-0".to_string())
            .unwrap();
        saga.abort();
        saga.complete(); // must panic
    }

    /// Invariant: calling `abort()` after `complete()` must panic.
    #[test]
    #[should_panic(expected = "Running")]
    fn saga_abort_after_complete_panics() {
        let mut saga = Saga::new();
        saga.step("step-0", || Ok(()), || "comp-0".to_string())
            .unwrap();
        saga.complete();
        saga.abort(); // must panic
    }

    /// Invariant: an empty saga can be completed without any steps.
    #[test]
    fn saga_empty_complete_is_valid() {
        let mut saga = Saga::new();
        assert_eq!(saga.completed_steps(), 0);
        saga.complete();
        assert_eq!(saga.state(), SagaState::Completed);
        assert!(saga.compensation_results().is_empty());
    }

    /// Invariant: an empty saga can be aborted (no compensations to run).
    #[test]
    fn saga_empty_abort_is_valid() {
        let mut saga = Saga::new();
        saga.abort();
        assert_eq!(saga.state(), SagaState::Aborted);
        assert!(saga.compensation_results().is_empty());
    }

    // --- wave 75 trait coverage ---

    #[test]
    fn remote_task_id_debug_clone_copy_eq_ord_hash() {
        use std::collections::HashSet;
        let a = RemoteTaskId::from_raw(42);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, RemoteTaskId::from_raw(99));
        assert!(a < RemoteTaskId::from_raw(100));
        let dbg = format!("{a:?}");
        assert!(dbg.contains("42"));
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn idempotency_key_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let k = IdempotencyKey::from_raw(12345);
        let k2 = k; // Copy
        let k3 = k;
        assert_eq!(k, k2);
        assert_eq!(k, k3);
        assert_ne!(k, IdempotencyKey::from_raw(99999));
        let dbg = format!("{k:?}");
        assert!(dbg.contains("12345"));
        let mut set = HashSet::new();
        set.insert(k);
        assert!(set.contains(&k2));
    }

    #[test]
    fn lease_state_debug_clone_copy_eq() {
        let s = LeaseState::Active;
        let s2 = s; // Copy
        let s3 = s;
        assert_eq!(s, s2);
        assert_eq!(s, s3);
        assert_ne!(s, LeaseState::Released);
        assert_ne!(s, LeaseState::Expired);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Active"));
    }

    #[test]
    fn saga_state_debug_clone_copy_eq() {
        let s = SagaState::Running;
        let s2 = s; // Copy
        let s3 = s;
        assert_eq!(s, s2);
        assert_eq!(s, s3);
        assert_ne!(s, SagaState::Completed);
        assert_ne!(s, SagaState::Compensating);
        assert_ne!(s, SagaState::Aborted);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Running"));
    }

    #[test]
    fn remote_task_state_debug_clone_eq() {
        let s = RemoteTaskState::Pending;
        let s2 = s.clone();
        assert_eq!(s, s2);
        assert_ne!(s, RemoteTaskState::Running);
        assert_ne!(s, RemoteTaskState::Completed);
        assert_ne!(s, RemoteTaskState::Failed);
        assert_ne!(s, RemoteTaskState::Cancelled);
        assert_ne!(s, RemoteTaskState::LeaseExpired);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Pending"));
    }

    #[test]
    fn remote_error_debug_clone_eq() {
        let e = RemoteError::NoCapability;
        let e2 = e.clone();
        assert_eq!(e, e2);
        assert_ne!(e, RemoteError::LeaseExpired);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("NoCapability"));
    }
}
