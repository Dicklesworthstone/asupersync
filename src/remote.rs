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
//! # Supported Contract
//!
//! This module is the authoritative remote execution contract for Track F. It
//! defines:
//!
//! - the transport-agnostic protocol payloads and envelopes
//! - the origin/remote state machines for spawn/ack/cancel/result/lease flows
//! - the capability, region-ownership, and idempotency rules for remote work
//! - the deterministic no-runtime fallback used when no [`RemoteRuntime`] is attached
//!
//! Outbound lifecycle integration remains injected through [`RemoteRuntime`] /
//! [`RemoteTransport`], so deterministic lab harnesses and real transports share
//! the same protocol rules. With the `tls` feature, this module also exposes a
//! bounded one-shot service adapter for executing one authenticated named
//! computation over an already-established TLS stream. Native TLS builds also
//! expose a structured TCP listener that owns accepted connections through a
//! child region and drains them explicitly. Protocol V2 listeners additionally
//! reserve idempotency keys per authenticated peer and replay retained terminal
//! outcomes before a retry can execute again. Protocol V3 retains that scoped
//! idempotency and owns cancellation plus renewable leases on the same mTLS
//! connection. The native client bounds connect, handshake, exchange, and
//! backoff, retries only failures proven to precede request delivery, and fails
//! closed on every ambiguous delivery because the listener's retained state is
//! process-local. V1/V2 computations remain one-request/one-response; V3 owns a
//! child region until handler completion, expiry, explicit cancellation, or
//! transport loss has drained to quiescence. Native TLS builds also expose
//! [`NativeRemoteRuntime`], which maps the synchronous [`RemoteRuntime`] trait
//! onto runtime-owned V3 session tasks without blocking the caller or detaching
//! network work from runtime shutdown.

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
use crate::channel::mpsc;
use crate::channel::oneshot;
#[cfg(feature = "tls")]
use crate::codec::{Framed, LengthDelimitedCodec};
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
use crate::combinator::JoinSet;
use crate::cx::Cx;
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
use crate::cx::{ChildRegionError, ChildRegionSpec};
use crate::distributed::membership::{LeaseAction, MembershipLeaseReactor, MembershipView};
use crate::distributed::{
    ComputationRegistryFingerprint, ComputationSchemaRegistry, ComputationSchemaRegistryError,
    HasSchema,
};
use crate::trace::distributed::{LogicalClockHandle, LogicalTime};
use crate::types::outcome::Outcome;
use crate::types::{Budget, CancelReason, ObligationId, RegionId, TaskId, Time};
use crate::util::det_hash::DetHashMap;
#[cfg(feature = "tls")]
use crate::{
    bytes::BytesMut,
    io::AsyncRead,
    io::AsyncWrite,
    stream::{Stream, StreamExt},
};
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
use crate::{
    net::{TcpListener, TcpStream, TcpStreamBuilder},
    runtime::{RuntimeHandle, SpawnError},
    server::{ConnectionManager, ShutdownPhase, ShutdownSignal, ShutdownStats},
    tls::{TlsAcceptor, TlsConnector, TlsError},
};
#[cfg(feature = "tls")]
use parking_lot::Mutex;
#[cfg(feature = "tls")]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::io;
use std::marker::PhantomData;
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
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
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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

    /// Returns the last observed lifecycle state for the given remote task, if
    /// the runtime tracks it.
    fn observe_task_state(&self, _task_id: RemoteTaskId) -> Option<RemoteTaskState> {
        None
    }

    /// Clears any runtime-tracked lifecycle state after a terminal result has
    /// been consumed locally.
    ///
    /// Implementations must remove the task from any state tracking maps to
    /// prevent resource leaks.
    fn clear_task_state(&self, task_id: RemoteTaskId);

    /// Unregisters a pending local task after spawn failure.
    ///
    /// Implementations that keep a pending-results map must remove the
    /// entry for `task_id` to prevent resource leaks.
    fn unregister_task(&self, task_id: RemoteTaskId);
}

// ---------------------------------------------------------------------------
// Phase-0 fallback policy
// ---------------------------------------------------------------------------

/// Failure mode used when `spawn_remote()` is called without an attached
/// [`RemoteRuntime`].
///
/// The no-runtime fallback must stay explicit and deterministic. It resolves
/// the handle to the configured terminal error immediately instead of spawning
/// detached work or sleeping on wall-clock time inside core runtime code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase0RemoteFailure {
    /// Simulate an unreachable destination node.
    NodeUnreachable,
    /// Simulate a node that exists but is currently down.
    NodeDown,
    /// Simulate a transport-layer failure after retry attempts.
    TransportError(String),
    /// Simulate a request that only times out.
    Timeout,
}

impl Phase0RemoteFailure {
    fn to_remote_error(&self, node: &NodeId) -> RemoteError {
        match self {
            Self::NodeUnreachable => RemoteError::NodeUnreachable(node.as_str().to_owned()),
            Self::NodeDown => RemoteError::NodeDown(node.as_str().to_owned()),
            Self::TransportError(message) => RemoteError::TransportError(message.clone()),
            Self::Timeout => RemoteError::Cancelled(CancelReason::timeout()),
        }
    }
}

/// Retry policy for the no-runtime remote fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phase0RetryPolicy {
    /// Total number of attempts, including the initial attempt.
    pub max_attempts: u32,
    /// Initial backoff before the second attempt.
    pub initial_backoff: Duration,
    /// Maximum backoff cap.
    pub max_backoff: Duration,
}

impl Default for Phase0RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(25),
            max_backoff: Duration::from_millis(100),
        }
    }
}

/// Configuration for the no-runtime remote fallback path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phase0SimulationConfig {
    /// Failure mode produced by the no-runtime fallback.
    pub failure: Phase0RemoteFailure,
    /// Descriptive retry schedule for higher-level transport simulations.
    pub retry: Phase0RetryPolicy,
    /// Descriptive timeout budget for higher-level transport simulations.
    pub timeout: Duration,
}

impl Default for Phase0SimulationConfig {
    fn default() -> Self {
        Self {
            failure: Phase0RemoteFailure::NodeUnreachable,
            retry: Phase0RetryPolicy::default(),
            timeout: Duration::from_millis(250),
        }
    }
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
    /// Explicit fallback policy used when no runtime is attached.
    phase0_simulation: Phase0SimulationConfig,
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
            phase0_simulation: Phase0SimulationConfig::default(),
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

    /// Configures the explicit no-runtime fallback policy.
    #[must_use]
    pub fn with_phase0_simulation(mut self, config: Phase0SimulationConfig) -> Self {
        self.phase0_simulation = config;
        self
    }

    /// Sets the failure mode used by the no-runtime fallback.
    #[must_use]
    pub fn with_phase0_failure(mut self, failure: Phase0RemoteFailure) -> Self {
        self.phase0_simulation.failure = failure;
        self
    }

    /// Sets the descriptive retry policy used by the no-runtime fallback.
    #[must_use]
    pub fn with_phase0_retry(mut self, retry: Phase0RetryPolicy) -> Self {
        self.phase0_simulation.retry = retry;
        self
    }

    /// Sets the descriptive timeout used by the no-runtime fallback.
    #[must_use]
    pub fn with_phase0_timeout(mut self, timeout: Duration) -> Self {
        self.phase0_simulation.timeout = timeout;
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

    /// Returns the configuration used by the no-runtime fallback policy.
    #[must_use]
    pub fn phase0_simulation(&self) -> &Phase0SimulationConfig {
        &self.phase0_simulation
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// The remote node is known but unavailable.
    NodeDown(String),
    /// The computation name is not registered on the remote node.
    UnknownComputation(String),
    /// The remote node explicitly rejected the spawn request.
    SpawnRejected(SpawnRejectReason),
    /// The lease expired before the task completed.
    LeaseExpired,
    /// The terminal remote result was already consumed.
    PolledAfterCompletion,
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
            Self::NodeDown(node) => write!(f, "node down: {node}"),
            Self::UnknownComputation(name) => {
                write!(f, "unknown computation: {name}")
            }
            Self::SpawnRejected(reason) => write!(f, "remote spawn rejected: {reason}"),
            Self::LeaseExpired => write!(f, "remote task lease expired"),
            Self::PolledAfterCompletion => {
                write!(f, "remote handle polled after completion")
            }
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
/// - `abort(&Cx)` to request cancellation of the remote task
///
/// # Region Ownership
///
/// The `RemoteHandle` is owned by the local region. When the region closes,
/// all remote handles participate in quiescence: the region waits for remote
/// tasks to complete (or escalates via cancellation/lease expiry).
///
/// # Current Contract
///
/// The handle is the local, region-owned proxy for the remote lifecycle defined
/// in this module. Attached runtimes drive it via the explicit
/// spawn/ack/cancel/result/lease protocol. When no runtime is attached, the
/// handle resolves through the configured deterministic fallback instead of
/// silently spawning detached work.
pub struct RemoteHandle {
    /// Unique identifier for this remote task.
    remote_task_id: RemoteTaskId,
    /// Local proxy task ID (if registered in the runtime).
    local_task_id: Option<TaskId>,
    /// Origin node used for follow-up protocol messages.
    origin_node: NodeId,
    /// Target node.
    node: NodeId,
    /// Computation name.
    computation: ComputationName,
    /// Region that owns this remote task.
    owner_region: RegionId,
    /// Runtime tracking lifecycle updates for this remote task.
    runtime: Option<Arc<dyn RemoteRuntime>>,
    /// Receiver for the remote result.
    receiver: oneshot::Receiver<Result<RemoteOutcome, RemoteError>>,
    /// Logical clock retained so drop-triggered protocol messages can stamp a
    /// fresh send event even when no `Cx` is available anymore.
    sender_clock: LogicalClockHandle,
    /// Lease duration for this task.
    lease: Duration,
    /// Current observed state.
    state: RemoteTaskState,
    /// Whether the terminal result has already been consumed.
    completed: bool,
}

impl Drop for RemoteHandle {
    fn drop(&mut self) {
        if self.completed {
            return;
        }

        let observed_state = self.observed_state();
        self.state = observed_state;
        let should_cancel = self.should_request_cancel();
        if should_cancel {
            // A dropped live handle should request remote cancellation, but it
            // must remain runtime-tracked until the distributed lifecycle
            // reaches a terminal state. Clearing it here would orphan the
            // remote task from origin-side quiescence accounting.
            self.request_cancel(CancelReason::user("remote handle dropped"));
        } else if self.receiver.is_ready() || self.receiver.is_closed() || self.runtime.is_none() {
            self.clear_runtime_state();
        }
    }
}

impl fmt::Debug for RemoteHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteHandle")
            .field("remote_task_id", &self.remote_task_id)
            .field("local_task_id", &self.local_task_id)
            .field("origin_node", &self.origin_node)
            .field("node", &self.node)
            .field("computation", &self.computation)
            .field("owner_region", &self.owner_region)
            .field("runtime", &self.runtime.as_ref().map(|_| "attached"))
            .field("sender_clock", &self.sender_clock)
            .field("lease", &self.lease)
            .field("state", &self.state)
            .field("completed", &self.completed)
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

    #[inline]
    fn closed_reason() -> CancelReason {
        CancelReason::user("remote handle channel closed")
    }

    #[inline]
    fn closed_transport_error(state: RemoteTaskState) -> RemoteError {
        RemoteError::TransportError(format!(
            "remote result channel closed after task reached terminal state {state}"
        ))
    }

    #[inline]
    fn clear_runtime_state(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.clear_task_state(self.remote_task_id);
        }
    }

    #[inline]
    fn abort_with(&self, origin_node: NodeId, sender_time: LogicalTime, reason: CancelReason) {
        let Some(runtime) = &self.runtime else {
            return;
        };

        let envelope = MessageEnvelope::new(
            origin_node.clone(),
            sender_time,
            RemoteMessage::CancelRequest(CancelRequest {
                remote_task_id: self.remote_task_id,
                reason,
                origin_node,
            }),
        );

        let _ = runtime.send_message(&self.node, envelope);
    }

    #[inline]
    fn request_cancel(&self, reason: CancelReason) {
        self.abort_with(self.origin_node.clone(), self.sender_clock.tick(), reason);
    }

    #[inline]
    fn observed_state(&self) -> RemoteTaskState {
        self.runtime
            .as_ref()
            .and_then(|runtime| runtime.observe_task_state(self.remote_task_id))
            .unwrap_or(self.state)
    }

    #[inline]
    fn has_buffered_terminal_result(&self) -> bool {
        self.completed || self.receiver.is_ready()
    }

    #[inline]
    fn should_request_cancel(&self) -> bool {
        // A closed result channel only means the sender disappeared; it does
        // not prove the remote lifecycle reached a terminal state. We only
        // suppress cancellation once the terminal result is buffered locally
        // or already consumed.
        if self.has_buffered_terminal_result() {
            return false;
        }

        matches!(
            self.observed_state(),
            RemoteTaskState::Pending | RemoteTaskState::Running
        )
    }

    #[inline]
    fn finish_result(
        &mut self,
        result: Result<RemoteOutcome, RemoteError>,
    ) -> Result<RemoteOutcome, RemoteError> {
        self.completed = true;
        self.state = Self::terminal_state_for_result(&result);
        self.clear_runtime_state();
        result
    }

    #[inline]
    fn finish_closed(&mut self) -> RemoteError {
        self.completed = true;
        let observed_state = self.observed_state();
        self.state = match observed_state {
            RemoteTaskState::Pending | RemoteTaskState::Running => RemoteTaskState::Cancelled,
            terminal => terminal,
        };
        self.clear_runtime_state();
        match observed_state {
            RemoteTaskState::LeaseExpired => RemoteError::LeaseExpired,
            RemoteTaskState::Completed | RemoteTaskState::Failed => {
                Self::closed_transport_error(observed_state)
            }
            _ => RemoteError::Cancelled(Self::closed_reason()),
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
    pub fn state(&self) -> RemoteTaskState {
        if self.completed {
            self.state
        } else if let Some(runtime) = &self.runtime {
            runtime
                .observe_task_state(self.remote_task_id)
                .unwrap_or(self.state)
        } else {
            self.state
        }
    }

    /// Returns true if a terminal remote result has been buffered locally.
    ///
    /// A merely closed result channel does not count as finished here. The
    /// sender may have disappeared before the remote lifecycle reached a
    /// terminal state, and callers still need `close()` / `abort()` to fence
    /// and drain the remote task in that case.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.completed || self.receiver.is_ready()
    }

    /// Requests cancellation and drains the remote lifecycle to a terminal state.
    ///
    /// This is the explicit close operation for a remote handle: it forwards a
    /// best-effort cancellation request when a runtime is attached, then awaits
    /// the terminal remote result so origin-side runtime state can be cleared.
    ///
    /// # Errors
    ///
    /// Unlike [`join`](Self::join), once `close()` starts draining it ignores
    /// caller cancellation so runtime bookkeeping is always finalized before
    /// returning. If the terminal result was already consumed, it returns
    /// `PolledAfterCompletion`.
    pub async fn close(&mut self, cx: &Cx) -> Outcome<RemoteOutcome, RemoteError> {
        if self.completed {
            return Outcome::err(RemoteError::PolledAfterCompletion);
        }

        if self.should_request_cancel() {
            let reason = cx
                .cancel_reason()
                .unwrap_or_else(|| CancelReason::user("remote handle close"));
            cx.trace(trace_events::CANCEL_SENT);
            self.request_cancel(reason);
        }

        match self.receiver.recv_uninterruptible().await {
            Ok(result) => {
                cx.trace(trace_events::RESULT_DELIVERED);
                match self.finish_result(result) {
                    Ok(outcome) => Outcome::ok(outcome),
                    Err(e) => Outcome::err(e),
                }
            }
            Err(oneshot::RecvError::Closed) => {
                let err = self.finish_closed();
                if err == RemoteError::LeaseExpired {
                    cx.trace(trace_events::LEASE_EXPIRED);
                }
                Outcome::err(err)
            }
            Err(oneshot::RecvError::Cancelled) => {
                unreachable!("RecvUninterruptibleFuture cannot return Cancelled")
            }
            Err(oneshot::RecvError::PolledAfterCompletion) => {
                unreachable!("RemoteHandle::close awaits a fresh uninterruptible recv future")
            }
        }
    }

    /// Waits for the remote task to complete and returns its result.
    ///
    /// This method yields until the remote task completes (or fails/cancels),
    /// unless the caller context is cancelled first.
    ///
    /// # Errors
    ///
    /// Returns `RemoteError` if the remote task failed, was cancelled,
    /// the lease expired, or a terminal result was already consumed.
    pub async fn join(&mut self, cx: &Cx) -> Outcome<RemoteOutcome, RemoteError> {
        if self.completed {
            return Outcome::err(RemoteError::PolledAfterCompletion);
        }

        match self.receiver.recv(cx).await {
            Ok(result) => {
                cx.trace(trace_events::RESULT_DELIVERED);
                match self.finish_result(result) {
                    Ok(outcome) => Outcome::ok(outcome),
                    Err(e) => Outcome::err(e),
                }
            }
            Err(oneshot::RecvError::Closed) => {
                let err = self.finish_closed();
                if err == RemoteError::LeaseExpired {
                    cx.trace(trace_events::LEASE_EXPIRED);
                }
                Outcome::err(err)
            }
            Err(oneshot::RecvError::Cancelled) => {
                let reason = cx
                    .cancel_reason()
                    .unwrap_or_else(CancelReason::parent_cancelled);
                Outcome::err(RemoteError::Cancelled(reason))
            }
            Err(oneshot::RecvError::PolledAfterCompletion) => {
                unreachable!("RemoteHandle::join awaits a fresh oneshot recv future")
            }
        }
    }

    /// Attempts to get the remote task's result without waiting.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(result))` if the remote task has completed
    /// - `Ok(None)` if the remote task is still running
    /// - `Err(RemoteError)` if the remote task failed
    pub fn try_join(&mut self) -> Result<Option<RemoteOutcome>, RemoteError> {
        if self.completed {
            return Err(RemoteError::PolledAfterCompletion);
        }

        match self.receiver.try_recv() {
            Ok(result) => Ok(Some(self.finish_result(result)?)),
            Err(oneshot::TryRecvError::Empty) => Ok(None),
            Err(oneshot::TryRecvError::Closed) => Err(self.finish_closed()),
        }
    }

    /// Requests cancellation of the remote task using the caller's remote capability.
    ///
    /// This is a request — the remote node may not stop immediately.
    /// The cancellation propagates via the remote protocol when the provided
    /// context carries an attached [`RemoteRuntime`].
    ///
    /// If the context does not have a remote capability, or if it is configured
    /// for deterministic Phase 0 fallback without an attached runtime, this is
    /// a no-op.
    pub fn abort(&self, cx: &Cx) {
        let Some(cap) = cx.remote() else {
            return;
        };
        if cap.runtime().is_none() {
            return;
        }
        if !self.should_request_cancel() {
            return;
        }

        let reason = cx
            .cancel_reason()
            .unwrap_or_else(|| CancelReason::user("remote handle abort"));
        cx.trace(trace_events::CANCEL_SENT);
        self.request_cancel(reason);
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
/// # Current Contract
///
/// Attached runtimes can use deterministic harnesses such as
/// [`DistributedHarness`](crate::lab::network::DistributedHarness) or later
/// real transports that implement the protocol defined in this module. When no
/// runtime is attached, `spawn_remote()` resolves the handle to the configured
/// explicit fallback error immediately. This keeps behavior deterministic and
/// avoids detached wall-clock work outside structured concurrency.
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
    let origin_node = cap.local_node().clone();
    let sender_clock = cx.logical_clock_handle();

    cx.trace("spawn_remote");

    // Create the oneshot channel for result delivery.
    let (tx, rx) = oneshot::channel::<Result<RemoteOutcome, RemoteError>>();

    // If a remote runtime is attached, register the task and send the request.
    let initial_state = if let Some(runtime) = cap.runtime() {
        runtime.register_task(remote_task_id, tx);

        let req = SpawnRequest {
            remote_task_id,
            computation: computation.clone(),
            input,
            lease,
            idempotency_key: IdempotencyKey::generate(cx),
            budget: cap.remote_budget,
            origin_node: origin_node.clone(),
            origin_region: region,
            origin_task: cx.task_id(),
        };
        cx.trace(trace_events::SPAWN_REQUEST_CREATED);

        let sender_time = cx.logical_tick();
        let envelope = MessageEnvelope::new(
            req.origin_node.clone(),
            sender_time,
            RemoteMessage::SpawnRequest(req),
        );
        if let Err(err) = runtime.send_message(&node, envelope) {
            runtime.unregister_task(remote_task_id);
            return Err(err);
        }
        cx.trace(trace_events::SPAWN_REQUEST_SENT);
        RemoteTaskState::Pending
    } else {
        let fallback_error = cap.phase0_simulation().failure.to_remote_error(&node);
        // This is an already-classified terminal result, not cancellable
        // remote work. Publishing it through the caller's Cx would turn an
        // already-cancelled caller into a send failure (and previously a
        // panic), even though the fresh handle must deterministically expose
        // the configured fallback error.
        tx.send_blocking(Err(fallback_error.clone()))
            .expect("fresh remote receiver must accept fallback result");
        RemoteHandle::terminal_state_for_result(&Err(fallback_error))
    };

    Ok(RemoteHandle {
        remote_task_id,
        local_task_id: None,
        origin_node,
        node,
        computation,
        owner_region: region,
        runtime: cap.runtime().cloned(),
        receiver: rx,
        sender_clock,
        lease,
        state: initial_state,
        completed: false,
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
        if self.state != LeaseState::Active || now >= self.expires_at {
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
        if now >= self.expires_at {
            self.state = LeaseState::Expired;
            return Err(LeaseError::Expired);
        }
        self.state = LeaseState::Released;
        // The caller is responsible for committing the obligation in RuntimeState.
        // This method just updates the lease state.
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
// Membership-driven lease manager (bead 8y37kz.4.3 — suspicion → obligation
// revocation)
// ===========================================================================

/// A lease the [`MembershipLeaseManager`] revoked because its node was confirmed
/// dead or left.
///
/// The caller aborts the underlying obligation
/// (`ObligationAbortReason::Cancel`) through `RuntimeState`, which triggers any
/// saga compensation attached to that obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedLease {
    /// The node whose membership transition caused the revocation.
    pub node: NodeId,
    /// The lease's underlying obligation, to be aborted by the caller.
    pub obligation_id: ObligationId,
}

/// Drives the remote lease lifecycle from SWIM membership (bead
/// `asupersync-dist-otp-completeness-8y37kz.4.3`).
///
/// It holds a per-node registry of outstanding [`Lease`]s and a
/// [`MembershipLeaseReactor`]. Feed it the watchable membership stream via
/// [`sync`](Self::sync): while a node is suspected, new grants to it are paused
/// ([`try_grant`](Self::try_grant) rejects them so a refutation can still rescue
/// existing leases); when a node is confirmed dead/left, each of its leases is
/// marked expired and surfaced as a [`RevokedLease`] so the caller aborts the
/// obligation through the normal protocol — death is just another reason an
/// obligation is aborted, so saga compensation flows through the existing path
/// with no novel failure handling (the parent's novel contribution).
#[derive(Debug, Default)]
pub struct MembershipLeaseManager {
    reactor: MembershipLeaseReactor,
    leases: std::collections::BTreeMap<NodeId, Vec<Lease>>,
}

impl MembershipLeaseManager {
    /// A manager with no observed membership and no registered leases.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `lease` as held for `node`. Rejected — returning the lease so
    /// the caller can abort it — if the node is currently suspected (grants
    /// paused) or already revoked (dead/left).
    pub fn try_grant(&mut self, node: &NodeId, lease: Lease) -> Result<(), Lease> {
        if self.reactor.is_paused(node) || self.reactor.is_revoked(node) {
            return Err(lease);
        }
        self.leases.entry(node.clone()).or_default().push(lease);
        Ok(())
    }

    /// Number of leases currently held for `node`.
    #[must_use]
    pub fn active_leases(&self, node: &NodeId) -> usize {
        self.leases.get(node).map_or(0, Vec::len)
    }

    /// Whether new grants to `node` are paused (the node is suspected).
    #[must_use]
    pub fn is_paused(&self, node: &NodeId) -> bool {
        self.reactor.is_paused(node)
    }

    /// Whether `node`'s leases have been revoked (the node is confirmed dead).
    #[must_use]
    pub fn is_revoked(&self, node: &NodeId) -> bool {
        self.reactor.is_revoked(node)
    }

    /// Applies pending membership transitions. For each node newly confirmed
    /// dead/left, marks its leases expired and returns them as [`RevokedLease`]s
    /// for the caller to abort through the obligation protocol (which triggers
    /// attached saga compensation). Suspicion/refutation transitions update the
    /// grant-pause state consulted by [`try_grant`](Self::try_grant).
    pub fn sync(&mut self, view: &MembershipView) -> Vec<RevokedLease> {
        let mut revoked = Vec::new();
        for (node, action) in self.reactor.poll(view) {
            if action != LeaseAction::Revoke {
                continue;
            }
            if let Some(mut leases) = self.leases.remove(&node) {
                for lease in &mut leases {
                    let obligation_id = lease.obligation_id();
                    // Revoke via the obligation protocol: mark the lease expired
                    // so the caller aborts the obligation (Cancel) and any saga
                    // compensation attached to it runs.
                    let _ = lease.mark_expired();
                    revoked.push(RevokedLease {
                        node: node.clone(),
                        obligation_id,
                    });
                }
            }
        }
        revoked
    }
}

// ===========================================================================
// Idempotency Store (tmh.2.2)
// ===========================================================================
//
// The remote side uses an IdempotencyStore to deduplicate spawn requests.
// Each entry maps an IdempotencyKey to its recorded outcome. In-flight entries
// remain resident for the operation lifetime; terminal entries expire after a
// configurable retention TTL to bound memory usage.

/// Recorded state of an admitted idempotent request.
#[derive(Clone, Debug)]
pub struct IdempotencyRecord {
    /// The key for this record.
    pub key: IdempotencyKey,
    /// The remote task ID assigned to this request.
    pub remote_task_id: RemoteTaskId,
    /// Stable fingerprint of the semantic request guarded by this key.
    pub request: IdempotencyRequestFingerprint,
    /// When this record was created.
    pub created_at: Time,
    /// Terminal-result retention deadline.
    ///
    /// This is `None` while the operation is in flight. Completion establishes
    /// the deadline, so a long-running operation cannot outlive its own
    /// deduplication record.
    pub expires_at: Option<Time>,
    /// The outcome, if the request has completed.
    pub outcome: Option<RemoteOutcome>,
}

/// Decision from the idempotency store when a request arrives.
#[derive(Clone, Debug)]
pub enum DedupDecision {
    /// New request admitted and key reserved. Proceed with canonical execution.
    New,
    /// Matching request already admitted. Attach to the canonical task or
    /// return its cached terminal outcome.
    Duplicate(IdempotencyRecord),
    /// Conflict — same key but different parameters. Reject.
    Conflict,
}

/// Stable fingerprint of the semantic spawn request guarded by an
/// [`IdempotencyKey`].
///
/// Remote task IDs are intentionally excluded because they are assigned per
/// delivery attempt. The deduplication contract is scoped to the logical
/// operation being requested, not to origin-side execution metadata. Retry-only
/// changes such as lease tuning, budget clamping, or origin task migration must
/// not turn a duplicate into a conflict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdempotencyRequestFingerprint {
    /// The computation that was requested.
    pub computation: ComputationName,
    /// Serialized input payload.
    pub input: RemoteInput,
}

impl IdempotencyRequestFingerprint {
    /// Creates a new request fingerprint.
    #[must_use]
    pub fn new(computation: ComputationName, input: RemoteInput) -> Self {
        Self { computation, input }
    }

    /// Builds a request fingerprint from a spawn request.
    #[must_use]
    pub fn from_spawn_request(request: &SpawnRequest) -> Self {
        Self {
            computation: request.computation.clone(),
            input: request.input.clone(),
        }
    }
}

/// Store for tracking idempotent request deduplication.
///
/// The remote node uses this to prevent duplicate execution while an operation
/// is in flight and during the configured post-terminal retention window. The
/// guarantee does not survive store reset or terminal-record eviction.
/// When a `SpawnRequest` arrives:
/// 1. Atomically check and record the idempotency key
/// 2. If new: execute the already-recorded operation
/// 3. If duplicate: attach to the canonical task or return its cached outcome
/// 4. If conflict (same key, different params): reject
///
/// In-flight entries are retained for the operation lifetime. Once an entry is
/// completed, it is retained for the configured TTL so retries can observe the
/// canonical outcome. Callers must complete every admitted entry when the
/// operation reaches a terminal state.
///
/// # Thread Safety
///
/// The store is designed for single-threaded use within the deterministic
/// lab runtime. For production multi-threaded use, wrap in a lock.
pub struct IdempotencyStore {
    entries: DetHashMap<IdempotencyKey, IdempotencyRecord>,
    /// Default retention TTL applied when an entry completes.
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
    /// Only terminal records can expire. In-flight records, and terminal
    /// records without a retention deadline, are retained fail-closed instead
    /// of allowing a second execution.
    ///
    /// This does not insert the key. Admission paths should normally use
    /// [`check_and_record`](Self::check_and_record), which makes the decision
    /// and insertion one indivisible store operation.
    #[must_use]
    #[cfg(test)]
    fn check(
        &mut self,
        key: &IdempotencyKey,
        request: &IdempotencyRequestFingerprint,
        now: Time,
    ) -> DedupDecision {
        let Some(record) = self.entries.get(key).cloned() else {
            return DedupDecision::New;
        };

        if record.outcome.is_some() && record.expires_at.is_some_and(|expiry| now >= expiry) {
            let _ = self.entries.remove(key);
            return DedupDecision::New;
        }

        if record.request == *request {
            DedupDecision::Duplicate(record)
        } else {
            DedupDecision::Conflict
        }
    }

    /// Atomically checks a request and records it when it is new.
    ///
    /// A [`DedupDecision::New`] result guarantees that the supplied key and
    /// canonical task ID were inserted before this method returned. Holding the
    /// store's exclusive borrow across both steps prevents a caller-visible
    /// check/record gap.
    #[must_use]
    pub fn check_and_record(
        &mut self,
        key: IdempotencyKey,
        remote_task_id: RemoteTaskId,
        request: IdempotencyRequestFingerprint,
        now: Time,
    ) -> DedupDecision {
        use std::collections::hash_map::Entry;
        match self.entries.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(Self::in_flight_record(key, remote_task_id, request, now));
                DedupDecision::New
            }
            Entry::Occupied(mut entry) => {
                let expired = entry.get().outcome.is_some()
                    && entry.get().expires_at.is_some_and(|expiry| now >= expiry);
                if expired {
                    entry.insert(Self::in_flight_record(key, remote_task_id, request, now));
                    DedupDecision::New
                } else if entry.get().request == request {
                    DedupDecision::Duplicate(entry.get().clone())
                } else {
                    DedupDecision::Conflict
                }
            }
        }
    }

    /// Records a new idempotent request.
    ///
    /// Returns `true` if the entry was inserted (new key).
    /// Returns `false` if the key already existed (no update).
    #[cfg(test)]
    fn record(
        &mut self,
        key: IdempotencyKey,
        remote_task_id: RemoteTaskId,
        request: IdempotencyRequestFingerprint,
        now: Time,
    ) -> bool {
        use std::collections::hash_map::Entry;
        match self.entries.entry(key) {
            Entry::Vacant(e) => {
                e.insert(Self::in_flight_record(key, remote_task_id, request, now));
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Updates the outcome of the canonical task and starts its terminal-result
    /// retention window at `now`.
    ///
    /// The task ID fences record generations after an expired key is admitted
    /// again. A delayed completion from the previous generation is rejected.
    ///
    /// Returns `true` if the matching canonical record was found and updated.
    pub fn complete(
        &mut self,
        key: &IdempotencyKey,
        remote_task_id: RemoteTaskId,
        outcome: RemoteOutcome,
        now: Time,
    ) -> bool {
        match self.entries.get_mut(key) {
            Some(record) if record.remote_task_id == remote_task_id => {
                record.outcome = Some(outcome);
                record.expires_at = Some(now + self.default_ttl);
                true
            }
            _ => false,
        }
    }

    /// Evicts terminal entries whose retention deadline has elapsed.
    ///
    /// In-flight entries are never evicted by this method.
    ///
    /// Returns the number of entries evicted.
    pub fn evict_expired(&mut self, now: Time) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, record| {
            record.outcome.is_none() || record.expires_at.is_none_or(|expires_at| now < expires_at)
        });
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

    fn in_flight_record(
        key: IdempotencyKey,
        remote_task_id: RemoteTaskId,
        request: IdempotencyRequestFingerprint,
        now: Time,
    ) -> IdempotencyRecord {
        IdempotencyRecord {
            key,
            remote_task_id,
            request,
            created_at: now,
            expires_at: None,
            outcome: None,
        }
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
            if std::thread::panicking() {
                // Already unwinding — running user closures that might panic
                // would abort the process.  Mark as aborted without running
                // compensations; the caller is already handling an error.
                self.state = SagaState::Aborted;
                return;
            }
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
// All messages carry the RemoteTaskId for correlation. While the remote
// idempotency record is retained, duplicate SpawnRequests with the same key are
// deduplicated by the remote node.

// ---------------------------------------------------------------------------
// Idempotency key
// ---------------------------------------------------------------------------

/// Idempotency key for bounded remote-spawn deduplication.
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

/// Stable version identifier for the remote-service wire protocol.
///
/// Admission currently requires an exact version match. A future compatible
/// range can be introduced deliberately without silently accepting a peer that
/// may interpret lifecycle messages differently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RemoteProtocolVersion {
    major: u16,
    minor: u16,
}

impl RemoteProtocolVersion {
    /// Initial version of the named-computation remote-service protocol.
    pub const V1: Self = Self::new(1, 0);
    /// Listener protocol with authenticated-peer-scoped idempotency.
    ///
    /// A V2 listener reserves a key before handler dispatch, retains terminal
    /// outcomes for bounded replay, and refuses ambiguous in-flight retries.
    /// The guarantee is process-local and does not survive service restart.
    pub const V2: Self = Self::new(2, 0);
    /// Listener protocol with same-connection lifecycle controls.
    ///
    /// V3 retains V2's authenticated-peer-scoped idempotency contract and adds
    /// connection-owned cancellation and lease renewal. A V3 request must be
    /// handled by the session driver; it must never fall back to V1 execution.
    pub const V3: Self = Self::new(3, 0);

    /// Creates a protocol version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Returns the major version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Returns the minor version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

impl fmt::Display for RemoteProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Peer metadata presented before remote protocol messages are dispatched.
///
/// The `peer_node` value is an asserted logical identity. A production network
/// adapter must bind it to an authenticated transport identity (for example, a
/// verified TLS certificate); this structure alone is not authentication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemotePeerHello {
    peer_node: NodeId,
    protocol_version: RemoteProtocolVersion,
    registry_fingerprint: ComputationRegistryFingerprint,
}

impl RemotePeerHello {
    /// Creates peer negotiation metadata.
    #[must_use]
    pub const fn new(
        peer_node: NodeId,
        protocol_version: RemoteProtocolVersion,
        registry_fingerprint: ComputationRegistryFingerprint,
    ) -> Self {
        Self {
            peer_node,
            protocol_version,
            registry_fingerprint,
        }
    }

    /// Asserted logical identity of the connecting peer.
    #[must_use]
    pub const fn peer_node(&self) -> &NodeId {
        &self.peer_node
    }

    /// Protocol version offered by the peer.
    #[must_use]
    pub const fn protocol_version(&self) -> RemoteProtocolVersion {
        self.protocol_version
    }

    /// Complete named-computation registry identity offered by the peer.
    #[must_use]
    pub const fn registry_fingerprint(&self) -> ComputationRegistryFingerprint {
        self.registry_fingerprint
    }
}

/// Fail-closed peer negotiation and dispatch diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemotePeerAdmissionError {
    /// The transport-authenticated peer has no capability grant.
    UnauthorizedPeer {
        /// Presented peer identity.
        peer: NodeId,
    },
    /// A certificate-bound peer was presented without a verified TLS stream.
    TlsAuthenticationRequired {
        /// Presented peer identity.
        peer: NodeId,
    },
    /// TLS admission was requested for a peer whose grant has no certificate pins.
    TlsIdentityNotConfigured {
        /// Presented peer identity.
        peer: NodeId,
    },
    /// The verified TLS session did not present a peer certificate.
    TlsPeerCertificateMissing {
        /// Presented peer identity.
        peer: NodeId,
    },
    /// The verified TLS peer certificate did not match the configured pin set.
    TlsPeerCertificateRejected {
        /// Presented peer identity.
        peer: NodeId,
        /// Pin-validation diagnostic.
        detail: String,
    },
    /// A TLS peer grant used an empty or report-only pin set.
    InvalidTlsPeerPinSet {
        /// Peer whose grant was rejected.
        peer: NodeId,
    },
    /// A configured grant names a computation absent from the registry.
    UnknownGrantedComputation {
        /// Name rejected while constructing the policy.
        computation: String,
    },
    /// The peer speaks a different remote-service protocol version.
    ProtocolVersionMismatch {
        /// Version accepted by this endpoint.
        accepted: RemoteProtocolVersion,
        /// Version presented by the peer.
        presented: RemoteProtocolVersion,
    },
    /// The peer advertises a different complete computation registry.
    RegistryFingerprintMismatch {
        /// Registry identity required by this endpoint.
        expected: ComputationRegistryFingerprint,
        /// Registry identity presented by the peer.
        presented: ComputationRegistryFingerprint,
    },
    /// The admitted peer lacks a capability grant for this computation.
    ComputationNotAuthorized {
        /// Admitted peer identity.
        peer: NodeId,
        /// Requested computation name.
        computation: String,
    },
}

impl fmt::Display for RemotePeerAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnauthorizedPeer { peer } => {
                write!(f, "remote peer is not capability-authorized: {peer}")
            }
            Self::TlsAuthenticationRequired { peer } => write!(
                f,
                "remote peer requires certificate-bound TLS admission: {peer}"
            ),
            Self::TlsIdentityNotConfigured { peer } => {
                write!(f, "remote peer has no certificate-bound TLS grant: {peer}")
            }
            Self::TlsPeerCertificateMissing { peer } => {
                write!(f, "remote TLS peer presented no certificate: {peer}")
            }
            Self::TlsPeerCertificateRejected { peer, detail } => write!(
                f,
                "remote TLS peer certificate was rejected for {peer}: {detail}"
            ),
            Self::InvalidTlsPeerPinSet { peer } => write!(
                f,
                "remote TLS peer grant requires a non-empty enforcing pin set: {peer}"
            ),
            Self::UnknownGrantedComputation { computation } => write!(
                f,
                "remote peer grant names an unregistered computation: {computation}"
            ),
            Self::ProtocolVersionMismatch {
                accepted,
                presented,
            } => write!(
                f,
                "remote protocol version mismatch: accepted {accepted}, presented {presented}"
            ),
            Self::RegistryFingerprintMismatch {
                expected,
                presented,
            } => write!(
                f,
                "remote computation registry mismatch: expected {expected}, presented {presented}"
            ),
            Self::ComputationNotAuthorized { peer, computation } => write!(
                f,
                "remote computation is not capability-authorized for {peer}: {computation}"
            ),
        }
    }
}

impl std::error::Error for RemotePeerAdmissionError {}

/// Capability policy applied after a network adapter authenticates a peer.
///
/// A policy starts with no grants. Each authorized peer receives an explicit
/// set of registered computation names. Admission additionally requires an
/// exact protocol version and complete registry fingerprint match.
#[derive(Clone, Debug)]
pub struct RemotePeerAdmissionPolicy {
    protocol_version: RemoteProtocolVersion,
    registry: ComputationSchemaRegistry,
    grants: BTreeMap<NodeId, RemotePeerGrant>,
}

#[derive(Clone, Debug)]
struct RemotePeerGrant {
    computations: BTreeSet<String>,
    #[cfg(feature = "tls")]
    tls_certificate_pins: Option<crate::tls::CertificatePinSet>,
}

impl RemotePeerAdmissionPolicy {
    /// Creates a fail-closed policy with no authorized peers.
    #[must_use]
    pub fn new(
        protocol_version: RemoteProtocolVersion,
        registry: ComputationSchemaRegistry,
    ) -> Self {
        Self {
            protocol_version,
            registry,
            grants: BTreeMap::new(),
        }
    }

    /// Grants one peer access to an explicit set of registered computations.
    ///
    /// Re-granting a peer replaces its prior set atomically. Unknown names are
    /// rejected before the policy is mutated.
    pub fn grant_peer<I, S>(
        &mut self,
        peer: NodeId,
        computations: I,
    ) -> Result<(), RemotePeerAdmissionError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let computations = self.validate_computations(computations)?;
        self.grants.insert(
            peer,
            RemotePeerGrant {
                computations,
                #[cfg(feature = "tls")]
                tls_certificate_pins: None,
            },
        );
        Ok(())
    }

    /// Grants one peer certificate-bound access to registered computations.
    ///
    /// The pin set must be non-empty and enforcing. Admission is then possible
    /// only through [`Self::admit_tls_peer`], which obtains the presented leaf
    /// certificate from a successfully handshaken [`crate::tls::TlsStream`].
    /// Calling [`Self::admit`] for this peer fails closed, so an asserted
    /// [`RemotePeerHello::peer_node`] cannot bypass the transport binding.
    #[cfg(feature = "tls")]
    pub fn grant_tls_peer<I, S>(
        &mut self,
        peer: NodeId,
        certificate_pins: crate::tls::CertificatePinSet,
        computations: I,
    ) -> Result<(), RemotePeerAdmissionError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if certificate_pins.is_empty() || !certificate_pins.is_enforcing() {
            return Err(RemotePeerAdmissionError::InvalidTlsPeerPinSet { peer });
        }
        let computations = self.validate_computations(computations)?;
        self.grants.insert(
            peer,
            RemotePeerGrant {
                computations,
                tls_certificate_pins: Some(certificate_pins),
            },
        );
        Ok(())
    }

    /// Builds the hello metadata for a node using this policy's wire contract.
    #[must_use]
    pub fn hello_for(&self, peer_node: NodeId) -> RemotePeerHello {
        RemotePeerHello::new(
            peer_node,
            self.protocol_version,
            self.registry.fingerprint(),
        )
    }

    /// Admits a peer and freezes its granted computation set for the session.
    pub fn admit(
        &self,
        hello: &RemotePeerHello,
    ) -> Result<RemotePeerSession, RemotePeerAdmissionError> {
        let grant = self.grant_for(hello)?;
        #[cfg(feature = "tls")]
        if grant.tls_certificate_pins.is_some() {
            return Err(RemotePeerAdmissionError::TlsAuthenticationRequired {
                peer: hello.peer_node().clone(),
            });
        }
        self.admit_grant(hello, grant)
    }

    /// Admits a certificate-bound peer from an established TLS session.
    ///
    /// The TLS acceptor must have completed certificate verification before
    /// this method is called. For inbound peers that means configuring mutual
    /// TLS; a server-only TLS session has no client certificate and is refused.
    #[cfg(feature = "tls")]
    pub fn admit_tls_peer<IO>(
        &self,
        hello: &RemotePeerHello,
        tls_stream: &crate::tls::TlsStream<IO>,
    ) -> Result<RemotePeerSession, RemotePeerAdmissionError> {
        let grant = self.grant_for(hello)?;
        let certificate_pins = grant.tls_certificate_pins.as_ref().ok_or_else(|| {
            RemotePeerAdmissionError::TlsIdentityNotConfigured {
                peer: hello.peer_node().clone(),
            }
        })?;
        let certificate_der = tls_stream.peer_leaf_certificate_der().ok_or_else(|| {
            RemotePeerAdmissionError::TlsPeerCertificateMissing {
                peer: hello.peer_node().clone(),
            }
        })?;
        let certificate = crate::tls::Certificate::from_der(certificate_der);
        certificate_pins.validate(&certificate).map_err(|error| {
            RemotePeerAdmissionError::TlsPeerCertificateRejected {
                peer: hello.peer_node().clone(),
                detail: error.to_string(),
            }
        })?;
        self.admit_grant(hello, grant)
    }

    fn validate_computations<I, S>(
        &self,
        computations: I,
    ) -> Result<BTreeSet<String>, RemotePeerAdmissionError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut granted = BTreeSet::new();
        for computation in computations {
            let computation = computation.as_ref();
            if !self.registry.contains(computation) {
                return Err(RemotePeerAdmissionError::UnknownGrantedComputation {
                    computation: computation.to_owned(),
                });
            }
            granted.insert(computation.to_owned());
        }
        Ok(granted)
    }

    fn grant_for(
        &self,
        hello: &RemotePeerHello,
    ) -> Result<&RemotePeerGrant, RemotePeerAdmissionError> {
        let Some(grant) = self.grants.get(hello.peer_node()) else {
            return Err(RemotePeerAdmissionError::UnauthorizedPeer {
                peer: hello.peer_node().clone(),
            });
        };
        Ok(grant)
    }

    fn admit_grant(
        &self,
        hello: &RemotePeerHello,
        grant: &RemotePeerGrant,
    ) -> Result<RemotePeerSession, RemotePeerAdmissionError> {
        if hello.protocol_version() != self.protocol_version {
            return Err(RemotePeerAdmissionError::ProtocolVersionMismatch {
                accepted: self.protocol_version,
                presented: hello.protocol_version(),
            });
        }
        let expected_registry = self.registry.fingerprint();
        if hello.registry_fingerprint() != expected_registry {
            return Err(RemotePeerAdmissionError::RegistryFingerprintMismatch {
                expected: expected_registry,
                presented: hello.registry_fingerprint(),
            });
        }
        Ok(RemotePeerSession {
            peer_node: hello.peer_node().clone(),
            protocol_version: self.protocol_version,
            registry_fingerprint: expected_registry,
            granted_computations: grant.computations.clone(),
        })
    }
}

/// Immutable capability grant produced by successful peer admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemotePeerSession {
    peer_node: NodeId,
    protocol_version: RemoteProtocolVersion,
    registry_fingerprint: ComputationRegistryFingerprint,
    granted_computations: BTreeSet<String>,
}

impl RemotePeerSession {
    /// Authenticated logical peer identity bound by the network adapter.
    #[must_use]
    pub const fn peer_node(&self) -> &NodeId {
        &self.peer_node
    }

    /// Negotiated protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> RemoteProtocolVersion {
        self.protocol_version
    }

    /// Negotiated complete computation-registry identity.
    #[must_use]
    pub const fn registry_fingerprint(&self) -> ComputationRegistryFingerprint {
        self.registry_fingerprint
    }

    /// Checks a named computation against this session's frozen capability set.
    pub fn authorize_computation(
        &self,
        computation: &ComputationName,
    ) -> Result<(), RemotePeerAdmissionError> {
        if self.granted_computations.contains(computation.as_str()) {
            Ok(())
        } else {
            Err(RemotePeerAdmissionError::ComputationNotAuthorized {
                peer: self.peer_node.clone(),
                computation: computation.as_str().to_owned(),
            })
        }
    }

    /// Applies the session capability to a protocol message before dispatch.
    ///
    /// Only spawn requests select code. Lifecycle messages are correlated to a
    /// task created under an already-authorized spawn and remain governed by
    /// the remote task state machine.
    pub fn authorize_message(
        &self,
        message: &RemoteMessage,
    ) -> Result<(), RemotePeerAdmissionError> {
        match message {
            RemoteMessage::SpawnRequest(request) => {
                self.authorize_computation(&request.computation)
            }
            RemoteMessage::SpawnAck(_)
            | RemoteMessage::CancelRequest(_)
            | RemoteMessage::ResultDelivery(_)
            | RemoteMessage::LeaseRenewal(_) => Ok(()),
        }
    }
}

/// Caller-owned future produced by a registered remote computation.
///
/// The registry never spawns this future. The service connection or scope that
/// awaits [`RemoteComputationRegistry::dispatch`] therefore remains its
/// structured owner, and dropping that owner drops the computation future.
pub type RemoteComputationFuture =
    Pin<Box<dyn Future<Output = Result<RemoteOutcome, RemoteError>> + Send + 'static>>;

type RemoteComputationHandler =
    Arc<dyn Fn(Cx, RemoteComputationInvocation) -> RemoteComputationFuture + Send + Sync>;

/// Authenticated invocation passed to executable named-computation handlers.
///
/// `peer_node` comes from the admitted session, not from the request payload.
/// Handlers can therefore use it for authorization-aware diagnostics without
/// trusting a caller-controlled `origin_node` field.
#[derive(Clone, Debug)]
pub struct RemoteComputationInvocation {
    peer_node: NodeId,
    request: SpawnRequest,
}

impl RemoteComputationInvocation {
    /// Transport-authenticated peer that requested the computation.
    #[must_use]
    pub const fn peer_node(&self) -> &NodeId {
        &self.peer_node
    }

    /// Admitted spawn request.
    #[must_use]
    pub const fn request(&self) -> &SpawnRequest {
        &self.request
    }

    /// Consumes the invocation and returns its spawn request.
    #[must_use]
    pub fn into_request(self) -> SpawnRequest {
        self.request
    }
}

/// Failure returned before or during executable named-computation dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteComputationDispatchError {
    /// The admitted peer session did not authorize the requested computation.
    Admission(RemotePeerAdmissionError),
    /// The registered handler failed while executing the computation.
    Execution(RemoteError),
}

impl fmt::Display for RemoteComputationDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => write!(f, "remote computation admission failed: {error}"),
            Self::Execution(error) => write!(f, "remote computation execution failed: {error}"),
        }
    }
}

impl std::error::Error for RemoteComputationDispatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Execution(error) => Some(error),
        }
    }
}

/// Executable, schema-identified registry for remote named computations.
///
/// Registration couples every handler name to a declared input/output schema
/// pair, so the complete registry fingerprint used during peer negotiation
/// describes the code-selection surface that can actually run. The handler is
/// still responsible for enforcing those declared schemas when it decodes and
/// encodes its raw bytes; registration does not silently choose a codec.
/// Dispatch requires an immutable admitted session and supplies an explicit
/// [`Cx`] clone to the handler. The registry does not spawn tasks or provide
/// ambient authority.
#[derive(Clone, Default)]
pub struct RemoteComputationRegistry {
    schemas: ComputationSchemaRegistry,
    handlers: BTreeMap<String, RemoteComputationHandler>,
}

impl fmt::Debug for RemoteComputationRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteComputationRegistry")
            .field("schemas", &self.schemas)
            .field("handler_names", &self.handlers.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl RemoteComputationRegistry {
    /// Creates an empty executable registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a `Cx`-threaded asynchronous named computation.
    ///
    /// `I` and `O` define the stable wire schemas advertised during peer
    /// negotiation. The handler receives the raw admitted invocation so the
    /// application remains explicit about its chosen serialization codec.
    pub fn register<I, O, F, Fut>(
        &mut self,
        name: impl Into<String>,
        handler: F,
    ) -> Result<(), ComputationSchemaRegistryError>
    where
        I: HasSchema,
        O: HasSchema,
        F: Fn(Cx, RemoteComputationInvocation) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RemoteOutcome, RemoteError>> + Send + 'static,
    {
        let name = name.into();
        self.schemas.register_typed::<I, O>(name.clone())?;
        let erased = move |cx: Cx,
                           invocation: RemoteComputationInvocation|
              -> RemoteComputationFuture { Box::pin(handler(cx, invocation)) };
        self.handlers.insert(name, Arc::new(erased));
        Ok(())
    }

    /// Schema registry that must be used to build the peer-admission policy.
    #[must_use]
    pub const fn schema_registry(&self) -> &ComputationSchemaRegistry {
        &self.schemas
    }

    /// Number of executable named computations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Returns true when no executable computation is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Authorizes and executes one named-computation request.
    ///
    /// No handler is invoked until the session capability accepts the name.
    /// The returned future is awaited inline and is never detached.
    pub async fn dispatch(
        &self,
        cx: &Cx,
        session: &RemotePeerSession,
        request: SpawnRequest,
    ) -> Result<RemoteOutcome, RemoteComputationDispatchError> {
        session
            .authorize_computation(&request.computation)
            .map_err(RemoteComputationDispatchError::Admission)?;
        let handler = self
            .handlers
            .get(request.computation.as_str())
            .ok_or_else(|| {
                RemoteComputationDispatchError::Execution(RemoteError::UnknownComputation(
                    request.computation.as_str().to_owned(),
                ))
            })?;
        let invocation = RemoteComputationInvocation {
            peer_node: session.peer_node().clone(),
            request,
        };
        handler(cx.clone(), invocation)
            .await
            .map_err(RemoteComputationDispatchError::Execution)
    }
}

/// Default maximum encoded request or response frame for the remote service.
pub const DEFAULT_REMOTE_SERVICE_MAX_FRAME_BYTES: usize = 64 * 1024;
/// Default deadline for an authenticated peer to send its first complete frame.
pub const DEFAULT_REMOTE_SERVICE_INITIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
/// Default V2/V3 terminal-outcome retention window for retry replay.
pub const DEFAULT_REMOTE_SERVICE_IDEMPOTENCY_RETENTION: Duration = Duration::from_secs(300);
/// Default V2/V3 retained/in-flight key cap per authenticated peer.
pub const DEFAULT_REMOTE_SERVICE_MAX_IDEMPOTENCY_RECORDS_PER_PEER: usize = 4096;

/// Bounded framing policy for one authenticated remote-service exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteServiceWireLimits {
    max_frame_bytes: usize,
}

impl RemoteServiceWireLimits {
    /// Creates a framing policy with the supplied encoded-frame limit.
    #[must_use]
    pub const fn new(max_frame_bytes: usize) -> Self {
        Self { max_frame_bytes }
    }

    /// Maximum encoded request or response bytes, excluding the length prefix.
    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }
}

impl Default for RemoteServiceWireLimits {
    fn default() -> Self {
        Self::new(DEFAULT_REMOTE_SERVICE_MAX_FRAME_BYTES)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RemoteServiceWireBudget {
    deadline_nanos: Option<u64>,
    poll_quota: u32,
    cost_quota: Option<u64>,
    priority: u8,
}

impl From<Budget> for RemoteServiceWireBudget {
    fn from(budget: Budget) -> Self {
        Self {
            deadline_nanos: budget.deadline.map(Time::as_nanos),
            poll_quota: budget.poll_quota,
            cost_quota: budget.cost_quota,
            priority: budget.priority,
        }
    }
}

impl From<RemoteServiceWireBudget> for Budget {
    fn from(budget: RemoteServiceWireBudget) -> Self {
        Self {
            deadline: budget.deadline_nanos.map(Time::from_nanos),
            poll_quota: budget.poll_quota,
            cost_quota: budget.cost_quota,
            priority: budget.priority,
        }
    }
}

/// Stable wire request for one authenticated named computation.
///
/// The authenticated origin is carried only in `hello`; the service rebuilds
/// [`SpawnRequest::origin_node`] from the admitted session instead of trusting
/// a second caller-controlled identity field. Runtime-local region and task IDs
/// retain their type-tagged serde representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteServiceWireRequest {
    hello: RemotePeerHello,
    remote_task_id: u64,
    computation: String,
    input: Vec<u8>,
    lease_secs: u64,
    lease_subsec_nanos: u32,
    idempotency_key_high: u64,
    idempotency_key_low: u64,
    budget: Option<RemoteServiceWireBudget>,
    origin_region: RegionId,
    origin_task: TaskId,
}

impl RemoteServiceWireRequest {
    /// Builds a wire request after checking the asserted hello identity agrees
    /// with the local spawn request.
    pub fn from_spawn_request(
        hello: RemotePeerHello,
        request: &SpawnRequest,
    ) -> Result<Self, RemoteComputationServiceError> {
        if hello.peer_node() != &request.origin_node {
            return Err(RemoteComputationServiceError::OriginIdentityMismatch {
                hello_peer: hello.peer_node().clone(),
                request_origin: request.origin_node.clone(),
            });
        }
        let idempotency_key = request.idempotency_key.raw();
        let idempotency_key_high = u64::try_from(idempotency_key >> 64)
            .expect("right-shifted u128 idempotency key fits u64");
        let idempotency_key_low = u64::try_from(idempotency_key & u128::from(u64::MAX))
            .expect("masked u128 idempotency key fits u64");
        Ok(Self {
            hello,
            remote_task_id: request.remote_task_id.raw(),
            computation: request.computation.as_str().to_owned(),
            input: request.input.data().to_vec(),
            lease_secs: request.lease.as_secs(),
            lease_subsec_nanos: request.lease.subsec_nanos(),
            idempotency_key_high,
            idempotency_key_low,
            budget: request.budget.map(Into::into),
            origin_region: request.origin_region,
            origin_task: request.origin_task,
        })
    }

    /// Peer negotiation metadata presented on the authenticated stream.
    #[must_use]
    pub const fn hello(&self) -> &RemotePeerHello {
        &self.hello
    }

    /// Correlation ID supplied by this delivery attempt.
    #[must_use]
    pub const fn remote_task_id(&self) -> RemoteTaskId {
        RemoteTaskId::from_raw(self.remote_task_id)
    }

    #[cfg(feature = "tls")]
    fn session_lease(&self) -> Option<Duration> {
        (self.lease_subsec_nanos < 1_000_000_000)
            .then(|| Duration::new(self.lease_secs, self.lease_subsec_nanos))
            .filter(|lease| !lease.is_zero())
    }

    #[cfg(feature = "tls")]
    fn into_spawn_request(self) -> Result<SpawnRequest, String> {
        if self.lease_subsec_nanos >= 1_000_000_000 {
            return Err(format!(
                "remote service lease nanoseconds must be below 1000000000, got {}",
                self.lease_subsec_nanos
            ));
        }
        let origin_node = self.hello.peer_node().clone();
        let idempotency_key =
            (u128::from(self.idempotency_key_high) << 64) | u128::from(self.idempotency_key_low);
        Ok(SpawnRequest {
            remote_task_id: RemoteTaskId::from_raw(self.remote_task_id),
            computation: ComputationName::new(self.computation),
            input: RemoteInput::new(self.input),
            lease: Duration::new(self.lease_secs, self.lease_subsec_nanos),
            idempotency_key: IdempotencyKey::from_raw(idempotency_key),
            budget: self.budget.map(Into::into),
            origin_node,
            origin_region: self.origin_region,
            origin_task: self.origin_task,
        })
    }
}

/// Stable terminal-outcome representation used by the remote-service adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", content = "value", rename_all = "snake_case")]
pub enum RemoteServiceWireOutcome {
    /// Handler returned serialized output bytes.
    Success(Vec<u8>),
    /// Handler returned an application failure.
    Failed(String),
    /// Handler completed through cancellation.
    Cancelled(CancelReason),
    /// Handler reported a panic boundary.
    Panicked(String),
}

impl From<RemoteOutcome> for RemoteServiceWireOutcome {
    fn from(outcome: RemoteOutcome) -> Self {
        match outcome {
            RemoteOutcome::Success(payload) => Self::Success(payload),
            RemoteOutcome::Failed(message) => Self::Failed(message),
            RemoteOutcome::Cancelled(reason) => Self::Cancelled(reason),
            RemoteOutcome::Panicked(message) => Self::Panicked(message),
        }
    }
}

impl From<RemoteServiceWireOutcome> for RemoteOutcome {
    fn from(outcome: RemoteServiceWireOutcome) -> Self {
        match outcome {
            RemoteServiceWireOutcome::Success(payload) => Self::Success(payload),
            RemoteServiceWireOutcome::Failed(message) => Self::Failed(message),
            RemoteServiceWireOutcome::Cancelled(reason) => Self::Cancelled(reason),
            RemoteServiceWireOutcome::Panicked(message) => Self::Panicked(message),
        }
    }
}

/// Machine-readable refusal category returned before a handler result exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemoteServiceRejectionCode {
    /// TLS identity, protocol version, registry identity, or peer grant failed.
    AdmissionDenied,
    /// The admission policy and executable handler registry do not match.
    ExecutableRegistryDrift,
    /// The admitted peer lacks capability for the requested computation.
    ComputationDenied,
    /// A decoded request contained invalid protocol field values.
    MalformedRequest,
    /// The selected handler returned a runtime execution error.
    ExecutionFailed,
    /// V2/V3 semantics were requested from an adapter lacking required lifecycle state.
    LifecycleUnavailable,
    /// Matching authenticated-peer request is still executing ambiguously.
    OperationInFlight,
    /// The authenticated peer reused a key for different computation input.
    IdempotencyConflict,
    /// The authenticated peer exhausted its bounded retained-key capacity.
    IdempotencyCapacity,
}

/// One fully flushed outcome or fail-closed refusal from the remote service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum RemoteServiceWireResponse {
    /// Authorized handler reached a terminal outcome.
    Outcome {
        /// Correlation ID supplied by the request.
        remote_task_id: u64,
        /// Serialized terminal outcome.
        outcome: RemoteServiceWireOutcome,
    },
    /// Request was refused before a terminal handler outcome existed.
    Rejected {
        /// Correlation ID supplied by the request.
        remote_task_id: u64,
        /// Stable rejection category.
        code: RemoteServiceRejectionCode,
        /// Human-readable diagnostic; callers must branch on `code`.
        diagnostic: String,
    },
}

impl RemoteServiceWireResponse {
    /// Correlation ID supplied by the request.
    #[must_use]
    pub const fn remote_task_id(&self) -> RemoteTaskId {
        let raw = match self {
            Self::Outcome { remote_task_id, .. } | Self::Rejected { remote_task_id, .. } => {
                *remote_task_id
            }
        };
        RemoteTaskId::from_raw(raw)
    }
}

/// Authenticated lifecycle command for one protocol V3 computation session.
///
/// Commands intentionally omit peer identity and idempotency data: the initial
/// request and its mutually authenticated TLS connection are the authority.
#[cfg(feature = "tls")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemoteServiceSessionCommand {
    /// Cancel the active computation with an attributed reason.
    Cancel {
        /// Active task correlation ID.
        remote_task_id: u64,
        /// Caller-supplied cancellation reason.
        reason: CancelReason,
    },
    /// Replace the active lease with a duration measured from receipt.
    RenewLease {
        /// Active task correlation ID.
        remote_task_id: u64,
        /// Strictly increasing command sequence number.
        renewal_id: u64,
        /// Whole seconds in the requested lease.
        lease_secs: u64,
        /// Subsecond nanoseconds in the requested lease.
        lease_subsec_nanos: u32,
    },
}

#[cfg(feature = "tls")]
impl RemoteServiceSessionCommand {
    /// Correlation ID for the active computation.
    #[must_use]
    pub const fn remote_task_id(&self) -> RemoteTaskId {
        let raw = match self {
            Self::Cancel { remote_task_id, .. } | Self::RenewLease { remote_task_id, .. } => {
                *remote_task_id
            }
        };
        RemoteTaskId::from_raw(raw)
    }
}

/// Server event emitted by a protocol V3 computation session.
#[cfg(feature = "tls")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemoteServiceSessionEvent {
    /// The operation is admitted and its child task is session-owned.
    Accepted {
        /// Active task correlation ID.
        remote_task_id: u64,
    },
    /// A numbered lease renewal became the active deadline.
    LeaseRenewed {
        /// Active task correlation ID.
        remote_task_id: u64,
        /// Command sequence number being acknowledged.
        renewal_id: u64,
        /// Whole seconds in the granted lease.
        lease_secs: u64,
        /// Subsecond nanoseconds in the granted lease.
        lease_subsec_nanos: u32,
    },
    /// A control frame was refused without mutating the active computation.
    CommandRejected {
        /// Correlation ID presented by the refused command.
        remote_task_id: u64,
        /// Renewal sequence number, when the command was a renewal.
        renewal_id: Option<u64>,
        /// Stable human-readable refusal diagnostic.
        diagnostic: String,
    },
    /// The operation reached its only terminal response.
    Terminal {
        /// Existing V1/V2 terminal representation, kept byte-stable itself.
        response: RemoteServiceWireResponse,
    },
}

#[cfg(feature = "tls")]
impl RemoteServiceSessionEvent {
    /// Correlation ID for the active computation.
    #[must_use]
    pub const fn remote_task_id(&self) -> RemoteTaskId {
        match self {
            Self::Accepted { remote_task_id }
            | Self::LeaseRenewed { remote_task_id, .. }
            | Self::CommandRejected { remote_task_id, .. } => {
                RemoteTaskId::from_raw(*remote_task_id)
            }
            Self::Terminal { response } => response.remote_task_id(),
        }
    }
}

#[cfg(feature = "tls")]
#[derive(Clone, Debug)]
struct CachedExecutionRejection {
    canonical_task_id: RemoteTaskId,
    diagnostic: String,
    expires_at: Time,
}

#[cfg(feature = "tls")]
struct RemoteServicePeerIdempotency {
    store: IdempotencyStore,
    execution_rejections: DetHashMap<IdempotencyKey, CachedExecutionRejection>,
}

#[cfg(feature = "tls")]
impl RemoteServicePeerIdempotency {
    fn new(retention: Duration) -> Self {
        Self {
            store: IdempotencyStore::new(retention),
            execution_rejections: DetHashMap::default(),
        }
    }

    fn evict_expired(&mut self, now: Time) {
        let _ = self.store.evict_expired(now);
        self.execution_rejections
            .retain(|_, rejection| now < rejection.expires_at);
    }
}

#[cfg(feature = "tls")]
struct RemoteServiceIdempotencyInner {
    peers: BTreeMap<NodeId, RemoteServicePeerIdempotency>,
}

#[cfg(feature = "tls")]
struct RemoteServiceIdempotency {
    inner: Mutex<RemoteServiceIdempotencyInner>,
    retention: Duration,
    max_records_per_peer: usize,
}

#[cfg(feature = "tls")]
enum RemoteServiceIdempotencyAdmission {
    Execute,
    CachedOutcome(RemoteOutcome),
    CachedExecutionRejection(String),
    InFlight,
    Conflict,
    Capacity,
}

#[cfg(feature = "tls")]
impl RemoteServiceIdempotency {
    fn new(retention: Duration, max_records_per_peer: usize) -> Self {
        Self {
            inner: Mutex::new(RemoteServiceIdempotencyInner {
                peers: BTreeMap::new(),
            }),
            retention,
            max_records_per_peer,
        }
    }

    fn admit(
        &self,
        peer: &NodeId,
        request: &SpawnRequest,
        now: Time,
    ) -> RemoteServiceIdempotencyAdmission {
        let mut inner = self.inner.lock();
        let peer_state = inner
            .peers
            .entry(peer.clone())
            .or_insert_with(|| RemoteServicePeerIdempotency::new(self.retention));
        peer_state.evict_expired(now);

        let key = request.idempotency_key;
        if !peer_state.store.entries.contains_key(&key)
            && peer_state.store.len() >= self.max_records_per_peer
        {
            return RemoteServiceIdempotencyAdmission::Capacity;
        }

        let remote_task_id = request.remote_task_id;
        let fingerprint = IdempotencyRequestFingerprint::from_spawn_request(request);
        match peer_state
            .store
            .check_and_record(key, remote_task_id, fingerprint, now)
        {
            DedupDecision::New => RemoteServiceIdempotencyAdmission::Execute,
            DedupDecision::Conflict => RemoteServiceIdempotencyAdmission::Conflict,
            DedupDecision::Duplicate(record) => {
                let Some(outcome) = record.outcome else {
                    return RemoteServiceIdempotencyAdmission::InFlight;
                };
                if let Some(rejection) = peer_state.execution_rejections.get(&key)
                    && rejection.canonical_task_id == record.remote_task_id
                    && now < rejection.expires_at
                {
                    return RemoteServiceIdempotencyAdmission::CachedExecutionRejection(
                        rejection.diagnostic.clone(),
                    );
                }
                RemoteServiceIdempotencyAdmission::CachedOutcome(outcome)
            }
        }
    }

    fn complete_outcome(
        &self,
        peer: &NodeId,
        key: IdempotencyKey,
        canonical_task_id: RemoteTaskId,
        outcome: RemoteOutcome,
        now: Time,
    ) -> bool {
        let mut inner = self.inner.lock();
        let Some(peer_state) = inner.peers.get_mut(peer) else {
            return false;
        };
        peer_state
            .store
            .complete(&key, canonical_task_id, outcome, now)
    }

    fn complete_execution_rejection(
        &self,
        peer: &NodeId,
        key: IdempotencyKey,
        canonical_task_id: RemoteTaskId,
        diagnostic: String,
        now: Time,
    ) -> bool {
        let mut inner = self.inner.lock();
        let Some(peer_state) = inner.peers.get_mut(peer) else {
            return false;
        };
        let completed = peer_state.store.complete(
            &key,
            canonical_task_id,
            RemoteOutcome::Failed(diagnostic.clone()),
            now,
        );
        if completed {
            peer_state.execution_rejections.insert(
                key,
                CachedExecutionRejection {
                    canonical_task_id,
                    diagnostic,
                    expires_at: now + self.retention,
                },
            );
        }
        completed
    }
}

/// Local failure while constructing or transporting a remote-service exchange.
#[derive(Debug)]
pub enum RemoteComputationServiceError {
    /// A zero-byte frame limit cannot admit any encoded request.
    InvalidFrameLimit,
    /// Client hello and spawn metadata asserted different logical origins.
    OriginIdentityMismatch {
        /// Origin asserted by the peer hello.
        hello_peer: NodeId,
        /// Origin carried by the spawn request.
        request_origin: NodeId,
    },
    /// Established transport failed while reading or fully flushing a frame.
    Transport(io::Error),
    /// Tagged request or response could not be serialized or decoded.
    Serialization(serde_json::Error),
    /// An encoded outbound frame exceeded the configured byte limit.
    FrameTooLarge {
        /// Maximum encoded bytes permitted for this exchange.
        max_frame_bytes: usize,
    },
    /// Peer closed the stream before one complete frame arrived.
    UnexpectedEof,
    /// Authenticated peer did not send one complete initial request in time.
    InitialFrameTimeout {
        /// Configured bound for the first framed request.
        timeout: Duration,
    },
    /// Listener-owned V2/V3 state disappeared before terminal publication.
    IdempotencyStateLost,
}

impl fmt::Display for RemoteComputationServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFrameLimit => write!(f, "remote service frame limit must be nonzero"),
            Self::OriginIdentityMismatch {
                hello_peer,
                request_origin,
            } => write!(
                f,
                "remote service origin mismatch: hello {hello_peer}, request {request_origin}"
            ),
            Self::Transport(error) => write!(f, "remote service transport error: {error}"),
            Self::Serialization(error) => {
                write!(f, "remote service serialization error: {error}")
            }
            Self::FrameTooLarge { max_frame_bytes } => write!(
                f,
                "remote service encoded frame exceeds {max_frame_bytes}-byte limit"
            ),
            Self::UnexpectedEof => write!(f, "remote service peer closed before a complete frame"),
            Self::InitialFrameTimeout { timeout } => write!(
                f,
                "remote service peer did not send an initial frame within {timeout:?}"
            ),
            Self::IdempotencyStateLost => {
                write!(f, "remote service idempotency state lost before completion")
            }
        }
    }
}

impl std::error::Error for RemoteComputationServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::InvalidFrameLimit
            | Self::OriginIdentityMismatch { .. }
            | Self::FrameTooLarge { .. }
            | Self::UnexpectedEof
            | Self::InitialFrameTimeout { .. }
            | Self::IdempotencyStateLost => None,
        }
    }
}

#[cfg(feature = "tls")]
struct RemoteServiceFrameWriter {
    encoded: Vec<u8>,
    max_frame_bytes: usize,
    exceeded: bool,
}

#[cfg(feature = "tls")]
impl RemoteServiceFrameWriter {
    fn new(max_frame_bytes: usize) -> Self {
        Self {
            encoded: Vec::new(),
            max_frame_bytes,
            exceeded: false,
        }
    }

    fn into_encoded(self) -> Vec<u8> {
        self.encoded
    }
}

#[cfg(feature = "tls")]
impl io::Write for RemoteServiceFrameWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.max_frame_bytes.saturating_sub(self.encoded.len()) {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "remote service encoded frame exceeds configured limit",
            ));
        }
        self.encoded.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "tls")]
fn remote_service_framed<IO>(
    stream: IO,
    limits: RemoteServiceWireLimits,
) -> Result<Framed<IO, LengthDelimitedCodec>, RemoteComputationServiceError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if limits.max_frame_bytes == 0 {
        return Err(RemoteComputationServiceError::InvalidFrameLimit);
    }
    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(limits.max_frame_bytes)
        .big_endian()
        .new_codec();
    Ok(Framed::new(stream, codec).with_max_buffer_len(limits.max_frame_bytes.saturating_add(4)))
}

#[cfg(feature = "tls")]
async fn read_remote_service_frame<T, IO>(
    _cx: &Cx,
    framed: &mut Framed<IO, LengthDelimitedCodec>,
) -> Result<T, RemoteComputationServiceError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    T: DeserializeOwned,
{
    let frame = framed
        .next()
        .await
        .ok_or(RemoteComputationServiceError::UnexpectedEof)?
        .map_err(RemoteComputationServiceError::Transport)?;
    serde_json::from_slice(&frame).map_err(RemoteComputationServiceError::Serialization)
}

#[cfg(feature = "tls")]
fn encode_remote_service_frame<T>(
    value: &T,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, RemoteComputationServiceError>
where
    T: Serialize + ?Sized,
{
    let mut writer = RemoteServiceFrameWriter::new(max_frame_bytes);
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        if writer.exceeded {
            return Err(RemoteComputationServiceError::FrameTooLarge { max_frame_bytes });
        }
        return Err(RemoteComputationServiceError::Serialization(error));
    }
    Ok(writer.into_encoded())
}

#[cfg(feature = "tls")]
async fn send_remote_service_frame<IO>(
    _cx: &Cx,
    framed: &mut Framed<IO, LengthDelimitedCodec>,
    encoded: &[u8],
) -> Result<(), RemoteComputationServiceError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    framed
        .send(BytesMut::from(encoded))
        .map_err(RemoteComputationServiceError::Transport)?;
    std::future::poll_fn(|task_cx| framed.poll_flush(task_cx))
        .await
        .map_err(RemoteComputationServiceError::Transport)
}

#[cfg(feature = "tls")]
async fn write_remote_service_frame<T, IO>(
    cx: &Cx,
    framed: &mut Framed<IO, LengthDelimitedCodec>,
    value: &T,
    max_frame_bytes: usize,
) -> Result<(), RemoteComputationServiceError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let encoded = encode_remote_service_frame(value, max_frame_bytes)?;
    send_remote_service_frame(cx, framed, &encoded).await
}

/// Protocol or transport failure while driving one V3 computation session.
#[cfg(feature = "tls")]
#[derive(Debug)]
#[non_exhaustive]
pub enum RemoteServiceSessionError {
    /// A session was started with a request that did not negotiate V3.
    WrongProtocol {
        /// Protocol version supplied by the request.
        presented: RemoteProtocolVersion,
    },
    /// A renewal duration was zero or otherwise not representable on the wire.
    InvalidLease,
    /// The peer emitted an event that is invalid at the current session phase.
    UnexpectedEvent {
        /// Event kind required by the current operation.
        expected: &'static str,
    },
    /// A command or event referred to a different task on the authenticated stream.
    TaskMismatch {
        /// Active task ID.
        expected: u64,
        /// Received task ID.
        actual: u64,
    },
    /// A renewal acknowledgement did not match the outstanding command.
    RenewalMismatch {
        /// Outstanding renewal sequence number.
        expected: u64,
        /// Received renewal sequence number.
        actual: u64,
    },
    /// A renewal acknowledgement changed the requested lease duration.
    RenewalLeaseMismatch {
        /// Duration sent by the client.
        expected: Duration,
        /// Duration echoed by the server.
        actual: Duration,
    },
    /// Every strictly increasing renewal sequence number has been used.
    RenewalSequenceExhausted,
    /// The caller context was cancelled while session I/O was pending.
    Cancelled,
    /// A prior terminal error already closed the session transport.
    SessionEnded,
    /// Framing, serialization, or transport failed.
    Service(RemoteComputationServiceError),
}

#[cfg(feature = "tls")]
impl fmt::Display for RemoteServiceSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongProtocol { presented } => {
                write!(
                    f,
                    "remote computation session requires protocol V3, got {presented}"
                )
            }
            Self::InvalidLease => write!(f, "remote computation session lease must be nonzero"),
            Self::UnexpectedEvent { expected } => {
                write!(f, "remote computation session expected {expected}")
            }
            Self::TaskMismatch { expected, actual } => write!(
                f,
                "remote computation session task mismatch: expected {expected}, got {actual}"
            ),
            Self::RenewalMismatch { expected, actual } => write!(
                f,
                "remote computation session renewal mismatch: expected {expected}, got {actual}"
            ),
            Self::RenewalLeaseMismatch { expected, actual } => write!(
                f,
                "remote computation session renewal lease mismatch: expected {expected:?}, got {actual:?}"
            ),
            Self::RenewalSequenceExhausted => {
                write!(
                    f,
                    "remote computation session renewal sequence is exhausted"
                )
            }
            Self::Cancelled => write!(f, "remote computation session caller was cancelled"),
            Self::SessionEnded => write!(f, "remote computation session already ended"),
            Self::Service(error) => write!(f, "remote computation session I/O failed: {error}"),
        }
    }
}

#[cfg(feature = "tls")]
impl std::error::Error for RemoteServiceSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Service(error) => Some(error),
            Self::WrongProtocol { .. }
            | Self::InvalidLease
            | Self::UnexpectedEvent { .. }
            | Self::TaskMismatch { .. }
            | Self::RenewalMismatch { .. }
            | Self::RenewalLeaseMismatch { .. }
            | Self::RenewalSequenceExhausted
            | Self::Cancelled
            | Self::SessionEnded => None,
        }
    }
}

#[cfg(feature = "tls")]
impl From<RemoteComputationServiceError> for RemoteServiceSessionError {
    fn from(error: RemoteComputationServiceError) -> Self {
        Self::Service(error)
    }
}

/// Result of starting one V3 computation on an authenticated stream.
#[cfg(feature = "tls")]
#[non_exhaustive]
pub enum RemoteComputationSessionStart<IO> {
    /// The server admitted the request and now owns its running child task.
    Running(RemoteComputationSession<IO>),
    /// The request reached a terminal response without starting a live session.
    Terminal(RemoteServiceWireResponse),
}

#[cfg(feature = "tls")]
enum RemoteSessionIoRace<T> {
    Completed(T),
    Cancelled,
}

#[cfg(feature = "tls")]
async fn remote_session_wait_for_cancellation(cx: &Cx) {
    if cx.checkpoint().is_err() {
        return;
    }
    let (sender, mut receiver) = oneshot::channel::<()>();
    let _ = receiver.recv(cx).await;
    drop(sender);
}

#[cfg(feature = "tls")]
async fn remote_session_race_io<F>(cx: &Cx, future: F) -> RemoteSessionIoRace<F::Output>
where
    F: Future,
{
    futures_lite::future::race(
        async { RemoteSessionIoRace::Completed(future.await) },
        async {
            remote_session_wait_for_cancellation(cx).await;
            RemoteSessionIoRace::Cancelled
        },
    )
    .await
}

/// One active V3 remote computation bound to one authenticated transport.
///
/// The value owns its framed transport, preventing two operations from sharing
/// a connection or losing decoder-buffered bytes between lifecycle messages.
/// Session I/O remains pending through server-side lease-expiry cleanup so the
/// caller can receive the canonical drained terminal; caller-context
/// cancellation is the explicit transport bound and drops the connection.
#[cfg(feature = "tls")]
pub struct RemoteComputationSession<IO> {
    framed: Option<Framed<IO, LengthDelimitedCodec>>,
    remote_task_id: RemoteTaskId,
    max_frame_bytes: usize,
    next_renewal_id: Option<u64>,
}

#[cfg(feature = "tls")]
impl<IO> fmt::Debug for RemoteComputationSession<IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteComputationSession")
            .field("remote_task_id", &self.remote_task_id)
            .field("max_frame_bytes", &self.max_frame_bytes)
            .field("next_renewal_id", &self.next_renewal_id)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "tls")]
impl<IO> RemoteComputationSession<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Starts one V3 operation over an already-authenticated transport.
    pub async fn start(
        cx: &Cx,
        transport: IO,
        request: &RemoteServiceWireRequest,
        limits: RemoteServiceWireLimits,
    ) -> Result<RemoteComputationSessionStart<IO>, RemoteServiceSessionError> {
        let presented = request.hello().protocol_version();
        if presented != RemoteProtocolVersion::V3 {
            return Err(RemoteServiceSessionError::WrongProtocol { presented });
        }
        if request.session_lease().is_none() {
            return Err(RemoteServiceSessionError::InvalidLease);
        }
        let remote_task_id = request.remote_task_id();
        let mut framed = remote_service_framed(transport, limits)?;
        let exchange = remote_session_race_io(cx, async {
            write_remote_service_frame(cx, &mut framed, request, limits.max_frame_bytes()).await?;
            read_remote_service_frame(cx, &mut framed).await
        })
        .await;
        let event: RemoteServiceSessionEvent = match exchange {
            RemoteSessionIoRace::Completed(result) => result?,
            RemoteSessionIoRace::Cancelled => return Err(RemoteServiceSessionError::Cancelled),
        };
        Self::validate_task(remote_task_id, &event)?;
        match event {
            RemoteServiceSessionEvent::Accepted { .. } => {
                Ok(RemoteComputationSessionStart::Running(Self {
                    framed: Some(framed),
                    remote_task_id,
                    max_frame_bytes: limits.max_frame_bytes(),
                    next_renewal_id: Some(1),
                }))
            }
            RemoteServiceSessionEvent::Terminal { response } => {
                Ok(RemoteComputationSessionStart::Terminal(response))
            }
            RemoteServiceSessionEvent::LeaseRenewed { .. } => {
                Err(RemoteServiceSessionError::UnexpectedEvent {
                    expected: "accepted or terminal event",
                })
            }
            RemoteServiceSessionEvent::CommandRejected { .. } => {
                Err(RemoteServiceSessionError::UnexpectedEvent {
                    expected: "accepted or terminal event",
                })
            }
        }
    }

    /// Active task correlation ID.
    #[must_use]
    pub const fn remote_task_id(&self) -> RemoteTaskId {
        self.remote_task_id
    }

    /// Renews the lease relative to server receipt time.
    ///
    /// A terminal event means completion or expiry won the race before the
    /// renewal was applied. The returned event is always task-correlated.
    pub async fn renew_lease(
        &mut self,
        cx: &Cx,
        lease: Duration,
    ) -> Result<RemoteServiceSessionEvent, RemoteServiceSessionError> {
        if lease.is_zero() {
            return Err(RemoteServiceSessionError::InvalidLease);
        }
        let renewal_id = self
            .next_renewal_id
            .ok_or(RemoteServiceSessionError::RenewalSequenceExhausted)?;
        let command = RemoteServiceSessionCommand::RenewLease {
            remote_task_id: self.remote_task_id.raw(),
            renewal_id,
            lease_secs: lease.as_secs(),
            lease_subsec_nanos: lease.subsec_nanos(),
        };
        let event = self.exchange_event(cx, Some(&command)).await?;
        if let Err(error) = Self::validate_task(self.remote_task_id, &event) {
            self.framed.take();
            return Err(error);
        }
        match &event {
            RemoteServiceSessionEvent::LeaseRenewed {
                renewal_id: actual, ..
            } if *actual != renewal_id => {
                self.framed.take();
                return Err(RemoteServiceSessionError::RenewalMismatch {
                    expected: renewal_id,
                    actual: *actual,
                });
            }
            RemoteServiceSessionEvent::LeaseRenewed {
                lease_secs,
                lease_subsec_nanos,
                ..
            } => {
                if *lease_subsec_nanos >= 1_000_000_000 {
                    self.framed.take();
                    return Err(RemoteServiceSessionError::UnexpectedEvent {
                        expected: "lease-renewed event with valid nanoseconds",
                    });
                }
                let actual = Duration::new(*lease_secs, *lease_subsec_nanos);
                if actual != lease {
                    self.framed.take();
                    return Err(RemoteServiceSessionError::RenewalLeaseMismatch {
                        expected: lease,
                        actual,
                    });
                }
                self.next_renewal_id = renewal_id.checked_add(1);
            }
            RemoteServiceSessionEvent::Terminal { .. } => {
                self.framed.take();
            }
            RemoteServiceSessionEvent::CommandRejected { .. } => {}
            RemoteServiceSessionEvent::Accepted { .. } => {
                self.framed.take();
                return Err(RemoteServiceSessionError::UnexpectedEvent {
                    expected: "lease-renewed, command-rejected, or terminal event",
                });
            }
        }
        Ok(event)
    }

    /// Cancels the active task and waits for its drained terminal response.
    pub async fn cancel(
        mut self,
        cx: &Cx,
        reason: CancelReason,
    ) -> Result<RemoteServiceWireResponse, RemoteServiceSessionError> {
        let command = RemoteServiceSessionCommand::Cancel {
            remote_task_id: self.remote_task_id.raw(),
            reason,
        };
        let event = self.exchange_event(cx, Some(&command)).await?;
        self.into_terminal(event)
    }

    /// Waits for handler completion or lease expiry.
    pub async fn wait(
        mut self,
        cx: &Cx,
    ) -> Result<RemoteServiceWireResponse, RemoteServiceSessionError> {
        let event = self
            .exchange_event::<RemoteServiceSessionCommand>(cx, None)
            .await?;
        self.into_terminal(event)
    }

    async fn exchange_event<T>(
        &mut self,
        cx: &Cx,
        command: Option<&T>,
    ) -> Result<RemoteServiceSessionEvent, RemoteServiceSessionError>
    where
        T: Serialize + ?Sized,
    {
        let framed = self
            .framed
            .as_mut()
            .ok_or(RemoteServiceSessionError::SessionEnded)?;
        let exchange = remote_session_race_io(cx, async {
            if let Some(command) = command {
                write_remote_service_frame(cx, framed, command, self.max_frame_bytes).await?;
            }
            read_remote_service_frame(cx, framed).await
        })
        .await;
        match exchange {
            RemoteSessionIoRace::Completed(Ok(event)) => Ok(event),
            RemoteSessionIoRace::Completed(Err(error)) => {
                self.framed.take();
                Err(RemoteServiceSessionError::Service(error))
            }
            RemoteSessionIoRace::Cancelled => {
                self.framed.take();
                Err(RemoteServiceSessionError::Cancelled)
            }
        }
    }

    fn into_terminal(
        mut self,
        event: RemoteServiceSessionEvent,
    ) -> Result<RemoteServiceWireResponse, RemoteServiceSessionError> {
        Self::validate_task(self.remote_task_id, &event)?;
        self.framed.take();
        match event {
            RemoteServiceSessionEvent::Terminal { response } => Ok(response),
            RemoteServiceSessionEvent::Accepted { .. }
            | RemoteServiceSessionEvent::LeaseRenewed { .. }
            | RemoteServiceSessionEvent::CommandRejected { .. } => {
                Err(RemoteServiceSessionError::UnexpectedEvent {
                    expected: "terminal event",
                })
            }
        }
    }

    fn validate_task(
        expected: RemoteTaskId,
        event: &RemoteServiceSessionEvent,
    ) -> Result<(), RemoteServiceSessionError> {
        let actual = event.remote_task_id();
        if actual != expected {
            return Err(RemoteServiceSessionError::TaskMismatch {
                expected: expected.raw(),
                actual: actual.raw(),
            });
        }
        Ok(())
    }
}

#[cfg(feature = "tls")]
enum RemoteServiceTerminalCommit {
    Outcome {
        peer: NodeId,
        key: IdempotencyKey,
        canonical_task_id: RemoteTaskId,
        outcome: RemoteOutcome,
    },
    ExecutionRejection {
        peer: NodeId,
        key: IdempotencyKey,
        canonical_task_id: RemoteTaskId,
        diagnostic: String,
    },
}

#[cfg(feature = "tls")]
impl RemoteServiceTerminalCommit {
    fn complete(self, state: &RemoteServiceIdempotency, now: Time) -> bool {
        match self {
            Self::Outcome {
                peer,
                key,
                canonical_task_id,
                outcome,
            } => state.complete_outcome(&peer, key, canonical_task_id, outcome, now),
            Self::ExecutionRejection {
                peer,
                key,
                canonical_task_id,
                diagnostic,
            } => state.complete_execution_rejection(&peer, key, canonical_task_id, diagnostic, now),
        }
    }

    fn into_encoding_rejection(self, diagnostic: String) -> Self {
        let (peer, key, canonical_task_id) = match self {
            Self::Outcome {
                peer,
                key,
                canonical_task_id,
                ..
            }
            | Self::ExecutionRejection {
                peer,
                key,
                canonical_task_id,
                ..
            } => (peer, key, canonical_task_id),
        };
        Self::ExecutionRejection {
            peer,
            key,
            canonical_task_id,
            diagnostic,
        }
    }
}

#[cfg(feature = "tls")]
fn remote_service_prepare_terminal_encoding(
    mut response: RemoteServiceWireResponse,
    mut commit: Option<RemoteServiceTerminalCommit>,
    max_frame_bytes: usize,
    session_envelope: bool,
) -> (
    RemoteServiceWireResponse,
    Option<RemoteServiceTerminalCommit>,
    Result<Vec<u8>, RemoteComputationServiceError>,
) {
    let encode = |response: &RemoteServiceWireResponse| {
        if session_envelope {
            encode_remote_service_frame(
                &RemoteServiceSessionEvent::Terminal {
                    response: response.clone(),
                },
                max_frame_bytes,
            )
        } else {
            encode_remote_service_frame(response, max_frame_bytes)
        }
    };
    let mut encoded = encode(&response);
    if encoded.is_err()
        && let Some(pending) = commit.take()
    {
        let diagnostic =
            "remote computation terminal exceeded the configured wire frame limit".to_owned();
        response = RemoteServiceWireResponse::Rejected {
            remote_task_id: response.remote_task_id().raw(),
            code: RemoteServiceRejectionCode::ExecutionFailed,
            diagnostic: diagnostic.clone(),
        };
        commit = Some(pending.into_encoding_rejection(diagnostic));
        encoded = encode(&response);
    }
    (response, commit, encoded)
}

#[cfg(feature = "tls")]
trait RemoteServiceResponseExt {
    fn with_no_commit(self) -> (Self, Option<RemoteServiceTerminalCommit>)
    where
        Self: Sized;
}

#[cfg(feature = "tls")]
impl RemoteServiceResponseExt for RemoteServiceWireResponse {
    fn with_no_commit(self) -> (Self, Option<RemoteServiceTerminalCommit>) {
        (self, None)
    }
}

#[cfg(feature = "tls")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemoteServiceExecutionMode {
    Inline,
    #[cfg(not(target_arch = "wasm32"))]
    LeaseBound,
}

#[cfg(feature = "tls")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemoteServiceProtocolKind {
    V1OneShot,
    V2Idempotent,
    V3Session,
    Unsupported,
}

#[cfg(feature = "tls")]
const fn remote_service_protocol_kind(version: RemoteProtocolVersion) -> RemoteServiceProtocolKind {
    if version.major == RemoteProtocolVersion::V1.major
        && version.minor == RemoteProtocolVersion::V1.minor
    {
        RemoteServiceProtocolKind::V1OneShot
    } else if version.major == RemoteProtocolVersion::V2.major
        && version.minor == RemoteProtocolVersion::V2.minor
    {
        RemoteServiceProtocolKind::V2Idempotent
    } else if version.major == RemoteProtocolVersion::V3.major
        && version.minor == RemoteProtocolVersion::V3.minor
    {
        RemoteServiceProtocolKind::V3Session
    } else {
        RemoteServiceProtocolKind::Unsupported
    }
}

#[cfg(feature = "tls")]
impl RemoteServiceExecutionMode {
    const fn enforces_request_lease(self) -> bool {
        match self {
            Self::Inline => false,
            #[cfg(not(target_arch = "wasm32"))]
            Self::LeaseBound => true,
        }
    }
}

/// Executes one bounded authenticated named computation over established TLS.
///
/// The caller owns the TLS handshake and the connection lifetime. This adapter
/// reads exactly one length-delimited tagged request, binds its hello to the
/// verified peer certificate, refuses policy/handler-registry drift, awaits the
/// selected handler inline under `cx`, and returns only after its tagged response
/// is fully flushed. It never spawns or detaches work. This one-shot adapter
/// accepts V1 only; it refuses V2 because it does not own shared listener
/// idempotency state and refuses V3 because it does not own a lifecycle
/// session. Unknown versions also fail closed instead of inheriting V1
/// semantics. V1 callers must not retry an ambiguous delivery as an
/// exactly-once lifecycle service.
#[cfg(feature = "tls")]
pub async fn serve_tls_computation_once<IO>(
    cx: &Cx,
    stream: &mut crate::tls::TlsStream<IO>,
    policy: &RemotePeerAdmissionPolicy,
    computations: &RemoteComputationRegistry,
    limits: RemoteServiceWireLimits,
) -> Result<RemoteServiceWireResponse, RemoteComputationServiceError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    serve_tls_computation_once_with_idempotency(
        cx,
        stream,
        policy,
        computations,
        limits,
        None,
        RemoteServiceExecutionMode::Inline,
        None,
    )
    .await
}

#[cfg(feature = "tls")]
async fn serve_tls_computation_once_with_idempotency<IO>(
    cx: &Cx,
    stream: &mut crate::tls::TlsStream<IO>,
    policy: &RemotePeerAdmissionPolicy,
    computations: &RemoteComputationRegistry,
    limits: RemoteServiceWireLimits,
    idempotency: Option<&RemoteServiceIdempotency>,
    execution_mode: RemoteServiceExecutionMode,
    initial_frame_timeout: Option<Duration>,
) -> Result<RemoteServiceWireResponse, RemoteComputationServiceError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut framed = remote_service_framed(stream, limits)?;
    let wire_request: RemoteServiceWireRequest = if let Some(timeout) = initial_frame_timeout {
        match crate::time::timeout(
            cx.now(),
            timeout,
            read_remote_service_frame(cx, &mut framed),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => return Err(RemoteComputationServiceError::InitialFrameTimeout { timeout }),
        }
    } else {
        read_remote_service_frame(cx, &mut framed).await?
    };
    let remote_task_id = wire_request.remote_task_id;
    let uses_v3_session_envelope = execution_mode == RemoteServiceExecutionMode::LeaseBound
        && wire_request.hello().protocol_version() == RemoteProtocolVersion::V3;
    let (response, terminal_commit) = match policy
        .admit_tls_peer(wire_request.hello(), &**framed.get_ref())
    {
        Err(error) => RemoteServiceWireResponse::Rejected {
            remote_task_id,
            code: RemoteServiceRejectionCode::AdmissionDenied,
            diagnostic: error.to_string(),
        }
        .with_no_commit(),
        Ok(session)
            if session.registry_fingerprint() != computations.schema_registry().fingerprint() =>
        {
            RemoteServiceWireResponse::Rejected {
                remote_task_id,
                code: RemoteServiceRejectionCode::ExecutableRegistryDrift,
                diagnostic: "admission policy registry differs from executable registry".to_owned(),
            }
            .with_no_commit()
        }
        Ok(session) => match wire_request.into_spawn_request() {
            Err(diagnostic) => RemoteServiceWireResponse::Rejected {
                remote_task_id,
                code: RemoteServiceRejectionCode::MalformedRequest,
                diagnostic,
            }
            .with_no_commit(),
            Ok(request) => {
                if remote_service_protocol_kind(session.protocol_version())
                    == RemoteServiceProtocolKind::V3Session
                    && execution_mode == RemoteServiceExecutionMode::LeaseBound
                {
                    let state =
                        idempotency.ok_or(RemoteComputationServiceError::IdempotencyStateLost)?;
                    return serve_tls_computation_v3_session(
                        cx,
                        &mut framed,
                        &session,
                        computations,
                        request,
                        state,
                        limits.max_frame_bytes(),
                    )
                    .await;
                }
                remote_service_dispatch_with_idempotency(
                    cx,
                    &session,
                    computations,
                    request,
                    idempotency,
                    execution_mode,
                )
                .await
            }
        },
    };
    let (response, terminal_commit, encoded) = remote_service_prepare_terminal_encoding(
        response,
        terminal_commit,
        limits.max_frame_bytes(),
        uses_v3_session_envelope,
    );
    if let Some(commit) = terminal_commit
        && !commit.complete(
            idempotency.ok_or(RemoteComputationServiceError::IdempotencyStateLost)?,
            cx.now(),
        )
    {
        return Err(RemoteComputationServiceError::IdempotencyStateLost);
    }
    let encoded = encoded?;
    send_remote_service_frame(cx, &mut framed, &encoded).await?;
    Ok(response)
}

#[cfg(feature = "tls")]
async fn remote_service_dispatch_with_idempotency(
    cx: &Cx,
    session: &RemotePeerSession,
    computations: &RemoteComputationRegistry,
    request: SpawnRequest,
    idempotency: Option<&RemoteServiceIdempotency>,
    execution_mode: RemoteServiceExecutionMode,
) -> (
    RemoteServiceWireResponse,
    Option<RemoteServiceTerminalCommit>,
) {
    let remote_task_id = request.remote_task_id;
    if let Err(error) = session.authorize_computation(&request.computation) {
        return RemoteServiceWireResponse::Rejected {
            remote_task_id: remote_task_id.raw(),
            code: RemoteServiceRejectionCode::ComputationDenied,
            diagnostic: error.to_string(),
        }
        .with_no_commit();
    }
    if execution_mode.enforces_request_lease() && request.lease.is_zero() {
        return RemoteServiceWireResponse::Rejected {
            remote_task_id: remote_task_id.raw(),
            code: RemoteServiceRejectionCode::MalformedRequest,
            diagnostic: "remote computation lease must be nonzero".to_owned(),
        }
        .with_no_commit();
    }

    let admission = match remote_service_protocol_kind(session.protocol_version()) {
        RemoteServiceProtocolKind::V1OneShot => None,
        RemoteServiceProtocolKind::V2Idempotent => {
            let Some(state) = idempotency else {
                return RemoteServiceWireResponse::Rejected {
                    remote_task_id: remote_task_id.raw(),
                    code: RemoteServiceRejectionCode::LifecycleUnavailable,
                    diagnostic: "protocol V2 requires listener-owned idempotency state".to_owned(),
                }
                .with_no_commit();
            };
            Some(state.admit(session.peer_node(), &request, cx.now()))
        }
        RemoteServiceProtocolKind::V3Session => {
            return RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::LifecycleUnavailable,
                diagnostic: "protocol V3 requires same-connection lifecycle session handling"
                    .to_owned(),
            }
            .with_no_commit();
        }
        RemoteServiceProtocolKind::Unsupported => {
            return RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::LifecycleUnavailable,
                diagnostic: format!(
                    "unsupported remote service protocol version {}",
                    session.protocol_version()
                ),
            }
            .with_no_commit();
        }
    };
    let should_commit = matches!(admission, Some(RemoteServiceIdempotencyAdmission::Execute));

    match admission {
        Some(RemoteServiceIdempotencyAdmission::CachedOutcome(outcome)) => {
            return RemoteServiceWireResponse::Outcome {
                remote_task_id: remote_task_id.raw(),
                outcome: outcome.into(),
            }
            .with_no_commit();
        }
        Some(RemoteServiceIdempotencyAdmission::CachedExecutionRejection(diagnostic)) => {
            return RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::ExecutionFailed,
                diagnostic,
            }
            .with_no_commit();
        }
        Some(RemoteServiceIdempotencyAdmission::InFlight) => {
            return RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::OperationInFlight,
                diagnostic: "matching protocol V2 operation is still in flight".to_owned(),
            }
            .with_no_commit();
        }
        Some(RemoteServiceIdempotencyAdmission::Conflict) => {
            return RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::IdempotencyConflict,
                diagnostic: "idempotency key was already used for different computation input"
                    .to_owned(),
            }
            .with_no_commit();
        }
        Some(RemoteServiceIdempotencyAdmission::Capacity) => {
            return RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::IdempotencyCapacity,
                diagnostic: "authenticated peer exhausted retained idempotency capacity".to_owned(),
            }
            .with_no_commit();
        }
        Some(RemoteServiceIdempotencyAdmission::Execute) | None => {}
    }

    let terminal = match execution_mode {
        RemoteServiceExecutionMode::Inline => {
            computations.dispatch(cx, session, request.clone()).await
        }
        #[cfg(not(target_arch = "wasm32"))]
        RemoteServiceExecutionMode::LeaseBound => {
            remote_service_dispatch_with_lease(cx, session, computations, request.clone()).await
        }
    };
    match terminal {
        Ok(outcome) => {
            let response = RemoteServiceWireResponse::Outcome {
                remote_task_id: remote_task_id.raw(),
                outcome: outcome.clone().into(),
            };
            let commit = should_commit.then(|| RemoteServiceTerminalCommit::Outcome {
                peer: session.peer_node().clone(),
                key: request.idempotency_key,
                canonical_task_id: remote_task_id,
                outcome,
            });
            (response, commit)
        }
        Err(RemoteComputationDispatchError::Admission(error)) => {
            RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::ComputationDenied,
                diagnostic: error.to_string(),
            }
            .with_no_commit()
        }
        Err(RemoteComputationDispatchError::Execution(error)) => {
            let diagnostic = error.to_string();
            let response = RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::ExecutionFailed,
                diagnostic: diagnostic.clone(),
            };
            let commit = should_commit.then(|| RemoteServiceTerminalCommit::ExecutionRejection {
                peer: session.peer_node().clone(),
                key: request.idempotency_key,
                canonical_task_id: remote_task_id,
                diagnostic,
            });
            (response, commit)
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
enum RemoteServiceV3Race {
    Expired,
    Completed(
        Result<Result<RemoteOutcome, RemoteComputationDispatchError>, crate::runtime::JoinError>,
    ),
    Flushed,
    FlushFailed(io::Error),
    Command(Option<io::Result<BytesMut>>),
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
enum RemoteServiceV3AcceptedFlush {
    Flushed,
    Expired,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
const fn remote_service_v3_next_renewal_id(last: Option<u64>) -> Option<u64> {
    match last {
        None => Some(1),
        Some(last) => last.checked_add(1),
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
async fn serve_tls_computation_v3_session<IO>(
    cx: &Cx,
    framed: &mut Framed<&mut crate::tls::TlsStream<IO>, LengthDelimitedCodec>,
    session: &RemotePeerSession,
    computations: &RemoteComputationRegistry,
    request: SpawnRequest,
    idempotency: &RemoteServiceIdempotency,
    max_frame_bytes: usize,
) -> Result<RemoteServiceWireResponse, RemoteComputationServiceError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let remote_task_id = request.remote_task_id;
    if let Err(error) = session.authorize_computation(&request.computation) {
        let response = RemoteServiceWireResponse::Rejected {
            remote_task_id: remote_task_id.raw(),
            code: RemoteServiceRejectionCode::ComputationDenied,
            diagnostic: error.to_string(),
        };
        return remote_service_v3_send_terminal(
            cx,
            framed,
            response,
            None,
            idempotency,
            max_frame_bytes,
        )
        .await;
    }
    if request.lease.is_zero() {
        let response = RemoteServiceWireResponse::Rejected {
            remote_task_id: remote_task_id.raw(),
            code: RemoteServiceRejectionCode::MalformedRequest,
            diagnostic: "remote computation lease must be nonzero".to_owned(),
        };
        return remote_service_v3_send_terminal(
            cx,
            framed,
            response,
            None,
            idempotency,
            max_frame_bytes,
        )
        .await;
    }

    match idempotency.admit(session.peer_node(), &request, cx.now()) {
        RemoteServiceIdempotencyAdmission::CachedOutcome(outcome) => {
            let response = RemoteServiceWireResponse::Outcome {
                remote_task_id: remote_task_id.raw(),
                outcome: outcome.into(),
            };
            return remote_service_v3_send_terminal(
                cx,
                framed,
                response,
                None,
                idempotency,
                max_frame_bytes,
            )
            .await;
        }
        RemoteServiceIdempotencyAdmission::CachedExecutionRejection(diagnostic) => {
            let response = RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::ExecutionFailed,
                diagnostic,
            };
            return remote_service_v3_send_terminal(
                cx,
                framed,
                response,
                None,
                idempotency,
                max_frame_bytes,
            )
            .await;
        }
        RemoteServiceIdempotencyAdmission::InFlight => {
            let response = RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::OperationInFlight,
                diagnostic: "matching protocol V3 operation is still in flight".to_owned(),
            };
            return remote_service_v3_send_terminal(
                cx,
                framed,
                response,
                None,
                idempotency,
                max_frame_bytes,
            )
            .await;
        }
        RemoteServiceIdempotencyAdmission::Conflict => {
            let response = RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::IdempotencyConflict,
                diagnostic: "idempotency key was already used for different computation input"
                    .to_owned(),
            };
            return remote_service_v3_send_terminal(
                cx,
                framed,
                response,
                None,
                idempotency,
                max_frame_bytes,
            )
            .await;
        }
        RemoteServiceIdempotencyAdmission::Capacity => {
            let response = RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::IdempotencyCapacity,
                diagnostic: "authenticated peer exhausted retained idempotency capacity".to_owned(),
            };
            return remote_service_v3_send_terminal(
                cx,
                framed,
                response,
                None,
                idempotency,
                max_frame_bytes,
            )
            .await;
        }
        RemoteServiceIdempotencyAdmission::Execute => {}
    }

    let accepted_at = cx.now();
    let mut expires_at = accepted_at + request.lease;
    let child_spec = request
        .budget
        .map_or_else(ChildRegionSpec::inherit, |budget| {
            ChildRegionSpec::inherit().with_budget(budget)
        });
    let child = match cx.open_child_region(child_spec).await {
        Ok(child) => child,
        Err(error) => {
            let diagnostic =
                format!("remote computation lifecycle could not create child region: {error}");
            let response = RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::ExecutionFailed,
                diagnostic: diagnostic.clone(),
            };
            let commit = RemoteServiceTerminalCommit::ExecutionRejection {
                peer: session.peer_node().clone(),
                key: request.idempotency_key,
                canonical_task_id: remote_task_id,
                diagnostic,
            };
            return remote_service_v3_send_terminal(
                cx,
                framed,
                response,
                Some(commit),
                idempotency,
                max_frame_bytes,
            )
            .await;
        }
    };
    let child_region_id = child.region_id();

    let accepted = RemoteServiceSessionEvent::Accepted {
        remote_task_id: remote_task_id.raw(),
    };
    match remote_service_v3_flush_accepted(cx, framed, &accepted, max_frame_bytes, expires_at).await
    {
        Ok(RemoteServiceV3AcceptedFlush::Flushed) => {}
        Ok(RemoteServiceV3AcceptedFlush::Expired) => {
            let terminal = remote_service_expire_child(cx, child, child_region_id).await;
            let (response, commit) =
                remote_service_v3_terminal_response(session, &request, terminal);
            return remote_service_v3_send_terminal(
                cx,
                framed,
                response,
                commit,
                idempotency,
                max_frame_bytes,
            )
            .await;
        }
        Err(error) => {
            return Err(remote_service_v3_abort_after_transport(
                cx,
                child,
                child_region_id,
                session,
                &request,
                idempotency,
                error,
            )
            .await);
        }
    }

    let owned_computations = computations.clone();
    let owned_session = session.clone();
    let retained_request = request.clone();
    let mut task = match child.cx().spawn(move |task_cx| async move {
        owned_computations
            .dispatch(&task_cx, &owned_session, retained_request)
            .await
    }) {
        Ok(task) => task,
        Err(error) => {
            let close_result = child.close().await;
            let diagnostic = match close_result {
                Ok(()) => format!("spawn V3 computation: {error}"),
                Err(close_error) => {
                    format!("spawn V3 computation: {error}; close child region: {close_error}")
                }
            };
            let response = RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::ExecutionFailed,
                diagnostic: diagnostic.clone(),
            };
            let commit = RemoteServiceTerminalCommit::ExecutionRejection {
                peer: session.peer_node().clone(),
                key: request.idempotency_key,
                canonical_task_id: remote_task_id,
                diagnostic,
            };
            return remote_service_v3_send_terminal(
                cx,
                framed,
                response,
                Some(commit),
                idempotency,
                max_frame_bytes,
            )
            .await;
        }
    };

    let mut last_renewal: Option<(u64, Duration)> = None;
    let mut flush_pending = false;
    let terminal = loop {
        let mut deadline = Box::pin(crate::time::sleep_until(expires_at));
        let raced = std::future::poll_fn(|task_cx| {
            if remote_service_lease_expired(cx.now(), expires_at) {
                return std::task::Poll::Ready(RemoteServiceV3Race::Expired);
            }
            if deadline.as_mut().poll(task_cx).is_ready() {
                return std::task::Poll::Ready(RemoteServiceV3Race::Expired);
            }
            if let std::task::Poll::Ready(joined) = task.poll_join(task_cx) {
                return std::task::Poll::Ready(RemoteServiceV3Race::Completed(joined));
            }
            if flush_pending {
                return match framed.poll_flush(task_cx) {
                    std::task::Poll::Ready(Ok(())) => {
                        std::task::Poll::Ready(RemoteServiceV3Race::Flushed)
                    }
                    std::task::Poll::Ready(Err(error)) => {
                        std::task::Poll::Ready(RemoteServiceV3Race::FlushFailed(error))
                    }
                    std::task::Poll::Pending => std::task::Poll::Pending,
                };
            }
            Pin::new(&mut *framed)
                .poll_next(task_cx)
                .map(RemoteServiceV3Race::Command)
        })
        .await;

        match raced {
            RemoteServiceV3Race::Expired => {
                break remote_service_expire_child(cx, child, child_region_id).await;
            }
            RemoteServiceV3Race::Completed(joined) => {
                child.close().await.map_err(|error| {
                    RemoteComputationServiceError::Transport(io::Error::other(format!(
                        "remote computation lifecycle could not close V3 child region: {error}"
                    )))
                })?;
                break remote_service_joined_outcome(joined);
            }
            RemoteServiceV3Race::Flushed => {
                flush_pending = false;
            }
            RemoteServiceV3Race::FlushFailed(error) => {
                let error = RemoteComputationServiceError::Transport(error);
                return Err(remote_service_v3_abort_after_transport(
                    cx,
                    child,
                    child_region_id,
                    session,
                    &request,
                    idempotency,
                    error,
                )
                .await);
            }
            RemoteServiceV3Race::Command(None) => {
                let error = RemoteComputationServiceError::UnexpectedEof;
                return Err(remote_service_v3_abort_after_transport(
                    cx,
                    child,
                    child_region_id,
                    session,
                    &request,
                    idempotency,
                    error,
                )
                .await);
            }
            RemoteServiceV3Race::Command(Some(Err(error))) => {
                let error = RemoteComputationServiceError::Transport(error);
                return Err(remote_service_v3_abort_after_transport(
                    cx,
                    child,
                    child_region_id,
                    session,
                    &request,
                    idempotency,
                    error,
                )
                .await);
            }
            RemoteServiceV3Race::Command(Some(Ok(frame))) => {
                let command: RemoteServiceSessionCommand = match serde_json::from_slice(&frame) {
                    Ok(command) => command,
                    Err(error) => {
                        let error = RemoteComputationServiceError::Serialization(error);
                        return Err(remote_service_v3_abort_after_transport(
                            cx,
                            child,
                            child_region_id,
                            session,
                            &request,
                            idempotency,
                            error,
                        )
                        .await);
                    }
                };
                let presented_task_id = command.remote_task_id();
                if presented_task_id != remote_task_id {
                    let rejected = RemoteServiceSessionEvent::CommandRejected {
                        remote_task_id: presented_task_id.raw(),
                        renewal_id: match command {
                            RemoteServiceSessionCommand::RenewLease { renewal_id, .. } => {
                                Some(renewal_id)
                            }
                            RemoteServiceSessionCommand::Cancel { .. } => None,
                        },
                        diagnostic: format!(
                            "session controls task {remote_task_id}, not {presented_task_id}"
                        ),
                    };
                    if let Err(error) =
                        remote_service_v3_queue_event(framed, &rejected, max_frame_bytes)
                    {
                        return Err(remote_service_v3_abort_after_transport(
                            cx,
                            child,
                            child_region_id,
                            session,
                            &request,
                            idempotency,
                            error,
                        )
                        .await);
                    }
                    flush_pending = true;
                    continue;
                }
                match command {
                    RemoteServiceSessionCommand::Cancel { reason, .. } => {
                        break remote_service_cancel_child(cx, child, child_region_id, reason)
                            .await;
                    }
                    RemoteServiceSessionCommand::RenewLease {
                        renewal_id,
                        lease_secs,
                        lease_subsec_nanos,
                        ..
                    } => {
                        if remote_service_lease_expired(cx.now(), expires_at) {
                            break remote_service_expire_child(cx, child, child_region_id).await;
                        }
                        let lease = (lease_subsec_nanos < 1_000_000_000)
                            .then(|| Duration::new(lease_secs, lease_subsec_nanos));
                        let expected_renewal_id = remote_service_v3_next_renewal_id(
                            last_renewal.map(|(last_id, _)| last_id),
                        );
                        let is_replay = last_renewal == lease.map(|lease| (renewal_id, lease));
                        if lease.is_none()
                            || lease.is_some_and(|duration| duration.is_zero())
                            || (!is_replay && expected_renewal_id != Some(renewal_id))
                        {
                            let expected = expected_renewal_id.map_or_else(
                                || "no further renewal ID after u64::MAX".to_owned(),
                                |expected| expected.to_string(),
                            );
                            let rejected = RemoteServiceSessionEvent::CommandRejected {
                                remote_task_id: remote_task_id.raw(),
                                renewal_id: Some(renewal_id),
                                diagnostic: format!(
                                    "invalid V3 lease renewal {renewal_id}; expected {expected} with a nonzero duration"
                                ),
                            };
                            if let Err(error) =
                                remote_service_v3_queue_event(framed, &rejected, max_frame_bytes)
                            {
                                return Err(remote_service_v3_abort_after_transport(
                                    cx,
                                    child,
                                    child_region_id,
                                    session,
                                    &request,
                                    idempotency,
                                    error,
                                )
                                .await);
                            }
                            flush_pending = true;
                            continue;
                        }
                        let lease = lease.expect("validated V3 renewal lease");
                        if !is_replay {
                            expires_at = cx.now() + lease;
                            last_renewal = Some((renewal_id, lease));
                        }
                        let renewed = RemoteServiceSessionEvent::LeaseRenewed {
                            remote_task_id: remote_task_id.raw(),
                            renewal_id,
                            lease_secs: lease.as_secs(),
                            lease_subsec_nanos: lease.subsec_nanos(),
                        };
                        if let Err(error) =
                            remote_service_v3_queue_event(framed, &renewed, max_frame_bytes)
                        {
                            return Err(remote_service_v3_abort_after_transport(
                                cx,
                                child,
                                child_region_id,
                                session,
                                &request,
                                idempotency,
                                error,
                            )
                            .await);
                        }
                        flush_pending = true;
                    }
                }
            }
        }
    };

    let (response, commit) = remote_service_v3_terminal_response(session, &request, terminal);
    remote_service_v3_send_terminal(cx, framed, response, commit, idempotency, max_frame_bytes)
        .await
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
fn remote_service_v3_queue_event<IO>(
    framed: &mut Framed<&mut crate::tls::TlsStream<IO>, LengthDelimitedCodec>,
    event: &RemoteServiceSessionEvent,
    max_frame_bytes: usize,
) -> Result<(), RemoteComputationServiceError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let encoded = encode_remote_service_frame(event, max_frame_bytes)?;
    framed
        .send(BytesMut::from(encoded.as_slice()))
        .map_err(RemoteComputationServiceError::Transport)
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
async fn remote_service_v3_flush_accepted<IO>(
    cx: &Cx,
    framed: &mut Framed<&mut crate::tls::TlsStream<IO>, LengthDelimitedCodec>,
    event: &RemoteServiceSessionEvent,
    max_frame_bytes: usize,
    expires_at: Time,
) -> Result<RemoteServiceV3AcceptedFlush, RemoteComputationServiceError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    remote_service_v3_queue_event(framed, event, max_frame_bytes)?;
    let mut deadline = Box::pin(crate::time::sleep_until(expires_at));
    std::future::poll_fn(|task_cx| {
        if remote_service_lease_expired(cx.now(), expires_at) {
            return std::task::Poll::Ready(Ok(RemoteServiceV3AcceptedFlush::Expired));
        }
        if deadline.as_mut().poll(task_cx).is_ready() {
            return std::task::Poll::Ready(Ok(RemoteServiceV3AcceptedFlush::Expired));
        }
        match framed.poll_flush(task_cx) {
            std::task::Poll::Ready(Ok(())) => {
                std::task::Poll::Ready(Ok(RemoteServiceV3AcceptedFlush::Flushed))
            }
            std::task::Poll::Ready(Err(error)) => {
                std::task::Poll::Ready(Err(RemoteComputationServiceError::Transport(error)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
async fn remote_service_v3_send_terminal<IO>(
    cx: &Cx,
    framed: &mut Framed<&mut crate::tls::TlsStream<IO>, LengthDelimitedCodec>,
    response: RemoteServiceWireResponse,
    commit: Option<RemoteServiceTerminalCommit>,
    idempotency: &RemoteServiceIdempotency,
    max_frame_bytes: usize,
) -> Result<RemoteServiceWireResponse, RemoteComputationServiceError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let (response, commit, encoded) =
        remote_service_prepare_terminal_encoding(response, commit, max_frame_bytes, true);
    if let Some(commit) = commit
        && !commit.complete(idempotency, cx.now())
    {
        return Err(RemoteComputationServiceError::IdempotencyStateLost);
    }
    let encoded = encoded?;
    send_remote_service_frame(cx, framed, &encoded).await?;
    Ok(response)
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
fn remote_service_v3_terminal_response(
    session: &RemotePeerSession,
    request: &SpawnRequest,
    terminal: Result<RemoteOutcome, RemoteComputationDispatchError>,
) -> (
    RemoteServiceWireResponse,
    Option<RemoteServiceTerminalCommit>,
) {
    let remote_task_id = request.remote_task_id;
    match terminal {
        Ok(outcome) => (
            RemoteServiceWireResponse::Outcome {
                remote_task_id: remote_task_id.raw(),
                outcome: outcome.clone().into(),
            },
            Some(RemoteServiceTerminalCommit::Outcome {
                peer: session.peer_node().clone(),
                key: request.idempotency_key,
                canonical_task_id: remote_task_id,
                outcome,
            }),
        ),
        Err(RemoteComputationDispatchError::Admission(error)) => (
            RemoteServiceWireResponse::Rejected {
                remote_task_id: remote_task_id.raw(),
                code: RemoteServiceRejectionCode::ComputationDenied,
                diagnostic: error.to_string(),
            },
            None,
        ),
        Err(RemoteComputationDispatchError::Execution(error)) => {
            let diagnostic = error.to_string();
            (
                RemoteServiceWireResponse::Rejected {
                    remote_task_id: remote_task_id.raw(),
                    code: RemoteServiceRejectionCode::ExecutionFailed,
                    diagnostic: diagnostic.clone(),
                },
                Some(RemoteServiceTerminalCommit::ExecutionRejection {
                    peer: session.peer_node().clone(),
                    key: request.idempotency_key,
                    canonical_task_id: remote_task_id,
                    diagnostic,
                }),
            )
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
fn remote_service_joined_outcome(
    joined: Result<
        Result<RemoteOutcome, RemoteComputationDispatchError>,
        crate::runtime::JoinError,
    >,
) -> Result<RemoteOutcome, RemoteComputationDispatchError> {
    match joined {
        Ok(terminal) => terminal,
        Err(crate::runtime::JoinError::Cancelled(reason)) => Ok(RemoteOutcome::Cancelled(reason)),
        Err(crate::runtime::JoinError::Panicked(payload)) => {
            Ok(RemoteOutcome::Panicked(payload.message().to_owned()))
        }
        Err(crate::runtime::JoinError::PolledAfterCompletion) => Err(
            RemoteComputationDispatchError::Execution(RemoteError::TransportError(
                "V3 computation join handle was polled after completion".to_owned(),
            )),
        ),
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
async fn remote_service_v3_abort_after_transport(
    cx: &Cx,
    child: crate::cx::ChildRegion,
    child_region_id: RegionId,
    session: &RemotePeerSession,
    request: &SpawnRequest,
    idempotency: &RemoteServiceIdempotency,
    source: RemoteComputationServiceError,
) -> RemoteComputationServiceError {
    let reason = CancelReason::with_origin(
        crate::types::CancelKind::Shutdown,
        child_region_id,
        cx.now(),
    )
    .with_message("remote computation session transport closed");
    match remote_service_cancel_child(cx, child, child_region_id, reason).await {
        Ok(outcome) => {
            let commit = RemoteServiceTerminalCommit::Outcome {
                peer: session.peer_node().clone(),
                key: request.idempotency_key,
                canonical_task_id: request.remote_task_id,
                outcome,
            };
            if commit.complete(idempotency, cx.now()) {
                source
            } else {
                RemoteComputationServiceError::IdempotencyStateLost
            }
        }
        Err(error) => RemoteComputationServiceError::Transport(io::Error::other(format!(
            "{source}; V3 disconnect cleanup failed: {error}"
        ))),
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
async fn remote_service_dispatch_with_lease(
    cx: &Cx,
    session: &RemotePeerSession,
    computations: &RemoteComputationRegistry,
    request: SpawnRequest,
) -> Result<RemoteOutcome, RemoteComputationDispatchError> {
    let accepted_at = cx.now();
    let expires_at = accepted_at + request.lease;
    let child_budget = cx.budget().tightened_by_timeout(accepted_at, request.lease);
    let child = cx
        .open_child_region(ChildRegionSpec::inherit().with_budget(child_budget))
        .await
        .map_err(|error| remote_service_execution_lifecycle_error("create child region", error))?;
    let child_region_id = child.region_id();

    if remote_service_lease_expired(cx.now(), expires_at) {
        return remote_service_expire_child(cx, child, child_region_id).await;
    }

    let owned_computations = computations.clone();
    let owned_session = session.clone();
    let mut task = match child.cx().spawn(move |task_cx| async move {
        owned_computations
            .dispatch(&task_cx, &owned_session, request)
            .await
    }) {
        Ok(task) => task,
        Err(error) => {
            let close_result = child.close().await;
            let diagnostic = match close_result {
                Ok(()) => format!("spawn leased computation: {error}"),
                Err(close_error) => {
                    format!("spawn leased computation: {error}; close child region: {close_error}")
                }
            };
            return Err(RemoteComputationDispatchError::Execution(
                RemoteError::TransportError(diagnostic),
            ));
        }
    };
    let mut deadline = Box::pin(crate::time::sleep_until(expires_at));

    enum LeaseRace<T> {
        Completed(T),
        Expired,
    }

    let raced = std::future::poll_fn(|task_cx| {
        if remote_service_lease_expired(cx.now(), expires_at) {
            return std::task::Poll::Ready(LeaseRace::Expired);
        }
        if deadline.as_mut().poll(task_cx).is_ready() {
            return std::task::Poll::Ready(LeaseRace::Expired);
        }
        task.poll_join(task_cx).map(LeaseRace::Completed)
    })
    .await;

    match raced {
        LeaseRace::Expired => remote_service_expire_child(cx, child, child_region_id).await,
        LeaseRace::Completed(joined) => {
            child.close().await.map_err(|error| {
                remote_service_execution_lifecycle_error("close child region", error)
            })?;
            match joined {
                Ok(terminal) => terminal,
                Err(crate::runtime::JoinError::Cancelled(reason)) => {
                    Ok(RemoteOutcome::Cancelled(reason))
                }
                Err(crate::runtime::JoinError::Panicked(payload)) => {
                    Ok(RemoteOutcome::Panicked(payload.message().to_owned()))
                }
                Err(crate::runtime::JoinError::PolledAfterCompletion) => Err(
                    RemoteComputationDispatchError::Execution(RemoteError::TransportError(
                        "leased computation join handle was polled after completion".to_owned(),
                    )),
                ),
            }
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
fn remote_service_lease_expired(now: Time, expires_at: Time) -> bool {
    now >= expires_at
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
async fn remote_service_expire_child(
    cx: &Cx,
    child: crate::cx::ChildRegion,
    child_region_id: RegionId,
) -> Result<RemoteOutcome, RemoteComputationDispatchError> {
    let reason = CancelReason::with_origin(
        crate::types::CancelKind::Deadline,
        child_region_id,
        cx.now(),
    )
    .with_message("remote computation lease expired");
    remote_service_cancel_child(cx, child, child_region_id, reason).await
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
async fn remote_service_cancel_child(
    _cx: &Cx,
    child: crate::cx::ChildRegion,
    _child_region_id: RegionId,
    reason: CancelReason,
) -> Result<RemoteOutcome, RemoteComputationDispatchError> {
    child
        .cancel(reason.clone())
        .map_err(|error| remote_service_execution_lifecycle_error("cancel child region", error))?;
    child.close().await.map_err(|error| {
        remote_service_execution_lifecycle_error("close cancelled child region", error)
    })?;
    Ok(RemoteOutcome::Cancelled(reason))
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
fn remote_service_execution_lifecycle_error(
    operation: &str,
    error: impl fmt::Display,
) -> RemoteComputationDispatchError {
    RemoteComputationDispatchError::Execution(RemoteError::TransportError(format!(
        "remote computation lifecycle could not {operation}: {error}"
    )))
}

/// Sends one bounded request and awaits its fully decoded TLS response.
///
/// This is the client half of [`serve_tls_computation_once`]. The caller owns
/// handshake, timeout, and connection reuse policy. A V1 caller must not retry
/// an ambiguous delivery. A V2 request can be retried with the same key and
/// semantic fingerprint only when the server is a structured listener.
#[cfg(feature = "tls")]
pub async fn call_tls_computation_once<IO>(
    cx: &Cx,
    stream: &mut crate::tls::TlsStream<IO>,
    request: &RemoteServiceWireRequest,
    limits: RemoteServiceWireLimits,
) -> Result<RemoteServiceWireResponse, RemoteComputationServiceError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut framed = remote_service_framed(stream, limits)?;
    write_remote_service_frame(cx, &mut framed, request, limits.max_frame_bytes()).await?;
    read_remote_service_frame(cx, &mut framed).await
}

/// Bounded connection and retry policy for [`RemoteComputationClient`].
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteComputationClientConfig {
    wire_limits: RemoteServiceWireLimits,
    connect_timeout: Duration,
    attempt_timeout: Duration,
    max_attempts: usize,
    initial_backoff: Duration,
    max_backoff: Duration,
    full_jitter: bool,
    tcp_nodelay: bool,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl RemoteComputationClientConfig {
    /// Creates a production-oriented bounded client policy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            wire_limits: RemoteServiceWireLimits::new(DEFAULT_REMOTE_SERVICE_MAX_FRAME_BYTES),
            connect_timeout: Duration::from_secs(5),
            attempt_timeout: Duration::from_secs(30),
            max_attempts: 3,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(1),
            full_jitter: true,
            tcp_nodelay: true,
        }
    }

    /// Sets the maximum encoded request and response frame size.
    #[must_use]
    pub const fn with_wire_limits(mut self, wire_limits: RemoteServiceWireLimits) -> Self {
        self.wire_limits = wire_limits;
        self
    }

    /// Sets the timeout for each TCP connection attempt.
    #[must_use]
    pub const fn with_connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    /// Sets the total timeout for one connect, handshake, and exchange attempt.
    #[must_use]
    pub const fn with_attempt_timeout(mut self, attempt_timeout: Duration) -> Self {
        self.attempt_timeout = attempt_timeout;
        self
    }

    /// Sets the total attempt cap, including the first attempt.
    #[must_use]
    pub const fn with_max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Sets the initial and maximum exponential retry delay.
    #[must_use]
    pub const fn with_backoff(mut self, initial: Duration, maximum: Duration) -> Self {
        self.initial_backoff = initial;
        self.max_backoff = maximum;
        self
    }

    /// Enables or disables deterministic-context full jitter.
    #[must_use]
    pub const fn with_full_jitter(mut self, enabled: bool) -> Self {
        self.full_jitter = enabled;
        self
    }

    /// Enables or disables TCP_NODELAY on successful connections.
    #[must_use]
    pub const fn with_tcp_nodelay(mut self, enabled: bool) -> Self {
        self.tcp_nodelay = enabled;
        self
    }

    /// Encoded-frame policy applied to every attempt.
    #[must_use]
    pub const fn wire_limits(self) -> RemoteServiceWireLimits {
        self.wire_limits
    }

    /// Timeout for each TCP connection attempt.
    #[must_use]
    pub const fn connect_timeout(self) -> Duration {
        self.connect_timeout
    }

    /// Total timeout for one connect, handshake, and exchange attempt.
    #[must_use]
    pub const fn attempt_timeout(self) -> Duration {
        self.attempt_timeout
    }

    /// Total attempt cap, including the first attempt.
    #[must_use]
    pub const fn max_attempts(self) -> usize {
        self.max_attempts
    }

    /// Initial exponential retry delay.
    #[must_use]
    pub const fn initial_backoff(self) -> Duration {
        self.initial_backoff
    }

    /// Maximum exponential retry delay.
    #[must_use]
    pub const fn max_backoff(self) -> Duration {
        self.max_backoff
    }

    /// Whether retry delays use deterministic-context full jitter.
    #[must_use]
    pub const fn full_jitter(self) -> bool {
        self.full_jitter
    }

    /// Whether successful sockets enable TCP_NODELAY.
    #[must_use]
    pub const fn tcp_nodelay(self) -> bool {
        self.tcp_nodelay
    }

    fn validate(self) -> Result<(), RemoteComputationClientError> {
        if self.wire_limits.max_frame_bytes() == 0 {
            return Err(RemoteComputationClientError::InvalidConfig(
                "remote client frame limit must be nonzero",
            ));
        }
        if self.connect_timeout.is_zero() {
            return Err(RemoteComputationClientError::InvalidConfig(
                "remote client connect timeout must be nonzero",
            ));
        }
        if self.attempt_timeout.is_zero() {
            return Err(RemoteComputationClientError::InvalidConfig(
                "remote client attempt timeout must be nonzero",
            ));
        }
        if self.max_attempts == 0 {
            return Err(RemoteComputationClientError::InvalidConfig(
                "remote client max attempts must be nonzero",
            ));
        }
        if self.initial_backoff > self.max_backoff {
            return Err(RemoteComputationClientError::InvalidConfig(
                "remote client initial backoff exceeds maximum backoff",
            ));
        }
        Ok(())
    }

    fn retry_delay(self, cx: &Cx, completed_attempts: usize) -> Duration {
        let exponent = u32::try_from(completed_attempts.saturating_sub(1).min(31))
            .expect("retry exponent is capped at 31");
        let multiplier = 1_u32 << exponent;
        let capped = self
            .initial_backoff
            .saturating_mul(multiplier)
            .min(self.max_backoff);
        if !self.full_jitter || capped.is_zero() {
            return capped;
        }
        let inclusive_max = u64::try_from(capped.as_nanos()).unwrap_or(u64::MAX);
        let nanos = if inclusive_max == u64::MAX {
            cx.random_u64()
        } else {
            cx.random_u64() % inclusive_max.saturating_add(1)
        };
        Duration::from_nanos(nanos)
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl Default for RemoteComputationClientConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Terminal local failure from a native remote-computation client call.
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
#[derive(Debug)]
#[non_exhaustive]
pub enum RemoteComputationClientError {
    /// Static client configuration cannot safely execute a call.
    InvalidConfig(&'static str),
    /// The supplied TLS server name is invalid.
    InvalidServerName(TlsError),
    /// The caller context cancelled before another attempt could start.
    Cancelled {
        /// Number of attempts started.
        attempts: usize,
    },
    /// Caller cancellation interrupted an attempt after delivery became uncertain.
    CancelledDuringAttempt {
        /// Number of attempts started.
        attempts: usize,
    },
    /// TCP connection attempts ended without a usable socket.
    Connect {
        /// Number of attempts started.
        attempts: usize,
        /// Last TCP failure.
        source: io::Error,
    },
    /// TLS handshake attempts ended without an authenticated stream.
    Tls {
        /// Number of attempts started.
        attempts: usize,
        /// Last TLS failure.
        source: TlsError,
    },
    /// An attempt timed out after work may have reached the authenticated peer.
    ///
    /// All protocol versions stop here because process-local deduplication
    /// cannot make a fresh-connection replay safe across restart or eviction.
    AttemptTimeout {
        /// Number of attempts started.
        attempts: usize,
        /// Bound applied to the final attempt.
        timeout: Duration,
    },
    /// The authenticated exchange lost transport after delivery became ambiguous.
    ///
    /// All protocol versions surface the first such failure. Process-local
    /// deduplication cannot make a replay safe across restart or eviction.
    AmbiguousExchange {
        /// Number of attempts started.
        attempts: usize,
        /// Final transport loss.
        source: RemoteComputationServiceError,
    },
    /// An authenticated response carried the wrong request correlation ID.
    ResponseTaskMismatch {
        /// Number of attempts started.
        attempts: usize,
        /// Correlation ID from the request.
        expected: u64,
        /// Correlation ID from the response.
        actual: u64,
    },
    /// A request exchange failed after TLS authentication.
    Exchange {
        /// Number of attempts started.
        attempts: usize,
        /// Last framing, serialization, or transport failure.
        source: RemoteComputationServiceError,
    },
    /// A V3 session failed during admission or lifecycle framing.
    Session {
        /// Number of connection attempts started.
        attempts: usize,
        /// Typed session failure.
        source: RemoteServiceSessionError,
    },
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl RemoteComputationClientError {
    /// Number of network attempts started before this failure.
    #[must_use]
    pub const fn attempts(&self) -> usize {
        match self {
            Self::InvalidConfig(_) | Self::InvalidServerName(_) => 0,
            Self::Cancelled { attempts }
            | Self::CancelledDuringAttempt { attempts }
            | Self::Connect { attempts, .. }
            | Self::Tls { attempts, .. }
            | Self::AttemptTimeout { attempts, .. }
            | Self::AmbiguousExchange { attempts, .. }
            | Self::ResponseTaskMismatch { attempts, .. }
            | Self::Exchange { attempts, .. }
            | Self::Session { attempts, .. } => *attempts,
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl fmt::Display for RemoteComputationClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(diagnostic) => f.write_str(diagnostic),
            Self::InvalidServerName(error) => write!(f, "remote client server name: {error}"),
            Self::Cancelled { attempts } => {
                write!(f, "remote client cancelled after {attempts} attempt(s)")
            }
            Self::CancelledDuringAttempt { attempts } => write!(
                f,
                "remote client cancelled during attempt {attempts}; request delivery is uncertain"
            ),
            Self::Connect { attempts, source } => {
                write!(
                    f,
                    "remote client TCP failed after {attempts} attempt(s): {source}"
                )
            }
            Self::Tls { attempts, source } => {
                write!(
                    f,
                    "remote client TLS failed after {attempts} attempt(s): {source}"
                )
            }
            Self::AttemptTimeout { attempts, timeout } => write!(
                f,
                "remote client attempt timed out after {attempts} attempt(s) at {timeout:?}; request delivery is uncertain"
            ),
            Self::AmbiguousExchange { attempts, source } => write!(
                f,
                "remote client transport was lost after {attempts} exchange attempt(s); request delivery is uncertain: {source}"
            ),
            Self::ResponseTaskMismatch {
                attempts,
                expected,
                actual,
            } => write!(
                f,
                "remote client response task mismatch after {attempts} attempt(s): expected {expected}, got {actual}"
            ),
            Self::Exchange { attempts, source } => write!(
                f,
                "remote client exchange failed after {attempts} attempt(s): {source}"
            ),
            Self::Session { attempts, source } => write!(
                f,
                "remote client V3 session failed after {attempts} attempt(s): {source}"
            ),
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl std::error::Error for RemoteComputationClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidServerName(error) => Some(error),
            Self::Connect { source, .. } => Some(source),
            Self::Tls { source, .. } => Some(source),
            Self::AmbiguousExchange { source, .. } => Some(source),
            Self::Exchange { source, .. } => Some(source),
            Self::Session { source, .. } => Some(source),
            Self::InvalidConfig(_)
            | Self::Cancelled { .. }
            | Self::CancelledDuringAttempt { .. }
            | Self::AttemptTimeout { .. }
            | Self::ResponseTaskMismatch { .. } => None,
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
enum RemoteComputationClientAttemptError {
    Connect(io::Error),
    Tls(TlsError),
    Timeout(Duration),
    Exchange(RemoteComputationServiceError),
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl RemoteComputationClientAttemptError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::Connect(error) => remote_client_io_error_is_transient(error),
            Self::Tls(TlsError::Io(error)) => remote_client_io_error_is_transient(error),
            Self::Tls(TlsError::Timeout(_)) => true,
            Self::Tls(_) => false,
            Self::Timeout(_) | Self::Exchange(_) => false,
        }
    }

    fn into_public(self, attempts: usize) -> RemoteComputationClientError {
        match self {
            Self::Connect(source) => RemoteComputationClientError::Connect { attempts, source },
            Self::Tls(source) => RemoteComputationClientError::Tls { attempts, source },
            Self::Timeout(timeout) => {
                RemoteComputationClientError::AttemptTimeout { attempts, timeout }
            }
            Self::Exchange(source) => {
                RemoteComputationClientError::AmbiguousExchange { attempts, source }
            }
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
fn remote_client_io_error_is_transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::AddrNotAvailable
    )
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
enum RemoteClientCancelRace<T> {
    Completed(T),
    Cancelled,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
async fn remote_client_wait_for_cancellation(cx: &Cx) {
    if cx.checkpoint().is_err() {
        return;
    }
    let (sender, mut receiver) = oneshot::channel::<()>();
    let _ = receiver.recv(cx).await;
    drop(sender);
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
async fn remote_client_race_cancellation<F>(cx: &Cx, future: F) -> RemoteClientCancelRace<F::Output>
where
    F: Future,
{
    futures_lite::future::race(
        async { RemoteClientCancelRace::Completed(future.await) },
        async {
            remote_client_wait_for_cancellation(cx).await;
            RemoteClientCancelRace::Cancelled
        },
    )
    .await
}

/// Native TCP+mTLS client for the authenticated remote-computation service.
///
/// Every protocol version retries only failures proven to precede request
/// delivery. Delivery-ambiguous timeout, framing, or transport loss fails closed,
/// as does a typed V2 in-flight response: listener deduplication is process-local
/// and cannot make a fresh-connection replay safe across restart or eviction.
/// The attempt cap and backoff are finite, and caller cancellation wakes both an
/// active attempt and its retry delay.
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
#[derive(Clone)]
pub struct RemoteComputationClient {
    endpoint: SocketAddr,
    server_name: String,
    tls_connector: TlsConnector,
    config: RemoteComputationClientConfig,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl fmt::Debug for RemoteComputationClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteComputationClient")
            .field("endpoint", &self.endpoint)
            .field("server_name", &self.server_name)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl RemoteComputationClient {
    /// Creates a native remote client after validating its static policy.
    pub fn new(
        endpoint: SocketAddr,
        server_name: impl Into<String>,
        tls_connector: TlsConnector,
        config: RemoteComputationClientConfig,
    ) -> Result<Self, RemoteComputationClientError> {
        config.validate()?;
        let server_name = server_name.into();
        TlsConnector::validate_domain(&server_name)
            .map_err(RemoteComputationClientError::InvalidServerName)?;
        Ok(Self {
            endpoint,
            server_name,
            tls_connector,
            config,
        })
    }

    /// Destination socket used by each connection attempt.
    #[must_use]
    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// TLS SNI/server-certificate name.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Bounded connection and retry policy.
    #[must_use]
    pub const fn config(&self) -> RemoteComputationClientConfig {
        self.config
    }

    /// Connects, authenticates, and starts one same-connection V3 operation.
    ///
    /// The configured attempt timeout bounds TCP, TLS, request delivery, and
    /// the initial accepted/terminal event only. Once returned, the session's
    /// request lease and caller context govern operation lifetime. This method
    /// never retries because failure after the request write is ambiguous; a
    /// dropped authenticated stream causes the V3 listener to cancel and drain
    /// its connection-owned child.
    pub async fn start_session(
        &self,
        cx: &Cx,
        request: &RemoteServiceWireRequest,
    ) -> Result<
        RemoteComputationSessionStart<crate::tls::TlsStream<TcpStream>>,
        RemoteComputationClientError,
    > {
        if cx.checkpoint().is_err() {
            return Err(RemoteComputationClientError::Cancelled { attempts: 0 });
        }
        let presented = request.hello().protocol_version();
        if presented != RemoteProtocolVersion::V3 {
            return Err(RemoteComputationClientError::Session {
                attempts: 0,
                source: RemoteServiceSessionError::WrongProtocol { presented },
            });
        }
        if let Err(source) =
            encode_remote_service_frame(request, self.config.wire_limits.max_frame_bytes())
        {
            return Err(RemoteComputationClientError::Session {
                attempts: 0,
                source: RemoteServiceSessionError::Service(source),
            });
        }

        let started = remote_client_race_cancellation(
            cx,
            crate::time::timeout(
                cx.now(),
                self.config.attempt_timeout,
                self.start_session_once(cx, request),
            ),
        )
        .await;
        if cx.checkpoint().is_err() {
            return Err(RemoteComputationClientError::CancelledDuringAttempt { attempts: 1 });
        }
        match started {
            RemoteClientCancelRace::Completed(Ok(result)) => result,
            RemoteClientCancelRace::Completed(Err(_)) => {
                Err(RemoteComputationClientError::AttemptTimeout {
                    attempts: 1,
                    timeout: self.config.attempt_timeout,
                })
            }
            RemoteClientCancelRace::Cancelled => {
                Err(RemoteComputationClientError::CancelledDuringAttempt { attempts: 1 })
            }
        }
    }

    /// Connects, authenticates, and executes one bounded request.
    pub async fn call(
        &self,
        cx: &Cx,
        request: &RemoteServiceWireRequest,
    ) -> Result<RemoteServiceWireResponse, RemoteComputationClientError> {
        if cx.checkpoint().is_err() {
            return Err(RemoteComputationClientError::Cancelled { attempts: 0 });
        }
        if let Err(source) =
            encode_remote_service_frame(request, self.config.wire_limits.max_frame_bytes())
        {
            return Err(RemoteComputationClientError::Exchange {
                attempts: 0,
                source,
            });
        }
        let mut attempts = 0_usize;
        loop {
            if cx.checkpoint().is_err() {
                return Err(RemoteComputationClientError::Cancelled { attempts });
            }
            attempts = attempts.saturating_add(1);
            let attempt = match remote_client_race_cancellation(
                cx,
                crate::time::timeout(
                    cx.now(),
                    self.config.attempt_timeout,
                    self.call_once(cx, request),
                ),
            )
            .await
            {
                RemoteClientCancelRace::Completed(result) => result.unwrap_or_else(|_| {
                    Err(RemoteComputationClientAttemptError::Timeout(
                        self.config.attempt_timeout,
                    ))
                }),
                RemoteClientCancelRace::Cancelled => {
                    return Err(RemoteComputationClientError::CancelledDuringAttempt { attempts });
                }
            };
            if cx.checkpoint().is_err() {
                return Err(RemoteComputationClientError::CancelledDuringAttempt { attempts });
            }
            match attempt {
                Ok(response) => {
                    let expected = request.remote_task_id().raw();
                    let actual = response.remote_task_id().raw();
                    if actual != expected {
                        return Err(RemoteComputationClientError::ResponseTaskMismatch {
                            attempts,
                            expected,
                            actual,
                        });
                    }
                    return Ok(response);
                }
                Err(error) if attempts < self.config.max_attempts && error.is_retryable() => {
                    self.sleep_before_retry(cx, attempts).await?;
                }
                Err(error) => return Err(error.into_public(attempts)),
            }
        }
    }

    async fn call_once(
        &self,
        cx: &Cx,
        request: &RemoteServiceWireRequest,
    ) -> Result<RemoteServiceWireResponse, RemoteComputationClientAttemptError> {
        let stream = TcpStreamBuilder::new(self.endpoint)
            .connect_timeout(self.config.connect_timeout)
            .nodelay(self.config.tcp_nodelay)
            .connect()
            .await
            .map_err(RemoteComputationClientAttemptError::Connect)?;
        let mut stream = self
            .tls_connector
            .connect(&self.server_name, stream)
            .await
            .map_err(RemoteComputationClientAttemptError::Tls)?;
        call_tls_computation_once(cx, &mut stream, request, self.config.wire_limits)
            .await
            .map_err(RemoteComputationClientAttemptError::Exchange)
    }

    async fn start_session_once(
        &self,
        cx: &Cx,
        request: &RemoteServiceWireRequest,
    ) -> Result<
        RemoteComputationSessionStart<crate::tls::TlsStream<TcpStream>>,
        RemoteComputationClientError,
    > {
        let stream = TcpStreamBuilder::new(self.endpoint)
            .connect_timeout(self.config.connect_timeout)
            .nodelay(self.config.tcp_nodelay)
            .connect()
            .await
            .map_err(|source| RemoteComputationClientError::Connect {
                attempts: 1,
                source,
            })?;
        let stream = self
            .tls_connector
            .connect(&self.server_name, stream)
            .await
            .map_err(|source| RemoteComputationClientError::Tls {
                attempts: 1,
                source,
            })?;
        RemoteComputationSession::start(cx, stream, request, self.config.wire_limits)
            .await
            .map_err(|source| RemoteComputationClientError::Session {
                attempts: 1,
                source,
            })
    }

    async fn sleep_before_retry(
        &self,
        cx: &Cx,
        completed_attempts: usize,
    ) -> Result<(), RemoteComputationClientError> {
        if cx.checkpoint().is_err() {
            return Err(RemoteComputationClientError::Cancelled {
                attempts: completed_attempts,
            });
        }
        let delay = self.config.retry_delay(cx, completed_attempts);
        if !delay.is_zero() {
            if matches!(
                remote_client_race_cancellation(cx, crate::time::sleep(cx.now(), delay)).await,
                RemoteClientCancelRace::Cancelled
            ) {
                return Err(RemoteComputationClientError::Cancelled {
                    attempts: completed_attempts,
                });
            }
        }
        if cx.checkpoint().is_err() {
            return Err(RemoteComputationClientError::Cancelled {
                attempts: completed_attempts,
            });
        }
        Ok(())
    }
}

/// Default cap on live operations admitted by [`NativeRemoteRuntime`].
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
pub const DEFAULT_NATIVE_REMOTE_MAX_IN_FLIGHT: usize = 256;

/// Static destination route for [`NativeRemoteRuntime`].
///
/// Discovery remains an outer concern: this value deliberately binds one
/// logical destination to one validated client endpoint and one V3 peer hello.
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
#[derive(Clone, Debug)]
pub struct NativeRemoteRoute {
    destination: NodeId,
    hello: RemotePeerHello,
    client: RemoteComputationClient,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl NativeRemoteRoute {
    /// Creates one immutable logical-node route.
    #[must_use]
    pub const fn new(
        destination: NodeId,
        hello: RemotePeerHello,
        client: RemoteComputationClient,
    ) -> Self {
        Self {
            destination,
            hello,
            client,
        }
    }

    /// Logical destination selected by [`spawn_remote`].
    #[must_use]
    pub const fn destination(&self) -> &NodeId {
        &self.destination
    }

    /// V3 hello bound to the authenticated client identity.
    #[must_use]
    pub const fn hello(&self) -> &RemotePeerHello {
        &self.hello
    }

    /// TCP+mTLS client used for this destination.
    #[must_use]
    pub const fn client(&self) -> &RemoteComputationClient {
        &self.client
    }
}

/// Admission and graceful-drain policy for [`NativeRemoteRuntime`].
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeRemoteRuntimeConfig {
    max_in_flight: usize,
    drain_timeout: Duration,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl NativeRemoteRuntimeConfig {
    /// Creates the production-oriented driver policy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_in_flight: DEFAULT_NATIVE_REMOTE_MAX_IN_FLIGHT,
            drain_timeout: Duration::from_secs(30),
        }
    }

    /// Sets the maximum number of live V3 session tasks.
    #[must_use]
    pub const fn with_max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = max_in_flight;
        self
    }

    /// Sets the graceful-cancel interval before force-closing transports.
    #[must_use]
    pub const fn with_drain_timeout(mut self, drain_timeout: Duration) -> Self {
        self.drain_timeout = drain_timeout;
        self
    }

    /// Maximum number of live V3 session tasks.
    #[must_use]
    pub const fn max_in_flight(self) -> usize {
        self.max_in_flight
    }

    /// Graceful-cancel interval before force-close.
    #[must_use]
    pub const fn drain_timeout(self) -> Duration {
        self.drain_timeout
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl Default for NativeRemoteRuntimeConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Static configuration error for [`NativeRemoteRuntime`].
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeRemoteRuntimeBuildError {
    /// A zero operation cap cannot admit remote work.
    ZeroMaxInFlight,
    /// The route advertised a protocol other than V3.
    WrongProtocol {
        /// Destination whose route was invalid.
        destination: NodeId,
        /// Version advertised by the route.
        presented: RemoteProtocolVersion,
    },
    /// The route hello asserted a different origin identity.
    OriginIdentityMismatch {
        /// Destination whose route was invalid.
        destination: NodeId,
        /// Runtime-local origin identity.
        expected: NodeId,
        /// Identity asserted by the route hello.
        presented: NodeId,
    },
    /// Two routes selected the same logical destination.
    DuplicateDestination(NodeId),
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl fmt::Display for NativeRemoteRuntimeBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxInFlight => {
                f.write_str("native remote runtime max-in-flight must be nonzero")
            }
            Self::WrongProtocol {
                destination,
                presented,
            } => write!(
                f,
                "native remote route {destination} must advertise protocol V3, got {presented}"
            ),
            Self::OriginIdentityMismatch {
                destination,
                expected,
                presented,
            } => write!(
                f,
                "native remote route {destination} asserts origin {presented}, expected {expected}"
            ),
            Self::DuplicateDestination(destination) => {
                write!(f, "duplicate native remote route for {destination}")
            }
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl std::error::Error for NativeRemoteRuntimeBuildError {}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
struct NativeRemoteControl {
    pending_cancel: Mutex<Option<CancelReason>>,
    pending_renewal: Mutex<Option<Duration>>,
    wake: mpsc::Sender<()>,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl fmt::Debug for NativeRemoteControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeRemoteControl")
            .field("cancel_pending", &self.pending_cancel.lock().is_some())
            .field("renewal_pending", &self.pending_renewal.lock().is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl NativeRemoteControl {
    fn new() -> (Arc<Self>, mpsc::Receiver<()>) {
        let (wake, receiver) = mpsc::channel(1);
        (
            Arc::new(Self {
                pending_cancel: Mutex::new(None),
                pending_renewal: Mutex::new(None),
                wake,
            }),
            receiver,
        )
    }

    fn signal(&self) -> bool {
        match self.wake.try_send(()) {
            Ok(()) | Err(mpsc::SendError::Full(())) => true,
            Err(mpsc::SendError::Disconnected(()) | mpsc::SendError::Cancelled(())) => false,
        }
    }

    fn request_cancel(&self, reason: CancelReason) -> bool {
        {
            let mut pending = self.pending_cancel.lock();
            if let Some(existing) = pending.as_mut() {
                existing.strengthen(&reason);
            } else {
                *pending = Some(reason);
            }
        }
        self.signal()
    }

    fn request_renewal(&self, lease: Duration) -> bool {
        *self.pending_renewal.lock() = Some(lease);
        self.signal()
    }

    fn take_cancel(&self) -> Option<CancelReason> {
        self.pending_cancel.lock().take()
    }

    fn cancel_reason(&self) -> Option<CancelReason> {
        self.pending_cancel.lock().clone()
    }

    fn take_renewal(&self) -> Option<Duration> {
        self.pending_renewal.lock().take()
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
struct NativeRemoteTaskEntry {
    result: Option<oneshot::Sender<Result<RemoteOutcome, RemoteError>>>,
    state: RemoteTaskState,
    control: Arc<NativeRemoteControl>,
    control_receiver: Option<mpsc::Receiver<()>>,
    driver_cx: Option<Cx>,
    control_in_flight: bool,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
struct NativeRemoteState {
    closed: bool,
    active: BTreeSet<RemoteTaskId>,
    tasks: BTreeMap<RemoteTaskId, NativeRemoteTaskEntry>,
    drain_waiters: Vec<oneshot::Sender<()>>,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl NativeRemoteState {
    fn new() -> Self {
        Self {
            closed: false,
            active: BTreeSet::new(),
            tasks: BTreeMap::new(),
            drain_waiters: Vec::new(),
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
struct NativeRemoteShared {
    max_in_flight: usize,
    state: Mutex<NativeRemoteState>,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl NativeRemoteShared {
    fn register(
        &self,
        task_id: RemoteTaskId,
        result: oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
    ) {
        let (control, control_receiver) = NativeRemoteControl::new();
        let mut state = self.state.lock();
        if state.closed || state.tasks.contains_key(&task_id) {
            drop(state);
            let _ = result.send_blocking(Err(RemoteError::TransportError(
                "native remote runtime is closed or task registration collided".to_owned(),
            )));
            return;
        }
        state.tasks.insert(
            task_id,
            NativeRemoteTaskEntry {
                result: Some(result),
                state: RemoteTaskState::Pending,
                control,
                control_receiver: Some(control_receiver),
                driver_cx: None,
                control_in_flight: false,
            },
        );
    }

    fn admit(&self, task_id: RemoteTaskId) -> Result<mpsc::Receiver<()>, RemoteError> {
        let mut state = self.state.lock();
        if state.closed {
            return Err(RemoteError::TransportError(
                "native remote runtime admission is closed".to_owned(),
            ));
        }
        if state.active.len() >= self.max_in_flight {
            return Err(RemoteError::SpawnRejected(
                SpawnRejectReason::CapacityExceeded,
            ));
        }
        let entry = state.tasks.get_mut(&task_id).ok_or_else(|| {
            RemoteError::TransportError(format!(
                "native remote task {task_id} was not registered before send"
            ))
        })?;
        let receiver = entry.control_receiver.take().ok_or_else(|| {
            RemoteError::TransportError(format!(
                "native remote task {task_id} was already published"
            ))
        })?;
        state.active.insert(task_id);
        Ok(receiver)
    }

    fn attach_driver_cx(&self, task_id: RemoteTaskId, cx: Cx) {
        let pending_cancel = {
            let mut state = self.state.lock();
            state.tasks.get_mut(&task_id).and_then(|entry| {
                entry.driver_cx = Some(cx.clone());
                (entry.state == RemoteTaskState::Pending)
                    .then(|| entry.control.cancel_reason())
                    .flatten()
            })
        };
        if let Some(reason) = pending_cancel {
            cx.set_cancel_reason(reason);
        }
    }

    fn set_running(&self, task_id: RemoteTaskId) {
        if let Some(entry) = self.state.lock().tasks.get_mut(&task_id) {
            entry.state = RemoteTaskState::Running;
        }
    }

    fn set_control_in_flight(&self, task_id: RemoteTaskId, in_flight: bool) {
        if let Some(entry) = self.state.lock().tasks.get_mut(&task_id) {
            entry.control_in_flight = in_flight;
        }
    }

    fn roll_back_admission(&self, task_id: RemoteTaskId) {
        let waiters = {
            let mut state = self.state.lock();
            state.active.remove(&task_id);
            state.tasks.remove(&task_id);
            if state.active.is_empty() {
                std::mem::take(&mut state.drain_waiters)
            } else {
                Vec::new()
            }
        };
        for waiter in waiters {
            let _ = waiter.send_blocking(());
        }
    }

    fn complete(&self, task_id: RemoteTaskId, result: Result<RemoteOutcome, RemoteError>) {
        let terminal_state = RemoteHandle::terminal_state_for_result(&result);
        let sender = {
            let mut state = self.state.lock();
            state.tasks.get_mut(&task_id).and_then(|entry| {
                entry.state = terminal_state;
                entry.driver_cx = None;
                entry.control_in_flight = false;
                entry.result.take()
            })
        };
        let delivered = sender.is_some_and(|sender| sender.send_blocking(result).is_ok());
        let waiters = {
            let mut state = self.state.lock();
            state.active.remove(&task_id);
            if !delivered {
                state.tasks.remove(&task_id);
            }
            let waiters = if state.active.is_empty() {
                std::mem::take(&mut state.drain_waiters)
            } else {
                Vec::new()
            };
            waiters
        };
        for waiter in waiters {
            let _ = waiter.send_blocking(());
        }
    }

    fn control(&self, task_id: RemoteTaskId) -> Result<Arc<NativeRemoteControl>, RemoteError> {
        self.state
            .lock()
            .tasks
            .get(&task_id)
            .map(|entry| Arc::clone(&entry.control))
            .ok_or_else(|| {
                RemoteError::TransportError(format!(
                    "native remote task {task_id} is not active or registered"
                ))
            })
    }

    fn request_cancel(
        &self,
        task_id: RemoteTaskId,
        reason: CancelReason,
    ) -> Result<(), RemoteError> {
        let (signaled, pending_driver) = {
            let state = self.state.lock();
            let entry = state.tasks.get(&task_id).ok_or_else(|| {
                RemoteError::TransportError(format!(
                    "native remote task {task_id} is not active or registered"
                ))
            })?;
            let signaled = entry.control.request_cancel(reason.clone());
            let pending_driver = (entry.state == RemoteTaskState::Pending
                || entry.control_in_flight)
                .then(|| entry.driver_cx.clone())
                .flatten();
            (signaled, pending_driver)
        };
        if let Some(cx) = pending_driver {
            cx.set_cancel_reason(reason);
        }
        if signaled {
            Ok(())
        } else {
            Err(RemoteError::TransportError(format!(
                "native remote task {task_id} control lane is closed"
            )))
        }
    }

    fn begin_drain(
        &self,
        wait_for_quiescence: bool,
    ) -> (bool, Vec<RemoteTaskId>, Option<oneshot::Receiver<()>>) {
        let mut state = self.state.lock();
        let newly_closed = !state.closed;
        state.closed = true;
        let task_ids = state.active.iter().copied().collect();
        let receiver = if state.active.is_empty() || !wait_for_quiescence {
            None
        } else {
            let (sender, receiver) = oneshot::channel();
            state.drain_waiters.push(sender);
            Some(receiver)
        };
        (newly_closed, task_ids, receiver)
    }

    fn force_close(&self) {
        let (controls, contexts) = {
            let mut state = self.state.lock();
            state.closed = true;
            let controls = state
                .active
                .iter()
                .filter_map(|task_id| state.tasks.get(task_id))
                .map(|entry| Arc::clone(&entry.control))
                .collect::<Vec<_>>();
            let contexts = state
                .active
                .iter()
                .filter_map(|task_id| state.tasks.get(task_id))
                .filter_map(|entry| entry.driver_cx.clone())
                .collect::<Vec<_>>();
            (controls, contexts)
        };
        for control in controls {
            control.request_cancel(CancelReason::shutdown());
        }
        for cx in contexts {
            cx.set_cancel_reason(CancelReason::shutdown());
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
struct NativeRemoteDriverGuard {
    shared: Arc<NativeRemoteShared>,
    task_id: RemoteTaskId,
    completed: bool,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl NativeRemoteDriverGuard {
    fn new(shared: Arc<NativeRemoteShared>, task_id: RemoteTaskId) -> Self {
        Self {
            shared,
            task_id,
            completed: false,
        }
    }

    fn finish(mut self, result: Result<RemoteOutcome, RemoteError>) {
        self.completed = true;
        self.shared.complete(self.task_id, result);
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl Drop for NativeRemoteDriverGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.shared.complete(
                self.task_id,
                Err(RemoteError::TransportError(
                    "native remote driver ended before terminal publication".to_owned(),
                )),
            );
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
enum NativeRemoteSessionRace {
    Event(Result<RemoteServiceSessionEvent, RemoteServiceSessionError>),
    Control(Result<(), mpsc::RecvError>),
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
async fn drive_native_remote_session(
    cx: &Cx,
    shared: &NativeRemoteShared,
    task_id: RemoteTaskId,
    client: &RemoteComputationClient,
    request: &RemoteServiceWireRequest,
    control: &NativeRemoteControl,
    control_receiver: &mut mpsc::Receiver<()>,
) -> Result<RemoteOutcome, RemoteError> {
    let started = client
        .start_session(cx, request)
        .await
        .map_err(|error| map_native_remote_client_error(cx, error))?;
    let mut session = match started {
        RemoteComputationSessionStart::Running(session) => {
            shared.set_running(task_id);
            session
        }
        RemoteComputationSessionStart::Terminal(response) => {
            return map_native_remote_response(response);
        }
    };

    loop {
        let race = futures_lite::future::race(
            async {
                NativeRemoteSessionRace::Event(
                    session
                        .exchange_event::<RemoteServiceSessionCommand>(cx, None)
                        .await,
                )
            },
            async { NativeRemoteSessionRace::Control(control_receiver.recv(cx).await) },
        )
        .await;
        match race {
            NativeRemoteSessionRace::Event(Ok(RemoteServiceSessionEvent::Terminal {
                response,
            })) => return map_native_remote_response(response),
            NativeRemoteSessionRace::Event(Ok(_)) => {
                return Err(RemoteError::TransportError(
                    "native remote session received an unsolicited non-terminal event".to_owned(),
                ));
            }
            NativeRemoteSessionRace::Event(Err(error)) => {
                return Err(map_native_remote_session_error(cx, control, error));
            }
            NativeRemoteSessionRace::Control(Ok(())) => {
                // Mark the control exchange before inspecting coalesced state.
                // A cancellation that races this point can then wake the
                // driver Cx and fail closed by dropping the authenticated
                // stream instead of waiting behind a lost renewal reply.
                shared.set_control_in_flight(task_id, true);
                if let Some(reason) = control.take_cancel() {
                    let response = session
                        .cancel(cx, reason)
                        .await
                        .map_err(|error| map_native_remote_session_error(cx, control, error))?;
                    return map_native_remote_response(response);
                }
                if let Some(lease) = control.take_renewal() {
                    let event = session
                        .renew_lease(cx, lease)
                        .await
                        .map_err(|error| map_native_remote_session_error(cx, control, error))?;
                    shared.set_control_in_flight(task_id, false);
                    match event {
                        RemoteServiceSessionEvent::LeaseRenewed { .. } => {}
                        RemoteServiceSessionEvent::Terminal { response } => {
                            return map_native_remote_response(response);
                        }
                        RemoteServiceSessionEvent::CommandRejected { diagnostic, .. } => {
                            return Err(RemoteError::TransportError(format!(
                                "native remote lease renewal rejected: {diagnostic}"
                            )));
                        }
                        RemoteServiceSessionEvent::Accepted { .. } => {
                            return Err(RemoteError::TransportError(
                                "native remote renewal received an accepted event".to_owned(),
                            ));
                        }
                    }
                } else {
                    shared.set_control_in_flight(task_id, false);
                }
            }
            NativeRemoteSessionRace::Control(Err(error)) => {
                return Err(RemoteError::TransportError(format!(
                    "native remote control channel failed: {error}"
                )));
            }
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
fn map_native_remote_client_error(cx: &Cx, error: RemoteComputationClientError) -> RemoteError {
    if let Some(reason) = cx.cancel_reason() {
        return RemoteError::Cancelled(reason);
    }
    if matches!(
        error,
        RemoteComputationClientError::Cancelled { .. }
            | RemoteComputationClientError::CancelledDuringAttempt { .. }
    ) {
        return RemoteError::Cancelled(
            cx.cancel_reason()
                .unwrap_or_else(CancelReason::parent_cancelled),
        );
    }
    RemoteError::TransportError(error.to_string())
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
fn map_native_remote_session_error(
    cx: &Cx,
    control: &NativeRemoteControl,
    error: RemoteServiceSessionError,
) -> RemoteError {
    if let Some(reason) = control.cancel_reason().or_else(|| cx.cancel_reason()) {
        return RemoteError::Cancelled(reason);
    }
    if matches!(error, RemoteServiceSessionError::Cancelled) {
        return RemoteError::Cancelled(
            cx.cancel_reason()
                .unwrap_or_else(CancelReason::parent_cancelled),
        );
    }
    RemoteError::TransportError(error.to_string())
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
fn map_native_remote_response(
    response: RemoteServiceWireResponse,
) -> Result<RemoteOutcome, RemoteError> {
    match response {
        RemoteServiceWireResponse::Outcome { outcome, .. } => match outcome {
            RemoteServiceWireOutcome::Success(payload) => Ok(RemoteOutcome::Success(payload)),
            RemoteServiceWireOutcome::Failed(diagnostic) => Ok(RemoteOutcome::Failed(diagnostic)),
            RemoteServiceWireOutcome::Cancelled(reason) if reason.is_time_exceeded() => {
                Err(RemoteError::LeaseExpired)
            }
            RemoteServiceWireOutcome::Cancelled(reason) => Ok(RemoteOutcome::Cancelled(reason)),
            RemoteServiceWireOutcome::Panicked(diagnostic) => {
                Ok(RemoteOutcome::Panicked(diagnostic))
            }
        },
        RemoteServiceWireResponse::Rejected {
            code, diagnostic, ..
        } => match code {
            RemoteServiceRejectionCode::ComputationDenied
            | RemoteServiceRejectionCode::ExecutableRegistryDrift => Err(
                RemoteError::SpawnRejected(SpawnRejectReason::UnknownComputation),
            ),
            RemoteServiceRejectionCode::MalformedRequest => Err(RemoteError::SpawnRejected(
                SpawnRejectReason::InvalidInput(diagnostic),
            )),
            RemoteServiceRejectionCode::IdempotencyConflict => Err(RemoteError::SpawnRejected(
                SpawnRejectReason::IdempotencyConflict,
            )),
            RemoteServiceRejectionCode::IdempotencyCapacity => Err(RemoteError::SpawnRejected(
                SpawnRejectReason::CapacityExceeded,
            )),
            _ => Err(RemoteError::TransportError(format!(
                "native remote service rejected the request ({code:?}): {diagnostic}"
            ))),
        },
    }
}

/// Production [`RemoteRuntime`] adapter backed by runtime-owned V3 sessions.
///
/// `send_message` performs only bounded local validation and scheduler
/// publication; TCP, mTLS, and lifecycle I/O run in child tasks admitted by the
/// supplied [`RuntimeHandle`]. Per-task cancellation is coalesced out of band,
/// so a dropped [`RemoteHandle`] cannot lose its cancel request to mailbox
/// saturation. Call [`close`](Self::close) to stop admission and prove driver
/// quiescence before releasing the surrounding runtime.
///
/// The adapter retains a strong [`RuntimeHandle`], and every live
/// [`RemoteHandle`] retains the adapter copied from its [`RemoteCap`]. Consuming
/// a terminal result releases that reference automatically, so a joined handle
/// does not pin the surrounding runtime.
///
/// This adapter uses immutable routes. It does not provide discovery, durable
/// idempotency across service restart, or a cross-process deployment daemon.
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
pub struct NativeRemoteRuntime {
    runtime: RuntimeHandle,
    local_node: NodeId,
    routes: BTreeMap<NodeId, NativeRemoteRoute>,
    config: NativeRemoteRuntimeConfig,
    shared: Arc<NativeRemoteShared>,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl fmt::Debug for NativeRemoteRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeRemoteRuntime")
            .field("local_node", &self.local_node)
            .field("destinations", &self.routes.keys().collect::<Vec<_>>())
            .field("active_operations", &self.active_operations())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl NativeRemoteRuntime {
    /// Creates an adapter with the default admission and drain policy.
    pub fn new<I>(
        runtime: RuntimeHandle,
        local_node: NodeId,
        routes: I,
    ) -> Result<Self, NativeRemoteRuntimeBuildError>
    where
        I: IntoIterator<Item = NativeRemoteRoute>,
    {
        Self::with_config(
            runtime,
            local_node,
            routes,
            NativeRemoteRuntimeConfig::new(),
        )
    }

    /// Creates an adapter with an explicit admission and drain policy.
    pub fn with_config<I>(
        runtime: RuntimeHandle,
        local_node: NodeId,
        routes: I,
        config: NativeRemoteRuntimeConfig,
    ) -> Result<Self, NativeRemoteRuntimeBuildError>
    where
        I: IntoIterator<Item = NativeRemoteRoute>,
    {
        if config.max_in_flight == 0 {
            return Err(NativeRemoteRuntimeBuildError::ZeroMaxInFlight);
        }
        let mut indexed = BTreeMap::new();
        for route in routes {
            if route.hello.protocol_version() != RemoteProtocolVersion::V3 {
                return Err(NativeRemoteRuntimeBuildError::WrongProtocol {
                    destination: route.destination,
                    presented: route.hello.protocol_version(),
                });
            }
            if route.hello.peer_node() != &local_node {
                return Err(NativeRemoteRuntimeBuildError::OriginIdentityMismatch {
                    destination: route.destination,
                    expected: local_node,
                    presented: route.hello.peer_node().clone(),
                });
            }
            let destination = route.destination.clone();
            if indexed.insert(destination.clone(), route).is_some() {
                return Err(NativeRemoteRuntimeBuildError::DuplicateDestination(
                    destination,
                ));
            }
        }
        Ok(Self {
            runtime,
            local_node,
            routes: indexed,
            config,
            shared: Arc::new(NativeRemoteShared {
                max_in_flight: config.max_in_flight,
                state: Mutex::new(NativeRemoteState::new()),
            }),
        })
    }

    /// Local identity every configured route must present.
    #[must_use]
    pub const fn local_node(&self) -> &NodeId {
        &self.local_node
    }

    /// Immutable static route for a logical destination.
    #[must_use]
    pub fn route(&self, destination: &NodeId) -> Option<&NativeRemoteRoute> {
        self.routes.get(destination)
    }

    /// Number of published driver tasks that have not reached terminal state.
    #[must_use]
    pub fn active_operations(&self) -> usize {
        self.shared.state.lock().active.len()
    }

    /// Stops new admission and requests graceful cancellation of every live task.
    ///
    /// Returns true only for the caller that first closed admission.
    #[must_use]
    pub fn begin_drain(&self) -> bool {
        let (newly_closed, task_ids, _) = self.shared.begin_drain(false);
        for task_id in task_ids {
            let _ = self
                .shared
                .request_cancel(task_id, CancelReason::shutdown());
        }
        newly_closed
    }

    /// Interrupts all live driver contexts, dropping their authenticated streams.
    pub fn force_close(&self) {
        self.shared.force_close();
    }

    /// Stops admission and waits for every driver to publish a terminal result.
    ///
    /// Graceful V3 cancellation is attempted first. If the configured drain
    /// timeout elapses, active driver contexts are cancelled so transport loss
    /// fences and drains the server-side child. The method then waits
    /// uninterruptibly for local terminal publication and returns false to
    /// report that force-close was required.
    pub async fn close(&self, cx: &Cx) -> bool {
        let (_, task_ids, mut receiver) = self.shared.begin_drain(true);
        for task_id in task_ids {
            let _ = self
                .shared
                .request_cancel(task_id, CancelReason::shutdown());
        }
        let Some(receiver) = receiver.as_mut() else {
            return true;
        };
        if crate::time::timeout(
            cx.now(),
            self.config.drain_timeout,
            receiver.recv_uninterruptible(),
        )
        .await
        .is_ok()
        {
            return true;
        }
        self.shared.force_close();
        let _ = receiver.recv_uninterruptible().await;
        false
    }

    fn validate_sender(&self, sender: &NodeId) -> Result<(), RemoteError> {
        if sender == &self.local_node {
            Ok(())
        } else {
            Err(RemoteError::TransportError(format!(
                "native remote envelope sender {sender} does not match local identity {}",
                self.local_node
            )))
        }
    }

    fn send_spawn(
        &self,
        destination: &NodeId,
        sender: &NodeId,
        request: SpawnRequest,
    ) -> Result<(), RemoteError> {
        self.validate_sender(sender)?;
        if request.origin_node != self.local_node {
            return Err(RemoteError::TransportError(format!(
                "native remote spawn origin {} does not match local identity {}",
                request.origin_node, self.local_node
            )));
        }
        let route = self
            .routes
            .get(destination)
            .ok_or_else(|| RemoteError::NodeUnreachable(destination.as_str().to_owned()))?;
        let wire_request =
            RemoteServiceWireRequest::from_spawn_request(route.hello.clone(), &request)
                .map_err(|error| RemoteError::SerializationError(error.to_string()))?;
        let task_id = request.remote_task_id;
        let mut control_receiver = self.shared.admit(task_id)?;
        let shared = Arc::clone(&self.shared);
        let driver_shared = Arc::clone(&shared);
        let client = route.client.clone();
        let control = shared.control(task_id)?;
        let spawn = self.runtime.try_spawn_with_cx(move |cx| async move {
            driver_shared.attach_driver_cx(task_id, cx.clone());
            let guard = NativeRemoteDriverGuard::new(Arc::clone(&driver_shared), task_id);
            let result = drive_native_remote_session(
                &cx,
                &driver_shared,
                task_id,
                &client,
                &wire_request,
                &control,
                &mut control_receiver,
            )
            .await;
            guard.finish(result);
        });
        if let Err(error) = spawn {
            self.shared.roll_back_admission(task_id);
            return Err(RemoteError::TransportError(format!(
                "native remote driver publication failed: {error}"
            )));
        }
        Ok(())
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl Drop for NativeRemoteRuntime {
    fn drop(&mut self) {
        self.shared.force_close();
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl RemoteRuntime for NativeRemoteRuntime {
    fn send_message(
        &self,
        destination: &NodeId,
        envelope: MessageEnvelope<RemoteMessage>,
    ) -> Result<(), RemoteError> {
        match envelope.payload {
            RemoteMessage::SpawnRequest(request) => {
                self.send_spawn(destination, &envelope.sender, request)
            }
            RemoteMessage::CancelRequest(request) => {
                self.validate_sender(&envelope.sender)?;
                if request.origin_node != self.local_node {
                    return Err(RemoteError::TransportError(format!(
                        "native remote cancel origin {} does not match local identity {}",
                        request.origin_node, self.local_node
                    )));
                }
                self.shared
                    .request_cancel(request.remote_task_id, request.reason)
            }
            RemoteMessage::LeaseRenewal(renewal) => {
                self.validate_sender(&envelope.sender)?;
                if renewal.new_lease.is_zero() {
                    return Err(RemoteError::TransportError(
                        "native remote lease renewal must be nonzero".to_owned(),
                    ));
                }
                let control = self.shared.control(renewal.remote_task_id)?;
                if control.request_renewal(renewal.new_lease) {
                    Ok(())
                } else {
                    Err(RemoteError::TransportError(format!(
                        "native remote task {} control lane is closed",
                        renewal.remote_task_id
                    )))
                }
            }
            RemoteMessage::SpawnAck(_) | RemoteMessage::ResultDelivery(_) => {
                Err(RemoteError::TransportError(
                    "native origin runtime cannot send remote-to-origin messages".to_owned(),
                ))
            }
        }
    }

    fn register_task(
        &self,
        task_id: RemoteTaskId,
        tx: oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
    ) {
        self.shared.register(task_id, tx);
    }

    fn observe_task_state(&self, task_id: RemoteTaskId) -> Option<RemoteTaskState> {
        self.shared
            .state
            .lock()
            .tasks
            .get(&task_id)
            .map(|entry| entry.state)
    }

    fn clear_task_state(&self, task_id: RemoteTaskId) {
        self.shared.state.lock().tasks.remove(&task_id);
    }

    fn unregister_task(&self, task_id: RemoteTaskId) {
        self.shared.roll_back_admission(task_id);
    }
}

/// Fatal listener lifecycle failure for [`RemoteComputationService`].
///
/// Connection-scoped TLS, framing, and handler failures are retained in the
/// terminal [`RemoteComputationServiceReport`] instead of terminating the
/// listener.
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
#[derive(Debug)]
pub enum RemoteComputationListenerError {
    /// A zero-byte frame limit cannot admit any encoded request.
    InvalidFrameLimit,
    /// A zero initial-frame timeout would reject every authenticated peer.
    InvalidInitialFrameTimeout,
    /// A zero retention window would permit immediate duplicate execution.
    InvalidIdempotencyRetention,
    /// A zero record cap cannot admit any V2/V3 operation.
    InvalidIdempotencyCapacity,
    /// The listening socket failed to bind or accept.
    Transport(io::Error),
    /// Runtime refused a structured connection-task spawn.
    Spawn(SpawnError),
    /// Service child-region creation or quiescent close failed.
    ChildRegion(ChildRegionError),
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl fmt::Display for RemoteComputationListenerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFrameLimit => write!(f, "remote listener frame limit must be nonzero"),
            Self::InvalidInitialFrameTimeout => {
                write!(f, "remote listener initial-frame timeout must be nonzero")
            }
            Self::InvalidIdempotencyRetention => {
                write!(f, "remote listener idempotency retention must be nonzero")
            }
            Self::InvalidIdempotencyCapacity => {
                write!(f, "remote listener idempotency record cap must be nonzero")
            }
            Self::Transport(error) => write!(f, "remote listener transport error: {error}"),
            Self::Spawn(error) => write!(f, "remote listener connection spawn failed: {error}"),
            Self::ChildRegion(error) => write!(f, "remote listener child region failed: {error}"),
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl std::error::Error for RemoteComputationListenerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Spawn(error) => Some(error),
            Self::ChildRegion(error) => Some(error),
            Self::InvalidFrameLimit
            | Self::InvalidInitialFrameTimeout
            | Self::InvalidIdempotencyRetention
            | Self::InvalidIdempotencyCapacity => None,
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
#[derive(Debug)]
enum RemoteComputationConnectionError {
    Tls(TlsError),
    Service(RemoteComputationServiceError),
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl fmt::Display for RemoteComputationConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls(error) => write!(f, "remote service TLS error: {error}"),
            Self::Service(error) => error.fmt(f),
        }
    }
}

/// Runtime-owned listener configuration for authenticated remote computations.
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteComputationServiceConfig {
    wire_limits: RemoteServiceWireLimits,
    max_connections: Option<usize>,
    initial_frame_timeout: Duration,
    drain_timeout: Duration,
    idempotency_retention: Duration,
    max_idempotency_records_per_peer: usize,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl RemoteComputationServiceConfig {
    /// Creates a production-oriented listener configuration.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            wire_limits: RemoteServiceWireLimits::new(DEFAULT_REMOTE_SERVICE_MAX_FRAME_BYTES),
            max_connections: Some(256),
            initial_frame_timeout: DEFAULT_REMOTE_SERVICE_INITIAL_FRAME_TIMEOUT,
            drain_timeout: Duration::from_secs(30),
            idempotency_retention: DEFAULT_REMOTE_SERVICE_IDEMPOTENCY_RETENTION,
            max_idempotency_records_per_peer:
                DEFAULT_REMOTE_SERVICE_MAX_IDEMPOTENCY_RECORDS_PER_PEER,
        }
    }

    /// Sets the maximum encoded request and response frame size.
    #[must_use]
    pub const fn with_wire_limits(mut self, wire_limits: RemoteServiceWireLimits) -> Self {
        self.wire_limits = wire_limits;
        self
    }

    /// Sets the listener-wide connection cap; `None` means unbounded.
    #[must_use]
    pub const fn with_max_connections(mut self, max_connections: Option<usize>) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Sets the deadline for an authenticated peer to send its first complete frame.
    #[must_use]
    pub const fn with_initial_frame_timeout(mut self, timeout: Duration) -> Self {
        self.initial_frame_timeout = timeout;
        self
    }

    /// Sets the graceful-drain interval before active connections are interrupted.
    #[must_use]
    pub const fn with_drain_timeout(mut self, drain_timeout: Duration) -> Self {
        self.drain_timeout = drain_timeout;
        self
    }

    /// Sets how long V2/V3 terminal outcomes remain replayable.
    #[must_use]
    pub const fn with_idempotency_retention(mut self, retention: Duration) -> Self {
        self.idempotency_retention = retention;
        self
    }

    /// Sets the V2/V3 retained/in-flight key cap for each authenticated peer.
    #[must_use]
    pub const fn with_max_idempotency_records_per_peer(mut self, max_records: usize) -> Self {
        self.max_idempotency_records_per_peer = max_records;
        self
    }

    /// Encoded-frame policy used by every accepted connection.
    #[must_use]
    pub const fn wire_limits(self) -> RemoteServiceWireLimits {
        self.wire_limits
    }

    /// Listener-wide connection cap.
    #[must_use]
    pub const fn max_connections(self) -> Option<usize> {
        self.max_connections
    }

    /// Deadline for an authenticated peer to send its first complete frame.
    #[must_use]
    pub const fn initial_frame_timeout(self) -> Duration {
        self.initial_frame_timeout
    }

    /// Graceful-drain interval before force-close.
    #[must_use]
    pub const fn drain_timeout(self) -> Duration {
        self.drain_timeout
    }

    /// V2/V3 terminal-outcome replay retention.
    #[must_use]
    pub const fn idempotency_retention(self) -> Duration {
        self.idempotency_retention
    }

    /// V2/V3 retained/in-flight key cap per authenticated peer.
    #[must_use]
    pub const fn max_idempotency_records_per_peer(self) -> usize {
        self.max_idempotency_records_per_peer
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl Default for RemoteComputationServiceConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Cloneable control plane for a running [`RemoteComputationService`].
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
#[derive(Clone)]
pub struct RemoteComputationServiceHandle {
    shutdown_signal: ShutdownSignal,
    connections: ConnectionManager,
    drain_timeout: Duration,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl fmt::Debug for RemoteComputationServiceHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteComputationServiceHandle")
            .field("shutdown_phase", &self.shutdown_signal.phase())
            .field("active_connections", &self.connections.active_count())
            .field("drain_timeout", &self.drain_timeout)
            .finish()
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl RemoteComputationServiceHandle {
    /// Stops admission and begins graceful connection drain.
    #[must_use]
    pub fn begin_drain(&self) -> bool {
        self.connections.begin_drain(self.drain_timeout)
    }

    /// Stops admission and immediately interrupts active connection work.
    pub fn force_close(&self) {
        let _ = self.connections.begin_drain(Duration::ZERO);
        self.shutdown_signal.trigger_immediate();
    }

    /// Shared phase signal for operator observation.
    #[must_use]
    pub fn shutdown_signal(&self) -> ShutdownSignal {
        self.shutdown_signal.clone()
    }

    /// Number of accepted connections whose structured tasks are still live.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.connections.active_count()
    }
}

/// Terminal accounting for one structured remote-computation listener run.
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
#[derive(Clone, Debug)]
pub struct RemoteComputationServiceReport {
    accepted_connections: u64,
    capacity_rejections: u64,
    completed_connections: u64,
    interrupted_connections: u64,
    failed_connections: u64,
    panicked_connections: u64,
    first_connection_failure: Option<String>,
    shutdown: ShutdownStats,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl RemoteComputationServiceReport {
    /// Connections accepted from the operating-system listener.
    #[must_use]
    pub const fn accepted_connections(&self) -> u64 {
        self.accepted_connections
    }

    /// Accepted sockets refused by the listener-wide capacity/drain gate.
    #[must_use]
    pub const fn capacity_rejections(&self) -> u64 {
        self.capacity_rejections
    }

    /// Connections that completed one fully flushed service exchange.
    #[must_use]
    pub const fn completed_connections(&self) -> u64 {
        self.completed_connections
    }

    /// Connections interrupted by cancellation or force-close.
    #[must_use]
    pub const fn interrupted_connections(&self) -> u64 {
        self.interrupted_connections
    }

    /// Connections that terminated with a transport, TLS, or protocol error.
    #[must_use]
    pub const fn failed_connections(&self) -> u64 {
        self.failed_connections
    }

    /// Connection tasks that crossed a panic boundary.
    #[must_use]
    pub const fn panicked_connections(&self) -> u64 {
        self.panicked_connections
    }

    /// First connection-scoped failure retained for bounded diagnostics.
    #[must_use]
    pub fn first_connection_failure(&self) -> Option<&str> {
        self.first_connection_failure.as_deref()
    }

    /// Connection-level graceful-drain accounting.
    #[must_use]
    pub const fn shutdown(&self) -> &ShutdownStats {
        &self.shutdown
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemoteConnectionCompletion {
    Completed,
    Interrupted,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
#[derive(Default)]
struct RemoteConnectionOutcomeCounts {
    completed: u64,
    interrupted: u64,
    failed: u64,
    panicked: u64,
    first_failure: Option<String>,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl RemoteConnectionOutcomeCounts {
    fn record(
        &mut self,
        outcome: Outcome<RemoteConnectionCompletion, RemoteComputationConnectionError>,
    ) {
        match outcome {
            Outcome::Ok(RemoteConnectionCompletion::Completed) => {
                self.completed = self.completed.saturating_add(1);
            }
            Outcome::Ok(RemoteConnectionCompletion::Interrupted) | Outcome::Cancelled(_) => {
                self.interrupted = self.interrupted.saturating_add(1);
            }
            Outcome::Err(error) => {
                self.failed = self.failed.saturating_add(1);
                if self.first_failure.is_none() {
                    self.first_failure = Some(error.to_string());
                }
            }
            Outcome::Panicked(_) => {
                self.panicked = self.panicked.saturating_add(1);
                if self.first_failure.is_none() {
                    self.first_failure =
                        Some("remote computation connection task panicked".to_owned());
                }
            }
        }
    }
}

/// TCP+mTLS listener that owns every connection through a child region.
///
/// `run` opens one child region, admits every connection through a region-owned
/// [`JoinSet`], stops acceptance before drain, races handshake/request/flush
/// against force-close and task cancellation, joins every connection outcome,
/// and closes the child region only after quiescence. V1/V2 connections perform
/// exactly one request. A V3 connection admits one request and then owns its
/// cancel/renew lifecycle until a terminal event. V2/V3 requests share this
/// listener's authenticated-peer-scoped idempotency state; durable restart
/// recovery and a production `RemoteRuntime` driver remain separate layers.
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
pub struct RemoteComputationService {
    tcp_listener: TcpListener,
    tls_acceptor: Arc<TlsAcceptor>,
    policy: Arc<RemotePeerAdmissionPolicy>,
    computations: Arc<RemoteComputationRegistry>,
    idempotency: Arc<RemoteServiceIdempotency>,
    config: RemoteComputationServiceConfig,
    shutdown_signal: ShutdownSignal,
    connections: ConnectionManager,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl fmt::Debug for RemoteComputationService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteComputationService")
            .field("local_addr", &self.tcp_listener.local_addr().ok())
            .field("config", &self.config)
            .field("shutdown_phase", &self.shutdown_signal.phase())
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
impl RemoteComputationService {
    /// Binds a structured authenticated computation listener.
    pub async fn bind<A>(
        addr: A,
        tls_acceptor: TlsAcceptor,
        policy: RemotePeerAdmissionPolicy,
        computations: RemoteComputationRegistry,
        config: RemoteComputationServiceConfig,
    ) -> Result<Self, RemoteComputationListenerError>
    where
        A: ToSocketAddrs + Send + 'static,
    {
        if config.wire_limits.max_frame_bytes() == 0 {
            return Err(RemoteComputationListenerError::InvalidFrameLimit);
        }
        if config.initial_frame_timeout.is_zero() {
            return Err(RemoteComputationListenerError::InvalidInitialFrameTimeout);
        }
        if config.idempotency_retention.is_zero() {
            return Err(RemoteComputationListenerError::InvalidIdempotencyRetention);
        }
        if config.max_idempotency_records_per_peer == 0 {
            return Err(RemoteComputationListenerError::InvalidIdempotencyCapacity);
        }
        let tcp_listener = TcpListener::bind(addr)
            .await
            .map_err(RemoteComputationListenerError::Transport)?;
        Self::from_listener(tcp_listener, tls_acceptor, policy, computations, config)
    }

    /// Constructs the service around an already-bound listener.
    pub fn from_listener(
        tcp_listener: TcpListener,
        tls_acceptor: TlsAcceptor,
        policy: RemotePeerAdmissionPolicy,
        computations: RemoteComputationRegistry,
        config: RemoteComputationServiceConfig,
    ) -> Result<Self, RemoteComputationListenerError> {
        if config.wire_limits.max_frame_bytes() == 0 {
            return Err(RemoteComputationListenerError::InvalidFrameLimit);
        }
        if config.initial_frame_timeout.is_zero() {
            return Err(RemoteComputationListenerError::InvalidInitialFrameTimeout);
        }
        if config.idempotency_retention.is_zero() {
            return Err(RemoteComputationListenerError::InvalidIdempotencyRetention);
        }
        if config.max_idempotency_records_per_peer == 0 {
            return Err(RemoteComputationListenerError::InvalidIdempotencyCapacity);
        }
        let shutdown_signal = ShutdownSignal::new();
        let connections = ConnectionManager::new(config.max_connections, shutdown_signal.clone());
        let idempotency = Arc::new(RemoteServiceIdempotency::new(
            config.idempotency_retention,
            config.max_idempotency_records_per_peer,
        ));
        Ok(Self {
            tcp_listener,
            tls_acceptor: Arc::new(tls_acceptor),
            policy: Arc::new(policy),
            computations: Arc::new(computations),
            idempotency,
            config,
            shutdown_signal,
            connections,
        })
    }

    /// Cloneable drain/force-close handle for operator ownership.
    #[must_use]
    pub fn handle(&self) -> RemoteComputationServiceHandle {
        RemoteComputationServiceHandle {
            shutdown_signal: self.shutdown_signal.clone(),
            connections: self.connections.clone(),
            drain_timeout: self.config.drain_timeout,
        }
    }

    /// Local address selected by the bound listener.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp_listener.local_addr()
    }

    /// Runs until drain, parent cancellation, or a fatal listener error.
    ///
    /// Connection-scoped TLS/protocol failures are counted in the returned
    /// report and never kill the accept loop. Fatal listener/spawn failures
    /// first drain all admitted connection tasks and close their child region,
    /// then return the typed error.
    pub async fn run(
        self,
        cx: &Cx,
    ) -> Result<RemoteComputationServiceReport, RemoteComputationListenerError> {
        let child_region = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .map_err(RemoteComputationListenerError::ChildRegion)?;
        let service_cx = child_region.cx().clone();
        let mut connection_tasks = JoinSet::in_cx(&service_cx);
        let mut shutdown_rx = self.shutdown_signal.subscribe();
        let mut accepted_connections = 0_u64;
        let mut capacity_rejections = 0_u64;
        let mut connection_outcomes = RemoteConnectionOutcomeCounts::default();
        let mut fatal_error = None;

        loop {
            if self.shutdown_signal.is_shutting_down() || cx.checkpoint().is_err() {
                break;
            }
            while let Some(outcome) = connection_tasks.try_join_next() {
                connection_outcomes.record(outcome);
            }

            let accepted = remote_service_accept_or_shutdown(
                cx,
                &self.tcp_listener,
                &self.shutdown_signal,
                &mut shutdown_rx,
            )
            .await;
            let accepted = match accepted {
                RemoteServiceAccept::Shutdown => break,
                RemoteServiceAccept::Accepted(result) => result,
            };
            let (stream, peer_addr) = match accepted {
                Ok(connection) => connection,
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted
                        && (cx.is_cancel_requested()
                            || self.shutdown_signal.is_shutting_down()) =>
                {
                    break;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    continue;
                }
                Err(error) => {
                    fatal_error = Some(RemoteComputationListenerError::Transport(error));
                    break;
                }
            };
            accepted_connections = accepted_connections.saturating_add(1);

            let Some(guard) = self.connections.register(peer_addr) else {
                capacity_rejections = capacity_rejections.saturating_add(1);
                drop(stream);
                continue;
            };

            let tls_acceptor = Arc::clone(&self.tls_acceptor);
            let policy = Arc::clone(&self.policy);
            let computations = Arc::clone(&self.computations);
            let idempotency = Arc::clone(&self.idempotency);
            let shutdown_signal = self.shutdown_signal.clone();
            let wire_limits = self.config.wire_limits;
            let initial_frame_timeout = self.config.initial_frame_timeout;
            if let Err(error) =
                connection_tasks.spawn(&service_cx, move |connection_cx| async move {
                    let _guard = guard;
                    let exchange = async {
                        let mut stream = tls_acceptor
                            .accept(stream)
                            .await
                            .map_err(RemoteComputationConnectionError::Tls)?;
                        serve_tls_computation_once_with_idempotency(
                            &connection_cx,
                            &mut stream,
                            &policy,
                            &computations,
                            wire_limits,
                            Some(&idempotency),
                            RemoteServiceExecutionMode::LeaseBound,
                            Some(initial_frame_timeout),
                        )
                        .await
                        .map_err(RemoteComputationConnectionError::Service)?;
                        Ok::<_, RemoteComputationConnectionError>(
                            RemoteConnectionCompletion::Completed,
                        )
                    };
                    Ok(
                        match race_remote_service_termination(
                            &connection_cx,
                            &shutdown_signal,
                            exchange,
                        )
                        .await
                        {
                            Some(result) => return result,
                            None => RemoteConnectionCompletion::Interrupted,
                        },
                    )
                })
            {
                fatal_error = Some(RemoteComputationListenerError::Spawn(error));
                break;
            }
        }

        // Close the admission surface before waiting for existing connection
        // tasks. Otherwise new peers can complete the TCP handshake into the
        // kernel backlog after the service has committed to drain.
        drop(self.tcp_listener);

        if self.shutdown_signal.phase() == ShutdownPhase::Running {
            let _ = self.connections.begin_drain(self.config.drain_timeout);
        }
        let mut shutdown = self.connections.drain_with_stats().await;
        let was_force_closing = self.shutdown_signal.phase() == ShutdownPhase::ForceClosing;
        let outcomes = connection_tasks.join_all(&service_cx).await;

        for outcome in outcomes {
            connection_outcomes.record(outcome);
        }

        let close_result = child_region
            .close()
            .await
            .map_err(RemoteComputationListenerError::ChildRegion);
        if self.connections.is_empty() {
            self.shutdown_signal.mark_stopped();
            if was_force_closing {
                let drain_report = shutdown.drain_report.take();
                shutdown = self
                    .shutdown_signal
                    .collect_stats(shutdown.drained, shutdown.force_closed);
                shutdown.drain_report = drain_report;
            }
        }

        let report = RemoteComputationServiceReport {
            accepted_connections,
            capacity_rejections,
            completed_connections: connection_outcomes.completed,
            interrupted_connections: connection_outcomes.interrupted,
            failed_connections: connection_outcomes.failed,
            panicked_connections: connection_outcomes.panicked,
            first_connection_failure: connection_outcomes.first_failure,
            shutdown,
        };

        if let Some(error) = fatal_error {
            return Err(error);
        }
        close_result?;
        Ok(report)
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
enum RemoteServiceAccept {
    Accepted(io::Result<(crate::net::TcpStream, SocketAddr)>),
    Shutdown,
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
async fn remote_service_accept_or_shutdown(
    cx: &Cx,
    listener: &TcpListener,
    shutdown_signal: &ShutdownSignal,
    shutdown_rx: &mut crate::signal::ShutdownReceiver,
) -> RemoteServiceAccept {
    let mut accept = core::pin::pin!(listener.accept());
    let mut shutdown = core::pin::pin!(shutdown_rx.wait());
    std::future::poll_fn(|task_cx| {
        if cx.checkpoint().is_err() || shutdown_signal.is_shutting_down() {
            return std::task::Poll::Ready(RemoteServiceAccept::Shutdown);
        }
        if shutdown.as_mut().poll(task_cx).is_ready() {
            return std::task::Poll::Ready(RemoteServiceAccept::Shutdown);
        }
        accept
            .as_mut()
            .poll(task_cx)
            .map(RemoteServiceAccept::Accepted)
    })
    .await
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
async fn race_remote_service_termination<F>(
    cx: &Cx,
    shutdown_signal: &ShutdownSignal,
    future: F,
) -> Option<F::Output>
where
    F: Future,
{
    let mut future = core::pin::pin!(future);
    let mut force_close =
        core::pin::pin!(shutdown_signal.wait_for_phase(ShutdownPhase::ForceClosing));
    std::future::poll_fn(|task_cx| {
        if cx.checkpoint().is_err()
            || shutdown_signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8
        {
            return std::task::Poll::Ready(None);
        }
        if force_close.as_mut().poll(task_cx).is_ready() {
            return std::task::Poll::Ready(None);
        }
        future.as_mut().poll(task_cx).map(Some)
    })
    .await
}

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
/// While its idempotency record is retained, a duplicate `SpawnRequest` with
/// the same key receives an accepted acknowledgement correlated to its current
/// delivery attempt and attaches to the canonical execution without
/// re-executing. The guarantee is scoped to the remote store lifetime and its
/// configured post-terminal retention window.
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
/// This mirrors the local [`Outcome`] lattice but
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

/// Outcome of a late spawn acknowledgement after the origin already sent cancel.
pub enum OriginCancelAckOutcome {
    /// Spawn was accepted before the cancel arrived; keep waiting for the
    /// terminal result under the existing cancel-sent state.
    Accepted(OriginSession<OriginCancelSent>),
    /// Spawn was rejected; the session terminates immediately.
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
    /// Receive a late spawn acknowledgement after sending cancel before ack.
    pub fn recv_spawn_ack(
        self,
        ack: &SpawnAck,
    ) -> Result<OriginCancelAckOutcome, RemoteProtocolError> {
        self.ensure_id(ack.remote_task_id)?;
        match ack.status {
            SpawnAckStatus::Accepted => Ok(OriginCancelAckOutcome::Accepted(self)),
            SpawnAckStatus::Rejected(_) => Ok(OriginCancelAckOutcome::Rejected(self.transition())),
        }
    }

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
    /// Send a lease renewal heartbeat while cancellation is draining.
    pub fn send_lease_renewal(self, renewal: &LeaseRenewal) -> Result<Self, RemoteProtocolError> {
        self.ensure_id(renewal.remote_task_id)?;
        Ok(self)
    }

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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use parking_lot::Mutex;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn lamport_raw(time: &LogicalTime) -> u64 {
        match time {
            LogicalTime::Lamport(time) => time.raw(),
            other => panic!("expected Lamport logical time, got {other:?}"),
        }
    }

    fn test_request_fingerprint(name: &str) -> IdempotencyRequestFingerprint {
        IdempotencyRequestFingerprint::new(ComputationName::new(name), RemoteInput::empty())
    }

    #[cfg(feature = "tls")]
    #[test]
    fn remote_service_protocol_classifier_is_explicit_and_fail_closed() {
        assert_eq!(
            remote_service_protocol_kind(RemoteProtocolVersion::V1),
            RemoteServiceProtocolKind::V1OneShot
        );
        assert_eq!(
            remote_service_protocol_kind(RemoteProtocolVersion::V2),
            RemoteServiceProtocolKind::V2Idempotent
        );
        assert_eq!(
            remote_service_protocol_kind(RemoteProtocolVersion::V3),
            RemoteServiceProtocolKind::V3Session
        );
        assert_eq!(
            remote_service_protocol_kind(RemoteProtocolVersion::new(2, 1)),
            RemoteServiceProtocolKind::Unsupported
        );
        assert_eq!(
            remote_service_protocol_kind(RemoteProtocolVersion::new(4, 0)),
            RemoteServiceProtocolKind::Unsupported
        );
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[test]
    fn remote_service_v3_renewal_sequence_never_wraps() {
        assert_eq!(remote_service_v3_next_renewal_id(None), Some(1));
        assert_eq!(remote_service_v3_next_renewal_id(Some(1)), Some(2));
        assert_eq!(
            remote_service_v3_next_renewal_id(Some(u64::MAX - 1)),
            Some(u64::MAX)
        );
        assert_eq!(remote_service_v3_next_renewal_id(Some(u64::MAX)), None);
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[test]
    fn remote_service_lease_expiry_wins_at_exact_boundary() {
        let expires_at = Time::from_nanos(50);
        assert!(!remote_service_lease_expired(
            Time::from_nanos(49),
            expires_at
        ));
        assert!(remote_service_lease_expired(expires_at, expires_at));
        assert!(remote_service_lease_expired(
            Time::from_nanos(51),
            expires_at
        ));
    }

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
        assert_eq!(cap.phase0_simulation(), &Phase0SimulationConfig::default());
    }

    #[test]
    fn remote_cap_builder() {
        let cap = RemoteCap::new()
            .with_default_lease(Duration::from_secs(60))
            .with_remote_budget(Budget::INFINITE)
            .with_local_node(NodeId::new("origin-a"))
            .with_phase0_failure(Phase0RemoteFailure::NodeDown)
            .with_phase0_timeout(Duration::from_secs(2));
        assert_eq!(cap.default_lease(), Duration::from_secs(60));
        assert!(cap.remote_budget().is_some());
        assert_eq!(cap.local_node().as_str(), "origin-a");
        assert_eq!(
            cap.phase0_simulation().failure,
            Phase0RemoteFailure::NodeDown
        );
        assert_eq!(cap.phase0_simulation().timeout, Duration::from_secs(2));
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

        fn clear_task_state(&self, _task_id: RemoteTaskId) {
            // No state to clear in capture runtime.
        }

        fn unregister_task(&self, _task_id: RemoteTaskId) {
            // No registration state to clean up in capture runtime.
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

        fn clear_task_state(&self, _task_id: RemoteTaskId) {
            // No persistent state to clear in failing send runtime.
        }

        fn unregister_task(&self, task_id: RemoteTaskId) {
            self.unregistered.lock().push(task_id);
        }
    }

    #[derive(Debug, Default)]
    struct LifecycleRuntime {
        sent: Mutex<Vec<(NodeId, MessageEnvelope<RemoteMessage>)>>,
        pending: Mutex<BTreeMap<RemoteTaskId, oneshot::Sender<Result<RemoteOutcome, RemoteError>>>>,
        states: Mutex<BTreeMap<RemoteTaskId, RemoteTaskState>>,
    }

    impl LifecycleRuntime {
        fn mark_state(&self, task_id: RemoteTaskId, state: RemoteTaskState) {
            self.states.lock().insert(task_id, state);
        }

        fn close_sender_preserving_state(&self, task_id: RemoteTaskId) {
            self.pending.lock().remove(&task_id);
        }

        fn deliver(
            &self,
            _cx: &Cx,
            task_id: RemoteTaskId,
            result: Result<RemoteOutcome, RemoteError>,
        ) {
            let state = match &result {
                Ok(RemoteOutcome::Success(_)) => RemoteTaskState::Completed,
                Ok(RemoteOutcome::Cancelled(_)) | Err(RemoteError::Cancelled(_)) => {
                    RemoteTaskState::Cancelled
                }
                Err(RemoteError::LeaseExpired) => RemoteTaskState::LeaseExpired,
                Ok(RemoteOutcome::Failed(_) | RemoteOutcome::Panicked(_)) | Err(_) => {
                    RemoteTaskState::Failed
                }
            };
            self.states.lock().insert(task_id, state);
            let tx = self
                .pending
                .lock()
                .remove(&task_id)
                .expect("pending remote task");
            if tx.send_blocking(result).is_err() {
                self.states.lock().remove(&task_id);
            }
        }

        fn sent_messages(&self) -> Vec<(NodeId, MessageEnvelope<RemoteMessage>)> {
            self.sent.lock().clone()
        }

        fn pending_count(&self) -> usize {
            self.pending.lock().len()
        }

        fn state_count(&self) -> usize {
            self.states.lock().len()
        }
    }

    fn last_remote_message(runtime: &LifecycleRuntime) -> RemoteMessage {
        runtime
            .sent_messages()
            .last()
            .expect("expected a sent remote message")
            .1
            .payload
            .clone()
    }

    fn last_spawn_request(runtime: &LifecycleRuntime) -> SpawnRequest {
        match last_remote_message(runtime) {
            RemoteMessage::SpawnRequest(request) => request,
            other => panic!("expected SpawnRequest, got {other:?}"),
        }
    }

    fn last_cancel_request(runtime: &LifecycleRuntime) -> CancelRequest {
        match last_remote_message(runtime) {
            RemoteMessage::CancelRequest(request) => request,
            other => panic!("expected CancelRequest, got {other:?}"),
        }
    }

    fn assert_runtime_drained(runtime: &LifecycleRuntime) {
        assert_eq!(runtime.pending_count(), 0, "pending remote result senders");
        assert_eq!(runtime.state_count(), 0, "tracked remote lifecycle states");
    }

    fn trace_messages(trace: &crate::trace::TraceBufferHandle) -> Vec<String> {
        trace
            .snapshot()
            .into_iter()
            .filter_map(|event| match event.data {
                crate::trace::TraceData::Message(message) => Some(message),
                _ => None,
            })
            .collect()
    }

    impl RemoteRuntime for LifecycleRuntime {
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
            task_id: RemoteTaskId,
            tx: oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
        ) {
            self.pending.lock().insert(task_id, tx);
            self.states.lock().insert(task_id, RemoteTaskState::Pending);
        }

        fn observe_task_state(&self, task_id: RemoteTaskId) -> Option<RemoteTaskState> {
            self.states.lock().get(&task_id).copied()
        }

        fn clear_task_state(&self, task_id: RemoteTaskId) {
            self.pending.lock().remove(&task_id);
            self.states.lock().remove(&task_id);
        }

        fn unregister_task(&self, task_id: RemoteTaskId) {
            self.pending.lock().remove(&task_id);
            self.states.lock().remove(&task_id);
        }
    }

    fn fast_phase0_cap() -> RemoteCap {
        RemoteCap::new().with_phase0_failure(Phase0RemoteFailure::NodeUnreachable)
    }

    fn timeout_phase0_cap() -> RemoteCap {
        RemoteCap::new().with_phase0_failure(Phase0RemoteFailure::Timeout)
    }

    #[test]
    fn spawn_remote_uses_cap_local_node_for_origin() {
        let runtime = Arc::new(CaptureRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let handle = spawn_remote(
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
        assert!(lamport_raw(&envelope.sender_time) > 0);
        match &envelope.payload {
            RemoteMessage::SpawnRequest(req) => {
                assert_eq!(req.remote_task_id, handle.remote_task_id());
                assert_eq!(req.origin_node.as_str(), "origin-a");
            }
            other => unreachable!("expected SpawnRequest, got {other:?}"),
        }
    }

    #[test]
    fn remote_handle_abort_with_attached_runtime_sends_cancel_request() {
        let runtime = Arc::new(CaptureRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        handle.abort(&cx);

        let (destination, envelope, spawn_time) = {
            let sent = runtime.sent.lock();
            assert_eq!(sent.len(), 2);
            (
                sent[1].0.clone(),
                sent[1].1.clone(),
                lamport_raw(&sent[0].1.sender_time),
            )
        };
        assert_eq!(destination.as_str(), "worker-1");
        assert_eq!(envelope.sender.as_str(), "origin-a");
        assert!(lamport_raw(&envelope.sender_time) > spawn_time);
        match &envelope.payload {
            RemoteMessage::CancelRequest(req) => {
                assert_eq!(req.remote_task_id, handle.remote_task_id());
                assert_eq!(req.origin_node.as_str(), "origin-a");
                assert_eq!(req.reason, CancelReason::user("remote handle abort"));
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
        }
    }

    #[test]
    fn remote_handle_abort_uses_handle_origin_even_with_different_caller_cap() {
        let runtime = Arc::new(CaptureRuntime::default());
        let spawn_cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let spawn_cx: Cx = Cx::for_testing_with_remote(spawn_cap);

        let handle = spawn_remote(
            &spawn_cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let abort_cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-b"))
            .with_runtime(runtime.clone());
        let abort_cx: Cx = Cx::for_testing_with_remote(abort_cap);
        let expected_reason = CancelReason::deadline();
        abort_cx.set_cancel_reason(expected_reason.clone());

        handle.abort(&abort_cx);

        let (destination, envelope, spawn_time) = {
            let sent = runtime.sent.lock();
            assert_eq!(sent.len(), 2);
            (
                sent[1].0.clone(),
                sent[1].1.clone(),
                lamport_raw(&sent[0].1.sender_time),
            )
        };
        assert_eq!(destination.as_str(), "worker-1");
        assert_eq!(envelope.sender.as_str(), "origin-a");
        assert!(lamport_raw(&envelope.sender_time) > spawn_time);
        match &envelope.payload {
            RemoteMessage::CancelRequest(req) => {
                assert_eq!(req.remote_task_id, handle.remote_task_id());
                assert_eq!(req.origin_node.as_str(), "origin-a");
                assert_eq!(req.reason, expected_reason);
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
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

        let err = RemoteError::NodeDown("worker-9".into());
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
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
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
        assert_eq!(handle.state(), RemoteTaskState::Failed);
        assert!(handle.is_finished());
        assert_eq!(handle.lease(), Duration::from_secs(30));
        assert!(handle.local_task_id().is_none());
    }

    #[test]
    fn remote_handle_debug() {
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
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
    fn remote_handle_phase0_fallback_finishes_immediately() {
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        let handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("add"),
            RemoteInput::empty(),
        )
        .unwrap();

        assert!(handle.is_finished());
        assert_eq!(handle.state(), RemoteTaskState::Failed);
    }

    #[test]
    fn remote_handle_try_join_phase0_fallback_returns_configured_error() {
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        let mut handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("work"),
            RemoteInput::empty(),
        )
        .unwrap();

        let err = handle
            .try_join()
            .expect_err("phase-0 fallback should fail explicitly");
        assert!(matches!(err, RemoteError::NodeUnreachable(_)));
        assert_eq!(handle.state(), RemoteTaskState::Failed);
    }

    #[test]
    fn phase0_fallback_publication_is_independent_of_caller_cancellation() {
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        cx.cancel_with(
            crate::types::CancelKind::User,
            Some("cancel before remote fallback"),
        );

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("cancelled-caller-fallback"),
            RemoteInput::empty(),
        )
        .expect("terminal fallback publication must not be cancelled by its caller Cx");

        let err = handle
            .try_join()
            .expect_err("the configured phase-0 failure must remain observable");
        assert!(matches!(err, RemoteError::NodeUnreachable(_)));
        assert_eq!(handle.state(), RemoteTaskState::Failed);
    }

    #[test]
    fn remote_handle_join_updates_terminal_state() {
        let cap = RemoteCap::new().with_phase0_simulation(Phase0SimulationConfig {
            failure: Phase0RemoteFailure::NodeDown,
            retry: Phase0RetryPolicy {
                max_attempts: 2,
                initial_backoff: Duration::from_millis(2),
                max_backoff: Duration::from_millis(2),
            },
            timeout: Duration::from_millis(20),
        });
        let cx: Cx = Cx::for_testing_with_remote(cap);
        let mut handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("join-state"),
            RemoteInput::empty(),
        )
        .expect("spawn");

        assert_eq!(handle.state(), RemoteTaskState::Failed);
        let result = futures_lite::future::block_on(handle.join(&cx));
        assert!(matches!(result, Outcome::Err(RemoteError::NodeDown(_))));
        assert_eq!(handle.state(), RemoteTaskState::Failed);
        assert!(handle.is_finished());
    }

    #[test]
    fn remote_handle_try_join_updates_terminal_state() {
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        let mut handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("try-join-state"),
            RemoteInput::empty(),
        )
        .expect("spawn");

        let err = handle
            .try_join()
            .expect_err("phase-0 fallback should fail explicitly");
        assert!(matches!(err, RemoteError::NodeUnreachable(_)));
        assert_eq!(handle.state(), RemoteTaskState::Failed);
    }

    #[test]
    fn remote_handle_phase0_timeout_maps_to_cancelled_state() {
        let cx: Cx = Cx::for_testing_with_remote(timeout_phase0_cap());
        let mut handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("timeout-state"),
            RemoteInput::empty(),
        )
        .expect("spawn");

        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
        let result = futures_lite::future::block_on(handle.join(&cx));
        assert!(matches!(
            result,
            Outcome::Err(RemoteError::Cancelled(reason))
                if reason.kind == crate::types::CancelKind::Timeout
        ));
        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
    }

    #[test]
    fn remote_handle_state_observes_runtime_lifecycle() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        assert_eq!(handle.state(), RemoteTaskState::Pending);

        runtime.mark_state(handle.remote_task_id(), RemoteTaskState::Running);
        assert_eq!(handle.state(), RemoteTaskState::Running);

        runtime.deliver(
            &cx,
            handle.remote_task_id(),
            Ok(RemoteOutcome::Success(vec![9, 9, 9])),
        );
        assert_eq!(handle.state(), RemoteTaskState::Completed);

        let outcome = handle.try_join().expect("result").expect("outcome");
        assert!(matches!(outcome, RemoteOutcome::Success(_)));
        assert!(
            runtime
                .observe_task_state(handle.remote_task_id())
                .is_none()
        );
    }

    #[test]
    fn remote_handle_close_skips_cancel_when_runtime_result_is_already_buffered() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        runtime.mark_state(handle.remote_task_id(), RemoteTaskState::Running);
        runtime.deliver(
            &cx,
            handle.remote_task_id(),
            Ok(RemoteOutcome::Cancelled(CancelReason::user(
                "closed remotely",
            ))),
        );
        runtime.mark_state(handle.remote_task_id(), RemoteTaskState::Running);

        let outcome = futures_lite::future::block_on(handle.close(&cx)).expect("close");
        assert!(matches!(outcome, RemoteOutcome::Cancelled(_)));
        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
        assert!(
            runtime
                .observe_task_state(handle.remote_task_id())
                .is_none()
        );

        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            1,
            "ready terminal result should not trigger a late cancel"
        );
    }

    #[test]
    fn remote_handle_close_ignores_caller_cancellation_until_terminal_result_arrives() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);
        cx.set_cancel_reason(CancelReason::deadline());

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Running);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let outcome = {
            let mut close = std::pin::pin!(handle.close(&cx));

            assert!(matches!(
                std::future::Future::poll(close.as_mut(), &mut task_cx),
                Poll::Pending
            ));
            assert_eq!(
                runtime.observe_task_state(remote_task_id),
                Some(RemoteTaskState::Running)
            );

            runtime.deliver(
                &cx,
                remote_task_id,
                Ok(RemoteOutcome::Cancelled(CancelReason::user(
                    "closed remotely",
                ))),
            );

            match std::future::Future::poll(close.as_mut(), &mut task_cx) {
                Poll::Ready(outcome) => outcome,
                Poll::Pending => panic!("close should drain terminal result"),
            }
        };
        assert!(matches!(
            outcome,
            Outcome::Ok(RemoteOutcome::Cancelled(reason))
                if reason == CancelReason::user("closed remotely")
        ));
        assert!(runtime.observe_task_state(remote_task_id).is_none());

        let sent = runtime.sent_messages();
        assert_eq!(sent.len(), 2);
        assert!(lamport_raw(&sent[1].1.sender_time) > lamport_raw(&sent[0].1.sender_time));
        match &sent[1].1.payload {
            RemoteMessage::CancelRequest(cancel) => {
                assert_eq!(cancel.remote_task_id, remote_task_id);
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
        }
    }

    #[test]
    fn remote_handle_close_with_plain_context_still_requests_cancel_when_runtime_attached() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let spawn_cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let spawn_cx: Cx = Cx::for_testing_with_remote(spawn_cap);
        let close_cx: Cx = Cx::for_testing();
        let expected_reason = CancelReason::deadline();
        close_cx.set_cancel_reason(expected_reason.clone());

        let mut handle = spawn_remote(
            &spawn_cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Running);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let outcome = {
            let mut close = std::pin::pin!(handle.close(&close_cx));

            assert!(matches!(
                std::future::Future::poll(close.as_mut(), &mut task_cx),
                Poll::Pending
            ));

            let sent = runtime.sent_messages();
            assert_eq!(sent.len(), 2);
            match &sent[1].1.payload {
                RemoteMessage::CancelRequest(cancel) => {
                    assert_eq!(cancel.remote_task_id, remote_task_id);
                    assert_eq!(cancel.origin_node.as_str(), "origin-a");
                    assert_eq!(cancel.reason, expected_reason);
                }
                other => unreachable!("expected CancelRequest, got {other:?}"),
            }

            runtime.deliver(
                &spawn_cx,
                remote_task_id,
                Ok(RemoteOutcome::Cancelled(CancelReason::user(
                    "closed remotely",
                ))),
            );

            match std::future::Future::poll(close.as_mut(), &mut task_cx) {
                Poll::Ready(outcome) => outcome,
                Poll::Pending => panic!("close should drain terminal result"),
            }
        };

        assert!(matches!(
            outcome,
            Outcome::Ok(RemoteOutcome::Cancelled(reason))
                if reason == CancelReason::user("closed remotely")
        ));
        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
        assert!(runtime.observe_task_state(remote_task_id).is_none());
    }

    #[test]
    fn remote_handle_join_closed_channel_preserves_runtime_lease_expired_state() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::LeaseExpired);
        runtime.close_sender_preserving_state(remote_task_id);

        let err = futures_lite::future::block_on(handle.join(&cx))
            .expect_err("closed channel should surface the observed lease-expired state");
        assert_eq!(err, RemoteError::LeaseExpired);
        assert_eq!(handle.state(), RemoteTaskState::LeaseExpired);
        assert!(runtime.observe_task_state(remote_task_id).is_none());
    }

    #[test]
    fn remote_handle_join_closed_channel_reports_transport_error_for_failed_state() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Failed);
        runtime.close_sender_preserving_state(remote_task_id);

        let err = futures_lite::future::block_on(handle.join(&cx))
            .expect_err("closed terminal failed channel should surface a transport error");
        assert!(matches!(
            err,
            RemoteError::TransportError(msg) if msg.contains("Failed")
        ));
        assert_eq!(handle.state(), RemoteTaskState::Failed);
        assert!(runtime.observe_task_state(remote_task_id).is_none());
    }

    #[test]
    fn remote_handle_try_join_closed_channel_reports_transport_error_for_completed_state() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Completed);
        runtime.close_sender_preserving_state(remote_task_id);

        let err = handle
            .try_join()
            .expect_err("closed terminal completed channel should surface a transport error");
        assert!(matches!(
            err,
            RemoteError::TransportError(msg) if msg.contains("Completed")
        ));
        assert_eq!(handle.state(), RemoteTaskState::Completed);
        assert!(runtime.observe_task_state(remote_task_id).is_none());
    }

    #[test]
    fn remote_handle_close_closed_channel_still_requests_cancel_for_live_runtime_task() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Running);
        runtime.close_sender_preserving_state(remote_task_id);

        let err = futures_lite::future::block_on(handle.close(&cx))
            .expect_err("closed live channel should still fail the close");
        assert_eq!(err, RemoteError::Cancelled(RemoteHandle::closed_reason()));
        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
        assert!(runtime.observe_task_state(remote_task_id).is_none());

        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            2,
            "close should still send a best-effort cancel when the runtime still observes a live remote task"
        );
        match &sent[1].1.payload {
            RemoteMessage::CancelRequest(cancel) => {
                assert_eq!(cancel.remote_task_id, remote_task_id);
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
        }
    }

    #[test]
    fn remote_handle_drop_cancels_live_runtime_task_but_preserves_runtime_state() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let remote_task_id = {
            let handle = spawn_remote(
                &cx,
                NodeId::new("worker-1"),
                ComputationName::new("encode_block"),
                RemoteInput::new(vec![1, 2, 3]),
            )
            .expect("spawn_remote should succeed");

            let remote_task_id = handle.remote_task_id();
            runtime.mark_state(remote_task_id, RemoteTaskState::Running);
            remote_task_id
        };

        assert_eq!(
            runtime.observe_task_state(remote_task_id),
            Some(RemoteTaskState::Running),
            "dropping a live handle must preserve runtime bookkeeping until the remote lifecycle finishes"
        );
        let sent = runtime.sent_messages();
        assert_eq!(sent.len(), 2, "spawn + best-effort drop cancel");
        assert!(lamport_raw(&sent[1].1.sender_time) > lamport_raw(&sent[0].1.sender_time));
        match &sent[1].1.payload {
            RemoteMessage::CancelRequest(cancel) => {
                assert_eq!(cancel.remote_task_id, remote_task_id);
                assert_eq!(cancel.reason, CancelReason::user("remote handle dropped"));
                assert_eq!(cancel.origin_node.as_str(), "origin-a");
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
        }
    }

    #[test]
    fn remote_handle_drop_clears_runtime_state_after_terminal_result_is_observed() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let remote_task_id = {
            let handle = spawn_remote(
                &cx,
                NodeId::new("worker-1"),
                ComputationName::new("encode_block"),
                RemoteInput::new(vec![1, 2, 3]),
            )
            .expect("spawn_remote should succeed");

            let remote_task_id = handle.remote_task_id();
            runtime.deliver(
                &cx,
                remote_task_id,
                Ok(RemoteOutcome::Success(vec![7, 8, 9])),
            );
            remote_task_id
        };

        assert!(
            runtime.observe_task_state(remote_task_id).is_none(),
            "dropping a handle after the runtime observes a terminal result should clear bookkeeping"
        );
        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            1,
            "terminal drop should not send an extra cancel"
        );
    }

    #[test]
    fn remote_handle_abort_skips_cancel_when_terminal_result_is_already_buffered() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.deliver(
            &cx,
            remote_task_id,
            Ok(RemoteOutcome::Success(vec![7, 8, 9])),
        );
        runtime.mark_state(remote_task_id, RemoteTaskState::Running);

        handle.abort(&cx);

        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            1,
            "buffered terminal result should suppress late cancel"
        );

        let outcome = handle.try_join().expect("result").expect("outcome");
        assert!(matches!(outcome, RemoteOutcome::Success(_)));
        assert_eq!(handle.state(), RemoteTaskState::Completed);
    }

    #[test]
    fn remote_handle_drop_skips_cancel_when_terminal_result_is_buffered_but_state_is_stale() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let remote_task_id = {
            let handle = spawn_remote(
                &cx,
                NodeId::new("worker-1"),
                ComputationName::new("encode_block"),
                RemoteInput::new(vec![1, 2, 3]),
            )
            .expect("spawn_remote should succeed");

            let remote_task_id = handle.remote_task_id();
            runtime.deliver(
                &cx,
                remote_task_id,
                Ok(RemoteOutcome::Success(vec![7, 8, 9])),
            );
            runtime.mark_state(remote_task_id, RemoteTaskState::Running);
            remote_task_id
        };

        assert!(
            runtime.observe_task_state(remote_task_id).is_none(),
            "dropping with a buffered terminal result should clear runtime bookkeeping even if observed state was stale"
        );
        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            1,
            "stale running state must not trigger a late drop cancel"
        );
    }

    #[test]
    fn remote_handle_drop_preserves_terminal_runtime_state_until_sender_settles() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let remote_task_id = {
            let handle = spawn_remote(
                &cx,
                NodeId::new("worker-1"),
                ComputationName::new("encode_block"),
                RemoteInput::new(vec![1, 2, 3]),
            )
            .expect("spawn_remote should succeed");

            let remote_task_id = handle.remote_task_id();
            runtime.mark_state(remote_task_id, RemoteTaskState::Completed);
            remote_task_id
        };

        assert_eq!(
            runtime.observe_task_state(remote_task_id),
            Some(RemoteTaskState::Completed),
            "dropping after the runtime observes a terminal state must preserve bookkeeping until the terminal sender settles"
        );

        runtime.deliver(
            &cx,
            remote_task_id,
            Ok(RemoteOutcome::Success(vec![7, 8, 9])),
        );

        assert!(
            runtime.observe_task_state(remote_task_id).is_none(),
            "once the terminal sender settles into a dropped receiver, runtime bookkeeping should clear"
        );
        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            1,
            "terminal drop should not emit a late cancel while waiting for sender cleanup"
        );
    }

    #[test]
    fn remote_handle_abort_closed_channel_still_requests_cancel_for_live_runtime_task() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Running);
        runtime.close_sender_preserving_state(remote_task_id);

        handle.abort(&cx);

        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            2,
            "explicit abort should still fence a live remote task even if the result sender already disappeared"
        );
        match &sent[1].1.payload {
            RemoteMessage::CancelRequest(cancel) => {
                assert_eq!(cancel.remote_task_id, remote_task_id);
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
        }
        assert_eq!(
            runtime.observe_task_state(remote_task_id),
            Some(RemoteTaskState::Running)
        );
    }

    #[test]
    fn remote_handle_is_finished_stays_false_for_closed_channel_while_runtime_task_is_live() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Running);
        runtime.close_sender_preserving_state(remote_task_id);

        assert!(
            !handle.is_finished(),
            "closed result channel without a buffered terminal result must not look finished"
        );
        assert_eq!(handle.state(), RemoteTaskState::Running);

        let err = futures_lite::future::block_on(handle.close(&cx))
            .expect_err("closed live channel should still fail the close");
        assert_eq!(err, RemoteError::Cancelled(RemoteHandle::closed_reason()));
        assert!(
            handle.is_finished(),
            "close should transition the handle to a terminal state"
        );
        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
        assert!(runtime.observe_task_state(remote_task_id).is_none());
    }

    #[test]
    fn remote_handle_drop_closed_channel_still_requests_cancel_for_live_runtime_task() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let remote_task_id = {
            let handle = spawn_remote(
                &cx,
                NodeId::new("worker-1"),
                ComputationName::new("encode_block"),
                RemoteInput::new(vec![1, 2, 3]),
            )
            .expect("spawn_remote should succeed");

            let remote_task_id = handle.remote_task_id();
            runtime.mark_state(remote_task_id, RemoteTaskState::Running);
            runtime.close_sender_preserving_state(remote_task_id);
            remote_task_id
        };

        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            2,
            "dropping a live handle must still request cancel even if the result sender already disappeared"
        );
        match &sent[1].1.payload {
            RemoteMessage::CancelRequest(cancel) => {
                assert_eq!(cancel.remote_task_id, remote_task_id);
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
        }
        assert_eq!(
            runtime.observe_task_state(remote_task_id),
            Some(RemoteTaskState::Running)
        );
    }

    #[test]
    fn remote_handle_runtime_rejection_fails_closed() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        runtime.deliver(
            &cx,
            handle.remote_task_id(),
            Err(RemoteError::SpawnRejected(
                SpawnRejectReason::CapacityExceeded,
            )),
        );

        assert_eq!(handle.state(), RemoteTaskState::Failed);
        let err = handle
            .try_join()
            .expect_err("runtime rejection should surface as terminal error");
        assert_eq!(
            err,
            RemoteError::SpawnRejected(SpawnRejectReason::CapacityExceeded)
        );
        assert!(
            runtime
                .observe_task_state(handle.remote_task_id())
                .is_none()
        );
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
            origin_node: NodeId::new("origin"),
            node: NodeId::new("n1"),
            computation: ComputationName::new("compute"),
            owner_region: cx.region_id(),
            runtime: None,
            receiver: rx,
            sender_clock: cx.logical_clock_handle(),
            lease: Duration::from_secs(30),
            state: RemoteTaskState::Pending,
            completed: false,
        };

        let result = handle.try_join().expect("result").expect("outcome");
        assert!(matches!(result, RemoteOutcome::Cancelled(_)));
        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
    }

    #[test]
    fn remote_handle_try_join_fails_closed_after_completion() {
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = oneshot::channel::<Result<RemoteOutcome, RemoteError>>();
        tx.send(&cx, Ok(RemoteOutcome::Success(Vec::new())))
            .expect("send outcome");

        let mut handle = RemoteHandle {
            remote_task_id: RemoteTaskId::next(),
            local_task_id: None,
            origin_node: NodeId::new("origin"),
            node: NodeId::new("n1"),
            computation: ComputationName::new("compute"),
            owner_region: cx.region_id(),
            runtime: None,
            receiver: rx,
            sender_clock: cx.logical_clock_handle(),
            lease: Duration::from_secs(30),
            state: RemoteTaskState::Pending,
            completed: false,
        };

        let first = handle.try_join().expect("result").expect("outcome");
        assert!(matches!(first, RemoteOutcome::Success(_)));
        assert_eq!(handle.state(), RemoteTaskState::Completed);

        let second = handle.try_join();
        assert!(matches!(second, Err(RemoteError::PolledAfterCompletion)));
    }

    #[test]
    fn remote_handle_join_fails_closed_after_completion() {
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = oneshot::channel::<Result<RemoteOutcome, RemoteError>>();
        tx.send(&cx, Ok(RemoteOutcome::Success(Vec::new())))
            .expect("send outcome");

        let mut handle = RemoteHandle {
            remote_task_id: RemoteTaskId::next(),
            local_task_id: None,
            origin_node: NodeId::new("origin"),
            node: NodeId::new("n1"),
            computation: ComputationName::new("compute"),
            owner_region: cx.region_id(),
            runtime: None,
            receiver: rx,
            sender_clock: cx.logical_clock_handle(),
            lease: Duration::from_secs(30),
            state: RemoteTaskState::Pending,
            completed: false,
        };

        let first = futures_lite::future::block_on(handle.join(&cx)).expect("first join");
        assert!(matches!(first, RemoteOutcome::Success(_)));
        assert_eq!(handle.state(), RemoteTaskState::Completed);

        let second = futures_lite::future::block_on(handle.join(&cx));
        assert!(matches!(
            second,
            Outcome::Err(RemoteError::PolledAfterCompletion)
        ));
    }

    #[test]
    fn remote_handle_join_uses_caller_cancel_reason_for_cancelled_wait() {
        let cx: Cx = Cx::for_testing();
        let (_tx, rx) = oneshot::channel::<Result<RemoteOutcome, RemoteError>>();
        let expected = CancelReason::deadline();
        cx.set_cancel_reason(expected.clone());

        let mut handle = RemoteHandle {
            remote_task_id: RemoteTaskId::next(),
            local_task_id: None,
            origin_node: NodeId::new("origin"),
            node: NodeId::new("n1"),
            computation: ComputationName::new("compute"),
            owner_region: cx.region_id(),
            runtime: None,
            receiver: rx,
            sender_clock: cx.logical_clock_handle(),
            lease: Duration::from_secs(30),
            state: RemoteTaskState::Running,
            completed: false,
        };

        let result = futures_lite::future::block_on(handle.join(&cx));
        assert!(matches!(
            result,
            Outcome::Err(RemoteError::Cancelled(reason)) if reason == expected
        ));
        assert_eq!(handle.state(), RemoteTaskState::Running);
        assert!(matches!(handle.try_join(), Ok(None)));
    }

    #[test]
    fn remote_handle_abort_without_attached_runtime_is_noop() {
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        let handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("long_task"),
            RemoteInput::empty(),
        )
        .unwrap();

        handle.abort(&cx);
    }

    #[test]
    fn remote_cap_custom_lease_propagates() {
        let cap = fast_phase0_cap().with_default_lease(Duration::from_secs(120));
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("slow"),
            RemoteInput::empty(),
        )
        .unwrap();

        assert_eq!(handle.lease(), Duration::from_secs(120));
    }

    #[test]
    fn remote_virtual_lifecycle_proof_exercises_runtime_transport_and_protocol() {
        let trace = crate::trace::TraceBufferHandle::new(96);
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);
        cx.set_trace_buffer(trace.clone());

        let mut success = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should enqueue a virtual transport request");
        let success_req = last_spawn_request(runtime.as_ref());
        let success_id = success.remote_task_id();
        let success_ack = test_ack_accepted(success_id);
        let origin = OriginSession::<OriginInit>::new(success_id)
            .send_spawn(&success_req)
            .expect("origin sends spawn");
        let remote = RemoteSession::<RemoteInit>::new(success_id)
            .recv_spawn(&success_req)
            .expect("remote receives spawn");
        let origin = match origin
            .recv_spawn_ack(&success_ack)
            .expect("origin receives accepted ack")
        {
            OriginAckOutcome::Accepted(session) => session,
            OriginAckOutcome::Rejected(_) => panic!("accepted ack must not reject"),
        };
        let remote = remote
            .send_ack_accepted(&success_ack)
            .expect("remote sends accepted ack");
        runtime.mark_state(success_id, RemoteTaskState::Running);

        let mut lease = Lease::new(
            test_obligation_id(),
            cx.region_id(),
            cx.task_id(),
            success_req.lease,
            Time::from_nanos(1_000_000_000),
        );
        assert!(lease.is_active(Time::from_nanos(1_000_000_000)));

        let renewal = LeaseRenewal {
            remote_task_id: success_id,
            new_lease: Duration::from_secs(15),
            current_state: RemoteTaskState::Running,
            node: NodeId::new("worker-1"),
        };
        let origin = origin
            .recv_lease_renewal(&renewal)
            .expect("origin accepts lease renewal");
        let remote = remote
            .send_lease_renewal(&renewal)
            .expect("remote sends lease renewal");
        lease
            .renew(renewal.new_lease, Time::from_secs(10))
            .expect("lease renewal extends liveness obligation");
        assert_eq!(lease.renewal_count(), 1);

        let success_result = ResultDelivery {
            remote_task_id: success_id,
            outcome: RemoteOutcome::Success(vec![9, 9, 9]),
            execution_time: Duration::from_millis(7),
        };
        let _remote_done = remote
            .send_result(&success_result)
            .expect("remote sends terminal result");
        let _origin_done = origin
            .recv_result(&success_result)
            .expect("origin receives terminal result");
        lease
            .release(Time::from_secs(11))
            .expect("terminal result releases lease");
        assert!(lease.is_released());
        runtime.deliver(&cx, success_id, Ok(success_result.outcome.clone()));

        let outcome = futures_lite::future::block_on(success.join(&cx))
            .expect("success result reaches origin handle");
        assert!(matches!(outcome, RemoteOutcome::Success(bytes) if bytes == vec![9, 9, 9]));
        assert_runtime_drained(runtime.as_ref());

        let mut cancelled_before_ack = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("pre_ack_cancel"),
            RemoteInput::new(vec![4]),
        )
        .expect("spawn before-ack cancel scenario");
        let cancel_before_req = last_spawn_request(runtime.as_ref());
        let cancel_before_id = cancelled_before_ack.remote_task_id();
        cancelled_before_ack.abort(&cx);
        let cancel_before = last_cancel_request(runtime.as_ref());
        let origin = OriginSession::<OriginInit>::new(cancel_before_id)
            .send_spawn(&cancel_before_req)
            .expect("origin sends spawn")
            .send_cancel(&cancel_before)
            .expect("origin sends cancel before ack");
        let remote = RemoteSession::<RemoteInit>::new(cancel_before_id)
            .recv_spawn(&cancel_before_req)
            .expect("remote receives spawn")
            .recv_cancel(&cancel_before)
            .expect("remote receives cancel before ack");
        let ack = test_ack_accepted(cancel_before_id);
        let origin = match origin
            .recv_spawn_ack(&ack)
            .expect("late ack after cancel is handled")
        {
            OriginCancelAckOutcome::Accepted(session) => session,
            OriginCancelAckOutcome::Rejected(_) => panic!("accepted late ack must not reject"),
        };
        let remote = remote
            .send_ack_accepted(&ack)
            .expect("remote accepts while cancel is pending");
        let result = ResultDelivery {
            remote_task_id: cancel_before_id,
            outcome: RemoteOutcome::Cancelled(CancelReason::user("cancelled before ack")),
            execution_time: Duration::from_millis(1),
        };
        let _remote_done = remote.send_result(&result).expect("remote drains cancel");
        let _origin_done = origin.recv_result(&result).expect("origin drains cancel");
        runtime.deliver(&cx, cancel_before_id, Ok(result.outcome.clone()));
        let outcome = futures_lite::future::block_on(cancelled_before_ack.join(&cx))
            .expect("cancelled result reaches origin handle");
        assert!(
            matches!(outcome, RemoteOutcome::Cancelled(reason) if reason == CancelReason::user("cancelled before ack"))
        );
        assert_runtime_drained(runtime.as_ref());

        let mut cancelled_running = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("running_cancel"),
            RemoteInput::new(vec![5]),
        )
        .expect("spawn running-cancel scenario");
        let running_req = last_spawn_request(runtime.as_ref());
        let running_id = cancelled_running.remote_task_id();
        let ack = test_ack_accepted(running_id);
        let origin = OriginSession::<OriginInit>::new(running_id)
            .send_spawn(&running_req)
            .expect("origin sends spawn");
        let remote = RemoteSession::<RemoteInit>::new(running_id)
            .recv_spawn(&running_req)
            .expect("remote receives spawn");
        let origin = match origin.recv_spawn_ack(&ack).expect("accepted ack") {
            OriginAckOutcome::Accepted(session) => session,
            OriginAckOutcome::Rejected(_) => panic!("accepted ack must not reject"),
        };
        let remote = remote.send_ack_accepted(&ack).expect("remote accepts");
        runtime.mark_state(running_id, RemoteTaskState::Running);
        let renewal = LeaseRenewal {
            remote_task_id: running_id,
            new_lease: Duration::from_secs(10),
            current_state: RemoteTaskState::Running,
            node: NodeId::new("worker-1"),
        };
        let origin = origin
            .recv_lease_renewal(&renewal)
            .expect("origin accepts running renewal");
        let remote = remote
            .send_lease_renewal(&renewal)
            .expect("remote sends running renewal");
        cancelled_running.abort(&cx);
        let cancel = last_cancel_request(runtime.as_ref());
        let origin = origin.send_cancel(&cancel).expect("origin sends cancel");
        let remote = remote.recv_cancel(&cancel).expect("remote receives cancel");
        let origin = origin
            .recv_lease_renewal(&renewal)
            .expect("origin accepts renewal while draining cancel");
        let remote = remote
            .send_lease_renewal(&renewal)
            .expect("remote renews while draining cancel");
        let result = ResultDelivery {
            remote_task_id: running_id,
            outcome: RemoteOutcome::Cancelled(CancelReason::user("cancelled while running")),
            execution_time: Duration::from_millis(3),
        };
        let _remote_done = remote
            .send_result(&result)
            .expect("remote sends cancel result");
        let _origin_done = origin
            .recv_result(&result)
            .expect("origin receives cancel result");
        runtime.deliver(&cx, running_id, Ok(result.outcome.clone()));
        let outcome = futures_lite::future::block_on(cancelled_running.join(&cx))
            .expect("running cancel reaches origin handle");
        assert!(
            matches!(outcome, RemoteOutcome::Cancelled(reason) if reason == CancelReason::user("cancelled while running"))
        );
        assert_runtime_drained(runtime.as_ref());

        let mut expired = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("lease_expiry"),
            RemoteInput::new(vec![6]),
        )
        .expect("spawn lease-expiry scenario");
        let expired_req = last_spawn_request(runtime.as_ref());
        let expired_id = expired.remote_task_id();
        let ack = test_ack_accepted(expired_id);
        let origin = OriginSession::<OriginInit>::new(expired_id)
            .send_spawn(&expired_req)
            .expect("origin sends spawn");
        let origin = match origin.recv_spawn_ack(&ack).expect("accepted ack") {
            OriginAckOutcome::Accepted(session) => session,
            OriginAckOutcome::Rejected(_) => panic!("accepted ack must not reject"),
        };
        let expired_cancel = CancelRequest {
            remote_task_id: expired_id,
            reason: CancelReason::deadline(),
            origin_node: NodeId::new("origin-a"),
        };
        let origin = origin
            .lease_expired()
            .send_cancel(&expired_cancel)
            .expect("lease expiry can request remote cleanup");
        let late_result = ResultDelivery {
            remote_task_id: expired_id,
            outcome: RemoteOutcome::Success(vec![1]),
            execution_time: Duration::from_millis(9),
        };
        let _origin_done = origin
            .recv_result(&late_result)
            .expect("late terminal result remains correlated");
        runtime.mark_state(expired_id, RemoteTaskState::LeaseExpired);
        runtime.close_sender_preserving_state(expired_id);
        let err = futures_lite::future::block_on(expired.join(&cx))
            .expect_err("closed lease-expired runtime state surfaces lease error");
        assert_eq!(err, RemoteError::LeaseExpired);
        assert_runtime_drained(runtime.as_ref());

        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let success_fingerprint = IdempotencyRequestFingerprint::from_spawn_request(&success_req);
        assert!(matches!(
            store.check(
                &success_req.idempotency_key,
                &success_fingerprint,
                Time::from_nanos(1_000_000_000)
            ),
            DedupDecision::New
        ));
        assert!(store.record(
            success_req.idempotency_key,
            success_id,
            success_fingerprint.clone(),
            Time::from_nanos(1_000_000_000),
        ));
        assert!(store.complete(
            &success_req.idempotency_key,
            success_id,
            RemoteOutcome::Success(vec![9, 9, 9]),
            Time::from_secs(1),
        ));
        match store.check(
            &success_req.idempotency_key,
            &success_fingerprint,
            Time::from_secs(1),
        ) {
            DedupDecision::Duplicate(record) => {
                assert_eq!(record.remote_task_id, success_id);
                assert!(
                    matches!(record.outcome, Some(RemoteOutcome::Success(bytes)) if bytes == vec![9, 9, 9])
                );
            }
            other => panic!("expected duplicate decision, got {other:?}"),
        }
        let conflict_fingerprint = IdempotencyRequestFingerprint::new(
            success_req.computation.clone(),
            RemoteInput::new(vec![0xff]),
        );
        assert!(matches!(
            store.check(
                &success_req.idempotency_key,
                &conflict_fingerprint,
                Time::from_secs(1),
            ),
            DedupDecision::Conflict
        ));

        let failing = Arc::new(FailingSendRuntime::default());
        let failing_cx: Cx =
            Cx::for_testing_with_remote(RemoteCap::new().with_runtime(failing.clone()));
        let err = spawn_remote(
            &failing_cx,
            NodeId::new("worker-1"),
            ComputationName::new("transport_failure"),
            RemoteInput::empty(),
        )
        .expect_err("send failure should fail spawn");
        assert!(
            matches!(err, RemoteError::TransportError(message) if message.contains("simulated send failure"))
        );
        let registered = failing.registered.lock().clone();
        assert_eq!(registered.len(), 1);
        assert_eq!(failing.unregistered.lock().clone(), registered);

        let fallback_cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        let mut fallback = spawn_remote(
            &fallback_cx,
            NodeId::new("missing-worker"),
            ComputationName::new("fallback"),
            RemoteInput::empty(),
        )
        .expect("phase-0 fallback creates a terminal handle");
        let err = fallback
            .try_join()
            .expect_err("phase-0 fallback surfaces configured error");
        assert!(matches!(err, RemoteError::NodeUnreachable(node) if node == "missing-worker"));

        let messages = trace_messages(&trace);
        for expected in [
            trace_events::SPAWN_REQUEST_CREATED,
            trace_events::SPAWN_REQUEST_SENT,
            trace_events::CANCEL_SENT,
            trace_events::RESULT_DELIVERED,
            trace_events::LEASE_EXPIRED,
        ] {
            assert!(
                messages.iter().any(|message| message == expected),
                "missing trace event {expected}; messages={messages:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Remote protocol contract tests
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
            lease: Duration::from_secs(60),
            idempotency_key: IdempotencyKey::generate(&cx),
            budget: None,
            origin_node: NodeId::new("origin-1"),
            origin_region: cx.region_id(),
            origin_task: cx.task_id(),
        };

        assert_eq!(req.computation.as_str(), "encode_block");
        assert_eq!(req.input.len(), 3);
        assert_eq!(req.lease, Duration::from_secs(60));
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
    fn origin_session_cancel_before_ack_then_late_accept_flow() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let origin = OriginSession::<OriginInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let origin = origin.send_spawn(&req).unwrap();
        let origin = origin.send_cancel(&test_cancel(rtid)).unwrap();
        let ack = test_ack_accepted(rtid);
        let outcome = origin.recv_spawn_ack(&ack).unwrap();
        assert!(matches!(outcome, OriginCancelAckOutcome::Accepted(_)));
        let origin = match outcome {
            OriginCancelAckOutcome::Accepted(session) => session,
            OriginCancelAckOutcome::Rejected(_) => return,
        };
        let result = test_result(
            rtid,
            RemoteOutcome::Cancelled(CancelReason::user("cancelled")),
        );
        let origin = origin.recv_result(&result).unwrap();
        assert_eq!(origin.remote_task_id(), rtid);
    }

    #[test]
    fn origin_session_cancel_before_ack_then_late_reject_flow() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let origin = OriginSession::<OriginInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let origin = origin.send_spawn(&req).unwrap();
        let origin = origin.send_cancel(&test_cancel(rtid)).unwrap();
        let ack = test_ack_rejected(rtid);
        let outcome = origin.recv_spawn_ack(&ack).unwrap();
        assert!(matches!(outcome, OriginCancelAckOutcome::Rejected(_)));
        if let OriginCancelAckOutcome::Rejected(session) = outcome {
            assert_eq!(session.remote_task_id(), rtid);
        }
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
    fn remote_session_cancelled_running_flow_allows_renewal_before_result() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let remote = RemoteSession::<RemoteInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let remote = remote.recv_spawn(&req).unwrap();
        let remote = remote.send_ack_accepted(&test_ack_accepted(rtid)).unwrap();
        let remote = remote.recv_cancel(&test_cancel(rtid)).unwrap();
        let remote = remote.send_lease_renewal(&test_renewal(rtid)).unwrap();
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
        RegionId::new_for_test(0, 1)
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
    fn lease_remaining_after_release_is_zero_even_before_original_expiry() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        lease.release(Time::from_secs(20)).unwrap();

        assert_eq!(lease.remaining(Time::from_secs(20)), Duration::ZERO);
        assert_eq!(lease.remaining(Time::from_secs(25)), Duration::ZERO);
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
    fn lease_remaining_after_mark_expired_is_zero_before_wall_clock_expiry() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        lease.mark_expired().unwrap();

        assert_eq!(lease.remaining(Time::from_secs(15)), Duration::ZERO);
        assert_eq!(lease.remaining(Time::from_secs(39)), Duration::ZERO);
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
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        assert!(store.is_empty());

        let key = IdempotencyKey::from_raw(1);
        let request = test_request_fingerprint("encode");
        let decision = store.check(&key, &request, Time::from_secs(10));
        assert!(matches!(decision, DedupDecision::New));

        let inserted = store.record(key, RemoteTaskId::next(), request, Time::from_secs(10));
        assert!(inserted);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn idempotency_store_in_flight_record_survives_insertion_ttl() {
        let mut store = IdempotencyStore::new(Duration::from_secs(60));
        let key = IdempotencyKey::from_raw(2);
        let canonical_task = RemoteTaskId::from_raw(11);
        let request = test_request_fingerprint("long-running");

        assert!(matches!(
            store.check_and_record(key, canonical_task, request.clone(), Time::from_secs(10)),
            DedupDecision::New
        ));

        assert_eq!(store.evict_expired(Time::from_secs(10_000)), 0);
        assert!(matches!(
            store.check(&key, &request, Time::from_secs(10_000)),
            DedupDecision::Duplicate(record)
                if record.remote_task_id == canonical_task
                    && record.outcome.is_none()
                    && record.expires_at.is_none()
        ));
        assert!(matches!(
            store.check(
                &key,
                &test_request_fingerprint("different-work"),
                Time::from_secs(10_000),
            ),
            DedupDecision::Conflict
        ));
    }

    #[test]
    fn idempotency_store_atomic_admission_fences_replaced_record_generation() {
        let mut store = IdempotencyStore::new(Duration::from_secs(60));
        let key = IdempotencyKey::from_raw(3);
        let request = test_request_fingerprint("reusable");
        let old_task = RemoteTaskId::from_raw(21);
        let new_task = RemoteTaskId::from_raw(22);

        assert!(matches!(
            store.check_and_record(key, old_task, request.clone(), Time::from_secs(10)),
            DedupDecision::New
        ));
        assert!(store.complete(
            &key,
            old_task,
            RemoteOutcome::Success(vec![1]),
            Time::from_secs(20),
        ));

        assert!(matches!(
            store.check_and_record(key, new_task, request.clone(), Time::from_secs(80)),
            DedupDecision::New
        ));
        assert_eq!(store.len(), 1);
        assert!(matches!(
            store.check(&key, &request, Time::from_secs(81)),
            DedupDecision::Duplicate(record)
                if record.remote_task_id == new_task
                    && record.outcome.is_none()
                    && record.expires_at.is_none()
        ));
        assert!(!store.complete(
            &key,
            old_task,
            RemoteOutcome::Failed("stale completion".into()),
            Time::from_secs(82),
        ));
        assert!(matches!(
            store.check(&key, &request, Time::from_secs(82)),
            DedupDecision::Duplicate(record)
                if record.remote_task_id == new_task
                    && record.outcome.is_none()
                    && record.expires_at.is_none()
        ));
        assert!(store.complete(
            &key,
            new_task,
            RemoteOutcome::Success(vec![2]),
            Time::from_secs(83),
        ));
        assert!(matches!(
            store.check(&key, &request, Time::from_secs(84)),
            DedupDecision::Duplicate(record)
                if record.remote_task_id == new_task
                    && matches!(record.outcome, Some(RemoteOutcome::Success(ref bytes)) if bytes.as_slice() == [2])
                    && record.expires_at == Some(Time::from_secs(143))
        ));
    }

    #[test]
    fn idempotency_store_duplicate_detection() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(42);
        let request = test_request_fingerprint("encode");

        store.record(
            key,
            RemoteTaskId::next(),
            request.clone(),
            Time::from_secs(10),
        );

        // Same key, same computation → Duplicate
        let decision = store.check(&key, &request, Time::from_secs(20));
        assert!(matches!(decision, DedupDecision::Duplicate(_)));

        // Trying to record again returns false
        let inserted = store.record(key, RemoteTaskId::next(), request, Time::from_secs(20));
        assert!(!inserted);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn idempotency_store_conflict_detection() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(42);

        store.record(
            key,
            RemoteTaskId::next(),
            test_request_fingerprint("encode"),
            Time::from_secs(10),
        );

        // Same key, DIFFERENT computation → Conflict
        let decision = store.check(
            &key,
            &test_request_fingerprint("decode"),
            Time::from_secs(20),
        );
        assert!(matches!(decision, DedupDecision::Conflict));
    }

    #[test]
    fn idempotency_store_complete_outcome() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(99);
        let task_id = RemoteTaskId::next();

        store.record(
            key,
            task_id,
            test_request_fingerprint("work"),
            Time::from_secs(10),
        );

        // Complete with success
        let updated = store.complete(
            &key,
            task_id,
            RemoteOutcome::Success(vec![1, 2, 3]),
            Time::from_secs(15),
        );
        assert!(updated);

        // Check returns duplicate with outcome
        let decision = store.check(&key, &test_request_fingerprint("work"), Time::from_secs(20));
        assert!(matches!(decision, DedupDecision::Duplicate(_)));
        if let DedupDecision::Duplicate(record) = decision {
            assert!(record.outcome.is_some());
            assert!(record.outcome.unwrap().is_success());
        }
    }

    #[test]
    fn idempotency_store_complete_unknown_key() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(999);

        // Complete on unknown key returns false
        let updated = store.complete(
            &key,
            RemoteTaskId::from_raw(1),
            RemoteOutcome::Failed("oops".into()),
            Time::from_secs(10),
        );
        assert!(!updated);
    }

    #[test]
    fn idempotency_store_eviction() {
        let mut store = IdempotencyStore::new(Duration::from_secs(60));
        let completed_key = IdempotencyKey::from_raw(1);
        let in_flight_key = IdempotencyKey::from_raw(2);
        let completed_task = RemoteTaskId::next();

        // Completion at t=20 establishes the terminal deadline at t=80.
        store.record(
            completed_key,
            completed_task,
            test_request_fingerprint("a"),
            Time::from_secs(10),
        );
        assert!(store.complete(
            &completed_key,
            completed_task,
            RemoteOutcome::Success(vec![]),
            Time::from_secs(20),
        ));

        // This second operation remains in flight and therefore has no
        // eviction deadline.
        store.record(
            in_flight_key,
            RemoteTaskId::next(),
            test_request_fingerprint("b"),
            Time::from_secs(50),
        );
        assert_eq!(store.len(), 2);

        assert_eq!(store.evict_expired(Time::from_secs(79)), 0);

        // The terminal record expires at the boundary; the in-flight record
        // remains resident.
        let evicted = store.evict_expired(Time::from_secs(80));
        assert_eq!(evicted, 1);
        assert_eq!(store.len(), 1);

        let decision = store.check(
            &in_flight_key,
            &test_request_fingerprint("b"),
            Time::from_secs(10_000),
        );
        assert!(matches!(decision, DedupDecision::Duplicate(_)));

        let decision = store.check(
            &completed_key,
            &test_request_fingerprint("a"),
            Time::from_secs(80),
        );
        assert!(matches!(decision, DedupDecision::New));
    }

    #[test]
    fn idempotency_store_check_treats_expired_records_as_new() {
        let mut store = IdempotencyStore::new(Duration::from_secs(60));
        let key = IdempotencyKey::from_raw(3);
        let task_id = RemoteTaskId::next();
        store.record(
            key,
            task_id,
            test_request_fingerprint("encode"),
            Time::from_secs(10),
        );
        assert!(store.complete(
            &key,
            task_id,
            RemoteOutcome::Success(vec![]),
            Time::from_secs(20),
        ));

        let decision = store.check(
            &key,
            &test_request_fingerprint("decode"),
            Time::from_secs(80),
        );
        assert!(
            matches!(decision, DedupDecision::New),
            "expired keys must not survive as stale conflicts"
        );
        assert!(store.is_empty(), "expired entry should be removed lazily");
    }

    #[test]
    fn idempotency_store_debug() {
        let store = IdempotencyStore::new(Duration::from_secs(60));
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
    fn saga_drop_during_unwind_skips_compensation_side_effects() {
        use std::panic::{self, AssertUnwindSafe};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let compensated = Arc::new(AtomicBool::new(false));
        let compensation_ran = Arc::clone(&compensated);

        let unwind = panic::catch_unwind(AssertUnwindSafe(move || {
            let mut saga = Saga::new();
            saga.step(
                "step-0",
                || Ok(()),
                move || {
                    compensation_ran.store(true, Ordering::SeqCst);
                    "comp-0".to_string()
                },
            )
            .unwrap();

            panic!("outer panic");
        }));

        assert!(unwind.is_err());
        assert!(
            !compensated.load(Ordering::SeqCst),
            "drop during unwind must not run compensation closures"
        );
    }

    #[test]
    fn saga_drop_during_unwind_with_panicking_compensation_preserves_process() {
        const CHILD_ENV: &str = "ASUPERSYNC_SAGA_UNWIND_CHILD";
        const TEST_NAME: &str =
            "remote::tests::saga_drop_during_unwind_with_panicking_compensation_preserves_process";

        if std::env::var_os(CHILD_ENV).is_some() {
            let mut saga = Saga::new();
            saga.step(
                "step-0",
                || Ok(()),
                || -> String { panic!("compensation panic during unwind") },
            )
            .unwrap();

            panic!("outer panic");
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .output()
            .expect("spawn child test binary");

        assert_eq!(
            output.status.code(),
            Some(101),
            "child should fail from the original panic without aborting the process: {:?}",
            output.status
        );
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

    /// Invariant: releasing a lease at or after `expires_at` must fail with
    /// `LeaseError::Expired` and transition the lease into `Expired`.
    #[test]
    fn lease_release_at_exact_expiry_boundary_fails() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        let result = lease.release(Time::from_secs(40));
        assert_eq!(result, Err(LeaseError::Expired));
        assert_eq!(lease.state(), LeaseState::Expired);
        assert!(lease.is_expired(Time::from_secs(40)));
        assert!(!lease.is_released());
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
        let mut store = IdempotencyStore::new(Duration::from_secs(60));
        let key = IdempotencyKey::from_raw(1);
        let request = test_request_fingerprint("work");
        let task_id = RemoteTaskId::next();

        // Record at t=10, then complete at t=20 (expires at t=80).
        store.record(key, task_id, request.clone(), Time::from_secs(10));
        // Complete with success
        store.complete(
            &key,
            task_id,
            RemoteOutcome::Success(vec![42]),
            Time::from_secs(20),
        );
        assert_eq!(store.len(), 1);

        // Evict at t=80 — should remove the completed entry
        let evicted = store.evict_expired(Time::from_secs(80));
        assert_eq!(evicted, 1);
        assert!(store.is_empty());

        // Re-check: the key should be New again
        let decision = store.check(&key, &request, Time::from_secs(80));
        assert!(matches!(decision, DedupDecision::New));
    }

    /// Invariant: checking a completed entry with a Failed outcome still returns
    /// Duplicate (not New), and the cached outcome is available.
    #[test]
    fn idempotency_store_check_after_failed_returns_duplicate_with_outcome() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(77);
        let request = test_request_fingerprint("fragile_op");
        let task_id = RemoteTaskId::next();

        store.record(key, task_id, request.clone(), Time::from_secs(10));
        store.complete(
            &key,
            task_id,
            RemoteOutcome::Failed("disk full".into()),
            Time::from_secs(15),
        );

        let decision = store.check(&key, &request, Time::from_secs(20));
        assert!(
            matches!(
                decision,
                DedupDecision::Duplicate(record)
                    if record.outcome.as_ref().is_some_and(|outcome| {
                        !outcome.is_success()
                            && matches!(
                                outcome,
                                RemoteOutcome::Failed(msg) if msg.contains("disk full")
                            )
                    })
            ),
            "expected Duplicate with failed outcome recorded"
        );
    }

    /// Invariant: completing the same key twice overwrites the outcome.
    /// The last `complete()` call wins.
    #[test]
    fn idempotency_store_complete_overwrites_outcome() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(88);
        let request = test_request_fingerprint("retry_op");
        let task_id = RemoteTaskId::next();

        store.record(key, task_id, request.clone(), Time::from_secs(10));

        // First complete: Failed
        store.complete(
            &key,
            task_id,
            RemoteOutcome::Failed("transient".into()),
            Time::from_secs(15),
        );
        // Second complete: Success (overwrites)
        store.complete(
            &key,
            task_id,
            RemoteOutcome::Success(vec![1, 2, 3]),
            Time::from_secs(18),
        );

        let decision = store.check(&key, &request, Time::from_secs(20));
        assert!(
            matches!(
                decision,
                DedupDecision::Duplicate(record)
                    if record
                        .outcome
                        .as_ref()
                        .is_some_and(RemoteOutcome::is_success)
            ),
            "expected Duplicate with the latest successful outcome"
        );
    }

    #[test]
    fn idempotency_store_same_computation_different_input_conflicts() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(0xfeed);
        let base = IdempotencyRequestFingerprint::new(
            ComputationName::new("encode"),
            RemoteInput::new(vec![1, 2, 3]),
        );
        let mut changed_input = base.clone();
        changed_input.input = RemoteInput::new(vec![9, 9, 9]);

        store.record(key, RemoteTaskId::next(), base, Time::from_secs(10));

        let decision = store.check(&key, &changed_input, Time::from_secs(20));
        assert!(
            matches!(decision, DedupDecision::Conflict),
            "same key + same computation but different payload must conflict"
        );
    }

    #[test]
    fn idempotency_store_retry_metadata_does_not_trigger_conflict() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(0xbeef);
        let base = SpawnRequest {
            remote_task_id: RemoteTaskId::from_raw(7),
            computation: ComputationName::new("encode"),
            input: RemoteInput::new(vec![1, 2, 3]),
            lease: Duration::from_secs(30),
            idempotency_key: key,
            budget: Some(Budget::MINIMAL),
            origin_node: NodeId::new("origin-a"),
            origin_region: RegionId::new_for_test(1, 1),
            origin_task: TaskId::new_for_test(1, 1),
        };
        let retry = SpawnRequest {
            remote_task_id: RemoteTaskId::from_raw(99),
            lease: Duration::from_secs(120),
            budget: Some(Budget::INFINITE),
            origin_node: NodeId::new("origin-b"),
            origin_region: RegionId::new_for_test(2, 2),
            origin_task: TaskId::new_for_test(2, 2),
            ..base.clone()
        };

        let recorded = IdempotencyRequestFingerprint::from_spawn_request(&base);
        assert!(store.record(
            key,
            base.remote_task_id,
            recorded.clone(),
            Time::from_secs(10),
        ));

        let decision = store.check(
            &key,
            &IdempotencyRequestFingerprint::from_spawn_request(&retry),
            Time::from_secs(20),
        );
        assert!(
            matches!(decision, DedupDecision::Duplicate(record) if record.request == recorded),
            "retries must deduplicate on logical operation, not lease/budget/origin metadata"
        );
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
    #[allow(clippy::clone_on_copy)]
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
