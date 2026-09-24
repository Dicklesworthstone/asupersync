//! Isolated native transport admission. The old logical-payload executor supplies
//! FIFO waiting; this domain additionally owns the actual native driver and its
//! application buffers. No public legacy runtime handle can bypass its quotas.

use super::*;
use crate::distributed::remote_owned::{
    RemoteAdmissionLimits, RemoteExecutor, RemotePeerLimits, RemoteQueueLimits,
    RemoteReservation as QueueReservation, RemoteReserveError,
};

/// Aggregate limits for a separate native transport domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeRemoteAdmissionLimits {
    /// Maximum configured routes, including aliases of a pinned peer.
    pub max_routes: usize,
    /// Reservations, live drivers and unread terminal results share this limit.
    pub max_in_flight: usize,
    /// Conservative application-buffer charges across all active reservations.
    pub max_buffer_bytes: usize,
    /// Maximum enrolled waiters. Waiting futures never own request payloads.
    pub max_waiters: usize,
    /// Maximum enrolled waiters for one authenticated SPKI identity.
    pub max_waiters_per_peer: usize,
}

/// Limits shared by every route with the same enforcing server SPKI pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeRemotePeerAdmissionLimits {
    /// Reservations, live drivers and unread terminal results for this identity.
    pub max_in_flight: usize,
    /// Conservative application-buffer charges for this authenticated identity.
    pub max_buffer_bytes: usize,
    /// Maximum original input length for one invocation.
    pub max_input_bytes: usize,
}

/// Current charges; these are conservative envelopes, not allocator measurements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeRemoteAdmissionUsage {
    /// Active reservations, drivers or unread terminal results.
    pub in_flight: usize,
    /// Charged application-buffer envelopes, including unused reserved space.
    pub buffer_bytes: usize,
    /// Enrolled waiters, each containing bounded metadata and no owned input.
    pub waiters: usize,
}

/// Local refusal before publication, or the original native transport refusal.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeRemoteAdmissionError {
    /// Immutable policy or route metadata is invalid.
    #[error("invalid native remote admission configuration: {0}")]
    InvalidConfig(&'static str),
    /// Every peer must have exactly one enforcing SPKI SHA-256 pin.
    #[error("native remote admission requires one enforcing server SPKI pin")]
    AuthenticationIdentity,
    /// Aliases for one authenticated identity supplied inconsistent quotas.
    #[error("native remote aliases must share identical peer limits")]
    ConflictingPeerLimits,
    /// The requested route was not configured for this domain.
    #[error("native remote admission destination is not configured")]
    UnknownRoute,
    /// Request length or conservative arithmetic cannot fit its static policy.
    #[error("native remote admission request exceeds its buffer or frame envelope")]
    RequestTooLarge,
    /// Commit must supply exactly the input length that was reserved.
    #[error("native remote admission input length differs from its reservation")]
    InputLength,
    /// Caller cancellation was observed before local publication.
    #[error("native remote admission caller is cancelled")]
    Cancelled,
    /// Admission was closed before publication.
    #[error("native remote admission is closed")]
    Closed,
    /// One protected close waiter already owns the drain observation slot.
    #[error("native remote admission already has an active close waiter")]
    CloseInProgress,
    /// A bounded control reason could not be encoded without truncation.
    #[error("native remote cancellation reason exceeds its protected control envelope")]
    ControlTooLarge,
    /// The existing bounded FIFO admission path refused.
    #[error(transparent)]
    Queue(#[from] RemoteReserveError),
    /// The existing native route/driver configuration refused.
    #[error(transparent)]
    Runtime(#[from] NativeRemoteRuntimeBuildError),
    /// Local publication failed; no automatic retry is added.
    #[error(transparent)]
    Remote(#[from] RemoteError),
}

struct RoutePolicy {
    peer: NodeId,
    max_input_bytes: usize,
    frame_bytes: usize,
    charge: usize,
}

struct Domain {
    runtime: Arc<NativeRemoteRuntime>,
    executor: RemoteExecutor,
    routes: BTreeMap<NodeId, RoutePolicy>,
    // Fast local refusal. NativeRemoteShared::admit provides the final atomic
    // admission/close fence; never hold this lock across scheduler callbacks.
    closed: Mutex<bool>,
    close_waiter: std::sync::atomic::AtomicBool,
    retired: Arc<crate::sync::Notify>,
}

impl Drop for Domain {
    fn drop(&mut self) {
        self.executor.close_admission();
        let _ = self.runtime.begin_drain();
    }
}

/// A native transport whose every entry point participates in bounded admission.
///
/// Construct this separately from a legacy [`NativeRemoteRuntime`]. It owns its
/// own driver registry, coalesced control channels and private native adapter;
/// legacy calls can neither publish into nor consume this domain's credits.
/// Legacy domains retain their original behavior and must be budgeted separately.
/// Runtime worker threads and reactor infrastructure may be shared.
///
/// Routes are immutable for this domain. Exactly one enforcing SPKI pin binds
/// each route to an authenticated server identity; aliases share that identity's
/// quota. Key rotation uses a new domain after closing the old one, so stale
/// reservations cannot acquire a new generation's authority or credits.
///
/// Each reservation charges `16 * (max_frame_bytes + 4) + 256 KiB`. This covers
/// original/native input copies, JSON encoding growth, framed read/write copies,
/// decoded terminal data and coalesced control reasons. Input length is also
/// bounded by the frame limit before any copy. Attempts are sequential and keep
/// the same charge through backoff and retry. Waiting borrows the caller's route
/// and context, owning no input or encoded request. Fixed route/TLS configuration,
/// allocator bookkeeping, TLS-engine internals, OS socket buffers and the shared
/// runtime are outside this application-buffer accounting; session and waiter
/// counts bound their cardinality. This is not a process-RSS limit.
///
/// A returned result transfers its bytes to the caller. Before that transfer,
/// unread results retain credit even after their driver has completed. Dropping
/// a live handle requests cancellation but the driver keeps credit until its
/// request/transport buffers have retired. Lease renewal and cancellation reuse
/// protected coalesced native controls without acquiring another data credit.
#[derive(Clone)]
pub struct AdmittedNativeRemoteRuntime {
    domain: Arc<Domain>,
}

impl fmt::Debug for AdmittedNativeRemoteRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmittedNativeRemoteRuntime")
            .field("routes", &self.domain.routes.len())
            .field("usage", &self.usage())
            .finish_non_exhaustive()
    }
}

impl AdmittedNativeRemoteRuntime {
    /// Creates an isolated domain without changing the legacy native defaults.
    /// Alias quotas must agree exactly. Zero data capacity explicitly refuses all
    /// invocations; zero waiting capacity still allows immediately fitting work.
    pub fn new<I>(
        runtime: RuntimeHandle,
        local_node: NodeId,
        routes: I,
        limits: NativeRemoteAdmissionLimits,
        config: NativeRemoteRuntimeConfig,
    ) -> Result<Self, NativeRemoteAdmissionError>
    where
        I: IntoIterator<Item = (NativeRemoteRoute, NativeRemotePeerAdmissionLimits)>,
    {
        if local_node.as_str().is_empty() || local_node.as_str().len() > 255 {
            return Err(NativeRemoteAdmissionError::InvalidConfig(
                "local node length",
            ));
        }
        if config.max_in_flight() < limits.max_in_flight {
            return Err(NativeRemoteAdmissionError::InvalidConfig(
                "native session limit is below admission limit",
            ));
        }
        let mut indexed = BTreeMap::new();
        let mut peers = BTreeMap::<[u8; 32], (NodeId, NativeRemotePeerAdmissionLimits)>::new();
        let mut native_routes = Vec::new();
        for (route, policy) in routes {
            if indexed.len() >= limits.max_routes {
                return Err(NativeRemoteAdmissionError::InvalidConfig("route count"));
            }
            if route.destination.as_str().is_empty()
                || route.destination.as_str().len() > 255
                || route.client.bootstrap_endpoints().len() > 64
            {
                return Err(NativeRemoteAdmissionError::InvalidConfig("route metadata"));
            }
            let pin = route
                .client
                .tls_connector
                .single_enforcing_spki()
                .ok_or(NativeRemoteAdmissionError::AuthenticationIdentity)?;
            let peer = match peers.get(&pin) {
                Some((peer, previous)) if previous == &policy => peer.clone(),
                Some(_) => return Err(NativeRemoteAdmissionError::ConflictingPeerLimits),
                None => {
                    let peer = NodeId::new(format!("pinned-peer-{}", peers.len()));
                    peers.insert(pin, (peer.clone(), policy));
                    peer
                }
            };
            let frame_bytes = route.client.config().wire_limits().max_frame_bytes();
            let charge = frame_bytes
                .checked_add(4)
                .and_then(|n| n.checked_mul(16))
                .and_then(|n| n.checked_add(256 * 1024))
                .ok_or(NativeRemoteAdmissionError::RequestTooLarge)?;
            if indexed
                .insert(
                    route.destination.clone(),
                    RoutePolicy {
                        peer,
                        max_input_bytes: policy.max_input_bytes.min(frame_bytes),
                        frame_bytes,
                        charge,
                    },
                )
                .is_some()
            {
                return Err(NativeRemoteAdmissionError::InvalidConfig("duplicate route"));
            }
            native_routes.push(route);
        }
        let executor = RemoteExecutor::new_queued(
            RemoteAdmissionLimits {
                max_peers: peers.len(),
                max_in_flight: limits.max_in_flight,
                max_input_bytes: limits.max_buffer_bytes,
            },
            peers.into_values().map(|(peer, policy)| {
                (
                    peer,
                    RemotePeerLimits {
                        max_in_flight: policy.max_in_flight,
                        max_input_bytes: policy.max_buffer_bytes,
                        max_request_bytes: policy.max_buffer_bytes,
                    },
                )
            }),
            RemoteQueueLimits {
                max_waiters: limits.max_waiters,
                max_waiters_per_peer: limits.max_waiters_per_peer,
                // These are prospective envelopes, not queued payloads. Checked
                // arithmetic in the existing queue refuses counter overflow.
                max_input_bytes: usize::MAX,
                max_input_bytes_per_peer: usize::MAX,
            },
        )
        .map_err(|error| NativeRemoteAdmissionError::Queue(error.into()))?;
        let mut runtime =
            NativeRemoteRuntime::with_config(runtime, local_node, native_routes, config)?;
        let retired = Arc::new(crate::sync::Notify::new());
        Arc::get_mut(&mut runtime.shared)
            .expect("new native runtime has unique state")
            .retirement_notify = Some(Arc::clone(&retired));
        Ok(Self {
            domain: Arc::new(Domain {
                runtime: Arc::new(runtime),
                executor,
                routes: indexed,
                closed: Mutex::new(false),
                close_waiter: std::sync::atomic::AtomicBool::new(false),
                retired,
            }),
        })
    }

    /// Conservative active charge for a route, independent of actual payload size.
    #[must_use]
    pub fn reservation_bytes(&self, node: &NodeId) -> Option<usize> {
        self.domain.routes.get(node).map(|route| route.charge)
    }

    /// Aggregate active and waiting observations, sampled from shared counters.
    #[must_use]
    pub fn usage(&self) -> NativeRemoteAdmissionUsage {
        let active = self.domain.executor.usage();
        NativeRemoteAdmissionUsage {
            in_flight: active.in_flight,
            buffer_bytes: active.input_bytes,
            waiters: self.domain.executor.queue_usage().waiters,
        }
    }

    /// Aliases return the same authenticated identity's usage.
    #[must_use]
    pub fn peer_usage(&self, node: &NodeId) -> Option<NativeRemoteAdmissionUsage> {
        let route = self.domain.routes.get(node)?;
        let active = self.domain.executor.peer_usage(&route.peer)?;
        Some(NativeRemoteAdmissionUsage {
            in_flight: active.in_flight,
            buffer_bytes: active.input_bytes,
            waiters: self.domain.executor.peer_queue_usage(&route.peer)?.waiters,
        })
    }

    /// Reserve one invocation before materializing any owned request buffers.
    /// FIFO is per pinned peer; the oldest currently feasible peer head wins.
    /// Impossible sizes refuse immediately. Cancellation/drop removes a parked
    /// ticket and releases its metadata; a positive timer-backed wait is required.
    pub async fn reserve(
        &self,
        cx: &Cx,
        node: &NodeId,
        input_bytes: usize,
        wait: Duration,
    ) -> Result<NativeRemoteReservation, NativeRemoteAdmissionError> {
        let route = self
            .domain
            .routes
            .get(node)
            .ok_or(NativeRemoteAdmissionError::UnknownRoute)?;
        if input_bytes > route.max_input_bytes {
            return Err(NativeRemoteAdmissionError::RequestTooLarge);
        }
        let reservation = self
            .domain
            .executor
            .reserve(cx, &route.peer, route.charge, wait)
            .await?;
        Ok(NativeRemoteReservation {
            domain: Arc::clone(&self.domain),
            node: node.clone(),
            input_bytes,
            credit: Arc::new(NativeRemoteCredit {
                _reservation: reservation,
            }),
        })
    }

    /// Stop admission and cancel live sessions. Pending and issued reservations
    /// cannot publish after this call; existing drivers retain their drain bounds.
    pub fn begin_drain(&self) -> bool {
        let changed = {
            let mut closed = self.domain.closed.lock();
            !std::mem::replace(&mut *closed, true)
        };
        self.domain.executor.close_admission();
        let _ = self.domain.runtime.begin_drain();
        changed
    }

    /// Drain the private native drivers. Unread terminal handles still retain
    /// their buffer charges; consume or drop them to release those charges.
    /// One protected waiter may observe drain at a time. Dropping this future
    /// releases that slot and its notification registration, allowing a retry.
    pub async fn close(&self, cx: &Cx) -> Result<bool, NativeRemoteAdmissionError> {
        if self
            .domain
            .close_waiter
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(NativeRemoteAdmissionError::CloseInProgress);
        }
        struct Waiter<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for Waiter<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _waiter = Waiter(&self.domain.close_waiter);
        self.begin_drain();
        let done = || self.domain.runtime.active_operations() == 0;
        if crate::time::timeout(
            cx.now(),
            self.domain.runtime.config.drain_timeout,
            self.domain.retired.wait_until(done),
        )
        .await
        .is_ok()
        {
            return Ok(true);
        }
        self.domain.runtime.force_close();
        self.domain.retired.wait_until(done).await;
        Ok(false)
    }
}

pub(super) struct NativeRemoteCredit {
    _reservation: QueueReservation,
}

/// One non-cloneable reservation bound to an immutable route and payload length.
/// Drop aborts local admission. No network operation exists until `commit`.
#[must_use = "dropping a reservation returns its admission credit"]
pub struct NativeRemoteReservation {
    domain: Arc<Domain>,
    node: NodeId,
    input_bytes: usize,
    credit: Arc<NativeRemoteCredit>,
}

impl fmt::Debug for NativeRemoteReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeRemoteReservation")
            .field("input_bytes", &self.input_bytes)
            .finish_non_exhaustive()
    }
}

impl NativeRemoteReservation {
    /// Commit exactly one local native publication. Input and name stay borrowed
    /// until their checked frame size is known, then are copied under the charge.
    /// This is not remote exactly-once execution; transport ambiguity is preserved.
    pub fn commit(
        self,
        cx: &Cx,
        computation: &ComputationName,
        input: &[u8],
        lease: Duration,
    ) -> Result<NativeRemoteAdmittedHandle, NativeRemoteAdmissionError> {
        if input.len() != self.input_bytes {
            return Err(NativeRemoteAdmissionError::InputLength);
        }
        if lease.is_zero() || computation.as_str().is_empty() || computation.as_str().len() > 255 {
            return Err(NativeRemoteAdmissionError::InvalidConfig(
                "lease or computation name",
            ));
        }
        if cx.checkpoint().is_err() {
            return Err(NativeRemoteAdmissionError::Cancelled);
        }
        let runtime = &self.domain.runtime;
        let route = runtime
            .route(&self.node)
            .ok_or(NativeRemoteAdmissionError::UnknownRoute)?;
        let task_id = RemoteTaskId::next();
        let key = IdempotencyKey::generate(cx);
        let budget = Some(cx.budget());
        let borrowed = BorrowedRequest {
            hello: &route.hello,
            remote_task_id: task_id.raw(),
            computation: computation.as_str(),
            input,
            lease_secs: lease.as_secs(),
            lease_subsec_nanos: lease.subsec_nanos(),
            idempotency_key_high: u64::try_from(key.raw() >> 64).expect("shifted key fits u64"),
            idempotency_key_low: u64::try_from(key.raw() & u128::from(u64::MAX))
                .expect("masked key fits u64"),
            budget: budget.map(Into::into),
            origin_region: cx.region_id(),
            origin_task: cx.task_id(),
        };
        let policy = &self.domain.routes[&self.node];
        count_frame(&borrowed, policy.frame_bytes)
            .map_err(|_| NativeRemoteAdmissionError::RequestTooLarge)?;
        if *self.domain.closed.lock() {
            return Err(NativeRemoteAdmissionError::Closed);
        }
        if cx.checkpoint().is_err() {
            return Err(NativeRemoteAdmissionError::Cancelled);
        }
        let request = SpawnRequest {
            remote_task_id: task_id,
            computation: computation.clone(),
            input: RemoteInput::new(input.to_vec()),
            lease,
            idempotency_key: key,
            budget,
            origin_node: runtime.local_node.clone(),
            origin_region: cx.region_id(),
            origin_task: cx.task_id(),
        };
        let (sender, receiver) = oneshot::channel();
        runtime.register_task(task_id, sender);
        if let Err(error) = runtime.send_spawn_with_admission(
            &self.node,
            runtime.local_node(),
            request,
            Some(Arc::clone(&self.credit)),
        ) {
            runtime.unregister_task(task_id);
            return Err(error.into());
        }
        cx.trace("remote::admission_committed");
        let handle = RemoteHandle {
            remote_task_id: task_id,
            local_task_id: None,
            origin_node: runtime.local_node.clone(),
            node: self.node,
            computation: computation.clone(),
            owner_region: cx.region_id(),
            runtime: Some(Arc::clone(runtime) as Arc<dyn RemoteRuntime>),
            receiver,
            sender_clock: cx.logical_clock_handle(),
            lease,
            state: RemoteTaskState::Pending,
            completed: false,
        };
        Ok(NativeRemoteAdmittedHandle {
            handle,
            credit: Some(self.credit),
            frame_bytes: policy.frame_bytes,
        })
    }
}

// Same strict field order and representation as RemoteServiceWireRequest. This
// preflight counts serialized bytes without allocating or cloning user input.
#[derive(Serialize)]
struct BorrowedRequest<'a> {
    hello: &'a RemotePeerHello,
    remote_task_id: u64,
    computation: &'a str,
    input: &'a [u8],
    lease_secs: u64,
    lease_subsec_nanos: u32,
    idempotency_key_high: u64,
    idempotency_key_low: u64,
    budget: Option<RemoteServiceWireBudget>,
    origin_region: RegionId,
    origin_task: TaskId,
}

fn count_frame(value: &impl Serialize, limit: usize) -> Result<usize, serde_json::Error> {
    struct Counter {
        bytes: usize,
        limit: usize,
    }
    impl io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|n| *n <= self.limit)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "frame limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { bytes: 0, limit };
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.bytes)
}

/// Charged native handle. The private legacy handle cannot escape this wrapper.
/// Like the explicit native adapter, this is caller-owned: call `close` before
/// leaving a region when remote cancellation/terminal collection is required.
pub struct NativeRemoteAdmittedHandle {
    // Drop the result receiver before releasing its final admission ownership.
    handle: RemoteHandle,
    credit: Option<Arc<NativeRemoteCredit>>,
    frame_bytes: usize,
}

impl fmt::Debug for NativeRemoteAdmittedHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeRemoteAdmittedHandle")
            .field("task", &self.handle.remote_task_id)
            .field("state", &self.handle.state())
            .field("charged", &self.credit.is_some())
            .finish_non_exhaustive()
    }
}

impl NativeRemoteAdmittedHandle {
    /// Existing protocol correlation identity.
    #[must_use]
    pub fn remote_task_id(&self) -> RemoteTaskId {
        self.handle.remote_task_id()
    }

    /// Observed native protocol state, without consuming a buffered result.
    #[must_use]
    pub fn state(&self) -> RemoteTaskState {
        self.handle.state()
    }

    /// Wait for a result. A cancelled wait retains admission and the live handle.
    pub async fn join(&mut self, cx: &Cx) -> Outcome<RemoteOutcome, RemoteError> {
        let result = self.handle.join(cx).await;
        if self.handle.completed {
            self.credit.take();
        }
        result
    }

    /// Consume a ready result, transferring its bytes and releasing handle credit.
    pub fn try_join(&mut self) -> Result<Option<RemoteOutcome>, RemoteError> {
        let result = self.handle.try_join();
        if self.handle.completed {
            self.credit.take();
        }
        result
    }

    /// Request cancellation through protected coalesced control capacity.
    /// Bounded reason validation precedes cloning; attribution is never truncated.
    pub fn cancel(&self, reason: &CancelReason) -> Result<(), NativeRemoteAdmissionError> {
        if !self.handle.should_request_cancel() {
            return Ok(());
        }
        if reason.chain().take(33).count() > 32 {
            return Err(NativeRemoteAdmissionError::ControlTooLarge);
        }
        #[derive(Serialize)]
        struct Cancel<'a> {
            command: &'static str,
            remote_task_id: u64,
            reason: &'a CancelReason,
        }
        let command = Cancel {
            command: "cancel",
            remote_task_id: self.handle.remote_task_id.raw(),
            reason,
        };
        count_frame(&command, self.frame_bytes.min(16 * 1024))
            .map_err(|_| NativeRemoteAdmissionError::ControlTooLarge)?;
        self.handle.request_cancel(reason.clone());
        Ok(())
    }

    /// Cancel with an explicit bounded reason, then collect terminal completion
    /// uninterruptibly. The native per-operation drain timeout remains effective.
    pub async fn close(
        &mut self,
        cx: &Cx,
        reason: &CancelReason,
    ) -> Result<Outcome<RemoteOutcome, RemoteError>, NativeRemoteAdmissionError> {
        if self.handle.completed {
            return Ok(Outcome::Err(RemoteError::PolledAfterCompletion));
        }
        self.cancel(reason)?;
        let result = match self.handle.receiver.recv_uninterruptible().await {
            Ok(result) => match self.handle.finish_result(result) {
                Ok(outcome) => Outcome::Ok(outcome),
                Err(error) => Outcome::Err(error),
            },
            Err(_) => Outcome::Err(self.handle.finish_closed()),
        };
        self.credit.take();
        cx.trace("remote::admission_terminal_collected");
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
