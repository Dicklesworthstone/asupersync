//! Existing symbol-service wire, with commit-before-receipt disk ownership.

use super::{
    Admission, ServiceRequest, ServiceResponse, SYMBOL_SERVICE_COMPUTATION,
    read_key, receipt, register_handler, split_request,
};
use crate::cx::{ChildRegionSpec, Cx};
use crate::distributed::ComputationSchemaRegistryError;
use crate::distributed::remote_owned::RemoteServiceAdmission;
use crate::distributed::symbol_service::durable::{DurableSymbolError, DurableSymbolReplicaStore};
use crate::distributed::symbol_service::{SymbolBatchKey, SymbolStoreError};
use crate::remote::{NodeId, RemoteComputationRegistry, RemoteOutcome};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use zeroize::Zeroizing;

/// Observes admission across all connections using one registered durable handler.
///
/// Exactly one blocking job may be admitted at a time. Saturation refuses; there
/// is no per-store request queue. Cloned registries retain the same handler/gate.
/// Separate registrations and synchronous administrative users are separate
/// admission domains; do not mistake this for a process-wide disk-worker limit.
#[derive(Debug, Clone)]
pub struct DurableSymbolServiceHandle(Arc<AtomicBool>);
impl DurableSymbolServiceHandle {
    /// Whether a queued/running durable job still owns its request and store credit.
    #[must_use]
    pub fn in_flight(&self) -> bool { self.0.load(Ordering::Acquire) }
}

struct Credit(Arc<AtomicBool>);
impl Credit {
    fn acquire(gate: &Arc<AtomicBool>) -> Option<Self> {
        gate.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).ok()?;
        Some(Self(Arc::clone(gate)))
    }
}
impl Drop for Credit {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

enum Request {
    Get(SymbolBatchKey),
    Put(Zeroizing<Vec<u8>>),
}

// Rust field destruction order keeps the credit through request/store retirement,
// including failed spawn, cancellation before the closure starts, and unwinding.
struct Job {
    store: Arc<DurableSymbolReplicaStore>,
    peer: NodeId,
    request: Request,
    _credit: Credit,
}
impl Job {
    fn execute(self, cx: &Cx) -> RemoteOutcome {
        let outcome = if cx.checkpoint().is_err() {
            cancelled(cx)
        } else {
            let result: Result<Vec<u8>, DurableSymbolError> = match &self.request {
                Request::Get(key) => self.store.get(&self.peer, *key).and_then(|batch| {
                    let source = batch.as_ref().as_ref();
                    let mut bytes = Vec::new();
                    bytes.try_reserve_exact(source.len()).map_err(|_| SymbolStoreError::Allocation)?;
                    bytes.extend_from_slice(source);
                    Ok(bytes)
                }),
                Request::Put(bytes) => self.store.put(&self.peer, bytes)
                    .map(|batch| receipt(self.store.replica_id(), &batch, cx.now())),
            };
            match result {
                Ok(bytes) => RemoteOutcome::Success(bytes),
                Err(error) => RemoteOutcome::Failed(error.to_string()),
            }
        };
        drop(self); // Destruction precedes publication of the worker result.
        outcome
    }
}

fn cancelled(cx: &Cx) -> RemoteOutcome {
    cx.cancel_reason().map_or_else(
        || RemoteOutcome::Failed("durable symbol checkpoint or worker refused".to_owned()),
        RemoteOutcome::Cancelled,
    )
}

async fn dispatch(
    cx: &Cx, store: Arc<DurableSymbolReplicaStore>, gate: Arc<AtomicBool>,
    peer: &NodeId, input: &[u8],
) -> RemoteOutcome {
    if cx.checkpoint().is_err() { return cancelled(cx); }
    if cx.blocking_pool_handle().is_none() {
        return RemoteOutcome::Failed("durable symbol service requires a context blocking pool".to_owned());
    }
    let Some(credit) = Credit::acquire(&gate) else {
        return RemoteOutcome::Failed("durable symbol service is busy".to_owned());
    };
    let parsed = split_request(input, store.replica_id()).and_then(|(get, body)| {
        if get { return read_key(body).map(Request::Get); }
        // The enclosing authenticated service frame already bounds input;
        // the journal enforces its independent batch limits.
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(body.len()).map_err(|_| SymbolStoreError::Allocation)?;
        bytes.extend_from_slice(body);
        Ok(Request::Put(bytes))
    });
    let request = match parsed {
        Ok(request) => request,
        Err(error) => return RemoteOutcome::Failed(error.to_string()),
    };
    let job = Job { store, peer: peer.clone(), request, _credit: credit };
    let mut task = match cx.spawn_blocking_drained(move |worker| job.execute(&worker)) {
        Ok(task) => task,
        Err(_) => return RemoteOutcome::Failed("durable symbol worker admission refused".to_owned()),
    };
    // The runtime owner survives handler cancellation until the pool retires
    // its captures. A late invocation cancellation cannot discard an already
    // completed journal transaction by short-circuiting this retirement wait.
    match task.join().await {
        Ok(outcome) => {
            // An enclosing ordinary task must acknowledge a late cancellation
            // before publishing this completed worker's typed result. The
            // observation cannot replace a transaction that already finished.
            if cx.is_cancel_requested() { let _ = cx.checkpoint(); }
            outcome
        }
        Err(_) => cancelled(cx),
    }
}

/// Register disk-backed put/fetch without changing V1 schemas or computation name.
///
/// This is an ALTERNATIVE to `register_symbol_service` for the same registry, not
/// a second capability. Clients retain the existing RemoteSymbolTransport wire.
/// Only operator configuration identifies the backend: the V1 receipt does not
/// negotiate durability or prove that a different server uses this implementation.
///
/// The authenticated invocation supplies the origin namespace. A real context
/// blocking pool and spawn capability are required; there is NO inline disk-I/O
/// fallback. Admission precedes request copies and spawn. A runtime-owned blocking
/// task retains the credit and request even if the network handler is dropped.
/// A queued cancelled request is skipped; its captures remain charged until a
/// pool worker retires them. Joining waits for that retirement independently of
/// invocation cancellation and preserves the completed transaction's result.
/// The pool's own admission and the listener's frame/connection limits still apply.
///
/// A checkpoint occurs before the disk transaction. Once a synchronous commit
/// starts, cancellation cannot preempt fsync or roll it back. The owning region
/// must drain its blocking task; a stuck filesystem can delay that drain. A lost
/// response may follow a successful commit. No automatic retry or remote-drain
/// guarantee is added. Initialize/reopen the journal off the executor beforehand.
pub fn register_durable_symbol_service(
    registry: &mut RemoteComputationRegistry,
    store: Arc<DurableSymbolReplicaStore>,
) -> Result<DurableSymbolServiceHandle, ComputationSchemaRegistryError> {
    register_durable_symbol_service_inner(registry, store, None)
}

/// Register disk-backed put/fetch with authenticated-peer execution admission.
///
/// Uses the same handler, wire capability and commit-before-receipt semantics as
/// [`register_durable_symbol_service`]. Admission precedes request copying and
/// blocking-worker submission, and owns the child region through actual worker
/// retirement even if the caller cancels or drops its dispatch waiter.
///
/// The existing one-job durable gate remains in force. To queue fairly for that
/// gate, use a dedicated [`RemoteServiceAdmission::new_queued`] budget with
/// `max_in_flight: 1`, explicit peer/waiter/byte limits and `Some(wait_timeout)`.
/// A larger execution limit can still encounter the durable handler's busy
/// refusal. Other registrations or direct journal users have independent gates.
/// `None` selects immediate refusal. See [`super::register_symbol_service_with_admission`]
/// for the shared admission, child-region and queue contracts.
///
/// Cancellation cannot undo a synchronous journal commit that already started;
/// a cancelled or lost response is not evidence of rollback.
pub fn register_durable_symbol_service_with_admission(
    registry: &mut RemoteComputationRegistry, store: Arc<DurableSymbolReplicaStore>,
    admission: &RemoteServiceAdmission, child: ChildRegionSpec, wait_timeout: Option<Duration>,
) -> Result<DurableSymbolServiceHandle, ComputationSchemaRegistryError> {
    register_durable_symbol_service_inner(registry, store,
        Some(Admission { limiter: admission, child, wait_timeout }))
}

fn register_durable_symbol_service_inner(
    registry: &mut RemoteComputationRegistry, store: Arc<DurableSymbolReplicaStore>,
    admission: Option<Admission<'_>>,
) -> Result<DurableSymbolServiceHandle, ComputationSchemaRegistryError> {
    let handle = DurableSymbolServiceHandle(Arc::new(AtomicBool::new(false)));
    let gate = Arc::clone(&handle.0);
    register_handler::<ServiceRequest, ServiceResponse, _, _>(
        registry,
        SYMBOL_SERVICE_COMPUTATION,
        admission,
        move |cx, invocation| {
            let store = Arc::clone(&store);
            let gate = Arc::clone(&gate);
            async move {
                Ok(dispatch(&cx, store, gate, invocation.peer_node(),
                    invocation.request().input.data()).await)
            }
        },
    )?;
    Ok(handle)
}

#[cfg(test)]
#[path = "durable_inline_tests.rs"]
mod tests;
