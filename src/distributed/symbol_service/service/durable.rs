//! Existing symbol-service wire, with commit-before-receipt disk ownership.

use super::{ServiceRequest, ServiceResponse, SYMBOL_SERVICE_COMPUTATION, read_key, receipt, split_request};
use crate::cx::Cx;
use crate::distributed::ComputationSchemaRegistryError;
use crate::distributed::symbol_service::durable::{DurableSymbolError, DurableSymbolReplicaStore};
use crate::distributed::symbol_service::{SymbolBatchKey, SymbolStoreError};
use crate::remote::{NodeId, RemoteComputationRegistry, RemoteOutcome};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    let handle = DurableSymbolServiceHandle(Arc::new(AtomicBool::new(false)));
    let gate = Arc::clone(&handle.0);
    registry.register::<ServiceRequest, ServiceResponse, _, _>(
        SYMBOL_SERVICE_COMPUTATION,
        move |cx, invocation| {
            let store = Arc::clone(&store);
            let gate = Arc::clone(&gate);
            async move {
                if cx.checkpoint().is_err() { return Ok(cancelled(&cx)); }
                if cx.blocking_pool_handle().is_none() {
                    return Ok(RemoteOutcome::Failed("durable symbol service requires a context blocking pool".to_owned()));
                }
                let Some(credit) = Credit::acquire(&gate) else {
                    return Ok(RemoteOutcome::Failed("durable symbol service is busy".to_owned()));
                };
                let input = invocation.request().input.data();
                let parsed = split_request(input, store.replica_id()).and_then(|(get, body)| {
                    if get { return read_key(body).map(Request::Get); }
                    // The enclosing authenticated service frame already bounds
                    // input; the journal enforces its independent batch limits.
                    let mut bytes = Zeroizing::new(Vec::new());
                    bytes.try_reserve_exact(body.len()).map_err(|_| SymbolStoreError::Allocation)?;
                    bytes.extend_from_slice(body);
                    Ok(Request::Put(bytes))
                });
                let request = match parsed {
                    Ok(request) => request,
                    Err(error) => return Ok(RemoteOutcome::Failed(error.to_string())),
                };
                let job = Job { store, peer: invocation.peer_node().clone(), request, _credit: credit };
                let mut task = match cx.spawn_blocking(move |worker| job.execute(&worker)) {
                    Ok(task) => task,
                    Err(_) => return Ok(RemoteOutcome::Failed("durable symbol worker admission refused".to_owned())),
                };
                match task.join(&cx).await {
                    Ok(outcome) if !cx.is_cancel_requested() => Ok(outcome),
                    _ => Ok(cancelled(&cx)),
                }
            }
        },
    )?;
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_registration_refuses_saturation_and_reuses_only_released_credit() {
        let gate = Arc::new(AtomicBool::new(false));
        let handle = DurableSymbolServiceHandle(Arc::clone(&gate));
        let credit = Credit::acquire(&gate).unwrap();
        assert!(handle.in_flight());
        assert!(Credit::acquire(&gate).is_none());
        drop(credit);
        assert!(!handle.in_flight());
        assert!(Credit::acquire(&gate).is_some());
    }

    #[test]
    fn unwinding_releases_owned_service_admission() {
        let gate = Arc::new(AtomicBool::new(false));
        let result = std::panic::catch_unwind(|| {
            let _credit = Credit::acquire(&gate).unwrap();
            panic!("worker sentinel");
        });
        assert!(result.is_err());
        assert!(!gate.load(Ordering::Acquire));
    }
}
