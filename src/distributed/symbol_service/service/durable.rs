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
        Ok(outcome) => outcome,
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
    let handle = DurableSymbolServiceHandle(Arc::new(AtomicBool::new(false)));
    let gate = Arc::clone(&handle.0);
    registry.register::<ServiceRequest, ServiceResponse, _, _>(
        SYMBOL_SERVICE_COMPUTATION,
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

    #[cfg(unix)]
    mod native {
        use super::*;
        use crate::distributed::symbol_service::durable::DurableSymbolLimits;
        use crate::distributed::symbol_service::service::{
            fetch_request, put_request, validate_receipt,
        };
        use crate::distributed::symbol_service::{
            EncodedSymbolBatch, SymbolBatchLimits, SymbolStoreLimits, encode_symbol_batch,
        };
        use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder, yield_now};
        use crate::security::{AuthKey, SecurityContext};
        use crate::types::CancelReason;
        use crate::types::symbol::Symbol;
        use std::fs::{File, OpenOptions};
        use std::future::{Future, poll_fn};
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        use std::path::PathBuf;
        use std::sync::atomic::AtomicU64;
        use std::task::Poll;
        use std::time::{Duration, Instant};

        fn limits() -> DurableSymbolLimits {
            DurableSymbolLimits {
                batch: SymbolBatchLimits { max_encoded_bytes: 4096, max_symbols: 8,
                    max_payload_bytes: 2048, max_decoded_bytes: 8192 },
                store: SymbolStoreLimits { max_batches: 1, max_bytes: 4096,
                    max_batches_per_peer: 1, max_bytes_per_peer: 4096 },
                max_journal_bytes: 8192,
            }
        }

        fn linked_store() -> (PathBuf, Arc<DurableSymbolReplicaStore>) {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let parent = std::env::temp_dir();
            loop {
                let path = parent.join(format!("asupersync-durable-handler-{}-{}",
                    std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
                match OpenOptions::new().create_new(true).read(true).write(true).mode(0o600).open(&path) {
                    Ok(file) => {
                        file.sync_all().unwrap();
                        File::open(&parent).unwrap().sync_all().unwrap();
                        let store = DurableSymbolReplicaStore::create(file, "replica",
                            AuthKey::from_seed(42), AuthKey::from_seed(99), limits()).unwrap();
                        return (path, Arc::new(store));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("linked durable handler fixture: {error}"),
                }
            }
        }

        fn batch() -> EncodedSymbolBatch {
            let security = SecurityContext::new(AuthKey::from_seed(42));
            let symbols = (0..3).map(|esi| security.sign_symbol(
                &Symbol::new_for_test(731, 0, esi, &[esi as u8; 128]),
            )).collect::<Vec<_>>();
            encode_symbol_batch(&symbols, limits().batch).unwrap()
        }

        fn runtime(workers: usize) -> Runtime {
            let builder = if workers == 1 { RuntimeBuilder::current_thread() }
                else { RuntimeBuilder::multi_thread().worker_threads(workers) };
            builder.blocking_threads(1, 1).build().unwrap()
        }

        fn assert_drained(runtime: &Runtime) {
            let report = runtime.shutdown_drained(Duration::from_secs(5));
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
            assert_eq!(report.live_tasks, 0);
            assert_eq!(report.live_regions, 0);
            assert_eq!(report.pending_obligations, 0);
            assert_eq!(report.pending_spawns, 0);
            assert_eq!(report.queued_finalizers, 0);
            assert!(!report.has_pending_obligation_posts);
        }

        #[test]
        #[allow(clippy::too_many_lines)]
        fn dropped_whole_frame_handler_retains_region_and_journal_until_worker_retirement() {
            for workers in [1, 2] {
                let (path, store) = linked_store();
                let inode = std::fs::metadata(&path).unwrap();
                let before = store.committed_bytes();
                let owner = Arc::downgrade(&store);
                let gate = Arc::new(AtomicBool::new(false));
                let handle = DurableSymbolServiceHandle(Arc::clone(&gate));
                let batch = batch();
                let input = put_request("replica", batch.as_ref()).unwrap();
                let peer = NodeId::new("origin");
                let runtime = runtime(workers);
                let pool = runtime.blocking_handle().unwrap();
                let (entered, parked) = std::sync::mpsc::channel();
                let (release, hold) = std::sync::mpsc::channel();
                let occupying = runtime.spawn_blocking(move || {
                    entered.send(()).unwrap();
                    hold.recv_timeout(Duration::from_secs(15)).unwrap();
                }).unwrap();
                parked.recv_timeout(Duration::from_secs(5)).expect("real blocking worker is occupied");

                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let mut handler = Box::pin(dispatch(&cx, Arc::clone(&store),
                        Arc::clone(&gate), &peer, &input));
                    poll_fn(|poll_cx| {
                        assert!(handler.as_mut().poll(poll_cx).is_pending());
                        Poll::Ready(())
                    }).await;
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while pool.pending_count() != 1 {
                        assert!(Instant::now() < deadline, "PUT must reach the real pool queue");
                        yield_now().await;
                    }
                    drop(handler); // The registration calls this exact future.
                    assert!(handle.in_flight(), "dropping a handler cannot recycle its job credit");
                    assert_eq!(Arc::strong_count(&store), 2, "the queued job retains the journal");
                    let busy = dispatch(&cx, Arc::clone(&store), Arc::clone(&gate), &peer, &input).await;
                    assert!(matches!(busy, RemoteOutcome::Failed(message)
                        if message == "durable symbol service is busy"));
                    assert_eq!(store.stats().batches, 0);
                });
                drop(store); // Only the cancelled, still-queued job owns this file.
                let report = runtime.shutdown_drained(Duration::from_millis(20));
                assert_eq!(report.outcome, RootDrainOutcome::TimedOut, "{report:?}");
                assert!(report.live_tasks > 0, "the queued journal owner must retain its region task");
                assert!(handle.in_flight());
                assert_eq!(owner.strong_count(), 1);
                assert_eq!(std::fs::metadata(&path).unwrap().len(), before);
                let locked = OpenOptions::new().read(true).write(true).open(&path).unwrap();
                assert!(matches!(DurableSymbolReplicaStore::open(locked, "replica",
                    AuthKey::from_seed(42), AuthKey::from_seed(99), limits()),
                    Err(DurableSymbolError::Locked)));

                release.send(()).unwrap();
                assert_drained(&runtime);
                assert!(occupying.wait_timeout(Duration::from_secs(1)));
                assert!(!handle.in_flight());
                assert!(owner.upgrade().is_none(), "retirement must release the last file owner");
                assert_eq!(std::fs::metadata(&path).unwrap().len(), before,
                    "a cancelled queued PUT cannot append or publish a receipt");
                assert!(runtime.shutdown_timeout(Duration::from_secs(5)));

                // The same journal and released admission credit remain usable;
                // shutdown did not execute, repair or replace the cancelled PUT.
                let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
                let store = Arc::new(DurableSymbolReplicaStore::open(file, "replica",
                    AuthKey::from_seed(42), AuthKey::from_seed(99), limits()).unwrap());
                let retry_runtime = self::runtime(workers);
                retry_runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let outcome = dispatch(&cx, Arc::clone(&store), Arc::clone(&gate), &peer, &input).await;
                    let RemoteOutcome::Success(bytes) = outcome else { panic!("explicit retry must commit"); };
                    validate_receipt(&bytes, "replica", batch.key(), batch.symbol_count()).unwrap();
                    assert!(!handle.in_flight());
                    let fetch = fetch_request("replica", batch.key()).unwrap();
                    let outcome = dispatch(&cx, Arc::clone(&store), Arc::clone(&gate), &peer, &fetch).await;
                    let RemoteOutcome::Success(bytes) = outcome else { panic!("committed batch must be fetchable"); };
                    assert_eq!(bytes, batch.as_ref());
                });
                assert_eq!(store.stats().batches, 1);
                assert!(store.committed_bytes() > before);
                let after = std::fs::metadata(&path).unwrap();
                assert_eq!((after.dev(), after.ino()), (inode.dev(), inode.ino()));
                assert_drained(&retry_runtime);
                assert!(retry_runtime.shutdown_timeout(Duration::from_secs(5)));
            }
        }

        #[test]
        fn completed_whole_frame_put_and_get_survive_late_invocation_cancellation() {
            for workers in [1, 2] {
                for get in [false, true] {
                    let (path, store) = linked_store();
                    let gate = Arc::new(AtomicBool::new(false));
                    let handle = DurableSymbolServiceHandle(Arc::clone(&gate));
                    let peer = NodeId::new("origin");
                    let batch = batch();
                    if get { store.put(&peer, batch.as_ref()).unwrap(); }
                    let before = store.committed_bytes();
                    let input = if get { fetch_request("replica", batch.key()).unwrap() }
                        else { put_request("replica", batch.as_ref()).unwrap() };
                    let runtime = runtime(workers);
                    let pool = runtime.blocking_handle().unwrap();
                    let (entered, parked) = std::sync::mpsc::channel();
                    let (release, hold) = std::sync::mpsc::channel();
                    let occupying = runtime.spawn_blocking(move || {
                        entered.send(()).unwrap();
                        hold.recv_timeout(Duration::from_secs(15)).unwrap();
                    }).unwrap();
                    parked.recv_timeout(Duration::from_secs(5)).expect("real blocking worker is occupied");

                    runtime.block_on(async {
                        let cx = Cx::current().unwrap().derive_cancel_scope();
                        let mut handler = Box::pin(dispatch(&cx, Arc::clone(&store),
                            Arc::clone(&gate), &peer, &input));
                        poll_fn(|poll_cx| {
                            assert!(handler.as_mut().poll(poll_cx).is_pending());
                            Poll::Ready(())
                        }).await;
                        let deadline = Instant::now() + Duration::from_secs(5);
                        while pool.pending_count() != 1 {
                            assert!(Instant::now() < deadline, "request must enter the real pool queue");
                            yield_now().await;
                        }
                        assert!(handle.in_flight());
                        release.send(()).unwrap();
                        let deadline = Instant::now() + Duration::from_secs(5);
                        while handle.in_flight() {
                            assert!(Instant::now() < deadline, "the real journal job must finish");
                            yield_now().await;
                        }
                        // The handler has not been polled again: the exact
                        // result exists and its job retired before cancellation.
                        assert_eq!(store.stats().batches, 1);
                        cx.cancel_with_reason(CancelReason::user("late invocation cancellation"));
                        assert!(cx.is_cancel_requested());
                        let outcome = handler.await;
                        let RemoteOutcome::Success(bytes) = outcome else {
                            panic!("a completed durable transaction must retain its terminal result");
                        };
                        if get {
                            assert_eq!(bytes, batch.as_ref());
                        } else {
                            validate_receipt(&bytes, "replica", batch.key(), batch.symbol_count()).unwrap();
                        }
                        assert!(!handle.in_flight());
                    });
                    assert!(occupying.wait_timeout(Duration::from_secs(1)));
                    assert_eq!(std::fs::metadata(path).unwrap().len(), store.committed_bytes());
                    if get { assert_eq!(store.committed_bytes(), before); }
                    else { assert!(store.committed_bytes() > before); }
                    assert_drained(&runtime);
                    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
                }
            }
        }
    }
}
