//! Chunked symbol wire backed by the existing authenticated durable journal.

use super::chunked::{
    ChunkedSymbolService, RequestSchema, ResponseSchema, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
    SymbolChunkedLimits, SymbolStagingStats,
};
use crate::cx::Cx;
use crate::distributed::ComputationSchemaRegistryError;
use crate::distributed::symbol_service::SymbolStoreError;
use crate::distributed::symbol_service::durable::DurableSymbolReplicaStore;
use crate::remote::{NodeId, RemoteComputationRegistry, RemoteOutcome};
use crate::types::Time;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

/// Multi-frame authenticated uploads with commit-before-receipt disk storage.
///
/// This uses the existing chunked V1 capability and journal format. A successful
/// COMMIT follows complete batch verification and `File::sync_all`; a fresh
/// receiver can reopen that journal and serve or reconcile the same batch.
/// Durability still requires the caller's durable file linkage and filesystem
/// guarantees. The wire does not negotiate or attest which storage backend the
/// operator configured.
///
/// Incomplete staging is bounded, plaintext, and IN MEMORY. BEGIN/CHUNK progress
/// is not a durable receipt. A receiver restart discards that prefix, so a client
/// reusing its exact persisted attempt begins again at zero unless the complete
/// batch committed. A lost COMMIT response is ambiguous; retry reconciles against
/// the authenticated immutable journal. A partial journal tail remains subject
/// to the durable store's existing read-only recovery policy.
///
/// Exactly one request per service may own a blocking job, across registrations
/// and peers. Saturation refuses without an implicit queue. This is an explicit
/// bounded disk-owner policy, not fair scheduling across peers. Incomplete stages
/// retain their independent global/per-peer byte reservations between requests.
pub struct DurableChunkedSymbolService {
    inner: ChunkedSymbolService,
    gate: Arc<AtomicBool>,
}

impl fmt::Debug for DurableChunkedSymbolService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableChunkedSymbolService")
            .field("in_flight", &self.in_flight())
            .field("staging", &self.stats())
            .finish_non_exhaustive()
    }
}

impl DurableChunkedSymbolService {
    /// Wrap an already initialized/reopened durable store without disk I/O.
    /// Initialize the journal off the async executor before registering it.
    #[must_use]
    pub fn new(store: Arc<DurableSymbolReplicaStore>, limits: SymbolChunkedLimits) -> Self {
        Self {
            inner: ChunkedSymbolService::new_durable(store, limits),
            gate: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Whether a queued/running job still owns its request, service and credit.
    #[must_use]
    pub fn in_flight(&self) -> bool { self.gate.load(Ordering::Acquire) }

    /// Volatile upload reservations; committed batches belong to the journal.
    #[must_use]
    pub fn stats(&self) -> SymbolStagingStats { self.inner.stats() }

    /// Retire expired volatile uploads using the registered handler's clock.
    /// This never changes committed disk records or starts a background task.
    pub fn reap_expired(&self, now: Time) -> usize { self.inner.reap_expired(now) }
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

// Field order retires the frame and service owner before releasing admission.
// The closure owns all of them even if its awaiting network handler is dropped.
struct Job {
    input: Zeroizing<Vec<u8>>,
    service: Arc<DurableChunkedSymbolService>,
    peer: NodeId,
    _credit: Credit,
}

impl Job {
    fn execute(self, cx: &Cx) -> RemoteOutcome {
        let outcome = if cx.checkpoint().is_err() {
            cancelled(cx)
        } else {
            match self.service.inner.handle(&self.peer, cx.now(), &self.input) {
                Ok(bytes) => RemoteOutcome::Success(bytes),
                Err(error) => RemoteOutcome::Failed(error.to_string()),
            }
        };
        drop(self);
        outcome
    }
}

fn cancelled(cx: &Cx) -> RemoteOutcome {
    cx.cancel_reason().map_or_else(
        || RemoteOutcome::Failed("durable chunked symbol checkpoint or worker refused".to_owned()),
        RemoteOutcome::Cancelled,
    )
}

async fn dispatch(
    cx: &Cx, service: Arc<DurableChunkedSymbolService>, peer: NodeId, source: &[u8],
) -> RemoteOutcome {
    if cx.checkpoint().is_err() { return cancelled(cx); }
    if cx.blocking_pool_handle().is_none() {
        return RemoteOutcome::Failed("durable chunked symbol service requires a context blocking pool".to_owned());
    }
    let Some(credit) = Credit::acquire(&service.gate) else {
        return RemoteOutcome::Failed("durable chunked symbol service is busy".to_owned());
    };
    let mut input = Zeroizing::new(Vec::new());
    if input.try_reserve_exact(source.len()).is_err() {
        return RemoteOutcome::Failed(SymbolStoreError::Allocation.to_string());
    }
    input.extend_from_slice(source);
    let job = Job { input, service, peer, _credit: credit };
    let mut task = match cx.spawn_blocking_drained(move |worker| job.execute(&worker)) {
        Ok(task) => task,
        Err(_) => return RemoteOutcome::Failed("durable chunked symbol worker admission refused".to_owned()),
    };
    // A committed terminal result must not cross the cancelled invocation Cx
    // again. The drained handle also keeps its region alive through worker
    // retirement if this handler is dropped.
    match task.join().await {
        Ok(outcome) => outcome,
        Err(_) => cancelled(cx),
    }
}

/// Register the existing chunked capability with a durable backing store.
///
/// This replaces `register_chunked_symbol_service` for a given registry. The
/// usual TLS peer grant, bounded frames and `RemoteSymbolTransport` chunked
/// constructor still apply. Registration grants no peer authority itself.
///
/// Every request runs on a Cx-owned blocking worker, including BEGIN/READ paths
/// that could otherwise wait behind journal fsync. A context blocking pool and
/// spawn capability are required; there is no inline disk-I/O fallback. The
/// single job credit is acquired before copying the frame and lives until the
/// worker retires its request, including dropped handlers and unwinding.
///
/// Cancellation is checked before a synchronous transaction. Once it starts,
/// it cannot preempt fsync or undo a commit. The owning region must drain that
/// blocking task; a stuck filesystem can delay the drain. A cancelled/lost
/// response therefore must not be interpreted as rollback.
pub fn register_durable_chunked_symbol_service(
    registry: &mut RemoteComputationRegistry, service: Arc<DurableChunkedSymbolService>,
) -> Result<(), ComputationSchemaRegistryError> {
    registry.register::<RequestSchema, ResponseSchema, _, _>(
        SYMBOL_CHUNKED_SERVICE_COMPUTATION,
        move |cx, invocation| {
            let service = Arc::clone(&service);
            async move {
                Ok(dispatch(&cx, service, invocation.peer_node().clone(),
                    invocation.request().input.data()).await)
            }
        },
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::distributed::symbol_service::durable::{DurableSymbolLimits, JournalStatus};
    use crate::distributed::symbol_service::service::chunked::{
        BEGIN, CHUNK, COMMIT, Upload, read_progress, request, upload_body,
    };
    use crate::distributed::symbol_service::{
        EncodedSymbolBatch, SymbolBatchLimits, SymbolStoreLimits, encode_symbol_batch,
    };
    use crate::security::{AuthKey, SecurityContext};
    use crate::types::symbol::Symbol;
    use crate::runtime::RuntimeBuilder;
    use std::fs::{File, OpenOptions};
    use std::future::{Future, poll_fn};
    use std::io::Write;
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

    fn linked_file() -> (PathBuf, File) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir();
        loop {
            let path = parent.join(format!("asupersync-durable-chunked-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match OpenOptions::new().create_new(true).read(true).write(true).open(&path) {
                Ok(file) => {
                    file.sync_all().unwrap();
                    File::open(&parent).unwrap().sync_all().unwrap();
                    return (path, file);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("linked journal fixture: {error}"),
            }
        }
    }

    fn make_service(store: Arc<DurableSymbolReplicaStore>) -> DurableChunkedSymbolService {
        DurableChunkedSymbolService::new(store,
            SymbolChunkedLimits::new(128, 1, 4096, 1, 4096, Duration::from_secs(60)).unwrap())
    }

    fn batch() -> EncodedSymbolBatch {
        let security = SecurityContext::new(AuthKey::from_seed(42));
        let symbols = (0..3).map(|esi| security.sign_symbol(
            &Symbol::new_for_test(71, 0, esi, &[esi as u8; 128]),
        )).collect::<Vec<_>>();
        encode_symbol_batch(&symbols, limits().batch).unwrap()
    }

    fn command(service: &DurableChunkedSymbolService, operation: u8, upload: Upload) -> Result<Vec<u8>, SymbolStoreError> {
        service.inner.handle(&NodeId::new("origin"), Time::ZERO,
            &request(operation, "replica", &upload_body(upload)).unwrap())
    }

    fn stage(service: &DurableChunkedSymbolService, batch: &EncodedSymbolBatch) -> Upload {
        let upload = Upload { key: batch.key(), attempt: 77, total: batch.as_ref().len(), count: batch.symbol_count() };
        command(service, BEGIN, upload).unwrap();
        for (index, piece) in batch.as_ref().chunks(128).enumerate() {
            let mut body = upload_body(upload);
            body.extend_from_slice(&((index * 128) as u64).to_le_bytes());
            body.extend_from_slice(piece);
            service.inner.handle(&NodeId::new("origin"), Time::ZERO,
                &request(CHUNK, "replica", &body).unwrap()).unwrap();
        }
        upload
    }

    #[test]
    fn durable_chunked_commit_reopens_and_reconciles_at_full_store_capacity() {
        let (path, file) = linked_file();
        let store = Arc::new(DurableSymbolReplicaStore::create(file, "replica",
            AuthKey::from_seed(42), AuthKey::from_seed(99), limits()).unwrap());
        let service = make_service(Arc::clone(&store));
        let batch = batch();
        let upload = stage(&service, &batch);
        assert_eq!(store.stats().batches, 0, "progress never means committed storage");
        let committed = command(&service, COMMIT, upload).unwrap();
        super::super::validate_receipt(&committed[8..], "replica", upload.key, upload.count).unwrap();
        assert_eq!(&committed[..8], &upload.attempt.to_le_bytes());
        let length = store.committed_bytes();
        assert_eq!(service.stats().reserved_bytes, 0);
        drop(service);
        drop(store);

        // A crash tail leaves committed objects available, even though this
        // journal cannot append a new object until the operator resolves it.
        let mut tail = OpenOptions::new().append(true).open(&path).unwrap();
        tail.write_all(&[0]).unwrap();
        tail.sync_all().unwrap();
        drop(tail);

        let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let store = Arc::new(DurableSymbolReplicaStore::open(file, "replica",
            AuthKey::from_seed(42), AuthKey::from_seed(99), limits()).unwrap());
        assert_eq!(store.status(), JournalStatus::ReadOnlyTail);
        let reopened = make_service(Arc::clone(&store));
        assert_eq!(read_progress(&command(&reopened, BEGIN, upload).unwrap(), upload).unwrap(), (upload.total, 128));
        command(&reopened, COMMIT, upload).unwrap();
        assert_eq!(store.stats().batches, 1);
        assert_eq!(store.committed_bytes(), length);
        assert_eq!(reopened.stats(), SymbolStagingStats { uploads: 0, reserved_bytes: 0, received_bytes: 0 });
        assert_eq!(store.get(&NodeId::new("origin"), upload.key).unwrap().as_ref().as_ref(), batch.as_ref());
        let mut missing = upload;
        missing.key.digest[0] ^= 1;
        missing.attempt += 1;
        assert_eq!(command(&reopened, BEGIN, missing), Err(SymbolStoreError::StorageUnavailable));
        assert_eq!(reopened.stats().uploads, 0);
        assert_eq!(std::fs::metadata(path).unwrap().len(), length + 1);
    }

    #[test]
    fn uncertain_durable_commit_releases_staging_and_refuses_new_admission() {
        let (path, file) = linked_file();
        let store = Arc::new(DurableSymbolReplicaStore::create(file, "replica",
            AuthKey::from_seed(42), AuthKey::from_seed(99), limits()).unwrap());
        let service = make_service(Arc::clone(&store));
        let batch = batch();
        let upload = stage(&service, &batch);
        // Deliberately violate the exclusive-owner contract to exercise the
        // journal's real poison boundary, without pretending to simulate fsync.
        let mut external = OpenOptions::new().append(true).open(&path).unwrap();
        external.write_all(&[1]).unwrap();
        external.sync_all().unwrap();
        let changed = external.metadata().unwrap().len();
        assert_eq!(command(&service, COMMIT, upload), Err(SymbolStoreError::StorageUnavailable));
        assert_eq!(store.status(), JournalStatus::Poisoned);
        assert_eq!(store.stats().batches, 0);
        assert_eq!(service.stats(), SymbolStagingStats { uploads: 0, reserved_bytes: 0, received_bytes: 0 });
        assert_eq!(command(&service, BEGIN, upload), Err(SymbolStoreError::StorageUnavailable));
        assert_eq!(service.stats().uploads, 0);
        assert_eq!(std::fs::metadata(path).unwrap().len(), changed);
    }

    #[test]
    fn dropped_chunked_handler_keeps_credit_until_queued_worker_retires_without_committing() {
        for workers in [1, 2] {
            let (_, file) = linked_file();
            let store = Arc::new(DurableSymbolReplicaStore::create(file, "replica",
                AuthKey::from_seed(42), AuthKey::from_seed(99), limits()).unwrap());
            let service = Arc::new(make_service(Arc::clone(&store)));
            let batch = batch();
            let upload = stage(&service, &batch);
            let before = store.committed_bytes();
            let builder = if workers == 1 { RuntimeBuilder::current_thread() }
                else { RuntimeBuilder::multi_thread().worker_threads(workers) };
            let runtime = builder.blocking_threads(1, 1).build().unwrap();
            let (entered, parked) = std::sync::mpsc::channel();
            let (release, hold) = std::sync::mpsc::channel();
            let occupying = runtime.spawn_blocking(move || {
                entered.send(()).unwrap();
                hold.recv_timeout(Duration::from_secs(10)).unwrap();
            }).unwrap();
            parked.recv_timeout(Duration::from_secs(5)).expect("real blocking worker is occupied");
            let pool = runtime.blocking_handle().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let request = request(COMMIT, "replica", &upload_body(upload)).unwrap();
                let mut handler = Box::pin(dispatch(&cx, Arc::clone(&service), NodeId::new("origin"), &request));
                poll_fn(|poll_cx| {
                    assert!(handler.as_mut().poll(poll_cx).is_pending());
                    Poll::Ready(())
                }).await;
                let deadline = Instant::now() + Duration::from_secs(5);
                while pool.pending_count() != 1 {
                    assert!(Instant::now() < deadline, "commit must reach the real pool queue");
                    crate::runtime::yield_now().await;
                }
                assert!(service.in_flight());
                drop(handler); // The actual registration uses this same future.
                assert!(service.in_flight(), "dropping the network future cannot recycle worker credit");
                assert_eq!(store.stats().batches, 0);
                assert_eq!(service.stats().reserved_bytes, upload.total);
                let busy = dispatch(&cx, Arc::clone(&service), NodeId::new("origin"), &request).await;
                assert!(matches!(busy, RemoteOutcome::Failed(message) if message == "durable chunked symbol service is busy"));
                release.send(()).unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                while service.in_flight() {
                    assert!(Instant::now() < deadline, "cancelled worker captures must retire");
                    crate::runtime::yield_now().await;
                }
                assert_eq!(store.stats().batches, 0, "a queued abandoned COMMIT must not execute");
                assert_eq!(store.committed_bytes(), before);
                assert_eq!(service.stats().received_bytes, upload.total,
                    "the unclaimed stage remains available to an explicit retry");
                let outcome = dispatch(&cx, Arc::clone(&service), NodeId::new("origin"), &request).await;
                let RemoteOutcome::Success(bytes) = outcome else { panic!("healthy retry must commit"); };
                super::super::validate_receipt(&bytes[8..], "replica", upload.key, upload.count).unwrap();
                assert!(!service.in_flight());
                assert_eq!(service.stats().reserved_bytes, 0);
                assert_eq!(store.stats().batches, 1);
            });
            assert!(occupying.wait_timeout(Duration::from_secs(1)));
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
        }
    }
}
