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
use std::sync::atomic::{AtomicUsize, Ordering};
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
/// Request credits allow independent uploads to progress while another COMMIT
/// verifies and syncs. The request bound is the staging upload count plus one
/// control slot, with a minimum of two, reduced if necessary so their complete
/// frame allowances fit in `usize`. The durable store still serializes journal
/// work. Saturation refuses before a request copy or spawn; queued/running jobs
/// remain bounded, without a service-owned waiter queue. This is not a fairness
/// guarantee across peers. Stages retain their separate byte reservations.
pub struct DurableChunkedSymbolService {
    inner: ChunkedSymbolService,
    gate: Arc<Credits>,
    max_request_bytes: usize,
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
        let inner = ChunkedSymbolService::new_durable(store, limits);
        let max_request_bytes = inner.request_byte_ceiling();
        let maximum = limits.max_uploads().saturating_add(1).max(2)
            .min(usize::MAX / max_request_bytes);
        Self { inner, gate: Arc::new(Credits { active: AtomicUsize::new(0), maximum }), max_request_bytes }
    }

    /// Whether a queued/running job still owns its request, service and credit.
    #[must_use]
    pub fn in_flight(&self) -> bool { self.gate.active.load(Ordering::Acquire) != 0 }

    /// Volatile upload reservations; committed batches belong to the journal.
    #[must_use]
    pub fn stats(&self) -> SymbolStagingStats { self.inner.stats() }

    /// Retire expired volatile uploads using the registered handler's clock.
    /// This never changes committed disk records or starts a background task.
    pub fn reap_expired(&self, now: Time) -> usize { self.inner.reap_expired(now) }
}

struct Credits {
    active: AtomicUsize,
    maximum: usize,
}

struct Credit(Arc<Credits>);

impl Credit {
    #[allow(deprecated)]
    fn acquire(gate: &Arc<Credits>) -> Option<Self> {
        gate.active.fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
            (active < gate.maximum).then(|| active + 1)
        }).ok()?;
        Some(Self(Arc::clone(gate)))
    }
}

impl Drop for Credit {
    fn drop(&mut self) { self.0.active.fetch_sub(1, Ordering::AcqRel); }
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
    if source.len() > service.max_request_bytes {
        return RemoteOutcome::Failed(SymbolStoreError::Limit("chunked request bytes").to_string());
    }
    let Some(credit) = Credit::acquire(&service.gate) else {
        return RemoteOutcome::Failed("durable chunked symbol service is busy".to_owned());
    };
    let mut input = Zeroizing::new(Vec::new());
    if input.try_reserve_exact(source.len()).is_err() {
        return RemoteOutcome::Failed(SymbolStoreError::Allocation.to_string());
    }
    if input.capacity() > service.max_request_bytes {
        return RemoteOutcome::Failed(SymbolStoreError::Limit("chunked request bytes").to_string());
    }
    input.extend_from_slice(source);
    let job = Job { input, service, peer, _credit: credit };
    let mut task = match cx.spawn_blocking_drained(move |worker| job.execute(&worker)) {
        Ok(task) => task,
        Err(_) => return RemoteOutcome::Failed("durable chunked symbol worker admission refused".to_owned()),
    };
    // The independent join retains actual worker retirement. Acknowledge an
    // observed late cancellation so an enclosing native task's completion
    // policy also preserves this completed result.
    match task.join().await {
        Ok(outcome) => {
            if cx.is_cancel_requested() { let _ = cx.checkpoint(); }
            outcome
        }
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
/// request credit and configured frame ceiling are checked before copying, and
/// that credit lives until the worker retires its request, including dropped
/// handlers and unwinding. Independent uploads may have bounded jobs in the
/// pool while the journal serializes their disk operations.
///
/// Cancellation is checked before a synchronous transaction. Once it starts,
/// it cannot preempt fsync or undo a commit. The owning region must drain that
/// blocking task; a stuck filesystem can delay the drain. A cancelled/lost
/// response therefore must not be interpreted as rollback. Dispatch preserves
/// an observed late cancellation's completed worker result; the remote server's
/// lease/session cancellation policy can still report a cancelled operation.
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
    use crate::channel::oneshot;
    use crate::distributed::symbol_service::durable::{DurableSymbolLimits, JournalStatus};
    use crate::distributed::symbol_service::service::chunked::{
        BEGIN, CHUNK, COMMIT, Upload, read_progress, request, upload_body,
    };
    use crate::distributed::symbol_service::{
        EncodedSymbolBatch, SymbolBatchLimits, SymbolStoreLimits, encode_symbol_batch,
    };
    use crate::security::{AuthKey, SecurityContext};
    use crate::types::symbol::Symbol;
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
    use crate::sync::Notify;
    use crate::types::CancelReason;
    use std::fs::{File, OpenOptions};
    use std::future::{Future, poll_fn};
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::sync::{Condvar, Mutex as StdMutex};
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
        stage_for(service, &NodeId::new("origin"), batch, 77, Time::ZERO)
    }

    fn stage_for(service: &DurableChunkedSymbolService, peer: &NodeId, batch: &EncodedSymbolBatch, attempt: u64, now: Time) -> Upload {
        let upload = Upload { key: batch.key(), attempt, total: batch.as_ref().len(), count: batch.symbol_count() };
        service.inner.handle(peer, now,
            &request(BEGIN, "replica", &upload_body(upload)).unwrap()).unwrap();
        for (index, piece) in batch.as_ref().chunks(128).enumerate() {
            let mut body = upload_body(upload);
            body.extend_from_slice(&((index * 128) as u64).to_le_bytes());
            body.extend_from_slice(piece);
            service.inner.handle(peer, now,
                &request(CHUNK, "replica", &body).unwrap()).unwrap();
        }
        upload
    }

    #[derive(Default)]
    struct CommitGate {
        entered: AtomicBool,
        changed: Notify,
        released: StdMutex<bool>,
        release_changed: Condvar,
    }

    impl CommitGate {
        fn block(&self) {
            self.entered.store(true, Ordering::Release);
            self.changed.notify_waiters();
            let released = self.released.lock().unwrap();
            let (released, _) = self.release_changed
                .wait_timeout_while(released, Duration::from_secs(15), |released| !*released).unwrap();
            assert!(*released, "commit gate must be released");
        }

        fn release(&self) {
            *self.released.lock().unwrap_or_else(|error| error.into_inner()) = true;
            self.release_changed.notify_all();
        }

        async fn entered(&self) {
            self.changed.wait_until(|| self.entered.load(Ordering::Acquire)).await;
        }
    }

    struct ReleaseCommit(Arc<CommitGate>);

    impl Drop for ReleaseCommit {
        fn drop(&mut self) { self.0.release(); }
    }

    #[test]
    fn independent_durable_upload_completes_while_another_commit_owns_credit_and_is_cancelled() {
        for workers in [1, 2] {
            let (path, file) = linked_file();
            let mut bounds = limits();
            bounds.store.max_batches = 2;
            bounds.store.max_bytes = 8192;
            bounds.max_journal_bytes = 16384;
            let store = Arc::new(DurableSymbolReplicaStore::create(file, "replica",
                AuthKey::from_seed(42), AuthKey::from_seed(99), bounds).unwrap());
            let service = Arc::new(DurableChunkedSymbolService::new(Arc::clone(&store),
                SymbolChunkedLimits::new(128, 2, 8192, 1, 4096, Duration::from_secs(60)).unwrap()));
            let batch = batch();
            let alice = NodeId::new("alice");
            let bob = NodeId::new("bob");
            let staged_at = crate::time::wall_now();
            let first_upload = stage_for(&service, &alice, &batch, 1, staged_at);
            let second_upload = Upload { attempt: 2, ..first_upload };
            service.inner.handle(&bob, staged_at,
                &request(BEGIN, "replica", &upload_body(second_upload)).unwrap()).unwrap();
            let gate = Arc::new(CommitGate::default());
            let paused = Arc::clone(&gate);
            let commits = AtomicUsize::new(0);
            *service.inner.commit_hook.lock() = Some(Arc::new(move || {
                if commits.fetch_add(1, Ordering::SeqCst) == 0 { paused.block(); }
            }));
            let builder = if workers == 1 { RuntimeBuilder::current_thread() }
                else { RuntimeBuilder::multi_thread().worker_threads(workers) };
            // One actual pool worker holds the first COMMIT; the other must
            // carry independent CHUNK/COMMIT traffic to completion.
            let runtime = builder.blocking_threads(2, 2).build().unwrap();
            let _release_on_unwind = ReleaseCommit(Arc::clone(&gate));
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                crate::time::timeout(cx.now(), Duration::from_secs(10), async {
                    let first_service = Arc::clone(&service);
                    let first_peer = alice.clone();
                    let frame = request(COMMIT, "replica", &upload_body(first_upload)).unwrap();
                    let (body_sender, mut body_receiver) = oneshot::channel();
                    let mut first = cx.spawn(move |body| async move {
                        body_sender.send_blocking(body.clone()).unwrap();
                        dispatch(&body, first_service, first_peer, &frame).await
                    }).unwrap();
                    gate.entered().await;
                    let body: Cx = body_receiver.recv(&cx).await.unwrap();
                    assert!(service.in_flight());
                    assert!(!first.is_finished());
                    for (index, piece) in batch.as_ref().chunks(128).enumerate() {
                        let mut body = upload_body(second_upload);
                        body.extend_from_slice(&((index * 128) as u64).to_le_bytes());
                        body.extend_from_slice(piece);
                        let frame = request(CHUNK, "replica", &body).unwrap();
                        let outcome = dispatch(&cx, Arc::clone(&service), bob.clone(), &frame).await;
                        let RemoteOutcome::Success(progress) = outcome else {
                            panic!("an independent chunk cannot be refused by another upload's COMMIT");
                        };
                        assert_eq!(read_progress(&progress, second_upload).unwrap().0,
                            (index * 128) + piece.len());
                    }
                    let frame = request(COMMIT, "replica", &upload_body(second_upload)).unwrap();
                    let outcome = dispatch(&cx, Arc::clone(&service), bob.clone(), &frame).await;
                    let RemoteOutcome::Success(receipt) = outcome else { panic!("second upload must commit"); };
                    super::super::validate_receipt(&receipt[8..], "replica", second_upload.key, second_upload.count).unwrap();
                    assert_eq!(store.stats().batches, 1);
                    assert_eq!(service.stats().reserved_bytes, first_upload.total);
                    assert!(!first.is_finished());

                    // This is a real spawned invocation, and cancellation is
                    // observed without acknowledging it on dispatch's behalf.
                    first.abort_with_reason(CancelReason::user("late chunked receipt cancellation"));
                    body.cancelled().await;
                    assert!(body.is_cancel_requested());
                    gate.release();
                    let outcome = first.join(&cx).await.expect("completed worker result survives task completion policy");
                    let RemoteOutcome::Success(receipt) = outcome else { panic!("first upload must retain its durable receipt"); };
                    super::super::validate_receipt(&receipt[8..], "replica", first_upload.key, first_upload.count).unwrap();
                    assert!(!service.in_flight());
                    assert_eq!(store.stats().batches, 2);
                    assert_eq!(service.stats(), SymbolStagingStats { uploads: 0, reserved_bytes: 0, received_bytes: 0 });
                }).await.expect("both independent uploads must complete before the watchdog");
            });
            let report = runtime.shutdown_drained(Duration::from_secs(5));
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
            assert_eq!(report.live_tasks, 0);
            assert_eq!(report.live_regions, 0);
            assert_eq!(report.pending_obligations, 0);
            assert_eq!(report.pending_spawns, 0);
            assert_eq!(report.queued_finalizers, 0);
            assert!(!report.has_pending_obligation_posts);
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
            drop(service);
            drop(store);
            let file = OpenOptions::new().read(true).write(true).open(path).unwrap();
            let reopened = DurableSymbolReplicaStore::open(file, "replica",
                AuthKey::from_seed(42), AuthKey::from_seed(99), bounds).unwrap();
            assert_eq!(reopened.stats().batches, 2);
            for peer in [&alice, &bob] {
                assert_eq!(reopened.get(peer, batch.key()).unwrap().as_ref().as_ref(), batch.as_ref());
            }
        }
    }

    #[test]
    fn request_frame_credit_accepts_the_full_chunk_and_refuses_excess_before_copy_or_spawn() {
        let (_, file) = linked_file();
        let store = Arc::new(DurableSymbolReplicaStore::create(file, "replica",
            AuthKey::from_seed(42), AuthKey::from_seed(99), limits()).unwrap());
        let service = Arc::new(make_service(Arc::clone(&store)));
        assert_eq!(service.max_request_bytes, 14 + "replica".len() + 68 + 8 + 128);
        let huge = DurableChunkedSymbolService::new(Arc::clone(&store),
            SymbolChunkedLimits::new(128, usize::MAX, usize::MAX, usize::MAX,
                usize::MAX, Duration::from_secs(60)).unwrap());
        assert!(huge.gate.maximum.checked_mul(huge.max_request_bytes).is_some(),
            "derived complete-frame credit cannot overflow the address-space bound");
        assert!(huge.gate.maximum > 0);
        let batch = batch();
        let upload = Upload { key: batch.key(), attempt: 1, total: batch.as_ref().len(), count: batch.symbol_count() };
        service.inner.handle(&NodeId::new("origin"), crate::time::wall_now(),
            &request(BEGIN, "replica", &upload_body(upload)).unwrap()).unwrap();
        let mut body = upload_body(upload);
        body.extend_from_slice(&0_u64.to_le_bytes());
        body.extend_from_slice(&batch.as_ref()[..128]);
        let full_chunk = request(CHUNK, "replica", &body).unwrap();
        assert_eq!(full_chunk.len(), service.max_request_bytes);
        let oversized = vec![0; service.max_request_bytes + 1];
        let before = store.committed_bytes();
        let runtime = RuntimeBuilder::current_thread().blocking_threads(1, 1).build().unwrap();
        let pool = runtime.blocking_handle().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let outcome = dispatch(&cx, Arc::clone(&service), NodeId::new("origin"), &oversized).await;
            assert!(matches!(outcome, RemoteOutcome::Failed(message)
                if message == SymbolStoreError::Limit("chunked request bytes").to_string()));
            assert!(!service.in_flight());
            assert_eq!(pool.pending_count(), 0);
            assert_eq!(service.stats().received_bytes, 0);
            let outcome = dispatch(&cx, Arc::clone(&service), NodeId::new("origin"), &full_chunk).await;
            let RemoteOutcome::Success(progress) = outcome else { panic!("maximum legitimate chunk must fit its frame credit"); };
            assert_eq!(read_progress(&progress, upload).unwrap(), (128, 128));
            assert!(!service.in_flight());
        });
        assert_eq!(store.committed_bytes(), before, "progress and oversized refusal do not commit");
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
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
            let upload = stage_for(&service, &NodeId::new("origin"), &batch, 77, crate::time::wall_now());
            let before = store.committed_bytes();
            let builder = if workers == 1 { RuntimeBuilder::current_thread() }
                else { RuntimeBuilder::multi_thread().worker_threads(workers) };
            let runtime = builder.blocking_threads(1, 1).build().unwrap();
            let (entered, parked) = std::sync::mpsc::channel();
            let (release, hold) = std::sync::mpsc::channel();
            let occupying = runtime.spawn_blocking(move || {
                entered.send(()).unwrap();
                hold.recv_timeout(Duration::from_secs(30)).unwrap();
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
                let mut second = Box::pin(dispatch(&cx, Arc::clone(&service), NodeId::new("origin"), &request));
                poll_fn(|poll_cx| {
                    assert!(second.as_mut().poll(poll_cx).is_pending());
                    Poll::Ready(())
                }).await;
                let deadline = Instant::now() + Duration::from_secs(5);
                while pool.pending_count() != 2 {
                    assert!(Instant::now() < deadline, "both frame owners must reach the real pool queue");
                    crate::runtime::yield_now().await;
                }
                drop(second);
                assert_eq!(service.gate.active.load(Ordering::Acquire), 2);
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
