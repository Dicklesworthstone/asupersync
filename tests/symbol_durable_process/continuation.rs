//! Resumed effects after real replica-process death, using the existing harness.

use super::*;
use asupersync::cx::ChildRegionSpec;
use asupersync::distributed::membership::authority::{MembershipControllerLimits, MembershipFloor, MembershipUpdate};
use asupersync::distributed::membership::durable::{MembershipJournal, MembershipJournalConfig, PersistentMembershipController};
use asupersync::distributed::membership::owned::{OwnedLeaseStatus, OwnedMembershipController};
use asupersync::distributed::membership::owned::work::MembershipWorkTrigger;
use asupersync::distributed::membership::{MembershipEvent, MembershipKind};
use asupersync::distributed::symbol_service::checkpoint::{CheckpointAuthority, CheckpointConfig, ManifestLimits, RecoveryManifest};
use asupersync::distributed::symbol_service::checkpoint::continuation::{
    ContinuationError, ContinuationFuture, ContinuationLimits, ContinuationRecoveryError,
    RestorableWorkload, StateCodecError, checkpoint_workload,
};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::task::Poll;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Progress { job: u64, next: u64, end: u64 }
struct Writer<const REV: u32> {
    endpoint: SocketAddr, // Trusted local provisioning, NEVER decoded from state.
    window: u64,
    starts: AtomicUsize,
    parked: Option<mpsc::SyncSender<()>>,
}
impl<const REV: u32> Writer<REV> {
    fn new(endpoint: SocketAddr, window: u64) -> Self {
        Self { endpoint, window, starts: AtomicUsize::new(0), parked: None }
    }
}
impl<const REV: u32> RestorableWorkload for Writer<REV> {
    const NAME: &'static str = "integration.acknowledged-sequence-writer";
    const REVISION: u32 = REV;
    const STATE_SCHEMA: [u8; 32] = [0x19; 32];
    type State = Progress;
    type Output = io::Result<Progress>;
    fn encode_state(&self, state: &Progress) -> Result<Vec<u8>, StateCodecError> {
        if state.job != 777 || state.next > state.end || state.end > 64 { return Err(StateCodecError::Invalid); }
        Ok([state.job.to_le_bytes(), state.next.to_le_bytes(), state.end.to_le_bytes()].concat())
    }
    fn decode_state(&self, bytes: &[u8]) -> Result<Progress, StateCodecError> {
        if bytes.len() != 24 { return Err(StateCodecError::Invalid); }
        let state = Progress { job: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            next: u64::from_le_bytes(bytes[8..16].try_into().unwrap()), end: u64::from_le_bytes(bytes[16..].try_into().unwrap()) };
        if state.job != 777 || state.next > state.end || state.end > 64 { return Err(StateCodecError::Invalid); }
        Ok(state)
    }
    fn resume(self: Arc<Self>, cx: Cx, mut state: Progress) -> ContinuationFuture<Self::Output> {
        self.starts.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            cx.checkpoint().map_err(|_| io::Error::from(io::ErrorKind::Interrupted))?;
            let mut stream = TcpStream::connect(self.endpoint).await?;
            let end = state.end.min(state.next.saturating_add(self.window));
            let mut reported = false;
            while state.next < end {
                cx.checkpoint().map_err(|_| io::Error::from(io::ErrorKind::Interrupted))?;
                stream.write_all(&[state.job.to_le_bytes(), state.next.to_le_bytes()].concat()).await?;
                let mut ack = [0; 8];
                {
                    let mut read = std::pin::pin!(stream.read_exact(&mut ack));
                    let mut cancelled = std::pin::pin!(cx.cancelled());
                    poll_fn(|task| {
                        if cancelled.as_mut().poll(task).is_ready() {
                            return Poll::Ready(Err(io::Error::from(io::ErrorKind::Interrupted)));
                        }
                        let result = read.as_mut().poll(task).map(|r| r.map(|_| ()));
                        if result.is_pending() && !reported {
                            if let Some(tx) = &self.parked {
                                tx.try_send(()).expect("one actual Pending read witness");
                                reported = true;
                            }
                        }
                        result
                    }).await?;
                }
                if u64::from_le_bytes(ack) != state.next { return Err(io::ErrorKind::InvalidData.into()); }
                state.next += 1; // Checkpoint advances only after the peer's exact acknowledgement.
            }
            stream.shutdown().await?;
            drop(stream);
            Ok(state)
        })
    }
}

// Explicit local test protocol, not a production authenticated effect service.
// The receiver retains progress across both producer runtimes. Every observed
// step must be the next one, so replaying the already-acknowledged prefix fails.
struct Sink {
    address: SocketAddr,
    quit: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<Vec<u64>>>>,
}
impl Sink {
    fn new(start: u64, end: u64, withhold_ack: bool) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let quit = Arc::new(AtomicBool::new(false)); let stop = Arc::clone(&quit);
        let worker = thread::spawn(move || {
            let mut expected = start; let mut seen = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(45);
            while expected < end {
                let (mut socket, _) = loop {
                    if stop.load(Ordering::Acquire) { return Err(io::ErrorKind::Interrupted.into()); }
                    if Instant::now() >= deadline { return Err(io::ErrorKind::TimedOut.into()); }
                    match listener.accept() {
                        Ok(value) => break value,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(1)),
                        Err(error) => return Err(error),
                    }
                };
                socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                socket.set_write_timeout(Some(Duration::from_secs(5)))?;
                loop {
                    // Distinguish clean boundary EOF from a partial protocol frame.
                    let mut record = [0; 16];
                    let n = Read::read(&mut socket, &mut record[..1])?;
                    if n == 0 { break; }
                    Read::read_exact(&mut socket, &mut record[1..])?;
                    let job = u64::from_le_bytes(record[..8].try_into().unwrap());
                    let step = u64::from_le_bytes(record[8..].try_into().unwrap());
                    if job != 777 || step != expected || expected >= end { return Err(io::ErrorKind::InvalidData.into()); }
                    seen.push(step); expected += 1;
                    if withhold_ack {
                        let mut byte = [0];
                        if Read::read(&mut socket, &mut byte)? != 0 { return Err(io::ErrorKind::InvalidData.into()); }
                        return Ok(seen); // Peer-observed EOF, not merely a returned cancellation value.
                    }
                    Write::write_all(&mut socket, &step.to_le_bytes())?;
                }
            }
            Ok(seen)
        });
        Self { address, quit, worker: Some(worker) }
    }
    fn finish(mut self) -> Vec<u64> { self.worker.take().unwrap().join().unwrap().unwrap() }
}
impl Drop for Sink {
    fn drop(&mut self) {
        self.quit.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

fn continuation_limits() -> ContinuationLimits {
    ContinuationLimits { max_snapshot_bytes: 4096, max_state_bytes: 24 }
}
fn decode_limits() -> SnapshotDecodeLimits {
    SnapshotDecodeLimits { max_snapshot_bytes: 4096, max_source_symbols_per_block: 32, max_source_blocks: 4 }
}
fn manifest_limits() -> ManifestLimits {
    ManifestLimits { max_encoded_bytes: 4096, max_replicas: 1, max_decoded_bytes: 4096 }
}
fn recovery() -> RemoteRecoveryConfig {
    RemoteRecoveryConfig { max_replicas: 1, max_concurrent_requests: 1, required_replicas: 1,
        recovery_timeout: Duration::from_secs(8), replica_timeout: Duration::from_secs(6),
        max_received_symbols: 64, max_received_payload_bytes: 16384 }
}
fn decision(incarnation: u64, sequence: u64, kind: MembershipKind) -> Vec<u8> {
    MembershipUpdate { event: MembershipEvent { node: NodeId::new("worker"), incarnation, kind }, sequence }
        .authenticated_bytes(&NodeId::new("authority"), 8, &AuthKey::from_seed(33)).unwrap()
}
fn volatile_owner(cx: &Cx) -> OwnedMembershipController {
    let owner = OwnedMembershipController::new(NodeId::new("authority"), 8, AuthKey::from_seed(33),
        vec![MembershipFloor { node: NodeId::new("worker"), incarnation: 0, sequence: 0 }],
        MembershipControllerLimits { max_members: 1, max_lease_ids: 8 }, cx.timer_driver().unwrap()).unwrap();
    owner.apply_authenticated(&NodeId::new("authority"), &decision(1, 1, MembershipKind::Alive)).unwrap(); owner
}
fn membership_config() -> MembershipJournalConfig {
    MembershipJournalConfig { authority: NodeId::new("authority"), epoch: 8,
        statement_key: AuthKey::from_seed(33), journal_key: AuthKey::from_seed(34),
        floors: vec![MembershipFloor { node: NodeId::new("worker"), incarnation: 0, sequence: 0 }],
        controller_limits: MembershipControllerLimits { max_members: 1, max_lease_ids: 8 }, max_journal_bytes: 16384 }
}
fn persistent_owner(runtime: &asupersync::runtime::Runtime) -> PersistentMembershipController {
    let path = journal_path();
    let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
    let mut journal = MembershipJournal::create(file, membership_config()).unwrap();
    journal.append(&decision(1, 1, MembershipKind::Alive)).unwrap();
    journal.append(&decision(1, 2, MembershipKind::Dead)).unwrap();
    journal.append(&decision(2, 3, MembershipKind::Alive)).unwrap();
    drop(journal);
    let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
    let journal = MembershipJournal::open(file, membership_config()).unwrap();
    let clock = runtime.block_on(async { Cx::current().unwrap().timer_driver().unwrap() });
    // Disk and recovery setup is outside any executor poll.
    PersistentMembershipController::new(journal, clock).unwrap()
}
async fn publish(cx: &Cx, endpoint: SocketAddr, workload: &Writer<1>, state: &Progress)
    -> (Vec<u8>, SnapshotIdentity)
{
    let transport = transport(cx, endpoint);
    let mut snapshot = RegionSnapshot::empty(cx.region_id());
    snapshot.origin_id = 77; snapshot.epoch = 5; snapshot.sequence = 9;
    let expected = SnapshotIdentity { region_id: snapshot.region_id, origin_id: 77, epoch: 5, sequence: 9 };
    let snapshot = checkpoint_workload(snapshot, workload, state, &AuthKey::from_seed(88), continuation_limits()).unwrap();
    let mut encoder = StateEncoder::new(EncodingConfig { symbol_size: 128, max_source_blocks: 2,
        min_repair_symbols: 0, repair_overhead: 1.0, path_quality: None }, DetRng::new(3));
    let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
    let security = SecurityContext::new(AuthKey::from_seed(42)); security.authorize_replica("replica", None).unwrap();
    let mut distributor = SymbolDistributor::new(DistributionConfig { consistency: ConsistencyLevel::All,
        max_concurrent: 1, ack_timeout: Duration::from_secs(8), ..Default::default() });
    let checkpoint = transport.replicate_checkpoint(&mut distributor, &encoded, &[ReplicaInfo::new("replica", "ignored")],
        &security, CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(89) },
        CheckpointConfig { manifest: manifest_limits(), decode: decode_limits(), minimum_recovery_replicas: 1,
            timeout: Duration::from_secs(10) }).await.unwrap();
    assert_eq!(transport.in_flight(), 0);
    (checkpoint.encoded_manifest().to_vec(), expected)
}
fn manifest(bytes: &[u8], expected: SnapshotIdentity) -> RecoveryManifest {
    RecoveryManifest::from_canonical_bytes(bytes, &AuthKey::from_seed(89), expected, &NodeId::new("origin"), manifest_limits()).unwrap()
}

#[test]
fn recovered_application_resumes_tcp_suffix_after_replica_crash_under_persistent_membership() {
    for workers in [1, 2] {
        let sink = Sink::new(0, 12, false);
        let path = journal_path(); let replica = Process::start(&path, "create");
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let (bytes, expected) = runtime.block_on(async {
            let cx = Cx::current().unwrap(); let owner = volatile_owner(&cx);
            let workload = Arc::new(Writer::<1>::new(sink.address, 5));
            let running = Arc::clone(&workload);
            let report = owner.run_scoped(&cx, &NodeId::new("worker"), 1, Duration::from_secs(5), ChildRegionSpec::inherit(),
                move |child| async move { running.resume(child, Progress { job: 777, next: 0, end: 12 }).await }).await.unwrap();
            assert!(report.is_success()); let state = report.task.unwrap().unwrap(); assert_eq!(state.next, 5);
            let published = publish(&cx, replica.address, workload.as_ref(), &state).await;
            owner.close(); published // Source state, workload, snapshot, encoder and batch owners are all dropped.
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        let saved = journal_path();
        let mut file = OpenOptions::new().read(true).write(true).open(&saved).unwrap();
        Write::write_all(&mut file, &bytes).unwrap(); file.sync_all().unwrap(); drop(file); drop(bytes);
        replica.crash_after_ack();
        let replica = Process::start(&path, "reopen");
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        let owner = persistent_owner(&runtime);
        let mut bytes = Vec::new(); File::open(saved).unwrap().take(4097).read_to_end(&mut bytes).unwrap();
        assert!(bytes.len() <= 4096); let manifest = manifest(&bytes, expected); drop(bytes);
        let workload = Arc::new(Writer::<1>::new(sink.address, 64));
        runtime.block_on(async {
            let cx = Cx::current().unwrap(); let transport = transport(&cx, replica.address);
            let prepared = transport.recover_workload(&manifest, recovery(), decode_limits(), &AuthKey::from_seed(88),
                continuation_limits(), Arc::clone(&workload)).await.unwrap();
            assert_eq!(workload.starts.load(Ordering::Relaxed), 0, "recovery must not execute before local admission");
            let report = prepared.run_persistent(&owner, &cx, &NodeId::new("worker"), 2, Duration::from_secs(5),
                ChildRegionSpec::inherit()).await.unwrap();
            assert!(report.is_success(), "{report:?}"); assert_eq!(report.task.unwrap().unwrap().next, 12);
            assert_eq!(transport.in_flight(), 0); assert_eq!(owner.live_leases(), 0); assert!(!cx.is_cancel_requested());
        });
        assert_eq!(workload.starts.load(Ordering::Relaxed), 1); owner.close(); drop(owner);
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3))); replica.finish(1);
        assert_eq!(sink.finish(), (0_u64..12).collect::<Vec<_>>(), "acknowledged prefix is never sent twice");
    }
}

#[test]
fn network_recovery_rejects_wrong_workload_and_small_snapshot_budget_without_resumed_effects() {
    let path = journal_path(); let replica = Process::start(&path, "create");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap(); let source = Writer::<1>::new(endpoint, 64);
        let (bytes, expected) = publish(&cx, replica.address, &source, &Progress { job: 777, next: 5, end: 12 }).await;
        let manifest = manifest(&bytes, expected); let transport = transport(&cx, replica.address);
        let wrong = Arc::new(Writer::<2>::new(endpoint, 64));
        assert!(matches!(transport.recover_workload(&manifest, recovery(), decode_limits(), &AuthKey::from_seed(88),
            continuation_limits(), Arc::clone(&wrong)).await,
            Err(ContinuationRecoveryError::Continuation(ContinuationError::Workload))));
        let too_small = ContinuationLimits { max_snapshot_bytes: 1, ..continuation_limits() };
        assert!(matches!(transport.recover_workload(&manifest, recovery(), decode_limits(), &AuthKey::from_seed(88),
            too_small, Arc::clone(&wrong)).await,
            Err(ContinuationRecoveryError::Continuation(ContinuationError::Limit("snapshot bytes")))));
        assert_eq!(wrong.starts.load(Ordering::Relaxed), 0); assert_eq!(transport.in_flight(), 0);
        assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3))); replica.finish(1);
}

// No failure path detaches the authority thread. Its channel wait is bounded;
// dropping the runner/controller cannot falsely pass as a successful revocation.
struct Revoker { owner: OwnedMembershipController, thread: Option<JoinHandle<()>> }
impl Revoker {
    fn finish(mut self) { self.thread.take().unwrap().join().expect("revocation owner"); }
}
impl Drop for Revoker {
    fn drop(&mut self) {
        self.owner.close();
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

#[test]
fn revoked_restored_work_closes_a_genuinely_parked_tcp_effect_before_reporting() {
    let sink = Sink::new(5, 6, true);
    let path = journal_path(); let replica = Process::start(&path, "create");
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let result = runtime.block_on(async {
        let cx = Cx::current().unwrap(); let owner = volatile_owner(&cx);
        let source = Writer::<1>::new(sink.address, 64);
        let (bytes, expected) = publish(&cx, replica.address, &source, &Progress { job: 777, next: 5, end: 12 }).await;
        let manifest = manifest(&bytes, expected); let transport = transport(&cx, replica.address);
        let (tx, rx) = mpsc::sync_channel(1);
        let workload = Arc::new(Writer::<1> { parked: Some(tx), ..Writer::new(sink.address, 64) });
        let prepared = transport.recover_workload(&manifest, recovery(), decode_limits(), &AuthKey::from_seed(88),
            continuation_limits(), Arc::clone(&workload)).await.unwrap();
        let authority = owner.clone();
        let revoke = Revoker { owner: owner.clone(), thread: Some(thread::spawn(move || {
            rx.recv_timeout(Duration::from_secs(8)).expect("actual Pending effect read");
            authority.apply_authenticated(&NodeId::new("authority"), &decision(1, 2, MembershipKind::Dead)).unwrap();
        })) };
        let report = asupersync::time::timeout(cx.now(), Duration::from_secs(10),
            prepared.run(&owner, &cx, &NodeId::new("worker"), 1, Duration::from_secs(30), ChildRegionSpec::inherit())).await;
        owner.close(); revoke.finish();
        let report = report.expect("continuation drain deadline").unwrap();
        assert!(!report.is_success());
        assert!(matches!(report.trigger, MembershipWorkTrigger::LeaseEnded(OwnedLeaseStatus::Revoked)));
        assert!(report.close.is_ok()); assert_eq!(owner.live_leases(), 0); assert_eq!(transport.in_flight(), 0);
        assert!(!cx.is_cancel_requested()); report
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3))); replica.finish(1);
    assert_eq!(sink.finish(), vec![5]); assert!(!result.is_success());
}
