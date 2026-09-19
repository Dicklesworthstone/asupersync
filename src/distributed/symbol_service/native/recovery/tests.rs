use super::*;
use crate::distributed::{EncodedState, EncodingConfig, StateEncoder};
use crate::time::{TimerDriver, VirtualClock};
use crate::types::symbol::Symbol;
use crate::types::CancelKind;
use crate::util::{ArenaIndex, DetRng};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

fn config() -> RemoteRecoveryConfig {
    RemoteRecoveryConfig {
        max_replicas: 4, max_concurrent_requests: 2, required_replicas: 2,
        recovery_timeout: Duration::from_nanos(100), replica_timeout: Duration::from_nanos(10),
        max_received_symbols: 100, max_received_payload_bytes: 10_000,
    }
}
fn plan(count: usize) -> Vec<ReplicaFetch> {
    (0..count).map(|i| ReplicaFetch {
        replica_id: format!("r{i}"), key: SymbolBatchKey { object_id: ObjectId::new_for_test(1), digest: [i as u8; 32] },
    }).collect()
}
#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes { fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); } }
struct Lab {
    cx: Cx, clock: Arc<VirtualClock>, driver: Arc<TimerDriver<VirtualClock>>, timer: TimerDriverHandle,
    wakes: Arc<Wakes>, waker: Waker,
}
impl Lab {
    fn new() -> Self {
        let clock = Arc::new(VirtualClock::new());
        let driver = Arc::new(TimerDriver::with_clock(Arc::clone(&clock)));
        let timer = TimerDriverHandle::new(Arc::clone(&driver));
        let wakes = Arc::new(Wakes::default());
        Self { cx: Cx::for_testing(), clock, driver, timer, waker: Waker::from(Arc::clone(&wakes)), wakes }
    }
    fn advance(&self, n: u64) { self.clock.advance(n); self.driver.process_timers(); }
    fn poll<F: Future>(&self, future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(&self.waker))
    }
}
struct Probe {
    ready: Vec<AtomicBool>, batches: Vec<Vec<AuthenticatedSymbol>>,
    active: AtomicUsize, peak: AtomicUsize, starts: Vec<AtomicUsize>, drops: AtomicUsize,
}
impl Probe {
    fn new(count: usize) -> Self {
        let security = SecurityContext::new(AuthKey::from_seed(42));
        Self {
            ready: (0..count).map(|_| AtomicBool::new(true)).collect(),
            batches: (0..count).map(|i| vec![security.sign_symbol(&Symbol::new_for_test(1, 0, i as u32, &[i as u8; 4]))]).collect(),
            active: AtomicUsize::new(0), peak: AtomicUsize::new(0), starts: (0..count).map(|_| AtomicUsize::new(0)).collect(),
            drops: AtomicUsize::new(0),
        }
    }
    fn fetch<'a>(&'a self, name: &str) -> FetchFuture<'a> {
        let index: usize = name[1..].parse().unwrap();
        self.starts[index].fetch_add(1, Ordering::SeqCst);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        Box::pin(Query { probe: self, index })
    }
}
struct Query<'a> { probe: &'a Probe, index: usize }
impl Future for Query<'_> {
    type Output = Result<Vec<AuthenticatedSymbol>, RemoteSymbolError>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        if self.probe.ready[self.index].load(Ordering::Acquire) {
            Poll::Ready(Ok(self.probe.batches[self.index].clone()))
        } else { Poll::Pending }
    }
}
impl Drop for Query<'_> {
    fn drop(&mut self) { self.probe.active.fetch_sub(1, Ordering::SeqCst); self.probe.drops.fetch_add(1, Ordering::SeqCst); }
}
fn ready<T>(poll: Poll<Result<T, RemoteRecoveryError>>) -> Result<T, RemoteRecoveryError> {
    match poll { Poll::Ready(result) => result, Poll::Pending => panic!("expected terminal collection") }
}

#[test]
fn stalled_first_replica_does_not_block_healthy_peers_and_cleanup_precedes_output() {
    let lab = Lab::new(); let requests = plan(3); let probe = Probe::new(3);
    probe.ready[0].store(false, Ordering::Release);
    let mut run = Box::pin(collect(&lab.cx, &requests, config(), lab.timer.clone(), |id, _| probe.fetch(id)));
    assert!(lab.poll(run.as_mut()).is_pending());
    assert_eq!(probe.starts[1].load(Ordering::SeqCst), 1);
    assert!(lab.poll(run.as_mut()).is_pending());
    assert_eq!(probe.starts[2].load(Ordering::SeqCst), 1);
    lab.advance(10);
    let result = ready(lab.poll(run.as_mut())).unwrap();
    assert_eq!(result.responding_replicas(), &["r1", "r2"]);
    assert_eq!(result.failures()[0].kind, ReplicaFetchFailureKind::Deadline);
    assert_eq!(probe.peak.load(Ordering::SeqCst), 2);
    assert_eq!(probe.active.load(Ordering::SeqCst), 0);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 3);
    assert_eq!(result.duration(), Duration::from_nanos(10));
}

#[test]
fn queued_replica_gets_its_own_deadline_at_admission() {
    let lab = Lab::new(); let requests = plan(2); let probe = Probe::new(2);
    for flag in &probe.ready { flag.store(false, Ordering::Release); }
    let mut cfg = config(); cfg.max_concurrent_requests = 1; cfg.required_replicas = 1;
    let mut run = Box::pin(collect(&lab.cx, &requests, cfg, lab.timer.clone(), |id, _| probe.fetch(id)));
    assert!(lab.poll(run.as_mut()).is_pending()); lab.advance(10);
    assert!(lab.poll(run.as_mut()).is_pending());
    assert!(lab.poll(run.as_mut()).is_pending()); // Second admission at t=10.
    lab.advance(5); probe.ready[1].store(true, Ordering::Release);
    assert_eq!(ready(lab.poll(run.as_mut())).unwrap().responding_replicas(), &["r1"]);
}

#[test]
fn required_replica_count_does_not_shrink_after_timeouts() {
    let lab = Lab::new(); let requests = plan(3); let probe = Probe::new(3);
    probe.ready[0].store(false, Ordering::Release);
    let mut cfg = config(); cfg.required_replicas = 3; cfg.max_concurrent_requests = 3;
    let mut run = Box::pin(collect(&lab.cx, &requests, cfg, lab.timer.clone(), |id, _| probe.fetch(id)));
    assert!(lab.poll(run.as_mut()).is_pending()); lab.advance(10);
    assert!(matches!(ready(lab.poll(run.as_mut())), Err(RemoteRecoveryError::Quorum { required: 3, received: 2, .. })));
}

#[test]
fn cancellation_wakes_a_parked_collection_and_retires_all_queries() {
    let lab = Lab::new(); let requests = plan(3); let probe = Probe::new(3);
    for flag in &probe.ready { flag.store(false, Ordering::Release); }
    let mut run = Box::pin(collect(&lab.cx, &requests, config(), lab.timer.clone(), |id, _| probe.fetch(id)));
    assert!(lab.poll(run.as_mut()).is_pending());
    let before = lab.wakes.0.load(Ordering::SeqCst);
    lab.cx.cancel_fast(CancelKind::User);
    assert!(lab.wakes.0.load(Ordering::SeqCst) > before);
    assert!(matches!(ready(lab.poll(run.as_mut())), Err(RemoteRecoveryError::Cancelled)));
    assert_eq!(probe.active.load(Ordering::SeqCst), 0);
    assert_eq!(probe.starts[2].load(Ordering::SeqCst), 0);
}

#[test]
fn external_drop_retires_all_admitted_queries_without_new_requests() {
    let lab = Lab::new(); let requests = plan(3); let probe = Probe::new(3);
    for flag in &probe.ready { flag.store(false, Ordering::Release); }
    let mut run = Box::pin(collect(&lab.cx, &requests, config(), lab.timer.clone(), |id, _| probe.fetch(id)));
    assert!(lab.poll(run.as_mut()).is_pending()); drop(run);
    assert_eq!(probe.active.load(Ordering::SeqCst), 0);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 2);
    assert_eq!(probe.starts[2].load(Ordering::SeqCst), 0);
}

#[test]
fn total_deadline_wins_against_simultaneous_success() {
    let lab = Lab::new(); let requests = plan(2); let probe = Probe::new(2);
    for flag in &probe.ready { flag.store(false, Ordering::Release); }
    let mut cfg = config(); cfg.recovery_timeout = Duration::from_nanos(5);
    let mut run = Box::pin(collect(&lab.cx, &requests, cfg, lab.timer.clone(), |id, _| probe.fetch(id)));
    assert!(lab.poll(run.as_mut()).is_pending()); lab.advance(5);
    for flag in &probe.ready { flag.store(true, Ordering::Release); }
    assert!(matches!(ready(lab.poll(run.as_mut())), Err(RemoteRecoveryError::Deadline)));
    assert_eq!(probe.active.load(Ordering::SeqCst), 0);
}

#[test]
fn duplicate_identity_or_mixed_object_plan_never_invokes_factory() {
    for mixed in [false, true] {
        let lab = Lab::new(); let mut requests = plan(2);
        if mixed { requests[1].key.object_id = ObjectId::new_for_test(2); }
        else { requests[1].replica_id = requests[0].replica_id.clone(); }
        let mut run = Box::pin(collect(&lab.cx, &requests, config(), lab.timer.clone(), |_, _| panic!("invalid plan dispatched")));
        assert!(matches!(ready(lab.poll(run.as_mut())), Err(RemoteRecoveryError::Configuration)));
    }
}

#[test]
fn redundant_symbols_are_deduplicated_but_all_received_bytes_are_charged() {
    let lab = Lab::new(); let requests = plan(2); let mut probe = Probe::new(2);
    probe.batches[1] = probe.batches[0].clone();
    let mut cfg = config(); cfg.max_received_payload_bytes = 7;
    let mut run = Box::pin(collect(&lab.cx, &requests, cfg, lab.timer.clone(), |id, _| probe.fetch(id)));
    assert!(matches!(ready(lab.poll(run.as_mut())), Err(RemoteRecoveryError::Limit("received payload bytes"))));
    cfg.max_received_payload_bytes = 8;
    let mut run = Box::pin(collect(&lab.cx, &requests, cfg, lab.timer.clone(), |id, _| probe.fetch(id)));
    let result = ready(lab.poll(run.as_mut())).unwrap();
    assert_eq!(result.symbols().len(), 1); assert_eq!(result.responding_replicas().len(), 2);
}

#[test]
fn conflicting_authenticated_symbols_cannot_be_merged() {
    let lab = Lab::new(); let requests = plan(2); let mut probe = Probe::new(2);
    probe.batches[1] = vec![SecurityContext::new(AuthKey::from_seed(42)).sign_symbol(&Symbol::new_for_test(1, 0, 0, b"different"))];
    let mut run = Box::pin(collect(&lab.cx, &requests, config(), lab.timer.clone(), |id, _| probe.fetch(id)));
    assert!(matches!(ready(lab.poll(run.as_mut())), Err(RemoteRecoveryError::Conflict)));
    assert_eq!(probe.active.load(Ordering::SeqCst), 0);
}

#[test]
fn response_order_does_not_reorder_symbols_or_replica_reports() {
    let lab = Lab::new(); let requests = plan(2); let probe = Probe::new(2);
    probe.ready[0].store(false, Ordering::Release);
    let mut run = Box::pin(collect(&lab.cx, &requests, config(), lab.timer.clone(), |id, _| probe.fetch(id)));
    assert!(lab.poll(run.as_mut()).is_pending()); probe.ready[0].store(true, Ordering::Release);
    let result = ready(lab.poll(run.as_mut())).unwrap();
    assert_eq!(result.responding_replicas(), &["r0", "r1"]);
    assert_eq!(result.symbols().iter().map(|s| s.symbol().esi()).collect::<Vec<_>>(), vec![0, 1]);
}

#[test]
fn empty_batch_never_counts_as_a_successful_replica() {
    let lab = Lab::new(); let requests = plan(2); let mut probe = Probe::new(2);
    probe.batches[1].clear();
    let mut run = Box::pin(collect(&lab.cx, &requests, config(), lab.timer.clone(), |id, _| probe.fetch(id)));
    assert!(matches!(ready(lab.poll(run.as_mut())), Err(RemoteRecoveryError::Quorum { received: 1, .. })));
}

fn decode_fixture() -> (RecoveredSymbols, EncodedState, SnapshotIdentity) {
    let region = RegionId::from_arena(ArenaIndex::new(3, 5));
    let mut snapshot = RegionSnapshot::empty(region);
    snapshot.origin_id = 77; snapshot.epoch = 4; snapshot.sequence = 9;
    snapshot.metadata = vec![73; 512]; snapshot.sign(&AuthKey::from_seed(88));
    let expected = SnapshotIdentity { region_id: region, origin_id: 77, epoch: 4, sequence: 9 };
    let mut encoder = StateEncoder::new(EncodingConfig { symbol_size: 128, max_source_blocks: 2, min_repair_symbols: 0, repair_overhead: 1.0, path_quality: None }, DetRng::new(5));
    let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
    let security = SecurityContext::new(AuthKey::from_seed(42));
    let recovered = RecoveredSymbols {
        object_id: encoded.params.object_id,
        symbols: encoded.symbols.iter().map(|s| security.sign_symbol(s)).collect(),
        responding_replicas: vec!["r0".into()], failures: Vec::new(), duration: Duration::ZERO,
    };
    (recovered, encoded, expected)
}
fn decode_limits() -> SnapshotDecodeLimits {
    SnapshotDecodeLimits { max_snapshot_bytes: 4096, max_source_symbols_per_block: 32, max_source_blocks: 4 }
}

#[test]
fn existing_raptorq_decoder_authenticates_the_reconstructed_multiblock_snapshot() {
    let (recovered, encoded, expected) = decode_fixture();
    let snapshot = recovered.decode_snapshot(encoded.params, expected, decode_limits(), &AuthKey::from_seed(42), &AuthKey::from_seed(88)).unwrap();
    assert_eq!(snapshot.metadata, vec![73; 512]); assert_eq!(snapshot.region_id, expected.region_id);
    assert_eq!(snapshot.sequence, 9);
}

#[test]
fn symbol_and_snapshot_authentication_keys_are_independent_and_rechecked() {
    let (recovered, encoded, expected) = decode_fixture();
    for (symbol, snapshot) in [(43, 88), (42, 89)] {
        assert!(matches!(recovered.decode_snapshot(encoded.params, expected, decode_limits(), &AuthKey::from_seed(symbol), &AuthKey::from_seed(snapshot)), Err(RemoteRecoveryError::Decode)));
    }
}

#[test]
fn valid_signature_cannot_bypass_exact_region_generation_epoch_or_sequence() {
    let (recovered, encoded, expected) = decode_fixture();
    for wrong in [
        SnapshotIdentity { region_id: RegionId::from_arena(ArenaIndex::new(3, 6)), ..expected },
        SnapshotIdentity { origin_id: 78, ..expected }, SnapshotIdentity { epoch: 5, ..expected },
        SnapshotIdentity { sequence: 10, ..expected },
    ] {
        assert!(matches!(recovered.decode_snapshot(encoded.params, wrong, decode_limits(), &AuthKey::from_seed(42), &AuthKey::from_seed(88)), Err(RemoteRecoveryError::SnapshotIdentity)));
    }
}

#[test]
fn decoder_limits_refuse_before_matrix_or_snapshot_allocation() {
    let (recovered, encoded, expected) = decode_fixture();
    for bounds in [
        SnapshotDecodeLimits { max_snapshot_bytes: 1, ..decode_limits() },
        SnapshotDecodeLimits { max_source_symbols_per_block: 0, ..decode_limits() },
        SnapshotDecodeLimits { max_source_blocks: 0, ..decode_limits() },
    ] {
        assert!(matches!(recovered.decode_snapshot(encoded.params, expected, bounds, &AuthKey::from_seed(42), &AuthKey::from_seed(88)), Err(RemoteRecoveryError::Limit(_))));
    }
}
