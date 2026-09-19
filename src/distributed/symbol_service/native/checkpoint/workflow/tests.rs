use super::*;
use crate::distributed::symbol_service::{SymbolBatchLimits, SymbolReplicaStore, SymbolStoreLimits, register_symbol_service};
use crate::distributed::{EncodingConfig, StateEncoder};
use crate::remote::{NodeId, RemoteComputationClient, RemoteComputationClientConfig, RemoteComputationRegistry, RemotePeerAdmissionPolicy, RemoteProtocolVersion};
use crate::tls::{Certificate, TlsConnectorBuilder};
use crate::types::RegionId;
use crate::util::DetRng;
use crate::time::{TimerDriver, VirtualClock};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::pin::Pin;
use std::task::{Context, Waker};

fn config() -> CheckpointConfig {
    CheckpointConfig {
        manifest: ManifestLimits { max_encoded_bytes: 4096, max_replicas: 8, max_decoded_bytes: 4096 },
        decode: SnapshotDecodeLimits { max_snapshot_bytes: 8192, max_source_symbols_per_block: 64, max_source_blocks: 4 },
        minimum_recovery_replicas: 1, timeout: Duration::from_secs(10),
    }
}
fn batch_limits() -> SymbolBatchLimits {
    SymbolBatchLimits { max_encoded_bytes: 32768, max_symbols: 128, max_payload_bytes: 16384, max_decoded_bytes: 65536 }
}
fn transport() -> RemoteSymbolTransport {
    let mut registry = RemoteComputationRegistry::new();
    register_symbol_service(&mut registry, Arc::new(SymbolReplicaStore::new("a", AuthKey::from_seed(42),
        batch_limits(), SymbolStoreLimits { max_batches: 4, max_bytes: 65536, max_batches_per_peer: 4, max_bytes_per_peer: 65536 }).unwrap())).unwrap();
    let policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    let cert = Certificate::from_pem(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls/server.crt"))).unwrap().remove(0);
    let connector = TlsConnectorBuilder::new().add_root_certificate(&cert).build().unwrap();
    let routes = ["a", "b", "c"].map(|id| (id.to_owned(), RemoteComputationClient::new(
        "127.0.0.1:9".parse().unwrap(), "localhost", connector.clone(), RemoteComputationClientConfig::new()).unwrap()));
    RemoteSymbolTransport::new_bounded(Cx::for_testing(), policy.hello_for(NodeId::new("origin")),
        routes, Arc::new(AuthKey::from_seed(42)), batch_limits(), 2).unwrap()
}
fn source() -> (EncodedState, SnapshotIdentity, SecurityContext, Vec<ReplicaInfo>) {
    let mut snapshot = RegionSnapshot::empty(RegionId::new_for_test(9, 3));
    snapshot.origin_id = 77; snapshot.epoch = 5; snapshot.sequence = 8;
    snapshot.metadata = vec![83; 768]; snapshot.sign(&AuthKey::from_seed(88));
    let expected = SnapshotIdentity { region_id: snapshot.region_id, origin_id: 77, epoch: 5, sequence: 8 };
    let mut encoder = StateEncoder::new(EncodingConfig { symbol_size: 128, max_source_blocks: 2,
        min_repair_symbols: 0, repair_overhead: 1.0, path_quality: None }, DetRng::new(3));
    let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
    let security = SecurityContext::new(AuthKey::from_seed(42));
    let replicas = ["a", "b", "c"].map(|id| { security.authorize_replica(id, None).unwrap(); ReplicaInfo::new(id, "never used") });
    (encoded, expected, security, replicas.into())
}
fn report(draft: &RecoveryManifest, count: u32) -> DistributionResult {
    DistributionResult {
        object_id: draft.params.object_id, symbols_distributed: count * 3,
        acks: ["b", "a"].map(|id| ReplicaAck { replica_id: id.into(), symbols_received: count, ack_time: Time::ZERO }).into(),
        failures: vec![ReplicaFailure { replica_id: "c".into(), error: "retired".into(), error_kind: ErrorKind::Cancelled }],
        quorum_achieved: true, duration: Duration::ZERO,
    }
}
fn draft() -> (RecoveryManifest, u32, usize) {
    let transport = transport(); let (encoded, expected, security, replicas) = source();
    prepare(&transport, &SymbolDistributor::new(Default::default()), &encoded, &replicas, &security,
        &CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(99) }, config()).unwrap()
}
fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn immediate<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match poll_once(future.as_mut()) { Poll::Ready(value) => value, Poll::Pending => panic!("unexpected I/O in refusal path") }
}

#[test]
fn source_authentication_and_exact_identity_are_checked_before_any_dispatch() {
    let transport = transport(); let (encoded, expected, security, replicas) = source();
    let distributor = SymbolDistributor::new(Default::default());
    let authority = CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(89), manifest_key: &AuthKey::from_seed(99) };
    assert!(matches!(prepare(&transport, &distributor, &encoded, &replicas, &security, &authority, config()), Err(CheckpointError::Decode)));
    let mut wrong = expected; wrong.region_id = RegionId::new_for_test(9, 4);
    let authority = CheckpointAuthority { expected: wrong, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(99) };
    assert!(matches!(prepare(&transport, &distributor, &encoded, &replicas, &security, &authority, config()), Err(CheckpointError::Identity)));
    assert_eq!(transport.in_flight(), 0);
}

#[test]
fn target_metadata_and_decoder_limits_refuse_before_signing_or_network() {
    let transport = transport(); let (mut encoded, expected, security, replicas) = source();
    let distributor = SymbolDistributor::new(Default::default());
    let authority = CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(99) };
    let duplicate = vec![ReplicaInfo::new("a", "unused"), ReplicaInfo::new("a", "unused")];
    assert!(matches!(prepare(&transport, &distributor, &encoded, &duplicate, &security, &authority, config()), Err(CheckpointError::Configuration)));
    let unknown = vec![ReplicaInfo::new("unknown", "127.0.0.1:9")];
    assert!(matches!(prepare(&transport, &distributor, &encoded, &unknown, &security, &authority, config()), Err(CheckpointError::Configuration)));
    let mut limited = config(); limited.decode.max_snapshot_bytes = 0;
    assert!(matches!(prepare(&transport, &distributor, &encoded, &replicas, &security, &authority, limited), Err(CheckpointError::Manifest(ManifestError::Limit(_)))));
    encoded.original_size += 1;
    assert!(matches!(prepare(&transport, &distributor, &encoded, &replicas, &security, &authority, config()), Err(CheckpointError::Configuration)));
}

#[test]
fn local_policy_and_recovery_floor_above_write_quorum_are_not_publishable() {
    let transport = transport(); let (encoded, expected, security, replicas) = source();
    let authority = CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(99) };
    let distributor = SymbolDistributor::new(crate::distributed::DistributionConfig { consistency: ConsistencyLevel::Local, ..Default::default() });
    assert!(matches!(prepare(&transport, &distributor, &encoded, &replicas, &security, &authority, config()), Err(CheckpointError::Configuration)));
    let mut strict = config(); strict.minimum_recovery_replicas = 3;
    assert!(matches!(prepare(&transport, &SymbolDistributor::new(Default::default()), &encoded, &replicas, &security, &authority, strict), Err(CheckpointError::Configuration)));
}

#[test]
fn sealing_keeps_only_confirmed_replicas_and_authenticates_the_result() {
    let (draft, count, required) = draft(); let report = report(&draft, count);
    let output = seal(draft, report, count, required, &AuthKey::from_seed(99), config().manifest).unwrap();
    assert_eq!(output.manifest().replicas().iter().map(|r| r.replica_id.as_str()).collect::<Vec<_>>(), ["a", "b"]);
    assert_eq!(output.distribution().failures.len(), 1);
    let restored = RecoveryManifest::from_canonical_bytes(output.encoded_manifest(), &AuthKey::from_seed(99),
        output.manifest().identity(), &NodeId::new("origin"), config().manifest).unwrap();
    assert_eq!(restored.replicas().len(), 2);
}

#[test]
fn quorum_receipt_drift_duplicates_and_short_counts_never_seal() {
    for case in 0..5 {
        let (draft, count, required) = draft(); let mut report = report(&draft, count);
        match case {
            0 => { report.acks.pop(); }
            1 => report.quorum_achieved = false,
            2 => report.acks[0].replica_id = "a".into(),
            3 => report.acks[0].symbols_received -= 1,
            _ => report.acks[0].replica_id = "not-planned".into(),
        }
        let result = seal(draft, report, count, required, &AuthKey::from_seed(99), config().manifest);
        if case < 2 { assert!(matches!(result, Err(CheckpointError::Quorum { .. }))); }
        else { assert!(matches!(result, Err(CheckpointError::Configuration))); }
    }
}

struct Probe { polls: Arc<AtomicUsize>, drops: Arc<AtomicUsize>, ready: bool }
impl Future for Probe {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if self.ready { Poll::Ready(()) } else { Poll::Pending }
    }
}
impl Drop for Probe { fn drop(&mut self) { self.drops.fetch_add(1, Ordering::SeqCst); } }

#[test]
fn overall_deadline_drops_pending_work_before_returning_and_zero_budget_never_polls() {
    let cx = Cx::for_testing(); let clock = Arc::new(VirtualClock::new());
    let driver = Arc::new(TimerDriver::with_clock(Arc::clone(&clock)));
    let timer = TimerDriverHandle::new(Arc::clone(&driver));
    let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
    let mut work = Box::pin(before_deadline(&cx, timer.clone(), Time::from_millis(10),
        Probe { polls: Arc::clone(&polls), drops: Arc::clone(&drops), ready: false }));
    assert!(poll_once(work.as_mut()).is_pending());
    clock.advance(10_000_000); driver.process_timers();
    assert!(matches!(poll_once(work.as_mut()), Poll::Ready(Err(CheckpointError::Deadline))));
    assert_eq!(polls.load(Ordering::SeqCst), 1); assert_eq!(drops.load(Ordering::SeqCst), 1);
    let result = immediate(before_deadline(&cx, timer, Time::ZERO,
        Probe { polls: Arc::clone(&polls), drops: Arc::clone(&drops), ready: true }));
    assert!(matches!(result, Err(CheckpointError::Deadline)));
    assert_eq!(polls.load(Ordering::SeqCst), 1); assert_eq!(drops.load(Ordering::SeqCst), 2);
}

#[test]
fn cancellation_and_external_drop_retire_pending_owners() {
    for cancel in [false, true] {
        let cx = Cx::for_testing();
        let timer = TimerDriverHandle::new(Arc::new(TimerDriver::with_clock(Arc::new(VirtualClock::new()))));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut work = Box::pin(before_deadline(&cx, timer, Time::from_secs(1),
            Probe { polls: Arc::new(AtomicUsize::new(0)), drops: Arc::clone(&drops), ready: false }));
        assert!(poll_once(work.as_mut()).is_pending());
        if cancel {
            cx.cancel_fast(crate::types::CancelKind::User);
            assert!(matches!(poll_once(work.as_mut()), Poll::Ready(Err(CheckpointError::Cancelled))));
        }
        drop(work); assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn recover_checkpoint_refuses_namespace_and_threshold_drift_without_io() {
    let transport = transport(); let (mut draft, _, _) = draft();
    let recovery = RemoteRecoveryConfig { max_replicas: 3, max_concurrent_requests: 1, required_replicas: 0,
        recovery_timeout: Duration::from_secs(1), replica_timeout: Duration::from_secs(1),
        max_received_symbols: 128, max_received_payload_bytes: 16384 };
    assert!(matches!(immediate(transport.recover_checkpoint(&draft, recovery, config().decode, &AuthKey::from_seed(88))),
        Err(CheckpointError::RecoveryThreshold)));
    draft.peer = NodeId::new("wrong-origin");
    assert!(matches!(immediate(transport.recover_checkpoint(&draft, recovery, config().decode, &AuthKey::from_seed(88))),
        Err(CheckpointError::Manifest(ManifestError::Identity))));
    assert_eq!(transport.in_flight(), 0);
}

#[test]
fn signing_context_must_match_the_transports_verification_key_before_dispatch() {
    let transport = transport(); let (encoded, expected, _, replicas) = source();
    let wrong = SecurityContext::new(AuthKey::from_seed(43));
    for replica in &replicas { wrong.authorize_replica(&replica.id, None).unwrap(); }
    let authority = CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(99) };
    assert!(matches!(prepare(&transport, &SymbolDistributor::new(Default::default()), &encoded, &replicas,
        &wrong, &authority, config()), Err(CheckpointError::Batch(SymbolStoreError::Authentication))));
    assert_eq!(transport.in_flight(), 0);
}
