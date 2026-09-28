//! Public striped checkpoints across independent native TCP+mTLS replica services.
//! These are real sockets on separate runtime threads, not process-crash/disk proof.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]
#![recursion_limit = "256"]

use asupersync::distributed::distribution::{DistributionConfig, DistributorTransport, SymbolDistributor};
use asupersync::codec::{Framed, LengthDelimitedCodec};
use asupersync::distributed::symbol_service::checkpoint::{
    CheckpointAuthority, CheckpointConfig, CheckpointError, ManifestLimits, RecoveryManifest,
};
use asupersync::distributed::symbol_service::recovery::{
    RemoteRecoveryConfig, RemoteRecoveryError, SnapshotDecodeLimits, SnapshotIdentity,
};
use asupersync::distributed::symbol_service::{
    RemoteSymbolTransport, SYMBOL_SERVICE_COMPUTATION, SymbolBatchLimits, SymbolReplicaStore,
    SymbolStoreLimits, encode_symbol_batch, register_symbol_service,
};
use asupersync::distributed::{AssignmentStrategy, EncodedState, EncodingConfig, RegionSnapshot, StateEncoder};
use asupersync::net::TcpListener;
use asupersync::record::distributed_region::{ConsistencyLevel, ReplicaInfo};
use asupersync::remote::{
    ComputationName, NodeId, RemoteComputationClient, RemoteComputationClientConfig, RemoteComputationRegistry,
    RemoteComputationService, RemoteComputationServiceConfig, RemoteComputationServiceHandle,
    RemotePeerAdmissionPolicy, RemoteProtocolVersion, RemoteServiceWireLimits, RemoteServiceWireRequest,
    RemoteServiceWireResponse, serve_tls_computation_once,
};
use asupersync::runtime::{Runtime, RuntimeBuilder, TaskHandle};
use asupersync::security::{AuthKey, AuthenticatedSymbol, SecurityContext};
use asupersync::stream::StreamExt;
use asupersync::sync::Notify;
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth, PrivateKey,
    RootCertStore, TlsAcceptor, TlsAcceptorBuilder, TlsConnector, TlsConnectorBuilder,
};
use asupersync::util::{ArenaIndex, DetRng};
use asupersync::{Cx, types::{RegionId, Time}};
use std::net::SocketAddr;
use std::future::{Future, poll_fn};
use std::sync::{Arc, mpsc};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MIB: usize = 1024 * 1024;
const IDS: [&str; 3] = ["stripe-a", "stripe-b", "stripe-c"];

fn batch_limits() -> SymbolBatchLimits {
    SymbolBatchLimits { max_encoded_bytes: 16 * MIB, max_symbols: 8192,
        max_payload_bytes: 12 * MIB, max_decoded_bytes: 24 * MIB }
}
fn store_limits() -> SymbolStoreLimits {
    SymbolStoreLimits { max_batches: 4, max_bytes: 48 * MIB,
        max_batches_per_peer: 4, max_bytes_per_peer: 48 * MIB }
}
fn manifest_limits() -> ManifestLimits {
    ManifestLimits { max_encoded_bytes: 4096, max_replicas: 3, max_decoded_bytes: 4096 }
}
fn decode_limits() -> SnapshotDecodeLimits {
    SnapshotDecodeLimits { max_snapshot_bytes: 5 * MIB, max_source_symbols_per_block: 1024, max_source_blocks: 4 }
}
fn checkpoint_config() -> CheckpointConfig {
    CheckpointConfig { manifest: manifest_limits(), decode: decode_limits(),
        minimum_recovery_replicas: 1, timeout: Duration::from_secs(45) }
}
fn recovery_config(required: usize) -> RemoteRecoveryConfig {
    RemoteRecoveryConfig { max_replicas: 3, max_concurrent_requests: 2, required_replicas: required,
        recovery_timeout: Duration::from_secs(30), replica_timeout: Duration::from_secs(15),
        max_received_symbols: 24576, max_received_payload_bytes: 36 * MIB }
}
fn tls() -> (TlsAcceptor, TlsConnector, CertificatePinSet) {
    let cert = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap().remove(0);
    let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
    let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
    let mut roots = RootCertStore::empty(); roots.add(&cert).unwrap();
    let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
        .client_auth(ClientAuth::Required(roots)).build().unwrap();
    let mut pins = CertificatePinSet::new(); pins.add(CertificatePin::compute_spki_sha256(&cert).unwrap());
    let connector = TlsConnectorBuilder::new().add_root_certificate(&cert).identity(chain, key)
        .with_certificate_pins(pins.clone()).build().unwrap();
    (acceptor, connector, pins)
}

struct Replica {
    address: SocketAddr,
    operator: RemoteComputationServiceHandle,
    thread: Option<JoinHandle<()>>,
    store: Arc<SymbolReplicaStore>,
}
impl Replica {
    fn start(id: &'static str) -> Self {
        let store = Arc::new(SymbolReplicaStore::new(id, AuthKey::from_seed(42), batch_limits(), store_limits()).unwrap());
        let retained = Arc::clone(&store);
        let (ready, receive) = mpsc::sync_channel(1);
        let thread = thread::spawn(move || {
            let runtime = RuntimeBuilder::current_thread().build().unwrap();
            let mut registry = RemoteComputationRegistry::new();
            register_symbol_service(&mut registry, retained).unwrap();
            let (acceptor, _, pins) = tls();
            let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
            policy.grant_tls_peer(NodeId::new("stripe-origin"), pins, [SYMBOL_SERVICE_COMPUTATION]).unwrap();
            let service = runtime.block_on(RemoteComputationService::bind("127.0.0.1:0", acceptor, policy, registry,
                RemoteComputationServiceConfig::new().with_max_connections(Some(4))
                    .with_wire_limits(RemoteServiceWireLimits::new(64 * MIB))
                    .with_drain_timeout(Duration::from_secs(5)))).unwrap();
            let operator = service.handle();
            ready.send((service.local_addr().unwrap(), operator.clone())).unwrap();
            let result = runtime.block_on(async {
                let cx = Cx::current().unwrap();
                asupersync::time::timeout(cx.now(), Duration::from_secs(180), service.run(&cx)).await
            });
            result.expect("native replica watchdog").expect("native replica drain");
            assert_eq!(operator.active_connections(), 0);
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
        });
        let (address, operator) = receive.recv_timeout(Duration::from_secs(10)).expect("native replica readiness");
        Self { address, operator, thread: Some(thread), store }
    }
    fn stop(&mut self) {
        let _ = self.operator.begin_drain();
        if let Some(thread) = self.thread.take() { thread.join().expect("native replica thread"); }
    }
}
impl Drop for Replica {
    fn drop(&mut self) {
        let _ = self.operator.begin_drain();
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

fn runtime(workers: usize) -> Runtime {
    if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
    else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() }
}
fn transport(cx: &Cx, peers: &[Replica; 3]) -> RemoteSymbolTransport {
    let mut registry = RemoteComputationRegistry::new();
    register_symbol_service(&mut registry, Arc::clone(&peers[0].store)).unwrap();
    let policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    let (_, connector, _) = tls();
    let routes = IDS.into_iter().zip(peers).map(|(id, peer)| {
        let client = RemoteComputationClient::new(peer.address, "localhost", connector.clone(),
            RemoteComputationClientConfig::new().with_max_attempts(1)
                .with_connect_timeout(Duration::from_secs(2)).with_attempt_timeout(Duration::from_secs(20))
                .with_wire_limits(RemoteServiceWireLimits::new(64 * MIB))).unwrap();
        (id.to_owned(), client)
    });
    RemoteSymbolTransport::new_bounded(cx.clone(), policy.hello_for(NodeId::new("stripe-origin")),
        routes, Arc::new(AuthKey::from_seed(42)), batch_limits(), 2).unwrap()
}
fn source(size: usize, repair_percent: usize) -> (RegionSnapshot, EncodedState, SnapshotIdentity, SecurityContext, Vec<ReplicaInfo>) {
    let mut snapshot = RegionSnapshot::empty(RegionId::from_arena(ArenaIndex::new(9, 3)));
    snapshot.origin_id = 77; snapshot.epoch = 5; snapshot.sequence = 8;
    snapshot.metadata = (0..size).map(|i| ((i.wrapping_mul(37) ^ (i >> 9)) & 255) as u8).collect();
    snapshot.sign(&AuthKey::from_seed(88));
    let expected = SnapshotIdentity { region_id: snapshot.region_id, origin_id: 77, epoch: 5, sequence: 8 };
    let source_symbols = snapshot.to_bytes().len().div_ceil(4096);
    let repair_symbols = u16::try_from(source_symbols.checked_mul(repair_percent).unwrap().div_ceil(100)).unwrap();
    // StateEncoder's explicit per-block repair count takes precedence over the
    // pipeline's overhead option. Derive actual emitted redundancy from K.
    let mut encoder = StateEncoder::new(EncodingConfig { symbol_size: 4096, max_source_blocks: 4,
        min_repair_symbols: repair_symbols, repair_overhead: 1.0, path_quality: None }, DetRng::new(31 + u64::try_from(size).unwrap()));
    let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
    assert_eq!(usize::from(encoded.source_count), source_symbols);
    assert_eq!(encoded.repair_count, repair_symbols);
    let security = SecurityContext::new(AuthKey::from_seed(42));
    let replicas = IDS.map(|id| { security.authorize_replica(id, None).unwrap(); ReplicaInfo::new(id, "not a route") }).into();
    (snapshot, encoded, expected, security, replicas)
}
fn distributor() -> SymbolDistributor {
    SymbolDistributor::new(DistributionConfig { consistency: ConsistencyLevel::Quorum, max_concurrent: 2,
        ack_timeout: Duration::from_secs(25), ..Default::default() })
}
fn assert_runtime_drained(runtime: Runtime) {
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
}

#[test]
fn striped_checkpoint_native_recovers_four_mib_from_two_partial_peers_after_one_peer_stops() {
    for workers in [1, 2] {
        let mut peers = IDS.map(Replica::start);
        let publisher = runtime(workers);
        let (bytes, expected, original, source_count) = publisher.block_on(async {
            let cx = Cx::current().unwrap(); let transport = transport(&cx, &peers);
            let (snapshot, encoded, expected, security, replicas) = source(4 * MIB, 80);
            assert_eq!(encoded.params.source_blocks, 4);
            let result = transport.replicate_striped_checkpoint(&mut distributor(), &encoded, &replicas, &security,
                CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(99) },
                checkpoint_config()).await.unwrap();
            assert_eq!(result.distribution().acks.len(), 3);
            assert_eq!(result.distribution().symbols_distributed as usize, encoded.symbols.len());
            for ack in &result.distribution().acks {
                assert!(ack.symbols_received < u32::from(encoded.source_count), "no replica contains enough symbols alone");
            }
            assert_ne!(result.manifest().replicas()[0].key, result.manifest().replicas()[1].key);
            assert!(peers.iter().all(|peer| peer.store.stats().batches == 1));
            assert_eq!(transport.in_flight(), 0);
            (result.encoded_manifest().to_vec(), expected, snapshot.to_bytes(), encoded.source_count)
        });
        assert_runtime_drained(publisher); // No publisher encoding/client survives recovery.
        peers[2].stop();
        let recovery = runtime(workers);
        recovery.block_on(async {
            let cx = Cx::current().unwrap(); let transport = transport(&cx, &peers);
            let manifest = RecoveryManifest::from_canonical_bytes(&bytes, &AuthKey::from_seed(99), expected,
                &NodeId::new("stripe-origin"), manifest_limits()).unwrap();
            let recovered = transport.recover_checkpoint(&manifest, recovery_config(2), decode_limits(), &AuthKey::from_seed(88)).await.unwrap();
            assert_eq!(recovered.to_bytes(), original, "all four MiB and every snapshot field survive erasure loss");
            // A successful storage response alone is insufficient. Re-request
            // either survivor on its own and prove authenticated decoding fails.
            for donor in &manifest.replicas()[..2] {
                let one = transport.collect_symbols(std::slice::from_ref(donor), recovery_config(1)).await.unwrap();
                assert!(one.symbols().len() < usize::from(source_count));
                assert!(matches!(one.decode_snapshot(manifest.params(), expected, decode_limits(),
                    &AuthKey::from_seed(42), &AuthKey::from_seed(88)), Err(RemoteRecoveryError::Decode)));
            }
            assert_eq!(transport.in_flight(), 0);
        });
        assert_runtime_drained(recovery);
        for peer in &mut peers { peer.stop(); }
    }
}

#[test]
fn striped_checkpoint_native_insufficient_surviving_union_refuses_publication_and_recovery() {
    for workers in [1, 2] {
        let mut peers = IDS.map(Replica::start);
        let client = runtime(workers);
        let (bytes, expected) = client.block_on(async {
            let cx = Cx::current().unwrap(); let transport = transport(&cx, &peers);
            let (_, encoded, expected, security, replicas) = source(64 * 1024, 0);
            assert_eq!(encoded.repair_count, 0);
            let result = transport.replicate_striped_checkpoint(&mut distributor(), &encoded, &replicas, &security,
                CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(99) },
                checkpoint_config()).await.unwrap();
            (result.encoded_manifest().to_vec(), expected)
        });
        peers[2].stop();
        client.block_on(async {
            let cx = Cx::current().unwrap(); let transport = transport(&cx, &peers);
            let manifest = RecoveryManifest::from_canonical_bytes(&bytes, &AuthKey::from_seed(99), expected,
                &NodeId::new("stripe-origin"), manifest_limits()).unwrap();
            assert!(matches!(transport.recover_checkpoint(&manifest, recovery_config(2), decode_limits(),
                &AuthKey::from_seed(88)).await, Err(CheckpointError::Recovery(RemoteRecoveryError::Decode))));
            // A fresh object avoids conflating insufficient coverage with the
            // immutable store's same-object write conflict.
            let (_, encoded, expected, security, replicas) = source(65 * 1024, 0);
            assert_ne!(encoded.params.object_id, manifest.params().object_id);
            let result = transport.replicate_striped_checkpoint(&mut distributor(), &encoded, &replicas, &security,
                CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(99) },
                checkpoint_config()).await;
            let Err(CheckpointError::InsufficientCoverage { distribution }) = result else { panic!("undecodable publication escaped"); };
            assert!(distribution.quorum_achieved);
            assert_eq!(distribution.acks.len(), 2);
            assert_eq!(distribution.failures.len(), 1);
            assert_eq!(transport.in_flight(), 0);
            let result = transport.replicate_striped_checkpoint_on_quorum(&mut distributor(), &encoded, &replicas, &security,
                CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(99) },
                checkpoint_config()).await;
            let Err(CheckpointError::InsufficientCoverage { distribution }) = result else { panic!("exhausted quorum coverage escaped"); };
            assert!(distribution.quorum_achieved); assert_eq!(distribution.acks.len(), 2);
            assert_eq!(distribution.failures.len(), 1); assert_eq!(transport.in_flight(), 0);
        });
        assert_runtime_drained(client);
        for peer in &mut peers { peer.stop(); }
    }
}

#[test]
fn striped_checkpoint_native_corrupt_and_stale_batches_cannot_supply_publication_receipts() {
    let mut peers = IDS.map(Replica::start);
    let client = runtime(2);
    client.block_on(async {
        let cx = Cx::current().unwrap(); let transport = transport(&cx, &peers);
        let (snapshot, encoded, expected, security, replicas) = source(128 * 1024, 80);
        let signed = security.sign_symbol(&encoded.symbols[0]);
        let mut altered = signed.symbol().clone(); altered.data_mut()[0] ^= 1;
        let corrupt = AuthenticatedSymbol::from_parts(altered, *signed.tag());
        assert!(transport.send_symbols(IDS[0], vec![corrupt]).await.is_err());
        assert_eq!(peers[0].store.stats().batches, 0, "corrupt symbol never retained");
        // An authentic but incomplete earlier batch has the same object ID.
        // The receiver must refuse replacing it with the requested stripe.
        transport.send_symbols(IDS[0], vec![signed]).await.unwrap();
        let result = transport.replicate_striped_checkpoint(&mut distributor(), &encoded, &replicas, &security,
            CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(99) },
            checkpoint_config()).await.unwrap();
        assert_eq!(result.distribution().acks.len(), 2);
        assert_eq!(result.distribution().failures.len(), 1);
        assert_eq!(result.distribution().failures[0].replica_id, IDS[0]);
        assert_eq!(result.manifest().replicas().iter().map(|replica| replica.replica_id.as_str()).collect::<Vec<_>>(), &IDS[1..]);
        let recovered = transport.recover_checkpoint(result.manifest(), recovery_config(2), decode_limits(), &AuthKey::from_seed(88)).await.unwrap();
        assert_eq!(recovered.to_bytes(), snapshot.to_bytes());
        let mut wrong = result.manifest().replicas()[0].key; wrong.digest[0] ^= 1;
        assert!(transport.fetch_symbols(IDS[1], wrong).await.is_err(), "no stale-key fallback");
        assert_eq!(transport.in_flight(), 0);
    });
    assert_runtime_drained(client);
    for peer in &mut peers { peer.stop(); }
}

#[test]
fn full_checkpoint_native_keeps_full_copy_keys_and_single_donor_recovery() {
    let mut peers = IDS.map(Replica::start);
    let client = runtime(1);
    let (bytes, expected, original) = client.block_on(async {
        let cx = Cx::current().unwrap(); let transport = transport(&cx, &peers);
        let (snapshot, encoded, expected, security, replicas) = source(64 * 1024, 0);
        let result = transport.replicate_checkpoint(&mut distributor(), &encoded, &replicas, &security,
            CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(99) },
            checkpoint_config()).await.unwrap();
        assert_eq!(result.distribution().symbols_distributed as usize, encoded.symbols.len() * 3);
        assert!(result.distribution().acks.iter().all(|ack| ack.symbols_received as usize == encoded.symbols.len()));
        assert!(result.manifest().replicas().windows(2).all(|pair| pair[0].key == pair[1].key));
        (result.encoded_manifest().to_vec(), expected, snapshot.to_bytes())
    });
    peers[1].stop(); peers[2].stop();
    client.block_on(async {
        let cx = Cx::current().unwrap(); let transport = transport(&cx, &peers);
        let manifest = RecoveryManifest::from_canonical_bytes(&bytes, &AuthKey::from_seed(99), expected,
            &NodeId::new("stripe-origin"), manifest_limits()).unwrap();
        let recovered = transport.recover_checkpoint(&manifest, recovery_config(1), decode_limits(), &AuthKey::from_seed(88)).await.unwrap();
        assert_eq!(recovered.to_bytes(), original);
        assert_eq!(transport.in_flight(), 0);
    });
    assert_runtime_drained(client);
    for peer in &mut peers { peer.stop(); }
}

// The transport refuses a send beyond its in-flight limit rather than queueing
// it. A distributor wider than that limit must wait for a slot, not count a
// healthy replica as failed: All needs all three, and the transport admits two.
#[test]
fn checkpoint_fanout_wider_than_transport_admission_still_reaches_every_healthy_replica() {
    for mode in ["full", "striped", "striped-on-quorum"] {
        let mut peers = IDS.map(Replica::start);
        let client = runtime(1);
        client.block_on(async {
            let cx = Cx::current().unwrap(); let transport = transport(&cx, &peers);
            assert_eq!(transport.max_in_flight(), 2);
            let (_, encoded, expected, security, replicas) = source(64 * 1024, 0);
            let mut wide = SymbolDistributor::new(DistributionConfig { consistency: ConsistencyLevel::All,
                max_concurrent: 3, ack_timeout: Duration::from_secs(25), ..Default::default() });
            let authority = CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(99) };
            let published = match mode {
                "full" => transport.replicate_checkpoint(&mut wide, &encoded, &replicas, &security,
                    authority, checkpoint_config()).await,
                "striped" => transport.replicate_striped_checkpoint(&mut wide, &encoded, &replicas, &security,
                    authority, checkpoint_config()).await,
                _ => transport.replicate_striped_checkpoint_on_quorum(&mut wide, &encoded, &replicas, &security,
                    authority, checkpoint_config()).await,
            };
            let result = published.unwrap_or_else(|error| panic!("{mode}: a replica beyond the admission limit must wait for a slot: {error}"));
            assert_eq!(result.distribution().acks.len(), 3, "{mode}");
            assert!(result.distribution().failures.is_empty(), "{mode}");
            assert!(peers.iter().all(|peer| peer.store.stats().batches == 1), "{mode}");
            assert_eq!(transport.in_flight(), 0);
        });
        assert_runtime_drained(client);
        for peer in &mut peers { peer.stop(); }
    }
}

#[derive(Default)]
struct PublicationGate { open: AtomicBool, changed: Notify }
impl PublicationGate {
    fn release(&self) { self.open.store(true, Ordering::Release); self.changed.notify_waiters(); }
    async fn wait(&self) { self.changed.wait_until(|| self.open.load(Ordering::Acquire)).await; }
}
#[derive(Default)]
struct PublicationWitness {
    requested: AtomicBool, closed: AtomicBool, replied: AtomicUsize, changed: Notify,
}
struct PublicationPeer {
    id: &'static str, address: SocketAddr, task: TaskHandle<()>,
    store: Arc<SymbolReplicaStore>, witness: Arc<PublicationWitness>,
}
fn publication_policy(store: Arc<SymbolReplicaStore>) -> (RemoteComputationRegistry, RemotePeerAdmissionPolicy) {
    let mut registry = RemoteComputationRegistry::new(); register_symbol_service(&mut registry, store).unwrap();
    let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    policy.grant_tls_peer(NodeId::new("stripe-origin"), tls().2, [SYMBOL_SERVICE_COMPUTATION]).unwrap();
    (registry, policy)
}
async fn publication_peer(
    cx: &Cx, id: &'static str, gate: Arc<PublicationGate>, requests: usize,
    held_put: Option<Vec<u8>>,
) -> PublicationPeer {
    let store = Arc::new(SymbolReplicaStore::new(id, AuthKey::from_seed(42), batch_limits(), store_limits()).unwrap());
    let (registry, policy) = publication_policy(Arc::clone(&store));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap(); let address = listener.local_addr().unwrap();
    let witness = Arc::new(PublicationWitness::default()); let observed = Arc::clone(&witness);
    let acceptor = tls().0;
    let task = cx.spawn(move |cx| async move {
        asupersync::time::timeout(cx.now(), Duration::from_secs(20), async {
            if let Some(expected) = held_put {
                let (stream, _) = listener.accept().await.unwrap(); let stream = acceptor.accept(stream).await.unwrap();
                let codec = LengthDelimitedCodec::builder().max_frame_length(4 * MIB).big_endian().new_codec();
                let mut framed = Framed::new(stream, codec).with_max_buffer_len(4 * MIB + 4);
                let bytes = framed.next().await.expect("actual striped PUT frame").unwrap();
                let request: RemoteServiceWireRequest = serde_json::from_slice(&bytes).unwrap();
                let admitted = policy.admit_tls_peer(request.hello(), framed.get_ref()).unwrap();
                admitted.authorize_computation(&ComputationName::new(SYMBOL_SERVICE_COMPUTATION)).unwrap();
                let fields: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(fields["computation"], SYMBOL_SERVICE_COMPUTATION);
                let input: Vec<u8> = serde_json::from_value(fields["input"].clone()).unwrap();
                assert_eq!(input, expected, "silent peer reached the exact authenticated stripe");
                observed.requested.store(true, Ordering::Release); observed.changed.notify_waiters();
                match framed.next().await {
                    None => {}
                    Some(Err(error)) => assert!(matches!(error.kind(), std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe)),
                    Some(Ok(_)) => panic!("unexpected second request on the held V1 connection"),
                }
                observed.closed.store(true, Ordering::Release); observed.changed.notify_waiters();
            } else {
                for _ in 0..requests {
                    let (stream, _) = listener.accept().await.unwrap(); let mut stream = acceptor.accept(stream).await.unwrap();
                    gate.wait().await;
                    let response = serve_tls_computation_once(&cx, &mut stream, &policy, &registry,
                        RemoteServiceWireLimits::new(4 * MIB)).await.unwrap();
                    assert!(matches!(response, RemoteServiceWireResponse::Outcome { .. }));
                    observed.replied.fetch_add(1, Ordering::AcqRel); observed.changed.notify_waiters();
                }
            }
        }).await.expect("bounded native checkpoint peer lifetime");
    }).unwrap();
    PublicationPeer { id, address, task, store, witness }
}
fn publication_transport(cx: &Cx, peers: &[PublicationPeer]) -> RemoteSymbolTransport {
    let (_, policy) = publication_policy(Arc::clone(&peers[0].store)); let connector = tls().1;
    let routes = peers.iter().map(|peer| {
        let client = RemoteComputationClient::new(peer.address, "localhost", connector.clone(),
            RemoteComputationClientConfig::new().with_max_attempts(1)
                .with_connect_timeout(Duration::from_secs(30)).with_attempt_timeout(Duration::from_secs(30))
                .with_wire_limits(RemoteServiceWireLimits::new(4 * MIB))).unwrap();
        (peer.id.to_owned(), client)
    });
    RemoteSymbolTransport::new_bounded(cx.clone(), policy.hello_for(NodeId::new("stripe-origin")), routes,
        Arc::new(AuthKey::from_seed(42)), batch_limits(), 4).unwrap()
}
fn held_stripe(encoded: &EncodedState, replicas: &[ReplicaInfo], security: &SecurityContext) -> Vec<u8> {
    let assignments = SymbolDistributor::compute_assignments_with_strategy(encoded, replicas, security, None, AssignmentStrategy::Striped);
    let held = &assignments[0];
    let signed: Vec<_> = held.symbol_indices.iter().map(|&index| security.sign_symbol(&encoded.symbols[index])).collect();
    let batch = encode_symbol_batch(&signed, batch_limits()).unwrap();
    let mut request = b"ASUPPUT\0".to_vec(); request.extend_from_slice(&1_u32.to_le_bytes());
    request.push(u8::try_from(held.replica_id.len()).unwrap()); request.extend_from_slice(held.replica_id.as_bytes());
    request.extend_from_slice(batch.as_ref()); request
}

#[test]
fn recoverable_striped_publication_waits_for_equations_and_retires_a_native_silent_put() {
    for (workers, hedged) in [(1, false), (2, true)] {
        let runtime = runtime(workers);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (snapshot, encoded, expected, security, mut replicas) = source(128 * 1024, 80);
            security.authorize_replica("stripe-held", None).unwrap();
            replicas.insert(0, ReplicaInfo::new("stripe-held", "not a route"));
            let assignments = SymbolDistributor::compute_assignments_with_strategy(
                &encoded, &replicas, &security, None, AssignmentStrategy::Striped);
            assert!(assignments[1..3].iter().map(|a| a.symbol_indices.len()).sum::<usize>() < usize::from(encoded.source_count),
                "first two successful stripes have fewer equations than source symbols");
            let fast = Arc::new(PublicationGate::default()); let last = Arc::new(PublicationGate::default());
            let mut peers = vec![
                publication_peer(&cx, "stripe-held", Arc::clone(&fast), 1, Some(held_stripe(&encoded, &replicas, &security))).await,
                publication_peer(&cx, IDS[0], Arc::clone(&fast), 2, None).await,
                publication_peer(&cx, IDS[1], Arc::clone(&fast), 2, None).await,
                publication_peer(&cx, IDS[2], Arc::clone(&last), 2, None).await,
            ];
            let transport = publication_transport(&cx, &peers);
            let mut distributor = SymbolDistributor::new(DistributionConfig {
                consistency: ConsistencyLevel::One, max_concurrent: 4, hedge_enabled: hedged,
                hedge_delay: Duration::ZERO, ack_timeout: Duration::from_secs(30), ..Default::default()
            });
            let mut config = checkpoint_config(); config.manifest.max_replicas = 4; config.timeout = Duration::from_secs(30);
            let snapshot_key = AuthKey::from_seed(88); let manifest_key = AuthKey::from_seed(99);
            let result = {
                let mut publication = std::pin::pin!(transport.replicate_striped_checkpoint_on_quorum(
                    &mut distributor, &encoded, &replicas, &security,
                    CheckpointAuthority { expected, snapshot_key: &snapshot_key, manifest_key: &manifest_key }, config));
                let mut observed = std::pin::pin!(peers[0].witness.changed.wait_until(|| peers[0].witness.requested.load(Ordering::Acquire)));
                asupersync::time::timeout(cx.now(), Duration::from_secs(5), poll_fn(|task| {
                    assert!(publication.as_mut().poll(task).is_pending()); observed.as_mut().poll(task)
                })).await.expect("exact authenticated silent PUT witness");
                assert!(transport.in_flight() > 0 && transport.in_flight() <= 4);
                fast.release();
                let mut first = std::pin::pin!(peers[1].witness.changed.wait_until(|| peers[1].witness.replied.load(Ordering::Acquire) == 1));
                let mut second = std::pin::pin!(peers[2].witness.changed.wait_until(|| peers[2].witness.replied.load(Ordering::Acquire) == 1));
                let (mut first_done, mut second_done) = (false, false);
                asupersync::time::timeout(cx.now(), Duration::from_secs(5), poll_fn(|task| {
                    assert!(publication.as_mut().poll(task).is_pending(), "count quorum cannot publish an undecodable checkpoint");
                    if !first_done { first_done = first.as_mut().poll(task).is_ready(); }
                    if !second_done { second_done = second.as_mut().poll(task).is_ready(); }
                    if first_done && second_done { std::task::Poll::Ready(()) } else { std::task::Poll::Pending }
                })).await.expect("two real successful stripe writes before coverage");
                assert_eq!(peers[1].store.stats().batches, 1); assert_eq!(peers[2].store.stats().batches, 1);
                assert_eq!(peers[3].store.stats().batches, 0); assert!(!peers[0].witness.closed.load(Ordering::Acquire));
                last.release();
                asupersync::time::timeout(cx.now(), Duration::from_secs(5), publication.as_mut()).await
                    .expect("decodable quorum finishes before thirty-second held acknowledgement").unwrap()
            };
            assert_eq!(result.distribution().acks.len(), 3); assert_eq!(transport.in_flight(), 0);
            assert_eq!(result.manifest().replicas().iter().map(|r| r.replica_id.as_str()).collect::<Vec<_>>(), IDS);
            for replica in result.manifest().replicas() {
                let peer = peers.iter().find(|peer| peer.id == replica.replica_id).unwrap();
                assert_eq!(peer.store.get(&NodeId::new("stripe-origin"), replica.key).unwrap().key(), replica.key);
            }
            asupersync::time::timeout(cx.now(), Duration::from_secs(3), peers[0].witness.changed
                .wait_until(|| peers[0].witness.closed.load(Ordering::Acquire))).await.expect("losing local PUT socket retired");
            let mut recovery = recovery_config(3); recovery.max_concurrent_requests = 3;
            let recovered = transport.recover_checkpoint_on_quorum(result.manifest(), recovery, decode_limits(), &snapshot_key).await.unwrap();
            assert_eq!(recovered.to_bytes(), snapshot.to_bytes()); assert_eq!(transport.in_flight(), 0);
            for peer in &mut peers {
                asupersync::time::timeout(cx.now(), Duration::from_secs(3), peer.task.join(&cx)).await
                    .expect("peer join bound").expect("peer finishes without panic");
            }
        });
        assert_runtime_drained(runtime);
    }
}

#[test]
fn recoverable_striped_publication_cancels_or_expires_after_authenticated_put_and_all_quorum_stays_fixed() {
    for cancel in [true, false] {
        let runtime = runtime(2);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let owner = cx.open_child_region(asupersync::cx::ChildRegionSpec::inherit()).await.unwrap();
            let operation_cx = owner.cx().clone();
            let (_, encoded, expected, security, mut replicas) = source(128 * 1024, 80);
            security.authorize_replica("stripe-held", None).unwrap();
            replicas.insert(0, ReplicaInfo::new("stripe-held", "not a route"));
            let open = Arc::new(PublicationGate::default()); open.release();
            let mut peers = vec![
                publication_peer(&cx, "stripe-held", Arc::clone(&open), 1, Some(held_stripe(&encoded, &replicas, &security))).await,
                publication_peer(&cx, IDS[0], Arc::clone(&open), 2, None).await,
                publication_peer(&cx, IDS[1], Arc::clone(&open), 2, None).await,
                publication_peer(&cx, IDS[2], Arc::clone(&open), 2, None).await,
            ];
            let transport = publication_transport(&operation_cx, &peers);
            let mut distributor = SymbolDistributor::new(DistributionConfig {
                consistency: ConsistencyLevel::All, max_concurrent: 4, hedge_enabled: true,
                ack_timeout: Duration::from_secs(30), ..Default::default()
            });
            let mut config = checkpoint_config(); config.manifest.max_replicas = 4;
            config.timeout = Duration::from_secs(if cancel { 30 } else { 8 });
            let snapshot_key = AuthKey::from_seed(88); let manifest_key = AuthKey::from_seed(99);
            {
                let mut publication = std::pin::pin!(transport.replicate_striped_checkpoint_on_quorum(
                    &mut distributor, &encoded, &replicas, &security,
                    CheckpointAuthority { expected, snapshot_key: &snapshot_key, manifest_key: &manifest_key }, config));
                let mut witnesses: Vec<_> = peers.iter().map(|peer| Box::pin(peer.witness.changed.wait_until(move || {
                    peer.witness.requested.load(Ordering::Acquire) || peer.witness.replied.load(Ordering::Acquire) == 1
                }))).collect();
                let mut observed = [false; 4];
                asupersync::time::timeout(cx.now(), Duration::from_secs(5), poll_fn(|task| {
                    assert!(publication.as_mut().poll(task).is_pending(), "three useful replicas cannot lower All's four-replica floor");
                    for (index, witness) in witnesses.iter_mut().enumerate() {
                        if !observed[index] { observed[index] = witness.as_mut().poll(task).is_ready(); }
                    }
                    if observed.iter().all(|ready| *ready) { std::task::Poll::Ready(()) } else { std::task::Poll::Pending }
                })).await.expect("all successful stores and exact parked authenticated PUT observed");
                assert!(transport.in_flight() > 0 && transport.in_flight() <= 4);
                if cancel { operation_cx.cancel_fast(asupersync::types::CancelKind::User); }
                let result = asupersync::time::timeout(cx.now(), Duration::from_secs(10), publication.as_mut()).await
                    .expect("publication observes cancellation or its original deadline");
                if cancel { assert!(matches!(result, Err(CheckpointError::Cancelled))); }
                else { assert!(matches!(result, Err(CheckpointError::Deadline))); }
            }
            assert_eq!(transport.in_flight(), 0);
            asupersync::time::timeout(cx.now(), Duration::from_secs(3), peers[0].witness.changed
                .wait_until(|| peers[0].witness.closed.load(Ordering::Acquire))).await.expect("cancelled local PUT socket closes");
            owner.close().await.unwrap();
            // Partial remote stores remain valid, immutable batches. New owner
            // admission can fetch them; failure never implies remote rollback.
            let fresh = publication_transport(&cx, &peers);
            let assignments = SymbolDistributor::compute_assignments_with_strategy(
                &encoded, &replicas, &security, None, AssignmentStrategy::Striped);
            for assignment in &assignments[1..] {
                let symbols: Vec<_> = assignment.symbol_indices.iter().map(|&index| security.sign_symbol(&encoded.symbols[index])).collect();
                let batch = encode_symbol_batch(&symbols, batch_limits()).unwrap();
                let fetched = fresh.fetch_symbols(&assignment.replica_id, batch.key()).await.unwrap();
                assert_eq!(encode_symbol_batch(&fetched, batch_limits()).unwrap().key(), batch.key());
            }
            assert_eq!(fresh.in_flight(), 0);
            for peer in &mut peers {
                asupersync::time::timeout(cx.now(), Duration::from_secs(3), peer.task.join(&cx)).await
                    .expect("peer join bound").expect("peer finishes without panic");
            }
        });
        assert_runtime_drained(runtime);
    }
}

#[test]
fn recoverable_striped_publication_rejects_wrong_snapshot_authority_before_native_dispatch() {
    let mut peers = IDS.map(Replica::start); let runtime = runtime(1);
    runtime.block_on(async {
        let cx = Cx::current().unwrap(); let transport = transport(&cx, &peers);
        let (_, encoded, expected, security, replicas) = source(64 * 1024, 80);
        let result = transport.replicate_striped_checkpoint_on_quorum(&mut distributor(), &encoded, &replicas, &security,
            CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(89), manifest_key: &AuthKey::from_seed(99) },
            checkpoint_config()).await;
        assert!(matches!(result, Err(CheckpointError::Decode)));
        let mut wrong = expected; wrong.sequence += 1;
        let result = transport.replicate_striped_checkpoint_on_quorum(&mut distributor(), &encoded, &replicas, &security,
            CheckpointAuthority { expected: wrong, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(99) },
            checkpoint_config()).await;
        assert!(matches!(result, Err(CheckpointError::Identity)));
        assert!(peers.iter().all(|peer| peer.store.stats().batches == 0 && peer.operator.active_connections() == 0));
        assert_eq!(transport.in_flight(), 0);
    });
    assert_runtime_drained(runtime);
    for peer in &mut peers { peer.stop(); }
}
