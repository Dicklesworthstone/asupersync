//! Authenticated recovery completes from useful donors while a real mTLS fetch
//! is unanswered. Healthy replies use the production symbol-service adapter.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]
#![recursion_limit = "256"]

use asupersync::codec::{Framed, LengthDelimitedCodec};
use asupersync::distributed::symbol_service::checkpoint::{ManifestLimits, RecoveryManifest};
use asupersync::distributed::symbol_service::recovery::{
    RemoteRecoveryConfig, RemoteRecoveryError, ReplicaFetch, SnapshotDecodeLimits, SnapshotIdentity,
};
use asupersync::distributed::symbol_service::{
    RemoteSymbolTransport, SYMBOL_SERVICE_COMPUTATION, SymbolBatchKey, SymbolBatchLimits,
    SymbolReplicaStore, SymbolStoreLimits, encode_symbol_batch, register_symbol_service,
};
use asupersync::distributed::{EncodingConfig, RegionSnapshot, StateEncoder};
use asupersync::net::TcpListener;
use asupersync::remote::{
    ComputationName, NodeId, RemoteComputationClient, RemoteComputationClientConfig,
    RemoteComputationRegistry, RemotePeerAdmissionPolicy, RemoteProtocolVersion,
    RemoteServiceWireLimits, RemoteServiceWireRequest, RemoteServiceWireResponse,
    serve_tls_computation_once,
};
use asupersync::runtime::{RuntimeBuilder, TaskHandle};
use asupersync::security::{AuthKey, AuthenticatedSymbol, SecurityContext};
use asupersync::stream::StreamExt;
use asupersync::sync::Notify;
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth, PrivateKey,
    RootCertStore, TlsAcceptor, TlsAcceptorBuilder, TlsConnector, TlsConnectorBuilder,
};
use asupersync::types::symbol::ObjectParams;
use asupersync::util::{ArenaIndex, DetRng};
use asupersync::{Cx, types::{RegionId, Time}};
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const ORIGIN: &str = "quorum-origin";
const IDS: [&str; 3] = ["quorum-a", "quorum-b", "quorum-c"];

fn limits() -> SymbolBatchLimits {
    SymbolBatchLimits { max_encoded_bytes: 65536, max_symbols: 128,
        max_payload_bytes: 32768, max_decoded_bytes: 131072 }
}
fn decode_limits() -> SnapshotDecodeLimits {
    SnapshotDecodeLimits { max_snapshot_bytes: 16384, max_source_symbols_per_block: 64, max_source_blocks: 2 }
}
fn config() -> RemoteRecoveryConfig {
    RemoteRecoveryConfig { max_replicas: 3, max_concurrent_requests: 3, required_replicas: 2,
        recovery_timeout: Duration::from_secs(30), replica_timeout: Duration::from_secs(30),
        max_received_symbols: 384, max_received_payload_bytes: 98304 }
}
fn tls() -> (TlsAcceptor, TlsConnector, CertificatePinSet) {
    let certificate = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap().remove(0);
    let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
    let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
    let mut roots = RootCertStore::empty(); roots.add(&certificate).unwrap();
    let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone()).client_auth(ClientAuth::Required(roots)).build().unwrap();
    let mut pins = CertificatePinSet::new(); pins.add(CertificatePin::compute_spki_sha256(&certificate).unwrap());
    let connector = TlsConnectorBuilder::new().add_root_certificate(&certificate)
        .identity(chain, key).with_certificate_pins(pins.clone()).build().unwrap();
    (acceptor, connector, pins)
}

#[derive(Default)]
struct Gate { open: AtomicBool, changed: Notify }
impl Gate {
    fn release(&self) { self.open.store(true, Ordering::Release); self.changed.notify_waiters(); }
    async fn wait(&self) { self.changed.wait_until(|| self.open.load(Ordering::Acquire)).await; }
}
#[derive(Default)]
struct Witness { requested: AtomicBool, closed: AtomicBool, replied: AtomicUsize, changed: Notify }
struct Peer { address: SocketAddr, task: TaskHandle<()>, witness: Arc<Witness> }

fn stored(id: &str, symbols: &[AuthenticatedSymbol]) -> (Arc<SymbolReplicaStore>, SymbolBatchKey) {
    let store = Arc::new(SymbolReplicaStore::new(id, AuthKey::from_seed(42), limits(),
        SymbolStoreLimits { max_batches: 2, max_bytes: 131072, max_batches_per_peer: 2, max_bytes_per_peer: 131072 }).unwrap());
    let encoded = encode_symbol_batch(symbols, limits()).unwrap();
    let key = encoded.key();
    assert_eq!(store.put(&NodeId::new(ORIGIN), encoded.as_ref()).unwrap().key(), key);
    (store, key)
}
fn policy(store: Arc<SymbolReplicaStore>) -> (RemoteComputationRegistry, RemotePeerAdmissionPolicy) {
    let mut registry = RemoteComputationRegistry::new(); register_symbol_service(&mut registry, store).unwrap();
    let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    policy.grant_tls_peer(NodeId::new(ORIGIN), tls().2, [SYMBOL_SERVICE_COMPUTATION]).unwrap();
    (registry, policy)
}
async fn serving_peer(cx: &Cx, store: Arc<SymbolReplicaStore>, gate: Arc<Gate>, requests: usize) -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let witness = Arc::new(Witness::default()); let observed = Arc::clone(&witness);
    let (registry, policy) = policy(store); let acceptor = tls().0;
    let task = cx.spawn(move |cx| async move {
        asupersync::time::timeout(cx.now(), Duration::from_secs(12), async {
            for _ in 0..requests {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                gate.wait().await;
                let response = serve_tls_computation_once(&cx, &mut stream, &policy, &registry,
                    RemoteServiceWireLimits::new(262144)).await.unwrap();
                assert!(matches!(response, RemoteServiceWireResponse::Outcome { .. }));
                observed.replied.fetch_add(1, Ordering::AcqRel); observed.changed.notify_waiters();
            }
        }).await.expect("bounded healthy native donor");
    }).unwrap();
    Peer { address, task, witness }
}
async fn silent_peer(cx: &Cx, store: Arc<SymbolReplicaStore>, expected: SymbolBatchKey) -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let witness = Arc::new(Witness::default()); let observed = Arc::clone(&witness);
    let id = store.replica_id().to_owned(); let (_, policy) = policy(store); let acceptor = tls().0;
    let task = cx.spawn(move |cx| async move {
        asupersync::time::timeout(cx.now(), Duration::from_secs(12), async {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            let codec = LengthDelimitedCodec::builder().max_frame_length(262144).big_endian().new_codec();
            let mut framed = Framed::new(stream, codec).with_max_buffer_len(262148);
            let bytes = framed.next().await.expect("actual fetch frame").unwrap();
            let request: RemoteServiceWireRequest = serde_json::from_slice(&bytes).unwrap();
            let admitted = policy.admit_tls_peer(request.hello(), framed.get_ref()).unwrap();
            admitted.authorize_computation(&ComputationName::new(SYMBOL_SERVICE_COMPUTATION)).unwrap();
            let fields: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(fields["computation"], SYMBOL_SERVICE_COMPUTATION);
            let input: Vec<u8> = serde_json::from_value(fields["input"].clone()).unwrap();
            let mut expected_input = b"ASUPGET\0".to_vec();
            expected_input.extend_from_slice(&1_u32.to_le_bytes()); expected_input.push(u8::try_from(id.len()).unwrap());
            expected_input.extend_from_slice(id.as_bytes());
            expected_input.extend_from_slice(&expected.object_id.as_u128().to_le_bytes()); expected_input.extend_from_slice(&expected.digest);
            assert_eq!(input, expected_input, "stalled state reached the exact authenticated fetch");
            observed.requested.store(true, Ordering::Release); observed.changed.notify_waiters();
            // Never release a response: the recovery owner's teardown must close
            // this connection. TLS without close_notify may report abrupt EOF.
            match framed.next().await {
                None => {}
                Some(Err(error)) => assert!(matches!(error.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe)),
                Some(Ok(_)) => panic!("unexpected second request on a V1 fetch connection"),
            }
            observed.closed.store(true, Ordering::Release); observed.changed.notify_waiters();
        }).await.expect("stalled donor must observe local connection closure");
    }).unwrap();
    Peer { address, task, witness }
}
fn transport(cx: &Cx, peers: &[Peer; 3], store: Arc<SymbolReplicaStore>) -> RemoteSymbolTransport {
    let (_, policy) = policy(store); let connector = tls().1;
    let routes = IDS.into_iter().zip(peers).map(|(id, peer)| {
        let client = RemoteComputationClient::new(peer.address, "localhost", connector.clone(),
            RemoteComputationClientConfig::new().with_max_attempts(1)
                .with_connect_timeout(Duration::from_secs(30)).with_attempt_timeout(Duration::from_secs(30))
                .with_wire_limits(RemoteServiceWireLimits::new(262144))).unwrap();
        (id.to_owned(), client)
    });
    RemoteSymbolTransport::new_bounded(cx.clone(), policy.hello_for(NodeId::new(ORIGIN)), routes,
        Arc::new(AuthKey::from_seed(42)), limits(), 3).unwrap()
}
fn source() -> (Vec<AuthenticatedSymbol>, ObjectParams, SnapshotIdentity, Vec<u8>) {
    let mut snapshot = RegionSnapshot::empty(RegionId::from_arena(ArenaIndex::new(7, 2)));
    snapshot.origin_id = 11; snapshot.epoch = 3; snapshot.sequence = 19;
    snapshot.metadata = (0..8192).map(|n| u8::try_from((n * 37) % 256).unwrap()).collect();
    snapshot.sign(&AuthKey::from_seed(88));
    let expected = SnapshotIdentity { region_id: snapshot.region_id, origin_id: 11, epoch: 3, sequence: 19 };
    let mut encoder = StateEncoder::new(EncodingConfig { symbol_size: 256, max_source_blocks: 2,
        min_repair_symbols: 0, repair_overhead: 1.0, path_quality: None }, DetRng::new(31));
    let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
    assert_eq!(encoded.params.source_blocks, 2); assert_eq!(encoded.repair_count, 0);
    let security = SecurityContext::new(AuthKey::from_seed(42));
    (encoded.symbols.iter().map(|s| security.sign_symbol(s)).collect(), encoded.params, expected, snapshot.to_bytes())
}
async fn join_peers(cx: &Cx, peers: &mut [Peer; 3]) {
    for peer in peers {
        asupersync::time::timeout(cx.now(), Duration::from_secs(3), peer.task.join(cx)).await
            .expect("native peer completion bound").expect("native peer completed without panic");
    }
}

#[test]
fn native_authenticated_quorum_retires_a_parked_fetch_and_reuses_healthy_routes() {
    for workers in [1, 2] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        runtime.block_on(async {
            let cx = Cx::current().unwrap(); let (symbols, params, expected, original) = source();
            let left: Vec<_> = symbols.iter().enumerate().filter(|(i, _)| i % 2 == 0).map(|(_, s)| s.clone()).collect();
            let right: Vec<_> = symbols.iter().enumerate().filter(|(i, _)| i % 2 == 1).map(|(_, s)| s.clone()).collect();
            assert!(left.len() < params.total_source_symbols() as usize && right.len() < params.total_source_symbols() as usize);
            let (a, ka) = stored(IDS[0], &symbols); let (b, kb) = stored(IDS[1], &left); let (c, kc) = stored(IDS[2], &right);
            let gate = Arc::new(Gate::default());
            let mut peers = [silent_peer(&cx, Arc::clone(&a), ka).await,
                serving_peer(&cx, b, Arc::clone(&gate), 2).await,
                serving_peer(&cx, c, Arc::clone(&gate), 2).await];
            let transport = transport(&cx, &peers, a);
            let requests: Vec<_> = IDS.into_iter().zip([ka, kb, kc]).map(|(id, key)| ReplicaFetch { replica_id: id.into(), key }).collect();
            let manifest_limits = ManifestLimits { max_encoded_bytes: 4096, max_replicas: 3, max_decoded_bytes: 4096 };
            let manifest = RecoveryManifest::new(NodeId::new(ORIGIN), params, expected, requests.clone(), 2, manifest_limits).unwrap();
            let bytes = manifest.to_canonical_bytes(&AuthKey::from_seed(99), 4096).unwrap();
            let manifest = RecoveryManifest::from_canonical_bytes(bytes.as_ref(), &AuthKey::from_seed(99), expected,
                &NodeId::new(ORIGIN), manifest_limits).unwrap();
            let snapshot_key = AuthKey::from_seed(88);
            {
            let mut recovery = std::pin::pin!(transport.recover_checkpoint_on_quorum(&manifest, config(), decode_limits(), &snapshot_key));
            let mut observed = std::pin::pin!(peers[0].witness.changed.wait_until(|| peers[0].witness.requested.load(Ordering::Acquire)));
            asupersync::time::timeout(cx.now(), Duration::from_secs(5), poll_fn(|task| {
                assert!(recovery.as_mut().poll(task).is_pending(), "healthy replies are causally withheld");
                observed.as_mut().poll(task)
            })).await.expect("stalled authenticated fetch witness");
            assert!(!peers[0].witness.closed.load(Ordering::Acquire)); assert!(transport.in_flight() >= 1);
            gate.release();
            let recovered = asupersync::time::timeout(cx.now(), Duration::from_secs(5), recovery.as_mut()).await
                .expect("healthy quorum must complete before the 30-second donor deadlines").unwrap();
            assert_eq!(recovered.to_bytes(), original); assert_eq!(transport.in_flight(), 0);
            asupersync::time::timeout(cx.now(), Duration::from_secs(3), peers[0].witness.changed
                .wait_until(|| peers[0].witness.closed.load(Ordering::Acquire))).await.expect("pending fetch connection closes");
            // The same bounded transport can immediately admit fresh requests.
            let again = transport.recover_snapshot_on_quorum(&requests[1..], config(), params, expected, decode_limits(), &snapshot_key).await.unwrap();
            assert_eq!(again.to_bytes(), original); assert_eq!(transport.in_flight(), 0);
            }
            join_peers(&cx, &mut peers).await;
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn native_quorum_waits_for_source_block_coverage_despite_two_valid_replies() {
    for workers in [1, 2] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        runtime.block_on(async {
            let cx = Cx::current().unwrap(); let (symbols, params, expected, original) = source();
            let first: Vec<_> = symbols.iter().filter(|s| s.symbol().sbn() == 0).cloned().collect();
            let second: Vec<_> = symbols.iter().filter(|s| s.symbol().sbn() == 1).cloned().collect();
            let (a, ka) = stored(IDS[0], &first); let (b, kb) = stored(IDS[1], &first); let (c, kc) = stored(IDS[2], &second);
            let ready = Arc::new(Gate::default()); ready.release(); let withheld = Arc::new(Gate::default());
            let mut peers = [serving_peer(&cx, Arc::clone(&a), Arc::clone(&ready), 1).await,
                serving_peer(&cx, b, ready, 1).await, serving_peer(&cx, c, Arc::clone(&withheld), 1).await];
            let transport = transport(&cx, &peers, a);
            let requests: Vec<_> = IDS.into_iter().zip([ka, kb, kc]).map(|(id, key)| ReplicaFetch { replica_id: id.into(), key }).collect();
            let snapshot_key = AuthKey::from_seed(88);
            {
                let mut recovery = std::pin::pin!(transport.recover_snapshot_on_quorum(&requests, config(), params, expected, decode_limits(), &snapshot_key));
                let witnesses = async {
                    for peer in &peers[..2] { peer.witness.changed.wait_until(|| peer.witness.replied.load(Ordering::Acquire) == 1).await; }
                };
                let mut witnesses = std::pin::pin!(witnesses);
                let mut replies_flushed = false;
                asupersync::time::timeout(cx.now(), Duration::from_secs(5), poll_fn(|task| {
                    assert!(recovery.as_mut().poll(task).is_pending(), "two replies cannot reconstruct the absent block");
                    if !replies_flushed { replies_flushed = witnesses.as_mut().poll(task).is_ready(); }
                    if replies_flushed && transport.in_flight() == 1 { std::task::Poll::Ready(()) }
                    else { std::task::Poll::Pending }
                })).await.expect("two fully flushed replies are consumed; only the missing block's fetch remains");
                assert!(!withheld.open.load(Ordering::Acquire));
                withheld.release();
                let recovered = asupersync::time::timeout(cx.now(), Duration::from_secs(5), recovery.as_mut()).await.unwrap().unwrap();
                assert_eq!(recovered.to_bytes(), original); assert_eq!(transport.in_flight(), 0);
            }
            join_peers(&cx, &mut peers).await;
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn native_quorum_refuses_an_independently_wrong_snapshot_key() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap(); let (symbols, params, expected, _) = source();
        let (a, ka) = stored(IDS[0], &symbols); let (b, kb) = stored(IDS[1], &symbols); let (c, kc) = stored(IDS[2], &symbols);
        let gate = Arc::new(Gate::default()); gate.release();
        let mut peers = [serving_peer(&cx, Arc::clone(&a), Arc::clone(&gate), 1).await,
            serving_peer(&cx, b, Arc::clone(&gate), 1).await, serving_peer(&cx, c, gate, 1).await];
        let transport = transport(&cx, &peers, a);
        let requests: Vec<_> = IDS.into_iter().zip([ka, kb, kc]).map(|(id, key)| ReplicaFetch { replica_id: id.into(), key }).collect();
        let result = transport.recover_snapshot_on_quorum(&requests, config(), params, expected, decode_limits(), &AuthKey::from_seed(89)).await;
        assert!(matches!(result, Err(RemoteRecoveryError::Decode))); assert_eq!(transport.in_flight(), 0);
        join_peers(&cx, &mut peers).await;
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}
