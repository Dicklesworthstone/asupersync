//! The same bounded chunked client, now across a durable receiver process crash.

use super::{Process, journal_path, tls};
use asupersync::Cx;
use asupersync::distributed::symbol_service::durable::DurableSymbolLimits;
use asupersync::distributed::symbol_service::recovery::{
    RemoteRecoveryConfig, ReplicaFetch, SnapshotDecodeLimits, SnapshotIdentity,
};
use asupersync::distributed::symbol_service::{
    ChunkedSymbolService, EncodedSymbolBatch, RemoteSymbolError, RemoteSymbolTransport,
    SYMBOL_CHUNKED_SERVICE_COMPUTATION, SymbolBatchLimits, SymbolChunkedLimits,
    SymbolReplicaStore, SymbolStoreLimits, encode_symbol_batch, register_chunked_symbol_service,
};
use asupersync::distributed::{EncodingConfig, RegionSnapshot, StateEncoder};
use asupersync::remote::{
    ComputationName, IdempotencyKey, NodeId, RemoteComputationClient,
    RemoteComputationClientConfig, RemoteComputationRegistry, RemoteInput, RemotePeerAdmissionPolicy,
    RemotePeerHello, RemoteProtocolVersion, RemoteServiceWireLimits, RemoteServiceWireOutcome,
    RemoteServiceWireRequest, RemoteServiceWireResponse, RemoteTaskId, SpawnRequest,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::{AuthKey, AuthenticatedSymbol, SecurityContext};
use asupersync::types::symbol::Symbol;
use asupersync::types::{RegionId, Time};
use asupersync::util::{ArenaIndex, DetRng};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::time::Duration;

pub(super) const FRAME_BYTES: usize = 384 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;
const SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const ATTEMPT: u64 = 0x7139_cdf1_9042_0017;

pub(super) fn limits() -> DurableSymbolLimits {
    DurableSymbolLimits {
        batch: SymbolBatchLimits {
            max_encoded_bytes: 8 * 1024 * 1024, max_symbols: 256,
            max_payload_bytes: 8 * 1024 * 1024, max_decoded_bytes: 16 * 1024 * 1024,
        },
        // Replay must still work when no new immutable object can be admitted.
        store: SymbolStoreLimits { max_batches: 1, max_bytes: 8 * 1024 * 1024,
            max_batches_per_peer: 1, max_bytes_per_peer: 8 * 1024 * 1024 },
        max_journal_bytes: 9 * 1024 * 1024,
    }
}

pub(super) fn staging_limits() -> SymbolChunkedLimits {
    SymbolChunkedLimits::new(CHUNK_BYTES, 1, limits().batch.max_encoded_bytes,
        1, limits().batch.max_encoded_bytes, Duration::from_secs(120)).unwrap()
}

fn client(endpoint: SocketAddr) -> (RemoteComputationClient, RemotePeerHello) {
    // The durable and memory registrations deliberately share exact schemas.
    let store = Arc::new(SymbolReplicaStore::new("replica", AuthKey::from_seed(42),
        limits().batch, limits().store).unwrap());
    let mut registry = RemoteComputationRegistry::new();
    register_chunked_symbol_service(&mut registry,
        Arc::new(ChunkedSymbolService::new(store, staging_limits()))).unwrap();
    let policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    let (_, connector, _) = tls();
    let client = RemoteComputationClient::new(endpoint, "localhost", connector,
        RemoteComputationClientConfig::new().with_max_attempts(1)
            .with_connect_timeout(Duration::from_secs(2)).with_attempt_timeout(Duration::from_secs(10))
            .with_wire_limits(RemoteServiceWireLimits::new(FRAME_BYTES))).unwrap();
    (client, policy.hello_for(NodeId::new("origin")))
}

fn transport(cx: &Cx, endpoint: SocketAddr) -> RemoteSymbolTransport {
    let (client, hello) = client(endpoint);
    RemoteSymbolTransport::new_chunked_bounded(cx.clone(), hello,
        [("replica".to_owned(), client)], Arc::new(AuthKey::from_seed(42)),
        limits().batch, 1, CHUNK_BYTES).unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn chunked_four_mib_snapshot_recovers_after_receiver_crash_with_source_symbol_loss() {
    for workers in [1, 2] {
        let path = journal_path();
        let inode = std::fs::metadata(&path).unwrap();
        let first = Process::start_with_workers(&path, "chunked-create", workers);
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let (params, key, expected, digest, count) = runtime.block_on(async {
            let mut snapshot = RegionSnapshot::empty(RegionId::from_arena(ArenaIndex::new(19, 7)));
            snapshot.origin_id = 91;
            snapshot.epoch = 3;
            snapshot.sequence = 24;
            snapshot.metadata = (0..SNAPSHOT_BYTES).map(|index| (index % 251) as u8).collect();
            snapshot.sign(&AuthKey::from_seed(88));
            let expected = SnapshotIdentity { region_id: snapshot.region_id,
                origin_id: snapshot.origin_id, epoch: snapshot.epoch, sequence: snapshot.sequence };
            let digest: [u8; 32] = Sha256::digest(snapshot.to_bytes()).into();
            let mut encoder = StateEncoder::new(EncodingConfig {
                symbol_size: 32768, min_repair_symbols: 32, max_source_blocks: 4,
                repair_overhead: 1.0, path_quality: None,
            }, DetRng::new(73));
            let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
            assert_eq!(encoded.params.source_blocks, 4);
            assert_eq!(encoded.repair_count, 32);
            let security = SecurityContext::new(AuthKey::from_seed(42));
            // Erase one source equation in EACH block. Eight repair equations
            // per block leave seven redundant equations beyond the source count.
            let signed = encoded.symbols.iter()
                .filter(|symbol| !(symbol.kind().is_source() && symbol.esi() == 0))
                .map(|symbol| security.sign_symbol(symbol)).collect::<Vec<_>>();
            assert_eq!(encoded.symbols.len() - signed.len(), 4);
            assert!(signed.iter().any(|symbol| symbol.symbol().kind().is_repair()));
            let canonical = encode_symbol_batch(&signed, limits().batch).unwrap();
            assert!(canonical.as_ref().len() > SNAPSHOT_BYTES);
            assert!(canonical.as_ref().len() > FRAME_BYTES * 8,
                "the complete batch must not fit a service frame");
            let key = canonical.key();
            let count = canonical.symbol_count();
            drop(canonical);
            let cx = Cx::current().unwrap();
            let transport = transport(&cx, first.address);
            let ack = transport.send_symbols_with_attempt("replica", signed, ATTEMPT).await.unwrap();
            assert_eq!(ack.replica_id, "replica");
            assert_eq!(ack.symbols_received, count);
            assert_eq!(transport.in_flight(), 0);
            (encoded.params, key, expected, digest, count)
            // All original snapshot, source equations and encoder owners die.
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
        let committed = std::fs::metadata(&path).unwrap().len();
        assert!(committed > SNAPSHOT_BYTES as u64);
        first.crash_after_ack();

        let reopened = Process::start_with_workers(&path, "chunked-reopen", workers);
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let transport = transport(&cx, reopened.address);
            let snapshot = transport.recover_snapshot(&[ReplicaFetch { replica_id: "replica".into(), key }],
                RemoteRecoveryConfig {
                    max_replicas: 1, max_concurrent_requests: 1, required_replicas: 1,
                    recovery_timeout: Duration::from_secs(90), replica_timeout: Duration::from_secs(80),
                    max_received_symbols: limits().batch.max_symbols,
                    max_received_payload_bytes: limits().batch.max_payload_bytes,
                }, params, expected,
                SnapshotDecodeLimits { max_snapshot_bytes: 8 * 1024 * 1024,
                    max_source_symbols_per_block: 64, max_source_blocks: 4 },
                &AuthKey::from_seed(88)).await.unwrap();
            assert_eq!(snapshot.metadata.len(), SNAPSHOT_BYTES);
            assert_eq!(<[u8; 32]>::from(Sha256::digest(snapshot.to_bytes())), digest,
                "the exact independently authenticated snapshot must survive source loss and process death");
            let fetched = transport.fetch_symbols("replica", key).await.unwrap();
            assert_eq!(fetched.len(), count as usize);
            assert!(fetched.iter().all(AuthenticatedSymbol::is_verified));
            assert_eq!(encode_symbol_batch(&fetched, limits().batch).unwrap().key(), key);
            let ack = transport.send_symbols_with_attempt("replica", fetched, ATTEMPT).await.unwrap();
            assert_eq!(ack.symbols_received, count);
            assert_eq!(transport.in_flight(), 0);
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
        reopened.finish(1);
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!((after.dev(), after.ino()), (inode.dev(), inode.ino()));
        assert_eq!(after.len(), committed, "recovery and exact-attempt replay never append a duplicate record");
    }
}

fn partial_symbols() -> Vec<AuthenticatedSymbol> {
    let security = SecurityContext::new(AuthKey::from_seed(42));
    (0..16).map(|esi| security.sign_symbol(
        &Symbol::new_for_test(991, 0, esi, &vec![esi as u8; 32768]),
    )).collect()
}

// Independent wire fixture: send only BEGIN or one exact CHUNK, then stop.
// This creates a causal acknowledged-prefix boundary without timing a live
// send loop or adding a public production pause hook.
async fn partial_request(
    cx: &Cx, endpoint: SocketAddr, batch: &EncodedSymbolBatch, chunk: bool,
) -> usize {
    let mut input = Vec::new();
    input.extend_from_slice(b"ASUPCHN\0");
    input.extend_from_slice(&1_u32.to_le_bytes());
    input.push(if chunk { 2 } else { 1 });
    input.push(7);
    input.extend_from_slice(b"replica");
    input.extend_from_slice(&batch.key().object_id.as_u128().to_le_bytes());
    input.extend_from_slice(&batch.key().digest);
    input.extend_from_slice(&ATTEMPT.to_le_bytes());
    input.extend_from_slice(&(batch.as_ref().len() as u64).to_le_bytes());
    input.extend_from_slice(&batch.symbol_count().to_le_bytes());
    let upload = input[21..].to_vec();
    if chunk {
        input.extend_from_slice(&0_u64.to_le_bytes());
        input.extend_from_slice(&batch.as_ref()[..CHUNK_BYTES]);
    }
    let (client, hello) = client(endpoint);
    let task = RemoteTaskId::next();
    let request = SpawnRequest {
        remote_task_id: task, computation: ComputationName::new(SYMBOL_CHUNKED_SERVICE_COMPUTATION),
        input: RemoteInput::new(input), lease: Duration::from_secs(10),
        idempotency_key: IdempotencyKey::from_raw(u128::from(task.raw())), budget: None,
        origin_node: NodeId::new("origin"), origin_region: cx.region_id(), origin_task: cx.task_id(),
    };
    let wire = RemoteServiceWireRequest::from_spawn_request(hello, &request).unwrap();
    let response = client.call(cx, &wire).await.unwrap();
    let RemoteServiceWireResponse::Outcome { outcome: RemoteServiceWireOutcome::Success(bytes), .. } = response
        else { panic!("authenticated partial request was refused"); };
    assert_eq!(bytes.len(), 92);
    assert_eq!(&bytes[..8], b"ASUPPRG\0");
    assert_eq!(&bytes[8..12], &1_u32.to_le_bytes());
    assert_eq!(&bytes[12..80], upload.as_slice());
    assert_eq!(u32::from_le_bytes(bytes[88..92].try_into().unwrap()) as usize, CHUNK_BYTES);
    usize::try_from(u64::from_le_bytes(bytes[80..88].try_into().unwrap())).unwrap()
}

#[test]
fn receiver_restart_discards_only_uncommitted_chunks_and_exact_attempt_reuploads() {
    let path = journal_path();
    let first = Process::start(&path, "chunked-create");
    let initial = std::fs::metadata(&path).unwrap().len();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let batch = encode_symbol_batch(&partial_symbols(), limits().batch).unwrap();
        assert_eq!(partial_request(&cx, first.address, &batch, false).await, 0);
        assert_eq!(partial_request(&cx, first.address, &batch, true).await, CHUNK_BYTES);
        // No further request is sent; the receiver cannot race ahead to COMMIT.
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), initial, "CHUNK progress is volatile");
    first.crash_after_ack();

    let reopened = Process::start_with_workers(&path, "chunked-reopen", 2);
    let runtime = RuntimeBuilder::multi_thread().worker_threads(2).build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let signed = partial_symbols();
        let batch = encode_symbol_batch(&signed, limits().batch).unwrap();
        assert_eq!(partial_request(&cx, reopened.address, &batch, false).await, 0,
            "a lost prefix must never be reported as durably received");
        let transport = transport(&cx, reopened.address);
        let ack = transport.send_symbols_with_attempt("replica", signed, ATTEMPT).await.unwrap();
        assert_eq!(ack.symbols_received, batch.symbol_count());
        let fetched = transport.fetch_symbols("replica", batch.key()).await.unwrap();
        assert_eq!(encode_symbol_batch(&fetched, limits().batch).unwrap().as_ref(), batch.as_ref());
        assert_eq!(transport.in_flight(), 0);
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    reopened.finish(1);
    assert!(std::fs::metadata(path).unwrap().len() > initial);
}

#[test]
fn durable_chunked_registration_without_a_blocking_pool_refuses_before_staging() {
    let path = journal_path();
    let process = Process::start(&path, "chunked-no-pool");
    let initial = std::fs::metadata(&path).unwrap().len();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let transport = transport(&cx, process.address);
        assert!(matches!(transport.send_symbols_with_attempt("replica", partial_symbols(), ATTEMPT).await,
            Err(RemoteSymbolError::Refused)), "the authenticated handler must refuse, not TCP or TLS");
        assert_eq!(transport.in_flight(), 0);
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    process.finish(0);
    assert_eq!(std::fs::metadata(path).unwrap().len(), initial);
}
