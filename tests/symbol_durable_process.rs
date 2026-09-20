//! Actual disk + mTLS + RaptorQ recovery after termination of the storing process.
//! This is process-crash coverage, NOT power-loss/filesystem-conformance proof.
#![cfg(all(unix, not(target_arch = "wasm32"), feature = "tls", feature = "test-internals"))]

use asupersync::distributed::distribution::{DistributionConfig, DistributorTransport, SymbolDistributor};
use asupersync::distributed::symbol_service::{
    RemoteSymbolTransport, SYMBOL_SERVICE_COMPUTATION, SymbolBatchLimits, SymbolReplicaStore,
    SymbolStoreLimits, encode_symbol_batch, register_durable_symbol_service, register_symbol_service,
};
use asupersync::distributed::symbol_service::durable::{DurableSymbolLimits, DurableSymbolReplicaStore};
use asupersync::distributed::symbol_service::recovery::{
    RemoteRecoveryConfig, ReplicaFetch, SnapshotDecodeLimits, SnapshotIdentity,
};
use asupersync::distributed::{EncodingConfig, RegionSnapshot, StateEncoder};
use asupersync::record::distributed_region::{ConsistencyLevel, ReplicaInfo};
use asupersync::remote::{
    NodeId, RemoteComputationClient, RemoteComputationClientConfig, RemoteComputationRegistry,
    RemoteComputationService, RemoteComputationServiceConfig, RemotePeerAdmissionPolicy, RemoteProtocolVersion,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::{AuthKey, SecurityContext};
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth,
    PrivateKey, RootCertStore, TlsAcceptor, TlsAcceptorBuilder, TlsConnector, TlsConnectorBuilder,
};
use asupersync::util::{ArenaIndex, DetRng};
use asupersync::{Cx, types::{RegionId, Time}};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::{Arc, mpsc};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const PREFIX: &str = "ASUP_DURABLE_";
fn limits() -> DurableSymbolLimits {
    DurableSymbolLimits {
        batch: SymbolBatchLimits { max_encoded_bytes: 32768, max_symbols: 64,
            max_payload_bytes: 16384, max_decoded_bytes: 65536 },
        store: SymbolStoreLimits { max_batches: 4, max_bytes: 65536,
            max_batches_per_peer: 4, max_bytes_per_peer: 65536 },
        max_journal_bytes: 131072,
    }
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

#[test]
#[ignore = "worker invoked explicitly by the parent process acceptance tests"]
fn durable_replica_process() {
    let path = std::env::var_os("ASUP_DURABLE_PATH").expect("worker journal");
    let mode = std::env::var("ASUP_DURABLE_MODE").expect("worker mode");
    let file = OpenOptions::new().read(true).write(true).open(path).unwrap();
    let store = Arc::new(if mode == "reopen" {
        DurableSymbolReplicaStore::open(file, "replica", AuthKey::from_seed(42), AuthKey::from_seed(99), limits())
    } else {
        DurableSymbolReplicaStore::create(file, "replica", AuthKey::from_seed(42), AuthKey::from_seed(99), limits())
    }.unwrap());
    let mut registry = RemoteComputationRegistry::new();
    let admission = register_durable_symbol_service(&mut registry, Arc::clone(&store)).unwrap();
    let (acceptor, _, pins) = tls();
    let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    policy.grant_tls_peer(NodeId::new("origin"), pins, [SYMBOL_SERVICE_COMPUTATION]).unwrap();
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, if mode == "no-pool" { 0 } else { 2 }).build().unwrap();
    let service = runtime.block_on(RemoteComputationService::bind(
        "127.0.0.1:0", acceptor, policy, registry,
        RemoteComputationServiceConfig::new().with_max_connections(Some(4))
            .with_drain_timeout(Duration::from_secs(5)),
    )).unwrap();
    let operator = service.handle();
    println!("{PREFIX}READY {}", service.local_addr().unwrap()); io::stdout().flush().unwrap();
    let stop = operator.clone();
    let stdin = thread::spawn(move || {
        let mut byte = [0]; let _ = io::stdin().read(&mut byte); let _ = stop.begin_drain();
    });
    let result = runtime.block_on(async {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(60), service.run(&cx)).await
    });
    stdin.join().unwrap();
    result.expect("worker deadline").expect("worker drain");
    assert_eq!(operator.active_connections(), 0);
    assert!(!admission.in_flight(), "blocking request owners must retire before shutdown");
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    println!("{PREFIX}DONE {}", store.stats().batches);
}

struct Process {
    child: Child,
    input: Option<ChildStdin>,
    pump: Option<JoinHandle<()>>,
    messages: mpsc::Receiver<String>,
    address: SocketAddr,
    reaped: bool,
}
impl Process {
    fn start(path: &Path, mode: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "durable_replica_process", "--ignored", "--nocapture", "--test-threads=1"])
            .env("ASUP_DURABLE_PATH", path).env("ASUP_DURABLE_MODE", mode)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
            .spawn().expect("start isolated durable replica");
        let stdout = child.stdout.take().unwrap();
        let input = child.stdin.take();
        let (tx, rx) = mpsc::sync_channel(4);
        let mut process = Self { child, input, pump: None, messages: rx,
            address: "127.0.0.1:0".parse().unwrap(), reaped: false };
        process.pump = Some(thread::spawn(move || {
            for line in io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break; };
                if let Some((_, message)) = line.split_once(PREFIX) { let _ = tx.try_send(message.to_owned()); }
            }
        }));
        let ready = process.messages.recv_timeout(Duration::from_secs(10)).expect("worker readiness");
        process.address = ready.strip_prefix("READY ").expect("ready receipt").parse().unwrap();
        process
    }
    fn reap(&mut self, crash: bool) -> (ExitStatus, bool) {
        assert!(!self.reaped);
        if crash { self.child.kill().expect("deliberate post-ack process termination"); }
        drop(self.input.take());
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut forced = false;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("poll child") { break status; }
            if Instant::now() >= deadline {
                forced = true; let _ = self.child.kill(); break self.child.wait().expect("reap watchdog child");
            }
            thread::sleep(Duration::from_millis(5));
        };
        self.reaped = true;
        if let Some(pump) = self.pump.take() { pump.join().expect("stdout pump"); }
        (status, forced)
    }
    fn crash_after_ack(mut self) {
        let (status, forced) = self.reap(true);
        assert!(!forced, "intentional crash still requires prompt reap");
        assert!(!status.success(), "a graceful stop is not the crash scenario");
    }
    fn finish(mut self, batches: usize) {
        let (status, forced) = self.reap(false);
        assert!(!forced && status.success(), "worker failed or watchdog terminated it");
        assert!(self.messages.try_iter().any(|line| line == format!("DONE {batches}")));
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.reaped { return; }
        drop(self.input.take());
        // Failure cleanup is not a successful graceful-shutdown receipt.
        let _ = self.child.kill(); let _ = self.child.wait(); self.reaped = true;
        if let Some(pump) = self.pump.take() { let _ = pump.join(); }
    }
}

fn journal_path() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let directory = std::env::temp_dir();
    loop {
        let path = directory.join(format!("asupersync-durable-process-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        match OpenOptions::new().create_new(true).read(true).write(true).open(&path) {
            Ok(file) => {
                file.sync_all().unwrap();
                File::open(&directory).unwrap().sync_all().unwrap(); // Caller persists linkage.
                return path; // Keep artifacts; no deletion on either success or failure.
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create linked journal: {error}"),
        }
    }
}

fn transport(cx: &Cx, endpoint: SocketAddr) -> RemoteSymbolTransport {
    // Both backend registrations deliberately share the existing V1 schemas.
    let mut schema = RemoteComputationRegistry::new();
    register_symbol_service(&mut schema, Arc::new(SymbolReplicaStore::new("replica",
        AuthKey::from_seed(42), limits().batch, limits().store).unwrap())).unwrap();
    let policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, schema.schema_registry().clone());
    let (_, connector, _) = tls();
    let client = RemoteComputationClient::new(endpoint, "localhost", connector,
        RemoteComputationClientConfig::new().with_max_attempts(1)
            .with_connect_timeout(Duration::from_secs(2)).with_attempt_timeout(Duration::from_secs(5))).unwrap();
    RemoteSymbolTransport::new_bounded(cx.clone(), policy.hello_for(NodeId::new("origin")),
        [("replica".to_owned(), client)], Arc::new(AuthKey::from_seed(42)), limits().batch, 1).unwrap()
}

#[test]
fn acknowledged_snapshot_survives_replica_process_crash_and_recovers_over_mtls() {
    for workers in [1, 2] {
        let path = journal_path();
        let first = Process::start(&path, "create");
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let (params, key, expected) = runtime.block_on(async {
            let cx = Cx::current().unwrap(); let transport = transport(&cx, first.address);
            let mut snapshot = RegionSnapshot::empty(RegionId::from_arena(ArenaIndex::new(9, 3)));
            snapshot.origin_id = 77; snapshot.epoch = 5; snapshot.sequence = 8;
            snapshot.metadata = vec![83; 768]; snapshot.sign(&AuthKey::from_seed(88));
            let expected = SnapshotIdentity { region_id: snapshot.region_id, origin_id: 77, epoch: 5, sequence: 8 };
            let mut encoder = StateEncoder::new(EncodingConfig { symbol_size: 128, max_source_blocks: 2,
                min_repair_symbols: 0, repair_overhead: 1.0, path_quality: None }, DetRng::new(3));
            let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
            let security = SecurityContext::new(AuthKey::from_seed(42));
            security.authorize_replica("replica", None).unwrap();
            let signed: Vec<_> = encoded.symbols.iter().map(|symbol| security.sign_symbol(symbol)).collect();
            let key = encode_symbol_batch(&signed, limits().batch).unwrap().key();
            let mut distributor = SymbolDistributor::new(DistributionConfig { consistency: ConsistencyLevel::All,
                max_concurrent: 1, ack_timeout: Duration::from_secs(8), ..Default::default() });
            let result = distributor.distribute(&cx, &encoded, &[ReplicaInfo::new("replica", "ignored")],
                &transport, &security).await;
            assert!(result.quorum_achieved); assert_eq!(result.acks.len(), 1);
            assert_eq!(result.acks[0].symbols_received as usize, signed.len());
            assert_eq!(transport.in_flight(), 0);
            (encoded.params, key, expected)
            // Original snapshot, signed symbols, encoder and client are dropped.
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
        let committed_len = std::fs::metadata(&path).unwrap().len();
        first.crash_after_ack();

        let reopened = Process::start(&path, "reopen");
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        runtime.block_on(async {
            let cx = Cx::current().unwrap(); let transport = transport(&cx, reopened.address);
            let requests = [ReplicaFetch { replica_id: "replica".into(), key }];
            let config = RemoteRecoveryConfig { max_replicas: 1, max_concurrent_requests: 1, required_replicas: 1,
                recovery_timeout: Duration::from_secs(8), replica_timeout: Duration::from_secs(6),
                max_received_symbols: 64, max_received_payload_bytes: 16384 };
            let recovered = transport.recover_snapshot(&requests, config, params, expected,
                SnapshotDecodeLimits { max_snapshot_bytes: 4096, max_source_symbols_per_block: 32, max_source_blocks: 4 },
                &AuthKey::from_seed(88)).await.unwrap();
            assert_eq!(recovered.metadata, vec![83; 768]); assert_eq!(recovered.sequence, 8);
            let fetched = transport.fetch_symbols("replica", key).await.unwrap();
            assert!(fetched.iter().all(|symbol| symbol.is_verified()));
            transport.send_symbols("replica", fetched).await.unwrap(); // Persistent idempotence.
            assert_eq!(transport.in_flight(), 0);
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
        reopened.finish(1);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), committed_len, "fetch and duplicate put never append");
    }
}

#[test]
fn durable_network_service_without_a_blocking_pool_refuses_without_disk_append() {
    let path = journal_path();
    let process = Process::start(&path, "no-pool");
    let before = std::fs::metadata(&path).unwrap().len();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap(); let transport = transport(&cx, process.address);
        let security = SecurityContext::new(AuthKey::from_seed(42));
        let signed = vec![security.sign_symbol(&asupersync::types::symbol::Symbol::new_for_test(1, 0, 0, b"must not append"))];
        let error = transport.send_symbols("replica", signed).await.unwrap_err();
        assert_eq!(error.error_kind, asupersync::error::ErrorKind::AdmissionDenied,
            "must reach the authenticated handler, not fail in TCP or TLS");
        assert_eq!(transport.in_flight(), 0);
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    process.finish(0);
    assert_eq!(std::fs::metadata(path).unwrap().len(), before);
}

#[test]
fn persisted_manifest_recovers_after_replica_crash_without_retaining_batch_parameters() {
    use asupersync::distributed::symbol_service::checkpoint::{
        CheckpointAuthority, CheckpointConfig, CheckpointError, ManifestLimits, RecoveryManifest,
    };
    let manifest_limits = ManifestLimits { max_encoded_bytes: 4096, max_replicas: 4, max_decoded_bytes: 4096 };
    let decode_limits = SnapshotDecodeLimits { max_snapshot_bytes: 4096, max_source_symbols_per_block: 32, max_source_blocks: 4 };
    let path = journal_path();
    let metadata_path = journal_path(); // A separate, newly created, durably linked file.
    let first = Process::start(&path, "create");
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let expected = runtime.block_on(async {
        let cx = Cx::current().unwrap(); let transport = transport(&cx, first.address);
        let mut snapshot = RegionSnapshot::empty(RegionId::from_arena(ArenaIndex::new(9, 3)));
        snapshot.origin_id = 77; snapshot.epoch = 5; snapshot.sequence = 8;
        snapshot.metadata = vec![83; 768]; snapshot.sign(&AuthKey::from_seed(88));
        let expected = SnapshotIdentity { region_id: snapshot.region_id, origin_id: 77, epoch: 5, sequence: 8 };
        let mut encoder = StateEncoder::new(EncodingConfig { symbol_size: 128, max_source_blocks: 2,
            min_repair_symbols: 0, repair_overhead: 1.0, path_quality: None }, DetRng::new(3));
        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
        let security = SecurityContext::new(AuthKey::from_seed(42));
        security.authorize_replica("replica", None).unwrap();
        let mut distributor = SymbolDistributor::new(DistributionConfig {
            consistency: ConsistencyLevel::All, max_concurrent: 1, ack_timeout: Duration::from_secs(8), ..Default::default()
        });
        let checkpoint = transport.replicate_checkpoint(&mut distributor, &encoded,
            &[ReplicaInfo::new("replica", "ignored")], &security,
            CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(88), manifest_key: &AuthKey::from_seed(101) },
            CheckpointConfig { manifest: manifest_limits, decode: decode_limits,
                minimum_recovery_replicas: 1, timeout: Duration::from_secs(12) }).await.unwrap();
        assert!(checkpoint.distribution().quorum_achieved);
        assert_eq!(checkpoint.manifest().replicas().len(), 1);
        assert_eq!(distributor.metrics.distributions_successful, 1);
        assert_eq!(transport.in_flight(), 0);
        let mut metadata = OpenOptions::new().write(true).open(&metadata_path).unwrap();
        metadata.write_all(checkpoint.encoded_manifest()).unwrap(); metadata.sync_all().unwrap();
        expected
        // All snapshot/encoding/batch/manifest owners die here. Only independent
        // expected authority survives; no ObjectParams or ReplicaFetch is kept.
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    first.crash_after_ack();
    let original_length = std::fs::metadata(&path).unwrap().len();
    let reopened = Process::start(&path, "reopen");
    let runtime = RuntimeBuilder::multi_thread().worker_threads(2).build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap(); let transport = transport(&cx, reopened.address);
        let bytes = std::fs::read(&metadata_path).unwrap(); // Small, caller-owned test fixture.
        let manifest = RecoveryManifest::from_canonical_bytes(&bytes, &AuthKey::from_seed(101), expected,
            &NodeId::new("origin"), manifest_limits).unwrap();
        drop(bytes);
        let config = RemoteRecoveryConfig { max_replicas: 4, max_concurrent_requests: 1, required_replicas: 1,
            recovery_timeout: Duration::from_secs(8), replica_timeout: Duration::from_secs(6),
            max_received_symbols: 64, max_received_payload_bytes: 16384 };
        let mut weak = config; weak.required_replicas = 0;
        assert!(matches!(transport.recover_checkpoint(&manifest, weak, decode_limits, &AuthKey::from_seed(88)).await,
            Err(CheckpointError::RecoveryThreshold)));
        assert_eq!(transport.in_flight(), 0);
        let snapshot = transport.recover_checkpoint(&manifest, config, decode_limits, &AuthKey::from_seed(88)).await.unwrap();
        assert_eq!(snapshot.metadata, vec![83; 768]); assert_eq!(snapshot.sequence, 8);
        assert_eq!(snapshot.region_id, expected.region_id);
        assert_eq!(snapshot.origin_id, expected.origin_id); assert_eq!(snapshot.epoch, expected.epoch);
        assert_eq!(transport.in_flight(), 0);
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    reopened.finish(1);
    assert_eq!(std::fs::metadata(path).unwrap().len(), original_length, "recovery performs no journal append");
}

#[test]
fn invalid_snapshot_key_never_publishes_a_checkpoint_to_a_live_replica() {
    use asupersync::distributed::symbol_service::checkpoint::{CheckpointAuthority, CheckpointConfig, CheckpointError, ManifestLimits};
    let path = journal_path(); let process = Process::start(&path, "create");
    let initial_length = std::fs::metadata(&path).unwrap().len();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap(); let transport = transport(&cx, process.address);
        let mut snapshot = RegionSnapshot::empty(RegionId::from_arena(ArenaIndex::new(9, 3)));
        snapshot.origin_id = 77; snapshot.epoch = 5; snapshot.sequence = 8;
        snapshot.metadata = vec![83; 768]; snapshot.sign(&AuthKey::from_seed(88));
        let expected = SnapshotIdentity { region_id: snapshot.region_id, origin_id: 77, epoch: 5, sequence: 8 };
        let mut encoder = StateEncoder::new(EncodingConfig { symbol_size: 128, max_source_blocks: 2,
            min_repair_symbols: 0, repair_overhead: 1.0, path_quality: None }, DetRng::new(3));
        let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();
        let security = SecurityContext::new(AuthKey::from_seed(42)); security.authorize_replica("replica", None).unwrap();
        let mut distributor = SymbolDistributor::new(Default::default());
        let result = transport.replicate_checkpoint(&mut distributor, &encoded,
            &[ReplicaInfo::new("replica", "ignored")], &security,
            CheckpointAuthority { expected, snapshot_key: &AuthKey::from_seed(89), manifest_key: &AuthKey::from_seed(101) },
            CheckpointConfig { manifest: ManifestLimits { max_encoded_bytes: 4096, max_replicas: 4, max_decoded_bytes: 4096 },
                decode: SnapshotDecodeLimits { max_snapshot_bytes: 4096, max_source_symbols_per_block: 32, max_source_blocks: 4 },
                minimum_recovery_replicas: 1, timeout: Duration::from_secs(8) }).await;
        assert!(matches!(result, Err(CheckpointError::Decode)));
        assert_eq!(distributor.metrics.distributions_total, 0);
        assert_eq!(transport.in_flight(), 0);
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    process.finish(0);
    assert_eq!(std::fs::metadata(path).unwrap().len(), initial_length);
}


#[path = "symbol_durable_process/continuation.rs"]
mod continuation;
