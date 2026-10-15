//! Separate OS processes run the actual mTLS symbol service and immutable store.
//! A deliberately stalled TCP/TLS peer verifies local loser-close, not storage.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]
// Raise the type-checker recursion limit for the deeply-nested async `Send`
// bound evaluation in this multi-process hedge test (the compiler suggests 256).
// Silences the future-incompatible `recursion_depth_exceeding_limit` warning
// (rust-lang #159228), which will otherwise become a hard error in a future rustc.
#![recursion_limit = "256"]

use asupersync::distributed::distribution::{
    DistributionConfig, DistributionResult, DistributorTransport, ReplicaAck, ReplicaFailure,
    SymbolDistributor,
};
use asupersync::distributed::symbol_service::{
    RemoteSymbolTransport, SYMBOL_SERVICE_COMPUTATION, SymbolBatchLimits,
    SymbolReplicaStore, SymbolStoreLimits, encode_symbol_batch, register_symbol_service,
};
use asupersync::distributed::EncodedState;
use asupersync::error::ErrorKind;
use asupersync::record::distributed_region::{ConsistencyLevel, ReplicaInfo};
use asupersync::remote::{
    NodeId, RemoteComputationClient, RemoteComputationClientConfig, RemoteComputationRegistry,
    RemoteComputationService, RemoteComputationServiceConfig, RemotePeerAdmissionPolicy,
    RemoteProtocolVersion,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::{AuthKey, AuthenticatedSymbol, SecurityContext};
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth,
    PrivateKey, RootCertStore, TlsAcceptor, TlsAcceptorBuilder, TlsConnector, TlsConnectorBuilder,
};
use asupersync::types::symbol::{ObjectParams, Symbol};
use asupersync::{Cx, types::Time};
use std::io::{self, BufRead, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const CERT: &[u8] = include_bytes!("fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("fixtures/tls/server.key");
const PREFIX: &str = "ASUPERSYNC_HEDGE_";

fn limits() -> SymbolBatchLimits {
    SymbolBatchLimits { max_encoded_bytes: 8192, max_symbols: 32, max_payload_bytes: 4096, max_decoded_bytes: 16384 }
}
fn store(id: &str, key: u64) -> Arc<SymbolReplicaStore> {
    Arc::new(SymbolReplicaStore::new(id, AuthKey::from_seed(key), limits(), SymbolStoreLimits {
        max_batches: 2, max_bytes: 16384, max_batches_per_peer: 2, max_bytes_per_peer: 16384,
    }).unwrap())
}
fn tls() -> (TlsAcceptor, TlsConnector, CertificatePinSet) {
    let certificate = Certificate::from_pem(CERT).unwrap().remove(0);
    let chain = CertificateChain::from_pem(CERT).unwrap();
    let key = PrivateKey::from_pem(KEY).unwrap();
    let mut roots = RootCertStore::empty(); roots.add(&certificate).unwrap();
    let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
        .client_auth(ClientAuth::Required(roots)).build().unwrap();
    let mut pins = CertificatePinSet::new();
    pins.add(CertificatePin::compute_spki_sha256(&certificate).unwrap());
    let connector = TlsConnectorBuilder::new().add_root_certificate(&certificate)
        .identity(chain, key).with_certificate_pins(pins.clone()).build().unwrap();
    (acceptor, connector, pins)
}
fn ready(id: &str, address: SocketAddr) {
    println!("{PREFIX}READY {id} {address}"); io::stdout().flush().unwrap();
}

// Each process owns a private store, runtime and address space. This ignored
// entry is a subprocess worker, not an acceptance test skipped by the parent.
#[test]
#[ignore = "worker invoked explicitly by the two parent process tests"]
fn replica_process() {
    let id = std::env::var("ASUPERSYNC_HEDGE_REPLICA").expect("worker replica identity");
    let mode = std::env::var("ASUPERSYNC_HEDGE_MODE").expect("worker behavior");
    if mode == "stall" {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap(); ready(&id, listener.local_addr().unwrap());
        let started = Instant::now();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(started.elapsed() < Duration::from_secs(60), "no primary connection");
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        drop(listener);
        stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        let mut bytes = 0;
        let mut buf = [0; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(count) => { bytes += count; assert!(bytes <= 65_536); }
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("loser connection was not closed: {error}"),
            }
        }
        assert!(bytes > 0, "must receive an actual TLS ClientHello");
        println!("{PREFIX}CLOSED {id} {bytes}");
        return;
    }

    let retained = store(&id, if mode == "wrong-key" { 43 } else { 42 });
    let mut registry = RemoteComputationRegistry::new();
    register_symbol_service(&mut registry, Arc::clone(&retained)).unwrap();
    let (acceptor, _, pins) = tls();
    let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    policy.grant_tls_peer(NodeId::new("origin"), pins, [SYMBOL_SERVICE_COMPUTATION]).unwrap();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let service = runtime.block_on(RemoteComputationService::bind(
        "127.0.0.1:0", acceptor, policy, registry,
        RemoteComputationServiceConfig::new().with_max_connections(Some(2))
            .with_drain_timeout(Duration::from_secs(3)),
    )).unwrap();
    let operator = service.handle();
    ready(&id, service.local_addr().unwrap());
    let stop = operator.clone();
    let stdin = thread::spawn(move || {
        let mut byte = [0]; let _ = io::stdin().read(&mut byte);
        let _ = stop.begin_drain(); // Parent closes stdin on success AND failure.
    });
    let result = runtime.block_on(async {
        let cx = Cx::current().expect("server context");
        asupersync::time::timeout(cx.now(), Duration::from_secs(60), service.run(&cx)).await
    });
    stdin.join().unwrap();
    let report = result.expect("worker service deadline").expect("worker service run");
    assert_eq!(operator.active_connections(), 0);
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    println!("{PREFIX}DONE {id} {} {} {} {}",
        retained.stats().batches, report.accepted_connections(),
        report.completed_connections(), report.failed_connections());
}

struct ReplicaProcess {
    child: Child,
    input: Option<ChildStdin>,
    pump: Option<JoinHandle<()>>,
    messages: mpsc::Receiver<String>,
    address: SocketAddr,
}
impl ReplicaProcess {
    fn start(id: &str, mode: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "replica_process", "--ignored", "--nocapture", "--test-threads=1"])
            .env("ASUPERSYNC_HEDGE_REPLICA", id).env("ASUPERSYNC_HEDGE_MODE", mode)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
            .spawn().expect("launch isolated replica process");
        let stdout = child.stdout.take().unwrap();
        let input = child.stdin.take();
        let (tx, rx) = mpsc::sync_channel(4);
        let mut process = Self {
            child, input, pump: None, messages: rx, address: "127.0.0.1:0".parse().unwrap(),
        };
        process.pump = Some(thread::spawn(move || {
            // Drain ordinary harness output too, so the child never blocks on a
            // full stdout pipe. At most READY and one terminal receipt are kept.
            for line in io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break; };
                if let Some((_, message)) = line.split_once(PREFIX) {
                    let _ = tx.try_send(message.to_owned());
                }
            }
        }));
        let ready = process.messages.recv_timeout(Duration::from_secs(10)).expect("replica readiness");
        let fields: Vec<_> = ready.split_whitespace().collect();
        assert_eq!(fields.len(), 3); assert_eq!(fields[0], "READY"); assert_eq!(fields[1], id);
        process.address = fields[2].parse().unwrap();
        process
    }
    fn stop(&mut self) -> io::Result<ExitStatus> {
        drop(self.input.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        let result = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                _ => {
                    // Watchdog only: forced termination is a test failure, not
                    // evidence of graceful drain. Always reap the owned child.
                    let _ = self.child.kill();
                    break self.child.wait();
                }
            }
        };
        if let Some(pump) = self.pump.take() { let _ = pump.join(); }
        result
    }
    fn finish(mut self) -> Vec<String> {
        let status = self.stop().expect("reap replica");
        assert!(status.success(), "replica failed or required watchdog termination: {status}");
        self.messages.try_iter().collect()
    }
}
impl Drop for ReplicaProcess {
    fn drop(&mut self) { let _ = self.stop(); }
}

struct Observed {
    inner: RemoteSymbolTransport,
    started: Mutex<Vec<String>>,
    active: AtomicUsize,
    peak: AtomicUsize,
}
struct Credit<'a>(&'a AtomicUsize);
impl Drop for Credit<'_> { fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); } }
impl DistributorTransport for Observed {
    async fn send_symbols(&self, replica: &str, symbols: Vec<AuthenticatedSymbol>)
        -> Result<ReplicaAck, ReplicaFailure>
    {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        let _credit = Credit(&self.active);
        self.peak.fetch_max(active, Ordering::SeqCst);
        self.started.lock().unwrap().push(replica.to_owned());
        self.inner.send_symbols(replica, symbols).await
    }
}

fn exercise(stalled: bool, workers: usize) {
    let primary = ReplicaProcess::start("r0", if stalled { "stall" } else { "wrong-key" });
    let healthy = ReplicaProcess::start("r1", "healthy");
    let backup = ReplicaProcess::start("r2", "healthy");
    let endpoints = [primary.address, healthy.address, backup.address];
    let capacity = if stalled { 2 } else { 1 };
    let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
    let result: DistributionResult = runtime.block_on(async {
        let cx = Cx::current().expect("client context");
        let (_, connector, _) = tls();
        let mut registry = RemoteComputationRegistry::new();
        register_symbol_service(&mut registry, store("schema-only", 42)).unwrap();
        let policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
        let hello = policy.hello_for(NodeId::new("origin"));
        let routes: Vec<_> = endpoints.iter().enumerate().map(|(i, &endpoint)| {
            let client = RemoteComputationClient::new(endpoint, "localhost", connector.clone(),
                RemoteComputationClientConfig::new().with_max_attempts(1)
                    .with_connect_timeout(Duration::from_secs(20))
                    .with_attempt_timeout(Duration::from_secs(30)),
            ).unwrap();
            (format!("r{i}"), client)
        }).collect();
        let transport = Observed {
            inner: RemoteSymbolTransport::new_bounded(cx.clone(), hello, routes,
                Arc::new(AuthKey::from_seed(42)), limits(), capacity).unwrap(),
            started: Mutex::new(Vec::new()), active: AtomicUsize::new(0), peak: AtomicUsize::new(0),
        };
        let security = SecurityContext::new(AuthKey::from_seed(42));
        let replicas: Vec<_> = (0..3).map(|i| {
            let id = format!("r{i}"); security.authorize_replica(&id, None).unwrap();
            ReplicaInfo::new(&id, "not-used-for-routing")
        }).collect();
        let encoded = EncodedState {
            params: ObjectParams::new_for_test(17, 64),
            symbols: (0..4).map(|esi| Symbol::new_for_test(17, 0, esi, &[5; 16])).collect(),
            source_count: 4, repair_count: 0, original_size: 64,
            encoded_at: Time::ZERO, layout_decision: Default::default(),
        };
        let signed: Vec<_> = encoded.symbols.iter().map(|s| security.sign_symbol(s)).collect();
        let key = encode_symbol_batch(&signed, limits()).unwrap().key(); drop(signed);
        let mut distributor = SymbolDistributor::new(DistributionConfig {
            consistency: if stalled { ConsistencyLevel::Quorum } else { ConsistencyLevel::All },
            max_concurrent: capacity, hedge_enabled: true, hedge_delay: Duration::from_millis(20),
            ack_timeout: Duration::from_secs(30), ..Default::default()
        });
        // Must terminate BEFORE any primary acknowledgement/connection timeout.
        let result = asupersync::time::timeout(cx.now(), Duration::from_secs(10),
            distributor.distribute(&cx, &encoded, &replicas, &transport, &security)).await
            .expect("hedge or impossibility must finish without waiting for primary timeout");
        drop(encoded);
        assert_eq!(transport.active.load(Ordering::SeqCst), 0);
        assert_eq!(transport.inner.in_flight(), 0);
        assert!(transport.peak.load(Ordering::SeqCst) <= capacity);
        assert!(!cx.is_cancel_requested(), "loser retirement must not cancel the parent");
        assert_eq!(distributor.metrics.distributions_total, 1);
        assert_eq!(distributor.metrics.symbols_sent_total, u64::from(result.symbols_distributed));
        let starts = transport.started.lock().unwrap().clone();
        if stalled {
            assert_eq!(starts, ["r0", "r1", "r2"]);
            assert!(result.quorum_achieved); assert_eq!(result.symbols_distributed, 12);
            assert_eq!(result.acks.iter().map(|ack| ack.replica_id.as_str()).collect::<Vec<_>>(), ["r1", "r2"]);
            assert_eq!(result.failures.len(), 1); assert_eq!(result.failures[0].error_kind, ErrorKind::Cancelled);
            assert_eq!(distributor.metrics.acks_received_total, 2);
            for replica in ["r1", "r2"] {
                let symbols = transport.inner.fetch_symbols(replica, key).await.unwrap();
                assert_eq!(symbols.len(), 4);
                for symbol in symbols { assert!(symbol.is_verified()); assert_eq!(symbol.symbol().data(), &[5; 16]); }
            }
        } else {
            assert_eq!(starts, ["r0"]); assert!(!result.quorum_achieved);
            assert!(result.acks.is_empty()); assert_eq!(result.symbols_distributed, 4);
            assert_eq!(result.failures.len(), 3);
            assert_eq!(result.failures[1].error_kind, ErrorKind::QuorumNotReached);
            assert_eq!(result.failures[2].error_kind, ErrorKind::QuorumNotReached);
        }
        assert_eq!(transport.inner.in_flight(), 0);
        result
    });
    let no_leaks = runtime.diagnostics().find_leaked_obligations().is_empty();
    let shutdown = runtime.shutdown_timeout(Duration::from_secs(3));
    let primary_messages = primary.finish();
    let healthy_messages = healthy.finish();
    let backup_messages = backup.finish();
    assert!(no_leaks); assert!(shutdown);
    if stalled {
        assert!(primary_messages.iter().any(|line| line.starts_with("CLOSED r0 ")));
        assert!(healthy_messages.iter().any(|line| line == "DONE r1 1 2 2 0"));
        assert!(backup_messages.iter().any(|line| line == "DONE r2 1 2 2 0"));
        assert!(result.quorum_achieved);
    } else {
        assert!(primary_messages.iter().any(|line| line.starts_with("DONE r0 0 1 ")));
        assert!(healthy_messages.iter().any(|line| line == "DONE r1 0 0 0 0"));
        assert!(backup_messages.iter().any(|line| line == "DONE r2 0 0 0 0"));
    }
}

#[test]
fn hedged_mtls_storage_quorum_closes_stalled_peer_in_separate_process() {
    for workers in [1, 2] { exercise(true, workers); }
}

#[test]
fn impossible_mtls_all_quorum_leaves_backup_processes_uncontacted() {
    exercise(false, 1);
}
