//! Process-restart membership fencing through the actual mTLS service and owned work.
//! Deliberate process termination is not power-loss/filesystem-conformance proof.
#![cfg(all(unix, feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::cx::ChildRegionSpec;
use asupersync::distributed::{HasSchema, SchemaDescriptor};
use asupersync::distributed::membership::{MembershipEvent, MembershipKind};
use asupersync::distributed::membership::authority::{MembershipControllerLimits, MembershipFloor, MembershipLeaseController, MembershipUpdate};
use asupersync::distributed::membership::durable::{MembershipJournal, MembershipJournalConfig,
    PersistentMembershipController, register_persistent_membership_service};
use asupersync::distributed::membership::service::{MEMBERSHIP_SERVICE_COMPUTATION,
    MembershipDeliveryError, register_membership_service, submit_membership_update};
use asupersync::remote::{ComputationName, IdempotencyKey, NodeId, RemoteComputationClient,
    RemoteComputationClientConfig, RemoteComputationRegistry, RemoteComputationService,
    RemoteComputationServiceConfig, RemoteInput, RemoteOutcome, RemotePeerAdmissionPolicy,
    RemotePeerHello, RemoteProtocolVersion, RemoteServiceWireOutcome, RemoteServiceWireRequest,
    RemoteServiceWireResponse, RemoteTaskId, SpawnRequest};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::AuthKey;
use asupersync::tls::{Certificate, CertificateChain, CertificatePin, CertificatePinSet,
    ClientAuth, PrivateKey, RootCertStore, TlsAcceptor, TlsAcceptorBuilder, TlsConnector, TlsConnectorBuilder};
use asupersync::Cx;
use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, mpsc};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const PREFIX: &str = "ASUP_PERSISTENT_MEMBERSHIP_";
const PROBE: &str = "test.persistent-membership.work.v1";
struct ProbeRequest;
struct ProbeResponse;
impl HasSchema for ProbeRequest { fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("test.membership.incarnation.v1") } }
impl HasSchema for ProbeResponse { fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("test.membership.work-result.v1") } }
fn config() -> MembershipJournalConfig {
    MembershipJournalConfig { authority: NodeId::new("authority"), epoch: 7,
        statement_key: AuthKey::from_seed(42), journal_key: AuthKey::from_seed(99),
        floors: vec![MembershipFloor { node: NodeId::new("worker"), incarnation: 0, sequence: 0 }],
        controller_limits: MembershipControllerLimits { max_members: 1, max_lease_ids: 16 }, max_journal_bytes: 65536 }
}
fn statement(incarnation: u64, sequence: u64, kind: MembershipKind) -> Vec<u8> {
    MembershipUpdate { event: MembershipEvent { node: NodeId::new("worker"), incarnation, kind }, sequence }
        .authenticated_bytes(&NodeId::new("authority"), 7, &AuthKey::from_seed(42)).unwrap()
}
fn tls() -> (TlsAcceptor, TlsConnector, CertificatePinSet) {
    let certificate = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap().remove(0);
    let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
    let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
    let mut roots = RootCertStore::empty(); roots.add(&certificate).unwrap();
    let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone()).client_auth(ClientAuth::Required(roots)).build().unwrap();
    let mut pins = CertificatePinSet::new(); pins.add(CertificatePin::compute_spki_sha256(&certificate).unwrap());
    let connector = TlsConnectorBuilder::new().add_root_certificate(&certificate).identity(chain, key)
        .with_certificate_pins(pins.clone()).build().unwrap();
    (acceptor, connector, pins)
}

#[test]
#[ignore = "worker explicitly launched by the two parent acceptance tests"]
fn persistent_member_process() {
    let mode = std::env::var("ASUP_PERSISTENT_MODE").unwrap();
    let file = OpenOptions::new().read(true).write(true).open(std::env::var_os("ASUP_PERSISTENT_PATH").unwrap()).unwrap();
    let journal = if mode == "reopen" { MembershipJournal::open(file, config()) }
        else { MembershipJournal::create(file, config()) }.unwrap();
    let runtime = RuntimeBuilder::current_thread().blocking_threads(0, if mode == "no-pool" { 0 } else { 2 }).build().unwrap();
    let clock = runtime.block_on(async { Cx::current().unwrap().timer_driver().unwrap() });
    let controller = Arc::new(PersistentMembershipController::new(journal, clock).unwrap());
    let mut registry = RemoteComputationRegistry::new();
    register_persistent_membership_service(&mut registry, Arc::clone(&controller)).unwrap();
    let work = Arc::clone(&controller);
    registry.register::<ProbeRequest, ProbeResponse, _, _>(PROBE, move |cx, invocation| {
        let work = Arc::clone(&work);
        async move {
            let input: &[u8] = invocation.request().input.data();
            let Ok(incarnation) = <[u8; 8]>::try_from(input) else {
                return Ok(RemoteOutcome::Failed("invalid probe".into()));
            };
            let result = work.run_scoped(&cx, &NodeId::new("worker"), u64::from_le_bytes(incarnation),
                Duration::from_secs(3), ChildRegionSpec::inherit(), |_child| async { 1u8 }).await;
            Ok(match result {
                Ok(report) if report.is_success() && report.task.as_ref().is_ok_and(|value| *value == 1) => RemoteOutcome::Success(b"ran".to_vec()),
                _ => RemoteOutcome::Failed("membership work refused".into()),
            })
        }
    }).unwrap();
    let (acceptor, _, pins) = tls();
    let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    policy.grant_tls_peer(NodeId::new("authority"), pins, [MEMBERSHIP_SERVICE_COMPUTATION, PROBE]).unwrap();
    let service = runtime.block_on(RemoteComputationService::bind("127.0.0.1:0", acceptor, policy, registry,
        RemoteComputationServiceConfig::new().with_max_connections(Some(4)).with_drain_timeout(Duration::from_secs(5)))).unwrap();
    let operator = service.handle(); let stop = operator.clone();
    println!("{PREFIX}READY {}", service.local_addr().unwrap()); io::stdout().flush().unwrap();
    let input = thread::spawn(move || { let mut byte = [0]; let _ = io::stdin().read(&mut byte); let _ = stop.begin_drain(); });
    let result = runtime.block_on(async {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(60), service.run(&cx)).await
    });
    input.join().unwrap(); result.expect("worker deadline").expect("service drain");
    controller.close();
    assert_eq!(controller.live_leases(), 0); assert!(!controller.update_in_flight());
    assert_eq!(operator.active_connections(), 0);
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    println!("{PREFIX}DONE");
}

struct Process { child: Child, input: Option<ChildStdin>, pump: Option<JoinHandle<()>>,
    messages: mpsc::Receiver<String>, address: SocketAddr, reaped: bool }
impl Process {
    fn start(path: &Path, mode: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "persistent_member_process", "--ignored", "--nocapture", "--test-threads=1"])
            .env("ASUP_PERSISTENT_PATH", path).env("ASUP_PERSISTENT_MODE", mode)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
        let stdout = child.stdout.take().unwrap(); let input = child.stdin.take();
        let (tx, messages) = mpsc::sync_channel(4);
        let mut process = Self { child, input, pump: None, messages, address: "127.0.0.1:0".parse().unwrap(), reaped: false };
        process.pump = Some(thread::spawn(move || {
            for line in io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break; };
                if let Some((_, payload)) = line.split_once(PREFIX) { let _ = tx.try_send(payload.to_owned()); }
            }
        }));
        let ready = process.messages.recv_timeout(Duration::from_secs(10)).expect("worker ready");
        process.address = ready.strip_prefix("READY ").unwrap().parse().unwrap(); process
    }
    fn finish(mut self, crash: bool) {
        if crash { self.child.kill().expect("terminate only the owned post-ack replica"); }
        drop(self.input.take());
        let deadline = Instant::now() + Duration::from_secs(8);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() { break status; }
            assert!(Instant::now() < deadline, "worker required failure-only watchdog cleanup");
            thread::sleep(Duration::from_millis(5));
        };
        self.reaped = true;
        self.pump.take().unwrap().join().unwrap();
        if crash { assert!(!status.success()); }
        else { assert!(status.success()); assert!(self.messages.try_iter().any(|line| line == "DONE")); }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if !self.reaped { drop(self.input.take()); let _ = self.child.kill(); let _ = self.child.wait(); }
        if let Some(pump) = self.pump.take() { let _ = pump.join(); }
    }
}
fn path() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let directory = std::env::temp_dir();
        let path = directory.join(format!("asupersync-persistent-member-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        match OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
            Ok(file) => { file.sync_all().unwrap(); File::open(directory).unwrap().sync_all().unwrap(); return path; }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
            Err(error) => panic!("caller-owned journal: {error}"),
        }
    }
}
fn client(address: SocketAddr) -> (RemoteComputationClient, RemotePeerHello) {
    // Build the hello using the EXISTING backend: matching schemas prove that the
    // persistent registration remains wire-compatible, not a parallel protocol.
    let cfg = config(); let mut registry = RemoteComputationRegistry::new();
    let policy = MembershipLeaseController::new(cfg.authority, cfg.epoch, cfg.statement_key, cfg.floors, cfg.controller_limits).unwrap();
    register_membership_service(&mut registry, Arc::new(Mutex::new(policy))).unwrap();
    registry.register::<ProbeRequest, ProbeResponse, _, _>(PROBE, |_cx, _| async { Ok(RemoteOutcome::Success(Vec::new())) }).unwrap();
    let policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    let (_, connector, _) = tls();
    (RemoteComputationClient::new(address, "localhost", connector, RemoteComputationClientConfig::new()
        .with_max_attempts(1).with_connect_timeout(Duration::from_secs(2)).with_attempt_timeout(Duration::from_secs(5))).unwrap(),
        policy.hello_for(NodeId::new("authority")))
}
async fn probe(cx: &Cx, client: &RemoteComputationClient, hello: &RemotePeerHello, incarnation: u64) -> bool {
    let task = RemoteTaskId::next();
    let request = SpawnRequest { remote_task_id: task, computation: ComputationName::new(PROBE),
        input: RemoteInput::new(incarnation.to_le_bytes().to_vec()), lease: Duration::from_secs(5),
        idempotency_key: IdempotencyKey::from_raw(u128::from(task.raw())), budget: None,
        origin_node: hello.peer_node().clone(), origin_region: cx.region_id(), origin_task: cx.task_id() };
    let wire = RemoteServiceWireRequest::from_spawn_request(hello.clone(), &request).unwrap();
    match client.call(cx, &wire).await.expect("real authenticated probe response") {
        RemoteServiceWireResponse::Outcome { outcome: RemoteServiceWireOutcome::Success(bytes), .. } => { assert_eq!(bytes, b"ran"); true }
        RemoteServiceWireResponse::Outcome { .. } => false,
        other @ RemoteServiceWireResponse::Rejected { .. } => panic!("unexpected probe response: {other:?}"),
    }
}

#[test]
fn acknowledged_death_survives_process_restart_and_fences_real_scoped_work() {
    for workers in [1, 2] {
        let path = path(); let first = Process::start(&path, "create");
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap(); let (client, hello) = client(first.address);
            submit_membership_update(&cx, &client, &hello, &statement(1, 1, MembershipKind::Alive)).await.unwrap();
            assert!(probe(&cx, &client, &hello, 1).await);
            submit_membership_update(&cx, &client, &hello, &statement(1, 2, MembershipKind::Dead)).await.unwrap();
            assert!(!probe(&cx, &client, &hello, 1).await);
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(5))); first.finish(true);
        let before = std::fs::metadata(&path).unwrap().len();
        let restarted = Process::start(&path, "reopen");
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        runtime.block_on(async {
            let cx = Cx::current().unwrap(); let (client, hello) = client(restarted.address);
            assert!(!probe(&cx, &client, &hello, 1).await, "reopen must restore fencing BEFORE serving work");
            for bytes in [statement(1, 1, MembershipKind::Alive), statement(1, 3, MembershipKind::Alive)] {
                assert!(matches!(submit_membership_update(&cx, &client, &hello, &bytes).await, Err(MembershipDeliveryError::Refused)));
            }
            submit_membership_update(&cx, &client, &hello, &statement(1, 2, MembershipKind::Dead)).await.unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().len(), before, "rejected replays and duplicate death never append");
            submit_membership_update(&cx, &client, &hello, &statement(2, 3, MembershipKind::Alive)).await.unwrap();
            assert!(probe(&cx, &client, &hello, 2).await);
            assert!(matches!(submit_membership_update(&cx, &client, &hello, &statement(1, 4, MembershipKind::Dead)).await,
                Err(MembershipDeliveryError::Refused)));
            assert!(probe(&cx, &client, &hello, 2).await, "late old-incarnation death cannot stop rejoined work");
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(5))); restarted.finish(false);
    }
}
#[test]
fn missing_blocking_pool_refuses_authenticated_decision_without_disk_mutation() {
    let path = path(); let process = Process::start(&path, "no-pool");
    let before = std::fs::metadata(&path).unwrap().len();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap(); let (client, hello) = client(process.address);
        assert!(matches!(submit_membership_update(&cx, &client, &hello, &statement(1, 1, MembershipKind::Alive)).await,
            Err(MembershipDeliveryError::Refused)), "must reach the authenticated handler, not fail TCP or TLS");
        assert!(!probe(&cx, &client, &hello, 1).await);
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(5))); process.finish(false);
    assert_eq!(std::fs::metadata(path).unwrap().len(), before);
}
