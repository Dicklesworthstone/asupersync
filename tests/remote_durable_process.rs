//! Durable remote outcomes and in-doubt fences across actual process death.
//! The crash witnesses follow real authenticated calls and synced file writes.
//! Killing a process is not power-loss or filesystem-conformance proof.

#![cfg(all(
    unix,
    feature = "tls",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::Cx;
use asupersync::distributed::{HasSchema, SchemaDescriptor};
use asupersync::remote::durable::{
    DurableRemoteComputation, DurableRemoteError, DurableRemoteJournal, DurableRemoteLimits,
};
use asupersync::remote::{
    ComputationName, IdempotencyKey, NodeId, RemoteComputationClient,
    RemoteComputationClientConfig, RemoteComputationRegistry, RemoteComputationService,
    RemoteComputationServiceConfig, RemoteError, RemoteInput, RemoteOutcome,
    RemotePeerAdmissionPolicy, RemotePeerHello, RemoteProtocolVersion,
    RemoteServiceRejectionCode, RemoteServiceWireOutcome, RemoteServiceWireRequest,
    RemoteServiceWireResponse, RemoteTaskId, SpawnRequest,
};
use asupersync::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
use asupersync::security::AuthKey;
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth, PrivateKey,
    RootCertStore, TlsAcceptor, TlsAcceptorBuilder, TlsConnector, TlsConnectorBuilder,
};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const PREFIX: &str = "ASUP_DURABLE_REMOTE_";
const COMPUTATION: &str = "test.durable-remote.effect.v1";
const PEER: &str = "durable-client";
const INPUT: &[u8] = b"\0persisted effect\xff";
const VERSION: [u8; 32] = [0x51; 32];
const KEY: u128 = 0x125_0000_0000_0001;
const EPOCH_MS: u64 = 1_712_340_000_000;
const RETENTION_MS: u64 = 1_000;
const WINDOW: Duration = Duration::from_secs(60);

struct InputSchema;
struct OutputSchema;

impl HasSchema for InputSchema {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("test.durable-remote.input.v1")
    }
}

impl HasSchema for OutputSchema {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("test.durable-remote.counter-and-input.v1")
    }
}

fn limits() -> DurableRemoteLimits {
    DurableRemoteLimits {
        max_entries: 8,
        max_peer_entries: 4,
        max_input_bytes: 1024,
        max_outcome_bytes: 4096,
        max_retained_bytes: 32_768,
        max_journal_bytes: 1_048_576,
        retention_ms: RETENTION_MS,
    }
}

fn open_journal(path: &Path, create: bool) -> DurableRemoteJournal {
    let file = OpenOptions::new().read(true).write(true).open(path).unwrap();
    if create {
        DurableRemoteJournal::create::<InputSchema, OutputSchema>(
            file, COMPUTATION, VERSION, AuthKey::from_seed(125), limits(),
        )
    } else {
        DurableRemoteJournal::open::<InputSchema, OutputSchema>(
            file, COMPUTATION, VERSION, AuthKey::from_seed(125), limits(),
        )
    }
    .expect("the same caller-owned journal and provisioning must authenticate")
}

fn output(count: u64, input: &[u8]) -> Vec<u8> {
    let mut bytes = b"durable-effect-v1\0".to_vec();
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(input);
    bytes
}

fn runtime(workers: usize) -> Runtime {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    };
    builder.blocking_threads(1, 2).build().unwrap()
}

fn finish_runtime(runtime: Runtime) {
    let report = runtime.shutdown_drained(WINDOW);
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.live_regions, 0);
    assert_eq!(report.pending_obligations, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.queued_finalizers, 0);
    assert!(!report.has_pending_obligation_posts);
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(WINDOW));
}

fn tls() -> (TlsAcceptor, TlsConnector, CertificatePinSet) {
    let certificate = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt"))
        .unwrap().remove(0);
    let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
    let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(&certificate).unwrap();
    let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
        .client_auth(ClientAuth::Required(roots)).build().unwrap();
    let mut pins = CertificatePinSet::new();
    pins.add(CertificatePin::compute_spki_sha256(&certificate).unwrap());
    let connector = TlsConnectorBuilder::new().add_root_certificate(&certificate)
        .identity(chain, key).with_certificate_pins(pins.clone()).build().unwrap();
    (acceptor, connector, pins)
}

fn emit(event: &str) {
    println!("{PREFIX}{event}");
    io::stdout().flush().unwrap();
}

#[test]
#[ignore = "child explicitly launched by the process-restart acceptance tests"]
fn durable_remote_process_worker() {
    let mode = std::env::var("ASUP_DURABLE_MODE").unwrap();
    let workers: usize = std::env::var("ASUP_DURABLE_WORKERS").unwrap().parse().unwrap();
    let journal_path = PathBuf::from(std::env::var_os("ASUP_DURABLE_JOURNAL").unwrap());
    let counter_path = PathBuf::from(std::env::var_os("ASUP_DURABLE_COUNTER").unwrap());
    let terminal_crash = mode == "terminal-crash";
    let effect_crash = mode == "effect-crash";
    let reconcile = mode == "reconcile";
    assert!(terminal_crash || effect_crash || reconcile || mode == "replay" || mode == "after-retention");
    // This fixture supplies a trusted epoch explicitly. Restart never resets
    // it to the new runtime's relative clock; advancing it requires no sleep.
    let now_ms = if mode == "after-retention" || reconcile {
        EPOCH_MS + RETENTION_MS + 1
    } else {
        EPOCH_MS
    };
    let owner = Arc::new(DurableRemoteComputation::new(
        open_journal(&journal_path, terminal_crash || effect_crash), move || now_ms,
    ));
    let runtime = runtime(workers);
    let mut registry = RemoteComputationRegistry::new();
    let registered = Arc::clone(&owner);
    registry.register::<InputSchema, OutputSchema, _, _>(COMPUTATION, move |cx, invocation| {
        let owner = Arc::clone(&registered);
        let counter_path = counter_path.clone();
        async move {
            assert_eq!(invocation.peer_node(), &NodeId::new(PEER));
            assert_eq!(invocation.request().idempotency_key, IdempotencyKey::from_raw(KEY));
            assert_eq!(invocation.request().input.data(), INPUT);
            if reconcile {
                // The parent killed and reaped the original process before
                // enabling this explicit recovery mode. No old writer remains.
                // The private counter is authoritative for this fixture's one
                // effect; uncertainty is never turned into another execution.
                return owner.reconcile(&cx, invocation, move |lookup_cx, invocation| async move {
                    let input = invocation.request().input.data().to_vec();
                    let mut lookup = lookup_cx.spawn_blocking_drained(move |worker| {
                        worker.checkpoint().map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "lookup cancelled"))?;
                        let mut file = OpenOptions::new().read(true).open(counter_path)?;
                        if file.metadata()?.len() != 1 { return Ok::<_, io::Error>(None); }
                        let mut value = [0];
                        file.read_exact(&mut value)?;
                        Ok((value == [1]).then_some(1))
                    }).ok()?;
                    let count = match lookup.join().await {
                        Ok(Ok(Some(count))) => count,
                        _ => return None,
                    };
                    emit("RECONCILIATION_LOOKUP");
                    Some(RemoteOutcome::Success(output(count, &input)))
                }).await.map_err(|error| RemoteError::TransportError(error.to_string()));
            }
            let outcome = owner.call(&cx, invocation, move |handler_cx, invocation| async move {
                let input = invocation.request().input.data().to_vec();
                let mut effect = handler_cx.spawn_blocking_drained(move |worker| {
                    worker.checkpoint().expect("effect worker admitted before crash");
                    let mut file = OpenOptions::new().read(true).append(true).open(counter_path)?;
                    let count = file.metadata()?.len().checked_add(1)
                        .ok_or_else(|| io::Error::other("counter overflow"))?;
                    file.write_all(&[1])?;
                    file.sync_all()?;
                    Ok::<_, io::Error>(count)
                }).unwrap();
                let count = effect.join().await.expect("effect worker retirement")
                    .expect("caller-owned side effect append and sync");
                emit("EFFECT");
                if effect_crash {
                    // The public application future has not returned, so no
                    // terminal append can begin before the parent kills us.
                    std::future::pending::<()>().await;
                }
                RemoteOutcome::Success(output(count, &input))
            }).await.map_err(|error| RemoteError::TransportError(error.to_string()))?;
            if terminal_crash {
                // The public adapter has returned its durable outcome, but
                // this registered wrapper has not returned it to the wire.
                emit("DURABLE");
                std::future::pending::<()>().await;
            }
            Ok(outcome)
        }
    }).unwrap();
    let (acceptor, _, pins) = tls();
    // V1 makes every authenticated retry reach this adapter. The framework's
    // V2/V3 in-memory terminal cache cannot satisfy the acceptance test.
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V1, registry.schema_registry().clone(),
    );
    policy.grant_tls_peer(NodeId::new(PEER), pins, [COMPUTATION]).unwrap();
    let service = runtime.block_on(RemoteComputationService::bind(
        "127.0.0.1:0", acceptor, policy, registry,
        RemoteComputationServiceConfig::new().with_max_connections(Some(4))
            .with_initial_frame_timeout(WINDOW).with_drain_timeout(WINDOW),
    )).unwrap();
    let operator = service.handle();
    let stop = operator.clone();
    emit(&format!("READY {}", service.local_addr().unwrap()));
    let input = thread::spawn(move || {
        let mut byte = [0];
        let _ = io::stdin().read(&mut byte);
        let _ = stop.begin_drain();
    });
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), WINDOW * 4, service.run(&cx)).await
    }).expect("child service watchdog").expect("child service drain");
    input.join().unwrap();
    assert!(!owner.in_flight());
    assert_eq!(operator.active_connections(), 0);
    drop(owner);
    finish_runtime(runtime);
    emit("DONE");
}

struct Files {
    journal: PathBuf,
    counter: PathBuf,
}

impl Files {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let parent = std::env::temp_dir();
            let directory = parent.join(format!(
                "asupersync-durable-remote-{}-{}", std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match std::fs::create_dir(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("caller-owned fixture directory: {error}"),
            }
            let files = Self {
                journal: directory.join("journal"), counter: directory.join("effects"),
            };
            for path in [&files.journal, &files.counter] {
                OpenOptions::new().read(true).write(true).create_new(true)
                    .open(path).unwrap().sync_all().unwrap();
            }
            File::open(directory).unwrap().sync_all().unwrap();
            File::open(parent).unwrap().sync_all().unwrap();
            return files;
        }
    }

    fn assert_one_effect(&self) {
        assert_eq!(std::fs::read(&self.counter).unwrap(), [1],
            "restart or retry must not perform the side effect again");
    }
}

fn client(address: SocketAddr) -> (RemoteComputationClient, RemotePeerHello) {
    let mut registry = RemoteComputationRegistry::new();
    registry.register::<InputSchema, OutputSchema, _, _>(COMPUTATION, |_cx, _| async {
        Ok(RemoteOutcome::Success(Vec::new()))
    }).unwrap();
    let policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V1, registry.schema_registry().clone(),
    );
    let (_, connector, _) = tls();
    let client = RemoteComputationClient::new(
        address, "localhost", connector,
        RemoteComputationClientConfig::new().with_max_attempts(1)
            .with_connect_timeout(WINDOW).with_attempt_timeout(WINDOW),
    ).unwrap();
    (client, policy.hello_for(NodeId::new(PEER)))
}

type WireResult = Result<RemoteServiceWireResponse, String>;

struct ClientCall {
    result: mpsc::Receiver<WireResult>,
    thread: Option<JoinHandle<()>>,
}

struct Process {
    child: Child,
    input: Option<ChildStdin>,
    pump: Option<JoinHandle<()>>,
    messages: mpsc::Receiver<String>,
    events: Vec<String>,
    address: SocketAddr,
    reaped: bool,
    call: Option<ClientCall>,
}

impl Process {
    fn start(files: &Files, mode: &str, workers: usize) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "durable_remote_process_worker", "--ignored", "--nocapture", "--test-threads=1"])
            .env("ASUP_DURABLE_JOURNAL", &files.journal)
            .env("ASUP_DURABLE_COUNTER", &files.counter)
            .env("ASUP_DURABLE_MODE", mode)
            .env("ASUP_DURABLE_WORKERS", workers.to_string())
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
            .spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let input = child.stdin.take();
        let (sender, messages) = mpsc::sync_channel(16);
        let mut process = Self {
            child, input, pump: None, messages, events: Vec::new(),
            address: "127.0.0.1:0".parse().unwrap(), reaped: false, call: None,
        };
        process.pump = Some(thread::spawn(move || {
            for line in io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break; };
                if let Some((_, event)) = line.split_once(PREFIX) {
                    let _ = sender.try_send(event.to_owned());
                }
            }
        }));
        let ready = process.messages.recv_timeout(WINDOW).expect("child service readiness");
        process.address = ready.strip_prefix("READY ").expect("child readiness address")
            .parse().unwrap();
        process.events.push(ready);
        process
    }

    fn begin_call(&mut self, workers: usize) -> RemoteTaskId {
        assert!(self.call.is_none());
        let task = RemoteTaskId::next();
        let address = self.address;
        let (sender, result) = mpsc::sync_channel(1);
        let thread = thread::spawn(move || {
            let runtime = runtime(workers);
            let response = runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (client, hello) = client(address);
                let request = SpawnRequest {
                    remote_task_id: task, computation: ComputationName::new(COMPUTATION),
                    input: RemoteInput::new(INPUT.to_vec()), lease: WINDOW * 2,
                    idempotency_key: IdempotencyKey::from_raw(KEY), budget: None,
                    origin_node: hello.peer_node().clone(), origin_region: cx.region_id(),
                    origin_task: cx.task_id(),
                };
                let wire = RemoteServiceWireRequest::from_spawn_request(hello, &request).unwrap();
                client.call(&cx, &wire).await.map_err(|error| error.to_string())
            });
            let _ = sender.send(response);
            finish_runtime(runtime);
        });
        self.call = Some(ClientCall { result, thread: Some(thread) });
        task
    }

    fn wait_for(&mut self, expected: &str) {
        let deadline = Instant::now() + WINDOW;
        loop {
            let remaining = deadline.checked_duration_since(Instant::now())
                .expect("child did not reach the authenticated crash window");
            let event = self.messages.recv_timeout(remaining)
                .expect("child must reach the authenticated crash window");
            let matched = event == expected;
            assert_ne!(event, "DONE", "child completed before the crash witness");
            self.events.push(event);
            if matched { return; }
        }
    }

    fn assert_call_pending(&self) {
        assert!(matches!(self.call.as_ref().unwrap().result.try_recv(),
            Err(mpsc::TryRecvError::Empty)), "no response may escape before the crash");
    }

    fn finish_call(&mut self) -> WireResult {
        let call = self.call.as_mut().unwrap();
        let response = call.result.recv_timeout(WINDOW).expect("bounded native client response");
        call.thread.take().unwrap().join().expect("owned native client thread");
        self.call = None;
        response
    }

    fn reap(&mut self, crashed: bool) {
        let deadline = Instant::now() + WINDOW;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() { break status; }
            let remaining = deadline.checked_duration_since(Instant::now())
                .expect("owned child failed to exit within its watchdog");
            // This only waits for process exit. Functional crash witnesses
            // above come from the application, never from an elapsed delay.
            match self.messages.recv_timeout(remaining.min(Duration::from_millis(20))) {
                Ok(event) => self.events.push(event),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => thread::yield_now(),
            }
        };
        self.reaped = true;
        self.pump.take().unwrap().join().expect("owned child stdout pump");
        self.events.extend(self.messages.try_iter());
        if crashed {
            assert_eq!(status.signal(), Some(9), "the owned child must actually receive SIGKILL");
        } else {
            assert!(status.success(), "restarted child failed: {status}");
            assert!(self.events.iter().any(|event| event == "DONE"));
        }
    }

    fn crash(&mut self) {
        self.child.kill().expect("kill only the child owned by this fixture");
        drop(self.input.take());
        self.reap(true);
    }

    fn finish(mut self) {
        assert!(self.call.is_none(), "join the owned client before service shutdown");
        drop(self.input.take());
        self.reap(false);
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // On assertion failure, stop the server first so its outstanding
        // native client cannot remain parked waiting for a response.
        if !self.reaped {
            drop(self.input.take());
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(mut call) = self.call.take()
            && let Some(thread) = call.thread.take()
        {
            let _ = thread.join();
        }
        if let Some(pump) = self.pump.take() { let _ = pump.join(); }
    }
}

#[test]
fn durable_terminal_replays_after_process_death_before_wire_response() {
    for workers in [1, 2] {
        let files = Files::new();
        let original = std::fs::metadata(&files.journal).unwrap();
        let mut first = Process::start(&files, "terminal-crash", workers);
        let original_task = first.begin_call(workers);
        first.wait_for("DURABLE");
        assert_eq!(first.events.iter().filter(|event| *event == "EFFECT").count(), 1);
        first.assert_call_pending();
        first.crash();
        assert!(first.finish_call().is_err(), "the killed process must not supply a wire outcome");
        files.assert_one_effect();
        assert_eq!(open_journal(&files.journal, false).records(), 2,
            "reservation and exact terminal must both survive the actual crash");
        let before_retry = std::fs::metadata(&files.journal).unwrap().len();

        let mut restarted = Process::start(&files, "replay", workers);
        let retry_task = restarted.begin_call(workers);
        assert_ne!(retry_task, original_task, "transport task identity must not determine replay");
        let response = restarted.finish_call().expect("authenticated replay response");
        assert_eq!(response, RemoteServiceWireResponse::Outcome {
            remote_task_id: retry_task.raw(),
            outcome: RemoteServiceWireOutcome::Success(output(1, INPUT)),
        });
        restarted.finish();
        files.assert_one_effect();
        let after = std::fs::metadata(&files.journal).unwrap();
        assert_eq!(after.len(), before_retry, "exact replay must not append another decision");
        assert_eq!((after.dev(), after.ino()), (original.dev(), original.ino()));
        assert_eq!(open_journal(&files.journal, false).records(), 2);
    }
}

#[test]
fn unresolved_effect_stays_in_doubt_after_process_restart_and_retention() {
    for workers in [1, 2] {
        let files = Files::new();
        let original = std::fs::metadata(&files.journal).unwrap();
        let mut first = Process::start(&files, "effect-crash", workers);
        let original_task = first.begin_call(workers);
        first.wait_for("EFFECT");
        first.assert_call_pending();
        first.crash();
        assert!(first.finish_call().is_err(), "the killed handler must not supply a wire outcome");
        files.assert_one_effect();
        assert_eq!(open_journal(&files.journal, false).records(), 1,
            "only the reservation preceded this completed side effect");
        let before_retry = std::fs::metadata(&files.journal).unwrap().len();

        let mut restarted = Process::start(&files, "after-retention", workers);
        let retry_task = restarted.begin_call(workers);
        assert_ne!(retry_task, original_task);
        let response = restarted.finish_call().expect("authenticated in-doubt refusal response");
        match response {
            RemoteServiceWireResponse::Rejected { remote_task_id, code, diagnostic } => {
                assert_eq!(remote_task_id, retry_task.raw());
                assert_eq!(code, RemoteServiceRejectionCode::ExecutionFailed);
                assert!(diagnostic.contains(&DurableRemoteError::InDoubt.to_string()),
                    "the durable owner must refuse uncertainty, not fail TLS/admission: {diagnostic}");
            }
            other @ RemoteServiceWireResponse::Outcome { .. } => {
                panic!("uncertain execution must not become a replay or a new result: {other:?}")
            }
        }
        restarted.finish();
        files.assert_one_effect();
        let after = std::fs::metadata(&files.journal).unwrap();
        assert_eq!(after.len(), before_retry, "pending retention must never admit another effect");
        assert_eq!((after.dev(), after.ino()), (original.dev(), original.ino()));
        assert_eq!(open_journal(&files.journal, false).records(), 1);
    }
}

#[test]
fn application_reconciliation_after_process_death_persists_known_effect_without_reexecution() {
    for workers in [1, 2] {
        let files = Files::new();
        let original = std::fs::metadata(&files.journal).unwrap();
        let mut first = Process::start(&files, "effect-crash", workers);
        first.begin_call(workers);
        first.wait_for("EFFECT");
        first.assert_call_pending();
        first.crash();
        assert!(first.finish_call().is_err());
        files.assert_one_effect();
        assert_eq!(open_journal(&files.journal, false).records(), 1);
        let pending_bytes = std::fs::metadata(&files.journal).unwrap().len();

        let mut ordinary = Process::start(&files, "after-retention", workers);
        let refused_task = ordinary.begin_call(workers);
        match ordinary.finish_call().unwrap() {
            RemoteServiceWireResponse::Rejected { remote_task_id, code, diagnostic } => {
                assert_eq!(remote_task_id, refused_task.raw());
                assert_eq!(code, RemoteServiceRejectionCode::ExecutionFailed);
                assert!(diagnostic.contains(&DurableRemoteError::InDoubt.to_string()));
            }
            other @ RemoteServiceWireResponse::Outcome { .. } => panic!("ordinary retry must remain fenced: {other:?}"),
        }
        ordinary.finish();
        assert_eq!(std::fs::metadata(&files.journal).unwrap().len(), pending_bytes);

        // Explicit operator recovery, after the original owner was killed and
        // reaped, reads the existing effect instead of appending another one.
        let mut recovery = Process::start(&files, "reconcile", workers);
        let recovery_task = recovery.begin_call(workers);
        recovery.wait_for("RECONCILIATION_LOOKUP");
        assert_eq!(recovery.finish_call().unwrap(), RemoteServiceWireResponse::Outcome {
            remote_task_id: recovery_task.raw(),
            outcome: RemoteServiceWireOutcome::Success(output(1, INPUT)),
        });
        recovery.finish();
        files.assert_one_effect();
        assert_eq!(open_journal(&files.journal, false).records(), 2);
        let terminal_bytes = std::fs::metadata(&files.journal).unwrap().len();
        assert!(terminal_bytes > pending_bytes);

        let mut replay = Process::start(&files, "after-retention", workers);
        let replay_task = replay.begin_call(workers);
        assert_eq!(replay.finish_call().unwrap(), RemoteServiceWireResponse::Outcome {
            remote_task_id: replay_task.raw(),
            outcome: RemoteServiceWireOutcome::Success(output(1, INPUT)),
        });
        replay.finish();
        files.assert_one_effect();
        let after = std::fs::metadata(&files.journal).unwrap();
        assert_eq!(after.len(), terminal_bytes);
        assert_eq!((after.dev(), after.ino()), (original.dev(), original.ino()));
        assert_eq!(open_journal(&files.journal, false).records(), 2);
    }
}
