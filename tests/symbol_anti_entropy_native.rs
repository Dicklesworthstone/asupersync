//! br-asupersync-dist-otp-completeness-8y37kz.6: real V3 catalog and V1 symbol
//! services, bounded resumable repair, authenticated namespaces and native drain.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]
#![recursion_limit = "256"]

use asupersync::distributed::{HasSchema, SchemaDescriptor};
use asupersync::distributed::anti_entropy::catalog::{Catalog, CatalogEntry, CatalogError, CatalogLimits};
use asupersync::distributed::anti_entropy::native::{SymbolRepairClient, SymbolRepairError,
    SymbolRepairLimits, SymbolRepairRequest, SymbolRepairRoundError, SymbolRepairRoundTrigger,
    SymbolRepairWorker, SymbolRepairWorkerConfig, SymbolRepairWorkerError, SymbolRepairWorkerStatus};
use asupersync::distributed::anti_entropy::symbols::{SYMBOL_CATALOG_COMPUTATION, SymbolCatalogService,
    capture_symbol_catalog, register_symbol_catalog_service};
use asupersync::distributed::symbol_service::{EncodedSymbolBatch, RemoteSymbolTransport,
    SYMBOL_SERVICE_COMPUTATION, SymbolBatchLimits, SymbolReplicaStore, SymbolStoreLimits,
    encode_symbol_batch, register_symbol_service};
use asupersync::remote::{NativeRemoteRoute, NativeRemoteRuntime, NativeRemoteRuntimeConfig,
    NodeId, RemoteCap, RemoteComputationClient, RemoteComputationClientConfig,
    RemoteComputationRegistry, RemoteComputationService, RemoteComputationServiceConfig,
    RemoteComputationServiceHandle, RemoteError, RemoteOutcome, RemotePeerAdmissionPolicy,
    RemoteProtocolVersion, RemoteRuntime, RemoteServiceWireLimits};
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder};
use asupersync::security::{AuthKey, SecurityContext};
use asupersync::sync::Notify;
use asupersync::tls::{Certificate, CertificateChain, CertificatePin, CertificatePinSet,
    ClientAuth, PrivateKey, RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder};
use asupersync::types::{Budget, CancelReason, Outcome, Time, symbol::Symbol};
use asupersync::Cx;
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

const CERT: &[u8] = include_bytes!("fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("fixtures/tls/server.key");
const PEER_CERT: &[u8] = include_bytes!("fixtures/tls/admission_peer.crt");
const PEER_KEY: &[u8] = include_bytes!("fixtures/tls/admission_peer.key");

fn batch_limits() -> SymbolBatchLimits {
    SymbolBatchLimits { max_encoded_bytes: 4096, max_symbols: 8,
        max_payload_bytes: 2048, max_decoded_bytes: 8192 }
}
fn catalog_limits() -> CatalogLimits {
    CatalogLimits { depth: 3, max_entries: 16, max_key_bytes: 16, max_total_key_bytes: 256,
        max_page_entries: 8, max_retained_bytes: 16_384, max_response_bytes: 4096 }
}
fn repair_limits() -> SymbolRepairLimits {
    SymbolRepairLimits { catalog: catalog_limits(), max_catalog_requests_per_step: 2,
        max_repairs_per_step: 1, max_bytes_per_step: 4096, max_total_repair_bytes: 32_768,
        max_batch_bytes: 4096, request_timeout: Duration::from_secs(5) }
}
fn store(replica: &str) -> Arc<SymbolReplicaStore> {
    Arc::new(SymbolReplicaStore::new(replica, AuthKey::from_seed(42), batch_limits(),
        SymbolStoreLimits { max_batches: 16, max_bytes: 65_536,
            max_batches_per_peer: 16, max_bytes_per_peer: 65_536 }).unwrap())
}
fn batch(object: u64) -> EncodedSymbolBatch {
    let security = SecurityContext::new(AuthKey::from_seed(42));
    let symbols = (0..2).map(|esi| security.sign_symbol(
        &Symbol::new_for_test(object, 0, esi, &[object as u8; 128]))).collect::<Vec<_>>();
    encode_symbol_batch(&symbols, batch_limits()).unwrap()
}

#[derive(Default)]
struct Gate {
    armed: AtomicBool, entered: AtomicBool, released: AtomicBool,
    retired: AtomicBool, calls: AtomicUsize, changed: Notify,
    allow_release: AtomicBool, failures_remaining: AtomicUsize,
}
impl Gate {
    async fn entered(&self) { self.changed.wait_until(|| self.entered.load(Ordering::Acquire)).await; }
    fn release(&self) { self.released.store(true, Ordering::Release); self.changed.notify_waiters(); }
}
struct Retired(Arc<Gate>);
impl Drop for Retired {
    fn drop(&mut self) {
        self.0.retired.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }
}

// The outer handler adds only a controllable native wait. After real mTLS
// admission it delegates to the production catalog registry, preserving the
// outer invocation's exact admitted peer. These local sessions are never served
// on a socket; they cannot authenticate a network caller by themselves.
struct RequestSchema;
struct ResponseSchema;
struct SymbolRequestSchema;
struct SymbolResponseSchema;
impl HasSchema for RequestSchema {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("asupersync.symbol-catalog.request.canonical-binary.v1") }
}
impl HasSchema for ResponseSchema {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("asupersync.symbol-catalog.response.canonical-binary.v1") }
}
impl HasSchema for SymbolRequestSchema {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("asupersync.symbol-service.request.canonical-binary.v1") }
}
impl HasSchema for SymbolResponseSchema {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("asupersync.symbol-service.response.canonical-binary.v1") }
}
fn gated_registry<I: HasSchema, O: HasSchema>(inner: RemoteComputationRegistry,
    computation: &'static str, protocol: RemoteProtocolVersion, gate: Arc<Gate>, await_cancel: bool)
    -> RemoteComputationRegistry
{
    let mut policy = RemotePeerAdmissionPolicy::new(protocol, inner.schema_registry().clone());
    let mut sessions = BTreeMap::new();
    for name in ["origin", "repair-peer"] {
        let peer = NodeId::new(name);
        policy.grant_peer(peer.clone(), [computation]).unwrap();
        sessions.insert(peer.clone(), policy.admit(&policy.hello_for(peer)).unwrap());
    }
    let schema = inner.schema_registry().fingerprint();
    let mut outer = RemoteComputationRegistry::new();
    outer.register::<I, O, _, _>(computation,
        move |cx, invocation| {
            let inner = inner.clone();
            let session = sessions.get(invocation.peer_node()).cloned();
            let gate = Arc::clone(&gate);
            async move {
                let session = session.ok_or_else(|| RemoteError::TransportError("unknown fixture peer".into()))?;
                gate.calls.fetch_add(1, Ordering::AcqRel);
                if gate.failures_remaining.fetch_update(Ordering::AcqRel, Ordering::Acquire,
                    |remaining| remaining.checked_sub(1)).is_ok()
                {
                    return Ok(RemoteOutcome::Failed("transient fixture read failure".into()));
                }
                let mut retirement = None;
                if gate.armed.swap(false, Ordering::AcqRel) {
                    retirement = Some(Retired(Arc::clone(&gate)));
                    let mut release = std::pin::pin!(gate.changed.wait_until(|| gate.released.load(Ordering::Acquire)));
                    let mut cancelled = std::pin::pin!(cx.cancelled());
                    poll_fn(|task| {
                        if cancelled.as_mut().poll(task).is_ready() { return Poll::Ready(()); }
                        if (!await_cancel || gate.allow_release.load(Ordering::Acquire))
                            && release.as_mut().poll(task).is_ready() { return Poll::Ready(()); }
                        // Signal only after the admitted handler's real wait
                        // registered its waker and returned Pending.
                        if !gate.entered.swap(true, Ordering::AcqRel) { gate.changed.notify_waiters(); }
                        Poll::Pending
                    }).await;
                    if cx.is_cancel_requested() {
                        let _ = cx.checkpoint();
                        return Ok(RemoteOutcome::Cancelled(cx.cancel_reason().unwrap_or_else(CancelReason::parent_cancelled)));
                    }
                }
                let result = inner.dispatch(&cx, &session, invocation.request().clone()).await
                    .map_err(|_| RemoteError::TransportError("production storage dispatch refused".into()));
                drop(retirement);
                result
            }
        }).unwrap();
    assert_eq!(outer.schema_registry().fingerprint(), schema);
    outer
}

#[derive(Default)]
struct Stop {
    services: Vec<RemoteComputationServiceHandle>, remotes: Vec<Arc<NativeRemoteRuntime>>,
    gates: Vec<Arc<Gate>>,
}
impl Drop for Stop {
    fn drop(&mut self) {
        for gate in &self.gates { gate.release(); }
        for remote in &self.remotes { let _ = remote.begin_drain(); }
        for service in &self.services { let _ = service.begin_drain(); }
    }
}

#[derive(Clone, Copy)]
enum Case {
    RepairAndRefusals, CancelAndResume, WorkerManual, WorkerPeriodic,
    WorkerStopDeadline, WorkerCancelMetadata, WorkerCancelData, WorkerRetries,
    WorkerStepLimit, WorkerClockExhausted,
}

fn exercise(workers: usize, case: Case) {
    let builder = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers) };
    let runtime = builder
        .thread_stack_size(FIXTURE_STACK_BYTES)
        .build()
        .unwrap();
    let handle = runtime.handle();
    runtime.block_on(async {
        let base = Cx::current().unwrap();
        asupersync::time::timeout(base.now(), Duration::from_secs(60), async {
            let mut stop = Stop::default();
            let origin = NodeId::new("origin");
            let source = store("source");
            let destination = store("destination");
            let batches = (1..=3).map(batch).collect::<Vec<_>>();
            for batch in &batches { source.put(&origin, batch.as_ref()).unwrap(); }
            let secret = batch(99);
            source.put(&NodeId::new("unrelated-origin"), secret.as_ref()).unwrap();
            destination.put(&origin, batches[0].as_ref()).unwrap();
            let catalogs = Arc::new(SymbolCatalogService::new("source", 2, 32_768).unwrap());
            catalogs.publish(Arc::new(capture_symbol_catalog(&source, origin.clone(), 1, catalog_limits()).unwrap())).unwrap();
            let gate = Arc::new(Gate::default());
            let data_gate = Arc::new(Gate::default());
            stop.gates.extend([Arc::clone(&gate), Arc::clone(&data_gate)]);
            let mut meta_registry = RemoteComputationRegistry::new();
            register_symbol_catalog_service(&mut meta_registry, Arc::clone(&catalogs)).unwrap();
            let meta_registry = gated_registry::<RequestSchema, ResponseSchema>(meta_registry,
                SYMBOL_CATALOG_COMPUTATION, RemoteProtocolVersion::V3, Arc::clone(&gate), true);
            let mut data_registry = RemoteComputationRegistry::new();
            register_symbol_service(&mut data_registry, Arc::clone(&source)).unwrap();
            let data_registry = gated_registry::<SymbolRequestSchema, SymbolResponseSchema>(data_registry,
                SYMBOL_SERVICE_COMPUTATION, RemoteProtocolVersion::V1, Arc::clone(&data_gate), false);

            let certificate = Certificate::from_pem(CERT).unwrap().remove(0);
            let chain = CertificateChain::from_pem(CERT).unwrap();
            let key = PrivateKey::from_pem(KEY).unwrap();
            let peer_certificate = Certificate::from_pem(PEER_CERT).unwrap().remove(0);
            let mut roots = RootCertStore::empty();
            roots.add(&certificate).unwrap();
            roots.add(&peer_certificate).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
                .client_auth(ClientAuth::Required(roots)).build().unwrap();
            let mut pins = CertificatePinSet::new();
            pins.add(CertificatePin::compute_spki_sha256(&certificate).unwrap());
            let connector = TlsConnectorBuilder::new().add_root_certificate(&certificate)
                .identity(chain, key).with_certificate_pins(pins.clone()).build().unwrap();
            let mut peer_pins = CertificatePinSet::new();
            peer_pins.add(CertificatePin::compute_spki_sha256(&peer_certificate).unwrap());
            assert_ne!(CertificatePin::compute_spki_sha256(&certificate).unwrap(),
                CertificatePin::compute_spki_sha256(&peer_certificate).unwrap());
            let peer_connector = TlsConnectorBuilder::new().add_root_certificate(&certificate)
                .identity(CertificateChain::from_pem(PEER_CERT).unwrap(), PrivateKey::from_pem(PEER_KEY).unwrap())
                .with_certificate_pins(pins.clone()).build().unwrap();
            let mut meta_policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V3, meta_registry.schema_registry().clone());
            let mut data_policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, data_registry.schema_registry().clone());
            for (name, identity) in [("origin", pins), ("repair-peer", peer_pins)] {
                meta_policy.grant_tls_peer(NodeId::new(name), identity.clone(), [SYMBOL_CATALOG_COMPUTATION]).unwrap();
                data_policy.grant_tls_peer(NodeId::new(name), identity, [SYMBOL_SERVICE_COMPUTATION]).unwrap();
            }
            let meta_hello = meta_policy.hello_for(origin.clone());
            let intruder_meta = meta_policy.hello_for(NodeId::new("repair-peer"));
            let data_hello = data_policy.hello_for(origin.clone());
            let intruder_data = data_policy.hello_for(NodeId::new("repair-peer"));
            let wire = RemoteServiceWireLimits::new(16_384);
            let server_config = RemoteComputationServiceConfig::new().with_max_connections(Some(4))
                .with_wire_limits(wire).with_drain_timeout(Duration::from_secs(3));
            let meta = RemoteComputationService::bind("127.0.0.1:0", acceptor.clone(), meta_policy,
                meta_registry, server_config).await.unwrap();
            let meta_addr = meta.local_addr().unwrap();
            stop.services.push(meta.handle());
            let mut meta_task = base.spawn(move |cx| async move { meta.run(&cx).await }).unwrap();
            let data = RemoteComputationService::bind("127.0.0.1:0", acceptor, data_policy,
                data_registry, server_config).await.unwrap();
            let data_addr = data.local_addr().unwrap();
            stop.services.push(data.handle());
            let mut data_task = base.spawn(move |cx| async move { data.run(&cx).await }).unwrap();
            let client_config = RemoteComputationClientConfig::new().with_max_attempts(1)
                .with_wire_limits(wire).with_connect_timeout(Duration::from_secs(3))
                .with_attempt_timeout(Duration::from_secs(5));
            let meta_client = RemoteComputationClient::new(meta_addr, "localhost", connector.clone(), client_config).unwrap();
            let data_client = RemoteComputationClient::new(data_addr, "localhost", connector, client_config).unwrap();
            let intruder_meta_client = RemoteComputationClient::new(meta_addr, "localhost", peer_connector.clone(), client_config).unwrap();
            let intruder_data_client = RemoteComputationClient::new(data_addr, "localhost", peer_connector, client_config).unwrap();
            let remote_config = NativeRemoteRuntimeConfig::new().with_max_in_flight(2)
                .with_drain_timeout(Duration::from_secs(3));
            let remote = Arc::new(NativeRemoteRuntime::with_config(handle.clone(), origin.clone(),
                [NativeRemoteRoute::new(NodeId::new("source"), meta_hello, meta_client.clone())], remote_config).unwrap());
            stop.remotes.push(Arc::clone(&remote));
            let cx = base.clone().with_remote_cap(RemoteCap::new().with_local_node(origin.clone())
                .with_runtime(Arc::clone(&remote) as Arc<dyn RemoteRuntime>));
            let symbols = RemoteSymbolTransport::new_bounded(cx.clone(), data_hello.clone(),
                [("source".to_owned(), data_client.clone())], Arc::new(AuthKey::from_seed(42)), batch_limits(), 1).unwrap();
            let repair = SymbolRepairClient::new(origin.clone(), NodeId::new("source"), Arc::clone(&destination), repair_limits()).unwrap();
            if !matches!(case, Case::RepairAndRefusals | Case::CancelAndResume) {
                exercise_worker(WorkerFixture {
                    cx: &cx, repair: &repair, symbols: &symbols, origin: &origin,
                    source: &source, destination: &destination, catalogs: &catalogs,
                    metadata: &gate, values: &data_gate, remote: &remote,
                }, case).await;
                for batch in &batches {
                    assert_eq!(destination.get(&origin, batch.key()).unwrap().as_ref().as_ref(), batch.as_ref());
                }
                assert!(destination.get(&origin, secret.key()).is_err());
                assert!(destination.get(&NodeId::new("unrelated-origin"), secret.key()).is_err());
            } else {
            let mut cursor = repair.start(&cx).await.unwrap();
            assert!(!cursor.progress().complete);

            if matches!(case, Case::CancelAndResume) {
                let before = cursor.progress();
                gate.armed.store(true, Ordering::Release);
                let task_repair = repair.clone();
                let task_symbols = symbols.clone();
                let mut waiting = cx.spawn(move |body| async move {
                    let mut cursor = cursor;
                    let result = task_repair.step(&body, &task_symbols, &mut cursor).await;
                    (cursor, result)
                }).unwrap();
                gate.entered().await;
                assert_eq!(remote.active_operations(), 1);
                waiting.abort_with_reason(CancelReason::user("cancel admitted catalog repair step"));
                let (returned, result) = waiting.join(&cx).await.expect("typed cancellation must survive actual task completion");
                assert!(matches!(result, Err(SymbolRepairError::Cancelled)));
                cursor = returned;
                assert_eq!(cursor.progress(), before);
                assert_eq!(remote.active_operations(), 0);
                assert_eq!(destination.stats().batches, 1);

                // The symbol transport still belongs to this healthy parent.
                // Cancelling a different repair task must retire its live GET,
                // release the shared transport credit and preserve its cursor.
                data_gate.armed.store(true, Ordering::Release);
                let mut cancelled_data = false;
                for _ in 0..32 {
                    let task_repair = repair.clone();
                    let task_symbols = symbols.clone();
                    let mut waiting = cx.spawn(move |body| async move {
                        let mut cursor = cursor;
                        let result = task_repair.step(&body, &task_symbols, &mut cursor).await;
                        (cursor, result)
                    }).unwrap();
                    let mut entered = std::pin::pin!(data_gate.entered());
                    let finished = poll_fn(|task| {
                        if entered.as_mut().poll(task).is_ready() { return Poll::Ready(None); }
                        waiting.poll_join(task).map(Some)
                    }).await;
                    if let Some(finished) = finished {
                        let (returned, result) = finished.unwrap();
                        cursor = returned;
                        assert!(!result.unwrap().complete, "real GET must be reached before convergence");
                        continue;
                    }
                    assert_eq!(symbols.in_flight(), 1, "actual remote GET holds the shared credit");
                    waiting.abort_with_reason(CancelReason::user("cancel admitted symbol repair GET"));
                    let (returned, result) = waiting.join(&cx).await.expect("data cancellation is a typed task result");
                    cursor = returned;
                    assert!(matches!(result, Err(SymbolRepairError::Cancelled)));
                    assert_eq!(cursor.progress().repaired_batches, 0);
                    assert_eq!(destination.stats().batches, 1);
                    assert_eq!(symbols.in_flight(), 0);
                    assert!(!cx.is_cancel_requested(), "borrowed transport owner remains healthy");
                    data_gate.release();
                    data_gate.changed.wait_until(|| data_gate.retired.load(Ordering::Acquire)).await;
                    cancelled_data = true;
                    break;
                }
                assert!(cancelled_data, "finite tree reaches a missing retained batch");
            }

            let mut steps = 0;
            while !cursor.progress().complete {
                let before = cursor.progress();
                let progress = repair.step(&cx, &symbols, &mut cursor).await.unwrap();
                assert!(progress.visited_nodes - before.visited_nodes <= 1);
                assert!(progress.repaired_batches - before.repaired_batches <= 1);
                steps += 1;
                assert!(steps <= 32, "finite tree and three values must finish");
            }
            assert!(steps > 1, "one-node/one-value steps must exercise the cursor");
            assert_eq!(cursor.progress().repaired_batches, 2);
            assert_eq!(destination.stats().batches, 3);
            for batch in &batches {
                assert_eq!(destination.get(&origin, batch.key()).unwrap().as_ref().as_ref(), batch.as_ref());
            }
            assert!(destination.get(&origin, secret.key()).is_err());
            assert!(destination.get(&NodeId::new("unrelated-origin"), secret.key()).is_err());
            assert_eq!(symbols.in_flight(), 0);

            if matches!(case, Case::RepairAndRefusals) {
                let empty = store("fresh-destination");
                let next = SymbolRepairClient::new(origin.clone(), NodeId::new("source"), Arc::clone(&empty), repair_limits()).unwrap();
                let mut old = next.start(&cx).await.unwrap();
                let fourth = batch(4);
                source.put(&origin, fourth.as_ref()).unwrap();
                catalogs.publish(Arc::new(capture_symbol_catalog(&source, origin.clone(), 2, catalog_limits()).unwrap())).unwrap();
                assert!(matches!(next.step(&cx, &symbols, &mut old).await,
                    Err(SymbolRepairError::Catalog(CatalogError::SnapshotChanged))));
                assert_eq!(empty.stats().batches, 0);

                let calls = gate.calls.load(Ordering::Acquire);
                assert!(matches!(next.step(&cx, &symbols, &mut cursor).await,
                    Err(SymbolRepairError::Catalog(CatalogError::Cursor))));
                assert_eq!(gate.calls.load(Ordering::Acquire), calls);
                let wrong_symbols = RemoteSymbolTransport::new_bounded(cx.clone(), intruder_data.clone(),
                    [("source".to_owned(), intruder_data_client)], Arc::new(AuthKey::from_seed(42)), batch_limits(), 1).unwrap();
                assert!(matches!(SymbolRepairWorker::new(repair.clone(), wrong_symbols.clone(),
                    SymbolRepairWorkerConfig::new(Duration::from_secs(5), 32)),
                    Err(SymbolRepairWorkerError::Authority)));
                assert!(matches!(repair.step(&cx, &wrong_symbols, &mut cursor).await, Err(SymbolRepairError::Authority)));
                assert_eq!(gate.calls.load(Ordering::Acquire), calls, "foreign origin refuses before metadata I/O");
                let data_calls = data_gate.calls.load(Ordering::Acquire);
                assert!(wrong_symbols.fetch_symbols("source", batches[0].key()).await.is_err(),
                    "a granted, connected repair peer cannot fetch another origin's batch");
                assert_eq!(data_gate.calls.load(Ordering::Acquire), data_calls + 1,
                    "distinct mTLS identity must reach the production namespace refusal");

                let intruder = Arc::new(NativeRemoteRuntime::with_config(handle.clone(), NodeId::new("repair-peer"),
                    [NativeRemoteRoute::new(NodeId::new("source"), intruder_meta, intruder_meta_client)], remote_config).unwrap());
                stop.remotes.push(Arc::clone(&intruder));
                let intruder_cx = base.clone().with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("repair-peer"))
                    .with_runtime(Arc::clone(&intruder) as Arc<dyn RemoteRuntime>));
                let intruder_repair = SymbolRepairClient::new(NodeId::new("repair-peer"), NodeId::new("source"),
                    Arc::clone(&empty), repair_limits()).unwrap();
                let meta_calls = gate.calls.load(Ordering::Acquire);
                assert!(matches!(intruder_repair.start(&intruder_cx).await, Err(SymbolRepairError::Remote)));
                assert_eq!(gate.calls.load(Ordering::Acquire), meta_calls + 1,
                    "catalog refusal must follow real authenticated handler admission");
                assert!(intruder.close(&intruder_cx).await);

                let mut tiny = repair_limits();
                tiny.max_total_repair_bytes = 1;
                let limited = SymbolRepairClient::new(origin.clone(), NodeId::new("source"), Arc::clone(&empty), tiny).unwrap();
                let mut limited_cursor = limited.start(&cx).await.unwrap();
                let mut refused = false;
                for _ in 0..32 {
                    match limited.step(&cx, &symbols, &mut limited_cursor).await {
                        Err(SymbolRepairError::Catalog(CatalogError::Limit("total repair bytes"))) => { refused = true; break; }
                        Ok(progress) => assert!(!progress.complete),
                        other => panic!("unexpected repair limit result: {other:?}"),
                    }
                }
                assert!(refused);
                assert_eq!(empty.stats().batches, 0);

                // An authenticated catalog's size assertion still cannot bypass
                // validation of the actual fetched canonical batch before put.
                let key = batches[0].key();
                let forged = Catalog::new(origin.clone(), 3, vec![CatalogEntry {
                    key: key.object_id.as_u128().to_le_bytes().to_vec(), value_hash: key.digest,
                    value_bytes: 1 }], catalog_limits()).unwrap();
                catalogs.publish(Arc::new(forged)).unwrap();
                let mut forged_cursor = next.start(&cx).await.unwrap();
                let mut refused = false;
                for _ in 0..32 {
                    match next.step(&cx, &symbols, &mut forged_cursor).await {
                        Err(SymbolRepairError::Catalog(CatalogError::Integrity)) => { refused = true; break; }
                        Ok(progress) => assert!(!progress.complete),
                        other => panic!("unexpected catalog-integrity result: {other:?}"),
                    }
                }
                assert!(refused);
                assert_eq!(empty.stats().batches, 0);
            }
            }

            assert_eq!(symbols.in_flight(), 0);
            assert!(remote.close(&cx).await);
            for service in &stop.services { let _ = service.begin_drain(); }
            let meta_report = meta_task.join(&base).await.unwrap().unwrap();
            let data_report = data_task.join(&base).await.unwrap().unwrap();
            assert!(meta_report.accepted_connections() > 1);
            assert!(data_report.accepted_connections() >= 2);
            for service in &stop.services { assert_eq!(service.active_connections(), 0); }
            assert_eq!(remote.active_operations(), 0);
        }).await.expect("native anti-entropy fixture watchdog");
    });
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.live_regions, 0);
    assert_eq!(report.pending_obligations, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.queued_finalizers, 0);
    assert!(!report.has_pending_obligation_posts);
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    // A strong RuntimeHandle keeps the runtime alive, and shutdown_timeout
    // waits for every such owner, so release this fixture's own first.
    drop(handle);
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
}

struct WorkerFixture<'a> {
    cx: &'a Cx,
    repair: &'a SymbolRepairClient,
    symbols: &'a RemoteSymbolTransport,
    origin: &'a NodeId,
    source: &'a Arc<SymbolReplicaStore>,
    destination: &'a Arc<SymbolReplicaStore>,
    catalogs: &'a Arc<SymbolCatalogService>,
    metadata: &'a Arc<Gate>,
    values: &'a Arc<Gate>,
    remote: &'a Arc<NativeRemoteRuntime>,
}

impl WorkerFixture<'_> {
    fn publish(&self, revision: u64, objects: impl IntoIterator<Item = u64>) {
        for object in objects {
            self.source.put(self.origin, batch(object).as_ref()).unwrap();
        }
        self.catalogs.publish(Arc::new(capture_symbol_catalog(self.source,
            self.origin.clone(), revision, catalog_limits()).unwrap())).unwrap();
    }

    async fn finish_repair(&self) {
        let mut cursor = self.repair.start(self.cx).await.unwrap();
        for _ in 0..64 {
            if cursor.progress().complete { return; }
            self.repair.step(self.cx, self.symbols, &mut cursor).await.unwrap();
        }
        assert!(cursor.progress().complete, "bounded healthy follow-up must converge");
    }
}

async fn exercise_worker(fixture: WorkerFixture<'_>, case: Case) {
    if matches!(case, Case::WorkerClockExhausted) {
        let timers = asupersync::time::TimerDriverHandle::with_virtual_clock(Arc::new(
            asupersync::time::VirtualClock::starting_at(Time::MAX)));
        // No task admission or I/O is expected, so a distinct test context can
        // expose the saturated clock without altering the live TLS services.
        let exhausted = Cx::new_with_drivers(fixture.cx.region_id(), fixture.cx.task_id(),
            Budget::INFINITE, None, None, None, Some(timers), None)
            .with_remote_cap(RemoteCap::new().with_local_node(fixture.origin.clone())
                .with_runtime(Arc::clone(fixture.remote) as Arc<dyn RemoteRuntime>));
        for periodic in [false, true] {
            let config = SymbolRepairWorkerConfig::new(Duration::from_nanos(1), 64);
            let config = if periodic { config.with_interval(Duration::from_nanos(1)) } else { config };
            let worker = SymbolRepairWorker::new(fixture.repair.clone(), fixture.symbols.clone(), config).unwrap();
            let control = worker.handle();
            let report = worker.run(&exhausted).await;
            assert!(matches!(report.outcome, Outcome::Err(SymbolRepairWorkerError::ClockExhausted)));
            assert_eq!(report.snapshot.status, SymbolRepairWorkerStatus::Failed);
            assert_eq!(report.snapshot.rounds_finished, 0);
            assert_eq!(control.request(), SymbolRepairRequest::Closed);
            assert_eq!(fixture.metadata.calls.load(Ordering::Acquire), 0);
            assert_eq!(fixture.remote.active_operations(), 0);
        }
        fixture.finish_repair().await;
        return;
    }

    let config = match case {
        Case::WorkerManual => SymbolRepairWorkerConfig::new(Duration::from_secs(10), 64)
            .with_initial_repair(false),
        Case::WorkerPeriodic => SymbolRepairWorkerConfig::new(Duration::from_secs(10), 64)
            .with_initial_repair(false).with_interval(Duration::from_millis(30)),
        Case::WorkerRetries => SymbolRepairWorkerConfig::new(Duration::from_secs(15), 64)
            .with_retry_policy(2, Duration::from_millis(10)),
        Case::WorkerStepLimit => SymbolRepairWorkerConfig::new(Duration::from_secs(10), 1)
            .with_retry_policy(2, Duration::from_millis(10)),
        Case::WorkerStopDeadline => SymbolRepairWorkerConfig::new(Duration::from_secs(2), 64),
        _ => SymbolRepairWorkerConfig::new(Duration::from_secs(10), 64),
    };
    let worker = SymbolRepairWorker::new(fixture.repair.clone(), fixture.symbols.clone(), config).unwrap();
    let control = worker.handle();
    assert_eq!(control.snapshot().status, SymbolRepairWorkerStatus::Prepared);
    assert_eq!(fixture.metadata.calls.load(Ordering::Acquire), 0, "construction cannot dispatch");
    match case {
        Case::WorkerManual => {
            assert_eq!(control.request(), SymbolRepairRequest::Scheduled);
            assert_eq!(control.request(), SymbolRepairRequest::Coalesced);
            fixture.metadata.allow_release.store(true, Ordering::Release);
            fixture.metadata.armed.store(true, Ordering::Release);
        }
        Case::WorkerStopDeadline | Case::WorkerCancelMetadata => {
            fixture.metadata.armed.store(true, Ordering::Release);
        }
        Case::WorkerCancelData => fixture.values.armed.store(true, Ordering::Release),
        Case::WorkerRetries => fixture.metadata.failures_remaining.store(1, Ordering::Release),
        _ => {}
    }
    let mut owned = fixture.cx.spawn(move |body| async move { worker.run(&body).await }).unwrap();
    let cancellation = CancelReason::user("cancel native retained-symbol repair worker");
    match case {
        Case::WorkerManual => {
            fixture.metadata.entered().await;
            assert_eq!(control.snapshot().rounds_started, 1);
            assert_eq!(control.request(), SymbolRepairRequest::Scheduled);
            for _ in 0..64 { assert_eq!(control.request(), SymbolRepairRequest::Coalesced); }
            assert!(control.snapshot().pending);
            fixture.metadata.release();
            let second = control.changed(1).await;
            assert_eq!(second.rounds_started, 2);
            assert_eq!(second.rounds_finished, 2);
            assert_eq!(second.successful_rounds, 2);
            assert!(second.last_round.as_ref().unwrap().is_success());
            assert_eq!(fixture.destination.stats().batches, 3);

            fixture.publish(2, [4]);
            assert_eq!(control.request(), SymbolRepairRequest::Scheduled);
            let third = control.changed(2).await;
            assert_eq!(third.rounds_finished, 3);
            let report = third.last_round.as_ref().unwrap();
            assert!(report.is_success());
            assert_eq!(report.progress.unwrap().repaired_batches, 1);
            assert_eq!(fixture.destination.stats().batches, 4);
            control.stop();
        }
        Case::WorkerPeriodic => {
            let mut observed = control.changed(0).await;
            assert!(observed.last_round.as_ref().unwrap().is_success());
            fixture.publish(2, [4]);
            let mut repaired = false;
            for _ in 0..8 {
                observed = control.changed(observed.rounds_finished).await;
                let report = observed.last_round.as_ref().unwrap();
                // A worker may already have started its next round before the
                // observer publishes revision 2. That old cut can legitimately
                // change; the following periodic round must still converge.
                if !report.is_success() {
                    assert!(matches!(&report.outcome,
                        Outcome::Err(SymbolRepairRoundError::Repair(
                            SymbolRepairError::Catalog(CatalogError::SnapshotChanged)))));
                    continue;
                }
                if fixture.destination.stats().batches == 4 { repaired = true; break; }
            }
            assert!(repaired, "periodic repair discovers a newly published source cut");
            assert!(observed.rounds_finished >= 2);
            control.stop();
        }
        Case::WorkerStopDeadline => {
            fixture.metadata.entered().await;
            assert_eq!(fixture.remote.active_operations(), 1);
            control.stop();
            assert_eq!(control.snapshot().status, SymbolRepairWorkerStatus::Stopping);
            assert_eq!(control.request(), SymbolRepairRequest::Closed);
        }
        Case::WorkerCancelMetadata => {
            fixture.metadata.entered().await;
            assert_eq!(fixture.remote.active_operations(), 1);
            owned.abort_with_reason(cancellation.clone());
        }
        Case::WorkerCancelData => {
            fixture.values.entered().await;
            assert_eq!(fixture.symbols.in_flight(), 1);
            owned.abort_with_reason(cancellation.clone());
        }
        Case::WorkerRetries => {
            let first = control.changed(0).await;
            let report = first.last_round.as_ref().unwrap();
            assert!(report.is_success());
            assert_eq!(report.attempts, 2, "a failed authenticated ROOT read gets a fresh cursor");

            // Change the source after a real old-cut GET is already pending.
            // Its verified immutable put survives, and the next ROOT refresh
            // must force the worker to acquire a fresh cursor within this round.
            fixture.publish(2, [4, 5]);
            fixture.values.armed.store(true, Ordering::Release);
            assert_eq!(control.request(), SymbolRepairRequest::Scheduled);
            fixture.values.entered().await;
            fixture.publish(3, [6]);
            fixture.values.release();
            let changed = control.changed(1).await;
            let report = changed.last_round.as_ref().unwrap();
            assert!(report.is_success());
            assert_eq!(report.attempts, 2);
            assert_eq!(fixture.destination.stats().batches, 6);

            let calls = fixture.metadata.calls.load(Ordering::Acquire);
            fixture.metadata.failures_remaining.store(3, Ordering::Release);
            assert_eq!(control.request(), SymbolRepairRequest::Scheduled);
            let exhausted = control.changed(2).await;
            let report = exhausted.last_round.as_ref().unwrap();
            assert!(!report.is_success());
            assert_eq!(report.attempts, 2);
            assert_eq!(fixture.metadata.calls.load(Ordering::Acquire) - calls, 2);
            assert!(matches!(&report.outcome,
                Outcome::Err(SymbolRepairRoundError::Repair(SymbolRepairError::Remote))));
            assert_eq!(exhausted.successful_rounds, 2);

            assert_eq!(control.request(), SymbolRepairRequest::Scheduled);
            let recovered = control.changed(3).await;
            assert!(recovered.last_round.as_ref().unwrap().is_success());
            assert_eq!(recovered.last_round.as_ref().unwrap().attempts, 2);
            assert_eq!(recovered.successful_rounds, 3);
            control.stop();
        }
        Case::WorkerStepLimit => {
            let limited = control.changed(0).await;
            let report = limited.last_round.as_ref().unwrap();
            assert!(matches!(&report.outcome, Outcome::Err(SymbolRepairRoundError::StepLimit)));
            assert!(!report.is_success());
            assert_eq!(report.steps, 1);
            assert_eq!(report.attempts, 1, "step exhaustion cannot reset the work allowance by retrying");
            assert!(!report.progress.unwrap().complete);
            control.stop();
        }
        _ => unreachable!("manual cursor cases and exhausted clocks run elsewhere"),
    }
    let report = owned.join(fixture.cx).await.expect("worker acknowledges cancellation and returns its terminal receipt");
    assert_eq!(control.request(), SymbolRepairRequest::Closed);
    assert!(!control.snapshot().pending);
    assert_eq!(fixture.remote.active_operations(), 0);
    assert_eq!(fixture.symbols.in_flight(), 0);
    assert!(!fixture.cx.is_cancel_requested(), "the transport's original owner stays healthy");
    match case {
        Case::WorkerCancelMetadata | Case::WorkerCancelData => {
            assert!(matches!(&report.outcome, Outcome::Cancelled(reason) if reason == &cancellation));
            assert_eq!(report.snapshot.status, SymbolRepairWorkerStatus::Cancelled);
            let round = report.snapshot.last_round.as_ref().unwrap();
            assert_eq!(round.trigger, SymbolRepairRoundTrigger::ParentCancelled(cancellation));
            assert!(!round.is_success());
            if matches!(case, Case::WorkerCancelMetadata) {
                assert!(fixture.metadata.retired.load(Ordering::Acquire));
            } else {
                assert_eq!(round.progress.unwrap().repaired_batches, 0);
                // A V1 GET's local connection retirement is not remote server
                // quiescence. Explicitly release and observe that fixture owner.
                fixture.values.release();
                fixture.values.changed.wait_until(|| fixture.values.retired.load(Ordering::Acquire)).await;
            }
            fixture.finish_repair().await;
        }
        Case::WorkerStopDeadline => {
            assert!(matches!(report.outcome, Outcome::Ok(())));
            assert_eq!(report.snapshot.status, SymbolRepairWorkerStatus::Stopped);
            let round = report.snapshot.last_round.as_ref().unwrap();
            assert_eq!(round.trigger, SymbolRepairRoundTrigger::Deadline);
            assert!(!round.is_success());
            assert!(fixture.metadata.retired.load(Ordering::Acquire));
            fixture.finish_repair().await;
        }
        _ => {
            assert!(matches!(report.outcome, Outcome::Ok(())));
            assert_eq!(report.snapshot.status, SymbolRepairWorkerStatus::Stopped);
            if matches!(case, Case::WorkerStepLimit) { fixture.finish_repair().await; }
        }
    }
    let terminal = control.changed(report.snapshot.rounds_finished).await;
    assert!(terminal.status.is_terminal(), "terminal observation never waits for an impossible new round");
}

// The fixture is one large future; a debug build's poll frames for it
// overflow a 2 MiB stack. That is libtest's test thread, which polls it under
// block_on, and the runtime's default worker stack, so both get a larger one.
const FIXTURE_STACK_BYTES: usize = 32 * 1024 * 1024;

fn exercise_on_large_stack(workers: usize, case: Case) {
    let run = std::thread::Builder::new()
        .name(format!("anti-entropy-{workers}"))
        .stack_size(FIXTURE_STACK_BYTES)
        .spawn(move || exercise(workers, case))
        .unwrap();
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn native_symbol_anti_entropy_repairs_exact_batches_and_refuses_cross_origin_stale_and_over_limit_work() {
    for workers in [1, 2] {
        exercise_on_large_stack(workers, Case::RepairAndRefusals);
    }
}

#[test]
fn native_symbol_anti_entropy_cancels_after_real_handler_admission_and_resumes_the_same_cursor() {
    for workers in [1, 2] {
        exercise_on_large_stack(workers, Case::CancelAndResume);
    }
}

#[test]
fn native_symbol_repair_worker_coalesces_hints_and_repairs_new_published_cuts() {
    for workers in [1, 2] { exercise_on_large_stack(workers, Case::WorkerManual); }
}

#[test]
fn native_symbol_repair_worker_periodically_discovers_retained_values() {
    for workers in [1, 2] { exercise_on_large_stack(workers, Case::WorkerPeriodic); }
}

#[test]
fn native_symbol_repair_worker_stop_waits_for_deadline_cancellation_and_real_metadata_retirement() {
    for workers in [1, 2] { exercise_on_large_stack(workers, Case::WorkerStopDeadline); }
}

#[test]
fn native_symbol_repair_worker_cancellation_reaches_parked_metadata_and_value_operations() {
    for workers in [1, 2] {
        exercise_on_large_stack(workers, Case::WorkerCancelMetadata);
        exercise_on_large_stack(workers, Case::WorkerCancelData);
    }
}

#[test]
fn native_symbol_repair_worker_retries_changed_cuts_and_transient_reads_with_finite_attempts() {
    for workers in [1, 2] { exercise_on_large_stack(workers, Case::WorkerRetries); }
}

#[test]
fn native_symbol_repair_worker_step_exhaustion_is_a_typed_incomplete_round() {
    for workers in [1, 2] { exercise_on_large_stack(workers, Case::WorkerStepLimit); }
}

#[test]
fn native_symbol_repair_worker_saturated_clock_refuses_without_dispatch_or_spin() {
    for workers in [1, 2] { exercise_on_large_stack(workers, Case::WorkerClockExhausted); }
}
