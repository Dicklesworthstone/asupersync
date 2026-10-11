//! br-asupersync-dist-otp-completeness-8y37kz.6: real V3 catalog and V1 symbol
//! services, bounded resumable repair, authenticated namespaces and native drain.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]
#![recursion_limit = "256"]

use asupersync::distributed::{HasSchema, SchemaDescriptor};
use asupersync::distributed::anti_entropy::catalog::{Catalog, CatalogEntry, CatalogError, CatalogLimits};
use asupersync::distributed::anti_entropy::native::{SymbolRepairClient, SymbolRepairError, SymbolRepairLimits};
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
use asupersync::types::{CancelReason, symbol::Symbol};
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
                let mut retirement = None;
                if gate.armed.swap(false, Ordering::AcqRel) {
                    retirement = Some(Retired(Arc::clone(&gate)));
                    let mut release = std::pin::pin!(gate.changed.wait_until(|| gate.released.load(Ordering::Acquire)));
                    let mut cancelled = std::pin::pin!(cx.cancelled());
                    poll_fn(|task| {
                        if cancelled.as_mut().poll(task).is_ready() { return Poll::Ready(()); }
                        if !await_cancel && release.as_mut().poll(task).is_ready() { return Poll::Ready(()); }
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
enum Case { RepairAndRefusals, CancelAndResume }

fn exercise(workers: usize, case: Case) {
    let builder = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers) };
    let runtime = builder.build().unwrap();
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
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
}

#[test]
fn native_symbol_anti_entropy_repairs_exact_batches_and_refuses_cross_origin_stale_and_over_limit_work() {
    for workers in [1, 2] { exercise(workers, Case::RepairAndRefusals); }
}

#[test]
fn native_symbol_anti_entropy_cancels_after_real_handler_admission_and_resumes_the_same_cursor() {
    for workers in [1, 2] { exercise(workers, Case::CancelAndResume); }
}
