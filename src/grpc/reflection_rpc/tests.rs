#![cfg(test)]
use super::*;
use crate::grpc::{Code, Metadata, Server};
use crate::remote::RemoteCap;
use std::collections::VecDeque;
use std::marker::PhantomPinned;
use std::sync::atomic::AtomicBool;
use std::task::{Wake, Waker};

const FIXTURE: &[u8] = include_bytes!("../reflection_descriptor/fixture.bin");
const LIST: &[u8] = b"\x3a\x00";
static METHODS: &[MethodDescriptor] = &[MethodDescriptor::unary("Ping", "/demo.Echo/Ping")];
static DESCRIPTOR: ServiceDescriptor = ServiceDescriptor::new("Echo", "demo", METHODS);

fn registry() -> ReflectionService {
    let registry = ReflectionService::new();
    registry.register_descriptor(&DESCRIPTOR);
    registry
}

fn rpc(registry: ReflectionService, config: ReflectionRpcConfig) -> ReflectionRpcService {
    registry.rpc_service(ReflectionDescriptorSet::decode(FIXTURE).unwrap(), config).unwrap()
}

fn remote() -> Cx {
    Cx::for_testing_with_remote(RemoteCap::new())
}

fn decode(bytes: Bytes) -> WireResponse {
    WireResponse::decode(bytes.as_ref()).unwrap()
}

#[derive(Default)]
struct Witness {
    polls: AtomicUsize,
    drops: AtomicUsize,
    restricted_drop: AtomicBool,
}

// An input device for the production adapter, deliberately !Unpin. These tests
// exercise actual ReflectionStream polling; they do not implement a second RPC.
struct Source {
    items: parking_lot::Mutex<VecDeque<Result<Bytes, Status>>>,
    eof: bool,
    witness: Arc<Witness>,
    _pin: PhantomPinned,
}

fn source(items: Vec<Result<Bytes, Status>>, eof: bool) -> (Source, Arc<Witness>) {
    let witness = Arc::new(Witness::default());
    (Source { items: parking_lot::Mutex::new(items.into()), eof, witness: Arc::clone(&witness), _pin: PhantomPinned }, witness)
}

impl Streaming for Source {
    type Message = Bytes;
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Bytes, Status>>> {
        let this = self.as_ref().get_ref();
        this.witness.polls.fetch_add(1, Ordering::SeqCst);
        if let Some(item) = this.items.lock().pop_front() {
            Poll::Ready(Some(item))
        } else if this.eof { Poll::Ready(None) } else { Poll::Pending }
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        self.witness.restricted_drop.store(Cx::current().is_some_and(|cx| cx.has_remote()), Ordering::SeqCst);
        self.witness.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn list_services_has_exact_standard_wire_and_restores_the_callers_context() {
    let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig::default());
    let _parent = Cx::set_current(Some(Cx::for_testing()));
    let result = service.answer(&remote(), &Bytes::from_static(LIST)).unwrap();
    assert_eq!(result.as_ref(), b"\x12\x02\x3a\x00\x32\x0d\x0a\x0b\x0a\x09demo.Echo");
    assert!(!Cx::current().unwrap().has_remote());
    let reply = decode(result);
    assert_eq!(reply.original_request.unwrap().query, Some(Query::ListServices(String::new())));
}

#[test]
fn file_symbol_and_extension_queries_return_original_bytes_with_imports() {
    let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig::default());
    let cx = remote();
    for query in [
        Query::FileByName("echo.proto".to_string()),
        Query::FileContainingSymbol("demo.Echo.Ping".to_string()),
        Query::FileContainingExtension(wire::ExtensionRequest { containing_type: "demo.Record".to_string(), number: 100 }),
    ] {
        let expected_name = if matches!(query, Query::FileContainingExtension(_)) { "ext.proto" } else { "echo.proto" };
        let request = WireRequest { host: "example.test".to_string(), query: Some(query) };
        let reply = decode(service.answer(&cx, &Bytes::from(request.encode_to_vec())).unwrap());
        assert_eq!(reply.valid_host, "example.test");
        assert_eq!(reply.original_request, Some(request));
        let Some(Reply::Files(files)) = reply.reply else { panic!("descriptor response expected") };
        let expected = service.shared.descriptors.file_by_name(expected_name).unwrap();
        assert_eq!(files.files.len(), 2);
        for (actual, expected) in files.files.iter().zip(expected) { assert_eq!(actual, expected.as_ref()); }
    }
    // Independent request bytes, not encoded through our Query derive.
    let request = Bytes::from_static(b"\x32\x0bdemo.Record");
    let reply = decode(service.answer(&cx, &request).unwrap());
    let Some(Reply::Extensions(extensions)) = reply.reply else { panic!("extension numbers expected") };
    assert_eq!(extensions.base_type_name, "demo.Record");
    assert_eq!(extensions.numbers, [100, 101]);
    let request = Bytes::from_static(b"\x2a\x0f\x0a\x0bdemo.Record\x10\x64");
    assert!(matches!(decode(service.answer(&cx, &request).unwrap()).reply, Some(Reply::Files(_))));
}

#[test]
fn lookup_errors_are_in_band_and_a_later_query_still_completes() {
    let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig::default());
    let (input, witness) = source(vec![Ok(Bytes::from_static(b"\x1a\x0dmissing.proto")), Ok(Bytes::new()), Ok(Bytes::from_static(LIST))], true);
    let (mut output, _) = service.open_stream(&remote(), input).unwrap().into_parts();
    let mut task = Context::from_waker(Waker::noop());
    for expected in [Code::NotFound, Code::InvalidArgument] {
        let Poll::Ready(Some(Ok(bytes))) = output.as_mut().poll_next(&mut task) else { panic!("in-band error expected") };
        let Some(Reply::Error(error)) = decode(bytes).reply else { panic!("error reply expected") };
        assert_eq!(error.code, expected as i32);
        assert_eq!(service.active_streams(), 1);
    }
    assert_eq!(witness.polls.load(Ordering::SeqCst), 2, "no request prefetch");
    let Poll::Ready(Some(Ok(bytes))) = output.as_mut().poll_next(&mut task) else { panic!("later success expected") };
    assert!(matches!(decode(bytes).reply, Some(Reply::Services(_))));
    assert!(matches!(output.as_mut().poll_next(&mut task), Poll::Ready(None)));
    assert_eq!(service.active_streams(), 0);
    assert_eq!(witness.drops.load(Ordering::SeqCst), 1);
    assert!(matches!(output.as_mut().poll_next(&mut task), Poll::Ready(None)));
}

#[test]
fn locked_missing_remote_and_denied_callbacks_never_poll_input() {
    for (registry, cx) in [
        (registry(), remote()),
        (registry().allow_anonymous(), Cx::for_testing()),
        (registry().with_auth(|_, _| Err(Status::unauthenticated("credential required"))), remote()),
    ] {
        let service = rpc(registry, ReflectionRpcConfig { max_streams: 0, ..ReflectionRpcConfig::default() });
        let (input, witness) = source(vec![Ok(Bytes::from_static(LIST))], true);
        let error = service.open_stream(&cx, input).unwrap_err();
        assert!(matches!(error.code(), Code::PermissionDenied | Code::Unauthenticated), "auth must precede capacity");
        assert_eq!(service.active_streams(), 0);
        assert_eq!(witness.polls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn revocation_and_callback_cancellation_end_the_rpc_without_schema_disclosure() {
    let allowed = Arc::new(AtomicBool::new(true));
    let check = Arc::clone(&allowed);
    let service = rpc(registry().with_auth(move |cx, method| {
        assert!(cx.has_remote());
        assert_eq!(method, "ListServices");
        if check.load(Ordering::SeqCst) { Ok(()) } else { Err(Status::permission_denied("revoked")) }
    }), ReflectionRpcConfig::default());
    let cx = remote();
    let (input, _) = source(vec![Ok(Bytes::from_static(LIST)), Ok(Bytes::from_static(LIST))], false);
    let (mut output, _) = service.open_stream(&cx, input).unwrap().into_parts();
    let mut task = Context::from_waker(Waker::noop());
    assert!(matches!(output.as_mut().poll_next(&mut task), Poll::Ready(Some(Ok(_)))));
    allowed.store(false, Ordering::SeqCst);
    assert!(matches!(output.as_mut().poll_next(&mut task), Poll::Ready(Some(Err(status))) if status.code() == Code::PermissionDenied));
    assert_eq!(service.active_streams(), 0);
    let service = rpc(registry().with_auth(|cx, _| { cx.cancel_fast(CancelKind::User); Ok(()) }), ReflectionRpcConfig::default());
    assert_eq!(service.answer(&remote(), &Bytes::from_static(LIST)).unwrap_err().code(), Code::Cancelled);
}

#[test]
fn clones_and_protocol_views_share_capacity_and_unpolled_drop_releases_it() {
    let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig { max_streams: 1, ..ReflectionRpcConfig::default() });
    let alpha = service.v1alpha();
    let cx = remote();
    let (input, witness) = source(vec![], false);
    let output = service.open_stream(&cx, input).unwrap();
    let (other, _) = source(vec![], false);
    assert_eq!(alpha.rpc.open_stream(&cx, other).unwrap_err().code(), Code::ResourceExhausted);
    drop(output);
    assert_eq!(service.active_streams(), 0);
    assert_eq!(witness.polls.load(Ordering::SeqCst), 0);
    assert_eq!(witness.drops.load(Ordering::SeqCst), 1);
    assert!(witness.restricted_drop.load(Ordering::SeqCst));
    let (other, _) = source(vec![], false);
    drop(alpha.rpc.open_stream(&cx, other).unwrap());
    assert_eq!(service.active_streams(), 0);
}

#[test]
fn cancellation_wakes_idle_input_and_removes_owned_wake_registration() {
    let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig::default());
    let cx = remote();
    let (input, witness) = source(vec![], false);
    let (mut output, _) = service.open_stream(&cx, input).unwrap().into_parts();
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let baseline = Arc::strong_count(&wakes);
    let mut task = Context::from_waker(&waker);
    assert!(output.as_mut().poll_next(&mut task).is_pending());
    assert!(Arc::strong_count(&wakes) > baseline);
    cx.cancel_fast(CancelKind::User);
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(output.as_mut().poll_next(&mut task), Poll::Ready(Some(Err(status))) if status.code() == Code::Cancelled));
    assert_eq!(witness.polls.load(Ordering::SeqCst), 1);
    assert_eq!(service.active_streams(), 0);
    assert_eq!(Arc::strong_count(&wakes), baseline);
}

#[test]
fn malformed_input_transport_errors_and_bounds_are_terminal_and_release_admission() {
    for (config, item, expected) in [
        (ReflectionRpcConfig::default(), Ok(Bytes::from_static(b"\xff")), Code::InvalidArgument),
        (ReflectionRpcConfig::default(), Err(Status::data_loss("bad input framing")), Code::DataLoss),
        (ReflectionRpcConfig { max_request_bytes: 1, ..ReflectionRpcConfig::default() }, Ok(Bytes::from_static(LIST)), Code::ResourceExhausted),
        (ReflectionRpcConfig { max_response_bytes: 1, ..ReflectionRpcConfig::default() }, Ok(Bytes::from_static(LIST)), Code::ResourceExhausted),
    ] {
        let service = rpc(registry().allow_anonymous(), config);
        let (input, witness) = source(vec![item, Ok(Bytes::from_static(LIST))], false);
        let (mut output, _) = service.open_stream(&remote(), input).unwrap().into_parts();
        let mut task = Context::from_waker(Waker::noop());
        assert!(matches!(output.as_mut().poll_next(&mut task), Poll::Ready(Some(Err(status))) if status.code() == expected));
        assert!(matches!(output.as_mut().poll_next(&mut task), Poll::Ready(None)));
        assert_eq!(service.active_streams(), 0);
        assert_eq!(witness.polls.load(Ordering::SeqCst), 1);
        assert_eq!(witness.drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn query_count_bounds_allow_exact_limit_eof_but_refuse_an_extra_query() {
    for extra in [false, true] {
        let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig { max_queries_per_stream: 1, ..ReflectionRpcConfig::default() });
        let count = if extra { 2 } else { 1 };
        let (input, _) = source(vec![Ok(Bytes::from_static(LIST)); count], true);
        let (mut output, _) = service.open_stream(&remote(), input).unwrap().into_parts();
        let mut task = Context::from_waker(Waker::noop());
        assert!(matches!(output.as_mut().poll_next(&mut task), Poll::Ready(Some(Ok(_)))));
        let next = output.as_mut().poll_next(&mut task);
        if extra { assert!(matches!(next, Poll::Ready(Some(Err(status))) if status.code() == Code::ResourceExhausted)); }
        else { assert!(matches!(next, Poll::Ready(None))); }
        assert_eq!(service.active_streams(), 0);
    }
}

#[test]
fn versioned_services_register_with_exact_bidi_paths_and_no_unary_fallback() {
    let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig::default());
    let alpha = service.v1alpha();
    assert_eq!(service.descriptor().methods[0].path, V1_PATH);
    assert_eq!(alpha.descriptor().methods[0].path, ALPHA_PATH);
    assert!(service.descriptor().methods[0].client_streaming);
    assert!(service.descriptor().methods[0].server_streaming);
    let server = Server::builder().add_service(service.clone()).add_service(alpha).build();
    assert!(server.get_service(ReflectionRpcService::NAME).is_some());
    assert!(server.get_service(ReflectionRpcV1AlphaService::NAME).is_some());
    let cx = remote();
    let mut refused = service.call_unary(&cx, V1_PATH, Request::new(Bytes::new()), Metadata::new());
    assert!(matches!(refused.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(status)) if status.code() == Code::Unimplemented));
}

#[test]
fn enable_reflection_preserves_explicitly_registered_v1alpha_service() {
    let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig::default());
    let alpha = service.v1alpha();
    // Case 1: add_service(alpha) BEFORE enable_reflection_with_auth
    let server1 = Server::builder()
        .add_service(alpha.clone())
        .enable_reflection_with_auth(|_, _| Ok(()))
        .build();
    let registered1 = server1.get_service(ReflectionRpcV1AlphaService::NAME).unwrap();
    assert_eq!(registered1.descriptor().methods[0].path, ALPHA_PATH);
    assert!(registered1.descriptor().methods[0].client_streaming);

    // Case 2: enable_reflection_with_auth BEFORE add_service(alpha)
    let server2 = Server::builder()
        .enable_reflection_with_auth(|_, _| Ok(()))
        .add_service(alpha.clone())
        .build();
    let registered2 = server2.get_service(ReflectionRpcV1AlphaService::NAME).unwrap();
    assert_eq!(registered2.descriptor().methods[0].path, ALPHA_PATH);
    assert!(registered2.descriptor().methods[0].client_streaming);

    // Case 3: enable(a) -> add_service(alpha) -> enable(b) still preserves the explicit service
    let server3 = Server::builder()
        .enable_reflection_with_auth(|_, _| Ok(()))
        .add_service(alpha)
        .enable_reflection_with_auth(|_, _| Ok(()))
        .build();
    let registered3 = server3.get_service(ReflectionRpcV1AlphaService::NAME).unwrap();
    assert_eq!(registered3.descriptor().methods[0].path, ALPHA_PATH);
    assert!(registered3.descriptor().methods[0].client_streaming);
}

#[test]
fn oversize_response_returns_in_band_error_reply_without_failing_stream() {
    // Case 1: Raw descriptors exceed max_response_bytes during files_reply (328 B > 200 B).
    let config = ReflectionRpcConfig {
        max_response_bytes: 200,
        ..Default::default()
    };
    let service = rpc(registry().allow_anonymous(), config);
    let cx = remote();
    let request = WireRequest {
        host: "example.test".to_string(),
        query: Some(Query::FileByName("echo.proto".to_string())),
    };
    let response = service.answer(&cx, &Bytes::from(request.encode_to_vec())).unwrap();
    let reply = decode(response);
    match reply.reply {
        Some(Reply::Error(err)) => {
            assert_eq!(err.code, Code::ResourceExhausted as i32);
            assert_eq!(err.message, "reflection descriptors exceed response limit");
        }
        other => panic!("expected in-band Error reply, got {other:?}"),
    }

    // Case 2: Raw descriptors fit (328 B <= 350 B), but framing and echoed request
    // push encoded response over the limit (~377 B > 350 B).
    let config2 = ReflectionRpcConfig {
        max_response_bytes: 350,
        ..Default::default()
    };
    let service2 = rpc(registry().allow_anonymous(), config2);
    let response2 = service2.answer(&cx, &Bytes::from(request.encode_to_vec())).unwrap();
    let reply2 = decode(response2);
    match reply2.reply {
        Some(Reply::Error(err)) => {
            assert_eq!(err.code, Code::ResourceExhausted as i32);
            assert_eq!(err.message, "reflection response byte limit exceeded");
        }
        other => panic!("expected in-band Error reply, got {other:?}"),
    }

    // Case 3: for_server derives message limits from ServerConfig.
    let server_config = crate::grpc::ServerConfig {
        max_send_message_size: 1024 * 1024,
        max_recv_message_size: 64 * 1024,
        ..Default::default()
    };
    let derived = ReflectionRpcConfig::for_server(&server_config);
    assert_eq!(derived.max_response_bytes, 1024 * 1024);
    assert_eq!(derived.max_request_bytes, 64 * 1024);
}

async fn deadline_scenario(cx: Cx) {
    use crate::cx::ChildRegionSpec;
    use crate::types::Budget;
    use std::future::poll_fn;
    use std::time::Duration;

    let cx = cx.with_remote_cap(RemoteCap::new());
    let deadline = cx.now() + Duration::from_millis(50);
    let region = cx.open_child_region(
        ChildRegionSpec::inherit().with_budget(Budget::new().with_deadline(deadline)),
    ).await.unwrap();
    let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig::default());
    let (input, witness) = source(vec![], false);
    let (mut output, _) = service.open_stream(region.cx(), input).unwrap().into_parts();
    poll_fn(|task| {
        assert!(output.as_mut().poll_next(task).is_pending(), "input must actually park");
        Poll::Ready(())
    }).await;
    let status = poll_fn(|task| output.as_mut().poll_next(task)).await.unwrap().unwrap_err();
    assert_eq!(status.code(), Code::DeadlineExceeded);
    assert!(cx.now() >= deadline);
    assert_eq!(service.active_streams(), 0);
    assert_eq!(witness.drops.load(Ordering::SeqCst), 1);
    drop(output);
    region.close().await.unwrap();
}

#[test]
fn idle_reflection_deadline_wakes_on_native_one_and_four_workers() {
    use crate::runtime::RuntimeBuilder;
    use std::time::Duration;

    for workers in [1, 4] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(workers) }.build().unwrap();
        let finished = Arc::new(AtomicBool::new(false));
        let completed = Arc::clone(&finished);
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            crate::time::timeout(cx.now(), Duration::from_secs(5), deadline_scenario(cx))
                .await.expect("reflection native deadline watchdog");
            completed.store(true, Ordering::SeqCst);
        }));
        assert!(finished.load(Ordering::SeqCst));
        let report = runtime.shutdown_drained(Duration::from_secs(3));
        assert_eq!(report.outcome, crate::runtime::RootDrainOutcome::Quiescent);
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_obligations, 0);
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn idle_reflection_deadline_uses_lab_virtual_time_and_reaches_quiescence() {
    use crate::{LabConfig, LabRuntime};
    use crate::types::Budget;

    for seed in [17, 41, 93] {
        let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(2048));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async {
            deadline_scenario(Cx::current().unwrap()).await;
        }).unwrap();
        lab.scheduler.lock().schedule(task, 0);
        let advanced = lab.run_with_auto_advance();
        let report = lab.run_until_quiescent_with_report();
        assert!(matches!(join.try_join(), Ok(Some(()))), "{advanced:?} {report:?}");
        assert!(lab.state.tasks_is_empty());
        assert!(lab.state.obligations_iter().all(|(_, obligation)| !obligation.is_pending()));
        assert!(report.lab_test_passed(), "{report:?}");
    }
}

/// br-asupersync-m5xrg1: descriptor lookups hand out whole schemas, so they
/// also pass the registry's DescribeService gate. A policy that allows only
/// ListServices still lists services, but every lookup gets an in-band
/// PermissionDenied reply.
#[test]
fn descriptor_lookups_need_describe_service_not_only_list_services() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let service = rpc(
        registry().with_auth(move |_, method| {
            record.lock().unwrap().push(method.to_string());
            if method == "ListServices" {
                Ok(())
            } else {
                Err(Status::permission_denied("schemas withheld"))
            }
        }),
        ReflectionRpcConfig::default(),
    );
    let cx = remote();
    let listed = decode(service.answer(&cx, &Bytes::from_static(LIST)).unwrap());
    assert!(
        matches!(listed.reply, Some(Reply::Services(_))),
        "{listed:?}"
    );
    for query in [
        Query::FileByName("echo.proto".to_string()),
        Query::FileContainingSymbol("demo.Echo.Ping".to_string()),
        Query::FileContainingExtension(wire::ExtensionRequest {
            containing_type: "demo.Record".to_string(),
            number: 100,
        }),
        Query::AllExtensionNumbers("demo.Record".to_string()),
    ] {
        let request = WireRequest {
            host: String::new(),
            query: Some(query),
        };
        let reply = decode(
            service
                .answer(&cx, &Bytes::from(request.encode_to_vec()))
                .unwrap(),
        );
        assert!(
            matches!(&reply.reply, Some(Reply::Error(error)) if error.code == Code::PermissionDenied as i32),
            "{reply:?}"
        );
    }
    let seen = seen.lock().unwrap();
    assert_eq!(
        seen.iter()
            .filter(|method| *method == "DescribeService")
            .count(),
        4,
        "{seen:?}"
    );
    assert_eq!(
        seen.iter()
            .filter(|method| *method == "ListServices")
            .count(),
        5,
        "{seen:?}"
    );
}


// Exercise the registration adapter, including its ownership of the request
// envelope, with the same deliberately pinned source used by stream tests.
fn dispatch_request(
    service: &ReflectionRpcService,
    cx: &Cx,
    path: &'static str,
    request: Request<Source>,
) -> Result<RegisteredServerStream, Status> {
    let mut call = registered_call(service, cx, path, request, path);
    match call.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("reflection admission unexpectedly parked"),
    }
}

fn identified_request(input: Source, principal: Option<&str>) -> Request<Source> {
    let mut request = Request::new(input);
    assert!(request.metadata_mut().insert("x-request-id", "request-42"));
    if let Some(principal) = principal {
        request.extensions_mut().insert_typed(
            crate::grpc::interceptor::AuthContext::with_principal(principal),
        );
    }
    request
}

/// asupersync-m5xrg1 M2: callers sharing one server Cx need not share authority.
#[test]
fn request_authorization_preserves_metadata_and_identity_for_both_versions() {
    use crate::grpc::interceptor::AuthContext;
    use crate::grpc::streaming::MetadataValue;

    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig::default())
        .with_request_authorization(move |cx, action, metadata, extensions| {
            observed.fetch_add(1, Ordering::SeqCst);
            assert!(cx.has_remote());
            assert!(Cx::current().unwrap().has_remote());
            assert!(matches!(action, ReflectionRpcAction::OpenStream | ReflectionRpcAction::ListServices));
            assert_eq!(metadata.get("x-request-id"), Some(&MetadataValue::Ascii("request-42".to_string())));
            let auth = extensions.get_typed::<AuthContext>()
                .ok_or_else(|| Status::unauthenticated("authenticated principal required"))?;
            if auth.principal == "schema-reader" {
                Ok(())
            } else {
                Err(Status::permission_denied("principal cannot inspect schemas"))
            }
        });
    let alpha = service.v1alpha();
    let cx = remote();
    let _parent = Cx::set_current(Some(Cx::for_testing()));
    for (view, path) in [(&service, V1_PATH), (&alpha.rpc, ALPHA_PATH)] {
        for principal in [None, Some("guest"), Some("schema-reader")] {
            let (input, witness) = source(vec![Ok(Bytes::from_static(LIST))], true);
            let result = dispatch_request(view, &cx, path, identified_request(input, principal));
            if principal == Some("schema-reader") {
                let (mut output, metadata) = result.unwrap().into_parts();
                assert!(metadata.is_empty(), "identity metadata must not be reflected");
                let mut task = Context::from_waker(Waker::noop());
                let Poll::Ready(Some(Ok(bytes))) = output.as_mut().poll_next(&mut task) else {
                    panic!("authorized caller should receive a service list");
                };
                assert!(matches!(decode(bytes).reply, Some(Reply::Services(_))));
                assert!(matches!(output.as_mut().poll_next(&mut task), Poll::Ready(None)));
            } else {
                let expected = if principal.is_none() { Code::Unauthenticated } else { Code::PermissionDenied };
                assert_eq!(result.unwrap_err().code(), expected);
                assert_eq!(witness.polls.load(Ordering::SeqCst), 0);
            }
            assert_eq!(service.active_streams(), 0);
            assert_eq!(witness.drops.load(Ordering::SeqCst), 1);
            assert!(witness.restricted_drop.load(Ordering::SeqCst));
            assert!(!Cx::current().unwrap().has_remote(), "caller context must be restored");
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 8, "admission and each query are checked");
}

#[test]
fn request_policy_authorizes_each_lookup_key_before_schema_access() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = Arc::clone(&seen);
    let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig::default())
        .with_request_authorization(move |_, action, _, _| {
            let key = match action {
                ReflectionRpcAction::OpenStream | ReflectionRpcAction::ListServices => return Ok(()),
                ReflectionRpcAction::FileByName(name) => {
                    observed.lock().unwrap().push(format!("file:{name}"));
                    if name == "echo.proto" { return Ok(()); }
                    return Err(Status::permission_denied("schema withheld"));
                }
                ReflectionRpcAction::FileContainingSymbol(symbol) => format!("symbol:{symbol}"),
                ReflectionRpcAction::FileContainingExtension { containing_type, number } =>
                    format!("extension:{containing_type}:{number}"),
                ReflectionRpcAction::AllExtensionNumbers(name) => format!("numbers:{name}"),
            };
            observed.lock().unwrap().push(key);
            Err(Status::permission_denied("schema withheld"))
        });
    let queries = [
        Query::ListServices(String::new()),
        Query::FileByName("echo.proto".to_string()),
        Query::FileByName("private.proto".to_string()),
        Query::FileContainingSymbol("demo.Echo.Ping".to_string()),
        Query::FileContainingExtension(wire::ExtensionRequest { containing_type: "demo.Record".to_string(), number: 100 }),
        Query::AllExtensionNumbers("demo.Record".to_string()),
        Query::ListServices(String::new()),
    ];
    let requests = queries.iter().cloned().map(|query| {
        Ok(Bytes::from(WireRequest { host: String::new(), query: Some(query) }.encode_to_vec()))
    }).collect();
    let (input, witness) = source(requests, true);
    let cx = remote();
    let (mut output, _) = dispatch_request(&service, &cx, V1_PATH, Request::new(input)).unwrap().into_parts();
    let mut task = Context::from_waker(Waker::noop());
    for (index, query) in queries.into_iter().enumerate() {
        let Poll::Ready(Some(Ok(bytes))) = output.as_mut().poll_next(&mut task) else {
            panic!("each query should receive an in-band answer");
        };
        let response = decode(bytes);
        assert_eq!(response.original_request.unwrap().query, Some(query));
        match (index, response.reply) {
            (0 | 6, Some(Reply::Services(_))) => {}
            (1, Some(Reply::Files(files))) => assert_eq!(files.files.len(), 2),
            (2..=5, Some(Reply::Error(error))) => {
                assert_eq!(error.code, Code::PermissionDenied as i32);
                assert_eq!(error.message, "schema withheld");
            }
            other => panic!("unexpected reflection reply: {other:?}"),
        }
        assert_eq!(witness.polls.load(Ordering::SeqCst), index + 1, "no query prefetch");
    }
    assert!(matches!(output.as_mut().poll_next(&mut task), Poll::Ready(None)));
    assert_eq!(*seen.lock().unwrap(), [
        "file:echo.proto", "file:private.proto", "symbol:demo.Echo.Ping",
        "extension:demo.Record:100", "numbers:demo.Record",
    ]);
    assert_eq!(service.active_streams(), 0);
}

#[test]
fn request_policy_rechecks_revocation_and_denied_queries_consume_the_limit() {
    let allowed = Arc::new(AtomicBool::new(true));
    let current = Arc::clone(&allowed);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig {
        max_queries_per_stream: 3, ..ReflectionRpcConfig::default()
    }).with_request_authorization(move |_, action, _, _| {
        observed.fetch_add(1, Ordering::SeqCst);
        if action == ReflectionRpcAction::OpenStream || current.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(Status::permission_denied("revoked"))
        }
    });
    let (input, witness) = source(vec![Ok(Bytes::from_static(LIST)); 4], true);
    let cx = remote();
    let (mut output, _) = dispatch_request(&service, &cx, V1_PATH, Request::new(input)).unwrap().into_parts();
    let mut task = Context::from_waker(Waker::noop());
    for permitted in [true, false, true] {
        allowed.store(permitted, Ordering::SeqCst);
        let Poll::Ready(Some(Ok(bytes))) = output.as_mut().poll_next(&mut task) else {
            panic!("query decision should be an in-band response");
        };
        let reply = decode(bytes).reply;
        if permitted {
            assert!(matches!(reply, Some(Reply::Services(_))));
        } else {
            assert!(matches!(reply, Some(Reply::Error(error)) if error.code == Code::PermissionDenied as i32));
        }
        assert_eq!(service.active_streams(), 1);
    }
    assert!(matches!(output.as_mut().poll_next(&mut task), Poll::Ready(Some(Err(status))) if status.code() == Code::ResourceExhausted));
    assert_eq!(calls.load(Ordering::SeqCst), 4, "over-limit input must not invoke the policy");
    assert_eq!(witness.polls.load(Ordering::SeqCst), 4);
    assert_eq!(service.active_streams(), 0);
}

#[test]
fn request_policy_cannot_weaken_legacy_registry_authorization() {
    for (registry, cx) in [
        (registry(), remote()),
        (registry().allow_anonymous(), Cx::for_testing()),
        (registry().with_auth(|_, _| Err(Status::unauthenticated("legacy refusal"))), remote()),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let service = rpc(registry, ReflectionRpcConfig { max_streams: 0, ..ReflectionRpcConfig::default() })
            .with_request_authorization(move |_, _, _, _| { observed.fetch_add(1, Ordering::SeqCst); Ok(()) });
        let (input, witness) = source(vec![Ok(Bytes::from_static(LIST))], true);
        let status = dispatch_request(&service, &cx, V1_PATH, Request::new(input)).unwrap_err();
        assert!(matches!(status.code(), Code::Unauthenticated | Code::PermissionDenied));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(witness.polls.load(Ordering::SeqCst), 0);
        assert_eq!(service.active_streams(), 0);
    }
    let service = rpc(registry().with_auth(|_, method| {
        if method == "ListServices" { Ok(()) } else { Err(Status::permission_denied("legacy schema refusal")) }
    }), ReflectionRpcConfig::default()).with_request_authorization(|_, action, _, _| {
        assert!(matches!(action, ReflectionRpcAction::OpenStream | ReflectionRpcAction::ListServices));
        Ok(())
    });
    let request = WireRequest { host: String::new(), query: Some(Query::FileByName("echo.proto".to_string())) };
    let response = decode(service.answer(&remote(), &Bytes::from(request.encode_to_vec())).unwrap());
    assert!(matches!(response.reply, Some(Reply::Error(error)) if error.code == Code::PermissionDenied as i32 && error.message == "legacy schema refusal"));
}

#[test]
fn cancellation_before_or_inside_request_policy_prevents_response_publication() {
    for trigger in [None, Some(ReflectionRpcAction::OpenStream), Some(ReflectionRpcAction::ListServices)] {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig::default())
            .with_request_authorization(move |cx, action, _, _| {
                observed.fetch_add(1, Ordering::SeqCst);
                if Some(action) == trigger {
                    cx.cancel_fast(CancelKind::User);
                    return Err(Status::permission_denied("cancellation takes precedence"));
                }
                Ok(())
            });
        let cx = remote();
        if trigger.is_none() { cx.cancel_fast(CancelKind::User); }
        let (input, witness) = source(vec![Ok(Bytes::from_static(LIST))], false);
        let result = dispatch_request(&service, &cx, V1_PATH, Request::new(input));
        if trigger == Some(ReflectionRpcAction::ListServices) {
            let (mut output, _) = result.unwrap().into_parts();
            let mut task = Context::from_waker(Waker::noop());
            assert!(matches!(output.as_mut().poll_next(&mut task), Poll::Ready(Some(Err(status))) if status.code() == Code::Cancelled));
            assert!(matches!(output.as_mut().poll_next(&mut task), Poll::Ready(None)));
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(witness.polls.load(Ordering::SeqCst), 1);
        } else {
            assert_eq!(result.unwrap_err().code(), Code::Cancelled);
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(trigger.is_some()));
            assert_eq!(witness.polls.load(Ordering::SeqCst), 0);
        }
        assert_eq!(service.active_streams(), 0);
        assert_eq!(witness.drops.load(Ordering::SeqCst), 1);
    }
}

struct AuthorizationLease(Arc<Witness>);

impl Drop for AuthorizationLease {
    fn drop(&mut self) {
        self.0.restricted_drop.store(Cx::current().is_some_and(|cx| cx.has_remote()), Ordering::SeqCst);
        self.0.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn request_extensions_retire_with_input_on_every_terminal_path() {
    for outcome in ["eof", "input_error", "malformed", "cancelled", "drop", "refused"] {
        let service = rpc(registry().allow_anonymous(), ReflectionRpcConfig::default())
            .with_request_authorization(move |_, action, _, extensions| {
                assert_eq!(action, ReflectionRpcAction::OpenStream);
                assert!(extensions.get_typed::<AuthorizationLease>().is_some());
                if outcome == "refused" { Err(Status::permission_denied("refused")) } else { Ok(()) }
            });
        let items = match outcome {
            "input_error" => vec![Err(Status::data_loss("transport failure"))],
            "malformed" => vec![Ok(Bytes::from_static(b"\xff"))],
            _ => vec![],
        };
        let (input, source_witness) = source(items, outcome == "eof");
        let mut request = Request::new(input);
        let lease = Arc::new(Witness::default());
        request.extensions_mut().insert_typed(AuthorizationLease(Arc::clone(&lease)));
        let cx = remote();
        let result = dispatch_request(&service, &cx, V1_PATH, request);
        if outcome == "refused" {
            assert_eq!(result.unwrap_err().code(), Code::PermissionDenied);
        } else {
            let (mut output, _) = result.unwrap().into_parts();
            assert_eq!(lease.drops.load(Ordering::SeqCst), 0, "admitted identity remains owned");
            if outcome == "drop" {
                drop(output);
            } else {
                if outcome == "cancelled" { cx.cancel_fast(CancelKind::User); }
                let terminal = output.as_mut().poll_next(&mut Context::from_waker(Waker::noop()));
                match outcome {
                    "eof" => assert!(matches!(terminal, Poll::Ready(None))),
                    "input_error" => assert!(matches!(terminal, Poll::Ready(Some(Err(status))) if status.code() == Code::DataLoss)),
                    "malformed" => assert!(matches!(terminal, Poll::Ready(Some(Err(status))) if status.code() == Code::InvalidArgument)),
                    "cancelled" => assert!(matches!(terminal, Poll::Ready(Some(Err(status))) if status.code() == Code::Cancelled)),
                    _ => unreachable!(),
                }
                assert_eq!(lease.drops.load(Ordering::SeqCst), 1, "terminal stream must release identity before output is dropped");
                drop(output);
            }
        }
        assert_eq!(service.active_streams(), 0);
        assert_eq!(source_witness.drops.load(Ordering::SeqCst), 1);
        assert_eq!(lease.drops.load(Ordering::SeqCst), 1);
        assert!(source_witness.restricted_drop.load(Ordering::SeqCst));
        assert!(lease.restricted_drop.load(Ordering::SeqCst));
    }
}
