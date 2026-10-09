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
