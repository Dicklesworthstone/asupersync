use super::*;
use crate::grpc::health::{HealthAuthMode, HealthReporter, ServingStatus};
use crate::grpc::status::Code;
use std::future::Future;
use std::sync::atomic::AtomicUsize;
use std::task::{Wake, Waker};

// The health registry's Check/Watch factories are synchronous computations
// wrapped in futures. Unexpected Pending is a failed test, not a busy-poll loop.
fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("health factory unexpectedly parked"),
    }
}

fn request(service: &str, token: Option<&str>) -> Request<Bytes> {
    let mut request = Request::new(Bytes::from(
        WireRequest { service: service.to_owned() }.encode_to_vec(),
    ));
    if let Some(token) = token {
        assert!(request.metadata_mut().insert("authorization", format!("Bearer {token}")));
    }
    request
}

fn check(rpc: &HealthRpcService, name: &str, token: Option<&str>) -> Result<Bytes, Status> {
    let cx = Cx::for_testing();
    ready(rpc.call_unary(&cx, CHECK_PATH, request(name, token), Metadata::new()))
        .map(|response| response.into_inner())
}

type ByteStream = Pin<Box<dyn Streaming<Message = Bytes> + Send + 'static>>;

fn watch(rpc: &HealthRpcService, name: &str, token: Option<&str>) -> Result<ByteStream, Status> {
    let cx = Cx::for_testing();
    ready(rpc.call_server_streaming(&cx, WATCH_PATH, request(name, token), Metadata::new()))
        .map(|stream| stream.into_parts().0)
}

fn next_status(stream: &mut ByteStream, task: &mut Context<'_>) -> i32 {
    match stream.as_mut().poll_next(task) {
        Poll::Ready(Some(Ok(bytes))) => WireResponse::decode(bytes.as_ref()).unwrap().status,
        _ => panic!("expected one health update"),
    }
}

#[test]
fn protobuf_health_fixtures_preserve_defaults_and_unknown_fields() {
    let decoded = decode_request(Request::new(Bytes::from_static(b"\x0a\x03svc"))).unwrap();
    assert_eq!(decoded.get_ref().service, "svc");
    assert!(decode_request(Request::new(Bytes::new())).unwrap().get_ref().service.is_empty());
    // Unknown field 2 and duplicate field 1 follow protobuf merge semantics.
    let decoded = decode_request(Request::new(Bytes::from_static(b"\x0a\x01a\x10\x01\x0a\x01b"))).unwrap();
    assert_eq!(decoded.get_ref().service, "b");
    for (status, expected) in [
        (ServingStatus::Unknown, &b""[..]),
        (ServingStatus::Serving, &b"\x08\x01"[..]),
        (ServingStatus::NotServing, &b"\x08\x02"[..]),
        (ServingStatus::ServiceUnknown, &b"\x08\x03"[..]),
    ] {
        assert_eq!(encode_response(HealthCheckResponse::new(status)).as_ref(), expected);
    }
}

#[test]
fn protobuf_request_validation_is_bounded_and_preserves_extensions() {
    for bytes in [&b"\x00"[..], &b"\x0a\x80"[..], &b"\x0a\x01\xff"[..], &b"\x08\x01"[..]] {
        assert_eq!(decode_request(Request::new(Bytes::from(bytes.to_vec()))).unwrap_err().code(), Code::InvalidArgument);
    }
    let oversized = Request::new(Bytes::from(vec![0; MAX_HEALTH_RPC_REQUEST_BYTES + 1]));
    assert_eq!(decode_request(oversized).unwrap_err().code(), Code::ResourceExhausted);
    assert!(decode_request(request(&"a".repeat(MAX_SERVICE_NAME_LEN), None)).is_ok());
    assert_eq!(decode_request(request(&"a".repeat(MAX_SERVICE_NAME_LEN + 1), None)).unwrap_err().code(), Code::InvalidArgument);
    let mut original = request("svc", Some("secret"));
    original.extensions_mut().insert_typed(17_u32);
    let decoded = decode_request(original).unwrap();
    assert_eq!(decoded.extensions().get_typed::<u32>(), Some(&17));
    assert!(decoded.metadata().get("authorization").is_some());
}

#[test]
fn callable_health_requires_auth_and_preserves_existing_unknown_policy() {
    let locked = HealthService::new().rpc_service(1);
    assert_eq!(check(&locked, "", Some("anything")).unwrap_err().code(), Code::Unauthenticated);
    assert_eq!(watch(&locked, "svc", None).err().unwrap().code(), Code::Unauthenticated);
    assert_eq!(locked.active_watches(), 0);
    let health = HealthService::with_auth_mode(HealthAuthMode::bearer_token("secret"));
    health.set_status("svc", ServingStatus::Serving);
    let rpc = health.rpc_service(1);
    for token in [None, Some("wrong")] {
        assert_eq!(check(&rpc, "svc", token).unwrap_err().code(), Code::Unauthenticated);
        assert_eq!(watch(&rpc, "svc", token).err().unwrap().code(), Code::Unauthenticated);
        assert_eq!(rpc.active_watches(), 0);
    }
    assert_eq!(check(&rpc, "svc", Some("secret")).unwrap().as_ref(), b"\x08\x01");
    assert_eq!(check(&rpc, "missing", Some("secret")).unwrap_err().code(), Code::PermissionDenied);
    let mut stream = watch(&rpc, "missing", Some("secret")).unwrap();
    assert_eq!(next_status(&mut stream, &mut Context::from_waker(Waker::noop())), 3);
    assert_eq!(rpc.active_watches(), 1);
    assert!(!format!("{rpc:?}").contains("secret"));
}

#[test]
fn watches_report_live_registry_and_reporter_transitions_then_release_admission() {
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    let health = HealthService::with_auth_mode(HealthAuthMode::bearer_token("secret"));
    let rpc = health.rpc_service(1);
    let mut stream = watch(&rpc, "svc", Some("secret")).unwrap();
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&counter));
    let mut task = Context::from_waker(&waker);
    assert_eq!(next_status(&mut stream, &mut task), 3);
    assert!(stream.as_mut().poll_next(&mut task).is_pending());
    let reporter = HealthReporter::new(health.clone(), "svc");
    reporter.set_serving();
    assert!(counter.0.load(Ordering::SeqCst) > 0);
    assert_eq!(next_status(&mut stream, &mut task), 1);
    assert!(stream.as_mut().poll_next(&mut task).is_pending());
    reporter.set_not_serving();
    assert_eq!(next_status(&mut stream, &mut task), 2);
    assert!(stream.as_mut().poll_next(&mut task).is_pending());
    drop(reporter);
    assert_eq!(next_status(&mut stream, &mut task), 3);
    assert!(stream.as_mut().poll_next(&mut task).is_pending());
    drop(stream);
    assert_eq!(rpc.active_watches(), 0);
    let wakes = counter.0.load(Ordering::SeqCst);
    health.set_status("svc", ServingStatus::Serving);
    assert_eq!(counter.0.load(Ordering::SeqCst), wakes, "retired watch left no registered waker");
}

#[test]
fn watch_capacity_is_shared_lazy_and_recovers_after_unpolled_drop() {
    let health = HealthService::with_auth_mode(HealthAuthMode::bearer_token("secret"));
    let rpc = health.rpc_service(1);
    let clone = rpc.clone();
    let cx = Cx::for_testing();
    let future = rpc.call_server_streaming(&cx, WATCH_PATH, request("svc", Some("secret")), Metadata::new());
    assert_eq!(rpc.active_watches(), 0, "future construction does not admit");
    let stream = ready(future).unwrap();
    assert_eq!(clone.active_watches(), 1);
    // Authentication refusal must not reveal saturation or acquire a slot.
    assert_eq!(watch(&clone, "svc", None).err().unwrap().code(), Code::Unauthenticated);
    assert_eq!(watch(&clone, "svc", Some("secret")).err().unwrap().code(), Code::ResourceExhausted);
    drop(stream);
    assert_eq!(rpc.active_watches(), 0);
    let stream = watch(&clone, "svc", Some("secret")).unwrap();
    assert_eq!(rpc.active_watches(), 1);
    drop(stream);
    assert_eq!(rpc.active_watches(), 0);
}

#[test]
fn disabled_watch_keeps_check_available_and_exact_routes_are_enforced() {
    let health = HealthService::with_auth_mode(HealthAuthMode::bearer_token("secret"));
    health.set_server_status(ServingStatus::Serving);
    let rpc = health.rpc_service(0);
    assert_eq!(rpc.watch_capacity(), 0);
    assert_eq!(check(&rpc, "", Some("secret")).unwrap().as_ref(), b"\x08\x01");
    assert_eq!(watch(&rpc, "", Some("secret")).err().unwrap().code(), Code::ResourceExhausted);
    let cx = Cx::for_testing();
    assert_eq!(ready(rpc.call_unary(&cx, WATCH_PATH, request("", Some("secret")), Metadata::new())).unwrap_err().code(), Code::Unimplemented);
    assert_eq!(ready(rpc.call_server_streaming(&cx, CHECK_PATH, request("", Some("secret")), Metadata::new())).unwrap_err().code(), Code::Unimplemented);
    assert_eq!(rpc.active_watches(), 0);
}

#[test]
fn cancelled_factory_and_cancel_during_auth_never_admit_a_watch() {
    let cx = Cx::for_testing();
    let cancel = cx.clone();
    let health = HealthService::with_auth_mode(HealthAuthMode::Custom(Arc::new(
        move |_: &Metadata, method: &str| {
            assert_eq!(method, "Watch");
            cancel.cancel_with(CancelKind::User, Some("auth cancelled owner"));
            Ok(())
        },
    )));
    let rpc = health.rpc_service(1);
    let result = ready(rpc.call_server_streaming(&cx, WATCH_PATH, request("svc", None), Metadata::new()));
    assert_eq!(result.unwrap_err().code(), Code::Cancelled);
    assert_eq!(rpc.active_watches(), 0);
    for (kind, expected) in [
        (CancelKind::Deadline, Code::DeadlineExceeded),
        (CancelKind::CostBudget, Code::ResourceExhausted),
        (CancelKind::User, Code::Cancelled),
    ] {
        let cx = Cx::for_testing();
        cx.cancel_with(kind, Some("pre-cancelled"));
        let result = ready(rpc.call_server_streaming(&cx, WATCH_PATH, request("svc", None), Metadata::new()));
        assert_eq!(result.unwrap_err().code(), expected);
        assert_eq!(rpc.active_watches(), 0);
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn last_slot_admission_is_atomic_across_contending_clones() {
    let admission = Arc::new(WatchAdmission { capacity: 1, active: AtomicUsize::new(0) });
    let gate = Arc::new(std::sync::Barrier::new(9));
    let wins = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let admission = Arc::clone(&admission);
        let gate = Arc::clone(&gate);
        let wins = Arc::clone(&wins);
        workers.push(std::thread::spawn(move || {
            gate.wait();
            let slot = admission.acquire().ok();
            if slot.is_some() { wins.fetch_add(1, Ordering::SeqCst); }
            gate.wait();
            gate.wait();
            drop(slot);
        }));
    }
    gate.wait();
    gate.wait();
    let active = admission.active.load(Ordering::Relaxed);
    let observed_wins = wins.load(Ordering::SeqCst);
    gate.wait();
    for worker in workers { worker.join().unwrap(); }
    assert_eq!(active, 1);
    assert_eq!(observed_wins, 1);
    assert_eq!(admission.active.load(Ordering::Relaxed), 0);
    assert!(admission.acquire().is_ok());
}

#[cfg(not(target_arch = "wasm32"))]
mod native;
