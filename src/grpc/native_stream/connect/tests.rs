//! Connection setup deadlines, authority and native TCP ownership.
//! br-asupersync-server-stack-hardening-eeexl1.10; fixed wire/virtual fixtures.

use super::*;
use crate::bytes::Bytes;
use crate::grpc::codec::IdentityCodec;
use crate::grpc::status::Code;
use crate::grpc::streaming::Metadata;
use crate::http::h2::{Frame, HpackDecoder};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::runtime::RuntimeBuilder;
use crate::time::VirtualClock;
use crate::types::{Budget, CancelKind, RegionId, TaskId};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Wake, Waker};

fn virtual_cx() -> (Cx, Arc<VirtualClock>, TimerDriverHandle) {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(10)));
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let cx = Cx::new_with_drivers(
        RegionId::new_for_test(1, 0), TaskId::new_for_test(1, 0), Budget::INFINITE,
        None, None, None, Some(timer.clone()), None,
    );
    (cx, clock, timer)
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("expected immediate fixture completion"),
    }
}

#[test]
fn setup_uses_one_inclusive_deadline_across_stages_and_rejects_late_values() {
    let (cx, clock, timer) = virtual_cx();
    let mut setup = Setup::new(cx.clone(), timer, Time::from_secs(12));
    assert_eq!(ready(setup.run(async { Ok(17) })).unwrap(), 17);
    clock.advance_to(Time::from_secs(11));
    assert_eq!(setup.remaining(), Duration::from_secs(1));
    assert_eq!(ready(setup.run(async { Ok(18) })).unwrap(), 18);
    let called = AtomicBool::new(false);
    clock.advance_to(Time::from_secs(12));
    assert_eq!(ready(setup.run(async {
        called.store(true, Ordering::SeqCst);
        Ok(19)
    })).unwrap_err().code(), Code::DeadlineExceeded);
    assert!(!called.load(Ordering::SeqCst));
    assert!(!cx.is_cancel_requested());

    let (cx, clock, timer) = virtual_cx();
    let drops = Arc::new(AtomicUsize::new(0));
    struct Value(Arc<AtomicUsize>);
    impl Drop for Value {
        fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    let mut setup = Setup::new(cx.clone(), timer, Time::from_secs(12));
    let result = ready(setup.run(async {
        clock.advance_to(Time::from_secs(12));
        Ok(Value(Arc::clone(&drops)))
    }));
    assert_eq!(result.err().unwrap().code(), Code::DeadlineExceeded);
    assert_eq!(drops.load(Ordering::SeqCst), 1, "late transport/result is retired");
    assert!(!cx.is_cancel_requested());
}

#[test]
fn setup_cancellation_wakes_pending_stage_and_preserves_original_cause() {
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    for (kind, expected) in [
        (CancelKind::User, Code::Cancelled),
        (CancelKind::Deadline, Code::DeadlineExceeded),
        (CancelKind::CostBudget, Code::ResourceExhausted),
    ] {
        let (cx, _, timer) = virtual_cx();
        let mut setup = Setup::new(cx.clone(), timer, Time::from_secs(20));
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&counter));
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(setup.run(std::future::pending::<Result<(), Status>>()));
        assert!(future.as_mut().poll(&mut task).is_pending());
        cx.cancel_with(kind, Some("setup fixture"));
        assert!(counter.0.load(Ordering::SeqCst) > 0, "cancel wakes a parked setup stage");
        match future.as_mut().poll(&mut task) {
            Poll::Ready(Err(status)) => assert_eq!(status.code(), expected),
            _ => panic!("expected exact cancellation status"),
        }
        drop(future);
        drop(setup);
        assert_eq!(cx.cancel_reason().unwrap().kind, kind);
    }
}

#[test]
fn setup_installs_only_its_explicit_context_per_poll() {
    let (cx, _, timer) = virtual_cx();
    let unrelated = Cx::for_testing();
    let _ambient = Cx::set_current(Some(unrelated.clone()));
    let mut setup = Setup::new(cx.clone(), timer, Time::from_secs(20));
    ready(setup.run(async {
        assert_eq!(Cx::current().unwrap().task_id(), cx.task_id());
        assert!(Cx::current().unwrap().timer_driver().is_some());
        Ok(())
    })).unwrap();
    assert_eq!(Cx::current().unwrap().task_id(), unrelated.task_id());
    assert!(!unrelated.is_cancel_requested());
}

struct IdleIo(Arc<AtomicUsize>);
impl Drop for IdleIo {
    fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
}
impl AsyncRead for IdleIo {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        panic!("construction must not perform I/O")
    }
}
impl AsyncWrite for IdleIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        panic!("construction must not perform I/O")
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("construction must not perform I/O")
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("construction must not perform I/O")
    }
}

#[test]
fn admitted_call_keeps_original_deadline_and_forwards_only_remaining_time() {
    let (cx, clock, _) = virtual_cx();
    let config = NativeStreamConfig { timeout: Some(Duration::from_secs(10)), ..Default::default() };
    let admitted = CallDeadline::capture(&cx, &Metadata::new(), config.timeout).unwrap();
    clock.advance_to(Time::from_secs(14)); // time spent connecting, not a new call
    let drops = Arc::new(AtomicUsize::new(0));
    let mut stream = NativeServerStream::new_admitted(
        &cx, IdleIo(Arc::clone(&drops)), "localhost", "/test.Service/Watch",
        Request::new(Bytes::new()), IdentityCodec, config, Some(admitted),
    ).unwrap();
    assert_eq!(stream.deadline, Some(Time::from_secs(20)));
    let connection = stream.connection.as_mut().unwrap();
    assert!(matches!(connection.next_frame(), Some(Frame::Settings(_))));
    let Some(Frame::Headers(head)) = connection.next_frame() else { panic!("request HEADERS") };
    let headers = HpackDecoder::new().decode(&mut head.header_block.clone()).unwrap();
    assert_eq!(headers.iter().find(|head| head.name == "grpc-timeout").unwrap().value, "6S");
    drop(stream);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(!cx.is_cancel_requested());
}

#[test]
fn expired_admission_drops_transport_without_codec_or_wire_work() {
    let (cx, clock, _) = virtual_cx();
    let admitted = CallDeadline::capture(&cx, &Metadata::new(), Some(Duration::from_secs(1))).unwrap();
    clock.advance_to(Time::from_secs(11));
    let drops = Arc::new(AtomicUsize::new(0));
    let result = NativeServerStream::new_admitted(
        &cx, IdleIo(Arc::clone(&drops)), "localhost", "/test.Service/Watch",
        Request::new(Bytes::new()), IdentityCodec, NativeStreamConfig::default(), Some(admitted),
    );
    assert_eq!(result.unwrap_err().code(), Code::DeadlineExceeded);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn endpoint_refuses_downgrade_invalid_routes_and_missing_explicit_authority() {
    let address = "127.0.0.1:50051".parse().unwrap();
    for authority in ["", "user@host", "host/path", "host\n", "host?x"] {
        assert!(NativeStreamEndpoint::new(address, authority, Duration::from_secs(1)).is_err());
    }
    assert!(NativeStreamEndpoint::new(address, "localhost", Duration::ZERO).is_err());
    let endpoint = NativeStreamEndpoint::new(address, "localhost", Duration::from_secs(1)).unwrap();
    let (cx, _, _) = virtual_cx(); // timer only: unrelated ambient authority cannot grant I/O
    let config = NativeStreamConfig { scheme: "https", ..Default::default() };
    assert_eq!(ready(endpoint.connect_tcp(&cx, "/svc/Watch", Request::new(Bytes::new()),
        IdentityCodec, config)).unwrap_err().code(), Code::InvalidArgument);
    assert_eq!(ready(endpoint.connect_tcp(&cx, "/svc/Watch", Request::new(Bytes::new()),
        IdentityCodec, NativeStreamConfig::default())).unwrap_err().code(), Code::FailedPrecondition);
}

fn runtime_case<F, Fut>(multithread: bool, test: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if multithread { RuntimeBuilder::new().worker_threads(2).build().unwrap() }
        else { RuntimeBuilder::current_thread().build().unwrap() };
    let finished = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&finished);
    runtime.block_on(runtime.handle().spawn(async move {
        test(Cx::current().expect("native context")).await;
        finished.store(true, Ordering::Release);
    }));
    assert!(observed.load(Ordering::Acquire), "native setup assertions did not finish");
}

#[test]
fn native_driver_admission_respects_runtime_io_restriction() {
    for multithread in [false, true] {
        runtime_case(multithread, |mut cx| async move {
            assert!(cx.io_driver_handle().is_some(), "native reactor is explicit");
            assert!(!cx.has_io(), "native contexts need no generic IoCap adapter");
            let endpoint = NativeStreamEndpoint::new(
                "127.0.0.1:9".parse().unwrap(), "localhost", Duration::from_secs(1),
            ).unwrap();
            let request = Request::new(Bytes::new());
            assert!(endpoint.admit(&cx, "/svc/Watch", &request, &NativeStreamConfig::default()).is_ok());
            cx.runtime_mask = crate::cx::cap::CapMask::none();
            assert!(cx.io_driver_handle().is_some(), "restriction retains the physical driver");
            let error = endpoint.admit(&cx, "/svc/Watch", &request, &NativeStreamConfig::default())
                .err().expect("a retained driver must not bypass the runtime mask");
            assert_eq!(error.code(), Code::FailedPrecondition);
        });
    }
}

#[test]
fn native_endpoint_dials_health_watch_and_closes_its_owned_connection() {
    use crate::grpc::health::{HealthAuthMode, HealthService, ServingStatus};
    use crate::grpc::server::{Server, ServerStreamingConfig};
    use crate::http::h1::server::HostPolicy;
    use crate::server::shutdown::ShutdownSignal;
    use std::num::NonZeroUsize;
    struct Stop(ShutdownSignal);
    impl Drop for Stop { fn drop(&mut self) { self.0.trigger_immediate(); } }
    for multithread in [false, true] {
        let runtime = if multithread { RuntimeBuilder::new().worker_threads(2).build().unwrap() }
            else { RuntimeBuilder::current_thread().build().unwrap() };
        let handle = runtime.handle().clone();
        let done = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&done);
        runtime.block_on(runtime.handle().spawn(async move {
            let health = HealthService::with_auth_mode(HealthAuthMode::bearer_token("endpoint-secret"));
            health.set_status("svc", ServingStatus::Serving);
            let rpc = health.rpc_service(1);
            let registry = rpc.clone();
            let server = Arc::new(Server::builder().add_service(rpc).build());
            let listener = server.bind_registered_streaming_http2("127.0.0.1:0", HostPolicy::allow_all(),
                ServerStreamingConfig {
                    frame_capacity: NonZeroUsize::new(2).unwrap(),
                    max_frame_bytes: NonZeroUsize::new(1024).unwrap(),
                    max_trailer_bytes: 1024, terminal_timeout: Duration::from_secs(1),
                }).await.unwrap();
            let endpoint = NativeStreamEndpoint::new(listener.local_addr().unwrap(), "localhost", Duration::from_secs(3)).unwrap();
            let stop = Stop(listener.shutdown_signal());
            let requests = listener.in_flight_requests();
            let client = handle.spawn(async move {
                let _stop = stop;
                let cx = Cx::current().unwrap();
                assert!(!cx.has_io(), "native task must not need a virtual IoCap");
                assert!(cx.io_driver_handle().is_some(), "actual native reactor");
                let mut request = Request::new(Bytes::from_static(b"\x0a\x03svc"));
                assert!(request.metadata_mut().insert("authorization", "Bearer endpoint-secret"));
                let mut stream = endpoint.connect_tcp(&cx, "/grpc.health.v1.Health/Watch", request,
                    IdentityCodec, NativeStreamConfig { timeout: Some(Duration::from_secs(10)), ..Default::default() }).await.unwrap();
                assert!(stream.initial_metadata().is_some());
                assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"\x08\x01");
                health.set_status("svc", ServingStatus::NotServing);
                assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"\x08\x02");
                stream.cancel();
                assert_eq!(stream.status().unwrap().code(), Code::Cancelled);
                let timer = cx.timer_driver().unwrap();
                crate::time::timeout(timer.now(), Duration::from_secs(3), async {
                    while registry.active_watches() != 0 { crate::runtime::yield_now().await; }
                }).await.expect("server retired watch before listener shutdown");
                assert!(!cx.is_cancel_requested());
                done.store(true, Ordering::Release);
            });
            listener.run_produced(&handle).await.unwrap();
            let _ = client.await;
            assert_eq!(requests.load(Ordering::Acquire), 0);
        }));
        assert!(observed.load(Ordering::Acquire));
    }
}

// Peer sends SETTINGS but no response headers. The atomic witness is set
// BEFORE those bytes wake the client, so Pending really belongs to header wait.
fn stalled_peer() -> (SocketAddr, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let reached = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&reached);
    let peer = std::thread::spawn(move || {
        let until = std::time::Instant::now() + Duration::from_secs(5);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < until, "peer accept watchdog");
                    std::thread::park_timeout(Duration::from_millis(1));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut preface = [0; 24];
        socket.read_exact(&mut preface).unwrap();
        assert_eq!(&preface, crate::http::h2::connection::CLIENT_PREFACE);
        observed.store(true, Ordering::Release);
        socket.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).unwrap();
        let mut bytes = [0; 4096];
        for _ in 0..128 {
            match socket.read(&mut bytes) {
                Ok(0) => return,
                Ok(_) => {},
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => return,
                Err(error) => panic!("owned setup transport did not close: {error}"),
            }
        }
        panic!("bounded setup peer did not observe transport closure");
    });
    (address, reached, peer)
}

#[test]
fn native_setup_timeout_closes_stalled_header_wait_without_cancelling_parent() {
    let (address, reached, peer) = stalled_peer();
    let observed = Arc::clone(&reached);
    runtime_case(false, move |cx| async move {
        let endpoint = NativeStreamEndpoint::new(address, "localhost", Duration::from_millis(500)).unwrap();
        let result = endpoint.connect_tcp(&cx, "/test.Service/Watch", Request::new(Bytes::new()),
            IdentityCodec, NativeStreamConfig::default()).await;
        assert!(reached.load(Ordering::Acquire), "peer received actual connection preface");
        assert_eq!(result.unwrap_err().code(), Code::DeadlineExceeded);
        assert!(!cx.is_cancel_requested());
    });
    peer.join().unwrap();
    assert!(observed.load(Ordering::Acquire));
}

#[test]
fn native_cancel_and_dropped_setup_retire_a_witnessed_pending_header_wait() {
    for multithread in [false, true] {
        for cancel in [false, true] {
            let (address, reached, peer) = stalled_peer();
            runtime_case(multithread, move |cx| async move {
                let endpoint = NativeStreamEndpoint::new(address, "localhost", Duration::from_secs(3)).unwrap();
                let mut future = Box::pin(endpoint.connect_tcp(&cx, "/test.Service/Watch",
                    Request::new(Bytes::new()), IdentityCodec, NativeStreamConfig::default()));
                poll_fn(|task| {
                    let polled = future.as_mut().poll(task);
                    assert!(polled.is_pending(), "peer deliberately withholds response headers");
                    if reached.load(Ordering::Acquire) { Poll::Ready(()) } else { Poll::Pending }
                }).await;
                if cancel {
                    let owner = cx.clone();
                    std::thread::spawn(move || owner.cancel_with(CancelKind::User, Some("cross-thread setup cancel"))).join().unwrap();
                    assert_eq!(future.await.unwrap_err().code(), Code::Cancelled);
                } else {
                    drop(future);
                    assert!(!cx.is_cancel_requested());
                }
            });
            peer.join().expect("peer observed setup connection retirement");
        }
    }
}

// has_io() census at 98ec112d: cx.rs tests/docs and the capability conformance
// tests query the optional IoCap; methodology_baselines benchmarks that query.
// NativeStreamEndpoint needs native reactor authority instead. ATP rendezvous
// has four separate logical candidate-policy uses, not gRPC transport checks.
// Keep that distinction: globally broadening has_io() would change virtual and
// browser semantics and would still fail to enforce the runtime IO mask.
#[test]
fn native_admission_uses_reactor_authority_without_a_virtual_provider() {
    for multithread in [false, true] {
        runtime_case(multithread, move |cx| async move {
            assert!(!cx.has_io(), "normal native task has no optional virtual IoCap");
            assert!(cx.io_driver_handle().is_some());
            let endpoint = NativeStreamEndpoint::new(
                "127.0.0.1:50051".parse().unwrap(), "localhost", Duration::from_secs(3),
            ).unwrap();
            let admitted = endpoint.admit(
                &cx, "/svc/Watch", &Request::new(Bytes::new()), &NativeStreamConfig::default(),
            );
            assert!(admitted.is_ok(), "native task must pass admission: {:?}", admitted.err());
            assert!(!cx.is_cancel_requested());
            eprintln!("scenario=native-grpc-admission workers={} virtual_io=false native_io=true admitted=true", if multithread { 2 } else { 1 });
        });
    }
}

#[test]
fn native_dial_refuses_missing_or_masked_authority_before_opening_a_socket() {
    use crate::cx::cap::CapSet;
    type NoIo = CapSet<true, true, true, false, true>;
    type NoTime = CapSet<true, false, true, true, true>;
    for multithread in [false, true] {
        runtime_case(multithread, move |cx| async move {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let endpoint = NativeStreamEndpoint::new(
                listener.local_addr().unwrap(), "localhost", Duration::from_secs(3),
            ).unwrap();
            // Obtain the restricted All-typed context through the public ambient
            // path. The raw reactor handle is retained for inheritance; only
            // the effective mask can prevent it from authorizing a new dial.
            let no_io = {
                let _guard = cx.clone().restrict::<NoIo>().set_current_restricted();
                Cx::current().unwrap()
            };
            let no_time = {
                let _guard = cx.clone().restrict::<NoTime>().set_current_restricted();
                Cx::current().unwrap()
            };
            assert!(no_io.io_driver_handle().is_some());
            assert!(no_time.io_driver_handle().is_some());
            assert!(no_io.timer_driver().is_some());
            let timer_only = virtual_cx().0;
            let virtual_only = Cx::for_testing_with_io();
            assert!(virtual_only.has_io());
            assert!(virtual_only.io_driver_handle().is_none());
            for (scenario, explicit, message) in [
                ("masked-io", no_io, "native streaming connect requires explicit I/O authority"),
                ("timer-only", timer_only, "native streaming connect requires explicit I/O authority"),
                ("virtual-only", virtual_only, "native streaming connect requires explicit I/O authority"),
                ("masked-time", no_time, "native streaming setup requires an explicit timer driver"),
            ] {
                // Poll under the still fully-authorized native context. It
                // must not fill in the explicit caller's missing authority.
                let error = ready(endpoint.connect_tcp(
                    &explicit, "/svc/Watch", Request::new(Bytes::new()),
                    IdentityCodec, NativeStreamConfig::default(),
                )).unwrap_err();
                assert_eq!(error.code(), Code::FailedPrecondition, "{scenario}");
                assert_eq!(error.message(), message, "{scenario}");
                assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock), "{scenario}: refused dial reached listener");
                assert!(!cx.is_cancel_requested());
                eprintln!("scenario={scenario} outcome=failed-precondition accepted_connections=0");
            }
        });
    }
}
