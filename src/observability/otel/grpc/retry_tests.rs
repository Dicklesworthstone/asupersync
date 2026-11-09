//! Retry behavior against native HTTP/2 collectors and an explicit virtual clock.

use super::super::tests as native;
use super::{
    Code, Cx, Duration, OtlpGrpcError, OtlpGrpcErrorKind, OtlpGrpcExporter, OtlpGrpcRetryPolicy,
    OtlpGrpcSignal, retryable, wait_delay,
};
use crate::cx::cap::{CapSet, CapSetRuntimeMask};
use crate::grpc::Status;
use crate::grpc::client::Channel;
use crate::http::h2::{Connection, Header};
use crate::runtime::RuntimeBuilder;
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, CancelKind, RegionId, TaskId, Time};
use crate::util::entropy::{DetEntropy, EntropySource};
use base64::Engine as _;
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

const SECRET: &str = "collector-retry-secret";
const BODY: &[u8] = b"\x0a\x00";

fn policy(retries: u32, initial: Duration, maximum: Duration) -> OtlpGrpcRetryPolicy {
    OtlpGrpcRetryPolicy::new(retries, initial, maximum)
        .unwrap()
        .with_jitter(false)
}

fn rich_status(code: Code, seconds: u8) -> Vec<u8> {
    // Independent protobuf fixture: Status -> Any -> RetryInfo -> Duration.
    assert!(seconds < 128);
    let mut bytes = vec![
        0x08,
        u8::try_from(code.as_i32()).unwrap(),
        0x1a,
        0x1e,
        0x0a,
        0x16,
    ];
    bytes.extend_from_slice(b"x/google.rpc.RetryInfo");
    bytes.extend_from_slice(&[0x12, 0x04, 0x0a, 0x02, 0x08, seconds]);
    bytes
}

fn respond(
    socket: &mut impl Write,
    connection: &mut Connection,
    stream: u32,
    code: Code,
    details: Option<&[u8]>,
    acknowledgement: Option<&[u8]>,
) {
    connection
        .send_headers(
            stream,
            vec![
                Header::new(":status", "200"),
                Header::new("content-type", "application/grpc"),
            ],
            false,
        )
        .unwrap();
    if let Some(body) = acknowledgement {
        connection
            .send_data(stream, native::framed(body), false)
            .unwrap();
    }
    let mut trailers = vec![
        Header::new("grpc-status", code.as_i32().to_string()),
        Header::new("grpc-message", SECRET),
    ];
    if let Some(details) = details {
        trailers.push(Header::new(
            "grpc-status-details-bin",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(details),
        ));
    }
    connection.send_headers(stream, trailers, true).unwrap();
    native::flush(socket, connection);
}

fn no_extra_connection(listener: &TcpListener) {
    assert!(
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "terminal export must not open another connection"
    );
}

fn registrations(cx: &Cx) -> usize {
    cx.inner.read().cancel_waker_registrations.len()
}

fn run_virtual_native<F, Fut>(budget: Budget, test: F)
where
    F: FnOnce(Cx, Arc<VirtualClock>, TimerDriverHandle) -> Fut,
    Fut: Future<Output = ()>,
{
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = RuntimeBuilder::current_thread()
        .with_timer_driver(timer.clone())
        .with_entropy_source(Arc::new(DetEntropy::new(0x07_1f_53)))
        .build()
        .unwrap();
    let owner = runtime.request_cx_with_budget(budget);
    let driver = runtime.request_cx_with_budget(Budget::INFINITE);
    let watchdog = native::WallWatchdog::new();
    runtime.block_on_with_cx(
        driver,
        Box::pin(async {
            let mut future = Box::pin(test(owner, clock, timer.clone()));
            poll_fn(|task| {
                *watchdog.signal.waiter.lock().unwrap() = Some(task.waker().clone());
                assert!(
                    !watchdog.signal.ready.load(Ordering::Acquire),
                    "retry watchdog elapsed"
                );
                future.as_mut().poll(task)
            })
            .await;
        }),
    );
    drop(watchdog);
    assert!(timer.is_empty(), "completed retry releases all timers");
    assert!(runtime.shutdown_timeout(Duration::from_secs(10)));
}

#[test]
fn status_table_and_rich_error_recoverability_are_otlp_specific() {
    let permitted = [
        Code::Cancelled,
        Code::DeadlineExceeded,
        Code::Aborted,
        Code::OutOfRange,
        Code::Unavailable,
        Code::DataLoss,
    ];
    for number in 0..=16 {
        let code = Code::from_i32(number);
        let error = OtlpGrpcError::rpc(&Status::new(code, SECRET));
        assert_eq!(retryable(&error), permitted.contains(&code), "{code}");
    }
    let resource = Status::with_details(
        Code::ResourceExhausted,
        SECRET,
        rich_status(Code::ResourceExhausted, 0).into(),
    );
    assert!(retryable(&OtlpGrpcError::rpc(&resource)));
    let malformed = Status::with_details(Code::Unavailable, SECRET, vec![0xff].into());
    assert!(!retryable(&OtlpGrpcError::rpc(&malformed)));
    let mismatched = Status::with_details(
        Code::Unavailable,
        SECRET,
        rich_status(Code::ResourceExhausted, 0).into(),
    );
    assert!(!retryable(&OtlpGrpcError::rpc(&mismatched)));
}

#[test]
fn retry_policy_validates_limits_and_jitter_is_bounded_and_replayable() {
    for (retries, initial, maximum) in [
        (17, Duration::from_secs(1), Duration::from_secs(2)),
        (1, Duration::ZERO, Duration::from_secs(1)),
        (1, Duration::from_secs(2), Duration::from_secs(1)),
        (1, Duration::from_secs(1), Duration::MAX),
    ] {
        assert_eq!(
            OtlpGrpcRetryPolicy::new(retries, initial, maximum)
                .unwrap_err()
                .kind(),
            OtlpGrpcErrorKind::InvalidRetryPolicy
        );
    }
    let jitter =
        OtlpGrpcRetryPolicy::new(16, Duration::from_nanos(1), Duration::from_nanos(u64::MAX))
            .unwrap();
    for nanos in [1, 5, 100_000_000, u64::MAX] {
        let base = Duration::from_nanos(nanos);
        assert_eq!(
            jitter.delay(base, 0),
            Duration::from_nanos(nanos.div_ceil(2))
        );
        assert_eq!(jitter.delay(base, u64::MAX), base);
        assert_eq!(jitter.with_jitter(false).delay(base, 0), base);
    }
    let first = DetEntropy::new(19);
    let replay = DetEntropy::new(19);
    let base = Duration::from_millis(100);
    for _ in 0..32 {
        let delay = jitter.delay(base, first.next_u64());
        assert_eq!(delay, jitter.delay(base, replay.next_u64()));
        assert!((Duration::from_millis(50)..=base).contains(&delay));
    }
}

#[test]
fn native_transient_status_retries_identical_bytes_and_permanent_status_stops() {
    for (code, details, should_retry) in [
        (Code::Unavailable, None, true),
        (Code::DeadlineExceeded, None, true),
        (Code::Aborted, None, true),
        (
            Code::ResourceExhausted,
            Some(rich_status(Code::ResourceExhausted, 0)),
            true,
        ),
        (Code::ResourceExhausted, None, false),
        (Code::ResourceExhausted, Some(vec![0xff]), false),
        (Code::Unavailable, Some(vec![0xff]), false),
        (Code::PermissionDenied, None, false),
    ] {
        let (listener, address) = native::listener();
        let peer_listener = listener.try_clone().unwrap();
        let peer = std::thread::spawn(move || {
            for attempt in 0..if should_retry { 2 } else { 1 } {
                let mut socket = native::accept(&peer_listener);
                let (mut connection, captured) = native::read_request(&mut socket);
                captured.assert_request(OtlpGrpcSignal::Metrics, BODY);
                respond(
                    &mut socket,
                    &mut connection,
                    captured.stream,
                    if attempt == 0 { code } else { Code::Ok },
                    if attempt == 0 {
                        details.as_deref()
                    } else {
                        None
                    },
                    if attempt == 0 { None } else { Some(&[]) },
                );
            }
        });
        native::run_native(|cx| async move {
            let channel = Channel::connect(format!("http://{address}")).await.unwrap();
            let exporter = OtlpGrpcExporter::new(channel).unwrap();
            let policy = policy(1, Duration::from_millis(1), Duration::from_millis(1));
            let result = exporter
                .send_with_retry(&cx, OtlpGrpcSignal::Metrics, BODY.to_vec(), &policy)
                .await;
            if should_retry {
                assert!(!result.unwrap().is_partial_success());
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), OtlpGrpcErrorKind::Rpc);
                assert_eq!(error.grpc_code(), Some(code));
                assert!(!format!("{error:?} {error}").contains(SECRET));
            }
            assert_eq!(registrations(&cx), 0);
        });
        peer.join().unwrap();
        no_extra_connection(&listener);
    }
}

#[test]
fn native_partial_success_warning_and_empty_presence_are_never_replayed() {
    for acknowledgement in [
        native::partial(7, SECRET),
        native::partial(0, SECRET),
        vec![0x0a, 0],
    ] {
        let (listener, address) = native::listener();
        let peer_listener = listener.try_clone().unwrap();
        let peer = std::thread::spawn(move || {
            let mut socket = native::accept(&peer_listener);
            let (mut connection, captured) = native::read_request(&mut socket);
            captured.assert_request(OtlpGrpcSignal::Logs, BODY);
            respond(
                &mut socket,
                &mut connection,
                captured.stream,
                Code::Ok,
                None,
                Some(&acknowledgement),
            );
        });
        native::run_native(|cx| async move {
            let channel = Channel::connect(format!("http://{address}")).await.unwrap();
            let exporter = OtlpGrpcExporter::new(channel).unwrap();
            let policy = policy(16, Duration::from_millis(1), Duration::from_millis(1));
            let receipt = exporter
                .send_with_retry(&cx, OtlpGrpcSignal::Logs, BODY.to_vec(), &policy)
                .await
                .unwrap();
            assert!(receipt.is_partial_success());
            assert_eq!(registrations(&cx), 0);
        });
        peer.join().unwrap();
        no_extra_connection(&listener);
    }
}

#[test]
fn native_retry_count_is_a_hard_limit() {
    for retries in [0, 2] {
        let (listener, address) = native::listener();
        let peer_listener = listener.try_clone().unwrap();
        let peer = std::thread::spawn(move || {
            for _ in 0..=retries {
                let mut socket = native::accept(&peer_listener);
                let (mut connection, captured) = native::read_request(&mut socket);
                captured.assert_request(OtlpGrpcSignal::Traces, BODY);
                respond(
                    &mut socket,
                    &mut connection,
                    captured.stream,
                    Code::Unavailable,
                    None,
                    None,
                );
            }
        });
        native::run_native(|cx| async move {
            let channel = Channel::connect(format!("http://{address}")).await.unwrap();
            let exporter = OtlpGrpcExporter::new(channel).unwrap();
            let policy = policy(retries, Duration::from_millis(1), Duration::from_millis(1));
            let error = exporter
                .send_with_retry(&cx, OtlpGrpcSignal::Traces, BODY.to_vec(), &policy)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), OtlpGrpcErrorKind::RetryExhausted);
            assert_eq!(error.grpc_code(), Some(Code::Unavailable));
        });
        peer.join().unwrap();
        no_extra_connection(&listener);
    }
}

#[test]
fn native_collector_throttle_is_a_floor_even_above_client_maximum() {
    let (listener, address) = native::listener();
    let peer_listener = listener.try_clone().unwrap();
    let peer = std::thread::spawn(move || {
        for attempt in 0..2 {
            let mut socket = native::accept(&peer_listener);
            let (mut connection, captured) = native::read_request(&mut socket);
            captured.assert_request(OtlpGrpcSignal::Metrics, BODY);
            let timeout =
                crate::grpc::server::parse_grpc_timeout(captured.header("grpc-timeout").unwrap())
                    .unwrap();
            assert_eq!(
                timeout,
                Duration::from_secs(if attempt == 0 { 10 } else { 7 })
            );
            let details = rich_status(Code::ResourceExhausted, 3);
            respond(
                &mut socket,
                &mut connection,
                captured.stream,
                if attempt == 0 {
                    Code::ResourceExhausted
                } else {
                    Code::Ok
                },
                if attempt == 0 { Some(&details) } else { None },
                if attempt == 0 { None } else { Some(&[]) },
            );
        }
    });
    run_virtual_native(Budget::INFINITE, |cx, clock, timer| async move {
        // The only timer before the total export deadline must be backoff,
        // not the channel's otherwise shorter default TCP setup timeout.
        let channel = Channel::builder(format!("http://{address}"))
            .connect_timeout(Duration::from_secs(10))
            .connect()
            .await
            .unwrap();
        let exporter = OtlpGrpcExporter::new(channel).unwrap();
        let policy = policy(1, Duration::from_secs(1), Duration::from_secs(1));
        let mut call = Box::pin(exporter.send_with_retry(
            &cx,
            OtlpGrpcSignal::Metrics,
            BODY.to_vec(),
            &policy,
        ));
        let mut waits = Vec::new();
        let receipt = poll_fn(|task| {
            let progress = call.as_mut().poll(task);
            if progress.is_pending()
                && let Some(wake) = timer.next_deadline()
                && wake < Time::from_secs(10)
            {
                assert_eq!(wake, Time::from_secs(3));
                waits.push(wake);
                clock.advance_to(wake);
                let _ = timer.process_timers();
                task.waker().wake_by_ref();
            }
            progress
        })
        .await
        .unwrap();
        assert!(!receipt.is_partial_success());
        assert_eq!(waits, vec![Time::from_secs(3)]);
        assert_eq!(registrations(&cx), 0);
    });
    peer.join().unwrap();
    no_extra_connection(&listener);
}

#[test]
fn native_attempts_share_one_total_deadline_tightened_by_channel_and_owner() {
    for (budget, channel_limit, total, expected) in [
        (Budget::INFINITE, None, 10, vec![10, 7, 1]),
        (
            Budget::INFINITE,
            Some(Duration::from_secs(5)),
            5,
            vec![5, 2],
        ),
        (
            Budget::new().with_deadline(Time::from_secs(4)),
            None,
            4,
            vec![4, 1],
        ),
    ] {
        let (listener, address) = native::listener();
        let peer_listener = listener.try_clone().unwrap();
        let attempts = expected.len();
        let peer = std::thread::spawn(move || {
            for remaining in expected {
                let mut socket = native::accept(&peer_listener);
                let (mut connection, captured) = native::read_request(&mut socket);
                captured.assert_request(OtlpGrpcSignal::Logs, BODY);
                let timeout = crate::grpc::server::parse_grpc_timeout(
                    captured.header("grpc-timeout").unwrap(),
                )
                .unwrap();
                assert_eq!(timeout, Duration::from_secs(remaining));
                respond(
                    &mut socket,
                    &mut connection,
                    captured.stream,
                    Code::Unavailable,
                    None,
                    None,
                );
            }
        });
        run_virtual_native(budget, |cx, clock, timer| async move {
            // Setup cannot supply an earlier timer that the fixture could
            // mistake for an exporter backoff. The overall budget still wins.
            let mut builder = Channel::builder(format!("http://{address}"))
                .connect_timeout(Duration::from_secs(10));
            if let Some(limit) = channel_limit {
                builder = builder.timeout(limit);
            }
            let exporter = OtlpGrpcExporter::new(builder.connect().await.unwrap()).unwrap();
            let policy = policy(16, Duration::from_secs(3), Duration::from_secs(6));
            let mut call = Box::pin(exporter.send_with_retry(
                &cx,
                OtlpGrpcSignal::Logs,
                BODY.to_vec(),
                &policy,
            ));
            let mut waits = Vec::new();
            let error = poll_fn(|task| {
                let progress = call.as_mut().poll(task);
                if progress.is_pending()
                    && let Some(wake) = timer.next_deadline()
                    && wake < Time::from_secs(total)
                {
                    waits.push(wake);
                    clock.advance_to(wake);
                    let _ = timer.process_timers();
                    task.waker().wake_by_ref();
                }
                progress
            })
            .await
            .unwrap_err();
            assert_eq!(error.kind(), OtlpGrpcErrorKind::RetryBudgetExhausted);
            assert_eq!(error.grpc_code(), Some(Code::Unavailable));
            assert_eq!(waits.len(), attempts - 1);
            assert_eq!(waits[0], Time::from_secs(3));
            if attempts == 3 {
                assert_eq!(waits[1], Time::from_secs(9));
            }
            assert_eq!(registrations(&cx), 0);
        });
        peer.join().unwrap();
        no_extra_connection(&listener);
    }
}

#[test]
fn oversized_collector_delay_stops_without_shortening_or_redialing() {
    let (listener, address) = native::listener();
    let peer_listener = listener.try_clone().unwrap();
    let peer = std::thread::spawn(move || {
        let mut socket = native::accept(&peer_listener);
        let (mut connection, captured) = native::read_request(&mut socket);
        respond(
            &mut socket,
            &mut connection,
            captured.stream,
            Code::ResourceExhausted,
            Some(&rich_status(Code::ResourceExhausted, 11)),
            None,
        );
    });
    run_virtual_native(Budget::INFINITE, |cx, _clock, timer| async move {
        let channel = Channel::connect(format!("http://{address}")).await.unwrap();
        let exporter = OtlpGrpcExporter::new(channel).unwrap();
        let policy = policy(16, Duration::from_secs(1), Duration::from_secs(1));
        let error = exporter
            .send_with_retry(&cx, OtlpGrpcSignal::Traces, BODY.to_vec(), &policy)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), OtlpGrpcErrorKind::RetryBudgetExhausted);
        assert_eq!(error.retry_delay(), Some(Duration::from_secs(11)));
        assert!(timer.is_empty());
        assert_eq!(registrations(&cx), 0);
    });
    peer.join().unwrap();
    no_extra_connection(&listener);
}

#[test]
fn native_cancel_and_drop_during_backoff_retire_timers_and_registrations() {
    for cancel in [false, true] {
        let (listener, address) = native::listener();
        let peer_listener = listener.try_clone().unwrap();
        let peer = std::thread::spawn(move || {
            let mut socket = native::accept(&peer_listener);
            let (mut connection, captured) = native::read_request(&mut socket);
            respond(
                &mut socket,
                &mut connection,
                captured.stream,
                Code::Unavailable,
                None,
                None,
            );
        });
        run_virtual_native(Budget::INFINITE, |cx, clock, timer| async move {
            let channel = Channel::connect(format!("http://{address}")).await.unwrap();
            let exporter = OtlpGrpcExporter::new(channel).unwrap();
            let policy = policy(3, Duration::from_secs(1), Duration::from_secs(1));
            let mut call = Box::pin(exporter.send_with_retry(
                &cx,
                OtlpGrpcSignal::Metrics,
                BODY.to_vec(),
                &policy,
            ));
            poll_fn(|task| {
                assert!(call.as_mut().poll(task).is_pending());
                if timer.next_deadline() == Some(Time::from_secs(1)) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            assert_eq!(timer.pending_count(), 1);
            assert_eq!(registrations(&cx), 1);
            if cancel {
                cx.cancel_fast(CancelKind::User);
                let error = call.as_mut().await.unwrap_err();
                assert_eq!(error.kind(), OtlpGrpcErrorKind::Context);
                assert_eq!(error.grpc_code(), Some(Code::Cancelled));
            }
            drop(call);
            assert!(timer.is_empty());
            assert_eq!(registrations(&cx), 0);
            clock.advance_to(Time::from_secs(2));
            assert_eq!(timer.process_timers(), 0);
        });
        peer.join().unwrap();
        no_extra_connection(&listener);
    }
}

#[test]
fn pending_native_attempt_cannot_outlive_the_total_export_budget() {
    let (listener, address) = native::listener();
    let peer_listener = listener.try_clone().unwrap();
    let observed = Arc::new(native::Signal::default());
    let witness = Arc::clone(&observed);
    let peer = std::thread::spawn(move || {
        let mut socket = native::accept(&peer_listener);
        let (_connection, captured) = native::read_request(&mut socket);
        captured.assert_request(OtlpGrpcSignal::Traces, BODY);
        observed.publish();
        let mut bytes = [0; 1024];
        loop {
            match socket.read(&mut bytes) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("expired native request retained its socket: {error}"),
            }
        }
    });
    run_virtual_native(Budget::INFINITE, |cx, clock, timer| async move {
        let channel = Channel::connect(format!("http://{address}")).await.unwrap();
        let exporter = OtlpGrpcExporter::new(channel)
            .unwrap()
            .try_with_timeout(Duration::from_secs(3))
            .unwrap();
        let policy = policy(3, Duration::from_secs(1), Duration::from_secs(1));
        let mut call =
            Box::pin(exporter.send_with_retry(&cx, OtlpGrpcSignal::Traces, BODY.to_vec(), &policy));
        let mut advanced = false;
        let error = poll_fn(|task| {
            *witness.waiter.lock().unwrap() = Some(task.waker().clone());
            let progress = call.as_mut().poll(task);
            if progress.is_pending() && witness.ready.load(Ordering::Acquire) && !advanced {
                advanced = true;
                clock.advance_to(Time::from_secs(3));
                let _ = timer.process_timers();
                task.waker().wake_by_ref();
            }
            progress
        })
        .await
        .unwrap_err();
        assert!(advanced);
        assert_eq!(error.kind(), OtlpGrpcErrorKind::RetryBudgetExhausted);
        assert!(timer.is_empty());
        assert_eq!(registrations(&cx), 0);
    });
    peer.join().unwrap();
    no_extra_connection(&listener);
}

#[test]
fn missing_timer_or_entropy_is_refused_before_native_io() {
    type NoTime = CapSet<true, false, true, true, true>;
    type NoEntropy = CapSet<true, true, false, true, true>;
    let (listener, address) = native::listener();
    native::run_native(|cx| async move {
        let channel = Channel::connect(format!("http://{address}")).await.unwrap();
        let exporter = OtlpGrpcExporter::new(channel).unwrap();
        for (mask, expected) in [
            (NoTime::MASK, OtlpGrpcErrorKind::RetryTimerUnavailable),
            (NoEntropy::MASK, OtlpGrpcErrorKind::RetryEntropyUnavailable),
        ] {
            let mut narrowed = cx.clone();
            narrowed.runtime_mask = mask;
            let error = exporter
                .send_with_retry(
                    &narrowed,
                    OtlpGrpcSignal::Metrics,
                    BODY.to_vec(),
                    &OtlpGrpcRetryPolicy::default(),
                )
                .await
                .unwrap_err();
            assert_eq!(error.kind(), expected);
            assert_eq!(registrations(&narrowed), 0);
        }
    });
    no_extra_connection(&listener);
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn virtual_backoff_never_wakes_early_and_cleans_up_before_future_drop() {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let cx = Cx::new_with_drivers(
        RegionId::new_for_test(0, 1),
        TaskId::new_for_test(0, 0),
        Budget::INFINITE,
        None,
        None,
        None,
        Some(timer.clone()),
        None,
    );
    let mut waiting = Box::pin(wait_delay(
        &cx,
        &timer,
        Time::from_secs(10),
        Duration::from_secs(3),
    ));
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut task = Context::from_waker(&waker);
    assert!(Pin::as_mut(&mut waiting).poll(&mut task).is_pending());
    assert_eq!(timer.next_deadline(), Some(Time::from_secs(3)));
    assert_eq!(registrations(&cx), 1);
    clock.advance_to(Time::from_nanos(2_999_999_999));
    assert_eq!(timer.process_timers(), 0);
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    assert_eq!(counter.0.load(Ordering::Acquire), 0);
    clock.advance_to(Time::from_secs(3));
    assert_eq!(timer.process_timers(), 1);
    assert!(counter.0.load(Ordering::Acquire) > 0);
    assert!(matches!(
        waiting.as_mut().poll(&mut task),
        Poll::Ready(Ok(()))
    ));
    assert!(timer.is_empty());
    assert_eq!(registrations(&cx), 0);
}
