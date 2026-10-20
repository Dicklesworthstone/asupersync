//! Native lifecycle contracts for the region-owned bounded OTLP consumer.
//!
//! Collector acknowledgements and actual Pending polls establish readiness;
//! elapsed wall time only bounds a broken journey. Every scenario runs on
//! current-thread/two-worker runtimes with unified and sharded state.
#![cfg(all(
    feature = "metrics",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::channel::oneshot;
use asupersync::cx::{ChildRegionSpec, Cx};
use asupersync::observability::otel::{
    ManagedOtlpError, ManagedOtlpOutcome, MetricsExporter, MetricsSnapshot,
    OTLP_EXPORT_QUEUE_MAX_BATCHES, OtlpHttpExporter, OtlpLogsHttpExporter,
    OtlpTraceSpanInput, OwnedOtlpTraceConfig, OwnedOtlpTraces,
};
use asupersync::runtime::{JoinError, RootDrainOutcome, RuntimeBuilder};
use asupersync::types::{CancelKind, CancelReason};
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::Poll;
use std::time::Duration;

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            for workers in [1, 2] {
                for sharded in [false, true] {
                    let builder = if workers == 1 {
                        RuntimeBuilder::current_thread()
                    } else {
                        RuntimeBuilder::new().worker_threads(workers)
                    };
                    let runtime = builder
                        .with_sharded_state(sharded)
                        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                        .build().unwrap();
                    runtime.block_on(async {
                        let root = Cx::current().unwrap();
                        let mut owner = root.spawn(scenario).unwrap();
                        owner.join(&root).await.unwrap();
                    });
                    let report = runtime.shutdown_drained(Duration::from_secs(5));
                    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                    assert_eq!(report.live_tasks, 0);
                    assert_eq!(report.pending_spawns, 0);
                    assert_eq!(report.pending_obligations, 0);
                }
            }
        }));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(45))
        .expect("managed OTLP service and descendants must retire");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn request(listener: &TcpListener) -> TcpStream {
    let (mut stream, _) = listener.accept().unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
        assert!(head.len() < 16_384);
    }
    let head = String::from_utf8(head).unwrap();
    assert!(head.starts_with("POST "));
    let length: usize = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().unwrap())
    }).unwrap();
    assert!(length < 4 * 1024 * 1024);
    stream.read_exact(&mut vec![0; length]).unwrap();
    stream
}

fn acknowledge(stream: &mut TcpStream) {
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
}

fn two_traces(exporter: &OtlpHttpExporter) {
    let traces = OwnedOtlpTraces::try_new(
        OwnedOtlpTraceConfig::new().with_max_spans_per_request(1),
    ).unwrap();
    let first = OtlpTraceSpanInput::new([1; 16], [1; 8], "first", 10, 20);
    let second = OtlpTraceSpanInput::new([1; 16], [2; 8], "second", 10, 20);
    assert_eq!(exporter.enqueue_owned_traces(&traces, &[first, second]).unwrap(), 2);
}

fn metric() -> MetricsSnapshot {
    let mut snapshot = MetricsSnapshot::new();
    snapshot.add_counter("requests", Vec::new(), 1);
    snapshot
}

async fn seal_and_drain(cx: Cx) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exporter = OtlpHttpExporter::new(format!("http://{}/v1/traces", listener.local_addr().unwrap()));
    two_traces(&exporter);
    let (arrived, mut arrival) = oneshot::channel();
    let (release, released) = mpsc::channel();
    let peer = std::thread::spawn(move || {
        let mut first = request(&listener);
        arrived.send_blocking(()).unwrap();
        released.recv_timeout(Duration::from_secs(5)).unwrap();
        acknowledge(&mut first);
        acknowledge(&mut request(&listener));
    });
    let mut service = exporter.spawn_queued(&cx, || panic!("traces retain their timestamps"))
        .await.unwrap();
    arrival.recv(&cx).await.unwrap();
    service.begin_drain();
    assert!(service.control().is_sealed());
    let traces = OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new()).unwrap();
    let span = OtlpTraceSpanInput::new([1; 16], [3; 8], "late", 10, 20);
    assert!(exporter.clone().enqueue_owned_traces(&traces, &[span])
        .unwrap_err().to_string().contains("otlp.queue.closed"));
    assert!(exporter.flush_queued(&cx, 1).await.unwrap_err()
        .to_string().contains("otlp.queue.consumer_busy"));
    {
        let mut observation = pin!(service.join(&cx));
        poll_fn(|task| {
            assert!(observation.as_mut().poll(task).is_pending(), "an unacknowledged request is not drained");
            Poll::Ready(())
        }).await;
    }
    release.send(()).unwrap();
    let report = service.join(&cx).await.unwrap();
    assert!(matches!(report.delivery, Some(ManagedOtlpOutcome::Drained)));
    assert!(report.task.is_ok());
    assert_ne!(report.region_id, cx.region_id());
    assert_ne!(report.task_id, cx.task_id());
    assert_eq!(report.queue.delivered_batches, 2);
    assert_eq!(report.queue.failed_batches, 0);
    assert_eq!(report.queue.retained_batches, 0);
    assert_eq!(report.queue.retained_bytes, 0);
    assert!(!report.queue.consumer_active);
    assert!(matches!(service.join(&cx).await, Err(ManagedOtlpError::AlreadyJoined)));
    peer.join().unwrap();
}

#[test]
fn graceful_seal_rejects_cloned_producers_and_waits_for_real_acknowledgements() {
    native(seal_and_drain);
}

async fn cancelled_observation(cx: Cx) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exporter = OtlpHttpExporter::new(format!("http://{}/v1/traces", listener.local_addr().unwrap()));
    two_traces(&exporter);
    let (arrived, mut arrival) = oneshot::channel();
    let (release, released) = mpsc::channel();
    let peer = std::thread::spawn(move || {
        let mut first = request(&listener);
        arrived.send_blocking(()).unwrap();
        released.recv_timeout(Duration::from_secs(5)).unwrap();
        acknowledge(&mut first);
        acknowledge(&mut request(&listener));
    });
    let mut service = exporter.spawn_queued(&cx, || 1).await.unwrap();
    arrival.recv(&cx).await.unwrap();
    let observer = Cx::for_testing();
    observer.cancel_with(CancelKind::User, Some("stop this observation"));
    assert!(matches!(service.join(&observer).await, Err(ManagedOtlpError::ObservationCancelled(_))));
    assert!(!service.control().is_sealed());
    assert_eq!(exporter.queue_stats().failed_batches, 0);
    service.begin_drain();
    release.send(()).unwrap();
    let report = service.join(&cx).await.unwrap();
    assert!(matches!(report.delivery, Some(ManagedOtlpOutcome::Drained)));
    assert_eq!(report.queue.delivered_batches, 2);
    assert_eq!(report.queue.failed_batches, 0);
    peer.join().unwrap();
}

#[test]
fn observation_cancellation_preserves_the_owned_service_and_later_join() {
    native(cancelled_observation);
}

async fn cancelled_owner(cx: Cx) {
    let boundary = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exporter = OtlpHttpExporter::new(format!("http://{}/v1/traces", listener.local_addr().unwrap()));
    two_traces(&exporter);
    let (arrived, mut arrival) = oneshot::channel();
    let peer = std::thread::spawn(move || {
        let mut socket = request(&listener);
        arrived.send_blocking(()).unwrap();
        assert_eq!(socket.read(&mut [0]).unwrap(), 0);
    });
    let mut service = exporter.spawn_queued(boundary.cx(), || 1).await.unwrap();
    arrival.recv(&cx).await.unwrap();
    boundary.cancel(CancelReason::user("stop OTLP owner")).unwrap();
    let report = service.join(&cx).await.unwrap();
    assert!(matches!(report.delivery, Some(ManagedOtlpOutcome::Cancelled(_))));
    assert_eq!(report.queue.delivered_batches, 0);
    assert_eq!(report.queue.failed_batches, 2);
    assert_eq!(report.queue.retained_batches, 0);
    assert_eq!(report.queue.retained_bytes, 0);
    assert!(!report.queue.consumer_active);
    boundary.close().await.unwrap();
    peer.join().unwrap();
}

#[test]
fn owner_cancellation_closes_inflight_io_and_accounts_for_unattempted_backlog() {
    native(cancelled_owner);
}

async fn cancelled_owner_task(cx: Cx) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exporter = OtlpHttpExporter::new(format!("http://{}/v1/traces", listener.local_addr().unwrap()));
    two_traces(&exporter);
    let (arrived, mut arrival) = oneshot::channel();
    let peer = std::thread::spawn(move || {
        let mut socket = request(&listener);
        arrived.send_blocking(()).unwrap();
        assert_eq!(socket.read(&mut [0]).unwrap(), 0);
    });
    let (publish, mut published) = oneshot::channel();
    let (ready, mut parked) = oneshot::channel();
    let producer = exporter.clone();
    let mut owner = cx.spawn(move |owner_cx| async move {
        let service = producer.spawn_queued(&owner_cx, || 1).await.unwrap();
        // The task that opened the service no longer owns its Rust handle.
        // Its live cancellation boundary must still stop the exporter.
        publish.send_blocking(service).unwrap();
        let mut ready = Some(ready);
        let mut cancelled = pin!(owner_cx.cancelled());
        poll_fn(|task| match cancelled.as_mut().poll(task) {
            Poll::Ready(()) => Poll::Ready(()),
            Poll::Pending => {
                if let Some(ready) = ready.take() {
                    ready.send_blocking(owner_cx.clone()).unwrap();
                }
                Poll::Pending
            }
        }).await;
        assert!(owner_cx.checkpoint().is_err());
    }).unwrap();
    let mut service = published.recv(&cx).await.unwrap();
    let owner_cx = parked.recv(&cx).await.unwrap();
    arrival.recv(&cx).await.unwrap();
    assert_eq!(owner_cx.region_id(), cx.region_id());
    owner.abort();
    let report = service.join(&cx).await.unwrap();
    assert!(matches!(report.delivery, Some(ManagedOtlpOutcome::Cancelled(_))));
    assert_eq!(report.queue.delivered_batches, 0);
    assert_eq!(report.queue.failed_batches, 2);
    assert_eq!(report.queue.retained_batches, 0);
    assert_eq!(report.queue.retained_bytes, 0);
    assert!(!report.queue.consumer_active);
    assert!(!cx.is_cancel_requested(), "the enclosing region was not cancelled");
    assert_ne!(report.task_id, owner.task_id());
    owner.join(&cx).await.unwrap();
    peer.join().unwrap();
}

#[test]
fn owner_task_abort_stops_inflight_delivery_after_the_handle_moves_elsewhere() {
    native(cancelled_owner_task);
}

async fn cancelled_before_start(cx: Cx) {
    let exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/v1/metrics");
    exporter.export(&metric()).unwrap();
    let producer = exporter.clone();
    let mut owner = cx.spawn(move |owner_cx| async move {
        owner_cx.cancel_with(CancelKind::User, Some("cancel before exporter admission"));
        owner_cx.cancelled().await;
        let before = producer.queue_stats();
        let error = producer.spawn_queued(&owner_cx, || panic!("cancelled owner ran clock"))
            .await.unwrap_err();
        assert!(matches!(error, ManagedOtlpError::Admission(_)));
        assert!(error.to_string().contains("otlp.queue.cancelled"));
        assert_eq!(producer.queue_stats(), before);
        // Acknowledge only in the owner task, after admission refused.
        assert!(owner_cx.checkpoint().is_err());
    }).unwrap();
    owner.join(&cx).await.unwrap();
    assert_eq!(exporter.queue_stats().retained_batches, 1);
    assert!(!exporter.queue_stats().consumer_active);
    // A fresh healthy owner can still claim and retire the original backlog.
    let mut service = exporter.spawn_queued(&cx, || 0).await.unwrap();
    service.abort();
    let report = service.join(&cx).await.unwrap();
    assert_eq!(report.queue.delivered_batches, 0);
    assert_eq!(report.queue.failed_batches, 1);
    assert_eq!(report.queue.retained_bytes, 0);
}

#[test]
fn already_cancelled_task_refuses_startup_without_consuming_queue_admission() {
    native(cancelled_before_start);
}

struct Dropped(Arc<AtomicUsize>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

async fn descendant(
    child: Cx,
    cleanup_owner: Cx,
    ready: oneshot::Sender<Cx>,
    cleanup_ready: oneshot::Sender<()>,
    mut release: oneshot::Receiver<()>,
    drops: Arc<AtomicUsize>,
) {
    let _dropped = Dropped(drops);
    let mut ready = Some(ready);
    let mut cancelled = pin!(child.cancelled());
    poll_fn(|task| match cancelled.as_mut().poll(task) {
        Poll::Ready(()) => Poll::Ready(()),
        Poll::Pending => {
            if let Some(ready) = ready.take() {
                ready.send_blocking(child.clone()).unwrap();
            }
            Poll::Pending
        }
    }).await;
    assert!(child.checkpoint().is_err(), "acknowledge cancellation before cleanup");
    let mut cleanup_ready = Some(cleanup_ready);
    let mut released = pin!(release.recv(&cleanup_owner));
    poll_fn(|task| match released.as_mut().poll(task) {
        Poll::Ready(result) => Poll::Ready(result.unwrap()),
        Poll::Pending => {
            if let Some(ready) = cleanup_ready.take() {
                ready.send_blocking(()).unwrap();
            }
            Poll::Pending
        }
    }).await;
}

async fn retained_close(cx: Cx) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exporter = OtlpHttpExporter::new(format!("http://{}/v1/metrics", listener.local_addr().unwrap()));
    exporter.export(&metric()).unwrap();
    let peer = std::thread::spawn(move || acknowledge(&mut request(&listener)));
    let (ready, mut parked) = oneshot::channel();
    let (cleanup_ready, mut cleanup_parked) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut setup = Some((cx.clone(), ready, cleanup_ready, released, Arc::clone(&drops)));
    let mut service = exporter.spawn_queued(&cx, move || {
        let actual = Cx::current().expect("clock runs in admitted OTLP task");
        let (owner, ready, cleanup_ready, released, drops) = setup.take().unwrap();
        actual.spawn(move |child| descendant(child, owner, ready, cleanup_ready, released, drops)).unwrap();
        100
    }).await.unwrap();
    let child = parked.recv(&cx).await.unwrap();
    assert_ne!(child.region_id(), cx.region_id());
    service.begin_drain();
    {
        let mut observing = pin!(service.join(&cx));
        let mut cleanup = pin!(cleanup_parked.recv(&cx));
        poll_fn(|task| {
            assert!(observing.as_mut().poll(task).is_pending(), "descendant is still owned");
            cleanup.as_mut().poll(task)
        }).await.unwrap();
    }
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let observer = Cx::for_testing();
    observer.cancel_with(CancelKind::User, Some("stop close observation"));
    assert!(matches!(service.join(&observer).await, Err(ManagedOtlpError::ObservationCancelled(_))));
    release.send_blocking(()).unwrap();
    let report = service.join(&cx).await.unwrap();
    assert!(matches!(report.delivery, Some(ManagedOtlpOutcome::Drained)));
    assert!(report.task.is_ok());
    assert_eq!(report.queue.delivered_batches, 1);
    assert_eq!(report.queue.retained_bytes, 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    peer.join().unwrap();
}

#[test]
fn join_retains_region_close_across_observer_cancellation_until_descendant_cleanup() {
    native(retained_close);
}

async fn panicked_controller(cx: Cx) {
    let exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/v1/metrics");
    exporter.export(&metric()).unwrap();
    exporter.export(&metric()).unwrap();
    let mut service = exporter.spawn_queued(&cx, || panic!("broken metrics clock")).await.unwrap();
    let report = service.join(&cx).await.unwrap();
    assert!(matches!(report.task, Err(JoinError::Panicked(_))));
    assert!(report.delivery.is_none());
    assert_eq!(report.queue.failed_batches, 2);
    assert_eq!(report.queue.delivered_batches, 0);
    assert_eq!(report.queue.retained_batches, 0);
    assert_eq!(report.queue.retained_bytes, 0);
    assert!(!report.queue.consumer_active);
    assert!(service.control().is_sealed());
    assert!(exporter.export(&metric()).unwrap_err().to_string().contains("otlp.queue.closed"));
}

#[test]
fn a_panicking_clock_closes_admission_and_reports_failed_owned_delivery() {
    native(panicked_controller);
}

async fn independent_abort(cx: Cx) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exporter = OtlpHttpExporter::new(format!("http://{}/v1/traces", listener.local_addr().unwrap()));
    for _ in 0..OTLP_EXPORT_QUEUE_MAX_BATCHES / 2 {
        two_traces(&exporter);
    }
    assert_eq!(exporter.queue_stats().retained_batches, OTLP_EXPORT_QUEUE_MAX_BATCHES);
    let (arrived, mut arrival) = oneshot::channel();
    let peer = std::thread::spawn(move || {
        let mut socket = request(&listener);
        arrived.send_blocking(()).unwrap();
        assert_eq!(socket.read(&mut [0]).unwrap(), 0);
    });
    let mut service = exporter.spawn_queued(&cx, || 1).await.unwrap();
    arrival.recv(&cx).await.unwrap();
    service.control().abort();
    let report = service.join(&cx).await.unwrap();
    assert!(matches!(report.delivery, Some(ManagedOtlpOutcome::Aborted)));
    assert!(report.task.is_ok());
    assert!(!cx.is_cancel_requested());
    assert_eq!(report.queue.delivered_batches, 0);
    assert_eq!(report.queue.failed_batches, OTLP_EXPORT_QUEUE_MAX_BATCHES as u64);
    assert_eq!(report.queue.retained_batches, 0);
    assert_eq!(report.queue.retained_bytes, 0);
    peer.join().unwrap();
}

#[test]
fn abort_control_interrupts_io_without_cancelling_the_service_owner() {
    native(independent_abort);
}

async fn dropped_handle(cx: Cx) {
    let boundary = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
    let exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/v1/metrics");
    exporter.export(&metric()).unwrap();
    let (ready, mut parked) = oneshot::channel();
    let (cleanup_ready, mut cleanup_parked) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut setup = Some((cx.clone(), ready, cleanup_ready, released, Arc::clone(&drops)));
    let service = exporter.spawn_queued(boundary.cx(), move || {
        let actual = Cx::current().unwrap();
        let (owner, ready, cleanup_ready, released, drops) = setup.take().unwrap();
        actual.spawn(move |child| descendant(child, owner, ready, cleanup_ready, released, drops)).unwrap();
        // Invalid time terminates before I/O; the descendant still needs the
        // real child-region close protocol after its controller has retired.
        0
    }).await.unwrap();
    parked.recv(&cx).await.unwrap();
    drop(service);
    let mut closing = pin!(boundary.close());
    {
        let mut cleanup = pin!(cleanup_parked.recv(&cx));
        poll_fn(|task| {
            assert!(closing.as_mut().poll(task).is_pending(), "Drop requests cleanup, not quiescence");
            cleanup.as_mut().poll(task)
        }).await.unwrap();
    }
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    release.send_blocking(()).unwrap();
    closing.await.unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(exporter.queue_stats().retained_batches, 0);
    assert_eq!(exporter.queue_stats().failed_batches, 1);
}

#[test]
fn dropping_the_handle_keeps_cleanup_owned_until_its_parent_reaches_quiescence() {
    native(dropped_handle);
}

async fn single_log_consumer(cx: Cx) {
    let exporter = OtlpLogsHttpExporter::new("http://127.0.0.1:4318/v1/logs");
    let mut service = exporter.spawn_queued(&cx).await.unwrap();
    let second = exporter.clone().spawn_queued(&cx).await;
    let Err(ManagedOtlpError::Admission(error)) = second else {
        panic!("one managed consumer must own the queue");
    };
    assert!(error.to_string().contains("otlp.queue.consumer_busy"));
    assert!(exporter.queue_stats().consumer_active);
    service.begin_drain();
    let report = service.join(&cx).await.unwrap();
    assert!(matches!(report.delivery, Some(ManagedOtlpOutcome::Drained)));
    assert!(report.task.is_ok());
    assert_eq!(report.queue.retained_batches, 0);
    assert_eq!(report.queue.failed_batches, 0);
    assert!(!report.queue.consumer_active);
}

#[test]
fn managed_log_queue_owns_one_consumer_and_drains_an_empty_service() {
    native(single_log_consumer);
}
