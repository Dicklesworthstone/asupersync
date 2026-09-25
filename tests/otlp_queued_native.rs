//! Real socket coverage for bounded OTLP composition (br-asupersync-bi2462.117).
#![cfg(all(
    feature = "metrics",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::Cx;
use asupersync::observability::otel::{
    ExportError, InMemoryExporter, LogsExporter, LogsSnapshot, MetricsExporter, MetricsSnapshot,
    MultiExporter, MultiLogsExporter, OtlpHttpExporter, OtlpLogRecord, OtlpLogsHttpExporter,
    StdoutExporter,
};
use asupersync::observability::{LogLevel, metrics::Metrics};
use asupersync::runtime::RuntimeBuilder;
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

fn native(workers: usize, test: impl FnOnce(asupersync::runtime::Runtime) + Send + 'static) {
    let (done, received) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let builder = if workers == 1 {
                RuntimeBuilder::current_thread()
            } else {
                RuntimeBuilder::multi_thread().worker_threads(workers)
            };
            let runtime = builder
                .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                .build()
                .unwrap();
            test(runtime);
        }));
        done.send(result).unwrap();
    });
    let result = received
        .recv_timeout(Duration::from_secs(15))
        .expect("native OTLP test must finish");
    thread.join().unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn request(listener: &TcpListener) -> (TcpStream, Vec<u8>) {
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
        assert!(head.len() < 16_384);
    }
    let head = String::from_utf8(head).unwrap();
    assert!(head.starts_with("POST "));
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .expect("bounded content length");
    assert!(length < 4 * 1024 * 1024);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    (stream, body)
}

fn acknowledge(stream: &mut TcpStream) {
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
}

struct SharedMemory(Arc<InMemoryExporter>);
impl MetricsExporter for SharedMemory {
    fn export(&self, snapshot: &MetricsSnapshot) -> Result<(), ExportError> {
        self.0.export(snapshot)
    }
    fn flush(&self) -> Result<(), ExportError> {
        self.0.flush()
    }
}

#[test]
fn multi_exporter_delivers_registry_snapshot_to_native_collector() {
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::metrics::v1::{metric::Data, number_data_point::Value};
    use prost::Message;
    for workers in [1, 2] {
        native(workers, |runtime| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}/v1/metrics", listener.local_addr().unwrap());
            let peer = std::thread::spawn(move || {
                let (mut socket, body) = request(&listener);
                acknowledge(&mut socket);
                body
            });
            let exporter = OtlpHttpExporter::new(endpoint);
            let memory = Arc::new(InMemoryExporter::new());
            let multi = MultiExporter::new(vec![
                Box::new(StdoutExporter::new()),
                Box::new(SharedMemory(memory.clone())),
                Box::new(exporter.clone()),
            ]);
            let mut registry = Metrics::new();
            registry.counter("requests").add(23);
            registry.gauge("active").set(2);
            registry.histogram("latency", vec![1.0, 5.0]).observe(3.0);
            let snapshot = registry.export_snapshot();
            multi.export(&snapshot).unwrap();
            assert!(
                multi
                    .flush()
                    .unwrap_err()
                    .to_string()
                    .contains("otlp.queue.pending")
            );
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                assert_eq!(exporter.flush_queued(&cx, 123_000).await.unwrap(), 1);
            });
            multi.flush().unwrap();
            assert_eq!(memory.snapshots()[0].counters, snapshot.counters);
            let body = peer.join().unwrap();
            let decoded = ExportMetricsServiceRequest::decode(body.as_slice()).unwrap();
            let metrics = &decoded.resource_metrics[0].scope_metrics[0].metrics;
            let requests = metrics
                .iter()
                .find(|metric| metric.name == "requests")
                .unwrap();
            match requests.data.as_ref().unwrap() {
                Data::Sum(sum) => {
                    assert_eq!(sum.data_points[0].value, Some(Value::AsInt(23)));
                    assert_eq!(sum.data_points[0].time_unix_nano, 123_000);
                }
                other => panic!("wrong metric type: {other:?}"),
            }
            assert_eq!(exporter.queue_stats().delivered_batches, 1);
            assert_eq!(exporter.queue_stats().retained_bytes, 0);
        });
    }
}

#[test]
fn multi_logs_exporter_delivers_without_async_context_at_admission() {
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::any_value::Value;
    use prost::Message;
    native(1, |runtime| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/v1/logs", listener.local_addr().unwrap());
        let peer = std::thread::spawn(move || {
            let (mut socket, body) = request(&listener);
            acknowledge(&mut socket);
            body
        });
        let exporter = OtlpLogsHttpExporter::new(endpoint);
        let multi = MultiLogsExporter::new(vec![Box::new(exporter.clone())]);
        let logs = LogsSnapshot::new("queued-native").with_record(OtlpLogRecord::new(
            LogLevel::Info,
            "actual queued log",
            100,
        ));
        multi.export(&logs).unwrap();
        assert!(multi.flush().is_err());
        runtime.block_on(async {
            exporter
                .flush_queued(&Cx::current().unwrap())
                .await
                .unwrap();
        });
        multi.flush().unwrap();
        let body = peer.join().unwrap();
        let decoded = ExportLogsServiceRequest::decode(body.as_slice()).unwrap();
        let record = &decoded.resource_logs[0].scope_logs[0].log_records[0];
        assert_eq!(record.time_unix_nano, 100);
        assert_eq!(
            record.body.as_ref().unwrap().value,
            Some(Value::StringValue("actual queued log".to_owned()))
        );
    });
}

#[test]
fn cancelled_parked_delivery_retires_once_and_keeps_later_batches() {
    for workers in [1, 2] {
        native(workers, |runtime| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}/v1/metrics", listener.local_addr().unwrap());
            let pending = Arc::new(AtomicBool::new(false));
            let polls = Arc::new(AtomicUsize::new(0));
            let peer_pending = pending.clone();
            let peer_polls = polls.clone();
            let owner = Cx::for_testing();
            let cancel_owner = owner.clone();
            let peer = std::thread::spawn(move || {
                let (mut socket, _) = request(&listener);
                // Only trigger after the whole HTTP request arrived and a
                // real Pending poll remains stable with all peer input silent.
                let start = Instant::now();
                loop {
                    let observed = peer_polls.load(Ordering::Acquire);
                    std::thread::sleep(Duration::from_millis(20));
                    if observed != 0
                        && peer_polls.load(Ordering::Acquire) == observed
                        && peer_pending.load(Ordering::Acquire)
                    {
                        break;
                    }
                    assert!(
                        start.elapsed() < Duration::from_secs(3),
                        "delivery must park"
                    );
                }
                cancel_owner.cancel_with(
                    asupersync::types::CancelKind::User,
                    Some("queued delivery cancelled"),
                );
                let mut byte = [0];
                assert_eq!(
                    socket.read(&mut byte).unwrap(),
                    0,
                    "cancellation closes in-flight request"
                );
                // A second fresh request is the later batch, not a retry of
                // the delivery whose collector acceptance became uncertain.
                let (mut socket, _) = request(&listener);
                acknowledge(&mut socket);
            });
            let exporter = OtlpHttpExporter::new(endpoint).with_timeout(Duration::from_secs(10));
            let mut snapshot = MetricsSnapshot::new();
            snapshot.add_counter("requests", Vec::new(), 1);
            exporter.export(&snapshot).unwrap();
            snapshot.counters[0].2 = 2;
            exporter.export(&snapshot).unwrap();
            runtime.block_on(async {
                let mut future = std::pin::pin!(exporter.flush_queued(&owner, 100));
                let result = poll_fn(|cx| {
                    pending.store(false, Ordering::Release);
                    polls.fetch_add(1, Ordering::AcqRel);
                    let result = future.as_mut().poll(cx);
                    pending.store(result.is_pending(), Ordering::Release);
                    result
                })
                .await;
                assert!(result.unwrap_err().to_string().contains("cancel"));
            });
            assert_eq!(exporter.queue_stats().failed_batches, 1);
            assert_eq!(exporter.queue_stats().queued_batches, 1);
            assert!(!exporter.queue_stats().consumer_active);
            runtime.block_on(async {
                assert_eq!(
                    exporter
                        .flush_queued(&Cx::current().unwrap(), 101)
                        .await
                        .unwrap(),
                    1
                );
            });
            peer.join().unwrap();
            assert_eq!(exporter.queue_stats().delivered_batches, 1);
            assert_eq!(exporter.queue_stats().retained_batches, 0);
            assert_eq!(exporter.queue_stats().retained_bytes, 0);
            assert!(
                exporter
                    .flush()
                    .unwrap_err()
                    .to_string()
                    .contains("delivery_failed")
            );
        });
    }
}

#[test]
fn caller_owned_sender_wakes_for_admission_and_cancels_while_idle() {
    for workers in [1, 2] {
        native(workers, |runtime| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let exporter = OtlpHttpExporter::new(format!(
                "http://{}/v1/metrics",
                listener.local_addr().unwrap()
            ));
            let producer = exporter.clone();
            let owner = Cx::for_testing();
            let cancel_owner = owner.clone();
            let pending = Arc::new(AtomicBool::new(false));
            let peer_pending = pending.clone();
            let peer = std::thread::spawn(move || {
                let start = Instant::now();
                while !peer_pending.load(Ordering::Acquire) {
                    assert!(
                        start.elapsed() < Duration::from_secs(3),
                        "sender did not park"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                let mut snapshot = MetricsSnapshot::new();
                snapshot.add_counter("admitted.after.park", Vec::new(), 1);
                producer.export(&snapshot).unwrap();
                let (mut socket, _) = request(&listener);
                acknowledge(&mut socket);
                drop(socket);
                while producer.queue_stats().delivered_batches != 1
                    || !peer_pending.load(Ordering::Acquire)
                {
                    assert!(
                        start.elapsed() < Duration::from_secs(5),
                        "sender did not complete delivery"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                cancel_owner.cancel_with(
                    asupersync::types::CancelKind::User,
                    Some("stop idle sender"),
                );
            });
            runtime.block_on(async {
                let mut sender = std::pin::pin!(exporter.run_queued(&owner, || 100));
                let result = poll_fn(|cx| {
                    pending.store(false, Ordering::Release);
                    let result = sender.as_mut().poll(cx);
                    pending.store(result.is_pending(), Ordering::Release);
                    result
                })
                .await;
                assert!(result.unwrap_err().to_string().contains("cancelled"));
            });
            peer.join().unwrap();
            assert_eq!(exporter.queue_stats().delivered_batches, 1);
            assert_eq!(exporter.queue_stats().failed_batches, 0);
            assert!(!exporter.queue_stats().consumer_active);
            exporter.flush().unwrap();
        });
    }
}
