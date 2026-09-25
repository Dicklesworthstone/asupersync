//! Native socket regressions for direct, caller-awaited metrics fan-out.
#![cfg(all(
    feature = "metrics",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::Cx;
use asupersync::observability::async_export::{
    AsyncExportOutcome, AsyncMultiExporter, MetricsExportBatch, OtlpSnapshotExporter,
};
use asupersync::observability::otel::{
    InMemoryExporter, MetricsSnapshot, OtlpHttpConfigBuilder,
};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use std::future::Future;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

fn native(workers: usize, test: impl FnOnce(Runtime) + Send + 'static) {
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
        .expect("direct OTLP export must not strand a native worker");
    thread.join().unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn request(listener: &TcpListener) -> (TcpStream, Vec<u8>) {
    listener.set_nonblocking(true).unwrap();
    let start = Instant::now();
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(start.elapsed() < Duration::from_secs(5), "client must connect");
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("collector accept failed: {error}"),
        }
    };
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
    assert!(head.starts_with("POST /v1/metrics "));
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .expect("bounded protobuf request length");
    assert!(length <= 4 * 1024 * 1024);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    (stream, body)
}

fn collector(response: &'static [u8]) -> (String, std::thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/v1/metrics", listener.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let (mut socket, body) = request(&listener);
        write!(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len(),
        )
        .unwrap();
        socket.write_all(response).unwrap();
        body
    });
    (endpoint, peer)
}

fn exporter(endpoint: String) -> OtlpSnapshotExporter {
    OtlpSnapshotExporter::from_config(OtlpHttpConfigBuilder::new(endpoint).build().unwrap())
}

fn snapshot() -> MetricsSnapshot {
    let mut snapshot = MetricsSnapshot::new();
    snapshot.add_counter("requests", vec![("route".into(), "/".into())], 42);
    snapshot.add_gauge("active", Vec::new(), -2);
    snapshot.add_histogram("duration", Vec::new(), 3, 1.5);
    snapshot
}

#[test]
fn direct_fanout_delivers_reference_decodable_metrics_with_explicit_epoch() {
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::metrics::v1::{metric::Data, number_data_point::Value};
    use prost::Message;

    for workers in [1, 2] {
        native(workers, |runtime| {
            let (endpoint, peer) = collector(&[]);
            let memory = Arc::new(InMemoryExporter::new());
            let multi = AsyncMultiExporter::try_new(vec![
                Box::new(exporter(endpoint)),
                Box::new(Arc::clone(&memory)),
            ])
            .unwrap();
            let snapshot = snapshot();
            let report = runtime.block_on(async {
                let cx = Cx::current().unwrap();
                multi
                    .export_all(&cx, MetricsExportBatch::new(&snapshot, 1000, 2000).unwrap())
                    .await
            });
            assert!(report.is_success(), "{report:?}");
            assert_eq!(report.succeeded(), 2);
            assert_eq!(memory.snapshots()[0].counters, snapshot.counters);
            let body = peer.join().unwrap();
            let decoded = ExportMetricsServiceRequest::decode(body.as_slice()).unwrap();
            let metrics = &decoded.resource_metrics[0].scope_metrics[0].metrics;
            assert_eq!(metrics.len(), 3);
            let Data::Sum(sum) = metrics[2].data.as_ref().unwrap() else {
                panic!("counter must be a cumulative sum");
            };
            assert_eq!(metrics[2].name, "requests");
            assert!(sum.is_monotonic);
            assert_eq!(sum.data_points[0].value, Some(Value::AsInt(42)));
            assert_eq!(sum.data_points[0].start_time_unix_nano, 1000);
            assert_eq!(sum.data_points[0].time_unix_nano, 2000);
            let Data::Gauge(gauge) = metrics[0].data.as_ref().unwrap() else {
                panic!("gauge must retain its own wire type");
            };
            assert_eq!(gauge.data_points[0].value, Some(Value::AsInt(-2)));
            assert_eq!(gauge.data_points[0].start_time_unix_nano, 0);
            let Data::Histogram(histogram) = metrics[1].data.as_ref().unwrap() else {
                panic!("histogram totals must not become synthetic quantiles");
            };
            assert_eq!(histogram.data_points[0].count, 3);
            assert_eq!(histogram.data_points[0].bucket_counts, vec![3]);
            assert!(histogram.data_points[0].explicit_bounds.is_empty());
        });
    }
}

#[test]
fn collector_partial_rejection_is_reported_but_does_not_suppress_later_destination() {
    for workers in [1, 2] {
        native(workers, |runtime| {
            // ExportMetricsServiceResponse.partial_success.rejected_data_points = 1.
            let (endpoint, peer) = collector(&[0x0a, 0x02, 0x08, 0x01]);
            let memory = Arc::new(InMemoryExporter::new());
            let multi = AsyncMultiExporter::try_new(vec![
                Box::new(exporter(endpoint)),
                Box::new(Arc::clone(&memory)),
            ])
            .unwrap();
            let snapshot = snapshot();
            let report = runtime.block_on(async {
                let cx = Cx::current().unwrap();
                multi
                    .export_all(&cx, MetricsExportBatch::new(&snapshot, 1000, 2000).unwrap())
                    .await
            });
            assert_eq!(report.failed(), 1);
            assert_eq!(report.succeeded(), 1);
            assert_eq!(report.not_attempted(), 0);
            let AsyncExportOutcome::Failed(error) = &report.outcomes()[0] else {
                panic!("collector rejection must not be reported as success");
            };
            assert!(error.to_string().contains("partial_success"));
            assert!(matches!(report.outcomes()[1], AsyncExportOutcome::Succeeded));
            assert_eq!(memory.snapshots().len(), 1);
            assert!(report.into_result().is_err());
            assert!(!peer.join().unwrap().is_empty());
        });
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("preflight must finish before network I/O"),
    }
}

#[test]
fn cancelled_direct_export_does_not_open_a_collector_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let exporter = exporter(format!("http://{}/v1/metrics", listener.local_addr().unwrap()));
    let cx = Cx::for_testing();
    cx.cancel_with(asupersync::types::CancelKind::User, None);
    let snapshot = snapshot();
    assert!(ready(exporter.export(
        &cx,
        MetricsExportBatch::new(&snapshot, 1000, 2000).unwrap(),
    ))
    .is_err());
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
}

#[test]
fn invalid_and_empty_snapshots_finish_before_network_io() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let exporter = exporter(format!("http://{}/v1/metrics", listener.local_addr().unwrap()));
    let cx = Cx::for_testing();
    let mut invalid = MetricsSnapshot::new();
    invalid.add_counter("overflow", Vec::new(), u64::MAX);
    assert!(ready(exporter.export(
        &cx,
        MetricsExportBatch::new(&invalid, 1000, 2000).unwrap(),
    ))
    .is_err());
    let empty = MetricsSnapshot::new();
    assert!(ready(exporter.export(
        &cx,
        MetricsExportBatch::new(&empty, 1000, 2000).unwrap(),
    ))
    .is_ok());
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
}
