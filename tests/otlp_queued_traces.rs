//! Actual collector delivery for atomic queued trace collections.
//! br-asupersync-5z2scg.2.7. Source-only additions; execution requires RCH.
#![cfg(all(feature = "metrics", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::Cx;
use asupersync::observability::otel::{
    OtlpHttpExporter, OtlpTraceSpanInput, OwnedOtlpTraceConfig, OwnedOtlpTraces,
};
use asupersync::runtime::RuntimeBuilder;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use prost::Message;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

fn native(workers: usize, test: impl FnOnce(asupersync::runtime::Runtime) + Send + 'static) {
    let (done, received) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let builder = if workers == 1 {
                RuntimeBuilder::current_thread()
            } else {
                RuntimeBuilder::multi_thread().worker_threads(workers)
            };
            let runtime = builder
                .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                .build().unwrap();
            test(runtime);
        }));
        done.send(result).unwrap();
    });
    let result = received.recv_timeout(Duration::from_secs(15)).expect("trace delivery watchdog");
    worker.join().unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn request(listener: &TcpListener) -> (TcpStream, String, ExportTraceServiceRequest) {
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
    assert!(head.starts_with("POST /v1/traces "));
    let length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
    }).unwrap();
    assert!(length < 4 * 1024 * 1024);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    (stream, head, ExportTraceServiceRequest::decode(body.as_slice()).unwrap())
}

fn reply(stream: &mut TcpStream, body: &[u8]) {
    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    stream.write_all(body).unwrap();
}

#[test]
fn queued_traces_preserve_order_timestamps_and_admission_config_over_http() {
    for workers in [1, 2] {
        native(workers, |runtime| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let exporter = OtlpHttpExporter::new(format!("http://{}/v1/traces", listener.local_addr().unwrap()));
            let peer = std::thread::spawn(move || {
                let mut spans = Vec::new();
                for _ in 0..2 {
                    let (mut socket, head, request) = request(&listener);
                    assert!(!head.lines().any(|line| line.to_ascii_lowercase().starts_with("authorization:")));
                    spans.extend(request.resource_spans[0].scope_spans[0].spans.clone());
                    reply(&mut socket, &[]);
                }
                spans
            });
            let traces = OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new().with_max_spans_per_request(1)).unwrap();
            let parent = OtlpTraceSpanInput::new([1; 16], [1; 8], "parent", 100, 500);
            let child = OtlpTraceSpanInput::new([1; 16], [2; 8], "child", 200, 400).with_parent_span_id([1; 8]);
            // Credentials on a plaintext endpoint are refused before admission
            // (d0303fdeb), so a credentialed clone of the queue admits nothing.
            let credentialed = exporter.clone().with_bearer_token("test-original-credential");
            let refused = credentialed.enqueue_owned_traces(&traces, &[child, parent]).unwrap_err();
            assert!(refused.to_string().contains("otlp.config.insecure_auth_transport"));
            assert_eq!(exporter.queue_stats().queued_batches, 0);
            assert_eq!(exporter.queue_stats().retained_bytes, 0);
            assert_eq!(exporter.enqueue_owned_traces(&traces, &[child, parent]).unwrap(), 2);
            // Delivery uses the configuration captured at admission, so a
            // credential added after admission never reaches the collector.
            let changed = exporter.clone().with_bearer_token("test-later-credential");
            runtime.block_on(async {
                assert_eq!(changed.flush_queued(&Cx::current().unwrap(), 999).await.unwrap(), 2);
            });
            let spans = peer.join().unwrap();
            assert_eq!(spans.iter().map(|span| span.name.as_str()).collect::<Vec<_>>(), ["parent", "child"]);
            assert_eq!(spans[0].start_time_unix_nano, 100);
            assert_eq!(spans[1].start_time_unix_nano, 200);
            assert_eq!(spans[1].parent_span_id, [1; 8]);
            assert_eq!(changed.queue_stats().delivered_batches, 2);
            assert_eq!(changed.queue_stats().failed_batches, 0);
            assert_eq!(changed.queue_stats().retained_bytes, 0);
        });
    }
}

#[test]
fn partial_rejection_is_terminal_and_does_not_replay_the_collection_prefix() {
    native(1, |runtime| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let exporter = OtlpHttpExporter::new(format!("http://{}/v1/traces", listener.local_addr().unwrap()));
        let peer = std::thread::spawn(move || {
            let (mut first, _, first_request) = request(&listener);
            // ExportTraceServiceResponse.partial_success.rejected_spans = 1.
            reply(&mut first, b"\x0a\x02\x08\x01");
            let (mut second, _, second_request) = request(&listener);
            reply(&mut second, &[]);
            [first_request, second_request].map(|request| request.resource_spans[0].scope_spans[0].spans[0].name.clone())
        });
        let traces = OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new().with_max_spans_per_request(1)).unwrap();
        let first = OtlpTraceSpanInput::new([1; 16], [1; 8], "first", 10, 20);
        let second = OtlpTraceSpanInput::new([1; 16], [2; 8], "second", 10, 20);
        exporter.enqueue_owned_traces(&traces, &[first, second]).unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let error = exporter.flush_queued(&cx, 1).await.unwrap_err();
            assert!(error.to_string().contains("partial_success"));
            assert_eq!(exporter.queue_stats().failed_batches, 1);
            assert_eq!(exporter.queue_stats().queued_batches, 1);
            assert_eq!(exporter.flush_queued(&cx, 1).await.unwrap(), 1);
        });
        assert_eq!(peer.join().unwrap(), ["first", "second"]);
        assert_eq!(exporter.queue_stats().delivered_batches, 1);
        assert_eq!(exporter.queue_stats().failed_batches, 1);
        assert_eq!(exporter.queue_stats().retained_bytes, 0);
    });
}
