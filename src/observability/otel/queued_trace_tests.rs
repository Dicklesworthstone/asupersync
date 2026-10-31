use super::*;

fn traces() -> OwnedOtlpTraces {
    OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new().with_max_spans_per_request(1))
        .expect("finite trace mapper")
}

#[test]
fn collection_admission_is_atomic_and_counts_the_inflight_request() {
    let exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/v1/traces");
    let traces = traces();
    let first = OtlpTraceSpanInput::new([1; 16], [1; 8], "first", 10, 20);
    let second = OtlpTraceSpanInput::new([1; 16], [2; 8], "second", 10, 20);
    for _ in 0..OTLP_EXPORT_QUEUE_MAX_BATCHES - 1 {
        assert_eq!(exporter.enqueue_owned_traces(&traces, &[first]).unwrap(), 1);
    }
    let before = exporter.queue_stats();
    assert!(exporter.enqueue_owned_traces(&traces, &[first, second]).is_err());
    assert_eq!(exporter.queue_stats(), before);

    let consumer = exporter.export_queue.consumer().unwrap();
    let delivery = exporter.export_queue.take().unwrap();
    assert!(exporter.enqueue_owned_traces(&traces, &[first, second]).is_err());
    assert_eq!(exporter.queue_stats().retained_batches, before.retained_batches);
    drop(delivery);
    assert_eq!(exporter.enqueue_owned_traces(&traces, &[first, second]).unwrap(), 2);
    assert_eq!(exporter.queue_stats().retained_batches, OTLP_EXPORT_QUEUE_MAX_BATCHES);
    assert_eq!(exporter.queue_stats().failed_batches, 1);
    drop(consumer);
}

#[test]
fn encoded_bytes_and_configuration_are_reserved_for_every_request() {
    let exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/v1/traces")
        .with_bearer_token("original-token");
    // Two individually bounded wire bodies exceed the retained-byte ceiling
    // once each captured configuration is included. No prefix may be queued.
    let requests = vec![
        vec![0; OWNED_OTLP_DEFAULT_REQUEST_BYTES],
        vec![0; OWNED_OTLP_DEFAULT_REQUEST_BYTES],
    ];
    assert!(exporter.export_queue.admit_traces(&exporter, requests).is_err());
    assert_eq!(exporter.queue_stats(), OtlpExportQueueStats::default());

    let span = OtlpTraceSpanInput::new([1; 16], [1; 8], "captured", 10, 20);
    // d0303fdeb refuses authentication headers on a plain-HTTP endpoint before
    // any encoding or admission, and this lane has no `tls` feature for an
    // https:// endpoint. Pin that refusal, then reserve the same encoded
    // collection through the queue admission enqueue_owned_traces delegates to.
    let refused = exporter.enqueue_owned_traces(&traces(), &[span]).unwrap_err();
    assert!(refused.message.contains("otlp.config.insecure_auth_transport"));
    assert_eq!(exporter.queue_stats(), OtlpExportQueueStats::default());
    let attributes = exporter
        .resource_attributes
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let requests = traces().collect(&[span], &attributes).unwrap().into_requests();
    assert_eq!(exporter.export_queue.admit_traces(&exporter, requests).unwrap(), 1);
    let later = exporter.clone().with_bearer_token("later-token");
    let delivery = later.export_queue.take().unwrap();
    let batch = delivery.batch.as_ref().unwrap();
    let Payload::Traces(body) = &batch.payload else {
        panic!("trace admission must retain the already encoded request");
    };
    assert_eq!(batch.config.auth_headers.len(), 1);
    assert_eq!(batch.config.auth_headers[0].value.0, "Bearer original-token");
    assert_eq!(batch.bytes, body.len() + config_bytes(&batch.config).unwrap());
    assert_eq!(later.queue_stats().retained_bytes, batch.bytes);
    drop(delivery);
    assert_eq!(later.queue_stats().retained_bytes, 0);
}

#[test]
fn invalid_late_span_admits_nothing_and_sampling_avoids_empty_batches() {
    let exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/v1/traces");
    let traces = traces();
    let first = OtlpTraceSpanInput::new([1; 16], [1; 8], "first", 10, 20);
    let invalid = OtlpTraceSpanInput::new([1; 16], [2; 8], "late-invalid", 20, 10);
    assert!(exporter.enqueue_owned_traces(&traces, &[first, invalid]).is_err());
    assert_eq!(exporter.queue_stats(), OtlpExportQueueStats::default());
    assert_eq!(exporter.enqueue_owned_traces(&traces, &[first.with_trace_flags(0)]).unwrap(), 0);
    assert_eq!(exporter.queue_stats(), OtlpExportQueueStats::default());
}
