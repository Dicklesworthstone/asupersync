use super::*;
use crate::grpc::Channel;
use crate::observability::otel::{OtlpGrpcExporter, PrivacyConfig};
use crate::observability::otlp_proto::common_and_resource::{AnyValueValue, KeyValue};
use opentelemetry::trace::{
    Event, Link, Span as _, SpanContext, TraceContextExt as _, TraceFlags, TraceId, Tracer as _,
    TracerProvider as _,
};
use opentelemetry::{Array, Context as SdkContext, KeyValue as SdkAttribute, Value};
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider, SpanEvents, SpanLinks};
use std::borrow::Cow;
use std::future::Future;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use std::time::UNIX_EPOCH;

type MappingResult = Result<OwnedOtlpPolicyOutput<Vec<Vec<u8>>>, OtlpSdkTraceError>;

fn context(id: u64, sampled: bool, remote: bool, state: TraceState) -> SpanContext {
    SpanContext::new(
        TraceId::from_bytes([0x11; 16]),
        SpanId::from_bytes(id.to_be_bytes()),
        if sampled {
            TraceFlags::SAMPLED
        } else {
            TraceFlags::default()
        },
        remote,
        state,
    )
}

fn span(id: u64, scope: &str) -> SpanData {
    SpanData {
        span_context: context(id, true, false, TraceState::default()),
        parent_span_id: SpanId::INVALID,
        parent_span_is_remote: false,
        span_kind: SpanKind::Internal,
        name: Cow::Borrowed("operation"),
        start_time: UNIX_EPOCH + Duration::from_secs(100),
        end_time: UNIX_EPOCH + Duration::from_secs(110),
        attributes: Vec::new(),
        dropped_attributes_count: 0,
        events: SpanEvents::default(),
        links: SpanLinks::default(),
        status: SdkStatus::Unset,
        instrumentation_scope: SdkScope::builder(scope.to_owned()).build(),
    }
}

fn resource() -> TraceResource {
    prepare_resource(
        &opentelemetry_sdk::Resource::builder_empty()
            .with_schema_url(
                [
                    SdkAttribute::new("service.name", "sdk-traces"),
                    SdkAttribute::new("resource.number", 7_i64),
                ],
                "https://example.test/resource",
            )
            .build(),
        &OtlpSdkTraceConfig::new(),
    )
    .unwrap()
}

fn map(spans: &[SpanData]) -> MappingResult {
    map_traces(
        spans,
        &resource(),
        &OwnedOtlpExportPolicy::new(),
        &OtlpSdkTraceConfig::new(),
    )
}

fn decode(output: &OwnedOtlpPolicyOutput<Vec<Vec<u8>>>) -> Vec<ExportTraceServiceRequest> {
    output
        .output()
        .iter()
        .map(|bytes| {
            ExportTraceServiceRequest::decode_from_bytes(
                bytes,
                crate::observability::otel::otlp_request_limits(MAX_BYTES),
            )
            .unwrap()
        })
        .collect()
}

fn all_spans(requests: &[ExportTraceServiceRequest]) -> Vec<&Span> {
    requests
        .iter()
        .flat_map(|request| &request.resource_spans)
        .flat_map(|resource| &resource.scope_spans)
        .flat_map(|scope| &scope.spans)
        .collect()
}

fn attribute<'a>(attributes: &'a [KeyValue], key: &str) -> Option<&'a AnyValueValue> {
    attributes
        .iter()
        .find(|attribute| attribute.key == key)?
        .value
        .as_ref()?
        .value
        .as_ref()
}

fn exporter() -> OtlpSdkSpanExporter {
    let mut connect = std::pin::pin!(Channel::connect("http://127.0.0.1:1"));
    let Poll::Ready(Ok(channel)) = connect
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("native channel construction performs no I/O");
    };
    OtlpSdkSpanExporter::new(QueuedOtlpGrpcExporter::new(
        OtlpGrpcExporter::new(channel).unwrap(),
    ))
}

#[test]
fn typed_sdk_spans_preserve_kinds_contexts_source_counts_and_schema_urls() {
    let kinds = [
        SpanKind::Internal,
        SpanKind::Server,
        SpanKind::Client,
        SpanKind::Producer,
        SpanKind::Consumer,
    ];
    let mut input: Vec<_> = kinds
        .into_iter()
        .enumerate()
        .map(|(index, kind)| {
            let mut span = span(u64::try_from(index + 1).unwrap(), "typed-scope");
            span.span_kind = kind;
            span.instrumentation_scope = SdkScope::builder("typed-scope")
                .with_version("2")
                .with_schema_url("https://example.test/scope")
                .with_attributes([SdkAttribute::new("scope.flag", true)])
                .build();
            span.attributes = vec![
                SdkAttribute::new("flag", true),
                SdkAttribute::new("integer", -7_i64),
                SdkAttribute::new("double", 1.5),
                SdkAttribute::new("text", "kept"),
                SdkAttribute::new("array", Value::Array(Array::I64(vec![2, 3]))),
            ];
            span
        })
        .collect();
    input[0].parent_span_id = SpanId::from_bytes([0x22; 8]);
    input[0].parent_span_is_remote = true;
    input[0].span_context = context(
        1,
        true,
        false,
        TraceState::from_key_value([("vendor", "value")]).unwrap(),
    );
    input[0].dropped_attributes_count = 3;
    input[0].events.events = vec![Event::new(
        "event",
        UNIX_EPOCH + Duration::from_secs(101),
        vec![SdkAttribute::new("event.flag", false)],
        4,
    )];
    input[0].events.dropped_count = 5;
    input[0].links.links = vec![Link::new(
        context(
            99,
            true,
            false,
            TraceState::from_key_value([("link", "value")]).unwrap(),
        ),
        vec![SdkAttribute::new("link.number", 8_i64)],
        6,
    )];
    input[0].links.dropped_count = 7;
    input[0].status = SdkStatus::Error {
        description: "failure".into(),
    };
    input[1].status = SdkStatus::Ok;
    let output = map(&input).unwrap();
    let decoded = decode(&output);
    assert_eq!(decoded.len(), 1);
    let group = &decoded[0].resource_spans[0];
    assert_eq!(group.schema_url, "https://example.test/resource");
    assert_eq!(
        attribute(
            &group.resource.as_ref().unwrap().attributes,
            "resource.number"
        ),
        Some(&AnyValueValue::Int(7))
    );
    let scope = &group.scope_spans[0];
    assert_eq!(scope.schema_url, "https://example.test/scope");
    assert_eq!(scope.scope.as_ref().unwrap().version, "2");
    assert_eq!(
        attribute(&scope.scope.as_ref().unwrap().attributes, "scope.flag"),
        Some(&AnyValueValue::Bool(true))
    );
    for (index, span) in scope.spans.iter().enumerate() {
        assert_eq!(span.kind, i32::try_from(index + 1).unwrap());
        assert_eq!(span.start_time_unix_nano, 100_000_000_000);
        assert_eq!(span.end_time_unix_nano, 110_000_000_000);
        assert_eq!(
            attribute(&span.attributes, "flag"),
            Some(&AnyValueValue::Bool(true))
        );
        assert_eq!(
            attribute(&span.attributes, "integer"),
            Some(&AnyValueValue::Int(-7))
        );
        assert_eq!(
            attribute(&span.attributes, "double"),
            Some(&AnyValueValue::Double(1.5))
        );
        let Some(AnyValueValue::Array(array)) = attribute(&span.attributes, "array") else {
            panic!("typed array");
        };
        assert_eq!(array.values[0].value, Some(AnyValueValue::Int(2)));
    }
    let span = &scope.spans[0];
    assert_eq!(span.flags, 0x301);
    assert_eq!(span.parent_span_id, [0x22; 8]);
    assert_eq!(span.trace_state, "vendor=value");
    assert_eq!(span.dropped_attributes_count, 3);
    assert_eq!(span.events[0].dropped_attributes_count, 4);
    assert_eq!(span.dropped_events_count, 5);
    assert_eq!(span.links[0].dropped_attributes_count, 6);
    assert_eq!(span.dropped_links_count, 7);
    assert_eq!(span.links[0].flags, 0x101);
    assert_eq!(span.links[0].trace_state, "link=value");
    assert_eq!(span.status.as_ref().unwrap().code, 2);
    assert_eq!(span.status.as_ref().unwrap().message, "failure");
    assert_eq!(scope.spans[1].status.as_ref().unwrap().code, 1);
    assert_eq!(scope.spans[2].status.as_ref().unwrap().code, 0);
    assert_eq!(*output.report(), OwnedOtlpPolicyReport::default());
}

struct Capture {
    resource: TraceResource,
    output: Arc<Mutex<Vec<MappingResult>>>,
}

impl fmt::Debug for Capture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Capture")
    }
}

impl SpanExporter for Capture {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        self.output.lock().unwrap().push(map_traces(
            &batch,
            &self.resource,
            &OwnedOtlpExportPolicy::new(),
            &OtlpSdkTraceConfig::new(),
        ));
        Ok(())
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        self.resource = prepare_resource(resource, &OtlpSdkTraceConfig::new()).unwrap();
    }
}

#[test]
fn actual_sdk_provider_supplies_resource_scope_and_last_attribute_update() {
    let output = Arc::new(Mutex::new(Vec::new()));
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(Capture {
            resource: TraceResource::empty(),
            output: Arc::clone(&output),
        })
        .with_sampler(Sampler::AlwaysOn)
        .with_resource(
            opentelemetry_sdk::Resource::builder_empty()
                .with_schema_url(
                    [SdkAttribute::new("service.name", "actual-sdk")],
                    "https://example.test/resource",
                )
                .build(),
        )
        .build();
    let tracer = provider.tracer_with_scope(
        SdkScope::builder("actual-scope")
            .with_schema_url("https://example.test/scope")
            .build(),
    );
    let parent =
        SdkContext::new().with_remote_span_context(context(99, true, true, TraceState::default()));
    let mut span = tracer
        .span_builder("actual-span")
        .with_start_time(UNIX_EPOCH + Duration::from_secs(100))
        .with_kind(SpanKind::Client)
        .start_with_context(&tracer, &parent);
    span.set_attribute(SdkAttribute::new("updated", "old"));
    span.set_attribute(SdkAttribute::new("updated", 9_i64));
    span.add_event_with_timestamp(
        "event",
        UNIX_EPOCH + Duration::from_secs(105),
        vec![
            SdkAttribute::new("updated", false),
            SdkAttribute::new("updated", true),
        ],
    );
    span.add_link(
        context(88, false, false, TraceState::default()),
        vec![
            SdkAttribute::new("updated", 1_i64),
            SdkAttribute::new("updated", 2_i64),
        ],
    );
    span.end_with_timestamp(UNIX_EPOCH + Duration::from_secs(110));
    provider.force_flush().unwrap();
    provider.shutdown().unwrap();
    let outputs = output.lock().unwrap();
    assert_eq!(outputs.len(), 1);
    let requests = decode(outputs[0].as_ref().unwrap());
    let resource = &requests[0].resource_spans[0];
    assert_eq!(
        attribute(
            &resource.resource.as_ref().unwrap().attributes,
            "service.name"
        ),
        Some(&AnyValueValue::String("actual-sdk".to_owned()))
    );
    assert_eq!(resource.schema_url, "https://example.test/resource");
    assert_eq!(
        resource.scope_spans[0].schema_url,
        "https://example.test/scope"
    );
    let spans = all_spans(&requests);
    assert_eq!(spans[0].flags, 0x301);
    assert_eq!(
        attribute(&spans[0].attributes, "updated"),
        Some(&AnyValueValue::Int(9))
    );
    assert_eq!(
        attribute(&spans[0].events[0].attributes, "updated"),
        Some(&AnyValueValue::Bool(true))
    );
    assert_eq!(
        attribute(&spans[0].links[0].attributes, "updated"),
        Some(&AnyValueValue::Int(2))
    );
    assert_eq!(
        spans[0].dropped_attributes_count, 0,
        "attribute replacement is not a producer drop"
    );
}

#[test]
fn explicit_unsampled_incomplete_lineage_and_outside_events_are_preserved() {
    let mut first = span(1, "scope");
    first.span_context = context(1, false, false, TraceState::default());
    first.parent_span_id = SpanId::from_bytes(77_u64.to_be_bytes());
    first.events.events = vec![
        Event::new("before", UNIX_EPOCH, Vec::new(), 0),
        Event::new(
            "after",
            UNIX_EPOCH + Duration::from_secs(200),
            Vec::new(),
            0,
        ),
    ];
    let mut child = span(2, "scope");
    child.parent_span_id = first.span_context.span_id();
    child.start_time = UNIX_EPOCH + Duration::from_secs(90);
    child.end_time = UNIX_EPOCH + Duration::from_secs(120);
    let requests = decode(&map(&[first, child]).unwrap());
    let spans = all_spans(&requests);
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[0].flags, 0x100);
    assert_eq!(spans[0].parent_span_id, 77_u64.to_be_bytes());
    assert_eq!(spans[0].events[0].time_unix_nano, 0);
    assert_eq!(spans[0].events[1].time_unix_nano, 200_000_000_000);
    assert_eq!(spans[1].start_time_unix_nano, 90_000_000_000);
    assert_eq!(spans[1].end_time_unix_nano, 120_000_000_000);
}

#[test]
fn shared_policy_preserves_types_and_adds_source_drop_counts() {
    let secret = "credential-private";
    let input_resource = prepare_resource(
        &opentelemetry_sdk::Resource::builder_empty()
            .with_attributes([
                SdkAttribute::new("service.name", "old"),
                SdkAttribute::new("secret", secret),
            ])
            .build(),
        &OtlpSdkTraceConfig::new(),
    )
    .unwrap();
    let mut input = span(1, "old-scope");
    input.instrumentation_scope = SdkScope::builder("old-scope")
        .with_attributes([
            SdkAttribute::new("secret", secret),
            SdkAttribute::new("typed", true),
        ])
        .build();
    input.name = Cow::Borrowed("operation credential-private");
    input.span_context = context(
        1,
        true,
        false,
        TraceState::from_key_value([("vendor", secret)]).unwrap(),
    );
    input.attributes = vec![
        SdkAttribute::new("secret", secret),
        SdkAttribute::new(
            "typed",
            Value::Array(Array::String(vec![secret.into(), "safe".into()])),
        ),
    ];
    input.dropped_attributes_count = 2;
    input.events.events = vec![Event::new(
        "event credential-private",
        UNIX_EPOCH + Duration::from_secs(105),
        vec![SdkAttribute::new("secret", secret)],
        3,
    )];
    input.links.links = vec![Link::new(
        context(
            9,
            true,
            false,
            TraceState::from_key_value([("vendor", secret)]).unwrap(),
        ),
        vec![SdkAttribute::new("secret", secret)],
        4,
    )];
    input.status = SdkStatus::Error {
        description: "error credential-private".into(),
    };
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_resource_attributes([("service.name".to_owned(), "override".to_owned())])
        .unwrap()
        .try_with_scope("policy-scope", "3")
        .unwrap()
        .try_with_privacy(
            PrivacyConfig::new()
                .with_drop_attribute("secret")
                .with_pii_pattern("credential-[a-z]+"),
        )
        .unwrap();
    let output = map_traces(
        &[input],
        &input_resource,
        &policy,
        &OtlpSdkTraceConfig::new(),
    )
    .unwrap();
    assert_eq!(output.report().dropped_attributes, 5);
    for bytes in output.output() {
        assert!(
            !bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes())
        );
    }
    let requests = decode(&output);
    let resource = &requests[0].resource_spans[0];
    assert_eq!(
        attribute(
            &resource.resource.as_ref().unwrap().attributes,
            "service.name"
        ),
        Some(&AnyValueValue::String("override".to_owned()))
    );
    assert_eq!(
        resource.resource.as_ref().unwrap().dropped_attributes_count,
        1
    );
    let scope = resource.scope_spans[0].scope.as_ref().unwrap();
    assert_eq!(scope.name, "policy-scope");
    assert_eq!(scope.version, "3");
    assert_eq!(
        attribute(&scope.attributes, "typed"),
        Some(&AnyValueValue::Bool(true))
    );
    assert_eq!(scope.dropped_attributes_count, 1);
    let span = &resource.scope_spans[0].spans[0];
    assert_eq!(span.dropped_attributes_count, 3);
    assert_eq!(span.events[0].dropped_attributes_count, 4);
    assert_eq!(span.links[0].dropped_attributes_count, 5);
    assert!(span.trace_state.is_empty());
    assert!(span.links[0].trace_state.is_empty());
    let Some(AnyValueValue::Array(array)) = attribute(&span.attributes, "typed") else {
        panic!("typed array");
    };
    assert_eq!(
        array.values[0].value,
        Some(AnyValueValue::String("[REDACTED]".to_owned()))
    );
    assert_eq!(
        array.values[1].value,
        Some(AnyValueValue::String("safe".to_owned()))
    );
}

#[test]
fn scope_overrides_keep_distinct_spans_and_each_scope_drop_count() {
    let mut first = span(1, "first");
    first.instrumentation_scope = SdkScope::builder("first")
        .with_attributes([SdkAttribute::new("secret", "value")])
        .build();
    let second = span(2, "second");
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_scope("combined", "")
        .unwrap()
        .try_with_privacy(PrivacyConfig::new().with_drop_attribute("secret"))
        .unwrap();
    let output = map_traces(
        &[first, second],
        &resource(),
        &policy,
        &OtlpSdkTraceConfig::new(),
    )
    .unwrap();
    let requests = decode(&output);
    assert_eq!(requests.len(), 1);
    assert_eq!(all_spans(&requests).len(), 2);
    let scopes = &requests[0].resource_spans[0].scope_spans;
    assert_eq!(scopes.len(), 2);
    let dropped: BTreeSet<_> = scopes
        .iter()
        .map(|scope| {
            let scope = scope.scope.as_ref().unwrap();
            assert_eq!(scope.name, "combined");
            scope.dropped_attributes_count
        })
        .collect();
    assert_eq!(dropped, BTreeSet::from([0, 1]));
}

#[test]
fn all_128_small_scopes_share_one_request_without_scope_loss() {
    let spans: Vec<_> = (1..=128)
        .map(|id| span(id, &format!("scope-{id}")))
        .collect();
    let output = map(&spans).unwrap();
    assert_eq!(output.output().len(), 1);
    let requests = decode(&output);
    assert_eq!(requests[0].resource_spans[0].scope_spans.len(), 128);
    assert_eq!(all_spans(&requests).len(), 128);
}

#[test]
fn request_byte_and_node_limits_split_only_at_complete_span_boundaries() {
    let spans: Vec<_> = (1..=100).map(|id| span(id, "one-scope")).collect();
    let config = OtlpSdkTraceConfig::new().with_max_request_bytes(512);
    let output = map_traces(&spans, &resource(), &OwnedOtlpExportPolicy::new(), &config).unwrap();
    assert!(output.output().len() > 1);
    assert!(output.output().iter().all(|bytes| bytes.len() <= 512));
    let requests = decode(&output);
    let encoded_spans = all_spans(&requests);
    assert_eq!(encoded_spans.len(), 100);
    let ids: BTreeSet<_> = encoded_spans
        .iter()
        .map(|span| span.span_id.clone())
        .collect();
    assert_eq!(ids.len(), 100);
    for span in encoded_spans {
        assert_eq!(span.start_time_unix_nano, 100_000_000_000);
        assert_eq!(span.end_time_unix_nano, 110_000_000_000);
    }
    let mut spans = [span(1, "scope"), span(2, "scope")];
    for span in &mut spans {
        span.attributes = (0..31)
            .map(|index| {
                SdkAttribute::new(
                    format!("array-{index}"),
                    Value::Array(Array::I64(vec![1; 100])),
                )
            })
            .collect();
    }
    let output = map(&spans).unwrap();
    assert_eq!(
        output.output().len(),
        2,
        "shared 4096-node envelope splits complete spans"
    );
    assert_eq!(all_spans(&decode(&output)).len(), 2);
}

#[test]
fn full_collection_refuses_late_invalid_data_and_duplicate_span_identity() {
    let mut invalid = span(2, "scope");
    invalid.attributes = vec![SdkAttribute::new("key", "x".repeat(4097))];
    assert_eq!(
        map(&[span(1, "scope"), invalid]).unwrap_err(),
        OtlpSdkTraceError::LimitExceeded
    );
    assert_eq!(
        map(&[span(1, "first"), span(1, "second")]).unwrap_err(),
        OtlpSdkTraceError::DuplicateSpan
    );
    let input = [span(1, "scope"), span(2, "scope")];
    assert_eq!(
        map_traces(
            &input,
            &resource(),
            &OwnedOtlpExportPolicy::new(),
            &OtlpSdkTraceConfig::new().with_max_spans(1)
        )
        .unwrap_err(),
        OtlpSdkTraceError::LimitExceeded
    );
    let mut oversized = span(1, "scope");
    oversized.attributes = (0..40)
        .map(|index| {
            SdkAttribute::new(
                format!("key-{index}"),
                Value::Array(Array::I64(vec![1; 128])),
            )
        })
        .collect();
    assert_eq!(
        map(&[oversized]).unwrap_err(),
        OtlpSdkTraceError::WireEnvelopeExceeded
    );
}

#[test]
fn trace_state_entry_and_aggregate_bounds_apply_before_header_allocation() {
    let over_entries =
        TraceState::from_key_value((0..33).map(|index| (format!("key{index}"), "x"))).unwrap();
    assert_eq!(
        trace_state_size(&over_entries),
        Err(OtlpSdkTraceError::InvalidTraceState)
    );
    let exact =
        TraceState::from_key_value([("a", "x".repeat(256)), ("b", "y".repeat(251))]).unwrap();
    assert_eq!(trace_state_size(&exact), Ok(512));
    assert_eq!(owned_trace_state(&exact).unwrap().len(), 512);
    let over_bytes =
        TraceState::from_key_value([("a", "x".repeat(256)), ("b", "y".repeat(252))]).unwrap();
    assert_eq!(
        trace_state_size(&over_bytes),
        Err(OtlpSdkTraceError::InvalidTraceState)
    );
    let duplicate = TraceState::from_key_value([("a", "first"), ("a", "second")]).unwrap();
    assert_eq!(
        trace_state_size(&duplicate),
        Err(OtlpSdkTraceError::InvalidTraceState)
    );
    let mut input = span(1, "scope");
    input.span_context = context(1, true, false, over_entries);
    assert_eq!(
        map(&[input]).unwrap_err(),
        OtlpSdkTraceError::InvalidTraceState
    );
}

#[test]
fn overwritten_raw_values_are_validated_and_scope_duplicates_remain_errors() {
    let mut input = span(1, "scope");
    input.attributes = vec![
        SdkAttribute::new("key", f64::NAN),
        SdkAttribute::new("key", 7_i64),
    ];
    assert_eq!(
        map(&[input]).unwrap_err(),
        OtlpSdkTraceError::InvalidNumericValue
    );
    let mut input = span(1, "scope");
    input.attributes = (0..129).map(|_| SdkAttribute::new("key", 1_i64)).collect();
    assert_eq!(
        map(&[input]).unwrap_err(),
        OtlpSdkTraceError::InvalidAttributes
    );
    let mut input = span(1, "scope");
    input.instrumentation_scope = SdkScope::builder("scope")
        .with_attributes([
            SdkAttribute::new("key", 1_i64),
            SdkAttribute::new("key", 2_i64),
        ])
        .build();
    assert_eq!(
        map(&[input]).unwrap_err(),
        OtlpSdkTraceError::InvalidAttributes
    );
}

#[test]
fn resource_setter_latches_static_failure_and_valid_update_recovers() {
    let mut exporter = exporter();
    let secret = "credential-private";
    let invalid = opentelemetry_sdk::Resource::builder_empty()
        .with_attribute(SdkAttribute::new("key", secret.repeat(400)))
        .build();
    exporter.set_resource(&invalid);
    assert!(matches!(
        exporter.resource,
        Err(OtlpSdkTraceError::LimitExceeded)
    ));
    assert!(!format!("{exporter:?}").contains(secret));
    exporter.set_resource(
        &opentelemetry_sdk::Resource::builder_empty()
            .with_attribute(SdkAttribute::new("key", 7_i64))
            .build(),
    );
    let resource = exporter.resource.as_ref().unwrap();
    assert_eq!(
        attribute(&resource.resource.attributes, "key"),
        Some(&AnyValueValue::Int(7))
    );
    assert_eq!(resource.resource.attributes.len(), 1);
    assert!(!format!("{exporter:?}").contains(secret));
}

#[test]
fn configuration_ids_timestamps_and_empty_batch_are_checked() {
    for config in [
        OtlpSdkTraceConfig::new().with_max_spans(0),
        OtlpSdkTraceConfig::new().with_max_scopes(MAX_SCOPES + 1),
        OtlpSdkTraceConfig::new().with_max_collection_bytes(0),
        OtlpSdkTraceConfig::new().with_max_request_bytes(MAX_BYTES + 1),
    ] {
        assert_eq!(
            config.validate(),
            Err(OtlpSdkTraceError::InvalidConfiguration)
        );
    }
    let mut invalid = span(1, "scope");
    invalid.span_context = SpanContext::NONE;
    assert_eq!(map(&[invalid]).unwrap_err(), OtlpSdkTraceError::InvalidSpan);
    let mut invalid = span(1, "scope");
    invalid.start_time = UNIX_EPOCH;
    assert_eq!(
        map(&[invalid]).unwrap_err(),
        OtlpSdkTraceError::InvalidTimestamp
    );
    let mut invalid = span(1, "scope");
    invalid.end_time = UNIX_EPOCH + Duration::from_secs(1);
    assert_eq!(
        map(&[invalid]).unwrap_err(),
        OtlpSdkTraceError::InvalidTimestamp
    );
    let empty = map(&[]).unwrap();
    assert!(empty.output().is_empty());
    assert_eq!(*empty.report(), OwnedOtlpPolicyReport::default());
}

#[test]
fn missing_managed_owner_is_immediate_and_future_remains_send() {
    let exporter = exporter();
    let mut future = std::pin::pin!(exporter.export(vec![span(1, "scope")]));
    let Poll::Ready(Err(error)) = future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("owner absence is immediate");
    };
    assert!(format!("{error}").contains("otlp.sdk.traces.owner_unavailable"));
    assert_eq!(exporter.queue().queue_stats().queue.queued_batches, 0);
    fn assert_send<T: Send>(_: T) {}
    assert_send(exporter.export(Vec::new()));
}
