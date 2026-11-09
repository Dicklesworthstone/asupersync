use super::*;
use crate::grpc::Channel;
use crate::observability::otel::{OtlpGrpcExporter, PrivacyConfig};
use crate::observability::otlp_proto::common_and_resource::{AnyValueValue, KeyValue};
use opentelemetry::logs::{AnyValue as LogValue, LogRecord as _, Logger as _, LoggerProvider as _};
use opentelemetry::{Key, KeyValue as SdkAttribute, SpanId, TraceFlags, TraceId};
use opentelemetry_sdk::logs::{SdkLogger, SdkLoggerProvider};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use std::time::UNIX_EPOCH;

type MappingResult = Result<OwnedOtlpPolicyOutput<Vec<Vec<u8>>>, OtlpSdkLogError>;

fn logger() -> SdkLogger {
    SdkLoggerProvider::builder()
        .with_resource(opentelemetry_sdk::Resource::builder_empty().build())
        .build()
        .logger("fixture")
}

fn resource() -> SdkResource {
    SdkResource::prepare(
        &opentelemetry_sdk::Resource::builder_empty()
            .with_schema_url(
                [
                    SdkAttribute::new("service.name", "sdk-logs"),
                    SdkAttribute::new("resource.number", 7_i64),
                ],
                "https://example.test/resource",
            )
            .build(),
        MAX_BYTES,
    )
    .unwrap()
}

fn map(records: &[(&SdkLogRecord, &SdkScope)]) -> MappingResult {
    map_logs(
        &LogBatch::new(records),
        &resource(),
        &OwnedOtlpExportPolicy::new(),
        &OtlpSdkLogConfig::new(),
    )
}

fn decode(output: &OwnedOtlpPolicyOutput<Vec<Vec<u8>>>) -> Vec<ExportLogsServiceRequest> {
    output
        .output()
        .iter()
        .map(|bytes| {
            ExportLogsServiceRequest::decode_from_bytes(
                bytes,
                crate::observability::otel::otlp_request_limits(MAX_BYTES),
            )
            .unwrap()
        })
        .collect()
}

fn all_records(requests: &[ExportLogsServiceRequest]) -> Vec<&LogRecord> {
    requests
        .iter()
        .flat_map(|request| &request.resource_logs)
        .flat_map(|resource| &resource.scope_logs)
        .flat_map(|scope| &scope.log_records)
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

fn exporter() -> OtlpSdkLogExporter {
    let mut connect = std::pin::pin!(Channel::connect("http://127.0.0.1:1"));
    let Poll::Ready(Ok(channel)) = connect
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("native channel construction performs no I/O");
    };
    OtlpSdkLogExporter::new(QueuedOtlpGrpcExporter::new(
        OtlpGrpcExporter::new(channel).unwrap(),
    ))
}

#[test]
fn typed_records_preserve_nested_values_correlation_and_distinct_schema_urls() {
    let logger = logger();
    let mut record = logger.create_log_record();
    record.set_timestamp(UNIX_EPOCH + Duration::from_secs(100));
    record.set_observed_timestamp(UNIX_EPOCH + Duration::from_secs(101));
    record.set_event_name("typed-event");
    record.set_severity_number(Severity::Warn2);
    record.set_severity_text("WARN2");
    record.set_trace_context(
        TraceId::from_bytes([0x11; 16]),
        SpanId::from_bytes([0x22; 8]),
        Some(TraceFlags::SAMPLED),
    );
    record.add_attribute("updated", "old");
    record.add_attribute("updated", 9_i64);
    record.add_attribute("flag", true);
    record.add_attribute("double", 1.5);
    record.set_body(LogValue::Map(Box::new(HashMap::from([
        (Key::new("integer"), LogValue::Int(i64::MIN)),
        (Key::new("double"), LogValue::Double(2.5)),
        (Key::new("text"), LogValue::from("kept")),
        (Key::new("flag"), LogValue::Boolean(false)),
        (
            Key::new("bytes"),
            LogValue::Bytes(Box::new(vec![0, 255, 1])),
        ),
        (
            Key::new("nested"),
            LogValue::ListAny(Box::new(vec![LogValue::Int(2), LogValue::Boolean(true)])),
        ),
    ]))));
    let scope = SdkScope::builder("typed-scope")
        .with_version("2")
        .with_schema_url("https://example.test/scope")
        .with_attributes([SdkAttribute::new("scope.flag", true)])
        .build();
    let output = map(&[(&record, &scope)]).unwrap();
    let requests = decode(&output);
    assert_eq!(requests.len(), 1);
    let group = &requests[0].resource_logs[0];
    assert_eq!(group.schema_url, "https://example.test/resource");
    assert_eq!(
        attribute(
            &group.resource.as_ref().unwrap().attributes,
            "resource.number"
        ),
        Some(&AnyValueValue::Int(7))
    );
    let scope = &group.scope_logs[0];
    assert_eq!(scope.schema_url, "https://example.test/scope");
    assert_eq!(scope.scope.as_ref().unwrap().version, "2");
    assert_eq!(
        attribute(&scope.scope.as_ref().unwrap().attributes, "scope.flag"),
        Some(&AnyValueValue::Bool(true))
    );
    let record = &scope.log_records[0];
    assert_eq!(record.time_unix_nano, 100_000_000_000);
    assert_eq!(record.observed_time_unix_nano, 101_000_000_000);
    assert_eq!(record.event_name, "typed-event");
    assert_eq!(record.severity_number, 14);
    assert_eq!(record.severity_text, "WARN2");
    assert_eq!(record.trace_id, [0x11; 16]);
    assert_eq!(record.span_id, [0x22; 8]);
    assert_eq!(record.flags, 1);
    assert_eq!(record.attributes.len(), 3);
    assert_eq!(
        attribute(&record.attributes, "updated"),
        Some(&AnyValueValue::Int(9))
    );
    assert_eq!(
        attribute(&record.attributes, "flag"),
        Some(&AnyValueValue::Bool(true))
    );
    assert_eq!(
        attribute(&record.attributes, "double"),
        Some(&AnyValueValue::Double(1.5))
    );
    assert_eq!(record.dropped_attributes_count, 0);
    let Some(AnyValueValue::KeyValueList(body)) = &record.body.as_ref().unwrap().value else {
        panic!("typed map body");
    };
    assert_eq!(
        attribute(&body.values, "integer"),
        Some(&AnyValueValue::Int(i64::MIN))
    );
    assert_eq!(
        attribute(&body.values, "double"),
        Some(&AnyValueValue::Double(2.5))
    );
    assert_eq!(
        attribute(&body.values, "text"),
        Some(&AnyValueValue::String("kept".into()))
    );
    assert_eq!(
        attribute(&body.values, "flag"),
        Some(&AnyValueValue::Bool(false))
    );
    assert_eq!(
        attribute(&body.values, "bytes"),
        Some(&AnyValueValue::Bytes(vec![0, 255, 1]))
    );
    let Some(AnyValueValue::Array(nested)) = attribute(&body.values, "nested") else {
        panic!("typed mixed array");
    };
    assert_eq!(nested.values[0].value, Some(AnyValueValue::Int(2)));
    assert_eq!(nested.values[1].value, Some(AnyValueValue::Bool(true)));
    assert_eq!(*output.report(), OwnedOtlpPolicyReport::default());
}

struct Capture {
    resource: SdkResource,
    outputs: Arc<Mutex<Vec<MappingResult>>>,
}

impl fmt::Debug for Capture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Capture")
    }
}

impl LogExporter for Capture {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        self.outputs.lock().unwrap().push(map_logs(
            &batch,
            &self.resource,
            &OwnedOtlpExportPolicy::new(),
            &OtlpSdkLogConfig::new(),
        ));
        Ok(())
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        self.resource = SdkResource::prepare(resource, MAX_BYTES).unwrap();
    }
}

#[test]
fn actual_sdk_provider_supplies_resource_scope_and_observed_time() {
    let outputs = Arc::new(Mutex::new(Vec::new()));
    let provider = SdkLoggerProvider::builder()
        .with_simple_exporter(Capture {
            resource: SdkResource::empty(),
            outputs: Arc::clone(&outputs),
        })
        .with_resource(
            opentelemetry_sdk::Resource::builder_empty()
                .with_schema_url(
                    [SdkAttribute::new("service.name", "actual-sdk")],
                    "https://example.test/provider",
                )
                .build(),
        )
        .build();
    let logger = provider.logger_with_scope(
        SdkScope::builder("actual-scope")
            .with_schema_url("https://example.test/instrumentation")
            .build(),
    );
    let mut record = logger.create_log_record();
    assert!(record.observed_timestamp().is_none());
    record.add_attribute("updated", false);
    record.add_attribute("updated", true);
    logger.emit(record);
    provider.force_flush().unwrap();
    provider.shutdown().unwrap();
    let outputs = outputs.lock().unwrap();
    assert_eq!(outputs.len(), 1, "simple shutdown does not reexport logs");
    let requests = decode(outputs[0].as_ref().unwrap());
    let group = &requests[0].resource_logs[0];
    assert_eq!(group.schema_url, "https://example.test/provider");
    assert_eq!(
        attribute(&group.resource.as_ref().unwrap().attributes, "service.name"),
        Some(&AnyValueValue::String("actual-sdk".into()))
    );
    assert_eq!(
        group.scope_logs[0].schema_url,
        "https://example.test/instrumentation"
    );
    let record = &group.scope_logs[0].log_records[0];
    assert_eq!(record.time_unix_nano, 0);
    assert!(record.observed_time_unix_nano > 0);
    assert_eq!(
        attribute(&record.attributes, "updated"),
        Some(&AnyValueValue::Bool(true))
    );
}

#[test]
fn target_overrides_name_without_erasing_other_scope_metadata() {
    let logger = logger();
    let mut first = logger.create_log_record();
    first.set_target("component");
    let second = first.clone();
    let first_scope = SdkScope::builder("original")
        .with_version("1")
        .with_schema_url("https://example.test/v1")
        .with_attributes([SdkAttribute::new("flag", false)])
        .build();
    let second_scope = SdkScope::builder("original")
        .with_version("2")
        .with_schema_url("https://example.test/v2")
        .with_attributes([SdkAttribute::new("flag", true)])
        .build();
    let entries = [(&first, &first_scope), (&second, &second_scope)];
    let output = map(&entries).unwrap();
    let requests = decode(&output);
    let scopes = &requests[0].resource_logs[0].scope_logs;
    assert_eq!(scopes.len(), 2);
    for (index, group) in scopes.iter().enumerate() {
        assert_eq!(group.scope.as_ref().unwrap().name, "component");
        assert_eq!(
            group.scope.as_ref().unwrap().version,
            (index + 1).to_string()
        );
        assert_eq!(
            group.schema_url,
            format!("https://example.test/v{}", index + 1)
        );
    }
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_scope("policy", "3")
        .unwrap();
    let output = map_logs(
        &LogBatch::new(&entries),
        &resource(),
        &policy,
        &OtlpSdkLogConfig::new(),
    )
    .unwrap();
    let requests = decode(&output);
    let scopes = &requests[0].resource_logs[0].scope_logs;
    assert_eq!(scopes.len(), 2);
    assert!(
        scopes
            .iter()
            .all(|group| group.scope.as_ref().unwrap().name == "policy")
    );
    assert!(
        scopes
            .iter()
            .all(|group| group.scope.as_ref().unwrap().version == "3")
    );
    assert_ne!(scopes[0].schema_url, scopes[1].schema_url);
}

#[test]
fn privacy_visits_nested_strings_and_keys_while_bytes_stay_opaque() {
    let logger = logger();
    let mut record = logger.create_log_record();
    record.set_event_name("event credential-private");
    record.set_severity_text("WARN credential-private");
    record.add_attribute("secret", "credential-private");
    record.add_attribute("owner", "credential-private");
    record.set_body(LogValue::Map(Box::new(HashMap::from([
        (Key::new("secret"), LogValue::from("credential-private")),
        (Key::new("text"), LogValue::from("credential-private")),
        (
            Key::new("bytes"),
            LogValue::Bytes(Box::new(b"credential-private".to_vec())),
        ),
        (
            Key::new("nested"),
            LogValue::ListAny(Box::new(vec![
                LogValue::Boolean(true),
                LogValue::Int(7),
                LogValue::from("credential-private"),
            ])),
        ),
    ]))));
    let scope = SdkScope::builder("scope").build();
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_privacy(
            PrivacyConfig::new()
                .with_drop_attribute("secret")
                .with_pii_pattern("credential-[a-z]+"),
        )
        .unwrap();
    let output = map_logs(
        &LogBatch::new(&[(&record, &scope)]),
        &resource(),
        &policy,
        &OtlpSdkLogConfig::new(),
    )
    .unwrap();
    assert_eq!(output.report().dropped_attributes, 1);
    assert_eq!(output.report().dropped_log_body_fields, 1);
    assert_eq!(output.report().redacted_values, 5);
    let requests = decode(&output);
    let record = all_records(&requests)[0];
    assert_eq!(record.event_name, "event [REDACTED]");
    assert_eq!(record.severity_text, "WARN [REDACTED]");
    assert_eq!(record.dropped_attributes_count, 1);
    assert_eq!(attribute(&record.attributes, "secret"), None);
    assert_eq!(
        attribute(&record.attributes, "owner"),
        Some(&AnyValueValue::String("[REDACTED]".into()))
    );
    let Some(AnyValueValue::KeyValueList(body)) = &record.body.as_ref().unwrap().value else {
        panic!("map body");
    };
    assert_eq!(attribute(&body.values, "secret"), None);
    assert_eq!(
        attribute(&body.values, "bytes"),
        Some(&AnyValueValue::Bytes(b"credential-private".to_vec()))
    );
    let Some(AnyValueValue::Array(nested)) = attribute(&body.values, "nested") else {
        panic!("nested values");
    };
    assert_eq!(nested.values[0].value, Some(AnyValueValue::Bool(true)));
    assert_eq!(nested.values[1].value, Some(AnyValueValue::Int(7)));
    assert_eq!(
        nested.values[2].value,
        Some(AnyValueValue::String("[REDACTED]".into()))
    );
}

#[test]
fn severity_range_missing_times_and_zero_correlation_are_preserved() {
    let logger = logger();
    let scope = SdkScope::builder("scope").build();
    let levels = [
        Severity::Trace,
        Severity::Trace2,
        Severity::Trace3,
        Severity::Trace4,
        Severity::Debug,
        Severity::Debug2,
        Severity::Debug3,
        Severity::Debug4,
        Severity::Info,
        Severity::Info2,
        Severity::Info3,
        Severity::Info4,
        Severity::Warn,
        Severity::Warn2,
        Severity::Warn3,
        Severity::Warn4,
        Severity::Error,
        Severity::Error2,
        Severity::Error3,
        Severity::Error4,
        Severity::Fatal,
        Severity::Fatal2,
        Severity::Fatal3,
        Severity::Fatal4,
    ];
    let mut records = vec![logger.create_log_record()];
    for level in levels {
        let mut record = logger.create_log_record();
        record.set_severity_number(level);
        record.set_severity_text(level.name());
        records.push(record);
    }
    records[0].set_trace_context(TraceId::INVALID, SpanId::INVALID, None);
    records[1].set_timestamp(UNIX_EPOCH);
    records[1].set_observed_timestamp(UNIX_EPOCH);
    let refs: Vec<_> = records.iter().map(|record| (record, &scope)).collect();
    let requests = decode(&map(&refs).unwrap());
    let records = all_records(&requests);
    assert_eq!(records[0].trace_id, [0; 16]);
    assert_eq!(records[0].span_id, [0; 8]);
    assert_eq!(records[0].flags, 0);
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record.severity_number, i32::try_from(index).unwrap());
        assert_eq!(record.time_unix_nano, 0);
        assert_eq!(record.observed_time_unix_nano, 0);
    }
    let mut invalid = logger.create_log_record();
    invalid.set_timestamp(UNIX_EPOCH - Duration::from_nanos(1));
    assert_eq!(
        map(&[(&invalid, &scope)]).unwrap_err(),
        OtlpSdkLogError::InvalidTimestamp
    );
    invalid.set_timestamp(UNIX_EPOCH);
    invalid.set_observed_timestamp(UNIX_EPOCH + Duration::from_secs(u64::MAX / 1_000_000_000 + 1));
    assert_eq!(
        map(&[(&invalid, &scope)]).unwrap_err(),
        OtlpSdkLogError::InvalidTimestamp
    );
}

#[test]
fn canonical_scope_keys_preserve_types_arrays_and_semantic_zero() {
    let logger = logger();
    let record = logger.create_log_record();
    let scopes = [
        SdkScope::builder("same")
            .with_attributes([
                SdkAttribute::new("z", 0.0),
                SdkAttribute::new("a", SdkValue::Array(SdkArray::F64(vec![0.0, 2.0]))),
            ])
            .build(),
        SdkScope::builder("same")
            .with_attributes([
                SdkAttribute::new("a", SdkValue::Array(SdkArray::F64(vec![-0.0, 2.0]))),
                SdkAttribute::new("z", -0.0),
            ])
            .build(),
        SdkScope::builder("same")
            .with_attributes([SdkAttribute::new("z", 0_i64)])
            .build(),
        SdkScope::builder("same")
            .with_attributes([SdkAttribute::new("z", "0")])
            .build(),
        SdkScope::builder("same")
            .with_attributes([SdkAttribute::new(
                "z",
                SdkValue::Array(SdkArray::Bool(vec![false])),
            )])
            .build(),
        SdkScope::builder("same")
            .with_attributes([SdkAttribute::new(
                "z",
                SdkValue::Array(SdkArray::I64(vec![0])),
            )])
            .build(),
        SdkScope::builder("same")
            .with_attributes([SdkAttribute::new(
                "z",
                SdkValue::Array(SdkArray::String(vec!["0".into()])),
            )])
            .build(),
    ];
    let refs: Vec<_> = scopes.iter().map(|scope| (&record, scope)).collect();
    let requests = decode(&map(&refs).unwrap());
    let groups = &requests[0].resource_logs[0].scope_logs;
    assert_eq!(
        groups.len(),
        6,
        "only the two signed-zero identities coalesce"
    );
    assert_eq!(
        groups
            .iter()
            .filter(|group| group.log_records.len() == 2)
            .count(),
        1
    );
    assert_eq!(all_records(&requests).len(), scopes.len());
}

#[test]
fn repeated_scope_inspections_share_the_finite_collection_budget() {
    let logger = logger();
    let record = logger.create_log_record();
    let scope = SdkScope::builder("large")
        .with_attributes([SdkAttribute::new(
            "large",
            SdkValue::Array(SdkArray::String(vec!["x".repeat(4096).into(); 10])),
        )])
        .build();
    let config = OtlpSdkLogConfig::new().with_max_collection_bytes(65_536);
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_privacy(PrivacyConfig::new().with_drop_attribute("large"))
        .unwrap();
    assert!(
        map_logs(
            &LogBatch::new(&[(&record, &scope)]),
            &resource(),
            &policy,
            &config
        )
        .is_ok()
    );
    let repeated = [(&record, &scope), (&record, &scope)];
    assert_eq!(
        map_logs(&LogBatch::new(&repeated), &resource(), &policy, &config).unwrap_err(),
        OtlpSdkLogError::LimitExceeded,
        "equal or policy-erased scopes cannot evade the borrowed traversal budget"
    );
}

#[test]
fn small_scopes_pack_together_and_scope_limit_is_atomic() {
    let logger = logger();
    let record = logger.create_log_record();
    let scopes: Vec<_> = (0..129)
        .map(|index| SdkScope::builder(format!("scope-{index:03}")).build())
        .collect();
    let refs: Vec<_> = scopes.iter().map(|scope| (&record, scope)).collect();
    let requests = decode(&map(&refs[..128]).unwrap());
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].resource_logs[0].scope_logs.len(), 128);
    assert_eq!(map(&refs).unwrap_err(), OtlpSdkLogError::LimitExceeded);
}

#[test]
fn request_byte_and_value_node_limits_split_only_between_complete_records() {
    let logger = logger();
    let scope = SdkScope::builder("scope").build();
    let records: Vec<_> = (0..100)
        .map(|index| {
            let mut record = logger.create_log_record();
            record.set_body(LogValue::Int(index));
            record
        })
        .collect();
    let refs: Vec<_> = records.iter().map(|record| (record, &scope)).collect();
    let config = OtlpSdkLogConfig::new().with_max_request_bytes(512);
    let output = map_logs(
        &LogBatch::new(&refs),
        &resource(),
        &OwnedOtlpExportPolicy::new(),
        &config,
    )
    .unwrap();
    assert!(output.output().len() > 1);
    assert!(output.output().iter().all(|request| request.len() <= 512));
    let requests = decode(&output);
    for (index, record) in all_records(&requests).iter().enumerate() {
        assert_eq!(
            record.body.as_ref().unwrap().value,
            Some(AnyValueValue::Int(i64::try_from(index).unwrap()))
        );
    }
    assert_eq!(all_records(&requests).len(), 100);

    let nested = |width: usize| {
        LogValue::ListAny(Box::new(
            (0..width)
                .map(|_| LogValue::ListAny(Box::new(vec![LogValue::Int(1); 100])))
                .collect(),
        ))
    };
    let mut first = logger.create_log_record();
    first.set_body(nested(30));
    let second = first.clone();
    let requests = decode(&map(&[(&first, &scope), (&second, &scope)]).unwrap());
    assert_eq!(
        requests.len(),
        2,
        "two 3031-node records use distinct requests"
    );
    assert!(
        requests
            .iter()
            .all(|request| request.resource_logs[0].scope_logs[0].log_records.len() == 1)
    );
    first.set_body(nested(41));
    assert_eq!(
        map(&[(&first, &scope)]).unwrap_err(),
        OtlpSdkLogError::WireEnvelopeExceeded
    );
}

#[test]
fn all_raw_updates_and_late_records_are_validated_before_mapping() {
    let logger = logger();
    let scope = SdkScope::builder("scope").build();
    let good = logger.create_log_record();
    let mut invalid = logger.create_log_record();
    invalid.add_attribute("updated", f64::NAN);
    invalid.add_attribute("updated", 1_i64);
    assert_eq!(
        map(&[(&good, &scope), (&invalid, &scope)]).unwrap_err(),
        OtlpSdkLogError::InvalidNumericValue
    );
    let mut updates = logger.create_log_record();
    for _ in 0..128 {
        updates.add_attribute("updated", true);
    }
    assert!(map(&[(&updates, &scope)]).is_ok());
    updates.add_attribute("updated", false);
    assert_eq!(
        map(&[(&updates, &scope)]).unwrap_err(),
        OtlpSdkLogError::InvalidAttributes
    );
    invalid = logger.create_log_record();
    invalid.set_body(LogValue::Map(Box::new(HashMap::from([(
        Key::new(""),
        LogValue::Int(1),
    )]))));
    assert_eq!(
        map(&[(&invalid, &scope)]).unwrap_err(),
        OtlpSdkLogError::InvalidAttributes
    );
    invalid = logger.create_log_record();
    invalid.add_attribute("", true);
    assert_eq!(
        map(&[(&invalid, &scope)]).unwrap_err(),
        OtlpSdkLogError::InvalidAttributes
    );
}

#[test]
fn recursive_depth_width_scalar_and_sparse_map_boundaries_are_enforced() {
    let logger = logger();
    let scope = SdkScope::builder("scope").build();
    let mut record = logger.create_log_record();
    let mut body = LogValue::Int(1);
    for _ in 0..15 {
        body = LogValue::ListAny(Box::new(vec![body]));
    }
    record.set_body(body.clone());
    assert!(map(&[(&record, &scope)]).is_ok());
    record.set_body(LogValue::ListAny(Box::new(vec![body])));
    assert_eq!(
        map(&[(&record, &scope)]).unwrap_err(),
        OtlpSdkLogError::LimitExceeded
    );
    for body in [
        LogValue::from("x".repeat(4096)),
        LogValue::Bytes(Box::new(vec![0; 4096])),
        LogValue::ListAny(Box::new(vec![LogValue::Int(1); 128])),
    ] {
        record.set_body(body);
        assert!(map(&[(&record, &scope)]).is_ok());
    }
    for body in [
        LogValue::from("x".repeat(4097)),
        LogValue::Bytes(Box::new(vec![0; 4097])),
        LogValue::ListAny(Box::new(vec![LogValue::Int(1); 129])),
    ] {
        record.set_body(body);
        assert_eq!(
            map(&[(&record, &scope)]).unwrap_err(),
            OtlpSdkLogError::LimitExceeded
        );
    }
    let mut sparse = HashMap::with_capacity(MAX_BYTES / std::mem::size_of::<(Key, LogValue)>() + 1);
    sparse.insert(Key::new("one"), LogValue::Int(1));
    assert!(sparse.capacity() * std::mem::size_of::<(Key, LogValue)>() > MAX_BYTES);
    record.set_body(LogValue::Map(Box::new(sparse)));
    assert_eq!(
        map(&[(&record, &scope)]).unwrap_err(),
        OtlpSdkLogError::LimitExceeded
    );
}

#[test]
fn map_encoding_is_deterministic_across_source_hash_insertion_order() {
    let logger = logger();
    let scope = SdkScope::builder("scope").build();
    let mut first = logger.create_log_record();
    let mut second = logger.create_log_record();
    let entries = [
        (Key::new("a"), LogValue::Int(1)),
        (Key::new("z"), LogValue::Boolean(true)),
        (Key::new("m"), LogValue::from("text")),
    ];
    first.set_body(LogValue::Map(Box::new(
        entries.clone().into_iter().collect(),
    )));
    second.set_body(LogValue::Map(Box::new(entries.into_iter().rev().collect())));
    assert_eq!(
        map(&[(&first, &scope)]).unwrap().output(),
        map(&[(&second, &scope)]).unwrap().output()
    );
}

#[test]
fn resource_updates_fail_without_retention_and_can_recover() {
    let mut exporter = exporter();
    let secret = "credential-private";
    exporter.set_resource(
        &opentelemetry_sdk::Resource::builder_empty()
            .with_attributes([SdkAttribute::new("owner", secret)])
            .build(),
    );
    assert!(exporter.resource.is_ok());
    assert!(!format!("{exporter:?}").contains(secret));
    exporter.set_resource(
        &opentelemetry_sdk::Resource::builder_empty()
            .with_attributes([SdkAttribute::new("owner", secret.repeat(300))])
            .build(),
    );
    assert!(matches!(
        exporter.resource,
        Err(OtlpSdkLogError::LimitExceeded)
    ));
    assert!(!format!("{exporter:?}").contains(secret));
    exporter.set_resource(
        &opentelemetry_sdk::Resource::builder_empty()
            .with_attributes([SdkAttribute::new("number", 3_i64)])
            .build(),
    );
    let resource = exporter.resource.as_ref().unwrap();
    assert_eq!(resource.resource.attributes.len(), 1);
    assert_eq!(
        attribute(&resource.resource.attributes, "number"),
        Some(&AnyValueValue::Int(3))
    );
    assert_eq!(attribute(&resource.resource.attributes, "owner"), None);
    assert_eq!(
        format!("{}", OtlpSdkLogError::InvalidNumericValue),
        "otlp.sdk.logs.invalid_numeric_value"
    );
}

#[test]
fn exporter_requires_managed_owner_before_admission_and_has_a_send_future() {
    let exporter = exporter();
    let logger = logger();
    let mut record = logger.create_log_record();
    record.set_body(LogValue::Double(f64::INFINITY));
    let scope = SdkScope::builder("scope").build();
    let entries = [(&record, &scope)];
    let future = exporter.export(LogBatch::new(&entries));
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&future);
    let mut future = std::pin::pin!(future);
    let Poll::Ready(Err(OTelSdkError::InternalFailure(code))) = future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("missing owner fails synchronously");
    };
    assert_eq!(code, "otlp.sdk.logs.owner_unavailable");
    assert_eq!(exporter.queue().queue_stats().queue.queued_batches, 0);
    assert!(
        exporter.event_enabled(Severity::Trace, "component", Some("event")),
        "SDK batch processors may ask before off-runtime export"
    );
    assert_eq!(
        OtlpSdkLogConfig::new().with_max_records(0).validate(),
        Err(OtlpSdkLogError::InvalidConfiguration)
    );
    assert_eq!(
        OtlpSdkLogConfig::new().with_max_scopes(129).validate(),
        Err(OtlpSdkLogError::InvalidConfiguration)
    );
    assert_eq!(
        OtlpSdkLogConfig::new()
            .with_max_request_bytes(MAX_BYTES + 1)
            .validate(),
        Err(OtlpSdkLogError::InvalidConfiguration)
    );
    assert!(map(&[]).unwrap().output().is_empty());
}
