//! OTLP-Trace span `add_attributes(Vec<KeyValue>)` production-seam tests.
//!
//! br-asupersync-803qzz converts the stale audit note into executable
//! coverage for `TestSpan::add_attributes`. The API accepts OTLP protobuf
//! `KeyValue` records, deduplicates duplicate keys with last-write-wins
//! semantics, applies the existing per-span attribute cap, filters invalid empty
//! keys, preserves typed values, and keeps `set_attribute` replacement behavior
//! unchanged.

#[cfg(all(test, feature = "metrics", feature = "tracing-integration"))]
mod tests {
    use crate::observability::otel::span_semantics::{
        AttributeValue, SpanConformanceConfig, TestSpan,
    };
    use opentelemetry::trace::SpanKind;
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue, ArrayValue, KeyValue, any_value::Value as ProtoValue,
    };

    const RCH_TEST_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_803qzz_add_attributes cargo test -p asupersync --lib otlp_add_attributes --features metrics,tracing-integration -- --nocapture";
    const MAX_OTEL_ATTRIBUTE_KEY_LEN: usize = 1024;

    fn test_config(max_attributes: usize) -> SpanConformanceConfig {
        SpanConformanceConfig {
            max_attributes,
            max_events: 8,
            max_attribute_length: Some(8),
            test_sampling: true,
            test_context_propagation: true,
        }
    }

    fn key_value(key: impl Into<String>, value: ProtoValue) -> KeyValue {
        KeyValue {
            key: key.into(),
            value: Some(AnyValue { value: Some(value) }),
        }
    }

    fn string_attr(key: impl Into<String>, value: impl Into<String>) -> KeyValue {
        key_value(key, ProtoValue::StringValue(value.into()))
    }

    fn int_attr(key: impl Into<String>, value: i64) -> KeyValue {
        key_value(key, ProtoValue::IntValue(value))
    }

    fn float_attr(key: impl Into<String>, value: f64) -> KeyValue {
        key_value(key, ProtoValue::DoubleValue(value))
    }

    fn bool_attr(key: impl Into<String>, value: bool) -> KeyValue {
        key_value(key, ProtoValue::BoolValue(value))
    }

    fn string_array_attr(key: impl Into<String>, values: &[&str]) -> KeyValue {
        key_value(
            key,
            ProtoValue::ArrayValue(ArrayValue {
                values: values
                    .iter()
                    .map(|value| AnyValue {
                        value: Some(ProtoValue::StringValue((*value).to_string())),
                    })
                    .collect(),
            }),
        )
    }

    fn empty_value_attr(key: impl Into<String>) -> KeyValue {
        KeyValue {
            key: key.into(),
            value: None,
        }
    }

    fn sanitized_fingerprint(span: &TestSpan) -> String {
        let mut entries: Vec<_> = span
            .attributes
            .iter()
            .map(|(key, value)| {
                if key.contains("authorization") || key.contains("token") {
                    format!("{key}=<redacted>")
                } else {
                    format!("{key}:len{}", value.len())
                }
            })
            .collect();
        entries.sort();
        entries.join("|")
    }

    #[test]
    fn add_attributes_empty_batch_is_noop() {
        let mut span = TestSpan::new("empty-batch", SpanKind::Internal);

        span.add_attributes(Vec::new());

        eprintln!(
            "OTLP_ADD_ATTRIBUTES scenario=empty input_batch_len=0 accepted=0 dropped=0 rch_command={RCH_TEST_COMMAND} verdict=pass"
        );
        assert!(span.attributes.is_empty());
        assert!(span.attribute_values.is_empty());
        assert_eq!(span.dropped_attributes_count, 0);
    }

    #[test]
    fn add_attributes_deduplicates_last_write_and_matches_set_attribute() {
        let mut batch = TestSpan::new("batch", SpanKind::Internal);
        batch.add_attributes(vec![
            string_attr("key1", "value1"),
            string_attr("key2", "value2"),
            string_attr("key1", "value3"),
        ]);

        let mut sequential = TestSpan::new("sequential", SpanKind::Internal);
        sequential.set_attribute("key1", "value1");
        sequential.set_attribute("key2", "value2");
        sequential.set_attribute("key1", "value3");

        eprintln!(
            "OTLP_ADD_ATTRIBUTES scenario=dedup input_batch_len=3 unique_keys=2 duplicate_keys=1 accepted=2 dropped=0 fingerprint={} rch_command={} verdict=pass",
            sanitized_fingerprint(&batch),
            RCH_TEST_COMMAND
        );
        assert_eq!(batch.attributes, sequential.attributes);
        assert_eq!(batch.attribute_values, sequential.attribute_values);
        assert_eq!(
            batch.attribute_values.get("key1"),
            Some(&AttributeValue::String("value3".to_string()))
        );
        assert_eq!(batch.dropped_attributes_count, 0);
    }

    #[test]
    fn add_attributes_replaces_existing_without_counting_capacity_drop() {
        let config = test_config(3);
        let mut span = TestSpan::new_with_config("capacity", SpanKind::Internal, &config);
        span.set_attribute("existing_key", "old");
        span.set_attribute("filled_1", "a");
        span.set_attribute("filled_2", "b");

        span.add_attributes(vec![
            string_attr("existing_key", "new_value"),
            string_attr("new_key", "value"),
        ]);

        eprintln!(
            "OTLP_ADD_ATTRIBUTES scenario=capacity_at_full input_batch_len=2 unique_keys=2 accepted=1 dropped=1 fingerprint={} rch_command={} verdict=pass",
            sanitized_fingerprint(&span),
            RCH_TEST_COMMAND
        );
        assert_eq!(
            span.attributes.get("existing_key").map(String::as_str),
            Some("new_valu")
        );
        assert!(!span.attributes.contains_key("new_key"));
        assert_eq!(span.attributes.len(), 3);
        assert_eq!(span.dropped_attributes_count, 1);
    }

    #[test]
    fn add_attributes_deduplicates_before_capacity_accounting() {
        let config = test_config(3);
        let mut span = TestSpan::new_with_config("dedup-capacity", SpanKind::Internal, &config);
        span.set_attribute("existing", "value");

        span.add_attributes(vec![
            string_attr("key1", "v1"),
            string_attr("key2", "v2"),
            string_attr("key1", "v3"),
        ]);

        eprintln!(
            "OTLP_ADD_ATTRIBUTES scenario=dedup_before_capacity input_batch_len=3 unique_keys=2 duplicate_keys=1 accepted=2 dropped=0 fingerprint={} rch_command={} verdict=pass",
            sanitized_fingerprint(&span),
            RCH_TEST_COMMAND
        );
        assert_eq!(span.attributes.len(), 3);
        assert_eq!(span.attributes.get("key1").map(String::as_str), Some("v3"));
        assert_eq!(span.attributes.get("key2").map(String::as_str), Some("v2"));
        assert_eq!(span.dropped_attributes_count, 0);
    }

    #[test]
    fn add_attributes_filters_empty_keys_and_truncates_oversized_keys() {
        let mut span = TestSpan::new("keys", SpanKind::Internal);
        let oversized_key = "k".repeat(MAX_OTEL_ATTRIBUTE_KEY_LEN + 64);

        span.add_attributes(vec![
            string_attr("", "drop"),
            string_attr(&oversized_key, "kept"),
        ]);

        let stored_key = span.attributes.keys().next().expect("stored key");
        eprintln!(
            "OTLP_ADD_ATTRIBUTES scenario=key_filtering input_batch_len=2 accepted=1 dropped=1 truncated_key_len={} fingerprint={} rch_command={} verdict=pass",
            stored_key.len(),
            sanitized_fingerprint(&span),
            RCH_TEST_COMMAND
        );
        assert_eq!(span.attributes.len(), 1);
        assert_eq!(stored_key.len(), MAX_OTEL_ATTRIBUTE_KEY_LEN);
        assert!(!span.attributes.contains_key(&oversized_key));
        assert_eq!(span.dropped_attributes_count, 1);
    }

    #[test]
    fn add_attributes_preserves_typed_values_and_stable_export_order() {
        let mut span = TestSpan::new("typed", SpanKind::Internal);
        span.add_attributes(vec![
            float_attr("ratio", 1.5),
            string_array_attr("zones", &["a", "b"]),
            int_attr("replicas", 3),
            bool_attr("healthy", true),
        ]);

        let exported_keys: Vec<_> = span
            .to_otlp_attributes()
            .into_iter()
            .map(|attribute| attribute.key)
            .collect();

        eprintln!(
            "OTLP_ADD_ATTRIBUTES scenario=typed_values input_batch_len=4 accepted=4 dropped=0 export_keys={exported_keys:?} fingerprint={} rch_command={} verdict=pass",
            sanitized_fingerprint(&span),
            RCH_TEST_COMMAND
        );
        assert_eq!(
            span.attribute_values.get("ratio"),
            Some(&AttributeValue::Float(1.5))
        );
        assert_eq!(
            span.attribute_values.get("zones"),
            Some(&AttributeValue::StringArray(vec![
                "a".to_string(),
                "b".to_string()
            ]))
        );
        assert_eq!(
            span.attribute_values.get("replicas"),
            Some(&AttributeValue::Int(3))
        );
        assert_eq!(
            span.attribute_values.get("healthy"),
            Some(&AttributeValue::Bool(true))
        );
        assert_eq!(exported_keys, vec!["healthy", "ratio", "replicas", "zones"]);
    }

    #[test]
    fn add_attributes_drops_unsupported_values_without_splitting_maps() {
        let mut span = TestSpan::new("staged", SpanKind::Internal);

        span.add_attributes(vec![
            string_attr("authorization", "secret-token"),
            empty_value_attr("unsupported"),
        ]);

        eprintln!(
            "OTLP_ADD_ATTRIBUTES scenario=unsupported_value input_batch_len=2 accepted=1 dropped=1 fingerprint={} rch_command={} verdict=pass",
            sanitized_fingerprint(&span),
            RCH_TEST_COMMAND
        );
        assert!(span.attributes.contains_key("authorization"));
        assert!(!sanitized_fingerprint(&span).contains("secret-token"));
        assert!(!span.attributes.contains_key("unsupported"));
        assert_eq!(span.attributes.len(), span.attribute_values.len());
        assert_eq!(span.dropped_attributes_count, 1);
    }

    #[test]
    fn set_attribute_replacement_and_capacity_behavior_is_unchanged() {
        let config = test_config(1);
        let mut span = TestSpan::new_with_config("set-unchanged", SpanKind::Internal, &config);

        span.set_attribute("key", "value1");
        span.set_attribute("key", "value2");
        span.set_attribute("new_key", "value3");

        eprintln!(
            "OTLP_ADD_ATTRIBUTES scenario=set_attribute_unchanged accepted=1 dropped=1 fingerprint={} rch_command={} verdict=pass",
            sanitized_fingerprint(&span),
            RCH_TEST_COMMAND
        );
        assert_eq!(
            span.attributes.get("key").map(String::as_str),
            Some("value2")
        );
        assert!(!span.attributes.contains_key("new_key"));
        assert_eq!(span.dropped_attributes_count, 1);
    }
}
