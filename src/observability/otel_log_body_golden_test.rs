//! Golden artifact tests for OTLP LogRecord body value mapping conformance.
//!
//! This module provides golden file testing to verify that LogRecord body values
//! consistently map to identical AnyValue protobuf representations.

#[cfg(all(test, feature = "tracing-integration"))]
mod tests {
    use super::super::{LogRecordBodyValue, log_record_body_value_to_any_value};
    use opentelemetry_proto::tonic::common::v1::AnyValue;
    use prost::Message;
    use std::fs;
    use std::path::Path;

    #[allow(clippy::approx_constant)]
    const FLOAT_PI_GOLDEN: f64 = 3.141_59;
    #[allow(clippy::approx_constant)]
    const FLOAT_NEGATIVE_E_GOLDEN: f64 = -2.718_28;

    /// Assert a golden file test for serialized AnyValue protobuf output.
    fn assert_golden_log_body(test_name: &str, body_value: &LogRecordBodyValue) {
        let golden_path =
            Path::new("tests/golden/otel/log_body").join(format!("{test_name}.golden"));

        let any_value = log_record_body_value_to_any_value(body_value);
        let mut serialized = Vec::new();
        any_value.encode(&mut serialized).unwrap();
        let actual = format!("{:?}", serialized);

        // UPDATE MODE: overwrite golden with actual output
        if std::env::var("UPDATE_GOLDENS").is_ok() {
            fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
            fs::write(&golden_path, &actual).unwrap();
            eprintln!("[GOLDEN] Updated: {}", golden_path.display());
            return;
        }

        // COMPARE MODE: diff actual vs golden
        let expected = fs::read_to_string(&golden_path).unwrap_or_else(|_| {
            panic!(
                "Golden file missing: {}\n\
                 Run with UPDATE_GOLDENS=1 to create it\n\
                 Then review and commit: git diff tests/golden/otel/",
                golden_path.display()
            )
        });

        if actual != expected.trim() {
            // Write actual for easy diffing
            let actual_path = golden_path.with_extension("actual");
            fs::write(&actual_path, &actual).unwrap();

            panic!(
                "GOLDEN MISMATCH: {test_name}\n\n\
                 Expected (golden): {}\n\
                 Actual (current): {}\n\n\
                 To update: UPDATE_GOLDENS=1 cargo test -- {test_name}\n\
                 To review: diff {} {}",
                expected.trim(),
                actual,
                golden_path.display(),
                actual_path.display(),
            );
        }
    }

    #[test]
    fn log_body_string_golden() {
        let body = LogRecordBodyValue::String("hello world".to_string());
        assert_golden_log_body("string_simple", &body);
    }

    #[test]
    fn log_body_int_golden() {
        let body = LogRecordBodyValue::Int(42);
        assert_golden_log_body("int_positive", &body);
    }

    #[test]
    fn log_body_bool_golden() {
        let body = LogRecordBodyValue::Bool(true);
        assert_golden_log_body("bool_true", &body);
    }

    #[test]
    fn log_body_float_golden() {
        let body = LogRecordBodyValue::Float(FLOAT_PI_GOLDEN);
        assert_golden_log_body("float_pi", &body);
    }

    #[test]
    fn log_body_string_array_golden() {
        let body = LogRecordBodyValue::StringArray(vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
        ]);
        assert_golden_log_body("string_array_abc", &body);
    }

    #[test]
    fn log_body_empty_string_golden() {
        let body = LogRecordBodyValue::String(String::new());
        assert_golden_log_body("string_empty", &body);
    }

    #[test]
    fn log_body_unicode_string_golden() {
        let body = LogRecordBodyValue::String("测试 🚀".to_string());
        assert_golden_log_body("string_unicode", &body);
    }

    /// Comprehensive conformance test covering all body value types.
    #[test]
    fn log_body_comprehensive_conformance() {
        let test_cases = vec![
            (
                "string_simple",
                LogRecordBodyValue::String("hello".to_string()),
            ),
            ("string_empty", LogRecordBodyValue::String(String::new())),
            ("int_zero", LogRecordBodyValue::Int(0)),
            ("int_positive", LogRecordBodyValue::Int(42)),
            ("int_negative", LogRecordBodyValue::Int(-100)),
            ("int_max", LogRecordBodyValue::Int(i64::MAX)),
            ("int_min", LogRecordBodyValue::Int(i64::MIN)),
            ("float_zero", LogRecordBodyValue::Float(0.0)),
            ("float_positive", LogRecordBodyValue::Float(FLOAT_PI_GOLDEN)),
            (
                "float_negative",
                LogRecordBodyValue::Float(FLOAT_NEGATIVE_E_GOLDEN),
            ),
            ("bool_true", LogRecordBodyValue::Bool(true)),
            ("bool_false", LogRecordBodyValue::Bool(false)),
            (
                "string_array_empty",
                LogRecordBodyValue::StringArray(vec![]),
            ),
            (
                "string_array_single",
                LogRecordBodyValue::StringArray(vec!["single".to_string()]),
            ),
            ("int_array_empty", LogRecordBodyValue::IntArray(vec![])),
            (
                "int_array_multi",
                LogRecordBodyValue::IntArray(vec![1, 2, 3]),
            ),
            ("float_array_empty", LogRecordBodyValue::FloatArray(vec![])),
            (
                "bool_array_mixed",
                LogRecordBodyValue::BoolArray(vec![true, false, true]),
            ),
        ];

        for (test_name, body_value) in test_cases {
            // Test deterministic conversion - same input should always produce same output
            let any_value_1 = log_record_body_value_to_any_value(&body_value);
            let any_value_2 = log_record_body_value_to_any_value(&body_value);
            assert_eq!(
                any_value_1, any_value_2,
                "LogRecord body conversion must be deterministic for {}",
                test_name
            );

            // Test serialization determinism - same AnyValue should produce same bytes
            let mut serialized_1 = Vec::new();
            let mut serialized_2 = Vec::new();
            any_value_1.encode(&mut serialized_1).unwrap();
            any_value_2.encode(&mut serialized_2).unwrap();
            assert_eq!(
                serialized_1, serialized_2,
                "AnyValue serialization must be deterministic for {}",
                test_name
            );

            // Verify round-trip: serialized bytes can be deserialized back to equivalent AnyValue
            let deserialized = AnyValue::decode(&serialized_1[..]).unwrap();
            assert_eq!(
                any_value_1, deserialized,
                "AnyValue round-trip failed for {}",
                test_name
            );
        }
    }
}
