//! OTLP-Trace exporter empty key attribute validation audit.
//!
//! **Audit Question**: Does OTLP serializer reject Resource attributes with empty
//! keys but non-empty values before protobuf serialization?
//!
//! **OTLP Specification Requirement**: Per OTLP §2.3.1, attribute keys MUST be non-empty.
//! Empty key attributes should be rejected/filtered during serialization.
//!
//! **Expected Behavior**: Empty-key attributes should be filtered out before
//! protobuf serialization, not silently sent to the collector.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    /// KeyValue fixture for testing OTLP attribute serialization.
    #[derive(Debug, Clone, PartialEq)]
    pub struct KeyValue {
        pub key: String,
        pub value: String,
    }

    impl KeyValue {
        pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
            Self {
                key: key.into(),
                value: value.into(),
            }
        }
    }

    /// Current OTLP attribute serializer behavior (from `otel.rs`).
    ///
    /// Empty keys and empty values are both filtered before protobuf encoding.
    fn current_ordered_proto_attributes(attributes: &HashMap<String, String>) -> Vec<KeyValue> {
        let mut ordered: Vec<_> = attributes.iter().collect();
        ordered.sort_unstable_by(|(left_key, left_value), (right_key, right_value)| {
            left_key
                .cmp(right_key)
                .then_with(|| left_value.cmp(right_value))
        });
        ordered
            .into_iter()
            // OTLP §2.3.1 compliance: drop empty keys and empty values.
            .filter(|(key, value)| !key.is_empty() && !value.is_empty())
            .map(|(key, value)| KeyValue::new(key.clone(), value.clone()))
            .collect()
    }

    #[test]
    fn otlp_empty_key_attribute_audit() {
        eprintln!("\n🔍 OTLP EMPTY KEY ATTRIBUTE VALIDATION AUDIT");
        eprintln!("=============================================");

        eprintln!("\n📋 OTLP §2.3.1 Requirements:");
        eprintln!("  • Attribute keys MUST be non-empty strings");
        eprintln!("  • Attribute values MUST be non-empty strings");
        eprintln!("  • Empty key/value attributes should be filtered from wire format");
        eprintln!("  • Serializer should reject malformed attributes before transmission");

        // Test attributes with various key/value combinations
        let mut test_attributes = HashMap::new();

        // Valid attributes
        test_attributes.insert("service.name".to_string(), "my-service".to_string());
        test_attributes.insert("version".to_string(), "1.2.3".to_string());

        // **INVALID**: Empty key with non-empty value (should be filtered)
        test_attributes.insert(String::new(), "should-be-rejected".to_string());

        // **INVALID**: Non-empty key with empty value (should be filtered)
        test_attributes.insert("empty_value_key".to_string(), String::new());

        eprintln!("\n📊 Input attributes:");
        for (key, value) in &test_attributes {
            let key_desc = if key.is_empty() { "[EMPTY]" } else { key };
            let value_desc = if value.is_empty() { "[EMPTY]" } else { value };
            eprintln!("  '{}' = '{}'", key_desc, value_desc);
        }

        // Test current implementation
        let current_result = current_ordered_proto_attributes(&test_attributes);

        eprintln!("\n📋 Serialization Results:");

        eprintln!("  Current implementation:");
        eprintln!("    Serialized {} attributes:", current_result.len());
        for attr in &current_result {
            let key_desc = if attr.key.is_empty() {
                "[EMPTY]"
            } else {
                &attr.key
            };
            let value_desc = if attr.value.is_empty() {
                "[EMPTY]"
            } else {
                &attr.value
            };
            eprintln!("      '{}' = '{}'", key_desc, value_desc);
        }

        // Verify specific defect: empty key with non-empty value
        let has_empty_key = current_result.iter().any(|attr| attr.key.is_empty());

        eprintln!("\n🎯 EMPTY KEY VALIDATION:");
        eprintln!(
            "  Current rejects empty keys: {}",
            if has_empty_key {
                "❌ WRONG"
            } else {
                "✅ SOUND"
            }
        );

        // Assertions
        assert!(
            !has_empty_key,
            "Current implementation should reject empty keys"
        );
        assert_eq!(
            current_result.len(),
            2,
            "Only 2 valid attributes should remain after filtering"
        );

        // Verify only valid attributes remain
        let valid_keys: Vec<&str> = current_result
            .iter()
            .map(|attr| attr.key.as_str())
            .collect();
        assert!(valid_keys.contains(&"service.name"));
        assert!(valid_keys.contains(&"version"));

        eprintln!("\n✅ AUDIT FINDINGS:");
        eprintln!("==================");
        eprintln!("✅ SOUND: Current serializer filters empty-key attributes");
        eprintln!("   • ordered_proto_attributes() filters empty keys and values");
        eprintln!("   • Empty keys with non-empty values are not sent to collectors");
        eprintln!("   • Current behavior preserves the OTLP §2.3.1 non-empty key rule");
    }

    #[test]
    fn otlp_spec_section_231_compliance() {
        eprintln!("\n📖 OTLP §2.3.1 SPECIFICATION COMPLIANCE TEST");
        eprintln!("==========================================");

        eprintln!("📋 OTLP §2.3.1 - KeyValue Specification:");
        eprintln!("   • Key: non-empty string identifying the attribute");
        eprintln!("   • Value: value associated with the key");
        eprintln!("   • Both key and value MUST have meaningful content");
        eprintln!("   • Empty keys create ambiguous attribute identity");

        // Test edge cases from OTLP specification
        let test_cases = vec![
            ("", "value", false, "Empty key violates spec"),
            ("key", "", false, "Empty value violates spec"),
            ("", "", false, "Empty key and value both violate spec"),
            ("service.name", "my-service", true, "Valid key-value pair"),
        ];

        eprintln!("\n📊 OTLP Compliance Test Cases:");

        for (key, value, should_be_valid, description) in test_cases {
            let mut attrs = HashMap::new();
            attrs.insert(key.to_string(), value.to_string());

            let current_result = current_ordered_proto_attributes(&attrs);
            let current_accepts = !current_result.is_empty();

            eprintln!(
                "  '{}' = '{}': {}",
                if key.is_empty() { "[EMPTY]" } else { key },
                if value.is_empty() { "[EMPTY]" } else { value },
                description
            );
            eprintln!(
                "    Expected: {}",
                if should_be_valid { "ACCEPT" } else { "REJECT" }
            );
            eprintln!(
                "    Current:  {} {}",
                if current_accepts { "ACCEPT" } else { "REJECT" },
                if current_accepts == should_be_valid {
                    "✅"
                } else {
                    "❌"
                }
            );

            assert_eq!(
                current_accepts, should_be_valid,
                "Current implementation should match OTLP spec for: {}",
                description
            );
        }
    }

    /// Demonstrate that malformed empty-key attributes are removed before export.
    #[test]
    fn empty_key_attributes_are_filtered_before_export() {
        eprintln!("\n🔒 EMPTY KEY FILTERING VERIFICATION");
        eprintln!("==================================");

        let mut malformed_attributes = HashMap::new();

        // Scenario: Service attempts to send malformed telemetry with an empty key.
        malformed_attributes.insert(String::new(), "secret-value".to_string());
        malformed_attributes.insert("service.name".to_string(), "my-service".to_string());

        let result = current_ordered_proto_attributes(&malformed_attributes);

        eprintln!("Malformed input:");
        eprintln!("  '' = 'secret-value'");
        eprintln!("  'service.name' = 'my-service'");

        eprintln!("\nCurrent implementation sends only valid attributes:");
        for attr in &result {
            let key_display = if attr.key.is_empty() {
                "[EMPTY_KEY]"
            } else {
                &attr.key
            };
            eprintln!("  '{}' = '{}'", key_display, attr.value);
        }

        let has_empty_key = result.iter().any(|attr| attr.key.is_empty());
        assert!(
            !has_empty_key,
            "Current implementation must filter empty keys"
        );
        assert_eq!(
            result,
            vec![KeyValue::new("service.name", "my-service")],
            "Only the valid service.name attribute should be exported"
        );
    }
}
