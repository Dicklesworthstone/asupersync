//! OTLP-Trace exporter span.set_attribute() replace-vs-append audit test.
//!
//! Per OTLP specification, span attribute updates should follow replace semantics
//! (last-write-wins) rather than append semantics. When set_attribute("key", v1)
//! is called followed by set_attribute("key", v2), the final value should be v2,
//! not both v1 and v2 as duplicate keys or concatenated values.
//!
//! This audit verifies that:
//! 1. Duplicate keys are replaced, not appended (last-write-wins)
//! 2. No duplicate keys exist in final attribute map
//! 3. Attribute count reflects unique keys, not total set operations
//! 4. Implementation follows OTLP specification requirements
//!
//! Audit date: 2026-05-03
//! OTLP spec reference: Attributes are key-value pairs with unique keys

use std::collections::HashMap;

use crate::observability::otel::{SpanKind, TestSpan, AttributeValue, SpanConformanceConfig};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_attribute_replace_not_append() {
        // AUDIT POINT 1: Verify set_attribute replaces existing keys (last-write-wins)

        let mut span = TestSpan::new("test_span", SpanKind::Internal);

        // Set initial attribute value
        span.set_attribute("service.name", "user-service-v1");

        // Verify initial value
        assert_eq!(span.attributes.get("service.name"), Some(&"user-service-v1".to_string()));
        assert_eq!(span.attributes.len(), 1, "Should have exactly 1 attribute");

        // Set same key with different value - should REPLACE, not append
        span.set_attribute("service.name", "user-service-v2");

        // ✅ SOUND: Last write wins, no duplicate keys
        assert_eq!(span.attributes.get("service.name"), Some(&"user-service-v2".to_string()));
        assert_eq!(span.attributes.len(), 1, "Should still have exactly 1 attribute (replaced)");

        // Verify no duplicate keys exist
        let service_name_count = span.attributes.keys().filter(|&k| k == "service.name").count();
        assert_eq!(service_name_count, 1, "Should have exactly 1 'service.name' key");

        eprintln!("✅ SOUND: set_attribute() uses replace semantics");
        eprintln!("   Initial: service.name = 'user-service-v1'");
        eprintln!("   After replacement: service.name = 'user-service-v2'");
        eprintln!("   Attribute count: 1 (no duplication)");
        eprintln!("   OTLP spec compliance: ✅");
    }

    #[test]
    fn test_set_attribute_multiple_replacements() {
        // AUDIT POINT 2: Verify multiple replacements of same key work correctly

        let mut span = TestSpan::new("test_span", SpanKind::Internal);

        // Add some initial attributes
        span.set_attribute("http.method", "GET");
        span.set_attribute("http.url", "https://api.example.com/v1");
        span.set_attribute("user.id", "12345");

        assert_eq!(span.attributes.len(), 3, "Should have 3 initial attributes");

        // Replace http.method multiple times
        span.set_attribute("http.method", "POST");  // First replacement
        span.set_attribute("http.method", "PUT");   // Second replacement
        span.set_attribute("http.method", "PATCH"); // Third replacement

        // Verify final state
        assert_eq!(span.attributes.get("http.method"), Some(&"PATCH".to_string()));
        assert_eq!(span.attributes.get("http.url"), Some(&"https://api.example.com/v1".to_string()));
        assert_eq!(span.attributes.get("user.id"), Some(&"12345".to_string()));
        assert_eq!(span.attributes.len(), 3, "Should still have exactly 3 attributes");

        // Verify no duplicate keys
        let method_count = span.attributes.keys().filter(|&k| k == "http.method").count();
        assert_eq!(method_count, 1, "Should have exactly 1 'http.method' key");

        eprintln!("✅ MULTIPLE REPLACEMENTS:");
        eprintln!("   http.method: GET → POST → PUT → PATCH");
        eprintln!("   Final value: PATCH (last-write-wins)");
        eprintln!("   Attribute count unchanged: 3");
        eprintln!("   No duplicate keys created");
    }

    #[test]
    fn test_set_attribute_typed_variants_replace() {
        // AUDIT POINT 3: Verify typed set_*_attribute methods also use replace semantics

        let mut span = TestSpan::new("test_span", SpanKind::Internal);

        // Test string attribute replacement
        span.set_attribute("operation.name", "initial_operation");
        span.set_attribute("operation.name", "final_operation");
        assert_eq!(span.attributes.get("operation.name"), Some(&"final_operation".to_string()));

        // Test integer attribute replacement
        span.set_int_attribute("retry.count", 1);
        span.set_int_attribute("retry.count", 3);
        assert_eq!(span.attribute_values.get("retry.count"), Some(&AttributeValue::Int(3)));

        // Test float attribute replacement
        span.set_float_attribute("duration.seconds", 1.5);
        span.set_float_attribute("duration.seconds", 2.7);
        assert_eq!(span.attribute_values.get("duration.seconds"), Some(&AttributeValue::Float(2.7)));

        // Test boolean attribute replacement
        span.set_bool_attribute("error.occurred", false);
        span.set_bool_attribute("error.occurred", true);
        assert_eq!(span.attribute_values.get("error.occurred"), Some(&AttributeValue::Bool(true)));

        // Verify attribute counts
        assert_eq!(span.attributes.len(), 4, "Should have 4 unique attributes");
        assert_eq!(span.attribute_values.len(), 4, "Should have 4 unique typed attributes");

        eprintln!("✅ TYPED ATTRIBUTE REPLACEMENTS:");
        eprintln!("   String: operation.name = 'final_operation'");
        eprintln!("   Integer: retry.count = 3");
        eprintln!("   Float: duration.seconds = 2.7");
        eprintln!("   Boolean: error.occurred = true");
        eprintln!("   All use replace semantics (last-write-wins)");
    }

    #[test]
    fn test_attribute_capacity_with_replacements() {
        // AUDIT POINT 4: Verify replacement behavior at attribute capacity limits

        let config = SpanConformanceConfig {
            max_attributes: 3, // Small capacity for testing
            max_events: 10,
            max_attribute_length: None,
            test_sampling: false,
            test_context_propagation: false,
        };

        let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, &config);

        // Fill to capacity
        span.set_attribute("key1", "value1");
        span.set_attribute("key2", "value2");
        span.set_attribute("key3", "value3");

        assert_eq!(span.attributes.len(), 3, "Should be at capacity");
        assert_eq!(span.dropped_attributes_count, 0, "No attributes dropped yet");

        // Replace existing attributes - should succeed
        span.set_attribute("key1", "new_value1");
        span.set_attribute("key2", "new_value2");
        span.set_attribute("key3", "new_value3");

        // Verify replacements succeeded
        assert_eq!(span.attributes.get("key1"), Some(&"new_value1".to_string()));
        assert_eq!(span.attributes.get("key2"), Some(&"new_value2".to_string()));
        assert_eq!(span.attributes.get("key3"), Some(&"new_value3".to_string()));
        assert_eq!(span.attributes.len(), 3, "Still at capacity");
        assert_eq!(span.dropped_attributes_count, 0, "No additional attributes dropped");

        // Try to add new attribute - should be dropped
        span.set_attribute("key4", "value4");

        assert_eq!(span.attributes.len(), 3, "Still at capacity");
        assert_eq!(span.dropped_attributes_count, 1, "New attribute should be dropped");
        assert!(!span.attributes.contains_key("key4"), "key4 should not exist");

        eprintln!("✅ CAPACITY BEHAVIOR:");
        eprintln!("   Replacements at capacity: ✓ (allowed)");
        eprintln!("   New keys at capacity: ✗ (dropped)");
        eprintln!("   Dropped count tracks new keys only");
    }

    #[test]
    fn test_no_duplicate_keys_in_final_state() {
        // AUDIT POINT 5: Comprehensive verification that no duplicate keys exist

        let mut span = TestSpan::new("test_span", SpanKind::Internal);

        // Perform many attribute operations with overlapping keys
        let operations = vec![
            ("http.method", "GET"),
            ("http.url", "https://api.example.com"),
            ("user.id", "user123"),
            ("http.method", "POST"),        // Replace
            ("service.name", "auth-service"),
            ("http.url", "https://auth.example.com"), // Replace
            ("trace.id", "trace456"),
            ("user.id", "user789"),         // Replace
            ("http.method", "PUT"),         // Replace again
            ("service.version", "1.2.3"),
            ("trace.id", "trace999"),       // Replace
        ];

        for (key, value) in operations {
            span.set_attribute(key, value);
        }

        // Collect all keys and check for duplicates
        let mut key_counts: HashMap<String, usize> = HashMap::new();
        for key in span.attributes.keys() {
            *key_counts.entry(key.clone()).or_insert(0) += 1;
        }

        // Verify no duplicate keys exist
        for (key, count) in &key_counts {
            assert_eq!(*count, 1, "Key '{}' appears {} times (should be 1)", key, count);
        }

        // Verify final values are the last-written ones
        assert_eq!(span.attributes.get("http.method"), Some(&"PUT".to_string()));
        assert_eq!(span.attributes.get("http.url"), Some(&"https://auth.example.com".to_string()));
        assert_eq!(span.attributes.get("user.id"), Some(&"user789".to_string()));
        assert_eq!(span.attributes.get("service.name"), Some(&"auth-service".to_string()));
        assert_eq!(span.attributes.get("service.version"), Some(&"1.2.3".to_string()));
        assert_eq!(span.attributes.get("trace.id"), Some(&"trace999".to_string()));

        let unique_key_count = key_counts.len();
        assert_eq!(span.attributes.len(), unique_key_count, "Attribute count should match unique keys");

        eprintln!("✅ DUPLICATE KEY VERIFICATION:");
        eprintln!("   Total attribute operations: {}", 11);
        eprintln!("   Unique keys in final state: {}", unique_key_count);
        eprintln!("   Duplicate keys found: 0");
        eprintln!("   All values represent last-write-wins");
    }

    #[test]
    fn test_otlp_spec_compliance_for_attribute_semantics() {
        // AUDIT POINT 6: Document OTLP specification compliance

        eprintln!("\n📋 OTLP ATTRIBUTE SEMANTICS SPECIFICATION");
        eprintln!("=========================================");
        eprintln!("Per OTLP specification:");
        eprintln!("   • Attributes are key-value pairs with unique keys");
        eprintln!("   • Multiple set_attribute() calls with same key should replace");
        eprintln!("   • No duplicate keys should exist in final attribute map");
        eprintln!("   • Attribute count reflects unique keys, not operations");

        let mut span = TestSpan::new("compliance_test", SpanKind::Internal);

        // Test the specification requirements
        span.set_attribute("test.key", "value1");
        let initial_count = span.attributes.len();

        span.set_attribute("test.key", "value2");  // Should replace, not append
        let after_replace_count = span.attributes.len();

        assert_eq!(initial_count, after_replace_count,
            "Attribute count should not increase on replacement");
        assert_eq!(span.attributes.get("test.key"), Some(&"value2".to_string()),
            "Should have last-written value");

        eprintln!("\n✅ OTLP SPECIFICATION COMPLIANCE:");
        eprintln!("   ✓ Attributes have unique keys");
        eprintln!("   ✓ set_attribute() uses replace semantics");
        eprintln!("   ✓ No duplicate keys created");
        eprintln!("   ✓ Attribute count reflects unique keys");
        eprintln!("   ✓ Last-write-wins behavior");

        eprintln!("\n🚫 WHAT WOULD BE WRONG (append semantics):");
        eprintln!("   ✗ Creating duplicate keys: test.key=value1, test.key=value2");
        eprintln!("   ✗ Concatenating values: test.key='value1,value2'");
        eprintln!("   ✗ Increasing count on replacement operations");

        eprintln!("\n✅ CURRENT IMPLEMENTATION: Replace semantics (CORRECT)");
    }

    #[test]
    fn test_attribute_value_types_replace_consistently() {
        // AUDIT POINT 7: Verify replace semantics across value type changes

        let mut span = TestSpan::new("test_span", SpanKind::Internal);

        // Set attribute as string initially
        span.set_attribute("flexible.value", "string_value");
        assert_eq!(span.attributes.get("flexible.value"), Some(&"string_value".to_string()));

        // Replace with integer (different type)
        span.set_int_attribute("flexible.value", 42);
        // Note: attributes HashMap stores string representation, attribute_values stores typed
        assert_eq!(span.attribute_values.get("flexible.value"), Some(&AttributeValue::Int(42)));

        // Replace with float
        span.set_float_attribute("flexible.value", 3.14);
        assert_eq!(span.attribute_values.get("flexible.value"), Some(&AttributeValue::Float(3.14)));

        // Replace with boolean
        span.set_bool_attribute("flexible.value", true);
        assert_eq!(span.attribute_values.get("flexible.value"), Some(&AttributeValue::Bool(true)));

        // Back to string
        span.set_attribute("flexible.value", "back_to_string");
        assert_eq!(span.attributes.get("flexible.value"), Some(&"back_to_string".to_string()));

        // Verify counts remain 1
        assert_eq!(span.attributes.len(), 1, "Should have 1 attribute in string map");
        assert_eq!(span.attribute_values.len(), 1, "Should have 1 attribute in typed map");

        eprintln!("✅ TYPE CHANGE REPLACEMENTS:");
        eprintln!("   String → Int → Float → Bool → String");
        eprintln!("   All replacements successful");
        eprintln!("   Attribute count remains 1 throughout");
        eprintln!("   Both string and typed maps updated consistently");
    }
}