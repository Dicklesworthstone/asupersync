#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::observability::otel::span_semantics::{SpanConformanceConfig, TestSpan};
use libfuzzer_sys::fuzz_target;
use opentelemetry::trace::SpanKind;

// OTLP specification limits and validation rules
const MAX_SPAN_NAME_LENGTH: usize = 1024;
const MAX_ATTRIBUTE_KEY_LENGTH: usize = 1024;

// Control characters that must be sanitized per OTLP spec
const FORBIDDEN_CHARS: &[char] = &['\0', '\r', '\n'];

/// Arbitrary implementation for generating fuzz test data
#[derive(Arbitrary, Debug)]
struct FuzzOtlpInput {
    span_name: String,
    attribute_keys: Vec<String>,
    attribute_values: Vec<String>,
    span_kind_variant: u8,
}

/// Validates that a string conforms to OTLP spec requirements
fn validate_otlp_string(input: &str, max_length: usize, field_name: &str) -> Result<(), String> {
    // Check for forbidden control characters
    for &forbidden_char in FORBIDDEN_CHARS {
        if input.contains(forbidden_char) {
            return Err(format!(
                "{} contains forbidden character: {:?} (U+{:04X})",
                field_name, forbidden_char, forbidden_char as u32
            ));
        }
    }

    // Check length constraints
    if input.len() > max_length {
        return Err(format!(
            "{} exceeds max length: {} > {} bytes",
            field_name,
            input.len(),
            max_length
        ));
    }

    // Check for valid UTF-8 (should always pass since input is String)
    if !input.is_valid_utf8() {
        return Err(format!("{} contains invalid UTF-8", field_name));
    }

    Ok(())
}

/// Sanitizes a string for OTLP compliance
fn sanitize_otlp_string(input: &str, max_length: usize) -> String {
    // First, sanitize forbidden characters
    let mut sanitized = input
        .chars()
        .map(|c| {
            if FORBIDDEN_CHARS.contains(&c) {
                '_' // Replace forbidden chars with underscore
            } else {
                c
            }
        })
        .collect::<String>();

    // Then truncate to max length while preserving UTF-8 boundaries
    if sanitized.len() > max_length {
        let mut cut = max_length;
        while cut > 0 && !sanitized.is_char_boundary(cut) {
            cut -= 1;
        }
        sanitized.truncate(cut);
    }

    sanitized
}

/// Test helper trait for UTF-8 validation
trait Utf8Validator {
    fn is_valid_utf8(&self) -> bool;
}

impl Utf8Validator for str {
    fn is_valid_utf8(&self) -> bool {
        // If we can construct a &str, it's already valid UTF-8
        true
    }
}

/// Creates sanitized span name according to OTLP spec
fn create_otlp_compliant_span_name(raw_name: &str) -> String {
    let sanitized = sanitize_otlp_string(raw_name, MAX_SPAN_NAME_LENGTH);

    // OTLP spec: empty span names should be replaced with a default
    if sanitized.is_empty() {
        "unknown_operation".to_string()
    } else {
        sanitized
    }
}

/// Creates sanitized attribute key according to OTLP spec
fn create_otlp_compliant_attribute_key(raw_key: &str) -> String {
    let sanitized = sanitize_otlp_string(raw_key, MAX_ATTRIBUTE_KEY_LENGTH);

    // OTLP spec: empty keys should be replaced with a default
    if sanitized.is_empty() {
        "unknown_key".to_string()
    } else {
        sanitized
    }
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent excessive memory usage
    if data.len() > 50_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let fuzz_input = match FuzzOtlpInput::arbitrary(&mut unstructured) {
        Ok(input) => input,
        Err(_) => return, // Not enough data to generate arbitrary input
    };

    // Map span kind variant to actual SpanKind
    let span_kind = match fuzz_input.span_kind_variant % 5 {
        0 => SpanKind::Internal,
        1 => SpanKind::Server,
        2 => SpanKind::Client,
        3 => SpanKind::Producer,
        _ => SpanKind::Consumer,
    };

    // Test 1: Span name validation and sanitization
    let raw_span_name = &fuzz_input.span_name;
    let sanitized_span_name = create_otlp_compliant_span_name(raw_span_name);

    // Verify sanitized span name meets OTLP requirements
    if let Err(e) = validate_otlp_string(&sanitized_span_name, MAX_SPAN_NAME_LENGTH, "span_name") {
        panic!("Span name sanitization failed: {}", e);
    }

    // Verify no forbidden characters remain
    for &forbidden_char in FORBIDDEN_CHARS {
        if sanitized_span_name.contains(forbidden_char) {
            panic!(
                "Sanitized span name still contains forbidden character: {:?}",
                forbidden_char
            );
        }
    }

    // Test 2: Create span with sanitized name
    let config = SpanConformanceConfig::default();
    let mut span = TestSpan::new_with_config(&sanitized_span_name, span_kind, &config);

    // Verify the span was created successfully
    assert_eq!(span.name, sanitized_span_name);
    assert_eq!(span.kind, span_kind);

    // Test 3: Attribute key validation and sanitization
    for (i, raw_key) in fuzz_input.attribute_keys.iter().enumerate() {
        let sanitized_key = create_otlp_compliant_attribute_key(raw_key);

        // Verify sanitized key meets OTLP requirements
        if let Err(e) =
            validate_otlp_string(&sanitized_key, MAX_ATTRIBUTE_KEY_LENGTH, "attribute_key")
        {
            panic!("Attribute key sanitization failed for key {}: {}", i, e);
        }

        // Verify no forbidden characters remain
        for &forbidden_char in FORBIDDEN_CHARS {
            if sanitized_key.contains(forbidden_char) {
                panic!(
                    "Sanitized attribute key {} still contains forbidden character: {:?}",
                    i, forbidden_char
                );
            }
        }

        // Test setting the attribute
        let value = fuzz_input
            .attribute_values
            .get(i)
            .unwrap_or(&"default_value".to_string());

        span.set_attribute(&sanitized_key, value);

        // Verify the attribute was stored properly
        if span.attributes.len() > i + 1 {
            // Note: The actual stored key might be truncated by the implementation
            let stored_keys: Vec<&String> = span.attributes.keys().collect();
            let stored_key = stored_keys.last().unwrap();

            // Verify stored key doesn't exceed limits
            assert!(
                stored_key.len() <= MAX_ATTRIBUTE_KEY_LENGTH,
                "Stored attribute key exceeds max length: {} > {}",
                stored_key.len(),
                MAX_ATTRIBUTE_KEY_LENGTH
            );

            // Verify stored key has no forbidden characters
            for &forbidden_char in FORBIDDEN_CHARS {
                assert!(
                    !stored_key.contains(forbidden_char),
                    "Stored attribute key contains forbidden character: {:?}",
                    forbidden_char
                );
            }
        }
    }

    // Test 4: Edge cases and invariants

    // Verify span name is never empty after sanitization
    assert!(
        !span.name.is_empty(),
        "Span name should never be empty after sanitization"
    );

    // Test extreme inputs
    let extreme_inputs = vec![
        "\0".repeat(2000),          // Null bytes
        "\r\n".repeat(1000),        // CRLF sequences
        "🔥".repeat(500),           // Unicode emoji
        "a".repeat(5000),           // Very long ASCII
        "\u{0000}\u{001F}\u{007F}", // Control characters
        "",                         // Empty string
        " \t\n\r ",                 // Whitespace only
    ];

    for extreme_input in extreme_inputs {
        let sanitized_name = create_otlp_compliant_span_name(&extreme_input);
        let sanitized_key = create_otlp_compliant_attribute_key(&extreme_input);

        // Both should be valid after sanitization
        validate_otlp_string(&sanitized_name, MAX_SPAN_NAME_LENGTH, "extreme_span_name")
            .expect("Extreme span name should be sanitized properly");
        validate_otlp_string(
            &sanitized_key,
            MAX_ATTRIBUTE_KEY_LENGTH,
            "extreme_attribute_key",
        )
        .expect("Extreme attribute key should be sanitized properly");

        // Both should be non-empty after sanitization
        assert!(
            !sanitized_name.is_empty(),
            "Sanitized span name should not be empty"
        );
        assert!(
            !sanitized_key.is_empty(),
            "Sanitized attribute key should not be empty"
        );
    }

    // Test 5: UTF-8 boundary preservation
    let multibyte_test = "🔒".repeat(400); // Each emoji is 4 bytes
    let sanitized_multibyte = sanitize_otlp_string(&multibyte_test, MAX_ATTRIBUTE_KEY_LENGTH);

    // Verify it's still valid UTF-8 after truncation
    assert!(
        sanitized_multibyte.is_valid_utf8(),
        "Sanitized multibyte string should remain valid UTF-8"
    );
    assert!(
        sanitized_multibyte.len() <= MAX_ATTRIBUTE_KEY_LENGTH,
        "Sanitized multibyte string should respect length limits"
    );

    // Test 6: Roundtrip validation
    // After sanitization, re-sanitizing should be idempotent
    let double_sanitized_name = create_otlp_compliant_span_name(&sanitized_span_name);
    assert_eq!(
        sanitized_span_name, double_sanitized_name,
        "Sanitization should be idempotent for span names"
    );

    for (i, raw_key) in fuzz_input.attribute_keys.iter().enumerate().take(5) {
        let sanitized_key = create_otlp_compliant_attribute_key(raw_key);
        let double_sanitized_key = create_otlp_compliant_attribute_key(&sanitized_key);
        assert_eq!(
            sanitized_key, double_sanitized_key,
            "Sanitization should be idempotent for attribute key {}",
            i
        );
    }

    // Test 7: Performance bounds - sanitization should not take excessive time
    let start = std::time::Instant::now();
    let _performance_test = create_otlp_compliant_span_name(&fuzz_input.span_name);
    let elapsed = start.elapsed();

    // Sanitization should complete within reasonable time (1ms per 1KB of input)
    let max_duration =
        std::time::Duration::from_millis((fuzz_input.span_name.len() / 1024 + 1) as u64);
    assert!(
        elapsed <= max_duration,
        "Span name sanitization took too long: {:?} > {:?}",
        elapsed,
        max_duration
    );
});
