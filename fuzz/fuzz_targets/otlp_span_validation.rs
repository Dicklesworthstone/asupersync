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
            let codepoint = forbidden_char as u32;
            return Err(format!(
                "{field_name} contains forbidden character: {forbidden_char:?} (U+{codepoint:04X})"
            ));
        }
    }

    // Check length constraints
    if input.len() > max_length {
        let input_len = input.len();
        return Err(format!(
            "{field_name} exceeds max length: {input_len} > {max_length} bytes"
        ));
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
        panic!("Span name sanitization failed: {e}");
    }

    // Verify no forbidden characters remain
    for &forbidden_char in FORBIDDEN_CHARS {
        if sanitized_span_name.contains(forbidden_char) {
            panic!("Sanitized span name still contains forbidden character: {forbidden_char:?}");
        }
    }

    // Test 2: Create span with sanitized name
    let config = SpanConformanceConfig::default();
    let expected_span_kind = span_kind.clone();
    let mut span = TestSpan::new_with_config(&sanitized_span_name, span_kind, &config);

    // Verify the span was created successfully
    assert_eq!(span.name, sanitized_span_name);
    assert_eq!(span.kind, expected_span_kind);

    // Test 3: Attribute key validation and sanitization
    for (i, raw_key) in fuzz_input.attribute_keys.iter().enumerate() {
        let sanitized_key = create_otlp_compliant_attribute_key(raw_key);

        // Verify sanitized key meets OTLP requirements
        if let Err(e) =
            validate_otlp_string(&sanitized_key, MAX_ATTRIBUTE_KEY_LENGTH, "attribute_key")
        {
            panic!("Attribute key sanitization failed for key {i}: {e}");
        }

        // Verify no forbidden characters remain
        for &forbidden_char in FORBIDDEN_CHARS {
            if sanitized_key.contains(forbidden_char) {
                panic!(
                    "Sanitized attribute key {i} still contains forbidden character: {forbidden_char:?}"
                );
            }
        }

        // Test setting the attribute
        let value = fuzz_input
            .attribute_values
            .get(i)
            .map_or("default_value", String::as_str);

        span.set_attribute(&sanitized_key, value);

        // Verify the stored keys stay compliant even after implementation-side truncation.
        for stored_key in span.attributes.keys() {
            let stored_len = stored_key.len();
            assert!(
                stored_len <= MAX_ATTRIBUTE_KEY_LENGTH,
                "Stored attribute key exceeds max length: {stored_len} > {MAX_ATTRIBUTE_KEY_LENGTH}"
            );

            for &forbidden_char in FORBIDDEN_CHARS {
                assert!(
                    !stored_key.contains(forbidden_char),
                    "Stored attribute key contains forbidden character: {forbidden_char:?}"
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
    let extreme_inputs = [
        "\0".repeat(2000),                      // Null bytes
        "\r\n".repeat(1000),                    // CRLF sequences
        "🔥".repeat(500),                       // Unicode emoji
        "a".repeat(5000),                       // Very long ASCII
        "\u{0000}\u{001F}\u{007F}".to_string(), // Control characters
        String::new(),                          // Empty string
        " \t\n\r ".to_string(),                 // Whitespace only
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
        std::str::from_utf8(sanitized_multibyte.as_bytes()).is_ok(),
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
            "Sanitization should be idempotent for attribute key {i}"
        );
    }
});
