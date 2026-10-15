//! W3C Trace ID format compliance audit test.
//!
//! **AUDIT SCOPE**: Verifies strict compliance with W3C Trace Context specification
//! for trace_id format, validation, and generation.
//!
//! **W3C REQUIREMENTS**:
//! - trace_id MUST be exactly 32 hex characters (16 bytes)
//! - trace_id MUST NOT be all zeros (invalid per spec)
//! - Generators MUST produce cryptographically random trace_ids
//! - Parsers MUST reject invalid formats and all-zero values
//!
//! **Reference**: https://w3c.github.io/trace-context/

#![cfg(test)]

use crate::observability::w3c_trace_context::{TraceContextError, TraceId, W3CTraceContext};
use std::collections::HashSet;
use std::str::FromStr;

/// **AUDIT TEST**: Trace ID generator never produces all-zeros.
///
/// **REQUIREMENT**: W3C spec mandates trace_id cannot be all zeros.
/// **RISK**: All-zero trace_id breaks trace correlation in downstream systems.
#[test]
fn audit_trace_id_generator_never_all_zeros() {
    let mut generated_ids = HashSet::new();

    // Generate 1000 trace IDs to verify no all-zeros and reasonable entropy
    for i in 0..1000 {
        let trace_id = TraceId::new_random();
        let hex_string = trace_id.to_hex();

        // CRITICAL: Must never generate all-zeros
        assert_ne!(
            hex_string, "00000000000000000000000000000000",
            "Iteration {}: Generated all-zero trace_id (FORBIDDEN by W3C spec)",
            i
        );

        // Verify format: exactly 32 hex characters
        assert_eq!(
            hex_string.len(),
            32,
            "Iteration {}: trace_id must be exactly 32 hex chars, got {}",
            i,
            hex_string.len()
        );

        // Verify all characters are valid hex
        assert!(
            hex_string.chars().all(|c| c.is_ascii_hexdigit()),
            "Iteration {}: trace_id contains non-hex characters: {}",
            i,
            hex_string
        );

        // Track uniqueness (basic entropy check)
        generated_ids.insert(hex_string);
    }

    // Verify reasonable entropy (no duplicates in 1000 generations)
    assert_eq!(
        generated_ids.len(),
        1000,
        "Expected 1000 unique trace_ids, got {} (possible entropy issue)",
        generated_ids.len()
    );

    println!("✅ AUDIT PASSED: TraceId::new_random() never generates all-zeros");
    println!("   Generated 1000 unique trace_ids with proper entropy");
}

/// **AUDIT TEST**: Parser strictly rejects all-zero trace_ids.
///
/// **REQUIREMENT**: W3C spec requires rejecting all-zero trace_id.
/// **ATTACK VECTOR**: Malicious clients might inject all-zero trace_id.
#[test]
fn audit_parser_rejects_all_zero_trace_id() {
    // Test cases: various representations of all-zero trace_id
    let all_zero_cases = vec![
        "00000000000000000000000000000000".to_string(), // explicit all-zeros
        "0".repeat(32),                                 // generated all-zeros
    ];

    for zero_trace_id in all_zero_cases {
        let result = TraceId::from_str(&zero_trace_id);

        assert!(
            result.is_err(),
            "Parser must reject all-zero trace_id: {}",
            zero_trace_id
        );

        assert!(
            matches!(&result, Err(TraceContextError::InvalidTraceId)),
            "Expected InvalidTraceId error for all-zero trace_id {}, got: {:?}",
            zero_trace_id,
            result
        );
    }

    // Verify full W3C context parsing also rejects all-zero trace_id
    let invalid_traceparent = "00-00000000000000000000000000000000-1234567890abcdef-01";
    let result = W3CTraceContext::from_str(invalid_traceparent);

    assert!(
        result.is_err(),
        "W3CTraceContext must reject traceparent with all-zero trace_id"
    );

    println!("✅ AUDIT PASSED: Parser strictly rejects all-zero trace_ids");
}

/// **AUDIT TEST**: Parser validates trace_id length and format.
///
/// **REQUIREMENT**: trace_id must be exactly 32 hex characters.
/// **SECURITY**: Prevents buffer overflows and format confusion attacks.
#[test]
fn audit_parser_validates_trace_id_format() {
    let invalid_cases = vec![
        // Wrong length cases
        ("", "empty string"),
        ("1234", "too short"),
        ("1234567890abcdef1234567890abcdef0", "too long (33 chars)"),
        ("1234567890abcdef1234567890abcde", "too short (31 chars)"),
        // Invalid character cases
        ("1234567890abcdefg123567890abcdef", "contains 'g' (not hex)"),
        ("1234567890abcdef 123567890abcdef", "contains space"),
        ("1234567890abcdef-123567890abcdef", "contains dash"),
    ];

    for (invalid_trace_id, description) in invalid_cases {
        let result = TraceId::from_str(invalid_trace_id);

        assert!(
            result.is_err(),
            "Parser must reject invalid trace_id ({}): '{}'",
            description,
            invalid_trace_id
        );

        println!("✅ Rejected {}: '{}'", description, invalid_trace_id);
    }

    println!("✅ AUDIT PASSED: Parser validates trace_id format strictly");
}

/// **AUDIT TEST**: Valid trace_id parsing and round-trip consistency.
///
/// **REQUIREMENT**: Valid trace_ids must parse correctly and round-trip.
/// **VERIFICATION**: Ensures parser doesn't reject valid inputs.
#[test]
fn audit_valid_trace_id_parsing() {
    let valid_cases = vec![
        (
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "4bf92f3577b34da6a3ce929d0e0e4736",
        ),
        (
            "1234567890abcdef1234567890abcdef",
            "1234567890abcdef1234567890abcdef",
        ),
        (
            "abcdef1234567890abcdef1234567890",
            "abcdef1234567890abcdef1234567890",
        ),
        (
            "1234567890ABCDEF1234567890abcdef",
            "1234567890abcdef1234567890abcdef",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffff",
        ), // max value
        (
            "00000000000000000000000000000001",
            "00000000000000000000000000000001",
        ), // minimal non-zero
    ];

    for (valid_trace_id, expected_hex) in valid_cases {
        // Parse trace_id
        let trace_id = TraceId::from_str(valid_trace_id).unwrap_or_else(|err| {
            panic!(
                "Valid trace_id '{}' must parse successfully: {}",
                valid_trace_id, err
            )
        });

        // Verify round-trip consistency
        let round_trip = trace_id.to_hex();
        assert_eq!(
            round_trip,
            expected_hex,
            "Round-trip failed: {} -> {} -> {}",
            valid_trace_id,
            trace_id.to_hex(),
            round_trip
        );

        println!(
            "✅ Valid trace_id parsed and round-tripped: {}",
            valid_trace_id
        );
    }

    println!("✅ AUDIT PASSED: Valid trace_ids parse correctly with round-trip consistency");
}

/// **AUDIT TEST**: W3C traceparent format compliance.
///
/// **REQUIREMENT**: Full traceparent format must follow W3C specification.
/// **FORMAT**: "00-{trace_id}-{span_id}-{flags}" with exact field lengths.
#[test]
fn audit_w3c_traceparent_format_compliance() {
    // Generate valid context
    let context = W3CTraceContext::new_root();
    let traceparent = context.to_traceparent();

    // Verify format: "00-{32-hex}-{16-hex}-{2-hex}"
    let parts: Vec<&str> = traceparent.split('-').collect();
    assert_eq!(
        parts.len(),
        4,
        "traceparent must have exactly 4 dash-separated parts"
    );

    // Version must be "00"
    assert_eq!(parts[0], "00", "version must be '00' per W3C spec");

    // Trace ID: 32 hex characters
    assert_eq!(parts[1].len(), 32, "trace_id must be exactly 32 hex chars");
    assert!(
        parts[1].chars().all(|c| c.is_ascii_hexdigit()),
        "trace_id must contain only hex characters: {}",
        parts[1]
    );
    assert_ne!(
        parts[1], "00000000000000000000000000000000",
        "trace_id cannot be all zeros"
    );

    // Span ID: 16 hex characters
    assert_eq!(parts[2].len(), 16, "span_id must be exactly 16 hex chars");
    assert!(
        parts[2].chars().all(|c| c.is_ascii_hexdigit()),
        "span_id must contain only hex characters: {}",
        parts[2]
    );
    assert_ne!(parts[2], "0000000000000000", "span_id cannot be all zeros");

    // Flags: 2 hex characters
    assert_eq!(parts[3].len(), 2, "flags must be exactly 2 hex chars");
    assert!(
        parts[3].chars().all(|c| c.is_ascii_hexdigit()),
        "flags must contain only hex characters: {}",
        parts[3]
    );

    println!("✅ AUDIT PASSED: W3C traceparent format fully compliant");
    println!("   Generated: {}", traceparent);
}

/// **AUDIT TEST**: Security bounds on trace_id processing.
///
/// **REQUIREMENT**: Prevent amplification attacks via oversized trace_ids.
/// **SECURITY**: Bounded parsing prevents log/memory amplification.
#[test]
fn audit_trace_id_security_bounds() {
    // Test oversized trace_id rejection
    let oversized_trace_id = "1".repeat(200);
    let oversized_traceparent = format!("00-{}-1234567890abcdef-01", oversized_trace_id);

    let result = W3CTraceContext::from_str(&oversized_traceparent);
    assert!(
        result.is_err(),
        "Oversized traceparent must be rejected for security"
    );

    println!("✅ AUDIT PASSED: Security bounds prevent trace_id amplification attacks");
}

/// **COMPREHENSIVE AUDIT REPORT**: Pin current W3C trace_id compliance.
#[test]
fn comprehensive_w3c_trace_id_compliance_report() {
    println!("\n🔍 COMPREHENSIVE W3C TRACE_ID COMPLIANCE AUDIT");
    println!("================================================");

    // Test all requirements
    audit_trace_id_generator_never_all_zeros();
    audit_parser_rejects_all_zero_trace_id();
    audit_parser_validates_trace_id_format();
    audit_valid_trace_id_parsing();
    audit_w3c_traceparent_format_compliance();
    audit_trace_id_security_bounds();

    println!("\n✅ AUDIT COMPLETE: W3C Trace Context trace_id handling is FULLY COMPLIANT");
    println!("   ✓ Generator never produces all-zeros");
    println!("   ✓ Parser rejects all-zero trace_ids");
    println!("   ✓ Format validation enforces 32 hex chars");
    println!("   ✓ Security bounds prevent amplification");
    println!("   ✓ Round-trip consistency preserved");
    println!("   ✓ Full W3C traceparent compliance");
    println!("\n📋 COMPLIANCE STATUS: SOUND - Behavior pinned by audit tests");
}
