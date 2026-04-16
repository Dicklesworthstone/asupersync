#![no_main]

use libfuzzer_sys::fuzz_target;

/// Redis RESP protocol fuzz testing for parser robustness.
///
/// This fuzz target extensively tests the Redis RESP (REdis Serialization Protocol)
/// parsing functions to ensure they handle malformed, malicious, and edge-case inputs
/// without crashes, memory leaks, or security vulnerabilities.
///
/// Targets the following critical parsing functions:
/// - RespValue::try_decode_with_limits() - Core RESP parser with protocol limits
/// - find_crlf() helper - CRLF line ending detection
/// - parse_i64_ascii() helper - ASCII integer parsing
/// - check_complete() validation - Recursive structure validation
///
/// Test cases cover:
/// - Valid RESP types: Simple strings (+), errors (-), integers (:), bulk strings ($), arrays (*)
/// - Nested arrays with deep nesting (test max_nesting_depth limit)
/// - Large bulk strings and arrays (test memory limits)
/// - Malformed/truncated inputs, protocol violations
/// - Integer overflow edge cases, invalid UTF-8
/// - Memory exhaustion protection verification

// Import the Redis module to test
use asupersync::messaging::redis::{RespValue, RedisProtocolLimits};

/// Generate valid RESP test cases for baseline testing
fn generate_valid_resp_samples(data: &[u8]) -> Vec<Vec<u8>> {
    let mut samples = Vec::new();

    if data.is_empty() {
        return samples;
    }

    // Generate simple string: +OK\r\n
    samples.push(b"+OK\r\n".to_vec());
    samples.push(b"+PONG\r\n".to_vec());

    // Generate error: -ERR unknown command\r\n
    samples.push(b"-ERR unknown command\r\n".to_vec());
    samples.push(b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n".to_vec());

    // Generate integers: :1000\r\n
    samples.push(b":0\r\n".to_vec());
    samples.push(b":1000\r\n".to_vec());
    samples.push(b":-42\r\n".to_vec());
    samples.push(b":9223372036854775807\r\n".to_vec()); // i64::MAX
    samples.push(b":-9223372036854775808\r\n".to_vec()); // i64::MIN

    // Generate bulk strings: $6\r\nfoobar\r\n
    samples.push(b"$6\r\nfoobar\r\n".to_vec());
    samples.push(b"$0\r\n\r\n".to_vec()); // Empty string
    samples.push(b"$-1\r\n".to_vec()); // NULL bulk string

    // Generate arrays: *2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n
    samples.push(b"*0\r\n".to_vec()); // Empty array
    samples.push(b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n".to_vec());
    samples.push(b"*-1\r\n".to_vec()); // NULL array

    // Generate nested arrays
    samples.push(b"*2\r\n*3\r\n:1\r\n:2\r\n:3\r\n*2\r\n+Foo\r\n-Bar\r\n".to_vec());

    // Use part of input data as string content (if valid UTF-8)
    if let Ok(s) = std::str::from_utf8(data.get(..data.len().min(50)).unwrap_or(&[])) {
        let content = s.replace('\r', "").replace('\n', "");
        if !content.is_empty() {
            samples.push(format!("+{content}\r\n").into_bytes());
            samples.push(format!("-ERR {content}\r\n").into_bytes());
            samples.push(format!("${}\r\n{content}\r\n", content.len()).into_bytes());
        }
    }

    samples
}

/// Generate malformed RESP data for edge case testing
fn generate_malformed_resp_data(data: &[u8]) -> Vec<Vec<u8>> {
    let mut malformed = Vec::new();

    if data.is_empty() {
        return malformed;
    }

    // Truncated/incomplete messages
    malformed.push(b"+OK".to_vec()); // Missing CRLF
    malformed.push(b"+OK\r".to_vec()); // Missing LF
    malformed.push(b"+OK\n".to_vec()); // Wrong line ending

    malformed.push(b":123".to_vec()); // Truncated integer
    malformed.push(b":".to_vec()); // Empty integer

    malformed.push(b"$5\r\nfoo".to_vec()); // Truncated bulk string
    malformed.push(b"$5".to_vec()); // Missing CRLF after length
    malformed.push(b"$".to_vec()); // Empty bulk string length

    malformed.push(b"*2\r\n+OK\r\n".to_vec()); // Array with wrong count
    malformed.push(b"*".to_vec()); // Empty array count

    // Invalid length values
    malformed.push(b"$-2\r\n".to_vec()); // Invalid negative length
    malformed.push(b"*-2\r\n".to_vec()); // Invalid negative array size

    // Very large lengths (memory exhaustion attempts)
    malformed.push(b"$999999999999999999\r\n".to_vec());
    malformed.push(b"*999999999999999999\r\n".to_vec());

    // Integer overflow attempts
    malformed.push(b":999999999999999999999999999999999\r\n".to_vec());
    malformed.push(b":-999999999999999999999999999999999\r\n".to_vec());

    // Non-ASCII/Unicode content in bulk strings
    if data.len() > 4 {
        let len = data.len().min(100);
        malformed.push(format!("${len}\r\n").into_bytes());
        malformed.extend_from_slice(data.get(..len).unwrap_or(&[]));
        malformed.extend_from_slice(b"\r\n");
    }

    // Invalid RESP type markers
    malformed.push(b"@invalid\r\n".to_vec());
    malformed.push(b"#hashtag\r\n".to_vec());
    malformed.push(b"!exclamation\r\n".to_vec());

    // Control characters and special bytes
    malformed.push(vec![0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
    malformed.push(b"\x00+OK\r\n".to_vec());
    malformed.push(b"+\x00\x01\x02\r\n".to_vec());

    malformed
}

/// Generate deeply nested arrays for nesting limit testing
fn generate_deep_nesting_data(depth: usize) -> Vec<u8> {
    let mut data = Vec::new();

    // Create nested arrays: *1\r\n*1\r\n*1\r\n...
    for _ in 0..depth {
        data.extend_from_slice(b"*1\r\n");
    }
    // Terminate with a simple value
    data.extend_from_slice(b"+END\r\n");

    data
}

/// Generate large arrays for array length limit testing
fn generate_large_array_data(count: usize) -> Vec<u8> {
    let mut data = Vec::new();

    data.extend_from_slice(format!("*{count}\r\n").as_bytes());
    for i in 0..count.min(1000) { // Cap iteration to prevent OOM during test generation
        data.extend_from_slice(format!(":{i}\r\n").as_bytes());
    }

    data
}

/// Test helper functions in isolation
fn test_helper_functions(data: &[u8]) {
    // Test find_crlf with various scenarios
    for start_pos in [0, 1, data.len().saturating_sub(1)] {
        // Call through RespValue to access find_crlf indirectly
        let _ = RespValue::try_decode(data);
    }

    // Test parse_i64_ascii by creating integer RESP values
    if let Ok(s) = std::str::from_utf8(data) {
        let clean_str = s.chars().filter(|c| c.is_ascii_digit() || *c == '-' || *c == '+').take(20).collect::<String>();
        if !clean_str.is_empty() {
            let resp_data = format!(":{clean_str}\r\n");
            let _ = RespValue::try_decode(resp_data.as_bytes());
        }
    }
}

/// Test protocol limits enforcement
fn test_protocol_limits(data: &[u8]) {
    // Test with strict limits
    let strict_limits = RedisProtocolLimits {
        max_frame_size: 1024,
        max_nesting_depth: 5,
        max_array_len: 10,
        max_bulk_string_len: 100,
    };

    let _ = RespValue::try_decode_with_limits(data, &strict_limits);

    // Test with very permissive limits
    let permissive_limits = RedisProtocolLimits {
        max_frame_size: 100_000_000,
        max_nesting_depth: 1000,
        max_array_len: 10_000_000,
        max_bulk_string_len: 1_000_000_000,
    };

    let _ = RespValue::try_decode_with_limits(data, &permissive_limits);

    // Test with minimal limits
    let minimal_limits = RedisProtocolLimits {
        max_frame_size: 1,
        max_nesting_depth: 1,
        max_array_len: 1,
        max_bulk_string_len: 1,
    };

    let _ = RespValue::try_decode_with_limits(data, &minimal_limits);
}

/// Round-trip test: encode then decode should preserve structure
fn test_round_trip_properties(data: &[u8]) {
    // Only test round-trip on successfully parsed values
    if let Ok(Some((value, _))) = RespValue::try_decode(data) {
        let encoded = value.encode();

        // The re-encoded value should parse successfully
        if let Ok(Some((value2, _))) = RespValue::try_decode(&encoded) {
            // Check basic structural equality
            assert_eq!(std::mem::discriminant(&value), std::mem::discriminant(&value2));

            // For non-recursive types, check exact equality
            match (&value, &value2) {
                (RespValue::SimpleString(s1), RespValue::SimpleString(s2)) => assert_eq!(s1, s2),
                (RespValue::Error(e1), RespValue::Error(e2)) => assert_eq!(e1, e2),
                (RespValue::Integer(i1), RespValue::Integer(i2)) => assert_eq!(i1, i2),
                (RespValue::BulkString(b1), RespValue::BulkString(b2)) => assert_eq!(b1, b2),
                _ => {} // Skip arrays due to potential recursion complexity
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs to prevent OOM during testing
    if data.len() > 1_000_000 {
        return;
    }

    // Test 1: Direct parsing of fuzz input with default limits
    let _ = RespValue::try_decode(data);

    // Test 2: Direct parsing with various protocol limits
    test_protocol_limits(data);

    // Test 3: Test all RESP type parsing through valid samples
    let valid_samples = generate_valid_resp_samples(data);
    for sample in &valid_samples {
        let result = RespValue::try_decode(sample);

        // Valid samples should generally parse successfully
        if let Ok(Some((value, consumed))) = result {
            // Verify consumed bytes make sense
            assert!(consumed <= sample.len());

            // Test encoding round-trip
            let encoded = value.encode();
            let _ = RespValue::try_decode(&encoded);
        }
    }

    // Test 4: Test parsing with malformed/edge case data
    let malformed_samples = generate_malformed_resp_data(data);
    for sample in &malformed_samples {
        let _ = RespValue::try_decode(sample);
    }

    // Test 5: Test helper functions indirectly
    test_helper_functions(data);

    // Test 6: Test deep nesting scenarios (up to reasonable depth)
    let max_test_depth = if data.is_empty() { 0 } else { (data[0] as usize % 100) + 1 };
    for depth in [1, 5, 10, max_test_depth.min(200)].iter().copied() {
        let deep_data = generate_deep_nesting_data(depth);
        let _ = RespValue::try_decode(&deep_data);
    }

    // Test 7: Test large array scenarios
    let max_test_count = if data.is_empty() { 0 } else { (data[0] as usize % 1000) + 1 };
    for count in [0, 1, 10, max_test_count.min(5000)].iter().copied() {
        let large_array_data = generate_large_array_data(count);
        let _ = RespValue::try_decode(&large_array_data);
    }

    // Test 8: Round-trip property verification
    test_round_trip_properties(data);

    // Test 9: Fragmented parsing simulation (partial buffer scenarios)
    if data.len() > 10 {
        for split_point in [1, data.len() / 4, data.len() / 2, data.len() - 1].iter().copied() {
            if split_point < data.len() {
                let first_part = &data[..split_point];
                let second_part = &data[split_point..];

                // Test parsing of partial data (should return Ok(None) for incomplete)
                let _ = RespValue::try_decode(first_part);

                // Test parsing of combined data
                let mut combined = first_part.to_vec();
                combined.extend_from_slice(second_part);
                let _ = RespValue::try_decode(&combined);
            }
        }
    }

    // Test 10: Boundary value testing for limits
    let boundary_limits = [
        RedisProtocolLimits {
            max_frame_size: data.len().saturating_sub(1).max(1),
            max_nesting_depth: 1,
            max_array_len: 1,
            max_bulk_string_len: 1,
        },
        RedisProtocolLimits {
            max_frame_size: data.len() + 1,
            max_nesting_depth: 64,
            max_array_len: 1_000_000,
            max_bulk_string_len: 512 * 1024 * 1024,
        },
    ];

    for limits in &boundary_limits {
        let _ = RespValue::try_decode_with_limits(data, limits);
    }
});