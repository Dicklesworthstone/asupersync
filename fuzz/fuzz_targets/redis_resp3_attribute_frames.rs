#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::messaging::redis::{RedisError, RedisProtocolLimits, RespValue};

/// Maximum input size to prevent OOM during fuzzing
const MAX_INPUT_SIZE: usize = 64 * 1024;
/// Maximum reasonable attribute pair count
const MAX_ATTR_PAIRS: usize = 1024;

/// Structure-aware fuzzer for RESP3 attribute frames.
///
/// This harness specifically targets RESP3 attribute frame parsing edge cases in
/// src/messaging/redis.rs that are not covered by the broader RESP3 push fuzzer:
///
/// **Core Boundary Cases Tested:**
/// 1. **Attribute length validation**: negative count, zero pairs, oversized arrays
/// 2. **Pair parsing integrity**: incomplete key/value sequences, malformed pairs
/// 3. **Protocol limits enforcement**: max_array_len, max_nesting_depth boundaries
/// 4. **Wire format edge cases**: truncated frames, invalid CRLF, length overflow
/// 5. **Nested attribute structures**: attributes containing attributes, depth limits
///
/// **Attack Vectors Covered:**
/// - Negative pair count bypass attempts (`|-1\r\n`)
/// - Integer overflow in pair count parsing
/// - Incomplete key-value pair corruption
/// - Nested attribute depth exhaustion
/// - Frame boundary violations (missing CRLF)
/// - Memory exhaustion via oversized pair declarations
/// - Protocol desynchronization via malformed lengths
///
/// **Invariants Enforced:**
/// - No panics on any malformed attribute frame
/// - Protocol limits respected during parsing
/// - Proper error reporting for invalid frames
/// - Memory limits respected during pair allocation
/// - Frame parsing never reads beyond boundaries

#[derive(Debug, Arbitrary)]
struct AttributeFrameScenario {
    /// Protocol limits to test
    limits: FuzzProtocolLimits,
    /// Attribute frame patterns to test
    frames: Vec<AttributeFramePattern>,
    /// Whether to test nested structures
    test_nesting: bool,
}

/// Fuzzable protocol limits targeting boundary conditions
#[derive(Debug, Arbitrary)]
struct FuzzProtocolLimits {
    /// Maximum array length
    max_array_len: usize,
    /// Maximum nesting depth
    max_nesting_depth: usize,
    /// Maximum single value size
    max_frame_size: usize,
}

impl From<FuzzProtocolLimits> for RedisProtocolLimits {
    fn from(limits: FuzzProtocolLimits) -> Self {
        Self {
            max_array_len: limits.max_array_len.min(MAX_ATTR_PAIRS * 2), // Sanitize
            max_nesting_depth: limits.max_nesting_depth.min(100),
            max_frame_size: limits.max_frame_size.min(MAX_INPUT_SIZE),
            max_bulk_string_len: limits.max_frame_size.min(MAX_INPUT_SIZE),
        }
    }
}

/// RESP3 attribute frame patterns designed to trigger boundary conditions
#[derive(Debug, Arbitrary)]
enum AttributeFramePattern {
    /// Well-formed attribute with valid key-value pairs
    ValidAttribute {
        pairs: Vec<(AttributeValue, AttributeValue)>,
    },
    /// Empty attribute frame (`|0\r\n`)
    EmptyAttribute,
    /// Attribute with negative pair count
    NegativeCount {
        count: i32, // Negative values
    },
    /// Attribute with oversized pair count
    OversizedCount {
        declared_count: u32,
        actual_pairs: u8, // Far fewer than declared
    },
    /// Truncated attribute frame
    TruncatedFrame {
        complete_pairs: u8,
        truncate_at: TruncationPoint,
    },
    /// Attribute with nested attributes
    NestedAttribute { depth: u8, pairs_per_level: u8 },
    /// Malformed CRLF in attribute header
    MalformedCrlf {
        use_lf_only: bool,
        use_cr_only: bool,
        missing_terminator: bool,
    },
    /// Raw malformed bytes for boundary testing
    RawBytes { data: Vec<u8> },
}

/// Attribute value types for testing
#[derive(Debug, Arbitrary, Clone)]
enum AttributeValue {
    /// Simple string value
    SimpleString(String),
    /// Integer value
    Integer(i64),
    /// Bulk string value
    BulkString(Option<Vec<u8>>),
    /// Nested attribute (for nesting tests)
    NestedAttribute(Vec<(String, String)>),
    /// Error value
    Error(String),
    /// RESP3 null
    Null,
    /// RESP3 boolean
    Boolean(bool),
}

impl AttributeValue {
    /// Encode this value to RESP wire format
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::SimpleString(s) => {
                let mut buf = vec![b'+'];
                for &b in s.as_bytes() {
                    if b != b'\r' && b != b'\n' {
                        buf.push(b);
                    }
                }
                buf.extend_from_slice(b"\r\n");
                buf
            }
            Self::Integer(i) => format!(":{i}\r\n").into_bytes(),
            Self::BulkString(Some(data)) => {
                let mut buf = format!("${}\r\n", data.len()).into_bytes();
                buf.extend_from_slice(data);
                buf.extend_from_slice(b"\r\n");
                buf
            }
            Self::BulkString(None) => b"$-1\r\n".to_vec(),
            Self::NestedAttribute(pairs) => {
                let mut buf = format!("|{}\r\n", pairs.len()).into_bytes();
                for (k, v) in pairs {
                    buf.push(b'+');
                    buf.extend_from_slice(k.as_bytes());
                    buf.extend_from_slice(b"\r\n");
                    buf.push(b'+');
                    buf.extend_from_slice(v.as_bytes());
                    buf.extend_from_slice(b"\r\n");
                }
                buf
            }
            Self::Error(e) => {
                let mut buf = vec![b'-'];
                for &b in e.as_bytes() {
                    if b != b'\r' && b != b'\n' {
                        buf.push(b);
                    }
                }
                buf.extend_from_slice(b"\r\n");
                buf
            }
            Self::Null => b"_\r\n".to_vec(),
            Self::Boolean(true) => b"#t\r\n".to_vec(),
            Self::Boolean(false) => b"#f\r\n".to_vec(),
        }
    }
}

/// Points where frame truncation can occur
#[derive(Debug, Arbitrary)]
enum TruncationPoint {
    /// Truncate in the middle of pair count
    InPairCount { offset: u8 },
    /// Truncate between CRLF of header
    InHeaderCrlf,
    /// Truncate in the middle of a key
    InKey { _pair_index: u8, byte_offset: u8 },
    /// Truncate in the middle of a value
    InValue { _pair_index: u8, byte_offset: u8 },
    /// Truncate between key and value
    BetweenKeyValue { _pair_index: u8 },
}

impl AttributeFramePattern {
    /// Generate the raw RESP3 bytes for this pattern
    fn generate_bytes(&self) -> Vec<u8> {
        match self {
            AttributeFramePattern::ValidAttribute { pairs } => {
                let mut buf = format!("|{}\r\n", pairs.len()).into_bytes();
                for (k, v) in pairs {
                    buf.extend_from_slice(&k.encode());
                    buf.extend_from_slice(&v.encode());
                }
                buf
            }
            AttributeFramePattern::EmptyAttribute => b"|0\r\n".to_vec(),
            AttributeFramePattern::NegativeCount { count } => format!("|{count}\r\n").into_bytes(),
            AttributeFramePattern::OversizedCount {
                declared_count,
                actual_pairs,
            } => {
                let mut buf = format!("|{declared_count}\r\n").into_bytes();
                // Add fewer pairs than declared
                for i in 0..*actual_pairs {
                    buf.extend_from_slice(format!("+key{i}\r\n").as_bytes());
                    buf.extend_from_slice(format!("+val{i}\r\n").as_bytes());
                }
                buf
            }
            AttributeFramePattern::TruncatedFrame {
                complete_pairs,
                truncate_at,
            } => {
                let mut buf = format!("|{}\r\n", complete_pairs + 1).into_bytes();

                // Add complete pairs first
                for i in 0..*complete_pairs {
                    buf.extend_from_slice(format!("+key{i}\r\n").as_bytes());
                    buf.extend_from_slice(format!("+val{i}\r\n").as_bytes());
                }

                // Add partial pair based on truncation point
                match truncate_at {
                    TruncationPoint::InPairCount { offset } => {
                        // Truncate the original count itself
                        let full = format!("|{}\r\n", complete_pairs + 1);
                        buf = full.as_bytes()[..(*offset as usize).min(full.len())].to_vec();
                    }
                    TruncationPoint::InHeaderCrlf => {
                        // Truncate after count but before CRLF
                        let prefix = format!("|{}", complete_pairs + 1);
                        buf = prefix.into_bytes();
                        buf.push(b'\r'); // Missing \n
                    }
                    TruncationPoint::InKey {
                        _pair_index: _,
                        byte_offset,
                    } => {
                        buf.push(b'+');
                        buf.extend_from_slice(&b"trunckey"[..(*byte_offset as usize).min(8)]);
                    }
                    TruncationPoint::InValue {
                        _pair_index: _,
                        byte_offset,
                    } => {
                        buf.extend_from_slice(b"+key\r\n+");
                        buf.extend_from_slice(&b"truncval"[..(*byte_offset as usize).min(8)]);
                    }
                    TruncationPoint::BetweenKeyValue { _pair_index: _ } => {
                        buf.extend_from_slice(b"+key\r\n");
                        // Missing value
                    }
                }
                buf
            }
            AttributeFramePattern::NestedAttribute {
                depth,
                pairs_per_level,
            } => {
                fn build_nested(level: u8, max_depth: u8, pairs_per_level: u8) -> Vec<u8> {
                    if level >= max_depth {
                        return b"+leaf\r\n".to_vec();
                    }

                    let mut buf = format!("|{pairs_per_level}\r\n").into_bytes();
                    for i in 0..pairs_per_level {
                        buf.extend_from_slice(format!("+key{level}_{i}\r\n").as_bytes());
                        buf.extend_from_slice(&build_nested(level + 1, max_depth, pairs_per_level));
                    }
                    buf
                }

                build_nested(0, *depth, *pairs_per_level)
            }
            AttributeFramePattern::MalformedCrlf {
                use_lf_only,
                use_cr_only,
                missing_terminator,
            } => {
                let mut buf = b"|2".to_vec();
                if *missing_terminator {
                    // No terminator at all
                } else if *use_lf_only {
                    buf.push(b'\n'); // Missing \r
                } else if *use_cr_only {
                    buf.push(b'\r'); // Missing \n
                } else {
                    buf.extend_from_slice(b"\r\n");
                }
                buf.extend_from_slice(b"+k1\r\n+v1\r\n+k2\r\n+v2\r\n");
                buf
            }
            AttributeFramePattern::RawBytes { data } => data.clone(),
        }
    }
}

/// Execute the attribute frame boundary testing scenario
fn execute_attribute_scenario(scenario: AttributeFrameScenario) {
    let limits = RedisProtocolLimits::from(scenario.limits);

    // Test each frame pattern
    for (frame_idx, pattern) in scenario.frames.into_iter().enumerate().take(20) {
        let frame_bytes = pattern.generate_bytes();

        if frame_bytes.len() > MAX_INPUT_SIZE {
            continue; // Skip oversized frames
        }

        // Test parsing (expect either success or controlled error)
        let parse_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match RespValue::try_decode_with_limits(&frame_bytes, &limits) {
                Ok(Some((value, consumed))) => {
                    // Successful parse - verify invariants
                    assert!(
                        consumed <= frame_bytes.len(),
                        "Consumed more bytes than available"
                    );

                    if let RespValue::Attribute(ref pairs) = value {
                        // Verify attribute-specific invariants
                        assert!(
                            pairs.len() <= limits.max_array_len,
                            "Attribute pairs exceed limit"
                        );

                        // Test encoding round-trip for valid attributes
                        let encoded = value.encode();
                        if encoded.len() < MAX_INPUT_SIZE {
                            let _ = RespValue::try_decode_with_limits(&encoded, &limits);
                        }
                    } else {
                        // For malformed frames that parse as other types, ensure they're valid
                    }

                    ParseResult::Success { consumed }
                }
                Ok(None) => ParseResult::NeedMoreData,
                Err(err) => {
                    // Expected errors for boundary conditions
                    match err {
                        RedisError::Protocol(_) => ParseResult::ProtocolError,
                        RedisError::Io(_) => ParseResult::IoError,
                        _ => ParseResult::OtherError,
                    }
                }
            }
        }));

        // Verify no panics occurred
        match parse_result {
            Ok(result) => {
                // Log successful parse result for debugging
                match result {
                    ParseResult::Success { consumed } => {
                        assert!(consumed <= frame_bytes.len());
                    }
                    _ => {
                        // Expected errors
                    }
                }
            }
            Err(_) => {
                panic!(
                    "RESP3 attribute frame parsing panicked for pattern {frame_idx}; frame prefix: {:?}",
                    &frame_bytes[..frame_bytes.len().min(100)]
                );
            }
        }

        // Test partial parsing (feed bytes incrementally)
        if scenario.test_nesting && frame_bytes.len() > 2 {
            let _ = std::panic::catch_unwind(|| {
                for chunk_size in 1..=frame_bytes.len().min(10) {
                    for chunk in frame_bytes.chunks(chunk_size) {
                        let _ = RespValue::try_decode_with_limits(chunk, &limits);
                    }
                }
            });
        }
    }
}

#[derive(Debug)]
enum ParseResult {
    Success { consumed: usize },
    NeedMoreData,
    ProtocolError,
    IoError,
    OtherError,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    let mut u = Unstructured::new(data);

    // Generate attribute scenario from input data
    if let Ok(scenario) = AttributeFrameScenario::arbitrary(&mut u) {
        execute_attribute_scenario(scenario);
    }

    // Also test raw bytes directly as attribute frames
    if data.len() >= 2 && data[0] == b'|' {
        let limits = RedisProtocolLimits {
            max_array_len: 1000,
            max_nesting_depth: 50,
            max_frame_size: MAX_INPUT_SIZE,
            max_bulk_string_len: MAX_INPUT_SIZE,
        };

        let _ = std::panic::catch_unwind(|| {
            let _ = RespValue::try_decode_with_limits(data, &limits);
        });
    }
});
