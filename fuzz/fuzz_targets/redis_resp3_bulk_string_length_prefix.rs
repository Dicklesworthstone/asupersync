#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::messaging::redis::{RedisError, RedisProtocolLimits, RespValue};

const MAX_LIMIT: usize = 4 * 1024;
const MAX_PAYLOAD: usize = 4 * 1024;
const OVERFLOW_DIGITS: usize = 20;

#[derive(Debug, Arbitrary)]
struct BulkStringLengthPrefixCase {
    limit: u16,
    scenario: BulkStringScenario,
}

#[derive(Debug, Arbitrary)]
enum BulkStringScenario {
    Valid {
        payload: Vec<u8>,
    },
    Null,
    OverLimit {
        declared_delta: u16,
    },
    OverflowDigits {
        digits: Vec<u8>,
    },
    Negative {
        magnitude: u8,
    },
    Truncated {
        payload: Vec<u8>,
        declared_extra: u8,
        include_trailer: bool,
    },
    WrongTrailer {
        payload: Vec<u8>,
        trailer: [u8; 2],
    },
}

fuzz_target!(|case: BulkStringLengthPrefixCase| {
    fuzz_bulk_string_length_prefix(case);
});

fn fuzz_bulk_string_length_prefix(case: BulkStringLengthPrefixCase) {
    let default_limit = normalized_limit(case.limit);

    match case.scenario {
        BulkStringScenario::Valid { payload } => {
            let payload = bounded_payload(payload);
            let max_bulk = default_limit.max(payload.len());
            let limits = fuzz_limits(max_bulk);
            let wire = RespValue::BulkString(Some(payload.clone())).encode();

            let decoded = RespValue::try_decode_with_limits(&wire, &limits)
                .expect("valid BulkString wire should not error")
                .expect("valid BulkString wire should decode");

            assert_eq!(decoded.1, wire.len());
            assert_eq!(decoded.0, RespValue::BulkString(Some(payload.clone())));
            assert_eq!(decoded.0.encode(), wire);
        }
        BulkStringScenario::Null => {
            let wire = b"$-1\r\n";
            let decoded = RespValue::try_decode_with_limits(wire, &fuzz_limits(default_limit))
                .expect("null BulkString wire should not error")
                .expect("null BulkString wire should decode");

            assert_eq!(decoded.1, wire.len());
            assert_eq!(decoded.0, RespValue::BulkString(None));
            assert_eq!(decoded.0.encode(), wire);
        }
        BulkStringScenario::OverLimit { declared_delta } => {
            let declared_len = default_limit + 1 + usize::from(declared_delta % 512);
            let wire = wire_with_length_prefix(&declared_len.to_string(), &[], None);
            let result = RespValue::try_decode_with_limits(&wire, &fuzz_limits(default_limit));

            assert!(matches!(
                result,
                Err(RedisError::Protocol(message))
                    if message.contains("bulk-shape length")
                        || message.contains("bulk string length")
            ));
        }
        BulkStringScenario::OverflowDigits { digits } => {
            let overflow_digits = overflow_length_digits(&digits);
            let wire = wire_with_length_prefix(&overflow_digits, &[], None);
            let result = RespValue::try_decode_with_limits(&wire, &fuzz_limits(default_limit));

            assert!(matches!(
                result,
                Err(RedisError::Protocol(message)) if message.contains("integer overflow")
            ));
        }
        BulkStringScenario::Negative { magnitude } => {
            let invalid_len = -2_i64 - i64::from(magnitude % 32);
            let wire = wire_with_length_prefix(&invalid_len.to_string(), &[], None);
            let result = RespValue::try_decode_with_limits(&wire, &fuzz_limits(default_limit));

            assert!(matches!(
                result,
                Err(RedisError::Protocol(message))
                    if message.contains("invalid bulk-shape length")
                        || message.contains("invalid bulk string length")
            ));
        }
        BulkStringScenario::Truncated {
            payload,
            declared_extra,
            include_trailer,
        } => {
            let payload = bounded_payload(payload);
            let declared_len = payload.len() + 1 + usize::from(declared_extra % 32);
            let trailer = include_trailer.then_some(b"\r\n".as_slice());
            let wire = wire_with_length_prefix(&declared_len.to_string(), &payload, trailer);
            let result = RespValue::try_decode_with_limits(&wire, &fuzz_limits(default_limit));

            assert!(matches!(result, Ok(None)));
        }
        BulkStringScenario::WrongTrailer { payload, trailer } => {
            let payload = bounded_payload(payload);
            let wrong_trailer = sanitize_wrong_trailer(trailer);
            let wire =
                wire_with_length_prefix(&payload.len().to_string(), &payload, Some(&wrong_trailer));
            let result = RespValue::try_decode_with_limits(&wire, &fuzz_limits(default_limit));

            assert!(matches!(
                result,
                Err(RedisError::Protocol(message)) if message.contains("trailing CRLF")
            ));
        }
    }
}

fn normalized_limit(limit: u16) -> usize {
    usize::from(limit).clamp(1, MAX_LIMIT)
}

fn bounded_payload(mut payload: Vec<u8>) -> Vec<u8> {
    payload.truncate(MAX_PAYLOAD);
    payload
}

fn fuzz_limits(max_bulk_string_len: usize) -> RedisProtocolLimits {
    RedisProtocolLimits::new()
        .max_frame_size(max_bulk_string_len.saturating_add(64))
        .max_nesting_depth(8)
        .max_array_len(8)
        .max_bulk_string_len(max_bulk_string_len)
}

fn wire_with_length_prefix(length_prefix: &str, payload: &[u8], trailer: Option<&[u8]>) -> Vec<u8> {
    let mut wire = Vec::with_capacity(length_prefix.len() + payload.len() + 5);
    wire.push(b'$');
    wire.extend_from_slice(length_prefix.as_bytes());
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(payload);
    if let Some(trailer) = trailer {
        wire.extend_from_slice(trailer);
    }
    wire
}

fn overflow_length_digits(source: &[u8]) -> String {
    let len = OVERFLOW_DIGITS + source.len().min(12);
    let mut digits = String::with_capacity(len);
    digits.push('9');
    for i in 1..len {
        let byte = source.get(i - 1).copied().unwrap_or(0);
        digits.push(char::from(b'0' + (byte % 10)));
    }
    digits
}

fn sanitize_wrong_trailer(mut trailer: [u8; 2]) -> [u8; 2] {
    if trailer == *b"\r\n" {
        trailer[1] = b'x';
    }
    trailer
}
