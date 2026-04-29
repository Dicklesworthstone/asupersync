#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::messaging::redis::{RedisError, RedisProtocolLimits, RespValue};

const MAX_BULK_LEN: usize = 8 * 1024;
const MAX_PAYLOAD_LEN: usize = 8 * 1024;

#[derive(Debug, Arbitrary)]
struct VerbatimStringCase {
    label: VerbatimLabel,
    payload: Vec<u8>,
    limit: u16,
    scenario: VerbatimScenario,
}

#[derive(Clone, Copy, Debug, Arbitrary)]
enum VerbatimLabel {
    Txt,
    Mkd,
}

impl VerbatimLabel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Txt => "txt",
            Self::Mkd => "mkd",
        }
    }
}

#[derive(Debug, Arbitrary)]
enum VerbatimScenario {
    Exact,
    Truncated { keep_bytes: u16 },
    MissingSeparator,
    WrongTrailer([u8; 2]),
    OverLimit { extra: u16 },
}

fuzz_target!(|case: VerbatimStringCase| {
    fuzz_verbatim_string(case);
});

fn fuzz_verbatim_string(case: VerbatimStringCase) {
    let payload = bounded_payload(case.payload);
    let label = case.label.as_str();
    let body_len = label.len().saturating_add(1).saturating_add(payload.len());
    let max_bulk_len = normalized_limit(case.limit).max(4);
    let limits = fuzz_limits(max_bulk_len);

    match case.scenario {
        VerbatimScenario::Exact => {
            let value = RespValue::Verbatim {
                format: label.to_string(),
                payload: payload.clone(),
            };
            let wire = value.encode();

            let decoded = RespValue::try_decode_with_limits(&wire, &limits)
                .expect("valid verbatim wire should not error")
                .expect("valid verbatim wire should decode");

            assert_eq!(decoded.1, wire.len());
            let decoded_value = decoded.0;
            match &decoded_value {
                RespValue::Verbatim {
                    format,
                    payload: decoded_payload,
                } => {
                    assert_eq!(format.as_str(), label, "verbatim label must stay exact");
                    assert_eq!(decoded_payload.as_slice(), payload.as_slice());
                }
                other => panic!("expected verbatim decode, got {other:?}"),
            }
            assert_eq!(decoded_value.encode(), wire);
        }
        VerbatimScenario::Truncated { keep_bytes } => {
            let wire = encode_raw_verbatim(label, &payload, body_len, b':', b"\r\n");
            let keep = usize::from(keep_bytes).min(wire.len().saturating_sub(1));
            let result = RespValue::try_decode_with_limits(&wire[..keep], &limits);
            assert!(matches!(result, Ok(None)));
        }
        VerbatimScenario::MissingSeparator => {
            let wire = encode_raw_verbatim(label, &payload, body_len, b';', b"\r\n");
            let result = RespValue::try_decode_with_limits(&wire, &limits);
            assert!(matches!(
                result,
                Err(RedisError::Protocol(message)) if message.contains("separator")
            ));
        }
        VerbatimScenario::WrongTrailer(trailer) => {
            let trailer = sanitize_wrong_trailer(trailer);
            let wire = encode_raw_verbatim(label, &payload, body_len, b':', &trailer);
            let result = RespValue::try_decode_with_limits(&wire, &limits);
            assert!(matches!(
                result,
                Err(RedisError::Protocol(message)) if message.contains("trailing CRLF")
            ));
        }
        VerbatimScenario::OverLimit { extra } => {
            let declared_len = max_bulk_len
                .saturating_add(1)
                .saturating_add(usize::from(extra % 128));
            let wire = encode_raw_verbatim(label, &payload, declared_len, b':', b"\r\n");
            let result = RespValue::try_decode_with_limits(&wire, &limits);
            assert!(matches!(
                result,
                Err(RedisError::Protocol(message))
                    if message.contains("verbatim length")
                        && message.contains("exceeds maximum")
            ));
        }
    }
}

fn normalized_limit(limit: u16) -> usize {
    usize::from(limit).clamp(4, MAX_BULK_LEN)
}

fn bounded_payload(mut payload: Vec<u8>) -> Vec<u8> {
    payload.truncate(MAX_PAYLOAD_LEN);
    payload
}

fn fuzz_limits(max_bulk_len: usize) -> RedisProtocolLimits {
    RedisProtocolLimits::new()
        .max_frame_size(max_bulk_len.saturating_add(64))
        .max_nesting_depth(8)
        .max_array_len(8)
        .max_bulk_string_len(max_bulk_len)
}

fn encode_raw_verbatim(
    label: &str,
    payload: &[u8],
    declared_len: usize,
    separator: u8,
    trailer: &[u8],
) -> Vec<u8> {
    let mut wire = Vec::with_capacity(label.len().saturating_add(payload.len()).saturating_add(32));
    wire.push(b'=');
    wire.extend_from_slice(declared_len.to_string().as_bytes());
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(label.as_bytes());
    wire.push(separator);
    wire.extend_from_slice(payload);
    wire.extend_from_slice(trailer);
    wire
}

fn sanitize_wrong_trailer(mut trailer: [u8; 2]) -> [u8; 2] {
    if trailer == *b"\r\n" {
        trailer[1] = b'x';
    }
    trailer
}
