#![no_main]

use arbitrary::{Arbitrary, Unstructured};
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
use asupersync::messaging::redis::{
    PubSubEvent, PubSubMessage, PubSubSubscriptionKind, RedisClientTrackingPush, RedisError,
    RedisProtocolLimits, RedisResp3NonPubSubPush, RespValue, decode_resp_value_for_fuzz,
    parse_acl_for_fuzz, parse_client_kill_for_fuzz, parse_client_tracking_push_for_fuzz,
    parse_cluster_command_for_fuzz, parse_latency_for_fuzz, parse_pubsub_event_for_fuzz,
    parse_pubsub_ping_event_for_fuzz, parse_resp3_non_pubsub_push_for_fuzz,
    parse_script_eval_for_fuzz, parse_slowlog_for_fuzz, parse_zadd_for_fuzz,
    parse_zrangebyscore_for_fuzz,
};

const MAX_STRUCTURED_FIELD_BYTES: usize = 96;

#[derive(Debug, Default)]
struct RespDecodeStats {
    complete: usize,
    incomplete: usize,
    errors: usize,
}

impl RespDecodeStats {
    fn total(&self) -> usize {
        self.complete + self.incomplete + self.errors
    }

    fn assert_attempts(&self, context: &str, expected: usize) {
        assert_eq!(
            self.total(),
            expected,
            "{context} should classify every decode attempt"
        );
    }
}

fn assert_visible_debug<T: core::fmt::Debug + ?Sized>(context: &str, value: &T) {
    let rendered = format!("{value:?}");
    assert!(
        !rendered.trim().is_empty(),
        "{context} should expose debug diagnostics"
    );
}

fn observe_resp_decode_result(
    context: &str,
    input_len: usize,
    result: Result<Option<(RespValue, usize)>, RedisError>,
    stats: &mut RespDecodeStats,
) -> Option<(RespValue, usize)> {
    match result {
        Ok(Some((value, consumed))) => {
            stats.complete += 1;
            assert!(
                consumed > 0 && consumed <= input_len,
                "{context} consumed {consumed} bytes from {input_len}-byte input"
            );
            assert_visible_debug(context, &value);
            let encoded = value.encode();
            assert!(
                !encoded.is_empty(),
                "{context} should encode complete values to nonempty RESP bytes"
            );
            Some((value, consumed))
        }
        Ok(None) => {
            stats.incomplete += 1;
            None
        }
        Err(error) => {
            stats.errors += 1;
            let diagnostic = error.to_string();
            assert!(
                !diagnostic.trim().is_empty(),
                "{context} should expose protocol-error diagnostics"
            );
            None
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum StructuredPushKind {
    Message,
    PatternMessage,
    Subscribe,
    Unsubscribe,
    PatternSubscribe,
    PatternUnsubscribe,
    Pong,
}

#[derive(Arbitrary, Debug, Clone)]
struct StructuredPushCase {
    kind: StructuredPushKind,
    channel: String,
    pattern: String,
    payload: Vec<u8>,
    pong_payload: Option<Vec<u8>>,
    remaining: u16,
}

impl StructuredPushCase {
    fn normalized(mut self) -> Self {
        truncate_text_field(&mut self.channel);
        truncate_text_field(&mut self.pattern);
        truncate_binary_field(&mut self.payload);
        if let Some(payload) = &mut self.pong_payload {
            truncate_binary_field(payload);
        }
        self
    }

    fn into_resp_value(self) -> RespValue {
        let mut items = vec![RespValue::BulkString(Some(
            self.kind_name().as_bytes().to_vec(),
        ))];
        match self.kind {
            StructuredPushKind::Message => {
                items.push(RespValue::BulkString(Some(self.channel.into_bytes())));
                items.push(RespValue::BulkString(Some(self.payload)));
            }
            StructuredPushKind::PatternMessage => {
                items.push(RespValue::BulkString(Some(self.pattern.into_bytes())));
                items.push(RespValue::BulkString(Some(self.channel.into_bytes())));
                items.push(RespValue::BulkString(Some(self.payload)));
            }
            StructuredPushKind::Subscribe
            | StructuredPushKind::Unsubscribe
            | StructuredPushKind::PatternSubscribe
            | StructuredPushKind::PatternUnsubscribe => {
                items.push(RespValue::BulkString(Some(self.channel.into_bytes())));
                items.push(RespValue::Integer(i64::from(self.remaining)));
            }
            StructuredPushKind::Pong => {
                if let Some(payload) = self.pong_payload {
                    items.push(RespValue::BulkString(Some(payload)));
                }
            }
        }
        RespValue::Push(items)
    }

    fn expected_event(&self) -> PubSubEvent {
        match self.kind {
            StructuredPushKind::Message => PubSubEvent::Message(PubSubMessage {
                channel: self.channel.clone(),
                pattern: None,
                payload: self.payload.clone(),
            }),
            StructuredPushKind::PatternMessage => PubSubEvent::Message(PubSubMessage {
                channel: self.channel.clone(),
                pattern: Some(self.pattern.clone()),
                payload: self.payload.clone(),
            }),
            StructuredPushKind::Subscribe => PubSubEvent::Subscription {
                kind: PubSubSubscriptionKind::Subscribe,
                channel: self.channel.clone(),
                remaining: i64::from(self.remaining),
            },
            StructuredPushKind::Unsubscribe => PubSubEvent::Subscription {
                kind: PubSubSubscriptionKind::Unsubscribe,
                channel: self.channel.clone(),
                remaining: i64::from(self.remaining),
            },
            StructuredPushKind::PatternSubscribe => PubSubEvent::Subscription {
                kind: PubSubSubscriptionKind::PatternSubscribe,
                channel: self.channel.clone(),
                remaining: i64::from(self.remaining),
            },
            StructuredPushKind::PatternUnsubscribe => PubSubEvent::Subscription {
                kind: PubSubSubscriptionKind::PatternUnsubscribe,
                channel: self.channel.clone(),
                remaining: i64::from(self.remaining),
            },
            StructuredPushKind::Pong => PubSubEvent::Pong(self.pong_payload.clone()),
        }
    }

    fn invalid_resp_value(&self) -> RespValue {
        let RespValue::Push(mut items) = self.clone().into_resp_value() else {
            unreachable!("structured push generator must emit RESP3 push frames");
        };

        match self.kind {
            StructuredPushKind::Message | StructuredPushKind::PatternMessage => {
                let _ = items.pop();
            }
            StructuredPushKind::Subscribe
            | StructuredPushKind::Unsubscribe
            | StructuredPushKind::PatternSubscribe
            | StructuredPushKind::PatternUnsubscribe => {
                if let Some(last) = items.last_mut() {
                    *last = RespValue::BulkString(Some(b"not-an-integer".to_vec()));
                }
            }
            StructuredPushKind::Pong => {
                items.push(RespValue::BulkString(Some(b"extra-pong".to_vec())));
                items.push(RespValue::BulkString(Some(b"trailing".to_vec())));
            }
        }

        RespValue::Push(items)
    }

    fn kind_name(&self) -> &'static str {
        match self.kind {
            StructuredPushKind::Message => "message",
            StructuredPushKind::PatternMessage => "pmessage",
            StructuredPushKind::Subscribe => "subscribe",
            StructuredPushKind::Unsubscribe => "unsubscribe",
            StructuredPushKind::PatternSubscribe => "psubscribe",
            StructuredPushKind::PatternUnsubscribe => "punsubscribe",
            StructuredPushKind::Pong => "pong",
        }
    }
}

fn truncate_text_field(field: &mut String) {
    if field.len() > MAX_STRUCTURED_FIELD_BYTES {
        let mut end = MAX_STRUCTURED_FIELD_BYTES;
        while !field.is_char_boundary(end) {
            end -= 1;
        }
        field.truncate(end);
    }
}

fn truncate_binary_field(field: &mut Vec<u8>) {
    if field.len() > MAX_STRUCTURED_FIELD_BYTES {
        field.truncate(MAX_STRUCTURED_FIELD_BYTES);
    }
}

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
    samples
        .push(b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n".to_vec());

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
        let content = s.replace(['\r', '\n'], "");
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
        let mut bulk_string = format!("${len}\r\n").into_bytes();
        bulk_string.extend_from_slice(data.get(..len).unwrap_or(&[]));
        bulk_string.extend_from_slice(b"\r\n");
        malformed.push(bulk_string);
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
    for i in 0..count.min(1000) {
        // Cap iteration to prevent OOM during test generation
        data.extend_from_slice(format!(":{i}\r\n").as_bytes());
    }

    data
}

fn longest_bulk_string_len(value: &RespValue) -> usize {
    match value {
        RespValue::BulkString(Some(bytes)) => bytes.len(),
        RespValue::Array(Some(items)) | RespValue::Set(items) | RespValue::Push(items) => {
            items.iter().map(longest_bulk_string_len).max().unwrap_or(0)
        }
        RespValue::Map(pairs) | RespValue::Attribute(pairs) => pairs
            .iter()
            .flat_map(|(key, value)| [longest_bulk_string_len(key), longest_bulk_string_len(value)])
            .max()
            .unwrap_or(0),
        _ => 0,
    }
}

fn exercise_structured_resp3_pushes(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    for _ in 0..4 {
        let Ok(case) = StructuredPushCase::arbitrary(&mut unstructured) else {
            break;
        };
        let case = case.normalized();

        let expected_event = case.expected_event();
        let malformed_push = case.invalid_resp_value();
        let push = case.clone().into_resp_value();
        let item_count = match &push {
            RespValue::Push(items) => items.len(),
            _ => unreachable!("structured push generator must emit RESP3 push frames"),
        };
        let max_bulk_len = longest_bulk_string_len(&push);
        let encoded = push.encode();

        assert_eq!(encoded.first(), Some(&b'>'));

        let decoded = RespValue::try_decode(&encoded)
            .expect("structured RESP3 push should decode")
            .expect("encoded RESP3 push should be complete");
        assert_eq!(decoded.0, push);
        assert_eq!(decoded.1, encoded.len());

        let event = parse_pubsub_event_for_fuzz(decoded.0.clone())
            .expect("structured RESP3 push event should parse");
        assert_eq!(event, expected_event);

        assert!(
            parse_pubsub_event_for_fuzz(malformed_push).is_err(),
            "malformed structured RESP3 push should be rejected"
        );

        for split in [1, encoded.len() / 2, encoded.len().saturating_sub(1)] {
            if split < encoded.len() {
                assert!(
                    RespValue::try_decode(&encoded[..split])
                        .expect("partial structured RESP3 push should not error")
                        .is_none()
                );
            }
        }

        if item_count > 0 {
            let tight_array_limits = RedisProtocolLimits {
                max_frame_size: encoded.len().saturating_add(1),
                max_nesting_depth: 8,
                max_array_len: item_count.saturating_sub(1),
                max_bulk_string_len: max_bulk_len.max(1),
            };
            assert!(
                RespValue::try_decode_with_limits(&encoded, &tight_array_limits).is_err(),
                "structured RESP3 push should respect max_array_len"
            );
        }

        if max_bulk_len > 0 {
            let tight_bulk_limits = RedisProtocolLimits {
                max_frame_size: encoded.len().saturating_add(1),
                max_nesting_depth: 8,
                max_array_len: item_count.max(1),
                max_bulk_string_len: max_bulk_len.saturating_sub(1),
            };
            assert!(
                RespValue::try_decode_with_limits(&encoded, &tight_bulk_limits).is_err(),
                "structured RESP3 push should respect max_bulk_string_len"
            );
        }
    }
}

fn exercise_pubsub_ping_echo_validation(data: &[u8]) {
    let payload = &data[..data.len().min(MAX_STRUCTURED_FIELD_BYTES)];

    assert!(
        parse_pubsub_event_for_fuzz(RespValue::SimpleString("PONG".to_string())).is_err(),
        "generic pubsub parsing must reject scalar PONG without request context"
    );
    assert!(
        parse_pubsub_event_for_fuzz(RespValue::BulkString(Some(payload.to_vec()))).is_err(),
        "generic pubsub parsing must reject scalar bulk replies without request context"
    );

    let no_payload =
        parse_pubsub_ping_event_for_fuzz(RespValue::SimpleString("PONG".to_string()), None)
            .expect("argument-less RESP3 PING should accept +PONG");
    assert_eq!(no_payload, PubSubEvent::Pong(None));
    assert!(
        parse_pubsub_ping_event_for_fuzz(
            RespValue::SimpleString("PONG".to_string()),
            Some(payload),
        )
        .is_err(),
        "payload PING must reject +PONG without an echo"
    );
    assert!(
        parse_pubsub_ping_event_for_fuzz(RespValue::SimpleString("pong".to_string()), None)
            .is_err(),
        "argument-less RESP3 PING must reject a non-canonical simple-string reply"
    );

    let exact = parse_pubsub_ping_event_for_fuzz(
        RespValue::BulkString(Some(payload.to_vec())),
        Some(payload),
    )
    .expect("RESP3 PING should accept an exact binary echo");
    assert_eq!(exact, PubSubEvent::Pong(Some(payload.to_vec())));
    assert!(
        parse_pubsub_ping_event_for_fuzz(RespValue::BulkString(Some(payload.to_vec())), None,)
            .is_err(),
        "argument-less RESP3 PING must reject a bulk response"
    );

    let mut mismatch = payload.to_vec();
    if let Some(first) = mismatch.first_mut() {
        *first ^= 1;
    } else {
        mismatch.push(0);
    }
    assert!(
        parse_pubsub_ping_event_for_fuzz(
            RespValue::BulkString(Some(mismatch.clone())),
            Some(payload),
        )
        .is_err(),
        "RESP3 PING must reject a mismatched binary echo"
    );

    let binary_canary = [0x00, 0xff, b'\r', b'\n'];
    let binary = parse_pubsub_ping_event_for_fuzz(
        RespValue::BulkString(Some(binary_canary.to_vec())),
        Some(&binary_canary),
    )
    .expect("RESP3 PING should preserve NUL, non-UTF8, and CRLF bytes");
    assert_eq!(binary, PubSubEvent::Pong(Some(binary_canary.to_vec())));
    let mut wrong_canary = binary_canary;
    wrong_canary[1] ^= 1;
    assert!(
        parse_pubsub_ping_event_for_fuzz(
            RespValue::BulkString(Some(wrong_canary.to_vec())),
            Some(&binary_canary),
        )
        .is_err(),
        "RESP3 PING must reject a one-bit binary echo mismatch"
    );

    let explicit_empty =
        parse_pubsub_ping_event_for_fuzz(RespValue::BulkString(Some(Vec::new())), Some(&[]))
            .expect("explicit empty RESP3 payload should accept an empty bulk echo");
    assert_eq!(explicit_empty, PubSubEvent::Pong(Some(Vec::new())));
    assert!(
        parse_pubsub_ping_event_for_fuzz(RespValue::BulkString(None), Some(payload)).is_err(),
        "PING must reject a null bulk echo"
    );

    let resp2_pong = |echo: Option<&[u8]>| {
        let mut items = vec![RespValue::BulkString(Some(b"pong".to_vec()))];
        if let Some(echo) = echo {
            items.push(RespValue::BulkString(Some(echo.to_vec())));
        }
        RespValue::Array(Some(items))
    };
    let resp2_exact = parse_pubsub_ping_event_for_fuzz(resp2_pong(Some(payload)), Some(payload))
        .expect("subscribed RESP2 PING should accept an exact binary echo");
    assert_eq!(resp2_exact, PubSubEvent::Pong(Some(payload.to_vec())));
    let resp2_no_payload = parse_pubsub_ping_event_for_fuzz(resp2_pong(Some(&[])), None)
        .expect("argument-less subscribed RESP2 PING should accept an empty echo");
    assert_eq!(resp2_no_payload, PubSubEvent::Pong(Some(Vec::new())));
    assert!(
        parse_pubsub_ping_event_for_fuzz(resp2_pong(Some(&mismatch)), Some(payload)).is_err(),
        "subscribed RESP2 PING must reject a mismatched echo"
    );
    assert!(
        parse_pubsub_ping_event_for_fuzz(resp2_pong(None), None).is_err(),
        "subscribed RESP2 PING must reject a missing payload field"
    );
    for non_canonical in [
        RespValue::Array(Some(vec![
            RespValue::SimpleString("pong".to_string()),
            RespValue::SimpleString(String::from_utf8_lossy(payload).into_owned()),
        ])),
        RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"PONG".to_vec())),
            RespValue::BulkString(Some(payload.to_vec())),
        ])),
        RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"pong".to_vec())),
            RespValue::SimpleString(String::from_utf8_lossy(payload).into_owned()),
        ])),
        RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"pong".to_vec())),
            RespValue::BulkString(Some(payload.to_vec())),
            RespValue::BulkString(Some(b"trailing".to_vec())),
        ])),
    ] {
        assert!(
            parse_pubsub_ping_event_for_fuzz(non_canonical, Some(payload)).is_err(),
            "subscribed RESP2 PING must reject non-canonical element types, casing, or arity"
        );
    }
    assert!(
        parse_pubsub_ping_event_for_fuzz(
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"pong".to_vec())),
                RespValue::BulkString(Some(payload.to_vec())),
            ]),
            Some(payload),
        )
        .is_err(),
        "RESP3 PING must reject an invented push-shaped PONG reply"
    );
    assert!(
        parse_pubsub_ping_event_for_fuzz(
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"subscribe".to_vec())),
                RespValue::BulkString(Some(b"channel".to_vec())),
                RespValue::Integer(1),
            ]),
            Some(payload),
        )
        .is_err(),
        "RESP3 PING must reject unexpected subscription control traffic"
    );
    assert!(
        parse_pubsub_ping_event_for_fuzz(
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"subscribe".to_vec())),
                RespValue::BulkString(Some(b"channel".to_vec())),
                RespValue::Integer(1),
            ])),
            Some(payload),
        )
        .is_err(),
        "RESP2 PING must reject unexpected subscription control traffic"
    );
}

fn exercise_client_tracking_push_parser(data: &[u8]) {
    let payload = &data[..data.len().min(MAX_STRUCTURED_FIELD_BYTES)];
    let split = payload.len() / 2;
    let first_key = &payload[..split];
    let second_key = &payload[split..];

    let invalidate_keys = RespValue::Push(vec![
        RespValue::BulkString(Some(b"invalidate".to_vec())),
        RespValue::Array(Some(vec![
            RespValue::BulkString(Some(first_key.to_vec())),
            RespValue::BulkString(Some(second_key.to_vec())),
        ])),
    ]);
    let encoded = invalidate_keys.encode();
    assert_eq!(encoded.first(), Some(&b'>'));
    let decoded = RespValue::try_decode(&encoded)
        .expect("client tracking push should decode")
        .expect("encoded client tracking push should be complete");
    assert_eq!(decoded.0, invalidate_keys);
    let _ = parse_client_tracking_push_for_fuzz(decoded.0)
        .expect("client tracking invalidate push should parse");

    let flush = RespValue::Push(vec![
        RespValue::BulkString(Some(b"invalidate".to_vec())),
        RespValue::Null,
    ]);
    let _ = parse_client_tracking_push_for_fuzz(flush)
        .expect("client tracking null invalidation should parse");

    let redirect_broken = RespValue::Push(vec![RespValue::BulkString(Some(
        b"tracking-redir-broken".to_vec(),
    ))]);
    let _ = parse_client_tracking_push_for_fuzz(redirect_broken)
        .expect("client tracking redirect-broken push should parse");

    let bad_key = RespValue::Push(vec![
        RespValue::BulkString(Some(b"invalidate".to_vec())),
        RespValue::Array(Some(vec![RespValue::Integer(1)])),
    ]);
    assert!(
        parse_client_tracking_push_for_fuzz(bad_key).is_err(),
        "client tracking invalidation keys must be payloads"
    );

    let pubsub_shape = RespValue::Array(Some(vec![
        RespValue::BulkString(Some(b"message".to_vec())),
        RespValue::BulkString(Some(b"__redis__:invalidate".to_vec())),
        RespValue::Array(Some(vec![RespValue::BulkString(Some(payload.to_vec()))])),
    ]));
    assert!(
        parse_client_tracking_push_for_fuzz(pubsub_shape).is_err(),
        "RESP2 redirect pubsub messages are not RESP3 tracking pushes"
    );
}

fn exercise_resp3_non_pubsub_push_parser(data: &[u8]) {
    let payload = &data[..data.len().min(MAX_STRUCTURED_FIELD_BYTES)];

    let generic_push = RespValue::Push(vec![
        RespValue::BulkString(Some(b"server-event".to_vec())),
        RespValue::BulkString(Some(payload.to_vec())),
        RespValue::Integer(i64::try_from(payload.len()).expect("bounded payload length fits i64")),
    ]);
    let encoded = generic_push.encode();
    assert_eq!(encoded.first(), Some(&b'>'));
    let decoded = RespValue::try_decode(&encoded)
        .expect("generic RESP3 push should decode")
        .expect("encoded generic RESP3 push should be complete");
    assert_eq!(decoded.0, generic_push);
    let _ = parse_resp3_non_pubsub_push_for_fuzz(decoded.0)
        .expect("generic non-pubsub RESP3 push should parse");

    let tracking_push = RespValue::Push(vec![
        RespValue::BulkString(Some(b"invalidate".to_vec())),
        RespValue::Array(Some(vec![RespValue::BulkString(Some(payload.to_vec()))])),
    ]);
    let _ = parse_resp3_non_pubsub_push_for_fuzz(tracking_push)
        .expect("client tracking push should parse through non-pubsub seam");

    let redirect_broken = RespValue::Push(vec![RespValue::BulkString(Some(
        b"tracking-redir-broken".to_vec(),
    ))]);
    assert_eq!(
        parse_resp3_non_pubsub_push_for_fuzz(redirect_broken)
            .expect("client tracking redirect-broken push should parse through non-pubsub seam"),
        RedisResp3NonPubSubPush::ClientTracking(RedisClientTrackingPush::RedirectBroken)
    );

    let pubsub_push = RespValue::Push(vec![
        RespValue::BulkString(Some(b"message".to_vec())),
        RespValue::BulkString(Some(b"chan".to_vec())),
        RespValue::BulkString(Some(payload.to_vec())),
    ]);
    assert!(
        parse_resp3_non_pubsub_push_for_fuzz(pubsub_push).is_err(),
        "pubsub RESP3 pushes must stay on the pubsub parser path"
    );

    assert!(
        parse_resp3_non_pubsub_push_for_fuzz(RespValue::Push(vec![])).is_err(),
        "empty RESP3 pushes must be rejected"
    );
}

fn append_stream_chunk(wire: &mut Vec<u8>, chunk: &[u8]) {
    wire.push(b';');
    wire.extend_from_slice(chunk.len().to_string().as_bytes());
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(chunk);
    wire.extend_from_slice(b"\r\n");
}

fn exercise_resp3_streamed_types(data: &[u8]) {
    let payload = &data[..data.len().min(MAX_STRUCTURED_FIELD_BYTES)];
    let split = payload.len() / 2;
    let limits = RedisProtocolLimits::new()
        .max_frame_size(payload.len().saturating_add(256))
        .max_nesting_depth(8)
        .max_array_len(8)
        .max_bulk_string_len(payload.len().max(1));

    let mut blob_wire = b"$?\r\n".to_vec();
    if split > 0 {
        append_stream_chunk(&mut blob_wire, &payload[..split]);
    }
    if split < payload.len() {
        append_stream_chunk(&mut blob_wire, &payload[split..]);
    }
    blob_wire.extend_from_slice(b";0\r\n");

    let decoded_blob = decode_resp_value_for_fuzz(&blob_wire, limits)
        .expect("valid RESP3 streamed blob should not error")
        .expect("valid RESP3 streamed blob should be complete");
    assert_eq!(decoded_blob.1, blob_wire.len());
    assert_eq!(
        decoded_blob.0,
        RespValue::BulkString(Some(payload.to_vec()))
    );

    let streamed_values: [(&[u8], RespValue); 3] = [
        (
            b"*?\r\n:1\r\n#f\r\n.\r\n",
            RespValue::Array(Some(vec![RespValue::Integer(1), RespValue::Boolean(false)])),
        ),
        (
            b"~?\r\n+alpha\r\n+beta\r\n.\r\n",
            RespValue::Set(vec![
                RespValue::SimpleString("alpha".to_string()),
                RespValue::SimpleString("beta".to_string()),
            ]),
        ),
        (
            b"%?\r\n+field\r\n:7\r\n.\r\n",
            RespValue::Map(vec![(
                RespValue::SimpleString("field".to_string()),
                RespValue::Integer(7),
            )]),
        ),
    ];

    for (wire, expected) in streamed_values {
        let decoded = decode_resp_value_for_fuzz(wire, limits)
            .expect("valid RESP3 streamed aggregate should not error")
            .expect("valid RESP3 streamed aggregate should be complete");
        assert_eq!(decoded.0, expected);
        assert_eq!(decoded.1, wire.len());
    }

    assert!(
        decode_resp_value_for_fuzz(b"$?\r\n;1\r\na\r\n", limits)
            .expect("incomplete RESP3 streamed blob should not error")
            .is_none()
    );
    assert!(
        decode_resp_value_for_fuzz(b"$?\r\n;3\r\nabc\r\n", limits).is_err(),
        "oversized incomplete RESP3 streamed blob chunk must fail closed"
    );
    assert!(
        decode_resp_value_for_fuzz(b"%?\r\n+key\r\n.\r\n", limits).is_err(),
        "streamed map with odd value count must fail closed"
    );
}

fn resp_value_nesting_depth(value: &RespValue) -> usize {
    match value {
        RespValue::Array(Some(items)) | RespValue::Set(items) | RespValue::Push(items) => {
            1 + items
                .iter()
                .map(resp_value_nesting_depth)
                .max()
                .unwrap_or(0)
        }
        RespValue::Map(pairs) | RespValue::Attribute(pairs) => {
            1 + pairs
                .iter()
                .flat_map(|(key, value)| {
                    [
                        resp_value_nesting_depth(key),
                        resp_value_nesting_depth(value),
                    ]
                })
                .max()
                .unwrap_or(0)
        }
        _ => 1,
    }
}

fn resp_value_attribute_count(value: &RespValue) -> usize {
    match value {
        RespValue::Attribute(pairs) => {
            pairs.len()
                + pairs
                    .iter()
                    .map(|(key, value)| {
                        resp_value_attribute_count(key) + resp_value_attribute_count(value)
                    })
                    .sum::<usize>()
        }
        RespValue::Array(Some(items)) | RespValue::Set(items) | RespValue::Push(items) => {
            items.iter().map(resp_value_attribute_count).sum()
        }
        RespValue::Map(pairs) => pairs
            .iter()
            .map(|(key, value)| resp_value_attribute_count(key) + resp_value_attribute_count(value))
            .sum(),
        _ => 0,
    }
}

fn resp_value_kind(value: &RespValue) -> &'static str {
    match value {
        RespValue::Attribute(_) => "attribute",
        RespValue::Array(_) => "array",
        RespValue::BulkString(_) => "bulk_string",
        RespValue::SimpleString(_) => "simple_string",
        RespValue::Error(_) => "error",
        RespValue::Integer(_) => "integer",
        RespValue::Null => "null",
        RespValue::Boolean(_) => "boolean",
        RespValue::Double(_) => "double",
        RespValue::BigNumber(_) => "big_number",
        RespValue::Verbatim { .. } => "verbatim",
        RespValue::BlobError(_) => "blob_error",
        RespValue::Map(_) => "map",
        RespValue::Set(_) => "set",
        RespValue::Push(_) => "push",
    }
}

fn wire_fingerprint(bytes: &[u8]) -> String {
    let mut acc = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        acc ^= u64::from(byte);
        acc = acc.wrapping_mul(0x100_0000_01b3);
    }
    format!("{acc:016x}")
}

fn exercise_resp3_attributes(data: &[u8]) {
    let payload = &data[..data.len().min(MAX_STRUCTURED_FIELD_BYTES)];
    let split = payload.len() / 2;
    let first = payload[..split].to_vec();
    let second = payload[split..].to_vec();
    let unknown_key = if payload.len() >= 3 {
        payload[..3].to_vec()
    } else {
        vec![0x01, 0x02, 0x03]
    };
    let limits = RedisProtocolLimits::new()
        .max_frame_size(payload.len().saturating_add(512))
        .max_nesting_depth(8)
        .max_array_len(16)
        .max_bulk_string_len(payload.len().max(1).saturating_add(16));

    let cases: Vec<(&str, RespValue)> = vec![
        (
            "scalar",
            RespValue::Attribute(vec![(
                RespValue::SimpleString("ttl".to_string()),
                RespValue::Integer(i64::try_from(payload.len()).expect("payload length fits i64")),
            )]),
        ),
        (
            "array",
            RespValue::Attribute(vec![(
                RespValue::SimpleString("items".to_string()),
                RespValue::Array(Some(vec![
                    RespValue::BulkString(Some(first.clone())),
                    RespValue::BulkString(Some(second.clone())),
                ])),
            )]),
        ),
        (
            "map",
            RespValue::Attribute(vec![(
                RespValue::SimpleString("meta".to_string()),
                RespValue::Map(vec![
                    (
                        RespValue::SimpleString("left".to_string()),
                        RespValue::BulkString(Some(first.clone())),
                    ),
                    (
                        RespValue::SimpleString("right".to_string()),
                        RespValue::BulkString(Some(second.clone())),
                    ),
                ]),
            )]),
        ),
        (
            "set",
            RespValue::Attribute(vec![(
                RespValue::SimpleString("members".to_string()),
                RespValue::Set(vec![
                    RespValue::BulkString(Some(first.clone())),
                    RespValue::BulkString(Some(second.clone())),
                ]),
            )]),
        ),
        (
            "push",
            RespValue::Attribute(vec![(
                RespValue::SimpleString("push".to_string()),
                RespValue::Push(vec![
                    RespValue::BulkString(Some(b"message".to_vec())),
                    RespValue::BulkString(Some(first.clone())),
                    RespValue::BulkString(Some(second.clone())),
                ]),
            )]),
        ),
        (
            "null",
            RespValue::Attribute(vec![(
                RespValue::SimpleString("nil".to_string()),
                RespValue::Null,
            )]),
        ),
        ("empty", RespValue::Attribute(vec![])),
        (
            "repeated",
            RespValue::Attribute(vec![
                (
                    RespValue::SimpleString("dup".to_string()),
                    RespValue::BulkString(Some(first.clone())),
                ),
                (
                    RespValue::SimpleString("dup".to_string()),
                    RespValue::BulkString(Some(second.clone())),
                ),
            ]),
        ),
        (
            "unknown_key",
            RespValue::Attribute(vec![(
                RespValue::BulkString(Some(unknown_key)),
                RespValue::SimpleString("opaque".to_string()),
            )]),
        ),
        (
            "nested_attribute",
            RespValue::Array(Some(vec![
                RespValue::Attribute(vec![(
                    RespValue::SimpleString("outer".to_string()),
                    RespValue::Attribute(vec![(
                        RespValue::SimpleString("inner".to_string()),
                        RespValue::Boolean(true),
                    )]),
                )]),
                RespValue::SimpleString("tail".to_string()),
            ])),
        ),
    ];

    for (label, value) in cases {
        let wire = value.encode();
        let fingerprint = wire_fingerprint(&wire);
        let decoded = decode_resp_value_for_fuzz(&wire, limits)
            .expect("valid RESP3 attribute case should not error")
            .expect("valid RESP3 attribute case should decode");
        assert_eq!(
            decoded.0,
            value,
            "{label} attribute case should round-trip; nesting_depth={} attribute_count={} value_kind={} parser_state=decoded fingerprint={fingerprint}",
            resp_value_nesting_depth(&decoded.0),
            resp_value_attribute_count(&decoded.0),
            resp_value_kind(&decoded.0),
        );
        assert_eq!(decoded.1, wire.len());
    }

    for (label, wire) in [
        (
            "streamed_attribute_not_supported",
            b"|?\r\n+meta\r\n.\r\n".as_slice(),
        ),
        (
            "nested_streamed_map_missing_value",
            b"|1\r\n+meta\r\n%?\r\n+field\r\n.\r\n".as_slice(),
        ),
    ] {
        assert!(
            decode_resp_value_for_fuzz(wire, limits).is_err(),
            "{label} should fail closed with malformed RESP3 attribute nesting"
        );
    }
}

fn bulk_arg(bytes: &[u8]) -> RespValue {
    RespValue::BulkString(Some(bytes.to_vec()))
}

fn append_lua_quoted_bytes(script: &mut Vec<u8>, bytes: &[u8]) {
    script.push(b'\'');
    for &byte in bytes {
        match byte {
            b'\'' | b'\\' => {
                script.push(b'\\');
                script.push(byte);
            }
            b'\n' => script.extend_from_slice(b"\\n"),
            b'\r' => script.extend_from_slice(b"\\r"),
            0x20..=0x7e => script.push(byte),
            _ => script.push(b'_'),
        }
    }
    script.push(b'\'');
}

fn exercise_script_eval_parser(data: &[u8]) {
    let payload = &data[..data.len().min(MAX_STRUCTURED_FIELD_BYTES)];
    let mut valid_script = b"local value = ".to_vec();
    append_lua_quoted_bytes(&mut valid_script, payload);
    valid_script.extend_from_slice(b"\nreturn value");

    let valid_command = RespValue::Array(Some(vec![
        bulk_arg(b"EVAL"),
        bulk_arg(&valid_script),
        bulk_arg(b"1"),
        bulk_arg(b"key"),
        bulk_arg(payload),
    ]));
    let parsed = parse_script_eval_for_fuzz(valid_command)
        .expect("sanitized SCRIPT EVAL command should parse");
    assert_eq!(parsed.keys, vec![b"key".to_vec()]);
    assert_eq!(parsed.argv, vec![payload.to_vec()]);
    assert_eq!(parsed.lua.lines, 2);

    let arbitrary_script = RespValue::Array(Some(vec![
        bulk_arg(b"EVAL_RO"),
        bulk_arg(payload),
        bulk_arg(b"0"),
    ]));
    let _ = parse_script_eval_for_fuzz(arbitrary_script);

    let mismatched_numkeys = RespValue::Array(Some(vec![
        bulk_arg(b"EVAL"),
        bulk_arg(b"return 1"),
        bulk_arg(b"2"),
        bulk_arg(b"only-one-key"),
    ]));
    assert!(
        parse_script_eval_for_fuzz(mismatched_numkeys).is_err(),
        "SCRIPT EVAL numkeys larger than provided key count must fail closed"
    );

    let unterminated_script = RespValue::Array(Some(vec![
        bulk_arg(b"EVAL"),
        bulk_arg(b"return 'unterminated"),
        bulk_arg(b"0"),
    ]));
    assert!(
        parse_script_eval_for_fuzz(unterminated_script).is_err(),
        "unterminated Lua strings must fail closed"
    );
}

fn exercise_client_kill_parser(data: &[u8]) {
    let payload = &data[..data.len().min(MAX_STRUCTURED_FIELD_BYTES)];
    let port = 1 + usize::from(data.first().copied().unwrap_or(0));
    let legacy_addr = format!("127.0.0.1:{port}");
    let legacy_command = RespValue::Array(Some(vec![
        bulk_arg(b"CLIENT"),
        bulk_arg(b"KILL"),
        bulk_arg(legacy_addr.as_bytes()),
    ]));
    let parsed =
        parse_client_kill_for_fuzz(legacy_command).expect("legacy CLIENT KILL should parse");
    assert_eq!(parsed.legacy_addr, Some(legacy_addr.into_bytes()));
    assert!(parsed.filters.is_empty());

    let user = if payload.is_empty() {
        b"default".as_slice()
    } else {
        payload
    };
    let valid_filters = RespValue::Array(Some(vec![
        bulk_arg(b"CLIENT"),
        bulk_arg(b"KILL"),
        bulk_arg(b"ID"),
        bulk_arg(b"42"),
        bulk_arg(b"TYPE"),
        bulk_arg(b"replica"),
        bulk_arg(b"USER"),
        bulk_arg(user),
        bulk_arg(b"ADDR"),
        bulk_arg(b"10.0.0.1:6379"),
        bulk_arg(b"LADDR"),
        bulk_arg(b"[::1]:6379"),
        bulk_arg(b"SKIPME"),
        bulk_arg(b"NO"),
        bulk_arg(b"MAXAGE"),
        bulk_arg(b"60"),
    ]));
    let parsed =
        parse_client_kill_for_fuzz(valid_filters).expect("CLIENT KILL filters should parse");
    assert!(parsed.legacy_addr.is_none());
    assert_eq!(parsed.filters.len(), 7);

    let arbitrary_user = RespValue::Array(Some(vec![
        bulk_arg(b"CLIENT"),
        bulk_arg(b"KILL"),
        bulk_arg(b"USER"),
        bulk_arg(payload),
    ]));
    let _ = parse_client_kill_for_fuzz(arbitrary_user);

    let unpaired_filter = RespValue::Array(Some(vec![
        bulk_arg(b"CLIENT"),
        bulk_arg(b"KILL"),
        bulk_arg(b"ID"),
        bulk_arg(b"7"),
        bulk_arg(b"TYPE"),
    ]));
    assert!(
        parse_client_kill_for_fuzz(unpaired_filter).is_err(),
        "CLIENT KILL filter mode requires paired filters"
    );

    let bad_skipme = RespValue::Array(Some(vec![
        bulk_arg(b"CLIENT"),
        bulk_arg(b"KILL"),
        bulk_arg(b"SKIPME"),
        bulk_arg(b"MAYBE"),
    ]));
    assert!(
        parse_client_kill_for_fuzz(bad_skipme).is_err(),
        "CLIENT KILL SKIPME must fail closed on non-YES/NO values"
    );

    let bad_legacy_addr = RespValue::Array(Some(vec![
        bulk_arg(b"CLIENT"),
        bulk_arg(b"KILL"),
        bulk_arg(b"127.0.0.1"),
    ]));
    assert!(
        parse_client_kill_for_fuzz(bad_legacy_addr).is_err(),
        "legacy CLIENT KILL address must include a port"
    );
}

fn exercise_slowlog_latency_parsers(data: &[u8]) {
    let payload = &data[..data.len().min(MAX_STRUCTURED_FIELD_BYTES)];
    let count = payload.len().to_string();
    let slowlog_get = RespValue::Array(Some(vec![
        bulk_arg(b"SLOWLOG"),
        bulk_arg(b"GET"),
        bulk_arg(count.as_bytes()),
    ]));
    let _ = parse_slowlog_for_fuzz(slowlog_get).expect("SLOWLOG GET count should parse");

    let slowlog_len = RespValue::Array(Some(vec![bulk_arg(b"SLOWLOG"), bulk_arg(b"LEN")]));
    let _ = parse_slowlog_for_fuzz(slowlog_len).expect("SLOWLOG LEN should parse");

    let slowlog_arbitrary_count = RespValue::Array(Some(vec![
        bulk_arg(b"SLOWLOG"),
        bulk_arg(b"GET"),
        bulk_arg(payload),
    ]));
    let _ = parse_slowlog_for_fuzz(slowlog_arbitrary_count);

    let slowlog_extra_len = RespValue::Array(Some(vec![
        bulk_arg(b"SLOWLOG"),
        bulk_arg(b"LEN"),
        bulk_arg(b"extra"),
    ]));
    assert!(
        parse_slowlog_for_fuzz(slowlog_extra_len).is_err(),
        "SLOWLOG LEN must fail closed on extra arguments"
    );

    let latency_event = if payload.is_empty() {
        b"command".as_slice()
    } else {
        payload
    };
    let latency_history = RespValue::Array(Some(vec![
        bulk_arg(b"LATENCY"),
        bulk_arg(b"HISTORY"),
        bulk_arg(latency_event),
    ]));
    let _ = parse_latency_for_fuzz(latency_history).expect("LATENCY HISTORY should parse");

    let latency_reset = RespValue::Array(Some(vec![
        bulk_arg(b"LATENCY"),
        bulk_arg(b"RESET"),
        bulk_arg(b"command"),
        bulk_arg(latency_event),
    ]));
    let _ = parse_latency_for_fuzz(latency_reset).expect("LATENCY RESET should parse");

    let latency_histogram = RespValue::Array(Some(vec![
        bulk_arg(b"LATENCY"),
        bulk_arg(b"HISTOGRAM"),
        bulk_arg(b"GET"),
        bulk_arg(payload),
    ]));
    let _ = parse_latency_for_fuzz(latency_histogram);

    let latency_missing_history_event =
        RespValue::Array(Some(vec![bulk_arg(b"LATENCY"), bulk_arg(b"HISTORY")]));
    assert!(
        parse_latency_for_fuzz(latency_missing_history_event).is_err(),
        "LATENCY HISTORY requires an event"
    );

    let latency_extra_latest = RespValue::Array(Some(vec![
        bulk_arg(b"LATENCY"),
        bulk_arg(b"LATEST"),
        bulk_arg(b"extra"),
    ]));
    assert!(
        parse_latency_for_fuzz(latency_extra_latest).is_err(),
        "LATENCY LATEST must fail closed on extra arguments"
    );
}

fn exercise_zadd_option_parser(data: &[u8]) {
    let payload = &data[..data.len().min(MAX_STRUCTURED_FIELD_BYTES)];
    let finite_score = format!("{}.{}", payload.len(), data.first().copied().unwrap_or(0));
    let valid_command = RespValue::Array(Some(vec![
        bulk_arg(b"ZADD"),
        bulk_arg(b"zset"),
        bulk_arg(b"NX"),
        bulk_arg(b"CH"),
        bulk_arg(finite_score.as_bytes()),
        bulk_arg(payload),
    ]));
    let parsed =
        parse_zadd_for_fuzz(valid_command).expect("sanitized ZADD NX CH command should parse");
    assert_eq!(parsed.key, b"zset".to_vec());
    assert!(parsed.options.changed);
    assert!(!parsed.options.increment);
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].score, finite_score.as_bytes());
    assert_eq!(parsed.entries[0].member, payload);

    let ordered_options = RespValue::Array(Some(vec![
        bulk_arg(b"ZADD"),
        bulk_arg(b"zset"),
        bulk_arg(b"GT"),
        bulk_arg(b"XX"),
        bulk_arg(b"INCR"),
        bulk_arg(b"1.25"),
        bulk_arg(b"member"),
    ]));
    let parsed = parse_zadd_for_fuzz(ordered_options)
        .expect("ZADD XX GT INCR single-pair command should parse");
    assert!(parsed.options.increment);
    assert_eq!(parsed.entries.len(), 1);

    let arbitrary_score = RespValue::Array(Some(vec![
        bulk_arg(b"ZADD"),
        bulk_arg(b"zset"),
        bulk_arg(payload),
        bulk_arg(b"member"),
    ]));
    let _ = parse_zadd_for_fuzz(arbitrary_score);

    let conflicting_options = RespValue::Array(Some(vec![
        bulk_arg(b"ZADD"),
        bulk_arg(b"zset"),
        bulk_arg(b"NX"),
        bulk_arg(b"LT"),
        bulk_arg(b"1"),
        bulk_arg(b"member"),
    ]));
    assert!(
        parse_zadd_for_fuzz(conflicting_options).is_err(),
        "ZADD NX and LT must fail closed"
    );

    let incr_multi_pair = RespValue::Array(Some(vec![
        bulk_arg(b"ZADD"),
        bulk_arg(b"zset"),
        bulk_arg(b"INCR"),
        bulk_arg(b"1"),
        bulk_arg(b"a"),
        bulk_arg(b"2"),
        bulk_arg(b"b"),
    ]));
    assert!(
        parse_zadd_for_fuzz(incr_multi_pair).is_err(),
        "ZADD INCR with multiple score/member pairs must fail closed"
    );

    let odd_pairing = RespValue::Array(Some(vec![
        bulk_arg(b"ZADD"),
        bulk_arg(b"zset"),
        bulk_arg(b"1"),
        bulk_arg(b"member"),
        bulk_arg(b"2"),
    ]));
    assert!(
        parse_zadd_for_fuzz(odd_pairing).is_err(),
        "ZADD score/member arguments must be paired"
    );

    let nan_score = RespValue::Array(Some(vec![
        bulk_arg(b"ZADD"),
        bulk_arg(b"zset"),
        bulk_arg(b"NaN"),
        bulk_arg(b"member"),
    ]));
    assert!(
        parse_zadd_for_fuzz(nan_score).is_err(),
        "ZADD NaN scores must fail closed"
    );
}

fn exercise_zrangebyscore_parser(data: &[u8]) {
    let payload = &data[..data.len().min(MAX_STRUCTURED_FIELD_BYTES)];
    let limit_count = payload.len().saturating_add(1).to_string();
    let valid_command = RespValue::Array(Some(vec![
        bulk_arg(b"ZRANGEBYSCORE"),
        bulk_arg(b"zset"),
        bulk_arg(b"(1"),
        bulk_arg(b"+inf"),
        bulk_arg(b"WITHSCORES"),
        bulk_arg(b"LIMIT"),
        bulk_arg(b"0"),
        bulk_arg(limit_count.as_bytes()),
    ]));
    let parsed = parse_zrangebyscore_for_fuzz(valid_command)
        .expect("sanitized ZRANGEBYSCORE command should parse");
    assert_eq!(parsed.key, b"zset".to_vec());
    assert!(parsed.with_scores);
    assert!(parsed.limit.is_some());

    let arbitrary_min = RespValue::Array(Some(vec![
        bulk_arg(b"ZRANGEBYSCORE"),
        bulk_arg(b"zset"),
        bulk_arg(payload),
        bulk_arg(b"+inf"),
    ]));
    let _ = parse_zrangebyscore_for_fuzz(arbitrary_min);

    let limit_before_withscores = RespValue::Array(Some(vec![
        bulk_arg(b"ZRANGEBYSCORE"),
        bulk_arg(b"zset"),
        bulk_arg(b"-inf"),
        bulk_arg(b"(42"),
        bulk_arg(b"LIMIT"),
        bulk_arg(b"1"),
        bulk_arg(b"-1"),
        bulk_arg(b"WITHSCORES"),
    ]));
    let parsed = parse_zrangebyscore_for_fuzz(limit_before_withscores)
        .expect("ZRANGEBYSCORE LIMIT before WITHSCORES should parse");
    assert!(parsed.with_scores);
    assert_eq!(parsed.limit.expect("LIMIT should be present").count, -1);

    let duplicate_withscores = RespValue::Array(Some(vec![
        bulk_arg(b"ZRANGEBYSCORE"),
        bulk_arg(b"zset"),
        bulk_arg(b"-inf"),
        bulk_arg(b"+inf"),
        bulk_arg(b"WITHSCORES"),
        bulk_arg(b"WITHSCORES"),
    ]));
    assert!(
        parse_zrangebyscore_for_fuzz(duplicate_withscores).is_err(),
        "ZRANGEBYSCORE duplicate WITHSCORES must fail closed"
    );

    let incomplete_limit = RespValue::Array(Some(vec![
        bulk_arg(b"ZRANGEBYSCORE"),
        bulk_arg(b"zset"),
        bulk_arg(b"-inf"),
        bulk_arg(b"+inf"),
        bulk_arg(b"LIMIT"),
        bulk_arg(b"0"),
    ]));
    assert!(
        parse_zrangebyscore_for_fuzz(incomplete_limit).is_err(),
        "ZRANGEBYSCORE LIMIT requires offset and count"
    );

    let nan_bound = RespValue::Array(Some(vec![
        bulk_arg(b"ZRANGEBYSCORE"),
        bulk_arg(b"zset"),
        bulk_arg(b"NaN"),
        bulk_arg(b"+inf"),
    ]));
    assert!(
        parse_zrangebyscore_for_fuzz(nan_bound).is_err(),
        "ZRANGEBYSCORE NaN bounds must fail closed"
    );
}

fn exercise_acl_parser(data: &[u8]) {
    let payload = &data[..data.len().min(MAX_STRUCTURED_FIELD_BYTES)];
    let user = if payload.is_empty() {
        b"default".as_slice()
    } else {
        payload
    };

    let getuser = RespValue::Array(Some(vec![
        bulk_arg(b"ACL"),
        bulk_arg(b"GETUSER"),
        bulk_arg(user),
    ]));
    let _ = parse_acl_for_fuzz(getuser).expect("sanitized ACL GETUSER should parse");

    let category = if payload.is_empty() {
        b"read".as_slice()
    } else {
        payload
    };
    let cat = RespValue::Array(Some(vec![
        bulk_arg(b"ACL"),
        bulk_arg(b"CAT"),
        bulk_arg(category),
    ]));
    let _ = parse_acl_for_fuzz(cat).expect("sanitized ACL CAT category should parse");

    let setuser = RespValue::Array(Some(vec![
        bulk_arg(b"ACL"),
        bulk_arg(b"SETUSER"),
        bulk_arg(user),
        bulk_arg(b"on"),
        bulk_arg(b"resetpass"),
        bulk_arg(b"resetkeys"),
        bulk_arg(b"resetchannels"),
        bulk_arg(b"+@read"),
        bulk_arg(b"-@dangerous"),
        bulk_arg(b"+get"),
        bulk_arg(b"~cache:*"),
        bulk_arg(b"&updates:*"),
        bulk_arg(b">secret"),
        bulk_arg(b"#0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
    ]));
    let _ = parse_acl_for_fuzz(setuser).expect("sanitized ACL SETUSER should parse");

    let arbitrary_rule = RespValue::Array(Some(vec![
        bulk_arg(b"ACL"),
        bulk_arg(b"SETUSER"),
        bulk_arg(b"fuzz-user"),
        bulk_arg(payload),
    ]));
    let _ = parse_acl_for_fuzz(arbitrary_rule);

    let log_reset = RespValue::Array(Some(vec![
        bulk_arg(b"ACL"),
        bulk_arg(b"LOG"),
        bulk_arg(b"RESET"),
    ]));
    let _ = parse_acl_for_fuzz(log_reset).expect("ACL LOG RESET should parse");

    let empty_category_rule = RespValue::Array(Some(vec![
        bulk_arg(b"ACL"),
        bulk_arg(b"SETUSER"),
        bulk_arg(b"fuzz-user"),
        bulk_arg(b"+@"),
    ]));
    assert!(
        parse_acl_for_fuzz(empty_category_rule).is_err(),
        "ACL category rules must include a category name"
    );

    let bad_hash = RespValue::Array(Some(vec![
        bulk_arg(b"ACL"),
        bulk_arg(b"SETUSER"),
        bulk_arg(b"fuzz-user"),
        bulk_arg(b"#not-a-sha256-hex-digest"),
    ]));
    assert!(
        parse_acl_for_fuzz(bad_hash).is_err(),
        "ACL password hash rules must validate SHA-256 hex shape"
    );

    let bad_log_selector = RespValue::Array(Some(vec![
        bulk_arg(b"ACL"),
        bulk_arg(b"LOG"),
        bulk_arg(b"maybe"),
    ]));
    assert!(
        parse_acl_for_fuzz(bad_log_selector).is_err(),
        "ACL LOG selector must be RESET or a decimal count"
    );
}

fn hex_cluster_node_id(data: &[u8]) -> [u8; 40] {
    let alphabet = b"0123456789abcdef";
    let mut node_id = [b'0'; 40];
    for (index, byte) in node_id.iter_mut().enumerate() {
        let source = if data.is_empty() {
            u8::try_from(index).expect("cluster node id index fits in u8")
        } else {
            data[index % data.len()]
        };
        *byte = alphabet[usize::from(source) % alphabet.len()];
    }
    node_id
}

fn exercise_cluster_command_parser(data: &[u8]) {
    let payload = &data[..data.len().min(MAX_STRUCTURED_FIELD_BYTES)];
    let node_id = hex_cluster_node_id(payload);

    let myid = RespValue::Array(Some(vec![bulk_arg(b"CLUSTER"), bulk_arg(b"MYID")]));
    let _ = parse_cluster_command_for_fuzz(myid).expect("CLUSTER MYID should parse");

    let reset_default = RespValue::Array(Some(vec![bulk_arg(b"CLUSTER"), bulk_arg(b"RESET")]));
    let _ = parse_cluster_command_for_fuzz(reset_default).expect("CLUSTER RESET should parse");

    let reset_hard = RespValue::Array(Some(vec![
        bulk_arg(b"CLUSTER"),
        bulk_arg(b"RESET"),
        bulk_arg(b"HARD"),
    ]));
    let _ = parse_cluster_command_for_fuzz(reset_hard).expect("CLUSTER RESET HARD should parse");

    let count_failure_reports = RespValue::Array(Some(vec![
        bulk_arg(b"CLUSTER"),
        bulk_arg(b"COUNT-FAILURE-REPORTS"),
        bulk_arg(&node_id),
    ]));
    let _ = parse_cluster_command_for_fuzz(count_failure_reports)
        .expect("CLUSTER COUNT-FAILURE-REPORTS should parse");

    let arbitrary_node_id = RespValue::Array(Some(vec![
        bulk_arg(b"CLUSTER"),
        bulk_arg(b"COUNT-FAILURE-REPORTS"),
        bulk_arg(payload),
    ]));
    let _ = parse_cluster_command_for_fuzz(arbitrary_node_id);

    let myid_extra = RespValue::Array(Some(vec![
        bulk_arg(b"CLUSTER"),
        bulk_arg(b"MYID"),
        bulk_arg(b"extra"),
    ]));
    assert!(
        parse_cluster_command_for_fuzz(myid_extra).is_err(),
        "CLUSTER MYID must reject extra arguments"
    );

    let bad_reset_mode = RespValue::Array(Some(vec![
        bulk_arg(b"CLUSTER"),
        bulk_arg(b"RESET"),
        bulk_arg(b"MAYBE"),
    ]));
    assert!(
        parse_cluster_command_for_fuzz(bad_reset_mode).is_err(),
        "CLUSTER RESET must reject unknown modes"
    );

    let bad_node_id = RespValue::Array(Some(vec![
        bulk_arg(b"CLUSTER"),
        bulk_arg(b"COUNT-FAILURE-REPORTS"),
        bulk_arg(b"not-a-node-id"),
    ]));
    assert!(
        parse_cluster_command_for_fuzz(bad_node_id).is_err(),
        "CLUSTER COUNT-FAILURE-REPORTS must validate node id shape"
    );
}

/// Test helper functions in isolation
fn test_helper_functions(data: &[u8]) {
    // Test find_crlf with various scenarios
    let mut indirect_crlf_stats = RespDecodeStats::default();
    let start_positions = [0, 1, data.len().saturating_sub(1)];
    for start_pos in start_positions {
        // Call through RespValue to access find_crlf indirectly
        let start_pos = start_pos.min(data.len());
        let probe = &data[start_pos..];
        observe_resp_decode_result(
            "indirect CRLF probe",
            probe.len(),
            RespValue::try_decode(probe),
            &mut indirect_crlf_stats,
        );
    }
    indirect_crlf_stats.assert_attempts("indirect CRLF probes", start_positions.len());

    // Test parse_i64_ascii by creating integer RESP values
    if let Ok(s) = std::str::from_utf8(data) {
        let clean_str = s
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '-' || *c == '+')
            .take(20)
            .collect::<String>();
        if !clean_str.is_empty() {
            let resp_data = format!(":{clean_str}\r\n");
            let mut integer_stats = RespDecodeStats::default();
            observe_resp_decode_result(
                "integer ASCII probe",
                resp_data.len(),
                RespValue::try_decode(resp_data.as_bytes()),
                &mut integer_stats,
            );
            integer_stats.assert_attempts("integer ASCII probes", 1);
        }
    }
}

/// Test protocol limits enforcement
fn test_protocol_limits(data: &[u8]) {
    let mut limit_stats = RespDecodeStats::default();

    // Test with strict limits
    let strict_limits = RedisProtocolLimits {
        max_frame_size: 1024,
        max_nesting_depth: 5,
        max_array_len: 10,
        max_bulk_string_len: 100,
    };

    observe_resp_decode_result(
        "strict Redis protocol limits",
        data.len(),
        RespValue::try_decode_with_limits(data, &strict_limits),
        &mut limit_stats,
    );

    // Test with very permissive limits
    let permissive_limits = RedisProtocolLimits {
        max_frame_size: 100_000_000,
        max_nesting_depth: 1000,
        max_array_len: 10_000_000,
        max_bulk_string_len: 1_000_000_000,
    };

    observe_resp_decode_result(
        "permissive Redis protocol limits",
        data.len(),
        RespValue::try_decode_with_limits(data, &permissive_limits),
        &mut limit_stats,
    );

    // Test with minimal limits
    let minimal_limits = RedisProtocolLimits {
        max_frame_size: 1,
        max_nesting_depth: 1,
        max_array_len: 1,
        max_bulk_string_len: 1,
    };

    observe_resp_decode_result(
        "minimal Redis protocol limits",
        data.len(),
        RespValue::try_decode_with_limits(data, &minimal_limits),
        &mut limit_stats,
    );
    limit_stats.assert_attempts("Redis protocol limit probes", 3);
}

/// Round-trip test: encode then decode should preserve structure
fn test_round_trip_properties(data: &[u8]) {
    // Only test round-trip on successfully parsed values
    let mut source_stats = RespDecodeStats::default();
    let Some((value, _)) = observe_resp_decode_result(
        "round-trip source decode",
        data.len(),
        RespValue::try_decode(data),
        &mut source_stats,
    ) else {
        source_stats.assert_attempts("round-trip source decode", 1);
        return;
    };
    source_stats.assert_attempts("round-trip source decode", 1);

    let encoded = value.encode();

    // The re-encoded value should parse successfully
    let mut encoded_stats = RespDecodeStats::default();
    let Some((value2, _)) = observe_resp_decode_result(
        "round-trip encoded decode",
        encoded.len(),
        RespValue::try_decode(&encoded),
        &mut encoded_stats,
    ) else {
        encoded_stats.assert_attempts("round-trip encoded decode", 1);
        return;
    };
    encoded_stats.assert_attempts("round-trip encoded decode", 1);

    // Check basic structural equality
    assert_eq!(
        std::mem::discriminant(&value),
        std::mem::discriminant(&value2)
    );

    // For non-recursive types, check exact equality
    match (&value, &value2) {
        (RespValue::SimpleString(s1), RespValue::SimpleString(s2)) => assert_eq!(s1, s2),
        (RespValue::Error(e1), RespValue::Error(e2)) => assert_eq!(e1, e2),
        (RespValue::Integer(i1), RespValue::Integer(i2)) => assert_eq!(i1, i2),
        (RespValue::BulkString(b1), RespValue::BulkString(b2)) => assert_eq!(b1, b2),
        _ => {} // Skip arrays due to potential recursion complexity
    }
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs to prevent OOM during testing
    if data.len() > 1_000_000 {
        return;
    }

    // Test 1: Direct parsing of fuzz input with default limits
    let mut direct_decode_stats = RespDecodeStats::default();
    observe_resp_decode_result(
        "direct fuzz input decode",
        data.len(),
        RespValue::try_decode(data),
        &mut direct_decode_stats,
    );
    direct_decode_stats.assert_attempts("direct fuzz input decode", 1);

    // Test 2: Direct parsing with various protocol limits
    test_protocol_limits(data);

    // Test 3: Test all RESP type parsing through valid samples
    let valid_samples = generate_valid_resp_samples(data);
    let mut valid_sample_stats = RespDecodeStats::default();
    let mut valid_roundtrip_stats = RespDecodeStats::default();
    for sample in &valid_samples {
        let result = RespValue::try_decode(sample);

        // Valid samples should generally parse successfully
        if let Some((value, _consumed)) = observe_resp_decode_result(
            "valid RESP sample",
            sample.len(),
            result,
            &mut valid_sample_stats,
        ) {
            // Test encoding round-trip
            let encoded = value.encode();
            observe_resp_decode_result(
                "valid RESP sample re-encode",
                encoded.len(),
                RespValue::try_decode(&encoded),
                &mut valid_roundtrip_stats,
            );
        }
    }
    valid_sample_stats.assert_attempts("valid RESP sample probes", valid_samples.len());
    valid_roundtrip_stats.assert_attempts(
        "valid RESP sample re-encode probes",
        valid_sample_stats.complete,
    );

    // Test 4: Test parsing with malformed/edge case data
    let malformed_samples = generate_malformed_resp_data(data);
    let mut malformed_sample_stats = RespDecodeStats::default();
    for sample in &malformed_samples {
        observe_resp_decode_result(
            "malformed RESP sample",
            sample.len(),
            RespValue::try_decode(sample),
            &mut malformed_sample_stats,
        );
    }
    malformed_sample_stats.assert_attempts("malformed RESP sample probes", malformed_samples.len());

    // Test 5: Test helper functions indirectly
    test_helper_functions(data);

    // Test 6: Test deep nesting scenarios (up to reasonable depth)
    let max_test_depth = if data.is_empty() {
        0
    } else {
        (data[0] as usize % 100) + 1
    };
    let mut deep_nesting_stats = RespDecodeStats::default();
    let mut deep_nesting_attempts = 0;
    for depth in [1, 5, 10, max_test_depth.min(200)].iter().copied() {
        let deep_data = generate_deep_nesting_data(depth);
        observe_resp_decode_result(
            "deep nested RESP array",
            deep_data.len(),
            RespValue::try_decode(&deep_data),
            &mut deep_nesting_stats,
        );
        deep_nesting_attempts += 1;
    }
    deep_nesting_stats.assert_attempts("deep nested RESP array probes", deep_nesting_attempts);

    // Test 7: Test large array scenarios
    let max_test_count = if data.is_empty() {
        0
    } else {
        (data[0] as usize % 1000) + 1
    };
    let mut large_array_stats = RespDecodeStats::default();
    let mut large_array_attempts = 0;
    for count in [0, 1, 10, max_test_count.min(5000)].iter().copied() {
        let large_array_data = generate_large_array_data(count);
        observe_resp_decode_result(
            "large RESP array",
            large_array_data.len(),
            RespValue::try_decode(&large_array_data),
            &mut large_array_stats,
        );
        large_array_attempts += 1;
    }
    large_array_stats.assert_attempts("large RESP array probes", large_array_attempts);

    // Test 8: Round-trip property verification
    test_round_trip_properties(data);

    // Test 9: Structured RESP3 pubsub push notifications
    exercise_structured_resp3_pushes(data);

    // Request-contextual companion to Test 9: exact Pub/Sub PING echoes
    exercise_pubsub_ping_echo_validation(data);

    // Test 10: RESP3 streamed string/aggregate parser seam
    exercise_resp3_streamed_types(data);

    // Test 11: RESP3 attribute-tagged nested value parity seam
    exercise_resp3_attributes(data);

    // Test 12: Redis SCRIPT EVAL command and Lua parser seam
    exercise_script_eval_parser(data);

    // Test 13: Redis ZADD option parser seam
    exercise_zadd_option_parser(data);

    // Test 14: Redis CLIENT KILL filter parser seam
    exercise_client_kill_parser(data);

    // Test 15: Redis SLOWLOG/LATENCY observability parser seams
    exercise_slowlog_latency_parsers(data);

    // Test 16: Redis ZRANGEBYSCORE range parser seam
    exercise_zrangebyscore_parser(data);

    // Test 16: Redis ACL USER/CAT/reset rule parser seam
    exercise_acl_parser(data);

    // Test 17: Redis CLUSTER MYID/RESET/COUNT-FAILURE-REPORTS parser seam
    exercise_cluster_command_parser(data);

    // Test 18: Redis CLIENT TRACKING RESP3 push parser seam
    exercise_client_tracking_push_parser(data);

    // Test 19: Redis RESP3 non-pubsub push parser seam
    exercise_resp3_non_pubsub_push_parser(data);

    // Test 20: Fragmented parsing simulation (partial buffer scenarios)
    if data.len() > 10 {
        let mut fragmented_stats = RespDecodeStats::default();
        let mut fragmented_attempts = 0;
        for split_point in [1, data.len() / 4, data.len() / 2, data.len() - 1]
            .iter()
            .copied()
        {
            if split_point < data.len() {
                let first_part = &data[..split_point];
                let second_part = &data[split_point..];

                // Test parsing of partial data (should return Ok(None) for incomplete)
                observe_resp_decode_result(
                    "fragmented RESP first part",
                    first_part.len(),
                    RespValue::try_decode(first_part),
                    &mut fragmented_stats,
                );
                fragmented_attempts += 1;

                // Test parsing of combined data
                let mut combined = first_part.to_vec();
                combined.extend_from_slice(second_part);
                observe_resp_decode_result(
                    "fragmented RESP recombined buffer",
                    combined.len(),
                    RespValue::try_decode(&combined),
                    &mut fragmented_stats,
                );
                fragmented_attempts += 1;
            }
        }
        fragmented_stats.assert_attempts("fragmented RESP probes", fragmented_attempts);
    }

    // Test 21: Boundary value testing for limits
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

    let mut boundary_limit_stats = RespDecodeStats::default();
    for limits in &boundary_limits {
        observe_resp_decode_result(
            "boundary Redis protocol limits",
            data.len(),
            RespValue::try_decode_with_limits(data, limits),
            &mut boundary_limit_stats,
        );
    }
    boundary_limit_stats.assert_attempts(
        "boundary Redis protocol limit probes",
        boundary_limits.len(),
    );
});
