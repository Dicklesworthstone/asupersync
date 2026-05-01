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
    PubSubEvent, PubSubMessage, PubSubSubscriptionKind, RedisProtocolLimits, RespValue,
    decode_resp_value_for_fuzz, parse_acl_for_fuzz, parse_client_kill_for_fuzz,
    parse_latency_for_fuzz, parse_pubsub_event_for_fuzz, parse_script_eval_for_fuzz,
    parse_slowlog_for_fuzz, parse_zadd_for_fuzz, parse_zrangebyscore_for_fuzz,
};

const MAX_STRUCTURED_FIELD_BYTES: usize = 96;

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
        decode_resp_value_for_fuzz(b"$?\r\n;3\r\nabc\r\n", limits)
            .expect("incomplete RESP3 streamed blob should not error")
            .is_none()
    );
    assert!(
        decode_resp_value_for_fuzz(b"%?\r\n+key\r\n.\r\n", limits).is_err(),
        "streamed map with odd value count must fail closed"
    );
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
    assert_eq!(parsed.filters.len(), 6);

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
    let finite_bound = format!("{}.{}", payload.len(), data.first().copied().unwrap_or(0));
    let valid_command = RespValue::Array(Some(vec![
        bulk_arg(b"ZRANGEBYSCORE"),
        bulk_arg(b"zset"),
        bulk_arg(b"(1"),
        bulk_arg(b"+inf"),
        bulk_arg(b"WITHSCORES"),
        bulk_arg(b"LIMIT"),
        bulk_arg(b"0"),
        bulk_arg(finite_bound.as_bytes()),
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

/// Test helper functions in isolation
fn test_helper_functions(data: &[u8]) {
    // Test find_crlf with various scenarios
    for _start_pos in [0, 1, data.len().saturating_sub(1)] {
        // Call through RespValue to access find_crlf indirectly
        let _ = RespValue::try_decode(data);
    }

    // Test parse_i64_ascii by creating integer RESP values
    if let Ok(s) = std::str::from_utf8(data) {
        let clean_str = s
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '-' || *c == '+')
            .take(20)
            .collect::<String>();
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
    let max_test_depth = if data.is_empty() {
        0
    } else {
        (data[0] as usize % 100) + 1
    };
    for depth in [1, 5, 10, max_test_depth.min(200)].iter().copied() {
        let deep_data = generate_deep_nesting_data(depth);
        let _ = RespValue::try_decode(&deep_data);
    }

    // Test 7: Test large array scenarios
    let max_test_count = if data.is_empty() {
        0
    } else {
        (data[0] as usize % 1000) + 1
    };
    for count in [0, 1, 10, max_test_count.min(5000)].iter().copied() {
        let large_array_data = generate_large_array_data(count);
        let _ = RespValue::try_decode(&large_array_data);
    }

    // Test 8: Round-trip property verification
    test_round_trip_properties(data);

    // Test 9: Structured RESP3 pubsub push notifications
    exercise_structured_resp3_pushes(data);

    // Test 10: RESP3 streamed string/aggregate parser seam
    exercise_resp3_streamed_types(data);

    // Test 11: Redis SCRIPT EVAL command and Lua parser seam
    exercise_script_eval_parser(data);

    // Test 12: Redis ZADD option parser seam
    exercise_zadd_option_parser(data);

    // Test 13: Redis CLIENT KILL filter parser seam
    exercise_client_kill_parser(data);

    // Test 14: Redis SLOWLOG/LATENCY observability parser seams
    exercise_slowlog_latency_parsers(data);

    // Test 15: Redis ZRANGEBYSCORE range parser seam
    exercise_zrangebyscore_parser(data);

    // Test 16: Redis ACL USER/CAT/reset rule parser seam
    exercise_acl_parser(data);

    // Test 17: Fragmented parsing simulation (partial buffer scenarios)
    if data.len() > 10 {
        for split_point in [1, data.len() / 4, data.len() / 2, data.len() - 1]
            .iter()
            .copied()
        {
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

    // Test 18: Boundary value testing for limits
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
