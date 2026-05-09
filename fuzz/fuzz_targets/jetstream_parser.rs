#![no_main]

//! Structure-aware fuzz target for the real JetStream ACK/API parser seam.

use arbitrary::{Arbitrary, Unstructured};
use asupersync::messaging::jetstream::{
    FuzzJsAckControl, FuzzJsAckMetadata, JsError, fuzz_parse_ack_control, fuzz_parse_api_error,
    fuzz_parse_js_message, fuzz_parse_pub_ack, fuzz_parse_stream_info,
};
use asupersync::messaging::nats::Message;
use libfuzzer_sys::fuzz_target;

const MAX_JSON_BYTES: usize = 4096;
const MAX_PAYLOAD_BYTES: usize = 512;
const MAX_TEXT_CHARS: usize = 64;
const MAX_SEGMENTS: usize = 4;
const HUGE_DIGITS_LEN: usize = 96;
const MAX_OBSERVED_DEBUG_BYTES: usize = 32 * 1024;

#[derive(Arbitrary, Debug)]
enum Scenario {
    StreamInfo(StreamInfoSpec),
    PubAck(PubAckSpec),
    ApiError(ApiErrorSpec),
    AckReply(AckReplySpec),
    AckControl(AckControlSpec),
}

#[derive(Arbitrary, Debug)]
struct StreamInfoSpec {
    mode: StreamInfoMode,
    name: String,
    messages: u64,
    bytes: u64,
    first_seq: u64,
    last_seq: u64,
    consumer_count: u32,
    description: String,
    code: u16,
}

#[derive(Arbitrary, Debug)]
enum StreamInfoMode {
    Valid,
    MissingName,
    ErrorApi,
    ErrorStreamNotFound,
    OversizedNumbers,
}

#[derive(Arbitrary, Debug)]
struct PubAckSpec {
    mode: PubAckMode,
    stream: String,
    seq: u64,
    duplicate: bool,
    description: String,
    code: u16,
}

#[derive(Arbitrary, Debug)]
enum PubAckMode {
    Valid,
    MissingStream,
    MissingSeq,
    ErrorApi,
    ErrorStreamNotFound,
    OversizedSeq,
}

#[derive(Arbitrary, Debug)]
struct ApiErrorSpec {
    mode: ApiErrorMode,
    code: u16,
    description: String,
}

#[derive(Arbitrary, Debug)]
enum ApiErrorMode {
    Generic,
    StreamNotFound,
    MissingDescription,
    MissingCode,
}

#[derive(Arbitrary, Debug)]
struct AckReplySpec {
    mode: AckReplyMode,
    stream_segments: Vec<String>,
    consumer_segments: Vec<String>,
    delivered: u32,
    stream_seq: u64,
    consumer_seq: u64,
    timestamp: u64,
    pending: u64,
    invalid_token: String,
    subject: String,
    payload: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
enum AckReplyMode {
    Valid,
    DottedNames,
    WrongPrefix,
    TooShort,
    InvalidDelivered,
    InvalidSequence,
    TruncatedTail,
}

#[derive(Arbitrary, Debug)]
struct AckControlSpec {
    mode: AckControlMode,
    token_seed: String,
}

#[derive(Arbitrary, Debug)]
enum AckControlMode {
    Ack,
    Nak,
    InProgress,
    Term,
    WrongCase,
    TrailingGarbage,
    LeadingWhitespace,
    UnknownToken,
}

fuzz_target!(|data: &[u8]| {
    fuzz_raw_inputs(data);

    let mut unstructured = Unstructured::new(data);
    if let Ok(scenario) = Scenario::arbitrary(&mut unstructured) {
        match scenario {
            Scenario::StreamInfo(spec) => fuzz_stream_info(spec),
            Scenario::PubAck(spec) => fuzz_pub_ack(spec),
            Scenario::ApiError(spec) => fuzz_api_error(spec),
            Scenario::AckReply(spec) => fuzz_ack_reply(spec),
            Scenario::AckControl(spec) => fuzz_ack_control(spec),
        }
    }
});

fn fuzz_raw_inputs(data: &[u8]) {
    let bounded = &data[..data.len().min(MAX_JSON_BYTES)];
    observe_js_result("raw stream info", fuzz_parse_stream_info(bounded));
    observe_js_result("raw pub ack", fuzz_parse_pub_ack(bounded));
    observe_ack_control("raw ack control", fuzz_parse_ack_control(bounded));

    let reply = String::from_utf8_lossy(bounded).into_owned();
    let api_error = fuzz_parse_api_error(&reply);
    observe_js_error("raw API error", &api_error);
    let parsed = fuzz_parse_js_message(Message {
        subject: "fuzz.jetstream".to_string(),
        sid: 1,
        reply_to: Some(reply),
        headers: None,
        payload: bounded[..bounded.len().min(MAX_PAYLOAD_BYTES)].to_vec(),
    });
    observe_js_message_metadata("raw JS message", parsed);
}

fn observe_js_result<T: std::fmt::Debug>(context: &str, result: Result<T, JsError>) {
    match result {
        Ok(value) => {
            let rendered = format!("{value:?}");
            assert!(
                !rendered.trim().is_empty(),
                "{context}: successful parse should be visible"
            );
            assert!(
                rendered.len() <= MAX_OBSERVED_DEBUG_BYTES,
                "{context}: successful parse debug output is too large: {} bytes",
                rendered.len()
            );
        }
        Err(err) => observe_js_error(context, &err),
    }
}

fn observe_js_error(context: &str, err: &JsError) {
    let diagnostic = format!("{err:?}");
    assert!(
        !diagnostic.trim().is_empty(),
        "{context}: parser failure should expose diagnostics"
    );
    assert!(
        diagnostic.len() <= MAX_OBSERVED_DEBUG_BYTES,
        "{context}: parser failure diagnostic is too large: {} bytes",
        diagnostic.len()
    );
}

fn observe_ack_control(context: &str, outcome: FuzzJsAckControl) {
    let rendered = format!("{outcome:?}");
    assert!(
        !rendered.trim().is_empty(),
        "{context}: ack-control outcome should be visible"
    );
}

fn observe_js_message_metadata(context: &str, parsed: Option<FuzzJsAckMetadata>) {
    if let Some(meta) = parsed {
        assert!(
            !meta.subject.is_empty(),
            "{context}: parsed metadata should retain a subject"
        );
        assert!(
            meta.payload_len <= MAX_PAYLOAD_BYTES,
            "{context}: parsed metadata payload length {} exceeds bounded input",
            meta.payload_len
        );
    }
}

fn fuzz_stream_info(spec: StreamInfoSpec) {
    let name = bounded_text(&spec.name);
    let description = bounded_text(&spec.description);
    let payload = match spec.mode {
        StreamInfoMode::Valid => format!(
            r#"{{"name":{},"messages":{},"bytes":{},"first_seq":{},"last_seq":{},"consumer_count":{}}}"#,
            json_string(&name),
            spec.messages,
            spec.bytes,
            spec.first_seq,
            spec.last_seq,
            spec.consumer_count
        ),
        StreamInfoMode::MissingName => format!(
            r#"{{"messages":{},"bytes":{},"first_seq":{},"last_seq":{},"consumer_count":{}}}"#,
            spec.messages, spec.bytes, spec.first_seq, spec.last_seq, spec.consumer_count
        ),
        StreamInfoMode::ErrorApi => format!(
            r#"{{"error":{{"code":{},"description":{}}}}}"#,
            normalized_code(spec.code),
            json_string(&description)
        ),
        StreamInfoMode::ErrorStreamNotFound => format!(
            r#"{{"error":{{"code":404,"err_code":10059,"description":{}}}}}"#,
            json_string(&description)
        ),
        StreamInfoMode::OversizedNumbers => {
            let huge = "9".repeat(HUGE_DIGITS_LEN);
            format!(
                r#"{{"name":{},"messages":{},"bytes":{},"first_seq":{},"last_seq":{},"consumer_count":{}}}"#,
                json_string(&name),
                huge,
                huge,
                huge,
                huge,
                huge
            )
        }
    };

    match spec.mode {
        StreamInfoMode::Valid => {
            let info = fuzz_parse_stream_info(payload.as_bytes()).expect("valid stream info");
            assert_eq!(info.config.name, name);
            assert_eq!(info.state.messages, spec.messages);
            assert_eq!(info.state.bytes, spec.bytes);
            assert_eq!(info.state.first_seq, spec.first_seq);
            assert_eq!(info.state.last_seq, spec.last_seq);
            assert_eq!(info.state.consumer_count, spec.consumer_count);
        }
        StreamInfoMode::MissingName => match fuzz_parse_stream_info(payload.as_bytes()) {
            Err(JsError::ParseError(msg)) => assert!(msg.contains("missing stream name"), "{msg}"),
            other => panic!("expected missing-name parse error, got {other:?}"),
        },
        StreamInfoMode::ErrorApi => match fuzz_parse_stream_info(payload.as_bytes()) {
            Err(JsError::Api {
                code,
                description: got,
            }) => {
                assert_eq!(code, normalized_code(spec.code));
                assert_eq!(got, description);
            }
            other => panic!("expected generic API error, got {other:?}"),
        },
        StreamInfoMode::ErrorStreamNotFound => match fuzz_parse_stream_info(payload.as_bytes()) {
            Err(JsError::StreamNotFound(got)) => assert_eq!(got, description),
            other => panic!("expected stream-not-found error, got {other:?}"),
        },
        StreamInfoMode::OversizedNumbers => {
            let info =
                fuzz_parse_stream_info(payload.as_bytes()).expect("name-only oversized numbers");
            assert_eq!(info.config.name, name);
            assert_eq!(info.state.messages, 0);
            assert_eq!(info.state.bytes, 0);
            assert_eq!(info.state.first_seq, 0);
            assert_eq!(info.state.last_seq, 0);
            assert_eq!(info.state.consumer_count, 0);
        }
    }
}

fn fuzz_pub_ack(spec: PubAckSpec) {
    let stream = bounded_text(&spec.stream);
    let description = bounded_text(&spec.description);
    let duplicate = if spec.duplicate {
        r#","duplicate":true"#
    } else {
        ""
    };
    let payload = match spec.mode {
        PubAckMode::Valid => format!(
            r#"{{"stream":{},"seq":{}{duplicate}}}"#,
            json_string(&stream),
            spec.seq
        ),
        PubAckMode::MissingStream => format!(r#"{{"seq":{}{duplicate}}}"#, spec.seq),
        PubAckMode::MissingSeq => format!(r#"{{"stream":{}{duplicate}}}"#, json_string(&stream)),
        PubAckMode::ErrorApi => format!(
            r#"{{"error":{{"code":{},"description":{}}}}}"#,
            normalized_code(spec.code),
            json_string(&description)
        ),
        PubAckMode::ErrorStreamNotFound => format!(
            r#"{{"error":{{"code":404,"err_code":10059,"description":{}}}}}"#,
            json_string(&description)
        ),
        PubAckMode::OversizedSeq => format!(
            r#"{{"stream":{},"seq":{}{duplicate}}}"#,
            json_string(&stream),
            "9".repeat(HUGE_DIGITS_LEN)
        ),
    };

    match spec.mode {
        PubAckMode::Valid => {
            let ack = fuzz_parse_pub_ack(payload.as_bytes()).expect("valid pub ack");
            assert_eq!(ack.stream, stream);
            assert_eq!(ack.seq, spec.seq);
            assert_eq!(ack.duplicate, spec.duplicate);
        }
        PubAckMode::MissingStream => match fuzz_parse_pub_ack(payload.as_bytes()) {
            Err(JsError::ParseError(msg)) => {
                assert!(msg.contains("missing stream in PubAck"), "{msg}")
            }
            other => panic!("expected missing-stream parse error, got {other:?}"),
        },
        PubAckMode::MissingSeq | PubAckMode::OversizedSeq => {
            match fuzz_parse_pub_ack(payload.as_bytes()) {
                Err(JsError::ParseError(msg)) => {
                    assert!(msg.contains("missing seq in PubAck"), "{msg}")
                }
                other => panic!("expected missing-seq parse error, got {other:?}"),
            }
        }
        PubAckMode::ErrorApi => match fuzz_parse_pub_ack(payload.as_bytes()) {
            Err(JsError::Api {
                code,
                description: got,
            }) => {
                assert_eq!(code, normalized_code(spec.code));
                assert_eq!(got, description);
            }
            other => panic!("expected generic API error, got {other:?}"),
        },
        PubAckMode::ErrorStreamNotFound => match fuzz_parse_pub_ack(payload.as_bytes()) {
            Err(JsError::StreamNotFound(got)) => assert_eq!(got, description),
            other => panic!("expected stream-not-found error, got {other:?}"),
        },
    }
}

fn fuzz_api_error(spec: ApiErrorSpec) {
    let description = bounded_text(&spec.description);
    let payload = match spec.mode {
        ApiErrorMode::Generic => format!(
            r#"{{"error":{{"code":{},"description":{}}}}}"#,
            normalized_code(spec.code),
            json_string(&description)
        ),
        ApiErrorMode::StreamNotFound => format!(
            r#"{{"error":{{"code":404,"err_code":10059,"description":{}}}}}"#,
            json_string(&description)
        ),
        ApiErrorMode::MissingDescription => {
            format!(r#"{{"error":{{"code":{}}}}}"#, normalized_code(spec.code))
        }
        ApiErrorMode::MissingCode => {
            format!(
                r#"{{"error":{{"description":{}}}}}"#,
                json_string(&description)
            )
        }
    };

    match spec.mode {
        ApiErrorMode::Generic => match fuzz_parse_api_error(&payload) {
            JsError::Api {
                code,
                description: got,
            } => {
                assert_eq!(code, normalized_code(spec.code));
                assert_eq!(got, description);
            }
            other => panic!("expected generic API error, got {other:?}"),
        },
        ApiErrorMode::StreamNotFound => match fuzz_parse_api_error(&payload) {
            JsError::StreamNotFound(got) => assert_eq!(got, description),
            other => panic!("expected stream-not-found error, got {other:?}"),
        },
        ApiErrorMode::MissingDescription => match fuzz_parse_api_error(&payload) {
            JsError::Api {
                code,
                description: got,
            } => {
                assert_eq!(code, normalized_code(spec.code));
                assert_eq!(got, "unknown error");
            }
            other => panic!("expected default-description API error, got {other:?}"),
        },
        ApiErrorMode::MissingCode => match fuzz_parse_api_error(&payload) {
            JsError::Api {
                code,
                description: got,
            } => {
                assert_eq!(code, 0);
                assert_eq!(got, description);
            }
            other => panic!("expected zero-code API error, got {other:?}"),
        },
    }
}

fn fuzz_ack_reply(spec: AckReplySpec) {
    let subject = subject_name(&spec.subject);
    let invalid_token = invalid_number_token(&spec.invalid_token);
    let reply = materialize_reply(&spec, &invalid_token);
    let payload = spec
        .payload
        .iter()
        .copied()
        .take(MAX_PAYLOAD_BYTES)
        .collect::<Vec<_>>();
    let parsed = fuzz_parse_js_message(Message {
        subject: subject.clone(),
        sid: 1,
        reply_to: Some(reply),
        headers: None,
        payload: payload.clone(),
    });

    match spec.mode {
        AckReplyMode::Valid | AckReplyMode::DottedNames => {
            let meta = parsed.expect("valid JetStream ACK reply");
            assert_eq!(meta.subject, subject);
            assert_eq!(meta.payload_len, payload.len());
            assert_eq!(meta.delivered, spec.delivered);
            assert_eq!(meta.sequence, spec.stream_seq);
        }
        AckReplyMode::WrongPrefix
        | AckReplyMode::TooShort
        | AckReplyMode::InvalidDelivered
        | AckReplyMode::InvalidSequence
        | AckReplyMode::TruncatedTail => {
            assert!(
                parsed.is_none(),
                "invalid reply should be rejected: {parsed:?}"
            );
        }
    }
}

fn fuzz_ack_control(spec: AckControlSpec) {
    let payload = materialize_ack_control(&spec);
    let parsed = fuzz_parse_ack_control(&payload);

    match spec.mode {
        AckControlMode::Ack => assert_eq!(parsed, FuzzJsAckControl::Ack),
        AckControlMode::Nak => assert_eq!(parsed, FuzzJsAckControl::Nak),
        AckControlMode::InProgress => assert_eq!(parsed, FuzzJsAckControl::InProgress),
        AckControlMode::Term => assert_eq!(parsed, FuzzJsAckControl::Term),
        AckControlMode::WrongCase
        | AckControlMode::TrailingGarbage
        | AckControlMode::LeadingWhitespace
        | AckControlMode::UnknownToken => {
            assert_eq!(parsed, FuzzJsAckControl::Unknown)
        }
    }
}

fn materialize_reply(spec: &AckReplySpec, invalid_token: &str) -> String {
    let mut stream = subject_segments(&spec.stream_segments, "stream");
    let mut consumer = subject_segments(&spec.consumer_segments, "consumer");
    if matches!(spec.mode, AckReplyMode::DottedNames) {
        if stream.len() < 2 {
            stream.push("branch".to_string());
        }
        if consumer.len() < 2 {
            consumer.push("worker".to_string());
        }
    }

    let mut tokens = vec!["$JS".to_string(), "ACK".to_string()];
    tokens.extend(stream);
    tokens.extend(consumer);
    tokens.push(spec.delivered.to_string());
    tokens.push(spec.stream_seq.to_string());
    tokens.push(spec.consumer_seq.to_string());
    tokens.push(spec.timestamp.to_string());
    tokens.push(spec.pending.to_string());

    match spec.mode {
        AckReplyMode::Valid | AckReplyMode::DottedNames => tokens.join("."),
        AckReplyMode::WrongPrefix => {
            tokens[1] = "NAK".to_string();
            tokens.join(".")
        }
        AckReplyMode::TooShort => {
            let keep = tokens.len().min(6);
            tokens[..keep].join(".")
        }
        AckReplyMode::InvalidDelivered => {
            let idx = tokens.len() - 5;
            tokens[idx] = invalid_token.to_string();
            tokens.join(".")
        }
        AckReplyMode::InvalidSequence => {
            let idx = tokens.len() - 4;
            tokens[idx] = invalid_token.to_string();
            tokens.join(".")
        }
        AckReplyMode::TruncatedTail => {
            let valid = tokens.join(".");
            let cut = valid.rfind('.').unwrap_or(valid.len());
            valid[..cut].to_string()
        }
    }
}

fn materialize_ack_control(spec: &AckControlSpec) -> Vec<u8> {
    match spec.mode {
        AckControlMode::Ack => b"+ACK".to_vec(),
        AckControlMode::Nak => b"-NAK".to_vec(),
        AckControlMode::InProgress => b"+WPI".to_vec(),
        AckControlMode::Term => b"+TERM".to_vec(),
        AckControlMode::WrongCase => {
            let mut token = bounded_text(&spec.token_seed)
                .to_ascii_lowercase()
                .into_bytes();
            if token.is_empty() {
                token = b"+ack".to_vec();
            }
            token
        }
        AckControlMode::TrailingGarbage => {
            let mut token = b"+ACK".to_vec();
            let suffix = bounded_text(&spec.token_seed);
            if suffix.is_empty() {
                token.push(b'!');
            } else {
                token.extend_from_slice(suffix.as_bytes());
            }
            token
        }
        AckControlMode::LeadingWhitespace => {
            let mut token = vec![b' '];
            token.extend_from_slice(b"-NAK");
            token
        }
        AckControlMode::UnknownToken => {
            let token = bounded_text(&spec.token_seed);
            if token.is_empty() {
                b"+NOPE".to_vec()
            } else {
                token.into_bytes()
            }
        }
    }
}

fn subject_segments(values: &[String], fallback: &str) -> Vec<String> {
    let mut segments = values
        .iter()
        .map(|value| subject_segment(value))
        .filter(|segment| !segment.is_empty())
        .take(MAX_SEGMENTS)
        .collect::<Vec<_>>();
    if segments.is_empty() {
        segments.push(fallback.to_string());
    }
    segments
}

fn subject_name(value: &str) -> String {
    let mut parts = value
        .split('.')
        .map(subject_segment)
        .filter(|segment| !segment.is_empty())
        .take(MAX_SEGMENTS)
        .collect::<Vec<_>>();
    if parts.is_empty() {
        parts.push("subject".to_string());
    }
    parts.join(".")
}

fn subject_segment(value: &str) -> String {
    let segment = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(*ch, '_' | '-'))
        .take(MAX_TEXT_CHARS)
        .collect::<String>();
    if segment.is_empty() {
        "seg".to_string()
    } else {
        segment
    }
}

fn invalid_number_token(value: &str) -> String {
    let token = value
        .chars()
        .filter(|ch| ch.is_ascii_alphabetic() || matches!(*ch, '-' | '_'))
        .take(MAX_TEXT_CHARS)
        .collect::<String>();
    if token.is_empty() {
        "x".to_string()
    } else {
        token
    }
}

fn bounded_text(value: &str) -> String {
    value.chars().take(MAX_TEXT_CHARS).collect()
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("String always serializes")
}

fn normalized_code(raw: u16) -> u32 {
    u32::from(200 + (raw % 400))
}
