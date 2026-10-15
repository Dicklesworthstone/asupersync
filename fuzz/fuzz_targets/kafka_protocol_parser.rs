//! Focused Kafka protocol parser fuzzer.
//!
//! This target stays entirely in the parser layer: request header framing,
//! response-frame validation, error/metadata/delivery parsing, compression
//! attribute decoding, and partial-frame recovery. It deliberately avoids live
//! Kafka clients so the fuzz bin compiles under the default fuzz feature set.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::kafka::{
    KafkaError, RecordMetadata, fuzz_parse_delivery_result, fuzz_parse_kafka_error_response,
    fuzz_parse_response_metadata, fuzz_validate_response_frame,
};
use libfuzzer_sys::fuzz_target;

const MAX_BODY_LEN: usize = 16_384;
const MAX_CLIENT_ID_LEN: usize = 256;
const MAX_FIELD_LEN: usize = 1024;
const MAX_TAGGED_FIELDS: usize = 16;
const MAX_TOPIC_LEN: usize = 256;
const MAX_MESSAGE_LEN: usize = 1024;

#[derive(Debug, Arbitrary)]
enum KafkaParserCase {
    RequestHeader(RequestHeaderCase),
    ResponseFrame(ResponseFrameCase),
    ErrorResponse(ErrorResponseCase),
    Metadata(MetadataCase),
    DeliveryResult(DeliveryResultCase),
    CompressionAttributes { attributes: Vec<i16> },
    PartialRecovery { data: Vec<u8>, cuts: Vec<u16> },
}

#[derive(Debug, Arbitrary)]
struct RequestHeaderCase {
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    client_id: ClientIdCase,
    tagged_fields: Vec<TaggedFieldCase>,
    body: Vec<u8>,
    declared_size_delta: i16,
    truncate_at: Option<u16>,
}

#[derive(Debug, Arbitrary)]
enum ClientIdCase {
    Null,
    Empty,
    Text(String),
}

#[derive(Debug, Arbitrary)]
struct TaggedFieldCase {
    tag: u32,
    data: Vec<u8>,
    corrupt_length: bool,
}

#[derive(Debug, Arbitrary)]
struct ResponseFrameCase {
    correlation_id: i32,
    first_payload_byte: u8,
    payload: Vec<u8>,
    declared_length_delta: i16,
    truncate_at: Option<u16>,
}

#[derive(Debug, Arbitrary)]
struct ErrorResponseCase {
    error_code: u8,
    message: Vec<u8>,
    declared_message_len_delta: i16,
    truncate_at: Option<u16>,
}

#[derive(Debug, Arbitrary)]
struct MetadataCase {
    offset: i64,
    partition: i32,
    timestamp_low: i32,
    topic: Vec<u8>,
    declared_topic_len_delta: i16,
    truncate_at: Option<u16>,
}

#[derive(Debug, Arbitrary)]
struct DeliveryResultCase {
    correlation_id: i32,
    status: u8,
    metadata: MetadataCase,
    declared_length_delta: i16,
    truncate_at: Option<u16>,
}

#[derive(Debug)]
struct ParsedRequestHeader {
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    client_id_len: Option<usize>,
    tagged_field_count: usize,
}

fuzz_target!(|case: KafkaParserCase| match case {
    KafkaParserCase::RequestHeader(case) => {
        let frame = build_request_frame(&case);
        match parse_request_header(&frame) {
            Ok(parsed) => {
                assert!(
                    api_version_supported(parsed.api_key, parsed.api_version),
                    "accepted unsupported Kafka API key/version pair"
                );
                assert_eq!(
                    parsed.correlation_id, case.correlation_id,
                    "request parser changed correlation id"
                );
                assert!(
                    parsed.client_id_len.unwrap_or(0) <= MAX_CLIENT_ID_LEN,
                    "client id length exceeded bound"
                );
                assert!(
                    parsed.tagged_field_count <= MAX_TAGGED_FIELDS,
                    "tagged field count exceeded bound"
                );
            }
            Err(message) => observe_parser_message(&message, "request header parse"),
        }
    }
    KafkaParserCase::ResponseFrame(case) => {
        let frame = build_response_frame(
            case.correlation_id,
            build_payload(case.first_payload_byte, &case.payload),
            case.declared_length_delta,
            case.truncate_at,
        );
        observe_unit_parse(
            fuzz_validate_response_frame(&frame),
            "response frame validation",
        );
        observe_delivery_parse(
            fuzz_parse_delivery_result(&frame),
            "response frame delivery parse",
        );
    }
    KafkaParserCase::ErrorResponse(case) => {
        let response = build_error_response(&case);
        observe_kafka_error_response(
            fuzz_parse_kafka_error_response(&response),
            "error response parse",
        );
    }
    KafkaParserCase::Metadata(case) => {
        let metadata = build_metadata_payload(&case);
        observe_metadata_parse(fuzz_parse_response_metadata(&metadata), "metadata parse");
    }
    KafkaParserCase::DeliveryResult(case) => {
        let payload = if case.status == 0 {
            let mut payload = vec![0];
            payload.extend_from_slice(&build_metadata_payload(&case.metadata));
            payload
        } else {
            vec![case.status]
        };
        let frame = build_response_frame(
            case.correlation_id,
            payload,
            case.declared_length_delta,
            case.truncate_at,
        );
        observe_delivery_parse(fuzz_parse_delivery_result(&frame), "delivery result parse");
    }
    KafkaParserCase::CompressionAttributes { attributes } => {
        for attribute in attributes.into_iter().take(128) {
            let codec = kafka_compression_codec(attribute);
            assert!(codec <= 7, "codec occupies exactly the low three bits");
            let valid = codec <= 4;
            if !valid {
                assert!(
                    matches!(codec, 5..=7),
                    "invalid Kafka compression codec should stay in reserved range"
                );
            }
        }
    }
    KafkaParserCase::PartialRecovery { data, cuts } => {
        let mut bounded = data;
        bounded.truncate(MAX_BODY_LEN);
        for cut in cuts.into_iter().take(64) {
            let end = usize::from(cut).min(bounded.len());
            let chunk = &bounded[..end];
            observe_unit_parse(
                fuzz_validate_response_frame(chunk),
                "partial response frame validation",
            );
            observe_kafka_error_response(
                fuzz_parse_kafka_error_response(chunk),
                "partial error response parse",
            );
            observe_metadata_parse(
                fuzz_parse_response_metadata(chunk),
                "partial metadata parse",
            );
            observe_delivery_parse(fuzz_parse_delivery_result(chunk), "partial delivery parse");
        }
    }
});

fn build_request_frame(case: &RequestHeaderCase) -> Vec<u8> {
    let mut frame = vec![0, 0, 0, 0];
    frame.extend_from_slice(&case.api_key.to_be_bytes());
    frame.extend_from_slice(&case.api_version.to_be_bytes());
    frame.extend_from_slice(&case.correlation_id.to_be_bytes());

    match &case.client_id {
        ClientIdCase::Null => write_varint(&mut frame, 0),
        ClientIdCase::Empty => write_varint(&mut frame, 1),
        ClientIdCase::Text(client_id) => {
            let client_id = bounded_bytes(client_id.as_bytes(), MAX_CLIENT_ID_LEN);
            write_varint(
                &mut frame,
                u32::try_from(client_id.len().saturating_add(1)).expect("bounded client id"),
            );
            frame.extend_from_slice(&client_id);
        }
    }

    let tagged_fields: Vec<&TaggedFieldCase> =
        case.tagged_fields.iter().take(MAX_TAGGED_FIELDS).collect();
    write_varint(
        &mut frame,
        u32::try_from(tagged_fields.len()).expect("bounded tagged field count"),
    );
    for field in tagged_fields {
        write_varint(&mut frame, field.tag);
        let data = bounded_bytes(&field.data, MAX_FIELD_LEN);
        let declared_len = if field.corrupt_length {
            data.len().saturating_add(1)
        } else {
            data.len()
        };
        write_varint(
            &mut frame,
            u32::try_from(declared_len).expect("bounded tagged field length"),
        );
        frame.extend_from_slice(&data);
    }

    frame.extend_from_slice(&bounded_bytes(&case.body, MAX_BODY_LEN));
    write_declared_len(&mut frame, case.declared_size_delta);
    apply_truncation(&mut frame, case.truncate_at);
    frame
}

fn parse_request_header(frame: &[u8]) -> Result<ParsedRequestHeader, String> {
    if frame.len() < 14 {
        return Err("request frame too short".to_string());
    }

    let declared_size = i32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if declared_size < 0 {
        return Err(format!("negative request size: {declared_size}"));
    }
    let expected_total = usize::try_from(declared_size)
        .unwrap_or(usize::MAX)
        .saturating_add(4);
    if frame.len() != expected_total {
        return Err(format!(
            "request size mismatch: declared {expected_total}, actual {}",
            frame.len()
        ));
    }

    let api_key = i16::from_be_bytes([frame[4], frame[5]]);
    let api_version = i16::from_be_bytes([frame[6], frame[7]]);
    if !api_version_supported(api_key, api_version) {
        return Err(format!(
            "unsupported api key/version: key={api_key}, version={api_version}"
        ));
    }
    let correlation_id = i32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]);

    let mut offset = 12;
    let client_len_plus = read_varint(frame, &mut offset)?;
    let client_id_len = if client_len_plus == 0 {
        None
    } else {
        let len = usize::try_from(client_len_plus - 1).expect("client id length fits usize");
        if len > MAX_CLIENT_ID_LEN {
            return Err(format!("client id too long: {len}"));
        }
        ensure_available(frame, offset, len, "client id")?;
        offset += len;
        Some(len)
    };

    let tagged_field_count =
        usize::try_from(read_varint(frame, &mut offset)?).expect("tagged field count fits usize");
    if tagged_field_count > MAX_TAGGED_FIELDS {
        return Err(format!("too many tagged fields: {tagged_field_count}"));
    }
    for _ in 0..tagged_field_count {
        let _tag = read_varint(frame, &mut offset)?;
        let len = usize::try_from(read_varint(frame, &mut offset)?)
            .expect("tagged field length fits usize");
        if len > MAX_FIELD_LEN {
            return Err(format!("tagged field too long: {len}"));
        }
        ensure_available(frame, offset, len, "tagged field")?;
        offset += len;
    }

    Ok(ParsedRequestHeader {
        api_key,
        api_version,
        correlation_id,
        client_id_len,
        tagged_field_count,
    })
}

fn build_response_frame(
    correlation_id: i32,
    payload: Vec<u8>,
    declared_length_delta: i16,
    truncate_at: Option<u16>,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len().saturating_add(8));
    frame.extend_from_slice(&correlation_id.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 0]);
    frame.extend_from_slice(&bounded_bytes(&payload, MAX_BODY_LEN));
    write_response_len(&mut frame, declared_length_delta);
    apply_truncation(&mut frame, truncate_at);
    frame
}

fn build_payload(first_byte: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len().saturating_add(1).min(MAX_BODY_LEN));
    out.push(first_byte);
    out.extend_from_slice(&bounded_bytes(payload, MAX_BODY_LEN.saturating_sub(1)));
    out
}

fn build_error_response(case: &ErrorResponseCase) -> Vec<u8> {
    let mut response = vec![case.error_code];
    let message = bounded_bytes(&case.message, MAX_MESSAGE_LEN);
    let declared = i32::try_from(message.len())
        .expect("bounded message length")
        .saturating_add(i32::from(case.declared_message_len_delta))
        .clamp(0, i32::from(u16::MAX));
    let declared = u16::try_from(declared).expect("declared message length is clamped");
    response.extend_from_slice(&declared.to_be_bytes());
    response.extend_from_slice(&message);
    apply_truncation(&mut response, case.truncate_at);
    response
}

fn build_metadata_payload(case: &MetadataCase) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&case.offset.to_be_bytes());
    payload.extend_from_slice(&case.partition.to_be_bytes());
    payload.extend_from_slice(&case.timestamp_low.to_be_bytes());
    let topic = bounded_bytes(&case.topic, MAX_TOPIC_LEN);
    let declared = i32::try_from(topic.len())
        .expect("bounded topic length")
        .saturating_add(i32::from(case.declared_topic_len_delta))
        .clamp(0, i32::from(u16::MAX));
    let declared = u16::try_from(declared).expect("declared topic length is clamped");
    payload.extend_from_slice(&declared.to_be_bytes());
    payload.extend_from_slice(&topic);
    apply_truncation(&mut payload, case.truncate_at);
    payload
}

fn api_version_supported(api_key: i16, version: i16) -> bool {
    let Some(max_version) = max_api_version(api_key) else {
        return false;
    };
    (0..=max_version).contains(&version)
}

fn max_api_version(api_key: i16) -> Option<i16> {
    match api_key {
        0 => Some(9),
        1 => Some(13),
        2 => Some(8),
        3 => Some(12),
        8 | 9 => Some(9),
        10..=18 => Some(4),
        19 | 20 => Some(7),
        21..=29 => Some(4),
        30..=51 => Some(3),
        55..=58 => Some(2),
        60..=67 => Some(1),
        _ => None,
    }
}

fn kafka_compression_codec(attributes: i16) -> u8 {
    u8::try_from(attributes & 0x07).expect("low three bits fit u8")
}

fn write_declared_len(frame: &mut [u8], delta: i16) {
    let declared = i32::try_from(frame.len().saturating_sub(4))
        .unwrap_or(i32::MAX)
        .saturating_add(i32::from(delta));
    frame[0..4].copy_from_slice(&declared.to_be_bytes());
}

fn write_response_len(frame: &mut [u8], delta: i16) {
    let declared = i32::try_from(frame.len().saturating_sub(8))
        .unwrap_or(i32::MAX)
        .saturating_add(i32::from(delta));
    frame[4..8].copy_from_slice(&declared.to_be_bytes());
}

fn write_varint(buffer: &mut Vec<u8>, mut value: u32) {
    while value >= 0x80 {
        buffer.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    buffer.push(value as u8);
}

fn read_varint(frame: &[u8], offset: &mut usize) -> Result<u32, String> {
    let mut result = 0u32;
    let mut shift = 0u32;
    loop {
        if *offset >= frame.len() {
            return Err("truncated varint".to_string());
        }
        let byte = frame[*offset];
        *offset += 1;
        result |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 32 {
            return Err("varint overflow".to_string());
        }
    }
}

fn ensure_available(frame: &[u8], offset: usize, len: usize, context: &str) -> Result<(), String> {
    if offset.saturating_add(len) <= frame.len() {
        Ok(())
    } else {
        Err(format!("truncated {context}"))
    }
}

fn bounded_bytes(bytes: &[u8], max_len: usize) -> Vec<u8> {
    bytes.iter().copied().take(max_len).collect()
}

fn apply_truncation(buffer: &mut Vec<u8>, truncate_at: Option<u16>) {
    if let Some(cut) = truncate_at {
        buffer.truncate(usize::from(cut).min(buffer.len()));
    }
}

fn observe_unit_parse(result: Result<(), String>, context: &str) {
    if let Err(message) = result {
        observe_parser_message(&message, context);
    }
}

fn observe_kafka_error_response(result: Result<KafkaError, String>, context: &str) {
    match result {
        Ok(error) => observe_kafka_error(&error, context),
        Err(message) => observe_parser_message(&message, context),
    }
}

fn observe_metadata_parse(result: Result<RecordMetadata, String>, context: &str) {
    match result {
        Ok(metadata) => {
            assert!(!metadata.topic.is_empty(), "{context} produced empty topic");
            assert!(
                metadata.partition >= 0,
                "{context} produced negative partition"
            );
            assert!(metadata.offset >= 0, "{context} produced negative offset");
        }
        Err(message) => observe_parser_message(&message, context),
    }
}

fn observe_delivery_parse(result: Result<RecordMetadata, KafkaError>, context: &str) {
    match result {
        Ok(metadata) => {
            assert!(!metadata.topic.is_empty(), "{context} produced empty topic");
            assert!(
                metadata.partition >= 0,
                "{context} produced negative partition"
            );
            assert!(metadata.offset >= 0, "{context} produced negative offset");
        }
        Err(error) => observe_kafka_error(&error, context),
    }
}

fn observe_kafka_error(error: &KafkaError, context: &str) {
    match error {
        KafkaError::Protocol(message)
        | KafkaError::Broker(message)
        | KafkaError::InvalidTopic(message)
        | KafkaError::Transaction(message)
        | KafkaError::Config(message)
        | KafkaError::Authentication(message) => observe_parser_message(message, context),
        KafkaError::MessageTooLarge { max_size, .. } => {
            assert!(*max_size > 0, "{context} max message size must be positive");
        }
        KafkaError::Io(_)
        | KafkaError::QueueFull
        | KafkaError::Cancelled
        | KafkaError::PolledAfterCompletion
        | KafkaError::FeatureDisabled => {}
    }
}

fn observe_parser_message(message: &str, context: &str) {
    assert!(
        !message.trim().is_empty(),
        "{context} parser diagnostic must be visible"
    );
    assert!(
        message.len() <= 4096,
        "{context} parser diagnostic grew unexpectedly: {message}"
    );
}
