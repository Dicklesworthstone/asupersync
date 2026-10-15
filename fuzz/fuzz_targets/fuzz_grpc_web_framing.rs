//! Fuzz target for gRPC-Web frame decoding.
//!
//! Exercises binary and text-mode framing, trailer decoding, and malformed
//! length/payload boundaries for the gRPC-Web codec.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::grpc::status::{Code, GrpcError, Status};
use asupersync::grpc::streaming::{Metadata, MetadataValue};
use asupersync::grpc::web::{
    ContentType, TrailerFrame, WebFrame, WebFrameCodec, base64_decode, base64_encode,
    decode_trailers, is_grpc_web_request, is_text_mode,
};

const MAX_STRUCTURED_PAYLOAD: usize = 4096;
const MAX_FRAMES: usize = 32;
const MAX_TEXT_CHARS: usize = 4096;
const MAX_METADATA_ITEMS: usize = 8;

#[derive(Debug, Clone, Arbitrary)]
enum FuzzInput {
    RawBinary {
        max_frame_size: u16,
        bytes: Vec<u8>,
    },
    TextMode {
        content_type: HeaderMode,
        text: String,
    },
    Structured(StructuredStream),
}

#[derive(Debug, Clone, Arbitrary)]
enum HeaderMode {
    Binary,
    Text,
    Invalid(String),
}

#[derive(Debug, Clone, Arbitrary)]
struct StructuredStream {
    text_mode: bool,
    max_frame_size: u16,
    frames: Vec<StructuredFrame>,
    trailing_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Arbitrary)]
enum StructuredFrame {
    Data {
        compressed: bool,
        payload: Vec<u8>,
    },
    StructuredTrailers {
        compressed_flag: bool,
        status_code: i32,
        message: String,
        ascii_metadata: Vec<AsciiMetadata>,
        binary_metadata: Vec<BinaryMetadata>,
    },
    RawTrailers {
        compressed_flag: bool,
        payload: Vec<u8>,
    },
    RawFrame {
        flag: u8,
        declared_length: u16,
        payload: Vec<u8>,
    },
}

#[derive(Debug, Clone, Arbitrary)]
struct AsciiMetadata {
    key: String,
    value: String,
}

#[derive(Debug, Clone, Arbitrary)]
struct BinaryMetadata {
    key: String,
    value: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_grpc_web_framing(input);
});

fn fuzz_grpc_web_framing(input: FuzzInput) {
    match input {
        FuzzInput::RawBinary {
            max_frame_size,
            bytes,
        } => exercise_binary_stream(usize::from(max_frame_size), bytes),
        FuzzInput::TextMode { content_type, text } => {
            let header = header_value(&content_type);
            let content_type = observe_content_type_parse(&header);
            let request_detected = observe_grpc_web_request_detection(&header, content_type);
            let header_is_text = observe_text_mode_detection(&header, content_type);
            let text = truncate_text(&text, MAX_TEXT_CHARS);
            let decoded = observe_base64_decode(&text);
            observe_text_payload_decode(request_detected, header_is_text, &text, &decoded);

            if header_is_text && let Ok(decoded) = decoded {
                exercise_binary_stream(DEFAULT_TEXT_MAX_FRAME_SIZE, decoded);
            }
        }
        FuzzInput::Structured(stream) => exercise_structured_stream(stream),
    }
}

const DEFAULT_TEXT_MAX_FRAME_SIZE: usize = 4096;

fn assert_grpc_error_observable(error: &GrpcError, context: &str) {
    assert!(
        !format!("{error:?}").is_empty(),
        "{context} errors must remain observable"
    );
}

fn observe_content_type_parse(header: &str) -> Option<ContentType> {
    let result = ContentType::from_header_value(header);

    match result {
        Some(content_type) => {
            assert!(
                is_grpc_web_request(header),
                "parsed gRPC-Web content type must satisfy request detection"
            );
            assert_eq!(
                content_type.is_text_mode(),
                is_text_mode(header),
                "content type text-mode parser must agree with helper"
            );
        }
        None => {
            assert!(
                !is_grpc_web_request(header),
                "unparsed gRPC-Web content type must not satisfy request detection"
            );
        }
    }

    result
}

fn observe_grpc_web_request_detection(header: &str, content_type: Option<ContentType>) -> bool {
    let detected = is_grpc_web_request(header);
    assert_eq!(
        detected,
        content_type.is_some(),
        "request detection should match content-type parsing"
    );
    detected
}

fn observe_text_mode_detection(header: &str, content_type: Option<ContentType>) -> bool {
    let text_mode = is_text_mode(header);
    assert_eq!(
        text_mode,
        content_type.is_some_and(ContentType::is_text_mode),
        "text-mode detection should match parsed content type"
    );
    text_mode
}

fn observe_base64_decode(text: &str) -> Result<Vec<u8>, GrpcError> {
    let result = base64_decode(text);

    match &result {
        Ok(decoded) => {
            assert!(
                decoded.len() <= text.len(),
                "base64 decode output should not exceed encoded input length"
            );
        }
        Err(error) => assert_grpc_error_observable(error, "base64 decode"),
    }

    result
}

fn observe_text_payload_decode(
    request_detected: bool,
    header_is_text: bool,
    text: &str,
    result: &Result<Vec<u8>, GrpcError>,
) {
    if header_is_text {
        assert!(
            request_detected,
            "text-mode gRPC-Web content type should be detected as a gRPC-Web request"
        );
    }
    if let Ok(decoded) = result {
        assert!(
            decoded.len() <= text.len(),
            "observed text decode should remain bounded by input text"
        );
    }
}

fn observe_decode_trailers(payload: &[u8]) -> Result<TrailerFrame, GrpcError> {
    let result = decode_trailers(payload);

    match &result {
        Ok(trailers) => {
            assert!(
                trailers.status.message().len() <= payload.len(),
                "decoded trailer status message should stay input-bounded"
            );
            for (key, _) in trailers.metadata.iter() {
                assert!(!key.is_empty(), "decoded trailer metadata key is empty");
            }
        }
        Err(error) => assert_grpc_error_observable(error, "trailer decode"),
    }

    result
}

fn observe_raw_trailer_payload_decode(
    compressed_flag: bool,
    payload: &[u8],
    result: &Result<TrailerFrame, GrpcError>,
) {
    match result {
        Ok(trailers) => {
            assert!(
                !format!("{:?}", trailers.status.code()).is_empty(),
                "decoded trailer status code should remain observable"
            );
            if compressed_flag {
                assert!(
                    !payload.is_empty() || trailers.metadata.iter().next().is_none(),
                    "direct trailer payload decode should not synthesize metadata"
                );
            }
        }
        Err(error) => assert_grpc_error_observable(error, "raw trailer payload decode"),
    }
}

fn exercise_structured_stream(stream: StructuredStream) {
    let mut bytes = build_structured_stream(&stream);
    bytes.extend_from_slice(&truncate_bytes(
        stream.trailing_bytes,
        MAX_STRUCTURED_PAYLOAD,
    ));

    if stream.text_mode {
        let encoded = base64_encode(&bytes);
        if let Ok(decoded) = base64_decode(&encoded) {
            exercise_binary_stream(usize::from(stream.max_frame_size), decoded);
        }
    } else {
        exercise_binary_stream(usize::from(stream.max_frame_size), bytes);
    }
}

fn build_structured_stream(stream: &StructuredStream) -> Vec<u8> {
    let mut out = BytesMut::new();
    let codec = WebFrameCodec::new();

    for frame in stream.frames.iter().take(MAX_FRAMES) {
        match frame {
            StructuredFrame::Data {
                compressed,
                payload,
            } => {
                let payload = truncate_bytes(payload.clone(), MAX_STRUCTURED_PAYLOAD);
                let before_len = out.len();
                let result = codec.encode_data(&payload, *compressed, &mut out);
                observe_frame_encode_result(
                    result,
                    "data frame encode",
                    before_len,
                    out.len(),
                    Some(5 + payload.len()),
                );
            }
            StructuredFrame::StructuredTrailers {
                compressed_flag,
                status_code,
                message,
                ascii_metadata,
                binary_metadata,
            } => {
                let status = Status::new(Code::from_i32(*status_code), truncate_text(message, 256));
                let mut metadata = Metadata::new();

                for item in ascii_metadata.iter().take(MAX_METADATA_ITEMS) {
                    observe_ascii_metadata_insert(
                        &mut metadata,
                        truncate_text(&item.key, 64),
                        truncate_text(&item.value, 128),
                    );
                }
                for item in binary_metadata.iter().take(MAX_METADATA_ITEMS) {
                    observe_binary_metadata_insert(
                        &mut metadata,
                        truncate_text(&item.key, 64),
                        Bytes::from(truncate_bytes(item.value.clone(), 128)),
                    );
                }

                let start = out.len();
                let result = codec.encode_trailers(&status, &metadata, &mut out);
                observe_frame_encode_result(result, "trailer frame encode", start, out.len(), None);
                if *compressed_flag && out.len() > start {
                    out[start] |= 0x01;
                }
            }
            StructuredFrame::RawTrailers {
                compressed_flag,
                payload,
            } => {
                let payload = truncate_bytes(payload.clone(), MAX_STRUCTURED_PAYLOAD);
                out.extend_from_slice(&build_raw_frame(
                    0x80 | u8::from(*compressed_flag),
                    payload.len() as u16,
                    &payload,
                ));
                let result = observe_decode_trailers(&payload);
                observe_raw_trailer_payload_decode(*compressed_flag, &payload, &result);
            }
            StructuredFrame::RawFrame {
                flag,
                declared_length,
                payload,
            } => {
                let payload = truncate_bytes(payload.clone(), MAX_STRUCTURED_PAYLOAD);
                out.extend_from_slice(&build_raw_frame(*flag, *declared_length, &payload));
            }
        }
    }

    out.to_vec()
}

fn observe_ascii_metadata_insert(metadata: &mut Metadata, key: String, value: String) {
    let before_len = metadata.iter().count();
    let inserted = metadata.insert(key, value);
    observe_metadata_insert_result(inserted, before_len, metadata.iter().count(), "ASCII");
}

fn observe_binary_metadata_insert(metadata: &mut Metadata, key: String, value: Bytes) {
    let before_len = metadata.iter().count();
    let inserted = metadata.insert_bin(key, value);
    observe_metadata_insert_result(inserted, before_len, metadata.iter().count(), "binary");
}

fn observe_metadata_insert_result(
    inserted: bool,
    before_len: usize,
    after_len: usize,
    context: &str,
) {
    if inserted {
        assert_eq!(
            after_len,
            before_len + 1,
            "{context} metadata insert should append exactly one entry"
        );
    } else {
        assert_eq!(
            after_len, before_len,
            "{context} metadata insert rejection should leave metadata unchanged"
        );
    }
}

fn observe_frame_encode_result(
    result: Result<(), GrpcError>,
    context: &str,
    before_len: usize,
    after_len: usize,
    expected_growth: Option<usize>,
) {
    match result {
        Ok(()) => {
            let growth = after_len
                .checked_sub(before_len)
                .expect("encoder shortened output buffer");
            if let Some(expected_growth) = expected_growth {
                assert_eq!(
                    growth, expected_growth,
                    "{context} wrote an unexpected frame length"
                );
            } else {
                assert!(growth >= 5, "{context} should write a frame header");
            }
        }
        Err(error) => {
            assert_grpc_error_observable(&error, context);
            assert_eq!(
                before_len, after_len,
                "{context} failure should not mutate output"
            );
        }
    }
}

fn exercise_binary_stream(max_frame_size: usize, bytes: Vec<u8>) {
    let max_frame_size = max_frame_size.max(1);
    let codec = WebFrameCodec::with_max_size(max_frame_size);
    let mut src = BytesMut::from(bytes.as_slice());
    let mut iterations = 0usize;

    while !src.is_empty() && iterations < MAX_FRAMES {
        let before = src.len();
        match codec.decode(&mut src) {
            Ok(Some(frame)) => {
                assert!(
                    src.len() < before,
                    "successful frame decode should consume at least the frame header"
                );
                inspect_frame(frame, max_frame_size);
            }
            Ok(None) => {
                assert_eq!(
                    src.len(),
                    before,
                    "incomplete gRPC-Web frame should remain buffered"
                );
                break;
            }
            Err(error) => {
                assert_grpc_error_observable(&error, "gRPC-Web frame decode");
                assert!(
                    codec.is_poisoned(),
                    "gRPC-Web decode errors should poison the codec"
                );
                if src.len() == before {
                    break;
                }
            }
        }
        iterations += 1;
    }
}

fn inspect_frame(frame: WebFrame, max_frame_size: usize) {
    match frame {
        WebFrame::Data { compressed, data } => {
            observe_data_frame(compressed, &data, max_frame_size);
        }
        WebFrame::Trailers(trailers) => {
            observe_trailer_frame(&trailers);
        }
    }
}

fn observe_data_frame(compressed: bool, data: &Bytes, max_frame_size: usize) {
    assert!(
        data.len() <= max_frame_size,
        "decoded data frame exceeded codec max frame size"
    );
    if compressed {
        assert!(
            !format!("{data:?}").is_empty(),
            "compressed data frame payload should remain observable"
        );
    }
}

fn observe_trailer_frame(trailers: &TrailerFrame) {
    assert!(
        !format!("{:?}", trailers.status.code()).is_empty(),
        "trailer status code should remain observable"
    );
    assert!(
        !format!("{:?}", trailers.status.message()).is_empty(),
        "trailer status message should remain observable"
    );
    for (key, value) in trailers.metadata.iter() {
        assert!(!key.is_empty(), "trailer metadata key is empty");
        match value {
            MetadataValue::Ascii(value) => assert!(
                value
                    .as_bytes()
                    .iter()
                    .all(|byte| (0x20..=0x7E).contains(byte)),
                "ASCII trailer metadata value should stay visible ASCII"
            ),
            MetadataValue::Binary(value) => {
                assert!(
                    key.ends_with("-bin"),
                    "binary trailer metadata key should end with -bin"
                );
                assert!(
                    !format!("{value:?}").is_empty(),
                    "binary trailer metadata value should remain observable"
                );
            }
        }
    }
}

fn build_raw_frame(flag: u8, declared_length: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(flag);
    out.extend_from_slice(&(u32::from(declared_length)).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn header_value(mode: &HeaderMode) -> String {
    match mode {
        HeaderMode::Binary => ContentType::GrpcWeb.as_header_value().to_string(),
        HeaderMode::Text => ContentType::GrpcWebText.as_header_value().to_string(),
        HeaderMode::Invalid(value) => truncate_text(value, 128),
    }
}

fn truncate_text(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn truncate_bytes(mut value: Vec<u8>, max_len: usize) -> Vec<u8> {
    value.truncate(max_len);
    value
}
