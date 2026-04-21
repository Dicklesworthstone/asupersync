//! Fuzz target for gRPC-Web frame decoding.
//!
//! Exercises binary and text-mode framing, trailer decoding, and malformed
//! length/payload boundaries for the gRPC-Web codec.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::grpc::status::{Code, Status};
use asupersync::grpc::streaming::Metadata;
use asupersync::grpc::web::{
    ContentType, WebFrame, WebFrameCodec, base64_decode, base64_encode, decode_trailers,
    is_grpc_web_request, is_text_mode,
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
            let _ = ContentType::from_header_value(&header);
            let _ = is_grpc_web_request(&header);
            let header_is_text = is_text_mode(&header);

            if header_is_text {
                if let Ok(decoded) = base64_decode(&truncate_text(&text, MAX_TEXT_CHARS)) {
                    exercise_binary_stream(DEFAULT_TEXT_MAX_FRAME_SIZE, decoded);
                }
            } else {
                let _ = base64_decode(&truncate_text(&text, MAX_TEXT_CHARS));
            }
        }
        FuzzInput::Structured(stream) => exercise_structured_stream(stream),
    }
}

const DEFAULT_TEXT_MAX_FRAME_SIZE: usize = 4096;

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
                let _ = codec.encode_data(&payload, *compressed, &mut out);
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
                    let _ = metadata.insert(
                        truncate_text(&item.key, 64),
                        truncate_text(&item.value, 128),
                    );
                }
                for item in binary_metadata.iter().take(MAX_METADATA_ITEMS) {
                    let _ = metadata.insert_bin(
                        truncate_text(&item.key, 64),
                        Bytes::from(truncate_bytes(item.value.clone(), 128)),
                    );
                }

                let start = out.len();
                let _ = codec.encode_trailers(&status, &metadata, &mut out);
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
                let _ = decode_trailers(&payload);
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

fn exercise_binary_stream(max_frame_size: usize, bytes: Vec<u8>) {
    let codec = WebFrameCodec::with_max_size(max_frame_size.max(1));
    let mut src = BytesMut::from(bytes.as_slice());
    let mut iterations = 0usize;

    while !src.is_empty() && iterations < MAX_FRAMES {
        let before = src.len();
        match codec.decode(&mut src) {
            Ok(Some(frame)) => inspect_frame(frame),
            Ok(None) => break,
            Err(_) => {
                if src.len() == before {
                    break;
                }
            }
        }
        iterations += 1;
    }
}

fn inspect_frame(frame: WebFrame) {
    match frame {
        WebFrame::Data { compressed, data } => {
            let _ = compressed;
            let _ = data.len();
        }
        WebFrame::Trailers(trailers) => {
            let _ = trailers.status.code().as_i32();
            let _ = trailers.status.message();
            for (key, value) in trailers.metadata.iter() {
                let _ = key;
                let _ = value;
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
