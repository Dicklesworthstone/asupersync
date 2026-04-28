use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::grpc::{
    Code, Metadata, MetadataValue, Status, WebFrame, WebFrameCodec, base64_decode, base64_encode,
};

#[test]
fn grpc_web_binary_data_frame_uses_standard_grpc_length_prefix() {
    let codec = WebFrameCodec::new();
    let mut wire = BytesMut::new();

    codec
        .encode_data(b"hello", false, &mut wire)
        .expect("binary gRPC-Web frame must encode");

    assert_eq!(wire[0], 0, "data frame must not set the trailer bit");
    assert_eq!(
        &wire[1..5],
        &[0, 0, 0, 5],
        "gRPC-Web data frames share the standard 4-byte big-endian length field"
    );
    assert_eq!(&wire[5..], b"hello");

    let decoded = codec
        .decode(&mut wire)
        .expect("decode must succeed")
        .expect("frame should be complete");

    match decoded {
        WebFrame::Data { compressed, data } => {
            assert!(!compressed);
            assert_eq!(data.as_ref(), b"hello");
        }
        other => panic!("expected data frame, got {other:?}"),
    }
}

#[test]
fn grpc_web_trailer_frames_set_bit_7_and_round_trip_status_metadata() {
    let codec = WebFrameCodec::new();
    let mut metadata = Metadata::new();
    assert!(metadata.insert("x-trace-id", "trace-123"));
    assert!(metadata.insert_bin("trace-context", Bytes::from_static(b"\x01\x02")));

    let mut wire = BytesMut::new();
    codec
        .encode_trailers(
            &Status::invalid_argument("bad\nfield"),
            &metadata,
            &mut wire,
        )
        .expect("trailer frame must encode");

    assert_eq!(wire[0], 0x80, "trailer frames must set bit 7");
    let trailer_len = u32::from_be_bytes([wire[1], wire[2], wire[3], wire[4]]) as usize;
    assert_eq!(
        trailer_len,
        wire.len() - 5,
        "trailer frame length must describe the HTTP/1.1 trailer block payload"
    );

    let decoded = codec
        .decode(&mut wire)
        .expect("decode must succeed")
        .expect("frame should be complete");

    match decoded {
        WebFrame::Trailers(trailer) => {
            assert_eq!(trailer.status.code(), Code::InvalidArgument);
            assert_eq!(trailer.status.message(), "bad\nfield");
            assert_eq!(
                trailer.metadata.get("x-trace-id"),
                Some(&MetadataValue::Ascii("trace-123".to_string()))
            );
            assert_eq!(
                trailer.metadata.get("trace-context-bin"),
                Some(&MetadataValue::Binary(Bytes::from_static(b"\x01\x02")))
            );
        }
        other => panic!("expected trailer frame, got {other:?}"),
    }
}

#[test]
fn grpc_web_compressed_bit_uses_flag_bit_zero() {
    let codec = WebFrameCodec::new();
    let mut wire = BytesMut::new();

    codec
        .encode_data(b"zip", true, &mut wire)
        .expect("compressed data frame must encode");

    assert_eq!(wire[0], 0x01, "compressed data frames must set flag bit 0");

    let decoded = codec
        .decode(&mut wire)
        .expect("decode must succeed")
        .expect("frame should be complete");

    match decoded {
        WebFrame::Data { compressed, data } => {
            assert!(compressed, "compression flag must survive decode");
            assert_eq!(data.as_ref(), b"zip");
        }
        other => panic!("expected data frame, got {other:?}"),
    }
}

#[test]
fn grpc_web_text_mode_base64_round_trips_entire_frame_stream() {
    let codec = WebFrameCodec::new();
    let mut binary = BytesMut::new();

    codec
        .encode_data(b"hello grpc-web", false, &mut binary)
        .expect("data frame must encode");
    codec
        .encode_trailers(&Status::ok(), &Metadata::new(), &mut binary)
        .expect("trailer frame must encode");

    let text = base64_encode(binary.as_ref());
    let decoded = base64_decode(&text).expect("base64 text mode must round-trip");

    assert_eq!(decoded, binary.to_vec());
}

#[test]
fn grpc_web_rejects_reserved_flag_bits() {
    let codec = WebFrameCodec::new();
    let mut wire = BytesMut::new();
    wire.put_u8(0x02);
    wire.put_u32(0);

    let err = codec
        .decode(&mut wire)
        .expect_err("reserved bits must be rejected");
    match err {
        asupersync::grpc::GrpcError::Protocol(message) => {
            assert!(
                message.contains("reserved flag bits"),
                "unexpected protocol error: {message}"
            );
        }
        other => panic!("expected protocol error, got {other:?}"),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// gRPC-Web Specification Conformance Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// Additional conformance tests targeting specific sections of the gRPC-Web
// specification:
// - https://github.com/grpc/grpc/blob/main/doc/PROTOCOL-WEB.md
// - Content-type negotiation per HTTP/1.1 semantics
// - Browser compatibility for trailers-in-body encoding
// - Status code validation and rejection of invalid codes

#[test]
fn grpc_web_content_type_negotiation_handles_subtype_parameters() {
    use asupersync::grpc::web::ContentType;

    // Per gRPC-Web spec, content-type may include parameters like charset
    assert_eq!(
        ContentType::from_header_value("application/grpc-web; charset=utf-8"),
        Some(ContentType::GrpcWeb),
        "content-type with charset parameter must be recognized"
    );

    assert_eq!(
        ContentType::from_header_value("application/grpc-web-text; boundary=frame"),
        Some(ContentType::GrpcWebText),
        "content-type with boundary parameter must be recognized"
    );

    // Proto subtype suffix (common in practice)
    assert_eq!(
        ContentType::from_header_value("application/grpc-web+proto"),
        Some(ContentType::GrpcWeb),
        "proto subtype suffix must be recognized"
    );

    assert_eq!(
        ContentType::from_header_value("application/grpc-web-text+proto"),
        Some(ContentType::GrpcWebText),
        "proto subtype suffix for text mode must be recognized"
    );

    // Case insensitive per HTTP/1.1 spec
    assert_eq!(
        ContentType::from_header_value("Application/gRPC-Web+Proto"),
        Some(ContentType::GrpcWeb),
        "content-type parsing must be case insensitive"
    );
}

#[test]
fn grpc_web_content_type_negotiation_rejects_ambiguous_prefixes() {
    use asupersync::grpc::web::ContentType;

    // Ensure precise matching - similar prefixes must be rejected
    assert_eq!(
        ContentType::from_header_value("application/grpc-websocket"),
        None,
        "grpc-websocket must not be confused with grpc-web"
    );

    assert_eq!(
        ContentType::from_header_value("application/grpc-web-textual"),
        None,
        "grpc-web-textual must not be confused with grpc-web-text"
    );

    assert_eq!(
        ContentType::from_header_value("application/grpc"),
        None,
        "standard gRPC content-type must be rejected for gRPC-Web"
    );

    // Invalid media types
    assert_eq!(
        ContentType::from_header_value("text/grpc-web"),
        None,
        "wrong media type must be rejected"
    );

    assert_eq!(
        ContentType::from_header_value("application/json"),
        None,
        "non-gRPC content-type must be rejected"
    );
}

#[test]
fn grpc_web_trailers_in_body_browser_compatibility() {
    // Per gRPC-Web spec: "trailers appear after the message data, not as actual HTTP trailers"
    // This is the key difference enabling browser compatibility since browsers cannot
    // access HTTP trailers via fetch() API

    let codec = WebFrameCodec::new();
    let mut stream = BytesMut::new();

    // Encode a complete gRPC-Web stream: data + trailers-in-body
    codec
        .encode_data(b"response_payload", false, &mut stream)
        .expect("data frame must encode");

    let mut metadata = Metadata::new();
    assert!(metadata.insert("x-custom-header", "browser-accessible"));

    codec
        .encode_trailers(
            &Status::new(Code::Ok, "Request completed"),
            &metadata,
            &mut stream,
        )
        .expect("trailers-in-body must encode");

    // Verify the stream contains data frame followed by trailer frame
    let mut decode_buf = stream.clone();

    // First frame: data
    let data_frame = codec
        .decode(&mut decode_buf)
        .expect("data frame must decode")
        .expect("frame should be complete");

    match data_frame {
        WebFrame::Data { compressed, data } => {
            assert!(!compressed);
            assert_eq!(data.as_ref(), b"response_payload");
        }
        other => panic!("expected data frame, got {other:?}"),
    }

    // Second frame: trailers (in body, not HTTP trailers)
    let trailer_frame = codec
        .decode(&mut decode_buf)
        .expect("trailer frame must decode")
        .expect("frame should be complete");

    match trailer_frame {
        WebFrame::Trailers(trailer) => {
            assert_eq!(trailer.status.code(), Code::Ok);
            assert_eq!(trailer.status.message(), "Request completed");
            assert_eq!(
                trailer.metadata.get("x-custom-header"),
                Some(&MetadataValue::Ascii("browser-accessible".to_string())),
                "browser must be able to access custom metadata from trailer frame in body"
            );
        }
        other => panic!("expected trailer frame, got {other:?}"),
    }

    // Stream should be fully consumed
    assert!(decode_buf.is_empty(), "stream must be fully parsed");
}

#[test]
fn grpc_web_rejects_invalid_status_codes_for_browser_compatibility() {
    use asupersync::grpc::web::decode_trailers;

    // Per gRPC spec, only status codes 0-16 are defined. HTTP 1xx status codes
    // and other invalid codes must be rejected to prevent confusion between
    // HTTP status codes and gRPC status codes

    // HTTP 1xx status codes (Continue, Switching Protocols, etc.)
    let invalid_1xx_trailer = b"grpc-status: 100\r\n";
    let result = decode_trailers(invalid_1xx_trailer);
    match result {
        Ok(trailer) => {
            // Invalid codes get mapped to UNKNOWN (2), not accepted as-is
            assert_eq!(
                trailer.status.code(),
                Code::Unknown,
                "invalid status code 100 must be mapped to UNKNOWN, not accepted literally"
            );
        }
        Err(_) => panic!("decoding should succeed but map invalid codes"),
    }

    // HTTP 2xx status codes
    let invalid_2xx_trailer = b"grpc-status: 200\r\n";
    let result = decode_trailers(invalid_2xx_trailer);
    match result {
        Ok(trailer) => {
            assert_eq!(
                trailer.status.code(),
                Code::Unknown,
                "invalid status code 200 must be mapped to UNKNOWN"
            );
        }
        Err(_) => panic!("decoding should succeed but map invalid codes"),
    }

    // Negative status codes
    let invalid_negative_trailer = b"grpc-status: -1\r\n";
    let result = decode_trailers(invalid_negative_trailer);
    match result {
        Ok(trailer) => {
            assert_eq!(
                trailer.status.code(),
                Code::Unknown,
                "negative status code must be mapped to UNKNOWN"
            );
        }
        Err(_) => panic!("decoding should succeed but map invalid codes"),
    }

    // Non-numeric status codes must be rejected as protocol errors
    let malformed_trailer = b"grpc-status: OK\r\n";
    let result = decode_trailers(malformed_trailer);
    match result {
        Err(asupersync::grpc::GrpcError::Protocol(msg)) => {
            assert!(
                msg.contains("malformed grpc-status"),
                "non-numeric status must be protocol error: {msg}"
            );
        }
        other => panic!("expected protocol error for non-numeric status, got {other:?}"),
    }
}

#[test]
fn grpc_web_text_mode_streaming_base64_decoder_handles_chunked_input() {
    use asupersync::grpc::web::Base64StreamDecoder;

    // Per gRPC-Web spec, text mode uses base64 encoding of the entire binary stream.
    // Browsers may deliver this in HTTP chunks that break base64 quartet boundaries.

    let binary_data = b"hello grpc-web streaming text mode";
    let full_base64 = asupersync::grpc::web::base64_encode(binary_data);

    // Simulate chunked delivery that breaks base64 boundaries
    let chunk1 = &full_base64[..10]; // Partial base64 quartet
    let chunk2 = &full_base64[10..20];
    let chunk3 = &full_base64[20..]; // Remainder with padding

    let mut decoder = Base64StreamDecoder::new();

    // Process chunks individually
    let mut result = Vec::new();
    result.extend(
        decoder
            .push(chunk1.as_bytes())
            .expect("chunk 1 must decode"),
    );
    result.extend(
        decoder
            .push(chunk2.as_bytes())
            .expect("chunk 2 must decode"),
    );
    result.extend(
        decoder
            .push(chunk3.as_bytes())
            .expect("chunk 3 must decode"),
    );

    // Finalize any remaining buffered data
    result.extend(decoder.finish().expect("finish must succeed"));

    assert_eq!(
        result,
        binary_data,
        "chunked base64 decoding must reconstruct original binary data"
    );
    assert!(
        decoder.is_sealed(),
        "decoder must be sealed after processing padded input"
    );
}

#[test]
fn grpc_web_frame_length_prefix_endianness_conformance() {
    // Per gRPC-Web spec: "The repeated sequence of Length-Prefixed-Message elements
    // that constitute the request/response stream. This is precisely the same format
    // as the gRPC HTTP/2 protocol"
    //
    // The 4-byte length prefix MUST be big-endian as per gRPC HTTP/2 spec.

    let codec = WebFrameCodec::new();
    let mut wire = BytesMut::new();

    // Use a specific payload size that would differ between endianness interpretations
    let payload = vec![0xAB; 0x1234]; // 4660 bytes

    codec
        .encode_data(&payload, false, &mut wire)
        .expect("large frame must encode");

    // Verify big-endian encoding: 0x1234 as big-endian bytes
    assert_eq!(wire[0], 0, "flag byte for uncompressed data");
    assert_eq!(wire[1], 0x00, "length prefix byte 1 (big-endian high)");
    assert_eq!(wire[2], 0x00, "length prefix byte 2");
    assert_eq!(wire[3], 0x12, "length prefix byte 3");
    assert_eq!(wire[4], 0x34, "length prefix byte 4 (big-endian low)");

    // Verify the length can be decoded correctly
    let frame_length = u32::from_be_bytes([wire[1], wire[2], wire[3], wire[4]]);
    assert_eq!(
        frame_length as usize,
        payload.len(),
        "big-endian length prefix must decode to correct payload size"
    );

    // Verify full frame round-trip
    let decoded = codec
        .decode(&mut wire)
        .expect("decode must succeed")
        .expect("frame should be complete");

    match decoded {
        WebFrame::Data { data, .. } => {
            assert_eq!(data.as_ref(), &payload, "payload must round-trip exactly");
        }
        other => panic!("expected data frame, got {other:?}"),
    }
}

#[test]
fn grpc_web_trailer_block_http_header_format_conformance() {
    // Per gRPC-Web spec: trailers are encoded as "HTTP/1.1 header block"
    // format within the trailer frame payload. This must conform to HTTP/1.1
    // header syntax: field-name ":" OWS field-value OWS CRLF

    let codec = WebFrameCodec::new();
    let mut metadata = Metadata::new();
    assert!(metadata.insert("x-request-id", "req-123"));
    assert!(metadata.insert("x-trace-parent", "trace-456"));

    let mut wire = BytesMut::new();
    codec
        .encode_trailers(
            &Status::new(Code::NotFound, "entity not found"),
            &metadata,
            &mut wire,
        )
        .expect("trailer encoding must succeed");

    // Extract the HTTP/1.1 header block from the trailer frame
    let header_block = &wire[5..]; // Skip 5-byte gRPC frame header
    let header_text = std::str::from_utf8(header_block)
        .expect("header block must be valid UTF-8");

    // Verify HTTP/1.1 header format conformance
    let lines: Vec<&str> = header_text.split("\r\n").collect();

    // Find and verify grpc-status header
    let status_line = lines
        .iter()
        .find(|line| line.starts_with("grpc-status:"))
        .expect("grpc-status header must be present");
    assert_eq!(
        status_line.trim(),
        "grpc-status: 5", // NotFound = 5
        "grpc-status header must follow HTTP/1.1 format"
    );

    // Find and verify grpc-message header
    let message_line = lines
        .iter()
        .find(|line| line.starts_with("grpc-message:"))
        .expect("grpc-message header must be present");
    assert_eq!(
        message_line.trim(),
        "grpc-message: entity not found",
        "grpc-message header must follow HTTP/1.1 format"
    );

    // Verify custom metadata headers
    assert!(
        lines.iter().any(|line| line.starts_with("x-request-id:")),
        "custom metadata must be formatted as HTTP/1.1 headers"
    );

    // Verify all lines end with CRLF (except possibly last empty line)
    for line in &lines[..lines.len().saturating_sub(1)] {
        assert!(
            !line.contains('\n') && !line.contains('\r'),
            "header lines must be properly CRLF-separated: {line:?}"
        );
    }

    // Round-trip verification: decode and check metadata survives
    let decoded = codec
        .decode(&mut wire)
        .expect("decode must succeed")
        .expect("frame should be complete");

    match decoded {
        WebFrame::Trailers(trailer) => {
            assert_eq!(trailer.status.code(), Code::NotFound);
            assert_eq!(trailer.status.message(), "entity not found");
            assert_eq!(
                trailer.metadata.get("x-request-id"),
                Some(&MetadataValue::Ascii("req-123".to_string()))
            );
        }
        other => panic!("expected trailer frame, got {other:?}"),
    }
}
