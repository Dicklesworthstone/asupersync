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
