//! gRPC message truncation fuzz target.
//!
//! Drives the gRPC length-prefixed message decoder through the HTTP/2 inbound
//! DATA path. The malformed case is: the gRPC header declares `N` payload bytes,
//! only `M < N` bytes arrive, then the peer half-closes the stream. The codec
//! must not accept a truncated message, and the HTTP/2 driver must reset the
//! stream with `RST_STREAM(INTERNAL_ERROR)`.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::codec::Decoder;
use asupersync::grpc::codec::{GrpcCodec, MESSAGE_HEADER_SIZE};
use asupersync::grpc::status::Code;
use asupersync::http::h2::connection::ReceivedFrame;
use asupersync::http::h2::frame::{DataFrame, Frame, HeadersFrame, RstStreamFrame, SettingsFrame};
use asupersync::http::h2::{Connection, ErrorCode, Settings};
use libfuzzer_sys::fuzz_target;

const STREAM_ID: u32 = 1;
const MAX_DECLARED_LEN: usize = 16 * 1024;

#[derive(Arbitrary, Debug)]
struct Scenario {
    declared_len: u16,
    actual_mod: u16,
    payload: Vec<u8>,
    chunks: Vec<u8>,
}

fuzz_target!(|scenario: Scenario| {
    let declared_len = normalize_declared_len(scenario.declared_len);
    let actual_len = usize::from(scenario.actual_mod) % declared_len;
    let wire = build_truncated_grpc_frame(declared_len, actual_len, &scenario.payload);

    let mut h2 = open_inbound_grpc_stream();
    let mut codec = GrpcCodec::with_max_size(MAX_DECLARED_LEN);
    let mut decode_buf = BytesMut::new();
    let mut cursor = 0usize;
    let mut chunk_index = 0usize;

    while cursor < wire.len() {
        let remaining = wire.len() - cursor;
        let requested = scenario
            .chunks
            .get(chunk_index % scenario.chunks.len().max(1))
            .copied()
            .unwrap_or(u8::MAX);
        let chunk_len = normalize_chunk_len(requested, remaining);
        let end_stream = cursor + chunk_len == wire.len();
        let chunk = wire.slice(cursor..cursor + chunk_len);

        match h2
            .process_frame(Frame::Data(DataFrame::new(
                STREAM_ID,
                chunk.clone(),
                end_stream,
            )))
            .expect("inbound DATA for an open stream should be accepted")
        {
            Some(ReceivedFrame::Data {
                stream_id,
                data,
                end_stream: observed_end_stream,
            }) => {
                assert_eq!(stream_id, STREAM_ID);
                assert_eq!(data, chunk);
                assert_eq!(observed_end_stream, end_stream);
                decode_buf.extend_from_slice(&data);
            }
            other => panic!("expected DATA event from HTTP/2 receive path, got {other:?}"),
        }

        if end_stream {
            assert_truncation_resets_stream(&mut h2, &mut codec, &mut decode_buf);
        } else {
            let before = decode_buf.clone();
            let decoded = codec
                .decode(&mut decode_buf)
                .expect("partial frame before half-close must not be a codec error");
            assert!(
                decoded.is_none(),
                "truncated frame decoded before the declared payload length arrived"
            );
            assert_eq!(
                decode_buf, before,
                "partial decode must retain bytes until the stream half-close is observed"
            );
        }

        cursor += chunk_len;
        chunk_index = chunk_index.saturating_add(1);
    }
});

fn normalize_declared_len(raw: u16) -> usize {
    usize::from(raw).clamp(1, MAX_DECLARED_LEN)
}

fn normalize_chunk_len(raw: u8, remaining: usize) -> usize {
    usize::from(raw).clamp(1, remaining)
}

fn build_truncated_grpc_frame(declared_len: usize, actual_len: usize, seed: &[u8]) -> Bytes {
    debug_assert!(actual_len < declared_len);

    let mut frame = BytesMut::with_capacity(MESSAGE_HEADER_SIZE + actual_len);
    frame.put_u8(0);
    frame.put_u32(u32::try_from(declared_len).expect("declared length is capped"));
    for idx in 0..actual_len {
        frame.put_u8(seed.get(idx % seed.len().max(1)).copied().unwrap_or(0xA5));
    }
    frame.freeze()
}

fn open_inbound_grpc_stream() -> Connection {
    let mut h2 = Connection::server(Settings::default());
    h2.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect("peer SETTINGS should open the server connection");
    drain_pending_settings_ack(&mut h2);

    let opened = h2
        .process_frame(Frame::Headers(HeadersFrame::new(
            STREAM_ID,
            Bytes::new(),
            false,
            true,
        )))
        .expect("request HEADERS should open the stream");
    assert!(matches!(
        opened,
        Some(ReceivedFrame::Headers {
            stream_id: STREAM_ID,
            ..
        })
    ));
    h2
}

fn drain_pending_settings_ack(h2: &mut Connection) {
    while matches!(h2.next_frame(), Some(Frame::Settings(_))) {}
}

fn assert_truncation_resets_stream(
    h2: &mut Connection,
    codec: &mut GrpcCodec,
    decode_buf: &mut BytesMut,
) {
    let before = decode_buf.clone();
    assert!(
        codec.decode(decode_buf).unwrap().is_none(),
        "N>M frame must still be incomplete before EOF handling"
    );
    assert_eq!(
        decode_buf, &before,
        "ordinary decode must not consume an incomplete gRPC message"
    );

    let err = codec
        .decode_eof(decode_buf)
        .expect_err("half-close with trailing partial message must fail");
    let status = err.into_status();
    assert_eq!(
        status.code(),
        Code::Unavailable,
        "truncated message at half-close must be classified as transport EOF"
    );

    h2.reset_stream(STREAM_ID, ErrorCode::InternalError);
    match h2
        .next_frame()
        .expect("decode EOF failure must emit RST_STREAM")
    {
        Frame::RstStream(RstStreamFrame {
            stream_id,
            error_code,
        }) => {
            assert_eq!(stream_id, STREAM_ID);
            assert_eq!(error_code, ErrorCode::InternalError);
        }
        other => panic!("expected RST_STREAM(INTERNAL_ERROR), got {other:?}"),
    }
}
