//! QUIC frame codec wire-format conformance harness (`arq-quic-epic-b0k8qo.9.6`, "H6").
//!
//! The DATAGRAM frame (RFC 9221, `0x30`/`0x31`) already has dedicated
//! wire-format conformance (`tests/quic_datagram_frame_rfc9221_wire_conformance.rs`)
//! and a fuzz-robustness pass (`tests/quic_frame_decode_robustness.rs`). This
//! file pins the remaining QUIC frame codec — every non-DATAGRAM
//! [`QuicFrame`] variant the data plane assembles and parses — with the four
//! conformance modes the epic DoD calls for:
//!
//! * **round-trip**: `encode` → `decode` is an identity for every variant across
//!   representative and boundary field values;
//! * **golden**: fixed byte vectors pin the exact wire encoding (frame-type code
//!   point + field layout) so a silent codec change is caught;
//! * **boundary**: QUIC varint size-class transitions (1/2/4/8 bytes) are
//!   exercised on a varint field;
//! * **negative**: truncated and unknown-type inputs fail closed with the typed
//!   [`QuicFrameError`] and never panic.
//!
//! Scope (no-claim boundary): this pins the RFC 9000 transport-frame codec in
//! `quic_native::quic_frames`. The RaptorQ-over-QUIC *symbol-envelope* schema
//! that rides inside a DATAGRAM payload is a Phase B (`transport_quic`) concern
//! and does not exist yet; it is documented as TBD in `docs/quic_wire_format.md`.
//! New test file only; no source touched.

#![allow(missing_docs)]

use asupersync::bytes::BytesMut;
use asupersync::net::atp::protocol::quic_frames::{
    AckRange, EcnCounts, QuicFrame, QuicFrameError, QuicFrameType,
};
use asupersync::net::atp::protocol::varint::VarInt;

// --- helpers ---------------------------------------------------------------

fn vi(value: u64) -> VarInt {
    VarInt::from_u64_unchecked(value)
}

fn encode(frame: &QuicFrame) -> Vec<u8> {
    let mut buf = BytesMut::new();
    frame.encode(&mut buf).expect("encode succeeds");
    buf.to_vec()
}

/// Decode exactly one frame from a byte slice.
fn decode_one(bytes: &[u8]) -> Result<Option<QuicFrame>, QuicFrameError> {
    let mut slice: &[u8] = bytes;
    QuicFrame::decode(&mut slice)
}

/// Assert `encode` then `decode` reproduces the original frame exactly.
fn assert_roundtrip(frame: &QuicFrame) {
    let bytes = encode(frame);
    let decoded = decode_one(&bytes)
        .expect("decode does not error")
        .expect("a frame is produced");
    assert_eq!(&decoded, frame, "round-trip identity for {frame:?}");
}

// --- round-trip: every variant --------------------------------------------

#[test]
fn roundtrip_control_frames_no_payload() {
    assert_roundtrip(&QuicFrame::Ping);
    assert_roundtrip(&QuicFrame::HandshakeDone);
    assert_roundtrip(&QuicFrame::Padding { length: 1 });
    assert_roundtrip(&QuicFrame::Padding { length: 7 });
}

#[test]
fn roundtrip_flow_control_frames() {
    assert_roundtrip(&QuicFrame::MaxData {
        maximum_data: vi(1_000_000),
    });
    assert_roundtrip(&QuicFrame::MaxStreamData {
        stream_id: vi(8),
        maximum_stream_data: vi(65_535),
    });
    assert_roundtrip(&QuicFrame::MaxStreams {
        maximum_streams: vi(128),
        bidirectional: true,
    });
    assert_roundtrip(&QuicFrame::MaxStreams {
        maximum_streams: vi(128),
        bidirectional: false,
    });
    assert_roundtrip(&QuicFrame::DataBlocked {
        maximum_data: vi(42),
    });
    assert_roundtrip(&QuicFrame::StreamDataBlocked {
        stream_id: vi(4),
        maximum_stream_data: vi(99),
    });
    assert_roundtrip(&QuicFrame::StreamsBlocked {
        maximum_streams: vi(16),
        bidirectional: true,
    });
    assert_roundtrip(&QuicFrame::StreamsBlocked {
        maximum_streams: vi(16),
        bidirectional: false,
    });
}

#[test]
fn roundtrip_stream_lifecycle_frames() {
    assert_roundtrip(&QuicFrame::ResetStream {
        stream_id: vi(12),
        error_code: vi(7),
        final_size: vi(4096),
    });
    assert_roundtrip(&QuicFrame::StopSending {
        stream_id: vi(12),
        error_code: vi(3),
    });
}

#[test]
fn roundtrip_crypto_frame_across_lengths() {
    for len in [0usize, 1, 17, 256, 1200] {
        let data: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        assert_roundtrip(&QuicFrame::Crypto {
            offset: vi(u64::try_from(len).unwrap()),
            data: data.into(),
        });
    }
}

#[test]
fn roundtrip_path_frames() {
    assert_roundtrip(&QuicFrame::PathChallenge {
        data: [1, 2, 3, 4, 5, 6, 7, 8],
    });
    assert_roundtrip(&QuicFrame::PathResponse {
        data: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
    });
}

#[test]
fn roundtrip_connection_close_quic_and_app() {
    assert_roundtrip(&QuicFrame::ConnectionClose {
        error_code: vi(0x0A),
        frame_type: Some(vi(0x06)),
        reason_phrase: BytesMut::from(&b"crypto error"[..]).freeze(),
    });
    assert_roundtrip(&QuicFrame::ConnectionClose {
        error_code: vi(0),
        frame_type: None,
        reason_phrase: BytesMut::new().freeze(),
    });
}

#[test]
fn roundtrip_ack_with_and_without_ecn() {
    let ranges = vec![
        AckRange {
            gap: vi(1),
            ack_range_length: vi(2),
        },
        AckRange {
            gap: vi(0),
            ack_range_length: vi(5),
        },
    ];
    assert_roundtrip(&QuicFrame::Ack {
        largest_acknowledged: vi(100),
        ack_delay: vi(25),
        ack_range_count: vi(u64::try_from(ranges.len()).unwrap()),
        first_ack_range: vi(3),
        ack_ranges: ranges.clone(),
        ecn_counts: None,
    });
    assert_roundtrip(&QuicFrame::Ack {
        largest_acknowledged: vi(100),
        ack_delay: vi(25),
        ack_range_count: vi(u64::try_from(ranges.len()).unwrap()),
        first_ack_range: vi(3),
        ack_ranges: ranges,
        ecn_counts: Some(EcnCounts {
            ect0_count: vi(10),
            ect1_count: vi(20),
            ecn_ce_count: vi(1),
        }),
    });
}

#[test]
fn roundtrip_stream_frame_flag_matrix() {
    // Every (offset?, fin?) combination with non-empty data (LEN bit set).
    for offset in [None, Some(vi(0)), Some(vi(1_000))] {
        for fin in [false, true] {
            assert_roundtrip(&QuicFrame::Stream {
                stream_id: vi(8),
                offset,
                data: BytesMut::from(&b"payload-bytes"[..]).freeze(),
                fin,
            });
        }
    }
    // Empty-data STREAM frame: now encoded WITH the LEN bit (explicit length 0),
    // so it is self-delimiting and round-trips as an identity even when it is not
    // the last frame in a packet (see
    // `empty_stream_frame_does_not_swallow_following_frame`).
    assert_roundtrip(&QuicFrame::Stream {
        stream_id: vi(8),
        offset: None,
        data: BytesMut::new().freeze(),
        fin: true,
    });
}

// --- golden: exact wire bytes ---------------------------------------------

#[test]
fn golden_wire_bytes_pin_codec() {
    assert_eq!(encode(&QuicFrame::Ping), vec![0x01]);
    assert_eq!(encode(&QuicFrame::HandshakeDone), vec![0x1e]);
    // PADDING is a run of zero bytes (one per `length`).
    assert_eq!(
        encode(&QuicFrame::Padding { length: 3 }),
        vec![0x00, 0x00, 0x00]
    );
    // MAX_DATA(16): type 0x10 + 1-byte varint 0x10.
    assert_eq!(
        encode(&QuicFrame::MaxData {
            maximum_data: vi(16)
        }),
        vec![0x10, 0x10]
    );
    // RESET_STREAM with 1-byte-varint fields.
    assert_eq!(
        encode(&QuicFrame::ResetStream {
            stream_id: vi(4),
            error_code: vi(7),
            final_size: vi(9),
        }),
        vec![0x04, 0x04, 0x07, 0x09]
    );
    // PATH_CHALLENGE: type 0x1a + 8 raw bytes (no length prefix).
    assert_eq!(
        encode(&QuicFrame::PathChallenge {
            data: [1, 2, 3, 4, 5, 6, 7, 8]
        }),
        vec![0x1a, 1, 2, 3, 4, 5, 6, 7, 8]
    );
    // CONNECTION_CLOSE: QUIC form is 0x1c, Application form is 0x1d.
    assert_eq!(
        encode(&QuicFrame::ConnectionClose {
            error_code: vi(0),
            frame_type: Some(vi(0)),
            reason_phrase: BytesMut::new().freeze(),
        })[0],
        0x1c
    );
    assert_eq!(
        encode(&QuicFrame::ConnectionClose {
            error_code: vi(0),
            frame_type: None,
            reason_phrase: BytesMut::new().freeze(),
        })[0],
        0x1d
    );
}

/// Regression: an empty / FIN-only STREAM frame must be self-delimiting (LEN bit
/// set, explicit length 0) so it does not swallow a following frame's bytes when
/// it is not the last frame in a packet. Before the fix the encoder omitted the
/// LEN bit for empty data and the decoder then consumed the rest of the packet as
/// stream data, silently corrupting trailing DATAGRAM symbols.
#[test]
fn empty_stream_frame_does_not_swallow_following_frame() {
    // STREAM (empty, FIN) followed by PING in the same packet buffer, mirroring
    // connection.rs emitting STREAM frames before other frames.
    let mut packet = encode(&QuicFrame::Stream {
        stream_id: vi(8),
        offset: None,
        data: BytesMut::new().freeze(),
        fin: true,
    });
    packet.extend_from_slice(&encode(&QuicFrame::Ping));

    let mut slice: &[u8] = &packet;
    let first = QuicFrame::decode(&mut slice)
        .expect("first frame decodes")
        .expect("a STREAM frame is produced");
    match first {
        QuicFrame::Stream { fin, ref data, .. } => {
            assert!(fin, "FIN preserved");
            assert!(data.is_empty(), "empty stream data, not the swallowed PING");
        }
        other => panic!("expected STREAM frame, got {other:?}"),
    }
    // The trailing PING must survive — before the fix the no-LEN STREAM frame
    // swallowed the rest of the packet as stream data.
    let second = QuicFrame::decode(&mut slice)
        .expect("following frame decodes")
        .expect("the trailing PING survives the STREAM frame");
    assert_eq!(second, QuicFrame::Ping, "trailing frame not swallowed");
    assert!(slice.is_empty(), "packet fully consumed");
}

#[test]
fn golden_stream_frame_type_flag_bits() {
    let base = |offset, data: &'static [u8], fin| {
        encode(&QuicFrame::Stream {
            stream_id: vi(8),
            offset,
            data: BytesMut::from(data).freeze(),
            fin,
        })[0]
    };
    // 0x08 base; +0x04 OFF, +0x02 LEN (ALWAYS set so STREAM frames are
    // self-delimiting — see the encoder), +0x01 FIN.
    assert_eq!(
        base(None, b"", false),
        0x0a,
        "empty STREAM (LEN always set)"
    );
    assert_eq!(base(None, b"x", false), 0x0a, "LEN bit");
    assert_eq!(base(Some(vi(1)), b"x", false), 0x0e, "OFF|LEN");
    assert_eq!(base(Some(vi(1)), b"x", true), 0x0f, "OFF|LEN|FIN");
    assert_eq!(base(None, b"", true), 0x0b, "FIN only (LEN always set)");
}

// --- boundary: varint size classes ----------------------------------------

#[test]
fn varint_size_class_boundaries_on_max_data() {
    // (value, expected total encoded length = 1 type byte + varint size)
    // varint sizes: <=63 ->1, <=16383 ->2, <=2^30-1 ->4, <=2^62-1 ->8.
    let cases: [(u64, usize); 8] = [
        (0, 2),
        (63, 2),
        (64, 3),
        (16_383, 3),
        (16_384, 5),
        ((1 << 30) - 1, 5),
        (1 << 30, 9),
        ((1 << 62) - 1, 9),
    ];
    for (value, expected_len) in cases {
        let frame = QuicFrame::MaxData {
            maximum_data: vi(value),
        };
        let bytes = encode(&frame);
        assert_eq!(
            bytes.len(),
            expected_len,
            "encoded length for MAX_DATA({value})"
        );
        // And the value round-trips exactly across the size-class boundary.
        let decoded = decode_one(&bytes).unwrap().unwrap();
        match decoded {
            QuicFrame::MaxData { maximum_data } => assert_eq!(maximum_data.value(), value),
            other => panic!("expected MaxData, got {other:?}"),
        }
    }
}

// --- negative: malformed / unknown fail closed ----------------------------

#[test]
fn empty_buffer_decodes_to_none() {
    assert!(decode_one(&[]).expect("no error").is_none());
}

#[test]
fn truncated_frames_fail_closed_with_unexpected_eof() {
    // ACK type byte with no following fields.
    assert!(matches!(
        decode_one(&[0x02]),
        Err(QuicFrameError::UnexpectedEof)
    ));
    // CRYPTO: offset=0, length=5, but no data bytes.
    assert!(matches!(
        decode_one(&[0x06, 0x00, 0x05]),
        Err(QuicFrameError::UnexpectedEof)
    ));
    // RESET_STREAM with only a stream id present.
    assert!(matches!(
        decode_one(&[0x04, 0x01]),
        Err(QuicFrameError::UnexpectedEof)
    ));
    // PATH_CHALLENGE needs 8 bytes; give 3.
    assert!(matches!(
        decode_one(&[0x1a, 0x00, 0x00, 0x00]),
        Err(QuicFrameError::UnexpectedEof)
    ));
    // CONNECTION_CLOSE (app): error code present, reason length claims 4, none follow.
    assert!(matches!(
        decode_one(&[0x1d, 0x00, 0x04]),
        Err(QuicFrameError::UnexpectedEof)
    ));
}

#[test]
fn unknown_frame_types_fail_closed() {
    // The codec implements a bounded set of frame types. NEW_TOKEN (0x07),
    // NEW_CONNECTION_ID (0x18), RETIRE_CONNECTION_ID (0x19) are intentionally not
    // decoded, and arbitrary high code points are rejected — never panicking.
    for ft in [0x07u8, 0x18, 0x19, 0x20, 0x3f] {
        assert!(
            matches!(
                decode_one(&[ft]),
                Err(QuicFrameError::UnknownFrameType(code)) if code == u64::from(ft)
            ),
            "frame type {ft:#x} must be rejected as UnknownFrameType"
        );
    }
}

// --- frame-type code-point mapping ----------------------------------------

#[test]
fn frame_type_code_point_mapping() {
    let expect = |code: u64, ty: QuicFrameType| {
        assert_eq!(
            QuicFrameType::from_varint(vi(code)).unwrap(),
            ty,
            "code point {code:#x}"
        );
    };
    expect(0x00, QuicFrameType::Padding);
    expect(0x01, QuicFrameType::Ping);
    expect(0x02, QuicFrameType::Ack);
    expect(0x03, QuicFrameType::AckEcn);
    expect(0x04, QuicFrameType::ResetStream);
    expect(0x05, QuicFrameType::StopSending);
    expect(0x06, QuicFrameType::Crypto);
    // STREAM frames span 0x08..=0x0f (flag bits) and all map to StreamBase.
    for code in 0x08..=0x0f {
        expect(code, QuicFrameType::StreamBase);
    }
    expect(0x10, QuicFrameType::MaxData);
    expect(0x11, QuicFrameType::MaxStreamData);
    expect(0x12, QuicFrameType::MaxStreamsBidi);
    expect(0x13, QuicFrameType::MaxStreamsUni);
    expect(0x1c, QuicFrameType::ConnectionCloseQuic);
    expect(0x1d, QuicFrameType::ConnectionCloseApp);
    expect(0x1e, QuicFrameType::HandshakeDone);
    expect(0x30, QuicFrameType::Datagram);
    expect(0x31, QuicFrameType::Datagram);
    // Out-of-range code point is a typed error.
    assert!(matches!(
        QuicFrameType::from_varint(vi(0x99)),
        Err(QuicFrameError::UnknownFrameType(0x99))
    ));
}

// --- multi-frame packets ---------------------------------------------------

#[test]
fn multi_frame_packet_decodes_in_order() {
    let frames = vec![
        QuicFrame::Ping,
        QuicFrame::MaxData {
            maximum_data: vi(1_000),
        },
        QuicFrame::ResetStream {
            stream_id: vi(4),
            error_code: vi(1),
            final_size: vi(2),
        },
        QuicFrame::Stream {
            stream_id: vi(8),
            offset: Some(vi(16)),
            data: BytesMut::from(&b"chunk"[..]).freeze(),
            fin: true,
        },
        QuicFrame::HandshakeDone,
    ];

    let mut buf = BytesMut::new();
    for f in &frames {
        f.encode(&mut buf).expect("encode");
    }

    let mut slice: &[u8] = &buf;
    let mut decoded = Vec::new();
    while let Some(frame) = QuicFrame::decode(&mut slice).expect("decode") {
        decoded.push(frame);
    }
    assert_eq!(decoded, frames, "all frames decode in order");
    assert!(slice.is_empty(), "no trailing bytes left undecoded");
}

#[test]
fn padding_run_then_frame_decodes() {
    // PADDING(2) followed by PING: padding collapses to a length, then PING.
    let mut buf = BytesMut::new();
    QuicFrame::Padding { length: 2 }
        .encode(&mut buf)
        .expect("encode padding");
    QuicFrame::Ping.encode(&mut buf).expect("encode ping");

    let mut slice: &[u8] = &buf;
    let first = QuicFrame::decode(&mut slice).unwrap().unwrap();
    assert_eq!(first, QuicFrame::Padding { length: 2 });
    let second = QuicFrame::decode(&mut slice).unwrap().unwrap();
    assert_eq!(second, QuicFrame::Ping);
    assert!(QuicFrame::decode(&mut slice).unwrap().is_none());
}
