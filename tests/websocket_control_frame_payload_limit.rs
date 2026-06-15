//! Phase-C security contract: WebSocket control-frame payload limit (bead asupersync-zs4jzu).
//!
//! RFC 6455 §5.5 caps control-frame payloads at 125 bytes. The public `Frame::ping`
//! and `Frame::pong` constructors must fail closed at construction — exactly like
//! `Frame::close` already does — instead of deferring rejection to the encoder.
//!
//! This integration crate exercises the contract through the fully public surface
//! (`asupersync::net::websocket::{Frame, Opcode, FrameCodec}`), so it builds the
//! library *without* `cfg(test)` and stays runnable independent of the (heavy,
//! churn-prone) lib-unittest binary.
//!
//! Coverage map against the bead's acceptance criteria:
//!   AC1 — ping/pong preserve a 125-byte boundary payload.
//!   AC2 — oversized 126-byte ping/pong panic at construction with deterministic
//!         diagnostics (`#[should_panic]` with the exact message prefix).
//!   AC3 — the encoder-side control validation remains intact as a defense-in-depth
//!         backstop: a manually constructed oversized control frame (bypassing the
//!         guarded constructor via public fields) is still rejected by the codec.

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::Encoder;
use asupersync::net::websocket::{Frame, FrameCodec, Opcode, WsError};

const CONTROL_FRAME_MAX_PAYLOAD_LEN: usize = 125;

/// AC1: a payload exactly at the 125-byte boundary is accepted and preserved
/// byte-for-byte by both control-frame constructors.
#[test]
fn ping_and_pong_preserve_max_boundary_payload() {
    let payload = Bytes::from(vec![0xA5u8; CONTROL_FRAME_MAX_PAYLOAD_LEN]);

    let ping = Frame::ping(payload.clone());
    assert_eq!(ping.opcode, Opcode::Ping);
    assert_eq!(ping.payload.len(), CONTROL_FRAME_MAX_PAYLOAD_LEN);
    assert_eq!(ping.payload, payload);
    assert!(ping.fin, "control frames must not be fragmented");

    let pong = Frame::pong(payload.clone());
    assert_eq!(pong.opcode, Opcode::Pong);
    assert_eq!(pong.payload.len(), CONTROL_FRAME_MAX_PAYLOAD_LEN);
    assert_eq!(pong.payload, payload);
    assert!(pong.fin, "control frames must not be fragmented");
}

/// AC1 (lower bound): an empty control payload remains valid.
#[test]
fn ping_and_pong_accept_empty_payload() {
    assert_eq!(Frame::ping(Bytes::new()).payload.len(), 0);
    assert_eq!(Frame::pong(Bytes::new()).payload.len(), 0);
}

/// AC2: a 126-byte ping payload panics at construction with deterministic diagnostics.
#[test]
#[should_panic(expected = "ping frame payload (126 bytes) exceeds 125-byte control frame limit")]
fn ping_rejects_one_byte_over_limit() {
    let _ = Frame::ping(Bytes::from(vec![0u8; CONTROL_FRAME_MAX_PAYLOAD_LEN + 1]));
}

/// AC2: a 126-byte pong payload panics at construction with deterministic diagnostics.
#[test]
#[should_panic(expected = "pong frame payload (126 bytes) exceeds 125-byte control frame limit")]
fn pong_rejects_one_byte_over_limit() {
    let _ = Frame::pong(Bytes::from(vec![0u8; CONTROL_FRAME_MAX_PAYLOAD_LEN + 1]));
}

/// AC3: the encoder-side guard is still a backstop. A control frame whose oversized
/// payload was assembled directly (bypassing the guarded constructor via the public
/// fields) must still be rejected by the codec rather than emitted onto the wire.
#[test]
fn encoder_backstop_rejects_oversized_control_frame() {
    for opcode in [Opcode::Ping, Opcode::Pong] {
        let oversized = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode,
            masked: false,
            mask_key: None,
            payload: Bytes::from(vec![0u8; CONTROL_FRAME_MAX_PAYLOAD_LEN + 1]),
        };

        let mut codec = FrameCodec::server();
        let mut dst = BytesMut::new();
        let err = codec
            .encode(oversized, &mut dst)
            .expect_err("encoder must reject an oversized control frame");
        assert!(
            matches!(err, WsError::ControlFrameTooLarge(len) if len == CONTROL_FRAME_MAX_PAYLOAD_LEN + 1),
            "expected ControlFrameTooLarge(126), got {err:?}"
        );
        assert!(
            dst.is_empty(),
            "rejected control frame must not leave partial bytes on the wire"
        );
    }
}

/// Defense-in-depth contrast: the 125-byte limit is control-frame specific. A data
/// frame larger than 125 bytes encodes successfully (extended length form), proving
/// the new guard did not over-broaden the rejection.
#[test]
fn data_frames_are_not_subject_to_control_limit() {
    let payload = Bytes::from(vec![0u8; CONTROL_FRAME_MAX_PAYLOAD_LEN + 75]);
    let frame = Frame::binary(payload);

    let mut codec = FrameCodec::server();
    let mut dst = BytesMut::new();
    codec
        .encode(frame, &mut dst)
        .expect("a 200-byte data frame must encode without hitting the control limit");
    assert!(!dst.is_empty());
}
