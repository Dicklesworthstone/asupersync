use crate::websocket_e2e::util::init_ws_test;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::net::websocket::{FrameCodec, WsError};

#[test]
fn ws_conformance_rejects_fragmented_control_frame_on_decode() {
    init_ws_test("ws_conformance_rejects_fragmented_control_frame_on_decode");

    // FIN=0, opcode=Ping (0x9), MASK=1, len=0.
    // Decoder validates FIN/opcode before consuming further bytes.
    let mut raw = BytesMut::from(&b"\x09\x80"[..]);
    let mut codec = FrameCodec::server();
    let err = codec
        .decode(&mut raw)
        .expect_err("fragmented control frame must be rejected");
    assert!(matches!(err, WsError::FragmentedControlFrame));
}
