#![allow(clippy::all)]
//! WebSocket frame fragmentation conformance tests per RFC 6455 Section 5.
//!
//! Tests the critical fragmentation behaviors required by the WebSocket protocol:
//! 1. Continuation frames (opcode 0) required after non-final text/binary frames
//! 2. Control frames cannot be fragmented (FIN=1 always required)
//! 3. Interleaved control frames allowed between data fragments
//! 4. Proper opcode sequence: first=text|binary, middle+last=continuation
//! 5. Single-frame messages must have FIN=1
//!
//! # References
//! - RFC 6455 Section 5: "Data Framing"
//! - RFC 6455 Section 5.4: "Fragmentation"
//! - RFC 6455 Section 5.5: "Control Frames"

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::net::websocket::{Frame, FrameCodec, Opcode, Role, WsError};

/// Test continuation frame requirement after non-final data frames.
/// RFC 6455 Section 5.4: "A fragmented message consists of a single frame with
/// the FIN bit clear and an opcode other than 0, followed by zero or more frames
/// with the FIN bit clear and the opcode set to 0, and terminated by a single
/// frame with the FIN bit set and an opcode of 0."
#[test]
fn test_continuation_required_after_nonfinal_text() {
    let mut encoder = FrameCodec::server();
    let mut decoder = FrameCodec::client();

    // First fragment: Text frame with FIN=false
    let mut first_fragment = Frame::text("Hello, ");
    first_fragment.fin = false;

    // Middle fragment: Continuation frame with FIN=false
    let mut middle_fragment = Frame {
        fin: false,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Continuation,
        masked: false,
        mask_key: None,
        payload: Bytes::from("WebSocket "),
    };

    // Final fragment: Continuation frame with FIN=true
    let final_fragment = Frame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Continuation,
        masked: false,
        mask_key: None,
        payload: Bytes::from("World!"),
    };

    // Encode and decode the sequence
    let mut buf = BytesMut::new();
    encoder.encode(first_fragment, &mut buf).unwrap();
    encoder.encode(middle_fragment, &mut buf).unwrap();
    encoder.encode(final_fragment, &mut buf).unwrap();

    // Decode all three frames
    let frame1 = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(!frame1.fin, "First fragment must have FIN=false");
    assert_eq!(frame1.opcode, Opcode::Text, "First fragment must be Text");

    let frame2 = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(!frame2.fin, "Middle fragment must have FIN=false");
    assert_eq!(
        frame2.opcode,
        Opcode::Continuation,
        "Middle fragment must be Continuation"
    );

    let frame3 = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(frame3.fin, "Final fragment must have FIN=true");
    assert_eq!(
        frame3.opcode,
        Opcode::Continuation,
        "Final fragment must be Continuation"
    );
}

/// Test continuation frame requirement after non-final binary frames.
/// Same requirements as text frames per RFC 6455 Section 5.4.
#[test]
fn test_continuation_required_after_nonfinal_binary() {
    let mut encoder = FrameCodec::server();
    let mut decoder = FrameCodec::client();

    // First fragment: Binary frame with FIN=false
    let mut first_fragment = Frame::binary(vec![0x01, 0x02]);
    first_fragment.fin = false;

    // Final fragment: Continuation frame with FIN=true
    let final_fragment = Frame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Continuation,
        masked: false,
        mask_key: None,
        payload: Bytes::from(vec![0x03, 0x04]),
    };

    let mut buf = BytesMut::new();
    encoder.encode(first_fragment, &mut buf).unwrap();
    encoder.encode(final_fragment, &mut buf).unwrap();

    let frame1 = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(!frame1.fin, "First binary fragment must have FIN=false");
    assert_eq!(
        frame1.opcode,
        Opcode::Binary,
        "First fragment must be Binary"
    );

    let frame2 = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(frame2.fin, "Final fragment must have FIN=true");
    assert_eq!(
        frame2.opcode,
        Opcode::Continuation,
        "Final fragment must be Continuation"
    );
}

/// Test that control frames cannot be fragmented.
/// RFC 6455 Section 5.5: "Control frames (see Section 11.8) MAY be injected in
/// the middle of a fragmented message. Control frames themselves MUST NOT be
/// fragmented."
#[test]
fn test_control_frames_cannot_be_fragmented() {
    let mut codec = FrameCodec::server();

    // Test Ping frame with FIN=false (should be rejected)
    let mut fragmented_ping = Frame::ping("test");
    fragmented_ping.fin = false;

    let mut buf = BytesMut::new();
    let result = codec.encode(fragmented_ping, &mut buf);
    assert!(
        matches!(result, Err(WsError::FragmentedControlFrame)),
        "Ping frame with FIN=false must be rejected"
    );

    // Test Pong frame with FIN=false (should be rejected)
    let mut fragmented_pong = Frame::pong("response");
    fragmented_pong.fin = false;

    let mut buf = BytesMut::new();
    let result = codec.encode(fragmented_pong, &mut buf);
    assert!(
        matches!(result, Err(WsError::FragmentedControlFrame)),
        "Pong frame with FIN=false must be rejected"
    );

    // Test Close frame with FIN=false (should be rejected)
    let mut fragmented_close = Frame::close(Some(1000), Some("goodbye"));
    fragmented_close.fin = false;

    let mut buf = BytesMut::new();
    let result = codec.encode(fragmented_close, &mut buf);
    assert!(
        matches!(result, Err(WsError::FragmentedControlFrame)),
        "Close frame with FIN=false must be rejected"
    );
}

/// Test that control frames can be interleaved between data fragments.
/// RFC 6455 Section 5.5: "Control frames MAY be injected in the middle of a
/// fragmented message."
#[test]
fn test_interleaved_control_frames_allowed() {
    let mut encoder = FrameCodec::server();
    let mut decoder = FrameCodec::client();

    // Create a fragmented text message with interleaved control frames
    let mut first_fragment = Frame::text("Start ");
    first_fragment.fin = false;

    let ping_frame = Frame::ping("alive?");

    let mut middle_fragment = Frame {
        fin: false,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Continuation,
        masked: false,
        mask_key: None,
        payload: Bytes::from("middle "),
    };

    let pong_frame = Frame::pong("yes!");

    let final_fragment = Frame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Continuation,
        masked: false,
        mask_key: None,
        payload: Bytes::from("end"),
    };

    // Encode sequence: data fragment, control, data fragment, control, final fragment
    let mut buf = BytesMut::new();
    encoder.encode(first_fragment, &mut buf).unwrap();
    encoder.encode(ping_frame, &mut buf).unwrap();
    encoder.encode(middle_fragment, &mut buf).unwrap();
    encoder.encode(pong_frame, &mut buf).unwrap();
    encoder.encode(final_fragment, &mut buf).unwrap();

    // Decode and verify the sequence
    let frame1 = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(!frame1.fin && frame1.opcode == Opcode::Text);

    let frame2 = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(frame2.fin && frame2.opcode == Opcode::Ping);

    let frame3 = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(!frame3.fin && frame3.opcode == Opcode::Continuation);

    let frame4 = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(frame4.fin && frame4.opcode == Opcode::Pong);

    let frame5 = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(frame5.fin && frame5.opcode == Opcode::Continuation);

    // Verify the control frames were processed correctly
    assert_eq!(frame2.payload.as_ref(), b"alive?");
    assert_eq!(frame4.payload.as_ref(), b"yes!");

    // Verify data frame sequence is correct
    assert_eq!(frame1.payload.as_ref(), b"Start ");
    assert_eq!(frame3.payload.as_ref(), b"middle ");
    assert_eq!(frame5.payload.as_ref(), b"end");
}

/// Test proper opcode sequence in fragmented messages.
/// RFC 6455 Section 5.4: "The opcode of the first frame indicates the
/// interpretation of the concatenated payload. For text frames, the payload
/// is always UTF-8. For binary frames, the payload is arbitrary."
#[test]
fn test_fragment_opcode_sequence() {
    let mut encoder = FrameCodec::server();
    let mut decoder = FrameCodec::client();

    // Test text fragmentation sequence: Text -> Continuation -> Continuation
    let mut text_first = Frame::text("Hello ");
    text_first.fin = false;

    let text_middle = Frame {
        fin: false,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Continuation,
        masked: false,
        mask_key: None,
        payload: Bytes::from("fragmented "),
    };

    let text_final = Frame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Continuation,
        masked: false,
        mask_key: None,
        payload: Bytes::from("text"),
    };

    let mut buf = BytesMut::new();
    encoder.encode(text_first, &mut buf).unwrap();
    encoder.encode(text_middle, &mut buf).unwrap();
    encoder.encode(text_final, &mut buf).unwrap();

    // Verify opcode sequence
    let frame1 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(
        frame1.opcode,
        Opcode::Text,
        "First fragment must be Text opcode"
    );
    assert!(!frame1.fin);

    let frame2 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(
        frame2.opcode,
        Opcode::Continuation,
        "Middle fragment must be Continuation"
    );
    assert!(!frame2.fin);

    let frame3 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(
        frame3.opcode,
        Opcode::Continuation,
        "Final fragment must be Continuation"
    );
    assert!(frame3.fin);

    // Test binary fragmentation sequence: Binary -> Continuation
    let mut binary_first = Frame::binary(vec![0xFF, 0xFE]);
    binary_first.fin = false;

    let binary_final = Frame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Continuation,
        masked: false,
        mask_key: None,
        payload: Bytes::from(vec![0xFD, 0xFC]),
    };

    let mut buf = BytesMut::new();
    encoder.encode(binary_first, &mut buf).unwrap();
    encoder.encode(binary_final, &mut buf).unwrap();

    let frame1 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(
        frame1.opcode,
        Opcode::Binary,
        "First fragment must be Binary opcode"
    );
    assert!(!frame1.fin);

    let frame2 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(
        frame2.opcode,
        Opcode::Continuation,
        "Final fragment must be Continuation"
    );
    assert!(frame2.fin);
}

/// Test that single-frame messages have FIN=1.
/// RFC 6455 Section 5.4: "An unfragmented message consists of a single frame
/// with the FIN bit set and an opcode other than 0."
#[test]
fn test_single_frame_messages_have_fin_set() {
    let mut encoder = FrameCodec::server();
    let mut decoder = FrameCodec::client();

    // Test single text frame
    let text_frame = Frame::text("Single text message");
    assert!(text_frame.fin, "Single text frame must have FIN=true");
    assert_eq!(text_frame.opcode, Opcode::Text);

    // Test single binary frame
    let binary_frame = Frame::binary(vec![0x01, 0x02, 0x03]);
    assert!(binary_frame.fin, "Single binary frame must have FIN=true");
    assert_eq!(binary_frame.opcode, Opcode::Binary);

    // Test control frames (always single)
    let ping_frame = Frame::ping("ping data");
    assert!(ping_frame.fin, "Ping frame must have FIN=true");
    assert_eq!(ping_frame.opcode, Opcode::Ping);

    let pong_frame = Frame::pong("pong data");
    assert!(pong_frame.fin, "Pong frame must have FIN=true");
    assert_eq!(pong_frame.opcode, Opcode::Pong);

    let close_frame = Frame::close(Some(1000), Some("goodbye"));
    assert!(close_frame.fin, "Close frame must have FIN=true");
    assert_eq!(close_frame.opcode, Opcode::Close);

    // Encode and decode to verify they work correctly
    let mut buf = BytesMut::new();
    encoder.encode(text_frame, &mut buf).unwrap();
    encoder.encode(binary_frame, &mut buf).unwrap();
    encoder.encode(ping_frame, &mut buf).unwrap();
    encoder.encode(pong_frame, &mut buf).unwrap();
    encoder.encode(close_frame, &mut buf).unwrap();

    // Decode all frames and verify FIN=true and correct opcodes
    let decoded_text = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(decoded_text.fin && decoded_text.opcode == Opcode::Text);

    let decoded_binary = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(decoded_binary.fin && decoded_binary.opcode == Opcode::Binary);

    let decoded_ping = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(decoded_ping.fin && decoded_ping.opcode == Opcode::Ping);

    let decoded_pong = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(decoded_pong.fin && decoded_pong.opcode == Opcode::Pong);

    let decoded_close = decoder.decode(&mut buf).unwrap().unwrap();
    assert!(decoded_close.fin && decoded_close.opcode == Opcode::Close);
}

/// Test edge case: empty continuation frames are valid.
/// RFC 6455 does not prohibit empty payload in continuation frames.
#[test]
fn test_empty_continuation_frames() {
    let mut encoder = FrameCodec::server();
    let mut decoder = FrameCodec::client();

    // Text message with empty middle fragment
    let mut first = Frame::text("Start");
    first.fin = false;

    let empty_middle = Frame {
        fin: false,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Continuation,
        masked: false,
        mask_key: None,
        payload: Bytes::new(), // Empty payload
    };

    let final_fragment = Frame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Continuation,
        masked: false,
        mask_key: None,
        payload: Bytes::from("End"),
    };

    let mut buf = BytesMut::new();
    encoder.encode(first, &mut buf).unwrap();
    encoder.encode(empty_middle, &mut buf).unwrap();
    encoder.encode(final_fragment, &mut buf).unwrap();

    // Decode and verify
    let frame1 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(frame1.opcode, Opcode::Text);
    assert!(!frame1.fin);
    assert_eq!(frame1.payload.as_ref(), b"Start");

    let frame2 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(frame2.opcode, Opcode::Continuation);
    assert!(!frame2.fin);
    assert!(frame2.payload.is_empty());

    let frame3 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(frame3.opcode, Opcode::Continuation);
    assert!(frame3.fin);
    assert_eq!(frame3.payload.as_ref(), b"End");
}

/// Test that multiple interleaved control frames are allowed.
/// RFC 6455 Section 5.5 allows multiple control frames between fragments.
#[test]
fn test_multiple_interleaved_control_frames() {
    let mut encoder = FrameCodec::server();
    let mut decoder = FrameCodec::client();

    // Fragmented message with multiple control frames
    let mut first = Frame::text("Fragment1");
    first.fin = false;

    let ping1 = Frame::ping("ping1");
    let ping2 = Frame::ping("ping2");
    let close_frame = Frame::close(Some(1000), Some("test close"));

    let final_fragment = Frame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Continuation,
        masked: false,
        mask_key: None,
        payload: Bytes::from("Fragment2"),
    };

    // Encode: data, control, control, control, data
    let mut buf = BytesMut::new();
    encoder.encode(first, &mut buf).unwrap();
    encoder.encode(ping1, &mut buf).unwrap();
    encoder.encode(ping2, &mut buf).unwrap();
    encoder.encode(close_frame, &mut buf).unwrap();
    encoder.encode(final_fragment, &mut buf).unwrap();

    // Decode and verify the sequence is preserved
    let data1 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(data1.opcode, Opcode::Text);
    assert!(!data1.fin);

    let ctrl1 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(ctrl1.opcode, Opcode::Ping);
    assert!(ctrl1.fin);

    let ctrl2 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(ctrl2.opcode, Opcode::Ping);
    assert!(ctrl2.fin);

    let ctrl3 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(ctrl3.opcode, Opcode::Close);
    assert!(ctrl3.fin);

    let data2 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(data2.opcode, Opcode::Continuation);
    assert!(data2.fin);
}

/// Test that a single continuation frame without a starting frame is a protocol violation.
/// RFC 6455 Section 5.4 requires fragmented messages to start with a non-continuation frame.
/// Note: This test documents expected behavior - the current codec may not enforce this.
#[test]
fn test_orphaned_continuation_frame_documentation() {
    let mut encoder = FrameCodec::server();
    let mut decoder = FrameCodec::client();

    // Create a standalone continuation frame (this should ideally be rejected by a
    // stateful frame validator, but the current codec is stateless)
    let orphaned_continuation = Frame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Continuation,
        masked: false,
        mask_key: None,
        payload: Bytes::from("orphaned"),
    };

    let mut buf = BytesMut::new();
    encoder.encode(orphaned_continuation, &mut buf).unwrap();

    // The current stateless codec will accept this, but a complete WebSocket
    // implementation should track fragmentation state and reject orphaned continuations
    let frame = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(frame.opcode, Opcode::Continuation);
    assert!(frame.fin);

    // This test documents that frame-level validation passes, but application-level
    // fragmentation state tracking would need to reject this sequence
}
