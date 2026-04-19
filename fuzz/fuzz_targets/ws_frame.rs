#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::net::websocket::frame::{Frame, FrameCodec, Opcode, Role, apply_mask};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzFrame {
    fin: bool,
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: u8,
    mask_key: Option<[u8; 4]>,
    payload: Vec<u8>,
}

impl FuzzFrame {
    fn to_opcode(&self) -> Option<Opcode> {
        match self.opcode & 0x0f {
            0x0 => Some(Opcode::Continuation),
            0x1 => Some(Opcode::Text),
            0x2 => Some(Opcode::Binary),
            0x8 => Some(Opcode::Close),
            0x9 => Some(Opcode::Ping),
            0xa => Some(Opcode::Pong),
            _ => None, // Invalid opcode for frame rejection testing
        }
    }

    fn to_frame(&self) -> Option<Frame> {
        self.to_opcode().map(|opcode| Frame {
            fin: self.fin,
            rsv1: self.rsv1,
            rsv2: self.rsv2,
            rsv3: self.rsv3,
            opcode,
            masked: self.mask_key.is_some(),
            mask_key: self.mask_key.unwrap_or([0; 4]),
            payload: Bytes::from(self.payload.clone()),
        })
    }
}

fuzz_target!(|fuzz_frame: FuzzFrame| {
    // Limit payload size to avoid excessive memory usage during fuzzing
    if fuzz_frame.payload.len() > 65536 {
        return;
    }

    // Skip invalid opcodes for basic round-trip testing
    let Some(opcode) = fuzz_frame.to_opcode() else {
        return;
    };

    // MR1: Masked client frames XOR-unmask to original payload
    if let Some(mask_key) = fuzz_frame.mask_key {
        let mut masked_payload = fuzz_frame.payload.clone();
        apply_mask(&mut masked_payload, mask_key);

        // Unmasking should recover original
        let mut unmasked_payload = masked_payload.clone();
        apply_mask(&mut unmasked_payload, mask_key);
        assert_eq!(
            unmasked_payload, fuzz_frame.payload,
            "XOR unmasking failed to recover original payload"
        );

        // XOR is its own inverse (idempotent)
        apply_mask(&mut unmasked_payload, mask_key);
        assert_eq!(
            unmasked_payload, masked_payload,
            "XOR masking is not idempotent"
        );
    }

    // Skip frames with invalid configurations for codec testing
    let Some(frame) = fuzz_frame.to_frame() else {
        return;
    };

    // MR5: Control frames must be ≤125 bytes and have FIN=1
    if opcode.is_control() {
        if frame.payload.len() > 125 {
            // Large control frames should be rejected by codec
            let mut client_codec = FrameCodec::new(Role::Client, true);
            let mut server_codec = FrameCodec::new(Role::Server, true);
            let mut dst = BytesMut::new();

            // Both codecs should reject oversized control frames
            assert!(
                client_codec.encode(frame.clone(), &mut dst).is_err(),
                "Client codec should reject control frame >125 bytes"
            );
            assert!(
                server_codec.encode(frame.clone(), &mut dst).is_err(),
                "Server codec should reject control frame >125 bytes"
            );
            return;
        }

        if !frame.fin {
            // Fragmented control frames should be rejected by codec
            let mut client_codec = FrameCodec::new(Role::Client, true);
            let mut server_codec = FrameCodec::new(Role::Server, true);
            let mut dst = BytesMut::new();

            // Both codecs should reject fragmented control frames
            assert!(
                client_codec.encode(frame.clone(), &mut dst).is_err(),
                "Client codec should reject fragmented control frame"
            );
            assert!(
                server_codec.encode(frame.clone(), &mut dst).is_err(),
                "Server codec should reject fragmented control frame"
            );
            return;
        }
    }

    // MR2: Reserved RSV bits non-zero rejected unless extension negotiated
    if (frame.rsv1 || frame.rsv2 || frame.rsv3) {
        // With validate_reserved_bits=true, RSV bits should be rejected
        let mut server_codec = FrameCodec::new(Role::Server, true);
        let mut dst = BytesMut::new();

        // Encode a valid frame first, then decode with RSV bits set
        let mut valid_frame = frame.clone();
        valid_frame.rsv1 = false;
        valid_frame.rsv2 = false;
        valid_frame.rsv3 = false;
        valid_frame.masked = false; // Server receives unmasked frames

        if server_codec.encode(valid_frame, &mut dst).is_ok() {
            // Manually inject RSV bits into the encoded frame
            if !dst.is_empty() {
                let first_byte = dst[0];
                let with_rsv = first_byte
                    | (if frame.rsv1 { 0x40 } else { 0 })
                    | (if frame.rsv2 { 0x20 } else { 0 })
                    | (if frame.rsv3 { 0x10 } else { 0 });
                dst[0] = with_rsv;

                // Decoding should fail due to reserved bits
                let mut decode_codec = FrameCodec::new(Role::Server, true);
                assert!(
                    decode_codec.decode(&mut dst).is_err(),
                    "Decoder should reject frame with reserved bits set"
                );
            }
        }
        return;
    }

    // MR3: Unmasked client frames rejected by server
    if !frame.masked {
        let mut server_codec = FrameCodec::new(Role::Server, true);
        let mut dst = BytesMut::new();

        // Create client frame (unmasked from server perspective means it should be masked)
        let mut client_frame = frame.clone();
        client_frame.masked = false; // Simulate unmasked client frame

        // Try to encode and then decode from server perspective
        let mut client_codec = FrameCodec::new(Role::Client, true);
        if client_codec.encode(frame.clone(), &mut dst).is_ok() && !dst.is_empty() {
            // Manually clear the mask bit to simulate unmasked client frame
            dst[1] &= 0x7f; // Clear mask bit

            // Server should reject unmasked client frame
            assert!(
                server_codec.decode(&mut dst).is_err(),
                "Server should reject unmasked client frame"
            );
        }
        return;
    }

    // MR4: Fragmented messages with FIN=0 continue with opcode=0
    if !frame.fin && opcode.is_data() {
        // First fragment should have data opcode
        let mut server_codec = FrameCodec::new(Role::Server, true);
        let mut dst = BytesMut::new();

        let mut first_fragment = frame.clone();
        first_fragment.fin = false;
        first_fragment.masked = false; // Server receives unmasked

        if server_codec.encode(first_fragment, &mut dst).is_ok() {
            // Continuation frame should have opcode=0
            let mut continuation = Frame {
                fin: true, // End the sequence
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode: Opcode::Continuation,
                masked: false,
                mask_key: [0; 4],
                payload: Bytes::from(vec![1, 2, 3]), // Small payload
            };

            let mut dst2 = BytesMut::new();
            // Continuation frames with opcode=0 should be valid
            assert!(
                server_codec.encode(continuation, &mut dst2).is_ok(),
                "Continuation frame with opcode=0 should be valid"
            );
        }
    }

    // Basic round-trip test for valid frames
    let mut client_codec = FrameCodec::new(Role::Client, true);
    let mut server_codec = FrameCodec::new(Role::Server, true);
    let mut dst = BytesMut::new();

    // Client encodes (always masked)
    let mut client_frame = frame.clone();
    client_frame.masked = true;
    if let Ok(()) = client_codec.encode(client_frame, &mut dst) {
        // Server decodes
        if let Ok(Some(decoded)) = server_codec.decode(&mut dst) {
            // Payload should match after unmasking
            assert_eq!(
                decoded.payload.len(),
                frame.payload.len(),
                "Decoded payload length mismatch"
            );
            assert_eq!(decoded.opcode, frame.opcode, "Decoded opcode mismatch");
            assert_eq!(decoded.fin, frame.fin, "Decoded FIN bit mismatch");
        }
    }

    // Test server to client direction (unmasked)
    let mut dst2 = BytesMut::new();
    let mut server_frame = frame.clone();
    server_frame.masked = false;
    if let Ok(()) = server_codec.encode(server_frame, &mut dst2) {
        if let Ok(Some(decoded)) = client_codec.decode(&mut dst2) {
            assert_eq!(
                decoded.payload.len(),
                frame.payload.len(),
                "Server-to-client payload length mismatch"
            );
            assert_eq!(
                decoded.opcode, frame.opcode,
                "Server-to-client opcode mismatch"
            );
        }
    }
});
