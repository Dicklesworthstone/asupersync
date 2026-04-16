#![no_main]

use libfuzzer_sys::fuzz_target;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::net::websocket::{FrameCodec, Role, Opcode, apply_mask};

fuzz_target!(|data: &[u8]| {
    // Fuzz target for WebSocket frame parsing according to RFC 6455.
    //
    // This fuzzer tests the core parsing logic that processes raw bytes into
    // structured WebSocket frames, exercising:
    // - Header parsing (FIN, RSV, opcode, mask, length)
    // - Extended length encoding (2-byte and 8-byte forms)
    // - Payload extraction and unmasking
    // - Protocol validation (reserved bits, control frame rules, etc.)
    // - Error handling for malformed frames
    //
    // Target: Pattern 1 (Crash Detector) - raw bytes → parser
    // Oracle: Crash detection + protocol validation invariants
    // Skip empty input and overly large inputs to focus fuzzing time
    if data.is_empty() || data.len() > 100_000 {
        return;
    }

    // Test both client and server role codecs since they have different
    // masking validation rules (RFC 6455 §5.1)
    let roles = [Role::Client, Role::Server];

    for &role in &roles {
        // Test with different max payload sizes to exercise size limits
        for &max_size in &[1024, 65536, 1024 * 1024] {
            let mut sized_codec = FrameCodec::new(role).max_payload_size(max_size);

            // Clone input data since decode() mutates the buffer
            let mut buf = BytesMut::from(data);

            // Attempt to decode - should never panic, only return Ok/Err
            let result = sized_codec.decode(&mut buf);

            // Invariants that must hold regardless of input:
            match result {
                Ok(Some(frame)) => {
                    // Decoded frame must satisfy protocol invariants

                    // Control frames must have FIN=true (RFC 6455 §5.5)
                    if frame.opcode.is_control() {
                        assert!(frame.fin, "control frame must have FIN=true");
                        assert!(frame.payload.len() <= 125, "control frame payload > 125 bytes");
                    }

                    // Reserved bits must be clear unless extensions are negotiated
                    // (we don't support extensions, so they must always be false)
                    // Note: FrameCodec validates this internally, so if we get a frame,
                    // reserved bits are already validated per codec configuration

                    // Mask key must be present iff masked flag is set
                    assert_eq!(frame.mask_key.is_some(), frame.masked,
                              "mask_key presence must match masked flag");

                    // Validate masking rules based on role (RFC 6455 §5.1)
                    match role {
                        Role::Server => {
                            // Server decodes client frames, which must be masked
                            assert!(frame.masked, "client frames must be masked");
                        }
                        Role::Client => {
                            // Client decodes server frames, which must not be masked
                            assert!(!frame.masked, "server frames must not be masked");
                        }
                    }

                    // Payload length must not exceed configured maximum
                    assert!(frame.payload.len() <= max_size,
                           "payload exceeds configured maximum");
                }
                Ok(None) => {
                    // Incomplete frame - need more data, which is valid
                }
                Err(_) => {
                    // Parse error - also valid for malformed input
                }
            }
        }

        // Test apply_mask function with fuzzed data
        if data.len() >= 4 {
            let mask_key = [data[0], data[1], data[2], data[3]];
            let payload_data = &data[4..];

            if payload_data.len() <= 1000 {  // Reasonable size limit
                let mut payload = payload_data.to_vec();
                let original = payload.clone();

                // Masking should be involutive: mask(mask(x)) == x
                apply_mask(&mut payload, mask_key);
                apply_mask(&mut payload, mask_key);

                assert_eq!(payload, original, "masking must be involutive");
            }
        }
    }

    // Test opcode parsing
    if !data.is_empty() {
        let opcode_byte = data[0] & 0x0F; // Extract opcode nibble
        let _ = Opcode::from_u8(opcode_byte); // Should never panic
    }

    // Close payload validation is tested indirectly through the decode path
    // when the codec encounters Close frames
});