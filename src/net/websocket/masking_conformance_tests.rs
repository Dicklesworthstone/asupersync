#![allow(clippy::all)]
//! WebSocket masking-key conformance tests (RFC 6455 §5.3).
//!
//! This module provides comprehensive golden tests validating the WebSocket
//! masking requirements defined in RFC 6455 Section 5.3.
//!
//! # RFC 6455 Section 5.3 Requirements
//!
//! ## Client-to-Server Masking (MUST)
//! - All frames sent by client MUST have mask bit set (bit 1 of second byte)
//! - All frames sent by client MUST include 32-bit masking-key
//! - Masking-key MUST be derived from strong source of entropy
//! - Each frame MUST use fresh unpredictable masking-key
//!
//! ## Server-to-Client Masking (MUST NOT)
//! - All frames sent by server MUST NOT be masked
//! - Server MUST reject masked frames from client with 1002 Protocol Error
//! - Server MUST close connection if client sends unmasked frame
//!
//! ## Masking Algorithm (RFC 6455 §5.3)
//! ```text
//! j = i MOD 4
//! transformed-octet-i = original-octet-i XOR masking-key-octet-j
//! ```
//!
//! ## Control Frame Masking
//! - Ping, Pong, Close frames follow same masking rules as data frames
//! - Client control frames MUST be masked
//! - Server control frames MUST NOT be masked
//!
//! # Test Coverage
//!
//! - ✅ Client data frames (Text, Binary) have mask bit + key
//! - ✅ Client control frames (Ping, Pong, Close) have mask bit + key
//! - ✅ Server frames are unmasked
//! - ✅ Server rejects unmasked client frames with Protocol Error
//! - ✅ Server rejects masked server frames in client codec
//! - ✅ Masking algorithm XOR correctness
//! - ✅ Mask key entropy requirements (unpredictable, fresh)
//! - ✅ Round-trip masking preserves payload integrity

#[cfg(test)]
mod tests {
    use super::super::frame::{Frame, FrameCodec, Opcode, WsError};
    use crate::bytes::{Bytes, BytesMut};
    use crate::codec::{Decoder, Encoder};
    use crate::util::EntropySource;

    /// Mock entropy source for deterministic testing of masking behavior.
    #[derive(Debug)]
    struct DeterministicEntropy {
        sequence: [u8; 16],
        counter: std::sync::atomic::AtomicUsize,
    }

    impl Clone for DeterministicEntropy {
        fn clone(&self) -> Self {
            Self {
                sequence: self.sequence,
                counter: std::sync::atomic::AtomicUsize::new(
                    self.counter.load(std::sync::atomic::Ordering::Relaxed),
                ),
            }
        }
    }

    impl DeterministicEntropy {
        fn new(seed: u64) -> Self {
            let mut sequence = [0u8; 16];
            for (i, byte) in sequence.iter_mut().enumerate() {
                *byte = ((seed ^ (i as u64)) & 0xFF) as u8;
            }
            Self {
                sequence,
                counter: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn next_key(&self) -> [u8; 4] {
            let idx = self
                .counter
                .fetch_add(4, std::sync::atomic::Ordering::Relaxed)
                % 16;
            [
                self.sequence[idx],
                self.sequence[(idx + 1) % 16],
                self.sequence[(idx + 2) % 16],
                self.sequence[(idx + 3) % 16],
            ]
        }
    }

    impl EntropySource for DeterministicEntropy {
        fn fill_bytes(&self, dest: &mut [u8]) {
            for (i, byte) in dest.iter_mut().enumerate() {
                let idx = (self.counter.load(std::sync::atomic::Ordering::Relaxed) + i) % 16;
                *byte = self.sequence[idx];
            }
            self.counter
                .fetch_add(dest.len(), std::sync::atomic::Ordering::Relaxed);
        }

        fn next_u64(&self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fork(&self, _task_id: crate::types::TaskId) -> std::sync::Arc<dyn EntropySource> {
            std::sync::Arc::new(self.clone())
        }

        fn source_id(&self) -> &'static str {
            "deterministic"
        }
    }

    /// Helper to extract mask key from encoded frame buffer.
    fn extract_mask_key(encoded: &[u8]) -> Option<[u8; 4]> {
        if encoded.len() < 2 {
            return None;
        }

        let second_byte = encoded[1];
        let masked = (second_byte & 0x80) != 0;
        if !masked {
            return None;
        }

        let payload_len_7 = second_byte & 0x7F;
        let mask_offset = match payload_len_7 {
            0..=125 => 2,
            126 => 4,  // 2 + 2 extended length bytes
            127 => 10, // 2 + 8 extended length bytes
            _ => return None,
        };

        if encoded.len() < mask_offset + 4 {
            return None;
        }

        Some([
            encoded[mask_offset],
            encoded[mask_offset + 1],
            encoded[mask_offset + 2],
            encoded[mask_offset + 3],
        ])
    }

    /// Helper to check if frame has mask bit set.
    fn has_mask_bit(encoded: &[u8]) -> bool {
        encoded.len() >= 2 && (encoded[1] & 0x80) != 0
    }

    // =========================================================================
    // RFC 6455 §5.3 - Client Masking Requirements
    // =========================================================================

    #[test]
    fn client_text_frame_must_be_masked() {
        // RFC 6455 §5.3: All frames sent from client to server are masked.
        let mut codec = FrameCodec::client();
        let frame = Frame::text("Hello, WebSocket!");
        let mut buf = BytesMut::new();

        codec.encode(frame, &mut buf).unwrap();

        // Verify mask bit is set (second byte, bit 7)
        assert!(has_mask_bit(&buf), "Client text frame missing mask bit");

        // Verify masking-key is present (4 bytes after length)
        let mask_key = extract_mask_key(&buf);
        assert!(mask_key.is_some(), "Client text frame missing masking-key");

        // Verify payload is actually masked (different from original)
        let payload_start = if buf[1] & 0x7F <= 125 { 6 } else { 8 }; // 2 header + 4 mask
        let masked_payload = &buf[payload_start..];
        assert_ne!(masked_payload, b"Hello, WebSocket!", "Payload not masked");
    }

    #[test]
    fn client_binary_frame_must_be_masked() {
        // RFC 6455 §5.3: Binary frames also require masking from client.
        let mut codec = FrameCodec::client();
        let original = vec![0x00, 0x01, 0x02, 0xFF, 0xAA, 0xBB];
        let frame = Frame::binary(Bytes::copy_from_slice(&original));
        let mut buf = BytesMut::new();

        codec.encode(frame, &mut buf).unwrap();

        assert!(has_mask_bit(&buf), "Client binary frame missing mask bit");
        assert!(
            extract_mask_key(&buf).is_some(),
            "Client binary frame missing masking-key"
        );

        // Verify payload is masked
        let payload_start = 6; // 2 header + 4 mask key for len <= 125
        let masked_payload = &buf[payload_start..];
        assert_ne!(masked_payload, &original, "Binary payload not masked");
    }

    #[test]
    fn client_ping_frame_must_be_masked() {
        // RFC 6455 §5.3: Control frames (Ping) must also be masked by client.
        let mut codec = FrameCodec::client();
        let frame = Frame::ping("ping-test");
        let mut buf = BytesMut::new();

        codec.encode(frame, &mut buf).unwrap();

        assert!(has_mask_bit(&buf), "Client ping frame missing mask bit");
        assert!(
            extract_mask_key(&buf).is_some(),
            "Client ping frame missing masking-key"
        );

        // Decode and verify opcode is preserved
        let mut server_codec = FrameCodec::server();
        let mut decode_buf = BytesMut::from(buf.as_ref());
        let decoded = server_codec.decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded.opcode, Opcode::Ping);
        assert_eq!(decoded.payload.as_ref(), b"ping-test");
    }

    #[test]
    fn client_pong_frame_must_be_masked() {
        // RFC 6455 §5.3: Control frames (Pong) must also be masked by client.
        let mut codec = FrameCodec::client();
        let frame = Frame::pong("pong-response");
        let mut buf = BytesMut::new();

        codec.encode(frame, &mut buf).unwrap();

        assert!(has_mask_bit(&buf), "Client pong frame missing mask bit");
        assert!(
            extract_mask_key(&buf).is_some(),
            "Client pong frame missing masking-key"
        );
    }

    #[test]
    fn client_close_frame_must_be_masked() {
        // RFC 6455 §5.3: Control frames (Close) must also be masked by client.
        let mut codec = FrameCodec::client();
        let frame = Frame::close(Some(1000), Some("goodbye"));
        let mut buf = BytesMut::new();

        codec.encode(frame, &mut buf).unwrap();

        assert!(has_mask_bit(&buf), "Client close frame missing mask bit");
        assert!(
            extract_mask_key(&buf).is_some(),
            "Client close frame missing masking-key"
        );

        // Verify close frame decodes correctly
        let mut server_codec = FrameCodec::server();
        let mut decode_buf = BytesMut::from(buf.as_ref());
        let decoded = server_codec.decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded.opcode, Opcode::Close);

        // Verify close payload (code + reason)
        let payload = decoded.payload;
        assert!(payload.len() >= 2);
        let code = u16::from_be_bytes([payload[0], payload[1]]);
        assert_eq!(code, 1000);
        let reason = std::str::from_utf8(&payload[2..]).unwrap();
        assert_eq!(reason, "goodbye");
    }

    // =========================================================================
    // RFC 6455 §5.1 - Server Unmasked Requirements
    // =========================================================================

    #[test]
    fn server_frames_must_not_be_masked() {
        // RFC 6455 §5.1: Server MUST NOT mask frames sent to client.
        let mut codec = FrameCodec::server();
        let frames = [
            Frame::text("server message"),
            Frame::binary(vec![1, 2, 3, 4]),
            Frame::ping("server ping"),
            Frame::pong("server pong"),
            Frame::close(Some(1000), Some("server close")),
        ];

        for frame in &frames {
            let mut buf = BytesMut::new();
            codec.encode(frame.clone(), &mut buf).unwrap();

            // Verify mask bit is NOT set
            assert!(
                !has_mask_bit(&buf),
                "Server frame incorrectly masked: {frame:?}"
            );

            // Verify no masking-key present
            assert_eq!(
                extract_mask_key(&buf),
                None,
                "Server frame has unexpected masking-key: {frame:?}"
            );
        }
    }

    #[test]
    fn server_rejects_unmasked_client_frames() {
        // RFC 6455 §5.1: Server MUST close connection if client sends unmasked frame.
        let mut server_codec = FrameCodec::server();

        // Craft unmasked text frame from "client"
        let mut buf = BytesMut::new();
        buf.put_u8(0x81); // FIN=1, opcode=Text
        buf.put_u8(0x05); // MASK=0, len=5 (unmasked!)
        buf.put_slice(b"hello");

        let result = server_codec.decode(&mut buf);
        assert!(
            matches!(result, Err(WsError::UnmaskedClientFrame)),
            "Server must reject unmasked client frame, got: {result:?}"
        );
    }

    #[test]
    fn client_rejects_masked_server_frames() {
        // RFC 6455 §5.1: Client should reject masked frames from server.
        let mut client_codec = FrameCodec::client();

        // Craft masked text frame from "server"
        let mut buf = BytesMut::new();
        buf.put_u8(0x81); // FIN=1, opcode=Text
        buf.put_u8(0x85); // MASK=1, len=5 (incorrectly masked!)
        buf.put_slice(&[0x12, 0x34, 0x56, 0x78]); // fake mask key
        buf.put_slice(b"hello"); // payload (would be masked)

        let result = client_codec.decode(&mut buf);
        assert!(
            matches!(result, Err(WsError::MaskedServerFrame)),
            "Client must reject masked server frame, got: {result:?}"
        );
    }

    // =========================================================================
    // RFC 6455 §5.3 - Masking Algorithm Correctness
    // =========================================================================

    #[test]
    fn masking_algorithm_xor_correctness() {
        // RFC 6455 §5.3: transformed-octet-i = original-octet-i XOR masking-key-octet-(i MOD 4)
        let original = b"WebSocket masking test with longer payload to exercise all key positions!";
        let mask_key = [0x37, 0xFA, 0x21, 0x3D];

        // Apply masking manually per RFC algorithm
        let mut expected_masked = original.to_vec();
        for (i, byte) in expected_masked.iter_mut().enumerate() {
            *byte ^= mask_key[i % 4];
        }

        // Use frame codec with fixed entropy to get predictable mask key
        let entropy = DeterministicEntropy::new(0x123456789ABCDEF0);
        // Ensure deterministic entropy produces our expected key
        let _generated_key = entropy.next_key();
        let entropy_with_target_key = DeterministicEntropy {
            sequence: [
                0x37, 0xFA, 0x21, 0x3D, 0x37, 0xFA, 0x21, 0x3D, 0x37, 0xFA, 0x21, 0x3D, 0x37, 0xFA,
                0x21, 0x3D,
            ],
            counter: std::sync::atomic::AtomicUsize::new(0),
        };

        let codec = FrameCodec::client();
        let frame = Frame::text(std::str::from_utf8(original).unwrap());
        let mut buf = BytesMut::new();

        codec
            .encode_with_entropy(&frame, &mut buf, &entropy_with_target_key)
            .unwrap();

        // Extract actual mask key from encoded frame
        let actual_key = extract_mask_key(&buf).unwrap();
        assert_eq!(actual_key, mask_key, "Mask key mismatch");

        // Extract masked payload and verify it matches RFC algorithm
        let payload_start = 6; // 2 header + 4 mask key
        let actual_masked = &buf[payload_start..];
        assert_eq!(
            actual_masked, &expected_masked,
            "Masked payload doesn't match RFC 6455 algorithm"
        );

        // Verify unmasking restores original
        let mut server_codec = FrameCodec::server();
        let mut decode_buf = BytesMut::from(buf.as_ref());
        let decoded = server_codec.decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(
            decoded.payload.as_ref(),
            original,
            "Unmasking failed to restore original"
        );
    }

    #[test]
    fn masking_involution_property() {
        // RFC 6455 §5.3: Masking is its own inverse (involution property).
        // Applying mask twice should restore original payload.
        use super::super::frame::apply_mask;

        let test_cases = [
            b"" as &[u8],                          // Empty payload
            b"A",                                  // Single byte
            b"AB",                                 // Two bytes
            b"ABC",                                // Three bytes
            b"ABCD",                               // Four bytes (one mask cycle)
            b"ABCDE",                              // Five bytes (wrap around)
            b"Hello, WebSocket world!",            // Typical message
            &[0x00, 0xFF, 0x80, 0x7F, 0x55, 0xAA], // Binary data
        ];

        let mask_key = [0x12, 0x34, 0x56, 0x78];

        for &original in &test_cases {
            let mut payload = original.to_vec();
            let backup = payload.clone();

            // Apply mask
            apply_mask(&mut payload, mask_key);

            // For non-empty payloads, verify it changed
            if !original.is_empty() {
                assert_ne!(payload, backup, "Masking should change non-empty payload");
            }

            // Apply mask again - should restore original
            apply_mask(&mut payload, mask_key);
            assert_eq!(
                payload, backup,
                "Double masking should restore original for: {original:?}"
            );
        }
    }

    // =========================================================================
    // RFC 6455 §5.3 - Entropy and Unpredictability Requirements
    // =========================================================================

    #[test]
    fn client_uses_fresh_mask_keys() {
        // RFC 6455 §5.3: Each frame MUST use fresh unpredictable masking-key.
        let mut codec = FrameCodec::client();
        let mut used_keys = std::collections::HashSet::new();

        // Generate multiple frames and verify each uses different mask key
        for i in 0..20 {
            let frame = Frame::text(format!("message {i}"));
            let mut buf = BytesMut::new();
            codec.encode(frame, &mut buf).unwrap();

            let mask_key = extract_mask_key(&buf).expect("Frame should have mask key");
            assert!(
                used_keys.insert(mask_key),
                "Mask key reused: {mask_key:?} (frame {i})"
            );
        }

        assert_eq!(used_keys.len(), 20, "All mask keys should be unique");
    }

    #[test]
    fn mask_keys_have_sufficient_entropy() {
        // RFC 6455 §5.3: Masking keys must be derived from strong source of entropy.
        let mut codec = FrameCodec::client();
        let mut key_bytes = Vec::new();

        // Collect mask key bytes from multiple frames
        for i in 0..100 {
            let frame = Frame::binary(vec![i as u8; 10]);
            let mut buf = BytesMut::new();
            codec.encode(frame, &mut buf).unwrap();

            let mask_key = extract_mask_key(&buf).expect("Frame should have mask key");
            key_bytes.extend_from_slice(&mask_key);
        }

        // Basic entropy check: each byte value should appear
        let mut byte_counts = [0; 256];
        for &byte in &key_bytes {
            byte_counts[byte as usize] += 1;
        }

        // Count how many different byte values we see
        let unique_bytes = byte_counts.iter().filter(|&&count| count > 0).count();

        // With 400 random bytes (100 frames * 4 bytes), we expect good coverage
        assert!(
            unique_bytes >= 200, // At least 78% of possible byte values
            "Poor entropy in mask keys: only {unique_bytes}/256 byte values seen"
        );
    }

    // =========================================================================
    // RFC 6455 §5.3 - Round-trip Integrity Tests
    // =========================================================================

    #[test]
    fn client_server_roundtrip_preserves_payload() {
        // Comprehensive test: client encodes with masking, server decodes.
        let mut client_codec = FrameCodec::client();
        let mut server_codec = FrameCodec::server();

        let large_text = "A".repeat(1000);
        let test_payloads = vec![
            // Text frames
            (String::new(), Opcode::Text),
            ("Hello".to_string(), Opcode::Text),
            (
                "WebSocket test with special chars: üñíçødé".to_string(),
                Opcode::Text,
            ),
            (large_text, Opcode::Text), // Large text
            // Binary frames
            (String::new(), Opcode::Binary),
            // Need to use a separate binary test below for actual binary data
        ];

        let binary_payloads = [
            vec![],                       // Empty
            vec![0x00, 0x01, 0x02, 0xFF], // Binary data
            vec![0x00; 500],              // Large binary
        ];

        // Test text payloads
        for (payload, opcode) in &test_payloads {
            let frame = Frame::text(payload.clone());

            // Client encodes (with masking)
            let mut buf = BytesMut::new();
            client_codec.encode(frame.clone(), &mut buf).unwrap();

            // Verify masking applied
            assert!(has_mask_bit(&buf), "Client frame should be masked");

            // Server decodes (unmasking)
            let decoded = server_codec.decode(&mut buf).unwrap().unwrap();

            // Verify payload integrity
            assert_eq!(
                decoded.opcode, *opcode,
                "Opcode mismatch for payload: {payload:?}"
            );
            assert_eq!(
                decoded.payload.as_ref(),
                payload.as_bytes(),
                "Payload mismatch for: {payload:?}"
            );
            assert!(
                decoded.masked,
                "Decoded frame should indicate it was masked"
            );
            assert!(
                decoded.mask_key.is_some(),
                "Decoded frame should have mask key"
            );
        }

        // Test binary payloads separately
        for payload_data in &binary_payloads {
            let frame = Frame::binary(payload_data.clone());

            // Client encodes (with masking)
            let mut buf = BytesMut::new();
            client_codec.encode(frame.clone(), &mut buf).unwrap();

            // Verify masking applied
            assert!(has_mask_bit(&buf), "Client frame should be masked");

            // Server decodes (unmasking)
            let decoded = server_codec.decode(&mut buf).unwrap().unwrap();

            // Verify payload integrity
            assert_eq!(
                decoded.opcode,
                Opcode::Binary,
                "Opcode mismatch for binary payload"
            );
            assert_eq!(
                decoded.payload.as_ref(),
                payload_data.as_slice(),
                "Binary payload mismatch"
            );
            assert!(
                decoded.masked,
                "Decoded frame should indicate it was masked"
            );
            assert!(
                decoded.mask_key.is_some(),
                "Decoded frame should have mask key"
            );
        }
    }

    #[test]
    fn server_client_roundtrip_no_masking() {
        // Server sends unmasked, client receives unmasked.
        let mut server_codec = FrameCodec::server();
        let mut client_codec = FrameCodec::client();

        let frames = [
            Frame::text("server to client"),
            Frame::binary(Vec::from(&b"binary data"[..])),
            Frame::ping("ping from server"),
            Frame::pong("pong from server"),
        ];

        for frame in &frames {
            // Server encodes (no masking)
            let mut buf = BytesMut::new();
            server_codec.encode(frame.clone(), &mut buf).unwrap();

            // Verify no masking
            assert!(!has_mask_bit(&buf), "Server frame should not be masked");

            // Client decodes
            let decoded = client_codec.decode(&mut buf).unwrap().unwrap();

            // Verify integrity
            assert_eq!(decoded.opcode, frame.opcode);
            assert_eq!(decoded.payload, frame.payload);
            assert!(
                !decoded.masked,
                "Server frame should not be marked as masked"
            );
            assert_eq!(
                decoded.mask_key, None,
                "Server frame should have no mask key"
            );
        }
    }

    // =========================================================================
    // RFC 6455 §5.3 - Edge Cases and Error Conditions
    // =========================================================================

    #[test]
    fn masking_empty_payload() {
        // RFC 6455 §5.3: Masking algorithm should handle empty payloads correctly.
        let mut codec = FrameCodec::client();
        let frame = Frame::text("");
        let mut buf = BytesMut::new();

        codec.encode(frame, &mut buf).unwrap();

        // Even empty frames must have mask bit and key
        assert!(has_mask_bit(&buf), "Empty frame should still have mask bit");
        assert!(
            extract_mask_key(&buf).is_some(),
            "Empty frame should still have mask key"
        );

        // Decode and verify
        let mut server_codec = FrameCodec::server();
        let decoded = server_codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.payload.len(), 0);
        assert!(decoded.masked);
    }

    #[test]
    fn masking_large_payload() {
        // RFC 6455 §5.3: Masking should work correctly for large payloads.
        let payload_size = 70_000; // Forces 8-byte length encoding
        let large_payload = "X".repeat(payload_size);

        let mut client_codec = FrameCodec::client();
        let frame = Frame::text(large_payload.clone());
        let mut buf = BytesMut::new();

        client_codec.encode(frame, &mut buf).unwrap();

        // Verify masking applied to large frame
        assert!(has_mask_bit(&buf), "Large frame should be masked");

        // Server decode (this exercises large buffer unmasking)
        let mut server_codec = FrameCodec::server();
        let decoded = server_codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.payload.len(), payload_size);
        assert_eq!(decoded.payload.as_ref(), large_payload.as_bytes());
        assert!(decoded.masked);
    }

    #[test]
    fn control_frame_masking_with_max_payload() {
        // RFC 6455 §5.5: Control frames can have up to 125 bytes.
        // Verify masking works correctly at this boundary.
        let max_control_payload = "A".repeat(125);

        let mut client_codec = FrameCodec::client();
        let frame = Frame::ping(max_control_payload.clone());
        let mut buf = BytesMut::new();

        client_codec.encode(frame, &mut buf).unwrap();

        assert!(
            has_mask_bit(&buf),
            "Max-size control frame should be masked"
        );

        let mut server_codec = FrameCodec::server();
        let decoded = server_codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.opcode, Opcode::Ping);
        assert_eq!(decoded.payload.len(), 125);
        assert_eq!(decoded.payload.as_ref(), max_control_payload.as_bytes());
        assert!(decoded.masked);
    }

    // =========================================================================
    // RFC 6455 §7.4.1 - Close Frame Error Code Tests
    // =========================================================================

    #[test]
    fn server_close_for_unmasked_frame_uses_protocol_error() {
        // RFC 6455 §7.4.1: When server closes due to protocol violation,
        // it should use close code 1002 (Protocol Error).
        let err = WsError::UnmaskedClientFrame;
        let close_code = err.as_close_code();

        // WsError::as_close_code() should map to Protocol Error
        use super::super::frame::CloseCode;
        assert_eq!(close_code as u16, CloseCode::ProtocolError as u16);
    }

    #[test]
    fn protocol_error_close_code_is_valid() {
        // Verify that Protocol Error (1002) is a valid close code to send.
        use super::super::frame::CloseCode;

        assert!(CloseCode::ProtocolError.is_sendable());
        assert!(CloseCode::is_valid_code(CloseCode::ProtocolError as u16));

        // Server can send this code when closing due to protocol violation
        let close_frame = Frame::close(Some(1002), Some("Protocol Error"));
        assert_eq!(close_frame.opcode, Opcode::Close);
    }

    // =========================================================================
    // Golden Test Vector Validation
    // =========================================================================

    #[test]
    fn rfc_6455_example_masking_vector() {
        // Test vector from RFC 6455 §5.7 example
        // Original: "Hello" (0x48656c6c6f)
        // Mask: 0x37fa213d
        // Masked: 0x7f9f4d5158
        use super::super::frame::apply_mask;

        let mut payload = b"Hello".to_vec();
        let mask_key = [0x37, 0xfa, 0x21, 0x3d];

        apply_mask(&mut payload, mask_key);

        // Expected masked result per RFC
        let expected_masked = [0x7f, 0x9f, 0x4d, 0x51, 0x58];
        assert_eq!(payload, expected_masked, "RFC 6455 test vector failed");

        // Verify unmasking restores original
        apply_mask(&mut payload, mask_key);
        assert_eq!(payload, b"Hello");
    }

    #[test]
    fn comprehensive_masking_conformance_validation() {
        // Final validation: ensure all RFC 6455 §5.3 requirements are met
        let mut client = FrameCodec::client();
        let mut server = FrameCodec::server();

        // Test all frame types from client (must be masked)
        let client_frames = [
            Frame::text("client text"),
            Frame::binary(Vec::from(&b"client binary"[..])),
            Frame::ping("client ping"),
            Frame::pong("client pong"),
            Frame::close(Some(1000), Some("client close")),
        ];

        for frame in &client_frames {
            let mut buf = BytesMut::new();
            client.encode(frame.clone(), &mut buf).unwrap();

            // RFC 6455 §5.3 requirements:
            assert!(
                has_mask_bit(&buf),
                "❌ Client frame missing mask bit: {frame:?}"
            );
            assert!(
                extract_mask_key(&buf).is_some(),
                "❌ Client frame missing mask key: {frame:?}"
            );

            // Server must decode successfully
            let mut decode_buf = BytesMut::from(buf.as_ref());
            let decoded = server.decode(&mut decode_buf).unwrap().unwrap();
            assert_eq!(
                decoded.opcode, frame.opcode,
                "❌ Opcode mismatch: {frame:?}"
            );
            assert_eq!(
                decoded.payload, frame.payload,
                "❌ Payload mismatch: {frame:?}"
            );
        }

        // Test all frame types from server (must NOT be masked)
        let server_frames = [
            Frame::text("server text"),
            Frame::binary(Vec::from(&b"server binary"[..])),
            Frame::ping("server ping"),
            Frame::pong("server pong"),
            Frame::close(Some(1000), Some("server close")),
        ];

        for frame in &server_frames {
            let mut buf = BytesMut::new();
            server.encode(frame.clone(), &mut buf).unwrap();

            // RFC 6455 §5.1 requirements:
            assert!(
                !has_mask_bit(&buf),
                "❌ Server frame incorrectly masked: {frame:?}"
            );
            assert_eq!(
                extract_mask_key(&buf),
                None,
                "❌ Server frame has mask key: {frame:?}"
            );

            // Client must decode successfully
            let mut client_decoder = FrameCodec::client();
            let mut decode_buf = BytesMut::from(buf.as_ref());
            let decoded = client_decoder.decode(&mut decode_buf).unwrap().unwrap();
            assert_eq!(
                decoded.opcode, frame.opcode,
                "❌ Opcode mismatch: {frame:?}"
            );
            assert_eq!(
                decoded.payload, frame.payload,
                "❌ Payload mismatch: {frame:?}"
            );
        }
    }
}
