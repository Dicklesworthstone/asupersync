    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use insta::assert_snapshot;

    fn render_wire_hex(label: &str, bytes: &[u8]) -> String {
        let mut out = String::new();
        out.push_str(label);
        out.push_str(":\n");
        for chunk in bytes.chunks(16) {
            let line = chunk
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&line);
            out.push('\n');
        }
        out
    }

    #[test]
    fn test_opcode_is_control() {
        assert!(!Opcode::Continuation.is_control());
        assert!(!Opcode::Text.is_control());
        assert!(!Opcode::Binary.is_control());
        assert!(Opcode::Close.is_control());
        assert!(Opcode::Ping.is_control());
        assert!(Opcode::Pong.is_control());
    }

    #[test]
    fn test_opcode_from_u8() {
        assert_eq!(Opcode::from_u8(0x0).unwrap(), Opcode::Continuation);
        assert_eq!(Opcode::from_u8(0x1).unwrap(), Opcode::Text);
        assert_eq!(Opcode::from_u8(0x2).unwrap(), Opcode::Binary);
        assert_eq!(Opcode::from_u8(0x8).unwrap(), Opcode::Close);
        assert_eq!(Opcode::from_u8(0x9).unwrap(), Opcode::Ping);
        assert_eq!(Opcode::from_u8(0xA).unwrap(), Opcode::Pong);
        assert!(Opcode::from_u8(0x3).is_err());
        assert!(Opcode::from_u8(0xF).is_err());
    }

    #[test]
    fn test_apply_mask() {
        let mask_key = [0x37, 0xfa, 0x21, 0x3d];
        let mut payload = b"Hello".to_vec();
        let original = payload.clone();

        apply_mask(&mut payload, mask_key);
        assert_ne!(payload, original);

        // Apply mask again to unmask
        apply_mask(&mut payload, mask_key);
        assert_eq!(payload, original);
    }

    #[test]
    fn test_encode_decode_text_frame() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::text("Hello, WebSocket!");

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        // Decode the frame (server decodes client-masked frames)
        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        assert!(parsed.fin);
        assert_eq!(parsed.opcode, Opcode::Text);
        assert_eq!(parsed.payload.as_ref(), b"Hello, WebSocket!");
    }

    #[test]
    fn test_encode_decode_binary_frame() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let payload: Bytes = vec![0x00, 0x01, 0x02, 0xFF].into();
        let frame = Frame::binary(payload.clone());

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        assert!(parsed.fin);
        assert_eq!(parsed.opcode, Opcode::Binary);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_encode_decode_ping_pong() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();

        // Ping
        let ping_request = Frame::ping("ping-data");
        let mut buf = BytesMut::new();
        encoder.encode(ping_request, &mut buf).unwrap();

        let ping_received = decoder.decode(&mut buf).unwrap().unwrap();
        assert!(ping_received.fin);
        assert_eq!(ping_received.opcode, Opcode::Ping);
        assert_eq!(ping_received.payload.as_ref(), b"ping-data");

        // Pong
        let pong_response = Frame::pong("pong-data");
        let mut buf = BytesMut::new();
        encoder.encode(pong_response, &mut buf).unwrap();

        let pong_response = decoder.decode(&mut buf).unwrap().unwrap();
        assert!(pong_response.fin);
        assert_eq!(pong_response.opcode, Opcode::Pong);
        assert_eq!(pong_response.payload.as_ref(), b"pong-data");
    }

    #[test]
    fn ping_pong_accept_max_control_payload() {
        let payload = Bytes::from(vec![0xA5; CONTROL_FRAME_MAX_PAYLOAD_LEN]);

        let ping = Frame::ping(payload.clone());
        assert_eq!(ping.opcode, Opcode::Ping);
        assert_eq!(ping.payload.len(), CONTROL_FRAME_MAX_PAYLOAD_LEN);
        assert_eq!(ping.payload, payload);

        let pong = Frame::pong(payload.clone());
        assert_eq!(pong.opcode, Opcode::Pong);
        assert_eq!(pong.payload.len(), CONTROL_FRAME_MAX_PAYLOAD_LEN);
        assert_eq!(pong.payload, payload);
    }

    #[test]
    #[should_panic(
        expected = "ping frame payload (126 bytes) exceeds 125-byte control frame limit"
    )]
    fn ping_rejects_oversized_control_payload() {
        let _ = Frame::ping(Bytes::from(vec![0u8; CONTROL_FRAME_MAX_PAYLOAD_LEN + 1]));
    }

    #[test]
    #[should_panic(
        expected = "pong frame payload (126 bytes) exceeds 125-byte control frame limit"
    )]
    fn pong_rejects_oversized_control_payload() {
        let _ = Frame::pong(Bytes::from(vec![0u8; CONTROL_FRAME_MAX_PAYLOAD_LEN + 1]));
    }

    #[test]
    fn test_encode_decode_close_frame() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let close = Frame::close(Some(1000), Some("goodbye"));

        let mut buf = BytesMut::new();
        encoder.encode(close, &mut buf).unwrap();

        let close_frame = decoder.decode(&mut buf).unwrap().unwrap();
        assert!(close_frame.fin);
        assert_eq!(close_frame.opcode, Opcode::Close);

        // Parse close payload
        let payload = close_frame.payload;
        assert!(payload.len() >= 2);
        let code = u16::from_be_bytes([payload[0], payload[1]]);
        assert_eq!(code, 1000);
        let reason = std::str::from_utf8(&payload[2..]).unwrap();
        assert_eq!(reason, "goodbye");
    }

    #[test]
    fn decoder_accepts_receive_only_close_code_range() {
        let mut server_decoder = FrameCodec::server();
        let mut masked_client_close =
            BytesMut::from(&[0x88, 0x82, 0x00, 0x00, 0x00, 0x00, 0x03, 0xf8][..]);

        let parsed = server_decoder
            .decode(&mut masked_client_close)
            .unwrap()
            .unwrap();

        assert_eq!(parsed.opcode, Opcode::Close);
        assert_eq!(parsed.payload.as_ref(), &1016u16.to_be_bytes());

        let mut client_decoder = FrameCodec::client();
        let mut unmasked_server_close = BytesMut::from(&[0x88, 0x02, 0x07, 0xd0][..]);

        let parsed = client_decoder
            .decode(&mut unmasked_server_close)
            .unwrap()
            .unwrap();

        assert_eq!(parsed.opcode, Opcode::Close);
        assert_eq!(parsed.payload.as_ref(), &2000u16.to_be_bytes());
    }

    #[test]
    fn test_payload_length_126() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::binary(Bytes::from(vec![0u8; 200])); // > 125, uses 2-byte length

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(parsed.payload.len(), 200);
    }

    #[test]
    fn test_payload_length_127() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::binary(Bytes::from(vec![0u8; 70_000])); // > 65535, uses 8-byte length

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(parsed.payload.len(), 70_000);
    }

    #[test]
    fn websocket_binary_length_prefix_boundaries_match_rfc6455() {
        let cases: &[(usize, &[u8])] = &[
            (0, &[0x82, 0x00]),
            (125, &[0x82, 0x7d]),
            (126, &[0x82, 0x7e, 0x00, 0x7e]),
            (65_535, &[0x82, 0x7e, 0xff, 0xff]),
            (65_536, &[0x82, 0x7f, 0, 0, 0, 0, 0, 1, 0, 0]),
        ];

        for &(payload_len, expected_prefix) in cases {
            let payload = vec![0x5a; payload_len];
            let mut encoded = BytesMut::new();

            FrameCodec::server()
                .encode(Frame::binary(Bytes::from(payload.clone())), &mut encoded)
                .unwrap();

            assert_eq!(
                &encoded[..expected_prefix.len()],
                expected_prefix,
                "RFC 6455 length prefix mismatch for payload length {payload_len}"
            );
            assert_eq!(encoded.len(), expected_prefix.len() + payload_len);
            assert_eq!(&encoded[expected_prefix.len()..], payload.as_slice());
        }
    }

    #[test]
    fn test_client_masking() {
        let mut client_codec = FrameCodec::client();
        let mut server_codec = FrameCodec::server();

        let frame = Frame::text("masked message");

        // Client encodes (with masking)
        let mut buf = BytesMut::new();
        client_codec.encode(frame, &mut buf).unwrap();

        // Check that the mask bit is set (second byte, high bit)
        assert!(buf[1] & 0x80 != 0);

        // Server decodes (unmasks)
        let parsed = server_codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(parsed.payload.as_ref(), b"masked message");
    }

    #[derive(Debug, Clone, Copy)]
    struct FixedEntropy([u8; 4]);

    impl EntropySource for FixedEntropy {
        fn fill_bytes(&self, dest: &mut [u8]) {
            for (idx, byte) in dest.iter_mut().enumerate() {
                *byte = self.0[idx % self.0.len()];
            }
        }

        fn next_u64(&self) -> u64 {
            u64::from_le_bytes([
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[0], self.0[1], self.0[2],
                self.0[3],
            ])
        }

        fn fork(&self, _task_id: crate::types::TaskId) -> std::sync::Arc<dyn EntropySource> {
            std::sync::Arc::new(*self)
        }

        fn source_id(&self) -> &'static str {
            "fixed"
        }
    }

    #[test]
    fn client_masking_uses_supplied_entropy_source() {
        let client_codec = FrameCodec::client();
        let mut server_codec = FrameCodec::server();
        let mut buf = BytesMut::new();
        let entropy = FixedEntropy([0x10, 0x20, 0x30, 0x40]);

        client_codec
            .encode_with_entropy(&Frame::text("mask-me"), &mut buf, &entropy)
            .unwrap();

        assert_eq!(&buf[2..6], &[0x10, 0x20, 0x30, 0x40]);

        let parsed = server_codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(parsed.payload.as_ref(), b"mask-me");
    }

    #[test]
    fn golden_websocket_frame_wire_bytes() {
        let mut snapshot = String::new();

        let mut server_text = BytesMut::new();
        FrameCodec::server()
            .encode(Frame::text("Hi"), &mut server_text)
            .unwrap();
        snapshot.push_str(&render_wire_hex("server_text_hi", &server_text));

        let mut client_text = BytesMut::new();
        FrameCodec::client()
            .encode_with_entropy(
                &Frame::text("Hi"),
                &mut client_text,
                &FixedEntropy([0x10, 0x20, 0x30, 0x40]),
            )
            .unwrap();
        snapshot.push_str(&render_wire_hex("client_text_hi_masked", &client_text));

        let mut close_frame = BytesMut::new();
        FrameCodec::server()
            .encode(Frame::close(Some(1000), Some("goodbye")), &mut close_frame)
            .unwrap();
        snapshot.push_str(&render_wire_hex("server_close_1000_goodbye", &close_frame));

        let extended_payload = Bytes::from((0u8..=125).collect::<Vec<_>>());
        let mut binary_len_126 = BytesMut::new();
        FrameCodec::server()
            .encode(Frame::binary(extended_payload), &mut binary_len_126)
            .unwrap();
        snapshot.push_str(&render_wire_hex("server_binary_len_126", &binary_len_126));

        assert_snapshot!(&snapshot, @r"
        server_text_hi:
        81 02 48 69
        client_text_hi_masked:
        81 82 10 20 30 40 58 49
        server_close_1000_goodbye:
        88 09 03 e8 67 6f 6f 64 62 79 65
        server_binary_len_126:
        82 7e 00 7e 00 01 02 03 04 05 06 07 08 09 0a 0b
        0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b
        1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b
        2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b
        3c 3d 3e 3f 40 41 42 43 44 45 46 47 48 49 4a 4b
        4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b
        5c 5d 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b
        6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 7b
        7c 7d
        "
        );
    }

    #[test]
    fn test_control_frame_too_large() {
        let mut codec = FrameCodec::server();
        let payload = Bytes::from(vec![0u8; 130]); // > 125 bytes
        let mut frame = Frame::ping(Bytes::new());
        frame.payload = payload;

        let mut buf = BytesMut::new();
        let result = codec.encode(frame, &mut buf);
        assert!(matches!(result, Err(WsError::ControlFrameTooLarge(_))));
    }

    #[test]
    fn test_fragmented_control_frame_rejected() {
        let mut codec = FrameCodec::server();
        let mut frame = Frame::ping("data");
        frame.fin = false; // Fragmented - invalid for control frames

        let mut buf = BytesMut::new();
        let result = codec.encode(frame, &mut buf);
        assert!(matches!(result, Err(WsError::FragmentedControlFrame)));
    }

    #[test]
    fn test_partial_frame_returns_none() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::text("Hello");

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        // Only provide partial data
        let partial = buf.split_to(3);
        let mut partial = BytesMut::from(partial.as_ref());

        // Should return None (need more data)
        assert!(decoder.decode(&mut partial).unwrap().is_none());
    }

    #[test]
    fn decode_masked_extended_length_frame_across_chunks() {
        let mut decoder = FrameCodec::server();
        let mask_key = [0x11, 0x22, 0x33, 0x44];
        let payload = vec![0x5a; 126];
        let mut masked_payload = payload.clone();
        apply_mask(&mut masked_payload, mask_key);

        let mut wire = BytesMut::new();
        wire.put_u8(0x82); // FIN=1, opcode=Binary.
        wire.put_u8(0x80 | 0x7e); // MASK=1, 16-bit extended length follows.
        wire.put_u16(payload.len() as u16);
        wire.put_slice(&mask_key);
        wire.put_slice(&masked_payload);

        let mut incoming = BytesMut::new();
        incoming.put_slice(&wire[..2]);
        assert!(decoder.decode(&mut incoming).unwrap().is_none());
        assert!(incoming.is_empty());

        incoming.put_slice(&wire[2..4]);
        assert!(decoder.decode(&mut incoming).unwrap().is_none());
        assert!(incoming.is_empty());

        incoming.put_slice(&wire[4..8]);
        assert!(decoder.decode(&mut incoming).unwrap().is_none());
        assert!(incoming.is_empty());

        incoming.put_slice(&wire[8..wire.len() - 1]);
        assert!(decoder.decode(&mut incoming).unwrap().is_none());
        assert_eq!(incoming.len(), payload.len() - 1);

        incoming.put_u8(wire[wire.len() - 1]);
        let parsed = decoder.decode(&mut incoming).unwrap().unwrap();

        assert!(incoming.is_empty());
        assert!(parsed.fin);
        assert!(parsed.masked);
        assert_eq!(parsed.mask_key, Some(mask_key));
        assert_eq!(parsed.opcode, Opcode::Binary);
        assert_eq!(parsed.payload.as_ref(), payload.as_slice());
    }

    #[test]
    fn test_empty_payload() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::binary(Bytes::new());

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn test_close_code_is_sendable() {
        assert!(CloseCode::Normal.is_sendable());
        assert!(CloseCode::GoingAway.is_sendable());
        assert!(CloseCode::ProtocolError.is_sendable());
        assert!(CloseCode::ServiceRestart.is_sendable());
        assert!(CloseCode::TryAgainLater.is_sendable());
        assert!(CloseCode::BadGateway.is_sendable());
        assert!(!CloseCode::Reserved.is_sendable());
        assert!(!CloseCode::NoStatusReceived.is_sendable());
        assert!(!CloseCode::Abnormal.is_sendable());
        assert!(!CloseCode::TlsHandshake.is_sendable());
    }

    #[test]
    fn test_close_code_from_u16_iana_registered() {
        assert_eq!(CloseCode::from_u16(1012), Some(CloseCode::ServiceRestart));
        assert_eq!(CloseCode::from_u16(1013), Some(CloseCode::TryAgainLater));
        assert_eq!(CloseCode::from_u16(1014), Some(CloseCode::BadGateway));
    }

    #[test]
    fn test_is_valid_code_iana_registered() {
        assert!(CloseCode::is_valid_code(1012));
        assert!(CloseCode::is_valid_code(1013));
        assert!(CloseCode::is_valid_code(1014));
    }

    #[test]
    fn test_invalid_opcode_from_u8() {
        // Reserved non-control opcodes.
        for &op in &[0x03, 0x04, 0x05, 0x06, 0x07] {
            let result = Opcode::from_u8(op);
            assert!(matches!(result, Err(WsError::InvalidOpcode(v)) if v == op));
        }
        // Reserved control opcodes.
        for &op in &[0x0B, 0x0C, 0x0D, 0x0E, 0x0F] {
            let result = Opcode::from_u8(op);
            assert!(matches!(result, Err(WsError::InvalidOpcode(v)) if v == op));
        }
    }

    #[test]
    fn test_opcode_is_data() {
        assert!(Opcode::Text.is_data());
        assert!(Opcode::Binary.is_data());
        assert!(Opcode::Continuation.is_data());
        assert!(!Opcode::Close.is_data());
        assert!(!Opcode::Ping.is_data());
        assert!(!Opcode::Pong.is_data());
    }

    #[test]
    fn test_close_frame_with_code_and_reason() {
        let frame = Frame::close(Some(1000), Some("goodbye"));
        assert_eq!(frame.opcode, Opcode::Close);
        assert!(frame.fin);
        // Payload: 2 bytes (u16 code) + "goodbye" (7 bytes) = 9
        assert_eq!(frame.payload.len(), 9);
        assert_eq!(&frame.payload[..2], &1000u16.to_be_bytes());
        assert_eq!(&frame.payload[2..], b"goodbye");
    }

    #[test]
    fn test_close_frame_code_only() {
        let frame = Frame::close(Some(1001), None);
        assert_eq!(frame.payload.len(), 2);
        assert_eq!(&frame.payload[..], &1001u16.to_be_bytes());
    }

    #[test]
    fn test_close_frame_no_payload() {
        let frame = Frame::close(None, None);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn test_ws_error_display_variants() {
        let err = WsError::InvalidOpcode(0x0F);
        assert!(err.to_string().contains("0xF"));

        let err = WsError::ReservedBitsSet;
        assert!(err.to_string().contains("reserved bits"));

        let err = WsError::PayloadTooLarge {
            size: 10_000,
            max: 1024,
        };
        assert!(err.to_string().contains("10000"));
        assert!(err.to_string().contains("1024"));

        let err = WsError::ControlFrameTooLarge(200);
        assert!(err.to_string().contains("200"));

        let err = WsError::FragmentedControlFrame;
        assert!(err.to_string().contains("fragmented"));

        let err = WsError::UnmaskedClientFrame;
        assert!(err.to_string().contains("masked"));

        let err = WsError::InvalidUtf8;
        assert!(err.to_string().contains("UTF-8"));

        let err = WsError::InvalidClosePayload;
        assert!(err.to_string().contains("close"));
    }

    #[test]
    fn test_roundtrip_server_to_client() {
        // Server sends unmasked; client decodes unmasked frames.
        let mut encoder = FrameCodec::server();
        let mut decoder = FrameCodec::client();
        let frame = Frame::text("server says hi");

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(parsed.opcode, Opcode::Text);
        assert!(!parsed.masked);
        assert_eq!(parsed.payload.as_ref(), b"server says hi");
    }

    #[test]
    fn test_decode_reserved_bits_rejected() {
        // Craft raw wire bytes with RSV1 set — must be rejected per RFC 6455 §5.2.
        let mut codec = FrameCodec::client();
        let mut buf = BytesMut::new();
        // FIN=1, RSV1=1, opcode=Text → 0xC1; MASK=0, len=5 → 0x05
        buf.put_u8(0xC1);
        buf.put_u8(0x05);
        buf.put_slice(b"Hello");

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(WsError::ReservedBitsSet)));
    }

    #[test]
    fn test_decode_unmasked_client_frame_rejected() {
        // Server codec must reject unmasked frames from client (RFC 6455 §5.1).
        let mut codec = FrameCodec::server();
        let mut buf = BytesMut::new();
        // FIN=1, opcode=Text → 0x81; MASK=0, len=5 → 0x05 (missing mask!)
        buf.put_u8(0x81);
        buf.put_u8(0x05);
        buf.put_slice(b"Hello");

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(WsError::UnmaskedClientFrame)));
    }

    #[test]
    fn test_decode_masked_server_frame_rejected() {
        // Client codec must reject masked frames from server (RFC 6455 §5.1).
        let mut codec = FrameCodec::client();
        let mask_key = [0x37, 0xfa, 0x21, 0x3d];
        let mut payload = b"Hello".to_vec();
        apply_mask(&mut payload, mask_key);

        let mut buf = BytesMut::new();
        // FIN=1, opcode=Text → 0x81; MASK=1, len=5 → 0x85.
        buf.put_u8(0x81);
        buf.put_u8(0x80 | payload.len() as u8);
        buf.put_slice(&mask_key);
        buf.put_slice(&payload);

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(WsError::MaskedServerFrame)));
    }

    #[test]
    fn test_decode_fragmented_control_rejected() {
        // Control frames must not be fragmented (FIN must be set, RFC 6455 §5.5).
        let mut codec = FrameCodec::client();
        let mut buf = BytesMut::new();
        // FIN=0, opcode=Ping → 0x09; MASK=0, len=4 → 0x04
        buf.put_u8(0x09);
        buf.put_u8(0x04);
        buf.put_slice(b"ping");

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(WsError::FragmentedControlFrame)));
    }

    #[test]
    fn test_decode_control_frame_extended_length_rejected() {
        // Control frames cannot use extended length encoding (payload > 125, RFC 6455 §5.5).
        let mut codec = FrameCodec::client();
        let mut buf = BytesMut::new();
        // FIN=1, opcode=Ping → 0x89; MASK=0, len=126 (2-byte extended) → 0x7E
        buf.put_u8(0x89);
        buf.put_u8(0x7E);
        // Extended length bytes (would indicate 200 bytes)
        buf.put_u16(200);

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(WsError::ControlFrameTooLarge(_))));
    }

    #[test]
    fn test_decode_multiple_frames_single_buffer() {
        // Verify the state machine correctly resets between frames in a streaming buffer.
        let mut encoder = FrameCodec::server();
        let mut decoder = FrameCodec::client();

        let mut buf = BytesMut::new();
        encoder.encode(Frame::text("first"), &mut buf).unwrap();
        encoder
            .encode(Frame::binary(Bytes::from("second")), &mut buf)
            .unwrap();

        let frame1 = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame1.opcode, Opcode::Text);
        assert_eq!(frame1.payload.as_ref(), b"first");

        let frame2 = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame2.opcode, Opcode::Binary);
        assert_eq!(frame2.payload.as_ref(), b"second");

        // Buffer exhausted
        assert!(decoder.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn test_close_frame_reason_without_code_fails_closed() {
        // Regression: do not silently synthesize Normal (1000) when callers
        // omit the code. That rewrites the protocol meaning of the close.
        let frame = Frame::close(None, Some("going away"));
        assert_eq!(frame.opcode, Opcode::Close);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn test_decode_non_minimal_2byte_length_rejected() {
        // RFC 6455 §5.2: 2-byte extended length must encode values >= 126.
        // A value < 126 in the 2-byte form is a protocol violation.
        let mut codec = FrameCodec::client();
        let mut buf = BytesMut::new();
        // FIN=1, opcode=Binary → 0x82; MASK=0, len_indicator=126 → 0x7E
        buf.put_u8(0x82);
        buf.put_u8(0x7E);
        // Extended length = 100 (non-minimal: should use 7-bit form)
        buf.put_u16(100);
        buf.put_slice(&[0u8; 100]);

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(WsError::ProtocolViolation(_))));
    }

    #[test]
    fn test_decode_non_minimal_8byte_length_rejected() {
        // RFC 6455 §5.2: 8-byte extended length must encode values >= 65536.
        let mut codec = FrameCodec::client();
        let mut buf = BytesMut::new();
        // FIN=1, opcode=Binary → 0x82; MASK=0, len_indicator=127 → 0x7F
        buf.put_u8(0x82);
        buf.put_u8(0x7F);
        // Extended length = 200 (non-minimal: should use 2-byte form)
        buf.put_u64(200);
        buf.put_slice(&[0u8; 200]);

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(WsError::ProtocolViolation(_))));
    }

    #[test]
    fn test_decode_8byte_length_msb_set_rejected() {
        // RFC 6455 §5.2: most significant bit of 64-bit length MUST be 0.
        let mut codec = FrameCodec::client().max_payload_size(usize::MAX); // disable size limit for this test
        let mut buf = BytesMut::new();
        // FIN=1, opcode=Binary → 0x82; MASK=0, len_indicator=127 → 0x7F
        buf.put_u8(0x82);
        buf.put_u8(0x7F);
        // 64-bit length with MSB set
        buf.put_u64(0x8000_0000_0000_0100);

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(WsError::ProtocolViolation(_))));
    }

    #[test]
    fn test_decode_valid_2byte_length_accepted() {
        // Ensure valid 2-byte lengths (>= 126) still decode correctly.
        let mut encoder = FrameCodec::server();
        let mut decoder = FrameCodec::client();
        let payload = Bytes::from(vec![0xABu8; 126]); // exactly 126 — uses 2-byte form
        let frame = Frame::binary(payload);

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(parsed.payload.len(), 126);
    }

    // =========================================================================
    // Audit regression tests (asupersync-10x0x.47)
    // =========================================================================

    #[test]
    fn decode_close_frame_1byte_payload_rejected() {
        // RFC 6455 §5.5.1: Close frame body must be empty or start with a
        // 2-byte status code. A 1-byte body is a protocol violation.
        let mut codec = FrameCodec::client();
        let mut buf = BytesMut::new();
        // FIN=1, opcode=Close → 0x88; MASK=0, len=1 → 0x01
        buf.put_u8(0x88);
        buf.put_u8(0x01);
        buf.put_u8(0xFF); // single invalid byte

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(WsError::InvalidClosePayload)));
    }

    #[test]
    fn decode_close_frame_empty_payload_accepted() {
        // Close frame with no body is valid per RFC 6455 §5.5.1.
        let mut codec = FrameCodec::client();
        let mut buf = BytesMut::new();
        // FIN=1, opcode=Close → 0x88; MASK=0, len=0 → 0x00
        buf.put_u8(0x88);
        buf.put_u8(0x00);

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.opcode, Opcode::Close);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn decode_close_frame_2byte_payload_accepted() {
        // Close frame with exactly 2 bytes (status code only) is valid.
        let mut codec = FrameCodec::client();
        let mut buf = BytesMut::new();
        // FIN=1, opcode=Close → 0x88; MASK=0, len=2 → 0x02
        buf.put_u8(0x88);
        buf.put_u8(0x02);
        buf.put_u16(1000); // Normal close

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.opcode, Opcode::Close);
        assert_eq!(frame.payload.len(), 2);
    }

    #[test]
    fn decode_close_frame_invalid_code_rejected() {
        let mut codec = FrameCodec::client();
        let mut buf = BytesMut::new();
        // FIN=1, opcode=Close → 0x88; MASK=0, len=2 → 0x02
        buf.put_u8(0x88);
        buf.put_u8(0x02);
        buf.put_u16(1005); // MUST NOT appear on the wire

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(WsError::InvalidClosePayload)));
    }

    #[test]
    fn decode_close_frame_invalid_code_poisons_codec() {
        let mut codec = FrameCodec::client();
        let mut buf = BytesMut::new();

        // First: invalid close frame (code 1005 must not appear on wire)
        buf.put_u8(0x88); // FIN=1, opcode=Close
        buf.put_u8(0x02); // MASK=0, len=2
        buf.put_u16(1005);

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(WsError::InvalidClosePayload)));

        // Second: valid text frame — codec is poisoned after any error,
        // so it must reject all subsequent decode attempts.
        buf.put_u8(0x81); // FIN=1, opcode=Text
        buf.put_u8(0x05); // MASK=0, len=5
        buf.put_slice(b"hello");

        let result2 = codec.decode(&mut buf);
        assert!(
            matches!(&result2, Err(WsError::ProtocolViolation(msg)) if msg.contains("poisoned")),
            "codec must be poisoned after close validation error, got: {result2:?}"
        );
    }

    #[test]
    fn decode_close_frame_invalid_utf8_reason_rejected() {
        let mut codec = FrameCodec::client();
        let mut buf = BytesMut::new();
        // FIN=1, opcode=Close → 0x88; MASK=0, len=4 → 0x04
        buf.put_u8(0x88);
        buf.put_u8(0x04);
        buf.put_u16(1000);
        buf.put_slice(&[0xF0, 0x28]); // malformed UTF-8 prefix

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(WsError::InvalidClosePayload)));
    }

    #[test]
    fn decode_close_frame_custom_code_with_utf8_reason_accepted() {
        let mut codec = FrameCodec::client();
        let reason = "custom";
        let mut buf = BytesMut::new();
        // FIN=1, opcode=Close → 0x88; MASK=0, len=8 → 0x08
        buf.put_u8(0x88);
        buf.put_u8((2 + reason.len()) as u8);
        buf.put_u16(4000);
        buf.put_slice(reason.as_bytes());

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.opcode, Opcode::Close);
        assert_eq!(frame.payload.len(), 2 + reason.len());
        assert_eq!(
            u16::from_be_bytes([frame.payload[0], frame.payload[1]]),
            4000
        );
        assert_eq!(&frame.payload[2..], reason.as_bytes());
    }

    #[test]
    fn encode_manual_close_frame_invalid_code_rejected() {
        let mut codec = FrameCodec::server();
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Close,
            masked: false,
            mask_key: None,
            payload: {
                let mut payload = BytesMut::with_capacity(2);
                payload.put_u16(1005);
                payload.freeze()
            },
        };

        let result = codec.encode(frame, &mut BytesMut::new());
        assert!(matches!(result, Err(WsError::InvalidClosePayload)));
    }

    #[test]
    fn encode_manual_close_frame_invalid_utf8_reason_rejected() {
        let mut codec = FrameCodec::server();
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Close,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(&[0x03, 0xE8, 0xF0, 0x28]),
        };

        let result = codec.encode(frame, &mut BytesMut::new());
        assert!(matches!(result, Err(WsError::InvalidClosePayload)));
    }

    #[test]
    fn encode_manual_close_frame_one_byte_payload_rejected() {
        let mut codec = FrameCodec::server();
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Close,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(&[0xFF]),
        };

        let result = codec.encode(frame, &mut BytesMut::new());
        assert!(matches!(result, Err(WsError::InvalidClosePayload)));
    }

    #[test]
    fn encode_manual_close_frame_receive_only_code_rejected() {
        // Codes 1016-2999 are valid for receiving but must not be sent
        let mut codec = FrameCodec::server();
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Close,
            masked: false,
            mask_key: None,
            payload: {
                let mut payload = BytesMut::with_capacity(2);
                payload.put_u16(1016); // receive-only code
                payload.freeze()
            },
        };

        let result = codec.encode(frame, &mut BytesMut::new());
        assert!(matches!(result, Err(WsError::InvalidClosePayload)));
    }

    #[test]
    #[should_panic(expected = "is not valid for use in a Close frame")]
    fn close_frame_code_1005_panics() {
        // RFC 6455 §7.4.1: 1005 (No Status Received) MUST NOT be set as a
        // status code in a Close control frame by an endpoint.
        let _ = Frame::close(Some(1005), None);
    }

    #[test]
    #[should_panic(expected = "is not valid for use in a Close frame")]
    fn close_frame_code_1006_panics() {
        // RFC 6455 §7.4.1: 1006 (Abnormal Closure) MUST NOT be set as a
        // status code in a Close control frame by an endpoint.
        let _ = Frame::close(Some(1006), None);
    }

    #[test]
    #[should_panic(expected = "is not valid for use in a Close frame")]
    fn close_frame_code_1015_panics() {
        // RFC 6455 §7.4.1: 1015 (TLS Handshake) MUST NOT be set as a
        // status code in a Close control frame by an endpoint.
        let _ = Frame::close(Some(1015), None);
    }

    #[test]
    #[should_panic(expected = "is not valid for use in a Close frame")]
    fn close_frame_code_1004_panics() {
        // RFC 6455 §7.4.1: 1004 is reserved and MUST NOT be sent.
        let _ = Frame::close(Some(1004), None);
    }

    #[test]
    #[should_panic(expected = "is not valid for use in a Close frame")]
    fn close_frame_unassigned_received_only_code_panics() {
        // RFC 6455 §7.4.2: 1016-2999 may be accepted when received, but
        // endpoints implementing this spec must not send them.
        let _ = Frame::close(Some(1016), None);
    }

    #[test]
    fn received_close_code_1015_rejected() {
        // RFC 6455 §7.4.1: 1015 is reserved for TLS layer only —
        // must never appear on the wire, even when receiving.
        assert!(!CloseCode::is_valid_received_code(1015));
    }

    #[test]
    fn received_close_code_unassigned_accepted() {
        // RFC 6455 §7.4.2: codes 1016-2999 are reserved for future
        // WebSocket revisions/extensions and must be accepted.
        assert!(CloseCode::is_valid_received_code(1016));
        assert!(CloseCode::is_valid_received_code(2000));
        assert!(CloseCode::is_valid_received_code(2999));
    }

    #[test]
    fn close_frame_iana_registered_codes_accepted() {
        // 1012, 1013, 1014 are IANA-registered close codes and must be accepted.
        let _ = Frame::close(Some(1012), None);
        let _ = Frame::close(Some(1013), None);
        let _ = Frame::close(Some(1014), None);
    }

    #[test]
    fn close_frame_valid_codes_accepted() {
        // Verify that commonly used close codes don't panic.
        let _ = Frame::close(Some(1000), Some("normal"));
        let _ = Frame::close(Some(1001), None);
        let _ = Frame::close(Some(1002), None);
        let _ = Frame::close(Some(1003), None);
        let _ = Frame::close(Some(1007), None);
        let _ = Frame::close(Some(1008), None);
        let _ = Frame::close(Some(1009), None);
        let _ = Frame::close(Some(1010), None);
        let _ = Frame::close(Some(1011), None);
        // Application-defined codes
        let _ = Frame::close(Some(4000), Some("app error"));
    }

    #[test]
    fn payload_too_large_rejected_in_7bit_path() {
        // Verify DoS protection: payload size exceeding max is rejected
        // even in the 7-bit length path.
        let mut codec = FrameCodec::client().max_payload_size(50);
        let mut buf = BytesMut::new();
        // FIN=1, opcode=Binary → 0x82; MASK=0, len=100 → 0x64
        buf.put_u8(0x82);
        buf.put_u8(100);
        buf.put_slice(&[0u8; 100]);

        let result = codec.decode(&mut buf);
        assert!(matches!(
            result,
            Err(WsError::PayloadTooLarge { size: 100, max: 50 })
        ));
    }

    #[test]
    fn mask_involution_empty_payload() {
        // Masking an empty payload should be a no-op.
        let mut payload = Vec::new();
        apply_mask(&mut payload, [0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(payload.is_empty());
    }

    #[test]
    fn mask_involution_all_key_bytes_exercised() {
        // Verify all 4 bytes of the mask key are used for payloads >= 4 bytes.
        let mask_key = [0x11, 0x22, 0x33, 0x44];
        let mut payload = vec![0x00; 5]; // 5 bytes exercises all 4 key positions + wrap
        apply_mask(&mut payload, mask_key);
        assert_eq!(payload, vec![0x11, 0x22, 0x33, 0x44, 0x11]);

        // Applying again should restore zeros.
        apply_mask(&mut payload, mask_key);
        assert_eq!(payload, vec![0x00; 5]);
    }

    #[test]
    fn codec_is_poisoned_after_decode_error() {
        // After a decode error, the codec should enter the Poisoned state
        // and reject all future frames.
        let mut codec = FrameCodec::client();

        // First: trigger a reserved-bits error.
        let mut bad_buf = BytesMut::new();
        bad_buf.put_u8(0xC1); // RSV1 set
        bad_buf.put_u8(0x05);
        bad_buf.put_slice(b"Hello");
        let err = codec.decode(&mut bad_buf);
        assert!(matches!(err, Err(WsError::ReservedBitsSet)));

        // Second: feed a valid frame — codec should reject it because it's poisoned.
        let mut good_buf = BytesMut::new();
        good_buf.put_u8(0x81);
        good_buf.put_u8(0x02);
        good_buf.put_slice(b"OK");
        let err2 = codec.decode(&mut good_buf);
        assert!(matches!(err2, Err(WsError::ProtocolViolation(msg)) if msg.contains("poisoned")));
    }

    // =========================================================================
    // Wave 56 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn opcode_debug_clone_copy_hash_eq() {
        use std::collections::HashSet;
        let op = Opcode::Text;
        let dbg = format!("{op:?}");
        assert!(dbg.contains("Text"), "{dbg}");
        let copied = op;
        let cloned = op;
        assert_eq!(copied, cloned);

        let mut set = HashSet::new();
        set.insert(Opcode::Text);
        set.insert(Opcode::Binary);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Opcode::Text));
    }

    #[test]
    fn frame_debug_clone() {
        let f = Frame::text("hello");
        let dbg = format!("{f:?}");
        assert!(dbg.contains("Frame"), "{dbg}");
        let cloned = f;
        assert_eq!(cloned.opcode, Opcode::Text);
    }

    #[test]
    fn role_debug_clone_copy_eq() {
        let r = Role::Client;
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Client"), "{dbg}");
        let copied = r;
        let cloned = r;
        assert_eq!(copied, cloned);
        assert_ne!(r, Role::Server);
    }

    #[test]
    fn close_code_debug_clone_copy_eq() {
        let c = CloseCode::Normal;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Normal"), "{dbg}");
        let copied = c;
        let cloned = c;
        assert_eq!(copied, cloned);
        assert_ne!(c, CloseCode::GoingAway);
    }
