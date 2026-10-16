    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn close_reason_parse_empty() {
        let reason = CloseReason::parse(&[]).unwrap();
        assert_eq!(reason.code, None);
        assert_eq!(reason.raw_code, None);
        assert_eq!(reason.text, None);
    }

    #[test]
    fn close_reason_parse_code_only() {
        let payload = 1000u16.to_be_bytes();
        let reason = CloseReason::parse(&payload).unwrap();
        assert_eq!(reason.code, Some(CloseCode::Normal));
        assert_eq!(reason.raw_code, Some(1000));
        assert_eq!(reason.text, None);
    }

    #[test]
    fn close_reason_parse_code_and_text() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1001u16.to_be_bytes());
        payload.extend_from_slice(b"Going away");

        let reason = CloseReason::parse(&payload).unwrap();
        assert_eq!(reason.code, Some(CloseCode::GoingAway));
        assert_eq!(reason.raw_code, Some(1001));
        assert_eq!(reason.text.as_deref(), Some("Going away"));
    }

    #[test]
    fn close_reason_parse_accepts_max_payload() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000u16.to_be_bytes());
        payload.resize(MAX_CLOSE_PAYLOAD_BYTES, b'a');

        let reason = CloseReason::parse(&payload).unwrap();
        assert_eq!(reason.code, Some(CloseCode::Normal));
        assert_eq!(
            reason.text.as_deref().map(str::len),
            Some(MAX_CLOSE_PAYLOAD_BYTES - CLOSE_CODE_BYTES)
        );
    }

    #[test]
    fn close_reason_parse_rejects_oversized_payload() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000u16.to_be_bytes());
        payload.resize(MAX_CLOSE_PAYLOAD_BYTES + 1, b'a');

        let result = CloseReason::parse(&payload);
        assert!(matches!(result, Err(WsError::InvalidClosePayload)));
    }

    #[test]
    fn close_reason_parse_custom_code_preserves_raw_code() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&3001u16.to_be_bytes());
        payload.extend_from_slice(b"custom");

        let reason = CloseReason::parse(&payload).unwrap();
        assert_eq!(reason.code, None);
        assert_eq!(reason.raw_code, Some(3001));
        assert_eq!(reason.wire_code(), Some(3001));
        assert_eq!(reason.text.as_deref(), Some("custom"));
    }

    #[test]
    fn close_reason_parse_invalid_single_byte() {
        let result = CloseReason::parse(&[0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn close_reason_parse_invalid_utf8() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000u16.to_be_bytes());
        payload.extend_from_slice(&[0xFF, 0xFE]); // Invalid UTF-8

        let result = CloseReason::parse(&payload);
        assert!(result.is_err());
    }

    #[test]
    fn cancellation_reason_uses_the_configured_sendable_code() {
        // br-asupersync-y6naky: CloseConfig::cancellation_code was
        // stored but never sent; cancellation always closed with GoingAway.
        let default = CloseHandshake::new().cancellation_reason();
        assert_eq!(default.code, Some(CloseCode::GoingAway));
        let restart = CloseHandshake::with_config(
            CloseConfig::new().with_cancellation_code(CloseCode::ServiceRestart),
        );
        let restart = restart.cancellation_reason();
        assert_eq!(restart.code, Some(CloseCode::ServiceRestart));
        let reserved = CloseHandshake::with_config(
            CloseConfig::new().with_cancellation_code(CloseCode::Abnormal),
        );
        assert_eq!(
            reserved.cancellation_reason().code,
            Some(CloseCode::GoingAway),
            "a code that may not be sent falls back to GoingAway"
        );
    }

    #[test]
    fn close_reason_parse_invalid_reserved_code() {
        let payload = 1004u16.to_be_bytes();
        let result = CloseReason::parse(&payload);
        assert!(matches!(result, Err(WsError::InvalidClosePayload)));
    }

    #[test]
    fn close_reason_parse_unassigned_code_accepted() {
        // 1016 is unassigned — RFC 6455 §7.4.2 requires endpoints to accept them
        let payload = 1016u16.to_be_bytes();
        let result = CloseReason::parse(&payload).unwrap();
        assert_eq!(result.code, None);
        assert_eq!(result.raw_code, Some(1016));
    }

    #[test]
    fn close_reason_parse_iana_registered_1012_accepted() {
        let payload = 1012u16.to_be_bytes();
        let result = CloseReason::parse(&payload);
        assert!(result.is_ok(), "IANA-registered code 1012 must parse");
    }

    #[test]
    fn close_reason_encode_empty() {
        let reason = CloseReason::empty();
        let encoded = reason.encode();
        assert!(encoded.is_empty());
    }

    #[test]
    fn close_reason_encode_code_only() {
        let reason = CloseReason::new(CloseCode::Normal, None);
        let encoded = reason.encode();
        assert_eq!(encoded.as_ref(), &1000u16.to_be_bytes());
    }

    #[test]
    fn close_reason_encode_code_and_text() {
        let reason = CloseReason::with_text(CloseCode::GoingAway, "bye");
        let encoded = reason.encode();

        let mut expected = Vec::new();
        expected.extend_from_slice(&1001u16.to_be_bytes());
        expected.extend_from_slice(b"bye");

        assert_eq!(encoded.as_ref(), expected.as_slice());
    }

    #[test]
    fn close_reason_encode_keeps_max_length_text() {
        let text = "a".repeat(MAX_CLOSE_PAYLOAD_BYTES - CLOSE_CODE_BYTES);
        let reason = CloseReason::with_text(CloseCode::Normal, &text);

        let encoded = reason.encode();
        let frame = reason.to_frame();

        assert_eq!(encoded.len(), MAX_CLOSE_PAYLOAD_BYTES);
        assert_eq!(frame.payload.len(), MAX_CLOSE_PAYLOAD_BYTES);
        assert_eq!(&encoded[..CLOSE_CODE_BYTES], &1000u16.to_be_bytes());
        assert_eq!(&encoded[CLOSE_CODE_BYTES..], text.as_bytes());
    }

    #[test]
    fn close_reason_encode_counts_limit_in_utf8_bytes() {
        let multibyte = "\u{20ac}";
        let text = multibyte.repeat((MAX_CLOSE_PAYLOAD_BYTES - CLOSE_CODE_BYTES) / multibyte.len());
        let reason = CloseReason::with_text(CloseCode::Normal, &text);

        let encoded = reason.encode();
        let frame = reason.to_frame();

        assert_eq!(text.len(), MAX_CLOSE_PAYLOAD_BYTES - CLOSE_CODE_BYTES);
        assert_eq!(encoded.len(), MAX_CLOSE_PAYLOAD_BYTES);
        assert_eq!(frame.payload.len(), MAX_CLOSE_PAYLOAD_BYTES);
        assert_eq!(&encoded[..CLOSE_CODE_BYTES], &1000u16.to_be_bytes());
        assert_eq!(&encoded[CLOSE_CODE_BYTES..], text.as_bytes());
    }

    #[test]
    fn close_reason_encode_drops_overlong_text_without_panicking() {
        let text = "a".repeat(MAX_CLOSE_PAYLOAD_BYTES - CLOSE_CODE_BYTES + 1);
        let reason = CloseReason::with_text(CloseCode::Normal, &text);

        let encoded = reason.encode();
        let frame = reason.to_frame();

        assert_eq!(encoded.as_ref(), &1000u16.to_be_bytes());
        assert_eq!(frame.payload.as_ref(), &1000u16.to_be_bytes());
    }

    #[test]
    fn close_reason_encode_drops_overlong_multibyte_text() {
        let multibyte = "\u{20ac}";
        let text =
            multibyte.repeat((MAX_CLOSE_PAYLOAD_BYTES - CLOSE_CODE_BYTES) / multibyte.len() + 1);
        let reason = CloseReason::with_text(CloseCode::Normal, &text);

        let encoded = reason.encode();
        let frame = reason.to_frame();

        assert!(text.len() > MAX_CLOSE_PAYLOAD_BYTES - CLOSE_CODE_BYTES);
        assert_eq!(encoded.as_ref(), &1000u16.to_be_bytes());
        assert_eq!(frame.payload.as_ref(), &1000u16.to_be_bytes());
    }

    #[test]
    fn close_reason_roundtrip() {
        let original = CloseReason::with_text(CloseCode::Normal, "goodbye");
        let encoded = original.encode();
        let parsed = CloseReason::parse(&encoded).unwrap();

        assert_eq!(original.code, parsed.code);
        assert_eq!(original.raw_code, parsed.raw_code);
        assert_eq!(original.text, parsed.text);
    }

    #[test]
    fn close_reason_encode_and_frame_payload_are_equivalent() {
        let overlong_text = "a".repeat(MAX_CLOSE_PAYLOAD_BYTES - CLOSE_CODE_BYTES + 1);
        let cases = [
            ("empty", CloseReason::empty()),
            ("normal", CloseReason::normal()),
            (
                "normal with text",
                CloseReason::with_text(CloseCode::Normal, "goodbye"),
            ),
            (
                "custom sendable",
                CloseReason::parse(&3001u16.to_be_bytes()).unwrap(),
            ),
            (
                "receive-only unassigned",
                CloseReason::parse(&2000u16.to_be_bytes()).unwrap(),
            ),
            (
                "text without code",
                CloseReason {
                    code: None,
                    raw_code: None,
                    text: Some("ignored".to_string()),
                },
            ),
            (
                "overlong text",
                CloseReason::with_text(CloseCode::Normal, &overlong_text),
            ),
        ];

        for (case, reason) in cases {
            let encoded = reason.encode();
            let frame = reason.to_frame();

            assert_eq!(frame.opcode, Opcode::Close, "{case}");
            assert_eq!(encoded.as_ref(), frame.payload.as_ref(), "{case}");
        }
    }

    #[test]
    fn close_reason_unsendable_received_code_encodes_as_empty_close() {
        let payload = 2000u16.to_be_bytes();
        let reason = CloseReason::parse(&payload).unwrap();

        assert_eq!(reason.raw_code, Some(2000));
        assert!(reason.encode().is_empty());
        assert!(reason.to_frame().payload.is_empty());
    }

    #[test]
    fn close_reason_without_code_drops_text_on_encode() {
        let reason = CloseReason {
            code: None,
            raw_code: None,
            text: Some("text without code".to_string()),
        };

        assert!(reason.encode().is_empty());
        assert!(reason.to_frame().payload.is_empty());
    }

    #[test]
    fn close_code_valid_ranges() {
        assert!(CloseCode::is_valid_code(1000));
        assert!(CloseCode::is_valid_code(1003));
        assert!(CloseCode::is_valid_code(1007));
        assert!(CloseCode::is_valid_code(1011));
        assert!(CloseCode::is_valid_code(3000));
        assert!(CloseCode::is_valid_code(4999));

        assert!(!CloseCode::is_valid_code(1004)); // Reserved
        assert!(!CloseCode::is_valid_code(1005)); // NoStatusReceived
        assert!(!CloseCode::is_valid_code(1006)); // Abnormal
        assert!(!CloseCode::is_valid_code(999)); // Below valid range
        assert!(!CloseCode::is_valid_code(5000)); // Above valid range
    }

    #[test]
    fn close_state_transitions() {
        assert!(CloseState::Open.is_open());
        assert!(!CloseState::Open.is_closed());
        assert!(!CloseState::Open.is_closing());

        assert!(!CloseState::CloseSent.is_open());
        assert!(!CloseState::CloseSent.is_closed());
        assert!(CloseState::CloseSent.is_closing());

        assert!(!CloseState::Closed.is_open());
        assert!(CloseState::Closed.is_closed());
        assert!(!CloseState::Closed.is_closing());
    }

    #[test]
    fn handshake_initiate_from_open() {
        let mut handshake = CloseHandshake::new();
        let frame = handshake.initiate(CloseReason::normal());

        assert!(frame.is_some());
        assert_eq!(handshake.state(), CloseState::CloseSent);
        assert!(handshake.our_reason().is_some());
    }

    #[test]
    fn handshake_initiate_when_already_closing() {
        let mut handshake = CloseHandshake::new();
        handshake.initiate(CloseReason::normal());

        // Second initiate should return None
        let frame = handshake.initiate(CloseReason::normal());
        assert!(frame.is_none());
    }

    #[test]
    fn handshake_receive_close_from_open() {
        let mut handshake = CloseHandshake::new();
        let close_frame = Frame::close(Some(1000), Some("bye"));

        let response = handshake.receive_close(&close_frame).unwrap();

        assert!(response.is_some());
        assert_eq!(handshake.state(), CloseState::CloseReceived);
        assert!(handshake.peer_reason().is_some());
    }

    #[test]
    fn handshake_receive_close_echoes_custom_code() {
        let mut handshake = CloseHandshake::new();
        let close_frame = Frame::close(Some(3001), Some("custom"));

        let response = handshake.receive_close(&close_frame).unwrap().unwrap();
        assert_eq!(response.opcode, Opcode::Close);
        assert_eq!(&response.payload[..2], &3001u16.to_be_bytes());
        assert_eq!(handshake.peer_reason().unwrap().wire_code(), Some(3001));
        assert_eq!(handshake.state(), CloseState::CloseReceived);
    }

    #[test]
    fn handshake_receive_close_rejects_rfc6455_tls_handshake_code_1015() {
        let mut handshake = CloseHandshake::new();
        let close_frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Close,
            masked: false,
            mask_key: None,
            payload: Bytes::copy_from_slice(&1015u16.to_be_bytes()),
        };

        let err = handshake.receive_close(&close_frame).unwrap_err();
        assert!(matches!(err, WsError::InvalidClosePayload));
        assert_eq!(handshake.state(), CloseState::Open);
        assert!(handshake.peer_reason().is_none());
    }

    #[test]
    fn handshake_receive_empty_close_keeps_response_payload_empty() {
        let mut handshake = CloseHandshake::new();
        let close_frame = Frame::close(None, None);

        let response = handshake.receive_close(&close_frame).unwrap().unwrap();

        assert_eq!(response.opcode, Opcode::Close);
        assert!(response.payload.is_empty());
        assert_eq!(handshake.peer_reason(), Some(&CloseReason::empty()));
        assert_eq!(handshake.state(), CloseState::CloseReceived);
    }

    #[test]
    fn handshake_receive_close_after_sent() {
        let mut handshake = CloseHandshake::new();
        handshake.initiate(CloseReason::normal());

        let close_frame = Frame::close(Some(1000), None);
        let response = handshake.receive_close(&close_frame).unwrap();

        assert!(response.is_none()); // No response needed
        assert_eq!(handshake.state(), CloseState::Closed);
    }

    #[test]
    fn handshake_complete_flow_initiator() {
        let mut handshake = CloseHandshake::new();

        // 1. We initiate close
        let frame = handshake.initiate(CloseReason::normal());
        assert!(frame.is_some());
        assert_eq!(handshake.state(), CloseState::CloseSent);

        // 2. We receive peer's close response
        let peer_close = Frame::close(Some(1000), None);
        let response = handshake.receive_close(&peer_close).unwrap();
        assert!(response.is_none()); // Handshake complete, no response
        assert_eq!(handshake.state(), CloseState::Closed);
    }

    #[test]
    fn handshake_complete_flow_receiver() {
        let mut handshake = CloseHandshake::new();

        // 1. We receive peer's close
        let peer_close = Frame::close(Some(1000), Some("goodbye"));
        let response = handshake.receive_close(&peer_close).unwrap();
        assert!(response.is_some());
        assert_eq!(handshake.state(), CloseState::CloseReceived);

        // 2. We prepare our close response
        let frame = handshake.initiate(CloseReason::normal());
        assert!(frame.is_some());
        assert_eq!(handshake.state(), CloseState::CloseReceived);

        // 3. The handshake only completes after the response is sent
        handshake.mark_response_sent();
        assert_eq!(handshake.state(), CloseState::Closed);
    }

    #[test]
    fn handshake_response_initiation_does_not_complete_before_send() {
        let mut handshake = CloseHandshake::new();

        let peer_close = Frame::close(Some(1000), Some("goodbye"));
        let response = handshake.receive_close(&peer_close).unwrap();
        assert!(response.is_some());
        assert_eq!(handshake.state(), CloseState::CloseReceived);

        let frame = handshake.initiate(CloseReason::with_text(CloseCode::Normal, "ack"));
        assert!(frame.is_some());
        assert_eq!(handshake.state(), CloseState::CloseReceived);
        assert!(!handshake.is_open());
        assert!(!handshake.is_closed());
    }

    #[test]
    fn handshake_mark_response_sent_closes_after_receiving_peer_close() {
        let mut handshake = CloseHandshake::new();

        let peer_close = Frame::close(Some(1000), Some("bye"));
        let response = handshake.receive_close(&peer_close).unwrap();
        assert!(response.is_some());
        assert_eq!(handshake.state(), CloseState::CloseReceived);

        handshake.mark_response_sent();
        assert_eq!(handshake.state(), CloseState::Closed);
        assert!(handshake.is_closed());
    }

    #[test]
    fn handshake_force_close() {
        let mut handshake = CloseHandshake::new();
        handshake.force_close(CloseReason::new(CloseCode::Abnormal, None));

        assert_eq!(handshake.state(), CloseState::Closed);
        assert!(handshake.our_reason().is_some());
    }

    #[test]
    fn handshake_force_close_preserves_supplied_reason() {
        let mut handshake = CloseHandshake::new();
        let reason = CloseReason::with_text(CloseCode::GoingAway, "cancelled by region close");

        handshake.force_close(reason.clone());

        assert_eq!(handshake.state(), CloseState::Closed);
        assert_eq!(handshake.our_reason(), Some(&reason));
        assert!(handshake.peer_reason().is_none());
    }

    #[test]
    fn close_config_builder() {
        let config = CloseConfig::new()
            .with_timeout(Duration::from_secs(10))
            .with_close_on_drop(false)
            .with_cancellation_code(CloseCode::InternalError);

        assert_eq!(config.close_timeout, Duration::from_secs(10));
        assert!(!config.close_on_drop);
        assert_eq!(config.cancellation_code, CloseCode::InternalError);
    }

    // =========================================================================
    // Wave 56 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn close_reason_debug_clone_eq() {
        let r = CloseReason::normal();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("CloseReason"), "{dbg}");
        let cloned = r.clone();
        assert_eq!(r, cloned);
    }

    #[test]
    fn close_state_debug_clone_copy_eq_default() {
        let s = CloseState::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Open"), "{dbg}");
        let copied = s;
        let cloned = s;
        assert_eq!(copied, cloned);
        assert_ne!(s, CloseState::CloseSent);
    }

    #[test]
    fn close_config_debug_clone() {
        let cfg = CloseConfig::new();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("CloseConfig"), "{dbg}");
        let cloned = cfg.clone();
        assert_eq!(cfg.close_timeout, cloned.close_timeout);
    }

    #[test]
    fn handshake_receive_close_does_not_echo_unassigned_code() {
        // RFC 6455 §7.4.2: unassigned codes (1016-2999) must be accepted when
        // received, but RFC 6455 endpoints must not send them.
        let mut handshake = CloseHandshake::new();

        let close_frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Close,
            masked: false,
            mask_key: None,
            payload: Bytes::copy_from_slice(&1016u16.to_be_bytes()),
        };

        let response = handshake.receive_close(&close_frame).unwrap().unwrap();
        assert_eq!(response.opcode, Opcode::Close);
        assert!(response.payload.is_empty());
        assert_eq!(handshake.state(), CloseState::CloseReceived);
    }

    #[test]
    fn handshake_initiate_with_overlong_reason_does_not_panic() {
        let mut handshake = CloseHandshake::new();
        let text = "a".repeat(MAX_CLOSE_PAYLOAD_BYTES - CLOSE_CODE_BYTES + 1);

        let frame = handshake
            .initiate(CloseReason::with_text(CloseCode::Normal, &text))
            .expect("open handshake should produce a close frame");

        assert_eq!(frame.opcode, Opcode::Close);
        assert_eq!(frame.payload.as_ref(), &1000u16.to_be_bytes());
        assert_eq!(handshake.state(), CloseState::CloseSent);
    }

    #[test]
    fn to_frame_with_unassigned_raw_code_does_not_panic() {
        // A CloseReason parsed from a peer with an unassigned code must not
        // panic if higher layers serialize it back out.
        let payload = 2000u16.to_be_bytes();
        let reason = CloseReason::parse(&payload).unwrap();
        assert_eq!(reason.raw_code, Some(2000));
        let frame = reason.to_frame();
        assert_eq!(frame.opcode, Opcode::Close);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn close_reason_code_falls_back_when_raw_code_is_absent() {
        let reason = CloseReason {
            code: Some(CloseCode::Normal),
            raw_code: None,
            text: None,
        };

        assert_eq!(reason.wire_code(), Some(1000));
        assert!(reason.is_normal());
        assert_eq!(reason.encode().as_ref(), &1000u16.to_be_bytes());
        assert_eq!(reason.to_frame().payload.as_ref(), &1000u16.to_be_bytes());
    }

    #[test]
    fn typed_unsendable_close_code_fails_closed_without_panicking() {
        let reason = CloseReason {
            code: Some(CloseCode::Abnormal),
            raw_code: None,
            text: None,
        };

        assert_eq!(reason.wire_code(), Some(1006));
        assert!(reason.encode().is_empty());
        let frame = reason.to_frame();
        assert_eq!(frame.opcode, Opcode::Close);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn typed_unsendable_close_code_drops_reason_text_instead_of_synthesizing_normal_close() {
        let reason = CloseReason {
            code: Some(CloseCode::NoStatusReceived),
            raw_code: None,
            text: Some("must not hit wire".to_string()),
        };

        assert_eq!(reason.wire_code(), Some(1005));
        assert!(reason.encode().is_empty());
        let frame = reason.to_frame();
        assert_eq!(frame.opcode, Opcode::Close);
        assert!(frame.payload.is_empty());
    }
