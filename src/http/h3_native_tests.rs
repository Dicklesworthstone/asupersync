mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn qpack_entry_by_insertion_id(
        table: &QpackDynamicTable,
        insertion_id: u64,
    ) -> Option<(&str, &str)> {
        table
            .get_by_insertion_id(insertion_id)
            .map(|entry| (entry.name(), entry.value()))
    }

    fn test_config() -> H3ConnectionConfig {
        H3ConnectionConfig::default()
    }

    #[test]
    fn settings_roundtrip_and_unknown_preservation() {
        let settings = H3Settings {
            qpack_max_table_capacity: Some(4096),
            max_field_section_size: Some(16384),
            qpack_blocked_streams: Some(16),
            enable_connect_protocol: Some(true),
            h3_datagram: Some(false),
            unknown: vec![UnknownSetting {
                id: 0xfeed,
                value: 7,
            }],
        };
        let mut payload = Vec::new();
        settings.encode_payload(&mut payload).expect("encode");
        let decoded = H3Settings::decode_payload(&payload).expect("decode");
        assert_eq!(decoded, settings);
    }

    #[test]
    fn settings_reject_duplicate_ids() {
        let mut payload = Vec::new();
        encode_setting(&mut payload, H3_SETTING_MAX_FIELD_SECTION_SIZE, 100).expect("first");
        encode_setting(&mut payload, H3_SETTING_MAX_FIELD_SECTION_SIZE, 200).expect("second");
        let err = H3Settings::decode_payload(&payload).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::DuplicateSetting(H3_SETTING_MAX_FIELD_SECTION_SIZE)
        );
    }

    #[test]
    fn settings_decode_large_unique_unknown_setting_set() {
        let mut payload = Vec::new();
        for id in 0x40u64..0x440 {
            encode_setting(&mut payload, id, id ^ 0x55).expect("encode unknown setting");
        }

        let decoded = H3Settings::decode_payload(&payload).expect("decode large settings set");
        assert_eq!(decoded.unknown.len(), 1024);
        assert_eq!(
            decoded.unknown.first(),
            Some(&UnknownSetting {
                id: 0x40,
                value: 0x15
            })
        );
        assert_eq!(
            decoded.unknown.last(),
            Some(&UnknownSetting {
                id: 0x43f,
                value: 0x46a,
            })
        );
    }

    #[test]
    fn settings_reject_invalid_boolean_values() {
        let mut payload = Vec::new();
        encode_setting(&mut payload, H3_SETTING_ENABLE_CONNECT_PROTOCOL, 2).expect("encode");
        let err = H3Settings::decode_payload(&payload).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidSettingValue(H3_SETTING_ENABLE_CONNECT_PROTOCOL)
        );
    }

    #[test]
    fn frame_roundtrip() {
        let frame = H3Frame::PushPromise {
            push_id: 9,
            field_block: vec![1, 2, 3, 4],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn control_stream_requires_settings_first() {
        let mut state = H3ControlState::new();
        let err = state
            .on_remote_control_frame(&H3Frame::Goaway(3))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("first remote control frame must be SETTINGS")
        );
    }

    #[test]
    fn control_stream_rejects_cancel_push_first() {
        let mut state = H3ControlState::new();
        let err = state
            .on_remote_control_frame(&H3Frame::CancelPush(123))
            .expect_err("CANCEL_PUSH as first frame must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("first remote control frame must be SETTINGS")
        );
    }

    #[test]
    fn control_stream_rejects_max_push_id_first() {
        let mut state = H3ControlState::new();
        let err = state
            .on_remote_control_frame(&H3Frame::MaxPushId(456))
            .expect_err("MAX_PUSH_ID as first frame must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("first remote control frame must be SETTINGS")
        );
    }

    #[test]
    fn control_stream_rejects_unknown_frame_first() {
        let mut state = H3ControlState::new();
        let unknown_frame = H3Frame::Unknown {
            frame_type: 0xBADF00D,
            payload: vec![1, 2, 3],
        };
        let err = state
            .on_remote_control_frame(&unknown_frame)
            .expect_err("unknown frame as first frame must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("first remote control frame must be SETTINGS")
        );
    }

    #[test]
    fn control_stream_rejects_data_headers_first() {
        let mut state = H3ControlState::new();

        // DATA frames are not allowed on control streams at all
        let err = state
            .on_remote_control_frame(&H3Frame::Data(vec![1, 2, 3]))
            .expect_err("DATA as first frame must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("first remote control frame must be SETTINGS")
        );

        let mut state2 = H3ControlState::new();

        // HEADERS frames are not allowed on control streams at all
        let err = state2
            .on_remote_control_frame(&H3Frame::Headers(vec![4, 5, 6]))
            .expect_err("HEADERS as first frame must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("first remote control frame must be SETTINGS")
        );
    }

    #[test]
    fn control_stream_accepts_settings_first_then_rejects_duplicate() {
        let mut state = H3ControlState::new();

        // First SETTINGS frame should be accepted
        state
            .on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("first SETTINGS should be accepted");

        // Second SETTINGS frame should be rejected
        let err = state
            .on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect_err("duplicate SETTINGS must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("duplicate SETTINGS on remote control stream")
        );

        // After SETTINGS, valid control frames should be accepted
        state
            .on_remote_control_frame(&H3Frame::Goaway(789))
            .expect("GOAWAY after SETTINGS should be accepted");

        state
            .on_remote_control_frame(&H3Frame::CancelPush(101))
            .expect("CANCEL_PUSH after SETTINGS should be accepted");

        state
            .on_remote_control_frame(&H3Frame::MaxPushId(202))
            .expect("MAX_PUSH_ID after SETTINGS should be accepted");
    }

    #[test]
    fn pseudo_header_validation() {
        let req = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        };
        validate_request_pseudo_headers(&req).expect("valid request");

        let resp = H3PseudoHeaders {
            status: Some(200),
            ..H3PseudoHeaders::default()
        };
        validate_response_pseudo_headers(&resp).expect("valid response");

        let connect = H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            authority: Some("upstream.example:443".to_string()),
            ..H3PseudoHeaders::default()
        };
        validate_request_pseudo_headers(&connect).expect("valid connect request");
    }

    #[test]
    fn pseudo_header_validation_rejects_invalid_connect_and_status() {
        let bad_connect = H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("upstream.example:443".to_string()),
            path: Some("/".to_string()),
            ..H3PseudoHeaders::default()
        };
        let err = validate_request_pseudo_headers(&bad_connect).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(
                "CONNECT request must not include :scheme or :path"
            )
        );

        let missing_authority_connect = H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            ..H3PseudoHeaders::default()
        };
        let err =
            validate_request_pseudo_headers(&missing_authority_connect).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("CONNECT request missing :authority")
        );

        let bad_resp = H3PseudoHeaders {
            status: Some(99),
            ..H3PseudoHeaders::default()
        };
        let err = validate_response_pseudo_headers(&bad_resp).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader("status must be in 100..=999")
        );
    }

    #[test]
    fn extended_connect_protocol_validation() {
        // Extended CONNECT with :protocol should be valid when enabled
        let extended_connect = H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("upstream.example:443".to_string()),
            path: Some("/websocket".to_string()),
            protocol: Some("websocket".to_string()),
            ..H3PseudoHeaders::default()
        };
        validate_request_pseudo_headers_with_settings(&extended_connect, true)
            .expect("valid extended connect request");

        // Extended CONNECT should fail without :protocol
        let missing_protocol = H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("upstream.example:443".to_string()),
            path: Some("/websocket".to_string()),
            protocol: None,
            ..H3PseudoHeaders::default()
        };
        let err = validate_request_pseudo_headers_with_settings(&missing_protocol, true)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("extended CONNECT request missing :protocol")
        );

        // Extended CONNECT should fail with empty :protocol
        let empty_protocol = H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            authority: Some("upstream.example:443".to_string()),
            protocol: Some(String::new()),
            ..H3PseudoHeaders::default()
        };
        let err = validate_request_pseudo_headers_with_settings(&empty_protocol, true)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(
                "extended CONNECT request :protocol must not be empty"
            )
        );

        // Standard CONNECT should reject :protocol when extended CONNECT is disabled
        let standard_connect_with_protocol = H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            authority: Some("upstream.example:443".to_string()),
            protocol: Some("websocket".to_string()),
            ..H3PseudoHeaders::default()
        };
        let err =
            validate_request_pseudo_headers_with_settings(&standard_connect_with_protocol, false)
                .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(
                "CONNECT request must not include :protocol (extended CONNECT not enabled)"
            )
        );
    }

    #[test]
    fn h3_request_head_validate_connect_method() {
        let extended_connect_head = H3RequestHead::new_with_settings(
            H3PseudoHeaders {
                method: Some("CONNECT".to_string()),
                authority: Some("upstream.example:443".to_string()),
                protocol: Some("websocket".to_string()),
                ..H3PseudoHeaders::default()
            },
            vec![],
            true,
        )
        .expect("valid extended connect");

        // Should validate successfully
        extended_connect_head
            .validate_connect_method(true)
            .expect("extended CONNECT validation should succeed");

        // Should fail if trying to use extended features with extended CONNECT disabled
        let err = extended_connect_head
            .validate_connect_method(false)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(
                "CONNECT request must not include :protocol (extended CONNECT not enabled)"
            )
        );

        // Non-CONNECT request should fail validation
        let get_head = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some("/".to_string()),
                ..H3PseudoHeaders::default()
            },
            vec![],
        )
        .expect("valid GET");

        let err = get_head
            .validate_connect_method(false)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(
                "validate_connect_method called on non-CONNECT request"
            )
        );
    }

    #[test]
    fn request_stream_state_enforces_headers_then_data() {
        let mut st = H3RequestStreamState::new();
        let err = st
            .on_frame(&H3Frame::Data(vec![1, 2, 3]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("DATA before initial HEADERS on request stream")
        );
        st.on_frame(&H3Frame::Headers(vec![0x80])).expect("headers");
        st.on_frame(&H3Frame::Data(vec![1])).expect("data");
        st.on_frame(&H3Frame::Headers(vec![0x81]))
            .expect("trailers headers");
        let err = st.on_frame(&H3Frame::Data(vec![2])).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("DATA not allowed after trailing HEADERS")
        );
    }

    #[test]
    fn request_stream_rejects_non_data_headers_frames() {
        let mut st = H3RequestStreamState::new();
        let err = st
            .on_frame(&H3Frame::Settings(H3Settings::default()))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("control frames are not valid on request streams")
        );
    }

    /// br-asupersync-8w9naj: H3RequestStreamState::on_frame must
    /// accept H3Frame::Datagram on a bidirectional request stream
    /// after the initial HEADERS, per RFC 9297 §2 and the project's
    /// own validate_bidirectional_frame allow-list. Pre-fix the
    /// catch-all `_` arm rejected DATAGRAM with a "only HEADERS/DATA"
    /// error, breaking RFC 9298 CONNECT-UDP interop on the per-
    /// stream state machine path.
    #[test]
    fn request_stream_accepts_datagram_after_headers() {
        let mut st = H3RequestStreamState::new();
        // HEADERS first establishes the stream's identity.
        st.on_frame(&H3Frame::Headers(vec![0x80])).expect("headers");
        // DATAGRAM is allowed at any point after HEADERS, before or
        // interleaved with DATA. Multiple DATAGRAMs are allowed.
        st.on_frame(&H3Frame::Datagram {
            quarter_stream_id: 0,
            payload: vec![1, 2, 3],
        })
        .expect("datagram-after-headers");
        st.on_frame(&H3Frame::Data(vec![10])).expect("data ok");
        st.on_frame(&H3Frame::Datagram {
            quarter_stream_id: 0,
            payload: vec![4, 5, 6],
        })
        .expect("datagram-between-headers-and-trailers");
        st.on_frame(&H3Frame::Headers(vec![0x81]))
            .expect("trailers headers");
        // DATAGRAM is also allowed after trailers (the stream's
        // datagram flow can outlive the request body — RFC 9297
        // imposes no upper bound from the HEADERS+DATA*+TRAILERS
        // sequence).
        st.on_frame(&H3Frame::Datagram {
            quarter_stream_id: 0,
            payload: vec![7, 8, 9],
        })
        .expect("datagram-after-trailers");
    }

    /// br-asupersync-8w9naj: DATAGRAM before the initial HEADERS is
    /// still a protocol error — the stream's identity (method,
    /// :protocol, capsule negotiation) is established by HEADERS,
    /// and a DATAGRAM with no preceding HEADERS has nothing to
    /// associate with.
    #[test]
    fn request_stream_rejects_datagram_before_headers() {
        let mut st = H3RequestStreamState::new();
        let err = st
            .on_frame(&H3Frame::Datagram {
                quarter_stream_id: 0,
                payload: vec![1, 2, 3],
            })
            .expect_err("must fail before HEADERS");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("DATAGRAM before initial HEADERS on request stream")
        );
    }

    /// br-asupersync-8w9naj: DATAGRAM frames do NOT advance the
    /// HEADERS+DATA*+TRAILERS state machine — they're an out-of-
    /// band sidecar. Receiving DATAGRAMs between HEADERS and DATA
    /// must NOT cause subsequent DATA to be rejected (which would
    /// happen if DATAGRAM accidentally bumped header_blocks_seen).
    #[test]
    fn request_stream_datagram_does_not_advance_state_machine() {
        let mut st = H3RequestStreamState::new();
        st.on_frame(&H3Frame::Headers(vec![0x80])).expect("headers");
        st.on_frame(&H3Frame::Datagram {
            quarter_stream_id: 0,
            payload: vec![1],
        })
        .expect("datagram");
        // DATA after a DATAGRAM still works — DATAGRAM did not
        // advance to "trailers" state.
        st.on_frame(&H3Frame::Data(vec![2]))
            .expect("data after datagram");
        // Trailers still allowed.
        st.on_frame(&H3Frame::Headers(vec![0x81]))
            .expect("trailers after data after datagram");
    }

    #[test]
    fn request_stream_ignores_unknown_frames_without_advancing_state_machine() {
        let mut st = H3RequestStreamState::new();
        st.on_frame(&H3Frame::Unknown {
            frame_type: 0xDEAD_BEEF,
            payload: vec![1, 2, 3],
        })
        .expect("unknown frames must be ignored before headers");
        let err = st
            .on_frame(&H3Frame::Data(vec![1]))
            .expect_err("unknown frame must not count as initial headers");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("DATA before initial HEADERS on request stream")
        );

        st.on_frame(&H3Frame::Headers(vec![0x80])).expect("headers");
        st.on_frame(&H3Frame::Unknown {
            frame_type: 0x40,
            payload: vec![4, 5],
        })
        .expect("unknown frames must be ignored after headers");
        st.on_frame(&H3Frame::Data(vec![2]))
            .expect("DATA after ignored unknown frame");
    }

    #[test]
    fn request_stream_accepts_push_promise_without_advancing_state_machine() {
        let mut st = H3RequestStreamState::new();
        st.on_frame(&H3Frame::PushPromise {
            push_id: 1,
            field_block: vec![0x80],
        })
        .expect("PUSH_PROMISE is a request-stream sidecar");
        let err = st
            .on_frame(&H3Frame::Data(vec![1]))
            .expect_err("PUSH_PROMISE must not count as initial headers");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("DATA before initial HEADERS on request stream")
        );

        st.on_frame(&H3Frame::Headers(vec![0x80])).expect("headers");
        st.on_frame(&H3Frame::PushPromise {
            push_id: 2,
            field_block: vec![0x81],
        })
        .expect("PUSH_PROMISE after headers");
        st.on_frame(&H3Frame::Data(vec![2]))
            .expect("DATA after push promise");
    }

    #[test]
    fn control_stream_rejects_data_after_settings() {
        let mut state = H3ControlState::new();
        state
            .on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        let err = state
            .on_remote_control_frame(&H3Frame::Data(vec![1]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("frame type not allowed on control stream")
        );
    }

    #[test]
    fn client_role_applies_goaway_to_new_request_ids() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        c.on_control_frame(&H3Frame::Goaway(12)).expect("goaway");
        assert_eq!(c.goaway_id(), Some(12));
        c.on_request_stream_frame(8, &H3Frame::Headers(vec![1]))
            .expect("allowed");
        let err = c
            .on_request_stream_frame(12, &H3Frame::Headers(vec![1]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("request stream id rejected after GOAWAY")
        );
    }

    #[test]
    fn server_role_accepts_push_id_goaway_without_blocking_request_streams() {
        let mut c = H3ConnectionState::new_server();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        c.on_control_frame(&H3Frame::Goaway(10))
            .expect("server role accepts client push-id goaway");
        assert_eq!(c.goaway_id(), Some(10));
        c.on_request_stream_frame(12, &H3Frame::Headers(vec![1]))
            .expect("server role must keep accepting request stream ids");
    }

    #[test]
    fn connection_state_rejects_increasing_goaway_id() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        c.on_control_frame(&H3Frame::Goaway(12)).expect("first");
        let err = c
            .on_control_frame(&H3Frame::Goaway(16))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("GOAWAY id must not increase")
        );
    }

    #[test]
    fn request_stream_rejects_unidirectional_stream_id() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        let err = c
            .on_request_stream_frame(2, &H3Frame::Headers(vec![1]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol(
                "request stream id must be client-initiated bidirectional"
            )
        );
    }

    #[test]
    fn connection_ignores_unknown_request_frame_without_opening_stream() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        c.on_request_stream_frame(
            0,
            &H3Frame::Unknown {
                frame_type: 0x21,
                payload: vec![0xAA],
            },
        )
        .expect("unknown frame on new request stream must be ignored");
        assert_eq!(c.active_request_stream_count(), 0);
        c.on_request_stream_frame(0, &H3Frame::Headers(vec![0x80]))
            .expect("headers still open the stream after ignored unknown");
        assert_eq!(c.active_request_stream_count(), 1);
    }

    #[test]
    fn connection_does_not_open_request_stream_after_invalid_first_frame() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        let err = c
            .on_request_stream_frame(0, &H3Frame::Data(vec![0xAA]))
            .expect_err("DATA before HEADERS must be rejected");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("DATA before initial HEADERS on request stream")
        );
        assert_eq!(c.active_request_stream_count(), 0);
        c.on_request_stream_frame(0, &H3Frame::Headers(vec![0x80]))
            .expect("valid first HEADERS should still open the stream");
        assert_eq!(c.active_request_stream_count(), 1);
    }

    #[test]
    fn request_stream_rejects_server_initiated_bidirectional_stream_id() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        let err = c
            .on_request_stream_frame(1, &H3Frame::Headers(vec![1]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol(
                "request stream id must be client-initiated bidirectional"
            )
        );
    }

    #[test]
    fn native_h3_adapter_static_only_accepts_peer_dynamic_qpack_permission() {
        let mut c = H3ConnectionState::new();
        let settings = H3Settings {
            qpack_max_table_capacity: Some(1024),
            qpack_blocked_streams: Some(8),
            ..H3Settings::default()
        };
        c.on_control_frame(&H3Frame::Settings(settings.clone()))
            .expect("peer capacity is optional permission for a static encoder");
        let qpack = QpackInstructionStreamState::from_settings(H3QpackMode::StaticOnly, &settings)
            .expect("static instruction state declines peer dynamic capacity");
        assert_eq!(qpack.context().dynamic_table().capacity(), 0);
    }

    #[test]
    fn duplicate_remote_control_uni_stream_rejected() {
        let mut c = H3ConnectionState::new();
        c.on_remote_uni_stream_type(3, H3_STREAM_TYPE_CONTROL)
            .expect("first control");
        let err = c
            .on_remote_uni_stream_type(7, H3_STREAM_TYPE_CONTROL)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("duplicate remote control stream")
        );
        c.on_uni_stream_frame(3, &H3Frame::Settings(H3Settings::default()))
            .expect("original control stream remains active");
        let err = c
            .on_uni_stream_frame(7, &H3Frame::Settings(H3Settings::default()))
            .expect_err("new duplicate stream must not become active");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("unknown unidirectional stream")
        );
    }

    #[test]
    fn uni_stream_type_rejects_bidirectional_stream_id() {
        let mut c = H3ConnectionState::new();
        let err = c
            .on_remote_uni_stream_type(0, H3_STREAM_TYPE_CONTROL)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol(
                "unidirectional stream type requires unidirectional stream id"
            )
        );
    }

    #[test]
    fn push_uni_stream_uses_headers_data_ordering() {
        let mut c = H3ConnectionState::new();
        c.on_remote_uni_stream_type(11, H3_STREAM_TYPE_PUSH)
            .expect("push type");
        let err = c
            .on_uni_stream_frame(11, &H3Frame::Headers(vec![0x80]))
            .expect_err("must fail before push header");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("push stream missing push id")
        );
        c.on_push_stream_header(11, 7).expect("push header");
        let err = c
            .on_uni_stream_frame(11, &H3Frame::Data(vec![1]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("DATA before initial HEADERS on request stream")
        );
        c.on_uni_stream_frame(11, &H3Frame::Headers(vec![0x80]))
            .expect("headers");
        c.on_uni_stream_frame(11, &H3Frame::Data(vec![1, 2]))
            .expect("data");
    }

    #[test]
    fn push_stream_duplicate_header_and_push_id_rejected() {
        let mut c = H3ConnectionState::new();
        c.on_remote_uni_stream_type(11, H3_STREAM_TYPE_PUSH)
            .expect("first push stream");
        c.on_push_stream_header(11, 7).expect("push header");
        let err = c
            .on_push_stream_header(11, 8)
            .expect_err("second push header must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("push stream header already received")
        );

        c.on_remote_uni_stream_type(15, H3_STREAM_TYPE_PUSH)
            .expect("second push stream");
        let err = c
            .on_push_stream_header(15, 7)
            .expect_err("duplicate push id must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("duplicate push id in push stream header")
        );
    }

    #[test]
    fn qpack_streams_reject_h3_frame_mapping() {
        let mut c = H3ConnectionState::new();
        c.on_remote_uni_stream_type(15, H3_STREAM_TYPE_QPACK_ENCODER)
            .expect("qpack encoder");
        let err = c
            .on_uni_stream_frame(15, &H3Frame::Data(vec![1]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("qpack streams carry instructions, not h3 frames")
        );
    }

    // ========================================================================
    // Pure data-type tests (wave 11 – CyanBarn)
    // ========================================================================

    #[test]
    fn h3_native_error_display_all_variants() {
        let cases: Vec<(H3NativeError, &str)> = vec![
            (H3NativeError::UnexpectedEof, "unexpected EOF"),
            (H3NativeError::InvalidFrame("bad"), "invalid frame: bad"),
            (
                H3NativeError::DuplicateSetting(0x6),
                "duplicate setting: 0x6",
            ),
            (
                H3NativeError::InvalidSettingValue(0x8),
                "invalid setting value: 0x8",
            ),
            (
                H3NativeError::ControlProtocol("dup"),
                "control stream protocol violation: dup",
            ),
            (
                H3NativeError::StreamProtocol("bad stream"),
                "stream protocol violation: bad stream",
            ),
            (
                H3NativeError::QpackPolicy("no dyn"),
                "qpack policy violation: no dyn",
            ),
            (
                H3NativeError::InvalidRequestPseudoHeader("missing"),
                "invalid request pseudo-header set: missing",
            ),
            (
                H3NativeError::InvalidResponsePseudoHeader("bad status"),
                "invalid response pseudo-header set: bad status",
            ),
        ];
        for (err, expected) in &cases {
            assert_eq!(format!("{err}"), *expected, "{err:?}");
        }
    }

    #[test]
    fn h3_native_error_debug_clone_eq() {
        let a = H3NativeError::UnexpectedEof;
        let b = a.clone();
        assert_eq!(a, b);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("UnexpectedEof"), "{dbg}");
    }

    #[test]
    fn h3_native_error_is_std_error() {
        let err = H3NativeError::UnexpectedEof;
        let _: &dyn std::error::Error = &err;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn h3_qpack_mode_default_debug_copy() {
        let mode: H3QpackMode = H3QpackMode::default();
        assert_eq!(mode, H3QpackMode::StaticOnly);
        let copied = mode; // Copy
        let cloned = mode;
        assert_eq!(copied, cloned);
        let dbg = format!("{mode:?}");
        assert!(dbg.contains("StaticOnly"), "{dbg}");
    }

    #[test]
    fn h3_qpack_mode_inequality() {
        assert_ne!(H3QpackMode::StaticOnly, H3QpackMode::DynamicTableAllowed);
    }

    #[test]
    fn h3_connection_config_default_debug_copy() {
        let config = H3ConnectionConfig::default();
        assert_eq!(config.qpack_mode, H3QpackMode::StaticOnly);
        assert_eq!(config.endpoint_role, H3EndpointRole::Client);
        let copied = config; // Copy
        let cloned = config;
        assert_eq!(copied, cloned);
        let dbg = format!("{config:?}");
        assert!(dbg.contains("H3ConnectionConfig"), "{dbg}");
    }

    #[test]
    fn h3_endpoint_role_default_debug_copy() {
        let role = H3EndpointRole::default();
        assert_eq!(role, H3EndpointRole::Client);
        let copied = role; // Copy
        let cloned = role;
        assert_eq!(copied, cloned);
        let dbg = format!("{role:?}");
        assert!(dbg.contains("Client"), "{dbg}");
    }

    #[test]
    fn h3_uni_stream_type_debug_copy_eq() {
        let t = H3UniStreamType::Control;
        let copied = t; // Copy
        let cloned = t;
        assert_eq!(copied, cloned);
        assert_ne!(H3UniStreamType::Control, H3UniStreamType::Push);
        assert_ne!(H3UniStreamType::QpackEncoder, H3UniStreamType::QpackDecoder);
        let dbg = format!("{t:?}");
        assert!(dbg.contains("Control"), "{dbg}");
    }

    #[test]
    fn h3_uni_stream_type_decode_all_known() {
        assert_eq!(H3UniStreamType::decode(0x00), H3UniStreamType::Control);
        assert_eq!(H3UniStreamType::decode(0x01), H3UniStreamType::Push);
        assert_eq!(H3UniStreamType::decode(0x02), H3UniStreamType::QpackEncoder);
        assert_eq!(H3UniStreamType::decode(0x03), H3UniStreamType::QpackDecoder);
    }

    #[test]
    fn h3_uni_stream_type_decode_unknown_accepted() {
        let kind = H3UniStreamType::decode(0xFF);
        assert_eq!(kind, H3UniStreamType::Unknown(0xFF));
    }

    #[test]
    fn unknown_setting_debug_clone_eq() {
        let a = UnknownSetting {
            id: 0xAA,
            value: 42,
        };
        let b = a.clone();
        assert_eq!(a, b);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("UnknownSetting"), "{dbg}");
    }

    #[test]
    fn h3_settings_default_debug_clone() {
        let s = H3Settings::default();
        assert!(s.qpack_max_table_capacity.is_none());
        assert!(s.unknown.is_empty());
        let dbg = format!("{s:?}");
        assert!(dbg.contains("H3Settings"), "{dbg}");
        let cloned = s.clone();
        assert_eq!(cloned, s);
    }

    #[test]
    fn h3_settings_empty_roundtrip() {
        let s = H3Settings::default();
        let mut payload = Vec::new();
        s.encode_payload(&mut payload).expect("encode");
        assert!(payload.is_empty());
        let decoded = H3Settings::decode_payload(&payload).expect("decode");
        assert_eq!(decoded, s);
    }

    #[test]
    fn h3_frame_debug_clone_all_variants() {
        let variants: Vec<H3Frame> = vec![
            H3Frame::Data(vec![1, 2]),
            H3Frame::Headers(vec![3, 4]),
            H3Frame::CancelPush(5),
            H3Frame::Settings(H3Settings::default()),
            H3Frame::PushPromise {
                push_id: 6,
                field_block: vec![7],
            },
            H3Frame::Goaway(8),
            H3Frame::MaxPushId(9),
            H3Frame::Unknown {
                frame_type: 0xFF,
                payload: vec![10],
            },
        ];
        for frame in &variants {
            let dbg = format!("{frame:?}");
            assert!(!dbg.is_empty());
            let cloned = frame.clone();
            assert_eq!(cloned, *frame);
        }
    }

    #[test]
    fn h3_control_state_default_debug_clone() {
        let s = H3ControlState::new();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("H3ControlState"), "{dbg}");
        let cloned = s.clone();
        assert_eq!(cloned, s);
    }

    #[test]
    fn h3_control_state_duplicate_local_settings() {
        let mut s = H3ControlState::new();
        s.build_local_settings(H3Settings::default())
            .expect("first ok");
        let err = s
            .build_local_settings(H3Settings::default())
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("SETTINGS already sent on local control stream")
        );
    }

    #[test]
    fn h3_control_state_duplicate_remote_settings() {
        let mut s = H3ControlState::new();
        s.on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("first ok");
        let err = s
            .on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("duplicate SETTINGS on remote control stream")
        );
    }

    #[test]
    fn h3_pseudo_headers_default_debug_clone() {
        let ph = H3PseudoHeaders::default();
        assert!(ph.method.is_none());
        assert!(ph.scheme.is_none());
        assert!(ph.authority.is_none());
        assert!(ph.path.is_none());
        assert!(ph.status.is_none());
        let dbg = format!("{ph:?}");
        assert!(dbg.contains("H3PseudoHeaders"), "{dbg}");
        let cloned = ph.clone();
        assert_eq!(cloned, ph);
    }

    #[test]
    fn h3_request_head_debug_clone_eq() {
        let head = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some("/".to_string()),
                status: None,
                protocol: None,
            },
            vec![],
        )
        .expect("valid");
        let dbg = format!("{head:?}");
        assert!(dbg.contains("H3RequestHead"), "{dbg}");
        let cloned = head.clone();
        assert_eq!(cloned, head);
    }

    #[test]
    fn h3_response_head_debug_clone_eq() {
        let head = H3ResponseHead::new(200, vec![]).expect("valid");
        let dbg = format!("{head:?}");
        assert!(dbg.contains("H3ResponseHead"), "{dbg}");
        assert_eq!(head.status, 200);
        let cloned = head.clone();
        assert_eq!(cloned, head);
    }

    #[test]
    fn h3_response_head_invalid_status() {
        let err = H3ResponseHead::new(50, vec![]).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader("status must be in 100..=999")
        );
    }

    #[test]
    fn response_pseudo_headers_reject_authority() {
        let headers = H3PseudoHeaders {
            status: Some(200),
            authority: Some("example.com".to_string()),
            ..H3PseudoHeaders::default()
        };
        let err = validate_response_pseudo_headers(&headers).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader(
                "response must not include request pseudo headers"
            )
        );
    }

    #[test]
    fn response_pseudo_headers_reject_101_switching_protocols() {
        let headers = H3PseudoHeaders {
            status: Some(101),
            ..H3PseudoHeaders::default()
        };
        let err = validate_response_pseudo_headers(&headers).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader(
                "HTTP/3 does not support 101 Switching Protocols"
            )
        );
    }

    #[test]
    fn qpack_field_plan_debug_clone_eq() {
        let idx = QpackFieldPlan::StaticIndex(17);
        let lit = QpackFieldPlan::Literal {
            name: "x".to_string(),
            value: "y".to_string(),
        };
        assert_ne!(idx, lit);
        let dbg = format!("{idx:?}");
        assert!(dbg.contains("StaticIndex"), "{dbg}");
        let cloned = lit.clone();
        assert_eq!(cloned, lit);
    }

    #[test]
    fn qpack_static_plans_use_known_indices() {
        let req = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some("/".to_string()),
                status: None,
                protocol: None,
            },
            vec![("accept".to_string(), "*/*".to_string())],
        )
        .expect("request");
        let req_plan = qpack_static_plan_for_request(&req);
        assert!(req_plan.contains(&QpackFieldPlan::StaticIndex(17)));
        assert!(req_plan.contains(&QpackFieldPlan::StaticIndex(23)));
        assert!(req_plan.contains(&QpackFieldPlan::StaticIndex(1)));

        let resp = H3ResponseHead::new(200, vec![("server".to_string(), "asupersync".to_string())])
            .expect("response");
        let resp_plan = qpack_static_plan_for_response(&resp);
        assert_eq!(resp_plan.first(), Some(&QpackFieldPlan::StaticIndex(25)));
    }

    // ========================================================================
    // QH3-U1 gap-filling tests
    // ========================================================================

    // --- 1. Frame roundtrips ---

    #[test]
    fn frame_roundtrip_data() {
        let frame = H3Frame::Data(vec![0xCA, 0xFE]);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn frame_roundtrip_headers() {
        let frame = H3Frame::Headers(vec![0x80, 0x81, 0x82]);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn frame_roundtrip_cancel_push() {
        let frame = H3Frame::CancelPush(42);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn frame_roundtrip_goaway() {
        let frame = H3Frame::Goaway(1000);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn frame_roundtrip_max_push_id() {
        let frame = H3Frame::MaxPushId(255);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn frame_roundtrip_unknown() {
        let frame = H3Frame::Unknown {
            frame_type: 0x1F,
            payload: vec![0xDE, 0xAD],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn frame_roundtrip_settings() {
        let settings = H3Settings {
            qpack_max_table_capacity: Some(4096),
            max_field_section_size: Some(8192),
            qpack_blocked_streams: None,
            enable_connect_protocol: Some(true),
            h3_datagram: None,
            unknown: vec![],
        };
        let frame = H3Frame::Settings(settings);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    // --- 2. Frame decode edge cases ---

    #[test]
    fn frame_decode_empty_input_error() {
        let err = H3Frame::decode(&[], &test_config()).expect_err("must fail on empty input");
        assert_eq!(err, H3NativeError::InvalidFrame("frame type varint"));
    }

    #[test]
    fn frame_decode_truncated_payload_unexpected_eof() {
        // Encode a Data frame with 4 bytes of payload, then truncate.
        let frame = H3Frame::Data(vec![1, 2, 3, 4]);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        // Truncate: remove the last 2 payload bytes.
        // Use saturating arithmetic to prevent underflow in test
        let truncated = &buf[..buf.len().saturating_sub(2)];
        let err =
            H3Frame::decode(truncated, &test_config()).expect_err("must fail on truncated payload");
        assert_eq!(err, H3NativeError::UnexpectedEof);
    }

    #[test]
    fn frame_decode_cancel_push_trailing_bytes_invalid_frame() {
        // Build a CancelPush frame manually with trailing bytes in the payload.
        let mut payload = Vec::new();
        encode_varint(7, &mut payload).expect("varint");
        payload.push(0xFF); // trailing garbage

        let mut buf = Vec::new();
        encode_varint(H3_FRAME_CANCEL_PUSH, &mut buf).expect("type");
        encode_varint(payload.len() as u64, &mut buf).expect("len");
        buf.extend_from_slice(&payload);

        let err = H3Frame::decode(&buf, &test_config()).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("cancel_push trailing bytes")
        );
    }

    #[test]
    fn frame_decode_goaway_trailing_bytes_invalid_frame() {
        let mut payload = Vec::new();
        encode_varint(50, &mut payload).expect("varint");
        payload.push(0xAA); // trailing garbage

        let mut buf = Vec::new();
        encode_varint(H3_FRAME_GOAWAY, &mut buf).expect("type");
        encode_varint(payload.len() as u64, &mut buf).expect("len");
        buf.extend_from_slice(&payload);

        let err = H3Frame::decode(&buf, &test_config()).expect_err("must fail");
        assert_eq!(err, H3NativeError::InvalidFrame("goaway trailing bytes"));
    }

    #[test]
    fn frame_decode_max_push_id_trailing_bytes_invalid_frame() {
        let mut payload = Vec::new();
        encode_varint(99, &mut payload).expect("varint");
        payload.push(0xBB); // trailing garbage

        let mut buf = Vec::new();
        encode_varint(H3_FRAME_MAX_PUSH_ID, &mut buf).expect("type");
        encode_varint(payload.len() as u64, &mut buf).expect("len");
        buf.extend_from_slice(&payload);

        let err = H3Frame::decode(&buf, &test_config()).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("max_push_id trailing bytes")
        );
    }

    /// br-asupersync-2gzkbh — RFC 9114 §7.2.5 requires the PUSH_PROMISE
    /// frame's Encoded Field Section to be non-empty. A frame whose
    /// payload contains only the push_id varint and no field-block
    /// bytes carries no headers and cannot describe a valid promised
    /// request; the parser rejects with H3_FRAME_ERROR.
    #[test]
    fn frame_decode_push_promise_empty_field_block_rejected() {
        // Payload = push_id varint (only); zero field_block bytes.
        let mut payload = Vec::new();
        encode_varint(7, &mut payload).expect("push_id varint");
        // No field_block follows.

        let mut buf = Vec::new();
        encode_varint(H3_FRAME_PUSH_PROMISE, &mut buf).expect("frame type");
        encode_varint(payload.len() as u64, &mut buf).expect("frame length");
        buf.extend_from_slice(&payload);

        let err = H3Frame::decode(&buf, &test_config()).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("push_promise empty field_block (RFC 9114 §7.2.5)")
        );
    }

    /// br-asupersync-2gzkbh — Regression guard: a PUSH_PROMISE frame
    /// with a non-empty field_block decodes cleanly. Without this, the
    /// reject above could silently degrade legitimate frames.
    #[test]
    fn frame_decode_push_promise_with_field_block_ok() {
        let mut payload = Vec::new();
        encode_varint(42, &mut payload).expect("push_id varint");
        payload.extend_from_slice(&[0x01, 0x02, 0x03]); // synthetic field block

        let mut buf = Vec::new();
        encode_varint(H3_FRAME_PUSH_PROMISE, &mut buf).expect("frame type");
        encode_varint(payload.len() as u64, &mut buf).expect("frame length");
        buf.extend_from_slice(&payload);

        let (frame, _consumed) = H3Frame::decode(&buf, &test_config()).expect("must decode");
        match frame {
            H3Frame::PushPromise {
                push_id,
                field_block,
            } => {
                assert_eq!(push_id, 42);
                assert_eq!(field_block, vec![0x01, 0x02, 0x03]);
            }
            other => panic!("expected PushPromise, got {other:?}"),
        }
    }

    /// br-asupersync-5vj2xy — RFC 9114 §4.2 forbidden-header check.
    /// Each name on the forbidden list must be rejected by
    /// `validate_header_name` even when its character set is
    /// otherwise valid (lowercase, RFC 9110 token).
    #[test]
    fn validate_header_name_rejects_rfc9114_forbidden_names() {
        for forbidden in [
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
        ] {
            let err = validate_header_name(forbidden).expect_err(forbidden);
            match err {
                H3NativeError::InvalidFrame(msg) => assert!(
                    msg.contains("forbidden"),
                    "wrong reject reason for {forbidden}: {msg}"
                ),
                other => panic!("expected InvalidFrame, got {other:?}"),
            }
        }
    }

    /// br-asupersync-5vj2xy — Regression guard: ordinary headers and
    /// pseudo-headers are NOT rejected by the new check.
    #[test]
    fn validate_header_name_accepts_ordinary_names() {
        for ok in [
            "content-type",
            "content-length",
            "x-custom-header",
            "te", // not on the forbidden list (only certain values are restricted)
            ":authority",
            ":method",
            ":path",
        ] {
            validate_header_name(ok).unwrap_or_else(|e| panic!("rejected {ok}: {e:?}"));
        }
    }

    /// br-asupersync-6ws34s — Pre-base relative-index arithmetic must
    /// fail closed at `u64::MAX` rather than wrap to a valid absolute
    /// index. The previous shape `base.checked_sub(relative_index + 1)`
    /// silently wrapped the inner add and returned `Some(base)`,
    /// mapping the crafted index to whatever entry sat at `base`.
    #[test]
    fn qpack_relative_to_absolute_pre_base_overflow_rejected() {
        let err = qpack_relative_to_absolute(100, u64::MAX, false)
            .expect_err("must reject u64::MAX relative_index");
        match err {
            H3NativeError::InvalidFrame(msg) => assert!(
                msg.contains("H3_QPACK_DECODER_STREAM_ERROR"),
                "wrong reject reason: {msg}"
            ),
            other => panic!("expected InvalidFrame, got {other:?}"),
        }
    }

    /// br-asupersync-6ws34s — Pre-base relative_index strictly less
    /// than base computes correctly: absolute = base - index - 1.
    /// Regression guard against the fix accidentally rejecting valid
    /// inputs.
    #[test]
    fn qpack_relative_to_absolute_pre_base_happy_path() {
        let abs = qpack_relative_to_absolute(10, 3, false).expect("valid pre-base");
        assert_eq!(abs, 6); // 10 - 3 - 1 = 6
        let abs0 = qpack_relative_to_absolute(1, 0, false).expect("base=1, index=0");
        assert_eq!(abs0, 0);
    }

    /// br-asupersync-6ws34s — Pre-base relative_index >= base must
    /// also reject (legitimate H3_QPACK_DECODER_STREAM_ERROR shape).
    #[test]
    fn qpack_relative_to_absolute_pre_base_index_geq_base_rejected() {
        // index = base means absolute = -1 (would underflow).
        assert!(qpack_relative_to_absolute(5, 5, false).is_err());
        // index > base also rejects.
        assert!(qpack_relative_to_absolute(5, 10, false).is_err());
        // index = base - 1 is the boundary: absolute = 0 (valid).
        assert_eq!(
            qpack_relative_to_absolute(5, 4, false).expect("boundary valid"),
            0
        );
    }

    // --- 3. Request stream state gaps ---

    #[test]
    fn request_stream_trailers_without_data_valid() {
        let mut st = H3RequestStreamState::new();
        st.on_frame(&H3Frame::Headers(vec![0x80]))
            .expect("first HEADERS");
        // RFC 9114 §4.1: trailers are valid without intervening DATA
        // (message format is HEADERS + DATA* + HEADERS? where DATA* = zero or more).
        st.on_frame(&H3Frame::Headers(vec![0x81]))
            .expect("trailers without DATA must succeed per RFC 9114");
    }

    #[test]
    fn request_stream_mark_end_stream_after_headers_only() {
        let mut st = H3RequestStreamState::new();
        st.on_frame(&H3Frame::Headers(vec![0x80]))
            .expect("first HEADERS");
        // Headers-only request: end stream immediately after initial HEADERS.
        st.mark_end_stream().expect("valid headers-only end");
    }

    #[test]
    fn request_stream_mark_end_stream_before_headers_error() {
        let mut st = H3RequestStreamState::new();
        let err = st.mark_end_stream().expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("request stream ended before initial HEADERS")
        );
    }

    #[test]
    fn request_stream_on_frame_after_end_stream_error() {
        let mut st = H3RequestStreamState::new();
        st.on_frame(&H3Frame::Headers(vec![0x80])).expect("HEADERS");
        st.mark_end_stream().expect("end");
        let err = st.on_frame(&H3Frame::Data(vec![1])).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("request stream already finished")
        );
    }

    // --- 4. Connection state gaps ---

    #[test]
    fn finish_request_stream_unknown_stream_id_error() {
        let mut c = H3ConnectionState::new();
        let err = c.finish_request_stream(999).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("unknown request stream on finish")
        );
    }

    #[test]
    fn finished_request_stream_rejects_late_frames() {
        let mut c = H3ConnectionState::new();
        c.on_request_stream_frame(0, &H3Frame::Headers(vec![0x80]))
            .expect("headers");
        c.finish_request_stream(0).expect("finish");
        let err = c
            .on_request_stream_frame(0, &H3Frame::Headers(vec![0x81]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("request stream already finished")
        );
    }

    #[test]
    fn finish_request_stream_twice_reports_finished() {
        let mut c = H3ConnectionState::new();
        c.on_request_stream_frame(0, &H3Frame::Headers(vec![0x80]))
            .expect("headers");
        c.finish_request_stream(0).expect("finish");
        let err = c.finish_request_stream(0).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("request stream already finished")
        );
    }

    #[test]
    fn native_h3_adapter_abort_request_releases_concurrency_and_stays_terminal() {
        let mut c = H3ConnectionState::with_config(H3ConnectionConfig {
            max_concurrent_request_streams: Some(1),
            ..H3ConnectionConfig::default()
        });
        c.on_request_stream_frame(0, &H3Frame::Headers(vec![0x80]))
            .expect("open first request");
        assert_eq!(c.active_request_stream_count(), 1);
        assert!(c.abort_request_stream(0).expect("abort live request"));
        assert_eq!(c.active_request_stream_count(), 0);
        assert!(!c.abort_request_stream(0).expect("abort is idempotent"));
        let late = c
            .on_request_stream_frame(0, &H3Frame::Data(vec![1]))
            .expect_err("late frame on aborted stream must fail");
        assert!(matches!(late, H3NativeError::ControlProtocol(_)));
        c.on_request_stream_frame(4, &H3Frame::Headers(vec![0x80]))
            .expect("successor fits released concurrency slot");
    }

    #[test]
    fn duplicate_qpack_encoder_stream_error() {
        let mut c = H3ConnectionState::new();
        c.on_remote_uni_stream_type(3, H3_STREAM_TYPE_QPACK_ENCODER)
            .expect("first encoder");
        let err = c
            .on_remote_uni_stream_type(7, H3_STREAM_TYPE_QPACK_ENCODER)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("duplicate remote qpack encoder stream")
        );
    }

    #[test]
    fn duplicate_qpack_decoder_stream_error() {
        let mut c = H3ConnectionState::new();
        c.on_remote_uni_stream_type(3, H3_STREAM_TYPE_QPACK_DECODER)
            .expect("first decoder");
        let err = c
            .on_remote_uni_stream_type(7, H3_STREAM_TYPE_QPACK_DECODER)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("duplicate remote qpack decoder stream")
        );
    }

    #[test]
    fn uni_stream_type_already_set_for_same_id_error() {
        let mut c = H3ConnectionState::new();
        c.on_remote_uni_stream_type(3, H3_STREAM_TYPE_CONTROL)
            .expect("first set");
        let err = c
            .on_remote_uni_stream_type(3, H3_STREAM_TYPE_PUSH)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("unidirectional stream type already set")
        );
    }

    #[test]
    fn goaway_decreasing_is_allowed() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        c.on_control_frame(&H3Frame::Goaway(100))
            .expect("first goaway=100");
        assert_eq!(c.goaway_id(), Some(100));
        c.on_control_frame(&H3Frame::Goaway(96))
            .expect("second goaway=96");
        assert_eq!(c.goaway_id(), Some(96));
    }

    #[test]
    fn client_role_rejects_non_request_goaway_id() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        let err = c
            .on_control_frame(&H3Frame::Goaway(10))
            .expect_err("must reject invalid goaway id");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol(
                "GOAWAY id must be a client-initiated bidirectional stream id"
            )
        );
    }

    #[test]
    fn client_role_rejects_max_push_id_control_frame() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        let err = c
            .on_control_frame(&H3Frame::MaxPushId(10))
            .expect_err("client must reject MAX_PUSH_ID from server");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("client must not receive MAX_PUSH_ID")
        );
    }

    #[test]
    fn client_role_goaway_zero_blocks_all_request_streams() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        c.on_control_frame(&H3Frame::Goaway(0)).expect("goaway=0");
        assert_eq!(c.goaway_id(), Some(0));
        // Stream ID 0 is the smallest bidirectional stream; it should be rejected.
        let err = c
            .on_request_stream_frame(0, &H3Frame::Headers(vec![1]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("request stream id rejected after GOAWAY")
        );
    }

    // --- 5. QPACK/settings gaps ---

    #[test]
    fn dynamic_table_allowed_accepts_nonzero_capacity() {
        let config = H3ConnectionConfig {
            qpack_mode: H3QpackMode::DynamicTableAllowed,
            ..H3ConnectionConfig::default()
        };
        let mut c = H3ConnectionState::with_config(config);
        let settings = H3Settings {
            qpack_max_table_capacity: Some(4096),
            qpack_blocked_streams: Some(100),
            ..H3Settings::default()
        };
        c.on_control_frame(&H3Frame::Settings(settings))
            .expect("dynamic table settings accepted");
    }

    #[test]
    fn client_role_rejects_locally_initiated_remote_uni_stream_id() {
        let mut c = H3ConnectionState::new();
        let err = c
            .on_remote_uni_stream_type(2, H3_STREAM_TYPE_CONTROL)
            .expect_err("client must reject locally initiated uni stream id");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol(
                "unidirectional stream type requires peer-initiated unidirectional stream id"
            )
        );
    }

    #[test]
    fn server_role_rejects_server_initiated_remote_uni_stream_id() {
        let mut c = H3ConnectionState::new_server();
        let err = c
            .on_remote_uni_stream_type(3, H3_STREAM_TYPE_CONTROL)
            .expect_err("server must reject its own uni stream ids as remote");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol(
                "unidirectional stream type requires peer-initiated unidirectional stream id"
            )
        );
    }

    #[test]
    fn server_role_rejects_push_streams() {
        let mut c = H3ConnectionState::new_server();
        let err = c
            .on_remote_uni_stream_type(2, H3_STREAM_TYPE_PUSH)
            .expect_err("server must reject client push streams");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("server endpoint must not receive push streams")
        );
    }

    #[test]
    fn qpack_static_plan_request_non_static_method_produces_literal() {
        let req = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("PATCH".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some("/resource".to_string()),
                status: None,
                protocol: None,
            },
            vec![],
        )
        .expect("valid request");
        let plan = qpack_static_plan_for_request(&req);
        // PATCH is not in the QPACK static table, so the first entry must be Literal.
        assert_eq!(
            plan[0],
            QpackFieldPlan::Literal {
                name: ":method".to_string(),
                value: "PATCH".to_string(),
            }
        );
    }

    #[test]
    fn qpack_static_plan_response_non_indexed_status_produces_literal() {
        let resp = H3ResponseHead::new(201, vec![]).expect("valid response");
        let plan = qpack_static_plan_for_response(&resp);
        // 201 is not in the QPACK static table, so the first entry must be Literal.
        assert_eq!(
            plan[0],
            QpackFieldPlan::Literal {
                name: ":status".to_string(),
                value: "201".to_string(),
            }
        );
    }

    #[test]
    fn qpack_wire_roundtrip_static_and_literal_field_lines() {
        let plan = vec![
            QpackFieldPlan::StaticIndex(17), // :method GET
            QpackFieldPlan::StaticIndex(23), // :scheme https
            QpackFieldPlan::StaticIndex(1),  // :path /
            QpackFieldPlan::Literal {
                name: ":authority".to_string(),
                value: "example.com".to_string(),
            },
            QpackFieldPlan::Literal {
                name: "accept".to_string(),
                value: "application/json".to_string(),
            },
        ];

        let encoded = qpack_encode_field_section(&plan).expect("encode");
        let decoded =
            qpack_decode_field_section(&encoded, H3QpackMode::StaticOnly).expect("decode");
        assert_eq!(decoded, plan);

        let headers = qpack_plan_to_header_fields(&decoded, None).expect("expand headers");
        assert_eq!(headers[0], (":method".to_string(), "GET".to_string()));
        assert_eq!(headers[1], (":scheme".to_string(), "https".to_string()));
        assert_eq!(headers[2], (":path".to_string(), "/".to_string()));
        assert_eq!(
            headers[3],
            (":authority".to_string(), "example.com".to_string())
        );
        assert_eq!(
            headers[4],
            ("accept".to_string(), "application/json".to_string())
        );
    }

    #[test]
    fn qpack_wire_request_and_response_helpers_roundtrip() {
        let request = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("POST".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("api.example.com".to_string()),
                path: Some("/upload".to_string()),
                status: None,
                protocol: None,
            },
            vec![("content-type".to_string(), "application/json".to_string())],
        )
        .expect("request");
        let request_plan = qpack_static_plan_for_request(&request);
        let request_wire = qpack_encode_request_field_section(&request).expect("request encode");
        let request_decoded = qpack_decode_field_section(&request_wire, H3QpackMode::StaticOnly)
            .expect("request decode");
        assert_eq!(request_decoded, request_plan);

        let response = H3ResponseHead::new(
            200,
            vec![("content-type".to_string(), "text/plain".to_string())],
        )
        .expect("response");
        let response_plan = qpack_static_plan_for_response(&response);
        let response_wire =
            qpack_encode_response_field_section(&response).expect("response encode");
        let response_decoded = qpack_decode_field_section(&response_wire, H3QpackMode::StaticOnly)
            .expect("response decode");
        assert_eq!(response_decoded, response_plan);
    }

    #[test]
    fn qpack_wire_decode_request_head_helper_roundtrip() {
        let request = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("api.example.com".to_string()),
                path: Some("/v1/items".to_string()),
                status: None,
                protocol: None,
            },
            vec![("accept".to_string(), "application/json".to_string())],
        )
        .expect("request");
        let wire = qpack_encode_request_field_section(&request).expect("encode");
        let decoded = qpack_decode_request_field_section(&wire, H3QpackMode::StaticOnly, None)
            .expect("decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn qpack_wire_decode_response_head_helper_roundtrip() {
        let response = H3ResponseHead::new(
            200,
            vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("server".to_string(), "asupersync".to_string()),
            ],
        )
        .expect("response");
        let wire = qpack_encode_response_field_section(&response).expect("encode");
        let decoded = qpack_decode_response_field_section(&wire, H3QpackMode::StaticOnly, None)
            .expect("decode");
        assert_eq!(decoded, response);
    }

    #[test]
    fn native_h3_adapter_qpack_trailers_accept_fields_and_reject_pseudo_headers() {
        let trailers = vec![("x-checksum".to_string(), "abc123".to_string())];
        let wire = qpack_encode_trailer_field_section(&trailers).expect("encode trailers");
        assert_eq!(
            qpack_decode_trailer_field_section(&wire, H3QpackMode::StaticOnly, None)
                .expect("decode trailers"),
            trailers
        );

        let err = qpack_encode_trailer_field_section(&[(":status".to_string(), "200".to_string())])
            .expect_err("trailers must reject pseudo headers");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("pseudo header forbidden in HTTP/3 trailers")
        );
    }

    #[test]
    fn qpack_request_decode_rejects_pseudo_after_regular_header() {
        let plan = vec![
            QpackFieldPlan::Literal {
                name: "accept".to_string(),
                value: "*/*".to_string(),
            },
            QpackFieldPlan::StaticIndex(17), // :method GET
            QpackFieldPlan::StaticIndex(23), // :scheme https
            QpackFieldPlan::StaticIndex(1),  // :path /
        ];
        let wire = qpack_encode_field_section(&plan).expect("encode");
        let err = qpack_decode_request_field_section(&wire, H3QpackMode::StaticOnly, None)
            .expect_err("fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(
                "request pseudo headers must precede regular headers",
            )
        );
    }

    #[test]
    fn qpack_request_decode_rejects_duplicate_method() {
        let plan = vec![
            QpackFieldPlan::StaticIndex(17), // :method GET
            QpackFieldPlan::Literal {
                name: ":method".to_string(),
                value: "POST".to_string(),
            },
            QpackFieldPlan::StaticIndex(23), // :scheme https
            QpackFieldPlan::StaticIndex(1),  // :path /
        ];
        let wire = qpack_encode_field_section(&plan).expect("encode");
        let err = qpack_decode_request_field_section(&wire, H3QpackMode::StaticOnly, None)
            .expect_err("fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("duplicate :method")
        );
    }

    #[test]
    fn qpack_response_decode_rejects_invalid_status_value() {
        let plan = vec![QpackFieldPlan::Literal {
            name: ":status".to_string(),
            value: "ok".to_string(),
        }];
        let wire = qpack_encode_field_section(&plan).expect("encode");
        let err = qpack_decode_response_field_section(&wire, H3QpackMode::StaticOnly, None)
            .expect_err("fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader("invalid :status value")
        );
    }

    #[test]
    fn response_decode_rejects_zero_padded_status_value() {
        let fields = vec![(":status".to_string(), "020".to_string())];
        let err = header_fields_to_response_head(&fields).expect_err("must reject zero-padded");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader("status must be in 100..=999")
        );
    }

    #[test]
    fn qpack_response_decode_rejects_non_three_digit_status_value() {
        let plan = vec![QpackFieldPlan::Literal {
            name: ":status".to_string(),
            value: "0200".to_string(),
        }];
        let wire = qpack_encode_field_section(&plan).expect("encode");
        let err = qpack_decode_response_field_section(&wire, H3QpackMode::StaticOnly, None)
            .expect_err("fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader("invalid :status value")
        );
    }

    #[test]
    fn qpack_response_decode_rejects_request_pseudo_header() {
        let plan = vec![
            QpackFieldPlan::StaticIndex(25), // :status 200
            QpackFieldPlan::Literal {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
        ];
        let wire = qpack_encode_field_section(&plan).expect("encode");
        let err = qpack_decode_response_field_section(&wire, H3QpackMode::StaticOnly, None)
            .expect_err("fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader(
                "response must not include request pseudo headers",
            )
        );
    }

    #[test]
    fn qpack_wire_static_only_rejects_required_insert_count() {
        // required_insert_count = 1, base = 0, then indexed static(:method GET).
        let wire = [0x01u8, 0x00, 0xD1];
        let err = qpack_decode_field_section(&wire, H3QpackMode::StaticOnly).expect_err("reject");
        assert_eq!(
            err,
            H3NativeError::QpackPolicy("required insert count must be zero in static-only mode")
        );
    }

    #[test]
    fn qpack_dynamic_decode_rejects_required_insert_count_beyond_table_state() {
        let mut context = QpackContext::new(4096);
        context
            .insert_dynamic_entry("x-one".to_string(), "value-1".to_string())
            .expect("insert entry");

        // Encoded Required Insert Count = 3 decodes to ReqInsertCount = 2 when
        // MaxEntries = 128. The decoder only knows about one insert, so it must
        // fail cleanly instead of speculatively resolving a dynamic reference.
        let wire = [0x03u8, 0x00, 0x80];
        let err = qpack_decode_field_section_with_context(
            &wire,
            H3QpackMode::DynamicTableAllowed,
            Some(&context),
        )
        .expect_err("required insert count should block decode");
        assert_eq!(
            err,
            H3NativeError::QpackPolicy("required insert count exceeds dynamic table state")
        );
    }

    #[test]
    fn qpack_dynamic_decode_resolves_relative_index_with_nonzero_ric() {
        let mut context = QpackContext::new(4096);
        context
            .insert_dynamic_entry("x-old".to_string(), "old".to_string())
            .expect("insert old entry");
        context
            .insert_dynamic_entry("x-middle".to_string(), "middle".to_string())
            .expect("insert middle entry");
        context
            .insert_dynamic_entry("x-new".to_string(), "new".to_string())
            .expect("insert new entry");

        // EncRIC=3 => ReqInsertCount=2 with MaxEntries=128. Base=2, so dynamic
        // relative index 0 resolves to absolute index 1 (the middle entry).
        let wire = [0x03u8, 0x00, 0x80];
        let plan = qpack_decode_field_section_with_context(
            &wire,
            H3QpackMode::DynamicTableAllowed,
            Some(&context),
        )
        .expect("decode dynamic field section");
        assert_eq!(plan, vec![QpackFieldPlan::DynamicIndex(1)]);

        let fields = qpack_plan_to_header_fields(&plan, Some(&context)).expect("resolve fields");
        assert_eq!(fields, vec![("x-middle".to_string(), "middle".to_string())]);
    }

    #[test]
    fn qpack_required_insert_count_encoder_matches_decoder_boundaries() {
        for required_insert_count in [1, 2, 3, 127, 128, 129, 255, 256, 257] {
            let encoded =
                qpack_encode_required_insert_count(required_insert_count, 4096).expect("encode");
            let decoded = qpack_decode_required_insert_count(encoded, required_insert_count, 4096)
                .expect("decode");
            assert_eq!(
                decoded, required_insert_count,
                "required insert count {required_insert_count} encoded as {encoded}"
            );
        }
    }

    #[test]
    fn qpack_dynamic_lookup_preserves_evicted_absolute_gaps() {
        let mut table = QpackDynamicTable::new(76);
        let old = table
            .insert("old".to_string(), "1".to_string())
            .expect("insert old");
        let middle = table
            .insert("middle".to_string(), "2".to_string())
            .expect("insert middle");
        assert!(table.reference_entry(old));

        let new = table
            .insert("new".to_string(), "3".to_string())
            .expect("insert new");

        assert_eq!(old, 0);
        assert_eq!(middle, 1);
        assert_eq!(new, 2);
        assert_eq!(table.evicted_count(), 1);
        assert_eq!(qpack_dynamic_entry(&table, old), Some(("old", "1")));
        assert_eq!(qpack_dynamic_entry(&table, middle), None);
        assert_eq!(qpack_dynamic_entry(&table, new), Some(("new", "3")));
    }

    #[test]
    fn qpack_wire_decodes_huffman_strings_in_static_mode() {
        let mut encoded_value = BytesMut::new();
        hpack_encode_huffman(&mut encoded_value, b"www.example.com");

        let mut wire = vec![0x00u8, 0x00];
        // Literal-with-name-reference, static :authority (index 0).
        qpack_encode_prefixed_int(&mut wire, 0x50, 4, 0).expect("encode name ref");
        qpack_encode_prefixed_int(&mut wire, 0x80, 7, encoded_value.len() as u64)
            .expect("encode huffman string len");
        wire.extend_from_slice(&encoded_value);

        let plan = qpack_decode_field_section(&wire, H3QpackMode::StaticOnly).expect("decode");
        assert_eq!(
            plan,
            vec![QpackFieldPlan::Literal {
                name: ":authority".to_string(),
                value: "www.example.com".to_string(),
            }]
        );
    }

    #[test]
    fn qpack_dynamic_wire_encode_roundtrips_with_context() {
        let mut context = QpackContext::new(4096);
        context
            .insert_dynamic_entry("x-old".to_string(), "old".to_string())
            .expect("insert old entry");
        context
            .insert_dynamic_entry("x-middle".to_string(), "middle".to_string())
            .expect("insert middle entry");
        context
            .insert_dynamic_entry("x-new".to_string(), "new".to_string())
            .expect("insert new entry");

        let plan = vec![
            QpackFieldPlan::DynamicIndex(1),
            QpackFieldPlan::DynamicNameLiteral {
                name_index: 2,
                value: "tail".to_string(),
            },
        ];

        let wire =
            qpack_encode_field_section_with_context(&plan, Some(&context)).expect("encode wire");
        let decoded = qpack_decode_field_section_with_context(
            &wire,
            H3QpackMode::DynamicTableAllowed,
            Some(&context),
        )
        .expect("decode wire");
        assert_eq!(decoded, plan);

        let headers = qpack_plan_to_header_fields(&decoded, Some(&context)).expect("resolve");
        assert_eq!(
            headers,
            vec![
                ("x-middle".to_string(), "middle".to_string()),
                ("x-new".to_string(), "tail".to_string()),
            ]
        );
    }

    #[test]
    fn qpack_dynamic_decode_resolves_post_base_lines() {
        let mut context = QpackContext::new(4096);
        context
            .insert_dynamic_entry("x-old".to_string(), "old".to_string())
            .expect("insert old entry");
        context
            .insert_dynamic_entry("x-middle".to_string(), "middle".to_string())
            .expect("insert middle entry");
        context
            .insert_dynamic_entry("x-new".to_string(), "new".to_string())
            .expect("insert new entry");

        // EncRIC=4 => ReqInsertCount=3. S=1, DeltaBase=0 => Base=2.
        // Indexed post-base index 0 => absolute index 2 ("x-new").
        // Literal post-base name ref index 0 => absolute name index 2 ("x-new").
        let wire = [0x04u8, 0x80, 0x10, 0x00, 0x04, b't', b'a', b'i', b'l'];
        let plan = qpack_decode_field_section_with_context(
            &wire,
            H3QpackMode::DynamicTableAllowed,
            Some(&context),
        )
        .expect("decode post-base wire");
        assert_eq!(
            plan,
            vec![
                QpackFieldPlan::DynamicIndex(2),
                QpackFieldPlan::DynamicNameLiteral {
                    name_index: 2,
                    value: "tail".to_string(),
                },
            ]
        );
    }

    #[test]
    fn qpack_decode_rejects_field_sections_over_header_count_limit() {
        let plan: Vec<_> = (0..=QPACK_MAX_DECODED_HEADERS)
            .map(|_| QpackFieldPlan::Literal {
                name: "x-test".to_string(),
                value: String::new(),
            })
            .collect();
        let wire = qpack_encode_field_section(&plan).expect("encode");

        let err = qpack_decode_field_section(&wire, H3QpackMode::StaticOnly).expect_err("reject");
        assert_eq!(
            err,
            H3NativeError::QpackPolicy("decoded header count exceeds safety limit")
        );
    }

    #[test]
    fn qpack_request_decode_with_limit_rejects_oversized_field_section() {
        let plan = vec![QpackFieldPlan::Literal {
            name: "x-test".to_string(),
            value: "abcdef".to_string(),
        }];
        let wire = qpack_encode_field_section(&plan).expect("encode");

        let err = qpack_decode_request_field_section_with_limit(
            &wire,
            H3QpackMode::StaticOnly,
            None,
            Some(40),
        )
        .expect_err("reject oversized field section");
        assert_eq!(
            err,
            H3NativeError::QpackPolicy("decoded field section exceeds maximum size limit")
        );
    }

    #[test]
    fn qpack_plan_to_header_fields_rejects_unknown_static_index() {
        let err = qpack_plan_to_header_fields(&[QpackFieldPlan::StaticIndex(999)], None)
            .expect_err("unknown static index");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown static qpack index")
        );
    }

    #[test]
    fn qpack_wire_decode_rejects_unknown_static_index() {
        // Field section prefix (RIC=0, base=0), then indexed static with index=99
        // encoded as 63 + continuation byte 36.
        let wire = [0x00u8, 0x00, 0xFF, 0x24];
        let err = qpack_decode_field_section(&wire, H3QpackMode::StaticOnly).expect_err("reject");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown static qpack index")
        );
    }

    #[test]
    fn qpack_wire_encode_rejects_unknown_static_index() {
        let err = qpack_encode_field_section(&[QpackFieldPlan::StaticIndex(999)])
            .expect_err("unknown static index");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown static qpack index")
        );
    }

    #[test]
    fn qpack_prefixed_int_rejects_high_shift_truncation() {
        // Build a QPACK integer with 9 continuation bytes that push shift to 63.
        // At shift=63, checked_shl(63) silently truncates (e.g., 2u64 << 63 = 0)
        // because checked_shl only checks shift >= bit_width, not result overflow.
        // prefix_len=8, first byte = 0xFF (max prefix = 255), then 9 continuation
        // bytes of 0x80 (part=0, continuation bit set). After the 9th continuation
        // byte at shift=56, shift advances to 63 which exceeds our cap of 56.
        let mut wire = vec![0xFFu8]; // max prefix
        wire.extend(std::iter::repeat_n(0x80, 9)); // continuation, part=0 — 9 bytes push shift from 0→63
        wire.push(0x02); // part=2, no continuation — would be decoded at shift=63
        // With the fix, the 9th continuation byte advances shift to 63 > 56 → error.
        let result = qpack_decode_prefixed_int(0xFF, 8, &wire[1..]);
        assert!(
            result.is_err(),
            "must reject integer that would silently truncate at high shifts"
        );
    }

    #[test]
    fn qpack_encoder_instruction_roundtrips_all_variants() {
        let cases = [
            QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 4096 },
            QpackEncoderInstruction::InsertWithNameReference {
                name: QpackInstructionNameRef::Static(1),
                value: "/index.html".to_string(),
            },
            QpackEncoderInstruction::InsertWithNameReference {
                name: QpackInstructionNameRef::Dynamic(2),
                value: "dynamic-value".to_string(),
            },
            QpackEncoderInstruction::InsertWithoutNameReference {
                name: "x-custom".to_string(),
                value: "literal-value".to_string(),
            },
            QpackEncoderInstruction::Duplicate { index: 3 },
        ];

        for instruction in cases {
            let mut wire = Vec::new();
            qpack_encode_encoder_instruction(&mut wire, &instruction).expect("encode");
            let (decoded, consumed) =
                qpack_decode_encoder_instruction(&wire).expect("decode encoder instruction");
            assert_eq!(decoded, instruction);
            assert_eq!(consumed, wire.len());
        }
    }

    #[test]
    fn qpack_encoder_instruction_uses_expected_wire_prefixes() {
        let cases = [
            (
                QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 0 },
                0b0010_0000,
            ),
            (
                QpackEncoderInstruction::InsertWithNameReference {
                    name: QpackInstructionNameRef::Static(0),
                    value: String::new(),
                },
                0b1100_0000,
            ),
            (
                QpackEncoderInstruction::InsertWithNameReference {
                    name: QpackInstructionNameRef::Dynamic(0),
                    value: String::new(),
                },
                0b1000_0000,
            ),
            (
                QpackEncoderInstruction::InsertWithoutNameReference {
                    name: String::new(),
                    value: String::new(),
                },
                0b0100_0000,
            ),
            (QpackEncoderInstruction::Duplicate { index: 0 }, 0b0000_0000),
        ];

        for (instruction, expected_first) in cases {
            let mut wire = Vec::new();
            qpack_encode_encoder_instruction(&mut wire, &instruction).expect("encode");
            assert_eq!(wire[0], expected_first);
        }
    }

    #[test]
    fn qpack_decoder_instruction_roundtrips_all_variants() {
        let cases = [
            QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 0 },
            QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 4 },
            QpackDecoderInstruction::StreamCancellation { stream_id: 8 },
            QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
            QpackDecoderInstruction::InsertCountIncrement { increment: 128 },
        ];

        for instruction in cases {
            let mut wire = Vec::new();
            qpack_encode_decoder_instruction(&mut wire, &instruction).expect("encode");
            let (decoded, consumed) =
                qpack_decode_decoder_instruction(&wire).expect("decode decoder instruction");
            assert_eq!(decoded, instruction);
            assert_eq!(consumed, wire.len());
        }
    }

    #[test]
    fn qpack_decoder_instruction_uses_expected_wire_prefixes() {
        let cases = [
            (
                QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 0 },
                0b1000_0000,
            ),
            (
                QpackDecoderInstruction::StreamCancellation { stream_id: 0 },
                0b0100_0000,
            ),
            (
                QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
                0b0000_0001,
            ),
        ];

        for (instruction, expected_first) in cases {
            let mut wire = Vec::new();
            qpack_encode_decoder_instruction(&mut wire, &instruction).expect("encode");
            assert_eq!(wire[0], expected_first);
        }
    }

    #[test]
    fn qpack_instruction_prefixed_integer_boundaries() {
        for capacity in [30, 31, 32, 1337, u16::MAX as u64] {
            let instruction = QpackEncoderInstruction::SetDynamicTableCapacity { capacity };
            let mut wire = Vec::new();
            qpack_encode_encoder_instruction(&mut wire, &instruction).expect("encode");
            let (decoded, consumed) =
                qpack_decode_encoder_instruction(&wire).expect("decode capacity");
            assert_eq!(decoded, instruction);
            assert_eq!(consumed, wire.len());
        }

        for stream_id in [126, 127, 128, 16_384] {
            let instruction = QpackDecoderInstruction::HeaderAcknowledgement { stream_id };
            let mut wire = Vec::new();
            qpack_encode_decoder_instruction(&mut wire, &instruction).expect("encode");
            let (decoded, consumed) =
                qpack_decode_decoder_instruction(&wire).expect("decode stream id");
            assert_eq!(decoded, instruction);
            assert_eq!(consumed, wire.len());
        }
    }

    #[test]
    fn qpack_instruction_string_edges_roundtrip() {
        let cases = [
            QpackEncoderInstruction::InsertWithNameReference {
                name: QpackInstructionNameRef::Static(0),
                value: String::new(),
            },
            QpackEncoderInstruction::InsertWithNameReference {
                name: QpackInstructionNameRef::Dynamic(0),
                value: "www.example.com".to_string(),
            },
            QpackEncoderInstruction::InsertWithoutNameReference {
                name: String::new(),
                value: String::new(),
            },
            QpackEncoderInstruction::InsertWithoutNameReference {
                name: "x-long-name".repeat(40),
                value: "large-bounded-value".repeat(40),
            },
        ];

        for instruction in cases {
            let mut wire = Vec::new();
            qpack_encode_encoder_instruction(&mut wire, &instruction).expect("encode");
            let (decoded, consumed) =
                qpack_decode_encoder_instruction(&wire).expect("decode string instruction");
            assert_eq!(decoded, instruction);
            assert_eq!(consumed, wire.len());
        }
    }

    #[test]
    fn qpack_instruction_value_string_uses_huffman_when_smaller() {
        let instruction = QpackEncoderInstruction::InsertWithNameReference {
            name: QpackInstructionNameRef::Static(0),
            value: "www.example.com".to_string(),
        };
        let mut wire = Vec::new();
        qpack_encode_encoder_instruction(&mut wire, &instruction).expect("encode");

        // Static name reference index 0 fits in the first byte, so byte 1 is
        // the value string prefix. Its high bit is the QPACK Huffman flag for
        // a 7-bit string prefix.
        assert_ne!(wire[1] & 0b1000_0000, 0);

        let (decoded, consumed) =
            qpack_decode_encoder_instruction(&wire).expect("decode huffman value");
        assert_eq!(decoded, instruction);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn qpack_instruction_decode_reports_consumed_prefix_only() {
        let instruction = QpackEncoderInstruction::Duplicate { index: 31 };
        let mut wire = Vec::new();
        qpack_encode_encoder_instruction(&mut wire, &instruction).expect("encode");
        let expected_instruction_len = wire.len();
        wire.extend_from_slice(&[0xAA, 0xBB]);

        let (decoded, consumed) =
            qpack_decode_encoder_instruction(&wire).expect("decode with trailing bytes");
        assert_eq!(decoded, instruction);
        assert_eq!(consumed, expected_instruction_len);
    }

    #[test]
    fn qpack_decoder_instruction_decode_reports_consumed_prefix_only() {
        let instruction = QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 127 };
        let mut wire = Vec::new();
        qpack_encode_decoder_instruction(&mut wire, &instruction).expect("encode");
        let expected_instruction_len = wire.len();
        wire.extend_from_slice(&[0xCC, 0xDD]);

        let (decoded, consumed) =
            qpack_decode_decoder_instruction(&wire).expect("decode with trailing bytes");
        assert_eq!(decoded, instruction);
        assert_eq!(consumed, expected_instruction_len);
    }

    #[test]
    fn qpack_encoder_instruction_rejects_truncated_capacity_integer() {
        // Set Dynamic Table Capacity with inline prefix saturated to 31, but no
        // continuation byte.
        let err = qpack_decode_encoder_instruction(&[0x3F]).expect_err("truncated capacity");
        assert_eq!(err, H3NativeError::UnexpectedEof);
    }

    #[test]
    fn qpack_encoder_instruction_rejects_overflow_capacity_integer() {
        let mut wire = vec![0x3Fu8];
        wire.extend(std::iter::repeat_n(0x80, 9));
        wire.push(0x02);

        let err = qpack_decode_encoder_instruction(&wire).expect_err("overflow capacity");
        assert_eq!(err, H3NativeError::InvalidFrame("qpack integer overflow"));
    }

    #[test]
    fn qpack_encoder_instruction_rejects_truncated_value_string() {
        // Insert With Name Reference: static name index 0, but no value string.
        let err = qpack_decode_encoder_instruction(&[0xC0]).expect_err("missing value");
        assert_eq!(err, H3NativeError::UnexpectedEof);
    }

    #[test]
    fn qpack_encoder_instruction_rejects_truncated_value_length_integer() {
        // Insert With Name Reference: static name index 0, then value length
        // prefix saturated to 127 without its required continuation byte.
        let err =
            qpack_decode_encoder_instruction(&[0xC0, 0x7F]).expect_err("truncated value length");
        assert_eq!(err, H3NativeError::UnexpectedEof);
    }

    #[test]
    fn qpack_encoder_instruction_rejects_truncated_literal_name() {
        // Insert Without Name Reference with literal name length 3, but only one byte follows.
        let err =
            qpack_decode_encoder_instruction(&[0x43, b'x']).expect_err("truncated literal name");
        assert_eq!(err, H3NativeError::UnexpectedEof);
    }

    #[test]
    fn qpack_decoder_instruction_rejects_truncated_stream_id_integer() {
        // Header Acknowledgement with inline prefix saturated to 127, but no
        // continuation byte.
        let err =
            qpack_decode_decoder_instruction(&[0xFF]).expect_err("truncated stream id integer");
        assert_eq!(err, H3NativeError::UnexpectedEof);
    }

    #[test]
    fn qpack_decoder_instruction_rejects_zero_insert_count_increment() {
        let err = qpack_encode_decoder_instruction(
            &mut Vec::new(),
            &QpackDecoderInstruction::InsertCountIncrement { increment: 0 },
        )
        .expect_err("zero increment encode must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("qpack insert count increment must be non-zero")
        );

        let err =
            qpack_decode_decoder_instruction(&[0x00]).expect_err("zero increment decode must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("qpack insert count increment must be non-zero")
        );
    }

    #[test]
    fn qpack_decoder_feedback_ack_releases_references_and_tracks_fields() {
        let mut context = QpackContext::new(128);
        let first = context
            .insert_dynamic_entry("one".to_string(), "1".to_string())
            .expect("insert first");
        let second = context
            .insert_dynamic_entry("two".to_string(), "2".to_string())
            .expect("insert second");
        let mut feedback = QpackDecoderFeedbackState::new();

        feedback
            .track_stream_references(&mut context, 4, &[first, second])
            .expect("track references");
        assert_eq!(feedback.known_received_count(), 0);
        assert_eq!(feedback.stream_outstanding_reference_count(4), 2);
        assert_eq!(feedback.outstanding_reference_count(), 2);
        assert_eq!(feedback.first_error(), None);
        assert_eq!(
            context
                .set_dynamic_table_capacity(0)
                .expect_err("referenced entries must block shrink"),
            "cannot reduce table capacity while entries are referenced"
        );

        qpack_apply_decoder_instruction(
            &mut feedback,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 4 },
        )
        .expect("ack releases references");

        assert!(feedback.acknowledged_stream_ids().contains(&4));
        assert!(!feedback.cancelled_stream_ids().contains(&4));
        assert_eq!(feedback.stream_outstanding_reference_count(4), 0);
        assert_eq!(feedback.outstanding_reference_count(), 0);
        assert_eq!(feedback.first_error(), None);
        context
            .set_dynamic_table_capacity(0)
            .expect("released references allow shrink");
    }

    #[test]
    fn qpack_decoder_feedback_ack_rejects_unknown_duplicate_and_cancelled() {
        let mut context = QpackContext::new(128);
        let mut feedback = QpackDecoderFeedbackState::new();

        let err = qpack_apply_decoder_instruction(
            &mut feedback,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 4 },
        )
        .expect_err("unknown stream");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown qpack decoder feedback stream")
        );
        assert_eq!(feedback.first_error(), Some(&err));

        let mut duplicate = QpackDecoderFeedbackState::new();
        duplicate
            .track_stream_references(&mut context, 8, &[])
            .expect("track empty references");
        qpack_apply_decoder_instruction(
            &mut duplicate,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 8 },
        )
        .expect("first ack");
        let err = qpack_apply_decoder_instruction(
            &mut duplicate,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 8 },
        )
        .expect_err("duplicate ack");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("duplicate qpack header acknowledgement")
        );
        assert_eq!(duplicate.first_error(), Some(&err));

        let mut cancelled = QpackDecoderFeedbackState::new();
        cancelled
            .track_stream_references(&mut context, 12, &[])
            .expect("track stream");
        qpack_apply_decoder_instruction(
            &mut cancelled,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::StreamCancellation { stream_id: 12 },
        )
        .expect("cancel");
        let err = qpack_apply_decoder_instruction(
            &mut cancelled,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 12 },
        )
        .expect_err("ack after cancel");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("qpack acknowledgement after stream cancellation")
        );
    }

    #[test]
    fn qpack_decoder_feedback_cancellation_releases_references_and_rejects_edges() {
        let mut context = QpackContext::new(128);
        let mut unknown = QpackDecoderFeedbackState::new();
        let err = qpack_apply_decoder_instruction(
            &mut unknown,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::StreamCancellation { stream_id: 14 },
        )
        .expect_err("unknown cancellation stream");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown qpack decoder feedback stream")
        );
        assert_eq!(unknown.first_error(), Some(&err));

        let insertion_id = context
            .insert_dynamic_entry("ref".to_string(), "value".to_string())
            .expect("insert reference");
        let mut feedback = QpackDecoderFeedbackState::new();
        feedback
            .track_stream_references(&mut context, 16, &[insertion_id])
            .expect("track references");

        qpack_apply_decoder_instruction(
            &mut feedback,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::StreamCancellation { stream_id: 16 },
        )
        .expect("cancel releases references");
        assert!(feedback.cancelled_stream_ids().contains(&16));
        assert!(!feedback.acknowledged_stream_ids().contains(&16));
        assert_eq!(feedback.outstanding_reference_count(), 0);
        context
            .set_dynamic_table_capacity(0)
            .expect("cancellation released references");

        let err = qpack_apply_decoder_instruction(
            &mut feedback,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::StreamCancellation { stream_id: 16 },
        )
        .expect_err("duplicate cancellation");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("duplicate qpack stream cancellation")
        );

        let mut acked = QpackDecoderFeedbackState::new();
        acked
            .track_stream_references(&mut context, 20, &[])
            .expect("track acked stream");
        qpack_apply_decoder_instruction(
            &mut acked,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 20 },
        )
        .expect("ack");
        let err = qpack_apply_decoder_instruction(
            &mut acked,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::StreamCancellation { stream_id: 20 },
        )
        .expect_err("cancel after ack");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("qpack stream cancellation after acknowledgement")
        );
    }

    #[test]
    fn qpack_decoder_feedback_insert_count_increment_boundaries() {
        let mut context = QpackContext::new(4096);
        // The encoder has inserted three entries; the Known Received Count may
        // advance up to three but RFC 9204 §4.4.3 forbids it going beyond.
        for i in 0..3 {
            context
                .insert_dynamic_entry(format!("k{i}"), format!("v{i}"))
                .expect("insert dynamic entry");
        }
        assert_eq!(context.dynamic_table().insertion_counter(), 3);

        let mut feedback = QpackDecoderFeedbackState::new();
        qpack_apply_decoder_instruction(
            &mut feedback,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
        )
        .expect("increment one");
        assert_eq!(feedback.known_received_count(), 1);
        qpack_apply_decoder_instruction(
            &mut feedback,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::InsertCountIncrement { increment: 2 },
        )
        .expect("advance to the insert boundary");
        assert_eq!(feedback.known_received_count(), 3);

        // Overshoot one past the insertion counter -> decoder-stream error.
        let err = qpack_apply_decoder_instruction(
            &mut feedback,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
        )
        .expect_err("known received count beyond inserts must be rejected");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("qpack known received count exceeds encoder insert count")
        );
        assert_eq!(
            feedback.known_received_count(),
            3,
            "a rejected increment must not advance the count"
        );
        assert_eq!(feedback.first_error(), Some(&err));

        // A huge increment from zero is bounded by inserts just the same (the old
        // u64::MAX path is now an overshoot, not a saturating accept).
        let mut huge = QpackDecoderFeedbackState::new();
        let err = qpack_apply_decoder_instruction(
            &mut huge,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::InsertCountIncrement {
                increment: u64::MAX,
            },
        )
        .expect_err("overshoot via a huge increment");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("qpack known received count exceeds encoder insert count")
        );
        assert_eq!(huge.known_received_count(), 0);

        let mut zero = QpackDecoderFeedbackState::new();
        let err = qpack_apply_decoder_instruction(
            &mut zero,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::InsertCountIncrement { increment: 0 },
        )
        .expect_err("zero increment");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("qpack decoder feedback increment must be non-zero")
        );
        assert_eq!(zero.known_received_count(), 0);
        assert_eq!(zero.first_error(), Some(&err));
    }

    #[test]
    fn qpack_decoder_feedback_static_only_rejects_before_mutation() {
        let mut context = QpackContext::new(128);
        let mut feedback = QpackDecoderFeedbackState::new();
        feedback
            .track_stream_references(&mut context, 24, &[])
            .expect("track stream");

        let before = feedback.clone();
        let err = qpack_apply_decoder_instruction(
            &mut feedback,
            &mut context,
            H3QpackMode::StaticOnly,
            &QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 24 },
        )
        .expect_err("static-only rejects decoder feedback");
        assert_eq!(
            err,
            H3NativeError::QpackPolicy("decoder feedback requires dynamic qpack mode")
        );
        assert_eq!(feedback.first_error(), Some(&err));
        assert_eq!(
            feedback.known_received_count(),
            before.known_received_count()
        );
        assert_eq!(
            feedback.acknowledged_stream_ids(),
            before.acknowledged_stream_ids()
        );
        assert_eq!(
            feedback.cancelled_stream_ids(),
            before.cancelled_stream_ids()
        );
        assert_eq!(
            feedback.outstanding_reference_count(),
            before.outstanding_reference_count()
        );
    }

    #[test]
    fn qpack_decoder_feedback_track_rejects_duplicate_terminal_and_unknown_reference() {
        let mut context = QpackContext::new(128);
        let mut feedback = QpackDecoderFeedbackState::new();

        let err = feedback
            .track_stream_references(&mut context, 28, &[0])
            .expect_err("unknown reference");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown dynamic qpack reference for stream")
        );
        assert_eq!(feedback.first_error(), Some(&err));

        let mut duplicate = QpackDecoderFeedbackState::new();
        duplicate
            .track_stream_references(&mut context, 32, &[])
            .expect("track once");
        let err = duplicate
            .track_stream_references(&mut context, 32, &[])
            .expect_err("duplicate track");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("qpack stream already tracked")
        );

        let mut terminal = QpackDecoderFeedbackState::new();
        terminal
            .track_stream_references(&mut context, 36, &[])
            .expect("track terminal");
        qpack_apply_decoder_instruction(
            &mut terminal,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 36 },
        )
        .expect("ack terminal");
        let err = terminal
            .track_stream_references(&mut context, 36, &[])
            .expect_err("cannot retrack acked stream");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("qpack stream already acknowledged")
        );
    }

    fn qpack_dynamic_wire(
        context: &QpackContext,
        insertion_id: u64,
    ) -> Result<Vec<u8>, H3NativeError> {
        qpack_encode_field_section_with_context(
            &[QpackFieldPlan::DynamicIndex(insertion_id)],
            Some(context),
        )
    }

    #[test]
    fn qpack_blocked_scheduler_ready_tracks_and_ack_releases_references() {
        let mut context = QpackContext::new(128);
        let insertion_id = context
            .insert_dynamic_entry("x-ready".to_string(), "ready".to_string())
            .expect("insert dynamic entry");
        let wire = qpack_dynamic_wire(&context, insertion_id).expect("encode field section");
        let mut feedback = QpackDecoderFeedbackState::new();
        let mut scheduler = QpackBlockedStreamScheduler::new(1);

        scheduler
            .apply_decoder_instruction(
                &mut feedback,
                &mut context,
                H3QpackMode::DynamicTableAllowed,
                &QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
            )
            .expect("advance known received count");
        let status = scheduler
            .submit_field_section(
                &mut context,
                &mut feedback,
                H3QpackMode::DynamicTableAllowed,
                4,
                &wire,
            )
            .expect("schedule ready stream");

        assert_eq!(status, QpackBlockedStreamStatus::Ready);
        assert_eq!(scheduler.blocked_stream_count(), 0);
        let record = scheduler.record(4).expect("record");
        assert_eq!(record.required_insert_count(), 1);
        assert_eq!(record.base(), 1);
        assert_eq!(record.protected_references(), &[insertion_id]);
        assert_eq!(
            context
                .set_dynamic_table_capacity(0)
                .expect_err("ready stream still protects referenced entry"),
            "cannot reduce table capacity while entries are referenced"
        );

        scheduler
            .apply_decoder_instruction(
                &mut feedback,
                &mut context,
                H3QpackMode::DynamicTableAllowed,
                &QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 4 },
            )
            .expect("ack releases references");
        assert_eq!(scheduler.record(4), None);
        assert!(feedback.acknowledged_stream_ids().contains(&4));
        context
            .set_dynamic_table_capacity(0)
            .expect("ack released protected entry");
    }

    #[test]
    fn qpack_blocked_scheduler_capacity_zero_and_static_only_fail_closed() {
        let mut context = QpackContext::new(128);
        let insertion_id = context
            .insert_dynamic_entry("x-blocked".to_string(), "blocked".to_string())
            .expect("insert dynamic entry");
        let wire = qpack_dynamic_wire(&context, insertion_id).expect("encode field section");
        let mut feedback = QpackDecoderFeedbackState::new();
        let mut scheduler = QpackBlockedStreamScheduler::new(0);

        let err = scheduler
            .submit_field_section(
                &mut context,
                &mut feedback,
                H3QpackMode::DynamicTableAllowed,
                4,
                &wire,
            )
            .expect_err("zero capacity rejects blocked field section");
        assert_eq!(
            err,
            H3NativeError::QpackPolicy("qpack blocked stream capacity is zero")
        );
        assert_eq!(scheduler.blocked_stream_count(), 0);
        let record = scheduler.record(4).expect("failed record");
        assert_eq!(record.status(), QpackBlockedStreamStatus::Failed);
        assert_eq!(record.first_failure(), Some(&err));
        assert_eq!(scheduler.first_failure(), Some(&err));
        assert_eq!(feedback.outstanding_reference_count(), 0);

        let mut static_scheduler = QpackBlockedStreamScheduler::new(1);
        let err = static_scheduler
            .submit_field_section(
                &mut context,
                &mut feedback,
                H3QpackMode::StaticOnly,
                8,
                &wire,
            )
            .expect_err("static-only must reject dynamic RIC");
        assert_eq!(
            err,
            H3NativeError::QpackPolicy("required insert count must be zero in static-only mode")
        );
        assert_eq!(
            static_scheduler.record(8).expect("static failure").status(),
            QpackBlockedStreamStatus::Failed
        );
    }

    #[test]
    fn qpack_blocked_scheduler_blocks_until_insert_count_increment_releases_capacity() {
        let mut context = QpackContext::new(128);
        let insertion_id = context
            .insert_dynamic_entry("x-blocked".to_string(), "blocked".to_string())
            .expect("insert dynamic entry");
        let wire = qpack_dynamic_wire(&context, insertion_id).expect("encode field section");
        let mut feedback = QpackDecoderFeedbackState::new();
        let mut scheduler = QpackBlockedStreamScheduler::new(1);

        assert_eq!(
            scheduler
                .submit_field_section(
                    &mut context,
                    &mut feedback,
                    H3QpackMode::DynamicTableAllowed,
                    4,
                    &wire,
                )
                .expect("first blocked stream"),
            QpackBlockedStreamStatus::Blocked
        );
        assert_eq!(scheduler.blocked_stream_count(), 1);
        assert_eq!(
            scheduler.record(4).expect("record").blocked_reason(),
            Some("required insert count exceeds known received count")
        );

        let err = scheduler
            .submit_field_section(
                &mut context,
                &mut feedback,
                H3QpackMode::DynamicTableAllowed,
                8,
                &wire,
            )
            .expect_err("second blocked stream exceeds limit");
        assert_eq!(
            err,
            H3NativeError::QpackPolicy("qpack blocked stream capacity exceeded")
        );
        assert_eq!(scheduler.blocked_stream_count(), 1);

        let unblocked = scheduler
            .apply_decoder_instruction(
                &mut feedback,
                &mut context,
                H3QpackMode::DynamicTableAllowed,
                &QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
            )
            .expect("known received count unblocks stream");
        assert_eq!(unblocked, vec![4]);
        assert_eq!(scheduler.blocked_stream_count(), 0);
        assert_eq!(
            scheduler.record(4).expect("record").status(),
            QpackBlockedStreamStatus::Ready
        );

        assert_eq!(
            scheduler
                .submit_field_section(
                    &mut context,
                    &mut feedback,
                    H3QpackMode::DynamicTableAllowed,
                    12,
                    &wire,
                )
                .expect("capacity released after unblock"),
            QpackBlockedStreamStatus::Ready
        );
    }

    #[test]
    fn qpack_blocked_scheduler_unblocks_multiple_streams_from_decoder_feedback() {
        let mut context = QpackContext::new(128);
        let insertion_id = context
            .insert_dynamic_entry("x-multi".to_string(), "multi".to_string())
            .expect("insert dynamic entry");
        let wire = qpack_dynamic_wire(&context, insertion_id).expect("encode field section");
        let mut feedback = QpackDecoderFeedbackState::new();
        let mut scheduler = QpackBlockedStreamScheduler::new(2);

        for stream_id in [4, 8] {
            let status = scheduler
                .submit_field_section(
                    &mut context,
                    &mut feedback,
                    H3QpackMode::DynamicTableAllowed,
                    stream_id,
                    &wire,
                )
                .expect("schedule blocked stream");
            assert_eq!(status, QpackBlockedStreamStatus::Blocked);
        }
        assert_eq!(scheduler.blocked_stream_count(), 2);
        assert_eq!(feedback.outstanding_reference_count(), 2);

        let unblocked = scheduler
            .apply_decoder_instruction(
                &mut feedback,
                &mut context,
                H3QpackMode::DynamicTableAllowed,
                &QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
            )
            .expect("unblock both streams");
        assert_eq!(unblocked, vec![4, 8]);
        assert_eq!(scheduler.blocked_stream_count(), 0);
        assert_eq!(
            scheduler.record(4).expect("stream 4").status(),
            QpackBlockedStreamStatus::Ready
        );
        assert_eq!(
            scheduler.record(8).expect("stream 8").status(),
            QpackBlockedStreamStatus::Ready
        );
        assert_eq!(feedback.outstanding_reference_count(), 2);
    }

    #[test]
    fn qpack_blocked_scheduler_encoder_instruction_unblocks_received_field_section() {
        let mut context = QpackContext::new(128);
        let mut feedback = QpackDecoderFeedbackState::new();
        let mut scheduler = QpackBlockedStreamScheduler::new(1);
        let mut wire = Vec::new();
        let encoded_ric = qpack_encode_required_insert_count(1, 128).expect("encode RIC");
        qpack_encode_prefixed_int(&mut wire, 0, 8, encoded_ric).expect("RIC prefix");
        qpack_encode_prefixed_int(&mut wire, 0, 7, 0).expect("base prefix");
        qpack_encode_prefixed_int(&mut wire, 0b1000_0000, 6, 0).expect("dynamic relative index 0");

        let status = scheduler
            .submit_received_field_section(
                &mut context,
                &mut feedback,
                H3QpackMode::DynamicTableAllowed,
                4,
                &wire,
            )
            .expect("received field section blocks before insert");
        assert_eq!(status, QpackBlockedStreamStatus::Blocked);
        assert_eq!(scheduler.blocked_stream_count(), 1);
        assert!(
            scheduler
                .record(4)
                .expect("blocked record")
                .protected_references()
                .is_empty()
        );

        let (inserted, unblocked) = scheduler
            .apply_encoder_instruction(
                &mut context,
                &mut feedback,
                H3QpackMode::DynamicTableAllowed,
                &QpackEncoderInstruction::InsertWithoutNameReference {
                    name: "x-received".to_string(),
                    value: "value".to_string(),
                },
            )
            .expect("encoder insert unblocks received field section");
        assert_eq!(inserted, Some(0));
        assert_eq!(unblocked, vec![4]);
        assert_eq!(scheduler.blocked_stream_count(), 0);
        let record = scheduler.record(4).expect("ready record");
        assert_eq!(record.status(), QpackBlockedStreamStatus::Ready);
        assert_eq!(record.protected_references(), &[0]);
        assert_eq!(feedback.outstanding_reference_count(), 1);
    }

    #[test]
    fn qpack_blocked_scheduler_cancellation_releases_blocked_and_ready_references() {
        let mut context = QpackContext::new(128);
        let insertion_id = context
            .insert_dynamic_entry("x-cancel".to_string(), "cancel".to_string())
            .expect("insert dynamic entry");
        let wire = qpack_dynamic_wire(&context, insertion_id).expect("encode field section");
        let mut feedback = QpackDecoderFeedbackState::new();
        let mut scheduler = QpackBlockedStreamScheduler::new(1);

        scheduler
            .submit_field_section(
                &mut context,
                &mut feedback,
                H3QpackMode::DynamicTableAllowed,
                4,
                &wire,
            )
            .expect("blocked stream");
        scheduler
            .cancel_stream(
                &mut feedback,
                &mut context,
                H3QpackMode::DynamicTableAllowed,
                4,
            )
            .expect("cancel blocked stream");
        assert_eq!(scheduler.blocked_stream_count(), 0);
        assert_eq!(scheduler.record(4), None);
        assert!(feedback.cancelled_stream_ids().contains(&4));
        context
            .set_dynamic_table_capacity(0)
            .expect("blocked cancellation released reference");

        let mut context = QpackContext::new(128);
        let insertion_id = context
            .insert_dynamic_entry("x-ready-cancel".to_string(), "cancel".to_string())
            .expect("insert dynamic entry");
        let wire = qpack_dynamic_wire(&context, insertion_id).expect("encode field section");
        let mut feedback = QpackDecoderFeedbackState::new();
        let mut scheduler = QpackBlockedStreamScheduler::new(1);
        scheduler
            .submit_field_section(
                &mut context,
                &mut feedback,
                H3QpackMode::DynamicTableAllowed,
                8,
                &wire,
            )
            .expect("blocked stream");
        scheduler
            .apply_decoder_instruction(
                &mut feedback,
                &mut context,
                H3QpackMode::DynamicTableAllowed,
                &QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
            )
            .expect("unblock stream");
        assert_eq!(
            context
                .set_dynamic_table_capacity(0)
                .expect_err("ready stream is still protected before terminal feedback"),
            "cannot reduce table capacity while entries are referenced"
        );
        scheduler
            .cancel_stream(
                &mut feedback,
                &mut context,
                H3QpackMode::DynamicTableAllowed,
                8,
            )
            .expect("cancel ready stream");
        assert_eq!(scheduler.record(8), None);
        context
            .set_dynamic_table_capacity(0)
            .expect("ready cancellation released reference");
    }

    #[test]
    fn qpack_blocked_scheduler_required_insert_count_boundaries_and_failures() {
        let mut context = QpackContext::new(128);
        let insertion_id = context
            .insert_dynamic_entry("x-boundary".to_string(), "boundary".to_string())
            .expect("insert dynamic entry");
        let wire = qpack_dynamic_wire(&context, insertion_id).expect("encode field section");

        let mut equal_feedback = QpackDecoderFeedbackState::new();
        qpack_apply_decoder_instruction(
            &mut equal_feedback,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
        )
        .expect("known equals RIC");
        let mut equal = QpackBlockedStreamScheduler::new(1);
        assert_eq!(
            equal
                .submit_field_section(
                    &mut context,
                    &mut equal_feedback,
                    H3QpackMode::DynamicTableAllowed,
                    4,
                    &wire,
                )
                .expect("equality is ready"),
            QpackBlockedStreamStatus::Ready
        );

        let mut less_feedback = QpackDecoderFeedbackState::new();
        let mut less = QpackBlockedStreamScheduler::new(1);
        assert_eq!(
            less.submit_field_section(
                &mut context,
                &mut less_feedback,
                H3QpackMode::DynamicTableAllowed,
                8,
                &wire,
            )
            .expect("less-than blocks"),
            QpackBlockedStreamStatus::Blocked
        );

        // A second insertion lets the Known Received Count (2) legitimately exceed
        // the field section's required insert count (1) without overshooting the
        // encoder's insertion counter (RFC 9204 §4.4.3).
        context
            .insert_dynamic_entry("x-boundary-2".to_string(), "boundary-2".to_string())
            .expect("insert second dynamic entry");
        let mut greater_feedback = QpackDecoderFeedbackState::new();
        qpack_apply_decoder_instruction(
            &mut greater_feedback,
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackDecoderInstruction::InsertCountIncrement { increment: 2 },
        )
        .expect("known greater than RIC");
        let mut greater = QpackBlockedStreamScheduler::new(1);
        assert_eq!(
            greater
                .submit_field_section(
                    &mut context,
                    &mut greater_feedback,
                    H3QpackMode::DynamicTableAllowed,
                    12,
                    &wire,
                )
                .expect("greater-than is ready"),
            QpackBlockedStreamStatus::Ready
        );

        let mut overflow_wire = Vec::new();
        qpack_encode_prefixed_int(&mut overflow_wire, 0, 8, 2).expect("encoded RIC");
        qpack_encode_prefixed_int(&mut overflow_wire, 0, 7, u64::MAX).expect("overflowing base");
        let mut overflow_feedback = QpackDecoderFeedbackState::new();
        let mut overflow = QpackBlockedStreamScheduler::new(1);
        let err = overflow
            .submit_field_section(
                &mut context,
                &mut overflow_feedback,
                H3QpackMode::DynamicTableAllowed,
                16,
                &overflow_wire,
            )
            .expect_err("base overflow");
        assert_eq!(err, H3NativeError::InvalidFrame("qpack integer overflow"));
        assert_eq!(
            overflow.record(16).expect("overflow record").status(),
            QpackBlockedStreamStatus::Failed
        );

        let mut evicted_context = QpackContext::new(76);
        let old = evicted_context
            .insert_dynamic_entry("old".to_string(), "1".to_string())
            .expect("insert old");
        let evicted = evicted_context
            .insert_dynamic_entry("evicted".to_string(), "2".to_string())
            .expect("insert evicted");
        assert!(evicted_context.dynamic_table_mut().reference_entry(old));
        evicted_context
            .insert_dynamic_entry("new".to_string(), "3".to_string())
            .expect("insert new");
        assert_eq!(
            qpack_dynamic_entry(evicted_context.dynamic_table(), evicted),
            None
        );
        let mut evicted_wire = Vec::new();
        let encoded_ric = qpack_encode_required_insert_count(2, 76).expect("encode RIC");
        qpack_encode_prefixed_int(&mut evicted_wire, 0, 8, encoded_ric).expect("RIC prefix");
        qpack_encode_prefixed_int(&mut evicted_wire, 0, 7, 0).expect("base prefix");
        qpack_encode_prefixed_int(&mut evicted_wire, 0b1000_0000, 6, 0)
            .expect("dynamic relative index 0 => evicted absolute 1");
        let mut evicted_feedback = QpackDecoderFeedbackState::new();
        let mut evicted_scheduler = QpackBlockedStreamScheduler::new(1);
        let err = evicted_scheduler
            .submit_field_section(
                &mut evicted_context,
                &mut evicted_feedback,
                H3QpackMode::DynamicTableAllowed,
                20,
                &evicted_wire,
            )
            .expect_err("evicted reference cannot be protected");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown dynamic qpack reference for stream")
        );
    }

    #[test]
    fn qpack_blocked_scheduler_reaps_terminal_records_but_keeps_blocked() {
        // Regression for the insert-only streams map (asupersync-...-i7afx1):
        // terminal records must be reaped to bound memory on long-lived
        // connections, while active Blocked records are always retained.
        let mut context = QpackContext::new(128);
        let mut feedback = QpackDecoderFeedbackState::new();
        let mut scheduler = QpackBlockedStreamScheduler::new(64);

        // One active blocked stream (highest id) must survive reaping.
        let blocked_id = 1_000_000u64;
        scheduler.streams.insert(
            blocked_id,
            QpackBlockedStreamRecord {
                stream_id: blocked_id,
                required_insert_count: 5,
                base: 0,
                status: QpackBlockedStreamStatus::Blocked,
                blocked_reason: Some("waiting on inserts"),
                protected_references: Vec::new(),
                blocked_field_section: None,
                first_failure: None,
            },
        );

        // A ready stream with protected references is still live until ack/cancel
        // feedback releases those references; it must not be treated as terminal.
        let protected_ready_id = 2_000_000u64;
        scheduler.streams.insert(
            protected_ready_id,
            QpackBlockedStreamRecord {
                stream_id: protected_ready_id,
                required_insert_count: 5,
                base: 5,
                status: QpackBlockedStreamStatus::Ready,
                blocked_reason: None,
                protected_references: vec![7],
                blocked_field_section: None,
                first_failure: None,
            },
        );

        // Far more terminal (failed) records than the retention cap.
        let extra = MAX_RETAINED_TERMINAL_RECORDS + 100;
        for stream_id in 0..extra as u64 {
            scheduler.streams.insert(
                stream_id,
                QpackBlockedStreamRecord::failed(
                    stream_id,
                    None,
                    H3NativeError::InvalidFrame("boom"),
                ),
            );
        }
        feedback
            .track_stream_references(&mut context, 0, &[])
            .expect("track unreferenced ready stream feedback");
        scheduler.streams.insert(
            0,
            QpackBlockedStreamRecord {
                stream_id: 0,
                required_insert_count: 0,
                base: 0,
                status: QpackBlockedStreamStatus::Ready,
                blocked_reason: None,
                protected_references: Vec::new(),
                blocked_field_section: None,
                first_failure: None,
            },
        );

        scheduler.reap_excess_records();

        // Unreferenced terminal records are bounded to the cap; the blocked
        // stream stays.
        let terminal = scheduler
            .streams
            .values()
            .filter(|record| record.is_reapable_terminal())
            .count();
        assert_eq!(terminal, MAX_RETAINED_TERMINAL_RECORDS);
        assert_eq!(
            scheduler.tracked_record_count(),
            MAX_RETAINED_TERMINAL_RECORDS + 2
        );
        assert!(scheduler.record(blocked_id).is_some());
        assert_eq!(
            scheduler
                .record(protected_ready_id)
                .expect("protected ready record")
                .protected_references(),
            &[7]
        );
        assert_eq!(scheduler.blocked_stream_count(), 1);

        // Oldest terminal records reaped first; newest retained.
        assert!(scheduler.record(0).is_none());
        assert!(scheduler.record((extra - 1) as u64).is_some());
        scheduler
            .apply_decoder_instruction(
                &mut feedback,
                &mut context,
                H3QpackMode::DynamicTableAllowed,
                &QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 0 },
            )
            .expect("feedback for compacted ready stream still applies");
        assert!(feedback.acknowledged_stream_ids().contains(&0));

        // Already at the cap: a further reap is a no-op (idempotent).
        scheduler.reap_excess_records();
        assert_eq!(
            scheduler.tracked_record_count(),
            MAX_RETAINED_TERMINAL_RECORDS + 2
        );
    }

    #[test]
    fn qpack_blocked_scheduler_out_of_order_acknowledgement_is_stable_error() {
        let mut context = QpackContext::new(128);
        let mut feedback = QpackDecoderFeedbackState::new();
        let mut scheduler = QpackBlockedStreamScheduler::new(1);

        let err = scheduler
            .apply_decoder_instruction(
                &mut feedback,
                &mut context,
                H3QpackMode::DynamicTableAllowed,
                &QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 99 },
            )
            .expect_err("ack before stream schedule");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown qpack decoder feedback stream")
        );
        assert_eq!(scheduler.first_failure(), Some(&err));
    }

    #[test]
    fn qpack_blocked_scheduler_e2e_logs_multistream_unblock() {
        let mut context = QpackContext::new(128);
        let insertion_id = context
            .insert_dynamic_entry("x-e2e".to_string(), "e2e".to_string())
            .expect("insert dynamic entry");
        let wire = qpack_dynamic_wire(&context, insertion_id).expect("encode field section");
        let mut feedback = QpackDecoderFeedbackState::new();
        let mut scheduler = QpackBlockedStreamScheduler::new(2);

        for stream_id in [4, 8] {
            scheduler
                .submit_field_section(
                    &mut context,
                    &mut feedback,
                    H3QpackMode::DynamicTableAllowed,
                    stream_id,
                    &wire,
                )
                .expect("schedule blocked stream");
        }
        let before_blocked = scheduler.blocked_stream_count();
        let unblocked = scheduler
            .apply_decoder_instruction(
                &mut feedback,
                &mut context,
                H3QpackMode::DynamicTableAllowed,
                &QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
            )
            .expect("decoder feedback unblocks both streams");
        let actual_event = format!("unblocked:{unblocked:?}");
        let log = serde_json::json!({
            "bead_id": "asupersync-55jlbl",
            "scenario_id": "qpack-blocked-multistream-increment-unblock",
            "qpack_mode": "DynamicTableAllowed",
            "required_insert_count": scheduler.record(4).expect("stream 4").required_insert_count(),
            "known_received_count": feedback.known_received_count(),
            "blocked_stream_count_before": before_blocked,
            "blocked_stream_count_after": scheduler.blocked_stream_count(),
            "settings_blocked_streams": scheduler.settings_blocked_streams(),
            "expected_event": "unblocked:[4, 8]",
            "actual_event": actual_event,
            "support_class": "deterministic-unit-e2e",
            "verdict": if unblocked == vec![4, 8] { "pass" } else { "fail" },
            "first_failure": scheduler.first_failure().map(ToString::to_string),
        });
        println!("{log}");

        assert_eq!(unblocked, vec![4, 8]);
        assert_eq!(scheduler.blocked_stream_count(), 0);
        assert_eq!(
            scheduler.record(4).expect("stream 4").status(),
            QpackBlockedStreamStatus::Ready
        );
        assert_eq!(
            scheduler.record(8).expect("stream 8").status(),
            QpackBlockedStreamStatus::Ready
        );
    }

    fn qpack_instruction_settings() -> H3Settings {
        H3Settings {
            qpack_max_table_capacity: Some(128),
            qpack_blocked_streams: Some(2),
            ..H3Settings::default()
        }
    }

    fn qpack_encoder_instruction_bytes(instruction: &QpackEncoderInstruction) -> Vec<u8> {
        let mut bytes = Vec::new();
        qpack_encode_encoder_instruction(&mut bytes, instruction).expect("encode encoder");
        bytes
    }

    fn qpack_decoder_instruction_bytes(instruction: &QpackDecoderInstruction) -> Vec<u8> {
        let mut bytes = Vec::new();
        qpack_encode_decoder_instruction(&mut bytes, instruction).expect("encode decoder");
        bytes
    }

    fn qpack_response_status_dynamic_wire() -> Vec<u8> {
        let mut wire = Vec::new();
        let encoded_ric = qpack_encode_required_insert_count(1, 128).expect("encode RIC");
        qpack_encode_prefixed_int(&mut wire, 0, 8, encoded_ric).expect("RIC prefix");
        qpack_encode_prefixed_int(&mut wire, 0, 7, 0).expect("base prefix");
        qpack_encode_prefixed_int(&mut wire, 0b1000_0000, 6, 0).expect("dynamic relative index 0");
        wire
    }

    fn qpack_instruction_row(
        state: &QpackInstructionStreamState,
        scenario_id: &str,
        required_insert_count: u64,
        expected_event: &str,
        actual_event: &str,
        verdict: &str,
        first_failure: Option<String>,
    ) -> serde_json::Value {
        let row = serde_json::json!({
            "bead_id": "asupersync-1xxmyo",
            "scenario_id": scenario_id,
            "qpack_mode": format!("{:?}", state.mode()),
            "encoder_stream_id": state.encoder_stream_id(),
            "decoder_stream_id": state.decoder_stream_id(),
            "required_insert_count": required_insert_count,
            "known_received_count": state.known_received_count(),
            "blocked_stream_count": state.blocked_stream_count(),
            "settings_blocked_streams": state.settings_blocked_streams(),
            "expected_event": expected_event,
            "actual_event": actual_event,
            "support_class": "deterministic-http3-qpack-instruction-proof",
            "verdict": verdict,
            "first_failure": first_failure,
        });
        for field in [
            "bead_id",
            "scenario_id",
            "qpack_mode",
            "encoder_stream_id",
            "decoder_stream_id",
            "required_insert_count",
            "known_received_count",
            "blocked_stream_count",
            "settings_blocked_streams",
            "expected_event",
            "actual_event",
            "support_class",
            "verdict",
            "first_failure",
        ] {
            assert!(row.get(field).is_some(), "missing proof log field {field}");
        }
        println!("{row}");
        row
    }

    #[test]
    fn qpack_instruction_stream_registers_from_h3_state_and_keeps_frame_boundary() {
        let mut connection =
            H3ConnectionState::with_config(H3ConnectionConfig::default().with_dynamic_qpack());
        assert_eq!(
            connection
                .on_remote_uni_stream_type(3, H3_STREAM_TYPE_QPACK_ENCODER)
                .expect("encoder stream type"),
            H3UniStreamType::QpackEncoder
        );
        assert_eq!(
            connection
                .on_remote_uni_stream_type(7, H3_STREAM_TYPE_QPACK_DECODER)
                .expect("decoder stream type"),
            H3UniStreamType::QpackDecoder
        );
        assert_eq!(connection.qpack_encoder_stream_id(), Some(3));
        assert_eq!(connection.qpack_decoder_stream_id(), Some(7));

        let err = connection
            .on_uni_stream_frame(3, &H3Frame::Data(vec![1]))
            .expect_err("qpack encoder stream must not parse h3 frames");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("qpack streams carry instructions, not h3 frames")
        );
        let err = connection
            .on_uni_stream_frame(7, &H3Frame::Headers(vec![0]))
            .expect_err("qpack decoder stream must not parse h3 frames");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("qpack streams carry instructions, not h3 frames")
        );

        let mut qpack = QpackInstructionStreamState::from_settings(
            H3QpackMode::DynamicTableAllowed,
            &qpack_instruction_settings(),
        )
        .expect("qpack instruction state");
        assert_eq!(
            connection
                .register_qpack_instruction_stream(&mut qpack, 3)
                .expect("register encoder"),
            H3UniStreamType::QpackEncoder
        );
        assert_eq!(
            connection
                .register_qpack_instruction_stream(&mut qpack, 7)
                .expect("register decoder"),
            H3UniStreamType::QpackDecoder
        );

        let insert =
            qpack_encoder_instruction_bytes(&QpackEncoderInstruction::InsertWithoutNameReference {
                name: "x-h3-boundary".to_string(),
                value: "value".to_string(),
            });
        let outcome = connection
            .feed_qpack_instruction_stream_bytes(&mut qpack, 3, &insert)
            .expect("encoder instruction bytes");
        assert_eq!(outcome.instructions_processed(), 1);
        assert_eq!(outcome.inserted_entry_ids(), &[0]);
    }

    #[test]
    fn qpack_instruction_stream_registration_and_wrong_stream_errors() {
        let mut qpack = QpackInstructionStreamState::from_settings(
            H3QpackMode::DynamicTableAllowed,
            &qpack_instruction_settings(),
        )
        .expect("qpack state");
        qpack
            .register_stream(3, H3UniStreamType::QpackEncoder)
            .expect("encoder registration");
        qpack
            .register_stream(7, H3UniStreamType::QpackDecoder)
            .expect("decoder registration");

        let err = qpack
            .register_stream(11, H3UniStreamType::QpackEncoder)
            .expect_err("duplicate encoder stream");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("duplicate remote qpack encoder stream")
        );

        let err = qpack
            .feed_encoder_stream_bytes(99, &[])
            .expect_err("unknown qpack stream id");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("unknown qpack instruction stream")
        );

        let decoder =
            qpack_decoder_instruction_bytes(&QpackDecoderInstruction::InsertCountIncrement {
                increment: 1,
            });
        let err = qpack
            .feed_instruction_stream_bytes(3, H3UniStreamType::QpackDecoder, &decoder)
            .expect_err("decoder instruction on encoder stream");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol(
                "qpack instruction type does not match registered stream"
            )
        );

        let err = qpack
            .register_stream(19, H3UniStreamType::Control)
            .expect_err("non-qpack stream rejected");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("qpack instruction stream requires qpack stream type")
        );
    }

    #[test]
    fn qpack_instruction_stream_dynamic_sequence_blocks_unblocks_and_decodes() {
        let mut connection =
            H3ConnectionState::with_config(H3ConnectionConfig::default().with_dynamic_qpack());
        connection
            .on_remote_uni_stream_type(3, H3_STREAM_TYPE_QPACK_ENCODER)
            .expect("encoder stream");
        connection
            .on_remote_uni_stream_type(7, H3_STREAM_TYPE_QPACK_DECODER)
            .expect("decoder stream");

        let mut qpack = QpackInstructionStreamState::from_settings(
            H3QpackMode::DynamicTableAllowed,
            &qpack_instruction_settings(),
        )
        .expect("qpack state");
        connection
            .register_qpack_instruction_stream(&mut qpack, 3)
            .expect("register encoder");
        connection
            .register_qpack_instruction_stream(&mut qpack, 7)
            .expect("register decoder");

        let field_section = qpack_response_status_dynamic_wire();
        let status = qpack
            .submit_received_field_section(4, &field_section)
            .expect("field section blocks before insert");
        assert_eq!(status, QpackBlockedStreamStatus::Blocked);
        assert_eq!(qpack.blocked_stream_count(), 1);

        let insert =
            qpack_encoder_instruction_bytes(&QpackEncoderInstruction::InsertWithoutNameReference {
                name: ":status".to_string(),
                value: "200".to_string(),
            });
        let outcome = connection
            .feed_qpack_instruction_stream_bytes(&mut qpack, 3, &insert)
            .expect("encoder insert unblocks field section");
        assert_eq!(outcome.inserted_entry_ids(), &[0]);
        assert_eq!(outcome.unblocked_stream_ids(), &[4]);
        assert_eq!(qpack.blocked_stream_count(), 0);

        let response = qpack_decode_response_field_section(
            &field_section,
            H3QpackMode::DynamicTableAllowed,
            Some(qpack.context()),
        )
        .expect("decode unblocked response field section");
        assert_eq!(response.status, 200);

        let increment =
            qpack_decoder_instruction_bytes(&QpackDecoderInstruction::InsertCountIncrement {
                increment: 1,
            });
        let outcome = connection
            .feed_qpack_instruction_stream_bytes(&mut qpack, 7, &increment)
            .expect("decoder feedback increment");
        assert_eq!(outcome.instructions_processed(), 1);
        assert_eq!(qpack.known_received_count(), 1);
    }

    #[test]
    fn qpack_instruction_stream_proof_runner_scenarios_log_required_fields() {
        let mut rows = Vec::new();

        let mut static_only =
            QpackInstructionStreamState::new(H3QpackMode::StaticOnly, 0, 0).expect("static qpack");
        static_only
            .register_stream(3, H3UniStreamType::QpackEncoder)
            .expect("encoder stream");
        let insert =
            qpack_encoder_instruction_bytes(&QpackEncoderInstruction::InsertWithoutNameReference {
                name: "x-static".to_string(),
                value: "reject".to_string(),
            });
        let err = static_only
            .feed_encoder_stream_bytes(3, &insert)
            .expect_err("static-only rejects encoder stream instructions");
        rows.push(qpack_instruction_row(
            &static_only,
            "static-only-rejection",
            0,
            "qpack-policy-error",
            &err.to_string(),
            "pass",
            Some(err.to_string()),
        ));

        let mut encoder_rt = QpackInstructionStreamState::from_settings(
            H3QpackMode::DynamicTableAllowed,
            &qpack_instruction_settings(),
        )
        .expect("dynamic qpack");
        encoder_rt
            .register_stream(3, H3UniStreamType::QpackEncoder)
            .expect("encoder stream");
        let insert =
            qpack_encoder_instruction_bytes(&QpackEncoderInstruction::InsertWithoutNameReference {
                name: "x-roundtrip".to_string(),
                value: "ok".to_string(),
            });
        let outcome = encoder_rt
            .feed_encoder_stream_bytes(3, &insert)
            .expect("encoder roundtrip");
        rows.push(qpack_instruction_row(
            &encoder_rt,
            "encoder-instruction-roundtrip",
            0,
            "inserted:[0]",
            &format!("inserted:{:?}", outcome.inserted_entry_ids()),
            if outcome.inserted_entry_ids() == [0] {
                "pass"
            } else {
                "fail"
            },
            None,
        ));

        let mut decoder_rt = QpackInstructionStreamState::from_settings(
            H3QpackMode::DynamicTableAllowed,
            &qpack_instruction_settings(),
        )
        .expect("dynamic qpack");
        decoder_rt
            .register_stream(3, H3UniStreamType::QpackEncoder)
            .expect("encoder stream");
        let decoder_insert =
            qpack_encoder_instruction_bytes(&QpackEncoderInstruction::InsertWithoutNameReference {
                name: "x-feedback".to_string(),
                value: "ok".to_string(),
            });
        decoder_rt
            .feed_encoder_stream_bytes(3, &decoder_insert)
            .expect("decoder feedback insertion");
        decoder_rt
            .register_stream(7, H3UniStreamType::QpackDecoder)
            .expect("decoder stream");
        let increment =
            qpack_decoder_instruction_bytes(&QpackDecoderInstruction::InsertCountIncrement {
                increment: 1,
            });
        decoder_rt
            .feed_decoder_stream_bytes(7, &increment)
            .expect("decoder feedback");
        rows.push(qpack_instruction_row(
            &decoder_rt,
            "decoder-feedback-roundtrip",
            0,
            "known-received-count:1",
            &format!("known-received-count:{}", decoder_rt.known_received_count()),
            if decoder_rt.known_received_count() == 1 {
                "pass"
            } else {
                "fail"
            },
            None,
        ));

        let mut blocked = QpackInstructionStreamState::from_settings(
            H3QpackMode::DynamicTableAllowed,
            &qpack_instruction_settings(),
        )
        .expect("dynamic qpack");
        blocked
            .register_stream(3, H3UniStreamType::QpackEncoder)
            .expect("encoder stream");
        blocked
            .submit_received_field_section(4, &qpack_response_status_dynamic_wire())
            .expect("blocked field section");
        let insert =
            qpack_encoder_instruction_bytes(&QpackEncoderInstruction::InsertWithoutNameReference {
                name: ":status".to_string(),
                value: "200".to_string(),
            });
        let outcome = blocked
            .feed_encoder_stream_bytes(3, &insert)
            .expect("encoder instruction unblocks");
        rows.push(qpack_instruction_row(
            &blocked,
            "blocked-then-unblocked-stream",
            1,
            "unblocked:[4]",
            &format!("unblocked:{:?}", outcome.unblocked_stream_ids()),
            if outcome.unblocked_stream_ids() == [4] {
                "pass"
            } else {
                "fail"
            },
            None,
        ));

        let mut cancelled = QpackInstructionStreamState::from_settings(
            H3QpackMode::DynamicTableAllowed,
            &qpack_instruction_settings(),
        )
        .expect("dynamic qpack");
        cancelled
            .register_stream(3, H3UniStreamType::QpackEncoder)
            .expect("encoder stream");
        cancelled
            .register_stream(7, H3UniStreamType::QpackDecoder)
            .expect("decoder stream");
        let cancel_insert =
            qpack_encoder_instruction_bytes(&QpackEncoderInstruction::InsertWithoutNameReference {
                name: "x-cancel-blocked".to_string(),
                value: "value".to_string(),
            });
        let inserted = cancelled
            .feed_encoder_stream_bytes(3, &cancel_insert)
            .expect("insert cancellation reference");
        let cancel_wire = qpack_dynamic_wire(cancelled.context(), inserted.inserted_entry_ids()[0])
            .expect("wire");
        cancelled
            .submit_field_section(8, &cancel_wire)
            .expect("outbound blocked field section");
        let cancel =
            qpack_decoder_instruction_bytes(&QpackDecoderInstruction::StreamCancellation {
                stream_id: 8,
            });
        cancelled
            .feed_decoder_stream_bytes(7, &cancel)
            .expect("cancel blocked stream");
        let cancel_event = if cancelled.blocked_scheduler().record(8).is_none() {
            "cancelled:removed".to_string()
        } else {
            "cancelled:retained".to_string()
        };
        rows.push(qpack_instruction_row(
            &cancelled,
            "cancellation-while-blocked",
            1,
            "cancelled:removed",
            &cancel_event,
            if cancel_event == "cancelled:removed" {
                "pass"
            } else {
                "fail"
            },
            None,
        ));

        let mut capacity =
            QpackInstructionStreamState::new(H3QpackMode::DynamicTableAllowed, 64, 1)
                .expect("capacity-limited qpack");
        capacity
            .register_stream(3, H3UniStreamType::QpackEncoder)
            .expect("encoder stream");
        let set_too_large =
            qpack_encoder_instruction_bytes(&QpackEncoderInstruction::SetDynamicTableCapacity {
                capacity: 128,
            });
        let err = capacity
            .feed_encoder_stream_bytes(3, &set_too_large)
            .expect_err("capacity exceeds setting");
        rows.push(qpack_instruction_row(
            &capacity,
            "capacity-exceeded",
            0,
            "capacity-policy-error",
            &err.to_string(),
            "pass",
            Some(err.to_string()),
        ));

        let mut malformed = QpackInstructionStreamState::from_settings(
            H3QpackMode::DynamicTableAllowed,
            &qpack_instruction_settings(),
        )
        .expect("dynamic qpack");
        malformed
            .register_stream(3, H3UniStreamType::QpackEncoder)
            .expect("encoder stream");
        let err = malformed
            .feed_encoder_stream_bytes(3, &[0b0100_0001])
            .expect_err("truncated encoder instruction");
        rows.push(qpack_instruction_row(
            &malformed,
            "malformed-instruction",
            0,
            "malformed-error",
            &err.to_string(),
            "pass",
            Some(err.to_string()),
        ));

        let mut wrong_stream = QpackInstructionStreamState::from_settings(
            H3QpackMode::DynamicTableAllowed,
            &qpack_instruction_settings(),
        )
        .expect("dynamic qpack");
        wrong_stream
            .register_stream(3, H3UniStreamType::QpackEncoder)
            .expect("encoder stream");
        let increment =
            qpack_decoder_instruction_bytes(&QpackDecoderInstruction::InsertCountIncrement {
                increment: 1,
            });
        let err = wrong_stream
            .feed_instruction_stream_bytes(3, H3UniStreamType::QpackDecoder, &increment)
            .expect_err("wrong stream type");
        rows.push(qpack_instruction_row(
            &wrong_stream,
            "wrong-stream-instruction",
            0,
            "wrong-stream-error",
            &err.to_string(),
            "pass",
            Some(err.to_string()),
        ));

        let expected = [
            "static-only-rejection",
            "encoder-instruction-roundtrip",
            "decoder-feedback-roundtrip",
            "blocked-then-unblocked-stream",
            "cancellation-while-blocked",
            "capacity-exceeded",
            "malformed-instruction",
            "wrong-stream-instruction",
        ];
        assert_eq!(rows.len(), expected.len());
        for scenario_id in expected {
            let row = rows
                .iter()
                .find(|row| row["scenario_id"] == scenario_id)
                .expect("scenario row");
            assert_eq!(row["bead_id"], "asupersync-1xxmyo");
            assert_eq!(row["verdict"], "pass");
        }
    }

    #[test]
    fn qpack_encoder_state_static_only_rejects_without_mutation() {
        let mut context = QpackContext::new(128);
        let before = (
            context.dynamic_table().len(),
            context.dynamic_table().size(),
            context.dynamic_table().insertion_counter(),
            context.dynamic_table().evicted_count(),
        );

        let err = qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::StaticOnly,
            &QpackEncoderInstruction::InsertWithoutNameReference {
                name: "x-test".to_string(),
                value: "value".to_string(),
            },
        )
        .expect_err("static-only mode must reject encoder instructions");

        assert_eq!(
            err,
            H3NativeError::QpackPolicy("encoder instructions require dynamic qpack mode")
        );
        assert_eq!(
            before,
            (
                context.dynamic_table().len(),
                context.dynamic_table().size(),
                context.dynamic_table().insertion_counter(),
                context.dynamic_table().evicted_count(),
            )
        );
    }

    #[test]
    fn qpack_encoder_state_set_capacity_grows_shrinks_and_zeroes() {
        let mut context = QpackContext::new(128);
        context
            .insert_dynamic_entry("alpha".to_string(), "one".to_string())
            .expect("insert alpha");
        context
            .insert_dynamic_entry("beta".to_string(), "two".to_string())
            .expect("insert beta");

        qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 96 },
        )
        .expect("shrink without eviction");
        assert_eq!(context.dynamic_table().capacity(), 96);
        assert_eq!(context.dynamic_table().len(), 2);

        qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 40 },
        )
        .expect("shrink with eviction");
        assert_eq!(context.dynamic_table().capacity(), 40);
        assert_eq!(context.dynamic_table().len(), 1);
        assert_eq!(context.dynamic_table().size(), 39);
        assert_eq!(context.dynamic_table().evicted_count(), 1);
        assert!(qpack_dynamic_entry(context.dynamic_table(), 0).is_none());
        assert_eq!(
            qpack_dynamic_entry(context.dynamic_table(), 1),
            Some(("beta", "two"))
        );

        qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 0 },
        )
        .expect("zero capacity evicts unreferenced entries");
        assert_eq!(context.dynamic_table().capacity(), 0);
        assert_eq!(context.dynamic_table().len(), 0);
        assert_eq!(context.dynamic_table().size(), 0);
    }

    #[test]
    fn qpack_encoder_state_set_capacity_rejects_peer_limit_and_referenced_shrink() {
        let mut context = QpackContext::new(128);
        let err = qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 129 },
        )
        .expect_err("capacity exceeds peer maximum");
        assert_eq!(
            err,
            H3NativeError::QpackPolicy("qpack dynamic table capacity exceeds peer limit")
        );
        assert_eq!(context.dynamic_table().capacity(), 128);

        let referenced = context
            .insert_dynamic_entry("ref".to_string(), "value".to_string())
            .expect("insert referenced");
        let _victim = context
            .insert_dynamic_entry("victim".to_string(), "value".to_string())
            .expect("insert victim");
        assert!(context.dynamic_table_mut().reference_entry(referenced));
        let before = (
            context.dynamic_table().len(),
            context.dynamic_table().size(),
            context.dynamic_table().capacity(),
            context.dynamic_table().evicted_count(),
        );

        let err = qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 39 },
        )
        .expect_err("referenced entry prevents shrink");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame(
                "qpack dynamic table capacity shrink blocked by referenced entries"
            )
        );
        assert_eq!(
            before,
            (
                context.dynamic_table().len(),
                context.dynamic_table().size(),
                context.dynamic_table().capacity(),
                context.dynamic_table().evicted_count(),
            )
        );
    }

    #[test]
    fn qpack_encoder_state_inserts_static_dynamic_and_literal_names() {
        let mut context = QpackContext::new(256);
        let static_insert = qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::InsertWithNameReference {
                name: QpackInstructionNameRef::Static(0),
                value: "www.example.com".to_string(),
            },
        )
        .expect("static-name insert")
        .expect("insert id");
        assert_eq!(
            qpack_entry_by_insertion_id(context.dynamic_table(), static_insert),
            Some((":authority", "www.example.com"))
        );

        let literal_insert = qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::InsertWithoutNameReference {
                name: "x-base".to_string(),
                value: String::new(),
            },
        )
        .expect("literal insert")
        .expect("insert id");
        assert_eq!(
            qpack_entry_by_insertion_id(context.dynamic_table(), literal_insert),
            Some(("x-base", ""))
        );

        let dynamic_insert = qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::InsertWithNameReference {
                name: QpackInstructionNameRef::Dynamic(0),
                value: "next".to_string(),
            },
        )
        .expect("dynamic-name insert")
        .expect("insert id");
        assert_eq!(
            qpack_entry_by_insertion_id(context.dynamic_table(), dynamic_insert),
            Some(("x-base", "next"))
        );
    }

    #[test]
    fn qpack_encoder_state_insert_rejects_unknown_names_and_oversized_entries() {
        let mut context = QpackContext::new(33);
        let exact = qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::InsertWithoutNameReference {
                name: "x".to_string(),
                value: String::new(),
            },
        )
        .expect("exact capacity insert")
        .expect("insert id");
        assert_eq!(
            qpack_entry_by_insertion_id(context.dynamic_table(), exact),
            Some(("x", ""))
        );

        let err = qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::InsertWithoutNameReference {
                name: "xx".to_string(),
                value: String::new(),
            },
        )
        .expect_err("entry exceeds capacity");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("qpack dynamic table entry exceeds capacity")
        );

        let err = qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::InsertWithNameReference {
                name: QpackInstructionNameRef::Static(999),
                value: "value".to_string(),
            },
        )
        .expect_err("unknown static name");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown static qpack name index")
        );

        let err = qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::InsertWithNameReference {
                name: QpackInstructionNameRef::Dynamic(9),
                value: "value".to_string(),
            },
        )
        .expect_err("unknown dynamic name");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown dynamic qpack name index")
        );
    }

    #[test]
    fn qpack_encoder_state_duplicate_handles_pressure_and_evicted_targets() {
        let mut context = QpackContext::new(100);
        let old = context
            .insert_dynamic_entry("old".to_string(), "1".to_string())
            .expect("insert old");
        let new = context
            .insert_dynamic_entry("new".to_string(), "2".to_string())
            .expect("insert new");

        let duplicate = qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::Duplicate { index: 0 },
        )
        .expect("duplicate newest")
        .expect("insert id");

        assert!(qpack_entry_by_insertion_id(context.dynamic_table(), old).is_none());
        assert_eq!(
            qpack_entry_by_insertion_id(context.dynamic_table(), new),
            Some(("new", "2"))
        );
        assert_eq!(
            qpack_entry_by_insertion_id(context.dynamic_table(), duplicate),
            Some(("new", "2"))
        );
        assert_eq!(context.dynamic_table().evicted_count(), 1);

        let err = qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::Duplicate { index: 2 },
        )
        .expect_err("duplicate target was evicted");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown dynamic qpack duplicate index")
        );
    }

    #[test]
    fn qpack_encoder_state_insert_fails_when_all_entries_are_referenced() {
        let mut context = QpackContext::new(75);
        let first = context
            .insert_dynamic_entry("a".to_string(), "1".to_string())
            .expect("insert first");
        let second = context
            .insert_dynamic_entry("b".to_string(), "2".to_string())
            .expect("insert second");
        assert!(context.dynamic_table_mut().reference_entry(first));
        assert!(context.dynamic_table_mut().reference_entry(second));

        let err = qpack_apply_encoder_instruction(
            &mut context,
            H3QpackMode::DynamicTableAllowed,
            &QpackEncoderInstruction::InsertWithoutNameReference {
                name: "c".to_string(),
                value: "3".to_string(),
            },
        )
        .expect_err("referenced entries block eviction");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("qpack dynamic table insert blocked by referenced entries")
        );
        assert_eq!(context.dynamic_table().insertion_counter(), 2);
        assert_eq!(context.dynamic_table().len(), 2);
    }

    #[test]
    fn qpack_encoder_state_instruction_sequences_are_deterministic() {
        let instructions = [
            QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 96 },
            QpackEncoderInstruction::InsertWithNameReference {
                name: QpackInstructionNameRef::Static(0),
                value: "site".to_string(),
            },
            QpackEncoderInstruction::InsertWithoutNameReference {
                name: "x-test".to_string(),
                value: "one".to_string(),
            },
            QpackEncoderInstruction::InsertWithNameReference {
                name: QpackInstructionNameRef::Dynamic(0),
                value: "two".to_string(),
            },
            QpackEncoderInstruction::Duplicate { index: 0 },
        ];

        let mut left = QpackContext::new(128);
        let mut right = QpackContext::new(128);
        for instruction in &instructions {
            qpack_apply_encoder_instruction(
                &mut left,
                H3QpackMode::DynamicTableAllowed,
                instruction,
            )
            .expect("left sequence step");
            qpack_apply_encoder_instruction(
                &mut right,
                H3QpackMode::DynamicTableAllowed,
                instruction,
            )
            .expect("right sequence step");
        }

        let left_entries: Vec<_> = left
            .dynamic_table()
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.insertion_id(),
                    entry.name().to_string(),
                    entry.value().to_string(),
                )
            })
            .collect();
        let right_entries: Vec<_> = right
            .dynamic_table()
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.insertion_id(),
                    entry.name().to_string(),
                    entry.value().to_string(),
                )
            })
            .collect();

        assert_eq!(left_entries, right_entries);
        assert_eq!(
            left.dynamic_table().insertion_counter(),
            right.dynamic_table().insertion_counter()
        );
        assert_eq!(left.dynamic_table().size(), right.dynamic_table().size());
        assert_eq!(
            left.dynamic_table().evicted_count(),
            right.dynamic_table().evicted_count()
        );
    }

    // --- 6. Validation gaps ---

    #[test]
    fn request_missing_scheme_error() {
        let pseudo = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: None,
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("missing :scheme")
        );
    }

    #[test]
    fn request_missing_path_error() {
        let pseudo = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: None,
            status: None,
            protocol: None,
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("missing :path")
        );
    }

    #[test]
    fn request_empty_method_error() {
        let pseudo = H3PseudoHeaders {
            method: Some(String::new()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("empty :method")
        );
    }

    #[test]
    fn request_invalid_method_token_error() {
        let pseudo = H3PseudoHeaders {
            method: Some("GET POST".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(":method must be a valid HTTP token")
        );
    }

    #[test]
    fn request_method_accepts_rfc5234_tchar_vector() {
        let pseudo = H3PseudoHeaders {
            method: Some("M!#$%&'*+-.^_`|~09".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        };
        validate_request_pseudo_headers(&pseudo).expect("RFC 5234 tchar vector must be valid");
    }

    #[test]
    fn request_empty_scheme_error() {
        let pseudo = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some(String::new()),
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("empty :scheme")
        );
    }

    #[test]
    fn request_empty_path_error() {
        let pseudo = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some(String::new()),
            status: None,
            protocol: None,
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("empty :path")
        );
    }

    #[test]
    fn connect_empty_authority_error() {
        let pseudo = H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            authority: Some(String::new()),
            ..H3PseudoHeaders::default()
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("CONNECT request missing :authority")
        );
    }

    #[test]
    fn connect_invalid_authority_value_error() {
        let pseudo = H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            authority: Some("example.com\r\nx-bad: 1".to_string()),
            ..H3PseudoHeaders::default()
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame(
                "header field value contains forbidden character (NUL, CR, or LF)"
            )
        );
    }

    #[test]
    fn connect_rejects_authority_whitespace() {
        let pseudo = H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            authority: Some("example.com :443".to_string()),
            ..H3PseudoHeaders::default()
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(
                ":authority must be RFC authority-form without whitespace"
            )
        );
    }

    #[test]
    fn request_authority_rfc4291_ipv6_literal_vector() {
        let valid = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("[2001:db8::8:800:200c:417a]:443".to_string()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        };
        validate_request_pseudo_headers(&valid).expect("compressed RFC 4291 IPv6 literal valid");

        let invalid = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("[2001:db8:::1]:443".to_string()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        };
        let err = validate_request_pseudo_headers(&invalid).expect_err("must reject bad IPv6");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(":authority has invalid IPv6 literal")
        );
    }

    #[test]
    fn request_rejects_empty_authority_when_present() {
        let pseudo = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some(String::new()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("empty :authority")
        );
    }

    #[test]
    fn request_rejects_non_origin_form_path() {
        let pseudo = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("noslash".to_string()),
            status: None,
            protocol: None,
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(":path must start with /")
        );
    }

    #[test]
    fn request_rejects_asterisk_form_for_non_options() {
        let pseudo = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("*".to_string()),
            status: None,
            protocol: None,
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("asterisk-form :path requires OPTIONS")
        );
    }

    #[test]
    fn options_allows_asterisk_form_path() {
        let pseudo = H3PseudoHeaders {
            method: Some("OPTIONS".to_string()),
            scheme: Some("https".to_string()),
            path: Some("*".to_string()),
            status: None,
            ..H3PseudoHeaders::default()
        };
        validate_request_pseudo_headers(&pseudo).expect("OPTIONS * is valid");
    }

    #[test]
    fn request_rejects_invalid_scheme_syntax() {
        let pseudo = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("1https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(":scheme must be a valid URI scheme")
        );
    }

    #[test]
    fn request_head_constructor_rejects_pseudo_header_in_regular_headers() {
        let err = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some("/".to_string()),
                status: None,
                protocol: None,
            },
            vec![(":status".to_string(), "200".to_string())],
        )
        .expect_err("must reject pseudo header contamination");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(
                "pseudo headers must not appear in regular header list"
            )
        );
    }

    #[test]
    fn request_head_constructor_rejects_invalid_regular_header_value() {
        let err = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some("/".to_string()),
                status: None,
                protocol: None,
            },
            vec![("x-test".to_string(), "bad\r\nvalue".to_string())],
        )
        .expect_err("must reject invalid regular header value");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame(
                "header field value contains forbidden character (NUL, CR, or LF)"
            )
        );
    }

    #[test]
    fn request_head_constructor_rejects_invalid_authority_pseudo_value() {
        let err = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com\r\nx-bad: 1".to_string()),
                path: Some("/".to_string()),
                status: None,
                protocol: None,
            },
            vec![],
        )
        .expect_err("must reject invalid pseudo header value");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame(
                "header field value contains forbidden character (NUL, CR, or LF)"
            )
        );
    }

    #[test]
    fn request_head_constructor_rejects_invalid_path_pseudo_value() {
        let err = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some("/ok\nbad".to_string()),
                status: None,
                protocol: None,
            },
            vec![],
        )
        .expect_err("must reject invalid pseudo header value");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame(
                "header field value contains forbidden character (NUL, CR, or LF)"
            )
        );
    }

    #[test]
    fn response_with_method_contaminant_error() {
        let pseudo = H3PseudoHeaders {
            status: Some(200),
            method: Some("GET".to_string()),
            ..H3PseudoHeaders::default()
        };
        let err = validate_response_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader(
                "response must not include request pseudo headers"
            )
        );
    }

    #[test]
    fn response_head_constructor_rejects_request_pseudo_header_in_regular_headers() {
        let err = H3ResponseHead::new(200, vec![(":path".to_string(), "/".to_string())])
            .expect_err("must reject request pseudo contamination");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader(
                "response must not include request pseudo headers"
            )
        );
    }

    #[test]
    fn response_head_constructor_rejects_invalid_regular_header_name() {
        let err = H3ResponseHead::new(200, vec![("Bad-Header".to_string(), "ok".to_string())])
            .expect_err("must reject uppercase regular header");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("header field name must be lowercase in HTTP/3")
        );
    }

    #[test]
    fn response_with_scheme_contaminant_error() {
        let pseudo = H3PseudoHeaders {
            status: Some(200),
            scheme: Some("https".to_string()),
            ..H3PseudoHeaders::default()
        };
        let err = validate_response_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader(
                "response must not include request pseudo headers"
            )
        );
    }

    // --- 7. Audit fixes: QPACK static table, header validation, unknown uni streams ---

    #[test]
    fn qpack_static_table_entries_2_through_14_present() {
        // These were previously missing, causing interop failures.
        assert_eq!(qpack_static_entry(2), Some(("age", "0")));
        assert_eq!(qpack_static_entry(4), Some(("content-length", "0")));
        assert_eq!(qpack_static_entry(5), Some(("cookie", "")));
        assert_eq!(qpack_static_entry(6), Some(("date", "")));
        assert_eq!(qpack_static_entry(12), Some(("location", "")));
        assert_eq!(qpack_static_entry(14), Some(("set-cookie", "")));
    }

    #[test]
    fn qpack_static_table_entries_29_through_62_present() {
        assert_eq!(qpack_static_entry(29), Some(("accept", "*/*")));
        assert_eq!(
            qpack_static_entry(31),
            Some(("accept-encoding", "gzip, deflate, br"))
        );
        assert_eq!(
            qpack_static_entry(46),
            Some(("content-type", "application/json"))
        );
        assert_eq!(qpack_static_entry(53), Some(("content-type", "text/plain")));
        assert_eq!(qpack_static_entry(59), Some(("vary", "accept-encoding")));
        assert_eq!(
            qpack_static_entry(62),
            Some(("x-xss-protection", "1; mode=block"))
        );
    }

    #[test]
    fn qpack_static_table_entries_72_through_98_present() {
        assert_eq!(qpack_static_entry(72), Some(("accept-language", "")));
        assert_eq!(qpack_static_entry(83), Some(("alt-svc", "clear")));
        assert_eq!(qpack_static_entry(90), Some(("origin", "")));
        assert_eq!(qpack_static_entry(95), Some(("user-agent", "")));
        assert_eq!(
            qpack_static_entry(98),
            Some(("x-frame-options", "sameorigin"))
        );
        // Index 99 does not exist.
        assert_eq!(qpack_static_entry(99), None);
    }

    #[test]
    fn header_name_rejects_uppercase() {
        let err = validate_header_name("Content-Type").expect_err("must reject uppercase");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("header field name must be lowercase in HTTP/3")
        );
    }

    #[test]
    fn header_name_rejects_null_byte() {
        let err = validate_header_name("x-\0-bad").expect_err("must reject null");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("header field name contains invalid character")
        );
    }

    #[test]
    fn header_name_rejects_space() {
        let err = validate_header_name("x bad").expect_err("must reject space");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("header field name contains invalid character")
        );
    }

    #[test]
    fn header_name_rejects_embedded_colon_in_regular_header() {
        let err = validate_header_name("x:bad").expect_err("must reject embedded colon");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("header field name contains invalid character")
        );
    }

    #[test]
    fn header_name_accepts_valid_token() {
        validate_header_name("content-type").expect("valid");
        validate_header_name("x-custom_header.1").expect("valid");
        validate_header_name(":method").expect("pseudo header valid");
    }

    #[test]
    fn header_value_rejects_crlf() {
        let err = validate_header_value("value\r\ninjected").expect_err("must reject CRLF");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame(
                "header field value contains forbidden character (NUL, CR, or LF)"
            )
        );
    }

    #[test]
    fn header_value_rejects_null() {
        let err = validate_header_value("value\0null").expect_err("must reject null");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame(
                "header field value contains forbidden character (NUL, CR, or LF)"
            )
        );
    }

    #[test]
    fn header_value_accepts_normal_text() {
        validate_header_value("application/json").expect("valid");
        validate_header_value("").expect("empty is valid");
        validate_header_value("value with spaces and tabs\tare ok").expect("valid");
    }

    #[test]
    fn unknown_uni_stream_type_accepted_and_data_ignored() {
        let mut c = H3ConnectionState::new();
        let kind = c
            .on_remote_uni_stream_type(3, 0x42)
            .expect("unknown type must be accepted per RFC 9114 §6.2");
        assert_eq!(kind, H3UniStreamType::Unknown(0x42));
        // Data on unknown streams is silently discarded.
        c.on_uni_stream_frame(3, &H3Frame::Data(vec![1, 2, 3]))
            .expect("data on unknown stream must be accepted");
    }

    #[test]
    fn request_decode_rejects_uppercase_header_name() {
        let fields = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":path".to_string(), "/".to_string()),
            ("Accept".to_string(), "*/*".to_string()),
        ];
        let err = header_fields_to_request_head(&fields).expect_err("must reject uppercase");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("header field name must be lowercase in HTTP/3")
        );
    }

    #[test]
    fn request_decode_rejects_embedded_colon_in_regular_header_name() {
        let fields = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":path".to_string(), "/".to_string()),
            ("x:bad".to_string(), "*/*".to_string()),
        ];
        let err = header_fields_to_request_head(&fields).expect_err("must reject embedded colon");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("header field name contains invalid character")
        );
    }

    #[test]
    fn request_decode_rejects_invalid_method_token() {
        let fields = vec![
            (":method".to_string(), "GET POST".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":path".to_string(), "/".to_string()),
        ];
        let err = header_fields_to_request_head(&fields).expect_err("must reject invalid method");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(":method must be a valid HTTP token")
        );
    }

    #[test]
    fn response_decode_rejects_crlf_in_header_value() {
        let fields = vec![
            (":status".to_string(), "200".to_string()),
            ("x-injected".to_string(), "foo\r\nbar".to_string()),
        ];
        let err = header_fields_to_response_head(&fields).expect_err("must reject CRLF");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame(
                "header field value contains forbidden character (NUL, CR, or LF)"
            )
        );
    }

    #[test]
    fn qpack_decode_string_rejects_prefix_len_8() {
        let err = qpack_decode_string(0xFF, 8, &[]).expect_err("must reject prefix_len=8");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("qpack string prefix length must be less than 8")
        );
    }

    #[test]
    fn settings_rejects_h2_reserved_ids() {
        // RFC 9114 §7.2.4.1: HTTP/2 reserved setting IDs (0x00, 0x02-0x05)
        // MUST be treated as a connection error.
        for reserved_id in [0x00u64, 0x02, 0x03, 0x04, 0x05] {
            let mut payload = Vec::new();
            encode_varint(reserved_id, &mut payload).expect("varint");
            encode_varint(42, &mut payload).expect("varint");
            let err = H3Settings::decode_payload(&payload).expect_err(&format!(
                "must reject H2 reserved setting 0x{reserved_id:02x}"
            ));
            assert_eq!(err, H3NativeError::InvalidSettingValue(reserved_id));
        }
    }

    #[test]
    fn settings_encode_rejects_h2_reserved_unknown_ids() {
        // RFC 9114 §7.2.4.1: HTTP/2 reserved setting identifiers MUST NOT be sent.
        for reserved_id in [0x00u64, 0x02, 0x03, 0x04, 0x05] {
            let settings = H3Settings {
                unknown: vec![UnknownSetting {
                    id: reserved_id,
                    value: 42,
                }],
                ..H3Settings::default()
            };

            let err = settings
                .encode_payload(&mut Vec::new())
                .expect_err("must reject reserved HTTP/2 setting IDs on encode");
            assert_eq!(err, H3NativeError::InvalidSettingValue(reserved_id));
        }
    }

    // --- HTTP/3 DATAGRAM Frame Conformance Tests (RFC 9297) ---

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_roundtrip() {
        // Basic DATAGRAM frame encode/decode roundtrip.
        let frame = H3Frame::Datagram {
            quarter_stream_id: 42,
            payload: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_roundtrip_empty_payload() {
        // DATAGRAM frame with empty payload should work.
        let frame = H3Frame::Datagram {
            quarter_stream_id: 0,
            payload: vec![],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_roundtrip_large_quarter_stream_id() {
        // Test maximum quarter-stream-id values (62-bit varint max).
        let frame = H3Frame::Datagram {
            quarter_stream_id: (1u64 << 62) - 1, // Maximum 62-bit value
            payload: vec![0x01, 0x02],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_golden_test_simple() {
        // Golden test: Known DATAGRAM frame encoding.
        // Frame type 0x30 (varint), length 6 (varint), quarter_stream_id 5 (varint), payload [0x01, 0x02, 0x03, 0x04].
        let frame = H3Frame::Datagram {
            quarter_stream_id: 5,
            payload: vec![0x01, 0x02, 0x03, 0x04],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");

        // Expected wire format: [0x30, 0x05, 0x05, 0x01, 0x02, 0x03, 0x04]
        // 0x30 = frame type (DATAGRAM)
        // 0x05 = frame length (1 byte quarter_stream_id + 4 bytes payload)
        // 0x05 = quarter_stream_id (5 as varint)
        // [0x01, 0x02, 0x03, 0x04] = payload
        let expected = vec![0x30u8, 0x05, 0x05, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(buf, expected, "DATAGRAM frame encoding mismatch");

        // Verify decode produces the same frame
        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_golden_test_zero_quarter_stream_id() {
        // Golden test: DATAGRAM frame with zero quarter_stream_id.
        let frame = H3Frame::Datagram {
            quarter_stream_id: 0,
            payload: vec![0xFF],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");

        // Expected: [0x30, 0x02, 0x00, 0xFF]
        // 0x30 = frame type, 0x02 = length, 0x00 = quarter_stream_id, 0xFF = payload
        let expected = vec![0x30u8, 0x02, 0x00, 0xFF];
        assert_eq!(buf, expected);

        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_large_payload() {
        // Test DATAGRAM frame with large payload (up to practical limits).
        let large_payload = vec![0x42u8; 1024];
        let frame = H3Frame::Datagram {
            quarter_stream_id: 1000,
            payload: large_payload.clone(),
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf, &test_config()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn datagram_frame_forbidden_on_control_stream() {
        // RFC 9297: DATAGRAM frames MUST NOT be sent on control streams.
        let frame = H3Frame::Datagram {
            quarter_stream_id: 10,
            payload: vec![0xAA, 0xBB],
        };

        let mut state = H3ControlState::new();
        state
            .on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        let err = state
            .on_remote_control_frame(&frame)
            .expect_err("must reject DATAGRAM on control stream");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("frame type not allowed on control stream")
        );
    }

    #[cfg(feature = "http3")]
    #[test]
    fn settings_h3_datagram_enabled() {
        // Test SETTINGS_H3_DATAGRAM=1 negotiation.
        let settings = H3Settings {
            qpack_max_table_capacity: Some(4096),
            max_field_section_size: Some(8192),
            qpack_blocked_streams: None,
            enable_connect_protocol: Some(false),
            h3_datagram: Some(true), // Enable DATAGRAM
            unknown: vec![],
        };

        let mut buf = Vec::new();
        settings.encode_payload(&mut buf).expect("encode settings");
        let decoded = H3Settings::decode_payload(&buf).expect("decode settings");
        assert_eq!(decoded.h3_datagram, Some(true));
    }

    #[cfg(feature = "http3")]
    #[test]
    fn settings_h3_datagram_disabled() {
        // Test SETTINGS_H3_DATAGRAM=0 (explicitly disabled).
        let settings = H3Settings {
            qpack_max_table_capacity: None,
            max_field_section_size: None,
            qpack_blocked_streams: None,
            enable_connect_protocol: None,
            h3_datagram: Some(false), // Explicitly disabled
            unknown: vec![],
        };

        let mut buf = Vec::new();
        settings.encode_payload(&mut buf).expect("encode settings");
        let decoded = H3Settings::decode_payload(&buf).expect("decode settings");
        assert_eq!(decoded.h3_datagram, Some(false));
    }

    #[cfg(feature = "http3")]
    #[test]
    fn settings_h3_datagram_not_negotiated() {
        // Test when SETTINGS_H3_DATAGRAM is not present (None).
        let settings = H3Settings {
            qpack_max_table_capacity: Some(1024),
            max_field_section_size: None,
            qpack_blocked_streams: None,
            enable_connect_protocol: None,
            h3_datagram: None, // Not negotiated
            unknown: vec![],
        };

        let mut buf = Vec::new();
        settings.encode_payload(&mut buf).expect("encode settings");
        let decoded = H3Settings::decode_payload(&buf).expect("decode settings");
        assert_eq!(decoded.h3_datagram, None);
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_context_id_boundary_values() {
        // Test boundary values for quarter_stream_id (context identifier).
        let test_cases = vec![
            0u64,             // Minimum value
            1,                // Minimum non-zero
            63,               // Single-byte varint maximum
            64,               // Two-byte varint minimum
            16383,            // Two-byte varint maximum
            16384,            // Three-byte varint minimum
            1073741823,       // Four-byte varint maximum
            (1u64 << 30),     // Five-byte varint minimum
            (1u64 << 62) - 1, // Maximum 62-bit value
        ];

        for quarter_stream_id in test_cases {
            let frame = H3Frame::Datagram {
                quarter_stream_id,
                payload: vec![0x00, 0x01],
            };
            let mut buf = Vec::new();
            frame
                .encode(&mut buf)
                .unwrap_or_else(|_| panic!("encode quarter_stream_id={quarter_stream_id}"));
            let (decoded, consumed) = H3Frame::decode(&buf, &test_config())
                .unwrap_or_else(|_| panic!("decode quarter_stream_id={quarter_stream_id}"));
            assert_eq!(decoded, frame);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn datagram_frame_decode_truncated_quarter_stream_id() {
        // Test frame with truncated quarter_stream_id varint.
        let mut buf = Vec::new();
        encode_varint(H3_FRAME_DATAGRAM, &mut buf).expect("frame type");
        encode_varint(2, &mut buf).expect("frame length");
        buf.push(0x80); // Incomplete varint (continuation bit set but no following byte)

        let err = H3Frame::decode(&buf, &test_config())
            .expect_err("must reject truncated quarter_stream_id");
        assert_eq!(err, H3NativeError::InvalidFrame("quarter stream id varint"));
    }

    #[test]
    fn datagram_frame_decode_truncated_payload() {
        // Test frame where declared length exceeds available data.
        let mut buf = Vec::new();
        encode_varint(H3_FRAME_DATAGRAM, &mut buf).expect("frame type");
        encode_varint(10, &mut buf).expect("frame length - claims 10 bytes");
        encode_varint(5, &mut buf).expect("quarter_stream_id");
        buf.extend_from_slice(&[0x01, 0x02]); // Only 2 bytes payload, but frame claims 10 total

        let err = H3Frame::decode(&buf, &test_config()).expect_err("must reject truncated payload");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("insufficient frame payload")
        );
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_varint_quarter_stream_id_encoding() {
        // Verify quarter_stream_id is properly encoded as varint in different ranges.
        let test_cases = vec![
            (0u64, vec![0x00]),                     // Zero
            (42, vec![0x2A]),                       // Single byte
            (300, vec![0x41, 0x2C]),                // Two bytes
            (100000, vec![0x80, 0x01, 0x86, 0xA0]), // Four bytes
        ];

        for (quarter_stream_id, expected_varint) in test_cases {
            let frame = H3Frame::Datagram {
                quarter_stream_id,
                payload: vec![0xFF],
            };
            let mut buf = Vec::new();
            frame.encode(&mut buf).expect("encode");

            // Skip frame type and length, check quarter_stream_id encoding
            let (_, type_len) = decode_varint(&buf).expect("frame type");
            let (declared_length, len_len) = decode_varint(&buf[type_len..]).expect("frame length");
            let quarter_stream_id_start = type_len + len_len;
            let (decoded_id, id_len) =
                decode_varint(&buf[quarter_stream_id_start..]).expect("quarter_stream_id");

            assert_eq!(decoded_id, quarter_stream_id);
            assert_eq!(declared_length as usize, id_len + 1);
            assert_eq!(
                &buf[quarter_stream_id_start..quarter_stream_id_start + id_len],
                &expected_varint
            );
        }
    }

    // =========================================================================
    // 0-RTT Early Data Conformance Tests - RFC 8446 Section 4.2.10
    // =========================================================================

    /// 0-RTT state tracker for testing early data acceptance rules.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ZeroRttState {
        /// 0-RTT not attempted or not available.
        NotAttempted,
        /// 0-RTT attempted, waiting for handshake completion.
        Pending,
        /// 0-RTT accepted by server.
        Accepted,
        /// 0-RTT rejected by server.
        Rejected,
        /// Handshake completed (1-RTT established).
        HandshakeComplete,
    }

    /// Configuration for 0-RTT early data limits and policies.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ZeroRttConfig {
        /// Maximum early data bytes allowed.
        pub max_early_data: u64,
        /// Whether to allow HTTP requests in early data.
        pub allow_early_requests: bool,
        /// Whether to allow SETTINGS frames in early data.
        pub allow_early_settings: bool,
        /// Current 0-RTT state.
        pub state: ZeroRttState,
        /// Bytes of early data sent so far.
        pub early_data_sent: u64,
    }

    impl Default for ZeroRttConfig {
        fn default() -> Self {
            Self {
                max_early_data: 16384, // 16KB default
                allow_early_requests: true,
                allow_early_settings: false, // Conservative default
                state: ZeroRttState::NotAttempted,
                early_data_sent: 0,
            }
        }
    }

    impl ZeroRttConfig {
        /// Check if early data is currently allowed.
        pub fn is_early_data_allowed(&self) -> bool {
            matches!(self.state, ZeroRttState::Pending | ZeroRttState::Accepted)
        }

        /// Check if we can send more early data.
        ///
        /// Uses `checked_add` so that overflow past `u64::MAX` is treated as
        /// exceeding the 0-RTT budget rather than saturating and silently
        /// re-permitting a byte that is not actually available.
        pub fn can_send_early_data(&self, additional_bytes: u64) -> bool {
            if !self.is_early_data_allowed() {
                return false;
            }
            match self.early_data_sent.checked_add(additional_bytes) {
                Some(total) => total <= self.max_early_data,
                None => false,
            }
        }

        /// Record early data sent.
        pub fn record_early_data_sent(&mut self, bytes: u64) -> Result<(), H3NativeError> {
            if !self.is_early_data_allowed() {
                return Err(H3NativeError::StreamProtocol(
                    "0-RTT not allowed in current state",
                ));
            }
            if !self.can_send_early_data(bytes) {
                return Err(H3NativeError::StreamProtocol("early data limit exceeded"));
            }
            self.early_data_sent = self.early_data_sent.saturating_add(bytes);
            Ok(())
        }

        /// Validate if a frame can be sent in early data.
        pub fn validate_early_frame(&self, frame: &H3Frame) -> Result<(), H3NativeError> {
            if !self.is_early_data_allowed() {
                return Ok(()); // Not in 0-RTT, no restrictions
            }

            match frame {
                // DATA and HEADERS are allowed in early data for requests
                H3Frame::Data(_) | H3Frame::Headers(_) if self.allow_early_requests => Ok(()),

                // SETTINGS may or may not be allowed based on policy
                H3Frame::Settings(_) if self.allow_early_settings => Ok(()),

                // Control frames that should wait for handshake completion
                H3Frame::Settings(_) if !self.allow_early_settings => Err(
                    H3NativeError::StreamProtocol("SETTINGS frame not allowed in 0-RTT"),
                ),

                // Frames that must never be sent in 0-RTT
                H3Frame::Goaway(_) | H3Frame::MaxPushId(_) => Err(H3NativeError::StreamProtocol(
                    "control frame not allowed in 0-RTT",
                )),

                // PUSH_PROMISE should not be sent in early data
                H3Frame::PushPromise { .. } => Err(H3NativeError::StreamProtocol(
                    "PUSH_PROMISE not allowed in 0-RTT",
                )),

                // Other frames follow default policy
                _ => {
                    if self.allow_early_requests {
                        Ok(())
                    } else {
                        Err(H3NativeError::StreamProtocol("frame not allowed in 0-RTT"))
                    }
                }
            }
        }
    }

    #[test]
    fn zero_rtt_state_transitions() {
        let mut config = ZeroRttConfig::default();
        assert_eq!(config.state, ZeroRttState::NotAttempted);
        assert!(!config.is_early_data_allowed());

        // Transition to pending 0-RTT
        config.state = ZeroRttState::Pending;
        assert!(config.is_early_data_allowed());
        assert!(config.can_send_early_data(1000));

        // Transition to accepted
        config.state = ZeroRttState::Accepted;
        assert!(config.is_early_data_allowed());

        // Transition to handshake complete
        config.state = ZeroRttState::HandshakeComplete;
        assert!(!config.is_early_data_allowed());

        // Transition to rejected
        config.state = ZeroRttState::Rejected;
        assert!(!config.is_early_data_allowed());
    }

    #[test]
    fn zero_rtt_early_data_limits() {
        let mut config = ZeroRttConfig {
            max_early_data: 1000,
            state: ZeroRttState::Pending,
            ..ZeroRttConfig::default()
        };

        // Can send within limit
        assert!(config.can_send_early_data(500));
        config
            .record_early_data_sent(500)
            .expect("record early data");
        assert_eq!(config.early_data_sent, 500);

        // Can send up to limit
        assert!(config.can_send_early_data(500));
        config
            .record_early_data_sent(500)
            .expect("record remaining");
        assert_eq!(config.early_data_sent, 1000);

        // Cannot exceed limit
        assert!(!config.can_send_early_data(1));
        let err = config.record_early_data_sent(1).expect_err("should reject");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));
    }

    #[test]
    fn zero_rtt_frame_validation_allows_requests() {
        let config = ZeroRttConfig {
            state: ZeroRttState::Pending,
            allow_early_requests: true,
            allow_early_settings: false,
            ..ZeroRttConfig::default()
        };

        // DATA and HEADERS should be allowed for requests
        let data_frame = H3Frame::Data(vec![1, 2, 3]);
        config
            .validate_early_frame(&data_frame)
            .expect("DATA allowed");

        let headers_frame = H3Frame::Headers(vec![4, 5, 6]);
        config
            .validate_early_frame(&headers_frame)
            .expect("HEADERS allowed");
    }

    #[test]
    fn zero_rtt_frame_validation_rejects_control_frames() {
        let config = ZeroRttConfig {
            state: ZeroRttState::Pending,
            allow_early_requests: true,
            allow_early_settings: false,
            ..ZeroRttConfig::default()
        };

        // Control frames should be rejected
        let settings_frame = H3Frame::Settings(H3Settings::default());
        let err = config
            .validate_early_frame(&settings_frame)
            .expect_err("SETTINGS rejected");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));

        let goaway_frame = H3Frame::Goaway(123);
        let err = config
            .validate_early_frame(&goaway_frame)
            .expect_err("GOAWAY rejected");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));

        let max_push_frame = H3Frame::MaxPushId(456);
        let err = config
            .validate_early_frame(&max_push_frame)
            .expect_err("MAX_PUSH_ID rejected");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));

        let push_promise_frame = H3Frame::PushPromise {
            push_id: 789,
            field_block: vec![7, 8, 9],
        };
        let err = config
            .validate_early_frame(&push_promise_frame)
            .expect_err("PUSH_PROMISE rejected");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));
    }

    #[test]
    fn zero_rtt_settings_policy_enforcement() {
        let mut config = ZeroRttConfig {
            state: ZeroRttState::Pending,
            allow_early_settings: true,
            ..ZeroRttConfig::default()
        };

        // SETTINGS allowed when policy permits
        let settings_frame = H3Frame::Settings(H3Settings::default());
        config
            .validate_early_frame(&settings_frame)
            .expect("SETTINGS allowed with policy");

        // SETTINGS rejected when policy forbids
        config.allow_early_settings = false;
        let err = config
            .validate_early_frame(&settings_frame)
            .expect_err("SETTINGS rejected by policy");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));
    }

    #[test]
    fn zero_rtt_request_policy_enforcement() {
        let config = ZeroRttConfig {
            state: ZeroRttState::Pending,
            allow_early_requests: false,
            ..ZeroRttConfig::default()
        };

        // DATA and HEADERS rejected when requests not allowed
        let data_frame = H3Frame::Data(vec![1, 2, 3]);
        let err = config
            .validate_early_frame(&data_frame)
            .expect_err("DATA rejected by policy");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));

        let headers_frame = H3Frame::Headers(vec![4, 5, 6]);
        let err = config
            .validate_early_frame(&headers_frame)
            .expect_err("HEADERS rejected by policy");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));
    }

    #[test]
    fn zero_rtt_no_restrictions_after_handshake() {
        let config = ZeroRttConfig {
            state: ZeroRttState::HandshakeComplete,
            allow_early_requests: false,
            allow_early_settings: false,
            ..ZeroRttConfig::default()
        };

        // All frames allowed after handshake completion
        let settings_frame = H3Frame::Settings(H3Settings::default());
        config
            .validate_early_frame(&settings_frame)
            .expect("SETTINGS allowed after handshake");

        let goaway_frame = H3Frame::Goaway(123);
        config
            .validate_early_frame(&goaway_frame)
            .expect("GOAWAY allowed after handshake");

        let data_frame = H3Frame::Data(vec![1, 2, 3]);
        config
            .validate_early_frame(&data_frame)
            .expect("DATA allowed after handshake");
    }

    #[test]
    fn zero_rtt_replay_protection_state_isolation() {
        // Test that 0-RTT state is properly isolated to prevent replay attacks
        let mut config1 = ZeroRttConfig {
            state: ZeroRttState::Accepted,
            max_early_data: 1000,
            ..ZeroRttConfig::default()
        };

        let mut config2 = ZeroRttConfig {
            state: ZeroRttState::Rejected,
            ..ZeroRttConfig::default()
        };

        // First connection can send early data
        config1
            .record_early_data_sent(500)
            .expect("config1 early data");
        assert_eq!(config1.early_data_sent, 500);

        // Second connection (replayed) cannot send early data
        let err = config2
            .record_early_data_sent(500)
            .expect_err("config2 should reject");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));
        assert_eq!(config2.early_data_sent, 0);
    }

    #[test]
    fn zero_rtt_conservative_defaults() {
        let config = ZeroRttConfig::default();

        // Conservative defaults: allow requests but not control frames
        assert!(config.allow_early_requests);
        assert!(!config.allow_early_settings);
        assert_eq!(config.max_early_data, 16384); // 16KB
        assert_eq!(config.state, ZeroRttState::NotAttempted);
        assert_eq!(config.early_data_sent, 0);
    }

    #[test]
    fn zero_rtt_saturation_arithmetic() {
        let mut config = ZeroRttConfig {
            state: ZeroRttState::Pending,
            max_early_data: u64::MAX,
            early_data_sent: u64::MAX - 100,
            ..ZeroRttConfig::default()
        };

        // Should saturate without overflow
        assert!(config.can_send_early_data(50));
        config.record_early_data_sent(50).expect("within bounds");

        assert!(config.can_send_early_data(50));
        config.record_early_data_sent(50).expect("exactly at limit");

        // Should not allow more after saturation
        assert!(!config.can_send_early_data(1));
    }

    // ========== QPACK Dynamic Table Eviction Conformance Tests ==========

    #[test]
    fn qpack_conformance_dynamic_table_lru_eviction() {
        // Conformance: RFC 9204 Section 3.2 - Dynamic Table
        // LRU eviction must evict least recently inserted unreferenced entries first.

        let mut table = QpackDynamicTable::new(200); // Small table for testing

        // Insert entries that together exceed capacity
        let id1 = table.insert("header-a".into(), "value-a".into()).unwrap();
        let id2 = table.insert("header-b".into(), "value-b".into()).unwrap();
        let id3 = table.insert("header-c".into(), "value-c".into()).unwrap();

        assert_eq!(table.len(), 3);

        // Insert a large entry that requires eviction
        let id4 = table
            .insert(
                "large-header".into(),
                "very-large-value-that-forces-eviction".into(),
            )
            .unwrap();

        // First entry (oldest, LRU) should have been evicted
        assert!(table.len() < 4);
        assert!(!table.reference_entry(id1)); // id1 should be gone
        assert!(table.reference_entry(id2)); // id2+ should still exist
        assert!(table.reference_entry(id3));
        assert!(table.reference_entry(id4));
    }

    #[test]
    fn qpack_conformance_dynamic_table_reference_protection() {
        // Conformance: RFC 9204 Section 3.2 - Referenced entries cannot be evicted.

        let mut table = QpackDynamicTable::new(150);

        let id1 = table
            .insert("ref-header".into(), "ref-value".into())
            .unwrap();
        let id2 = table
            .insert("temp-header".into(), "temp-value".into())
            .unwrap();

        // Reference the first entry
        assert!(table.reference_entry(id1));

        // Insert entries that would normally evict both
        let _id3 = table
            .insert("push-header-1".into(), "push-value-1".into())
            .unwrap();
        let _id4 = table
            .insert("push-header-2".into(), "push-value-2".into())
            .unwrap();

        // Referenced entry should be protected, unreferenced should be evicted
        assert!(table.reference_entry(id1)); // Still referenced and present
        assert!(!table.reference_entry(id2)); // Should be evicted
    }

    #[test]
    fn qpack_conformance_dynamic_table_size_accounting() {
        // Conformance: RFC 9204 Section 4.4 - Dynamic table size calculation.
        // Size = 32 + name_len + value_len for each entry.

        let mut table = QpackDynamicTable::new(1000);
        let initial_size = table.size();

        // Insert entry: 32 + 4 + 5 = 41 bytes
        let _id1 = table.insert("name".into(), "value".into()).unwrap();
        assert_eq!(table.size(), initial_size + 41);

        // Insert another: 32 + 7 + 8 = 47 bytes
        let _id2 = table.insert("content".into(), "response".into()).unwrap();
        assert_eq!(table.size(), initial_size + 41 + 47);

        // Size accounting must be exact
        assert!(table.size() <= table.capacity());
    }

    #[test]
    fn qpack_conformance_dynamic_table_capacity_enforcement() {
        // Conformance: RFC 9204 Section 3.2 - Table must not exceed max capacity.

        let capacity = 100;
        let mut table = QpackDynamicTable::new(capacity);

        // Fill table close to capacity
        let _id1 = table.insert("a".into(), "b".into()).unwrap(); // 32 + 1 + 1 = 34
        let _id2 = table.insert("c".into(), "d".into()).unwrap(); // 32 + 1 + 1 = 34

        assert_eq!(table.size(), 68);

        // Try to insert entry larger than remaining space
        let _id3 = table.insert("large".into(), "header-value".into()).unwrap(); // 32 + 5 + 12 = 49

        // Should have evicted entries to make space
        assert!(table.size() <= capacity);

        // Try to insert entry larger than total capacity
        let result = table.insert(
            "oversized-header-name".into(),
            "oversized-header-value-that-exceeds-table-capacity".into(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn qpack_conformance_dynamic_table_insertion_pressure() {
        // Conformance: Under heavy insertion pressure, table should maintain
        // size constraints while evicting appropriate entries.

        let mut table = QpackDynamicTable::new(200);
        let mut insertion_ids = Vec::new();

        // Insert many small entries
        for i in 0..20 {
            let name = format!("header-{}", i);
            let value = format!("value-{}", i);
            if let Ok(id) = table.insert(name, value) {
                insertion_ids.push(id);
            }
        }

        // Table should not exceed capacity
        assert!(table.size() <= table.capacity());

        // Some entries should have been evicted due to pressure
        assert!(table.evicted_count > 0);

        // Verify LRU ordering - early entries should be evicted first
        let first_half_present = insertion_ids
            .iter()
            .take(10)
            .filter(|&&id| table.reference_entry(id))
            .count();
        let second_half_present = insertion_ids
            .iter()
            .skip(10)
            .filter(|&&id| table.reference_entry(id))
            .count();

        // Later entries should be more likely to remain
        assert!(second_half_present >= first_half_present);
    }

    #[test]
    fn qpack_conformance_dynamic_table_reference_lifecycle() {
        // Conformance: Reference counting must accurately track entry usage.

        let mut table = QpackDynamicTable::new(300);

        let id1 = table
            .insert("lifecycle".into(), "test-entry".into())
            .unwrap();

        // Add multiple references
        assert!(table.reference_entry(id1));
        assert!(table.reference_entry(id1));
        assert!(table.reference_entry(id1));

        // Entry should be protected from eviction
        for i in 0..10 {
            let _ = table.insert(format!("filler-{}", i), "filler-value".into());
        }

        // Should still be referenceable (not evicted)
        assert!(table.reference_entry(id1));

        // Remove references gradually
        assert!(table.unreference_entry(id1));
        assert!(table.unreference_entry(id1));
        assert!(table.unreference_entry(id1));
        assert!(table.unreference_entry(id1)); // Remove extra reference we added for testing

        // Now should be evictable
        let large_entry_result = table.insert(
            "force-eviction".into(),
            "large-value-to-trigger-eviction-of-unreferenced-entries".into(),
        );
        assert!(large_entry_result.is_ok());

        // Entry should now be evicted (no longer referenceable)
        assert!(!table.reference_entry(id1));
    }

    #[test]
    fn qpack_conformance_dynamic_table_memory_pressure_simulation() {
        // Conformance: Table should gracefully handle memory pressure scenarios.

        let small_capacity = 150;
        let mut table = QpackDynamicTable::new(small_capacity);

        // Scenario 1: Many tiny entries
        let mut tiny_ids = Vec::new();
        for i in 0..50 {
            if let Ok(id) = table.insert(format!("t{}", i), "x".into()) {
                tiny_ids.push(id);
            }
        }
        assert!(table.size() <= small_capacity);

        // Scenario 2: Mix of sizes with references
        let medium_id = table
            .insert("medium-header".into(), "medium-value".into())
            .unwrap();
        assert!(table.reference_entry(medium_id));

        // Scenario 3: Sudden large insertion
        let large_result = table.insert(
            "emergency-large".into(),
            "large-emergency-header-value".into(),
        );
        assert!(large_result.is_ok());

        // Referenced medium entry should survive, unreferenced tiny entries evicted
        assert!(table.reference_entry(medium_id));
        assert!(table.size() <= small_capacity);

        // Scenario 4: Capacity exhaustion with all entries referenced
        let ids: Vec<_> = table.entries.iter().map(|e| e.insertion_order).collect();
        for id in ids {
            // Try to reference all remaining entries
            let _ = table.reference_entry(id);
        }

        let impossible_result = table.insert(
            "impossible".into(),
            "this-should-fail-due-to-references".into(),
        );
        // Should fail when no entries can be evicted
        assert!(impossible_result.is_err());
    }

    #[test]
    fn qpack_conformance_dynamic_table_eviction_order_deterministic() {
        // Conformance: Eviction order must be deterministic and follow LRU strictly.

        let mut table1 = QpackDynamicTable::new(120);
        let mut table2 = QpackDynamicTable::new(120);

        // Insert identical sequences in both tables
        let sequence = vec![
            ("first", "entry"),
            ("second", "entry"),
            ("third", "entry"),
            ("fourth", "entry"),
        ];

        let mut ids1 = Vec::new();
        let mut ids2 = Vec::new();

        for (name, value) in &sequence {
            ids1.push(table1.insert(name.to_string(), value.to_string()).unwrap());
            ids2.push(table2.insert(name.to_string(), value.to_string()).unwrap());
        }

        // Force eviction with identical large entry
        let large_name = "eviction-trigger";
        let large_value = "large-value-that-forces-eviction";

        let _final1 = table1
            .insert(large_name.into(), large_value.into())
            .unwrap();
        let _final2 = table2
            .insert(large_name.into(), large_value.into())
            .unwrap();

        // Both tables should have identical state after eviction
        assert_eq!(table1.len(), table2.len());
        assert_eq!(table1.size(), table2.size());
        assert_eq!(table1.evicted_count, table2.evicted_count);

        // Surviving entries should be the same in both tables
        for (id1, id2) in ids1.iter().zip(ids2.iter()) {
            let present1 = table1.reference_entry(*id1);
            let present2 = table2.reference_entry(*id2);
            assert_eq!(present1, present2, "Eviction determinism violated");
        }
    }

    #[test]
    fn frame_payload_size_limit_enforcement() {
        // Test that frame payload size limits are enforced per RFC 9114 §4.2
        let config = H3ConnectionConfig {
            max_frame_payload_size: 100, // Very small limit for testing
            ..Default::default()
        };

        // Create a DATA frame with payload larger than the limit
        let large_payload = vec![0x42; 200]; // 200 bytes > 100 byte limit
        let frame = H3Frame::Data(large_payload);

        // Encode the frame
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode should succeed");

        // Decode should fail due to payload size limit
        let err = H3Frame::decode(&buf, &config).expect_err("decode must reject oversized frame");
        match err {
            H3NativeError::FrameTooLarge {
                payload_size,
                max_size,
            } => {
                assert_eq!(payload_size, 200);
                assert_eq!(max_size, 100);
            }
            other => panic!("expected FrameTooLarge error, got: {:?}", other), // ubs:ignore - test logic
        }

        // Test that frames within the limit still work
        let small_payload = vec![0x42; 50]; // 50 bytes < 100 byte limit
        let small_frame = H3Frame::Data(small_payload.clone());

        let mut small_buf = Vec::new();
        small_frame
            .encode(&mut small_buf)
            .expect("encode small frame");

        let (decoded, consumed) = H3Frame::decode(&small_buf, &config).expect("decode small frame");
        assert_eq!(decoded, small_frame);
        assert_eq!(consumed, small_buf.len());
    }

    #[test]
    fn frame_payload_size_limit_applies_to_all_frame_types() {
        let config = H3ConnectionConfig {
            max_frame_payload_size: 50,
            ..Default::default()
        };

        // Test HEADERS frame
        let large_headers_payload = vec![0x00; 100]; // Larger than 50-byte limit
        let headers_frame = H3Frame::Headers(large_headers_payload);

        let mut buf = Vec::new();
        headers_frame
            .encode(&mut buf)
            .expect("encode headers frame");

        let err = H3Frame::decode(&buf, &config).expect_err("headers frame must be rejected");
        assert!(matches!(err, H3NativeError::FrameTooLarge { .. }));

        // Test PUSH_PROMISE frame
        let large_field_block = vec![0x00; 100];
        let push_promise_frame = H3Frame::PushPromise {
            push_id: 42,
            field_block: large_field_block,
        };

        let mut buf = Vec::new();
        push_promise_frame
            .encode(&mut buf)
            .expect("encode push promise frame");

        let err = H3Frame::decode(&buf, &config).expect_err("push promise frame must be rejected");
        assert!(matches!(err, H3NativeError::FrameTooLarge { .. }));
    }

    #[test]
    fn concurrent_stream_limit_rejects_new_stream_once_full() {
        let mut c = H3ConnectionState::with_config(H3ConnectionConfig {
            max_concurrent_request_streams: Some(2),
            ..H3ConnectionConfig::default()
        });
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");

        // Two client-initiated bidi streams (ids 0, 4) occupy the cap.
        c.on_request_stream_frame(0, &H3Frame::Headers(vec![1]))
            .expect("first within limit");
        c.on_request_stream_frame(4, &H3Frame::Headers(vec![2]))
            .expect("second within limit");
        assert_eq!(c.active_request_stream_count(), 2);

        // Third new stream (id 8) must be rejected with the dedicated error,
        // reporting both the current count and the negotiated limit.
        let err = c
            .on_request_stream_frame(8, &H3Frame::Headers(vec![3]))
            .expect_err("third stream must exceed cap");
        assert_eq!(
            err,
            H3NativeError::ConcurrentStreamLimitExceeded {
                active: 2,
                limit: 2,
            }
        );
        // Rejection must not have created state for the rejected id.
        assert_eq!(c.active_request_stream_count(), 2);
    }

    #[test]
    fn concurrent_stream_limit_does_not_block_frames_on_existing_streams() {
        let mut c = H3ConnectionState::with_config(H3ConnectionConfig {
            max_concurrent_request_streams: Some(1),
            ..H3ConnectionConfig::default()
        });
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");

        c.on_request_stream_frame(0, &H3Frame::Headers(vec![1]))
            .expect("create stream 0");
        // Follow-up DATA on the same stream must still be accepted even
        // though active_count == limit — the cap applies to *new* streams.
        c.on_request_stream_frame(0, &H3Frame::Data(vec![0xAA]))
            .expect("additional frame on existing stream");
    }

    #[test]
    fn concurrent_stream_limit_allows_new_stream_after_finish() {
        let mut c = H3ConnectionState::with_config(H3ConnectionConfig {
            max_concurrent_request_streams: Some(1),
            ..H3ConnectionConfig::default()
        });
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");

        c.on_request_stream_frame(0, &H3Frame::Headers(vec![1]))
            .expect("first stream");
        c.finish_request_stream(0).expect("finish first stream");
        // With the first stream finished, active count drops to 0 and a
        // new stream id must be admitted.
        c.on_request_stream_frame(4, &H3Frame::Headers(vec![2]))
            .expect("second stream after finish");
        assert_eq!(c.active_request_stream_count(), 1);
    }

    #[test]
    fn concurrent_stream_limit_unbounded_by_default() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        // No cap configured — opening many streams must not error.
        for stream_id in (0..20).map(|i| i * 4) {
            c.on_request_stream_frame(stream_id, &H3Frame::Headers(vec![1]))
                .expect("unbounded by default");
        }
        assert_eq!(c.active_request_stream_count(), 20);
    }

    #[test]
    fn concurrent_stream_limit_runtime_update_applies_to_future_streams() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        c.on_request_stream_frame(0, &H3Frame::Headers(vec![1]))
            .expect("first stream");
        c.on_request_stream_frame(4, &H3Frame::Headers(vec![2]))
            .expect("second stream");

        // Tighten the cap after the fact. Already-live streams stay live,
        // but a new stream id beyond the cap must be rejected.
        c.set_max_concurrent_request_streams(Some(2));
        let err = c
            .on_request_stream_frame(8, &H3Frame::Headers(vec![3]))
            .expect_err("third stream must exceed tightened cap");
        assert!(matches!(
            err,
            H3NativeError::ConcurrentStreamLimitExceeded {
                active: 2,
                limit: 2
            }
        ));
        // In-flight frames on existing stream 4 still pass.
        c.on_request_stream_frame(4, &H3Frame::Data(vec![0xAA]))
            .expect("existing stream unaffected");
    }

    #[test]
    fn bidirectional_frame_validation_allows_valid_frames() {
        // DATA frames are allowed on bidirectional streams
        let data_frame = H3Frame::Data(vec![1, 2, 3]);
        validate_bidirectional_frame(&data_frame).expect("DATA frame should be allowed");

        // HEADERS frames are allowed on bidirectional streams
        let headers_frame = H3Frame::Headers(vec![4, 5, 6]);
        validate_bidirectional_frame(&headers_frame).expect("HEADERS frame should be allowed");

        // PUSH_PROMISE frames can be sent by servers on request streams
        let push_promise_frame = H3Frame::PushPromise {
            push_id: 123,
            field_block: vec![7, 8, 9],
        };
        validate_bidirectional_frame(&push_promise_frame)
            .expect("PUSH_PROMISE frame should be allowed");

        // DATAGRAM frames are sent on bidirectional streams per RFC 9297
        let datagram_frame = H3Frame::Datagram {
            quarter_stream_id: 456,
            payload: vec![10, 11, 12],
        };
        validate_bidirectional_frame(&datagram_frame).expect("DATAGRAM frame should be allowed");
    }

    #[test]
    fn bidirectional_frame_validation_rejects_control_frames() {
        // SETTINGS frames belong on control streams
        let settings_frame = H3Frame::Settings(H3Settings::default());
        let err =
            validate_bidirectional_frame(&settings_frame).expect_err("SETTINGS should be rejected");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("SETTINGS frame not allowed on bidirectional stream")
        );

        // CANCEL_PUSH frames belong on control streams
        let cancel_push_frame = H3Frame::CancelPush(789);
        let err = validate_bidirectional_frame(&cancel_push_frame)
            .expect_err("CANCEL_PUSH should be rejected");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("CANCEL_PUSH frame not allowed on bidirectional stream")
        );

        // GOAWAY frames belong on control streams
        let goaway_frame = H3Frame::Goaway(101);
        let err =
            validate_bidirectional_frame(&goaway_frame).expect_err("GOAWAY should be rejected");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("GOAWAY frame not allowed on bidirectional stream")
        );

        // MAX_PUSH_ID frames belong on control streams
        let max_push_id_frame = H3Frame::MaxPushId(202);
        let err = validate_bidirectional_frame(&max_push_id_frame)
            .expect_err("MAX_PUSH_ID should be rejected");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("MAX_PUSH_ID frame not allowed on bidirectional stream")
        );
    }

    #[test]
    fn bidirectional_frame_validation_ignores_unknown_frames_per_rfc9114_7_2_8() {
        // RFC 9114 §7.2.8: unknown frame types received on a request stream
        // MUST be ignored (silently skipped). Validates the GREASE /
        // forward-compatibility contract — see br-asupersync-94bp7i.

        // Arbitrary unknown type with payload.
        let unknown_frame = H3Frame::Unknown {
            frame_type: 0xDEAD_BEEF,
            payload: vec![13, 14, 15],
        };
        validate_bidirectional_frame(&unknown_frame).expect(
            "RFC 9114 §7.2.8 violation: unknown frame on bidi stream must be ignored, not errored",
        );

        // Empty-payload unknown type.
        let unknown_empty = H3Frame::Unknown {
            frame_type: 0xF00D,
            payload: Vec::new(),
        };
        validate_bidirectional_frame(&unknown_empty)
            .expect("RFC 9114 §7.2.8 violation: empty-payload unknown frame must be ignored");

        // Canonical GREASE frame type per RFC 9114 §7.2.8 (0x1f * N + 0x21).
        // We exercise N = 0 (type 0x21) and N = 1 (type 0x40).
        for grease_type in [0x21u64, 0x40u64, 0x1f * 12345 + 0x21] {
            let grease = H3Frame::Unknown {
                frame_type: grease_type,
                payload: vec![0xAA; 32],
            };
            validate_bidirectional_frame(&grease).unwrap_or_else(|e| {
                panic!(
                    "RFC 9114 §7.2.8 violation: GREASE frame type 0x{grease_type:x} \
                     rejected on bidi stream (got {e:?}); MUST be ignored"
                )
            });
        }
    }

    #[test]
    fn qpack_decode_enforces_max_field_section_size() {
        // Create a valid QPACK-encoded field section with static headers
        let plan = vec![
            QpackFieldPlan::StaticIndex(17), // :method GET
            QpackFieldPlan::StaticIndex(23), // :scheme https
            QpackFieldPlan::StaticIndex(1),  // :path /
            QpackFieldPlan::Literal {
                name: "x-large-header".to_string(),
                value: "a".repeat(1000), // 1000 byte value
            },
        ];
        let wire = qpack_encode_field_section(&plan).expect("encode");

        // Test that decode succeeds without limit
        let result = qpack_decode_request_field_section(&wire, H3QpackMode::StaticOnly, None);
        assert!(result.is_ok(), "decode should succeed without limit");

        // RFC 9114 §4.2.2 size = sum(name.len()+value.len()+32) per field.
        // 3 static (:method GET=42, :scheme https=44, :path /=38) + literal
        // (x-large-header(14)+"a"*1000+32 = 1046) = 1170 bytes.
        let result = qpack_decode_request_field_section_with_limit(
            &wire,
            H3QpackMode::StaticOnly,
            None,
            Some(1200),
        );
        assert!(result.is_ok(), "decode should succeed with high limit");

        // Test that decode fails with low limit
        let err = qpack_decode_request_field_section_with_limit(
            &wire,
            H3QpackMode::StaticOnly,
            None,
            Some(500),
        )
        .expect_err("decode should fail with low limit");

        assert_eq!(
            err,
            H3NativeError::QpackPolicy("decoded field section exceeds maximum size limit")
        );

        // Test response function too
        let response_plan = vec![
            QpackFieldPlan::StaticIndex(25), // :status 200
            QpackFieldPlan::Literal {
                name: "x-response-header".to_string(),
                value: "b".repeat(800), // 800 byte value
            },
        ];
        let response_wire = qpack_encode_field_section(&response_plan).expect("encode response");

        let err = qpack_decode_response_field_section_with_limit(
            &response_wire,
            H3QpackMode::StaticOnly,
            None,
            Some(400),
        )
        .expect_err("response decode should fail with low limit");

        assert_eq!(
            err,
            H3NativeError::QpackPolicy("decoded field section exceeds maximum size limit")
        );
    }
}
