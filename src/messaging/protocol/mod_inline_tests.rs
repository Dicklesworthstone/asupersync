    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::{
        ProtocolAdapter, ProtocolAdapterError, ProtocolConnectionState, ProtocolTransportEvent,
        RespProtocolAdapter,
    };
    use crate::cx::Cx;
    use crate::messaging::redis::{RedisProtocolLimits, RespValue};
    use crate::types::{Budget, RegionId, TaskId};

    fn test_cx(slot: u32) -> Cx {
        Cx::new(
            RegionId::new_for_test(slot, 0),
            TaskId::new_for_test(slot, 0),
            Budget::INFINITE,
        )
    }

    #[test]
    fn resp_adapter_reports_handshake_capabilities() {
        let cx = test_cx(1);
        let adapter = RespProtocolAdapter::default();

        let negotiation = adapter.begin_handshake(&cx).expect("handshake succeeds");

        assert_eq!(negotiation.adapter_name, "redis-resp-adapter");
        assert_eq!(negotiation.protocol_family, "redis-resp");
        assert_eq!(negotiation.version_hint, Some("RESP2"));
        assert!(negotiation.capabilities.pipelined_requests);
        assert!(negotiation.capabilities.request_reply);
        assert!(negotiation.capabilities.features.contains(&"bulk_strings"));
    }

    #[test]
    fn resp_adapter_round_trips_resp_frames() {
        let adapter = RespProtocolAdapter::default();
        let frame = RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"PING".to_vec())),
            RespValue::BulkString(Some(b"payload".to_vec())),
        ]));

        let mut encoded = Vec::new();
        adapter
            .encode_message(&frame, &mut encoded)
            .expect("encode succeeds");

        let decoded = adapter
            .try_decode_message(&encoded)
            .expect("decode succeeds")
            .expect("full frame available");

        assert_eq!(decoded.message, frame);
        assert_eq!(decoded.consumed, encoded.len());
    }

    #[test]
    fn resp_adapter_encode_is_append_stable_for_prefilled_buffers() {
        let adapter = RespProtocolAdapter::default();
        let frame = RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"ECHO".to_vec())),
            RespValue::BulkString(Some(b"prefixed".to_vec())),
        ]));

        let mut standalone = Vec::new();
        adapter
            .encode_message(&frame, &mut standalone)
            .expect("standalone encode succeeds");

        let prefix = b"connection-buffer-prefix:";
        let mut prefilled = prefix.to_vec();
        adapter
            .encode_message(&frame, &mut prefilled)
            .expect("prefilled encode succeeds");

        assert_eq!(&prefilled[..prefix.len()], prefix);
        assert_eq!(&prefilled[prefix.len()..], standalone.as_slice());

        let decoded = adapter
            .try_decode_message(&prefilled[prefix.len()..])
            .expect("prefilled suffix decodes")
            .expect("full frame available");

        assert_eq!(decoded.message, frame);
        assert_eq!(decoded.consumed, standalone.len());
    }

    #[test]
    fn resp_adapter_decode_is_prefix_stable_under_pipelined_frames() {
        let adapter = RespProtocolAdapter::default();
        let first = RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"PING".to_vec())),
            RespValue::BulkString(Some(b"one".to_vec())),
        ]));
        let second = RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"ECHO".to_vec())),
            RespValue::BulkString(Some(b"two".to_vec())),
        ]));

        let mut first_frame = Vec::new();
        adapter
            .encode_message(&first, &mut first_frame)
            .expect("first frame encode succeeds");

        let mut second_frame = Vec::new();
        adapter
            .encode_message(&second, &mut second_frame)
            .expect("second frame encode succeeds");

        let baseline = adapter
            .try_decode_message(&first_frame)
            .expect("baseline decode succeeds")
            .expect("baseline frame available");

        let mut pipelined = first_frame.clone();
        pipelined.extend_from_slice(&second_frame);
        let pipelined_first = adapter
            .try_decode_message(&pipelined)
            .expect("pipelined decode succeeds")
            .expect("first pipelined frame available");

        assert_eq!(pipelined_first.message, baseline.message);
        assert_eq!(pipelined_first.consumed, first_frame.len());

        let pipelined_second = adapter
            .try_decode_message(&pipelined[pipelined_first.consumed..])
            .expect("second pipelined decode succeeds")
            .expect("second pipelined frame available");

        assert_eq!(pipelined_second.message, second);
        assert_eq!(pipelined_second.consumed, second_frame.len());
    }

    #[test]
    fn resp_adapter_decode_ignores_partial_trailing_frame() {
        let adapter = RespProtocolAdapter::default();
        let first = RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"SET".to_vec())),
            RespValue::BulkString(Some(b"key".to_vec())),
            RespValue::BulkString(Some(b"value".to_vec())),
        ]));

        let mut first_frame = Vec::new();
        adapter
            .encode_message(&first, &mut first_frame)
            .expect("first frame encode succeeds");
        let baseline = adapter
            .try_decode_message(&first_frame)
            .expect("baseline decode succeeds")
            .expect("baseline frame available");

        let mut with_partial_trailer = first_frame.clone();
        with_partial_trailer.extend_from_slice(b"$5\r\nhe");
        let decoded = adapter
            .try_decode_message(&with_partial_trailer)
            .expect("complete leading frame should decode")
            .expect("leading frame available");

        assert_eq!(decoded.message, baseline.message);
        assert_eq!(decoded.consumed, first_frame.len());
        assert_eq!(
            adapter
                .try_decode_message(&with_partial_trailer[decoded.consumed..])
                .expect("partial trailing frame is not a protocol error"),
            None
        );
    }

    #[test]
    fn resp_adapter_reports_partial_frames_without_consumption() {
        let adapter = RespProtocolAdapter::default();

        let decoded = adapter
            .try_decode_message(b"$5\r\nhe")
            .expect("partial frame should not be a protocol error");

        assert_eq!(decoded, None);
    }

    #[test]
    fn resp_adapter_enforces_configured_decode_limits() {
        let adapter = RespProtocolAdapter::new(RedisProtocolLimits::new().max_bulk_string_len(3));

        let err = adapter
            .try_decode_message(b"$4\r\nfour\r\n")
            .expect_err("oversized bulk string should surface as adapter decode error");

        assert!(matches!(
            err,
            ProtocolAdapterError::Decode { detail, .. }
                if detail.contains("bulk string length 4 exceeds maximum 3")
        ));
    }

    #[test]
    fn resp_adapter_tracks_lifecycle_and_health() {
        let cx = test_cx(2);
        let mut adapter = RespProtocolAdapter::default();

        assert_eq!(adapter.connection_state(), ProtocolConnectionState::Idle);
        assert_eq!(
            adapter.on_transport_event(&cx, ProtocolTransportEvent::Connected),
            Ok(ProtocolConnectionState::Ready)
        );
        assert!(adapter.health_check(&cx).expect("health").ready);
        assert_eq!(
            adapter.on_transport_event(&cx, ProtocolTransportEvent::DrainRequested),
            Ok(ProtocolConnectionState::Draining)
        );
        assert_eq!(
            adapter.on_transport_event(&cx, ProtocolTransportEvent::Closed),
            Ok(ProtocolConnectionState::Closed)
        );
        assert!(!adapter.health_check(&cx).expect("health").ready);
    }

    #[test]
    fn resp_adapter_rejects_reopen_after_close() {
        let cx = test_cx(3);
        let mut adapter = RespProtocolAdapter::default();
        adapter
            .on_transport_event(&cx, ProtocolTransportEvent::Closed)
            .expect("initial close succeeds");

        let err = adapter
            .on_transport_event(&cx, ProtocolTransportEvent::Connected)
            .expect_err("closed adapter should reject reconnect");

        assert!(matches!(err, ProtocolAdapterError::Lifecycle { .. }));
    }

    #[test]
    fn resp_adapter_reset_is_terminal_for_frame_operations() {
        let cx = test_cx(4);
        let mut adapter = RespProtocolAdapter::default();
        assert_eq!(
            adapter.on_transport_event(&cx, ProtocolTransportEvent::Reset),
            Ok(ProtocolConnectionState::Closed)
        );

        let handshake_err = adapter
            .begin_handshake(&cx)
            .expect_err("closed adapter should reject handshake");
        assert!(matches!(
            handshake_err,
            ProtocolAdapterError::Lifecycle { detail, .. }
                if detail.contains("cannot negotiate after transport close")
        ));

        let mut encoded = Vec::new();
        let encode_err = adapter
            .encode_message(&RespValue::SimpleString("PING".to_string()), &mut encoded)
            .expect_err("closed adapter should reject encode");
        assert!(matches!(
            encode_err,
            ProtocolAdapterError::Lifecycle { detail, .. }
                if detail.contains("cannot encode after transport close")
        ));
        assert!(encoded.is_empty());

        let decode_err = adapter
            .try_decode_message(b"+PONG\r\n")
            .expect_err("closed adapter should reject decode");
        assert!(matches!(
            decode_err,
            ProtocolAdapterError::Lifecycle { detail, .. }
                if detail.contains("cannot decode after transport close")
        ));

        let health = adapter.health_check(&cx).expect("closed health");
        assert_eq!(health.state, ProtocolConnectionState::Closed);
        assert!(!health.ready);
        assert_eq!(health.detail, "transport closed");
    }

    #[test]
    fn resp_adapter_observes_cancellation() {
        let cx = test_cx(5);
        cx.set_cancel_requested(true);

        let adapter = RespProtocolAdapter::default();
        let err = adapter
            .begin_handshake(&cx)
            .expect_err("cancelled cx should fail handshake");

        assert_eq!(err, ProtocolAdapterError::Cancelled);
    }
