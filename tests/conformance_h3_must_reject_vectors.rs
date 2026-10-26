//! HTTP/3 RFC 9114 + 9204 + 9297 + 9298 must-reject conformance vectors.
//!
//! Each test asserts that asupersync's `H3ConnectionState` /
//! `H3ControlState` / `H3RequestStreamState` / `validate_*`
//! infrastructure rejects a specific spec-required protocol
//! violation. These tests document the contract and serve as
//! regression guards.
//!
//! Coverage map:
//!   (1) HEADERS frame on the control stream — RFC 9114 §6.2.1
//!       (the control stream carries SETTINGS / GOAWAY / CANCEL_PUSH /
//!       MAX_PUSH_ID only; HEADERS belong on request streams).
//!   (2) Request-stream id rejected when not client-initiated bidi —
//!       RFC 9114 §4.1 (request streams MUST be client-initiated bidi).
//!   (3) Dynamic field sections in static-only QPACK mode — RFC 9204
//!       §2.1.2 + project policy (H3QpackMode::StaticOnly). A peer's
//!       nonzero SETTINGS permit dynamic use but do not require it.
//!   (4) GOAWAY with stream_id GREATER than previously received —
//!       RFC 9114 §5.2 (GOAWAY id MUST NOT increase).
//!   (5) DATAGRAM frame on the control stream — RFC 9297 (DATAGRAM
//!       belongs on request streams when peers have negotiated
//!       SETTINGS_H3_DATAGRAM=1; on the control stream it's a
//!       protocol error regardless of negotiation).
//!   (6) CONNECT request with malformed `:authority` — RFC 9298 §3
//!       requires a valid authority for CONNECT-UDP target masque
//!       URIs; asupersync's validate_authority_form is the chokepoint.

use asupersync::http::h3_native::{
    H3ConnectionConfig, H3ConnectionState, H3ControlState, H3EndpointRole, H3Frame, H3NativeError,
    H3PseudoHeaders, H3QpackMode, H3RequestHead, H3Settings, QpackBlockedStreamStatus,
    QpackEncoderInstruction, QpackInstructionStreamState, qpack_dynamic_entry,
};

/// (1) RFC 9114 §6.2.1: HEADERS frame is not allowed on the control
/// stream. The remote control state machine must reject a HEADERS
/// frame even AFTER the initial SETTINGS frame has been received.
#[test]
fn rfc9114_headers_on_control_stream_must_reject() {
    let mut control = H3ControlState::new();
    // Initial SETTINGS first — required.
    let settings_ok = control.on_remote_control_frame(&H3Frame::Settings(H3Settings::default()));
    assert!(
        settings_ok.is_ok(),
        "initial SETTINGS on control stream must be accepted"
    );
    // Now feed a HEADERS frame on the control stream — must be rejected.
    let headers = H3Frame::Headers(b"x".to_vec());
    let result = control.on_remote_control_frame(&headers);
    assert!(
        result.is_err(),
        "HEADERS frame on control stream must be rejected; got {:?}",
        result.as_ref().map(|_| "Ok")
    );
}

/// (2) RFC 9114 §4.1: request streams MUST be client-initiated
/// bidirectional. Feeding any frame to a non-client-bidi stream id
/// must fail with a stream protocol error.
#[test]
fn rfc9114_request_frame_on_non_client_bidi_must_reject() {
    let mut conn = H3ConnectionState::new_server();
    // Server-initiated bidi stream id (1 mod 4 == 1) is NOT a client
    // request stream; even a well-formed HEADERS frame here must be
    // rejected at the connection layer.
    let server_bidi_stream_id = 1u64; // server-initiated bidi has 0x1 in lo bits.
    let headers = H3Frame::Headers(b"x".to_vec());
    let result = conn.on_request_stream_frame(server_bidi_stream_id, &headers);
    assert!(
        result.is_err(),
        "frame on non-client-bidi stream id must be rejected; got {:?}",
        result.as_ref().map(|_| "Ok")
    );
}

/// (3) RFC 9204 §2.1.2 + project's static-only QPACK policy:
/// peer SETTINGS advertise decoder limits, not mandatory encoder use.
/// Accepting that permission must leave local dynamic capacity and the
/// blocked-stream budget at zero, and dynamic field sections must fail.
#[test]
fn rfc9204_dynamic_field_section_in_static_only_mode_must_reject() {
    let config = H3ConnectionConfig {
        endpoint_role: H3EndpointRole::Server,
        qpack_mode: H3QpackMode::StaticOnly,
        ..H3ConnectionConfig::default()
    };
    let mut conn = H3ConnectionState::with_config(config);
    let settings = H3Settings {
        qpack_max_table_capacity: Some(128),
        qpack_blocked_streams: Some(16),
        ..H3Settings::default()
    };
    conn.on_control_frame(&H3Frame::Settings(settings.clone()))
        .expect("peer dynamic QPACK permission must be accepted");
    let mut qpack = QpackInstructionStreamState::from_settings(config.qpack_mode, &settings)
        .expect("static-only state must decline peer dynamic permission");
    assert_eq!(qpack.mode(), H3QpackMode::StaticOnly);
    assert_eq!(qpack.context().dynamic_table().capacity(), 0);
    assert_eq!(qpack.settings_blocked_streams(), 0);

    // Zero Required Insert Count and Base, then static index 17 (:method GET).
    let static_field_section = [0x00, 0x00, 0xD1];
    assert_eq!(
        qpack.submit_received_field_section(0, &static_field_section),
        Ok(QpackBlockedStreamStatus::Ready)
    );

    // Required Insert Count 1 (encoded as 2), Base 1, dynamic relative index 0.
    let dynamic_field_section = [0x02, 0x00, 0x80];
    let error = qpack
        .submit_received_field_section(4, &dynamic_field_section)
        .expect_err("peer permission must not enable dynamic field sections");
    assert_eq!(
        error,
        H3NativeError::QpackPolicy("required insert count must be zero in static-only mode")
    );
    assert_eq!(qpack.first_failure(), Some(&error));
    assert_eq!(qpack.blocked_stream_count(), 0);
    assert_eq!(qpack.context().dynamic_table().capacity(), 0);

    // The same dynamic bytes are valid with an explicitly enabled dynamic
    // context: they wait for the first insert rather than failing to parse.
    let mut dynamic =
        QpackInstructionStreamState::from_settings(H3QpackMode::DynamicTableAllowed, &settings)
            .expect("opt-in dynamic QPACK state");
    assert_eq!(
        dynamic.submit_received_field_section(4, &dynamic_field_section),
        Ok(QpackBlockedStreamStatus::Blocked)
    );
    assert_eq!(dynamic.blocked_stream_count(), 1);
}

/// QPACK instructions are a byte stream, so a transport read boundary must
/// neither reject nor prematurely apply an incomplete instruction.
#[test]
fn rfc9204_fragmented_encoder_stream_unblocks_the_received_field_section() {
    let mut connection =
        H3ConnectionState::with_config(H3ConnectionConfig::default().with_dynamic_qpack());
    connection
        .on_remote_uni_stream_type(3, 0x02)
        .expect("remote encoder stream");
    let settings = H3Settings {
        qpack_max_table_capacity: Some(512),
        qpack_blocked_streams: Some(1),
        ..H3Settings::default()
    };
    let mut qpack = QpackInstructionStreamState::from_local_and_peer_settings(
        H3QpackMode::DynamicTableAllowed,
        &settings,
        &H3Settings::default(),
    )
    .expect("directional state");
    assert_eq!(
        qpack.submit_received_field_section(0, &[0x02, 0x00, 0x80]),
        Ok(QpackBlockedStreamStatus::Blocked)
    );

    // RFC 9204 wire bytes: capacity 512, then a literal-name insert of
    // x-test=fragmented. Capacity itself has a multi-byte prefixed integer.
    let wire = b"\x3f\xe1\x03\x46x-test\x0afragmented";
    let mut processed = 0;
    let mut unblocked = Vec::new();
    for (index, byte) in wire.iter().enumerate() {
        let outcome = connection
            .feed_qpack_instruction_stream_bytes(&mut qpack, 3, std::slice::from_ref(byte))
            .expect("an ordinary read boundary is not a QPACK error");
        processed += outcome.instructions_processed();
        unblocked.extend_from_slice(outcome.unblocked_stream_ids());
        if index + 1 < wire.len() {
            assert!(qpack.received_context().dynamic_table().is_empty());
            assert_eq!(qpack.received_blocked_scheduler().blocked_stream_count(), 1);
            assert!(unblocked.is_empty());
        }
    }
    assert_eq!(processed, 2);
    assert_eq!(unblocked, vec![0]);
    assert_eq!(qpack.received_blocked_scheduler().blocked_stream_count(), 0);
    assert_eq!(
        qpack_dynamic_entry(qpack.received_context().dynamic_table(), 0),
        Some(("x-test", "fragmented"))
    );
    assert_eq!(
        qpack
            .received_blocked_scheduler()
            .record(0)
            .expect("stream record")
            .status(),
        QpackBlockedStreamStatus::Ready
    );
    assert!(qpack.context().dynamic_table().is_empty());
    assert_eq!(qpack.context().dynamic_table().capacity(), 0);
    assert!(qpack.first_failure().is_none());
}

/// The peer's advertised capacity grants permission to our encoder; it cannot
/// enlarge the limit our decoder advertised for incoming encoder instructions.
#[test]
fn rfc9204_peer_settings_must_not_raise_the_local_decoder_capacity() {
    let mut connection =
        H3ConnectionState::with_config(H3ConnectionConfig::default().with_dynamic_qpack());
    connection
        .on_remote_uni_stream_type(3, 0x02)
        .expect("remote encoder stream");
    let local_settings = H3Settings {
        qpack_max_table_capacity: Some(128),
        ..H3Settings::default()
    };
    let peer_settings = H3Settings {
        qpack_max_table_capacity: Some(512),
        ..H3Settings::default()
    };
    let mut qpack = QpackInstructionStreamState::from_local_and_peer_settings(
        H3QpackMode::DynamicTableAllowed,
        &local_settings,
        &peer_settings,
    )
    .expect("directional state");
    assert_eq!(qpack.context().max_table_capacity(), 512);
    assert_eq!(qpack.received_context().max_table_capacity(), 128);
    let error = connection
        .feed_qpack_instruction_stream_bytes(&mut qpack, 3, b"\x3f\xe1\x03")
        .expect_err("peer encoder exceeded the local advertised capacity");
    assert!(matches!(&error, H3NativeError::QpackPolicy(_)));
    assert_eq!(qpack.first_failure(), Some(&error));
    assert_eq!(qpack.received_context().dynamic_table().capacity(), 0);
    assert!(qpack.received_context().dynamic_table().is_empty());
    assert!(qpack.context().dynamic_table().is_empty());
}

/// Decoder-stream ACKs retire dynamic field sections in order, not an entire
/// request stream. Static sections create no ACK slot, and an earlier ACK must
/// not prevent the sender from adding a later section on that stream.
#[test]
fn rfc9204_decoder_stream_acknowledges_each_dynamic_section_and_rejects_an_extra_ack() {
    let mut connection =
        H3ConnectionState::with_config(H3ConnectionConfig::default().with_dynamic_qpack());
    connection
        .on_remote_uni_stream_type(7, 0x03)
        .expect("remote decoder stream");
    let peer_settings = H3Settings {
        qpack_max_table_capacity: Some(256),
        qpack_blocked_streams: Some(1),
        ..H3Settings::default()
    };
    let mut qpack = QpackInstructionStreamState::from_local_and_peer_settings(
        H3QpackMode::DynamicTableAllowed,
        &H3Settings::default(),
        &peer_settings,
    )
    .expect("directional state");
    qpack
        .apply_local_encoder_instruction(
            &QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 256 },
        )
        .expect("select encoder capacity");
    for (name, value) in [(":status", "103"), (":status", "200"), ("x-checksum", "done")] {
        qpack
            .apply_local_encoder_instruction(&QpackEncoderInstruction::InsertWithoutNameReference {
                name: name.to_string(),
                value: value.to_string(),
            })
            .expect("insert section field");
    }

    // RIC 1, static status 103, RIC 2, RIC 3. The dynamic sections use
    // Base == RIC and relative index zero, so each references its own insert.
    for section in [
        [0x02, 0x00, 0x80],
        [0x00, 0x00, 0xD8],
        [0x03, 0x00, 0x80],
        [0x04, 0x00, 0x80],
    ] {
        qpack
            .submit_field_section(0, &section)
            .expect("informational, final, and trailer sections on one stream");
    }
    assert_eq!(
        qpack.decoder_feedback().stream_outstanding_section_count(0),
        3
    );
    assert_eq!(qpack.blocked_stream_count(), 1);

    // 0x80 is a Section Acknowledgment for request stream zero.
    let first = connection
        .feed_qpack_instruction_stream_bytes(&mut qpack, 7, &[0x80])
        .expect("acknowledge only the first section");
    assert_eq!(first.instructions_processed(), 1);
    assert!(first.unblocked_stream_ids().is_empty());
    assert_eq!(qpack.decoder_feedback().known_received_count(), 1);
    assert_eq!(
        qpack.decoder_feedback().stream_outstanding_section_count(0),
        2
    );
    assert_eq!(qpack.decoder_feedback().outstanding_reference_count(), 2);
    qpack
        .apply_local_encoder_instruction(
            &QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 0 },
        )
        .expect_err("later sections must remain protected after the first ACK");
    assert!(qpack.first_failure().is_none());

    assert_eq!(
        qpack.submit_field_section(0, &[0x02, 0x00, 0x80]),
        Ok(QpackBlockedStreamStatus::Ready)
    );
    assert_eq!(
        qpack.decoder_feedback().stream_outstanding_section_count(0),
        3
    );
    for (known_received_count, remaining) in [(2, 2), (3, 1), (3, 0)] {
        let outcome = connection
            .feed_qpack_instruction_stream_bytes(&mut qpack, 7, &[0x80])
            .expect("acknowledge the next dynamic section");
        assert_eq!(outcome.instructions_processed(), 1);
        assert_eq!(
            qpack.decoder_feedback().known_received_count(),
            known_received_count
        );
        assert_eq!(
            qpack.decoder_feedback().stream_outstanding_section_count(0),
            remaining
        );
        assert_eq!(
            qpack.decoder_feedback().outstanding_reference_count(),
            remaining
        );
        assert_eq!(
            qpack.blocked_stream_count(),
            u64::from(known_received_count < 3)
        );
        if known_received_count == 3 && remaining == 1 {
            assert_eq!(outcome.unblocked_stream_ids(), &[0]);
        } else {
            assert!(outcome.unblocked_stream_ids().is_empty());
        }
    }
    qpack
        .apply_local_encoder_instruction(
            &QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 0 },
        )
        .expect("every outstanding section has released its references");
    assert!(qpack.context().dynamic_table().is_empty());
    assert!(qpack.received_context().dynamic_table().is_empty());

    let error = connection
        .feed_qpack_instruction_stream_bytes(&mut qpack, 7, &[0x80])
        .expect_err("the static section did not create an extra ACK slot");
    assert!(matches!(&error, H3NativeError::InvalidFrame(_)));
    assert_eq!(qpack.first_failure(), Some(&error));
}

/// Declared instruction lengths are checked before retaining their payload,
/// and a failed connection cannot resume mutating its compression state.
#[test]
fn rfc9204_oversized_fragmented_instruction_must_reject_before_payload() {
    let mut connection =
        H3ConnectionState::with_config(H3ConnectionConfig::default().with_dynamic_qpack());
    connection
        .on_remote_uni_stream_type(3, 0x02)
        .expect("remote encoder stream");
    let mut qpack = QpackInstructionStreamState::new(H3QpackMode::DynamicTableAllowed, 512, 1)
        .expect("dynamic state")
        .with_max_instruction_size(16)
        .expect("local instruction bound");
    let partial = connection
        .feed_qpack_instruction_stream_bytes(&mut qpack, 3, &[0x5f])
        .expect("incomplete name-length integer");
    assert_eq!(partial.instructions_processed(), 0);

    // The next byte declares a 32-byte literal name; no payload is needed
    // to establish that it cannot fit this receiver's 16-byte policy.
    let error = connection
        .feed_qpack_instruction_stream_bytes(&mut qpack, 3, &[0x01])
        .expect_err("oversized declaration");
    assert!(matches!(
        &error,
        H3NativeError::FrameTooLarge { payload_size, max_size: 16 } if *payload_size > 16
    ));
    assert_eq!(qpack.first_failure(), Some(&error));
    let next = connection
        .feed_qpack_instruction_stream_bytes(&mut qpack, 3, b"\x41x\x01y")
        .expect_err("terminal instruction failure stays terminal");
    assert_eq!(next, error);
    assert!(qpack.context().dynamic_table().is_empty());
}

/// (4) RFC 9114 §5.2: GOAWAY id MUST NOT increase. After a smaller
/// GOAWAY has been received, a later GOAWAY with a larger id must
/// be rejected as a control-stream protocol error.
#[test]
fn rfc9114_goaway_id_increase_must_reject() {
    // Start a CLIENT (so received GOAWAYs reference client-initiated
    // bidi stream ids — those have id mod 4 == 0).
    let mut conn = H3ConnectionState::new_client();
    // Initial SETTINGS so the control state machine is past handshake.
    conn.on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("initial SETTINGS on control stream must succeed");

    // First GOAWAY with id=4 (client-initiated bidi: 0, 4, 8, ...).
    conn.on_control_frame(&H3Frame::Goaway(4))
        .expect("first GOAWAY must succeed");

    // Subsequent GOAWAY with HIGHER id=8 must be rejected.
    let result = conn.on_control_frame(&H3Frame::Goaway(8));
    assert!(
        result.is_err(),
        "GOAWAY id increase from 4 to 8 must be rejected; got {:?}",
        result.as_ref().map(|_| "Ok")
    );

    // Lower (or equal) id is allowed — codifies the "narrows only" rule.
    let lower = conn.on_control_frame(&H3Frame::Goaway(0));
    assert!(
        lower.is_ok(),
        "GOAWAY id LOWERING from 4 to 0 must be accepted; got {:?}",
        lower
    );
}

/// (5) RFC 9297: DATAGRAM frames belong on bidirectional request
/// streams when both peers have negotiated SETTINGS_H3_DATAGRAM=1.
/// A DATAGRAM frame appearing on the CONTROL stream is a protocol
/// error regardless of negotiation, since the control stream
/// carries control frames only (SETTINGS / GOAWAY / CANCEL_PUSH /
/// MAX_PUSH_ID).
#[test]
fn rfc9297_datagram_on_control_stream_must_reject() {
    let mut control = H3ControlState::new();
    // Initial SETTINGS — required first.
    control
        .on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("initial SETTINGS on control stream must be accepted");
    // DATAGRAM frame on the control stream — protocol error.
    let datagram = H3Frame::Datagram {
        quarter_stream_id: 0,
        payload: b"hello".to_vec(),
    };
    let result = control.on_remote_control_frame(&datagram);
    assert!(
        result.is_err(),
        "DATAGRAM frame on control stream must be rejected; got {:?}",
        result.as_ref().map(|_| "Ok")
    );
}

/// (6) RFC 9298 §3: a CONNECT-UDP target authority MUST be a valid
/// authority-form URI per RFC 9112 §3.2.3 (`host[:port]`). Asupersync's
/// validate_authority_form is the chokepoint inside H3RequestHead
/// construction; a malformed authority must fail validation.
#[test]
fn rfc9298_connect_udp_malformed_authority_must_reject() {
    // Missing host (just :port) — invalid authority.
    let pseudo = H3PseudoHeaders {
        method: Some("CONNECT".to_string()),
        scheme: None,
        // Authority with no host part — empty host before the colon.
        authority: Some(":443".to_string()),
        path: None,
        status: None,
        protocol: Some("connect-udp".to_string()),
    };
    let result = H3RequestHead::new_with_settings(
        pseudo,
        Vec::new(),
        /* enable_connect_protocol */ true,
    );
    assert!(
        result.is_err(),
        "CONNECT-UDP with malformed authority ':443' must be rejected; got {:?}",
        result.as_ref().map(|_| "Ok")
    );

    // CR/LF injection attempt in the authority — header smuggling vector.
    let pseudo_crlf = H3PseudoHeaders {
        method: Some("CONNECT".to_string()),
        scheme: None,
        authority: Some("evil.example\r\nX-Injected: yes".to_string()),
        path: None,
        status: None,
        protocol: Some("connect-udp".to_string()),
    };
    let result_crlf = H3RequestHead::new_with_settings(
        pseudo_crlf,
        Vec::new(),
        /* enable_connect_protocol */ true,
    );
    assert!(
        result_crlf.is_err(),
        "CONNECT-UDP with CRLF-injection in authority must be rejected; got {:?}",
        result_crlf.as_ref().map(|_| "Ok")
    );
}
