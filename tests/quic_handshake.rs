//! Integration tests for QUIC handshake implementation

use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::cx::Cx;
use asupersync::net::atp::handshake::{
    EndpointRole, HandshakeEvent, HandshakeState, HandshakeTracer, KeyDerivation, KeySchedule,
    PacketSpace, QuicHandshakeMachine, QuicVersion, RetryPacket, RetryTokenHandler, TraceLevel,
    TransportParamId, TransportParameters, VersionNegotiation, VersionNegotiationPacket,
};
use asupersync::net::atp::quic::AtpPacketProtectionConfig;
use asupersync::{Budget, RegionId, TaskId};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

fn test_cx() -> Cx {
    Cx::new(
        RegionId::new_for_test(1, 0),
        TaskId::new_for_test(1, 0),
        Budget::INFINITE,
    )
}

#[test]
fn test_client_server_handshake_basic() {
    // Create client and server handshake machines
    let config = AtpPacketProtectionConfig::default();
    let timeout = Duration::from_secs(30);

    let mut client = QuicHandshakeMachine::new(EndpointRole::Client, config.clone(), timeout);
    let _server = QuicHandshakeMachine::new(EndpointRole::Server, config, timeout);

    // Start client handshake
    let cx = test_cx();
    let result = client.start(&cx, QuicVersion::V1 as u32);
    assert!(result.is_ok());

    // Verify initial state
    assert!(matches!(client.state(), HandshakeState::Initial { .. }));
    assert!(!client.is_complete());
    assert!(!client.is_failed());

    // Check trace generation
    let traces = client.trace_events();
    assert_eq!(traces.len(), 1);
    match &traces[0] {
        HandshakeEvent::Started {
            role,
            initial_version,
            ..
        } => {
            assert_eq!(*role, EndpointRole::Client);
            assert_eq!(*initial_version, QuicVersion::V1 as u32);
        }
        _ => panic!("Expected Started event"),
    }
}

#[test]
fn test_version_negotiation() {
    // Test version negotiation packet encoding/decoding
    let source_cid = Bytes::from_static(b"server_cid_12345");
    let dest_cid = Bytes::from_static(b"client_cid_12345");
    let supported_versions = vec![QuicVersion::V1 as u32, 0x12345678];

    let packet = VersionNegotiationPacket::new(
        source_cid.clone(),
        dest_cid.clone(),
        supported_versions.clone(),
    );

    // Test encoding and decoding
    let encoded = packet.encode().unwrap();
    let decoded = VersionNegotiationPacket::decode(&encoded).unwrap();

    assert_eq!(decoded.source_cid, source_cid);
    assert_eq!(decoded.dest_cid, dest_cid);
    assert_eq!(decoded.supported_versions, supported_versions);

    // Test version selection
    assert_eq!(packet.select_version(QuicVersion::V1 as u32), None);
    assert_eq!(
        packet.select_version(0xabcdef00),
        Some(QuicVersion::V1 as u32)
    );

    // Test negotiation utilities
    assert!(!VersionNegotiation::is_negotiation_needed(
        QuicVersion::V1 as u32,
        &supported_versions
    ));
    assert!(VersionNegotiation::is_negotiation_needed(
        0xabcdef00,
        &supported_versions
    ));
}

#[test]
fn test_retry_token_validation() {
    let secret_key = [42u8; 32];
    let handler = RetryTokenHandler::new(secret_key, 300); // 5 minute lifetime

    let client_addr = SocketAddr::new(Ipv4Addr::new(192, 168, 1, 100).into(), 12345);
    let original_dest_cid = b"original_conn_id";

    // Generate token
    let token = handler
        .generate_token(client_addr, original_dest_cid)
        .unwrap();
    assert!(!token.is_empty());

    // Validate with correct parameters
    let result = handler.validate_token(&token, client_addr, original_dest_cid);
    assert!(result.is_ok());

    // Validate with wrong address
    let wrong_addr = SocketAddr::new(Ipv4Addr::new(192, 168, 1, 101).into(), 12345);
    let result = handler.validate_token(&token, wrong_addr, original_dest_cid);
    assert!(result.is_err());

    // Validate with wrong CID
    let wrong_cid = b"wrong_connection_id";
    let result = handler.validate_token(&token, client_addr, wrong_cid);
    assert!(result.is_err());
}

#[test]
fn test_retry_packet_integrity() {
    let retry_key = [123u8; 32];

    let packet = RetryPacket::new(
        QuicVersion::V1 as u32,
        Bytes::from_static(b"server_cid"),
        Bytes::from_static(b"client_cid"),
        Bytes::from_static(b"retry_token_data"),
    );

    // Test encoding and decoding
    let encoded = packet.encode(&retry_key).unwrap();
    let decoded = RetryPacket::decode(&encoded, &retry_key).unwrap();

    assert_eq!(decoded.version, packet.version);
    assert_eq!(decoded.source_cid, packet.source_cid);
    assert_eq!(decoded.dest_cid, packet.dest_cid);
    assert_eq!(decoded.retry_token, packet.retry_token);

    // Test integrity protection - wrong key should fail
    let wrong_key = [124u8; 32];
    let result = RetryPacket::decode(&encoded, &wrong_key);
    assert!(result.is_err());
}

#[test]
fn test_retry_rejects_oversized_connection_ids() {
    let retry_key = [123u8; 32];
    let oversized_cid = Bytes::from(vec![0xab; 21]);

    let oversized_dest = RetryPacket::new(
        QuicVersion::V1 as u32,
        Bytes::from_static(b"server_cid"),
        oversized_cid.clone(),
        Bytes::from_static(b"retry_token_data"),
    );
    assert!(oversized_dest.encode(&retry_key).is_err());

    let oversized_source = RetryPacket::new(
        QuicVersion::V1 as u32,
        oversized_cid.clone(),
        Bytes::from_static(b"client_cid"),
        Bytes::from_static(b"retry_token_data"),
    );
    assert!(oversized_source.encode(&retry_key).is_err());

    let mut encoded_oversized_dest = BytesMut::new();
    encoded_oversized_dest.put_u8(0xf0);
    encoded_oversized_dest.put_u32(QuicVersion::V1 as u32);
    encoded_oversized_dest.put_u8(oversized_cid.len() as u8);
    encoded_oversized_dest.put_slice(&oversized_cid);
    encoded_oversized_dest.put_u8(0);
    encoded_oversized_dest.put_slice(&[0; 16]);
    assert!(RetryPacket::decode(&encoded_oversized_dest, &retry_key).is_err());

    let handler = RetryTokenHandler::new([42u8; 32], 300);
    let client_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345);
    assert!(handler.generate_token(client_addr, &oversized_cid).is_err());
}

#[test]
fn test_transport_parameters() {
    // Test client defaults
    let client_params = TransportParameters::client_defaults();
    assert!(
        client_params
            .get_integer(TransportParamId::MaxIdleTimeout)
            .is_some()
    );
    assert!(
        client_params
            .get_integer(TransportParamId::InitialMaxData)
            .is_some()
    );
    assert!(!client_params.has_flag(TransportParamId::DisableActiveMigration));

    // Test custom parameters
    let mut params = TransportParameters::new();
    params.set_integer(TransportParamId::MaxIdleTimeout, 60000);
    params.set_integer(TransportParamId::InitialMaxData, 2048 * 1024);
    params.set_flag(TransportParamId::DisableActiveMigration);
    params.set_bytes(
        TransportParamId::StatelessResetToken,
        Bytes::from_static(&[
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
            0xba, 0x98,
        ]),
    );

    // Test encoding and decoding
    let encoded = params.encode().unwrap();
    let decoded = TransportParameters::decode(&encoded).unwrap();

    assert_eq!(
        decoded.get_integer(TransportParamId::MaxIdleTimeout),
        Some(60000)
    );
    assert_eq!(
        decoded.get_integer(TransportParamId::InitialMaxData),
        Some(2048 * 1024)
    );
    assert!(decoded.has_flag(TransportParamId::DisableActiveMigration));
    assert_eq!(
        decoded
            .get_bytes(TransportParamId::StatelessResetToken)
            .unwrap()
            .len(),
        16
    );

    // Test validation
    assert!(params.validate().is_ok());

    // Test invalid parameters
    let mut invalid_params = TransportParameters::new();
    invalid_params.set_integer(TransportParamId::AckDelayExponent, 25); // Too large
    assert!(invalid_params.validate().is_err());

    // Test timeout conversion
    assert_eq!(
        params.max_idle_timeout(),
        Some(Duration::from_millis(60000))
    );
}

#[test]
fn test_key_schedule_lifecycle() {
    let mut schedule = KeySchedule::new();

    // Initially no keys established
    assert!(!schedule.keys_established(PacketSpace::Initial));
    assert!(!schedule.keys_established(PacketSpace::Handshake));
    assert!(!schedule.keys_established(PacketSpace::Application));

    // Install Initial keys
    let (local_initial, remote_initial) = KeyDerivation::derive_initial_keys(b"test_cid").unwrap();
    schedule
        .install_initial_keys(local_initial, remote_initial)
        .unwrap();
    assert!(schedule.keys_established(PacketSpace::Initial));

    // Install Handshake keys
    let handshake_secret = [0x48u8; 32];
    let (local_handshake, remote_handshake) =
        KeyDerivation::derive_handshake_keys(&handshake_secret).unwrap();
    schedule
        .install_handshake_keys(local_handshake, remote_handshake)
        .unwrap();
    assert!(schedule.keys_established(PacketSpace::Handshake));

    // Install 1-RTT keys
    let application_secret = [0xA5u8; 32];
    let (local_app, remote_app) =
        KeyDerivation::derive_application_keys(&application_secret).unwrap();
    schedule
        .install_application_keys(local_app, remote_app)
        .unwrap();
    assert!(schedule.keys_established(PacketSpace::Application));

    // Test key discard rules
    assert!(schedule.can_discard_initial_keys());
    assert!(schedule.can_discard_handshake_keys());

    // Discard handshake keys
    schedule.discard_keys(PacketSpace::Initial).unwrap();
    schedule.discard_keys(PacketSpace::Handshake).unwrap();

    assert!(!schedule.keys_established(PacketSpace::Initial));
    assert!(!schedule.keys_established(PacketSpace::Handshake));
    assert!(schedule.keys_established(PacketSpace::Application));

    // Cannot discard 1-RTT keys
    assert!(schedule.discard_keys(PacketSpace::Application).is_err());
}

#[test]
fn test_key_update_lifecycle() {
    let mut schedule = KeySchedule::new();

    // Install 1-RTT keys
    let local_secret = [1u8; 32];
    let remote_secret = [2u8; 32];
    let (local_keys, remote_keys) = KeyDerivation::derive_application_keys(&local_secret).unwrap();
    schedule
        .install_application_keys(local_keys, remote_keys)
        .unwrap();

    // Initial state
    assert_eq!(schedule.current_key_phase().0, 0);
    assert!(!schedule.key_update_pending());
    assert_eq!(schedule.key_update_count(), 0);

    // Initiate key update
    schedule
        .initiate_key_update(&local_secret, &remote_secret)
        .unwrap();
    assert!(schedule.key_update_pending());

    // Commit key update
    schedule.commit_key_update().unwrap();
    assert_eq!(schedule.current_key_phase().0, 1);
    assert!(!schedule.key_update_pending());
    assert_eq!(schedule.key_update_count(), 1);

    // Cannot update without 1-RTT keys
    let mut empty_schedule = KeySchedule::new();
    assert!(
        empty_schedule
            .initiate_key_update(&local_secret, &remote_secret)
            .is_err()
    );
}

#[test]
fn test_handshake_tracing() {
    let mut tracer = HandshakeTracer::new(TraceLevel::Debug, 100);

    // Trace some events
    let start_event = HandshakeEvent::Started {
        role: EndpointRole::Client,
        initial_version: QuicVersion::V1 as u32,
        region_id: "test-region".to_string(),
    };
    tracer.trace_handshake_event(&start_event, Some("test-region".to_string()));

    let complete_event = HandshakeEvent::Completed {
        elapsed: Duration::from_millis(150),
        final_version: QuicVersion::V1 as u32,
    };
    tracer.trace_handshake_event(&complete_event, Some("test-region".to_string()));

    // Check trace contents
    assert_eq!(tracer.entries().len(), 2);

    // Generate qlog
    let qlog = tracer.to_qlog();
    assert!(qlog.get("qlog_version").is_some());
    assert!(qlog.get("traces").is_some());

    // Generate summary
    let summary = tracer.summary();
    assert_eq!(summary["total_events"], 2);

    // Test filtering
    let info_entries = tracer.filter_by_level(TraceLevel::Info);
    assert_eq!(info_entries.len(), 2);

    let handshake_entries = tracer.filter_by_category("handshake");
    assert_eq!(handshake_entries.len(), 2);
}

#[test]
fn test_packet_number_generation() {
    let config = AtpPacketProtectionConfig::default();
    let timeout = Duration::from_secs(30);
    let mut machine = QuicHandshakeMachine::new(EndpointRole::Client, config, timeout);

    // Packet numbers should start at 0 and increment
    assert_eq!(machine.next_packet_number(PacketSpace::Initial), 0);
    assert_eq!(machine.next_packet_number(PacketSpace::Initial), 1);
    assert_eq!(machine.next_packet_number(PacketSpace::Initial), 2);

    // Different spaces should be independent
    assert_eq!(machine.next_packet_number(PacketSpace::Handshake), 0);
    assert_eq!(machine.next_packet_number(PacketSpace::Application), 0);
    assert_eq!(machine.next_packet_number(PacketSpace::Initial), 3);
}

#[test]
fn test_handshake_timeout() {
    let config = AtpPacketProtectionConfig::default();
    let timeout = Duration::from_millis(10); // Very short timeout for testing
    let mut machine = QuicHandshakeMachine::new(EndpointRole::Client, config, timeout);

    let cx = test_cx();
    machine.start(&cx, QuicVersion::V1 as u32).unwrap();

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(20));

    // Process a dummy packet to trigger timeout check
    let dummy_packet = vec![0u8; 10];
    let result = machine.process_packet(&cx, &dummy_packet, PacketSpace::Initial);

    assert!(result.is_err());
    assert!(machine.is_failed());

    // Check that timeout was recorded in traces
    let traces = machine.trace_events();
    assert!(
        traces
            .iter()
            .any(|event| matches!(event, HandshakeEvent::Failed { .. }))
    );
}

#[test]
fn test_invalid_version_handling() {
    let config = AtpPacketProtectionConfig::default();
    let timeout = Duration::from_secs(30);
    let mut machine = QuicHandshakeMachine::new(EndpointRole::Client, config, timeout);

    let cx = test_cx();
    let result = machine.start(&cx, 0x12345678); // Unsupported version

    assert!(result.is_err());
    assert!(machine.is_failed());

    // Check error type
    match machine.state() {
        HandshakeState::Failed { error, .. } => {
            assert!(matches!(
                error,
                asupersync::net::atp::handshake::HandshakeError::UnsupportedVersion { .. }
            ));
        }
        _ => panic!("Expected failed state"),
    }
}
