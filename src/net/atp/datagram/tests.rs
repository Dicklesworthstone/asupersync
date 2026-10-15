//! Integration tests for QUIC DATAGRAM support
//!
//! Tests cover the acceptance criteria scenarios including:
//! - No-support peers handling
//! - Oversized datagram rejection
//! - Congestion drop behavior
//! - Path beacon functionality
//! - Malformed frame handling

use crate::bytes::{Bytes, BytesMut};
use crate::net::atp::datagram::*;
use crate::net::atp::handshake::transport_params::{TransportParamId, TransportParameters};
use crate::types::outcome::Outcome;
use std::time::{Duration, Instant};

fn peer_datagram_params(max_size: u64) -> TransportParameters {
    let mut params = TransportParameters::new();
    params.set_integer(TransportParamId::MaxDatagramFrameSize, max_size);
    params
}

/// Test DATAGRAM frame encoding/decoding with various payload sizes
#[test]
fn test_datagram_frame_codec() {
    // Small payload
    let small_payload = Bytes::from_static(b"small");
    let frame = DatagramFrame::with_length(small_payload.clone());

    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();

    let mut decode_buf = buf.clone();
    let decoded = DatagramFrame::decode(&mut decode_buf, 1024).unwrap();
    assert_eq!(decoded.payload(), &small_payload);
    assert!(decoded.has_length_field());

    // Large payload
    let large_payload = Bytes::from(vec![0xAB; 512]);
    let frame = DatagramFrame::without_length(large_payload.clone());

    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();

    let mut decode_buf = buf;
    let decoded = DatagramFrame::decode(&mut decode_buf, 1024).unwrap();
    assert_eq!(decoded.payload(), &large_payload);
    assert!(!decoded.has_length_field());
}

/// Test rejection of oversized datagrams
#[test]
fn test_oversized_datagram_rejection() {
    let oversized_payload = Bytes::from(vec![0xFF; 2048]);
    let frame = DatagramFrame::with_length(oversized_payload);

    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();

    let mut decode_buf = buf;
    let result = DatagramFrame::decode(&mut decode_buf, 1024);

    assert!(matches!(
        result,
        Outcome::Err(DatagramError::PayloadTooLarge {
            size: 2048,
            max: 1024
        })
    ));
}

/// Test transport parameter negotiation
#[test]
fn test_transport_parameter_negotiation() {
    // Local peer supports DATAGRAM with 1024 byte limit
    let mut local_transport = DatagramTransport::new(true, 1024).unwrap();
    assert!(!local_transport.is_enabled()); // No peer negotiated yet

    // Simulate peer negotiation with RFC 9221 max_datagram_frame_size.
    let params = peer_datagram_params(1024);
    local_transport.process_peer_params(&params).unwrap();

    // Should now be enabled because both local and peer advertised support.
    assert!(local_transport.is_enabled());
    assert_eq!(local_transport.max_frame_size(), Some(1024));
}

/// Test disabled DATAGRAM handling
#[test]
fn test_disabled_datagram_handling() {
    let disabled_transport = DatagramTransport::disabled();
    assert!(!disabled_transport.is_enabled());
    assert_eq!(disabled_transport.max_frame_size(), None);

    // Size validation should fail
    let result = disabled_transport.validate_size(100);
    assert!(matches!(result, Outcome::Err(DatagramError::NotSupported)));
}

/// Test DATAGRAM configuration validation
#[test]
fn test_datagram_config_validation() {
    // Valid configuration
    let valid_config = DatagramConfig::enabled();
    assert!(valid_config.validate().is_ok());

    // Configuration with clamped size
    let clamped_config = DatagramConfig::new().with_max_frame_size(100000); // Will be clamped to MAX_DATAGRAM_SIZE
    assert_eq!(clamped_config.max_frame_size, MAX_DATAGRAM_SIZE);

    // Create transport from config
    let transport = valid_config.create_transport().unwrap();
    assert_eq!(transport.local_max_size(), DEFAULT_MAX_DATAGRAM_SIZE);
}

/// Test path beacon creation and statistics
#[test]
fn test_path_beacon_functionality() {
    let mut beacon_manager = BeaconManager::new(Duration::from_secs(30));

    // Create beacon
    let beacon = beacon_manager.create_beacon(1, BeaconMeasurement::with_rtt(50_000, 5_000));
    let beacon_data = beacon.encode().unwrap();
    assert!(!beacon_data.is_empty());

    // Process beacon (simulate response)
    let beacon = PathBeacon::decode(&beacon_data).unwrap();
    assert_eq!(beacon.path_id, 1);

    let response = PathBeacon::response(2, 1, BeaconMeasurement::empty());
    assert!(beacon_manager.process_received_beacon(response).is_none());

    let stats = beacon_manager.get_path_stats(1).unwrap();
    assert_eq!(stats.sent_count, 1);
    assert_eq!(stats.response_count, 1);
    assert!(stats.avg_rtt.is_some());
}

/// Test path probe creation and response handling
#[test]
fn test_path_probe_functionality() {
    let transport = DatagramTransport::default_enabled();
    let mut probe_manager = ProbeManager::new(transport);

    // Create discovery probe
    let probe_frame = probe_manager.create_probe(ProbeType::Discovery, 1).unwrap();
    assert!(probe_frame.payload_len() > 0);
    assert_eq!(probe_manager.pending_count(), 1);

    // Decode and process probe
    let probe_data = probe_frame.payload().clone();
    let response_frame = probe_manager.process_probe(&probe_data).unwrap();

    // Should generate response for request
    assert!(response_frame.is_some());

    // Process response
    if let Some(response) = response_frame {
        let response_data = response.payload().clone();
        let result = probe_manager.process_probe(&response_data).unwrap();
        assert!(result.is_none()); // No response to response
    }

    // Check statistics updated
    let stats = probe_manager.get_path_stats(1);
    assert!(stats.is_some());
}

/// Test congestion control behavior
#[test]
fn test_congestion_control() {
    let config = CongestionConfig::default();
    let mut controller = CongestionController::new(config);

    // Test priority ordering
    let (low_frame, low_meta) = create_test_datagram(DatagramPriority::Low);
    let (high_frame, high_meta) = create_test_datagram(DatagramPriority::High);

    controller.enqueue_datagram(low_frame, low_meta).unwrap();
    controller.enqueue_datagram(high_frame, high_meta).unwrap();

    // High priority should come out first
    let (_frame, metadata) = controller.try_send_next().unwrap().unwrap();
    assert_eq!(metadata.priority, DatagramPriority::High);

    // Test congestion feedback
    controller.update_congestion_feedback(Some(Duration::from_millis(100)), true);

    let stats = controller.get_stats();
    assert!(stats.congestion_events > 0);
}

/// Test queue depth limiting and dropping
#[test]
fn test_queue_depth_limiting() {
    let mut config = CongestionConfig::default();
    config.max_queue_depth = 2;

    let mut controller = CongestionController::new(config);

    // Fill queue to limit
    for _ in 0..2 {
        let (frame, metadata) = create_test_datagram(DatagramPriority::Normal);
        controller.enqueue_datagram(frame, metadata).unwrap();
    }

    // Add higher priority item - should succeed by dropping lower priority
    let (high_frame, high_meta) = create_test_datagram(DatagramPriority::High);
    controller.enqueue_datagram(high_frame, high_meta).unwrap();

    // Add another normal priority - should fail
    let (normal_frame, normal_meta) = create_test_datagram(DatagramPriority::Normal);
    let result = controller.enqueue_datagram(normal_frame, normal_meta);

    assert!(matches!(
        result,
        Outcome::Err(DatagramError::CongestionDrop)
    ));
}

/// Test expired datagram handling
#[test]
fn test_expired_datagram_cleanup() {
    let config = CongestionConfig::default();
    let mut controller = CongestionController::new(config);

    // Create expired datagram
    let frame = DatagramFrame::with_length(Bytes::from_static(b"expired"));
    let metadata = DatagramMetadata::new("test")
        .with_priority(DatagramPriority::Normal)
        .with_expiration(
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("test instant should support one-second subtraction"),
        );

    controller.enqueue_datagram(frame, metadata).unwrap();

    // Try to send - should clean up expired item
    let result = controller.try_send_next().unwrap();
    assert!(result.is_none());

    let stats = controller.get_stats();
    assert!(stats.expired_count > 0);
}

/// Test malformed frame handling
#[test]
fn test_malformed_frame_handling() {
    // Invalid frame type
    let mut bad_frame = BytesMut::new();
    bad_frame.extend_from_slice(&[0x99]); // Invalid frame type

    let result = DatagramFrame::decode(&mut bad_frame, 1024);
    assert!(matches!(
        result,
        Outcome::Err(DatagramError::InvalidFrame(_))
    ));

    // Empty buffer
    let mut empty_buf = BytesMut::new();
    let result = DatagramFrame::decode(&mut empty_buf, 1024);
    assert!(matches!(
        result,
        Outcome::Err(DatagramError::InvalidFrame(_))
    ));

    // Truncated frame with length
    let mut truncated_buf = BytesMut::new();
    truncated_buf.extend_from_slice(&[0x31, 0x10]); // DatagramWithLength, length=16
    truncated_buf.extend_from_slice(&[1, 2, 3]); // Only 3 bytes payload

    let result = DatagramFrame::decode(&mut truncated_buf, 1024);
    assert!(matches!(
        result,
        Outcome::Err(DatagramError::InvalidFrame(_))
    ));
}

/// Test probe encoding/decoding edge cases
#[test]
fn test_probe_encoding_edge_cases() {
    // Probe with challenge
    let probe =
        PathProbe::new_request(1, ProbeType::Validation, 1, 1).with_challenge(vec![1, 2, 3, 4]);

    let encoded = probe.encode().unwrap();
    let decoded = PathProbe::decode(&encoded).unwrap();

    assert_eq!(decoded.challenge, Some(vec![1, 2, 3, 4]));

    // Probe with payload
    let probe = PathProbe::new_request(2, ProbeType::Bandwidth, 1, 2).with_payload(vec![0xFF; 64]);

    let encoded = probe.encode().unwrap();
    let decoded = PathProbe::decode(&encoded).unwrap();

    assert_eq!(decoded.payload, Some(vec![0xFF; 64]));

    // Invalid JSON
    let result = PathProbe::decode(b"invalid json");
    assert!(matches!(
        result,
        Outcome::Err(DatagramError::InvalidFrame(_))
    ));
}

/// Test RTT calculation accuracy
#[test]
fn test_rtt_calculation() {
    let request = PathProbe::new_request(1, ProbeType::Rtt, 1, 1);
    let mut response = request.new_response();
    response.timestamp = request.timestamp + 10_000;
    let rtt = request.calculate_rtt(&response);

    assert_eq!(rtt, Some(Duration::from_millis(10)));
}

/// Test beacon statistics tracking
#[test]
fn test_beacon_statistics_tracking() {
    let mut beacon_manager = BeaconManager::new(Duration::from_secs(10));

    let beacon = beacon_manager.create_beacon(
        1,
        BeaconMeasurement {
            srtt_us: Some(50_000),
            rttvar_us: Some(5_000),
            loss_rate_per_1000: Some(50),
            bandwidth_bps: Some(1_000_000),
            ..BeaconMeasurement::empty()
        },
    );
    assert_eq!(beacon.measurement_data.srtt_us, Some(50_000));
    assert_eq!(beacon.measurement_data.loss_rate_per_1000, Some(50));
    assert_eq!(beacon.measurement_data.bandwidth_bps, Some(1_000_000));

    let response = PathBeacon::response(2, 1, BeaconMeasurement::empty());
    assert!(beacon_manager.process_received_beacon(response).is_none());

    let stats = beacon_manager.get_path_stats(1).unwrap();
    assert_eq!(stats.sent_count, 1);
    assert_eq!(stats.response_count, 1);
    assert!(stats.current_rtt().is_some());
    assert!(stats.loss_rate >= 0.0);
}

/// Test different congestion algorithms
#[test]
fn test_congestion_algorithms() {
    for algorithm in [
        CongestionAlgorithm::RateLimited,
        CongestionAlgorithm::Aimd,
        CongestionAlgorithm::TokenBucket,
        CongestionAlgorithm::Adaptive,
    ] {
        let mut config = CongestionConfig::default();
        config.algorithm = algorithm;

        let mut controller = CongestionController::new(config);

        // Should be able to send initially
        let (frame, metadata) = create_test_datagram(DatagramPriority::Normal);
        controller.enqueue_datagram(frame, metadata).unwrap();

        let result = controller.try_send_next().unwrap();
        assert!(result.is_some());
    }
}

/// Helper function to create test datagram
fn create_test_datagram(priority: DatagramPriority) -> (DatagramFrame, DatagramMetadata) {
    let frame = DatagramFrame::with_length(Bytes::from_static(b"test"));
    let metadata = DatagramMetadata::new("test").with_priority(priority);
    (frame, metadata)
}

/// Test integration: full DATAGRAM workflow
#[test]
fn test_full_datagram_workflow() {
    // Setup transport
    let mut transport = DatagramTransport::new(true, 1024).unwrap();
    let params = crate::net::atp::handshake::transport_params::TransportParameters::new();
    transport.process_peer_params(&params).unwrap();

    // Setup managers
    let mut probe_manager = ProbeManager::new(transport.clone());
    let mut beacon_manager = BeaconManager::new(Duration::from_secs(30));
    let mut congestion_controller = CongestionController::new(CongestionConfig::default());

    // Create and send probe
    let probe_frame = probe_manager.create_probe(ProbeType::Discovery, 1).unwrap();
    let probe_metadata = DatagramMetadata::new("probe").with_priority(DatagramPriority::High);

    congestion_controller
        .enqueue_datagram(probe_frame, probe_metadata)
        .unwrap();

    // Send probe
    let (_sent_frame, sent_metadata) = congestion_controller.try_send_next().unwrap().unwrap();
    assert_eq!(sent_metadata.payload_class, "probe");

    // Create beacon
    let beacon_frame = beacon_manager
        .create_beacon(1, BeaconMeasurement::empty())
        .to_datagram_frame()
        .unwrap();
    let beacon_metadata = DatagramMetadata::new("beacon").with_priority(DatagramPriority::Normal);

    congestion_controller
        .enqueue_datagram(beacon_frame, beacon_metadata)
        .unwrap();

    // Send beacon
    let (_sent_frame, sent_metadata) = congestion_controller.try_send_next().unwrap().unwrap();
    assert_eq!(sent_metadata.payload_class, "beacon");

    // Verify stats
    let stats = congestion_controller.get_stats();
    assert_eq!(stats.sent_count, 2);
    assert!(stats.is_performing_well());
}

#[cfg(test)]
mod probe_manager_tests {
    use super::*;

    #[test]
    fn test_probe_manager_cleanup() {
        let transport = DatagramTransport::default_enabled();
        let mut manager = ProbeManager::new(transport);

        // Create probe
        manager.create_probe(ProbeType::Rtt, 1).unwrap();
        assert_eq!(manager.pending_count(), 1);

        // Cleanup with current time - should retain
        manager.cleanup_expired_probes(Instant::now());
        assert_eq!(manager.pending_count(), 1);

        // Cleanup with future time - should remove
        manager.cleanup_expired_probes(Instant::now() + Duration::from_secs(60));
        assert_eq!(manager.pending_count(), 0);
    }

    #[test]
    fn test_probe_type_properties() {
        assert!(ProbeType::Discovery.timeout() > ProbeType::Validation.timeout());
        assert_eq!(ProbeType::Validation.priority(), DatagramPriority::High);
        assert_eq!(ProbeType::Bandwidth.priority(), DatagramPriority::Low);
        assert!(ProbeType::Bandwidth.payload_size() > ProbeType::KeepAlive.payload_size());
    }
}

#[cfg(test)]
mod beacon_manager_tests {
    use super::*;

    #[test]
    fn test_beacon_manager_path_lifecycle() {
        let mut manager = BeaconManager::new(Duration::from_secs(30));
        assert!(manager.get_path_stats(42).is_none());

        manager.create_beacon(42, BeaconMeasurement::empty());
        assert!(manager.get_path_stats(42).is_some());

        manager.cleanup_old_stats(Duration::from_secs(0));
        assert!(manager.get_path_stats(42).is_none());
    }

    #[test]
    fn test_beacon_creation_disabled_transport() {
        let disabled_transport = DatagramTransport::disabled();
        let mut manager = BeaconManager::new(Duration::from_secs(30));

        let beacon = manager.create_beacon(1, BeaconMeasurement::empty());
        let encoded = beacon.encode().unwrap();
        let result = disabled_transport.validate_size(encoded.len());
        assert!(matches!(result, Outcome::Err(DatagramError::NotSupported)));
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;

    #[test]
    fn test_transport_size_validation_edge_cases() {
        let mut transport = DatagramTransport::new(true, 100).unwrap();
        let params = peer_datagram_params(100);
        transport.process_peer_params(&params).unwrap();

        // Size exactly at limit should pass
        assert!(transport.validate_size(100).is_ok());

        // Size over limit should fail
        let result = transport.validate_size(101);
        assert!(matches!(
            result,
            Outcome::Err(DatagramError::PayloadTooLarge {
                size: 101,
                max: 100
            })
        ));
    }

    #[test]
    fn test_transport_peer_state_reset() {
        let mut transport = DatagramTransport::new(true, 1024).unwrap();

        // Simulate peer negotiation
        let params = peer_datagram_params(1024);
        transport.process_peer_params(&params).unwrap();
        assert!(transport.is_enabled());

        // Reset peer state
        transport.reset_peer_state();
        assert!(!transport.is_enabled());
        assert_eq!(transport.peer_max_size(), None);
    }
}
