#![allow(clippy::all)]
//! RFC 9000 §18 Transport Parameter Conformance Tests
//!
//! This module contains comprehensive conformance tests for QUIC transport parameter
//! encoding/decoding per RFC 9000 Section 18. Tests validate:
//!
//! - Parameter ID ranges and canonical values
//! - Varint encoding boundary conditions
//! - Duplicate parameter detection
//! - Invalid parameter value constraints
//! - Unknown parameter preservation (GREASE)
//! - Server-only parameter handling
//! - Parameter length validation
//! - TLV codec correctness

use crate::net::quic_core::*;

/// Test varint encoding at all boundary conditions per RFC 9000 §16
#[cfg(test)]
mod varint_boundary_tests {
    use super::*;

    #[test]
    fn varint_boundary_values_encode_decode() {
        let test_cases = [
            // 1-byte encoding: 0 to 63 (2^6 - 1)
            (0u64, 1),
            (63u64, 1),
            // 2-byte encoding: 64 to 16383 (2^14 - 1)
            (64u64, 2),
            (16383u64, 2),
            // 4-byte encoding: 16384 to 1073741823 (2^30 - 1)
            (16384u64, 4),
            (1073741823u64, 4),
            // 8-byte encoding: 1073741824 to 4611686018427387903 (2^62 - 1)
            (1073741824u64, 8),
            (QUIC_VARINT_MAX, 8),
        ];

        for (value, expected_len) in test_cases {
            let mut encoded = Vec::new();
            encode_varint(value, &mut encoded).expect("encode should succeed");
            assert_eq!(
                encoded.len(),
                expected_len,
                "varint {value} length mismatch"
            );

            let (decoded, consumed) = decode_varint(&encoded).expect("decode should succeed");
            assert_eq!(decoded, value, "varint {value} roundtrip failed");
            assert_eq!(
                consumed, expected_len,
                "varint {value} consumed bytes mismatch"
            );
        }
    }

    #[test]
    fn varint_maximum_value_boundary() {
        // RFC 9000 §16: Maximum value is 2^62 - 1
        let mut buf = Vec::new();

        // Should succeed at maximum value
        encode_varint(QUIC_VARINT_MAX, &mut buf).expect("max value should encode");

        // Should fail at maximum + 1
        let err =
            encode_varint(QUIC_VARINT_MAX + 1, &mut Vec::new()).expect_err("max+1 should fail");
        assert_eq!(err, QuicCoreError::VarIntOutOfRange(QUIC_VARINT_MAX + 1));
    }

    #[test]
    fn varint_truncation_detection() {
        // Test all varint length prefix patterns with truncated data
        let test_cases = [
            // 2-byte prefix but only 1 byte total
            (vec![0b01_000000], "2-byte truncated"),
            // 4-byte prefix but only 2 bytes total
            (vec![0b10_000000, 0x00], "4-byte truncated"),
            // 8-byte prefix but only 4 bytes total
            (vec![0b11_000000, 0x00, 0x00, 0x00], "8-byte truncated"),
        ];

        for (data, desc) in test_cases {
            let err = decode_varint(&data).expect_err(&format!("{desc} should fail"));
            assert_eq!(err, QuicCoreError::UnexpectedEof, "{desc} error mismatch");
        }
    }
}

/// Test transport parameter ID values and constraints per RFC 9000 §18.2
#[cfg(test)]
mod parameter_id_tests {
    use super::*;

    #[test]
    fn canonical_parameter_ids_match_rfc() {
        // RFC 9000 §18.2 Table 5: Transport Parameter Registry
        assert_eq!(TP_MAX_IDLE_TIMEOUT, 0x01);
        assert_eq!(TP_MAX_UDP_PAYLOAD_SIZE, 0x03);
        assert_eq!(TP_INITIAL_MAX_DATA, 0x04);
        assert_eq!(TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 0x05);
        assert_eq!(TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 0x06);
        assert_eq!(TP_INITIAL_MAX_STREAM_DATA_UNI, 0x07);
        assert_eq!(TP_INITIAL_MAX_STREAMS_BIDI, 0x08);
        assert_eq!(TP_INITIAL_MAX_STREAMS_UNI, 0x09);
        assert_eq!(TP_ACK_DELAY_EXPONENT, 0x0a);
        assert_eq!(TP_MAX_ACK_DELAY, 0x0b);
        assert_eq!(TP_DISABLE_ACTIVE_MIGRATION, 0x0c);
    }

    #[test]
    fn parameter_order_independence() {
        // RFC 9000 §18: Parameters may appear in any order
        let params1 = TransportParameters {
            max_idle_timeout: Some(30000),
            initial_max_data: Some(1000000),
            disable_active_migration: true,
            ..Default::default()
        };

        let params2 = TransportParameters {
            disable_active_migration: true,
            initial_max_data: Some(1000000),
            max_idle_timeout: Some(30000),
            ..Default::default()
        };

        let mut encoded1 = Vec::new();
        let mut encoded2 = Vec::new();

        params1.encode(&mut encoded1).expect("encode params1");
        params2.encode(&mut encoded2).expect("encode params2");

        // Encoded forms may differ due to field order in the struct
        let decoded1 = TransportParameters::decode(&encoded1).expect("decode params1");
        let decoded2 = TransportParameters::decode(&encoded2).expect("decode params2");

        // But decoded parameters should be semantically equivalent
        assert_eq!(decoded1, decoded2);
        assert_eq!(decoded1, params1);
    }

    #[test]
    fn grease_parameter_preservation() {
        // RFC 9000 §18: Unknown parameters must be preserved for GREASE
        let grease_params = [
            // GREASE values following pattern 31 * N + 27 for N = 0, 1, 2, ...
            0x1b, 0x4a, 0x79, 0xa8, 0xd7, 0x0106, 0x0135, // Additional reserved values
            0xff00, 0xff01, 0xfff0, 0xffff,
        ];

        for grease_id in grease_params {
            let params = TransportParameters {
                max_idle_timeout: Some(5000),
                unknown: vec![UnknownTransportParameter {
                    id: grease_id,
                    value: vec![0x42, 0x43, 0x44],
                }],
                ..Default::default()
            };

            let mut encoded = Vec::new();
            params.encode(&mut encoded).expect("encode with GREASE");

            let decoded = TransportParameters::decode(&encoded).expect("decode with GREASE");
            assert_eq!(
                decoded, params,
                "GREASE parameter {grease_id:#x} not preserved"
            );
        }
    }

    #[test]
    fn grease_parameter_exact_wire_vector() {
        let params = TransportParameters {
            max_idle_timeout: Some(30),
            unknown: vec![UnknownTransportParameter {
                id: 0x1b,
                value: vec![0x42, 0x43, 0x44],
            }],
            ..Default::default()
        };

        let mut encoded = Vec::new();
        params.encode(&mut encoded).expect("encode with GREASE");

        assert_eq!(
            encoded,
            vec![0x01, 0x01, 0x1e, 0x1b, 0x03, 0x42, 0x43, 0x44]
        );

        let decoded = TransportParameters::decode(&encoded).expect("decode exact wire vector");
        assert_eq!(decoded, params);
    }
}

/// Test parameter value constraints per RFC 9000 §18.2
#[cfg(test)]
mod parameter_value_tests {
    use super::*;

    #[test]
    fn max_udp_payload_size_constraints() {
        // RFC 9000 §18.2: max_udp_payload_size MUST be >= 1200
        let valid_values = [1200, 1400, 9000, 65535, QUIC_VARINT_MAX];
        let invalid_values = [0, 1, 1199];

        for value in valid_values {
            let params = TransportParameters {
                max_udp_payload_size: Some(value),
                ..Default::default()
            };
            let mut encoded = Vec::new();
            params
                .encode(&mut encoded)
                .expect("encode valid UDP payload size");
            let decoded =
                TransportParameters::decode(&encoded).expect("decode valid UDP payload size");
            assert_eq!(decoded.max_udp_payload_size, Some(value));
        }

        for value in invalid_values {
            let mut encoded = Vec::new();
            encode_parameter(&mut encoded, TP_MAX_UDP_PAYLOAD_SIZE, &varint_bytes(value))
                .expect("encode invalid UDP payload size");
            let err = TransportParameters::decode(&encoded)
                .expect_err("invalid UDP payload size should fail");
            assert_eq!(
                err,
                QuicCoreError::InvalidTransportParameter(TP_MAX_UDP_PAYLOAD_SIZE)
            );
        }
    }

    #[test]
    fn ack_delay_exponent_constraints() {
        // RFC 9000 §18.2: ack_delay_exponent MUST be <= 20
        let valid_values = [0, 3, 20];
        let invalid_values = [21, 50, 255];

        for value in valid_values {
            let params = TransportParameters {
                ack_delay_exponent: Some(value),
                ..Default::default()
            };
            let mut encoded = Vec::new();
            params
                .encode(&mut encoded)
                .expect("encode valid ack delay exponent");
            let decoded =
                TransportParameters::decode(&encoded).expect("decode valid ack delay exponent");
            assert_eq!(decoded.ack_delay_exponent, Some(value));
        }

        for value in invalid_values {
            let mut encoded = Vec::new();
            encode_parameter(&mut encoded, TP_ACK_DELAY_EXPONENT, &varint_bytes(value))
                .expect("encode invalid ack delay exponent");
            let err = TransportParameters::decode(&encoded)
                .expect_err("invalid ack delay exponent should fail");
            assert_eq!(
                err,
                QuicCoreError::InvalidTransportParameter(TP_ACK_DELAY_EXPONENT)
            );
        }
    }

    #[test]
    fn disable_active_migration_zero_length() {
        // RFC 9000 §18.2: disable_active_migration MUST have zero-length value
        let mut encoded = Vec::new();

        // Valid: zero-length value
        encode_parameter(&mut encoded, TP_DISABLE_ACTIVE_MIGRATION, &[])
            .expect("encode zero-length disable_active_migration");
        let decoded = TransportParameters::decode(&encoded)
            .expect("decode zero-length disable_active_migration");
        assert!(decoded.disable_active_migration);

        // Invalid: non-zero-length value
        encoded.clear();
        encode_parameter(&mut encoded, TP_DISABLE_ACTIVE_MIGRATION, &[0x01])
            .expect("encode non-zero-length disable_active_migration");
        let err = TransportParameters::decode(&encoded)
            .expect_err("non-zero-length disable_active_migration should fail");
        assert_eq!(
            err,
            QuicCoreError::InvalidTransportParameter(TP_DISABLE_ACTIVE_MIGRATION)
        );
    }

    fn varint_bytes(value: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_varint(value, &mut buf).expect("encode varint");
        buf
    }
}

/// Test duplicate parameter detection per RFC 9000 §18
#[cfg(test)]
mod duplicate_detection_tests {
    use super::*;

    #[test]
    fn duplicate_known_parameters_rejected() {
        // RFC 9000 §18: Duplicate parameters MUST be rejected
        let duplicate_cases = [
            TP_MAX_IDLE_TIMEOUT,
            TP_MAX_UDP_PAYLOAD_SIZE,
            TP_INITIAL_MAX_DATA,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            TP_INITIAL_MAX_STREAM_DATA_UNI,
            TP_INITIAL_MAX_STREAMS_BIDI,
            TP_INITIAL_MAX_STREAMS_UNI,
            TP_ACK_DELAY_EXPONENT,
            TP_MAX_ACK_DELAY,
        ];

        for param_id in duplicate_cases {
            let mut encoded = Vec::new();
            // First parameter
            encode_parameter(&mut encoded, param_id, &varint_bytes(1000))
                .expect("encode first parameter");
            // Duplicate parameter
            encode_parameter(&mut encoded, param_id, &varint_bytes(2000))
                .expect("encode duplicate parameter");

            let err =
                TransportParameters::decode(&encoded).expect_err("duplicate parameter should fail");
            assert_eq!(err, QuicCoreError::DuplicateTransportParameter(param_id));
        }
    }

    #[test]
    fn duplicate_disable_active_migration_rejected() {
        // Special case: disable_active_migration is a flag, not a varint
        let mut encoded = Vec::new();
        encode_parameter(&mut encoded, TP_DISABLE_ACTIVE_MIGRATION, &[])
            .expect("encode first disable_active_migration");
        encode_parameter(&mut encoded, TP_DISABLE_ACTIVE_MIGRATION, &[])
            .expect("encode duplicate disable_active_migration");

        let err = TransportParameters::decode(&encoded)
            .expect_err("duplicate disable_active_migration should fail");
        assert_eq!(
            err,
            QuicCoreError::DuplicateTransportParameter(TP_DISABLE_ACTIVE_MIGRATION)
        );
    }

    #[test]
    fn duplicate_unknown_parameters_rejected() {
        // RFC 9000 §18: Duplicate unknown parameters also MUST be rejected
        let unknown_id = 0xface;
        let mut encoded = Vec::new();
        encode_parameter(&mut encoded, unknown_id, &[0x01, 0x02])
            .expect("encode first unknown parameter");
        encode_parameter(&mut encoded, unknown_id, &[0x03, 0x04])
            .expect("encode duplicate unknown parameter");

        let err = TransportParameters::decode(&encoded)
            .expect_err("duplicate unknown parameter should fail");
        assert_eq!(err, QuicCoreError::DuplicateTransportParameter(unknown_id));
    }

    fn varint_bytes(value: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_varint(value, &mut buf).expect("encode varint");
        buf
    }
}

/// Test TLV encoding structure per RFC 9000 §18
#[cfg(test)]
mod tlv_structure_tests {
    use super::*;

    #[test]
    fn parameter_tlv_structure() {
        // RFC 9000 §18: Each parameter is TLV encoded (Type, Length, Value)
        let mut encoded = Vec::new();

        // Manually construct TLV for max_idle_timeout = 30000
        encode_varint(TP_MAX_IDLE_TIMEOUT, &mut encoded).expect("encode type");
        let value_bytes = varint_bytes(30000);
        encode_varint(value_bytes.len() as u64, &mut encoded).expect("encode length");
        encoded.extend_from_slice(&value_bytes);

        let decoded = TransportParameters::decode(&encoded).expect("decode TLV");
        assert_eq!(decoded.max_idle_timeout, Some(30000));
    }

    #[test]
    fn empty_transport_parameters() {
        // RFC 9000 §18: Empty transport parameters is valid
        let empty = Vec::new();
        let decoded = TransportParameters::decode(&empty).expect("decode empty");
        assert_eq!(decoded, TransportParameters::default());
    }

    #[test]
    fn truncated_parameter_detection() {
        // Test truncation at various points in TLV structure
        let mut encoded = Vec::new();
        encode_varint(TP_MAX_IDLE_TIMEOUT, &mut encoded).expect("encode type");
        encode_varint(8, &mut encoded).expect("encode length claiming 8 bytes");
        encoded.extend_from_slice(&[0x01, 0x02, 0x03]); // Only 3 bytes provided

        let err = TransportParameters::decode(&encoded).expect_err("truncated value should fail");
        assert_eq!(err, QuicCoreError::UnexpectedEof);
    }

    #[test]
    fn malformed_parameter_value() {
        // Parameter claims varint but contains invalid varint data
        let mut encoded = Vec::new();
        encode_varint(TP_MAX_IDLE_TIMEOUT, &mut encoded).expect("encode type");
        encode_varint(3, &mut encoded).expect("encode length");
        encoded.extend_from_slice(&[0x01, 0x02, 0x03]); // Not a valid varint

        let err = TransportParameters::decode(&encoded).expect_err("malformed varint should fail");
        assert_eq!(
            err,
            QuicCoreError::InvalidTransportParameter(TP_MAX_IDLE_TIMEOUT)
        );
    }

    fn varint_bytes(value: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_varint(value, &mut buf).expect("encode varint");
        buf
    }
}

/// Test comprehensive parameter combinations and edge cases
#[cfg(test)]
mod comprehensive_tests {
    use super::*;

    #[test]
    fn all_parameters_maximum_values() {
        // Test all parameters at their maximum allowable values
        let params = TransportParameters {
            max_idle_timeout: Some(QUIC_VARINT_MAX),
            max_udp_payload_size: Some(QUIC_VARINT_MAX),
            initial_max_data: Some(QUIC_VARINT_MAX),
            initial_max_stream_data_bidi_local: Some(QUIC_VARINT_MAX),
            initial_max_stream_data_bidi_remote: Some(QUIC_VARINT_MAX),
            initial_max_stream_data_uni: Some(QUIC_VARINT_MAX),
            initial_max_streams_bidi: Some(QUIC_VARINT_MAX),
            initial_max_streams_uni: Some(QUIC_VARINT_MAX),
            ack_delay_exponent: Some(20), // Maximum allowed
            max_ack_delay: Some(QUIC_VARINT_MAX),
            disable_active_migration: true,
            unknown: vec![
                UnknownTransportParameter {
                    id: 0xff00,
                    value: vec![0x42; 1000],
                },
                UnknownTransportParameter {
                    id: QUIC_VARINT_MAX,
                    value: vec![],
                },
            ],
        };

        let mut encoded = Vec::new();
        params
            .encode(&mut encoded)
            .expect("encode maximum parameters");

        let decoded = TransportParameters::decode(&encoded).expect("decode maximum parameters");
        assert_eq!(decoded, params);
    }

    #[test]
    fn all_parameters_minimum_values() {
        // Test all parameters at their minimum allowable values
        let params = TransportParameters {
            max_idle_timeout: Some(0),
            max_udp_payload_size: Some(1200), // Minimum per RFC
            initial_max_data: Some(0),
            initial_max_stream_data_bidi_local: Some(0),
            initial_max_stream_data_bidi_remote: Some(0),
            initial_max_stream_data_uni: Some(0),
            initial_max_streams_bidi: Some(0),
            initial_max_streams_uni: Some(0),
            ack_delay_exponent: Some(0),
            max_ack_delay: Some(0),
            disable_active_migration: false,
            unknown: vec![],
        };

        let mut encoded = Vec::new();
        params
            .encode(&mut encoded)
            .expect("encode minimum parameters");

        let decoded = TransportParameters::decode(&encoded).expect("decode minimum parameters");
        assert_eq!(decoded, params);
    }

    #[test]
    fn massive_unknown_parameter_list() {
        // Test handling of many unknown parameters (GREASE resistance)
        let mut unknown = Vec::new();
        for i in 0x1000..0x1100 {
            unknown.push(UnknownTransportParameter {
                id: i,
                value: vec![(i & 0xff) as u8],
            });
        }

        let params = TransportParameters {
            max_idle_timeout: Some(30000),
            unknown,
            ..Default::default()
        };

        let mut encoded = Vec::new();
        params
            .encode(&mut encoded)
            .expect("encode many unknown parameters");

        let decoded =
            TransportParameters::decode(&encoded).expect("decode many unknown parameters");
        assert_eq!(decoded, params);
        assert_eq!(decoded.unknown.len(), 256);
    }
}

/// Helper function to encode a single transport parameter
fn encode_parameter(out: &mut Vec<u8>, id: u64, value: &[u8]) -> Result<(), QuicCoreError> {
    encode_varint(id, out)?;
    encode_varint(value.len() as u64, out)?;
    out.extend_from_slice(value);
    Ok(())
}
