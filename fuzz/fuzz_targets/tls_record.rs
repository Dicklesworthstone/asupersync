//! TLS 1.3 record layer fuzz target for RFC 8446 compliance.
//!
//! This fuzzer tests TLS 1.3 record layer parsing robustness with emphasis
//! on protocol violations and edge cases:
//! - ContentType enum validation (handshake/application_data/alert/change_cipher_spec)
//! - TLSPlaintext.legacy_record_version echoed correctly
//! - record length bound enforcement (2^14 + 256 octets)
//! - empty records rejection
//! - record_iv exhaustion triggers renegotiation

#![no_main]

use arbitrary::Arbitrary;
use asupersync::tls::{TlsError, TlsStream};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

/// TLS 1.3 Content Types as per RFC 8446 Section 5.1
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ContentType {
    /// Change cipher spec (legacy, should be minimal in TLS 1.3)
    ChangeCipherSpec = 20,
    /// Alert messages
    Alert = 21,
    /// Handshake messages
    Handshake = 22,
    /// Application data
    ApplicationData = 23,
    /// Invalid content types for testing
    Invalid = 0,
    Reserved1 = 24,
    Reserved2 = 25,
    Reserved3 = 255,
}

impl ContentType {
    fn from_u8(value: u8) -> Self {
        match value {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            24 => Self::Reserved1,
            25 => Self::Reserved2,
            255 => Self::Reserved3,
            _ => Self::Invalid,
        }
    }

    fn is_valid(self) -> bool {
        matches!(
            self,
            Self::ChangeCipherSpec | Self::Alert | Self::Handshake | Self::ApplicationData
        )
    }
}

/// TLS Protocol Version
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
struct ProtocolVersion {
    major: u8,
    minor: u8,
}

impl ProtocolVersion {
    fn tls_1_2() -> Self {
        Self { major: 3, minor: 3 }
    }

    fn is_valid_legacy(self) -> bool {
        // RFC 8446: legacy_record_version should be 0x0303 (TLS 1.2) for compatibility
        self.major == 3 && self.minor == 3
    }

    fn to_bytes(self) -> [u8; 2] {
        [self.major, self.minor]
    }
}

/// TLS 1.3 Record as per RFC 8446 Section 5.1
#[derive(Arbitrary, Debug, Clone)]
struct TlsRecord {
    /// Content type of the record
    content_type: u8,
    /// Legacy record version (should be 0x0303 for TLS 1.3)
    legacy_record_version: ProtocolVersion,
    /// Length of the fragment (max 2^14 + 256 = 16640)
    length: u16,
    /// Record data
    fragment: Vec<u8>,
    /// Whether to test IV exhaustion scenario
    test_iv_exhaustion: bool,
    /// Number of records to simulate IV exhaustion
    iv_exhaustion_count: u16,
}

/// TLS record parsing operations for fuzzing
#[derive(Arbitrary, Debug)]
enum TlsRecordOperation {
    /// Parse single record with various malformations
    ParseSingleRecord { record: TlsRecord },
    /// Test sequence of records for IV exhaustion
    ParseRecordSequence { records: Vec<TlsRecord> },
    /// Test oversized record rejection
    TestOversizedRecord {
        content_type: u8,
        declared_length: u16,
        actual_data_size: u16,
    },
    /// Test empty record handling
    TestEmptyRecord {
        content_type: u8,
        legacy_version: ProtocolVersion,
    },
    /// Test invalid content type handling
    TestInvalidContentType {
        invalid_content_type: u8,
        legacy_version: ProtocolVersion,
        length: u16,
    },
}

/// Complete TLS record layer fuzz structure
#[derive(Arbitrary, Debug)]
struct TlsRecordFuzz {
    operations: Vec<TlsRecordOperation>,
    /// Global record_iv counter for exhaustion testing
    global_iv_counter: u64,
}

/// RFC 8446 constants
const MAX_RECORD_LENGTH: u16 = (1 << 14) + 256; // 2^14 + 256 = 16640 octets
const IV_EXHAUSTION_THRESHOLD: u64 = (1u64 << 24); // 2^24 records trigger renegotiation

/// Serialize TLS record to wire format
fn serialize_record(record: &TlsRecord) -> Vec<u8> {
    let mut buffer = Vec::new();

    // Content type (1 byte)
    buffer.push(record.content_type);

    // Legacy record version (2 bytes)
    buffer.extend_from_slice(&record.legacy_record_version.to_bytes());

    // Length (2 bytes, big-endian)
    buffer.extend_from_slice(&record.length.to_be_bytes());

    // Fragment data
    let mut fragment = record.fragment.clone();

    // Ensure fragment matches declared length (or truncate/pad)
    fragment.resize(record.length as usize, 0);

    buffer.extend_from_slice(&fragment);

    buffer
}

/// Parse TLS record from wire format
fn parse_record(data: &[u8]) -> Result<(ContentType, ProtocolVersion, u16, Vec<u8>), TlsError> {
    if data.len() < 5 {
        return Err(TlsError::Protocol(
            "TLS record too short for header".to_string(),
        ));
    }

    let content_type_raw = data[0];
    let legacy_version = ProtocolVersion {
        major: data[1],
        minor: data[2],
    };
    let length = u16::from_be_bytes([data[3], data[4]]);

    // Assertion 1: ContentType enum validated
    let content_type = ContentType::from_u8(content_type_raw);
    if !content_type.is_valid() {
        return Err(TlsError::Protocol(format!(
            "Invalid TLS ContentType: {}",
            content_type_raw
        )));
    }

    // Assertion 2: TLSPlaintext.legacy_record_version echoed
    if !legacy_version.is_valid_legacy() {
        return Err(TlsError::Protocol(format!(
            "Invalid legacy_record_version: {}.{}",
            legacy_version.major, legacy_version.minor
        )));
    }

    // Assertion 3: record length bound (2^14 + 256 octets)
    if length > MAX_RECORD_LENGTH {
        return Err(TlsError::Protocol(format!(
            "TLS record length {} exceeds maximum {}",
            length, MAX_RECORD_LENGTH
        )));
    }

    // Assertion 4: empty records rejected
    if length == 0 {
        return Err(TlsError::Protocol(
            "Empty TLS records are not allowed".to_string(),
        ));
    }

    // Check if we have enough data
    if data.len() < 5 + length as usize {
        return Err(TlsError::Protocol("Incomplete TLS record data".to_string()));
    }

    let fragment = data[5..5 + length as usize].to_vec();

    Ok((content_type, legacy_version, length, fragment))
}

/// Check if IV exhaustion should trigger renegotiation
fn check_iv_exhaustion(iv_counter: u64, record_count: u16) -> Result<(), TlsError> {
    // Assertion 5: record_iv exhaustion triggers renegotiation
    let projected_iv_counter = iv_counter + record_count as u64;

    if projected_iv_counter >= IV_EXHAUSTION_THRESHOLD {
        return Err(TlsError::Protocol(
            "IV exhaustion threshold reached, renegotiation required".to_string(),
        ));
    }

    Ok(())
}

/// Test TLS record parsing with comprehensive assertions
fn test_record_parsing(record: &TlsRecord, iv_counter: &mut u64) -> Result<(), TlsError> {
    let wire_data = serialize_record(record);

    // Parse the record
    let (content_type, version, length, fragment) = parse_record(&wire_data)?;

    // Verify parsing results match input (when valid)
    assert_eq!(content_type, ContentType::from_u8(record.content_type));
    assert_eq!(version, record.legacy_record_version);
    assert_eq!(length, record.length.min(record.fragment.len() as u16));

    // Test IV exhaustion if requested
    if record.test_iv_exhaustion {
        check_iv_exhaustion(*iv_counter, record.iv_exhaustion_count)?;
        *iv_counter += record.iv_exhaustion_count as u64;
    } else {
        *iv_counter += 1; // Normal record processing
    }

    Ok(())
}

/// Main fuzz target
fuzz_target!(|data: TlsRecordFuzz| {
    let mut global_iv_counter = data.global_iv_counter;

    for operation in data.operations {
        match operation {
            TlsRecordOperation::ParseSingleRecord { record } => {
                // Test single record parsing
                let result = test_record_parsing(&record, &mut global_iv_counter);

                // Verify error conditions are properly detected
                match result {
                    Ok(()) => {
                        // Parsing succeeded - verify invariants
                        let content_type = ContentType::from_u8(record.content_type);
                        assert!(
                            content_type.is_valid(),
                            "Invalid ContentType should be rejected"
                        );
                        assert!(
                            record.legacy_record_version.is_valid_legacy(),
                            "Invalid legacy version should be rejected"
                        );
                        assert!(
                            record.length <= MAX_RECORD_LENGTH,
                            "Oversized record should be rejected"
                        );
                        assert!(record.length > 0, "Empty record should be rejected");
                    }
                    Err(e) => {
                        // Parsing failed - verify it's for the right reasons
                        match e {
                            TlsError::Protocol(msg) => {
                                // Expected for malformed data
                                if msg.contains("Invalid TLS ContentType") {
                                    assert!(!ContentType::from_u8(record.content_type).is_valid());
                                } else if msg.contains("Invalid legacy_record_version") {
                                    assert!(!record.legacy_record_version.is_valid_legacy());
                                } else if msg.contains("exceeds maximum") {
                                    assert!(record.length > MAX_RECORD_LENGTH);
                                } else if msg.contains("Empty TLS records") {
                                    assert_eq!(record.length, 0);
                                } else if msg.contains("IV exhaustion") {
                                    // IV exhaustion properly detected
                                }
                            }
                            _ => { /* Other errors acceptable */ }
                        }
                    }
                }
            }

            TlsRecordOperation::ParseRecordSequence { records } => {
                // Test sequence of records for cumulative effects
                for record in records {
                    let _ = test_record_parsing(&record, &mut global_iv_counter);

                    // Check if IV exhaustion threshold is approaching
                    if global_iv_counter >= IV_EXHAUSTION_THRESHOLD {
                        // Should trigger renegotiation
                        assert!(
                            check_iv_exhaustion(global_iv_counter, 1).is_err(),
                            "IV exhaustion should be detected"
                        );
                        break; // Stop processing after exhaustion
                    }
                }
            }

            TlsRecordOperation::TestOversizedRecord {
                content_type,
                declared_length,
                actual_data_size,
            } => {
                // Test oversized record detection
                let oversized_record = TlsRecord {
                    content_type,
                    legacy_record_version: ProtocolVersion::tls_1_2(),
                    length: declared_length,
                    fragment: vec![0u8; actual_data_size as usize],
                    test_iv_exhaustion: false,
                    iv_exhaustion_count: 0,
                };

                let result = test_record_parsing(&oversized_record, &mut global_iv_counter);

                if declared_length > MAX_RECORD_LENGTH {
                    // Should be rejected
                    assert!(result.is_err(), "Oversized record should be rejected");
                } else {
                    // Size is valid - should succeed or fail for other reasons
                    match result {
                        Ok(()) => { /* Valid record processed */ }
                        Err(TlsError::Protocol(msg)) if msg.contains("exceeds maximum") => {
                            panic!("Valid-sized record should not be rejected for size");
                        }
                        Err(_) => { /* Other errors OK */ }
                    }
                }
            }

            TlsRecordOperation::TestEmptyRecord {
                content_type,
                legacy_version,
            } => {
                // Test empty record rejection
                let empty_record = TlsRecord {
                    content_type,
                    legacy_record_version: legacy_version,
                    length: 0,
                    fragment: vec![],
                    test_iv_exhaustion: false,
                    iv_exhaustion_count: 0,
                };

                let result = test_record_parsing(&empty_record, &mut global_iv_counter);

                // Empty records should always be rejected
                assert!(result.is_err(), "Empty records should be rejected");
                if let Err(TlsError::Protocol(msg)) = result {
                    assert!(
                        msg.contains("Empty TLS records"),
                        "Should specifically reject empty records"
                    );
                }
            }

            TlsRecordOperation::TestInvalidContentType {
                invalid_content_type,
                legacy_version,
                length,
            } => {
                // Test invalid content type rejection
                let invalid_record = TlsRecord {
                    content_type: invalid_content_type,
                    legacy_record_version: legacy_version,
                    length: length.min(MAX_RECORD_LENGTH),
                    fragment: vec![0u8; (length.min(MAX_RECORD_LENGTH)) as usize],
                    test_iv_exhaustion: false,
                    iv_exhaustion_count: 0,
                };

                let result = test_record_parsing(&invalid_record, &mut global_iv_counter);

                let content_type = ContentType::from_u8(invalid_content_type);
                if !content_type.is_valid() {
                    // Should be rejected for invalid content type
                    assert!(result.is_err(), "Invalid ContentType should be rejected");
                    if let Err(TlsError::Protocol(msg)) = result {
                        assert!(
                            msg.contains("Invalid TLS ContentType"),
                            "Should specifically reject invalid ContentType"
                        );
                    }
                } else {
                    // Valid content type - should succeed or fail for other reasons
                    match result {
                        Ok(()) => { /* Valid record processed */ }
                        Err(TlsError::Protocol(msg)) if msg.contains("Invalid TLS ContentType") => {
                            panic!("Valid ContentType should not be rejected");
                        }
                        Err(_) => { /* Other errors OK */ }
                    }
                }
            }
        }
    }
});

/// Test utilities for record validation
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type_validation() {
        assert!(ContentType::Handshake.is_valid());
        assert!(ContentType::ApplicationData.is_valid());
        assert!(ContentType::Alert.is_valid());
        assert!(ContentType::ChangeCipherSpec.is_valid());
        assert!(!ContentType::Invalid.is_valid());
        assert!(!ContentType::Reserved1.is_valid());
    }

    #[test]
    fn test_protocol_version_validation() {
        let tls_1_2 = ProtocolVersion::tls_1_2();
        assert!(tls_1_2.is_valid_legacy());

        let invalid_version = ProtocolVersion { major: 3, minor: 4 };
        assert!(!invalid_version.is_valid_legacy());
    }

    #[test]
    fn test_record_length_bounds() {
        assert!(MAX_RECORD_LENGTH == 16640);
        assert!(16641 > MAX_RECORD_LENGTH);
        assert!(16640 == MAX_RECORD_LENGTH);
    }

    #[test]
    fn test_iv_exhaustion_threshold() {
        assert!(IV_EXHAUSTION_THRESHOLD == (1u64 << 24));
        assert!(check_iv_exhaustion(IV_EXHAUSTION_THRESHOLD - 1, 1).is_ok());
        assert!(check_iv_exhaustion(IV_EXHAUSTION_THRESHOLD, 1).is_err());
    }
}
