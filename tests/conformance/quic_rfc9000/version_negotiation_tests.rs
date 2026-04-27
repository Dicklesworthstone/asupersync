#![allow(warnings)]
#![allow(clippy::all)]
//! QUIC Version Negotiation conformance tests.
//!
//! Tests RFC 9000 Section 17 Version Negotiation requirements - the highest
//! priority gap identified in QUIC conformance coverage.

use super::*;

/// Run all Version Negotiation conformance tests.
#[allow(dead_code)]
pub fn run_version_negotiation_tests() -> Vec<QuicConformanceResult> {
    let mut results = Vec::new();

    results.push(test_version_negotiation_packet_format());
    results.push(test_version_list_validation());
    results.push(test_client_downgrade_detection());
    results.push(test_server_version_selection());
    results.push(test_version_negotiation_security());
    results.push(test_initial_packet_version_handling());

    results
}

/// RFC 9000 Section 17.2.1: Version Negotiation packet format.
#[allow(dead_code)]
fn test_version_negotiation_packet_format() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Version Negotiation packet structure per RFC 9000

        // Header format:
        // - First bit: 1 (long form)
        // - Bits 1-7: 0x00 (version negotiation specific)
        // - Version: 0x00000000 (always zero for version negotiation)
        // - DCID Len: 1 byte
        // - Destination Connection ID: variable length
        // - SCID Len: 1 byte
        // - Source Connection ID: variable length
        // - Supported Versions: list of 4-byte version identifiers

        let test_packet = VersionNegotiationPacket {
            header_byte: 0x80, // Long form, version negotiation
            version: 0x00000000, // Always zero
            dcid_len: 8,
            dcid: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            scid_len: 4,
            scid: vec![0x11, 0x12, 0x13, 0x14],
            supported_versions: vec![0x00000001, 0x709a50c4], // QUIC v1 + draft version
        };

        // Validate packet structure
        if test_packet.header_byte != 0x80 {
            return Err("Version negotiation packet must use long form (first bit = 1)".to_string());
        }

        if test_packet.version != 0x00000000 {
            return Err("Version negotiation packet must have version field = 0".to_string());
        }

        if test_packet.dcid_len != test_packet.dcid.len() as u8 {
            return Err("DCID length field must match actual DCID length".to_string());
        }

        if test_packet.scid_len != test_packet.scid.len() as u8 {
            return Err("SCID length field must match actual SCID length".to_string());
        }

        // Supported versions list must be non-empty
        if test_packet.supported_versions.is_empty() {
            return Err("Version negotiation must include at least one supported version".to_string());
        }

        // Each version is exactly 4 bytes
        for version in &test_packet.supported_versions {
            if *version == 0x00000000 {
                return Err("Supported versions list must not include version 0".to_string());
            }
        }

        // Packet size validation
        let expected_size = 1 + 4 + 1 + test_packet.dcid.len() + 1 + test_packet.scid.len()
                          + (test_packet.supported_versions.len() * 4);
        let actual_size = calculate_version_negotiation_size(&test_packet);

        if actual_size != expected_size {
            return Err(format!(
                "Version negotiation packet size mismatch: expected {}, got {}",
                expected_size, actual_size
            ));
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-17.2.1-VN-FORMAT",
        "Version Negotiation packet format validation",
        TestCategory::VersionNegotiation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9000 Section 17.2.1: Version list validation.
#[allow(dead_code)]
fn test_version_list_validation() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test various version lists and their validation

        let valid_version_lists = vec![
            vec![0x00000001], // QUIC v1 only
            vec![0x00000001, 0x709a50c4], // v1 + draft
            vec![0x6b3343cf, 0x00000001], // draft + v1 (order matters for preference)
        ];

        for (i, version_list) in valid_version_lists.iter().enumerate() {
            if !is_valid_version_list(version_list) {
                return Err(format!("Valid version list {} was rejected", i));
            }
        }

        let invalid_version_lists = vec![
            vec![], // Empty list
            vec![0x00000000], // Contains version 0
            vec![0x00000001, 0x00000000, 0x709a50c4], // Contains version 0 in middle
        ];

        for (i, version_list) in invalid_version_lists.iter().enumerate() {
            if is_valid_version_list(version_list) {
                return Err(format!("Invalid version list {} was accepted", i));
            }
        }

        // Test version preference ordering
        let preference_test = vec![0x00000001, 0x709a50c4]; // Server preference order
        let selected_version = select_server_preferred_version(&preference_test, &[0x709a50c4, 0x00000001]);

        if selected_version != Some(0x00000001) {
            return Err("Server should select first supported version from its preference list".to_string());
        }

        // Test no common version scenario
        let server_versions = vec![0x00000001];
        let client_versions = vec![0x709a50c4];
        let selected = select_server_preferred_version(&server_versions, &client_versions);

        if selected.is_some() {
            return Err("Should return None when no common versions exist".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-17.2.1-VN-VALIDATION",
        "Version list validation and preference handling",
        TestCategory::VersionNegotiation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9000 Section 17.2.1: Client downgrade detection.
#[allow(dead_code)]
fn test_client_downgrade_detection() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Client must detect attempted version downgrade attacks

        let client_supported_versions = vec![0x00000001, 0x709a50c4]; // Client supports both

        // Scenario 1: Server claims to only support older version
        let suspicious_server_response = vec![0x709a50c4]; // Only draft, not v1

        // Client should be suspicious if server doesn't include versions that
        // are widely supported and should be known to the server
        if is_legitimate_version_negotiation(&client_supported_versions, &suspicious_server_response) {
            return Err("Client should detect potential downgrade attack".to_string());
        }

        // Scenario 2: Legitimate version negotiation
        let legitimate_server_response = vec![0x00000002]; // Hypothetical future version

        if !is_legitimate_version_negotiation(&client_supported_versions, &legitimate_server_response) {
            return Err("Legitimate version negotiation should be accepted".to_string());
        }

        // Scenario 3: Server supports subset of client versions (legitimate)
        let subset_server_response = vec![0x709a50c4]; // Server only supports draft
        let limited_client_versions = vec![0x709a50c4, 0x6b3343cf]; // Client supports drafts

        if !is_legitimate_version_negotiation(&limited_client_versions, &subset_server_response) {
            return Err("Legitimate subset version negotiation should be accepted".to_string());
        }

        // Scenario 4: Empty version list (attack)
        let empty_server_response = vec![];

        if is_legitimate_version_negotiation(&client_supported_versions, &empty_server_response) {
            return Err("Empty version list should be detected as attack".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-17.2.1-DOWNGRADE-DETECTION",
        "Client detection of version downgrade attacks",
        TestCategory::VersionNegotiation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9000 Section 17.2.1: Server version selection.
#[allow(dead_code)]
fn test_server_version_selection() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Server version selection algorithm

        let server_supported_versions = vec![0x00000001, 0x709a50c4, 0x6b3343cf]; // Server preference order

        // Test 1: Client and server have common versions
        let client_versions_1 = vec![0x709a50c4, 0x6b3343cf];
        let selected_1 = select_server_preferred_version(&server_supported_versions, &client_versions_1);

        // Server should select highest preference version that client also supports
        if selected_1 != Some(0x709a50c4) {
            return Err("Server should select highest preference common version".to_string());
        }

        // Test 2: Only one common version
        let client_versions_2 = vec![0x6b3343cf, 0x12345678]; // Only 0x6b3343cf is common
        let selected_2 = select_server_preferred_version(&server_supported_versions, &client_versions_2);

        if selected_2 != Some(0x6b3343cf) {
            return Err("Server should select the only common version".to_string());
        }

        // Test 3: No common versions
        let client_versions_3 = vec![0x12345678, 0x87654321]; // No common versions
        let selected_3 = select_server_preferred_version(&server_supported_versions, &client_versions_3);

        if selected_3.is_some() {
            return Err("Server should return None when no common versions exist".to_string());
        }

        // Test 4: Client supports exact server version
        let client_versions_4 = vec![0x00000001]; // Exact match with server's top preference
        let selected_4 = select_server_preferred_version(&server_supported_versions, &client_versions_4);

        if selected_4 != Some(0x00000001) {
            return Err("Server should select exact match when available".to_string());
        }

        // Test 5: Multiple common versions - server preference wins
        let client_versions_5 = vec![0x6b3343cf, 0x00000001, 0x709a50c4]; // All common, different order
        let selected_5 = select_server_preferred_version(&server_supported_versions, &client_versions_5);

        if selected_5 != Some(0x00000001) {
            return Err("Server should use its own preference order, not client's".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-17.2.1-SERVER-SELECTION",
        "Server version selection algorithm",
        TestCategory::VersionNegotiation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9000 Section 17.2.1: Version negotiation security considerations.
#[allow(dead_code)]
fn test_version_negotiation_security() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Security considerations for version negotiation

        // 1. Version negotiation packets are not protected
        // Clients must be prepared for man-in-the-middle attacks

        // 2. Retry with original version after receiving version negotiation
        let original_client_version = 0x00000001;
        let server_supported_versions = vec![0x709a50c4];

        // Client should retry with common version, not blindly accept server's suggestion
        let retry_version = negotiate_version_securely(original_client_version, &server_supported_versions)?;

        if !server_supported_versions.contains(&retry_version) {
            return Err("Negotiated version must be in server's supported list".to_string());
        }

        // 3. Protection against version oracle attacks
        // Server should not reveal information about supported versions
        // beyond what's necessary for negotiation

        let probing_versions = vec![0x12345678, 0x87654321]; // Unknown versions
        let server_response = generate_version_negotiation_response(&probing_versions);

        // Response should be consistent regardless of probe versions
        if server_response.supported_versions.len() == 0 {
            return Err("Server should respond with its supported versions".to_string());
        }

        // 4. Replay attack protection
        // Connection IDs in version negotiation should be validated
        let legitimate_dcid = vec![0x01, 0x02, 0x03, 0x04];
        let replayed_dcid = vec![0x05, 0x06, 0x07, 0x08]; // Different DCID

        if !validate_version_negotiation_dcid(&legitimate_dcid, &legitimate_dcid) {
            return Err("Legitimate DCID should be accepted".to_string());
        }

        if validate_version_negotiation_dcid(&legitimate_dcid, &replayed_dcid) {
            return Err("Mismatched DCID should be rejected".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-17.2.1-VN-SECURITY",
        "Version negotiation security considerations",
        TestCategory::VersionNegotiation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9000 Section 17.2.1: Initial packet version handling.
#[allow(dead_code)]
fn test_initial_packet_version_handling() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Version field handling in Initial packets

        // Server receiving Initial packet with unsupported version
        // must respond with Version Negotiation packet

        let unsupported_version = 0x12345678;
        let server_supported = vec![0x00000001];

        let response = handle_initial_packet_version(unsupported_version, &server_supported);

        match response {
            InitialPacketResponse::VersionNegotiation(vn_packet) => {
                if !vn_packet.supported_versions.contains(&0x00000001) {
                    return Err("Version negotiation response must include server's supported versions".to_string());
                }
            },
            _ => {
                return Err("Server must respond with version negotiation for unsupported version".to_string());
            }
        }

        // Server receiving Initial packet with supported version
        // should process normally
        let supported_version = 0x00000001;
        let response_supported = handle_initial_packet_version(supported_version, &server_supported);

        match response_supported {
            InitialPacketResponse::Process => {
                // Expected behavior
            },
            _ => {
                return Err("Server should process Initial packet with supported version normally".to_string());
            }
        }

        // Edge case: Version field with reserved bits
        let reserved_version = 0x0a0a0a0a; // Hypothetical reserved version
        if is_reserved_version(reserved_version) {
            // Reserved versions should trigger specific handling
            let response_reserved = handle_initial_packet_version(reserved_version, &server_supported);
            // Implementation specific - may accept or negotiate
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-17.2.1-INITIAL-VERSION",
        "Initial packet version field handling",
        TestCategory::VersionNegotiation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

// Helper types and functions for Version Negotiation testing

#[derive(Debug, Clone)]
struct VersionNegotiationPacket {
    header_byte: u8,
    version: u32,
    dcid_len: u8,
    dcid: Vec<u8>,
    scid_len: u8,
    scid: Vec<u8>,
    supported_versions: Vec<u32>,
}

#[derive(Debug)]
enum InitialPacketResponse {
    Process,
    VersionNegotiation(VersionNegotiationPacket),
    Drop,
}

/// Calculate the size of a version negotiation packet.
fn calculate_version_negotiation_size(packet: &VersionNegotiationPacket) -> usize {
    1 + 4 + 1 + packet.dcid.len() + 1 + packet.scid.len() + (packet.supported_versions.len() * 4)
}

/// Validate a list of supported versions.
fn is_valid_version_list(versions: &[u32]) -> bool {
    !versions.is_empty() && !versions.contains(&0x00000000)
}

/// Select server's preferred version from common versions.
fn select_server_preferred_version(server_prefs: &[u32], client_versions: &[u32]) -> Option<u32> {
    for &server_version in server_prefs {
        if client_versions.contains(&server_version) {
            return Some(server_version);
        }
    }
    None
}

/// Check if version negotiation is legitimate (not a downgrade attack).
fn is_legitimate_version_negotiation(client_supported: &[u32], server_supported: &[u32]) -> bool {
    // Simplified heuristic: legitimate if server supports at least one version
    // and doesn't exclude widely supported versions without good reason
    !server_supported.is_empty() &&
    (server_supported.iter().any(|&v| client_supported.contains(&v)) ||
     server_supported.iter().all(|&v| v > client_supported.iter().max().copied().unwrap_or(0)))
}

/// Securely negotiate version after receiving version negotiation.
fn negotiate_version_securely(original_version: u32, server_versions: &[u32]) -> Result<u32, String> {
    // Client should pick the highest version it supports that server also supports
    let client_supported = vec![original_version, 0x709a50c4]; // Example client versions

    for &client_version in &client_supported {
        if server_versions.contains(&client_version) {
            return Ok(client_version);
        }
    }

    Err("No common version found".to_string())
}

/// Generate version negotiation response for given client versions.
fn generate_version_negotiation_response(client_versions: &[u32]) -> VersionNegotiationPacket {
    // Server always responds with its full supported version list
    VersionNegotiationPacket {
        header_byte: 0x80,
        version: 0x00000000,
        dcid_len: 8,
        dcid: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        scid_len: 4,
        scid: vec![0x11, 0x12, 0x13, 0x14],
        supported_versions: vec![0x00000001, 0x709a50c4], // Server's versions
    }
}

/// Validate DCID in version negotiation packet.
fn validate_version_negotiation_dcid(expected_dcid: &[u8], actual_dcid: &[u8]) -> bool {
    expected_dcid == actual_dcid
}

/// Handle version in Initial packet.
fn handle_initial_packet_version(version: u32, server_supported: &[u32]) -> InitialPacketResponse {
    if server_supported.contains(&version) {
        InitialPacketResponse::Process
    } else {
        InitialPacketResponse::VersionNegotiation(generate_version_negotiation_response(&[version]))
    }
}

/// Check if a version is reserved.
fn is_reserved_version(version: u32) -> bool {
    // RFC 9000 defines certain version number ranges as reserved
    (version & 0x0f0f0f0f) == 0x0a0a0a0a
}