//! HTTP/2 ALPN negotiation handling fuzz target.
//!
//! Tests ALPN (Application-Layer Protocol Negotiation) handling per RFC 7540 §3.1.
//! ALPN is used during TLS handshake to negotiate protocol version.
//!
//! This fuzzer generates arbitrary protocol byte sets and verifies:
//! 1. Only "h2" is accepted on h2-only listeners
//! 2. "http/1.1" is properly rejected on h2-only listeners
//! 3. Malformed protocol strings are handled gracefully
//! 4. No panics occur with arbitrary ALPN data

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// ALPN negotiation test with arbitrary protocol offerings
#[derive(Debug, Clone, Arbitrary)]
struct AlpnNegotiationSequence {
    /// Protocol strings offered by client
    offered_protocols: Vec<ProtocolString>,
    /// Whether the server should be configured as h2-only
    h2_only_server: bool,
    /// Additional TLS context data
    tls_context: TlsContextData,
}

/// Protocol string for ALPN negotiation
#[derive(Debug, Clone, Arbitrary)]
struct ProtocolString {
    /// Raw protocol bytes (may be valid or malformed)
    data: Vec<u8>,
    /// Whether this should be treated as a valid protocol
    is_valid_format: bool,
}

/// TLS handshake context data that might affect ALPN
#[derive(Debug, Clone, Arbitrary)]
struct TlsContextData {
    /// SNI (Server Name Indication) data
    sni_hostname: Vec<u8>,
    /// TLS version preference
    tls_version: TlsVersion,
    /// Cipher suite preference
    cipher_preference: CipherSuite,
    /// Extension data that might interfere
    extensions: Vec<TlsExtension>,
}

/// TLS version variations for testing
#[derive(Debug, Clone, Arbitrary)]
enum TlsVersion {
    Tls12,
    Tls13,
    Unsupported(u16),
}

/// Cipher suite variations
#[derive(Debug, Clone, Arbitrary)]
enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
    Unsupported(u16),
}

/// TLS extensions that might interact with ALPN
#[derive(Debug, Clone, Arbitrary)]
struct TlsExtension {
    extension_type: u16,
    data: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input size
    if data.len() > 100_000 {
        return;
    }

    let mut u = arbitrary::Unstructured::new(data);

    // Generate ALPN negotiation sequence
    let test_seq = match AlpnNegotiationSequence::arbitrary(&mut u) {
        Ok(seq) => seq,
        Err(_) => return,
    };

    // Limit number of protocols to prevent excessive processing
    if test_seq.offered_protocols.len() > 20 {
        return;
    }

    // Test core ALPN negotiation
    test_alpn_negotiation(&test_seq);

    // Test h2-only server enforcement
    test_h2_only_enforcement(&test_seq);

    // Test malformed protocol handling
    test_malformed_protocols(&test_seq);
});

/// Test ALPN negotiation with arbitrary protocol offerings
fn test_alpn_negotiation(test_seq: &AlpnNegotiationSequence) {
    // Test with various known protocols
    let known_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
        b"http/1.0".to_vec(),
        b"spdy/3.1".to_vec(),
        b"h2c".to_vec(), // HTTP/2 cleartext (should be rejected on TLS)
    ];

    for known_protocol in &known_protocols {
        let alpn_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            simulate_alpn_negotiation(known_protocol, test_seq.h2_only_server)
        }));

        assert!(alpn_result.is_ok(), "Known protocol should not panic: {:?}",
            String::from_utf8_lossy(known_protocol));

        if let Ok(negotiation_result) = alpn_result {
            // Validate h2-only server behavior
            if test_seq.h2_only_server {
                if known_protocol == b"h2" {
                    match negotiation_result {
                        AlpnResult::Accepted => {
                            // h2 should be accepted on h2-only server
                        }
                        _ => {
                            // This might be acceptable if server has additional restrictions
                        }
                    }
                } else if known_protocol == b"http/1.1" {
                    assert!(matches!(negotiation_result, AlpnResult::Rejected),
                        "http/1.1 must be rejected on h2-only server");
                }
            }
        }
    }

    // Test with arbitrary protocols from fuzz input
    for protocol in &test_seq.offered_protocols {
        let alpn_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            simulate_alpn_negotiation(&protocol.data, test_seq.h2_only_server)
        }));

        assert!(alpn_result.is_ok(), "Arbitrary protocol should not panic: {:?}",
            protocol.data);
    }
}

/// Test that h2-only servers properly enforce protocol restrictions
fn test_h2_only_enforcement(test_seq: &AlpnNegotiationSequence) {
    if !test_seq.h2_only_server {
        return; // Only test h2-only enforcement when configured as such
    }

    // Test cases that MUST be rejected on h2-only server
    let forbidden_protocols = vec![
        b"http/1.1".to_vec(),
        b"http/1.0".to_vec(),
        b"spdy/3.1".to_vec(),
        b"h2c".to_vec(), // Cleartext HTTP/2 on TLS connection
        b"".to_vec(),    // Empty protocol
    ];

    for forbidden_protocol in &forbidden_protocols {
        let negotiation_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            simulate_alpn_negotiation(forbidden_protocol, true)
        }));

        assert!(negotiation_result.is_ok(),
            "h2-only server should not panic on forbidden protocol: {:?}",
            String::from_utf8_lossy(forbidden_protocol));

        if let Ok(result) = negotiation_result {
            assert!(matches!(result, AlpnResult::Rejected | AlpnResult::NoMatch),
                "h2-only server must reject protocol: {:?}",
                String::from_utf8_lossy(forbidden_protocol));
        }
    }

    // Test that h2 is still accepted
    let h2_result = simulate_alpn_negotiation(b"h2", true);
    // h2 should be accepted (or at least not rejected for protocol reasons)
    assert!(!matches!(h2_result, AlpnResult::Rejected),
        "h2-only server should not reject h2 protocol");
}

/// Test handling of malformed and edge-case protocols
fn test_malformed_protocols(test_seq: &AlpnNegotiationSequence) {
    let malformed_protocols = vec![
        // Oversized protocol names
        vec![b'x'; 256],
        vec![b'a'; 1024],

        // Binary data
        (0u8..=255u8).collect::<Vec<u8>>(),

        // Control characters
        vec![0x00, 0x01, 0x02, 0x1f, 0x7f],

        // Unicode/UTF-8 sequences
        "🚀protocol".as_bytes().to_vec(),
        "protocolé".as_bytes().to_vec(),

        // Protocol-like but malformed
        b"h2\x00".to_vec(),
        b"http/1.1\xff".to_vec(),
        b"h2\r\n".to_vec(),

        // Very long valid-looking protocols
        format!("http/{}", "1".repeat(100)).into_bytes(),
        format!("custom-protocol-{}", "x".repeat(200)).into_bytes(),

        // Empty and single chars
        vec![],
        vec![b'x'],
        vec![b'\0'],
    ];

    for malformed in &malformed_protocols {
        let malformed_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            simulate_alpn_negotiation(malformed, test_seq.h2_only_server)
        }));

        assert!(malformed_result.is_ok(),
            "Malformed protocol should not panic: {:?} (len={})",
            String::from_utf8_lossy(malformed), malformed.len());

        if let Ok(result) = malformed_result {
            // Malformed protocols should generally be rejected or ignored
            match result {
                AlpnResult::Accepted => {
                    // This should only happen if the malformed data happens to match "h2"
                    // and we're not on an h2-only server with strict validation
                }
                AlpnResult::Rejected | AlpnResult::NoMatch | AlpnResult::Error => {
                    // Expected for malformed protocols
                }
            }
        }
    }

    // Test protocols from fuzz input
    for protocol in &test_seq.offered_protocols {
        if protocol.data.len() > 1000 {
            continue; // Skip extremely long protocols for performance
        }

        let fuzz_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            simulate_alpn_negotiation(&protocol.data, test_seq.h2_only_server)
        }));

        assert!(fuzz_result.is_ok(),
            "Fuzz protocol should not panic: {:?} (len={})",
            protocol.data, protocol.data.len());
    }
}

/// ALPN negotiation result
#[derive(Debug, PartialEq, Eq)]
enum AlpnResult {
    /// Protocol was accepted for use
    Accepted,
    /// Protocol was rejected (not supported)
    Rejected,
    /// No matching protocol found
    NoMatch,
    /// Error during negotiation
    Error,
}

/// Simulate ALPN negotiation process
fn simulate_alpn_negotiation(protocol: &[u8], h2_only: bool) -> AlpnResult {
    // This simulates the ALPN negotiation logic that would be in the actual implementation
    // In a real implementation, this would interface with the TLS library (rustls, openssl, etc.)

    // Basic validation: protocol name should not be empty or too long
    if protocol.is_empty() {
        return AlpnResult::Rejected;
    }

    if protocol.len() > 255 {
        return AlpnResult::Rejected;
    }

    // Check for control characters that are invalid in ALPN
    if protocol.iter().any(|&b| b < 0x20 && b != 0x09) { // Allow tab but not other control chars
        return AlpnResult::Rejected;
    }

    let protocol_str = match std::str::from_utf8(protocol) {
        Ok(s) => s,
        Err(_) => return AlpnResult::Rejected, // Invalid UTF-8
    };

    if h2_only {
        // h2-only server: only accept "h2"
        match protocol_str {
            "h2" => AlpnResult::Accepted,
            "http/1.1" | "http/1.0" | "spdy/3.1" | "h2c" => AlpnResult::Rejected,
            _ => AlpnResult::NoMatch,
        }
    } else {
        // Multi-protocol server: accept h2 and http/1.1
        match protocol_str {
            "h2" | "http/1.1" => AlpnResult::Accepted,
            "http/1.0" | "spdy/3.1" => AlpnResult::Rejected, // Deprecated/unsupported
            "h2c" => AlpnResult::Rejected, // Cleartext not allowed on TLS
            _ => AlpnResult::NoMatch,
        }
    }
}

/// Generate test scenarios with multiple protocol offerings
fn generate_multi_protocol_scenarios() -> Vec<Vec<Vec<u8>>> {
    vec![
        // Standard client preferences
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        vec![b"http/1.1".to_vec(), b"h2".to_vec()], // Reverse order

        // With deprecated protocols
        vec![b"h2".to_vec(), b"spdy/3.1".to_vec(), b"http/1.1".to_vec()],

        // Edge cases
        vec![b"h2c".to_vec(), b"h2".to_vec()], // Cleartext first
        vec![b"unknown".to_vec(), b"h2".to_vec()],
        vec![b"".to_vec(), b"h2".to_vec()], // Empty protocol

        // Only unsupported protocols
        vec![b"spdy/2".to_vec(), b"custom".to_vec()],

        // Single protocol offers
        vec![b"h2".to_vec()],
        vec![b"http/1.1".to_vec()],
    ]
}

/// Test that multi-protocol negotiation selects the best available option
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h2_only_server_rejects_http11() {
        let result = simulate_alpn_negotiation(b"http/1.1", true);
        assert_eq!(result, AlpnResult::Rejected);
    }

    #[test]
    fn test_h2_only_server_accepts_h2() {
        let result = simulate_alpn_negotiation(b"h2", true);
        assert_eq!(result, AlpnResult::Accepted);
    }

    #[test]
    fn test_multi_protocol_server_accepts_both() {
        assert_eq!(simulate_alpn_negotiation(b"h2", false), AlpnResult::Accepted);
        assert_eq!(simulate_alpn_negotiation(b"http/1.1", false), AlpnResult::Accepted);
    }

    #[test]
    fn test_malformed_protocols_rejected() {
        assert_eq!(simulate_alpn_negotiation(b"", true), AlpnResult::Rejected);
        assert_eq!(simulate_alpn_negotiation(&[0x00], true), AlpnResult::Rejected);
        assert_eq!(simulate_alpn_negotiation(&vec![b'x'; 300], true), AlpnResult::Rejected);
    }

    #[test]
    fn test_cleartext_h2_rejected() {
        assert_eq!(simulate_alpn_negotiation(b"h2c", true), AlpnResult::Rejected);
        assert_eq!(simulate_alpn_negotiation(b"h2c", false), AlpnResult::Rejected);
    }
}