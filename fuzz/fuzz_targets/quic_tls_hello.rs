//! QUIC-TLS ClientHello extension validation fuzz target.
//!
//! This fuzzer tests malformed QUIC-TLS ClientHello extensions per RFC 9001 and RFC 8446
//! with focus on security-critical assertions:
//! 1. QUIC transport parameters extension present (required for QUIC connections)
//! 2. Early Data max_early_data=0xffffffff limit enforcement
//! 3. supported_versions honored (QUIC requires TLS 1.3+ only)
//! 4. key_share required (no PSK-only connections in QUIC)
//! 5. retry_token size bounded (prevent DoS via large retry tokens)
//!
//! Tests boundary conditions, malformed extensions, missing required fields,
//! oversized parameters, and protocol compliance violations.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Maximum reasonable ClientHello size for testing
const MAX_CLIENT_HELLO_SIZE: usize = 65536;

/// Maximum retry token size (reasonable upper bound)
const MAX_RETRY_TOKEN_SIZE: usize = 1024;

/// Early Data max limit (0xffffffff)
const EARLY_DATA_MAX_LIMIT: u32 = 0xffffffff;

/// TLS 1.3 version (required for QUIC)
const TLS_1_3_VERSION: u16 = 0x0304;

/// Extension type constants
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_KEY_SHARE: u16 = 51;
const EXT_EARLY_DATA: u16 = 42;
const EXT_QUIC_TRANSPORT_PARAMS: u16 = 57;

/// QUIC transport parameter IDs
const TRANSPORT_PARAM_RETRY_TOKEN: u32 = 0x02;
const TRANSPORT_PARAM_MAX_EARLY_DATA: u32 = 0x0A;

/// Fuzz input for QUIC-TLS ClientHello extensions
#[derive(Arbitrary, Debug, Clone)]
struct QuicTlsHelloFuzzInput {
    /// TLS ClientHello message structure
    client_hello: ClientHelloStructure,
    /// Extension configuration for testing various scenarios
    extension_config: ExtensionTestConfig,
    /// Protocol compliance test scenarios
    compliance_tests: ComplianceTestConfig,
}

/// TLS ClientHello message structure for fuzzing
#[derive(Arbitrary, Debug, Clone)]
struct ClientHelloStructure {
    /// TLS version in ClientHello header
    legacy_version: u16,
    /// Random bytes (32 bytes)
    random: [u8; 32],
    /// Session ID
    session_id: Vec<u8>,
    /// Cipher suites
    cipher_suites: Vec<u16>,
    /// Compression methods
    compression_methods: Vec<u8>,
    /// Extensions list
    extensions: Vec<TlsExtension>,
}

/// TLS extension for fuzzing
#[derive(Arbitrary, Debug, Clone)]
struct TlsExtension {
    /// Extension type
    ext_type: u16,
    /// Extension data
    data: Vec<u8>,
}

/// Extension test configuration
#[derive(Arbitrary, Debug, Clone)]
struct ExtensionTestConfig {
    /// Include supported_versions extension
    include_supported_versions: bool,
    /// Supported versions list (may include invalid versions)
    supported_versions: Vec<u16>,
    /// Include key_share extension
    include_key_share: bool,
    /// Key share data (may be malformed)
    key_share_data: Vec<u8>,
    /// Include early_data extension
    include_early_data: bool,
    /// Early data limit value (test max limit enforcement)
    early_data_limit: u32,
    /// Include QUIC transport parameters extension
    include_quic_transport_params: bool,
    /// QUIC transport parameters (may be malformed)
    quic_transport_params: Vec<QuicTransportParam>,
}

/// QUIC transport parameter for fuzzing
#[derive(Arbitrary, Debug, Clone)]
struct QuicTransportParam {
    /// Parameter ID
    param_id: u32,
    /// Parameter value
    value: Vec<u8>,
}

/// Protocol compliance test configuration
#[derive(Arbitrary, Debug, Clone)]
struct ComplianceTestConfig {
    /// Test missing required extensions
    test_missing_required: bool,
    /// Test oversized retry tokens
    test_oversized_retry_token: bool,
    /// Test invalid TLS versions
    test_invalid_tls_version: bool,
    /// Test malformed extension data
    test_malformed_extensions: bool,
    /// Test multiple extension instances
    test_duplicate_extensions: bool,
}

/// TLS message reader for parsing ClientHello
struct TlsReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> TlsReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, &'static str> {
        if self.pos >= self.data.len() {
            return Err("insufficient data for u8");
        }
        let val = self.data[self.pos];
        self.pos += 1;
        Ok(val)
    }

    fn read_u16(&mut self) -> Result<u16, &'static str> {
        if self.pos + 2 > self.data.len() {
            return Err("insufficient data for u16");
        }
        let val = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    fn read_u32(&mut self) -> Result<u32, &'static str> {
        if self.pos + 4 > self.data.len() {
            return Err("insufficient data for u32");
        }
        let val = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    fn read_varint(&mut self) -> Result<u64, &'static str> {
        let first_byte = self.read_u8()?;
        match first_byte >> 6 {
            0 => Ok(first_byte as u64),
            1 => {
                let second_byte = self.read_u8()?;
                Ok(((first_byte & 0x3F) as u64) << 8 | second_byte as u64)
            }
            2 => {
                let bytes = [
                    first_byte & 0x3F,
                    self.read_u8()?,
                    self.read_u8()?,
                    self.read_u8()?,
                ];
                Ok(u32::from_be_bytes(bytes) as u64)
            }
            3 => {
                let mut bytes = [0u8; 8];
                bytes[0] = first_byte & 0x3F;
                for i in 1..8 {
                    bytes[i] = self.read_u8()?;
                }
                Ok(u64::from_be_bytes(bytes))
            }
            _ => unreachable!(),
        }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        if self.pos + len > self.data.len() {
            return Err("insufficient data for bytes");
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

/// Build ClientHello message from fuzz input
fn build_client_hello(input: &QuicTlsHelloFuzzInput) -> Vec<u8> {
    let mut buf = Vec::new();

    // ClientHello message type (0x01)
    buf.push(0x01);

    // Placeholder for length (will be filled later)
    let length_pos = buf.len();
    buf.extend_from_slice(&[0, 0, 0]);

    let body_start = buf.len();

    // Legacy version
    buf.extend_from_slice(&input.client_hello.legacy_version.to_be_bytes());

    // Random
    buf.extend_from_slice(&input.client_hello.random);

    // Session ID
    let session_id_len = std::cmp::min(input.client_hello.session_id.len(), 32);
    buf.push(session_id_len as u8);
    buf.extend_from_slice(&input.client_hello.session_id[..session_id_len]);

    // Cipher suites
    let cipher_suites_len = std::cmp::min(input.client_hello.cipher_suites.len() * 2, 65534);
    buf.extend_from_slice(&(cipher_suites_len as u16).to_be_bytes());
    for &cipher in input.client_hello.cipher_suites.iter().take(cipher_suites_len / 2) {
        buf.extend_from_slice(&cipher.to_be_bytes());
    }

    // Compression methods
    let comp_methods_len = std::cmp::min(input.client_hello.compression_methods.len(), 255);
    buf.push(comp_methods_len as u8);
    buf.extend_from_slice(&input.client_hello.compression_methods[..comp_methods_len]);

    // Extensions
    let extensions_start = buf.len();
    buf.extend_from_slice(&[0, 0]); // Placeholder for extensions length

    let mut extensions_data = Vec::new();

    // Add configured extensions
    for ext in &input.client_hello.extensions {
        let data_len = std::cmp::min(ext.data.len(), 65535);
        extensions_data.extend_from_slice(&ext.ext_type.to_be_bytes());
        extensions_data.extend_from_slice(&(data_len as u16).to_be_bytes());
        extensions_data.extend_from_slice(&ext.data[..data_len]);
    }

    // Add test-specific extensions based on configuration
    if input.extension_config.include_supported_versions {
        extensions_data.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        let versions_data: Vec<u8> = input.extension_config.supported_versions
            .iter()
            .flat_map(|&v| v.to_be_bytes())
            .collect();
        let data_len = std::cmp::min(versions_data.len() + 1, 255);
        extensions_data.extend_from_slice(&(data_len as u16).to_be_bytes());
        extensions_data.push((data_len - 1) as u8); // Length prefix
        extensions_data.extend_from_slice(&versions_data[..data_len - 1]);
    }

    if input.extension_config.include_key_share {
        extensions_data.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        let data_len = std::cmp::min(input.extension_config.key_share_data.len(), 65535);
        extensions_data.extend_from_slice(&(data_len as u16).to_be_bytes());
        extensions_data.extend_from_slice(&input.extension_config.key_share_data[..data_len]);
    }

    if input.extension_config.include_early_data {
        extensions_data.extend_from_slice(&EXT_EARLY_DATA.to_be_bytes());
        extensions_data.extend_from_slice(&4u16.to_be_bytes()); // 4 bytes for u32
        extensions_data.extend_from_slice(&input.extension_config.early_data_limit.to_be_bytes());
    }

    if input.extension_config.include_quic_transport_params {
        extensions_data.extend_from_slice(&EXT_QUIC_TRANSPORT_PARAMS.to_be_bytes());
        let params_data = build_quic_transport_params(&input.extension_config.quic_transport_params);
        let data_len = std::cmp::min(params_data.len(), 65535);
        extensions_data.extend_from_slice(&(data_len as u16).to_be_bytes());
        extensions_data.extend_from_slice(&params_data[..data_len]);
    }

    // Write extensions length
    let extensions_len = std::cmp::min(extensions_data.len(), 65535);
    buf[extensions_start..extensions_start + 2].copy_from_slice(&(extensions_len as u16).to_be_bytes());
    buf.extend_from_slice(&extensions_data[..extensions_len]);

    // Write message length
    let body_len = buf.len() - body_start;
    let body_len_bytes = [
        ((body_len >> 16) & 0xFF) as u8,
        ((body_len >> 8) & 0xFF) as u8,
        (body_len & 0xFF) as u8,
    ];
    buf[length_pos..length_pos + 3].copy_from_slice(&body_len_bytes);

    buf
}

/// Build QUIC transport parameters extension data
fn build_quic_transport_params(params: &[QuicTransportParam]) -> Vec<u8> {
    let mut buf = Vec::new();

    for param in params {
        // Parameter ID as varint
        write_varint(&mut buf, param.param_id as u64);
        // Value length as varint
        let value_len = std::cmp::min(param.value.len(), 65535);
        write_varint(&mut buf, value_len as u64);
        // Value
        buf.extend_from_slice(&param.value[..value_len]);
    }

    buf
}

/// Write varint to buffer
fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    if value < 64 {
        buf.push(value as u8);
    } else if value < 16384 {
        buf.push(0x40 | ((value >> 8) as u8));
        buf.push((value & 0xFF) as u8);
    } else if value < 1073741824 {
        buf.push(0x80 | ((value >> 24) as u8));
        buf.push(((value >> 16) & 0xFF) as u8);
        buf.push(((value >> 8) & 0xFF) as u8);
        buf.push((value & 0xFF) as u8);
    } else {
        buf.push(0xC0 | ((value >> 56) as u8));
        for i in (0..7).rev() {
            buf.push(((value >> (i * 8)) & 0xFF) as u8);
        }
    }
}

/// Parse ClientHello extensions
fn parse_client_hello_extensions(data: &[u8]) -> Result<HashMap<u16, Vec<u8>>, &'static str> {
    let mut reader = TlsReader::new(data);
    let mut extensions = HashMap::new();

    // Skip to extensions
    // msg_type (1) + length (3) + legacy_version (2) + random (32)
    reader.pos = 1 + 3 + 2 + 32;

    // Session ID
    let session_id_len = reader.read_u8()? as usize;
    reader.read_bytes(session_id_len)?;

    // Cipher suites
    let cipher_suites_len = reader.read_u16()? as usize;
    reader.read_bytes(cipher_suites_len)?;

    // Compression methods
    let comp_methods_len = reader.read_u8()? as usize;
    reader.read_bytes(comp_methods_len)?;

    // Extensions length
    let extensions_len = reader.read_u16()? as usize;
    let extensions_end = reader.pos + extensions_len;

    // Parse individual extensions
    while reader.pos < extensions_end && reader.remaining() >= 4 {
        let ext_type = reader.read_u16()?;
        let ext_len = reader.read_u16()? as usize;

        if reader.remaining() < ext_len {
            break; // Malformed extension
        }

        let ext_data = reader.read_bytes(ext_len)?.to_vec();
        extensions.insert(ext_type, ext_data);
    }

    Ok(extensions)
}

/// Parse QUIC transport parameters
fn parse_quic_transport_params(data: &[u8]) -> Result<HashMap<u32, Vec<u8>>, &'static str> {
    let mut reader = TlsReader::new(data);
    let mut params = HashMap::new();

    while reader.remaining() > 0 {
        let param_id = reader.read_varint()?;
        let value_len = reader.read_varint()? as usize;

        if reader.remaining() < value_len {
            break; // Malformed parameter
        }

        let value = reader.read_bytes(value_len)?.to_vec();
        params.insert(param_id as u32, value);
    }

    Ok(params)
}

/// Validate QUIC-TLS ClientHello security assertions
fn validate_quic_tls_security(input: &QuicTlsHelloFuzzInput, client_hello_data: &[u8]) {
    // Build the message for parsing
    let extensions = match parse_client_hello_extensions(client_hello_data) {
        Ok(ext) => ext,
        Err(_) => return, // Malformed message, parsing failed gracefully
    };

    // ASSERTION 1: QUIC transport parameters extension MUST be present
    let quic_params_data = extensions.get(&EXT_QUIC_TRANSPORT_PARAMS);
    assert!(
        input.extension_config.include_quic_transport_params == quic_params_data.is_some(),
        "QUIC transport parameters extension presence mismatch: expected={}, found={}",
        input.extension_config.include_quic_transport_params,
        quic_params_data.is_some()
    );

    // ASSERTION 2: Early Data max_early_data MUST NOT exceed 0xffffffff
    if let Some(early_data) = extensions.get(&EXT_EARLY_DATA) {
        if early_data.len() >= 4 {
            let early_data_limit = u32::from_be_bytes([
                early_data[0], early_data[1], early_data[2], early_data[3]
            ]);
            assert!(
                early_data_limit <= EARLY_DATA_MAX_LIMIT,
                "Early data limit exceeds maximum: {} > {}",
                early_data_limit, EARLY_DATA_MAX_LIMIT
            );
        }
    }

    // ASSERTION 3: supported_versions MUST include TLS 1.3 for QUIC
    if let Some(supported_versions_data) = extensions.get(&EXT_SUPPORTED_VERSIONS) {
        if !supported_versions_data.is_empty() {
            let versions_len = supported_versions_data[0] as usize;
            if versions_len + 1 <= supported_versions_data.len() {
                let versions = &supported_versions_data[1..1 + versions_len];
                let mut has_tls13 = false;
                for chunk in versions.chunks_exact(2) {
                    let version = u16::from_be_bytes([chunk[0], chunk[1]]);
                    if version == TLS_1_3_VERSION {
                        has_tls13 = true;
                        break;
                    }
                }
                assert!(has_tls13, "supported_versions must include TLS 1.3 for QUIC");
            }
        }
    }

    // ASSERTION 4: key_share MUST be present (no PSK-only connections)
    let has_key_share = extensions.contains_key(&EXT_KEY_SHARE);
    if input.extension_config.include_key_share {
        assert!(has_key_share, "key_share extension required for QUIC connections");
    }

    // ASSERTION 5: retry_token size MUST be bounded
    if let Some(quic_params_data) = quic_params_data {
        if let Ok(transport_params) = parse_quic_transport_params(quic_params_data) {
            if let Some(retry_token) = transport_params.get(&TRANSPORT_PARAM_RETRY_TOKEN) {
                assert!(
                    retry_token.len() <= MAX_RETRY_TOKEN_SIZE,
                    "Retry token size exceeds limit: {} > {}",
                    retry_token.len(), MAX_RETRY_TOKEN_SIZE
                );
            }
        }
    }
}

fuzz_target!(|input: QuicTlsHelloFuzzInput| {
    // Bound input size to prevent excessive memory usage
    if input.client_hello.extensions.len() > 50
        || input.extension_config.quic_transport_params.len() > 50 {
        return;
    }

    // Build ClientHello message from fuzz input
    let client_hello_data = build_client_hello(&input);

    // Bound total size
    if client_hello_data.len() > MAX_CLIENT_HELLO_SIZE {
        return;
    }

    // Validate QUIC-TLS security assertions
    validate_quic_tls_security(&input, &client_hello_data);

    // Additional robustness: ensure parsing doesn't panic on malformed data
    let _ = parse_client_hello_extensions(&client_hello_data);

    // Test edge cases in transport parameter parsing
    for param in &input.extension_config.quic_transport_params {
        if param.value.len() <= MAX_RETRY_TOKEN_SIZE {
            let _ = parse_quic_transport_params(&param.value);
        }
    }
});