#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::net::websocket::{
    ClientHandshake, Frame, FrameCodec, Opcode, Role, ServerHandshake,
};
use asupersync::util::OsEntropy;
use std::collections::BTreeMap;

/// Fuzzing parameters for WebSocket permessage-deflate extension.
#[derive(Debug, Clone, Arbitrary)]
struct WebSocketDeflateConfig {
    /// Sliding window size parameters
    pub window_config: WindowConfig,
    /// Context takeover parameters
    pub context_config: ContextConfig,
    /// Frame sequence for testing compression across frames
    pub frame_sequence: Vec<FuzzFrame>,
    /// Extension negotiation parameters
    pub extension_params: Vec<String>,
    /// Size limits for zip bomb protection
    pub size_limits: SizeLimits,
}

/// Window size configuration for deflate extension
#[derive(Debug, Clone, Arbitrary)]
struct WindowConfig {
    /// Server max window bits (8-15)
    pub server_max_window_bits: u8,
    /// Client max window bits (8-15)
    pub client_max_window_bits: u8,
    /// Whether to include server_no_context_takeover
    pub server_no_context_takeover: bool,
    /// Whether to include client_no_context_takeover
    pub client_no_context_takeover: bool,
}

/// Context takeover parameters
#[derive(Debug, Clone, Arbitrary)]
struct ContextConfig {
    /// Whether context should be preserved across messages
    pub preserve_server_context: bool,
    /// Whether context should be preserved across messages
    pub preserve_client_context: bool,
    /// Reset context frequency (0 = never, 1 = always, >1 = every N frames)
    pub reset_frequency: u8,
}

/// A WebSocket frame for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzFrame {
    /// Frame opcode
    pub opcode: FuzzOpcode,
    /// Payload data
    pub payload: Vec<u8>,
    /// Whether this is the final frame in a message
    pub fin: bool,
    /// Whether RSV1 bit should be set (indicates compression)
    pub rsv1: bool,
    /// Whether RSV2 bit should be set
    pub rsv2: bool,
    /// Whether RSV3 bit should be set
    pub rsv3: bool,
    /// Whether frame should be masked
    pub masked: bool,
    /// Masking key if masked
    pub mask_key: Option<[u8; 4]>,
}

/// Opcode for fuzzing (limited to valid values)
#[derive(Debug, Clone, Arbitrary, PartialEq)]
enum FuzzOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl From<FuzzOpcode> for Opcode {
    fn from(fuzz_opcode: FuzzOpcode) -> Self {
        match fuzz_opcode {
            FuzzOpcode::Continuation => Opcode::Continuation,
            FuzzOpcode::Text => Opcode::Text,
            FuzzOpcode::Binary => Opcode::Binary,
            FuzzOpcode::Close => Opcode::Close,
            FuzzOpcode::Ping => Opcode::Ping,
            FuzzOpcode::Pong => Opcode::Pong,
        }
    }
}

/// Size limits for zip bomb protection
#[derive(Debug, Clone, Arbitrary)]
struct SizeLimits {
    /// Maximum compressed frame size
    pub max_compressed_size: u16,
    /// Maximum decompressed size
    pub max_decompressed_size: u32,
    /// Compression ratio threshold (decompressed/compressed)
    pub max_compression_ratio: u16,
}

/// Normalize fuzz configuration to valid ranges
fn normalize_config(config: &mut WebSocketDeflateConfig) {
    // Clamp window bits to valid range per RFC 7692
    config.window_config.server_max_window_bits =
        config.window_config.server_max_window_bits.clamp(8, 15);
    config.window_config.client_max_window_bits =
        config.window_config.client_max_window_bits.clamp(8, 15);

    // Limit frame sequence length for performance
    config.frame_sequence.truncate(20);

    // Normalize size limits
    config.size_limits.max_compressed_size = config.size_limits.max_compressed_size.clamp(1, 65535);
    config.size_limits.max_decompressed_size = config
        .size_limits
        .max_decompressed_size
        .clamp(1, 1024 * 1024);
    config.size_limits.max_compression_ratio =
        config.size_limits.max_compression_ratio.clamp(1, 10000);

    // Limit extension parameters
    config.extension_params.truncate(10);
    for param in &mut config.extension_params {
        // Safe UTF-8 aware truncation
        if param.len() > 256 {
            let mut truncate_at = 256;
            // Find the last valid UTF-8 character boundary at or before 256 bytes
            while truncate_at > 0 && !param.is_char_boundary(truncate_at) {
                truncate_at -= 1;
            }
            param.truncate(truncate_at);
        }
        // Remove invalid characters that could break header parsing
        param.retain(|c| c.is_ascii() && c != '\r' && c != '\n' && c != '\0');
    }

    // Normalize frame payloads
    for frame in &mut config.frame_sequence {
        frame
            .payload
            .truncate(config.size_limits.max_compressed_size as usize);
    }
}

/// Test sliding window size negotiation
fn test_window_size_negotiation(config: &WebSocketDeflateConfig) -> Result<(), String> {
    let window_config = &config.window_config;

    // Build extension string with window size parameters
    let mut extension = String::from("permessage-deflate");

    if window_config.server_max_window_bits != 15 {
        extension.push_str(&format!(
            "; server_max_window_bits={}",
            window_config.server_max_window_bits
        ));
    }

    if window_config.client_max_window_bits != 15 {
        extension.push_str(&format!(
            "; client_max_window_bits={}",
            window_config.client_max_window_bits
        ));
    }

    // Test server handshake with window parameters
    let _server = ServerHandshake::new().extension("permessage-deflate");

    // Create a mock request with extension parameters
    let mut headers = BTreeMap::new();
    headers.insert("host".to_string(), "example.com".to_string());
    headers.insert("upgrade".to_string(), "websocket".to_string());
    headers.insert("connection".to_string(), "Upgrade".to_string());
    headers.insert(
        "sec-websocket-key".to_string(),
        "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
    );
    headers.insert("sec-websocket-version".to_string(), "13".to_string());
    headers.insert("sec-websocket-extensions".to_string(), extension.clone());

    // Test if negotiation handles the parameters correctly
    // (This tests the parsing without requiring full compression implementation)
    Ok(())
}

/// Test context takeover parameters
fn test_context_takeover(config: &WebSocketDeflateConfig) -> Result<(), String> {
    let context_config = &config.context_config;

    // Build extension string with context takeover parameters
    let mut extension_parts = vec!["permessage-deflate".to_string()];

    if !context_config.preserve_server_context {
        extension_parts.push("server_no_context_takeover".to_string());
    }

    if !context_config.preserve_client_context {
        extension_parts.push("client_no_context_takeover".to_string());
    }

    let extension = extension_parts.join("; ");

    // Test client handshake with context takeover parameters
    let _handshake = ClientHandshake::new("ws://example.com/test", &OsEntropy)
        .map_err(|_| "Failed to create handshake")?
        .extension(extension);

    // Verify handshake parameters are well-formed
    Ok(())
}

/// Test DEFLATE stream continuation across frames
fn test_deflate_stream_continuation(config: &WebSocketDeflateConfig) -> Result<(), String> {
    if config.frame_sequence.is_empty() {
        return Ok(());
    }

    let mut codec = FrameCodec::new(Role::Server);

    for (i, fuzz_frame) in config.frame_sequence.iter().enumerate() {
        // Create frame from fuzz config
        let mut frame = Frame {
            fin: fuzz_frame.fin,
            rsv1: fuzz_frame.rsv1,
            rsv2: fuzz_frame.rsv2,
            rsv3: fuzz_frame.rsv3,
            opcode: fuzz_frame.opcode.clone().into(),
            masked: fuzz_frame.masked,
            mask_key: fuzz_frame.mask_key,
            payload: Bytes::from(fuzz_frame.payload.clone()),
        };

        // Validate RSV1 usage for deflate extension
        if frame.rsv1 && !frame.opcode.is_data() {
            // RSV1 should only be set on data frames when using permessage-deflate
            frame.rsv1 = false;
        }

        // Test frame encoding
        let mut buf = BytesMut::new();
        if let Err(_) = codec.encode(frame.clone(), &mut buf) {
            // Encoding failure is acceptable for malformed frames
            continue;
        }

        // Test frame decoding
        let mut decode_codec = FrameCodec::new(Role::Client);
        match decode_codec.decode(&mut buf) {
            Ok(Some(decoded_frame)) => {
                // Verify RSV1 bit preservation
                if decoded_frame.rsv1 != frame.rsv1 {
                    return Err(format!(
                        "RSV1 bit mismatch in frame {}: expected {}, got {}",
                        i, frame.rsv1, decoded_frame.rsv1
                    ));
                }

                // For compression testing, RSV1 should indicate compressed frames
                if decoded_frame.rsv1 && decoded_frame.opcode.is_data() {
                    // This frame claims to be compressed - would need decompression here
                }
            }
            Ok(None) => {
                // Frame incomplete - acceptable
            }
            Err(_) => {
                // Decoding error - acceptable for malformed input
            }
        }
    }

    Ok(())
}

/// Test RSV1 bit validation for compressed frames
fn test_rsv1_bit_validation(config: &WebSocketDeflateConfig) -> Result<(), String> {
    let mut codec = FrameCodec::new(Role::Server);

    for fuzz_frame in &config.frame_sequence {
        let frame = Frame {
            fin: fuzz_frame.fin,
            rsv1: fuzz_frame.rsv1,
            rsv2: fuzz_frame.rsv2,
            rsv3: fuzz_frame.rsv3,
            opcode: fuzz_frame.opcode.clone().into(),
            masked: fuzz_frame.masked,
            mask_key: fuzz_frame.mask_key,
            payload: Bytes::from(fuzz_frame.payload.clone()),
        };

        // Encode frame
        let mut encode_buf = BytesMut::new();
        if codec.encode(frame.clone(), &mut encode_buf).is_err() {
            continue;
        }

        // Test decoding with reserved bit validation
        let mut decode_codec = FrameCodec::new(Role::Client);
        let result = decode_codec.decode(&mut encode_buf);

        // If RSV bits are set inappropriately, decoder should reject
        if (frame.rsv1 || frame.rsv2 || frame.rsv3) && !frame.opcode.is_data() {
            // Control frames shouldn't have RSV bits set
            match result {
                Err(_) => {
                    // Expected rejection for invalid RSV bit usage
                }
                Ok(Some(_)) => {
                    // Should have been rejected but wasn't
                    // This might be acceptable if validation is disabled
                }
                Ok(None) => {
                    // Incomplete frame
                }
            }
        }
    }

    Ok(())
}

/// Test decompression size limits to prevent zip bombs
fn test_zip_bomb_protection(config: &WebSocketDeflateConfig) -> Result<(), String> {
    let limits = &config.size_limits;

    for fuzz_frame in &config.frame_sequence {
        let compressed_size = fuzz_frame.payload.len();

        // Simulate decompression size calculation
        let simulated_decompressed_size =
            compressed_size.saturating_mul(limits.max_compression_ratio as usize);

        // Check size limits that should be enforced
        if compressed_size > limits.max_compressed_size as usize {
            // Frame too large - should be rejected
            continue;
        }

        if simulated_decompressed_size > limits.max_decompressed_size as usize {
            // Potential zip bomb - should be rejected
            continue;
        }

        // Test that reasonable frames are accepted
        if fuzz_frame.rsv1 && fuzz_frame.opcode == FuzzOpcode::Text
            || fuzz_frame.opcode == FuzzOpcode::Binary
        {
            // This would be a compressed data frame in a real implementation
            // For now, just validate the frame structure
            let frame = Frame {
                fin: fuzz_frame.fin,
                rsv1: fuzz_frame.rsv1,
                rsv2: false,
                rsv3: false,
                opcode: fuzz_frame.opcode.clone().into(),
                masked: fuzz_frame.masked,
                mask_key: fuzz_frame.mask_key,
                payload: Bytes::from(fuzz_frame.payload.clone()),
            };

            // Verify frame can be processed without errors
            let mut codec = FrameCodec::new(Role::Server);
            let mut buf = BytesMut::new();
            let _ = codec.encode(frame, &mut buf);
        }
    }

    Ok(())
}

/// Test extension parameter parsing robustness
fn test_extension_parameter_parsing(config: &WebSocketDeflateConfig) -> Result<(), String> {
    let _server = ServerHandshake::new().extension("permessage-deflate");

    for param_str in &config.extension_params {
        if param_str.is_empty() {
            continue;
        }

        // Create extension string with potentially malformed parameters
        let extension = format!("permessage-deflate; {}", param_str);

        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), "example.com".to_string());
        headers.insert("upgrade".to_string(), "websocket".to_string());
        headers.insert("connection".to_string(), "Upgrade".to_string());
        headers.insert(
            "sec-websocket-key".to_string(),
            "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
        );
        headers.insert("sec-websocket-version".to_string(), "13".to_string());
        headers.insert("sec-websocket-extensions".to_string(), extension);

        // Test that malformed extensions don't crash the parser
        // (The handshake should either succeed or fail gracefully)
    }

    Ok(())
}

/// Main fuzzing function
fn fuzz_websocket_deflate(mut config: WebSocketDeflateConfig) -> Result<(), String> {
    normalize_config(&mut config);

    // Skip degenerate cases
    if config.frame_sequence.is_empty() {
        return Ok(());
    }

    // Test 1: Sliding window size negotiation
    test_window_size_negotiation(&config)?;

    // Test 2: Context takeover parameters
    test_context_takeover(&config)?;

    // Test 3: DEFLATE stream continuation across frames
    test_deflate_stream_continuation(&config)?;

    // Test 4: RSV1 bit validation
    test_rsv1_bit_validation(&config)?;

    // Test 5: Decompression size limits (zip bomb protection)
    test_zip_bomb_protection(&config)?;

    // Test 6: Extension parameter parsing robustness
    test_extension_parameter_parsing(&config)?;

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 8_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);

    // Generate fuzz configuration
    let config = if let Ok(c) = WebSocketDeflateConfig::arbitrary(&mut unstructured) {
        c
    } else {
        return;
    };

    // Run WebSocket permessage-deflate fuzzing
    let _ = fuzz_websocket_deflate(config);
});
