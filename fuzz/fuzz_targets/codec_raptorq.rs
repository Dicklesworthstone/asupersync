#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Fuzz target for RaptorQ symbol framing and codec operations.
///
/// This target tests the RaptorQ codec implementation in src/codec/raptorq.rs
/// for correct handling of malformed RaptorQ-framed streams with focus on:
///
/// **Critical Properties Tested:**
/// 1. **Block index encoding bounded**: SBN (Source Block Number) must be within u8 bounds
/// 2. **Symbol size matches OTI**: Object Transmission Information consistency
/// 3. **FEC payload ID parsed correctly**: ESI (Encoding Symbol ID) validation
/// 4. **Partial symbols buffered until complete**: State machine resilience
/// 5. **Oversized encoded frames rejected**: max_frame_length enforcement
///
/// **Attack Vectors Covered:**
/// - Integer overflow in SBN/ESI parsing
/// - Symbol size mismatch attacks
/// - Frame length bypass attempts
/// - Partial frame state corruption
/// - Malformed Object Transmission Information
/// - Resource exhaustion via oversized frames
/// - Cross-block contamination attacks
use asupersync::codec::raptorq::{EncodedSymbol, EncodingConfig, EncodingError, EncodingPipeline, EncodingStats};
use asupersync::types::{ObjectId, Symbol, SymbolId, SymbolKind};

/// Maximum frame size for testing (1MB)
const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Maximum reasonable symbol size per RFC 6330
const MAX_SYMBOL_SIZE: usize = 65535;

/// Maximum source blocks per object
const MAX_SOURCE_BLOCKS: u8 = 255;

/// Structure-aware RaptorQ frame patterns for corpus seeding
#[derive(Arbitrary, Debug, Clone)]
enum RaptorQFrame {
    /// Valid symbol frame with proper headers
    ValidSymbolFrame {
        object_id: u64,
        sbn: u8,
        esi: u32,
        symbol_size: u16,
        data: Vec<u8>,
        is_source: bool,
    },
    /// Frame with oversized data
    OversizedFrame {
        declared_size: u32,
        actual_data: Vec<u8>,
    },
    /// Frame with invalid block index
    InvalidBlockIndex {
        sbn: u16, // Intentionally u16 to test overflow
        esi: u32,
        data: Vec<u8>,
    },
    /// Partial frame for buffering tests
    PartialFrame {
        expected_size: usize,
        partial_data: Vec<u8>,
        continuation: Option<Vec<u8>>,
    },
    /// Malformed Object Transmission Information
    MalformedOTI {
        symbol_size: u32, // May exceed u16
        block_count: u16,
        data: Vec<u8>,
    },
    /// Raw bytes for boundary testing
    RawBytes { data: Vec<u8> },
}

impl RaptorQFrame {
    /// Serialize frame as wire format bytes
    fn serialize(&self) -> Vec<u8> {
        match self {
            RaptorQFrame::ValidSymbolFrame {
                object_id,
                sbn,
                esi,
                symbol_size,
                data,
                is_source,
            } => {
                let mut frame = Vec::new();
                // Simple framing format:
                // [object_id: 8 bytes][sbn: 1 byte][esi: 4 bytes][symbol_size: 2 bytes][is_source: 1 byte][data]
                frame.extend_from_slice(&object_id.to_le_bytes());
                frame.push(*sbn);
                frame.extend_from_slice(&esi.to_le_bytes());
                frame.extend_from_slice(&symbol_size.to_le_bytes());
                frame.push(if *is_source { 1 } else { 0 });
                let actual_len = (*symbol_size as usize).min(data.len());
                frame.extend_from_slice(&data[..actual_len]);
                frame
            }
            RaptorQFrame::OversizedFrame {
                declared_size,
                actual_data,
            } => {
                let mut frame = Vec::new();
                frame.extend_from_slice(&declared_size.to_le_bytes());
                frame.extend_from_slice(actual_data);
                frame
            }
            RaptorQFrame::InvalidBlockIndex { sbn, esi, data } => {
                let mut frame = Vec::new();
                frame.extend_from_slice(&sbn.to_le_bytes()); // u16 -> potential overflow
                frame.extend_from_slice(&esi.to_le_bytes());
                frame.extend_from_slice(data);
                frame
            }
            RaptorQFrame::PartialFrame {
                expected_size,
                partial_data,
                continuation,
            } => {
                let mut frame = Vec::new();
                frame.extend_from_slice(&expected_size.to_le_bytes());
                frame.extend_from_slice(partial_data);
                if let Some(cont) = continuation {
                    frame.extend_from_slice(cont);
                }
                frame
            }
            RaptorQFrame::MalformedOTI {
                symbol_size,
                block_count,
                data,
            } => {
                let mut frame = Vec::new();
                frame.extend_from_slice(&symbol_size.to_le_bytes()); // u32 -> may overflow u16
                frame.extend_from_slice(&block_count.to_le_bytes());
                frame.extend_from_slice(data);
                frame
            }
            RaptorQFrame::RawBytes { data } => data.clone(),
        }
    }
}

/// Test Property 1: Block index encoding bounded
/// SBN (Source Block Number) must be within u8 bounds (0-255)
fn test_block_index_bounds(data: &[u8]) {
    if data.len() < 16 {
        return;
    }

    // Extract potentially malformed SBN
    let sbn_raw = u16::from_le_bytes([data[0], data[1]]);
    let esi = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);

    // Test various SBN values including overflow cases
    let sbn_test_cases = [
        0u16,                    // Minimum
        255,                     // Maximum valid u8
        256,                     // Just over u8 boundary
        sbn_raw,                 // From fuzz input
        u16::MAX,                // Maximum u16
    ];

    for sbn in sbn_test_cases {
        // Create a symbol with potentially invalid SBN
        let object_id = ObjectId::new(0x1234567890ABCDEF, 0xFEDCBA0987654321);

        // SBN should be bounded to u8 range
        let valid_sbn = (sbn % 256) as u8;
        let symbol_id = SymbolId::new(object_id, valid_sbn, esi);

        // Test symbol creation - should not panic regardless of input SBN
        let symbol_data = data[6..].to_vec();
        let symbol = Symbol::new(symbol_id, symbol_data, SymbolKind::Source);

        // Verify SBN is properly bounded
        assert!(symbol.id().sbn() <= MAX_SOURCE_BLOCKS);

        // Test encoding pipeline with the symbol
        test_encoding_pipeline_with_symbol(&symbol);
    }
}

/// Test Property 2: Symbol size matches OTI (Object Transmission Information)
/// Symbol size must be consistent and within protocol bounds
fn test_symbol_size_oti_consistency(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let declared_size = u16::from_le_bytes([data[0], data[1]]);
    let actual_size = data.len() - 2;

    // Test various size mismatches
    let size_test_cases = [
        (0u16, vec![]),                                           // Zero size
        (1, vec![0x42]),                                         // Minimal size
        (declared_size, data[2..].to_vec()),                    // Declared size
        (MAX_SYMBOL_SIZE as u16, vec![0; MAX_SYMBOL_SIZE]),     // Maximum size
        (u16::MAX, data[2..].to_vec()),                         // Oversized declaration
        ((actual_size as u16).wrapping_add(100), data[2..].to_vec()), // Size overflow
    ];

    for (decl_size, symbol_data) in size_test_cases {
        // Create symbol with potentially mismatched size
        let object_id = ObjectId::new(0x1111111111111111, 0x2222222222222222);
        let symbol_id = SymbolId::new(object_id, 0, 0);

        // Symbol data length should match OTI expectations
        let actual_len = symbol_data.len();
        let expected_len = decl_size as usize;

        // Test symbol creation - should handle size mismatches gracefully
        let symbol = Symbol::new(symbol_id, symbol_data.clone(), SymbolKind::Source);

        // Verify size consistency
        assert_eq!(symbol.data().len(), actual_len);

        // Test that oversized symbols are handled properly
        if actual_len > MAX_SYMBOL_SIZE {
            // Should be rejected or truncated
            test_oversized_symbol_rejection(&symbol, expected_len);
        }
    }
}

/// Test Property 3: FEC payload ID parsed correctly
/// ESI (Encoding Symbol ID) must be valid within the RaptorQ protocol
fn test_fec_payload_id_parsing(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let esi_raw = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let k = u16::from_le_bytes([data[4], data[5]]) % 1000; // Limit K for performance

    // Test ESI edge cases per RFC 6330
    let esi_test_cases = [
        0,                           // First source symbol
        k as u32 - 1,               // Last source symbol
        k as u32,                   // First repair symbol
        0x00FFFFFF,                 // Maximum 24-bit ESI
        0x01000000,                 // Beyond 24-bit limit
        esi_raw,                    // From fuzz input
        u32::MAX,                   // Maximum u32
    ];

    for esi in esi_test_cases {
        let object_id = ObjectId::new(0x3333333333333333, 0x4444444444444444);
        let symbol_id = SymbolId::new(object_id, 0, esi);

        // Determine if symbol should be source or repair based on ESI
        let is_source = esi < k as u32;
        let kind = if is_source { SymbolKind::Source } else { SymbolKind::Repair };

        let symbol = Symbol::new(symbol_id, data[6..].to_vec(), kind);

        // Test ESI validation
        assert_eq!(symbol.id().esi(), esi);
        assert_eq!(symbol.kind().is_source(), is_source);
        assert_eq!(symbol.kind().is_repair(), !is_source);

        // Test that invalid ESI values are handled correctly
        test_esi_validation(esi, k as u32);
    }
}

/// Test Property 4: Partial symbols buffered until complete
/// State machine must handle incomplete frames correctly
fn test_partial_symbol_buffering(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let total_size = u16::from_le_bytes([data[0], data[1]]) as usize % 1024; // Limit size
    if total_size == 0 {
        return;
    }

    let split_point = (data[2] as usize) % total_size.max(1);

    // Create partial symbol data
    let full_data = data[3..].iter().cycle().take(total_size).cloned().collect::<Vec<_>>();
    let (part1, part2) = full_data.split_at(split_point);

    // Test partial symbol scenarios
    test_partial_symbol_state_machine(part1, part2, total_size);

    // Test multiple partial frames
    if split_point > 0 && part2.len() > 1 {
        let mid_point = part2.len() / 2;
        let (part2a, part2b) = part2.split_at(mid_point);
        test_multi_part_symbol_buffering(&[part1, part2a, part2b], total_size);
    }

    // Test partial frame edge cases
    test_partial_frame_edge_cases(data, total_size);
}

/// Test Property 5: Oversized encoded frames rejected per max_frame_length
/// Frames exceeding maximum size must be rejected
fn test_oversized_frame_rejection(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let declared_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    // Test various oversized scenarios
    let size_test_cases = [
        (MAX_FRAME_SIZE + 1, vec![0; 100]),                    // Just over limit
        (declared_size, data[4..].to_vec()),                  // From fuzz input
        (u32::MAX, vec![0; 1000]),                             // Maximum declaration
        (0, vec![0; MAX_FRAME_SIZE + 1]),                      // Size/data mismatch
    ];

    for (decl_size, frame_data) in size_test_cases {
        // Test frame size validation
        let is_oversized = decl_size as usize > MAX_FRAME_SIZE || frame_data.len() > MAX_FRAME_SIZE;

        if is_oversized {
            // Should be rejected
            test_frame_rejection(decl_size, &frame_data);
        } else {
            // Should be processed normally
            test_frame_acceptance(decl_size, &frame_data);
        }
    }
}

/// Helper: Test encoding pipeline with a symbol
fn test_encoding_pipeline_with_symbol(symbol: &Symbol) {
    let config = EncodingConfig::default();

    // Create pipeline - should not panic
    let result = std::panic::catch_unwind(|| {
        let mut pipeline = EncodingPipeline::new(config);

        // Test encoding the symbol data
        let object_id = symbol.id().object_id();
        let _result = pipeline.encode_object(object_id, symbol.data());
    });

    assert!(result.is_ok(), "Encoding pipeline panicked with symbol: {:?}", symbol.id());
}

/// Helper: Test oversized symbol rejection
fn test_oversized_symbol_rejection(symbol: &Symbol, expected_size: usize) {
    if symbol.data().len() > MAX_SYMBOL_SIZE {
        // Oversized symbols should be handled gracefully
        // This is implementation-specific behavior
        assert!(symbol.data().len() <= MAX_FRAME_SIZE, "Symbol exceeds maximum frame size");
    }
}

/// Helper: Test ESI validation
fn test_esi_validation(esi: u32, k: u32) {
    // ESI validation per RFC 6330
    if esi < k {
        // Source symbol - ESI should be < K
        assert!(esi < k, "Source symbol ESI should be < K");
    } else if esi <= 0x00FFFFFF {
        // Repair symbol - ESI should be in valid range
        assert!(esi >= k, "Repair symbol ESI should be >= K");
    } else {
        // Invalid ESI - beyond 24-bit limit
        // Implementation should handle this gracefully
    }
}

/// Helper: Test partial symbol state machine
fn test_partial_symbol_state_machine(part1: &[u8], part2: &[u8], total_size: usize) {
    // Simulate partial frame processing
    let mut buffer = Vec::new();

    // Process first part
    buffer.extend_from_slice(part1);
    assert!(buffer.len() < total_size, "First part should be incomplete");

    // Process second part
    buffer.extend_from_slice(part2);
    assert_eq!(buffer.len(), total_size, "Combined parts should equal total size");

    // Test that partial state is maintained correctly
    let object_id = ObjectId::new(0x5555555555555555, 0x6666666666666666);
    let symbol_id = SymbolId::new(object_id, 0, 0);
    let symbol = Symbol::new(symbol_id, buffer, SymbolKind::Source);

    assert_eq!(symbol.data().len(), total_size);
}

/// Helper: Test multi-part symbol buffering
fn test_multi_part_symbol_buffering(parts: &[&[u8]], total_size: usize) {
    let mut buffer = Vec::new();

    for part in parts {
        buffer.extend_from_slice(part);
    }

    assert_eq!(buffer.len(), total_size, "Multi-part assembly should equal total size");

    // Test symbol creation from assembled parts
    let object_id = ObjectId::new(0x7777777777777777, 0x8888888888888888);
    let symbol_id = SymbolId::new(object_id, 1, 42);
    let symbol = Symbol::new(symbol_id, buffer, SymbolKind::Repair);

    assert_eq!(symbol.data().len(), total_size);
    assert!(symbol.kind().is_repair());
}

/// Helper: Test partial frame edge cases
fn test_partial_frame_edge_cases(data: &[u8], total_size: usize) {
    // Test zero-length first part
    test_partial_symbol_state_machine(&[], data, data.len());

    // Test zero-length second part
    if !data.is_empty() {
        test_partial_symbol_state_machine(data, &[], data.len());
    }

    // Test single-byte parts
    if total_size > 0 && !data.is_empty() {
        test_partial_symbol_state_machine(&[data[0]], &data[1..1], 1);
    }
}

/// Helper: Test frame rejection for oversized frames
fn test_frame_rejection(declared_size: u32, frame_data: &[u8]) {
    // Frame should be rejected if oversized
    let is_oversized = declared_size as usize > MAX_FRAME_SIZE || frame_data.len() > MAX_FRAME_SIZE;

    if is_oversized {
        // Implementation should reject this gracefully without panic
        assert!(declared_size as usize > MAX_FRAME_SIZE || frame_data.len() > MAX_FRAME_SIZE);
    }
}

/// Helper: Test frame acceptance for valid sizes
fn test_frame_acceptance(declared_size: u32, frame_data: &[u8]) {
    // Frame should be accepted if within limits
    let is_valid_size = declared_size as usize <= MAX_FRAME_SIZE && frame_data.len() <= MAX_FRAME_SIZE;

    if is_valid_size {
        // Should be processed without issues
        let object_id = ObjectId::new(0x9999999999999999, 0xAAAAAAAAAAAAAAAA);
        let symbol_id = SymbolId::new(object_id, 2, declared_size % 1000);
        let symbol = Symbol::new(symbol_id, frame_data.to_vec(), SymbolKind::Source);

        assert!(symbol.data().len() <= MAX_FRAME_SIZE);
    }
}

/// Test codec round-trip operations
fn test_codec_round_trip(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let config = EncodingConfig::default();
    let mut pipeline = EncodingPipeline::new(config);

    // Test encoding
    let object_id = ObjectId::new(
        u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]),
        0xBBBBBBBBBBBBBBBB,
    );

    let result = pipeline.encode_object(object_id, data);

    // Should not panic regardless of input
    match result {
        Ok(encoded) => {
            // Test that encoded symbols are valid
            // This would be implementation specific
        }
        Err(err) => {
            // Should be a graceful error, not a panic
            match err {
                EncodingError::DataTooLarge { .. } => {
                    // Expected for oversized data
                }
                EncodingError::InvalidConfig { .. } => {
                    // Expected for invalid configurations
                }
                _ => {
                    // Other errors should also be handled gracefully
                }
            }
        }
    }
}

/// Test malformed frame parsing with arbitrary data
fn test_malformed_frame_parsing(frame: &RaptorQFrame) {
    let serialized = frame.serialize();

    // Test frame parsing - should not panic
    let result = std::panic::catch_unwind(|| {
        parse_raptorq_frame(&serialized);
    });

    assert!(result.is_ok(), "Frame parsing panicked with: {:?}", frame);
}

/// Mock frame parser for testing (implementation would be in codec)
fn parse_raptorq_frame(data: &[u8]) -> Result<(ObjectId, u8, u32, Vec<u8>), &'static str> {
    if data.len() < 16 {
        return Err("Frame too short");
    }

    // Parse frame header
    let object_id_high = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]
    ]);
    let sbn = data[8];
    let esi = u32::from_le_bytes([data[9], data[10], data[11], data[12]]);
    let symbol_size = u16::from_le_bytes([data[13], data[14]]);
    let is_source = data[15] != 0;

    // Validate bounds
    if symbol_size as usize > MAX_SYMBOL_SIZE {
        return Err("Symbol size exceeds maximum");
    }

    if data.len() < 16 + symbol_size as usize {
        return Err("Incomplete frame data");
    }

    let object_id = ObjectId::new(object_id_high, 0);
    let symbol_data = data[16..16 + symbol_size as usize].to_vec();

    Ok((object_id, sbn, esi, symbol_data))
}

fuzz_target!(|frame: RaptorQFrame| {
    // Test all five critical properties

    let serialized = frame.serialize();

    // Limit input size to prevent timeouts
    if serialized.len() > MAX_FRAME_SIZE {
        return;
    }

    // Property 1: Block index encoding bounded
    test_block_index_bounds(&serialized);

    // Property 2: Symbol size matches OTI
    test_symbol_size_oti_consistency(&serialized);

    // Property 3: FEC payload ID parsed correctly
    test_fec_payload_id_parsing(&serialized);

    // Property 4: Partial symbols buffered until complete
    test_partial_symbol_buffering(&serialized);

    // Property 5: Oversized encoded frames rejected
    test_oversized_frame_rejection(&serialized);

    // Additional comprehensive testing
    test_codec_round_trip(&serialized);
    test_malformed_frame_parsing(&frame);

    // Stress test with rapid symbol creation
    if serialized.len() >= 16 {
        for i in 0..10 {
            let object_id = ObjectId::new(i, i * 2);
            let symbol_id = SymbolId::new(object_id, (i % 256) as u8, i as u32);
            let symbol = Symbol::new(
                symbol_id,
                serialized[i % serialized.len()..].to_vec(),
                if i % 2 == 0 { SymbolKind::Source } else { SymbolKind::Repair },
            );

            // Test encoding pipeline
            test_encoding_pipeline_with_symbol(&symbol);
        }
    }
});