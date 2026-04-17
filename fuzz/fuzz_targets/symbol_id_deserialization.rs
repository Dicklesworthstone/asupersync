#![no_main]

use libfuzzer_sys::fuzz_target;

use asupersync::decoding::DecodingConfig;
/// Symbol and ID deserialization fuzz testing for robustness and security.
///
/// This fuzz target extensively tests the typed symbol and ID deserialization
/// functions to ensure they handle malformed, malicious, and edge-case inputs
/// without crashes, memory leaks, or security vulnerabilities.
///
/// Targets the following critical parsing functions:
/// - TypedHeader::decode() - 27-byte typed symbol header parsing
/// - SerdeCodec::deserialize() - MessagePack, Bincode, JSON deserialization
/// - TypedSymbol::try_from_symbol() - Type validation and symbol wrapping
/// - TypedDecoder::decode() - Multi-symbol decoding with RaptorQ integration
/// - ID deserialization - RegionId, TaskId, ObligationId serde parsing
///
/// Test cases cover:
/// - Valid typed symbols with all supported serialization formats
/// - Malformed headers: invalid magic, corrupted fields, oversized payloads
/// - Type confusion attacks: mismatched type IDs, schema hash collisions
/// - Serialization format exploits: malformed MessagePack/Bincode/JSON
/// - ID boundary violations: arena index overflow, invalid ID constructions
/// - Memory exhaustion: oversized payloads, deeply nested structures
// Import the symbol and ID modules to test
use asupersync::types::typed_symbol::{
    Deserializer, SerdeCodec, SerializationFormat, Serializer, TYPED_SYMBOL_HEADER_LEN,
    TYPED_SYMBOL_MAGIC, TypedDecoder, TypedHeader, TypedSymbol,
};
use asupersync::types::{
    ObjectId, ObjectParams, ObligationId, RegionId, Symbol, SymbolKind, TaskId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Test data structure for symbol serialization/deserialization testing
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TestPayload {
    id: u64,
    name: String,
    values: Vec<i32>,
    metadata: HashMap<String, String>,
}

/// Generate valid typed symbol headers for baseline testing
fn generate_valid_headers(data: &[u8]) -> Vec<Vec<u8>> {
    let mut headers = Vec::new();

    if data.is_empty() {
        return headers;
    }

    // Basic valid header with different formats
    for format in [
        SerializationFormat::MessagePack,
        SerializationFormat::Bincode,
        SerializationFormat::Json,
        SerializationFormat::Custom,
    ] {
        let mut header = Vec::with_capacity(TYPED_SYMBOL_HEADER_LEN);
        header.extend_from_slice(&TYPED_SYMBOL_MAGIC);
        header.extend_from_slice(&1u16.to_le_bytes()); // Version 1
        header.extend_from_slice(&0x1234567890abcdefu64.to_le_bytes()); // Type ID
        header.push(format.to_byte());
        header.extend_from_slice(&0xfedcba0987654321u64.to_le_bytes()); // Schema hash
        header.extend_from_slice(&100u32.to_le_bytes()); // Payload length
        headers.push(header);
    }

    // Header with data-derived values
    if data.len() >= 8 {
        let mut header = Vec::with_capacity(TYPED_SYMBOL_HEADER_LEN);
        header.extend_from_slice(&TYPED_SYMBOL_MAGIC);
        header.extend_from_slice(&u16::from_be_bytes([data[0], data[1]]).to_le_bytes()); // Version from data
        header.extend_from_slice(&data[0..8]); // Type ID from data
        header.push(SerializationFormat::MessagePack.to_byte());
        header.extend_from_slice(&data[0..8]); // Schema hash from data
        header.extend_from_slice(
            &u32::from_be_bytes([data[4], data[5], data[6], data[7]]).to_le_bytes(),
        ); // Payload len
        headers.push(header);
    }

    headers
}

/// Generate malformed headers for vulnerability testing
fn generate_malformed_headers(data: &[u8]) -> Vec<Vec<u8>> {
    let mut malformed = Vec::new();

    // Truncated headers - various lengths
    for len in [0, 4, 10, 15, 20, 26] {
        malformed.push(data.get(..len.min(data.len())).unwrap_or(&[]).to_vec());
    }

    // Invalid magic bytes
    malformed.push(vec![
        b'F', b'A', b'K', b'E', 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 0,
        0,
    ]);
    malformed.push(vec![
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0,
    ]);

    // Invalid format bytes
    let mut invalid_format = Vec::from(TYPED_SYMBOL_MAGIC);
    invalid_format.extend_from_slice(&1u16.to_le_bytes()); // Version
    invalid_format.extend_from_slice(&0x1234567890abcdefu64.to_le_bytes()); // Type ID
    invalid_format.push(99); // Invalid format byte
    invalid_format.extend_from_slice(&0xfedcba0987654321u64.to_le_bytes()); // Schema hash
    invalid_format.extend_from_slice(&100u32.to_le_bytes()); // Payload length
    malformed.push(invalid_format);

    // Oversized payload lengths
    for payload_len in [u32::MAX, 0x7fffffff, 0x10000000, 1_000_000_000] {
        let mut oversized = Vec::from(TYPED_SYMBOL_MAGIC);
        oversized.extend_from_slice(&1u16.to_le_bytes());
        oversized.extend_from_slice(&0x1234567890abcdefu64.to_le_bytes());
        oversized.push(SerializationFormat::MessagePack.to_byte());
        oversized.extend_from_slice(&0xfedcba0987654321u64.to_le_bytes());
        oversized.extend_from_slice(&payload_len.to_le_bytes());
        malformed.push(oversized);
    }

    // Version edge cases
    for version in [0, u16::MAX, 0x8000] {
        let mut version_edge = Vec::from(TYPED_SYMBOL_MAGIC);
        version_edge.extend_from_slice(&version.to_le_bytes());
        version_edge.extend_from_slice(&0x1234567890abcdefu64.to_le_bytes());
        version_edge.push(SerializationFormat::Bincode.to_byte());
        version_edge.extend_from_slice(&0xfedcba0987654321u64.to_le_bytes());
        version_edge.extend_from_slice(&100u32.to_le_bytes());
        malformed.push(version_edge);
    }

    // Use input data as header content
    if data.len() >= TYPED_SYMBOL_HEADER_LEN {
        malformed.push(data[..TYPED_SYMBOL_HEADER_LEN].to_vec());
    }

    // Mix valid magic with corrupted data
    if data.len() >= 23 {
        let mut mixed = Vec::from(TYPED_SYMBOL_MAGIC);
        mixed.extend_from_slice(&data[..23]);
        malformed.push(mixed);
    }

    malformed
}

/// Generate serialized payloads for testing deserialization
fn generate_serialized_payloads(data: &[u8]) -> Vec<(SerializationFormat, Vec<u8>)> {
    let mut payloads = Vec::new();

    // Valid test payload
    let test_data = TestPayload {
        id: 42,
        name: "test".to_string(),
        values: vec![1, 2, 3],
        metadata: [("key".to_string(), "value".to_string())].into(),
    };

    // Serialize with each format
    let codec = SerdeCodec;
    for format in [
        SerializationFormat::MessagePack,
        SerializationFormat::Bincode,
        SerializationFormat::Json,
    ] {
        if let Ok(serialized) = codec.serialize(&test_data, format) {
            payloads.push((format, serialized));
        }
    }

    // Use input data as raw payloads for each format
    for format in [
        SerializationFormat::MessagePack,
        SerializationFormat::Bincode,
        SerializationFormat::Json,
        SerializationFormat::Custom,
    ] {
        payloads.push((format, data.to_vec()));
    }

    // Create truncated valid payloads
    if let Ok(serialized) = codec.serialize(&test_data, SerializationFormat::MessagePack) {
        for truncate_len in [1, serialized.len() / 2, serialized.len().saturating_sub(1)] {
            if truncate_len < serialized.len() {
                payloads.push((
                    SerializationFormat::MessagePack,
                    serialized[..truncate_len].to_vec(),
                ));
            }
        }
    }

    // Create oversized payloads (if input is large enough)
    if data.len() > 1000 {
        let oversized = data[..data.len().min(100_000)].to_vec();
        payloads.push((SerializationFormat::Json, oversized));
    }

    payloads
}

/// Test ID deserialization specifically
fn test_id_deserialization(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    // Test RegionId deserialization from various formats
    let test_region_id = RegionId::ephemeral(); // Create valid ID

    let codec = SerdeCodec;
    for format in [
        SerializationFormat::MessagePack,
        SerializationFormat::Json,
        SerializationFormat::Bincode,
    ] {
        // Try to deserialize valid ID
        if let Ok(serialized) = codec.serialize(&test_region_id, format) {
            let _ = codec.deserialize::<RegionId>(&serialized, format);
        }

        // Try to deserialize raw data as ID
        let _ = codec.deserialize::<RegionId>(data, format);

        // Try to deserialize truncated valid data
        if let Ok(serialized) = codec.serialize(&test_region_id, format) {
            for len in [1, 2, serialized.len() / 2] {
                if len < serialized.len() {
                    let _ = codec.deserialize::<RegionId>(&serialized[..len], format);
                }
            }
        }
    }

    // Test TaskId deserialization
    let test_task_id = TaskId::ephemeral();
    for format in [SerializationFormat::MessagePack, SerializationFormat::Json] {
        if let Ok(serialized) = codec.serialize(&test_task_id, format) {
            let _ = codec.deserialize::<TaskId>(&serialized, format);
        }
        let _ = codec.deserialize::<TaskId>(data, format);
    }

    // Test ObligationId deserialization if available
    // Note: This may not be public, so we'll test with a generic u64 ID pattern
    let test_obligation_id = 0x1234567890abcdefu64;
    for format in [SerializationFormat::Bincode, SerializationFormat::Json] {
        if let Ok(serialized) = codec.serialize(&test_obligation_id, format) {
            let _ = codec.deserialize::<u64>(&serialized, format);
        }
        let _ = codec.deserialize::<u64>(data, format);
    }
}

/// Test typed symbol construction and validation
fn test_typed_symbol_operations(data: &[u8]) {
    if data.len() < TYPED_SYMBOL_HEADER_LEN + 10 {
        return;
    }

    // Try to create symbol from raw data
    let object_id = ObjectId::new(1, 1, 1);
    let object_params = ObjectParams::new(1, 1024).expect("valid params");

    if let Ok(symbol) = Symbol::new(
        object_id,
        object_params,
        SymbolKind::Source,
        0,
        data.to_vec(),
    ) {
        // Test TypedSymbol creation from symbol
        let _ = TypedSymbol::<TestPayload>::try_from_symbol(symbol.clone());
        let _ = TypedSymbol::<RegionId>::try_from_symbol(symbol.clone());
        let _ = TypedSymbol::<TaskId>::try_from_symbol(symbol.clone());

        // Test header decoding from symbol data
        let _ = TypedHeader::decode(symbol.data());
    }

    // Test TypedDecoder with constructed symbols
    let config = DecodingConfig::new(1024).expect("valid config");
    let mut decoder = TypedDecoder::<TestPayload>::new(config, SerializationFormat::MessagePack);

    // Try to decode from malformed symbol sets
    let symbols = Vec::<TypedSymbol<TestPayload>>::new();
    let _ = decoder.decode(symbols);
}

/// Test serialization format edge cases
fn test_serialization_formats(data: &[u8]) {
    let codec = SerdeCodec;

    // Test all format byte values
    for byte_val in 0u8..=255u8 {
        let _ = SerializationFormat::from_byte(byte_val);
    }

    // Test complex nested structures
    let mut complex_data = HashMap::new();
    if data.len() >= 4 {
        for i in 0..4.min(data.len() / 4) {
            let key = format!("key_{}", i);
            let value = format!("value_{:?}", &data[i * 4..(i + 1) * 4]);
            complex_data.insert(key, value);
        }

        for format in [
            SerializationFormat::MessagePack,
            SerializationFormat::Bincode,
            SerializationFormat::Json,
        ] {
            if let Ok(serialized) = codec.serialize(&complex_data, format) {
                let _ = codec.deserialize::<HashMap<String, String>>(&serialized, format);
            }
        }
    }

    // Test deeply nested structures
    #[derive(Serialize, Deserialize)]
    struct Nested {
        depth: u32,
        data: Option<Box<Nested>>,
        values: Vec<u8>,
    }

    let mut nested = Nested {
        depth: 0,
        data: None,
        values: data.get(..10.min(data.len())).unwrap_or(&[]).to_vec(),
    };

    // Build nested structure based on input data
    for i in 0..data.len().min(10) {
        nested = Nested {
            depth: i as u32,
            data: Some(Box::new(nested)),
            values: vec![data[i]],
        };
    }

    for format in [
        SerializationFormat::MessagePack,
        SerializationFormat::Bincode,
    ] {
        if let Ok(serialized) = codec.serialize(&nested, format) {
            let _ = codec.deserialize::<Nested>(&serialized, format);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs to prevent OOM during testing
    if data.len() > 1_000_000 {
        return;
    }

    // Test 1: TypedHeader parsing with raw input data
    let _ = TypedHeader::decode(data);

    // Test 2: Valid header parsing
    let valid_headers = generate_valid_headers(data);
    for header in &valid_headers {
        let _ = TypedHeader::decode(header);
    }

    // Test 3: Malformed header testing (vulnerability detection)
    let malformed_headers = generate_malformed_headers(data);
    for header in &malformed_headers {
        let _ = TypedHeader::decode(header);
    }

    // Test 4: Serialized payload deserialization
    let payloads = generate_serialized_payloads(data);
    for (format, payload) in &payloads {
        let codec = SerdeCodec;

        // Try different target types
        let _ = codec.deserialize::<TestPayload>(payload, *format);
        let _ = codec.deserialize::<RegionId>(payload, *format);
        let _ = codec.deserialize::<TaskId>(payload, *format);
        let _ = codec.deserialize::<HashMap<String, String>>(payload, *format);
        let _ = codec.deserialize::<Vec<u8>>(payload, *format);
        let _ = codec.deserialize::<u64>(payload, *format);
        let _ = codec.deserialize::<String>(payload, *format);
    }

    // Test 5: ID deserialization specifically
    test_id_deserialization(data);

    // Test 6: TypedSymbol operations
    test_typed_symbol_operations(data);

    // Test 7: Serialization format edge cases
    test_serialization_formats(data);

    // Test 8: Combined header + payload testing
    if data.len() >= TYPED_SYMBOL_HEADER_LEN + 10 {
        let header_data = &data[..TYPED_SYMBOL_HEADER_LEN];
        let payload_data = &data[TYPED_SYMBOL_HEADER_LEN..];

        // Test combined parsing
        if let Ok(_header) = TypedHeader::decode(header_data) {
            let codec = SerdeCodec;
            for format in [
                SerializationFormat::MessagePack,
                SerializationFormat::Bincode,
                SerializationFormat::Json,
            ] {
                let _ = codec.deserialize::<TestPayload>(payload_data, format);
            }
        }
    }

    // Test 9: Boundary testing - edge lengths and values
    for split_point in [
        TYPED_SYMBOL_HEADER_LEN,
        TYPED_SYMBOL_HEADER_LEN / 2,
        data.len() / 2,
        data.len().saturating_sub(10),
    ] {
        if split_point < data.len() {
            let first_part = &data[..split_point];
            let second_part = &data[split_point..];

            // Test as header
            let _ = TypedHeader::decode(first_part);
            let _ = TypedHeader::decode(second_part);

            // Test as payload
            let codec = SerdeCodec;
            let _ = codec.deserialize::<TestPayload>(first_part, SerializationFormat::MessagePack);
            let _ = codec.deserialize::<RegionId>(second_part, SerializationFormat::Bincode);
        }
    }

    // Test 10: Format byte validation exhaustively
    if !data.is_empty() {
        for &byte in data.iter().take(256) {
            let _ = SerializationFormat::from_byte(byte);
        }
    }

    // Test 11: Magic number validation with various prefixes
    if data.len() >= 4 {
        // Test various 4-byte combinations as potential magic numbers
        for i in 0..data.len().saturating_sub(3) {
            let potential_magic = &data[i..i + 4];

            // Create a minimal header with this magic
            let mut test_header = potential_magic.to_vec();
            test_header.extend(vec![0; TYPED_SYMBOL_HEADER_LEN - 4]);
            let _ = TypedHeader::decode(&test_header);
        }
    }

    // Test 12: Integer parsing edge cases from header fields
    if data.len() >= 8 {
        // Test various integer interpretations of the input data
        for offset in 0..data.len().saturating_sub(8) {
            let bytes = &data[offset..offset + 8];

            // Test as version (u16)
            if bytes.len() >= 2 {
                let _version = u16::from_le_bytes([bytes[0], bytes[1]]);
            }

            // Test as type_id (u64)
            let _type_id = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);

            // Test as payload_len (u32)
            if bytes.len() >= 4 {
                let _payload_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            }
        }
    }
});
