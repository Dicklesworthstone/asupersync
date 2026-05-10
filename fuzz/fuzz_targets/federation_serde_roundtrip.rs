#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// Federation config structures fuzz testing for serialization round-trip properties.
///
/// This fuzz target tests the serde serialization/deserialization of federation
/// configuration structures to ensure they handle malformed input gracefully and
/// maintain round-trip consistency.
///
/// Targets the following federation config structures:
/// - MorphismConstraints - morphism class restrictions and limits
/// - LeafConfig - leaf node configuration for federation bridges
///
/// Test cases cover:
/// - Valid structure generation via Arbitrary derive
/// - JSON serialization round-trip (serialize → deserialize must be identity)
/// - Malformed JSON input handling (must not panic)
/// - Edge cases: empty collections, max/min values, special characters
/// - Cross-format consistency (JSON vs bincode if applicable)
use asupersync::messaging::federation::{LeafConfig, MorphismConstraints};

/// Test helper for round-trip serialization properties
fn test_json_roundtrip<T>(value: &T) -> Result<(), Box<dyn std::error::Error>>
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    // Serialize to JSON
    let json_bytes = serde_json::to_vec(value)?;

    // Deserialize back
    let deserialized: T = serde_json::from_slice(&json_bytes)?;

    // Must be identical
    if value != &deserialized {
        panic!(
            "Round-trip failed: original != deserialized\nOriginal: {:#?}\nDeserialized: {:#?}",
            value, deserialized
        );
    }

    // Test pretty-printing round-trip as well
    let pretty_json = serde_json::to_string_pretty(value)?;
    let pretty_deserialized: T = serde_json::from_str(&pretty_json)?;

    if value != &pretty_deserialized {
        panic!("Pretty JSON round-trip failed");
    }

    Ok(())
}

/// Test malformed JSON inputs don't cause panics
fn test_malformed_json_handling<T>(malformed_json: &[u8])
where
    T: for<'de> serde::Deserialize<'de>,
{
    // Should handle malformed input gracefully (error, not panic)
    let _ = serde_json::from_slice::<T>(malformed_json);
}

/// Generate malformed JSON test cases
fn generate_malformed_json_cases(data: &[u8]) -> Vec<Vec<u8>> {
    let mut cases = vec![
        // Empty input
        b"".to_vec(),
        // Invalid JSON syntax
        b"{".to_vec(),
        b"}".to_vec(),
        b"{{".to_vec(),
        b"]}".to_vec(),
        b"null".to_vec(),
        b"true".to_vec(),
        b"false".to_vec(),
        b"123".to_vec(),
        b"\"string\"".to_vec(),
        // Invalid structure
        b"[]".to_vec(),
        b"{\"unknown_field\": true}".to_vec(),
        b"{\"allowed_classes\": \"not_a_set\"}".to_vec(),
        b"{\"max_expansion_factor\": -1}".to_vec(),
        b"{\"max_fanout\": \"not_a_number\"}".to_vec(),
        // Nested invalid
        b"{\"allowed_classes\": {\"invalid\": \"structure\"}}".to_vec(),
        b"{\"morphism_constraints\": null}".to_vec(),
    ];

    // Use fuzz input as malformed JSON
    if !data.is_empty() {
        cases.push(data.to_vec());

        // Corrupt valid JSON with fuzz data
        let base_valid = b"{\"allowed_classes\":[],\"max_expansion_factor\":1,\"max_fanout\":1}";
        let mut corrupted = base_valid.to_vec();
        let insert_pos = corrupted.len().saturating_sub(10);
        corrupted.splice(insert_pos..insert_pos, data.iter().take(20).copied());
        cases.push(corrupted);
    }

    cases
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs
    if data.len() > 100_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);

    // Test 1: Generate valid MorphismConstraints and test round-trip
    if let Ok(constraints) = MorphismConstraints::arbitrary(&mut unstructured) {
        if let Err(e) = test_json_roundtrip(&constraints) {
            panic!("MorphismConstraints round-trip failed: {}", e);
        }

        // Test that serialized form is valid JSON
        let json_str = serde_json::to_string(&constraints).expect("serialization should work");
        assert!(
            serde_json::from_str::<serde_json::Value>(&json_str).is_ok(),
            "Serialized JSON should be valid"
        );
    }

    // Test 2: Generate valid LeafConfig and test round-trip
    let mut unstructured2 = Unstructured::new(data);
    if let Ok(leaf_config) = LeafConfig::arbitrary(&mut unstructured2) {
        if let Err(e) = test_json_roundtrip(&leaf_config) {
            panic!("LeafConfig round-trip failed: {}", e);
        }

        // Test that serialized form is valid JSON
        let json_str = serde_json::to_string(&leaf_config).expect("serialization should work");
        assert!(
            serde_json::from_str::<serde_json::Value>(&json_str).is_ok(),
            "Serialized JSON should be valid"
        );
    }

    // Test 3: Test malformed JSON handling for both types
    let malformed_cases = generate_malformed_json_cases(data);
    for case in &malformed_cases {
        test_malformed_json_handling::<MorphismConstraints>(case);
        test_malformed_json_handling::<LeafConfig>(case);
    }

    // Test 4: Test direct JSON deserialization from fuzz input
    test_malformed_json_handling::<MorphismConstraints>(data);
    test_malformed_json_handling::<LeafConfig>(data);

    // Test 5: Test that valid structures can be serialized deterministically
    let mut unstructured3 = Unstructured::new(data);
    if let Ok(constraints) = MorphismConstraints::arbitrary(&mut unstructured3) {
        let json1 = serde_json::to_string(&constraints)
            .expect("MorphismConstraints deterministic serialization pass 1 should work");
        let json2 = serde_json::to_string(&constraints)
            .expect("MorphismConstraints deterministic serialization pass 2 should work");
        assert_eq!(json1, json2, "Serialization should be deterministic");

        // Test compact vs pretty formatting consistency
        let compact = serde_json::to_string(&constraints)
            .expect("MorphismConstraints compact JSON serialization should work");
        let pretty = serde_json::to_string_pretty(&constraints)
            .expect("MorphismConstraints pretty JSON serialization should work");
        let compact_parsed: serde_json::Value =
            serde_json::from_str(&compact).expect("compact JSON should parse");
        let pretty_parsed: serde_json::Value =
            serde_json::from_str(&pretty).expect("pretty JSON should parse");
        assert_eq!(
            compact_parsed, pretty_parsed,
            "Compact and pretty JSON should represent same data"
        );
    }

    // Test 6: Access generated structures without panicking.
    if let Ok(constraints) = MorphismConstraints::arbitrary(&mut Unstructured::new(data)) {
        // Should be able to access all fields without panicking
        let _ = constraints.allowed_classes.len();
        let _ = constraints.max_expansion_factor;
        let _ = constraints.max_fanout;
    }

    if let Ok(leaf_config) = LeafConfig::arbitrary(&mut Unstructured::new(data)) {
        // LeafConfig should have reasonable limits and no panics when accessing fields
        let _ = leaf_config.max_reconnect_backoff;
        let _ = leaf_config.offline_buffer_limit;
        let _ = leaf_config.morphism_constraints.allowed_classes.len();
    }
});
