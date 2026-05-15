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
    T: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    // Should handle malformed input gracefully (error, not panic), and any
    // accepted edge-case value must remain serializable.
    match serde_json::from_slice::<T>(malformed_json) {
        Ok(value) => {
            let json_value = serde_json::to_value(&value)
                .expect("accepted malformed-input edge case should serialize");
            assert!(
                json_value.is_object(),
                "accepted federation config JSON should serialize as an object"
            );
        }
        Err(error) => {
            let diagnostic = error.to_string();
            assert!(
                !diagnostic.is_empty(),
                "malformed JSON rejection should expose a diagnostic"
            );
        }
    }
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

fn observe_morphism_constraints_fields(constraints: &MorphismConstraints) {
    let value = serde_json::to_value(constraints)
        .expect("MorphismConstraints field observer serialization should work");
    let object = value
        .as_object()
        .expect("MorphismConstraints should serialize as a JSON object");

    let allowed_classes = object
        .get("allowed_classes")
        .and_then(serde_json::Value::as_array)
        .expect("allowed_classes should serialize as a JSON array");
    assert_eq!(
        allowed_classes.len(),
        constraints.allowed_classes.len(),
        "serialized allowed_classes count should match generated set"
    );

    assert_eq!(
        object
            .get("max_expansion_factor")
            .and_then(serde_json::Value::as_u64),
        Some(u64::from(constraints.max_expansion_factor)),
        "serialized max_expansion_factor should match generated field"
    );
    assert_eq!(
        object.get("max_fanout").and_then(serde_json::Value::as_u64),
        Some(u64::from(constraints.max_fanout)),
        "serialized max_fanout should match generated field"
    );

    let roundtrip: MorphismConstraints = serde_json::from_value(value)
        .expect("MorphismConstraints field observer round-trip should deserialize");
    assert_eq!(
        &roundtrip, constraints,
        "MorphismConstraints field observer round-trip should preserve fields"
    );
}

fn observe_leaf_config_fields(leaf_config: &LeafConfig) {
    let value = serde_json::to_value(leaf_config)
        .expect("LeafConfig field observer serialization should work");
    let object = value
        .as_object()
        .expect("LeafConfig should serialize as a JSON object");

    let backoff_value = serde_json::to_value(leaf_config.max_reconnect_backoff)
        .expect("LeafConfig backoff field should serialize");
    let backoff_roundtrip: std::time::Duration =
        serde_json::from_value(backoff_value).expect("LeafConfig backoff field should deserialize");
    assert_eq!(
        backoff_roundtrip, leaf_config.max_reconnect_backoff,
        "LeafConfig reconnect backoff should survive field-level serde"
    );

    assert_eq!(
        object
            .get("offline_buffer_limit")
            .and_then(serde_json::Value::as_u64),
        Some(leaf_config.offline_buffer_limit),
        "serialized offline_buffer_limit should match generated field"
    );

    let nested_constraints: MorphismConstraints = serde_json::from_value(
        object
            .get("morphism_constraints")
            .expect("LeafConfig should serialize morphism_constraints")
            .clone(),
    )
    .expect("LeafConfig nested morphism_constraints should deserialize");
    assert_eq!(
        nested_constraints, leaf_config.morphism_constraints,
        "LeafConfig nested constraints should survive field-level serde"
    );
    observe_morphism_constraints_fields(&leaf_config.morphism_constraints);

    let roundtrip: LeafConfig = serde_json::from_value(value)
        .expect("LeafConfig field observer round-trip should deserialize");
    assert_eq!(
        &roundtrip, leaf_config,
        "LeafConfig field observer round-trip should preserve fields"
    );
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
        observe_morphism_constraints_fields(&constraints);
    }

    if let Ok(leaf_config) = LeafConfig::arbitrary(&mut Unstructured::new(data)) {
        observe_leaf_config_fields(&leaf_config);
    }
});
