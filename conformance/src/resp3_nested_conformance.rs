//! RESP3 nested Map/Set conformance tests.
//!
//! This module implements value-model conformance tests for RESP3 nested Map/Set
//! encoding/decoding. Tests focus on round-trip fidelity and wire format compatibility
//! with known good golden vectors from redis-rs value model.
//!
//! # Coverage
//!
//! - RESP3 Map encoding roundtrip fidelity
//! - RESP3 Set encoding roundtrip fidelity
//! - Nested Map-in-Map structures
//! - Nested Set-in-Set structures
//! - Mixed Map/Set nesting scenarios
//! - Golden file compatibility with redis-rs wire format

use serde::{Deserialize, Serialize};
use asupersync::messaging::redis::RespValue;

/// Configuration for RESP3 conformance test suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resp3ConformanceConfig {
    /// Maximum nesting depth to test.
    pub max_nesting_depth: usize,
    /// Include edge cases (empty maps/sets, single elements).
    pub include_edge_cases: bool,
}

impl Default for Resp3ConformanceConfig {
    fn default() -> Self {
        Self {
            max_nesting_depth: 5,
            include_edge_cases: true,
        }
    }
}

/// Test result from a single RESP3 conformance check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resp3TestResult {
    pub scenario: String,
    pub passed: bool,
    pub wire_bytes: Vec<u8>,
    pub expected_bytes: Vec<u8>,
    pub error: Option<String>,
}

/// RESP3 nested Map/Set conformance test runner.
pub struct Resp3ConformanceRunner {
    config: Resp3ConformanceConfig,
}

impl Resp3ConformanceRunner {
    pub fn new(config: Resp3ConformanceConfig) -> Self {
        Self { config }
    }

    /// Run the full RESP3 conformance test suite.
    pub fn run_all(&self) -> Vec<Resp3TestResult> {
        let mut results = Vec::new();

        // Test nested Maps
        results.extend(self.test_nested_maps());

        // Test nested Sets
        results.extend(self.test_nested_sets());

        // Test mixed Map/Set nesting
        results.extend(self.test_mixed_nesting());

        // Test edge cases
        if self.config.include_edge_cases {
            results.extend(self.test_edge_cases());
        }

        results
    }

    /// Test nested Map structures against known golden wire formats.
    fn test_nested_maps(&self) -> Vec<Resp3TestResult> {
        let mut results = Vec::new();

        // Test case 1: Simple nested map
        let nested_map = RespValue::Map(vec![
            (
                RespValue::BulkString(Some(b"level1".to_vec())),
                RespValue::Map(vec![
                    (
                        RespValue::BulkString(Some(b"level2".to_vec())),
                        RespValue::Integer(42),
                    ),
                    (
                        RespValue::SimpleString("key".to_string()),
                        RespValue::SimpleString("value".to_string()),
                    ),
                ]),
            ),
            (
                RespValue::BulkString(Some(b"direct".to_vec())),
                RespValue::Integer(123),
            ),
        ]);

        // Expected RESP3 wire format for nested map
        let expected_nested_map = concat!(
            "%2\r\n",                           // Map with 2 entries
            "$6\r\nlevel1\r\n",                 // First key: "level1"
            "%2\r\n",                           // Value: Map with 2 entries
            "$6\r\nlevel2\r\n",                 // Nested key: "level2"
            ":42\r\n",                          // Nested value: 42
            "+key\r\n",                         // Nested key: "key"
            "+value\r\n",                       // Nested value: "value"
            "$6\r\ndirect\r\n",                 // Second key: "direct"
            ":123\r\n",                         // Second value: 123
        ).as_bytes();

        results.push(self.test_wire_format_conformance(
            "nested_map_basic",
            &nested_map,
            expected_nested_map,
        ));

        results
    }

    /// Test nested Set structures against known golden wire formats.
    fn test_nested_sets(&self) -> Vec<Resp3TestResult> {
        let mut results = Vec::new();

        // Test case 1: Simple nested set
        let nested_set = RespValue::Set(vec![
            RespValue::Integer(1),
            RespValue::Set(vec![
                RespValue::BulkString(Some(b"inner1".to_vec())),
                RespValue::BulkString(Some(b"inner2".to_vec())),
            ]),
            RespValue::Integer(3),
        ]);

        // Expected RESP3 wire format for nested set
        let expected_nested_set = concat!(
            "~3\r\n",                           // Set with 3 elements
            ":1\r\n",                           // First element: 1
            "~2\r\n",                           // Second element: Set with 2 elements
            "$6\r\ninner1\r\n",                 // Nested element: "inner1"
            "$6\r\ninner2\r\n",                 // Nested element: "inner2"
            ":3\r\n",                           // Third element: 3
        ).as_bytes();

        results.push(self.test_wire_format_conformance(
            "nested_set_basic",
            &nested_set,
            expected_nested_set,
        ));

        results
    }

    /// Test mixed Map/Set nesting scenarios.
    fn test_mixed_nesting(&self) -> Vec<Resp3TestResult> {
        let mut results = Vec::new();

        // Test case: Complex mixed scenario (matches the existing redis.rs test)
        let complex_mixed = RespValue::Map(vec![
            (
                RespValue::BulkString(Some(b"numbers".to_vec())),
                RespValue::Set(vec![
                    RespValue::Integer(1),
                    RespValue::BulkString(Some(b"two".to_vec())),
                ]),
            ),
            (
                RespValue::BulkString(Some(b"meta".to_vec())),
                RespValue::Map(vec![
                    (
                        RespValue::SimpleString("proto".to_string()),
                        RespValue::Integer(3),
                    ),
                    (
                        RespValue::SimpleString("mode".to_string()),
                        RespValue::SimpleString("standalone".to_string()),
                    ),
                ]),
            ),
        ]);

        // Expected wire format (matches the golden in existing redis.rs test)
        let expected_complex_mixed = concat!(
            "%2\r\n",                           // Map with 2 entries
            "$7\r\nnumbers\r\n",                // First key: "numbers"
            "~2\r\n",                           // Value: Set with 2 elements
            ":1\r\n",                           // Set element: 1
            "$3\r\ntwo\r\n",                    // Set element: "two"
            "$4\r\nmeta\r\n",                   // Second key: "meta"
            "%2\r\n",                           // Value: Map with 2 entries
            "+proto\r\n",                       // Nested key: "proto"
            ":3\r\n",                           // Nested value: 3
            "+mode\r\n",                        // Nested key: "mode"
            "+standalone\r\n",                  // Nested value: "standalone"
        ).as_bytes();

        results.push(self.test_wire_format_conformance(
            "complex_mixed_redis_rs_model",
            &complex_mixed,
            expected_complex_mixed,
        ));

        results
    }

    /// Test edge cases.
    fn test_edge_cases(&self) -> Vec<Resp3TestResult> {
        let mut results = Vec::new();

        // Empty Map
        let empty_map = RespValue::Map(vec![]);
        let expected_empty_map = b"%0\r\n";
        results.push(self.test_wire_format_conformance(
            "empty_map", &empty_map, expected_empty_map));

        // Empty Set
        let empty_set = RespValue::Set(vec![]);
        let expected_empty_set = b"~0\r\n";
        results.push(self.test_wire_format_conformance(
            "empty_set", &empty_set, expected_empty_set));

        // Single element Map
        let single_map = RespValue::Map(vec![
            (RespValue::SimpleString("key".to_string()), RespValue::Integer(42)),
        ]);
        let expected_single_map = concat!(
            "%1\r\n",                           // Map with 1 entry
            "+key\r\n",                         // Key: "key"
            ":42\r\n",                          // Value: 42
        ).as_bytes();
        results.push(self.test_wire_format_conformance(
            "single_element_map", &single_map, expected_single_map));

        // Single element Set
        let single_set = RespValue::Set(vec![RespValue::Integer(42)]);
        let expected_single_set = concat!(
            "~1\r\n",                           // Set with 1 element
            ":42\r\n",                          // Element: 42
        ).as_bytes();
        results.push(self.test_wire_format_conformance(
            "single_element_set", &single_set, expected_single_set));

        results
    }

    /// Test wire format conformance: encode + roundtrip + golden comparison.
    fn test_wire_format_conformance(
        &self,
        scenario: &str,
        value: &RespValue,
        expected_bytes: &[u8],
    ) -> Resp3TestResult {
        // Encode with asupersync implementation
        let actual_bytes = value.encode();

        // Test 1: Wire format matches expected golden
        let wire_matches = actual_bytes == expected_bytes;

        // Test 2: Round-trip decoding produces identical value
        let roundtrip_ok = match RespValue::try_decode(&actual_bytes) {
            Ok(Some((decoded, consumed))) => {
                decoded == *value && consumed == actual_bytes.len()
            }
            _ => false,
        };

        // Test 3: Can also decode the expected golden bytes
        let golden_decode_ok = match RespValue::try_decode(expected_bytes) {
            Ok(Some((decoded, consumed))) => {
                decoded == *value && consumed == expected_bytes.len()
            }
            _ => false,
        };

        let passed = wire_matches && roundtrip_ok && golden_decode_ok;

        Resp3TestResult {
            scenario: scenario.to_string(),
            passed,
            wire_bytes: actual_bytes,
            expected_bytes: expected_bytes.to_vec(),
            error: if !passed {
                Some(format!(
                    "Wire format conformance failed: wire_matches={}, roundtrip_ok={}, golden_decode_ok={}",
                    wire_matches, roundtrip_ok, golden_decode_ok
                ))
            } else {
                None
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resp3_nested_map_set_value_model_conformance() {
        let config = Resp3ConformanceConfig::default();
        let runner = Resp3ConformanceRunner::new(config);

        let results = runner.run_all();

        // Assert all tests pass
        let mut failures = Vec::new();
        for result in &results {
            if !result.passed {
                failures.push(format!(
                    "RESP3 conformance test failed for scenario '{}': {}",
                    result.scenario,
                    result.error.as_deref().unwrap_or("Unknown error")
                ));
            }
        }

        if !failures.is_empty() {
            panic!("RESP3 conformance failures:\n{}", failures.join("\n"));
        }

        // Assert we tested the critical scenarios
        let scenarios: std::collections::HashSet<_> = results.iter().map(|r| &r.scenario).collect();
        assert!(scenarios.contains(&"complex_mixed_redis_rs_model".to_string()),
                "Must test the redis-rs value model compatibility scenario");
        assert!(scenarios.contains(&"nested_map_basic".to_string()),
                "Must test basic nested map scenario");
        assert!(scenarios.contains(&"nested_set_basic".to_string()),
                "Must test basic nested set scenario");

        println!("RESP3 nested Map/Set conformance: {} tests passed", results.len());
    }

    #[test]
    fn test_redis_rs_value_model_golden_wire_format() {
        // Test the exact scenario and golden bytes from the existing redis.rs test
        let value = RespValue::Map(vec![
            (
                RespValue::BulkString(Some(b"numbers".to_vec())),
                RespValue::Set(vec![
                    RespValue::Integer(1),
                    RespValue::BulkString(Some(b"two".to_vec())),
                ]),
            ),
            (
                RespValue::BulkString(Some(b"meta".to_vec())),
                RespValue::Map(vec![
                    (
                        RespValue::SimpleString("proto".to_string()),
                        RespValue::Integer(3),
                    ),
                    (
                        RespValue::SimpleString("mode".to_string()),
                        RespValue::SimpleString("standalone".to_string()),
                    ),
                ]),
            ),
        ]);

        // This is the exact golden wire format from the existing test in redis.rs
        let expected_golden = concat!(
            "%2\r\n",                   // Map with 2 key-value pairs
            "$7\r\nnumbers\r\n",        // BulkString key "numbers"
            "~2\r\n",                   // Set with 2 elements
            ":1\r\n",                   // Integer 1
            "$3\r\ntwo\r\n",            // BulkString "two"
            "$4\r\nmeta\r\n",           // BulkString key "meta"
            "%2\r\n",                   // Map with 2 key-value pairs
            "+proto\r\n",               // SimpleString key "proto"
            ":3\r\n",                   // Integer 3
            "+mode\r\n",                // SimpleString key "mode"
            "+standalone\r\n",          // SimpleString "standalone"
        ).as_bytes();

        // Test our encoding matches the golden
        let actual = value.encode();
        assert_eq!(actual, expected_golden,
            "RESP3 wire format must match redis-rs value model golden bytes\n\
             Expected: {:?}\n\
             Actual:   {:?}",
            String::from_utf8_lossy(expected_golden),
            String::from_utf8_lossy(&actual));

        // Test round-trip decoding
        let (decoded, consumed) = RespValue::try_decode(&actual)
            .expect("decode should succeed")
            .expect("should have complete value");

        assert_eq!(decoded, value, "round-trip decode must preserve value");
        assert_eq!(consumed, actual.len(), "must consume entire input");
    }

    #[test]
    fn test_single_scenario_runner() {
        // Test individual scenario execution
        let runner = Resp3ConformanceRunner::new(Resp3ConformanceConfig::default());

        let simple_map = RespValue::Map(vec![
            (RespValue::SimpleString("key".to_string()), RespValue::Integer(42)),
        ]);
        let expected = b"%1\r\n+key\r\n:42\r\n";

        let result = runner.test_wire_format_conformance("test_single", &simple_map, expected);

        assert!(result.passed,
                "Single scenario test must pass: {}",
                result.error.unwrap_or_else(|| "No error".to_string()));
    }
}