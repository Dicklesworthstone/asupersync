//! RESP3 nested Map/Set conformance tests.
//!
//! This module implements value-model conformance tests for RESP3 nested Map/Set
//! encoding/decoding. Tests focus on round-trip fidelity and wire format compatibility
//! with known good golden vectors matching the redis-rs value model.

#[cfg(test)]
mod tests {
    use super::super::redis::RespValue;

    #[test]
    fn test_resp3_nested_map_set_value_model_conformance() {
        // Test the critical scenarios from redis-rs value model
        test_complex_mixed_scenario();
        test_nested_map_basic();
        test_nested_set_basic();
        test_edge_cases();
    }

    fn test_complex_mixed_scenario() {
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
            "%2\r\n",            // Map with 2 key-value pairs
            "$7\r\nnumbers\r\n", // BulkString key "numbers"
            "~2\r\n",            // Set with 2 elements
            ":1\r\n",            // Integer 1
            "$3\r\ntwo\r\n",     // BulkString "two"
            "$4\r\nmeta\r\n",    // BulkString key "meta"
            "%2\r\n",            // Map with 2 key-value pairs
            "+proto\r\n",        // SimpleString key "proto"
            ":3\r\n",            // Integer 3
            "+mode\r\n",         // SimpleString key "mode"
            "+standalone\r\n",   // SimpleString "standalone"
        )
        .as_bytes();

        // Test our encoding matches the golden
        let actual = value.encode();
        assert_eq!(
            actual,
            expected_golden,
            "RESP3 wire format must match redis-rs value model golden bytes\n\
             Expected: {:?}\n\
             Actual:   {:?}",
            String::from_utf8_lossy(expected_golden),
            String::from_utf8_lossy(&actual)
        );

        // Test round-trip decoding
        let (decoded, consumed) = RespValue::try_decode(&actual)
            .expect("decode should succeed")
            .expect("should have complete value");

        assert_eq!(decoded, value, "round-trip decode must preserve value");
        assert_eq!(consumed, actual.len(), "must consume entire input");
    }

    fn test_nested_map_basic() {
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

        // Test round-trip
        let encoded = nested_map.encode();
        let (decoded, consumed) = RespValue::try_decode(&encoded)
            .expect("decode should succeed")
            .expect("should have complete value");

        assert_eq!(decoded, nested_map, "nested map round-trip failed");
        assert_eq!(consumed, encoded.len(), "must consume entire input");
    }

    fn test_nested_set_basic() {
        let nested_set = RespValue::Set(vec![
            RespValue::Integer(1),
            RespValue::Set(vec![
                RespValue::BulkString(Some(b"inner1".to_vec())),
                RespValue::BulkString(Some(b"inner2".to_vec())),
            ]),
            RespValue::Integer(3),
        ]);

        // Test round-trip
        let encoded = nested_set.encode();
        let (decoded, consumed) = RespValue::try_decode(&encoded)
            .expect("decode should succeed")
            .expect("should have complete value");

        assert_eq!(decoded, nested_set, "nested set round-trip failed");
        assert_eq!(consumed, encoded.len(), "must consume entire input");
    }

    fn test_edge_cases() {
        // Empty Map
        let empty_map = RespValue::Map(vec![]);
        let encoded = empty_map.encode();
        assert_eq!(encoded, b"%0\r\n");
        let (decoded, consumed) = RespValue::try_decode(&encoded).unwrap().unwrap();
        assert_eq!(decoded, empty_map);
        assert_eq!(
            consumed,
            encoded.len(),
            "empty map must consume entire input"
        );

        // Empty Set
        let empty_set = RespValue::Set(vec![]);
        let encoded = empty_set.encode();
        assert_eq!(encoded, b"~0\r\n");
        let (decoded, consumed) = RespValue::try_decode(&encoded).unwrap().unwrap();
        assert_eq!(decoded, empty_set);
        assert_eq!(
            consumed,
            encoded.len(),
            "empty set must consume entire input"
        );

        // Single element Map
        let single_map = RespValue::Map(vec![(
            RespValue::SimpleString("key".to_string()),
            RespValue::Integer(42),
        )]);
        let encoded = single_map.encode();
        let (decoded, consumed) = RespValue::try_decode(&encoded).unwrap().unwrap();
        assert_eq!(decoded, single_map);
        assert_eq!(
            consumed,
            encoded.len(),
            "single-element map must consume entire input"
        );

        // Single element Set
        let single_set = RespValue::Set(vec![RespValue::Integer(42)]);
        let encoded = single_set.encode();
        let (decoded, consumed) = RespValue::try_decode(&encoded).unwrap().unwrap();
        assert_eq!(decoded, single_set);
        assert_eq!(
            consumed,
            encoded.len(),
            "single-element set must consume entire input"
        );
    }
}
