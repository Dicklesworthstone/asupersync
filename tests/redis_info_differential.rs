//! Differential conformance tests for Redis INFO response parsing.

use std::collections::BTreeMap;

use asupersync::messaging::redis::RespValue;
use redis::{InfoDict, from_redis_value, parse_redis_value};

struct InfoFixture {
    name: &'static str,
    payload: &'static str,
    expected: &'static [(&'static str, &'static str)],
}

#[test]
fn info_sections_match_redis_rs_info_dict_model() {
    let fixtures = [
        InfoFixture {
            name: "multiple_sections_and_colon_values",
            payload: concat!(
                "# Server\n",
                "redis_version:7.2.4\n",
                "redis_mode:standalone\n",
                "# Replication\n",
                "role:master\n",
                "master0:ip=127.0.0.1,port=6379,state=online\n",
                "run_id:abc:def\n",
            ),
            expected: &[
                ("redis_version", "7.2.4"),
                ("redis_mode", "standalone"),
                ("role", "master"),
                ("master0", "ip=127.0.0.1,port=6379,state=online"),
                ("run_id", "abc:def"),
            ],
        },
        InfoFixture {
            name: "duplicate_keys_keep_last_value",
            payload: concat!(
                "# Clients\n",
                "connected_clients:12\n",
                "blocked_clients:0\n",
                "connected_clients:9\n",
            ),
            expected: &[("blocked_clients", "0"), ("connected_clients", "9")],
        },
        InfoFixture {
            name: "blank_comments_and_malformed_lines_are_ignored",
            payload: concat!(
                "# CPU\n",
                "\n",
                "used_cpu_sys:12.34\n",
                "this line has no colon\n",
                "# Memory\n",
                "used_memory:1024\n",
            ),
            expected: &[("used_cpu_sys", "12.34"), ("used_memory", "1024")],
        },
    ];

    for fixture in fixtures {
        let wire = encode_bulk_string(fixture.payload);
        let ours = ours_parse_info_wire(&wire);
        let reference = redis_rs_parse_info_wire(&wire);
        let expected = expected_map(fixture.expected);

        assert_eq!(ours, expected, "{} asupersync INFO parse", fixture.name);
        assert_eq!(reference, expected, "{} redis-rs INFO parse", fixture.name);
        assert_eq!(ours, reference, "{} differential parity", fixture.name);
    }
}

fn encode_bulk_string(payload: &str) -> Vec<u8> {
    format!("${}\r\n{}\r\n", payload.len(), payload).into_bytes()
}

fn ours_parse_info_wire(wire: &[u8]) -> BTreeMap<String, String> {
    let (value, consumed) = RespValue::try_decode(wire)
        .expect("INFO wire should decode")
        .expect("INFO wire should be complete");
    assert_eq!(consumed, wire.len(), "INFO wire must fully decode");

    let payload = match value {
        RespValue::BulkString(Some(bytes)) => {
            String::from_utf8(bytes).expect("INFO payload should stay UTF-8")
        }
        RespValue::SimpleString(text) => text,
        other => panic!("expected INFO bulk string, got {other:?}"),
    };

    parse_info_like_redis_rs(&payload)
}

fn redis_rs_parse_info_wire(wire: &[u8]) -> BTreeMap<String, String> {
    let value = parse_redis_value(wire).expect("redis-rs should parse INFO wire");
    let info: InfoDict = from_redis_value(value).expect("redis-rs should build InfoDict");
    info.iter()
        .map(|(key, value)| {
            let value: String = from_redis_value(value.clone())
                .expect("redis-rs InfoDict entries should stay strings");
            (key.clone(), value)
        })
        .collect()
}

fn parse_info_like_redis_rs(payload: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in payload.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, ':');
        let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        map.insert(key.to_string(), value.to_string());
    }
    map
}

fn expected_map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}
