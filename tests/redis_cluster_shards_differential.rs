use asupersync::messaging::redis::RespValue;
use redis::{Value as RedisValue, parse_redis_value};

#[derive(Debug, PartialEq, Eq)]
struct ShardTopology {
    shards: Vec<ShardInfo>,
}

#[derive(Debug, PartialEq, Eq)]
struct ShardInfo {
    slots: Vec<(u16, u16)>,
    nodes: Vec<NodeInfo>,
}

#[derive(Debug, PartialEq, Eq)]
struct NodeInfo {
    id: String,
    endpoint: Option<String>,
    ip: Option<String>,
    hostname: Option<String>,
    port: Option<u16>,
    tls_port: Option<u16>,
    role: String,
    replication_offset: i64,
    health: String,
}

#[test]
fn cluster_shards_resp3_matches_redis_rs_shard_topology() {
    let expected = ShardTopology {
        shards: vec![
            ShardInfo {
                slots: vec![(0, 5460), (6000, 6001)],
                nodes: vec![
                    NodeInfo {
                        id: "master-a".to_string(),
                        endpoint: Some("127.0.0.1".to_string()),
                        ip: Some("127.0.0.1".to_string()),
                        hostname: None,
                        port: Some(30001),
                        tls_port: None,
                        role: "master".to_string(),
                        replication_offset: 72156,
                        health: "online".to_string(),
                    },
                    NodeInfo {
                        id: "replica-a".to_string(),
                        endpoint: Some("127.0.0.2".to_string()),
                        ip: Some("127.0.0.2".to_string()),
                        hostname: None,
                        port: Some(30006),
                        tls_port: None,
                        role: "replica".to_string(),
                        replication_offset: 72155,
                        health: "loading".to_string(),
                    },
                ],
            },
            ShardInfo {
                slots: vec![],
                nodes: vec![NodeInfo {
                    id: "spare-b".to_string(),
                    endpoint: None,
                    ip: Some("127.0.0.3".to_string()),
                    hostname: Some("cache-b.internal".to_string()),
                    port: None,
                    tls_port: Some(40003),
                    role: "master".to_string(),
                    replication_offset: 0,
                    health: "online".to_string(),
                }],
            },
        ],
    };

    let wire = cluster_shards_resp3_fixture().encode();

    let ours = ours_parse_cluster_shards(&wire);
    let reference = redis_rs_parse_cluster_shards(&wire);

    assert_eq!(ours, expected, "asupersync CLUSTER SHARDS topology");
    assert_eq!(reference, expected, "redis-rs CLUSTER SHARDS topology");
    assert_eq!(ours, reference, "CLUSTER SHARDS differential parity");
}

fn cluster_shards_resp3_fixture() -> RespValue {
    RespValue::Array(Some(vec![
        RespValue::Map(vec![
            (
                RespValue::SimpleString("slots".to_string()),
                RespValue::Array(Some(vec![
                    RespValue::Integer(0),
                    RespValue::Integer(5460),
                    RespValue::Integer(6000),
                    RespValue::Integer(6001),
                ])),
            ),
            (
                RespValue::SimpleString("nodes".to_string()),
                RespValue::Array(Some(vec![
                    RespValue::Map(vec![
                        (
                            RespValue::SimpleString("id".to_string()),
                            RespValue::BulkString(Some(b"master-a".to_vec())),
                        ),
                        (
                            RespValue::SimpleString("port".to_string()),
                            RespValue::Integer(30001),
                        ),
                        (
                            RespValue::SimpleString("ip".to_string()),
                            RespValue::BulkString(Some(b"127.0.0.1".to_vec())),
                        ),
                        (
                            RespValue::SimpleString("endpoint".to_string()),
                            RespValue::BulkString(Some(b"127.0.0.1".to_vec())),
                        ),
                        (
                            RespValue::SimpleString("role".to_string()),
                            RespValue::BulkString(Some(b"master".to_vec())),
                        ),
                        (
                            RespValue::SimpleString("replication-offset".to_string()),
                            RespValue::Integer(72156),
                        ),
                        (
                            RespValue::SimpleString("health".to_string()),
                            RespValue::BulkString(Some(b"online".to_vec())),
                        ),
                    ]),
                    RespValue::Map(vec![
                        (
                            RespValue::SimpleString("id".to_string()),
                            RespValue::BulkString(Some(b"replica-a".to_vec())),
                        ),
                        (
                            RespValue::SimpleString("port".to_string()),
                            RespValue::Integer(30006),
                        ),
                        (
                            RespValue::SimpleString("ip".to_string()),
                            RespValue::BulkString(Some(b"127.0.0.2".to_vec())),
                        ),
                        (
                            RespValue::SimpleString("endpoint".to_string()),
                            RespValue::BulkString(Some(b"127.0.0.2".to_vec())),
                        ),
                        (
                            RespValue::SimpleString("role".to_string()),
                            RespValue::BulkString(Some(b"replica".to_vec())),
                        ),
                        (
                            RespValue::SimpleString("replication-offset".to_string()),
                            RespValue::Integer(72155),
                        ),
                        (
                            RespValue::SimpleString("health".to_string()),
                            RespValue::BulkString(Some(b"loading".to_vec())),
                        ),
                    ]),
                ])),
            ),
        ]),
        RespValue::Map(vec![
            (
                RespValue::SimpleString("slots".to_string()),
                RespValue::Array(Some(vec![])),
            ),
            (
                RespValue::SimpleString("nodes".to_string()),
                RespValue::Array(Some(vec![RespValue::Map(vec![
                    (
                        RespValue::SimpleString("id".to_string()),
                        RespValue::BulkString(Some(b"spare-b".to_vec())),
                    ),
                    (
                        RespValue::SimpleString("ip".to_string()),
                        RespValue::BulkString(Some(b"127.0.0.3".to_vec())),
                    ),
                    (
                        RespValue::SimpleString("endpoint".to_string()),
                        RespValue::Null,
                    ),
                    (
                        RespValue::SimpleString("hostname".to_string()),
                        RespValue::BulkString(Some(b"cache-b.internal".to_vec())),
                    ),
                    (
                        RespValue::SimpleString("tls-port".to_string()),
                        RespValue::Integer(40003),
                    ),
                    (
                        RespValue::SimpleString("role".to_string()),
                        RespValue::BulkString(Some(b"master".to_vec())),
                    ),
                    (
                        RespValue::SimpleString("replication-offset".to_string()),
                        RespValue::Integer(0),
                    ),
                    (
                        RespValue::SimpleString("health".to_string()),
                        RespValue::BulkString(Some(b"online".to_vec())),
                    ),
                ])])),
            ),
        ]),
    ]))
}

fn ours_parse_cluster_shards(wire: &[u8]) -> ShardTopology {
    let (value, consumed) = RespValue::try_decode(wire)
        .expect("CLUSTER SHARDS wire should decode")
        .expect("CLUSTER SHARDS wire should be complete");
    assert_eq!(consumed, wire.len(), "CLUSTER SHARDS must fully decode");
    shard_topology_from_resp(&value)
}

fn redis_rs_parse_cluster_shards(wire: &[u8]) -> ShardTopology {
    let value = parse_redis_value(wire).expect("redis-rs should parse CLUSTER SHARDS wire");
    shard_topology_from_redis(&value)
}

fn shard_topology_from_resp(value: &RespValue) -> ShardTopology {
    let RespValue::Array(Some(shards)) = value else {
        panic!("expected RESP3 array for CLUSTER SHARDS, got {value:?}");
    };
    ShardTopology {
        shards: shards.iter().map(shard_from_resp).collect(),
    }
}

fn shard_from_resp(value: &RespValue) -> ShardInfo {
    let RespValue::Map(entries) = value else {
        panic!("expected RESP3 shard map, got {value:?}");
    };
    let slots = slot_ranges_from_resp(required_resp_map_value(entries, "slots"));
    let nodes = nodes_from_resp(required_resp_map_value(entries, "nodes"));
    ShardInfo { slots, nodes }
}

fn slot_ranges_from_resp(value: &RespValue) -> Vec<(u16, u16)> {
    let RespValue::Array(Some(values)) = value else {
        panic!("expected slots array, got {value:?}");
    };
    assert_eq!(
        values.len() % 2,
        0,
        "slots array must contain start/end pairs"
    );
    values
        .chunks(2)
        .map(|pair| {
            (
                resp_u16(&pair[0], "slot start"),
                resp_u16(&pair[1], "slot end"),
            )
        })
        .collect()
}

fn nodes_from_resp(value: &RespValue) -> Vec<NodeInfo> {
    let RespValue::Array(Some(values)) = value else {
        panic!("expected nodes array, got {value:?}");
    };
    values.iter().map(node_from_resp).collect()
}

fn node_from_resp(value: &RespValue) -> NodeInfo {
    let RespValue::Map(entries) = value else {
        panic!("expected node map, got {value:?}");
    };
    NodeInfo {
        id: resp_string(required_resp_map_value(entries, "id"), "id"),
        endpoint: resp_optional_string(find_resp_map_value(entries, "endpoint")),
        ip: resp_optional_string(find_resp_map_value(entries, "ip")),
        hostname: resp_optional_string(find_resp_map_value(entries, "hostname")),
        port: find_resp_map_value(entries, "port").map(|value| resp_u16(value, "port")),
        tls_port: find_resp_map_value(entries, "tls-port").map(|value| resp_u16(value, "tls-port")),
        role: resp_string(required_resp_map_value(entries, "role"), "role"),
        replication_offset: resp_i64(
            required_resp_map_value(entries, "replication-offset"),
            "replication-offset",
        ),
        health: resp_string(required_resp_map_value(entries, "health"), "health"),
    }
}

fn required_resp_map_value<'a>(entries: &'a [(RespValue, RespValue)], key: &str) -> &'a RespValue {
    find_resp_map_value(entries, key).unwrap_or_else(|| panic!("missing RESP map key {key}"))
}

fn find_resp_map_value<'a>(
    entries: &'a [(RespValue, RespValue)],
    key: &str,
) -> Option<&'a RespValue> {
    entries.iter().find_map(|(entry_key, entry_value)| {
        if resp_key_matches(entry_key, key) {
            Some(entry_value)
        } else {
            None
        }
    })
}

fn resp_key_matches(value: &RespValue, key: &str) -> bool {
    matches!(value, RespValue::SimpleString(text) if text == key)
        || matches!(value, RespValue::BulkString(Some(bytes)) if bytes == key.as_bytes())
}

fn resp_string(value: &RespValue, field: &str) -> String {
    match value {
        RespValue::SimpleString(text) => text.clone(),
        RespValue::BulkString(Some(bytes)) => {
            String::from_utf8(bytes.clone()).unwrap_or_else(|_| panic!("{field} must be UTF-8"))
        }
        other => panic!("{field} must be a string, got {other:?}"),
    }
}

fn resp_optional_string(value: Option<&RespValue>) -> Option<String> {
    match value {
        None | Some(RespValue::Null) => None,
        Some(value) => Some(resp_string(value, "optional string")),
    }
}

fn resp_i64(value: &RespValue, field: &str) -> i64 {
    match value {
        RespValue::Integer(number) => *number,
        other => panic!("{field} must be an integer, got {other:?}"),
    }
}

fn resp_u16(value: &RespValue, field: &str) -> u16 {
    u16::try_from(resp_i64(value, field)).unwrap_or_else(|_| panic!("{field} must fit in u16"))
}

fn shard_topology_from_redis(value: &RedisValue) -> ShardTopology {
    let RedisValue::Array(shards) = value else {
        panic!("expected redis-rs array for CLUSTER SHARDS, got {value:?}");
    };
    ShardTopology {
        shards: shards.iter().map(shard_from_redis).collect(),
    }
}

fn shard_from_redis(value: &RedisValue) -> ShardInfo {
    let RedisValue::Map(entries) = value else {
        panic!("expected redis-rs shard map, got {value:?}");
    };
    let slots = slot_ranges_from_redis(required_redis_map_value(entries, "slots"));
    let nodes = nodes_from_redis(required_redis_map_value(entries, "nodes"));
    ShardInfo { slots, nodes }
}

fn slot_ranges_from_redis(value: &RedisValue) -> Vec<(u16, u16)> {
    let RedisValue::Array(values) = value else {
        panic!("expected redis-rs slots array, got {value:?}");
    };
    assert_eq!(
        values.len() % 2,
        0,
        "slots array must contain start/end pairs"
    );
    values
        .chunks(2)
        .map(|pair| {
            (
                redis_u16(&pair[0], "slot start"),
                redis_u16(&pair[1], "slot end"),
            )
        })
        .collect()
}

fn nodes_from_redis(value: &RedisValue) -> Vec<NodeInfo> {
    let RedisValue::Array(values) = value else {
        panic!("expected redis-rs nodes array, got {value:?}");
    };
    values.iter().map(node_from_redis).collect()
}

fn node_from_redis(value: &RedisValue) -> NodeInfo {
    let RedisValue::Map(entries) = value else {
        panic!("expected redis-rs node map, got {value:?}");
    };
    NodeInfo {
        id: redis_string(required_redis_map_value(entries, "id"), "id"),
        endpoint: redis_optional_string(find_redis_map_value(entries, "endpoint")),
        ip: redis_optional_string(find_redis_map_value(entries, "ip")),
        hostname: redis_optional_string(find_redis_map_value(entries, "hostname")),
        port: find_redis_map_value(entries, "port").map(|value| redis_u16(value, "port")),
        tls_port: find_redis_map_value(entries, "tls-port")
            .map(|value| redis_u16(value, "tls-port")),
        role: redis_string(required_redis_map_value(entries, "role"), "role"),
        replication_offset: redis_i64(
            required_redis_map_value(entries, "replication-offset"),
            "replication-offset",
        ),
        health: redis_string(required_redis_map_value(entries, "health"), "health"),
    }
}

fn required_redis_map_value<'a>(
    entries: &'a [(RedisValue, RedisValue)],
    key: &str,
) -> &'a RedisValue {
    find_redis_map_value(entries, key).unwrap_or_else(|| panic!("missing redis-rs map key {key}"))
}

fn find_redis_map_value<'a>(
    entries: &'a [(RedisValue, RedisValue)],
    key: &str,
) -> Option<&'a RedisValue> {
    entries.iter().find_map(|(entry_key, entry_value)| {
        if redis_key_matches(entry_key, key) {
            Some(entry_value)
        } else {
            None
        }
    })
}

fn redis_key_matches(value: &RedisValue, key: &str) -> bool {
    matches!(value, RedisValue::SimpleString(text) if text == key)
        || matches!(value, RedisValue::BulkString(bytes) if bytes == key.as_bytes())
}

fn redis_string(value: &RedisValue, field: &str) -> String {
    match value {
        RedisValue::SimpleString(text) => text.clone(),
        RedisValue::BulkString(bytes) => {
            String::from_utf8(bytes.clone()).unwrap_or_else(|_| panic!("{field} must be UTF-8"))
        }
        other => panic!("{field} must be a string, got {other:?}"),
    }
}

fn redis_optional_string(value: Option<&RedisValue>) -> Option<String> {
    match value {
        None | Some(RedisValue::Nil) => None,
        Some(value) => Some(redis_string(value, "optional string")),
    }
}

fn redis_i64(value: &RedisValue, field: &str) -> i64 {
    match value {
        RedisValue::Int(number) => *number,
        other => panic!("{field} must be an integer, got {other:?}"),
    }
}

fn redis_u16(value: &RedisValue, field: &str) -> u16 {
    u16::try_from(redis_i64(value, field)).unwrap_or_else(|_| panic!("{field} must fit in u16"))
}
