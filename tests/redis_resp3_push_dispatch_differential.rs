//! Differential RESP3 push dispatch parity tests against redis-rs.

use asupersync::messaging::redis::RespValue;
use redis::{Value as RedisValue, parse_redis_value};

struct PushDispatchFixture {
    name: &'static str,
    wire: &'static [u8],
    expected_kind: &'static str,
    expected_data: Vec<RespValue>,
}

#[test]
fn resp3_push_dispatch_matches_redis_rs_for_invalidate_and_tracking() {
    let fixtures = vec![
        PushDispatchFixture {
            name: "invalidate",
            wire: concat!(
                ">2\r\n",
                "+invalidate\r\n",
                "*2\r\n",
                "$5\r\nalpha\r\n",
                "$4\r\nbeta\r\n",
            )
            .as_bytes(),
            expected_kind: "invalidate",
            expected_data: vec![RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"alpha".to_vec())),
                RespValue::BulkString(Some(b"beta".to_vec())),
            ]))],
        },
        PushDispatchFixture {
            name: "tracking",
            wire: concat!(">3\r\n", "+tracking\r\n", "$5\r\nalpha\r\n", ":7\r\n",).as_bytes(),
            expected_kind: "tracking",
            expected_data: vec![
                RespValue::BulkString(Some(b"alpha".to_vec())),
                RespValue::Integer(7),
            ],
        },
    ];

    for fixture in fixtures {
        let (decoded, consumed) = RespValue::try_decode(fixture.wire)
            .expect("RESP3 push wire should not error")
            .expect("RESP3 push wire should decode");
        assert_eq!(
            consumed,
            fixture.wire.len(),
            "{} push must consume the entire frame",
            fixture.name
        );
        assert_eq!(
            decoded.encode(),
            fixture.wire,
            "{} push must round-trip byte-for-byte",
            fixture.name
        );

        let (our_kind, our_data) = ours_dispatch(decoded);
        let (redis_kind, redis_data) = redis_rs_dispatch(fixture.wire);

        assert_eq!(our_kind, fixture.expected_kind, "{} kind", fixture.name);
        assert_eq!(our_data, fixture.expected_data, "{} data", fixture.name);
        assert_eq!(
            redis_kind, fixture.expected_kind,
            "{} redis-rs kind",
            fixture.name
        );
        assert_eq!(
            redis_data, fixture.expected_data,
            "{} redis-rs data",
            fixture.name
        );
        assert_eq!(our_kind, redis_kind, "{} kind parity", fixture.name);
        assert_eq!(our_data, redis_data, "{} data parity", fixture.name);
    }
}

fn ours_dispatch(value: RespValue) -> (String, Vec<RespValue>) {
    match value {
        RespValue::Push(mut items) => {
            let kind = decode_kind(items.remove(0));
            (kind, items)
        }
        other => panic!("expected RESP3 push frame, got {other:?}"),
    }
}

fn redis_rs_dispatch(wire: &[u8]) -> (String, Vec<RespValue>) {
    match parse_redis_value(wire).expect("redis-rs should parse RESP3 push wire") {
        RedisValue::Push { kind, data } => (
            kind.to_string(),
            data.iter().map(redis_value_to_resp).collect(),
        ),
        other => panic!("redis-rs expected push frame, got {other:?}"),
    }
}

fn decode_kind(value: RespValue) -> String {
    match value {
        RespValue::SimpleString(kind) => kind,
        RespValue::BulkString(Some(bytes)) => {
            String::from_utf8(bytes).expect("push kind should be valid UTF-8")
        }
        other => panic!("push kind must be text, got {other:?}"),
    }
}

fn redis_value_to_resp(value: &RedisValue) -> RespValue {
    match value {
        RedisValue::Nil => RespValue::Null,
        RedisValue::Int(value) => RespValue::Integer(*value),
        RedisValue::BulkString(bytes) => RespValue::BulkString(Some(bytes.clone())),
        RedisValue::Array(values) => {
            RespValue::Array(Some(values.iter().map(redis_value_to_resp).collect()))
        }
        RedisValue::SimpleString(value) => RespValue::SimpleString(value.clone()),
        other => panic!("unexpected redis-rs push payload value {other:?}"),
    }
}
