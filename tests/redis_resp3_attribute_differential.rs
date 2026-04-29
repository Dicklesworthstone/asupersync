use asupersync::messaging::redis::RespValue;
use redis::{Value as RedisValue, parse_redis_value};

struct AttributeFixture {
    name: &'static str,
    wire: &'static [u8],
    expected_attributes: Vec<(RespValue, RespValue)>,
    expected_data: RespValue,
}

#[test]
fn resp3_attribute_frames_match_redis_rs_attribute_map_and_data() {
    let fixtures = vec![
        AttributeFixture {
            name: "bulk_string_with_two_attributes",
            wire: concat!(
                "|2\r\n",
                "+ttl\r\n",
                ":7\r\n",
                "+mode\r\n",
                "+hot\r\n",
                "$5\r\nvalue\r\n",
            )
            .as_bytes(),
            expected_attributes: vec![
                (
                    RespValue::SimpleString("ttl".to_string()),
                    RespValue::Integer(7),
                ),
                (
                    RespValue::SimpleString("mode".to_string()),
                    RespValue::SimpleString("hot".to_string()),
                ),
            ],
            expected_data: RespValue::BulkString(Some(b"value".to_vec())),
        },
        AttributeFixture {
            name: "array_with_boolean_attribute",
            wire: concat!(
                "|1\r\n",
                "+cached\r\n",
                "#t\r\n",
                "*2\r\n",
                ":1\r\n",
                "$5\r\nalpha\r\n",
            )
            .as_bytes(),
            expected_attributes: vec![(
                RespValue::SimpleString("cached".to_string()),
                RespValue::Boolean(true),
            )],
            expected_data: RespValue::Array(Some(vec![
                RespValue::Integer(1),
                RespValue::BulkString(Some(b"alpha".to_vec())),
            ])),
        },
    ];

    for fixture in fixtures {
        let (our_attributes, our_data) = ours_parse_attribute_reply(fixture.wire);
        let (redis_attributes, redis_data) = redis_rs_parse_attribute_reply(fixture.wire);

        assert_eq!(
            our_attributes, fixture.expected_attributes,
            "{} asupersync attributes",
            fixture.name
        );
        assert_eq!(
            our_data, fixture.expected_data,
            "{} asupersync data",
            fixture.name
        );
        assert_eq!(
            redis_attributes, fixture.expected_attributes,
            "{} redis-rs attributes",
            fixture.name
        );
        assert_eq!(
            redis_data, fixture.expected_data,
            "{} redis-rs data",
            fixture.name
        );
        assert_eq!(
            our_attributes, redis_attributes,
            "{} attribute parity",
            fixture.name
        );
        assert_eq!(our_data, redis_data, "{} data parity", fixture.name);
    }
}

fn ours_parse_attribute_reply(wire: &[u8]) -> (Vec<(RespValue, RespValue)>, RespValue) {
    let Some((attributes, consumed)) =
        RespValue::try_decode(wire).expect("attribute-prefixed reply must parse")
    else {
        panic!("attribute-prefixed reply must be complete");
    };
    let RespValue::Attribute(attributes) = attributes else {
        panic!("expected leading RESP3 attribute frame");
    };

    let Some((data, tail_consumed)) =
        RespValue::try_decode(&wire[consumed..]).expect("attribute payload value must parse")
    else {
        panic!("attribute payload value must be complete");
    };
    assert_eq!(
        consumed + tail_consumed,
        wire.len(),
        "attribute-prefixed reply must consume full wire"
    );

    (attributes, data)
}

fn redis_rs_parse_attribute_reply(wire: &[u8]) -> (Vec<(RespValue, RespValue)>, RespValue) {
    match parse_redis_value(wire).expect("redis-rs should parse attribute-prefixed reply") {
        RedisValue::Attribute { data, attributes } => (
            attributes
                .iter()
                .map(|(key, value)| (redis_value_to_resp(key), redis_value_to_resp(value)))
                .collect(),
            redis_value_to_resp(&data),
        ),
        other => panic!("redis-rs expected Value::Attribute, got {other:?}"),
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
        RedisValue::Boolean(value) => RespValue::Boolean(*value),
        RedisValue::Okay => RespValue::SimpleString("OK".to_string()),
        other => panic!("unsupported redis-rs value in RESP3 attribute differential: {other:?}"),
    }
}
