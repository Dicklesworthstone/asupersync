//! Differential checks for RESP3 map ordering and duplicate-key preservation.

use asupersync::messaging::redis::RespValue;

#[test]
fn resp3_map_duplicate_keys_preserve_pair_order_like_redis_rs() {
    // redis-rs models RESP3 maps as ordered Vec<(Value, Value)> pairs and
    // does not coalesce duplicate keys. Lock that duplicate-key ordering here
    // so the same wire bytes decode to the same pair sequence.
    let wire = concat!(
        "%3\r\n",
        "+dup\r\n",
        ":1\r\n",
        "+dup\r\n",
        ":2\r\n",
        "$4\r\nmode\r\n",
        "+standalone\r\n",
    )
    .as_bytes();

    let expected_pairs = vec![
        (
            RespValue::SimpleString("dup".to_string()),
            RespValue::Integer(1),
        ),
        (
            RespValue::SimpleString("dup".to_string()),
            RespValue::Integer(2),
        ),
        (
            RespValue::BulkString(Some(b"mode".to_vec())),
            RespValue::SimpleString("standalone".to_string()),
        ),
    ];

    let (decoded, consumed) = RespValue::try_decode(wire)
        .expect("RESP3 map wire should not error")
        .expect("RESP3 map wire should decode");

    assert_eq!(consumed, wire.len());
    assert_eq!(decoded, RespValue::Map(expected_pairs.clone()));
    assert_eq!(decoded.encode(), wire);

    match decoded {
        RespValue::Map(pairs) => assert_eq!(pairs, expected_pairs),
        other => panic!("expected RESP3 map, got {other:?}"),
    }
}
