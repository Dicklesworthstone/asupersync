//! Differential coverage for RESP3 BigNumber parsing against redis-rs.

use asupersync::messaging::redis::RespValue;
use redis::{Value as RedisValue, parse_redis_value};

struct BigNumberFixture {
    name: &'static str,
    wire: &'static [u8],
    expected_payload: &'static str,
    expected_redis_decimal: &'static str,
}

#[test]
fn resp3_big_numbers_match_redis_rs_for_protocol_decimal_forms() {
    let fixtures = [
        BigNumberFixture {
            name: "zero",
            wire: b"(0\r\n",
            expected_payload: "0",
            expected_redis_decimal: "0",
        },
        BigNumberFixture {
            name: "positive_huge",
            wire: b"(3492890328409238509324850943850943825024385\r\n",
            expected_payload: "3492890328409238509324850943850943825024385",
            expected_redis_decimal: "3492890328409238509324850943850943825024385",
        },
        BigNumberFixture {
            name: "negative_huge",
            wire: b"(-3492890328409238509324850943850943825024385\r\n",
            expected_payload: "-3492890328409238509324850943850943825024385",
            expected_redis_decimal: "-3492890328409238509324850943850943825024385",
        },
        BigNumberFixture {
            name: "explicit_plus",
            wire: b"(+42\r\n",
            expected_payload: "+42",
            expected_redis_decimal: "42",
        },
    ];

    for fixture in fixtures {
        let ours = ours_parse_big_number(fixture.wire);
        let redis_rs = redis_rs_parse_big_number(fixture.wire);

        assert_eq!(
            ours, fixture.expected_payload,
            "{} asupersync payload",
            fixture.name
        );
        assert_eq!(
            redis_rs, fixture.expected_redis_decimal,
            "{} redis-rs BigInt decimal",
            fixture.name
        );
    }
}

#[test]
fn resp3_big_numbers_reject_payloads_redis_rs_rejects() {
    let fixtures: [(&str, &[u8]); 7] = [
        ("empty", b"(\r\n"),
        ("plus_only", b"(+\r\n"),
        ("minus_only", b"(-\r\n"),
        ("double_plus", b"(++1\r\n"),
        ("minus_plus", b"(-+1\r\n"),
        ("fractional", b"(1.5\r\n"),
        ("alpha", b"(12abc\r\n"),
    ];

    for (name, wire) in fixtures {
        let ours = RespValue::try_decode(wire);
        let redis_rs = parse_redis_value(wire);

        assert!(ours.is_err(), "{name} asupersync should reject");
        assert!(redis_rs.is_err(), "{name} redis-rs should reject");
    }
}

fn ours_parse_big_number(wire: &[u8]) -> String {
    let Some((value, consumed)) =
        RespValue::try_decode(wire).expect("asupersync should parse RESP3 BigNumber wire")
    else {
        panic!("RESP3 BigNumber wire should be complete");
    };
    assert_eq!(consumed, wire.len(), "asupersync consumed bytes");

    match value {
        RespValue::BigNumber(payload) => payload,
        other => panic!("asupersync expected RESP3 BigNumber, got {other:?}"),
    }
}

fn redis_rs_parse_big_number(wire: &[u8]) -> String {
    match parse_redis_value(wire).expect("redis-rs should parse RESP3 BigNumber wire") {
        RedisValue::BigNumber(value) => value.to_string(),
        other => panic!("redis-rs expected BigNumber, got {other:?}"),
    }
}
