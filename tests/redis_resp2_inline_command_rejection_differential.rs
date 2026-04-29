//! Differential conformance for RESP2 inline-command rejection parity.

use asupersync::messaging::redis::RespValue;
use redis::parse_redis_value;

struct InlineCommandFixture {
    name: &'static str,
    wire: &'static [u8],
}

#[test]
fn resp2_inline_command_bytes_are_rejected_like_redis_rs() {
    // redis-rs does not expose a legacy inline-command fallback parser; it
    // rejects these bytes as malformed RESP. Keep our low-level parser aligned
    // so a bare `PING\r\n` or `SET key value\r\n` cannot be misclassified as a
    // framed RESP value.
    let fixtures = [
        InlineCommandFixture {
            name: "ping",
            wire: b"PING\r\n",
        },
        InlineCommandFixture {
            name: "get_single_key",
            wire: b"GET cache:key\r\n",
        },
        InlineCommandFixture {
            name: "set_with_value",
            wire: b"SET cache:key value\r\n",
        },
        InlineCommandFixture {
            name: "hset_binaryish_value",
            wire: b"HSET cache hash-field bin\x00ary\r\n",
        },
    ];

    for fixture in fixtures {
        let ours = RespValue::try_decode(fixture.wire);
        let redis_rs = parse_redis_value(fixture.wire);

        assert!(
            ours.is_err(),
            "{} inline-command bytes must not decode as RESP in asupersync",
            fixture.name
        );
        assert!(
            redis_rs.is_err(),
            "{} inline-command bytes must not decode as RESP in redis-rs",
            fixture.name
        );
    }
}
