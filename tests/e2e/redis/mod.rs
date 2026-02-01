//! Redis end-to-end (E2E) test suite.
//!
//! This test crate is intentionally split from unit tests:
//! - Unit tests live in `src/messaging/redis.rs`
//! - E2E tests validate the real-wire behavior against a live Redis server
//!
//! Run locally via:
//! - `./scripts/test_redis_e2e.sh`
//!
//! The tests in this module skip when `REDIS_URL` is not set.

use asupersync::cx::Cx;
use asupersync::messaging::redis::RespValue;
use asupersync::messaging::RedisClient;

fn init_redis_test(test_name: &str) {
    crate::common::init_test_logging();
    crate::test_phase!(test_name);
}

fn redis_url() -> Option<String> {
    std::env::var("REDIS_URL").ok()
}

#[test]
fn redis_e2e_get_set_incr_and_pipeline() {
    init_redis_test("redis_e2e_get_set_incr_and_pipeline");

    let Some(url) = redis_url() else {
        tracing::info!(
            "REDIS_URL not set; skipping Redis E2E test (run ./scripts/test_redis_e2e.sh)"
        );
        return;
    };

    futures_lite::future::block_on(async move {
        let cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).expect("connect");

        let key = "asupersync:e2e:redis:key";
        client.set(&cx, key, b"hello", None).await.expect("SET");
        let got = client.get(&cx, key).await.expect("GET").expect("value");
        assert_eq!(&got, b"hello");

        let counter = "asupersync:e2e:redis:counter";
        client
            .set(&cx, counter, b"0", None)
            .await
            .expect("SET counter");
        let n = client.incr(&cx, counter).await.expect("INCR");
        assert_eq!(n, 1);

        let mut pipe = client.pipeline();
        pipe.cmd(&["PING"]);
        pipe.cmd_bytes(&[b"ECHO", b"hi"]);
        let responses = pipe.exec(&cx).await.expect("pipeline exec");
        assert_eq!(responses.len(), 2);
        assert_eq!(
            responses[0],
            RespValue::SimpleString("PONG".to_string()),
            "PING"
        );
        assert_eq!(
            responses[1],
            RespValue::BulkString(Some(b"hi".to_vec())),
            "ECHO"
        );
    });
}
