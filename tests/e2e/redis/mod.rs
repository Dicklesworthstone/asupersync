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
use std::time::Duration;

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
        let client = RedisClient::connect(&cx, &url).await.expect("connect");

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

        let del1 = "asupersync:e2e:redis:del:1";
        let del2 = "asupersync:e2e:redis:del:2";
        client.set(&cx, del1, b"a", None).await.expect("SET del1");
        client.set(&cx, del2, b"b", None).await.expect("SET del2");
        let removed = client.del(&cx, &[del1, del2]).await.expect("DEL");
        assert_eq!(removed, 2);

        let exp_key = "asupersync:e2e:redis:expire:key";
        client
            .set(&cx, exp_key, b"expires", None)
            .await
            .expect("SET expire");
        assert!(
            client
                .expire(&cx, exp_key, Duration::from_secs(60))
                .await
                .expect("EXPIRE existing"),
            "EXPIRE should succeed for existing key"
        );
        assert!(
            !client
                .expire(
                    &cx,
                    "asupersync:e2e:redis:expire:missing",
                    Duration::from_secs(60)
                )
                .await
                .expect("EXPIRE missing"),
            "EXPIRE should return false for missing key"
        );

        let hash = "asupersync:e2e:redis:hash";
        let field = "field";
        assert!(
            client
                .hset(&cx, hash, field, b"v1")
                .await
                .expect("HSET insert"),
            "HSET should report insert"
        );
        assert!(
            !client
                .hset(&cx, hash, field, b"v2")
                .await
                .expect("HSET update"),
            "HSET should report update"
        );
        let got = client
            .hget(&cx, hash, field)
            .await
            .expect("HGET")
            .expect("hash value");
        assert_eq!(&got, b"v2");
        let removed = client.hdel(&cx, hash, &[field]).await.expect("HDEL");
        assert_eq!(removed, 1);
        assert!(
            client.hget(&cx, hash, field).await.expect("HGET").is_none(),
            "HGET should return None after HDEL"
        );

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
