#![allow(missing_docs)]

#[macro_use]
mod common;

#[path = "e2e/redis/mod.rs"]
mod redis_e2e;

use asupersync::cx::Cx;
use asupersync::messaging::RedisClient;
use asupersync::messaging::redis::RespValue;
use std::time::Duration;

fn init_redis_test(name: &str) {
    common::init_test_logging();
    test_phase!(name);
}

fn redis_url_or_skip(name: &str) -> Option<String> {
    std::env::var("REDIS_URL").map_or_else(
        |_| {
            tracing::info!(
                "REDIS_URL not set; skipping Redis E2E test (run ./scripts/test_redis_e2e.sh)"
            );
            test_complete!(name, skipped = true);
            None
        },
        Some,
    )
}

fn key_for(test_name: &str, suffix: &str) -> String {
    format!("asupersync:e2e:redis:{test_name}:{suffix}")
}

#[test]
fn redis_e2e_ping_returns_pong() {
    let name = "redis_e2e_ping_returns_pong";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        let resp = client.cmd(&cx, &["PING"]).await.expect("PING");
        assert_with_log!(
            resp == RespValue::SimpleString("PONG".to_string()),
            "PING response",
            RespValue::SimpleString("PONG".to_string()),
            resp
        );
    });

    test_complete!(name);
}

#[test]
fn redis_e2e_cmd_echo_returns_bulk_string() {
    let name = "redis_e2e_cmd_echo_returns_bulk_string";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        let resp = client.cmd(&cx, &["ECHO", "hello"]).await.expect("ECHO");
        assert_with_log!(
            resp == RespValue::BulkString(Some(b"hello".to_vec())),
            "ECHO response",
            RespValue::BulkString(Some(b"hello".to_vec())),
            resp
        );
    });

    test_complete!(name);
}

#[test]
fn redis_e2e_set_get_roundtrip() {
    let name = "redis_e2e_set_get_roundtrip";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };
    let key = key_for(name, "value");

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        client.set(&cx, &key, b"hello", None).await.expect("SET");
        let got = client.get(&cx, &key).await.expect("GET");
        assert_with_log!(got.as_deref() == Some(b"hello"), "GET", Some(b"hello"), got);
        let _ = client.del(&cx, &[&key]).await;
    });

    test_complete!(name);
}

#[test]
fn redis_e2e_get_missing_returns_none() {
    let name = "redis_e2e_get_missing_returns_none";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };
    let key = key_for(name, "missing");

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        let got = client.get(&cx, &key).await.expect("GET");
        assert_with_log!(got.is_none(), "missing key", true, got.is_none());
    });

    test_complete!(name);
}

#[test]
fn redis_e2e_incr_increments_from_zero() {
    let name = "redis_e2e_incr_increments_from_zero";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };
    let key = key_for(name, "counter");

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        client.set(&cx, &key, b"0", None).await.expect("SET");
        let value = client.incr(&cx, &key).await.expect("INCR");
        assert_with_log!(value == 1, "counter increments", 1, value);
        let _ = client.del(&cx, &[&key]).await;
    });

    test_complete!(name);
}

#[test]
fn redis_e2e_del_removes_multiple_keys() {
    let name = "redis_e2e_del_removes_multiple_keys";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };
    let key1 = key_for(name, "one");
    let key2 = key_for(name, "two");

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        client.set(&cx, &key1, b"a", None).await.expect("SET1");
        client.set(&cx, &key2, b"b", None).await.expect("SET2");
        let removed = client.del(&cx, &[&key1, &key2]).await.expect("DEL");
        assert_with_log!(removed == 2, "removed count", 2, removed);
    });

    test_complete!(name);
}

#[test]
fn redis_e2e_expire_existing_and_missing() {
    let name = "redis_e2e_expire_existing_and_missing";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };
    let key = key_for(name, "expire");

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        client.set(&cx, &key, b"expires", None).await.expect("SET");
        let ok = client
            .expire(&cx, &key, Duration::from_secs(60))
            .await
            .expect("EXPIRE");
        assert_with_log!(ok, "expire existing", true, ok);
        let missing = client
            .expire(&cx, &key_for(name, "missing"), Duration::from_secs(60))
            .await
            .expect("EXPIRE missing");
        assert_with_log!(!missing, "expire missing", false, missing);
        let _ = client.del(&cx, &[&key]).await;
    });

    test_complete!(name);
}

#[test]
fn redis_e2e_hash_roundtrip_and_delete() {
    let name = "redis_e2e_hash_roundtrip_and_delete";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };
    let key = key_for(name, "hash");
    let field = "field";

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        let inserted = client.hset(&cx, &key, field, b"v1").await.expect("HSET");
        assert_with_log!(inserted, "hset insert", true, inserted);
        let got = client.hget(&cx, &key, field).await.expect("HGET");
        assert_with_log!(got.as_deref() == Some(b"v1"), "hget", Some(b"v1"), got);
        let removed = client.hdel(&cx, &key, &[field]).await.expect("HDEL");
        assert_with_log!(removed == 1, "hdel count", 1, removed);
        let _ = client.del(&cx, &[&key]).await;
    });

    test_complete!(name);
}

#[test]
fn redis_e2e_pipeline_executes_multiple() {
    let name = "redis_e2e_pipeline_executes_multiple";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        let mut pipe = client.pipeline();
        pipe.cmd(&["PING"]);
        pipe.cmd(&["ECHO", "hi"]);
        let responses = pipe.exec(&cx).await.expect("pipeline");
        assert_with_log!(responses.len() == 2, "pipeline len", 2, responses.len());
        assert_with_log!(
            responses[0] == RespValue::SimpleString("PONG".to_string()),
            "pipeline ping",
            RespValue::SimpleString("PONG".to_string()),
            responses[0].clone()
        );
        assert_with_log!(
            responses[1] == RespValue::BulkString(Some(b"hi".to_vec())),
            "pipeline echo",
            RespValue::BulkString(Some(b"hi".to_vec())),
            responses[1].clone()
        );
    });

    test_complete!(name);
}

#[test]
fn redis_e2e_cmd_bytes_binary_echo() {
    let name = "redis_e2e_cmd_bytes_binary_echo";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        let payload = b"hi\x00there";
        let resp = client
            .cmd_bytes(&cx, &[b"ECHO", payload])
            .await
            .expect("ECHO");
        assert_with_log!(
            resp == RespValue::BulkString(Some(payload.to_vec())),
            "binary echo",
            RespValue::BulkString(Some(payload.to_vec())),
            resp
        );
    });

    test_complete!(name);
}
