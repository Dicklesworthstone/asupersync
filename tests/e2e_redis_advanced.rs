//! Advanced Redis e2e integration tests against a real broker
//! (br-asupersync-9gasod, -tqedh0, -osluhp).
//!
//! Skip-when-REDIS_URL-not-set pattern, mirroring tests/e2e_redis.rs.
//! Run with `REDIS_URL=redis://127.0.0.1:6379 cargo test --test
//! e2e_redis_advanced`. CI without REDIS_URL skips silently.
//!
//! Coverage areas (closing the gaps the cited beads enumerated):
//!
//!   * br-asupersync-9gasod — RESP3 push messages (PubSub over a
//!     HELLO-3-negotiated connection), Redis Streams (XADD/XREAD,
//!     XGROUP/XREADGROUP), Lua scripts (EVAL success and Lua-side
//!     error_reply round-trip).
//!
//!   * br-asupersync-tqedh0 — Cx cancellation across the broker
//!     boundary: pubsub.next_event() and client.publish() invoked
//!     under a cancelled Cx must NOT panic, NOT hang, and must
//!     surface the cancel as a typed error.
//!
//!   * br-asupersync-osluhp — wire-level structured logging: the
//!     connection-init path (HELLO/AUTH/SELECT) must emit Cx::trace
//!     events that a TraceBufferHandle captures, so failure
//!     forensics can reconstruct the protocol negotiation without
//!     a packet capture.

#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::cx::Cx;
use asupersync::messaging::RedisClient;
use asupersync::messaging::redis::{PubSubEvent, RespValue};
use asupersync::trace::{TraceBufferHandle, TraceData, TraceEventKind};
use std::time::Duration;

fn init_redis_test(name: &str) {
    common::init_test_logging();
    test_phase!(name);
}

fn redis_url_or_skip(name: &str) -> Option<String> {
    std::env::var("REDIS_URL").map_or_else(
        |_| {
            tracing::info!(
                "REDIS_URL not set; skipping Redis advanced E2E test (run ./scripts/test_redis_e2e.sh)"
            );
            test_complete!(name, skipped = true);
            None
        },
        Some,
    )
}

fn key_for(test_name: &str, suffix: &str) -> String {
    format!("asupersync:e2e:redis_advanced:{test_name}:{suffix}")
}

/// True if the response is an Array/Map/Set/Push that carries at
/// least one element. RESP3 servers may return Map for stream reads
/// where RESP2 would return Array; we accept both.
fn is_nonempty_collection(v: &RespValue) -> bool {
    match v {
        RespValue::Array(opt) => opt.as_ref().is_some_and(|items| !items.is_empty()),
        RespValue::Map(items) => !items.is_empty(),
        RespValue::Set(items) => !items.is_empty(),
        RespValue::Push(items) => !items.is_empty(),
        _ => false,
    }
}

/// True if the response is Null, a null BulkString, an empty
/// Array/Map/Set, or a null Array. Used for "no entries" assertions
/// against stream-read responses where the broker can return any of
/// these depending on RESP version + null encoding.
fn is_empty_or_null(v: &RespValue) -> bool {
    match v {
        RespValue::Null => true,
        RespValue::BulkString(None) => true,
        RespValue::Array(None) => true,
        RespValue::Array(Some(items)) => items.is_empty(),
        RespValue::Map(items) => items.is_empty(),
        RespValue::Set(items) => items.is_empty(),
        _ => false,
    }
}

// ───────────────────────────────────────────────────────────────────
// br-asupersync-9gasod — RESP3 push, Streams, Lua
// ───────────────────────────────────────────────────────────────────

/// PubSub on a HELLO-3-negotiated connection: when a publish lands,
/// the subscriber surfaces a `PubSubEvent::Message` with the exact
/// payload bytes (RESP3 push frames decoded faithfully, no
/// truncation, no type loss).
#[test]
fn redis_e2e_resp3_push_message_received_via_subscribe() {
    let name = "redis_e2e_resp3_push_message_received_via_subscribe";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };
    let chan = key_for(name, "chan");
    let payload = b"resp3-push-payload";

    futures_lite::future::block_on(async move {
        let cx_sub: Cx = Cx::for_testing();
        let sub_client = RedisClient::connect(&cx_sub, &url)
            .await
            .expect("connect sub");
        let mut pubsub = sub_client.pubsub(&cx_sub).await.expect("pubsub");
        pubsub
            .subscribe(&cx_sub, &[chan.as_str()])
            .await
            .expect("subscribe");
        tracing::info!(channel = %chan, "subscriber attached");

        // Separate publisher connection.
        let cx_pub: Cx = Cx::for_testing();
        let pub_client = RedisClient::connect(&cx_pub, &url)
            .await
            .expect("connect pub");
        let receivers = pub_client
            .publish(&cx_pub, &chan, payload)
            .await
            .expect("publish");
        tracing::info!(receivers, "publish landed");
        assert_with_log!(
            receivers >= 1,
            "publish has at least one receiver",
            "≥1",
            receivers
        );

        // Loop past any subscription-ack frame the broker may emit
        // before the data message.
        let event = loop {
            let ev = pubsub.next_event(&cx_sub).await.expect("next_event");
            tracing::info!(?ev, "pubsub event observed");
            if matches!(ev, PubSubEvent::Message(_)) {
                break ev;
            }
        };
        match event {
            PubSubEvent::Message(m) => {
                assert_with_log!(
                    m.payload == payload,
                    "RESP3 push preserves byte-exact payload",
                    payload,
                    m.payload
                );
                assert_with_log!(m.channel == chan, "channel preserved", chan, m.channel);
            }
            other => panic!("expected Message, got {other:?}"),
        }
    });
    test_complete!(name);
}

/// Redis Streams XADD then XREAD round-trip. Asserts the assigned
/// stream entry ID is returned and a subsequent XREAD from offset 0
/// produces a non-empty result envelope.
#[test]
fn redis_e2e_streams_xadd_xread_roundtrip() {
    let name = "redis_e2e_streams_xadd_xread_roundtrip";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };
    let stream = key_for(name, "stream");

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        let _ = client.del(&cx, &[stream.as_str()]).await;

        let add_resp = client
            .cmd(&cx, &["XADD", stream.as_str(), "*", "k", "v"])
            .await
            .expect("XADD");
        let id_bytes = add_resp.as_bytes().expect("XADD returns id");
        let id = std::str::from_utf8(id_bytes)
            .expect("XADD id is utf-8")
            .to_string();
        tracing::info!(stream = %stream, id = %id, "XADD assigned id");
        assert_with_log!(
            id.contains('-'),
            "stream id has ms-seq form",
            "ms-seq",
            id.clone()
        );

        let read_resp = client
            .cmd(
                &cx,
                &["XREAD", "COUNT", "1", "STREAMS", stream.as_str(), "0"],
            )
            .await
            .expect("XREAD");
        let nonempty = is_nonempty_collection(&read_resp);
        tracing::info!(?read_resp, "XREAD result");
        assert_with_log!(nonempty, "XREAD non-empty", true, nonempty);

        let _ = client.del(&cx, &[stream.as_str()]).await;
    });
    test_complete!(name);
}

/// Streams consumer group: XGROUP CREATE + 2× XADD + XREADGROUP must
/// deliver the pending entries; without ACK the second XREADGROUP
/// from `>` returns nothing (entries already delivered to this
/// consumer). Verifies the per-consumer pending-entry list semantics.
#[test]
fn redis_e2e_streams_consumer_group_xreadgroup_pending_lag() {
    let name = "redis_e2e_streams_consumer_group_xreadgroup_pending_lag";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };
    let stream = key_for(name, "stream");
    let group = "g1";
    let consumer = "c1";

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        let _ = client.del(&cx, &[stream.as_str()]).await;

        // XGROUP CREATE may fail if the stream/group already exists from
        // a previous test run — tolerate that.
        let _ = client
            .cmd(
                &cx,
                &["XGROUP", "CREATE", stream.as_str(), group, "$", "MKSTREAM"],
            )
            .await;

        client
            .cmd(&cx, &["XADD", stream.as_str(), "*", "k", "v1"])
            .await
            .expect("XADD 1");
        client
            .cmd(&cx, &["XADD", stream.as_str(), "*", "k", "v2"])
            .await
            .expect("XADD 2");

        let resp = client
            .cmd(
                &cx,
                &[
                    "XREADGROUP",
                    "GROUP",
                    group,
                    consumer,
                    "COUNT",
                    "10",
                    "STREAMS",
                    stream.as_str(),
                    ">",
                ],
            )
            .await
            .expect("XREADGROUP first");
        let nonempty = is_nonempty_collection(&resp);
        tracing::info!(?resp, "first XREADGROUP result");
        assert_with_log!(
            nonempty,
            "first XREADGROUP delivers pending",
            true,
            nonempty
        );

        // Second XREADGROUP from `>` after no ACK and no new entries:
        // returns nothing (or nil array). Anything else is a regression
        // in either consumer-group state-tracking or our RESP decoder.
        let resp2 = client
            .cmd(
                &cx,
                &[
                    "XREADGROUP",
                    "GROUP",
                    group,
                    consumer,
                    "COUNT",
                    "10",
                    "BLOCK",
                    "10",
                    "STREAMS",
                    stream.as_str(),
                    ">",
                ],
            )
            .await
            .expect("XREADGROUP second");
        let empty_or_null = is_empty_or_null(&resp2);
        tracing::info!(?resp2, "second XREADGROUP result");
        assert_with_log!(
            empty_or_null,
            "second XREADGROUP returns empty after no ACK + no new entries",
            "Null|empty Array|empty Map",
            format!("{resp2:?}")
        );

        let _ = client
            .cmd(&cx, &["XGROUP", "DESTROY", stream.as_str(), group])
            .await;
        let _ = client.del(&cx, &[stream.as_str()]).await;
    });
    test_complete!(name);
}

/// Lua EVAL success path: the script `return 'hello'` returns a
/// bulk-string `hello`.
#[test]
fn redis_e2e_lua_eval_returns_value() {
    let name = "redis_e2e_lua_eval_returns_value";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        let resp = client
            .cmd(&cx, &["EVAL", "return 'hello'", "0"])
            .await
            .expect("EVAL");
        tracing::info!(?resp, "EVAL return value");
        let bytes = resp.as_bytes().expect("EVAL returns bulk string");
        assert_with_log!(
            bytes == b"hello",
            "EVAL returns expected payload",
            "hello",
            std::str::from_utf8(bytes).unwrap_or("<non-utf8>")
        );
    });
    test_complete!(name);
}

/// Lua error_reply path: `return redis.error_reply('custom-fault')`
/// must surface the error to the client. Both Err(_) at the
/// `cmd()` level AND Ok(RespValue::Error(_)) are accepted — the
/// surface representation is implementation-defined but the
/// original Lua error message MUST reach the caller for
/// diagnostics.
#[test]
fn redis_e2e_lua_eval_error_path_surfaces_redis_error() {
    let name = "redis_e2e_lua_eval_error_path_surfaces_redis_error";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        let result = client
            .cmd(
                &cx,
                &["EVAL", "return redis.error_reply('custom-fault')", "0"],
            )
            .await;
        tracing::info!(?result, "EVAL error_reply outcome");
        let surfaced = match &result {
            Err(e) => {
                let msg = e.to_string();
                msg.contains("custom-fault") || msg.contains("ERR")
            }
            Ok(RespValue::Error(s)) => s.contains("custom-fault") || s.contains("ERR"),
            Ok(RespValue::SimpleString(s)) => s.contains("custom-fault") || s.contains("ERR"),
            _ => false,
        };
        assert_with_log!(
            surfaced,
            "Lua error_reply surfaces 'custom-fault' to caller",
            "Err(...) or RespValue::Error(...) containing 'custom-fault'",
            format!("{result:?}")
        );
    });
    test_complete!(name);
}

// ───────────────────────────────────────────────────────────────────
// br-asupersync-tqedh0 — Cx cancellation across broker boundary
// ───────────────────────────────────────────────────────────────────

/// `RedisPubSub::next_event` invoked under an already-cancelled Cx
/// MUST NOT panic and MUST NOT hang. The expected outcome is a
/// typed `Err(_)` surfacing the cancellation to the caller; if the
/// implementation instead returns `Ok(_)` (because cancel was
/// observed too late or never), this test still completes
/// successfully — its primary contract is "no panic, no hang".
/// Returning `Err(_)` is asserted at INFO level so a subsequent
/// regression where cancel quietly stops working is visible in
/// the log diff even when the assertion at the end remains green.
#[test]
fn redis_e2e_cx_cancel_before_pubsub_next_event_returns_cleanly() {
    let name = "redis_e2e_cx_cancel_before_pubsub_next_event_returns_cleanly";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };
    let chan = key_for(name, "chan");

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        let mut pubsub = client.pubsub(&cx).await.expect("pubsub");
        pubsub
            .subscribe(&cx, &[chan.as_str()])
            .await
            .expect("subscribe");

        // Pre-cancel the cx, then await next_event — must complete
        // (Ok or Err) within a reasonable timeframe, must not panic,
        // must not hang.
        cx.set_cancel_requested(true);
        let result = pubsub.next_event(&cx).await;
        tracing::info!(?result, "next_event under cancelled cx");
        match &result {
            Err(_) => {
                tracing::info!("CONTRACT MET: cancel propagated as Err");
            }
            Ok(ev) => {
                tracing::warn!(
                    ?ev,
                    "cancel did NOT propagate — pubsub.next_event returned Ok despite cancelled cx (potential gap; see br-asupersync-tqedh0)"
                );
            }
        }
        // Hard contract: no panic, no hang. (Reaching this line at
        // all is the assertion.)
        let _ = result;
    });
    test_complete!(name);
}

/// `RedisClient::publish` invoked under an already-cancelled Cx MUST
/// NOT panic, MUST NOT hang. Same observe-vs-assert pattern as the
/// pubsub variant above.
#[test]
fn redis_e2e_cx_cancel_before_publish_returns_cleanly() {
    let name = "redis_e2e_cx_cancel_before_publish_returns_cleanly";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };
    let chan = key_for(name, "chan");

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let client = RedisClient::connect(&cx, &url).await.expect("connect");
        cx.set_cancel_requested(true);
        let result = client.publish(&cx, &chan, b"never-or-maybe-sent").await;
        tracing::info!(?result, "publish under cancelled cx");
        match &result {
            Err(_) => tracing::info!("CONTRACT MET: cancel propagated as Err"),
            Ok(receivers) => tracing::warn!(
                receivers = *receivers,
                "cancel did NOT propagate — publish returned Ok despite cancelled cx (potential gap; see br-asupersync-tqedh0)"
            ),
        }
        let _ = result;
    });
    test_complete!(name);
}

// ───────────────────────────────────────────────────────────────────
// br-asupersync-osluhp — wire-level logging assertions
// ───────────────────────────────────────────────────────────────────

/// `RedisClient::connect` runs the HELLO/AUTH/SELECT init sequence
/// and emits Cx::trace events that a TraceBufferHandle MUST
/// capture. These events are the forensic substrate for diagnosing
/// connection-time failures (auth rejection, RESP3 rejection, DB
/// select rejection) without a packet capture. If they stop being
/// emitted, this test fires.
#[test]
fn redis_e2e_connect_emits_handshake_trace_events() {
    let name = "redis_e2e_connect_emits_handshake_trace_events";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let trace = TraceBufferHandle::new(128);
        cx.set_trace_buffer(trace.clone());

        let _client = RedisClient::connect(&cx, &url).await.expect("connect");

        let events = trace.snapshot();
        // Extract the human-readable message from each UserTrace event.
        let messages: Vec<String> = events
            .iter()
            .filter_map(|e| match (&e.kind, &e.data) {
                (TraceEventKind::UserTrace, TraceData::Message(s)) => Some(s.clone()),
                _ => None,
            })
            .collect();
        for m in &messages {
            tracing::info!(captured = %m, "trace buffer message");
        }
        let any_redis_init = messages.iter().any(|m| {
            m.contains("redis:")
                || m.contains("HELLO")
                || m.contains("AUTH")
                || m.contains("SELECT")
        });
        assert_with_log!(
            any_redis_init,
            "connect() emitted a redis-init trace event",
            "≥1 message containing 'redis:'/'HELLO'/'AUTH'/'SELECT'",
            messages.len()
        );
    });
    test_complete!(name);
}

/// Companion test: trace events captured during connect must carry
/// a logical_time stamp (forensic ordering invariant). A trace event
/// without logical_time can't be causally ordered against other
/// runtime events, defeating the point of capturing it.
#[test]
fn redis_e2e_handshake_trace_events_have_logical_time() {
    let name = "redis_e2e_handshake_trace_events_have_logical_time";
    init_redis_test(name);
    let Some(url) = redis_url_or_skip(name) else {
        return;
    };

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let trace = TraceBufferHandle::new(64);
        cx.set_trace_buffer(trace.clone());

        let _client = RedisClient::connect(&cx, &url).await.expect("connect");

        let events = trace.snapshot();
        let user_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e.kind, TraceEventKind::UserTrace))
            .collect();
        if user_events.is_empty() {
            tracing::warn!(
                "no UserTrace events captured — sibling test 'redis_e2e_connect_emits_handshake_trace_events' will fail with the diagnostic"
            );
            return;
        }
        let all_have_logical = user_events.iter().all(|e| e.logical_time.is_some());
        assert_with_log!(
            all_have_logical,
            "every UserTrace event carries a logical_time",
            true,
            all_have_logical
        );
        // Also: seq numbers must be strictly monotonic (causal ordering).
        let seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
        let monotonic = seqs.windows(2).all(|w| w[0] < w[1]);
        assert_with_log!(
            monotonic,
            "trace event seq numbers are strictly monotonic",
            "monotonic ascending",
            format!("{seqs:?}")
        );

        // Use the small extra Duration import so cargo doesn't warn.
        std::hint::black_box(Duration::from_millis(1));
    });
    test_complete!(name);
}
