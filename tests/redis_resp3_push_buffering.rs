#![allow(clippy::all)]
#![allow(missing_docs)]

use asupersync::cx::Cx;
use asupersync::messaging::RedisClient;
use asupersync::messaging::redis::{RedisClientTrackingPush, RedisResp3NonPubSubPush, RespValue};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

fn init_test(name: &str) {
    tracing::info!(test = name, "redis resp3 push buffering test start");
}

fn read_resp_frame(stream: &mut std::net::TcpStream) -> RespValue {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some((value, consumed)) =
            RespValue::try_decode(&buf).expect("fake redis server should decode RESP command")
        {
            assert_eq!(
                consumed,
                buf.len(),
                "fake redis server expected exactly one RESP frame per phase"
            );
            return value;
        }
        let n = stream.read(&mut chunk).expect("read client command");
        assert!(n > 0, "client closed before sending a full RESP command");
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn assert_resp_command(frame: RespValue, expected: &[&[u8]]) {
    let items = match frame {
        RespValue::Array(Some(items)) => items,
        other => panic!("expected RESP array command frame, got {other:?}"),
    };
    let actual: Vec<Vec<u8>> = items
        .into_iter()
        .map(|item| match item {
            RespValue::BulkString(Some(bytes)) => bytes,
            other => panic!("expected bulk-string command arg, got {other:?}"),
        })
        .collect();
    let expected: Vec<Vec<u8>> = expected.iter().map(|arg| arg.to_vec()).collect();
    assert_eq!(actual, expected, "unexpected RESP command");
}

fn write_hello3_ok(stream: &mut std::net::TcpStream) {
    let hello = read_resp_frame(stream);
    assert_resp_command(hello, &[b"HELLO", b"3"]);
    let hello_reply = RespValue::Map(vec![(
        RespValue::SimpleString("proto".to_string()),
        RespValue::Integer(3),
    )])
    .encode();
    stream.write_all(&hello_reply).expect("write HELLO reply");
    stream.flush().expect("flush HELLO reply");
}

fn buffer_fingerprint(bytes: &[u8]) -> String {
    let mut acc = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        acc ^= u64::from(byte);
        acc = acc.wrapping_mul(0x100_0000_01b3);
    }
    format!("{acc:016x}")
}

#[test]
fn redis_resp3_push_buffering_e2e_fake_server_interleaves_pushes_and_responses() {
    let name = "redis_resp3_push_buffering_e2e_fake_server_interleaves_pushes_and_responses";
    init_test(name);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake redis server");
    let addr = listener.local_addr().expect("listener addr");

    let first_buffer = {
        let mut bytes = Vec::new();
        RespValue::Push(vec![
            RespValue::BulkString(Some(b"invalidate".to_vec())),
            RespValue::Array(Some(vec![RespValue::BulkString(Some(
                b"cache-key".to_vec(),
            ))])),
        ])
        .encode_into(&mut bytes);
        RespValue::SimpleString("FIRST".to_string()).encode_into(&mut bytes);
        bytes
    };
    let second_buffer = {
        let mut bytes = Vec::new();
        RespValue::Push(vec![
            RespValue::BulkString(Some(b"monitor".to_vec())),
            RespValue::BulkString(Some(b"background-checkpoint".to_vec())),
        ])
        .encode_into(&mut bytes);
        RespValue::SimpleString("SECOND".to_string()).encode_into(&mut bytes);
        bytes
    };
    let combined_fingerprint = format!(
        "{}+{}",
        buffer_fingerprint(&first_buffer),
        buffer_fingerprint(&second_buffer)
    );

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept redis client");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        write_hello3_ok(&mut stream);

        let first = read_resp_frame(&mut stream);
        assert_resp_command(first, &[b"PING"]);
        stream
            .write_all(&first_buffer)
            .expect("write first push + response");
        stream.flush().expect("flush first push + response");

        let second = read_resp_frame(&mut stream);
        assert_resp_command(second, &[b"PING"]);
        stream
            .write_all(&second_buffer)
            .expect("write second push + response");
        stream.flush().expect("flush second push + response");
    });

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let url = format!("redis://{}:{}/0", addr.ip(), addr.port());
        let client = RedisClient::connect(&cx, &url).await.expect("connect");

        let first = client.cmd(&cx, &["PING"]).await.expect("first PING");
        let second = client.cmd(&cx, &["PING"]).await.expect("second PING");
        assert_eq!(first, RespValue::SimpleString("FIRST".to_string()));
        assert_eq!(second, RespValue::SimpleString("SECOND".to_string()));

        let push1 = client
            .try_next_resp3_push()
            .expect("push queue read")
            .expect("first push queued");
        let push2 = client
            .try_next_resp3_push()
            .expect("push queue read")
            .expect("second push queued");
        let push3 = client.try_next_resp3_push().expect("queue drained");
        assert_eq!(push3, None);

        tracing::info!(
            command_responses = 2usize,
            push_count = 2usize,
            queue_len_after_drain = client.resp3_pending_pushes(),
            dropped_pushes = client.resp3_dropped_pushes(),
            buffer_fingerprint = %combined_fingerprint,
            "redis RESP3 push buffering integration test"
        );

        assert_eq!(
            push1,
            RedisResp3NonPubSubPush::ClientTracking(RedisClientTrackingPush::Invalidate {
                keys: Some(vec![b"cache-key".to_vec()]),
            })
        );
        assert_eq!(
            push2,
            RedisResp3NonPubSubPush::Other {
                kind: "monitor".to_string(),
                payload: vec![RespValue::BulkString(Some(
                    b"background-checkpoint".to_vec(),
                ))],
            }
        );
    });

    server.join().expect("server join");
    tracing::info!(test = name, "redis resp3 push buffering test complete");
}
