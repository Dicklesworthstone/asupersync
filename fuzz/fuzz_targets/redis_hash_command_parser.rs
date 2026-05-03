#![no_main]

use arbitrary::Arbitrary;
use asupersync::{
    messaging::redis::{RedisClient, RedisError, RespValue},
    test_utils::run_test_with_cx,
};
use libfuzzer_sys::fuzz_target;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

const MAX_KEY_BYTES: usize = 128;
const MAX_FIELD_BYTES: usize = 128;
const MAX_VALUE_BYTES: usize = 512;

#[derive(Debug, Arbitrary, Clone)]
struct HashCommandCase {
    key: Vec<u8>,
    field: Vec<u8>,
    value: Vec<u8>,
    wrapper_scenario: WrapperScenario,
}

#[derive(Debug, Arbitrary, Clone, Copy)]
enum WrapperScenario {
    Hit,
    Miss,
    HSetWrongType,
    HGetWrongType,
}

fuzz_target!(|case: HashCommandCase| {
    let case = case.sanitize();
    run_test_with_cx(|cx| async move {
        exercise_binary_pipeline(&cx, &case).await;
        if let (Ok(key), Ok(field)) = (
            String::from_utf8(case.key.clone()),
            String::from_utf8(case.field.clone()),
        ) {
            exercise_wrappers(&cx, &key, &field, &case.value, case.wrapper_scenario).await;
        }
    });
});

impl HashCommandCase {
    fn sanitize(mut self) -> Self {
        self.key.truncate(MAX_KEY_BYTES);
        self.field.truncate(MAX_FIELD_BYTES);
        self.value.truncate(MAX_VALUE_BYTES);
        self
    }
}

async fn exercise_binary_pipeline(cx: &asupersync::cx::Cx, case: &HashCommandCase) {
    let key = case.key.clone();
    let field = case.field.clone();
    let value = case.value.clone();
    let (addr, server) = start_server(move |stream| {
        handshake_resp3(stream);

        let hset = read_resp_frame(stream);
        assert_resp_command(hset, &[b"HSET".as_slice(), &key, &field, &value]);
        let hget = read_resp_frame(stream);
        assert_resp_command(hget, &[b"HGET".as_slice(), &key, &field]);

        stream
            .write_all(&RespValue::Integer(1).encode())
            .expect("write HSET integer reply");
        stream.flush().expect("flush HSET integer reply");
        stream
            .write_all(&RespValue::BulkString(Some(value.clone())).encode())
            .expect("write HGET bulk reply");
        stream.flush().expect("flush HGET bulk reply");
    });

    let client = connect_client(cx, addr).await;
    let mut pipeline = client.pipeline();
    pipeline
        .cmd_bytes(&[b"HSET".as_slice(), &case.key, &case.field, &case.value])
        .cmd_bytes(&[b"HGET".as_slice(), &case.key, &case.field]);
    let results = pipeline
        .exec(cx)
        .await
        .expect("binary hash pipeline should complete");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0], Ok(RespValue::Integer(1)));
    assert_eq!(
        results[1],
        Ok(RespValue::BulkString(Some(case.value.clone())))
    );
    server
        .join()
        .expect("binary pipeline fake redis server join");
}

async fn exercise_wrappers(
    cx: &asupersync::cx::Cx,
    key: &str,
    field: &str,
    value: &[u8],
    scenario: WrapperScenario,
) {
    let key_bytes = key.as_bytes().to_vec();
    let field_bytes = field.as_bytes().to_vec();
    let value_bytes = value.to_vec();

    let (addr, server) = start_server(move |stream| {
        handshake_resp3(stream);

        match scenario {
            WrapperScenario::Hit => {
                let hset = read_resp_frame(stream);
                assert_resp_command(
                    hset,
                    &[b"HSET".as_slice(), &key_bytes, &field_bytes, &value_bytes],
                );
                stream
                    .write_all(&RespValue::Integer(1).encode())
                    .expect("write HSET hit reply");
                stream.flush().expect("flush HSET hit reply");

                let hget = read_resp_frame(stream);
                assert_resp_command(hget, &[b"HGET".as_slice(), &key_bytes, &field_bytes]);
                stream
                    .write_all(&RespValue::BulkString(Some(value_bytes.clone())).encode())
                    .expect("write HGET hit reply");
                stream.flush().expect("flush HGET hit reply");
            }
            WrapperScenario::Miss => {
                let hset = read_resp_frame(stream);
                assert_resp_command(
                    hset,
                    &[b"HSET".as_slice(), &key_bytes, &field_bytes, &value_bytes],
                );
                stream
                    .write_all(&RespValue::Integer(0).encode())
                    .expect("write HSET miss reply");
                stream.flush().expect("flush HSET miss reply");

                let hget = read_resp_frame(stream);
                assert_resp_command(hget, &[b"HGET".as_slice(), &key_bytes, &field_bytes]);
                stream
                    .write_all(&RespValue::BulkString(None).encode())
                    .expect("write HGET nil reply");
                stream.flush().expect("flush HGET nil reply");
            }
            WrapperScenario::HSetWrongType => {
                let hset = read_resp_frame(stream);
                assert_resp_command(
                    hset,
                    &[b"HSET".as_slice(), &key_bytes, &field_bytes, &value_bytes],
                );
                stream
                    .write_all(&RespValue::BulkString(Some(b"wrong".to_vec())).encode())
                    .expect("write HSET wrong-type reply");
                stream.flush().expect("flush HSET wrong-type reply");
            }
            WrapperScenario::HGetWrongType => {
                let hset = read_resp_frame(stream);
                assert_resp_command(
                    hset,
                    &[b"HSET".as_slice(), &key_bytes, &field_bytes, &value_bytes],
                );
                stream
                    .write_all(&RespValue::Integer(1).encode())
                    .expect("write HSET ok reply");
                stream.flush().expect("flush HSET ok reply");

                let hget = read_resp_frame(stream);
                assert_resp_command(hget, &[b"HGET".as_slice(), &key_bytes, &field_bytes]);
                stream
                    .write_all(&RespValue::Integer(9).encode())
                    .expect("write HGET wrong-type reply");
                stream.flush().expect("flush HGET wrong-type reply");
            }
        }
    });

    let client = connect_client(cx, addr).await;

    match scenario {
        WrapperScenario::Hit => {
            let inserted = client
                .hset(cx, key, field, value)
                .await
                .expect("HSET hit should parse cleanly");
            assert!(inserted);

            let fetched = client
                .hget(cx, key, field)
                .await
                .expect("HGET hit should parse cleanly");
            assert_eq!(fetched, Some(value.to_vec()));
        }
        WrapperScenario::Miss => {
            let inserted = client
                .hset(cx, key, field, value)
                .await
                .expect("HSET miss/update should parse cleanly");
            assert!(!inserted);

            let fetched = client
                .hget(cx, key, field)
                .await
                .expect("HGET nil should parse cleanly");
            assert_eq!(fetched, None);
        }
        WrapperScenario::HSetWrongType => {
            let err = client
                .hset(cx, key, field, value)
                .await
                .expect_err("malformed HSET reply must fail closed");
            assert!(
                matches!(err, RedisError::Protocol(msg) if msg.contains("HSET did not return integer"))
            );
        }
        WrapperScenario::HGetWrongType => {
            let inserted = client
                .hset(cx, key, field, value)
                .await
                .expect("HSET before malformed HGET should parse cleanly");
            assert!(inserted);

            let err = client
                .hget(cx, key, field)
                .await
                .expect_err("malformed HGET reply must fail closed");
            assert!(
                matches!(err, RedisError::Protocol(msg) if msg.contains("HGET expected bulk string"))
            );
        }
    }
    server.join().expect("wrapper fake redis server join");
}

async fn connect_client(cx: &asupersync::cx::Cx, addr: SocketAddr) -> RedisClient {
    RedisClient::connect(cx, &format!("redis://{}:{}/0", addr.ip(), addr.port()))
        .await
        .expect("connect fake redis client")
}

fn start_server(
    handler: impl FnOnce(&mut TcpStream) + Send + 'static,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake redis listener");
    let addr = listener.local_addr().expect("fake redis listener addr");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fake redis client");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set fake redis read timeout");
        handler(&mut stream);
    });
    (addr, handle)
}

fn handshake_resp3(stream: &mut TcpStream) {
    let hello = read_resp_frame(stream);
    assert_resp_command(hello, &[b"HELLO", b"3"]);
    let hello_reply = RespValue::Map(vec![(
        RespValue::SimpleString("proto".to_string()),
        RespValue::Integer(3),
    )])
    .encode();
    stream
        .write_all(&hello_reply)
        .expect("write fake redis HELLO reply");
    stream.flush().expect("flush fake redis HELLO reply");
}

fn read_resp_frame(stream: &mut TcpStream) -> RespValue {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some((value, consumed)) =
            RespValue::try_decode(&buf).expect("server should decode RESP command")
        {
            assert_eq!(
                consumed,
                buf.len(),
                "expected exactly one RESP frame per server phase"
            );
            return value;
        }
        let n = stream.read(&mut chunk).expect("read client RESP frame");
        assert!(n > 0, "client closed before sending a full RESP frame");
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
    assert_eq!(actual, expected, "unexpected RESP command frame");
}
