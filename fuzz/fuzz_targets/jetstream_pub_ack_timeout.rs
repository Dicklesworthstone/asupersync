#![no_main]

use arbitrary::Arbitrary;
use asupersync::{
    messaging::{
        jetstream::{JetStreamContext, JsError},
        nats::{NatsClient, NatsConfig, NatsError},
    },
    test_utils::{assert_completes_within, run_test_with_cx},
};
use libfuzzer_sys::fuzz_target;
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

const MAX_SUBJECT_TOKENS: usize = 4;
const MAX_TOKEN_BYTES: usize = 24;
const MAX_PAYLOAD_BYTES: usize = 256;

#[derive(Debug, Arbitrary)]
struct PubAckTimeoutCase {
    subject_tokens: Vec<Vec<u8>>,
    payload: Vec<u8>,
    timeout_millis: u8,
}

fuzz_target!(|case: PubAckTimeoutCase| {
    let subject = materialize_subject(&case.subject_tokens);
    let payload = bounded_payload(case.payload);
    let request_timeout = Duration::from_millis(u64::from(case.timeout_millis % 5) + 1);
    let (addr, server) = start_no_ack_server();

    run_test_with_cx(|cx| async move {
        assert_completes_within(
            Duration::from_secs(1),
            "JetStream publish without PubAck returns configured timeout",
            move || {
                let cx = cx.clone();
                let subject = subject.clone();
                let payload = payload.clone();
                Box::pin(async move {
                    let config = NatsConfig {
                        host: addr.ip().to_string(),
                        port: addr.port(),
                        request_timeout,
                        ..Default::default()
                    };
                    let client = NatsClient::connect_with_config(&cx, config)
                        .await
                        .expect("connect to no-ack NATS mock");
                    let mut js = JetStreamContext::new(client);
                    let err = js
                        .publish(&cx, &subject, &payload)
                        .await
                        .expect_err("missing PubAck must return timeout");
                    assert_pub_ack_timeout(err);
                })
            },
        )
        .await;
    });

    server.join().expect("no-ack NATS mock server join");
});

fn assert_pub_ack_timeout(err: JsError) {
    assert!(
        err.is_timeout(),
        "JetStream publish error must classify as timeout: {err:?}"
    );
    match err {
        JsError::Nats(NatsError::Io(io_err)) => {
            assert_eq!(io_err.kind(), io::ErrorKind::TimedOut);
        }
        other => panic!("missing PubAck must surface a NATS timed-out I/O error, got {other:?}"),
    }
}

fn start_no_ack_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind no-ack NATS listener");
    let addr = listener.local_addr().expect("no-ack NATS listener addr");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept NATS client");
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set NATS mock read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .expect("set NATS mock write timeout");
        stream
            .write_all(
                b"INFO {\"server_id\":\"id\",\"server_name\":\"fuzz\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576}\r\n",
            )
            .expect("write NATS INFO");
        stream.flush().expect("flush NATS INFO");

        let mut reader = BufReader::new(stream);
        let connect = read_protocol_line(&mut reader);
        assert!(
            connect.starts_with("CONNECT "),
            "unexpected NATS CONNECT frame: {connect:?}"
        );

        let subscribe = read_protocol_line(&mut reader);
        assert!(
            subscribe.starts_with("SUB _INBOX."),
            "unexpected NATS request subscription frame: {subscribe:?}"
        );

        let publish = read_protocol_line(&mut reader);
        assert!(
            publish.starts_with("PUB "),
            "unexpected JetStream publish frame: {publish:?}"
        );
        let payload_len = parse_request_payload_len(&publish);
        let mut payload = vec![0_u8; payload_len + 2];
        reader
            .read_exact(&mut payload)
            .expect("read JetStream publish payload");
        assert_eq!(&payload[payload_len..], b"\r\n");

        let unsubscribe = read_protocol_line(&mut reader);
        assert!(
            unsubscribe.starts_with("UNSUB "),
            "timeout cleanup must unsubscribe request inbox, got {unsubscribe:?}"
        );
    });
    (addr, handle)
}

fn read_protocol_line(reader: &mut BufReader<TcpStream>) -> String {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("read NATS protocol line");
    assert!(
        !line.is_empty(),
        "NATS mock connection closed before expected frame"
    );
    line
}

fn parse_request_payload_len(header: &str) -> usize {
    let parts: Vec<_> = header.split_whitespace().collect();
    assert_eq!(parts.first().copied(), Some("PUB"));
    assert_eq!(parts.len(), 4, "request publish must include reply-to");
    parts[3].parse().expect("parse request payload length")
}

fn materialize_subject(raw_tokens: &[Vec<u8>]) -> String {
    let mut tokens: Vec<String> = raw_tokens
        .iter()
        .take(MAX_SUBJECT_TOKENS)
        .map(|raw| materialize_token(raw))
        .collect();
    if tokens.is_empty() {
        tokens.push("events".to_string());
    }
    tokens.join(".")
}

fn materialize_token(raw: &[u8]) -> String {
    raw.iter()
        .copied()
        .chain(std::iter::repeat(b'a'))
        .take(raw.len().clamp(1, MAX_TOKEN_BYTES))
        .map(|byte| match byte % 36 {
            0..=25 => char::from(b'a' + (byte % 26)),
            _ => char::from(b'0' + (byte % 10)),
        })
        .collect()
}

fn bounded_payload(mut payload: Vec<u8>) -> Vec<u8> {
    payload.truncate(MAX_PAYLOAD_BYTES);
    payload
}
