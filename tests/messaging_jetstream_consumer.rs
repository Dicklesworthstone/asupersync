#![allow(missing_docs)]
//! br-asupersync-vu86e3 — e2e test for JetStream durable-consumer
//! create + pull semantics.
//!
//! ## Why an e2e test
//!
//! `src/messaging/jetstream.rs` carries the wire serialisation for
//! `ConsumerConfig` (`to_json`, file-private), the `pull_with_timeout`
//! pull-request body (`{"batch":N,"expires":<ns>}`), and the
//! durable-consumer ack-wait timeout that production relies on for
//! redelivery semantics. None of that has an e2e test against a
//! NATS+JetStream-protocol-speaking peer; the existing tests are
//! all in-process unit tests of the type's public surface. A
//! regression in the wire format (e.g. `ack_wait` accidentally
//! emitted in seconds instead of nanos, `deliver_policy` enum
//! renamed without updating the wire serialisation, pull-request
//! `expires` skipping the i64 clamp) would not be caught.
//!
//! ## What this test covers
//!
//! 1. **`create_consumer` wire format.** A mock NATS+JetStream
//!    server captures the PUB subject + payload that asupersync's
//!    `JetStreamContext::create_consumer` emits when given a
//!    `ConsumerConfig` with non-default `ack_policy`, `ack_wait`,
//!    `deliver_policy`, and `max_deliver`. The test asserts the
//!    PUB subject is the canonical `$JS.API.CONSUMER.CREATE.<stream>.<name>`
//!    form and that every config knob round-trips into the JSON
//!    payload at the right field name and unit.
//!
//! 2. **Durable-consumer ack-wait nanoseconds encoding.** Per the
//!    JetStream API contract `ack_wait` is in nanoseconds. The
//!    test sets `ack_wait` to a humane round number (5 seconds) and
//!    asserts the wire JSON contains the corresponding
//!    `5_000_000_000` ns literal — guarding against a regression
//!    that emits seconds, milliseconds, or `Display` formatting.
//!
//! 3. **Pull-request batch+expires parity.** After `create_consumer`,
//!    the test invokes `Consumer::pull_with_timeout` and the mock
//!    server captures the resulting `$JS.API.CONSUMER.MSG.NEXT.*`
//!    request payload. The test asserts the JSON contains both
//!    `"batch":N` and `"expires":<ns>` with the expected nanosecond
//!    encoding — pinning the contract that asupersync emits a
//!    pull-style request (not a push subscription) and that the
//!    deadline is correctly serialised.
//!
//! Note: this test does NOT cover the production NATS+JetStream
//! server. It pins the asupersync client's wire emission against
//! the JetStream protocol grammar, mirroring the e2e shape of
//! tests/messaging_nats_handshake.rs.

use asupersync::cx::Cx;
use asupersync::messaging::jetstream::{
    AckPolicy, ConsumerConfig, DeliverPolicy, JetStreamContext,
};
use asupersync::messaging::nats::NatsClient;
use asupersync::runtime::RuntimeBuilder;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// One captured NATS PUB command from the client.
#[derive(Debug, Clone)]
struct CapturedPub {
    /// Full subject (e.g. `$JS.API.CONSUMER.CREATE.ORDERS.payments`).
    subject: String,
    /// Reply-to subject the client provided (`_INBOX.<sid>.<rand>`).
    reply_to: String,
    /// The PUB payload bytes.
    payload: Vec<u8>,
}

/// Mock JetStream server. Runs on `std::thread`, owns a
/// `std::net::TcpListener`, performs the NATS handshake, then
/// services request/reply pairs by:
///   1. Accepting `SUB _INBOX.* <sid>` from the client.
///   2. Accepting `PUB $JS.API.<...>` with the inbox as reply-to.
///   3. Capturing the (subject, reply_to, payload) triple.
///   4. Replying with a synthetic JetStream API response on the
///      inbox subject so the client returns control to its caller.
struct MockJsServer {
    port: u16,
    captured: Arc<Mutex<Vec<CapturedPub>>>,
    /// One reply scripted per request, in order.
    /// Drained by the server thread as PUBs arrive.
    /// Each entry is `(subject_match_substring, reply_payload)`.
    /// The mock is dumb — it sends `reply_payload` as the MSG body
    /// for the next inbox the client subscribes to, regardless of
    /// content.
    _replies_handle: mpsc::Sender<(String, Vec<u8>)>,
}

impl MockJsServer {
    fn start() -> (Self, mpsc::Sender<(String, Vec<u8>)>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local_addr").port();
        let (replies_tx, replies_rx) = mpsc::channel::<(String, Vec<u8>)>();
        let captured: Arc<Mutex<Vec<CapturedPub>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_thread = Arc::clone(&captured);

        thread::spawn(move || {
            let (mut stream, _addr) = match listener.accept() {
                Ok(p) => p,
                Err(_) => return,
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .ok();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .ok();

            // 1. Send INFO. headers:true so JetStream's
            // publish_with_id path also works if the test ever
            // exercises it.
            let info = r#"INFO {"server_id":"mockjs","version":"0.0.0","go":"mock","host":"127.0.0.1","port":4222,"max_payload":1048576,"proto":1,"headers":true,"tls_required":false}"#;
            if stream.write_all(info.as_bytes()).is_err() {
                return;
            }
            if stream.write_all(b"\r\n").is_err() {
                return;
            }

            // 2. Read CONNECT.
            let read_stream = stream.try_clone().expect("clone");
            let mut reader = BufReader::new(read_stream);
            let mut connect_line = String::new();
            if reader.read_line(&mut connect_line).is_err() {
                return;
            }

            // 3. Service request/reply pairs. Each request is two
            // lines: SUB then PUB (the asupersync client subscribes
            // to its inbox before publishing the request — see
            // NatsClient::request at nats.rs:1437).
            loop {
                // SUB line.
                let mut sub_line = String::new();
                if reader.read_line(&mut sub_line).unwrap_or(0) == 0 {
                    return;
                }
                let sub_line = sub_line.trim_end_matches(['\r', '\n']).to_string();
                let inbox_subject = match parse_sub(&sub_line) {
                    Some((subject, _sid)) => subject,
                    None => continue,
                };

                // PUB line: parse `PUB <subject> <reply-to> <len>\r\n`.
                let mut pub_line = String::new();
                if reader.read_line(&mut pub_line).unwrap_or(0) == 0 {
                    return;
                }
                let pub_line = pub_line.trim_end_matches(['\r', '\n']).to_string();
                let (pub_subject, pub_reply, pub_len) = match parse_pub(&pub_line) {
                    Some(t) => t,
                    None => continue,
                };

                // Read the payload + trailing \r\n.
                let mut payload = vec![0u8; pub_len];
                if reader.read_exact(&mut payload).is_err() {
                    return;
                }
                let mut crlf = [0u8; 2];
                let _ = reader.read_exact(&mut crlf);

                if let Ok(mut cap) = captured_thread.lock() {
                    cap.push(CapturedPub {
                        subject: pub_subject.clone(),
                        reply_to: pub_reply.clone(),
                        payload,
                    });
                }

                // Find the first scripted reply whose subject-match
                // substring is contained in the PUB subject. If none
                // matches, send a generic empty body on the inbox.
                let reply_payload =
                    match replies_rx.try_recv() {
                        Ok((substring, body))
                            if substring.is_empty() || pub_subject.contains(&substring) =>
                        {
                            body
                        }
                        Ok(_) => Vec::new(),
                        Err(_) => Vec::new(),
                    };

                let header = format!(
                    "MSG {} 1 {}\r\n",
                    inbox_subject,
                    reply_payload.len()
                );
                if stream.write_all(header.as_bytes()).is_err() {
                    return;
                }
                if stream.write_all(&reply_payload).is_err() {
                    return;
                }
                if stream.write_all(b"\r\n").is_err() {
                    return;
                }
            }
        });

        (
            Self {
                port,
                captured,
                _replies_handle: replies_tx.clone(),
            },
            replies_tx,
        )
    }

    fn url(&self) -> String {
        format!("nats://127.0.0.1:{}", self.port)
    }

    fn captured(&self) -> Vec<CapturedPub> {
        self.captured.lock().unwrap().clone()
    }
}

/// Parse `SUB <subject> <sid>\r\n`.
fn parse_sub(line: &str) -> Option<(String, u64)> {
    let rest = line.strip_prefix("SUB ")?;
    let mut parts = rest.split_whitespace();
    let subject = parts.next()?.to_string();
    let sid = parts.next()?.parse().ok()?;
    Some((subject, sid))
}

/// Parse `PUB <subject> [<reply-to>] <len>\r\n`.
fn parse_pub(line: &str) -> Option<(String, String, usize)> {
    let rest = line.strip_prefix("PUB ")?;
    let parts: Vec<&str> = rest.split_whitespace().collect();
    match parts.len() {
        2 => Some((
            parts[0].to_string(),
            String::new(),
            parts[1].parse().ok()?,
        )),
        3 => Some((
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].parse().ok()?,
        )),
        _ => None,
    }
}

#[test]
fn jetstream_create_consumer_emits_canonical_wire_format_vu86e3() {
    let (server, replies_tx) = MockJsServer::start();
    let url = server.url();

    // Script the reply for the CONSUMER.CREATE request.
    // The client only consults the response for the consumer name
    // (extracted via extract_json_string_simple), so a minimal body
    // suffices.
    let create_reply = br#"{"name":"payments","stream_name":"ORDERS"}"#;
    replies_tx
        .send(("CONSUMER.CREATE".to_string(), create_reply.to_vec()))
        .expect("script reply");

    let runtime = RuntimeBuilder::new()
        .worker_threads(1)
        .build()
        .expect("build runtime");

    let outcome: Result<(), String> = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        let client = NatsClient::connect(&cx, &url)
            .await
            .map_err(|e| format!("connect: {e:?}"))?;
        let mut js = JetStreamContext::new(client);

        let cfg = ConsumerConfig::new("payments")
            .ack_policy(AckPolicy::Explicit)
            .ack_wait(Duration::from_secs(5))
            .deliver_policy(DeliverPolicy::All)
            .max_deliver(7);

        let _consumer = js
            .create_consumer(&cx, "ORDERS", cfg)
            .await
            .map_err(|e| format!("create_consumer: {e:?}"))?;
        Ok::<_, String>(())
    }));
    outcome.expect("create_consumer must succeed against mock");

    // Inspect the captured PUB. Exactly one PUB should have been
    // captured for the CONSUMER.CREATE request.
    let captured = server.captured();
    let create = captured
        .iter()
        .find(|c| c.subject.contains("CONSUMER.CREATE"))
        .expect("a CONSUMER.CREATE PUB must be captured");

    // Subject must follow $JS.API.CONSUMER.CREATE.<stream>.<consumer>.
    assert!(
        create.subject.starts_with("$JS.API.CONSUMER.CREATE.ORDERS"),
        "CREATE subject must be $JS.API.CONSUMER.CREATE.ORDERS.<consumer>, got: {}",
        create.subject
    );
    assert!(
        create.subject.ends_with(".payments"),
        "CREATE subject must include consumer name (durable), got: {}",
        create.subject
    );

    let body = String::from_utf8_lossy(&create.payload).into_owned();

    assert!(
        body.contains("\"stream_name\":\"ORDERS\""),
        "CREATE body must carry stream_name, got: {body}"
    );
    assert!(
        body.contains("\"name\":\"payments\""),
        "CREATE body must carry consumer name, got: {body}"
    );
    assert!(
        body.contains("\"ack_policy\":\"explicit\""),
        "ack_policy=explicit must serialize as the lowercase string literal, got: {body}"
    );
    // br-asupersync-vu86e3: ack_wait MUST be in nanoseconds, not
    // seconds or millis — JetStream API contract.
    assert!(
        body.contains("\"ack_wait\":5000000000"),
        "ack_wait must be encoded as nanoseconds (5s -> 5_000_000_000), got: {body}"
    );
    assert!(
        body.contains("\"max_deliver\":7"),
        "max_deliver must round-trip into the wire body, got: {body}"
    );
    assert!(
        body.contains("\"deliver_policy\":\"all\""),
        "deliver_policy=all must serialize lowercase, got: {body}"
    );
}

#[test]
fn jetstream_pull_request_carries_batch_and_expires_in_nanos_vu86e3() {
    let (server, replies_tx) = MockJsServer::start();
    let url = server.url();

    // Script: first reply is the CREATE response; second reply is
    // the pull batch (an empty body — the client tolerates a 0-msg
    // batch and exits the receive loop without waiting forever
    // because timeout_at fires).
    replies_tx
        .send(("CONSUMER.CREATE".to_string(), br#"{"name":"payments"}"#.to_vec()))
        .expect("script create reply");
    replies_tx
        .send(("CONSUMER.MSG.NEXT".to_string(), Vec::new()))
        .expect("script pull reply");

    let runtime = RuntimeBuilder::new()
        .worker_threads(1)
        .build()
        .expect("build runtime");

    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        let client = match NatsClient::connect(&cx, &url).await {
            Ok(c) => c,
            Err(e) => panic!("nats connect failed: {e:?}"),
        };
        let mut js = JetStreamContext::new(client);
        let cfg = ConsumerConfig::new("payments")
            .ack_policy(AckPolicy::Explicit)
            .ack_wait(Duration::from_secs(5));
        let consumer = match js.create_consumer(&cx, "ORDERS", cfg).await {
            Ok(c) => c,
            Err(e) => panic!("create_consumer failed: {e:?}"),
        };
        // Pull with explicit timeout so we know the exact expires
        // value to assert against. The Consumer::pull_with_timeout
        // signature borrows the client mutably; reach back through
        // the JetStreamContext to get that borrow.
        let _ = consumer
            .pull_with_timeout(js.client(), &cx, 16, Duration::from_secs(2))
            .await;
    }));

    let captured = server.captured();
    let pull = captured
        .iter()
        .find(|c| c.subject.contains("CONSUMER.MSG.NEXT"))
        .expect("a CONSUMER.MSG.NEXT pull PUB must be captured");

    assert!(
        pull.subject.starts_with("$JS.API.CONSUMER.MSG.NEXT.ORDERS.payments"),
        "pull subject must address the durable consumer by stream + name, got: {}",
        pull.subject
    );
    assert!(
        !pull.reply_to.is_empty(),
        "pull request must include a reply-to inbox, got empty"
    );

    let body = String::from_utf8_lossy(&pull.payload).into_owned();
    assert!(
        body.contains("\"batch\":16"),
        "pull body must carry batch=N, got: {body}"
    );
    // br-asupersync-vu86e3: pull expires MUST be in nanoseconds
    // (2s -> 2_000_000_000). This pins push-vs-pull parity at the
    // wire layer: the durable consumer is pull-mode (request/reply
    // over $JS.API.CONSUMER.MSG.NEXT) rather than push-mode (server-
    // initiated MSG to a deliver_subject); no `deliver_subject` was
    // configured, so the asupersync client must emit a pull request,
    // not subscribe-and-wait.
    assert!(
        body.contains("\"expires\":2000000000"),
        "pull body must encode expires in nanoseconds (2s -> 2_000_000_000), got: {body}"
    );
}
