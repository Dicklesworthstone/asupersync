#![allow(missing_docs)]
//! br-asupersync-vynlt0 — e2e test for NATS protocol handshake.
//!
//! ## Why an e2e test
//!
//! `src/messaging/nats.rs` already has thorough unit coverage of the
//! `subscription_matches_subject` matcher (see `nats.rs:2244-2278`),
//! but no test drives `NatsClient::connect` through a real TCP
//! handshake. The handshake is the security-critical path: it
//! reads INFO, decides whether to send CONNECT, and gates on
//! `tls_required` (see br-asupersync-2kmc12 in `nats.rs:751`). A
//! regression in any of those would not be caught by the unit
//! tests — only an e2e against a live wire would notice.
//!
//! ## What this test covers
//!
//! 1. **Wire-protocol handshake.** A minimal scripted NATS protocol
//!    server (`ScriptedNatsServer`) running on `std::thread`:
//!      - Sends `INFO { ... }` immediately on accept.
//!      - Reads the client's `CONNECT { ... }` line.
//!      - Records the raw CONNECT line so the assertion side can
//!        verify it.
//!
//! 2. **CONNECT JSON shape.** The asupersync client must declare
//!    lang=rust, protocol=1, headers=true (br-asupersync-byc2d1),
//!    and no_responders=true (per the NATS spec when headers is on).
//!
//! 3. **TLS-required gate.** A second scripted server scenario advertises
//!    `tls_required:true` in INFO. The asupersync client must abort
//!    with `NatsError::TlsRequired` BEFORE sending CONNECT — verified
//!    by the absence of any captured CONNECT line on the server side.
//!    This pins the br-asupersync-2kmc12 regression.
//!
//! Note: this test does NOT cover the production NATS server. Its
//! oracle is the protocol grammar described in
//! https://docs.nats.io/reference/reference-protocols/nats-protocol —
//! deviations either side would surface as a panic / timeout.
//! The supervisor scenarios also cover idle server PING handling, ordered
//! subscription delivery without an explicit `process()` call, reconnect
//! replay, graceful close, and drop-triggered supervisor cancellation. They
//! also cover a permissions violation (the connection stays open), a server
//! that refuses each connection after CONNECT (backoff and the attempt limit
//! hold across reconnections), and a PING cancelled before its PONG (the
//! connection is replaced instead of left failing every command). A dropped
//! subscription is unsubscribed on the wire, and a command whose caller gave
//! up before the supervisor reached it is not sent.

use asupersync::cx::{ChildRegionSpec, Cx};
use asupersync::messaging::nats::{NatsClient, NatsConfig, NatsError};
use asupersync::runtime::RuntimeBuilder;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Minimal scripted NATS protocol server harness.
struct ScriptedNatsServer {
    port: u16,
    /// Receives the captured CONNECT JSON line from the server thread,
    /// or `None` if the server closed before a CONNECT was sent.
    connect_rx: mpsc::Receiver<Option<String>>,
}

impl ScriptedNatsServer {
    fn start(tls_required: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local_addr").port();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let (mut stream, _addr) = match listener.accept() {
                Ok(p) => p,
                Err(_) => {
                    let _ = tx.send(None);
                    return;
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

            // 1. Send INFO. `headers:false` because this harness does not
            // implement HMSG dispatch.
            let info = format!(
                r#"INFO {{"server_id":"scripted","version":"0.0.0","go":"rust","host":"127.0.0.1","port":4222,"max_payload":1048576,"proto":1,"headers":false,"tls_required":{}}}"#,
                tls_required
            );
            if stream.write_all(info.as_bytes()).is_err() {
                let _ = tx.send(None);
                return;
            }
            if stream.write_all(b"\r\n").is_err() {
                let _ = tx.send(None);
                return;
            }

            // 2. Read the client's CONNECT line — IF it sends one.
            // When tls_required is on, the asupersync client must
            // abort before CONNECT (br-asupersync-2kmc12), so we
            // expect to see EOF here instead.
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut connect_line = String::new();
            match reader.read_line(&mut connect_line) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(None);
                }
                Ok(_) => {
                    let connect_line = connect_line.trim_end_matches(['\r', '\n']).to_string();
                    let _ = tx.send(Some(connect_line));
                }
            }

            // 3. Drain the rest of the stream silently so the
            // client does not get an unexpected EOF mid-test.
            let mut sink = [0u8; 4096];
            while reader.get_mut().read(&mut sink).unwrap_or(0) > 0 {}
        });

        Self {
            port,
            connect_rx: rx,
        }
    }

    fn url(&self) -> String {
        format!("nats://127.0.0.1:{}", self.port)
    }

    /// Returns `Some(connect_json)` if the server received a CONNECT
    /// line from the client, `None` if the client closed first
    /// (expected behavior under the TLS-required gate).
    fn captured_connect(&self) -> Option<String> {
        self.connect_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server thread reported its outcome within timeout")
    }
}

#[test]
fn nats_handshake_sends_well_formed_connect_vynlt0() {
    let server = ScriptedNatsServer::start(false);
    let url = server.url();

    let runtime = RuntimeBuilder::new()
        .worker_threads(1)
        .build()
        .expect("build runtime");

    let connected: bool = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        NatsClient::connect(&cx, &url).await.is_ok()
    }));
    assert!(
        connected,
        "NatsClient::connect must succeed against scripted server"
    );

    let connect_line = server
        .captured_connect()
        .expect("server must receive CONNECT line when tls_required=false");
    assert!(
        connect_line.starts_with("CONNECT {"),
        "expected CONNECT JSON line, got: {connect_line}"
    );
    assert!(
        connect_line.contains("\"lang\":\"rust\""),
        "CONNECT must declare lang=rust, got: {connect_line}"
    );
    assert!(
        connect_line.contains("\"protocol\":1"),
        "CONNECT must declare protocol=1, got: {connect_line}"
    );
    assert!(
        connect_line.contains("\"headers\":true"),
        "CONNECT must advertise headers=true (br-asupersync-byc2d1), got: {connect_line}"
    );
    assert!(
        connect_line.contains("\"no_responders\":true"),
        "CONNECT must advertise no_responders=true (NATS spec for headers-aware clients), got: {connect_line}"
    );
}

#[test]
fn nats_handshake_aborts_before_connect_when_tls_required_vynlt0() {
    // br-asupersync-2kmc12 regression: the client must NOT send
    // CONNECT (which would carry credentials in cleartext) when the
    // server advertises tls_required=true and no TLS upgrade is
    // wired. The expected error is NatsError::TlsRequired, and the
    // scripted server's CONNECT capture must report None (EOF before
    // any CONNECT line was sent).
    let server = ScriptedNatsServer::start(true);
    let url = server.url();

    let runtime = RuntimeBuilder::new()
        .worker_threads(1)
        .build()
        .expect("build runtime");

    let outcome: Result<(), NatsError> = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        NatsClient::connect(&cx, &url).await.map(|_| ())
    }));

    match outcome {
        #[cfg(not(feature = "tls"))]
        Err(NatsError::TlsRequired { .. }) => {}
        // A TLS-capable build upgrades instead of refusing. Against this
        // plaintext server the upgrade fails (or, without trust roots, cannot
        // start), and still no CONNECT is sent: the capture below checks that.
        #[cfg(feature = "tls")]
        Err(NatsError::Tls(_)) => {}
        other => panic!(
            "expected NatsError::TlsRequired, got: {other:?} (br-asupersync-2kmc12 regression)"
        ),
    }

    let captured = server.captured_connect();
    assert!(
        captured.is_none(),
        "client must NOT send CONNECT when tls_required=true; server captured: {captured:?}"
    );
}

fn read_nats_line(reader: &mut BufReader<std::net::TcpStream>) -> String {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).expect("read NATS line");
    assert!(bytes > 0, "peer closed before sending a NATS line");
    line.trim_end_matches(['\r', '\n']).to_string()
}

#[test]
fn nats_supervisor_answers_idle_ping_and_delivers_in_order_7207gg() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind supervisor listener");
    let addr = listener.local_addr().expect("listener addr");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept supervisor client");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set write timeout");
        stream
            .write_all(
                b"INFO {\"server_id\":\"idle\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576}\r\n",
            )
            .expect("write INFO");
        stream.flush().expect("flush INFO");

        let mut reader = BufReader::new(stream);
        assert!(read_nats_line(&mut reader).starts_with("CONNECT "));
        assert_eq!(read_nats_line(&mut reader), "SUB events.idle 1");

        reader
            .get_mut()
            .write_all(b"PING\r\n")
            .expect("write idle PING");
        reader.get_mut().flush().expect("flush idle PING");
        assert_eq!(
            read_nats_line(&mut reader),
            "PONG",
            "supervisor must answer without process()"
        );

        reader
            .get_mut()
            .write_all(b"MSG events.idle 1 5\r\nfirst\r\nMSG events.idle 1 6\r\nsecond\r\n")
            .expect("write ordered messages");
        reader.get_mut().flush().expect("flush ordered messages");

        let mut byte = [0_u8; 1];
        reader
            .get_mut()
            .read(&mut byte)
            .expect("observe graceful supervisor shutdown")
    });

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        let mut client = NatsClient::connect(&cx, &format!("nats://{addr}"))
            .await
            .expect("connect supervised client");
        let mut subscription = client
            .subscribe(&cx, "events.idle")
            .await
            .expect("subscribe");

        let first = subscription
            .next(&cx)
            .await
            .expect("first receive")
            .expect("first message");
        let second = subscription
            .next(&cx)
            .await
            .expect("second receive")
            .expect("second message");
        assert_eq!(first.payload, b"first");
        assert_eq!(second.payload, b"second");

        client.close(&cx).await.expect("close supervised client");
        assert!(
            subscription
                .next(&cx)
                .await
                .expect("closed subscription result")
                .is_none()
        );
    }));

    assert_eq!(server.join().expect("server join"), 0);
}

#[test]
fn nats_supervisor_reconnect_replays_active_subscription_7207gg() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind reconnect listener");
    let addr = listener.local_addr().expect("listener addr");
    let server = thread::spawn(move || {
        let mut subscriptions = Vec::new();
        for connection_index in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept reconnect client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .expect("set write timeout");
            stream
                .write_all(
                    b"INFO {\"server_id\":\"reconnect\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576}\r\n",
                )
                .expect("write INFO");
            stream.flush().expect("flush INFO");

            let mut reader = BufReader::new(stream);
            assert!(read_nats_line(&mut reader).starts_with("CONNECT "));
            subscriptions.push(read_nats_line(&mut reader));

            if connection_index == 1 {
                reader
                    .get_mut()
                    .write_all(b"MSG events.reconnect 1 9\r\nreplayed!\r\n")
                    .expect("write replayed message");
                reader.get_mut().flush().expect("flush replayed message");
                let mut byte = [0_u8; 1];
                assert_eq!(
                    reader
                        .get_mut()
                        .read(&mut byte)
                        .expect("observe reconnect supervisor shutdown"),
                    0
                );
            }
        }
        subscriptions
    });

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        let mut config =
            NatsConfig::from_url(&format!("nats://{addr}")).expect("parse reconnect URL");
        config.reconnect_delay = Duration::ZERO;
        config.max_reconnect_delay = Duration::ZERO;
        config.max_reconnect_attempts = 3;
        let mut client = NatsClient::connect_with_config(&cx, config)
            .await
            .expect("connect supervised client");
        let mut subscription = client
            .subscribe(&cx, "events.reconnect")
            .await
            .expect("subscribe before reconnect");

        let message = subscription
            .next(&cx)
            .await
            .expect("reconnect receive")
            .expect("message after replay");
        assert_eq!(message.payload, b"replayed!");
        client.close(&cx).await.expect("close reconnected client");
    }));

    assert_eq!(
        server.join().expect("server join"),
        vec![
            "SUB events.reconnect 1".to_string(),
            "SUB events.reconnect 1".to_string()
        ]
    );
}

#[test]
fn nats_supervisor_drop_cancels_task_and_releases_subscription_7207gg() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind drop listener");
    let addr = listener.local_addr().expect("listener addr");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept drop client");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        stream
            .write_all(
                b"INFO {\"server_id\":\"drop\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576}\r\n",
            )
            .expect("write INFO");
        stream.flush().expect("flush INFO");

        let mut reader = BufReader::new(stream);
        assert!(read_nats_line(&mut reader).starts_with("CONNECT "));
        assert_eq!(read_nats_line(&mut reader), "SUB events.drop 1");
        let mut byte = [0_u8; 1];
        reader
            .get_mut()
            .read(&mut byte)
            .expect("observe cancelled supervisor shutdown")
    });

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        let mut client = NatsClient::connect(&cx, &format!("nats://{addr}"))
            .await
            .expect("connect supervised client");
        let mut subscription = client
            .subscribe(&cx, "events.drop")
            .await
            .expect("subscribe before drop");

        drop(client);
        assert!(
            subscription
                .next(&cx)
                .await
                .expect("dropped-client subscription result")
                .is_none()
        );
    }));

    assert_eq!(server.join().expect("server join"), 0);
}

#[test]
fn nats_cancelled_request_releases_supervisor_for_next_command() {
    for workers in [1, 2] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind caller-cancel peer");
        let addr = listener.local_addr().expect("caller-cancel address");
        let (published_tx, published_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept caller-cancel client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set caller-cancel peer timeout");
            stream
                .write_all(b"INFO {\"server_id\":\"caller-cancel\",\"max_payload\":1048576}\r\n")
                .expect("send caller-cancel INFO");
            let mut reader = BufReader::new(stream);
            assert!(read_nats_line(&mut reader).starts_with("CONNECT "));
            assert_eq!(read_nats_line(&mut reader), "SUB events.cancel 1");
            let inbox = read_nats_line(&mut reader);
            assert!(inbox.starts_with("SUB _INBOX."), "request inbox: {inbox}");
            let request = read_nats_line(&mut reader);
            assert!(request.starts_with("PUB service.silent _INBOX."));
            assert!(request.ends_with(" 6"));
            let mut payload = [0_u8; 8];
            reader.read_exact(&mut payload).expect("read full request");
            assert_eq!(&payload, b"parked\r\n");
            published_tx
                .send(reader.get_ref().try_clone().expect("clone cleanup socket"))
                .expect("publish wire-state witness");

            // Withhold the reply. A cancelled caller must release the
            // supervisor so a different live owner can put PING on this same
            // socket, without waiting for request_timeout or another frame.
            // The abandoned inbox is unsubscribed first, or the server would
            // keep routing replies to it for the life of the connection.
            assert_eq!(
                read_nats_line(&mut reader),
                "UNSUB 2",
                "the cancelled request's inbox is unsubscribed before the next command"
            );
            let next = read_nats_line(&mut reader);
            assert_eq!(next, "PING", "next command after caller cancellation");
            reader
                .get_mut()
                .write_all(b"PONG\r\nMSG events.cancel 1 5\r\nalive\r\n")
                .expect("answer next command and publish healthy message");
            let mut byte = [0_u8; 1];
            reader.get_mut().read(&mut byte).expect("observe close")
        });

        let runtime = RuntimeBuilder::new()
            .worker_threads(workers)
            .build()
            .expect("build caller-cancel runtime");
        let (owner_tx, owner_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let task = runtime.handle().spawn(async move {
            let cx = Cx::current().expect("native caller context");
            let mut config =
                NatsConfig::from_url(&format!("nats://{addr}")).expect("parse caller-cancel URL");
            config.auto_reconnect = false;
            config.request_timeout = Duration::from_secs(60);
            let mut client = NatsClient::connect_with_config(&cx, config)
                .await
                .expect("connect caller-cancel client");
            let mut subscription = client
                .subscribe(&cx, "events.cancel")
                .await
                .expect("subscribe");
            let owner = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .expect("open independent request owner");
            owner_tx
                .send(owner.cx().clone())
                .expect("publish request owner");

            let cancelled = client
                .request(owner.cx(), "service.silent", b"parked")
                .await;
            assert!(
                matches!(cancelled, Err(NatsError::Cancelled)),
                "{cancelled:?}"
            );
            assert!(
                !cx.is_cancel_requested(),
                "caller cancellation escaped its context"
            );
            client
                .ping(&cx)
                .await
                .expect("live next command must progress");
            let message = subscription
                .next(&cx)
                .await
                .expect("healthy subscription")
                .expect("message");
            assert_eq!(message.payload, b"alive");
            client.close(&cx).await.expect("close caller-cancel client");
            assert!(
                subscription
                    .next(&cx)
                    .await
                    .expect("closed subscription")
                    .is_none()
            );
            owner
                .close()
                .await
                .expect("request owner reaches quiescence");
            let _ = done_tx.send(());
        });

        let owner = owner_rx.recv_timeout(Duration::from_secs(3));
        let published = published_rx.recv_timeout(Duration::from_secs(3));
        if let (Ok(owner), Ok(_)) = (&owner, &published) {
            owner.cancel_with(
                asupersync::types::CancelKind::User,
                Some("cancel NATS request"),
            );
        }
        let completed = done_rx.recv_timeout(Duration::from_secs(2));
        // This shutdown is only failure cleanup; it occurs after capturing the
        // next-command result so EOF cannot stand in for cancellation progress.
        if let Ok(stream) = &published {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        let peer_result = server.join();
        drop(task);
        let drained = runtime.shutdown_timeout(Duration::from_secs(3));
        assert!(owner.is_ok(), "request owner was not admitted: {owner:?}");
        assert!(
            published.is_ok(),
            "request never reached peer: {published:?}"
        );
        assert!(
            completed.is_ok(),
            "NATS_CANCEL_OWNER workers={workers} published=true next_command={completed:?}"
        );
        assert_eq!(peer_result.expect("caller-cancel peer joined"), 0);
        assert!(drained, "caller-cancel runtime did not drain");
    }
}

/// Accepts one client within `window`, or returns `None`.
fn accept_within(listener: &TcpListener, window: Duration) -> Option<std::net::TcpStream> {
    listener
        .set_nonblocking(true)
        .expect("poll listener without blocking");
    let deadline = std::time::Instant::now() + window;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).expect("blocking peer socket");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("set read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .expect("set write timeout");
                return Some(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accept NATS client: {error}"),
        }
    }
}

fn send_info(stream: &mut std::net::TcpStream, server_id: &str) {
    let info = format!(
        "INFO {{\"server_id\":\"{server_id}\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576}}\r\n"
    );
    stream.write_all(info.as_bytes()).expect("write INFO");
    stream.flush().expect("flush INFO");
}

/// Reads until the client closes the connection. Returns false if it is
/// still open after `within`.
fn closed_by_client(reader: &mut BufReader<std::net::TcpStream>, within: Duration) -> bool {
    reader
        .get_mut()
        .set_read_timeout(Some(within))
        .expect("set close timeout");
    let mut sink = [0_u8; 256];
    loop {
        match reader.read(&mut sink) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(error) => {
                return matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                );
            }
        }
    }
}

#[test]
fn nats_supervisor_keeps_the_connection_after_a_permissions_violation() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind permissions listener");
    let addr = listener.local_addr().expect("listener addr");
    let server = thread::spawn(move || {
        let mut stream =
            accept_within(&listener, Duration::from_secs(5)).expect("accept permissions client");
        send_info(&mut stream, "permissions");
        let mut reader = BufReader::new(stream);
        assert!(read_nats_line(&mut reader).starts_with("CONNECT "));
        assert_eq!(read_nats_line(&mut reader), "SUB events.allowed 1");
        assert_eq!(read_nats_line(&mut reader), "SUB events.denied 2");
        // A real server refuses the second SUB this way and keeps the
        // connection open, so the message behind the refusal still arrives.
        reader
            .get_mut()
            .write_all(
                b"-ERR 'Permissions Violation for Subscription to \"events.denied\"'\r\nMSG events.allowed 1 5\r\nfirst\r\n",
            )
            .expect("write refusal and message");
        reader.get_mut().flush().expect("flush refusal and message");
        let closed = closed_by_client(&mut reader, Duration::from_secs(5));
        let reconnected = accept_within(&listener, Duration::from_millis(300)).is_some();
        (closed, reconnected)
    });

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let (done_tx, done_rx) = mpsc::channel();
    let task = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        let mut config =
            NatsConfig::from_url(&format!("nats://{addr}")).expect("parse permissions URL");
        config.reconnect_delay = Duration::ZERO;
        config.max_reconnect_delay = Duration::ZERO;
        let mut client = NatsClient::connect_with_config(&cx, config)
            .await
            .expect("connect supervised client");
        let mut allowed = client
            .subscribe(&cx, "events.allowed")
            .await
            .expect("subscribe allowed");
        let _denied = client
            .subscribe(&cx, "events.denied")
            .await
            .expect("the SUB is written before the server refuses it");
        let message = allowed
            .next(&cx)
            .await
            .expect("receive behind the refusal")
            .expect("message behind the refusal");
        assert_eq!(message.payload, b"first");
        client.close(&cx).await.expect("close supervised client");
        let _ = done_tx.send(());
    });

    let completed = done_rx.recv_timeout(Duration::from_secs(5));
    let peer = server.join();
    drop(task);
    let drained = runtime.shutdown_timeout(Duration::from_secs(3));
    assert!(
        completed.is_ok(),
        "the message behind a permissions violation was not delivered"
    );
    assert_eq!(
        peer.expect("permissions peer joined"),
        (true, false),
        "(closed only by the client's close, reconnected)"
    );
    assert!(drained, "permissions runtime did not drain");
}

/// Publish-then-ping is the usual flush. A permissions violation for the
/// publish arrives before the PONG; ping() returned it as an error and the
/// supervisor reconnected, dropping in-flight messages, although the server
/// keeps the connection open.
#[test]
fn nats_ping_after_a_denied_publish_succeeds_without_reconnecting() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind flush listener");
    let addr = listener.local_addr().expect("listener addr");
    let server = thread::spawn(move || {
        let mut stream =
            accept_within(&listener, Duration::from_secs(5)).expect("accept flush client");
        send_info(&mut stream, "flush");
        let mut reader = BufReader::new(stream);
        assert!(read_nats_line(&mut reader).starts_with("CONNECT "));
        assert_eq!(read_nats_line(&mut reader), "PUB events.denied 1");
        assert_eq!(read_nats_line(&mut reader), "x");
        assert_eq!(read_nats_line(&mut reader), "PING");
        reader
            .get_mut()
            .write_all(b"-ERR 'Permissions Violation for Publish to \"events.denied\"'\r\nPONG\r\n")
            .expect("write refusal and PONG");
        reader.get_mut().flush().expect("flush refusal and PONG");
        let closed = closed_by_client(&mut reader, Duration::from_secs(5));
        let reconnected = accept_within(&listener, Duration::from_millis(300)).is_some();
        (closed, reconnected)
    });

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let (done_tx, done_rx) = mpsc::channel();
    let task = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        let mut config = NatsConfig::from_url(&format!("nats://{addr}")).expect("parse flush URL");
        config.reconnect_delay = Duration::ZERO;
        config.max_reconnect_delay = Duration::ZERO;
        let mut client = NatsClient::connect_with_config(&cx, config)
            .await
            .expect("connect supervised client");
        client
            .publish(&cx, "events.denied", b"x")
            .await
            .expect("the PUB is written before the server refuses it");
        let flushed = client.ping(&cx).await;
        client.close(&cx).await.expect("close supervised client");
        let _ = done_tx.send(flushed.is_ok());
    });

    let flushed = done_rx.recv_timeout(Duration::from_secs(5));
    let peer = server.join();
    drop(task);
    let drained = runtime.shutdown_timeout(Duration::from_secs(3));
    assert_eq!(
        flushed,
        Ok(true),
        "ping must succeed after a permissions violation"
    );
    assert_eq!(
        peer.expect("flush peer joined"),
        (true, false),
        "(closed only by the client's close, reconnected)"
    );
    assert!(drained, "flush runtime did not drain");
}

#[test]
fn nats_supervisor_backs_off_across_connections_the_server_refuses_after_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind refusing listener");
    let addr = listener.local_addr().expect("listener addr");
    let server = thread::spawn(move || {
        // Each connection completes the handshake and is then refused, as a
        // server refuses bad credentials. Accept for a fixed window.
        let started = std::time::Instant::now();
        let mut accepted = Vec::new();
        while accepted.len() < 64 {
            let remaining = Duration::from_millis(2_500).saturating_sub(started.elapsed());
            let Some(mut stream) = accept_within(&listener, remaining) else {
                break;
            };
            accepted.push(started.elapsed());
            send_info(&mut stream, "refusing");
            let mut reader = BufReader::new(stream);
            assert!(read_nats_line(&mut reader).starts_with("CONNECT "));
            let _ = reader
                .get_mut()
                .write_all(b"-ERR 'Authorization Violation'\r\n");
            let _ = reader.get_mut().flush();
        }
        accepted
    });

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let (done_tx, done_rx) = mpsc::channel();
    let task = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        let mut config =
            NatsConfig::from_url(&format!("nats://{addr}")).expect("parse refusing URL");
        config.reconnect_delay = Duration::from_millis(200);
        config.max_reconnect_delay = Duration::from_secs(2);
        config.max_reconnect_attempts = 3;
        let client = NatsClient::connect_with_config(&cx, config)
            .await
            .expect("the first handshake completes before the refusal");
        // Hold the client while the server refuses its reconnections.
        asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(2_800)).await;
        drop(client);
        let _ = done_tx.send(());
    });

    let accepted = server.join().expect("refusing peer joined");
    let completed = done_rx.recv_timeout(Duration::from_secs(5));
    drop(task);
    let drained = runtime.shutdown_timeout(Duration::from_secs(3));
    assert_eq!(
        accepted.len(),
        4,
        "the first connection plus max_reconnect_attempts=3 reconnections, accepted at {accepted:?}"
    );
    assert!(
        accepted[2].saturating_sub(accepted[1]) >= Duration::from_millis(150),
        "a reconnection refused right away delays the next one: {accepted:?}"
    );
    assert!(
        accepted[3].saturating_sub(accepted[2]) >= Duration::from_millis(350),
        "the delay doubles across refused reconnections: {accepted:?}"
    );
    assert!(completed.is_ok(), "refused client task did not finish");
    assert!(drained, "refusing runtime did not drain");
}

#[test]
fn nats_supervisor_keeps_reconnecting_a_flapping_connection_at_a_bounded_rate() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind flapping listener");
    let addr = listener.local_addr().expect("listener addr");
    let server = thread::spawn(move || {
        // Each connection completes the handshake and is then dropped without
        // an error, as a flapping network or a restarting proxy drops it.
        let started = std::time::Instant::now();
        let mut accepted = Vec::new();
        while accepted.len() < 64 {
            let remaining = Duration::from_millis(2_000).saturating_sub(started.elapsed());
            let Some(mut stream) = accept_within(&listener, remaining) else {
                break;
            };
            accepted.push(started.elapsed());
            send_info(&mut stream, "flapping");
            let mut reader = BufReader::new(stream);
            assert!(read_nats_line(&mut reader).starts_with("CONNECT "));
        }
        accepted
    });

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let (done_tx, done_rx) = mpsc::channel();
    let task = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        let mut config =
            NatsConfig::from_url(&format!("nats://{addr}")).expect("parse flapping URL");
        config.reconnect_delay = Duration::from_millis(100);
        config.max_reconnect_delay = Duration::from_secs(2);
        config.max_reconnect_attempts = 2;
        let client = NatsClient::connect_with_config(&cx, config)
            .await
            .expect("connect supervised client");
        asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(2_300)).await;
        drop(client);
        let _ = done_tx.send(());
    });

    let accepted = server.join().expect("flapping peer joined");
    let completed = done_rx.recv_timeout(Duration::from_secs(5));
    drop(task);
    let drained = runtime.shutdown_timeout(Duration::from_secs(3));
    // Drops without a server error never exhaust max_reconnect_attempts=2:
    // every reconnection that succeeds starts a new budget.
    assert!(
        accepted.len() >= 5,
        "a dropped connection is reconnected each time: {accepted:?}"
    );
    for pair in accepted[1..].windows(2) {
        assert!(
            pair[1].saturating_sub(pair[0]) >= Duration::from_millis(80),
            "a connection dropped right after reconnecting waits reconnect_delay: {accepted:?}"
        );
    }
    assert!(completed.is_ok(), "flapping client task did not finish");
    assert!(drained, "flapping runtime did not drain");
}

#[test]
fn nats_supervisor_replaces_a_connection_a_cancelled_ping_left_unusable() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ping listener");
    let addr = listener.local_addr().expect("listener addr");
    let (ping_seen_tx, ping_seen_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut first =
            accept_within(&listener, Duration::from_secs(5)).expect("accept ping client");
        send_info(&mut first, "ping-cut");
        let mut first = BufReader::new(first);
        assert!(read_nats_line(&mut first).starts_with("CONNECT "));
        assert_eq!(read_nats_line(&mut first), "SUB events.kept 1");
        assert_eq!(read_nats_line(&mut first), "PING");
        ping_seen_tx.send(()).expect("publish PING witness");
        // Withhold the PONG. The cancelled PING leaves this connection
        // marked unusable, so the client must close it and reconnect.
        let first_closed = closed_by_client(&mut first, Duration::from_secs(5));
        let Some(mut second) = accept_within(&listener, Duration::from_secs(5)) else {
            return (first_closed, Vec::new());
        };
        send_info(&mut second, "ping-cut");
        let mut second = BufReader::new(second);
        let lines = vec![
            read_nats_line(&mut second),
            read_nats_line(&mut second),
            read_nats_line(&mut second),
        ];
        second
            .get_mut()
            .write_all(b"MSG events.after 2 5\r\nfresh\r\n")
            .expect("write message on the replacement connection");
        second.get_mut().flush().expect("flush message");
        assert!(closed_by_client(&mut second, Duration::from_secs(5)));
        (first_closed, lines)
    });

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let (owner_tx, owner_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let task = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        let mut config = NatsConfig::from_url(&format!("nats://{addr}")).expect("parse ping URL");
        config.reconnect_delay = Duration::ZERO;
        config.max_reconnect_delay = Duration::ZERO;
        let mut client = NatsClient::connect_with_config(&cx, config)
            .await
            .expect("connect supervised client");
        let _kept = client
            .subscribe(&cx, "events.kept")
            .await
            .expect("subscribe before the PING");
        let owner = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("open PING owner");
        owner_tx
            .send(owner.cx().clone())
            .expect("publish PING owner");
        let cancelled = client.ping(owner.cx()).await;
        assert!(
            matches!(cancelled, Err(NatsError::Cancelled)),
            "{cancelled:?}"
        );
        let mut after = client
            .subscribe(&cx, "events.after")
            .await
            .expect("a command after a cancelled PING");
        let message = after
            .next(&cx)
            .await
            .expect("receive on the replacement connection")
            .expect("message on the replacement connection");
        assert_eq!(message.payload, b"fresh");
        client.close(&cx).await.expect("close supervised client");
        owner.close().await.expect("PING owner reaches quiescence");
        let _ = done_tx.send(());
    });

    let owner = owner_rx.recv_timeout(Duration::from_secs(3));
    let ping_seen = ping_seen_rx.recv_timeout(Duration::from_secs(3));
    if let (Ok(owner), Ok(())) = (&owner, &ping_seen) {
        owner.cancel_with(
            asupersync::types::CancelKind::User,
            Some("cancel NATS ping"),
        );
    }
    let completed = done_rx.recv_timeout(Duration::from_secs(10));
    let peer = server.join();
    drop(task);
    let drained = runtime.shutdown_timeout(Duration::from_secs(3));
    assert!(owner.is_ok(), "PING owner was not admitted: {owner:?}");
    assert!(ping_seen.is_ok(), "PING never reached the peer");
    assert!(
        completed.is_ok(),
        "a command after a cancelled PING must succeed on a replacement connection"
    );
    let (first_closed, lines) = peer.expect("ping peer joined");
    assert!(
        first_closed,
        "the connection the PING was cut off on stays open"
    );
    assert!(lines[0].starts_with("CONNECT "), "{lines:?}");
    assert_eq!(
        &lines[1..],
        &[
            "SUB events.kept 1".to_string(),
            "SUB events.after 2".to_string()
        ],
        "replay, then the new SUB, on the replacement connection"
    );
    assert!(drained, "ping runtime did not drain");
}

#[test]
fn nats_supervisor_unsubscribes_a_dropped_subscription() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind drop-unsub listener");
    let addr = listener.local_addr().expect("listener addr");
    let server = thread::spawn(move || {
        let mut stream =
            accept_within(&listener, Duration::from_secs(5)).expect("accept drop-unsub client");
        send_info(&mut stream, "drop-unsub");
        let mut reader = BufReader::new(stream);
        assert!(read_nats_line(&mut reader).starts_with("CONNECT "));
        let mut lines = vec![read_nats_line(&mut reader), read_nats_line(&mut reader)];
        let next = read_nats_line(&mut reader);
        if next == "PING" {
            reader
                .get_mut()
                .write_all(b"PONG\r\n")
                .expect("answer PING");
        }
        lines.push(next);
        (lines, closed_by_client(&mut reader, Duration::from_secs(5)))
    });

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let (done_tx, done_rx) = mpsc::channel();
    let task = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        let mut client = NatsClient::connect(&cx, &format!("nats://{addr}"))
            .await
            .expect("connect supervised client");
        let subscription = client
            .subscribe(&cx, "events.dropped")
            .await
            .expect("subscribe");
        drop(subscription);
        client.ping(&cx).await.expect("ping after the drop");
        client.close(&cx).await.expect("close supervised client");
        let _ = done_tx.send(());
    });

    let completed = done_rx.recv_timeout(Duration::from_secs(10));
    let peer = server.join();
    drop(task);
    let drained = runtime.shutdown_timeout(Duration::from_secs(3));
    let (lines, closed) = peer.expect("drop-unsub peer joined");
    assert_eq!(
        lines,
        ["SUB events.dropped 1", "UNSUB 1", "PING"],
        "a dropped subscription is unsubscribed before the next command"
    );
    assert!(closed, "client did not close");
    assert!(completed.is_ok(), "drop-unsub client task did not finish");
    assert!(drained, "drop-unsub runtime did not drain");
}

#[test]
fn nats_supervisor_skips_a_publish_whose_caller_gave_up() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind abandoned listener");
    let addr = listener.local_addr().expect("listener addr");
    let (abandoned_tx, abandoned_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut stream =
            accept_within(&listener, Duration::from_secs(5)).expect("accept abandoned client");
        send_info(&mut stream, "abandoned");
        let mut reader = BufReader::new(stream);
        assert!(read_nats_line(&mut reader).starts_with("CONNECT "));
        // Hold the supervisor inside the first PING until the client has also
        // queued and abandoned a publish behind it.
        let first = read_nats_line(&mut reader);
        let abandoned = abandoned_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        reader
            .get_mut()
            .write_all(b"PONG\r\n")
            .expect("answer the abandoned PING");
        let next = read_nats_line(&mut reader);
        if next == "PING" {
            reader
                .get_mut()
                .write_all(b"PONG\r\n")
                .expect("answer the live PING");
        }
        let closed = closed_by_client(&mut reader, Duration::from_secs(5));
        (first, abandoned, next, closed)
    });

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let (done_tx, done_rx) = mpsc::channel();
    let task = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        let mut client = NatsClient::connect(&cx, &format!("nats://{addr}"))
            .await
            .expect("connect supervised client");
        let ping = asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_secs(1),
            client.ping(&cx),
        )
        .await;
        assert!(ping.is_err(), "the first PING is held: {ping:?}");
        let publish = asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_millis(200),
            client.publish(&cx, "events.late", b"late"),
        )
        .await;
        assert!(
            publish.is_err(),
            "the publish waits behind the PING: {publish:?}"
        );
        abandoned_tx.send(()).expect("report the abandoned publish");
        client.ping(&cx).await.expect("live ping");
        client.close(&cx).await.expect("close supervised client");
        let _ = done_tx.send(());
    });

    let completed = done_rx.recv_timeout(Duration::from_secs(10));
    let peer = server.join();
    drop(task);
    let drained = runtime.shutdown_timeout(Duration::from_secs(3));
    let (first, abandoned, next, closed) = peer.expect("abandoned peer joined");
    assert_eq!(first, "PING");
    assert!(abandoned, "client did not abandon its publish");
    assert_eq!(
        next, "PING",
        "a publish whose caller gave up before the supervisor reached it is not sent"
    );
    assert!(closed, "client did not close");
    assert!(completed.is_ok(), "abandoned client task did not finish");
    assert!(drained, "abandoned runtime did not drain");
}

/// A supervised `process()` whose caller stopped waiting (a timeout drops
/// the future; it does not cancel the caller's Cx) kept the supervisor
/// reading the socket until the next inbound frame, so every later command
/// waited for it. A JetStream pull ends every round with such a timeout, and
/// the next frame is often the server's PING, minutes later.
#[test]
fn nats_timed_out_process_does_not_hold_the_supervisor() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind process listener");
    let addr = listener.local_addr().expect("listener addr");
    let server = thread::spawn(move || {
        let mut stream =
            accept_within(&listener, Duration::from_secs(5)).expect("accept process client");
        send_info(&mut stream, "process-timeout");
        let mut reader = BufReader::new(stream);
        assert!(read_nats_line(&mut reader).starts_with("CONNECT "));
        // Stay silent. The PUB must arrive without any frame from here; if
        // it has not after 3 s, a PING releases a supervisor stuck reading,
        // so the test fails instead of hanging.
        reader
            .get_mut()
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set silent window");
        let mut needed_ping = false;
        let publish = loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => panic!("client closed before publishing"),
                Ok(_) if line.starts_with("PUB ") => break line.trim_end().to_string(),
                Ok(_) => {}
                Err(_) => {
                    needed_ping = true;
                    reader
                        .get_mut()
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .expect("set read timeout");
                    reader.get_mut().write_all(b"PING\r\n").expect("write PING");
                    reader.get_mut().flush().expect("flush PING");
                }
            }
        };
        assert_eq!(read_nats_line(&mut reader), "ok");
        let closed = closed_by_client(&mut reader, Duration::from_secs(5));
        (needed_ping, publish, closed)
    });

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let (done_tx, done_rx) = mpsc::channel();
    let task = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task context");
        let mut config =
            NatsConfig::from_url(&format!("nats://{addr}")).expect("parse process URL");
        config.auto_reconnect = false;
        let mut client = NatsClient::connect_with_config(&cx, config)
            .await
            .expect("connect supervised client");
        let timed_out =
            asupersync::time::timeout(cx.now(), Duration::from_millis(100), client.process(&cx))
                .await;
        assert!(
            timed_out.is_err(),
            "the silent server sent nothing to process"
        );
        client
            .publish(&cx, "after.timeout", b"ok")
            .await
            .expect("publish after the timed-out process");
        client.close(&cx).await.expect("close supervised client");
        let _ = done_tx.send(());
    });

    let completed = done_rx.recv_timeout(Duration::from_secs(15));
    let peer = server.join();
    drop(task);
    let drained = runtime.shutdown_timeout(Duration::from_secs(3));
    let (needed_ping, publish, closed) = peer.expect("process peer joined");
    assert_eq!(publish, "PUB after.timeout 2");
    assert!(
        !needed_ping,
        "the publish waited until an inbound frame released the supervisor"
    );
    assert!(closed, "client did not close");
    assert!(completed.is_ok(), "process client task did not finish");
    assert!(drained, "process runtime did not drain");
}
