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
//! 1. **Wire-protocol handshake.** A minimal NATS protocol mock
//!    server (`MockNatsServer`) running on `std::thread`:
//!      - Sends `INFO { ... }` immediately on accept.
//!      - Reads the client's `CONNECT { ... }` line.
//!      - Records the raw CONNECT line so the assertion side can
//!        verify it.
//!
//! 2. **CONNECT JSON shape.** The asupersync client must declare
//!    lang=rust, protocol=1, headers=true (br-asupersync-byc2d1),
//!    and no_responders=true (per the NATS spec when headers is on).
//!
//! 3. **TLS-required gate.** A second mock server scenario advertises
//!    `tls_required:true` in INFO. The asupersync client must abort
//!    with `NatsError::TlsRequired` BEFORE sending CONNECT — verified
//!    by the absence of any captured CONNECT line on the server side.
//!    This pins the br-asupersync-2kmc12 regression.
//!
//! Note: this test does NOT cover the production NATS server. Its
//! oracle is the protocol grammar described in
//! https://docs.nats.io/reference/reference-protocols/nats-protocol —
//! deviations either side would surface as a panic / timeout.
//! Subscribe / wildcard delivery is intentionally out of scope here:
//! the NATS client's current design pumps inbound MSGs only on the
//! caller's API call (no background reader task), so a wire-level
//! wildcard test would require additional pump plumbing that is
//! tracked separately.

use asupersync::cx::Cx;
use asupersync::messaging::nats::{NatsClient, NatsError};
use asupersync::runtime::RuntimeBuilder;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Minimal NATS protocol mock-server harness.
struct MockNatsServer {
    port: u16,
    /// Receives the captured CONNECT JSON line from the server thread,
    /// or `None` if the server closed before a CONNECT was sent.
    connect_rx: mpsc::Receiver<Option<String>>,
}

impl MockNatsServer {
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
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .ok();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .ok();

            // 1. Send INFO. `headers:false` because this mock does not
            // implement HMSG dispatch.
            let info = format!(
                r#"INFO {{"server_id":"mock","version":"0.0.0","go":"mock","host":"127.0.0.1","port":4222,"max_payload":1048576,"proto":1,"headers":false,"tls_required":{}}}"#,
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
    let server = MockNatsServer::start(false);
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
        "NatsClient::connect must succeed against mock server"
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
    // mock server's CONNECT capture must report None (EOF before
    // any CONNECT line was sent).
    let server = MockNatsServer::start(true);
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
        Err(NatsError::TlsRequired { .. }) => {}
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
