//! Structure-aware fuzz target for `src/tls/stream.rs`.
//!
//! This target exercises `TlsConnector::connect()` plus `TlsStream` read/write
//! paths against a real rustls server connection behind a mock async transport.
//! The transport mutates only the server-to-client TLS records so the harness
//! can focus on record framing, fragmentation, close-notify handling, and
//! malformed header behavior inside the stream adapter.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::time::{timeout, wall_now};
use asupersync::tls::{Certificate, TlsConnector, TlsConnectorBuilder};
use libfuzzer_sys::fuzz_target;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::collections::VecDeque;
use std::io::{self, Cursor, Write};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

const TEST_CERT_PEM: &str = include_str!("../../tests/fixtures/tls/server.crt");
const TEST_KEY_PEM: &str = include_str!("../../tests/fixtures/tls/server.key");
const MAX_PAYLOAD_LEN: usize = 512;
const MAX_TRAILING_GARBAGE: usize = 32;
const CONNECT_TIMEOUT_MS: u64 = 200;
const IO_TIMEOUT_MS: u64 = 200;

#[derive(Arbitrary, Debug, Clone)]
struct TlsStreamRecordInput {
    read_chunk_limit: u8,
    write_chunk_limit: u8,
    pending_read_every: u8,
    pending_write_every: u8,
    mutation: ServerMutation,
    post_handshake: PostHandshakeAction,
    client_payload: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
enum ServerMutation {
    None,
    TruncateFirstFlight { drop_bytes: u8 },
    CorruptFirstFlightByte { offset: u8, mask: u8 },
    InflateFirstRecordLength { extra: u8 },
    AppendGarbage(Vec<u8>),
}

#[derive(Arbitrary, Debug, Clone)]
enum PostHandshakeAction {
    None,
    ServerData(Vec<u8>),
    ServerDataThenClose(Vec<u8>),
    CloseNotifyOnly,
    EofAfterHandshake,
}

#[derive(Debug)]
enum Outcome {
    ConnectOk,
    ConnectErr,
    ConnectTimeout,
}

struct LoopbackServerIo {
    server: ServerConnection,
    input: TlsStreamRecordInput,
    queued_to_client: VecDeque<u8>,
    first_flight_mutated: bool,
    post_handshake_sent: bool,
    eof_after_drain: bool,
    read_ops: usize,
    write_ops: usize,
}

impl LoopbackServerIo {
    fn new(input: TlsStreamRecordInput) -> Option<Self> {
        Some(Self {
            server: ServerConnection::new(server_config()?).ok()?,
            input,
            queued_to_client: VecDeque::new(),
            first_flight_mutated: false,
            post_handshake_sent: false,
            eof_after_drain: false,
            read_ops: 0,
            write_ops: 0,
        })
    }

    fn maybe_pending(cx: &Context<'_>, every: u8, op_index: usize) -> bool {
        if every > 0 && op_index % every as usize == 0 {
            cx.waker().wake_by_ref();
            return true;
        }
        false
    }

    fn read_chunk_limit(&self) -> usize {
        usize::from(self.input.read_chunk_limit.max(1))
    }

    fn write_chunk_limit(&self) -> usize {
        usize::from(self.input.write_chunk_limit.max(1))
    }

    fn queue_server_output(&mut self) -> io::Result<()> {
        let mut output = Vec::new();
        while self.server.wants_write() {
            let written = self.server.write_tls(&mut output)?;
            if written == 0 {
                break;
            }
        }

        if output.is_empty() {
            return Ok(());
        }

        if !self.first_flight_mutated {
            apply_mutation(&mut output, &self.input.mutation);
            self.first_flight_mutated = true;
        }

        self.queued_to_client.extend(output);
        Ok(())
    }

    fn maybe_send_post_handshake(&mut self) -> io::Result<()> {
        if self.post_handshake_sent || self.server.is_handshaking() {
            return Ok(());
        }

        self.post_handshake_sent = true;
        match &self.input.post_handshake {
            PostHandshakeAction::None => {}
            PostHandshakeAction::ServerData(data) => {
                let payload = truncate_bytes(data, MAX_PAYLOAD_LEN);
                if !payload.is_empty() {
                    self.server.writer().write_all(&payload)?;
                }
            }
            PostHandshakeAction::ServerDataThenClose(data) => {
                let payload = truncate_bytes(data, MAX_PAYLOAD_LEN);
                if !payload.is_empty() {
                    self.server.writer().write_all(&payload)?;
                }
                self.server.send_close_notify();
            }
            PostHandshakeAction::CloseNotifyOnly => {
                self.server.send_close_notify();
            }
            PostHandshakeAction::EofAfterHandshake => {
                self.eof_after_drain = true;
            }
        }

        self.queue_server_output()
    }
}

impl AsyncRead for LoopbackServerIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.read_ops += 1;
        if Self::maybe_pending(cx, self.input.pending_read_every, self.read_ops) {
            return Poll::Pending;
        }

        if self.queued_to_client.is_empty() {
            if self.eof_after_drain {
                return Poll::Ready(Ok(()));
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        let max_chunk = self.read_chunk_limit().min(buf.remaining());
        for _ in 0..max_chunk {
            let Some(byte) = self.queued_to_client.pop_front() else {
                break;
            };
            buf.put_slice(&[byte]);
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for LoopbackServerIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_ops += 1;
        if Self::maybe_pending(cx, self.input.pending_write_every, self.write_ops) {
            return Poll::Pending;
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let accepted = buf.len().min(self.write_chunk_limit());
        let mut cursor = Cursor::new(&buf[..accepted]);
        self.server.read_tls(&mut cursor)?;
        self.server
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.queue_server_output()?;
        self.maybe_send_post_handshake()?;
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.eof_after_drain = true;
        Poll::Ready(Ok(()))
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(mut input) = Unstructured::new(data).arbitrary::<TlsStreamRecordInput>() else {
        return;
    };
    normalize_input(&mut input);

    let Some(connector) = test_connector() else {
        return;
    };
    let Some(io) = LoopbackServerIo::new(input.clone()) else {
        return;
    };

    let runtime = match simple_runtime() {
        Ok(runtime) => runtime,
        Err(_) => return,
    };

    let clean_success_expected = expects_clean_success(&input);
    let async_input = input.clone();
    let result = runtime.block_on(async move {
        let connect_result = timeout(
            wall_now(),
            Duration::from_millis(CONNECT_TIMEOUT_MS),
            connector.connect("localhost", io),
        )
        .await;

        let mut stream = match connect_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(_)) => return Outcome::ConnectErr,
            Err(_) => return Outcome::ConnectTimeout,
        };

        if !async_input.client_payload.is_empty() {
            let write_result = timeout(
                wall_now(),
                Duration::from_millis(IO_TIMEOUT_MS),
                stream.write_all(&async_input.client_payload),
            )
            .await;

            if clean_success_expected {
                match write_result {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => panic!("clean TLS stream write should succeed: {err}"),
                    Err(_) => panic!("clean TLS stream write should not time out"),
                }
            }
        }

        if expected_server_plaintext(&async_input.post_handshake).is_some()
            || !clean_success_expected
        {
            let mut read_buf = Vec::new();
            let read_result = timeout(
                wall_now(),
                Duration::from_millis(IO_TIMEOUT_MS),
                stream.read_to_end(&mut read_buf),
            )
            .await;

            if clean_success_expected {
                match read_result {
                    Ok(Ok(_)) => {
                        if let Some(expected) =
                            expected_server_plaintext(&async_input.post_handshake)
                        {
                            assert_eq!(read_buf, expected, "clean server plaintext must roundtrip");
                        }
                    }
                    Ok(Err(err)) => panic!("clean TLS stream read should succeed: {err}"),
                    Err(_) => panic!("clean TLS stream read should not time out"),
                }
            }
        }

        let _ = timeout(
            wall_now(),
            Duration::from_millis(IO_TIMEOUT_MS),
            stream.shutdown(),
        )
        .await;

        Outcome::ConnectOk
    });

    if clean_success_expected {
        assert!(
            matches!(result, Outcome::ConnectOk),
            "clean TLS stream path must succeed, got {result:?}"
        );
    }
});

fn normalize_input(input: &mut TlsStreamRecordInput) {
    input.client_payload = truncate_bytes(&input.client_payload, MAX_PAYLOAD_LEN);
    if let PostHandshakeAction::ServerData(data) | PostHandshakeAction::ServerDataThenClose(data) =
        &mut input.post_handshake
    {
        *data = truncate_bytes(data, MAX_PAYLOAD_LEN);
    }
    if let ServerMutation::AppendGarbage(bytes) = &mut input.mutation {
        *bytes = truncate_bytes(bytes, MAX_TRAILING_GARBAGE);
    }
}

fn truncate_bytes(bytes: &[u8], max_len: usize) -> Vec<u8> {
    bytes.iter().copied().take(max_len).collect()
}

fn expected_server_plaintext(action: &PostHandshakeAction) -> Option<Vec<u8>> {
    match action {
        PostHandshakeAction::ServerData(data) | PostHandshakeAction::ServerDataThenClose(data) => {
            Some(truncate_bytes(data, MAX_PAYLOAD_LEN))
        }
        PostHandshakeAction::CloseNotifyOnly | PostHandshakeAction::EofAfterHandshake => {
            Some(Vec::new())
        }
        PostHandshakeAction::None => None,
    }
}

fn expects_clean_success(input: &TlsStreamRecordInput) -> bool {
    matches!(input.mutation, ServerMutation::None)
}

fn apply_mutation(bytes: &mut Vec<u8>, mutation: &ServerMutation) {
    match mutation {
        ServerMutation::None => {}
        ServerMutation::TruncateFirstFlight { drop_bytes } => {
            let keep = bytes.len().saturating_sub(usize::from(*drop_bytes).max(1));
            bytes.truncate(keep);
        }
        ServerMutation::CorruptFirstFlightByte { offset, mask } => {
            if !bytes.is_empty() {
                let idx = usize::from(*offset) % bytes.len();
                bytes[idx] ^= (*mask).max(1);
            }
        }
        ServerMutation::InflateFirstRecordLength { extra } => {
            if bytes.len() >= 5 {
                let len = u16::from_be_bytes([bytes[3], bytes[4]]);
                let inflated = len.saturating_add(u16::from(*extra).max(1));
                let encoded = inflated.to_be_bytes();
                bytes[3] = encoded[0];
                bytes[4] = encoded[1];
            }
        }
        ServerMutation::AppendGarbage(extra) => {
            bytes.extend_from_slice(&truncate_bytes(extra, MAX_TRAILING_GARBAGE));
        }
    }
}

fn test_connector() -> Option<TlsConnector> {
    static CONNECTOR: OnceLock<Option<TlsConnector>> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            let certs = Certificate::from_pem(TEST_CERT_PEM.as_bytes()).ok()?;
            let root = certs.into_iter().next()?;
            TlsConnectorBuilder::new()
                .add_root_certificate(&root)
                .handshake_timeout(Duration::from_millis(CONNECT_TIMEOUT_MS))
                .build()
                .ok()
        })
        .clone()
}

fn server_config() -> Option<Arc<ServerConfig>> {
    static CONFIG: OnceLock<Option<Arc<ServerConfig>>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let cert = parse_fixture_cert()?;
        let key = parse_fixture_key()?;
        let builder = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .ok()?;
        let config = builder
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .ok()?;
        Some(Arc::new(config))
    })
    .clone()
}

fn parse_fixture_cert() -> Option<CertificateDer<'static>> {
    let mut cursor = Cursor::new(TEST_CERT_PEM.as_bytes());
    rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .ok()?
        .into_iter()
        .next()
}

fn parse_fixture_key() -> Option<PrivateKeyDer<'static>> {
    let mut cursor = Cursor::new(TEST_KEY_PEM.as_bytes());
    rustls_pemfile::pkcs8_private_keys(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .ok()?
        .into_iter()
        .next()
        .map(PrivateKeyDer::Pkcs8)
}

fn simple_runtime() -> Result<Runtime, asupersync::error::Error> {
    RuntimeBuilder::current_thread().build()
}
