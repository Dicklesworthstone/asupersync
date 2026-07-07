//! End-to-end ATP-over-QUIC transfer over real loopback UDP sockets.
//!
//! This is the B4 gate for `asupersync-arq-quic-epic-b0k8qo.2`: it proves the
//! public [`transport_quic::send_path`] actually moves bytes to a real QUIC
//! receiver, not via the in-process `establish_loopback` substitute but over two
//! real `QuicUdpEndpoint` sockets on `127.0.0.1`, with the genuine
//! `rustls::quic` TLS-1.3 handshake (real WebPKI server-identity verification),
//! QUIC 1-RTT AEAD authentication, RaptorQ symbols sprayed as QUIC DATAGRAMs, the
//! fountain feedback loop recovering simulated symbol loss, and SHA-256 +
//! flat-merkle verification before an atomic commit.
//!
//! Covers the B4 acceptance shape: single file, directory tree, an object that
//! spans more than one RaptorQ source block, and datagram loss → K-of-N decode
//! → verify → commit.

#![cfg(all(feature = "tls", feature = "test-internals"))]

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use asupersync::cx::Cx;
use asupersync::net::atp::transport_quic::native_link::{
    QuicClientTls, QuicServerTls, bind_server_endpoint, receive_on_endpoint,
};
use asupersync::net::atp::transport_quic::{
    DEFAULT_MAX_BLOCK_SIZE, DEFAULT_SYMBOL_SIZE, QuicConfig, QuicTransportError, ReceiveReport,
    SendReport, send_path,
};
use asupersync::net::quic_native::handshake_driver::{ATP_QUIC_ALPN, client_config, server_config};
use asupersync::observability::{LogCollector, LogLevel};
use asupersync::security::SecurityContext;
use futures_lite::future::{block_on, zip};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, RootCertStore};

// Canonical CA + leaf chain (P-256), leaf has SAN DNS:localhost / IP:127.0.0.1
// and the serverAuth EKU rustls-webpki requires; the client trusts the CA, so
// the handshake exercises the REAL WebPKI verifier (no insecure skip-verify).
// Shared with `tests/quic_native_handshake_udp_loopback.rs`.
const LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBwTCCAWigAwIBAgIUTQyiZ96ufyKHVqRYRZBXpRQABGMwCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAUMRIwEAYDVQQDDAlhdHBxLXRlc3QwWTATBgcqhkjOPQIBBggq\n\
hkjOPQMBBwNCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBbxlDvlrJDWhuXLXcrwcK4\n\
eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hdo4GSMIGPMBoGA1UdEQQTMBGCCWxv\n\
Y2FsaG9zdIcEfwAAATATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA\n\
MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUTWWIxYJyvXlJNVcDd8An36rhuMQw\n\
HwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNzvtYwCgYIKoZIzj0EAwIDRwAw\n\
RAIgOkNWPyvljX7zxCWN9sJ/rpX7XV5ubXvNrPdV70sF8oECIGtMuJr6XEmcump1\n\
YuX2YYZ2gAU6aNU/up/PediXcN5u\n\
-----END CERTIFICATE-----\n";

const LEAF_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpE59cRbMDhBIZaha\n\
UPAvB8O86PWbkhxy/8cx/FrSa1ShRANCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBb\n\
xlDvlrJDWhuXLXcrwcK4eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hd\n\
-----END PRIVATE KEY-----\n";

const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBlDCCATugAwIBAgIUYOTxo/FMMZjqCnJT+IDmJ2BNux0wCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAXMRUwEwYDVQQDDAxhdHBxLXRlc3QtY2EwWTATBgcqhkjOPQIB\n\
BggqhkjOPQMBBwNCAASAsNg5paEJFgZwYGu7aCzsZYPyDyjzzcT7fi3O5JHGW0xA\n\
pTqjgqykWTDkyfwdITXWXIfrx2D2+QwoGXOV4OFSo2MwYTAdBgNVHQ4EFgQUG872\n\
eUJJNl9C6SZHmR9sCRNzvtYwHwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNz\n\
vtYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID\n\
RwAwRAIgFLcs0Qdsy190QfKzpvLj28srfpw6wZ2PURF20N+twm8CIFZMWnG65VsE\n\
WkX8ykcdUfalGtZ1XFOTo+aaWs+3gyI1\n\
-----END CERTIFICATE-----\n";

// 2127-01-01T00:00:00Z, after LEAF_CERT_PEM's 2126-05-23 notAfter.
const AFTER_LEAF_CERT_EXPIRY_UNIX_SECS: u64 = 4_954_435_200;

#[derive(Debug)]
struct FixedTimeProvider {
    now: UnixTime,
}

impl TimeProvider for FixedTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        Some(self.now)
    }
}

fn parse_one_cert(pem: &str) -> CertificateDer<'static> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .next()
        .expect("one cert")
        .expect("valid cert pem")
}

fn leaf_key() -> PrivateKeyDer<'static> {
    let mut reader = std::io::BufReader::new(LEAF_KEY_PEM.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .expect("read key pem")
        .expect("one key")
}

fn client_tls() -> QuicClientTls {
    let alpn = vec![ATP_QUIC_ALPN.to_vec()];
    QuicClientTls {
        server_name: ServerName::try_from("localhost").expect("server name"),
        config: client_config(vec![parse_one_cert(CA_CERT_PEM)], alpn).expect("client config"),
    }
}

fn client_config_at_time(
    roots: Vec<CertificateDer<'static>>,
    alpn: Vec<Vec<u8>>,
    unix_secs: u64,
) -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    for cert in roots {
        root_store.add(cert).expect("root certificate must parse");
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let fixed_time = UnixTime::since_unix_epoch(Duration::from_secs(unix_secs));
    let mut config = ClientConfig::builder_with_details(
        provider,
        Arc::new(FixedTimeProvider { now: fixed_time }),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("client protocol versions")
    .with_root_certificates(root_store)
    .with_no_client_auth();
    config.alpn_protocols = alpn;
    Arc::new(config)
}

fn server_tls() -> QuicServerTls {
    let alpn = vec![ATP_QUIC_ALPN.to_vec()];
    QuicServerTls {
        config: server_config(vec![parse_one_cert(LEAF_CERT_PEM)], leaf_key(), alpn)
            .expect("server config"),
    }
}

/// A pair of matching send/receive configs sharing the same direct transport auth posture.
struct Configs {
    send: QuicConfig,
    recv: QuicConfig,
}

// Loopback transfers complete in well under a second; tight timeouts keep any
// regression from hanging the suite for the 60s production default.
const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_QUIC_SOURCE_SYMBOLS_PER_BLOCK: usize = 512;
const LOSSY_PROXY_TIMEOUT: Duration = Duration::from_secs(75);

fn tighten_timeouts(cfg: &mut QuicConfig) {
    cfg.idle_timeout = TEST_TIMEOUT;
    cfg.handshake_timeout = TEST_TIMEOUT;
    cfg.accept_timeout = TEST_TIMEOUT;
}

fn assert_default_quic_k512(cfg: &QuicConfig) {
    assert_eq!(cfg.symbol_size, DEFAULT_SYMBOL_SIZE);
    assert_eq!(cfg.max_block_size, DEFAULT_MAX_BLOCK_SIZE);
    assert_eq!(
        cfg.max_block_size / usize::from(cfg.symbol_size),
        DEFAULT_QUIC_SOURCE_SYMBOLS_PER_BLOCK
    );
    assert_eq!(
        DEFAULT_MAX_BLOCK_SIZE,
        usize::from(DEFAULT_SYMBOL_SIZE) * DEFAULT_QUIC_SOURCE_SYMBOLS_PER_BLOCK
    );
}

fn authenticated_configs(seed: u64) -> Configs {
    let mut send = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(seed));
    send.client_tls = Some(client_tls());
    tighten_timeouts(&mut send);
    let mut recv = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(seed));
    recv.server_tls = Some(server_tls());
    tighten_timeouts(&mut recv);
    Configs { send, recv }
}

fn transport_authenticated_configs() -> Configs {
    let mut send = QuicConfig::default().use_transport_authenticated_symbols();
    send.client_tls = Some(client_tls());
    tighten_timeouts(&mut send);
    let mut recv = QuicConfig::default().use_transport_authenticated_symbols();
    recv.server_tls = Some(server_tls());
    tighten_timeouts(&mut recv);
    Configs { send, recv }
}

/// Run a full send_path -> receive_on_endpoint transfer over real loopback UDP.
fn run_transfer(
    send_cfg: QuicConfig,
    recv_cfg: QuicConfig,
    source: &Path,
    dest_dir: &Path,
) -> (
    Result<SendReport, QuicTransportError>,
    Result<ReceiveReport, QuicTransportError>,
) {
    block_on(async {
        let cx = Cx::for_testing();
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_endpoint = bind_server_endpoint(&cx, listen)
            .await
            .expect("bind server endpoint");
        let server_addr = server_endpoint.local_addr();

        zip(
            send_path(&cx, server_addr, source, send_cfg, "atp-quic-client"),
            receive_on_endpoint(&cx, server_endpoint, dest_dir, &recv_cfg, "atp-quic-server"),
        )
        .await
    })
}

#[derive(Debug)]
struct DelayedPacket {
    due: Instant,
    target: SocketAddr,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct ProxyRateLimit {
    bytes_per_sec: u64,
    burst_bytes: u64,
    max_queue_delay: Duration,
}

#[derive(Debug)]
struct ProxyRateState {
    limit: ProxyRateLimit,
    next_available: Instant,
}

impl ProxyRateState {
    fn new(limit: ProxyRateLimit) -> Self {
        Self {
            limit,
            next_available: Instant::now(),
        }
    }

    fn schedule(&mut self, now: Instant, bytes: usize) -> Option<Instant> {
        if self.limit.bytes_per_sec == 0 {
            return Some(now);
        }
        let burst_window =
            duration_for_rate_bytes(self.limit.burst_bytes, self.limit.bytes_per_sec);
        let burst_floor = now.checked_sub(burst_window).unwrap_or(now);
        self.next_available = self.next_available.max(burst_floor);
        let due = self.next_available.max(now);
        if due.duration_since(now) > self.limit.max_queue_delay {
            return None;
        }
        let interval = duration_for_rate_bytes(
            u64::try_from(bytes.max(1)).unwrap_or(u64::MAX),
            self.limit.bytes_per_sec,
        );
        self.next_available = due.checked_add(interval).unwrap_or(due);
        Some(due)
    }
}

fn duration_for_rate_bytes(bytes: u64, bytes_per_sec: u64) -> Duration {
    if bytes_per_sec == 0 {
        return Duration::ZERO;
    }
    let nanos = u128::from(bytes)
        .saturating_mul(1_000_000_000)
        .div_ceil(u128::from(bytes_per_sec));
    Duration::from_nanos(u64::try_from(nanos.max(1)).unwrap_or(u64::MAX))
}

#[derive(Debug)]
struct DeterministicLoss {
    state: u64,
}

impl DeterministicLoss {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        u32::try_from(self.state >> 32).expect("shifted PRNG state fits u32")
    }

    fn chance_per_mille(&mut self, per_mille: u32) -> bool {
        self.next_u32() % 1_000 < per_mille
    }

    fn millis_below(&mut self, upper_exclusive: u64) -> u64 {
        u64::from(self.next_u32()) % upper_exclusive.max(1)
    }
}

struct LossyUdpProxy {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl LossyUdpProxy {
    #[allow(dead_code)]
    fn spawn_with_rate(
        server_addr: SocketAddr,
        seed: u64,
        data_rate_limit: Option<ProxyRateLimit>,
    ) -> Self {
        Self::spawn_with_rate_timeout(server_addr, seed, data_rate_limit, LOSSY_PROXY_TIMEOUT)
    }

    fn spawn_with_rate_timeout(
        server_addr: SocketAddr,
        seed: u64,
        data_rate_limit: Option<ProxyRateLimit>,
        proxy_timeout: Duration,
    ) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind lossy proxy");
        socket
            .set_nonblocking(true)
            .expect("proxy socket nonblocking");
        let addr = socket.local_addr().expect("proxy local addr");
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            run_lossy_proxy(
                socket,
                server_addr,
                thread_stop,
                seed,
                data_rate_limit,
                proxy_timeout,
            );
        });
        Self {
            addr,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for LossyUdpProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = UdpSocket::bind("127.0.0.1:0")
            .and_then(|socket| socket.send_to(&[0], self.addr).map(|_| ()));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn enqueue_lossy_packet(
    pending: &mut VecDeque<DelayedPacket>,
    rng: &mut DeterministicLoss,
    rate: Option<&mut ProxyRateState>,
    packet_index: u64,
    target: SocketAddr,
    bytes: &[u8],
) {
    const HANDSHAKE_PACKET_PREFIX: u64 = 64;
    const LOSS_PER_MILLE: u32 = 100;
    const DUP_PER_MILLE: u32 = 10;
    const REORDER_PER_MILLE: u32 = 50;
    const BASE_DELAY_MS: u64 = 100;
    const JITTER_MS: u64 = 8;
    const REORDER_EXTRA_MS: u64 = 12;

    let protected = packet_index <= HANDSHAKE_PACKET_PREFIX;
    if !protected && rng.chance_per_mille(LOSS_PER_MILLE) {
        return;
    }

    let now = Instant::now();
    let mut delay = if protected {
        0
    } else {
        BASE_DELAY_MS + rng.millis_below(JITTER_MS)
    };
    if !protected && rng.chance_per_mille(REORDER_PER_MILLE) {
        delay = delay.saturating_add(REORDER_EXTRA_MS);
    }
    let mut due = now + Duration::from_millis(delay);
    if !protected && let Some(rate) = rate {
        let Some(rate_due) = rate.schedule(now, bytes.len()) else {
            return;
        };
        due = due.max(rate_due);
    }
    pending.push_back(DelayedPacket {
        due,
        target,
        bytes: bytes.to_vec(),
    });
    if !protected && rng.chance_per_mille(DUP_PER_MILLE) {
        pending.push_back(DelayedPacket {
            due: due + Duration::from_millis(1),
            target,
            bytes: bytes.to_vec(),
        });
    }
}

fn flush_due_proxy_packets(socket: &UdpSocket, pending: &mut VecDeque<DelayedPacket>) {
    let now = Instant::now();
    let mut index = 0usize;
    while index < pending.len() {
        if pending[index].due > now {
            index += 1;
            continue;
        }
        let Some(packet) = pending.remove(index) else {
            continue;
        };
        let _ = socket.send_to(&packet.bytes, packet.target);
    }
}

fn run_lossy_proxy(
    socket: UdpSocket,
    server_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    seed: u64,
    data_rate_limit: Option<ProxyRateLimit>,
    proxy_timeout: Duration,
) {
    let mut rng = DeterministicLoss::new(seed);
    let mut client_addr = None;
    let mut pending = VecDeque::<DelayedPacket>::new();
    let mut packet_index = 0u64;
    let mut data_rate = data_rate_limit.map(ProxyRateState::new);
    let started = Instant::now();
    let mut buf = vec![0u8; 65_535];

    while !stop.load(Ordering::Relaxed) && started.elapsed() < proxy_timeout {
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    let target = if src == server_addr {
                        let Some(client) = client_addr else {
                            continue;
                        };
                        client
                    } else {
                        client_addr = Some(src);
                        server_addr
                    };
                    packet_index = packet_index.saturating_add(1);
                    let rate = (target == server_addr)
                        .then_some(())
                        .and_then(|()| data_rate.as_mut());
                    enqueue_lossy_packet(
                        &mut pending,
                        &mut rng,
                        rate,
                        packet_index,
                        target,
                        &buf[..len],
                    );
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(_) => return,
            }
        }
        flush_due_proxy_packets(&socket, &mut pending);
        thread::sleep(Duration::from_millis(1));
    }
}

#[allow(dead_code)]
fn run_transfer_via_rate_limited_lossy_proxy(
    send_cfg: QuicConfig,
    recv_cfg: QuicConfig,
    source: &Path,
    dest_dir: &Path,
    seed: u64,
    data_rate_limit: ProxyRateLimit,
) -> (
    Result<SendReport, QuicTransportError>,
    Result<ReceiveReport, QuicTransportError>,
    LogCollector,
) {
    run_transfer_via_rate_limited_lossy_proxy_with_timeout(
        send_cfg,
        recv_cfg,
        source,
        dest_dir,
        seed,
        data_rate_limit,
        LOSSY_PROXY_TIMEOUT,
    )
}

fn run_transfer_via_rate_limited_lossy_proxy_with_timeout(
    send_cfg: QuicConfig,
    recv_cfg: QuicConfig,
    source: &Path,
    dest_dir: &Path,
    seed: u64,
    data_rate_limit: ProxyRateLimit,
    proxy_timeout: Duration,
) -> (
    Result<SendReport, QuicTransportError>,
    Result<ReceiveReport, QuicTransportError>,
    LogCollector,
) {
    block_on(async {
        let cx = Cx::for_testing();
        let collector = LogCollector::new(512).with_min_level(LogLevel::Trace);
        cx.set_log_collector(collector.clone());
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_endpoint = bind_server_endpoint(&cx, listen)
            .await
            .expect("bind server endpoint");
        let server_addr = server_endpoint.local_addr();
        let proxy = LossyUdpProxy::spawn_with_rate_timeout(
            server_addr,
            seed,
            Some(data_rate_limit),
            proxy_timeout,
        );

        let (send, recv) = zip(
            send_path(&cx, proxy.addr, source, send_cfg, "atp-quic-client"),
            receive_on_endpoint(&cx, server_endpoint, dest_dir, &recv_cfg, "atp-quic-server"),
        )
        .await;
        (send, recv, collector)
    })
}

fn run_transfer_via_lossy_proxy(
    send_cfg: QuicConfig,
    recv_cfg: QuicConfig,
    source: &Path,
    dest_dir: &Path,
    seed: u64,
    proxy_timeout: Duration,
) -> (
    Result<SendReport, QuicTransportError>,
    Result<ReceiveReport, QuicTransportError>,
) {
    block_on(async {
        let cx = Cx::for_testing();
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_endpoint = bind_server_endpoint(&cx, listen)
            .await
            .expect("bind server endpoint");
        let server_addr = server_endpoint.local_addr();
        let proxy = LossyUdpProxy::spawn_with_rate_timeout(server_addr, seed, None, proxy_timeout);

        zip(
            send_path(&cx, proxy.addr, source, send_cfg, "atp-quic-client"),
            receive_on_endpoint(&cx, server_endpoint, dest_dir, &recv_cfg, "atp-quic-server"),
        )
        .await
    })
}

fn need_more_round_losses(collector: &LogCollector) -> Vec<f64> {
    collector
        .peek()
        .into_iter()
        .filter(|entry| entry.message() == "atp_quic.receive.need_more")
        .filter_map(|entry| {
            entry
                .get_field("round_loss_fraction")
                .and_then(|value| value.parse::<f64>().ok())
        })
        .collect()
}

fn assert_receive_report_counters(
    send: &SendReport,
    recv: &ReceiveReport,
    expected_bytes: u64,
    expected_files: u32,
) {
    assert!(recv.committed, "receiver must commit");
    assert_eq!(recv.bytes_received, expected_bytes);
    assert_eq!(recv.files, expected_files);
    assert_eq!(send.transfer_id, recv.transfer_id);
    assert_eq!(send.receipt.symbols_accepted, recv.symbols_accepted);
    assert_eq!(send.receipt.feedback_rounds, recv.feedback_rounds);
    assert_eq!(send.receipt.decode_count, recv.decode_count);
    assert!(
        recv.symbols_accepted > 0,
        "receiver report must expose accepted-symbol progress"
    );
    assert!(
        recv.decode_count > 0,
        "receiver report must expose at least one decoded block"
    );
    assert!(
        recv.committed_paths.len() >= usize::try_from(expected_files).expect("file count fits"),
        "receiver report must expose committed-path evidence"
    );
}

/// Assert the receiver left no `.atp-quic-staging-*` residue in the destination
/// (the staging directory must be reclaimed on every path).
fn assert_no_staging_residue(dest_dir: &Path) {
    for entry in std::fs::read_dir(dest_dir).expect("read dest dir") {
        let name = entry.expect("dir entry").file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.starts_with(".atp-quic-staging"),
            "receiver leaked a staging directory: {name}"
        );
    }
}

fn assert_send_fails_closed_before_commit(send: QuicConfig, recv: QuicConfig, file_name: &str) {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let source = src.path().join(file_name);
    std::fs::write(&source, b"secret payload").expect("write source");

    let (send_res, _recv_res) = run_transfer(send, recv, &source, dst.path());
    assert!(
        send_res.is_err(),
        "client must not complete a transfer when server identity verification fails"
    );
    assert!(
        std::fs::read(dst.path().join(file_name)).is_err(),
        "no bytes may be committed when the handshake fails closed"
    );
}

#[test]
fn real_udp_quic_transfer_single_file_authenticated() {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let source = src.path().join("payload.bin");
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source, &payload).expect("write source");

    let cfg = authenticated_configs(0x51A7);
    let (send, recv) = run_transfer(cfg.send, cfg.recv, &source, dst.path());

    let send = send.expect("send_path completes over real UDP");
    let recv = recv.expect("receiver commits");
    assert_receive_report_counters(&send, &recv, payload.len() as u64, 1);
    assert_eq!(
        recv.feedback_rounds, 0,
        "lossless loopback should not need repair feedback rounds"
    );
    assert_eq!(send.files, 1);
    assert_eq!(send.bytes_sent, payload.len() as u64);
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);

    let committed = dst.path().join("payload.bin");
    assert_eq!(
        std::fs::read(&committed).expect("read committed file"),
        payload,
        "committed bytes must match the source"
    );
    assert_no_staging_residue(dst.path());
}

#[test]
fn real_udp_quic_good_transport_auth_uses_reliable_source_stream() {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let source = src.path().join("good-stream.bin");
    let payload: Vec<u8> = (0..16384u32)
        .map(|i| (i.wrapping_mul(19).wrapping_add(7) % 251) as u8)
        .collect();
    std::fs::write(&source, &payload).expect("write source");

    let mut cfg = transport_authenticated_configs();
    cfg.send.round0_loss_target = 0.001;
    cfg.recv.round0_loss_target = 0.001;
    let (send, recv) = run_transfer(cfg.send, cfg.recv, &source, dst.path());

    let send = send.expect("GOOD transport-auth source stream send_path completes");
    let recv = recv.expect("GOOD transport-auth source stream receiver commits");
    assert!(recv.committed, "receiver must commit");
    assert_eq!(send.transfer_id, recv.transfer_id);
    assert_eq!(send.files, 1);
    assert_eq!(recv.files, 1);
    assert_eq!(send.bytes_sent, payload.len() as u64);
    assert_eq!(recv.bytes_received, payload.len() as u64);
    assert!(
        send.symbols_sent > 0,
        "GOOD transport-auth transfers should send source bytes on the reliable stream plus a small FEC repair tail"
    );
    assert!(
        recv.symbols_accepted > 0,
        "receiver should feed source-stream symbols through the RaptorQ decoder"
    );
    assert!(
        recv.decode_count > 0,
        "source-stream bytes should complete through the block decoder before commit"
    );
    assert_eq!(
        recv.feedback_rounds, 0,
        "GOOD transport-auth source-stream transfer should not need fountain repair"
    );
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);
    assert_eq!(
        std::fs::read(dst.path().join("good-stream.bin")).expect("read committed"),
        payload,
        "committed bytes must match the source"
    );
    assert_no_staging_residue(dst.path());
}

#[test]
fn real_udp_quic_broken_loss_transport_auth_source_stream_commits_without_marker_deadlock() {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let source = src.path().join("broken-loss-stream.bin");
    let payload: Vec<u8> = (0..(2 * 1024 * 1024))
        .map(|i| u8::try_from((i * 43 + i / 257 + 29) % 251).expect("byte pattern fits u8"))
        .collect();
    std::fs::write(&source, &payload).expect("write source");

    let mut cfg = transport_authenticated_configs();
    cfg.send.round0_loss_target = 0.10;
    cfg.recv.round0_loss_target = 0.10;
    cfg.send.idle_timeout = Duration::from_secs(45);
    cfg.recv.idle_timeout = Duration::from_secs(45);
    cfg.send.handshake_timeout = Duration::from_secs(20);
    cfg.recv.handshake_timeout = Duration::from_secs(20);
    cfg.send.accept_timeout = Duration::from_secs(20);
    cfg.recv.accept_timeout = Duration::from_secs(20);

    let (send, recv) = run_transfer_via_lossy_proxy(
        cfg.send,
        cfg.recv,
        &source,
        dst.path(),
        0x23_83_50_0A,
        Duration::from_secs(60),
    );
    let send = send.unwrap_or_else(|err| {
        panic!(
            "10% lossy source-stream sender must receive reliable proof: {err:?}; receiver={recv:?}"
        )
    });
    let recv = recv.expect("10% lossy source-stream receiver commits");

    assert!(
        recv.committed,
        "receiver must commit under induced 10% loss"
    );
    assert_eq!(send.transfer_id, recv.transfer_id);
    assert_eq!(send.files, 1);
    assert_eq!(recv.files, 1);
    assert_eq!(send.bytes_sent, payload.len() as u64);
    assert_eq!(recv.bytes_received, payload.len() as u64);
    assert_eq!(
        recv.feedback_rounds, 0,
        "reliable source-stream path should not fall back to RaptorQ repair feedback"
    );
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);
    assert_eq!(
        std::fs::read(dst.path().join("broken-loss-stream.bin")).expect("read committed"),
        payload,
        "committed bytes must match the source through 10% loopback packet loss"
    );
    assert_no_staging_residue(dst.path());
}

/// Regression for br-asupersync-jmri58: the client's final handshake flight
/// (the packets carrying its TLS Finished) is dropped exactly once. A TLS 1.3
/// client completes on *sending* Finished, so before the fix the client moved
/// on to the data plane (dropping the server's retransmitted long-header
/// flight as NotOneRtt) while the server could never complete — a mutual
/// wedge that killed ~19% of broken-regime session establishments. The
/// recovery handshake (server re-offers its flight on early 1-RTT evidence;
/// client re-sends its retained Finished flight when it drops a long-header
/// packet) must converge and the transfer must commit.
#[test]
fn real_udp_quic_transfer_recovers_lost_client_finished_flight() {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let source = src.path().join("finished-drop.bin");
    let payload: Vec<u8> = (0..65536u32)
        .map(|i| u8::try_from((i.wrapping_mul(23).wrapping_add(11)) % 251).expect("byte"))
        .collect();
    std::fs::write(&source, &payload).expect("write source");

    let cfg = transport_authenticated_configs();

    let (send, recv) = block_on(async {
        let cx = Cx::for_testing();
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_endpoint = bind_server_endpoint(&cx, listen)
            .await
            .expect("bind server endpoint");
        let server_addr = server_endpoint.local_addr();

        let proxy_sock = UdpSocket::bind("127.0.0.1:0").expect("bind proxy socket");
        proxy_sock.set_nonblocking(true).expect("proxy nonblocking");
        let proxy_addr = proxy_sock.local_addr().expect("proxy addr");
        let stop = Arc::new(AtomicBool::new(false));
        let proxy = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut client_addr: Option<SocketAddr> = None;
                let mut dropped_finished = 0usize;
                let mut buf = vec![0u8; 65_535];
                let started = Instant::now();
                while !stop.load(Ordering::Relaxed) && started.elapsed() < Duration::from_secs(30) {
                    match proxy_sock.recv_from(&mut buf) {
                        Ok((len, src_addr)) => {
                            let (target, from_client) = if src_addr == server_addr {
                                let Some(client) = client_addr else { continue };
                                (client, false)
                            } else {
                                client_addr = Some(src_addr);
                                (server_addr, true)
                            };
                            // Drop the client's first Handshake-space flight
                            // (the Finished) once: long header (0x80 form bit)
                            // with packet type bits 0x20 (Handshake).
                            if from_client
                                && dropped_finished < 2
                                && len > 0
                                && buf[0] & 0x80 != 0
                                && buf[0] & 0x30 == 0x20
                            {
                                dropped_finished += 1;
                                continue;
                            }
                            let _ = proxy_sock.send_to(&buf[..len], target);
                        }
                        Err(err) if err.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_micros(200));
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        let out = zip(
            send_path(&cx, proxy_addr, &source, cfg.send, "atp-quic-client"),
            receive_on_endpoint(
                &cx,
                server_endpoint,
                dst.path(),
                &cfg.recv,
                "atp-quic-server",
            ),
        )
        .await;
        stop.store(true, Ordering::Relaxed);
        proxy.join().expect("finished-drop proxy thread exits");
        out
    });

    let send = send.unwrap_or_else(|err| {
        panic!("sender must recover a lost Finished flight: {err:?}; receiver={recv:?}")
    });
    let recv = recv.expect("receiver must complete the handshake via recovery");
    assert!(recv.committed, "receiver must commit after recovery");
    assert_eq!(send.transfer_id, recv.transfer_id);
    assert_eq!(recv.bytes_received, payload.len() as u64);
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);
    assert_eq!(
        std::fs::read(dst.path().join("finished-drop.bin")).expect("read committed"),
        payload,
        "committed bytes must match through a dropped Finished flight"
    );
    assert_no_staging_residue(dst.path());
}

/// Regression for br-asupersync-daqxbz: a packed 2000-member tree — whose
/// manifest spans >100 control-stream packets — must commit through a lossy
/// path whose RTT exceeds the base stall PTO. Before the fix, the clock-warped
/// app-data loss expiry fired every 200ms (faster than the ~200ms+ RTT), so
/// every in-flight packet was declared lost and front-requeued before its ACK
/// could return: ACK progress pinned at zero, the retransmit copies starved
/// the never-yet-sent manifest tail forever, the receiver could not finish
/// the manifest (and so never drained the source stream), and both sides
/// wedged to their idle timeouts. The exponential stall-PTO backoff must let
/// ACKs land, clear in-flight, and deliver the manifest tail.
#[test]
fn real_udp_quic_tree_manifest_survives_lossy_control_stream() {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let root = src.path().join("tree");
    std::fs::create_dir_all(&root).expect("mkdir tree root");
    // 2000 members keep the manifest at >100 control-stream packets (the
    // wedge trigger) while ~200-byte bodies keep the bulk phase fast enough
    // for a bounded test runtime; bulk must still be pending during the
    // manifest exchange for the flush-priority contention to exist.
    let mut expected = Vec::with_capacity(2000);
    for index in 0..2000usize {
        let rel = format!("dir_{:02}/member_{index:04}.bin", index % 40);
        let path = root.join(&rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        let len = 160 + (index % 11) * 13;
        let payload = (0..len)
            .map(|byte| ((byte.wrapping_mul(29) + index.wrapping_mul(13)) % 251) as u8)
            .collect::<Vec<_>>();
        std::fs::write(&path, &payload).expect("write tree member");
        expected.push((rel, payload));
    }

    let mut cfg = transport_authenticated_configs();
    // Mirror the broken-regime cell: declared-lossy discipline (MTU packet cap)
    // and timeouts wide enough for lossy recovery yet far below the wedge's
    // 360s signature.
    cfg.send.round0_loss_target = 0.10;
    cfg.recv.round0_loss_target = 0.10;
    cfg.send.idle_timeout = Duration::from_secs(45);
    cfg.recv.idle_timeout = Duration::from_secs(45);
    cfg.send.handshake_timeout = Duration::from_secs(20);
    cfg.recv.handshake_timeout = Duration::from_secs(20);
    cfg.send.accept_timeout = Duration::from_secs(20);
    cfg.recv.accept_timeout = Duration::from_secs(20);

    let (send, recv) = run_transfer_via_lossy_proxy(
        cfg.send,
        cfg.recv,
        &root,
        dst.path(),
        0xDA_0B_2D_15,
        Duration::from_secs(75),
    );

    let send = send.unwrap_or_else(|err| {
        panic!("lossy tree-manifest sender must complete: {err:?}; receiver={recv:?}")
    });
    let recv = recv.expect("lossy tree-manifest receiver commits");
    assert!(recv.committed, "receiver must commit the packed tree");
    assert_eq!(send.transfer_id, recv.transfer_id);
    assert_eq!(send.files as usize, expected.len());
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);
    let committed_paths: Vec<&String> = send.receipt.committed_paths.iter().collect();
    for (rel, payload) in &expected {
        let member_path = committed_paths
            .iter()
            .find(|path| path.ends_with(rel))
            .unwrap_or_else(|| {
                panic!(
                    "member {rel} missing from {} committed paths",
                    committed_paths.len()
                )
            });
        let committed = std::fs::read(member_path)
            .unwrap_or_else(|err| panic!("read committed member {member_path}: {err}"));
        assert_eq!(&committed, payload, "member {rel} bytes must match");
    }
    assert_no_staging_residue(dst.path());
}

/// Regression for br-asupersync-u6m3dy: an undecryptable UDP packet arriving
/// alone in an inbound pump turn must be dropped per QUIC without consuming
/// the idle allowance. Before the fix, `pump_inbound_for` returned `Ok(0)`
/// for a batch whose packets all failed unprotect, and the receive session
/// escalated that zero into a fatal "transport timeout after 360s" seconds
/// into a healthy transfer — every encrypted broken-regime matrix cell ≥5M
/// died this way (uniform ~363s failures with data still flowing).
///
/// The blaster thread sprays plausible 1-RTT short-header junk (0x40 marker +
/// fresh packet numbers + garbage ciphertext) at the receiver for the whole
/// transfer, so many pump turns wake up to a junk-only batch. The transfer
/// must still commit with verified bytes.
#[test]
fn real_udp_quic_transfer_survives_solo_undecryptable_junk_packets() {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let source = src.path().join("junk-survivor.bin");
    let payload: Vec<u8> = (0..(4 * 1024 * 1024))
        .map(|i| u8::try_from((i * 31 + i / 509 + 17) % 251).expect("byte pattern fits u8"))
        .collect();
    std::fs::write(&source, &payload).expect("write source");

    let cfg = transport_authenticated_configs();

    let (send, recv) = block_on(async {
        let cx = Cx::for_testing();
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_endpoint = bind_server_endpoint(&cx, listen)
            .await
            .expect("bind server endpoint");
        let server_addr = server_endpoint.local_addr();

        let stop = Arc::new(AtomicBool::new(false));
        let blaster = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let sock = UdpSocket::bind("127.0.0.1:0").expect("bind junk socket");
                // Let the (loopback-fast) handshake finish so the junk lands
                // on the established 1-RTT pump, matching the wedge cells.
                thread::sleep(Duration::from_millis(200));
                let mut junk = [0u8; 48];
                junk[0] = 0x40;
                for (i, byte) in junk.iter_mut().enumerate().skip(9) {
                    *byte = u8::try_from((i * 37 + 11) % 251).expect("byte pattern fits u8");
                }
                let mut fake_pn: u64 = 0xFFFF_0000_0000_0000;
                while !stop.load(Ordering::Relaxed) {
                    junk[1..9].copy_from_slice(&fake_pn.to_be_bytes());
                    fake_pn = fake_pn.wrapping_add(1);
                    let _ = sock.send_to(&junk, server_addr);
                    thread::sleep(Duration::from_micros(500));
                }
            })
        };

        let out = zip(
            send_path(&cx, server_addr, &source, cfg.send, "atp-quic-client"),
            receive_on_endpoint(
                &cx,
                server_endpoint,
                dst.path(),
                &cfg.recv,
                "atp-quic-server",
            ),
        )
        .await;
        stop.store(true, Ordering::Relaxed);
        blaster.join().expect("junk blaster thread exits");
        out
    });

    let send = send.unwrap_or_else(|err| {
        panic!("sender must survive junk-packet spray: {err:?}; receiver={recv:?}")
    });
    let recv = recv.expect("receiver must drop junk packets without fake idle timeout");

    assert!(recv.committed, "receiver must commit through junk spray");
    assert_eq!(send.transfer_id, recv.transfer_id);
    assert_eq!(send.bytes_sent, payload.len() as u64);
    assert_eq!(recv.bytes_received, payload.len() as u64);
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);
    assert_eq!(
        std::fs::read(dst.path().join("junk-survivor.bin")).expect("read committed"),
        payload,
        "committed bytes must match the source through continuous junk spray"
    );
    assert_no_staging_residue(dst.path());
}

fn assert_non_dividing_transport_auth_transfer(
    max_block_size: usize,
    file_name: &str,
    len: usize,
    round0_loss_target: f64,
) {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let source = src.path().join(file_name);
    let payload: Vec<u8> = (0..len)
        .map(|i| {
            let byte = i.wrapping_mul(37).wrapping_add(i / 97).wrapping_add(13) % 251;
            u8::try_from(byte).expect("byte pattern fits u8")
        })
        .collect();
    std::fs::write(&source, &payload).expect("write source");

    let mut cfg = transport_authenticated_configs();
    cfg.send.symbol_size = 1141;
    cfg.recv.symbol_size = 1141;
    cfg.send.max_block_size = max_block_size;
    cfg.recv.max_block_size = max_block_size;
    cfg.send.round0_loss_target = round0_loss_target;
    cfg.recv.round0_loss_target = round0_loss_target;

    let (send, recv) = run_transfer(cfg.send, cfg.recv, &source, dst.path());
    let send = send.unwrap_or_else(|err| {
        panic!(
            "non-dividing QUIC/TLS send must not fail handshake for max_block_size={max_block_size}: {err:?}; receiver={recv:?}"
        )
    });
    let recv = recv.expect("non-dividing QUIC/TLS receiver commits");

    assert_receive_report_counters(&send, &recv, payload.len() as u64, 1);
    assert_eq!(send.transfer_id, recv.transfer_id);
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);
    assert_eq!(
        std::fs::read(dst.path().join(file_name)).expect("read committed non-dividing transfer"),
        payload,
        "committed bytes must match the source for non-dividing symbol geometry"
    );
    assert_no_staging_residue(dst.path());
}

#[test]
fn real_udp_quic_transport_auth_accepts_non_dividing_default_block_geometry() {
    assert_non_dividing_transport_auth_transfer(
        512 * 1024,
        "nondividing-default.bin",
        16 * 1024,
        0.01,
    );
}

#[test]
fn real_udp_quic_transport_auth_accepts_non_dividing_4m_block_geometry() {
    assert_non_dividing_transport_auth_transfer(
        4 * 1024 * 1024,
        "nondividing-4m.bin",
        1024 * 1024,
        0.01,
    );
}

#[test]
fn real_udp_quic_transfer_directory_tree_authenticated() {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let root = src.path().join("tree");
    std::fs::create_dir_all(root.join("sub")).expect("mkdir sub");
    let a = (0..2048u32).map(|i| (i % 97) as u8).collect::<Vec<_>>();
    let b = (0..3000u32)
        .map(|i| (i.wrapping_mul(7) % 211) as u8)
        .collect::<Vec<_>>();
    let c = b"a small leaf file".to_vec();
    std::fs::write(root.join("a.bin"), &a).expect("write a");
    std::fs::write(root.join("sub/b.bin"), &b).expect("write b");
    std::fs::write(root.join("sub/c.txt"), &c).expect("write c");

    let cfg = authenticated_configs(0x7EE2);
    let (send, recv) = run_transfer(cfg.send, cfg.recv, &root, dst.path());

    let send = send.expect("send_path completes over real UDP");
    let recv = recv.expect("receiver commits");
    let expected_bytes = u64::try_from(a.len() + b.len() + c.len()).expect("test size fits");
    assert_receive_report_counters(&send, &recv, expected_bytes, 3);
    assert_eq!(
        recv.feedback_rounds, 0,
        "lossless directory loopback should not need repair feedback rounds"
    );
    assert_eq!(send.files, 3);

    let base = dst.path().join("tree");
    assert_eq!(std::fs::read(base.join("a.bin")).expect("read a"), a);
    assert_eq!(std::fs::read(base.join("sub/b.bin")).expect("read b"), b);
    assert_eq!(std::fs::read(base.join("sub/c.txt")).expect("read c"), c);
    assert_no_staging_residue(dst.path());
}

fn write_many_entry_tree(root: &Path, count: usize) -> Vec<(String, Vec<u8>)> {
    let mut expected = Vec::with_capacity(count);
    for index in 0..count {
        let rel = match index % 5 {
            0 => format!("alpha/file_{index:02}.bin"),
            1 => format!("alpha/beta/file_{index:02}.bin"),
            2 => format!("gamma/file_{index:02}.dat"),
            3 => format!("delta/epsilon/file_{index:02}.txt"),
            _ => format!("zeta/file_{index:02}.bin"),
        };
        let path = root.join(&rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }

        let len = 4096 + (index % 7) * 257;
        let payload = (0..len)
            .map(|byte_index| ((byte_index.wrapping_mul(31) + index.wrapping_mul(17)) % 251) as u8)
            .collect::<Vec<_>>();
        std::fs::write(&path, &payload).expect("write many-entry tree file");
        expected.push((rel, payload));
    }
    expected
}

#[test]
fn real_udp_quic_transfer_many_entry_tree_reports_sender_success() {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let root = src.path().join("tree");
    let expected = write_many_entry_tree(&root, 35);

    let cfg = authenticated_configs(0x6909);
    let (send_result, recv_result) = run_transfer(cfg.send, cfg.recv, &root, dst.path());

    let send = send_result.unwrap_or_else(|err| {
        panic!(
            "sender receives the final Proof for a 35-entry tree: {err:?}; receiver result: {recv_result:?}"
        )
    });
    let recv = recv_result.expect("receiver commits the 35-entry tree");
    let expected_bytes = expected
        .iter()
        .map(|(_, payload)| u64::try_from(payload.len()).expect("test payload fits"))
        .sum();
    assert_receive_report_counters(&send, &recv, expected_bytes, expected.len() as u32);
    assert_eq!(
        recv.feedback_rounds, 0,
        "lossless many-entry loopback should not need repair feedback rounds"
    );
    assert!(send.receipt.committed, "sender receipt must report commit");
    assert!(
        send.receipt.sha_ok,
        "sender receipt must preserve sha proof"
    );
    assert!(
        send.receipt.merkle_ok,
        "sender receipt must preserve merkle proof"
    );
    assert_eq!(send.transfer_id, recv.transfer_id);
    assert_eq!(send.files, expected.len() as u32);
    assert_eq!(recv.files, expected.len() as u32);
    assert_eq!(
        send.receipt.committed_paths.len(),
        expected.len(),
        "sender must receive the full committed-path proof without timing out"
    );

    let committed_root = dst.path().join("tree");
    for (rel, payload) in expected {
        assert_eq!(
            std::fs::read(committed_root.join(&rel)).expect("read committed many-entry file"),
            payload,
            "committed bytes must match source for {rel}"
        );
    }
    assert_no_staging_residue(dst.path());
}

#[test]
fn real_udp_quic_transfer_multiblock_authenticated() {
    // A file that spans more than one RaptorQ source block (256-byte symbols,
    // 1 KiB blocks -> 4 symbols/block, ~8 blocks for 8 KiB), no loss: proves the
    // multi-block source spray/decode path works over the real link.
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let source = src.path().join("multiblock.bin");
    let payload: Vec<u8> = (0..8192u32)
        .map(|i| (i.wrapping_mul(31).wrapping_add(5) % 253) as u8)
        .collect();
    std::fs::write(&source, &payload).expect("write source");

    let mut send = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(0xB10C));
    send.symbol_size = 256;
    send.max_block_size = 1024;
    send.client_tls = Some(client_tls());
    tighten_timeouts(&mut send);

    let mut recv = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(0xB10C));
    recv.symbol_size = 256;
    recv.max_block_size = 1024;
    recv.server_tls = Some(server_tls());
    tighten_timeouts(&mut recv);

    let (send_res, recv_res) = run_transfer(send, recv, &source, dst.path());
    let send_res = send_res.expect("multi-block send_path completes over real UDP");
    let recv_res = recv_res.expect("receiver commits multi-block object");
    assert_receive_report_counters(&send_res, &recv_res, payload.len() as u64, 1);
    assert_eq!(
        recv_res.feedback_rounds, 0,
        "lossless multi-block loopback should not need repair feedback rounds"
    );
    assert_eq!(send_res.bytes_sent, payload.len() as u64);
    assert_eq!(
        std::fs::read(dst.path().join("multiblock.bin")).expect("read committed"),
        payload,
        "multi-block RaptorQ decode must reconstruct the exact bytes"
    );
}

#[test]
fn real_udp_quic_transfer_recovers_from_symbol_loss() {
    // Datagram loss -> K-of-N decode -> verify -> commit. The sender sprays a
    // generous repair tail and the link deliberately drops every 4th symbol; the
    // RaptorQ fountain property means any K-of-N symbols suffice, so the receiver
    // still reconstructs and commits the exact bytes over the real UDP link.
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let source = src.path().join("lossy.bin");
    let payload: Vec<u8> = (0..16384u32)
        .map(|i| (i.wrapping_mul(53).wrapping_add(11) % 251) as u8)
        .collect();
    std::fs::write(&source, &payload).expect("write source");

    let mut send = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(0xC0FFEE));
    assert_default_quic_k512(&send);
    // 200% repair overhead so K-of-N recovery survives losing every 4th symbol.
    send.repair_overhead = 3.0;
    send.debug_drop_one_in = 4;
    send.client_tls = Some(client_tls());
    tighten_timeouts(&mut send);

    let mut recv = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(0xC0FFEE));
    assert_default_quic_k512(&recv);
    recv.repair_overhead = 3.0;
    recv.server_tls = Some(server_tls());
    tighten_timeouts(&mut recv);

    let (send_res, recv_res) = run_transfer(send, recv, &source, dst.path());
    let send_res = send_res.expect("send_path recovers from simulated symbol loss");
    let recv_res = recv_res.expect("receiver commits after K-of-N recovery");
    assert_receive_report_counters(&send_res, &recv_res, payload.len() as u64, 1);
    assert!(
        recv_res.feedback_rounds <= 1,
        "generous initial repair plus exact-deficit feedback should converge without repeated symbol-rounds"
    );
    assert_eq!(send_res.bytes_sent, payload.len() as u64);
    assert_eq!(
        std::fs::read(dst.path().join("lossy.bin")).expect("read committed"),
        payload,
        "K-of-N RaptorQ recovery must reconstruct the exact bytes despite dropped symbols"
    );
}

#[test]
// pending SapphireHill netns A/B verification
#[ignore]
fn real_udp_quic_pivot_a_rate_limited_lossy_proxy_converges_non_dividing_multiblock() {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let source = src.path().join("pivot-a-rate-limited-lossy-proxy.bin");
    let payload: Vec<u8> = (0..((16 * 1024 * 1024) + 113) as u32)
        .map(|i| (i.wrapping_mul(41).wrapping_add(i / 251).wrapping_add(23) % 251) as u8)
        .collect();
    std::fs::write(&source, &payload).expect("write source");

    let mut cfg = authenticated_configs(0x0001_0CC2);
    cfg.send.symbol_size = 1141;
    cfg.recv.symbol_size = 1141;
    cfg.send.repair_overhead = 1.0;
    cfg.recv.repair_overhead = 1.0;
    cfg.send.round0_loss_target = 0.10;
    cfg.recv.round0_loss_target = 0.10;
    cfg.send.max_block_size = 512 * 1024;
    cfg.recv.max_block_size = 512 * 1024;
    cfg.send.idle_timeout = Duration::from_secs(180);
    cfg.recv.idle_timeout = Duration::from_secs(180);

    let data_rate_limit = ProxyRateLimit {
        bytes_per_sec: 1_250_000,
        burst_bytes: 16 * 1024,
        max_queue_delay: Duration::from_millis(300),
    };
    let (send_res, recv_res, collector) = run_transfer_via_rate_limited_lossy_proxy_with_timeout(
        cfg.send,
        cfg.recv,
        &source,
        dst.path(),
        0x0A5A_5170,
        data_rate_limit,
        Duration::from_secs(300),
    );
    let round_losses = need_more_round_losses(&collector);
    let max_round_loss = round_losses.iter().copied().fold(0.0, f64::max);
    println!("max_round_loss_fraction={max_round_loss:.6} round_losses={round_losses:?}");

    let send_res = send_res.unwrap_or_else(|err| {
        panic!(
            "rate-limited lossy-proxy QUIC sender should converge: {err:?}; receiver={recv_res:?}"
        )
    });
    let recv_res = recv_res.expect("rate-limited lossy-proxy QUIC receiver commits");

    assert_receive_report_counters(&send_res, &recv_res, payload.len() as u64, 1);
    assert!(
        recv_res.feedback_rounds > 0,
        "10% deterministic 1-RTT packet loss under a 1.25 MB/s cap should exercise the repair-feedback loop"
    );
    assert!(
        !round_losses.is_empty(),
        "repair-feedback trace must expose round_loss_fraction"
    );
    assert!(
        max_round_loss < 0.30,
        "rate-limited repair pacing should keep repair-round loss near the true 10% link loss, got {max_round_loss:.4} from {round_losses:?}"
    );
    assert_eq!(send_res.bytes_sent, payload.len() as u64);
    assert_eq!(
        std::fs::read(dst.path().join("pivot-a-rate-limited-lossy-proxy.bin"))
            .expect("read committed"),
        payload,
        "rate-limited lossy QUIC/TLS DATAGRAM transfer with 1141-byte symbols must commit exact bytes after reliable control-stream feedback"
    );
    assert_no_staging_residue(dst.path());
}

#[test]
fn real_udp_quic_send_fails_closed_when_client_distrusts_server() {
    // Client that trusts NO roots must fail the handshake closed (no fake
    // transfer), proving send_path inherits the driver's WebPKI verification.
    let alpn = vec![ATP_QUIC_ALPN.to_vec()];
    let mut send = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(1));
    send.client_tls = Some(QuicClientTls {
        server_name: ServerName::try_from("localhost").expect("server name"),
        // Empty root store: the server certificate cannot be verified.
        config: client_config(Vec::new(), alpn).expect("client config builds w/o roots"),
    });
    // Short handshake timeout so the doomed handshake fails fast.
    send.handshake_timeout = Duration::from_secs(5);
    send.accept_timeout = Duration::from_secs(5);

    let mut recv = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(1));
    recv.server_tls = Some(server_tls());
    recv.accept_timeout = Duration::from_secs(5);
    recv.handshake_timeout = Duration::from_secs(5);

    assert_send_fails_closed_before_commit(send, recv, "untrusted-root.bin");
}

#[test]
fn real_udp_quic_send_fails_closed_on_wrong_server_name() {
    // The client trusts the CA but asks WebPKI for a DNS name not present in the
    // server certificate SAN. The production send_path path must fail closed.
    let alpn = vec![ATP_QUIC_ALPN.to_vec()];
    let mut send = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(2));
    send.client_tls = Some(QuicClientTls {
        server_name: ServerName::try_from("not-localhost.example").expect("server name"),
        config: client_config(vec![parse_one_cert(CA_CERT_PEM)], alpn).expect("client config"),
    });
    send.handshake_timeout = Duration::from_secs(5);
    send.accept_timeout = Duration::from_secs(5);

    let mut recv = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(2));
    recv.server_tls = Some(server_tls());
    recv.accept_timeout = Duration::from_secs(5);
    recv.handshake_timeout = Duration::from_secs(5);

    assert_send_fails_closed_before_commit(send, recv, "wrong-hostname.bin");
}

#[test]
fn real_udp_quic_send_fails_closed_on_expired_server_certificate() {
    // This trusts the CA and uses the correct SAN (`localhost`), but advances
    // rustls' WebPKI clock past the leaf's notAfter. The production send_path
    // path must fail closed on certificate expiry before committing bytes.
    let alpn = vec![ATP_QUIC_ALPN.to_vec()];
    let mut send = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(3));
    send.client_tls = Some(QuicClientTls {
        server_name: ServerName::try_from("localhost").expect("server name"),
        config: client_config_at_time(
            vec![parse_one_cert(CA_CERT_PEM)],
            alpn,
            AFTER_LEAF_CERT_EXPIRY_UNIX_SECS,
        ),
    });
    send.handshake_timeout = Duration::from_secs(5);
    send.accept_timeout = Duration::from_secs(5);

    let mut recv = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(3));
    recv.server_tls = Some(server_tls());
    recv.accept_timeout = Duration::from_secs(5);
    recv.handshake_timeout = Duration::from_secs(5);

    assert_send_fails_closed_before_commit(send, recv, "expired-cert.bin");
}

#[test]
fn real_udp_quic_direct_symbol_auth_mismatch_fails_closed() {
    // Direct single-connection QUIC/TLS still honors an explicit per-symbol
    // HMAC context. Mismatched sender/receiver contexts must fail before commit.
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let source = src.path().join("auth-failing-symbol.bin");
    let payload: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(17).wrapping_add(23) % 251) as u8)
        .collect();
    std::fs::write(&source, &payload).expect("write source");

    let mut send = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(0xA17A));
    send.client_tls = Some(client_tls());
    send.idle_timeout = Duration::from_secs(5);
    send.handshake_timeout = Duration::from_secs(5);
    send.accept_timeout = Duration::from_secs(5);

    let mut recv = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(0xBEEF));
    recv.server_tls = Some(server_tls());
    recv.idle_timeout = Duration::from_secs(5);
    recv.handshake_timeout = Duration::from_secs(5);
    recv.accept_timeout = Duration::from_secs(5);

    let (send_res, recv_res) = run_transfer(send, recv, &source, dst.path());
    assert!(
        send_res.is_err() || recv_res.as_ref().map_or(true, |report| !report.committed),
        "mismatched direct QUIC symbol-auth contexts must not complete successfully"
    );
    assert!(
        std::fs::read(dst.path().join("auth-failing-symbol.bin")).is_err(),
        "direct QUIC must not commit bytes when explicit per-symbol auth fails"
    );
}
