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
use std::io::{ErrorKind, Read as _, Seek as _};
#[cfg(unix)]
use std::io::Write as _;
use std::net::{SocketAddr, UdpSocket};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use asupersync::atp::object::MetadataPolicy;
use asupersync::cx::Cx;
#[cfg(feature = "zstd")]
use asupersync::net::atp::transport_common::CompressionMode;
#[cfg(feature = "zstd")]
use asupersync::net::atp::transport_quic::native_link::set_receiver_ignores_codec_offers_for_testing;
use asupersync::net::atp::transport_quic::native_link::{
    QuicClientTls, QuicServerTls, bind_server_endpoint, receive_on_endpoint,
    receive_on_endpoint_with_options, set_receiver_member_path_delay_for_testing,
};
use asupersync::net::atp::transport_quic::{
    DEFAULT_MAX_BLOCK_SIZE, DEFAULT_SYMBOL_SIZE, QuicConfig, QuicReceiveOptions, QuicSendOptions,
    QuicTransportError, ReceiveReport, SendReport, send_path, send_path_with_options,
};
use asupersync::net::quic_native::handshake_driver::{ATP_QUIC_ALPN, client_config, server_config};
use asupersync::observability::{LogCollector, LogLevel};
use asupersync::security::{AuthMode, SecurityContext};
use futures_lite::future::{block_on, zip};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
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
    CertificateDer::pem_reader_iter(&mut reader)
        .next()
        .expect("one cert")
        .expect("valid cert pem")
}

fn leaf_key() -> PrivateKeyDer<'static> {
    let mut reader = std::io::BufReader::new(LEAF_KEY_PEM.as_bytes());
    PrivateKeyDer::pem_reader_iter(&mut reader)
        .next()
        .transpose()
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
/// Backstop lifetime of the lossy proxy in the 2000-member tree-manifest tests,
/// which can legitimately run past `LOSSY_PROXY_TIMEOUT` on a loaded worker.
const TREE_MANIFEST_PROXY_TIMEOUT: Duration = Duration::from_secs(300);

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

fn delta_authenticated_configs() -> Configs {
    let mut configs = transport_authenticated_configs();
    configs.send = configs
        .send
        .with_delta_control_auth(SecurityContext::for_testing(0xD3_17_A0));
    configs.recv = configs
        .recv
        .with_delta_control_auth(SecurityContext::for_testing(0xD3_17_A0));
    for config in [&mut configs.send, &mut configs.recv] {
        config.enable_delta = true;
        config.chunk_size = 1024;
        config.metadata_policy = MetadataPolicy::portable();
    }
    configs
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
    run_transfer_with_options(
        send_cfg,
        recv_cfg,
        source,
        dest_dir,
        QuicReceiveOptions::default(),
    )
}

fn run_transfer_with_options(
    send_cfg: QuicConfig,
    recv_cfg: QuicConfig,
    source: &Path,
    dest_dir: &Path,
    options: QuicReceiveOptions,
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
            receive_on_endpoint_with_options(
                &cx,
                server_endpoint,
                dest_dir,
                &recv_cfg,
                "atp-quic-server",
                options,
            ),
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

/// Same lossy-proxy transfer, keeping the shared trace collector (sized by
/// `collector_capacity` entries) so a test can count sender-side events such
/// as `atp_quic.control_stream.retransmit` over the whole transfer.
fn run_transfer_via_lossy_proxy_with_collector(
    send_cfg: QuicConfig,
    recv_cfg: QuicConfig,
    source: &Path,
    dest_dir: &Path,
    seed: u64,
    proxy_timeout: Duration,
    collector_capacity: usize,
) -> (
    Result<SendReport, QuicTransportError>,
    Result<ReceiveReport, QuicTransportError>,
    LogCollector,
) {
    block_on(async {
        let cx = Cx::for_testing();
        let collector = LogCollector::new(collector_capacity).with_min_level(LogLevel::Trace);
        cx.set_log_collector(collector.clone());
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_endpoint = bind_server_endpoint(&cx, listen)
            .await
            .expect("bind server endpoint");
        let server_addr = server_endpoint.local_addr();
        let proxy = LossyUdpProxy::spawn_with_rate_timeout(server_addr, seed, None, proxy_timeout);
        let (send, recv) = zip(
            send_path(&cx, proxy.addr, source, send_cfg, "atp-quic-client"),
            receive_on_endpoint(&cx, server_endpoint, dest_dir, &recv_cfg, "atp-quic-server"),
        )
        .await;
        (send, recv, collector)
    })
}

/// One sender-side stall-expiry re-send of source-stream frames, as traced by
/// `atp_quic.control_stream.retransmit` with a `source_stream*_pto` reason.
#[derive(Debug, Clone)]
struct StallPtoResend {
    reason: String,
    stream_frames: u64,
    packets: u64,
}

fn stall_pto_resends(collector: &LogCollector) -> Vec<StallPtoResend> {
    collector
        .peek()
        .into_iter()
        .filter(|entry| entry.message() == "atp_quic.control_stream.retransmit")
        .filter_map(|entry| {
            let reason = entry.get_field("reason")?;
            if !(reason.starts_with("source_stream") && reason.ends_with("_pto")) {
                return None;
            }
            Some(StallPtoResend {
                reason: reason.to_string(),
                stream_frames: entry.get_field("stream_frames")?.parse().ok()?,
                packets: entry.get_field("packets")?.parse().ok()?,
            })
        })
        .collect()
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

#[cfg(unix)]
fn write_sparse_fixture(path: &Path, logical_size: usize, marker: &[u8]) -> Vec<u8> {
    let mut file = std::fs::File::create(path).expect("create sparse fixture");
    file.set_len(u64::try_from(logical_size).expect("sparse fixture size fits u64"))
        .expect("pre-size sparse fixture");
    file.write_all(marker).expect("write sparse fixture prefix");
    let tail_offset = logical_size
        .checked_sub(marker.len())
        .expect("sparse fixture exceeds marker");
    file.seek(std::io::SeekFrom::Start(
        u64::try_from(tail_offset).expect("sparse fixture tail fits u64"),
    ))
    .expect("seek sparse fixture tail");
    file.write_all(marker).expect("write sparse fixture suffix");
    file.sync_all().expect("sync sparse fixture");
    let mut expected = vec![0u8; logical_size];
    expected[..marker.len()].copy_from_slice(marker);
    expected[tail_offset..].copy_from_slice(marker);
    expected
}

#[cfg(unix)]
fn assert_sparse_fixture(path: &Path, expected: &[u8], context: &str) {
    assert_eq!(
        std::fs::read(path).expect("read sparse fixture"),
        expected,
        "sparse reconstruction must preserve logical bytes for {context}"
    );
    let metadata = std::fs::metadata(path).expect("sparse fixture metadata");
    assert_eq!(
        metadata.len(),
        u64::try_from(expected.len()).expect("expected sparse size fits u64")
    );
    assert!(
        metadata.blocks().saturating_mul(512) < metadata.len() / 2,
        "sparse allocation must remain below half the logical size for {context}"
    );
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

/// asupersync-nnm3gw: a receiver that refuses the manifest must say so. The
/// receiver's metadata policy denies timestamps, and the sender's preserves
/// them (as `atp send` does). The receiver used to drop the connection without
/// a word, so the sender waited out its whole idle timeout, 360 s by default.
/// It now sends the failed-commit Proof with the reason. Both idle timeouts
/// here are 120 s, so only the in-band refusal can end the send quickly.
#[test]
fn receiver_manifest_refusal_reaches_the_sender_with_its_reason() {
    const REFUSAL_BOUND: Duration = Duration::from_secs(60);
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let source = src.path().join("payload.bin");
    std::fs::write(&source, vec![7_u8; 4096]).expect("write source");

    let mut cfg = transport_authenticated_configs();
    cfg.send.metadata_policy = MetadataPolicy {
        preserve_timestamps: true,
        ..MetadataPolicy::default()
    };
    cfg.recv.metadata_policy = MetadataPolicy {
        preserve_timestamps: false,
        ..MetadataPolicy::default()
    };
    cfg.send.idle_timeout = Duration::from_secs(120);
    cfg.recv.idle_timeout = Duration::from_secs(120);

    let started = Instant::now();
    let (sent, received) = run_transfer(cfg.send, cfg.recv, &source, dst.path());
    let elapsed = started.elapsed();

    let received = received.expect_err("the receiver refuses a timestamped manifest");
    assert!(
        matches!(received, QuicTransportError::Source(ref message)
            if message.contains("timestamps are denied by receiver metadata policy")),
        "receiver error: {received:?}"
    );
    let sent = sent.expect_err("the sender must learn of the refusal");
    assert!(
        matches!(sent, QuicTransportError::Integrity(ref reason)
            if reason.starts_with("receiver refused the manifest: ")
                && reason.contains("timestamps are denied by receiver metadata policy")),
        "sender error: {sent:?}"
    );
    assert!(
        elapsed < REFUSAL_BOUND,
        "the refusal reached the sender only after {elapsed:?}"
    );
    assert!(
        std::fs::read(dst.path().join("payload.bin")).is_err(),
        "a refused manifest must commit nothing"
    );
    assert_no_staging_residue(dst.path());
}

/// asupersync-nnm3gw: a receiver that cannot prepare its destination (here the
/// destination crosses a symlink) tells the sender so promptly, without
/// naming any receiver-side path.
#[cfg(unix)]
#[test]
fn receiver_destination_refusal_reaches_the_sender_without_its_paths() {
    const REFUSAL_BOUND: Duration = Duration::from_secs(60);
    let src = tempfile::tempdir().expect("src dir");
    let source = src.path().join("payload.bin");
    std::fs::write(&source, vec![9_u8; 4096]).expect("write source");
    let root = tempfile::tempdir().expect("receiver root");
    let real = root.path().join("real");
    std::fs::create_dir_all(&real).expect("real dir");
    let linked = root.path().join("linked");
    std::os::unix::fs::symlink(&real, &linked).expect("symlink");
    let dest = linked.join("inbox");

    let mut cfg = transport_authenticated_configs();
    cfg.send.idle_timeout = Duration::from_secs(120);
    cfg.recv.idle_timeout = Duration::from_secs(120);

    let started = Instant::now();
    let (sent, received) = run_transfer(cfg.send, cfg.recv, &source, &dest);
    let elapsed = started.elapsed();

    let received = received.expect_err("the receiver refuses a destination through a symlink");
    assert!(
        matches!(received, QuicTransportError::Source(ref message) if message.contains("symlink")),
        "receiver error: {received:?}"
    );
    let sent = sent.expect_err("the sender must learn of the refusal");
    assert!(
        matches!(sent, QuicTransportError::Integrity(ref reason)
            if reason == "receiver could not prepare its destination"),
        "sender error: {sent:?}"
    );
    let receiver_root = root.path().display().to_string();
    assert!(
        !format!("{sent:?}").contains(&receiver_root),
        "the sender must not learn receiver paths: {sent:?}"
    );
    assert!(
        elapsed < REFUSAL_BOUND,
        "the refusal reached the sender only after {elapsed:?}"
    );
    assert!(
        !real.join("inbox").exists(),
        "a refused destination must stay untouched"
    );
}

/// Delta policy refusals use the challenged session before a transfer mode is
/// selected. First exercise full and already-in-sync transfers with the same
/// public configuration so the refusal cannot pass through a disabled-delta
/// fallback. The original code silently dropped this authenticated refusal.
#[test]
fn authenticated_delta_refusal_preserves_full_and_noop_transfer_paths() {
    const REFUSAL_BOUND: Duration = Duration::from_secs(60);
    let src = tempfile::tempdir().expect("source directory");
    let dst = tempfile::tempdir().expect("destination directory");
    let source = src
        .path()
        .canonicalize()
        .expect("canonical source")
        .join("payload.bin");
    let destination = dst.path().canonicalize().expect("canonical destination");
    let payload = vec![37_u8; 4096];
    std::fs::write(&source, &payload).expect("write source");
    let mut configs = delta_authenticated_configs();
    configs.send.idle_timeout = Duration::from_secs(120);
    configs.recv.idle_timeout = Duration::from_secs(120);

    let (sent, received) = run_transfer(
        configs.send.clone(),
        configs.recv.clone(),
        &source,
        &destination,
    );
    let sent = sent.expect("missing destination selects full transfer");
    let received = received.expect("full delta fallback commits");
    assert_eq!(sent.bytes_sent, payload.len() as u64);
    assert_eq!(received.bytes_received, payload.len() as u64);
    assert!(sent.receipt.committed && received.committed);
    assert_eq!(
        std::fs::read(destination.join("payload.bin")).unwrap(),
        payload
    );

    let (sent, received) = run_transfer(
        configs.send.clone(),
        configs.recv.clone(),
        &source,
        &destination,
    );
    let sent = sent.expect("unchanged destination selects authenticated no-op");
    let received = received.expect("bound no-op proof commits");
    assert_eq!(sent.bytes_sent, 0, "the public path really negotiated delta");
    assert_eq!(received.bytes_received, 0);
    assert!(sent.receipt.committed && received.committed);
    assert_no_staging_residue(&destination);

    configs.send.metadata_policy.preserve_timestamps = true;
    let started = Instant::now();
    let (sent, received) = run_transfer(configs.send, configs.recv, &source, &destination);
    let elapsed = started.elapsed();
    let received = received.expect_err("receiver refuses the new metadata policy");
    assert!(
        matches!(received, QuicTransportError::Source(ref message)
            if message.contains("timestamps are denied by receiver metadata policy")),
        "receiver error: {received:?}"
    );
    let sent = sent.expect_err("delta refusal must reach the waiting sender");
    assert!(
        matches!(sent, QuicTransportError::Integrity(ref reason)
            if reason.starts_with("receiver refused the manifest: ")
                && reason.contains("timestamps are denied by receiver metadata policy")),
        "sender error: {sent:?}"
    );
    assert!(elapsed < REFUSAL_BOUND, "delta refusal took {elapsed:?}");
    assert_eq!(
        std::fs::read(destination.join("payload.bin")).unwrap(),
        payload
    );
    assert_no_staging_residue(&destination);
}

/// A failure to inspect the receiver's destination happens before ObjectRequest
/// and must carry a bound refusal, with no receiver filesystem paths disclosed.
#[cfg(unix)]
#[test]
fn authenticated_delta_destination_refusal_reaches_sender_without_paths() {
    const REFUSAL_BOUND: Duration = Duration::from_secs(60);
    let src = tempfile::tempdir().expect("source directory");
    let source = src
        .path()
        .canonicalize()
        .expect("canonical source")
        .join("payload.bin");
    std::fs::write(&source, vec![19_u8; 4096]).expect("write source");
    let root = tempfile::tempdir().expect("receiver root");
    let root_path = root.path().canonicalize().expect("canonical receiver root");
    let real = root_path.join("real");
    std::fs::create_dir(&real).expect("real destination");
    let linked = root_path.join("linked");
    std::os::unix::fs::symlink(&real, &linked).expect("destination symlink");
    let destination = linked.join("inbox");
    let mut configs = delta_authenticated_configs();
    configs.send.idle_timeout = Duration::from_secs(120);
    configs.recv.idle_timeout = Duration::from_secs(120);

    let started = Instant::now();
    let (sent, received) = run_transfer(configs.send, configs.recv, &source, &destination);
    let elapsed = started.elapsed();
    let received = received.expect_err("receiver refuses a symlinked destination");
    assert!(
        matches!(received, QuicTransportError::Source(ref message) if message.contains("symlink")),
        "receiver error: {received:?}"
    );
    let sent = sent.expect_err("sender hears the pre-request refusal");
    assert!(
        matches!(sent, QuicTransportError::Integrity(ref reason)
            if reason == "receiver could not prepare its delta request"),
        "sender error: {sent:?}"
    );
    assert!(!format!("{sent:?}").contains(&root_path.display().to_string()));
    assert!(elapsed < REFUSAL_BOUND, "delta refusal took {elapsed:?}");
    assert!(
        !real.join("inbox").exists(),
        "refusal must not publish a destination"
    );
    assert_no_staging_residue(&real);
}

/// asupersync-nnm3gw: a refusing receiver does not wait on a sender that is
/// still streaming. The source-stream sender queues an 8 MiB payload. It
/// stalls on stream credit that the refusing receiver no longer grants, and
/// sends keep-alive pings until its own 30 s idle timeout. It reads the Proof
/// only after its last byte. Every ping restarted the receiver's wait for
/// Close. The receiver must still return within a few PTOs, because a listener
/// that serves transfers one at a time (atpd) is blocked until it does. The
/// sender must hear the refusal while it is stalled, and fail with the
/// receiver's reason instead of its own idle timeout.
#[test]
fn refusing_receiver_does_not_wait_for_a_streaming_sender() {
    const RECEIVER_BOUND: Duration = Duration::from_secs(15);
    const SENDER_BOUND: Duration = Duration::from_secs(15);
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let source = src.path().join("payload.bin");
    // Four times the receiver's 2 MiB stream window: once the receiver
    // refuses, it grants no more credit, and the sender sits credit-blocked,
    // sending keep-alive pings.
    let mut noise = DeterministicLoss::new(0x5EED_0930);
    let payload: Vec<u8> = (0..8 << 20).map(|_| noise.next_u32().to_le_bytes()[0]).collect();
    std::fs::write(&source, &payload).expect("write source");

    let mut cfg = transport_authenticated_configs();
    cfg.send.metadata_policy = MetadataPolicy {
        preserve_timestamps: true,
        ..MetadataPolicy::default()
    };
    cfg.recv.metadata_policy = MetadataPolicy {
        preserve_timestamps: false,
        ..MetadataPolicy::default()
    };
    // The reliable source stream (no bwlimit, low loss target): its sender
    // reads no control frame until the last byte is queued. A spray sender
    // checks control between symbols and stops at the refusal on its own.
    cfg.send.round0_loss_target = 0.001;
    cfg.recv.round0_loss_target = 0.001;
    cfg.send.idle_timeout = Duration::from_secs(30);
    cfg.recv.idle_timeout = Duration::from_secs(40);
    let (send_cfg, recv_cfg) = (cfg.send, cfg.recv);

    let started = Instant::now();
    let ((sent, sent_at), (received, received_at)) = block_on(async {
        let cx = Cx::for_testing();
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_endpoint = bind_server_endpoint(&cx, listen)
            .await
            .expect("bind server endpoint");
        let server_addr = server_endpoint.local_addr();
        zip(
            async {
                let result = send_path(&cx, server_addr, &source, send_cfg, "atp-quic-client").await;
                (result, started.elapsed())
            },
            async {
                let result = receive_on_endpoint(
                    &cx,
                    server_endpoint,
                    dst.path(),
                    &recv_cfg,
                    "atp-quic-server",
                )
                .await;
                (result, started.elapsed())
            },
        )
        .await
    });

    let received = received.expect_err("the receiver refuses a timestamped manifest");
    assert!(
        matches!(received, QuicTransportError::Source(ref message)
            if message.contains("timestamps are denied by receiver metadata policy")),
        "receiver error: {received:?}"
    );
    eprintln!("refusal timing: receiver {received_at:?}, sender {sent_at:?}: {sent:?}");
    assert!(
        received_at < RECEIVER_BOUND,
        "the refusing receiver returned only after {received_at:?} (sender finished at {sent_at:?})"
    );
    let sent = sent.expect_err("the sender must not report success");
    assert!(
        matches!(sent, QuicTransportError::Integrity(ref reason)
            if reason.contains("timestamps are denied by receiver metadata policy")),
        "the sender must report the receiver's reason: {sent:?}"
    );
    assert!(
        sent_at < SENDER_BOUND,
        "the stalled sender heard the refusal only after {sent_at:?}"
    );
    assert!(
        std::fs::read(dst.path().join("payload.bin")).is_err(),
        "a refused manifest must commit nothing"
    );
    assert_no_staging_residue(dst.path());
}

/// asupersync-wlbrlr: a RELATIVE destination directory (`atp recv out/dir`,
/// the bench harness's cell paths) must be accepted. The receiver's
/// destination-root preparation walked the empty ancestor of a relative path
/// after `create_dir_all` and failed every such receive with "No such file
/// or directory" right after the manifest (shipped in v0.4.10 and v0.4.11).
/// The destination is a directory built by hand inside the package's
/// `target/` (git-ignored) so its path stays relative to the test's working
/// directory: cargo runs the test binary from the package root, and
/// `tempfile` would absolutize a relative parent.
#[test]
fn real_udp_quic_transfer_accepts_a_relative_destination_directory() {
    let src = tempfile::tempdir().expect("src dir");
    let source = src.path().join("payload.bin");
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 241) as u8).collect();
    std::fs::write(&source, &payload).expect("write source");
    let dst = Path::new("target").join(format!(
        "quic-relative-dest-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos())
    ));
    std::fs::create_dir_all(&dst).expect("relative dst dir");
    assert!(
        dst.is_relative(),
        "the destination must be relative to the working directory: {}",
        dst.display()
    );

    let cfg = authenticated_configs(0x5E1A);
    let (send, recv) = run_transfer(cfg.send, cfg.recv, &source, &dst);
    let committed = std::fs::read(dst.join("payload.bin"));
    let residue = std::fs::read_dir(&dst).map(|entries| {
        entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".atp-"))
            .count()
    });
    let _ = std::fs::remove_dir_all(&dst);

    let recv = recv.expect("receiver commits into a relative destination directory");
    let send = send.expect("send_path completes over real UDP");
    assert_receive_report_counters(&send, &recv, payload.len() as u64, 1);
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);
    assert_eq!(
        committed.expect("read committed file"),
        payload,
        "committed bytes must match the source"
    );
    assert_eq!(
        residue.expect("list the destination"),
        0,
        "no staging residue may remain under the relative destination"
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
    // Source-stream design: ALL source bytes ride the reliable QUIC stream and
    // commit straight from sha-verified staged bytes, so the RaptorQ path must
    // stay untouched. Loss on this tier is repaired by QUIC stream
    // retransmission, not fountain repair (see the broken_loss variant below,
    // which asserts feedback_rounds == 0 under 10% induced loss).
    assert_eq!(
        send.symbols_sent, 0,
        "lossless source-stream transfer must not spray FEC symbols"
    );
    assert_eq!(
        recv.symbols_accepted, 0,
        "lossless source-stream receiver must not engage the RaptorQ decoder"
    );
    assert_eq!(
        recv.decode_count, 0,
        "lossless source-stream commit must come from staged stream bytes, not block decode"
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

/// A clean UDP forwarder between the sender and the receiver. It counts the
/// bytes the sender sends: what crossed the wire, compressed or not.
struct CountingUdpProxy {
    addr: SocketAddr,
    sent: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

/// Cancel only after payload has crossed the wire and the receiver has staged
/// a known changed range. Staging preallocates the whole file, so length alone
/// cannot prove a write. This probe needs no delay or decrypted ATP frames.
struct StagedTransferCancellation {
    cx: Cx,
    minimum_wire_bytes: u64,
    dest_dir: PathBuf,
    staged_probe_offset: u64,
    expected_staged_bytes: [u8; 32],
    fired: Arc<AtomicBool>,
}

impl StagedTransferCancellation {
    fn trigger(&self, wire_bytes: u64) -> bool {
        if wire_bytes < self.minimum_wire_bytes {
            return false;
        }
        let Ok(entries) = std::fs::read_dir(&self.dest_dir) else {
            return false;
        };
        let has_staged_bytes = entries.filter_map(Result::ok).any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".atp-quic-staging")
                && std::fs::read_dir(entry.path()).is_ok_and(|files| {
                    files.filter_map(Result::ok).any(|file| {
                        let Ok(mut staged) = std::fs::File::open(file.path()) else {
                            return false;
                        };
                        let mut probe = [0_u8; 32];
                        staged
                            .seek(std::io::SeekFrom::Start(self.staged_probe_offset))
                            .is_ok()
                            && staged.read_exact(&mut probe).is_ok()
                            && probe == self.expected_staged_bytes
                    })
                })
        });
        if has_staged_bytes {
            self.fired.store(true, Ordering::Relaxed);
            self.cx.set_cancel_requested(true);
        }
        has_staged_bytes
    }
}

impl CountingUdpProxy {
    fn spawn(server_addr: SocketAddr) -> Self {
        Self::spawn_with_cancellation(server_addr, None)
    }

    fn spawn_with_cancellation(
        server_addr: SocketAddr,
        cancellation: Option<StagedTransferCancellation>,
    ) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind counting proxy");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("proxy read timeout");
        let addr = socket.local_addr().expect("proxy local addr");
        let sent = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_sent, thread_stop) = (Arc::clone(&sent), Arc::clone(&stop));
        let handle = thread::spawn(move || {
            let mut client = None;
            let mut cancelled = false;
            let mut buf = vec![0_u8; 65_536];
            while !thread_stop.load(Ordering::Relaxed) {
                let Ok((len, from)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if from == server_addr {
                    if let Some(client) = client {
                        let _ = socket.send_to(&buf[..len], client);
                    }
                } else {
                    client = Some(from);
                    let wire_bytes = thread_sent
                        .fetch_add(len as u64, Ordering::Relaxed)
                        .saturating_add(len as u64);
                    if !cancelled
                        && cancellation
                            .as_ref()
                            .is_some_and(|cancel| cancel.trigger(wire_bytes))
                    {
                        cancelled = true;
                    }
                    if !cancelled {
                        let _ = socket.send_to(&buf[..len], server_addr);
                    }
                }
            }
        });
        Self {
            addr,
            sent,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for CountingUdpProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A transfer through a [`CountingUdpProxy`], with sender options; returns the
/// bytes the sender put on the wire.
#[cfg(feature = "zstd")]
fn run_counted_transfer(
    send_cfg: QuicConfig,
    recv_cfg: QuicConfig,
    source: &Path,
    dest_dir: &Path,
    options: QuicSendOptions,
) -> (
    Result<SendReport, QuicTransportError>,
    Result<ReceiveReport, QuicTransportError>,
    u64,
) {
    run_counted_transfer_with_options(
        send_cfg,
        recv_cfg,
        source,
        dest_dir,
        options,
        QuicReceiveOptions::new(),
    )
}

fn run_counted_transfer_with_options(
    send_cfg: QuicConfig,
    recv_cfg: QuicConfig,
    source: &Path,
    dest_dir: &Path,
    send_options: QuicSendOptions,
    receive_options: QuicReceiveOptions,
) -> (
    Result<SendReport, QuicTransportError>,
    Result<ReceiveReport, QuicTransportError>,
    u64,
) {
    block_on(async {
        let cx = Cx::for_testing();
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_endpoint = bind_server_endpoint(&cx, listen)
            .await
            .expect("bind server endpoint");
        let proxy = CountingUdpProxy::spawn(server_endpoint.local_addr());
        let (send, recv) = zip(
            send_path_with_options(
                &cx,
                proxy.addr,
                source,
                send_cfg,
                "atp-quic-client",
                send_options,
            ),
            receive_on_endpoint_with_options(
                &cx,
                server_endpoint,
                dest_dir,
                &recv_cfg,
                "atp-quic-server",
                receive_options,
            ),
        )
        .await;
        (send, recv, proxy.sent.load(Ordering::Relaxed))
    })
}

// Deliberately larger than the async file read buffer: the chunk manifest and
// payload must agree even when filling one chunk requires multiple reads.
const DELTA_TEST_CHUNK_BYTES: usize = 256 * 1024;

fn changed_chunk_configs() -> Configs {
    let mut configs = delta_authenticated_configs();
    for config in [&mut configs.send, &mut configs.recv] {
        config.chunk_size = DELTA_TEST_CHUNK_BYTES;
        config.round0_loss_target = 0.001;
    }
    configs
}

fn changed_chunk_payload(chunks: usize, tail: usize) -> Vec<u8> {
    let mut noise = DeterministicLoss::new(0xD3_17_A0_26);
    (0..chunks * DELTA_TEST_CHUNK_BYTES + tail)
        .map(|_| noise.next_u32().to_le_bytes()[0])
        .collect()
}

fn assert_changed_chunk_reports(send: &SendReport, receive: &ReceiveReport, bytes: usize) {
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);
    assert!(receive.committed);
    assert_eq!(send.transfer_id, receive.transfer_id);
    assert_eq!(send.files, 1);
    assert_eq!(receive.files, 1);
    assert_eq!(send.bytes_sent, bytes as u64);
    assert_eq!(send.receipt.bytes_received, bytes as u64);
    assert_eq!(receive.bytes_received, bytes as u64);
    assert_eq!(send.symbols_sent, 0);
    assert_eq!(receive.symbols_accepted, 0);
    assert_eq!(send.feedback_rounds, 0);
    assert_eq!(receive.feedback_rounds, 0);
    assert_eq!(receive.decode_count, 0);
    assert_eq!(receive.decode_micros, 0);
    assert_eq!(receive.committed_paths.len(), 1);
}

fn assert_changed_chunk_destination(destination: &Path, expected: &[u8]) {
    assert_eq!(
        std::fs::read(destination.join("payload.bin")).expect("read committed payload"),
        expected
    );
    assert_no_staging_residue(destination);
    assert_eq!(
        std::fs::read_dir(destination).expect("read destination").count(),
        1,
        "only the destination file may survive a terminal transfer"
    );
}

/// I3/B8: the public API must perform a full first copy, send only one changed
/// chunk next, and then negotiate an authenticated no-op. Wire counts come
/// from real encrypted UDP packets, independently of the receipt counters.
#[test]
fn real_udp_quic_changed_chunks_full_partial_and_noop() {
    let src = tempfile::tempdir().expect("source directory");
    let dst = tempfile::tempdir().expect("destination directory");
    let source = src.path().join("payload.bin");
    let mut payload = changed_chunk_payload(12, 131);
    std::fs::write(&source, &payload).expect("write initial source");
    let configs = changed_chunk_configs();
    let send_options = QuicSendOptions::new().with_delta_chunks(true);
    let receive_options = QuicReceiveOptions::new().with_delta_chunks(true);

    let (send, receive, full_wire_bytes) = run_counted_transfer_with_options(
        configs.send.clone(),
        configs.recv.clone(),
        &source,
        dst.path(),
        send_options,
        receive_options,
    );
    assert_changed_chunk_reports(
        &send.expect("first copy sends the whole object"),
        &receive.expect("first copy commits"),
        payload.len(),
    );
    assert!(full_wire_bytes > payload.len() as u64);
    assert_changed_chunk_destination(dst.path(), &payload);

    payload[5 * DELTA_TEST_CHUNK_BYTES + 71] ^= 0xA5;
    std::fs::write(&source, &payload).expect("write small edit");
    let (send, receive, delta_wire_bytes) = run_counted_transfer_with_options(
        configs.send.clone(),
        configs.recv.clone(),
        &source,
        dst.path(),
        send_options,
        receive_options,
    );
    assert_changed_chunk_reports(
        &send.expect("changed chunk send completes"),
        &receive.expect("changed chunk receive commits"),
        DELTA_TEST_CHUNK_BYTES,
    );
    assert!(
        delta_wire_bytes < full_wire_bytes / 2,
        "one changed chunk used {delta_wire_bytes} wire bytes versus {full_wire_bytes} for full copy"
    );
    assert_changed_chunk_destination(dst.path(), &payload);

    let (send, receive, noop_wire_bytes) = run_counted_transfer_with_options(
        configs.send,
        configs.recv,
        &source,
        dst.path(),
        send_options,
        receive_options,
    );
    assert_changed_chunk_reports(
        &send.expect("unchanged sender receives a bound proof"),
        &receive.expect("unchanged destination commits a no-op"),
        0,
    );
    assert!(
        noop_wire_bytes < delta_wire_bytes / 2,
        "no-op used {noop_wire_bytes} wire bytes versus {delta_wire_bytes} for one changed chunk"
    );
    assert_changed_chunk_destination(dst.path(), &payload);
}

/// The sender and receiver negotiate CDC on the public native path. Inserts and
/// deletes shift later offsets, so the unchanged suffix must be reused by content
/// identity rather than retransmitted as fixed blocks. Counts below are measured
/// by the encrypted UDP proxy, independently of the transfer receipts.
#[test]
fn real_udp_quic_cdc_reuses_content_after_insert_delete_and_noop() {
    let src = tempfile::tempdir().expect("source directory");
    let dst = tempfile::tempdir().expect("destination directory");
    let source = src.path().join("payload.bin");
    let baseline = changed_chunk_payload(12, 131);
    std::fs::write(&source, &baseline).expect("write initial source");
    let configs = changed_chunk_configs();
    let send_options = QuicSendOptions::new().with_cdc_delta(true);
    let receive_options = QuicReceiveOptions::new().with_cdc_delta(true);

    let (send, receive, full_wire_bytes) = run_counted_transfer_with_options(
        configs.send.clone(),
        configs.recv.clone(),
        &source,
        dst.path(),
        send_options,
        receive_options,
    );
    assert_changed_chunk_reports(
        &send.expect("first CDC transfer sends all content"),
        &receive.expect("first CDC transfer commits"),
        baseline.len(),
    );
    assert_changed_chunk_destination(dst.path(), &baseline);
    assert!(full_wire_bytes > baseline.len() as u64);

    let insertion = vec![0xA7; 2017];
    let inserted = [&baseline[..90_001], &insertion, &baseline[90_001..]].concat();
    let deleted = [&inserted[..1_600_013], &inserted[1_608_050..]].concat();
    for (operation, updated) in [("insert", &inserted), ("delete", &deleted)] {
        std::fs::write(&source, updated).expect("write shifted source");
        let (send, receive, wire_bytes) = run_counted_transfer_with_options(
            configs.send.clone(),
            configs.recv.clone(),
            &source,
            dst.path(),
            send_options,
            receive_options,
        );
        let send = send.unwrap_or_else(|error| panic!("{operation} sender: {error:?}"));
        let receive = receive.unwrap_or_else(|error| panic!("{operation} receiver: {error:?}"));
        assert!(
            send.bytes_sent > 0 && send.bytes_sent < DELTA_TEST_CHUNK_BYTES as u64,
            "{operation} must transfer a bounded changed region, not the shifted suffix: {send:?}"
        );
        assert_changed_chunk_reports(
            &send,
            &receive,
            usize::try_from(send.bytes_sent).expect("bounded missing bytes"),
        );
        assert!(
            wire_bytes < full_wire_bytes / 2,
            "{operation} used {wire_bytes} wire bytes versus {full_wire_bytes} for the first copy"
        );
        assert_changed_chunk_destination(dst.path(), updated);
    }

    let (send, receive, noop_wire_bytes) = run_counted_transfer_with_options(
        configs.send,
        configs.recv,
        &source,
        dst.path(),
        send_options,
        receive_options,
    );
    assert_changed_chunk_reports(
        &send.expect("unchanged CDC sender receives a bound proof"),
        &receive.expect("unchanged CDC receiver commits a no-op"),
        0,
    );
    assert!(noop_wire_bytes < full_wire_bytes / 2);
    assert_changed_chunk_destination(dst.path(), &deleted);
}

#[test]
fn real_udp_quic_cdc_preserves_fixed_and_legacy_peer_fallback() {
    // CDC implies chunk reuse, but a peer that only knows fixed chunks must see
    // the unchanged fixed schema. A peer with no chunk opt-in gets the full file.
    for (sender_cdc, receiver_cdc, sender_fixed, receiver_fixed, expected_chunks) in [
        (true, false, false, true, 1),
        (false, true, true, false, 1),
        (true, false, false, false, 0),
        (false, true, false, false, 0),
    ] {
        let src = tempfile::tempdir().expect("source directory");
        let dst = tempfile::tempdir().expect("destination directory");
        let source = src.path().join("payload.bin");
        let baseline = changed_chunk_payload(3, 23);
        let mut updated = baseline.clone();
        updated[DELTA_TEST_CHUNK_BYTES + 19] ^= 0x3C;
        std::fs::write(&source, &updated).expect("write changed source");
        std::fs::write(dst.path().join("payload.bin"), &baseline).expect("write baseline");
        let configs = changed_chunk_configs();
        let (send, receive, _) = run_counted_transfer_with_options(
            configs.send,
            configs.recv,
            &source,
            dst.path(),
            QuicSendOptions::new()
                .with_delta_chunks(sender_fixed)
                .with_cdc_delta(sender_cdc),
            QuicReceiveOptions::new()
                .with_delta_chunks(receiver_fixed)
                .with_cdc_delta(receiver_cdc),
        );
        assert_changed_chunk_reports(
            &send.expect("mixed-version sender completes"),
            &receive.expect("mixed-version receiver commits"),
            if expected_chunks == 1 {
                DELTA_TEST_CHUNK_BYTES
            } else {
                updated.len()
            },
        );
        assert_changed_chunk_destination(dst.path(), &updated);
    }
}

// The 2 MiB file stays plain; the three smaller files and empty file form a
// pack. Editing the 256 KiB member changes exactly 10% of logical tree bytes,
// and must not force the unchanged members of its pack onto the wire.
fn write_tree_delta_fixture(root: &Path) -> Vec<(String, Vec<u8>)> {
    std::fs::create_dir_all(root.join("small")).expect("create tree source");
    let files = vec![
        ("00-large.bin".to_string(), changed_chunk_payload(8, 0)),
        ("small/changed.bin".to_string(), changed_chunk_payload(1, 0)),
        (
            "small/kept-a.bin".to_string(),
            changed_chunk_payload(0, DELTA_TEST_CHUNK_BYTES / 2),
        ),
        (
            "small/kept-b.bin".to_string(),
            changed_chunk_payload(0, DELTA_TEST_CHUNK_BYTES / 2)
                .into_iter()
                .map(|byte| byte ^ 0x37)
                .collect(),
        ),
        ("small/empty.bin".to_string(), Vec::new()),
    ];
    for (path, bytes) in &files {
        std::fs::write(root.join(path), bytes).expect("write tree source member");
    }
    files
}

fn assert_tree_delta_reports(send: &SendReport, receive: &ReceiveReport, missing_bytes: u64) {
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);
    assert!(receive.committed);
    assert_eq!(send.transfer_id, receive.transfer_id);
    assert_eq!(send.files, receive.files);
    assert_eq!(send.bytes_sent, missing_bytes);
    assert_eq!(send.receipt.bytes_received, missing_bytes);
    assert_eq!(receive.bytes_received, missing_bytes);
}

fn assert_tree_delta_destination(destination: &Path, files: &[(String, Vec<u8>)]) {
    for (path, bytes) in files {
        assert_eq!(
            std::fs::read(destination.join("tree").join(path))
                .unwrap_or_else(|error| panic!("read committed {path}: {error}")),
            *bytes,
            "committed tree member {path}"
        );
    }
    assert_no_staging_residue(destination);
}

/// I3: re-sync a directory containing both packed and plain files. Receipt
/// counters and independently counted encrypted UDP packets must both shrink
/// when only one packed member changes; receiver-only files remain intact.
#[test]
fn real_udp_quic_tree_delta_reuses_plain_and_packed_files_and_noops() {
    let src = tempfile::tempdir().expect("source directory");
    let dst = tempfile::tempdir().expect("destination directory");
    let root = src.path().join("tree");
    let mut files = write_tree_delta_fixture(&root);
    let total_bytes = files.iter().map(|(_, bytes)| bytes.len() as u64).sum::<u64>();
    let mut configs = changed_chunk_configs();
    configs.send.metadata_policy.preserve_unix_permissions = cfg!(unix);
    configs.recv.metadata_policy.preserve_unix_permissions = cfg!(unix);
    let send_options = QuicSendOptions::new().with_tree_delta(true);
    let receive_options = QuicReceiveOptions::new().with_tree_delta(true);

    let (send, receive, full_wire_bytes) = run_counted_transfer_with_options(
        configs.send.clone(),
        configs.recv.clone(),
        &root,
        dst.path(),
        send_options,
        receive_options,
    );
    assert_tree_delta_reports(
        &send.expect("initial tree sender completes"),
        &receive.expect("initial tree receiver commits"),
        total_bytes,
    );
    assert_tree_delta_destination(dst.path(), &files);
    assert!(full_wire_bytes > total_bytes);
    let extra = dst.path().join("tree/receiver-only.txt");
    std::fs::write(&extra, b"keep this independent file").expect("write receiver-only file");

    let (_, changed) = files
        .iter_mut()
        .find(|(path, _)| path == "small/changed.bin")
        .expect("changed packed member");
    changed[71] ^= 0xA5;
    std::fs::write(root.join("small/changed.bin"), changed).expect("edit one packed member");
    let missing_bytes = DELTA_TEST_CHUNK_BYTES as u64;
    assert_eq!(missing_bytes * 10, total_bytes);
    let (send, receive, delta_wire_bytes) = run_counted_transfer_with_options(
        configs.send.clone(),
        configs.recv.clone(),
        &root,
        dst.path(),
        send_options,
        receive_options,
    );
    assert_tree_delta_reports(
        &send.expect("directory delta sender completes"),
        &receive.expect("directory delta receiver commits"),
        missing_bytes,
    );
    assert!(
        delta_wire_bytes < full_wire_bytes / 2,
        "one changed member used {delta_wire_bytes} wire bytes versus {full_wire_bytes} for full tree"
    );
    assert_tree_delta_destination(dst.path(), &files);
    assert_eq!(
        std::fs::read(&extra).expect("receiver-only file"),
        b"keep this independent file"
    );

    // Reusing every content byte still needs publication: a missing empty file
    // and a permission-only change cannot be skipped as an already-synced tree.
    std::fs::remove_file(dst.path().join("tree/small/empty.bin"))
        .expect("remove only the test destination's empty member");
    #[cfg(unix)]
    {
        std::fs::set_permissions(
            root.join("small/changed.bin"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("change source permissions without changing content");
        std::fs::set_permissions(
            dst.path().join("tree/small/changed.bin"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("set different destination permissions");
    }
    let (send, receive, noop_wire_bytes) = run_counted_transfer_with_options(
        configs.send,
        configs.recv,
        &root,
        dst.path(),
        send_options,
        receive_options,
    );
    assert_tree_delta_reports(
        &send.expect("unchanged tree sender receives proof"),
        &receive.expect("unchanged tree receiver commits"),
        0,
    );
    assert!(
        noop_wire_bytes < delta_wire_bytes / 2,
        "tree no-op used {noop_wire_bytes} wire bytes versus {delta_wire_bytes} for a changed member"
    );
    assert_tree_delta_destination(dst.path(), &files);
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(dst.path().join("tree/small/changed.bin"))
            .expect("read committed permissions")
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "all-content-reused transfer must apply current source metadata"
    );
    assert_eq!(
        std::fs::read(&extra).expect("receiver-only file"),
        b"keep this independent file"
    );
}

#[test]
fn real_udp_quic_tree_delta_preserves_legacy_peer_fallback() {
    for (sender_tree, receiver_tree) in [(true, false), (false, true)] {
        let src = tempfile::tempdir().expect("source directory");
        let dst = tempfile::tempdir().expect("destination directory");
        let root = src.path().join("tree");
        let mut files = write_tree_delta_fixture(&root);
        write_tree_delta_fixture(&dst.path().join("tree"));
        let (_, changed) = files
            .iter_mut()
            .find(|(path, _)| path == "small/changed.bin")
            .expect("changed member");
        changed[19] ^= 0x3C;
        std::fs::write(root.join("small/changed.bin"), changed).expect("change tree source");
        let total_bytes = files.iter().map(|(_, bytes)| bytes.len() as u64).sum::<u64>();
        let configs = changed_chunk_configs();
        let (send, receive, _) = run_counted_transfer_with_options(
            configs.send,
            configs.recv,
            &root,
            dst.path(),
            QuicSendOptions::new().with_tree_delta(sender_tree),
            QuicReceiveOptions::new().with_tree_delta(receiver_tree),
        );
        assert_tree_delta_reports(
            &send.expect("mixed-version directory sender completes"),
            &receive.expect("mixed-version directory receiver commits"),
            total_bytes,
        );
        assert_tree_delta_destination(dst.path(), &files);
    }
}

#[test]
fn real_udp_quic_tree_delta_cancel_after_staging_preserves_baseline() {
    let src = tempfile::tempdir().expect("source directory");
    let dst = tempfile::tempdir().expect("destination directory");
    let root = src.path().join("tree");
    let baseline_root = dst.path().join("tree");
    std::fs::create_dir_all(&root).expect("create source tree");
    std::fs::create_dir_all(&baseline_root).expect("create baseline tree");
    let baseline = changed_chunk_payload(32, 0);
    let updated = baseline.iter().map(|byte| byte ^ 0xC3).collect::<Vec<_>>();
    let kept = changed_chunk_payload(0, 128 * 1024);
    std::fs::write(root.join("changed.bin"), &updated).expect("write updated member");
    std::fs::write(root.join("kept.bin"), &kept).expect("write reusable member");
    std::fs::write(baseline_root.join("changed.bin"), &baseline).expect("write baseline member");
    std::fs::write(baseline_root.join("kept.bin"), &kept).expect("write reusable baseline");
    let extra = baseline_root.join("receiver-only.txt");
    std::fs::write(&extra, b"preserve receiver-only data").expect("write receiver-only file");
    let configs = changed_chunk_configs();
    let probe_offset = 1024 * 1024 + 17;
    let fired = Arc::new(AtomicBool::new(false));
    let (send, receive) = block_on(async {
        let cx = Cx::for_testing();
        let endpoint = bind_server_endpoint(&cx, "127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind directory receiver");
        let proxy = CountingUdpProxy::spawn_with_cancellation(
            endpoint.local_addr(),
            Some(StagedTransferCancellation {
                cx: cx.clone(),
                minimum_wire_bytes: 1024 * 1024,
                dest_dir: dst.path().to_path_buf(),
                staged_probe_offset: probe_offset as u64,
                expected_staged_bytes: updated[probe_offset..probe_offset + 32]
                    .try_into()
                    .expect("staged probe width"),
                fired: Arc::clone(&fired),
            }),
        );
        zip(
            send_path_with_options(
                &cx,
                proxy.addr,
                &root,
                configs.send,
                "tree-sender",
                QuicSendOptions::new().with_tree_delta(true),
            ),
            receive_on_endpoint_with_options(
                &cx,
                endpoint,
                dst.path(),
                &configs.recv,
                "tree-receiver",
                QuicReceiveOptions::new().with_tree_delta(true),
            ),
        )
        .await
    });
    assert!(
        fired.load(Ordering::Relaxed),
        "cancellation must observe changed directory payload in staging"
    );
    assert!(
        matches!(&send, Err(QuicTransportError::Cancelled)),
        "sender: {send:?}"
    );
    assert!(
        matches!(&receive, Err(QuicTransportError::Cancelled)),
        "receiver: {receive:?}"
    );
    assert_tree_delta_destination(
        dst.path(),
        &[
            ("changed.bin".to_string(), baseline),
            ("kept.bin".to_string(), kept),
        ],
    );
    assert_eq!(
        std::fs::read(&extra).expect("receiver-only file"),
        b"preserve receiver-only data"
    );
}

#[test]
fn real_udp_quic_changed_chunks_reuse_reordered_and_repeated_content() {
    let src = tempfile::tempdir().expect("source directory");
    let dst = tempfile::tempdir().expect("destination directory");
    let source = src.path().join("payload.bin");
    let baseline = changed_chunk_payload(3, 0);
    let updated = [
        &baseline[2 * DELTA_TEST_CHUNK_BYTES..],
        &baseline[..DELTA_TEST_CHUNK_BYTES],
        &baseline[..DELTA_TEST_CHUNK_BYTES],
    ]
    .concat();
    assert_ne!(baseline, updated);
    std::fs::write(&source, &updated).expect("write reordered source");
    std::fs::write(dst.path().join("payload.bin"), &baseline).expect("write baseline");
    let configs = changed_chunk_configs();
    let (send, receive, _) = run_counted_transfer_with_options(
        configs.send,
        configs.recv,
        &source,
        dst.path(),
        QuicSendOptions::new().with_delta_chunks(true),
        QuicReceiveOptions::new().with_delta_chunks(true),
    );
    assert_changed_chunk_reports(
        &send.expect("reused chunks need no literal payload"),
        &receive.expect("receiver reconstructs at the new offsets"),
        0,
    );
    assert_changed_chunk_destination(dst.path(), &updated);
}

#[cfg(unix)]
#[test]
fn real_udp_quic_changed_chunks_commit_metadata_without_literal_payload() {
    let src = tempfile::tempdir().expect("source directory");
    let dst = tempfile::tempdir().expect("destination directory");
    let source = src.path().join("payload.bin");
    let destination = dst.path().join("payload.bin");
    let payload = changed_chunk_payload(2, 19);
    std::fs::write(&source, &payload).expect("write source");
    std::fs::write(&destination, &payload).expect("write baseline");
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600))
        .expect("set source permissions");
    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o640))
        .expect("set baseline permissions");
    let mut configs = changed_chunk_configs();
    configs.send.metadata_policy = MetadataPolicy::default();
    configs.recv.metadata_policy = MetadataPolicy::default();
    let (send, receive, _) = run_counted_transfer_with_options(
        configs.send,
        configs.recv,
        &source,
        dst.path(),
        QuicSendOptions::new().with_delta_chunks(true),
        QuicReceiveOptions::new().with_delta_chunks(true),
    );
    assert_changed_chunk_reports(
        &send.expect("metadata-only send completes"),
        &receive.expect("metadata-only reconstruction commits"),
        0,
    );
    assert_eq!(
        std::fs::metadata(destination).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_changed_chunk_destination(dst.path(), &payload);
}

/// Three new chunks exceed the bounded control-stream receive window several
/// times. The existing proxy introduces loss, delay, duplication and reorder,
/// so stream credit and retransmission must keep the changed-chunk path alive.
#[test]
fn real_udp_quic_changed_chunks_append_survives_loss_and_stream_credit() {
    let src = tempfile::tempdir().expect("source directory");
    let dst = tempfile::tempdir().expect("destination directory");
    let source = src.path().join("payload.bin");
    let baseline = changed_chunk_payload(3, 0);
    let updated = changed_chunk_payload(6, 113);
    std::fs::write(&source, &updated).expect("write appended source");
    std::fs::write(dst.path().join("payload.bin"), &baseline).expect("write baseline");
    let mut configs = changed_chunk_configs();
    // Per-symbol authentication disables the ordinary reliable source stream.
    // Changed chunks must still use their negotiated control-stream data path.
    configs.send = configs
        .send
        .with_symbol_auth(SecurityContext::for_testing(0xD3_17_FE));
    configs.recv = configs
        .recv
        .with_symbol_auth(SecurityContext::for_testing(0xD3_17_FE));
    for config in [&mut configs.send, &mut configs.recv] {
        config.round0_loss_target = 0.10;
        config.idle_timeout = Duration::from_secs(45);
    }
    let (send, receive) = block_on(async {
        let cx = Cx::for_testing();
        let endpoint = bind_server_endpoint(&cx, "127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind receiver");
        let proxy = LossyUdpProxy::spawn_with_rate_timeout(
            endpoint.local_addr(),
            0xD3_17_A0_10,
            None,
            Duration::from_secs(60),
        );
        zip(
            send_path_with_options(
                &cx,
                proxy.addr,
                &source,
                configs.send,
                "delta-sender",
                QuicSendOptions::new().with_delta_chunks(true),
            ),
            receive_on_endpoint_with_options(
                &cx,
                endpoint,
                dst.path(),
                &configs.recv,
                "delta-receiver",
                QuicReceiveOptions::new().with_delta_chunks(true),
            ),
        )
        .await
    });
    let send = send.unwrap_or_else(|error| {
        panic!("lossy changed-chunk sender failed: {error:?}; receiver={receive:?}")
    });
    assert_changed_chunk_reports(
        &send,
        &receive.expect("lossy changed-chunk receiver commits"),
        updated.len() - baseline.len(),
    );
    assert_changed_chunk_destination(dst.path(), &updated);
}

#[test]
fn real_udp_quic_changed_chunks_one_sided_opt_in_keeps_full_fallback() {
    for (sender_opt_in, receiver_opt_in) in [(true, false), (false, true)] {
        let src = tempfile::tempdir().expect("source directory");
        let dst = tempfile::tempdir().expect("destination directory");
        let source = src.path().join("payload.bin");
        let baseline = changed_chunk_payload(3, 23);
        let mut updated = baseline.clone();
        updated[DELTA_TEST_CHUNK_BYTES + 19] ^= 0x3C;
        std::fs::write(&source, &updated).expect("write changed source");
        std::fs::write(dst.path().join("payload.bin"), &baseline).expect("write baseline");
        let configs = changed_chunk_configs();
        let (send, receive, _) = run_counted_transfer_with_options(
            configs.send,
            configs.recv,
            &source,
            dst.path(),
            QuicSendOptions::new().with_delta_chunks(sender_opt_in),
            QuicReceiveOptions::new().with_delta_chunks(receiver_opt_in),
        );
        assert_changed_chunk_reports(
            &send.expect("one-sided offer preserves existing sender behavior"),
            &receive.expect("one-sided offer preserves existing receiver behavior"),
            updated.len(),
        );
        assert_changed_chunk_destination(dst.path(), &updated);
    }
}

#[test]
fn real_udp_quic_changed_chunks_require_enabled_delta_and_strict_control_auth() {
    let src = tempfile::tempdir().expect("source directory");
    let dst = tempfile::tempdir().expect("destination directory");
    let source = src.path().join("payload.bin");
    std::fs::write(&source, [7_u8; 1024]).expect("write source");
    for invalid_case in ["disabled", "missing key", "permissive key"] {
        let mut configs = changed_chunk_configs();
        for config in [&mut configs.send, &mut configs.recv] {
            match invalid_case {
                "disabled" => config.enable_delta = false,
                "missing key" => config.delta_control_auth_context = None,
                _ => {
                    config.delta_control_auth_context = Some(
                        SecurityContext::for_testing_with_mode(0xD3_17_A0, AuthMode::Permissive),
                    );
                }
            }
        }
        block_on(async {
            let cx = Cx::for_testing();
            let endpoint = bind_server_endpoint(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .expect("bind receiver");
            let send = send_path_with_options(
                &cx,
                endpoint.local_addr(),
                &source,
                configs.send,
                "delta-sender",
                QuicSendOptions::new().with_delta_chunks(true),
            )
            .await;
            assert!(
                matches!(&send, Err(QuicTransportError::Config(reason)) if reason.contains("delta")),
                "{invalid_case}: sender must reject options before waiting for a peer: {send:?}"
            );
            let receive = receive_on_endpoint_with_options(
                &cx,
                endpoint,
                dst.path(),
                &configs.recv,
                "delta-receiver",
                QuicReceiveOptions::new().with_delta_chunks(true),
            )
            .await;
            assert!(
                matches!(&receive, Err(QuicTransportError::Config(reason)) if reason.contains("delta")),
                "{invalid_case}: receiver must reject options before accepting a peer: {receive:?}"
            );
        });
    }
    assert_eq!(std::fs::read_dir(dst.path()).unwrap().count(), 0);
}

#[test]
fn real_udp_quic_changed_chunks_reject_wrong_client_key_before_destination_changes() {
    let src = tempfile::tempdir().expect("source directory");
    let dst = tempfile::tempdir().expect("destination directory");
    let source = src.path().join("payload.bin");
    let baseline = changed_chunk_payload(2, 29);
    let mut updated = baseline.clone();
    updated[17] ^= 0xD7;
    std::fs::write(&source, &updated).expect("write source");
    std::fs::write(dst.path().join("payload.bin"), &baseline).expect("write baseline");
    let mut configs = changed_chunk_configs();
    configs.send.delta_control_auth_context = Some(SecurityContext::for_testing(0xBA_D0));
    configs.send.idle_timeout = Duration::from_secs(5);
    configs.recv.idle_timeout = Duration::from_secs(5);
    let (send, receive, _) = run_counted_transfer_with_options(
        configs.send,
        configs.recv,
        &source,
        dst.path(),
        QuicSendOptions::new().with_delta_chunks(true),
        QuicReceiveOptions::new().with_delta_chunks(true),
    );
    assert!(send.is_err(), "an unauthorized sender must receive no successful receipt");
    assert!(
        matches!(&receive, Err(QuicTransportError::HandshakeRejected(reason))
            if reason.contains("authentication failed")),
        "receiver must reject the client proof despite valid server TLS: {receive:?}"
    );
    assert_changed_chunk_destination(dst.path(), &baseline);
}

#[test]
fn real_udp_quic_changed_chunks_deliver_metadata_policy_refusal() {
    let src = tempfile::tempdir().expect("source directory");
    let dst = tempfile::tempdir().expect("destination directory");
    let source = src.path().join("payload.bin");
    let baseline = changed_chunk_payload(2, 17);
    let mut updated = baseline.clone();
    updated[DELTA_TEST_CHUNK_BYTES + 13] ^= 0x8D;
    std::fs::write(&source, &updated).expect("write source");
    std::fs::write(dst.path().join("payload.bin"), &baseline).expect("write baseline");
    let mut configs = changed_chunk_configs();
    configs.send.metadata_policy.preserve_timestamps = true;
    let (send, receive, _) = run_counted_transfer_with_options(
        configs.send,
        configs.recv,
        &source,
        dst.path(),
        QuicSendOptions::new().with_delta_chunks(true),
        QuicReceiveOptions::new().with_delta_chunks(true),
    );
    assert!(
        matches!(&receive, Err(QuicTransportError::Source(reason))
            if reason.contains("timestamps are denied by receiver metadata policy")),
        "receiver policy refusal: {receive:?}"
    );
    assert!(
        matches!(&send, Err(QuicTransportError::Integrity(reason))
            if reason.starts_with("receiver refused the manifest: ")
                && reason.contains("timestamps are denied by receiver metadata policy")),
        "bound refusal must reach the sender: {send:?}"
    );
    assert_changed_chunk_destination(dst.path(), &baseline);
}

#[test]
fn real_udp_quic_changed_chunks_cancel_after_staging_preserves_baseline() {
    assert_quic_chunk_cancellation_preserves_baseline(false);
}

#[test]
fn real_udp_quic_cdc_cancel_after_staging_preserves_baseline() {
    assert_quic_chunk_cancellation_preserves_baseline(true);
}

fn assert_quic_chunk_cancellation_preserves_baseline(cdc: bool) {
    let src = tempfile::tempdir().expect("source directory");
    let dst = tempfile::tempdir().expect("destination directory");
    let source = src.path().join("payload.bin");
    let baseline = changed_chunk_payload(32, 0);
    let mut updated = baseline.clone();
    for byte in &mut updated[16 * DELTA_TEST_CHUNK_BYTES..] {
        *byte ^= 0xC3;
    }
    std::fs::write(&source, &updated).expect("write changed source");
    std::fs::write(dst.path().join("payload.bin"), &baseline).expect("write baseline");
    let configs = changed_chunk_configs();
    let probe_offset = 16 * DELTA_TEST_CHUNK_BYTES + 17;
    let fired = Arc::new(AtomicBool::new(false));
    let (send, receive) = block_on(async {
        let cx = Cx::for_testing();
        let endpoint = bind_server_endpoint(&cx, "127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind receiver");
        let proxy = CountingUdpProxy::spawn_with_cancellation(
            endpoint.local_addr(),
            Some(StagedTransferCancellation {
                cx: cx.clone(),
                minimum_wire_bytes: 1024 * 1024,
                dest_dir: dst.path().to_path_buf(),
                staged_probe_offset: probe_offset as u64,
                expected_staged_bytes: updated[probe_offset..probe_offset + 32]
                    .try_into()
                    .expect("staged probe width"),
                fired: Arc::clone(&fired),
            }),
        );
        zip(
            send_path_with_options(
                &cx,
                proxy.addr,
                &source,
                configs.send,
                "delta-sender",
                QuicSendOptions::new()
                    .with_delta_chunks(!cdc)
                    .with_cdc_delta(cdc),
            ),
            receive_on_endpoint_with_options(
                &cx,
                endpoint,
                dst.path(),
                &configs.recv,
                "delta-receiver",
                QuicReceiveOptions::new()
                    .with_delta_chunks(!cdc)
                    .with_cdc_delta(cdc),
            ),
        )
        .await
    });
    assert!(
        fired.load(Ordering::Relaxed),
        "cancellation must observe received payload in staging before it fires"
    );
    assert!(
        matches!(&send, Err(QuicTransportError::Cancelled)),
        "sender must stop at cancellation: {send:?}"
    );
    assert!(
        matches!(&receive, Err(QuicTransportError::Cancelled)),
        "receiver must stop at cancellation: {receive:?}"
    );
    assert_changed_chunk_destination(dst.path(), &baseline);
}

/// zstd over the reliable source stream (br-asupersync-t1fblr.29).
/// - A receiver that accepts the offer gets compressible data in a fraction
///   of its size.
/// - A receiver that ignores the offer, as one that predates compression
///   does, gets the stream raw.
/// - A sender that makes no offer sends it raw too.
/// - Auto compresses this text entry as Zstd does (t1fblr.24).
/// In every case the committed file equals the source, verified on its raw
/// bytes, and the reports count raw bytes.
#[cfg(feature = "zstd")]
#[test]
fn real_udp_quic_source_stream_compresses_with_zstd() {
    let words = [
        "region ",
        "obligation ",
        "cancel ",
        "scope ",
        "budget ",
        "trace\n",
    ];
    let mut state = 11_u64;
    let mut payload = Vec::with_capacity(1 << 20);
    while payload.len() < 1 << 20 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        payload.extend_from_slice(
            words[usize::try_from(state >> 61).unwrap() % words.len()].as_bytes(),
        );
    }
    payload.truncate(1 << 20);
    let len = payload.len() as u64;
    let zstd = QuicSendOptions::new().with_compression(CompressionMode::Zstd);
    let auto = QuicSendOptions::new().with_compression(CompressionMode::Auto);
    let mut wire = Vec::new();
    for (label, options, receiver_ignores_offer, name) in [
        ("accepted", zstd, false, "compressible.txt"),
        ("ignored", zstd, true, "compressible.txt"),
        (
            "not offered",
            QuicSendOptions::new(),
            false,
            "compressible.txt",
        ),
        ("auto", auto, false, "compressible.txt"),
        ("auto, a .png entry", auto, false, "compressible.png"),
    ] {
        let src = tempfile::tempdir().expect("src dir");
        let dst = tempfile::tempdir().expect("dst dir");
        let source = src.path().join(name);
        std::fs::write(&source, &payload).expect("write source");
        let mut cfg = transport_authenticated_configs();
        cfg.send.round0_loss_target = 0.001;
        cfg.recv.round0_loss_target = 0.001;
        set_receiver_ignores_codec_offers_for_testing(receiver_ignores_offer);
        let (send, recv, sent) =
            run_counted_transfer(cfg.send, cfg.recv, &source, dst.path(), options);
        set_receiver_ignores_codec_offers_for_testing(false);
        let send = send.unwrap_or_else(|error| panic!("{label}: send failed: {error}"));
        let recv = recv.unwrap_or_else(|error| panic!("{label}: receive failed: {error}"));
        assert!(recv.committed, "{label}: receiver must commit");
        assert!(
            send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok,
            "{label}"
        );
        assert_eq!(send.bytes_sent, len, "{label}: the report counts raw bytes");
        assert_eq!(
            recv.bytes_received, len,
            "{label}: the report counts raw bytes"
        );
        assert_eq!(
            send.symbols_sent, 0,
            "{label}: the source stream carried everything"
        );
        assert!(
            std::fs::read(dst.path().join(name)).expect("read committed") == payload,
            "{label}: committed bytes must match the source"
        );
        assert_no_staging_residue(dst.path());
        wire.push((label, sent));
    }
    let (compressed, ignored, plain) = (wire[0].1, wire[1].1, wire[2].1);
    let (auto, auto_png) = (wire[3].1, wire[4].1);
    assert!(
        compressed < len / 3,
        "accepted: {compressed} wire bytes for {len}"
    );
    assert!(ignored > len, "ignored: {ignored} wire bytes for {len}");
    assert!(plain > len, "not offered: {plain} wire bytes for {len}");
    // Auto compresses a text entry as Zstd does, and sends an entry named as
    // an already-compressed format raw (br-asupersync-t1fblr.24).
    assert!(auto < len / 3, "auto: {auto} wire bytes for {len}");
    assert!(
        auto_png > len,
        "auto, a .png entry: {auto_png} wire bytes for {len}"
    );
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

/// The packed 2000-member tree of the br-asupersync-daqxbz regression: the
/// manifest spans >100 control-stream packets while ~200-byte bodies keep the
/// bulk phase short. Returns the members as (relative path, bytes).
fn write_lossy_manifest_tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    write_manifest_tree(root, 2000)
}

/// `members` small files spread over 40 directories; the sender packs them
/// into one packed entry.
fn write_manifest_tree(root: &Path, members: usize) -> Vec<(String, Vec<u8>)> {
    std::fs::create_dir_all(root).expect("mkdir tree root");
    let mut expected = Vec::with_capacity(members);
    for index in 0..members {
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
    expected
}

/// Largest single proof-wait stall-expiry re-send the fixed sender may take:
/// the ramp starts at the 8-packet fast-drain size, doubles only while the
/// peer stays ACK-silent, and is capped at the 64-packet ack-gap burst
/// ceiling, so a receiver that stays silent for several intervals never sees
/// the old 91-146-packet storms rebuild.
const MAX_STALL_PTO_RESEND_PACKETS: u64 = 64;
/// Total stall-expiry re-sends over the whole transfer: about twice the
/// ~150-packet manifest, where the old sender re-sent ~146 packets per storm
/// for five or more storms.
const MAX_STALL_PTO_RESEND_TOTAL_PACKETS: u64 = 320;

/// asupersync-9bb6pt: the same lossy packed-tree transfer, measured. Before
/// the fix the sender's stall expiry (200 ms base) fired at the path RTT
/// (~200 ms) while it awaited the receiver's Proof, drained every in-flight
/// source-stream packet (~311 frames / 146 packets) and re-sent all of them,
/// repeating every stall interval while the receiver — acknowledging once per
/// drained batch — fell further behind under ~6.7 MB of duplicates; the
/// head-of-line hole was filled only by the fifth storm at ~9.9 s. The stall
/// threshold now floors at base + RTT + variance + burst time, and a silent
/// expiry re-sends a probe-sized burst that grows only with further silence,
/// so stall-expiry re-sends stay bounded per storm and in total.
#[test]
fn real_udp_quic_tree_manifest_stall_pto_resends_stay_bounded() {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let root = src.path().join("tree");
    let expected = write_lossy_manifest_tree(&root);
    let mut cfg = transport_authenticated_configs();
    cfg.send.round0_loss_target = 0.10;
    cfg.recv.round0_loss_target = 0.10;
    cfg.send.idle_timeout = Duration::from_secs(45);
    cfg.recv.idle_timeout = Duration::from_secs(45);
    cfg.send.handshake_timeout = Duration::from_secs(20);
    cfg.recv.handshake_timeout = Duration::from_secs(20);
    cfg.send.accept_timeout = Duration::from_secs(20);
    // The receiver's accept clock starts before the sender has built its
    // 2000-member manifest, and that build alone passed 20 s on a loaded
    // worker; the receiver then stopped accepting and both sides timed out
    // with no packet exchanged (asupersync-bi2462.147.70). A real receiver
    // accepts indefinitely; only the lossy transfer is under test here.
    cfg.recv.accept_timeout = Duration::from_secs(120);
    // The proxy forwards nothing after its timeout. At 75 s it died mid-transfer
    // on loaded workers (the manifest build plus the lossy transfer outlived
    // it), and both sides then timed out in silence: the receiver after its
    // last Proof retransmit, the sender in its proof wait
    // (asupersync-bi2462.147.70). Drop stops the proxy at the end of the test
    // anyway, so the timeout is only a backstop.
    let (send, recv, collector) = run_transfer_via_lossy_proxy_with_collector(
        cfg.send,
        cfg.recv,
        &root,
        dst.path(),
        0xDA_0B_2D_15,
        TREE_MANIFEST_PROXY_TIMEOUT,
        65_536,
    );
    let resends = stall_pto_resends(&collector);
    let total_packets: u64 = resends.iter().map(|resend| resend.packets).sum();
    let total_frames: u64 = resends.iter().map(|resend| resend.stream_frames).sum();
    let max_packets = resends
        .iter()
        .map(|resend| resend.packets)
        .max()
        .unwrap_or(0);
    println!(
        "proof_wait_pto_resends={} max_packets={max_packets} total_packets={total_packets} \
         total_stream_frames={total_frames} resends={resends:?}",
        resends
            .iter()
            .filter(|resend| resend.reason.ends_with("proof_wait_pto"))
            .count()
    );
    let send = send.unwrap_or_else(|err| {
        panic!("lossy tree-manifest sender must complete: {err:?}; receiver={recv:?}")
    });
    let recv = recv.expect("lossy tree-manifest receiver commits");
    assert!(recv.committed, "receiver must commit the packed tree");
    assert_eq!(send.transfer_id, recv.transfer_id);
    assert_eq!(send.files as usize, expected.len());
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);
    assert!(
        max_packets <= MAX_STALL_PTO_RESEND_PACKETS,
        "a single stall-expiry re-send must stay probe-sized on a live path \
         (asupersync-9bb6pt): max {max_packets} packets > {MAX_STALL_PTO_RESEND_PACKETS}; \
         resends={resends:?}"
    );
    assert!(
        total_packets <= MAX_STALL_PTO_RESEND_TOTAL_PACKETS,
        "stall-expiry re-sends over the transfer must stay bounded \
         (asupersync-9bb6pt): {total_packets} packets > {MAX_STALL_PTO_RESEND_TOTAL_PACKETS}; \
         resends={resends:?}"
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
    // Room for the sender's 2000-member manifest build before its first
    // packet (asupersync-bi2462.147.70; see the stall-PTO test above).
    cfg.recv.accept_timeout = Duration::from_secs(120);

    let (send, recv) = run_transfer_via_lossy_proxy(
        cfg.send,
        cfg.recv,
        &root,
        dst.path(),
        0xDA_0B_2D_15,
        TREE_MANIFEST_PROXY_TIMEOUT,
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

/// br-asupersync-r02ssd: a receiver that commits a packed tree slowly keeps
/// the sender alive. The commit-start loop that resolves and checks every
/// member path sent no keep-alive. For 2000 members it took 10 s on an idle
/// machine and longer under load, so a sender whose idle budget ran out first
/// reported failure for a transfer the receiver then committed. The test hook
/// makes that loop take at least 16 s (80 ms for each of 200 members) against
/// a 10 s sender idle budget. Few members keep the per-member commit (a
/// directory fsync each) far below the sender's 80 s proof-wait cap even on a
/// loaded disk: 2000 members exceeded it there.
#[test]
fn real_udp_quic_tree_commit_slower_than_the_sender_idle_budget_keeps_the_sender_alive() {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let root = src.path().join("tree");
    let expected = write_manifest_tree(&root, 200);
    let mut cfg = transport_authenticated_configs();
    cfg.send.idle_timeout = Duration::from_secs(10);
    cfg.recv.accept_timeout = Duration::from_secs(120);

    // The receive is driven on this thread by `block_on`, which is where the
    // hook applies.
    set_receiver_member_path_delay_for_testing(Duration::from_millis(80));
    let (send, recv) = run_transfer(cfg.send, cfg.recv, &root, dst.path());
    set_receiver_member_path_delay_for_testing(Duration::ZERO);

    let send = send.unwrap_or_else(|err| {
        panic!("the sender must outlast a commit slower than its idle budget: {err:?}; receiver={recv:?}")
    });
    let recv = recv.expect("the receiver commits the packed tree");
    assert!(recv.committed, "receiver must commit the packed tree");
    assert_eq!(send.transfer_id, recv.transfer_id);
    assert_eq!(send.files as usize, expected.len());
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);
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

    // Transport-auth transfers ride the reliable source stream: staged bytes
    // commit via sha verify and the RaptorQ decoder stays disengaged on a
    // lossless loopback link, so the FEC counters must read zero (the spray
    // tier's assert_receive_report_counters expects the opposite).
    assert!(recv.committed, "receiver must commit");
    assert_eq!(recv.bytes_received, payload.len() as u64);
    assert_eq!(recv.files, 1);
    assert_eq!(send.receipt.symbols_accepted, recv.symbols_accepted);
    assert_eq!(send.receipt.feedback_rounds, recv.feedback_rounds);
    assert_eq!(send.receipt.decode_count, recv.decode_count);
    assert_eq!(
        recv.symbols_accepted, 0,
        "lossless source-stream receiver must not engage the RaptorQ decoder"
    );
    assert_eq!(
        recv.decode_count, 0,
        "lossless source-stream commit must come from staged stream bytes, not block decode"
    );
    assert_eq!(
        recv.feedback_rounds, 0,
        "source-stream transfer must not need fountain repair feedback"
    );
    assert!(
        !recv.committed_paths.is_empty(),
        "receiver report must expose committed-path evidence"
    );
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

#[cfg(unix)]
#[test]
fn real_udp_quic_transfer_metadata_fidelity_authenticated() {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let root = src.path().join("metadata-tree");
    std::fs::create_dir_all(&root).expect("create metadata tree");

    let payload = root.join("payload.bin");
    std::fs::write(&payload, b"quic metadata fidelity\n").expect("write payload");
    std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o640))
        .expect("set payload mode");
    let fixed_mtime = std::time::UNIX_EPOCH + Duration::new(1_600_000_123, 456_789_123);
    std::fs::File::open(&payload)
        .expect("open payload for timestamp")
        .set_times(std::fs::FileTimes::new().set_modified(fixed_mtime))
        .expect("set payload mtime");
    let source_payload_metadata = std::fs::metadata(&payload).expect("source payload metadata");
    let expected_payload_mode = source_payload_metadata.permissions().mode() & 0o7777;
    let expected_payload_mtime = (
        source_payload_metadata.mtime(),
        source_payload_metadata.mtime_nsec(),
    );
    assert_eq!(expected_payload_mode, 0o640);
    let xattr_name = "user.asupersync.quic-metadata-e2e";
    let xattr_value = b"metadata-value\0with-binary";
    let xattr_supported = xattr::set(&payload, xattr_name, xattr_value).is_ok();

    let empty = root.join("empty-dir");
    std::fs::create_dir(&empty).expect("create empty directory");
    std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o750))
        .expect("set empty directory mode");

    std::os::unix::fs::symlink("payload.bin", root.join("relative-link"))
        .expect("create relative symlink");
    std::os::unix::fs::symlink("missing-target", root.join("dangling-link"))
        .expect("create dangling symlink");

    let hardlink_primary = root.join("hardlink-a.txt");
    let hardlink_alias = root.join("hardlink-b.txt");
    std::fs::write(&hardlink_primary, b"shared hardlink content\n")
        .expect("write hardlink primary");
    std::fs::hard_link(&hardlink_primary, &hardlink_alias).expect("create hardlink alias");

    let packed_sparse = root.join("packed-sparse.bin");
    let packed_sparse_expected = write_sparse_fixture(&packed_sparse, 512 * 1024, b"packed-sparse");
    let regular_sparse = root.join("regular-sparse.bin");
    let regular_sparse_expected =
        write_sparse_fixture(&regular_sparse, 2 * 1024 * 1024, b"regular-sparse");
    std::fs::set_permissions(&regular_sparse, std::fs::Permissions::from_mode(0o604))
        .expect("set direct regular sparse mode");
    let regular_sparse_mtime = std::time::UNIX_EPOCH + Duration::new(1_600_000_456, 987_654_321);
    std::fs::File::open(&regular_sparse)
        .expect("open direct regular sparse for timestamp")
        .set_times(std::fs::FileTimes::new().set_modified(regular_sparse_mtime))
        .expect("set direct regular sparse mtime");
    let source_regular_sparse_metadata =
        std::fs::metadata(&regular_sparse).expect("source direct regular sparse metadata");
    let expected_regular_sparse_mode = source_regular_sparse_metadata.permissions().mode() & 0o7777;
    let expected_regular_sparse_mtime = (
        source_regular_sparse_metadata.mtime(),
        source_regular_sparse_metadata.mtime_nsec(),
    );
    assert_eq!(expected_regular_sparse_mode, 0o604);
    for sparse_source in [&packed_sparse, &regular_sparse] {
        let metadata = std::fs::metadata(sparse_source).expect("source sparse metadata");
        assert!(
            metadata.blocks().saturating_mul(512) < metadata.len() / 2,
            "source fixture must be genuinely sparse: {}",
            sparse_source.display()
        );
    }

    let fifo = root.join("events.fifo");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o620))
        .expect("create source FIFO");
    std::fs::set_permissions(&fifo, std::fs::Permissions::from_mode(0o620)).expect("set FIFO mode");

    let mut cfg = authenticated_configs(0x6D37_A001);
    cfg.send.metadata_policy = MetadataPolicy::full_preservation();
    cfg.recv.metadata_policy = MetadataPolicy::full_preservation();
    cfg.send.allow_special_files = true;
    cfg.recv.allow_special_files = true;
    cfg.send.preserve_hardlinks = true;
    cfg.recv.preserve_hardlinks = true;

    let (send, recv) = run_transfer_with_options(
        cfg.send,
        cfg.recv,
        &root,
        dst.path(),
        QuicReceiveOptions::new().with_sparse_files(true),
    );
    let send = send.expect("metadata-fidelity send_path completes over real UDP");
    let recv = recv.expect("metadata-fidelity receiver commits");
    let expected_bytes = 47
        + u64::try_from(packed_sparse_expected.len()).expect("packed sparse size fits u64")
        + u64::try_from(regular_sparse_expected.len()).expect("regular sparse size fits u64");
    assert_receive_report_counters(&send, &recv, expected_bytes, 9);
    assert_eq!(send.files, 9, "sender must report all logical entries");
    assert!(send.receipt.committed, "sender receipt must report commit");
    assert!(send.receipt.sha_ok, "sender receipt must report SHA proof");
    assert!(
        send.receipt.merkle_ok,
        "sender receipt must report merkle proof"
    );
    assert!(recv.committed, "receiver must report commit");
    assert_eq!(send.transfer_id, recv.transfer_id);

    let out = dst.path().join("metadata-tree");
    assert_eq!(
        std::fs::read(out.join("payload.bin")).expect("read committed payload"),
        b"quic metadata fidelity\n"
    );
    let payload_metadata = std::fs::metadata(out.join("payload.bin")).expect("payload metadata");
    assert_eq!(
        payload_metadata.permissions().mode() & 0o7777,
        expected_payload_mode
    );
    assert_eq!(
        (payload_metadata.mtime(), payload_metadata.mtime_nsec()),
        expected_payload_mtime,
        "regular-file mtime seconds and nanoseconds must round-trip exactly"
    );
    if xattr_supported {
        assert_eq!(
            xattr::get(out.join("payload.bin"), xattr_name).expect("read committed xattr"),
            Some(xattr_value.to_vec()),
            "xattr value must round-trip byte-identically"
        );
    }

    let empty_metadata =
        std::fs::symlink_metadata(out.join("empty-dir")).expect("committed empty directory");
    assert!(empty_metadata.is_dir(), "empty directory must survive");
    assert_eq!(empty_metadata.permissions().mode() & 0o7777, 0o750);
    assert!(
        std::fs::read_dir(out.join("empty-dir"))
            .expect("read committed empty directory")
            .next()
            .is_none(),
        "empty directory must remain empty"
    );

    for (name, target) in [
        ("relative-link", Path::new("payload.bin")),
        ("dangling-link", Path::new("missing-target")),
    ] {
        let link = out.join(name);
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("committed symlink")
                .file_type()
                .is_symlink(),
            "{name} must remain a symlink"
        );
        assert_eq!(std::fs::read_link(link).expect("read symlink"), target);
    }
    assert!(
        !out.join("dangling-link").exists(),
        "dangling symlink must remain unresolved"
    );

    let out_hardlink_primary = out.join("hardlink-a.txt");
    let out_hardlink_alias = out.join("hardlink-b.txt");
    assert_eq!(
        std::fs::read(&out_hardlink_primary).expect("read hardlink primary"),
        b"shared hardlink content\n"
    );
    assert_eq!(
        std::fs::read(&out_hardlink_alias).expect("read hardlink alias"),
        b"shared hardlink content\n"
    );
    let primary_metadata =
        std::fs::metadata(&out_hardlink_primary).expect("hardlink primary metadata");
    let alias_metadata = std::fs::metadata(&out_hardlink_alias).expect("hardlink alias metadata");
    assert_eq!(
        (primary_metadata.dev(), primary_metadata.ino()),
        (alias_metadata.dev(), alias_metadata.ino()),
        "hardlink entries must share an inode after commit"
    );

    let fifo_metadata =
        std::fs::symlink_metadata(out.join("events.fifo")).expect("committed FIFO metadata");
    assert!(
        fifo_metadata.file_type().is_fifo(),
        "FIFO must be recreated"
    );
    assert_eq!(fifo_metadata.permissions().mode() & 0o7777, 0o620);
    for (name, expected) in [
        ("packed-sparse.bin", packed_sparse_expected),
        ("regular-sparse.bin", regular_sparse_expected),
    ] {
        let committed = out.join(name);
        assert_sparse_fixture(&committed, &expected, name);
    }
    let committed_regular_sparse_metadata = std::fs::metadata(out.join("regular-sparse.bin"))
        .expect("committed direct regular metadata");
    assert_eq!(
        committed_regular_sparse_metadata.permissions().mode() & 0o7777,
        expected_regular_sparse_mode
    );
    assert_eq!(
        (
            committed_regular_sparse_metadata.mtime(),
            committed_regular_sparse_metadata.mtime_nsec()
        ),
        expected_regular_sparse_mtime,
        "direct regular-file mtime seconds and nanoseconds must round-trip exactly"
    );
    assert_no_staging_residue(dst.path());
}

#[cfg(unix)]
#[test]
fn real_udp_quic_source_stream_preserves_sparse_regular_and_packed_entries() {
    let src = tempfile::tempdir().expect("src dir");
    let dst = tempfile::tempdir().expect("dst dir");
    let root = src.path().join("source-stream-sparse-tree");
    std::fs::create_dir_all(&root).expect("create source-stream sparse tree");

    let packed_a = root.join("packed-a-sparse.bin");
    let packed_a_expected = write_sparse_fixture(&packed_a, 256 * 1024, b"packed-a-source-stream");
    let packed_b = root.join("packed-b-sparse.bin");
    let packed_b_expected = write_sparse_fixture(&packed_b, 256 * 1024, b"packed-b-source-stream");
    let regular = root.join("regular-sparse.bin");
    let regular_expected =
        write_sparse_fixture(&regular, 2 * 1024 * 1024, b"regular-source-stream");
    assert_sparse_fixture(&packed_a, &packed_a_expected, "packed source A");
    assert_sparse_fixture(&packed_b, &packed_b_expected, "packed source B");
    assert_sparse_fixture(&regular, &regular_expected, "regular source");

    let cfg = transport_authenticated_configs();
    let (send, recv) = run_transfer_with_options(
        cfg.send,
        cfg.recv,
        &root,
        dst.path(),
        QuicReceiveOptions::new().with_sparse_files(true),
    );
    let send = send.expect("source-stream sparse send completes over real UDP");
    let recv = recv.expect("source-stream sparse receiver commits");
    let expected_bytes =
        u64::try_from(packed_a_expected.len() + packed_b_expected.len() + regular_expected.len())
            .expect("sparse fixture total fits u64");
    assert!(recv.committed, "source-stream receiver must commit");
    assert_eq!(recv.bytes_received, expected_bytes);
    assert_eq!(send.bytes_sent, expected_bytes);
    assert_eq!(recv.files, 3);
    assert_eq!(send.files, 3);
    assert_eq!(send.transfer_id, recv.transfer_id);
    assert_eq!(send.receipt.symbols_accepted, recv.symbols_accepted);
    assert_eq!(send.receipt.feedback_rounds, recv.feedback_rounds);
    assert_eq!(send.receipt.decode_count, recv.decode_count);
    assert_eq!(
        send.symbols_sent, 0,
        "source-stream sender must not emit RaptorQ symbols"
    );
    assert_eq!(
        (
            recv.symbols_accepted,
            recv.decode_count,
            recv.feedback_rounds
        ),
        (0, 0, 0),
        "lossless transport-auth transfer must prove the reliable source-stream path"
    );
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);

    let out = dst.path().join("source-stream-sparse-tree");
    assert_sparse_fixture(
        &out.join("packed-a-sparse.bin"),
        &packed_a_expected,
        "packed source-stream destination A",
    );
    assert_sparse_fixture(
        &out.join("packed-b-sparse.bin"),
        &packed_b_expected,
        "packed source-stream destination B",
    );
    assert_sparse_fixture(
        &out.join("regular-sparse.bin"),
        &regular_expected,
        "regular source-stream destination",
    );
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
#[ignore = "pending SapphireHill netns A/B verification"]
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
