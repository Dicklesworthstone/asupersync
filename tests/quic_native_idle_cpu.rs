//! GH#67 (asupersync-t64ggs): an established [`NativeQuicUdpConnection`] with a
//! silent peer must not burn CPU while its owner loops
//! `drive_io_once(cx, 500ms)` under the documented caller-driven composition
//! (`futures_lite::block_on` plus an explicit capability context, no runtime
//! reactor turning the socket).
//!
//! The reporter measured `IdleOutcome { wall_ms: 6000, cpu_ms: 6000,
//! cpu_fraction_percent: 99, wakeups: 12 }`: every bounded receive wait spent
//! its entire window on-CPU instead of parking. This test reproduces that
//! measurement (process `utime + stime` from `/proc/self/stat` across an idle
//! window) and asserts the wait parks.
//!
//! Gating: `tls` (real rustls handshake) + `quic` + `test-internals`
//! (`Cx::for_testing`), Linux only because the CPU accounting reads
//! `/proc/self/stat`. The in-tree HTTP/3 live-UDP test gates on `http3`; this
//! test deliberately does not, so the `test-internals,tls,quic` lane that is
//! required to run it cannot compile it away silently.

#![cfg(all(
    feature = "tls",
    feature = "quic",
    feature = "test-internals",
    target_os = "linux"
))]
#![allow(missing_docs)]

use std::io::BufReader;
use std::time::{Duration, Instant};

use asupersync::cx::Cx;
use asupersync::net::quic_core::{ConnectionId, TransportParameters};
use asupersync::net::quic_native::handshake_driver::{
    QuicHandshakeDriver, client_config, server_config,
};
use asupersync::net::quic_native::{
    NativeQuicConnectionConfig, NativeQuicUdpConnection, NativeQuicUdpConnectionError,
    NativeQuicUdpIoProgress, QuicUdpEndpoint, QuicUdpEndpointConfig,
};
use futures_lite::future::{block_on, zip};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};

const ALPN: &[u8] = b"hq-29";

/// The receive window the reporter drove with.
const IDLE_DRIVE_STEP: Duration = Duration::from_millis(500);
/// Each idle window covers a little more than one drive step so it observes at
/// least one full bounded wait; two windows keep the wall budget under ~3 s.
const IDLE_WINDOW: Duration = Duration::from_millis(800);
/// Generous bound: a parked wait costs ~0 %, the defect costs ~100 %. The slack
/// absorbs shared-worker noise; the measurement is repeated and the minimum is
/// asserted so one noisy window cannot fail a fixed build.
const MAX_IDLE_CPU_PERCENT: u64 = 15;
/// `/proc/self/stat` utime/stime are reported in `USER_HZ` ticks, which Linux
/// fixes at 100 for the procfs ABI independent of the kernel's `CONFIG_HZ`.
const USER_HZ: u64 = 100;

// The CPU sample is process-wide. Native handshakes in sibling tests must not
// overlap that sample; the CPU threshold and idle-window oracle stay intact.
static NATIVE_IDLE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// Canonical test CA + leaf chain shared with `tests/quic_h3_live_udp.rs`. The
// leaf has SAN DNS:localhost and the serverAuth EKU; the client trusts only
// this CA, so the handshake crosses WebPKI's real verifier.
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

fn parse_one_cert(pem: &str) -> CertificateDer<'static> {
    CertificateDer::pem_reader_iter(&mut BufReader::new(pem.as_bytes()))
        .next()
        .expect("one certificate")
        .expect("valid certificate PEM")
}

fn leaf_key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::pem_reader_iter(&mut BufReader::new(LEAF_KEY_PEM.as_bytes()))
        .next()
        .transpose()
        .expect("read private key PEM")
        .expect("one private key")
}

fn connection_config() -> NativeQuicConnectionConfig {
    NativeQuicConnectionConfig {
        max_local_bidi: 16,
        max_local_uni: 8,
        send_window: 1 << 18,
        recv_window: 1 << 18,
        connection_send_limit: 4 << 20,
        connection_recv_limit: 4 << 20,
        ..NativeQuicConnectionConfig::default()
    }
}

fn transport_parameters(config: NativeQuicConnectionConfig, idle_millis: Option<u64>) -> Vec<u8> {
    let parameters = TransportParameters {
        max_idle_timeout: idle_millis,
        max_udp_payload_size: Some(1_200),
        initial_max_data: Some(config.connection_recv_limit),
        initial_max_stream_data_bidi_local: Some(config.recv_window),
        initial_max_stream_data_bidi_remote: Some(config.recv_window),
        initial_max_stream_data_uni: Some(config.recv_window),
        initial_max_streams_bidi: Some(config.max_local_bidi),
        initial_max_streams_uni: Some(config.max_local_uni),
        disable_active_migration: true,
        max_datagram_frame_size: Some(config.max_datagram_frame_size as u64),
        ..TransportParameters::default()
    };
    let mut encoded = Vec::new();
    parameters
        .encode(&mut encoded)
        .expect("encode RFC 9000 transport parameters");
    encoded
}

/// Two loopback UDP endpoints joined by a real TLS 1.3 / QUIC handshake, driven
/// exactly the way the in-tree live-UDP tests drive them.
async fn live_pair(
    cx: &Cx,
) -> (
    Result<NativeQuicUdpConnection, NativeQuicUdpConnectionError>,
    Result<NativeQuicUdpConnection, NativeQuicUdpConnectionError>,
) {
    live_pair_with_idle(cx, None, None).await
}

async fn live_pair_with_idle(
    cx: &Cx,
    client_idle_millis: Option<u64>,
    server_idle_millis: Option<u64>,
) -> (
    Result<NativeQuicUdpConnection, NativeQuicUdpConnectionError>,
    Result<NativeQuicUdpConnection, NativeQuicUdpConnectionError>,
) {
    let udp_config = QuicUdpEndpointConfig {
        max_packet_size: 16_384,
        ..QuicUdpEndpointConfig::default()
    };
    let client_endpoint = QuicUdpEndpoint::bind(
        cx,
        "127.0.0.1:0".parse().expect("client bind address"),
        udp_config.clone(),
    )
    .await
    .expect("bind client UDP endpoint");
    let server_endpoint = QuicUdpEndpoint::bind(
        cx,
        "127.0.0.1:0".parse().expect("server bind address"),
        udp_config,
    )
    .await
    .expect("bind server UDP endpoint");
    let server_addr = server_endpoint.local_addr();

    let protocols = vec![ALPN.to_vec()];
    let client_tls = client_config(vec![parse_one_cert(CA_CERT_PEM)], protocols.clone())
        .expect("client TLS config");
    let server_tls = server_config(vec![parse_one_cert(LEAF_CERT_PEM)], leaf_key(), protocols)
        .expect("server TLS config");
    let client_connection_config = connection_config();
    let server_connection_config = connection_config();
    let client_driver = QuicHandshakeDriver::client(
        client_tls,
        ServerName::try_from("localhost").expect("server name"),
        transport_parameters(client_connection_config, client_idle_millis),
    )
    .expect("client handshake driver");
    let server_driver = QuicHandshakeDriver::server(
        server_tls,
        transport_parameters(server_connection_config, server_idle_millis),
    )
    .expect("server handshake driver");

    let initial_dcid =
        ConnectionId::new(b"idle-in1").expect("valid initial destination connection ID");
    let client_cid = ConnectionId::new(b"idle-cl1").expect("valid client source connection ID");
    let server_cid = ConnectionId::new(b"idle-sv1").expect("valid server source connection ID");

    zip(
        NativeQuicUdpConnection::connect(
            cx,
            client_endpoint,
            server_addr,
            client_driver,
            initial_dcid,
            client_cid,
            client_connection_config,
            ALPN,
        ),
        NativeQuicUdpConnection::accept(
            cx,
            server_endpoint,
            server_driver,
            initial_dcid,
            server_cid,
            server_connection_config,
            ALPN,
        ),
    )
    .await
}

/// Process CPU time in `USER_HZ` ticks: field 14 (`utime`) + field 15
/// (`stime`) of `/proc/self/stat`, indexed after the `)` that terminates the
/// command name so a space in the name cannot shift the fields.
fn process_cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").expect("read /proc/self/stat");
    let close = stat.rfind(')').expect("process stat comm terminator");
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    let user: u64 = fields[11].parse().expect("process utime ticks");
    let system: u64 = fields[12].parse().expect("process stime ticks");
    user + system
}

#[derive(Debug, Clone, Copy)]
struct IdleOutcome {
    wall_ms: u64,
    cpu_ms: u64,
    cpu_fraction_percent: u64,
    wakeups: u32,
}

fn is_quiet(progress: NativeQuicUdpIoProgress) -> bool {
    progress.receive_timed_out
        && progress.packets_received == 0
        && progress.packets_sent == 0
        && progress.early_packets_replayed == 0
        && progress.handshake_flights_retransmitted == 0
}

/// Drive both sides with short windows until neither has anything left to
/// send or acknowledge, so the idle window that follows has nothing in flight
/// and no nearer PTO deadline than the requested receive window.
async fn settle(
    cx: &Cx,
    client: &mut NativeQuicUdpConnection,
    server: &mut NativeQuicUdpConnection,
) {
    const SETTLE_STEP: Duration = Duration::from_millis(25);
    let mut quiet_rounds = 0;
    for round in 0..60 {
        let client_progress = client
            .drive_io_once(cx, SETTLE_STEP)
            .await
            .expect("client settle drive");
        let server_progress = server
            .drive_io_once(cx, SETTLE_STEP)
            .await
            .expect("server settle drive");
        if is_quiet(client_progress) && is_quiet(server_progress) {
            quiet_rounds += 1;
            if quiet_rounds >= 2 {
                return;
            }
        } else {
            quiet_rounds = 0;
        }
        assert!(
            round < 59,
            "connection never went quiet: client={client_progress:?} server={server_progress:?}"
        );
    }
}

/// Loop `drive_io_once(cx, 500ms)` on `connection` for at least `window` of
/// wall time with the peer silent, accounting process CPU across the window.
async fn measure_idle_window(
    cx: &Cx,
    connection: &mut NativeQuicUdpConnection,
    window: Duration,
) -> IdleOutcome {
    let ticks_before = process_cpu_ticks();
    let started = Instant::now();
    let mut wakeups = 0u32;
    while started.elapsed() < window {
        let progress = connection
            .drive_io_once(cx, IDLE_DRIVE_STEP)
            .await
            .expect("idle drive_io_once");
        wakeups += 1;
        assert!(
            progress.receive_timed_out && progress.packets_received == 0,
            "peer was supposed to be silent during the idle window: {progress:?}"
        );
    }
    let wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let ticks = process_cpu_ticks().saturating_sub(ticks_before);
    let cpu_ms = ticks.saturating_mul(1000) / USER_HZ;
    IdleOutcome {
        wall_ms,
        cpu_ms,
        cpu_fraction_percent: cpu_ms.saturating_mul(100) / wall_ms.max(1),
        wakeups,
    }
}

/// Serialize sibling tests so their native handshakes cannot pollute the
/// process-wide CPU accounting.
#[test]
fn idle_connection_with_silent_peer_parks_instead_of_spinning() {
    let _serial = NATIVE_IDLE_TEST_LOCK.lock().unwrap();
    block_on(async {
        let cx = Cx::for_testing();
        let (client, server) = live_pair(&cx).await;
        let mut client = client.expect("authenticated client live handle");
        let mut server = server.expect("authenticated server live handle");
        assert_eq!(client.peer_addr(), server.local_addr());
        assert_eq!(server.peer_addr(), client.local_addr());

        settle(&cx, &mut client, &mut server).await;

        // The server is never driven again: it is the silent peer. Only the
        // client loops its bounded receive wait.
        let probe_before = asupersync::net::fallback_io_driver_probe()
            .expect("driverless polls during the handshake started the fallback I/O driver");
        let first = measure_idle_window(&cx, &mut client, IDLE_WINDOW).await;
        let second = measure_idle_window(&cx, &mut client, IDLE_WINDOW).await;
        let probe_after = asupersync::net::fallback_io_driver_probe().expect("probe after idle");

        // A parked wait wakes once per bounded window (plus the window's own
        // remainder); a polling loop that stays under the CPU threshold by
        // sleeping in tiny slices would still show hundreds of wakeups here.
        let max_wakeups = u32::try_from(IDLE_WINDOW.as_millis() / IDLE_DRIVE_STEP.as_millis())
            .expect("window/step ratio fits u32")
            + 2;
        for (label, outcome) in [("first", first), ("second", second)] {
            assert!(
                outcome.wakeups <= max_wakeups,
                "{label} idle window woke {} times; a parked wait wakes at most {max_wakeups}: {outcome:?}",
                outcome.wakeups
            );
        }
        // The socket really parked on the fallback driver: it was re-armed
        // during the idle windows and never took the legacy self-wake path.
        assert!(
            probe_after.fallback_rearms > probe_before.fallback_rearms,
            "idle windows must re-arm the fallback registration: before={probe_before:?} after={probe_after:?}"
        );
        assert_eq!(
            probe_after.fallback_self_wakes, probe_before.fallback_self_wakes,
            "no legacy self-wake may occur while idle: before={probe_before:?} after={probe_after:?}"
        );
        let best = if second.cpu_fraction_percent < first.cpu_fraction_percent {
            second
        } else {
            first
        };
        eprintln!("GH#67 idle windows: first={first:?} second={second:?}");

        assert!(
            first.wakeups >= 1 && second.wakeups >= 1,
            "each idle window must observe at least one bounded wait: first={first:?} second={second:?}"
        );
        assert!(
            best.cpu_fraction_percent < MAX_IDLE_CPU_PERCENT,
            "idle drive_io_once loop burned CPU instead of parking (GH#67): \
             best window spent {} ms on-CPU over {} ms of wall time across {} wakeups \
             ({}% on-CPU; first={first:?}, second={second:?}); \
             expected < {MAX_IDLE_CPU_PERCENT}% of wall time on-CPU",
            best.cpu_ms,
            best.wall_ms,
            best.wakeups,
            best.cpu_fraction_percent
        );
        drop(server);
    });
}

#[test]
fn negotiated_idle_expiry_wakes_the_native_udp_owner_and_stops_output() {
    use asupersync::net::quic_native::QuicConnectionState;
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    let _serial = NATIVE_IDLE_TEST_LOCK.lock().unwrap();
    for workers in [1, 2] {
        let builder = if workers == 1 {
            asupersync::runtime::RuntimeBuilder::current_thread()
        } else {
            asupersync::runtime::RuntimeBuilder::multi_thread().worker_threads(workers)
        };
        let runtime = builder
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().expect("native root context");
            let (client, server) = live_pair_with_idle(&cx, Some(9_000), Some(2_000)).await;
            let mut client = client.expect("authenticated idle client");
            let mut server = server.expect("authenticated idle peer");
            settle(&cx, &mut client, &mut server).await;
            assert_eq!(client.connection().state(), QuicConnectionState::Established);
            assert_eq!(server.connection().state(), QuicConnectionState::Established);
            let started = Instant::now();
            let mut parked_polls = 0;
            let mut turns = 0;
            asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
                // The real peer keeps its bound socket but stops driving I/O.
                // A 60-second caller wait must wake at the shorter negotiated
                // deadline. The old driver never consulted that deadline.
                while client.connection().state() == QuicConnectionState::Established {
                    turns += 1;
                    assert!(turns < 64, "idle owner must not spin through drive turns");
                    let mut drive = Box::pin(client.drive_io_once(&cx, Duration::from_secs(60)));
                    let progress = poll_fn(|task| {
                        let result = drive.as_mut().poll(task);
                        if matches!(result, Poll::Pending) {
                            parked_polls += 1;
                        }
                        result
                    })
                    .await
                    .expect("native idle drive");
                    assert_eq!(progress.packets_received, 0, "peer remains silent");
                }
            })
            .await
            .expect("negotiated idle expiry must beat the caller's receive bound");
            assert!(parked_polls > 0, "real parked UDP receive witness");
            assert_eq!(client.connection().state(), QuicConnectionState::Closed);
            assert!(!client.connection().can_send_app_data());
            assert_eq!(client.connection().inner().transport().close_code(), Some(0));
            assert!(!client.connection().close_was_peer_initiated());
            assert_eq!(client.flush(&cx).await.unwrap(), 0);
            assert!(client.connection_mut().open_bidi_stream(&cx).is_err());
            assert_eq!(server.connection().state(), QuicConnectionState::Established);
            eprintln!("bead=asupersync-bi2462.108 scenario=standalone_idle_expiry workers={workers} parked_polls={parked_polls} turns={turns} elapsed_ms={} terminal=Closed close_code=0", started.elapsed().as_millis());
            drop(client);
            drop(server);
            assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
        });
        assert!(
            runtime.is_quiescent(),
            "native idle test leaves no tasks or obligations"
        );
    }
}

#[test]
fn cancelling_a_native_idle_wait_preserves_the_owner_for_explicit_cleanup() {
    use asupersync::net::quic_native::QuicConnectionState;
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    let _serial = NATIVE_IDLE_TEST_LOCK.lock().unwrap();
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().expect("native root context");
        let region = cx
            .open_child_region(asupersync::cx::ChildRegionSpec::inherit())
            .await
            .unwrap();
        let owner = region.cx().clone();
        let (client, server) = live_pair_with_idle(&owner, Some(30_000), None).await;
        let mut client = client.unwrap();
        let mut server = server.unwrap();
        settle(&owner, &mut client, &mut server).await;
        let (parked_tx, parked_rx) = std::sync::mpsc::sync_channel(1);
        let cancel_owner = owner.clone();
        let canceller = std::thread::spawn(move || {
            parked_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("parked native receive");
            cancel_owner.set_cancel_requested(true);
        });
        let mut notified = false;
        let result = {
            let mut drive = Box::pin(client.drive_io_once(&owner, Duration::from_secs(60)));
            asupersync::time::timeout(
                cx.now(),
                Duration::from_secs(5),
                poll_fn(|task| {
                    let result = drive.as_mut().poll(task);
                    if matches!(result, Poll::Pending) && !notified {
                        parked_tx.send(()).unwrap();
                        notified = true;
                    }
                    result
                }),
            )
            .await
            .expect("cancellation must wake the parked native receive")
        };
        canceller.join().unwrap();
        assert!(notified, "parked receive precedes cancellation");
        assert!(
            matches!(result, Err(NativeQuicUdpConnectionError::Cancelled)),
            "exact cancellation result: {result:?}"
        );
        assert_eq!(client.connection().state(), QuicConnectionState::Established);
        assert!(client.close(&cx, 7).await.unwrap() > 0);
        let observed = server
            .drive_io_once(&cx, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(observed.packets_received > 0);
        assert_eq!(server.connection().state(), QuicConnectionState::Draining);
        assert_eq!(server.connection().inner().transport().close_code(), Some(7));
        assert!(server.connection().close_was_peer_initiated());
        drop(client);
        drop(server);
        region.close().await.unwrap();
        assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
        eprintln!("bead=asupersync-bi2462.108 scenario=standalone_idle_cancel parked=true result=Cancelled cleanup=region_closed");
    });
    assert!(
        runtime.is_quiescent(),
        "native cancellation leaves no tasks or obligations"
    );
}
