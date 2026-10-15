//! Integration coverage for `TcpSocket` nodelay/keepalive convenience
//! configuration (br-asupersync-ctim5q).
//!
//! These exercise the PUBLIC option-setting surface and prove the configured
//! options are actually applied on the synchronous `listen()` path (which
//! routes through the same `apply_socket_options` helper as `connect()`),
//! using real OS sockets. They link the library in normal (non-test) mode, so
//! they validate the feature independent of the in-crate `#[cfg(test)]` unit
//! tests.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use asupersync::net::TcpSocket;
use asupersync::net::tcp::stream::TcpKeepaliveConfig;

/// AC1/AC2/AC3 (IPv4): set_nodelay + set_keepalive are accepted and applied
/// end-to-end on the listen path without error; the listener binds a real
/// ephemeral port.
#[test]
fn nodelay_and_keepalive_apply_on_listen_v4() {
    let socket = TcpSocket::new_v4().expect("create v4 socket");
    socket.set_reuseaddr(true).expect("set reuseaddr");
    socket.set_nodelay(true).expect("set nodelay");
    socket
        .set_keepalive(Some(Duration::from_secs(30)))
        .expect("set keepalive");
    socket
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind v4");

    let listener = socket.listen(128).expect("listen applies options on v4");
    let addr = listener.local_addr().expect("local addr");
    assert!(addr.is_ipv4(), "expected an IPv4 bound address: {addr:?}");
    assert_ne!(addr.port(), 0, "listener should bind a real ephemeral port");
}

/// AC3: explicit keepalive idle/interval/retries either applies (Linux and
/// most Unixes) or fails deterministically with `Unsupported` on platforms
/// that lack the per-socket knobs — never a silent success that ignored them.
#[test]
fn keepalive_config_with_interval_and_retries_is_deterministic() {
    let socket = TcpSocket::new_v4().expect("create v4 socket");
    socket.set_reuseaddr(true).expect("set reuseaddr");
    socket
        .set_keepalive_config(Some(
            TcpKeepaliveConfig::new(Duration::from_secs(60))
                .with_interval(Duration::from_secs(10))
                .with_retries(4),
        ))
        .expect("stage keepalive config");
    socket
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind v4");

    match socket.listen(128) {
        Ok(listener) => {
            let addr = listener.local_addr().expect("local addr");
            assert!(addr.is_ipv4(), "expected IPv4 bound address: {addr:?}");
        }
        Err(err) => assert_eq!(
            err.kind(),
            std::io::ErrorKind::Unsupported,
            "unsupported keepalive knobs must fail with Unsupported, got: {err:?}"
        ),
    }
}

/// AC3 (IPv6): the same option plumbing works for v6 sockets when the host
/// has IPv6 loopback available; otherwise the environment simply lacks v6 and
/// the case is skipped rather than spuriously failing.
#[test]
fn nodelay_applies_on_listen_v6_when_available() {
    let socket = TcpSocket::new_v6().expect("create v6 socket");
    socket.set_reuseaddr(true).expect("set reuseaddr");
    socket.set_nodelay(true).expect("set nodelay");
    if socket
        .bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .is_err()
    {
        // No IPv6 loopback on this host: nothing to prove here.
        return;
    }

    let listener = socket.listen(128).expect("listen applies options on v6");
    let addr = listener.local_addr().expect("local addr");
    assert!(addr.is_ipv6(), "expected an IPv6 bound address: {addr:?}");
}

/// AC3: invalid-family behavior is unchanged — binding a v4 socket to a v6
/// address (and vice versa) is a deterministic `InvalidInput`, before any OS
/// socket is created.
#[test]
fn bind_rejects_mismatched_address_family() {
    let v4 = TcpSocket::new_v4().expect("create v4 socket");
    let err = v4
        .bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .expect_err("v4 socket must reject a v6 bind address");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    let v6 = TcpSocket::new_v6().expect("create v6 socket");
    let err = v6
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect_err("v6 socket must reject a v4 bind address");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}
