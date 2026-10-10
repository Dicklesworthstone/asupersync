//! GH #73: Linux-only UDP launch-time sends (`SO_TXTIME` / `SCM_TXTIME`) and
//! error-queue reads (`MSG_ERRQUEUE`), without privileges.
//!
//! Loopback uses the `noqueue` discipline, so launch times are not enforced
//! here: these tests cover the plumbing (option, control message, error
//! queue, reactor readiness), not the timing.
#![cfg(target_os = "linux")]
#![allow(missing_docs, clippy::pedantic, clippy::nursery)]

use asupersync::net::{UdpErrorOrigin, UdpSocket, UdpTxTimeClock, UdpTxTimeConfig};
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{timeout, wall_now};
use futures_lite::future;
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(10);

/// Runs `test` as a task on a runtime, so sockets register with its ambient
/// reactor.
fn on_runtime<F>(test: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build runtime");
    runtime.block_on(runtime.handle().spawn(test));
}

/// A loopback address nothing listens on (bound, then released).
fn closed_port(ip: &str) -> SocketAddr {
    let probe = std::net::UdpSocket::bind((ip, 0)).expect("reserve a port");
    probe.local_addr().expect("reserved address")
}

/// Aborts the test process if `fut` has not finished within the wait (the
/// fallback-driver path has no runtime timer to bound it).
async fn with_watchdog<F: std::future::Future>(fut: F) -> F::Output {
    let (done, finished) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        if finished.recv_timeout(WAIT) == Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
            eprintln!("watchdog: operation did not finish within {WAIT:?}");
            std::process::abort();
        }
    });
    let output = fut.await;
    drop(done);
    output
}

async fn recv_within(socket: &mut UdpSocket, buf: &mut [u8]) -> (usize, SocketAddr) {
    timeout(wall_now(), WAIT, socket.recv_from(buf))
        .await
        .expect("datagram within the wait")
        .expect("recv_from")
}

#[test]
fn launch_time_send_delivers_and_plain_sends_are_refused() {
    on_runtime(async {
        let mut rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let mut tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx_addr = tx.local_addr().unwrap();

        // Without SO_TXTIME a launch-time send is refused up front.
        let err = tx
            .send_to_with_txtime(b"early", rx_addr, 1)
            .await
            .expect_err("launch-time send before set_txtime");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(tx.txtime(), None);

        let config = UdpTxTimeConfig::new(UdpTxTimeClock::Monotonic).with_report_errors(true);
        tx.set_txtime(config)
            .expect("SO_TXTIME with CLOCK_MONOTONIC needs no privileges");
        assert_eq!(tx.txtime(), Some(config));

        let launch = UdpTxTimeClock::Monotonic.now_ns().unwrap() + 1_000_000;
        let payload = b"launch-time datagram";
        let sent = tx
            .send_to_with_txtime(payload, rx_addr, launch)
            .await
            .unwrap();
        assert_eq!(sent, payload.len());
        let mut buf = [0_u8; 64];
        let (n, from) = recv_within(&mut rx, &mut buf).await;
        assert_eq!(&buf[..n], payload);
        assert_eq!(from, tx_addr);

        // Every plain send path is refused now: ETF would drop the datagram.
        let refused = |r: io::Result<usize>| {
            let err = r.expect_err("plain send after SO_TXTIME");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        };
        refused(tx.send_to(b"plain", rx_addr).await);
        let batch = tx
            .send_batch_to(&[asupersync::net::UdpOutboundDatagram {
                payload: b"plain batch",
                dst_addr: rx_addr,
            }])
            .await;
        assert_eq!(
            batch.expect_err("plain batch after SO_TXTIME").kind(),
            io::ErrorKind::InvalidInput
        );

        // A clone made afterwards shares the socket and inherits the refusal.
        let mut clone = tx.try_clone().unwrap();
        assert_eq!(clone.txtime(), Some(config));
        refused(clone.send_to(b"plain clone", rx_addr).await);

        // Connected form.
        tx.connect(rx_addr).await.unwrap();
        refused(tx.send(b"plain connected").await);
        let launch = UdpTxTimeClock::Monotonic.now_ns().unwrap() + 1_000_000;
        let sent = tx
            .send_with_txtime(b"connected launch", launch)
            .await
            .unwrap();
        assert_eq!(sent, 16);
        let (n, _) = recv_within(&mut rx, &mut buf).await;
        assert_eq!(&buf[..n], b"connected launch");

        // Nothing but the two launch-time datagrams arrived.
        let mut probe = [0_u8; 8];
        let extra = timeout(
            wall_now(),
            Duration::from_millis(100),
            rx.recv_from(&mut probe),
        )
        .await;
        assert!(
            extra.is_err(),
            "a refused plain send leaked a datagram: {extra:?}"
        );
    });
}

#[test]
fn txtime_on_a_privileged_clock_needs_cap_net_admin() {
    future::block_on(async {
        if nix::unistd::Uid::effective().is_root() {
            eprintln!("not exercised: running as root with CAP_NET_ADMIN");
            return;
        }
        let mut socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = UdpTxTimeConfig::new(UdpTxTimeClock::Tai).with_report_errors(true);
        match socket.set_txtime(config) {
            // Offloaded test runs can have CAP_NET_ADMIN even when not root.
            Ok(()) => {
                eprintln!("not exercised: process has CAP_NET_ADMIN privilege");
            }
            Err(err) => {
                assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
                // A failed set leaves the socket usable for plain sends.
                assert_eq!(socket.txtime(), None);
                let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                socket
                    .send_to(b"still plain", peer.local_addr().unwrap())
                    .await
                    .unwrap();
            }
        }
    });
}

/// Sends to a closed port from a clone while `recv_error` is already parked
/// on `Interest::ERROR`, and checks the ICMP report that wakes it.
async fn icmp_report_wakes_parked_recv_error(ip: &'static str, expected_origin: UdpErrorOrigin) {
    let mut socket = UdpSocket::bind((ip, 0)).await.unwrap();
    socket.set_recverr(true).unwrap();
    let local = socket.local_addr().unwrap();
    let dead = closed_port(ip);
    let mut sender = socket.try_clone().unwrap();

    let mut empty = [0_u8; 32];
    assert!(
        socket.try_recv_error(&mut empty).unwrap().is_none(),
        "fresh socket has an empty error queue"
    );

    let mut payload_buf = [0_u8; 64];
    let (report, delayed_join) = {
        let mut pending = pin!(socket.recv_error(&mut payload_buf));
        assert!(
            future::poll_once(pending.as_mut()).await.is_none(),
            "recv_error must wait while the error queue is empty"
        );
        let delayed_send = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            future::block_on(async {
                let sent = sender.send_to(b"to a closed port", dead).await.unwrap();
                assert_eq!(sent, 16);
            });
        });
        let rep = timeout(wall_now(), WAIT, pending)
            .await
            .expect("the ICMP report must wake the parked recv_error")
            .expect("recv_error");
        (rep, delayed_send)
    };
    delayed_join.join().expect("delayed sender thread joined");

    assert_eq!(report.origin, expected_origin);
    assert_eq!(report.errno, libc::ECONNREFUSED);
    assert_eq!(report.error().kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(report.destination, Some(dead));
    assert_eq!(report.offender.map(|a| a.ip()), Some(local.ip()));
    assert_eq!(&payload_buf[..report.len], b"to a closed port");
    assert!(!report.truncated);
    assert_eq!(report.txtime_error(), None);

    // Drained: the queue is empty again and ordinary receives still work
    // with the same registration.
    assert!(socket.try_recv_error(&mut empty).unwrap().is_none());
    let peer = std::net::UdpSocket::bind((ip, 0)).unwrap();
    peer.send_to(b"after the report", local).unwrap();
    let mut buf = [0_u8; 32];
    let (n, from) = recv_within(&mut socket, &mut buf).await;
    assert_eq!(&buf[..n], b"after the report");
    assert_eq!(from, peer.local_addr().unwrap());
}

#[test]
fn icmp_port_unreachable_reaches_recv_error_on_runtime_reactor() {
    on_runtime(icmp_report_wakes_parked_recv_error(
        "127.0.0.1",
        UdpErrorOrigin::Icmp,
    ));
}

/// A connected socket without `set_recverr` keeps an ICMP error in the
/// socket's error field, not in the error queue, and the kernel keeps raising
/// POLLERR for it. `recv_error` returns that pending error instead of
/// re-arming on it in a loop. Before, it spun until something else cleared it.
#[test]
fn recv_error_returns_a_pending_socket_error_instead_of_spinning() {
    on_runtime(async {
        let dead = closed_port("127.0.0.1");
        let mut socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        socket.connect(dead).await.unwrap();
        socket.send(b"to a closed port").await.unwrap();
        let mut buf = [0_u8; 32];
        let error = timeout(
            wall_now(),
            Duration::from_secs(2),
            socket.recv_error(&mut buf),
        )
        .await
        .expect("recv_error must not keep waiting on a raised POLLERR")
        .expect_err("no queued report, only the pending socket error");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert!(
            socket.try_recv_error(&mut buf).unwrap().is_none(),
            "nothing was queued"
        );
    });
}

/// br-asupersync-vs1vdk U1: with set_recverr on, recv_error read and
/// discarded a pending socket error, taking it for the shadow of a report it
/// had already delivered. But dequeuing a report clears that error, so with
/// the queue empty it is the only record: here the ICMP error arrived before
/// IP_RECVERR was set. It was lost and recv_error waited forever.
#[test]
fn recv_error_returns_a_socket_error_that_predates_set_recverr() {
    on_runtime(async {
        let dead = closed_port("127.0.0.1");
        let mut socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        socket.connect(dead).await.unwrap();
        socket.send(b"to a closed port").await.unwrap();
        // Loopback answers within the send; leave margin so the error is in
        // the socket's error field before IP_RECVERR is turned on.
        std::thread::sleep(Duration::from_millis(100));
        socket.set_recverr(true).unwrap();
        let mut buf = [0_u8; 32];
        let error = timeout(
            wall_now(),
            Duration::from_secs(2),
            socket.recv_error(&mut buf),
        )
        .await
        .expect("recv_error must return the pending error, not wait for another")
        .expect_err("no queued report, only the pending socket error");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    });
}

#[test]
fn icmpv6_port_unreachable_reaches_recv_error_on_runtime_reactor() {
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        eprintln!("skipping: no IPv6 loopback on this host");
        return;
    }
    on_runtime(icmp_report_wakes_parked_recv_error(
        "::1",
        UdpErrorOrigin::Icmp6,
    ));
}

#[test]
fn recv_error_truncates_payload_into_a_short_buffer_without_a_runtime() {
    // No runtime: readiness goes through the process-global fallback driver.
    future::block_on(async {
        let mut socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.set_recverr(true).unwrap();
        let dead = closed_port("127.0.0.1");
        let mut sender = socket.try_clone().unwrap();

        let mut short = [0_u8; 4];
        let (report, delayed_join) = {
            let mut pending = pin!(socket.recv_error(&mut short));
            assert!(
                future::poll_once(pending.as_mut()).await.is_none(),
                "recv_error must wait while the error queue is empty"
            );
            let delayed_send = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                future::block_on(async {
                    let sent = sender.send_to(b"0123456789", dead).await.unwrap();
                    assert_eq!(sent, 10);
                });
            });
            let rep = with_watchdog(pending).await.unwrap();
            (rep, delayed_send)
        };
        delayed_join.join().expect("delayed sender thread joined");

        assert_eq!(report.origin, UdpErrorOrigin::Icmp);
        assert_eq!(report.len, 4);
        assert!(report.truncated);
        assert_eq!(&short, b"0123");

        // The one pending error was consumed with the report, so the next
        // ordinary receive is not poisoned by it.
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.send_to(b"ok", socket.local_addr().unwrap()).unwrap();
        let mut buf = [0_u8; 8];
        let (n, _) = socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ok");
    });
}
