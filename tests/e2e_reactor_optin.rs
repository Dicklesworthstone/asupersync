//! Burn-in smoke for the default platform reactor
//! (br-asupersync-1ajbtl).
//!
//! Default-built runtimes now construct the platform backend (epoll on Linux)
//! and attach the `IoDriver`, so socket readiness drives wakeups instead of
//! 1ms fallback wheel-timer re-polls. These tests exercise that full-builder
//! default reactor path with real TCP traffic:
//!   - `platform_reactor_serves_tcp_round_trip`: connect, write, delayed
//!     echo read, EOF-clean close.
//!   - `platform_reactor_read_with_far_timeout_completes_promptly`: the
//!     rr849p regression shape under the reactor regime — a generous
//!     `timeout()` around a read completes when data arrives, not when the
//!     far timer fires.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;

/// Std-thread echo server: accepts one connection, reads `len` bytes,
/// echoes them back after `delay` (so the client read genuinely waits on
/// readiness), then closes.
fn delayed_echo_server(len: usize, delay: Duration) -> (SocketAddr, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind echo server");
    let addr = listener.local_addr().expect("echo server addr");
    let join = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        conn.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("set server read timeout");
        let mut buf = vec![0u8; len];
        conn.read_exact(&mut buf).expect("server read");
        std::thread::sleep(delay);
        conn.write_all(&buf).expect("server write");
    });
    (addr, join)
}

#[test]
fn platform_reactor_serves_tcp_round_trip() {
    const PAYLOAD: &[u8] = b"reactor-burn-in";

    let (addr, server) = delayed_echo_server(PAYLOAD.len(), Duration::from_millis(200));

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime with platform reactor");
    let echoed = runtime.block_on(runtime.handle().spawn(async move {
        let mut stream = TcpStream::connect(addr).await.expect("client connect");
        stream.write_all(PAYLOAD).await.expect("client write");
        let mut buf = vec![0u8; PAYLOAD.len()];
        stream.read_exact(&mut buf).await.expect("client read");
        buf
    }));
    assert_eq!(
        echoed, PAYLOAD,
        "reactor-driven round trip must deliver the payload intact"
    );
    server.join().expect("echo server thread");
}

#[test]
fn platform_reactor_read_with_far_timeout_completes_promptly() {
    const PAYLOAD: &[u8] = b"prompt";

    let (addr, server) = delayed_echo_server(PAYLOAD.len(), Duration::from_millis(100));

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime with platform reactor");
    let started = std::time::Instant::now();
    let echoed = runtime.block_on(runtime.handle().spawn(async move {
        let mut stream = TcpStream::connect(addr).await.expect("client connect");
        stream.write_all(PAYLOAD).await.expect("client write");
        let mut buf = vec![0u8; PAYLOAD.len()];
        asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_secs(30),
            stream.read_exact(&mut buf),
        )
        .await
        .expect("read completes inside the generous timeout")
        .expect("client read");
        buf
    }));
    let elapsed = started.elapsed();
    assert_eq!(echoed, PAYLOAD);
    // The echo arrives ~100ms in; anything close to the 30s deadline means
    // readiness was lost and the timer fired instead (rr849p shape).
    assert!(
        elapsed < Duration::from_secs(10),
        "read must complete on data arrival, not at the far deadline (elapsed {elapsed:?})"
    );
    server.join().expect("echo server thread");
}
