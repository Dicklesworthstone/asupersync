//! Capability-gated default-client conformance for the `HttpClient` facade —
//! br-asupersync-server-stack-hardening-eeexl1.4, AC6: "No ambient global:
//! compile-fail/doc proof that client access flows through Cx capability."
//!
//! The compile-fail half of AC6 lives as a `compile_fail` doctest on
//! `src/http/client.rs` (a `Cx<NoCaps>` cannot name `default_for_runtime`).
//! These integration tests pin the *positive* runtime half through the public
//! [`Client::default_for_runtime`] accessor:
//!
//! - it yields a working, pooled client when handed a `Cx` that carries I/O
//!   authority (a real loopback GET round-trips byte-for-byte);
//! - the returned value is a cheap-clone handle over a shared pool — cloning it
//!   shares the same idle connection rather than dialing again (this is the
//!   "shared pool" the no-global design hangs on);
//! - obtaining the default client never reaches the network ambiently: a fresh
//!   handle has dialed nothing, repeated accessor calls against the same `Cx`
//!   share the runtime-owned lazy slot, and separate runtime contexts do not
//!   leak through a process-global singleton.
//!
//! Standalone crate (mirrors the sibling `http_client_*` conformance tests).
//! Requires `--features test-internals` for `Cx::for_testing()`.

use asupersync::Cx;
use asupersync::http::Client;
use asupersync::runtime::RuntimeBuilder;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Drive an async body on a lightweight current-thread runtime.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime")
        .block_on(fut)
}

/// Accept one connection from a non-blocking listener, polling until `timeout`.
fn accept_with_timeout(listener: &TcpListener, timeout: Duration) -> std::io::Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((conn, _peer)) => return Ok(conn),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "accept timed out",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) => return Err(err),
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read a request head up to and including the terminating `\r\n\r\n`.
fn read_request_head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    let mut scratch = [0u8; 512];
    loop {
        if find_subslice(&buf, b"\r\n\r\n").is_some() {
            return Ok(buf);
        }
        let n = stream.read(&mut scratch)?;
        if n == 0 {
            return Ok(buf);
        }
        buf.extend_from_slice(&scratch[..n]);
    }
}

/// Block until the peer sends a second request, closes, or the timeout elapses.
/// Used only to keep the connection open so the client can return it to the
/// idle pool; the returned value is intentionally ignored.
fn drain_until_idle_or_close(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut scratch = [0u8; 512];
    loop {
        match stream.read(&mut scratch) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Ok(());
            }
            Err(err) => return Err(err),
        }
    }
}

fn request_method(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Write a fixed-length keep-alive `200 OK` carrying `body`.
fn write_keepalive_ok(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

/// Serve exactly one keep-alive GET, then keep the connection open (so the
/// client can return it to the idle pool) until the client closes or times out.
fn spawn_keepalive_once(body: &'static [u8]) -> (SocketAddr, JoinHandle<std::io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");
    let addr = listener.local_addr().expect("listener local_addr");

    let handle = thread::spawn(move || -> std::io::Result<()> {
        let mut conn = accept_with_timeout(&listener, IO_TIMEOUT)?;
        conn.set_nonblocking(false)?;
        conn.set_read_timeout(Some(IO_TIMEOUT))?;
        conn.set_write_timeout(Some(IO_TIMEOUT))?;
        let head = read_request_head(&mut conn)?;
        assert_eq!(request_method(&head), "GET");
        write_keepalive_ok(&mut conn, body)?;
        drain_until_idle_or_close(&mut conn)
    });

    (addr, handle)
}

/// AC6 (positive): the capability-gated accessor returns a usable, pooled
/// client when handed a `Cx` carrying I/O authority.
#[test]
fn default_for_runtime_yields_a_working_pooled_client() {
    let (addr, server) = spawn_keepalive_once(b"DEFAULT-OK");

    block_on(async move {
        let cx = Cx::for_testing();
        // The accessor demands `Caps: HasIo`; `Cx::for_testing()` is `Cx<All>`.
        let client: Client = Client::default_for_runtime(&cx);

        // Obtaining the default client dials nothing — no ambient network reach.
        let fresh = client.pool_stats();
        assert_eq!(
            fresh.connections_created, 0,
            "fresh default client has not dialed"
        );
        assert_eq!(fresh.total_connections, 0);

        let url = format!("http://{addr}/");
        let resp = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("default client should complete the request");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"DEFAULT-OK");
    });

    server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
}

/// AC6 (shared pool): the returned value is a cheap-clone handle over a shared
/// pool — cloning shares the same idle connection without dialing again.
#[test]
fn default_client_is_a_cheap_clone_over_a_shared_pool() {
    let (addr, server) = spawn_keepalive_once(b"POOLED");

    block_on(async move {
        let cx = Cx::for_testing();
        let client = Client::default_for_runtime(&cx);
        let url = format!("http://{addr}/");

        let resp = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("request should succeed");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"POOLED");

        // A fully-consumed keep-alive response returns its connection to idle.
        let stats = client.pool_stats();
        assert_eq!(
            stats.idle_connections, 1,
            "keep-alive connection returned to the idle pool"
        );
        assert_eq!(stats.total_connections, 1);

        // Cloning the handle is a refcount bump that shares the SAME pool: the
        // clone observes the idle connection without any new dial.
        let clone = client.clone();
        let clone_stats = clone.pool_stats();
        assert_eq!(
            clone_stats.idle_connections, 1,
            "clone shares the originating client's pool"
        );
        assert_eq!(clone_stats.total_connections, 1);
        assert_eq!(
            clone_stats.connections_created, stats.connections_created,
            "cloning must not dial a connection"
        );
    });

    server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
}

/// br-asupersync-8z4uq3: repeated accessor calls against the same `Cx` share
/// the runtime-owned lazy default-client slot rather than allocating unrelated
/// pools.
#[test]
fn repeated_accessors_share_the_runtime_default_pool() {
    let (addr, server) = spawn_keepalive_once(b"RUNTIME-SLOT");

    block_on(async move {
        let cx = Cx::for_testing();
        let first = Client::default_for_runtime(&cx);

        let fresh = first.pool_stats();
        assert_eq!(fresh.total_connections, 0);
        assert_eq!(fresh.connections_created, 0);

        let url = format!("http://{addr}/");
        let resp = first
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("request through runtime default client should succeed");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"RUNTIME-SLOT");

        let first_after = first.pool_stats();
        assert_eq!(
            first_after.idle_connections, 1,
            "first accessor returns the keep-alive connection to the runtime pool"
        );
        assert_eq!(first_after.total_connections, 1);

        let second = Client::default_for_runtime(&cx);
        let second_after = second.pool_stats();
        assert_eq!(
            second_after.idle_connections, 1,
            "second accessor observes the same runtime-owned idle pool"
        );
        assert_eq!(second_after.total_connections, 1);
        assert_eq!(
            second_after.connections_created, first_after.connections_created,
            "re-calling the accessor must not allocate or dial a fresh pool"
        );
    });

    server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
}

/// AC6 (no hidden global): separate root contexts have separate lazy slots, so
/// the runtime-owned default never degenerates into a process-wide singleton.
#[test]
fn separate_runtime_contexts_do_not_share_default_client_slot() {
    let (addr, server) = spawn_keepalive_once(b"CONTEXT-A");

    block_on(async move {
        let first_cx = Cx::for_testing();
        let second_cx = Cx::for_testing();
        let first = Client::default_for_runtime(&first_cx);
        let second = Client::default_for_runtime(&second_cx);

        let url = format!("http://{addr}/");
        let resp = first
            .get(url.as_str())
            .send(&first_cx)
            .await
            .expect("request through first runtime default client should succeed");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"CONTEXT-A");

        assert_eq!(first.pool_stats().total_connections, 1);
        assert_eq!(
            second.pool_stats().total_connections,
            0,
            "a second root Cx must not observe the first root's default-client pool"
        );
        assert_eq!(second.pool_stats().connections_created, 0);
    });

    server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
}
