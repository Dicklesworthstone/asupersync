//! Behavioral coverage of the erased default-client slot (GH #86).
//! Real loopback HTTP, actual Cx inheritance, and concurrent first access.
//! Run with `--features behavior`, and again with `--features behavior,tls`.
#![forbid(unsafe_code)]

use asupersync::http::Client;
use asupersync::runtime::RuntimeBuilder;
use asupersync::{CancelKind, Cx};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const BOUND: Duration = Duration::from_secs(10);

/// A finite server that accepts both pooled and unpooled clients. Wrong pool
/// sharing must produce a connection-count failure, not a hung second dial.
struct Server {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<usize>>>,
}

impl Server {
    fn new(requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).expect("nonblocking accept");
        let addr = listener.local_addr().expect("listener address");
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let deadline = Instant::now() + BOUND;
            let mut peers: Vec<(TcpStream, Vec<u8>, bool)> = Vec::new();
            let mut completed = 0;
            while completed < requests {
                if stopped.load(Ordering::Acquire) {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "test stopped"));
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "missing requests"));
                }
                // Bound both accepted connections and work per loop.
                while peers.len() < requests {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false)?;
                            stream.set_read_timeout(Some(Duration::from_millis(2)))?;
                            stream.set_write_timeout(Some(Duration::from_secs(1)))?;
                            peers.push((stream, Vec::new(), false));
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    }
                }
                for (stream, buffered, closed) in &mut peers {
                    if *closed {
                        continue;
                    }
                    let mut scratch = [0_u8; 1024];
                    match stream.read(&mut scratch) {
                        Ok(0) => {
                            *closed = true;
                            continue;
                        }
                        Ok(n) => buffered.extend_from_slice(&scratch[..n]),
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) => continue,
                        Err(error) => return Err(error),
                    }
                    if buffered.len() > 16 * 1024 {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversized head"));
                    }
                    while let Some(end) = buffered.windows(4).position(|w| w == b"\r\n\r\n") {
                        if !buffered.starts_with(b"GET /slot HTTP/1.1\r\n") {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected request"));
                        }
                        buffered.drain(..end + 4);
                        completed += 1;
                        let body = format!("slot-{completed}");
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
                            body.len()
                        )?;
                        stream.flush()?;
                    }
                }
                thread::sleep(Duration::from_millis(1));
            }
            Ok(peers.len())
        });
        Self {
            addr,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://{}/slot", self.addr)
    }

    fn finish(mut self) -> usize {
        self.thread
            .take()
            .expect("server handle")
            .join()
            .expect("server panic")
            .expect("server I/O")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            // Also reap on assertion failure; do not panic during unwinding.
            let _ = thread.join();
        }
    }
}

async fn get(client: &Client, cx: &Cx, url: &str, sequence: usize) {
    let response = asupersync::time::timeout(
        asupersync::time::wall_now(),
        BOUND,
        client.get(url).send(cx),
    )
    .await
    .expect("bounded request")
    .expect("HTTP request");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, format!("slot-{sequence}").as_bytes());
}

/// The slot's existing Debug implementation reports OnceLock initialization.
/// Inspect only this field on unattached test contexts; do not snapshot the
/// runtime's recursive handles or add a public introspection API for a test.
fn assert_initialized(cx: &Cx, initialized: bool) {
    let marker = format!("default_http_client: DefaultHttpClientSlot {{ initialized: {initialized},");
    assert!(
        format!("{cx:?}").contains(&marker),
        "unexpected lazy-slot state"
    );
}

#[test]
fn cloning_a_context_does_not_initialize_its_http_client() {
    let cx = Cx::for_testing();
    let clone = cx.clone();
    let separate = Cx::for_testing();
    assert_initialized(&cx, false);
    assert_initialized(&clone, false);
    let client = Client::default_for_runtime(&clone);
    assert_initialized(&cx, true);
    assert_initialized(&clone, true);
    assert_initialized(&separate, false);
    assert_eq!(client.pool_stats().connections_created, 0);
    assert_eq!(client.pool_stats().total_connections, 0);
}

#[test]
fn concurrent_first_access_returns_one_shared_pool() {
    const CALLERS: usize = 4;
    let cx = Cx::for_testing();
    assert_initialized(&cx, false);
    let barrier = Arc::new(Barrier::new(CALLERS));
    let clients = thread::scope(|scope| {
        let handles: Vec<_> = (0..CALLERS)
            .map(|_| {
                let cx = cx.clone();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    Client::default_for_runtime(&cx)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("accessor thread"))
            .collect::<Vec<_>>()
    });
    assert_initialized(&cx, true);
    for client in &clients {
        assert_eq!(client.pool_stats().connections_created, 0);
    }
    let separate = Client::default_for_runtime(&Cx::for_testing());
    let server = Server::new(CALLERS);
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    runtime.block_on(async {
        for (index, client) in clients.iter().enumerate() {
            get(client, &cx, &server.url(), index + 1).await;
            for shared in &clients {
                assert_eq!(
                    shared.pool_stats().connections_created,
                    1,
                    "same pool after each request"
                );
            }
        }
    });
    assert_eq!(
        server.finish(),
        1,
        "all accessor results reuse one TCP connection"
    );
    assert_eq!(
        separate.pool_stats().connections_created,
        0,
        "not a global singleton"
    );
}

#[test]
fn spawned_and_ambient_contexts_inherit_the_same_default_pool() {
    for workers in [0, 2] {
        let builder = if workers == 0 {
            RuntimeBuilder::current_thread()
        } else {
            RuntimeBuilder::new().worker_threads(workers)
        };
        let runtime = builder.build().expect("runtime");
        let server = Server::new(3);
        let url = server.url();
        runtime.block_on(async {
            let parent = Cx::current().expect("runtime-owned parent context");
            let child_url = url.clone();
            // Spawn before the parent ever accesses the slot: InheritedHandles
            // must share the lazy cell, not copy an already-built client.
            let mut task = parent
                .spawn(move |child| async move {
                    let ambient = Cx::current().expect("admitted child context");
                    let child_client = Client::default_for_runtime(&child);
                    let ambient_client = Client::default_for_runtime(&ambient);
                    get(&child_client, &child, &child_url, 1).await;
                    (child_client, ambient_client)
                })
                .expect("spawn child");
            let (child_client, ambient_client) = asupersync::time::timeout(
                asupersync::time::wall_now(),
                BOUND,
                task.join(&parent),
            )
            .await
            .expect("bounded child join")
            .expect("child completes");
            let parent_client = Client::default_for_runtime(&parent);
            assert_eq!(parent_client.pool_stats().connections_created, 1);
            get(&parent_client, &parent, &url, 2).await;
            get(&ambient_client, &parent, &url, 3).await;
            for client in [&parent_client, &child_client, &ambient_client] {
                assert_eq!(client.pool_stats().connections_created, 1);
            }
        });
        assert_eq!(server.finish(), 1, "inherited pool with {workers} workers");
    }
}

#[test]
fn cancellation_via_a_context_clone_prevents_default_client_io() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind witness");
    listener.set_nonblocking(true).expect("nonblocking witness");
    let url = format!("http://{}/slot", listener.local_addr().expect("address"));
    let cx = Cx::for_testing();
    let client = Client::default_for_runtime(&cx);
    cx.clone().cancel_fast(CancelKind::User);
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    runtime.block_on(async {
        let result = asupersync::time::timeout(
            asupersync::time::wall_now(),
            BOUND,
            client.get(url.as_str()).send(&cx),
        )
        .await
        .expect("cancellation must not hang");
        assert!(result.expect_err("cancelled request").is_cancelled());
    });
    assert_eq!(client.pool_stats().connections_created, 0);
    assert_eq!(client.pool_stats().total_connections, 0);
    assert_eq!(
        listener
            .accept()
            .expect_err("no connection may be attempted")
            .kind(),
        io::ErrorKind::WouldBlock
    );
}
