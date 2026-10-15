//! Opt-in waiting at the HTTP/1 client's connection limit
//! (`HttpClientBuilder::pool_wait_timeout`, br-asupersync-vxmjgn MEDIUM 2).
//!
//! By default a request that finds its host's connection limit reached fails
//! at once with `ClientError::PoolExhausted`, so a seventh concurrent request
//! to one host (default limit six) fails. With a wait timeout it takes the
//! connection an in-flight request releases instead. These tests run against
//! a real keep-alive server and count the connections it accepts.
//!
//! Requires `--features test-internals` (`Cx::for_testing`).
#![cfg(feature = "test-internals")]

use asupersync::Cx;
use asupersync::http::h1::{ClientError, HttpClient};
use asupersync::runtime::RuntimeBuilder;
use asupersync::types::CancelKind;
use futures_lite::future::zip;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime")
        .block_on(fut)
}

/// A keep-alive server that holds every response for `delay`. Returns its
/// address and the number of connections it has accepted.
fn spawn_server(delay: Duration) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            counter.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || serve(stream, delay));
        }
    });
    (addr, accepted)
}

fn serve(mut stream: TcpStream, delay: Duration) {
    let mut buf = Vec::new();
    let mut scratch = [0_u8; 512];
    loop {
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut scratch) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&scratch[..n]),
            }
        }
        let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        buf.drain(..end);
        thread::sleep(delay);
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
        if stream.write_all(response).is_err() {
            return;
        }
    }
}

fn is_pool_exhausted(result: &Result<asupersync::http::h1::types::Response, ClientError>) -> bool {
    matches!(result, Err(ClientError::PoolExhausted { .. }))
}

#[test]
fn a_request_beyond_the_host_limit_waits_for_the_released_connection_when_enabled() {
    let (addr, accepted) = spawn_server(Duration::from_millis(150));
    let url = format!("http://{addr}/item");

    // Control: the default fails the second concurrent request at once.
    let client = HttpClient::builder().max_connections_per_host(1).build();
    let cx = Cx::for_testing();
    let (first, second) = block_on(zip(client.send_get(&cx, &url), client.send_get(&cx, &url)));
    assert_eq!(first.expect("first request").status, 200);
    assert!(is_pool_exhausted(&second), "default fails fast: {second:?}");

    let accepted_before = accepted.load(Ordering::SeqCst);
    let client = HttpClient::builder()
        .max_connections_per_host(1)
        .pool_wait_timeout(Duration::from_secs(5))
        .build();
    let (first, second) = block_on(zip(
        client.send_get(&cx, &url),
        zip(client.send_get(&cx, &url), client.send_get(&cx, &url)),
    ));
    let (second, third) = second;
    for result in [first, second, third] {
        assert_eq!(result.expect("waiting request succeeds").status, 200);
    }
    assert_eq!(
        accepted.load(Ordering::SeqCst) - accepted_before,
        1,
        "the waiting requests reuse the one released connection"
    );
    let stats = client.pool_stats();
    assert_eq!(stats.total_connections, 1);
    assert_eq!(stats.idle_connections, 1);
}

#[test]
fn a_request_still_waiting_when_its_wait_timeout_elapses_fails_with_pool_exhausted() {
    let (addr, _accepted) = spawn_server(Duration::from_millis(1500));
    let url = format!("http://{addr}/slow");
    let client = HttpClient::builder()
        .max_connections_per_host(1)
        .pool_wait_timeout(Duration::from_millis(100))
        .build();
    let cx = Cx::for_testing();
    let started = Instant::now();
    let (first, (second, gave_up_after)) = block_on(zip(client.send_get(&cx, &url), async {
        let result = client.send_get(&cx, &url).await;
        (result, started.elapsed())
    }));
    assert_eq!(first.expect("first request").status, 200);
    assert!(is_pool_exhausted(&second), "{second:?}");
    assert!(
        gave_up_after >= Duration::from_millis(100) && gave_up_after < Duration::from_millis(1400),
        "the wait ends at its timeout, not when the connection frees: {gave_up_after:?}"
    );
}

#[test]
fn cancelling_a_waiting_request_ends_its_wait() {
    let (addr, _accepted) = spawn_server(Duration::from_millis(1500));
    let url = format!("http://{addr}/slow");
    let client = HttpClient::builder()
        .max_connections_per_host(1)
        .pool_wait_timeout(Duration::from_secs(30))
        .build();
    let cx = Cx::for_testing();
    let waiter_cx = Cx::for_testing();
    let canceller = {
        let waiter_cx = waiter_cx.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            waiter_cx.cancel_fast(CancelKind::User);
        })
    };
    let started = Instant::now();
    let (first, (second, gave_up_after)) = block_on(zip(client.send_get(&cx, &url), async {
        let result = client.send_get(&waiter_cx, &url).await;
        (result, started.elapsed())
    }));
    canceller.join().expect("canceller thread");
    assert_eq!(first.expect("first request").status, 200);
    let error = second.expect_err("the cancelled waiter fails");
    assert!(error.is_cancelled(), "{error:?}");
    assert!(
        gave_up_after < Duration::from_millis(1400),
        "cancellation ends the wait before the connection frees: {gave_up_after:?}"
    );
}
