//! `HttpClient` requests by host NAME under a runtime whose blocking pool forbids blocking work (P05).
//!
//! The client is given a `Resolver` with an explicit nameserver, which the forbidden profile resolves on the
//! reactor (no worker thread, no `getaddrinfo`), and then connects to the resolved address. A local UDP
//! nameserver answers one made-up name and a local HTTP server closes every connection. Controls: the same
//! client without a resolver must be refused by the forbidden policy (so the positive is not passing merely
//! because the pool was open), and the pool must have run nothing at all.

use asupersync::http::HttpClient;
use asupersync::net::dns::{Resolver, ResolverConfig};
use asupersync::runtime::{BlockingAdmissionPolicy, RuntimeBuilder};
use asupersync::types::Budget;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

const MADE_UP_NAME: &str = "forbidden-pool-test.example";

/// Overall deadline of every request in this test (DNS, connect and response). A regression that stalls
/// any of them ends as `ClientError::DeadlineExceeded` and a failed assertion, never as a hang.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Socket timeout of the fixtures, so a stuck peer cannot hold a fixture thread.
const FIXTURE_IO_TIMEOUT: Duration = Duration::from_millis(500);

/// Owns the fixture threads: dropping it stops and joins them, so a failing assertion (or a
/// `block_on` that unwinds) cannot leave a server running until the process exits.
struct Fixtures {
    stop: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Drop for Fixtures {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for handle in self.threads.drain(..) {
            let fixture_panicked = handle.join().is_err();
            assert!(
                !fixture_panicked || thread::panicking(),
                "a fixture thread panicked"
            );
        }
    }
}

/// Answers every A question with `answer` and every other type with NODATA.
fn dns_response(query: &[u8], answer: Ipv4Addr) -> Option<Vec<u8>> {
    let mut end = 12;
    loop {
        let len = usize::from(*query.get(end)?);
        end += 1;
        if len == 0 {
            break;
        }
        end += len;
    }
    let question = query.get(12..end + 4)?;
    let is_a = u16::from_be_bytes([query[end], query[end + 1]]) == 1;
    let mut response = Vec::new();
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&u16::from(is_a).to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(question);
    if is_a {
        response.extend_from_slice(&0xc00cu16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&answer.octets());
    }
    Some(response)
}

#[test]
fn http_client_resolves_and_connects_by_name_on_a_forbidden_pool_without_blocking_work() {
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().expect("create reactor"))
        .blocking_threads(0, 1)
        .blocking_admission_policy(BlockingAdmissionPolicy::Forbidden)
        .build()
        .expect("build forbidden runtime");

    // Created before any fixture thread, so every thread spawned below is joined even if a later step panics.
    let mut fixtures = Fixtures {
        stop: Arc::new(AtomicBool::new(false)),
        threads: Vec::new(),
    };

    // A local HTTP server that answers 200 and closes every connection.
    let http_listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind http");
    let http_port = http_listener.local_addr().expect("http addr").port();
    http_listener.set_nonblocking(true).expect("nonblocking");
    let http_stop = Arc::clone(&fixtures.stop);
    fixtures.threads.push(thread::spawn(move || {
        while !http_stop.load(Ordering::Relaxed) {
            match http_listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(FIXTURE_IO_TIMEOUT))
                        .expect("read timeout");
                    stream
                        .set_write_timeout(Some(FIXTURE_IO_TIMEOUT))
                        .expect("write timeout");
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    );
                    let _ = stream.flush();
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    }));

    // A local UDP nameserver that answers MADE_UP_NAME with 127.0.0.1 and counts every datagram.
    let udp_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind udp");
    let udp_addr = udp_socket.local_addr().expect("udp addr");
    udp_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("udp read timeout");
    udp_socket
        .set_write_timeout(Some(FIXTURE_IO_TIMEOUT))
        .expect("udp write timeout");
    let queries = Arc::new(AtomicUsize::new(0));
    let udp_stop = Arc::clone(&fixtures.stop);
    let udp_queries = Arc::clone(&queries);
    fixtures.threads.push(thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while !udp_stop.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = udp_socket.recv_from(&mut buf) {
                udp_queries.fetch_add(1, Ordering::Relaxed);
                if let Some(response) = dns_response(&buf[..n], Ipv4Addr::LOCALHOST) {
                    let _ = udp_socket.send_to(&response, peer);
                }
            }
        }
    }));

    let resolver = Resolver::with_config(ResolverConfig {
        nameservers: vec![udp_addr],
        timeout: Duration::from_secs(3),
        retries: 0,
        ..ResolverConfig::default()
    });
    let client = HttpClient::builder().dns_resolver(resolver.clone()).build();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let url = format!("http://{MADE_UP_NAME}:{http_port}/test");

    // Positive: resolve by name on the reactor, connect, read a 200.
    let first = runtime
        .block_on(async { client.get(&url).timeout(REQUEST_TIMEOUT).send(&cx).await })
        .expect("a request by name must succeed on a forbidden pool");
    assert_eq!(first.status, 200);
    assert_eq!(
        queries.load(Ordering::Relaxed),
        2,
        "one lookup is exactly one A and one AAAA datagram"
    );

    // The server closed the connection, so this connects afresh, from the DNS cache and with no new datagram.
    let second = runtime
        .block_on(async { client.get(&url).timeout(REQUEST_TIMEOUT).send(&cx).await })
        .expect("the second request by name must succeed");
    assert_eq!(second.status, 200);
    assert_eq!(
        queries.load(Ordering::Relaxed),
        2,
        "the repeat is a cache hit"
    );
    assert!(resolver.cache_stats().hits >= 1);

    // The blocking pool ran nothing: no thread started, nothing queued.
    let pool = runtime
        .blocking_handle()
        .expect("a pool that refuses, not an absent one");
    assert_eq!((pool.active_threads(), pool.pending_count()), (0, 0));

    // Control: without a resolver the same request goes through the system path and the policy refuses it, so
    // the positive above is a property of the reactor route and not of an open pool.
    let control = HttpClient::builder().build();
    let refused = runtime
        .block_on(async { control.get(&url).timeout(REQUEST_TIMEOUT).send(&cx).await })
        .expect_err("a request by name without a resolver must be refused on a forbidden pool");
    assert!(
        refused.to_string().contains("forbidden"),
        "refused by the blocking admission policy, got: {refused}"
    );
    assert_eq!(
        queries.load(Ordering::Relaxed),
        2,
        "a refusal sends no datagram"
    );
    // `fixtures` stops and joins both threads here, and also when any assertion above fails.
}
