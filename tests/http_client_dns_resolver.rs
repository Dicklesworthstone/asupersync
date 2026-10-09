//! Integration test for `HttpClientBuilder::dns_resolver` (asupersync-lfhzhl).
//!
//! Runs a local UDP nameserver that answers one made-up name, and an HTTP server
//! that closes every connection. A client with dns_resolver reaches the made-up name
//! twice; the nameserver sees one lookup (A and AAAA) and the shared cache_stats
//! shows the second connect hit the cache. Control: connect_io ignoring the resolver
//! must fail the test (the system resolver cannot resolve the made-up name).

use asupersync::cx::Cx;
use asupersync::http::HttpClient;
use asupersync::net::dns::{CacheConfig, Resolver, ResolverConfig};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

const MADE_UP_NAME: &str = "custom-resolver-test.local";

fn build_dns_response(query: &[u8], target_name: &str, answer_ip: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let id = &query[..2];
    let mut pos = 12;
    let mut name_parts = Vec::new();
    while pos < query.len() {
        let len = query[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1;
        if pos + len > query.len() {
            return None;
        }
        let part = std::str::from_utf8(&query[pos..pos + len]).ok()?;
        name_parts.push(part);
        pos += len;
    }
    let qname = name_parts.join(".");
    if pos + 4 > query.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
    let question_bytes = &query[12..pos + 4];

    if !qname.eq_ignore_ascii_case(target_name) {
        // NXDOMAIN
        let mut resp = Vec::new();
        resp.extend_from_slice(id);
        resp.extend_from_slice(&0x8183u16.to_be_bytes()); // Standard response, NXDOMAIN
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
        resp.extend_from_slice(question_bytes);
        return Some(resp);
    }

    if qtype == 1 {
        // A record
        let mut resp = Vec::new();
        resp.extend_from_slice(id);
        resp.extend_from_slice(&0x8180u16.to_be_bytes()); // Standard response, NoError
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
        resp.extend_from_slice(question_bytes);
        // Answer: Name pointer (0xc00c), TYPE A (1), CLASS IN (1), TTL (60s), RDLENGTH (4), RDATA
        resp.extend_from_slice(&0xc00cu16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
        resp.extend_from_slice(&answer_ip.octets());
        Some(resp)
    } else {
        // AAAA (28) or other: NOERROR with 0 answers (NODATA)
        let mut resp = Vec::new();
        resp.extend_from_slice(id);
        resp.extend_from_slice(&0x8180u16.to_be_bytes()); // Standard response, NoError
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
        resp.extend_from_slice(question_bytes);
        Some(resp)
    }
}

#[test]
fn http_client_custom_dns_resolver_resolves_and_caches() {
    let runtime = asupersync::runtime::RuntimeBuilder::new()
        .build()
        .expect("build runtime");

    // 1. Start HTTP server that closes every connection with Connection: close
    let http_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("bind http listener");
    let http_addr = http_listener.local_addr().expect("http local addr");
    let http_port = http_addr.port();
    let http_stop = Arc::new(AtomicBool::new(false));
    let http_stop_clone = Arc::clone(&http_stop);
    let http_connections = Arc::new(AtomicUsize::new(0));
    let http_conn_counter = Arc::clone(&http_connections);

    let http_handle = thread::spawn(move || {
        http_listener
            .set_nonblocking(true)
            .expect("set nonblocking");
        while !http_stop_clone.load(Ordering::Relaxed) {
            match http_listener.accept() {
                Ok((mut stream, _)) => {
                    http_conn_counter.fetch_add(1, Ordering::Relaxed);
                    stream
                        .set_read_timeout(Some(Duration::from_millis(500)))
                        .expect("set read timeout");
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let body = "OK";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.flush();
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    // 2. Start local UDP nameserver answering MADE_UP_NAME with 127.0.0.1
    let udp_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("bind udp nameserver");
    let udp_addr = udp_socket.local_addr().expect("udp local addr");
    let udp_stop = Arc::new(AtomicBool::new(false));
    let udp_stop_clone = Arc::clone(&udp_stop);
    let query_count = Arc::new(AtomicUsize::new(0));
    let query_counter = Arc::clone(&query_count);

    let udp_handle = thread::spawn(move || {
        udp_socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("set udp timeout");
        let mut buf = [0u8; 2048];
        while !udp_stop_clone.load(Ordering::Relaxed) {
            match udp_socket.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    query_counter.fetch_add(1, Ordering::Relaxed);
                    if let Some(resp) = build_dns_response(&buf[..n], MADE_UP_NAME, Ipv4Addr::LOCALHOST) {
                        let _ = udp_socket.send_to(&resp, peer);
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
        }
    });

    // 3. Configure Resolver pointing to local UDP nameserver
    let resolver_config = ResolverConfig {
        nameservers: vec![udp_addr],
        cache_enabled: true,
        cache_config: CacheConfig::default(),
        timeout: Duration::from_secs(3),
        retries: 0,
        happy_eyeballs: true,
        happy_eyeballs_delay: Duration::from_millis(50),
    };
    let resolver = Resolver::with_config(resolver_config);

    // 4. Build client with dns_resolver
    let client = HttpClient::builder()
        .dns_resolver(resolver.clone())
        .build();

    let cx = Cx::for_testing();
    let url = format!("http://{MADE_UP_NAME}:{http_port}/test");

    // First request: should resolve via UDP nameserver, connect, and receive 200 OK
    let resp1 = runtime.block_on(async { client.get(&url).send(&cx).await });
    let resp1 = resp1.expect("first request with custom resolver should succeed");
    assert_eq!(resp1.status, 200);

    // Initial query count: A and AAAA queries sent during initial lookup
    let queries_after_first = query_count.load(Ordering::Relaxed);
    assert!(
        queries_after_first > 0,
        "nameserver should receive at least 1 query on initial lookup"
    );

    // Second request: connection closed by server, so a fresh connect is required;
    // should hit the DNS cache, requiring 0 additional UDP queries!
    let resp2 = runtime.block_on(async { client.get(&url).send(&cx).await });
    let resp2 = resp2.expect("second request with custom resolver should succeed");
    assert_eq!(resp2.status, 200);

    let queries_after_second = query_count.load(Ordering::Relaxed);
    assert_eq!(
        queries_after_first, queries_after_second,
        "second request must not send new DNS queries (must hit cache)"
    );

    // Verify cache stats on the shared resolver
    let stats = resolver.cache_stats();
    assert!(
        stats.hits >= 1,
        "resolver cache_stats must record at least 1 hit, got {stats:?}"
    );

    // Control: a client without dns_resolver must fail to resolve the made-up host
    let control_client = HttpClient::builder().build();
    let control_resp = runtime.block_on(async { control_client.get(&url).send(&cx).await });
    assert!(
        control_resp.is_err(),
        "client without dns_resolver must fail to resolve made-up domain"
    );

    // Cleanup servers
    http_stop.store(true, Ordering::Relaxed);
    udp_stop.store(true, Ordering::Relaxed);
    let _ = http_handle.join();
    let _ = udp_handle.join();
}
