//! Ordinary CONNECT against a scripted native HTTP/2 proxy.

use super::*;
use asupersync::http::h2::client::{Http2TunnelConfig, Http2TunnelError};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use std::num::NonZeroU64;

const TARGET: &str = "destination.invalid:443";

fn limits(send: u64, receive: u64) -> Http2TunnelConfig {
    Http2TunnelConfig::new(
        NonZeroU64::new(send).unwrap(),
        NonZeroU64::new(receive).unwrap(),
    )
}

fn request(peer: &mut Peer, target: &str) -> (u32, Vec<Header>) {
    loop {
        if let Some(ReceivedFrame::Headers {
            stream_id,
            headers,
            end_stream,
        }) = peer.receive()
        {
            assert!(!end_stream, "CONNECT leaves its upload half open");
            let pseudo: Vec<_> = headers
                .iter()
                .filter(|header| header.name.starts_with(':'))
                .map(|header| (header.name.as_str(), header.value.as_str()))
                .collect();
            assert_eq!(pseudo, vec![(":method", "CONNECT"), (":authority", target)]);
            return (stream_id, headers);
        }
    }
}

fn accept(peer: &mut Peer, id: u32) {
    peer.connection
        .send_headers(
            id,
            vec![
                Header::new(":status", "200"),
                Header::new("proxy-agent", "native-test"),
            ],
            false,
        )
        .unwrap();
    peer.flush();
}

#[test]
fn ordinary_connect_uses_proxy_endpoint_and_crosses_both_flow_control_windows() {
    for workers in [1, 2] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            // This peer sends only ordinary SETTINGS, without setting 0x8.
            let mut peer = Peer::accept(listener, 65_535);
            let (id, headers) = request(&mut peer, TARGET);
            assert!(headers.iter().any(|header| {
                header.name == "proxy-authorization" && header.value == "Basic dGVzdA=="
            }));
            peer.connection
                .send_headers(
                    id,
                    vec![
                        Header::new(":status", "200"),
                        Header::new("content-length", "0"),
                        Header::new("proxy-agent", "native-test"),
                    ],
                    false,
                )
                .unwrap();
            peer.flush();
            let mut received = 0;
            loop {
                if let Some(ReceivedFrame::Data {
                    stream_id,
                    data,
                    end_stream,
                }) = peer.receive()
                {
                    assert_eq!(stream_id, id);
                    for (offset, byte) in data.iter().enumerate() {
                        assert_eq!(usize::from(*byte), (received + offset) % 251);
                    }
                    received += data.len();
                    if !data.is_empty() {
                        peer.connection.send_data(id, data, false).unwrap();
                    }
                    if end_stream {
                        assert_eq!(received, LARGE_BODY);
                        // The proxy can still send bytes after the client's
                        // FIN. Closing its transport here would lose them.
                        peer.connection
                            .send_data(id, Bytes::from_static(b"after-fin"), true)
                            .unwrap();
                    }
                    peer.flush();
                    if end_stream {
                        break;
                    }
                }
            }
            peer.eof();
        });
        let runtime = runtime(workers);
        runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(10), async {
                let mut tunnel = Http2Client::new()
                    .timeout(Duration::from_secs(3))
                    .request(
                        Method::Connect,
                        format!("http://{address}/proxy?not-forwarded=yes"),
                    )
                    .header("proxy-authorization", "Basic dGVzdA==")
                    .connect_proxy_tunnel(
                        &cx,
                        TARGET,
                        limits(2 * LARGE_BODY as u64, 2 * LARGE_BODY as u64),
                    )
                    .await
                    .unwrap();
                assert_eq!(tunnel.status(), 200);
                assert_eq!(tunnel.header("proxy-agent"), Some("native-test"));
                assert_eq!(tunnel.header("content-length"), Some("0"));
                let payload: Vec<u8> = (0..LARGE_BODY).map(|index| (index % 251) as u8).collect();
                // Consume each echo before producing the next chunk: bounded
                // unread DATA must not be mistaken for a flow-control defect.
                for chunk in payload.chunks(8191) {
                    tunnel.write_all(chunk).await.unwrap();
                    let mut echoed = vec![0; chunk.len()];
                    tunnel.read_exact(&mut echoed).await.unwrap();
                    assert_eq!(echoed, chunk);
                }
                tunnel.shutdown().await.unwrap();
                let mut tail = Vec::new();
                tunnel.read_to_end(&mut tail).await.unwrap();
                assert_eq!(tail, b"after-fin");
                assert_eq!(tunnel.sent_bytes(), LARGE_BODY as u64);
                assert_eq!(tunnel.received_bytes(), LARGE_BODY as u64 + 9);
                assert!(tunnel.is_closed());
                assert_eq!(
                    tunnel.write(b"late").await.unwrap_err().kind(),
                    std::io::ErrorKind::BrokenPipe
                );
            })
            .await
            .expect("both CONNECT directions advance beyond their initial windows");
        });
        peer.join().unwrap();
        quiescent(&runtime);
    }
}

#[test]
fn ordinary_connect_peer_fin_preserves_the_client_write_half() {
    for workers in [1, 2] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let target = "[2001:db8::1]:8443";
        let peer = std::thread::spawn(move || {
            let mut peer = Peer::accept(listener, 65_535);
            let (id, _) = request(&mut peer, target);
            accept(&mut peer, id);
            peer.connection
                .send_data(id, Bytes::from_static(b"banner"), true)
                .unwrap();
            peer.flush();
            let mut uploaded = Vec::new();
            loop {
                if let Some(ReceivedFrame::Data {
                    stream_id,
                    data,
                    end_stream,
                }) = peer.receive()
                {
                    assert_eq!(stream_id, id);
                    uploaded.extend_from_slice(&data);
                    if end_stream {
                        break;
                    }
                }
            }
            assert_eq!(uploaded, b"after-server-fin");
            peer.eof();
        });
        let runtime = runtime(workers);
        runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
                let mut tunnel = Http2Client::new()
                    .request(Method::Connect, format!("http://{address}/"))
                    .connect_proxy_tunnel(&cx, target, limits(64, 64))
                    .await
                    .unwrap();
                let mut banner = Vec::new();
                tunnel.read_to_end(&mut banner).await.unwrap();
                assert_eq!(banner, b"banner");
                assert!(
                    !tunnel.is_closed(),
                    "remote FIN leaves local writes available"
                );
                tunnel.write_all(b"after-server-fin").await.unwrap();
                tunnel.shutdown().await.unwrap();
                assert!(tunnel.is_closed());
            })
            .await
            .expect("independent CONNECT FIN directions complete");
        });
        peer.join().unwrap();
        quiescent(&runtime);
    }
}

#[test]
fn ordinary_connect_owner_cancellation_wakes_a_silent_read_and_retires_transport() {
    for workers in [1, 2] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let mut peer = Peer::accept(listener, 65_535);
            let (id, _) = request(&mut peer, TARGET);
            accept(&mut peer, id);
            peer.eof();
        });
        let runtime = runtime(workers);
        let owner = runtime.request_cx_with_budget(Budget::INFINITE);
        let controller_owner = owner.clone();
        let (parked_tx, parked_rx) = mpsc::channel();
        let controller = std::thread::spawn(move || {
            parked_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            controller_owner
                .cancel_with_reason(CancelReason::user("proxy tunnel reader cancelled"));
        });
        runtime.block_on(async move {
            let poller = Cx::current().unwrap();
            assert_ne!(owner.task_id(), poller.task_id());
            let mut tunnel = Http2Client::new()
                .timeout(Duration::from_secs(3))
                .request(Method::Connect, format!("http://{address}/"))
                .connect_proxy_tunnel(&owner, TARGET, limits(64, 64))
                .await
                .unwrap();
            let mut bytes = [0; 1];
            let error = {
                let mut reading = Box::pin(tunnel.read(&mut bytes));
                let mut parked = Some(parked_tx);
                asupersync::time::timeout(
                    poller.now(),
                    Duration::from_secs(3),
                    poll_fn(|task| {
                        let result = reading.as_mut().poll(task);
                        if result.is_pending()
                            && let Some(parked) = parked.take()
                        {
                            parked.send(()).unwrap();
                        }
                        result
                    }),
                )
                .await
                .expect("original owner cancellation wakes the silent read")
                .unwrap_err()
            };
            assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
            assert_eq!(
                tunnel.read(&mut bytes).await.unwrap_err().kind(),
                std::io::ErrorKind::BrokenPipe
            );
            assert!(
                poller.checkpoint().is_ok(),
                "the polling task was not the cancelled owner"
            );
            drop(tunnel);
        });
        controller.join().unwrap();
        peer.join().unwrap();
        quiescent(&runtime);
    }
}

#[test]
fn ordinary_connect_lifetime_byte_limits_close_the_owned_socket() {
    for workers in [1, 2] {
        for receive_limit in [false, true] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let peer = std::thread::spawn(move || {
                let mut peer = Peer::accept(listener, 65_535);
                let (id, _) = request(&mut peer, TARGET);
                accept(&mut peer, id);
                if receive_limit {
                    peer.connection
                        .send_data(id, Bytes::from_static(b"four"), false)
                        .unwrap();
                    peer.flush();
                } else {
                    let mut uploaded = Vec::new();
                    while uploaded.len() < 3 {
                        if let Some(ReceivedFrame::Data {
                            stream_id,
                            data,
                            end_stream,
                        }) = peer.receive()
                        {
                            assert_eq!(stream_id, id);
                            assert!(!end_stream);
                            uploaded.extend_from_slice(&data);
                        }
                    }
                    assert_eq!(uploaded, b"abc");
                    peer.connection
                        .send_data(id, Bytes::from_static(b"ack"), false)
                        .unwrap();
                    peer.flush();
                }
                peer.eof();
            });
            let runtime = runtime(workers);
            runtime.block_on(async move {
                let cx = Cx::current().unwrap();
                asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
                    let config = if receive_limit {
                        limits(8, 3)
                    } else {
                        limits(3, 8)
                    };
                    let mut tunnel = Http2Client::new()
                        .request(Method::Connect, format!("http://{address}/"))
                        .connect_proxy_tunnel(&cx, TARGET, config)
                        .await
                        .unwrap();
                    let error = if receive_limit {
                        tunnel.read(&mut [0; 8]).await.unwrap_err()
                    } else {
                        tunnel.write_all(b"abc").await.unwrap();
                        let mut ack = [0; 3];
                        tunnel.read_exact(&mut ack).await.unwrap();
                        assert_eq!(&ack, b"ack");
                        assert_eq!(tunnel.sent_bytes(), 3);
                        tunnel.write(b"d").await.unwrap_err()
                    };
                    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
                    drop(tunnel);
                })
                .await
                .expect("byte-limit refusal retires the CONNECT socket");
            });
            peer.join().unwrap();
            quiescent(&runtime);
        }
    }
}

#[test]
fn ordinary_connect_rejects_bad_targets_and_body_fields_before_dialing() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let runtime = runtime(1);
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        let client = Http2Client::new().timeout(Duration::from_millis(100));
        let url = format!("http://{address}/");
        for target in [
            "",
            "example.com",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com:-1",
            "example.com:abc",
            "user@example.com:443",
            "http://example.com:443",
            "example.com:443/path",
            "example.com:443?x",
            "example.com:443#x",
            "example.com:443\r\nx: y",
            "::1:443",
            "[::1]",
            "[gg::1]:443",
            "[::1]:443junk",
        ] {
            let result = client
                .request(Method::Connect, &url)
                .connect_proxy_tunnel(&cx, target, limits(64, 64))
                .await;
            assert!(
                matches!(
                    result,
                    Err(Http2TunnelError::Client(Http2ClientError::InvalidRequest(
                        _
                    )))
                ),
                "invalid target {target:?} must fail before transport setup: {result:?}"
            );
        }
        for builder in [
            client.get(&url),
            client.request(Method::Connect, &url).body("buffered"),
            client
                .request(Method::Connect, &url)
                .header("content-length", "0"),
            client
                .request(Method::Connect, &url)
                .header("te", "trailers"),
            client
                .request(Method::Connect, &url)
                .header("trailer", "checksum"),
            client
                .request(Method::Connect, &url)
                .header("host", address.to_string()),
        ] {
            let result = builder
                .connect_proxy_tunnel(&cx, TARGET, limits(64, 64))
                .await;
            assert!(
                matches!(
                    result,
                    Err(Http2TunnelError::Client(Http2ClientError::InvalidRequest(
                        _
                    )))
                ),
                "invalid CONNECT metadata must fail before transport setup: {result:?}"
            );
        }
    });
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("invalid CONNECT input opened a proxy socket: {other:?}"),
    }
    quiescent(&runtime);
}

#[test]
fn ordinary_connect_waits_for_response_without_requiring_extended_negotiation() {
    for extended in [false, true] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let mut peer = Peer::accept(listener, 65_535);
            if !extended {
                request(&mut peer, TARGET);
            }
            // No final response and no ENABLE_CONNECT_PROTOCOL setting.
            peer.eof();
        });
        let runtime = runtime(1);
        runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            let builder = Http2Client::new()
                .timeout(Duration::from_millis(250))
                .request(Method::Connect, format!("http://{address}/"));
            let result = if extended {
                builder
                    .connect_tunnel(&cx, "websocket", limits(64, 64))
                    .await
            } else {
                builder
                    .connect_proxy_tunnel(&cx, TARGET, limits(64, 64))
                    .await
            };
            if extended {
                assert!(
                    matches!(result, Err(Http2TunnelError::NotNegotiated)),
                    "{result:?}"
                );
            } else {
                assert!(
                    matches!(
                        result,
                        Err(Http2TunnelError::Client(Http2ClientError::DeadlineExceeded))
                    ),
                    "{result:?}"
                );
            }
        });
        peer.join().unwrap();
        quiescent(&runtime);
    }
}
