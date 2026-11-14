//! br-asupersync-8udzw7: aggregate metadata amplification across H1 decoders.
//!
//! These fixed wire fixtures use 1023 metadata bytes per one-byte chunk. Every
//! individual size line fits the established 1024-byte limit. Sixteen chunks
//! spend 16368 bytes; the next line has 32 bytes of allowance, including the
//! 16 payload bytes already decoded. No large allocation or timing oracle is
//! needed to distinguish the vulnerable aggregate behavior.

use super::{ChunkedBodyDecoder, Http1Codec, HttpError};
use crate::bytes::BytesMut;
use crate::codec::Decoder;
use crate::http::h1::client::Http1ClientCodec;

#[derive(Clone, Copy, Debug)]
enum Metadata {
    Extensions,
    ZeroPadding,
    Mixed,
}

const METADATA: [Metadata; 3] = [Metadata::Extensions, Metadata::ZeroPadding, Metadata::Mixed];

fn size_line(size: usize, cost: usize, metadata: Metadata) -> Vec<u8> {
    let padding = match metadata {
        Metadata::Extensions => 0,
        Metadata::ZeroPadding => cost,
        Metadata::Mixed => cost / 2,
    };
    let extension = cost - padding;
    let mut line = vec![b'0'; padding];
    line.extend_from_slice(format!("{size:X}").as_bytes());
    if extension != 0 {
        assert!(extension >= 2, "fixture uses a nonempty extension token");
        line.push(b';');
        line.extend(std::iter::repeat_n(b'a', extension - 1));
    }
    assert!(line.len() <= 1024, "fixture must pass the per-line limit");
    line.extend_from_slice(b"\r\n");
    line
}

fn body(chunks: usize, terminal_cost: usize, metadata: Metadata) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..chunks {
        bytes.extend(size_line(1, 1023, metadata));
        bytes.extend_from_slice(b"x\r\n");
    }
    bytes.extend(size_line(0, terminal_cost, metadata));
    bytes.extend_from_slice(b"\r\n");
    bytes
}

fn request(body: &[u8]) -> Vec<u8> {
    let mut wire =
        b"POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    wire.extend_from_slice(body);
    wire
}

fn response(body: &[u8]) -> Vec<u8> {
    let mut wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    wire.extend_from_slice(body);
    wire
}

fn decode_fragmented<D: Decoder>(
    decoder: &mut D,
    wire: &[u8],
    fragment_size: usize,
) -> Result<D::Item, D::Error> {
    let mut buffered = BytesMut::new();
    let mut supplied = 0;
    for fragment in wire.chunks(fragment_size) {
        supplied += fragment.len();
        buffered.extend_from_slice(fragment);
        if let Some(message) = decoder.decode(&mut buffered)? {
            assert_eq!(supplied, wire.len(), "fixture must end at message EOF");
            assert!(buffered.is_empty());
            return Ok(message);
        }
        // Re-polling without new input must not charge the same partial size
        // line twice or erase the cumulative charge from earlier chunks.
        assert!(decoder.decode(&mut buffered)?.is_none());
    }
    panic!("complete fixture did not produce a message or framing error");
}

#[test]
fn buffered_requests_reject_aggregate_chunk_metadata_amplification() {
    for metadata in METADATA {
        let wire = request(&body(17, 0, metadata));
        for fragment_size in [1, 2, 31, 1024, 4096, usize::MAX] {
            let result = decode_fragmented(
                &mut Http1Codec::new().max_body_size(32),
                &wire,
                fragment_size,
            );
            assert!(
                matches!(result, Err(HttpError::BadChunkedEncoding)),
                "{metadata:?}, fragment size {fragment_size}: {result:?}"
            );
        }
    }
}

#[test]
fn buffered_requests_accept_exact_metadata_boundary_and_ordinary_padding() {
    for metadata in METADATA {
        let wire = request(&body(16, 32, metadata));
        for fragment_size in [1, 7, 4096, usize::MAX] {
            let decoded = decode_fragmented(
                &mut Http1Codec::new().max_body_size(16),
                &wire,
                fragment_size,
            )
            .expect("metadata exactly at allowance is valid");
            assert_eq!(decoded.body, vec![b'x'; 16]);
        }
    }

    let wire = request(b"0003;name=value\r\nabc\r\n0000;end=yes\r\nX-Final: ok\r\n\r\n");
    let decoded = decode_fragmented(&mut Http1Codec::new(), &wire, 1)
        .expect("ordinary zero padding, extensions and trailers remain valid");
    assert_eq!(decoded.body, b"abc");
    assert_eq!(decoded.trailers, [("X-Final".to_owned(), "ok".to_owned())]);
}

#[test]
fn buffered_maximum_chunk_line_accepts_split_crlf_without_relaxing_cap() {
    let line = size_line(1, 1023, Metadata::Extensions);
    let mut buffered = BytesMut::from(&line[..1025]);
    assert!(
        super::split_line_crlf(&mut buffered, 1024)
            .unwrap()
            .is_none()
    );
    assert_eq!(buffered.len(), 1025);
    buffered.extend_from_slice(b"\nnext");
    assert_eq!(
        super::split_line_crlf(&mut buffered, 1024)
            .unwrap()
            .unwrap()
            .as_ref(),
        &line[..1024]
    );
    assert_eq!(buffered.as_ref(), b"next");

    for suffix in [b"".as_slice(), b"\r", b"\r\n"] {
        let mut buffered = BytesMut::from(vec![b'0'; 1025].as_slice());
        buffered.extend_from_slice(suffix);
        assert!(matches!(
            super::split_line_crlf(&mut buffered, 1024),
            Err(HttpError::BadChunkedEncoding)
        ));
    }
}

#[test]
fn buffered_metadata_limit_includes_terminal_chunk_and_excludes_future_data() {
    for metadata in METADATA {
        let wire = request(&body(16, 33, metadata));
        assert!(matches!(
            decode_fragmented(&mut Http1Codec::new(), &wire, 1),
            Err(HttpError::BadChunkedEncoding)
        ));

        // Only previously received data earns allowance. The next declared
        // 100 bytes have not arrived and must not admit this over-budget line.
        let mut prefix = Vec::new();
        for _ in 0..16 {
            prefix.extend(size_line(1, 1023, metadata));
            prefix.extend_from_slice(b"x\r\n");
        }
        prefix.extend(size_line(100, 33, metadata));
        let mut buffered = BytesMut::from(request(&prefix).as_slice());
        assert!(matches!(
            Http1Codec::new().decode(&mut buffered),
            Err(HttpError::BadChunkedEncoding)
        ));
    }
}

#[test]
fn metadata_accounting_resets_only_at_complete_message_boundaries() {
    for metadata in METADATA {
        let complete_body = body(16, 32, metadata);
        let mut decoder = ChunkedBodyDecoder::new(16, 1024);
        for _ in 0..2 {
            let mut buffered = BytesMut::from(complete_body.as_slice());
            let (decoded, trailers) = decoder.decode(&mut buffered).unwrap().unwrap();
            assert_eq!(decoded, vec![b'x'; 16]);
            assert!(trailers.is_empty());
            assert!(buffered.is_empty());
        }

        let wire = request(&complete_body);
        let mut buffered = BytesMut::from(wire.as_slice());
        buffered.extend_from_slice(&wire);
        let mut codec = Http1Codec::new();
        for _ in 0..2 {
            assert_eq!(
                codec.decode(&mut buffered).unwrap().unwrap().body,
                vec![b'x'; 16]
            );
        }
        assert!(buffered.is_empty());
        assert!(codec.decode(&mut buffered).unwrap().is_none());
    }
}

#[test]
fn buffered_responses_enforce_the_same_aggregate_metadata_budget() {
    for metadata in METADATA {
        for fragment_size in [1, 4096, usize::MAX] {
            let wire = response(&body(17, 0, metadata));
            assert!(matches!(
                decode_fragmented(&mut Http1ClientCodec::new(), &wire, fragment_size),
                Err(HttpError::BadChunkedEncoding)
            ));

            let wire = response(&body(16, 32, metadata));
            let decoded = decode_fragmented(&mut Http1ClientCodec::new(), &wire, fragment_size)
                .expect("client accepts the same exact boundary as the server");
            assert_eq!(decoded.body, vec![b'x'; 16]);
        }
    }
}

#[test]
fn streaming_request_discard_cannot_bypass_chunk_metadata_budget() {
    use crate::cx::Cx;
    use crate::http::h1::{BodyKind, IncomingBodyError, IncomingRequestBody};

    for metadata in METADATA {
        let cx = Cx::for_testing();
        let (mut writer, consumer) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);
        drop(consumer);
        assert!(matches!(
            writer.discard_bytes(&body(17, 0, metadata)),
            Err(IncomingBodyError::BadChunkedEncoding)
        ));
        assert_eq!(writer.drain_progress().bytes, 16);

        let (mut writer, consumer) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);
        drop(consumer);
        let wire = body(16, 32, metadata);
        for fragment in wire.chunks(7) {
            writer
                .discard_bytes(fragment)
                .expect("valid fragmented boundary");
        }
        let progress = writer.drain_progress();
        assert_eq!(progress.bytes, 16);
        assert!(progress.synchronized_eof);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_buffered_server_refuses_metadata_amplification_before_handler() {
    use crate::http::h1::server::{ConnectionPhase, HostPolicy, Http1Config, Http1Server};
    use crate::http::h1::types::Response;
    use crate::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use crate::runtime::RuntimeBuilder;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("native runtime");
    for metadata in METADATA {
        runtime.block_on(async {
            let mut wire = request(&body(17, 0, metadata));
            wire.extend_from_slice(b"GET /must-not-run HTTP/1.1\r\nHost: localhost\r\n\r\n");
            let (mut peer, transport) = duplex(wire.len() + 1);
            peer.write_all(&wire)
                .await
                .expect("queue the complete malicious request");
            peer.shutdown().await.expect("peer request EOF");

            let calls = Arc::new(AtomicUsize::new(0));
            let seen = Arc::clone(&calls);
            let server = Http1Server::with_config(
                move |_| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    async { Response::new(200, "OK", b"handler must not run") }
                },
                Http1Config {
                    allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                    ..Http1Config::default()
                },
            );
            let receive = async {
                let mut bytes = Vec::new();
                peer.read_to_end(&mut bytes)
                    .await
                    .expect("read refusal through EOF");
                bytes
            };
            let (state, bytes) = futures_lite::future::zip(server.serve(transport), receive).await;
            let state = state.expect("framing refusal closes cleanly");
            let wire = String::from_utf8(bytes).expect("HTTP refusal is UTF-8");
            assert!(wire.starts_with("HTTP/1.1 400 "), "{metadata:?}: {wire}");
            assert!(
                wire.to_ascii_lowercase()
                    .contains("\r\nconnection: close\r\n")
            );
            assert_eq!(wire.matches("HTTP/1.1 ").count(), 1);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(state.requests_served, 1);
            assert_eq!(state.phase, ConnectionPhase::Closing);
        });
    }
    assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(5)));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_streaming_client_enforces_metadata_budget_and_fences_reuse() {
    use crate::bytes::Buf;
    use crate::http::body::{Body, Frame};
    use crate::http::h1::client::Http1Client;
    use crate::http::h1::types::{Method, Request, Version};
    use crate::io::{AsyncWriteExt, duplex};
    use crate::runtime::RuntimeBuilder;
    use std::future::poll_fn;
    use std::pin::Pin;

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("native runtime");
    for metadata in METADATA {
        for accepted in [false, true] {
            runtime.block_on(async {
                let payload = if accepted {
                    body(16, 32, metadata)
                } else {
                    body(17, 0, metadata)
                };
                let wire = response(&payload);
                let (transport, mut origin) = duplex(wire.len() + 1);
                origin.write_all(&wire).await.expect("queue response bytes");
                origin.shutdown().await.expect("origin response EOF");
                let request = Request {
                    method: Method::Get,
                    uri: "/".to_owned(),
                    version: Version::Http11,
                    headers: vec![("Host".to_owned(), "localhost".to_owned())],
                    body: Vec::new(),
                    trailers: Vec::new(),
                    peer_addr: None,
                };
                let mut response = Http1Client::request_streaming(transport, request)
                    .await
                    .expect("valid response head");
                let mut received = 0;
                loop {
                    match poll_fn(|task| Pin::new(&mut response.body).poll_frame(task)).await {
                        Some(Ok(Frame::Data(bytes))) => received += bytes.remaining(),
                        Some(Err(HttpError::BadChunkedEncoding)) if !accepted => break,
                        None if accepted => break,
                        other => panic!("{metadata:?}, accepted={accepted}: {other:?}"),
                    }
                }
                assert_eq!(received, 16);
                assert!(
                    poll_fn(|task| Pin::new(&mut response.body).poll_frame(task))
                        .await
                        .is_none()
                );
                assert_eq!(response.body.is_complete_for_reuse(), accepted);
            });
        }
    }
    assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(5)));
}
