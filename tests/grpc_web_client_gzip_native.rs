#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::pedantic, clippy::nursery)]
// An integration test is its own crate and does not inherit `src/lib.rs`'s
// `recursion_limit`. Proving `Send` for its async chains exceeds rustc's default
// depth, which the future-incompatible `recursion_depth_exceeding_limit` lint
// (rust-lang #159228) will turn into a hard error.
#![recursion_limit = "256"]

use asupersync::grpc::{
    Code, GrpcWebClient, GrpcWebClientConfig, GrpcWebCompressionConfig,
};

#[cfg(not(feature = "compression"))]
#[test]
fn gzip_policy_fails_closed_without_the_compression_feature() {
    let error = GrpcWebClient::with_config_and_compression(
        GrpcWebClientConfig::default(),
        GrpcWebCompressionConfig::gzip(),
    )
    .unwrap_err();
    assert_eq!(error.code(), Code::Unimplemented);
}

#[cfg(feature = "compression")]
mod gzip {
    use super::*;
    use asupersync::bytes::Bytes;
    use asupersync::cx::Cx;
    use asupersync::grpc::{
        IdentityCodec, Request, WebContentType, gzip_frame_compress, gzip_frame_decompress,
    };
    use asupersync::runtime::RuntimeBuilder;
    use base64::Engine as _;
    use std::future::Future;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    fn listener() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://{}/test.Service/Compress",
            listener.local_addr().unwrap()
        );
        (listener, url)
    }

    fn read_request(socket: &mut TcpStream) -> (String, Vec<u8>) {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 32 * 1024, "request headers are bounded");
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let length = head
            .split("\r\n")
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .unwrap()
            .1
            .trim()
            .parse::<usize>()
            .unwrap();
        assert!(length < 1024 * 1024);
        let mut body = vec![0; length];
        socket.read_exact(&mut body).unwrap();
        (head, body)
    }

    fn frame(flag: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![flag];
        frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn trailers() -> Vec<u8> {
        frame(0x80, b"grpc-status: 0\r\nx-compression-proof: gzip\r\n")
    }

    fn fixed_response(
        socket: &mut TcpStream,
        content_type: &str,
        extra_headers: &str,
        body: &[u8],
    ) {
        write!(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n",
            body.len(),
        )
        .unwrap();
        socket.write_all(body).unwrap();
        socket.flush().unwrap();
    }

    fn decode_request_body(mode: WebContentType, body: &[u8]) -> Vec<u8> {
        if mode.is_text_mode() {
            base64::engine::general_purpose::STANDARD
                .decode(body)
                .unwrap()
        } else {
            body.to_vec()
        }
    }

    fn assert_gzip_request(mode: WebContentType, head: &str, body: &[u8]) {
        let lower = head.to_ascii_lowercase();
        assert!(lower.contains("grpc-encoding: gzip\r\n"), "{head}");
        assert!(
            lower.contains("grpc-accept-encoding: gzip,identity\r\n"),
            "{head}"
        );
        assert!(
            lower.contains(&format!(
                "content-type: {}\r\n",
                mode.as_header_value()
            )),
            "{head}"
        );
        let wire = decode_request_body(mode, body);
        assert_eq!(wire[0], 1, "request must set compressed-flag");
        let length = u32::from_be_bytes([wire[1], wire[2], wire[3], wire[4]]) as usize;
        assert_eq!(wire.len(), 5 + length);
        let decoded = gzip_frame_decompress(
            Bytes::copy_from_slice(&wire[5..]),
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(decoded.as_ref(), b"compress this request");
    }

    fn run_with_runtime<F, Fut>(test: F)
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime installs a current context");
            test(cx).await;
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    }

    #[test]
    fn native_binary_and_text_calls_send_gzip_and_accept_mixed_response_frames() {
        for mode in [WebContentType::GrpcWeb, WebContentType::GrpcWebText] {
            let (listener, url) = listener();
            let peer = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                let (head, body) = read_request(&mut socket);
                assert_gzip_request(mode, &head, &body);

                let compressed = gzip_frame_compress(Bytes::from_static(b"compressed response"))
                    .unwrap();
                let mut wire = frame(0, b"plain response");
                wire.extend(frame(1, compressed.as_ref()));
                wire.extend(trailers());
                let body = if mode.is_text_mode() {
                    base64::engine::general_purpose::STANDARD
                        .encode(wire)
                        .into_bytes()
                } else {
                    wire
                };
                fixed_response(
                    &mut socket,
                    mode.as_header_value(),
                    "Grpc-Encoding: gzip\r\n",
                    &body,
                );
            });

            run_with_runtime(move |cx| async move {
                    let client = GrpcWebClient::with_config_and_compression(
                        GrpcWebClientConfig {
                            content_type: mode,
                            timeout: Duration::from_secs(4),
                            ..GrpcWebClientConfig::default()
                        },
                        GrpcWebCompressionConfig::gzip(),
                    )
                    .unwrap();
                    let mut stream = client
                        .server_streaming(
                            &cx,
                            &url,
                            Request::new(Bytes::from_static(b"compress this request")),
                            IdentityCodec,
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        stream.message().await.unwrap().unwrap().as_ref(),
                        b"plain response"
                    );
                    assert_eq!(
                        stream.message().await.unwrap().unwrap().as_ref(),
                        b"compressed response"
                    );
                    assert!(stream.message().await.unwrap().is_none());
                    assert_eq!(
                        stream
                            .trailing_metadata()
                            .unwrap()
                            .get("x-compression-proof")
                            .and_then(|value| match value {
                                asupersync::grpc::MetadataValue::Ascii(value) => Some(value.as_str()),
                                asupersync::grpc::MetadataValue::Binary(_) => None,
                            }),
                        Some("gzip")
                    );
            });
            peer.join().unwrap();
        }
    }

    #[test]
    fn selected_gzip_is_rejected_when_the_client_did_not_advertise_it() {
        let (listener, url) = listener();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let _ = read_request(&mut socket);
            let compressed = gzip_frame_compress(Bytes::from_static(b"response")).unwrap();
            let mut body = frame(1, compressed.as_ref());
            body.extend(trailers());
            fixed_response(
                &mut socket,
                WebContentType::GrpcWeb.as_header_value(),
                "Grpc-Encoding: gzip\r\n",
                &body,
            );
        });
        run_with_runtime(move |cx| async move {
                let client = GrpcWebClient::with_config(GrpcWebClientConfig {
                    timeout: Duration::from_secs(4),
                    ..GrpcWebClientConfig::default()
                })
                .unwrap();
                let error = client
                    .unary(&cx, &url, Request::new(Bytes::new()), IdentityCodec)
                    .await
                    .unwrap_err();
                assert_eq!(error.code(), Code::Unimplemented);
        });
        peer.join().unwrap();
    }

    #[test]
    fn compressed_flag_requires_a_selected_non_identity_encoding() {
        let (listener, url) = listener();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let _ = read_request(&mut socket);
            let compressed = gzip_frame_compress(Bytes::from_static(b"response")).unwrap();
            let mut body = frame(1, compressed.as_ref());
            body.extend(trailers());
            fixed_response(
                &mut socket,
                WebContentType::GrpcWeb.as_header_value(),
                "",
                &body,
            );
        });
        run_with_runtime(move |cx| async move {
                let client = GrpcWebClient::with_config_and_compression(
                    GrpcWebClientConfig {
                        timeout: Duration::from_secs(4),
                        ..GrpcWebClientConfig::default()
                    },
                    GrpcWebCompressionConfig::identity().with_accept_gzip(true),
                )
                .unwrap();
                let error = client
                    .unary(&cx, &url, Request::new(Bytes::new()), IdentityCodec)
                    .await
                    .unwrap_err();
                assert_eq!(error.code(), Code::Unimplemented);
        });
        peer.join().unwrap();
    }

    #[test]
    fn gzip_expansion_is_bounded_by_the_decoded_message_limit() {
        let (listener, url) = listener();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let _ = read_request(&mut socket);
            let compressed = gzip_frame_compress(Bytes::from(vec![0_u8; 4096])).unwrap();
            assert!(compressed.len() < 64, "fixture must pass the wire-size precheck");
            let mut body = frame(1, compressed.as_ref());
            body.extend(trailers());
            fixed_response(
                &mut socket,
                WebContentType::GrpcWeb.as_header_value(),
                "Grpc-Encoding: gzip\r\n",
                &body,
            );
        });
        run_with_runtime(move |cx| async move {
                let client = GrpcWebClient::with_config_and_compression(
                    GrpcWebClientConfig {
                        max_recv_message_size: 64,
                        timeout: Duration::from_secs(4),
                        ..GrpcWebClientConfig::default()
                    },
                    GrpcWebCompressionConfig::identity().with_accept_gzip(true),
                )
                .unwrap();
                let error = client
                    .unary(&cx, &url, Request::new(Bytes::new()), IdentityCodec)
                    .await
                    .unwrap_err();
                assert_eq!(error.code(), Code::ResourceExhausted);
        });
        peer.join().unwrap();
    }

    #[test]
    fn unknown_and_duplicate_response_encodings_fail_closed() {
        for (headers, expected) in [
            ("Grpc-Encoding: snappy\r\n", Code::Unimplemented),
            (
                "Grpc-Encoding: gzip\r\nGrpc-Encoding: gzip\r\n",
                Code::Internal,
            ),
            ("Content-Encoding: gzip\r\n", Code::Unimplemented),
        ] {
            let (listener, url) = listener();
            let peer = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                let _ = read_request(&mut socket);
                let mut body = frame(0, b"response");
                body.extend(trailers());
                fixed_response(
                    &mut socket,
                    WebContentType::GrpcWeb.as_header_value(),
                    headers,
                    &body,
                );
            });
            run_with_runtime(move |cx| async move {
                    let client = GrpcWebClient::with_config_and_compression(
                        GrpcWebClientConfig {
                            timeout: Duration::from_secs(4),
                            ..GrpcWebClientConfig::default()
                        },
                        GrpcWebCompressionConfig::identity().with_accept_gzip(true),
                    )
                    .unwrap();
                    let error = client
                        .unary(&cx, &url, Request::new(Bytes::new()), IdentityCodec)
                        .await
                        .unwrap_err();
                    assert_eq!(error.code(), expected, "headers={headers:?}: {error}");
            });
            peer.join().unwrap();
        }
    }
}
