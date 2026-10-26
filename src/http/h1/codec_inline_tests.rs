    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn decode_one(codec: &mut Http1Codec, data: &[u8]) -> Result<Option<Request>, HttpError> {
        let mut buf = BytesMut::from(data);
        codec.decode(&mut buf)
    }

    fn encode_one(codec: &mut Http1Codec, resp: Response) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(1024);
        codec.encode(resp, &mut buf).unwrap();
        buf.to_vec()
    }

    #[test]
    fn decode_eof_rejects_truncated_requests_at_every_input_split() {
        // Several chunk states consume all available bytes while still
        // requiring a terminator or more data. EOF must consult parser state,
        // not just whether the caller's buffer happens to be empty.
        let incomplete: &[&[u8]] = &[
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\n",
            b"POST /upload HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
            b"POST /upload HTTP/1.1\r\nContent-Length: 5\r\n\r\nhell",
            b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
            b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello",
            b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
            b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n",
            b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nx-checksum: abc\r\n",
        ];
        for &raw in incomplete {
            for split in 0..=raw.len() {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::from(&raw[..split]);
                assert!(codec.decode(&mut buf).unwrap().is_none());
                buf.extend_from_slice(&raw[split..]);
                let result = codec.decode_eof(&mut buf);
                assert!(
                    matches!(&result, Err(HttpError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof),
                    "split {split} of {raw:?}: {result:?}"
                );

                // Truncated framing is terminal even if someone retries the
                // codec with a fresh, otherwise valid request buffer.
                let mut replacement = BytesMut::from(&b"GET / HTTP/1.1\r\n\r\n"[..]);
                assert!(matches!(
                    codec.decode(&mut replacement),
                    Err(HttpError::BadHeader)
                ));
            }
        }
    }

    #[test]
    fn decode_eof_preserves_complete_pipelined_requests_and_trailers() {
        let mut codec = Http1Codec::new();
        let mut buf = BytesMut::from(
            &b"GET /first HTTP/1.1\r\n\r\n\
               POST /second HTTP/1.1\r\nContent-Length: 2\r\n\r\nok\
               POST /third HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
               3\r\nend\r\n0\r\nx-checksum: abc\r\n\r\n"[..],
        );
        let first = codec.decode_eof(&mut buf).unwrap().unwrap();
        assert_eq!(first.uri, "/first");
        assert!(first.body.is_empty());
        let second = codec.decode_eof(&mut buf).unwrap().unwrap();
        assert_eq!(second.uri, "/second");
        assert_eq!(second.body, b"ok");
        let third = codec.decode_eof(&mut buf).unwrap().unwrap();
        assert_eq!(third.uri, "/third");
        assert_eq!(third.body, b"end");
        assert_eq!(
            third.trailers,
            vec![("x-checksum".to_owned(), "abc".to_owned())]
        );
        assert!(buf.is_empty());
        assert!(codec.decode_eof(&mut buf).unwrap().is_none());
        assert!(codec.decode_eof(&mut buf).unwrap().is_none());
    }

    #[test]
    fn framed_request_reader_reports_truncation_once_instead_of_clean_eof() {
        use crate::stream::Stream;
        use std::pin::Pin;
        use std::task::{Context, Poll, Waker};

        for raw in [
            &b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n"[..],
            &b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"[..],
        ] {
            let mut reader = crate::codec::FramedRead::new(raw, Http1Codec::new());
            let mut task = Context::from_waker(Waker::noop());
            let result = Pin::new(&mut reader).poll_next(&mut task);
            assert!(
                matches!(&result, Poll::Ready(Some(Err(HttpError::Io(error)))) if error.kind() == io::ErrorKind::UnexpectedEof),
                "{result:?}"
            );
            assert!(matches!(
                Pin::new(&mut reader).poll_next(&mut task),
                Poll::Ready(None)
            ));
        }
    }

    /// br-asupersync-2ovm8z: a complete request whose body contains a
    /// bare 0x0D byte (any binary upload — gRPC, protobuf, image — has
    /// 0x0D appearing in ~1/256 random bytes) must NOT poison the
    /// codec. Previously the bare-CR scan ran over the entire `src`
    /// buffer (head + body), rejecting any 0x0D in the body as
    /// BadRequestLine and tripping the codec into Poisoned state.
    #[test]
    fn ovm8z_body_with_bare_cr_byte_decodes_cleanly() {
        let mut codec = Http1Codec::new();
        // Build a request with Content-Length=4 and a body containing a
        // bare 0x0D (no \n successor) — the kind of byte sequence that
        // appears in any binary payload.
        let mut data = Vec::new();
        data.extend_from_slice(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n");
        data.extend_from_slice(&[0x42, 0x0D, 0x44, 0x45]); // 4-byte body with bare \r
        let mut buf = BytesMut::from(&data[..]);
        let result = codec.decode(&mut buf);
        assert!(
            result.is_ok(),
            "binary body with bare 0x0D must NOT poison the codec, got: {result:?}"
        );
        let req = result.unwrap().expect("complete request decodes");
        assert_eq!(
            AsRef::<[u8]>::as_ref(&req.body),
            &[0x42, 0x0D, 0x44, 0x45][..]
        );
    }

    /// br-asupersync-2ovm8z: a chunked request where the body chunk
    /// contains 0x0D bytes must also decode cleanly (covers the
    /// pipelined / chunked pathway).
    #[test]
    fn ovm8z_chunked_body_with_bare_cr_byte_does_not_poison() {
        let mut codec = Http1Codec::new();
        // Head with Transfer-Encoding: chunked, then a single chunk of 4
        // bytes containing a bare 0x0D.
        let mut data = Vec::new();
        data.extend_from_slice(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n");
        data.extend_from_slice(b"4\r\n");
        data.extend_from_slice(&[0x42, 0x0D, 0x44, 0x45]);
        data.extend_from_slice(b"\r\n0\r\n\r\n");
        let mut buf = BytesMut::from(&data[..]);
        let result = codec.decode(&mut buf);
        assert!(
            result.is_ok(),
            "chunked body with bare 0x0D must decode cleanly, got: {result:?}"
        );
    }

    /// br-asupersync-2ovm8z: bare-CR within the HEAD itself must STILL
    /// be rejected (the original smuggling-defense intent).
    #[test]
    fn ovm8z_bare_cr_in_head_still_rejected() {
        let mut codec = Http1Codec::new();
        // Bare 0x0D in the request line (not followed by \n) — must be
        // rejected as BadRequestLine.
        let data = b"GET /\rsmuggle HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut buf = BytesMut::from(&data[..]);
        let err = codec
            .decode(&mut buf)
            .expect_err("bare CR in head must still reject");
        assert!(matches!(err, HttpError::BadRequestLine));
    }

    #[test]
    fn decode_simple_get() {
        let mut codec = Http1Codec::new();
        let req = decode_one(&mut codec, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(req.method, Method::Get);
        assert_eq!(req.uri, "/");
        assert_eq!(req.version, Version::Http11);
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.headers[0].0, "Host");
        assert_eq!(req.headers[0].1, "localhost");
        assert!(req.body.is_empty());
    }

    #[test]
    fn decode_request_with_leading_blank_lines_rfc9112() {
        let mut codec = Http1Codec::new();

        // Single leading CRLF per RFC 9112 §2.2
        let req1 = decode_one(
            &mut codec,
            b"\r\nGET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .unwrap()
        .expect("single leading CRLF must be ignored");
        assert_eq!(req1.method, Method::Get);
        assert_eq!(req1.uri, "/");

        // Multiple leading CRLFs
        let req2 = decode_one(
            &mut codec,
            b"\r\n\r\n\r\nGET /multi HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .unwrap()
        .expect("multiple leading CRLFs must be ignored");
        assert_eq!(req2.method, Method::Get);
        assert_eq!(req2.uri, "/multi");

        // Only CRLFs with no request line yet yields Ok(None) (waiting for request line)
        let mut only_crlfs = BytesMut::from(&b"\r\n\r\n"[..]);
        assert!(codec.decode(&mut only_crlfs).unwrap().is_none());
        // Once request line and headers arrive, it completes successfully
        only_crlfs.extend_from_slice(b"GET /delayed HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let req3 = codec
            .decode(&mut only_crlfs)
            .unwrap()
            .expect("delayed request must decode");
        assert_eq!(req3.method, Method::Get);
        assert_eq!(req3.uri, "/delayed");

        // Streaming head decoder ignores leading CRLF
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut stream_buf =
                BytesMut::from(&b"\r\nPOST /stream HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"[..]);
            let (head, kind) = decode_streaming_request_head(&mut stream_buf, 4096, 4096)
                .unwrap()
                .expect("streaming head with leading CRLF must succeed");
            assert_eq!(head.method, Method::Post);
            assert_eq!(head.uri, "/stream");
            assert_eq!(kind, StreamingBodyKind::Empty);
        }
    }

    /// asupersync-8udzw7 (review of f5e6fda16): the RFC 9112 §2.2 allowance
    /// of empty lines before a request-line is bounded. A longer run is a
    /// malformed request, refused as soon as it passes the allowance; the
    /// unbounded skip buffered a trickled run up to 64 KiB, walking it again
    /// on every read.
    #[test]
    fn a_run_of_leading_empty_lines_past_the_allowance_is_refused_at_once() {
        let mut ten = b"\r\n".repeat(MAX_LEADING_EMPTY_LINES);
        ten.extend_from_slice(b"GET /ten HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let req = decode_one(&mut Http1Codec::new(), &ten)
            .unwrap()
            .expect("the allowed empty lines are ignored");
        assert_eq!(req.uri, "/ten");

        let mut eleven = b"\r\n".repeat(MAX_LEADING_EMPTY_LINES + 1);
        eleven.extend_from_slice(b"GET /eleven HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(matches!(
            decode_one(&mut Http1Codec::new(), &eleven),
            Err(HttpError::BadRequestLine)
        ));

        let mut codec = Http1Codec::new();
        let mut buf = BytesMut::new();
        let mut refused_at = None;
        for (fed, byte) in b"\r\n".repeat(2048).into_iter().enumerate() {
            buf.extend_from_slice(&[byte]);
            match codec.decode(&mut buf) {
                Ok(None) => {}
                Ok(Some(req)) => panic!("a run of empty lines decoded as {req:?}"),
                Err(err) => {
                    assert!(matches!(err, HttpError::BadRequestLine), "{err:?}");
                    refused_at = Some(fed + 1);
                    break;
                }
            }
        }
        let refused_at = refused_at.expect("a trickled run of empty lines must be refused");
        assert!(
            refused_at <= 2 * (MAX_LEADING_EMPTY_LINES + 2),
            "refused only after {refused_at} bytes"
        );
    }

    /// Feed `raw` one byte per decode call, as a peer trickling its request
    /// would, and return every decode result that is not `Ok(None)`.
    fn decode_trickled(codec: &mut Http1Codec, raw: &[u8]) -> Vec<Result<Request, HttpError>> {
        let mut buf = BytesMut::new();
        let mut out = Vec::new();
        for byte in raw {
            buf.extend_from_slice(&[*byte]);
            match codec.decode(&mut buf) {
                Ok(None) => {}
                Ok(Some(req)) => out.push(Ok(req)),
                Err(err) => {
                    out.push(Err(err));
                    break;
                }
            }
        }
        out
    }

    #[test]
    fn a_trickled_head_is_scanned_in_linear_time() {
        let raw = format!(
            "GET /pad HTTP/1.1\r\nHost: a\r\nX-Pad: {}\r\n\r\nGET /next HTTP/1.1\r\nHost: a\r\n\r\n",
            "p".repeat(8_000)
        );
        let mut codec = Http1Codec::new();
        let results = decode_trickled(&mut codec, raw.as_bytes());
        let uris: Vec<String> = results
            .into_iter()
            .map(|result| result.expect("valid requests").uri)
            .collect();
        assert_eq!(uris, ["/pad", "/next"]);
        // Each byte is scanned with the three before it (the terminator can
        // straddle reads): linear, where a rescan per read is quadratic.
        assert!(
            codec.head_bytes_scanned < 8 * raw.len(),
            "{} head bytes scanned for {} bytes of requests",
            codec.head_bytes_scanned,
            raw.len()
        );
    }

    #[test]
    fn a_trickled_head_reports_the_same_errors() {
        let bare_cr = decode_trickled(&mut Http1Codec::new(), b"GET / HTTP/1.1\r\nX: a\rb\r\n\r\n");
        assert!(matches!(
            bare_cr.as_slice(),
            [Err(HttpError::BadRequestLine)]
        ));

        let long_line = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_REQUEST_LINE));
        let too_long = decode_trickled(&mut Http1Codec::new(), long_line.as_bytes());
        assert!(matches!(
            too_long.as_slice(),
            [Err(HttpError::RequestLineTooLong)]
        ));

        let mut small = Http1Codec::new().max_headers_size(64);
        let big = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(100));
        let too_large = decode_trickled(&mut small, big.as_bytes());
        assert!(matches!(
            too_large.as_slice(),
            [Err(HttpError::HeadersTooLarge)]
        ));
    }

    #[test]
    fn decode_post_with_body() {
        let mut codec = Http1Codec::new();
        let raw = b"POST /data HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let req = decode_one(&mut codec, raw).unwrap().unwrap();
        assert_eq!(req.method, Method::Post);
        assert_eq!(req.uri, "/data");
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn decode_chunked_body() {
        let mut codec = Http1Codec::new();
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                     5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let req = decode_one(&mut codec, raw).unwrap().unwrap();
        assert_eq!(req.body, b"hello world");
        assert!(req.trailers.is_empty());
    }

    #[test]
    fn decode_chunked_with_extensions() {
        let mut codec = Http1Codec::new();
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                     5;ext=1\r\nhello\r\n0\r\n\r\n";
        let req = decode_one(&mut codec, raw).unwrap().unwrap();
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn chunk_size_line_search_is_bounded_like_the_buffered_codec() {
        let mut line = b"1;".to_vec();
        line.resize(MAX_CHUNK_LINE_LEN, b'a');
        line.extend_from_slice(b"\r\nX");
        assert_eq!(
            find_chunk_size_line_end(&line).unwrap(),
            Some(MAX_CHUNK_LINE_LEN)
        );

        let mut long = b"1;".to_vec();
        long.resize(MAX_CHUNK_LINE_LEN + 1, b'a');
        long.extend_from_slice(b"\r\nX");
        assert!(matches!(
            find_chunk_size_line_end(&long),
            Err(HttpError::BadChunkedEncoding)
        ));
        assert!(matches!(
            find_chunk_size_line_end(&long[..MAX_CHUNK_LINE_LEN + 2]),
            Err(HttpError::BadChunkedEncoding)
        ));
        assert_eq!(
            find_chunk_size_line_end(&long[..MAX_CHUNK_LINE_LEN + 1]).unwrap(),
            None
        );
    }

    #[test]
    fn parse_chunk_size_line_accepts_only_bare_hex_digits() {
        let accepted: &[(&[u8], usize)] = &[
            (b"0", 0),
            (b"000f", 15),
            (b"10", 16),
            (b"A;ext=1", 10),
            (b"a;name=value", 10),
            (b"5;a=\"quoted value\"", 5),
            (b"5;a=1;b", 5),
        ];
        for &(line, expected) in accepted {
            assert_eq!(
                parse_chunk_size_line(line).unwrap(),
                expected,
                "expected chunk size {expected} for {line:?}",
            );
        }

        let rejected: &[&[u8]] = &[
            b"",
            b";ext=1",
            b"+1",
            b"-1",
            b" 1",
            b"1 ",
            b"1\t",
            b"0x10",
            b"g",
            b"1\0",
            &[0xff],
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            // Control characters inside a chunk extension (RFC 9112 §7.1.1).
            b"5;ext\nX",
            b"5;ext\rX",
            b"5;a=\"q\nq\"",
            b"5;ext\x7f",
            b"5;\x00",
        ];
        for line in rejected {
            assert!(
                matches!(
                    parse_chunk_size_line(line),
                    Err(HttpError::BadChunkedEncoding)
                ),
                "expected BadChunkedEncoding for {line:?}",
            );
        }
    }

    #[test]
    fn decode_chunked_with_trailers() {
        let mut codec = Http1Codec::new();
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                     5\r\nhello\r\n0\r\nX-Trailer: one\r\nY-Trailer: two\r\n\r\n";
        let req = decode_one(&mut codec, raw).unwrap().unwrap();
        assert_eq!(req.body, b"hello");
        assert_eq!(req.trailers.len(), 2);
        assert_eq!(req.trailers[0].0, "X-Trailer");
        assert_eq!(req.trailers[0].1, "one");
    }

    /// br-asupersync-135g0e: trailers carrying RFC 9110 §6.5.1 forbidden
    /// header names must be rejected at the parser. A trailer carrying
    /// `Content-Length` or `Transfer-Encoding` is the canonical smuggling
    /// vector when downstream middleware merges trailers into the header
    /// set.
    #[test]
    fn decode_chunked_rejects_forbidden_trailers() {
        // Each entry is a forbidden trailer name. `decode_one` must reach
        // chunked-trailer parsing and return BadHeader. The set covers
        // RFC 9110 §6.5.2's restricted-fields table plus the legacy
        // hop-by-hop fields (Keep-Alive, Proxy-Connection) that share the
        // same framing-critical semantics.
        let forbidden = [
            "Content-Length",
            "Transfer-Encoding",
            "transfer-encoding",
            "TRANSFER-ENCODING",
            "Content-Encoding",
            "Content-Type",
            "Content-Range",
            "Trailer",
            "Host",
            "Authorization",
            "Cookie",
            "Set-Cookie",
            "Cache-Control",
            "Range",
            "TE",
            "Pragma",
            "Max-Forwards",
            "Expect",
            "Proxy-Authorization",
            "Proxy-Authenticate",
            "WWW-Authenticate",
            "Upgrade",
            // br-asupersync-ko0gde: hop-by-hop fields explicitly listed in
            // RFC 9110 §6.5.2's restricted-fields table. A trailer
            // `Connection: x-secret` could be coalesced into a downstream
            // proxy's header set and used as a request-smuggling primitive
            // (the proxy would then strip `x-secret` on the next hop).
            "Connection",
            "connection",
            "Keep-Alive",
            "keep-alive",
            // Not standardized but implemented by widely deployed proxies;
            // shares the same framing semantics as Connection.
            "Proxy-Connection",
            "proxy-connection",
        ];
        for name in forbidden {
            let raw = format!(
                "POST /u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n{name}: x\r\n\r\n"
            );
            let mut codec = Http1Codec::new();
            let result = decode_one(&mut codec, raw.as_bytes());
            assert!(
                matches!(result, Err(HttpError::BadHeader)),
                "expected BadHeader for forbidden trailer {name:?}, got {result:?}"
            );
        }
    }

    /// Positive control: benign trailers must still parse after the filter
    /// is in place. Drift here would silently neuter a legitimate use case.
    #[test]
    fn decode_chunked_accepts_safe_trailers() {
        let safe = [
            "X-Trailer-Checksum",
            "X-Custom-Metadata",
            "X-Request-Id",
            "ETag",
        ];
        for name in safe {
            let raw = format!(
                "POST /u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n{name}: ok\r\n\r\n"
            );
            let mut codec = Http1Codec::new();
            let req = decode_one(&mut codec, raw.as_bytes())
                .unwrap_or_else(|e| panic!("safe trailer {name:?} rejected: {e:?}"))
                .unwrap();
            assert_eq!(req.trailers.len(), 1, "expected one trailer for {name:?}");
            assert_eq!(req.trailers[0].0, name);
        }
    }

    #[test]
    fn decode_chunked_keeps_pipelined_next_request() {
        let mut codec = Http1Codec::new();
        let mut raw =
            b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec();
        raw.extend_from_slice(b"GET /next HTTP/1.1\r\nX-Long: ");
        raw.extend_from_slice(&vec![b'a'; 9000]);
        raw.extend_from_slice(b"\r\n\r\n");

        let mut buf = BytesMut::from(raw.as_slice());
        let first = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(first.method, Method::Post);
        assert_eq!(first.uri, "/upload");
        assert!(first.trailers.is_empty());
        assert!(buf.as_ref().starts_with(b"GET /next HTTP/1.1\r\n"));
    }

    #[test]
    fn decode_incomplete_returns_none() {
        let mut codec = Http1Codec::new();
        let result = decode_one(&mut codec, b"GET / HTTP/1.1\r\nHost:");
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn decode_incomplete_body_returns_none() {
        let mut codec = Http1Codec::new();
        let result = decode_one(
            &mut codec,
            b"POST /x HTTP/1.1\r\nContent-Length: 10\r\n\r\nhel",
        );
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn preview_request_head_available_before_body_bytes() {
        let raw = b"POST /upload HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let codec = Http1Codec::new();

        let preview = preview_request_head(&codec, &buf)
            .unwrap()
            .expect("header preview should be available before body bytes arrive");

        assert_eq!(preview.version, Version::Http11);
        assert_eq!(
            preview
                .headers()
                .find(|(name, _)| name.eq_ignore_ascii_case("expect"))
                .map(|(_, value)| value),
            Some(b"100-continue".as_slice())
        );
        assert_eq!(
            preview
                .headers()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value),
            Some(b"5".as_slice())
        );
        assert_eq!(buf.as_ref(), raw);

        let mut codec = Http1Codec::new();
        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert!(buf.is_empty(), "head bytes should move into codec state");

        let preview = preview_request_head(&codec, &buf)
            .unwrap()
            .expect("pending codec state should still expose request head");
        assert_eq!(preview.version, Version::Http11);
        assert_eq!(
            preview
                .headers()
                .find(|(name, _)| name.eq_ignore_ascii_case("expect"))
                .map(|(_, value)| value),
            Some(b"100-continue".as_slice())
        );
        assert_eq!(
            preview
                .headers()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value),
            Some(b"5".as_slice())
        );
    }

    #[test]
    fn borrowed_request_head_is_zero_copy_and_owned_decode_equivalent() {
        let raw = b"POST /upload?q=1 HTTP/1.1\r\nHost: example.test\r\nX-Obs: \xFFok\r\nContent-Length: 4\r\n\r\ndata";
        let codec = Http1Codec::new();
        let head = codec
            .inspect_request_head(raw)
            .unwrap()
            .expect("complete request head");

        assert_eq!(head.method, BorrowedMethod::Post);
        assert_eq!(head.uri, "/upload?q=1");
        assert_eq!(head.version, Version::Http11);
        assert_eq!(head.header_count(), 3);
        assert_eq!(head.body_kind(), StreamingBodyKind::ContentLength(4));
        assert_eq!(&raw[head.consumed_len()..], b"data");

        let input = raw.as_ptr_range();
        assert!(input.contains(&head.uri.as_ptr()));
        let borrowed_headers: Vec<_> = head.headers().collect();
        for header in &borrowed_headers {
            assert!(input.contains(&header.name.as_ptr()));
            assert!(input.contains(&header.value.as_ptr()));
        }
        assert_eq!(borrowed_headers[1].value, b"\xFFok");
        assert!(borrowed_headers[1].value_str().is_err());

        let expected_headers: Vec<_> = head
            .headers()
            .map(|header| (header.name.to_owned(), header.value_to_owned()))
            .collect();
        let mut owned_codec = Http1Codec::new();
        let owned = decode_one(&mut owned_codec, raw).unwrap().unwrap();
        assert_eq!(owned.method, head.method.into_owned());
        assert_eq!(owned.uri, head.uri);
        assert_eq!(owned.version, head.version);
        assert_eq!(owned.headers, expected_headers);
        assert_eq!(owned.body, b"data");
    }

    #[test]
    fn borrowed_and_owned_framing_reject_non_rfc_ows() {
        for content_length in [
            "\u{2003}5\u{2003}".as_bytes().to_vec(),
            vec![0xA0, b'5', 0xA0],
        ] {
            let mut raw = b"POST / HTTP/1.1\r\nContent-Length: ".to_vec();
            raw.extend_from_slice(&content_length);
            raw.extend_from_slice(b"\r\n\r\nhello");

            let codec = Http1Codec::new();
            assert!(matches!(
                codec.inspect_request_head(&raw),
                Err(HttpError::BadContentLength)
            ));

            let mut owned_codec = Http1Codec::new();
            assert!(matches!(
                decode_one(&mut owned_codec, &raw),
                Err(HttpError::BadContentLength)
            ));
        }
    }

    #[test]
    fn borrowed_request_head_is_non_consuming_and_honors_codec_limit() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let codec = Http1Codec::new();
        let before = raw.as_slice();
        assert!(codec.inspect_request_head(before).unwrap().is_some());
        assert_eq!(before, raw);

        let limited = Http1Codec::new().max_headers_size(raw.len() - 1);
        assert!(matches!(
            limited.inspect_request_head(raw),
            Err(HttpError::HeadersTooLarge)
        ));
    }

    #[test]
    fn borrowed_extension_method_stays_in_the_input_buffer() {
        let raw = b"PURGE /cache HTTP/1.1\r\n\r\n";
        let head = Http1Codec::new()
            .inspect_request_head(raw)
            .unwrap()
            .expect("complete request head");
        let BorrowedMethod::Extension(method) = head.method else {
            panic!("expected borrowed extension method, got {:?}", head.method);
        };
        assert_eq!(method, "PURGE");
        assert!(raw.as_ptr_range().contains(&method.as_ptr()));

        let mut owned_codec = Http1Codec::new();
        let owned = decode_one(&mut owned_codec, raw).unwrap().unwrap();
        assert_eq!(owned.method, Method::Extension("PURGE".to_owned()));
    }

    #[test]
    fn decode_extension_method() {
        let mut codec = Http1Codec::new();
        let req = decode_one(&mut codec, b"PURGE /cache HTTP/1.1\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(req.method, Method::Extension("PURGE".into()));
    }

    #[test]
    fn parse_request_line_fast_path() {
        let (method, uri, version) = parse_request_line_bytes(b"GET /fast HTTP/1.1").unwrap();
        assert_eq!(method, Method::Get);
        assert_eq!(uri, "/fast");
        assert_eq!(version, Version::Http11);
    }

    /// br-asupersync-w6u4cn: absolute-form (RFC 9112 §3.2.2) MUST have a
    /// non-empty authority. `http:///path` parses cleanly under split_once
    /// but has no authority and must be rejected; per-RFC the authority is
    /// the substring of `rest` before the first '/', '?', or '#'.
    #[test]
    fn parse_request_line_absolute_form_rejects_empty_authority() {
        // Empty authority shapes — must all reject.
        let empty = [
            "GET http:/// HTTP/1.1",
            "GET http:///path HTTP/1.1",
            "GET http://?query HTTP/1.1",
            "GET http://#fragment HTTP/1.1",
            "GET http:// HTTP/1.1",
        ];
        for line in empty {
            assert!(
                matches!(
                    parse_request_line_bytes(line.as_bytes()),
                    Err(HttpError::BadRequestLine)
                ),
                "expected BadRequestLine for {line:?}"
            );
        }

        // Positive controls — well-formed absolute-form must still parse.
        let ok = [
            "GET http://host/path HTTP/1.1",
            "GET http://host:8080/path HTTP/1.1",
            "GET http://user@host/p HTTP/1.1",
            "GET http://host HTTP/1.1",
            "GET https://host/p?q=1 HTTP/1.1",
        ];
        for line in ok {
            let parsed = parse_request_line_bytes(line.as_bytes());
            assert!(parsed.is_ok(), "expected Ok for {line:?}, got {parsed:?}");
        }
    }

    /// RFC 9112 §3.2.3: CONNECT requests use authority-form, specifically
    /// `host:port`. The port delimiter is not enough; the port token must be
    /// numeric so invalid authority values cannot slide through as paths.
    #[test]
    fn parse_request_line_connect_authority_requires_numeric_port() {
        let ok = [
            "CONNECT example.com:443 HTTP/1.1",
            "CONNECT localhost:8080 HTTP/1.1",
            "CONNECT [2001:db8::1]:443 HTTP/1.1",
        ];
        for line in ok {
            let parsed = parse_request_line_bytes(line.as_bytes());
            assert!(parsed.is_ok(), "expected Ok for {line:?}, got {parsed:?}");
        }

        let invalid = [
            "CONNECT example.com:http HTTP/1.1",
            "CONNECT example.com:443x HTTP/1.1",
            "CONNECT example.com: HTTP/1.1",
            "CONNECT :443 HTTP/1.1",
            "CONNECT 2001:db8::1:443 HTTP/1.1",
            "CONNECT [2001:db8::1:443 HTTP/1.1",
            "CONNECT [2001:db8::1]443 HTTP/1.1",
            "CONNECT []:443 HTTP/1.1",
            "CONNECT [2001:db8::1]: HTTP/1.1",
        ];
        for line in invalid {
            assert!(
                matches!(
                    parse_request_line_bytes(line.as_bytes()),
                    Err(HttpError::BadRequestLine)
                ),
                "expected BadRequestLine for {line:?}"
            );
        }
    }

    /// Differential vs `httparse` 1.10.x default request parsing: repeated
    /// SP delimiters are rejected unless the caller explicitly enables the
    /// lenient `allow_multiple_spaces_in_request_line_delimiters(true)` mode.
    #[test]
    fn parse_request_line_rejects_multiple_spaces_like_httparse_default() {
        let line = b"GET   /slow   HTTP/1.1";
        assert!(
            matches!(
                parse_request_line_bytes(line),
                Err(HttpError::BadRequestLine)
            ),
            "default parser should reject repeated request-line delimiters",
        );
    }

    #[test]
    fn crlf_search_matches_only_complete_pairs() {
        assert_eq!(find_crlf(b"GET / HTTP/1.1\r\nHost: example.com"), Some(14));
        assert_eq!(find_crlf(b"GET / HTTP/1.1\nHost: example.com"), None);
        assert_eq!(find_crlf(b"GET / HTTP/1.1\rHost: example.com"), None);

        let mut positions = smallvec::SmallVec::<[usize; 32]>::new();
        collect_crlf_positions(b"bad\nline\r\nnext\r\n", &mut positions);
        assert_eq!(positions.as_slice(), &[8, 14]);
    }

    #[test]
    fn decode_request_line_too_long_without_crlf() {
        let mut codec = Http1Codec::new();
        let raw = vec![b'G'; MAX_REQUEST_LINE + 1];
        let result = decode_one(&mut codec, &raw);
        assert!(matches!(result, Err(HttpError::RequestLineTooLong)));
    }

    #[test]
    fn decode_unsupported_version() {
        let mut codec = Http1Codec::new();
        let result = decode_one(&mut codec, b"GET / HTTP/2.0\r\n\r\n");
        assert!(matches!(result, Err(HttpError::UnsupportedVersion)));
    }

    #[test]
    fn decode_headers_too_large() {
        let mut codec = Http1Codec::new().max_headers_size(32);
        let result = decode_one(
            &mut codec,
            b"GET / HTTP/1.1\r\nX-Large: aaaaaaaaaaaaaaa\r\n\r\n",
        );
        assert!(matches!(result, Err(HttpError::HeadersTooLarge)));
    }

    #[test]
    fn decode_too_many_headers() {
        let mut request = b"GET / HTTP/1.1\r\n".to_vec();
        for idx in 0..=MAX_HEADERS {
            request.extend_from_slice(format!("X-{idx}: value\r\n").as_bytes());
        }
        request.extend_from_slice(b"\r\n");

        let mut codec = Http1Codec::new();
        let result = decode_one(&mut codec, &request);
        assert!(matches!(result, Err(HttpError::TooManyHeaders)));
    }

    #[test]
    fn decode_bad_content_length() {
        let mut codec = Http1Codec::new();
        let result = decode_one(
            &mut codec,
            b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
        );
        assert!(matches!(result, Err(HttpError::BadContentLength)));
    }

    #[test]
    fn reject_duplicate_content_length() {
        let mut codec = Http1Codec::new();
        let result = decode_one(
            &mut codec,
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
        );
        assert!(matches!(result, Err(HttpError::DuplicateContentLength)));
    }

    #[test]
    fn reject_duplicate_transfer_encoding() {
        let mut codec = Http1Codec::new();
        let result = decode_one(
            &mut codec,
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n\
              0\r\n\r\n",
        );
        assert!(matches!(result, Err(HttpError::DuplicateTransferEncoding)));
    }

    #[test]
    fn reject_unsupported_transfer_encoding() {
        let mut codec = Http1Codec::new();
        let result = decode_one(
            &mut codec,
            b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
        );
        assert!(matches!(result, Err(HttpError::BadTransferEncoding)));
    }

    #[test]
    fn framing_ows_is_strictly_space_or_tab() {
        // RFC 9110 defines OWS as SP / HTAB. Treating Unicode whitespace or
        // Latin-1 obs-text as OWS can make two HTTP hops disagree about the
        // framing value, which is a request-smuggling primitive.
        let content_length_cases: [&[u8]; 2] = [
            b"POST / HTTP/1.1\r\nContent-Length: \xC2\xA05\xC2\xA0\r\n\r\nhello",
            b"POST / HTTP/1.1\r\nContent-Length: \xA05\xA0\r\n\r\nhello",
        ];
        for request in content_length_cases {
            let codec = Http1Codec::new();
            assert!(matches!(
                codec.inspect_request_head(request),
                Err(HttpError::BadContentLength)
            ));

            let mut codec = Http1Codec::new();
            assert!(matches!(
                decode_one(&mut codec, request),
                Err(HttpError::BadContentLength)
            ));
        }

        let transfer_encoding_cases: [&[u8]; 2] = [
            b"POST / HTTP/1.1\r\nTransfer-Encoding: \xC2\xA0chunked\xC2\xA0\r\n\r\n0\r\n\r\n",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: \xA0chunked\xA0\r\n\r\n0\r\n\r\n",
        ];
        for request in transfer_encoding_cases {
            let codec = Http1Codec::new();
            assert!(matches!(
                codec.inspect_request_head(request),
                Err(HttpError::BadTransferEncoding)
            ));

            let mut codec = Http1Codec::new();
            assert!(matches!(
                decode_one(&mut codec, request),
                Err(HttpError::BadTransferEncoding)
            ));
        }

        let valid_ows = b"POST / HTTP/1.1\r\nContent-Length:\t 5 \t\r\n\r\nhello";
        let codec = Http1Codec::new();
        assert!(codec.inspect_request_head(valid_ows).unwrap().is_some());
        let mut codec = Http1Codec::new();
        assert!(decode_one(&mut codec, valid_ows).unwrap().is_some());

        let mut encoded = BytesMut::new();
        let mut codec = Http1Codec::new();
        let response = Response::new(200, "OK", b"hello".to_vec())
            .with_header("Content-Length", "\u{a0}5\u{a0}");
        assert!(matches!(
            codec.encode(response, &mut encoded),
            Err(HttpError::BadContentLength)
        ));

        let mut encoded = BytesMut::new();
        let mut codec = Http1Codec::new();
        let response = Response::new(200, "OK", b"hello".to_vec())
            .with_header("Transfer-Encoding", "\u{a0}chunked\u{a0}");
        assert!(matches!(
            codec.encode(response, &mut encoded),
            Err(HttpError::BadTransferEncoding)
        ));
    }

    #[test]
    fn reject_chunked_http10() {
        let mut codec = Http1Codec::new();
        let result = decode_one(
            &mut codec,
            b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        );
        assert!(matches!(result, Err(HttpError::BadTransferEncoding)));
    }

    #[test]
    fn decode_multiple_headers() {
        let mut codec = Http1Codec::new();
        let req = decode_one(
            &mut codec,
            b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(req.headers.len(), 3);
    }

    #[test]
    fn decode_http10() {
        let mut codec = Http1Codec::new();
        let req = decode_one(&mut codec, b"GET / HTTP/1.0\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(req.version, Version::Http10);
    }

    #[test]
    fn encode_simple_response() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(200, "OK", b"hello".to_vec());
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\nhello"));
    }

    /// A handler (or a proxy copying upstream headers) can put
    /// Transfer-Encoding: chunked on a 204 or 304. The terminator it wrote
    /// was read by a keep-alive client as the start of the next response.
    #[test]
    fn encode_bodyless_status_never_writes_chunked_framing() {
        for status in [103, 204, 304] {
            let mut codec = Http1Codec::new();
            let resp = Response::new(status, "", Vec::new())
                .with_header("ETag", "\"v1\"")
                .with_header("Transfer-Encoding", "chunked")
                .with_header("Trailer", "x-digest")
                .with_trailer("x-digest", "abc");
            let wire = String::from_utf8(encode_one(&mut codec, resp)).unwrap();
            assert!(wire.ends_with("ETag: \"v1\"\r\n\r\n"), "{status}: {wire:?}");
            let lower = wire.to_ascii_lowercase();
            assert!(!lower.contains("transfer-encoding"), "{status}: {wire:?}");
            assert!(!lower.contains("trailer"), "{status}: {wire:?}");
            assert!(!lower.contains("x-digest"), "{status}: {wire:?}");
        }
    }

    /// RFC 9112 6.1: chunked is undecodable for an HTTP/1.0 recipient, which
    /// would take the chunk syntax as body bytes.
    #[test]
    fn encode_http10_response_uses_content_length_instead_of_chunked() {
        let mut codec = Http1Codec::new();
        let mut resp = Response::new(200, "OK", b"hello".to_vec())
            .with_header("Transfer-Encoding", "chunked")
            .with_trailer("x-digest", "abc");
        resp.version = Version::Http10;
        let wire = String::from_utf8(encode_one(&mut codec, resp)).unwrap();
        assert_eq!(wire, "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello");

        // An HTTP/1.1 response keeps its chunked framing and trailers.
        let mut codec = Http1Codec::new();
        let resp = Response::new(200, "OK", b"hello".to_vec())
            .with_header("Transfer-Encoding", "chunked")
            .with_trailer("x-digest", "abc");
        let wire = String::from_utf8(encode_one(&mut codec, resp)).unwrap();
        assert_eq!(
            wire,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nx-digest: abc\r\n\r\n"
        );
    }

    #[test]
    fn encode_empty_body() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(204, "No Content", Vec::new());
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(!s.contains("Content-Length"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn encode_with_explicit_headers() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(200, "OK", b"{}".to_vec())
            .with_header("Content-Type", "application/json")
            .with_header("Content-Length", "2");
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Content-Type: application/json\r\n"));
        assert_eq!(s.matches("Content-Length").count(), 1);
    }

    #[test]
    fn encode_head_response_with_content_length() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(200, "OK", Vec::new()).with_header("Content-Length", "1024");
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Content-Length: 1024\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn encode_default_reason_phrase() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(404, "", Vec::new());
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn encode_chunked_response() {
        let mut codec = Http1Codec::new();
        let resp =
            Response::new(200, "OK", b"hello".to_vec()).with_header("Transfer-Encoding", "chunked");
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Transfer-Encoding: chunked\r\n"));
        assert!(!s.contains("Content-Length"));
        assert!(s.ends_with("5\r\nhello\r\n0\r\n\r\n"));
    }

    #[test]
    fn encode_chunked_response_with_trailers() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(200, "OK", b"hello".to_vec())
            .with_header("Transfer-Encoding", "chunked")
            .with_trailer("X-Trailer", "one");
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.ends_with("0\r\nX-Trailer: one\r\n\r\n"));
    }

    #[test]
    fn encode_trailers_without_chunked_is_error() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(200, "OK", b"hello".to_vec()).with_trailer("X-Trailer", "one");
        let mut buf = BytesMut::with_capacity(256);
        let err = codec.encode(resp, &mut buf).unwrap_err();
        assert!(matches!(err, HttpError::TrailersNotAllowed));
    }

    #[test]
    fn decode_sequential_requests() {
        let mut codec = Http1Codec::new();
        let raw = b"GET /a HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHost: b\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);

        let r1 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(r1.uri, "/a");

        let r2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(r2.uri, "/b");
    }

    #[test]
    fn decode_body_too_large_content_length() {
        let mut codec = Http1Codec::new().max_body_size(10);
        let raw = b"POST /data HTTP/1.1\r\nContent-Length: 100\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Err(HttpError::BodyTooLarge)));
    }

    #[test]
    fn decode_body_too_large_chunked() {
        let mut codec = Http1Codec::new().max_body_size(10);
        // Chunked body with 20 bytes total (exceeds 10 byte limit)
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                    14\r\n01234567890123456789\r\n0\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Err(HttpError::BodyTooLarge)));
    }

    #[test]
    fn decode_body_at_limit_succeeds() {
        let mut codec = Http1Codec::new().max_body_size(5);
        let raw = b"POST /data HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let req = decode_one(&mut codec, raw).unwrap().unwrap();
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn decode_chunked_body_at_limit_succeeds() {
        let mut codec = Http1Codec::new().max_body_size(11);
        // "hello world" = 11 bytes, exactly at the limit
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                     5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let req = decode_one(&mut codec, raw).unwrap().unwrap();
        assert_eq!(req.body, b"hello world");
    }

    // Security: Request smuggling protection (RFC 7230 3.3.3)
    #[test]
    fn reject_both_content_length_and_transfer_encoding() {
        let mut codec = Http1Codec::new();
        // Having both headers is a request smuggling vector
        let raw = b"POST /data HTTP/1.1\r\n\
                    Content-Length: 5\r\n\
                    Transfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n0\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Err(HttpError::AmbiguousBodyLength)));
    }

    #[test]
    fn reject_transfer_encoding_before_content_length() {
        let mut codec = Http1Codec::new();
        // Order shouldn't matter - still reject
        let raw = b"POST /data HTTP/1.1\r\n\
                    Transfer-Encoding: chunked\r\n\
                    Content-Length: 5\r\n\r\n\
                    5\r\nhello\r\n0\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Err(HttpError::AmbiguousBodyLength)));
    }

    // Security: Chunked encoding CRLF validation
    #[test]
    fn reject_invalid_crlf_after_chunk() {
        let mut codec = Http1Codec::new();
        // Invalid: "XX" instead of "\r\n" after chunk data
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhelloXX0\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Err(HttpError::BadChunkedEncoding)));
    }

    #[test]
    fn reject_invalid_trailer_header_line() {
        let mut codec = Http1Codec::new();
        // Invalid: trailer header line missing ':'.
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n0\r\nXX\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Err(HttpError::BadHeader)));
    }

    #[test]
    fn decode_obs_text_header_value() {
        let mut codec = Http1Codec::new();
        let raw = b"GET / HTTP/1.1\r\nTest-Header: \xff\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Ok(Some(_))));
    }

    /// Grammar-based fuzz test for HTTP/1.1 codec covering chunked encoding,
    /// trailers, 100-continue, HEAD body suppression, and fold pipelining.
    #[test]
    fn grammar_based_http11_features_fuzz() {
        /// HTTP/1.1 grammar-based test generator
        struct Http11Grammar {
            seed: u64,
            counter: u64,
        }

        impl Http11Grammar {
            fn new(seed: u64) -> Self {
                Self { seed, counter: 0 }
            }

            fn next_u8(&mut self) -> u8 {
                self.counter = self.counter.wrapping_add(1);
                ((self
                    .seed
                    .wrapping_add(self.counter)
                    .wrapping_mul(1103515245)
                    .wrapping_add(12345))
                    >> 16) as u8
            }

            fn next_bool(&mut self) -> bool {
                self.next_u8() & 1 == 1
            }

            fn next_choice<T: Copy>(&mut self, choices: &[T]) -> T {
                let idx = (self.next_u8() as usize) % choices.len();
                choices[idx]
            }

            /// Generate chunked encoding test case
            fn generate_chunked_request(&mut self) -> Vec<u8> {
                let mut request = Vec::new();

                // Request line
                let method = self.next_choice(&[&b"POST"[..], &b"PUT"[..], &b"PATCH"[..]]);
                request.extend_from_slice(method);
                request.extend_from_slice(b" /test HTTP/1.1\r\n");

                // Headers
                request.extend_from_slice(b"Host: example.com\r\n");
                request.extend_from_slice(b"Transfer-Encoding: chunked\r\n");

                // Expect: 100-continue (grammar condition)
                if self.next_bool() {
                    request.extend_from_slice(b"Expect: 100-continue\r\n");
                }

                request.extend_from_slice(b"\r\n");

                // Chunked body with variable chunk sizes
                let chunk_sizes = [0, 1, 5, 10, 255, 4096];
                let chunk_size = self.next_choice(&chunk_sizes);

                if chunk_size > 0 {
                    request.extend_from_slice(format!("{:x}\r\n", chunk_size).as_bytes());
                    for _ in 0..chunk_size {
                        request.push(b'A' + (self.next_u8() % 26));
                    }
                    request.extend_from_slice(b"\r\n");
                }

                // Terminal chunk
                request.extend_from_slice(b"0\r\n");

                // Trailers (grammar condition)
                if self.next_bool() {
                    let trailer_names = [
                        &b"X-Checksum"[..],
                        &b"X-Final-Status"[..],
                        &b"X-Processing-Time"[..],
                    ];
                    let trailer_name = self.next_choice(&trailer_names);
                    request.extend_from_slice(trailer_name);
                    request.extend_from_slice(b": test-value\r\n");
                }

                request.extend_from_slice(b"\r\n");
                request
            }

            /// Generate HEAD request test case for body suppression
            fn generate_head_request(&mut self) -> Vec<u8> {
                let mut request = Vec::new();

                request.extend_from_slice(b"HEAD /resource HTTP/1.1\r\n");
                request.extend_from_slice(b"Host: example.com\r\n");

                // Content-Length header that should be preserved in response
                // but body suppressed
                if self.next_bool() {
                    request.extend_from_slice(b"Accept: application/json\r\n");
                }

                request.extend_from_slice(b"\r\n");
                request
            }

            /// Generate pipelined request test case
            fn generate_pipelined_requests(&mut self) -> Vec<u8> {
                let mut requests = Vec::new();

                // First request
                requests.extend_from_slice(b"GET /first HTTP/1.1\r\n");
                requests.extend_from_slice(b"Host: example.com\r\n");
                requests.extend_from_slice(b"\r\n");

                // Second request (pipelined)
                let second_method = self.next_choice(&[&b"GET"[..], &b"HEAD"[..], &b"POST"[..]]);
                requests.extend_from_slice(second_method);
                requests.extend_from_slice(b" /second HTTP/1.1\r\n");
                requests.extend_from_slice(b"Host: example.com\r\n");

                if second_method == &b"POST"[..] {
                    requests.extend_from_slice(b"Content-Length: 4\r\n");
                    requests.extend_from_slice(b"\r\n");
                    requests.extend_from_slice(b"data");
                } else {
                    requests.extend_from_slice(b"\r\n");
                }

                requests
            }

            /// Generate folded header test case
            fn generate_folded_headers(&mut self) -> Vec<u8> {
                let mut request = Vec::new();

                request.extend_from_slice(b"GET / HTTP/1.1\r\n");
                request.extend_from_slice(b"Host: example.com\r\n");

                // Folded header (obs-fold - obsolete but sometimes encountered)
                request.extend_from_slice(b"X-Long-Header: first-part\r\n");
                request.extend_from_slice(b" second-part\r\n"); // Folded continuation

                request.extend_from_slice(b"\r\n");
                request
            }
        }

        let test_cases = [
            ("chunked_encoding", 0x1234),
            ("head_body_suppression", 0x5678),
            ("pipelined_requests", 0x9abc),
            ("folded_headers", 0xdef0),
            ("chunked_with_trailers", 0x2468),
            ("chunked_100_continue", 0xace1),
        ];

        for (test_name, seed) in &test_cases {
            let mut grammar = Http11Grammar::new(*seed);
            let mut codec = Http1Codec::new();

            let test_data = match *test_name {
                "chunked_encoding" | "chunked_with_trailers" | "chunked_100_continue" => {
                    grammar.generate_chunked_request()
                }
                "head_body_suppression" => grammar.generate_head_request(),
                "pipelined_requests" => grammar.generate_pipelined_requests(),
                "folded_headers" => grammar.generate_folded_headers(),
                _ => continue,
            };

            // Test parsing - should not panic and handle edge cases gracefully
            let result = {
                let mut buf = BytesMut::new();
                buf.extend_from_slice(&test_data);
                codec.decode(&mut buf)
            };

            match result {
                Ok(Some(request)) => {
                    // Validate grammar-specific invariants
                    match *test_name {
                        "head_body_suppression" => {
                            assert_eq!(request.method, Method::Head);
                        }
                        "chunked_encoding" | "chunked_with_trailers" | "chunked_100_continue" => {
                            // Should have chunked encoding headers
                            let has_chunked = request
                                .headers
                                .iter()
                                .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
                            if has_chunked {
                                // Validate we can parse chunked encoding structure
                            }
                        }
                        _ => {}
                    }
                }
                Ok(None) => {
                    // Incomplete data - acceptable for fuzzing
                }
                Err(err) => {
                    // Should fail gracefully with appropriate error types
                    match err {
                        HttpError::BadRequestLine
                        | HttpError::BadHeader
                        | HttpError::UnsupportedVersion
                        | HttpError::BadMethod
                        | HttpError::BadContentLength
                        | HttpError::DuplicateContentLength
                        | HttpError::DuplicateTransferEncoding
                        | HttpError::BadTransferEncoding
                        | HttpError::InvalidHeaderName
                        | HttpError::InvalidHeaderValue
                        | HttpError::HeadersTooLarge
                        | HttpError::TooManyHeaders
                        | HttpError::RequestLineTooLong
                        | HttpError::BadChunkedEncoding
                        | HttpError::BodyTooLarge
                        | HttpError::AmbiguousBodyLength
                        | HttpError::TrailersNotAllowed => {
                            // Expected error types - codec correctly rejected malformed input
                        }
                        _ => {
                            // Unexpected error type might indicate a bug
                            println!("Test '{}' produced unexpected error: {:?}", test_name, err);
                        }
                    }
                }
            }
        }

        // Additional stress test with combined features
        let mut combined_grammar = Http11Grammar::new(0xcafe);
        for _ in 0..100 {
            let mut codec = Http1Codec::new();
            let mut request = Vec::new();

            // Grammar: Method selection
            let method = combined_grammar.next_choice(&[
                &b"GET"[..],
                &b"HEAD"[..],
                &b"POST"[..],
                &b"PUT"[..],
            ]);
            request.extend_from_slice(method);
            request.extend_from_slice(b" /combined HTTP/1.1\r\n");

            // Grammar: Header combinations
            request.extend_from_slice(b"Host: test.example\r\n");

            if method == &b"POST"[..] || method == &b"PUT"[..] {
                if combined_grammar.next_bool() {
                    // Chunked
                    request.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
                    if combined_grammar.next_bool() {
                        request.extend_from_slice(b"Expect: 100-continue\r\n");
                    }
                } else {
                    // Fixed length
                    let length = combined_grammar.next_choice(&[0, 1, 10, 100]);
                    request.extend_from_slice(format!("Content-Length: {}\r\n", length).as_bytes());
                }
            }

            request.extend_from_slice(b"\r\n");

            // Test without panicking
            let mut buf = BytesMut::new();
            buf.extend_from_slice(&request);
            let _ = codec.decode(&mut buf);
        }
    }

    /// HTTP/1.1 request parsing conformance test against httparse reference implementation.
    ///
    /// This test ensures that the same byte stream produces identical (method, uri, version,
    /// headers) tuples between our implementation and the httparse reference implementation.
    /// This is Pattern 1: Differential Testing (Reference Implementation) from the
    /// testing-conformance-harnesses methodology.
    #[test]
    fn http1_codec_conformance_against_httparse() {
        /// Canonical HTTP request for conformance testing.
        #[derive(Debug, Clone)]
        struct CanonicalRequest {
            raw_bytes: Vec<u8>,
            description: String,
            expect_error: bool,
            coverage: ReferenceCoverage,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum ReferenceCoverage {
            HttparseRequestHead,
            CodecOnly,
        }

        impl CanonicalRequest {
            fn httparse_head(raw_bytes: &[u8], description: &str, expect_error: bool) -> Self {
                Self {
                    raw_bytes: raw_bytes.to_vec(),
                    description: description.to_string(),
                    expect_error,
                    coverage: ReferenceCoverage::HttparseRequestHead,
                }
            }

            fn codec_only_error(raw_bytes: &[u8], description: &str) -> Self {
                Self {
                    raw_bytes: raw_bytes.to_vec(),
                    description: description.to_string(),
                    expect_error: true,
                    coverage: ReferenceCoverage::CodecOnly,
                }
            }
        }

        /// Parsed request tuple for comparison.
        #[derive(Debug, PartialEq, Eq)]
        struct ParsedRequest {
            method: String,
            uri: String,
            version: String,
            headers: Vec<(String, String)>,
        }

        // Test cases covering various HTTP/1.1 scenarios including chunked encoding edge cases
        let test_cases = vec![
            // Basic GET request
            CanonicalRequest::httparse_head(
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "Basic GET request",
                false,
            ),

            // POST with Content-Length
            CanonicalRequest::httparse_head(
                b"POST /api/v1/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"test\":\"data\"}",
                "POST with Content-Length body",
                false,
            ),

            // Chunked encoding - basic
            CanonicalRequest::httparse_head(
                b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
                "Basic chunked encoding",
                false,
            ),

            // Chunked encoding edge case: chunk extensions
            CanonicalRequest::httparse_head(
                b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=value\r\nhello\r\n0\r\n\r\n",
                "Chunked encoding with extensions",
                false,
            ),

            // Chunked encoding edge case: zero-length chunks in middle
            CanonicalRequest::httparse_head(
                b"POST /stream HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n0\r\n\r\n3\r\nbar\r\n0\r\n\r\n",
                "Chunked encoding with zero-length chunks",
                false,
            ),

            // Complex headers with multiple values
            CanonicalRequest::httparse_head(
                b"PUT /resource HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test-client/1.0\r\nAccept: application/json, text/plain\r\nAuthorization: Bearer token123\r\nContent-Length: 0\r\n\r\n",
                "Complex headers with multiple values",
                false,
            ),

            // HTTP/1.0 version
            CanonicalRequest::httparse_head(
                b"GET /legacy HTTP/1.0\r\nHost: old.example.com\r\n\r\n",
                "HTTP/1.0 request",
                false,
            ),

            // Edge case: method with unusual but valid characters
            CanonicalRequest::httparse_head(
                b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "OPTIONS with asterisk URI",
                false,
            ),

            // Edge case: chunked with trailers
            CanonicalRequest::httparse_head(
                b"POST /data HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nX-Checksum: abc123\r\n\r\n",
                "Chunked encoding with trailers",
                false,
            ),

            // Error case: malformed request line
            CanonicalRequest::httparse_head(b"GET\r\n\r\n", "Malformed request line", true),

            // Body-semantic error: httparse only validates the request head, so this
            // stays as a direct codec assertion instead of a differential verdict.
            CanonicalRequest::codec_only_error(
                b"POST /bad HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\ndata\r\n",
                "Invalid chunk size",
            ),
        ];

        /// Parse request with our implementation.
        fn parse_with_our_codec(raw_bytes: &[u8]) -> Result<ParsedRequest, String> {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(raw_bytes);

            match codec.decode(&mut buf) {
                Ok(Some(req)) => Ok(ParsedRequest {
                    method: format!("{:?}", req.method),
                    uri: req.uri,
                    version: format!("{:?}", req.version),
                    headers: req.headers.into_iter().collect(),
                }),
                Ok(None) => Err("Incomplete request".to_string()),
                Err(e) => Err(format!("{:?}", e)),
            }
        }

        /// Parse request with httparse reference implementation.
        fn parse_with_httparse_reference(raw_bytes: &[u8]) -> Result<ParsedRequest, String> {
            let mut headers = [httparse::Header {
                name: "",
                value: &[],
            }; 64];
            let mut req = httparse::Request::new(&mut headers);

            match req.parse(raw_bytes) {
                Ok(httparse::Status::Complete(_)) => {
                    let method = req.method.ok_or("Missing method")?.to_string();
                    let uri = req.path.ok_or("Missing path")?.to_string();
                    let version = req
                        .version
                        .map(|v| {
                            if v == 1 {
                                "Http11".to_string()
                            } else {
                                "Http10".to_string()
                            }
                        })
                        .unwrap_or_else(|| "Http11".to_string());

                    let headers: Vec<(String, String)> = req
                        .headers
                        .iter()
                        .filter(|h| !h.name.is_empty())
                        .map(|h| {
                            (
                                h.name.to_string(),
                                String::from_utf8_lossy(h.value).to_string(),
                            )
                        })
                        .collect();

                    Ok(ParsedRequest {
                        method,
                        uri,
                        version,
                        headers,
                    })
                }
                Ok(httparse::Status::Partial) => Err("Partial request".to_string()),
                Err(e) => Err(format!("httparse error: {:?}", e)),
            }
        }

        let mut conformance_failures = Vec::new();
        let mut both_error_count = 0;
        let mut both_success_count = 0;

        for test_case in &test_cases {
            let our_result = parse_with_our_codec(&test_case.raw_bytes);

            if test_case.coverage == ReferenceCoverage::CodecOnly {
                match (&our_result, test_case.expect_error) {
                    (Err(_), true) => {
                        both_error_count += 1;
                    }
                    (Ok(parsed), true) => {
                        conformance_failures.push(format!(
                            "EXPECTED CODEC ERROR but our implementation succeeded: {}\n\
                             Our result: {:?}\n\
                             Raw bytes:  {:?}",
                            test_case.description,
                            parsed,
                            String::from_utf8_lossy(&test_case.raw_bytes)
                        ));
                    }
                    (Ok(_), false) => {
                        both_success_count += 1;
                    }
                    (Err(err), false) => {
                        conformance_failures.push(format!(
                            "CODEC ERROR but expected success: {}\n\
                             Our error:  {}\n\
                             Raw bytes:  {:?}",
                            test_case.description,
                            err,
                            String::from_utf8_lossy(&test_case.raw_bytes)
                        ));
                    }
                }
                continue;
            }

            let ref_result = parse_with_httparse_reference(&test_case.raw_bytes);

            match (&our_result, &ref_result, test_case.expect_error) {
                // Both implementations succeeded - compare results
                (Ok(our_parsed), Ok(ref_parsed), false) => {
                    if our_parsed == ref_parsed {
                        both_success_count += 1;
                    } else {
                        conformance_failures.push(format!(
                            "CONFORMANCE MISMATCH: {}\n\
                             Our result:  {:?}\n\
                             Ref result:  {:?}\n\
                             Raw bytes:   {:?}",
                            test_case.description,
                            our_parsed,
                            ref_parsed,
                            String::from_utf8_lossy(&test_case.raw_bytes)
                        ));
                    }
                }

                // Both implementations failed (expected for error cases)
                (Err(_), Err(_), true) => {
                    both_error_count += 1;
                }

                // Expected error but one succeeded
                (Ok(parsed), Err(err), true) => {
                    conformance_failures.push(format!(
                        "EXPECTED ERROR but our implementation succeeded: {}\n\
                         Our result: {:?}\n\
                         Ref error:  {}\n\
                         Raw bytes:  {:?}",
                        test_case.description,
                        parsed,
                        err,
                        String::from_utf8_lossy(&test_case.raw_bytes)
                    ));
                }
                (Err(err), Ok(parsed), true) => {
                    conformance_failures.push(format!(
                        "EXPECTED ERROR but reference succeeded: {}\n\
                         Our error:  {}\n\
                         Ref result: {:?}\n\
                         Raw bytes:  {:?}",
                        test_case.description,
                        err,
                        parsed,
                        String::from_utf8_lossy(&test_case.raw_bytes)
                    ));
                }

                // Unexpected success/error mismatch
                (Ok(our_parsed), Err(ref_err), false) => {
                    conformance_failures.push(format!(
                        "SUCCESS/ERROR MISMATCH: {}\n\
                         Our success: {:?}\n\
                         Ref error:   {}\n\
                         Raw bytes:   {:?}",
                        test_case.description,
                        our_parsed,
                        ref_err,
                        String::from_utf8_lossy(&test_case.raw_bytes)
                    ));
                }
                (Err(our_err), Ok(ref_parsed), false) => {
                    conformance_failures.push(format!(
                        "ERROR/SUCCESS MISMATCH: {}\n\
                         Our error:   {}\n\
                         Ref success: {:?}\n\
                         Raw bytes:   {:?}",
                        test_case.description,
                        our_err,
                        ref_parsed,
                        String::from_utf8_lossy(&test_case.raw_bytes)
                    ));
                }
                (Err(our_err), Err(ref_err), false) => {
                    conformance_failures.push(format!(
                        "BOTH ERRORED but expected success: {}\n\
                         Our error:  {}\n\
                         Ref error:  {}\n\
                         Raw bytes:  {:?}",
                        test_case.description,
                        our_err,
                        ref_err,
                        String::from_utf8_lossy(&test_case.raw_bytes)
                    ));
                }

                // Both succeeded but we expected error
                (Ok(our_parsed), Ok(ref_parsed), true) => {
                    conformance_failures.push(format!(
                        "BOTH SUCCEEDED but expected error: {}\n\
                         Our result: {:?}\n\
                         Ref result: {:?}\n\
                         Raw bytes:  {:?}",
                        test_case.description,
                        our_parsed,
                        ref_parsed,
                        String::from_utf8_lossy(&test_case.raw_bytes)
                    ));
                }
            }
        }

        // Generate conformance report
        let total_tests = test_cases.len();
        let success_rate =
            (both_success_count + both_error_count) as f64 / total_tests as f64 * 100.0;

        eprintln!(
            "HTTP/1.1 Codec Conformance Report:\n\
             - Total tests: {}\n\
             - Both succeeded: {}\n\
             - Both failed (expected): {}\n\
             - Conformance rate: {:.1}%\n\
             - Failures: {}",
            total_tests,
            both_success_count,
            both_error_count,
            success_rate,
            conformance_failures.len()
        );

        // If there are failures, create insta snapshots for debugging
        if !conformance_failures.is_empty() {
            use std::collections::BTreeMap;

            let failure_report = conformance_failures
                .into_iter()
                .enumerate()
                .map(|(i, failure)| (format!("failure_{}", i), failure))
                .collect::<BTreeMap<String, String>>();

            insta::with_settings!({
                snapshot_path => "../../tests/snapshots",
                prepend_module_to_snapshot => false,
            }, {
                insta::assert_yaml_snapshot!("http1_codec_conformance_failures", failure_report);
            });

            panic!(
                "HTTP/1.1 codec conformance test failed: {} mismatches against httparse reference.\n\
                 Check snapshot file for detailed comparison.",
                failure_report.len()
            );
        }

        // Success: perfect conformance with httparse reference
        eprintln!(
            "✅ HTTP/1.1 codec conformance test passed: {:.1}% compliance with httparse reference",
            success_rate
        );
    }
