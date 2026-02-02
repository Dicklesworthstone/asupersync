//! Protocol benchmark suite for Asupersync.
//!
//! Benchmarks the performance of protocol implementations:
//! - HTTP/1.1: Request parsing, response serialization
//! - HTTP/2: HPACK compression, frame parsing
//! - WebSocket: Frame encoding/decoding, masking
//!
//! Performance targets:
//! - HTTP/1 request parsing: < 500ns for typical GET request
//! - HPACK header decoding: < 1μs for typical header block
//! - WebSocket frame parsing: < 100ns for data frames

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::Decoder;
use asupersync::http::h1::Http1Codec;
use asupersync::http::h2::{Header, HpackDecoder, HpackEncoder};
use asupersync::net::websocket::{FrameCodec, Role};

// =============================================================================
// HTTP/1.1 BENCHMARKS
// =============================================================================

/// Sample HTTP/1.1 GET request for benchmarking.
const SIMPLE_GET_REQUEST: &[u8] = b"GET /api/v1/users HTTP/1.1\r\n\
Host: example.com\r\n\
User-Agent: bench/1.0\r\n\
Accept: application/json\r\n\
Accept-Encoding: gzip, deflate\r\n\
Connection: keep-alive\r\n\
\r\n";

/// HTTP/1.1 POST request with body.
const POST_REQUEST_WITH_BODY: &[u8] = b"POST /api/v1/data HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Type: application/json\r\n\
Content-Length: 45\r\n\
\r\n\
{\"name\":\"test\",\"value\":42,\"active\":true}";

/// HTTP/1.1 request with many headers.
fn request_with_many_headers(header_count: usize) -> Vec<u8> {
    let mut request = b"GET /api/test HTTP/1.1\r\nHost: example.com\r\n".to_vec();
    for i in 0..header_count {
        request.extend_from_slice(format!("X-Custom-Header-{i}: value-{i}\r\n").as_bytes());
    }
    request.extend_from_slice(b"\r\n");
    request
}

fn bench_http1_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("http1/parse");

    // Simple GET request
    group.throughput(Throughput::Bytes(SIMPLE_GET_REQUEST.len() as u64));
    group.bench_function("simple_get", |b| {
        b.iter_batched(
            || {
                let codec = Http1Codec::new();
                let buf = BytesMut::from(SIMPLE_GET_REQUEST);
                (codec, buf)
            },
            |(mut codec, mut buf)| {
                let result = codec.decode(&mut buf);
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    // POST request with body
    group.throughput(Throughput::Bytes(POST_REQUEST_WITH_BODY.len() as u64));
    group.bench_function("post_with_body", |b| {
        b.iter_batched(
            || {
                let codec = Http1Codec::new();
                let buf = BytesMut::from(POST_REQUEST_WITH_BODY);
                (codec, buf)
            },
            |(mut codec, mut buf)| {
                let result = codec.decode(&mut buf);
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    // Requests with varying header counts
    for &header_count in &[5, 20, 50] {
        let request = request_with_many_headers(header_count);
        group.throughput(Throughput::Bytes(request.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("headers", header_count),
            &request,
            |b, request| {
                b.iter_batched(
                    || {
                        let codec = Http1Codec::new();
                        let buf = BytesMut::from(&request[..]);
                        (codec, buf)
                    },
                    |(mut codec, mut buf)| {
                        let result = codec.decode(&mut buf);
                        black_box(result)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// HPACK BENCHMARKS (HTTP/2)
// =============================================================================

/// Typical HTTP/2 request headers.
fn typical_request_headers() -> Vec<Header> {
    vec![
        Header::new(":method", "GET"),
        Header::new(":path", "/api/v1/users"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.com"),
        Header::new("accept", "application/json"),
        Header::new("accept-encoding", "gzip, deflate, br"),
        Header::new("accept-language", "en-US,en;q=0.9"),
        Header::new("user-agent", "Mozilla/5.0 (compatible; Bench/1.0)"),
    ]
}

/// Typical HTTP/2 response headers.
fn typical_response_headers() -> Vec<Header> {
    vec![
        Header::new(":status", "200"),
        Header::new("content-type", "application/json; charset=utf-8"),
        Header::new("content-length", "1234"),
        Header::new("cache-control", "max-age=3600"),
        Header::new("date", "Sun, 01 Feb 2026 00:00:00 GMT"),
        Header::new("server", "asupersync/0.1.0"),
    ]
}

fn bench_hpack_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("hpack/encode");

    // Encode typical request headers
    group.bench_function("request_headers", |b| {
        let headers = typical_request_headers();
        b.iter_batched(
            || {
                let encoder = HpackEncoder::new();
                let buf = BytesMut::with_capacity(256);
                (encoder, headers.clone(), buf)
            },
            |(mut encoder, headers, mut buf)| {
                encoder.encode(&headers, &mut buf);
                black_box(buf.len())
            },
            BatchSize::SmallInput,
        )
    });

    // Encode typical response headers
    group.bench_function("response_headers", |b| {
        let headers = typical_response_headers();
        b.iter_batched(
            || {
                let encoder = HpackEncoder::new();
                let buf = BytesMut::with_capacity(256);
                (encoder, headers.clone(), buf)
            },
            |(mut encoder, headers, mut buf)| {
                encoder.encode(&headers, &mut buf);
                black_box(buf.len())
            },
            BatchSize::SmallInput,
        )
    });

    // Benchmark repeated encoding (dynamic table optimization)
    group.bench_function("repeated_headers", |b| {
        let headers = typical_request_headers();
        let mut encoder = HpackEncoder::new();
        let mut buf = BytesMut::with_capacity(256);

        // Warm up the dynamic table
        for _ in 0..10 {
            buf.clear();
            encoder.encode(&headers, &mut buf);
        }

        b.iter(|| {
            buf.clear();
            encoder.encode(&headers, &mut buf);
            black_box(buf.len())
        })
    });

    group.finish();
}

fn bench_hpack_decoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("hpack/decode");

    // Pre-encode headers for decoding benchmarks
    let request_headers = typical_request_headers();
    let response_headers = typical_response_headers();

    let mut encoder = HpackEncoder::new();
    let mut encoded_request_buf = BytesMut::with_capacity(256);
    encoder.encode(&request_headers, &mut encoded_request_buf);
    let encoded_request: Bytes = encoded_request_buf.freeze();

    let mut encoded_response_buf = BytesMut::with_capacity(256);
    encoder.encode(&response_headers, &mut encoded_response_buf);
    let encoded_response: Bytes = encoded_response_buf.freeze();

    // Decode request headers
    group.throughput(Throughput::Bytes(encoded_request.len() as u64));
    group.bench_function("request_headers", |b| {
        b.iter_batched(
            || {
                let decoder = HpackDecoder::new();
                (decoder, encoded_request.clone())
            },
            |(mut decoder, mut encoded): (HpackDecoder, Bytes)| {
                let result = decoder.decode(&mut encoded);
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    // Decode response headers
    group.throughput(Throughput::Bytes(encoded_response.len() as u64));
    group.bench_function("response_headers", |b| {
        b.iter_batched(
            || {
                let decoder = HpackDecoder::new();
                (decoder, encoded_response.clone())
            },
            |(mut decoder, mut encoded): (HpackDecoder, Bytes)| {
                let result = decoder.decode(&mut encoded);
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    // Benchmark with varying dynamic table sizes
    for &table_size in &[256, 4096, 16384] {
        group.bench_with_input(
            BenchmarkId::new("table_size", table_size),
            &table_size,
            |b, &table_size| {
                b.iter_batched(
                    || {
                        let decoder = HpackDecoder::with_max_size(table_size);
                        (decoder, encoded_request.clone())
                    },
                    |(mut decoder, mut encoded): (HpackDecoder, Bytes)| {
                        let result = decoder.decode(&mut encoded);
                        black_box(result)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// WEBSOCKET BENCHMARKS
// =============================================================================

/// Create a WebSocket binary frame with masking.
fn create_ws_frame(payload_len: usize, masked: bool) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload_len);

    // First byte: FIN=1, opcode=0x2 (binary)
    frame.push(0x82);

    // Second byte: MASK bit + length
    let mask_bit = if masked { 0x80 } else { 0x00 };

    if payload_len < 126 {
        frame.push(mask_bit | (payload_len as u8));
    } else if payload_len < 65536 {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        frame.push(mask_bit | 127);
        frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
    }

    // Masking key (if masked)
    if masked {
        frame.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    }

    // Payload
    frame.extend(std::iter::repeat(0xAB).take(payload_len));

    frame
}

fn bench_websocket_frame(c: &mut Criterion) {
    let mut group = c.benchmark_group("websocket/frame");

    // Frame parsing for different payload sizes
    for &size in &[64, 1024, 8192, 65536] {
        let frame = create_ws_frame(size, true);
        group.throughput(Throughput::Bytes(frame.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("parse_masked", size),
            &frame,
            |b, frame| {
                b.iter_batched(
                    || {
                        let codec = FrameCodec::new(Role::Server);
                        let buf = BytesMut::from(&frame[..]);
                        (codec, buf)
                    },
                    |(mut codec, mut buf)| {
                        let result = codec.decode(&mut buf);
                        black_box(result)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Unmasked frame parsing (server-to-client)
    for &size in &[64, 1024, 8192] {
        let frame = create_ws_frame(size, false);
        group.throughput(Throughput::Bytes(frame.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("parse_unmasked", size),
            &frame,
            |b, frame| {
                b.iter_batched(
                    || {
                        let codec = FrameCodec::new(Role::Client);
                        let buf = BytesMut::from(&frame[..]);
                        (codec, buf)
                    },
                    |(mut codec, mut buf)| {
                        let result = codec.decode(&mut buf);
                        black_box(result)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// THROUGHPUT BENCHMARKS
// =============================================================================

fn bench_protocol_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol/throughput");
    group.sample_size(50);

    // HTTP/1 request parsing throughput
    for &count in &[100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("http1_requests", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    for _ in 0..count {
                        let mut codec = Http1Codec::new();
                        let mut buf = BytesMut::from(SIMPLE_GET_REQUEST);
                        let result = codec.decode(&mut buf);
                        let _ = black_box(result);
                    }
                })
            },
        );
    }

    // HPACK encode/decode throughput
    let headers = typical_request_headers();
    for &count in &[100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("hpack_roundtrips", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    let mut encoder = HpackEncoder::new();
                    let mut decoder = HpackDecoder::new();
                    let mut buf = BytesMut::with_capacity(256);

                    for _ in 0..count {
                        buf.clear();
                        encoder.encode(&headers, &mut buf);
                        // Convert BytesMut to Bytes for decoding
                        let mut encoded = Bytes::from(buf.as_ref().to_vec());
                        let decoded = decoder.decode(&mut encoded);
                        let _ = black_box(decoded);
                    }
                })
            },
        );
    }

    group.finish();
}

// =============================================================================
// MAIN
// =============================================================================

criterion_group!(
    benches,
    bench_http1_parsing,
    bench_hpack_encoding,
    bench_hpack_decoding,
    bench_websocket_frame,
    bench_protocol_throughput,
);

criterion_main!(benches);
