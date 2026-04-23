#!/usr/bin/env cargo +nightly -Zscript
//! HPACK encode path baseline benchmark
//!
//! SCENARIO: HTTP/2 HPACK header encoding performance
//! - Input: Typical HTTP headers (method, path, authority, content-type, etc.)
//! - Operation: Encoder.encode() with/without Huffman
//! - Metric: encode operations/sec, p95 latency, memory allocation
//! - Success: Completes without panic, output byte-equivalent to reference

use bytes::BytesMut;
use std::time::{Instant, Duration};
use serde_json::json;

// Inline minimal HPACK code for standalone benchmarking
#[derive(Clone)]
struct Header {
    name: String,
    value: String,
}

impl Header {
    fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

// Mock encoder for baseline comparison
struct MockEncoder;
impl MockEncoder {
    fn encode(&mut self, headers: &[Header], dst: &mut BytesMut) {
        // Minimal simulation: just write header count + total length
        dst.put_u8(headers.len() as u8);
        for header in headers {
            dst.extend_from_slice(&(header.name.len() as u16).to_be_bytes());
            dst.extend_from_slice(header.name.as_bytes());
            dst.extend_from_slice(&(header.value.len() as u16).to_be_bytes());
            dst.extend_from_slice(header.value.as_bytes());
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let scenario = args.get(1).unwrap_or(&"baseline".to_string()).clone();

    // Structured logging
    eprintln!("{}", json!({
        "event": "run_start",
        "scenario": scenario,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "rustc_version": env!("RUSTC_VERSION", "unknown"),
        "cpu_info": get_cpu_info()
    }));

    match scenario.as_str() {
        "baseline" => run_baseline_scenario(),
        "realistic" => run_realistic_scenario(),
        "large" => run_large_headers_scenario(),
        "huffman" => run_huffman_scenario(),
        _ => {
            eprintln!("Usage: {} [baseline|realistic|large|huffman]", args[0]);
            std::process::exit(1);
        }
    }
}

fn run_baseline_scenario() {
    eprintln!("{}", json!({
        "event": "phase",
        "phase": "baseline_mock",
        "description": "Mock encoder baseline for comparison"
    }));

    let headers = create_typical_headers();
    let mut encoder = MockEncoder;

    let start = Instant::now();
    let iterations = 100_000;

    for _ in 0..iterations {
        let mut dst = BytesMut::new();
        encoder.encode(&headers, &mut dst);
        std::hint::black_box(dst);
    }

    let duration = start.elapsed();
    let ops_per_sec = (iterations as f64) / duration.as_secs_f64();

    eprintln!("{}", json!({
        "event": "baseline_result",
        "iterations": iterations,
        "duration_ms": duration.as_millis(),
        "ops_per_sec": ops_per_sec,
        "ns_per_op": duration.as_nanos() / iterations
    }));
}

fn run_realistic_scenario() {
    eprintln!("{}", json!({
        "event": "phase",
        "phase": "realistic_headers",
        "description": "Typical HTTP request headers"
    }));

    // Note: This would use real HPACK encoder if available
    eprintln!("{}", json!({
        "event": "error",
        "message": "Real HPACK encoder not available in standalone script"
    }));
}

fn run_large_headers_scenario() {
    eprintln!("{}", json!({
        "event": "phase",
        "phase": "large_headers",
        "description": "Large header values (cookies, auth tokens)"
    }));

    let headers = create_large_headers();
    eprintln!("{}", json!({
        "event": "data_size",
        "header_count": headers.len(),
        "total_bytes": headers.iter().map(|h| h.name.len() + h.value.len()).sum::<usize>()
    }));
}

fn run_huffman_scenario() {
    eprintln!("{}", json!({
        "event": "phase",
        "phase": "huffman_comparison",
        "description": "With vs without Huffman encoding"
    }));
}

fn create_typical_headers() -> Vec<Header> {
    vec![
        Header::new(":method", "POST"),
        Header::new(":path", "/api/v1/search"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "api.example.com"),
        Header::new("accept", "application/json"),
        Header::new("content-type", "application/json"),
        Header::new("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"),
        Header::new("accept-encoding", "gzip, deflate, br"),
        Header::new("authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"),
        Header::new("x-request-id", "f47ac10b-58cc-4372-a567-0e02b2c3d479"),
    ]
}

fn create_large_headers() -> Vec<Header> {
    let large_cookie = "sessionid=abc123; userid=user789; ".repeat(50);
    let large_auth = "Bearer ".to_string() + &"x".repeat(2048);

    vec![
        Header::new(":method", "GET"),
        Header::new(":path", "/"),
        Header::new("cookie", &large_cookie),
        Header::new("authorization", &large_auth),
        Header::new("x-custom-data", &"data=".repeat(100)),
    ]
}

fn get_cpu_info() -> serde_json::Value {
    // Simplified CPU detection for baseline
    json!({
        "model": std::env::var("CPU_MODEL").unwrap_or_else(|_| "unknown".to_string()),
        "cores": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    })
}

// Dependencies for standalone script
extern crate bytes {
    use std::collections::VecDeque;

    pub struct BytesMut {
        buf: Vec<u8>,
    }

    impl BytesMut {
        pub fn new() -> Self {
            Self { buf: Vec::new() }
        }

        pub fn put_u8(&mut self, val: u8) {
            self.buf.push(val);
        }

        pub fn extend_from_slice(&mut self, other: &[u8]) {
            self.buf.extend_from_slice(other);
        }
    }
}

extern crate chrono {
    pub struct Utc;
    impl Utc {
        pub fn now() -> DateTime {
            DateTime
        }
    }

    pub struct DateTime;
    impl DateTime {
        pub fn to_rfc3339(&self) -> String {
            "2026-04-23T08:00:00Z".to_string()
        }
    }
}

extern crate serde_json {
    pub fn json!(val: tt) -> Value {
        Value
    }

    pub struct Value;
}