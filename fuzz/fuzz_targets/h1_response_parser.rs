//! HTTP/1.1 Client Response Parser Fuzzing
//!
//! This fuzzes the HTTP/1.1 client-side response parsing functionality
//! in src/http/h1/client.rs. Specifically tests Http1ClientCodec::decode
//! and Http1ClientCodec::decode_eof for parsing arbitrary HTTP response bytes.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::client::Http1ClientCodec;
use libfuzzer_sys::fuzz_target;

const MAX_DATA_SIZE: usize = 10_000_000; // 10MB limit to prevent OOM

fuzz_target!(|data: &[u8]| {
    // Size guard to prevent OOM
    if data.len() > MAX_DATA_SIZE {
        return;
    }

    // Create a fresh codec for each input
    let mut codec = Http1ClientCodec::new();

    // Copy data to BytesMut for decoding
    let mut buf = BytesMut::from(data);

    // Try to decode HTTP response - should never panic
    let _ = codec.decode(&mut buf);

    // Also test decode_eof for edge cases where connection closes mid-response
    let mut buf2 = BytesMut::from(data);
    let _ = codec.decode_eof(&mut buf2);

    // Test codec reuse after potential error
    let mut buf3 = BytesMut::from(data);
    let _ = codec.decode(&mut buf3);
});
