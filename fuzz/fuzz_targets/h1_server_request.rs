#![no_main]

use libfuzzer_sys::fuzz_target;
use asupersync::bytes::BytesMut;
use asupersync::http::h1::codec::Http1Codec;

// Maximum data size to prevent timeouts on extremely large inputs
const MAX_DATA_SIZE: usize = 10 * 1024 * 1024; // 10MB

fuzz_target!(|data: &[u8]| {
    // Size guard to prevent timeout on massive inputs
    if data.len() > MAX_DATA_SIZE {
        return;
    }

    // Create a new codec instance for each test
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(data);

    // Test request parsing - must not panic
    let _ = codec.decode(&mut buf);

    // Test multiple decode calls on the same buffer (simulates pipelined requests)
    let _ = codec.decode(&mut buf);

    // Test with different buffer sizes to trigger boundary conditions
    if data.len() > 1 {
        let mut small_buf = BytesMut::from(&data[..1]);
        let _ = codec.decode(&mut small_buf);
    }

    // Test with mid-sized buffer
    if data.len() > 100 {
        let mid = data.len() / 2;
        let mut mid_buf = BytesMut::from(&data[..mid]);
        let _ = codec.decode(&mut mid_buf);
    }

    // Test codec with different size limits
    let mut small_headers_codec = Http1Codec::new().max_headers_size(256);
    let mut small_body_codec = Http1Codec::new().max_body_size(256);

    let mut buf_copy1 = BytesMut::from(data);
    let mut buf_copy2 = BytesMut::from(data);

    let _ = small_headers_codec.decode(&mut buf_copy1);
    let _ = small_body_codec.decode(&mut buf_copy2);
});