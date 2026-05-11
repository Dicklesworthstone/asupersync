#![no_main]

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::Http1Codec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return; // Bound size to prevent OOM
    }

    // Set max body size to allow large chunks but fail gracefully if they exceed limit
    let mut codec = Http1Codec::new().max_body_size(1024 * 1024);
    let mut buf = BytesMut::new();

    // Inject a valid request header block for chunked encoding
    buf.extend_from_slice(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
    // Append fuzzed data which will be parsed as chunked body
    buf.extend_from_slice(data);

    // Run one decode under a panic catch block to be defensive.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| codec.decode(&mut buf)));

    match res {
        Ok(Ok(Some(_req))) => {
            // Successfully decoded the request.
        }
        Ok(Ok(None)) => {
            // Incomplete input.
        }
        Ok(Err(_e)) => {
            // Valid rejection (e.g. invalid hex, too large chunk, bad CRLF)
        }
        Err(e) => {
            std::panic::resume_unwind(e); // Panic is a bug
        }
    }
});
