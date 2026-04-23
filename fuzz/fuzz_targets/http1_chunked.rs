#![no_main]

use libfuzzer_sys::fuzz_target;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError};

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

    // Call decode repeatedly until it returns None or Error
    loop {
        // Run under a panic catch block to be defensive
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            codec.decode(&mut buf)
        }));
        
        match res {
            Ok(Ok(Some(_req))) => {
                // Successfully decoded the request. 
                // If there's pipelined data, we could keep going, but one is enough.
                break;
            }
            Ok(Ok(None)) => {
                // Incomplete input.
                break;
            }
            Ok(Err(_e)) => {
                // Valid rejection (e.g. invalid hex, too large chunk, bad CRLF)
                break;
            }
            Err(e) => {
                std::panic::resume_unwind(e); // Panic is a bug
            }
        }
    }
});