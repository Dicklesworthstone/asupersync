#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::compress::accept_encoding_from_headers;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct HeaderPairs {
    headers: Vec<(String, String)>,
}

fuzz_target!(|input: HeaderPairs| {
    if input.headers.len() > 64 {
        return;
    }
    
    // Some headers might have long names or values, so let's bound them too
    for (name, value) in &input.headers {
        if name.len() > 1024 || value.len() > 4096 {
            return;
        }
    }

    let _ = accept_encoding_from_headers(&input.headers);
});