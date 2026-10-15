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

    observe_accept_encoding(&input.headers);
});

fn observe_accept_encoding(headers: &[(String, String)]) {
    let observed = accept_encoding_from_headers(headers);
    let expected = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
        .map(|(_, value)| value.as_str());

    assert_eq!(
        observed, expected,
        "accept-encoding extraction did not return the first matching header"
    );

    if let Some(value) = observed {
        assert!(
            headers.iter().any(|(name, candidate)| {
                name.eq_ignore_ascii_case("accept-encoding") && candidate == value
            }),
            "accept-encoding observer returned a value absent from the input"
        );
    }
}
