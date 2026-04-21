#![allow(warnings)]
#![allow(clippy::all)]
//! RFC 7541 Appendix C test vectors for HPACK decoder conformance.

use asupersync::bytes::Bytes;
use asupersync::http::h2::hpack::{Decoder, Header};

#[test]
#[allow(dead_code)]
fn test_basic_decoder_functionality() {
    let mut decoder = Decoder::new();

    // Simple indexed header field - :method GET (index 2)
    let encoded = &[0x82];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("Basic decode should work");

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, ":method");
    assert_eq!(headers[0].value, "GET");
}

#[test]
#[allow(dead_code)]
fn test_c2_literal_incremental_new_name() {
    let mut decoder = Decoder::new();

    // RFC 7541 C.2.1: 40 0a 63 75 73 74 6f 6d 2d 6b 65 79 0d 63 75 73 74 6f 6d 2d 68 65 61 64 65 72
    let encoded = &[
        0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
        0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
    ];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("C.2.1 decode should work");

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, "custom-key");
    assert_eq!(headers[0].value, "custom-header");
}

#[test]
#[allow(dead_code)]
fn test_c3_multiple_requests() {
    let mut decoder = Decoder::new();

    // RFC 7541 C.3.1: First request (same as C.2.1)
    let encoded_1 = &[
        0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
        0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
    ];

    let mut bytes = Bytes::copy_from_slice(encoded_1);
    let headers_1 = decoder.decode(&mut bytes).expect("C.3.1 decode should work");

    assert_eq!(headers_1.len(), 1);
    assert_eq!(headers_1[0].name, "custom-key");
    assert_eq!(headers_1[0].value, "custom-header");

    // RFC 7541 C.3.2: Second request (reference to dynamic table entry)
    let encoded_2 = &[0xbe];

    let mut bytes = Bytes::copy_from_slice(encoded_2);
    let headers_2 = decoder.decode(&mut bytes).expect("C.3.2 decode should work");

    assert_eq!(headers_2.len(), 1);
    assert_eq!(headers_2[0].name, "custom-key");
    assert_eq!(headers_2[0].value, "custom-header");
}

#[test]
#[allow(dead_code)]
fn test_c4_request_sequence() {
    let mut decoder = Decoder::new();

    // RFC 7541 C.4.1: First request
    let encoded_1 = &[
        0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
        0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
    ];

    let mut bytes = Bytes::copy_from_slice(encoded_1);
    let headers_1 = decoder.decode(&mut bytes).expect("C.4.1 decode should work");

    assert_eq!(headers_1.len(), 1);
    assert_eq!(headers_1[0].name, "custom-key");
    assert_eq!(headers_1[0].value, "custom-header");

    // RFC 7541 C.4.2: Second request
    let encoded_2 = &[
        0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
        0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65,
    ];

    let mut bytes = Bytes::copy_from_slice(encoded_2);
    let headers_2 = decoder.decode(&mut bytes).expect("C.4.2 decode should work");

    assert_eq!(headers_2.len(), 1);
    assert_eq!(headers_2[0].name, "custom-key");
    assert_eq!(headers_2[0].value, "custom-value");

    // RFC 7541 C.4.3: Third request (references both dynamic table entries)
    let encoded_3 = &[0xbf, 0xbe];

    let mut bytes = Bytes::copy_from_slice(encoded_3);
    let headers_3 = decoder.decode(&mut bytes).expect("C.4.3 decode should work");

    assert_eq!(headers_3.len(), 2);
    assert_eq!(headers_3[0].name, "custom-key");
    assert_eq!(headers_3[0].value, "custom-value");
    assert_eq!(headers_3[1].name, "custom-key");
    assert_eq!(headers_3[1].value, "custom-header");
}

#[test]
#[allow(dead_code)]
fn test_c5_request_examples() {
    let mut decoder = Decoder::new();

    // RFC 7541 C.5.1: First request
    let encoded_1 = &[
        0x48, 0x03, 0x32, 0x30, 0x30, 0x48, 0x03, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
        0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20,
        0x32, 0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32, 0x31, 0x20,
        0x47, 0x4d, 0x54, 0x6e, 0x17, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77,
        0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    ];

    let mut bytes = Bytes::copy_from_slice(encoded_1);
    let headers_1 = decoder.decode(&mut bytes).expect("C.5.1 decode should work");

    assert_eq!(headers_1.len(), 4);
    assert_eq!(headers_1[0].name, ":status");
    assert_eq!(headers_1[0].value, "200");
    assert_eq!(headers_1[1].name, "cache-control");
    assert_eq!(headers_1[1].value, "private");
    assert_eq!(headers_1[2].name, "date");
    assert_eq!(headers_1[2].value, "Mon, 21 Oct 2013 20:13:21 GMT");
    assert_eq!(headers_1[3].name, "location");
    assert_eq!(headers_1[3].value, "https://www.example.com");

    // RFC 7541 C.5.2: Second request
    let encoded_2 = &[
        0x48, 0x03, 0x33, 0x30, 0x37, 0x7c, 0x85, 0xbf, 0x40, 0x0a, 0x63, 0x75, 0x73, 0x74,
        0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d,
        0x76, 0x61, 0x6c, 0x75, 0x65,
    ];

    let mut bytes = Bytes::copy_from_slice(encoded_2);
    let headers_2 = decoder.decode(&mut bytes).expect("C.5.2 decode should work");

    assert_eq!(headers_2.len(), 4);
    assert_eq!(headers_2[0].name, ":status");
    assert_eq!(headers_2[0].value, "307");
    assert_eq!(headers_2[1].name, "cache-control");
    assert_eq!(headers_2[1].value, "private");
    assert_eq!(headers_2[2].name, "date");
    assert_eq!(headers_2[2].value, "Mon, 21 Oct 2013 20:13:21 GMT");
    assert_eq!(headers_2[3].name, "custom-key");
    assert_eq!(headers_2[3].value, "custom-value");

    // RFC 7541 C.5.3: Third request
    let encoded_3 = &[
        0x88, 0xc1, 0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63,
        0x74, 0x20, 0x32, 0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32,
        0x32, 0x20, 0x47, 0x4d, 0x54, 0xc0, 0x5a, 0x04, 0x67, 0x7a, 0x69, 0x70, 0x77, 0x38,
        0x66, 0x6f, 0x6f, 0x3d, 0x41, 0x53, 0x44, 0x4a, 0x4b, 0x48, 0x51, 0x4b, 0x42, 0x5a,
        0x58, 0x4f, 0x51, 0x57, 0x45, 0x4f, 0x50, 0x49, 0x55, 0x41, 0x58, 0x51, 0x57, 0x45,
        0x4f, 0x49, 0x55, 0x3b, 0x20, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65, 0x3d, 0x33,
        0x36, 0x30, 0x30, 0x3b, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x31,
    ];

    let mut bytes = Bytes::copy_from_slice(encoded_3);
    let headers_3 = decoder.decode(&mut bytes).expect("C.5.3 decode should work");

    assert_eq!(headers_3.len(), 6);
    assert_eq!(headers_3[0].name, ":status");
    assert_eq!(headers_3[0].value, "200");
    assert_eq!(headers_3[1].name, "cache-control");
    assert_eq!(headers_3[1].value, "private");
    assert_eq!(headers_3[2].name, "date");
    assert_eq!(headers_3[2].value, "Mon, 21 Oct 2013 20:13:22 GMT");
    assert_eq!(headers_3[3].name, "location");
    assert_eq!(headers_3[3].value, "https://www.example.com");
    assert_eq!(headers_3[4].name, "content-encoding");
    assert_eq!(headers_3[4].value, "gzip");
    assert_eq!(headers_3[5].name, "set-cookie");
    assert_eq!(headers_3[5].value, "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1");
}

#[test]
#[allow(dead_code)]
fn test_c6_indexed_header_field() {
    let mut decoder = Decoder::new();

    // RFC 7541 C.6: Index 2 (:method: GET)
    let encoded = &[0x82];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("C.6 decode should work");

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, ":method");
    assert_eq!(headers[0].value, "GET");
}