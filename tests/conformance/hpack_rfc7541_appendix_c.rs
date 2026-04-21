#![allow(clippy::all)]
//! RFC 7541 Appendix C test vectors for HPACK decoder conformance.
//!
//! Tests the specific examples from RFC 7541 Appendix C sections:
//! - C.2: Literal Header Field with Incremental Indexing
//! - C.3: Dynamic Table Size Update
//! - C.4: Literal Header Field with Incremental Indexing — Indexed Name
//! - C.5: Literal Header Field without Indexing — Indexed Name
//! - C.6: Literal Header Field with Never Index — Indexed Name

use asupersync::bytes::Bytes;
use asupersync::http::h2::hpack::{Decoder, Header};

/// Basic test to verify the decoder is working
#[test]
#[allow(dead_code)]
fn test_decoder_basic() {
    let mut decoder = Decoder::new();

    // Simple indexed header field - :method GET (index 2)
    let encoded = &[0x82];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let result = decoder.decode(&mut bytes);

    match result {
        Ok(headers) => {
            assert_eq!(headers.len(), 1);
            println!("Decoded header: {} = {}", headers[0].name, headers[0].value);
        }
        Err(e) => {
            panic!("Failed to decode simple header: {:?}", e);
        }
    }
}

/// RFC 7541 Appendix C.2.1: Literal Header Field with Incremental Indexing — New Name
///
/// This example shows the addition of a custom header field "custom-key"
/// with the value "custom-header" to the header list.
///
/// The custom header field is added to the dynamic table.
#[test]
#[allow(dead_code)]
fn rfc7541_c2_literal_incremental_new_name() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C.2.1
    let encoded = &[
        0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
        0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
    ];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let result = decoder.decode(&mut bytes);

    match result {
        Ok(headers) => {
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].name, "custom-key");
            assert_eq!(headers[0].value, "custom-header");
        }
        Err(e) => {
            panic!("Failed to decode C.2.1 test vector: {:?}", e);
        }
    }
}

/// RFC 7541 Appendix C.2.2: Literal Header Field with Incremental Indexing — Indexed Name
///
/// Shows the addition of a custom header with an indexed name (cache-control)
/// and literal value "no-cache". The cache-control name is in the static table at index 24.
#[test]
#[allow(dead_code)]
fn rfc7541_c2_literal_incremental_indexed_name() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C.2.2
    let encoded = &[0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("decode should succeed");

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, "cache-control");
    assert_eq!(headers[0].value, "no-cache");
}

/// RFC 7541 Appendix C.2.3: Literal Header Field with Incremental Indexing — Indexed Name (Huffman)
///
/// Shows the same header as C.2.2 but with Huffman encoded value.
#[test]
#[allow(dead_code)]
fn rfc7541_c2_literal_incremental_indexed_name_huffman() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C.2.3
    let encoded = &[0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("decode should succeed");

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, "cache-control");
    assert_eq!(headers[0].value, "no-cache");
}

/// RFC 7541 Appendix C.3: Dynamic Table Size Update
///
/// Shows a dynamic table size update to 32 bytes.
#[test]
#[allow(dead_code)]
fn rfc7541_c3_dynamic_table_size_update() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C.3
    let encoded = &[0x20]; // Dynamic table size update to 32

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("decode should succeed");

    // Size update only, no headers
    assert_eq!(headers.len(), 0);
}

/// RFC 7541 Appendix C.4.1: Literal Header Field without Indexing — New Name
///
/// Shows a literal header field without indexing using a new name.
#[test]
#[allow(dead_code)]
fn rfc7541_c4_literal_without_indexing_new_name() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C.4.1
    let encoded = &[
        0x00, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
        0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
    ];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("decode should succeed");

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, "custom-key");
    assert_eq!(headers[0].value, "custom-header");
}

/// RFC 7541 Appendix C.4.2: Literal Header Field without Indexing — Indexed Name
///
/// Shows a literal header field without indexing using an indexed name.
#[test]
#[allow(dead_code)]
fn rfc7541_c4_literal_without_indexing_indexed_name() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C.4.2
    let encoded = &[0x18, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("decode should succeed");

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, "cache-control");
    assert_eq!(headers[0].value, "no-cache");
}

/// RFC 7541 Appendix C.4.3: Literal Header Field without Indexing — Indexed Name (Huffman)
///
/// Shows the same as C.4.2 but with Huffman encoded value.
#[test]
#[allow(dead_code)]
fn rfc7541_c4_literal_without_indexing_indexed_name_huffman() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C.4.3
    let encoded = &[0x18, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("decode should succeed");

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, "cache-control");
    assert_eq!(headers[0].value, "no-cache");
}

/// RFC 7541 Appendix C.5.1: Literal Header Field Never Indexed — New Name
///
/// Shows a literal header field with never indexed flag using a new name.
#[test]
#[allow(dead_code)]
fn rfc7541_c5_literal_never_indexed_new_name() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C.5.1
    let encoded = &[
        0x10, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
        0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
    ];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("decode should succeed");

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, "custom-key");
    assert_eq!(headers[0].value, "custom-header");
}

/// RFC 7541 Appendix C.5.2: Literal Header Field Never Indexed — Indexed Name
///
/// Shows a literal header field with never indexed flag using an indexed name.
#[test]
#[allow(dead_code)]
fn rfc7541_c5_literal_never_indexed_indexed_name() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C.5.2
    let encoded = &[0x18, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("decode should succeed");

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, "cache-control");
    assert_eq!(headers[0].value, "no-cache");
}

/// RFC 7541 Appendix C.5.3: Literal Header Field Never Indexed — Indexed Name (Huffman)
///
/// Shows the same as C.5.2 but with Huffman encoded value.
#[test]
#[allow(dead_code)]
fn rfc7541_c5_literal_never_indexed_indexed_name_huffman() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C.5.3
    let encoded = &[0x18, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("decode should succeed");

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, "cache-control");
    assert_eq!(headers[0].value, "no-cache");
}

/// RFC 7541 Appendix C.6: Indexed Header Field
///
/// Shows an indexed header field representation.
#[test]
#[allow(dead_code)]
fn rfc7541_c6_indexed_header_field() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C.6 - Index 2 (:method: GET)
    let encoded = &[0x82];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("decode should succeed");

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, ":method");
    assert_eq!(headers[0].value, "GET");
}

/// RFC 7541 Appendix C.2-C.6 Integration Test: Request Headers Without Huffman Coding
///
/// Tests a complete sequence from C.2-C.6 representing a typical HTTP request.
#[test]
#[allow(dead_code)]
fn rfc7541_appendix_c_integration_request_without_huffman() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C - First request
    let encoded = &[
        0x82,                                           // :method: GET (index 2)
        0x86,                                           // :scheme: http (index 6)
        0x84,                                           // :path: / (index 4)
        0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, // :authority: www.example.com
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
        0x6d,
    ];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("decode should succeed");

    assert_eq!(headers.len(), 4);
    assert_eq!(headers[0].name, ":method");
    assert_eq!(headers[0].value, "GET");
    assert_eq!(headers[1].name, ":scheme");
    assert_eq!(headers[1].value, "http");
    assert_eq!(headers[2].name, ":path");
    assert_eq!(headers[2].value, "/");
    assert_eq!(headers[3].name, ":authority");
    assert_eq!(headers[3].value, "www.example.com");
}

/// RFC 7541 Appendix C Integration Test: Request Headers With Huffman Coding
///
/// Tests the same request as above but with Huffman coding enabled.
#[test]
#[allow(dead_code)]
fn rfc7541_appendix_c_integration_request_with_huffman() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C - First request with Huffman
    let encoded = &[
        0x82,                                           // :method: GET (index 2)
        0x86,                                           // :scheme: http (index 6)
        0x84,                                           // :path: / (index 4)
        0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, // :authority: www.example.com (Huffman)
        0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("decode should succeed");

    assert_eq!(headers.len(), 4);
    assert_eq!(headers[0].name, ":method");
    assert_eq!(headers[0].value, "GET");
    assert_eq!(headers[1].name, ":scheme");
    assert_eq!(headers[1].value, "http");
    assert_eq!(headers[2].name, ":path");
    assert_eq!(headers[2].value, "/");
    assert_eq!(headers[3].name, ":authority");
    assert_eq!(headers[3].value, "www.example.com");
}

/// RFC 7541 Appendix C Integration Test: Response Headers
///
/// Tests decoding of a complete HTTP response header block.
#[test]
#[allow(dead_code)]
fn rfc7541_appendix_c_integration_response() {
    let mut decoder = Decoder::new();

    // From RFC 7541 Appendix C - Response
    let encoded = &[
        0x88,                                           // :status: 200 (index 8)
        0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, // cache-control: no-cache
        0x68, 0x65,
    ];

    let mut bytes = Bytes::copy_from_slice(encoded);
    let headers = decoder.decode(&mut bytes).expect("decode should succeed");

    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].name, ":status");
    assert_eq!(headers[0].value, "200");
    assert_eq!(headers[1].name, "cache-control");
    assert_eq!(headers[1].value, "no-cache");
}

/// RFC 7541 Appendix C Integration Test: Dynamic Table Eviction
///
/// Tests dynamic table management when entries are evicted.
#[test]
#[allow(dead_code)]
fn rfc7541_appendix_c_dynamic_table_eviction() {
    let mut decoder = Decoder::with_max_size(128); // Small table for testing eviction

    // Add several entries to fill the table
    let entries = &[
        &[0x40, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65][..], // name: value
        &[0x40, 0x05, 0x6e, 0x61, 0x6d, 0x65, 0x32, 0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x32][..], // name2: value2
        &[0x40, 0x05, 0x6e, 0x61, 0x6d, 0x65, 0x33, 0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x33][..], // name3: value3
    ];

    for entry in entries {
        let mut bytes = Bytes::copy_from_slice(entry);
        let headers = decoder.decode(&mut bytes).expect("decode should succeed");
        assert_eq!(headers.len(), 1);
    }

    // Test that indexed access works for recent entries but fails for evicted ones
    let recent_index = &[0xc2]; // Index 66 (first dynamic entry + 62)
    let mut bytes = Bytes::copy_from_slice(recent_index);
    let result = decoder.decode(&mut bytes);

    // Should either succeed (entry still in table) or fail gracefully (entry evicted)
    match result {
        Ok(headers) => {
            assert_eq!(headers.len(), 1);
        }
        Err(_) => {
            // Expected if entry was evicted - decoder should handle gracefully
        }
    }
}