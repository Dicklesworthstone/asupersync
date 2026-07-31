//! Bounded, oracle-free fuzzing for the exact A4 DER residue implementation.
//!
//! The source module is included directly so this separate cargo-fuzz package
//! exercises the same implementation without widening the production API.

#![no_main]

#[path = "../../src/tls/der_min.rs"]
mod der_min;

use der_min::{
    DerError, extract_spki_der, inspect_basic_constraints_ca, inspect_pinned_leaf_shape,
    inspect_server_chain_metadata,
};
use libfuzzer_sys::fuzz_target;
use std::io::BufReader;

const MAX_CERTIFICATE_DER_BYTES: u64 = 1_048_576;
const MAX_CERTIFICATE_DER_BYTES_USIZE: usize = 1_048_576;
const MAX_PEM_CERTIFICATES_PER_INPUT: usize = 4;

fn assert_error_is_bounded<T>(result: &Result<T, DerError>, input_len: usize) {
    if let Err(error) = result {
        assert!(error.offset <= input_len);
        if let Some(detail) = error.detail {
            assert!(detail.observed <= MAX_CERTIFICATE_DER_BYTES);
            assert!(detail.limit <= MAX_CERTIFICATE_DER_BYTES);
        }
    }
}

fn exercise_der(input: &[u8]) {
    let spki_first = extract_spki_der(input);
    let spki_second = extract_spki_der(input);
    assert_eq!(spki_first, spki_second);
    assert_error_is_bounded(&spki_first, input.len());

    let root_first = inspect_basic_constraints_ca(input);
    let root_second = inspect_basic_constraints_ca(input);
    assert_eq!(root_first, root_second);
    assert_error_is_bounded(&root_first, input.len());

    let preflight_first = inspect_server_chain_metadata(input);
    let preflight_second = inspect_server_chain_metadata(input);
    assert_eq!(preflight_first, preflight_second);
    assert_error_is_bounded(&preflight_first, input.len());

    let pin_first = inspect_pinned_leaf_shape(input);
    let pin_second = inspect_pinned_leaf_shape(input);
    assert_eq!(pin_first, pin_second);
    assert_error_is_bounded(&pin_first, input.len());
}

fuzz_target!(|input: &[u8]| {
    exercise_der(input);

    if input.len() <= MAX_CERTIFICATE_DER_BYTES_USIZE
        && input.starts_with(b"-----BEGIN CERTIFICATE-----")
    {
        let mut reader = BufReader::new(input);
        for certificate in rustls_pemfile::certs(&mut reader)
            .take(MAX_PEM_CERTIFICATES_PER_INPUT)
            .flatten()
        {
            exercise_der(certificate.as_ref());
        }
    }
});
