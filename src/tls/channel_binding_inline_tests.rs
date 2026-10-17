//! Certificate-fact tests. Mutated signature identifiers deliberately do not
//! create trusted certificates; this API computes bindings, not signatures.

use super::{BindingHash, Certificate, MAX_CHANNEL_BINDING_CERTIFICATE_BYTES, TlsError};

fn certificate() -> Certificate {
    Certificate::from_pem(include_bytes!("../../tests/fixtures/tls/server.crt"))
        .expect("fixture PEM")
        .into_iter()
        .next()
        .expect("fixture leaf")
}

fn signature_offsets(der: &[u8]) -> Vec<usize> {
    let oid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    let offsets = der
        .windows(oid.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == oid).then_some(offset + oid.len() - 1))
        .collect::<Vec<_>>();
    assert_eq!(offsets.len(), 2, "inner and outer fixture signature OIDs");
    offsets
}

fn with_signature_oid(last: u8) -> Certificate {
    let mut der = certificate().as_der().to_vec();
    for offset in signature_offsets(&der) {
        der[offset] = last;
    }
    Certificate::from_der(der)
}

#[test]
fn certificate_binding_matches_independent_full_der_digest_vectors() {
    // Computed independently with Python's OpenSSL-backed hashlib, from the
    // complete fixture DER after replacing BOTH RSA signature OID suffixes.
    // These pins distinguish SHA-224 from SHA-512/224 (and SHA-256 from
    // SHA-512/256), and distinguish a full-certificate hash from an SPKI hash.
    for (oid, expected) in [
        (4, "99f0eee5afe728d2ad397eedb7d6070dd225614f2a10a09ce9fabfb455cb8d12"),
        (5, "8eb84760315a0f35be7fd5eb7c5657e38c5a22b04afe835f04973eb18c6b5f69"),
        (11, "0d83c852d9cfe254ceddae68a155b12bdbe13bc6293bec041c3a13d6519bfa4b"),
        (12, "4fd46049d8a656d262e3f28e4508a25a7c4996992b77284a0ce085c0548025ea1d1538c62871a90e1a52a9ff93d332a8"),
        (13, "f381ac28748e461423cb19ed80c075935e923aff70be6934bcfa09cbdce5adfc61ee2300d0a95c0af2b9c1832c153efd5b6076b9702e5fc0de7e071ed674928c"),
        (14, "406246e95f84594a6a8433dff59d276cf03ea159c80c6fae9bbd7076"),
        (15, "d1dd959df5a7337e3673246d9899514f3afb75529e54e7c8371d802e"),
        (16, "fda58c913982c734d5fe1b8fe25df4eb7a3235e78360a10de0c11aab53b5f4c5"),
    ] {
        assert_eq!(
            with_signature_oid(oid)
                .tls_server_end_point_channel_binding()
                .expect("supported signature hash"),
            hex::decode(expected).expect("digest vector"),
            "RSA signature OID suffix {oid}",
        );
    }
}

#[test]
fn sha1_signatures_upgrade_but_sha2_signatures_keep_their_hash() {
    for oid in [
        "1.2.840.113549.1.1.4",
        "1.2.840.113549.1.1.5",
        "1.2.840.10045.4.1",
        "1.2.840.10040.4.3",
        "1.3.14.3.2.27",
        "1.3.14.3.2.29",
    ] {
        assert_eq!(BindingHash::from_signature_oid(oid).unwrap(), BindingHash::Sha256);
    }
    for (rsa, ec, dsa, expected) in [
        ("1.2.840.113549.1.1.14", "1.2.840.10045.4.3.1", "2.16.840.1.101.3.4.3.1", BindingHash::Sha224),
        ("1.2.840.113549.1.1.11", "1.2.840.10045.4.3.2", "2.16.840.1.101.3.4.3.2", BindingHash::Sha256),
        ("1.2.840.113549.1.1.12", "1.2.840.10045.4.3.3", "2.16.840.1.101.3.4.3.3", BindingHash::Sha384),
        ("1.2.840.113549.1.1.13", "1.2.840.10045.4.3.4", "2.16.840.1.101.3.4.3.4", BindingHash::Sha512),
    ] {
        for oid in [rsa, ec, dsa] {
            assert_eq!(BindingHash::from_signature_oid(oid).unwrap(), expected, "{oid}");
        }
    }
}

#[test]
fn unsupported_algorithms_never_become_sha256_by_default() {
    for oid in [
        "1.2.840.113549.1.1.1", // RSA public-key OID is not a signature hash.
        "1.2.840.113549.1.1.10", // PSS requires a separately parsed hash parameter.
        "1.3.101.112", // Ed25519 has no RFC 5929 single signature hash.
        "1.3.101.113", // Ed448 likewise.
        "1.2.3.4.5",
        "",
    ] {
        assert!(matches!(
            BindingHash::from_signature_oid(oid),
            Err(TlsError::Configuration(_))
        ));
    }
    assert!(matches!(
        with_signature_oid(127).tls_server_end_point_channel_binding(),
        Err(TlsError::Configuration(_))
    ));
}

#[test]
fn rejects_mismatched_inner_and_outer_signature_algorithms() {
    let mut der = certificate().as_der().to_vec();
    let offsets = signature_offsets(&der);
    der[offsets[1]] = 12;
    assert!(matches!(
        Certificate::from_der(der).tls_server_end_point_channel_binding(),
        Err(TlsError::Certificate(_))
    ));
}

#[test]
fn rejects_every_truncated_prefix_and_trailing_bytes() {
    let original = certificate();
    for length in 0..original.as_der().len() {
        assert!(matches!(
            Certificate::from_der(original.as_der()[..length].to_vec())
                .tls_server_end_point_channel_binding(),
            Err(TlsError::Certificate(_))
        ), "truncated length {length}");
    }
    for suffix in [&b"\0"[..], original.as_der()] {
        let mut der = original.as_der().to_vec();
        der.extend_from_slice(suffix);
        assert!(matches!(
            Certificate::from_der(der).tls_server_end_point_channel_binding(),
            Err(TlsError::Certificate(_))
        ));
    }
}

#[test]
fn certificate_size_is_bounded_before_parsing() {
    assert!(matches!(
        Certificate::from_der(vec![0; MAX_CHANNEL_BINDING_CERTIFICATE_BYTES + 1])
            .tls_server_end_point_channel_binding(),
        Err(TlsError::Certificate(_))
    ));
}

#[test]
fn binding_includes_signature_bytes_and_is_repeatable() {
    let original = certificate();
    let expected = original.tls_server_end_point_channel_binding().unwrap();
    assert_eq!(expected, original.tls_server_end_point_channel_binding().unwrap());
    let mut der = original.as_der().to_vec();
    *der.last_mut().unwrap() ^= 1;
    assert_ne!(
        expected,
        Certificate::from_der(der).tls_server_end_point_channel_binding().unwrap()
    );
}
