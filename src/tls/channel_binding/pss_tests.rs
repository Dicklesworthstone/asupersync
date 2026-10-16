//! PSS schema and full-certificate regression cases. Certificate mutations
//! below deliberately do not produce trusted signatures.

use super::{BindingHash, MAX_PARAMETERS_BYTES, binding_hash, complete_value};
use crate::tls::{Certificate, TlsError};
use x509_parser::asn1_rs::{Any, FromDer};

const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const SHA224: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 4];
const SHA256: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];
const SHA384: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 2];
const SHA512: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 3];
const MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 8];
const PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 10];

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut encoded = vec![tag];
    if content.len() < 128 {
        encoded.push(u8::try_from(content.len()).unwrap());
    } else {
        let length = content.len().to_be_bytes();
        let first = length.iter().position(|byte| *byte != 0).unwrap();
        encoded.push(0x80 | u8::try_from(length.len() - first).unwrap());
        encoded.extend_from_slice(&length[first..]);
    }
    encoded.extend_from_slice(content);
    encoded
}

fn algorithm(oid: &[u8], parameter: Option<&[u8]>) -> Vec<u8> {
    let mut content = tlv(0x06, oid);
    if let Some(parameter) = parameter {
        content.extend_from_slice(parameter);
    }
    tlv(0x30, &content)
}

fn parameters(hash: Option<&[u8]>, mask: Option<&[u8]>, null: bool) -> Vec<u8> {
    let null_parameter = null.then_some(&[0x05, 0][..]);
    let mut content = Vec::new();
    if let Some(hash) = hash {
        content.extend(tlv(0xa0, &algorithm(hash, null_parameter)));
    }
    if let Some(mask) = mask {
        content.extend(tlv(
            0xa1,
            &algorithm(MGF1, Some(&algorithm(mask, null_parameter))),
        ));
    }
    tlv(0x30, &content)
}

fn classify(encoded: &[u8]) -> Result<BindingHash, TlsError> {
    binding_hash(Some(&complete_value(encoded)?))
}

fn malformed(encoded: &[u8]) {
    assert!(
        matches!(classify(encoded), Err(TlsError::Certificate(_))),
        "expected a malformed parameter error for {encoded:02x?}",
    );
}

fn unsupported(encoded: &[u8]) {
    assert!(
        matches!(classify(encoded), Err(TlsError::Configuration(_))),
        "expected an unsupported binding error for {encoded:02x?}",
    );
}

fn children(sequence: &[u8]) -> Vec<&[u8]> {
    let (tail, sequence) = Any::from_der(sequence).unwrap();
    assert!(tail.is_empty());
    let mut remaining = sequence.as_bytes();
    let mut children = Vec::new();
    while !remaining.is_empty() {
        let (tail, _) = Any::from_der(remaining).unwrap();
        children.push(&remaining[..remaining.len() - tail.len()]);
        remaining = tail;
    }
    children
}

fn certificate_with_parameters(inner: Option<&[u8]>, outer: Option<&[u8]>) -> Certificate {
    let certificate = Certificate::from_pem(include_bytes!("../../../tests/fixtures/tls/server.crt"))
        .unwrap()
        .remove(0);
    let fields = children(certificate.as_der());
    assert_eq!(fields.len(), 3);
    let tbs = children(fields[0]);
    let mut tbs_content = Vec::new();
    for (index, field) in tbs.iter().enumerate() {
        if index == 2 {
            tbs_content.extend(algorithm(PSS, inner));
        } else {
            tbs_content.extend_from_slice(field);
        }
    }
    let mut content = tlv(0x30, &tbs_content);
    content.extend(algorithm(PSS, outer));
    content.extend_from_slice(fields[2]);
    Certificate::from_der(tlv(0x30, &content))
}

#[test]
fn defaults_and_explicit_sha1_use_sha256_without_a_hash_substitution_mismatch() {
    assert_eq!(classify(&[0x30, 0]).unwrap(), BindingHash::Sha256);
    for null in [false, true] {
        for (hash, mask) in [(None, Some(SHA1)), (Some(SHA1), None), (Some(SHA1), Some(SHA1))] {
            assert_eq!(classify(&parameters(hash, mask, null)).unwrap(), BindingHash::Sha256);
        }
    }
    assert!(matches!(binding_hash(None), Err(TlsError::Certificate(_))));
    malformed(&[0x05, 0]); // absent PSS fields != absent or NULL PSS parameters
}

#[test]
fn supported_sha2_hashes_accept_absent_and_null_algorithm_parameters() {
    for (oid, expected) in [
        (SHA224, BindingHash::Sha224),
        (SHA256, BindingHash::Sha256),
        (SHA384, BindingHash::Sha384),
        (SHA512, BindingHash::Sha512),
    ] {
        for null in [false, true] {
            assert_eq!(classify(&parameters(Some(oid), Some(oid), null)).unwrap(), expected);
        }
    }
}

#[test]
fn different_message_and_mask_hashes_are_rejected_before_sha1_upgrade() {
    for (hash, mask) in [
        (Some(SHA256), None),
        (None, Some(SHA256)),
        (Some(SHA256), Some(SHA1)),
        (Some(SHA1), Some(SHA256)),
        (Some(SHA384), Some(SHA256)),
    ] {
        unsupported(&parameters(hash, mask, true));
    }
}

#[test]
fn mask_generator_and_hash_algorithms_fail_closed() {
    unsupported(&parameters(Some(&[0x2a, 3, 4]), Some(SHA256), true));
    unsupported(&parameters(Some(SHA256), Some(&[0x2a, 3, 4]), true));
    let wrong_mgf = algorithm(&[0x2a, 3, 4], Some(&algorithm(SHA256, None)));
    unsupported(&tlv(0x30, &tlv(0xa1, &wrong_mgf)));
    malformed(&tlv(0x30, &tlv(0xa1, &algorithm(MGF1, None))));
    malformed(&tlv(0x30, &tlv(0xa1, &algorithm(MGF1, Some(&[5, 0])))));
    let invalid_hash_parameter = algorithm(SHA256, Some(&[4, 0]));
    malformed(&tlv(0x30, &tlv(0xa0, &invalid_hash_parameter)));
    let constructed_null = algorithm(SHA256, Some(&[0x25, 0]));
    malformed(&tlv(0x30, &tlv(0xa0, &constructed_null)));
}

#[test]
fn duplicate_reordered_unknown_and_implicit_fields_are_rejected() {
    let hash = tlv(0xa0, &algorithm(SHA256, None));
    let mask = tlv(0xa1, &algorithm(MGF1, Some(&algorithm(SHA256, None))));
    for content in [
        [hash.clone(), hash.clone()].concat(),
        [mask, hash.clone()].concat(),
        tlv(0xa4, &[5, 0]),
        tlv(0x80, &algorithm(SHA256, None)),
        tlv(0x60, &algorithm(SHA256, None)),
        tlv(0xa0, &[]),
        tlv(0xa0, &[algorithm(SHA256, None), vec![5, 0]].concat()),
        tlv(0xa0, &tlv(0x30, &[tlv(6, SHA256), vec![5, 0, 5, 0]].concat())),
    ] {
        malformed(&tlv(0x30, &content));
    }
    malformed(&tlv(0x10, &hash)); // primitive SEQUENCE
    malformed(&tlv(0x70, &hash)); // application-class SEQUENCE
}

#[test]
fn salt_and_trailer_encodings_are_validated_without_allocating_the_salt() {
    for salt in [vec![0], vec![1], vec![20], vec![0, 0x80], vec![0, 0xff]] {
        let encoded = tlv(0x30, &tlv(0xa2, &tlv(2, &salt)));
        assert_eq!(classify(&encoded).unwrap(), BindingHash::Sha256);
    }
    for salt in [vec![], vec![0x80], vec![0xff], vec![0, 1], vec![0, 0]] {
        malformed(&tlv(0x30, &tlv(0xa2, &tlv(2, &salt))));
    }
    malformed(&tlv(0x30, &tlv(0xa2, &[0x22, 1, 1])));
    assert_eq!(classify(&tlv(0x30, &tlv(0xa3, &[2, 1, 1]))).unwrap(), BindingHash::Sha256);
    for trailer in [0, 2, 0xff] {
        malformed(&tlv(0x30, &tlv(0xa3, &[2, 1, trailer])));
    }
}

#[test]
fn incomplete_non_der_trailing_and_oversized_parameters_are_rejected() {
    let encoded = parameters(Some(SHA384), Some(SHA384), true);
    for length in 0..encoded.len() {
        malformed(&encoded[..length]);
    }
    malformed(&[encoded, vec![5, 0]].concat());
    malformed(&[0x30, 0x80, 0, 0]); // indefinite length
    malformed(&tlv(0x30, &vec![0; MAX_PARAMETERS_BYTES + 1]));
}

#[test]
fn public_certificate_binding_matches_independent_asn1_and_hashlib_vectors() {
    // ASN.1-aware certificate mutation using Python asn1crypto, then OpenSSL-
    // backed hashlib over the full DER. Existing signature bytes are retained:
    // these are hash-selection vectors, not certificate-validation fixtures.
    for (encoded, expected) in [
        ("3000", "bd8fc56de941595e5add84af5f3b59987d78c95b7b654c78b4b3f605ca648700"),
        ("3034a00f300d06096086480165030402040500a11c301a06092a864886f70d010108300d06096086480165030402040500a20302011c", "24807cabef8655fa3602f9be52f1aa4fb20d4c65d4a471b711eab136"),
        ("3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120", "abfb1836035c402260a1f0fab8700006307ece405c89d0bf3cda6a14669864b8"),
        ("3034a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130", "e368362203355cd75460a538678c1c7ede2ec180327b33def487a55c7d612e132560a873b1ca1b00588d7cdec52f8144"),
        ("3034a00f300d06096086480165030402030500a11c301a06092a864886f70d010108300d06096086480165030402030500a203020140", "ab53a3e0fb69b02ec89503badd50207d14c400a71a287979bd4fe5cbcb1daab8bac34c18420f8246af70067831d906d2ac56c3bfffe11221e95afa75e04ffa38"),
    ] {
        let encoded = hex::decode(encoded).unwrap();
        let certificate = certificate_with_parameters(Some(&encoded), Some(&encoded));
        let binding = certificate.tls_server_end_point_channel_binding().unwrap();
        assert_eq!(binding, hex::decode(expected).unwrap());
        assert_eq!(binding, certificate.tls_server_end_point_channel_binding().unwrap());
    }
}

#[test]
fn public_certificate_binding_rejects_missing_mismatched_and_ambiguous_parameters() {
    let sha256 = parameters(Some(SHA256), Some(SHA256), true);
    let sha384 = parameters(Some(SHA384), Some(SHA384), true);
    for (inner, outer) in [
        (None, None),
        (Some(&sha256[..]), None),
        (Some(&sha256[..]), Some(&sha384[..])),
    ] {
        assert!(matches!(
            certificate_with_parameters(inner, outer).tls_server_end_point_channel_binding(),
            Err(TlsError::Certificate(_)),
        ));
    }
    let ambiguous = parameters(Some(SHA256), None, true);
    assert!(matches!(
        certificate_with_parameters(Some(&ambiguous), Some(&ambiguous))
            .tls_server_end_point_channel_binding(),
        Err(TlsError::Configuration(_)),
    ));
}
