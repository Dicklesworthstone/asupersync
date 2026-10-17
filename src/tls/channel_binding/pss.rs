//! RFC 4055 signature parameters for RFC 5929 certificate bindings.
//!
//! This is a bounded schema walk over the existing DER decoder, not a second
//! certificate parser or a signature verifier. In particular, signature salt
//! suitability, key restrictions and certificate trust remain with rustls.

use super::{BindingHash, TlsError};
use x509_parser::asn1_rs::{Any, Class, FromDer, Tag};

const MAX_PARAMETERS_BYTES: usize = 1024;
const MGF1_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PssHash {
    Sha1,
    Sha2(BindingHash),
}

pub(super) fn binding_hash(parameters: Option<&Any<'_>>) -> Result<BindingHash, TlsError> {
    // Signature parameters MUST be present, unlike PSS public-key parameters.
    let parameters = parameters.ok_or_else(malformed)?;
    expect_type(parameters, Tag::Sequence, true)?;
    if parameters.as_bytes().len() > MAX_PARAMETERS_BYTES {
        return Err(malformed());
    }
    let mut remaining = parameters.as_bytes();
    let mut last_tag = None;
    let mut message_hash = PssHash::Sha1;
    let mut mask_hash = PssHash::Sha1;
    while !remaining.is_empty() {
        let (rest, field) = Any::from_der(remaining).map_err(|_| malformed())?;
        let tag = field.tag().0;
        if field.class() != Class::ContextSpecific
            || !field.header.is_constructed()
            || tag > 3
            || last_tag.is_some_and(|previous| tag <= previous)
        {
            return Err(malformed());
        }
        last_tag = Some(tag);
        // Each EXPLICIT wrapper contains exactly one complete DER value.
        let inner = complete_value(field.as_bytes())?;
        match tag {
            0 => message_hash = hash_identifier(&inner)?,
            1 => {
                let (oid, hash) = algorithm_parts(&inner)?;
                if oid != MGF1_OID {
                    return Err(TlsError::Configuration(
                        "unsupported PSS mask generator for tls-server-end-point".into(),
                    ));
                }
                // An explicit MGF1 requires its own HashAlgorithm parameter;
                // an omitted maskGenAlgorithm alone gets the SHA-1 default.
                mask_hash = hash_identifier(&hash.ok_or_else(malformed)?)?;
            }
            2 => {
                nonnegative_integer(&inner)?;
            }
            3 => {
                if nonnegative_integer(&inner)? != [1] {
                    return Err(malformed());
                }
            }
            _ => unreachable!("PSS context tag was checked above"),
        }
        remaining = rest;
    }
    // Compare identities BEFORE SHA-1's binding-hash upgrade. Otherwise a
    // SHA-256/MGF1-SHA-1 signature would incorrectly look single-hash.
    if message_hash != mask_hash {
        return Err(TlsError::Configuration(
            "tls-server-end-point is undefined for PSS with different message and MGF1 hashes"
                .into(),
        ));
    }
    Ok(match message_hash {
        PssHash::Sha1 => BindingHash::Sha256,
        PssHash::Sha2(hash) => hash,
    })
}

fn malformed() -> TlsError {
    TlsError::Certificate("invalid RSASSA-PSS parameters for tls-server-end-point".into())
}

fn expect_type(value: &Any<'_>, tag: Tag, constructed: bool) -> Result<(), TlsError> {
    if value.class() != Class::Universal
        || value.tag() != tag
        || value.header.is_constructed() != constructed
        || value.header.assert_definite().is_err()
    {
        return Err(malformed());
    }
    Ok(())
}

fn complete_value(bytes: &[u8]) -> Result<Any<'_>, TlsError> {
    let (remaining, value) = Any::from_der(bytes).map_err(|_| malformed())?;
    if !remaining.is_empty() {
        return Err(malformed());
    }
    Ok(value)
}

fn algorithm_parts<'a>(value: &Any<'a>) -> Result<(&'a [u8], Option<Any<'a>>), TlsError> {
    expect_type(value, Tag::Sequence, true)?;
    let (remaining, oid) = Any::from_der(value.as_bytes()).map_err(|_| malformed())?;
    expect_type(&oid, Tag::Oid, false)?;
    let parameter = if remaining.is_empty() {
        None
    } else {
        Some(complete_value(remaining)?)
    };
    Ok((oid.as_bytes(), parameter))
}

fn hash_identifier(value: &Any<'_>) -> Result<PssHash, TlsError> {
    let (oid, parameter) = algorithm_parts(value)?;
    // RFC 4055 section 2.1 requires accepting both absent and NULL hash
    // parameters. Arbitrary values, constructed NULLs and trailing fields
    // do not describe the same hash algorithm.
    if let Some(parameter) = parameter {
        expect_type(&parameter, Tag::Null, false)?;
        if !parameter.as_bytes().is_empty() {
            return Err(malformed());
        }
    }
    let hash = match oid {
        [0x2b, 0x0e, 0x03, 0x02, 0x1a] => PssHash::Sha1,
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04] => {
            PssHash::Sha2(BindingHash::Sha224)
        }
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => {
            PssHash::Sha2(BindingHash::Sha256)
        }
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => {
            PssHash::Sha2(BindingHash::Sha384)
        }
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => {
            PssHash::Sha2(BindingHash::Sha512)
        }
        _ => {
            return Err(TlsError::Configuration(
                "unsupported PSS hash for tls-server-end-point".into(),
            ));
        }
    };
    Ok(hash)
}

fn nonnegative_integer<'a>(value: &Any<'a>) -> Result<&'a [u8], TlsError> {
    expect_type(value, Tag::Integer, false)?;
    let bytes = value.as_bytes();
    let Some(&first) = bytes.first() else {
        return Err(malformed());
    };
    if first & 0x80 != 0
        || (bytes.len() > 1 && first == 0 && bytes[1] & 0x80 == 0)
    {
        return Err(malformed());
    }
    // No allocation or conversion proportional to the salt length. This
    // method only checks its encoding, not signature or RSA-modulus validity.
    Ok(bytes)
}

#[cfg(test)]
#[path = "pss_tests.rs"]
mod tests;
