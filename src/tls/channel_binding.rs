//! Certificate-derived channel-binding data, not certificate validation.

use super::{Certificate, TlsError};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

// Bound work before handing untrusted certificate bytes to the existing parser.
const MAX_CHANNEL_BINDING_CERTIFICATE_BYTES: usize = 1_048_576;

impl Certificate {
    /// Compute RFC 5929 `tls-server-end-point` data from this server certificate.
    ///
    /// Hashes the complete DER certificate, not its public key, signature, or
    /// TLS handshake transcript. The certificate's signature hash selects the
    /// digest; MD5 and SHA-1 signatures use SHA-256 instead. RSA PKCS#1, ECDSA,
    /// and DSA signatures using the supported SHA-2 hashes are recognized.
    /// The result is raw digest bytes, without a binding-type prefix or base64.
    ///
    /// Both endpoints must use the *server's leaf certificate actually selected
    /// for the connection*, including with mutual TLS, SNI, or certificate
    /// rotation. This certificate-only operation performs no I/O, checks no
    /// handshake state, and does not establish peer trust. A matching binding
    /// is not a substitute for the application's normal certificate validation.
    /// It is usable with TLS 1.2 and TLS 1.3; it is not `tls-unique` or the
    /// connection-specific RFC 9266 `tls-exporter` binding.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Certificate`] for malformed, oversized, trailing, or
    /// inconsistent certificate encodings. Returns [`TlsError::Configuration`]
    /// for unsupported signature algorithms, including RSASSA-PSS and EdDSA.
    /// An unknown algorithm never silently falls back to SHA-256. The method
    /// does not verify the certificate signature, name, chain, or validity time.
    pub fn tls_server_end_point_channel_binding(&self) -> Result<Vec<u8>, TlsError> {
        server_end_point(self.as_der())
    }
}

pub(super) fn server_end_point(der: &[u8]) -> Result<Vec<u8>, TlsError> {
    if der.is_empty() || der.len() > MAX_CHANNEL_BINDING_CERTIFICATE_BYTES {
        return Err(TlsError::Certificate(
            "tls-server-end-point certificate is empty or exceeds the size limit".into(),
        ));
    }
    let (remaining, certificate) = x509_parser::parse_x509_certificate(der).map_err(|_| {
        TlsError::Certificate("invalid tls-server-end-point certificate DER".into())
    })?;
    if !remaining.is_empty() {
        return Err(TlsError::Certificate(
            "trailing bytes after tls-server-end-point certificate".into(),
        ));
    }
    if certificate.signature_algorithm != certificate.tbs_certificate.signature {
        return Err(TlsError::Certificate(
            "certificate signature algorithm identifiers disagree".into(),
        ));
    }
    let algorithm = BindingHash::from_signature_oid(
        &certificate.signature_algorithm.algorithm.to_id_string(),
    )?;
    Ok(algorithm.digest(der))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingHash {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512Truncated224,
    Sha512Truncated256,
}

impl BindingHash {
    fn from_signature_oid(oid: &str) -> Result<Self, TlsError> {
        // Select the certificate signature's hash, not the public-key type or
        // TLS CertificateVerify scheme. The latter can be PSS even when a CA
        // signed this certificate using ordinary RSA PKCS#1 with SHA-256.
        match oid {
            // md5WithRSAEncryption; SHA-1 with RSA, ECDSA, DSA (including OIW).
            "1.2.840.113549.1.1.4"
            | "1.2.840.113549.1.1.5"
            | "1.2.840.10045.4.1"
            | "1.2.840.10040.4.3"
            | "1.3.14.3.2.27"
            | "1.3.14.3.2.29" => Ok(Self::Sha256),
            // SHA-224 with RSA, ECDSA, DSA.
            "1.2.840.113549.1.1.14" | "1.2.840.10045.4.3.1" | "2.16.840.1.101.3.4.3.1" => {
                Ok(Self::Sha224)
            }
            // SHA-256 with RSA, ECDSA, DSA.
            "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" | "2.16.840.1.101.3.4.3.2" => {
                Ok(Self::Sha256)
            }
            // SHA-384 with RSA, ECDSA, DSA.
            "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" | "2.16.840.1.101.3.4.3.3" => {
                Ok(Self::Sha384)
            }
            // SHA-512 with RSA, ECDSA, DSA.
            "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" | "2.16.840.1.101.3.4.3.4" => {
                Ok(Self::Sha512)
            }
            "1.2.840.113549.1.1.15" => Ok(Self::Sha512Truncated224),
            "1.2.840.113549.1.1.16" => Ok(Self::Sha512Truncated256),
            _ => Err(TlsError::Configuration(
                "unsupported certificate signature hash for tls-server-end-point".into(),
            )),
        }
    }

    fn digest(self, der: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha224 => Sha224::digest(der).to_vec(),
            Self::Sha256 => Sha256::digest(der).to_vec(),
            Self::Sha384 => Sha384::digest(der).to_vec(),
            Self::Sha512 => Sha512::digest(der).to_vec(),
            Self::Sha512Truncated224 => Sha512_224::digest(der).to_vec(),
            Self::Sha512Truncated256 => Sha512_256::digest(der).to_vec(),
        }
    }
}

#[cfg(test)]
#[path = "channel_binding_inline_tests.rs"]
mod tests;
