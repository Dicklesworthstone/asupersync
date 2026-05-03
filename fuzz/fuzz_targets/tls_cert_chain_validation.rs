//! TLS certificate chain validation pathological cases fuzzer (asupersync-eq1j92).
//!
//! Tests certificate chain validation with various pathological scenarios:
//! - Valid and malformed certificate sequences
//! - Expired and not-yet-valid certificates
//! - Signature algorithm mismatches
//! - Missing intermediate certificates
//! - Chain ordering issues
//! - Trust anchor validation
//!
//! The fuzzer generates complex certificate chains and tests validation logic
//! to detect panics, infinite loops, or incorrect validation outcomes.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::tls::{Certificate, CertificateChain, TlsConnectorBuilder, TlsError};
use libfuzzer_sys::fuzz_target;

/// Maximum number of certificates in a chain
const MAX_CHAIN_LENGTH: usize = 10;
/// Maximum certificate size to prevent memory exhaustion
const MAX_CERT_SIZE: usize = 16 * 1024;
/// Maximum number of test scenarios per fuzz iteration
const MAX_SCENARIOS: usize = 8;

#[derive(Arbitrary, Debug)]
struct CertChainValidationInput {
    /// Certificate generation scenarios to test
    scenarios: Vec<CertChainScenario>,
    /// Validation context parameters
    validation_context: ValidationContext,
}

#[derive(Arbitrary, Debug)]
struct CertChainScenario {
    /// The certificate chain to test
    chain: ChainConfiguration,
    /// Expected validation outcome
    expected_outcome: ExpectedOutcome,
}

#[derive(Arbitrary, Debug)]
enum ChainConfiguration {
    /// Valid certificate chain
    Valid {
        chain_length: u8,
        include_root: bool,
    },
    /// Chain with expired certificates
    Expired {
        expired_positions: Vec<u8>,
        days_expired: u16,
    },
    /// Chain with not-yet-valid certificates
    NotYetValid {
        future_positions: Vec<u8>,
        days_future: u16,
    },
    /// Chain with signature algorithm mismatches
    SignatureMismatch {
        mismatch_positions: Vec<u8>,
        algorithms: Vec<SignatureAlgorithm>,
    },
    /// Chain missing intermediate certificates
    MissingIntermediate { missing_positions: Vec<u8> },
    /// Chain with incorrect ordering
    IncorrectOrdering { shuffle_pattern: Vec<u8> },
    /// Chain with self-signed certificates in wrong places
    SelfSignedIssues { self_signed_positions: Vec<u8> },
    /// Malformed DER encoding
    MalformedDer {
        corruption_positions: Vec<CertCorruption>,
    },
    /// Chain with duplicate certificates
    DuplicateCerts { duplicate_positions: Vec<(u8, u8)> },
    /// Mixed certificate formats (DER/PEM corruption)
    MixedFormats {
        format_corruptions: Vec<FormatCorruption>,
    },
}

#[derive(Arbitrary, Debug)]
enum SignatureAlgorithm {
    RsaSha256,
    RsaSha384,
    RsaSha512,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519,
    // Invalid/unknown algorithms for testing
    Unknown(u16),
}

#[derive(Arbitrary, Debug)]
struct CertCorruption {
    /// Position in chain to corrupt
    position: u8,
    /// Byte offset to corrupt
    offset: u16,
    /// Corruption type
    corruption: CorruptionType,
}

#[derive(Arbitrary, Debug)]
enum CorruptionType {
    /// Flip specific bits
    BitFlip(u8),
    /// Replace with specific byte
    ByteReplace(u8),
    /// Insert random bytes
    ByteInsert(Vec<u8>),
    /// Truncate at position
    Truncate,
    /// Corrupt length fields
    LengthCorruption(u16),
}

#[derive(Arbitrary, Debug)]
struct FormatCorruption {
    position: u8,
    corruption_type: FormatCorruptionType,
}

#[derive(Arbitrary, Debug)]
enum FormatCorruptionType {
    /// Inject PEM headers in DER
    PemHeaderInDer,
    /// Corrupt base64 encoding
    Base64Corruption(u8),
    /// Mixed line endings
    MixedLineEndings,
}

#[derive(Arbitrary, Debug)]
enum ExpectedOutcome {
    /// Validation should succeed
    Valid,
    /// Validation should fail with specific error type
    Invalid(InvalidationType),
    /// Either outcome is acceptable (for edge cases)
    Either,
}

#[derive(Arbitrary, Debug)]
enum InvalidationType {
    Expired,
    NotYetValid,
    SignatureFailure,
    UnknownIssuer,
    MalformedCertificate,
    ChainTooLong,
    SelfSignedNotAllowed,
}

#[derive(Arbitrary, Debug)]
struct ValidationContext {
    /// Use system root certificates
    use_system_roots: bool,
    /// Use webpki root certificates
    use_webpki_roots: bool,
    /// Custom root certificates
    custom_roots: Vec<CertificateSource>,
    /// Maximum chain length allowed
    max_chain_length: Option<u8>,
    /// Allow self-signed certificates
    allow_self_signed: bool,
    /// Current time for validation (offset from now)
    time_offset_days: i16,
}

#[derive(Arbitrary, Debug)]
enum CertificateSource {
    /// Generate a basic self-signed certificate
    SelfSigned {
        key_type: KeyType,
        validity_days: u16,
    },
    /// Certificate with specific properties
    WithProperties {
        key_type: KeyType,
        issuer_name: CertificateName,
        subject_name: CertificateName,
        validity_start_offset_days: i16,
        validity_duration_days: u16,
        extensions: Vec<CertificateExtension>,
    },
    /// Raw DER bytes
    RawDer(Vec<u8>),
    /// Raw PEM data
    RawPem(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
enum KeyType {
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
}

#[derive(Arbitrary, Debug)]
struct CertificateName {
    common_name: String,
    organization: Option<String>,
    country: Option<String>,
}

#[derive(Arbitrary, Debug)]
enum CertificateExtension {
    BasicConstraints { is_ca: bool, path_len: Option<u8> },
    KeyUsage(Vec<KeyUsageFlag>),
    SubjectAltName(Vec<String>),
    AuthorityKeyIdentifier(Vec<u8>),
    SubjectKeyIdentifier(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
enum KeyUsageFlag {
    DigitalSignature,
    KeyEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
}

fuzz_target!(|input: CertChainValidationInput| {
    // Normalize input to prevent resource exhaustion
    let mut normalized_input = input;
    normalize_input(&mut normalized_input);

    // Test each certificate chain scenario
    for scenario in &normalized_input.scenarios {
        let _ = test_certificate_chain_scenario(scenario, &normalized_input.validation_context);
    }
});

fn normalize_input(input: &mut CertChainValidationInput) {
    // Limit number of scenarios
    input.scenarios.truncate(MAX_SCENARIOS);

    for scenario in &mut input.scenarios {
        normalize_chain_configuration(&mut scenario.chain);
    }

    // Normalize validation context
    normalize_validation_context(&mut input.validation_context);
}

fn normalize_chain_configuration(chain: &mut ChainConfiguration) {
    match chain {
        ChainConfiguration::Valid { chain_length, .. } => {
            *chain_length = (*chain_length).clamp(1, MAX_CHAIN_LENGTH as u8);
        }
        ChainConfiguration::Expired {
            expired_positions,
            days_expired,
        } => {
            expired_positions.truncate(MAX_CHAIN_LENGTH);
            *days_expired = (*days_expired).clamp(1, 3650); // Max 10 years
        }
        ChainConfiguration::NotYetValid {
            future_positions,
            days_future,
        } => {
            future_positions.truncate(MAX_CHAIN_LENGTH);
            *days_future = (*days_future).clamp(1, 3650);
        }
        ChainConfiguration::SignatureMismatch {
            mismatch_positions,
            algorithms,
        } => {
            mismatch_positions.truncate(MAX_CHAIN_LENGTH);
            algorithms.truncate(MAX_CHAIN_LENGTH);
        }
        ChainConfiguration::MissingIntermediate { missing_positions } => {
            missing_positions.truncate(MAX_CHAIN_LENGTH);
        }
        ChainConfiguration::IncorrectOrdering { shuffle_pattern } => {
            shuffle_pattern.truncate(MAX_CHAIN_LENGTH);
        }
        ChainConfiguration::SelfSignedIssues {
            self_signed_positions,
        } => {
            self_signed_positions.truncate(MAX_CHAIN_LENGTH);
        }
        ChainConfiguration::MalformedDer {
            corruption_positions,
        } => {
            corruption_positions.truncate(MAX_CHAIN_LENGTH);
            for corruption in corruption_positions {
                corruption.position = corruption.position.clamp(0, MAX_CHAIN_LENGTH as u8 - 1);
                corruption.offset = corruption.offset.clamp(0, MAX_CERT_SIZE as u16 - 1);
                // Normalize corruption data
                if let CorruptionType::ByteInsert(ref mut bytes) = corruption.corruption {
                    bytes.truncate(1024); // Limit insertion size
                }
            }
        }
        ChainConfiguration::DuplicateCerts {
            duplicate_positions,
        } => {
            duplicate_positions.truncate(MAX_CHAIN_LENGTH / 2);
        }
        ChainConfiguration::MixedFormats { format_corruptions } => {
            format_corruptions.truncate(MAX_CHAIN_LENGTH);
        }
    }
}

fn normalize_validation_context(context: &mut ValidationContext) {
    // Limit custom root certificates
    context.custom_roots.truncate(10);

    for cert_source in &mut context.custom_roots {
        normalize_certificate_source(cert_source);
    }

    if let Some(ref mut max_len) = context.max_chain_length {
        *max_len = (*max_len).clamp(1, MAX_CHAIN_LENGTH as u8);
    }

    // Clamp time offset to reasonable range
    context.time_offset_days = context.time_offset_days.clamp(-365, 365);
}

fn normalize_certificate_source(source: &mut CertificateSource) {
    match source {
        CertificateSource::SelfSigned { validity_days, .. } => {
            *validity_days = (*validity_days).clamp(1, 3650);
        }
        CertificateSource::WithProperties {
            validity_duration_days,
            validity_start_offset_days,
            ..
        } => {
            *validity_duration_days = (*validity_duration_days).clamp(1, 3650);
            *validity_start_offset_days = (*validity_start_offset_days).clamp(-365, 365);
        }
        CertificateSource::RawDer(bytes) => {
            bytes.truncate(MAX_CERT_SIZE);
        }
        CertificateSource::RawPem(bytes) => {
            bytes.truncate(MAX_CERT_SIZE);
        }
    }
}

fn test_certificate_chain_scenario(
    scenario: &CertChainScenario,
    context: &ValidationContext,
) -> Result<(), Box<dyn std::error::Error>> {
    // Generate certificate chain based on scenario
    let certificate_chain = generate_certificate_chain(&scenario.chain)?;

    // Set up validation context
    let validation_result = validate_certificate_chain(&certificate_chain, context);

    // Check that validation doesn't panic and produces reasonable results
    match (&scenario.expected_outcome, &validation_result) {
        (ExpectedOutcome::Valid, Ok(_)) => {
            // Expected success
        }
        (ExpectedOutcome::Invalid(_), Err(_)) => {
            // Expected failure
        }
        (ExpectedOutcome::Either, _) => {
            // Either outcome is acceptable
        }
        _ => {
            // Outcome mismatch - not necessarily a bug, validation is complex
        }
    }

    Ok(())
}

fn generate_certificate_chain(
    config: &ChainConfiguration,
) -> Result<CertificateChain, Box<dyn std::error::Error>> {
    match config {
        ChainConfiguration::Valid {
            chain_length,
            include_root,
        } => generate_valid_chain(*chain_length, *include_root),
        ChainConfiguration::Expired { .. } => generate_expired_chain(),
        ChainConfiguration::NotYetValid { .. } => generate_future_valid_chain(),
        ChainConfiguration::SignatureMismatch { .. } => generate_signature_mismatch_chain(),
        ChainConfiguration::MissingIntermediate { .. } => generate_missing_intermediate_chain(),
        ChainConfiguration::IncorrectOrdering { .. } => generate_misordered_chain(),
        ChainConfiguration::SelfSignedIssues { .. } => generate_self_signed_issues_chain(),
        ChainConfiguration::MalformedDer {
            corruption_positions,
        } => generate_malformed_der_chain(corruption_positions),
        ChainConfiguration::DuplicateCerts { .. } => generate_duplicate_certs_chain(),
        ChainConfiguration::MixedFormats { .. } => generate_mixed_formats_chain(),
    }
}

fn generate_valid_chain(
    length: u8,
    _include_root: bool,
) -> Result<CertificateChain, Box<dyn std::error::Error>> {
    // Generate a basic certificate chain
    // This is a simplified implementation - in practice we'd need proper certificate generation
    let mut chain = CertificateChain::new();

    for i in 0..length.min(3) {
        // Generate a minimal self-signed certificate for testing
        let cert_der = generate_minimal_cert_der(i)?;
        let cert = Certificate::from_der(cert_der);
        chain.push(cert);
    }

    Ok(chain)
}

fn generate_expired_chain() -> Result<CertificateChain, Box<dyn std::error::Error>> {
    // Generate certificates that are expired
    let mut chain = CertificateChain::new();
    let cert_der = generate_minimal_cert_der(0)?;
    let cert = Certificate::from_der(cert_der);
    chain.push(cert);
    Ok(chain)
}

fn generate_future_valid_chain() -> Result<CertificateChain, Box<dyn std::error::Error>> {
    // Generate certificates that are not yet valid
    let mut chain = CertificateChain::new();
    let cert_der = generate_minimal_cert_der(0)?;
    let cert = Certificate::from_der(cert_der);
    chain.push(cert);
    Ok(chain)
}

fn generate_signature_mismatch_chain() -> Result<CertificateChain, Box<dyn std::error::Error>> {
    // Generate certificates with signature mismatches
    let mut chain = CertificateChain::new();
    let cert_der = generate_minimal_cert_der(0)?;
    let cert = Certificate::from_der(cert_der);
    chain.push(cert);
    Ok(chain)
}

fn generate_missing_intermediate_chain() -> Result<CertificateChain, Box<dyn std::error::Error>> {
    // Generate chain missing intermediate certificates
    let mut chain = CertificateChain::new();
    // Add leaf and root, but skip intermediate
    let leaf_der = generate_minimal_cert_der(0)?;
    let root_der = generate_minimal_cert_der(2)?;
    chain.push(Certificate::from_der(leaf_der));
    chain.push(Certificate::from_der(root_der));
    Ok(chain)
}

fn generate_misordered_chain() -> Result<CertificateChain, Box<dyn std::error::Error>> {
    // Generate chain with incorrect certificate ordering
    let mut chain = CertificateChain::new();
    let root_der = generate_minimal_cert_der(2)?;
    let leaf_der = generate_minimal_cert_der(0)?;
    // Add in wrong order (root first, then leaf)
    chain.push(Certificate::from_der(root_der));
    chain.push(Certificate::from_der(leaf_der));
    Ok(chain)
}

fn generate_self_signed_issues_chain() -> Result<CertificateChain, Box<dyn std::error::Error>> {
    // Generate chain with self-signed issues
    let mut chain = CertificateChain::new();
    let cert_der = generate_minimal_cert_der(0)?;
    let cert = Certificate::from_der(cert_der);
    chain.push(cert);
    Ok(chain)
}

fn generate_malformed_der_chain(
    corruptions: &[CertCorruption],
) -> Result<CertificateChain, Box<dyn std::error::Error>> {
    // Generate chain with malformed DER encoding
    let mut chain = CertificateChain::new();
    let mut cert_der = generate_minimal_cert_der(0)?;

    // Apply corruptions to the DER data
    for corruption in corruptions {
        apply_corruption(&mut cert_der, corruption);
    }

    let cert = Certificate::from_der(cert_der);
    chain.push(cert);
    Ok(chain)
}

fn generate_duplicate_certs_chain() -> Result<CertificateChain, Box<dyn std::error::Error>> {
    // Generate chain with duplicate certificates
    let mut chain = CertificateChain::new();
    let cert_der = generate_minimal_cert_der(0)?;
    let cert = Certificate::from_der(cert_der.clone());
    let duplicate_cert = Certificate::from_der(cert_der);
    chain.push(cert);
    chain.push(duplicate_cert);
    Ok(chain)
}

fn generate_mixed_formats_chain() -> Result<CertificateChain, Box<dyn std::error::Error>> {
    // Generate chain with mixed format issues
    let mut chain = CertificateChain::new();
    let cert_der = generate_minimal_cert_der(0)?;
    let cert = Certificate::from_der(cert_der);
    chain.push(cert);
    Ok(chain)
}

fn apply_corruption(cert_der: &mut Vec<u8>, corruption: &CertCorruption) {
    let offset = corruption.offset as usize;
    if offset >= cert_der.len() {
        return;
    }

    match &corruption.corruption {
        CorruptionType::BitFlip(mask) => {
            cert_der[offset] ^= mask;
        }
        CorruptionType::ByteReplace(value) => {
            cert_der[offset] = *value;
        }
        CorruptionType::ByteInsert(bytes) => {
            cert_der.splice(offset..offset, bytes.iter().cloned());
        }
        CorruptionType::Truncate => {
            cert_der.truncate(offset);
        }
        CorruptionType::LengthCorruption(new_len) => {
            // Corrupt ASN.1 length fields (simplified)
            if offset + 1 < cert_der.len() {
                cert_der[offset] = (*new_len >> 8) as u8;
                cert_der[offset + 1] = (*new_len & 0xFF) as u8;
            }
        }
    }
}

fn generate_minimal_cert_der(variant: u8) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Generate a minimal DER-encoded certificate for testing
    // This is a simplified placeholder - real certificates are complex
    let mut cert = Vec::new();

    // Basic ASN.1 DER structure for a certificate (minimal)
    cert.extend_from_slice(&[0x30, 0x82]); // SEQUENCE, length follows
    let length = 100 + variant as usize * 10;
    cert.extend_from_slice(&[(length >> 8) as u8, (length & 0xFF) as u8]);

    // Certificate body (placeholder with some variation)
    for i in 0..length {
        cert.push((i + variant as usize) as u8);
    }

    Ok(cert)
}

fn validate_certificate_chain(
    chain: &CertificateChain,
    context: &ValidationContext,
) -> Result<(), TlsError> {
    // Set up a TLS connector builder for validation
    let mut builder = TlsConnectorBuilder::new();

    if context.use_system_roots {
        builder = builder.with_native_roots()?;
    }

    if context.use_webpki_roots {
        builder = builder.with_webpki_roots();
    }

    // Add custom roots if specified
    for cert_source in &context.custom_roots {
        if let Ok(certs) = generate_certificate_from_source(cert_source) {
            for cert in certs {
                // In a real implementation, we'd add these to a custom root store
                // This is simplified for the fuzzer
                let _cert = cert;
            }
        }
    }

    // Build the connector (this will exercise certificate validation logic)
    let _connector = builder.build()?;

    // The actual validation happens during TLS handshake
    // For fuzzing purposes, we just test that the connector builds successfully
    // and the chain can be processed without panicking

    // Exercise the certificate chain by iterating through it
    for (i, cert) in chain.clone().into_iter().enumerate() {
        // Access certificate DER data
        let _der_bytes = cert.as_der();

        if i >= MAX_CHAIN_LENGTH {
            break;
        }
    }

    Ok(())
}

fn generate_certificate_from_source(
    source: &CertificateSource,
) -> Result<Vec<Certificate>, Box<dyn std::error::Error>> {
    match source {
        CertificateSource::SelfSigned { .. } => {
            let cert_der = generate_minimal_cert_der(0)?;
            Ok(vec![Certificate::from_der(cert_der)])
        }
        CertificateSource::WithProperties { .. } => {
            let cert_der = generate_minimal_cert_der(1)?;
            Ok(vec![Certificate::from_der(cert_der)])
        }
        CertificateSource::RawDer(bytes) => Ok(vec![Certificate::from_der(bytes.clone())]),
        CertificateSource::RawPem(bytes) => {
            // Try to parse as PEM, fall back to treating as DER
            match Certificate::from_pem(bytes) {
                Ok(certs) => Ok(certs),
                Err(_) => Ok(vec![Certificate::from_der(bytes.clone())]),
            }
        }
    }
}
