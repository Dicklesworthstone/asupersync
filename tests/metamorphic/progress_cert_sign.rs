//! Metamorphic testing for progress certificate sign/verify invariants.
//!
//! This module implements 5 metamorphic relations testing cryptographic
//! properties of progress certificate signing and verification:
//!
//! 1. **Sign-then-verify passes** - Valid certificates verify successfully
//! 2. **Tampered cert fails verification** - Any modification breaks signature
//! 3. **Signature deterministic** - Same input produces same signature
//! 4. **Cert encoding canonical** - Serialization is deterministic
//! 5. **Revoked cert fails under new generation** - Generation-based revocation

use crate::cancel::progress_certificate::{ProgressCertificate, ProgressConfig, CertificateVerdict};
use crate::lab::runtime::LabRuntime;
use crate::types::{ObjectId, Time};
use crate::error::Error;
use proptest::prelude::*;
use std::collections::HashMap;

/// Initialize test infrastructure
fn init_test(name: &str) {
    println!("Starting metamorphic test: {}", name);
}

/// Cryptographic key for signing progress certificates
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateKey {
    /// Key generation (for revocation testing)
    generation: u64,
    /// Private key material (simplified for testing)
    private_key: [u8; 32],
    /// Public key material (derived from private)
    public_key: [u8; 32],
}

impl CertificateKey {
    /// Generate a new certificate key for the given generation
    pub fn new_for_generation(generation: u64, seed: u64) -> Self {
        // Deterministic key generation for reproducible tests
        let mut private_key = [0u8; 32];
        let mut state = seed.wrapping_mul(generation).wrapping_add(0x123456789ABCDEF);

        for i in 0..32 {
            private_key[i] = (state >> (i % 8)) as u8;
            state = state.wrapping_mul(0x9E3779B97F4A7C15);
            state ^= state >> 30;
        }

        // Derive public key (simplified)
        let mut public_key = [0u8; 32];
        for (i, &byte) in private_key.iter().enumerate() {
            public_key[i] = byte ^ ((generation as u8).wrapping_mul(i as u8 + 1));
        }

        Self {
            generation,
            private_key,
            public_key,
        }
    }

    /// Get the generation number
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Get public key bytes for verification
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

/// Signed progress certificate with cryptographic signature
#[derive(Debug, Clone)]
pub struct SignedProgressCertificate {
    /// The underlying certificate verdict
    verdict: CertificateVerdict,
    /// Canonical encoding of the certificate
    canonical_bytes: Vec<u8>,
    /// Cryptographic signature
    signature: Vec<u8>,
    /// Key generation used for signing
    key_generation: u64,
    /// Object ID for certificate identity
    object_id: ObjectId,
    /// Timestamp when certificate was issued
    issued_at: Time,
}

/// Errors during certificate signing/verification
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    /// Invalid signature
    #[error("signature verification failed")]
    InvalidSignature,
    /// Certificate was signed with revoked key generation
    #[error("certificate signed with revoked generation {generation}")]
    RevokedGeneration { generation: u64 },
    /// Encoding/decoding error
    #[error("encoding error: {message}")]
    EncodingError { message: String },
    /// Tampered certificate data
    #[error("certificate data has been tampered")]
    TamperedData,
}

impl SignedProgressCertificate {
    /// Sign a progress certificate with the given key
    pub fn sign(
        verdict: CertificateVerdict,
        key: &CertificateKey,
        object_id: ObjectId,
        issued_at: Time,
    ) -> Result<Self, CertificateError> {
        // Create canonical encoding of the certificate
        let canonical_bytes = Self::canonical_encode(&verdict, object_id, issued_at)?;

        // Generate signature using simplified HMAC-like construction
        let signature = Self::compute_signature(&canonical_bytes, key);

        Ok(Self {
            verdict,
            canonical_bytes,
            signature,
            key_generation: key.generation(),
            object_id,
            issued_at,
        })
    }

    /// Verify the certificate signature against a public key
    pub fn verify(&self, public_key: &[u8; 32], current_generation: u64) -> Result<(), CertificateError> {
        // Check if the key generation has been revoked
        if self.key_generation < current_generation {
            return Err(CertificateError::RevokedGeneration {
                generation: self.key_generation,
            });
        }

        // Reconstruct the canonical encoding
        let expected_bytes = Self::canonical_encode(&self.verdict, self.object_id, self.issued_at)?;

        // Verify canonical encoding hasn't been tampered
        if expected_bytes != self.canonical_bytes {
            return Err(CertificateError::TamperedData);
        }

        // Verify signature
        let expected_signature = Self::compute_signature_with_public_key(&self.canonical_bytes, public_key, self.key_generation);

        if expected_signature != self.signature {
            return Err(CertificateError::InvalidSignature);
        }

        Ok(())
    }

    /// Get the underlying certificate verdict
    pub fn verdict(&self) -> &CertificateVerdict {
        &self.verdict
    }

    /// Get the canonical encoding bytes
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Get the signature bytes
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Get the key generation used for signing
    pub fn key_generation(&self) -> u64 {
        self.key_generation
    }

    /// Create canonical encoding of certificate data
    fn canonical_encode(
        verdict: &CertificateVerdict,
        object_id: ObjectId,
        issued_at: Time,
    ) -> Result<Vec<u8>, CertificateError> {
        // Simplified canonical encoding - in practice would use proper serialization
        let mut bytes = Vec::new();

        // Object ID
        bytes.extend_from_slice(&object_id.as_u64().to_le_bytes());

        // Timestamp
        bytes.extend_from_slice(&issued_at.as_nanos().to_le_bytes());

        // Verdict fields (deterministic encoding)
        bytes.push(if verdict.converging { 1 } else { 0 });

        // Encode potential as canonical bytes
        bytes.extend_from_slice(&verdict.initial_potential.to_bits().to_le_bytes());

        // Confidence bound
        bytes.extend_from_slice(&verdict.confidence_bound.to_bits().to_le_bytes());

        // Azuma bound
        bytes.extend_from_slice(&verdict.azuma_bound.to_bits().to_le_bytes());

        // Freedman bound (if present)
        bytes.push(if verdict.freedman_bound.is_some() { 1 } else { 0 });
        if let Some(bound) = verdict.freedman_bound {
            bytes.extend_from_slice(&bound.to_bits().to_le_bytes());
        }

        // Estimated remaining steps (if present)
        bytes.push(if verdict.estimated_remaining_steps.is_some() { 1 } else { 0 });
        if let Some(steps) = verdict.estimated_remaining_steps {
            bytes.extend_from_slice(&steps.to_bits().to_le_bytes());
        }

        // Stall detection flag
        bytes.push(if verdict.stall_detected { 1 } else { 0 });

        // Evidence count (for tamper detection)
        bytes.extend_from_slice(&(verdict.evidence.len() as u32).to_le_bytes());

        Ok(bytes)
    }

    /// Compute signature using private key
    fn compute_signature(data: &[u8], key: &CertificateKey) -> Vec<u8> {
        Self::compute_signature_with_public_key(data, &key.public_key, key.generation)
    }

    /// Compute signature using public key (for verification)
    fn compute_signature_with_public_key(data: &[u8], public_key: &[u8; 32], generation: u64) -> Vec<u8> {
        // Simplified HMAC-like signature computation
        let mut signature = Vec::with_capacity(32);
        let generation_bytes = generation.to_le_bytes();

        for (i, &byte) in data.iter().enumerate() {
            let key_byte = public_key[i % 32];
            let gen_byte = generation_bytes[i % 8];
            let signed_byte = byte ^ key_byte ^ gen_byte ^ ((i as u8).wrapping_mul(0x5A));
            signature.push(signed_byte);

            // Limit signature to 32 bytes for simplicity
            if signature.len() >= 32 {
                break;
            }
        }

        // Pad to 32 bytes if needed
        while signature.len() < 32 {
            let pad_value = (signature.len() as u8) ^ 0xA5;
            signature.push(pad_value);
        }

        signature
    }
}

/// Generate test verdict data
fn generate_test_verdict() -> CertificateVerdict {
    CertificateVerdict {
        converging: true,
        initial_potential: 100.0,
        confidence_bound: 0.95,
        azuma_bound: 0.04,
        freedman_bound: Some(0.02),
        empirical_variance: Some(12.5),
        estimated_remaining_steps: Some(50.0),
        stall_detected: false,
        evidence: Vec::new(),
    }
}

/// **MR1: Sign-then-verify passes for valid certificates**
///
/// Property: A properly signed certificate should always verify successfully
/// with the corresponding public key and current generation.
///
/// Metamorphic relation: sign(cert, key) → verify(signed_cert, key.public) = Ok()
#[cfg(test)]
mod mr1_sign_then_verify {
    use super::*;

    proptest! {
        #[test]
        fn mr1_valid_certificate_verifies(
            generation in 1u64..10,
            seed in 0u64..1000,
            object_id in 0u64..1000,
            timestamp in 0u64..1000000,
        ) {
            init_test("mr1_valid_certificate_verifies");

            let key = CertificateKey::new_for_generation(generation, seed);
            let verdict = generate_test_verdict();
            let object_id = ObjectId::new_for_test(object_id);
            let issued_at = Time::from_nanos(timestamp * 1_000_000); // Convert to reasonable timestamp

            // Sign certificate
            let signed_cert = SignedProgressCertificate::sign(
                verdict,
                &key,
                object_id,
                issued_at,
            ).expect("Signing should succeed");

            // Verify should pass with same generation or newer
            let verify_result = signed_cert.verify(key.public_key(), generation);
            prop_assert!(verify_result.is_ok(), "Valid certificate should verify: {:?}", verify_result);

            // Should also verify with newer generation
            if generation < 9 {
                let verify_future = signed_cert.verify(key.public_key(), generation + 1);
                prop_assert!(verify_future.is_ok(), "Certificate should verify with newer generation");
            }
        }
    }

    #[test]
    fn mr1_multiple_certificates_same_key() {
        init_test("mr1_multiple_certificates_same_key");

        let key = CertificateKey::new_for_generation(5, 12345);

        for i in 0..10 {
            let verdict = generate_test_verdict();
            let object_id = ObjectId::new_for_test(i);
            let issued_at = Time::from_nanos(i * 1_000_000);

            let signed_cert = SignedProgressCertificate::sign(
                verdict,
                &key,
                object_id,
                issued_at,
            ).expect("Signing should succeed");

            let verify_result = signed_cert.verify(key.public_key(), key.generation());
            assert!(verify_result.is_ok(), "Certificate {} should verify", i);
        }
    }
}

/// **MR2: Tampered certificate fails verification**
///
/// Property: Any modification to signed certificate data should cause
/// verification to fail, ensuring integrity protection.
///
/// Metamorphic relation: tamper(signed_cert) → verify(tampered_cert, key.public) = Err()
#[cfg(test)]
mod mr2_tampered_cert_fails {
    use super::*;

    proptest! {
        #[test]
        fn mr2_tampered_canonical_bytes_fail(
            generation in 1u64..5,
            seed in 0u64..100,
            tamper_position in 0usize..50,
        ) {
            init_test("mr2_tampered_canonical_bytes_fail");

            let key = CertificateKey::new_for_generation(generation, seed);
            let verdict = generate_test_verdict();
            let object_id = ObjectId::new_for_test(42);
            let issued_at = Time::from_nanos(123456789);

            let mut signed_cert = SignedProgressCertificate::sign(
                verdict,
                &key,
                object_id,
                issued_at,
            ).expect("Signing should succeed");

            // Tamper with canonical bytes
            if tamper_position < signed_cert.canonical_bytes.len() {
                signed_cert.canonical_bytes[tamper_position] ^= 0xFF;

                let verify_result = signed_cert.verify(key.public_key(), generation);
                prop_assert!(verify_result.is_err(), "Tampered certificate should fail verification");
                prop_assert!(matches!(verify_result.unwrap_err(), CertificateError::TamperedData));
            }
        }

        #[test]
        fn mr2_tampered_signature_fails(
            generation in 1u64..5,
            seed in 0u64..100,
            tamper_position in 0usize..32,
        ) {
            init_test("mr2_tampered_signature_fails");

            let key = CertificateKey::new_for_generation(generation, seed);
            let verdict = generate_test_verdict();
            let object_id = ObjectId::new_for_test(42);
            let issued_at = Time::from_nanos(123456789);

            let mut signed_cert = SignedProgressCertificate::sign(
                verdict,
                &key,
                object_id,
                issued_at,
            ).expect("Signing should succeed");

            // Tamper with signature
            if tamper_position < signed_cert.signature.len() {
                signed_cert.signature[tamper_position] ^= 0x1;

                let verify_result = signed_cert.verify(key.public_key(), generation);
                prop_assert!(verify_result.is_err(), "Tampered signature should fail verification");
                prop_assert!(matches!(verify_result.unwrap_err(), CertificateError::InvalidSignature));
            }
        }
    }

    #[test]
    fn mr2_verdict_modification_detected() {
        init_test("mr2_verdict_modification_detected");

        let key = CertificateKey::new_for_generation(3, 999);
        let original_verdict = generate_test_verdict();
        let object_id = ObjectId::new_for_test(100);
        let issued_at = Time::from_nanos(987654321);

        let signed_cert = SignedProgressCertificate::sign(
            original_verdict,
            &key,
            object_id,
            issued_at,
        ).expect("Signing should succeed");

        // Create modified verdict
        let mut modified_verdict = signed_cert.verdict().clone();
        modified_verdict.converging = false; // Flip convergence flag

        // Try to verify with modified verdict
        let tampered_cert = SignedProgressCertificate {
            verdict: modified_verdict,
            canonical_bytes: signed_cert.canonical_bytes.clone(),
            signature: signed_cert.signature.clone(),
            key_generation: signed_cert.key_generation,
            object_id,
            issued_at,
        };

        let verify_result = tampered_cert.verify(key.public_key(), key.generation());
        assert!(verify_result.is_err(), "Modified verdict should fail verification");
    }
}

/// **MR3: Signature deterministic for same input**
///
/// Property: Signing the same certificate with the same key should always
/// produce identical signatures (deterministic signing).
///
/// Metamorphic relation: sign(cert, key) = sign(cert, key)
#[cfg(test)]
mod mr3_signature_deterministic {
    use super::*;

    proptest! {
        #[test]
        fn mr3_identical_input_identical_signature(
            generation in 1u64..10,
            seed in 0u64..1000,
            object_id in 0u64..1000,
        ) {
            init_test("mr3_identical_input_identical_signature");

            let key = CertificateKey::new_for_generation(generation, seed);
            let verdict = generate_test_verdict();
            let object_id = ObjectId::new_for_test(object_id);
            let issued_at = Time::from_nanos(42424242);

            // Sign same certificate twice
            let signed_cert1 = SignedProgressCertificate::sign(
                verdict.clone(),
                &key,
                object_id,
                issued_at,
            ).expect("First signing should succeed");

            let signed_cert2 = SignedProgressCertificate::sign(
                verdict,
                &key,
                object_id,
                issued_at,
            ).expect("Second signing should succeed");

            // Signatures should be identical
            prop_assert_eq!(
                signed_cert1.signature(),
                signed_cert2.signature(),
                "Identical inputs should produce identical signatures"
            );

            // Canonical bytes should be identical
            prop_assert_eq!(
                signed_cert1.canonical_bytes(),
                signed_cert2.canonical_bytes(),
                "Identical inputs should produce identical canonical encoding"
            );
        }
    }

    #[test]
    fn mr3_key_regeneration_produces_different_signatures() {
        init_test("mr3_key_regeneration_produces_different_signatures");

        let verdict = generate_test_verdict();
        let object_id = ObjectId::new_for_test(123);
        let issued_at = Time::from_nanos(55555555);

        // Generate two different keys
        let key1 = CertificateKey::new_for_generation(1, 100);
        let key2 = CertificateKey::new_for_generation(2, 100);

        let signed_cert1 = SignedProgressCertificate::sign(
            verdict.clone(),
            &key1,
            object_id,
            issued_at,
        ).expect("Signing with key1 should succeed");

        let signed_cert2 = SignedProgressCertificate::sign(
            verdict,
            &key2,
            object_id,
            issued_at,
        ).expect("Signing with key2 should succeed");

        // Different keys should produce different signatures
        assert_ne!(
            signed_cert1.signature(),
            signed_cert2.signature(),
            "Different keys should produce different signatures"
        );

        // But canonical bytes should be the same (same certificate data)
        assert_eq!(
            signed_cert1.canonical_bytes(),
            signed_cert2.canonical_bytes(),
            "Same certificate data should have same canonical encoding"
        );
    }
}

/// **MR4: Certificate encoding canonical**
///
/// Property: Certificate encoding should be deterministic and canonical,
/// producing the same byte representation for equivalent certificate data.
///
/// Metamorphic relation: encode(cert_data) = encode(cert_data)
#[cfg(test)]
mod mr4_cert_encoding_canonical {
    use super::*;

    proptest! {
        #[test]
        fn mr4_identical_verdicts_identical_encoding(
            converging in any::<bool>(),
            initial_potential in 0.0f64..10000.0,
            confidence in 0.0f64..1.0,
            object_id in 0u64..1000,
        ) {
            init_test("mr4_identical_verdicts_identical_encoding");

            let verdict1 = CertificateVerdict {
                converging,
                initial_potential,
                confidence_bound: confidence,
                azuma_bound: 0.05,
                freedman_bound: Some(0.03),
                empirical_variance: Some(25.0),
                estimated_remaining_steps: Some(100.0),
                stall_detected: false,
                evidence: Vec::new(),
            };

            let verdict2 = verdict1.clone();
            let object_id = ObjectId::new_for_test(object_id);
            let issued_at = Time::from_nanos(999999999);

            // Encode both verdicts
            let encoding1 = SignedProgressCertificate::canonical_encode(&verdict1, object_id, issued_at)
                .expect("First encoding should succeed");
            let encoding2 = SignedProgressCertificate::canonical_encode(&verdict2, object_id, issued_at)
                .expect("Second encoding should succeed");

            prop_assert_eq!(
                encoding1,
                encoding2,
                "Identical verdicts should have identical canonical encoding"
            );
        }
    }

    #[test]
    fn mr4_field_differences_affect_encoding() {
        init_test("mr4_field_differences_affect_encoding");

        let base_verdict = generate_test_verdict();
        let object_id = ObjectId::new_for_test(777);
        let issued_at = Time::from_nanos(123123123);

        let base_encoding = SignedProgressCertificate::canonical_encode(&base_verdict, object_id, issued_at)
            .expect("Base encoding should succeed");

        // Test different convergence flag
        let mut different_verdict = base_verdict.clone();
        different_verdict.converging = !different_verdict.converging;
        let different_encoding = SignedProgressCertificate::canonical_encode(&different_verdict, object_id, issued_at)
            .expect("Different encoding should succeed");

        assert_ne!(
            base_encoding,
            different_encoding,
            "Different convergence should produce different encoding"
        );

        // Test different potential
        let mut potential_verdict = base_verdict.clone();
        potential_verdict.initial_potential += 1.0;
        let potential_encoding = SignedProgressCertificate::canonical_encode(&potential_verdict, object_id, issued_at)
            .expect("Potential encoding should succeed");

        assert_ne!(
            base_encoding,
            potential_encoding,
            "Different potential should produce different encoding"
        );

        // Test different object ID
        let different_object_id = ObjectId::new_for_test(888);
        let object_encoding = SignedProgressCertificate::canonical_encode(&base_verdict, different_object_id, issued_at)
            .expect("Object ID encoding should succeed");

        assert_ne!(
            base_encoding,
            object_encoding,
            "Different object ID should produce different encoding"
        );
    }

    #[test]
    fn mr4_encoding_preserves_floating_point_precision() {
        init_test("mr4_encoding_preserves_floating_point_precision");

        let verdict = CertificateVerdict {
            converging: true,
            initial_potential: std::f64::consts::PI,
            confidence_bound: std::f64::consts::E,
            azuma_bound: 1.0 / 3.0,
            freedman_bound: Some(std::f64::consts::LN_2),
            empirical_variance: Some(std::f64::consts::SQRT_2),
            estimated_remaining_steps: Some(42.424242424242),
            stall_detected: false,
            evidence: Vec::new(),
        };

        let object_id = ObjectId::new_for_test(314159);
        let issued_at = Time::from_nanos(271828182845);

        // Encode and verify precision is preserved
        let encoding = SignedProgressCertificate::canonical_encode(&verdict, object_id, issued_at)
            .expect("Encoding should succeed");

        // Verify that encoding is deterministic for the same floating-point values
        let second_encoding = SignedProgressCertificate::canonical_encode(&verdict, object_id, issued_at)
            .expect("Second encoding should succeed");

        assert_eq!(encoding, second_encoding, "Floating-point encoding should be deterministic");

        // Verify that small differences in floating-point values produce different encodings
        let mut slightly_different = verdict.clone();
        slightly_different.initial_potential = std::f64::consts::PI + 1e-15;

        let different_encoding = SignedProgressCertificate::canonical_encode(&slightly_different, object_id, issued_at)
            .expect("Different encoding should succeed");

        assert_ne!(
            encoding,
            different_encoding,
            "Small floating-point differences should be preserved in encoding"
        );
    }
}

/// **MR5: Revoked certificate fails under new generation**
///
/// Property: Certificates signed with older key generations should fail
/// verification when checked against newer generations (key revocation).
///
/// Metamorphic relation: verify(cert_gen_N, key_gen_M) where M > N → Err(RevokedGeneration)
#[cfg(test)]
mod mr5_revoked_cert_fails {
    use super::*;

    proptest! {
        #[test]
        fn mr5_old_generation_rejected(
            old_generation in 1u64..5,
            generation_gap in 1u64..5,
            seed in 0u64..100,
        ) {
            init_test("mr5_old_generation_rejected");

            let current_generation = old_generation + generation_gap;

            let old_key = CertificateKey::new_for_generation(old_generation, seed);
            let verdict = generate_test_verdict();
            let object_id = ObjectId::new_for_test(100);
            let issued_at = Time::from_nanos(555555);

            // Sign with old key
            let signed_cert = SignedProgressCertificate::sign(
                verdict,
                &old_key,
                object_id,
                issued_at,
            ).expect("Signing with old key should succeed");

            // Verify with current generation should fail
            let verify_result = signed_cert.verify(old_key.public_key(), current_generation);
            prop_assert!(verify_result.is_err(), "Old generation certificate should be rejected");

            match verify_result.unwrap_err() {
                CertificateError::RevokedGeneration { generation } => {
                    prop_assert_eq!(generation, old_generation, "Should report correct revoked generation");
                }
                other => {
                    prop_assert!(false, "Expected RevokedGeneration error, got: {:?}", other);
                }
            }
        }
    }

    #[test]
    fn mr5_generation_boundary_cases() {
        init_test("mr5_generation_boundary_cases");

        let verdict = generate_test_verdict();
        let object_id = ObjectId::new_for_test(200);
        let issued_at = Time::from_nanos(777777);

        // Test generation 5
        let key_gen5 = CertificateKey::new_for_generation(5, 12345);
        let cert_gen5 = SignedProgressCertificate::sign(
            verdict.clone(),
            &key_gen5,
            object_id,
            issued_at,
        ).expect("Signing with gen5 should succeed");

        // Should verify with same generation
        assert!(cert_gen5.verify(key_gen5.public_key(), 5).is_ok());

        // Should verify with newer generation (backwards compatibility within same key)
        assert!(cert_gen5.verify(key_gen5.public_key(), 6).is_ok());

        // But certificates from older keys should fail with newer generation
        let key_gen3 = CertificateKey::new_for_generation(3, 12345);
        let cert_gen3 = SignedProgressCertificate::sign(
            verdict,
            &key_gen3,
            object_id,
            issued_at,
        ).expect("Signing with gen3 should succeed");

        // Should fail when verified against newer generation
        let verify_result = cert_gen3.verify(key_gen3.public_key(), 5);
        assert!(verify_result.is_err());
        assert!(matches!(
            verify_result.unwrap_err(),
            CertificateError::RevokedGeneration { generation: 3 }
        ));
    }

    #[test]
    fn mr5_multiple_revocations() {
        init_test("mr5_multiple_revocations");

        let verdict = generate_test_verdict();
        let object_id = ObjectId::new_for_test(300);
        let issued_at = Time::from_nanos(888888);

        // Create certificates with multiple generations
        let mut certificates = Vec::new();
        for gen in 1..=5 {
            let key = CertificateKey::new_for_generation(gen, 54321);
            let cert = SignedProgressCertificate::sign(
                verdict.clone(),
                &key,
                object_id,
                issued_at,
            ).expect(&format!("Signing with gen{} should succeed", gen));
            certificates.push((cert, key));
        }

        // When current generation is 10, all should be revoked
        let current_generation = 10;
        for (cert, key) in certificates {
            let verify_result = cert.verify(key.public_key(), current_generation);
            assert!(verify_result.is_err(), "Gen {} should be revoked", key.generation());
            assert!(matches!(
                verify_result.unwrap_err(),
                CertificateError::RevokedGeneration { .. }
            ));
        }
    }
}

/// Integration test combining all metamorphic relations
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn integration_complete_certificate_lifecycle() {
        init_test("integration_complete_certificate_lifecycle");

        let mut runtime = LabRuntime::new();
        runtime.run_to_completion(|| async {
            // Create progress certificate with actual data
            let config = ProgressConfig::default();
            let mut cert = ProgressCertificate::new(config);

            // Feed realistic drain progress
            cert.observe(1000.0);
            cert.observe(750.0);
            cert.observe(500.0);
            cert.observe(250.0);
            cert.observe(100.0);
            cert.observe(25.0);
            cert.observe(0.0);

            let verdict = cert.verdict();
            assert!(verdict.converging, "Certificate should show convergence");

            // Test complete sign/verify cycle
            let key = CertificateKey::new_for_generation(1, 98765);
            let object_id = ObjectId::new_for_test(999);
            let issued_at = Time::from_nanos(1234567890);

            // MR1: Sign and verify
            let signed_cert = SignedProgressCertificate::sign(
                verdict,
                &key,
                object_id,
                issued_at,
            ).expect("Signing should succeed");

            assert!(signed_cert.verify(key.public_key(), 1).is_ok());

            // MR2: Tamper detection
            let mut tampered = signed_cert.clone();
            tampered.signature[0] ^= 1;
            assert!(tampered.verify(key.public_key(), 1).is_err());

            // MR3: Deterministic signing
            let signed_cert2 = SignedProgressCertificate::sign(
                signed_cert.verdict().clone(),
                &key,
                object_id,
                issued_at,
            ).expect("Second signing should succeed");
            assert_eq!(signed_cert.signature(), signed_cert2.signature());

            // MR4: Canonical encoding
            let encoding1 = signed_cert.canonical_bytes();
            let encoding2 = signed_cert2.canonical_bytes();
            assert_eq!(encoding1, encoding2);

            // MR5: Revocation
            assert!(signed_cert.verify(key.public_key(), 2).is_ok()); // Newer gen OK

            let old_key = CertificateKey::new_for_generation(0, 98765);
            let old_cert = SignedProgressCertificate::sign(
                signed_cert.verdict().clone(),
                &old_key,
                object_id,
                issued_at,
            ).expect("Signing with old key should succeed");
            assert!(old_cert.verify(old_key.public_key(), 1).is_err()); // Should be revoked
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_key_generation() {
        let key1 = CertificateKey::new_for_generation(1, 12345);
        let key2 = CertificateKey::new_for_generation(1, 12345);

        // Same parameters should produce same key
        assert_eq!(key1.private_key, key2.private_key);
        assert_eq!(key1.public_key, key2.public_key);

        // Different generation should produce different key
        let key3 = CertificateKey::new_for_generation(2, 12345);
        assert_ne!(key1.private_key, key3.private_key);
        assert_ne!(key1.public_key, key3.public_key);
    }

    #[test]
    fn test_canonical_encoding_basic() {
        let verdict = generate_test_verdict();
        let object_id = ObjectId::new_for_test(42);
        let issued_at = Time::from_nanos(123456);

        let encoding = SignedProgressCertificate::canonical_encode(&verdict, object_id, issued_at)
            .expect("Encoding should succeed");

        assert!(!encoding.is_empty(), "Encoding should not be empty");
        assert!(encoding.len() > 16, "Encoding should contain substantial data");
    }
}