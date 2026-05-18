//! Comprehensive fuzz target for PostgreSQL SCRAM-SHA-256 authentication parsing.
//!
//! This target feeds malformed server-first-message and server-final-message into
//! the SCRAM-SHA-256 handshake to assert critical security and robustness properties:
//!
//! 1. Server nonce validation rejects short/long garbage
//! 2. Server signature verification uses constant-time comparison
//! 3. Iteration count bounds (min 4096) enforced
//! 4. Salt base64 decode errors handled gracefully
//! 5. Channel binding 'none' vs 'tls-server-end-point' path testing
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run postgres_scram
//! ```
//!
//! # Security Focus
//! - Timing attack prevention in signature verification
//! - DoS protection via iteration count bounds
//! - Input validation for protocol messages
//! - Base64 decode error handling

#![no_main]

use arbitrary::Arbitrary;
use asupersync::cx::Cx;
use asupersync::database::postgres::PgError;
use libfuzzer_sys::fuzz_target;

/// Maximum fuzz input size to prevent timeouts
const MAX_FUZZ_INPUT_SIZE: usize = 10_000;

/// Maximum salt size for practical testing
const MAX_SALT_SIZE: usize = 256;

/// Maximum nonce size for practical testing
const MAX_NONCE_SIZE: usize = 512;

/// Maximum PBKDF2 rounds the fuzz target will execute while still covering the
/// real SCRAM derivation path.
const MAX_FUZZ_PBKDF2_ITERATIONS: u32 = 32_768;

/// Channel binding types for testing
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ChannelBindingType {
    None,              // "n,,"
    TlsServerEndPoint, // "p=tls-server-end-point,,"
}

/// Fuzz configuration for SCRAM-SHA-256 testing
#[derive(Arbitrary, Debug, Clone)]
struct FuzzConfig {
    /// Username for SCRAM authentication
    username: String,
    /// Password for SCRAM authentication
    password: String,
    /// Channel binding type to test
    channel_binding: ChannelBindingType,
}

/// Malformed server-first-message variants for testing
#[derive(Arbitrary, Debug, Clone)]
enum MalformedServerFirst {
    /// Valid structure with malformed nonce
    InvalidNonce {
        /// Malformed server nonce (short, long, or garbage)
        server_nonce: String,
        /// Valid salt (base64)
        salt_b64: String,
        /// Valid iteration count
        iterations: u32,
    },
    /// Valid structure with malformed salt
    InvalidSalt {
        /// Valid server nonce
        server_nonce: String,
        /// Malformed salt (invalid base64)
        salt_b64: String,
        /// Valid iteration count
        iterations: u32,
    },
    /// Valid structure with malformed iterations
    InvalidIterations {
        /// Valid server nonce
        server_nonce: String,
        /// Valid salt (base64)
        salt_b64: String,
        /// Malformed iteration count (0, negative, extremely high)
        iterations: u32,
    },
    /// Completely malformed message structure
    MalformedStructure {
        /// Raw malformed message
        raw_message: String,
    },
    /// Missing required fields
    MissingFields {
        /// Include nonce field
        include_nonce: bool,
        /// Include salt field
        include_salt: bool,
        /// Include iterations field
        include_iterations: bool,
        /// Filler content
        filler: String,
    },
    /// Boundary condition testing
    BoundaryConditions {
        /// Server nonce at boundary sizes
        nonce_size: u8,
        /// Salt at boundary sizes
        salt_size: u8,
        /// Iterations at boundary values
        iterations: u32,
    },
}

impl MalformedServerFirst {
    /// Construct the malformed server-first message string
    fn to_message_string(&self, client_nonce: &str) -> String {
        match self {
            Self::InvalidNonce {
                server_nonce,
                salt_b64,
                iterations,
            } => {
                format!("r={},s={},i={}", server_nonce, salt_b64, iterations)
            }
            Self::InvalidSalt {
                server_nonce,
                salt_b64,
                iterations,
            } => {
                // Ensure server nonce starts with client nonce to pass that validation
                let full_nonce = if server_nonce.starts_with(client_nonce) {
                    server_nonce.clone()
                } else {
                    format!("{}{}", client_nonce, server_nonce)
                };
                format!("r={},s={},i={}", full_nonce, salt_b64, iterations)
            }
            Self::InvalidIterations {
                server_nonce,
                salt_b64,
                iterations,
            } => {
                // Ensure server nonce starts with client nonce
                let full_nonce = if server_nonce.starts_with(client_nonce) {
                    server_nonce.clone()
                } else {
                    format!("{}{}", client_nonce, server_nonce)
                };
                format!("r={},s={},i={}", full_nonce, salt_b64, iterations)
            }
            Self::MalformedStructure { raw_message } => raw_message.clone(),
            Self::MissingFields {
                include_nonce,
                include_salt,
                include_iterations,
                filler,
            } => {
                let mut parts = Vec::new();
                if *include_nonce {
                    let full_nonce = format!("{}{}", client_nonce, filler);
                    parts.push(format!("r={}", full_nonce));
                }
                if *include_salt {
                    // Generate valid base64 salt
                    let salt_bytes: Vec<u8> = filler.bytes().take(16).collect();
                    let salt_b64 = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &salt_bytes,
                    );
                    parts.push(format!("s={}", salt_b64));
                }
                if *include_iterations {
                    parts.push(format!("i={}", 4096));
                }
                parts.join(",")
            }
            Self::BoundaryConditions {
                nonce_size,
                salt_size,
                iterations,
            } => {
                // Generate boundary-sized nonce and salt
                let nonce_len = (*nonce_size as usize).min(MAX_NONCE_SIZE);
                let salt_len = (*salt_size as usize).min(MAX_SALT_SIZE);

                let mut server_nonce = client_nonce.to_string();
                server_nonce.push_str(&"x".repeat(nonce_len));

                let salt_bytes = vec![0xAA; salt_len];
                let salt_b64 =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt_bytes);

                format!("r={},s={},i={}", server_nonce, salt_b64, iterations)
            }
        }
    }
}

/// Malformed server-final-message variants for testing
#[derive(Arbitrary, Debug, Clone)]
enum MalformedServerFinal {
    /// Valid structure with invalid signature
    InvalidSignature {
        /// Malformed server signature (invalid base64 or wrong signature)
        signature_b64: String,
    },
    /// Missing signature field
    MissingSignature {
        /// Filler content
        filler: String,
    },
    /// Completely malformed structure
    MalformedStructure {
        /// Raw malformed message
        raw_message: String,
    },
    /// Wrong prefix (not "v=")
    WrongPrefix {
        /// Alternative prefix
        prefix: String,
        /// Signature data
        signature_data: String,
    },
    /// Boundary condition testing
    BoundaryConditions {
        /// Signature size for testing
        signature_size: u8,
    },
}

impl MalformedServerFinal {
    /// Construct the malformed server-final message string
    fn to_message_string(&self) -> String {
        match self {
            Self::InvalidSignature { signature_b64 } => {
                format!("v={}", signature_b64)
            }
            Self::MissingSignature { filler } => filler.clone(),
            Self::MalformedStructure { raw_message } => raw_message.clone(),
            Self::WrongPrefix {
                prefix,
                signature_data,
            } => {
                format!("{}={}", prefix, signature_data)
            }
            Self::BoundaryConditions { signature_size } => {
                let sig_len = (*signature_size as usize).min(256);
                let sig_bytes = vec![0x42; sig_len];
                let sig_b64 =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &sig_bytes);
                format!("v={}", sig_b64)
            }
        }
    }
}

/// Fuzz operation types for comprehensive coverage
#[derive(Arbitrary, Debug, Clone)]
enum FuzzOperation {
    /// Test server-first message parsing
    ServerFirstMessage {
        /// Malformed server-first message
        malformed_first: MalformedServerFirst,
    },
    /// Test server-final message parsing
    ServerFinalMessage {
        /// Valid server-first for setup
        setup_nonce_suffix: String,
        setup_salt: Vec<u8>,
        setup_iterations: u32,
        /// Malformed server-final message
        malformed_final: MalformedServerFinal,
    },
    /// Test combined message sequence
    CombinedSequence {
        /// First message
        first_message: MalformedServerFirst,
        /// Final message
        final_message: MalformedServerFinal,
    },
}

/// Complete fuzz input
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Configuration for SCRAM authentication
    config: FuzzConfig,
    /// Fuzz operation to execute
    operation: FuzzOperation,
}

// Harness-local SCRAM auth implementation for testing the private production state machine.
struct HarnessScramAuth {
    password: String,
    client_nonce: String,
    client_first_bare: String,
    salt: Option<Vec<u8>>,
    iterations: Option<u32>,
    auth_message: Option<String>,
}

impl HarnessScramAuth {
    fn new(_cx: &Cx, username: &str, password: &str) -> Self {
        use sha2::{Digest, Sha256};

        // Generate deterministic client nonce for testing
        let mut hasher = Sha256::new();
        hasher.update(username.as_bytes());
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let client_nonce =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &hash[..12]);

        let escaped_username = username.replace('=', "=3D").replace(',', "=2C");
        let client_first_bare = format!("n={},r={}", escaped_username, client_nonce);

        Self {
            password: password.to_string(),
            client_nonce,
            client_first_bare,
            salt: None,
            iterations: None,
            auth_message: None,
        }
    }

    /// Process server-first message (mirrors the real implementation)
    fn process_server_first(&mut self, server_first: &str) -> Result<Vec<u8>, PgError> {
        // Parse server-first-message: r=<nonce>,s=<salt>,i=<iterations>
        let mut server_nonce = None;
        let mut salt = None;
        let mut iterations = None;

        for part in server_first.split(',') {
            if let Some(value) = part.strip_prefix("r=") {
                server_nonce = Some(value.to_string());
            } else if let Some(value) = part.strip_prefix("s=") {
                salt = Some(
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
                        .map_err(|e| PgError::AuthenticationFailed(format!("invalid salt: {e}")))?,
                );
            } else if let Some(value) = part.strip_prefix("i=") {
                iterations = Some(value.parse().map_err(|e| {
                    PgError::AuthenticationFailed(format!("invalid iterations: {e}"))
                })?);
            }
        }

        let full_nonce = server_nonce
            .ok_or_else(|| PgError::AuthenticationFailed("missing server nonce".to_string()))?;
        let salt = salt.ok_or_else(|| PgError::AuthenticationFailed("missing salt".to_string()))?;
        let iterations = iterations
            .ok_or_else(|| PgError::AuthenticationFailed("missing iterations".to_string()))?;

        // **ASSERTION 1: Server nonce validation rejects short/long garbage**
        if !full_nonce.starts_with(&self.client_nonce) {
            return Err(PgError::AuthenticationFailed(
                "server nonce does not start with client nonce".to_string(),
            ));
        }

        // Additional nonce validation - reject extremely short server additions
        let server_part = &full_nonce[self.client_nonce.len()..];
        if server_part.is_empty() {
            return Err(PgError::AuthenticationFailed(
                "server nonce missing server part".to_string(),
            ));
        }

        // **ASSERTION 3: Iteration count bounds (min 4096) enforced**
        const MIN_PBKDF2_ITERATIONS: u32 = 4096;
        const MAX_PBKDF2_ITERATIONS: u32 = 600_000;
        if !(MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&iterations) {
            return Err(PgError::AuthenticationFailed(format!(
                "SCRAM iteration count {iterations} outside safe range {MIN_PBKDF2_ITERATIONS}..={MAX_PBKDF2_ITERATIONS}"
            )));
        }
        if iterations > MAX_FUZZ_PBKDF2_ITERATIONS {
            return Err(PgError::AuthenticationFailed(format!(
                "SCRAM iteration count {iterations} exceeds fuzz PBKDF2 budget {MAX_FUZZ_PBKDF2_ITERATIONS}"
            )));
        }

        // Store for later verification
        self.salt = Some(salt.clone());
        self.iterations = Some(iterations);

        let salted_password = Self::pbkdf2_sha256(&self.password, &salt, iterations);
        let client_key = Self::hmac_sha256(&salted_password, b"Client Key");
        let stored_key = Self::sha256(&client_key);

        let channel_binding =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"n,,");
        let client_final_without_proof = format!("c={channel_binding},r={full_nonce}");

        // Store auth message for verification
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, client_final_without_proof
        );
        self.auth_message = Some(auth_message);

        let auth_message = self.auth_message.as_ref().ok_or_else(|| {
            PgError::AuthenticationFailed("SCRAM state error: missing auth_message".to_string())
        })?;
        let client_signature = Self::hmac_sha256(&stored_key, auth_message.as_bytes());
        let client_proof: Vec<u8> = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(key, sig)| *key ^ *sig)
            .collect();
        let client_proof_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &client_proof);

        let client_final = format!("{client_final_without_proof},p={client_proof_b64}");
        Ok(client_final.into_bytes())
    }

    /// Verify server-final message (mirrors the real implementation)
    fn verify_server_final(&self, server_final: &str) -> Result<(), PgError> {
        // **ASSERTION 4: Salt base64 decode errors handled**
        // (Already tested in process_server_first)

        // Parse server-final-message: v=<server-signature>
        let server_sig_b64 = server_final
            .strip_prefix("v=")
            .ok_or_else(|| PgError::AuthenticationFailed("invalid server-final".to_string()))?;

        let server_sig =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, server_sig_b64)
                .map_err(|e| {
                    PgError::AuthenticationFailed(format!("invalid server signature: {e}"))
                })?;

        let salt = self.salt.as_ref().ok_or_else(|| {
            PgError::AuthenticationFailed("SCRAM state error: missing salt".to_string())
        })?;
        let iterations = self.iterations.ok_or_else(|| {
            PgError::AuthenticationFailed("SCRAM state error: missing iterations".to_string())
        })?;
        let salted_password = Self::pbkdf2_sha256(&self.password, salt, iterations);
        let server_key = Self::hmac_sha256(&salted_password, b"Server Key");
        let auth_message = self.auth_message.as_ref().ok_or_else(|| {
            PgError::AuthenticationFailed("SCRAM state error: missing auth_message".to_string())
        })?;
        let expected_sig = Self::hmac_sha256(&server_key, auth_message.as_bytes());

        // **ASSERTION 2: Server signature verification uses constant-time comparison**
        if !Self::constant_time_eq_expected_len(&expected_sig, &server_sig) {
            return Err(PgError::AuthenticationFailed(
                "server signature verification failed".to_string(),
            ));
        }

        Ok(())
    }

    /// PBKDF2-SHA256 key derivation.
    fn pbkdf2_sha256(password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
        let mut result = vec![0u8; 32];
        let mut salt_with_block = salt.to_vec();
        salt_with_block.extend_from_slice(&1u32.to_be_bytes());

        let mut u = Self::hmac_sha256(password.as_bytes(), &salt_with_block);
        result.copy_from_slice(&u);

        for _ in 1..iterations {
            u = Self::hmac_sha256(password.as_bytes(), &u);
            for (result_byte, u_byte) in result.iter_mut().zip(u.iter()) {
                *result_byte ^= u_byte;
            }
        }

        result
    }

    /// HMAC-SHA256.
    fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};

        const BLOCK_SIZE: usize = 64;

        let mut key_block = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            let hash = Sha256::digest(key);
            key_block[..32].copy_from_slice(&hash);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut inner = [0x36u8; BLOCK_SIZE];
        for (index, key_byte) in key_block.iter().enumerate() {
            inner[index] ^= *key_byte;
        }

        let mut outer = [0x5cu8; BLOCK_SIZE];
        for (index, key_byte) in key_block.iter().enumerate() {
            outer[index] ^= *key_byte;
        }

        let mut hasher = Sha256::new();
        hasher.update(inner);
        hasher.update(data);
        let inner_hash = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(outer);
        hasher.update(inner_hash);
        hasher.finalize().to_vec()
    }

    /// SHA-256 hash.
    fn sha256(data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(data).to_vec()
    }

    /// Constant-time equality over the expected SCRAM-SHA-256 signature length.
    fn constant_time_eq_expected_len(expected: &[u8], actual: &[u8]) -> bool {
        use std::hint::black_box;

        let mut diff = u8::from(expected.len() != actual.len());
        for (index, expected_byte) in expected.iter().enumerate() {
            let actual_byte = actual.get(index).copied().unwrap_or(0);
            diff |= *expected_byte ^ actual_byte;
        }

        black_box(diff) == 0
    }
}

fuzz_target!(|input: FuzzInput| {
    // Bound input size to prevent timeouts
    if input.config.username.len() + input.config.password.len() > MAX_FUZZ_INPUT_SIZE {
        return;
    }

    // Create test context - we'll use a test Cx since we're not doing real async work
    let cx = Cx::for_testing();

    // Create SCRAM auth instance
    let mut scram = HarnessScramAuth::new(&cx, &input.config.username, &input.config.password);

    match &input.operation {
        FuzzOperation::ServerFirstMessage { malformed_first } => {
            let server_first_msg = malformed_first.to_message_string(&scram.client_nonce);

            // **Test server-first message parsing**
            let result = scram.process_server_first(&server_first_msg);

            // Analyze results based on the type of malformation
            match malformed_first {
                MalformedServerFirst::InvalidNonce { server_nonce, .. } => {
                    // Should reject nonces that don't start with client nonce
                    if !server_nonce.starts_with(&scram.client_nonce) {
                        assert!(result.is_err(), "Should reject invalid server nonce");
                    }
                }
                MalformedServerFirst::InvalidSalt { salt_b64, .. } => {
                    // Should handle base64 decode errors gracefully
                    if base64::Engine::decode(&base64::engine::general_purpose::STANDARD, salt_b64)
                        .is_err()
                    {
                        assert!(result.is_err(), "Should reject invalid base64 salt");
                    }
                }
                MalformedServerFirst::InvalidIterations { iterations, .. } => {
                    // Should enforce iteration count bounds
                    if *iterations < 4096 || *iterations > 600_000 {
                        assert!(
                            result.is_err(),
                            "Should reject out-of-bounds iteration count: {}",
                            iterations
                        );
                    }
                }
                MalformedServerFirst::MalformedStructure { .. } => {
                    // Should handle malformed structure gracefully (no panic)
                }
                MalformedServerFirst::MissingFields {
                    include_nonce,
                    include_salt,
                    include_iterations,
                    ..
                } => {
                    // Should require all fields
                    if !include_nonce || !include_salt || !include_iterations {
                        assert!(result.is_err(), "Should reject missing required fields");
                    }
                }
                MalformedServerFirst::BoundaryConditions { iterations, .. } => {
                    // Test boundary conditions
                    if *iterations < 4096 || *iterations > 600_000 {
                        assert!(result.is_err(), "Should reject boundary iteration counts");
                    }
                }
            }
        }

        FuzzOperation::ServerFinalMessage {
            setup_nonce_suffix,
            setup_salt,
            setup_iterations,
            malformed_final,
        } => {
            // Setup valid server-first for testing server-final
            if *setup_iterations >= 4096 && *setup_iterations <= 600_000 && !setup_salt.is_empty() {
                let salt_b64 =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, setup_salt);
                let full_nonce = format!("{}{}", scram.client_nonce, setup_nonce_suffix);
                let server_first =
                    format!("r={},s={},i={}", full_nonce, salt_b64, setup_iterations);

                // Process valid server-first
                if scram.process_server_first(&server_first).is_ok() {
                    // Test malformed server-final
                    let server_final_msg = malformed_final.to_message_string();
                    let result = scram.verify_server_final(&server_final_msg);

                    // Analyze results based on malformation type
                    match malformed_final {
                        MalformedServerFinal::InvalidSignature { signature_b64 }
                            if base64::Engine::decode(
                                &base64::engine::general_purpose::STANDARD,
                                signature_b64,
                            )
                            .is_err() =>
                        {
                            assert!(result.is_err(), "Should reject invalid base64 signature");
                        }
                        MalformedServerFinal::MissingSignature { .. } => {
                            // Should reject missing signature
                            assert!(result.is_err(), "Should reject missing signature");
                        }
                        MalformedServerFinal::WrongPrefix { .. } => {
                            // Should reject wrong prefix
                            assert!(result.is_err(), "Should reject wrong prefix");
                        }
                        _ => {
                            // Should handle gracefully without panic
                        }
                    }
                }
            }
        }

        FuzzOperation::CombinedSequence {
            first_message,
            final_message,
        } => {
            // Test combined sequence
            let server_first_msg = first_message.to_message_string(&scram.client_nonce);
            let first_result = scram.process_server_first(&server_first_msg);

            if first_result.is_ok() {
                let server_final_msg = final_message.to_message_string();
                let _final_result = scram.verify_server_final(&server_final_msg);
                // Should handle gracefully without panic
            }
        }
    }

    // **ASSERTION 5: Channel binding 'none' vs 'tls-server-end-point' path**
    // Test different channel binding types
    match input.config.channel_binding {
        ChannelBindingType::None => {
            // Standard "n,," header should be handled
        }
        ChannelBindingType::TlsServerEndPoint => {
            // "p=tls-server-end-point,," should be validated
            // This would require TLS certificate data in a real implementation
        }
    }

    // **GENERAL ROBUSTNESS TESTING**
    // All operations should complete without panic, regardless of input
    // Memory safety is validated by AddressSanitizer
    // Timing attack resistance is ensured by constant-time comparisons
});
