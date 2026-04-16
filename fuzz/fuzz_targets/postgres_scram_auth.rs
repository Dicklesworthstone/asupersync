#![no_main]

use libfuzzer_sys::fuzz_target;

/// SCRAM-SHA-256 message parser for fuzzing PostgreSQL authentication
struct ScramParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ScramParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_until(&mut self, delimiter: u8) -> Result<&'a [u8], String> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != delimiter {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return Err("Delimiter not found".to_string());
        }
        let result = &self.data[start..self.pos];
        self.pos += 1; // Skip delimiter
        Ok(result)
    }

    fn read_to_end(&mut self) -> &'a [u8] {
        let result = &self.data[self.pos..];
        self.pos = self.data.len();
        result
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

/// Parse SCRAM-SHA-256 server-first message
/// Format: r=<nonce>,s=<salt>,i=<iterations>
fn parse_server_first(data: &[u8]) -> Result<(String, Vec<u8>, u32), String> {
    let message = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8")?;

    let mut server_nonce = None;
    let mut salt_b64 = None;
    let mut iterations = None;

    for part in message.split(',') {
        if let Some(value) = part.strip_prefix("r=") {
            if value.is_empty() {
                return Err("Empty server nonce".to_string());
            }
            if value.len() > 256 {
                return Err("Server nonce too long".to_string());
            }
            server_nonce = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("s=") {
            if value.is_empty() {
                return Err("Empty salt".to_string());
            }
            salt_b64 = Some(value);
        } else if let Some(value) = part.strip_prefix("i=") {
            iterations = Some(value.parse::<u32>().map_err(|_| "Invalid iteration count")?);
        }
    }

    let server_nonce = server_nonce.ok_or("Missing server nonce")?;
    let salt_b64 = salt_b64.ok_or("Missing salt")?;
    let iterations = iterations.ok_or("Missing iterations")?;

    // Decode base64 salt
    use base64::Engine;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(salt_b64)
        .map_err(|_| "Invalid base64 salt")?;

    if salt.is_empty() || salt.len() > 64 {
        return Err("Invalid salt length".to_string());
    }

    // Validate iteration count (RFC 7677 recommends 4096 minimum)
    const MAX_ITERATIONS: u32 = 600_000;
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err(format!("Invalid iteration count: {iterations}"));
    }

    Ok((server_nonce, salt, iterations))
}

/// Parse SCRAM-SHA-256 server-final message
/// Format: v=<signature> or e=<error>
fn parse_server_final(data: &[u8]) -> Result<Vec<u8>, String> {
    let message = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8")?;

    if let Some(error) = message.strip_prefix("e=") {
        return Err(format!("Server error: {error}"));
    }

    let signature_b64 = message
        .strip_prefix("v=")
        .ok_or("Missing server signature")?;

    if signature_b64.is_empty() {
        return Err("Empty server signature".to_string());
    }

    // Decode base64 signature
    use base64::Engine;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|_| "Invalid base64 signature")?;

    // SHA-256 output should be 32 bytes
    if signature.len() != 32 {
        return Err(format!("Invalid signature length: {}", signature.len()));
    }

    Ok(signature)
}

/// Parse PostgreSQL SASL mechanism list
fn parse_sasl_mechanisms(data: &[u8]) -> Result<Vec<String>, String> {
    let mut parser = ScramParser::new(data);
    let mut mechanisms = Vec::new();

    while parser.remaining() > 0 {
        let mechanism_bytes = parser.read_until(0)?;
        let mechanism = std::str::from_utf8(mechanism_bytes)
            .map_err(|_| "Invalid UTF-8 in mechanism name")?;

        if mechanism.is_empty() {
            continue;
        }

        if mechanism.len() > 64 {
            return Err("Mechanism name too long".to_string());
        }

        mechanisms.push(mechanism.to_string());

        if mechanisms.len() > 10 {
            return Err("Too many mechanisms".to_string());
        }
    }

    Ok(mechanisms)
}

/// Generate client-first message for fuzzing
fn generate_client_first(username: &str, client_nonce: &str) -> Result<Vec<u8>, String> {
    if username.is_empty() || username.len() > 63 {
        return Err("Invalid username length".to_string());
    }

    if client_nonce.is_empty() || client_nonce.len() > 32 {
        return Err("Invalid client nonce length".to_string());
    }

    // Validate username contains only safe characters
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err("Invalid username characters".to_string());
    }

    // client-first-message-bare
    let client_first_bare = format!("n={username},r={client_nonce}");

    // Complete client-first-message with GS2 header
    let client_first = format!("n,,{client_first_bare}");

    Ok(client_first.into_bytes())
}

/// Parse client-final message for validation
fn parse_client_final(data: &[u8]) -> Result<(String, String, Vec<u8>), String> {
    let message = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8")?;

    let mut channel_binding = None;
    let mut nonce = None;
    let mut proof_b64 = None;

    for part in message.split(',') {
        if let Some(value) = part.strip_prefix("c=") {
            channel_binding = Some(value);
        } else if let Some(value) = part.strip_prefix("r=") {
            nonce = Some(value);
        } else if let Some(value) = part.strip_prefix("p=") {
            proof_b64 = Some(value);
        }
    }

    let channel_binding = channel_binding.ok_or("Missing channel binding")?;
    let nonce = nonce.ok_or("Missing nonce")?.to_string();
    let proof_b64 = proof_b64.ok_or("Missing proof")?;

    // Decode base64 proof
    use base64::Engine;
    let proof = base64::engine::general_purpose::STANDARD
        .decode(proof_b64)
        .map_err(|_| "Invalid base64 proof")?;

    // Client proof should be 32 bytes (SHA-256)
    if proof.len() != 32 {
        return Err(format!("Invalid proof length: {}", proof.len()));
    }

    Ok((channel_binding.to_string(), nonce, proof))
}

/// Simple PBKDF2-SHA256 implementation for testing
fn pbkdf2_sha256_test(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    if iterations == 0 || iterations > 100_000 || salt.is_empty() || salt.len() > 64 {
        return vec![0u8; 32]; // Return zero bytes for invalid inputs
    }

    // Simplified PBKDF2 - just for parsing validation, not crypto security
    let mut result = vec![0u8; 32];
    let mut current = salt.to_vec();
    current.extend_from_slice(&1u32.to_be_bytes());

    // Very simple hash mixing - not secure, just for fuzz testing structure
    for _ in 0..iterations.min(1000) {
        for (i, &pwd_byte) in password.iter().enumerate() {
            if i < current.len() {
                current[i] ^= pwd_byte;
            }
        }

        // Simple hash function for testing
        let mut hash = 0u32;
        for &byte in &current {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
        }

        for i in 0..result.len() {
            result[i] ^= (hash >> (i % 4 * 8)) as u8;
        }
    }

    result
}

/// Test various SCRAM-SHA-256 parsing edge cases
fn test_scram_edge_cases(data: &[u8]) {
    // Test with empty data
    if data.is_empty() {
        return;
    }

    // Test username extraction from various formats
    if let Ok(s) = std::str::from_utf8(data) {
        // Test as username
        let _ = generate_client_first(s, "testnonce123");

        // Test as nonce
        let _ = generate_client_first("testuser", s);

        // Test as server-first message
        let _ = parse_server_first(data);

        // Test as server-final message
        let _ = parse_server_final(data);
    }

    // Test PBKDF2 with fuzzed inputs
    let iterations = if data.len() >= 4 {
        u32::from_be_bytes([
            data[0],
            data.get(1).copied().unwrap_or(0),
            data.get(2).copied().unwrap_or(0),
            data.get(3).copied().unwrap_or(0)
        ])
    } else {
        4096
    };

    let (password_data, salt_data) = if data.len() > 4 {
        data[4..].split_at(data[4..].len() / 2)
    } else {
        (data, &[0u8; 1][..])
    };

    let _ = pbkdf2_sha256_test(password_data, salt_data, iterations);
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 10_000 {
        return;
    }

    // Test 1: Parse as SASL mechanism list
    let _ = parse_sasl_mechanisms(data);

    // Test 2: Parse as SCRAM server-first message
    let _ = parse_server_first(data);

    // Test 3: Parse as SCRAM server-final message
    let _ = parse_server_final(data);

    // Test 4: Parse as client-final message
    let _ = parse_client_final(data);

    // Test 5: SCRAM edge cases and malformed inputs
    test_scram_edge_cases(data);

    // Test 6: Username and nonce validation
    if let Ok(s) = std::str::from_utf8(data) {
        // Split data into username and nonce parts
        let parts: Vec<&str> = s.splitn(2, ',').collect();
        if parts.len() == 2 {
            let _ = generate_client_first(parts[0], parts[1]);
        }
    }

    // Test 7: Base64 decoding edge cases
    if let Ok(s) = std::str::from_utf8(data) {
        use base64::Engine;
        let _ = base64::engine::general_purpose::STANDARD.decode(s);
        let _ = base64::engine::general_purpose::URL_SAFE.decode(s);
        let _ = base64::engine::general_purpose::STANDARD_NO_PAD.decode(s);
    }

    // Test 8: Parser state machine with truncated inputs
    let mut parser = ScramParser::new(data);
    while parser.remaining() > 0 {
        let _ = parser.read_until(b',');
        let _ = parser.read_until(b'=');
        let _ = parser.read_until(b'\0');
    }
    let _ = parser.read_to_end();
});