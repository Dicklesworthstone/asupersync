#![no_main]

use libfuzzer_sys::fuzz_target;

/// TLS message reader for fuzzing TLS protocol parsing
struct TlsReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> TlsReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        if self.pos >= self.data.len() {
            return Err("Not enough data for u8".to_string());
        }
        let val = self.data[self.pos];
        self.pos += 1;
        Ok(val)
    }

    fn read_u16(&mut self) -> Result<u16, String> {
        if self.pos + 2 > self.data.len() {
            return Err("Not enough data for u16".to_string());
        }
        let val = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    fn read_u24(&mut self) -> Result<u32, String> {
        if self.pos + 3 > self.data.len() {
            return Err("Not enough data for u24".to_string());
        }
        let val = u32::from_be_bytes([
            0,
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
        ]);
        self.pos += 3;
        Ok(val)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.pos + len > self.data.len() {
            return Err("Not enough data for bytes".to_string());
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    fn read_variable_length_vector(&mut self, len_bytes: usize) -> Result<&'a [u8], String> {
        let len = match len_bytes {
            1 => self.read_u8()? as usize,
            2 => self.read_u16()? as usize,
            3 => self.read_u24()? as usize,
            _ => return Err("Invalid length field size".to_string()),
        };

        if len > 1_000_000 {
            return Err("Vector too large".to_string());
        }

        self.read_bytes(len)
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

/// Parse TLS handshake message structure
fn parse_handshake_message(data: &[u8]) -> Result<(u8, u32, &[u8]), String> {
    let mut reader = TlsReader::new(data);

    let msg_type = reader.read_u8()?;
    let length = reader.read_u24()?;

    if length > 1_000_000 {
        return Err("Message too large".to_string());
    }

    let body = reader.read_bytes(length as usize)?;
    Ok((msg_type, length, body))
}

/// Parse TLS Certificate handshake message
fn parse_certificate_handshake(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut reader = TlsReader::new(data);

    // Certificate list length (24-bit)
    let cert_list_len = reader.read_u24()?;
    if cert_list_len > 1_000_000 {
        return Err("Certificate list too large".to_string());
    }

    let mut certificates = Vec::new();

    while reader.remaining() > 0 {
        // Certificate length (24-bit)
        let cert_len = reader.read_u24()?;
        if cert_len > 100_000 {
            return Err("Certificate too large".to_string());
        }

        let cert_data = reader.read_bytes(cert_len as usize)?.to_vec();
        certificates.push(cert_data);

        if certificates.len() > 10 {
            return Err("Too many certificates".to_string());
        }
    }

    Ok(certificates)
}

/// Parse TLS ServerHello message
fn parse_server_hello(data: &[u8]) -> Result<(), String> {
    let mut reader = TlsReader::new(data);

    // Protocol version
    let _version = reader.read_u16()?;

    // Random (32 bytes)
    let _random = reader.read_bytes(32)?;

    // Session ID length
    let session_id_len = reader.read_u8()? as usize;
    if session_id_len > 32 {
        return Err("Invalid session ID length".to_string());
    }

    // Session ID
    let _session_id = reader.read_bytes(session_id_len)?;

    // Cipher suite
    let _cipher_suite = reader.read_u16()?;

    // Compression method
    let _compression = reader.read_u8()?;

    // Extensions (optional)
    if reader.remaining() > 0 {
        let extensions_len = reader.read_u16()?;
        let _extensions = reader.read_bytes(extensions_len as usize)?;
    }

    Ok(())
}

/// Parse ClientHello message
fn parse_client_hello(data: &[u8]) -> Result<(), String> {
    let mut reader = TlsReader::new(data);

    // Protocol version
    let _version = reader.read_u16()?;

    // Random (32 bytes)
    let _random = reader.read_bytes(32)?;

    // Session ID
    let session_id_len = reader.read_u8()? as usize;
    if session_id_len > 32 {
        return Err("Invalid session ID length".to_string());
    }
    let _session_id = reader.read_bytes(session_id_len)?;

    // Cipher suites
    let cipher_suites_len = reader.read_u16()? as usize;
    if cipher_suites_len % 2 != 0 {
        return Err("Invalid cipher suites length".to_string());
    }
    let _cipher_suites = reader.read_bytes(cipher_suites_len)?;

    // Compression methods
    let compression_len = reader.read_u8()? as usize;
    let _compression_methods = reader.read_bytes(compression_len)?;

    // Extensions (optional)
    if reader.remaining() > 0 {
        let extensions_len = reader.read_u16()?;
        let _extensions = reader.read_bytes(extensions_len as usize)?;
    }

    Ok(())
}

/// Parse TLS extension
fn parse_extension(data: &[u8]) -> Result<(u16, &[u8]), String> {
    let mut reader = TlsReader::new(data);
    let ext_type = reader.read_u16()?;
    let ext_data = reader.read_variable_length_vector(2)?;
    Ok((ext_type, ext_data))
}

/// Parse Server Name Indication (SNI) extension
fn parse_sni_extension(data: &[u8]) -> Result<Vec<String>, String> {
    let mut reader = TlsReader::new(data);

    let list_len = reader.read_u16()?;
    if list_len as usize != reader.remaining() {
        return Err("SNI list length mismatch".to_string());
    }

    let mut names = Vec::new();

    while reader.remaining() > 0 {
        let name_type = reader.read_u8()?;
        let name_len = reader.read_u16()? as usize;

        if name_len > 255 {
            return Err("SNI name too long".to_string());
        }

        let name_bytes = reader.read_bytes(name_len)?;

        if name_type == 0 {
            // hostname
            let hostname = String::from_utf8_lossy(name_bytes).to_string();
            names.push(hostname);
        }

        if names.len() > 10 {
            return Err("Too many SNI names".to_string());
        }
    }

    Ok(names)
}

/// Test certificate parsing with asupersync types
fn test_certificate_parsing(data: &[u8]) {
    use asupersync::tls::{Certificate, CertificateChain, CertificatePin, CertificatePinSet};

    // Test DER parsing
    let _ = Certificate::from_der(data.to_vec());

    // Test PEM parsing
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Certificate::from_pem(s.as_bytes());
    }

    // Test chain operations
    let cert = Certificate::from_der(data.to_vec());
    let mut chain = CertificateChain::new();
    chain.push(cert.clone());

    // Test pin computation
    let _ = CertificatePin::compute_spki_sha256(&cert);
    let _ = CertificatePin::compute_cert_sha256(&cert);

    // Test pin set validation
    let pin_set = CertificatePinSet::new();
    let _ = pin_set.validate(&cert);
}

/// Test private key parsing
fn test_private_key_parsing(data: &[u8]) {
    use asupersync::tls::PrivateKey;

    // Test PKCS#8 DER
    let _ = PrivateKey::from_pkcs8_der(data.to_vec());

    // Test SEC1 DER
    let _ = PrivateKey::from_sec1_der(data.to_vec());

    // Test PEM parsing
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = PrivateKey::from_pem(s.as_bytes());
    }
}

/// Test certificate pin operations
fn test_certificate_pin_operations(data: &[u8]) {
    use asupersync::tls::{CertificatePin, CertificatePinSet};

    // Test base64 decoding
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = CertificatePin::spki_sha256_base64(s);
        let _ = CertificatePin::cert_sha256_base64(s);
    }

    // Test raw bytes
    if data.len() >= 32 {
        let _ = CertificatePin::spki_sha256(&data[..32]);
        let _ = CertificatePin::cert_sha256(&data[..32]);
    }

    // Test pin set operations
    let mut pin_set = CertificatePinSet::new();
    if let Ok(pin) = CertificatePin::spki_sha256(vec![0u8; 32]) {
        pin_set.add(pin);
    }
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 100_000 {
        return;
    }

    // Test 1: Parse as TLS handshake message
    if data.len() >= 4 {
        let _ = parse_handshake_message(data);
    }

    // Test 2: Parse as Certificate handshake message
    if data.len() >= 3 {
        let _ = parse_certificate_handshake(data);
    }

    // Test 3: Parse as ServerHello message
    if data.len() >= 35 {
        let _ = parse_server_hello(data);
    }

    // Test 4: Parse as ClientHello message
    if data.len() >= 35 {
        let _ = parse_client_hello(data);
    }

    // Test 5: Parse as TLS extension
    if data.len() >= 4 {
        let _ = parse_extension(data);
    }

    // Test 6: Parse as SNI extension
    if data.len() >= 2 {
        let _ = parse_sni_extension(data);
    }

    // Test 7: Certificate parsing with asupersync types
    test_certificate_parsing(data);

    // Test 8: Private key parsing
    test_private_key_parsing(data);

    // Test 9: Certificate pin operations
    test_certificate_pin_operations(data);

    // Test 10: TLS message structure parsing
    let mut reader = TlsReader::new(data);
    let _ = reader.read_u8();
    let _ = reader.read_u16();
    let _ = reader.read_u24();
    let _ = reader.read_variable_length_vector(1);
    let _ = reader.read_variable_length_vector(2);
    let _ = reader.read_variable_length_vector(3);
});
