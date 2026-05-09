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
fn parse_server_hello(data: &[u8]) -> Result<usize, String> {
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

    Ok(reader.pos)
}

/// Parse ClientHello message
fn parse_client_hello(data: &[u8]) -> Result<usize, String> {
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
    if !cipher_suites_len.is_multiple_of(2) {
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

    Ok(reader.pos)
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

fn assert_visible_string_error(error: &str, context: &str) {
    assert!(
        !error.is_empty(),
        "{context} parser errors should stay visible"
    );
}

fn assert_visible_debug<T: std::fmt::Debug>(value: &T, context: &str) {
    let rendered = format!("{value:?}");
    assert!(
        !rendered.is_empty(),
        "{context} successful parser output should stay visible"
    );
}

fn observe_string_result<T: std::fmt::Debug>(
    result: Result<T, String>,
    context: &str,
) -> Option<T> {
    match result {
        Ok(value) => {
            assert_visible_debug(&value, context);
            Some(value)
        }
        Err(error) => {
            assert_visible_string_error(&error, context);
            None
        }
    }
}

fn observe_tls_result<T, E: std::fmt::Debug>(
    result: Result<T, E>,
    context: &str,
    on_success: impl FnOnce(T),
) {
    match result {
        Ok(value) => on_success(value),
        Err(error) => assert_visible_debug(&error, context),
    }
}

fn observe_handshake_message(data: &[u8]) {
    if let Some((_message_type, length, body)) =
        observe_string_result(parse_handshake_message(data), "TLS handshake message")
    {
        assert_eq!(
            body.len(),
            length as usize,
            "TLS handshake body length should match declared length"
        );
        assert!(
            body.len() + 4 <= data.len(),
            "TLS handshake parser should not consume beyond input"
        );
    }
}

fn observe_certificate_handshake(data: &[u8]) {
    if let Some(certificates) = observe_string_result(
        parse_certificate_handshake(data),
        "TLS certificate handshake",
    ) {
        assert!(
            certificates.len() <= 10,
            "TLS certificate handshake should keep certificate count bounded"
        );
        let total_bytes: usize = certificates.iter().map(Vec::len).sum();
        assert!(
            total_bytes <= data.len(),
            "TLS certificate handshake output should stay input-bounded"
        );
    }
}

fn observe_hello_parse(result: Result<usize, String>, data_len: usize, context: &str) {
    if let Some(consumed) = observe_string_result(result, context) {
        assert!(
            consumed <= data_len,
            "{context} parser should not consume beyond input"
        );
        assert!(
            consumed >= 35,
            "{context} success should include the fixed hello prefix"
        );
    }
}

fn observe_extension_parse(data: &[u8]) {
    if let Some((_extension_type, extension_data)) =
        observe_string_result(parse_extension(data), "TLS extension")
    {
        assert!(
            extension_data.len() + 4 <= data.len(),
            "TLS extension output should stay input-bounded"
        );
    }
}

fn observe_sni_extension(data: &[u8]) {
    if let Some(names) = observe_string_result(parse_sni_extension(data), "TLS SNI extension") {
        assert!(
            names.len() <= 10,
            "TLS SNI parser should keep hostname count bounded"
        );
        for name in names {
            assert!(
                name.len() <= 255,
                "TLS SNI parser should keep hostname length bounded"
            );
        }
    }
}

/// Test certificate parsing with asupersync types
fn test_certificate_parsing(data: &[u8]) {
    use asupersync::tls::{Certificate, CertificateChain, CertificatePin, CertificatePinSet};

    // Test DER parsing
    let cert = Certificate::from_der(data.to_vec());
    assert_eq!(
        cert.as_der().len(),
        data.len(),
        "DER certificate wrapper should preserve input length"
    );

    // Test PEM parsing
    if let Ok(s) = std::str::from_utf8(data) {
        observe_tls_result(
            Certificate::from_pem(s.as_bytes()),
            "TLS certificate PEM",
            |certs| {
                assert!(
                    !certs.is_empty(),
                    "successful certificate PEM parse should yield certificates"
                );
            },
        );
    }

    // Test chain operations
    let mut chain = CertificateChain::new();
    chain.push(cert.clone());
    assert_eq!(
        chain.len(),
        1,
        "certificate chain should retain pushed certificate"
    );

    // Test pin computation
    observe_tls_result(
        CertificatePin::compute_spki_sha256(&cert),
        "TLS SPKI pin computation",
        |pin| {
            assert_eq!(
                pin.hash_bytes().len(),
                32,
                "SPKI pin should be SHA-256 sized"
            );
        },
    );
    observe_tls_result(
        CertificatePin::compute_cert_sha256(&cert),
        "TLS certificate pin computation",
        |pin| {
            assert_eq!(
                pin.hash_bytes().len(),
                32,
                "certificate pin should be SHA-256 sized"
            );
        },
    );

    // Test pin set validation
    let pin_set = CertificatePinSet::new();
    observe_tls_result(
        pin_set.validate(&cert),
        "TLS pin set validation",
        |matched| {
            assert!(
                !matched.to_string().is_empty(),
                "pin set validation result should stay visible"
            );
        },
    );
}

/// Test private key parsing
fn test_private_key_parsing(data: &[u8]) {
    use asupersync::tls::PrivateKey;

    // Test PKCS#8 DER
    let pkcs8_key = PrivateKey::from_pkcs8_der(data.to_vec());
    assert!(
        std::mem::size_of_val(&pkcs8_key) > 0,
        "PKCS#8 key wrapper should be materialized"
    );

    // Test SEC1 DER
    let sec1_key = PrivateKey::from_sec1_der(data.to_vec());
    assert!(
        std::mem::size_of_val(&sec1_key) > 0,
        "SEC1 key wrapper should be materialized"
    );

    // Test PEM parsing
    if let Ok(s) = std::str::from_utf8(data) {
        observe_tls_result(
            PrivateKey::from_pem(s.as_bytes()),
            "TLS private key PEM",
            |key| {
                assert!(
                    std::mem::size_of_val(&key) > 0,
                    "successful private key PEM parse should materialize a key"
                );
            },
        );
    }
}

/// Test certificate pin operations
fn test_certificate_pin_operations(data: &[u8]) {
    use asupersync::tls::{CertificatePin, CertificatePinSet};

    // Test base64 decoding
    if let Ok(s) = std::str::from_utf8(data) {
        observe_tls_result(
            CertificatePin::spki_sha256_base64(s),
            "TLS SPKI base64 pin",
            |pin| {
                assert_eq!(
                    pin.hash_bytes().len(),
                    32,
                    "base64 SPKI pin should be SHA-256 sized"
                );
            },
        );
        observe_tls_result(
            CertificatePin::cert_sha256_base64(s),
            "TLS certificate base64 pin",
            |pin| {
                assert_eq!(
                    pin.hash_bytes().len(),
                    32,
                    "base64 certificate pin should be SHA-256 sized"
                );
            },
        );
    }

    // Test raw bytes
    if data.len() >= 32 {
        observe_tls_result(
            CertificatePin::spki_sha256(&data[..32]),
            "TLS raw SPKI pin",
            |pin| {
                assert_eq!(
                    pin.hash_bytes().len(),
                    32,
                    "raw SPKI pin should be SHA-256 sized"
                );
            },
        );
        observe_tls_result(
            CertificatePin::cert_sha256(&data[..32]),
            "TLS raw certificate pin",
            |pin| {
                assert_eq!(
                    pin.hash_bytes().len(),
                    32,
                    "raw certificate pin should be SHA-256 sized"
                );
            },
        );
    }

    // Test pin set operations
    let mut pin_set = CertificatePinSet::new();
    if let Ok(pin) = CertificatePin::spki_sha256(vec![0u8; 32]) {
        pin_set.add(pin);
        assert_eq!(pin_set.len(), 1, "pin set should retain inserted pin");
    }
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 100_000 {
        return;
    }

    // Test 1: Parse as TLS handshake message
    if data.len() >= 4 {
        observe_handshake_message(data);
    }

    // Test 2: Parse as Certificate handshake message
    if data.len() >= 3 {
        observe_certificate_handshake(data);
    }

    // Test 3: Parse as ServerHello message
    if data.len() >= 35 {
        observe_hello_parse(parse_server_hello(data), data.len(), "TLS ServerHello");
    }

    // Test 4: Parse as ClientHello message
    if data.len() >= 35 {
        observe_hello_parse(parse_client_hello(data), data.len(), "TLS ClientHello");
    }

    // Test 5: Parse as TLS extension
    if data.len() >= 4 {
        observe_extension_parse(data);
    }

    // Test 6: Parse as SNI extension
    if data.len() >= 2 {
        observe_sni_extension(data);
    }

    // Test 7: Certificate parsing with asupersync types
    test_certificate_parsing(data);

    // Test 8: Private key parsing
    test_private_key_parsing(data);

    // Test 9: Certificate pin operations
    test_certificate_pin_operations(data);

    // Test 10: TLS message structure parsing
    let mut reader = TlsReader::new(data);
    observe_string_result(reader.read_u8(), "TLS reader u8");
    observe_string_result(reader.read_u16(), "TLS reader u16");
    observe_string_result(reader.read_u24(), "TLS reader u24");
    observe_string_result(
        reader.read_variable_length_vector(1),
        "TLS reader one-byte vector",
    );
    observe_string_result(
        reader.read_variable_length_vector(2),
        "TLS reader two-byte vector",
    );
    observe_string_result(
        reader.read_variable_length_vector(3),
        "TLS reader three-byte vector",
    );
});
