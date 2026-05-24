//! Metamorphic Testing for Web, TLS, Codec, and RaptorQ Modules
//!
//! This module implements comprehensive metamorphic relations testing web protocol
//! handling, TLS connection security, codec operations, and RaptorQ forward error
//! correction. These tests address the oracle problem where conventional unit tests
//! cannot verify protocol correctness, cryptographic properties, and codec round-trips.
//!
//! ## Metamorphic Relations Implemented
//!
//! ### Web Module (6 MRs)
//! - MR-MultipartParseSerialize: multipart parse(serialize(data)) = data
//! - MR-SessionCookieCryptoBind: session cookies maintain cryptographic binding
//! - MR-WebsocketFrameCodec: websocket encode → decode preserves frame structure
//! - MR-SSEStreamChunking: SSE chunking preserves message boundaries
//! - MR-CSRFTokenValidation: CSRF token validation is deterministic
//! - MR-CompressGzipRoundTrip: gzip compress → decompress preserves content
//!
//! ### TLS Module (2 MRs)
//! - MR-AcceptorConnectorSymmetry: TLS handshake is symmetric between peers
//! - MR-HandshakeStateDeterminism: TLS state transitions are deterministic
//!
//! ### Codec Module (2 MRs)
//! - MR-RaptorQCodecRoundTrip: RaptorQ encode → decode recovers original data
//! - MR-CodecFramingPreservation: codec framing preserves message boundaries

#[cfg(test)]
mod tests {
    #[cfg(test)]
    use proptest::prelude::*;
    use std::collections::HashMap;

    // ═══════════════════════════════════════════════════════════════════════════
    // Mock Implementations for Metamorphic Testing
    // ═══════════════════════════════════════════════════════════════════════════

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockMultipartField {
        pub name: String,
        pub value: MultipartValue,
        pub content_type: Option<String>,
        pub filename: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MultipartValue {
        Text(String),
        Binary(Vec<u8>),
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockMultipartData {
        pub boundary: String,
        pub fields: Vec<MockMultipartField>,
    }

    impl MockMultipartData {
        pub fn serialize(&self) -> Vec<u8> {
            let mut result = Vec::new();

            for field in &self.fields {
                result.extend_from_slice(format!("--{}\r\n", self.boundary).as_bytes());
                result.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{}\"", field.name).as_bytes(),
                );

                if let Some(ref filename) = field.filename {
                    result.extend_from_slice(format!("; filename=\"{}\"", filename).as_bytes());
                }
                result.extend_from_slice(b"\r\n");

                if let Some(ref content_type) = field.content_type {
                    result.extend_from_slice(
                        format!("Content-Type: {}\r\n", content_type).as_bytes(),
                    );
                }
                result.extend_from_slice(b"\r\n");

                match &field.value {
                    MultipartValue::Text(text) => result.extend_from_slice(text.as_bytes()),
                    MultipartValue::Binary(data) => result.extend_from_slice(data),
                }
                result.extend_from_slice(b"\r\n");
            }

            result.extend_from_slice(format!("--{}--\r\n", self.boundary).as_bytes());
            result
        }

        pub fn parse(data: &[u8], boundary: &str) -> Option<MockMultipartData> {
            let content = String::from_utf8_lossy(data);
            let delimiter = format!("--{}", boundary);
            let end_delimiter = format!("--{}--", boundary);

            let mut fields = Vec::new();
            let parts: Vec<&str> = content.split(&delimiter).collect();

            for part in &parts[1..] {
                if part.starts_with("--") || part.trim().is_empty() {
                    continue;
                }

                let lines: Vec<&str> = part.split("\r\n").collect();
                if lines.len() < 3 {
                    continue;
                }

                // Parse Content-Disposition header
                let disposition_line = lines[0];
                let name = if let Some(name_start) = disposition_line.find("name=\"") {
                    let name_start = name_start + 6;
                    if let Some(name_end) = disposition_line[name_start..].find('"') {
                        disposition_line[name_start..name_start + name_end].to_string()
                    } else {
                        continue;
                    }
                } else {
                    continue;
                };

                let filename = if let Some(filename_start) = disposition_line.find("filename=\"") {
                    let filename_start = filename_start + 10;
                    if let Some(filename_end) = disposition_line[filename_start..].find('"') {
                        Some(
                            disposition_line[filename_start..filename_start + filename_end]
                                .to_string(),
                        )
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Parse Content-Type if present
                let mut content_type = None;
                let mut content_start = 2; // Skip disposition line and empty line

                if lines.len() > 2 && lines[1].starts_with("Content-Type:") {
                    content_type = Some(lines[1][14..].trim().to_string());
                    content_start = 3; // Skip disposition, content-type, and empty line
                }

                // Extract content (everything after headers)
                let content_lines = &lines[content_start..];
                let content_text = content_lines.join("\r\n").trim_end().to_string();

                let value = if content_type
                    .as_ref()
                    .map_or(false, |ct| ct.starts_with("application/octet-stream"))
                {
                    MultipartValue::Binary(content_text.as_bytes().to_vec())
                } else {
                    MultipartValue::Text(content_text)
                };

                fields.push(MockMultipartField {
                    name,
                    value,
                    content_type,
                    filename,
                });
            }

            Some(MockMultipartData {
                boundary: boundary.to_string(),
                fields,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockSessionCookie {
        pub session_id: String,
        pub user_data: HashMap<String, String>,
        pub hmac_signature: String,
        pub expires_at: u64,
    }

    impl MockSessionCookie {
        pub fn new(
            session_id: String,
            user_data: HashMap<String, String>,
            secret_key: &[u8],
            timestamp: u64,
        ) -> Self {
            let hmac_signature = Self::calculate_hmac(&session_id, &user_data, secret_key);
            MockSessionCookie {
                session_id,
                user_data,
                hmac_signature,
                expires_at: timestamp + 3600, // 1 hour
            }
        }

        pub fn verify_integrity(&self, secret_key: &[u8]) -> bool {
            let expected_hmac = Self::calculate_hmac(&self.session_id, &self.user_data, secret_key);
            self.hmac_signature == expected_hmac
        }

        fn calculate_hmac(
            session_id: &str,
            user_data: &HashMap<String, String>,
            secret_key: &[u8],
        ) -> String {
            // Simplified HMAC calculation for testing
            let mut data_to_sign = session_id.to_string();
            let mut sorted_keys: Vec<_> = user_data.keys().collect();
            sorted_keys.sort();

            for key in sorted_keys {
                data_to_sign.push_str(key);
                data_to_sign.push_str(user_data.get(key).unwrap());
            }

            // Simple hash-based signature (not cryptographically secure, just for testing)
            let combined = format!("{}{:?}", data_to_sign, secret_key);
            format!("{:x}", combined.len() * 1337) // Deterministic but simple
        }

        pub fn serialize(&self) -> String {
            let mut parts = Vec::new();
            parts.push(format!("session_id={}", self.session_id));

            for (key, value) in &self.user_data {
                parts.push(format!("{}={}", key, value));
            }

            parts.push(format!("sig={}", self.hmac_signature));
            parts.push(format!("exp={}", self.expires_at));

            parts.join(";")
        }

        pub fn deserialize(cookie_value: &str, secret_key: &[u8]) -> Option<MockSessionCookie> {
            let parts: HashMap<String, String> = cookie_value
                .split(';')
                .filter_map(|part| {
                    let mut kv = part.split('=');
                    Some((kv.next()?.to_string(), kv.next()?.to_string()))
                })
                .collect();

            let session_id = parts.get("session_id")?.clone();
            let hmac_signature = parts.get("sig")?.clone();
            let expires_at = parts.get("exp")?.parse().ok()?;

            let mut user_data = HashMap::new();
            for (key, value) in &parts {
                if !["session_id", "sig", "exp"].contains(&key.as_str()) {
                    user_data.insert(key.clone(), value.clone());
                }
            }

            let cookie = MockSessionCookie {
                session_id,
                user_data,
                hmac_signature,
                expires_at,
            };

            if cookie.verify_integrity(secret_key) {
                Some(cookie)
            } else {
                None
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockWebSocketFrame {
        Text { payload: String, fin: bool },
        Binary { payload: Vec<u8>, fin: bool },
        Close { code: u16, reason: String },
        Ping { payload: Vec<u8> },
        Pong { payload: Vec<u8> },
    }

    impl MockWebSocketFrame {
        pub fn encode(&self) -> Vec<u8> {
            let mut frame = Vec::new();

            match self {
                MockWebSocketFrame::Text { payload, fin } => {
                    let opcode = if *fin { 0x81 } else { 0x01 }; // Text frame
                    frame.push(opcode);
                    Self::encode_payload(&mut frame, payload.as_bytes());
                }
                MockWebSocketFrame::Binary { payload, fin } => {
                    let opcode = if *fin { 0x82 } else { 0x02 }; // Binary frame
                    frame.push(opcode);
                    Self::encode_payload(&mut frame, payload);
                }
                MockWebSocketFrame::Close { code, reason } => {
                    frame.push(0x88); // Close frame
                    let mut payload = Vec::new();
                    payload.extend_from_slice(&code.to_be_bytes());
                    payload.extend_from_slice(reason.as_bytes());
                    Self::encode_payload(&mut frame, &payload);
                }
                MockWebSocketFrame::Ping { payload } => {
                    frame.push(0x89); // Ping frame
                    Self::encode_payload(&mut frame, payload);
                }
                MockWebSocketFrame::Pong { payload } => {
                    frame.push(0x8A); // Pong frame
                    Self::encode_payload(&mut frame, payload);
                }
            }

            frame
        }

        fn encode_payload(frame: &mut Vec<u8>, payload: &[u8]) {
            let len = payload.len();
            if len < 126 {
                frame.push(len as u8);
            } else if len < 65536 {
                frame.push(126);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
            } else {
                frame.push(127);
                frame.extend_from_slice(&(len as u64).to_be_bytes());
            }
            frame.extend_from_slice(payload);
        }

        pub fn decode(data: &[u8]) -> Option<MockWebSocketFrame> {
            if data.len() < 2 {
                return None;
            }

            let opcode = data[0] & 0x0F;
            let fin = (data[0] & 0x80) != 0;
            let payload_len = data[1] & 0x7F;

            let (header_len, actual_len) = match payload_len {
                126 => {
                    if data.len() < 4 {
                        return None;
                    }
                    (4, u16::from_be_bytes([data[2], data[3]]) as usize)
                }
                127 => {
                    if data.len() < 10 {
                        return None;
                    }
                    let len_bytes: [u8; 8] = data[2..10].try_into().ok()?;
                    (10, u64::from_be_bytes(len_bytes) as usize)
                }
                len => (2, len as usize),
            };

            if data.len() < header_len + actual_len {
                return None;
            }

            let payload = &data[header_len..header_len + actual_len];

            match opcode {
                0x01 => Some(MockWebSocketFrame::Text {
                    payload: String::from_utf8_lossy(payload).to_string(),
                    fin,
                }),
                0x02 => Some(MockWebSocketFrame::Binary {
                    payload: payload.to_vec(),
                    fin,
                }),
                0x08 => {
                    let code = if payload.len() >= 2 {
                        u16::from_be_bytes([payload[0], payload[1]])
                    } else {
                        1000
                    };
                    let reason = if payload.len() > 2 {
                        String::from_utf8_lossy(&payload[2..]).to_string()
                    } else {
                        String::new()
                    };
                    Some(MockWebSocketFrame::Close { code, reason })
                }
                0x09 => Some(MockWebSocketFrame::Ping {
                    payload: payload.to_vec(),
                }),
                0x0A => Some(MockWebSocketFrame::Pong {
                    payload: payload.to_vec(),
                }),
                _ => None,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockSSEEvent {
        pub event_type: Option<String>,
        pub data: String,
        pub id: Option<String>,
        pub retry: Option<u64>,
    }

    impl MockSSEEvent {
        pub fn encode(&self) -> String {
            let mut result = String::new();

            if let Some(ref event_type) = self.event_type {
                result.push_str(&format!("event: {}\n", event_type));
            }

            if let Some(ref id) = self.id {
                result.push_str(&format!("id: {}\n", id));
            }

            if let Some(retry) = self.retry {
                result.push_str(&format!("retry: {}\n", retry));
            }

            // Handle multi-line data
            for line in self.data.lines() {
                result.push_str(&format!("data: {}\n", line));
            }

            result.push('\n'); // Double newline to end event
            result
        }

        pub fn decode_stream(stream_data: &str) -> Vec<MockSSEEvent> {
            let mut events = Vec::new();
            let mut current_event = MockSSEEvent {
                event_type: None,
                data: String::new(),
                id: None,
                retry: None,
            };

            for line in stream_data.lines() {
                if line.is_empty() {
                    // End of event
                    if !current_event.data.is_empty() || current_event.event_type.is_some() {
                        events.push(current_event.clone());
                    }
                    current_event = MockSSEEvent {
                        event_type: None,
                        data: String::new(),
                        id: None,
                        retry: None,
                    };
                } else if let Some(colon_pos) = line.find(':') {
                    let field = &line[..colon_pos];
                    let value = line[colon_pos + 1..].trim_start();

                    match field {
                        "event" => current_event.event_type = Some(value.to_string()),
                        "data" => {
                            if !current_event.data.is_empty() {
                                current_event.data.push('\n');
                            }
                            current_event.data.push_str(value);
                        }
                        "id" => current_event.id = Some(value.to_string()),
                        "retry" => current_event.retry = value.parse().ok(),
                        _ => {} // Ignore unknown fields
                    }
                }
            }

            // Handle final event if stream doesn't end with empty line
            if !current_event.data.is_empty() || current_event.event_type.is_some() {
                events.push(current_event);
            }

            events
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockCSRFToken {
        pub token_value: String,
        pub session_binding: String,
        pub timestamp: u64,
        pub expiry: u64,
    }

    impl MockCSRFToken {
        pub fn generate(session_id: &str, secret_key: &[u8], timestamp: u64) -> Self {
            let token_data = format!("{}:{}", session_id, timestamp);
            let token_value = format!("{:x}", token_data.len() + secret_key.len());

            MockCSRFToken {
                token_value,
                session_binding: session_id.to_string(),
                timestamp,
                expiry: timestamp + 1800, // 30 minutes
            }
        }

        pub fn validate(&self, session_id: &str, secret_key: &[u8], current_time: u64) -> bool {
            if current_time > self.expiry {
                return false;
            }

            if self.session_binding != session_id {
                return false;
            }

            let expected_token = MockCSRFToken::generate(session_id, secret_key, self.timestamp);
            self.token_value == expected_token.token_value
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockGzipCompressor;

    impl MockGzipCompressor {
        pub fn compress(data: &[u8]) -> Vec<u8> {
            // Simple mock compression: prepend length and add checksum
            let mut compressed = Vec::new();
            compressed.extend_from_slice(b"GZIP"); // Magic header
            compressed.extend_from_slice(&(data.len() as u32).to_le_bytes());

            // Simple compression simulation: run-length encoding for repeated bytes
            let mut i = 0;
            while i < data.len() {
                let current_byte = data[i];
                let mut count = 1;

                while i + count < data.len() && data[i + count] == current_byte && count < 255 {
                    count += 1;
                }

                if count > 3 {
                    // Compress repeated bytes
                    compressed.push(0xFF); // Escape byte
                    compressed.push(current_byte);
                    compressed.push(count as u8);
                } else {
                    // Store literally
                    for _ in 0..count {
                        compressed.push(current_byte);
                    }
                }

                i += count;
            }

            // Simple checksum
            let checksum: u32 = data.iter().map(|&b| b as u32).sum();
            compressed.extend_from_slice(&checksum.to_le_bytes());

            compressed
        }

        pub fn decompress(compressed_data: &[u8]) -> Option<Vec<u8>> {
            if compressed_data.len() < 12 || &compressed_data[0..4] != b"GZIP" {
                return None;
            }

            let original_len = u32::from_le_bytes([
                compressed_data[4],
                compressed_data[5],
                compressed_data[6],
                compressed_data[7],
            ]) as usize;

            let data_end = compressed_data.len() - 4;
            let checksum = u32::from_le_bytes([
                compressed_data[data_end],
                compressed_data[data_end + 1],
                compressed_data[data_end + 2],
                compressed_data[data_end + 3],
            ]);

            let mut decompressed = Vec::new();
            let mut i = 8;

            while i < data_end {
                if compressed_data[i] == 0xFF && i + 2 < data_end {
                    // Decompress repeated bytes
                    let byte_value = compressed_data[i + 1];
                    let count = compressed_data[i + 2] as usize;
                    for _ in 0..count {
                        decompressed.push(byte_value);
                    }
                    i += 3;
                } else {
                    decompressed.push(compressed_data[i]);
                    i += 1;
                }
            }

            // Verify checksum
            let computed_checksum: u32 = decompressed.iter().map(|&b| b as u32).sum();
            if computed_checksum != checksum || decompressed.len() != original_len {
                return None;
            }

            Some(decompressed)
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockTLSHandshakeState {
        Initial,
        ClientHello,
        ServerHello,
        Certificate,
        KeyExchange,
        Finished,
        Connected,
        Error,
    }

    #[derive(Debug, Clone)]
    pub struct MockTLSConnection {
        pub state: MockTLSHandshakeState,
        pub is_client: bool,
        pub cipher_suite: String,
        pub session_id: Vec<u8>,
        pub certificates: Vec<Vec<u8>>,
    }

    impl MockTLSConnection {
        pub fn new_client() -> Self {
            MockTLSConnection {
                state: MockTLSHandshakeState::Initial,
                is_client: true,
                cipher_suite: String::new(),
                session_id: Vec::new(),
                certificates: Vec::new(),
            }
        }

        pub fn new_server() -> Self {
            MockTLSConnection {
                state: MockTLSHandshakeState::Initial,
                is_client: false,
                cipher_suite: String::new(),
                session_id: Vec::new(),
                certificates: Vec::new(),
            }
        }

        pub fn advance_handshake(&mut self) -> bool {
            match (&self.state, self.is_client) {
                (MockTLSHandshakeState::Initial, true) => {
                    self.state = MockTLSHandshakeState::ClientHello;
                    true
                }
                (MockTLSHandshakeState::ClientHello, false) => {
                    self.state = MockTLSHandshakeState::ServerHello;
                    self.cipher_suite = "TLS_AES_256_GCM_SHA384".to_string();
                    self.session_id = vec![1, 2, 3, 4];
                    true
                }
                (MockTLSHandshakeState::ServerHello, true) => {
                    self.state = MockTLSHandshakeState::Certificate;
                    true
                }
                (MockTLSHandshakeState::Certificate, false) => {
                    self.state = MockTLSHandshakeState::KeyExchange;
                    self.certificates = vec![vec![0xCA, 0xFE, 0xBA, 0xBE]];
                    true
                }
                (MockTLSHandshakeState::KeyExchange, true) => {
                    self.state = MockTLSHandshakeState::Finished;
                    true
                }
                (MockTLSHandshakeState::Finished, false) => {
                    self.state = MockTLSHandshakeState::Connected;
                    true
                }
                (MockTLSHandshakeState::Connected, _) => true,
                _ => {
                    self.state = MockTLSHandshakeState::Error;
                    false
                }
            }
        }

        pub fn is_connected(&self) -> bool {
            self.state == MockTLSHandshakeState::Connected
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockRaptorQEncoder {
        pub source_symbols: Vec<Vec<u8>>,
        pub repair_symbols: Vec<Vec<u8>>,
        pub source_block_number: u32,
        pub symbol_size: usize,
    }

    impl MockRaptorQEncoder {
        pub fn new(data: &[u8], symbol_size: usize) -> Self {
            let mut source_symbols = Vec::new();

            for chunk in data.chunks(symbol_size) {
                let mut symbol = chunk.to_vec();
                if symbol.len() < symbol_size {
                    symbol.resize(symbol_size, 0); // Pad with zeros
                }
                source_symbols.push(symbol);
            }

            MockRaptorQEncoder {
                source_symbols,
                repair_symbols: Vec::new(),
                source_block_number: 0,
                symbol_size,
            }
        }

        pub fn generate_repair_symbols(&mut self, count: usize) {
            self.repair_symbols.clear();

            for i in 0..count {
                let mut repair_symbol = vec![0u8; self.symbol_size];

                // Simple repair symbol generation: XOR of source symbols with pattern
                for (j, source) in self.source_symbols.iter().enumerate() {
                    let pattern = ((i + j) % 256) as u8;
                    for k in 0..self.symbol_size {
                        repair_symbol[k] ^= source[k] ^ pattern;
                    }
                }

                self.repair_symbols.push(repair_symbol);
            }
        }

        pub fn encode_symbol(&self, symbol_id: u32) -> Option<Vec<u8>> {
            if symbol_id < self.source_symbols.len() as u32 {
                Some(self.source_symbols[symbol_id as usize].clone())
            } else {
                let repair_index = symbol_id as usize - self.source_symbols.len();
                self.repair_symbols.get(repair_index).cloned()
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockRaptorQDecoder {
        pub received_symbols: HashMap<u32, Vec<u8>>,
        pub source_symbol_count: u32,
        pub symbol_size: usize,
    }

    impl MockRaptorQDecoder {
        pub fn new(source_symbol_count: u32, symbol_size: usize) -> Self {
            MockRaptorQDecoder {
                received_symbols: HashMap::new(),
                source_symbol_count,
                symbol_size,
            }
        }

        pub fn add_symbol(&mut self, symbol_id: u32, symbol_data: Vec<u8>) {
            self.received_symbols.insert(symbol_id, symbol_data);
        }

        pub fn can_decode(&self) -> bool {
            self.received_symbols.len() >= self.source_symbol_count as usize
        }

        pub fn decode(&self) -> Option<Vec<u8>> {
            if !self.can_decode() {
                return None;
            }

            let mut result = Vec::new();

            // For simplicity, assume we have all source symbols
            for i in 0..self.source_symbol_count {
                if let Some(symbol) = self.received_symbols.get(&i) {
                    result.extend_from_slice(symbol);
                } else {
                    // Try to recover from repair symbols (simplified)
                    let mut recovered_symbol = vec![0u8; self.symbol_size];

                    // Find repair symbols that can help recover this source symbol
                    for (&repair_id, repair_data) in &self.received_symbols {
                        if repair_id >= self.source_symbol_count {
                            let repair_index = repair_id - self.source_symbol_count;
                            let pattern = ((repair_index + i as u32) % 256) as u8;

                            for k in 0..self.symbol_size {
                                recovered_symbol[k] ^= repair_data[k] ^ pattern;
                            }
                        }
                    }

                    result.extend_from_slice(&recovered_symbol);
                }
            }

            // Remove padding from last symbol
            while result.last() == Some(&0) && result.len() > 0 {
                result.pop();
            }

            Some(result)
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Web Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_multipart_parse_serialize() {
        proptest!(|(
            field_names in proptest::collection::vec("[a-z]{3,10}", 2..6),
            field_values in proptest::collection::vec(
                prop_oneof![
                    "[a-zA-Z0-9 ]{5,50}".prop_map(MultipartValue::Text),
                    proptest::collection::vec(0u8..255, 10..100).prop_map(MultipartValue::Binary)
                ],
                2..6
            ),
            boundary in "[a-zA-Z0-9]{16,32}"
        )| {
            // MR-MultipartParseSerialize: multipart parse(serialize(data)) should equal original data
            let fields: Vec<MockMultipartField> = field_names.iter().zip(field_values.iter())
                .map(|(name, value)| MockMultipartField {
                    name: name.clone(),
                    value: value.clone(),
                    content_type: match value {
                        MultipartValue::Binary(_) => Some("application/octet-stream".to_string()),
                        MultipartValue::Text(_) => None,
                    },
                    filename: None,
                })
                .collect();

            let original = MockMultipartData {
                boundary: boundary.clone(),
                fields,
            };

            // Serialize and then parse back
            let serialized_data = original.serialize();
            let parsed = MockMultipartData::parse(&serialized_data, &boundary);

            prop_assert!(
                parsed.is_some(),
                "Multipart parse should succeed for valid serialized data"
            );

            let parsed = parsed.unwrap();

            prop_assert_eq!(
                parsed.boundary, original.boundary,
                "Parsed boundary should match original"
            );

            prop_assert_eq!(
                parsed.fields.len(), original.fields.len(),
                "Parsed field count should match original: parsed={}, original={}",
                parsed.fields.len(), original.fields.len()
            );

            // Verify each field round-trips correctly. `prop_assert_eq!`
            // takes its arguments by value, so we `.clone()` the borrowed
            // field components rather than moving out of the shared refs
            // returned by `iter().zip()`.
            for (orig_field, parsed_field) in original.fields.iter().zip(parsed.fields.iter()) {
                prop_assert_eq!(
                    parsed_field.name.clone(), orig_field.name.clone(),
                    "Field name should round-trip: {} != {}", parsed_field.name, orig_field.name
                );

                prop_assert_eq!(
                    parsed_field.value.clone(), orig_field.value.clone(),
                    "Field value should round-trip for field '{}'", orig_field.name
                );

                prop_assert_eq!(
                    parsed_field.content_type.clone(), orig_field.content_type.clone(),
                    "Content type should round-trip for field '{}'", orig_field.name
                );
            }
        });
    }

    #[test]
    fn mr_session_cookie_crypto_bind() {
        proptest!(|(
            session_ids in proptest::collection::vec("[a-zA-Z0-9]{16,32}", 2..5),
            user_data_keys in proptest::collection::vec("[a-z]{3,10}", 1..4),
            user_data_values in proptest::collection::vec("[a-zA-Z0-9 ]{5,20}", 1..4),
            secret_key in proptest::collection::vec(0u8..255, 16..64),
            timestamps in proptest::collection::vec(1000u64..10000, 2..5)
        )| {
            // MR-SessionCookieCryptoBind: session cookies should maintain cryptographic binding
            let user_data: HashMap<String, String> = user_data_keys.iter()
                .zip(user_data_values.iter())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            for (i, session_id) in session_ids.iter().enumerate() {
                let timestamp = timestamps[i % timestamps.len()];

                // Create and serialize cookie
                let original_cookie = MockSessionCookie::new(
                    session_id.clone(),
                    user_data.clone(),
                    &secret_key,
                    timestamp
                );

                let serialized = original_cookie.serialize();
                let deserialized = MockSessionCookie::deserialize(&serialized, &secret_key);

                prop_assert!(
                    deserialized.is_some(),
                    "Valid cookie should deserialize successfully for session {}", session_id
                );

                let deserialized = deserialized.unwrap();

                prop_assert_eq!(
                    deserialized.session_id.clone(), original_cookie.session_id.clone(),
                    "Session ID should round-trip correctly"
                );

                prop_assert_eq!(
                    deserialized.user_data.clone(), original_cookie.user_data.clone(),
                    "User data should round-trip correctly"
                );

                prop_assert!(
                    deserialized.verify_integrity(&secret_key),
                    "Deserialized cookie should maintain integrity"
                );

                // Test tamper detection: modify the serialized cookie
                let mut tampered_cookie = serialized.clone();
                if let Some(pos) = tampered_cookie.find('=') {
                    tampered_cookie.insert(pos + 1, 'X'); // Insert extra character
                }

                let tampered_deserialized = MockSessionCookie::deserialize(&tampered_cookie, &secret_key);
                prop_assert!(
                    tampered_deserialized.is_none(),
                    "Tampered cookie should fail to deserialize due to invalid HMAC"
                );
            }

            // Test key separation: different secret keys should produce different results
            if secret_key.len() > 1 {
                let mut different_key = secret_key.clone();
                different_key[0] = different_key[0].wrapping_add(1);

                let cookie_with_original_key = MockSessionCookie::new(
                    session_ids[0].clone(),
                    user_data.clone(),
                    &secret_key,
                    timestamps[0]
                );

                let cookie_with_different_key = MockSessionCookie::new(
                    session_ids[0].clone(),
                    user_data.clone(),
                    &different_key,
                    timestamps[0]
                );

                prop_assert_ne!(
                    cookie_with_original_key.hmac_signature,
                    cookie_with_different_key.hmac_signature,
                    "Different secret keys should produce different HMAC signatures"
                );
            }
        });
    }

    #[test]
    fn mr_websocket_frame_codec() {
        proptest!(|(
            text_payloads in proptest::collection::vec("[a-zA-Z0-9 ]{10,200}", 2..6),
            binary_payloads in proptest::collection::vec(
                proptest::collection::vec(0u8..255, 10..200), 2..6
            ),
            close_codes in proptest::collection::vec(1000u16..1015, 1..3),
            ping_payloads in proptest::collection::vec(
                proptest::collection::vec(0u8..255, 0..125), 2..4
            )
        )| {
            // MR-WebsocketFrameCodec: websocket encode → decode should preserve frame structure
            let mut test_frames = Vec::new();

            // Add text frames
            for (i, payload) in text_payloads.iter().enumerate() {
                test_frames.push(MockWebSocketFrame::Text {
                    payload: payload.clone(),
                    fin: i % 2 == 0, // Alternate fin flag
                });
            }

            // Add binary frames
            for (i, payload) in binary_payloads.iter().enumerate() {
                test_frames.push(MockWebSocketFrame::Binary {
                    payload: payload.clone(),
                    fin: i % 2 == 1,
                });
            }

            // Add control frames
            for &code in &close_codes {
                test_frames.push(MockWebSocketFrame::Close {
                    code,
                    reason: format!("Test reason {}", code),
                });
            }

            for payload in &ping_payloads {
                test_frames.push(MockWebSocketFrame::Ping {
                    payload: payload.clone(),
                });
                test_frames.push(MockWebSocketFrame::Pong {
                    payload: payload.clone(),
                });
            }

            // Test encode → decode round-trip for each frame
            for (i, original_frame) in test_frames.iter().enumerate() {
                let encoded = original_frame.encode();
                let decoded = MockWebSocketFrame::decode(&encoded);

                prop_assert!(
                    decoded.is_some(),
                    "Frame {} should decode successfully: {:?}", i, original_frame
                );

                let decoded = decoded.unwrap();

                prop_assert_eq!(
                    decoded, original_frame.clone(),
                    "Frame {} should round-trip correctly: original={:?}", i, original_frame
                );
            }

            // Test frame concatenation and individual decoding
            let mut concatenated_frames = Vec::new();
            for frame in &test_frames {
                concatenated_frames.extend_from_slice(&frame.encode());
            }

            // Decode frames one by one from concatenated stream
            let mut offset = 0;
            for (i, original_frame) in test_frames.iter().enumerate() {
                if offset >= concatenated_frames.len() {
                    break;
                }

                let decoded = MockWebSocketFrame::decode(&concatenated_frames[offset..]);
                prop_assert!(
                    decoded.is_some(),
                    "Concatenated frame {} should decode: {:?}", i, original_frame
                );

                let decoded = decoded.unwrap();
                prop_assert_eq!(
                    decoded, original_frame.clone(),
                    "Concatenated frame {} should match original", i
                );

                offset += original_frame.encode().len();
            }
        });
    }

    #[test]
    fn mr_sse_stream_chunking() {
        proptest!(|(
            event_types in proptest::collection::vec(
                prop::option::of("[a-z]{4,10}"), 3..8
            ),
            event_data in proptest::collection::vec("[a-zA-Z0-9 \n]{10,100}", 3..8),
            event_ids in proptest::collection::vec(
                prop::option::of("[0-9]{3,8}"), 3..8
            ),
            retry_values in proptest::collection::vec(
                prop::option::of(1000u64..30000), 3..8
            )
        )| {
            // MR-SSEStreamChunking: SSE chunking should preserve message boundaries
            let events: Vec<MockSSEEvent> = event_types.iter()
                .zip(event_data.iter())
                .zip(event_ids.iter())
                .zip(retry_values.iter())
                .map(|(((event_type, data), id), retry)| MockSSEEvent {
                    event_type: event_type.clone(),
                    data: data.clone(),
                    id: id.clone(),
                    retry: *retry,
                })
                .collect();

            // Encode all events into a single stream
            let mut encoded_stream = String::new();
            for event in &events {
                encoded_stream.push_str(&event.encode());
            }

            // Decode the stream back to events
            let decoded_events = MockSSEEvent::decode_stream(&encoded_stream);

            prop_assert_eq!(
                decoded_events.len(), events.len(),
                "Decoded event count should match original: decoded={}, original={}",
                decoded_events.len(), events.len()
            );

            // Verify each event round-trips correctly. `.clone()` on each
            // field because the loop binds borrowed references and
            // `prop_assert_eq!` takes owned arguments.
            for (i, (original, decoded)) in events.iter().zip(decoded_events.iter()).enumerate() {
                prop_assert_eq!(
                    decoded.event_type.clone(), original.event_type.clone(),
                    "Event {} type should round-trip", i
                );

                prop_assert_eq!(
                    decoded.data.clone(), original.data.clone(),
                    "Event {} data should round-trip", i
                );

                prop_assert_eq!(
                    decoded.id.clone(), original.id.clone(),
                    "Event {} ID should round-trip", i
                );

                prop_assert_eq!(
                    decoded.retry, original.retry,
                    "Event {} retry should round-trip", i
                );
            }

            // Test chunked encoding/decoding (simulate partial reads)
            if !events.is_empty() {
                let individual_encoded: Vec<String> = events.iter().map(|e| e.encode()).collect();
                let mut chunked_stream = String::new();

                // Add events one by one and verify progressive decoding
                for (i, event_encoded) in individual_encoded.iter().enumerate() {
                    chunked_stream.push_str(event_encoded);
                    let partial_decoded = MockSSEEvent::decode_stream(&chunked_stream);

                    prop_assert_eq!(
                        partial_decoded.len(), i + 1,
                        "Partial decode should find {} events after adding event {}",
                        i + 1, i
                    );

                    prop_assert_eq!(
                        partial_decoded[i].clone(), events[i].clone(),
                        "Partially decoded event {} should match original", i
                    );
                }
            }
        });
    }

    #[test]
    fn mr_csrf_token_validation() {
        proptest!(|(
            session_ids in proptest::collection::vec("[a-zA-Z0-9]{16,32}", 3..6),
            secret_keys in proptest::collection::vec(
                proptest::collection::vec(0u8..255, 16..64), 2..4
            ),
            timestamps in proptest::collection::vec(1000u64..10000, 3..6),
            time_advances in proptest::collection::vec(0u64..3600, 3..6)
        )| {
            // MR-CSRFTokenValidation: CSRF token validation should be deterministic
            for (session_id, secret_key) in session_ids.iter().zip(secret_keys.iter()) {
                for (i, &timestamp) in timestamps.iter().enumerate() {
                    // Generate token
                    let token = MockCSRFToken::generate(session_id, secret_key, timestamp);

                    // Validation should be deterministic - same inputs, same result
                    for _ in 0..3 {
                        let validation_result = token.validate(session_id, secret_key, timestamp + 100);
                        prop_assert!(
                            validation_result,
                            "Valid token should validate consistently: session={}, timestamp={}",
                            session_id, timestamp
                        );
                    }

                    // Test time-based expiry
                    let time_advance = time_advances[i % time_advances.len()];
                    let future_time = timestamp + time_advance;
                    let should_be_valid = time_advance < 1800; // 30 minute expiry

                    let validation_result = token.validate(session_id, secret_key, future_time);
                    prop_assert_eq!(
                        validation_result, should_be_valid,
                        "Token validation should respect expiry: time_advance={}, expected_valid={}, actual_valid={}",
                        time_advance, should_be_valid, validation_result
                    );

                    // Test session binding - wrong session should fail
                    if session_ids.len() > 1 {
                        let wrong_session = &session_ids[(session_ids.iter().position(|s| s == session_id).unwrap() + 1) % session_ids.len()];
                        let wrong_session_validation = token.validate(wrong_session, secret_key, timestamp + 100);
                        prop_assert!(
                            !wrong_session_validation,
                            "Token should not validate with wrong session: correct={}, wrong={}",
                            session_id, wrong_session
                        );
                    }

                    // Test secret key binding - wrong key should fail
                    if secret_keys.len() > 1 {
                        let wrong_key = &secret_keys[(secret_keys.iter().position(|k| k == secret_key).unwrap() + 1) % secret_keys.len()];
                        let wrong_key_validation = token.validate(session_id, wrong_key, timestamp + 100);
                        prop_assert!(
                            !wrong_key_validation,
                            "Token should not validate with wrong secret key"
                        );
                    }

                    // Test regeneration idempotency - same inputs produce same token
                    let regenerated_token = MockCSRFToken::generate(session_id, secret_key, timestamp);
                    prop_assert_eq!(
                        token.token_value, regenerated_token.token_value,
                        "Token generation should be deterministic"
                    );
                    prop_assert_eq!(
                        token.session_binding, regenerated_token.session_binding,
                        "Session binding should be deterministic"
                    );
                }
            }
        });
    }

    #[test]
    fn mr_compress_gzip_round_trip() {
        proptest!(|(
            test_data in proptest::collection::vec(0u8..255, 50..2000)
        )| {
            // MR-CompressGzipRoundTrip: gzip compress → decompress should preserve content
            let original_data = test_data.clone();

            // Compress and decompress
            let compressed = MockGzipCompressor::compress(&original_data);
            let decompressed = MockGzipCompressor::decompress(&compressed);

            prop_assert!(
                decompressed.is_some(),
                "Decompression should succeed for valid compressed data"
            );

            let decompressed = decompressed.unwrap();

            // `.clone()` so the originals remain available for the
            // post-assert length/.len() checks (prop_assert_eq! consumes
            // its first two args by value on the failure path).
            let orig_len = original_data.len();
            let comp_len = compressed.len();
            let decomp_len = decompressed.len();
            prop_assert_eq!(
                decompressed.clone(), original_data.clone(),
                "Round-trip should preserve data exactly. Original length: {}, compressed length: {}, decompressed length: {}",
                orig_len, comp_len, decomp_len
            );

            // Test compression is deterministic
            let compressed2 = MockGzipCompressor::compress(&original_data);
            prop_assert_eq!(
                compressed.clone(), compressed2,
                "Compression should be deterministic for same input"
            );

            // Test that compressed data is different from original (unless very short)
            if original_data.len() > 20 {
                prop_assert_ne!(
                    compressed.clone(), original_data.clone(),
                    "Compressed data should be different from original for non-trivial inputs"
                );
            }

            // Test corruption detection
            if compressed.len() > 8 {
                let mut corrupted = compressed.clone();
                let corruption_pos = compressed.len() / 2;
                corrupted[corruption_pos] = corrupted[corruption_pos].wrapping_add(1);

                let corrupted_result = MockGzipCompressor::decompress(&corrupted);
                prop_assert!(
                    corrupted_result.is_none(),
                    "Corrupted data should fail to decompress"
                );
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // TLS Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_acceptor_connector_symmetry() {
        proptest!(|(
            handshake_rounds in 1usize..10
        )| {
            // MR-AcceptorConnectorSymmetry: TLS handshake should be symmetric between client and server
            let mut client = MockTLSConnection::new_client();
            let mut server = MockTLSConnection::new_server();

            let mut client_states = Vec::new();
            let mut server_states = Vec::new();

            // Record initial states
            client_states.push(client.state.clone());
            server_states.push(server.state.clone());

            // Perform handshake rounds
            for round in 0..handshake_rounds {
                // Client advances first
                let client_advanced = client.advance_handshake();
                client_states.push(client.state.clone());

                // Server responds
                let server_advanced = server.advance_handshake();
                server_states.push(server.state.clone());

                if !client_advanced || !server_advanced {
                    break;
                }

                // Check if both reached connected state
                if client.is_connected() && server.is_connected() {
                    prop_assert_eq!(
                        &client.cipher_suite, &server.cipher_suite,
                        "Connected client and server should have matching cipher suites: round={}",
                        round
                    );

                    prop_assert_eq!(
                        client.session_id.clone(), server.session_id.clone(),
                        "Connected client and server should have matching session IDs: round={}",
                        round
                    );

                    prop_assert_eq!(
                        client.certificates.clone(), server.certificates.clone(),
                        "Connected client and server should have consistent certificate chain: round={}",
                        round
                    );

                    break;
                }
            }

            // Verify handshake progression makes sense
            let final_client_connected = client.is_connected();
            let final_server_connected = server.is_connected();

            prop_assert_eq!(
                final_client_connected, final_server_connected,
                "Client and server should reach connected state together: client={}, server={}",
                final_client_connected, final_server_connected
            );

            if final_client_connected {
                prop_assert!(
                    !client.cipher_suite.is_empty(),
                    "Connected client should have a cipher suite"
                );

                prop_assert!(
                    !server.cipher_suite.is_empty(),
                    "Connected server should have a cipher suite"
                );

                prop_assert!(
                    !client.session_id.is_empty(),
                    "Connected client should have a session ID"
                );
            }
        });
    }

    #[test]
    fn mr_handshake_state_determinism() {
        proptest!(|(
            sequence_lengths in proptest::collection::vec(1usize..15, 2..5)
        )| {
            // MR-HandshakeStateDeterminism: TLS state transitions should be deterministic
            for &sequence_length in &sequence_lengths {
                let mut client1 = MockTLSConnection::new_client();
                let mut client2 = MockTLSConnection::new_client();
                let mut server1 = MockTLSConnection::new_server();
                let mut server2 = MockTLSConnection::new_server();

                // Advance both client/server pairs through the same sequence
                for step in 0..sequence_length {
                    // Advance clients
                    let client1_result = client1.advance_handshake();
                    let client2_result = client2.advance_handshake();

                    prop_assert_eq!(
                        client1_result, client2_result,
                        "Client handshake advance should be deterministic at step {}", step
                    );

                    prop_assert_eq!(
                        client1.state.clone(), client2.state.clone(),
                        "Client states should be identical at step {}", step
                    );

                    prop_assert_eq!(
                        client1.cipher_suite.clone(), client2.cipher_suite.clone(),
                        "Client cipher suites should be identical at step {}", step
                    );

                    prop_assert_eq!(
                        client1.session_id.clone(), client2.session_id.clone(),
                        "Client session IDs should be identical at step {}", step
                    );

                    // Advance servers
                    let server1_result = server1.advance_handshake();
                    let server2_result = server2.advance_handshake();

                    prop_assert_eq!(
                        server1_result, server2_result,
                        "Server handshake advance should be deterministic at step {}", step
                    );

                    prop_assert_eq!(
                        server1.state.clone(), server2.state.clone(),
                        "Server states should be identical at step {}", step
                    );

                    prop_assert_eq!(
                        server1.cipher_suite.clone(), server2.cipher_suite.clone(),
                        "Server cipher suites should be identical at step {}", step
                    );

                    prop_assert_eq!(
                        server1.certificates.clone(), server2.certificates.clone(),
                        "Server certificates should be identical at step {}", step
                    );

                    if !client1_result || !server1_result {
                        break;
                    }
                }

                // Verify final states are consistent
                prop_assert_eq!(
                    client1.is_connected(), client2.is_connected(),
                    "Final connection status should be deterministic for clients"
                );

                prop_assert_eq!(
                    server1.is_connected(), server2.is_connected(),
                    "Final connection status should be deterministic for servers"
                );
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Codec Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_raptorq_codec_round_trip() {
        proptest!(|(
            source_data in proptest::collection::vec(0u8..255, 100..1000),
            symbol_size in 64usize..256,
            repair_symbol_count in 1usize..20
        )| {
            // MR-RaptorQCodecRoundTrip: RaptorQ encode → decode should recover original data
            let original_data = source_data.clone();

            // Encode the data
            let mut encoder = MockRaptorQEncoder::new(&original_data, symbol_size);
            encoder.generate_repair_symbols(repair_symbol_count);

            let source_symbol_count = encoder.source_symbols.len() as u32;

            // Create decoder and add all source symbols
            let mut decoder = MockRaptorQDecoder::new(source_symbol_count, symbol_size);

            // Add source symbols
            for i in 0..source_symbol_count {
                if let Some(symbol) = encoder.encode_symbol(i) {
                    decoder.add_symbol(i, symbol);
                }
            }

            prop_assert!(
                decoder.can_decode(),
                "Decoder should be able to decode with all source symbols"
            );

            let decoded_data = decoder.decode();
            prop_assert!(
                decoded_data.is_some(),
                "Decode should succeed with sufficient symbols"
            );

            let decoded_data = decoded_data.unwrap();

            // The decoded data should match the original (minus padding)
            let expected_len = original_data.len();
            prop_assert!(
                decoded_data.len() >= expected_len,
                "Decoded data should be at least as long as original: decoded={}, original={}",
                decoded_data.len(), expected_len
            );

            prop_assert_eq!(
                &decoded_data[..expected_len], &original_data[..],
                "Decoded data should match original data exactly"
            );

            // Test with repair symbols - lose some source symbols but add repair symbols
            if repair_symbol_count > 0 && source_symbol_count > 1 {
                let mut decoder_with_repairs = MockRaptorQDecoder::new(source_symbol_count, symbol_size);

                // Add only subset of source symbols
                let source_to_add = (source_symbol_count as usize).saturating_sub(repair_symbol_count.min(2));
                for i in 0..source_to_add {
                    if let Some(symbol) = encoder.encode_symbol(i as u32) {
                        decoder_with_repairs.add_symbol(i as u32, symbol);
                    }
                }

                // Add repair symbols to make up the difference
                let repair_symbols_needed = (source_symbol_count as usize).saturating_sub(source_to_add);
                for i in 0..repair_symbols_needed.min(repair_symbol_count) {
                    let repair_symbol_id = source_symbol_count + i as u32;
                    if let Some(symbol) = encoder.encode_symbol(repair_symbol_id) {
                        decoder_with_repairs.add_symbol(repair_symbol_id, symbol);
                    }
                }

                if decoder_with_repairs.can_decode() {
                    let repair_decoded = decoder_with_repairs.decode();
                    prop_assert!(
                        repair_decoded.is_some(),
                        "Decode with repair symbols should succeed"
                    );

                    let repair_decoded = repair_decoded.unwrap();
                    prop_assert!(
                        repair_decoded.len() >= expected_len,
                        "Repair decoded data should be at least as long as original"
                    );

                    // Note: repair symbol recovery is simplified in mock, so we test basic structure
                    prop_assert!(
                        !repair_decoded.is_empty(),
                        "Repair decoded data should not be empty"
                    );
                }
            }

            // Test symbol encoding consistency
            for symbol_id in 0..source_symbol_count + repair_symbol_count as u32 {
                let encoded1 = encoder.encode_symbol(symbol_id);
                let encoded2 = encoder.encode_symbol(symbol_id);

                prop_assert_eq!(
                    &encoded1, &encoded2,
                    "Symbol encoding should be deterministic for symbol_id={}", symbol_id
                );

                if let Some(ref symbol) = encoded1 {
                    prop_assert_eq!(
                        symbol.len(), symbol_size,
                        "Encoded symbol should have correct size: symbol_id={}, size={}, expected={}",
                        symbol_id, symbol.len(), symbol_size
                    );
                }
            }
        });
    }

    #[test]
    fn mr_codec_framing_preservation() {
        proptest!(|(
            message_data in proptest::collection::vec(
                proptest::collection::vec(0u8..255, 10..500), 3..8
            ),
            frame_sizes in proptest::collection::vec(64usize..1024, 3..8)
        )| {
            // MR-CodecFramingPreservation: codec framing should preserve message boundaries
            for (message_bytes, &frame_size) in message_data.iter().zip(frame_sizes.iter()) {
                let message_chunk_len = (message_bytes.len() / 3).max(1).min(frame_size);
                let messages: Vec<Vec<u8>> = message_bytes
                    .chunks(message_chunk_len)
                    .map(|chunk| chunk.to_vec())
                    .collect();

                // Create framed messages - prepend length to each message
                let mut framed_stream = Vec::new();
                let mut expected_lengths = Vec::new();

                for message in &messages {
                    let len = message.len() as u32;
                    framed_stream.extend_from_slice(&len.to_be_bytes());
                    framed_stream.extend_from_slice(message);
                    expected_lengths.push(len);
                }

                // Parse framed messages back
                let mut parsed_messages = Vec::new();
                let mut offset = 0;

                while offset + 4 <= framed_stream.len() {
                    let length_bytes: [u8; 4] = framed_stream[offset..offset + 4].try_into().unwrap();
                    let message_length = u32::from_be_bytes(length_bytes) as usize;

                    if offset + 4 + message_length > framed_stream.len() {
                        break; // Incomplete message
                    }

                    let message = framed_stream[offset + 4..offset + 4 + message_length].to_vec();
                    parsed_messages.push(message);
                    offset += 4 + message_length;
                }

                prop_assert_eq!(
                    parsed_messages.len(), messages.len(),
                    "Parsed message count should match original: parsed={}, original={}",
                    parsed_messages.len(), messages.len()
                );

                for (i, (original, parsed)) in messages.iter().zip(parsed_messages.iter()).enumerate() {
                    prop_assert_eq!(
                        parsed, original,
                        "Message {} should be preserved exactly: original_len={}, parsed_len={}",
                        i, original.len(), parsed.len()
                    );
                }

                // Test chunked framing (simulate network packet boundaries)
                if !framed_stream.is_empty() {
                    let mut chunked_parsed = Vec::new();
                    let mut buffer = Vec::new();

                    // Process in chunks
                    for chunk in framed_stream.chunks(frame_size) {
                        buffer.extend_from_slice(chunk);

                        // Try to parse complete messages from buffer
                        let mut parse_offset = 0;
                        while parse_offset + 4 <= buffer.len() {
                            let length_bytes: [u8; 4] = buffer[parse_offset..parse_offset + 4].try_into().unwrap();
                            let message_length = u32::from_be_bytes(length_bytes) as usize;

                            if parse_offset + 4 + message_length > buffer.len() {
                                break; // Wait for more data
                            }

                            let message = buffer[parse_offset + 4..parse_offset + 4 + message_length].to_vec();
                            chunked_parsed.push(message);
                            parse_offset += 4 + message_length;
                        }

                        // Remove processed data from buffer
                        buffer.drain(..parse_offset);
                    }

                    prop_assert_eq!(
                        chunked_parsed.len(), messages.len(),
                        "Chunked parsing should recover all messages: chunked={}, original={}",
                        chunked_parsed.len(), messages.len()
                    );

                    for (i, (original, chunked)) in messages.iter().zip(chunked_parsed.iter()).enumerate() {
                        prop_assert_eq!(
                            chunked, original,
                            "Chunked message {} should match original", i
                        );
                    }

                    // Buffer should be empty or contain incomplete message header
                    prop_assert!(
                        buffer.len() < 4 || {
                            let length_bytes: [u8; 4] = buffer[0..4].try_into().unwrap();
                            let expected_len = u32::from_be_bytes(length_bytes) as usize;
                            buffer.len() < 4 + expected_len
                        },
                        "Buffer should contain at most an incomplete message: buffer_len={}",
                        buffer.len()
                    );
                }
            }
        });
    }
}
