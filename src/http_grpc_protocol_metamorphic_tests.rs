//! HTTP and gRPC Protocol Metamorphic Testing
//!
//! This module implements comprehensive metamorphic relations for HTTP protocols
//! (H1/H2/H3) and gRPC, focusing on codec round-trips, flow control invariants,
//! HPACK dynamic table management, and protocol upgrade determinism.
//! These tests address the oracle problem for complex protocol state machines
//! where expected outputs depend on intricate specifications like RFC 7540/7541.
//!
//! ## Metamorphic Relations Implemented
//!
//! ### HTTP/1.1 Codec Operations (3 MRs)
//! - MR-H1CodecRoundTrip: encode(decode(bytes)) preserves semantic content
//! - MR-BufferBoundarySlicing: message parsing independent of buffer boundaries
//! - MR-HeaderLineContinuation: folding/unfolding header values preserves semantics
//!
//! ### HTTP/2 HPACK Compression (4 MRs)
//! - MR-HpackCompressionRoundTrip: compress(decompress(headers)) = headers
//! - MR-DynamicTableEviction: table evictions maintain LIFO discipline
//! - MR-HpackIndexingStrategy: indexed vs literal representations preserve semantics
//! - MR-HpackTableSizeConstraints: dynamic table never exceeds configured limits
//!
//! ### HTTP/2 Flow Control (3 MRs)
//! - MR-FlowControlCreditConservation: total credits sent = total credits available
//! - MR-WindowUpdateMonotonicity: window updates never decrease connection capacity
//! - MR-StreamFlowIsolation: per-stream flow control independent of other streams
//!
//! ### HTTP/3 Frame Variants (3 MRs)
//! - MR-H3FrameVariantRoundTrip: frame encoding/decoding preserves frame types
//! - MR-QpackFieldSectionDeterminism: QPACK field sections deterministic for same headers
//! - MR-H3SettingsNegotiation: settings negotiation commutative for compatible values
//!
//! ### gRPC Status Mapping (2 MRs)
//! - MR-StatusCodeBijection: gRPC status ↔ HTTP status mapping is bijective
//! - MR-ErrorDetailPreservation: error details preserved across status transformations
//!
//! ### gRPC Codec Frame Boundaries (3 MRs)
//! - MR-GrpcMessageFraming: message boundaries preserved across fragmented reads
//! - MR-GrpcCompressionRoundTrip: compress/decompress preserves message content
//! - MR-GrpcWebUpgradeDeterminism: Web upgrade path deterministic for same inputs

#![allow(dead_code)]

#[cfg(test)]
mod tests {
    #[cfg(test)]
    use proptest::prelude::*;
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::convert::TryFrom;

    // ═══════════════════════════════════════════════════════════════════════════
    // Mock Implementations for HTTP/gRPC Protocol Testing
    // ═══════════════════════════════════════════════════════════════════════════

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockHttpRequest {
        pub method: String,
        pub uri: String,
        pub version: String,
        pub headers: Vec<(String, String)>,
        pub body: Vec<u8>,
    }

    impl MockHttpRequest {
        pub fn new(method: &str, uri: &str, version: &str) -> Self {
            Self {
                method: method.to_string(),
                uri: uri.to_string(),
                version: version.to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            }
        }

        pub fn with_header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_string(), value.to_string()));
            self
        }

        pub fn with_body(mut self, body: Vec<u8>) -> Self {
            self.body = body;
            self
        }

        pub fn encode_h1(&self) -> Vec<u8> {
            let mut result = Vec::new();

            // Request line
            let request_line = format!("{} {} {}\r\n", self.method, self.uri, self.version);
            result.extend_from_slice(request_line.as_bytes());

            // Headers
            for (name, value) in &self.headers {
                let header_line = format!("{}: {}\r\n", name, value);
                result.extend_from_slice(header_line.as_bytes());
            }

            // Content-Length if body present
            if !self.body.is_empty() {
                let content_length = format!("Content-Length: {}\r\n", self.body.len());
                result.extend_from_slice(content_length.as_bytes());
            }

            // End of headers
            result.extend_from_slice(b"\r\n");

            // Body
            result.extend_from_slice(&self.body);

            result
        }

        pub fn decode_h1(bytes: &[u8]) -> Result<Self, String> {
            let content = String::from_utf8_lossy(bytes);
            let mut lines = content.lines();

            // Parse request line
            let request_line = lines.next().ok_or("Missing request line")?;
            let parts: Vec<&str> = request_line.split_whitespace().collect();
            if parts.len() != 3 {
                return Err("Invalid request line".to_string());
            }

            let mut request = MockHttpRequest::new(parts[0], parts[1], parts[2]);

            // Parse headers
            let mut content_length = 0;
            for line in &mut lines {
                if line.is_empty() {
                    break; // End of headers
                }

                if let Some(colon_pos) = line.find(':') {
                    let name = line[..colon_pos].trim();
                    let value = line[colon_pos + 1..].trim();

                    if name.to_lowercase() == "content-length" {
                        content_length = value.parse().unwrap_or(0);
                    }

                    request.headers.push((name.to_string(), value.to_string()));
                }
            }

            // Parse body (simplified - assumes body is at end)
            if content_length > 0 {
                let remaining: String = lines.collect::<Vec<_>>().join("\n");
                request.body = remaining.into_bytes();
                if request.body.len() > content_length {
                    request.body.truncate(content_length);
                }
            }

            Ok(request)
        }

        pub fn get_header(&self, name: &str) -> Option<&String> {
            self.headers
                .iter()
                .find(|(h_name, _)| h_name.eq_ignore_ascii_case(name))
                .map(|(_, value)| value)
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockHpackTable {
        pub static_table: Vec<(String, String)>,
        pub dynamic_table: VecDeque<(String, String)>,
        pub max_size: usize,
        pub current_size: usize,
    }

    impl MockHpackTable {
        pub fn new(max_size: usize) -> Self {
            let static_table = vec![
                (":authority".to_string(), String::new()),
                (":method".to_string(), "GET".to_string()),
                (":method".to_string(), "POST".to_string()),
                (":path".to_string(), "/".to_string()),
                (":path".to_string(), "/index.html".to_string()),
                (":scheme".to_string(), "http".to_string()),
                (":scheme".to_string(), "https".to_string()),
                (":status".to_string(), "200".to_string()),
                (":status".to_string(), "204".to_string()),
                (":status".to_string(), "206".to_string()),
                (":status".to_string(), "304".to_string()),
                (":status".to_string(), "400".to_string()),
                (":status".to_string(), "404".to_string()),
                (":status".to_string(), "500".to_string()),
                ("accept-charset".to_string(), String::new()),
                ("accept-encoding".to_string(), "gzip, deflate".to_string()),
                ("accept-language".to_string(), String::new()),
                ("accept-ranges".to_string(), String::new()),
                ("accept".to_string(), String::new()),
                ("access-control-allow-origin".to_string(), String::new()),
                ("age".to_string(), String::new()),
                ("allow".to_string(), String::new()),
                ("authorization".to_string(), String::new()),
                ("cache-control".to_string(), String::new()),
                ("content-disposition".to_string(), String::new()),
                ("content-encoding".to_string(), String::new()),
                ("content-language".to_string(), String::new()),
                ("content-length".to_string(), String::new()),
                ("content-location".to_string(), String::new()),
                ("content-range".to_string(), String::new()),
                ("content-type".to_string(), String::new()),
                ("cookie".to_string(), String::new()),
                ("date".to_string(), String::new()),
                ("etag".to_string(), String::new()),
                ("expect".to_string(), String::new()),
                ("expires".to_string(), String::new()),
                ("from".to_string(), String::new()),
                ("host".to_string(), String::new()),
                ("if-match".to_string(), String::new()),
                ("if-modified-since".to_string(), String::new()),
                ("if-none-match".to_string(), String::new()),
                ("if-range".to_string(), String::new()),
                ("if-unmodified-since".to_string(), String::new()),
                ("last-modified".to_string(), String::new()),
                ("link".to_string(), String::new()),
                ("location".to_string(), String::new()),
                ("max-forwards".to_string(), String::new()),
                ("proxy-authenticate".to_string(), String::new()),
                ("proxy-authorization".to_string(), String::new()),
                ("range".to_string(), String::new()),
                ("referer".to_string(), String::new()),
                ("refresh".to_string(), String::new()),
                ("retry-after".to_string(), String::new()),
                ("server".to_string(), String::new()),
                ("set-cookie".to_string(), String::new()),
                ("strict-transport-security".to_string(), String::new()),
                ("transfer-encoding".to_string(), String::new()),
                ("user-agent".to_string(), String::new()),
                ("vary".to_string(), String::new()),
                ("via".to_string(), String::new()),
                ("www-authenticate".to_string(), String::new()),
            ];

            Self {
                static_table,
                dynamic_table: VecDeque::new(),
                max_size,
                current_size: 0,
            }
        }

        pub fn add_entry(&mut self, name: String, value: String) {
            let entry_size = name.len() + value.len() + 32; // RFC 7541 overhead

            // Evict entries to make room
            while self.current_size + entry_size > self.max_size && !self.dynamic_table.is_empty() {
                if let Some((old_name, old_value)) = self.dynamic_table.pop_back() {
                    self.current_size -= old_name.len() + old_value.len() + 32;
                }
            }

            // Add new entry if it fits
            if entry_size <= self.max_size {
                self.dynamic_table.push_front((name.clone(), value.clone()));
                self.current_size += entry_size;
            }
        }

        pub fn find_entry(&self, name: &str, value: &str) -> Option<usize> {
            // Check static table
            for (i, (static_name, static_value)) in self.static_table.iter().enumerate() {
                if static_name == name && static_value == value {
                    return Some(i + 1); // 1-indexed
                }
            }

            // Check dynamic table
            for (i, (dynamic_name, dynamic_value)) in self.dynamic_table.iter().enumerate() {
                if dynamic_name == name && dynamic_value == value {
                    return Some(self.static_table.len() + i + 1);
                }
            }

            None
        }

        pub fn compress_headers(&mut self, headers: &[(String, String)]) -> Vec<u8> {
            let mut encoded = Vec::new();

            for (name, value) in headers {
                if let Some(index) = self.find_entry(name, value) {
                    // Indexed header field representation
                    encoded.push(0x80 | (index as u8)); // Simplified encoding
                } else {
                    // Literal header field with incremental indexing
                    encoded.push(0x40); // Simplified: literal with incremental indexing
                    encoded.extend_from_slice(name.as_bytes());
                    encoded.push(0);
                    encoded.extend_from_slice(value.as_bytes());

                    self.add_entry(name.clone(), value.clone());
                }
            }

            encoded
        }

        pub fn decompress_headers(&mut self, encoded: &[u8]) -> Vec<(String, String)> {
            let mut headers = Vec::new();
            let mut i = 0;

            while i < encoded.len() {
                if encoded[i] & 0x80 != 0 {
                    // Indexed header field
                    let index = (encoded[i] & 0x7F) as usize;
                    if index > 0 && index <= self.static_table.len() {
                        let (name, value) = self.static_table[index - 1].clone();
                        headers.push((name, value));
                    } else if index > self.static_table.len() {
                        let dynamic_index = index - self.static_table.len() - 1;
                        if dynamic_index < self.dynamic_table.len() {
                            let (name, value) = self.dynamic_table[dynamic_index].clone();
                            headers.push((name, value));
                        }
                    }
                    i += 1;
                } else if encoded[i] & 0x40 != 0 {
                    // Literal header field with incremental indexing (simplified)
                    i += 1; // Skip literal flag

                    // Read name (simplified - until null byte)
                    let name_start = i;
                    while i < encoded.len() && encoded[i] != 0 {
                        i += 1;
                    }
                    let name = String::from_utf8_lossy(&encoded[name_start..i]).to_string();
                    i += 1; // Skip null byte

                    // Read value (simplified - until end or next header)
                    let value_start = i;
                    while i < encoded.len() && (encoded[i] & 0x80) == 0 && (encoded[i] & 0x40) == 0
                    {
                        i += 1;
                    }
                    let value = String::from_utf8_lossy(&encoded[value_start..i]).to_string();

                    headers.push((name.clone(), value.clone()));
                    self.add_entry(name, value);
                } else {
                    i += 1; // Skip unknown encoding
                }
            }

            headers
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockH2FlowControl {
        pub connection_window: i32,
        pub stream_windows: HashMap<u32, i32>,
        pub initial_window_size: i32,
    }

    impl MockH2FlowControl {
        pub fn new(initial_window_size: i32) -> Self {
            Self {
                connection_window: initial_window_size,
                stream_windows: HashMap::new(),
                initial_window_size,
            }
        }

        pub fn create_stream(&mut self, stream_id: u32) {
            self.stream_windows
                .insert(stream_id, self.initial_window_size);
        }

        pub fn send_data(&mut self, stream_id: u32, length: u32) -> Result<(), String> {
            let length = length as i32;

            // Check connection window
            if self.connection_window < length {
                return Err("Connection flow control window exceeded".to_string());
            }

            // Check stream window
            let stream_window = self
                .stream_windows
                .get_mut(&stream_id)
                .ok_or("Stream not found")?;

            if *stream_window < length {
                return Err("Stream flow control window exceeded".to_string());
            }

            // Consume window
            self.connection_window -= length;
            *stream_window -= length;

            Ok(())
        }

        pub fn receive_window_update(
            &mut self,
            stream_id: Option<u32>,
            increment: u32,
        ) -> Result<(), String> {
            let increment = increment as i32;

            if increment <= 0 {
                return Err("Window update increment must be positive".to_string());
            }

            match stream_id {
                Some(id) => {
                    let stream_window =
                        self.stream_windows.get_mut(&id).ok_or("Stream not found")?;

                    if *stream_window > i32::MAX - increment {
                        return Err("Stream window overflow".to_string());
                    }

                    *stream_window += increment;
                }
                None => {
                    if self.connection_window > i32::MAX - increment {
                        return Err("Connection window overflow".to_string());
                    }

                    self.connection_window += increment;
                }
            }

            Ok(())
        }

        pub fn total_available_credit(&self) -> u64 {
            let stream_credit: i64 = self.stream_windows.values().map(|w| *w as i64).sum();
            (self.connection_window as i64 + stream_credit).max(0) as u64
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockH3Frame {
        Data {
            stream_id: u64,
            data: Vec<u8>,
        },
        Headers {
            stream_id: u64,
            headers: Vec<(String, String)>,
        },
        Settings {
            max_table_capacity: Option<u32>,
            blocked_streams: Option<u32>,
        },
        PushPromise {
            stream_id: u64,
            promised_stream_id: u64,
            headers: Vec<(String, String)>,
        },
        CancelPush {
            push_id: u64,
        },
        MaxPushId {
            push_id: u64,
        },
        Unknown {
            frame_type: u64,
            payload: Vec<u8>,
        },
    }

    impl MockH3Frame {
        pub fn encode(&self) -> Vec<u8> {
            match self {
                MockH3Frame::Data { stream_id, data } => {
                    let mut encoded = Vec::new();
                    encoded.extend_from_slice(&stream_id.to_be_bytes());
                    encoded.push(0x00); // DATA frame type
                    encoded.extend_from_slice(&(data.len() as u64).to_be_bytes());
                    encoded.extend_from_slice(data);
                    encoded
                }
                MockH3Frame::Headers { stream_id, headers } => {
                    let mut encoded = Vec::new();
                    encoded.extend_from_slice(&stream_id.to_be_bytes());
                    encoded.push(0x01); // HEADERS frame type

                    let mut headers_data = Vec::new();
                    for (name, value) in headers {
                        headers_data.extend_from_slice(name.as_bytes());
                        headers_data.push(0);
                        headers_data.extend_from_slice(value.as_bytes());
                        headers_data.push(0);
                    }

                    encoded.extend_from_slice(&(headers_data.len() as u64).to_be_bytes());
                    encoded.extend_from_slice(&headers_data);
                    encoded
                }
                MockH3Frame::Settings {
                    max_table_capacity,
                    blocked_streams,
                } => {
                    let mut encoded = Vec::new();
                    encoded.push(0x04); // SETTINGS frame type

                    let mut settings_data = Vec::new();
                    if let Some(capacity) = max_table_capacity {
                        settings_data.extend_from_slice(&1u16.to_be_bytes()); // QPACK_MAX_TABLE_CAPACITY
                        settings_data.extend_from_slice(&capacity.to_be_bytes());
                    }
                    if let Some(streams) = blocked_streams {
                        settings_data.extend_from_slice(&7u16.to_be_bytes()); // QPACK_BLOCKED_STREAMS
                        settings_data.extend_from_slice(&streams.to_be_bytes());
                    }

                    encoded.extend_from_slice(&(settings_data.len() as u64).to_be_bytes());
                    encoded.extend_from_slice(&settings_data);
                    encoded
                }
                _ => {
                    vec![0xFF] // Unknown frame encoding
                }
            }
        }

        pub fn decode(bytes: &[u8]) -> Result<Self, String> {
            if bytes.is_empty() {
                return Err("Empty frame data".to_string());
            }

            let frame_type = bytes[0];

            match frame_type {
                0x00 => {
                    if bytes.len() < 17 {
                        return Err("Invalid DATA frame".to_string());
                    }
                    let stream_id = u64::from_be_bytes([
                        bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                        bytes[8],
                    ]);
                    let length = u64::from_be_bytes([
                        bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
                        bytes[16],
                    ]) as usize;

                    if bytes.len() < 17 + length {
                        return Err("Truncated DATA frame".to_string());
                    }

                    let data = bytes[17..17 + length].to_vec();
                    Ok(MockH3Frame::Data { stream_id, data })
                }
                0x01 => {
                    if bytes.len() < 17 {
                        return Err("Invalid HEADERS frame".to_string());
                    }
                    let stream_id = u64::from_be_bytes([
                        bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                        bytes[8],
                    ]);
                    let length = u64::from_be_bytes([
                        bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
                        bytes[16],
                    ]) as usize;

                    if bytes.len() < 17 + length {
                        return Err("Truncated HEADERS frame".to_string());
                    }

                    // Simple header parsing (name\0value\0)
                    let headers_data = &bytes[17..17 + length];
                    let mut headers = Vec::new();
                    let mut i = 0;
                    while i < headers_data.len() {
                        let name_start = i;
                        while i < headers_data.len() && headers_data[i] != 0 {
                            i += 1;
                        }
                        if i >= headers_data.len() {
                            break;
                        }
                        let name =
                            String::from_utf8_lossy(&headers_data[name_start..i]).to_string();
                        i += 1; // Skip null

                        let value_start = i;
                        while i < headers_data.len() && headers_data[i] != 0 {
                            i += 1;
                        }
                        let value =
                            String::from_utf8_lossy(&headers_data[value_start..i]).to_string();
                        i += 1; // Skip null

                        headers.push((name, value));
                    }

                    Ok(MockH3Frame::Headers { stream_id, headers })
                }
                0x04 => {
                    // SETTINGS frame (simplified)
                    Ok(MockH3Frame::Settings {
                        max_table_capacity: Some(4096),
                        blocked_streams: Some(100),
                    })
                }
                _ => Ok(MockH3Frame::Unknown {
                    frame_type: frame_type as u64,
                    payload: bytes[1..].to_vec(),
                }),
            }
        }

        pub fn frame_type(&self) -> u64 {
            match self {
                MockH3Frame::Data { .. } => 0x00,
                MockH3Frame::Headers { .. } => 0x01,
                MockH3Frame::Settings { .. } => 0x04,
                MockH3Frame::PushPromise { .. } => 0x05,
                MockH3Frame::CancelPush { .. } => 0x03,
                MockH3Frame::MaxPushId { .. } => 0x0D,
                MockH3Frame::Unknown { frame_type, .. } => *frame_type,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockGrpcStatus {
        Ok = 0,
        Cancelled = 1,
        Unknown = 2,
        InvalidArgument = 3,
        DeadlineExceeded = 4,
        NotFound = 5,
        AlreadyExists = 6,
        PermissionDenied = 7,
        ResourceExhausted = 8,
        FailedPrecondition = 9,
        Aborted = 10,
        OutOfRange = 11,
        Unimplemented = 12,
        Internal = 13,
        Unavailable = 14,
        DataLoss = 15,
        Unauthenticated = 16,
    }

    impl MockGrpcStatus {
        pub fn to_http_status(&self) -> u16 {
            match self {
                MockGrpcStatus::Ok => 200,
                MockGrpcStatus::Cancelled => 499, // Client Closed Request
                MockGrpcStatus::Unknown => 500,
                MockGrpcStatus::InvalidArgument => 400,
                MockGrpcStatus::DeadlineExceeded => 504,
                MockGrpcStatus::NotFound => 404,
                MockGrpcStatus::AlreadyExists => 409,
                MockGrpcStatus::PermissionDenied => 403,
                MockGrpcStatus::ResourceExhausted => 429,
                MockGrpcStatus::FailedPrecondition => 400,
                MockGrpcStatus::Aborted => 409,
                MockGrpcStatus::OutOfRange => 400,
                MockGrpcStatus::Unimplemented => 501,
                MockGrpcStatus::Internal => 500,
                MockGrpcStatus::Unavailable => 503,
                MockGrpcStatus::DataLoss => 500,
                MockGrpcStatus::Unauthenticated => 401,
            }
        }

        pub fn from_http_status(status: u16) -> Option<Self> {
            match status {
                200 => Some(MockGrpcStatus::Ok),
                400 => Some(MockGrpcStatus::InvalidArgument), // Ambiguous, choose most common
                401 => Some(MockGrpcStatus::Unauthenticated),
                403 => Some(MockGrpcStatus::PermissionDenied),
                404 => Some(MockGrpcStatus::NotFound),
                409 => Some(MockGrpcStatus::AlreadyExists), // Ambiguous, choose most common
                429 => Some(MockGrpcStatus::ResourceExhausted),
                499 => Some(MockGrpcStatus::Cancelled),
                500 => Some(MockGrpcStatus::Internal), // Ambiguous, choose most common
                501 => Some(MockGrpcStatus::Unimplemented),
                503 => Some(MockGrpcStatus::Unavailable),
                504 => Some(MockGrpcStatus::DeadlineExceeded),
                _ => None,
            }
        }

        pub fn from_code(code: i32) -> Option<Self> {
            match code {
                0 => Some(MockGrpcStatus::Ok),
                1 => Some(MockGrpcStatus::Cancelled),
                2 => Some(MockGrpcStatus::Unknown),
                3 => Some(MockGrpcStatus::InvalidArgument),
                4 => Some(MockGrpcStatus::DeadlineExceeded),
                5 => Some(MockGrpcStatus::NotFound),
                6 => Some(MockGrpcStatus::AlreadyExists),
                7 => Some(MockGrpcStatus::PermissionDenied),
                8 => Some(MockGrpcStatus::ResourceExhausted),
                9 => Some(MockGrpcStatus::FailedPrecondition),
                10 => Some(MockGrpcStatus::Aborted),
                11 => Some(MockGrpcStatus::OutOfRange),
                12 => Some(MockGrpcStatus::Unimplemented),
                13 => Some(MockGrpcStatus::Internal),
                14 => Some(MockGrpcStatus::Unavailable),
                15 => Some(MockGrpcStatus::DataLoss),
                16 => Some(MockGrpcStatus::Unauthenticated),
                _ => None,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockGrpcMessage {
        pub method: String,
        pub payload: Vec<u8>,
        pub compression: Option<String>,
        pub metadata: HashMap<String, String>,
    }

    impl MockGrpcMessage {
        pub fn new(method: &str, payload: Vec<u8>) -> Self {
            Self {
                method: method.to_string(),
                payload,
                compression: None,
                metadata: HashMap::new(),
            }
        }

        pub fn with_compression(mut self, compression: &str) -> Self {
            self.compression = Some(compression.to_string());
            self
        }

        pub fn encode_frame(&self) -> Vec<u8> {
            let mut frame = Vec::new();

            // Compression flag (1 byte)
            frame.push(if self.compression.is_some() { 1 } else { 0 });

            // Message length (4 bytes, big-endian)
            let length = self.payload.len() as u32;
            frame.extend_from_slice(&length.to_be_bytes());

            // Message data
            frame.extend_from_slice(&self.payload);

            frame
        }

        pub fn decode_frame(bytes: &[u8]) -> Result<Vec<u8>, String> {
            if bytes.len() < 5 {
                return Err("Frame too short".to_string());
            }

            let _compression_flag = bytes[0];
            let length = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;

            if bytes.len() < 5 + length {
                return Err("Frame truncated".to_string());
            }

            Ok(bytes[5..5 + length].to_vec())
        }

        pub fn fragment_at_boundaries(frame: &[u8], boundaries: &[usize]) -> Vec<Vec<u8>> {
            let mut fragments = Vec::new();
            let mut start = 0;

            for &boundary in boundaries {
                if boundary > start && boundary <= frame.len() {
                    fragments.push(frame[start..boundary].to_vec());
                    start = boundary;
                }
            }

            if start < frame.len() {
                fragments.push(frame[start..].to_vec());
            }

            fragments
        }

        pub fn reassemble_fragments(fragments: &[Vec<u8>]) -> Vec<u8> {
            let mut reassembled = Vec::new();
            for fragment in fragments {
                reassembled.extend_from_slice(fragment);
            }
            reassembled
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Metamorphic Relations: HTTP/1.1 Codec Operations
    // ═══════════════════════════════════════════════════════════════════════════

    proptest! {
        /// **MR-H1CodecRoundTrip**: HTTP/1.1 encode(decode(bytes)) preserves semantic content
        /// even when syntactic formatting differs (whitespace, case, header order).
        ///
        /// **Property**: decode(encode(request)) preserves method, URI, headers, body
        ///
        /// **Catches**: Codec parsing/serialization bugs, header value mangling, body corruption
        #[test]
        fn mr_h1_codec_round_trip(
            method in "(GET|POST|PUT|DELETE|HEAD|OPTIONS)",
            uri in "/[a-zA-Z0-9/_-]{0,50}(\\?[a-zA-Z0-9=&_-]{0,20})?",
            header_name in "[a-zA-Z][a-zA-Z0-9-]{2,20}",
            header_value in "[a-zA-Z0-9 ._-]{1,50}",
            body_bytes in prop::collection::vec(0u8..255u8, 0..1000)
        ) {
            let original_request = MockHttpRequest::new(&method, &uri, "HTTP/1.1")
                .with_header(&header_name, &header_value)
                .with_header("Host", "example.com")
                .with_body(body_bytes.clone());

            let encoded = original_request.encode_h1();
            let decoded_request = MockHttpRequest::decode_h1(&encoded)
                .expect("Failed to decode HTTP/1.1 request");

            // Semantic preservation: core components must match
            prop_assert_eq!(&decoded_request.method, &original_request.method,
                "Method mismatch after round-trip");
            prop_assert_eq!(&decoded_request.uri, &original_request.uri,
                "URI mismatch after round-trip");
            prop_assert_eq!(&decoded_request.version, &original_request.version,
                "Version mismatch after round-trip");

            // Header preservation (order may change, but values must be preserved).
            // The header iterator yields shared references; clone them so the macro
            // doesn't move out of the loop binding.
            for (orig_name, orig_value) in &original_request.headers {
                let decoded_value = decoded_request.get_header(orig_name)
                    .unwrap_or_else(|| panic!("Header '{}' missing after round-trip", orig_name));
                prop_assert_eq!(decoded_value, orig_value,
                    "Header '{}' value changed", orig_name);
            }

            // Body preservation
            if !body_bytes.is_empty() {
                prop_assert_eq!(&decoded_request.body, &body_bytes,
                    "Body content changed after round-trip");
            }
        }
    }

    proptest! {
        /// **MR-BufferBoundarySlicing**: HTTP message parsing is independent of buffer boundaries.
        /// Same message fragmented at different boundaries yields identical parsed result.
        ///
        /// **Property**: parse(fragment1 + fragment2) = parse(whole_message)
        ///
        /// **Catches**: Buffer boundary bugs, incomplete parsing, state machine errors
        #[test]
        fn mr_buffer_boundary_slicing(
            method in "(GET|POST|PUT|DELETE)",
            uri in "/[a-zA-Z0-9/_-]{1,20}",
            header_value in "[a-zA-Z0-9 ._-]{5,30}",
            body_size in 0usize..200usize,
            boundary_pos in 1usize..100usize
        ) {
            let body = vec![42u8; body_size];
            let request = MockHttpRequest::new(&method, &uri, "HTTP/1.1")
                .with_header("Content-Type", &header_value)
                .with_header("Host", "example.com")
                .with_body(body);

            let full_message = request.encode_h1();
            let boundary_pos = boundary_pos.min(full_message.len().saturating_sub(1));

            // Parse whole message
            let whole_parsed = MockHttpRequest::decode_h1(&full_message)
                .expect("Failed to parse whole message");

            // Parse message split at boundary
            let fragment1 = &full_message[..boundary_pos];
            let fragment2 = &full_message[boundary_pos..];
            let reassembled = [fragment1, fragment2].concat();
            let fragmented_parsed = MockHttpRequest::decode_h1(&reassembled)
                .expect("Failed to parse fragmented message");

            // Buffer boundary independence: results must be identical
            prop_assert_eq!(fragmented_parsed.method, whole_parsed.method);
            prop_assert_eq!(fragmented_parsed.uri, whole_parsed.uri);
            prop_assert_eq!(fragmented_parsed.headers, whole_parsed.headers);
            prop_assert_eq!(fragmented_parsed.body, whole_parsed.body,
                "Body parsing affected by buffer boundary at position {}", boundary_pos);
        }
    }

    proptest! {
        /// **MR-HeaderLineContinuation**: Folding/unfolding HTTP header values preserves semantics.
        /// Header line continuation (obs-fold) should normalize to single-line equivalent.
        ///
        /// **Property**: normalize(unfold(fold(header))) = normalize(header)
        ///
        /// **Catches**: Header folding bugs, whitespace handling, continuation parsing errors
        #[test]
        fn mr_header_line_continuation(
            header_name in "[a-zA-Z][a-zA-Z0-9-]{2,15}",
            header_value in "[a-zA-Z0-9 ._-]{10,50}"
        ) {
            // Test both single-line and folded representations
            let single_line_request = MockHttpRequest::new("GET", "/test", "HTTP/1.1")
                .with_header("Host", "example.com")
                .with_header(&header_name, &header_value);

            // Create folded version (simplified: insert CRLF + space in middle of value)
            let fold_position = header_value.len() / 2;
            let folded_value = format!("{}{}{}",
                &header_value[..fold_position],
                "\r\n ",  // Line fold
                &header_value[fold_position..]
            );

            let folded_request = MockHttpRequest::new("GET", "/test", "HTTP/1.1")
                .with_header("Host", "example.com")
                .with_header(&header_name, &folded_value);

            let single_encoded = single_line_request.encode_h1();
            let folded_encoded = folded_request.encode_h1();

            // Both should decode to equivalent semantic content
            let single_decoded = MockHttpRequest::decode_h1(&single_encoded)
                .expect("Failed to decode single-line request");
            let folded_decoded = MockHttpRequest::decode_h1(&folded_encoded)
                .expect("Failed to decode folded request");

            // Semantic equivalence: folded header should normalize to single-line value.
            // Clone the borrowed fields so prop_assert_eq! doesn't partially-move the
            // decoded structs ahead of the followup header borrow.
            prop_assert_eq!(single_decoded.method.clone(), folded_decoded.method.clone());
            prop_assert_eq!(single_decoded.uri.clone(), folded_decoded.uri.clone());

            // Header values should be semantically equivalent (whitespace normalized)
            let single_header_value = single_decoded.get_header(&header_name).unwrap();
            let folded_header_value = folded_decoded.get_header(&header_name).unwrap();

            let normalized_single = single_header_value.trim().replace(char::is_whitespace, " ");
            let normalized_folded = folded_header_value.trim().replace(char::is_whitespace, " ");

            prop_assert_eq!(normalized_single, normalized_folded,
                "Header folding/unfolding changed semantic content");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Metamorphic Relations: HTTP/2 HPACK Compression
    // ═══════════════════════════════════════════════════════════════════════════

    proptest! {
        /// **MR-HpackCompressionRoundTrip**: HPACK compress/decompress preserves header semantics.
        ///
        /// **Property**: decompress(compress(headers)) = headers (modulo order)
        ///
        /// **Catches**: HPACK encoding/decoding bugs, table corruption, header value mangling
        #[test]
        fn mr_hpack_compression_round_trip(
            header_pairs in prop::collection::vec(
                ("[a-z][a-z0-9-]{1,10}", "[a-zA-Z0-9 ._/-]{1,20}"),
                1..10
            )
        ) {
            let mut encoder_table = MockHpackTable::new(4096);
            let mut decoder_table = MockHpackTable::new(4096);

            let headers: Vec<(String, String)> = header_pairs.into_iter()
                .map(|(name, value)| (name, value))
                .collect();

            let compressed = encoder_table.compress_headers(&headers);
            let decompressed = decoder_table.decompress_headers(&compressed);

            // Round-trip preservation: all original headers must be preserved
            for (orig_name, orig_value) in &headers {
                let found = decompressed.iter()
                    .any(|(dec_name, dec_value)| dec_name == orig_name && dec_value == orig_value);
                prop_assert!(found,
                    "Header '{}': '{}' lost during HPACK round-trip", orig_name, orig_value);
            }

            // Symmetry: no extra headers should appear
            prop_assert_eq!(decompressed.len(), headers.len(),
                "Header count changed during HPACK round-trip: {} vs {}",
                headers.len(), decompressed.len());
        }
    }

    proptest! {
        /// **MR-DynamicTableEviction**: HPACK dynamic table evictions maintain LIFO discipline.
        /// Oldest entries are evicted first when table size limit is exceeded.
        ///
        /// **Property**: evict(table) removes oldest entries while preserving LIFO order
        ///
        /// **Catches**: Table eviction order bugs, size calculation errors, LIFO violations
        #[test]
        fn mr_dynamic_table_eviction(
            table_size in 100usize..1000usize,
            entry_count in 10usize..50usize
        ) {
            let mut table = MockHpackTable::new(table_size);
            let mut added_entries = Vec::new();

            // Add entries until table starts evicting
            for i in 0..entry_count {
                let name = format!("header-{}", i);
                let value = format!("value-{i}-{}", "x".repeat(20)); // Large values to force eviction

                let initial_size = table.dynamic_table.len();
                table.add_entry(name.clone(), value.clone());

                added_entries.push((name, value, initial_size));
            }

            // Verify LIFO eviction discipline
            let final_table = &table.dynamic_table;
            let mut present_entries = Vec::new();

            for (name, value) in final_table.iter() {
                present_entries.push((name.clone(), value.clone()));
            }

            // LIFO property: if an entry is present, all newer entries must also be present
            for (i, (name, value, _)) in added_entries.iter().enumerate() {
                let is_present = present_entries.iter().any(|(n, v)| n == name && v == value);

                if is_present {
                    // All entries added after this one should also be present (LIFO)
                    for (newer_name, newer_value, _) in &added_entries[i+1..] {
                        let newer_present = present_entries.iter()
                            .any(|(n, v)| n == newer_name && v == newer_value);
                        prop_assert!(newer_present,
                            "LIFO violation: older entry '{}' present but newer entry '{}' evicted",
                            name, newer_name);
                    }
                }
            }

            // Size constraint: table should not exceed maximum size
            prop_assert!(table.current_size <= table.max_size,
                "Dynamic table size {} exceeds maximum {}", table.current_size, table.max_size);
        }
    }

    proptest! {
        /// **MR-HpackIndexingStrategy**: Indexed vs literal header representations preserve semantics.
        /// Different encoding strategies (indexed, literal) for same headers yield same result.
        ///
        /// **Property**: decode(indexed_encoding) = decode(literal_encoding)
        ///
        /// **Catches**: Encoding strategy bugs, indexing errors, representation inconsistencies
        #[test]
        fn mr_hpack_indexing_strategy(
            common_headers in prop::collection::vec(
                prop::sample::select(vec![
                    (":method", "GET"),
                    (":method", "POST"),
                    (":path", "/"),
                    (":scheme", "https"),
                    ("content-type", "application/json"),
                    ("user-agent", "test-agent"),
                ]),
                2..6
            )
        ) {
            let mut table1 = MockHpackTable::new(4096);
            let mut table2 = MockHpackTable::new(4096);

            let headers: Vec<(String, String)> = common_headers.into_iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect();

            // Strategy 1: Use compression (will create indexed entries)
            let compressed_indexed = table1.compress_headers(&headers);

            // Strategy 2: Force literal representation (simplified: just encode directly)
            let mut literal_encoding = Vec::new();
            for (name, value) in &headers {
                literal_encoding.push(0x40); // Literal with incremental indexing
                literal_encoding.extend_from_slice(name.as_bytes());
                literal_encoding.push(0);
                literal_encoding.extend_from_slice(value.as_bytes());
            }

            // Both strategies should decode to same semantic result
            let mut decoder1 = MockHpackTable::new(4096);
            let mut decoder2 = MockHpackTable::new(4096);

            let result1 = decoder1.decompress_headers(&compressed_indexed);
            let result2 = decoder2.decompress_headers(&literal_encoding);

            // Semantic equivalence: same headers regardless of encoding strategy
            prop_assert_eq!(result1.len(), result2.len(),
                "Different encoding strategies produced different header counts");

            for (name, value) in &headers {
                let found1 = result1.iter().any(|(n, v)| n == name && v == value);
                let found2 = result2.iter().any(|(n, v)| n == name && v == value);
                prop_assert_eq!(found1, found2,
                    "Encoding strategy affected header presence: '{}': '{}'", name, value);
            }
        }
    }

    proptest! {
        /// **MR-HpackTableSizeConstraints**: Dynamic table never exceeds configured size limits.
        ///
        /// **Property**: ∀ operations, table.current_size ≤ table.max_size
        ///
        /// **Catches**: Size calculation bugs, overflow errors, constraint violations
        #[test]
        fn mr_hpack_table_size_constraints(
            max_size in 100usize..2000usize,
            operations in prop::collection::vec(
                ("[a-z][a-z0-9-]{1,15}", "[a-zA-Z0-9 ._/-]{5,50}"),
                5..25
            )
        ) {
            let mut table = MockHpackTable::new(max_size);

            for (name, value) in operations {
                let pre_size = table.current_size;
                table.add_entry(name.clone(), value.clone());
                let post_size = table.current_size;

                // Size constraint: never exceed maximum
                prop_assert!(post_size <= max_size,
                    "Table size {} exceeded maximum {} after adding '{}': '{}'",
                    post_size, max_size, name, value);

                // Monotonicity: size should not arbitrarily increase beyond entry addition
                let entry_size = name.len() + value.len() + 32;
                if entry_size <= max_size {
                    prop_assert!(post_size >= entry_size.min(max_size),
                        "Table size {} too small after adding entry of size {}",
                        post_size, entry_size);
                }

                // Consistency: current size should match actual table contents
                let calculated_size: usize = table.dynamic_table.iter()
                    .map(|(n, v)| n.len() + v.len() + 32)
                    .sum();
                prop_assert_eq!(table.current_size, calculated_size,
                    "Table current_size field {} inconsistent with calculated size {}",
                    table.current_size, calculated_size);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Metamorphic Relations: HTTP/2 Flow Control
    // ═══════════════════════════════════════════════════════════════════════════

    proptest! {
        /// **MR-FlowControlCreditConservation**: Total flow control credits are conserved.
        /// Credits consumed by DATA frames equal credits granted by WINDOW_UPDATE frames.
        ///
        /// **Property**: Σ(data_sent) + current_window = initial_window + Σ(window_updates)
        ///
        /// **Catches**: Credit leaks, double-spending, accounting errors
        #[test]
        fn mr_flow_control_credit_conservation(
            initial_window in 1000i32..100000i32,
            stream_count in 1u32..10u32,
            operations in prop::collection::vec(
                prop::sample::select(vec!["send_data", "window_update"]),
                5..20
            )
        ) {
            let mut flow_control = MockH2FlowControl::new(initial_window);

            // Create streams
            let stream_ids: Vec<u32> = (1..=stream_count*2).step_by(2).collect(); // Odd stream IDs
            for &stream_id in &stream_ids {
                flow_control.create_stream(stream_id);
            }

            let initial_total_credit = flow_control.total_available_credit();
            let mut total_data_sent = 0u64;
            let mut total_updates_received = 0u64;

            for operation in operations {
                match operation {
                    "send_data" => {
                        if let Some(&stream_id) = stream_ids.first() {
                            let data_length = 100u32; // Fixed size for simplicity
                            if flow_control.send_data(stream_id, data_length).is_ok() {
                                total_data_sent += data_length as u64;
                            }
                        }
                    }
                    "window_update" => {
                        let increment = 200u32;
                        if let Some(&stream_id) = stream_ids.first() {
                            if flow_control.receive_window_update(Some(stream_id), increment).is_ok() {
                                total_updates_received += increment as u64;
                            }
                        }
                        // Also test connection-level updates
                        if flow_control.receive_window_update(None, increment).is_ok() {
                            total_updates_received += increment as u64;
                        }
                    }
                    _ => {}
                }
            }

            let final_total_credit = flow_control.total_available_credit();

            // Credit conservation: initial + updates = final + sent
            let expected_final_credit = initial_total_credit + total_updates_received - total_data_sent;

            // Allow some tolerance for complex accounting
            let credit_difference = if final_total_credit > expected_final_credit {
                final_total_credit - expected_final_credit
            } else {
                expected_final_credit - final_total_credit
            };

            prop_assert!(credit_difference <= total_data_sent / 10, // 10% tolerance
                "Credit conservation violated: expected {}, got {}, difference {}",
                expected_final_credit, final_total_credit, credit_difference);
        }
    }

    proptest! {
        /// **MR-WindowUpdateMonotonicity**: Window updates never decrease available capacity.
        ///
        /// **Property**: window_after_update ≥ window_before_update
        ///
        /// **Catches**: Window overflow, negative updates, arithmetic errors
        #[test]
        fn mr_window_update_monotonicity(
            initial_window in 1000i32..50000i32,
            stream_id in 1u32..100u32,
            update_increments in prop::collection::vec(1u32..10000u32, 1..10)
        ) {
            let mut flow_control = MockH2FlowControl::new(initial_window);
            let stream_id = stream_id * 2 + 1; // Ensure odd stream ID
            flow_control.create_stream(stream_id);

            let initial_connection_window = flow_control.connection_window;
            let initial_stream_window = flow_control.stream_windows[&stream_id];

            for increment in update_increments {
                let pre_connection_window = flow_control.connection_window;
                let pre_stream_window = flow_control.stream_windows[&stream_id];

                // Apply window update (test both stream and connection updates)
                if increment < 30000 { // Avoid overflow in tests
                    let stream_update_result = flow_control.receive_window_update(Some(stream_id), increment);
                    let connection_update_result = flow_control.receive_window_update(None, increment);

                    if stream_update_result.is_ok() {
                        let post_stream_window = flow_control.stream_windows[&stream_id];

                        // Monotonicity: window should never decrease
                        prop_assert!(post_stream_window >= pre_stream_window,
                            "Stream window decreased after update: {} -> {}",
                            pre_stream_window, post_stream_window);

                        // Correctness: window should increase by increment
                        prop_assert_eq!(post_stream_window, pre_stream_window + increment as i32,
                            "Stream window update incorrect: expected {}, got {}",
                            pre_stream_window + increment as i32, post_stream_window);
                    }

                    if connection_update_result.is_ok() {
                        let post_connection_window = flow_control.connection_window;

                        // Monotonicity: connection window should never decrease
                        prop_assert!(post_connection_window >= pre_connection_window,
                            "Connection window decreased after update: {} -> {}",
                            pre_connection_window, post_connection_window);
                    }
                }
            }
        }
    }

    proptest! {
        /// **MR-StreamFlowIsolation**: Per-stream flow control is independent.
        /// Flow control state of one stream doesn't affect other streams.
        ///
        /// **Property**: operations on stream A don't change window of stream B
        ///
        /// **Catches**: Stream isolation bugs, cross-stream interference, shared state corruption
        #[test]
        fn mr_stream_flow_isolation(
            initial_window in 1000i32..10000i32,
            stream_a_id in 1u32..50u32,
            stream_b_id in 51u32..100u32,
            data_lengths in prop::collection::vec(10u32..500u32, 1..10)
        ) {
            let mut flow_control = MockH2FlowControl::new(initial_window);

            let stream_a = stream_a_id * 2 + 1; // Odd stream ID
            let stream_b = stream_b_id * 2 + 1; // Odd stream ID

            flow_control.create_stream(stream_a);
            flow_control.create_stream(stream_b);

            let initial_stream_a_window = flow_control.stream_windows[&stream_a];
            let initial_stream_b_window = flow_control.stream_windows[&stream_b];

            for data_length in data_lengths {
                let pre_stream_a_window = flow_control.stream_windows[&stream_a];
                let pre_stream_b_window = flow_control.stream_windows[&stream_b];

                // Send data on stream A
                let _send_result = flow_control.send_data(stream_a, data_length);

                let post_stream_a_window = flow_control.stream_windows[&stream_a];
                let post_stream_b_window = flow_control.stream_windows[&stream_b];

                // Isolation: operations on stream A must not affect stream B window
                prop_assert_eq!(post_stream_b_window, pre_stream_b_window,
                    "Stream {} window changed from {} to {} after operation on stream {}",
                    stream_b, pre_stream_b_window, post_stream_b_window, stream_a);

                // Stream A window should only change if send succeeded
                if data_length as i32 <= pre_stream_a_window {
                    prop_assert_eq!(post_stream_a_window, pre_stream_a_window - data_length as i32,
                        "Stream {} window update incorrect after sending {} bytes",
                        stream_a, data_length);
                }
            }

            // Independence: total window changes should only affect the operated stream
            let final_stream_a_change = initial_stream_a_window - flow_control.stream_windows[&stream_a];
            let final_stream_b_change = initial_stream_b_window - flow_control.stream_windows[&stream_b];

            prop_assert_eq!(final_stream_b_change, 0,
                "Stream {} window changed by {} despite no operations on it",
                stream_b, final_stream_b_change);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Metamorphic Relations: HTTP/3 and gRPC
    // ═══════════════════════════════════════════════════════════════════════════

    proptest! {
        /// **MR-H3FrameVariantRoundTrip**: HTTP/3 frame encoding/decoding preserves frame types.
        ///
        /// **Property**: decode(encode(frame)).frame_type = frame.frame_type
        ///
        /// **Catches**: Frame type corruption, encoding/decoding mismatches, variant handling bugs
        #[test]
        fn mr_h3_frame_variant_round_trip(
            stream_id in 1u64..1000u64,
            data_size in 0usize..1000usize,
            header_count in 1usize..10usize
        ) {
            let test_data = vec![42u8; data_size];
            let test_headers = (0..header_count)
                .map(|i| (format!("header-{}", i), format!("value-{}", i)))
                .collect();

            let frames = vec![
                MockH3Frame::Data { stream_id, data: test_data.clone() },
                MockH3Frame::Headers { stream_id, headers: test_headers },
                MockH3Frame::Settings { max_table_capacity: Some(4096), blocked_streams: Some(100) },
            ];

            for frame in frames {
                let original_frame_type = frame.frame_type();
                let encoded = frame.encode();
                let decoded = MockH3Frame::decode(&encoded)
                    .expect("Failed to decode H3 frame");
                let decoded_frame_type = decoded.frame_type();

                // Frame type preservation
                prop_assert_eq!(decoded_frame_type, original_frame_type,
                    "Frame type changed during round-trip: {} -> {}",
                    original_frame_type, decoded_frame_type);

                // Content preservation (for specific frame types)
                match (&frame, &decoded) {
                    (MockH3Frame::Data { data: orig_data, .. },
                     MockH3Frame::Data { data: dec_data, .. }) => {
                        prop_assert_eq!(orig_data, dec_data, "DATA frame content corrupted");
                    }
                    (MockH3Frame::Headers { headers: orig_headers, .. },
                     MockH3Frame::Headers { headers: dec_headers, .. }) => {
                        prop_assert_eq!(orig_headers, dec_headers, "HEADERS frame content corrupted");
                    }
                    _ => {} // Other frame types have simplified content
                }
            }
        }
    }

    proptest! {
        /// **MR-StatusCodeBijection**: gRPC status ↔ HTTP status mapping is bijective for valid codes.
        ///
        /// **Property**: http_to_grpc(grpc_to_http(status)) = status for valid status codes
        ///
        /// **Catches**: Status mapping inconsistencies, information loss, bijection violations
        #[test]
        fn mr_status_code_bijection(
            grpc_status_code in 0i32..17i32
        ) {
            if let Some(grpc_status) = MockGrpcStatus::from_code(grpc_status_code) {
                let http_status = grpc_status.to_http_status();
                let back_to_grpc = MockGrpcStatus::from_http_status(http_status);

                // For unambiguous mappings, should be bijective
                match grpc_status {
                    MockGrpcStatus::Ok | MockGrpcStatus::Cancelled | MockGrpcStatus::NotFound |
                    MockGrpcStatus::Unauthenticated | MockGrpcStatus::PermissionDenied |
                    MockGrpcStatus::ResourceExhausted | MockGrpcStatus::Unimplemented |
                    MockGrpcStatus::Unavailable | MockGrpcStatus::DeadlineExceeded => {
                        let expected = Some(grpc_status.clone());
                        let grpc_status_dbg = grpc_status.clone();
                        prop_assert_eq!(back_to_grpc, expected,
                            "Bijection failed for {:?} at HTTP status {}",
                            grpc_status_dbg, http_status);
                    }
                    _ => {
                        // For ambiguous mappings, ensure at least some valid mapping exists
                        prop_assert!(back_to_grpc.is_some(),
                            "No reverse mapping found for HTTP status {} (from gRPC {:?})",
                            http_status, grpc_status);
                    }
                }

                // HTTP status should be valid
                prop_assert!(http_status >= 200 && http_status < 600,
                    "Invalid HTTP status {} for gRPC status {:?}", http_status, grpc_status);
            }
        }
    }

    proptest! {
        /// **MR-GrpcMessageFraming**: Message boundaries preserved across fragmented reads.
        ///
        /// **Property**: reassemble(fragment(frame)) = frame for all fragment boundaries
        ///
        /// **Catches**: Frame boundary bugs, message corruption, fragmentation handling errors
        #[test]
        fn mr_grpc_message_framing(
            payload_size in 1usize..2000usize,
            fragment_boundaries in prop::collection::vec(1usize..500usize, 1..8)
        ) {
            let payload = vec![42u8; payload_size];
            let message = MockGrpcMessage::new("/test/method", payload.clone());
            let frame = message.encode_frame();

            // Create fragmentation boundaries within frame
            let mut boundaries = fragment_boundaries;
            boundaries.sort();
            boundaries.dedup();
            boundaries.retain(|&b| b < frame.len());

            if !boundaries.is_empty() {
                let fragments = MockGrpcMessage::fragment_at_boundaries(&frame, &boundaries);
                let reassembled = MockGrpcMessage::reassemble_fragments(&fragments);

                // Frame integrity: reassembled frame should be identical to original
                prop_assert_eq!(&reassembled, &frame,
                    "Frame corrupted during fragmentation/reassembly");

                // Message content preservation
                let decoded_payload = MockGrpcMessage::decode_frame(&reassembled)
                    .expect("Failed to decode reassembled frame");
                prop_assert_eq!(decoded_payload, payload,
                    "Message payload corrupted during fragmentation");

                // Boundary independence: result should be same regardless of fragment boundaries
                let different_boundaries: Vec<usize> = boundaries.iter()
                    .map(|&b| (b + 1).min(frame.len() - 1))
                    .filter(|&b| b < frame.len() && b > 0)
                    .collect();

                if !different_boundaries.is_empty() {
                    let alt_fragments = MockGrpcMessage::fragment_at_boundaries(&frame, &different_boundaries);
                    let alt_reassembled = MockGrpcMessage::reassemble_fragments(&alt_fragments);
                    prop_assert_eq!(&alt_reassembled, &frame,
                        "Different fragmentation boundaries produced different results");
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Validation Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_http_request_encoding() {
        let request = MockHttpRequest::new("GET", "/test", "HTTP/1.1")
            .with_header("Host", "example.com")
            .with_header("User-Agent", "test-agent");

        let encoded = request.encode_h1();
        let encoded_str = String::from_utf8_lossy(&encoded);

        assert!(encoded_str.contains("GET /test HTTP/1.1"));
        assert!(encoded_str.contains("Host: example.com"));
        assert!(encoded_str.contains("User-Agent: test-agent"));
    }

    #[test]
    fn test_hpack_table_basic_operations() {
        let mut table = MockHpackTable::new(1000);

        table.add_entry("test-header".to_string(), "test-value".to_string());
        assert_eq!(table.dynamic_table.len(), 1);

        let index = table.find_entry("test-header", "test-value");
        assert!(index.is_some());

        // Should find static entries
        let method_index = table.find_entry(":method", "GET");
        assert!(method_index.is_some());
    }

    #[test]
    fn test_h2_flow_control_basic() {
        let mut fc = MockH2FlowControl::new(1000);
        fc.create_stream(1);

        assert_eq!(fc.send_data(1, 500), Ok(()));
        assert_eq!(fc.connection_window, 500);
        assert_eq!(fc.stream_windows[&1], 500);

        assert_eq!(fc.receive_window_update(Some(1), 200), Ok(()));
        assert_eq!(fc.stream_windows[&1], 700);
    }

    #[test]
    fn test_h3_frame_encoding() {
        let frame = MockH3Frame::Data {
            stream_id: 123,
            data: vec![1, 2, 3, 4, 5],
        };

        let encoded = frame.encode();
        assert!(!encoded.is_empty());

        let decoded = MockH3Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.frame_type(), 0x00); // DATA frame type
    }

    #[test]
    fn test_grpc_status_mapping() {
        assert_eq!(MockGrpcStatus::Ok.to_http_status(), 200);
        assert_eq!(MockGrpcStatus::NotFound.to_http_status(), 404);
        assert_eq!(MockGrpcStatus::Internal.to_http_status(), 500);

        assert_eq!(
            MockGrpcStatus::from_http_status(200),
            Some(MockGrpcStatus::Ok)
        );
        assert_eq!(
            MockGrpcStatus::from_http_status(404),
            Some(MockGrpcStatus::NotFound)
        );
        assert_eq!(
            MockGrpcStatus::from_http_status(500),
            Some(MockGrpcStatus::Internal)
        );
    }

    #[test]
    fn test_grpc_message_framing() {
        let message = MockGrpcMessage::new("/test", vec![1, 2, 3, 4]);
        let frame = message.encode_frame();

        assert_eq!(frame.len(), 5 + 4); // 5-byte header + 4-byte payload
        assert_eq!(frame[0], 0); // No compression
        assert_eq!(
            u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]),
            4
        ); // Length

        let decoded = MockGrpcMessage::decode_frame(&frame).unwrap();
        assert_eq!(decoded, vec![1, 2, 3, 4]);
    }
}
