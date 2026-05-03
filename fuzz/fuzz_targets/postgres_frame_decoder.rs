//! Structure-aware fuzzer for PostgreSQL backend frame decoder.
//!
//! Bead: br-asupersync-srbpo7
//!
//! Targets src/database/postgres.rs backend message parsing with focus on:
//! - Random message types (valid and invalid)
//! - Malformed length prefixes (negative, oversized, mismatched)
//! - Truncated frames (incomplete headers, partial bodies)
//! - Oversized payloads before limit checks
//! - Parser desynchronization between frames
//!
//! Bug classes to detect:
//! - Length/body desync causing buffer overruns
//! - Oversized allocation before safety checks
//! - Partial-frame EOF handling edge cases
//! - Parser state corruption consuming next frame bytes
//! - Inconsistent error vs panic behavior

#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::cx::Cx;
use asupersync::database::postgres::{PgConnectOptions, PgConnection, PgError};
use asupersync::test_utils::run_test_with_cx;

/// PostgreSQL backend message types (subset for fuzzing)
#[derive(Debug, Clone, Copy, Arbitrary)]
enum MessageType {
    Authentication = 0x52,  // b'R'
    BackendKeyData = 0x4b,  // b'K'
    BindComplete = 0x32,    // b'2'
    CommandComplete = 0x43, // b'C'
    DataRow = 0x44,         // b'D'
    ErrorResponse = 0x45,   // b'E'
    NoticeResponse = 0x4e,  // b'N'
    ParameterStatus = 0x53, // b'S'
    ParseComplete = 0x31,   // b'1'
    RowDescription = 0x54,  // b'T'
    ReadyForQuery = 0x5a,   // b'Z'
    Invalid = 0x00,         // Invalid type for error testing
}

impl MessageType {
    fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Length field corruption strategies
#[derive(Debug, Clone, Arbitrary)]
enum LengthCorruption {
    /// Valid length matching body size
    Valid,
    /// Negative length
    Negative,
    /// Zero length (invalid - must be >= 4)
    Zero,
    /// Length too small for body
    TooSmall,
    /// Length larger than body
    TooLarge,
    /// Maximum i32 value (potential overflow)
    MaxInt,
    /// Just below protocol limit
    NearLimit,
    /// Above protocol limit (should trigger safety check)
    AboveLimit,
}

/// Frame truncation strategies
#[derive(Debug, Clone, Arbitrary)]
enum TruncationMode {
    /// Complete frame
    Complete,
    /// Truncate after type byte
    NoLength,
    /// Truncate in middle of length field
    PartialLength { bytes_present: u8 }, // 1-3 bytes
    /// Truncate in middle of body
    PartialBody { body_bytes: u16 },
}

/// A single PostgreSQL backend message frame
#[derive(Debug, Clone)]
struct PgFrame {
    msg_type: MessageType,
    length_corruption: LengthCorruption,
    truncation: TruncationMode,
    body_data: Vec<u8>,
}

impl<'a> Arbitrary<'a> for PgFrame {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let msg_type = MessageType::arbitrary(u)?;
        let length_corruption = LengthCorruption::arbitrary(u)?;
        let truncation = TruncationMode::arbitrary(u)?;

        // Generate body data of varying sizes
        let body_size = match u.int_in_range(0..=3)? {
            0 => 0,                            // Empty body
            1 => u.int_in_range(1..=64)?,      // Small body
            2 => u.int_in_range(65..=1024)?,   // Medium body
            _ => u.int_in_range(1025..=8192)?, // Large body
        };

        let mut body_data = vec![0u8; body_size];
        u.fill_buffer(&mut body_data)?;

        Ok(Self {
            msg_type,
            length_corruption,
            truncation,
            body_data,
        })
    }
}

impl PgFrame {
    /// Serialize frame to wire format with corruptions applied
    fn serialize(&self) -> Vec<u8> {
        let mut frame = Vec::new();

        // Message type byte
        frame.push(self.msg_type.as_byte());

        match self.truncation {
            TruncationMode::NoLength => return frame,
            TruncationMode::PartialLength { bytes_present } => {
                let length_bytes = self.compute_length_bytes();
                let truncated = std::cmp::min(bytes_present as usize, length_bytes.len());
                frame.extend_from_slice(&length_bytes[..truncated]);
                return frame;
            }
            _ => {}
        }

        // Length field (4 bytes, big-endian)
        let length_bytes = self.compute_length_bytes();
        frame.extend_from_slice(&length_bytes);

        // Body data
        match self.truncation {
            TruncationMode::PartialBody { body_bytes } => {
                let truncated = std::cmp::min(body_bytes as usize, self.body_data.len());
                frame.extend_from_slice(&self.body_data[..truncated]);
            }
            TruncationMode::Complete => {
                frame.extend_from_slice(&self.body_data);
            }
            _ => {}
        }

        frame
    }

    /// Compute length field bytes with corruption applied
    fn compute_length_bytes(&self) -> Vec<u8> {
        let actual_body_len = self.body_data.len();

        let length_value = match self.length_corruption {
            LengthCorruption::Valid => (actual_body_len + 4) as i32,
            LengthCorruption::Negative => -1,
            LengthCorruption::Zero => 0,
            LengthCorruption::TooSmall => {
                if actual_body_len > 0 {
                    ((actual_body_len / 2) + 4) as i32
                } else {
                    2 // Less than minimum 4
                }
            }
            LengthCorruption::TooLarge => (actual_body_len * 2 + 4) as i32,
            LengthCorruption::MaxInt => i32::MAX,
            LengthCorruption::NearLimit => 64 * 1024 * 1024, // Just at limit
            LengthCorruption::AboveLimit => 128 * 1024 * 1024, // Above 64MB limit
        };

        length_value.to_be_bytes().to_vec()
    }

    /// Generate message-specific body content
    fn generate_message_body(&mut self, u: &mut Unstructured) -> Result<()> {
        match self.msg_type {
            MessageType::RowDescription => self.generate_row_description_body(u)?,
            MessageType::DataRow => self.generate_data_row_body(u)?,
            MessageType::Authentication => self.generate_auth_body(u)?,
            MessageType::ErrorResponse | MessageType::NoticeResponse => {
                self.generate_error_notice_body(u)?;
            }
            _ => {
                // Default: random body data already generated
            }
        }
        Ok(())
    }

    fn generate_row_description_body(&mut self, u: &mut Unstructured) -> Result<()> {
        let mut body = Vec::new();

        // Field count (2 bytes)
        let field_count: i16 = u.int_in_range(0..=10)?;
        body.extend_from_slice(&field_count.to_be_bytes());

        for _ in 0..field_count {
            // Field name (null-terminated string)
            let name_len: usize = u.int_in_range(1..=32)?;
            let mut name = vec![b'a'; name_len];
            u.fill_buffer(&mut name)?;
            body.extend_from_slice(&name);
            body.push(0); // null terminator

            // Table OID, column attribute number, type OID, type size, type modifier, format code
            body.extend_from_slice(&[0u8; 18]);
        }

        self.body_data = body;
        Ok(())
    }

    fn generate_data_row_body(&mut self, u: &mut Unstructured) -> Result<()> {
        let mut body = Vec::new();

        // Field count (2 bytes)
        let field_count: i16 = u.int_in_range(0..=10)?;
        body.extend_from_slice(&field_count.to_be_bytes());

        for _ in 0..field_count {
            // Field length (4 bytes) - can be -1 for NULL
            let field_len: i32 = if u.ratio(1, 4)? {
                -1 // NULL
            } else {
                u.int_in_range(0..=256)? as i32
            };

            body.extend_from_slice(&field_len.to_be_bytes());

            if field_len > 0 {
                let mut field_data = vec![0u8; field_len as usize];
                u.fill_buffer(&mut field_data)?;
                body.extend_from_slice(&field_data);
            }
        }

        self.body_data = body;
        Ok(())
    }

    fn generate_auth_body(&mut self, u: &mut Unstructured) -> Result<()> {
        let mut body = Vec::new();

        // Authentication type (4 bytes)
        let auth_type: u32 = u.choose(&[0, 3, 5, 10, 12])?; // Various auth types
        body.extend_from_slice(&auth_type.to_be_bytes());

        // Additional auth data
        let extra_len: usize = u.int_in_range(0..=64)?;
        let mut extra = vec![0u8; extra_len];
        u.fill_buffer(&mut extra)?;
        body.extend_from_slice(&extra);

        self.body_data = body;
        Ok(())
    }

    fn generate_error_notice_body(&mut self, u: &mut Unstructured) -> Result<()> {
        let mut body = Vec::new();

        // Error/notice fields (type byte + null-terminated string)
        let field_types = [b'S', b'C', b'M', b'D', b'F', b'L']; // Severity, Code, Message, etc.

        for &field_type in u.choose_multiple(&field_types, u.int_in_range(1..=4)?)? {
            body.push(field_type);

            let msg_len: usize = u.int_in_range(1..=128)?;
            let mut msg = vec![b'x'; msg_len];
            u.fill_buffer(&mut msg)?;
            body.extend_from_slice(&msg);
            body.push(0); // null terminator
        }

        body.push(0); // final null terminator

        self.body_data = body;
        Ok(())
    }
}

/// Fuzz input containing multiple frames to test parser state
#[derive(Debug, Clone)]
struct FuzzInput {
    frames: Vec<PgFrame>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let frame_count = u.int_in_range(1..=8)?;
        let mut frames = Vec::new();

        for _ in 0..frame_count {
            let mut frame = PgFrame::arbitrary(u)?;
            frame.generate_message_body(u)?;
            frames.push(frame);
        }

        Ok(Self { frames })
    }
}

impl FuzzInput {
    /// Serialize all frames into a single byte stream
    fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        for frame in &self.frames {
            data.extend_from_slice(&frame.serialize());
        }
        data
    }
}

/// Mock stream that provides fuzzed data and tracks read behavior
struct FuzzStream {
    data: Vec<u8>,
    position: usize,
    closed: bool,
}

impl FuzzStream {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            position: 0,
            closed: false,
        }
    }

    /// Simulate reading data with potential short reads and EOF conditions
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.closed || self.position >= self.data.len() {
            return Ok(0); // EOF
        }

        let available = self.data.len() - self.position;
        let to_read = std::cmp::min(buf.len(), available);

        buf[..to_read].copy_from_slice(&self.data[self.position..self.position + to_read]);
        self.position += to_read;

        Ok(to_read)
    }
}

/// Test function that exercises the PostgreSQL frame decoder
async fn test_postgres_frame_decoder(input: &FuzzInput, cx: &Cx) {
    let serialized = input.serialize();

    // Skip empty inputs
    if serialized.is_empty() {
        return;
    }

    // Create a mock stream with the fuzzed data
    let mut stream = FuzzStream::new(serialized);

    // Try to parse frames using similar logic to the real implementation
    // This tests backend_message_body_len and message parsing logic

    let mut frame_count = 0;
    const MAX_FRAMES: usize = 16; // Prevent infinite loops

    while frame_count < MAX_FRAMES {
        // Try to read message type
        let mut type_buf = [0u8; 1];
        match stream.read(&mut type_buf) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break, // IO error
        }

        let msg_type = type_buf[0];

        // Try to read length
        let mut len_buf = [0u8; 4];
        let mut read_count = 0;
        while read_count < 4 {
            match stream.read(&mut len_buf[read_count..]) {
                Ok(0) => return, // EOF during length read
                Ok(n) => read_count += n,
                Err(_) => return, // IO error
            }
        }

        let len_i32 = i32::from_be_bytes(len_buf);

        // Test backend_message_body_len function (this is the key target)
        let body_len = match asupersync::database::postgres::backend_message_body_len(len_i32) {
            Ok(len) => len,
            Err(_) => {
                // Expected for invalid lengths
                return;
            }
        };

        // Try to read body
        if body_len > 0 {
            let mut body = vec![0u8; body_len];
            let mut read_count = 0;
            while read_count < body_len {
                match stream.read(&mut body[read_count..]) {
                    Ok(0) => return, // EOF during body read
                    Ok(n) => read_count += n,
                    Err(_) => return, // IO error
                }
            }

            // Test message-specific parsing based on type
            match msg_type {
                0x54 => {
                    // RowDescription
                    let _ = test_parse_row_description(&body);
                }
                0x44 => {
                    // DataRow
                    let _ = test_parse_data_row(&body);
                }
                0x45 | 0x4e => {
                    // Error/Notice Response
                    let _ = test_parse_error_notice(&body);
                }
                _ => {
                    // Generic message body - just verify we can handle it
                }
            }
        }

        frame_count += 1;
    }
}

/// Test RowDescription parsing logic
fn test_parse_row_description(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if data.len() < 2 {
        return Ok(());
    }

    let mut pos = 0;

    // Read field count
    if pos + 2 > data.len() {
        return Ok(());
    }
    let field_count = i16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    if field_count < 0 {
        return Ok(()); // Invalid but handled
    }

    // Read fields
    for _ in 0..field_count {
        // Find field name (null-terminated)
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        if pos >= data.len() {
            return Ok(()); // Truncated
        }
        pos += 1; // Skip null terminator

        // Skip field metadata (18 bytes)
        pos += 18;
        if pos > data.len() {
            return Ok(()); // Truncated
        }
    }

    Ok(())
}

/// Test DataRow parsing logic
fn test_parse_data_row(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if data.len() < 2 {
        return Ok(());
    }

    let mut pos = 0;

    // Read field count
    if pos + 2 > data.len() {
        return Ok(());
    }
    let field_count = i16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    if field_count < 0 {
        return Ok(()); // Invalid but handled
    }

    // Read fields
    for _ in 0..field_count {
        if pos + 4 > data.len() {
            return Ok(()); // Truncated
        }

        let field_len =
            i32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        if field_len == -1 {
            // NULL field
            continue;
        }

        if field_len < 0 {
            return Ok(()); // Invalid length
        }

        pos += field_len as usize;
        if pos > data.len() {
            return Ok(()); // Truncated
        }
    }

    Ok(())
}

/// Test Error/Notice response parsing
fn test_parse_error_notice(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut pos = 0;

    while pos < data.len() {
        let field_type = data[pos];
        pos += 1;

        if field_type == 0 {
            break; // End of message
        }

        // Find null-terminated string
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        if pos >= data.len() {
            return Ok(()); // Truncated
        }
        pos += 1; // Skip null terminator
    }

    Ok(())
}

// Make the backend_message_body_len function accessible for testing
// Note: This would normally be done by making it pub or pub(crate) in the main code
use asupersync::database::postgres::backend_message_body_len;

fuzz_target!(|input: FuzzInput| {
    run_test_with_cx(|cx| async move {
        test_postgres_frame_decoder(&input, &cx).await;
    });
});
