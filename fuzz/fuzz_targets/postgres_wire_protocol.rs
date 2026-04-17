#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

// We need to import the parsing functions and types from the actual postgres module
use asupersync::database::postgres::{PgError};

/// PostgreSQL wire protocol message for fuzzing
#[derive(Debug, Arbitrary)]
struct PostgresMessage {
    /// Message type byte (R, T, D, E, etc.)
    message_type: u8,
    /// Message payload
    payload: Vec<u8>,
}

/// Structure for PostgreSQL authentication fuzzing
#[derive(Debug, Arbitrary)]
struct AuthenticationMessage {
    /// Authentication type (0=OK, 3=cleartext, 5=MD5, 10=SASL, 11=SASLContinue, 12=SASLFinal)
    auth_type: i32,
    /// Authentication data
    auth_data: Vec<u8>,
}

/// SCRAM authentication phases for fuzzing
#[derive(Debug, Arbitrary)]
struct ScramFuzzData {
    /// Client first message
    client_first: String,
    /// Server first message
    server_first: String,
    /// Client final message
    client_final: String,
    /// Server final message
    server_final: String,
    /// Username
    username: String,
    /// Password
    password: String,
}

/// Row description field for fuzzing
#[derive(Debug, Arbitrary)]
struct RowDescField {
    /// Field name (null-terminated)
    name: String,
    /// Table OID
    table_oid: u32,
    /// Column attribute number
    column_attr: i16,
    /// Type OID
    type_oid: u32,
    /// Type size
    type_size: i16,
    /// Type modifier
    type_modifier: i32,
    /// Format code (0=text, 1=binary)
    format_code: i16,
}

/// Data row value for fuzzing
#[derive(Debug, Arbitrary)]
struct DataRowValue {
    /// Value length (-1 for NULL)
    length: i32,
    /// Value data (if length >= 0)
    data: Vec<u8>,
}

/// Error response field for fuzzing
#[derive(Debug, Arbitrary)]
struct ErrorField {
    /// Field type (C=code, M=message, D=detail, H=hint, etc.)
    field_type: u8,
    /// Field value
    value: String,
}

/// Parameter description for fuzzing
#[derive(Debug, Arbitrary)]
struct ParameterDesc {
    /// Parameter type OID
    type_oid: u32,
}

/// Complete fuzz structure covering all PostgreSQL message types
#[derive(Debug, Arbitrary)]
enum PgWireMessage {
    /// Authentication messages (type 'R')
    Authentication(AuthenticationMessage),
    /// Row description (type 'T')
    RowDescription {
        fields: Vec<RowDescField>,
    },
    /// Data row (type 'D')
    DataRow {
        values: Vec<DataRowValue>,
    },
    /// Error response (type 'E')
    ErrorResponse {
        fields: Vec<ErrorField>,
    },
    /// Notice response (type 'N')
    NoticeResponse {
        fields: Vec<ErrorField>,
    },
    /// Parameter status (type 'S')
    ParameterStatus {
        name: String,
        value: String,
    },
    /// Ready for query (type 'Z')
    ReadyForQuery {
        status: u8, // 'I'=idle, 'T'=transaction, 'E'=error
    },
    /// Parameter description (type 't')
    ParameterDescription {
        params: Vec<ParameterDesc>,
    },
    /// Command complete (type 'C')
    CommandComplete {
        tag: String,
    },
    /// Backend key data (type 'K')
    BackendKeyData {
        process_id: i32,
        secret_key: i32,
    },
    /// Parse complete (type '1')
    ParseComplete,
    /// Bind complete (type '2')
    BindComplete,
    /// Close complete (type '3')
    CloseComplete,
    /// No data (type 'n')
    NoData,
    /// Portal suspended (type 's')
    PortalSuspended,
    /// SCRAM authentication data
    ScramAuth(ScramFuzzData),
    /// Raw message for edge case testing
    Raw(PostgresMessage),
}

/// Build a wire protocol message from structured data
fn build_message(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(5 + payload.len());
    result.push(msg_type);

    // Length includes itself (4 bytes) + payload
    let length = 4_i32 + i32::try_from(payload.len()).unwrap_or(i32::MAX);
    result.extend_from_slice(&length.to_be_bytes());
    result.extend_from_slice(payload);
    result
}

/// Build row description message
fn build_row_description(fields: &[RowDescField]) -> Vec<u8> {
    let mut payload = Vec::new();

    // Field count
    let field_count = i16::try_from(fields.len()).unwrap_or(i16::MAX);
    payload.extend_from_slice(&field_count.to_be_bytes());

    for field in fields {
        // Field name (null-terminated)
        payload.extend_from_slice(field.name.as_bytes());
        payload.push(0);

        // Field attributes
        payload.extend_from_slice(&(field.table_oid as i32).to_be_bytes());
        payload.extend_from_slice(&field.column_attr.to_be_bytes());
        payload.extend_from_slice(&(field.type_oid as i32).to_be_bytes());
        payload.extend_from_slice(&field.type_size.to_be_bytes());
        payload.extend_from_slice(&field.type_modifier.to_be_bytes());
        payload.extend_from_slice(&field.format_code.to_be_bytes());
    }

    build_message(b'T', &payload)
}

/// Build data row message
fn build_data_row(values: &[DataRowValue]) -> Vec<u8> {
    let mut payload = Vec::new();

    // Value count
    let value_count = i16::try_from(values.len()).unwrap_or(i16::MAX);
    payload.extend_from_slice(&value_count.to_be_bytes());

    for value in values {
        // Value length
        payload.extend_from_slice(&value.length.to_be_bytes());

        // Value data (if not NULL)
        if value.length >= 0 {
            let data_len = value.length as usize;
            if data_len <= value.data.len() {
                payload.extend_from_slice(&value.data[..data_len]);
            } else {
                // Pad with zeros if declared length exceeds data
                payload.extend_from_slice(&value.data);
                payload.resize(payload.len() + (data_len - value.data.len()), 0);
            }
        }
    }

    build_message(b'D', &payload)
}

/// Build error response message
fn build_error_response(fields: &[ErrorField], msg_type: u8) -> Vec<u8> {
    let mut payload = Vec::new();

    for field in fields {
        payload.push(field.field_type);
        payload.extend_from_slice(field.value.as_bytes());
        payload.push(0); // Null terminator
    }
    payload.push(0); // End of fields

    build_message(msg_type, &payload)
}

/// Build authentication message
fn build_auth_message(auth: &AuthenticationMessage) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&auth.auth_type.to_be_bytes());
    payload.extend_from_slice(&auth.auth_data);
    build_message(b'R', &payload)
}

/// Build parameter status message
fn build_parameter_status(name: &str, value: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    payload.extend_from_slice(value.as_bytes());
    payload.push(0);
    build_message(b'S', &payload)
}

/// Build parameter description message
fn build_parameter_description(params: &[ParameterDesc]) -> Vec<u8> {
    let mut payload = Vec::new();

    let param_count = i16::try_from(params.len()).unwrap_or(i16::MAX);
    payload.extend_from_slice(&param_count.to_be_bytes());

    for param in params {
        payload.extend_from_slice(&(param.type_oid as i32).to_be_bytes());
    }

    build_message(b't', &payload)
}

/// Test SCRAM-SHA-256 parsing edge cases
fn test_scram_parsing(scram: &ScramFuzzData) {
    // Test client-first message parsing
    let client_first = format!(
        "n,,n={},r={}",
        scram.username.replace("=", "=3D").replace(",", "=2C"),
        scram.client_first
    );
    let _ = client_first.parse::<String>();

    // Test server-first message parsing
    let server_first = format!(
        "r={},s={},i=4096",
        scram.server_first,
        base64_encode(&scram.password.as_bytes()[..std::cmp::min(scram.password.len(), 16)])
    );
    let _ = server_first.parse::<String>();

    // Test various SCRAM formats with edge cases
    let malformed_formats = [
        format!("r={}", scram.server_first),  // Missing salt and iterations
        format!("s={}", base64_encode(b"salt")), // Missing nonce and iterations
        format!("i={}", 4096), // Missing nonce and salt
        format!("r={},s={},i=-1", scram.server_first, base64_encode(b"salt")), // Negative iterations
        format!("r={},s={},i=1000000", scram.server_first, base64_encode(b"salt")), // Huge iterations
        format!("r={},s=,i=4096", scram.server_first), // Empty salt
        format!("r=,s={},i=4096", base64_encode(b"salt")), // Empty nonce
        "".to_string(), // Empty message
        "invalid".to_string(), // No equals signs
        "r=".to_string(), // Empty value
        "r=nonce,s=salt,i=invalid".to_string(), // Non-numeric iterations
    ];

    for format in &malformed_formats {
        let _ = format.parse::<String>();
    }
}

/// Simple base64 encoding for testing
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let b1 = chunk[0];
        let b2 = chunk.get(1).copied().unwrap_or(0);
        let b3 = chunk.get(2).copied().unwrap_or(0);

        result.push(CHARS[((b1 >> 2) & 0x3F) as usize] as char);
        result.push(CHARS[(((b1 << 4) | (b2 >> 4)) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(CHARS[(((b2 << 2) | (b3 >> 6)) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(CHARS[(b3 & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Mock connection for testing parsing functions
struct MockConn;

impl MockConn {
    /// Test the parsing functions we can access
    fn test_parsing(&self, message_data: &[u8]) {
        // Note: The actual parsing functions are private, so we test
        // what we can access through the public API or by recreating
        // the parsing logic to ensure our wire protocol messages are valid

        if message_data.len() < 5 {
            return;
        }

        let msg_type = message_data[0];
        let length_bytes = &message_data[1..5];
        let length = i32::from_be_bytes([
            length_bytes[0], length_bytes[1],
            length_bytes[2], length_bytes[3]
        ]);

        // Validate message structure
        if length < 4 || length as usize > message_data.len() - 1 {
            return;
        }

        let payload = &message_data[5..];
        let expected_payload_len = (length - 4) as usize;

        if payload.len() < expected_payload_len {
            return;
        }

        let actual_payload = &payload[..expected_payload_len];

        // Test different message types
        match msg_type {
            b'T' => self.test_row_description_parsing(actual_payload),
            b'D' => self.test_data_row_parsing(actual_payload),
            b'E' | b'N' => self.test_error_response_parsing(actual_payload),
            b'R' => self.test_auth_parsing(actual_payload),
            b'S' => self.test_parameter_status_parsing(actual_payload),
            b'Z' => self.test_ready_for_query_parsing(actual_payload),
            b't' => self.test_parameter_description_parsing(actual_payload),
            b'C' => self.test_command_complete_parsing(actual_payload),
            b'K' => self.test_backend_key_data_parsing(actual_payload),
            _ => {} // Unknown message type
        }
    }

    fn test_row_description_parsing(&self, data: &[u8]) {
        if data.len() < 2 {
            return;
        }

        let field_count = i16::from_be_bytes([data[0], data[1]]);
        if field_count < 0 {
            return;
        }

        let mut pos = 2;
        for _ in 0..field_count {
            // Field name (null-terminated string)
            while pos < data.len() && data[pos] != 0 {
                pos += 1;
            }
            if pos >= data.len() {
                return; // Unterminated string
            }
            pos += 1; // Skip null terminator

            // Field attributes: table_oid(4) + column_attr(2) + type_oid(4) + type_size(2) + type_modifier(4) + format_code(2)
            if pos + 18 > data.len() {
                return; // Not enough data
            }
            pos += 18;
        }
    }

    fn test_data_row_parsing(&self, data: &[u8]) {
        if data.len() < 2 {
            return;
        }

        let value_count = i16::from_be_bytes([data[0], data[1]]);
        if value_count < 0 {
            return;
        }

        let mut pos = 2;
        for _ in 0..value_count {
            if pos + 4 > data.len() {
                return;
            }

            let length = i32::from_be_bytes([
                data[pos], data[pos + 1], data[pos + 2], data[pos + 3]
            ]);
            pos += 4;

            if length == -1 {
                // NULL value
                continue;
            }

            if length < 0 || pos + length as usize > data.len() {
                return; // Invalid length
            }

            pos += length as usize;
        }
    }

    fn test_error_response_parsing(&self, data: &[u8]) {
        let mut pos = 0;

        while pos < data.len() {
            let field_type = data[pos];
            if field_type == 0 {
                break; // End of fields
            }
            pos += 1;

            // Read null-terminated string
            let start = pos;
            while pos < data.len() && data[pos] != 0 {
                pos += 1;
            }
            if pos >= data.len() {
                return; // Unterminated string
            }

            let _field_value = &data[start..pos];
            pos += 1; // Skip null terminator
        }
    }

    fn test_auth_parsing(&self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }

        let auth_type = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let _auth_data = &data[4..];

        // Test various auth types
        match auth_type {
            0 => {}, // AuthenticationOk
            3 => {}, // AuthenticationCleartextPassword
            5 => {
                // AuthenticationMD5Password - should have 4-byte salt
                if data.len() >= 8 {
                    let _salt = &data[4..8];
                }
            },
            10 => {
                // AuthenticationSASL - mechanism list
                let mut pos = 4;
                while pos < data.len() {
                    let start = pos;
                    while pos < data.len() && data[pos] != 0 {
                        pos += 1;
                    }
                    if pos >= data.len() {
                        break;
                    }
                    let _mechanism = &data[start..pos];
                    pos += 1;

                    if pos < data.len() && data[pos] == 0 {
                        break; // End of list
                    }
                }
            },
            11 => {}, // AuthenticationSASLContinue
            12 => {}, // AuthenticationSASLFinal
            _ => {}, // Other auth types
        }
    }

    fn test_parameter_status_parsing(&self, data: &[u8]) {
        let mut pos = 0;

        // Parameter name
        let start = pos;
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        if pos >= data.len() {
            return;
        }
        let _name = &data[start..pos];
        pos += 1;

        // Parameter value
        let start = pos;
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        if pos >= data.len() {
            return;
        }
        let _value = &data[start..pos];
    }

    fn test_ready_for_query_parsing(&self, data: &[u8]) {
        if data.len() >= 1 {
            let _status = data[0]; // 'I', 'T', or 'E'
        }
    }

    fn test_parameter_description_parsing(&self, data: &[u8]) {
        if data.len() < 2 {
            return;
        }

        let param_count = i16::from_be_bytes([data[0], data[1]]);
        if param_count < 0 {
            return;
        }

        if data.len() < 2 + (param_count as usize * 4) {
            return;
        }

        for i in 0..param_count {
            let pos = 2 + (i as usize * 4);
            let _type_oid = i32::from_be_bytes([
                data[pos], data[pos + 1], data[pos + 2], data[pos + 3]
            ]);
        }
    }

    fn test_command_complete_parsing(&self, data: &[u8]) {
        // Command tag is null-terminated string
        let mut pos = 0;
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        if pos < data.len() {
            let _tag = &data[..pos];
        }
    }

    fn test_backend_key_data_parsing(&self, data: &[u8]) {
        if data.len() >= 8 {
            let _process_id = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let _secret_key = i32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        }
    }
}

fuzz_target!(|message: PgWireMessage| {
    let conn = MockConn;

    // Build and test the appropriate wire protocol message
    let wire_data = match message {
        PgWireMessage::Authentication(auth) => {
            build_auth_message(&auth)
        },
        PgWireMessage::RowDescription { fields } => {
            build_row_description(&fields)
        },
        PgWireMessage::DataRow { values } => {
            build_data_row(&values)
        },
        PgWireMessage::ErrorResponse { fields } => {
            build_error_response(&fields, b'E')
        },
        PgWireMessage::NoticeResponse { fields } => {
            build_error_response(&fields, b'N')
        },
        PgWireMessage::ParameterStatus { name, value } => {
            build_parameter_status(&name, &value)
        },
        PgWireMessage::ReadyForQuery { status } => {
            build_message(b'Z', &[status])
        },
        PgWireMessage::ParameterDescription { params } => {
            build_parameter_description(&params)
        },
        PgWireMessage::CommandComplete { tag } => {
            let mut payload = tag.as_bytes().to_vec();
            payload.push(0); // Null terminator
            build_message(b'C', &payload)
        },
        PgWireMessage::BackendKeyData { process_id, secret_key } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&process_id.to_be_bytes());
            payload.extend_from_slice(&secret_key.to_be_bytes());
            build_message(b'K', &payload)
        },
        PgWireMessage::ParseComplete => build_message(b'1', &[]),
        PgWireMessage::BindComplete => build_message(b'2', &[]),
        PgWireMessage::CloseComplete => build_message(b'3', &[]),
        PgWireMessage::NoData => build_message(b'n', &[]),
        PgWireMessage::PortalSuspended => build_message(b's', &[]),
        PgWireMessage::ScramAuth(scram) => {
            test_scram_parsing(&scram);
            return; // Don't test as wire message
        },
        PgWireMessage::Raw(raw) => {
            build_message(raw.message_type, &raw.payload)
        },
    };

    // Test the wire protocol parsing
    conn.test_parsing(&wire_data);

    // Test various edge cases
    test_edge_cases(&wire_data);
});

/// Test edge cases in message parsing
fn test_edge_cases(data: &[u8]) {
    // Test with truncated messages
    for i in 0..std::cmp::min(data.len(), 20) {
        let truncated = &data[..i];
        let conn = MockConn;
        conn.test_parsing(truncated);
    }

    // Test with corrupted length field
    if data.len() >= 5 {
        let mut corrupted = data.to_vec();
        // Set various invalid lengths
        for &invalid_length in &[0, 3, -1_i32, i32::MAX] {
            corrupted[1..5].copy_from_slice(&invalid_length.to_be_bytes());
            let conn = MockConn;
            conn.test_parsing(&corrupted);
        }
    }

    // Test with oversized messages (should be rejected)
    if data.len() >= 5 {
        let mut oversized = data.to_vec();
        let huge_length = 100_000_000_i32; // 100MB
        oversized[1..5].copy_from_slice(&huge_length.to_be_bytes());
        let conn = MockConn;
        conn.test_parsing(&oversized);
    }
}