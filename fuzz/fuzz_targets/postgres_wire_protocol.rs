#![no_main]

use libfuzzer_sys::fuzz_target;

/// PostgreSQL protocol message reader
struct MessageReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MessageReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_i16(&mut self) -> Result<i16, String> {
        if self.pos + 2 > self.data.len() {
            return Err("Not enough data for i16".to_string());
        }
        let val = i16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    fn read_i32(&mut self) -> Result<i32, String> {
        if self.pos + 4 > self.data.len() {
            return Err("Not enough data for i32".to_string());
        }
        let val = i32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.data.len() {
            return Err("Not enough data for u32".to_string());
        }
        let val = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    fn read_cstring(&mut self) -> Result<String, String> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return Err("Unterminated C string".to_string());
        }
        let s = String::from_utf8_lossy(&self.data[start..self.pos]).to_string();
        self.pos += 1; // Skip null terminator
        Ok(s)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.pos + len > self.data.len() {
            return Err("Not enough data for bytes".to_string());
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }
}

#[derive(Debug)]
struct PgColumn {
    name: String,
    table_oid: u32,
    column_attr: i16,
    type_oid: u32,
    type_size: i16,
    type_modifier: i32,
    format_code: i16,
}

/// Parse PostgreSQL RowDescription message (message type 'T')
fn parse_row_description(data: &[u8]) -> Result<Vec<PgColumn>, String> {
    let mut reader = MessageReader::new(data);
    let num_fields = reader.read_i16()?;

    if num_fields < 0 {
        return Err("Negative field count".to_string());
    }

    if num_fields > 10000 {
        return Err("Too many fields".to_string());
    }

    let mut columns = Vec::with_capacity(num_fields as usize);

    for _ in 0..num_fields {
        let name = reader.read_cstring()?;
        let table_oid = reader.read_u32()?;
        let column_attr = reader.read_i16()?;
        let type_oid = reader.read_u32()?;
        let type_size = reader.read_i16()?;
        let type_modifier = reader.read_i32()?;
        let format_code = reader.read_i16()?;

        columns.push(PgColumn {
            name,
            table_oid,
            column_attr,
            type_oid,
            type_size,
            type_modifier,
            format_code,
        });
    }

    Ok(columns)
}

/// Parse PostgreSQL DataRow message (message type 'D')
fn parse_data_row(data: &[u8]) -> Result<Vec<Option<Vec<u8>>>, String> {
    let mut reader = MessageReader::new(data);
    let num_values = reader.read_i16()?;

    if num_values < 0 {
        return Err("Negative value count".to_string());
    }

    if num_values > 10000 {
        return Err("Too many values".to_string());
    }

    let mut values = Vec::with_capacity(num_values as usize);

    for _ in 0..num_values {
        let len = reader.read_i32()?;
        if len == -1 {
            values.push(None); // NULL value
        } else if len < 0 {
            return Err("Invalid value length".to_string());
        } else if len > 1_000_000 {
            return Err("Value too large".to_string());
        } else {
            let value_data = reader.read_bytes(len as usize)?.to_vec();
            values.push(Some(value_data));
        }
    }

    Ok(values)
}

/// Parse PostgreSQL ErrorResponse message (message type 'E')
fn parse_error_response(data: &[u8]) -> Result<(String, String), String> {
    let mut reader = MessageReader::new(data);
    let mut code = String::new();
    let mut message = String::new();

    while reader.pos < data.len() {
        let field_type = if reader.pos < data.len() {
            data[reader.pos]
        } else {
            break;
        };

        if field_type == 0 {
            break; // End of fields
        }

        reader.pos += 1;
        let field_value = reader.read_cstring()?;

        match field_type {
            b'C' => code = field_value, // Error code
            b'M' => message = field_value, // Message
            _ => {}, // Ignore other fields
        }
    }

    Ok((code, message))
}

/// Parse PostgreSQL ParameterDescription message (message type 't')
fn parse_parameter_description(data: &[u8]) -> Result<Vec<u32>, String> {
    let mut reader = MessageReader::new(data);
    let num_params = reader.read_i16()?;

    if num_params < 0 {
        return Err("Negative parameter count".to_string());
    }

    if num_params > 1000 {
        return Err("Too many parameters".to_string());
    }

    let mut oids = Vec::with_capacity(num_params as usize);
    for _ in 0..num_params {
        oids.push(reader.read_u32()?);
    }

    Ok(oids)
}

/// Parse text value for specific PostgreSQL type
fn parse_text_value(data: &[u8], type_oid: u32) -> Result<String, String> {
    let s = std::str::from_utf8(data)
        .map_err(|_| "Invalid UTF-8".to_string())?;

    // Simulate type-specific parsing
    match type_oid {
        16 => {
            // BOOL
            match s {
                "t" | "true" | "y" | "yes" | "on" | "1" => Ok("true".to_string()),
                "f" | "false" | "n" | "no" | "off" | "0" => Ok("false".to_string()),
                _ => Err("Invalid boolean".to_string()),
            }
        },
        21 => {
            // INT2
            s.parse::<i16>().map(|_| s.to_string()).map_err(|_| "Invalid i16".to_string())
        },
        23 => {
            // INT4
            s.parse::<i32>().map(|_| s.to_string()).map_err(|_| "Invalid i32".to_string())
        },
        20 => {
            // INT8
            s.parse::<i64>().map(|_| s.to_string()).map_err(|_| "Invalid i64".to_string())
        },
        700 => {
            // FLOAT4
            s.parse::<f32>().map(|_| s.to_string()).map_err(|_| "Invalid f32".to_string())
        },
        701 => {
            // FLOAT8
            s.parse::<f64>().map(|_| s.to_string()).map_err(|_| "Invalid f64".to_string())
        },
        17 => {
            // BYTEA (hex format)
            if s.starts_with("\\x") {
                hex_decode(&s[2..]).map(|_| s.to_string())
            } else {
                Ok(s.to_string()) // Raw format fallback
            }
        },
        _ => Ok(s.to_string()), // Default: return as text
    }
}

/// Simple hex decoder
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Odd length hex string".to_string());
    }

    let mut result = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hex_str = std::str::from_utf8(chunk).map_err(|_| "Invalid hex".to_string())?;
        let byte = u8::from_str_radix(hex_str, 16).map_err(|_| "Invalid hex digit".to_string())?;
        result.push(byte);
    }

    Ok(result)
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs
    if data.len() > 100_000 {
        return;
    }

    // Test 1: Parse as RowDescription message
    let _ = parse_row_description(data);

    // Test 2: Parse as DataRow message
    let _ = parse_data_row(data);

    // Test 3: Parse as ErrorResponse message
    let _ = parse_error_response(data);

    // Test 4: Parse as ParameterDescription message
    let _ = parse_parameter_description(data);

    // Test 5: Parse as text values for different PostgreSQL types
    for type_oid in [16, 21, 23, 20, 700, 701, 17, 25, 1043] {
        let _ = parse_text_value(data, type_oid);
    }

    // Test 6: Hex decoding (for BYTEA type)
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = hex_decode(s);
    }

    // Test 7: Test message reader operations directly
    let mut reader = MessageReader::new(data);
    let _ = reader.read_i16();
    let _ = reader.read_i32();
    let _ = reader.read_u32();
    let _ = reader.read_cstring();
});