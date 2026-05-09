#![no_main]

//! Structure-aware fuzz target for MySQL row packet decoding.
//!
//! This target exercises both text and binary row parsing with intelligent
//! input generation to find edge cases in MySQL protocol row decoding logic.
//!
//! Row formats tested:
//! - Text protocol rows (ResultSet)
//! - Binary protocol rows (Prepared statements)
//! - NULL value handling
//! - Various MySQL column types
//! - Malformed packets and boundary conditions
//!
//! Usage: cargo fuzz run mysql_row_decoder

use arbitrary::{Arbitrary, Unstructured};
use asupersync::database::mysql::{
    MySqlColumn, MySqlError, MySqlValue, fuzz_parse_binary_row, fuzz_parse_data_row_or_terminator,
    fuzz_parse_text_row,
};
use libfuzzer_sys::fuzz_target;

/// Maximum size for row packet payload (reasonable upper bound)
const MAX_ROW_SIZE: usize = 8192;
/// Maximum number of columns in a row (MySQL limit is 4096)
const MAX_COLUMNS: usize = 64;

/// Structure-aware generator for MySQL row packets
#[derive(Arbitrary, Debug, Clone)]
struct RowPacketScenario {
    /// The row type and format to generate
    row_type: RowType,
    /// Column definitions for the row
    columns: Vec<TestColumn>,
    /// Fuzzing parameters for edge cases
    params: FuzzParams,
}

/// Row type variants for structure-aware generation
#[derive(Arbitrary, Debug, Clone)]
enum RowType {
    /// Text protocol row (standard query results)
    Text(TextRowData),
    /// Binary protocol row (prepared statement results)
    Binary(BinaryRowData),
    /// Data row that might be a terminator
    DataOrTerminator { deprecate_eof: bool },
    /// Malformed rows for edge case testing
    Malformed(MalformedRow),
}

/// Text protocol row data
#[derive(Arbitrary, Debug, Clone)]
struct TextRowData {
    /// Values for each column
    values: Vec<TextValue>,
}

/// Binary protocol row data
#[derive(Arbitrary, Debug, Clone)]
struct BinaryRowData {
    /// Values for each column
    values: Vec<BinaryValue>,
    /// Custom NULL bitmap manipulation
    null_bitmap_override: Option<Vec<u8>>,
}

/// Test column definition
#[derive(Arbitrary, Debug, Clone)]
struct TestColumn {
    /// Column name
    name: String,
    /// MySQL column type
    column_type: MySqlColumnType,
    /// Additional column properties
    charset: u16,
    length: u32,
    flags: u16,
    decimals: u8,
}

/// MySQL column types for testing
#[derive(Arbitrary, Debug, Clone)]
enum MySqlColumnType {
    Tiny,
    Short,
    Long,
    LongLong,
    Float,
    Double,
    VarChar,
    Blob,
    DateTime,
    Time,
    Date,
    Year,
}

/// Text protocol values
#[derive(Arbitrary, Debug, Clone)]
enum TextValue {
    Null,
    String(Vec<u8>),
    Integer(i64),
    Float(f64),
}

/// Binary protocol values
#[derive(Arbitrary, Debug, Clone)]
enum BinaryValue {
    Null,
    Tiny(i8),
    Short(i16),
    Long(i32),
    LongLong(i64),
    Float(f32),
    Double(f64),
    String(Vec<u8>),
    DateTime {
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        microsec: u32,
    },
    Time {
        sign: u8,
        days: u32,
        hour: u8,
        minute: u8,
        second: u8,
        microsec: u32,
    },
}

/// Parameters for fuzzing edge cases
#[derive(Arbitrary, Debug, Clone)]
struct FuzzParams {
    /// Add leading junk bytes
    leading_junk: Vec<u8>,
    /// Add trailing garbage
    trailing_junk: Vec<u8>,
    /// Corrupt length-encoded values
    corrupt_lenenc: bool,
    /// Force specific NULL patterns
    force_null_pattern: Option<u8>,
    /// Truncate packet at specific position
    truncate_at: Option<u16>,
}

/// Malformed row variants for boundary testing
#[derive(Arbitrary, Debug, Clone)]
enum MalformedRow {
    /// Empty row
    Empty,
    /// Binary row without proper header
    NoBinaryHeader,
    /// Binary row with invalid null bitmap
    BadNullBitmap(Vec<u8>),
    /// Text row with invalid length encoding
    BadLenencoding(Vec<u8>),
    /// Row with too many/few values for columns
    ValueCountMismatch(Vec<u8>),
    /// Binary garbage
    BinaryGarbage(Vec<u8>),
}

impl RowPacketScenario {
    /// Generate the raw bytes for this row packet
    fn materialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Add leading junk if specified
        result.extend_from_slice(&self.params.leading_junk);

        // Generate the base packet based on type
        let base_packet = match &self.row_type {
            RowType::Text(data) => self.materialize_text_row(data),
            RowType::Binary(data) => self.materialize_binary_row(data),
            RowType::DataOrTerminator { .. } => {
                self.materialize_text_row(&TextRowData { values: Vec::new() })
            }
            RowType::Malformed(malformed) => self.materialize_malformed_row(malformed),
        };

        result.extend_from_slice(&base_packet);

        // Apply corruptions
        if self.params.corrupt_lenenc {
            self.corrupt_length_encoding(&mut result);
        }

        // Add trailing junk if specified
        result.extend_from_slice(&self.params.trailing_junk);

        // Apply truncation if specified
        if let Some(truncate_pos) = self.params.truncate_at {
            result.truncate(truncate_pos as usize);
        }

        // Ensure reasonable size limit
        result.truncate(MAX_ROW_SIZE);

        result
    }

    /// Generate MySQL text protocol row bytes
    fn materialize_text_row(&self, data: &TextRowData) -> Vec<u8> {
        let mut result = Vec::new();

        for (i, value) in data.values.iter().enumerate() {
            if i >= self.columns.len() {
                break; // More values than columns - truncate
            }

            match value {
                TextValue::Null => {
                    result.push(0xFB); // NULL marker
                }
                TextValue::String(bytes) => {
                    self.write_lenenc_int(&mut result, bytes.len() as u64);
                    result.extend_from_slice(bytes);
                }
                TextValue::Integer(val) => {
                    let s = val.to_string();
                    let bytes = s.as_bytes();
                    self.write_lenenc_int(&mut result, bytes.len() as u64);
                    result.extend_from_slice(bytes);
                }
                TextValue::Float(val) => {
                    let s = val.to_string();
                    let bytes = s.as_bytes();
                    self.write_lenenc_int(&mut result, bytes.len() as u64);
                    result.extend_from_slice(bytes);
                }
            }
        }

        result
    }

    /// Generate MySQL binary protocol row bytes
    fn materialize_binary_row(&self, data: &BinaryRowData) -> Vec<u8> {
        let mut result = Vec::new();

        // Binary row header (0x00)
        result.push(0x00);

        // NULL bitmap
        let null_bitmap_len = (self.columns.len() + 7 + 2) / 8;
        let mut null_bitmap = if let Some(ref custom) = data.null_bitmap_override {
            custom.clone()
        } else {
            let mut bitmap = vec![0u8; null_bitmap_len];

            // Set NULL bits based on values
            for (i, value) in data.values.iter().enumerate() {
                if matches!(value, BinaryValue::Null) {
                    let bit_idx = i + 2;
                    bitmap[bit_idx / 8] |= 1 << (bit_idx % 8);
                }
            }

            bitmap
        };

        // Apply force null pattern if specified
        if let Some(pattern) = self.params.force_null_pattern {
            for byte in &mut null_bitmap {
                *byte = pattern;
            }
        }

        null_bitmap.truncate(null_bitmap_len);
        null_bitmap.resize(null_bitmap_len, 0);
        result.extend_from_slice(&null_bitmap);

        // Binary values (non-NULL only)
        for (i, value) in data.values.iter().enumerate() {
            if i >= self.columns.len() {
                break;
            }

            if matches!(value, BinaryValue::Null) {
                continue; // NULL values not encoded in data section
            }

            match value {
                BinaryValue::Tiny(val) => result.extend_from_slice(&val.to_le_bytes()),
                BinaryValue::Short(val) => result.extend_from_slice(&val.to_le_bytes()),
                BinaryValue::Long(val) => result.extend_from_slice(&val.to_le_bytes()),
                BinaryValue::LongLong(val) => result.extend_from_slice(&val.to_le_bytes()),
                BinaryValue::Float(val) => result.extend_from_slice(&val.to_le_bytes()),
                BinaryValue::Double(val) => result.extend_from_slice(&val.to_le_bytes()),
                BinaryValue::String(bytes) => {
                    self.write_lenenc_int(&mut result, bytes.len() as u64);
                    result.extend_from_slice(bytes);
                }
                BinaryValue::DateTime {
                    year,
                    month,
                    day,
                    hour,
                    minute,
                    second,
                    microsec,
                } => {
                    if *year == 0
                        && *month == 0
                        && *day == 0
                        && *hour == 0
                        && *minute == 0
                        && *second == 0
                        && *microsec == 0
                    {
                        result.push(0); // All-zero datetime has 0-byte encoding
                    } else if *hour == 0 && *minute == 0 && *second == 0 && *microsec == 0 {
                        result.push(4); // Date only
                        result.extend_from_slice(&year.to_le_bytes());
                        result.push(*month);
                        result.push(*day);
                    } else if *microsec == 0 {
                        result.push(7); // Without microseconds
                        result.extend_from_slice(&year.to_le_bytes());
                        result.push(*month);
                        result.push(*day);
                        result.push(*hour);
                        result.push(*minute);
                        result.push(*second);
                    } else {
                        result.push(11); // With microseconds
                        result.extend_from_slice(&year.to_le_bytes());
                        result.push(*month);
                        result.push(*day);
                        result.push(*hour);
                        result.push(*minute);
                        result.push(*second);
                        result.extend_from_slice(&microsec.to_le_bytes());
                    }
                }
                BinaryValue::Time {
                    sign,
                    days,
                    hour,
                    minute,
                    second,
                    microsec,
                } => {
                    if *days == 0 && *hour == 0 && *minute == 0 && *second == 0 && *microsec == 0 {
                        result.push(0); // Zero time
                    } else if *microsec == 0 {
                        result.push(8); // Without microseconds
                        result.push(*sign);
                        result.extend_from_slice(&days.to_le_bytes());
                        result.push(*hour);
                        result.push(*minute);
                        result.push(*second);
                    } else {
                        result.push(12); // With microseconds
                        result.push(*sign);
                        result.extend_from_slice(&days.to_le_bytes());
                        result.push(*hour);
                        result.push(*minute);
                        result.push(*second);
                        result.extend_from_slice(&microsec.to_le_bytes());
                    }
                }
                BinaryValue::Null => unreachable!(), // Handled above
            }
        }

        result
    }

    /// Generate malformed row bytes for boundary testing
    fn materialize_malformed_row(&self, malformed: &MalformedRow) -> Vec<u8> {
        match malformed {
            MalformedRow::Empty => Vec::new(),
            MalformedRow::NoBinaryHeader => {
                let mut result = Vec::new();
                result.push(0x01); // Wrong header
                result.extend_from_slice(&vec![0; 10]); // Some data
                result
            }
            MalformedRow::BadNullBitmap(bitmap) => {
                let mut result = Vec::new();
                result.push(0x00); // Binary row header
                result.extend_from_slice(bitmap);
                result
            }
            MalformedRow::BadLenencoding(data) => data.clone(),
            MalformedRow::ValueCountMismatch(data) => data.clone(),
            MalformedRow::BinaryGarbage(data) => data.clone(),
        }
    }

    /// Write a length-encoded integer
    fn write_lenenc_int(&self, buf: &mut Vec<u8>, value: u64) {
        if value < 251 {
            buf.push(value as u8);
        } else if value < 65536 {
            buf.push(0xFC);
            buf.extend_from_slice(&(value as u16).to_le_bytes());
        } else if value < 16777216 {
            buf.push(0xFD);
            buf.extend_from_slice(&(value as u32).to_le_bytes()[..3]);
        } else {
            buf.push(0xFE);
            buf.extend_from_slice(&value.to_le_bytes());
        }
    }

    /// Corrupt length encodings in the buffer
    fn corrupt_length_encoding(&self, buf: &mut Vec<u8>) {
        for byte in buf.iter_mut() {
            if *byte == 0xFC || *byte == 0xFD || *byte == 0xFE {
                *byte = 0xFF; // Invalid length encoding prefix
                break;
            }
        }
    }

    /// Convert to MySqlColumn for testing
    fn to_mysql_columns(&self) -> Vec<MySqlColumn> {
        self.columns
            .iter()
            .take(MAX_COLUMNS)
            .map(|col| MySqlColumn {
                catalog: "def".to_string(),
                schema: "test".to_string(),
                table: "test_table".to_string(),
                org_table: "test_table".to_string(),
                name: col.name.clone(),
                org_name: col.name.clone(),
                charset: col.charset,
                length: col.length,
                column_type: match col.column_type {
                    MySqlColumnType::Tiny => 1,
                    MySqlColumnType::Short => 2,
                    MySqlColumnType::Long => 3,
                    MySqlColumnType::LongLong => 8,
                    MySqlColumnType::Float => 4,
                    MySqlColumnType::Double => 5,
                    MySqlColumnType::VarChar => 15,
                    MySqlColumnType::Blob => 252,
                    MySqlColumnType::DateTime => 12,
                    MySqlColumnType::Time => 11,
                    MySqlColumnType::Date => 10,
                    MySqlColumnType::Year => 13,
                },
                flags: col.flags,
                decimals: col.decimals,
            })
            .collect()
    }
}

fn observe_row_parse(
    result: Result<Vec<MySqlValue>, MySqlError>,
    columns: &[MySqlColumn],
    context: &str,
) {
    match result {
        Ok(values) => {
            assert_eq!(
                values.len(),
                columns.len(),
                "{context} returned {} values for {} columns",
                values.len(),
                columns.len()
            );
        }
        Err(err) => observe_mysql_error(&err, context),
    }
}

fn observe_data_row_or_terminator(
    result: Result<Option<Vec<MySqlValue>>, MySqlError>,
    columns: &[MySqlColumn],
    context: &str,
) {
    match result {
        Ok(Some(values)) => {
            assert_eq!(
                values.len(),
                columns.len(),
                "{context} returned {} values for {} columns",
                values.len(),
                columns.len()
            );
        }
        Ok(None) => {}
        Err(err) => observe_mysql_error(&err, context),
    }
}

fn observe_mysql_error(err: &MySqlError, context: &str) {
    let diagnostic = format!("{err:?}");
    assert!(
        !diagnostic.is_empty(),
        "{context} parser error must be observable"
    );
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent excessive memory usage
    if data.len() > MAX_ROW_SIZE {
        return;
    }

    // Test 1: Direct raw bytes fuzzing (classic approach)
    let columns = create_test_columns();

    // Test text row parsing
    observe_row_parse(
        fuzz_parse_text_row(data, &columns),
        &columns,
        "raw text row",
    );

    // Test binary row parsing
    observe_row_parse(
        fuzz_parse_binary_row(data, &columns),
        &columns,
        "raw binary row",
    );

    // Test data row or terminator parsing
    observe_data_row_or_terminator(
        fuzz_parse_data_row_or_terminator(data, &columns, true),
        &columns,
        "raw data row or terminator with deprecated EOF",
    );
    observe_data_row_or_terminator(
        fuzz_parse_data_row_or_terminator(data, &columns, false),
        &columns,
        "raw data row or terminator",
    );

    // Test 2: Structure-aware fuzzing if we can parse the input
    let mut u = Unstructured::new(data);
    if let Ok(mut scenario) = RowPacketScenario::arbitrary(&mut u) {
        // Limit the number of columns to prevent resource exhaustion
        scenario.columns.truncate(MAX_COLUMNS);

        // Skip empty column sets for meaningful testing
        if scenario.columns.is_empty() {
            return;
        }

        let generated_bytes = scenario.materialize();

        // Don't fuzz empty packets (not interesting)
        if generated_bytes.is_empty() {
            return;
        }

        let mysql_columns = scenario.to_mysql_columns();

        // Test the generated packet with all parsers
        match scenario.row_type {
            RowType::Text(_) => {
                let result = fuzz_parse_text_row(&generated_bytes, &mysql_columns);

                // For well-formed text rows, verify basic structure
                if scenario.params.leading_junk.is_empty()
                    && scenario.params.trailing_junk.is_empty()
                    && !scenario.params.corrupt_lenenc
                    && scenario.params.truncate_at.is_none()
                {
                    if let Ok(values) = &result {
                        assert_eq!(
                            values.len(),
                            mysql_columns.len(),
                            "Text row value count mismatch: got {}, expected {}",
                            values.len(),
                            mysql_columns.len()
                        );
                    }
                }
                observe_row_parse(result, &mysql_columns, "generated text row");
            }
            RowType::Binary(_) => {
                let result = fuzz_parse_binary_row(&generated_bytes, &mysql_columns);

                // For well-formed binary rows, verify basic structure
                if scenario.params.leading_junk.is_empty()
                    && scenario.params.trailing_junk.is_empty()
                    && scenario.params.force_null_pattern.is_none()
                    && scenario.params.truncate_at.is_none()
                {
                    if let Ok(values) = &result {
                        assert_eq!(
                            values.len(),
                            mysql_columns.len(),
                            "Binary row value count mismatch: got {}, expected {}",
                            values.len(),
                            mysql_columns.len()
                        );
                    }
                }
                observe_row_parse(result, &mysql_columns, "generated binary row");
            }
            RowType::DataOrTerminator { deprecate_eof } => {
                observe_data_row_or_terminator(
                    fuzz_parse_data_row_or_terminator(
                        &generated_bytes,
                        &mysql_columns,
                        deprecate_eof,
                    ),
                    &mysql_columns,
                    "generated data row or terminator",
                );
            }
            RowType::Malformed(_) => {
                // Malformed data should be handled gracefully (not crash)
                observe_row_parse(
                    fuzz_parse_text_row(&generated_bytes, &mysql_columns),
                    &mysql_columns,
                    "malformed text row",
                );
                observe_row_parse(
                    fuzz_parse_binary_row(&generated_bytes, &mysql_columns),
                    &mysql_columns,
                    "malformed binary row",
                );
            }
        }
    }

    // Test 3: Boundary condition fuzzing
    fuzz_boundary_conditions(data);
});

/// Create a set of test columns for fuzzing
fn create_test_columns() -> Vec<MySqlColumn> {
    vec![
        MySqlColumn {
            catalog: "def".to_string(),
            schema: "test".to_string(),
            table: "test_table".to_string(),
            org_table: "test_table".to_string(),
            name: "id".to_string(),
            org_name: "id".to_string(),
            charset: 33, // utf8_general_ci
            length: 11,
            column_type: 3, // LONG
            flags: 515,     // NOT_NULL | PRI_KEY | AUTO_INCREMENT
            decimals: 0,
        },
        MySqlColumn {
            catalog: "def".to_string(),
            schema: "test".to_string(),
            table: "test_table".to_string(),
            org_table: "test_table".to_string(),
            name: "name".to_string(),
            org_name: "name".to_string(),
            charset: 33, // utf8_general_ci
            length: 255,
            column_type: 15, // VARCHAR
            flags: 0,
            decimals: 0,
        },
        MySqlColumn {
            catalog: "def".to_string(),
            schema: "test".to_string(),
            table: "test_table".to_string(),
            org_table: "test_table".to_string(),
            name: "score".to_string(),
            org_name: "score".to_string(),
            charset: 63, // binary
            length: 12,
            column_type: 5, // DOUBLE
            flags: 0,
            decimals: 2,
        },
    ]
}

/// Test specific boundary conditions and edge cases
fn fuzz_boundary_conditions(data: &[u8]) {
    let columns = create_test_columns();

    // Test very short inputs
    if data.len() <= 16 {
        observe_row_parse(
            fuzz_parse_text_row(data, &columns),
            &columns,
            "short text row",
        );
        observe_row_parse(
            fuzz_parse_binary_row(data, &columns),
            &columns,
            "short binary row",
        );
    }

    // Test inputs that start with specific bytes
    if !data.is_empty() {
        match data[0] {
            0x00 => {
                // Potential binary row
                observe_row_parse(
                    fuzz_parse_binary_row(data, &columns),
                    &columns,
                    "0x00 binary row",
                );
            }
            0xFB => {
                // NULL marker in text protocol
                observe_row_parse(
                    fuzz_parse_text_row(data, &columns),
                    &columns,
                    "0xfb text row",
                );
            }
            0xFC | 0xFD | 0xFE => {
                // Length encoding prefixes
                observe_row_parse(
                    fuzz_parse_text_row(data, &columns),
                    &columns,
                    "length-encoded text row",
                );
            }
            0xFF => {
                // Often indicates error packet or invalid state
                observe_data_row_or_terminator(
                    fuzz_parse_data_row_or_terminator(data, &columns, false),
                    &columns,
                    "0xff data row or terminator",
                );
            }
            _ => {
                // Regular data
                observe_row_parse(
                    fuzz_parse_text_row(data, &columns),
                    &columns,
                    "regular text row",
                );
            }
        }
    }

    // Test with different column configurations
    if data.len() > 4 {
        // Single column
        let single_col = vec![columns[0].clone()];
        observe_row_parse(
            fuzz_parse_text_row(data, &single_col),
            &single_col,
            "single-column text row",
        );
        observe_row_parse(
            fuzz_parse_binary_row(data, &single_col),
            &single_col,
            "single-column binary row",
        );

        // Many columns
        let many_cols: Vec<MySqlColumn> = (0..10)
            .map(|i| {
                let mut col = columns[i % columns.len()].clone();
                col.name = format!("col_{}", i);
                col
            })
            .collect();
        observe_row_parse(
            fuzz_parse_text_row(data, &many_cols),
            &many_cols,
            "many-column text row",
        );
        observe_row_parse(
            fuzz_parse_binary_row(data, &many_cols),
            &many_cols,
            "many-column binary row",
        );
    }
}
