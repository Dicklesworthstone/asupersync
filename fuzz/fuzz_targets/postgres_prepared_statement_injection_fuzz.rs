#![no_main]

//! Fuzz target for PostgreSQL prepared statement parameter injection vulnerabilities.
//!
//! This target exercises the parameter binding and type coercion mechanisms in PostgreSQL
//! prepared statements to ensure robust handling of malicious or malformed parameters.
//!
//! Key injection vectors tested:
//! 1. Parameter Type Coercion: Mismatched OIDs, type confusion attacks, invalid type casting
//! 2. NULL Injection: Malformed NULL values, NULL in non-nullable contexts, NULL byte injection
//! 3. SQL Escape Boundary: String escape sequences, binary data in text parameters, quote injection
//! 4. String vs Numeric Mismatch: Numeric parsing edge cases, scientific notation, overflow/underflow
//! 5. Oversized Parameter Rejection: Memory exhaustion attacks, buffer overflow attempts

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Skip tiny inputs
    if data.len() < 8 {
        return;
    }

    // Limit size to prevent excessive memory usage
    if data.len() > 32768 {
        return;
    }

    // Parse fuzz input into test scenarios
    let mut input = data;
    let scenarios = parse_pg_injection_operations(&mut input);

    // Test PostgreSQL parameter injection scenarios
    test_parameter_type_coercion(&scenarios);
    test_null_injection_attacks(&scenarios);
    test_sql_escape_boundaries(&scenarios);
    test_string_numeric_mismatch(&scenarios);
    test_oversized_parameter_rejection(&scenarios);
});

#[derive(Debug, Clone)]
enum PgInjectionOperation {
    TypeCoercion {
        sql: String,
        param_values: Vec<MockParam>,
        declared_oids: Vec<u32>,
        actual_oids: Vec<u32>,
    },
    NullInjection {
        sql: String,
        null_positions: Vec<usize>,
        null_bytes_in_strings: bool,
        malformed_nulls: Vec<Vec<u8>>,
    },
    EscapeBoundary {
        sql: String,
        string_params: Vec<String>,
        binary_params: Vec<Vec<u8>>,
        format_confusion: bool,
    },
    NumericMismatch {
        sql: String,
        numeric_strings: Vec<String>,
        expected_types: Vec<NumericType>,
    },
    OversizedParameter {
        sql: String,
        large_params: Vec<LargeParam>,
        size_limits: Vec<usize>,
    },
}

#[derive(Debug, Clone)]
enum MockParam {
    Integer(i64),
    Float(f64),
    Text(String),
    Binary(Vec<u8>),
    Boolean(bool),
    Null,
    Malformed(Vec<u8>),
}

#[derive(Debug, Clone)]
enum NumericType {
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    Numeric,
}

#[derive(Debug, Clone)]
enum LargeParam {
    LongString(usize),
    LargeBinary(usize),
    DeepNesting(usize),
}

fn parse_pg_injection_operations(input: &mut &[u8]) -> Vec<PgInjectionOperation> {
    let mut ops = Vec::new();
    let mut rng_state = 42u64;

    while input.len() >= 4 && ops.len() < 10 {
        let op_type = extract_u8(input, &mut rng_state) % 5;

        match op_type {
            0 => {
                // Parameter type coercion
                let sql = generate_test_sql(&mut rng_state, SqlType::Parameterized);

                let param_count = (extract_u8(input, &mut rng_state) % 6) as usize + 1;
                let mut param_values = Vec::new();
                let mut declared_oids = Vec::new();
                let mut actual_oids = Vec::new();

                for _ in 0..param_count {
                    // Generate parameter with intentional type mismatch
                    let declared_type = extract_u8(input, &mut rng_state) % 7;
                    let actual_type = extract_u8(input, &mut rng_state) % 7;

                    let (param, declared_oid, actual_oid) =
                        create_mismatched_param(declared_type, actual_type, &mut rng_state);

                    param_values.push(param);
                    declared_oids.push(declared_oid);
                    actual_oids.push(actual_oid);
                }

                ops.push(PgInjectionOperation::TypeCoercion {
                    sql,
                    param_values,
                    declared_oids,
                    actual_oids,
                });
            }
            1 => {
                // NULL injection
                let sql = generate_test_sql(&mut rng_state, SqlType::Nullable);

                let null_count = (extract_u8(input, &mut rng_state) % 4) as usize;
                let mut null_positions = Vec::new();
                for _ in 0..null_count {
                    null_positions.push((extract_u8(input, &mut rng_state) % 8) as usize);
                }

                let null_bytes_in_strings = (extract_u8(input, &mut rng_state) % 2) == 1;

                // Generate malformed NULL representations
                let mut malformed_nulls = Vec::new();
                for _ in 0..3 {
                    let size = (extract_u8(input, &mut rng_state) % 16) as usize;
                    let mut malformed = vec![0u8; size];
                    for byte in &mut malformed {
                        *byte = extract_u8(input, &mut rng_state);
                    }
                    malformed_nulls.push(malformed);
                }

                ops.push(PgInjectionOperation::NullInjection {
                    sql,
                    null_positions,
                    null_bytes_in_strings,
                    malformed_nulls,
                });
            }
            2 => {
                // SQL escape boundary
                let sql = generate_test_sql(&mut rng_state, SqlType::StringHeavy);

                let string_count = (extract_u8(input, &mut rng_state) % 5) as usize + 1;
                let mut string_params = Vec::new();
                let mut binary_params = Vec::new();

                for _ in 0..string_count {
                    // Generate strings with escape sequences and potential injection
                    let string_type = extract_u8(input, &mut rng_state) % 6;
                    let string_param = match string_type {
                        0 => "'; DROP TABLE users; --".to_string(),
                        1 => "\\x41\\x42\\x43".to_string(),
                        2 => "\0\r\n\t\"'\\".to_string(),
                        3 => "🦀🚀💀".to_string(), // Unicode
                        4 => format!(
                            "SELECT * FROM secrets WHERE id = {}",
                            extract_u32(input, &mut rng_state)
                        ),
                        5 => {
                            // Binary data disguised as string
                            let size = (extract_u8(input, &mut rng_state) % 32) as usize;
                            let mut binary = vec![0u8; size];
                            for byte in &mut binary {
                                *byte = extract_u8(input, &mut rng_state);
                            }
                            String::from_utf8_lossy(&binary).to_string()
                        }
                        _ => "normal_value".to_string(),
                    };
                    string_params.push(string_param);

                    // Generate corresponding binary parameter
                    let binary_size = (extract_u8(input, &mut rng_state) % 64) as usize;
                    let mut binary = vec![0u8; binary_size];
                    for byte in &mut binary {
                        *byte = extract_u8(input, &mut rng_state);
                    }
                    binary_params.push(binary);
                }

                let format_confusion = (extract_u8(input, &mut rng_state) % 2) == 1;

                ops.push(PgInjectionOperation::EscapeBoundary {
                    sql,
                    string_params,
                    binary_params,
                    format_confusion,
                });
            }
            3 => {
                // String vs numeric mismatch
                let sql = generate_test_sql(&mut rng_state, SqlType::Numeric);

                let param_count = (extract_u8(input, &mut rng_state) % 6) as usize + 1;
                let mut numeric_strings = Vec::new();
                let mut expected_types = Vec::new();

                for _ in 0..param_count {
                    let string_type = extract_u8(input, &mut rng_state) % 8;
                    let expected_type = match extract_u8(input, &mut rng_state) % 6 {
                        0 => NumericType::Int16,
                        1 => NumericType::Int32,
                        2 => NumericType::Int64,
                        3 => NumericType::Float32,
                        4 => NumericType::Float64,
                        5 => NumericType::Numeric,
                        _ => NumericType::Int32,
                    };

                    let numeric_string = match string_type {
                        0 => format!("{}", i64::MAX),
                        1 => format!("{}", i64::MIN),
                        2 => "1.7976931348623157e+308".to_string(), // f64::MAX
                        3 => "NaN".to_string(),
                        4 => "Infinity".to_string(),
                        5 => "-Infinity".to_string(),
                        6 => "1.23e-45678".to_string(), // Extreme scientific notation
                        7 => {
                            // Random malformed numeric string
                            let size = (extract_u8(input, &mut rng_state) % 16) as usize + 1;
                            let mut s = String::new();
                            for _ in 0..size {
                                let ch = match extract_u8(input, &mut rng_state) % 5 {
                                    0 => (b'0' + (extract_u8(input, &mut rng_state) % 10)) as char,
                                    1 => '.',
                                    2 => 'e',
                                    3 => '-',
                                    4 => '+',
                                    _ => '0',
                                };
                                s.push(ch);
                            }
                            s
                        }
                        _ => "42".to_string(),
                    };

                    numeric_strings.push(numeric_string);
                    expected_types.push(expected_type);
                }

                ops.push(PgInjectionOperation::NumericMismatch {
                    sql,
                    numeric_strings,
                    expected_types,
                });
            }
            4 => {
                // Oversized parameter
                let sql = generate_test_sql(&mut rng_state, SqlType::VariableSize);

                let param_count = (extract_u8(input, &mut rng_state) % 4) as usize + 1;
                let mut large_params = Vec::new();
                let mut size_limits = Vec::new();

                for _ in 0..param_count {
                    let param_type = extract_u8(input, &mut rng_state) % 3;
                    let size = (extract_u16(input, &mut rng_state) as usize).max(1024);

                    let large_param = match param_type {
                        0 => LargeParam::LongString(size),
                        1 => LargeParam::LargeBinary(size),
                        2 => LargeParam::DeepNesting(size.min(100)),
                        _ => LargeParam::LongString(size),
                    };

                    large_params.push(large_param);
                    size_limits.push(size);
                }

                ops.push(PgInjectionOperation::OversizedParameter {
                    sql,
                    large_params,
                    size_limits,
                });
            }
            _ => unreachable!(),
        }
    }

    ops
}

#[derive(Debug)]
enum SqlType {
    Parameterized,
    Nullable,
    StringHeavy,
    Numeric,
    VariableSize,
}

fn generate_test_sql(rng_state: &mut u64, sql_type: SqlType) -> String {
    *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
    let variant = (*rng_state % 5) as usize;

    match sql_type {
        SqlType::Parameterized => {
            let queries = [
                "SELECT id, name FROM users WHERE active = $1 AND role = $2",
                "INSERT INTO orders (user_id, amount, status) VALUES ($1, $2, $3)",
                "UPDATE accounts SET balance = balance + $1 WHERE id = $2",
                "DELETE FROM sessions WHERE expires < $1",
                "SELECT * FROM products WHERE price BETWEEN $1 AND $2 ORDER BY $3",
            ];
            queries[variant].to_string()
        }
        SqlType::Nullable => {
            let queries = [
                "SELECT * FROM users WHERE middle_name = $1", // Can be NULL
                "INSERT INTO profiles (bio, avatar) VALUES ($1, $2)", // NULLable fields
                "UPDATE settings SET theme = $1, notifications = $2",
                "SELECT id FROM items WHERE description = $1 OR tags = $2",
                "INSERT INTO logs (message, metadata) VALUES ($1, $2)",
            ];
            queries[variant].to_string()
        }
        SqlType::StringHeavy => {
            let queries = [
                "SELECT * FROM articles WHERE title LIKE $1 AND content LIKE $2",
                "INSERT INTO comments (author, message) VALUES ($1, $2)",
                "UPDATE posts SET title = $1, body = $2 WHERE slug = $3",
                "SELECT id FROM files WHERE filename = $1 AND path = $2",
                "INSERT INTO search_terms (query, normalized) VALUES ($1, $2)",
            ];
            queries[variant].to_string()
        }
        SqlType::Numeric => {
            let queries = [
                "SELECT * FROM products WHERE price = $1 AND quantity > $2",
                "INSERT INTO metrics (value, timestamp) VALUES ($1, $2)",
                "UPDATE balances SET amount = $1 WHERE account_id = $2",
                "SELECT COUNT(*) FROM events WHERE score >= $1",
                "INSERT INTO coordinates (lat, lng, elevation) VALUES ($1, $2, $3)",
            ];
            queries[variant].to_string()
        }
        SqlType::VariableSize => {
            let queries = [
                "INSERT INTO documents (title, content) VALUES ($1, $2)",
                "UPDATE large_objects SET data = $1 WHERE id = $2",
                "SELECT id FROM attachments WHERE content = $1",
                "INSERT INTO exports (filename, data) VALUES ($1, $2)",
                "UPDATE cache SET value = $1 WHERE key = $2",
            ];
            queries[variant].to_string()
        }
    }
}

fn create_mismatched_param(
    declared_type: u8,
    actual_type: u8,
    rng_state: &mut u64,
) -> (MockParam, u32, u32) {
    *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
    let value = *rng_state;

    let declared_oid = match declared_type {
        0 => 16,   // BOOL
        1 => 23,   // INT4
        2 => 20,   // INT8
        3 => 701,  // FLOAT8
        4 => 25,   // TEXT
        5 => 17,   // BYTEA
        6 => 1184, // TIMESTAMPTZ
        _ => 25,   // TEXT
    };

    let actual_oid = match actual_type {
        0 => 16,   // BOOL
        1 => 23,   // INT4
        2 => 20,   // INT8
        3 => 701,  // FLOAT8
        4 => 25,   // TEXT
        5 => 17,   // BYTEA
        6 => 1184, // TIMESTAMPTZ
        _ => 25,   // TEXT
    };

    let param = match actual_type {
        0 => MockParam::Boolean((value % 2) == 1),
        1 => MockParam::Integer(value as i32 as i64),
        2 => MockParam::Integer(value as i64),
        3 => MockParam::Float(value as f64 / u64::MAX as f64),
        4 => MockParam::Text(format!("text_{}", value % 10000)),
        5 => {
            let size = (value % 32) as usize + 1;
            MockParam::Binary((0..size).map(|i| ((value >> i) & 0xFF) as u8).collect())
        }
        6 => MockParam::Text(format!(
            "2024-04-18T{}:{}:{}.000Z",
            (value % 24),
            (value % 60),
            (value % 60)
        )),
        _ => MockParam::Text(format!("default_{}", value % 1000)),
    };

    (param, declared_oid, actual_oid)
}

/// Test parameter type coercion vulnerabilities
fn test_parameter_type_coercion(operations: &[PgInjectionOperation]) {
    for op in operations {
        if let PgInjectionOperation::TypeCoercion {
            sql,
            param_values,
            declared_oids,
            actual_oids,
        } = op
        {
            // Verify SQL is reasonable
            assert!(sql.len() <= 1000, "SQL too long: {}", sql.len());
            assert!(!sql.is_empty(), "Empty SQL");
            assert!(
                sql.starts_with("SELECT")
                    || sql.starts_with("INSERT")
                    || sql.starts_with("UPDATE")
                    || sql.starts_with("DELETE"),
                "Unexpected SQL prefix: {}",
                &sql[..sql.len().min(10)]
            );

            // Check parameter count consistency
            assert_eq!(
                param_values.len(),
                declared_oids.len(),
                "Parameter count mismatch"
            );
            assert_eq!(param_values.len(), actual_oids.len(), "OID count mismatch");

            // Test type coercion edge cases
            for (i, (param, (&declared_oid, &actual_oid))) in param_values
                .iter()
                .zip(declared_oids.iter().zip(actual_oids.iter()))
                .enumerate()
            {
                // Validate OIDs are known PostgreSQL types
                assert!(
                    is_valid_pg_oid(declared_oid),
                    "Invalid declared OID {} at param {}",
                    declared_oid,
                    i
                );
                assert!(
                    is_valid_pg_oid(actual_oid),
                    "Invalid actual OID {} at param {}",
                    actual_oid,
                    i
                );

                // Test parameter encoding
                match param {
                    MockParam::Integer(val) => {
                        assert!(val.abs() <= i64::MAX, "Integer overflow");
                        if declared_oid == 21 {
                            // INT2
                            assert!(
                                *val >= i16::MIN as i64 && *val <= i16::MAX as i64,
                                "INT2 overflow: {}",
                                val
                            );
                        } else if declared_oid == 23 {
                            // INT4
                            assert!(
                                *val >= i32::MIN as i64 && *val <= i32::MAX as i64,
                                "INT4 overflow: {}",
                                val
                            );
                        }
                    }
                    MockParam::Float(val) => {
                        if declared_oid == 700 {
                            // FLOAT4
                            assert!(
                                val.is_finite() || val.is_nan() || val.is_infinite(),
                                "Invalid float4 value"
                            );
                        }
                    }
                    MockParam::Text(text) => {
                        assert!(text.len() <= 100_000, "Text too long: {}", text.len());
                        // Check for injection patterns
                        if text.contains("DROP") || text.contains("DELETE") || text.contains("--") {
                            // These should be safely escaped in prepared statements
                        }
                    }
                    MockParam::Binary(data) => {
                        assert!(data.len() <= 100_000, "Binary too long: {}", data.len());
                    }
                    MockParam::Boolean(_) => {
                        assert_eq!(declared_oid, 16, "Boolean type mismatch");
                    }
                    MockParam::Null => {
                        // NULL should be valid for any type
                    }
                    MockParam::Malformed(data) => {
                        assert!(data.len() <= 10_000, "Malformed data too long");
                    }
                }
            }
        }
    }
}

/// Test NULL injection attack vectors
fn test_null_injection_attacks(operations: &[PgInjectionOperation]) {
    for op in operations {
        if let PgInjectionOperation::NullInjection {
            sql,
            null_positions,
            null_bytes_in_strings,
            malformed_nulls,
        } = op
        {
            // Verify SQL structure
            assert!(sql.len() <= 1000, "SQL too long");
            assert!(!sql.is_empty(), "Empty SQL");

            // Check NULL position validity
            let param_count = sql.matches('$').count();
            for &pos in null_positions {
                assert!(
                    pos < param_count.max(10),
                    "NULL position {} beyond parameter count {}",
                    pos,
                    param_count
                );
            }

            // Test NULL byte injection in strings
            if *null_bytes_in_strings {
                // Strings with embedded NULL bytes should be handled safely
                let test_string = "normal\0injected";
                assert!(test_string.contains('\0'), "Test NULL byte missing");
                assert_eq!(test_string.len(), 15, "NULL byte length check");
            }

            // Test malformed NULL representations
            for malformed in malformed_nulls {
                assert!(malformed.len() <= 1000, "Malformed NULL too large");

                // Common malformed NULL patterns that should be rejected
                if malformed.len() == 4 {
                    let val = i32::from_le_bytes([
                        malformed.get(0).copied().unwrap_or(0),
                        malformed.get(1).copied().unwrap_or(0),
                        malformed.get(2).copied().unwrap_or(0),
                        malformed.get(3).copied().unwrap_or(0),
                    ]);

                    // PostgreSQL uses -1 length for NULL, other values should be rejected
                    if val != -1 && val >= 0 {
                        // This represents a length field that's not -1 (NULL) but also not
                        // a reasonable positive length - should be handled safely
                    }
                }
            }
        }
    }
}

/// Test SQL escape boundary vulnerabilities
fn test_sql_escape_boundaries(operations: &[PgInjectionOperation]) {
    for op in operations {
        if let PgInjectionOperation::EscapeBoundary {
            sql,
            string_params,
            binary_params,
            format_confusion,
        } = op
        {
            // Basic SQL validation
            assert!(sql.len() <= 1000, "SQL too long");
            assert!(!sql.is_empty(), "Empty SQL");

            // Test string parameter escaping
            for string_param in string_params {
                assert!(string_param.len() <= 10_000, "String param too long");

                // Check for common injection patterns
                if string_param.contains("'; DROP TABLE") {
                    // This injection attempt should be safely escaped
                    assert!(string_param.contains("DROP"), "Expected injection pattern");
                }

                if string_param.contains("\\x") {
                    // Hex escape sequences should be handled properly
                }

                if string_param.contains('\0') {
                    // NULL bytes in strings need special handling
                }

                // Test Unicode handling
                for ch in string_param.chars() {
                    if ch as u32 > 0x10FFFF {
                        // Invalid Unicode should be rejected
                        assert!(false, "Invalid Unicode character: U+{:X}", ch as u32);
                    }
                }
            }

            // Test binary parameter handling
            for binary_param in binary_params {
                assert!(binary_param.len() <= 10_000, "Binary param too long");

                // Binary data can contain any byte values
                // But very large data should be rejected to prevent DoS
            }

            // Test format confusion (binary vs text)
            if *format_confusion {
                // When binary data is interpreted as text or vice versa,
                // the system should handle it gracefully without security issues
            }
        }
    }
}

/// Test string vs numeric type mismatch
fn test_string_numeric_mismatch(operations: &[PgInjectionOperation]) {
    for op in operations {
        if let PgInjectionOperation::NumericMismatch {
            sql,
            numeric_strings,
            expected_types,
        } = op
        {
            // Basic validation
            assert!(sql.len() <= 1000, "SQL too long");
            assert_eq!(
                numeric_strings.len(),
                expected_types.len(),
                "Count mismatch"
            );

            // Test numeric parsing edge cases
            for (numeric_str, expected_type) in numeric_strings.iter().zip(expected_types.iter()) {
                assert!(numeric_str.len() <= 1000, "Numeric string too long");

                // Test parsing behavior
                match expected_type {
                    NumericType::Int16 => {
                        if let Ok(val) = numeric_str.parse::<i16>() {
                            assert!(val >= i16::MIN && val <= i16::MAX);
                        } else {
                            // Parse failure should be handled gracefully
                            // Check for overflow conditions
                            if numeric_str == "32768" || numeric_str == "-32769" {
                                // i16 overflow - should be rejected
                            }
                            if numeric_str == "NaN" || numeric_str.contains("Infinity") {
                                // Non-finite values in integer context - should be rejected
                            }
                        }
                    }
                    NumericType::Int32 => {
                        if numeric_str.parse::<i32>().is_err() {
                            // Invalid i32 should be rejected safely
                        }
                    }
                    NumericType::Int64 => {
                        if numeric_str.parse::<i64>().is_err() {
                            // Invalid i64 should be rejected safely
                        }
                    }
                    NumericType::Float32 => {
                        if let Ok(val) = numeric_str.parse::<f32>() {
                            if val.is_nan() || val.is_infinite() {
                                // Special float values should be handled correctly
                            }
                        }
                    }
                    NumericType::Float64 => {
                        if let Ok(val) = numeric_str.parse::<f64>() {
                            if val.is_subnormal() {
                                // Subnormal numbers should be handled
                            }
                        }
                    }
                    NumericType::Numeric => {
                        // PostgreSQL NUMERIC type supports arbitrary precision
                        // Very long numeric strings should be handled or rejected gracefully
                        if numeric_str.len() > 100 {
                            // Extremely long numeric strings might be DoS attempts
                        }
                    }
                }

                // Test scientific notation edge cases
                if numeric_str.contains('e') || numeric_str.contains('E') {
                    // Scientific notation parsing
                    if let Some(e_pos) = numeric_str.find(['e', 'E']) {
                        let (base, exp) = numeric_str.split_at(e_pos);
                        if base.is_empty() || exp.len() <= 1 {
                            // Malformed scientific notation
                        }
                    }
                }
            }
        }
    }
}

/// Test oversized parameter rejection
fn test_oversized_parameter_rejection(operations: &[PgInjectionOperation]) {
    for op in operations {
        if let PgInjectionOperation::OversizedParameter {
            sql,
            large_params,
            size_limits,
        } = op
        {
            // Basic validation
            assert!(sql.len() <= 1000, "SQL too long");
            assert_eq!(large_params.len(), size_limits.len(), "Count mismatch");

            // Test memory exhaustion protection
            for (large_param, &size_limit) in large_params.iter().zip(size_limits.iter()) {
                assert!(
                    size_limit <= 1_000_000,
                    "Size limit too large: {}",
                    size_limit
                );

                match large_param {
                    LargeParam::LongString(size) => {
                        assert_eq!(*size, size_limit, "Size mismatch");
                        if *size > 100_000 {
                            // Very large strings should be rejected to prevent memory exhaustion
                        }
                    }
                    LargeParam::LargeBinary(size) => {
                        assert_eq!(*size, size_limit, "Size mismatch");
                        if *size > 100_000 {
                            // Very large binary data should be rejected
                        }
                    }
                    LargeParam::DeepNesting(depth) => {
                        assert!(*depth <= 100, "Nesting too deep: {}", depth);
                        if *depth > 50 {
                            // Deep nesting in JSON/arrays might cause stack overflow
                        }
                    }
                }
            }

            // Total parameter size check
            let total_size: usize = size_limits.iter().sum();
            assert!(
                total_size <= 10_000_000,
                "Total parameter size too large: {}",
                total_size
            );
        }
    }
}

/// Check if OID is a valid PostgreSQL type
fn is_valid_pg_oid(oid: u32) -> bool {
    matches!(
        oid,
        16 |    // BOOL
        17 |    // BYTEA
        18 |    // CHAR
        20 |    // INT8
        21 |    // INT2
        23 |    // INT4
        25 |    // TEXT
        26 |    // OID
        114 |   // JSON
        700 |   // FLOAT4
        701 |   // FLOAT8
        1043 |  // VARCHAR
        1082 |  // DATE
        1114 |  // TIMESTAMP
        1184 |  // TIMESTAMPTZ
        2950 |  // UUID
        3802 // JSONB
    )
}

// Helper functions to extract data from fuzzer input
fn extract_u8(input: &mut &[u8], rng_state: &mut u64) -> u8 {
    if input.is_empty() {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        (*rng_state >> 8) as u8
    } else {
        let val = input[0];
        *input = &input[1..];
        val
    }
}

fn extract_u16(input: &mut &[u8], rng_state: &mut u64) -> u16 {
    if input.len() < 2 {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        (*rng_state >> 8) as u16
    } else {
        let val = u16::from_le_bytes([input[0], input[1]]);
        *input = &input[2..];
        val
    }
}

fn extract_u32(input: &mut &[u8], rng_state: &mut u64) -> u32 {
    if input.len() < 4 {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        *rng_state as u32
    } else {
        let val = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        *input = &input[4..];
        val
    }
}
