#![no_main]

//! Schema-aware fuzz target for PostgreSQL RowDescription and DataRow decoding.

use arbitrary::{Arbitrary, Unstructured};
use asupersync::database::postgres::{
    PgColumn, PgError, PgValue, fuzz_parse_data_row, fuzz_parse_row_description, oid,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_COLUMNS: usize = 24;
const MAX_FIELD_BYTES: usize = 512;
const MAX_TRAILING_BYTES: usize = 16;
const VALID_SCHEMA_ROW_SEED: &[u8] = b"schema-valid-row";
const LENGTH_LIE_BINARY_SEED: &[u8] = b"length-lie-binary";

#[derive(Arbitrary, Debug, Clone)]
struct SchemaAwareScenario {
    schema: SchemaSpec,
    row: DataRowSpec,
}

#[derive(Arbitrary, Debug, Clone)]
struct SchemaSpec {
    declared_fields: CountEncoding,
    columns: Vec<ColumnSpec>,
    truncate_at: Option<u16>,
    trailing_bytes: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
struct DataRowSpec {
    declared_values: CountEncoding,
    values: Vec<CellSpec>,
    truncate_at: Option<u16>,
    trailing_bytes: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
enum CountEncoding {
    Actual,
    Negative(u8),
    SmallerBy(u8),
    LargerBy(u8),
    Exact(u8),
}

impl CountEncoding {
    fn apply(&self, actual: usize) -> i16 {
        match self {
            Self::Actual => actual.min(i16::MAX as usize) as i16,
            Self::Negative(seed) => -((i16::from(*seed % 7)) + 1),
            Self::SmallerBy(delta) => actual.saturating_sub(usize::from((*delta % 4) + 1)) as i16,
            Self::LargerBy(delta) => actual.saturating_add(usize::from((*delta % 4) + 1)) as i16,
            Self::Exact(raw) => usize::from(*raw % 32) as i16,
        }
    }

    fn is_actual(&self) -> bool {
        matches!(self, Self::Actual)
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct ColumnSpec {
    name: NamePattern,
    type_oid: TypeOidSpec,
    format_code: FormatCodeSpec,
    table_oid: u16,
    column_id: i16,
    type_size: i16,
    type_modifier: i32,
}

#[derive(Arbitrary, Debug, Clone)]
enum NamePattern {
    Unique(u8),
    Duplicate(u8),
    Empty,
    Long(u8),
}

impl NamePattern {
    fn materialize(&self, index: usize) -> String {
        match self {
            Self::Unique(tag) => format!("col_{index}_{}", tag % 16),
            Self::Duplicate(tag) => format!("dup_{}", tag % 4),
            Self::Empty => String::new(),
            Self::Long(tag) => {
                let width = usize::from((tag % 20) + 4);
                let suffix = char::from(b'a' + (tag % 26));
                format!("{}_{index}", suffix.to_string().repeat(width))
            }
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum TypeOidSpec {
    Bool,
    Int2,
    Int4,
    Oid,
    Int8,
    Float4,
    Float8,
    Text,
    Varchar,
    Bytea,
    Jsonb,
    Uuid,
    Unknown(u32),
}

impl TypeOidSpec {
    fn to_oid(&self) -> u32 {
        match self {
            Self::Bool => oid::BOOL,
            Self::Int2 => oid::INT2,
            Self::Int4 => oid::INT4,
            Self::Oid => oid::OID,
            Self::Int8 => oid::INT8,
            Self::Float4 => oid::FLOAT4,
            Self::Float8 => oid::FLOAT8,
            Self::Text => oid::TEXT,
            Self::Varchar => oid::VARCHAR,
            Self::Bytea => oid::BYTEA,
            Self::Jsonb => oid::JSONB,
            Self::Uuid => oid::UUID,
            Self::Unknown(raw) => *raw,
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum FormatCodeSpec {
    Text,
    Binary,
    Invalid(u16),
}

impl FormatCodeSpec {
    fn to_code(&self) -> i16 {
        match self {
            Self::Text => 0,
            Self::Binary => 1,
            Self::Invalid(raw) => i16::from_be_bytes(raw.to_be_bytes()),
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct CellSpec {
    mode: CellMode,
    length: LengthEncoding,
    data: Vec<u8>,
    scalar: u64,
}

#[derive(Arbitrary, Debug, Clone)]
enum CellMode {
    Null,
    MatchType,
    MismatchType,
    InvalidUtf8,
    RawBytes,
}

#[derive(Arbitrary, Debug, Clone)]
enum LengthEncoding {
    Honest,
    ShortBy(u8),
    LongBy(u8),
    Negative(u8),
    Huge(u16),
}

impl LengthEncoding {
    fn is_honest(&self) -> bool {
        matches!(self, Self::Honest)
    }
}

fn normalize_scenario(mut scenario: SchemaAwareScenario) -> SchemaAwareScenario {
    scenario.schema.columns.truncate(MAX_COLUMNS);
    scenario.row.values.truncate(MAX_COLUMNS);
    scenario.schema.trailing_bytes.truncate(MAX_TRAILING_BYTES);
    scenario.row.trailing_bytes.truncate(MAX_TRAILING_BYTES);

    for cell in &mut scenario.row.values {
        cell.data.truncate(MAX_FIELD_BYTES);
    }

    scenario
}

fn materialize_columns(schema: &SchemaSpec) -> Vec<PgColumn> {
    schema
        .columns
        .iter()
        .enumerate()
        .map(|(index, spec)| PgColumn {
            name: spec.name.materialize(index),
            table_oid: u32::from(spec.table_oid),
            column_id: spec.column_id,
            type_oid: spec.type_oid.to_oid(),
            type_size: spec.type_size,
            type_modifier: spec.type_modifier,
            format_code: spec.format_code.to_code(),
        })
        .collect()
}

fn build_row_description_bytes(schema: &SchemaSpec, columns: &[PgColumn]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&schema.declared_fields.apply(columns.len()).to_be_bytes());

    for column in columns {
        data.extend_from_slice(column.name.as_bytes());
        data.push(0);
        data.extend_from_slice(&column.table_oid.to_be_bytes());
        data.extend_from_slice(&column.column_id.to_be_bytes());
        data.extend_from_slice(&(column.type_oid as i32).to_be_bytes());
        data.extend_from_slice(&column.type_size.to_be_bytes());
        data.extend_from_slice(&column.type_modifier.to_be_bytes());
        data.extend_from_slice(&column.format_code.to_be_bytes());
    }

    maybe_truncate_and_trail(data, schema.truncate_at, &schema.trailing_bytes)
}

fn build_data_row_bytes(row: &DataRowSpec, columns: &[PgColumn]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&row.declared_values.apply(row.values.len()).to_be_bytes());

    for (index, cell) in row.values.iter().enumerate() {
        let column = columns.get(index);
        let payload = materialize_payload(column, cell);
        let declared_len = declared_length(cell, payload.len());
        data.extend_from_slice(&declared_len.to_be_bytes());
        if declared_len >= 0 {
            data.extend_from_slice(&payload);
        }
    }

    maybe_truncate_and_trail(data, row.truncate_at, &row.trailing_bytes)
}

fn maybe_truncate_and_trail(
    mut data: Vec<u8>,
    truncate_at: Option<u16>,
    trailing_bytes: &[u8],
) -> Vec<u8> {
    if let Some(limit) = truncate_at {
        let limit = usize::from(limit) % (data.len().saturating_add(1));
        data.truncate(limit);
    }
    data.extend_from_slice(trailing_bytes);
    data
}

fn materialize_payload(column: Option<&PgColumn>, cell: &CellSpec) -> Vec<u8> {
    if matches!(cell.mode, CellMode::Null) {
        return Vec::new();
    }

    let fallback_text = asciiish_bytes(&cell.data, b'x');
    let type_oid = column.map_or(oid::TEXT, |col| col.type_oid);
    let format_code = column.map_or(0, |col| col.format_code);

    match cell.mode {
        CellMode::MatchType => match format_code {
            0 => matching_text_payload(type_oid, cell, &fallback_text),
            1 => matching_binary_payload(type_oid, cell, &fallback_text),
            _ => fallback_text,
        },
        CellMode::MismatchType => mismatching_payload(type_oid, format_code),
        CellMode::InvalidUtf8 => vec![0xFF, 0xFE, 0xF8, 0x00],
        CellMode::RawBytes => {
            if cell.data.is_empty() {
                vec![b'?', b'!']
            } else {
                cell.data.clone()
            }
        }
        CellMode::Null => Vec::new(),
    }
}

fn matching_text_payload(type_oid: u32, cell: &CellSpec, fallback_text: &[u8]) -> Vec<u8> {
    match type_oid {
        oid::BOOL => {
            if cell.scalar & 1 == 0 {
                b"t".to_vec()
            } else {
                b"f".to_vec()
            }
        }
        oid::INT2 => ((cell.scalar as i16).to_string()).into_bytes(),
        oid::INT4 | oid::OID => ((cell.scalar as i32).to_string()).into_bytes(),
        oid::INT8 => ((cell.scalar as i64).to_string()).into_bytes(),
        oid::FLOAT4 => format!("{}", f32::from_bits(cell.scalar as u32)).into_bytes(),
        oid::FLOAT8 => format!("{}", f64::from_bits(cell.scalar)).into_bytes(),
        oid::BYTEA => {
            let bytes = byte_seed(cell);
            let mut out = Vec::with_capacity(2 + bytes.len() * 2);
            out.extend_from_slice(b"\\x");
            for byte in bytes {
                out.extend_from_slice(format!("{byte:02x}").as_bytes());
            }
            out
        }
        _ => {
            if fallback_text.is_empty() {
                b"ok".to_vec()
            } else {
                fallback_text.to_vec()
            }
        }
    }
}

fn matching_binary_payload(type_oid: u32, cell: &CellSpec, fallback_text: &[u8]) -> Vec<u8> {
    match type_oid {
        oid::BOOL => vec![(cell.scalar & 1) as u8],
        oid::INT2 => (cell.scalar as i16).to_be_bytes().to_vec(),
        oid::INT4 | oid::OID => (cell.scalar as i32).to_be_bytes().to_vec(),
        oid::INT8 => (cell.scalar as i64).to_be_bytes().to_vec(),
        oid::FLOAT4 => f32::from_bits(cell.scalar as u32).to_be_bytes().to_vec(),
        oid::FLOAT8 => f64::from_bits(cell.scalar).to_be_bytes().to_vec(),
        oid::BYTEA => byte_seed(cell),
        oid::JSONB => {
            let mut payload = vec![1];
            payload.extend_from_slice(if fallback_text.is_empty() {
                b"{}"
            } else {
                fallback_text
            });
            payload
        }
        _ => {
            if fallback_text.is_empty() {
                b"text".to_vec()
            } else {
                fallback_text.to_vec()
            }
        }
    }
}

fn mismatching_payload(type_oid: u32, format_code: i16) -> Vec<u8> {
    match (format_code, type_oid) {
        (0, oid::BOOL) => b"maybe".to_vec(),
        (0, oid::INT2 | oid::INT4 | oid::OID | oid::INT8) => b"not-a-number".to_vec(),
        (0, oid::FLOAT4 | oid::FLOAT8) => b"nan(not)".to_vec(),
        (0, _) => vec![0xFF, 0xFE],
        (1, oid::BOOL) => vec![2],
        (1, oid::INT2) => vec![0x12],
        (1, oid::INT4 | oid::OID) => vec![0xDE, 0xAD, 0xBE],
        (1, oid::INT8) => vec![0xBA, 0xAD, 0xF0, 0x0D],
        (1, oid::FLOAT4) => vec![1, 2, 3],
        (1, oid::FLOAT8) => vec![1, 2, 3, 4, 5],
        (1, _) => vec![0xFF, 0xFE, 0xFD],
        _ => b"??".to_vec(),
    }
}

fn declared_length(cell: &CellSpec, actual_len: usize) -> i32 {
    if matches!(cell.mode, CellMode::Null) {
        return -1;
    }

    match cell.length {
        LengthEncoding::Honest => actual_len.min(i32::MAX as usize) as i32,
        LengthEncoding::ShortBy(delta) => actual_len.saturating_sub(usize::from(delta % 8)) as i32,
        LengthEncoding::LongBy(delta) => actual_len.saturating_add(usize::from(delta % 32)) as i32,
        LengthEncoding::Negative(seed) => -((i32::from(seed % 7)) + 2),
        LengthEncoding::Huge(delta) => {
            i32::try_from(MAX_FIELD_BYTES + usize::from(delta % 128)).unwrap_or(i32::MAX)
        }
    }
}

fn byte_seed(cell: &CellSpec) -> Vec<u8> {
    if cell.data.is_empty() {
        cell.scalar.to_be_bytes()[..4].to_vec()
    } else {
        cell.data.clone()
    }
}

fn asciiish_bytes(raw: &[u8], fallback: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len().max(2));
    for byte in raw.iter().copied().take(MAX_FIELD_BYTES) {
        let mapped = match byte {
            b' '..=b'~' if byte != 0 => byte,
            _ => fallback,
        };
        out.push(mapped);
    }
    if out.is_empty() {
        out.extend_from_slice(b"txt");
    }
    out
}

fn clean_schema_path(schema: &SchemaSpec) -> bool {
    schema.declared_fields.is_actual()
        && schema.truncate_at.is_none()
        && schema.trailing_bytes.is_empty()
}

fn clean_row_path(row: &DataRowSpec, columns: &[PgColumn]) -> bool {
    row.declared_values.is_actual()
        && row.values.len() == columns.len()
        && row.truncate_at.is_none()
        && row.trailing_bytes.is_empty()
        && row
            .values
            .iter()
            .zip(columns)
            .all(|(cell, column)| match cell.mode {
                CellMode::Null => true,
                CellMode::MatchType => {
                    cell.length.is_honest() && format_is_valid(column.format_code)
                }
                _ => false,
            })
}

fn format_is_valid(format_code: i16) -> bool {
    matches!(format_code, 0 | 1)
}

fn column_signature(columns: &[PgColumn]) -> Vec<(String, u32, i16, u32, i16, i32, i16)> {
    columns
        .iter()
        .map(|col| {
            (
                col.name.clone(),
                col.table_oid,
                col.column_id,
                col.type_oid,
                col.type_size,
                col.type_modifier,
                col.format_code,
            )
        })
        .collect()
}

fn value_signature(values: &[PgValue]) -> Vec<String> {
    values.iter().map(|value| format!("{value:?}")).collect()
}

fn error_signature(err: &PgError) -> String {
    format!("{err:?}")
}

fn assert_duplicate_index_map(columns: &[PgColumn], indices: &BTreeMap<String, usize>) {
    let expected = columns
        .iter()
        .enumerate()
        .fold(BTreeMap::new(), |mut map, (index, column)| {
            map.insert(column.name.clone(), index);
            map
        });
    assert_eq!(
        indices, &expected,
        "RowDescription duplicate-name index map should be stable"
    );
}

fn expected_kind(column: &PgColumn) -> Option<&'static str> {
    match column.type_oid {
        oid::BOOL => Some("Bool"),
        oid::INT2 => Some("Int2"),
        oid::INT4 | oid::OID => Some("Int4"),
        oid::INT8 => Some("Int8"),
        oid::FLOAT4 => Some("Float4"),
        oid::FLOAT8 => Some("Float8"),
        oid::BYTEA => Some("Bytes"),
        oid::TEXT | oid::VARCHAR | oid::UUID | oid::JSONB | oid::JSON => Some("Text"),
        _ => None,
    }
}

fn value_kind(value: &PgValue) -> &'static str {
    match value {
        PgValue::Null => "Null",
        PgValue::Bool(_) => "Bool",
        PgValue::Int2(_) => "Int2",
        PgValue::Int4(_) => "Int4",
        PgValue::Int8(_) => "Int8",
        PgValue::Float4(_) => "Float4",
        PgValue::Float8(_) => "Float8",
        PgValue::Text(_) => "Text",
        PgValue::Bytes(_) => "Bytes",
    }
}

fn assert_row_description_deterministic(
    data: &[u8],
) -> Result<(Vec<PgColumn>, BTreeMap<String, usize>), PgError> {
    let first = fuzz_parse_row_description(data);
    let second = fuzz_parse_row_description(data);

    match (&first, &second) {
        (Ok((columns_a, indices_a)), Ok((columns_b, indices_b))) => {
            assert_eq!(column_signature(columns_a), column_signature(columns_b));
            assert_eq!(indices_a, indices_b);
            assert_duplicate_index_map(columns_a, indices_a);
        }
        (Err(err_a), Err(err_b)) => {
            assert_eq!(error_signature(err_a), error_signature(err_b));
        }
        _ => panic!("RowDescription parse must be deterministic"),
    }

    first
}

fn assert_data_row_deterministic(
    data: &[u8],
    columns: &[PgColumn],
) -> Result<Vec<PgValue>, PgError> {
    let first = fuzz_parse_data_row(data, columns);
    let second = fuzz_parse_data_row(data, columns);

    match (&first, &second) {
        (Ok(values_a), Ok(values_b)) => {
            assert_eq!(value_signature(values_a), value_signature(values_b));
        }
        (Err(err_a), Err(err_b)) => {
            assert_eq!(error_signature(err_a), error_signature(err_b));
        }
        _ => panic!("DataRow parse must be deterministic"),
    }

    first
}

fn assert_clean_path_semantics(columns: &[PgColumn], row: &DataRowSpec, values: &[PgValue]) {
    assert_eq!(values.len(), columns.len());

    for ((column, cell), value) in columns.iter().zip(&row.values).zip(values) {
        match cell.mode {
            CellMode::Null => assert!(matches!(value, PgValue::Null)),
            CellMode::MatchType => {
                if let Some(kind) = expected_kind(column) {
                    assert_eq!(
                        value_kind(value),
                        kind,
                        "matched payload should decode to the expected PgValue variant"
                    );
                }
            }
            _ => {}
        }
    }
}

fn fuzz_schema_aware_pair(scenario: SchemaAwareScenario) {
    let scenario = normalize_scenario(scenario);
    let materialized_columns = materialize_columns(&scenario.schema);
    let row_description = build_row_description_bytes(&scenario.schema, &materialized_columns);
    let parsed_columns = match assert_row_description_deterministic(&row_description) {
        Ok((columns, _indices)) => columns,
        Err(_) => materialized_columns.clone(),
    };

    let data_row = build_data_row_bytes(&scenario.row, &parsed_columns);
    if let Ok(values) = assert_data_row_deterministic(&data_row, &parsed_columns) {
        if clean_schema_path(&scenario.schema) && clean_row_path(&scenario.row, &parsed_columns) {
            assert_clean_path_semantics(&parsed_columns, &scenario.row, &values);
        }
    }
}

fn valid_seed_scenario() -> SchemaAwareScenario {
    SchemaAwareScenario {
        schema: SchemaSpec {
            declared_fields: CountEncoding::Actual,
            columns: vec![
                ColumnSpec {
                    name: NamePattern::Duplicate(1),
                    type_oid: TypeOidSpec::Int4,
                    format_code: FormatCodeSpec::Text,
                    table_oid: 0,
                    column_id: 1,
                    type_size: 4,
                    type_modifier: -1,
                },
                ColumnSpec {
                    name: NamePattern::Duplicate(1),
                    type_oid: TypeOidSpec::Bytea,
                    format_code: FormatCodeSpec::Binary,
                    table_oid: 0,
                    column_id: 2,
                    type_size: -1,
                    type_modifier: -1,
                },
                ColumnSpec {
                    name: NamePattern::Unique(7),
                    type_oid: TypeOidSpec::Bool,
                    format_code: FormatCodeSpec::Text,
                    table_oid: 0,
                    column_id: 3,
                    type_size: 1,
                    type_modifier: -1,
                },
            ],
            truncate_at: None,
            trailing_bytes: Vec::new(),
        },
        row: DataRowSpec {
            declared_values: CountEncoding::Actual,
            values: vec![
                CellSpec {
                    mode: CellMode::MatchType,
                    length: LengthEncoding::Honest,
                    data: Vec::new(),
                    scalar: 42,
                },
                CellSpec {
                    mode: CellMode::MatchType,
                    length: LengthEncoding::Honest,
                    data: vec![0xDE, 0xAD, 0xBE, 0xEF],
                    scalar: 0,
                },
                CellSpec {
                    mode: CellMode::MatchType,
                    length: LengthEncoding::Honest,
                    data: Vec::new(),
                    scalar: 0,
                },
            ],
            truncate_at: None,
            trailing_bytes: Vec::new(),
        },
    }
}

fn length_lie_seed_scenario() -> SchemaAwareScenario {
    SchemaAwareScenario {
        schema: SchemaSpec {
            declared_fields: CountEncoding::Actual,
            columns: vec![
                ColumnSpec {
                    name: NamePattern::Unique(3),
                    type_oid: TypeOidSpec::Int4,
                    format_code: FormatCodeSpec::Binary,
                    table_oid: 0,
                    column_id: 1,
                    type_size: 4,
                    type_modifier: -1,
                },
                ColumnSpec {
                    name: NamePattern::Unique(4),
                    type_oid: TypeOidSpec::Text,
                    format_code: FormatCodeSpec::Text,
                    table_oid: 0,
                    column_id: 2,
                    type_size: -1,
                    type_modifier: -1,
                },
            ],
            truncate_at: None,
            trailing_bytes: Vec::new(),
        },
        row: DataRowSpec {
            declared_values: CountEncoding::Actual,
            values: vec![
                CellSpec {
                    mode: CellMode::MatchType,
                    length: LengthEncoding::Huge(32),
                    data: vec![0, 0, 0, 7],
                    scalar: 7,
                },
                CellSpec {
                    mode: CellMode::InvalidUtf8,
                    length: LengthEncoding::LongBy(3),
                    data: vec![0xFF, 0xFE, 0xFD],
                    scalar: 0,
                },
            ],
            truncate_at: None,
            trailing_bytes: Vec::new(),
        },
    }
}

fn seeded_scenario(data: &[u8]) -> Option<SchemaAwareScenario> {
    if data.starts_with(VALID_SCHEMA_ROW_SEED) {
        return Some(valid_seed_scenario());
    }
    if data.starts_with(LENGTH_LIE_BINARY_SEED) {
        return Some(length_lie_seed_scenario());
    }
    None
}

fuzz_target!(|data: &[u8]| {
    if let Some(scenario) = seeded_scenario(data) {
        fuzz_schema_aware_pair(scenario);
        return;
    }

    let mut unstructured = Unstructured::new(data);
    if let Ok(scenario) = SchemaAwareScenario::arbitrary(&mut unstructured) {
        fuzz_schema_aware_pair(scenario);
    }
});
