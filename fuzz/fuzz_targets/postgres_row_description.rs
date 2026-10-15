#![no_main]

//! Structure-aware fuzzer for PostgreSQL RowDescription body parsing.

use arbitrary::Arbitrary;
use asupersync::database::postgres::{PgColumn, PgError, fuzz_parse_row_description, oid};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_COLUMNS: usize = 96;
const MAX_RAW_BODY: usize = 4096;
const MAX_TRAILING_BYTES: usize = 32;

#[derive(Arbitrary, Debug)]
enum Scenario {
    Columns {
        columns: Vec<ColumnSpec>,
        malformed: Option<MalformedBody>,
    },
    CombinationMatrix {
        names: NameSet,
        type_oids: Vec<TypeOidSpec>,
        type_modifiers: Vec<TypeModifierSpec>,
        format_codes: Vec<FormatCodeSpec>,
    },
    RawBody {
        bytes: Vec<u8>,
    },
}

#[derive(Arbitrary, Debug, Clone)]
struct ColumnSpec {
    name: NameSpec,
    table_oid: u32,
    column_id: i16,
    type_oid: TypeOidSpec,
    type_size: i16,
    type_modifier: TypeModifierSpec,
    format_code: FormatCodeSpec,
}

#[derive(Arbitrary, Debug, Clone)]
enum NameSpec {
    Unique(u8),
    Duplicate(u8),
    Empty,
    Long(u8),
}

impl NameSpec {
    fn materialize(&self, index: usize) -> String {
        match self {
            Self::Unique(tag) => format!("col_{index}_{}", tag % 32),
            Self::Duplicate(tag) => format!("dup_{}", tag % 8),
            Self::Empty => String::new(),
            Self::Long(tag) => {
                let len = usize::from((tag % 40) + 8);
                let ch = char::from(b'a' + (tag % 26));
                format!("{}_{index}", ch.to_string().repeat(len))
            }
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum NameSet {
    Unique,
    Duplicate(u8),
    Empty,
}

impl NameSet {
    fn materialize(&self, index: usize) -> String {
        match self {
            Self::Unique => format!("matrix_col_{index}"),
            Self::Duplicate(tag) => format!("matrix_dup_{}", tag % 4),
            Self::Empty => String::new(),
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum TypeOidSpec {
    Bool,
    Int2,
    Int4,
    Int8,
    Float4,
    Float8,
    Text,
    Varchar,
    Bytea,
    Timestamp,
    Timestamptz,
    Date,
    Interval,
    Uuid,
    Json,
    Jsonb,
    Unknown(u32),
}

impl TypeOidSpec {
    fn to_oid(&self) -> u32 {
        match self {
            Self::Bool => oid::BOOL,
            Self::Int2 => oid::INT2,
            Self::Int4 => oid::INT4,
            Self::Int8 => oid::INT8,
            Self::Float4 => oid::FLOAT4,
            Self::Float8 => oid::FLOAT8,
            Self::Text => oid::TEXT,
            Self::Varchar => oid::VARCHAR,
            Self::Bytea => oid::BYTEA,
            Self::Timestamp => oid::TIMESTAMP,
            Self::Timestamptz => oid::TIMESTAMPTZ,
            Self::Date => oid::DATE,
            Self::Interval => oid::INTERVAL,
            Self::Uuid => oid::UUID,
            Self::Json => oid::JSON,
            Self::Jsonb => oid::JSONB,
            Self::Unknown(raw) => *raw,
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum TypeModifierSpec {
    Unspecified,
    Zero,
    Positive(u16),
    Negative(u16),
    Raw(i32),
}

impl TypeModifierSpec {
    fn to_i32(&self) -> i32 {
        match self {
            Self::Unspecified => -1,
            Self::Zero => 0,
            Self::Positive(raw) => i32::from(*raw),
            Self::Negative(raw) => -i32::from((*raw % 4096) + 1),
            Self::Raw(raw) => *raw,
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum FormatCodeSpec {
    Text,
    Binary,
    Negative(u8),
    InvalidPositive(u16),
    Raw(i16),
}

impl FormatCodeSpec {
    fn to_i16(&self) -> i16 {
        match self {
            Self::Text => 0,
            Self::Binary => 1,
            Self::Negative(raw) => -i16::from((*raw % 64) + 1),
            Self::InvalidPositive(raw) => {
                let normalized = (*raw % (i16::MAX as u16 - 1)) + 2;
                i16::try_from(normalized).unwrap_or(i16::MAX)
            }
            Self::Raw(raw) => *raw,
        }
    }
}

#[derive(Arbitrary, Debug)]
enum MalformedBody {
    DeclaredCountSmaller(u8),
    DeclaredCountLarger(u8),
    NegativeCount(u8),
    TruncateAt(u16),
    AddTrailing(Vec<u8>),
    FlipByte { index: u16, mask: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ColumnSummary {
    name: String,
    table_oid: u32,
    column_id: i16,
    type_oid: u32,
    type_size: i16,
    type_modifier: i32,
    format_code: i16,
}

impl From<&PgColumn> for ColumnSummary {
    fn from(column: &PgColumn) -> Self {
        Self {
            name: column.name.clone(),
            table_oid: column.table_oid,
            column_id: column.column_id,
            type_oid: column.type_oid,
            type_size: column.type_size,
            type_modifier: column.type_modifier,
            format_code: column.format_code,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseSummary {
    Ok {
        columns: Vec<ColumnSummary>,
        indices: BTreeMap<String, usize>,
    },
    Err(String),
}

fn materialize_columns(specs: &[ColumnSpec]) -> Vec<PgColumn> {
    specs
        .iter()
        .take(MAX_COLUMNS)
        .enumerate()
        .map(|(index, spec)| PgColumn {
            name: spec.name.materialize(index),
            table_oid: spec.table_oid,
            column_id: spec.column_id,
            type_oid: spec.type_oid.to_oid(),
            type_size: spec.type_size,
            type_modifier: spec.type_modifier.to_i32(),
            format_code: spec.format_code.to_i16(),
        })
        .collect()
}

fn materialize_matrix(
    names: &NameSet,
    type_oids: &[TypeOidSpec],
    type_modifiers: &[TypeModifierSpec],
    format_codes: &[FormatCodeSpec],
) -> Vec<PgColumn> {
    let mut type_oids = type_oids.to_vec();
    let mut type_modifiers = type_modifiers.to_vec();
    let mut format_codes = format_codes.to_vec();

    if type_oids.is_empty() {
        type_oids.push(TypeOidSpec::Text);
    }
    if type_modifiers.is_empty() {
        type_modifiers.push(TypeModifierSpec::Unspecified);
    }
    if format_codes.is_empty() {
        format_codes.push(FormatCodeSpec::Text);
    }

    let mut columns = Vec::new();
    for type_oid in type_oids.iter().take(12) {
        for type_modifier in type_modifiers.iter().take(8) {
            for format_code in format_codes.iter().take(8) {
                if columns.len() == MAX_COLUMNS {
                    return columns;
                }
                let index = columns.len();
                columns.push(PgColumn {
                    name: names.materialize(index),
                    table_oid: index as u32,
                    column_id: i16::try_from(index).unwrap_or(i16::MAX),
                    type_oid: type_oid.to_oid(),
                    type_size: expected_type_size(type_oid.to_oid()),
                    type_modifier: type_modifier.to_i32(),
                    format_code: format_code.to_i16(),
                });
            }
        }
    }
    columns
}

fn expected_type_size(type_oid: u32) -> i16 {
    match type_oid {
        oid::BOOL => 1,
        oid::INT2 => 2,
        oid::INT4 | oid::FLOAT4 | oid::DATE => 4,
        oid::INT8 | oid::FLOAT8 | oid::TIMESTAMP | oid::TIMESTAMPTZ => 8,
        _ => -1,
    }
}

fn expected_indices(columns: &[PgColumn]) -> BTreeMap<String, usize> {
    let mut indices = BTreeMap::new();
    for (index, column) in columns.iter().enumerate() {
        indices.insert(column.name.clone(), index);
    }
    indices
}

fn build_row_description_body(columns: &[PgColumn], declared_count: i16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&declared_count.to_be_bytes());

    for column in columns {
        body.extend_from_slice(column.name.as_bytes());
        body.push(0);
        body.extend_from_slice(&column.table_oid.to_be_bytes());
        body.extend_from_slice(&column.column_id.to_be_bytes());
        body.extend_from_slice(&column.type_oid.to_be_bytes());
        body.extend_from_slice(&column.type_size.to_be_bytes());
        body.extend_from_slice(&column.type_modifier.to_be_bytes());
        body.extend_from_slice(&column.format_code.to_be_bytes());
    }

    body
}

fn summarize_parse(
    result: Result<(Vec<PgColumn>, BTreeMap<String, usize>), PgError>,
) -> ParseSummary {
    match result {
        Ok((columns, indices)) => ParseSummary::Ok {
            columns: columns.iter().map(ColumnSummary::from).collect(),
            indices,
        },
        Err(err) => ParseSummary::Err(err.to_string()),
    }
}

fn assert_deterministic(body: &[u8]) -> ParseSummary {
    let first = summarize_parse(fuzz_parse_row_description(body));
    let second = summarize_parse(fuzz_parse_row_description(body));
    assert_eq!(
        first, second,
        "RowDescription parsing must be deterministic for identical bytes"
    );
    observe_parse_summary(&first);
    first
}

fn observe_parse_summary(summary: &ParseSummary) {
    match summary {
        ParseSummary::Ok { columns, indices } => {
            assert!(columns.len() <= MAX_COLUMNS);
            assert!(indices.len() <= columns.len());
            for (name, index) in indices {
                assert!(
                    *index < columns.len(),
                    "RowDescription index {index} must point into {} columns",
                    columns.len()
                );
                assert_eq!(
                    columns[*index].name, *name,
                    "RowDescription index map must point at the named column"
                );
            }
        }
        ParseSummary::Err(message) => {
            assert!(!message.is_empty(), "parser errors must be observable");
        }
    }
}

fn assert_valid_body_round_trips(columns: &[PgColumn]) {
    let body = build_row_description_body(columns, columns.len() as i16);
    let summary = assert_deterministic(&body);
    assert_eq!(
        summary,
        ParseSummary::Ok {
            columns: columns.iter().map(ColumnSummary::from).collect(),
            indices: expected_indices(columns),
        },
        "valid RowDescription must preserve OIDs, type modifiers, and format codes"
    );
}

fn apply_malformed_body(body: &mut Vec<u8>, malformed: MalformedBody, column_count: usize) {
    match malformed {
        MalformedBody::DeclaredCountSmaller(delta) => {
            let declared = column_count.saturating_sub(usize::from((delta % 8) + 1));
            body[..2].copy_from_slice(&(declared as i16).to_be_bytes());
        }
        MalformedBody::DeclaredCountLarger(delta) => {
            let declared = column_count
                .saturating_add(usize::from((delta % 8) + 1))
                .min(i16::MAX as usize);
            body[..2].copy_from_slice(&(declared as i16).to_be_bytes());
        }
        MalformedBody::NegativeCount(raw) => {
            let declared = -i16::from((raw % 64) + 1);
            body[..2].copy_from_slice(&declared.to_be_bytes());
        }
        MalformedBody::TruncateAt(raw) => {
            let limit = usize::from(raw) % body.len().saturating_add(1);
            body.truncate(limit);
        }
        MalformedBody::AddTrailing(mut trailing) => {
            trailing.truncate(MAX_TRAILING_BYTES);
            body.extend_from_slice(&trailing);
        }
        MalformedBody::FlipByte { index, mask } => {
            if !body.is_empty() {
                let index = usize::from(index) % body.len();
                body[index] ^= mask;
            }
        }
    }
}

fn exercise_malformed_body(columns: &[PgColumn], malformed: MalformedBody) {
    let mut body = build_row_description_body(columns, columns.len() as i16);
    apply_malformed_body(&mut body, malformed, columns.len());
    assert_deterministic(&body);
}

fuzz_target!(|scenario: Scenario| {
    match scenario {
        Scenario::Columns { columns, malformed } => {
            let columns = materialize_columns(&columns);
            assert_valid_body_round_trips(&columns);
            if let Some(malformed) = malformed {
                exercise_malformed_body(&columns, malformed);
            }
        }
        Scenario::CombinationMatrix {
            names,
            type_oids,
            type_modifiers,
            format_codes,
        } => {
            let columns = materialize_matrix(&names, &type_oids, &type_modifiers, &format_codes);
            assert_valid_body_round_trips(&columns);
        }
        Scenario::RawBody { mut bytes } => {
            bytes.truncate(MAX_RAW_BODY);
            assert_deterministic(&bytes);
        }
    }
});
