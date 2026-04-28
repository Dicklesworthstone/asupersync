#![no_main]

//! Structure-aware fuzz target for PostgreSQL RowDescription wire packets.
//!
//! Bead: br-asupersync-hfm239

use arbitrary::Arbitrary;
use asupersync::cx::Cx;
use asupersync::database::postgres::{
    PgColumn, PgError, fuzz_parse_row_description, fuzz_read_backend_message, oid,
};
use futures_lite::future::block_on;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_COLUMNS: usize = 24;
const MAX_NAME_BYTES: usize = 48;
const MAX_TRAILING_BYTES: usize = 16;

#[derive(Arbitrary, Debug, Clone)]
struct Scenario {
    declared_fields: CountEncoding,
    packet_length: PacketLengthEncoding,
    columns: Vec<ColumnSpec>,
    truncate_body_at: Option<u16>,
    trailing_bytes: Vec<u8>,
    byte_flip: Option<ByteFlip>,
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
            Self::Exact(raw) => i16::from(*raw % 32),
        }
    }

    fn is_actual(&self) -> bool {
        matches!(self, Self::Actual)
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum PacketLengthEncoding {
    Actual,
    TooSmall(u8),
    SmallerBy(u8),
    LargerBy(u8),
    Negative,
    Huge(u16),
}

impl PacketLengthEncoding {
    fn encode(&self, body_len: usize) -> [u8; 4] {
        let actual = body_len.saturating_add(4);
        let len = match self {
            Self::Actual => i32::try_from(actual).unwrap_or(i32::MAX),
            Self::TooSmall(raw) => i32::from(*raw % 4),
            Self::SmallerBy(delta) => {
                let shrink = usize::from((*delta % 8) + 1);
                i32::try_from(actual.saturating_sub(shrink)).unwrap_or(0)
            }
            Self::LargerBy(delta) => {
                let grow = usize::from((*delta % 16) + 1);
                i32::try_from(actual.saturating_add(grow)).unwrap_or(i32::MAX)
            }
            Self::Negative => -1,
            Self::Huge(raw) => 64 * 1024 * 1024 + i32::from((*raw % 1024) + 1),
        };
        len.to_be_bytes()
    }

    fn is_actual(&self) -> bool {
        matches!(self, Self::Actual)
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct ColumnSpec {
    name: NamePattern,
    table_oid: u32,
    column_id: i16,
    type_oid: TypeOidSpec,
    type_size: i16,
    type_modifier: i32,
    format_code: FormatCodeSpec,
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
                let ch = char::from(b'a' + (tag % 26));
                format!("{}_{index}", ch.to_string().repeat(width))
            }
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum TypeOidSpec {
    Bool,
    Int2,
    Int4,
    Int8,
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
            Self::Int8 => oid::INT8,
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
struct ByteFlip {
    index: u16,
    mask: u8,
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

fn normalize_scenario(mut scenario: Scenario) -> Scenario {
    scenario.columns.truncate(MAX_COLUMNS);
    scenario.trailing_bytes.truncate(MAX_TRAILING_BYTES);
    scenario
}

fn materialize_columns(columns: &[ColumnSpec]) -> Vec<PgColumn> {
    columns
        .iter()
        .enumerate()
        .map(|(index, spec)| PgColumn {
            name: spec.name.materialize(index),
            table_oid: spec.table_oid,
            column_id: spec.column_id,
            type_oid: spec.type_oid.to_oid(),
            type_size: spec.type_size,
            type_modifier: spec.type_modifier,
            format_code: spec.format_code.to_code(),
        })
        .collect()
}

fn expected_indices(columns: &[PgColumn]) -> BTreeMap<String, usize> {
    let mut indices = BTreeMap::new();
    for (index, column) in columns.iter().enumerate() {
        indices.insert(column.name.clone(), index);
    }
    indices
}

fn build_row_description_body(scenario: &Scenario, columns: &[PgColumn]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&scenario.declared_fields.apply(columns.len()).to_be_bytes());

    for column in columns {
        let mut name_bytes = column.name.as_bytes().to_vec();
        name_bytes.truncate(MAX_NAME_BYTES);
        body.extend_from_slice(&name_bytes);
        body.push(0);
        body.extend_from_slice(&column.table_oid.to_be_bytes());
        body.extend_from_slice(&(column.column_id).to_be_bytes());
        body.extend_from_slice(&(column.type_oid as i32).to_be_bytes());
        body.extend_from_slice(&column.type_size.to_be_bytes());
        body.extend_from_slice(&column.type_modifier.to_be_bytes());
        body.extend_from_slice(&column.format_code.to_be_bytes());
    }

    if let Some(limit) = scenario.truncate_body_at {
        let limit = usize::from(limit) % (body.len().saturating_add(1));
        body.truncate(limit);
    }
    body.extend_from_slice(&scenario.trailing_bytes);
    if let Some(flip) = &scenario.byte_flip
        && !body.is_empty()
    {
        let idx = usize::from(flip.index) % body.len();
        body[idx] ^= flip.mask;
    }

    body
}

fn build_packet(body: &[u8], length: &PacketLengthEncoding) -> Vec<u8> {
    let mut packet = Vec::with_capacity(body.len().saturating_add(5));
    packet.push(b'T');
    packet.extend_from_slice(&length.encode(body.len()));
    packet.extend_from_slice(body);
    packet
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

fn assert_row_description_deterministic(body: &[u8]) -> ParseSummary {
    let first = summarize_parse(fuzz_parse_row_description(body));
    let second = summarize_parse(fuzz_parse_row_description(body));
    assert_eq!(
        first, second,
        "RowDescription parsing must be deterministic for identical bodies"
    );
    first
}

fn is_honest_packet(scenario: &Scenario) -> bool {
    scenario.declared_fields.is_actual()
        && scenario.packet_length.is_actual()
        && scenario.truncate_body_at.is_none()
        && scenario.trailing_bytes.is_empty()
        && scenario.byte_flip.is_none()
}

fuzz_target!(|scenario: Scenario| {
    let scenario = normalize_scenario(scenario);
    let expected_columns = materialize_columns(&scenario.columns);
    let expected_indices = expected_indices(&expected_columns);
    let body = build_row_description_body(&scenario, &expected_columns);
    let packet = build_packet(&body, &scenario.packet_length);

    let cx = Cx::for_testing();
    match block_on(fuzz_read_backend_message(&cx, &packet)) {
        Ok((msg_type, extracted_body)) => {
            assert_eq!(
                msg_type, b'T',
                "target only synthesizes RowDescription packets"
            );
            let summary = assert_row_description_deterministic(&extracted_body);

            if is_honest_packet(&scenario) {
                assert_eq!(
                    extracted_body, body,
                    "honest frame decoding should preserve the RowDescription body"
                );
                assert_eq!(
                    summary,
                    ParseSummary::Ok {
                        columns: expected_columns.iter().map(ColumnSummary::from).collect(),
                        indices: expected_indices,
                    },
                    "honest RowDescription packets should parse exactly as materialized"
                );
            }
        }
        Err(err) => {
            if is_honest_packet(&scenario) {
                panic!("honest RowDescription packet should decode successfully: {err}");
            }
        }
    }
});
