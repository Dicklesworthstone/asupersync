#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::database::mysql::{MySqlColumn, MySqlError, fuzz_parse_column_definition};
use libfuzzer_sys::fuzz_target;

const MAX_FIELD_BYTES: usize = 96;
const MAX_TRAILING_BYTES: usize = 16;

#[derive(Arbitrary, Debug, Clone)]
struct ColumnDefinitionScenario {
    catalog: FieldSpec,
    schema: FieldSpec,
    table: FieldSpec,
    org_table: FieldSpec,
    name: FieldSpec,
    org_name: FieldSpec,
    charset: u16,
    length: u32,
    column_type: u8,
    flags: u16,
    decimals: u8,
    filler: [u8; 2],
    trailing: Vec<u8>,
    truncate_at: Option<u16>,
}

#[derive(Arbitrary, Debug, Clone)]
struct FieldSpec {
    raw: Vec<u8>,
    prefix_width: PrefixWidth,
    declared_length: DeclaredLength,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum PrefixWidth {
    Inline,
    U16,
    U24,
    U64,
}

#[derive(Arbitrary, Debug, Clone)]
enum DeclaredLength {
    Honest,
    ShortBy(u8),
    LongBy(u8),
    NullPrefix,
    InvalidPrefix,
}

#[derive(Debug, Clone)]
struct ExpectedColumn {
    catalog: String,
    schema: String,
    table: String,
    org_table: String,
    name: String,
    org_name: String,
    charset: u16,
    length: u32,
    column_type: u8,
    flags: u16,
    decimals: u8,
}

fuzz_target!(|data: &[u8]| {
    observe_column_definition_parse(data);

    let Ok(scenario) = ColumnDefinitionScenario::arbitrary(&mut Unstructured::new(data)) else {
        return;
    };

    let scenario = normalize_scenario(scenario);
    let (bytes, expected) = build_column_definition(&scenario);
    assert_deterministic(&bytes);

    if let Some(expected) = expected {
        let parsed = fuzz_parse_column_definition(&bytes)
            .expect("honest structured column definition should parse");
        assert_matches(&parsed, &expected);
    }
});

fn observe_column_definition_parse(data: &[u8]) {
    match fuzz_parse_column_definition(data) {
        Ok(column) => {
            let rendered = render_parse_result(Ok(column));
            assert!(
                !rendered.is_empty(),
                "successful column-definition parse should be visible"
            );
        }
        Err(err) => {
            let rendered = format!("{err:?}");
            assert!(
                !rendered.is_empty(),
                "column-definition parse error should be visible"
            );
        }
    }
}

fn normalize_scenario(mut scenario: ColumnDefinitionScenario) -> ColumnDefinitionScenario {
    for spec in [
        &mut scenario.catalog,
        &mut scenario.schema,
        &mut scenario.table,
        &mut scenario.org_table,
        &mut scenario.name,
        &mut scenario.org_name,
    ] {
        spec.raw.truncate(MAX_FIELD_BYTES);
    }

    scenario.trailing.truncate(MAX_TRAILING_BYTES);
    scenario
}

fn build_column_definition(
    scenario: &ColumnDefinitionScenario,
) -> (Vec<u8>, Option<ExpectedColumn>) {
    let mut bytes = Vec::new();
    let mut honest = true;

    let (catalog_bytes, catalog, field_honest) = encode_field(&scenario.catalog);
    bytes.extend_from_slice(&catalog_bytes);
    honest &= field_honest;

    let (schema_bytes, schema, field_honest) = encode_field(&scenario.schema);
    bytes.extend_from_slice(&schema_bytes);
    honest &= field_honest;

    let (table_bytes, table, field_honest) = encode_field(&scenario.table);
    bytes.extend_from_slice(&table_bytes);
    honest &= field_honest;

    let (org_table_bytes, org_table, field_honest) = encode_field(&scenario.org_table);
    bytes.extend_from_slice(&org_table_bytes);
    honest &= field_honest;

    let (name_bytes, name, field_honest) = encode_field(&scenario.name);
    bytes.extend_from_slice(&name_bytes);
    honest &= field_honest;

    let (org_name_bytes, org_name, field_honest) = encode_field(&scenario.org_name);
    bytes.extend_from_slice(&org_name_bytes);
    honest &= field_honest;

    bytes.push(0x0C);
    bytes.extend_from_slice(&scenario.charset.to_le_bytes());
    bytes.extend_from_slice(&scenario.length.to_le_bytes());
    bytes.push(scenario.column_type);
    bytes.extend_from_slice(&scenario.flags.to_le_bytes());
    bytes.push(scenario.decimals);
    bytes.extend_from_slice(&scenario.filler);
    bytes.extend_from_slice(&scenario.trailing);

    if let Some(truncate_at) = scenario.truncate_at {
        bytes.truncate(usize::from(truncate_at).min(bytes.len()));
        honest = false;
    }

    let expected = honest.then_some(ExpectedColumn {
        catalog,
        schema,
        table,
        org_table,
        name,
        org_name,
        charset: scenario.charset,
        length: scenario.length,
        column_type: scenario.column_type,
        flags: scenario.flags,
        decimals: scenario.decimals,
    });

    (bytes, expected)
}

fn encode_field(spec: &FieldSpec) -> (Vec<u8>, String, bool) {
    let value = ascii_string(&spec.raw);
    match spec.declared_length {
        DeclaredLength::NullPrefix => (vec![0xFB], value, false),
        DeclaredLength::InvalidPrefix => (vec![0xFF], value, false),
        DeclaredLength::Honest | DeclaredLength::ShortBy(_) | DeclaredLength::LongBy(_) => {
            let actual_len = value.len();
            let declared_len = match spec.declared_length {
                DeclaredLength::Honest => actual_len,
                DeclaredLength::ShortBy(delta) => {
                    actual_len.saturating_sub(usize::from((delta % 8) + 1))
                }
                DeclaredLength::LongBy(delta) => {
                    actual_len.saturating_add(usize::from((delta % 8) + 1))
                }
                DeclaredLength::NullPrefix | DeclaredLength::InvalidPrefix => unreachable!(),
            };

            let mut encoded = encode_lenenc_int(declared_len as u64, spec.prefix_width);
            encoded.extend_from_slice(value.as_bytes());
            (
                encoded,
                value,
                matches!(spec.declared_length, DeclaredLength::Honest),
            )
        }
    }
}

fn encode_lenenc_int(value: u64, width: PrefixWidth) -> Vec<u8> {
    match width {
        PrefixWidth::Inline => vec![(value & 0xFF) as u8],
        PrefixWidth::U16 => {
            let mut encoded = vec![0xFC];
            encoded.extend_from_slice(&(value as u16).to_le_bytes());
            encoded
        }
        PrefixWidth::U24 => {
            let mut encoded = vec![0xFD];
            encoded.push((value & 0xFF) as u8);
            encoded.push(((value >> 8) & 0xFF) as u8);
            encoded.push(((value >> 16) & 0xFF) as u8);
            encoded
        }
        PrefixWidth::U64 => {
            let mut encoded = vec![0xFE];
            encoded.extend_from_slice(&value.to_le_bytes());
            encoded
        }
    }
}

fn ascii_string(raw: &[u8]) -> String {
    raw.iter()
        .map(|byte| match byte % 4 {
            0 => char::from(b'a' + (byte % 26)),
            1 => char::from(b'0' + (byte % 10)),
            2 => '-',
            _ => '_',
        })
        .collect()
}

fn assert_deterministic(bytes: &[u8]) {
    let first = render_parse_result(fuzz_parse_column_definition(bytes));
    let second = render_parse_result(fuzz_parse_column_definition(bytes));
    assert_eq!(
        first, second,
        "column-definition parsing must be deterministic"
    );
}

fn render_parse_result(result: Result<MySqlColumn, MySqlError>) -> String {
    match result {
        Ok(column) => format!(
            "ok:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{}:{}:{}:{}:{}",
            column.catalog,
            column.schema,
            column.table,
            column.org_table,
            column.name,
            column.org_name,
            column.charset,
            column.length,
            column.column_type,
            column.flags,
            column.decimals
        ),
        Err(err) => format!("err:{err:?}"),
    }
}

fn assert_matches(parsed: &MySqlColumn, expected: &ExpectedColumn) {
    assert_eq!(parsed.catalog, expected.catalog);
    assert_eq!(parsed.schema, expected.schema);
    assert_eq!(parsed.table, expected.table);
    assert_eq!(parsed.org_table, expected.org_table);
    assert_eq!(parsed.name, expected.name);
    assert_eq!(parsed.org_name, expected.org_name);
    assert_eq!(parsed.charset, expected.charset);
    assert_eq!(parsed.length, expected.length);
    assert_eq!(parsed.column_type, expected.column_type);
    assert_eq!(parsed.flags, expected.flags);
    assert_eq!(parsed.decimals, expected.decimals);
}
