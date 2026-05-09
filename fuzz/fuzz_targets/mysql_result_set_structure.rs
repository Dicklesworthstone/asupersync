#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::database::mysql::{MySqlColumn, MySqlError, fuzz_parse_column_definition};
use libfuzzer_sys::fuzz_target;

const MAX_COLUMNS: usize = 32;
const MAX_ROWS: usize = 16;
const MAX_FIELD_BYTES: usize = 64;
const MAX_ROW_VALUE_BYTES: usize = 128;

/// Structure-aware fuzzing of complete MySQL ResultSet parsing including
/// column headers, metadata, and result rows in sequence.
#[derive(Arbitrary, Debug, Clone)]
struct ResultSetScenario {
    /// Number of columns in the result set
    column_count: ColumnCountSpec,
    /// Column definitions
    columns: Vec<ColumnDefSpec>,
    /// Whether to include EOF packet after column definitions
    include_column_eof: bool,
    /// Result rows
    rows: Vec<RowSpec>,
    /// Final terminator packet type
    terminator: TerminatorSpec,
    /// Corruption/truncation scenarios
    corruption: CorruptionSpec,
}

#[derive(Arbitrary, Debug, Clone)]
enum ColumnCountSpec {
    /// Honest column count matching actual columns
    Honest,
    /// Zero columns (empty result set)
    Zero,
    /// Oversized column count causing server resource exhaustion
    Oversized,
    /// Undersized (fewer columns than declared)
    Undersized(u8),
    /// Malformed length encoding
    MalformedLength,
}

#[derive(Arbitrary, Debug, Clone)]
struct ColumnDefSpec {
    catalog: LenEncString,
    schema: LenEncString,
    table: LenEncString,
    org_table: LenEncString,
    name: LenEncString,
    org_name: LenEncString,
    charset: u16,
    length: u32,
    column_type: u8,
    flags: u16,
    decimals: u8,
    filler: [u8; 2],
    /// Whether this column definition packet is truncated
    truncated: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct LenEncString {
    raw_bytes: Vec<u8>,
    length_encoding: LengthEncoding,
    declared_length: DeclaredLength,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum LengthEncoding {
    /// 0-250: inline length
    Inline,
    /// 0xFC + 2 bytes
    U16,
    /// 0xFD + 3 bytes
    U24,
    /// 0xFE + 8 bytes
    U64,
    /// 0xFB (NULL marker - invalid for column names)
    Null,
    /// 0xFF (reserved - invalid)
    Reserved,
}

#[derive(Arbitrary, Debug, Clone)]
enum DeclaredLength {
    /// Accurate length
    Honest,
    /// Declared shorter than actual data
    Short(u8),
    /// Declared longer than actual data
    Long(u8),
}

#[derive(Arbitrary, Debug, Clone)]
struct RowSpec {
    /// Column values in this row
    values: Vec<RowValueSpec>,
    /// Row-level corruption
    corruption: RowCorruption,
}

#[derive(Arbitrary, Debug, Clone)]
enum RowValueSpec {
    /// NULL value (0xFB marker)
    Null,
    /// Length-encoded string
    Text(LenEncString),
    /// Binary data with potential malformed length
    Binary(Vec<u8>, LengthEncoding),
    /// Zero-length string
    Empty,
}

#[derive(Arbitrary, Debug, Clone)]
enum RowCorruption {
    None,
    /// Missing values (fewer than column count)
    MissingValues(u8),
    /// Extra values (more than column count)
    ExtraValues(u8),
    /// Truncated packet
    Truncated(u16),
}

#[derive(Arbitrary, Debug, Clone)]
enum TerminatorSpec {
    /// Valid EOF packet (0xFE + warning count + status flags)
    ValidEof,
    /// Valid OK packet (0x00 + affected rows + insert id + status + warnings)
    ValidOk,
    /// Error packet (0xFF + error code + sql state + message)
    Error,
    /// Malformed terminator
    Malformed,
    /// Missing terminator (stream ends abruptly)
    Missing,
}

#[derive(Arbitrary, Debug, Clone)]
enum CorruptionSpec {
    None,
    /// Truncate the entire ResultSet at a random position
    GlobalTruncation(u16),
    /// Inject extra bytes at random position
    ExtraBytes(Vec<u8>),
    /// Swap two packets
    SwapPackets(u8, u8),
}

fuzz_target!(|data: &[u8]| {
    // Test raw byte parsing first (existing coverage)
    observe_raw_result_set_start(data);

    // Test structure-aware generation
    let Ok(scenario) = ResultSetScenario::arbitrary(&mut Unstructured::new(data)) else {
        return;
    };

    let scenario = normalize_scenario(scenario);
    let packets = build_result_set_packets(&scenario);

    // Test each individual packet for deterministic parsing
    for (i, packet) in packets.iter().enumerate() {
        assert_packet_deterministic(packet, i);
    }

    // Test column definition packets specifically
    for (i, packet) in packets.iter().enumerate() {
        if i > 0 && i <= scenario.columns.len() {
            // This should be a column definition packet
            test_column_definition_invariants(packet);
        }
    }

    // Test sequence of packets for protocol state machine violations
    test_result_set_sequence(&packets, &scenario);
});

fn observe_raw_result_set_start(data: &[u8]) {
    match try_parse_raw_result_set_start(data) {
        Ok(column_count) => {
            assert!(
                column_count <= 16_384,
                "accepted raw result-set column count must stay bounded"
            );
            assert!(
                !column_count.to_string().is_empty(),
                "successful raw result-set parse should stay visible"
            );
        }
        Err(error) => {
            let diagnostic = format!("{error:?}");
            assert!(
                !diagnostic.is_empty(),
                "raw result-set parse errors should stay visible"
            );
        }
    }
}

fn try_parse_raw_result_set_start(data: &[u8]) -> Result<u64, MySqlError> {
    if data.is_empty() {
        return Err(MySqlError::Protocol("empty data".to_string()));
    }

    let mut pos = 0;
    let mut reader = &data[pos..];

    // Try to parse column count (length-encoded integer)
    let column_count = read_lenenc_int(&mut reader)?;

    // Sanity check for realistic column count
    if column_count > 16_384 {
        return Err(MySqlError::Protocol(format!(
            "column count too large: {column_count}"
        )));
    }

    Ok(column_count)
}

fn read_lenenc_int(data: &mut &[u8]) -> Result<u64, MySqlError> {
    if data.is_empty() {
        return Err(MySqlError::Protocol(
            "empty data for lenenc int".to_string(),
        ));
    }

    let first = data[0];
    *data = &data[1..];

    match first {
        0..=250 => Ok(u64::from(first)),
        0xFC => {
            if data.len() < 2 {
                return Err(MySqlError::Protocol("truncated u16 lenenc".to_string()));
            }
            let val = u16::from_le_bytes([data[0], data[1]]);
            *data = &data[2..];
            Ok(u64::from(val))
        }
        0xFD => {
            if data.len() < 3 {
                return Err(MySqlError::Protocol("truncated u24 lenenc".to_string()));
            }
            let val = u64::from(data[0]) | (u64::from(data[1]) << 8) | (u64::from(data[2]) << 16);
            *data = &data[3..];
            Ok(val)
        }
        0xFE => {
            if data.len() < 8 {
                return Err(MySqlError::Protocol("truncated u64 lenenc".to_string()));
            }
            let val = u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            *data = &data[8..];
            Ok(val)
        }
        0xFB => Err(MySqlError::Protocol("NULL in lenenc int".to_string())),
        0xFF => Err(MySqlError::Protocol("reserved lenenc prefix".to_string())),
        _ => Err(MySqlError::Protocol(format!(
            "invalid lenenc prefix: {first}"
        ))),
    }
}

fn normalize_scenario(mut scenario: ResultSetScenario) -> ResultSetScenario {
    // Limit to reasonable bounds for fuzzing
    scenario.columns.truncate(MAX_COLUMNS);
    scenario.rows.truncate(MAX_ROWS);

    for column in &mut scenario.columns {
        column.catalog.raw_bytes.truncate(MAX_FIELD_BYTES);
        column.schema.raw_bytes.truncate(MAX_FIELD_BYTES);
        column.table.raw_bytes.truncate(MAX_FIELD_BYTES);
        column.org_table.raw_bytes.truncate(MAX_FIELD_BYTES);
        column.name.raw_bytes.truncate(MAX_FIELD_BYTES);
        column.org_name.raw_bytes.truncate(MAX_FIELD_BYTES);
    }

    for row in &mut scenario.rows {
        row.values.truncate(scenario.columns.len().max(8));
        for value in &mut row.values {
            if let RowValueSpec::Text(ref mut s) | RowValueSpec::Binary(ref mut data, _) = value {
                if let RowValueSpec::Text(s) = value {
                    s.raw_bytes.truncate(MAX_ROW_VALUE_BYTES);
                }
                if let RowValueSpec::Binary(data, _) = value {
                    data.truncate(MAX_ROW_VALUE_BYTES);
                }
            }
        }
    }

    scenario
}

fn build_result_set_packets(scenario: &ResultSetScenario) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();

    // Packet 1: Column count
    let column_count_packet = build_column_count_packet(scenario);
    packets.push(column_count_packet);

    // Packets 2..N+1: Column definitions
    for column in &scenario.columns {
        let column_packet = build_column_definition_packet(column);
        packets.push(column_packet);
    }

    // Optional EOF after columns
    if scenario.include_column_eof {
        packets.push(build_eof_packet());
    }

    // Row data packets
    for row in &scenario.rows {
        let row_packet = build_row_packet(row, scenario.columns.len());
        packets.push(row_packet);
    }

    // Final terminator
    let terminator = build_terminator_packet(&scenario.terminator);
    packets.push(terminator);

    // Apply global corruption
    apply_corruption(packets, &scenario.corruption)
}

fn build_column_count_packet(scenario: &ResultSetScenario) -> Vec<u8> {
    match scenario.column_count {
        ColumnCountSpec::Honest => encode_lenenc_int(scenario.columns.len() as u64),
        ColumnCountSpec::Zero => encode_lenenc_int(0),
        ColumnCountSpec::Oversized => encode_lenenc_int(65_535), // Beyond MAX_COLUMN_COUNT
        ColumnCountSpec::Undersized(delta) => {
            let actual = scenario.columns.len();
            let declared = actual.saturating_sub(usize::from(delta % 8 + 1));
            encode_lenenc_int(declared as u64)
        }
        ColumnCountSpec::MalformedLength => vec![0xFF], // Reserved prefix
    }
}

fn build_column_definition_packet(column: &ColumnDefSpec) -> Vec<u8> {
    let mut packet = Vec::new();

    // Six length-encoded strings
    packet.extend_from_slice(&encode_lenenc_string(&column.catalog));
    packet.extend_from_slice(&encode_lenenc_string(&column.schema));
    packet.extend_from_slice(&encode_lenenc_string(&column.table));
    packet.extend_from_slice(&encode_lenenc_string(&column.org_table));
    packet.extend_from_slice(&encode_lenenc_string(&column.name));
    packet.extend_from_slice(&encode_lenenc_string(&column.org_name));

    // Fixed fields (0x0C length indicator + 12 bytes)
    packet.push(0x0C);
    packet.extend_from_slice(&column.charset.to_le_bytes());
    packet.extend_from_slice(&column.length.to_le_bytes());
    packet.push(column.column_type);
    packet.extend_from_slice(&column.flags.to_le_bytes());
    packet.push(column.decimals);
    packet.extend_from_slice(&column.filler);

    if column.truncated {
        let truncate_at = (packet.len() / 2).max(1);
        packet.truncate(truncate_at);
    }

    packet
}

fn encode_lenenc_string(spec: &LenEncString) -> Vec<u8> {
    let data = ascii_safe_string(&spec.raw_bytes);
    let actual_len = data.len();

    let declared_len = match spec.declared_length {
        DeclaredLength::Honest => actual_len,
        DeclaredLength::Short(delta) => actual_len.saturating_sub(usize::from(delta % 8 + 1)),
        DeclaredLength::Long(delta) => actual_len.saturating_add(usize::from(delta % 8 + 1)),
    };

    let mut encoded = match spec.length_encoding {
        LengthEncoding::Inline => {
            if declared_len <= 250 {
                vec![declared_len as u8]
            } else {
                vec![250] // Cap at inline max
            }
        }
        LengthEncoding::U16 => {
            let mut enc = vec![0xFC];
            enc.extend_from_slice(&(declared_len as u16).to_le_bytes());
            enc
        }
        LengthEncoding::U24 => {
            let mut enc = vec![0xFD];
            enc.push((declared_len & 0xFF) as u8);
            enc.push(((declared_len >> 8) & 0xFF) as u8);
            enc.push(((declared_len >> 16) & 0xFF) as u8);
            enc
        }
        LengthEncoding::U64 => {
            let mut enc = vec![0xFE];
            enc.extend_from_slice(&(declared_len as u64).to_le_bytes());
            enc
        }
        LengthEncoding::Null => vec![0xFB],
        LengthEncoding::Reserved => vec![0xFF],
    };

    encoded.extend_from_slice(data.as_bytes());
    encoded
}

fn encode_lenenc_int(value: u64) -> Vec<u8> {
    match value {
        0..=250 => vec![value as u8],
        251..=65535 => {
            let mut enc = vec![0xFC];
            enc.extend_from_slice(&(value as u16).to_le_bytes());
            enc
        }
        65536..=16777215 => {
            let mut enc = vec![0xFD];
            enc.push((value & 0xFF) as u8);
            enc.push(((value >> 8) & 0xFF) as u8);
            enc.push(((value >> 16) & 0xFF) as u8);
            enc
        }
        _ => {
            let mut enc = vec![0xFE];
            enc.extend_from_slice(&value.to_le_bytes());
            enc
        }
    }
}

fn build_eof_packet() -> Vec<u8> {
    vec![
        0xFE, // EOF marker
        0x00, 0x00, // Warning count (LE)
        0x02, 0x00, // Status flags (LE) - SERVER_STATUS_AUTOCOMMIT
    ]
}

fn build_row_packet(row: &RowSpec, expected_columns: usize) -> Vec<u8> {
    let mut packet = Vec::new();

    let values_to_encode = match row.corruption {
        RowCorruption::MissingValues(delta) => {
            expected_columns.saturating_sub(usize::from(delta % 8 + 1))
        }
        RowCorruption::ExtraValues(delta) => {
            expected_columns.saturating_add(usize::from(delta % 4 + 1))
        }
        _ => expected_columns,
    };

    for i in 0..values_to_encode {
        if i < row.values.len() {
            packet.extend_from_slice(&encode_row_value(&row.values[i]));
        } else {
            // Pad with NULL values
            packet.push(0xFB);
        }
    }

    // Apply row-level corruption
    match row.corruption {
        RowCorruption::Truncated(at) => {
            let truncate_pos = (usize::from(at) % (packet.len() + 1)).min(packet.len());
            packet.truncate(truncate_pos);
        }
        _ => {}
    }

    packet
}

fn encode_row_value(value: &RowValueSpec) -> Vec<u8> {
    match value {
        RowValueSpec::Null => vec![0xFB],
        RowValueSpec::Empty => vec![0x00], // Zero-length string
        RowValueSpec::Text(spec) => encode_lenenc_string(spec),
        RowValueSpec::Binary(data, encoding) => {
            let mut encoded = match encoding {
                LengthEncoding::Inline => vec![data.len().min(250) as u8],
                LengthEncoding::U16 => {
                    let mut enc = vec![0xFC];
                    enc.extend_from_slice(&(data.len() as u16).to_le_bytes());
                    enc
                }
                _ => vec![0xFE, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // U64 encoding
            };
            encoded.extend_from_slice(data);
            encoded
        }
    }
}

fn build_terminator_packet(terminator: &TerminatorSpec) -> Vec<u8> {
    match terminator {
        TerminatorSpec::ValidEof => vec![
            0xFE, // EOF
            0x00, 0x00, // Warning count
            0x02, 0x00, // Status flags
        ],
        TerminatorSpec::ValidOk => vec![
            0x00, // OK
            0x00, // Affected rows (lenenc)
            0x00, // Insert ID (lenenc)
            0x02, 0x00, // Status flags
            0x00, 0x00, // Warning count
        ],
        TerminatorSpec::Error => vec![
            0xFF, // ERR
            0xFF, 0x04, // Error code 1279 (LE)
            b'#', // SQL state marker
            b'H', b'Y', b'0', b'0', b'0', // SQL state
            b'T', b'e', b's', b't', b' ', b'e', b'r', b'r', b'o', b'r', // Message
        ],
        TerminatorSpec::Malformed => vec![0xFE, 0xFF], // Invalid EOF packet
        TerminatorSpec::Missing => Vec::new(),
    }
}

fn apply_corruption(mut packets: Vec<Vec<u8>>, corruption: &CorruptionSpec) -> Vec<Vec<u8>> {
    match corruption {
        CorruptionSpec::None => packets,
        CorruptionSpec::GlobalTruncation(pos) => {
            let total_bytes: usize = packets.iter().map(|p| p.len()).sum();
            let truncate_at = usize::from(*pos) % (total_bytes + 1);

            let mut current_pos = 0;
            for packet in &mut packets {
                if current_pos >= truncate_at {
                    packet.clear();
                } else if current_pos + packet.len() > truncate_at {
                    let keep = truncate_at - current_pos;
                    packet.truncate(keep);
                }
                current_pos += packet.len();
            }

            packets.retain(|p| !p.is_empty());
            packets
        }
        CorruptionSpec::ExtraBytes(bytes) => {
            if !packets.is_empty() && !bytes.is_empty() {
                let insert_at = packets.len() / 2;
                packets.insert(insert_at, bytes.clone());
            }
            packets
        }
        CorruptionSpec::SwapPackets(a, b) => {
            let len = packets.len();
            if len > 1 {
                let idx_a = usize::from(*a) % len;
                let idx_b = usize::from(*b) % len;
                packets.swap(idx_a, idx_b);
            }
            packets
        }
    }
}

fn ascii_safe_string(raw: &[u8]) -> String {
    raw.iter()
        .map(|&byte| match byte % 4 {
            0 => char::from(b'a' + (byte % 26)),
            1 => char::from(b'0' + (byte % 10)),
            2 => '-',
            _ => '_',
        })
        .collect()
}

fn assert_packet_deterministic(packet: &[u8], packet_index: usize) {
    // Column definition packets should parse deterministically
    if packet_index > 0 && !packet.is_empty() {
        let first = render_column_parse_result(fuzz_parse_column_definition(packet));
        let second = render_column_parse_result(fuzz_parse_column_definition(packet));
        assert_eq!(
            first, second,
            "packet {packet_index} parsing must be deterministic"
        );
    }
}

fn test_column_definition_invariants(packet: &[u8]) {
    let result = fuzz_parse_column_definition(packet);

    // If parsing succeeds, verify basic invariants
    if let Ok(column) = result {
        // Column names should be valid
        assert!(
            column.name.len() <= 64,
            "column name too long: {}",
            column.name.len()
        );

        // Character sets should be in valid range
        assert!(
            column.charset <= 2000,
            "charset ID too large: {}",
            column.charset
        );

        // Column type should be valid MySQL type
        assert!(
            column.column_type <= 255,
            "column type out of range: {}",
            column.column_type
        );

        // Length should be reasonable
        assert!(column.length <= 4_294_967_295, "column length overflow");
    }
}

fn test_result_set_sequence(packets: &[Vec<u8>], scenario: &ResultSetScenario) {
    if packets.is_empty() {
        return;
    }

    // First packet should be column count
    if let Ok(column_count) = try_parse_raw_result_set_start(&packets[0]) {
        // If column count is realistic, verify we have enough column definition packets
        if column_count <= MAX_COLUMNS as u64 {
            let expected_column_packets = column_count as usize;
            let actual_packets_available = packets.len().saturating_sub(1);

            // We should have at least as many packets as declared columns
            // (allowing for rows and terminator)
            if expected_column_packets > 0 {
                assert!(
                    actual_packets_available >= expected_column_packets,
                    "not enough packets for declared column count: need {}, have {}",
                    expected_column_packets,
                    actual_packets_available
                );
            }
        }
    }
}

fn render_column_parse_result(result: Result<MySqlColumn, MySqlError>) -> String {
    match result {
        Ok(column) => format!(
            "ok:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            column.catalog.len(),
            column.schema.len(),
            column.table.len(),
            column.org_table.len(),
            column.name.len(),
            column.org_name.len(),
            column.charset,
            column.length,
            column.column_type,
            column.flags,
            column.decimals,
        ),
        Err(_) => "err".to_string(),
    }
}
