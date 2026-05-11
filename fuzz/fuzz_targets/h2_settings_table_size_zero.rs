#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::http::h2::{Header, HpackDecoder, HpackEncoder};
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;

const MAX_PRODUCTION_TABLE_SIZE: usize = 1024 * 1024;
const MAX_PRODUCTION_INITIAL_ENTRIES: usize = 8;
const MAX_PRODUCTION_BLOCKS: usize = 4;
const MAX_PRODUCTION_HEADERS: usize = 8;
const MAX_PRODUCTION_COMPONENT_LEN: usize = 96;

/// HTTP/2 SETTINGS_HEADER_TABLE_SIZE=0 HPACK fuzz target.
///
/// Tests HPACK dynamic table eviction when peer sends SETTINGS_HEADER_TABLE_SIZE=0,
/// which forces immediate eviction of all dynamic table entries. This is a critical
/// edge case for HPACK decoders that must handle complete table eviction without
/// corrupting state or panicking.
///
/// RFC 7541 §4.2: "A change in the maximum size of the dynamic table is signaled
/// via a dynamic table size update. This dynamic table size update MUST occur at
/// the beginning of the first header block that is encoded after the change to
/// the dynamic table size."
///
/// Critical test scenarios:
/// - Complete dynamic table eviction (size 0)
/// - Table state consistency after eviction
/// - Subsequent header block processing
/// - Index references after eviction (must be invalid)

#[derive(Arbitrary, Debug, Clone)]
struct HpackTableInput {
    /// Initial dynamic table size
    initial_table_size: u32,

    /// Pre-populate dynamic table with entries
    initial_entries: Vec<HpackEntry>,

    /// New table size setting (should be 0 for this test)
    new_table_size: u32,

    /// Header blocks to process after size change
    header_blocks: Vec<HpackHeaderBlock>,

    /// Decoder configuration
    decoder_config: HpackDecoderConfig,
}

#[derive(Arbitrary, Debug, Clone)]
struct HpackEntry {
    name: String,
    value: String,
    /// Whether this entry is sensitive (affects eviction order)
    sensitive: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct HpackHeaderBlock {
    /// Dynamic table size update (if any)
    table_size_update: Option<u32>,

    /// Header representations in this block
    headers: Vec<HpackRepresentation>,

    /// Expected processing result
    expected_result: ExpectedResult,
}

#[derive(Arbitrary, Debug, Clone)]
enum HpackRepresentation {
    /// Index reference (dynamic or static table)
    IndexedHeader { index: u8 },

    /// Literal header with incremental indexing
    LiteralIncremental {
        name_index: Option<u8>,
        name: String,
        value: String,
    },

    /// Literal header without indexing
    LiteralNoIndex {
        name_index: Option<u8>,
        name: String,
        value: String,
    },

    /// Literal header never indexed (sensitive)
    LiteralNeverIndex {
        name_index: Option<u8>,
        name: String,
        value: String,
    },

    /// Dynamic table size update
    TableSizeUpdate { size: u32 },
}

#[derive(Arbitrary, Debug, Clone)]
enum ExpectedResult {
    Success,
    DecodingError,
    ImplementationDefined,
}

#[derive(Arbitrary, Debug, Clone)]
struct HpackDecoderConfig {
    /// Maximum allowed table size
    max_table_size: u32,

    /// Whether to track eviction statistics
    track_evictions: bool,

    /// Eviction strategy
    eviction_strategy: EvictionStrategy,

    /// Whether to validate index references strictly
    strict_index_validation: bool,
}

impl Default for HpackDecoderConfig {
    fn default() -> Self {
        Self {
            max_table_size: 4096, // RFC 7541 default
            track_evictions: true,
            eviction_strategy: EvictionStrategy::Fifo,
            strict_index_validation: true,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, PartialEq)]
enum EvictionStrategy {
    /// First-in, first-out (RFC 7541 requirement)
    Fifo,
    /// Evict all immediately on size reduction
    Immediate,
    /// Evict by size priority
    BySize,
}

/// Mock HPACK decoder for testing dynamic table eviction
struct MockHpackDecoder {
    /// Current dynamic table size limit
    table_size: u32,

    /// Dynamic table entries (FIFO order)
    dynamic_table: VecDeque<HpackTableEntry>,

    /// Current dynamic table memory usage
    current_size: u32,

    /// Static table (RFC 7541 Appendix A - simplified)
    static_table: Vec<HpackTableEntry>,

    /// Configuration
    config: HpackDecoderConfig,

    /// Eviction statistics
    eviction_stats: EvictionStats,
}

#[derive(Debug, Clone)]
struct HpackTableEntry {
    name: String,
    value: String,
    size: u32, // name.len() + value.len() + 32 per RFC 7541 §4.1
    sensitive: bool,
}

#[derive(Debug, Clone, Default)]
struct EvictionStats {
    total_evictions: u32,
    evictions_by_size_update: u32,
    evictions_by_overflow: u32,
    zero_size_evictions: u32,
}

impl MockHpackDecoder {
    fn new(config: HpackDecoderConfig) -> Self {
        let static_table = Self::build_static_table();

        Self {
            table_size: config.max_table_size,
            dynamic_table: VecDeque::new(),
            current_size: 0,
            static_table,
            config,
            eviction_stats: EvictionStats::default(),
        }
    }

    fn build_static_table() -> Vec<HpackTableEntry> {
        // Simplified static table (RFC 7541 Appendix A subset)
        vec![
            HpackTableEntry {
                name: ":authority".to_string(),
                value: "".to_string(),
                size: 42,
                sensitive: false,
            },
            HpackTableEntry {
                name: ":method".to_string(),
                value: "GET".to_string(),
                size: 42,
                sensitive: false,
            },
            HpackTableEntry {
                name: ":method".to_string(),
                value: "POST".to_string(),
                size: 43,
                sensitive: false,
            },
            HpackTableEntry {
                name: ":path".to_string(),
                value: "/".to_string(),
                size: 37,
                sensitive: false,
            },
            HpackTableEntry {
                name: ":scheme".to_string(),
                value: "http".to_string(),
                size: 43,
                sensitive: false,
            },
        ]
    }

    /// Process dynamic table size update per RFC 7541 §4.2
    fn update_table_size(&mut self, new_size: u32) -> TableUpdateResult {
        let old_size = self.table_size;
        let old_entries = self.dynamic_table.len();

        if new_size > self.config.max_table_size {
            return TableUpdateResult::Error(format!(
                "New size {} exceeds maximum {}",
                new_size, self.config.max_table_size
            ));
        }

        self.table_size = new_size;

        // RFC 7541 §4.2: "Whenever the maximum size for the dynamic table is reduced,
        // entries are evicted from the end of the dynamic table until the size of
        // the dynamic table is less than or equal to the maximum size."
        let evicted_count = self.evict_to_size(new_size);

        if self.config.track_evictions {
            self.eviction_stats.evictions_by_size_update += evicted_count;
            if new_size == 0 {
                self.eviction_stats.zero_size_evictions += evicted_count;
            }
        }

        TableUpdateResult::Updated {
            old_size,
            new_size,
            old_entries,
            new_entries: self.dynamic_table.len(),
            evicted_count,
        }
    }

    fn evict_to_size(&mut self, target_size: u32) -> u32 {
        let mut evicted = 0;
        let _eviction_strategy = &self.config.eviction_strategy;

        if target_size == 0 {
            // Complete eviction for zero size
            let sensitive_evictions = self
                .dynamic_table
                .iter()
                .filter(|entry| entry.sensitive)
                .count();
            debug_assert!(sensitive_evictions <= self.dynamic_table.len());
            evicted = self.dynamic_table.len() as u32;
            self.dynamic_table.clear();
            self.current_size = 0;
            self.eviction_stats.total_evictions += evicted;
            return evicted;
        }

        // RFC 7541 §4.4: Evict from end (oldest entries first)
        while self.current_size > target_size && !self.dynamic_table.is_empty() {
            if let Some(entry) = self.dynamic_table.pop_back() {
                self.current_size = self.current_size.saturating_sub(entry.size);
                evicted += 1;
            }
        }

        self.eviction_stats.total_evictions += evicted;
        evicted
    }

    /// Decode header block with potential table size updates
    fn decode_header_block(&mut self, block: &HpackHeaderBlock) -> HeaderBlockResult {
        let mut decoded_headers = Vec::new();

        // Process table size update first if present
        if let Some(size_update) = block.table_size_update {
            let update_result = self.update_table_size(size_update);
            if let TableUpdateResult::Error(msg) = update_result {
                return HeaderBlockResult::Error(format!("Table size update failed: {}", msg));
            }
        }

        // Process each header representation
        for repr in &block.headers {
            match self.process_representation(repr) {
                Ok(header) => {
                    if let Some(h) = header {
                        decoded_headers.push(h);
                    }
                }
                Err(msg) => {
                    return HeaderBlockResult::Error(msg);
                }
            }
        }

        HeaderBlockResult::Success {
            headers: decoded_headers,
            table_entries: self.dynamic_table.len(),
            table_size: self.current_size,
        }
    }

    fn process_representation(
        &mut self,
        repr: &HpackRepresentation,
    ) -> Result<Option<(String, String)>, String> {
        match repr {
            HpackRepresentation::IndexedHeader { index } => self.get_header_by_index(*index),

            HpackRepresentation::LiteralIncremental {
                name_index,
                name,
                value,
            } => {
                let header_name = if let Some(idx) = name_index {
                    self.get_name_by_index(*idx)?
                } else {
                    name.clone()
                };

                // Add to dynamic table
                self.add_to_dynamic_table(header_name.clone(), value.clone(), false)?;
                Ok(Some((header_name, value.clone())))
            }

            HpackRepresentation::LiteralNoIndex {
                name_index,
                name,
                value,
            } => {
                let header_name = if let Some(idx) = name_index {
                    self.get_name_by_index(*idx)?
                } else {
                    name.clone()
                };
                Ok(Some((header_name, value.clone())))
            }

            HpackRepresentation::LiteralNeverIndex {
                name_index,
                name,
                value,
            } => {
                let header_name = if let Some(idx) = name_index {
                    self.get_name_by_index(*idx)?
                } else {
                    name.clone()
                };
                Ok(Some((header_name, value.clone())))
            }

            HpackRepresentation::TableSizeUpdate { size } => {
                let update_result = self.update_table_size(*size);
                match update_result {
                    TableUpdateResult::Error(msg) => Err(msg),
                    _ => Ok(None), // No header output for size updates
                }
            }
        }
    }

    fn get_header_by_index(&self, index: u8) -> Result<Option<(String, String)>, String> {
        let index = index as usize;

        if index == 0 {
            return Err("Index 0 is invalid".to_string());
        }

        // Static table first
        if index <= self.static_table.len() {
            let entry = &self.static_table[index - 1];
            return Ok(Some((entry.name.clone(), entry.value.clone())));
        }

        // Dynamic table
        let dynamic_index = index - self.static_table.len() - 1;
        if dynamic_index >= self.dynamic_table.len() {
            if !self.config.strict_index_validation {
                return Ok(None);
            }
            return Err(format!(
                "Dynamic table index {} out of range (table size {})",
                dynamic_index,
                self.dynamic_table.len()
            ));
        }

        let entry = &self.dynamic_table[dynamic_index];
        Ok(Some((entry.name.clone(), entry.value.clone())))
    }

    fn get_name_by_index(&self, index: u8) -> Result<String, String> {
        if let Ok(Some((name, _))) = self.get_header_by_index(index) {
            Ok(name)
        } else {
            Err(format!("Cannot get name for index {}", index))
        }
    }

    fn add_to_dynamic_table(
        &mut self,
        name: String,
        value: String,
        sensitive: bool,
    ) -> Result<(), String> {
        if self.table_size == 0 {
            // Cannot add to zero-size table
            return Ok(());
        }

        let entry_size = (name.len() + value.len() + 32) as u32; // RFC 7541 §4.1

        if entry_size > self.table_size {
            // Entry too large for table
            return Ok(());
        }

        // Make space by evicting if necessary
        while self.current_size + entry_size > self.table_size && !self.dynamic_table.is_empty() {
            if let Some(evicted) = self.dynamic_table.pop_back() {
                self.current_size = self.current_size.saturating_sub(evicted.size);
                self.eviction_stats.evictions_by_overflow += 1;
                self.eviction_stats.total_evictions += 1;
            }
        }

        if self.current_size + entry_size <= self.table_size {
            let entry = HpackTableEntry {
                name,
                value,
                size: entry_size,
                sensitive,
            };

            self.dynamic_table.push_front(entry);
            self.current_size += entry_size;
        }

        Ok(())
    }

    fn get_table_state(&self) -> TableState {
        TableState {
            size_limit: self.table_size,
            current_size: self.current_size,
            entry_count: self.dynamic_table.len(),
            eviction_stats: self.eviction_stats.clone(),
        }
    }
}

#[derive(Debug, PartialEq)]
enum TableUpdateResult {
    Updated {
        old_size: u32,
        new_size: u32,
        old_entries: usize,
        new_entries: usize,
        evicted_count: u32,
    },
    Error(String),
}

#[derive(Debug, PartialEq)]
enum HeaderBlockResult {
    Success {
        headers: Vec<(String, String)>,
        table_entries: usize,
        table_size: u32,
    },
    Error(String),
}

#[derive(Debug, Clone)]
struct TableState {
    size_limit: u32,
    current_size: u32,
    entry_count: usize,
    eviction_stats: EvictionStats,
}

fuzz_target!(|input: HpackTableInput| {
    // Normalize input for reasonable fuzzing bounds
    let mut input = input;
    if input.new_table_size > 100000 {
        input.new_table_size = 0; // Focus on zero case
    }

    exercise_production_hpack_zero_size(&input);

    let mut decoder = MockHpackDecoder::new(input.decoder_config.clone());

    // Set initial table size
    let initial_update = decoder.update_table_size(input.initial_table_size);
    if let TableUpdateResult::Error(_) = initial_update {
        return; // Invalid initial config
    }

    // Pre-populate dynamic table
    for entry in input.initial_entries.iter().take(10) {
        // Limit for performance
        let _ =
            decoder.add_to_dynamic_table(entry.name.clone(), entry.value.clone(), entry.sensitive);
    }

    let initial_state = decoder.get_table_state();

    // Test the critical zero table size update
    let zero_update_result = decoder.update_table_size(input.new_table_size);

    match zero_update_result {
        TableUpdateResult::Updated {
            evicted_count,
            new_size,
            new_entries,
            ..
        } => {
            if input.new_table_size == 0 {
                // Verify complete eviction for zero size
                assert_eq!(
                    new_entries, 0,
                    "Dynamic table should be empty after size=0 update"
                );
                assert_eq!(
                    decoder.current_size, 0,
                    "Current size should be zero after size=0 update"
                );

                if initial_state.entry_count > 0 {
                    assert!(
                        evicted_count > 0,
                        "Should have evicted entries when reducing to zero size"
                    );
                }
            }

            assert_eq!(
                new_size, input.new_table_size,
                "Table size should match new setting"
            );
        }

        TableUpdateResult::Error(_) => {
            // Errors are acceptable for invalid sizes
        }
    }

    let post_update_state = decoder.get_table_state();
    assert!(
        post_update_state.current_size <= post_update_state.size_limit,
        "Post-update table size should not exceed limit"
    );

    // Test subsequent header block processing
    for (block_idx, block) in input.header_blocks.iter().enumerate().take(3) {
        // Limit for performance
        let _expected_result = &block.expected_result;
        let decode_result = decoder.decode_header_block(block);

        match decode_result {
            HeaderBlockResult::Success {
                table_entries,
                table_size,
                ..
            } => {
                // Verify table constraints are maintained
                if input.new_table_size == 0 {
                    assert_eq!(
                        table_entries, 0,
                        "Dynamic table should remain empty with zero size limit"
                    );
                    assert_eq!(table_size, 0, "Table size should remain zero");
                }

                assert!(
                    table_size <= decoder.table_size,
                    "Current table size {} should not exceed limit {}",
                    table_size,
                    decoder.table_size
                );
            }

            HeaderBlockResult::Error(ref msg) => {
                // Check if error is related to invalid index references after eviction
                if input.new_table_size == 0 {
                    // Index references to dynamic table should fail after zero-size eviction
                    for repr in &block.headers {
                        if let HpackRepresentation::IndexedHeader { index } = repr
                            && *index as usize > decoder.static_table.len()
                        {
                            assert!(
                                msg.contains("out of range") || msg.contains("invalid"),
                                "Block {} should properly detect invalid dynamic table references: {}",
                                block_idx,
                                msg
                            );
                            break;
                        }
                    }
                }
            }
        }
    }

    // Verify eviction statistics consistency
    let final_state = decoder.get_table_state();
    let stats = &final_state.eviction_stats;

    assert_eq!(
        stats.evictions_by_size_update + stats.evictions_by_overflow,
        stats.total_evictions,
        "Eviction statistics should be consistent"
    );

    if input.new_table_size == 0 && initial_state.entry_count > 0 {
        assert!(
            stats.zero_size_evictions > 0,
            "Should track zero-size evictions"
        );
    }

    // Verify no panics occurred during zero-size handling
    // (Implicit - if we reach here without panicking, the test passed)

    // Additional consistency checks
    assert!(
        final_state.current_size <= final_state.size_limit,
        "Final table size should not exceed limit"
    );

    if final_state.size_limit == 0 {
        assert_eq!(
            final_state.entry_count, 0,
            "Zero size limit should result in empty table"
        );
        assert_eq!(
            final_state.current_size, 0,
            "Zero size limit should result in zero current size"
        );
    }
});

fn exercise_production_hpack_zero_size(input: &HpackTableInput) {
    let initial_size = bounded_production_table_size(input.initial_table_size);
    let mut encoder = HpackEncoder::with_max_size(initial_size);
    let mut decoder = HpackDecoder::with_max_size(initial_size);
    decoder.set_allowed_table_size(initial_size);

    production_encode_decode_headers(
        &mut encoder,
        &mut decoder,
        &initial_production_headers(input),
        input
            .initial_entries
            .iter()
            .take(MAX_PRODUCTION_INITIAL_ENTRIES)
            .any(|entry| entry.sensitive),
    );

    production_apply_zero_table_size(&mut encoder, &mut decoder);

    for (block_index, block) in input
        .header_blocks
        .iter()
        .take(MAX_PRODUCTION_BLOCKS)
        .enumerate()
    {
        if let Some(update) = block.table_size_update {
            let size = if update == 0 {
                0
            } else {
                bounded_production_table_size(update)
            };
            production_apply_table_size(&mut encoder, &mut decoder, size);
            if size != 0 {
                production_apply_zero_table_size(&mut encoder, &mut decoder);
            }
        }

        let headers = block_production_headers(block, block_index);
        production_encode_decode_headers(
            &mut encoder,
            &mut decoder,
            &headers,
            block
                .headers
                .iter()
                .any(|repr| matches!(repr, HpackRepresentation::LiteralNeverIndex { .. })),
        );

        assert_eq!(
            encoder.dynamic_table_size(),
            0,
            "encoder dynamic table must stay empty after zero table size"
        );
        assert_eq!(
            decoder.dynamic_table_size(),
            0,
            "decoder dynamic table must stay empty after zero table size"
        );
    }
}

fn production_apply_zero_table_size(encoder: &mut HpackEncoder, decoder: &mut HpackDecoder) {
    production_apply_table_size(encoder, decoder, 0);
    assert_eq!(
        encoder.dynamic_table_size(),
        0,
        "encoder must evict every dynamic entry after table size zero"
    );
    assert_eq!(
        decoder.dynamic_table_size(),
        0,
        "decoder must evict every dynamic entry after table size zero"
    );
}

fn production_apply_table_size(
    encoder: &mut HpackEncoder,
    decoder: &mut HpackDecoder,
    size: usize,
) {
    encoder.set_max_table_size(size);
    decoder.set_allowed_table_size(size);

    let mut encoded = BytesMut::new();
    encoder.encode(&[], &mut encoded);
    let decoded = decoder
        .decode(&mut encoded.freeze())
        .expect("production HPACK table-size update must decode");
    assert!(
        decoded.is_empty(),
        "table-size update block should not produce headers"
    );
    assert!(
        encoder.dynamic_table_size() <= encoder.dynamic_table_max_size(),
        "encoder table exceeds configured maximum"
    );
    assert!(
        decoder.dynamic_table_size() <= decoder.dynamic_table_max_size(),
        "decoder table exceeds configured maximum"
    );
}

fn production_encode_decode_headers(
    encoder: &mut HpackEncoder,
    decoder: &mut HpackDecoder,
    headers: &[Header],
    sensitive: bool,
) {
    let mut encoded = BytesMut::new();
    if sensitive {
        encoder.encode_sensitive(headers, &mut encoded);
    } else {
        encoder.encode(headers, &mut encoded);
    }

    let decoded = decoder
        .decode(&mut encoded.freeze())
        .expect("production HPACK block encoded by local encoder must decode");
    assert_eq!(
        decoded, headers,
        "production HPACK round-trip changed headers"
    );
    assert!(
        encoder.dynamic_table_size() <= encoder.dynamic_table_max_size(),
        "encoder table exceeds configured maximum after header block"
    );
    assert!(
        decoder.dynamic_table_size() <= decoder.dynamic_table_max_size(),
        "decoder table exceeds configured maximum after header block"
    );
}

fn initial_production_headers(input: &HpackTableInput) -> Vec<Header> {
    let mut headers: Vec<Header> = input
        .initial_entries
        .iter()
        .take(MAX_PRODUCTION_INITIAL_ENTRIES)
        .enumerate()
        .map(|(index, entry)| {
            Header::new(
                normalized_header_name(&entry.name, "x-initial", index),
                bounded_visible_ascii(&entry.value, "value", MAX_PRODUCTION_COMPONENT_LEN),
            )
        })
        .collect();

    if headers.is_empty() {
        headers.push(Header::new(":method", "GET"));
        headers.push(Header::new(":path", "/"));
        headers.push(Header::new(":scheme", "https"));
        headers.push(Header::new(":authority", "example.test"));
        headers.push(Header::new("x-seed", "value"));
    }

    headers
}

fn block_production_headers(block: &HpackHeaderBlock, block_index: usize) -> Vec<Header> {
    let mut headers = Vec::new();

    for (header_index, repr) in block
        .headers
        .iter()
        .take(MAX_PRODUCTION_HEADERS)
        .enumerate()
    {
        match repr {
            HpackRepresentation::IndexedHeader { index } => {
                headers.push(static_or_fallback_header(*index, block_index, header_index));
            }
            HpackRepresentation::LiteralIncremental { name, value, .. }
            | HpackRepresentation::LiteralNoIndex { name, value, .. }
            | HpackRepresentation::LiteralNeverIndex { name, value, .. } => {
                headers.push(Header::new(
                    normalized_header_name(name, "x-block", header_index),
                    bounded_visible_ascii(value, "value", MAX_PRODUCTION_COMPONENT_LEN),
                ));
            }
            HpackRepresentation::TableSizeUpdate { .. } => {}
        }
    }

    if headers.is_empty() {
        headers.push(Header::new(format!("x-block-{block_index}"), "value"));
    }

    headers
}

fn static_or_fallback_header(index: u8, block_index: usize, header_index: usize) -> Header {
    match index {
        1 => Header::new(":authority", "example.test"),
        2 => Header::new(":method", "GET"),
        3 => Header::new(":method", "POST"),
        4 => Header::new(":path", "/"),
        5 => Header::new(":path", "/index.html"),
        6 => Header::new(":scheme", "http"),
        7 => Header::new(":scheme", "https"),
        _ => Header::new(
            format!("x-index-{block_index}-{header_index}"),
            bounded_visible_ascii(&index.to_string(), "value", MAX_PRODUCTION_COMPONENT_LEN),
        ),
    }
}

fn bounded_production_table_size(size: u32) -> usize {
    (size as usize).min(MAX_PRODUCTION_TABLE_SIZE)
}

fn normalized_header_name(raw: &str, prefix: &str, index: usize) -> String {
    let mut normalized = String::new();
    for byte in raw.bytes().take(MAX_PRODUCTION_COMPONENT_LEN) {
        let lower = byte.to_ascii_lowercase();
        if lower.is_ascii_lowercase() || lower.is_ascii_digit() || lower == b'-' {
            normalized.push(char::from(lower));
        }
    }

    if normalized.is_empty() {
        format!("{prefix}-{index}")
    } else {
        normalized
    }
}

fn bounded_visible_ascii(input: &str, fallback: &str, max_len: usize) -> String {
    let mut out = String::new();
    for byte in input.bytes().take(max_len) {
        match byte {
            b'\r' | b'\n' | b'\0' => out.push('-'),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => {}
        }
    }

    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
}
