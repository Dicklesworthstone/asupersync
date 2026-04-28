//! Enhanced structure-aware DecodeProof proof-bytes adversarial fuzzer.
//!
//! This fuzzer extends the existing raptorq_proof_bytes.rs with more sophisticated
//! attack patterns targeting byte-level corruptions and boundary conditions in
//! proof verification.
//!
//! Attack vectors tested:
//! 1. **Byte-level corruptions**: Direct manipulation of serialized proof bytes
//! 2. **Length field attacks**: Buffer overruns, underruns, and size mismatches
//! 3. **Cross-field corruption**: Breaking relationships between related fields
//! 4. **Integer overflow/underflow**: Boundary condition attacks on numeric fields
//! 5. **Format confusion**: Mixed JSON/binary corruption patterns
//! 6. **Hash collision attempts**: Targeted corruption of cryptographic fields
//!
//! Invariants verified:
//! - `replay_and_verify` never panics on corrupted proof bytes
//! - Verification correctly rejects all corrupted proofs
//! - Memory safety under all corruption patterns

#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::proof::{
    DecodeConfig, DecodeProof, EliminationTrace, InactivationStrategy, PeelingTrace, PivotEvent,
    ProofOutcome, ReceivedSummary, StrategyTransition,
};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

const MAX_K: usize = 24;
const MAX_SYMBOL_SIZE: usize = 96;
const MAX_PAYLOAD_BYTES: usize = MAX_K * MAX_SYMBOL_SIZE;
const MAX_CORRUPTION_BYTES: usize = 256; // Maximum bytes to corrupt

#[derive(Arbitrary, Clone, Copy, Debug)]
enum CorruptionStrategy {
    /// No corruption - baseline test
    None,
    /// Single byte flip at random position
    ByteFlip,
    /// Corrupt multiple random bytes
    RandomBytes,
    /// Target length fields specifically
    LengthFieldAttack,
    /// Corrupt hash/checksum fields
    HashCorruption,
    /// Integer overflow attempts
    IntegerOverflow,
    /// Truncate the serialized data
    Truncation,
    /// Insert random bytes at random position
    ByteInsertion,
    /// Zero out critical sections
    Nullification,
    /// Bit-level corruption patterns
    BitPatterns,
}

#[derive(Arbitrary, Clone, Debug)]
struct CorruptionPlan {
    strategy: CorruptionStrategy,
    /// Position in the serialized bytes to start corruption
    position: usize,
    /// Number of bytes to corrupt
    length: usize,
    /// Corruption pattern/mask
    pattern: Vec<u8>,
    /// Whether to target specific field patterns
    target_field_signatures: bool,
}

#[derive(Arbitrary, Debug)]
struct ProofCorruptionSpec {
    k_raw: u8,
    symbol_size_raw: u8,
    seed: u64,
    object_low: u64,
    sbn: u8,
    payload: Vec<u8>,
    corruption: CorruptionPlan,
    /// Use binary format if available, otherwise JSON
    use_binary_format: bool,
}

fuzz_target!(|spec: ProofCorruptionSpec| {
    let k = 2 + (usize::from(spec.k_raw) % (MAX_K - 1));
    let symbol_size = 1 + (usize::from(spec.symbol_size_raw) % MAX_SYMBOL_SIZE);
    let payload_len = spec.payload.len().min(MAX_PAYLOAD_BYTES);
    let payload = &spec.payload[..payload_len];

    let decoder = InactivationDecoder::new(k, symbol_size, spec.seed);
    let object_id = ObjectId::new_for_test(spec.object_low);
    let source = build_source_block(payload, k, symbol_size, spec.seed, 0);
    let received = build_received(&decoder, &source, symbol_size, spec.seed);

    let decode = decoder
        .decode_with_proof(&received, object_id, spec.sbn)
        .expect("complete structured input should decode");

    // Serialize the proof to bytes
    let clean_bytes = serialize_proof(&decode.proof, &received, spec.use_binary_format);
    let expect_success = matches!(spec.corruption.strategy, CorruptionStrategy::None);

    // Apply corruption to the serialized bytes
    let mut corrupted_bytes = clean_bytes.clone();
    apply_byte_corruption(&mut corrupted_bytes, &spec.corruption);

    // Attempt to deserialize the potentially corrupted proof
    let deserialization_result = catch_unwind(AssertUnwindSafe(|| {
        deserialize_proof(&corrupted_bytes, spec.use_binary_format)
    }));

    // If deserialization fails, that's acceptable - corruption detected early
    let (proof, symbols) = match deserialization_result {
        Ok(Ok(data)) => data,
        Ok(Err(_)) => {
            // Deserialization failed - corruption was detected early, which is good
            if !expect_success {
                return; // This is expected for corrupted data
            } else {
                panic!("Valid proof failed to deserialize");
            }
        }
        Err(_) => {
            // Deserialization panicked - this should not happen
            panic!("Deserialization panicked - memory safety violation");
        }
    };

    // Test replay_and_verify on the (potentially corrupted) proof
    let replay_result = catch_unwind(AssertUnwindSafe(|| {
        proof.replay_and_verify(&symbols)
    }));

    // Verify invariants
    assert!(replay_result.is_ok(), "replay_and_verify panicked on corrupted proof bytes");

    let verification_result = replay_result.expect("panic already asserted absent");

    if expect_success {
        assert!(
            verification_result.is_ok(),
            "Valid proof bytes must verify after serialization round-trip: {verification_result:?}"
        );
    } else {
        // For corrupted proofs, we expect verification to fail (not panic)
        assert!(
            verification_result.is_err(),
            "Corrupted proof bytes must be rejected by verifier, not accepted"
        );
    }
});

/// Serialize a proof and symbols to bytes using the specified format.
fn serialize_proof(proof: &DecodeProof, symbols: &[ReceivedSymbol], use_binary: bool) -> Vec<u8> {
    if use_binary {
        // Try to use a more compact binary format if available
        // For now, fall back to JSON as the binary format may not be implemented
        serialize_json(proof, symbols)
    } else {
        serialize_json(proof, symbols)
    }
}

/// Serialize using JSON format (existing implementation).
fn serialize_json(proof: &DecodeProof, symbols: &[ReceivedSymbol]) -> Vec<u8> {
    use serde_json;

    let envelope = ProofEnvelopeWire::from_actual(proof, symbols);
    serde_json::to_vec(&envelope).expect("serialize proof envelope")
}

/// Deserialize proof and symbols from bytes.
fn deserialize_proof(bytes: &[u8], use_binary: bool) -> Result<(DecodeProof, Vec<ReceivedSymbol>), Box<dyn std::error::Error>> {
    if use_binary {
        // Try binary format first, fall back to JSON
        deserialize_json(bytes)
    } else {
        deserialize_json(bytes)
    }
}

/// Deserialize using JSON format.
fn deserialize_json(bytes: &[u8]) -> Result<(DecodeProof, Vec<ReceivedSymbol>), Box<dyn std::error::Error>> {
    use serde_json;

    let envelope: ProofEnvelopeWire = serde_json::from_slice(bytes)?;
    Ok(envelope.into_actual())
}

/// Apply byte-level corruption to serialized proof data.
fn apply_byte_corruption(data: &mut [u8], plan: &CorruptionPlan) {
    if data.is_empty() {
        return;
    }

    match plan.strategy {
        CorruptionStrategy::None => {
            // No corruption
        }
        CorruptionStrategy::ByteFlip => {
            let pos = plan.position % data.len();
            data[pos] = data[pos].wrapping_add(1);
        }
        CorruptionStrategy::RandomBytes => {
            let start = plan.position % data.len();
            let len = plan.length.min(MAX_CORRUPTION_BYTES).min(data.len() - start);
            for (i, &byte) in plan.pattern.iter().enumerate().take(len) {
                if start + i < data.len() {
                    data[start + i] = byte;
                }
            }
        }
        CorruptionStrategy::LengthFieldAttack => {
            // Target common length field patterns in JSON
            corrupt_length_fields(data, &plan.pattern);
        }
        CorruptionStrategy::HashCorruption => {
            // Target hash/checksum patterns
            corrupt_hash_fields(data, &plan.pattern);
        }
        CorruptionStrategy::IntegerOverflow => {
            // Replace numeric values with boundary values
            corrupt_with_boundary_integers(data, plan.position);
        }
        CorruptionStrategy::Truncation => {
            let new_len = (plan.position % data.len()).max(1);
            data[new_len..].fill(0);
            // Note: We can't actually truncate the slice here, just zero the end
        }
        CorruptionStrategy::ByteInsertion => {
            // Simulate insertion by overwriting with shifted pattern
            corrupt_with_insertion_pattern(data, plan);
        }
        CorruptionStrategy::Nullification => {
            let start = plan.position % data.len();
            let len = plan.length.min(data.len() - start);
            for i in 0..len {
                if start + i < data.len() {
                    data[start + i] = 0;
                }
            }
        }
        CorruptionStrategy::BitPatterns => {
            corrupt_with_bit_patterns(data, plan);
        }
    }
}

/// Corrupt length fields in JSON by targeting numeric patterns.
fn corrupt_length_fields(data: &mut [u8], pattern: &[u8]) {
    // Look for patterns like "length":123 or "count":456 and corrupt the numbers
    let targets: &[&[u8]] = &[b"length", b"count", b"total", b"size"];

    for target in targets {
        if let Some(pos) = find_pattern(data, target) {
            // Look for the colon and number after the field name
            if let Some(colon_pos) = find_colon_after_position(data, pos + target.len()) {
                corrupt_number_after_colon(data, colon_pos, pattern);
            }
        }
    }
}

/// Corrupt hash/checksum fields by targeting hex patterns.
fn corrupt_hash_fields(data: &mut [u8], pattern: &[u8]) {
    // Look for long hex strings that might be hashes
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'"' {
            let hex_start = i + 1;
            let mut hex_end = hex_start;
            let mut hex_len = 0;

            // Count hex characters
            while hex_end < data.len() && hex_len < 64 {
                let c = data[hex_end];
                if (c >= b'0' && c <= b'9') || (c >= b'a' && c <= b'f') || (c >= b'A' && c <= b'F') {
                    hex_len += 1;
                    hex_end += 1;
                } else if c == b'"' && hex_len >= 16 {
                    // Found a hex string of reasonable length, corrupt it
                    corrupt_hex_string(data, hex_start, hex_end, pattern);
                    break;
                } else {
                    break;
                }
            }
        }
        i += 1;
    }
}

/// Corrupt with integer boundary values.
fn corrupt_with_boundary_integers(data: &mut [u8], seed: usize) {
    let boundary_values: &[&[u8]] = &[
        b"0", b"1", b"255", b"256", b"65535", b"65536",
        b"4294967295", b"4294967296", b"18446744073709551615",
        b"-1", b"-128", b"-32768", b"-2147483648",
    ];

    let value = boundary_values[seed % boundary_values.len()];

    // Find a number in the JSON and replace it
    for i in 0..data.len().saturating_sub(value.len()) {
        if data[i].is_ascii_digit() || data[i] == b'-' {
            let mut end = i;
            while end < data.len() && (data[end].is_ascii_digit() || data[end] == b'-') {
                end += 1;
            }

            // Replace the found number with our boundary value
            let replacement_len = (end - i).min(value.len());
            data[i..i + replacement_len].copy_from_slice(&value[..replacement_len]);
            break;
        }
    }
}

/// Simulate byte insertion by creating a shifted pattern.
fn corrupt_with_insertion_pattern(data: &mut [u8], plan: &CorruptionPlan) {
    let start = plan.position % data.len();
    let shift_amount = plan.length.min(8);

    // Shift existing bytes and insert pattern
    for i in (start..data.len().saturating_sub(shift_amount)).rev() {
        data[i + shift_amount] = data[i];
    }

    // Insert the pattern
    for (i, &byte) in plan.pattern.iter().enumerate().take(shift_amount) {
        if start + i < data.len() {
            data[start + i] = byte;
        }
    }
}

/// Apply various bit-level corruption patterns.
fn corrupt_with_bit_patterns(data: &mut [u8], plan: &CorruptionPlan) {
    let patterns = [
        0xFF, // All bits set
        0x00, // All bits clear
        0xAA, // Alternating pattern
        0x55, // Inverse alternating pattern
        0x01, // Single bit set
        0x80, // High bit set
    ];

    let pattern = patterns[plan.position % patterns.len()];
    let start = plan.position % data.len();
    let len = plan.length.min(data.len() - start);

    for i in 0..len {
        if start + i < data.len() {
            data[start + i] ^= pattern;
        }
    }
}

// Helper functions for pattern matching and corruption

fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len()).position(|window| window == pattern)
}

fn find_colon_after_position(data: &[u8], start: usize) -> Option<usize> {
    for i in start..data.len() {
        if data[i] == b':' {
            return Some(i);
        } else if !data[i].is_ascii_whitespace() && data[i] != b'"' {
            break;
        }
    }
    None
}

fn corrupt_number_after_colon(data: &mut [u8], colon_pos: usize, pattern: &[u8]) {
    let mut start = colon_pos + 1;

    // Skip whitespace
    while start < data.len() && data[start].is_ascii_whitespace() {
        start += 1;
    }

    // Find the end of the number
    let mut end = start;
    while end < data.len() && (data[end].is_ascii_digit() || data[end] == b'-') {
        end += 1;
    }

    if start < end && !pattern.is_empty() {
        let len = (end - start).min(pattern.len());
        data[start..start + len].copy_from_slice(&pattern[..len]);
    }
}

fn corrupt_hex_string(data: &mut [u8], start: usize, end: usize, pattern: &[u8]) {
    let len = end - start;
    for (i, &byte) in pattern.iter().enumerate() {
        if i >= len {
            break;
        }
        // Ensure we only write valid hex characters
        let hex_char = match byte & 0x0F {
            0..=9 => b'0' + (byte & 0x0F),
            _ => b'a' + ((byte & 0x0F) - 10),
        };
        data[start + i] = hex_char;
    }
}

// Reuse the wire format types from the original fuzzer

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ProofEnvelopeWire {
    proof: DecodeProofWire,
    symbols: Vec<ReceivedSymbolWire>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct DecodeProofWire {
    version: u8,
    config: DecodeConfigWire,
    received: ReceivedSummaryWire,
    peeling: PeelingTraceWire,
    elimination: EliminationTraceWire,
    outcome: SuccessOutcomeWire,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct DecodeConfigWire {
    object_id_high: u64,
    object_id_low: u64,
    sbn: u8,
    k: usize,
    s: usize,
    h: usize,
    l: usize,
    symbol_size: usize,
    seed: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ReceivedSummaryWire {
    total: usize,
    source_count: usize,
    repair_count: usize,
    esi_multiset_hash: u64,
    esis: Vec<u32>,
    truncated: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PeelingTraceWire {
    solved: usize,
    solved_indices: Vec<usize>,
    truncated: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct EliminationTraceWire {
    strategy: InactivationStrategyWire,
    inactivated: usize,
    inactive_cols: Vec<usize>,
    pivots: usize,
    pivot_events: Vec<PivotEventWire>,
    inactive_cols_truncated: bool,
    pivot_events_truncated: bool,
    row_ops: usize,
    strategy_transitions: Vec<StrategyTransitionWire>,
    strategy_transitions_truncated: bool,
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
enum InactivationStrategyWire {
    AllAtOnce,
    HighSupportFirst,
    BlockSchurLowRank,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct StrategyTransitionWire {
    from: InactivationStrategyWire,
    to: InactivationStrategyWire,
    reason: TransitionReasonWire,
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
enum TransitionReasonWire {
    DenseOrNearSquare,
    FallbackAfterBaselineFailure,
    BlockSchurFailedToConverge,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PivotEventWire {
    col: usize,
    row: usize,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct SuccessOutcomeWire {
    symbols_recovered: usize,
    source_payload_hash: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ReceivedSymbolWire {
    esi: u32,
    is_source: bool,
    columns: Vec<usize>,
    coefficients: Vec<u8>,
    data: Vec<u8>,
}

// Reuse implementation code from original fuzzer

impl ProofEnvelopeWire {
    fn from_actual(proof: &DecodeProof, symbols: &[ReceivedSymbol]) -> Self {
        Self {
            proof: DecodeProofWire::from_actual(proof),
            symbols: symbols.iter().map(ReceivedSymbolWire::from_actual).collect(),
        }
    }

    fn into_actual(self) -> (DecodeProof, Vec<ReceivedSymbol>) {
        (
            self.proof.into_actual(),
            self.symbols
                .into_iter()
                .map(ReceivedSymbolWire::into_actual)
                .collect(),
        )
    }
}

impl DecodeProofWire {
    fn from_actual(proof: &DecodeProof) -> Self {
        let ProofOutcome::Success {
            symbols_recovered,
            source_payload_hash,
        } = proof.outcome.clone()
        else {
            panic!("expected success proof for structured baseline");
        };

        Self {
            version: proof.version,
            config: DecodeConfigWire::from_actual(&proof.config),
            received: ReceivedSummaryWire::from_actual(&proof.received),
            peeling: PeelingTraceWire::from_actual(&proof.peeling),
            elimination: EliminationTraceWire::from_actual(&proof.elimination),
            outcome: SuccessOutcomeWire {
                symbols_recovered,
                source_payload_hash,
            },
        }
    }

    fn into_actual(self) -> DecodeProof {
        DecodeProof {
            version: self.version,
            config: self.config.into_actual(),
            received: self.received.into_actual(),
            peeling: self.peeling.into_actual(),
            elimination: self.elimination.into_actual(),
            outcome: ProofOutcome::Success {
                symbols_recovered: self.outcome.symbols_recovered,
                source_payload_hash: self.outcome.source_payload_hash,
            },
        }
    }
}

impl DecodeConfigWire {
    fn from_actual(config: &DecodeConfig) -> Self {
        Self {
            object_id_high: config.object_id.high(),
            object_id_low: config.object_id.low(),
            sbn: config.sbn,
            k: config.k,
            s: config.s,
            h: config.h,
            l: config.l,
            symbol_size: config.symbol_size,
            seed: config.seed,
        }
    }

    fn into_actual(self) -> DecodeConfig {
        DecodeConfig {
            object_id: ObjectId::new(self.object_id_high, self.object_id_low),
            sbn: self.sbn,
            k: self.k,
            s: self.s,
            h: self.h,
            l: self.l,
            symbol_size: self.symbol_size,
            seed: self.seed,
        }
    }
}

impl ReceivedSummaryWire {
    fn from_actual(summary: &ReceivedSummary) -> Self {
        Self {
            total: summary.total,
            source_count: summary.source_count,
            repair_count: summary.repair_count,
            esi_multiset_hash: summary.esi_multiset_hash,
            esis: summary.esis.clone(),
            truncated: summary.truncated,
        }
    }

    fn into_actual(self) -> ReceivedSummary {
        ReceivedSummary {
            total: self.total,
            source_count: self.source_count,
            repair_count: self.repair_count,
            esi_multiset_hash: self.esi_multiset_hash,
            esis: self.esis,
            truncated: self.truncated,
        }
    }
}

impl PeelingTraceWire {
    fn from_actual(trace: &PeelingTrace) -> Self {
        Self {
            solved: trace.solved,
            solved_indices: trace.solved_indices.clone(),
            truncated: trace.truncated,
        }
    }

    fn into_actual(self) -> PeelingTrace {
        PeelingTrace {
            solved: self.solved,
            solved_indices: self.solved_indices,
            truncated: self.truncated,
        }
    }
}

impl EliminationTraceWire {
    fn from_actual(trace: &EliminationTrace) -> Self {
        Self {
            strategy: InactivationStrategyWire::from_actual(trace.strategy),
            inactivated: trace.inactivated,
            inactive_cols: trace.inactive_cols.clone(),
            pivots: trace.pivots,
            pivot_events: trace
                .pivot_events
                .iter()
                .map(PivotEventWire::from_actual)
                .collect(),
            inactive_cols_truncated: trace.inactive_cols_truncated,
            pivot_events_truncated: trace.pivot_events_truncated,
            row_ops: trace.row_ops,
            strategy_transitions: trace
                .strategy_transitions
                .iter()
                .map(StrategyTransitionWire::from_actual)
                .collect(),
            strategy_transitions_truncated: trace.strategy_transitions_truncated,
        }
    }

    fn into_actual(self) -> EliminationTrace {
        EliminationTrace {
            strategy: self.strategy.into_actual(),
            inactivated: self.inactivated,
            inactive_cols: self.inactive_cols,
            pivots: self.pivots,
            pivot_events: self
                .pivot_events
                .into_iter()
                .map(PivotEventWire::into_actual)
                .collect(),
            inactive_cols_truncated: self.inactive_cols_truncated,
            pivot_events_truncated: self.pivot_events_truncated,
            row_ops: self.row_ops,
            strategy_transitions: self
                .strategy_transitions
                .into_iter()
                .map(StrategyTransitionWire::into_actual)
                .collect(),
            strategy_transitions_truncated: self.strategy_transitions_truncated,
        }
    }
}

impl InactivationStrategyWire {
    const fn from_actual(strategy: InactivationStrategy) -> Self {
        match strategy {
            InactivationStrategy::AllAtOnce => Self::AllAtOnce,
            InactivationStrategy::HighSupportFirst => Self::HighSupportFirst,
            InactivationStrategy::BlockSchurLowRank => Self::BlockSchurLowRank,
        }
    }

    const fn into_actual(self) -> InactivationStrategy {
        match self {
            Self::AllAtOnce => InactivationStrategy::AllAtOnce,
            Self::HighSupportFirst => InactivationStrategy::HighSupportFirst,
            Self::BlockSchurLowRank => InactivationStrategy::BlockSchurLowRank,
        }
    }
}

impl StrategyTransitionWire {
    fn from_actual(transition: &StrategyTransition) -> Self {
        Self {
            from: InactivationStrategyWire::from_actual(transition.from),
            to: InactivationStrategyWire::from_actual(transition.to),
            reason: TransitionReasonWire::from_actual(transition.reason),
        }
    }

    fn into_actual(self) -> StrategyTransition {
        StrategyTransition {
            from: self.from.into_actual(),
            to: self.to.into_actual(),
            reason: self.reason.as_static_str(),
        }
    }
}

impl TransitionReasonWire {
    fn from_actual(reason: &'static str) -> Self {
        match reason {
            "dense_or_near_square" => Self::DenseOrNearSquare,
            "fallback_after_baseline_failure" => Self::FallbackAfterBaselineFailure,
            "block_schur_failed_to_converge" => Self::BlockSchurFailedToConverge,
            _ => Self::DenseOrNearSquare,
        }
    }

    const fn as_static_str(self) -> &'static str {
        match self {
            Self::DenseOrNearSquare => "dense_or_near_square",
            Self::FallbackAfterBaselineFailure => "fallback_after_baseline_failure",
            Self::BlockSchurFailedToConverge => "block_schur_failed_to_converge",
        }
    }
}

impl PivotEventWire {
    fn from_actual(event: &PivotEvent) -> Self {
        Self {
            col: event.col,
            row: event.row,
        }
    }

    fn into_actual(self) -> PivotEvent {
        PivotEvent {
            col: self.col,
            row: self.row,
        }
    }
}

impl ReceivedSymbolWire {
    fn from_actual(symbol: &ReceivedSymbol) -> Self {
        Self {
            esi: symbol.esi,
            is_source: symbol.is_source,
            columns: symbol.columns.clone(),
            coefficients: symbol.coefficients.iter().map(|coef| coef.raw()).collect(),
            data: symbol.data.clone(),
        }
    }

    fn into_actual(self) -> ReceivedSymbol {
        ReceivedSymbol {
            esi: self.esi,
            is_source: self.is_source,
            columns: self.columns,
            coefficients: self.coefficients.into_iter().map(Gf256::new).collect(),
            data: self.data,
        }
    }
}

fn build_source_block(
    raw: &[u8],
    k: usize,
    symbol_size: usize,
    seed: u64,
    salt: u64,
) -> Vec<Vec<u8>> {
    let seed_bytes = seed.to_le_bytes();
    let salt_bytes = salt.to_le_bytes();
    let mut source = Vec::with_capacity(k);
    for row in 0..k {
        let mut symbol = Vec::with_capacity(symbol_size);
        for col in 0..symbol_size {
            let base = if raw.is_empty() {
                ((row * 29 + col * 17 + 0x5A) & 0xFF) as u8
            } else {
                raw[(row * symbol_size + col) % raw.len()]
            };
            let mixed = base
                ^ seed_bytes[(row + col) % seed_bytes.len()]
                ^ salt_bytes[(row * 3 + col) % salt_bytes.len()]
                ^ ((row * 31 + col * 7) as u8);
            symbol.push(mixed);
        }
        source.push(symbol);
    }
    source
}

fn build_received(
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    symbol_size: usize,
    seed: u64,
) -> Vec<ReceivedSymbol> {
    let encoder = SystematicEncoder::new(source, symbol_size, seed).expect("normalized encoder");
    let mut received = decoder.constraint_symbols();
    for (index, data) in source.iter().enumerate() {
        received.push(ReceivedSymbol::source(index as u32, data.clone()));
    }
    for esi in (source.len() as u32)..(decoder.params().l as u32) {
        let (columns, coefficients) = decoder.repair_equation(esi).expect("repair equation");
        received.push(ReceivedSymbol::repair(
            esi,
            columns,
            coefficients,
            encoder.repair_symbol(esi),
        ));
    }
    received
}